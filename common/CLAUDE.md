# common/

The modules every other directory reads. Nothing in here belongs to a protocol,
and that is the entry test rather than a description: a file lands here because
more than one family needs it, not because it felt general.

| File | What it is |
|---|---|
| `config_file.js` | The one place that decides what `CONFIG_FILE` means. Requires nothing at all. |
| `config.js` | Every setting this service has, and the refusal to start without one. The only module `helpers.js` depends on. |
| `helpers.js` | Log, keys, `signJwt()`, `userFor()`, the cross-protocol parsers. |
| `crypto.js` | **EVERY SIGNATURE AND EVERY CIPHER IN THIS SERVICE, since 2026-08-27.** XML Signature and XML Encryption, JWS, JWE, key and certificate generation, thumbprints, constant-time comparison. A LEAF — it sits UNDER `helpers.js` and may never require it back. See below. |
| `app.js` | The express app and every middleware. Requiring it is how a protocol module gets somewhere to register. |
| `admin_stats.js` | The counters, the revocation set, and `recordAuthentication()` — the single authentication funnel. |
| `audit.js` | What happened, when, and to whom, as discrete events. Sits BESIDE `admin_stats.js`, not under it. |
| `error_codes.js` | **THE ONE TABLE OF EVERY FAILURE CONDITION (2026-09-12)** — `STS-<SUBSYSTEM>-<NNNN>`, by subsystem, with what the client sees beside each. `mark()`, `tag()`, and the generator for `docs/error-codes.md`. A LEAF that requires nothing. See below. |
| `used_assertions.js` | **EVERY RFC 7523 JWT AND RFC 7522 SAML ASSERTION ACCEPTED, SO NONE IS ACCEPTED TWICE, EVER (2026-09-13).** One history for client authentication and the grant, both profiles, per realm; persisted in every store with one and in BOTH modes; claimed atomically on postgres; spent only when the token request issues tokens. A LIBRARY (rule 3ae) with its own logger, installed by `persistence.js`. |
| `applications.js` | Every application this service has been asked about, stored in the directory under `ou=applications`. |
| `delegation.js` | Who acted on whose behalf, through what, to reach what — eight mechanisms across three protocol families in ONE model. What HAPPENED. |
| `app_permissions.js` | **Who MAY reach what, decided in advance** — delegated permissions between two OAuth application entries, in Microsoft Entra ID's shape. The CONFIGURED twin of the file above it, and never to be drawn as one register with it. |
| `user_graph.js` | ONE PERSON, END TO END: that register UNIONED with the issued one, so a picture can show every grant, flow, assertion, ticket and SVID in somebody's name beside every delegation naming them. |
| `credential_graph.js` | ONE CREDENTIAL, END TO END: where it came from — who held it, in whose name, to reach what — and every generation of exchange behind it, back to the issuance the line rests on. |
| `claim_attributes.js` | Which LDAP attributes a token or an assertion carries, per claim set. |
| `group_claims.js` | The groups claim, in all five claim sets at once. |
| `pki_authoring.js` | **THE CERTIFICATE & KEY CONFIGURATION PANE, AS A MODEL (2026-09-10)** — the parent project's *PKI / X.509* workflow: fourteen profiles, five cryptographic approaches, a subject DN, twenty-two X.509v3 extensions, PKCS#10 and four keystore formats, over the same vendored encoder. A LEAF (rule 3aa): it draws no HTML and holds no store. |
| `pqc_support.js` | **DOES THIS KEY PAIR USE A POST-QUANTUM ALGORITHM — ONE ANSWER (2026-09-13).** Behind the icon on `/admin/pki` and `/admin/keys`, the `pqc` member on those pages' JSON, and the mark in the certificate details dialog. It reads every spelling the two pages hold a key in — a JOSE `alg`, a key-material id, a node key type, an OID, a certificate's SubjectPublicKeyInfo — and answers one of FOUR kinds, because "PQC" is four claims: `pq` (ML-DSA, SLH-DSA), `composite` (one key with a post-quantum and a classical half), `kem` (ML-KEM, which signs nothing), and `hybrid` (a CLASSICAL key whose certificate carries an alternative post-quantum key under X.509 (2019) clause 9.8 — the key itself is not post-quantum). **The key decides, never the signature on its certificate**: an ML-DSA key under an RSA CA is marked and an EC key under an ML-DSA CA is not. A classical key is `null`. A LEAF over `pq_jose.js` and the vendored registry. |
| `certificate_details.js` | **ONE CERTIFICATE, EVERY FIELD, AND THE PATH IT BUILDS (2026-09-13)** — the model behind the certificate details dialog on `/admin/pki` and `/admin/crypto-metadata` and `GET /admin-api/certificates`: the tbsCertificate in RFC 5280 section 4.1's order (both signature algorithms, every RDN with its OID, each validity bound's ASN.1 time type, the key's parameters and bytes, both unique identifiers, every extension decoded) and a trust chain BUILT by matching each issuer's name AND verifying its signature, because a stored chain is a snapshot and a replaced Root has the same subject as the one it replaced. Built on the vendored inspector (`describeCertificate()`, `verifyChain()`); fingerprints are node's, and a post-quantum key is named from the PQC registry because the inspector summarises a composite by its classical half. A LEAF: it reads no caller's PEM and decides nothing about where a certificate came from — `admin-core/certificate_views.js` does. |
| `pki_merge.js` | **ONE CERTIFICATE AUTHORITY ROW WRITTEN BY SEVERAL NODES AT ONCE (2026-09-14, #46).** The three-way merge `keystore.js` applies under the row's lock: revocations and issued serials are unions, a CA tier or certificate slot is first writer wins, the register's CRL number adds. Pure JSON in, JSON out; a LEAF over config and bunyan. Its header argues why a merge and not a row per revocation. |
| `pki.js` | **A CERTIFICATE AUTHORITY PER TRUST REALM, since 2026-09-10** — Root, Intermediate, Issuing, and the signing key pairs it issues to applications. **And since 2026-09-11 the SPIFFE authority every X509-SVID is minted under**, which is the one Issuing CA here with room beneath it and the one door that issues WITHOUT recording (`issueUnder()`). A LEAF (rule 3w): it holds no store, registers no route, and requires `config`, `crypto`, `keystore`, `realms` and the two vendored PKI modules. |
| `cert_enrollment.js` | **WHO MAY BE ISSUED A CERTIFICATE FOR WHOM, AND WHAT GOES IN IT (2026-09-13)** — the core ACME (`acme/`), EST (`est/`) and SCEP (`scep/`) issue through, so none of the three decides any of it: the identity rule (yourself, or any person or application in the realm for a holder of Admin Write), the nine issued `/admin/pki` profiles and the five refused by design, the PKCS#10 proof of possession for every key family, names built from the DIRECTORY ENTRY with an unowned name refusing the request, every certificate kept on the entry it names (and a private key only when this service made it), and the two entry-bound credentials — an ACME EAB key and a SCEP challenge. A LIBRARY (rule 3ag) whose store is the entry, through a slot `ldap/ldap_server.js` fills. |
| `enrollment_monitor.js` | **WHAT THE THREE ENROLLMENT PROTOCOLS HAVE DONE (2026-09-13)** — one vocabulary of counters for `/admin/{acme,est,scep}/monitor`, per realm, merged across processes in `gnap_monitor.js`'s shape, and unable to throw into the request it counts. |
| `jose_certificate_header.js` | **WHICH `x5c` OR `x5u` A SIGNED TOKEN CARRIES (2026-09-13)** — twelve use cases, one setting each in its protocol's group (`none`/`x5c`/`x5u`/`both`, `x5u` by default, per realm), the chain of the certified key that signed (leaf to service Root), and the `x5u` resource behind `GET /pki/chain/{scope}/{sha256}.pem`. A LIBRARY over `config`, `realms` and `error_codes`; `pki` and `helpers` lazily. See *3af* below. |
| `jose_kid.js` | **WHICH `kid` A SIGNED TOKEN CARRIES (2026-09-13)** — `keys.kidFormat`, per realm: `internal` (the default, `sts-…`) or `jwk-thumbprint-uri`, the signing key's RFC 9278 JWK Thumbprint URI. A TRANSLATION at the edges — the header a signer writes, the JWKS, a lookup of one of this service's own tokens — while the key set, the keystore, the certificate register and `certificateHeaderFor()` go on naming a key by its internal kid. A LIBRARY over `config`, `crypto` and `error_codes`. See *3af, continued* below. |
| `tls_client_certificates.js` | **A PERSON'S — AND SINCE 2026-09-13 AN APPLICATION'S — TLS CLIENT CERTIFICATE, AND THE GATE THAT MAKES TRUSTING THE SERVICE ROOT SAFE (2026-09-13).** Issues a `clientAuth` leaf from the realm's `tls-client` Issuing CA through `pki.certify()` (so OCSP, the CRL and `/admin/pki`'s revocation pane know it), packages it as a password-protected PKCS#12 and PEM files through the vendored exporter, and revokes one only among the holder's own. **And `identityOf()`**, which every door that turns a verified client certificate into an identity asks — see *3ag* below. A LIBRARY: it registers nothing. |
| `certificate_subject.js` | **RFC 8705 SECTION 2.1.2's FIVE CERTIFICATE SUBJECT PARAMETERS, READ AND COMPARED (2026-09-13)** — an RFC 4514 DN compared as a name (types, OIDs, escapes, caseIgnoreMatch, a multi-valued RDN in any order), the four subjectAltName kinds off node's `X509Certificate` (a host name without case, an IP by value, an email's domain without case, a URI exactly), and the grammar a registration may hold. `applications.js` asks it what may be written and `oauth-oidc/client_auth.js` whether a certificate matches. A LEAF over `helpers.js`. |
| `realm_chooser.js` | **WHICH REALM TO SIGN IN THROUGH (2026-09-14, #32).** A GET of exactly `/admin` or `/portal`, in the default realm, with no session and realms defined, asks which realm first — a list in development and a text box in product (`mode.listsRealmsBeforeSignIn()`) — and `?realm=<id>` redirects to that realm's surface, BUILT from the registry and never echoed. A LIBRARY both surfaces call from their own gate, so they cannot ask differently; `admin-ui/CLAUDE.md` 8d. |
| `revocation_status.js` | **REVOCATION, CONSULTED (2026-09-12)** — the one function that answers whether a PRESENTED certificate chain is revoked: from the register for one this service issued, from the OCSP responder and the CRL (delta and indirect included) it names for anybody else's. `pki_revocation.js` publishes; this checks. A LIBRARY (rule 3ad). |
| `vendored/` | Byte-identical copies of the parent project's files. **Do not edit them here** — see `common/vendored/CLAUDE.md`. |

**`config_file.js` is new with the 2026-08-23 reorganisation and it exists
because of it.** Fourteen modules read the appconfig file directly for the one
thing they need before `config.js` exists — a bunyan log level — and node
resolves a relative `require()` against the directory of the module doing the
requiring. While every module sat in the package root, `CONFIG_FILE=./env/local.js`
worked from all fourteen by accident. From `common/` it resolves to
`common/env/local.js`, which does not exist: `config.js` and `helpers.js` read it
UNGUARDED and would die with `MODULE_NOT_FOUND` naming a path nobody typed, and
the eleven guarded readers would quietly fall back to `info`. So the variable is
made absolute once, in place, before anything reads it. Three callers require it
first and between them cover every way this service is loaded — `server.js`,
`config.js` and `helpers.js` — and it is idempotent, so all three costs nothing.
Four of the fourteen readers are VENDORED files this repository may not edit,
which is why the fix is a mutation of `process.env` rather than fourteen edits.

---

## `helpers.js` holds what more than one protocol needs

**`parseBody()` PARSES multipart/form-data SINCE 2026-09-13**, every part as
text under its name, for the RFC 9728 upload on `/admin/applications/new` (the
console's CSRF check reads that token out of it); `multipartParts()` returns the
parts with filenames and bytes, finds a delimiter only at a line start (RFC 2046
section 5.1.1) and caps the count. **And `applications.js`'s create now checks
`oauthPermissionBaseUri` and `oauthPermission` as the update always did**
(STS-REG-0012..0015) — a create never reached those checks, so an import naming
an unusable scope would have written it.

`userFor`, `parseBody`, `bodyValues`, `oauthError`, `vciError`, `signJwt` and
`firstByLocal`/`textByLocal` are in `helpers.js` because more than one protocol needs
them, not because they are especially general. The last two are read by three parsers
— the WS-Trust RST, WS-Federation's `wreq`, and the `wresult` the mock relying party
is POSTed — and they match on **local name with the namespace ignored** because the
trust namespace alone has four versions in use. That is what lets one parser answer
WS-Trust 1.0 through 1.4 instead of four.

**`bodyValues()` IS THE NEWEST OF THEM AND IT EXISTS BECAUSE `parseBody()` IS NOT
GOING TO CHANGE.** That function builds a PLAIN OBJECT, so a repeated field keeps
only its last value: `resource=a&resource=b` on a Token Request arrived as `b`
and the first was silently gone. Two specifications say the parameter may repeat
— RFC 8707 section 2's `resource` and RFC 8693 section 2.1's `audience` — so
until 2026-08-26 neither could actually be repeated here whatever the RFC said.
The fix is a second reader beside the first rather than a new shape for it:
sixty-odd call sites across fourteen modules read that object with
`String(body.x)`, and giving them an array for a repeat would change what every
one of them sees to serve two parameters. **The authorization endpoint needs none
of it** — it reads `req.query`, and express gives an array for a repeat already,
which is worth knowing before somebody looks for the same bug there.
`admin-ui/admin.js`'s `listField()` is the same function, written first, for the
console's checkbox columns; neither calls the other because that module requires
`oauth2.js` (rule 5) and nothing below it can require back. The shapes are
deliberately identical, so folding them is a one-line delegation in THAT file.

**`dnRfc4514()` MOVED HERE RATHER THAN BEING WRITTEN
TWICE.** It renders a certificate subject the way LDAP and RFC 4514 write one —
leaf first, no spaces after the commas, values escaped — which is a DIFFERENT
string from the most-significant-first form node and `openssl x509 -subject`
print, and it is the form this service files an identity under. It was in
`tls/tls_server.js`, which still re-exports it, because `scim_auth.js` and
`spiffe_auth.js` require that module for it and have done since before it moved.
What forced the move is `spiffe_ca.js`: the directory now records the
certificate every X509-SVID mint produces, using the same six `x509*` attributes
a verified TLS client certificate writes, so the two paths must render a DN
identically — **two spellings of one DN is two people on `/admin/users`** — and
that module CANNOT require `tls_server.js`. Rule 3e's test says why:
`admin-ui/admin.js` requires `spiffe_ca.js`, and `server.js` requires `admin.js`
at 18 and `tls_server.js` at 20, so the require would pull every `/tls*` route
into the router ahead of the console's and `GET /admin/sts-metadata` walks that router.
A leaf here moves no route and closes no cycle. **It takes BOTH shapes of DN node
produces** — the object from `getPeerCertificate()` and the newline-separated
string from `crypto.X509Certificate` — which is the whole reason it is one
function and not two that agree today.


---

## The signing key is parsed ONCE, and `privateKeyPem` is still there

`helpers.js` builds `STS.privateKey` — a `crypto.KeyObject` — beside the
`STS.privateKeyPem` it has always exported, and **every `jwt.sign()` in this
repository takes the KeyObject**. Handing jsonwebtoken the PEM string made node
re-parse it into a key on every signature, which measured 21% of this service's
non-idle CPU against 48% for the RSA signature it was preparing for: a third of
the cost of issuing a token was re-reading a key that has not changed since
startup. One signature went from 1.08ms to 0.48ms and the token endpoint's
throughput rather more than doubled.

`privateKeyPem` is KEPT and is not deprecated — `crypto.js`'s XML signer hands
it to node-forge, which wants a PEM. **A caller picks by what it is doing**:
`signJws()` takes `STS.privateKey`, `signXml()` takes `STS.privateKeyPem`. They
are the same key and are derived from each other, so they cannot drift.

That sentence used to name three files and xml-crypto. There is one signer now
and this service requires xml-crypto nowhere — see below.

---

## `crypto.js`: one signer, one verifier, one cipher

**It replaced six XML signers, four XML signature verifiers, two hand-rolled JWE
halves, three RFC 7638 thumbprints, two self-signed certificate builders and two
`timingSafeEqual` wrappers.** None of those was carelessness: each was written
where it was needed and the copies agreed on the day they were made. What the
copies cost is recorded in `saml/CLAUDE.md` — the `Id="_0"` defect, where every
SAML 1.1 assertion this service ever issued carried an attribute the schema does
not have, it verified anyway so it survived for months, and the fix had to be
applied to EACH SIGNER SEPARATELY.

**The mechanism is `common/vendored/xmldsig.js` and the policy is here**, and
that split is the design rather than tidiness. The vendored file is the parent
project's own XML security module, copied byte-identical, and it is the OTHER
END of most of these exchanges: `tests/xmlsec_interop.js` over there already
drives it against xml-crypto AND xml-encryption across all three SAML versions.
What `crypto.js` adds is what is true of THIS service — which placements its
documents use, that a verifier must be TOLD which element it is checking, that a
decryption answers rather than throws, that a token read back against our own
certificate gets the configured clock skew.

**IT IS A LEAF AND MUST STAY ONE.** It requires npm packages, the vendored
signer and `config.js` — which requires nothing here — so the require is
downward and no cycle is possible. `helpers.js` requires IT. Concretely that
means **nothing in it reads `STS`, the ambient realm or a session**: every
function takes the key it is to use as a parameter, and the realm-aware half
stays in `helpers.js`. It also means `logArtifact()` is out of reach, which is
why `encryptElement()` takes the logger as an ORDINARY PARAMETER that
`saml/saml2.js` fills in — not a sixth inverted slot, because rule 3e is for a
require that would close a cycle or move a route, and a caller that already has
the function can simply hand it over.

**THE VERIFIER TAKES THE ELEMENT'S NAME AND THAT IS NOT A CONVENIENCE.** A SAML
Response carrying a signed assertion has two signatures. Three of the four
implementations this replaced took the FIRST `<ds:Signature>` in the document,
so a caller asking "is this Response signed by us" was answered about the
ASSERTION — a confident yes about a different element, one step from accepting a
response whose assertion was swapped for another validly-signed one. The shared
verifier is told which element, takes the signature that is that element's own
DIRECT CHILD, and additionally refuses a signature whose reference names
something else, which none of the four ever checked. `tests/crypto_module.js`
asserts all of it and was mutation-tested against eight mutants.

**XML ENCRYPTION MOVED RATHER THAN BEING REPLACED**, and it is the one place the
vendored file did not win. It was never duplicated — one implementation, two
callers — and the vendored `encryptXml()` produces a byte-compatible document,
so there was no interop gap to close. What this one has is the DIAGNOSIS: it
answers rather than throwing, names an unknown cipher and an unknown key
transport separately, checks the unwrapped key's LENGTH (RSA-1_5 unwraps a wrong
key to plausible garbage rather than failing), parses the plaintext before
calling CBC a success, and tells a NamespaceError in a good NameID apart from a
wrong certificate. Those messages are the product.

**THE PROTECTED HEADER IS THIS FILE'S TO BUILD, AND FOR THREE YEARS TWO OF THE
THREE SIGNING PATHS DID NOT HONOUR A CALLER'S.** `jsonwebtoken` merges
`options.header` into the header it makes, so the library path had always taken
a caller's `typ`. The other two — the `ownSigner` branch (EdDSA and ES256K, the
two the library refuses) and the post-quantum branch — each hard-coded
`typ: 'JWT'` and ignored `options.header` entirely. **The same call therefore
produced a different header depending on which algorithm was chosen**, and no
caller could have seen that coming from the outside.

It was found on 2026-08-31 by the Shared Signals family, which is the first
thing here that mints a JWT that is not an ordinary one: RFC 8417 section 2.2
gives a Security Event Token `typ: "secevent+jwt"`, and a receiver that
dispatches on the media type — several do — drops one without it with no error
anybody sees. On RS256 it got the header it asked for; on EdDSA, ES256K and
every post-quantum algorithm it silently did not.

`protectedHeaderFor()` is the fix and all three paths go through it.
**`alg` and `kid` remain this file's to set and a caller may not override
them**: the algorithm is what was actually used and the kid names the key that
was actually used, so a caller that could change either would be labelling a
signature as something it is not. Everything else in `options.header` is merged.
`helpers.signJwtAs()` and `signJwtAsAsync()` thread it through, which is how the
one caller that needs it reaches it.

**xml-crypto IS STILL A DEPENDENCY AND NOTHING IN THE SERVICE REQUIRES IT.** It
is there for `tests/crypto_module.js`, which is the only independent reading of
XMLDSIG in this repository — the thing that makes "our signature verifies"
mean something. Removing it saves a package and costs that.

## `applications.js` GREW A FOURTH ATTRIBUTE ROLE, AND THE NAME IS THE ARGUMENT

`declarationAttributes()` walks the `PROTOCOLS` table for an `identifier`, a
`redirect`, a `logout` and a `secret`. Shared Signals added a fifth kind of
attribute and it was given a **`delivery`** role of its own rather than being
folded into `redirect`.

The temptation is obvious — both answer "where does the answer go?" — and it is
wrong in a way this repository is otherwise careful about. **A redirect is where
a BROWSER is sent back to after a protocol hop. `ssfDeliveryEndpoint` is a URL
this service OPENS A CONNECTION TO.** Calling it a redirect would make a table
that is read literally, by the console and by `GET /admin-api/applications/new`,
say something false about the one attribute here with an outbound request behind
it.

The attribute itself is DECLARATION ONLY and nothing reads it: a push goes to
the endpoint on the STREAM, which the receiver named when it created one, and
this service will not take a URL to dial from an application entry. That is the
same position `federation/federation_http.js` takes about `oauthJwksUri` one
family along — a URL recorded here is a note about what a receiver IS, and a URL
on a stream is a URL this service dials. The two are deliberately not one store.

Its sibling `ssfReceiverId` is the opposite and is worth the contrast: it is one
of the few declaration attributes a PROTOCOL also writes, because a receiver
authenticating and being agreed a stream is exactly the kind of event this
registry exists to hold.

## A RETURN ADDRESS HAS A PROVENANCE, AND `returnAddressesOf()` IS THE ONE PLACE IT IS READ (2026-09-12)

Development mode writes the return address a request NAMED onto the attribute
product mode checks requests against — `samlAssertionConsumerService` from a
SAML 2.0 ACS URL or a SAML 1.1 `shire`, `wsfedReplyUrl` from a `wreply`, and
`oauthRedirectUri` when `common/oidc_rp.js` teaches the console's or portal's
own client the address it was reached at. A realm switched to product kept all
of it and believed it as registered; the only guard was a sentence telling the
operator to review before switching.

**The entry now records PROVENANCE on `appReturnAddressObserved`**, one value
per marked address, `<attribute> <address>` — ONE attribute rather than one
per family because the families are `RETURN_ADDRESS_ATTRIBUTES`, derived from
the `PROTOCOLS` table, so a family added tomorrow is covered with no schema row
of its own; the attribute name goes first because it has no space in it and the
URL takes the remainder, which is `consent.js`'s rule about the unconstrained
field. It is DERIVED and in no `EDITABLE` row.

* **What marks**: `seen()` marks an address a sighting ADDS (never one already
  on the entry — a sighting may not demote a registration), and
  `updateApplication()` marks an `add` carrying `observed: true` — the one
  caller is `oidc_rp.js`'s learning, which is a sighting in an update's shape —
  only in a mode that accepts unregistered addresses.
* **What unmarks**: `confirmReturnAddress()` (mark off, address kept),
  `discardReturnAddress()` (both off), an explicit `add` of the address with no
  flag (an operator's write is a registration), a `remove`, and an RFC 7591 /
  7592 registration naming the redirect URI. The two actions are
  `confirm-address` / `discard-address` in `admin-core/admin_actions.js`, drawn
  on the application's console page and mirrored at
  `POST /admin-api/applications/{action}`; both refuse an unmarked address by
  name (`STS-REG-0050`) rather than doing nothing.
* **What reads**: `returnAddressesOf(source, attribute)` answers `registered`
  (what the check may believe in this realm's mode) and `unconfirmed` (what it
  withheld). Development believes everything and `unconfirmed` is always empty
  there; product withholds every marked address. Both SAML profiles and
  WS-Federation hand both lists to `saml/return_address.js`, which refuses a
  withheld address with `STS-REG-0049` and a sentence naming the confirm
  operation, and `clientConfigOf()` builds `redirect_uris` from it — so the
  console's and portal's sign-in and RFC 9700 mode's exact match both see the
  same answer. `view()` lists the marks as `returnAddressesObserved`, each with
  `trusted` in the current mode.

**What it cannot do is tell an address recorded before the mark existed from a
registered one**, and it does not guess — "anything a sighting could have
written" would refuse addresses operators really did register. That half stays
a review by hand and every surface says so. `tests/return_address_provenance.js`
pins it, seventeen mutants caught.

## `appHomePageUrl`: THE ONE URL ON AN APPLICATION ENTRY THAT IS FOR A PERSON

Added 2026-09-10 for `/portal/applications`, which lists the applications a
person may be signed in to and until then named them without being able to say
where any of them was.

**IT IS DECLARED AND IS NEVER DERIVED, AND THAT IS THE WHOLE DECISION.** The
first implementation computed it from the redirect URIs already on the entry —
the ORIGIN of the first http(s) one — and it was rejected on the same
distinction the `delivery` role above is about, read the other way. Every other
URL on one of these entries is an address in a PROTOCOL: a redirect URI is where
a browser is sent back to after a hop, a delivery endpoint is where this service
posts an event, a single logout service is where a LogoutRequest goes. **None of
them is a front door.** A browser sent to a callback carrying none of the
parameters it exists to receive gets an error from the application, and the
origin above that callback is a guess that is wrong for every application served
under a path. A page whose links are right often enough that nobody checks them
is worse than a page with no links.

So it is a fact somebody STATES — by hand, from the console's `set`, from
`POST /admin-api/applications/set`, or from `register()` out of RFC 7591's
`client_uri`, which is defined as exactly this and was being recorded nowhere.
`labeledURI` (RFC 2079) was the standards-purist alternative and was not taken:
its value is a URI followed by an optional label, so holding one URL in it would
need a grammar and a parser, and it is multi-valued by definition where an
application has one home page.

**THE VALUE IS CHECKED TWICE AND BOTH ARE NEEDED.** `homePageProblem()` refuses
anything but http or https where it is written — the two doors that go through
`normaliseFields()` and `updateApplication()` — and `homePageOf()` refuses it
again where it is read, because `ldapmodify` on TCP 389 reaches this attribute
exactly as it reaches every other one here. The schemes are an ALLOWLIST rather
than a list of ones to avoid, and `javascript:` is why: this registry accepts an
entry from a dynamic client registration, so a scheme of somebody's choosing
must not be able to reach an attribute that a signed-in person's page renders as
an `href`. `portal/CLAUDE.md` argues what the page does with the answer,
including why an entry with none is drawn greyed out and still listed.

## `cors.js` and `appCorsOrigin`: AN ALLOWLIST WHERE `*` WAS (2026-09-13)

Every response carried `Access-Control-Allow-Origin: *` until this date (bar
`/oauth2/authorize` in RFC 9700 mode), so a script on any origin could read any
answer to a request that carried no cookie. rcbj asked for CORS origins on the
application objects, with an empty list allowing no third-party origin, and
answered four questions about it:

* **per client, strictly** — a request that names a client is judged against
  that client's `appCorsOrigin` and nothing else, and one naming a client the
  realm does not have gets NO CORS header: "they may just get a cors error
  rather than a real error";
* **the realm's union only where no client CAN be named** — discovery, JWKS,
  DID documents, every preflight (which has no body and no Authorization);
* **an allowlist on EVERY path**, not only the OAuth, OIDC, OpenID4VCI,
  OpenID4VP and DID ones the ask named — SCIM, GNAP, `/admin-api` and the rest
  are behind the same decision;
* **this service's own origins always**, and **both modes** — it is not a
  refusal a client under test learns from, so it is not mode-gated.

`cors.js`'s header is the argument; what a maintainer needs beside it:

**THE DECISION IS TWO MIDDLEWARES BECAUSE A `client_id` IS IN THE BODY.**
`preflight()` answers every OPTIONS where the `cors` middleware always sat, and
`response()` is below the body parsers in `app.js`, which is the first point a
form's `client_id` can be read. Moving `response()` up makes every token request
read as naming nobody — the union — which passes every test that only looks at
discovery.

**A ROUTE MUST NEVER SET `Access-Control-Allow-Origin` ITSELF.** Two did —
`/bbs/keys/1` and `/oid4vp/result/:state` set `*` — and a route's header
overwrites the middleware's, so each was an open door the allowlist could not
see. Both were removed; a third would reopen one silently.

**THE READERS DO NOT CALL `list()`.** `corsOriginsForClient()` and
`corsOriginsOfRealm()` read `allApplications()` off the directory and pick one
attribute, because `list()` builds a `view()` that OPENS every sealed signing
key — per cross-origin request. Only a request with a non-own `Origin` pays even
that.

**THE ACCESS TOKEN IS READ UNVERIFIED**, and the header says why that is safe:
a forged `client_id` only selects that client's list, and
`Access-Control-Allow-Credentials` is never sent.

**A BASIC USER NAME IS A CLIENT ON AN `/oauth2/` PATH AND MAYBE A PERSON
ELSEWHERE.** SCIM and EST accept a person's Basic credential, so off those paths
a name that resolves to no application is ignored rather than refused as an
unknown client.

**A NAVIGATION (`Sec-Fetch-Mode: navigate`) IS NOT DECIDED**, or every SAML
HTTP-POST from a service provider would log a withheld header CORS has nothing
to say about.

**GNAP'S `OPTIONS /gnap` MOVED HERE WITH IT**: it continues to its route
whatever the decision (RFC 9635 section 9), carrying the headers when allowed.

Values are normalised when written (`validation.normaliseOrigin()`: case, the
default port, IDN) and again when read, for `ldapmodify`. Refused: a path, a
wildcard, `null`, a user name — `STS-REG-0150`. A withheld preflight is marked
`STS-HTTP-0019`; a withheld header on a real request is a log line tagged
`-0020` (no client named), `-0021` (unknown client) or `-0022` (not listed),
because the request itself was answered.

**What it does not do:** accept an origin at RFC 7591 registration (no
registered client metadata member names one — it is set from the console,
`/admin-api` or `ldapmodify`), send `Access-Control-Allow-Credentials`, or
honour a wildcard. `global.corsOrigins` is the deployment's own list, for a page
it vouches for that it does not serve (the parent debugger in a test stack).
**`tests/cors.js`** drives the decision over HTTP through the real middlewares;
nothing drives it against the running container yet.

## `worker.js` and `worker_pool.js`: the computation that must not run here

Node runs this service's six listener families on ONE THREAD, so a synchronous
computation does not slow it down, it STOPS it. Post-quantum signing is that
computation — stalls of 14.6, 15.4, 17.8 and 23.3 seconds were measured on
2026-08-29 — and the cross-cutting argument and the table of those stalls are
immediately below, moved from the root `CLAUDE.md`'s *One listener process, N
stateless workers*. Everything else about the pool is here, including the
five things to know, which used to be over there.

**This service is one node process and it owns six listener families** — the
express app, the KDC on TCP and UDP 88, the Kerberos service on 8888, the LDAP
directory, two gRPC surfaces and two HTTPS endpoints. Node runs all of them on
ONE THREAD, so a synchronous computation does not slow this service down, it
STOPS it.

Post-quantum signing is that computation, and until 2026-08-30 it ran on that
thread. Stalls measured on 2026-08-29 while the parent project's suite ran:

| Stall | Operation |
|---|---|
| 23.3s | a composite `verify()` |
| 17.8s | a composite `verify()` |
| 15.4s | `signJwtAs()` SLH-DSA-SHAKE-128s |
| 14.6s | `signJwtAs()` SLH-DSA-SHAKE-128s |

For those seconds this service answered nobody, and **a KDC that does not answer
looks from the outside exactly like a KDC that is not there** — which is why not
one of the failures they caused named one. They were a Kerberos reply that never
came, a Populate button never drawn, a login screen that never arrived, and a
refresh request whose socket this service closed on its way back out. The parent
project marked two of its jobs `EXCLUSIVE` to work around it (its issue #268)
and this is what that marking was interim to.

**The design is one front process and N stateless children.** This process keeps
every socket AND ALL THE STATE; a child is handed everything it needs in the job
and hands back everything it produced.

**Workers hold no state, and that is load-bearing rather than a
simplification.** The state here is read and written ACROSS sessions, not within
one: `operatorConfig`, `realms`, the KDC `replayCache`, `digestNonces` /
`hobaChallenges` / `hobaSeen`, `principals`, the SPIFFE registry, and the tokens
this service mints — minted on one worker and introspected from another. Split
N ways those fail SILENTLY: replay detection that stops detecting, a config
change that lands on one worker of four, an introspection 404 for a token that
exists. Session affinity narrows that window; it does not close it. So nothing
is split, and **two workers can never disagree about anything because neither
remembers anything.**

**`worker.js` is the child process AND the job table**, and it is one file for
that reason: the table it exports is what the pool runs in THIS process when
`workers.count` is 0, so "a pooled signature and an unpooled one are the same
bytes" is true by construction rather than by a test that happens to pass. The
wiring that makes a process a worker is guarded on `require.main === module`, so
requiring this file to reach the table does not turn the requiring process into
a worker. FOUR jobs since 2026-09-07: `pq.sign`, `pq.verify`, `pq.generate`
and `scrypt.derive`. Each is
**synchronous on purpose** — blocking is what a worker is for, and a table of
promises would invite a second job onto a process that is already computing,
which does not make it finish sooner and makes the pool's idea of "least loaded"
a fiction.

**`worker_pool.js` is fork, route, restart and drain**, and four of its
decisions are worth knowing before changing any of them.

* **The pool is lazy and re-read per job.** Nothing is forked until the first
  post-quantum job, which is what keeps every in-process loader of this tree —
  the parent project's Kerberos jobs, `npm test`, `env/generate_defaults.js` —
  free of children they would never use. Re-reading `workers.count` on every
  call is what makes it genuinely runtime rather than runtime-in-the-table.

* **A worker is REFERENCED only while it is owed an answer, and BOTH halves have
  to be** — the child process handle and the IPC channel. This is the one that
  cost an afternoon: with the process handle left unreferenced, node drained its
  event loop the instant a worker was SIGKILLed, so the `exit` that fails that
  worker's jobs was never delivered and the promise never settled. It looked
  like a hang, and it was **LOG-LEVEL DEPENDENT** — at `debug`, bunyan's writes
  to a piped stdout were themselves enough to hold the loop open, so the same
  code passed at one level and hung at another.

* **A worker that dies FAILS its jobs, with a sentence.** A promise nobody
  settles is a request that hangs, which is the symptom this whole module
  exists to remove. The replacement is forked by the next job rather than
  immediately, and after `QUICK_EXIT_LIMIT` short-lived exits in a row the pool
  **gives up on children and computes here** — a child that cannot start is a
  broken `CONFIG_FILE` or a machine out of memory, and forking it forever would
  turn a service that works slowly into one that does nothing but fork. One
  finished job resets the count.

* **Affinity is a preference and never a correctness requirement.** A worker
  remembers nothing, so forgetting a session costs a re-route and nothing else —
  which is why the map is capped and drops its oldest entry rather than growing
  for as long as a test suite mints sessions.

**Requiring `worker_pool.js` is what arms `pq_jose.js`.** The reference is
handed down from the foot of that file, because the pool requires `worker.js`
which requires `pq_jose.js` and a require back up would close a cycle (rule 2).
The side effect is the point, and it is the same shape as rule 1 — requiring a
protocol module is what registers its routes. **A worker is never armed**,
because a child requires `worker.js` and `worker.js` does not require the pool.

`common/crypto.js` is what requires it, because that is the module that routes
an `alg` to `pq_jose.js` in the first place. `crypto.js` gained
`signJwsAsync()`, `verifyCompactJwsAsync()` and `verifyJwsAsync()` beside their
synchronous namesakes rather than in place of them: every other caller in this
service verifies RS256 in microseconds and has nothing to gain from a promise.
`verifyCompactJws()` was split into `prepareVerification()` / `verifyBytes()` /
`finishVerification()` so that both entry points run the same reading of the
token and refuse in the same ORDER — a token whose `alg` is not in the caller's
list is refused for that and never for its signature, whichever was used.

### `scrypt.derive` is the fourth job and the first that is not post-quantum (2026-09-07)

It earns its place on the same measurement the other three do, with a different
shape. `crypto.js` sets scrypt's N to 2^15 deliberately, so **one password hash
or one verification measured 68ms on this machine** — and for those 68ms this
process answers nobody: not the next HTTP caller, not the KDC on port 88, not
the LDAP socket. That is not the 14.6 seconds an SLH-DSA signature costs, and it
is paid FAR more often: **once per authentication, in five protocols** — the
sign-in screen, an LDAP bind, SCIM Basic, WS-Trust and the portal's password
form — rather than on the few signatures a client points at a post-quantum
algorithm.

Measured with ten hashes back to back, with a 5ms heartbeat running: the
synchronous path took 616ms wall and **the event loop ticked zero times**; the
pooled path took 154ms and it ticked 29. The wall-clock difference is the five
workers computing at once; the tick count is the whole point.

**THE JOB IS A PRIMITIVE AND HOLDS NO POLICY, AND THAT IS WHAT LETS IT BE THERE
AT ALL.** `crypto.js` remains the one place this service decides the cost
parameters, the stored form, how it is parsed and how the comparison is made,
and NONE of that is in `worker.js`. Every parameter travels in the job, exactly
as `pq.sign` is handed the key it is to use.

**The reason it must be that way round is a hard constraint rather than
tidiness.** `crypto.js` requires `worker_pool.js` — that require is what arms
the pool — so a worker that required `crypto.js` back would reach the line at
the foot of `worker_pool.js` and **start forking children of its own**. So the
derivation is written out in `worker.js` against node's own crypto, which that
file may require freely because it is a leaf. It is also why `crypto.js` hands
the pool this job DIRECTLY rather than through `pq_jose.js`: a scrypt
derivation is not a JOSE operation, and routing it there would have put a
password in a file about post-quantum signing.

### The cost of a NEW hash is a setting, and nothing already stored moves (2026-09-12)

`security.passwordHashLogN`, `…R` and `…P` replace the three constants for what
the NEXT hash is written under; the constants are the defaults and N's floor is
2^14, clamped here as well as refused by the settings table, because the one
thing this file must never do is write a hash cheaper than it promises. N is set
as its logarithm because scrypt accepts only a power of two. **Every stored hash
keeps verifying** — `$scrypt$N$r$p$salt$hash` names its own parameters, which is
why the stored form was made self-describing — and the worker-pool job is handed
the parameters read ONCE, so the encoded value always names the cost the
derivation really used. `tests/password_policy.js` pins both halves.

### The four scrypt functions are one implementation with two doors

`hashSecret` / `hashSecretAsync` and `verifySecret` / `verifySecretAsync` in
`crypto.js`, and `verify` / `verifyAsync` in `credentials.js`. **This is the
same split `verifyCompactJws()` already makes** — `prepareVerification()` /
`verifyBytes()` / `finishVerification()`, described above — and it is made for
the same reason: so that both entry points run one reading of the input and
refuse in the same ORDER.

In `crypto.js` the shared halves are `encodeStoredSecret()` and
`decodeStoredSecret()`, so `$scrypt$N$r$p$salt$hash` has one definition and a
value written through either door verifies through either door. In
`credentials.js` the shared halves are `verifyPrepare()` and `verifyFinish()`:
**everything decidable without computing scrypt is decided in the first** — the
reserved refusal, development mode, a missing name, a missing store, a store
that threw, nobody by that name, a stored form this service did not write — and
those are the overwhelming majority of refusals, none of which costs 68ms. An
async door with its own copy of those seven refusals is exactly the shape that
file exists to prevent: `verify()` is the one place a presented password is
checked, and two copies of "when do we say no" would eventually say it in two
different sets of circumstances.

**THE SYNC DOORS ARE KEPT AND ARE NOT DEPRECATED.** `workers.count = 0` is a
supported configuration, the parent project loads this tree in process, and a
caller that cannot be made asynchronous is better off blocking than wrong.

**WHAT IS NOT DONE YET, SAID PLAINLY: no protocol surface calls the async door.**
Eleven call sites still reach the synchronous one — `scim/scim_auth.js`,
`authn/authn.js`, `ldap/ldap_server.js`, `ws-trust/wstrust.js`, `portal/portal.js`
(three) and `admin-ui/admin.js` (four) — and every one of them needs its
enclosing handler chain made asynchronous first. That is not incidental: it is
the same prerequisite the whole move-request-processing-to-workers plan needs,
so it is phase 1 of that plan rather than eleven separate conversions, and
converting some of them now would leave one policy behaving two ways across
five protocols.

### Five things to know before touching any of it

**These moved here from the root `CLAUDE.md` when that file was broken up.** The
root keeps what is genuinely cross-cutting — that this process owns six listener
families on one thread, and the stalls that measured — and this is the rest.

1. **NOTHING IS FORKED UNTIL THE FIRST POST-QUANTUM JOB.** A process that never
   signs one never pays for a pool, which is what keeps the parent project's
   in-process Kerberos jobs, this repository's own `npm test` and
   `node env/generate_defaults.js` free of children they would never use and
   would then have to wait for. It also makes `workers.count` genuinely runtime:
   the pool is reconciled with the setting on the NEXT job, so raising it forks
   the difference and setting it to 0 drains the pool and computes here.

2. **`workers.count = 0` IS A SUPPORTED CONFIGURATION AND PRODUCES THE SAME
   BYTES.** The pool runs the SAME job table in this process — `worker.js`
   exports it, and the child wiring below it is guarded on
   `require.main === module` — so "a pooled signature and an unpooled one agree"
   is true by construction rather than by a test that happens to pass. Nine of
   the eleven algorithms sign deterministically and `tests/worker_pool.js`
   asserts byte equality for those; the three composite ECDSA ones cannot be
   equal (node's ECDSA is randomized, and it must be) and are held to
   cross-verification instead.

3. **REQUIRING `common/worker_pool.js` IS WHAT ARMS `common/pq_jose.js`.** The
   pool requires `worker.js`, which requires `pq_jose.js`, so pq_jose.js cannot
   require the pool back without closing a cycle (rule 2) — the reference is
   handed DOWN, from the foot of worker_pool.js. That also means **a worker
   process is never armed**, because a child requires worker.js and worker.js
   does not require the pool: `signAsync()` inside a worker computes in the
   worker, which is what a worker is for and what stops a child forking a pool
   of its own. `common/crypto.js` filled that slot for one afternoon, and a
   process that required pq_jose.js WITHOUT crypto.js then computed everything
   in itself while reporting no pool and no error.

4. **FOUR CALL PATHS ARE ASYNCHRONOUS BECAUSE OF THIS AND NO OTHERS.** They are
   the four a CLIENT can point at a post-quantum algorithm: the ID Token
   (`id_token_signed_response_alg`), the signed UserInfo response
   (`userinfo_signed_response_alg`), a `private_key_jwt` client assertion, and
   an OID4VCI proof of possession — plus the JWKS, which is where a realm's
   eleven post-quantum keys are GENERATED. Everything else still signs and
   verifies synchronously on purpose: an RS256 signature is microseconds, and an
   IPC round trip to save that would be a cost with no saving. The token
   endpoint and `issueAuthorizationResponse()` became `async` as a consequence,
   and the token endpoint is now registered through **a wrapper that catches** —
   express 4 does not look at what a handler returns, so an `async` handler's
   throw is an unhandled rejection and a request that hangs where it used to be
   a 500.

5. **A REALM MAY NOT CARRY `workers.count`.** It is the first setting marked
   `perProcess`, which is a SECOND rule beside the `realms.*` prefix rather than
   the same one spelt twice: a pool belongs to the OS process, and one realm
   resizing it would resize every other realm's too. Both ends go through
   `config.isPerProcess()` — the reading end in `config.js`'s `realmFor()` and
   the writing end in `realms.js`'s `checkRealmOverride()` — because the two
   ends of the `realms.*` rule were written separately and disagreed within the
   hour.

**A REALM'S ELEVEN KEYS ARE MADE WHEN THE REALM IS**, and that is the pool's
second consequence rather than a sixth thing to know about it. One of the
eleven is expensive out of all proportion: an SLH-DSA-SHAKE-128s KEY GENERATION
is about 5.1 of the 5.8 seconds the whole set takes, and it is one indivisible
job that no pool size divides. That put a realm's first JWKS fetch a little
over five seconds — and `federation.outboundTimeoutMs` is FIVE, deliberately,
because a browser is waiting on that request.

It never failed, and why it never failed is the part worth keeping: while the
generation was SYNCHRONOUS it blocked this process's event loop, so the timer
enforcing that budget could not fire until the keys were already made. **The
response won a race the timeout was never allowed to run in.** The moment the
computation moved to a worker and the loop stayed free, the timer fired
correctly at five seconds and aborted a fetch three tenths of a second from
finishing — one federated sign-in in the parent project's suite, reporting
"the JWKS could not be fetched", which is a sentence about a service that was
working perfectly.

So `helpers.js` warms a realm's post-quantum keys on `realms.onChange`'s
`create`, through `stsKeysFor.of(id)` because a watcher has no ambient realm.
That was not affordable before — eager generation meant 5.8 seconds of a
stopped service per realm, which is exactly why they were lazy — and it is the
point rather than a workaround: **the pool does not merely move the cost off
the request that pays it, it makes paying it EARLY free.** Measured: a realm
created through `/admin-api/realms/create` answers its first JWKS in 8ms.

`tests/worker_pool.js` has the four contracts and the measurement that shows the
loop is free.


## `protocol_stack.js`: THE REQUIRE ORDER MOVED OUT OF `server.js` (2026-09-07)

**This moved here from the root `CLAUDE.md` when that file was broken up.**

**The order is unchanged and the root `CLAUDE.md`'s require-order table is
still the index of it.** What changed is where the sequence LIVES, and it moved
for one reason: it acquired a second reader.

`server.js` loads that file and then binds the sockets. **`common/request_worker.js`
loads the SAME file and binds none of them** — it is a child process that runs
the service and answers HTTP on a unix socket the front process proxies to. A
second copy of the require order would be a second answer to "which handler
wins", and the two processes would disagree in exactly the cases hardest to see:
a route registered before a middleware in one and after it in the other.

The five modules that own listeners are returned rather than merely required,
because `server.js` needs the handles for `listen()`. Requiring them still
registers their HTTP views and starts nothing — which is a separation that
predates this change by a fortnight, made for a different reason (binding can
fail and a `require` that throws takes the process down), and is what makes a
request worker possible at all.

## `request_pool.js` and `request_worker.js`: THE SECOND POOL, AND IT IS A DIFFERENT KIND OF WORKER

**This moved here from the root `CLAUDE.md` when that file was broken up.** The
family-specific halves — the directory's operations and its sockets, SPIFFE's
gRPC seam, the TLS listener certificate and the truststore pin — are argued in
`ldap/CLAUDE.md`, `spiffe/CLAUDE.md` and `tls/CLAUDE.md`, and are named here only
where the pool-level rule needs them.

| | `common/worker_pool.js` | `common/request_pool.js` |
|---|---|---|
| A worker runs | a JOB TABLE — four leaf computations | THE SERVICE — the whole protocol stack |
| Handed | everything the job needs | an HTTP request |
| Speaks | the IPC channel, structured clone | real HTTP over a unix socket |
| Forked | LAZILY, on the first post-quantum job | EAGERLY, before the listener binds |
| Setting | `workers.count` (5) | `workers.requestCount` (0) |
| Off by default | no | **yes, and nothing is dispatched until `workers.dispatch` names a path** |

**The goal of the second one is one sentence: the front process should be doing
request/response I/O and nothing else.** The first moved four computations off
that thread; every handler still ran on it.

**ROUTING IS THE PART TO GET RIGHT AND THE CUT IS NOT THE OBVIOUS ONE.** It is
**sessionless versus session-bearing**, not stateless versus stateful.
`workers.fanout` names the exceptions and everything else dispatched holds
affinity, which is the right way round: a protocol subsystem carries a browser
flow across several requests and belongs on one worker, and the surfaces that do
not are few enough to write down — `/scim`, `/xacml` and `/admin-api`, each
carrying its own credential per call and naming its own target.

**EVERYTHING UNDER `/admin` IS THE CONSOLE AND HOLDS AFFINITY, `/admin/ldap/*`
INCLUDED.** Those pages are pages somebody reads while signed in; the fact that
what they draw is the directory does not make them the directory's protocol.
Keeping them apart from `/admin-api` is not automatic either — a bare prefix
match makes `/admin` match `/admin-api`, which would put the management API on
the affinity side silently. A prefix ends at a SEGMENT BOUNDARY, and
`tests/request_routing.js` fails if it stops doing so.

**AND THE LDAP PROTOCOL IS DISPATCHED TOO, AS AN OPERATION — REALLY DISPATCHED
SINCE 2026-09-12** — and SPIFFE'S TWO gRPC SURFACES are the second family, the
same day. `ldap/CLAUDE.md` (the operation channel, the three days nothing filled
it, and why an operation holds affinity to its CONNECTION) and
`spiffe/CLAUDE.md` (forty-two of forty-seven methods, the five server streams
that do not cross, and the channel forked `serialization: 'advanced'`) argue
them.

The same mechanism is what the KDC would use, and what the first two families
cost is the index of what a third one owes: a request shape and a result shape,
an error that crosses as a NAME or a CODE rather than as a rebuilt table, a
decision about what may not cross (`unbind` may not, because it ends a file
descriptor; a server stream may not, because it is a subscription), and a test
comparing a dispatched answer with the same handler called directly.
`ldap/CLAUDE.md` and `spiffe/CLAUDE.md` argue them.

**AND ONE RULE CAME OUT OF THE SECOND FAMILY THAT THE FIRST DID NOT FIND: THE
WORKER TABLE IS FILLED ONLY IN A WORKER.** Requiring `common/request_worker.js`
pulls `common/service_state.js` in at module scope — the store, the keys, the
minted rows, coordination — so registering from the front process buys a table
nothing there will ever read with a load of half the service's startup
machinery. It was unconditional for ten minutes and `tests/spiffe_pki.js` went
red in the suite while passing alone, because `run.js` runs every file in one
process and the new require changed what a later file saw of the certificate
hierarchy. Both families gate on `STS_REQUEST_WORKER` now.

Those surfaces are emphatically NOT stateless — SCIM and LDAP writes mutate the
directory every other family reads — but that is a question about the state
channel and not about which worker answers.

**AFFINITY IS A LOCALITY MEASURE AND NEVER A CORRECTNESS ONE.** Of the stores
this service keeps, only the sign-on sessions and the pending authentication
records are per-session. The rest are read by a request other than the one that
wrote them.

**A WORKER IS ANOTHER PROCESS AGAINST THE STORE, AND THAT IS THE STATE
CHANNEL.** There was nearly a second mechanism here. There did not need to be:
this repository already built *several processes against one store* —
`persistence/persistence_replication.js`, five appliers, a change log that is
the contract and a notification that is only latency — and **a request worker is
exactly one more such process.** So a worker runs `common/service_state.js`, the
same four startup steps `server.js` runs and from the same file: the store, the
signing keys, the minted rows, and COORDINATION. What makes dispatch correct is
that last step, not anything written for the pool.

**AND THERE IS EXACTLY ONE THING THE STORE CANNOT CARRY, WHICH IS WHY THE
SENTENCE ABOVE NEEDED A SECOND MECHANISM AFTER ALL (2026-09-09): A SOCKET.**
In LDAP the connection IS the session — RFC 4511 section 4.2 — so the only
sign-out that protocol has is a file descriptor being closed, and a file
descriptor belongs to the process that accepted it. The front process holds
every LDAP connection and a worker holds the session that decides one should
end. `ldap/CLAUDE.md` argues both halves — the list going OUT as a snapshot and
the instruction coming BACK on the response — and
`common/request_pool.js`'s `LDAP_DROP_HEADER` argues the ordering.

**AND A THIRD THING THE POOL HAD TO LEARN, WHICH IS NEITHER A SOCKET NOR A
ROW: A REALM'S SIGNING KEYS ARE MADE ONCE (2026-09-12).** See *THE REALM WATCHER
ASKS AND DOES NOT TAKE* under 3ab below.

**AND A FOURTH, WHICH IS A QUEUE AND NOT A ROW EITHER: THE WORKER SOCKET'S
LISTEN BACKLOG.** `sts_directory_bulk_load_scim` answered `4999 of 5000` with
one `502 … connect EAGAIN /tmp/sts-workers-*/w2.sock` — **a request that never
reached a worker**, told in the 502's own words that it could simply be made
again. EAGAIN from an AF_UNIX `connect()` is the listen backlog being full, and
the front process opens a connection per dispatched request while the whole
suite runs at once. `bindSocket()` takes an explicit backlog now.

**AND THE FRONT PROCESS BOUNDS ITS END, WHICH IS A SEPARATE CHANGE AND NOT THE
FIX FOR THAT.** Dispatch used node's global agent, `maxSockets: Infinity`; each
worker has an agent of its own now, capped by `workers.maxSockets`. That job
issues its five thousand creates ONE AT A TIME, so no per-worker cap was near
being reached by it — an unbounded proxy in front of a single-threaded worker
is simply a bug on its own account. **The cap must not be small**: this service
makes requests to itself, so a worker whose connections are all held by
requests awaiting a reentrant call needs one more to make progress.

**THE RULE THAT COMES OUT OF IT** is worth more than the mechanism: a store is
shared by coordination, and anything that is NOT a row in a store — a socket, a
timer, a listener — is held by one process and reachable from no other. There
is one such thing today. A second would need this argument made again rather
than this mechanism copied.

**THE SECOND ARRIVED ON 2026-09-12 AND IT TOOK THE ARGUMENT RATHER THAN THE
MECHANISM, WHICH IS WHAT THAT SENTENCE ASKED FOR: THE TLS LISTENER
CERTIFICATE.** The directory needed a MIRROR pushed out and an instruction sent
BACK; here the decision is the front process's ALONE, so nothing comes back and
what goes out is the RESULT. `tls/CLAUDE.md` argues both halves,
`common/request_pool.js`'s `reconcileTheListener()` is the caller, and
`tests/worker_server_certificate.js` pins it. **THE THIRD IS THE
CLIENT-CERTIFICATE TRUSTSTORE'S GATED DOORS (2026-09-12), AND IT TOOK THE
SIMPLER OF THE TWO SHAPES: A PIN** — `request_pool.js`'s `NEVER_DISPATCHED`;
`tls/CLAUDE.md` argues it. The suite's own blind spot one layer out is
`tests/CLAUDE.md`'s.

**DISPATCH WITHOUT COORDINATION IS REFUSED, AND THE SERVICE DOES NOT START.**
Everything else about the pool degrades — no workers means the front process
does the work, a dead worker is a 502, a pool that gave up handles everything
here — and all of those leave a service that is correct and slow. This one
leaves a service that answers WRONGLY, which was measured before the guard
existed: `/admin-api` across three workers with a memory store, one setting
written, six reads, and the fifth returned the value from before the write.
Nothing errored and nothing logged. So it is fatal, with a message naming both
ways out, on the same argument `persistence.start()` makes about a store it
cannot open.

**WITH COORDINATION ON IT WAS MEASURED AGAIN AND IT HOLDS.** Three workers
against one PostgreSQL store: a setting written through one worker and read back
twelve times gave `1500 override` twelve times, with the thirteen requests
fanned 5/4/4 across all three; a person created over SCIM in one worker was
found by all three, 9 reads out of 9. **Convergence is 0.5–1.0s** — the change
log with `LISTEN`/`NOTIFY` doing the work and the five-second poll as the
backstop.

**CONVERGENCE IS NOT READ-YOUR-WRITE, AND `workers.readYourWrite` IS THE
DIFFERENCE.** With it off — the default — a caller that writes through one
worker and immediately reads through another may be answered by one that has
not caught up. Measured across three workers, writing and reading over SCIM
with no pause: **20 of 40 could not read their own write.** With it on: **0 of
40.**

The mechanism pays on the READ side. The obvious fix — make every write wake
every worker and wait — was rejected because it charges every write for a read
that mostly never happens; a bulk load of five thousand entries would pay it
five thousand times for one read-back. Instead the pool keeps a GENERATION,
bumped when a request that may have written finishes, and a worker that is
behind pulls before it answers. So the cost falls on the first read after a
write on each worker, and on nothing at all while nothing is being written.
**What counts as a write is the METHOD**, which is conservative on purpose: the
front process is proxying bytes and cannot know whether a POST changed
anything, and an occasional unnecessary pull is the error worth making.

Measured cost, three workers on one PostgreSQL store: 37ms to 43ms per read and
30ms to 37ms per write. **It is OFF by default** because that is the behaviour
that existed before it, and because whether the wait is worth it is a question
about the callers rather than about the pool.

**THE BARRIER HAS A SECOND HALF — THE TICKETS — AND A 502 WEDGED IT FOR THE
LIFE OF THE PROCESS (2026-09-11).** The generation says whether a worker is
BEHIND; the tickets say whether everything already ANSWERED has actually
landed, which no generation can express because the generation does not move
until it has. Each dispatched request takes a ticket; it ARMS when the front
process has piped that response out; it CLEARS when the worker that answered it
announces its flush covered it. `proxy()` armed the ticket on
`upstream.on('error')` as well — the path where the worker never answered and
the client is handed a **502** — and the worker, never having run the handler,
announces nothing ever. So that ticket stayed armed for good and **every read
after it waited the full 2,000ms bound and then served stale anyway.**

It is a cliff and not a slope, and the measurements are the reason this is
written down rather than fixed quietly: a service 41 minutes idle with 5,521
stuck tickets, `GET /admin-api/ldap/directory?per=1` taking 2.6s, and all four
bulk-load jobs failing on a **10-second CONNECT timeout** rather than on any
assertion — the SCIM one got through 536 of 5,000 creates in 405s, against 93s
for all 5,000 in the `postgres` mode. After the fix, 22ms per create and 45/s.

**NOTHING COULD SEE IT**, which is the part worth keeping. Every answer was
correct. The only signal was the line the barrier prints when a flush is merely
slow, so a wedged pool and a busy one read identically. `pool.stats().tickets`
gives the state a name now — in the pool's own report, which no console page
draws, so the thing that makes it VISIBLE is the second half: a ticket armed
for thirty seconds with no worker explaining it is REAPED, with a line naming
both causes that reach it — on the
argument that a reader who timed out was served without it, and so is every
reader after, so dropping it changes no answer and removes the wait.
`common/request_pool.js`'s `ticketAbandoned()` carries both halves and
`tests/request_barrier.js` pins them.

**AND A SECOND CLIFF IN THE SAME BOOKKEEPING, 2026-09-13: A READER THAT TIMED
OUT NEVER LEFT THE WAITER LIST.** The 2,000ms bound resolved a waiter and left
it in `ticketWaiters` for as long as its tickets stayed armed, and every release
walked every waiter against the whole outstanding set — O(waiters × in-flight)
per commit announcement, 980ms of blocked event loop measured for 10,000 × 6,000.
The `dispatch` run that found it: a session sweep's CAEP storm put 5,752
loopback pushes in flight, the front process logged nothing for three minutes,
one SCIM create went unanswered for 300s (undici's headers timeout — the
`fetch failed` in `sts_directory_bulk_load_scim`) and 6,479 pushes died
together at the server's own 300s request timeout. A settled waiter is dropped
now, the blocking ticket is computed once per worker over the FINISHED set, the
barrier's syncs are one round per worker shared by every reader it covers (5,759
had been outstanding at one worker, holding the store's pool), a proxied request
whose client left is released instead of staying queued behind
`workers.maxSockets`, and the two barrier timeouts log once a second with a
count. `tests/request_barrier.js` sections 6–9.

**THE WORKERS HAD THE OTHER HALF OF IT, AND SO DID EVERY POSTGRES PROCESS.**
`persistence.flush()` answered a caller arriving during a flush with a waiter of
its own, and a postgres store has a caller per WRITE — so waiters re-chained on
every commit and never drained under load. It is what killed the single-process
`postgres` service under `sts_directory_bulk_load_ldap_50k` (heap out of memory;
`fetch failed` on the read-back) and what grew the dispatched workers past 7 GB.
`persistence/CLAUDE.md` carries it.

`persistence_replication.js`'s `syncNow()` is the barrier itself, and it is a
different shape from `pull()` beside it on purpose: `pull()` returns at once
when a catch-up is already running, which is right for a timer and useless for
a caller that needs to know it is up to date.

**AND THE GENERATION MOVES FOR THIS PROCESS'S OWN WRITES TOO, SINCE
2026-09-09 — IT DID NOT, AND THAT IS A SECOND BUG OF THE SAME FAMILY AS THE
LDAP ONE ABOVE.** It was bumped in exactly one place: a WORKER announcing that
its flush had committed. That is the whole story for the dispatched HTTP port,
and **this process answers on five more socket families that are never
dispatched** — the two TLS listeners (which have a handler of their own rather
than going through `app`), the directory, the KDC and SPIFFE's gRPC pair.
Everything minted there is written by the front process, and no worker was ever
marked stale for it.

The symptom was a sign-out that left a session behind. A verified client
certificate on 9443 starts a sign-on session; the session is minted here,
`/logout` is answered by a worker, and that worker's copy of the session store
had never heard of it — so a global sign-out reported ending everything and
left a live way in. **It is intermittent by construction**: the worker gets
there on the replication poll, so whether the sign-out is correct depends on
how long the run took to reach it, which is why it failed once in a three-mode
run and passed when the same job was run alone.

The signal is `persistence.changeRowsWritten()`, sampled at DISPATCH and
compared with the last value seen. It counts rows COMMITTED to the change log,
so it moves only when there is something a worker can actually pull — the same
contract `receiveCommitted()` keeps for a worker. It is sampled rather than
pushed from the writer because the alternative is five socket families each
learning about this pool. `tests/front_process_writes.js` pins the decision,
which is a comparison of two integers.

**THE TWO FIXES TOGETHER ARE THE RULE**: a store is shared by coordination and
a socket is not, so anything the front process holds needs a mechanism of its
own — the LDAP connection needed a mirror and an ask, and everything the front
process MINTS needed the barrier to know it had. Neither was found by reasoning
about the design; both were found by one job in one mode.

### A SECOND POOL FOR THE CONSOLE AND THE PORTAL (2026-09-13)

`workers.surfaceCount` workers kept for this service's OWN two hosted
surfaces — `workers.surfaces`, default `/admin,/portal` — beside the
`workers.requestCount` workers that run the protocols. The console and the
portal are pages a person is waiting on, and with one pool they queued behind a
SCIM bulk load or a CAEP storm on the same workers; a console page walking the
directory held a protocol worker the other way round. It is off by default (0),
and with it off those paths go wherever the rest of `workers.dispatch` goes.

**WHICH POOL, NOT WHETHER.** `workers.dispatch` is still the one list of what
leaves the front process (the 2026-09-12 merge argues why there is one), and
`poolFor()` is asked only after `dispatched()` has said yes. The same
`matchesAny()` decides it, so the realm segment is stripped and `/admin` stops
at a segment boundary: **`/admin-api` stays with the protocols**, so that a bulk
load through the management API cannot hold the console. The console's and the
portal's own Shared Signals receivers go with their surfaces, which is what
takes a CAEP storm's loopback pushes off the protocol workers that sent them.

**ONE TABLE OF WORKERS, AND ONLY ROUTING IS PER POOL.** A surface worker loads
the same stack and runs the same four startup steps; it is one more process
against the store. So everything that keeps PROCESSES agreeing stays global and
walks the one `workers` array — the barrier's generation and tickets (a write
answered in either pool must make both stale), the key registry, the PKI and
listener-certificate broadcasts, the directory's connection list. What each pool
has of its own is its size, its affinity map, its routing cookie
(`sts_pool` for the protocols, unchanged; `sts_pool_surfaces`) and whether it
gave up. **The maps have to be two**: one browser holds a worker in each pool
under the same session cookie, and one map would re-bind that key on every
crossing. **So do the cookies**: a pin names one pid, and with one cookie every
browser pinned to a surface worker would share one key in the protocol pool's
map, which funnels them all to one protocol worker. Operations (LDAP, SPIFFE)
use the protocol pool only.

**THE BACK CHANNEL IS WHAT HAD TO CHANGE OUTSIDE THIS FILE.** `oidc_rp.js`
redeems the console's code by dialling this service's own token endpoint, and
since 2026-09-07 it named its OWN pid in `sts_pool` so the request reached the
worker holding the code. In a surface worker that pid is no protocol worker.
The front process holds the binding the browser's session cookie has in the
protocol pool, so on every request to a SURFACE worker it looks that worker up
(`heldWorker()`, which binds nothing) and sends its pid in
`x-sts-pool-protocol-worker`, stripped from what the client sent.
`request_worker.js` puts it on `req.stsProtocolWorker`, every `backChannel()`
call passes `from: req`, and a worker forked with
`STS_REQUEST_WORKER_POOL=surfaces` pins to that pid instead of its own. No hint
means no pin: the request is routed by load, which is correct under the barrier.

**AND IT CANNOT START WITHOUT `workers.readYourWrite`** (`STS-WORKER-0038`,
fatal, raised after the coordination guard). With one pool a console sign-in
minted and read everything on one worker. With two, `/admin/callback` runs in a
surface worker and reads a sign-on session a protocol worker minted
milliseconds earlier, and every later console page checks that parent is alive.
Coordination gets it there in 0.5–1.0s and a browser, or the suite, is faster,
so the console would fail to sign in, or sign in and end the session as an
orphan, intermittently. That is `start()`'s own reason for refusing dispatch
without coordination, one layer in. A surface pool whose prefixes nothing
dispatches is the other case and is only a warning (`STS-WORKER-0039`): those
workers would receive nothing, so they are not forked. **A surface pool that
gives up** hands its paths to the protocol pool rather than to the front
process, because that is what `surfaceCount=0` means.

### THE BATCH LANE (2026-09-14)

**Batch traffic may use a share of a pool's workers and a number of requests in
flight, and waits in the front process for the rest.** A `dispatch` run's SCIM
bulk load — one write at a time, each pushing two Shared Signals events back
into this service's own receivers — filled every worker; the read barrier waited
on workers that could not answer, and nothing was answered for fourteen
minutes. rcbj asked for batch throughput balanced against everything else.

* **`workers.batch`** names the batch paths (default `/scim` and the console's
  and portal's `…/signals/receive`), matched like every other prefix list.
* **TWO LIMITS, because one cannot do both jobs.** `workers.batchWorkerShare`
  (50%) confines an UNBOUND batch request to the first workers by fork order —
  at least one, and fewer than the pool below 100% — which is what leaves
  workers free in a pool of several. `workers.batchConcurrency` (8 per lane
  worker) caps what is in flight, which is what protects a pool of ONE (the
  suite's surface pool), where no share leaves anything free.
* **A BOUND REQUEST KEEPS ITS WORKER.** `workerFor()` asks for the key's held
  worker before the lane narrows a new choice, because `mutationKeyOf()`'s
  resource binding is what stops two read-modify-writes of one SCIM resource
  losing an update. The cap QUEUES rather than reroutes.
* **What waits is a closure, not a buffered body**, bounded by
  `workers.batchQueueLimit` (5000, then 503 `STS-WORKER-0040`) and
  `workers.batchQueueTimeoutS` (60, then 503 `STS-WORKER-0041`), both with
  Retry-After and logged through `warnSparingly()`. A client that leaves is
  dropped from the queue. `stats().batch` reports each pool's lane.

`tests/request_batch_lane.js` pins it, four mutants caught and one equivalent
removed.

### A RATE-LIMIT COUNT IS WRITTEN DOWN EVERY TIME IT MOVES (2026-09-14)

`websecurity.js`'s buckets are a persisted `sharedMap()`, and `attempt()` set a
bucket on its first failure and then did `row.count += 1` on the row it held —
so only the FIRST failure was journalled. In the request-worker pool every
worker kept its own count, a caller spreading guesses across three workers was
never refused, and `sts_est_enrollment` in `dispatch` mode got 401, 401, 401
where the third must be 429, two runs in a row. The row is `set()` again after
every increment, and the read barrier then makes the next request see the
count. Two concurrent attempts can still both read the older count: the limit
holds to within one caller's concurrency. `tests/rate_limit_replication.js`
pins it. **Where a store is shared, that row is no longer the count at all** —
see *Several nodes: one rate-limit budget* at the end of this file.

`tests/request_routing.js`'s `checkTheSurfacePool()` pins the pool choice, the
cookies, both startup checks and, as source, the three files that must agree on
the hint. It was mutation-tested against eight mutants and caught all eight. The suite's
`dispatch` mode runs one surface worker (`tests/tools/modes.sh` says why one),
and `docker-compose.yml` defaults to TWO since 2026-09-13 (it was one): one
worker behind both surfaces meant a slow console page held every portal page
and every console sign-in callback, and its death sent both surfaces to the
protocol pool until the re-fork. The setting's own default stays 0, because a
non-zero one would require dispatch and read-your-write of every
single-process run.


## `realms.js`: several logical copies of this service, in one process

A **trust realm** is a whole mock identity service — its own configuration, its
own signing key, its own sessions, authorization codes, tokens, offers,
artifacts, statistics and audit log — answering on the SAME sockets as every
other and told apart by a segment at the front of the path:

```
http://host:8081/oauth2/token                the DEFAULT realm
http://host:8081/realm/acme/oauth2/token     the realm `acme`
```

**THE DEFAULT REALM HAS AN EMPTY PREFIX AND THAT IS THE WHOLE CONTRACT.** A
service with no realms defined behaves exactly as it did before this module
existed — nothing is stripped, no URL is rewritten, no store is partitioned
differently, no page grows a control. That is a property of ONE predicate,
`active()`, rather than a claim spread over twenty files, and it is what keeps
every test, container and client that predates realms working unchanged. It is
the first thing to check if something here ever seems to have changed for a
caller that has never heard of realms.

`/admin/realms` defines them, `POST /admin-api/realms/create` does it without a
browser, and `GET /realms` is the ungated directory a client discovers them
from. The console carries a realm switcher on every page and shows ONE realm at
a time — including every settings form, which reads AND WRITES the realm it is
reached in.

### Forty modules became realm-aware without being edited

The obvious implementation threads a realm argument through every function that
reads a setting, mints a token or touches a store — several hundred call sites,
every one of them a chance to drop the argument silently. A token minted for the
wrong realm looks exactly like a token minted for the right one.

So the realm is **AMBIENT**, held in an `AsyncLocalStorage` that `app.js`'s front
middleware enters for the whole life of a request. Four consequences, and they
are why this module is short:

* **`config.value(key)`** consults the current realm's overrides first, so every
  one of the 200-odd setting reads in this service is realm-aware where it
  stands. Rule 3m, below.
* **`helpers.baseUrlOf(req)`** appends the realm's prefix, so every issuer
  identifier, metadata document, entityID, `did:web`, DPoP `htu`, redirect and
  form action this service builds names the realm it was built in. That one line
  brought eighty call sites with it.
* **`helpers.STS`** is a Proxy onto the CURRENT realm's key set, generated
  lazily. Eight modules destructure it and read `STS.kid`, `STS.certPem`,
  `STS.privateKey`; not one of them changed.
* **A store declared `realms.map()`, `realms.arr()` or `realms.obj()`** is
  partitioned by realm behind an unchanged Map/Array/Object interface, so
  converting one was a one-line edit at the declaration and no edit at all at its
  hundred readers.

**The middleware that enters it is `app.js`'s FIRST.** That middleware also
strips the prefix before the router sees the URL, which is why no route
registration in this service carries a realm and no protocol module was edited.
**Nothing may be registered above it.**

`AsyncLocalStorage` is the right primitive rather than a convenient one. A
request here is a chain of awaits and callbacks — an LDAP search, an RSA
signature, a gRPC call — and a module-level `currentRealm` variable would be
correct only until two requests for two realms overlapped: correct in every test
and wrong in every use, with the failure being a token signed with another
realm's key under load and nothing else.

**The one place it does not propagate is an EventEmitter listener**, which runs
in the async context of whatever emitted the event rather than the one it was
added in. `app.js`'s call log and audit row are written through a function bound
to `req.realm` EXPLICITLY. It is not belt and braces: without it the statistics
land in whichever realm the process happened to be in, which under load is a
different one. **Since 2026-09-14 (#46) that function runs in `res.end()`, not
from `res.on('finish')`** (which only catches a response that bypassed `end()`),
so the rows are in the journal when the cluster barrier decides whether to hold
the response — `cluster/CLAUDE.md`, *The barrier*.

**And a path naming a realm this process does not hold is caught up first on an
active-active node** (2026-09-14, #46): the realm middleware runs above the
cluster barrier, so a realm created on node A was a 404 on node B's first
request (2 of 6). When `clusterBarrier.isActive()` and
`realms.unknownRealmPath()` both say so, the middleware runs the barrier
(`syncShared()`), matches again, and falls through to Express's own
`Cannot GET` only if the realm still does not exist; it tells the barrier
middleware (`markSynced()`), so the request catches up once. With an empty
`realms.pathSegment` the first segment of every registered route is excluded, or
every mistyped path would cost a round trip.

**`realms.arr({ persist, segment: N })`** (2026-09-14, #46) stores an array in
rows of N elements keyed by ABSOLUTE position instead of one whole-array row —
for a ring appended at one end and trimmed at the other, and nothing else. A
push rewrites one segment; a shift writes nothing until a whole segment has
left; anything that renumbers rewrites every segment. A stored copy can carry up
to N-1 elements the owner already dropped, so the reader trims (`audit.js`'s
`merged()` keeps `audit.maxEvents` per origin) — `realms.js`'s `segmentedArr()`
argues it. `audit.events` is the one declared so (`segment: 32`); the measured
reason is in `cluster/CLAUDE.md`.

### A store becomes per realm at its DECLARATION, and "everything it is made of" is the test

**This moved here from the root `CLAUDE.md` when that file was broken up.**

**A store becomes per realm at its declaration and nowhere else** —
`const sessions = realms.map()` in place of `new Map()`, and its hundred
readers are unchanged and correct. About thirty-five stores were converted
this way. **The ones left process-wide were left because the DIRECTORY was
shared, and that reason expired on 2026-08-25** when the directory became a
subtree per realm: `admin_stats.js`'s identity register and its revocation
set were converted on 2026-08-25 for exactly that reason, and until they
were, every realm's `/admin/users` listed every other realm's people beside a
directory reader that reported each of them missing. A store still declared
`new Map()` today needs an argument that does not rest on the directory —
`tests/realm_isolation.js` is the guard, and the reasoning is the
section above.

**TWO MORE WERE FOUND ON 2026-08-28 AND BOTH WERE THE SAME MISTAKE MADE TWO
WAYS.** `admin_stats.js`'s `CLAIM_SETS` was still a plain object, so a custom
claim added at `/realm/acme/admin/claims` was added to the ONE table and
carried by every access token this process minted — the DEFAULT realm's
included — while each realm's console showed it as that realm's own
configuration. It is `realms.obj()` now. And `claim_attributes.js`'s
`selections` was already a `realms.obj()` and was SEEDED AFTER THE CALL,
which seeds exactly one partition: every other realm got an empty object, so
the three `attributes` actions on all three claim-set doors refused every
set in every realm — with a sentence that listed the set it was refusing,
because the list comes from the process-wide table and the lookup did not.
It is seeded by the FACTORY now. **The lesson is that the two halves of ONE
claim set were held in two modules and only one of them was per realm**, so
the rule to check a converted store against is not "is it `realms.map()`"
but "is everything this thing is made of". This repository's own
`tests/vendored/sts_admin_api_operations.js` is the guard for both: it mints
a token in a realm and looks for the claim in the default realm's.

**A THIRD WAS FOUND ON 2026-09-06 AND IT IS THE SAME EXPIRED REASON AGAIN.**
`admin_stats.js`'s `scimCounts` was a plain object beside every other store in
that file. `/scim/v2` is realm-prefixed like every other endpoint here and
writes into the directory that became a subtree per realm on 2026-08-25, so a
provisioning client working in `/realm/acme` created entries in acme and was
counted in the DEFAULT realm's totals — one page reporting traffic that happened
somewhere else, beside a directory count that was correctly partitioned, which
is the identity register's leak exactly. It is `realms.obj(freshScimCounts)`
now, and `tests/realm_isolation.js` holds it both ways round and across a
purge, because that file's header asks for a third such store to go there
rather than into a file of its own. **It surfaced because `/admin/scim/monitor`
draws the counters and the directory side by side**, which is worth noting on
its own: the leak had been visible across two tabs for twelve days and nobody
had a reason to hold them next to each other.

**SEVEN MORE ON 2026-09-12, FOUND BY LOOKING RATHER THAN BY A PAGE.** A sweep of
module-level `new Map()` / `new Set()` / `{}` / `let` stores across the protocol
directories, after SPIFFE gained a pair of sockets per realm:

| Store | Was | Now | What leaked |
|---|---|---|---|
| `ssf/caep.js` register | `new Map()` | `realms.map({ persist: 'caep.register' })` | every realm's sessions on every realm's `/admin/caep-sessions` |
| `ssf/risc.js` register | `new Map()` | `realms.map({ persist: 'risc.register' })` | a deletion in one realm's directory on every realm's `/admin/risc-accounts` |
| `oid4vc/vc_offers.js` `deferredAccessTokens` | `new Set()` | `realms.map({ persist })`, keyed by a SHA-256 of the token | a deferred token deferred in every realm, and on one worker |
| `spiffe/spiffe_auth.js` recorded connections | `sharedMap()`, `scope: 'shared'` | `realms.map({ persist })` | one realm's gRPC connections evicting another's from the cap |
| `scim/scim_auth.js` Digest nonces, HOBA challenges and replay set | `new Map()` ×3 | `realms.map()`, not persisted | one realm's unauthenticated challenges evicting another's |
| `federation/federation.js` release index | two `let`s | `realms.keyed()` | one realm's release policy applied to another realm's tokens for five seconds |
| `oid4vc/vc_issuer.js` last Credential Request | a `let` | `realms.keyed()` | one realm's debugging endpoint reporting another's request |

**TWO OF THEM NEEDED MORE THAN A DECLARATION, AND THE REASON IS WORTH KEEPING.**
CAEP's and RISC's state machines edit a row object ALREADY IN THE MAP —
`row.counts[uri] += 1`, `row.state = 'revoked'` — and `realms.map()` journals a
`set()`, so a persisted register would write each row as it was CREATED. Each
file has a `touch()` that re-sets the same key after an edit, which keeps the
row's place in the insertion order and puts nothing back that was trimmed or
replaced meanwhile. `persistence/CLAUDE.md`'s "every mutation funnels through
`set`" is true of the store and not of what is stored in it.

**THE SPIFFE ONE IS WHERE AN HTTP-SHAPED ANSWER GOES WRONG.** A gRPC call has no
realm segment — the path is the method — so the realm a connection is in is the
LISTENER it was accepted on: `spiffe_server.js`'s `handlersInRealm()` wraps every
handler of every realm's servers (the default realm's four sockets included) in
`realms.run()`, and `recordCaller()` runs inside `prepareCall()`, inside that
handler, in the front process.

**WHAT WAS LOOKED AT AND LEFT PROCESS-WIDE**, each with an argument that does not
rest on the directory: catalogues built once from code (`vc_claims.js`'s,
`federation_map.js`'s `DEFAULT_MAP`/`seenIncoming`, the XACML function and
datatype tables, `ssf_events.js`'s `EVENT_BY_URI`, `applications.js`'s schema
maps); `xacml_store.js`'s `parsed`, keyed by the SHA-256 of a document's TEXT, so
two realms holding one policy share one parse and cannot share a wrong one;
`spiffe_ca.js`'s `building`, already keyed BY realm id, and `warnedShadows`, a
log de-duplicator; `xacml_role_pep.js`'s `dryRun`, a flag set and restored inside
one synchronous call; `spiffe_server.js`'s `listeners`, keyed by realm id and
owning sockets; the two worker pools, the request pool's tickets and affinity,
and `keystore.js`'s `material`/`shared`/`pkiHeld`, all keyed by realm id or
belonging to the OS process; and `authn.js`'s observer and sweep timer, which
are wiring rather than state.


### A replicated row for a realm this process has not heard of yet (2026-09-14)

**`partitionId()` sent every UNKNOWN realm id to the default realm's
partition.** It was written to make `''` mean the default realm, and it read
`(get(realmId) || DEFAULT_REALM).id`. A second process learns another's write
through a store's `restore` accessor (`persistence_minted.js`'s
`applyLocally()`), and in a dispatched service a realm's first stream, session
or token is replicated milliseconds after the realm — often before the realm
reaches that process. So the row landed in the DEFAULT partition, the next
in-place edit there journalled it as a default-realm row, and every process
adopted it. Measured on the kept stack of a `dispatch` run: the default realm
held forty other realms' own Shared Signals receiver streams, each created 250ms
before the realm's own copy, and every default-realm event was pushed to all of
them (`ssf/CLAUDE.md`).

An unknown id is now its OWN partition, so the rows wait for the realm. One
guard beside it: `retired` holds ids this process REMOVED and has not defined
again, and `acceptsRows()` refuses a restore for those — a row arriving after
the purge would otherwise rebuild the partition it emptied, and a realm defined
again under the id would inherit it. `tests/realm_row_arrival.js` pins both,
two mutants caught.

### Rule 3m: the realm's overrides are an inverted hook into `config.js`

`realms.js` requires `config.js` in the ordinary direction — it validates a
realm's settings through `checkOverride()` and reads its own two settings
through `value()`. `config.js` needs the current realm's overrides and cannot
require this module back, so it offers `setRealmContext()` and this fills it at
require time. That is rule 3e's shape and it passes rule 3e's test in the one
direction that matters: a require here would close a cycle.

The slot answers the REALM RECORD rather than its overrides, because
**`config.js` writes through it too**. `setOverride()` in a realm sets the
REALM's value — which is what makes every settings form in the console,
`/admin/token-lifetimes` and `POST /admin-api/config/set` realm-aware without
one of them being edited, including the twenty-one drawn on protocol pages
since 2026-08-27.
Setting a value while `acme` is ambient means setting it for `acme`; anything
else would be a console page that reads one realm and writes another.

**TWO SETTINGS ARE EXEMPT IN BOTH DIRECTIONS** and it is not caution:
`realms.enabled` and `realms.pathSegment` are read below the realm layer,
always. A realm that could switch realms off would be doing it from inside the
request that found it, and a realm that could move its own prefix would change
the prefix that had already been used to find it. They are refused at the writing
end as well, but the reading end is the lock that cannot be got around.

**THE WRITING-END LOCK WAS MISSING UNTIL 2026-08-25, AND THE SENTENCE ABOVE
DESCRIBED IT ANYWAY** — which is the whole lesson. `realms.setOverride()` went
straight to `config.checkOverride()`, which knows only whether a setting exists
and is runtime-settable, so `POST /admin-api/realms/set` with
`realms.pathSegment` answered `ok: true` and stored it on the realm. Nothing
MISBEHAVED, because `realmFor()` at the reading end returns null for any
`realms.` key and the value was never consulted — the second lock did its job
alone, exactly as the sentence above claims it can. What was wrong is subtler
and worse than a wrong value: `GET /admin-api/realms` lists a realm's overrides,
so this API asserted that a realm carried a prefix setting no reader would ever
look at. **A dead write is not harmless when something publishes what was
written.**

The lock is `checkRealmOverride()` in `realms.js`, and two things about it are
deliberate. It matches by PREFIX rather than naming the two settings, so a third
`realms.*` setting is refused the day it is added rather than the day somebody
remembers this function. And **every writing path goes through it** —
`setOverride()`, and `checkOverrides()`, which is what `create()` and `update()`
validate a whole object with — because the two were written separately at first
and that is exactly how one of them came to be missing.

**One door still accepts those two keys and must**: `POST
/realm/acme/admin-api/config/set` goes through `config.setOverride()`, where
`realmFor()` answers null and the write lands PROCESS-WIDE. That is the
documented behaviour rather than a hole — it is the same exemption read from
the other side — and the reply names no realm, which is what tells the caller
where it went. Do not "fix" that one to match: refusing it would leave
`realms.enabled` unsettable from inside any realm, which is every request in a
process where realms are switched on.

### A new realm is born with its own names for the things that are NAMES

Six settings here are identifiers rather than behaviour — the SAML 2.0 entityID,
the SAML 1.1 providerID, the WS-Federation entityID, the WS-Trust issuer, the
SAML assertion issuer and the OpenID4VP verifier client id — and each defaults to
a fixed string. Two realms carrying one of those strings is not a configuration
choice: it is two identity providers claiming one entityID, which a service
provider is entitled to refuse. So `create()` seeds each with the realm id
appended.

They are **ORDINARY SETTINGS ON THE REALM**, listed as such on `/admin/realms`,
which is the whole reason this is done at creation rather than inside the six
reads: an operator can see what was chosen, change it, or unset it and go back to
sharing the process's name — a realm deliberately impersonating another being a
case worth building on a mock. A derivation buried in a getter would give six
values that could not be seen and could not be changed.

`oauth2.issuer` is deliberately NOT seeded: it defaults to empty, meaning "name
the base URL this request arrived on", and that already carries the prefix.

### What a realm does NOT separate, and why saying so is the feature

`realmSupport()` is the index, and both `/admin/realms` and `GET /realms` render
it, so the answer is something this service tells you rather than something a
reader derives from four directory files. The short version:

* **What a realm separates completely** is what this service ISSUES and
  everything it holds while issuing it: keys, sessions, authorization codes,
  tokens, refresh families, DPoP and client-assertion replay state, offers,
  pre-authorized codes, presentation transactions, SAML request state and
  artifacts, the claim selections, the verifier's request, the statistics and
  the audit log.
* **THE DIRECTORY IS SEPARATED TOO — A STORE PER REALM BEHIND ONE SOCKET — AND
  THIS BULLET SAID THE OPPOSITE UNTIL 2026-08-25.** Each realm's directory is
  its own `realms.map()` partition, named by `dc=<id>` beneath `ldap.baseDn`,
  with its own `ou=users`, `ou=groups`, `ou=applications`, `ou=federations` and
  SPIFFE containers — so OAuth client registrations, SAML service provider
  entries and the SPIFFE registry are a realm's own. The realm is in the DN
  because the socket has no path to put a segment in, and the DN is therefore
  also how the socket picks which store to answer from. It was a subtree of one
  shared Map for two days, and `../ldap/CLAUDE.md` argues why that was one day
  too many: the isolation was a rule every reader had to remember, and two
  readers did not. **The TWO ADMIN CONSOLE ROLES were the exception and were
  pinned to the DEFAULT realm's `ou=groups` until 2026-09-14** — one roster for
  the process, since a per-realm roster would have let anybody who can create a
  realm administer the service. **#32 gave each realm a roster of its own,
  CONFINED to that realm by `admin-ui/admin_scope.js`**, and kept the default
  realm's as the service roster over every realm; `admin-ui/CLAUDE.md` 8d
  argues it. **The console's SESSION follows the roster and its SIGN-IN does
  not, and that sentence split in two on 2026-09-11.** It read *the console's
  SIGN-ON follows the roster: its gate accepts the DEFAULT realm's session and
  no other*, which was one answer to two questions. The console's own session is
  still in the default realm's partition — so the realm switcher switches
  without a second sign-in, and one console session reads every realm. What
  moved is where it AUTHENTICATES: the code flow runs in the AMBIENT realm, so
  that `/realm/acme/admin` and `/realm/acme/portal` are answered out of one
  sign-on session instead of two. Before it, moving between this service's own
  two surfaces inside a realm meant signing in again, in both directions.
  `../common/oidc_rp.js`'s surface table argues the split and
  `../tests/cross_surface_sso.js` pins it. It still changes nothing for a
  protocol endpoint — `/oauth2/authorize` in the realm switched to still sees no
  session unless somebody signed in THERE, and still should.
* **WHAT IS LEFT PROCESS-WIDE NEEDS AN ARGUMENT THAT IS NOT "THE DIRECTORY IS
  SHARED".** That sentence justified two stores in `admin_stats.js` — the
  identity register and the revocation set — and it was true for one day. Both
  are `realms.map()`/`realms.keyed()` since 2026-08-25, and what they were doing
  before is worth knowing because neither raised anything: every realm's
  `/admin/users` listed every other realm's people, while the realm's own
  directory reader reported each of those entries as missing (which, in that
  realm, they were); and one realm's `tokens.revoked` appeared under every realm
  beside a correctly partitioned `tokens.held`, with
  `POST /realm/acme/oauth2/revoke` able to kill a jti the default realm issued.
  `tests/realm_isolation.js` guards both directions and the purge.
* **Kerberos, the two TLS listeners and SPIFFE's four sockets are shared**, for
  the same reason. **SPIFFE'S X.509 AUTHORITY STOPPED BEING SHARED ON
  2026-09-11 AND ITS SOCKETS DID NOT**, which looks like a contradiction and is
  not: the authority is a realm's SPIFFE Issuing CA, the trust ANCHOR is the
  service Root that no realm owns, so every realm's bundle is the same document
  and an SVID minted on those shared sockets — which answer in the default realm
  — verifies against it wherever it was fetched. What partitioning the authority
  buys is a chain that says which realm issued an SVID; what it deliberately
  does not touch is the trust domain, which is still one for the whole service.
  **KERBEROS LEFT THIS BULLET ON 2026-09-15 (#33)**, by the route written down
  here while it was still owed: Kerberos already HAS a realm, so each trust
  realm gets a `krb5.realm` of its own and a request is dispatched on the realm
  name it carries. What stood in the way — *the principal database and its
  long-term keys are built from it at require time* — was the thing to change
  rather than the obstacle: the DEFAULT realm's database is still built at
  require time, another realm's is built when its Kerberos is turned on and
  rebuilt when a setting it was built from changes, and `krb5.realm` is
  `realmRuntime` for exactly that reason. The two sockets and the
  development-mode trust are still the process's. `kerberos/CLAUDE.md` argues
  it.
* **MOVED FROM THE ROOT `CLAUDE.md`'s TRUST-REALM INDEX, AND IT IS LATER THAN
  THE BULLET ABOVE:** the two TLS listeners are still shared, because a socket
  has no path to put a segment in and — unlike the directory — no name inside it
  to put one in either. **Kerberos was on this list until 2026-09-15**, when the
  realm name inside the protocol turned out to be exactly such a name. **SPIFFE LEFT THIS LIST ON 2026-09-12
  AND THE SENTENCE IT LEFT BEHIND IS WORTH KEEPING**: it read *SPIFFE's sockets
  are still shared and its X.509 authority is not, since 2026-09-11, and the two
  facts are compatible for exactly one reason — the trust ANCHOR is the service
  Root, which no realm owns … a realm still gets no trust domain, no bundle
  endpoint of its own in any meaningful sense, and no socket.* Every clause was
  true and the last one is what changed. A realm now gets a TRUST DOMAIN of its
  own — `<realm>.<the service's>`, seeded when the realm is created — and, when
  its `spiffe.enabled` is turned on, a Workload API and a SPIRE Server API of its
  own on an ADDRESS of its own. **The discriminator is the endpoint address
  because gRPC's path is the METHOD name**, fixed by the Workload API
  specification, so there is nowhere in the protocol for a realm segment; that
  is also what a real deployment does, one SPIRE server being one trust domain.
  A realm is created with SPIFFE OFF, so nothing binds until somebody asks.
  `spiffe/CLAUDE.md` carries the rest.

### An id is a path segment, so it is narrower than a name

Lower-case letters, digits and hyphens, starting with a letter or a digit, at
most 31 characters. It may not be `default`, and **it may not be the first
segment of a path this service already serves** — that list is read off the LIVE
ROUTER through a provider `app.js` installs, so a family added tomorrow protects
itself. The refusal stands whatever `realms.pathSegment` is set to, precisely
because that setting is runtime-settable: a realm created under a segment and
legal there would otherwise become a shadow over the console the moment somebody
cleared it, and the failure would arrive as "the console stopped existing".

### `onCreate()`: the one store that cannot be built lazily

`keyed()`, `map()`, `arr()` and `obj()` all build a realm's value on FIRST TOUCH,
and that works because every one of their readers is reached through a request
that has already entered the realm. **The embedded directory is the exception and
`realms.onCreate()` exists for it.** It is one tree keyed by DN, served by a
socket with no path in it, and a realm's isolation is a subtree
(`dc=acme,dc=example,dc=com`) — so "first touch" can be an `ldapsearch` arriving
on 389 for a base DN with no realm ambient at all, and the honest answer for a
subtree that was never built is `LDAP_NO_SUCH_OBJECT`. A realm that exists over
HTTP and not over LDAP is the kind of half-truth this service exists to make
impossible, so the subtree exists from the moment the realm does.

It fires AFTER the registry row is written, so a builder may read the realm back
through `get()`, and a builder that throws leaves a realm that exists rather than
half of one — the mirror of `onRemove()`, whose purges run after the row is
deleted. The asymmetry is deliberate in both directions: a realm with an unbuilt
subtree is recoverable, and a create that failed half way is not.

**One caller.** Adding a second is the same test `keyed()` fails: it has to be
something a request cannot build on demand.

### `onChange()`: a realm row changed, and it is an EVENT rather than a slot

Added 2026-08-27 for persistence. `onCreate()` and `onRemove()` already covered
two of the five doors into this registry; the other three — `update()`,
`setOverride()` and `clearOverride()` — had no hook at all, because until a realm
could be written down nothing needed to know that a name or an override had
changed.

**It is not another inverted hook, and the distinction is worth keeping.** Rule
3e's slots exist because a require in the obvious direction would close a cycle
or move a route, and the module on the far end fills a hole this one left. This
is the opposite shape: `persistence/persistence.js` REQUIRES this file, in the
ordinary direction, and subscribes. Nothing here knows what persistence is or
whether any exists, and a process that never loaded that module has an empty
listener list and behaves exactly as it did.

It fires AFTER the change, for the reason `built()` runs after the registry row
is written — a listener that reads the registry back must see what the caller
just did. **`remove()` fires it after the PURGES**, and that ordering is the
whole of what makes a removal persist correctly: a listener fired before them
would walk stores that still held the realm's entries and write them all back
down. A listener that throws is logged and does not fail the operation: the realm
IS renamed, and a persistence layer that could not write it down has not made
that less true.

### Removing a realm takes its state with it

Every store made here registers a purge and `remove()` calls them all. If removal
only dropped the registry row, a realm re-created with the same id would inherit
the last one's sessions and tokens — the single most surprising thing a
re-created realm could do. **The directory purges too, and that is new**: it is a
subtree per realm since 2026-08-25, so `ldap_server.js` registers a purge like
every other store and removal takes the realm's people, groups, applications,
federation relationships and SPIFFE registrations with it. That sentence used to
read "nothing is removed from the directory, because nothing there belongs to a
realm", and it is worth knowing why the reversal does not break the rule it
looks like it breaks: *nothing is ever deleted from `ou=users`* is about a PERSON
being removed while their realm stands, and it still holds. This is the realm
itself going away, and leaving its subtree behind would leak a tree nobody can
reach — every path to it, HTTP and LDAP alike, named a realm that is gone.

**A realm cannot remove ITSELF.** The response is a 303 to `/admin/realms`, which
`app.js` is about to rewrite into the realm being deleted; the reader would be
redirected into a prefix that stopped existing one instruction earlier.
Everything else about the removal would have worked, which is what makes it worth
refusing rather than special-casing.

### The HTML rewrite in `app.js`, and its one honest limitation

Every root-relative `href`, `action` and `src` in a `text/html` response is
rewritten to carry the current realm's prefix. That is what makes the console's
several hundred hand-written links, the login screen's form and the four autopost
pages work inside a realm without one of them being edited — and a missed link
would be one that silently LEAVES the realm rather than one that breaks, which is
why it is done once at the choke point rather than at the call sites. It runs in
a non-default realm only, so the default realm's bytes are not merely unchanged
but untouched.

**A URL built inside a SCRIPT is not markup and is not rewritten.** There is one
such page — `/admin-api/docs`, whose explorer builds request URLs from the
OpenAPI document's `path` members — and it is handled by being HANDED the prefix
as `data-realm-prefix` rather than by having its markup rewritten. Without that,
pressing "Try it" inside a realm would call the DEFAULT realm's API: the page
would look right, the call would succeed, and it would have changed the wrong
service. A fifth scripted page would need the same treatment and would not get it
for free.

## `config.js` is the only place a setting is read

Configuration used to be forty-odd `process.env.X || 'a default'` expressions spread
over twelve modules. Each was readable where it stood and the set of them was not:
there was no way to ask this service what it was configured with, no way to change
anything without restarting it, and no list anywhere of what could be changed at all
— the answer was a grep, and the grep only found the ones spelt the way you guessed.

**A new setting is a row in `SETTINGS` and a regenerated `env/defaults.js`** —
`node env/generate_defaults.js`, and the service tells you when you have forgotten
by refusing to start and naming the row. The row carries the key
(which is both the dot path in the appconfig file and the name every surface uses),
the environment variable, the type, the default, the prose, and `runtime`. From that
one row it appears in the admin console — on the page for the protocol it
configures, which since 2026-08-27 is where each group is drawn — in
`GET /admin-api/config`, in the OpenAPI
document's `Config` schema, and in the startup audit — none of which has a list of
its own to update. A `process.env` read added anywhere else is invisible to all four,
which is the state this file exists to end.

**`runtime: false` is a claim you have to be able to defend.** It means the value was
consumed before the service was listening, so changing it now would do nothing — and
`set` refuses it with the `restartReason` rather than accepting it, because an
accepted change that does nothing reads as having worked. Three kinds qualify and it
is worth knowing which: a **bound socket** (the HTTP port AND ITS SCHEME — see
`global.https`, which is why `oauth2.rfc9700` is restart-only — both TLS ports,
both LDAP ports, both Kerberos ports); **material derived at startup** (the TLS certificate is
issued for `tls.hostnames`/`tls.ips` at boot, and the DEFAULT realm's Kerberos principal
database and every long-term key in it comes from the realm, the SIDs and the passwords at
require time — another trust realm's is built when its Kerberos is turned on, which is why
those ten rows are `realmRuntime`); and **the directory tree**, which `ldap.baseDn` is the
root of. Marking a
setting runtime when the thing derived from it is not rebuilt is worse than marking
it restart-only, because the two then disagree silently.

**`realmRuntime` IS THE ONE EXEMPTION AND IT IS AN APPLICATION OF THAT RULE
RATHER THAN A HOLE IN IT.** One row carries it — `oauth2.rfc9700` — and the
argument is short: that flag is restart-only for exactly one reason, that
`global.https` derives its default from it and a listener's scheme is settled
when the socket is bound. **A realm binds no socket.** It answers on the port
this process already opened, in the scheme that port was opened in, so nothing
about a realm was consumed at startup and `oauth2_bcp.js`'s `enabled()` reads
the setting per request through the realm layer like any runtime row. So
`checkOverride(key, raw, forRealm)` takes a third argument, and the refusal a
person meets at `/admin/oauth2` in the default realm — and at `POST
/admin-api/config/set` outside a realm — is unchanged. `describe()` decides
`editable` the same way, so the console under a realm's prefix offers the
control the same page in the default realm correctly refuses.

**OMITTING THAT ARGUMENT MEANS "WHEREVER THIS WRITE WOULD LAND", SINCE
2026-08-28, AND UNTIL THEN IT MEANT "NOWHERE".** `realms.js`'s
`checkRealmOverride()` passes `true` explicitly, because it validates a realm's
overrides before any realm is ambient — it is the only caller that can know the
answer without asking. Every OTHER caller is inside a request, so the realm is
the ambient one, and every one of them passed nothing: `setOverride()` here,
and the three places in `admin-ui/admin.js` that pre-validate a whole section
before writing any of it. **So the exemption was unreachable through the four
doors a person actually uses**, and the symptom was worse than the rule being
absent. The console draws this control ENABLED inside a realm — correctly — and
a settings section's Save posts `set-many`, which is ALL-OR-NOTHING, so pressing
Save on `/realm/acme/admin/oauth2` was refused BY NAME every time, including
when nothing on the page had been changed, with a refusal that explained that a
realm may carry the setting it was refusing. The whole page was unusable inside
a realm. `checkOverride()` now defaults the argument from `realmFor(key)`, which
fixes all four call sites at once and leaves an explicit `true` and an explicit
`false` meaning exactly what they did. The parent project's
`tests/vendored/sts_admin_console.js` presses that Save button and is the guard; the
in-process half is `tests/appconfig_persistence.js`, which asserts the rule
itself.

What that buys is the thing two processes used to be needed for: `/oauth2/authorize`
permissive and `/realm/<id>/oauth2/authorize` enforcing the BCP, in one service.
What a realm does NOT get is a scheme of its own — the main port is HTTPS or it is
not, for every realm at once — and that is REPORTED rather than hidden:
`mainPortIsTls()` is false, `GET /oauth2/rfc9700` says so, and the four
requirements that are properties of the deployment come back `no` rather than
`deployment`.

**Do not add a second `realmRuntime` row by analogy.** The test is the paragraph
above: the restart reason has to be something a realm demonstrably does not have.
Anything whose value was consumed at startup to build MATERIAL — the TLS
certificate, the directory tree — was consumed for the whole process, realms
included, so marking one of those would be exactly the silent disagreement this
section warns about.

**THIS PARAGRAPH NAMED `krb5.realm` AS "THE CLEAREST NO", AND ON 2026-09-15 TEN
KERBEROS ROWS WERE MARKED — BY THE TEST ABOVE RATHER THAN AGAINST IT.** The
material a realm's Kerberos is built from is no longer built at startup: a realm
is created with `krb5.enabled` off and builds its principal database when it is
turned on, rebuilding it when one of those ten changes. So for a realm nothing
was consumed at any startup, which is the same argument SPIFFE's six made on
2026-09-12. What is still consumed for the PROCESS is still a no: `krb5.kdcPort`
and `krb5.servicePort` are bound sockets, and `krb5.trustedRealm` and its three
build the development-mode second realm at startup.

**MOVED FROM THE ROOT `CLAUDE.md`'s TRUST-REALM INDEX, AND IT DISAGREES WITH THE
TWO PARAGRAPHS ABOVE, WHICH SAY ONE ROW** — a realm may be in RFC 9700 mode while
the process is not: the `realmRuntime` marker, which had SEVEN rows from
2026-09-12 (it had one until then), TWELVE from 2026-09-13 and **TWENTY-TWO since
2026-09-15**, and must not get a twenty-third by analogy: `oauth2.rfc9700`,
`oauth2.oauth21`, the six SPIFFE rows a realm's own listeners are bound from, and
the ten Kerberos rows a realm's own principal database is built from — each
group's argument made at the head of its own group in `config.js` rather than
borrowed from this one. `tests/config_realm_layer.js` pins the list, which is
what makes adding one a decision. **`oauth2.oauth21` (2026-09-13) made the argument again
rather than copying the line**: it turns RFC 9700 mode on, so its ONE
restart-only consequence is the same socket through the same derivation —
`global.https` reads both flags through `processValue()` — and nothing else is
consumed at startup, since `oauth-oidc/oauth21.js` reads it per request. It is in
`tests/config_realm_layer.js`'s list, whose generic check that a realmRuntime row
moves no derived row holds for it for that reason. A realm binds no socket, so the reason `oauth2.rfc9700`
is restart-only service-wide does not reach it; what a realm does NOT get is a
scheme of its own.

**A ROW MAY NARROW ITS TYPE, and only the `int` type can so far.** `min`, `max`
and `step` are OPTIONAL members of a row that `TYPES.int.check()` applies; a row
carrying none of them behaves exactly as every int row did before they existed,
which is what kept the forty-odd existing ones untouched. They arrived for the
four token-lifetime settings (`oauth-oidc/CLAUDE.md` argues the numbers), where
the bounds are part of what the setting MEANS rather than a validation nicety: a
lifetime of nine seconds and a clock skew of a fortnight are both typeable, both
pass "is it a whole number", and both produce a service whose tokens are wrong
in a way that reads as a client bug. **`step` is a MULTIPLE-OF rather than a
slider increment**, counted from `min` so that a floor which is not itself a
multiple of the step is still reachable. `describe()` publishes all three, so
every settings form in the console and the OpenAPI `ConfigSetting` schema
render the same three numbers the check enforces — the bound is declared once
and nothing repeats it. **Put a new constraint here rather than at the call
site**: this is the only place one refusal can serve the console form, the
management API and an environment variable read at startup, and the last of
those has nowhere else to be caught.

**A runtime setting must be READ WHERE IT IS USED.** That is why so many of the
module-level `const`s became functions — `vciBatchSize()`, `clockSkewSeconds()`,
`maxEntries()`. A `const` captured at require time is the one thing `/admin/config`
cannot change, and it fails in the direction that looks like the console is broken.

**Resolution order is override, env var, LEGACY env var, the appconfig file
`CONFIG_FILE` names, `env/defaults.js`.** Env beating the file is what keeps every
existing container and test working: nothing in the parent project sets these
variables in compose, but
`tests/krb5_spnego_http.js` sets `KRB5_REALM`, `KRB5_KDC_PORT` and
`KRB5_SERVICE_PORT` before requiring the KDC in-process, and that still wins. The
legacy level has exactly one occupant: `STS_ISSUER`, which used to be a single value
serving as the SAML assertion issuer, the WS-Trust token issuer AND the
WS-Federation entityID. Those are three different things that shared a default — an
entityID names the identity provider, an Issuer names whoever signed an assertion —
so they are now `saml.issuer`, `wstrust.issuer` and `wsfed.entityId`, all three still
fed by `STS_ISSUER` when it is set.

**AND THERE IS NO SIXTH LEVEL — `requireComplete()` REFUSES TO START INSTEAD.**
A setting with no value in either appconfig file and no environment variable
stops the process, by name, listing both places its value could go. That is the
2026-08-24 change and it is the point of the table rather than a strictness bolted
onto it: a value arriving from a constant buried in a module is a value nobody
can find, change or see on a page, which is the state this file exists to end,
and a silent fallback underneath it was one way back in. The `dflt` column is
still there and is still where a default is WRITTEN DOWN — beside the paragraph
saying why it is the default — but it is documentation and a generator input
rather than a source the service leans on. `process.exit(1)` rather than a throw,
because a throw out of a require lands as a stack trace whose top frame is node's
module loader and the reason ends up three screens above where anybody looks.

**WHAT THAT REFUSAL CAN ACTUALLY CATCH IS A MAINTAINER'S MISTAKE, NOT AN
OPERATOR'S**, and knowing which is the difference between the rule being useful
and being a trap. **The appconfig layer is TWO FILES unioned**: `env/defaults.js`
carries a default for every non-derived row, and the file `CONFIG_FILE` names is
merged over it key by key with the operator's value winning. So an operator's
file can never be incomplete — only smaller — and three things follow, each of
which had to be true at once:

* a config file that is NOT this service's still loads every module here, which
  is what the parent project's in-process Kerberos jobs need (`CONFIG_FILE`
  pointing at the TEST suite's config, which carries `logLevel` and nothing else
  of ours);
* a row added to `SETTINGS` tomorrow does not break every config file in the
  world on the day it is added;
* so the refusal fires on the one case left — a row here with no row in
  `env/defaults.js`, which is a setting somebody added and did not finish adding,
  caught at the first start after the mistake.

**`env/defaults.js` IS GENERATED AND MUST NOT BE HAND-EDITED.** `node
env/generate_defaults.js` writes it from the `dflt` column. Two copies of a
default is one copy that will be wrong, and wrong in the quietest way — the
service running on one value while the console, the OpenAPI document's
`default` property and README.md's table all report the other. That generator
neutralises `process.exit` for the length of its own `require` of this module,
because regenerating the file is the one moment when an incomplete
`env/defaults.js` is EXPECTED; the bypass is in the build tool and deliberately
not a flag here, since a flag in the service is a flag somebody can leave on.

**3q. THE RUNTIME OVERRIDE LAYER IS DURABLE SINCE 2026-08-27, AND IT IS STILL
ONE LAYER.** `setOverrideStore()` is an inverted hook filled by
`persistence/persistence.js`, and it passes rule 3e's test on the same clause the
realm slot above it does: that module reads `persistence.mode` and four more
settings through `value()`, so it requires this file, and a require back closes
the cycle — node answers a cycle with a half-initialised module whose exports are
`undefined`, and the symptom would arrive later as "notify is not a function"
from inside a console Save.

**IT IS A NOTIFICATION AND NOT A STORE**, which is why it takes a realm id and
returns nothing. This file does not know what persistence is, whether it is on,
or where it writes; it knows that something changed and IN WHICH REALM, because
that is the thing only this file can say — a process-wide override and a realm's
override are written to different places by the module on the far end, and
`setOverride()` already makes exactly that decision for its own purposes.
**`clearOverride()` and `clearAllOverrides()` fire it too**, and that is the half
that is easy to miss: a store told only about writes would still hold a cleared
override and would put it back on the next start, which is worse than no reset at
all.

**THERE IS STILL NO SIXTH LAYER**, and the reason is `applyPersistedOverrides()`:
saved values are put back through the same `setOverride()` path a caller uses, so
what comes out of the store is a layer-1 runtime override and nothing else. The
ordering above is untouched, and an environment variable still does NOT beat a
saved override — because a saved override is a runtime override, and layer 1 has
always beaten layer 2.

**RE-APPLYING THEM AFTER EVERY MODULE HAS LOADED IS SAFE, and it is a property of
the table rather than of the ordering.** Only a `runtime: true` setting can be
overridden at all — `checkOverride()` refuses every other by name — and a runtime
setting is BY DEFINITION one that is read per call rather than captured at
require time; that is what the column means and what `restartReason` documents
the absence of. So nothing in a saved file can reach `global.https`,
`oauth2.rfc9700`, `ldap.port` or `ldap.baseDn`, and **a saved file cannot change
the scheme this service answers on**. Every value is re-checked on the way back
in rather than trusted: the file was written by this service, but possibly by an
older version of it, and a setting may have been renamed, retyped, had its enum
narrowed or been made restart-only since.

`persistence/CLAUDE.md` argues the rest. A REALM's overrides are not in this
layer's file at all — they live on the realm row and are written down with the
realm registry, because that is where they live in memory too.

**`resolve()` READS THE TWO FILES SEPARATELY EVEN THOUGH THEY ARE UNIONED**, and
that is not redundancy: `appconfig` is the union and is what the bootstrap logger
reads, while `resolve()` digs the operator's file and then `env/defaults.js` so
it can say WHICH — `source: 'appconfig'` against `source: 'defaults'`. A value
from the operator's file and the same value from the defaults are
indistinguishable once merged, and "where did this come from?" is the question
the *Source* column on every settings form exists to answer. `auditAppconfig()` reads the operator's file
alone for the same reason: audited against the union it would answer "nothing is
missing" every time and be dead code that looked alive.

**`logLevel` IS THE ONE KEY THAT IS NOT DISTINCTIVE OF THIS SERVICE** and the
audit's "somebody else's file" branch has to exclude it. Every appconfig file in
this ecosystem has one — the parent's api, its client, its test suites — because
it is the only setting that predates this table. Counting it made that branch
almost unreachable for the very case it was written for, and the result was a
hundred-and-fourteen-name warning on every in-process Kerberos run. Both drift
warnings now cap their name list at twelve and a count, for the same reason: a
list long enough to scroll is a list nobody reads.

**It is a library (rule 3) and it sits UNDER `helpers.js`.** It requires only bunyan
and `process.env.CONFIG_FILE`, and makes a bunyan logger of its own rather than
taking the shared one, because `helpers.js` requires IT. A cycle here would hand
`helpers.js` a half-initialised module whose `value` is undefined, and the symptom
would arrive somewhere else entirely as "value is not a function".

**The three `env/*.js` files were GENERATED from the table** and carry every key with
the value the expression in the module used to have, so a run with the shipped file
behaves exactly as one with the old file that carried only `logLevel`. FOUR settings
are deliberately absent from all four files, `env/defaults.js` included, because
their default is DERIVED from another (`krb5.serviceDomains` from the realm,
`oid4vp.walletUrl` from `oid4vci.walletUrl`, `global.https` from `oauth2.rfc9700`,
and since 2026-09-13 `adminApi.audience` from `global.publicBaseUrl` or the main
port's scheme, host and port — see `mgmt-api/CLAUDE.md` for why the gate still
accepts the request-relative audience while that row is at its default);
they carry `derived: true`, which keeps the startup audit from reporting them as
drift AND exempts them from the refusal above — a literal in a file would freeze the
derivation at whatever it evaluated to the day the file was written, so demanding one
would be demanding the one thing that is wrong. That audit — `auditAppconfig()` —
logs a setting the file omits and a key the table does not know, and does neither
when the file carries none of this service's DISTINCTIVE keys, which is the ordinary
case for the parent project's in-process tests: they load this service's KDC modules
with `CONFIG_FILE` pointing at the TEST suite's config.

**`tests/Dockerfile` in the parent project copies this file.** It is under
`helpers.js` in the graph, so every in-process job that loads `krb5_kdc.js`,
`app.js` or `spnego.js` needs it; missing, the failure is `Cannot find module
'./config'` before any test has run. **IT NEEDS `env/` AS A WHOLE DIRECTORY
TOO**, and that line is in place over there since the 2026-08-28 repair (see
`docs/parent-project-migration.md`): this module requires `env/defaults.js` by
absolute path off the package root whatever `CONFIG_FILE` says, so narrowing the
copy to the one file a job names puts every in-process job back to dying at load
with `Cannot find module` naming a file the operator never mentioned.


---

3b. **`admin_stats.js` is a library like `dpop.js`, and one dependency into it is
   INVERTED.** It registers nothing and requires only `helpers.js`, which it needs to
   stay that way more than `dpop.js` does: it is called from `app.js`'s call log,
   `helpers.js`'s `signJwt()`, both assertion builders, the KDC and the credential
   issuer. Because `helpers.js` cannot require it back (that is the cycle rule 2
   exists for), `helpers.js` offers a slot — `setJwtRecorder()` — and `admin_stats.js`
   installs itself in it at require time. **`app.js` is what requires
   `admin_stats.js`**, which is a real dependency (the call log is there) and also
   what makes the ordering safe: every protocol module requires `app.js`, so the
   recorder is installed before any route exists. Do not "simplify" that into a
   require in the other direction, and do not count tokens at their call sites
   instead — `signJwt()` is the single funnel, and five counted call sites means a
   sixth that is not.

   **ITS ONE OBSERVER SLOT NOW CARRIES THREE KINDS OF EVENT, AND THAT IS NOT A
   SIXTH HOOK.** `setUserObserver()` is still one slot filled by one module at
   its require time; what changed is that `ldap_server.js` is offered an `event`
   of `authentication`, `issuance` or `credential-status` through it.
   `recordAuthentication()` sends the first, `recordSvid('X.509', …)` sends the
   second when an X509-SVID is minted, and `recordCredentialStatus()` — which
   `spiffe_registry.js` calls by a plain require — sends the third. Keeping them
   on one slot rather than adding two more is what rule 3e asks for: a slot is
   the price you pay when a require would close a cycle or move a route, and one
   cycle does not become three. **AN ABSENT `event` MEANS AN AUTHENTICATION**,
   so an older `ldap_server.js` behaves exactly as it did, and only that event
   is counted on `/admin/users` or written to the audit log as one — an issuance
   that inflated the authentication count would make this page's central number
   mean two things at once.

   **AND THE PAYLOAD CARRIES A `federation` FIELD, WHICH IS A THIRD THING AGAIN
   AND STILL NOT A NEW SLOT.** A federated sign-in — `../federation/federation_sp.js`
   — puts the attributes a FOREIGN identity provider asserted onto the observer's
   detail, already mapped to this directory's own names, and `ldap_server.js`
   writes them onto the entry. It is not a fourth `event`, and that is rule 3e's
   test rather than convenience: this IS an authentication, and filing it as
   something else would take a federated sign-in off `/admin/users`, which is
   precisely where somebody looks for one. It is not a sixth slot either —
   `certificate` and `linkedTo` already established that a family with an extra
   fact about the identity puts it on THIS payload, and this is the third. What
   would justify a slot is a require that closes a cycle or moves a route, and
   there is none: `federation.js` registers nothing.

   **`recordAuthentication()` is NOT what a federated sign-in calls, and the
   reason belongs here because it is about this funnel.** It calls
   `authn.startSession()`, which records the authentication itself — so calling
   both produced TWO records for one sign-in, `/admin/users` counted every
   federated arrival twice, and the audit log carried a duplicate of each. That
   is what `startSession()`'s sixth argument exists for. The rule to keep: **one
   act is one row at this funnel**, and a caller that starts a session must not
   also record the authentication that started it.

3c. **`audit.js` is a library too, it sits BESIDE `admin_stats.js` rather than
   under it, and one dependency into it is inverted.** `admin_stats.js` answers
   "how much"; this answers "what, when, and to whom", as a list of discrete
   events. It requires `helpers.js` and `config.js` and NOTHING ELSE in this
   repository, and that has to stay true: it is called from `app.js`'s call log,
   from `admin_stats.js`'s `recordAuthentication()`, from `authn.js`'s session
   store and from every LDAP handler, which between them are most of the
   service. In particular it must not require `admin_stats.js`, because that
   module requires THIS one — so the identity normalisation an audit row wants
   is passed IN by the one caller that has already done it.

   **Five recording points, and four of them are funnels this service already
   had.** `app.js`'s call log covers three of the six categories (the console,
   the management API and every protocol endpoint) because it is the single
   place every answered request passes through; `recordAuthentication()` covers
   the sixteen protocol families for the same reason it covers the directory's
   user observer; `authn.js`'s `startSession`/`endSession` covers both
   protocols' sign-in and sign-out. Only `ldap_server.js` has a site per
   operation, because ldapjs dispatches straight into the handler and what a row
   says genuinely differs per operation. Do not add a recording site beside a
   funnel — that is how a category comes to be counted twice for one act.

   **One request is deliberately not an event: a `/healthcheck` that answered
   200** (`QUIET_WHEN_OK` / `isQuietProbe()` in `recordHttp()`). It is asked
   every few seconds for the whole life of the service — the compose
   healthcheck, the CI wait loop, every launcher in the parent project — and it
   always answers the same thing, so recorded it is by a wide margin the most
   common row here and it pushes everything a person came to the page to read
   off the end of a capped list. Note what the rule matches on: a probe that
   answered anything ELSE is still recorded, because a failing healthcheck is
   precisely the event somebody hunting a start-up failure is looking for, and
   it happens once rather than every five seconds. **The counters are
   untouched** — `/admin/metrics` counts the call as it always did, since a
   counter is one row however often it goes up. This is a rule about the event
   log, where one act is one line, and not about how much the service was asked
   to do. Anything added to that list needs the same two properties: constant,
   and uninteresting when it succeeds.

   **The one inverted dependency is the ACTOR.** An HTTP row wants the
   signed-in user's name and only `authn.js` can supply it, but `authn.js`
   requires `app.js` and `app.js` requires this — so `audit.js` offers
   `setActorResolver()` and `authn.js` fills it at require time, the same shape
   `setJwtRecorder()` and `setUserObserver()` have. The resolver it installs is
   deliberately NOT `sessionOf()`: that function deletes an expired session as
   it finds it, and an observer that quietly ended sessions while reporting on
   them would be changing the thing it describes.

   **Three properties are load-bearing and each is easy to undo.** `audit()`
   CANNOT THROW — it is wrapped, and a caller must never guard it, because an
   audit log that could fail a bind is a worse bug than a missing row. **NO
   CREDENTIAL IS EVER RECORDED** — no password, bearer token, assertion, or
   request/response body; a modify names the attributes it changed and never
   their values, a compare says whether it matched and not what was tried, and
   the query string redacts `code`, `id_token_hint` and the rest of
   `REDACTED_QUERY_KEYS`. The one field read out of an admin body is `action`,
   by name and capped, and widening that would put a pasted JWT on a web page.
   And the VOCABULARY IS A TABLE — `CATEGORIES` and `ACTIONS` — from which the
   console's filter selects and the API's `actions` member are both built, so an
   action cannot occur and be unfilterable nor be offered and never occur. A new
   action is a row there and nothing else.

   **Both its settings are read per event, not captured at require time**
   (`maxEvents()`, `protocolCallsRecorded()`), which is what the `runtime: true`
   on `audit.maxEvents` and `audit.protocolCalls` claims — see the config
   section below for why a captured `const` is the one thing `/admin/config`
   cannot reach.

   **`logout.global` and `logout.selective` are ONE ROW PER ACT and not one per
   thing ended**, which is this rule read from the other side. A global logout
   ends sessions, revokes tokens, discards codes, drops directory connections
   and stamps a Kerberos principal — and every session it ends already writes
   its own `session.end` through `dropSession()`. A row per item would count one
   sign-out twice at two layers. What those two actions add is the fact none of
   the others can carry: that these were one act, asked for by one person, at
   one moment, and how much of it could NOT be ended. They are in the `session`
   category rather than a seventh, because a category per family would be six
   categories for one act.

   **There is no clear operation and there must not be one.** An erase control
   on an unprotected console would make an audit log unable to answer the one
   question it exists for. Restarting the service is how you get an empty one:
   the ring is in memory and dies with the process, and **it stays that way now
   that some things do not** — see `persistence/CLAUDE.md`. An audit log is
   something this process RECORDED rather than something somebody TYPED, which
   is the line that decides what is written down, and it is on the resetting
   side of it. Persisting it would also make "restart to clear" stop being
   true, which is the only clear operation there is.


3ac. **`error_codes.js`: every failure has a name, and the name never reaches
   the client (2026-09-12).** A failure used to be identified by its SENTENCE —
   an `error_description`, a log line, an audit summary — and a sentence is
   reworded, carries per-request values and exists in three wordings for one
   condition. So there is one table, and every refusal and failure in the
   service is a row in it.

   **Moved here from the root `CLAUDE.md`, which keeps the short rule:** Every
   way this service can fail or refuse — an HTTP refusal, an error redirect, an
   LDAP result code, a KRB-ERROR, a gRPC status, a SOAP fault, a failed outbound
   request, a store that cannot be written, a startup refusal — has a code
   `STS-<SUBSYSTEM>-<NNNN>` in the ONE table in `common/error_codes.js`,
   organised by protocol subsystem or major component. `docs/error-codes.md` is
   generated from it. It goes on the audit row (`errorCode`, filterable at
   `/admin/audit?code=` and `GET /admin-api/audit?code=`) and at the front of a
   log line. It is never in a response body, header or redirect, and **it
   changes no specification's error**: the client still gets `invalid_grant`,
   `KDC_ERR_PREAUTH_FAILED` or the LDAP result code it got before.
   `mark(res, code)` writes to the response OBJECT under a Symbol that nothing
   serialises, and the call-log funnel reads it after the bytes have gone.
   **A NEW FAILURE IS NOT FINISHED UNTIL IT HAS A CODE**, and that is enforced
   rather than asked: a row in the table, a `mark()` / `errorCode:` / `tag()`
   where the failure is detected, and `node common/error_codes.js --docs`.
   `tests/error_codes.js` fails on an uncoded failure-shaped call site, a code
   used and not registered, a code registered and raised nowhere, a stale page,
   and a code literal on a line that writes a response.

   **IT IS A LEAF THAT REQUIRES NOTHING AT ALL**, not even a logger, so
   `config.js`, `crypto.js`, `realms.js` and `audit.js` — which cannot require
   each other freely — can all require it. Its `log` is console-backed, the
   `version.js` arrangement for the same reason.

   **THREE WAYS A CODE IS RECORDED, CHOSEN BY WHAT HOLDS THE FAILURE:**

   | Situation | How |
   |---|---|
   | an HTTP response that refuses or fails | `errorCodes.mark(res, code)` before the call that sends it; `audit.recordHttp()` reads it off the response on `finish` |
   | a non-HTTP refusal (LDAP, KRB-ERROR, gRPC), an outbound or background failure | `errorCode:` on the audit row that already exists, or `audit.failure(code, …)` where none does (`service.failure` for one that belongs to no request) |
   | a failure no audit row can hold — the process is exiting, or the module cannot require `audit.js` without a cycle | `errorCodes.tag(code)` at the front of the log message |

   A library that RETURNS a refusal to a caller that sends it (a verdict, an
   `{ ok: false }` action result) attaches the code under the same
   `Symbol.for('mock-sts.errorCode')` that `mark()` uses, NON-ENUMERABLY, and
   the caller marks `errorCodes.codeOf(result) || '<its own fallback>'`. The
   symbol is what makes that safe: several of those results are serialised
   whole to `/admin-api` clients, and an enumerable `errorCode` member would
   have put the code on the wire through the one door nobody thinks of as a
   response.

   **THE CODE CHANGES NO BYTE A CLIENT RECEIVES**, and that is the design rather
   than a precaution. A client under test must see its protocol's own error and
   nothing else; a code is an operator's name for the condition. The table's
   `spec` column records what the client IS told, so the documentation page can
   say it without anybody reading the handler.

   **`audit.js` CHANGED IN THREE WAYS FOR IT, AND EACH IS A RULE.**
   * A row with `errorCode` and no `outcome` is a REFUSAL, not a success — a
     failure in the success count beside its own code would be the log
     disagreeing with itself.
   * A row with `errorCode` writes ONE log line, from `logFailure()`, so the
     audit ring and the service log cannot disagree about which code a failure
     had and no site has to remember to log it. `info` for a refusal, `error`
     for an error — a refusal is this service working.
   * **A FAILURE IS RECORDED WITH `audit.protocolCalls` OFF.** That setting
     silences JWKS polls and metadata fetches; a refused request is the row
     somebody turned the firehose off to be able to find. And every failed HTTP
     response carries a code — the one marked, or a generic `STS-HTTP-0001`
     (unrouted), `-0002` (4xx) or `-0003` (5xx) — so a row with `-0002` or
     `-0003` on it is a failure site MISSING its code, and the documentation
     page tells a reader to report one.

   **A NEW `service` CATEGORY**, with `service.failure`, beside
   `protocol.failure`: a store that could not be written or a worker that
   stopped answering answers none of the questions the other categories are
   filtered by.

   **`tests/error_codes.js` IS WHAT KEEPS THE TABLE COMPLETE**, and the check
   that matters most is the one that looks least like a test: every line
   matching a FAILURE PATTERN — `.status(4xx)`, `oauthError(`, `log.error(`,
   `outcome: 'refused'`, an ldapjs error, and each subsystem's own helper
   shapes — must have a code within a few lines, or `// error-code: none —
   <why>` with the reason spelled out. **A protocol family added tomorrow with
   a `fooError(res, …)` helper of its own is invisible to that check until its
   shape is added to the list**, which is the one gap the list cannot close by
   itself; adding the family is adding the pattern.

   **NEVER RENUMBER, NEVER REUSE.** A code ends up in an alert rule and a saved
   log search. A condition that stops existing keeps its row with `retired:
   true`, and the test stops requiring it to be raised.

3d. **`claim_attributes.js` is the THIRD reader of `vc_claims.js`'s catalogue,
   and it is a library like the other two.** `vc_claims.js` says what an issued
   CREDENTIAL carries and `vc_verifier_config.js` says what the mock Verifier
   ASKS FOR; this says which LDAP attributes a TOKEN or an ASSERTION carries,
   per claim set, and it is the second half of ALL THREE claim-set pages —
   `/admin/claims` for the two JWT sets, `/admin/userinfo-claims` for the
   UserInfo one and `/admin/saml-attributes` for the two SAML ones, which is a
   split of the CONSOLE and not of anything here: this file still holds one
   selection per set and answers all three pages through it. **Adding the fifth
   set on 2026-08-26 edited nothing in this module**, which is what `SET_IDS`
   being read off `admin_stats.js` rather than written out again is for. It
   registers no
   route and requires `helpers.js`, `admin_stats.js`, `vc_claims.js` and
   `audit.js`, none of which requires it back.

   **The catalogue is not copied and the three selections are not shared**, and
   both halves of that matter. One catalogue, because two lists of spellings is
   one list that will eventually be wrong about `schacDateOfBirth` while both
   look right alone. Three selections, because "issue a credential carrying a
   claim the access token does not" and "ask for a claim nothing here issues"
   are the mismatches a client's error paths are built for, and a single page
   setting all three would make both impossible to produce.

   **The merge into a token is INVERTED, and that is what keeps the four
   issuance sites unchanged.** `admin_stats.js` offers `setAttributeResolver()`
   and this module fills it at ITS require time; `jwtClaims()` and
   `samlAttributes()` then merge what comes back. It has to be that direction —
   `vc_claims.js` requires `admin_stats.js`, so a require the other way closes a
   loop (rule 2). Do not "simplify" it by calling this module from `oauth2.js`
   and the two assertion builders instead: four edited call sites are four that
   drift and a fifth added later with none. **`server.js` requires this module
   itself**, ahead of the modules that issue, because an unfilled slot means
   tokens issued without their configured attributes and `admin.js` requiring it
   would only make that true by accident.

   **Nothing is selected on a fresh start, in any of the five sets.** Unlike
   `/admin/vc`'s ten defaults — which reproduce what that issuer already carried
   — this page changes what every client of this service receives, so it does
   nothing until it is asked to.

   **Precedence is three deep — four at the UserInfo endpoint — and most of it
   is only visible in a collision**: the protocol's own claim wins (an ID Token always carries
   `name`, `given_name`, `family_name`, `preferred_username` and `email`, so
   ticking `cn`, `givenName`, `sn`, `uid` or `mail` on THAT set changes nothing
   a client sees), then a typed claim of the same name, then the attribute. In
   the two assertion builders that had to be written as a FILTER rather than as
   an assignment order, because an assertion is a list of elements: a duplicate
   name is not an overwrite, it is two `<Attribute>` elements with one name and
   a relying party reading whichever was emitted first. SAML 1.1 filters on
   NAMESPACE AND NAME together, since that profile splits a claim URI into the
   two.

   **THE USERINFO ENDPOINT HAS A FOURTH LAYER ABOVE ALL THREE, and it is the
   only one a CLIENT controls.** OpenID Connect Core section 5.5's claims
   request names individual claims, and `requestedClaimsFor()` in this module
   resolves them off the same catalogue — indexed the other way round, by claim
   name rather than by LDAP attribute type, including the top-level name of a
   nested claim (`address` returns the whole Address Claim of Core 5.1.1) and a
   language tag as part of the name (Core 5.2). It wins over the three above it
   BY DESIGN and the reason is written at the merge in `oauth-oidc/oauth2.js`: a
   scope asks for a category and a request names a claim, so answering
   `{"email":null}` with the invented persona value while the entry holds a real
   `mail` would defeat the only reason the feature exists. Nothing it can
   resolve is a structural claim — every name comes from this catalogue or from
   `PERSONA_CLAIMS` — so `sub`, `iss` and `exp` are out of its reach by
   construction rather than by a guard.


3d-ii. **`group_claims.js` is the FOURTH library over that catalogue's
   territory, and it is the only one that reads the directory's GROUPS.**
   `vc_claims.js` says what a CREDENTIAL carries, `vc_verifier_config.js` what
   the Verifier ASKS FOR, `claim_attributes.js` which ATTRIBUTES a token
   carries; this puts the GROUPS somebody is a member of into all four claim
   sets at once. It registers no route and requires `helpers.js`, `config.js`
   and `admin_stats.js`, none of which requires it back.

   **IT IS AUTOMATIC AND THEREFORE NOT A SELECTION.** There is nothing to tick
   per user and nothing to tick per set — with `groups.claim` on, all five
   carry it — which is also why it is REPORTED by all three claim-set pages and
   owned by none of them. That is the deliberate opposite of `/admin/claims`'s
   three selections, and it is why the control is a `config.js` ROW rather than a
   form: four settings in `config.js`'s table, drawn by the console on
   `/admin/groups` — where the membership they name is — and already served by
   `POST /admin-api/config/set`, so the console's parity rule (rule 7) is
   satisfied by there being no new control. **A second form on `/admin/claims`,
   `/admin/userinfo-claims` or `/admin/saml-attributes` would be a second door
   to one setting** — four doors now that there are three pages — which is the
   two-stores mistake rule 5 exists for.

   **ON BY DEFAULT IS DEFENSIBLE ONLY BECAUSE THE CLAIM IS OMITTED FOR SOMEBODY
   IN NO GROUP** — absent, not an empty array. On a fresh start the only people
   in a group are the three the directory seeds, so a caller who never touched
   `ou=groups` gets exactly the tokens it got before. An empty array would be a
   new member in every token every existing client parses, which is what
   `claim_attributes.js` defaults its selection to nothing to avoid.

   **TWO INVERSIONS, and each fails rule 3e's test in a different direction.**
   `admin_stats.js` offers `setGroupResolver()` and this module fills it (a
   require the other way closes a cycle, since this module requires that one for
   `identityKeyOf()`, the set ids and the reserved names); and this module offers
   `setDirectory()`, which `ldap_server.js` fills with `groupsOfUser()` — a
   require reaching THAT module would drag every `/ldap` route to the front of
   the router. What it buys is the thing every inversion here buys: NO ISSUANCE
   SITE CHANGED.

   **`ldap_server.js` OWNS WHAT A GROUP IS; THIS OWNS WHAT A TOKEN BELIEVES.**
   `groupsOfUser()` applies both group rules and resolves `member`,
   `uniqueMember` and `memberUid` exactly as the console's member list does —
   `memberUid` holds a bare name and the other two hold a DN, and treating them
   alike is how every `posixGroup` membership silently stops reaching a token.
   It reports BOTH directions (`via` for the group's own attributes,
   `viaMemberOf` for the person's claim) and applies neither, because which one
   a token believes is `groups.claimFromMemberOf` and that is a policy. Same
   split as `oauth2_bcp.js` and `oauth2.js`. **An entry is not required**: a
   group listing a DN nothing is stored at is a dangling member from the group's
   side and is still the group saying so.

   **PRECEDENCE IS NOW THREE DEEP IN A SECOND SENSE**, under the one rule 3d
   describes: a typed claim wins over a directory attribute, and both win over
   the groups claim — which is the only one of the three nobody named on a page.
   In `samlAttributes()` that is a FILTER for the reason stated there, and the
   groups layer is filtered against BOTH layers above it. A `groups.claimName`
   naming something this service sets itself is REFUSED AT ISSUANCE, not at
   configuration time, because `config.js` requires nothing from this repository
   and a copied reserved list is one that goes wrong.

   **A SAML ATTRIBUTE IS MULTI-VALUED and both builders now say so.** `values`
   is an array of `<AttributeValue>` children under one `<Attribute>`; `value`
   is untouched and is what every existing caller passes. One element per group
   with the same name is not a multi-valued attribute — it is a relying party
   reading the first and silently seeing one group where the person is in four,
   the exact defect `samlAttributes()`'s dedup filter exists to prevent.

   **CARRYING A GROUP IS NOT GRANTING ONE.** No endpoint here reads this claim
   and nothing decides anything on one, which is the same distinction this
   service already draws between an identity being RECORDED and one being
   AUTHENTICATED. What stopped being true is the OTHER half of the old sentence
   — "no token carries a group from this directory" — and the two halves are
   split on `/admin/groups`, on both claim-set pages and in README.md rather than
   merged back into one claim that is now half wrong.


---

3g. **`applications.js` is a library like `dpop.js`, and THE DIRECTORY IS ITS
   STORE.** It holds every application this service has been asked about — an
   OAuth client, an OIDC relying party, a SAML 2.0 or 1.1 service provider, a
   WS-Federation application, a WS-Trust relying party, the OID4VP verifier, a
   Kerberos service — as entries under `ou=applications`. It registers no route
   and requires only `helpers.js`, `audit.js` and `config.js`, so it cannot join
   a cycle;
   `admin_stats.js`, `oauth2.js`, `wsfed.js`, `wstrust.js`, `krb5_kdc.js` and
   `krb5_service.js` require it in the ordinary direction, and `ldap_server.js`
   fills its `setDirectory()` slot at require time for the reason
   `vc_claims.js`'s is filled (rule 6). Seven things are load-bearing:

   **A SIGHTING MAY NAME SEVERAL KINDS, AND TWO PROTOCOLS NEED IT TO.** `seen()`
   takes a list as readily as a string and accumulates them. A `wtrealm` is a
   WS-FEDERATION application AND the audience of whichever assertion it was
   handed; an `AppliesTo` handed a SAML 2.0 assertion is a WS-Trust relying party
   AND that assertion's service provider. Recording only the second of each left
   `wsfed-relying-party` a kind NO code path produced — offered by the console's
   filter and by the management API's enum, and matching nothing, forever. Pass a
   list rather than calling `seen()` twice: two calls count two authentications
   for one act, which is what `counts: false` exists to prevent one field over.

   **A KERBEROS SERVICE IS RECORDED AT BOTH ENDS, AND THAT IS NOT A DOUBLE
   ENTRY.** The KDC records an SPN when it ISSUES a service ticket
   (`krb5_kdc.js`'s TGS handler) and `krb5_service.js` records it again when it
   ACCEPTS one, under the same `SPN@REALM` identifier, so the two land on one
   entry with two descriptions. The acceptor's half is not redundant: it is the
   only one that fires for a ticket some OTHER KDC issued — a real Active
   Directory, which the parent project's real-DC and relay jobs use — where the
   client was recorded and the service was not. It goes in `accept()` and NOT in
   `spnego.js`, which calls that function for every check it makes and adds none
   of its own; a second call there would count one ticket twice.

   **THERE IS NO MAP SHADOWING THE ENTRIES.** Every read is a directory read and
   nothing is cached, which is what makes an `ldapmodify` of `oauthRedirectUri`
   change what RFC 9700 mode accepts on the NEXT request. A cache added for
   speed would quietly undo the whole design, and on a mock whose store is a Map
   in this process there is nothing to gain by one. `oauth2.js`'s
   `registeredClients` Map is GONE for the same reason — the RFC 7591
   registrations are entries, reached through `registrationOf()`.

   **THE SPELLING TABLE IS TWO LISTS AND ONE DOOR.** `ldap_server.js`'s
   `CANONICAL_NAMES` puts the conventional capitalisation back on a name the
   store lower-cased. It is `STANDARD_NAMES` (types somebody else defined, the
   specification named per group) plus `OWN_NAMES` (this service's inventions),
   each written ONCE as the canonical spelling with the lookup key derived by
   `toLowerCase()` — never as `lower: 'Mixed'` pairs, where a typo in the key is
   invisible and the table fails silently at its only job. It covers ~150 names
   rather than the ~30 this service writes, deliberately: the directory is
   schemaless and a certificate subject arrives as attributes nobody here chose,
   so a table that knew only its own writes would be wrong exactly where a reader
   needs it. FOUR SOURCES merge — the two lists, `vc_claims.js`'s catalogue and
   `applications.js`'s schema — and all four go through `learnName()`, which
   keeps the first spelling and WARNS on a second rather than letting merge order
   decide silently. Add a name to a list, never to the map; `memberOf` is in
   neither category and says so where it sits.

   **THE STORE'S TWO DIRECTIONS ARE NOT SYMMETRICAL, and that is the fix for
   the DN.** A WRITE speaks in attribute objects — all a record has to say — but
   `readApplication()` and `allApplications()` hand back the whole ENTRY (`dn`,
   `origin`, `createdAt`, `modifiedAt`, `operational`, `attributes`), the same
   shape `objectFor()` gives the console for a person. It has to be the entry,
   because THE DN IS NOT AN ATTRIBUTE — it is the key the entry is stored under
   — so a caller handed only the attributes had no way to learn where the
   application lives, and every applications page could show the `cn` and
   nothing else. The DN is published inside `attributes` as `entryDN` (RFC 5020,
   and what `matchable()` already calls it) and SYNTHESISED on every read: a
   stored copy is a second definition of one fact and the one that goes stale,
   which `applicationEntry()`'s rename fallback shows is a case that happens.
   Two consequences to keep. `view()` exposes `attributes` as the WHOLE entry
   and `fields` as the schema half `recordFromAttributes()` understands — they
   are different questions and the narrow one was being served under the wide
   one's name. And every attribute lookup in `applications.js` goes through
   `byLowerName()`, because names now arrive canonically spelled on the way out
   and lower-cased in the store; an index assuming either produces a record with
   an empty identifier rather than an error.

   **THE ATTRIBUTES WIN OVER THE STORED DOCUMENT.** RFC 7591 permits arbitrary
   metadata and RFC 7592's read must return what was registered, which no fixed
   attribute set can represent — so the whole registration is kept verbatim in
   `appRegistrationJson`. When the record is rebuilt that document is the
   STARTING POINT and every member with an attribute of its own is overwritten
   from the attribute. Reverse those and an operator's edit is silently ignored
   by the one check that matters, which is the two-stores failure in miniature.

   **THE SCHEMA IS A TABLE AND IT IS A VOCABULARY, NOT A CONSTRAINT.** node-ldapjs
   has no schema subsystem (its whole `lib/` mentions objectClass three times: a
   default filter and two result-code names) and it is a submodule this repo does
   not modify, so there was nothing to register with. `SCHEMA.attributes` is the
   definition: the entry is built by WALKING it, `/admin/ldap/applications` publishes
   it, and an attribute not in it is REFUSED rather than written. `multi`
   accumulates and `single` is assigned — get that backwards on a counter and the
   entry grows a value per sign-in, which is `applyVcAttributes()`'s second rule.
   Where a registered class fits it is used (`applicationProcess`, RFC 4519);
   `stsApplication` is invented because nothing standard has a `client_id`.

   **THE APPLICATION FUNNEL IS NOT THE USER FUNNEL, and cannot be.** A person is
   recorded at `recordAuthentication()`; an application is recorded where its own
   protocol accepts it, because in the authorization code flow the person is
   authenticated in `authn.js`, which knows nothing about OAuth and never reads a
   `client_id`. `counts: true` exactly where a credential was accepted FOR that
   application — the authorization endpoint counts, the token endpoint does not,
   since redeeming the code is the same transaction continuing.

   **`ou=applications` IS ITS OWN CONTAINER AND MUST STAY OUT OF THE ou=users
   SWEEPS.** `populateVcAttributes()` would give an OAuth client a birthdate and
   `/admin/groups` reports membership from there; both already walk `ou=users`
   only. This is the OPPOSITE decision from `didPlan()`, where being outside
   those sweeps was the bug because a DID names a person.

   **THE CONSOLE IS NOT A THIRD DOOR.** `/admin/applications` and
   `POST /admin-api/applications/{action}` both call functions in THIS module —
   `createApplication`, `updateApplication`, `deleteApplication`,
   `forgetRegistration` — which do the same read-modify-write `seen()` does
   against the same entries. A form post and an `ldapmodify` are one act
   arriving by two routes, which is what keeps the one-store rule intact with
   three ways in. `applicationsView()` builds the HTML and the JSON together and
   the API throws the markup away, the way `usersView()`/`groupsView()` already
   do; the drill-down pages its ATTRIBUTE list under `attributesPage` rather
   than the bare `page`, which is `pagingOf()`'s convention for a view holding a
   list that is not the top-level one.

   **WHAT MAY BE CHANGED IS DECLARED AND NOT DERIVED, and the line is the
   `EDITABLE` table here rather than a judgement at each call site.** Declared is
   what the application may DO — redirect URIs, grant types, scopes, secret,
   auth method — which is configuration and is what RFC 9700 mode reads. Derived
   is what HAPPENED — the counters, the sightings, the kinds, the protocols,
   `appRedirectUriObserved` — and a form that could rewrite it would make the
   page lie about this service's own behaviour, indistinguishably from the
   recording being broken. `ldapmodify` still reaches everything: refusing it
   HERE is the difference between offering an operation and merely not
   preventing it. The console's selects are built from the same table the
   actions validate against, so a form cannot offer a field the action refuses.

   **`appAllowedProtocol` IS THE DECLARED TWIN OF `appProtocol`, AND IT IS THE
   ONE PLACE IN THIS MODULE WHERE TWO ATTRIBUTES HOLD ONE NOUN ON PURPOSE.**
   Added 2026-08-25 with `/admin/applications/new`. `appProtocol` is DERIVED —
   the families this application has appeared in, accumulated by `seen()` — and
   `appAllowedProtocol` is DECLARED: the families somebody ticked on that page
   before it had connected to anything. It is editable and the other is not,
   which is the `EDITABLE` line above applied to a pair that would otherwise
   look like a duplicate to anybody tidying up.

   **DECLARING A FAMILY GRANTS AND REFUSES NOTHING, and the sentence to change
   if that ever stops being true is the one in `PROTOCOLS`'s header rather than
   a page's.** No endpoint reads the attribute: an application declared for
   `saml2` alone is still issued an access token, because a mock that refused a
   protocol would remove a test case rather than add one. It is a record of
   intent, exactly as being in this registry at all is — the same claim
   `/admin/applications`'s caveat already makes about the whole entry.

   **EVERY PROTOCOL FAMILY NOW NAMES THE ATTRIBUTES ITS CONFIGURATION LANDS
   ON**, and that is what removed the KIND select from the create form rather
   than a second table being added beside it. A `PROTOCOLS` row carries
   `identifierAttribute` and `redirectAttribute`; `declarationAttributes()`
   walks them, DEDUPES BY ATTRIBUTE, and is what `/admin/applications/new` draws
   its fields from and `GET /admin-api/applications/new` publishes as
   `declarations`. Several families naming one attribute is the point rather
   than a shortcut: OAuth 2.0, OpenID Connect and OpenID4VCI all name
   `oauthClientId` because a relying party IS an OAuth client and a wallet
   authenticates as one, and both SAML profiles name `samlEntityId` — the
   specifications share the identifier, so two attributes would be two spellings
   of one fact that disagree the first time either is edited.

   **THEY ARE ALL `multi` BAR ONE, AND THE EXCEPTION IS THE ONE SOMETHING
   ENFORCES.** `oauthClientId`, `samlEntityId`, `wsfedRealm`,
   `wstrustAppliesTo`, `krb5ServicePrincipalName` and `oid4vpClientId` were
   `single` until 2026-08-25 and now accumulate, because one application
   legitimately answers to two client_ids or two SPNs. `oauthTlsClientAuthSubjectDn`
   stays `single`: RFC 8705 section 2.1 matches a certificate against "the
   single expected subject", and since 2026-09-13 it is one of five subject
   parameters a client holds at most one of (`mtlsAttributeProblem()`),
   compared by `certificate_subject.js` as a name — widening it means first
   deciding what "any of these" should mean to a security check, which is a
   different change from giving a form a field. **Flipping a row's `kind` also means flipping its
   `EDITABLE` mode**, `set` to `multi`, or the console offers a `set` the action
   refuses.

   **EACH IDENTIFIER ATTRIBUTE ALSO CARRIES `identifierName` — THE PROTOCOL'S
   OWN WORD FOR IT — AND `identifiersOf()` IS WHAT READS THE PAIR.** Added
   2026-08-27 for the delegation pictures, which draw an application by the
   name somebody GAVE it and said nowhere on the diagram what a request would
   have to present to reach it. The attribute is unfriendly by design (an
   `ldapsearch` and `/admin-api` share its spelling), so `oauthClientId` carries
   `client_id`, `samlEntityId` carries `entityID`, `wsfedRealm` carries
   `wtrealm`, `wstrustAppliesTo` carries `AppliesTo`,
   `krb5ServicePrincipalName` carries `SPN`, and so on for all eleven.
   `identifiersOf()` takes a `view()`, a record or a bare fields object and
   returns one row per identifier attribute the entry actually carries a value
   in — the attribute, that word, the FAMILIES it serves as labels, and the
   values — in table order, skipping the empty ones.

   **IT IS HERE RATHER THAN IN THE RENDERER FOR THE REASON EVERYTHING ELSE IN
   THIS MODULE IS.** Which attribute is a family's identifier is the `PROTOCOLS`
   table's statement and what the specification spells it is the `SCHEMA` row's;
   a page building either list for itself would be a second opinion about the
   store, and the first time a family was added it would be a second opinion
   that disagreed. The families come back as LABELS and as a list because
   several families share one attribute — naming only the first of OAuth 2.0,
   OpenID Connect and OpenID4VCI would be picking one of three true answers.
   `admin-ui/CLAUDE.md` argues what the picture then does with the rows,
   including why it groups them by VALUE rather than by attribute.

   **`oauthAudience` IS DECLARED AND IT IS READ, WHICH MAKES IT THE ONE OF ITS
   KIND.** Added 2026-08-26. It is the audience an access token addressed to this
   application carries — a URI, the resource rather than the client that calls
   it — and it is the OAuth spelling of a fact `wstrustAppliesTo` and
   `samlEntityId` already record for their own families. Nothing presents an
   audience as its own name, so nothing here writes it and it cannot be derived.
   What makes it different from the four declaration-only attributes below is
   that `oauth-oidc/oauth2.js` LOOKS IT UP: `forAudience()` turns the `audience`
   on an RFC 8693 exchange into the application that registered it, so a
   delegation reaching `https://esb1.example.com` is filed against `esb1` and
   `/admin/delegation/map` draws one chain instead of two halves that share
   nothing. **It is a lookup and not a permission** — an audience nobody
   registered is exchanged for exactly as before and recorded verbatim, which is
   the same sentence `appAllowedProtocol` gets and for the same reason. Do not
   give it a fallback to the identifier: `get()` already answers that question,
   and a lookup trying both would make `audience=esb1` and
   `audience=https://esb1.example.com` indistinguishable in the one place the
   difference is the point.

   **`forPermissionBase()` IS THE FIFTH LOOKUP, added 2026-09-02, and it is
   `forPermission()` asked one level up.** That one takes a whole permission
   identifier and answers which application defines it; this takes the BASE
   ALONE. It exists for a reader holding an ISSUED TOKEN rather than a request:
   `audienceScopes()` writes the base URI onto the `aud` and the bare names onto
   the `scope`, so what a picture has is a base and nothing else — and none of
   the four lookups above it can turn that back into an entry.
   `forAudience()` reads `oauthAudience`, a different attribute a resource is
   under no obligation to have set; `forClientId()` reads a bare name; and
   `forPermission()` needs a name on the end that the reader is trying to work
   out. `common/user_graph.js`'s `permissionsAddressedTo()` is its one caller.

   **IT NORMALISES BOTH SIDES, WHICH IS ITS ONE DIFFERENCE FROM `forAudience()`
   AND IS NOT A SOFTENING OF THAT RULE.** An `ldapmodify` is not normalised, so
   an entry can hold `https://example.com` while every identifier this service
   composed from it — and therefore every `aud` a token addressed to it carries
   — ends in the separator. `permissionBaseOf()` is what added that separator,
   so comparing through it is comparing a value this module composed with
   itself. Get that wrong in the ENTRY direction and the entry is unreachable
   from its own tokens, which reads as the feature quietly not working rather
   than as an error; `tests/user_graph_permissions.js` caught exactly that
   mutant on its second round. It is still not case-folded, and **an entry with
   no base is never matched** — `permissionBaseOf('')` is empty, so a lookup
   without that guard answers with the first entry that has none, which is the
   one entry it must never be.

   **`forClientId()` IS THE SECOND LOOKUP THAT IS NOT BY IDENTIFIER, added
   2026-08-26 beside it, and the paragraph above is exactly why it is a separate
   function.** It matches `oauthClientId`, and `oauth-oidc/oauth2.js`'s
   `audienceScopes()` is its one caller: a scope value that names another
   application becomes that access token's audience, and a scope is a BARE NAME
   where an `aud` from RFC 8707 is a URI. Folding the two into one lookup would
   be the fallback the paragraph above refuses, one function along — the caller
   knows which question it is asking, so it asks it. Same three properties as
   its neighbour: not a permission, not case-folded, a walk rather than an index.

   **FOUR ATTRIBUTES HERE ARE DECLARATION AND NOTHING EVER WRITES THEM** —
   `federationPartnerId`, `ldapBindDn`, `scimClientId`, `spiffeWorkloadId` —
   because those surfaces authenticate the CALLER rather than an application
   (LDAP, SCIM), file the identity in a container of their own (SPIFFE), or keep
   the arrangement under `ou=federations` (Federation). They are the same claim
   `appAllowedProtocol` is, narrowed to a name: a fact an operator has, in the
   place the rest of what that application is already lives. Do not "fix" one by
   wiring a protocol module to write it — check first that the module has an
   application identifier at all, which is what the empty `kinds` on those
   `PROTOCOLS` rows records.

   **`wsfedReplyUrl` SPLIT OFF `samlAssertionConsumerService` ON 2026-08-25**,
   and the reason is worth keeping: that attribute is READ. `/admin/saml2` and
   `/admin/saml11` take the last value on it as the assertion consumer service
   and as the Single Logout fallback, and `wsfed.js` had been writing its
   `wreply` into it — so a WS-Federation application appeared to have named a
   SAML ACS it had never heard of, and a LogoutResponse could have been handed to
   a WS-Federation endpoint. One attribute per fact.

   **`createApplication()` TAKES `fields`, AND IT WAS IGNORING THEM.** The
   member had been in the argument since `saml2Action()` and `saml11Action()`
   were written — both pass `fields: { samlEntityId: identifier }` — and nothing
   read it, so *Register* on either SAML page produced an entry with no entityID
   until a real request arrived and `seen()` wrote one. Nothing failed, which is
   why it survived. `normaliseFields()` is now the one gate: an attribute has to
   be in the schema AND `editable`, so a create cannot assert a counter or a
   sighting, and a `single` attribute given several values is REFUSED rather than
   truncated to the first.

   **THE VOCABULARY IS CLOSED AND VALIDATED IN TWO PLACES BECAUSE THERE ARE TWO
   DOORS.** `createApplication()` refuses an unknown family, and
   `updateApplication()` refuses one on an `add` — but NOT on a `remove`,
   deliberately: a remove names a value that is already on the entry and
   `ldapmodify` can have put anything there, so refusing it would shut the one
   door that could tidy that up.

   **THE MATCH BETWEEN THE TWO LISTS IS ON KINDS AND NOT ON PROTOCOL LABELS**,
   and that is the one thing here that was wrong first and is worth keeping
   written down. `view()` answers `recordedProtocols` beside `allowedProtocols`
   so a page can read them against each other; the first attempt derived it from
   `appProtocol`'s prose labels, and a FEDERATION partner's sighting is recorded
   under whichever protocol its relationship speaks — so every ordinary OAuth
   client read as a federation partner, because both write `OAuth 2.0`. The
   kinds are a closed vocabulary and `federation-identity-provider` is a thing
   an application IS. One consequence is stated on the page rather than hidden:
   a kind can also be given at CREATE time, so `recordedProtocols` is not
   "has authenticated" and `appAuthentications` is the figure that is.

   **`clientConfigOf()` CARRIES `declared` SINCE 2026-09-13, AND IT IS NOT
   `registered`.** OAuth 2.1 mode refuses a token request from a client that
   declares nothing, and "has an entry" cannot be that test, because `seen()`
   gives every client_id that ever reached an endpoint an entry. `declared` is
   *anything on the entry a sighting never writes* — a registration, a redirect
   URI of its own, an authentication method, a credential, an assertion issuer,
   or `appAllowedProtocol` naming an OAuth family — so the list of what an OAuth
   sighting writes (`oauthClientId`, `appAuthorizationServer`, `oauthScope`,
   `oauthResponseType`, `oauthGrantType`, `appRedirectUriObserved`) is a
   constraint on `seen()` callers now: **a sighting that started writing a
   credential attribute would make every client it touched look declared.**

   **AND THE THREE ADDRESS ATTRIBUTES ARE CHECKED ON THE WAY IN SINCE THE SAME
   DAY.** `oauthRedirectUri`, `oauthPostLogoutRedirectUri` and
   `oauthFrontchannelLogoutUri` were never validated at registration, at a
   console `add` or at `/admin-api`, so `javascript:` could be stored in all
   three. `addressProblem()` asks `common/validation.js`'s `redirectUriProblem()`
   (http or https with a host, or a private-use scheme named for a domain — an
   ALLOWLIST, where `validation.types.uri` is a blocklist of five executable
   schemes and must stay one for OID4VC's wallet parameter) and
   `frontchannelUriProblem()` (http or https only — a browser frames it). Only a
   value being ADDED is checked, never a remove or a re-save of what is already
   there, and `register()` / `updateRegistration()` refuse the whole document as
   a backstop behind the endpoint's own 400. `ldapmodify` still reaches all
   three, which is why `frontchannel_logout.js` checks again when it reads.

   **`clientConfigOf()` IS WHAT THE SECURITY CHECKS READ, NOT `registrationOf()`.**
   The two answer different questions — "what may this client do" versus "what
   did it register" — and they stopped coinciding the moment the console could
   create an application with redirect URIs and no registration behind it. So
   the RFC 9700 checks in `oauth2.js` pass `clientConfigOf()`, which is built
   from the ATTRIBUTES; `appRegistered` records how an application got here and
   not whether what it holds counts. `registrationOf()` is still what RFC 7592
   and the UserInfo signing algorithm read, because those are genuinely
   questions about the registration.

   **THE TWO APPLICATIONS THAT ARE THIS PROCESS ARE SEEDED AT STARTUP, AND
   THEY ARE REGISTRATIONS RATHER THAN LABELS.** Every other entry arrives
   because a caller PRESENTED an identifier; the admin console and the
   management API are surfaces of this process, so nobody ever does, and the
   registry answered "what applications have you seen?" with everything except
   the two things the reader was standing in. `seedInternalApplications()` at
   the foot of this file writes `sts-admin-console` (a confidential OIDC
   relying party on the code grant) and `sts-management-api` (a confidential
   client on `client_credentials`), each with a secret and an RFC 7592
   registration access token minted at startup — so `clientConfigOf()` answers
   for them, RFC 9700 mode checks those secrets, and `GET
   /oauth2/register/{id}` reads back. Four rules on it. The call sits in
   `ldap_server.js` IMMEDIATELY AFTER `setDirectory()` — the earliest moment
   there is a container, and the reason it cannot live in that file's `seed()`,
   which builds the tree and does not know this schema. It is seeded ONLY WHERE
   THE IDENTIFIER IS FREE (`spiffe_registry.js`'s rule: an operator who deleted
   one meant it). And `applications.seedInternal` turns it off, restart-only
   because this runs once at require time.

   **THERE ARE THREE OF THEM SINCE 2026-09-06, AND TWO OF THEM ARE NOW
   LOAD-BEARING RATHER THAN DESCRIPTIVE.** `sts-user-portal` joined the pair,
   and — the change that matters — **`/admin` and `/portal` AUTHENTICATE
   THROUGH THESE ENTRIES**. They are relying parties of this service's own
   authorization server: an unauthenticated request is sent to
   `/oauth2/authorize` as the client below, comes back to the redirect URI
   below with a code, and the code is redeemed at `/oauth2/token` with the
   secret below. `common/oidc_rp.js` is the client and argues the whole of it.
   This paragraph used to say *nothing serves `/admin/callback` … the console's
   gate is a sign-on session and two directory groups*; the ROLES half of that
   is unchanged and the AUTHENTICATION half has moved onto the protocol.

   Four consequences worth knowing before editing one of these rows:

   * **DELETING ONE TAKES ITS SURFACE OFFLINE UNTIL A RESTART**, with a refusal
     that names the entry rather than a redirect into a flow that cannot
     complete. That is the seeding rule (*an operator who deleted one meant
     it*) finally having an observable consequence.
   * **`realmScope` decides where each is seeded**, and the three answers are
     three different arguments — argued on the rows themselves. The console's
     client is the DEFAULT realm's alone, because its gate accepts that realm's
     session wherever the console is reached; the portal's is in EVERY realm,
     because `/portal` reads the ambient realm's session; the management API's
     is a description of a caller rather than a client anything signs in as.
   * **BOTH CARRY `oauthGlobalConsent`.** `oauth2.consentRequired` is on by
     default and is the only policy here that is, so without it a person
     signing in to look at their own account would first be asked to consent to
     this service reading their own profile — a question with one sensible
     answer, in front of every sign-in, whose Deny button makes the surface
     unreachable. It is an ATTRIBUTE rather than an exemption in `consent.js`,
     so an operator who wants the screen removes the values and gets it.
   * **The redirect URI on the entry is LEARNT as well as seeded — in
     DEVELOPMENT, with `global.publicBaseUrl` empty, up to
     `oidcRp.maxRedirectUris`.** The seeded value names `localhost:<port>`,
     because it is written before any request exists; the first flow through a
     different base ADDS that base's callback, since RFC 9700 mode matches
     `redirect_uri` by exact string and a service reached by a container name
     would otherwise refuse itself. **Two corrections on 2026-09-12**: the base
     comes from the request's `Host` header whether or not `global.trustProxy`
     is on, so learning in product mode was an anonymous way to plant a
     callback on this service's own client — it is REFUSED there now, and a
     pinned base is never learnt — and the call that learnt it had never worked
     at all (it passed one object where `updateApplication()` takes an
     identifier and a change), so this bullet described a behaviour nothing had
     ever performed. `common/oidc_rp.js`'s `ensureRedirectUri()` carries both.

   **TWO ATTRIBUTES HOLD CREDENTIALS IN THE CLEAR** — `oauthClientSecret` and
   `appRegistrationAccessToken` — which is the `/krb5/principals` decision about
   the Kerberos passwords, made again and for the same reason. Now that RFC 9700
   mode CHECKS that secret, anyone who can read the directory can authenticate as
   that client; that is the honest state of a service that authenticates nobody.
   They are never given to `audit.js`, whose no-credential rule is untouched.


---

3l. **`delegation.js` is a library like `audit.js`, it sits BESIDE
   `admin_stats.js` too, and THERE IS NO FUNNEL FOR IT — which is the one thing
   about it that breaks a pattern this repository otherwise keeps.**
   `admin_stats.js` answers "how much", `audit.js` answers "what, when and to
   whom", and this answers *who acted on whose behalf, through what, to reach
   what* — one model over Kerberos S4U2Self, S4U2Proxy (classic and
   resource-based) and a forwarded TGT, WS-Trust `OnBehalfOf` and `ActAs`, and
   RFC 8693 token exchange in both its shapes.

   It requires `helpers.js`, `config.js` and `admin_stats.js` — that last one
   for `identityKeyOf()`'s normalisation only, so that `alice`, `alice@REALM`
   and her `urn:uuid:<entryUUID>` (or the retired `urn:sts:user:alice`) are
   one person on a chain rather than three.
   `admin_stats.js` requires nothing here, so there is no cycle and none of
   rule 3e's slots is needed. Keep it that way: it is called from the KDC, from
   WS-Trust and from the token endpoint, and anything it required all three
   would require transitively.

   **THE MISSING FUNNEL IS THE THING TO UNDERSTAND BEFORE CHANGING ANY OF IT.**
   `signJwt()` is the single point every JWT passes and
   `recordAuthentication()` is the single point every accepted credential
   passes, so each of those is counted in one place and a new call site cannot
   be forgotten. Delegation has no such point and cannot be given one: it
   happens in three modules that share no code path, and the moment it becomes
   visible is different in each — a padata in a TGS-REQ, an element in an RST,
   a form field on a token request. So this file is called from several places
   ON PURPOSE. What the shape buys instead is that all of them produce the same
   row, and each caller is as close as possible to a funnel of its own:
   `krb5_kdc.js` records ELEVEN refusal paths at ONE site, by carrying an
   `intent` out of `resolveS4u()` through `refuseS4u()`.

   **REFUSALS ARE RECORDED AND THAT IS MOST OF THE POINT.** A delegation that
   succeeded is also an accepted credential, so it already has an
   `authentication` row and a `/admin/users` row. A delegation that was REFUSED
   has neither — nothing was accepted — so this is the only list it is in, and
   it is the one somebody hunting a misconfiguration actually wants. The reason
   on the row is the KDC's OWN `e-text`, the same sentence the client was sent,
   rather than a second wording that could come to disagree with it.

   **NOTHING HERE WRITES AN AUDIT ROW, deliberately.** A successful act would
   get a second row for one act, which is the double-count rule 3c warns about;
   a refused one writes none because nothing was accepted, and closing that gap
   is what this store is for rather than a seventh audit category. Cite this
   paragraph before adding an `audit()` call to it.

   **IT IS `merge: 'own'` AND FOR TWO DAYS IT FANNED NOTHING IN (2026-09-11).**
   The store is an ACCUMULATOR — a row is a thing that happened, not a value —
   so it is declared `merge: 'own'`, which is right and is `audit.js`'s event
   ring word for word. What that declaration MEANS is the part this file did
   not honour: `persistence_minted.js`'s applier hands another process's `own`
   row to `replication.contribute()` rather than to the store, on purpose, so
   **the merge has to happen on the way OUT** and every reader of such a store
   owes a `remoteRows()` call. `audit.js`, `admin_stats.js` and
   `xacml_monitor.js` all make one; this file made none, so in `dispatch` mode
   a reader saw only the acts the worker answering it had recorded itself.
   `sts_jwt_bearer_grant` and `sts_saml2_bearer_grant` both asked
   `/admin-api/delegation` for an act the token endpoint had recorded on a
   different worker and were both answered with an empty list.

   `merged()` is the fan-in and `list()` and `summary()` are its only callers,
   which is what makes it complete: every other view function here takes `rows`
   or falls back to `list()`. Two consequences are audit.js's and are stated
   there — `seq` is monotonic only within one process, so the sort is by TIME,
   and the cap is per process. **The test to apply to the next `merge: 'own'`
   store is not "is it declared right" but "does everything that REPORTS it
   fan in"**: three stores in this service still do not, and each is a page
   that under-reports rather than a page that is wrong —
   `admin_stats.scimCounts`, `admin_stats.users` and `ssf_streams.received`.

   **`record()` CANNOT THROW.** The whole body is wrapped and a caller must
   never guard it — the fourth place that rule applies (after `audit()`,
   `signJwt()`'s recorder and the directory's user observer), and the first
   where the thing it protects is a Kerberos ticket already half built.

   **A ROW IS AN ACT, NOT A RELATIONSHIP**, and `chainKey` is what collapses
   them: the mechanism and the three parties, with the time, the credentials
   and — deliberately — the OUTCOME left out, so a chain refused nine times and
   then fixed is ONE edge that changes colour rather than two that never meet.
   `chainList()` is where the collapse lives, here rather than in `admin.js`,
   because what counts as one chain is a statement about this store.

   One thing it deliberately does NOT do: create an application entry for a
   layer it names. `ou=applications` holds what this service was ASKED ABOUT,
   and a delegation naming something nobody has otherwise mentioned — an RFC
   8693 `audience`, typically — is an ordinary and interesting outcome. The
   page resolves the name against that registry and reports which of the two it
   found; writing the entry from here would be a fifth door onto it and would
   make the page unable to report the difference.

   **`graph()` IS THE PICTURE'S MODEL AND IT IS NOT `chainList()` WITH BOXES.**
   `/admin/delegation/map` draws it and `../admin-ui/delegation_map.js` lays it
   out; this file says what the nodes and edges ARE, for the reason every other
   view function is here — what counts as one party is a statement about this
   store. It walks the ACTS rather than that function's answer, deliberately: a
   chain has three parties and therefore up to TWO edges, the boxes are SHARED
   between chains (which is the whole reason to draw one), and it needs the two
   things `chainList()` drops on purpose — the CREDENTIALS, since the picture is
   asked to say what was issued, and the spread of one identity across roles.
   Reading them back off a chain would have meant putting them into a chain and
   making that shape a worse answer to the question it does answer.

   Four judgements are in it and each is argued at length above the function. A
   NODE IS AN IDENTITY rather than a role, so a party that is the target of one
   chain and the intermediary of the next is ONE box with a line in and a line
   out. AN ABSENT PARTY IS NOT A BOX and the edge jumps it, carrying `skipped` —
   a shared "(nobody named)" node would make every unconstrained delegation in
   the process appear to converge on a party they have in common. A SELF-EDGE IS
   A FACT ABOUT THE BOX (`selfTarget`) and not a loop on it, because S4U2Self is
   a ticket to yourself and an arrow leaving a box and coming back draws nothing.
   And THE ISSUER IS IN THE PICTURE and is not a party: one node carrying the
   TRUST REALM, with an edge to whoever ASKED — the intermediary where a chain
   has one, the initial identity where it does not.

   **`nodeIdOf()` is `chainKeyOf()`'s expression with the APPLICATION normalised
   too**, and that difference is not an oversight in either. A party carries
   `key` — `identityKeyOf()`'s answer — only when something was PRESENTED, so a
   target names an application and its identifier arrives exactly as the protocol
   spelled it. On an S4U2Self that is one principal twice, and unnormalised the
   picture drew the requester and the service it asked for a ticket to ITSELF as
   two boxes with a line between them. **Two spellings of one identity is two
   people** — the rule `dnRfc4514()` and `userFor()` follow one layer down. The
   TABLE is deliberately left alone: it shows both spellings side by side, where
   seeing them is the point, and changing `chainKey` would change what
   `/admin-api/delegation` calls a chain.

   **`actsOfChain()`, `applicationList()`, `applicationRolesIn()` and
   `actsForApplication()` are the same rule again, for the two drill-downs the
   console grew on 2026-08-25.** They are here, beside `chainList()`, because
   each answers a question about what the STORE holds rather than about how a
   page looks: which acts belong to one chain, which applications appear in
   these acts, and what role a given application played in a given act. A
   `filter()` in `admin.js` would have been a second opinion about the last of
   those and would have drifted from the first.

   **The APPLICATION is keyed on its IDENTIFIER and deliberately NOT on
   `nodeIdOf()`'s answer**, which is the one thing to understand before touching
   any of them. A node is what a party IS — its normalised identity where it
   presented one — and for a Kerberos front end that is the same string as its
   application. For an RFC 8693 exchange it is not: the intermediary's box is
   the ACTOR named in the actor_token, and the application it acted THROUGH is
   the `client_id` beside it. So a chooser built on node ids would offer that
   client under a person's name or not at all, and *show me everything delegated
   through this client* is the question `/admin/delegation/application` exists to
   answer. The identifier is normalised the way `nodeIdOf()` normalises one, so
   two spellings are one application, and every spelling is kept beside the key —
   the collapse has to be something a reader can SEE, which is `party()`'s reason
   for keeping `presented` next to `key`.

   **The CONFIGURED half of `/admin/delegation` is NOT in this file.** Who may
   delegate to whom is `krb5_principals.js`'s `delegationPolicy()`, because
   what those two attributes mean is a statement about the principal database
   and that store is over there. A `common/` module reaching into `kerberos/`
   would have been the layering inversion this directory's entry test exists to
   prevent; `admin.js` requires both and renders them side by side.

3s. **`app_permissions.js` is a library, and the whole of it is the argument
   for why a CONFIGURED register is not the observed one with a flag on it.**
   `delegation.js` above holds ACTS — one row per exchange, at a moment, with a
   credential in it. This holds GRANTS: which client applications have been
   given which permissions on which resource applications, typed in before
   anybody asked for anything. It requires `helpers.js` and `applications.js`
   and nothing else; neither requires it back, so there is no cycle and none of
   rule 3e's slots is needed.

   **THE TWO MUST NEVER BE DRAWN AS ONE REGISTER**, and this repository already
   keeps exactly that distinction one file over: `appProtocol` is what happened
   and `appAllowedProtocol` is what somebody declared, and `applications.js`'s
   PROTOCOLS header spends a page on why collapsing them would be wrong.
   `/admin/delegation` shows both and says which is which on every heading,
   because the interesting reading is the DIFFERENCE — a grant nobody has used,
   and a delegation nobody granted.

   **THE MODEL IS ENTRA ID'S, DELIBERATELY AND BY NAME.** A resource
   application exposes an API (`oauthPermissionBaseUri`, their Application ID
   URI; `oauthPermission`, their `oauth2PermissionScopes`) and a client is
   granted some of them (`oauthDelegatedPermission`, their
   `requiredResourceAccess`). A permission is identified by the base URI
   followed by its name, and a client asks for it by putting that whole string
   in an OAuth `scope`. **One-to-many and many-to-one both fall out of that one
   identifier with no container of their own** — three permissions granted to
   one client is three values on one entry, and one permission granted to three
   clients is one value on each of three — which is why there is no
   `ou=delegations` and why there should not be.

   **`ou=applications` IS THE STORE AND THERE IS NO SECOND ONE HERE.** Every
   function is a read of the registry or a write through
   `applications.updateApplication()`. That is `applications.js`'s own rule
   applied again: a Map in this file would look correct alone and would be the
   one that silently disagreed. It also means an `ldapmodify` IS a
   configuration change here, exactly as it is for a redirect URI.

   **THE DIVISION OF LABOUR WITH `applications.js` IS EXACT**, and it is the
   split `delegation.js`/`delegation_map.js` already have. THAT module owns the
   SCHEMA — how a permission is spelled (`name` or `name|description`), how base
   and name are joined (`permissionIdOf()`), which spellings are legal, and the
   two lookups a reader of ONE entry needs (`forPermission()`,
   `holdsPermission()`). THIS module owns what the two halves MEAN read against
   each other: the register in both directions, the five actions, and the graph.

   **THE ORDERING RULE IS ENFORCED IN `applications.js` AND NOT HERE**, and
   that is worth stating because this is where somebody will look for it. A
   permission must be DEFINED before it can be GRANTED, and the check lives in
   `updateApplication()` because that is the ONE door the console form, the
   management API's generic `update` operation and the five actions below all
   go through. A copy here would be a second opinion, and the generic attribute
   editor would be the way around it.

   **`graph()` RETURNS `delegation.graph()`'s SHAPE**, so `delegation_map.js`
   draws it with no argument about which graph it is looking at — which is the
   property that file's header says it was split out to keep. Three things
   about it are claims rather than mechanics, and `tests/app_permissions.js`
   asserts all three: **every box is an application and there is no person on
   it** (a permission says *this client may reach that API as whoever is signed
   in*, and there is no whoever yet); **this service is not on it either**, so
   no hexagon, because every line on the acts picture exists because something
   was issued and none of these has been asked for; and **`acts` stays zero on
   every box**, which is load-bearing rather than tidy — `edgeLook()` paints an
   edge RED when `acts && !issued`, so a box claiming an act would draw every
   configured grant in the refusal colour.

   **ONE EDGE PER PERMISSION, NOT PER PAIR**, for `delegation.graph()`'s reason
   about two mechanisms joining the same boxes. And a line is DASHED until the
   client has actually asked for that permission — read off its own
   `oauthScope` — which is the single most useful thing a configured picture can
   say and the one thing an acts diagram can never say, because a grant nobody
   needed draws no act at all.

   **`clusters()` PARTITIONS IT, AND IT IS THE FILE'S ONE READING OF THE
   REGISTER THAT IS NOT A ROW OF IT (2026-09-02).** `graph()` answers *what may
   reach what* for the whole registry at once, which is the right picture for
   five applications and the wrong one for eighty: past a certain size the
   interesting reading is never the whole of it, it is which applications are
   joined to each other at all. So a GROUP is a connected component of the grant
   graph, `/admin/delegation/allowed` lists them and
   `/admin/delegation/cluster` draws ONE.

   **THE DIRECTION IS IGNORED, AND THAT IS THE ONE DECISION IN IT.** A grant is
   directed — the picture draws both ends differently precisely because they are
   not interchangeable — but following the arrows would answer *what can this
   client eventually reach*, which is a question about a CHAIN, and **this
   register has no chains in it**: holding a permission on an API does not grant
   that API's own permissions to anybody, so the transitive reading is a claim
   the model does not make. Following a grant either way is the only reading
   under which an API and the three front ends holding permissions on it come
   out as ONE group rather than as four. Membership ignores direction; the
   picture does not.

   **THE MEMBERSHIP UNIVERSE IS EVERY RESOURCE AND EVERY CLIENT, NOT THE TWO
   ENDS OF EVERY GRANT.** An API with permissions defined and nothing granted on
   them appears in no grant, so a partition built from the grants alone would
   have dropped it — and *somebody described an API and nothing may reach it* is
   the most interesting group of one there is. The other two groups of one are a
   client holding only DANGLING grants (no application defines the permission,
   so there is no far end) and an application granted its OWN permission (one
   application however it is drawn); each is reported as what it is rather than
   left as an empty page.

   **A GROUP IS NAMED AFTER THE MEMBER WHOSE IDENTIFIER SORTS FIRST AND NEVER
   AFTER THE UNION-FIND ROOT.** The root is whichever identifier the joins
   happened to leave on top, so it moves when a grant is added anywhere inside
   the group — and every link to a group on the console would go stale for a
   reason nobody could see. The first member is a property of the SET.

   **`counts.lines` IS WHAT THE RENDERER WILL ACTUALLY DRAW** and is computed
   here rather than by the page, because a table reading `3 grants` above a
   diagram with one line on it is the console disagreeing with itself about the
   same three rows. `tests/app_permissions.js` asserts it against
   `graph()`'s own edge count, along with the direction decision — over the one
   shape that tells the two readings apart, two clients of one resource, which
   a ring cannot.

3p. **`user_graph.js` is a library over TWO registers, and the whole of it is
   the argument for why the union is here rather than in the console.** It
   requires `helpers.js`, `admin_stats.js` and `delegation.js`; nothing requires
   it but `../admin-ui/admin.js`, which renders it at `/admin/delegation/user`.
   It registers no route, so rule 3e's test is not even reached — a plain
   require in the ordinary direction closes no cycle and moves nothing.

   **THE QUESTION IT ANSWERS CANNOT BE ASKED OF EITHER REGISTER ALONE.**
   `/admin/delegation/application` next door narrows the ACTS and hands them to
   `delegation.graph()`, because both halves of *what has been delegated through
   this application* live in one store. *What has this service done in alice's
   name* does not: an act is by definition a request carrying two credentials,
   and an authorization code grant is not one, nor is a Kerberos AS-REQ, nor a
   SAML assertion. Drawn from the delegation register alone, somebody who signed
   in nine times and holds twenty tokens is an EMPTY PICTURE. So this file
   unions that register with `admin_stats.js`'s — the tokens, the artifacts and
   the authentication events — and it is a file rather than a `filter()` in
   `admin.js` for the reason every other view function moved down here: the join
   is a statement about what the two stores MEAN, and a renderer holding a
   second opinion about any of it is drift nothing can see.

   **IT EXTENDS `delegation.graph()`'s SHAPE AND DOES NOT INVENT A SECOND ONE.**
   `graphFor()` starts by calling that function for the acts naming this person
   — so the delegation half is drawn by the code that owns it, byte for byte as
   `/admin/delegation/map` draws it — and folds the issuance on top as nodes and
   edges carrying the same fields plus three (`credentials`, `flows`,
   `isSubject` on a node; `credentials` on an edge). `../admin-ui/delegation_map.js`
   therefore draws this picture with no idea it is different. A second shape
   would have meant a second renderer, and two renderers agreeing about what a
   box means is a thing that stays true for about a month.

   **TWO NEW `relation` VALUES, AND NEITHER TAKES A MODE COLOUR.** `signed-in`
   runs from the person INTO the hexagon, one line per protocol family, labelled
   with the methods — it is the authentication half, and without it the picture
   shows tokens beside somebody who as far as the drawing goes has never been
   here. `issued-for` is a credential going to whoever holds it, LABELLED WITH
   THE GRANT. Amber and green are this console's judgement about impersonation
   versus delegation, which are properties of a DELEGATION mechanism; an
   ordinary grant claims neither, so colouring one green would tell a reader who
   learnt the pairing from the table something false.

   **AND SINCE 2026-08-26 A THIRD LINE, WHICH IS NOT A THIRD RELATION.** An
   access token issued to `webapp1` and addressed to `apigw1` is this service
   saying that webapp1 may reach apigw1 in that person's name — which is exactly
   what a token exchange's `reaches` line says, with no exchange in it. It was
   drawn only where an exchange had happened until then, so the FIRST HOP of
   every chain was missing: the picture showed `apigw1 → esb1` and `esb1 → sp1`
   and nothing at all about how apigw1 came to hold a token. So the audience of
   every credential drawn here gets a `reaches` line from whoever HOLDS it,
   keyed on the grant the way the `issued-for` line is, carrying the SAME
   relation value the delegation half emits rather than a fifth one — the fact
   being stated is identical, and the mechanism on the label is what tells them
   apart. A second relation would have been a second colour and a second row in
   the legend for one idea.

   Three consequences, and each is a place this could have gone wrong quietly.
   The audience is resolved through the applications registry
   (`audienceParties()`, exported for `credential_graph.js`, which had a copy of
   it), so a token addressed to `https://apigw1.example.com` lands on the BOX
   for apigw1 — the failure the exchange's own lookup already exists to prevent.
   **It is TWO lookups since 2026-08-26** — `forAudience()` then
   `forClientId()` — because an audience here is as often a bare NAME as a URI:
   that is what `oauth2.js`'s `audienceScopes()` writes when a client names the
   API it wants in its scope list instead of through RFC 8707, and `apigw1` and
   `https://apigw1.example.com` have to land on ONE box or this console has
   invented a party.
   An `aud` naming SEVERAL resources draws several lines, because RFC 7519
   section 4.1.3 allows a list and RFC 8707 section 2.3 is how one gets here,
   and `recordJwt()` joins them with a space: a single lookup of the joined
   string finds nothing and draws one box named after two URLs. And an audience
   that is **this service's own** is not a party and is dropped — a refresh
   token is addressed to the token endpoint and an access token nobody named a
   resource for carries `<base>/resource`, so without that rule every plain
   sign-in gained a box called `http://localhost:8081/resource`. That last check
   is why `recordJwt()` keeps `iss`: `oauth2.issuer` is empty by default so one
   process answers correctly under every name it is reached by, which makes the
   base a property of the REQUEST — by the time a page reads the record there is
   no request to ask, so the token has to have remembered it.

   **`FLOWS` IS KEYED ON THE STRING `oauth2.js` ALREADY RECORDS, VERBATIM.**
   `issuanceContext()` over there puts a `grant` on every signed JWT and
   `recordJwt()` keeps it; those strings are the ids here rather than a tidier
   vocabulary, because a translation that misses a value fails SILENTLY. An
   unknown one comes back NAMED AFTER ITSELF with a warning — the choice
   `delegation.js`'s `recordUnguarded()` makes about a type it does not know —
   so a grant added to `oauth2.js` and not to this table shows up as a bug
   report rather than as an empty cell. **Adding a grant there is a row here**,
   and nothing else.

   **A CREDENTIAL BOTH REGISTERS KNOW IS DRAWN ONCE, DEDUPED ON THE IDENTIFIER
   AND NOTHING ELSE.** An RFC 8693 exchange writes a delegation act AND a token
   record for one access token, so the issuance half skips any JWT whose `jti`
   the delegation half already carries, and the count of what was skipped is
   REPORTED rather than left to be noticed. Matching on anything softer — a
   subject and a kind within a time window — would eventually collapse two real
   credentials into one, which is worse than listing one twice. **The Kerberos
   overlap therefore survives on purpose**: an S4U service ticket is in both
   registers and has no identifier in either, so it is drawn on both lines and
   the page says which register each came from.

   **AND SINCE 2026-09-02 THAT LINE SAYS WHAT THE TOKEN MAY DO AT THE FAR END,
   which is the one thing the ACTS picture could never say and the CONFIGURED
   one always could.** A `may-reach` line on `/admin/delegation/allowed` carries
   the permission it is a grant of, because a configured grant IS a permission;
   a `reaches` line drawn from an issued token carried the mechanism and a
   credential count and nothing else — so the picture showing what a client DID
   was the one that could not say what it did it WITH.
   `permissionsAddressedTo()` is the rule, and it is three sentences.

   **IT IS ASKED OF THE TOKEN AND NOT OF THE REQUEST, which is what makes the
   two spellings a client may use come out as one rule.** `oauth2.js`'s
   `audienceScopes()` turns `scope=https://api.example.com/read` into
   `aud: https://api.example.com/` and `scope: read`, and turns `scope=apigw1`
   into `aud: apigw1` with that value taken OFF the scope claim. Whichever was
   sent, what arrives here is an audience and a scope claim — so the rule is
   *the scope values that name a permission THIS resource defines*, resolved
   through `applications.forPermissionBase()` beside the two lookups
   `audienceParties()` already makes. The first spelling answers with names; the
   second answers with none, and **an EMPTY ARRAY is an answer** — the picture
   draws it as `default permissions`, which is the commonest state there is.

   **THE INTERSECTION IS WHAT MAKES IT SAFE.** A scope claim carries the
   protocol's own words and anything else a client cared to send, so a label
   built from the scope claim alone would name a resource with `openid`. Only
   names the resolved resource has DEFINED are reported, which also means a
   permission removed from the register since the token was minted drops off the
   line — the same reading `audienceParties()` makes when it resolves an `aud`
   against the CURRENT registry.

   **AND NOTHING HERE ASKS WHETHER THE GRANT WAS HELD.** `holdsPermission()` is
   that question and it belongs to the configured register;
   `oauth2.delegatedPermissionsEnforced` is off by default, so a token carrying
   a permission its client was never granted is an ordinary outcome here and the
   line reports what was ISSUED. Colouring it as a refusal would be this model
   deciding a policy the token endpoint declined to decide.

   **THE ARRAY'S PRESENCE IS THE DISCRIMINATOR, and that is load-bearing rather
   than incidental.** `delegation.graph()` emits the identical `reaches` relation
   for a delegation ACT, which has no scope claim anywhere behind it and carries
   no such member — so `delegation_map.js` tests for the member rather than for
   the relation, and an act line says nothing instead of saying `default
   permissions` about a Kerberos ticket. An edge seeded without it would be
   drawn as an act.

   **IT ALSO MOVED THE AUDIENCE BLOCK OUT OF `if (holder)`.** `holder` is null
   when the credential's `client_id` IS the box the page is about, which is what
   the CLIENT CREDENTIALS grant looks like here — so that guard drew the grant
   line and threw away the only interesting thing about a machine-to-machine
   token: which API it was for. The line now runs from the holder, or from the
   person where there is no separate holder.

   **`credential_graph.js` DRAWS THE SAME LINE AND TAKES THE SAME ANSWER**,
   through an export, for the reason `holderOf()`, `detailOf()` and
   `audienceParties()` are already exported to it: two answers to *which
   permissions does this token carry* would be two labels on one relationship on
   two pages of one console.

   **`userList()` UNIONS THE TWO REGISTERS TOO, and that is the half worth
   keeping.** An identity named only by a delegation — an S4U2Self subject, an
   `OnBehalfOf` — has never authenticated and may have been issued nothing, and
   *there is no such person* and *somebody was impersonated who has never signed
   in* are opposite answers to one question. The chooser offers both and each
   row says which side it came from.

---

3q. **`credential_graph.js` is the same union asked a NARROWER question, and it
   is a file for the same reason `user_graph.js` is.** It requires `helpers.js`,
   `admin_stats.js`, `delegation.js`, `user_graph.js` and `applications.js`;
   nothing requires it but `../admin-ui/admin.js`, which renders it at
   `/admin/tokens/credential` — the first drill-down the tokens page has ever
   had, reached from every identifier in its last column. It registers no route,
   so rule 3e's test is not reached.

   **A LINE, NOT A FAN, WHICH IS WHY IT IS NOT A FILTER ON THE PERSON'S
   PICTURE.** `user_graph.js` answers *what has this service done in alice's
   name*; this answers *where did THIS credential come from*, and the answer is
   an ancestry. A token exchange consumes one credential and produces another,
   so the identifiers form a chain, and following it is the only way to get from
   an access token that reaches `sp1` back to the browser sign-in three tiers
   away that everything after it rests on. Filtering the person's picture cannot
   do it: that picture is every credential ever issued in their name, with
   nothing to say which four are this one's ancestors.

   **THE JOIN IS THE IDENTIFIER AND NOTHING ELSE.** An act records what it
   CONSUMED and what it PRODUCED, each with the identifier its protocol gives it
   — a `jti`, an `AssertionID` — and that is the one thing both registers hold
   about the same object. `stats.issuedById()` (added with this file, for the
   same reason `issuedList()` lives over there rather than in a caller) turns
   one into a row. Anything cleverer — a subject and a time window, a kind and a
   client — would eventually join two credentials that merely look alike, and a
   lineage that is WRONG is worse than one that is short, because the whole page
   is an assertion about causation.

   **A WALL IS NOT AN ORIGIN, and they are reported separately.** Two mechanisms
   here consume a credential with nothing to quote: WS-Trust consumes the
   requester's WS-Security credential, which this service never issued, and a
   Kerberos ticket has no identifier in the protocol at all. So a trail can stop
   because it has reached the beginning, or because the thing handed in cannot
   be named — and those are opposite answers. `walls` carries the second.

   **THE ORIGIN IS DRAWN AS AN ISSUANCE, IN `user_graph.js`'s VOCABULARY.**
   `issued-for` from the person to the application, labelled with the GRANT, plus
   the dashed `issued` line from this service — not `acts-for`, which would
   colour an authorization code grant amber for impersonation and claim a
   mechanism that was not involved. The two pages therefore agree about what an
   issuance looks like, which is what lets somebody read both. It is also why
   `holderOf()` and `detailOf()` are exported from that file rather than written
   again here: two answers to *whose token is this* would be two pictures of one
   issuance on two pages of one console.

   **THE AUDIENCE IS RESOLVED THROUGH THE REGISTRY, exactly as the token
   exchange resolves one** (`applications.forAudience()`, and see the
   `oauthAudience` note in 3g). A box for `https://esb1.example.com` beside a box
   for `esb1` would be two parties for one, which is the failure that lookup
   exists to prevent. And the audience is drawn ONLY for the credential at the
   head of the line: everything below it was produced by an act, and the act
   already says where it went. **The lookup itself moved to `user_graph.js` on
   2026-08-26** — `audienceParties()`, required from here the way `holderOf()`
   and `detailOf()` already are — because the person's picture draws the same
   resource at the end of the same line, and two answers to *what is this token
   for* would be two pictures of one issuance on two pages of one console. This
   file's own copy had two bugs the shared one does not: an `aud` naming several
   resources came back as one box named after a joined string, and an audience
   that is this service's own was drawn as a party. `applications.js` is no
   longer required here at all.

   **IT WALKS BACKWARDS ONLY.** *What was later made from this* is a tree rather
   than a line — one subject token can be exchanged by any number of clients —
   and drawing both would make the common case, a credential with no ancestry and
   no descendants, into a page explaining itself in two directions. The forward
   direction is what `/admin/delegation` and its map are for.

## An OAuth client is not a person, and now it has somewhere to be

* **An OAuth client is not a person, and now it has somewhere to be.** It is still
  skipped by `autoCreateUser()` — `ou=users` is for people — but every client,
  relying party, service provider and Kerberos service gets an entry under
  `ou=applications` instead (rule 3g). That container is a REGISTRY rather than a
  record: the RFC 7591 registrations live there, nothing caches them, and an
  `ldapmodify` — or a form on `/admin/applications`, or a POST to
  `/admin-api/applications/{action}`, which are the same functions — changes what
  the protocol endpoints do. What those two will NOT change is the derived half:
  the counters and the sightings are what happened, and only LDAP reaches them.
  Since 2026-08-25 there is a THIRD door onto the create, `/admin/applications/new`,
  and it is not a third store either: it posts `action=create` to the same
  endpoint the list page's own row does.

## AN APPLICATION ENTRY CAN NOW CARRY ITS OWN SAML SETTINGS, AND THAT IS A THIRD KIND OF ATTRIBUTE

Added 2026-08-27. Ten attributes — five per SAML profile — each naming one
`config.js` setting in an `overrides` member on its SCHEMA row and, where the
entry carries a value, winning over that setting for that application alone.

**IT IS A THIRD KIND, AND THE SECTION BELOW'S TWO-WAY SPLIT IS WHY THAT NEEDS
SAYING.** Every attribute here used to be either RECORDED (what happened) or
DECLARED (what somebody said, which nothing reads). These are declared AND read:
`saml/saml2_sso.js` and `saml/saml11_sso.js` resolve every one of their five
settings through `settingFor()` on every assertion. They join
`appFederationRelationship` and `appAuthnMechanism` on the short list of
declarations that actually do something — and unlike those two, what they change
is not WHERE somebody signs in but what the document they get looks like.

**THE MAPPING IS BUILT FROM THE SCHEMA, ONCE, AND THERE IS NO SECOND TABLE.**
`OVERRIDE_ATTRIBUTES` is derived from the rows' own `overrides` members at
require time; `settingFor()` reads it, `overridableSettings()` publishes it, and
`/admin/saml-assertions` and `/admin/applications/new` both draw from that.
Adding an eleventh override is a row in `SCHEMA.attributes` and nothing else — a
map written by hand here would be the first thing to disagree with the schema.

**`config` IS PASSED IN RATHER THAN REQUIRED**, which keeps this module's near-
empty require list true (rule 3g) and keeps the resolver testable with a stub.

**ALL TEN ARE `single`, AGAINST THE GRAIN OF EVERY IDENTIFIER HERE.** Those are
`multi` because an application answering to two client_ids is one application. A
SETTING is the opposite case: there is one answer to "sign the assertion?", and
a list would be a question with no rule for which value won.

**IT IS TWENTY-ONE ATTRIBUTES ACROSS FOUR PROTOCOLS SINCE THE SECOND PASS**, and
the mechanism did not change to take them: SIX OAuth 2.0 / OIDC per-client
settings, the SAML ten, WS-Federation's assertion lifetime, and the group
claim's four. Each is a row in `SCHEMA.attributes` carrying `overrides`, and
that is the whole of what adding one costs — `settingFor()`, the New Application
form, both defaults pages and `GET /admin-api/saml-assertions` all read the same
derived table.

**THE SIXTH OAUTH ONE IS `oauthTokenExchangeRefreshToken` (2026-09-02) AND IT
BROUGHT A NEW MEMBER WITH IT: `families`.** It overrides
`oauth2.tokenExchangeRefreshToken` — whether an RFC 8693 token exchange this
client performs comes back with a refresh token, in three words rather than two;
`oauth-oidc/CLAUDE.md` argues the values. What is new here is not the override,
which is the same derived table as the other twenty, but the SCOPE:

* **A row may declare `families: ['oauth2', 'oidc']`, and the attribute may then
  only be WRITTEN onto an entry declared for one of them.** Both write doors go
  through `familyRefusal()` — `updateApplication()` reads the list off
  `appAllowedProtocol` and `createApplication()` passes the families the create
  is about to write, which is why that function takes the list as a PARAMETER
  rather than reading it: at create time the attribute does not exist on the
  entry yet, and a check that read an empty entry would refuse the one
  submission that ticks the family and fills the field together.
* **The console filters its two selects through the same function**, so the rule
  `editableOptions()` already followed — a form cannot offer a field the action
  would refuse — stays true with nothing written down twice.
* **WHY THIS ONE AND NOT THE OTHER TWENTY.** Every other override is a DEFAULT
  something reads if it ever gets the chance, so `saml2SignAssertion` on an
  OAuth client is inert rather than wrong and refusing it would be this registry
  having an opinion about an attribute nothing reads. This one decides what the
  TOKEN ENDPOINT does for one `client_id` — so on an entry no token request
  could ever name, it is not inert, it is a POLICY SOMEBODY BELIEVES IS IN
  FORCE. That is the state the refusal exists to prevent, and it is the test to
  apply before putting `families` on a second row.
* **A REMOVE AND A CLEAR ARE NEVER REFUSED**, the same asymmetry the permission
  ordering rule and `appAllowedProtocol`'s closed vocabulary already have: a
  value can arrive by `ldapmodify` or be left behind when a family is untimed
  from the entry, and refusing to take it off would shut the one door that could
  tidy it up.
* **It is `appAllowedProtocol` that is read and not `appProtocol`** — declared
  and not derived. An application ticked for OAuth 2.0 that has never yet made a
  request is exactly the entry somebody is configuring when they reach for this,
  and testing what the service has SEEN would refuse every write until after the
  first token request.

**THE GROUP CLAIM'S FOUR ARE THE ONE SET THAT IS NOT A PROTOCOL'S**, and they
are the reason `appOf(context)` in `group_claims.js` looks at `client_id` OR
`audience`: those four reach an access token, an ID Token, a SAML 2.0 assertion
and a SAML 1.1 one from a single resolver, so one application entry has to be
findable from whichever of the four is being built. An application declared for
two protocols therefore gets the same claim name in both, which is what a claim
mapping should do.

**WHAT IS DELIBERATELY NOT OVERRIDABLE is worth reading before adding a
twenty-first.** Not `oauth2.issuer` or `oauth2.rfc9700` — those describe the
authorization SERVER, and a per-client issuer produces tokens that fail
discovery. Not any clock skew, in any protocol: `oauth2.clockSkewS`,
`oauth2.clientAssertionSkewS` and `saml.clockSkewS` are facts about the clocks in
the estate this service issues into, decided once, and a per-application answer
would be a question two applications could not meaningfully answer differently.
And not a socket, a port, a key or a limit anywhere.

**AN APPLICATION DECLARED FOR SAML GETS AN ENTITYID.** `createApplication()`
fills `samlEntityId` from the identifier when `saml2` or `saml11` is ticked and
no entityID was given — because that is what the same application would have got
by ARRIVING on its own, where the registry files a service provider under its
entityID. Without it the declaration was a note and nothing more: `samlEntityId`
is what both SAML modules file an application under and what their
per-service-provider metadata is published for. It is a default and not a rule —
an explicit value wins, and nothing is refused, because this service accepts any
entityID on sight everywhere else.

---

## An application entry now says WHERE ITS PEOPLE SIGN IN, and that is the first thing on one anybody reads

Every attribute on an application entry is one of two things, and the schema's
own comments have said so for a while: it RECORDS what happened (the counters,
the sightings, `appProtocol`, `appRedirectUriObserved`) or it DECLARES something
— and of the declarations, `appAllowedProtocol` and the four per-family
identifiers say in capitals that nothing in this service reads them.

**`appFederationRelationship` is read.** Each value holds the `fedId` of a
service-provider-side relationship in THIS realm, and `authn.js` consults it on
the way to the sign-in screen: with one named and `appFederationAutoRedirect`
left at its default, the browser is sent straight to that partner and the
screen is never drawn. With the auto-redirect off, the screen appears and those
partners are the ONLY ones offered on it.

**IT HOLDS A LIST SINCE 2026-08-26, AND IT USED TO HOLD ONE VALUE.** An
application with two identity providers is the ordinary case in a real
deployment — a workforce partner and a customer one, or one partner reached over
two protocols during a migration — and while this attribute was single-valued
the only way to say it was to configure nothing and let the person choose from
the WHOLE register. Naming several is the middle answer: the choice is still
made by a person, and the list they choose from is this application's own. The
values need not share a protocol, because what the list names is where somebody
can be authenticated and not how.

**With more than one usable, `authn.js` draws `/authn/select-idp`** — one button
per partner, no password field, and a banner per value that names something this
service cannot use. `appFederationAutoRedirect` still means "without the sign-in
screen" and never "without a page"; that page IS the screen's job done without
the screen, and FALSE still keeps the screen with the buttons under the password
box. `authn/CLAUDE.md` argues the chooser and why it is not the screen with its
form hidden.

**Its EDITABLE mode changed with its kind, from `set` to `multi`.** A caller
that used to write it with `POST /admin-api/applications/set` now uses
`/applications/add` and `/applications/remove` — which is the same rule every
other identifier attribute here follows, and for the same reason: a `set` would
replace the list with one value and read afterwards as the others having been
forgotten.

**What it answers is a question this registry could not answer before.** A
relationship under `ou=federations` says how to talk to a foreign identity
provider and says nothing about WHO should be sent there; an application entry
said what the application is and nothing about how its people sign in. So the
only home realm discovery available was a person choosing a button at the foot
of the screen, once per sign-in — which is not what a deployment with one
federated identity provider does, and it meant every federated flow in this
service began with a step no real user performs.

**FOUR CHECKS, AND ALL FOUR ARE MADE WHEN IT IS READ.** The relationship must
exist in this realm, be service-provider-side, be enabled, and be fully
configured. None of them is made at the write, and that is deliberate rather
than lax: the attribute is a string on a directory entry that `ldapmodify`
reaches, and the relationship it names can be disabled or deleted afterwards by
somebody who never looked at this application — so a check made at the write
would be a check about the past.

**A failure of any of them is SHOWN, on the sign-in screen, in the error banner
the password step already had.** The alternative is the one that had to be
avoided: falling silently back to the password box means a federated
application quietly authenticating people locally, which looks exactly like it
working.

**It grants and refuses nothing**, which keeps it consistent with everything
else here. Nothing stops a person reaching the screen by another route and
typing a name; clearing the attribute takes the shortcut away rather than
locking anybody out. What it changes is the DEFAULT ROUTE, and `federation/`
still owns every decision about what is then accepted.

**`appFederationAutoRedirect` defaults to TRUE once a relationship is named**,
which is the opposite of RFC 7591 section 2's rule that an omitted boolean is
FALSE. Both rules meet on one entry, so it is said out loud here and in the
schema row: naming a partner and then having to press a button is the state
nobody wants, and with no relationship named the attribute does nothing at all
rather than being an error.

### `appAuthnMechanism` — the THIRD of that group, and the generalisation of the other two

Added 2026-08-26. The pair above can say "send my people to a federated identity
provider" and can say nothing else, because until then there was nothing else to
say: every way of authenticating somebody here was either this service's own
screen or somebody else's service. **The SPNEGO sign-in is neither** — it is a
credential the browser already holds — so an application had no way of asking
for the commonest integrated-authentication deployment there is.

It is a single value from the SAME closed vocabulary `fedAuthnMechanism` uses:
`password`, `password-mfa`, `webauthn`, `spnego`, `federation`. **One table for
both**, because the two attributes answer the same question from two sides —
this one says where THIS APPLICATION's people sign in, that one says what to do
when THAT PARTNER asks — and two tables would have drifted the first time either
grew a value. **The list is deliberately NOT imported into `applications.js`**:
`federation.js` requires that file, so a require back would close a cycle. It is
checked where it is READ, in `authn.js`'s `declaredMechanismFor()`, which is
where `appFederationRelationship`'s four checks are made too and for the same
reason.

Three properties are load-bearing and each is the same rule the pair above
follows:

* **An empty value is not `password`** — it is "this entry says nothing". Every
  entry in the field holds an empty one, so reading it as an explicit "use the
  screen" would have switched off every `appFederationRelationship` in existence
  in one commit.
* **`federation` falls through to the list below it**, because that is what
  naming a relationship already implied, said out loud — so it changes nothing.
  Declaring it while naming nothing usable is REPORTED on the screen rather than
  falling quietly back to a password box.
* **A value this service cannot honour is REPORTED, not dropped** — a mechanism
  it does not have, or `spnego` while `krb5.spnegoAuthentication` is off. The
  second is why the setting is checked at the read rather than the write: it is
  settable at runtime, and without the check somebody meets a 403 halfway
  through a sign-in.

**It grants and refuses nothing either.** The Kerberos button is on the sign-in
screen for every application whether or not one declares this, so what the
attribute changes is the DEFAULT ROUTE and nothing about what is then
accepted — exactly what `appFederationRelationship` changes.

## WHERE THE ONE CRYPTO MODULE IS DESCRIBED TO A READER

`crypto.js` is the one place this service signs, verifies, encrypts and
decrypts (rule 3r above). Since 2026-08-30 there is a console page that REPORTS
it — `/admin/crypto-metadata`, built by `admin-ui/crypto_metadata.js` — and the
one thing worth knowing here is the direction: **that page reads this module's
tables and this module knows nothing about it.** `JWS_ALGS`, `JWE_ALGS`,
`JWE_ENCS`, `BLOCK_CIPHERS`, `KEY_TRANSPORTS` and the re-exported `xmldsig`
tables are already exported, so nothing here changed for it, and nothing here
should: `crypto.js` is a LEAF and a require back would end that.

The rule it puts on this file is small and worth stating, because it is the one
that will be broken by accident: **an algorithm this service performs must be in
a TABLE here rather than in a literal at a call site.** A `switch` in a
protocol module is invisible to that page, so the page would go on looking
complete while being wrong — which is the failure `sts_metadata.js` exists to
prevent for endpoints and this arrangement extends to algorithms.

## WHERE A SIGN-OUT GOES, AND THE CLIENT SECRET, ON THE NEW-APPLICATION FORM (2026-08-30)

`PROTOCOLS` gained two optional members beside `identifierAttribute` and
`redirectAttribute`, and `declarationAttributes()` walks both:

* **`logoutAttribute`** — `oauthPostLogoutRedirectUri` (OAuth 2.0, OpenID
  Connect), `samlSingleLogoutService` (SAML 2.0) and `wsfedSignOutUri`
  (WS-Federation, the one attribute this schema did not have). All three are
  `multi`, so the form draws a textarea and several addresses are one per line
  — which is what a service provider with an endpoint per binding actually has.
* **`secretAttribute`** — `oauthClientSecret`, on the two OAuth families. The
  attribute already existed; what it did not have was a door on the create
  form, so an application made by hand could not be given one.

**THE ABSENCES ARE THE INTERESTING HALF AND EACH IS A FACT ABOUT THE PROTOCOL.**
SAML 1.1 has no Single Logout at all — that arrived with 2.0 — so a field for it
would be a control whose value nothing could ever read. WS-Trust issues a token
and holds no session to end; Kerberos hands out a ticket this service cannot
recall; federation deliberately does not consume a partner's sign-out. The rule
is the one the identifiers already follow: a field is offered where an attribute
exists to hold it, and nowhere else.

**Adding them to the WALK rather than to the form is what made this one edit.**
The form, `GET /admin-api/applications/new` and `createApplication()`'s accepted
set all read `declarationAttributes()`, so a field that exists on one exists on
all three, and `DECLARATION_ATTRIBUTE_NAMES` picked the two new roles up for
free.

**`wsfedSignOutUri` IS DECLARED AND NOT YET READ, and the schema row says so.**
`cleanupTargetsFor()` builds its ping list from `session.wsfedRealms` — the
`wreply` each sign-in response actually went to — so what this service pings is
what it OBSERVED, and this attribute is what an operator DECLARED. They are two
different facts. Wiring it in as the fallback for a realm signed into with no
wreply is the obvious next step and is deliberately not taken: storing it is one
change, and changing where a cleanup goes is a change to what the protocol does.

## `consent.js`: what a person AGREED to, which is neither an act nor an intent

Rule 3t. It is the THIRD register in this directory that looks like the other
two and answers a different question, and saying which is which is most of what
this file has to do. `delegation.js` holds ACTS — one row per exchange, evidence
that something happened. `app_permissions.js` holds INTENT — what an operator
allowed between two applications, typed before anybody asked for anything.
**`consent.js` holds neither: it holds what somebody SAID YES TO**, and every row
in it has a person in it, which is what stops it being a fourth heading on
`/admin/delegation`.

**IT IS A LIBRARY (rule 3) AND IT HOLDS NO STORE.** It registers no route, so
its place in the require order is not a place. The store is the DIRECTORY in
both halves — `oauthConsent` on a person under `ou=users`, `oauthGlobalConsent`
on an application under `ou=applications` — for the reason `applications.js`
states about the registry: a Map here would be a second store that looked right
on its own and silently disagreed with an `ldapsearch`. It also means an
`ldapmodify` IS a configuration change here, exactly as it is for a redirect
URI.

It requires `helpers.js`, `config.js`, `applications.js` and `admin_stats.js`
(for `identityKeyOf()`, so that `alice`, `alice@EXAMPLE.COM` and her
`urn:uuid:<entryUUID>` — or the retired `urn:sts:user:alice` — are one person
here exactly as they are one entry in the directory), and nothing requires it back. **The directory arrives through
`setDirectory()`, which `ldap_server.js` fills at ITS require time** — the same
inversion `group_claims.js`, `applications.js`, `federation.js`,
`spiffe_registry.js`, `vc_claims.js` and `admin_rbac.js` all use, and for their
reason: that module is required at 21 precisely so its routes are registered
last.

### The unit is (person, application, scope) and it is ONE VALUE

Not a snapshot of the `scope` string, and not a list hanging off a pair. Both
were considered and both answer the wrong question. A SNAPSHOT makes
`openid profile` and `profile openid` two different agreements, and adding one
scope to a client's request throws away the agreement to the other four. A LIST
inside one attribute value is a value that grows, which a directory cannot add
to or remove from a member of — every change would be a read, a rewrite and a
race.

One value per triple makes every operation an `add` or a `remove` of exactly the
thing being talked about, and makes the question the authorization endpoint asks
— *which of these five scopes has this person not agreed to for this client* — a
set difference rather than a parse.

### Why the client_id is the LAST field of the value

    oauthConsent: 20260901143000Z openid webapp1

Three fields, space-separated, and the order is the only order this value can be
parsed in without a rule somebody can break. The TIMESTAMP is a GeneralizedTime
— digits and a `Z` — and cannot contain a space. The SCOPE cannot either, and
that is guaranteed by CONSTRUCTION rather than by a check: a scope value only
ever reaches this module by having been split out of a space-delimited `scope`
parameter (RFC 6749 section 3.3), so a value with a space in it is not one
scope. The CLIENT_ID is the one field with no rule at all —
`identifierProblem()` refuses only a line break, a NUL and 512 characters — so
it goes last and takes the remainder.

That is also why the delimiter is a SPACE rather than this repository's usual
`|`. The `|` convention works on `oauthPermission` (`name|description`) because
the unconstrained field is last there too; here the unconstrained field contains
`|` as happily as anything else.

**THE TIMESTAMP IS CHECKED AGAINST ITS OWN SHAPE AND NOT MERELY SPLIT OFF**, and
that check is what tells a value this service wrote from a sentence somebody
left on an entry. `this is not a consent` fits a space-counting grammar exactly
and would otherwise read as a consent to `is` for a client called
`not a consent` — a permission granted to nobody, invented by a parser out of
prose. Fourteen digits and a `Z` is what `generalizedTime()` emits; anything
else is reported as unreadable and consents nothing.

**A DELEGATED PERMISSION IS STORED WHOLE.** `https://example.com/write` is what
the client put in its `scope`, so it is what is recorded. Storing the resolved
permission NAME instead was refused for the reason the feature exists: two
resources may both expose `read`, the person agreed to one of them, and a
consent recorded as `read` would silently cover the other.

### The override is not a record, and that decides what removing it does

`oauthGlobalConsent` on the CLIENT APPLICATION's entry, one value per scope. A
scope named there is never asked about: everybody who signs in to that
application skips the prompt for it and **nothing is written about anybody**.

Two consequences follow and both are said on the console page, because they are
what somebody gets wrong:

* **Removing one asks EVERYBODY again**, including the people who would have
  said yes — there is no record of who they were. Removing a person's own
  `oauthConsent` asks one person.
* **It is keyed on (application, scope) and never on the scope alone.** A
  service-wide list of harmless scopes would be shorter to configure and would
  mean an application registered five minutes ago inheriting a decision made
  about a different one.

### Two more things

**THE RULE ABOUT WHAT A SCOPE MAY BE LIVES IN `applications.js`.** RFC 6749
section 3.3's `scope-token` is `scopeTokenProblem()` over there, beside
`permissionNameProblem()` which is that rule plus a refusal of `|`. That module
owns the SCHEMA, so it owns what a value of one of its attributes may be, and a
second copy of the grammar here would be the thing that eventually disagreed.
This file delegates in one line.

**A SERVICE WHOSE SLOT WAS NEVER FILLED PROMPTS EVERY TIME AND SAYS SO.** Not
"consents to everything": an agreement that cannot be remembered is one nobody
gave, and the honest behaviour is to ask again. `record()` answers
`{ ok: true, stored: false }` so that a directory which cannot hold the answer
never fails an authorization request — a mock that stopped issuing because it
could not file the paperwork would be a mock that stopped answering.

**IT IS PER REALM FOR FREE.** Both halves live in the directory, the directory
is a subtree per realm, and `applications.js`'s registry is that subtree's
`ou=applications`. So a consent agreed in `acme` is invisible in the default
realm without one line in this file mentioning a realm — which is the property
to check a new store against, answered here by having no store.

## `roles.js` and `issuance_gate.js`: the fourth register, and the leaf that asks about it

Rules 3u and 3v. They arrived together on 2026-09-05 and they are two files
rather than one for a reason worth stating before anything else: **one of them
holds the answer and the other one holds nothing at all.**

`roles.js` is the register — who HOLDS a role. `issuance_gate.js` is an empty
shell that nine issuance sites ask before this service issues anything, and
whose decider is filled by `xacml/xacml_role_pep.js` at 23c. A process that
never loaded the XACML family has no decider installed and every call answers
`allowed`, which is what keeps `npm test`, the parent project's in-process
Kerberos jobs and the remote PEP container a SMALLER service rather than a
broken one.

### It is the one register a USER, a GROUP and an APPLICATION are all in

`delegation.js` records what an application DID; `app_permissions.js` configures
what one MAY do; `consent.js` holds what a PERSON agreed to. This is the fourth,
and what makes it different is that all three kinds of directory object are
first-class members of one role.

**The third one is the unusual one and it is the point.** A `client_credentials`
grant has no person in it at all, so until an application could hold a role
there was nothing to decide about one — the subject of that decision is the
CLIENT, and a register that only knew about people could not have answered it.

### The two relations are kept apart, and collapsing them is the mistake

|  | Stored on | Edited at | Means |
|---|---|---|---|
| MEMBERSHIP | the ROLE entry, `ou=roles` | `/admin/roles` | who HOLDS the role |
| REQUIREMENT | the APPLICATION entry, `appRequiredRole` | the application's own page | what it DEMANDS before anything is issued |

An application appears in both and means opposite things in each: in the first
it holds the role, in the second it demands it. That is why `ou=roles` is only
half the feature and why `/admin/ldap/roles` says so at the top — a reader
looking in that container for the reason somebody was refused is one container
across from the answer.

### `EVERYBODY` is what makes this off by default without being absent

Six roles are BUILT IN, computed from the context of the decision, and in no
container: `EVERYBODY`, `ALL_AUTHENTICATED_USERS`,
`ALL_UNAUTHENTICATED_USERS`, `ALL_APPLICATIONS`,
`ALL_AUTHENTICATED_APPLICATIONS`, `ALL_UNAUTHENTICATED_APPLICATIONS`.

**THERE ARE EIGHT NOW, AND THE LAST TWO ARE A DIFFERENT SHAPE.** The six above
read `kind` and `authenticated` and touch no store. `REMOTE_PEPS` (2026-09-06)
and `XACML_USER` (beside it) are held by whoever is in one named GROUP —
`roles.remotePepGroup` and `roles.xacmlUserGroup` — which makes them hybrids,
and the hybrid is argued at each of them in `roles.js`. The short version is
that both guard a surface that has to be guarded in a realm nobody has
configured: **a configured role is absent until somebody makes it, `ou=roles`
is per realm, and a role seeded once in the default realm leaves every later
realm with a gate nobody chose the state of.** A built-in role is computed, so
it exists in the realm most deployments only ever have.

**THEY ARE TWO ROLES AND MUST NOT BECOME ONE.** `REMOTE_PEPS` reaches
`/xacml/pep/*` and `POST /xacml/pip` — the documents this service enforces its
own access with, and a named person's directory attributes. `XACML_USER`
reaches the four XACML endpoints proper. One group granting both would make
admitting a caller to the demonstration surface silently admit it to those,
which is the collapse the split exists to prevent.

**A PERSON IS GRANTED ONE BY GOING IN THE GROUP**, not by a role entry: the
role is computed, so `uid=alice` added to `cn=xacml-users` holds `XACML_USER`
on the very next request, because membership is resolved at DECISION TIME.
`ldap_server.js` seeds both groups and an identity in each — `cn=remote-pep-1`
and `cn=xacml-user-1` — because the party holding one is normally a certificate
DN that does not exist until a launcher mints it, and a gate whose grant
appears the moment somebody knocks is not a gate.

An application that names no required role requires `EVERYBODY`; everybody holds
`EVERYBODY`; the decision is Permit and the service behaves exactly as it did
before any of this existed. **That is a better default than "no roles configured
means do not ask"**, because the machinery is then always running and always
visible: the console shows the decision, the audit log records it, and turning
enforcement on for an application is NARROWING A LIST rather than switching on a
subsystem that has never run.

The consequence for a reader is the sentence `/admin/ldap/roles` and
`GET /admin-api/ldap/roles` both carry: **an empty `ou=roles` is the ordinary
state of a service refusing nobody**, not a sign that the feature failed to
load.

### `roles.js` is a LEAF and must stay one

It requires `helpers.js` and `config.js` and nothing else here, which is what
lets `admin_stats.js` require it in the ORDINARY DIRECTION for the roles claim
rather than being offered a fifth inverted hook. Rule 3e is explicit that a slot
is what you reach for when a require would close a cycle or move a route, and
that a fifth must not be added by analogy with the fourth: here a plain require
works, so a plain require is what is used. **Do not make this file require
`admin_stats.js`** — the moment it does, that argument is gone and a slot is the
only way back.

The DIRECTORY arrives through a slot pointing the other way, as
`group_claims.js`, `applications.js` and `xacml_store.js` do it: only
`ldap/ldap_server.js` can answer what is in `ou=roles`, and it is required at 21.

### An empty decider means ISSUE, and the fail-closed case is not in this file

`issuance_gate.js` is absent-safe on purpose, and the reason is about failure
rather than about tests: this service exists to be exercised, and an
authorization subsystem that could brick every protocol family by being
half-loaded would be the worst possible thing to put in front of a mock.

**Where enforcement must fail CLOSED it does so in the PEP**, which knows
whether anybody actually asked for a restriction — an application that names no
required role costs nothing when the policy is missing, and one whose entry
names `staff` is refused, because somebody deliberately asked for that. Both
halves are argued in `xacml/CLAUDE.md`. This file's job is to be absent-safe; it
is not the file that decides what a restriction means.

`ISSUANCE` is a VOCABULARY and not a list of call sites: its nine values become
the XACML `action-id` of the request, so adding one is adding a word a policy
author can match on, and RENAMING one silently stops every policy that named the
old word from matching — which is a policy that permits nothing rather than an
error. The nine are spread over eight `gate.check()` calls in seven modules,
because the two SAML profiles both issue `issue-saml-assertion` and `oauth2.js`
asks twice.

### The six built-in roles became reachable on 2026-09-05, and three of them were not before

`BUILT_IN` has held six rows since this file was written, and `holds()` on each
is a pure function of the context it is handed. That made three of them
unreachable in practice, because the contexts the nine issuance sites built
were partly CONSTANTS:

| Role | Before 2026-09-05 | Now |
|---|---|---|
| `EVERYBODY` | always held | unchanged — `holds()` is `return true` |
| `ALL_AUTHENTICATED_USERS` | always held by a person | held when the SESSION says somebody authenticated |
| `ALL_UNAUTHENTICATED_USERS` | **held by nobody, ever** | held by an unauthenticated session |
| `ALL_APPLICATIONS` | held under `client_credentials` | unchanged |
| `ALL_AUTHENTICATED_APPLICATIONS` | always held by a client | held when the client PROVED who it is on this request |
| `ALL_UNAUTHENTICATED_APPLICATIONS` | **held by nobody, ever** | held by a public client, and by a confidential one that presented nothing |

**The roles did not change. The facts underneath them did**, in three modules,
and it is worth knowing which because they are three different kinds of answer:

* **A USER's answer belongs to the SESSION**, and `authn.js` now puts
  `authenticated` on the session object rather than six call sites assuming it.
  See that directory's file for the unauthenticated session and the third
  button that starts one.
* **It has to TRAVEL to the token endpoint**, which is a back channel with no
  cookie on it — so the authorization code carries `session_authenticated`
  frozen at the moment it was minted, and `admin_stats.js`'s token registry
  carries the same thing for a REFRESH. Both are `!== false` at the read, so a
  record made before the field existed goes on meaning what it meant.
* **AN APPLICATION's answer belongs to the REQUEST**, because client
  authentication is something a client does every time it calls. It is
  `oauth2_bcp.observeClientAuthentication()`, deliberately not mode-gated —
  see `oauth-oidc/CLAUDE.md`.

**A computed role and a configured one exercise different halves of this
file**, and that is the lesson the bug in `authn.js`'s sign-in gate taught: a
suite that narrows applications only to CONFIGURED roles cannot see a wrong
answer in `holds()` at all, because `configuredRolesOf()` answers those the
same whatever the context says. `tests/vendored/sts_roles.js` is the configured
half and `tests/vendored/sts_roles_builtin.js` is the computed one, and neither
substitutes for the other.

**`EVERYBODY` HAS NO NEGATIVE CASE AND THAT IS A PROPERTY OF THE ROLE.** Its
`holds()` is `return true`, so an application requiring it can refuse nobody —
which is exactly what makes this feature off-by-default without being absent.
The test asserts that rather than leaving the missing negative to be noticed: it
checks the catalogue still describes `EVERYBODY` as the DEFAULT requirement, so
that anybody who gives it a `holds()` that can answer false fails there.

## `setId` IS THE THIRD THING THE TOKEN REGISTRY IS TOLD OUT OF BAND (2026-09-05)

`recordJwt()` keeps three facts that are on no token as a claim, and all three
arrive the same way — through `signJwt()`'s third parameter, from the call site
that built the thing:

| Field | What states it | Why it cannot be read off the payload |
|---|---|---|
| `sessionId` | the issuance site | no token carries a session identifier, and inventing one to make a console page easier would change what every client receives |
| `sessionAuthenticated` | the issuance site | the refresh grant has no session and no cookie, so what it can say about the person is what this registry remembers |
| `setId` | the issuance site | **two replies can agree on every other field in this record** |

That last row is the whole argument for the third one. **OAuth 2.0 and OIDC are
the only families this service speaks that hand back several credentials at
once**, and `/admin/tokens` lists what came back TOGETHER — so something has to
say which credentials those are. Two people redeeming two authorization codes at
the same client in the same millisecond produce six records agreeing on `sub`,
`username`, `client_id`, `scope`, `grant` and `issuedAt`: every field a heuristic
could read. A grouping derived from those would report a credential handover
that never happened, which is worse than the ungrouped list it replaced.

So the ISSUER states it. `oauth-oidc/CLAUDE.md` argues the two call sites; what
matters here is that **a caller that says nothing is stating that this credential
was issued alone**, which is true of the credential issuer, the OID4VP Request
Object and WS-Trust's JWT, and `issuedSets()` draws each as a set of one.

**It is in no token, no client ever sees it, and it is not a claim** — unlike
`sid`, which is a claim precisely because OpenID Connect Front-Channel Logout
section 3 requires the OP to send one. That is the bar a new claim has to clear
here, and this does not try to.

### `issuedSets()` beside `issuedList()`, and the three derived fields

The merged list stays what it was; the grouping is a second reading of it. Three
of the set's own fields are not what a reader first expects, and each is a
refusal to average:

* **`state`** is the state every member shares, or `mixed`. An access token
  expires in fifteen minutes and the refresh token beside it in a day, so most
  sets are neither valid nor expired within the hour — and choosing one would be
  this function deciding which member matters.
* **`expiresAtMs`** is the EARLIEST member's, when the set starts to come apart;
  `lastExpiresAtMs` is when it is finished. A member stating no expiry is skipped
  on both ends rather than counted as zero, which is the 1970 bug `expiresAtMs`
  already warns about, met from the other direction.
* **`setKey`** is what a page addresses a set BY, and it is not `setId`: a row
  with no set id needs a handle too, so it gets `one:` and this service's own key
  for that row.

**That last one is why `recordArtifact()` now stamps a `key`.** A Kerberos ticket
carries no identifier anybody can quote — the protocol gives it none and the KDC
keeps no handle on it — so without a row handle of this service's own there
would be nothing to address its row by at all. It is deliberately kept apart from
`identifier`: that is what somebody can quote back at this service and what
`credential_graph.js` looks a lineage up by; this is only ever a way of naming
one row of the issued register. `nums.artifactsRecorded` counts what has EVER
been recorded and is not `artifacts.length`, which falls back as the cap shifts.

### And one ordering fix that is easy to read past

`issuedList()` now stamps an ordinal before it sorts, and ties break on it.
Members of one reply are minted well inside one millisecond, so sorting on
`issuedAt` alone left them in whatever order the sort happened to be stable in —
and the set page would have printed the refresh token above the access token
issued before it. `tests/issued_sets.js` asserts the order explicitly for that
reason.

## `keystore.js` AND `secrets.js`: WHERE THE SIGNING KEYS LIVE, AND WHAT OPENS THEM (2026-09-06)

Two files, one for each half of a question this service did not previously have:
**what happens to a signing key when the process stops.**

Development mode's answer is still "it dies", and that is a feature rather than
a limitation — `makeStsKeys()`'s own comment explains that the `kid` is derived
from the key material precisely so two instances cannot publish one name over
two keys. Product mode's answer has to be "it does not", because a token issued
yesterday must verify today.

### The signing key is regenerated on every start — IN DEVELOPMENT MODE

**This moved here from the root `CLAUDE.md` when that file was broken up.**

**THIS SECTION WAS UNCONDITIONAL UNTIL 2026-09-06 AND THE HEADING IS THE ONLY
PART THAT CHANGED.** Everything below is still exactly what a development-mode
service does, and development is the default. What is new is that `product` mode
generates the keys ONCE and reads them back from the persistence store — which
is why product mode REQUIRES a store — encrypted with AES-256-GCM under a key
this service never generates and never stores, read from a mounted file (the
default), AWS Secrets Manager, GCP Secret Manager, Azure Key Vault or HashiCorp
Vault. `common/keystore.js` and `common/secrets.js` are the two halves and the
subsections below argue both; `persistence/CLAUDE.md` carries what it means
for the store.

**A service that cannot read its own signing key does not start.** It does not
generate a replacement and carry on: that would stop every token, assertion and
signed document it has ever issued from verifying, silently, at somebody else's
relying party.

Deliberate, and two things depend on it: the `kid` is derived from the key material
(`sts-<thumbprint>`) so two instances cannot claim the same kid over different
keys, and every document that carries or describes the key is served
`Cache-Control: no-store`. If you add a document that publishes the key, it needs
that header too.

**THAT SECOND RULE IS ENFORCED SINCE 2026-09-10 AND WAS BEING BROKEN WHEN IT
STARTED BEING.** `tests/vendored/sts_metadata_anonymous.js` asks it of every
metadata document at once — nineteen of them — and `/sts/cert` was the one
served without the header: a WS-Trust STS certificate this process mints at
startup and throws away at exit, cacheable by anything between here and a
client that would then be checking today's signatures against the certificate
of a service no longer running. That job is the enforcement for the sentence
above; add a document that publishes a key and it fails until the row is
there.

### `keystore.js` — the material

* **Loaded once, served synchronously, and that shape is forced.**
  `stsKeysFor` is a `realms.keyed()` factory reached through a PROXY — eight
  modules do `STS.privateKey` on a property read — so it cannot await anything,
  and reading a secret from AWS can only be asynchronous. The two are reconciled
  the way `persistence.js` already reconciles opening a connection pool:
  everything asynchronous happens in `start()`, before the listener binds, and
  what is left is a map lookup.
* **A realm created at RUNTIME is the case that does not fit**, and it is
  handled honestly: keys are generated on the spot and written asynchronously
  afterwards.
* **What is stored is PEM and a JWK, never a derived value.** `privateKey` is a
  parsed `KeyObject` rebuilt from `privateKeyPem`, and every `kid` is recomputed
  from the public material — storing a derived value is how a store comes to
  disagree with itself after a change to the derivation.
* **What is NOT stored, and each is a decision**: the eleven post-quantum keys
  per realm (generated on the worker pool because generating them is expensive,
  and cached by `pq_jose.js`), the TLS server certificate, and the SPIFFE JWT
  authority. All are named in `mode.js`'s `NOT_YET`. **The SPIFFE X.509
  authority came off that list on 2026-09-11** — it is `pki.js`'s SPIFFE Issuing
  CA now, so it is in the `pki:` row family and inherits that module's mode
  exactly as the rest of the hierarchy does. The JWT half has no certificate and
  no hierarchy to hang from and is still generated per start in either mode.
* **Rotation is destructive and says so.** There is no overlap — this service
  publishes one key per realm per algorithm — so everything signed with the old
  key stops verifying the moment the new one is in use. Overlapping keys in JWKS
  are the obvious next increment.

### WHAT IS RESIDENT IS THE CIPHERTEXT (2026-09-06)

The bullets above are about the key AT REST, and until this date they were the
whole story — which meant a store encrypted under a key from a cloud secret
manager sat behind a process that held every realm's private key in the clear
from `start()` until it exited. The encryption protected the disk and nothing
else.

Now `material` holds `{ cipher, createdAt, plain, parsed, timer }` per realm.
`storedFor()` decrypts on demand, `purgeFor()` drops the result, and
`keys.plaintextRetention` decides when:

| Word | What it does |
|---|---|
| `timed` (default) | drop it once it has gone `keys.plaintextTtlS` unused — an IDLE clock, restarted on every use, so a busy realm keeps its key and a quiet one lets it go |
| `per-use` | drop it at the end of the turn of the event loop that needed it |
| `resident` | keep it for the life of the process — what this service did before the setting existed |

**THREE WORDS AND NOT A FLAG**, for `oauth2.tokenExchangeRefreshToken`'s reason:
a boolean could only have reached two of the three, and the interesting bug is
usually on the side a boolean would have hidden.

Six things are load-bearing, and the first is the one that decides whether any
of the rest is worth having.

* **THE CLAIM IS ABOUT A WINDOW AND NOTHING ELSE, and every surface says so.**
  The key-encryption key is resident too — it has to be — so an attacker who can
  read this process's memory at a moment of their choosing waits for the next
  signature. What narrows is exposure to a SNAPSHOT: a core dump, a heap dump, a
  swapped page, a `/proc/<pid>/mem` read, a debugger attached for a moment. That
  is the realistic exposure for material that used to sit there for weeks, and
  it is the whole benefit. Anything stronger needs the key somewhere this
  process cannot read at all — an HSM, or a KMS that signs on your behalf —
  which is in `mode.js`'s `NOT_YET`.
* **A JAVASCRIPT STRING CANNOT BE WIPED.** The Buffer the decrypt produces IS
  zeroed; the strings `JSON.parse()` makes out of it and the copy OpenSSL keeps
  inside a `KeyObject` are RELEASED, because there is no other verb available
  from here. Saying so is the point: a feature like this is worth exactly
  nothing if somebody reads it as "the key is not in memory".
* **THE PARSED `KeyObject` PURGES WITH THE PLAINTEXT, and that is not
  pedantry.** `privateMaterialFor()` caches the parsed key on the same entry and
  `purgeFor()` clears both, so the parsed key can never outlive the string it
  came from. A KeyObject cache with a lifetime of its own would make the purge
  cosmetic — and `report()` counts a realm as held when EITHER field is set, so
  a purge that forgot one is reported rather than looking like success.
  `tests/key_residency.js` mutation-tests exactly that.
* **`helpers.js`'s KEY SET HOLDS THE PUBLIC HALF AND GETS THE PRIVATE HALF.**
  `lazyKeySet()` is the other half of the feature and without it the first half
  buys nothing: the kid, the certificate and every curve key's public JWK are
  ordinary properties, and `privateKeyPem`, `privateKey` and each
  `extraKeys[].privateKey` are GETTERS that ask the keystore afresh. So the JWKS
  endpoint walking every key on every fetch decrypts nothing, and the eight
  modules that do `STS.privateKey` are untouched — a property read of a getter
  is a property read, which is the second thing the `STS` proxy has paid for.
  **Nothing in that function may close over the plaintext blob it was built
  from**; each getter captures the realm id and, for a curve key, its `kid`.
* **THE UNIT OF `per-use` IS THE TURN OF THE EVENT LOOP AND NOT THE OPERATION.**
  This is reached through a property read, so when `storedFor()` returns, the
  caller has the key and has not signed with it yet; a synchronous purge would
  hand back a key and destroy it before use. It is a `setImmediate`, which for a
  synchronous signature is exactly the operation and for one that awaits the
  worker pool is the tick it was dispatched on. Stated rather than rounded off.
* **THE PURGE TIMER IS `unref()`d.** Without it a service holding a decrypted
  key keeps the event loop alive for the whole TTL after everything else has
  finished — so `npm test` hangs for five minutes at the end, and the cause is a
  key that was purged correctly.

**IT ONLY APPLIES WHERE KEYS PERSIST**, which is not squeamishness about
development mode: a service that generates its key in memory has no ciphertext
to fall back to, so there is nothing to purge TO. `/admin/keys` says that in as
many words rather than drawing an empty table, and the setting's own description
says it too.

**`/admin/keys` GAINED A REPORT AND DELIBERATELY NO CONTROL.** It names the
policy and the realms whose key is decrypted right now — a number a reader can
watch change, which is the only way to tell the feature is working rather than
configured. A *Purge now* button was refused: that page's one POST answers with
a FILE rather than a page, so a second action would be the one form in this
console whose two buttons answer in two different shapes, and it would shorten a
window the timer shortens anyway. **The same change fixed two sentences on that
page that had been false since the keystore landed** — `regeneratedEveryStart`
was the constant `true`, and the warning that makes handing a private key to a
browser defensible said these keys die with the process. Both are computed now.

### A SHARED BLOB NAMES THE KEY, NOT WHAT THE KEY CURRENTLY PUBLISHES (2026-09-11)

`serialise()` is what one process of this service offers another, and what
`remember()` writes to `sts_keys`. It read `keys.certPem` and `keys.certB64` —
which `helpers.js`'s `certifiedView()` makes GETTERS that switch from the
self-signed certificate a key set was BORN with to the one `pki.js` issued over
it. So the blob moved under a key that had not, and **two things that compare
blobs by certificate stopped working the moment a realm's keys were certified**:

* **`publishShared()`'s enrichment test**, which is how a realm's POST-QUANTUM
  keys reach the other processes at all. A key set is generated and published
  before anything certifies it, and its eleven post-quantum keys arrive a second
  or two LATER — `pqKeysForAsync()` — so the second publish is the same set with
  more in it. That is told from a losing race by comparing the certificate, and
  after certification the comparison was false for ever. Every offer was
  refused. Measured on 2026-09-11 in a dispatched service: **four processes
  generating the default realm's eleven post-quantum keys independently**, each
  publishing its own in `/oauth2/jwks` and signing with its own, so a UserInfo
  response or an ID Token signed by one worker could not be verified against the
  JWKS served by another — `No key in the set has kid "sts-ml-dsa-44-…"`.
* **the `kid` a RESTORED set derives.** `certifiedView()` names a key after the
  certificate it is handed as the self-signed one, so a blob carrying the issued
  certificate would have made the `kid` move across a restart — which is the one
  thing that block's own header says must never happen.

So the blob carries `selfSignedCertPem` / `selfSignedCertB64`, which is the
certificate the key was born with and never changes for the life of that key.
**Nothing about what a process PUBLISHES changed**: every key set builds its
certificate view from `pki.js` in the process that holds it, so a certified
realm still publishes the certified certificate everywhere. `tests/keystore.js`
section 5 pins it, and the shape to remember is that neither half failed — the
service was correct, slower, and wrong only at a client.

### AND THE STORE UNDID THE ARBITRATION, WHICH IS THE THIRD OF THESE AND THE QUIETEST (2026-09-12)

The channel above decides a race — several processes generating one realm's keys
at once — by **first-generator-wins**: the loser is sent the winner's blob,
`adoptShared()` drops its CACHED set, and `helpers.js` rebuilds. That was
complete for as long as there was nothing else to rebuild FROM.

**With `keys.source=persisted` there is, and the rebuild found the loser's own
row.** `helpers.js` looks a realm's keys up STORED → SIBLING → generate, in that
order and for the reason the block above it argues; a process that had already
written its losing set to `sts_keys` rebuilt from it, so **adopting became a
no-op that logged as a success.**

Measured on a dispatched stack the day `dispatch` mode started reading its
key-encryption key from the OpenBao container: a realm created at runtime had
**four key sets in four processes**, three of them generated within 43ms of each
other and each written down. `/oauth2/jwks` answered a different key per worker,
so an assertion encrypted to the key one worker published would not decrypt on
another — which is how it was found, as an "intermittent" OAEP failure in
`tests/vendored/sts_jwt_bearer_grant.js` that had been written down as a flake.

**PRODUCT MODE WITH REQUEST WORKERS HAD THIS ALL ALONG.** In development with no
keystore `storedFor()` answers null, so the channel worked and nothing anywhere
could see the hole. `adoptShared()` now holds the adopted blob as this process's
material and writes it down — so the row converges on the set everybody is
using rather than on whichever process wrote last — and `tests/keystore.js`
pins both halves.

### AND THE POST-QUANTUM HALF WAS WRITTEN AND NEVER READ BACK (2026-09-12)

`serialise()` has carried a realm's eleven post-quantum keys since 2026-09-07
and `deserialise()` has read them back the whole time. **Nothing put them on a
restored key set.** `helpers.js` has two paths into a key set and only one of
them copied them: `plainKeySet()` — a SIBLING's, over the pool's channel — did,
and `lazyKeySet()` — the STORE's — did not, because `privateMaterialFor()` had
nowhere to keep them.

So a process that restored a realm generated eleven more, offered them to its
siblings, was refused because another process had got there first, and went on
signing with its own. **Measured in a dispatched stack: three workers publishing
three different ML-DSA and SLH-DSA kids for one realm**, so a UserInfo response
signed by one could not be verified against the JWKS served by another —
`No key in the set has kid "sts-slh-dsa-shake-128s-…"`.

**AND THERE WAS A SECOND HALF, WHICH IS WHY THE FIRST ONE ALONE CHANGED
NOTHING.** The only writer of a realm's blob was `remember()` at GENERATION
time — which is before the post-quantum keys exist. The stored blob therefore
never had them to restore. `pqKeysForAsync()` writes them down now, beside the
publish it already did: one hands them to the processes running now, the other
to the next process to restore this realm.

Both are pinned in `tests/keystore.js` section 2, and the shape to remember is
the one this file records twice already: **a thing that is written and never
read back fails silently, and a cache invalidated without its backing row fails
the same way.**

### AND THE OPENID4VCI REQUEST-ENCRYPTION KEY IS A MEMBER OF THE SET (2026-09-12)

`vciRequestEncKey` — `{ privateKey, publicJwk }` — is made by `makeStsKeys()`
WITH the set, and it replaced a key of its own that `oid4vc/vc_issuer.js`
generated at module load, `request_pool.js` handed down the fork in
`STS_VCI_REQUEST_ENC_KEY_PEM`, and every realm in a pooled process shared.
`mode.js`'s `vci-request-encryption-key` NOT_YET row was that. **Every property
it lacked is one this set already had**, which is the whole argument for putting
it here rather than building a keystore row family and a pool channel of its own:
per realm, sealed in `sts_keys`, decrypted only while used, agreed by the key
channel. `pki.js`'s placement argument again — a second answer to *where does
this service keep a private key* is the one nobody remembers to rotate.

**IT IS A PLAIN KEY AND NOT A LEAF.** OID4VCI section 10 publishes a bare JWK
that a wallet trusts because it read it out of the issuer's own metadata over
TLS; nothing looks for a certificate on it, and every certificate `pki.js`
issues from a use case is a SIGNING certificate while this key only decrypts.
The kid is derived from the key, as the curve keys' are.

**THE TRAPS THIS FILE RECORDS WERE EACH MET ON PURPOSE, THE SAME DAY**:

* `serialise()` writes it (as PEM), `deserialise()` reads it back, and
  `privateMaterialFor()` parses it as `vci` on the purged record — the three
  places the post-quantum half needed and got one at a time.
* **both key-set paths put it back**: `plainKeySet()` copies it off a sibling's
  blob, `lazyKeySet()` keeps the PUBLIC JWK resident and the private half a
  getter, so publishing the issuer metadata decrypts nothing.
* **`makeStsKeys()` runs inside the realm the set is for** (`realms.run()` in
  the factory), because it reads `oid4vci.requestEncryptionKeyBits` and `.of()`
  from a watcher is not ambient in that realm.
* **A SET WRITTEN BEFORE THE KEY EXISTED IS BACKFILLED**, by
  `helpers.requestEncryptionKeyFor()`, in a fixed order: ASK first
  (`keystore.requestEncryptionKeyHeldFor()` — the store, then the shared blob —
  because a process may have adopted a sibling's backfill without its cached set
  being dropped, `adoptShared()` dropping one only when it REPLACES a shared
  blob), then make one in the set's realm, then `remember()` and
  `publishShared()` it as an ENRICHMENT. A backfilled key on a RESTORED set is
  held on the set until exit — one key, once, on the first start after an
  upgrade; the next start restores it from the row.
* **THE ENRICHMENT RULE IS ONE FUNCTION NOW**, `keystore.enriches()`, applied by
  `publishShared()` and by `request_pool.js`'s `receivePublishedKeys()`. It was
  written out in both with ONE member — the post-quantum count — and is now
  *the same certificate, at least everything held has, and strictly more of
  something*: a set gaining its request-encryption key offered against a held
  blob that already has post-quantum keys it lacks must not replace that blob.
* **NO WATCHER GENERATES IT.** It is made with the set, and `pki.js`'s realm
  watcher still asks rather than takes.

`tests/vci_request_encryption_key.js` pins every bullet, twenty mutants across
it and `tests/realm_isolation.js`, all caught; the enrichment mutant survived the
first round because the fixture asserted only one direction of the two-member
rule.

### AND THE RFC 9101 REQUEST OBJECT ENCRYPTION KEYS ARE THE FOURTH MEMBER (2026-09-13)

`requestObjectEncKeys` — `{ rsa, ec }`, each `{ privateKey, publicJwk }` — took
the OpenID4VCI key's path above member for member: made by `makeStsKeys()`
(`oauth2.requestObjectEncryptionKeyBits`, `oauth2.requestObjectEncryptionCurve`),
copied by `plainKeySet()`, a private-half getter in `lazyKeySet()` reading
`privateMaterialFor(realmId).ro`, serialised as PEM, counted by `enriches()`,
and BACKFILLED into a set written before it by `helpers.requestObjectKeysFor()`.
**The difference is that these ARE published** — in the realm's JWKS with
`use: "enc"` and a `sts-ro-` kid, after the signing keys — because a client
encrypting a request object has nowhere else to read them. Still plain keys and
not leaves, for the reason above. `oauth-oidc/CLAUDE.md` 3ak.

### AND SINCE 2026-09-10 IT HOLDS THE CERTIFICATE AUTHORITIES TOO

`common/pki.js` builds a Root, an Intermediate and an Issuing CA per realm.
Those are **private keys this service generated**, which is the exact
description of what this file already holds — so they go in the same table,
under the same key-encryption key, read back by the same `start()` and shared
across the request-worker pool by the same kind of channel.

**THE ROW KEY IS `pki:<realm>` AND THAT IS THE WHOLE OF THE SCHEMA CHANGE.**
`sts_keys` has one key column, and a hierarchy is per realm — so prefixing
distinguishes the two kinds of row without a migration and without a column
whose only value is a discriminator. `start()` routes them on the way in, and a
`pki:` row that reached `material` would be handed to `deserialise()` and come
back as a key set with no private key in it.

**IT IS A SECOND CHANNEL AND NOT MORE MEMBERS ON THE FIRST**, and the test is
rule 3e's read one layer down. The key channel arbitrates FIRST-GENERATOR-WINS,
because two processes racing to make a realm's signing keys is a race nobody
asked for. A hierarchy is built by an OPERATOR pressing a button, so there is
no race and the last write wins — putting it on the key channel would have meant
teaching that arbitration to tell an enrichment from a replacement for a second
kind of payload, and getting it wrong there would have broken signing.
`request_pool.js`'s `receivePublishedPki()` says the same thing from the other
end, and forwards a `null` for a REMOVAL — a worker still holding a CA the
operator threw away would go on issuing from it.

**WHAT IS RESIDENT IS THE PLAINTEXT, WHICH IS A WEAKER CLAIM THAN THE SIGNING
KEYS GET AND IS SAID RATHER THAN GLOSSED.** Every read of a CA key is an
OPERATOR ACTION — build a hierarchy, issue a key pair, draw the page — and a
page that had to decrypt to print a serial number would decrypt on every render.
Narrowing this window the same way is the obvious next increment and is named in
`mode.js`'s `NOT_YET` rather than left to be discovered.

### BETWEEN NODES THE STORE IS THE ARBITER (2026-09-14, #46 section 1)

Everything above agrees the processes of ONE container: first generator wins for
a key set over the request pool's IPC, last write wins for a hierarchy, and the
store a mirror each process wrote whole. Between containers the only link is the
store, and that was the issue's worst section — two nodes cold-starting against
an empty store each generated keys and the later UPSERT won the row while the
earlier went on signing; `applyKeysChange()` did nothing, so a rotation, a realm
created on A and used on B, and a rebuilt Root each reached one node; and a
scope's whole certificate authority was one row any node's next save threw
another node's revocations out of. **One rule now: a write asks the store what
is there, under the row's lock, and every node ends up holding what the store
holds.**

* **THE WRITE.** `persistence_postgres.js`'s `mergeKeys(realm, cipher, merge)`
  locks the row (`SELECT … FOR UPDATE`, or an `INSERT … ON CONFLICT DO NOTHING`
  and round again where there is none) and calls `merge(currentCipher)`, which
  is this file's because only it holds the KEK. Writes are QUEUED per row, one
  running and one waiting that takes the latest attach (a branch build saves a
  dozen times), and `pendingWrites()`/`settleAll()` feed the cluster barrier's
  commit-before-respond through `persistence.pendingWrites()` and `flushMinted()`.
* **A KEY SET IS FIRST WRITER WINS** (`decideKeys()`): another set in the row is
  kept and this process ADOPTS it — material, shared blob and the cached set
  (`adoptStoredKeys()`), published over the pool marked `confirmed` so
  `request_pool.js`'s `receivePublishedKeys()` adopts it instead of arbitrating
  it away. The same set is JOINED: a member one side lacks (post-quantum keys,
  the three encryption key pairs) is taken from the other.
* **A CERTIFICATE AUTHORITY ROW IS A THREE-WAY MERGE** against `pkiBase`, the
  ciphertext this process last read or wrote — equal ciphertexts are the fast
  path, since every seal has a fresh IV. `pki_merge.js` has the rules: a
  revocation and an issued serial are UNIONS (only a released `certificateHold`
  leaves), the register's CRL number adds both bumps, a CA tier or a certificate
  slot is FIRST WRITER WINS and reported in `lost`, a displaced slot record's
  serial is kept in `issuedKeyPairs`. A merged row is held, published, and handed
  to the store hook `hierarchyAdopted`, which reconciles the listener.
* **A ROW ANOTHER NODE WROTE IS ADOPTED** — `applyStoredChange()`, called by
  `persistence.js`'s `keys` applier for every change row: it reads the CURRENT
  row, defers to a write of its own in flight, drops a set whose row is gone
  (rotation, removal — `deleteKeys()` logs a change row since this), and adopts a
  different set or a richer one. `rotate()` now drops the cached set as well.
* **A COLD START SETTLES BEFORE ANYTHING IS SERVED** — `service_state.js`'s
  `settleSigningKeys()`, after coordination and before `pki.start()`: every realm
  in active-active mode, the default realm otherwise.

**WHAT ADOPTING STRANDS, AND WHY IT IS RIGHT.** `applyKeysChange()` refused to
adopt because it would strand what the process had signed. But the set a node
adopts away from is, by construction, one the store REJECTED while every other
node signs with the winner — refusing strands those tokens for ever rather than
for a window. The window is the first write's round trip; a cold start closes it
by settling, and a realm created at runtime keeps the one it always had inside a
container. There are no retained keys to fall back on (one key per realm per
algorithm — `rotate()`, and `mode.js`'s `NOT_YET`).

**`arbitrates()` GATES ALL OF IT**: keys persisted, a store with `mergeKeys`
and `loadKey` (postgres), a KEK, and `cluster.mode` not `off`. `ldif`,
development and a cluster switched off keep the upsert and the do-nothing
applier exactly as they were — measured: two nodes with `cluster.mode=off`
started together against one empty store still publish two JWKS (and two Roots
when their starts overlap), where `active-active` publishes one of each.
`tests/cluster_key_pki_agreement.js` holds every rule to a stub store and two
fresh module instances.

### A REALM'S KEY SET, MADE OFF THE EVENT LOOP (2026-09-14, #46 follow-up)

`stsKeysFor` is a factory behind a property read, so a realm this process holds
no keys for was generated INSIDE the first read — four 2048-bit RSA generations
and a certificate, ~470ms of a stopped process (measured in process), ~1.2s on
a loaded product node. One realm at a time that is a slow request; a list is
not one at a time. `GET /admin-api/realms` and `/admin/realms` show every
realm's `kid`, a realm created on another node is one this node holds nothing
for, and thirteen realms listed in process stopped the loop for 7.7s. In a
cluster that is past `cluster.nodeTtlMs`: twenty realms created on node A and
listed on node B killed BOTH nodes (`STS-CLUSTER-0011`), and so did twenty
concurrent first requests to those realms on B (`cluster/CLAUDE.md`, *A node's
thread and its lifetime*, has the numbers either side of the fix).
`service_state.js`'s cold-start settle had the same loop over every realm.

* **`helpers.prepareKeySet(realmId)`** generates the four RSA pairs with
  `crypto.generateKeyPair` — libuv's threads, never this one — and hands them
  to the factory through `prepared`; `makeStsKeys(made)` assembles the set
  either way, so there is ONE assembly and the two doors cannot disagree about
  its shape (`crypto.selfSignedRsaCertificate()` takes `rsaPrivateKeyPem`).
  The six curve keys, the secret and the certificate signature stay on the
  thread: tens of milliseconds. **The factory's order is untouched** — stored,
  a sibling's, then generated — and a prepared set the factory does not use is
  dropped. It never rejects: a failure is `STS-CORE-0092` and the read
  generates on the thread as before.
* **`prepareKeySets(ids)`** runs them one after another with a `setImmediate`
  between realms: one realm's four generations fill the default thread pool,
  which DNS, the file system and scrypt share.
* **Callers**: the middleware in `app.js` below the cluster barrier (the
  request's realm — after the first request a map lookup), the realm list and
  drill-down on both admin surfaces, and `settleSigningKeys()`. A read reached
  another way — an LDAP bind, a KDC exchange, a background sweep — still
  generates on the thread, one realm.
* **Not `worker_pool.js`**: RSA and EC generation is node's own OpenSSL with an
  asynchronous door of its own, which costs no IPC and no child. 3aa's reason
  for keeping `pki_authoring.js` off the pool is about the post-quantum
  encoders and is untouched — and that pane's SLH-DSA signature (13.7s
  measured) is what `cluster.nodeTtlMs`'s new default is sized against.

### `secrets.js` — the key-encryption key

Five providers behind one `read()`. **`file` is the default because it needs
nothing**: Kubernetes mounts a Secret as a file, Docker mounts a secret as a
file, and every other provider here is that same idea with somebody else's
access control in front of it.

**The four cloud adapters lazily `require()` their official SDK, and that is a
dependency decision.** This service is a mock first — the debugger suite installs
it, CI installs it — and four cloud SDKs to use none of them would be carried by
every one of those installs. So they are **optional PEER dependencies**, not
`optionalDependencies`: that field means "install it, but do not fail if you
cannot", npm installs them by default, and `.npmrc`'s `omit=dev` does not touch
them — so it would have carried all five while the comment claimed otherwise. A
peer marked `optional: true` is not installed automatically, which is what the
prose actually describes.

**They are not hand-rolled over REST**, which was the first instinct and the
wrong one: signing an AWS request is SigV4, and the failure mode of getting it
subtly wrong is a service that cannot read its own signing key on a Tuesday. The
SDKs also carry the credential chains — instance roles, workload identity,
managed identity — which is most of what makes a secret manager usable.

**A missing SDK is reported as the package to install**, never as
`Cannot find module`, which names a file nobody chose.

### TWO SECRETS SINCE 2026-09-12, AND THE HEADING ABOVE IS NOW HALF TRUE

The KEK was the only thing this file read for six days. The second is **the
database password**, and it arrived for the reason the first did: it was sitting
in a configuration string in plain text.

**A SECRET IS A DESCRIPTOR NOW AND THE PROVIDERS TAKE ONE.** `read(spec)` rather
than `read()`, where the spec names which settings hold the provider and the
location, what the secret is called in a sentence, and which FIELD to take if
the value turns out to be JSON. `readKek()` is `read(KEK)` and every deployment
reading raw bytes out of a mounted file sees exactly what it saw before — that
is the compatibility guarantee, and it rests on the KEK's descriptor naming no
default field, so its value is taken whole.

**THE TWO CAN LIVE IN ONE PLACE, WHICH IS THE POINT.** The database password's
location DEFAULTS TO THE KEK's, because a deployment already mounts one file or
already keeps one cloud secret and being made to provision a second is work this
service would have invented. `pick()` is what tells them apart inside it: a
named field taken out of a JSON object, the whole value otherwise.

**AND THE ONE REFUSAL THAT MATTERS IS ABOUT A *SHARED* LOCATION.** A secret of
its own that is not JSON is the whole password — that is what somebody who put a
password in a secret meant. A SHARED one that is not JSON is the
key-encryption key, and returning it would hand this service's master key to a
database server as a password, in the clear, on the wire, with a failed
connection as the only symptom. So `borrowed` is passed down to `pick()` and
that case throws. `tests/database_password.js` breaks if it stops.

**WHAT IS SHARED IS THE STORE AND WHAT IS NOT IS THE SECRET — BY DEFAULT.**
`keys.kekVault`, `keys.kekRegion` and `keys.kekToken` say how to REACH Vault,
AWS or Key Vault and a deployment usually has one of those, so the database
password reads them too. The provider and the location are per secret, because
those are what ordinarily differ.

**SINCE 2026-09-12 THE DATABASE PASSWORD MAY OVERRIDE ALL THREE** —
`persistence.databasePasswordVault`, `…Region` and `…Token`, EMPTY by default
and empty meaning the key's. The paragraph above was right about the deployment
it describes and silent about the one whose database credential is owned by
somebody else, in a different Vault, region or Key Vault, which could not be
configured at all. They are overrides rather than rows of their own so the
shared store stays the answer nobody has to type. `reachOf()` is the one place
the decision is made, the read path and the `/admin/secrets` probes both ask it,
and a Vault store's identity in that report is the endpoint AND whether a token
is used — two secrets reached two ways are two logins. The client-certificate
settings (`keys.vaultClient*`) stay shared: they are this service's identity,
not the store's. **The `cert` auth mount is `keys.vaultCertAuthMount` since the
same day** (it was the literal `auth/cert/login`), and a value that is not a
plain path is refused rather than put into a request line.
`tests/database_password.js` sections K and L pin both.

**THE INJECTION IS `persistence.js`'s AND NOT THIS FILE'S.** This module answers
*what is the password*; putting it into a connection string is a fact about
`pg`, and that file argues it — including why it is injected into the string
rather than passed beside it, which is not a preference.

### AND IT AUTHENTICATES WITH A CERTIFICATE NOW, NOT ONLY A TOKEN (2026-09-12)

`keys.vaultClientCert` / `keys.vaultClientKey` / `keys.vaultCaCert` are about
the CONNECTION rather than about either secret, which is why they are
`keys.vault*` and not `keys.kek*`: one deployment has one secret store, and both
secrets reach it the same way. With a certificate configured the provider logs
in through `auth/cert` and the token in the configuration is not used.

**A TOKEN IN A FILE IS A BEARER CREDENTIAL** — whoever reads the file is the
identity, it does not expire, and rotating it is an outage. A certificate the
STORE issued is an identity the store can revoke, bound to a policy the store
holds. `openbao/` is the stack that demonstrates it: the store builds a
certificate authority of its own, issues this service a certificate from it, and
binds that certificate to a policy that can read two paths and write nothing.

**THE TLS MATERIAL IS PASSED TWICE AND IT HAS TO BE.** `node-vault` merges
`requestOptions` into the calls its own helpers make and `rpDefaults` into the
request library's defaults, and `client.request()` — the escape hatch below —
uses only the second. Passing one of them gives a login that works and a read
that does not, or the reverse.

**AND THE LOGIN GOES THROUGH `client.request()` RATHER THAN `certLogin()`,
WHICH IS A BUG IN THE SDK.** node-vault 0.10.2 declares `certLogin` with
`schema.req = { type: 'object' }` and no `properties`, and its
`extendOptions()` does `Object.keys(reqSchema.properties)` the moment any
argument is passed — so `certLogin({ name })` throws *Cannot convert undefined
or null to object* before a request is made, and `certLogin()` with no argument
cannot name a role. Going through `request()` sends the role and keeps the SDK's
TLS handling.

### The encryption, in `crypto.js`

AES-256-GCM and **not** CBC, and the difference is the one that matters: GCM is
authenticated, so a ciphertext somebody altered fails to decrypt instead of
yielding a subtly different key. A signing key that decrypted to the wrong bytes
would produce signatures nothing can verify, and the failure would surface at a
relying party as "the signature is invalid" — as far from the cause as it is
possible to get.

**A per-record subkey, derived with HKDF.** The KEK never encrypts anything
directly: each record uses HKDF-SHA256(KEK, random salt, purpose), so the same
KEK protects the whole store without any record's IV mattering to any other —
and a single key encrypting many records under many IVs is one IV-reuse bug away
from catastrophic in GCM.

**A KEK shorter than 32 bytes is refused rather than stretched.** Stretching
would let a four-character password protect every signing key this service holds
while the log said AES-256, which is the kind of comfortable lie this repository
refuses everywhere else. Hex is tried before base64, because a 64-character hex
string is also valid base64 and reading it that way produces 48 different bytes.

### ONE KEK FOR THE SERVICE, NOT ONE PER REALM — AND THE HKDF ABOVE IS NOT THAT (2026-09-12)

Asked directly, and written down here because the per-record subkey paragraph
above reads like an answer to it and is not.

**There is a single key-encryption key per PROCESS.** `keystore.js` holds one
module-level `kek`, filled by the only call to `secrets.readKek()` there is;
that function takes no realm and reads one value from one provider. `seal()` and
`open()` take `(plaintext, label)` and **no realm** — the `label` is accounting
for `/admin/encryption`'s per-kind counters and reaches no key derivation, which
that function's own header says in as many words. Every call site agrees:
`'totp-secret'`, `'application-private-key'`, `'person-private-key'`,
`'minted-rows'`. Labels, never realms.

**The HKDF `info` IS A CONSTANT** (`'sts key material v1'`), so the
separation the paragraph above buys is **per record and not per tenant**: every
sealed value has its own key and IV, and one master key opens all of them in
every realm.

**THE DISTINCTION TO KEEP STRAIGHT IS WHICH KEY IS THE SUBJECT.** Realm
separation in this service is about *which keys exist* — signing keys per realm
in `material`, a certificate-authority branch per realm since the Root was
shared — not about *which key encrypts them*. A reader who knows the first can
reasonably assume the second, and it is not true.

Three consequences, and the third is already visible in the code:

* whoever can read the KEK can open **every realm's** sealed data, so a realm is
  not a cryptographic boundary at rest;
* rotating the KEK rotates every realm at once;
* **and that is why `open()` swallows a failure rather than throwing.** A value
  written under a previous KEK is the ordinary outcome of a rotation, so the
  restore counts them and drops them — the alternative is a service that will
  not start because of a session from last week.

`docs/encryption-at-rest.md` is the operator-facing half, and
`docs/trust-realms.md`'s *what a realm does not separate* names it beside the
three socket families.

#### Making it per realm, if it is ever asked for — NEITHER IS IMPLEMENTED

Written down so the costs are not re-derived. **Nothing below describes code
that exists.**

* **A per-realm subkey from the one master key.** Put the realm id into the
  HKDF `info` beside the constant, thread the realm through `seal()` / `open()`,
  and bump the envelope version (`$aesgcm$2$…`) so records written before the
  change still open under v1. Cryptographic separation per realm from one
  secret, no new provisioning, no extra secret-store round trips — and it is
  SEPARATION rather than INDEPENDENCE: an operator holding the master key still
  opens everything.
* **A key-encryption key per realm, from the secret store.** Genuine
  independence and a much larger change. `secrets.js` grows a keyed read;
  `keystore.start()` can no longer read one value before the realm registry
  exists, which inverts the ordering `start()` is built on; every call site
  needs an ambient realm, **and `persistence_minted.js`'s flush does not have
  one** — it runs on a timer rather than inside a request, which is the same
  shape of problem the request pool's barrier hit from the other direction.
  Creating a realm would also become a key-provisioning act, where today it is
  one API call.


### `storeReport()`: THE SAME MODULE ANSWERING A MONITORING QUESTION (2026-09-12)

`describe()` says where a secret is configured to come from. **`storeReport()`
says whether it actually got there, and what the thing at the other end is
doing** — it is what `/admin/secrets` and `GET /admin-api/secrets` draw, and
`admin-ui/CLAUDE.md` argues the page. Three things about it belong here, beside
the module:

* **THE PROBES LIVE IN A TABLE AND NOT ON THE FIVE PROVIDER OBJECTS**
  (`PROBES`, keyed by provider id), and that is a separation rather than
  tidiness. A provider's `read()` is on the path this service STARTS on — it
  runs before the listener binds, and in product mode a throw there is a
  service that does not come up. A probe is on the path a console page is drawn
  on. Two places is what makes it impossible for somebody adding a probe to
  break a read, and every probe is new code against somebody else's SDK, which
  is exactly the code that breaks.
* **THE READ LEDGER IS THE FACT NOTHING ELSE HERE COULD CARRY.** `read()`
  records every read, success and failure, with the instant and the error and
  never the value. A development-mode service on a memory store never asks for
  the key-encryption key at all, so a perfectly broken provider and a working
  one are indistinguishable from any settings page — and the row an operator
  most needs is the one a service that did not start cannot show anybody.
* **`scrub()` IS THE SAME CLAIM ASSERTED TWICE AND IT HAS FIRED IN ANGER.**
  Every probe picks its fields by name, so in a correct build the deny-list
  deletes nothing; what it catches is a future probe that hands back a
  provider's answer whole, and that mistake is silent, one-way and fatal —
  `auth/token/lookup-self` answers the live token in a member called `id`. It
  is also why a probe must name its OWN members: the `mounts` probe returned
  `{}` against a store with four engines mounted, because it had called them
  `secret` and `auth` and both are on the list.

**`vaultConnect()` WAS EXTRACTED FROM `vaultProvider.read()` THAT DAY AND IS
NOW SHARED BY BOTH.** A second login for the probes would have been a second
answer to *how this service proves who it is to the store*, and a page
reporting the policies of a token obtained differently from the one the read
uses is a page that is right about something nobody is running. The session
object the probes thread through it is what makes a render cost ONE login
rather than eight.


## 3w. `pki.js`: a certificate authority, and the three decisions in it

Added 2026-09-10, for RFC 7521 and RFC 7523: an application can authenticate, or
present an authorization grant, with a signed assertion instead of a shared
secret — and **a signing key nobody vouched for is a key an operator has to move
by hand.** So this builds a hierarchy and issues from it.

**IT IS A LEAF (rule 3).** It registers no route, so its position in the require
order is not a position. It requires `config`, `crypto`, `keystore`, `realms`
and `vendored/x509.js` / `vendored/key_material.js` — none of which requires it
back — and it is read by `oauth-oidc/assertion_grant.js`,
`admin-ui/pki_admin.js`, `admin-ui/crypto_metadata.js` and `mgmt-api`. **It
makes a logger of its own rather than requiring `helpers.js`**, for
`keystore.js`'s reason one file along: it sits on the token endpoint's path
through `assertion_grant.js`, and putting the whole key-set proxy behind a
module about certificates would be a require nothing needs.

### THE MECHANISM IS THE VENDORED MODULE'S AND THE POLICY IS HERE

That is `crypto.js`'s own split, made a second time and for the same reason.
`common/vendored/x509.js` is the parent project's PKI code, byte-identical —
already held to roughly 240 certificates against OpenSSL over there, already
what `spiffe/spiffe_ca.js` mints every X509-SVID with. What this file adds is
what is true of THIS service: which three tiers, which realm they belong to,
where the private keys live, that a leaf is a SIGNING certificate, and what a
path check must refuse.

The three tiers are that module's own `root-ca`, `intermediate-ca` and
`issuing-ca` **PROFILES** rather than a table here, so a change to what an
Intermediate CA IS reaches this service and that project's page together.
`tests/pki.js` asserts the lifetimes against `x509.profile()` for exactly that
reason.

### THE SHAPE CHANGED ON 2026-09-11, AND ONE SENTENCE IN THIS FILE REVERSED

**It is one Root for the SERVICE now**, an Intermediate per trust realm and one
for the process, and an Issuing CA under each for every use case: `jose`,
`xml`, `assertions`, `spiffe`, and (since 2026-09-13) `pep-tls`, `acme`, `est`,
`scep` and `tls-client` under a realm, `tls` under the process. (This sentence put `spiffe` under the
process for two days after the paragraph below moved it.) **Every key pair this
service generates is a leaf of it**, so an
operator installs one anchor and it covers 8443, 9443, LDAPS 636, the main port
and every token, assertion and signed document this service issues.

**WHAT REVERSED IS THE SENTENCE BELOW, and what replaced it is not a weaker
claim.** *IT IS PER REALM* used to be argued here as: a CA shared across realms
would be one authority vouching for several identity services, which is the one
thing a realm boundary exists to prevent.

That argument was about the ANCHOR. **The boundary is the INTERMEDIATE now** —
per realm, unique by construction — and `verifyLeaf()` requires the path to pass
through this scope's own. This is the single most important consequence of the
change and the one a reader is most likely to get wrong: with one Root, *does
this chain to our Root* is true of every certificate this service has ever
issued, in any realm, so **an anchor test that was a boundary became an anchor
test that is not one.** A check written on the old rule would admit every
realm's clients to every other realm's token endpoint, with every signature
verifying and nothing to see.

**THE STORAGE HALF IS THE PLACEMENT ARGUMENT AGAIN.** The Root lives in a row
of its own (`pki:*service`) and `rawChainFor()` composes it back on top of each
branch, so there is ONE copy of that private key rather than one per realm —
which is the same reason this module keeps no store of its own.

**AND THE THREE-TIER VIEW IS UNCHANGED FOR EVERY CALLER THAT HAD ONE.**
`describe()`, `chainPemFor()`, `trustAnchorsFor()` and `issueSigningKeyPair()`
still see Root, Intermediate, Issuing — the third being the `assertions` use
case, which IS the old `issuing` tier under a name that says which of the five
it is. Nothing those callers did before this change stopped working.

~~**WHAT IS DELIBERATELY NOT A LEAF**, said here because an absence is what
nothing reports: the eleven post-quantum keys per realm, which come from
`common/pq_jose.js`, whose independence from the vendored encoder is the point
of it — see `common/vendored/CLAUDE.md`. It is stated on `/admin/pki` rather
than left to be discovered.~~

**THE POST-QUANTUM KEYS ARE LEAVES TOO, SINCE 2026-09-13, AND THE INDEPENDENCE
WAS KEPT RATHER THAN SPENT.** `certifyPqKeys()` issues each of a realm's eleven
from that realm's JOSE Issuing CA — reached from `pqKeysForAsync()` and
`pqKeysFor()` when they are made (by the process whose set the realm keeps,
`remember()`'s rule), from a store restore, and from `certifyKeySet()` — and the
ML-DSA listener certificate from the TLS Issuing CA. Four things decide whether
it is still the arrangement `common/vendored/CLAUDE.md` asks for:

* **ONLY THE PUBLIC KEY CROSSES.** `helpers.js` hands `certifyPqLater()` the
  `alg` and `publicJwk` of each and nothing else; generation, the private bytes
  and every signature stay in `pq_jose.js` and the worker pool that runs it.
* **THE ONE LAYOUT DIFFERENCE IS A TABLE AND A FUNCTION.** `PQ_JOSE_IN_X509`
  maps each JOSE `alg` to the vendored registry's id, and
  `pqSubjectPublicKeyPem()` adds the `0x04` an ECDSA composite half carries in
  X.509 and not in JOSE — refusing, by name, a half that is not the JOSE length
  rather than guessing.
* **THE CROSSING IS CHECKED BY BOTH READINGS.** `tests/pq_key_certification.js`
  verifies a `pq_jose.js` signature under `pqc_x509.js` against the key read
  back out of each certificate, and shows the untranslated bytes do not verify.
* **THE REALM BOUNDARY NEEDED NOTHING NEW.** Each lands in its realm's row,
  under its realm's Intermediate, and `verifyLeaf()` refuses it elsewhere for
  the reason it refuses every leaf.

**The register now keeps each certificate's subject key**
(`subjectPublicKeyPem`, `subjectKeyFingerprint`). The fingerprint is how
`certifyPqKeys()` is idempotent — a key already certified by the current Issuing
CA is left alone, a DIFFERENT key in the slot is reissued and the old
certificate superseded — and the PEM is how `recertifyUseCase()` renews a
composite, whose key node's OpenSSL cannot parse out of the old certificate.

What stays outside is outside by its nature: the SPIFFE JWT authority, which has
no certificate, and the OpenID4VCI request-encryption key above.

**THE SPIFFE X.509 AUTHORITY WAS THE SECOND ENTRY ON THAT LIST AND CAME OFF IT
ON 2026-09-11.** The sentence was *self-signed on purpose, and an Issuing CA
carries `pathLen: 0` so it could not sign one anyway*, and both halves were
answered rather than waived. The trust-decision half: the SPIFFE authority is a
SIBLING of the TLS one — its own Issuing CA, its own key, under its own realm's
Intermediate — and the only thing they share is the anchor an operator installs,
so narrowing trust to SPIFFE alone is still sayable by pinning that Issuing CA.
The `pathLen` half was a real obstacle and was moved: the `spiffe` use case
carries `pathLen: 1`, because `NewDownstreamX509CA` on the SPIRE Server API asks
that authority for a CA and not a leaf.

**AND THAT IS WHY AN INTERMEDIATE'S `pathLen` IS COMPUTED RATHER THAN TAKEN
FROM THE PROFILE.** `intermediatePathLen(kind)` is one deeper than the deepest
Issuing CA a scope carries, so a realm's is 2 and the process branch's is still
1. The fix HAS to be made in two places or it is made in none — widening the
Issuing CA alone leaves the Intermediate refusing the extra level, widening the
Intermediate alone leaves the Issuing CA refusing it — and a chain that violates
either encodes cleanly and is refused at the far end of somebody else's path
builder with a message naming neither certificate. Deriving the second from the
first is what stops the two drifting; writing the 2 in by hand would also have
widened every Intermediate in the service for one use case in one of them.

**A USE CASE MAY ALSO PREFER A KEY ALGORITHM, AND EXACTLY ONE DOES.** `spiffe`
asks for EC P-256, which is what SPIRE issues and what the X509-SVID
specification recommends — the fidelity `spiffe/spiffe_ca.js` justifies vendoring
a certificate encoder for. It is a PREFERENCE: `algorithmsForUseCase()` honours
it only when neither the build call nor `pki.keyAlgorithm` named one, because an
operator who chose an algorithm for their certificate authority meant it for
every Issuing CA in it.

**THAT PREFERENCE EXPOSED A LATENT BUG WORTH KNOWING ABOUT.** A tier's stored
`signatureAlg` is what its PARENT signed it with, and both `certify()` and
`issueUnder()` were handing it to the primitive as the algorithm to sign a LEAF
with, using that tier's OWN key. The two coincide whenever a branch is one key
family throughout, which every branch this service had ever built was — so
nothing could see it until an EC Issuing CA sat under an RSA Intermediate, and
then it is `Invalid key type` out of Web Crypto naming neither the tier nor the
algorithm. Both sites go through `signatureForIssuer()` now, which answers the
stored value when the key can produce it and the right default when it cannot.
`tests/spiffe_pki.js` guards both, and it is the only place in the service where
either can be asked.

### `pep-tls`: A SERVER KEY PAIR FOR A PROCESS THIS SERVICE DOES NOT RUN, AND THE TOP-UP IT FORCED (2026-09-13)

The sixth use case certifies a remote XACML PEP's HTTPS listener, and it is
REALM-scoped where `tls` is process-scoped for the reason the scope column
exists: `tls` certifies sockets every realm answers on, and a PEP registers
against one realm's PDP and enforces one realm's policy.
`xacml/CLAUDE.md` and `xacml-pep/CLAUDE.md` argue the feature; three things are
this module's.

* **`issueTlsServerKeyPair()` IS THE ONE DOOR HERE THAT HANDS A SERVER PRIVATE
  KEY OUTSIDE THIS PROCESS.** It generates the pair, certifies it through
  `certify()` under a SLOT named for the PEP, and returns the private key once.
  `certify()` and not `issueUnder()`, because a listener certificate lives for
  months and names its issuer's CRL and OCSP responder — a responder with no
  record of the serial answers `unknown` — and because a slot is what makes a
  reissue SUPERSEDE the certificate it replaces. The register keeps no key,
  exactly as for a key this service holds.
* **ONLY RSA AND NIST-CURVE ECDSA** (`TLS_SERVER_KEY_ALGS`), a narrower list
  than `keyAlgorithms()`: a listener that starts and fails every handshake is
  the worst version of this feature. **A certificate with no subjectAltName is
  refused** (`STS-PKI-0166`), because node's `checkServerIdentity()` no longer
  falls back to the CN. `keyEncipherment` is asserted for an RSA key only.
* **ADDING A REALM USE CASE MADE EVERY STORED BRANCH INCOMPLETE, SO
  `ensureScope()` TOPS UP INSTEAD OF REBUILDING.** It rebuilt any branch
  missing an Issuing CA, which was right while "missing" could only mean a
  build that failed half way. The day a use case is added, every branch in a
  PRODUCT-mode store is missing one on the next start — and a rebuild replaces
  the realm's Intermediate, superseding every Issuing CA under it and every
  certificate those issued, the published JOSE and XML chains included. That is
  a restart revoking a realm to add an authority nobody had used.
  `topUpScopeNow()` issues just the missing Issuing CAs under the Intermediate
  the branch already has, and supersedes nothing. **It is taken only when every
  missing use case has `pathLen: 0`**, because a missing CA needing room
  beneath it (`spiffe`'s shape) may not fit the depth the stored Intermediate
  was issued with; that case rebuilds, as before. A branch with NO Issuing CA
  at all is still built whole. `tests/pep_listener_certificate.js` section A
  pins it.

### THE DEFAULTS OF A BUILD NOBODY TYPED INTO ARE SETTINGS, AND A FULL STORE REFUSES (2026-09-12)

Four things the console's Build form could say and nothing else could:

* **`pki.signatureAlgorithm` is `algorithmsFrom()`'s default now**, beside
  `pki.keyAlgorithm`, which it always was. The startup auto-build, a realm
  created at runtime and `certify()`'s repair of a stale branch pass `{}` and
  had silently got the per-key default whatever the setting said. A configured
  value the key cannot produce is SKIPPED rather than refused — the SPIFFE use
  case prefers EC while the setting may name an RSA digest — and a CALLER that
  names a mismatched pair is still refused by name.
* **The three tier lifetimes are `pki.rootLifetimeYears`,
  `pki.intermediateLifetimeYears` and `pki.issuingLifetimeYears`, ZERO meaning
  the vendored profile's own number**, so a change to what an Intermediate CA IS
  still reaches this service from the parent project's table. `tierYearsFrom()`
  also fixed a bug the form had: `buildScope()` handed `ensureRoot()` the
  `{ root, intermediate, issuing }` object and `buildRoot()` did
  `Number(object)`, so the Root lifetime the form collects was NaN and fell to
  the profile like a blank.
* **`issueSigningKeyPair()` reads `pki.leafLifetimeDays`** where it had the
  literal 365 beside a `certify()` that read the setting — so the one setting
  described as the default lifetime of an issued key pair governed every issued
  key pair except the ones it was written for. `leafLifetimeDays()` is both
  doors' one read.
* **A full object store REFUSES the next object** (`pki.maxStoredObjects`,
  default 200) where it used to discard the OLDEST — which is very often a CA
  key pair somebody kept and other objects were issued from, discarded on a
  page about a different object. `roomForObject()` answers before a key is
  generated, a REPLACEMENT of an id already held always has room, and
  `MAX_OBJECTS` is a GETTER on the exports so a reader of `pki.MAX_OBJECTS`
  sees the setting. **`common/pki_authoring.js` does not yet check
  `putObject()`'s `ok`**, so an issue into a full store reports the certificate
  and stores nothing; that file is the caller and the gap is recorded rather
  than papered over.

`tests/pki_defaults.js` pins all four, mutation-tested against nine.

### ONE BUILD OF A SCOPE IN THE CLUSTER (2026-09-14, #46)

`oneBuildAtATime()` is per process, and `ensureRoot()` asked this process's copy
whether a Root existed — "no" on every node of a cold start, so each built a Root
and a branch and the last save won. **`oneBuildInTheCluster()`** wraps every
ensure and deliberate build where `keystore.arbitrates()`: read the row from the
store, take a `pki.build` claim (`cluster/cluster_claims.js`), read it again,
build only if still missing, await the row's write, release. A node that finds
the claim held polls the store and takes the other node's build. **The claim is
an optimisation and the merge is the arbiter** — a tier is first writer wins in
`pki_merge.js`, so a build that ran anyway is reported: an ensure adopts the
other node's tier (`STS-PKI-0182` at warn), a deliberate Build is refused with
it. It is a claim and not `cluster.withLease()`, because a lease there is a role a
node keeps, and a Build pressed on any other node would be refused for as long as
the holder lived. `STS-PKI-0183` is a store that could not be asked,
`STS-PKI-0184` a claim held past three minutes. `scep/scep_ra.js` uses the same
function under a claim of its own. `buildScopeNow()` also writes its branch onto
the row as it is when it saves, not as it was read before nine awaits.

**CRL NUMBERS ACROSS NODES** — `pki_revocation.js`'s `agreedCrlNumber()` advances
the clock-based candidate in `cluster/cluster_counters.js` wherever a shared
store is open, stepping past any number another node used; a store that cannot
be asked signs nothing (`STS-PKI-0185`), because a duplicate or backwards number
is what the field exists to prevent.

**AND `serialBytes()` LEAKED THE BUFFER POOL INTO EVERY CRL (fixed 2026-09-14).**
For a serial with its high bit set it returned `Buffer.concat(…).buffer` — node's
shared 8 KB allocation pool — so the CRL entry's "serial" was whatever the process
had recently put there. The two-node revocation probe read one beginning `SELECT
seq, origin, realm, key FROM sts_changes`. Pinned in
`tests/cluster_key_pki_agreement.js` section 12.

### A BRANCH IN ONE ACT, OR NONE

A trust chain is only worth anything WHOLE — and since the shape changed that
rule is about a BRANCH rather than three tiers: an Intermediate with two of its
three Issuing CAs is the state in which one use case silently has no authority
and its keys come out uncertified. An Issuing CA with no Intermediate
above it is a two-tier chain wearing a three-tier name, and a half-built
hierarchy is exactly the state in which somebody issues a certificate that
verifies here and nowhere else. A failure at any tier stores nothing, and a
second call REPLACES rather than adding — with everything issued from the old
one saying so, because a leaf whose issuer is gone stopped verifying and there
is no honest way to hide that.

### IT KEEPS NO STORE OF ITS OWN, AND THAT IS THE DECISION TO CHECK FIRST

The hierarchy lives in **`keystore.js`**, in the `sts_keys` row family, sealed
under the same key-encryption key as the signing keys and read back by the same
`start()`. A store of this module's own would have been a **second answer to
*where does this service keep a private key*** — and the second answer is the
one nobody remembers to rotate, nobody thinks to seal, and nobody purges when a
realm is removed.

**SO IT INHERITS THE MODE, WHICH IS THE HONEST ANSWER RATHER THAN A GAP.**
Product mode keeps it; development mode holds it in memory and loses it with the
process, which is the rule the signing key already follows and for its reason.
Both `report()` and `/admin/pki` say which is in force rather than describing
the mode they wish they were in.

### WHAT IS HANDED OUT AND WHAT NEVER IS

A CA private key never leaves this module. What leaves is a LEAF — a key pair
for one application, handed back ONCE at issuance and written onto that
application's entry — and after that this module holds no copy, because holding
one would make `ou=applications` and this module two answers to *what is that
client's signing key* and the second one unreadable.

`describe()` is the ONE place a private key is dropped, so a caller cannot leak
the Root's by forgetting. `tests/pki.js` asserts that over the whole serialised
view rather than field by field, because what is being checked is that nothing
anywhere in it is a key.

### THE PATH CHECK IS WHERE A SECURITY CLAIM RESTS

`verifyLeaf()` decides whether an `x5c` header counts, and **a chain to somebody
else's anchor verifies every link of itself and means nothing here** — so it
refuses a path that does not end at this realm's own Root, in those words,
rather than reporting a bad signature about signatures that were all fine.

**IT FILLS IN THIS REALM'S TIERS ONLY WHERE THE PRESENTED PATH DOES NOT ALREADY
END SOMEWHERE**, and grafting them unconditionally was the first version's bug:
a complete foreign chain had our three appended after it, so the link walk
reported that their root "is not signed by" our Issuing CA — true, useless, and
about a signature when the thing that is wrong is the ANCHOR. `tests/pki.js`
caught it.

**WHAT IT DOES NOT DO IS CONSULT A REVOCATION LIST, AND THAT SENTENCE
NARROWED ON 2026-09-11 RATHER THAN GOING AWAY.** It read *no CRL is published
and no OCSP is answered, so a certificate this service issued is good until it
expires* — and `common/pki_revocation.js` reversed both halves of it: every
authority signs an RFC 5280 CRL and answers RFC 6960 OCSP, one of each per CA
rather than per realm (a list is signed by an ISSUER, so a list per realm would
have no valid issuer), every certificate names its own over plain http and ldap
(never https or ldaps — RFC 5280 section 8 — on `pki.httpPort`, a listener that
serves `/pki/` and nothing else), and
anything rotated goes on its issuer's list as `superseded` automatically.

**From the root `CLAUDE.md`'s index of things this service does not do — and
its sentence about schemes DISAGREES with the paragraph above, which says http
and ldap only:** the lists and responders are served at `/pki/crl/{scope}/{ca}`,
`/pki/ocsp/{scope}/{ca}` and `/pki/ca/{scope}/{ca}.cer` with an index at
`/pki/revocation`, published into the directory under `ou=crl`, and named inside
every certificate this service issues in THREE SCHEMES (http, ldap, ldaps). A
pane on `/admin/pki` revokes by hand with any of the nine reasons RFC 5280
section 5.3.1 defines. What is left of CONSULTING are limits — a BARE registered
key names no list, a relative name needs `pki.revocationLdapDirectory` — and
`common/mode.js`'s `certificate-revocation` row carries them. **AND *Take the
key pair off* IS A THIRD ACT WITH THE SAME WORD IN IT**: it stops this service
ACCEPTING what that key signs, puts nothing on any list, and does not stop the
certificate chaining.

~~**`verifyLeaf()` STILL DOES NOT LOOK AT ANY OF IT.**~~ **IT LOOKS SINCE
2026-09-12.** That paragraph read *a certificate revoked on this service's own
`/admin/pki` is still accepted here*. `verifyLeaf()`'s last check asks the
register about every certificate on the path — through `revocation_status.js`'s
synchronous door, because the checks before it guarantee the path is this
service's own — and a revoked one is refused with `STS-PKI-0118`.
`admin-ui/crypto_metadata.js` still draws published and consulted as SEPARATE
ROWS, because they are still two claims; the section below argues the check.

**AND IT ASKS WHO WAS ENTITLED TO SIGN EACH LINK, SINCE 2026-09-13.** It
checked every signature, name and validity window and nothing else — so a path
through one of this service's own LEAVES built, anchored and passed through the
realm's Intermediate: every issued key pair is handed over with its private
half, and a holder could sign a certificate of their own and present it under
their leaf. With no subjectAltName the forged leaf named no person and could
assert about anybody. `authorityProblem()` (every issuer `cA=TRUE`, `keyCertSign`
permitted, `pathLenConstraint` held — `STS-PKI-0158`) and `signerProblem()` (the
signer not a CA, `digitalSignature` permitted — `0159`) are the one set of rules,
asked AFTER the two realm checks and BEFORE revocation, and
`registerCertificate()` asks the same functions.

### 3w, CONTINUED: THE SIGNER'S CHAIN AT EVERY USE (2026-09-13)

`verifySignerChain(realm, { certificate, chain, key, source })` is what the three
RFC 7523 / RFC 7522 verifiers ask once a registered certificate's key has
verified a signature. **A registered chain used to be checked once, when it was
written down**, so an expired certificate or intermediate, a rebuilt branch and a
JWKS pasted by hand went on verifying assertions with only revocation looked at.
Three anchors, decided by who issued the leaf:

* **`realm`** — the path built by issuer ends at the service Root; `verifyLeaf()`
  decides it (the realm boundary is its question), called with
  `revocation: false` because the caller's `registeredVerdictFor()` reports a
  registered certificate's revocation under `STS-PKI-0129`.
* **`registered-root`** — anybody else's leaf, with the chain registered beside
  it ending at a SELF-SIGNED ROOT that was registered too. That is the rule rcbj
  chose for uploads the same day, held again at use: links, validity,
  `authorityProblem()`, `signerProblem()`. Nothing is fetched to complete a chain
  (`STS-PKI-0156`): a certificate from an address inside the certificate is not
  one anybody registered.
* **`pinned`** — a self-signed certificate is its own whole chain; its
  self-signature and validity are checked and `cA=TRUE` is NOT refused, because
  every `openssl req -x509` certificate carries it.

`key`, where given, must be the key the certificate holds (RFC 7517 section 4.7,
`STS-PKI-0160`) — compared as SubjectPublicKeyInfo DER, through
`pqSubjectPublicKeyPem()` and pkijs for a post-quantum JWK, since node cannot read
that key out of a certificate. **Refused in both modes**, by the user's decision:
the signature is the whole security of both grants. A bare key is not asked.
`registerCertificate()` and this function build the path with the one
`pathByIssuer()` over `realmCandidatesFor()`, so registration and use cannot
disagree about what the path is. `tests/signer_chain_validation.js` pins it,
thirteen mutants caught (keyCertSign only after its fixture was added).

`report()` carries `revocation` — the sentence, so every surface drawing it
repeats one wording — and `/admin/pki` carries `revocationNote` beside
`revocation`, which is the REGISTER. They are two members because an empty list
and no lists at all are different answers and one field could only carry one of
them.

### THE LEAF IS A SIGNING CERTIFICATE AND DELIBERATELY NOT A TLS ONE

`digitalSignature` and `nonRepudiation`, no extended key usage. What it signs is
a JWT; giving it `clientAuth` would make it usable for RFC 8705 section 2 as
well, which is a DIFFERENT credential with a different registration attribute,
and one certificate quietly doing both is how a deployment ends up unable to
revoke either.

**AND THE SIGNATURE ON IT IS CONSTRAINED BY THE ISSUER'S KEY, NOT THE
SUBJECT'S.** The vendored module's header spends a paragraph on what getting
that backwards produces: a certificate whose declared algorithm and actual
signature disagree, which `openssl verify` reports as a bad signature naming
neither.

**`jwsAlgFor()` IS THE ONE PLACE THE TWO VOCABULARIES MEET.** An RSA key under a
SHA-384 chain signs RS384 — the certificate's digest decides. An EC key does
NOT: RFC 7518 pins ES256 to P-256, ES384 to P-384 and ES512 to P-521, so a P-256
key under a SHA-512 chain is still ES256, and naming it ES512 would produce
assertions nothing can verify. `tests/pki.js` asserts both readings.

### A LEAF IS ISSUED FOR A PROFILE, AND THE TWO PROFILES' KEY PAIRS ARE TWO (2026-09-11)

`issueSigningKeyPair()` takes a `purpose`: `jwt` for RFC 7523 and `saml` for RFC
7522. **An application may hold BOTH**, and the whole point of the field is that
they are genuinely separate — `applications.js` keeps them in two attribute sets
that share no name (`oauthAssertion*` and `oauthSamlAssertion*`), and no verifier
reads the other's. So neither key pair can sign for the other profile, and taking
one off leaves the other working.

**THE PURPOSE IS PUT IN THE CERTIFICATE ITSELF**, as a second URI
`subjectAltName` carrying RFC 7522's grant-type URN, so that a certificate read
out of context says which profile it was issued for. The alternative — telling
them apart by which directory attribute they were stored in — is an answer
nobody holding a PEM file can get to.

**`jwt` IS THE DEFAULT AND ITS SUBJECTALTNAME IS WHAT THIS FUNCTION PRODUCED
BEFORE PURPOSES EXISTED**: one SAN, the application URI. That is deliberate
rather than tidy — every certificate issued before 2026-09-11 is a `jwt` one,
and a default that changed how one reads would make this function's output
depend on when it was called. A purpose it does not know is REFUSED rather than
defaulted, because quietly handing back the other profile's certificate would
put a key pair on the wrong attribute set with nothing saying so.

**IT IS NO LONGER BYTE-FOR-BYTE, AND THAT IS THE 2026-09-12 CHANGE.** Every
key pair from this function — `jwt`, `saml`, an application's and a person's —
now carries `cRLDistributionPoints` (http, ldap, ldaps) and an Authority
Information Access (OCSP, caIssuers) naming the `assertions` Issuing CA that
signed it, which `certify()` and `issueCaTier()` had done since 2026-09-11 and
this door had not. So the one certificate this hierarchy hands to something
that is not this service was the one that could not say where its list was.
**The pointers cost a record**: the responder answers `good` only for a serial
its authority is known to have issued, so the row keeps `issuedKeyPairs` —
serial, subject, expiry, who for, never a key — and `pki_revocation.js`'s
`issuedList()` reads it as its fifth source. Without it the certificate would
point a relying party at a responder that answers `unknown` about it, and the
revoke pane could not offer it. Expired records are dropped at the next issue.
Replacing an application's key pair does NOT supersede the old one on the list;
that is still an operator's Revoke. `tests/pki_revocation.js` section G pins
it.

**`/admin/pki` WRITES SIX ATTRIBUTES FOR ONE AND FIVE FOR THE OTHER**, and the
missing one is the JWKS: SAML has none, and what a party registers for that
profile IS a certificate. The key handle differs for the same reason — a `kid`
where a JWS header names one, a THUMBPRINT where an XML Signature carries the
certificate itself. `admin-ui/pki_admin.js`'s `PURPOSE_WRITES` is the table, and
`oauth-oidc/CLAUDE.md` 3z argues why the sets may never be merged: a SAML
assertion is verified ONLY against a certificate registered under the RFC 7522
attributes, and a chain to this realm's Root is deliberately not enough, because
it is evidence about the REALM and not about the APPLICATION.

### AND THE KEY PAIR IT ISSUES IS SEALED WHERE IT LANDS (2026-09-10)

The three CA key pairs never leave this process. The one the hierarchy ISSUES
does — onto the application's own directory entry under
`oauthAssertionPrivateKey`, or under `oauthSamlAssertionPrivateKey` for an RFC
7522 pair, because `pki.js` hands it over once and keeps no copy — and that
attribute was **the last piece of private key material in this service stored in
the clear.** Both are in `SEALED_FIELDS`, which is a LIST rather than an `if`
for exactly this reason: the second one was added by somebody adding a row to
`SCHEMA`, and a list is where they looked. It is sealed now, under the same key-encryption
key as the hierarchy it came from, through the same `keystore.seal()` /
`keystore.open()` that seal this service's own signing keys, every minted row in
product mode, and an authenticator's shared secret. A new mechanism for the one
remaining case would have been a second answer to *how does this service protect
a private key*, and `pki.js`'s whole placement argument is about not having one.

**THE RULE IS `keystore.persists()` AND NOT `keystore.sealed()`**, which is
`writeTotpRecord()`'s word for word: the question is whether the KEY outlives
the process. Development mode HAS a key-encryption key — an ephemeral one, so
the request-worker pool can share minted rows — and sealing a DIRECTORY
attribute under it would be worse than clear, because the entry survives a
restart in the `ldif` and `postgres` stores and the key does not: the
certificate would come back and the private half would be permanent garbage.

**SEALED AT REST, OPENED FOR A READER THAT CAME THROUGH `applications.js`.**
The split needed no new shape — it is `view()`'s existing one. `fields` is what
that module has recorded about the application and is opened; `attributes` is
what the ENTRY carries and is not. So `/admin/applications` and
`GET /admin-api/applications`, both behind a credential, hand over the PEM
exactly as they did, and an `ldapsearch` on TCP 389 where every bind succeeds,
an LDIF file, a database row and a backup of either hold `$aesgcm$…`. **The seal
protects the STORE and not the console an operator collects an issued credential
from**, and an issued key pair nobody can collect is an issued key pair nobody
can use.

`/admin/ldap/applications` is the deliberate exception and shows the ciphertext,
because that page is headed *the registry as the directory sees it* and an
opened value there would be a page lying about its own subject. The console's
application page is the one surface that draws both halves together, and it
marks the row *sealed at rest* rather than leaving a reader to wonder which they
are looking at.

**A SEALED VALUE SAYS SO AND NOTHING HAS TO REMEMBER.** `crypto.encryptWithKek()`'s
envelope begins `$aesgcm$` and a PEM begins `-----BEGIN`, so `isSealed()` is a
prefix test rather than a marker attribute beside it — a second attribute would
be a second fact to keep in step, and an entry carried between two modes would
be read wrongly the first time the two disagreed. It is also what stops a value
copied off one entry onto another through the console's `set` being sealed
twice, which would open to ciphertext.

**FIVE OF THE SIX ATTRIBUTES AN ISSUE WRITES ARE UNTOUCHED.** A certificate, a
chain, a JWKS, a kid and an expiry are what a relying party is MEANT to be
given, and `client_auth.js` and `assertion_grant.js` read the JWKS to verify
what this key signs. Sealing them would hide something published and break the
verification path in the same act. `tests/pki.js` asserts that, the ciphertext
at rest, the PEM at the surface, that an unrelated edit to the same entry does
not rewrite the key in the clear, and the double-seal refusal.

## 3ab. `person_assertions.js`: a PERSON as an RFC 7523 issuer, and the one refusal it exists for

Added 2026-09-11. `oauth-oidc/assertion_grant.js` accepted an assertion grant
from an APPLICATION and from nothing else: an operator declares
`oauthAssertionIssuer` on an entry, and that party may then sign a document
saying *this person is alice, issue a token for her*. This module is the second
kind of issuer — **a person, signing about themselves** — and the register of
what that takes.

**IT IS RFC 7523 READ LITERALLY RATHER THAN EXTENDED.** Section 3 claim 1 asks
only that `iss` be "a unique identifier for the JWT issuer", and claim 2 says
the `sub` of an authorization grant "typically identifies an authorized accessor
or resource owner". A resource owner holding a key of their own is the case the
profile describes, and it is the one a client author most often wants to run:
no browser, no password, a signature and an access token.

**THE ONE REFUSAL, AND IT IS THE WHOLE SECURITY OF THE FEATURE.** A person's
assertion may name only themselves as `sub`. An application's declaration is an
operator saying *this party may speak about people*; a person holding a key pair
has said nothing of the kind, and reading it as an authority over others would
mean anybody ever issued a key on `/admin/pki` can obtain a token as anybody in
the realm — with the signature verifying, the issuer registered and the claims
well formed while they do it. An operator who WANTS a party that may speak for
others has the door that already existed: an application entry with the issuer
declared on it.

**IT IS CHECKED IN TWO PLACES BECAUSE THERE ARE TWO WAYS IN**, and the second is
the one that would have been missed: a key found on the person's entry, and a
CERTIFICATE presented in the assertion's `x5c` that this service can see it
issued. The chain path does not consult the registry at all — that is the point
of it — so `common/pki.js` puts the answer IN the certificate, as a URI
subjectAltName of `urn:sts:person:<name>`, and `assertion_grant.js` reads
it there. Before people could hold a key pair, *it chains here* and *it may
assert about somebody* were one sentence; that SAN is what keeps them apart.
**The name in the certificate stands on its own**, with no entry required: a
check that lapses when the lookup fails is a check that lapses exactly when
somebody has tidied the entry away.

**SEVEN ATTRIBUTES THAT SHARE NO NAME WITH THE APPLICATION'S.** `stsAssertion*`
on the person's entry — the declaration, the JWKS, the certificate, the chain,
the kid, the expiry and the private half — against `oauthAssertion*` (RFC 7523)
and `oauthSamlAssertion*` (RFC 7522) on an application's. That is
`applications.js`'s rule about its own pair, made a third time for a third kind
of holder: no code path crosses the sets, so no pair can sign for another's
holder, and taking one off leaves the others working. `keysForParty()` in
`assertion_grant.js` is therefore told WHICH KIND of party it is reading rather
than trying every name it knows — the store is schemaless, and a function that
read both lists off whatever it was handed would accept an
`oauthAssertionJwks` somebody had put on a person.

**THE PRIVATE HALF IS SEALED AND IS HANDED OVER ONCE.** Sealed by
`keystore.seal()` wherever the key-encryption key outlives the process, which is
`applications.js`'s decision and `writeTotpRecord()`'s rule word for word:
`persists()` and not `sealed()`, because development's key is ephemeral and
sealing a DIRECTORY attribute under it would leave the certificate readable
after a restart and the private half permanent garbage. **And the issue RETURNS
the PEM**, which the application arm deliberately does not: an application's is
readable afterwards through `applications.view()` — `/admin/applications` and
`GET /admin-api/applications` both open it — and a person's entry is drawn
through no module that would. The alternatives were a console page that prints
somebody's private key on every visit, or a key this service holds that no human
can obtain. That is also why the console's control posts to `/admin/pki/person`
and gets a PAGE back: `respondToAction()` 303s with its message on the query
string, and a private key on a query string is a private key in the browser
history, the access log and the next request's `Referer`.

**A PERSON WITH NO KEY PAIR IS NOT AN ISSUER**, which is not an optimisation.
`issuerFor()` falls back to the username exactly as `issuerEntry()` falls back
to an application's client_id — and without the key-pair condition every person
in the realm would be an issuer by that fallback, so an assertion naming any of
them would get past the registered-issuer refusal and be judged on its `x5c`
alone. Holding a key pair is the thing an operator DID.

**IT HOLDS NO STORE.** `ldap/ldap_server.js` fills a `setDirectory()` slot at
require time with three functions — a read of one person's assertion attributes
in their canonical spelling, a write of one attribute, and the list of NAMES in
the realm. Rule 3e's test answers yes both ways round: this module is required
by `assertion_grant.js`, which `oauth2.js` requires at 9, so a require from
there to the directory would register every `/ldap` route ahead of the
authorization server. The canonical-spelling translation is on the directory's
side of the slot, so this register never learns that the store lower-cases an
attribute name — which is the fact that made `ou=roles` report `0 user(s)` for a
role somebody held.

**TWO DOORS WRITE THROUGH IT SINCE 2026-09-12 AND THEY ARE THE SAME ACT.**
`/admin/pki` is an operator issuing to somebody; `/portal/signing-key` is the
person issuing to themselves. Both call `pki.issueSigningKeyPair()` and then
`write()`, so there is one answer to what is on that entry afterwards. **The
self-service door is only allowable because of the refusal above** — a button
that minted a key able to assert about anybody would hand every person who can
sign in a token as every other person — and because that refusal lives in the
GRANT rather than on either page, neither door can forget it.
`pki.personSelfService` turns the portal's offer off without touching a key
anybody already holds, which is `totp.enabled`'s contract; `portal/CLAUDE.md`
argues the page.

`tests/rfc7523_person_issuer.js` is the in-process half and section 13 of
`tests/vendored/sts_jwt_bearer_grant.js` the over-HTTP one. Two of the claims
cannot be reached over HTTP at all: the sealing is a property of what is on the
entry rather than of any reply, and a certificate issued to somebody who has
since been deleted is a state no sequence of endpoint calls can produce while
still holding the key that goes with it.


### THE REALM WATCHER ASKS AND DOES NOT TAKE (2026-09-12)

`pki.js` subscribes to `realms.onChange(… 'create')` so that a realm made at
runtime gets a branch under the service Root. It ended with:

```js
// AND ITS KEYS, if they have been generated already.
return certifyKeySet(id, keySetProvider(id));
```

**THE COMMENT AND THE CODE SAID DIFFERENT THINGS AND THE CODE WON.**
`keySetProvider` is `helpers.stsKeysFor.of()`, which MAKES a key set for a
realm that has none — so that line did not certify a realm's keys, it CREATED
them, **in every process that saw the realm appear**. In a dispatched service
that is the front process and every request worker.

**WHAT IT COST, MEASURED ON A `--modes=dispatch` RUN OF THE WHOLE SUITE.** A
realm created at 17:48:47.995 had FOUR key sets in four processes within 95ms —
kids `7223b2499bdb` (pid 33), `5adaac82b8f3` (pid 40), `2865074f6ea8` (pid 1)
and `ee9c19ca8208` (pid 34). Each was generated, each was written to
`sts_keys`, and `request_pool.js`'s first-generator-wins arbitrated all but one
of them away. **They converge; what they do not do is converge before
answering**, and every response served inside that window carries a key set the
service is about to disown.

It reached the suite as `tests/vendored/sts_jwt_bearer_grant.js` section 7 — an
RSA public key read from `/oauth2/jwks` on one worker, an assertion encrypted
to it, a token request decrypted on another — **`oaep decoding error`**, which
names nothing and reads as a broken JWE.

**THE FIX IS THE COMMENT MADE TRUE**: a second provider, `keySetHeldFor`,
answers whether this process ALREADY holds that realm's keys, and the watcher
certifies only when it does. Where it does not, nothing is made — the keys are
built once, by whichever process first has a REQUEST that needs them, published
to the others over the pool's key channel, and certified from the other
direction by `helpers.js`'s `certifyLater()`. **The two are the same job
reached from the two directions a realm's keys and its branch can arrive in,
and only one of them can race.**

Measured again on a real dispatched stack, three request workers on one
PostgreSQL store, creating four realms and requesting nothing:

| | key generations |
|---|---|
| before | **13** (three or four per realm, one per process) |
| after | **0** |

It also restores what `helpers.js` already said happened and had silently
stopped being true: *a realm created at runtime makes its keys on first use.*

**THE HELD-CHECK MUST READ THE CACHE AND NEVER `.of()`**, which is the one way
to write this fix so that it is the defect again: `.of()` generates, so a
held-check written with it would answer *yes, this process holds them* **by
making them**. `common/service_state.js` supplies it as
`helpers.stsKeysFor.existing()`, and `tests/key_agreement_storm.js` asserts
that — the fix lives in two files, and a mutation run showed that pinning only
`pki.js` leaves the production wiring free to be deleted with everything green.

## 3ad. `revocation_status.js`: REVOCATION, CONSULTED (2026-09-12)

`pki_revocation.js` PUBLISHES; this CONSULTS. Until it existed a client
certificate on 8443, 9443 or the main port, an X509-SVID at the SPIRE Server API
and an assertion's `x5c` were checked against their anchors and never against a
list. **One function answers** — `verdictFor(input)` (asynchronous) or
`localVerdictFor(input)` (the register only, synchronous) — `good`, `revoked`
with the reason and moment, or `unknown` with why; `decide()` applies
`pki.revocationCheck`. The module header argues all of it; five things reach
outside.

* **WHO SIGNED IT DECIDES WHERE THE ANSWER COMES FROM.** An authority this
  process holds — found by NAME AND SIGNATURE, over `keystore.pkiAll()` rather
  than `pki.rawRowFor()`, whose empty scope id means *the ambient realm* — is
  answered from the register, walking UP through the held tiers whether or not
  the client sent them, so a revoked Issuing CA refuses a leaf presented alone.
  Anybody else's is answered by the OCSP responder its Authority Information
  Access names and the CRL its `cRLDistributionPoints` names — see below.
* **THE FIFTH OUTBOUND REQUEST, ARGUED FROM SCRATCH.** A URL is dialled only for
  a chain that VERIFIED against the truststore — the issuer who wrote it is one an
  administrator installed — and never for an unverified one. http/https only, no
  redirects, a timeout and a size cap, a cache honouring `nextUpdate` capped by
  `pki.revocationCrlMaxAgeS`, failures remembered for
  `pki.revocationFailureRetryS`, one fetch per URL at a time. https is not
  certificate-checked: the CRL's own signature is the authentication.
* **`auto` IS `mode.refusesUnknownRevocationStatus()`**: hard-fail in product,
  soft-fail in development. Development checks too, because the register cannot
  make a good certificate fail. A certificate naming no fetchable list is not
  refused by hard-fail unless `pki.revocationRequireDistributionPoint` — there
  is no fetch to block.
* **THE MAIN PORT IS ANNOTATED, NOT REFUSED.** `common/app.js` runs
  `annotateRequest()` below `requestPool.middleware()` — in the worker that
  answers a dispatched request — onto `req.certificateRevocation`, and the
  synchronous doors read it: `mtls.peerVerified()` (so both XACML chains),
  SCIM's client-certificate scheme and `client_auth.verifyCertificate()`. A
  worker sees the chain because `request_pool.peerOf()` now forwards
  `issuerChain` beside the leaf, and the register because it is a `pki:` row
  every process holds.
* **LAZILY REQUIRED FROM `pki.js`**, inside `verifyLeaf()`, for the cycle
  `pki_revocation.js` already is.

### OCSP, DELTA AND INDIRECT CRLs, THE SAME DAY

The first version read one CRL per foreign certificate and refused as unusable
any list carrying an issuing distribution point or a delta indicator. Four
decisions came with closing that, and the module header argues each.

* **OCSP FIRST, THE CRL AS FALLBACK, AND `pki.revocationOcsp` MAY REVERSE IT.**
  An OCSP answer is about one certificate, usually fresher than the list, and
  the fallback is what keeps a responder that is down from turning revoked into
  unknown. **Revoked from either route wins; a signed `unknown` is NOT upgraded
  by a CRL that does not list the certificate**, because it is the issuer's own
  responder disowning it. The CertID is SHA-1 — an identifier the RFC 5019
  profile requires, never relied on for collision resistance — and a 32-octet
  nonce is always sent: a different nonce echoed back is a replay, none echoed is
  believed unless `pki.revocationOcspRequireNonce`. The signer must be the issuer,
  or a delegated responder the issuer certified with `id-kp-OCSPSigning` and
  whose key the responderID names; that responder's OWN revocation is not asked.
* **THE REASONS ARE A MASK AND THE LOOP IS OVER POINTS, NOT URLS** (RFC 5280
  section 6.3.3). A certificate is good only once its lists cover every reason
  between them; a list with `onlySomeReasons`, or a point with `reasons`, covers
  less. **Three extensions are read out of their raw DER** because pkijs parses
  `onlySomeReasons` into a number that is not the bit string and hands a point's
  `reasons` over with the unused-bits octet in front.
* **A DELTA THAT CANNOT BE APPLIED LEAVES ONLY A PERMANENT REVOCATION
  STANDING.** A base's keyCompromise is revoked whatever a newer list says; a
  base that lists nothing, or a hold, is exactly what a delta updates, so it is
  unknown — blocking the delta must not hide the newest revocations.
* **AN INDIRECT CRL'S SIGNER IS AUTHORISED BY THE CERTIFICATE, WHEREVER ITS
  CERTIFICATE CAME FROM.** The certificate's own `cRLIssuer` names who may issue
  its list; that name's certificate must carry `cRLSign` and chain to an authority
  the presented path passes through, and is looked for in the chain, among this
  process's authorities, in `pki.revocationCrlIssuersFile` and — since the third
  pass — at the caIssuers address the LIST's own Authority Information Access
  names (RFC 5280 section 5.2.7). This file said *never fetched, because the only
  URL for it would be inside the document whose signer is in question*, and that
  is exactly why fetching it is safe: what is fetched is believed only for its
  name, its cRLSign, its validity, its chain to the path and its key verifying the
  list — an impostor gains nothing it could not have had from anywhere. The same
  fetch verifies a DIRECT list signed with the issuer's rollover key. Entries are
  keyed by ISSUER and serial, attributed per RFC 5280 section 5.3.3.

**THE SIGNATURE IS CHECKED WITH THE ENGINE AND NOT `crl.verify()`**, which
answers false for an unknown critical extension and for an issuer name whose
bytes differ from the signer's subject — so a list refused for its extension was
reported as forged. Found by the existing critical-extension test the moment
`2.5.29.27` stopped being unknown and the fixture moved to an OID nobody knows.

### THE THIRD PASS: EVERY ITEM THE SECOND LISTED AS NOT DONE

That paragraph listed four gaps and all four are closed; the module header's
*WHAT IS NOT DONE* is what is left, and it is argued rather than outstanding.

* **A DELEGATED OCSP RESPONDER'S OWN STATUS IS CHECKED** (RFC 6960 section
  4.2.2.2.1) — never through OCSP, which would be the responder vouching for
  itself, but through the CRL its own certificate names. `id-pkix-ocsp-nocheck`
  is honoured and the verdict says `not-checked`. REVOKED makes its answers
  unusable under every policy (`STS-PKI-0127`); UNKNOWN is decided per call where
  the answer is used — hard-fail does not believe it, soft-fail does and records
  that it did — because the answer is cached and the policy is per realm.
* **LDAP IS THE SECOND OUTBOUND PROTOCOL, AND IT IS ARGUED AT `fetchLdap()`.**
  The node-ldapjs SUBMODULE's client, unpatched. `ldaps:` by default, verified
  against node's store plus `pki.revocationLdapCaFile` — an LDAP session is far
  more library code than a DER parser, so TLS bounds who may speak it; plain
  `ldap:` only with `pki.revocationLdap=ldaps-and-ldap`, which is an operator
  saying the directory's network is theirs. RFC 4516 read strictly (a host, base
  scope, no critical extension, only a list's or a CA certificate's attributes),
  one deadline, the connection's bytes capped, one entry, no referral followed.
  OCSP stays http(s): RFC 6960 appendix A defines no other transport.
* **A DISTRIBUTION POINT NAMED RELATIVE TO ITS CRL ISSUER IS RESOLVED** where the
  whole name is unambiguous — every RDN single-valued — and looked up in the
  directory `pki.revocationLdapDirectory` names; a multi-valued RDN, or no
  directory, is refused BY NAME. The certificate does not say which directory,
  and a guess is a request to a host nobody signed.
* **A REGISTERED CERTIFICATE IS CHECKED WHEN IT IS USED** —
  `registeredVerdictFor()`, `STS-PKI-0129`. The RFC 7523 grant and client
  authentication (a registered JWK's `x5c`), RFC 7522 (the registered or issued
  certificate), the federation consumer in all five protocols
  (`fedSigningCertificate`, a partner JWK's `x5c`) and the OID4VP response
  endpoint (`oid4vp.trustedIssuerCertificates`). **Every one of those paths is
  asynchronous and was made to wait**, so there is no register-only twin. Its
  issuer is fetched hop by hop from its own caIssuers address, because nothing
  presents one; a certificate naming no such address is refused only under
  `pki.revocationRequireDistributionPoint`, one naming an address that did not
  answer is refusable under hard-fail. **A bare key is reported `bare` and never
  `good`.** SPIFFE federated bundles are trust anchors, which no list revokes.

The two defence-in-depth delta checks — a delta signed by another authorised key
than its base, and a base with no cRLNumber — have OpenSSL fixtures now, and this
service's own Issuing CA signing an indirect list about a certificate under a
sub-CA it does not hold has one too. LDAPS 636 still asks for no client
certificate. **Node's own `crl` secure-context option was measured and
refused**: it makes OpenSSL require a CRL for EVERY issuer, so a client from an
authority with no list loaded fails with `UNABLE_TO_GET_CRL`.

`tests/revocation_status.js` pins it all in four child processes — the register
and CRL half (with this service's own authority as an indirect-CRL signer and
every door that uses a registered certificate), the listeners, an OpenSSL half
whose every certificate, OCSP response and complete CRL OpenSSL made (pkijs
builds only the indirect lists, which `openssl crl` then verifies), and a closing
half — the responder's own status, caIssuers, the two delta checks, a registered
certificate with nothing presented, and ldap and ldaps against an in-process
ldapjs directory on ephemeral ports. **They are children for what they share with
a process**: `global.mode`, a dozen `pki.revocation*` settings, authorities
revoked in the keystore's rows, and the module-wide caches. The branch race that
first put them there is fixed below.

### A BRANCH IS BUILT ONCE, IN ONE PROCESS (2026-09-12)

`ensureScope()` looked for a complete branch and, finding none, AWAITED a build
of nine signatures. Two callers inside that window both built and the second
REPLACED the first's branch, so a leaf issued from the first was *not signed
by* an Issuing CA of the same name. The two callers were ordinary —
`realms.create()` fires the realm watcher, which builds without being awaited,
and the code that created the realm asks for the branch next — and
`tests/revocation_status.js` met it under `npm test`.

**`oneBuildAtATime()` is a queue per scope**, and `ensureScope()` looks for the
branch INSIDE it, which is what makes the second caller a reader of the first
caller's branch rather than its replacement. `buildScope()` queues the same way
and still replaces — a console rebuild and `certify()`'s repair of a stale
branch mean it. The Root is one more scope (`SERVICE_SCOPE`): two branches built
at once on a service with no Root made two Roots. A build that fails releases
its place.

**AND ACROSS PROCESSES THE WATCHER NO LONGER BUILDS A REALM IT ONLY LEARNT
ABOUT.** `persistence.js` restores a replicated realm through `realms.create()`,
so every process of a dispatched service fired the watcher and built — last
write winning over `keystore`'s PKI channel. `realms.create()` now tells its
watchers `{ restored: true }` for those, and the branch is the creating
process's to build and everyone else's to adopt over that channel, which is
immediate where replication is not. An explicit `ensureScope()` in a process
that needs the branch before it arrives still builds; that is an ask, not an
event every process sees. `tests/pki_scope_builds.js` pins all of it, four
mutants caught.

## 3aa. `pki_authoring.js`: the pane, and the two things it is NOT

Added 2026-09-10 with `/admin/pki`'s Certificate & Key Configuration pane — the
parent project's *PKI / X.509* workflow drawn by a server for a console with no
script on it — drawn as ONE FORM of a hundred and fifteen fields, where that
page has event handlers. `admin-ui/CLAUDE.md` argues
the PAGE; this is the module.

**IT IS A LIBRARY (rule 3)** — it registers no route, so its position in the
require order is not a position. It requires `config`, `pki` and the two
vendored PKI modules; none of them requires it back.

### It is not `pki.js` and it is not the renderer

`pki.js` builds the THREE TIERS and issues ONE kind of leaf, because that is
what RFC 7521 and RFC 7523 need. This issues an ARBITRARY certificate from any
authority whose private key is here: fourteen profiles, five cryptographic
approaches, a subject DN, twenty-two extensions, a PKCS#10 request and four
keystore formats.

They are two files because the first one is on the token endpoint's path
through `assertion_grant.js` and holds the check a security claim rests on
(`verifyLeaf()`), and the second is seven hundred lines of form reading. Burying
one in the other would have made the security-critical file the place somebody
edits to add a checkbox.

**THE MECHANISM IS THE VENDORED MODULE'S AND THE POLICY IS HERE**, which is
`crypto.js`'s split made a third time. `x509.issueCertificate()` takes the whole
extension object; what this file owns is turning a POSTED FORM into one —
the six line grammars, the subject's encoding order, the profile defaults, which
algorithms an approach allows, and what an issue does with all of it.

### The form is the state, and there is no draft store

Every field is re-posted by every button, so *Apply the profile* is a pure
function of what was on the screen. Three things follow and each is worth
keeping:

* **it works across the request-worker pool with no affinity**, because there
  is nothing to be affine to;
* **there is no fourth place a half-finished certificate could be sitting**,
  beside the sessions, the pending authentications and the consent records;
* and **every action answers with a `draft`** — which is what the console's own
  POST re-renders (it answers a 200 PAGE rather than going through
  `respondToAction()`, for `/admin/users/new`'s reason: a redirect carries a
  message on a query string and cannot carry a hundred and fifteen fields) and
  what lets a machine driving `/admin-api` do apply-profile, then issue.

**A FLAG IS PRESENT-OR-ABSENT, EXCEPT WHEN IT IS A REAL BOOLEAN.** An unticked
checkbox posts nothing, so presence is the reading — and the API's own replies
carry those flags as JSON booleans, so a `false` posted back must be `false`.
Without that line `apply-profile` followed by `issue-certificate` with the draft
in between turned every cleared box ON, and the first thing it produced was a
refusal about a reuse checkbox nobody had ticked.
`tests/vendored/sts_pki_workbench.js` found it on its first run;
`"false"` and `"0"` are excluded for the same reason one step along.

### `FIELDS` is a table because the page and the parser are two files

A field parsed and never drawn falls back to its default on every round trip; a
field drawn and never parsed is a control that does nothing. **Neither is an
error anywhere.** So the list is declared here, `admin-ui/pki_admin.js` draws
from it, and `tests/pki_authoring.js` compares the two — which is
`sts_metadata.js`'s argument about endpoints, one layer down. It caught
`pki_selected` being absent whenever the object store was empty.

**The field NAMES are the debugger page's, verbatim.** Not decoration: the two
are one form over one encoder and a reader moving between them should be able to
see that.

**The nine keyUsage bits, the sixteen extendedKeyUsage purposes and the five
Netscape types are GENERATED from the encoder's own tables** rather than written
out, which is `crypto_metadata.js`'s rule applied to a form: a checkbox for a
bit the encoder does not have cannot exist, and one it gains appears the day it
is added.

### A grammar REFUSES and never drops

Six boxes take one item per line and each throws with the grammar in the
message. **A certificate quietly missing a name somebody typed is the worst
outcome available on this page, because it verifies** — which is why every
refusal names the line rather than the field.

### The cost that is stated rather than discovered

Generating a post-quantum key pair is slow and it runs on this thread.
**`common/worker_pool.js` is deliberately not used**: that pool's job table runs
`common/pq_jose.js`, which is this service's OWN reading of the post-quantum
constructions and is independent of the vendored one on purpose — and handing a
key generated by one to an encoder that expects the other's byte layout is
exactly the class of defect that independence exists to expose.
`common/vendored/CLAUDE.md` argues the same thing from the other end.

So `SLOW_FAMILIES` is what the page warns with. In `dispatch` mode the console
holds affinity to a REQUEST worker, so the stall is that worker's rather than
the listener's — a real mitigation, and not a reason to pretend the cost is
gone.

### The object store is `pki.js`'s and not this module's

For that file's own reason: a second place to put a private key is the one
nobody remembers to seal, to purge with the realm, or to share with a request
worker. The objects live in the `pki:<realm>` keystore row beside the three
tiers, and the two are kept apart by ONE rule stated in both directions —
**building the hierarchy does not empty the store and clearing the store does
not remove the hierarchy.** One button meaning both would be the worst kind of
surprise on a page that holds key material.

**`pki_save_keys` IS THE ONE FIELD THAT MEANS SOMETHING DIFFERENT FROM THE PAGE
IT IS MODELLED ON**, and it is kept rather than dropped. There it decides
whether the browser writes the key to `localStorage`; here there is no browser
store, so it decides whether the issued object keeps its private half at all.
The observable behaviour is the same one — an object that can be inspected and
used as a trust anchor and can never sign again — which is why losing the field
to a difference in where the store is would have been the wrong call.

## 3ac. `password_policy.js`: THE PASSWORD POLICY, AND WHERE IT IS ASKED (2026-09-12)

**THIS SECTION'S HEADING READ "`credentials.js` HOLDS THE PASSWORD RULE, AND IT
IS LENGTH" FOR A FEW HOURS THE SAME DAY.** `setPassword()` had stored a
one-character password in product mode, and the fix was a minimum length read
from `security.passwordMinLength`, with no composition rules because NIST SP
800-63B advises against them. rcbj then asked for a policy with composition
rules, a history and a page — so the setting was retired into the profile below
and the NIST sentence became what it always was: an argument a deployment can
act on by setting the symbol count to 0 and both booleans off. What survives of
the length rule is the part that was right — ONE place decides and every door
asks it. (`credentials.factorScanLimit` replacing `FACTOR_SCAN_LIMIT` was the
same day and is unaffected.)

**THE PROFILE IS A DIRECTORY ENTRY**, `cn=default,ou=passwordPolicies` in each
realm, and rcbj chose that over a settings group for the reasons every register
here is in the directory: per realm, persisted and replicated with it, visible
to `ldapsearch`, and a container that can hold a second profile the day one can
be assigned. Six fields — `pwdMinLength` (12), `pwdInHistory` (5),
`stsPwdMinSymbols` (1), `stsPwdRequireUppercase` (TRUE), `stsPwdRequireDigit`
(TRUE), `stsPwdGeneratedLength` (20). **The `pwd*` names are
draft-behera-ldap-password-policy's**, which is what OpenLDAP's ppolicy overlay
reads, and `pwdInHistory` keeps the draft's meaning: PREVIOUS passwords, with the
current one refused beside them. The draft defines no composition rule, so those
are `stsPwd*` and nobody mistakes them for the draft's.

**IT IS A LEAF (rule 3)** requiring `helpers.js`, `mode.js` and the
`generate-password` package, and its directory arrives through a slot
`ldap_server.js` fills — `roles.js`'s arrangement exactly. **`FIELDS` is one
table read five ways**: the schema, the console's form, the management API's
request schema, the validation and the parse. Three decisions in it:

* **THE PROFILE IS NOT SEEDED.** An absent entry means the built-in defaults are
  in force, which is `role-issuance`'s argument: a seed is written into ONE
  realm, and a policy that silently did not exist in the realms created later is
  the defect that argument was made about.
* **AN UNREADABLE STORED VALUE FALLS BACK TO THE DEFAULT, NEVER TO "NO RULE"**,
  and is reported in `problems`. `pwdMinLength: twelve` has broken one attribute;
  the answer must not be a policy with no minimum.
* **A SAVE REPLACES AND CARRIES EVERY FIELD**, refusing a missing one by name —
  a save that quietly reset what it was not told about is the invisible way to
  loosen a policy. The console form is told apart so that an unticked checkbox
  (which posts nothing) reads as "no".

**THE GENERATOR IS `generate-password` AND ITS JOB IS THE DRAW.** It draws from
`crypto.randomBytes` with rejection sampling (no modulo bias) and has no
dependencies; it cannot count symbols, so this file draws whole passwords with
all four pools on and REJECTS any that fail the profile, which keeps the result
uniform over the passwords that pass. `"` and a backtick are left out because a
generated password is pasted into shells and JSON bodies.

**`credentials.js` IS WHERE IT IS ASKED.** `preparePassword()` decides
everything — composition, history, the hash, the history to leave — and writes
nothing; `setPassword()` calls it and writes; the LDAP add and modify handlers
call it inside their atomic working copy. **Enforced only where
`mode.verifiesCredentials()`**, for the length rule's reason; the HISTORY is
RECORDED in both modes, because moving the previous hash into `pwdHistory` costs
no new hash and a realm switched to product should not start empty.
`opts.generated` skips the history comparison (up to six scrypt derivations on
the one thread every socket is served from, for a password nothing could have
used before). A stored value that is not a scrypt hash is compared in constant
time as the string it is, and never copied into the history.
`tests/password_policy.js` holds all of it, eight mutants caught.

**From the root `CLAUDE.md`'s `common/` row:** the profile is drawn at
*Directory → Policies* (`/admin/policies`), ENFORCED IN PRODUCT MODE at every
door that sets a password, and is the generator every made-up password is
drawn from, which is now the default credential for a new user on the console
and on `/admin-api`.

## `credentials.js` GENERATES A PASSWORD IN ONE PLACE, AND `set-password` FINALLY EXISTS (2026-09-06)

Two small changes made when `/admin/users/new` gave the console a way to set a
credential at all, and both are the same rule read twice.

**`generatePassword()` IS THE ONE PLACE THIS SERVICE INVENTS A PASSWORD**, in
the file that is already the one place it verifies or sets one. It is 32 bytes
of `randomBytes` as base64url — not derived from the username, not a word list,
not shortened for typing, because a generated credential guessable from
anything on the screen it was shown on is worse than no generator. `bootstrap()`
had that line inline; it calls this now, so the account a fresh product-mode
service is reachable through and the password an operator generates on the
console are the same strength by construction rather than by both happening to
say 32.

**AND `POST /admin-api/users/set-password` NOW EXISTS.** This file NAMED it
twice — in the sentence a refused sign-in gets, and in the bootstrap banner that
tells an operator to change the generated password — and the operation had never
been written, so anybody who followed either instruction got a 404 naming an
endpoint this service documents. **A message that names an endpoint is a
promise**, and it was easier to keep than to notice: nothing in the code, the
tests or the console reads these strings, so nothing could have shown it. It is
an arm of `admin.js`'s `usersAction()`, which means the console and the API
reach one function.

Both are worth reading beside *ALL FIVE GATED SURFACES* above: the gap there was
an enum documenting itself as done, and the gap here was an error message doing
the same thing.

## `credentials.js` OFFERS A PASSWORD OBSERVER, AND `applications.js` A WITHHELD FIELD (2026-09-12)

Both exist for the stored Kerberos keys, whose register is
`kerberos/krb5_person_keys.js` and whose argument is `kerberos/CLAUDE.md`'s. What
belongs here is the half of each that is this directory's.

**`setPasswordObserver(fn)` IS CALLED AT EXACTLY TWO MOMENTS**: after
`setPassword()` has WRITTEN a password, and after `verify()` or `verifyAsync()`
has answered `reason: 'verified'`. Those are the only two moments this file holds
a plaintext password that is known to be the person's, and a product-mode KDC
needs one — RFC 3961 string-to-key runs over the plaintext and no key can be
derived from the scrypt hash this file stores. It is never called for a
development-mode verification (which checked nothing) or for a refusal.

* **RULE 3e, ON A LAYERING CLAUSE AS WELL AS THE USUAL TWO.** A require from here
  to the filler would be `common/` reaching into `kerberos/` — the inversion this
  directory's entry test exists to prevent — would load the principal database and
  the codec into every process that verifies a password, and would close a cycle,
  because the filler requires this file.
* **WRAPPED, AND IT MAY NOT KEEP THE PASSWORD.** An observer that throws is logged
  and the credential act answers exactly as it would have. The Kerberos filler
  queues one asynchronous derivation and drops the plaintext when it settles — a
  sign-in is never delayed or refused because a key could not be made.
* **THE LDAP DOORS REACH IT THROUGH `passwordWritten()`** (later the same day). They
  write a password through `preparePassword()` inside an atomic modify rather than
  through `setPassword()`, and this bullet read *THE LDAP DOORS DO NOT CALL IT*; the
  handler now calls `passwordWritten()` after it has committed, which notifies the
  observer as a `set`. The stamp still guards any other door that writes the hash.

**`WITHHELD_FIELDS` IS A STRONGER CLAIM THAN `SEALED_FIELDS`.** A sealed field is
OPENED for a reader that came through this module, because an application's
signing key is something an operator collects. `krb5ServiceKeys` is not: it leaves
this service once, as the keytab its create hands over, so `view()` replaces it —
in `fields` AND in `attributes`, ciphertext included — with a sentence saying how
much was kept back. The ENTRY still holds it; the KDC reads it through the
directory, never through here. **It is a schema row and not a raw attribute for a
reason that is not optional**: `writeApplication()` replaces an entry from its
record, and an attribute the schema does not list would be erased by the next
sighting — for a Kerberos service, the next ticket issued for it. **And it is written
through the directory slot, never through `updateApplication()`**, whose audit
summary, log line and reply all quote the value written.

## `totp.js`: RFC 6238, AND THE SECOND CREDENTIAL THIS SERVICE REALLY CHECKS (2026-09-10)

The second second factor. A WebAuthn ceremony is bound to an origin and runs in
a browser; a six-digit code is typed into a form, so it works from a curl
script, from a test job, and from a phone standing beside a machine that has
neither.

**IT IS A LIBRARY (rule 3)** — it registers no route, so its position in the
require order is not a position. It requires `config`, `crypto`, `helpers` and
`realms`, none of which requires it back, and it is read by
`common/credentials.js`, `authn/authn.js`, `portal/portal.js`,
`admin-ui/admin.js` and `admin-ui/crypto_metadata.js`.

### The split with `crypto.js` is the one every pair in that file makes

`crypto.hotpCode()` is RFC 4226 section 5.3 and nothing else: a key, a counter
and a shape in, digits out. It is THERE and not here because **an HOTP value is
a truncated HMAC, and an HMAC is a keyed signature** — this is the fourth thing
this service signs with, and rule 3r is that there is one place that happens. A
`createHmac` in this file would be the fifth call site of a cryptographic
primitive outside the module that exists to hold them all, which is the argument
the six XML signers lost in 2026-08-27.

Everything that is a DEPLOYMENT DECISION is here: the time step, the skew
window, how long an unconfirmed enrolment lives, base32, and what goes in the QR
code. So this file can be read for the mechanism's behaviour and that one for
its arithmetic.

### The code is verified FOR REAL, in both modes, and it is the SPNEGO argument again

`credentials.js`'s header argues that permissiveness here is an IMPLEMENTATION
rather than an absence. This mechanism is the second exception to it and the
first is `kerberos/CLAUDE.md`'s: **Kerberos cannot be permissive because the
password there IS the key, and RFC 6238 cannot be permissive because the code IS
the comparison.** Take the comparison away and there is nothing left of the
specification — no artifact to inspect, no failure mode to demonstrate, nothing
for a client author to test an authenticator integration against.

**And unlike a password there is no usability cost.** The permissiveness
elsewhere exists so somebody can type any name and get a token about it; here
the person has already been let in under whatever name they typed, and the code
is checked against a secret this service generated and showed them ninety
seconds ago.

What development mode still relaxes is everything AROUND it: the password in
front of it is unchecked, the name is unchecked, and any name may enrol.

### It can never be a first factor, and that is arithmetic rather than policy

A WebAuthn credential can be `primary` or `mfa` because the authenticator keeps
a private key this service never sees. **A TOTP secret proves possession of
something THIS SERVICE ALSO HOLDS** — anybody who can read the store can
generate the same codes. That is fine for proving somebody still has the app and
is not a thing to hang an account on, so there is no `role` on a TOTP record and
no setting that adds one. `mechanismsFor().usable` and `.activated` were
therefore left exactly as they were, which is the property to check first if
this is ever reworked. From the root `CLAUDE.md`'s index of things this service
does not do: there is no `primary` reading of it, no setting that adds one, and
every door that could arrive at *a person whose only credential is a second
factor* refuses that state.

### One secret per person, and the reason is in the protocol

`stsWebauthnCredential` is multi-valued because an assertion NAMES the
credential that produced it. A TOTP code is six digits and names nothing. Two
secrets would mean trying both — doubling what a guess can hit, and leaving
section 5.2's accept-once rule with no answer to *which counter was spent*. So
`stsTotpCredential` is single-valued and enrolling replaces.

### The one credential in this directory that can be READ BACK

Verifying a code means COMPUTING it, so the secret cannot be hashed the way
`userPassword` and `stsActivationToken` are. That changes what a directory dump
is worth, and `/admin/ldap/directory` prints every attribute of every entry by
design — so:

* **product mode SEALS it**, with `keystore.seal()`, under the same
  AES-256-GCM key-encryption key that protects the signing keys and every minted
  row. A dump then prints ciphertext.
* **development mode stores the base32**, deliberately. Development's KEK is
  EPHEMERAL where it has one at all — generated per run, never written down —
  so sealing there would mean an authenticator that silently stopped working at
  the next restart, which is precisely the defect that moved the WebAuthn
  credentials out of an in-memory map and onto the entry.

**The test is `keystore.persists()` and NOT `keystore.sealed()`**: the question
is whether the KEY outlives the process, not whether there is one. A record says
which it is (`sealed`), so a store carried between modes is read correctly
rather than being decoded as base32 into codes that are wrong.

**An enrolment that will not open is reported as UNUSABLE and never as absent**,
and that is the opposite conclusion from the one `keystore.open()` draws about a
session row — because the consequences are opposite. Dropping an unreadable
session costs somebody a sign-in; dropping an unreadable SECOND FACTOR silently
removes a security control. `verifyTotp()` refuses those people by name, so they
cannot sign in at all until an operator clears the enrolment on their own row
under `/admin/users`.

### Enrolment is two steps and the first writes nothing

`beginTotpEnrolment()` mints a secret and holds it in a `realms.map()`;
`confirmTotpEnrolment()` takes a code, checks it, and only then writes.
**An unconfirmed secret on somebody's entry would be a second factor they cannot
produce** — a person who opens the page and never scans it would be locked out
by a form they abandoned.

**The three pending stores are persisted since 2026-09-14 (#46)** —
`credentials.pendingTotp`, `credentials.pendingBackupCodes` and
`credentials.pendingKeys`. They were deliberately undeclared, on the argument
that an unconfirmed secret should not reach a disk and that the pages reading
it hold worker affinity. Behind a balancer nothing holds affinity: the setup
POST answered by one node redirects to a GET answered by the other, which drew
no QR code, no recovery codes and no WebAuthn challenge (five jobs in the
suite's `cluster` mode). The worry is answered by the row instead of by its
absence: written only where minted state is (never a single development process,
never memory or ldif), sealed like every minted row, never edited in place (so
no `touch()`), and deleted on confirm, abandon, replace or any process's sweep.
No `tombstone` — `pendingTotp` and `pendingKeys` are keyed by a name a person
writes again every time they start over.

The counter that confirmed the enrolment is stored WITH it, so the very code
used to set the app up cannot also sign somebody in. Section 5.2 applied from
the first moment rather than from the second.

### `secondFactorHolders()` is the one function here that answers about somebody else

Written for the roster on `/admin/users` — which is where `/admin/mfa`'s roster
half went hours after it arrived — and for `GET /admin-api/mfa`, which answers
out of that same view. It is in this file
rather than in the console because *who holds a credential* is a
credential-store question, and a console reading `stsTotpCredential` off entries
itself would be a second implementation of what an enrolment IS — the
sealed-versus-clear distinction included. It unions the realm's directory people
with the names this service has SEEN, because neither alone is right: the second
is all a service with no directory hook has, and the first is the only register
holding somebody who was provisioned through SCIM, spent an activation link,
enrolled an authenticator and has never signed in.

### What `mechanismsFor()` grew, and what it deliberately did not

`totp`, `totpUsable`, `totpDetail` and `secondFactor` are new; `mfaRequired` now
means *either kind*; `usable` and `activated` are UNCHANGED, for the reason two
sections up. `secondFactor` exists because there are two mechanisms and the
sign-in screen has to ask for the right one — it prefers the KEY where somebody
holds both, because that ceremony is bound to this origin and a code is not, and
`authn/CLAUDE.md` argues the link that offers the other.

### `certify()` repairs a stale branch before it issues from one (2026-09-11)

`buildRoot()` replaces the Root and leaves the branches where they are. The
console's Replace-the-Root control rebuilds them in the same act — and a branch
whose rebuild FAILS is logged and skipped, which leaves a hierarchy whose Root
signs none of its own Intermediates.

Issuing from that state is the worst available outcome, because everything
downstream looks right: the leaf is minted, the chain travels with it,
`/tls/server-certificate` publishes the current Root beside them, and the two
Roots have the SAME SUBJECT so every page and every log line agrees with
itself. What it costs is every node client, while curl accepts it.

So `certify()` checks `scopeChainsToRoot()` first and rebuilds the branch when
it does not. **It is there because that function is the one funnel every leaf
goes through** — the TLS listener, an application's assertion key pair, a
SPIFFE authority — so no caller can forget, and because it is the only place
that holds the branch and the Root at once. `scopeChainsToRoot()` compares the
SIGNATURE and not the names, which is the only comparison that can see the
state at all.

`tls/CLAUDE.md` carries what it looked like from the outside, and
`tests/pki_anchor_drift.js` pins the repair.

### And it records only what the CURRENT authority signed (2026-09-15, #46)

The signature is an await, and a branch rebuild or a reissue of the use case
can land inside it — the realm watcher certifies a new realm's keys in the same
moment `POST /admin-api/pki/build` rebuilds that branch. A certificate signed by
the replaced Issuing CA and recorded afterwards would be published, with the
old Intermediate as its chain, until something certified that slot again; a
rebuild's own re-mint (`admin-ui/CLAUDE.md`, *A rebuild re-mints*) only reaches
what was recorded before it. So just before `saveRow()` — no await between —
`certify()` compares the row's Issuing CA and Intermediate with the ones it
signed with, and when either moved it SIGNS AGAIN from the current one. Nothing
is superseded: the first certificate was never recorded, returned or
published. Bounded at three retries, then refused with `STS-PKI-0186`.
`tests/pki_rebuild_recertifies.js` section B drives it deterministically by
replacing the authority from inside a wrapped encoder.

### The pool had no bound on a job, only on a worker's life (2026-09-11)

`worker_pool.js`'s header states the principle — *a promise nobody settles is
a request that hangs* — and `reap()` honours it for a worker that DIES: every
job in flight is rejected with a sentence naming the pid. **Nothing covered a
worker that stays alive and never answers.**

One did. Five idle children, no CPU anywhere in the process tree, the service
answering every other request in eleven milliseconds, and a single HTTP request
parked until the test runner's 300-second watchdog killed the job. Twice per
mode, in every mode, which is ten minutes a run.

`workers.jobTimeoutS` is the bound, 120 seconds by default and `0` to remove
it. The default is generous deliberately: the stalls this pool exists to move
off the event loop were measured at 15 to 23 seconds, so two minutes is far
beyond any real job and far short of a watchdog.

**It is a backstop and not a diagnosis.** Why a reply goes missing is not
known; what changed is that the caller is told instead of waiting for ever. The
worker is left alone when it fires — it is alive, and it holds no state, so it
is kept for the next job. `tests/worker_pool.js` section F drives it, and the
way that test first passed for the wrong reason is written down beside it: an
earlier section leaves the pool computing in the FRONT process, where there is
no worker to time out, so a bound cannot fire and the assertion recorded a
resolve.

## 3y. `backup_codes.js`: the third second factor, the only mechanism here that no specification defines — and the one whose design REVERSED on 2026-09-11

A short list of single-use strings that stands in for whichever second factor a
person is configured for when they cannot produce it. `common/backup_codes.js`
is the MECHANISM (what a code is made of, how one is generated, how one is
compared, and since 2026-09-11 how one is HASHED) and the recovery-codes
section of `common/credentials.js` is the STORE (where a set lives, when it is
issued, what spending one does). Exactly the split `totp.js` has, for its
reason.

**It is a LIBRARY (rule 3)** — registers no route, requires `config`, `crypto`
and `helpers`, and nothing it requires can reach back.

### There is no document, and that changes what the arguments are made of

Every other mechanism here implements somebody's specification and the
interesting questions are about fidelity. Nobody ever wrote an RFC for a
recovery code. What every identity provider does converges anyway — a handful
of random strings, shown once, each accepted once — so what is left is a set of
product decisions, argued in the module rather than cited from anywhere.

### WHAT REVERSED, AND WHAT IT COST

Two decisions were reversed together on 2026-09-11 and neither survives alone.
The old text is kept because both arguments are still TRUE; what changed is
which side of each trade this service takes.

**IT WAS ISSUED BY AN ACT AND NOT BY A REQUEST.** `ensureBackupCodes()` was
called from the end of `confirmTotpEnrolment()` and from `addKey()` for an
`mfa` key, and there was no door anywhere that created a set on request. The
argument: *making recovery a thing a person has to remember to ask for produces
exactly the population it exists to protect, one person at a time — the ones
who did not ask are precisely the ones who will need it.* It also closed a
one-way door, since a flat phone was otherwise an account nobody could get into
until they found an operator.

**AND IT WAS ENCRYPTED RATHER THAN HASHED.** `crypto.js`'s rule is that a
secret this service VERIFIES is hashed and one it must PRESENT cannot be. A
recovery code was both, and what decided it was that a person could look at
their remaining codes again on `/portal/mfa` — *a list shown exactly once, at
the end of an enrolment somebody is rushing through, is a list most people
close without reading, and the moment it matters is months later.*

**WHAT IS TRUE NOW.** A person generates their own set when they ask to see
one; it is shown ONCE, on the response to that POST; and it is stored only when
they press *I have saved these codes*, at which point each code is put through
`crypto.hashSecret()` — scrypt, the same function `userPassword` goes through
(rule 3r: one place). Nothing anywhere can produce a stored code again.

**THE SECOND REVERSAL IS WHAT FORCED THE FIRST**, and that is the part worth
keeping: a hash can only be made while the code is in the clear, so an
automatic issue would have to hash a list at a moment nobody was looking at
it — a credential its owner never saw, which is worse than a way back nobody
asked for. The two could not be kept.

**WHAT REPLACED THE AUTOMATIC ISSUE IS `recoveryAdvised`**, a flag on
`mechanismsFor()` and on every row of the second-factor roster, true of
somebody who holds a second factor and no set. `/portal/mfa` draws a standing
prompt from it and `/admin/users` a column. **A nudge somebody can ignore is
weaker than a set they were handed**, and this file says so rather than
pretending the trade was free.

### Two steps, and the first writes nothing

`beginBackupCodes()` mints a set into a pending `realms.map()`;
`confirmBackupCodes()` hashes it and writes it. That is
`beginTotpEnrolment()` / `confirmTotpEnrolment()` beside it, shape for shape,
and for its reason — an unconfirmed credential on somebody's entry is a second
factor they cannot produce. Here it is sharper, because confirming REPLACES: a
set written before the person said they had kept it would replace a working
list with one they never read. The pending set expires on
`backupCodes.pendingTtlS`, and expiring it changes nothing about a set already
confirmed.

### The cost of hashing is real, and it is why there is an async door

Measured on this machine: one scrypt hash is **72ms**, and a WRONG code must be
compared against every code in the set — ten by default — which measured
**860ms with the event loop ticking ZERO times**. Node runs this service's six
listener families on one thread, so that is not a slow request; it is a service
that answers nobody for most of a second, every time somebody mistypes ten
characters off a printed list.

So `credentials.verifyBackupCodeAsync()` puts the candidates on the worker pool
in parallel — **263ms, with the loop ticking 56 times** — and `/authn/backup-code`
uses it. The synchronous door is kept for `workers.count = 0`, for `npm test`,
and because a caller that cannot be made asynchronous is better off blocking
than wrong. Both go through one `backupPrepare()`, so they refuse in the same
ORDER: a password typed into the code box is refused on its SHAPE and costs no
hashing at all.

### A set written by an older build still works

`backupCodes.isHash()` tells the two stored forms apart PER ENTRY, and a legacy
entry is compared as a string exactly as it was. **It is not migrated**, which
would mean hashing codes at a moment nobody is looking at them; the person is
invited to generate a new set instead, and `backupCodeStatus()` reports
`legacy` so every surface can say which kind it is. Somebody is holding that
list on paper and the one thing this mechanism may never do is stop working
with nothing having said so.

### Two numbers that read a legal zero as absent (fixed 2026-09-12)

`backupCodes.groupSize` was `Number(x || 5)`, so its documented zero — *print it
unbroken* — became five; `totp.js`'s `totp.window` was `Number(x || 1)`, so the
zero its row names for demonstrating a synchronised clock forgave a step either
side. Both read through `numberOr()` now, and `report().atRest` — which
`/admin/crypto-metadata` prints — stopped saying the codes are "ENCRYPTED and
not hashed", a day after they became hashes.

### A spend that will not write is a REFUSAL

`verifyTotp()` treats a failed counter write as a warning; this refuses,
because a recovery code that cannot be marked spent is a permanent
credential — the single property a single-use credential may not have.

**It is checked FOR REAL, in development too** — from the root `CLAUDE.md`'s
index of things this service does not do: a single-use RECOVERY CODE presented
at `/authn/backup-code` is compared against the set on that person's entry and
SPENT (2026-09-10), for the third reading of the same argument as SPNEGO's and
TOTP's: there is nothing left of a one-time credential once the comparison goes.

### The alphabet is base32's thirty-two characters and is NOT shared with `totp.js`

`totp.js` uses them for INTEROPERABILITY — the `otpauth://` Key Uri Format says
a shared secret is base32. This uses the same thirty-two for a different
reason: **no pair of them is confusable**. No `0` beside `O`, no `1` beside
`I`, no `8` beside `B`. A recovery code is the one credential here somebody
writes on paper and types back months later. They are declared separately
because they are the same set today by coincidence of good properties.

### It is never a FIRST factor and never the factor a sign-in ASKS for

`mechanismsFor().secondFactor` answers `webauthn` or `totp` and never this, and
`mfaRequired` is deliberately not true of somebody who holds only a set. A
recovery code stands in for a factor the person cannot produce, so treating
them as configured for two factors would ask for a second factor at a sign-in
they have no way to complete.

## 3z. `inetorgperson.js`: what a person IS, and why the account page draws a list rather than the entry (2026-09-11)

Every person `ldap/ldap_server.js` creates carries `objectClass: ['top',
'person', 'organizationalPerson', 'inetOrgPerson']`, and this file is the
definition of that last class — the union of the three, fifty attributes,
because inetOrgPerson subclasses organizationalPerson which subclasses person.

It exists because `/portal`'s Overview grew a section that had to answer *what
does this identity provider hold about me*, and there was no list to answer it
from. The four facts it showed — username, subject, email, name — came off the
SESSION, so the page reported what the sign-in happened to carry rather than
what the directory holds.

**A LIBRARY (rule 3)** requiring only `helpers` — not `config`, not `realms`,
because it is a SCHEMA and there is nothing about it a deployment or a trust
realm could change. Required by `portal/portal.js` and `ldap/ldap_server.js`.

### THE LIST IS THE WHOLE DESIGN, AND THE ALTERNATIVE IS THE DEFECT

The obvious implementation of that section is to print every attribute the
entry carries. It is the one thing it must not do, and the reason is not
tidiness: **an entry in this directory carries whatever anybody put on it.** A
TLS client certificate's subject becomes attributes RDN by RDN, SCIM writes its
own mapping, an `ldapadd` on 389 writes anything at all — and this service puts
four `sts`-prefixed CREDENTIALS on that same object, one of which
(`stsTotpCredential`) can be read back and used.

So a page that printed the entry would print a shared secret the day somebody
enrolled an authenticator, with nothing anywhere having decided that it should.
**A new attribute this service invents cannot appear on the account page**, and
that is a property of the list rather than of anybody remembering.

`tests/vendored/sts_portal_directory_attributes.js` is where that is held: it
confirms an enrolment, checks through `/admin-api` that the secret really is on
the entry, and then requires that it is nowhere in the HTML. **Every other
assertion in that file passes against the dump-the-entry implementation. Only
that one fails** — and the first version of it passed too, because it started
an enrolment instead of confirming one and so had nothing on the entry to leak.

### `rowFor()` REFUSES TWO KINDS, AND IT REFUSES THEM HERE RATHER THAN AT THE PAGE

* **`secret` — `userPassword`.** It is on the `person` MAY list, so a faithful
  reading of the schema puts it on the page. What sits in it is a scrypt hash,
  which is not a plaintext leak and is still the thing a sign-in is CHECKED
  against.
* **`binary` — `audio`, `jpegPhoto`, `photo`, `userCertificate`, `userPKCS12`,
  `userSMIMECertificate`.** RFC 4522 transfer syntax: octets, not text. And
  **`userPKCS12` conventionally carries a PRIVATE KEY**, which is why the flag
  refuses rather than truncates.

Marking them here means a second surface that ever draws this list gets both
refusals without knowing about them. **The page ALSO branches on `secret`** —
it has to, to word the cell — so the two are belt and braces, and the
consequence is that the over-HTTP job cannot tell whether this module still
refuses. `tests/inetorgperson.js` pins it at the function; deleting the branch
fails that file and passes the whole protocol suite.

### The alphabet of names is checked against the directory, and the SECTIONS against the RFCs

The spellings are merged into `ldap/ldap_server.js`'s `learnName()` like every
other schema here, so a disagreement with `STANDARD_NAMES` is reported at
startup rather than resolved by merge order. **One name is deliberately not
spelt the way RFC 2798 spells it**: that document writes
`x500uniqueIdentifier`, RFC 4519 section 2.43 registers `x500UniqueIdentifier`,
and this file follows the registered spelling because `ldap_server.js` already
chose it and said why.

**THE SECTION NUMBERS ARE A DIFFERENT PROBLEM AND NOTHING COULD HAVE CAUGHT
ONE.** A citation is not a spelling, so `learnName()` never sees it — and a
wrong one is worse than none, because the whole reason it is printed under
every value is so that a reader can go and look the attribute up. Every one in
this file was checked against the RFC text itself when it was written, which
found several in the draft (`mobile` and `pager` cited as RFC 2798 when they
are RFC 4524; `audio` at RFC 2798 2.1, which is `carLicense`).

**It also found six that had been in this repository since the tables they were
in were written.** `oid4vc/vc_claims.js` had `givenName` at RFC 4519 2.6 — that
section is alphabetical and 2.6 is `destinationIndicator` — `labeledURI` at RFC
2079 2 in a document whose sections are unnumbered, and all four of its RFC
2798 rows off by two; `scim/scim_map.js` had `employeeType` at 2.7 rather than
2.5. All are corrected.

`tests/inetorgperson.js` compares the two catalogues' citations for every
attribute they share, so the NEXT divergence is a failure rather than something
a reader would have to notice. It cannot check either against an RFC — nothing
in that process can reach one — which is the limit worth knowing: **it enforces
agreement, not correctness**, and the correctness was established once, by
reading the documents.

### RFC 2798 defines nine attributes and the class allows twenty-seven

Not a contradiction: an object class MAY-list NAMES attributes, it does not
define them. The twenty-seven are defined across five documents, and the
citation on each row is the document that DEFINES the attribute rather than the
one whose MAY list it is met in — because the citation is there to be followed.

## `mode.js`: WHERE `development` AND `product` ARE TOLD APART (2026-09-06)

**This moved here from the root `CLAUDE.md` when that file was broken up** —
its `common/` row and its index of things this service does not do.

**Since 2026-09-06 `mode.js`, `credentials.js`, `keystore.js` and `secrets.js`
— the four files that make this service a PRODUCT as well as a mock.**
`mode.js` is the one place `development` and `product` are told apart, and
every surface that used to decide for itself whether a credential was required
asks it instead.

**THE THREE TURNSTILES CANNOT BE TURNED OFF ANY MORE.** The SCIM endpoints, the
SPIRE Server API and the admin console are a turnstile rather than a lock, and
**none of the three can be turned off**: the settings that did it are gone since
2026-09-06 — see `common/mode.js`.

**IN PRODUCT MODE, since 2026-09-12, this service does not start with
demonstration data, invent a claim value, or open a test control to anybody.**
No seeded people, groups, Kerberos fixture accounts or SPIFFE entries; no
persona surname, `@sts.example` address or `email_verified: true`;
`POST /tls/trust`, `POST /dpop/nonce-mode`, open client registration, the SAML
1.1 attribute authority and a sign-out naming somebody else are refused.
Development keeps all of it, which is what the test suite drives.

## ALL FIVE GATED SURFACES ASK THE POLICY, AND THEY ALL SIGN IN THROUGH ONE STORE (2026-09-06)

`common/access_gate.js` declared five resources from the day it was written and
**two of them asked** — the admin console and the User Portal. The management
API, SCIM and the SPIRE Server API were entries in an enum that nothing
consulted, and the prose in `xacml/xacml.js`, `xacml/xacml_admin.js`,
`mgmt-api/admin_api_spec.js` and two test files said all five did.

**THAT IS WORSE THAN AN UNFINISHED LIST AND IS THE LESSON WORTH KEEPING.** An
unimplemented item on a list is visible. A five-entry enum with prose asserting
five callers is a to-do that documents itself as done: nothing in the code, the
tests or the console could show the gap, and the console was telling operators
something untrue. It is the failure the drift checks exist to prevent, committed
in the prose those checks do not read.

All five ask now. Each asks **after its own check and never instead of it** —
the console's two roles, SCIM's six RFC 7644 schemes and SPIRE's per-method
table all still decide first, so a refusal a caller sees is the most specific
one available and an unedited service behaves exactly as it did.

| Surface | Where it asks | What decided first |
|---|---|---|
| `admin-console` | `admin-ui/admin.js`'s gate | the two console roles |
| `user-portal` | `portal/portal.js`'s `requireSignIn()` | a sign-on session |
| `scim` | `scim/scim_auth.js`'s `authenticate()` funnel | six RFC 7644 schemes, then the scope |
| `spire-server-api` | `spiffe/spiffe_grpc.js`'s `prepareCall()` | SPIRE's own per-method table |
| `management-api` | `mgmt-api/admin_api.js`'s middleware, **product mode only** | the two console roles |
| `xacml-pep-api` | `xacml/xacml.js`'s `pepAccess()` | a VERIFIED client certificate resolved to a directory entry |
| `xacml-api` | `xacml/xacml.js`'s `xacmlAccess()` | the same chain, with `XACML_USER` on the end |

**THE TWO XACML ROWS ARE NOT LIKE THE FIVE ABOVE THEM, AND THE DIFFERENCE IS
THE DEFAULT.** The five are surfaces an operator NARROWS: they require
`EVERYBODY` until somebody says otherwise, which is what kept this layer from
changing behaviour the day it was added. The two XACML ones carry their
requirement in the REQUEST and are restricted out of the box, because a gate
that is permissive until configured is a gate that is open on every deployment
nobody has configured. It is still a POLICY decision either way — one
`access-control` document decides all seven, and `xacml.enforceAccess` is the
one switch that stops it deciding.

**THE MANAGEMENT API IS THE ONE ASYMMETRY AND IT IS ARGUED RATHER THAN
INHERITED.** That surface is open in development by design — it is what the
tests drive and the way back in when nobody holds a role — so there is no
credential, no session and no subject. Asking a policy whose built-in document
refuses an unauthenticated subject would close the recovery path. **A policy
layer must not be the thing that removes the way back in.**

### The session is `authn.startSession()`, and a second register was the wrong answer

Three of the five authenticate PER REQUEST — a bearer token, a Basic header, an
X509-SVID over mutual TLS — and held no session at all: nothing on
`/admin/sessions`, nothing for a global sign-out to end, no subject with a
session behind it for the policy.

The obvious fix was a register of API sessions. **It is the mistake rule 3m
exists to prevent**: `authn.js`'s map is where a session lives, `logout.js`
reads it, the console draws it and CAEP observes it, and a second store beside
it would be a second answer to *is somebody signed in* — with the wrong half
being whichever surface a reader happened to open. So it is one store and two
fields on the record:

* **`detail.key`** — a fingerprint of what was presented. A call whose key
  matches a live session TOUCHES it instead of minting one, so a provisioning
  client doing a thousand PATCHes leaves one row. The key is the SCHEME AND THE
  PRINCIPAL rather than the credential, for two reasons pointing the same way:
  nothing here keeps what was presented (a bearer token in a register is a
  second place to steal one from), and the right unit is the CLIENT — an agent
  that rotates its SVID mid-run is the same agent, and keying on the
  certificate would give it a second row and leave the first until it expired.
* **`detail.cookie: false`** — a SCIM client is not a browser, and handing one
  a session cookie would invite a client to use it as a credential: a second
  way into that surface none of its own rules would ever see. Opt-OUT, because
  every caller that existed before this field is a browser.

**ONE STORE DOES NOT MEAN ONE KIND OF ROW.** `logout.js` branches on
`credentialKey` — the one predicate that decides — so an API session is drawn
by its own surface, carries the FOURTH expiry rule (`SESSION_EXPIRY_RULES.api`,
the only one **extended by use**, because these exist only while a client is
calling where a browser holds a cookie that outlives its own use), and reports
CALLS rather than the relying parties a browser session carries. A SCIM client
drawn as a "Browser sign-on session" would be that page saying something untrue
about the one thing it exists to report.

**ENDING ONE REVOKES NOTHING, and the rule says so where it is read.** The
token, password or certificate behind it is accepted without consulting any
register, so the next call authenticates again and the row comes back. What
ending it buys is what a sign-out buys everywhere else: the record stops saying
somebody is using the surface, and a global sign-out can say what it reached.

`tests/api_sessions.js` pins all of it, including — last, so that nothing above
could pass by making every session an API session — that a browser session is
exactly what it was.

## `oidc_rp.js`: THIS SERVICE'S OWN TWO SURFACES ARE CLIENTS OF ITS OWN AUTHORIZATION SERVER (2026-09-06)

**This moved here from the root `CLAUDE.md` when that file was broken up.**

Since 2026-09-06. `/admin` and `/portal` used to authenticate by REDIRECTING
STRAIGHT TO THE SIGN-IN SCREEN and then reading the session that screen minted.
They are **OpenID Connect relying parties** now: an unauthenticated request is
sent to `/oauth2/authorize`, comes back to a registered redirect URI with a
code, and the code is redeemed at `/oauth2/token` with a client secret and a
PKCE verifier for an ID Token that establishes a session of that surface's own.

**WHAT WAS WRONG WITH THE OLD ARRANGEMENT IS THE WHOLE ARGUMENT**: this
service's own two applications were the only applications in the process that
did not use the protocol this service exists to demonstrate. A real relying
party has no access to the provider's session store; these two read it.

`common/oidc_rp.js` is the client and carries the design at length. Six things
reach outside it and this is the index of them:

1. **THEY ARE ORDINARY ENTRIES IN THE REGISTRY.** `sts-admin-console` and
   `sts-user-portal` under `ou=applications`, seeded at startup
   (`applications.seedInternal`), each a confidential client with a secret
   minted per start, `authorization_code` + `refresh_token`, `response_types:
   ['code']` and `client_secret_basic`. **Deleting one takes its surface offline
   until a restart**, with a refusal that names the entry — which is the seeding
   rule finally having an observable consequence. — *THERE ARE THREE OF THEM
   SINCE 2026-09-06* under `applications.js`, above
2. **THE BACK CHANNEL IS A REAL HTTP REQUEST AND IS THIS REPOSITORY'S FOURTH
   OUTBOUND ONE.** It dials ITSELF, at a loopback address it computes, on a port
   it is listening on, pinned to its own TLS certificate, carrying the BROWSER'S
   Host header so the `iss` claim is the one the authorization endpoint
   advertised. Redeeming the code in process would have been a client that skips
   client authentication, skips PKCE verification and writes no audit row — the
   half of the flow that only looks run. — `common/oidc_rp.js`
3. **THERE ARE TWO KINDS OF BROWSER SESSION NOW AND ONE STORE.** The SIGN-ON
   session is what a person has with the identity provider; a RELYING PARTY
   session is what one application has with a person who signed in through it.
   Both are rows in `authn.js`'s map, told apart by `rpSurface` exactly as an
   API session is told apart by `credentialKey`, because a second register would
   be a second answer to "is somebody signed in" (rule 3m). **A relying-party
   session names the sign-on session it came from and dies with it**, in a
   cascade inside `dropSession()` — the one place a session ends. **What it no
   longer dies with, since 2026-09-12, is the sign-on session RUNNING OUT**: the
   console and the portal keep the tokens their sign-in was issued and, when
   the ID Token and access token expire, renew them with the refresh token grant
   over the same back channel, writing them onto the same session — same cookie,
   same page, no sign-in — for up to the refresh token's lifetime from the
   sign-in (`common/oidc_rp.js` section 4, `oidcRp.renewBeforeExpiryS`) — once
   per session across NODES as well as requests since 2026-09-14 (#46), through
   a claim (`oauth-oidc/CLAUDE.md`, *Several nodes*). A
   sign-out still ends it. — `authn/CLAUDE.md`, `logout/CLAUDE.md`
4. **`/admin/callback` IS THE ONE PATH UNDER `/admin` THE CONSOLE GATE DOES NOT
   GUARD**, and it cannot be: somebody arriving there has no console session
   yet. It is an exemption IN the gate rather than a route registered above it,
   so "everything below the gate is guarded" stays true by construction. **The
   SECOND exemption is `/admin/signout`** (2026-09-06), which is guarded — a
   session and this session's CSRF token are both required — and is exempt from
   the ROLE check only, because ending your own session is the one act on that
   console needing no permission and the alternative is a console a reader can
   enter and cannot leave. **The THIRD is `/admin/signals/receive`**
   (2026-09-10), where this console takes delivery of its own Shared Signals
   stream: a push is a server-to-server request carrying no session by
   construction, so the gate could only refuse it, and what guards it instead is
   the stream's own bearer token, the audience and the signature. **The check
   moved rather than went away, which is the test a fourth exemption has to
   pass.** — `admin-ui/CLAUDE.md`, `ssf/CLAUDE.md`
5. **EACH SURFACE HAS A SIGN OUT BUTTON OF ITS OWN, AND IT ENDS TWO
   SESSIONS.** `POST /admin/signout` (in the console's shell, on every page —
   inside the ACCOUNT MENU since 2026-09-10, whose other row is a link to that
   person's own account in the portal)
   and `POST /portal/signout` (in the portal's own shell, on every page since
   2026-09-06) end the
   surface's relying-party session AND the sign-on session behind it. Ending
   only the first would be a button that signs nobody out: the next request
   runs the code flow, meets the live sign-on session, and comes back in with
   nothing typed. Neither is `/logout`, which ends everything an identity
   holds in every protocol and is still linked from both. — `admin-ui/CLAUDE.md`,
   `portal/CLAUDE.md`
6. **NEITHER SURFACE PROMPTS FOR CONSENT**, because both entries carry
   `oauthGlobalConsent`. — *BOTH CARRY `oauthGlobalConsent`* under
   `applications.js`, above

**THE REALM RULES SPLIT IN TWO ON 2026-09-11, AND THIS PARAGRAPH SAID THEY
WERE UNCHANGED.** It read: *the console's runs in the DEFAULT realm wherever it
was reached, because the role roster lives there; the portal's runs in the
AMBIENT realm, because `/portal` is a person's own account in the realm they are
in — which is why the portal's client is seeded in every realm and the console's
in one.* Every clause was true and the FIRST ONE COST THE THING THIS WHOLE
SECTION IS FOR.

**An authorization endpoint can only answer out of the realm it is reached in**,
because `authn.js`'s session store is per realm. So a console authorizing in the
default realm and a portal authorizing in `acme` were asking two different
authorization servers, neither of which could see the other's sign-on session:
**two sign-ins, in both directions, for one person in one browser**, everywhere
but the default realm. Single sign-on between this service's own two surfaces —
the one thing moving them onto the code flow was supposed to make fall out for
free — worked in exactly the configuration nobody notices.

**A SURFACE HAS TWO REALMS NOW AND THEY ANSWER TWO QUESTIONS.** The FLOW realm
is which `/oauth2/authorize` the browser is sent to, and it is AMBIENT for both:
that is the single sign-on, and it is why the console's client is seeded in
every realm now rather than in one. The SESSION realm is where the surface's own
session lives, and the console's is still DEFAULT wherever it was reached —
which is what keeps one console session readable from every realm, keeps the
realm switcher switching without a prompt, and keeps the role roster in one
place. The portal's is the ambient realm, unchanged, because `/portal` is a
person's own account in the realm they are in.

**THE CONSEQUENCE IS ONE SENTENCE AND EVERYTHING IN `authn.js` THAT LEARNT IT
IS THERE: a console session's PARENT is in a different partition from the
session itself.** `derivedFromRealm` is the field, `relyingPartySessionOf()`
looks the parent up where it lives, and `dropSession()`'s cascade walks the
default partition as well as the parent's own — without which a sign-out ends
the sign-on session and leaves the console session it issued working, which is
the defect that cascade exists to prevent. `tests/cross_surface_sso.js` pins all
of it in process and `common/oidc_rp.js`'s surface table argues the split.

**AND A SECOND, OLDER BUG CAME OUT WITH IT: A `Location` HEADER IS NOT MARKUP.**
`app.js` rewrites every root-relative `href`, `action` and `src` in an HTML
response into the current realm, which is what carries the console's several
hundred hand-written links; a redirect header is none of those. The console
passed `req.originalUrl` as its return address and kept the prefix by accident;
the portal passed the CONSTANT `/portal` and lost it — so signing in at
`/realm/acme/portal` completed the flow in acme, was handed a session in acme,
and landed on the DEFAULT realm's portal, which correctly has no session and
asks again. It is fixed at `oidc_rp.js`'s one choke point and is idempotent,
because a prefix a caller has to remember to add is one the eighth call site
will not have.

## `version.js`: M.N.O, and why the build number is not computed at startup (2026-09-06)

**It is a PORT of the parent project's `client/version.js`, not an invention**,
and the whole reason to say so first is that this repository is a submodule of
that one: its container is built beside that project's two, and a reader who
has learnt to read one version string should not have to learn a second. What
changed in the port is written down in this file's own header — four things,
each with its reason — and is not repeated here. The scheme, the surfaces it
reaches and the one number this repository cannot reconcile with the parent are
under *The scheme, and the number is fixed when an artifact is BUILT* at the end
of this section, moved from the root `CLAUDE.md`'s *Versioning*.

What belongs here is the four properties that make it a `common/` module rather
than a script.

**IT IS A LEAF AND MUST STAY ONE (rule 3).** It registers no route and requires
NOTHING from this repository — not `helpers.js`, not `config.js`, not even the
logger. So its position in the require order is not a position, and it can never
close a cycle. That matters more here than it did in the parent project:
`server.js`, `home/home.js` (6a), `admin-ui/admin.js` (18),
`mgmt-api/admin_api.js` (19), `portal/portal.js` and `sts_metadata.js` (24) all
read it, which is six modules spread across the whole require order — including
the two whose positions are the most constrained in the file. **A version module
that could drag a route would be a version module that decided where routes
go.**

**ITS `log` IS CONSOLE-BACKED AND THAT IS THE SECOND HALF OF THE SAME
DECISION.** The Entering/Leaving convention applies to it like everything else,
and `helpers.js` owns the logger — so the convention is met with the same call
shape over `console` rather than by requiring the thing that would break the
paragraph above. The parent had a different reason for the same code (this file
can run before any install has happened, at build time); both hold, and the
stronger one here is the leaf rule.

**EVERY CALLER READS IT ONCE, AT REQUIRE TIME.** The version cannot change while
the process runs — it is stamped into the artifact or computed once at startup —
so `const APP_VERSION = version.load()` at module scope is not a
micro-optimisation but the correct statement of what the value is. The console's
shell is the one that would have cost something: reading a file on every page
render, in the module that renders the most pages, to learn something fixed for
the life of the process.

**A VERSION MAY NEVER STOP THIS SERVICE STARTING**, and this is the one place in
`common/` where a read failure is deliberately survivable. An unreadable
`VERSION` falls back to `0.0` with a message on stderr; a corrupt `version.json`
falls back to a computed record. Compare `keystore.js` two sections up, where a
key that cannot be read is FATAL and the argument for that is spelt out: a wrong
version misinforms a reader, and a wrong key invalidates every token this
service has ever issued. The two files are the two ends of that judgement and it
is worth reading them together.

**THE PACKAGE ROOT IS FOUND, NOT ASSUMED, AND THAT IS WHAT LETS ONE COPY SERVE
TWO IMAGES.** `findRoot()` probes for the directory holding the `VERSION` file:
one level above `common/` here, and this file's OWN directory in the
`xacml-pep/` image, where the Dockerfile copies it to the container root as
`version.js` with `VERSION` beside it. A hard-coded `__dirname/..` there would
be `/usr/src` — `--stamp` would write a `version.json` nothing reads and
`load()` would find none, and the PEP would silently report a computed number
that changed on every restart. See `xacml-pep/CLAUDE.md` for why the copy goes
to the container root rather than beside the shim.

**`userAgent()` LIVES HERE FOR THE REASON THE MODULE DOES.** This service makes
four outbound requests and three of them reach somebody else's server —
federation's, SSF's RFC 8935 push, and XACML's change nudge. Each says
`sts/<M.N.O> (<component>)` in RFC 9110 product form, built from one copy
of the product token, because three hand-written strings in three modules is
three places for a rename to reach two of. It is not a claim about HTTP living
in a version module: it is the one string in this service that is *made of* the
version.

### The scheme, and the number is fixed when an artifact is BUILT

**This moved here from the root `CLAUDE.md`'s *Versioning* when that file was
broken up.** Its `xacml-pep/` half is in `xacml-pep/CLAUDE.md`.

Since 2026-09-06, and it is **the parent project's scheme rather than one of
this repository's own** — `id-proto-debugger/client/version.js` is where it was
written, `common/version.js` is a port of it, and the differences are listed in
that file's header rather than here.

```
0.1.20260906143205
│ │ └── the BUILD NUMBER: the UTC build instant, YYYYMMDDHHMMSS, or BUILD_NUMBER
│ └──── minor ┐ both from the repo-root VERSION file, which is the single
└────── major ┘ source of M.N. Bump a release by editing it.
```

**THE BUILD NUMBER IS DECIDED AT IMAGE BUILD TIME AND NOT AT STARTUP, AND THAT
IS THE WHOLE DESIGN.** `Dockerfile` runs `node common/version.js --stamp .`
after the source is copied, which writes a `version.json` that ships inside the
image; `load()` prefers that record and computes one only when there is none. A
service that numbered itself when the process started would report a different
build every time its container restarted — which makes *which build is this*
unanswerable in exactly the situation where it gets asked, because restarting is
what somebody does when they suspect the build. **A record that was computed
rather than stamped says so**, and every surface that draws the version repeats
it: `stamped: false` means a checkout is being run and the number is when it
started.

**SEVEN SURFACES DRAW IT AND THERE IS ONE SOURCE.** The startup banner, the front
page's version line, the foot of every admin console page, the foot of every
user portal page, `GET /admin-api` (with `build`, `commit`, `builtAt` and
`stamped` broken out beside it, so a client reads fields rather than writing a
regular expression), `/admin/sts-metadata` — the one page whose subject is
what this service IS, where it is in the lead paragraph and in the JSON — and
**the remote PEP's own `GET /`, together with the row it registers on the PDP's
`/admin/xacml/peps`**, which is the seventh and the subject of
`xacml-pep/CLAUDE.md`. **Two
of them used to read `require('../package.json').version`**, which is `M.N.0`
with a placeholder patch, so the front page and the management API reported the
same string for every build ever made. `tests/version.js` asserts the SOURCE
each of them reads and not the string it renders, because two surfaces reading
two different sources agree perfectly right up until they stop.

**THE THREE OUTBOUND REQUESTS SAY WHICH BUILD IS CALLING**, in RFC 9110 product
form — `sts/0.1.<build> (federation)`, `(ssf-transmitter)`,
`(xacml-pdp-notify)` — built by `version.userAgent()` so there is one copy of
the product token. Each of those reaches somebody else's server, and their
access log is where an integration with a mock they did not install gets
diagnosed.

**Both `package.json` files carry the same M.N as `M.N.0`** (semver needs three
parts, and the real build number is not one of them). `node common/version.js
--check-manifests` reports drift and `--sync-manifests` fixes it.

**ONE NUMBER IS NOT RECONCILED WITH THE PARENT AND CANNOT BE FROM HERE.** That
project's own `--sync-manifests` carries `sts` in its manifest list and rewrites
`sts/package.json` to the PARENT's M.N.0. That checkout is this repository, so
after a parent sync the two say different things — which is correct: they answer
*which release of the debugger is this submodule pinned into* and *which release
of the mock STS is this*, and those are different questions. `--check-manifests`
here checks this tree only, and `../id-proto-debugger/sts` is read-only forever.

## 3w, CONTINUED: A CERTIFICATE UPLOADED IN PLACE OF AN ISSUED KEY PAIR (2026-09-13)

`pki.registerCertificate()` is the second way an application's RFC 7523 or RFC
7522 key pair is replaced, beside `issueSigningKeyPair()`. The application
generated its own key pair and brings the certificate; nothing here receives or
stores a private key, and an upload carrying one is refused by name.

**WHAT "COMPLETE" MEANS DEPENDS ON WHO ISSUED IT.** The path is built by ISSUER
over the uploaded certificates plus this realm's own tiers and the service Root
— never by paste order. A path ending at THIS SERVICE'S Root is held to
`verifyLeaf()` (this realm's Intermediate, nothing revoked), so a leaf this
realm issued may arrive alone and another realm's leaf is refused even with its
whole branch: with one Root, "chains to a self-signed root" is true of every
realm's certificates, and treating that as an external authority would walk the
realm boundary through an upload form. Any other path must end at a
self-signed root that was UPLOADED, and is held to the checks a signature walk
alone misses: every issuer a CA (basicConstraints), permitted keyCertSign,
within its pathLen; the leaf not a CA and permitted digitalSignature; nothing
unrelated uploaded; a self-signed leaf refused (it belongs on `oauthJwks` /
`oauthSamlAssertionSigningCertificate`); revocation checked through
`revocation_status.registeredVerdictFor()`. The key must be one the profile's
verifier can use — RSA ≥ 2048 or ECDSA P-256/384/521 for both, secp256k1 and
Ed25519 for JWT only.

**AN EXTERNAL CHAIN IS STORED WITH ITS ROOT**, where the issued convention
leaves this service's Root out: a foreign root is held nowhere else, and the
revocation check needs every issuer. That is also why
`saml_assertion_grant.js` now hands the managed certificate's CHAIN to the
revocation check (threaded through `clientConfigOf()`'s new
`saml_assertion_certificate_chain` for §2.2); the JWT side already carried it
in the JWK's `x5c`.

**THE RECORD IS THE ISSUE'S SHAPE WITH AN EMPTY PRIVATE KEY**, so one table
writes both and the empty private key clears the one an earlier issue left —
an entry holding a key for a certificate it does not match would go on handing
that key out. `oauthAssertionKeySource` / `oauthSamlAssertionKeySource` record
the provenance (`KEY_SOURCES`: `issued`, `uploaded-realm-ca`,
`uploaded-external-ca`), and `applications.KEY_PAIR_ATTRIBUTES` is the one
table naming which attribute holds which half per profile.

**`applications.regenerateClientSecret()`** mints a secret the way a
registration does and updates the stored registration document. **And
`updateApplication()` no longer quotes a credential's value** into the audit
summary, the log line and the reply: it did, for `oauthClientSecret` written
through the console's generic Set, while the comment on the audit call said the
value was kept out. `tests/application_credentials.js` pins all of it,
eighteen mutants caught and one recorded as equivalent.

## 3ab, CONTINUED: A PERSON'S RFC 7522 KEY PAIR, AND A CERTIFICATE IN PLACE OF EITHER (2026-09-13)

Asked for as *the application's Credentials section, for users*, and it cost a
reversal: `/admin/pki` refused an RFC 7522 key pair for a person
(`STS-PKI-0108`, retired) because the SAML verifier read nothing off a person, and
refused an upload for a person (`STS-PKI-0153`, retired) as *an operator
registering a key a person never saw*. Both arguments were true of the code they
described; the verifier reads a person now, and an upload carries no private key.

* **A FOURTH ATTRIBUTE SET, `stsSamlAssertion*`** — Issuer, Certificate,
  CertificateChain, a sealed PrivateKey, Thumbprint (the handle an XML Signature's
  certificate is matched by), ExpiresAt, KeySource — sharing no name with
  `stsAssertion*`, which gained `stsAssertionKeySource`.
  `person_assertions.KEY_PAIR_ATTRIBUTES` is the table, in
  `applications.KEY_PAIR_ATTRIBUTES`' shape. **`write()`, `clear()`, `issuerFor()`
  and `subjectIsSelf()` take a profile and DEFAULT TO `jwt`**, which is what
  every caller written before the set means. `/portal/signing-key` passes one
  since 2026-09-13 — it issues and takes off either profile. `issuerFor(iss, 'saml')`
  finds a person only while they hold a SAML key pair, which is the crossing,
  made once as a lookup. `holders()` keeps its JWT members and nests `saml`.
* **`pki.registerCertificate()` TAKES `subjectKind`** (the `kid` prefix, the
  wording) and refuses, for a leaf THIS realm issued, the two registrations that
  WIDEN whoever holds the key (`STS-PKI-0155`): for a person, a leaf naming
  anybody else (another person's holder could assert as this one); for an
  application, a leaf naming a person (that person would speak for others).
  **One application's leaf for another stays allowed**, as uploads shipped — the
  first version refused it too and broke Request 1's own job, which uploads a
  donor application's certificate. A self-signed leaf for a person is refused
  with no by-value alternative named, because a person has none.
* `tests/person_credentials.js` pins it, fourteen mutants caught (two only after
  the fixture asserted the issued private key WAS there and read the view while a
  private key was held — a leak check over an entry holding no key proves
  nothing).

## 3ae. `used_assertions.js`: AN ASSERTION IS ACCEPTED ONCE, EVER (2026-09-13)

Asked for as *a history of SAML assertions and JWTs submitted successfully for a
grant or client authentication, each usable once ever, persistent, and kept only
until it would have expired*. It replaced THREE replay caches — one each in
`oauth-oidc/client_auth.js`, `assertion_grant.js` and `saml_assertion_grant.js`
— and the module header lists the four ways those were not "once ever". Four
decisions were asked of the owner before it was built and each took the
recommended answer; they are the design.

* **PERSISTENT IN EVERY STORE, IN BOTH MODES.** This is the one thing a request
  writes that persists in development mode, and the reason is the reason
  minted state does NOT: "development persists nothing it minted" rests on the
  signing key being regenerated, so a restored token verifies against nothing.
  An assertion is signed by the CLIENT's key, on its directory entry, which
  every store keeps — so it verifies after a restart, and forgetting it was
  spent is a replay. `memory` keeps it in the process and loses nothing a
  restart would not also lose.
* **A STORE OF ITS OWN, NOT A `realms.map({ persist })`.** The journal flushes
  after the fact and converges through the change log, which is exactly the
  window "once ever" cannot have. postgres holds `sts_used_assertions`, claimed
  by one `INSERT … ON CONFLICT (realm, key) DO UPDATE … WHERE expires_at < now`
  — a live row is never overwritten and an expired one is replaced, which is
  "until it would have expired" read literally. ldif holds a file per realm,
  written before the claim returns. The driver groups are tested for BY NAME
  (`DATABASE_GROUP`, `SNAPSHOT_GROUP`), and a driver with neither is warned
  about rather than trusted.
* **ONE HISTORY FOR EVERY USE.** The key is SHA-256 over FORMAT, ISSUER and
  IDENTIFIER — not the use — so a JWT that authenticated a client is refused as
  a grant and the reverse. The format is in the key because a SAML `ID` and a
  `jti` are two namespaces. `client_auth.js` keys by the client_id, which the
  library has already required to equal `iss`, and the grant by `iss`, so both
  reach one row; `tests/used_assertions.js` holds that as behaviour and as
  source.
* **SUCCESSFUL MEANS TOKENS WERE ISSUED.** A claim made with a `request` is
  RESERVED and bound to `request.res`: `finish` with a 2xx makes it `spent`,
  anything else — or `close` without `finish` — releases it. A reservation
  refuses a racing replay exactly as a spent row does. Without a request (the
  in-process tests, anything verifying outside HTTP) it is spent at once, which
  is what every caller did before.

**THREE PROPERTIES THAT ARE EASY TO BREAK:**

* **THE CLAIM IS THE LAST CHECK OF THE DOCUMENT** in all three verifiers, so an
  assertion refused for any other reason is not also used up. Moving it earlier
  would make a bad `aud` or a lifetime refusal burn a good assertion's `jti`.
* **A CRASH LEAVES A RESERVATION AND THAT IS THE SAFE DIRECTION.** A process
  that dies before its response finishes neither confirms nor releases, so the
  assertion is refused as used until it expires. A reservation that evaporated
  would, on a crash after the tokens reached the client, be a replayable
  assertion.
* **THE STORE FAILING FAILS CLOSED** (`STS-OAUTH-0243`): an assertion this
  service cannot prove unused is not one it accepts. The store's own message
  goes to the log and never to the client.

**AND IT FOUND A BUG IT DID NOT CAUSE.** In RFC 9700 mode the token endpoint
verified a client assertion twice per request — policy, then observation — and
with one cache that spent on the first, the second was a replay: the client was
observed as unauthenticated. `client_auth.js`'s `verifiedOnce()` is the fix and
`oauth-oidc/CLAUDE.md` 3i records it. It was not visible before because the old
caches were each in one process and the refusal was an observation rather than a
response.

**THE CAP IS UNCHANGED IN MEANING AND NARROWER IN EFFECT**:
`oauth2.assertionReplayCacheSize` is one count per realm now rather than one per
cache, and a full history still refuses rather than forgets. On postgres the
count is read in the claim's own statement and is not under a lock, so two
claims at the edge can put a realm one or two over; the cap bounds a table, and
a replay is what the key bounds.

**It is drawn at `/admin/used-assertions` and `GET /admin-api/used-assertions`**,
one function (`admin-core/admin_views.js`'s `usedAssertionsView()`, a PROMISE,
because on postgres the history is a query), read-only on purpose: forgetting a
row would make a still-valid assertion usable again.

**Verified against a real PostgreSQL**, which no in-process test can do: the
least-privilege role opening a store built by `postgres/schema.sql`, twenty-five
concurrent claims of one assertion with exactly one accepted, a release deleting
and a 2xx confirming, an expired row replaced, a second driver refusing a
replay, the cap refusing the eleventh, and a version-3 database refused with
`STS-STORE-0029` until `schema.sql` is run again. `tests/used_assertions.js`
holds the in-process half — thirteen mutants: nine caught at the first round,
two after the fixture was fixed (a restart check a later write had quietly
passed, and no cross-verifier check), one by the source check (the grant keying
by a prefixed issuer, which no in-process request reaches), and one equivalent
(the restore's expiry filter, which the sweep every read runs makes
unobservable) — and sections 14
and 13 of `tests/vendored/sts_jwt_bearer_grant.js` and
`sts_saml2_bearer_grant.js` the HTTP half, with four service mutants caught
there.

## 3af. `jose_certificate_header.js`: A SIGNED TOKEN NAMES ITS CHAIN (2026-09-13)

Every JWT this service signs with a certified key may carry `x5c` (the chain
inline) or `x5u` (the address of the chain), chosen per USE CASE and per realm.
The module header argues the design; four decisions came from the owner and are
the design rather than details of it: **`x5u` by default**, **signatures only**
(no JWE — every JWE here is encrypted to somebody else's key or to the
refresh-token keys, which are not leaves), **settings on each protocol's page**
(twelve rows in six groups — RFC 9701's JWT introspection response the
twelfth, 2026-09-13 — built by one `certificateHeaderSetting()` in
`config.js`), and **the FULL chain**, leaf to the service Root.

* **ONE FUNNEL, AND A SOURCE CHECK FOR THE FEW WHO GO AROUND IT.**
  `helpers.signJwt()`, `signJwtAs()` and `signJwtAsAsync()` take
  `certificateHeader: '<use case>'`; the four signers that call
  `stsCrypto.signJws()` directly merge `helpers.certificateHeaderFor()` into
  their own header. `tests/jose_certificate_header.js` section B fails on any
  signing call outside `common/crypto.js` that names no use case and carries no
  `// certificate-header: none — <why>`, and on a use case the table has that no
  signer names. **A new signer is a row in `USE_CASES`, a row in `config.js` and
  the option at the call.**
* **THE CERTIFICATE MUST HOLD THE KEY.** The register row for the key's slot is
  used only when its SubjectPublicKeyInfo fingerprint matches the signing key —
  cached by certificate thumbprint and `kid`, so the token endpoint pays no key
  export per signature. A mismatch gives no header and logs `STS-PKI-0163` once.
* **THE `x5u` ORIGIN IS AMBIENT.** `common/app.js` enters the request into an
  `AsyncLocalStorage` just below the realm middleware; `global.publicBaseUrl`
  wins where pinned; a signature with neither gets no `x5u`. The address is
  `/pki/chain/{scope}/{sha256}.pem` in `pki/pki_service.js`, scope in the path
  for the CRL's reason and named by the CERTIFICATE so it never answers a chain
  over a rotated key.
* **TWO SIGNERS ARE EXEMPT AND ONE WAS A MISTAKE FIRST.** The SPIFFE JWT-SVID has
  no certificate. The DIF Domain Linkage Credential had a use case for an hour:
  its specification allows exactly `alg` and `kid`, and the vendored `vc_did.js`
  job failed on the first run against it. A setting whose every non-`none` value
  breaks conformance is a trap, so it is exempt with that reason.
* **`signed_metadata`'s cache key includes the setting**, or a change would go
  unseen for the life of an entry.

`tests/jose_certificate_header.js` pins it: eleven service mutants through a
require hook and one source mutant on disk, all caught.

## 3af, CONTINUED: THE `kid` MAY BE THE KEY'S RFC 9278 THUMBPRINT URI (2026-09-13)

`common/jose_kid.js` argues the design; four decisions came from the owner:
**one setting per realm** (`keys.kidFormat`, drawn under Key material, because
a `kid` names a key in the realm's one JWKS), **not the default**, **the JWKS
listing every signing key under BOTH names while it is on** (so a token signed
before the switch still finds its key), and the URI naming the key rather than
its certificate. Four things reach outside the module:

* **THE INTERNAL KID IS STILL THE KEY'S NAME.** `helpers.publishedKidFor()` is
  applied where a header is written — `signJwtAs()`, `signJwtAsAsync()`,
  `signJwt()`, `oauth2.js`'s `signPublishedDocument()`, `vc_issuer.js`'s
  credential signer, GNAP's key document — and `certificateHeaderFor()` is
  still handed the INTERNAL kid, because that is how it finds the key. A new
  direct signer translates the kid it writes and nothing else.
* **A LOOKUP OF THIS SERVICE'S OWN TOKEN ACCEPTS EITHER NAME, WHATEVER THE
  SETTING SAYS** — `helpers.kidNamesKey()`, asked by `ssf_events.js`'s
  `publicKeyForHeader()` and `vc_verifier.js`'s issuer check. The verifiers
  that fetch `/oauth2/jwks` (`oidc_rp.js`, `federation_sp.js`) need nothing:
  the set carries both names.
* **`crypto.js` GAINED THE AKP MEMBER LIST** (`alg`, `kty`, `pub`, RFC 9964),
  so a post-quantum key has a thumbprint. DPoP and ACME still refuse those
  algorithms by name; their comments give the missing row as the reason and
  predate it.
* **NOT TRANSLATED**: HMAC (no kid), the SPIFFE JWT-SVID (a separate
  authority), and the three DID-bound kids — the DIF Domain Linkage Credential,
  `/did/generate`'s credential, and the DID document's verification method ids.
  A key whose thumbprint cannot be computed signs under its internal kid and
  logs `STS-KEYS-0055` once.

`tests/jose_kid.js` pins it: RFC 7638's own example to RFC 9278's URI, the AKP
members, the setting row, the library, and — in a child process — the header,
the doubled JWKS, verification by the entry the kid names, ES256 and ML-DSA-44,
a SET verified here, GNAP's key document, off again, and a realm's own override.
**`signed_metadata`'s cache key carries the format** (`oauth2.js`'s
`signedMetadata()`), for the certificate header's reason; the test found it
missing. Fourteen mutants, all caught.

## 3ag. `tls_client_certificates.js`: TRUSTING THE ROOT IS NOT TRUSTING WHAT IT ISSUED (2026-09-13)

`/portal/signing-key` hands a person a TLS client certificate to install in a
browser. It is useless unless the TLS listeners trust its chain, their client
truststore was empty by default, and OpenSSL will not end a path at an Issuing CA
without a partial-chain flag node does not expose — **so the listeners trust the
SERVICE ROOT**, behind `tls.trustIssuedClientCertificates` (`tls/CLAUDE.md`).

**THE ROOT VOUCHES FOR EVERY KEY PAIR THIS SERVICE HAS EVER ISSUED.** An
application's RFC 7523 key pair has no extended key usage, which OpenSSL reads as
any purpose, and a CN that is a client_id; an X509-SVID carries `clientAuth`.
With the Root trusted and nothing else changed, each would complete a handshake
as VERIFIED, start a sign-on session for its CN, and resolve to a directory entry
at the XACML and SCIM doors. `identityOf()` is what refuses that, and it has
FOUR conditions, each with a fixture of its own in `tests/tls_client_certificates.js`
because a leaf failing two at once hid two deleted checks in the first round:

* the leaf was signed — by NAME AND SIGNATURE, through `revocation_status.js`'s
  `walk()`, now exported with `heldAuthorityKey()` — by a realm Issuing CA in
  `IDENTITY_USE_CASES`: `tls-client`, and `acme`, `est` and `scep`, whose enrolled
  leaves the enrollment session asked to count;
* it carries `clientAuth`;
* it names exactly ONE `urn:sts:person:` or `urn:sts:application:` subjectAltName,
  which is the identity (an enrolled leaf's CN need not be the username);
* for `tls-client`, that name is also the CN, which `issue()` writes from one
  username.

A chain through NO held authority answers `issuedHere: false` and every door
treats it exactly as before — that is an anchor somebody installed at `/tls/trust`.

**THE REALM IS THE ISSUING CA'S.** The TLS listeners are shared by every realm and
a socket has no path to carry one, so `identityOf()` answers the realm of the
authority that signed the leaf and the listeners start the session and record the
authentication there (`realms.run()`). `checkSocket()`, for the main-port doors
that DO have an ambient realm — `mtls.peerVerified()` and SCIM's client-certificate
scheme — refuses a certificate from another realm's authority, which is
`pki.verifyLeaf()`'s Intermediate rule read at a TLS door.

**NO SECOND STORE.** A person's certificates are `pki.certify()` records under the
slot `person:<username>:<12 hex>`, so the holder is read back off the slot and a
rebuilt branch, a revocation on `/admin/pki` and a realm purge all already reach
them. The cap (`pki.personTlsClientCertificateMax`) counts VALID ones only, so
revoking an old device's certificate makes room; expired records of that person
are forgotten at the next issue. **A revocation is looked up among the holder's
own certificates**, `credentials.removeKey()`'s rule, so a serial in a form body
cannot revoke somebody else's.

**THE FILES** are the vendored `exportKeyPair()`'s — the exporter `/admin/keys`
already uses — so PBES2 AES-256-CBC with PBKDF2 and an HMAC-SHA-256 MAC. The page
names the `openssl pkcs12 -export -legacy` rebuild for an older macOS that refuses
that, rather than this service writing a second, weaker format.

`tests/tls_client_certificates.js` pins it (nine mutants) and section 9 of
`tests/vendored/sts_portal_signing_key.js` the portal half (two service mutants).

**AN APPLICATION MAY HOLD ONE SINCE 2026-09-13.** `issue()`, `listFor()`,
`activeFor()` and `revoke()` take a holder KIND, and an application's slot is
`application:<identifier>:<12 hex>` with its own cap
(`pki.applicationTlsClientCertificateMax`, `STS-PKI-0180`/`0181`). The CN is the
identifier and the SAN `urn:sts:application:<identifier>`, which the gate's
CN-equals-SAN rule now applies to for either kind. **`stillHeld()`** answers
whether the holder's record still lists a certificate — the `tls-client`
register for this module's own, `cert_enrollment.findEnrolled()` in the
certificate's realm for ACME, EST and SCEP — and is what RFC 8705's implicit
mapping at the token endpoint asks (`oauth-oidc/CLAUDE.md` 3an). An
application's certificate signs nobody in at 8443 or 9443 (`tls/CLAUDE.md`).

**A PERSON'S CERTIFICATE FOLLOWS THEIR ENTRY SINCE 2026-09-14.** The CN, the SAN, the
slot and an enrolled certificate's issued record all carry the name the person had at
issuance, so a rename left a certificate naming nobody and a name deleted and re-created
handed it to somebody else. `pki.certify()` and `pki.issueEnrolled()` now keep the
holder's `urn:uuid:` subject beside the record (`holderSubject`), and `identityOf()` asks
`currentHolderOf()` on every call — never memoised, since it is the directory's answer —
which answers the entry's current name, `certifiedName` for the one the certificate
carries, or `HOLDER_GONE` when the subject names nobody. `stillHeld()` compares the slot
with the certified name, and `cert_enrollment.findEnrolled()` resolves the subject too. A
record written before the subject was kept is answered by its name, as before.

## 3ag. `cert_enrollment.js`: ACME, EST AND SCEP ISSUE THROUGH ONE CORE (2026-09-13)

Asked for as *implement ACME, EST and SCEP, tied to the embedded CA, isolated
between realms, supporting every `/admin/pki` profile, where a user may only
obtain a certificate that maps to their own identity and an admin to any user in
the realm, every certificate maps to a directory entry, and a private key is
kept on the entry*. **Four decisions were asked of rcbj before anything was
written and each took the recommended answer**; they are the design:

1. **A PRIVATE KEY IS KEPT ONLY WHEN THIS SERVICE GENERATED IT.** ACME, SCEP and
   EST `/simpleenroll` send a CSR — the CA never has the key — so the certificate
   and chain are always written onto the entry, and a sealed private key only for
   EST `/serverkeygen` and the console's server-generated issue.
2. **AUTHENTICATION IS PROTOCOL-NATIVE.** An ACME account is bound FOR LIFE to
   the entry an External Account Binding key was issued for; EST takes HTTP Basic
   (the directory password or client_id + secret, both following `global.mode`)
   or a realm-issued TLS client certificate; SCEP takes a single-use challenge
   password issued for one entry and one profile. The EAB MAC and the challenge
   are verified in BOTH modes (TOTP's argument).
3. **FIVE PROFILES ARE REFUSED**: Root, Intermediate and Issuing CA, OCSP
   Responder and Kerberos KDC — each holder could issue certificates, sign OCSP
   answers for this authority, or impersonate the KDC. `REFUSED_PROFILES` carries
   the reason each page draws.
4. **A HOST NAME IS ISSUED ONLY WHEN IT IS REGISTERED ON THE ENTRY**
   (`stsCertificateHostName` / `appCertificateHostName`, set by an administrator).
   ACME authorizations for those names are pre-validated and no challenge dials
   out, so the root `CLAUDE.md`'s "never dials a caller-supplied URL" row stays
   true.

**WHAT THE CORE OWNS AND THE FAMILIES MAY NOT DECIDE**, which is the whole
reason it is one file: the identity rule (`authorizeTarget()`), the profile
table and the settings that narrow it (`checkProfile()`), the proof of
possession (`parseCsr()` — RSA/ECDSA through pkijs, Ed25519 through node, ML-DSA
and the composites through `x509.verifyBytes()`, a KEM key refused unless the CSR
is a TEMPLATE), the certificate's content (`namesFor()` — subject and SAN from
the ENTRY, an unowned name REFUSES rather than being dropped, and `email`,
`smartcard-logon` and the two `tls-server*` profiles adding or requiring a name of
their own), issuance and storage (`issue()` over `pki.issueEnrolled()`), the two
credentials, host names, revocation, and the two OWASP helpers every endpoint
shares (`transportRefusal()`, `throttled()`/`countFailure()`).

**ADMIN IS DECIDED IN THE DEFAULT REALM WITH THE CREDENTIAL CHECKED THERE.** The
console's roster is the default realm's groups; reading it by NAME alone would
make a realm's person who shares a default-realm administrator's name an
administrator of every realm, so `adminFor()` verifies the password against the
default realm's entry before the roster is consulted. **An EMPTY roster grants
nothing here** (`open` refused), the LDAP socket's rule: *everybody is an
administrator because nobody is* is a console bootstrap, not a reason to issue
certificates in anybody's name. A console or `/admin-api` session is asked the
same roster through `sessionPrincipal()`.

**THE STORE IS THE ENTRY, AND THE CREDENTIAL ID NAMES IT.** Four attribute
families per kind (`stsEnrolledCertificate`/`appEnrolledCertificate` public
JSON records; `…EnrolledPrivateKey`, `…AcmeEabKey`, `…ScepChallenge` SECRET) plus
the host names. An EAB kid is `eab-<p|a>-<base64url(id)>-<16 hex>` and a SCEP
challenge `scep-<p|a>-<base64url(id)>-<16 hex>.<secret>`, so neither needs a
register or a scan and a guessed prefix gains nothing. **Application attributes
are schema rows** (`applications.js`) or the next sighting rewriting the entry
from its record would erase them; the three secret ones are `WITHHELD_FIELDS`,
and all six secret names are in `ldap_server.js`'s `SECRET_ATTRIBUTES`. A
person's subject DN is added to `x509subject`, which every certificate-to-entry
lookup here already reads.

**CERTIFICATE AUTHENTICATION CHECKS THREE THINGS AND THE THIRD IS THE
MAPPING**: `pki.verifyLeaf()` in this realm (another realm's certificate does not
pass through this Intermediate), `clientAuth`, and a urn:sts: SAN naming an entry
that HOLDS this serial unrevoked. A certificate taken off its entry is not that
entry's credential however well it verifies.

**`pki.issueEnrolled()` IS `issueUnder()` PLUS A RECORD.** Three realm use cases
(`acme`, `est`, `scep`) — one Issuing CA per protocol for the reason `jose` and
`xml` are two — and the serial goes into `issuedKeyPairs` under the family, so
`/pki/ocsp` answers `good` and the CRL can list it. A branch built before the use
cases existed is topped up by `ensureScope()`.

`tests/cert_enrollment.js` holds it in process — 238 assertions; fifteen mutants,
fourteen caught and one recorded as EQUIVALENT (the canonical-base64url check in
`entryOfCredentialId()`, which the exact kid comparison makes unobservable). Two
survived the first version and both were the fixture: the non-canonical kid never
got past the regex, and no certificate was presented that its entry did not hold.


## `credentials.js`: A RESET LINK, A REMOVED PASSWORD, AND A REQUIRED SECOND FACTOR (2026-09-13)

For the *Password and second factors* section of a person's console page.
`admin-core/admin_actions.js` is the caller; the rules are here, beside
`setPassword()` and the TOTP and key stores they touch.

* **`removePassword(username)`** moves the current hash into the history
  (`password_policy.historyValue()`), so it cannot be set again, and asks the
  slot's `clearPassword` to delete `userPassword` (`STS-AUTHN-0169`). It exists
  for **issue-password-reset**, which removes the password before handing a
  link over: a link beside a password that still works is not a reset.
* **`issuePasswordReset()` / `checkPasswordReset()` / `consumePasswordReset()`
  / `passwordResetPending()`** — 32 random bytes as base64url, stored as a
  scrypt hash with an expiry of `security.passwordResetTtlMinutes`. Issuing
  replaces any earlier link. The check answers a reason per failure (`0165`
  none issued, `0166` expired, `0167` mismatch, `0168` incomplete) for the audit
  row; the page shows the requester one sentence for all of them.
* **`mfaRequirementFor(username)`** is `{ required, byUser, byRealm }` —
  `stsMfaRequired` on the entry OR `authn.mfaRequired` — and `setMfaRequired()`
  writes the first (`0170`). `mechanismsFor()` carries it as `mfaRequirement`,
  beside `passwordResetLink`.
* **`removePrimaryKeys()`** removes every key in the `primary` role and refuses
  somebody holding no password (`0161`), which is what stops it being a lockout;
  **`removeSecondFactors()`** removes the authenticator app, every `mfa` key and
  the recovery codes, and on a partial failure (`0163`) reports what it removed
  so the caller's signals describe what really happened.
* **`entryExists()`** asks the directory's `personExists`, because `hasEntry()`
  answers false by design and `hasAnyEntry()` is effectively always true.

**Two settings**: `authn.mfaRequired` (group *Second-factor requirement*, drawn
on `/admin/totp` and `/admin/webauthn`) and `security.passwordResetTtlMinutes`.
**Two defaults changed**: `caep.autoEmitTypes` names `credential-change` and
`risc.autoEmitTypes` names `account-credential-change-required` and
`recovery-information-changed` — `ssf/CLAUDE.md` has the table of which door
sends what.

## Several nodes: second factors, links, enrollment credentials and the bootstrap (2026-09-14, #46)

Issue #46 sections 2 and 8. Every value here was spent by reading an entry (or
a replicated map) and writing it back: atomic on one node, and two acceptances
across two inside the change log's window. The capability rows
`authn.second-factors-once`, `credentials.links-once` and `ops.bootstrap-once`
are provided by `credentials.js`, and `enrollment.credentials-once` by
`cert_enrollment.js`, at require time. The argument for each is in the comment
above the function named; what a maintainer needs before touching them:

* **A TOTP step is a COUNTER, not a claim** (`verifyTotpAsync()`), through
  `cluster/cluster_counters.js`, keyed by the person and the enrolment's
  `enrolledAt`: a claim on (person, step) stops the same step twice and not
  an older step after a newer one, which is what `totp.verify()` refuses. The
  entry's `lastCounter` stays the first check and is still written. A refusal is the
  replay it always was (`STS-AUTHN-0106`).
* **A WebAuthn assertion claims its CHALLENGE and advances its COUNTER**
  (`spendAssertion()`, called by `authn/authn.js` after verification): the claim
  is the only defence for an always-zero counter (synced passkeys), the counter
  catches a cloned authenticator even when a stale write took the entry's copy
  backwards (`STS-AUTHN-0035`, the same condition `webauthn.js` names). A
  refused counter gives the challenge back.
* **A WebAuthn REGISTRATION claims its credential id** (2026-09-14,
  `addKeyClaimed()`, called by both ceremony doors — the sign-in screen's and
  `confirmKeyEnrolment()`, which answers a promise now): two concurrent
  registrations of one attestation passed the entry check on two nodes and the
  directory merge kept both rows (they differ in `enrolledAt`). The second is
  refused (`STS-AUTHN-0193`; `STS-AUTHN-0194` when the store cannot be asked).
  The claim is HELD on success for thirty minutes — nothing legitimate registers
  one credential id twice — and given back when the write is refused; after it,
  `addKey()` refuses an id already on the entry whatever door asks
  (`STS-AUTHN-0095`, which only the two ceremonies' begin-time exclusion list
  asked before).
* **A recovery code is claimed by the person and its stored hash, and the
  ENTRY IS MADE TO CONVERGE ON THE CLAIMS** (`spendBackupCode()`,
  `reconcileBackupCodes()`): two nodes spending two different codes each write
  the whole set back and the later write resurrects the other's code. Three
  repairs — every spend writes other claimed codes as spent, a spend on a shared
  store schedules a reconcile eight seconds later (never over a REPLACED set:
  `generatedAt` must match), and a code refused by its claim repairs on the
  spot.
  The residue is stated in the code: a claim lives thirty days.
* **The synchronous doors `verifyTotp()` and `verifyBackupCode()` are NOT
  cluster-safe** and have no production caller; they are kept for their tests.
* **Links are claimed by the PORTAL, not here** (`spendActivation()`,
  `spendPasswordReset()`): only the door knows which POST finishes. It claims
  before setting anything and releases on every response but the finishing one
  (`portal/portal.js`'s `holdLinkClaim()`); `STS-AUTHN-0183` is the refusal.
* **The bootstrap is one claim per realm around BOTH steps** (`bootstrapOnce()`,
  called by `server.js`): the seed of the administrator as well as the password,
  because a node whose seed committed after another node's password write
  replaced the entry with one holding none. The winner catches up, runs, waits
  for its commit and releases; a loser logs who holds it and prints nothing; a
  store that cannot be asked runs nothing (`STS-AUTHN-0185`).
* **`cert_enrollment.js`**: `bindEabOnce()` claims the key id before the binding
  is written (the same account retrying at a second node before replication is
  refused once — the claim cannot say which account holds it);
  `redeemScepChallengeOnce()` claims the challenge id between the peek and the
  spend. ACME's nonce and finalize and SCEP's transaction are in their own
  directories' files; the SPIFFE join token in `spiffe/spiffe_api.js`.
* **`STS-AUTHN-0182`** is one code for "a single-use credential could not be
  proved unspent": every door refuses on it.

`tests/cluster_single_use_credentials.js` holds each against a stub store with
postgres's semantics.

**Verified against a real postgres, two active-active product-mode nodes on one
host (2026-09-14).** Each probe was run first with the fix bypassed by a
`--require` preload that restores the old function, to show it discriminates:

* **Cold start of both nodes at once against an empty store.** Bypassed: two
  of three runs printed TWO bootstrap passwords, and in each only one verified
  against the stored hash. Fixed: three of three printed ONE, and it verified;
  the other node logged that another node held the bootstrap (or, when the
  winner had already released, won the claim, caught up and found the
  credential).
* **One activation link POSTed to both nodes at once, ten rounds.** Bypassed:
  ten of ten rounds, BOTH nodes answered *Your account is ready* with two
  different passwords. Fixed: ten of ten, exactly one did.

Not run against two nodes: the TOTP, recovery-code and WebAuthn doors, the
reset link, ACME, SCEP and the SPIFFE join token — in process only.

## Several nodes: one rate-limit budget, who a request came from, and the connections (2026-09-14, #46)

Issue #46 sections 2 and 8. The capability row `security.rate-limits` is
provided by `websecurity.js` at require time. What a maintainer needs:

### The limiter counts in the store every node shares

* **Every production door calls `attemptShared()`, `blockedShared()` and
  `succeededShared()`** — the sign-in screen, the password grant, the four
  second-factor steps, the portal's activation, reset and password forms, the
  signing-key and enrollment self-service, client-secret failures at the token,
  PAR and introspection endpoints, the ACME/EST/SCEP throttles
  (`cert_enrollment.js`'s `throttledShared()`), GNAP's user code, `POST
  /xacml/pip` and the LDAP bind. Same buckets, window, limits, refusals and
  codes as the synchronous three, which stay for the tests that drive them.
* **On a shared store (postgres) the count is a row of
  `sts_cluster_windows`**, one conditional upsert per bucket that resets a
  passed window and increments a live one, returning the count THIS attempt
  made (`cluster/cluster_counters.js`'s `countInWindow()`). The replicated
  bucket row was last writer wins on a counter — two nodes each read 3 and each
  wrote 4 — and each node refused on its own view, so N nodes were N budgets.
  **Without a shared store they ARE the synchronous functions.**
* **A store that cannot be asked falls back to this process's buckets**,
  logged `STS-CLUSTER-0023` — deliberately unlike a claim, which refuses: a
  limiter that cannot reach the shared count still has one, and refusing every
  sign-in while the database is unreachable is an outage nobody caused.
* **`blockedShared()` then a counted failure was not atomic**, exactly as on one
  node: concurrent attempts all read the count first (the 19–34 of 40 below). A
  door that counts before it checks (`attemptShared()`) is refused at exactly
  the limit under any concurrency.
* **Since 2026-09-14 the doors that verify first decide the ANSWER on the
  atomic count** — client secrets at the token, PAR and introspection endpoints
  (`countSecretFailure()` / `settleSecretSuccess()` in `oauth2.js`), the LDAP
  bind, and the EST, ACME and SCEP refusal writers
  (`cert_enrollment.js`'s `countFailureShared()`, where `sharesThrottle()`).
  A failure is counted with `failedShared()` and awaited, and one whose
  increment took a bucket past the limit is answered with the lockout rather
  than "wrong" — at most `limit` failures per window are answered as failures,
  on every node together. A verified credential is answered only while the
  bucket is under the limit (`succeededShared({ unlessBlocked })`), so a right
  guess racing a spent budget teaches nothing. **They do not reserve at
  admission** (count every attempt before verifying) because that counts
  successes still in flight: six concurrent token requests from one client
  host, or a connection pool binding fifty connections as one DN, would be
  refused for being busy — the reason `blocked()` exists. What remains is a
  right guess that completes before the burst's failures have counted, the
  race a before-verification lockout had too. The enrollment doors do not
  re-check a success (a success there clears nothing). With no shared store
  every one of these is the synchronous path it was.
  `tests/cluster_followups.js` section H: forty concurrent failures, limit 5 —
  exactly 5 answered as failures; the control (a count read and written back)
  answers 40.
  **Measured live** (two active-active product nodes, `rateLimitPerIdentity=10`,
  40 concurrent wrong client secrets at `/oauth2/token` alternating nodes, three
  runs): answered `invalid_client` 10, 10, 10 — the control build 27, 37, 39;
  and 30 concurrent RIGHT secrets from one address, 30 of 30 answered 200.
* Where a handler was synchronous it became `async` (`authn.js`'s sign-in,
  TOTP and recovery-code POSTs, the portal's `GET` activation and reset and
  `POST /portal/password`, `POST /xacml/pip`); ACME's `gateRefused()` and EST's
  `refusedBeforeBody()` return promises; the LDAP bind handler finishes in
  `finishBind()` once the limiter has answered.
* `tests/cluster_limits_challenges_retention.js` section A: forty concurrent
  guesses at one person over twenty addresses are allowed exactly the limit
  against a store with postgres's semantics, and more than the limit against
  the control (a read-and-write-back row).
* **Measured on two live active-active nodes** (product mode, two request
  workers each, `security.rateLimitPerIdentity=10`, a private postgres), three
  runs each. The control ran the same build with `--require` making
  `sharesWindows()` answer false — the journalled buckets as they were:

  | Probe | shared windows | control |
  |---|---|---|
  | 40 concurrent password-grant guesses at one person, alternating nodes — answered `Authentication failed` rather than refused | 10, 10, 10 | 29, 20, 21 |
  | 30 sequential wrong client secrets, alternating nodes — answered before the first 429 | 10, 10, 10 | 10, 10, 10 |
  | after a burst of 40 wrong secrets, the next one on each node | 429 on both, 3 of 3 | 429 on both in 2 of 3 |

  The sequential row is the same both ways because the read barrier already
  carried the journalled count to the other node between two sequential
  requests; the password row is the race the store fixes. A burst of wrong
  client secrets was still let through — 19 to 34 of 40 with shared windows, 29
  to 40 in the control — because that door read (`blockedShared()`) before it
  counted; the whole burst was counted, so the next attempt on either node was
  refused. That door now answers on the count (the bullet above).

### `client_address.js`: which hops may say where a request came from

* **`global.trustProxy` alone believed a forwarded header from ANYBODY** who
  could reach a node — on the container network, past the load balancer — so a
  direct caller picked a fresh rate-limit address per guess and picked what
  `baseUrlOf()` believed this service's URL was. And the limiter read the
  LEFT-MOST `X-Forwarded-For` entry, which the client writes.
* **In the request-worker pool every caller was ONE address bucket**:
  `addressOf()` read the socket when the setting was off, and a worker's socket
  is a unix socket whose `remoteAddress` is `undefined` — `unknown` for
  everybody (measured). The front process wrote `X-Forwarded-For` from
  `req.ip`, which behind a balancer is the balancer.
* **`global.trustedProxies`** (CIDRs, empty by default = the old rule exactly):
  set, forwarded headers are believed only from a peer in a range, and the
  client is the right-most `X-Forwarded-For` hop not in one. The front process
  writes ONE resolved address and drops a forwarded host its peer may not send;
  a worker believes it because only the front process reaches its socket.
  `helpers.forwardedFrom()` asks the same question for the base URL.
* **Mutual TLS needs L4 passthrough.** No forwarded client-certificate header is
  read in any mode and none will be (a forwarded certificate is a certificate
  anybody can forge). A balancer that TERMINATES TLS on 8443, 9443, the main
  port when `global.https` is on, or the SPIRE Server API disables RFC 8705
  `tls_client_auth` and certificate-bound tokens, certificate sign-in, the XACML
  certificate gates and SPIRE's SVID authentication. Pass those listeners
  through at L4 (TCP) and terminate TLS on the node. Behind an L4 balancer the
  peer address is the balancer's unless it sends the PROXY protocol — see the
  next section, which puts the client's address on the socket so this file
  never sees the balancer as a hop.

### `proxy_protocol.js`: the client's address from below TLS (2026-09-14, #46)

`global.proxyProtocol` (`off` | `v2`, restart-only) reads a HAProxy PROXY
protocol v2 header off every TCP listener this service owns — the main port,
8443/9443, LDAP 389/636, the KDC's TCP listener, the debugger and the plain PKI
listener — for an AWS Network Load Balancer with TLS passthrough and
`proxy_protocol_v2.enabled`. The file's header argues every point; the ones a
maintainer of a listener has to know:

* **One list, `global.trustedProxies`**, not a second: the same question one
  layer down. `client_address.isTrustedProxy()` answers it and, unlike
  `peerIsTrustedProxy()`, an EMPTY list trusts nobody — so v2 with no usable
  range stops the service (`STS-PROXY-0009`, in `server.js` after the store
  restored any runtime override).
* **Three kinds of peer.** Trusted: a valid header is REQUIRED (LOCAL and
  PROXY/UNSPEC — health checks, verified in AWS's documentation — keep the
  socket's address). Untrusted: CLOSED, not served plain. This host (loopback,
  or peer = local address): served PLAIN, because `oidc_rp.js`'s back channel,
  the SSF push and every request worker dial the main port on
  `helpers.loopbackHost()` with no header; a same-host peer that is also
  trusted (a sidecar) may send one or not, told apart by the signature's first
  byte.
* **The address is put on the SOCKET, not in a field.** The TCP handle gets an
  own `getpeername()` and the socket's `_peername` is replaced, so express's
  `req.ip`, `clientAddressOf()`, the request pool's `X-Forwarded-For`, ldapjs's
  connection id, the LDAP bind limiter, the KDC and `/tls/whoami` read the
  client with no change. The HANDLE because a `TLSSocket` asks its TLSWrap,
  which proxies `getpeername` to the TCP handle — shadowing the JS socket's
  getter would miss every TLS reader (measured).
* **`install(server)` shadows `server.emit('connection')`** instead of putting a
  second `net.Server` in front, so `listen()`, `address()`,
  `setSecureContext()` and the truststore registration are untouched. Bytes
  that arrived with the header are unshifted onto the paused socket; a
  `tls.Server` drains them into the TLS engine, every other server needs the
  socket RESUMED after the real emit — without that `http.Server` answered 408
  (measured).
* **A refusal is one audit row per (code, address) per minute**, the rest
  counted in `report()`: the connections refused here are the ones a stranger
  can open as fast as they like, and the audit ring is capped.
* **Not covered**: the KDC's UDP socket (no stream), and the SPIFFE gRPC
  listeners (grpc-js owns its server). `tests/proxy_protocol.js` holds the
  parser, the three peers and the round trips through http, https with a
  client certificate, net and ldapjs.

### Database connections per container

Each process that opens the store holds a `pg` pool of `max: 4`
(`persistence_postgres.js`) plus ONE dedicated connection for `LISTEN`. A
container is its front process, `workers.requestCount` request workers and
`workers.surfaceCount` surface workers — with `docker-compose.yml`'s defaults
(3 and 2) six processes, so **up to 30 connections per container**. Against
PostgreSQL's default `max_connections=100` (less `superuser_reserved_connections`
and whatever else connects) the fourth container's `persistence.start()` fails,
and that failure is FATAL by design. Size `max_connections` to
`containers × processes × 5` plus headroom, or lower the worker counts.
**PgBouncer in transaction mode breaks `LISTEN`** — a notification is
delivered to a session, and transaction pooling hands the session to somebody
else — so either give the listener a direct connection or session mode; the
poll (`persistence.pollInterval`) still converges without it, at up to that
interval's latency. Every commit NOTIFYs every process of every container.

