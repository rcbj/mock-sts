# iya-sts

An **identity provider and security token service** that speaks seventeen protocol
families. Four of them (Kerberos, LDAP, TLS and SPIFFE) do not run as HTTP on its
main listener at all. The others include OAuth 2.0 and OpenID Connect, SAML,
WS-Trust, WS-Federation, SCIM, OpenID4VC, Shared Signals, XACML and GNAP. The
service also has a certificate authority of its own. *What it speaks*, below,
has the full list.

## Where it started, and where it is going

**It started life as part of a test suite.** It was the mock STS inside the
[OAuth2/OIDC Debugger](https://idptools.com) project, the identity service that
project's tests drove clients against. That job needed a complete, protocol-correct
exchange (real tokens, assertions, tickets and credentials) without standing up a
real identity provider. So the service was deliberately permissive: it authenticated
nobody, checked no passwords and validated no access tokens. *Authentication was
intentionally fake; protocol behaviour was not.* It was later extracted into a
repository of its own, and was called `mock-sts` until 2026-09-15.

**It is now on a journey to becoming a real identity provider.** The permissive
service has not gone away. It has become one of two modes, set by `global.mode`
for each trust realm, so a single process can serve both:

* **`development`**, the default, is the mock this project started as. Any username
  typed at the sign-in screen becomes the identity. Anything named is created.
  Signing keys are regenerated on every start. Test controls are open. In Kerberos,
  where the password *is* the encryption key, every account shares `password!`.
  Use this mode to test whether an application correctly speaks OAuth, OIDC, SAML,
  WS-Federation, WS-Trust, WebAuthn, DPoP, OpenID4VC or any other protocol here.
  **Never use it to protect anything.**
* **`product`** runs the same protocol implementations with the permissiveness taken
  out:
  * a presented password is verified against the hashed password on the person's
    own directory entry;
  * a response goes only to an address somebody registered;
  * there is no demonstration data and no invented claim value;
  * signing keys and the certificate authority persist, sealed under a
    key-encryption key the service never generates itself;
  * several containers can serve one PostgreSQL store.

**The journey is not finished.** Much of what is described below was built for
development mode first. Where product mode behaves differently, the setting or
section says so. Read those notes before you deploy a feature, and do not assume
that a feature which works in development has been hardened for product.

The documentation below comes from the engineering notes of the project it came
from, so it explains *why* things are the way they are. Most of it is the record of
something having gone wrong once.

## Where the code is

Since 2026-08-23 the modules live in directories by protocol family rather than in
the package root. **The files did not change; the paths did.**

| Directory | |
|---|---|
| `common/` | config, helpers, the express app, the counters, the audit log, the application registry, the claim catalogues, the delegated permission register and the **consent** register |
| `common/vendored/` | byte-identical copies of the parent project's PKI and JSON-LD modules, plus the `contexts/` they read. **Do not edit them here.** |
| `oauth-oidc/` | the authorization server, RFC 9700 mode, DPoP, mTLS, client authentication, the multi-AS profiles, and the **consent screen** at `/oauth2/consent` |
| `authn/` | the sign-in screen and the WebAuthn relying party. Owns the session |
| `saml/` | the two assertion builders |
| `ws-trust/` · `ws-federation/` | the two WS-\* profiles |
| `federation/` | **federation relationships** — the register, the attribute mapping, the four endpoints, and the only outbound request this service makes |
| `kerberos/` | the KDC, the acceptor, SPNEGO in three layers — the negotiation, the page that explains it, and the sign-in that turns a ticket into a session — and the codec |
| `ldap/` · `scim/` · `tls/` · `spiffe/` · `oid4vc/` | one family each |
| `acme/`, `est/`, `scep/` | **CERTIFICATE ENROLLMENT** — ACME (RFC 8555), EST (RFC 7030) and SCEP (RFC 8894), each with its console pages under Protocols and Monitoring and its `/admin-api` operations, all issuing through `common/cert_enrollment.js` |
| `gnap/` | **GNAP** — the grant engine, the resource-owner pages, RFC 9421 HTTP message signatures, the five token formats, the RS-facing endpoints and the two console pages |
| `persistence/` | **the only place this service writes anything down** — three modes (`memory`, `ldif`, `postgres`) behind one driver interface, and the RFC 2849 codec under the middle one |
| `admin-ui/` · `mgmt-api/` | the console and the management API |
| `admin-core/` | **what those two both DO, with neither of them in it** — the thirty-one actions behind every control on `/admin` and every `/admin-api` operation that changes something. They were in `admin-ui/admin.js` until 2026-09-12, which made the API depend on the console |
| `home/` | the front door — `GET /`, and the one image this service serves |
| `logout/` | the protocol-independent sign-out — one model of what a live session IS across every family, and the endpoint that ends it |
| `tests/` | **the only test directory in this repository** — in-process assertions about its own module contracts, `npm test`, no port and no container. Every test that drives this service over HTTP lives in the [OAuth2/OIDC Debugger](https://idptools.com) project's suite, federation included |
| `docs/` | the user-facing documentation, published as a GitHub Pages site |

At the package root there are exactly two modules: **`server.js`**, the shell that
requires the others and listens, and **`sts_metadata.js`**, which reads the router
to list what everything else registered and is therefore required last. `logout/logout.js`
is required immediately before it, second to last, because it reads nine of the
modules above and must come after every one of them.

Every directory carries a `CLAUDE.md` with the reasoning for the modules in it —
that is where the engineering notes below have been distributed to. `CLAUDE.md` at
the root keeps only what is cross-cutting: the require order, the library and hook
rules, the two CSP rules, the code style and the state of the tests.

**One consequence for the parent project**, which reaches in here by path in its
`tests/Dockerfile` and `tests/module_paths.js`: those paths were broken by the
move and were repaired over there on 2026-08-28, with the `sts/` gitlink bumped
past the reorganisation. What remains is a standing obligation rather than a
migration — that Dockerfile copies the transitive closure of what the in-process
Kerberos jobs require, so a new `require()` here can oblige it to add a line. It
is written down in
[`docs/parent-project-migration.md`](docs/parent-project-migration.md).

## What it speaks

| | |
|---|---|
| **Kerberos v5 (RFC 4120)** | a KDC, on **raw TCP and UDP port 88** and over MS-KKDCP: the AS and TGS exchanges, pre-authentication carrying the salt in PA-ETYPE-INFO2, a signed [MS-PAC] in every ticket, two realms with a trust between them so cross-realm referrals work, and delegation all four ways ([MS-SFU] S4U2Self, S4U2Proxy under either authorization, forwarded tickets, renewals) — plus a **service** that decrypts an RFC 4121 GSS token, checks the ticket eight ways and proves itself back |
| **SPNEGO (RFC 4178) over HTTP (RFC 4559)** | a **protected web page**: `/spnego` advertises it — the SPN, the realm, the mechanisms, the hosts it will answer for (`acceptsAnySpnForHosts`) and three knobs that break the negotiation one way each — and the 401 itself carries `X-Krb5-Service-Principal` and `X-Krb5-Accepts-Spn-Hosts`, which are nobody's standard and exist because SPNEGO carries no SPN at all: a client has to guess `HTTP/<url host>`, and that guess being wrong is the commonest SPNEGO failure there is — and `/spnego/protected` answers `401 WWW-Authenticate: Negotiate` to an unauthenticated request and `200` with an AP-REP in that header to a valid one. NegTokenInit with the optimistic mechToken, NegTokenResp in all four negStates, and the mechListMIC in both directions with section 5's rule for when it is mandatory. Only Kerberos is offered: NTLM is recognised in a client's list and never selected, because advertising a mechanism this service cannot perform would be a lie a client would act on. **Every Kerberos check is the protected service's, unchanged** — this is a transport and a negotiation, and no protocol code of its own. **And since 2026-08-26 the same handshake is also a SIGN-IN**: `/authn/spnego` verifies the ticket through the same acceptor and mints the browser session every protocol family here reads, so a person holding a Kerberos credential completes an OAuth authorization request, a `wsignin1.0`, a SAML `AuthnRequest` or the admin console without typing anything. It is available to every application and registered for none — a button on the sign-in screen, `appAuthnMechanism: spnego` on an application entry, or `fedAuthnMechanism: spnego` on a federation relationship. **It is the one sign-in in this service that rests on a credential the service genuinely verified**; what the session then claims is read off the ticket's own flags (`pre-authent` → `amr ["pwd"]`, `hw-authent` → `["hwk"]`, neither → nothing at all, because this service will not name a factor no credential evidenced) |
| **WS-Trust 1.0–1.4** | Issue / Renew / Validate / Cancel, WS-Security, WS-Addressing, optional XML-DSIG and XML-Enc. **In product mode** (2026-09-12) every operation requires a credential — a UsernameToken verified against the directory, or a SAML assertion this STS signed that is inside its Conditions — an `OnBehalfOf`/`ActAs` requires the requester's own credential and an assertion this STS signed inside it, and `?encrypt=1` that cannot encrypt is a Fault rather than plaintext. In both modes a requested `wst:Lifetime` is clamped to `wstrust.maxTokenLifetimeMin`, the JWT carries a `jti` and a `kid`, the assertion's AuthnContext names the credential (`PreviousSession` for an assertion, `unspecified` for none or a delegation) rather than a password, and a delegation starts no session for the subject |
| **SAML 2.0 and SAML 1.1** | signed assertions of both vintages, the metadata a relying party needs, and **a browser-facing identity provider for each** — SAML 2.0's Web Browser SSO profile over all three bindings with Single Logout, and SAML 1.1's Browser/POST and Browser/Artifact profiles with a SOAP responder that is also an attribute authority. They are separate implementations: SAML 1.1 has no request message and no Single Logout. 1.1 is also what a WS-Federation relying party expects by default |
| **SAML 2.0 Web Browser SSO** | a full identity provider at `/saml2`: the Single Sign-On service over **HTTP Redirect** and **HTTP POST**, and the Response over **HTTP POST, HTTP Redirect or HTTP Artifact** — the third with a **SOAP Artifact Resolution Service** behind it, where the assertion never passes through the browser at all and an artifact resolves **exactly once**. Plus **Single Logout** in both directions, and **signed metadata PER SERVICE PROVIDER**: `/saml2/metadata/{sp}` names an identity provider of its own with its own endpoints, the way Okta and Ping do, and **it is minted for any entityID asked for** — nothing has to be provisioned before a service provider can be pointed here, and the first valid AuthnRequest creates its application entry. It accepts every entityID and verifies no request signature (both are recorded); `NameIDPolicy`, `ForceAuthn`, `IsPassive` (answered with `NoPassive`, not a screen) and `RequestedAuthnContext` are all honoured, and a `ProtocolBinding` it does not implement is refused **by name**. It has no sign-in screen of its own — see below for the SameSite hop that makes that possible — and a mock service provider at `/saml2/sp` verifies a response check by check |
| **WS-Federation 1.2** | the Web (Passive) Requestor Profile of section 13 — `wsignin1.0` with `wtrealm`, `wreply`, `wctx`, `wct`, `wfresh`, `wauth`, `whr` and `wreq`, the response as a **form POST**, `wsignout1.0` with front-channel cleanup, signed federation metadata at AD FS's path, and a mock relying party that verifies the response check by check |
| **Federation, in five of those protocols** | this service as **either end** of a relationship with a foreign identity service — SAML 2.0, SAML 1.1, WS-Federation 1.2, OpenID Connect and OAuth 2.0. As a **service provider** it sends the request, consumes what comes back at `/federation/acs/{id}`, **verifies it against a certificate configured on that relationship**, maps the attributes onto an entry under `ou=users` and starts a session — the SAME session every other protocol here reads, which is what lets a federated identity satisfy an OAuth 2.0 authorization request, a WS-Federation `wsignin1.0` or a SAML `AuthnRequest` without any of those knowing federation exists. `/authn/login` grows a button per usable partner for exactly that reason. As an **identity provider** it marks a partner as a federation partner rather than a test client and decides **which attributes are released to it**. **It is the one feature here that has to be configured before it will do anything, and the one that refuses by default** — see *Federation* below, where that inversion is argued rather than assumed: "accept any SAML Response" is not a permissive mock, it is an authentication bypass for every protocol in the process. It is also the only thing here that makes an **outbound** request, and `jwks_uri` on an application entry and WS-Federation's `wreqptr` are still never followed — the difference is a URL an administrator configured against a URL a caller supplied |
| **OAuth 2.0** | a full authorization server: RFC 8414 metadata plus every endpoint it advertises — authorize (which redirects to the authentication service when nobody is signed in), token, userinfo, introspect, revoke, register (RFC 7591 with software statements — verified against this realm's key or a declared publisher's, and issued from the console — and the RFC 7592 read/update/delete operations), jwks. Introspection answers as RFC 7662 JSON or, when asked, as an **RFC 9701 JWT** signed and optionally encrypted for the resource server that asked. Authorization requests may be **JWT-secured (RFC 9101)** — a signed, optionally encrypted request object by value or from a `request_uri` the client registered — or **pushed first (RFC 9126)** to `/oauth2/par`, authenticated as at the token endpoint, for a one-time `request_uri`. PKCE (RFC 7636), **Rich Authorization Requests (RFC 9396)** — `authorization_details` of every type a resource application declares, with JSON Schemas, consent drawn per detail and the token addressed to that resource — the `iss` authorization response parameter (RFC 9207), and every one of the seven grant types its metadata advertises — including **Token Exchange (RFC 8693)**. It is permissive by design, and it can be told not to be: `oauth2.rfc9700` puts the authorization flow into **RFC 9700** mode — exact-string redirect URI matching with RFC 8252's loopback port exception, no open redirector at either redirecting endpoint, PKCE required of public clients with S256 only, the PKCE downgrade and value reuse refused, and no response type that issues an access token from the authorization endpoint, refresh token rotation with replay detection that revokes the whole chain, no password grant, no CORS at the authorization endpoint, and the one client credential this service checks — and it turns port 8081 itself into an **HTTPS** listener, on the certificate 8443, 9443 and LDAPS 636 already share, so the issuer and every endpoint in every metadata document follow. Off by default; `GET /oauth2/rfc9700` says what it does and does not enforce |
| **Consent, at `/oauth2/consent`** | **The one policy in this service that is ON by default.** The first time a given username signs in to a given `client_id` for a given scope, a screen lists the scopes that are new and nothing is issued until they answer; Allow writes one `oauthConsent` value per scope onto that person's own entry under `ou=users`, so the second sign-in is silent and an `ldapsearch` can read what somebody agreed to, and Deny returns `access_denied` to the client and records nothing at all. A delegated permission is recorded by its **whole identifier** and never by the bare permission name, because two resources may each expose a `read`. `oauthGlobalConsent` on an APPLICATION's entry consents a scope for everybody who signs in to it and **writes nothing about anybody** — an override rather than a record, so removing it asks everybody again, including the people who would have said yes. `prompt=consent` asks again and takes nothing away; `prompt=none` with something outstanding is `consent_required`. It carries no script, so the service-wide `script-src 'none'` is untouched. Off with `oauth2.consentRequired`, and OFF means nothing asked and nothing recorded rather than everybody consented |
| **OpenID Connect 1.0** | `id_token` with `nonce`, `at_hash` and `c_hash` across all three flows, the section 5.3 UserInfo endpoint, **Discovery 1.0** at all three URLs a client may look at, RP-Initiated Logout, and **Front-Channel Logout 1.0** — the provider's side of it: the two discovery members, the two per-client registration members, the `sid` claim on an ID Token issued on a browser session, and a hidden iframe per registered `frontchannel_logout_uri` on every sign-out. Back-channel logout is a different specification and is not implemented; the metadata says so |
| **A protocol-independent sign-out** | `GET /logout` lists **everything this service is still holding for one identity across every family** — sessions, relying parties, realms, service providers, revocable tokens, outstanding authorization and pre-authorized codes, directory connections bound as them, and the Kerberos ticket position — with a checkbox against each, and a POST that ticks nothing ends all of it. Two of those mechanisms are new: a **Kerberos sign-out instant**, after which a `TGS-REQ` carrying an older ticket is refused KDC_ERR_TGT_REVOKED (20), and closing the **LDAP connections** bound as that person, which is the only sign-out RFC 4511 has. **What cannot be ended is listed anyway, with the reason** — an assertion, a service ticket or an SVID already issued is beyond recall because nothing consults this service when one is presented, and hiding those would make a global logout look complete when it is not |
| **WebAuthn Level 3** | the relying party's half, on the login screen, in **both roles**: a second factor after the password, or the **primary credential** with no password at all. Registration and assertion are verified either way, and `amr` / `acr` in the tokens that follow say which happened — `["pwd","hwk"]`/`mfa` for two factors, `["hwk"]`/`1` for a passwordless sign-in, which is one factor however phishing-resistant it is |
| **TOTP (RFC 6238 over RFC 4226)** | the **other second factor** on that same login screen, and the only credential this service verifies besides a Kerberos ticket. A person enrols an authenticator app from `/portal/mfa` or while spending an activation link: a **QR code this server rendered** (an SVG data: URI — every page of the portal is `script-src 'none'`) and the same secret in base32 beside it, because the phone is often the browser showing the page. **Two steps, and the first writes nothing**: an unconfirmed secret on somebody's entry would be a second factor they cannot produce. Once enrolled, **a password alone stops signing them in** — the sign-in screen asks for a code without being told to — and the session says `amr ["pwd","otp"]` / `acr mfa`, `otp` being RFC 8176's value for exactly this. **Codes are checked FOR REAL in both modes**: all three digests, a settable step and digit count, a symmetric skew window, and section 5.2's accept-once rule enforced against the step last accepted, so the code that set the app up cannot also sign anybody in. It can never be a first factor — this service holds the same shared secret the app does — and there is no self-service reset, because one anybody can use is no second factor: an operator's Clear on that person's row under `/admin/users` is the way back for a lost phone |
| **Recovery codes** | the **way back in when neither of those is to hand** — the phone is lost or flat, the security key is at home — and **the one mechanism here that no specification defines**. **Since 2026-09-11 a person GENERATES their own set** from `/portal/mfa`: the codes are shown once, on the page that made them, and **nothing is stored until they confirm they have saved them** — at which point what is stored is a **scrypt hash of each code**, so this service can check one and can never show one again. Generating a set REPLACES any set they hold, and the page says so before it generates anything. Enrolling a second factor issues nothing and instead leaves a standing prompt to generate one. (It used to be the other way round — issued automatically and ONCE by the act of enrolling, and stored encrypted so the person could read their remaining codes back. Hashing is what made that impossible: a hash can only be made while the code is in the clear.) The sign-in screen never ASKS for one — it asks for whichever factor the account is configured for and offers `/authn/backup-code` as a link beside it |
| **DPoP (RFC 9449)** | all twelve section 4.3 proof checks, `cnf.jkt` on access *and* refresh tokens, `dpop_jkt`, replay detection, the nonce handshake |
| **mTLS client authentication (RFC 8705 §2)** | `tls_client_auth` authenticates a client by a certificate **whose chain verified** against the client truststore, mapped to the client **implicitly** — a TLS client certificate this realm issued to that application (`urn:sts:application:<id>`, issued from its Credentials section or enrolled over ACME/EST/SCEP, and still listed on its record) needs nothing registered — or **explicitly**, by exactly one of the five registration parameters `tls_client_auth_subject_dn` (compared as a name, not a string), `_san_dns`, `_san_uri`, `_san_ip` or `_san_email`. `self_signed_tls_client_auth` matches the `x5c` of a key in the client's `jwks` (§2.2.2) or a registered thumbprint. A client that declares either method is held to it **in every mode**. See *Mutual TLS (RFC 8705)* below |
| **JWT assertions (RFC 7521, RFC 7523)** | **BOTH halves of the profile, since 2026-09-10.** Section 2.2 is *client authentication*: `client_assertion` in place of a secret, verified against the JWKS the client registered, against a JWKS **this service issued it** from its own certificate authority, or against an `x5c` chain that builds a path to this realm's Root CA. Section 2.1 is the *authorization grant*: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer` with an `assertion` naming somebody, and a token comes back **for that person** — no browser, no password and no consent step anywhere in it. **Every optional component is implemented**: `nbf`, `iat` (which also bounds the lifetime, `oauth2.jwtBearerMaxLifetimeS`), `jti` against a replay cache, other claims carried onto the issued token, the requested `scope` narrowed against what the assertion permits and never widened, `aud` as an array, `client_id` omitted where the assertion identifies the party, a `cnf` recorded and not enforced — and **claim 10, an ENCRYPTED assertion**: a nested JWT in any of sixteen key management algorithms against six content encryption ones, to this service's own RSA or EC key, or under the client secret. Every JWS algorithm this service verifies is accepted, the eleven post-quantum ones included. **The one thing that is not permissive** is the assertion ISSUER: it must be declared on an application entry as `oauthAssertionIssuer`, because the signature is the whole of that grant's security, and "accept any signed assertion" means anybody who can reach this port getting a token as anybody. That refusal and federation's are the only two here that default to ON. **And since 2026-09-11 a PERSON may be the issuer too** — a signing key pair issued onto their own `ou=users` entry as `stsAssertion*`, signing an assertion about themselves, which is §3 read literally (claim 2 says the `sub` of an authorization grant typically identifies a resource owner). It comes with the one rule the feature needs: **a person's assertion may only be about themselves**, `iss` and `sub` naming the same person, on the registered key and on a certificate presented in `x5c` alike — a key issued to one resource owner is that person's credential rather than permission to speak for the others, and a party that may assert about OTHER people is an application with the issuer declared on it |
| **SAML 2.0 assertions (RFC 7521, RFC 7522)** | **BOTH halves of the other profile of that framework, since 2026-09-11, and it is a SEPARATE IMPLEMENTATION rather than the JWT one with a format flag** — the same decision `/saml2` and `/saml11` rest on, for the same reason: a JWT is three base64url parts and a claim set, and this is an XML document with an enveloped XML Signature, a `<Conditions>` element and a `Recipient` attribute that has no JWT equivalent at all. Section 2.1 is the *authorization grant*, `grant_type=urn:ietf:params:oauth:grant-type:saml2-bearer` with a base64url `<saml:Assertion>`; section 2.2 is *client authentication*, `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:saml2-bearer` — whose `token_endpoint_auth_method` here is `saml2_bearer`, **this service's own name, because that RFC registers none**, published in `token_endpoint_auth_methods_supported` so a client discovers it rather than reading it in a document. **All eleven items of section 3 are checked**, including the three most implementations get wrong: an expired `<SubjectConfirmation>` is *discarded* and the others still considered rather than making the assertion invalid (item 6's own distinction); an expiry on *either* `NotOnOrAfter` satisfies item 4; and an unrecognised `<Condition>` makes the assertion **Invalid** per SAML core §2.5.1 rather than being ignored (item 11). A whole `<EncryptedAssertion>` and an `<EncryptedID>` are decrypted with this realm's own key (item 10). **TWO things are not permissive**: the `<Issuer>` must be declared on an application entry as `oauthSamlAssertionIssuer`, for the reason RFC 7523's must be — *and* the assertion is verified **only** against a certificate registered against that party under the RFC 7522 attributes. A certificate in `<ds:KeyInfo>` that merely chains to this realm's Root is **not** accepted, which is the one place this service is stricter here than for RFC 7523: a chain proves the *realm* issued a key and says nothing about *which application* holds it, so accepting one would let an application's own RFC 7523 leaf sign a SAML assertion. **The two profiles hold separate key pairs per application**, in two attribute sets no verifier crosses |
| **A certificate authority, at `/admin/pki`** | **The only surface here that issues an X.509 certificate to something that is not this service.** A **Root CA, an Intermediate CA and an Issuing CA per trust realm** — all three built in one act or none, because a half-built hierarchy is exactly the state in which somebody issues a certificate that verifies here and nowhere else — and a **signing key pair issued from the bottom of it to an application — or, since 2026-09-11, to a PERSON** (`target=person`, written onto their `ou=users` entry as `stsAssertion*`, and their private key handed over once because nothing here opens it again) — which is what makes the two RFCs above usable without an operator moving key material by hand. The key pair goes onto that application's own directory entry: the private key under `oauthAssertionPrivateKey`, **sealed at rest under the same key-encryption key as the hierarchy it came from** wherever that key outlives the process (in the clear in development mode, where it would not survive the restart the entry does), the public half as a JWKS carrying `x5c` and `x5t#S256`, and **this service keeps no second copy** — it is handed over once, at issuance. The encoder is the debugger's own PKI code, vendored byte-identical, so a certificate issued here and one issued on that project's *PKI / X.509* page are built by ONE encoder. **Two things it does not do, both said on the page**: nothing is ever *revoked* — no CRL, no OCSP, so taking a key pair off an application stops this service ACCEPTING what it signs and does not stop the certificate chaining — and in development mode the hierarchy lives exactly as long as the process, which is the rule the signing key already follows |
| **mTLS-bound tokens (RFC 8705)** | the *other* sender constraint RFC 9700 names: with `global.https` on, the main listener asks for a client certificate and a Token Request made with one is answered with `cnf["x5t#S256"]` — the SHA-256 of its DER — on the access **and** refresh tokens, which the protected endpoints — UserInfo, the credential endpoints, SCIM, SSF, `/admin-api` and the embedded debugger — then check against the certificate the connection was made with, and introspection reports as `cnf` (§3.2). A client that registers `tls_client_certificate_bound_access_tokens: true` is refused a token without a certificate, in every mode (§3.4). A refresh by a client that authenticated by certificate may present a NEW certificate (§7.1, §6.3). Advertised only where it can actually be done |
| **Resource Indicators (RFC 8707)** | `resource` at the authorization endpoint and on **every** grant at the token endpoint becomes the access token's `aud`, so a token can be restricted to one resource server or a small set of them — repeat the parameter for a set — and the resource server here refuses one issued for a different audience |
| **OpenID4VCI 1.0** | a Credential Issuer: SD-JWT VC (RFC 9901), `jwt_vc_json`, `ldp_vc` with bbs-2023; Credential Offers, the pre-authorized code grant with `tx_code`, `authorization_details` (including its `claims` member, so a wallet can ask for a subset of the claims), batch issuance, response encryption, deferred issuance, the Notification Endpoint |
| **OpenID4VP 1.0** | a Verifier with DCQL that **actually verifies** what it is sent, check by check |
| **W3C DID Core 1.0** | its own `did:web` document, and the DIF Well Known DID Configuration that links it to its origin |
| **TLS / mutual TLS (RFC 8446)** | two **HTTPS listeners of its own** — 8443 asks for a client certificate and never refuses one, 9443 *requires* it — whose entire content is what the **server** saw: the request as it arrived, what TLS negotiated underneath it, and the client certificate exactly as presented, chain and all. It is the half of a handshake a client cannot report. It already knows what it sent; what it cannot know is which chain the server built out of that, which anchor it verified against, or whether the certificate was accepted at all — which, under TLS 1.3, it has not learned by the time its own handshake completes. The client truststore starts **empty** and is filled at runtime through `POST /tls/trust`, because the CA it has to verify is usually generated in a *browser* minutes before the connection and exists nowhere a file could hold it. `GET /tls` describes it; `GET /tls/whoami` over either listener is the report |
| **SPIFFE, and the SPIRE Server API** | a **SPIFFE issuing authority** for one trust domain PER TRUST REALM (2026-09-12 — a realm is created with `<realm>.<the service's>` and with SPIFFE off; turning it on binds a Workload API and a SPIRE Server API of its own, on an address of its own, because gRPC's path is the method name and the endpoint is the only thing a client can name a tenant with), in all three of its server-side shapes. The **bundle endpoint** is plain HTTPS at `/spiffe/bundle` — a JWK Set with `spiffe_sequence` and `spiffe_refresh_hint`, every key carrying the `use` a consumer must have to consider it at all. The **Workload API** is the gRPC service `SpiffeWorkloadAPI` on a **Unix socket** (SPIRE's own `/tmp/spire-agent/public/api.sock`, which is what `SPIFFE_ENDPOINT_SOCKET` means to every real client) and on TCP: X509-SVIDs with their private keys and the trust bundle, JWT-SVIDs for an audience, both bundle streams, and a `ValidateJWTSVID` that really verifies. The streams are held open and re-sent at half the SVID lifetime, so a client's **rotation** path runs without anybody waiting an hour. The **SPIRE Server API** is six gRPC services and 42 methods from the vendored `spire-api-sdk` protos — Entry, Agent, Bundle, SVID, TrustDomain, Debug — of which 36 are implemented and the other six each answer with a reason. **Its TCP port is mutual TLS**: a caller presents an X509-SVID from this trust domain and every method is authorized against SPIRE's own per-method table, with the Unix socket trusted as `local` the way a real `spire-server` trusts its private one (`spiffe.trustLocalSocket`). **Nothing is attested** either way — a Workload API caller is identified only by its transport, the endpoint it reached and its peer address, because node cannot read a socket's peer credentials, and an agent's attestation payload is taken on trust. `GET /spiffe` is all of that at length |
| **LDAP v3 (RFC 4511)** | an embedded **directory on two raw sockets — TCP 389 in the clear and TCP 636 over TLS (LDAPS)**, one set of handlers and one store behind both: simple bind, unbind, add, delete, modify, modifyDN, compare and search with RFC 4515 filters and all three scopes, a root DSE, and result codes 0, 2, 4, 11, 16, 32, 49, 66 and 68 all reachable. Built on the [`ldapjs`](https://github.com/rcbj/node-ldapjs) submodule and used unmodified. It is **schemaless on purpose** and says so, it enforces the four structural rules whose absence would teach a client something false — plus one of its own, that an add under `ou=users` whose username is already there is `LDAP_ENTRY_ALREADY_EXISTS` (68), because one person is one entry however they got in — and it deliberately does not do referential integrity. `GET /admin/ldap/service` describes it and `GET /admin/ldap/directory` lists every entry. **`LDAP_AUTOCREATE_USERS`, on by default, grows an entry under `ou=users` for anybody who authenticates through any of the other twelve families** — and `ou=applications` grows one for the CLIENT, relying party, service provider or Kerberos service on the other side of that authentication, which is a **registry rather than a record**: the RFC 7591 registrations live there, nothing caches them, and an `ldapmodify` of `oauthRedirectUri` changes which redirect URI RFC 9700 mode accepts — one hook on the single funnel they all already pass |
| **Certificate enrollment: ACME (RFC 8555), EST (RFC 7030), SCEP (RFC 8894)** | three ways for a client, a device or a person to get a **certificate from this realm's own certificate authority** — each protocol has an Issuing CA of its own under the realm's Intermediate. **Who a certificate is for is one rule for all three**: yourself, or — for a holder of Admin Write — any person or application in the realm, and every certificate names that directory entry (`urn:sts:person:` / `urn:sts:application:`) and is kept on it. ACME at `/enroll/acme/directory` binds an account to an entry with an **External Account Binding** key; EST at `/.well-known/est` takes a directory password, a client secret or a certificate this realm issued, and can generate the key (`/serverkeygen`, the only path that keeps a private key, sealed, on the entry); SCEP at `/enroll/scep` takes a **single-use challenge password** issued for one entry and one profile. The nine leaf profiles of `/admin/pki` are issued; Root, Intermediate and Issuing CA, OCSP Responder and Kerberos KDC are refused. A DNS name or address is issued only when it is registered on the entry — nothing is ever dialled to prove control. A person makes their own EAB key and challenge on `/portal/certificates`. See [docs/acme.md](docs/acme.md), [docs/est.md](docs/est.md) and [docs/scep.md](docs/scep.md) |
| **GNAP (RFC 9635, RFC 9767)** | an **authorization server for the Grant Negotiation and Authorization Protocol**, per trust realm, at `/gnap`: grant requests with every access, subject, client and user member; all four interaction start modes (redirect, app, user code, user code URI) and both finish methods (redirect, push) with the interaction hash; continuation, modification and revocation; token rotation and **client key rotation**; all four key proofing methods — **RFC 9421 HTTP message signatures** with RFC 9530 Content-Digest, mutual TLS, detached and attached JWS; and the **five token formats RFC 9767 registers** — signed JWT, encrypted JWT, macaroon, biscuit and ZCAP-LD. The RS half is there too: discovery at `/.well-known/gnap-as-rs`, introspection, resource set registration and token derivation. Every request body is held to a JSON Schema, a GNAP client is an application entry with its shared keys sealed at rest, and a revoked grant or token is a CAEP `session-revoked` to a stream a GNAP web application owns — which hears only about people who approved it. See [docs/gnap.md](docs/gnap.md) |
| **Shared Signals (OpenID SSF 1.0)** | a **transmitter**, and the one family here that TALKS BACK: every other answers a request, and this one agrees a **stream** with a receiver and then delivers a **Security Event Token** (RFC 8417) at the moment something happens. The stream management API at `/ssf/stream` — one path, five methods — with the status, subject and verification endpoints beside it, every one of them DISCOVERED from `/.well-known/ssf-configuration` because SSF fixes no paths. Subjects in all eight **RFC 9493** formats plus SSF's **complex subject**, whose `user`/`device`/`session` members are what make *"this session was revoked"* expressible at all; each format's member set is CLOSED and a subject carrying an extra member is REFUSED BY NAME, because a conforming receiver must reject one and it looks perfectly fine in a log. Delivery by **RFC 8935 push** or **RFC 8936 poll**, and a **receiver of its own** at `/ssf/receive` so that a client can be the transmitter. **AND SINCE 2026-09-10 THIS SERVICE'S OWN ADMIN CONSOLE AND USER PORTAL ARE REGISTERED RECEIVERS**, each with a stream seeded per trust realm asking for every CAEP and every RISC event type, each taking delivery over a REAL RFC 8935 push at an endpoint of its own — this service dials itself, on the loopback interface, with its own certificate pinned — and each drawing what arrived at `/admin/signals` and `/portal/signals`. Handing the event to the page in process would have been a receiver that never parses a body, checks a media type, presents a credential or verifies a signature, so those two pages are the only surfaces here that go EMPTY when delivery is broken and therefore the only ones that can report that it is; the portal shows each person only the events whose subject is THEM, and that filter fails closed. **SSF is the pipe and not the vocabulary**: it defines two event types, both about the pipe, and **both vocabularies over it are implemented** — CAEP's eight about a SESSION and RISC's fourteen about an ACCOUNT. Two things here therefore send a Security Event Token with nobody having asked, watching two different registers: a sign-in, a single sign-on or a sign-out (CAEP), and a change to the embedded directory — a person deleted, an account marked inactive, a mail address moved (RISC). Eleven of RISC's fourteen carry no payload members at all, so the SUBJECT is the entire message; one of them is deprecated by its own specification in favour of a CAEP event; and RISC section 3.1's own compatibility note — a production transmitter that spells the subject discriminator `subject_type` rather than `format` — is reproducible at `risc.googleSubjectType`, which makes it the only deliberate defect here that a specification asks for by name. Every SET is signed through the same signer everything else here uses, so `ssf.signingAlgorithm` reaches the whole table including ML-DSA and SLH-DSA — which matters more for this document than for any other, because RFC 8417 forbids a SET to expire and it is therefore read long after it was written |
| **SCIM 2.0 (RFC 7642, 7643, 7644)** | a provisioning endpoint at `/scim/v2`, and **the only family here whose purpose is to write**: create, read, list, replace, PATCH (section 3.5.2 in full, `emails[type eq "work"].value` paths included), delete, both shapes of `.search`, bulk, filtering, sorting, pagination, attribute projection, and the three discovery documents. **What it provisions into is the LDAP directory above — the same entries, no second store and no cache** — so a `POST /scim/v2/Users` and an `ldapadd` create the same entry, and somebody provisioned over SCIM turns up on `/admin/users`, in an `ldapsearch`, in whatever group a client puts them in, and in the attributes their next access token carries. The SCIM `id` **is** the entry's DN, because that already is the opaque server-assigned identifier RFC 7643 asks for. **It is the one family here that requires a credential** — all six schemes RFC 7644 section 2 names are offered (OAuth 2.0 bearer and DPoP tokens with `scim:read` / `scim:write`, HTTP Basic, HTTP Digest, HOBA, the session cookie and a TLS client certificate), and every one of them is permissive, so it is a turnstile rather than a lock. `active: false` **deactivates nobody**: it is stored as `scimActive` and read by nothing, which is worth reading twice, because deprovisioning is the commonest thing a SCIM client is built to do |

`GET /admin/sts-metadata` is the authoritative list — every endpoint read from the running
router, so it cannot go stale, and fifty specifications with how far each one
goes. See *The index of itself* below, including the one blind spot that design has:
a protocol that registers no route, which is exactly what Kerberos, LDAP and the two
HTTPS listeners are. SCIM is deliberately **not** one of them — it is HTTP all the way
down, and its routes are registered against the shared app one by one rather than
behind a mounted Express `Router`, which that walk would skip. That is most of why the
`scimmy-routers` package is not used; the rest of the reason is that its constructor
requires an authentication scheme, and what this service would have installed is a
handler that accepts everything, dressed as a check.

**WS-Federation used to be the gap here, and this note used to say so.** Until
`wsfed.js` existed, the pieces a passive-requestor profile needs — the assertion
builder, the signer, the login screen — were all present and the profile that joins
them was not, which made this an assertion *issuer* rather than an identity provider
with a browser-facing SSO profile. It now has one; see *WS-Federation* below. What
is still absent is named there rather than left to be inferred, which is the point
this paragraph was making in the first place.

**SAML 2.0 Web SSO used to be the gap beside it, and as of 2026-08-24 it is
not.** This paragraph said there was no `SingleSignOnService`, no `AuthnRequest`
and no `Response`, and that the only browser SSO profile here was
WS-Federation's. There is now a full SAML 2.0 identity provider at `/saml2` —
see *SAML 2.0 Web Browser SSO* below — over all three bindings, with Single
Logout and **signed metadata per service provider**.

The WS-Federation metadata still publishes no `IDPSSODescriptor`, and the reason
has changed: it is a statement about *that document*, which describes a
`fed:SecurityTokenServiceType` and not a SAML identity provider. The
`IDPSSODescriptor` is at `/saml2/metadata`, and at
`/saml2/metadata/{sp}` there is one per service provider.

## Running it

```bash
# Once per checkout: the LDAP directory is built on node-ldapjs, which is a
# SUBMODULE. An uninitialised submodule is an empty directory, so without this
# the install succeeds and the service dies at startup with
# "Cannot find module 'ldapjs'" — a message that names a package.
git submodule update --init

# --omit=dev is not tidiness. npm installs a `file:` dependency's OWN
# devDependencies, and ldapjs's are tap and eslint: ~200 packages and a dozen
# advisories against a test runner this service never loads. .npmrc says the
# same thing, so a bare `npm install` here behaves too.
npm install --omit=dev

CONFIG_FILE=./env/local.js node server.js      # 8081, LDAP on 389, LDAPS on 636
```

**THE MAIN PORT IS HTTPS**, and has been since 2026-08-30: every appconfig file
in `env/` carries `global.https: true`, so 8081 answers on the same self-signed
certificate 8443, 9443 and LDAPS 636 already served — one pair, regenerated on
every start. That is one trust decision for the whole service instead of four,
and it is what closed the gap where a caller who had trusted this key for three
sockets still met an unencrypted fourth on the port every protocol family
actually answers on.

It costs one unverified call, necessarily: with it on there is no plain listener
left in this process, and the key does not exist until the process starts, so
nothing can hold an anchor for it in advance.

```bash
curl -k https://localhost:8081/tls/server-certificate > /tmp/sts.pem
curl --cacert /tmp/sts.pem https://localhost:8081/healthcheck    # verified from here on
export NODE_EXTRA_CA_CERTS=/tmp/sts.pem                          # for a node client
```

`STS_HTTPS=false` restores the plain port, and it is a supported configuration
rather than an escape hatch — a client that cannot be taught to trust a
per-start certificate is exactly the thing this service exists to exercise.

### The ports

Twelve bindings across eleven numbers — 88 is listed twice because TCP and UDP are two
sockets. Every default is in the table; every one is settable.

| Port | | Setting / env var | What is on it |
|---|---|---|---|
| **8081** | tcp | `global.port` / `STS_PORT` | **The main port, and everything path-based is here** — OAuth 2.0 / OIDC, both SAML profiles, WS-Trust, WS-Federation, federation, SCIM, OID4VC, Shared Signals, XACML, `/admin`, `/portal`, `/admin-api`, the SPIFFE **bundle** endpoint, and Kerberos over **MS-KKDCP at `/KdcProxy`**. **HTTPS** unless `STS_HTTPS=false` — one listener, never both schemes |
| **8082** | tcp | `pki.httpPort` / `PKI_HTTP_PORT` | **Plain HTTP, `/pki/` and nothing else** — the CRLs, OCSP responders and CA certificates, at the address every certificate this service issues names for them. Plain on purpose: RFC 5280 section 8 says a CA SHOULD NOT write an https URI into an extension, and RFC 5019 section 5 says an OCSP responder MUST answer HTTP. Every other path is a 404. `0` turns it off, and certificates then name the main port |
| **8443** | tcp | `tls.port` / `STS_TLS_PORT` | The TLS endpoint that **asks** for a client certificate and never refuses one |
| **9443** | tcp | `tls.mutualPort` / `STS_MTLS_PORT` | The one that **requires** it — node refuses an unverified certificate during the handshake, so nothing here runs for one |
| **88** | **tcp** | `krb5.kdcPort` / `KRB5_KDC_PORT` | The KDC. `0` asks for any free port — it does not turn it off |
| **88** | **udp** | *(the same setting)* | The KDC again: both transports, two sockets, one number |
| **8888** | tcp | `krb5.servicePort` / `KRB5_SERVICE_PORT` | The Kerberized test service that accepts an AP-REQ |
| **389** | tcp | `ldap.port` / `LDAP_PORT` | The embedded directory, plain LDAP |
| **636** | tcp | `ldap.tlsPort` / `LDAPS_PORT` | The same directory over TLS. A **second server object**, not an option on the first — see below |
| **8092** | tcp | `spiffe.workloadPort` / `STS_SPIFFE_WORKLOAD_PORT` | The SPIFFE **Workload API** over gRPC. `0` turns it off and leaves the Unix socket alone |
| **8181** | tcp | `spiffe.serverPort` / `STS_SPIFFE_SERVER_PORT` | The **SPIRE Server API** over gRPC. Always mutual TLS — a caller presents an X509-SVID from this trust domain and every method is authorized against SPIRE's own table, which the service **mode** decides rather than a setting of its own. 8181 rather than SPIRE's own 8081, because that number is this service's HTTP port — so a client configured for a real `spire-server` has one thing to change |
| **8444** | tcp | `debugger.port` / `STS_DEBUGGER_PORT` | **The embedded identity protocol debugger**, when it is embedded (`debugger.enabled`: on in development, off in product, by default) and its built tree is installed. A separate ORIGIN from the console on purpose, in the main port's scheme and with its certificate. Its static site, its sign-in callback and `/api`, which is forwarded to the debugger's api running as a child process on a unix socket. Every request needs a console administrator — see *The embedded protocol debugger* |

And two **Unix domain sockets**, which are what `SPIFFE_ENDPOINT_SOCKET` means to
every real client and which no `EXPOSE` can publish — to reach them from the
host or another container, mount the directory as a volume:

| Socket | Setting / env var | On? |
|---|---|---|
| `/tmp/spire-agent/public/api.sock` | `spiffe.workloadSocket` / `STS_SPIFFE_WORKLOAD_SOCKET`, switched by `spiffe.workloadSocketEnabled` / `STS_SPIFFE_WORKLOAD_SOCKET_ENABLED` | **on** — SPIRE's own path, for the Workload API |
| `/tmp/spire-server/private/api.sock` | `spiffe.serverSocket` / `STS_SPIFFE_SERVER_SOCKET`, switched by `spiffe.serverSocketEnabled` / `STS_SPIFFE_SERVER_SOCKET_ENABLED` | **off** — the SPIRE Server API's private socket, trusted as `local` when it is on |

**The four raw-socket families start from `listen()` and a failure to bind is
RECORDED rather than thrown.** A route cannot fail to register; a port can, so
binding one at require time would let a busy port take down a service whose
other sixteen protocol families were fine. **Every socket reports itself
separately** rather than through one flag per family — `GET /krb5/principals`,
`GET /admin/ldap/service`, `GET /tls`, `GET /spiffe` — for the reason given
below about 389 and 636.

**`/admin/sts-metadata` cannot see any of them.** That page is built by walking
the live Express router, so a protocol that registers no route is invisible to
it — the raw listeners are described there by hand or they go unlisted with
nothing failing.

**`docker-compose.yml` publishes 8081 and 8082.** 8082 is published because its
whole purpose is to be reached from outside — every certificate this service
issues names it — and the stack TELLS the service which host port it landed on
(`STS_PKI_HOST_PORT` → `PKI_DISTRIBUTION_PORT`), since nothing inside a container
can see the host side of a port mapping. The rest are `EXPOSE`d, which
publishes nothing; 389 and 636 are deliberately left unpublished, because the
host most likely to want a mock directory is a host already running slapd. And
**9090 is not this service** — it is the `xacml-pep/` container, a separate
program on the same network.

**Ports 389 and 636 are both privileged**, so a host run that is not root will fail to
bind them — which is reported and is not fatal, the rest of the service being
unaffected. Set `LDAP_PORT` and `LDAPS_PORT` to something unprivileged for a host run,
and remember that the parent project's api has to allow the new ports in
`ldapAllowedPorts` (its default list carries `1389` and `1636` for exactly this). The
two sockets bind **independently**: 389 up and 636 down is the ordinary outcome of a
host run, and `GET /admin/ldap/service` reports each of them separately rather than through one flag
that would have to lie about one.

### Behind an L4 load balancer — the PROXY protocol

**Put this service behind a Network Load Balancer, not an Application Load
Balancer**, and pass TLS through. An L7 balancer terminates TLS, and every
feature here that reads the client's certificate — RFC 8705
`tls_client_auth` and certificate-bound tokens, certificate sign-in, 9443, the
XACML certificate gates, the SPIRE Server API — needs the handshake to happen on
the node; no forwarded certificate header is believed, in any mode. An L7
balancer also cannot carry LDAP, LDAPS or Kerberos at all.

At L4 the node sees the balancer as every connection's peer. `global.proxyProtocol`
set to `v2` is how the client's address still arrives: the balancer writes a
binary header at the front of each TCP connection, and this service takes it off
before TLS, LDAP or the KDC read a byte. For an **AWS Network Load Balancer**:

* **TCP listeners** (not TLS listeners) for 443→8081, 8443, 9443, 389, 636 and 88,
  each forwarding to a **TCP target group** on the node's port. The KDC's UDP 88
  cannot carry a header; put Kerberos clients on TCP.
* **`proxy_protocol_v2.enabled = true`** on every one of those target groups.
  AWS documents that health checks then carry the header too, with no client
  information in it — they are accepted, and keep the balancer's address.
* **`preserve_client_ip.enabled = false`** (the default for IP targets, not for
  instance targets), so connections come from the balancer's own private
  addresses, and **`global.trustedProxies`** set to the CIDRs of the subnets the
  balancer is in. With client IP preservation on, the peer is the client and
  every connection is refused as untrusted.
* `global.publicBaseUrl` set to the name clients use, as for any deployment.

A connection from an address outside `global.trustedProxies` is **closed**, not
served — a node reachable around the balancer is a network fault, and closing it
makes the balancer the only way in. A trusted address that sends no header is
closed too (`STS-PROXY-0002`). The one exception is **this host**: loopback, or a
peer on the node's own address, is served plain, because the console's and the
portal's OpenID Connect back channel and the Shared Signals push dial the main
port on loopback without a header. `common/proxy_protocol.js` argues each of
these; the refusals are `STS-PROXY-0001`–`0009` in `docs/error-codes.md`.

### Configuration

`CONFIG_FILE` selects a configuration from `env/`, and that file carries **every
setting this service has** — 118 of them, 78 changeable while running, grouped
by the protocol they belong to: the three issuers, the listeners, the OID4VCI
and OID4VP tuning, the Kerberos realm, SIDs, passwords and clock, the
directory's base DN and limits, the audit log's cap, the SCIM endpoints'
authentication schemes, the SPIFFE trust domain and what its two gRPC surfaces
check, and the three that put the authorization flow into RFC 9700 mode. (The
startup log line reports the count, and it is the number to trust: this
paragraph is prose and `common/config.js`'s table is the source.) At the default
log level `debug` the service logs every endpoint call — path, request and
response headers and bodies, status, elapsed time — and every assertion, JWT and
SD-JWT VC both before and after signing or encryption, which is the point of a
mock.

**Every one of the 118 is listed below**, with its appconfig key, its
environment variable, its default and whether it can be changed without a
restart. That table is generated from the same rows the console renders, so it
cannot describe a setting this service does not have.

**Since 2026-08-27 the console draws each setting on the page for the protocol
it configures** — the Kerberos settings on `/admin/kerberos`, the SCIM ones on
`/admin/scim`, and so on for all twenty-two groups. `/admin/config` keeps the
five that belong to no protocol (the bind address, the port, the scheme, the
proxy header and the log level) and is otherwise the INDEX: every group, its
size, what is overridden right now, and the page that draws it. Nothing else
changed — every one of those forms posts to the same endpoint against the same
override map, and `GET /admin/config?format=json` and `GET /admin-api/config`
still answer the whole table.

#### Where a value comes from

Highest wins:

| | Where | Survives a restart? |
|---|---|---|
| 1 | a **runtime override** — set on the console page for that setting's protocol, or through `POST /admin-api/config/set` | only with a persistent store — see below |
| 2 | the setting's **environment variable** — `STS_PORT`, `KRB5_REALM`, … | yes |
| 3 | its **legacy** environment variable, where it has one — only `STS_ISSUER` does | yes |
| 4 | the **appconfig file** `CONFIG_FILE` names, e.g. `env/local.js` | yes |
| 5 | **`env/defaults.js`**, the default appconfig file that 4 is unioned on top of | yes |

**And there is no sixth. A setting with no value in 4 or 5 and no variable in 2
or 3 stops this service from starting**, naming every such setting and both
places its value could go:

```
config: FATAL — 2 setting(s) have no value in the appconfig layer and no environment variable:

  ldap.baseDn         LDAP_BASE_DN
  spiffe.trustDomain  STS_SPIFFE_TRUST_DOMAIN

Each must be set in ./env/local.js, in ./env/defaults.js (the default appconfig
file every other one is unioned on top of), or as the environment variable
beside it.
```

That is the point of the whole arrangement rather than a strictness for its own
sake. A value that arrives from a constant buried in a module is a value nobody
can find, change, or see on a page — which is the state this table was built to
end, and a silent fallback underneath it would have quietly kept one way back
into it.

**Layers 4 and 5 are one layer, unioned.** `env/defaults.js` carries a default
for every setting; the file `CONFIG_FILE` names is merged over it key by key,
and **the operator's value wins wherever both carry a key**. So a config file
may carry as few keys as its author likes and still be complete — a file
carrying only `logLevel` resolves everything else through the defaults, which is
what lets the parent project's in-process Kerberos jobs point `CONFIG_FILE` at
their own test config and still load these modules. It also means a setting
added to the table tomorrow does not break every config file in the world on the
day it is added. What the refusal above actually catches is the one case left: a
setting added to `common/config.js`'s table with no row in `env/defaults.js`,
which is a setting somebody added and did not finish adding.

**`env/defaults.js` is GENERATED and is not the file to edit.** `node
env/generate_defaults.js` writes it from the table's `dflt` column, which is
where each default is written down next to the paragraph explaining why it is
the default. Two copies of a default is one copy that will be wrong, and wrong
in the quietest possible way — the service running on one value while the
console, the OpenAPI document and this table all report the other. To
configure a deployment, edit the file `CONFIG_FILE` names, or set the
environment variable.

**Four settings are exempt from the refusal and from both files**, marked
*(derived)* in the table: `global.https` takes its default from
`oauth2.rfc9700`, `oid4vp.walletUrl` from `oid4vci.walletUrl`,
`krb5.serviceDomains` from `krb5.realm`, and `adminApi.audience` — the base URL
of the management API — from `global.publicBaseUrl`, or from the main port's
scheme, host and port where that is empty. Their default is a function of a
neighbour, so a literal in a file would freeze the derivation at whatever it
evaluated to the day the file was written. Each still has its own environment
variable and its own appconfig key, and setting either replaces the derivation.

**Whether a runtime override survives a restart is `persistence.appconfig`.**
Layer 1 is the admin console and the management API. In the default
`persistence.mode=memory` an edit lasts for the life of the process and no
longer, which is what this service did until 2026-08-27; with a store turned on
it is written down and applied again at the next start — through the same
`setOverride()` a caller uses, so **this adds no sixth layer** and the ordering
above is unchanged. A *reset* is written down too, which is the half that is
easy to miss: a reset that did not survive would be worse than no reset.

**Nothing here ever writes to an appconfig FILE**, in either mode, and that is
deliberate rather than unfinished: a service that edited a file checked into a
repository would leave a test's forgotten change behind permanently. The durable
copy goes to the persistent store, which is not a place anything is checked in
from. So the file is what a person EDITS and the store is what the console
WRITES, and neither overwrites the other.

`POST /admin-api/config/reset-all` is what a test should call to put the service
back; in memory mode a restart does the same thing. A setting the table marks
restart-only is **refused** with the reason rather than accepted and ignored,
because an accepted change that does nothing reads as having worked — which is
also why restoring saved overrides after every module has loaded is safe: only a
runtime-changeable setting can be saved, and a runtime setting is by definition
one that is read per call rather than captured at startup.

`common/config.js` is the table, and it is the one place that says, for each
setting, what it does, what its environment variable is, what the default is and
*why*, and whether changing it while the service runs does anything.
The console renders that table with the effective value of each setting and
**which of the five places above it came from** — the question it exists to
answer, since the five are indistinguishable once a value has been read — with
each group on the page for the protocol it configures and `/admin/config`
holding the index and the five settings that belong to no protocol. `GET
/admin-api/config` is the same thing over JSON, whole, and `POST
/admin-api/config/{set,set-many,reset,reset-all}` are its four actions.
`set-many` is all-or-nothing, so a section's Save cannot half-apply.

**An environment variable is a string and the table knows what to do with it.**
A `bool` takes `1/true/yes/on` and `0/false/no/off` in either case; anything else
is warned about and falls back to that setting's own default, so
`LDAP_AUTOCREATE_USERS=treu` does not silently turn a feature off. A `csv` is a
comma-separated list, trimmed, and may be written as a real array in an appconfig
file. An `int` may narrow itself with a minimum, a maximum and a multiple-of —
the four token lifetimes do — and the same three numbers constrain the console's
form, the management API and the variable read at startup, because there is one
check rather than three.

**`STS_ISSUER` was one value doing three jobs** and is now three settings.
`saml.issuer` is the `<saml:Issuer>` of every SAML assertion (WS-Federation's
included, since the same two functions build them); `wstrust.issuer` is the
`iss` of the JWT this STS returns; `wsfed.entityId` is the `entityID` in the
federation metadata. They shared a default and nothing else — an entityID names
the identity provider, an Issuer names whoever signed an assertion — so a
deployment that needed one of them to be its own real name had to change all
three. All three still default to `urn:wstrust:mock:sts` and all three are still
fed by `STS_ISSUER` when it is set, which is the whole of layer 3.

**The `SAML` group has a second row since 2026-08-27**, and it is the one
setting here that changes what goes INTO an assertion's validity window rather
than how long that window is. `saml.clockSkewS` is added to BOTH ENDS of every
assertion this service issues — `NotBefore` backdated, `NotOnOrAfter` extended
— which is the answer to a service provider whose clock is a few seconds behind
refusing a perfectly good assertion as not-yet-valid. It is deliberately not
`oauth2.clockSkewS`: that one is a TOLERANCE applied wherever this service reads
a document back, including an inbound federation partner's assertion, and a
deployment wanting a strict reading and a forgiving issuance has to be able to
say so. How LONG an assertion is valid is still per profile —
`saml2.assertionLifetimeMin` and `saml11.assertionLifetimeMin` — because the two
profiles are separate implementations consumed differently. All three are drawn
together on `/admin/saml-assertions`, which is the only page where both
lifetimes are visible at once.

**AND SINCE 2026-08-27 TEN OF THOSE SETTINGS ARE DEFAULTS RATHER THAN
DECISIONS.** Five per profile — the assertion lifetime, `signAssertion`,
`signResponse`, `nameIdFormat` and `artifactTtlS` — can be answered PER
APPLICATION on an application entry, and where they are, that answer wins for
that application alone. The attributes are `saml2AssertionLifetimeMin`,
`saml2SignAssertion`, `saml2SignResponse`, `saml2NameIdFormat`,
`saml2ArtifactTtlS` and the five `saml11*` equivalents; set them on
`/admin/applications/new`, with `POST /admin-api/applications/set`, or with an
`ldapmodify`. An ABSENT attribute means inherit — there is no third state — and
a value that will not parse is ignored, logged and the setting used instead.
`GET /admin-api/saml-assertions` lists which setting each attribute overrides.
The keys and environment variables above are unchanged; what changed is that
they are now the answer for an application that has not been given one of its
own.

**An application declared for SAML 2.0 or SAML 1.1 gets an `samlEntityId`** — its
own identifier, if none was given — so its per-service-provider metadata at
`/saml2/metadata/{sp}` and `/saml11/metadata/{rp}` is publishable the moment the
entry exists.

### Per-application configuration, in one place

`/admin/applications/new` is where an application's own answers are typed, and
since 2026-08-27 **twenty settings across four protocols** can be answered there
rather than only service-wide:

| Protocol | Settings a single application may overrule | Attributes |
|---|---|---|
| OAuth 2.0 / OIDC | the three token lifetimes, the refresh idle timeout, revoke-on-logout, and whether an RFC 8693 token exchange comes back with a refresh token | `oauthAccessTokenTtlS`, `oauthIdTokenTtlS`, `oauthRefreshTokenTtlS`, `oauthRefreshIdleSeconds`, `oauthRevokeRefreshOnLogout`, `oauthTokenExchangeRefreshToken` |
| SAML 2.0 | assertion lifetime, both signature switches, NameID format, artifact lifetime | `saml2AssertionLifetimeMin`, `saml2SignAssertion`, `saml2SignResponse`, `saml2NameIdFormat`, `saml2ArtifactTtlS` |
| SAML 1.1 | the same five | `saml11*` |
| WS-Federation | assertion lifetime | `wsfedAssertionLifetimeMin` |
| the groups claim | whether it is carried, its name, its value form, where it is read from | `appGroupsClaim`, `appGroupsClaimName`, `appGroupsClaimValue`, `appGroupsClaimFromMemberOf` |

An **absent attribute means inherit** — there is no third state — and a value
that will not parse is ignored, logged and the setting used instead. The
defaults live on `/admin/token-lifetimes` and `/admin/saml-assertions`, and each
page names the attribute that overrides each row. The globals each protocol
keeps — its issuer identity, its sockets, its clock skews — stay on that
protocol's own page.

**One of them is REFUSED rather than merely inert on an entry of the wrong
family, and it is the only attribute in this registry that is.**
`oauthTokenExchangeRefreshToken` applies to the OAuth 2.0 and OpenID Connect
families, and both console doors and `/admin-api` turn away a write of it onto
an application declared for neither, naming what to tick first. Every other
attribute here is a default something reads if it ever gets the chance, so
writing `saml2SignAssertion` onto an OAuth client costs nothing and says nothing
false; that one decides what the **token endpoint** does for one `client_id`, so
on an entry no token request could ever name it would sit there reading like a
policy that was in force. The rule is declared on the schema row itself
(`families: ['oauth2', 'oidc']`) rather than written into either door, so a
second attribute that needs it costs a member and nothing else. `ldapmodify`
reaches the attribute either way, as it reaches every attribute here — the
refusal is the difference between offering an operation and merely not
preventing it.

**The New Application form shows a field only when its protocol is ticked**, so
an OAuth client is not asked for a SAML entityID. That is done in CSS with
`:has()` and no script; a browser without `:has()` shows every field, which the
page says on itself.

### SAML 2.0 encryption

Since 2026-08-27 this service encrypts and decrypts. There is no
`EncryptedAuthnRequest` in SAML 2.0, so "request encryption" means
`<saml:EncryptedID>`:

| | Outbound | Inbound |
|---|---|---|
| Response | `<saml:EncryptedAssertion>` | — |
| LogoutRequest | `<saml:EncryptedID>` | `<saml:EncryptedID>`, always decrypted |

The assertion is **signed first and then encrypted**, so the signature is inside
the ciphertext. `/saml2/metadata` now publishes a `use="encryption"`
KeyDescriptor — the same certificate it signs with, regenerated on every start —
which is what a service provider encrypts an `EncryptedID` to.

**Where the recipient's certificate comes from**, most specific first:

1. `samlSpMetadata` / `samlSpMetadataUrl` on the entry. Set the URL and press
   **Refresh the metadata** on the application page (or
   `POST /admin-api/applications/refresh-metadata`); the `use="encryption"`
   KeyDescriptor is extracted into `samlEncryptionCertificate`. The document can
   also be pasted for a service provider this service cannot reach.
2. `samlEncryptionCertificate`, typed.
3. `samlSigningCertificate` — captured off a signed AuthnRequest, so a service
   provider that signs its requests needs no configuration at all.
4. Nothing: the assertion goes out **in clear** and says so at WARN. It is not
   refused, because a mock that stopped issuing when a key was missing is
   useless exactly when somebody is setting it up.

**The fetch never happens while a flow is running.** It is an explicit action
that writes the certificate onto the entry, and issuing reads the entry — so no
sign-in waits on somebody else's web server. It is the second outbound-request
surface in this service after federation, and follows the same refusals: https
only unless `federation.outboundAllowInsecure` is on, a timeout of
`federation.outboundTimeoutMs`, no redirects followed, and a size cap. A failure
changes nothing, so an application that was working keeps working.

**The OAuth 2.0 / OIDC issuer identifier is empty by default**, which means each
response names the base URL the request arrived on — what makes one process
answer correctly as `localhost`, as `sts` on a compose network and through a
published port. Set `oauth2.issuer` to pin it, which is how a conforming
client's "the issuer is not the one I fetched from" refusal is produced on
purpose. Only the identifier moves: every endpoint in the discovery document
stays on the request's base URL, because an endpoint has to be reachable and a
pinned issuer may not be.

**Seven listeners, not one.** 8081 is the main service, and it is **HTTPS** with
every appconfig file this repository ships — `global.https`, which is also what
`oauth2.rfc9700` derives — serving the same certificate as the three TLS sockets
below, with no plain port left in the process. `STS_HTTPS=false` makes it plain
HTTP, which is what it was before 2026-08-30; the KDC also binds **TCP and
UDP 88**, the Kerberos-protected service a TCP socket of its own (8888), the
directory **TCP 389** and — the same directory over TLS — **TCP 636**, and the TLS
endpoint **8443** and **9443**. Every one of them
is started from an exported `listen()` that `server.js` calls *after* the HTTP server
is up, and a failure to bind is logged rather than thrown — ports 88, 389 and 636 are
privileged, a host run is usually not root, and a require that throws would take the
whole service down over a protocol family the caller may not be using. Set
`KRB5_KDC_PORT`, `LDAP_PORT`, `LDAPS_PORT`, `STS_TLS_PORT` and `STS_MTLS_PORT` to
something unprivileged or unoccupied for a host run, and remember that the parent
project's api allowlists the port it will reach on each of them: its
`krb5AllowedPorts` and `ldapAllowedPorts` have to allow whatever these become,
and its default list carries `1389` and `1636` for exactly that reason.


**`CONFIG_FILE` is the one environment variable with no appconfig key**, and it
cannot have one: it is what chooses the file. It names a JavaScript module,
resolved against this package root and then against the working directory, so
the documented `./env/local.js` works from wherever the process was started —
fourteen modules read it directly for the one thing they need before the table
exists, a bunyan log level, and a relative path would otherwise resolve against
each of their own directories (see `common/config_file.js`). It defaults to
nothing: unset, every value comes from `env/defaults.js` or from the
environment. A file that cannot be loaded is fatal and says so, because
continuing would mean starting a service configured as nobody asked for.

In Docker:

```bash
docker build -t iya-sts .
docker run --rm -p 8081:8081 iya-sts
```

That publishes the HTTP port only, which is enough for everything except a raw
Kerberos client: in the container this process is root, so the KDC does bind 88, but
nothing forwards it. `-p 88:88/tcp -p 88:88/udp -p 8888:8888` adds it. The
`docker-compose.yml` here publishes 8081 alone for the same reason — an in-browser
Kerberos client reaches the KDC through `POST /KdcProxy` (MS-KKDCP) on the HTTP port,
which is the whole reason that endpoint exists.

The OIDC Discovery Metadata Endpoint:
```
https://localhost:8081/server001/.well-known/openid-configuration
```

Via Docker-Compose:
```bash
docker-compose up
```

### Every setting

Generated from `common/config.js`'s table — the same rows the console renders
and `GET /admin-api/config` answers, so this list cannot describe a setting this
service does not have or miss one it does. The **Group** each setting belongs to
is also the console page that draws it: the *Kerberos* rows are on
`/admin/kerberos`, the *SCIM* rows on `/admin/scim`, and `/admin/config` lists
the mapping for all thirty-two.

How to read it. **The appconfig key is the dot path in the file**, so
`oid4vci.batchSize` is `oid4vci: { batchSize: … }`; `logLevel` is the one key
that sits at the top level rather than in a section, because it was there before
this table existed and moving it would have broken every config file for no
gain. **Every setting has an environment variable and it beats the file.**
**Change while running** says whether the console and `POST
/admin-api/config/set` will take it: *restart* means the value was consumed
before the service was listening — a bound socket, the TLS certificate's names,
the Kerberos principal database and its long-term keys, the directory tree's
root — and the reason is on the row. ***(derived)*** marks the four whose
default is computed from a neighbouring setting rather than written in a file.

The *What it does* column is the first sentence or two of the setting's own
description. The full paragraph — with the reasoning, which is usually the
record of something having gone wrong once — is in `common/config.js` beside the
row, and beside the input on whichever console page draws it.


Four things about these settings do not fit in a cell and have cost real time:

* **`OID4VCI_WALLET_URL` is the base URL the BROWSER uses**, not one this
  service fetches. The Credential Offer pages and the verifier's request pages
  hand the End-User back by appending `/vc-issuance-1.html` or
  `/vc-presentation-1.html` to it (`oid4vci.walletIssuancePath` and
  `oid4vp.walletPresentationPath` since 2026-09-12), so its default of `http://localhost:3000` is
  right only when the browser and the wallet share a host. Get it wrong and the
  hand-off lands on an unreachable origin — and because the URL still *contains*
  the wallet page, a `urlContains` wait passes and the failure looks like an
  unrelated timeout.
* **`KRB5_KDC_PORT` is the TCP *and* UDP port.** Both transports are bound to the
  same number on purpose: a client that fails over from UDP after
  `KRB_ERR_RESPONSE_TOO_BIG` retries at the address it already had.
* **`LDAPS_PORT` is bound by a second server object**, not by an option on the
  first — ldapjs decides between a `net.Server` and a `tls.Server` at
  construction — so 389 and 636 fail independently and `GET /admin/ldap/service` reports each
  separately. There is no StartTLS to turn on instead: it is an extended
  operation, ldapjs implements none, and this repository does not patch that
  submodule. And `LDAP_BASE_DN` is the only naming context there is —
  `ou=users`, `ou=groups`, `ou=applications` and `ou=spiffe` are derived from it
  rather than configured, because two variables that could disagree with it
  would put entries in a tree nobody is searching.
* **`STS_TLS_PORT` and `STS_MTLS_PORT` are two ports rather than one port and a
  flag.** 8443 *asks* for a client certificate and never refuses one; 9443
  *requires* one. "Does this server require a client certificate" is a question
  a debugger answers by connecting twice, so it needs a server that answers each
  way at the same time.


#### Trust realms

| Appconfig key | Environment variable | Default | Change while running? | What it does |
|---|---|---|---|---|
| `realms.enabled` | `STS_REALMS_ENABLED` | `true` | yes | Whether the realms defined on `/admin/realms` answer on their path prefixes. Turning it OFF leaves every definition in place and stops the paths working, which is what to reach for when a realm is answering something it should not: nothing has to be deleted to find out whether a realm is the reason for something. It has no effect at all until at least one realm is defined. |
| `realms.pathSegment` | `STS_REALMS_PATH_SEGMENT` | `realm` | yes | The segment in front of a realm id, so that the realm `acme` is at `/realm/acme/oauth2/token`. Set it to the empty string for the bare `/acme/oauth2/token` shape. A realm may never be named after the first segment of a path this service already serves, WHATEVER this is set to, precisely so that clearing it cannot turn an existing realm into a shadow over the console or the authorization server. |

**Neither of these two can be set ON a realm.** A realm that could switch realms
off would be doing it from inside the request that found it, and a realm that
could move its own prefix would change the prefix already used to find it. They
are refused at both ends.

#### Global

| Appconfig key | Environment variable | Default | Change while running? | What it does |
|---|---|---|---|---|
| `global.mode` | `STS_MODE` | `development` | yes — and it is **per trust realm**, so one process can serve a development realm and a product realm at once | What this service IS. `development` is every release before 2026-09-06 and is what makes it a mock: no password is checked, anything named is created, and there are no public-client restrictions. `product` runs the SAME protocol implementations with the permissiveness taken out — a presented password is verified against the hashed `userPassword` on the person's own entry, nothing is created because it was named, every OAuth application holds a secret, and `/admin-api` is gated. **It replaced `admin.authRequired`, `scim.authRequired`, `spiffe.authRequired` and `ssf.authRequired`, which are gone**: "is authentication required here" had four answers and now has one. Those four gates are ON in BOTH modes — what the mode changes is whether the credential they ask for is CHECKED. |
| `global.host` | `STS_HOST` | `0.0.0.0` | **restart** — the listener is bound when the process starts | The address the HTTP listener binds. 0.0.0.0 is every interface, which is what a container needs; 127.0.0.1 confines this service to the machine it runs on. |
| `global.port` | `STS_PORT` | `8081` | **restart** — the listener is bound when the process starts | The port everything HTTP here answers on: the protocol endpoints, the console and this API. The two TLS listeners are separate and are under TLS below. **Several nodes against one store must all use the same value**: the console's and portal's own Shared Signals receivers are seeded at `<loopback>:<global.port>` and every node pushes to that address on its own loopback (`ssf/CLAUDE.md`, *Several nodes*). |
| `global.https` *(derived)* | `STS_HTTPS` | `false`, but **`true` in every appconfig file shipped here** — see *Running it* | **restart** — the listener is bound when the process starts, and its scheme is decided there | Serve the main port over HTTPS, with the SAME certificate and key the 8443, 9443 and LDAPS 636 listeners use — one self-signed pair generated per start, so a caller trusts this service once rather than four times. |
| `global.trustProxy` | `STS_TRUST_PROXY` | `false` | yes | Believe X-Forwarded-Proto and X-Forwarded-Host — which is what a TLS-terminating reverse proxy sets to say what the CLIENT used. |
| `global.trustedProxies` | `STS_TRUSTED_PROXIES` | *(empty)* | yes | The addresses or CIDR ranges this deployment's own proxies connect from. Read for forwarded headers only with `global.trustProxy` on, and for a PROXY protocol header whenever `global.proxyProtocol` is `v2` — where empty trusts nobody and the service does not start. **Empty keeps the old rule** — forwarded headers believed from any caller, the rate limiter taking the left-most `X-Forwarded-For` entry. Set, they are believed only from a peer in a range and the client is the right-most hop outside them, so a caller reaching a node directly cannot choose its own rate-limit address or this service's URL. `common/CLAUDE.md`, *Several nodes*, also says why mutual TLS needs L4 passthrough. |
| `global.proxyProtocol` | `STS_PROXY_PROTOCOL` | `off` | **restart** — installed on each listener when it binds | `v2` reads a HAProxy PROXY protocol version 2 header at the front of every connection to the main port, 8443, 9443, 389, 636, the KDC's TCP 88 (not UDP), the debugger and 8082 — **before TLS**, so the client's address reaches the rate limiter, LDAP, `/tls/whoami` and the request workers while TLS and mutual TLS still terminate on the node. A connection from `global.trustedProxies` must carry a valid header (a `LOCAL` one — a health check — keeps the balancer's address); any other address is closed, except this host's own, which is served plain. Version 1 is refused; the SPIFFE gRPC listeners are not covered. See *Behind an L4 load balancer* above. |
| `global.proxyProtocolTimeoutMs` | `STS_PROXY_PROTOCOL_TIMEOUT_MS` | `5000` | yes | How long a trusted proxy may take to send its complete header before the connection is closed. |
| `global.corsOrigins` | `STS_CORS_ORIGINS` | *(empty)* | yes | Origins CORS treats as this deployment's OWN, comma-separated — allowed on every path whichever client a request names, beside this service's listeners, `global.publicBaseUrl` and the embedded debugger. **Empty adds none**; every other origin must be listed in an application's `appCorsOrigin`. A value that is not an origin is ignored and logged. |
| `global.logLevel` | `STS_LOG_LEVEL` | `info` | yes | debug is the useful level for a mock whose job is to show what it did: every endpoint call, and every token and assertion both before and after it was signed. |
| `workers.count` | `STS_WORKERS_COUNT` | `2` | yes — the pool is reconciled on the next signature | How many child processes the post-quantum signing, verification and key generation are handed to, so that the process holding the sockets is never the one computing an SLH-DSA signature — which takes SECONDS, during which node answers nothing at all, the KDC on port 88 included. `0` means compute in this process, which is what this service did before the pool existed: correct, identical byte for byte, and blocking for as long as each signature takes. Nothing is forked until the first post-quantum job, so a process that never signs one never pays for a pool. **A realm may not carry this**: a pool belongs to the OS process. |
| `workers.batch` | `STS_WORKERS_BATCH` | `/scim,/admin/signals/receive,/portal/signals/receive` | yes (per process — a realm may not carry it) | Path prefixes that are **batch traffic** when requests are dispatched to request workers: routed only to a share of each pool's workers and held to a number in flight, so a bulk load cannot take every worker. Empty turns the lane off. |
| `workers.batchWorkerShare` | `STS_WORKERS_BATCH_WORKER_SHARE` | `50` | yes (per process) | The percentage of a pool's workers batch traffic may use — at least one, and one fewer than the pool below 100. A request already bound to a worker (a write to one SCIM resource) keeps it. |
| `workers.batchConcurrency` | `STS_WORKERS_BATCH_CONCURRENCY` | `8` | yes (per process) | Batch requests in flight per lane worker, per pool; the rest wait in the front process in order. `0` keeps the lane and removes the cap. |
| `workers.batchQueueLimit` | `STS_WORKERS_BATCH_QUEUE_LIMIT` | `5000` | yes (per process) | How many batch requests may wait; past it they are answered 503 with Retry-After. |
| `workers.batchQueueTimeoutS` | `STS_WORKERS_BATCH_QUEUE_TIMEOUT_S` | `60` | yes (per process) | A batch request that waited this long is answered 503 with Retry-After. |

#### GNAP

The Grant Negotiation and Authorization Protocol (RFC 9635) and its resource
server connections (RFC 9767), drawn on `/admin/gnap`. Every row is settable per
trust realm. [docs/gnap.md](docs/gnap.md) says what each one changes on the wire.

| Appconfig key | Environment variable | Default | Change while running? | What it does |
|---|---|---|---|---|
| `gnap.enabled` | `STS_GNAP_ENABLED` | `true` | yes | Off makes every /gnap endpoint, the RS-facing discovery document and the resource-owner pages answer that GNAP is turned off in this realm. |
| `gnap.accessTokenFormat` | `STS_GNAP_ACCESS_TOKEN_FORMAT` | `jwt-signed` | yes | The RFC 9767 token format issued when nothing more specific decides. |
| `gnap.tokenFormats` | `STS_GNAP_TOKEN_FORMATS` | `jwt-signed,jwt-encrypted,macaroon,biscuit,zcap` | yes | RFC 9767 section 3.1's token_formats_supported. |
| `gnap.accessTokenLifetimeS` | `STS_GNAP_ACCESS_TOKEN_LIFETIME_S` | `3600` | yes | The expires_in of every access token, and the exp of the formats that carry one. |
| `gnap.interactionLifetimeS` | `STS_GNAP_INTERACTION_LIFETIME_S` | `600` | yes | How long the interaction start URIs and user codes of a pending grant stay usable (RFC 9635 section 3.3's expires_in). |
| `gnap.continueWaitS` | `STS_GNAP_CONTINUE_WAIT_S` | `5` | yes | The wait of every continuation response. |
| `gnap.maxPolls` | `STS_GNAP_MAX_POLLS` | `60` | yes | How many continuation polls a pending grant accepts before it is finalized with too_many_attempts (section 5.2). |
| `gnap.signatureMaxAgeS` | `STS_GNAP_SIGNATURE_MAX_AGE_S` | `300` | yes | How far a key proof's created time may be from now, either way (sections 7.3.1, 7.3.3 and 7.3.4). |
| `gnap.interactionStartModes` | `STS_GNAP_INTERACTION_START_MODES` | `redirect,app,user_code,user_code_uri` | yes | Section 9's interaction_start_modes_supported. |
| `gnap.finishMethods` | `STS_GNAP_FINISH_METHODS` | `redirect,push` | yes | Section 9's interaction_finish_methods_supported. |
| `gnap.keyProofs` | `STS_GNAP_KEY_PROOFS` | `httpsig,mtls,jwsd,jws` | yes | Section 9's key_proofs_supported. |
| `gnap.subIdFormats` | `STS_GNAP_SUB_ID_FORMATS` | `opaque,iss_sub,email,account,uri,phone_number,aliases` | yes | Section 9's sub_id_formats_supported, in RFC 9493's own spellings. |
| `gnap.assertionFormats` | `STS_GNAP_ASSERTION_FORMATS` | `id_token,saml2` | yes | Section 9's assertion_formats_supported: an OpenID Connect ID Token and a SAML 2.0 assertion, built by the same code the OIDC and SAML families use. |
| `gnap.assertionMaxAgeS` | `STS_GNAP_ASSERTION_MAX_AGE_S` | `300` | yes | Section 2.4 lets an AS "accept a recently expired assertion in order to help bootstrap a new session". |
| `gnap.keyRotation` | `STS_GNAP_KEY_ROTATION` | `true` | yes | Section 9's key_rotation_supported, and section 6.1.1. |
| `gnap.tokenManagement` | `STS_GNAP_TOKEN_MANAGEMENT` | `true` | yes | Whether access tokens carry a manage URI and management token (section 6). |
| `gnap.bearerTokens` | `STS_GNAP_BEARER_TOKENS` | `true` | yes | Off refuses the bearer flag with invalid_flag for every client (section 2.1.1). |
| `gnap.durableTokens` | `STS_GNAP_DURABLE_TOKENS` | `false` | yes | Section 3.2.1's durable flag: a token survives the grant being modified. |
| `gnap.revokeOnModify` | `STS_GNAP_REVOKE_ON_MODIFY` | `true` | yes | Section 5.3: "The AS MAY revoke previously issued access tokens after a modification has occurred" — unless they were issued durable. |
| `gnap.instanceIds` | `STS_GNAP_INSTANCE_IDS` | `true` | yes | Section 3.5: a client that sent its key by value is handed an instance_id it can send by reference next time. |
| `gnap.continueAfterApproval` | `STS_GNAP_CONTINUE_AFTER_APPROVAL` | `true` | yes | Whether an approved grant's response carries a continue member, so the client can modify (section 5.3) or revoke (section 5.4) it later. |
| `gnap.consentRequired` | `STS_GNAP_CONSENT_REQUIRED` | `true` | yes | Off approves every interactive grant as soon as the resource owner has signed in, with no approval page. |
| `gnap.rememberApprovals` | `STS_GNAP_REMEMBER_APPROVALS` | `true` | yes | Write what a resource owner approved into the consent register on their own entry (as gnap:<digest> values), so the same rights are not asked for again. |
| `gnap.allowCrossUser` | `STS_GNAP_ALLOW_CROSS_USER` | `false` | yes | Section 2.4: when the request named a user and somebody else signs in, the AS SHOULD answer unknown_user. |
| `gnap.userCodeLength` | `STS_GNAP_USER_CODE_LENGTH` | `8` | yes | Section 3.3.3: RECOMMENDED between six and eight characters. |
| `gnap.unknownAccessReferences` | `STS_GNAP_UNKNOWN_ACCESS_REFERENCES` | `accept` | yes | What an access reference string (section 8.1) that names no registered resource set, and is not in the client's gnapAllowedAccess, does: carried onto the token as it stands, or refused with request_denied. |
| `gnap.introspection` | `STS_GNAP_INTROSPECTION` | `true` | yes | RFC 9767 section 3.3. |
| `gnap.resourceRegistration` | `STS_GNAP_RESOURCE_REGISTRATION` | `true` | yes | RFC 9767 section 3.4. |
| `gnap.tokenDerivation` | `STS_GNAP_TOKEN_DERIVATION` | `true` | yes | RFC 9767 section 4: a resource server presents a token it was given as existing_access_token and receives a token for a downstream resource server. |
| `gnap.pushFinish` | `STS_GNAP_PUSH_FINISH` | `true` | yes | Section 4.2.2: an HTTP POST to a URI the CLIENT supplied. |
| `gnap.pushAllowInsecure` | `STS_GNAP_PUSH_ALLOW_INSECURE` | `false` | yes | Push to a plain http URI, or to an https one whose certificate does not verify. |
| `gnap.pushAllowedHosts` | `STS_GNAP_PUSH_ALLOWED_HOSTS` | `` | yes | Host names a push finish may go to. |
| `gnap.pushTimeoutMs` | `STS_GNAP_PUSH_TIMEOUT_MS` | `5000` | yes | How long a push interaction finish may take. |
| `gnap.jweEnc` | `STS_GNAP_JWE_ENC` | `A256GCM` | yes | The enc of a jwt-encrypted token encrypted to a resource server's own key. |

#### ACME

Automatic Certificate Management Environment (RFC 8555), drawn on `/admin/acme`. Every row is settable per trust realm. [docs/acme.md](docs/acme.md) says what each one changes on the wire.

| Appconfig key | Environment variable | Default | Change while running? | What it does |
|---|---|---|---|---|
| `acme.enabled` | `STS_ACME_ENABLED` | `true` | yes | Off makes every /enroll/acme endpoint answer that ACME is turned off in this realm (HTTP 503, an RFC 7807 serverInternal problem naming the setting). |
| `acme.allowedProfiles` | `STS_ACME_ALLOWED_PROFILES` | `tls-server,tls-client,tls-server-client,digital-signature,key-encipherment,code-signing,email,timestamping,smartcard-logon` | yes | The /admin/pki profiles an order may name in its `profile` member (draft-ietf-acme-profiles) and the directory advertises. |
| `acme.defaultProfile` | `STS_ACME_DEFAULT_PROFILE` | `tls-client` | yes | Most ACME clients never name a profile. |
| `acme.certificateLifetimeDays` | `STS_ACME_CERTIFICATE_LIFETIME_DAYS` | `90` | yes | The validity of a certificate issued at finalize, shortened to the ACME Issuing CA's own notAfter. |
| `acme.maxRequestBytes` | `STS_ACME_MAX_REQUEST_BYTES` | `65536` | yes | A flattened JWS larger than this is refused (HTTP 413) before it is parsed. |
| `acme.attemptsPerIdentity` | `STS_ACME_ATTEMPTS_PER_IDENTITY` | `30` | yes | Refused requests one account (or EAB key id) may make in one web-security window before ACME answers rateLimited. |
| `acme.attemptsPerAddress` | `STS_ACME_ATTEMPTS_PER_ADDRESS` | `120` | yes | Refused requests one client address may make in one web-security window before ACME answers rateLimited. |
| `acme.nonceLifetimeS` | `STS_ACME_NONCE_LIFETIME_S` | `300` | yes | How long a Replay-Nonce may wait before it is presented. |
| `acme.orderLifetimeS` | `STS_ACME_ORDER_LIFETIME_S` | `86400` | yes | How long an order stays pending or ready before it expires with its authorizations. |
| `acme.eabLifetimeS` | `STS_ACME_EAB_LIFETIME_S` | `604800` | yes | How long an EAB key issued on the console, through /admin-api or on the user portal may wait before it binds an account. |

#### EST

Enrollment over Secure Transport (RFC 7030), drawn on `/admin/est`. Every row is settable per trust realm. [docs/est.md](docs/est.md) says what each one changes on the wire.

| Appconfig key | Environment variable | Default | Change while running? | What it does |
|---|---|---|---|---|
| `est.enabled` | `STS_EST_ENABLED` | `true` | yes | Off makes every /.well-known/est endpoint answer 503 in this realm. |
| `est.allowedProfiles` | `STS_EST_ALLOWED_PROFILES` | `tls-server,tls-client,tls-server-client,digital-signature,key-encipherment,code-signing,email,timestamping,smartcard-logon` | yes | The /admin/pki profiles an EST label may name (/.well-known/est/<profile>/…). |
| `est.defaultProfile` | `STS_EST_DEFAULT_PROFILE` | `tls-client` | yes | What /.well-known/est/simpleenroll issues, with no label. |
| `est.certificateLifetimeDays` | `STS_EST_CERTIFICATE_LIFETIME_DAYS` | `365` | yes | The validity of an EST certificate, shortened to the EST Issuing CA's own notAfter. |
| `est.maxRequestBytes` | `STS_EST_MAX_REQUEST_BYTES` | `65536` | yes | A PKCS#10 body larger than this is refused (HTTP 413) before it is decoded. |
| `est.attemptsPerIdentity` | `STS_EST_ATTEMPTS_PER_IDENTITY` | `10` | yes | Refused authentications or enrollments one username, client_id or certificate may make in one web-security window before EST answers 429. |
| `est.attemptsPerAddress` | `STS_EST_ATTEMPTS_PER_ADDRESS` | `60` | yes | Refused requests one client address may make in one web-security window before EST answers 429. |
| `est.basicAuthentication` | `STS_EST_BASIC_AUTHENTICATION` | `true` | yes | A person's directory password or an application's client_id and client_secret (RFC 7030 section 3.2.3). |
| `est.certificateAuthentication` | `STS_EST_CERTIFICATE_AUTHENTICATION` | `true` | yes | A client certificate THIS REALM issued, verified to its Intermediate and mapped to its entry by the urn:sts:person: or urn:sts:application: name in it (RFC 7030 section 3.3.2). |
| `est.serverKeyGeneration` | `STS_EST_SERVER_KEY_GENERATION` | `true` | yes | Whether this service generates the key pair (RFC 7030 section 4.4) — the one enrollment path in which it holds a private key, which it then keeps, sealed, on the entry the certificate names. |

#### SCEP

The Simple Certificate Enrolment Protocol (RFC 8894), drawn on `/admin/scep`. Every row is settable per trust realm. [docs/scep.md](docs/scep.md) says what each one changes on the wire.

| Appconfig key | Environment variable | Default | Change while running? | What it does |
|---|---|---|---|---|
| `scep.enabled` | `STS_SCEP_ENABLED` | `true` | yes | Off makes every /enroll/scep request answer 503 in this realm. |
| `scep.allowedProfiles` | `STS_SCEP_ALLOWED_PROFILES` | `tls-server,tls-client,tls-server-client,digital-signature,key-encipherment,code-signing,email,timestamping,smartcard-logon` | yes | The /admin/pki profiles a challenge password may be issued for. |
| `scep.defaultProfile` | `STS_SCEP_DEFAULT_PROFILE` | `tls-client` | yes | The profile preselected when a challenge password is made. |
| `scep.certificateLifetimeDays` | `STS_SCEP_CERTIFICATE_LIFETIME_DAYS` | `365` | yes | The validity of a SCEP certificate, shortened to the SCEP Issuing CA's own notAfter. |
| `scep.maxRequestBytes` | `STS_SCEP_MAX_REQUEST_BYTES` | `262144` | yes | A pkiMessage larger than this — POSTed, or base64 in the GET binding's message parameter — is refused before it is decoded. |
| `scep.attemptsPerIdentity` | `STS_SCEP_ATTEMPTS_PER_IDENTITY` | `10` | yes | Refused PKIOperations one challenge id may cause in one web-security window before SCEP answers 429. |
| `scep.attemptsPerAddress` | `STS_SCEP_ATTEMPTS_PER_ADDRESS` | `60` | yes | Refused requests one client address may make in one web-security window before SCEP answers 429. |
| `scep.challengeLifetimeS` | `STS_SCEP_CHALLENGE_LIFETIME_S` | `3600` | yes | How long a challenge password may wait before it is redeemed. |
| `scep.raKeyAlgorithm` | `STS_SCEP_RA_KEY_ALGORITHM` | `rsa-2048` | yes | SCEP encrypts the request to the RA with RSA key transport (RFC 8894 section 3.1), so the RA certificate is RSA whatever the SCEP Issuing CA is. |
| `gnap.demoResourceServer` | `STS_GNAP_DEMO_RESOURCE_SERVER` | `true` | yes | GET/POST /gnap/rs/resource: judges a presented token in any of the five formats and answers the RS-first challenge of section 9.1. |
| `gnap.caepEvents` | `STS_GNAP_CAEP_EVENTS` | `true` | yes | A grant or token revoked sends session-revoked, and a grant modified onto different access sends token-claims-change, to every stream that takes them. |
| `gnap.scopedSignals` | `STS_GNAP_SCOPED_SIGNALS` | `true` | yes | A Shared Signals stream owned by a GNAP client application with a finish URI carries events only about people who approved a grant to that application. |

#### Web security

Sessions, the sign-in clocks, this service's own OpenID Connect client, and
passwords. Added 2026-09-12; every default is the literal it replaced, so an
unedited service behaves exactly as it did.

| Appconfig key | Environment variable | Default | Change while running? | What it does |
|---|---|---|---|---|
| `authn.sessionLifetimeS` | `STS_AUTHN_SESSION_LIFETIME_S` | `3600` | yes — applies to the next session | How long a sign-on session lasts from creation, and with it the console's and the portal's own sessions. ABSOLUTE for a browser; an API client's session is extended by this much on every call. |
| `authn.sessionIdleTimeoutS` | `STS_AUTHN_SESSION_IDLE_TIMEOUT_S` | `0` | yes — applies to sessions that already exist | How long a session may go unused before it ends, on top of the lifetime. **Zero means no idle timeout**, which is what this service has always done. A request to the console or the portal counts as use of the sign-on session behind it. |
| `authn.pendingTtlS` | `STS_AUTHN_PENDING_TTL_S` | `600` | yes | How long a sign-in waits at the screen — and the console's and portal's own authorization code flows, and an arrival session's inactivity window, which are the same clock on purpose. |
| `authn.mfaStepTtlS` | `STS_AUTHN_MFA_STEP_TTL_S` | `300` | yes | How long somebody past the password step has to present a security key, a one-time code or a recovery code. |
| `authn.mfaRequired` | `STS_AUTHN_MFA_REQUIRED` | `false` | yes | Require a second factor — an authenticator app or a security key in the `mfa` role — of everybody who signs in at this realm's sign-in screen. Somebody who holds neither is shown `/authn/mfa-setup` after their password is accepted and gets no session until one is enrolled; a passwordless security-key sign-in is refused. The same requirement can be placed on one person from their `/admin/users` page. **It is enforced at the sign-in screen only**: a federated assertion, a SPNEGO ticket, a TLS client certificate, the OAuth password grant, an LDAP bind, WS-Trust and SCIM Basic do not meet it. |
| `oidcRp.maxFlows` | `STS_OIDC_RP_MAX_FLOWS` | `200` | yes | Console and portal sign-ins in flight at once, per trust realm; past it the oldest is dropped. |
| `oidcRp.backChannelTimeoutS` | `STS_OIDC_RP_BACK_CHANNEL_TIMEOUT_S` | `10` | yes | How long the console and the portal wait for this service's own token endpoint and JWKS over the loopback interface. |
| `oidcRp.maxRedirectUris` | `STS_OIDC_RP_MAX_REDIRECT_URIS` | `20` | yes | The most redirect URIs `sts-admin-console` and `sts-user-portal` may carry before a sign-in at a new address stops adding its callback. **Learning happens only in development mode with `global.publicBaseUrl` empty**; in product mode an address the entry does not carry is REFUSED, and a pinned base is never learnt. |
| `oidcRp.renewBeforeExpiryS` | `STS_OIDC_RP_RENEW_BEFORE_EXPIRY_S` | `60` | yes | How long before their ID Token or access token runs out the console and the portal renew them with the refresh token grant, on the next request. **The renewal is inside the same session** — same cookie, same page, no sign-in — and a session renews for at most the refresh token's lifetime from its sign-in (`oauth2.refreshTokenTtlS`, or the client's `oauthRefreshTokenTtlS`). `0` renews only once they have run out. |
| `security.passwordHashLogN` | `STS_SECURITY_PASSWORD_HASH_LOG_N` | `15` | yes | log2 of scrypt's N for a NEWLY stored password, client secret, activation token or recovery code; 14 is the floor. A stored hash carries its own parameters and keeps verifying. |
| `security.passwordHashR` | `STS_SECURITY_PASSWORD_HASH_R` | `8` | yes | scrypt's block size for a new hash. |
| `security.passwordHashP` | `STS_SECURITY_PASSWORD_HASH_P` | `1` | yes | scrypt's parallelism for a new hash. |
| `security.passwordResetTtlMinutes` | `STS_SECURITY_PASSWORD_RESET_TTL_MINUTES` | `60` | yes | How long a password reset link an administrator issues from a person's `/admin/users` page stays usable at `/portal/reset-password`. Issuing one also removes the person's current password and signs them out everywhere, so the link is the only way back in until it is used or another is issued. |
| `credentials.factorScanLimit` | `STS_CREDENTIALS_FACTOR_SCAN_LIMIT` | `5000` | yes | How many directory entries the second-factor columns on `/admin/users` and `GET /admin-api/mfa` read before stopping; the reply says when it stopped. |

#### OAuth 2.0 / OIDC

| Appconfig key | Environment variable | Default | Change while running? | What it does |
|---|---|---|---|---|
| `oauth2.issuer` | `STS_OAUTH2_ISSUER` | *(empty)* | yes | The `issuer` in the RFC 8414 and OpenID Provider metadata, and the `iss` of every token signed here. |
| `oauth2.rfc9700` | `STS_OAUTH2_RFC9700` | `false` | **restart** — it decides whether the main port is bound as HTTPS (global.https), and a listener is bound when the process starts. A **trust realm** may carry it even so: a realm binds no socket, so only the mode's checks change | Enforce RFC 9700 (OAuth 2.0 Security Best Current Practice) on the authorization flow: exact-string redirect URI matching with the loopback port exception, no open redirects, no http redirect URI off the loopback, PKCE required of public clients with S256 only, PKCE downgrade and value-reuse refused, a nonce required with any id_token, and no response type that issues an access token from the authorization endpoint. |
| `oauth2.oauth21` | `STS_OAUTH2_OAUTH21` | `false` | **restart** — it turns RFC 9700 mode on, which decides whether the main port is bound as HTTPS (global.https). A **trust realm** may carry it even so: a realm binds no socket | Enforce the OAuth 2.1 Authorization Framework (draft-ietf-oauth-v2-1-16, still an Internet-Draft). It turns RFC 9700 mode on and adds PKCE for confidential clients (unless one relies on the OpenID Connect nonce), `code_challenge_method` required, a client that registered its own redirect URI (`oauth2.redirectUris` is not read), a token request naming an undeclared client refused, a presented credential that must verify, one authentication method per request, client credentials for authenticated clients only, a JWT client assertion addressed to the issuer alone, no SAML client authentication, no repeated parameters, a ten-minute code and `error_description`'s grammar. A token request may omit `redirect_uri`, and an authorization request may omit it when the client registered one. `GET /oauth2/oauth21` lists every requirement. |
| `oauth2.delegatedPermissionsEnforced` | `STS_OAUTH2_DELEGATED_PERMISSIONS_ENFORCED` | `false` | yes | REFUSE an authorization or token request that asks for a permission the client has not been granted. A permission is defined on a resource application — a base URI and a name, joined into `https://example.com/write` — and granted to a client application on its own entry; `/admin/delegation` is the register and defines both. With this OFF (the default) an ungranted permission is still honoured: the token is audienced to the base URI and carries the permission name on its scope claim exactly as a granted one would, and the console marks it. With it ON the same request is refused `invalid_scope` at the AUTHORIZATION endpoint — where the client can still be told — and at the token endpoint for the grants that never reach it. A scope naming no defined permission is unaffected in both modes. It does NOT re-judge a grant already issued. |
| `oauth2.consentRequired` | `STS_OAUTH2_CONSENT_REQUIRED` | **`true`** — the one policy here that is on by default | yes | ASK THE PERSON before the authorization endpoint issues anything for a scope they have not already agreed to for that application. The first time a given username signs in to a given `client_id` for a given scope, `/oauth2/consent` is drawn listing the scopes that are new; nothing is issued until they press Allow, and Deny returns `access_denied` to the client. The answer is written to `oauthConsent` on that person's own entry under `ou=users` — one value per (person, application, scope), spelled `<when> <scope> <client_id>` — so the second sign-in is silent and an `ldapsearch` can read what somebody agreed to. A delegated permission is recorded by its WHOLE identifier (`https://example.com/write`) and never by the bare permission name, because two resources may each expose a `read`. `oauthGlobalConsent` on an APPLICATION's entry consents a scope for everybody who signs in to it and writes nothing about anybody — an override rather than a record, so removing it asks everybody again. `prompt=consent` asks again whatever is on the entry; `prompt=none` with something outstanding is `consent_required`. With this OFF nothing is asked and nothing is recorded, which is what this service did before the screen existed — it is NOT "everybody consented". `/admin/consent` is the register. |
| `oauth2.tokenExchangeRefreshToken` | `STS_OAUTH2_TOKEN_EXCHANGE_REFRESH_TOKEN` | `when-requested` | yes | WHETHER AN RFC 8693 TOKEN EXCHANGE HANDS BACK A `refresh_token` beside the exchanged access token. Section 2.2.1 makes it OPTIONAL and names the case it is for: a client that must keep reaching a resource "even when the original credential is no longer valid" — the user-not-present case, where there is no session by design. Three values. `when-requested` is the default and is section 2.1 read literally — the client asks with `requested_token_type=urn:ietf:params:oauth:token-type:refresh_token` and gets one only if it did. `never` refuses the ask silently: the exchange still succeeds, with no refresh token in it, which is what this service did before the parameter was implemented. `always` hands one to every exchange whether it asked or not, which is how several deployed authorization servers behave and is the path a client written against the other two has never run. What comes back is an ORDINARY refresh token of this service in every case — redeemable at the refresh grant, revocable, subject to `oauth2.refreshTokenTtlS`, rotated in RFC 9700 mode, and bound to the DPoP key or client certificate the exchange was made with — and `issued_token_type` says `access_token` throughout, because it describes the token in the `access_token` member. `oauthTokenExchangeRefreshToken` on the CLIENT application's entry overrides it for that client alone. |
| `oauth2.breakIdTokenNonce` | `STS_OAUTH2_BREAK_ID_TOKEN_NONCE` | `false` | yes | Put a DELIBERATELY WRONG nonce in every ID Token that should carry one. |
| `oauth2.refreshIdleSeconds` | `STS_OAUTH2_REFRESH_IDLE_SECONDS` | `86400` | yes | In RFC 9700 mode, how long a refresh CHAIN may go unused before it stops working — section 2.2.2 says a refresh token SHOULD expire after a period of client inactivity, and says the period is deployment-dependent, which is why this is a setting rather than a constant. |
| `oauth2.revokeRefreshOnLogout` | `STS_OAUTH2_REVOKE_REFRESH_ON_LOGOUT` | `true` | yes | In RFC 9700 mode, end a browser sign-on session and every refresh token issued ON that session is revoked — the section MAY that names logout and a password change as the examples. |
| `oauth2.frontchannelLogout` | `STS_OAUTH2_FRONTCHANNEL_LOGOUT` | `true` | yes | OpenID Connect Front-Channel Logout 1.0: the two discovery members, the `sid` claim on an ID Token issued on a browser sign-on session, and a hidden iframe per registered `frontchannel_logout_uri` on every sign-out — with `iss` and `sid` where the client registered `frontchannel_logout_session_required`. Off, none of the three happens and the tokens are byte-for-byte what this service issued before the feature existed. |
| `oauth2.eddsaCurve` | `STS_OAUTH2_EDDSA_CURVE` | `Ed25519` | yes | Which Edwards curve an `EdDSA` signature is made on (`Ed25519` or `Ed448`). RFC 8037 registers ONE algorithm value for both curves and puts the curve in the key itself, so a client registering `id_token_signed_response_alg="EdDSA"` has no way to say which it wants — this is that way. BOTH keys are published in the JWKS whatever this is set to, with different kids, so a verifier follows the kid and needs to know nothing about this setting. |
| `oauth2.clientAssertionSkewS` | `STS_OAUTH2_CLIENT_ASSERTION_SKEW_S` | `60` | yes | How far out an assertion's exp, nbf and iat may be and still be accepted (RFC 7523 section 3). It applies to BOTH halves of that profile — the `client_assertion` of section 2.2 and the `assertion` of the section 2.1 grant — because it answers "how far out may somebody else's clock be" and this service has no reason to hold two opinions about that. Sixty seconds is the usual allowance for two machines that are not synchronised. |
| `oauth2.jwtBearerGrant` | `STS_OAUTH2_JWT_BEARER_GRANT` | `true` | yes | Whether the token endpoint performs `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer` (RFC 7523 section 2.1). The metadata advertises the grant only while it is on, because a `grant_types_supported` member is a promise. It does NOT affect section 2.2 — client authentication by assertion — which is a different feature sharing a document format. |
| `oauth2.jwtBearerRequireRegisteredIssuer` | `STS_OAUTH2_JWT_BEARER_REQUIRE_REGISTERED_ISSUER` | `true` | yes | Whether that grant is refused when no application in the realm declares the assertion's `iss` on `oauthAssertionIssuer`. **ON, and it is one of only two refusals here that default to on** — federation is the other, for the same reason. Turning it off does not make the grant accept unsigned assertions; the signature still has to verify against a key registered for the issuer or a certificate this service issued. |
| `oauth2.jwtBearerMaxLifetimeS` | `STS_OAUTH2_JWT_BEARER_MAX_LIFETIME_S` | `300` | yes | The most seconds between an assertion's `iat` and its `exp` that this authorization server will accept in an RFC 7523 grant. RFC 7521 section 5.2 invites a server to refuse an assertion whose lifetime is unreasonable and leaves "unreasonable" to it; a short life is the whole difference between an assertion and a long-lived credential somebody has to be able to revoke. ZERO switches the check off, which is the way to exercise a client that mints day-long assertions. An assertion with no `iat` is measured from NOW to its `exp` — until 2026-09-12 it was not checked at all, so leaving out the optional claim was the way round the ceiling. IN PRODUCT MODE the same ceiling also applies to an RFC 7523 CLIENT assertion (private_key_jwt, client_secret_jwt), which there must carry an `exp` as well; development leaves client assertions uncapped, as it always did. |
| `oauth2.saml2BearerGrant` | `STS_OAUTH2_SAML2_BEARER_GRANT` | `true` | yes | Whether the token endpoint performs `grant_type=urn:ietf:params:oauth:grant-type:saml2-bearer` (RFC 7522 section 2.1). The metadata advertises the grant only while it is on. **It is a separate setting from `oauth2.jwtBearerGrant` and not the same switch**: RFC 7522 and RFC 7523 are two profiles of one framework and a deployment legitimately offers one and not the other, so a single switch would make "turn the JWT grant off" also turn off a grant a SAML deployment depends on. It does NOT affect section 2.2 — client authentication by SAML assertion. |
| `oauth2.saml2BearerRequireRegisteredIssuer` | `STS_OAUTH2_SAML2_BEARER_REQUIRE_REGISTERED_ISSUER` | `true` | yes | Whether that grant is refused when no application in the realm declares the assertion's `<Issuer>` on `oauthSamlAssertionIssuer`. **ON**, for the reason the JWT row above is on. Turning it off does not make the grant accept unsigned assertions, and it does not make it accept a certificate this service holds no registration for: a SAML assertion is only ever verified against a certificate registered against the asserting party under the RFC 7522 attributes, and there is no setting that changes that. |
| `oauth2.saml2BearerMaxLifetimeS` | `STS_OAUTH2_SAML2_BEARER_MAX_LIFETIME_S` | `300` | yes | The most seconds between a SAML assertion's `IssueInstant` and its expiry that this authorization server accepts. RFC 7522 section 3 item 6 says a server may reject an assertion whose `NotOnOrAfter` is unreasonably far in the future and leaves "unreasonable" to it. Zero switches the check off. The expiry it measures to is the `<Conditions>` `NotOnOrAfter` where there is one and the `<SubjectConfirmationData>` one otherwise, which is item 4's own ordering. |
| `oauth2.assertionReplayCacheSize` | `STS_OAUTH2_ASSERTION_REPLAY_CACHE_SIZE` | `1000` | yes | How many unexpired rows the USED-ASSERTION HISTORY holds per trust realm: every RFC 7523 JWT and RFC 7522 SAML assertion accepted, as client authentication or as a grant, in ONE history (it was three caches until 2026-09-13). The history persists in the ldif and postgres stores in both modes, so this bounds a file or a table as well as memory. **A FULL HISTORY REFUSES THE NEXT ASSERTION RATHER THAN FORGETTING A LIVE ONE**: until 2026-09-12 the caches dropped their oldest entry whether or not it had expired, which let a captured assertion be replayed as soon as a thousand newer ones had pushed it out. Expired rows are swept first, so the refusal is reached only by that many assertions being live at once — raise this, or shorten oauth2.jwtBearerMaxLifetimeS, rather than accept a replay window. /admin/used-assertions lists what is held. |
| `oauth2.dpopNonceRequired` | `STS_OAUTH2_DPOP_NONCE_REQUIRED` | `false` | yes | Require every DPoP proof to carry a nonce this server supplied (RFC 9449 sections 8 and 9), which turns the first request of a session into a 401 or 400 and a retry. It makes proofs FRESHER and never makes them mandatory: a request with no DPoP header is still a Bearer request. PER TRUST REALM since 2026-09-12 — it was one switch for the whole process, so a realm turning it on turned it on for every other. In development POST /dpop/nonce-mode writes this setting for the realm it is reached in; in product that endpoint refuses and this row — through /admin/oauth2 or POST /admin-api/config/set, both behind a credential — is the only way to change it. |
| `oauth2.dpopIatSkewS` | `STS_OAUTH2_DPOP_IAT_SKEW_S` | `300` | yes | How far a DPoP proof's `iat` may be from now, either way (RFC 9449 section 11.1). It is how long a captured proof stays useful for the same method and URI, so it is short; the jti replay cache remembers a proof for twice this, so the two cover the same span. |
| `oauth2.dpopNonceTtlS` | `STS_OAUTH2_DPOP_NONCE_TTL_S` | `300` | yes | How long a server-supplied DPoP nonce is accepted after it was handed out. Only read while oauth2.dpopNonceRequired is on. |
| `oauth2.openRegistration` | `STS_OAUTH2_OPEN_REGISTRATION` | `false` | yes | Whether POST /oauth2/register (RFC 7591) accepts a registration from anybody who can reach it IN PRODUCT MODE. Development always does — it is how a client under test registers itself — and this setting changes nothing there. In product it is OFF, the endpoint refuses with `access_denied` naming this setting, and `registration_endpoint` is left out of both discovery documents: a published endpoint that refuses every caller is a promise broken. Create applications through /admin or /admin-api instead, which require a credential. Turning it on is a decision to let the internet mint confidential clients on this authorization server. |
| `oauth2.softwareStatementRequireTrustedIssuer` | `STS_OAUTH2_SOFTWARE_STATEMENT_REQUIRE_TRUSTED_ISSUER` | `true` | yes | Whether registration refuses a `software_statement` whose issuer nothing in this realm trusts, with `unapproved_software_statement`, in both modes. Off, such a statement is accepted UNVERIFIED: its claims lose to the JSON, the entry records it as untrusted, and it never opens a closed endpoint. A malformed, unsigned, badly signed or expired statement is refused either way. |
| `oauth2.softwareStatementOpensRegistration` | `STS_OAUTH2_SOFTWARE_STATEMENT_OPENS_REGISTRATION` | `true` | yes | Whether a registration carrying a TRUSTED software statement is accepted where `POST /oauth2/register` is otherwise closed (product mode, `oauth2.openRegistration` off). While on, `registration_endpoint` stays advertised, and a client registered this way must present a trusted statement from the same issuer with every RFC 7592 update. |
| `oauth2.softwareStatementRequired` | `STS_OAUTH2_SOFTWARE_STATEMENT_REQUIRED` | `false` | yes | Whether registration and RFC 7592 updates refuse a document carrying no `software_statement`, with `invalid_software_statement`. |
| `oauth2.authorizationDetailsMaxEntries` | `STS_OAUTH2_AUTHORIZATION_DETAILS_MAX_ENTRIES` | `20` | yes | How many objects one RFC 9396 `authorization_details` array may carry at the authorization, token and pushed authorization request endpoints. A longer array is refused `invalid_authorization_details` before any type's schema is run. |
| `oauth2.requireSignedRequestObject` | `STS_OAUTH2_REQUIRE_SIGNED_REQUEST_OBJECT` | `false` | yes | RFC 9101 section 10.5 for the whole realm: an authorization request with no request object, or with an unsigned one, is refused. Published as `require_signed_request_object`, and `none` leaves `request_object_signing_alg_values_supported`. A client's own `require_signed_request_object` and a named authorization server's member do the same for that client or that server. |
| `oauth2.requireRequestObjectType` | `STS_OAUTH2_REQUIRE_REQUEST_OBJECT_TYPE` | `false` | yes | Whether a request object must carry `typ: oauth-authz-req+jwt`. Off, a missing `typ` or `JWT` is accepted and only a JWT typed as something ELSE (section 10.8) is refused. |
| `oauth2.requireRequestObjectIssuerAudience` | `STS_OAUTH2_REQUIRE_REQUEST_OBJECT_ISSUER_AUDIENCE` | `false` | yes | Whether a request object must carry `iss` and `aud`. They are checked wherever present either way: `iss` must be the client and `aud` this authorization server's issuer or its authorization endpoint. |
| `oauth2.requestUriTimeoutMs` | `STS_OAUTH2_REQUEST_URI_TIMEOUT_MS` | `5000` | yes | How long fetching a registered `request_uri` may take before the request is refused `invalid_request_uri`. |
| `oauth2.requestUriMaxBytes` | `STS_OAUTH2_REQUEST_URI_MAX_BYTES` | `65536` | yes | The largest request object a `request_uri` may answer with; a longer answer is abandoned and refused. |
| `oauth2.requestUriCacheS` | `STS_OAUTH2_REQUEST_URI_CACHE_S` | `0` | yes | How long a fetched request object is reused for the same `request_uri` (OpenID Connect Core section 6.2). Zero fetches on every request — and the authorization endpoint runs each request twice, before and after sign-in. A fragment names a version, so a changed fragment is a different entry. |
| `oauth2.requestObjectEncryptionKeyBits` | `STS_OAUTH2_REQUEST_OBJECT_ENCRYPTION_KEY_BITS` | `2048` | yes | The size of the realm's RSA request object encryption key, published in the JWKS with `use: "enc"`. Read when a key set is made. |
| `oauth2.requestObjectEncryptionCurve` | `STS_OAUTH2_REQUEST_OBJECT_ENCRYPTION_CURVE` | `P-256` | yes | The curve of the realm's EC request object encryption key (ECDH-ES), published beside the RSA one. Read when a key set is made. |
| `oauth2.pushedAuthorizationRequests` | `STS_OAUTH2_PUSHED_AUTHORIZATION_REQUESTS` | `true` | yes | RFC 9126: offer `POST /oauth2/par` and publish `pushed_authorization_request_endpoint`. Off, the member is removed and the endpoint answers 404; a `request_uri` already issued stays usable. |
| `oauth2.requirePushedAuthorizationRequests` | `STS_OAUTH2_REQUIRE_PUSHED_AUTHORIZATION_REQUESTS` | `false` | yes | RFC 9126 section 4 for the whole realm: an authorization request that was not pushed is refused `invalid_request`. Published as `require_pushed_authorization_requests`. A client's own member and a named authorization server's do the same for that client or server. |
| `oauth2.parRequestUriLifetimeS` | `STS_OAUTH2_PAR_REQUEST_URI_LIFETIME_S` | `60` | yes | The `expires_in` of a pushed `request_uri`, 5 to 600 seconds. It covers the whole sign-in: the `request_uri` is read again after the sign-in and consent screens and spent when the authorization response is issued. |
| `oauth2.parMaxRequests` | `STS_OAUTH2_PAR_MAX_REQUESTS` | `10000` | yes | How many live pushed requests one realm holds. Expired ones are swept first; a full store refuses the next push 503 rather than forgetting a live one. |
| `oauth2.parMaxBodyBytes` | `STS_OAUTH2_PAR_MAX_BODY_BYTES` | `65536` | yes | The largest body `/oauth2/par` accepts; a larger one is 413. |
| `oauth2.parRequestsPerMinute` | `STS_OAUTH2_PAR_REQUESTS_PER_MINUTE` | `600` | yes | Pushes one client_id may make from one address per `security.rateLimitWindowS` before a 429 (the address bucket is ten times this). |
| `oauth2.parAllowUnregisteredRedirectUris` | `STS_OAUTH2_PAR_ALLOW_UNREGISTERED_REDIRECT_URIS` | `false` | yes | RFC 9126 section 2.4: a client that authenticated at the push may name a redirect URI it never registered. A public client never may; asked again when the `request_uri` is used. |
| `oauth2.stepUpAcrValues` | `STS_OAUTH2_STEP_UP_ACR_VALUES` | *(empty)* | yes | RFC 9470 section 3 at this service's own resource server (UserInfo, the OpenID4VCI endpoints, SCIM, Shared Signals): space-separated acr values, most preferred first. A token meeting none is challenged 401 `insufficient_user_authentication`. Ordered `0` < `1` < `mfa`. Empty requires nothing. |
| `oauth2.stepUpMaxAgeS` | `STS_OAUTH2_STEP_UP_MAX_AGE_S` | `-1` | yes | RFC 9470's `max_age` at the same endpoints: a token whose `auth_time` is older, or absent, is challenged. `-1` requires nothing; `0` is a real requirement. |
| `oauth2.softwareStatementLifetimeS` | `STS_OAUTH2_SOFTWARE_STATEMENT_LIFETIME_S` | `31536000` | yes | The `exp` of a software statement this realm issues, as seconds after issue, unless the issue request names its own. Zero issues one with no `exp`. |
| `oauth2.registeredSecretLifetimeS` | `STS_OAUTH2_REGISTERED_SECRET_LIFETIME_S` | `0` | yes | The `client_secret_expires_at` RFC 7591 section 3.2.1 publishes for a client registered at POST /oauth2/register, as seconds after registration. ZERO, the default, is that section's own "never", which is what this service always said. It is stamped when the client registers and is not moved by a later change. |
| `oauth2.registeredClientIdPrefix` | `STS_OAUTH2_REGISTERED_CLIENT_ID_PREFIX` | `sts-client-` | yes | What a client_id minted by POST /oauth2/register starts with, before its random part. RFC 7591 leaves the shape to the server; a prefix is how an operator tells a dynamically registered client from one created by hand in a list. |
| `oauth2.registeredClientIdBytes` | `STS_OAUTH2_REGISTERED_CLIENT_ID_BYTES` | `8` | yes | How many random bytes follow the prefix in a registered client_id, base64url-encoded. A client_id is not a secret, so this is about collisions and not about guessing. |
| `oauth2.registeredSecretBytes` | `STS_OAUTH2_REGISTERED_SECRET_BYTES` | `24` | yes | How many random bytes make a registered client's `client_secret` and its RFC 7592 `registration_access_token`. Both ARE secrets, which is why the floor is 16 bytes (128 bits). |
| `oauth2.authorizationCodeTtlS` | `STS_OAUTH2_AUTHORIZATION_CODE_TTL_S` | `300` | yes | How long an authorization code may wait to be redeemed. RFC 6749 section 4.1.2 recommends at most ten minutes. It is ALSO what RFC 9700 mode's transaction memory is measured from — a PKCE challenge or nonce is remembered for twice this — so the two cannot drift apart. A code already issued keeps the expiry it was minted with. |
| `oauth2.maxPendingTransactions` | `STS_OAUTH2_MAX_PENDING_TRANSACTIONS` | `500` | yes | How many authorization transactions RFC 9700 mode remembers to refuse a reused PKCE challenge or nonce. Past it the oldest is forgotten, and a forgotten one is a reuse check NOT made rather than a false refusal — which is the safe direction for this cache, because what it protects against is a client bug and not a captured credential. |
| `oauth2.maxRefreshTokenFamilies` | `STS_OAUTH2_MAX_REFRESH_TOKEN_FAMILIES` | `2000` | yes | How many refresh tokens RFC 9700 mode tracks for rotation and replay detection. When it is full, EXPIRED ones are forgotten first, then ROTATED ones (already revoked, so a replay of one is still refused — what is lost is the whole-family revocation that replay would trigger), and only then the oldest live one, with a warning. A live one forgotten still works; its next rotation starts a new family. Raise it for a deployment with more concurrently live refresh tokens than this. |
| `oauth2.signedMetadataAlgorithm` | `STS_OAUTH2_SIGNED_METADATA_ALGORITHM` | `RS256` | yes | The JWS algorithm of the `signed_metadata` member of the RFC 8414 document, the OpenID Provider Configuration and the OID4VCI issuer metadata. Every value is one this realm holds a key for, and every key is in /oauth2/jwks under its own kid. The post-quantum algorithms are deliberately not offered: discovery is the most-fetched endpoint here and is signed on the request thread. |
| `oauth2.signedMetadataCacheS` | `STS_OAUTH2_SIGNED_METADATA_CACHE_S` | `60` | yes | How long one signature over an unchanged metadata document is served before it is signed again. ZERO signs per request. The ceiling is half the signature's own hour, so a caller is never handed one about to expire. |
| `oauth2.maxSignedMetadataEntries` | `STS_OAUTH2_MAX_SIGNED_METADATA_ENTRIES` | `64` | yes | How many distinct signed metadata documents are cached. The key includes the base URL a request arrived on, which comes off the Host header, so it has to be bounded. |
| `oauth2.basicAuthRealm` | `STS_OAUTH2_BASIC_AUTH_REALM` | `sts` | yes | The `realm` in the `WWW-Authenticate: Basic` challenge the token endpoint answers a failed client_secret_basic with (RFC 7617 section 2). A browser shows it in its credential prompt, which is why a deployment names itself here. |
| `oauth2.maxAuthorizationServerProfiles` | `STS_OAUTH2_MAX_AUTHORIZATION_SERVER_PROFILES` | `200` | yes | How many path-selected authorization server profiles are RECORDED. A name past it is still served with the defaults and simply not recorded, because the name comes off a URL path and a load generator must not take the feature away from the names that matter. |
| `oauth2.maxRequestedClaims` | `STS_OAUTH2_MAX_REQUESTED_CLAIMS` | `64` | yes | The most claims one OpenID Connect Core section 5.5 claims request may name, across its members. The request rides inside the access token, so this also bounds the token. |
| `pki.keyAlgorithm` | `STS_PKI_KEY_ALGORITHM` | `rsa-2048` | yes | Which key algorithm a new certificate authority is built with when the form names none: `rsa-2048`, `rsa-3072`, `rsa-4096`, `ec-p256`, `ec-p384`, `ec-p521` or `ed25519`. RSA 2048 because the LEAF this chain exists to issue signs a client assertion somebody else's OAuth library has to verify. |
| `pki.signatureAlgorithm` | `STS_PKI_SIGNATURE_ALGORITHM` | *(empty)* | yes | Which signature algorithm the tiers sign each other with. **Empty means "the right one for the key algorithm"**, which is what almost every deployment wants: an EC key's digest is decided by its CURVE, and a fixed value here would hand a P-521 key SHA-256 — legal, verifying, and nobody's intention. |
| `pki.organisation` | `STS_PKI_ORGANISATION` | `sts` | yes | The `O=` every tier of a new hierarchy carries, and what the tiers are named after when the form gives no common names. |
| `pki.leafLifetimeDays` | `STS_PKI_LEAF_LIFETIME_DAYS` | `365` | yes | How long a signing certificate issued to an application or a person is good for when the request names no lifetime — every door that issues one, since 2026-09-12. **Clamped** to the Issuing CA's own expiry rather than refused where it would overshoot. |
| `pki.personSelfService` | `STS_PKI_PERSON_SELF_SERVICE` | `true` | yes | Whether `/portal/signing-key` lets a person issue **themselves** an RFC 7523 or RFC 7522 key pair (one switch for both). The key can only assert about its own holder, so it is a credential for an account they are already signed in to. **Turning it off takes nobody's key away** — one already on an entry goes on verifying — and it stops new ones from the PORTAL only; `/admin/pki` and `POST /admin-api/pki/issue` are an operator's door and are unaffected. |
| `pki.personSelfServicePerIdentity` | `STS_PKI_PERSON_SELF_SERVICE_PER_IDENTITY` | `5` | yes | How many self-issued key pairs one person may generate on `/portal/signing-key` per `security.rateLimitWindowS` window. |
| `pki.personSelfServicePerAddress` | `STS_PKI_PERSON_SELF_SERVICE_PER_ADDRESS` | `5` | yes | The same limit per client ADDRESS, counted across everybody behind it — its own row so a deployment reached through one NAT can raise it without raising what one person may do. |
| `pki.personTlsClientCertificateMax` | `STS_PKI_PERSON_TLS_CLIENT_CERTIFICATE_MAX` | `5` | yes | How many still-valid TLS client certificates one person may issue themselves on `/portal/signing-key` — one per browser or device. Revoked and expired ones do not count; past it the portal refuses rather than revoking one somebody may still use. |
| `pki.rootLifetimeYears` | `STS_PKI_ROOT_LIFETIME_YEARS` | `0` | yes | How long a Root CA is built for when the build names no lifetime. **Zero is the `root-ca` profile's own twenty years.** |
| `pki.intermediateLifetimeYears` | `STS_PKI_INTERMEDIATE_LIFETIME_YEARS` | `0` | yes | The same for an Intermediate CA — at startup, for a realm created at runtime, and for a branch rebuilt under a replaced Root. Zero is the profile's ten. |
| `pki.issuingLifetimeYears` | `STS_PKI_ISSUING_LIFETIME_YEARS` | `0` | yes | The same for each Issuing CA. Zero is the profile's five. |
| `pki.maxStoredObjects` | `STS_PKI_MAX_STORED_OBJECTS` | `200` | yes | How many objects the Certificate & Key Configuration pane keeps per realm. **A full store refuses the next one** rather than discarding the oldest, which may carry a private key somebody kept. |
| `pki.revocationCheck` | `STS_PKI_REVOCATION_CHECK` | `auto` | yes | Whether a certificate PRESENTED to this service — on 8443/9443, on the main port (XACML, SCIM, RFC 8705 client authentication), at the SPIRE Server API or in an assertion's `x5c` — is checked for revocation: `off`, `soft-fail` (refuse a revoked one), `hard-fail` (refuse one whose status could not be established too). One this service issued is looked up in its own register; one from another authority against the CRL it names. **`auto` is hard-fail in product mode and soft-fail in development.** |
| `pki.revocationRequireDistributionPoint` | `STS_PKI_REVOCATION_REQUIRE_DISTRIBUTION_POINT` | `false` | yes | Under hard-fail, whether a foreign certificate naming no http/https CRL distribution point is refused. Off by default: there is no fetch an attacker could block, and refusing it makes every private CA without a CRL unusable. |
| `pki.revocationFetchTimeoutMs` | `STS_PKI_REVOCATION_FETCH_TIMEOUT_MS` | `3000` | yes | How long fetching a foreign CRL may take. |
| `pki.revocationMaxCrlBytes` | `STS_PKI_REVOCATION_MAX_CRL_BYTES` | `1048576` | yes | The largest CRL fetched; a bigger answer is refused as unreachable. |
| `pki.revocationCrlCacheEntries` | `STS_PKI_REVOCATION_CRL_CACHE_ENTRIES` | `256` | yes | How many verified foreign CRLs (and remembered failures) are held in memory. |
| `pki.revocationCrlMaxAgeS` | `STS_PKI_REVOCATION_CRL_MAX_AGE_S` | `3600` | yes | A cached CRL is used until its own `nextUpdate` or this long after it was fetched, whichever is sooner. |
| `pki.revocationFailureRetryS` | `STS_PKI_REVOCATION_FAILURE_RETRY_S` | `60` | yes | How long an unreachable or unusable CRL is remembered before it is dialled again. Zero retries on every request. |
| `pki.revocationOcsp` | `STS_PKI_REVOCATION_OCSP` | `first` | yes | Whether the OCSP responder a foreign certificate names is asked (RFC 6960): `first` (before the CRL, which is the fallback), `after-crl` (only when the CRL gave no answer) or `off`. A signed `unknown` is never upgraded to good by a CRL; a CRL that revokes still wins. |
| `pki.revocationOcspMaxAgeS` | `STS_PKI_REVOCATION_OCSP_MAX_AGE_S` | `3600` | yes | How long an OCSP response with no `nextUpdate` is fresh after its `thisUpdate`, and the longest any response is cached. |
| `pki.revocationOcspRequireNonce` | `STS_PKI_REVOCATION_OCSP_REQUIRE_NONCE` | `false` | yes | Every OCSP request carries a nonce and a response echoing a different one is always refused. Turn this on to refuse a response that echoes none too — off by default, because the pre-produced responses most large responders serve cannot carry one. |
| `pki.revocationClockSkewS` | `STS_PKI_REVOCATION_CLOCK_SKEW_S` | `300` | yes | How far a CRL's or OCSP response's `nextUpdate` may be in the past, and an OCSP `thisUpdate` in the future, before it is refused. Zero is legal. |
| `pki.revocationCrlIssuersFile` | `STS_PKI_REVOCATION_CRL_ISSUERS_FILE` | *(empty)* | yes | A PEM file of certificates that may sign an INDIRECT CRL a certificate's `cRLIssuer` names. Also looked for in the presented chain, among this service's own authorities, and at the caIssuers address the CRL itself names; in every case it must carry `cRLSign` and chain to an authority the presented chain passes through. |
| `pki.revocationLdap` | `STS_PKI_REVOCATION_LDAP` | `ldaps` | yes | Whether ldap: and ldaps: CRL distribution points and caIssuers addresses are dialled: `ldaps` (TLS only, the directory's certificate verified), `ldaps-and-ldap` or `off`. |
| `pki.revocationLdapCaFile` | `STS_PKI_REVOCATION_LDAP_CA_FILE` | *(empty)* | yes | A PEM file of CA certificates an ldaps directory's certificate may chain to, beside node's own CA store. |
| `pki.revocationLdapDirectory` | `STS_PKI_REVOCATION_LDAP_DIRECTORY` | *(empty)* | yes | The directory (`ldaps://host:port`) a distribution point named relative to its CRL issuer is looked up in. Empty: such a name is not dialled. |
| `oauth2.accessTokenTtlS` | `STS_OAUTH2_ACCESS_TOKEN_TTL_S` | `3600` | yes | How long an access token is good for: its `exp` is this many seconds after it was signed, and it is the `expires_in` of every token response that carries one. One hour by default. |
| `oauth2.idTokenTtlS` | `STS_OAUTH2_ID_TOKEN_TTL_S` | `3600` | yes | How long an ID Token is good for. |
| `oauth2.refreshTokenTtlS` | `STS_OAUTH2_REFRESH_TOKEN_TTL_S` | `86400` | yes | The ABSOLUTE lifetime of a refresh token — the `exp` on the token itself, enforced in both modes by the refresh grant. |
| `oauth2.refreshTokenEncryptionAlg` | `STS_OAUTH2_REFRESH_TOKEN_ENCRYPTION_ALG` | `RSA-OAEP-256` | yes | EVERY REFRESH TOKEN IS A SIGNED JWT ENCRYPTED TO ITS OWN TRUST REALM — a compact JWE with `cty: JWT` (RFC 7519 section 11.2), opaque to the client as RFC 6749 section 1.5 already makes it. This picks the key management algorithm a new token is sealed under: any the JWE module implements (RSA-OAEP, RSA-OAEP-256, ECDH-ES and its three key-wrap variants, A128KW–A256KW, A128GCMKW–A256GCMKW, PBES2, `dir`; RSA1_5 is not offered). Each realm holds its own RSA key, EC key and secret, so a change strands no token already issued. An UNENCRYPTED refresh token is refused (`invalid_grant`, and `active: false` at introspection). |
| `oauth2.refreshTokenEncryptionEnc` | `STS_OAUTH2_REFRESH_TOKEN_ENCRYPTION_ENC` | `A256GCM` | yes | The JWE content encryption algorithm for refresh tokens — A128GCM, A192GCM, A256GCM, A128CBC-HS256, A192CBC-HS384 or A256CBC-HS512. |
| `oauth2.refreshTokenEncryptionKeyBits` | `STS_OAUTH2_REFRESH_TOKEN_ENCRYPTION_KEY_BITS` | `2048` | yes | The RSA modulus of each realm's refresh-token encryption key. Reaches key sets made after the change; rotate a realm's keys to apply it. |
| `oauth2.refreshTokenEncryptionCurve` | `STS_OAUTH2_REFRESH_TOKEN_ENCRYPTION_CURVE` | `P-256` | yes | The curve of each realm's refresh-token encryption EC key (for ECDH-ES): P-256, P-384 or P-521. Reaches key sets made after the change. |
| `oauth2.clockSkewS` | `STS_OAUTH2_CLOCK_SKEW_S` | `30` | yes | The allowance applied to `exp` and `nbf` EVERYWHERE this service reads back a token it issued: introspection, UserInfo, the refresh grant, token exchange, the DPoP-bound access token check, and the expiry every console screen reports. |
| `oauth2.redirectUris` | `STS_OAUTH2_REDIRECT_URIS` | *(empty)* | yes | The redirect URIs RFC 9700 mode compares an authorization request against, by EXACT STRING MATCH — for every client that did not register its own redirect_uris at POST /oauth2/register, which is every client this service has only ever seen at the authorization endpoint. |
| `oauth2.loopbackPortWildcard` | `STS_OAUTH2_LOOPBACK_PORT_WILDCARD` | `true` | yes | In RFC 9700 mode, allow a registered LOOPBACK redirect URI (127.0.0.1, [::1] or localhost) to match on any port — RFC 8252 section 7.3, because a native application cannot reserve one. |

#### Admin console

**There is no setting that opens this console, and there used to be.**
`admin.authRequired` was removed on 2026-09-06 when `global.mode` took over the
question: every page and every form under `/admin` needs a browser sign-on
session and one of the two roles below, in BOTH modes, and `mode.gatesConsole()`
is the one place that is decided. What the mode changes is whether the password
typed at that screen is CHECKED — in `development` it is not, so the gate is a
turnstile proving somebody typed a name that holds a role.

| Appconfig key | Environment variable | Default | Change while running? | What it does |
|---|---|---|---|---|
| `admin.readGroup` | `ADMIN_READ_GROUP` | `admin-read` | yes | The cn of the directory group whose members may READ the console — every page, and every ?format=json view of one. It is an ordinary group under ou=groups, so an ldapmodify, a SCIM PATCH and the /admin/rbac screen are three doors onto the same membership. |
| `admin.writeGroup` | `ADMIN_WRITE_GROUP` | `admin-write` | yes | The cn of the directory group whose members may POST a console form — revoke a token, add a claim, change a setting, grant a role. |
| `admin.openWhenEmpty` | `ADMIN_OPEN_WHEN_EMPTY` | `true` | yes | ON, anybody who signs in holds both roles UNTIL the bootstrap administrator (`admin.bootstrapUsername`) first signs in to `/admin`, and the console says so in a banner on every page; OFF, only members of the two role groups from the start. A process that never seeded the bootstrap administrator keeps the older rule: open while NEITHER role group has a member. |
| `admin.bootstrapUsername` | `STS_ADMIN_BOOTSTRAP_USERNAME` | `admin` | **restart** — the account is seeded once, before the listener binds | The default realm's bootstrap administrator: made at startup if absent, a member of both console roles, forced to choose a new password at its first sign-in, and impossible to delete or rename. In product mode it is also who gets the generated password, logged once, when nobody holds a credential. |

#### Protocol debugger

**There is no setting that opens the debugger either.** Every request to it
needs an access token carrying `urn:sts:debugger-api:debugger`, which the
authorization server issues to members of the two console role groups and
leaves off for anybody else. These rows decide whether it is served, where, and
what its api may dial.

| Appconfig key | Environment variable | Default | Change while running? | What it does |
|---|---|---|---|---|
| `debugger.enabled` | `STS_DEBUGGER_ENABLED` | `auto` | **restart** — the listener is bound and the api process forked when the service starts | Whether this process serves the identity protocol debugger on a listener of its own. `auto` is on in development mode and off in product mode. |
| `debugger.port` | `STS_DEBUGGER_PORT` | `8444` | **restart** — the listener is bound when the process starts | The port the debugger is served on, in the main port's scheme and with its certificate — a separate origin from the console on purpose. |
| `debugger.publicBaseUrl` | `STS_DEBUGGER_PUBLIC_BASE_URL` | *(empty)* | **restart** — the debugger client's redirect URI is seeded at startup | The scheme, host and port the debugger is reached at. Empty reads it off each request. |
| `debugger.uiDirectory` | `STS_DEBUGGER_UI_DIRECTORY` | `debugger/embedded/ui` | **restart** — the listener checks the directory when it starts | Where the debugger's built static site is. |
| `debugger.apiDirectory` | `STS_DEBUGGER_API_DIRECTORY` | `debugger/embedded/api` | **restart** — the api process is forked when the service starts | Where the debugger's api tree is — forked, never required. |
| `debugger.allowedDestinations` | `STS_DEBUGGER_ALLOWED_DESTINATIONS` | *(empty)* | **restart** — the allow-list is handed to the api process when it is forked | CIDR ranges the embedded api may dial IN PRODUCT MODE, beside this service's own addresses. |
| `debugger.startTimeoutS` | `STS_DEBUGGER_START_TIMEOUT_S` | `30` | yes | How long a forked api process has to report that it is listening. |
| `debugger.restartLimit` | `STS_DEBUGGER_RESTART_LIMIT` | `5` | yes | Failed starts in a row before the api is given up on until a restart. |
| `debugger.proxyTimeoutS` | `STS_DEBUGGER_PROXY_TIMEOUT_S` | `120` | yes | How long the gate waits on the api process for one response. |
| `debugger.maxRequestBytes` | `STS_DEBUGGER_MAX_REQUEST_BYTES` | `5242880` | yes | The largest request body forwarded to the api process. |

#### Applications

| Appconfig key | Environment variable | Default | Change while running? | What it does |
|---|---|---|---|---|
| `applications.max` | `STS_APPLICATIONS_MAX` | `500` | yes | How many entries may live under ou=applications — an OAuth client_id, a WS-Federation wtrealm, a SAML entityID, a WS-Trust AppliesTo, a Kerberos SPN. |
| `portal.applicationScanLimit` | `STS_PORTAL_APPLICATION_SCAN_LIMIT` | `1000` | yes | How many registry entries `/portal/applications` asks the issuance policy about before it stops; the page says how many it did not look at. |
| `applications.seedInternal` | `STS_APPLICATIONS_SEED_INTERNAL` | `true` | **restart** — the two entries are written once, as ldap_server.js is required and fills the registry's directory slot | Create an application entry for the ADMIN CONSOLE at /admin and one for the MANAGEMENT API at /admin-api when this service starts, under ou=applications with everything else. |

#### Federation

| Appconfig key | Environment variable | Default | Change while running? | What it does |
|---|---|---|---|---|
| `federation.enabled` | `STS_FEDERATION_ENABLED` | `true` | yes | Whether /federation answers at all. |
| `federation.max` | `STS_FEDERATION_MAX` | `50` | yes | How many entries may live under ou=federations. |
| `federation.usernamePrefix` | `STS_FEDERATION_USERNAME_PREFIX` | *(empty)* | yes | Put in front of every username a foreign identity provider supplies, so a federated `alice` and the local `alice` are two entries. |
| `federation.loginButtons` | `STS_FEDERATION_LOGIN_BUTTONS` | `true` | yes | Show a button per usable service-provider-side relationship on /authn/login, so a federated identity can satisfy ANY flow already in progress — an OAuth 2.0 authorization request, a WS-Federation sign-in, a SAML AuthnRequest, the admin console. |
| `federation.outbound` | `STS_FEDERATION_OUTBOUND` | `true` | yes | Whether this service may make an HTTP request OUT, to a partner's token endpoint, UserInfo endpoint or JWKS. |
| `federation.outboundTimeoutMs` | `STS_FEDERATION_OUTBOUND_TIMEOUT_MS` | `15000` | yes | How long to wait for a partner to answer before giving up. It was `5000` until 2026-08-30: the partner here is usually THIS process (a trust realm is a logical copy of this service), and the first thing anybody asks a brand-new realm for is its JWKS — which brings that realm's eleven post-quantum keys into being, one of them an SLH-DSA key generation of about five seconds. |
| `federation.outboundAllowInsecure` | `STS_FEDERATION_OUTBOUND_ALLOW_INSECURE` | `false` | yes | OFF by default, which is the one place this service is stricter than a mock would ordinarily be: what travels on these requests is a client secret and an authorization code, at somebody else's service. |
| `federation.requestTtlMin` | `STS_FEDERATION_REQUEST_TTL_MIN` | `10` | yes | How long this service remembers that it sent somebody to a partner. |
| `federation.maxContexts` | `STS_FEDERATION_MAX_CONTEXTS` | `500` | yes | Outbound federated sign-ins held per realm; past it the oldest is dropped. Was a constant. |
| `federation.maxApplicationLength` | `STS_FEDERATION_MAX_APPLICATION_LENGTH` | `256` | yes | The longest `?application=` a federated login carries across the round trip. |
| `federation.maxApplicationUse` | `STS_FEDERATION_MAX_APPLICATION_USE` | `64` | yes | Per-application counter rows (`fedApplicationUse`) kept on one relationship. |
| `federation.releaseIndexTtlMs` | `STS_FEDERATION_RELEASE_INDEX_TTL_MS` | `5000` | yes | How long the release-policy index is reused before the register is walked again; `0` rebuilds it per token. |
| `federation.maxResponseBytes` | `STS_FEDERATION_MAX_RESPONSE_BYTES` | `262144` | yes | The cap on a partner's token response, UserInfo document or JWKS. |
| `federation.jwtAlgorithms` | `STS_FEDERATION_JWT_ALGORITHMS` | `RS256,RS384,RS512,PS256,PS384,PS512,ES256,ES384,ES512` | yes | The algorithms a partner's ID Token or JWT access token may use. It NARROWS the family the partner's key admits and cannot add `none` or an HMAC. |
| `federation.spNameIdFormat` | `STS_FEDERATION_SP_NAMEID_FORMAT` | `urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified` | yes | The `<md:NameIDFormat>` in `/federation/metadata/{id}`. |

#### SAML

| Appconfig key | Environment variable | Default | Change while running? | What it does |
|---|---|---|---|---|
| `saml.issuer` | `STS_SAML_ISSUER`<br>or `STS_ISSUER` | `urn:wstrust:mock:sts` | yes | The <saml:Issuer> of every SAML 2.0 assertion and the Issuer attribute of every SAML 1.1 one. WS-Federation's assertions are built by the same two functions, so this is their issuer too, and it is what /wsfed/rp checks a presented assertion against. |
| `saml.clockSkewS` | `STS_SAML_CLOCK_SKEW_S` | `0` | yes | How far to widen the validity window of every assertion this service ISSUES, at both ends: Conditions/NotBefore is backdated by this many seconds and NotOnOrAfter is extended by it. Both builders apply it, so it reaches SAML 2.0, SAML 1.1, WS-Trust and WS-Federation alike. IssueInstant and the authentication instant are NOT moved — those state when something happened. 0 to 300; 0 is what this service always did. It is NOT `oauth2.clockSkewS`, which is the tolerance applied when this service READS a document back. |
| `saml.signatureAlgorithm` | `STS_SAML_SIGNATURE_ALGORITHM` | `rsa-sha256` | yes | The SignatureMethod of every XML signature this service makes on a SAML assertion, response, LogoutRequest/Response, SAML or WS-Federation metadata and a signed federated AuthnRequest, and the Redirect binding's `SigAlg`: `rsa-sha256`, `rsa-sha384`, `rsa-sha512`, or the broken `rsa-sha1`. |
| `saml.canonicalizationAlgorithm` | `STS_SAML_CANONICALIZATION_ALGORITHM` | `exclusive` | yes | `exclusive` or `exclusive-with-comments`. Inclusive c14n is not offered: an assertion is signed standalone and embedded, and inclusive c14n would fail at every relying party. |
| `saml.organizationName` | `STS_SAML_ORGANIZATION_NAME` | `sts` | yes | `<md:OrganizationName>` in `/saml2/metadata` and `/saml11/metadata`. Empty omits the whole `<md:Organization>`, in either mode. |
| `saml.organizationDisplayName` | `STS_SAML_ORGANIZATION_DISPLAY_NAME` | `Mock security token service` | yes | `<md:OrganizationDisplayName>`; empty omits the element. |
| `saml.organizationUrl` | `STS_SAML_ORGANIZATION_URL` | *(empty)* | yes | `<md:OrganizationURL>`; empty means this service's own base URL. |

#### SAML 2.0

These are their own group and `saml.issuer` above is deliberately not one of
them: that setting names whoever SIGNED an assertion and is shared with WS-Trust
and WS-Federation, while every row here governs how this service behaves as an
identity provider in a browser profile.

| Appconfig key | Environment variable | Default | Change while running? | What it does |
|---|---|---|---|---|
| `saml2.entityId` | `STS_SAML2_ENTITY_ID` | `urn:sts:idp` | yes | The entityID this identity provider publishes in its SAML 2.0 metadata, and the <saml:Issuer> of every Response and Assertion the Web Browser SSO profile issues. It is NOT the SAML issuer above: that one names whoever signed an assertion and is shared with WS-Trust and WS-Federation, and a service provider checks THIS one against the metadata it was configured from. They are separate for the reason wsfed.entityId is separate from it. |
| `saml2.perApplicationEntityId` | `STS_SAML2_PER_APPLICATION_ENTITY_ID` | `true` | yes | ON by default, and it is what makes the metadata at /saml2/metadata/{sp} UNIQUE PER APPLICATION: the identity provider names itself <entityID>:{sp} in that document and in everything it issues to that service provider, the way Okta and Ping give each application its own identity provider. OFF makes every document carry the entityID above and differ only in its endpoint URLs, which is what a service provider library that keys its trust store off the entityID expects. Both are real deployments, which is why it is a setting and not a decision. |
| `saml2.assertionLifetimeMin` | `STS_SAML2_ASSERTION_LIFETIME_MIN` | `60` | yes | How long an issued assertion is valid for: it becomes Conditions/NotOnOrAfter and the bearer SubjectConfirmationData/NotOnOrAfter alike. Set it to 1 to watch a service provider refuse a stale assertion, which is the check most of them get wrong. |
| `saml2.signAssertion` | `STS_SAML2_SIGN_ASSERTION` | `true` | yes | Sign the <saml:Assertion> itself. ON by default because a service provider that verifies anything verifies this, and because an assertion that travels on its own — out of an ArtifactResponse, say — has nothing else carrying a signature. Turning it OFF is a test case rather than a mistake: a service provider that accepts an unsigned assertion has a hole, and this is how to find out. |
| `saml2.signResponse` | `STS_SAML2_SIGN_RESPONSE` | `true` | yes | Sign the <samlp:Response> around the assertion as well, which is what AD FS and Keycloak do by default. Both signatures are ordinary: the response is signed AFTER the assertion inside it, so the assertion's own signature is part of what the response signature covers. On the HTTP Redirect binding this ALSO controls the query-string signature of section 3.4.4.1, which is the one a redirect response is really verified by. |
| `saml2.nameIdFormat` | `STS_SAML2_NAMEID_FORMAT` | `urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified` | yes | The Format on the NameID when the AuthnRequest's NameIDPolicy asks for none. A request that DOES name one is answered with the one it named — any of them, including a format this service has never heard of, because a service provider being told its own format back is the behaviour worth exercising and refusing with InvalidNameIDPolicy would remove the test case. |
| `saml2.artifactTtlS` | `STS_SAML2_ARTIFACT_TTL_S` | `300` | yes | How long a SAML artifact can be resolved for at the Artifact Resolution Service. An artifact is ALSO one-shot — resolving it destroys it, which section 3.6.4.1 requires and which no lifetime can express — so a second ArtifactResolve for the same artifact is refused however long this is. |
| `saml2.encryptAssertion` | `STS_SAML2_ENCRYPT_ASSERTION` | `false` | yes | Wrap the assertion in a `<saml:EncryptedAssertion>`. Needs a recipient certificate; with none the assertion is sent IN CLEAR and the reason is logged at WARN. Per application with `saml2EncryptAssertion`. |
| `saml2.encryptionAlgorithm` | `STS_SAML2_ENCRYPTION_ALGORITHM` | `aes256-gcm` | yes | The block cipher: `aes256-gcm`, `aes128-gcm`, `aes256-cbc`, `aes128-cbc`. The GCM pair is authenticated; the CBC pair is not, which is CBC's property and is offered because real service providers require it. Per application with `saml2EncryptionAlgorithm`. |
| `saml2.keyTransportAlgorithm` | `STS_SAML2_KEY_TRANSPORT_ALGORITHM` | `rsa-oaep-mgf1p` | yes | How the content key is wrapped: `rsa-oaep-mgf1p` or `rsa-1_5`. The second is Bleichenbacher-broken and is offered because many deployed service providers accept nothing else. Per application with `saml2KeyTransportAlgorithm`. |
| `saml2.encryptLogoutNameId` | `STS_SAML2_ENCRYPT_LOGOUT_NAMEID` | `false` | yes | Send `<saml:EncryptedID>` rather than `<saml:NameID>` in a LogoutRequest — the only encryptable thing in a SAML 2.0 request. Reading one is never gated. Per application with `saml2EncryptLogoutNameId`. |
| `saml2.autocreateApplications` | `STS_SAML2_AUTOCREATE_APPLICATIONS` | `true` | yes | ON by default: an entityID this service has not seen before gets an application entry under ou=applications the moment it appears in a valid AuthnRequest — or the moment somebody asks for its metadata — so nothing has to be provisioned before a service provider can be pointed here. OFF still ANSWERS the request; it simply records nothing, which is what somebody driving a fuzzer at this endpoint wants before their directory has ten thousand entries in it. |
| `saml2.defaultSingleLogoutService` | `STS_SAML2_DEFAULT_SLO_SERVICE` | *(empty)* | yes | Where a <samlp:LogoutResponse> goes when the service provider has no SingleLogoutService recorded on its application entry. A LogoutRequest carries no return address of its own — only SP metadata has one, and this service does not consume SP metadata — so without this the fallback is the assertion consumer service URL that application last used, which is stated on the page rather than done quietly. Set it to remove the guess. |
| `saml2.requestTtlMin` | `STS_SAML2_REQUEST_TTL_MIN` | `10` | yes | How long an AuthnRequest is held while the browser is at the sign-in screen. |
| `saml2.mockSpContextTtlMin` | `STS_SAML2_MOCK_SP_CONTEXT_TTL_MIN` | `30` | yes | How long the non-spec mock service provider at /saml2/sp remembers a RelayState it minted. |
| `saml2.redirectWarnLength` | `STS_SAML2_REDIRECT_WARN_LENGTH` | `8000` | yes | A Response on the HTTP Redirect binding longer than this is logged at WARN (and still sent). |
| `saml2.spMetadataMaxBytes` | `STS_SAML2_SP_METADATA_MAX_BYTES` | `524288` | yes | The cap on a service provider's metadata fetched by the refresh action. |

#### SAML 1.1

These nine are a group of their own for the reason the SAML 2.0 nine are, and for
one more besides. The shared reason: `saml.issuer` above names whoever SIGNED an
assertion and is read by WS-Trust and WS-Federation, while every row here governs
how this service behaves as an identity provider in a browser profile. The reason
peculiar to this group: **SAML 1.1 and SAML 2.0 are different specifications
rather than two dialects**, and a shared set of rows would make `signResponse`
mean two things — over there it is an XML signature or a signed query string
depending on the binding, and here there is no redirect binding for a response at
all. A relying party that trusts this service for 1.1 and not for 2.0 is also the
ordinary case, and one `entityId` between them would make that unexpressible.

| Appconfig key | Environment variable | Default | Change while running? | What it does |
|---|---|---|---|---|
| `saml11.providerId` | `STS_SAML11_PROVIDER_ID` | `urn:sts:idp:saml11` | yes | What this identity provider calls itself in the SAML 1.1 browser profiles: the `Issuer` ATTRIBUTE of every assertion they issue, the `entityID` of the metadata document at /saml11/metadata, and the string whose SHA-1 becomes the SourceID inside every type 0x0001 artifact. SAML 1.1 calls it a providerID and SAML 2.0 metadata calls the same thing an entityID; they are one value and this row is it. It is deliberately NOT saml2.entityId — a relying party that trusts this service for 1.1 and not for 2.0 is the ordinary case, and one value would make that unexpressible. |
| `saml11.perApplicationProviderId` | `STS_SAML11_PER_APPLICATION_PROVIDER_ID` | `true` | yes | Give every relying party its own providerID — `{providerID}:{slug}` — and its own endpoints under the same path segment, which is what /saml11/metadata/{rp} publishes. Turn it off for a relying party whose trust store is keyed off the providerID and which is surprised to meet a new one per application. THE ENDPOINTS STAY PER-APPLICATION either way, because that is what makes the documents worth having separately. It also changes every artifact this service mints: the SourceID is a hash of the providerID, so turning this off makes one SourceID where there were many. |
| `saml11.assertionLifetimeMin` | `STS_SAML11_ASSERTION_LIFETIME_MIN` | `60` | yes | How long the browser profiles' assertions are valid for, in the NotBefore and NotOnOrAfter of <saml:Conditions>. It is separate from the WS-Federation lifetime for the same reason the SAML 2.0 one is: a browser profile assertion is consumed within seconds of being issued and a short lifetime here is a realistic test, where the same value would make a WS-Federation session expire while somebody was reading it. |
| `saml11.signAssertion` | `STS_SAML11_SIGN_ASSERTION` | `true` | yes | Sign the <saml:Assertion> itself, with ds:Signature as its LAST child and the reference naming AssertionID — which is where the 1.1 schema puts it and is not where SAML 2.0 does. ON by default because the Browser/POST profile REQUIRES a signed assertion (saml-profile-1.1 section 4.2.1.4): the assertion passes through the browser, so nothing else authenticates it. Turning it off is a test case rather than a mistake — a relying party that accepts it anyway has a hole in it, and this is how somebody finds that out. |
| `saml11.signResponse` | `STS_SAML11_SIGN_RESPONSE` | `true` | yes | Sign the <samlp:Response> around the assertion as well, with the reference naming ResponseID. Real identity providers differ here and both are worth exercising, which is why it is a setting: the profile requires the RESPONSE to be signed in Browser/POST and says nothing about it for the assertion pulled back over the artifact channel, where the SOAP exchange is what a relying party is trusting. |
| `saml11.nameIdFormat` | `STS_SAML11_NAMEID_FORMAT` | `urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified` | yes | The Format on the <saml:NameIdentifier> when the request asks for none — which in SAML 1.1 is ALWAYS, because the profile has no request message to carry a NameIDPolicy in. That is the difference from saml2.nameIdFormat, which is a default a request routinely overrides: this one is the answer unless the non-spec `format` parameter overrides it. |
| `saml11.defaultProfile` | `STS_SAML11_DEFAULT_PROFILE` | `post` | yes | Which profile the inter-site transfer service uses when the request does not say: Browser/POST (section 4.2), where the assertion travels through the browser in a form POST, or Browser/Artifact (section 4.1), where a reference travels through the browser and the relying party fetches the assertion over SOAP. POST is the default because it needs no server behind the relying party's assertion consumer, so it is the one that works when somebody points this at a URL and watches. A request naming `profile` or carrying `SAMLart` overrides it. |
| `saml11.artifactTtlS` | `STS_SAML11_ARTIFACT_TTL_S` | `300` | yes | How long an artifact can be resolved for at the SAML responder before it is swept. It is an UPPER bound and not the rule that matters: an artifact is resolvable exactly ONCE (saml-bindings-1.1 section 3.2.3), so resolving one destroys it whatever this says, and no lifetime setting can express that. Five minutes is what the profile recommends and is generous for an exchange that takes milliseconds. |
| `saml11.autocreateApplications` | `STS_SAML11_AUTOCREATE_APPLICATIONS` | `true` | yes | Create an application entry under ou=applications the first time a relying party is named — by a TARGET arriving, by a metadata document being fetched, or by an artifact being resolved. Off means the browser profiles still work and /admin/saml11 stays empty, which is what somebody driving a load test wants and nobody else does. |
| `saml11.requestTtlMin` | `STS_SAML11_REQUEST_TTL_MIN` | `10` | yes | How long a SAML 1.1 browser flow is held while the browser is at the sign-in screen. |
| `saml11.assertionCacheMax` | `STS_SAML11_ASSERTION_CACHE_MAX` | `500` | yes | Assertions the SAML 1.1 responder keeps per realm for `<samlp:AssertionIDReference>`. |

#### WS-Trust

| Appconfig key | Environment variable | Default | Change while running? | What it does |
|---|---|---|---|---|
| `wstrust.issuer` | `STS_WSTRUST_ISSUER`<br>or `STS_ISSUER` | `urn:wstrust:mock:sts` | yes | The `iss` of the JWT this STS returns in a RequestSecurityTokenResponse, and the issuer named on GET /sts. A SAML token requested through WS-Trust is built by the SAML modules and carries the SAML issuer above. |
| `wstrust.tokenLifetimeMin` | `STS_WSTRUST_TOKEN_LIFETIME_MIN` | `60` | yes | How long an issued or renewed token is valid for when the RST carries no `wst:Lifetime`. |
| `wstrust.maxTokenLifetimeMin` | `STS_WSTRUST_MAX_TOKEN_LIFETIME_MIN` | `1440` | yes | The ceiling on a requested `wst:Lifetime`, in both modes; the RSTR states what was issued. |
| `wstrust.jwtAlgorithm` | `STS_WSTRUST_JWT_ALGORITHM` | `RS256` | yes | The `alg` of the JWT token type: `RS256`–`RS512`, `PS256`–`PS512`, `ES256`–`ES512` or `EdDSA`, with the key's `kid` in the header. |

#### WS-Federation

| Appconfig key | Environment variable | Default | Change while running? | What it does |
|---|---|---|---|---|
| `wsfed.assertionLifetimeMin` | `STS_WSFED_ASSERTION_LIFETIME_MIN` | `60` | yes | How long the SAML 1.1 assertion inside a WS-Federation sign-in response is valid, and the wsu:Lifetime of the RequestSecurityTokenResponse around it. It was a hardcoded 60 in wsfed.js until 2026-08-27. Per relying party with `wsfedAssertionLifetimeMin` on the application entry; the default is drawn on `/admin/saml-assertions`, because a WS-Federation response carries a SAML 1.1 assertion built by the same function. |
| `wsfed.entityId` | `STS_WSFED_ENTITY_ID`<br>or `STS_ISSUER` | `urn:wstrust:mock:sts` | yes | The entityID in the federation metadata at /FederationMetadata/2007-06/FederationMetadata.xml. Split from the SAML issuer because the two are different things that happened to share a value: this names the IdP, that names whoever signed an assertion. |
| `wsfed.mockRpContextTtlMin` | `STS_WSFED_MOCK_RP_CONTEXT_TTL_MIN` | `30` | yes | How long the non-spec mock relying party at /wsfed/rp remembers a wctx it minted. |

#### TLS

| Appconfig key | Environment variable | Default | Change while running? | What it does |
|---|---|---|---|---|
| `tls.port` | `STS_TLS_PORT` | `8443` | **restart** — the listener is bound when the process starts | The permissive listener: it always asks for a client certificate, never refuses one, and reports what it saw. |
| `tls.mutualPort` | `STS_MTLS_PORT` | `9443` | **restart** — the listener is bound when the process starts | The strict listener: node refuses an unverified client certificate during the handshake, so nothing in this service runs for one. |
| `tls.trustIssuedClientCertificates` | `STS_TLS_TRUST_ISSUED_CLIENT_CERTIFICATES` | `true` | **restart** — the service Root is put into the listeners' client truststore when their TLS context is built | Adds this service's own Root CA to the client truststore of 8443, 9443 and the main port, so a TLS client certificate issued on the user portal signs its holder in, in the realm whose TLS client Issuing CA signed it. A chain through that Root is an identity only for a TLS client or enrollment (ACME, EST, SCEP) leaf with `clientAuth` and one `urn:sts:person:`/`urn:sts:application:` name; every other key pair this service issues is refused as one. |
| `tls.hostnames` | `STS_TLS_HOSTNAMES` | `localhost,sts,sts-mock,sts.example.com` | **restart** — the server certificate is issued at startup for these names | The subjectAltName DNS entries on the certificate both TLS listeners present. |
| `tls.ips` | `STS_TLS_IPS` | `127.0.0.1` | **restart** — the server certificate is issued at startup for these addresses | The subjectAltName IP entries on the same certificate. |
| `tls.certificateAlgorithms` | `STS_TLS_CERT_ALGS` | `rsa` | **restart** — the certificates are issued when the listeners are bound | Which server certificates the two TLS listeners present: `rsa` (the default), and any of `ml-dsa-44`, `ml-dsa-65` and `ml-dsa-87`. MORE THAN ONE IS THE INTERESTING SETTING — OpenSSL 3.5 serves whichever certificate matches the signature algorithms the CLIENT offered, so `rsa,ml-dsa-65` answers an ordinary client with RSA and a post-quantum one with ML-DSA over the same port. It is not the default because an ML-DSA certificate is refused by everything older than OpenSSL 3.5. |
| `tls.minVersion` | `STS_TLS_MIN_VERSION` | `TLSv1.2` | **restart** — the TLS contexts are built when the listeners are created | The lowest protocol version 8443, 9443, LDAPS and the main HTTPS port negotiate: `TLSv1`, `TLSv1.1`, `TLSv1.2` (node's own default, and what this service always did) or `TLSv1.3`. |
| `tls.ciphers` | `STS_TLS_CIPHERS` | *(empty)* | **restart** — the TLS contexts are built when the listeners are created | An OpenSSL cipher list for the same four listeners. Empty means node's default list. A list matching no cipher stops the service at startup, naming this setting. |
| `tls.trustAnchorsFile` | `STS_TLS_TRUST_ANCHORS_FILE` | *(empty)* | **restart** — the anchors are read when the listeners are created | A PEM file of CA certificates that client certificates are verified against, read at startup. The product-mode way to fill the truststore: `POST /tls/trust` and `/tls/trust/clear` answer anybody in development mode and are refused (403, naming this setting) in product mode. A file that cannot be read stops the service. |
| `tls.selfSignedKeyBits` | `STS_TLS_SELF_SIGNED_KEY_BITS` | `2048` | **restart** — the certificate is generated when the process starts | The RSA key size of the self-signed listener certificate made when no other certificate is available. 2048–8192, in steps of 1024. |
| `tls.selfSignedValidityYears` | `STS_TLS_SELF_SIGNED_YEARS` | `2` | **restart** — the certificate is generated when the process starts | How long that certificate is valid. |
| `tls.selfSignedOrganization` | `STS_TLS_SELF_SIGNED_ORGANIZATION` | `sts` | **restart** — the certificate is generated when the process starts | The `O=` of its subject; the `CN` is the first of `tls.hostnames`. |

#### OID4VCI

| Appconfig key | Environment variable | Default | Change while running? | What it does |
|---|---|---|---|---|
| `oid4vci.walletUrl` | `OID4VCI_WALLET_URL` | `http://localhost:3000` | yes | Where the wallet lives, as a URL the BROWSER can use. The Credential Offer pages send the End-User here, so it is the debugger's own address rather than anything this service serves. |
| `oid4vci.authorizationServer` | `OID4VCI_AUTHORIZATION_SERVER` | *(empty)* | yes | Set this to advertise a SEPARATE authorization server in the credential issuer metadata's authorization_servers. Empty — the default — means this service is its own, which is the arrangement every test here uses. |
| `oid4vci.batchSize` | `OID4VCI_BATCH_SIZE` | `4` | yes | batch_credential_issuance.batch_size in the issuer metadata: how many proofs one credential request may carry, and therefore how many credentials come back from it. |
| `oid4vci.deferredReadyMs` | `OID4VCI_DEFERRED_READY_MS` | `4000` | yes | How long a deferred credential stays issuance_pending before it is ready. Long enough that a wallet has to poll and short enough that a test does not time out. |
| `oid4vci.deferredIntervalS` | `OID4VCI_DEFERRED_INTERVAL_S` | `2` | yes | The `interval` this issuer asks a wallet to wait between deferred polls. |
| `oid4vci.offerUsername` | `OID4VCI_OFFER_USERNAME` | `diploma.student` | yes | Whose credential the issuer-initiated offer pages build. The claims come from that person's directory entry. |
| `oid4vci.requestEncryptionRequired` | `OID4VCI_REQUEST_ENCRYPTION_REQUIRED` | `false` | yes | When on, a credential request that is not a JWE is refused. The negative worth having: a wallet cannot prove it encrypts by encrypting when the issuer accepts plaintext too. |
| `oid4vci.sdJwtIssuerDid` | `OID4VCI_SD_JWT_ISSUER_DID` | `false` | **restart** — vc_did.js reads it once at require time, and the issuer metadata is built from what it read | Switch the PLAIN dc+sd-jwt credential configuration over to naming its issuer by did:web instead of by https URL — what a deployment that had gone to DIDs throughout would look like. |
| `oid4vci.ldpVcIssuerDid` | `OID4VCI_LDP_VC_ISSUER_DID` | `false` | **restart** — vc_did.js reads it once at require time, and the issuer metadata is built from what it read | The same for the PLAIN ldp_vc configuration. |
| `oid4vci.txCodeLength` | `OID4VCI_TX_CODE_LENGTH` | `5` | yes | How many digits the Transaction Code a pre-authorized offer shows on the issuer's screen has. Drawn from a CSPRNG whatever this is — it was Math.random() until 2026-09-12, which is predictable from other values it produced. |
| `oid4vci.txCodeMaxAttempts` | `OID4VCI_TX_CODE_MAX_ATTEMPTS` | `5` | yes | IN PRODUCT MODE, how many wrong Transaction Codes a pre-authorized code survives. The last one SPENDS it, so a five-digit code cannot be guessed at the token endpoint inside the offer's lifetime; the End-User asks the issuer for a new offer. Development counts nothing, so a wallet can be driven through its wrong-code path as often as a test likes. |
| `oid4vci.offerTtlS` | `OID4VCI_OFFER_TTL_S` | `600` | yes | How long a Credential Offer, its issuer_state, its pre-authorized code and a notification_id stay usable. |
| `oid4vci.preAuthorizedPollIntervalS` | `OID4VCI_PRE_AUTHORIZED_POLL_INTERVAL_S` | `5` | yes | The `interval` a pre-authorized_code grant in an offer names — the seconds a wallet waits between token requests. |
| `oid4vci.walletIssuancePath` | `OID4VCI_WALLET_ISSUANCE_PATH` | `/vc-issuance-1.html` | yes | The page under the wallet URL that a Credential Offer is handed to. The default is the debugger's own wallet page. |
| `oid4vci.allowedWalletUrls` | `OID4VCI_ALLOWED_WALLET_URLS` | `(empty)` | yes | IN PRODUCT MODE, the wallet URLs besides oid4vci.walletUrl that the `wallet` query parameter on /issuer/offer may name. Any other is refused, because an offer link that sends the End-User wherever its query string says is an open redirect carrying a pre-authorized code. Development accepts any URL, which is how a wallet on a laptop is pointed at this service. |
| `oid4vci.requestEncryptionKeyBits` | `OID4VCI_REQUEST_ENCRYPTION_KEY_BITS` | `2048` | yes | The RSA modulus of the key credential_request_encryption publishes. Each trust realm has its own key, made when the realm first needs one, so a change reaches keys made AFTER it and never a key that exists. |
| `oid4vci.requestEncryptionEncValues` | `OID4VCI_REQUEST_ENCRYPTION_ENC_VALUES` | `A128GCM,A256GCM` | yes | The content encryption algorithms credential_request_encryption advertises and accepts. Only A128GCM and A256GCM are implemented; anything else named here is ignored with a warning rather than advertised, because metadata that overstates is worse than metadata that says little. |
| `oid4vci.responseEncryptionEncValues` | `OID4VCI_RESPONSE_ENCRYPTION_ENC_VALUES` | `A128GCM,A256GCM` | yes | The content encryption algorithms credential_response_encryption advertises and accepts. Same rule as the request row: A128GCM and A256GCM are implemented and nothing else is advertised. The key transport is RSA-OAEP-256, which is the only one implemented and is not a setting. |
| `oid4vci.responseEncryptionRequired` | `OID4VCI_RESPONSE_ENCRYPTION_REQUIRED` | `false` | yes | When on, a credential request that does not ask for an encrypted response (credential_response_encryption) is refused, and the metadata says encryption_required: true. |
| `oid4vci.credentialLifetimeS` | `OID4VCI_CREDENTIAL_LIFETIME_S` | `2592000` | yes | How long every credential this issuer mints is valid — the `exp` of a dc+sd-jwt and a jwt_vc_json credential and the `validUntil` of an ldp_vc one. Thirty days by default. |
| `oid4vci.credentialSigningAlgorithm` | `OID4VCI_CREDENTIAL_SIGNING_ALGORITHM` | `RS256` | yes | The JWS algorithm dc+sd-jwt and jwt_vc_json credentials are signed with, and the one the DID Configuration's Domain Linkage Credential and /did/generate's did:web credential use. The metadata's credential_signing_alg_values_supported names it, /oauth2/jwks and /.well-known/did.json publish the key, and the mock Verifier checks against it. ldp_vc is bbs-2023 and is not affected. A credential already issued keeps the algorithm it was signed with. |
| `oid4vci.proofIatWindowS` | `OID4VCI_PROOF_IAT_WINDOW_S` | `600` | yes | How far a wallet's openid4vci-proof+jwt `iat` may be from now, either way. The c_nonce is what makes a proof single use; this is what stops one minted long ago being used at all. |
| `oid4vci.cNonceTtlS` | `OID4VCI_C_NONCE_TTL_S` | `300` | yes | How long a c_nonce from the Nonce Endpoint may be quoted in a proof; `c_nonce_expires_in` says the same number. |
| `oid4vci.issuerDisplayName` | `OID4VCI_ISSUER_DISPLAY_NAME` | `IdP Tools Mock Credential Issuer` | yes | The `display.name` of the credential issuer metadata — what a wallet shows as who is offering the credential. The credential configurations' own display names and colours are part of the catalogue in oid4vc/vc_issuer.js and are not settings. |
| `oid4vci.domainLinkageLifetimeS` | `OID4VCI_DOMAIN_LINKAGE_LIFETIME_S` | `31536000` | yes | How long the Domain Linkage Credential at /.well-known/did-configuration.json says it is valid. It is signed per request, so this is the window a cached copy may be believed for. |
| `oid4vci.generatedDidCredentialLifetimeS` | `OID4VCI_GENERATED_DID_CREDENTIAL_LIFETIME_S` | `3600` | yes | How long the SD-JWT VC that /did/generate signs with the DID it hands back is valid. |

#### OID4VP

| Appconfig key | Environment variable | Default | Change while running? | What it does |
|---|---|---|---|---|
| `oid4vp.clientId` | `OID4VP_CLIENT_ID` | `sts-verifier` | yes | The client_id the mock Verifier presents in its Authorization Request, and the `aud` the Key Binding JWT must name. |
| `oid4vp.walletUrl` *(derived)* | `OID4VP_WALLET_URL` | `http://localhost:3000` | yes | Where the Verifier sends the holder to present. Falls back to the OID4VCI wallet URL, since it is the same wallet in every arrangement this service is used in. |
| `oid4vp.kbMaxAgeS` | `OID4VP_KB_MAX_AGE_S` | `600` | yes | How old a Key Binding JWT's `iat` may be before the Verifier rejects the presentation as a replay. |
| `oid4vp.claims` | `OID4VP_CLAIMS` | `given_name,family_name` | yes | The mock Verifier's STARTING request, and — this is the part worth knowing — the target its Reset returns to. It is not the live list: /admin/vc-verifier-config owns that, and copies this at startup. |
| `oid4vp.presentationRequestTtlS` | `OID4VP_PRESENTATION_REQUEST_TTL_S` | `600` | yes | How long a presentation request — its nonce, state and Request Object — may wait for a wallet's response. |
| `oid4vp.walletPresentationPath` | `OID4VP_WALLET_PRESENTATION_PATH` | `/vc-presentation-1.html` | yes | The page under the wallet URL a presentation request is handed to. The default is the debugger's own wallet page. |
| `oid4vp.allowedWalletUrls` | `OID4VP_ALLOWED_WALLET_URLS` | `(empty)` | yes | IN PRODUCT MODE, the wallet URLs besides oid4vp.walletUrl that the `wallet` query parameter on the Verifier's start page may name; any other is refused as an open redirect. Development accepts any URL. |
| `oid4vp.trustedIssuerCertificates` | `OID4VP_TRUSTED_ISSUER_CERTIFICATES` | `(empty)` | yes | PEM certificates, concatenated, whose keys the mock Verifier accepts an SD-JWT VC or jwt_vc_json credential signature from IN ADDITION to this realm's own issuer. Empty — the default — trusts this issuer alone, which is what it always did. A certificate is used as a KEY: no chain is built and no revocation is checked. |
| `oid4vp.expectedVct` | `OID4VP_EXPECTED_VCT` | `urn:idptools:sd-jwt-vc:identity` | yes | The `vct` the Verifier requires of a presented SD-JWT VC. The default is the type this issuer mints; set it to accept a credential another issuer mints under its own type. |
| `oid4vp.maxRequestedClaims` | `OID4VP_MAX_REQUESTED_CLAIMS` | `40` | yes | The most claims /admin/vc-verifier-config lets the Verifier's request name. |

#### Kerberos

| Appconfig key | Environment variable | Default | Change while running? | What it does |
|---|---|---|---|---|
| `krb5.enabled` | `KRB5_ENABLED` | `true` | yes | Whether this realm's KDC answers. On the service as a whole it is on, and the sockets stay bound either way. **On a TRUST REALM it decides whether that realm has a Kerberos realm at all**, and a realm is created with it OFF: turning it on is refused until the realm has a `krb5.realm` of its own that no other realm answers to, and it builds that realm's principal database. |
| `krb5.realm` | `KRB5_REALM` | `EXAMPLE.COM` | **restart** for the process — the principal database and every long-term key in it are derived from the realm at startup; **settable on a trust realm**, whose database is built when its Kerberos is turned on | The realm this KDC serves. Its lower-cased form is the domain, which is where the default service domains and the PAC's domain name come from. On a trust realm it is the name port 88 routes that realm's requests by: no two realms may answer to one name, and it cannot be changed while that realm's Kerberos is on. |
| `krb5.kdcPort` | `KRB5_KDC_PORT` | `88` | **restart** — the TCP and UDP sockets are bound when the process starts | The KDC listens on TCP and UDP alike. 88 is privileged, so a host run that is not root fails to bind it — which is recorded rather than thrown, and reported by GET /krb5/principals. 0 asks for any free port. |
| `krb5.servicePort` | `KRB5_SERVICE_PORT` | `8888` | **restart** — the socket is bound when the process starts | The Kerberized test service that accepts an AP-REQ. |
| `krb5.servicePrincipal` | `KRB5_SERVICE_PRINCIPAL` | `HTTP/web.example.com` | **restart** — the account and its long-term keys are created at startup | The SPN that test service holds, in the usual service/hostname form. |
| `krb5.clockSkew` | `KRB5_CLOCK_SKEW` | `300` | yes | How far apart the KDC will let its clock and a client's be. RFC 4120 suggests five minutes and this is where KRB_AP_ERR_SKEW comes from. |
| `krb5.clockOffset` | `KRB5_CLOCK_OFFSET` | `0` | yes | Moves this KDC's clock deliberately, so a skew failure can be produced on purpose rather than by changing the machine's time. |
| `krb5.userPassword` | `KRB5_USER_PASSWORD` | `password!` | **restart** — every user's long-term keys are derived from it at startup | The password every user account here has. It is PUBLISHED by GET /krb5/principals on purpose: a debugger whose accounts are unusable without reading the source is worse than one that says what they are. |
| `krb5.unknownUsers` | `KRB5_UNKNOWN_USERS` | `nosuchuser,nobody` | yes | Usernames this KDC refuses to create on demand, so KDC_ERR_C_PRINCIPAL_UNKNOWN stays reachable. |
| `krb5.serviceDomains` *(derived)* | `KRB5_SERVICE_DOMAINS` | `example.com,localhost,sts,127.0.0.1` | **restart** — the service accounts are created at startup | The host domains a service principal is created on demand for. Setting it to an empty string creates nothing, which is the behaviour this service had before the setting existed. |
| `krb5.autoServicePassword` | `KRB5_AUTO_SERVICE_PASSWORD` | `auto-service-password` | **restart** — those accounts' long-term keys are derived from it at startup | One password for every service created on demand, and it is published for the same reason the user password is: it is what lets a reader decrypt a service ticket this mock issued and read the PAC inside it. |
| `krb5.krbtgtPassword` | `KRB5_KRBTGT_PASSWORD` | `krbtgt-mock-password` | **restart** — the krbtgt keys are derived from it at startup | The key that seals every Ticket-Granting Ticket this realm issues. |
| `krb5.domainSid` | `KRB5_DOMAIN_SID` | `S-1-5-21-1004336348-1177238915-682003330` | **restart** — every principal's PAC identity is built at startup | The domain SID every account's PAC is built under. A Kerberos ticket says who you are; a Windows service authorizes on the SIDs in the PAC. |
| `krb5.trustedRealm` | `KRB5_TRUSTED_REALM` | `PARTNER.COM` | **restart** — the second realm and the trust between them are built at startup | The second realm, for cross-realm referrals. A trust is not a flag: it is a shared key held by one principal in each realm. |
| `krb5.trustPassword` | `KRB5_TRUST_PASSWORD` | `inter-realm-trust-password` | **restart** — the inter-realm key is derived from it at startup | The shared secret both realms hold for the cross-realm trust. |
| `krb5.trustedDomainSid` | `KRB5_TRUSTED_DOMAIN_SID` | `S-1-5-21-2035427030-2118130302-1178042555` | **restart** — the trusted realm's principals are built at startup | The other realm's domain SID. It differs from this one on purpose: SID filtering across a trust is about whose domain a SID belongs to. |
| `krb5.trustedKrbtgtPassword` | `KRB5_TRUSTED_KRBTGT_PASSWORD` | `partner-krbtgt-password` | **restart** — that realm's krbtgt keys are derived from it at startup | The krbtgt password of the trusted realm. |
| `krb5.spnegoAuthentication` | `KRB5_SPNEGO_AUTHENTICATION` | `true` | yes | Whether `/authn/spnego` turns a Kerberos ticket into a browser session — integrated authentication, available to every application and registered for none. With it off that endpoint answers 403 saying which setting it was, and `/spnego/protected` still performs the whole handshake and shows both halves of it; what it will not do is give you a session. An application or a federation relationship naming the `spnego` mechanism while this is off is REPORTED on the sign-in screen rather than meeting a 403 halfway through a flow. |
| `krb5.spnegoLoginButton` | `KRB5_SPNEGO_LOGIN_BUTTON` | `true` | yes | Show a "Sign in with Kerberos" button on `/authn/login`, so a ticket can satisfy any flow already in progress — an authorization request, a `wsignin1.0`, an `AuthnRequest`, the console. Same reason `federation.loginButtons` exists, and it needs no registration at all: whether somebody can use a ticket is a fact about their machine, not about the relying party. Withheld from a request that demanded two factors, and it says so. |
| `krb5.s2kparams` | `KRB5_S2KPARAMS` | `omit` | yes | Whether PA-ETYPE-INFO2 carries s2kparams. Windows Server omits it and this mock sent it, which is the one difference the captured real-DC exchange found; omit is therefore the default and send is kept so a client that reads it can be exercised. |
| `krb5.servicePassword` | `KRB5_SERVICE_PASSWORD` | `service-account-password` | **restart** — the service account's long-term keys are derived from it at startup | The password of the account `krb5.servicePrincipal` names — the keytab equivalent. The account is built FROM that setting (it was always `HTTP/web.<realm domain>` before 2026-09-12). **Product mode refuses the published default**: the account is not created, the acceptor and `/authn/spnego` accept no ticket, and `GET /krb5/service` says why. |
| `krb5.serviceSalt` | `KRB5_SERVICE_SALT` | *(empty)* | **restart** — the service account's long-term keys are derived from it at startup | The string-to-key salt for that account. Empty means this service's convention (`EXAMPLE.COMHTTPweb`); an account in a real Active Directory is salted with its sAMAccountName, so an acceptor for a real KDC's tickets needs it set. |
| `krb5.enctypes` | `KRB5_ENCTYPES` | `18,17,20,19,23` | **restart** — every principal's supported encryption types are fixed at startup | The encryption types the KDC and acceptor use at all, strongest first. Removing `23` (RC4) is what a hardened domain does. A number the codec does not implement stops the service at startup. |
| `krb5.kvno` | `KRB5_KVNO` | `3` | **restart** — every principal's key version is fixed at startup | The key version number every account built from a password in the configuration holds (krbtgt, the acceptor, and in development every fixture and on-demand account); for those, rotation is not modelled. It is also the STARTING kvno of a directory person's first stored keys and of a service principal created at `/admin/kerberos/principals` — and those two do rotate: a password change or a Rotate adds one to the stored kvno, which changing this setting later does not move. |
| `krb5.personKeys` | `KRB5_PERSON_KEYS` | `true` | yes | PRODUCT MODE ONLY. Whether a person's Kerberos keys are derived from their password when it is set or verified, and stored sealed on their own directory entry, so the KDC authenticates them with that password. Off, nothing new is derived and the KDC refuses every person naming this setting; keys already stored stay until cleared at `/admin/kerberos/principals`. The keys are password-equivalent, which is why this can be switched off. Development mode never reads it. |
| `krb5.retainedKeyVersions` | `KRB5_RETAINED_KEY_VERSIONS` | `1` | yes | How many PREVIOUS key versions a stored Kerberos key keeps after a password change or a rotation (0–10). A kept version only opens a ticket already issued under it — the KDC issues under the current kvno and pre-authentication uses the current key only. 0 keeps none: a ticket under the previous kvno is refused `KRB_AP_ERR_BADKEYVER` at once. |
| `krb5.retainedKeyTtlS` | `KRB5_RETAINED_KEY_TTL_S` | `0` | yes | How long each previous key version is kept after it stops being current. 0 means `krb5.ticketLifetimeSeconds` plus `krb5.clockSkew`, the longest a ticket under it can still be presented. Read at every use, so shortening it ends windows at once; lengthening it never revives a version past the bound it was retired under. |
| `krb5.ticketLifetimeSeconds` | `KRB5_TICKET_LIFETIME_S` | `36000` | yes | The longest a ticket this KDC issues is valid for. |
| `krb5.renewLifetimeSeconds` | `KRB5_RENEW_LIFETIME_S` | `604800` | yes | How far renew-till reaches for a renewable ticket. |
| `krb5.logonServer` | `KRB5_LOGON_SERVER` | `DC01` | yes | The LogonServer name in every PAC. |
| `krb5.maxRequestBytes` | `KRB5_MAX_REQUEST_BYTES` | `131072` | yes | The most a client may send on one TCP connection to the KDC before it is closed. |
| `krb5.udpMaxReplyBytes` | `KRB5_UDP_MAX_REPLY_BYTES` | `1465` | yes | A reply larger than this over UDP is answered KRB_ERR_RESPONSE_TOO_BIG so the client retries over TCP. |
| `krb5.serviceMaxTokenBytes` | `KRB5_SERVICE_MAX_TOKEN_BYTES` | `65536` | yes | The largest AP-REQ the acceptor and SPNEGO read. |
| `krb5.replayCacheMaxEntries` | `KRB5_REPLAY_CACHE_MAX_ENTRIES` | `10000` | yes | How many Authenticators the acceptor holds inside the replay window. When it is full the acceptor refuses a NEW Authenticator rather than forgetting one that could still be replayed. |
| `krb5.spnegoPendingTtlSeconds` | `KRB5_SPNEGO_PENDING_TTL_S` | `120` | yes | How long an unfinished request-mic SPNEGO negotiation is held between its two requests. |
| `krb5.spnegoMaxPending` | `KRB5_SPNEGO_MAX_PENDING` | `64` | yes | How many of those are held at once. |

#### LDAP

| Appconfig key | Environment variable | Default | Change while running? | What it does |
|---|---|---|---|---|
| `ldap.port` | `LDAP_PORT` | `389` | **restart** — the socket is bound when the process starts | The plain LDAP listener. 389 is privileged, so a host run that is not root fails to bind it — recorded rather than thrown, and reported by GET /admin/ldap/service. |
| `ldap.tlsPort` | `LDAPS_PORT` | `636` | **restart** — the socket is bound when the process starts | The LDAPS listener, which serves the certificate the TLS module generated. It binds independently of 389, so "389 is up and 636 is not" is an ordinary outcome and each reports itself separately. |
| `ldap.baseDn` | `LDAP_BASE_DN` | `dc=example,dc=com` | **restart** — the directory tree is built under it at startup | The root of the embedded directory. ou=users and ou=groups hang off it. |
| `ldap.autocreateUsers` | `LDAP_AUTOCREATE_USERS` | `true` | yes | When on, an entry appears at uid=<name>,ou=users,<base> the first time anybody authenticates to this service through ANY protocol. On by default: a directory that fills up as you use the other protocols is the thing this one is here to show. |
| `ldap.maxEntries` | `LDAP_MAX_ENTRIES` | `2000` | yes | How large the directory may grow. A ceiling rather than a target: entries appear for anybody who authenticates through any protocol here. |
| `ldap.sizeLimit` | `LDAP_SIZE_LIMIT` | `500` | yes | The server-side size limit for a search, which is what produces LDAP_SIZE_LIMIT_EXCEEDED. |
| `ldap.plainListener` | `LDAP_PLAIN_LISTENER` | `true` | **restart** — the socket is bound when the process starts | Whether the unencrypted listener on `ldap.port` starts at all. Off leaves LDAPS as the only way in — what a product deployment, whose binds are verified, wants; product mode with it on logs a warning that 389 carries passwords in the clear. |
| `ldap.selfWritableAttributes` | `LDAP_SELF_WRITABLE_ATTRIBUTES` | `telephoneNumber,mobile,homePhone,displayName,preferredLanguage,postalAddress,street,l,st,postalCode,userPassword` | yes | In **product** mode, the attributes a connection bound as a person may change on that person's own entry with an LDAP modify. Every other write — another entry, any add, delete or rename, any attribute not listed — needs a connection bound as somebody holding Admin Write in the default realm, and an anonymous connection writes nothing (result code 50). `userPassword` still meets the password policy. Development authorizes no LDAP write. |

#### SCIM

**There is no `scim.authRequired` and there used to be.** It was removed on
2026-09-06 with the other three gate settings: every endpoint under `/scim/v2`
requires a credential in BOTH modes — one of RFC 7644 section 2's six schemes,
with the OAuth ones needing `scim:read` or `scim:write` — because those
endpoints create and DELETE accounts. `global.mode` decides whether the
credential is CHECKED; `mode.gatesScim()` is the one place the gate is decided.

| Appconfig key | Environment variable | Default | Change while running? | What it does |
|---|---|---|---|---|
| `scim.enabled` | `SCIM_ENABLED` | `true` | yes | When on, the SCIM 2.0 endpoints under /scim/v2 create, read, replace, patch and delete entries in the embedded directory. On by default, like every other protocol family here. |
| `scim.maxResults` | `SCIM_MAX_RESULTS` | `200` | yes | The largest page a list or a search will return, published as filter.maxResults in the ServiceProviderConfig and used as the page size when a client asks for none. |
| `scim.bulkMaxOperations` | `SCIM_BULK_MAX_OPERATIONS` | `100` | yes | How many operations one POST /scim/v2/Bulk may carry, published as bulk.maxOperations. A request carrying more is refused with 413 and the payloadTooLarge scimType, which is a reachable negative worth having. |
| `scim.bulkMaxPayloadSize` | `SCIM_BULK_MAX_PAYLOAD_SIZE` | `1048576` | yes | The largest BulkRequest body in bytes, published as bulk.maxPayloadSize and CHECKED against that number rather than against the express body parser's service-wide 5 MB. |
| `scim.authDiscovery` | `SCIM_AUTH_DISCOVERY` | `false` | yes | Whether /ServiceProviderConfig, /ResourceTypes and /Schemas need a credential as well. |
| `scim.authRealm` | `SCIM_AUTH_REALM` | `SCIM` | yes | The protection space named in every WWW-Authenticate challenge, and — for HTTP Digest and HOBA — a value that is hashed or signed OVER, so changing it invalidates every credential computed against the old one. |
| `scim.scopeRead` | `SCIM_SCOPE_READ` | `scim:read` | yes | The OAuth 2.0 scope an access token must carry to read at /scim/v2 — the first scope requirement anywhere in this service. |
| `scim.scopeWrite` | `SCIM_SCOPE_WRITE` | `scim:write` | yes | The scope needed to create, replace, patch, delete or bulk. |
| `scim.authBearer` | `SCIM_AUTH_BEARER` | `true` | yes | Whether an access token is accepted, as Bearer (RFC 6750) or — when it is bound — as DPoP (RFC 9449). |
| `scim.authBasic` | `SCIM_AUTH_BASIC` | `true` | yes | Any username with any password except the reserved "invalid", which is refused so that a 401 stays reachable. RFC 7644 section 2 DISCOURAGES this scheme in those words, and it is offered anyway because it is what a provisioning client most often meets. |
| `scim.authDigest` | `SCIM_AUTH_DIGEST` | `true` | yes | RFC 7616, with SHA-256, SHA-512-256 and MD5 offered in that order and the -sess variants accepted. |
| `scim.digestPassword` | `SCIM_DIGEST_PASSWORD` | `password!` | yes | The password every username shares for HTTP Digest — the same value KRB5_USER_PASSWORD defaults to, so that there is one fact to remember rather than two. |
| `scim.digestNonceSeconds` | `SCIM_DIGEST_NONCE_SECONDS` | `300` | yes | How long a Digest nonce stays usable. After it a credential is refused with stale=true, which RFC 7616 section 3.3 says a client should retry with the same credentials rather than prompting a person — a path most hand-written clients have never run. |
| `scim.digestMd5` | `SCIM_DIGEST_MD5` | `true` | yes | Whether Digest offers and accepts MD5 beside SHA-256 and SHA-512-256. Off, an MD5 credential is refused naming this setting. **Digest itself is never offered in product mode**, whatever `scim.authDigest` says: RFC 7616 needs the server to hold each password or its digest hash, product mode holds only a scrypt hash, and the shared `scim.digestPassword` is not a credential a deployment can offer. The 401 names that password only in development. |
| `scim.maxDigestNonces` | `SCIM_MAX_DIGEST_NONCES` | `2000` | yes | How many issued Digest nonces are remembered. Forgetting a live one does not re-open a replay — its nonce-count record goes with it, so a credential naming it is refused with stale=true. |
| `scim.authHoba` | `SCIM_AUTH_HOBA` | `true` | yes | HTTP Origin-Bound Authentication (RFC 7486), the signature-based scheme RFC 7644 section 2 names and the only one of the six with no shared secret in it. Also turns POST /.well-known/hoba/register on or off. |
| `scim.hobaMaxAgeSeconds` | `SCIM_HOBA_MAX_AGE_SECONDS` | `600` | yes | The max-age published in the HOBA challenge and enforced on the signature. |
| `scim.maxHobaChallenges` | `SCIM_MAX_HOBA_CHALLENGES` | `2000` | yes | How many issued HOBA challenges are remembered; a signature over a forgotten one is refused with a fresh challenge. |
| `scim.maxHobaSeen` | `SCIM_MAX_HOBA_SEEN` | `5000` | yes | How many accepted (kid, challenge, nonce) triples are remembered for replay detection. Expired ones go first; past the bound the oldest goes **with its challenge**, so a copied signature is refused rather than accepted twice. |
| `scim.authCookie` | `SCIM_AUTH_COOKIE` | `true` | yes | Whether the browser sign-on session this service already has — the one /authn/login creates and WS-Federation shares — authenticates a SCIM request. RFC 7644 section 2 names cookies explicitly. |
| `scim.authClientCert` | `SCIM_AUTH_CLIENT_CERT` | `true` | yes | Mutual TLS, the first scheme RFC 7644 section 2 names. It applies only where the request arrived over TLS with a certificate that VERIFIED against an anchor POSTed to /tls/trust, so on the main port only when global.https is on. |

#### Roles

Who holds a role, and what requires one. **A role is not a group**: a group here
grants nothing, and holding a role is what an ISSUANCE is decided on. It is also
not the two *Admin console* roles, which are directory groups granting `/admin`
and nothing else. Both halves of a role — who holds one, and which roles an
application demands — are edited on `/admin/roles` and on the application's own
page rather than in a setting.

| Setting | Environment | Default | Change while running | What it does |
|---|---|---|---|---|
| `roles.claim` | `STS_ROLES_CLAIM` | `true` | yes | When on, every OAuth 2.0 access token, OIDC ID Token, SAML 2.0 assertion and SAML 1.1 assertion names the roles its subject holds. The BUILT-IN roles are never carried — eight of them since 2026-09-06: `EVERYBODY` and `ALL_AUTHENTICATED_USERS` are true of almost every token this service issues, so carrying them would tell a relying party nothing it did not know from holding the token, and the two group-derived ones (`REMOTE_PEPS`, `XACML_USER`) say which of this service's own XACML endpoints the holder may reach, which is nobody else's business. |
| `roles.claimName` | `STS_ROLES_CLAIM_NAME` | `roles` | yes | What the claim is called: the JWT member name, the SAML 2.0 Attribute Name and the SAML 1.1 AttributeName. |
| `authn.unauthenticatedSessions` | `STS_AUTHN_UNAUTHENTICATED_SESSIONS` | `false` | yes | Show a third button on `/authn/login` — **Continue without signing in** — that starts a session for somebody who declines to authenticate. The session is real: it has a cookie, it satisfies a flow already in progress, tokens can be issued on it, and it appears on `/admin/sessions` in a section of its own. What it records is `authenticated: false`, so an application requiring `ALL_AUTHENTICATED_USERS` refuses it and one requiring `EVERYBODY` does not — **the only place in this service where the difference between those two built-in roles is visible**. The person is the stable `anonymous` principal, which gets a directory entry like anybody else and can therefore hold configured roles too. **Off by default**, unlike `roles.enforceIssuance` beside it, because this one changes a SCREEN: enforcement on by default changes nothing for an unedited service, and a third button on every sign-in screen would change what every existing caller's user sees. Cancel is unchanged and still answers `access_denied` without creating anything. |
| `roles.enforceIssuance` | `STS_ROLES_ENFORCE_ISSUANCE` | `true` | yes | Whether this service ASKS before it issues anything. On, each of the nine kinds of issuance is a XACML request decided by the embedded PEP against a policy; off, nothing is asked and everything is allowed. **On by default costs nothing until an application is narrowed**: one that names no required role requires `EVERYBODY`, everybody holds `EVERYBODY`, and the answer is Permit — so the machinery is always running and always visible, and turning enforcement on for an application is narrowing a list rather than switching on a subsystem that has never run. Off is the way back if a policy edit locks something out. |
| `roles.maxRoles` | `STS_ROLES_MAX` | `200` | yes | How many role entries `ou=roles` will hold, per trust realm. |
| `roles.remotePepGroup` | `STS_ROLES_REMOTE_PEP_GROUP` | `remote-peps` | yes | The directory group whose members hold the built-in `REMOTE_PEPS` role, which is what `POST /xacml/pep/register`, `GET /xacml/pep/policies`, `POST /xacml/pep/heartbeat` and `POST /xacml/pip` require. A remote Policy Enforcement Point presenting a client certificate this service VERIFIED is somebody it can NAME; membership of this group is what makes them somebody it lets IN, and the two are kept apart on purpose — **the certificate says who and the group says whether**, so a perfectly valid certificate for the wrong common name is refused while being fully authenticated. Setting it to the empty string means nobody holds the role, which closes those four endpoints to every caller including a correctly configured PEP. |
| `roles.xacmlUserGroup` | `STS_ROLES_XACML_USER_GROUP` | `xacml-users` | yes | The same arrangement for the built-in `XACML_USER` role, which is what the four XACML endpoints proper require — `GET /xacml`, `POST /xacml/pdp`, `GET /xacml/policies` and `GET /xacml/protected`. **It is a SECOND group and not the same one**, because `/xacml/pep/*` publishes the documents this service enforces its own access with and `POST /xacml/pip` publishes a named person's directory attributes; one group granting both would make admitting a caller to the demonstration surface silently admit it to those. A person is granted the role by being put in this group — one line on `/admin/ldap/directory` or one `ldapmodify` — and it takes effect on the very next request, because membership is resolved at decision time. Setting it to the empty string closes those four endpoints to everybody, which is how to take the XACML surface away without turning `xacml.enabled` off and losing the embedded issuance and access PEPs with it. `xacml.enforceAccess` is the other way, and it opens both sets at once. |

#### TOTP MFA

RFC 6238 one-time passwords — the second factor a person enrols from
`/portal/mfa` or while spending an activation link, and the only credential
this service checks besides a Kerberos ticket. Drawn on **`/admin/totp`**,
under Protocols.

**This group was called `Multi-factor authentication` until 2026-09-10**, and
its page was `/admin/mfa` under Identities. It named a CATEGORY where every
other group here names a mechanism or a family, and its page mixed these eight
rows in with a roster of people — so a reader looking for the skew window and a
reader looking for *who has no second factor* landed on one screen and read past
each other. There are two mechanisms, each has a group and a page of its own
now, and the roster is columns on `/admin/users`.

| Appconfig key | Environment variable | Default | Change while running? | What it does |
|---|---|---|---|---|
| `totp.enabled` | `STS_TOTP_ENABLED` | `true` | yes | Whether a person may enrol an RFC 6238 authenticator app as a second factor, on `/portal/mfa` or while spending an activation link. **Turning it off does NOT disable a secret somebody already enrolled** — that account is still configured for two factors and the sign-in screen still asks for the code. A setting that silently downgraded every enrolled account to a password alone would be a security control whose off switch does something other than what it says. What it stops is new enrolments; an existing one is removed on that person's own row under `/admin/users`. |
| `totp.issuer` | `STS_TOTP_ISSUER` | *(empty)* | yes | The name an authenticator app shows beside the account — the `issuer` of the otpauth Key Uri Format, written both as a prefix on the label and as a parameter because older apps read one and newer ones the other. **Empty means this realm's own host**, with the realm id after it where there is one, which is deliberate: two realms of one process are two identity providers, and a phone showing two accounts with the same name beside them is a list nobody can use. |
| `totp.algorithm` | `STS_TOTP_ALGORITHM` | `SHA1` | yes | RFC 6238 section 1.2 defines all three and names HMAC-SHA-1 as the default. **LEAVE IT AT SHA1 UNLESS YOU ARE TESTING EXACTLY THIS.** Several widely used authenticator apps — Google Authenticator among them — IGNORE the `algorithm` parameter in the QR code and always compute SHA-1, so any other value produces a code that scans perfectly and then generates codes this service refuses, with nothing anywhere saying why. SHA-1 is not a weakness here: this is a keyed MAC over a counter, not a collision-resistant digest. Changing it affects NEW enrolments only — an existing secret is verified with the algorithm it was enrolled under, which is the one the app was told. |
| `totp.digits` | `STS_TOTP_DIGITS` | `6` | yes | Six is what every authenticator app shows and what RFC 4226 section 5.3 recommends; eight is defined and is worth setting only to find out what a client does with it. NEW enrolments only, for the reason the digest gives. |
| `totp.period` | `STS_TOTP_PERIOD` | `30` | yes | RFC 6238 section 4.1's time step X. Thirty seconds is the default and what every app assumes. NEW enrolments only. |
| `totp.window` | `STS_TOTP_WINDOW` | `1` | yes | How many steps either side of now are accepted. RFC 6238 section 5.2 recommends at most one, which is the default and makes a code good for about ninety seconds. **This one IS live** and applies to every existing enrolment — how much a deployment forgives a phone with a drifting clock is a policy rather than something the QR code told the app. Zero demands a perfectly synchronised clock and is the setting to reach for when demonstrating what happens without one. |
| `totp.secretBytes` | `STS_TOTP_SECRET_BYTES` | `20` | yes | RFC 4226 section 4 requirement R6 says at least 128 bits and recommends 160, which is the 20 bytes here and the length of an HMAC-SHA-1 key. Longer is allowed and is transcribed by hand by anybody who cannot scan the QR code — 20 bytes is already 32 base32 characters. |
| `totp.enrolmentTtlMinutes` | `STS_TOTP_ENROLMENT_TTL_MINUTES` | `10` | yes | How long a secret that has been SHOWN but not yet confirmed with a code stays available. It is held in memory and never written to the directory until a code proves the app really has it — an unconfirmed secret on somebody's entry would be a second factor they cannot produce, which is a lockout rather than a control. Ten minutes is long enough to find a phone and short enough that an abandoned enrolment does not sit in memory. |

Three things about these do not fit in a cell.

* **The digest, the digit count and the period affect NEW enrolments only.** An
  existing secret is verified with the parameters it was enrolled under, which
  are the ones the QR code told the app — this service cannot change them
  retrospectively, and a setting that silently locked out everybody who had
  already enrolled would be the worst kind of knob. **The skew window is the
  exception and applies to everybody**: how much a deployment forgives a
  drifting clock is a policy rather than something the app was told.
* **Leave `totp.algorithm` at SHA1 unless you are testing exactly that.**
  Several widely used authenticator apps — Google Authenticator among them —
  ignore the `algorithm` parameter in the QR code and always compute SHA-1, so
  any other value produces a code that scans perfectly and then generates codes
  this service refuses, with nothing anywhere saying why. SHA-1 is not a
  weakness here: this is a keyed MAC over a counter, not a
  collision-resistant digest.
* **`totp.enabled` off does not disable an existing enrolment**, and that is
  deliberate. A person who enrolled while it was on still holds the second
  factor their account is configured for, and a setting that silently
  DOWNGRADED every one of those accounts to a password alone would be a
  security control with an off switch that does something else. What it stops
  is new enrolments; an existing one is removed on that person's own row
  under `/admin/users`.

#### Backup codes

Recovery codes — the way back in when the second factor is not to hand. Drawn
on **`/admin/backup-codes`**, under Protocols.

**This is the only mechanism on that console that no specification defines.**
Everything else here implements somebody's document and can be checked against
it; there is no RFC for a recovery code. What every identity provider does
converges anyway — a handful of random strings, each accepted once — so the
decisions that are left are this service's own, and `common/backup_codes.js`
argues each of them.

| Appconfig key | Environment variable | Default | Change while running? | What it does |
|---|---|---|---|---|
| `backupCodes.enabled` | `STS_BACKUP_CODES_ENABLED` | `true` | yes | Whether a person may generate a set of single-use recovery codes on `/portal/mfa` — shown once, stored as scrypt hashes only when they confirm they kept it. (Until 2026-09-11 a set was issued automatically on enrolling a second factor.) **Turning it off does NOT invalidate a set somebody already holds**, which is the contract `totp.enabled` and `webauthn.enabled` both keep: a person issued ten codes still holds ten and the sign-in door still accepts one. A setting that silently took away the only way back into an account whose phone is lost would be the worst knob in this service. What it stops is a new set being issued. |
| `backupCodes.count` | `STS_BACKUP_CODES_COUNT` | `10` | yes | How many codes are issued. Ten is what almost every identity provider settles on: enough that losing a printed copy of one does not end the account, few enough to fit on a card in a wallet. **A set is never topped up**: generating a new one replaces the old set whole. |
| `backupCodes.length` | `STS_BACKUP_CODES_LENGTH` | `10` | yes | Out of an alphabet of thirty-two, so ten characters is fifty bits — which is the number that matters rather than the length. |
| `backupCodes.groupSize` | `STS_BACKUP_CODES_GROUP_SIZE` | `5` | yes | Purely presentational: `A2CDE-FGH3J` rather than `A2CDEFGH3J`, so that a person transcribing one does not lose their place. Every door strips the dashes and the spaces back out before comparing, so a code typed either way is the same code. Zero prints it unbroken. |

Five things about this mechanism do not fit in a cell.

* **A SET IS ISSUED BY AN ACT AND NOT BY A REQUEST.** There is no control
  anywhere — on `/portal`, on `/admin`, on `/admin-api` — that issues one. The
  two call sites are a confirmed authenticator enrolment and a security key
  enrolled in the `mfa` role, both in `common/credentials.js`. A recovery
  mechanism a person has to remember to ask for produces exactly the population
  it exists to protect, one person at a time: the ones who did not ask are the
  ones who will need it.
* **ONCE. NOT ONCE PER ENROLMENT.** Enrolling a different second factor does
  not reissue. Somebody who printed a list in March and replaced their
  authenticator app in June would otherwise be holding a page of strings that
  had stopped working with nothing having said so, and a recovery credential
  that silently expires is worse than none — the person believes they have a
  way back. **An operator's Clear on that person's row under `/admin/users` is
  the only route to a second set**, after which the next enrolment issues one.
* **THE CODES ARE ENCRYPTED AND NOT HASHED**, which is the opposite of
  `userPassword` and is a product decision rather than a cryptographic one.
  This repository's rule is that a secret this service VERIFIES is hashed and
  a secret it must PRESENT cannot be; a recovery code is both, and what decides
  it is whether a person may look at their remaining codes again. This service
  says yes — a list shown exactly once at the end of an enrolment somebody is
  rushing through is a list most people close without reading, and the moment
  it matters is months later. They are sealed with AES-256-GCM under the same
  key-encryption key as the signing keys wherever that key outlives the
  process, and stored as the strings they were shown as where it does not,
  because sealing under development mode's per-run key would mean a printed
  list that stopped working at the next restart.
* **THE ALPHABET IS THE BASE32 CHARACTERS AND IS NOT SHARED WITH `totp.*`.**
  That one is base32 because the `otpauth` URI says so — an interoperability
  requirement. This one is the same thirty-two characters because none of them
  is confusable with another: no `0` beside `O`, no `1` beside `I`. A recovery
  code is the one credential here that somebody writes on paper and types back
  months later.
* **A CODE IS NEVER A FIRST FACTOR AND NEVER THE FACTOR A SIGN-IN ASKS FOR.**
  The screen asks for whichever mechanism the person is CONFIGURED for, and
  `/authn/backup-code` is reachable only as a link out of one of those two
  screens. Holding a set does not make a second factor required of anybody.

#### WebAuthn

Security keys — W3C WebAuthn Level 3 over FIDO CTAP2 — as a second factor OR as
the only credential on an account. Drawn on **`/admin/webauthn`**, under
Protocols.

**NOT ONE OF THESE EXISTED UNTIL 2026-09-10**, and the sentence they replace is
worth knowing: this project said WebAuthn had *no settings at all — what a
ceremony does is decided by the specification and by the browser*. That is true
of the CRYPTOGRAPHY and false of the CEREMONY. What a browser does with
`navigator.credentials.create()` is decided almost entirely by the options the
relying party hands it, and every one of those was a literal inside a string in
`authn/authn.js` — so a client author trying to find out what their client does
with `attestation: "none"`, or with a discoverable credential, had no way to ask
this service for one.

| Appconfig key | Environment variable | Default | Change while running? | What it does |
|---|---|---|---|---|
| `webauthn.enabled` | `STS_WEBAUTHN_ENABLED` | `true` | yes | Whether this service offers a WebAuthn ceremony at all — the two boxes on the sign-in screen, the enrolment on `/portal/keys`, and the `/authn/webauthn` screen itself. **Turning it off does NOT remove a key somebody already enrolled**, exactly as `totp.enabled` does not remove a shared secret. What it stops is new ceremonies. |
| `webauthn.rpName` | `STS_WEBAUTHN_RP_NAME` | `Mock authorization server` | yes | The `rp.name` handed to the browser — what a person and their password manager see while deciding whether to create a credential, and what a platform authenticator stores beside it. It has NO security meaning: WebAuthn binds a credential to the RP ID and to nothing else. |
| `webauthn.rpId` | `STS_WEBAUTHN_RP_ID` | *(empty)* | yes | **Empty means the host this service was reached on**, which is almost always right. A value may only WIDEN it to a registrable domain suffix of that host — `example.com` when reached at `sts.example.com` — which is WebAuthn's own rule; anything else is refused here by name in the log, because a browser refuses it with an error indistinguishable from a hardware failure. **In development mode** the host is then used instead; **in product mode the ceremony is refused**. Widening it means every host under that suffix can assert these credentials. |
| `webauthn.allowedOrigins` | `STS_WEBAUTHN_ALLOWED_ORIGINS` | *(empty)* | yes | The origins a ceremony's clientDataJSON may carry, comma-separated. **Empty derives the one origin from the address this service was reached at** (which `global.publicBaseUrl` pins); set, the list is the whole answer. |
| `webauthn.algorithms` | `STS_WEBAUTHN_ALGORITHMS` | `ES256,RS256` | yes | `pubKeyCredParams`, in preference order, as JOSE names: `ES256`, `ES384`, `ES512`, `EdDSA`, `RS256`, `RS384`, `RS512`. A name outside that table is dropped with a warning rather than sent — offering an algorithm this service cannot verify produces a credential that enrols perfectly and then fails every assertion it is ever used for. |
| `webauthn.userVerification` | `STS_WEBAUTHN_USER_VERIFICATION` | `preferred` | yes | Whether the authenticator must verify the PERSON — a PIN, a fingerprint, a face — as well as prove possession. **THIS IS THE ONE CEREMONY SETTING THIS SERVICE ALSO ENFORCES**: `required` is sent to the browser and the UV flag in the signed authenticator data is then checked. **It does not change what a session CLAIMS** — a passwordless sign-in still records `amr ["hwk"]` and `acr "1"`, because RFC 8176 has no value for *the authenticator verified the user* this service could honestly assert. |
| `webauthn.attestation` | `STS_WEBAUTHN_ATTESTATION` | `direct` | yes | How much the browser is asked to say about the authenticator. `direct` is the default because this is a debugging service and the attestation object is worth looking at; a real deployment with no attestation policy should send `none`. **NO ATTESTATION STATEMENT IS VERIFIED WHATEVER IS ASKED FOR** — no metadata service, no vendor trust anchor, no model allow-list. |
| `webauthn.timeoutMs` | `STS_WEBAUTHN_TIMEOUT_MS` | `60000` | yes | The `timeout` in the options handed to the browser. It is a HINT and clients may clamp it. The pending step this service holds expires on its own five-minute clock regardless, so a longer timeout buys a ceremony that succeeds in the browser and is then refused here. |
| `webauthn.authenticatorAttachment` | `STS_WEBAUTHN_ATTACHMENT` | `any` | yes | Which kind of authenticator may answer — `platform` (Touch ID, Windows Hello, a screen lock) or `cross-platform` (a roaming CTAP2 key over USB, NFC or BLE). `any` sends no preference at all, because the options dictionary has no value meaning one. It is a FILTER IN THE BROWSER and not a check here. |
| `webauthn.residentKey` | `STS_WEBAUTHN_RESIDENT_KEY` | `discouraged` | yes | Whether the credential is stored ON the authenticator — a CTAP2 *resident key*, which is what a passkey is and what a usernameless sign-in needs. `discouraged` is the default because a resident key consumes one of the small number of slots a roaming authenticator has and cannot always be deleted from it. **This service offers no usernameless flow**, so `required` buys a slot and nothing else here. |
| `webauthn.credProps` | `STS_WEBAUTHN_CRED_PROPS` | `true` | yes | Asks the browser to report whether the credential it made is actually discoverable. It is the only way to find out — `residentKey: "preferred"` may or may not produce one and nothing in the attestation says which. The answer is recorded beside the key and decides nothing. |
| `webauthn.primaryAllowed` | `STS_WEBAUTHN_PRIMARY_ALLOWED` | `true` | yes | Whether a key may be the ONLY credential on an account — a passwordless sign-in. Off, keys still work as a second factor. **It does not disable a primary key somebody already holds**: an operator flipping a switch must not lock somebody out of their own account. |
| `webauthn.mfaAllowed` | `STS_WEBAUTHN_MFA_ALLOWED` | `true` | yes | Whether a key may be enrolled as a second factor beside a password. With this and `totp.enabled` both off, this service offers no second factor at all, which is a supported configuration and is what it did before either existed. An enrolled `mfa` key goes on being demanded. |
| `webauthn.maxKeysPerPerson` | `STS_WEBAUTHN_MAX_KEYS` | `10` | yes | How many security keys one person may hold. Several is the ordinary case and the specification expects it — an assertion NAMES the credential that produced it, so there is none of the ambiguity two shared secrets would have. It refuses the ENROLMENT and never an authentication. |

Three things about these do not fit in a cell.

* **ONE of them is enforced and the rest are requests.**
  `webauthn.userVerification` is sent to the browser AND checked against the UV
  flag when the ceremony returns, because that flag is inside the bytes the
  authenticator signed. Nothing signed says what the browser was asked about
  attestation, the resident key or the attachment — so a check on those would be
  a comparison against a value this service itself supplied. What it does
  instead is RECORD what came back, beside the key.
* **The last four rows are not WebAuthn.** `enabled`, `primaryAllowed`,
  `mfaAllowed` and `maxKeysPerPerson` are what THIS service will do with a key
  once the ceremony is over, decided here rather than by any specification — and
  all four refuse an ENROLMENT and never an authentication. A key already on
  somebody's entry goes on working when the role that produced it is switched
  off.
* **The RP ID may be widened and never moved.** It is the host this service was
  reached on unless `webauthn.rpId` names a registrable domain suffix of that
  host. That is WebAuthn's rule and browsers enforce it; this service enforces
  it too, so a wrong value is a line in the log rather than what looks like a
  broken authenticator.

#### Group claim

| Appconfig key | Environment variable | Default | Change while running? | What it does |
|---|---|---|---|---|
| `groups.claim` | `STS_GROUPS_CLAIM` | `true` | yes | When on, every OAuth 2.0 access token, OIDC ID Token, SAML 2.0 assertion and SAML 1.1 assertion this service issues carries a claim naming the directory groups the person is a member of. |
| `groups.claimName` | `STS_GROUPS_CLAIM_NAME` | `groups` | yes | What the claim is called: the JWT member name, the SAML 2.0 Attribute Name and the SAML 1.1 AttributeName. `groups` is the conventional spelling and what most relying parties look for, but `roles` and a URI are both common and both worth being able to produce. |
| `groups.claimValue` | `STS_GROUPS_CLAIM_VALUE` | `cn` | yes | Whether each value is the group's common name (`developers`) or its whole DN (`cn=developers,ou=groups,dc=example,dc=com`). |
| `groups.claimFromMemberOf` | `STS_GROUPS_CLAIM_FROM_MEMBEROF` | `true` | yes | Whether a group named by the PERSON'S own `memberOf` counts as membership when the group entry does not list them back. |

#### Audit log

| Appconfig key | Environment variable | Default | Change while running? | What it does |
|---|---|---|---|---|
| `audit.maxEvents` | `AUDIT_MAX_EVENTS` | `5000` | yes | How many audit events /admin/audit keeps before the oldest are dropped. What was dropped is COUNTED and shown, so a truncated log says it was truncated rather than implying the cap is all there ever was. |
| `audit.protocolCalls` | `AUDIT_PROTOCOL_CALLS` | `true` | yes | Whether every call into a protocol endpoint gets an audit event. |

#### Delegation

| Appconfig key | Environment variable | Default | Change while running? | What it does |
|---|---|---|---|---|
| `delegation.maxRecords` | `DELEGATION_MAX_RECORDS` | `2000` | yes | How many delegation acts /admin/delegation keeps before the oldest are dropped. An act is one exchange in which somebody acted on somebody else's behalf — a Kerberos S4U request or forwarded ticket, a WS-Trust OnBehalfOf or ActAs, an RFC 8693 token exchange — and REFUSED attempts are recorded too. What was dropped is COUNTED and shown. |
| `logout.anyUser` | `LOGOUT_ANY_USER` | `true` | yes | Whether `/logout` honours a `username` naming somebody other than whoever the session cookie names. **In development mode** it grants nothing that was not already true — no password is checked at any sign-in screen there, so becoming that person takes one request — and what it buys is a headless test. **In product mode it is ignored**: a sign-out may name only the signed-in caller, because otherwise an anonymous request could end anybody's sessions and revoke their tokens. Off, `/logout` acts only on the caller's own session and 403s a request that names another name; `/admin/logout` and `/admin-api/logout` are unaffected. |
| `logout.kerberosSignOut` | `LOGOUT_KERBEROS_SIGN_OUT` | `true` | yes | Whether a logout stamps a sign-out instant on the Kerberos principal, after which a `TGS-REQ` carrying a ticket whose `authtime` is earlier is refused KDC_ERR_TGT_REVOKED (20). It does NOT stop a service ticket already in a cache — accepting one never contacts the KDC — and an `AS-REQ` still succeeds and clears the instant. Off, the KDC behaves exactly as it did before this feature existed. |
| `logout.ldapDisconnect` | `LOGOUT_LDAP_DISCONNECT` | `true` | yes | Whether a logout closes every connection to the embedded directory, 389 and 636 alike, whose bind DN names that person. RFC 4511 section 4.2 makes the bind the authorization state of a CONNECTION, so the connection is the session. Off, they are left alone and listed on `/logout` as untouched rather than hidden. |
| `logout.maxRows` | `LOGOUT_MAX_ROWS` | `500` | yes | How many live items `/logout` lists for one person. The cap is on what is DRAWN and offered as a checkbox, never on what a termination reaches — a global logout still ends all of them. |

#### SPIFFE

**There is no `spiffe.authRequired` and there used to be.** It was removed on
2026-09-06 with the other three gate settings, and with it the restart-only
caveat that row carried: the SPIRE Server API's TCP port is bound as mutual TLS,
always, because what comes out of that surface is a credential another service
will believe. Every method is authorized against SPIRE's own per-method table,
which `GET /spiffe` publishes in full. **The Workload API is deliberately not on
that list and must never be**: its specification says it MUST NOT authenticate a
caller, because a workload has no root of trust until that call gives it one.
What it lacks there is ATTESTATION, not authentication, and no mode changes it.

| Appconfig key | Environment variable | Default | Change while running? | What it does |
|---|---|---|---|---|
| `spiffe.enabled` | `STS_SPIFFE_ENABLED` | `true` | yes | Whether the three SPIFFE surfaces answer. |
| `spiffe.trustDomain` | `STS_SPIFFE_TRUST_DOMAIN` | `example.org` | **restart**, and **settable on a REALM** — the process's authorities are generated at startup and every certificate they hold names this trust domain; a realm is created with SPIFFE off and builds its own when it is turned on | The trust domain this service is the issuing authority for: the authority part of every SPIFFE ID it mints, so spiffe://example.org/… by default. **It is also the common root every other realm's is built from** — a realm created here is given `<realm>.<this value>`, the way it is given an entityID of its own. Set it on a realm to name that realm's domain outright. Once a realm's authorities are built the name is fixed, and a later change is reported as drift on `/admin/spiffe` rather than acted on. |
| `spiffe.x509KeyType` | `STS_SPIFFE_X509_KEY_TYPE` | `ec-p256` | **restart** — the X.509 authority is generated with this key type at startup | The key the trust domain's X.509 authority is generated with, and therefore the key type of every X509-SVID it signs. EC P-256 by default because that is what SPIRE issues and what the X509-SVID specification recommends. |
| `spiffe.jwtKeyType` | `STS_SPIFFE_JWT_KEY_TYPE` | `ec-p256` | **restart** — the JWT authority is generated with this key type at startup | The key the trust domain's JWT authority is generated with, which decides the `alg` of every JWT-SVID: ES256, ES384, ES512 or RS256. |
| `spiffe.caTtl` | `STS_SPIFFE_CA_TTL` | `86400` | **restart** — the authority certificate is issued for this long at startup | How long the X.509 authority's own certificate is valid. |
| `spiffe.svidTtl` | `STS_SPIFFE_SVID_TTL` | `3600` | yes | The default lifetime of an X509-SVID. A registration entry may name its own and that wins; this is what an entry with no `x509SvidTtl` gets. |
| `spiffe.jwtSvidTtl` | `STS_SPIFFE_JWT_SVID_TTL` | `300` | yes | The default lifetime of a JWT-SVID. Much shorter than the X.509 one on purpose and in both SPIRE and here: a JWT-SVID is a bearer credential — whoever holds it can present it — where an X509-SVID is bound to a private key. |
| `spiffe.refreshHint` | `STS_SPIFFE_REFRESH_HINT` | `300` | yes | The `spiffe_refresh_hint` published in the bundle: how often a consumer should come back for it. |
| `spiffe.svidSubject` | `STS_SPIFFE_SVID_SUBJECT` | `C=US,O=SPIRE` | yes | The X.501 subject written into every X509-SVID. The SPIFFE ID is in a URI subjectAltName and IS the identity; this is decoration, and it is SPIRE's own value by default so that an SVID from here looks like one from there. |
| `spiffe.caSubject` | `STS_SPIFFE_CA_SUBJECT` | `CN=sts SPIFFE {kind} ({trustDomain}),O=sts` | yes | The subject of a CA this service builds for SPIFFE itself — the self-signed fallback authority and every downstream CA. `{kind}` is `CA` or `downstream CA`. A realm under the certificate authority takes its Issuing CA's subject from `/admin/pki`. |
| `spiffe.retainedAuthorities` | `STS_SPIFFE_RETAINED_AUTHORITIES` | `4` | yes | How many authorities a rotation keeps published (self-signed X.509 and JWT), the new one included. At least 2. |
| `spiffe.agentSvidTtl` | `STS_SPIFFE_AGENT_SVID_TTL` | `0` | yes | The lifetime of an agent's X509-SVID from AttestAgent and RenewAgent. `0` means `spiffe.svidTtl`. |
| `spiffe.autoCreateEntries` | `STS_SPIFFE_AUTOCREATE_ENTRIES` | `true` | yes | THIS IS THE SETTING THAT MAKES THIS A MOCK. |
| `spiffe.requireSecurityHeader` | `STS_SPIFFE_REQUIRE_SECURITY_HEADER` | `true` | yes | The Workload Endpoint specification says a client MUST send `workload.spiffe.io: true` on every call and a server MUST refuse one without it. |
| `spiffe.trustLocalSocket` | `STS_SPIFFE_TRUST_LOCAL_SOCKET` | `true` | yes | A real SPIRE server trusts its private Unix socket outright — the access control is the socket's filesystem permissions — and a caller there is the `local` entity, which may do everything an admin may and two things an admin may not. |
| `spiffe.adminIds` | `STS_SPIFFE_ADMIN_IDS` | *(empty)* | yes | SPIFFE IDs whose holders are administrators of the SPIRE Server API, separated by commas or spaces — SPIRE's own `admin_ids`, and like SPIRE's it needs NO registration entry behind it. |
| `spiffe.clockSkew` | `STS_SPIFFE_CLOCK_SKEW` | `60` | yes | How far out a caller's clock may be when its X509-SVID is checked for validity. |
| `spiffe.attestWorkloads` | `STS_SPIFFE_ATTEST_WORKLOADS` | `true` | yes | ON, a Workload API caller is IDENTIFIED from what this service can actually see about it — the transport, the endpoint it reached, its peer address — and is answered with the registration entries whose selectors that identification matches, which is what a real agent does. |
| `spiffe.acceptAssertedSelectors` | `STS_SPIFFE_ACCEPT_ASSERTED_SELECTORS` | `false` | yes | OFF by default, and it is the one setting here that is not attestation of any kind. |
| `spiffe.maxEntries` | `STS_SPIFFE_MAX_ENTRIES` | `500` | yes | How many entries may live under ou=spiffe. Past it a new one is REFUSED and the SVID request that would have created it is answered without one — the registry is a directory container and a container has a size, the same cap ou=applications has. |
| `spiffe.maxAgents` | `STS_SPIFFE_MAX_AGENTS` | `200` | yes | How many attested agents are held. The agent id comes off whatever the caller sent, so any caller can invent one; past the cap the oldest is dropped rather than the newest refused, because an agent that cannot attest is an agent that cannot do anything at all. |
| `spiffe.maxFederatedBundles` | `STS_SPIFFE_MAX_FEDERATED_BUNDLES` | `32` | yes | How many foreign trust domains' bundles are held. They are PASTED IN and never fetched — see /spiffe — so this bounds what an operator or the SPIRE Server API can add, not what any polling loop could accumulate. |
| `spiffe.joinTokenTtl` | `STS_SPIFFE_JOIN_TOKEN_TTL` | `600` | yes | A join token's lifetime when CreateJoinToken names none. |
| `spiffe.maxJoinTokens` | `STS_SPIFFE_MAX_JOIN_TOKENS` | `256` | yes | Unspent, unexpired join tokens a realm holds. At the bound a NEW token is refused with RESOURCE_EXHAUSTED; a token already handed to an agent is never evicted. |
| `spiffe.maxPageSize` | `STS_SPIFFE_MAX_PAGE_SIZE` | `1000` | yes | The cap on `page_size` for every SPIRE Server API `List*` method. |
| `spiffe.maxRecordedConnections` | `STS_SPIFFE_MAX_RECORDED_CONNECTIONS` | `512` | yes (per process — a realm may not carry it) | How many mTLS connections are remembered so an X509-SVID is one authentication per connection rather than per call. |
| `spiffe.bundlePath` | `STS_SPIFFE_BUNDLE_PATH` | `/spiffe/bundle` | **restart** — the route is registered at require time, and the require order is the route order | Where the trust bundle is published. A real federation partner is configured with this URL and polls it. |
| `spiffe.workloadSocketEnabled` | `STS_SPIFFE_WORKLOAD_SOCKET_ENABLED` | `true` | **restart** — the listener is bound when the process starts | Whether the Workload API is served on a Unix domain socket. ON by default because that is what SPIFFE_ENDPOINT_SOCKET means to every real client — go-spiffe, spiffe-helper, the SPIRE agent — so without it nothing connects unconfigured. |
| `spiffe.workloadSocket` | `STS_SPIFFE_WORKLOAD_SOCKET` | `/tmp/spire-agent/public/api.sock` | **restart** — the listener is bound when the process starts | Where that socket lives. SPIRE's own default path, so a client that was pointed at a SPIRE agent needs no change. |
| `spiffe.workloadPort` | `STS_SPIFFE_WORKLOAD_PORT` | `8092` | **restart** — the listener is bound when the process starts | The Workload API over TCP, which the Workload Endpoint specification permits (tcp://host:port) and which is how this is reached from another container or from a host that cannot share the socket. 0 turns it off and leaves the Unix socket alone. |
| `spiffe.serverPort` | `STS_SPIFFE_SERVER_PORT` | `8181` | **restart** — the listener is bound when the process starts | The SPIRE Server API — Entry, Agent, Bundle, SVID, TrustDomain and Debug — over gRPC. |
| `spiffe.serverSocketEnabled` | `STS_SPIFFE_SERVER_SOCKET_ENABLED` | `false` | **restart** — the listener is bound when the process starts | Whether the SPIRE Server API is also served on a Unix socket, which is where a real spire-server keeps its administrative API. |
| `spiffe.serverSocket` | `STS_SPIFFE_SERVER_SOCKET` | `/tmp/spire-server/private/api.sock` | **restart** — the listener is bound when the process starts | Where that socket lives when it is on. SPIRE's own default path, for the same reason the Workload API's is. |
| `spiffe.grpcHost` | `STS_SPIFFE_GRPC_HOST` | `0.0.0.0` | **restart**, and **settable on a REALM** — a realm's listeners are bound when its SPIFFE is turned on | The address both TCP gRPC listeners bind. 0.0.0.0 is every interface, which is what a container needs; 127.0.0.1 confines them to the machine this runs on. **THIS IS THE ROW THAT KEEPS TWO REALMS APART**: each takes an address of its own and keeps the ports, because the endpoint address is the only thing a SPIFFE client has to name a tenant with. A realm left on the wildcard collides with the default realm's listeners, and the refusal says so by name. |
| `ssf.authBasic` | `STS_SSF_AUTH_BASIC` | `true` | yes | Whether the Shared Signals endpoints accept HTTP Basic. Development accepts any name with any password but `invalid`; product mode verifies it against the person's hashed `userPassword`. A Basic principal holds both scopes either way — turn this off to enforce `ssf:read`/`ssf:write` for every caller. |
| `ssf.pushMaxResponseBytes` | `STS_SSF_PUSH_MAX_RESPONSE_BYTES` | `65536` | yes | How much of a receiver's answer to a push is read before the push counts as failed. |
| `ssf.pushRetries` | `STS_SSF_PUSH_RETRIES` | `0` | yes | How many times a failed push is tried again. `0` is what this service always did. Only a connection failure, a timeout, a 5xx or a 429 is retried — never a receiver's 400 refusal. |
| `ssf.pushRetryDelayMs` | `STS_SSF_PUSH_RETRY_DELAY_MS` | `1000` | yes | The wait before a retry, times the attempt number. |
| `ssf.pushConcurrency` | `STS_SSF_PUSH_CONCURRENCY` | `8` | yes | How many pushes one process makes at once; the rest wait in order. `0` removes the cap. **Per process, not per cluster**: N nodes of P processes push up to N×P× this at once. |
| `ssf.pushBacklog` | `STS_SSF_PUSH_BACKLOG` | `2000` | yes | How many pushes may wait for a slot. Past it the SET goes to the stream's dead-letter queue instead of being pushed. Per process, like the cap. |
| `ssf.deadStreamTimeoutS` | `STS_SSF_DEAD_STREAM_TIMEOUT_S` | `300` | yes | A push stream whose pushes have all failed for this long is declared **dead**: nothing more is pushed, its SETs go to its dead-letter queue, and one is pushed as a probe each period — a success revives it (so does `POST /admin-api/ssf/revive`). `0` turns it off. |
| `ssf.deadLetterRetentionS` | `STS_SSF_DEAD_LETTER_RETENTION_S` | `3600` | yes | How long an undeliverable SET is kept on its stream's dead-letter queue, with the reason, for inspection on `/admin/ssf` and counted on Monitoring → Shared Signals → Dead letters (`/admin/ssf/dead-letters`). |
| `ssf.deadLetterMaxPerStream` | `STS_SSF_DEAD_LETTER_MAX_PER_STREAM` | `1000` | yes | The most dead letters one stream keeps; past it the oldest is deleted. |
| `ssf.deadLetterSweepS` | `STS_SSF_DEAD_LETTER_SWEEP_S` | `60` | yes | How often each process deletes expired dead letters, probes due dead streams and logs **one** summary line of what could not be delivered — never a line per SET. |
| `caep.eventsPerSession` | `STS_CAEP_EVENTS_PER_SESSION` | `25` | yes | How many recent events a CAEP register row lists; the per-type counts beside it never forget. |
| `caep.historyPerSession` | `STS_CAEP_HISTORY_PER_SESSION` | `10` | yes | How many credential changes a CAEP row keeps. |
| `risc.eventsPerAccount` | `STS_RISC_EVENTS_PER_ACCOUNT` | `25` | yes | How many recent events a RISC register row lists. |
| `risc.historyPerAccount` | `STS_RISC_HISTORY_PER_ACCOUNT` | `10` | yes | How many credential-compromise and identifier-change records a RISC row keeps, each. |
| `persistence.mode` | `STS_PERSISTENCE_MODE` | `memory` | **restart** — the store is opened and READ before the HTTP listener binds, so a mode changed at runtime would leave a service whose directory came from one place and whose writes went to another | Where the embedded directory, the trust realm registry and the runtime setting changes are written down. `memory` writes nothing and is what this service did until 2026-08-27. `ldif` writes an RFC 2849 file per realm plus two JSON files into `dataDir` and needs no database. `postgres` writes six tables. What this service MINTS — sessions, tokens, codes, artifacts, Kerberos principals, the replay caches, the counters and the audit log — is persisted in PRODUCT mode on `postgres` and in no other configuration, each row encrypted under the same key-encryption key as the signing keys; development mode persists none of it, because the signing key is regenerated on every start there. See *Persistence* above. |
| `persistence.dataDir` | `STS_PERSISTENCE_DATA_DIR` | `./data` | **restart** — same reason | Where `ldif` mode writes. A relative path resolves against the package root rather than the working directory, for the reason `CONFIG_FILE` does. Ignored in the other two modes. In a container this is what a volume mounts over. |
| `persistence.databaseUrl` | `STS_DATABASE_URL` | `postgres://sts:sts@localhost:5432/sts` | **restart** — the connection pool is opened before the listener binds | The connection string `postgres` mode dials. **The default names an OWNER and the compose stack does not**: the default is for a local database with nothing in it, which this service builds for itself, while the stack dials the least-privileged `sts_app` that `postgres/schema.sql` created — see *Building the schema*. The default is a LOCAL DEVELOPMENT one matching the Postgres service in this repository's `docker-compose.yml` (user, password and database all `sts`), so turning persistence on against a local database is one setting rather than two. **It is never dialled unless `persistence.mode` is `postgres`**, which is not the default, so it is inert on an ordinary run. The compose stack sets this variable itself with `postgres` as the host, that being the service name on its network. It carries a password, so this service never echoes it back — `/admin/persistence` reports the host, port, database and user parsed out of it. |
| `keys.vaultClientCert` | `STS_KEYS_VAULT_CLIENT_CERT` | *(empty)* | **restart** | A PEM certificate this service presents to Vault or OpenBao, authenticating through the `cert` auth method instead of with a token. Set with `keys.vaultClientKey`. **The certificate should be issued BY the store** — that is what makes the identity the store's to grant and revoke rather than a file somebody copied in. The stack this repository ships does exactly that; see `openbao/`. |
| `keys.vaultClientKey` | `STS_KEYS_VAULT_CLIENT_KEY` | *(empty)* | **restart** | The private key for that certificate. Read at startup, never logged. |
| `keys.vaultCaCert` | `STS_KEYS_VAULT_CA_CERT` | *(empty)* | **restart** | What this service verifies the store's TLS listener against. **A different question from who signed the client certificate**, and usually a different certificate: one is the connection, the other is the identity. |
| `keys.vaultCertRole` | `STS_KEYS_VAULT_CERT_ROLE` | *(empty)* | **restart** | Which `auth/cert` role to log in against. Empty lets the store try every trusted certificate, which is what a store with one of them wants. |
| `keys.vaultCertAuthMount` | `STS_KEYS_VAULT_CERT_AUTH_MOUNT` | `cert` | **restart** | Where the `cert` auth method is mounted; the login goes to `auth/<this>/login`. A value that is not a plain path is refused rather than put into a request. |
| `keys.kidFormat` | `STS_KEYS_KID_FORMAT` | `internal` | yes, per realm | What the `kid` header of every JWT the realm signs names its key by: `internal` is this service's own opaque `sts-…` name; `jwk-thumbprint-uri` is the RFC 9278 JWK Thumbprint URI, `urn:ietf:params:oauth:jwk-thumbprint:sha-256:<RFC 7638 thumbprint>`. **While it is on, the JWKS lists every signing key twice**, under both names, so tokens signed before the switch still verify; turning it off again drops the second entries. It names the key, not its certificate — that is `x5c`/`x5u` (`docs/pki.md`). |
| `persistence.databasePasswordProvider` | `STS_DATABASE_PASSWORD_PROVIDER` | `none` | **restart** — the pool is opened before the listener binds | Read the database password from a secret store at startup and inject it into `persistence.databaseUrl` instead of the password that string carries. The five providers are `keys.kekProvider`'s and the mechanism is the same one: `file`, `aws`, `gcp`, `azure`, `vault`. `none` changes nothing — the connection string is dialled exactly as written. **A read that fails stops the service**, like any other store that was configured and cannot be opened. |
| `persistence.databasePasswordRef` | `STS_DATABASE_PASSWORD_REF` | *(empty)* | **restart** | Where the password is in that provider: a path for `file`, a name or ARN for `aws`, a resource name for `gcp`, a secret name for `azure`, a read path for `vault`. **Empty means the same place as the key-encryption key** (`keys.kekFile` / `keys.kekRef`) — one mounted file or one cloud secret holding both, which is the arrangement most deployments want. A SHARED location holding something that is not a JSON object is refused rather than read: what is there is the key itself, and handing that to a database as a password is the mistake the refusal exists to prevent. |
| `persistence.databasePasswordField` | `STS_DATABASE_PASSWORD_FIELD` | `databasePassword` | **restart** | The member to take when the stored secret is a JSON object — `{"kek": "…", "databasePassword": "…"}` in one file, or the `{"username": …, "password": …}` shape AWS Secrets Manager writes for a database credential (set it to `password` for one of those). A secret of its own that is not JSON is taken whole; empty takes the value whole even where it is JSON. |
| `persistence.databasePasswordVault` | `STS_DATABASE_PASSWORD_VAULT` | *(empty)* | **restart** | The Vault endpoint or Key Vault URL the database password is read from. **Empty means the key-encryption key's store** (`keys.kekVault`), which is the arrangement most deployments want. |
| `persistence.databasePasswordRegion` | `STS_DATABASE_PASSWORD_REGION` | *(empty)* | **restart** | The AWS region for the database password. Empty means `keys.kekRegion`. |
| `persistence.databasePasswordToken` | `STS_DATABASE_PASSWORD_TOKEN` | *(empty)* | **restart** | A Vault token for the database password. Empty means `keys.kekToken`; ignored where a client certificate is configured. |
| `persistence.writeDelay` | `STS_PERSISTENCE_WRITE_DELAY` | `1500` | yes | How long a change waits before the `ldif` files are rewritten, so a burst — a realm build writes thirteen entries — costs one file write. What it risks is that many milliseconds of writes on a `kill -9`, which no process can trap; SIGTERM and SIGINT flush first. **Postgres ignores it** and uses 0: the unit of writing there is a transaction, so every change made while handling one request commits as one transaction the moment that request is done. |
| `persistence.changeLogRetentionS` | `STS_PERSISTENCE_CHANGE_LOG_RETENTION_S` | `3600` | yes | How long a row of `sts_changes` is kept at least. A row is removed only when older than this AND below the lowest position every process still reading the change log has reported; a reader silent this long, or whose cluster node is gone, is taken to be gone. `0` never trims, which is what the log did before 2026-09-14. |
| `persistence.realms` | `STS_PERSISTENCE_REALMS` | `true` | **restart** — the realm rows are restored before the listener binds | Whether trust realm definitions — names, descriptions and per-realm settings — are written down beside the directory. Turning it off is a half-persisted service rather than a smaller one: a realm holds its own directory, so its entries would be stored with no realm to restore them into, and the next run's first write would remove them. |
| `persistence.appconfig` | `STS_PERSISTENCE_APPCONFIG` | `true` | **restart** — the saved overrides are applied before the listener binds | Whether a setting changed through the console or the management API survives a restart. It adds NO LAYER: the saved values are re-applied at startup through the same `setOverride()` a caller uses, so the five layers above are unchanged and a runtime override is simply durable. Only a runtime-changeable setting can be saved, because only one can be set — which is what makes applying them after every module has loaded safe. |

## How it is put together

A mock Security Token Service used by the test suite, **split across forty-nine files at its root** (it was one 4,489-line `server.js` until 2026-08-03; eight protocol families in one file meant no way to see what was in it short of reading it). `server.js` is now the shell — it requires `app.js` (the express app and every middleware, which must load before any route) and `helpers.js` (the log, the keys, and the helpers more than one protocol needs), then the modules that register routes, and listens: `authn.js`, `wstrust.js`, `oauth2.js`, `wsfed.js`, `vc_offers.js`, `vc_did.js`, `vc_issuer.js`, `vc_verifier.js`, `krb5_kdc.js`, `krb5_service.js`, `spnego.js`, `admin.js`, `admin_api.js`, `ldap_server.js`, `tls_server.js`, `sts_metadata.js`. The rest are reached through those rather than named there — `saml2.js`, `saml11.js`, `vc_configs.js`, `vc_claims.js`, `vc_verifier_config.js`, `claim_attributes.js`, `group_claims.js`, `dpop.js`, `admin_stats.js`, `audit.js`, `bbs2023.js`, `webauthn.js`, `admin_api_spec.js`, `admin_api_docs.js` and the nine `krb5_*.js` files under the KDC and the negotiation — which is not a hierarchy so much as the consequence of the rule below. One file among them is **not a module at all**: `admin_api_explorer.js` is browser code, read off disk by `admin_api_docs.js` and served verbatim at `/admin/api-explorer/explorer.js`, and nothing in node ever requires it.

The Kerberos files are a stack rather than a feature list, bottom up: `krb5_primitives.js`
(what no runtime gives you — CTS, RC4, MD4, MD5), `krb5_crypto.js` (the RFC 3961
framework and the five etypes), `krb5_asn1.js` (DER for RFC 4120's ASN.1),
`krb5_messages.js` (the messages, the pre-authentication and the [MS-SFU] structures),
`krb5_ndr.js` and `krb5_pac.js` (the PAC, which arrives in Windows' RPC marshalling
rather than in ASN.1), `krb5_principals.js` (the principal database, salts and PAC
identities), `krb5_gss.js` (the RFC 4121 framing a real service is handed),
`krb5_kdc.js` (the KDC) and `krb5_service.js` (the acceptor). Only the last two
register anything.

Three things about that split are load-bearing. **Requiring a module registers its
endpoints** — each does `app.get(...)` at its top level against the shared app from
`app.js`, rather than exporting a `register()` function, which is what let 4,400
lines of handlers move without being re-indented; so the require order in
`server.js` is the route order, and the middleware has to live in `app.js` because
express applies it only to routes added after it. **`vc_configs.js` and
`vc_offers.js` exist to break cycles, not to group code**: the credential
configurations are read by both the issuer and the authorization server, and the
Credential Offer's pre-authorized codes are *minted* by the offer pages and
*redeemed at the token endpoint*, so that state cannot live in either OID4VCI or
OAuth2 without those two requiring each other. A require cycle in node does not fail
loudly — it hands back a half-initialised module whose exports are `undefined`, and
the symptom arrives later as something that is not a function. **Five helpers
(`userFor`, `parseBody`, `oauthError`, `vciError`, `signJwt`) are in `helpers.js`
for the same reason** and not because they are especially general.

`dpop.js` is the exception to the rule above: it registers nothing. It is a library
— there is no `app.get` in it — so its position in `server.js`'s require order does
not matter, and it requires `helpers.js` and nothing else, so it cannot be part of a
cycle. **`admin_stats.js` is a library in exactly that sense and for exactly that
reason**, and it needs the property more than `dpop.js` does: it is called from
`app.js`'s call log, from `helpers.js`'s `signJwt()`, from both assertion builders,
from the KDC and from the credential issuer, which between them are most of the
service — so anything it required, all of those would require transitively. See *The
admin console* below for the one place that constraint had to be inverted rather than
satisfied. `webauthn.js` is a library in the same sense, and it goes one step further: it
falls back to a silent logger when `./helpers` is not resolvable, because the parent
project's cross-implementation test copies *that one file* next to its own scripts and
a verifier written to be checked by somebody else has no business dragging the service
in behind it.

**Kerberos bends the require rule in one direction and the dependency rule in
another.** `krb5_kdc.js` and `krb5_service.js` register their HTTP views at require
time like everything else, but their **sockets are started by an exported `listen()`**
that `server.js` calls: a route cannot fail to register, and binding a privileged port
can. And the seven of those files that **also run in the browser** — everything except
`krb5_principals.js`, `krb5_kdc.js` and `krb5_service.js`, which reach for `./helpers`,
`net` and `dgram` — must not `require("crypto")` at all. They are staged into the
parent project's client tree and bundled by browserify, which
substitutes a bare `require("crypto")` with crypto-browserify and ships `elliptic`
(GHSA-848j-6mx2-7j84, no patched version) into the bundle. So the codec is written
against `globalThis.crypto.subtle`, which is why every function in `krb5_crypto.js` is
async, and why MD5 and RC4 are written out by hand in `krb5_primitives.js` even though
node has both: Web Crypto does not, and one module that behaves differently in the two
places is worse than one that is slower in both. Note that this sharing is the opposite
arrangement from `webauthn.js` and `bbs2023.js`, deliberately: a codec has to produce
the same bytes wherever it runs, so the tests over it are a **round-trip oracle**
(`tests/krb5_codec.js` re-encodes what it read) and byte-level pinning
(`tests/krb5_gss_tokens.js`) rather than two implementations agreeing with each other.

### Trust realms — several logical copies of this service, on one port

A **trust realm** is a whole mock identity service: its own configuration, its
own signing key, and its own sessions, authorization codes, access and refresh
tokens, credential offers, SAML request state, artifacts, statistics and audit
log. Every realm answers on the SAME sockets as every other, and they are told
apart by a segment at the front of the path.

```
http://host:8081/oauth2/token                the DEFAULT realm
http://host:8081/realm/acme/oauth2/token     the realm `acme`
```

**The default realm has an empty prefix, and a service with no realms defined
behaves exactly as it did before this existed.** Nothing is stripped, no URL is
rewritten, no page grows a control. If you are not using realms you can stop
reading here and nothing about this service has changed.

#### Defining one

```bash
curl -k -X POST https://localhost:8081/admin-api/realms/create \
     -H 'content-type: application/json' \
     -d '{"id":"acme","name":"Acme Corporation"}'
```

or on `/admin/realms` in the console, which is also where a realm's settings,
its endpoints and its signing key identifier are.

**A realm ROW survives a restart when `persistence.realms` has a store under it**
— its name, its description, its per-realm settings and its own directory all
come back. In the default `persistence.mode=memory` it does not, and a stack
that wants its realms back creates them from that call. **The KEYS never come
back either way**: every realm's signing key is regenerated on every start,
exactly like the default realm's, so a token minted in a realm today verifies
against nothing tomorrow.

The id becomes a path segment: lower-case letters, digits and hyphens, starting
with a letter or a digit. It may not be `default`, and it may not be the first
segment of a path this service already serves — `GET /admin-api/realms` lists
those in `reserved`, read off the live router.

#### Finding one

`GET /realms` is the directory, and it is **deliberately ungated**: the prefix
segment is a setting and the ids are whatever somebody typed, so a client being
pointed at a realm cannot construct a single URL without it.

```json
{
  "pathSegment": "realm",
  "enabled": true,
  "active": true,
  "current": "default",
  "realms": [
    { "id": "default", "pathPrefix": "",            "baseUrl": "https://localhost:8081" },
    { "id": "acme",    "pathPrefix": "/realm/acme", "baseUrl": "https://localhost:8081/realm/acme" }
  ],
  "support": [ ... ]
}
```

Everything follows from `baseUrl`: `…/realm/acme/.well-known/openid-configuration`
publishes an `issuer` of `https://localhost:8081/realm/acme` and endpoints under
it, `…/realm/acme/oauth2/jwks` publishes that realm's own key, and
`…/realm/acme/saml2/metadata` publishes an entityID of its own.

#### What a realm actually separates

**A REALM SEPARATES WHAT THIS SERVICE ISSUES, NOT WHO IT KNOWS**, and the
distinction is worth understanding before you build a test on it.

Separated, completely, by the path:

* the **signing key** — each realm generates its own, so a token minted in one
  does not verify against another's JWKS. That is the point of a realm rather
  than a side effect of one, and each realm's `kid` is on `/admin/realms`.
* every **setting** in the table above, per realm, above whatever the process is
  configured with. Every settings form in the console and `POST
  /admin-api/config/set` reached under a realm's prefix read and write THAT
  realm.
* **sessions** (so signing in to one realm signs you in to that realm only —
  with ONE exception, the admin console, whose gate resolves the session cookie
  in whichever realm minted it so that the realm switcher does not sign you out;
  every protocol endpoint still sees only its own realm's sessions),
  authorization codes, access and refresh tokens, refresh families, DPoP replay
  and nonce state, client-assertion replay state, named authorization servers,
  credential offers, pre-authorized codes, deferred transactions, issuance
  nonces, presentation transactions, SAML 2.0 and 1.1 request state and
  artifacts, the custom claim and credential claim selections, the verifier's
  request, the **statistics** and the **audit log** (whose sequence numbers are
  per realm, so one realm's rows are contiguous).
* the six settings that are **NAMES** — the SAML 2.0 entityID, the SAML 1.1
  providerID, the WS-Federation entityID, the WS-Trust issuer, the SAML
  assertion issuer and the OpenID4VP verifier client id. A new realm is created
  with each of them suffixed with its id, because two realms carrying one
  entityID is two identity providers claiming one name. They are ordinary
  settings on the realm: change them, or unset them to go back to sharing the
  process's name.

**Separated — the embedded directory, as a subtree.** Since 2026-08-25 each
realm owns a subtree of the one naming context:

```
dc=example,dc=com                 the DEFAULT realm  (ldap.baseDn itself)
dc=acme,dc=example,dc=com         the realm `acme`
```

with its own `ou=users`, `ou=groups`, `ou=applications`, `ou=federations` and
SPIFFE containers under each. So:

* the same name signing in to two realms is **two entries**, one per realm;
* an **OAuth client** registered under one realm is unknown to every other;
* a **SAML service provider** entry belongs to the realm it was created in;
* the **SPIFFE registry** is per realm — though the trust domain and the signing
  authority in front of it are not;
* and `ldapsearch -b "dc=acme,dc=example,dc=com"` reaches it, which is the whole
  reason the realm is in the DN rather than in a store of its own: LDAP answers
  on a socket with no path to put a segment in, so a **name** is the only thing
  a client can carry.

A subtree search from `dc=example,dc=com` still returns every realm's entries,
because that is what a naming context is. What is isolated is the container each
realm reads and writes: `ou=users,dc=example,dc=com` holds no `acme` person.

**Separated, and confined — the two admin console roles (since 2026-09-14).**
Each realm has its own `cn=admin-read` and `cn=admin-write` in its own
`ou=groups`, seeded with an `admin` account that must change its password at its
first sign-in (in product mode, creating the realm shows a generated password
once). Their members administer **that realm only**: the pages and settings
about the whole process — the store, the database, the secret store, the TLS
listeners and truststore, Kerberos, the embedded debugger, the API explorer,
per-process settings — are hidden and refused, and so are creating or removing a
realm and replacing the service Root. The **default realm's** two groups are the
service administrators and administer every realm. A grant made through
`/realm/acme/admin-api/rbac/grant` lands in acme's roster. The console asks the
roster of the realm a person signed in through, so `admin` in `acme` and `admin`
in the default realm are two people. When realms are defined, the plain `/admin`
and `/portal` ask which realm first (a list in development, a text box in
product; `?realm=<id>` skips the question). `/admin-api` accepts the default
realm's token everywhere and a realm's own `sts-management-api` token in that
realm only.

**Separated — Kerberos, by REALM NAME (2026-09-15).** Port 88 is one socket for
every realm, and the Kerberos realm name inside each request says which trust
realm answers it — the discriminator the protocol has always carried. A realm is
created with `krb5.enabled` OFF and no name of its own; give it a `krb5.realm`
no other realm answers to and turn it on, and it builds a principal database,
long-term keys, a krbtgt and a service account of its own, from its own
settings, over its own directory subtree. A bare `/KdcProxy` routes by the name
too; a realm's own `/realm/<id>/KdcProxy` is pinned to that realm and refuses
another realm's name. Trust realms do not trust each other's Kerberos: the
cross-realm trust with `krb5.trustedRealm` is the default realm's alone.

**Not separated — two socket families.** The two TLS listeners, and SPIFFE's
four sockets. LDAP's 389 and 636 used to be on this list and no longer are — the
sockets are still shared, but what they serve is partitioned by DN — and
Kerberos left it on 2026-09-15. A socket has no path in it, and what is left on
this list is what has no name inside its protocol to put a realm in either.

`GET /realms` and `/admin/realms` both publish this list, family by family, so
the answer is something the service tells you rather than something to remember.

#### The console

Every page shows ONE realm — the one whose prefix it was reached under — and
carries a switcher at the top of the sidebar that moves to the same page in
another realm. The switcher's links are absolute URLs on purpose: every
root-relative link in an HTML response is rewritten to carry the current realm's
prefix, which is what makes the console work inside a realm without a link being
edited, and is exactly wrong for the one control whose job is to leave.

`/admin-api` is realm-scoped by the same prefix, so `/realm/acme/admin-api/config`
is that realm's configuration and every one of its operations works per realm.
The five operations under `/admin-api/realms` manage the registry itself, which
is process-wide: there is one list of realms, and `remove` refuses to remove the
realm the call arrived in.

### The signing key is regenerated on every start

Two consequences follow, and both are deliberate. Its `kid` is derived from the key
material (`sts-<thumbprint>`) rather than being a constant, so two instances —
a stale container beside a fresh one — cannot both claim the same kid over different
keys and make "the signature does not verify" look like a corrupt document instead
of the wrong issuer. And every document that carries or describes the key (RFC 8414
metadata, OID4VCI credential issuer metadata, `jwt-vc-issuer`, the JWKS, the DID
document and the DID Configuration) is served `Cache-Control: no-store`, because a
cached copy outlives the key it describes.

All tokens are RS256 JWTs signed with that key, so they verify against the advertised
JWKS.

### One crypto module — `common/crypto.js`

**Every signature, verification, encryption and decryption in this service goes
through one module**, and has since 2026-08-27. Before that it did all four in about
twenty places: six XML signers, four XML signature verifiers, two hand-rolled halves
of one JWE, three RFC 7638 JWK thumbprints, two self-signed certificate builders and
two constant-time comparisons. Each was written where it was needed and each was
correct on the day it was written; what they could not do was stay correct together.

Three things it holds that are worth knowing as a *user* of this service rather than
as a maintainer:

* **The XML signer is the debugger's own**, vendored byte-identical from
  `../id-proto-debugger/common/xmldsig.js`. Both ends of a SAML or WS-Federation
  exchange with this service now canonicalize with the same code — which matters
  because a disagreement about canonicalization is invisible until it is a signature
  that verifies on one side and not the other.
* **A verifier is always told which element it is checking.** A SAML Response
  carrying a signed assertion has two signatures; asking "is this Response signed
  by us" and being answered about the assertion is a step away from accepting a
  response whose assertion was swapped. A signature whose reference names a
  different element is refused outright.
* **The reference always names the element's real id** — `ID`, `AssertionID`,
  `ResponseID` or `RequestID`. Nothing is ever invented.

One user-visible behaviour changed with it: four places in the OpenID4VCI code read
this service's own access tokens back **without** the configured `oauth2.clockSkewS`
allowance, so a token that introspected active could be refused at a credential
endpoint seconds before it should have been. They apply it now, like everywhere else.

`tests/crypto_module.js` (`npm test`) checks the whole surface against `xml-crypto` —
an independent implementation — in both directions.

### Persistence — three things survive a restart, and nothing this service mints does

Until 2026-08-27 this service persisted nothing at all, and every document in
this repository said so. That is no longer true, and the replacement sentence
has to be exact, because a half-remembered version of it is worse than either
version.

**Three things persist when a store is configured:**

* **The embedded LDAP directory** — every entry under every realm's base. In
  this service that is also the applications registry, the federation register,
  the SPIFFE registry and the group roster, because those *are* directory
  entries and are not copies of anything kept elsewhere.
* **The trust realm registry** — the rows, their names, descriptions and
  per-realm settings.
* **The runtime appconfig overrides** — what the console and
  `POST /admin-api/config/set` write.

**Nothing this service MINTS ever persists, in any mode.** Sessions, access
tokens, ID Tokens, refresh tokens, authorization codes, pre-authorized codes,
SAML artifacts, Kerberos tickets, the replay caches, the statistics and the audit
log are all still in memory and still gone with the process. **The one exception,
since 2026-09-13, is the RFC 7523 / RFC 7522 used-assertion history**: it persists
in the `ldif` and `postgres` stores in both modes, because the key that verifies a
client's assertion is the client's and survives a restart — so an assertion spent
before one must still be refused after it. See `/admin/used-assertions`.

That is deliberate, and the section immediately above is the reason: **the
signing key is regenerated on every start.** A token restored from a disk would
verify against nothing, and a statistics file that outlived the key that signed
the tokens it described would be worse than none. So the rule is *what persists
is what somebody typed, and what resets is what this process minted or counted*.

#### Three modes

| `persistence.mode` | What it does |
|---|---|
| `memory` | Writes nothing. **The default**, so a run that says nothing about persistence behaves exactly as every run before this existed — which is why no test in the parent project's suite had to be told about it. |
| `ldif` | Local development, no database. One RFC 2849 LDIF file per trust realm in `persistence.dataDir`, plus `realms.json` and `appconfig.json`. |
| `postgres` | The shared store: five tables, one transaction per flush, `persistence.databaseUrl` to reach it. **The schema is built by `postgres/schema.sql` and this service's own database role cannot change it** — see *Building the schema* below. |

**LDIF rather than a JSON dump of our own**, because a directory has an
interchange format that predates this service by thirty years: the file is
something `ldapadd -f`, `slapadd` and a reviewer can all read, so the answer to
"how do I get this into a real directory" is *you already have it*. The one
thing LDIF has no home for is this service's `origin` marker, which rides as a
`# sts-origin:` comment that every other reader ignores — an invented attribute
would have been real on reload, searchable, and matchable by a filter.

**There is no persistence option in node-ldapjs, and there could not be.**
`ldapjs` is a protocol library — a BER codec, a client, and a `Server` that
routes a parsed operation to a handler you wrote — and it ships no storage of any
kind. (`lib/persistent_search.js` is the LDAP *persistent search* change-
notification control; the name is a trap.) The store here is ours and always
was. Proxying to a real OpenLDAP instead would have given persistence for free
and ended the service: this directory is schemaless on purpose, accepts any bind,
creates a person on first sight of any name in any protocol, and is written into
directly by six other modules as ordinary function calls.

#### Getting it running

```bash
# No database. One file per realm, and a directory you can read with an editor.
STS_PERSISTENCE_MODE=ldif STS_PERSISTENCE_DATA_DIR=./data node server.js

# The shared store.
STS_PERSISTENCE_MODE=postgres \
  STS_DATABASE_URL=postgres://sts:sts@localhost:5432/sts node server.js
```

`docker compose up` does the second for you — the compose file brings up a
Postgres container beside this service, with a named volume under each and the
`env/` directory bind-mounted so the appconfig files are editable from the host.
`docker compose down` keeps the volumes; `down -v` removes them.

#### Building the schema

```bash
psql -v ON_ERROR_STOP=1 -f postgres/schema.sql "postgres://owner@host:5432/sts"
```

**`postgres/schema.sql` builds the five tables and creates the role this service
connects as**, and those are two halves of one thing. The role it creates —
`sts_app`, or whatever `-v sts_app_role=` names — holds `SELECT`, `INSERT`,
`UPDATE` and `DELETE` on the tables and `USAGE` but **not** `CREATE` on the
schema, so a running mock can change every row in its store and cannot add,
alter, truncate or drop a table in it. Run it as a superuser or as the owner of
the database; it is idempotent, so running it again is how the password is
rotated.

**The compose stack does it for you**, through `postgres/apply-schema.sh` in the
database container's `/docker-entrypoint-initdb.d` — but *only on the start that
creates the cluster*, which is how that mechanism works. A `sts-db` volume from
before 2026-09-06 has the tables and no `sts_app`, and the service then
restart-loops with `password authentication failed`. `docker compose down -v` is
the answer, and what it removes is the directory, the realm registry and the
appconfig overrides — never anything this service minted.

**A database with nothing in it still works with no script**, which is what the
default connection string above is for: the driver asks which objects exist and
creates the ones that do not, so a privileged role against an empty database
behaves as it always did. What it will not do is issue a `CREATE` when there is
nothing to create — and that is not a tidying: `CREATE TABLE IF NOT EXISTS`
checks `CREATE` on the schema *before* it checks whether the table exists, so a
least-privileged role would otherwise be refused on every start by statements
that had nothing to do.

#### The parts worth knowing before you turn it on

**A failed write is logged and never thrown.** If the database goes away, the
operation that triggered the write still succeeds, this service keeps answering
out of memory, and `/admin/persistence` and `GET /admin/ldap/service` both carry the error. The
next change recomputes the same difference and tries again, so nothing is lost by
a failure. A database outage taking down seventeen protocol families that do not
need a database is the one failure mode a mock must not have.

**The whole write path is one function.** Every writer in the directory already
had to call `touchDirectory()` — a rule that predates this and exists for a group
index — so persistence hangs off that single choke point and computes a diff
against a shadow of what it last wrote. A new writer that forgets it produces a
stale groups claim; a new writer that forgot a separate `persist()` call would
produce an entry that exists until the process restarts and then does not.

**A restored person shows on `/admin/users` as *restored*, not as having
authenticated.** They exist — an entry, searchable over 389, readable over SCIM
— and they have not signed in during *this* process, so they are not counted
among the sign-ins. The counts and the per-person event list are statistics and
start at zero with everything else.

**Restoring settings after every module has loaded is safe**, and not by luck:
only a runtime-changeable setting can be overridden at all, and a runtime setting
is by definition one that is read per call rather than captured at startup. No
saved value can reach `global.https`, `oauth2.rfc9700` or a bound port.

**Processes against one Postgres store coordinate, since 2026-09-06 — and this
paragraph said the opposite until then.** It read *"persistence is not
coordination… one process per store"*, and that was the honest description of
what existed.

Every change is now written to a monotonic log (`sts_changes`) **inside the
transaction that made it**, and each process asks for everything it has not yet
applied: the directory, the realm registry, the runtime settings and the minted
rows alike. A `LISTEN`/`NOTIFY` nudge wakes that ask early and is allowed to fail
in every way a best-effort mechanism can — dropped connection, at-most-once
delivery, an 8000-byte payload limit — because **the log is the contract and the
notification is only latency.** `persistence.coordinate` turns it off, which is
what this service did before; `persistence.pollInterval` is the worst-case
convergence lag when a notification is lost.

**It shares state and not sockets, and that is where the surprises are.** The
KDC, both LDAP listeners, the two TLS ports and SPIFFE's four are bound per
process and always will be. And the **replay caches and DPoP `jti` sets converge
rather than synchronise**: between a write in one process and its arrival in
another there is a window the size of the poll interval in which a proof one
process refused is accepted by another. **Not the RFC 7523 / RFC 7522
used-assertion history** (2026-09-13): recording a use there is one atomic
`INSERT … ON CONFLICT` in its own table, so every process agrees at once. Sticky sessions at the load balancer
close it; nothing here does. `status.coordinates` and `status.replication` report
all of it.

`/admin/persistence` in the console and `GET /admin-api/persistence` report which
mode is in force, how much it holds, when it last wrote and what went wrong if
that failed. **A store that was configured and could not be OPENED does not get
that far**: since 2026-08-28 this service refuses to start rather than running
as something it is not — see *Persistence* below — so `mode` and
`configuredMode` disagreeing is a state a running process cannot be in. What
those pages still report is a store that broke afterwards, which is recorded
and is not fatal.
`GET /admin/ldap/service` carries the same object and is not behind the console gate.

### The JSON-LD contexts are not optional

`bbs2023.js` reads the three files in `common/vendored/contexts/` **at require
time**, at module
scope — so a missing one is not a degraded feature, the service does not start at
all. They are vendored rather than fetched because a signature is computed over
canonicalized statements: a one-byte difference in a context fails every signature
later, which looks like a crypto bug and is not one.

### Two discovery documents, built from one object

An OAuth client looks for `/.well-known/oauth-authorization-server` (RFC 8414); an OIDC
client looks for `/.well-known/openid-configuration` (OpenID Connect Discovery 1.0) and
will not look anywhere else. Both are served, and this service spoke OIDC for a long
time — `id_token`, `nonce`, `at_hash`, `c_hash`, all three flows — while being
impossible to *configure* from an OIDC client, which is a strange gap in a mock whose
whole job is to be pointed at.

**The OIDC document is `asMetadata()` extended, not a second copy.** The two overlap in
twenty-five members describing one server, and two hand-kept copies of twenty-five
members disagree the first time somebody edits one: a client configured from one
document would then behave differently from a client configured from the other against
the same endpoints, and nothing would report it. So `oidcMetadata()` is
`Object.assign(asMetadata(req), {…})` and adds only what Discovery defines on top —
`subject_types_supported`, `id_token_signing_alg_values_supported`, `claims_supported`,
`claim_types_supported`, `prompt_values_supported`, the three request/claims-parameter
booleans, `end_session_endpoint`, and the two logout-notification booleans. RFC 8414 was
written *from* Discovery and shares its member registry, so the overlap is real rather
than a coincidence that has to be maintained.

**What it does not say is the part worth reading.**
`display_values_supported`, the encryption members and `check_session_iframe` are all
absent (`acr_values_supported` is published since RFC 9470 made the authorization endpoint
honour `acr_values` — see *Step-up authentication*), because none is implemented and an invented value is worse than the member's
absence, which says exactly the right thing. `end_session_endpoint` *is* advertised
because `/oauth2/logout` really does end the session — but it neither requires nor
checks `id_token_hint` and does not validate the redirect target, so it is the shape of
RP-initiated logout and not its security, and `/admin/sts-metadata` grades it `mock`.

**Three URLs, because an issuer with a path resolves differently in the two specs** —
which is the usual reason a discovery fetch 404s. Discovery section 4 *appends*
(`/tenant1/.well-known/openid-configuration`), RFC 8414 section 3.1 *inserts*
(`/.well-known/openid-configuration/tenant1`), and both are answered. The appended form
rebuilds the issuer from the path it was reached at, since a document fetched under
`/tenant1` that claims to be issued by the bare origin is one a conforming client MUST
reject; the inserted form behaves like its `oauth-authorization-server` twin.

Writing the OIDC document beside the RFC 8414 one made three claims in the older
document visibly untrue, and they were removed rather than copied across:
`response_modes_supported` promised `form_post`, which `redirectBack()` has never done —
it 302s, always — so a client asking for it sat waiting for a POST that could not come;
`ui_locales_supported` named four locales for a login screen that is written in English
and never reads the parameter; and `scopes_supported` offered `address` and `phone`,
each of which is a request for a named set of claims (OIDC Core 5.4) that `userFor()`
does not mint. That last one is the argument for the shared object in miniature: the
omission was invisible for as long as no `claims_supported` list sat next to it.
`response_types_supported` gained `id_token token`, which the authorization endpoint has
always honoured and the document did not mention, and
`authorization_response_iss_parameter_supported` (RFC 9207) was likewise true and
unadvertised — `iss` is on every authorization response, errors included, but a client
may only *require* it, and so refuse a mix-up attacker's response without it, if the
metadata says the server sends it.

### RFC 9700 mode — the Security BCP, as a switch

This service is permissive on purpose. It authenticates nobody, accepts any client
secret, and until now would issue a code to any `redirect_uri` a request named. RFC
9700, *Best Current Practice for OAuth 2.0 Security*, is a list of things a real
authorization server refuses — and a client that has only ever been pointed at a
permissive server has never run the code paths it will need in production.

So the BCP is here as a **mode**, `oauth2.rfc9700`, and the contract is one sentence:

* **Off** — the default — every endpoint behaves exactly as it did before
  `oauth2_bcp.js` existed. Not nearly; nothing in that module runs.
* **On** — the requirements below are enforced across the whole of the BCP's
  section 2, both discovery documents stop advertising what would now be refused,
  and **the main port becomes an HTTPS listener** carrying the certificate the other TLS sockets in this process
  already serve, so every URL those documents publish — the issuer included —
  names `https`.

**Why a flag at all, given that RFC 9700 is a list of MUSTs.** Because a client is
exercised by both answers. One that only ever meets a strict server cannot reproduce
the loose behaviour it is trying to detect, and one that only ever meets a permissive
server has never seen its own "the authorization server refused my `redirect_uri`"
path run. The existing callers of this mock are the second kind: the debugger's own
panes use an unregistered `redirect_uri`, no PKCE and — in one of them — the implicit
grant. Turning that on unconditionally would not make them compliant; it would make
them stop working, at the point of use, with no explanation. Every refusal the mode
introduces names RFC 9700 and the section, because a 400 saying only
`invalid_request` is how somebody comes to spend an afternoon in their own code
looking for a decision this server made.

**`GET /oauth2/rfc9700`** publishes the whole model: whether the mode is on, the
three settings, and every requirement with its section, its level, whom it binds and
whether it is *enforced*, only *detected*, *always* true here, or *not* enforced with
the reason attached. RFC 9700 defines no discovery member and no endpoint of its own,
so there is otherwise no way for a client to find out which kind of server it is
talking to.

#### Redirect URIs (section 2.1)

`redirect_uri` is compared to the registered URIs by **exact string match** — RFC 3986
section 6.2.1, no normalisation, no trailing-slash forgiveness, no case folding of the
path — and there is no pattern syntax in the comparison at all. That last part is the
only way to be sure of the *MUST NOT* beside it: a matcher that supports wildcards and
is configured not to use them is one configuration mistake away from an open
redirector.

The registered set is the client's own `redirect_uris` when it registered any through
RFC 7591, and the **`oauth2.redirectUris`** setting otherwise — which is every client
this service has only ever seen at the authorization endpoint. That setting is empty
by default, so turning the mode on with nothing configured refuses every authorization
request; the refusal names the setting and the registration endpoint, so the next step
is on the page rather than in the source.

The one exception RFC 9700 carves out is **RFC 8252 section 7.3's**: a native
application cannot reserve a port, so a registered *loopback* URI — `127.0.0.1`,
`[::1]` or `localhost` — matches on any port. Everything else about it must still
match exactly and the host must be the same literal: a registration for
`http://127.0.0.1/cb` does not authorise `http://localhost/cb`, because those are
different names however alike they resolve, and treating them as one is a pattern
match wearing a different hat. `oauth2.loopbackPortWildcard` turns that exception off,
which makes this server deliberately **non**-compliant — that is the point of the
setting, since it is how a native-app client gets shown what happens when it meets a
server that got this wrong.

`http` is refused off the loopback (section 2.6), which is also the enforceable half
of *authorization responses MUST NOT be sent over unencrypted connections*. **The
other half is not enforced and the report says so**: the request itself arrives on
this service's plain HTTP listener, which is the only listener carrying
`/oauth2/authorize` — the two HTTPS listeners are `tls_server.js`'s own and serve the
connection report and nothing else. Refusing it would make the mode unreachable rather
than compliant. A compliance mode that quietly skipped a requirement it advertises
would be the most misleading thing in this repository, which is why that row is in the
table with `enforced: no` and its reason rather than left out of it.

**The order of the checks is load-bearing, not stylistic.** The `redirect_uri` is
matched *first*, before there is anything to report an error with, and a failure is
answered **here** as a 400. Every other refusal is reported by redirecting to
`redirect_uri` — which is right once that URI is known to be registered and is an open
redirector until then. `error=invalid_request` forwarded to an arbitrary URL is still
the browser being forwarded to an arbitrary URL, and an attacker does not mind which
parameters ride along.

The same comparison now guards **`post_logout_redirect_uri`** at
`/oauth2/logout`, which without the mode is the plainest open redirector in the
service: any absolute `http(s)` URL in a query parameter, followed, with no client and
no session involved. `/admin/sts-metadata` says that about it in both directions rather than
only the flattering one.

#### The port itself becomes HTTPS

*Authorization responses MUST NOT be sent over unencrypted connections* is the
requirement in section 2.1 that no check can satisfy: by the time any code here
runs, the request has already arrived over whatever it arrived over, and
refusing it would report the problem down the same channel. It is a property of
the **socket**, so it is settled where the socket is bound.

**`oauth2.rfc9700` turns port 8081 into an HTTPS listener.** It does it through
`global.https`, whose default *is* that flag — a row of its own so it can be set
either way independently, which both directions of are a real case. It is not a
fourth keypair: `tls_server.js` generates **one** self-signed certificate per
start and 8443, 9443 and the directory's LDAPS 636 already serve it, so a caller
trusts this service once rather than four times.

Everything a client reads then follows the socket **by itself**. `baseUrlOf()`
builds every URL from `req.protocol` and the Host header — which is what already
makes one process answer correctly as `localhost`, as `sts` on a compose network
and through a published port — so the RFC 8414 document, the OpenID Provider
Configuration, the OID4VCI and OID4VP metadata, the federation metadata, the DID
document and the `iss` of every token move together and none of them had to be
told. Nothing pins a scheme anywhere, and nothing should: a hardcoded `https` is
wrong on the default plain listener, and a document whose endpoints disagree with
the port they were fetched from is exactly the failure this derivation prevents.

The **issuer identifier** is the one value that needed a line of code, and only
when it is *pinned*. `oauth2.issuer` is empty by default, so it is the base URL
and is already `https`. A pinned `http://…` written before the mode was turned on
is now an identifier for a URL that no longer exists on this machine, so its
scheme is upgraded and the upgrade is logged. It is an upgrade rather than a
refusal because of what a client does with it: a conforming relying party must
reject a document whose `issuer` is not the identifier it fetched from, so a
pinned `http` issuer served over `https` fails at *every* client with a message
about the issuer, leaving the reader to work out that the scheme was the part
that moved. The mismatch worth producing on purpose is a different **host** or
path, and pinning still does that untouched.

Two consequences, neither of them hidden:

**`oauth2.rfc9700` is restart-only now — for the PROCESS.** It used to be a
runtime setting and stopped being one the moment it grew a consequence that
happens before the service is listening. A flag that was runtime for its checks
and restart-only for its socket would report the mode as *on* at `/admin/oauth2`
while every authorization response still went out over plain HTTP — the silent
disagreement `config.js` warns about in its own header. Set it in the appconfig
file or as `STS_OAUTH2_RFC9700` and restart; `POST /admin-api/config/set`
refuses it with that reason.

**A TRUST REALM MAY CARRY IT EVEN SO, AND THAT IS THE ONE EXEMPTION IN THIS
TABLE.** The reason above is about a *bound socket*, and a realm has none: it
answers on the port this process already opened, in the scheme that port was
opened in. So `oauth2.rfc9700` carries the `realmRuntime` marker (so does `oauth2.oauth21`, below, for the same reason), and

```bash
curl -k -X POST https://localhost:8081/admin-api/realms/create \
     -H 'Content-Type: application/json' \
     -d '{"id":"rfc9700","name":"RFC 9700 mode",
          "overrides":{"oauth2.rfc9700":true}}'
```

gives one process a permissive authorization server at `/oauth2/authorize` and a
compliant one at `/realm/rfc9700/oauth2/authorize`, each with its own issuer,
signing key, codes and tokens. `/admin/oauth2` reached under that prefix offers
the control the same page in the default realm refuses.

What a realm does **not** bring with it is a scheme. The main port is HTTPS or it
is not, for every realm at once — so a compliant realm on a plain-HTTP process
enforces every check and still publishes `http://` endpoints. That is the
combination `global.https` exists to make settable both ways and it is
*published* rather than hidden: `GET /oauth2/rfc9700` reports the port's scheme,
and the four requirements that are properties of the deployment come back `no`
instead of `deployment`. A stack that wants the compliant pass over HTTPS turns
`global.https` on for the whole process (`STS_HTTPS=true`) and leaves
`oauth2.rfc9700` to the realm.

**There is then no plain listener in this process at all**, and `POST /tls/trust`
and `GET /tls/server-certificate` were on one deliberately — they are what a
caller reaches *before* it trusts anything. So the first fetch has to be made
without verifying the certificate (`curl -k`), which is the ordinary bootstrap
for a certificate regenerated on every start: it is the same act as trusting the
PEM that endpoint hands back, done one step earlier. `/tls`, `/admin/sts-metadata` and
the startup line all say so rather than leaving it to be met as a handshake
failure, and the compose healthcheck picks its own scheme from the environment
for the same reason — a probe that spoke `http` at an HTTPS listener would mark
the container unhealthy while the service answered every request perfectly.

The session cookie gains `Secure` when — and only when — the port is TLS. It has
to be conditional: a browser silently drops a `Secure` cookie that arrives over
plain HTTP, so setting it unconditionally would leave the default deployment with
a sign-in that appears to succeed and a session that is never there again.

If a client cannot be taught to trust a per-start certificate, `global.https`
set explicitly to `false` runs every other check over plain HTTP. That case is
deliberately reachable, and `GET /oauth2/rfc9700` reports it as
`response-over-tls: no` with the reason rather than letting it pass quietly.

#### The authorization code flow (section 2.1.1)

**PKCE is required of every client this server cannot see to be confidential**, and
what that means is worth stating because it is the one judgement in here. A client is
taken to be confidential only when it registered at `/oauth2/register` with a
`token_endpoint_auth_method` other than `none` — RFC 7591 section 2 makes
`client_secret_basic` the default, so a registration that omits the member is
confidential. Everything else, including every `client_id` this service has never seen
registered, is public and must send a `code_challenge`. For a confidential client PKCE
is a *SHOULD*: the request is answered and the omission is logged, because a mock a
client is calibrated against being stricter than the specification is its own kind of
wrong.

`code_challenge_method=plain` is refused and `code_challenge_methods_supported` drops
to `S256` alone — the two have to agree, or the discovery document is a promise this
endpoint breaks. An `S256` challenge is also checked to be 43 characters of base64url,
which is what SHA-256 produces and nothing else does; it catches a verifier sent as a
challenge at the authorization request rather than leaving it to fail as a mismatch at
the token endpoint.

At the token endpoint the mode adds the **PKCE downgrade** refusal (section 4.8.2): a
`code_verifier` presented for a code that was issued *without* a challenge is rejected
rather than ignored. Ignoring it is how the downgrade works — an attacker who strips
`code_challenge` from the authorization request can then supply any verifier and be
told nothing is wrong. It also adds the two RFC 6749 section 4.1.3 checks this service
never made: the code is redeemed by the client it was issued to, and `redirect_uri` is
*present* rather than merely compared when the client volunteered it.

**Transaction-specific values are detected, which is the part a real server generally
cannot do.** A `code_challenge` or `nonce` is remembered from the moment a code is
issued for it, with the client it belonged to and whether that code was redeemed.
Presenting it again for a *new* authorization request after the earlier code was
redeemed is a second transaction reusing a first one's value, and is refused; so is
the same value arriving from a different `client_id`. What is deliberately **not**
refused is the same value while the earlier code is still unredeemed — that is a
reloaded tab or a retried request, the same transaction, and refusing it is how a
check like this comes to be turned off by the people it was meant to help. A response
carrying no code at all ends its transaction where it stands, so its `nonce` is
recorded as spent immediately; otherwise reuse would be undetectable in the one flow
where the nonce is the only protection there is.

That check runs **immediately before a code is minted** and nowhere else, for a reason
particular to this service: an authorization request runs through `/oauth2/authorize`
*twice*, once before the sign-in screen and once on the way back with a session. A
check at the top of the endpoint would refuse every request in the service for reusing
its own values between its own two passes.

A `nonce` is required whenever `response_type` names `id_token`. OpenID Connect Core
already requires it for the implicit and hybrid flows; the mode requires it always,
since the nonce is what makes an injected code detectable for a client that has no
PKCE (section 4.5.3.2).

#### Access token protection — sender constraint (sections 2.2, 2.2.1)

A bearer token is *whoever holds it can use it*. A sender-constrained one is
*token + proof of key possession*, and the BCP names two mechanisms. This service
now has **both**.

**DPoP (RFC 9449)** was already here in full — all twelve section 4.3 proof checks,
`cnf.jkt` on access *and* refresh tokens, `dpop_jkt` at the authorization request,
`jti` replay detection, and the server-supplied nonce handshake. RFC 9700 notes that
DPoP works for public clients, which is exactly why the wallet flows here use it.

**RFC 8705 certificate binding is new.** When `global.https` is on — which RFC 9700
mode turns on — the main listener now *asks* for a client certificate and never
requires one, the posture port 8443 has. A Token Request made with one comes back
with `cnf: {"x5t#S256": …}`, the base64url SHA-256 of the certificate's **DER**, and
the four protected endpoints thumbprint the connection's certificate again and
compare. Verified against `openssl` end to end: the same certificate is accepted, a
different one and none at all are refused, and the **refresh token is bound too** —
otherwise the long-lived half of the grant stays a bearer credential that mints bound
tokens for whoever holds it, which is worse than not binding at all, because the
`cnf` on what it mints implies a guarantee nobody checked.

An **unverified** certificate still binds, and that is not a hole: RFC 8705 section 3
binds to the certificate and explicitly permits a self-signed one — the proof is that
the same key completed *this* handshake, not that a CA vouched for it. Requiring
verification would also make the feature unreachable, since `/tls/trust` starts empty
by design. Section 2, mutual-TLS *client authentication* where the certificate
replaces the secret, is implemented beside it — see *Mutual TLS (RFC 8705)* below.

`tls_client_certificate_bound_access_tokens` is advertised **only when the deployment
can actually do it**. A client reads a metadata member as a promise, and there is
nothing to bind to on a plain HTTP listener.

The two resource-server MUSTs beside it were already true and now have rows saying so:
the proof of possession is **validated** and its replay is **prevented**, both at
`presentedAccessToken()` — the single check all four protected endpoints share, which
is why adding the certificate check there was one edit rather than four. A bound token
presented as a plain `Bearer` is refused rather than quietly accepted, which is the
single most likely way to implement DPoP and gain nothing from it.

#### Audience restriction and least privilege (section 2.3)

Every access token here has always carried `aud` — and always the *same* `aud`,
`<base>/resource`, which is a restriction that is true and buys nothing: one audience
that never varies restricts a token to everything this service protects.

**Resource Indicators (RFC 8707) fix that.** `resource` is read at the authorization
endpoint and again at the token endpoint and becomes the audience. It must be an
absolute URI with **no fragment** (a fragment is the part a server never receives, so
an audience carrying one names something no resource server can match); repeating it
asks for the *small set* section 2.3 allows where one is impractical; and the token
endpoint may **narrow** what the authorization request asked for and never widen it —
a grant that let a client add an audience afterwards would be the same escalation the
refresh scope check refuses, one step earlier.

**It is read for EVERY grant** (since 2026-08-26; it was two before). Section 2 puts
the parameter on *a token request*, not on a chosen pair of grant types, so
`authorization_code`, `refresh_token`, `client_credentials`, `password`, OpenID4VCI's
pre-authorized code grant and RFC 8693 token exchange all honour it, and a malformed
one is `invalid_target` from all six. Only the first two have a **narrowing** rule,
because only they have something earlier to narrow: the other four had no authorization
request, so what is asked for is what is granted. **And repeating it now works** —
`resource=a&resource=b` on a Token Request used to arrive as `b` alone, because the
form parser kept the last value of a repeated field; the array `parseResourceIndicators()`
had always been written to accept could never actually reach it. The token exchange
gains the same fix twice over: RFC 8693 §2.1's `audience` and `resource` are **unioned**
rather than the resource being discarded whenever both were sent, and a `resource` there
is now validated like every other.

**And the resource server refuses a token meant for somebody else**, which is the MUST
in that section. Ask for `resource=https://api.example.com/v1` and the token comes back
with that audience — and presenting it at `/oauth2/userinfo` is now a
`401 invalid_token` naming the audience it was for. Two details are deliberate: it
applies only to a token this service **issued**, since the `aud` of a foreign token is
a string this service cannot check and was never the audience of anyway; and "this
resource server" is matched on the **whole URL** — `<base>/resource`, or
`<base>/<id>/resource` for a named authorization server, with `<base>` the address
the request arrived on. It was matched on the path until 2026-09-13, so that a token
minted at `localhost:8081` would work at `127.0.0.1:8081`; that also admitted
`https://api.partner.example/resource`, and RFC 9068 section 4 allows neither. See
*JWT access tokens (RFC 9068)* below; `global.publicBaseUrl` gives a service reached
under several names one.

This is a **feature**, not a mode behaviour: a request that sends no `resource` is
unaffected in either mode.

**A scope that names another application is an audience too** — added 2026-08-26, and
it is there because RFC 8707 is how a client *should* name a resource server and a
scope list is how one actually does. `scope=openid email profile apigw1` with no
`resource` anywhere used to produce a token audienced to the `<base>/resource`
stand-in, so the one fact in the request about which party the token was for went
nowhere. Now a scope value that is the **`client_id` of another application in the
registry** becomes the `aud` and comes off the scope claim. The match is against
`oauthClientId` and nothing else (a scope is a bare name, an RFC 8707 audience is a
URI); the audience is the scope value **verbatim**, not that application's registered
`oauthAudience`, because the client said `apigw1` and so does the token; a
**spec-defined scope is never an audience** whatever the registry says, so registering
a client called `profile` cannot readdress every OIDC token in the service; and the
client's own `client_id` is skipped, since a token addressed to itself is what the ID
Token already is. A request naming none of them is unaffected in every respect.

Two things about it are worth knowing before reading a token. **The refresh token keeps
the whole scope** while the access token loses the value that became its audience —
they are the two halves of a grant answering different questions, and stripping it from
both would refuse a client that refreshes with the scope list it originally sent. And
**a token for an API is for the API alone** (since 2026-09-13; until then an `openid`
token named the derived audience *and* `<base>/resource`, so that it could still call
UserInfo). `scope=openid email profile apigw1` now produces `aud: apigw1` with
`openid`, `email` and `profile` left off the access token's scope claim and the
response's `scope` member — Microsoft Entra ID's arrangement — because RFC 9068 section
2.2.3 says every scope on the token must mean something to its audience. Those scopes
are still granted: the ID Token is issued and the refresh token keeps them. A client
that wants UserInfo asks for a token without the API in it.

#### JWT access tokens (RFC 9068)

Every access token is a JWT access token by RFC 9068's profile, in **every mode**:

* **The header says `typ: "at+jwt"`** (section 2.1). It said `JWT`, exactly like the ID
  Token beside it, so a resource server following section 4 refused every token this
  service issued — and one that did not could take an ID Token for an access token.
* **The claims**: `iss`, `exp`, `aud`, `sub`, `client_id`, `iat` and `jti` as before;
  `scope` only when something was granted; `preferred_username` beside `username` where
  there is a person; `auth_time`, `amr` and `acr` where an authentication event is
  behind the grant.
* **Every resource server here checks section 4** — UserInfo, the OID4VCI credential
  endpoints, SCIM, the SSF endpoints and `/admin-api`: the header is `at+jwt`, `iss` is
  an authorization server this service publishes **at the address the request arrived
  on**, and `aud` names this resource server. A token minted under one host name is
  refused under another. A foreign token at the credential endpoints is still accepted
  unverified, as it always was.
* **An ambiguous token is refused** (section 3), at the authorization endpoint with a
  redirected error and at the token endpoint with a 400:

  | Request | Answer |
  |---|---|
  | a scope naming two applications or two APIs' permissions | `invalid_scope` |
  | `resource=A` with a scope naming application B | `invalid_scope` |
  | two or more `resource` values and a scope tied to none of them | `invalid_target` |

  A multi-audience token may carry a delegated permission (kept as its whole
  identifier, which names its API) and, where this service's own resource server is one
  of the audiences, OpenID Connect scopes. With no scope at all it is issued.

For least privilege the enforceable parts are enforced and have rows of their own — a
refresh may not widen a scope, and the audience is restrictable. What is left is which
scopes a client asks for, and this service deliberately **grants a scope it does not
advertise** rather than refusing it, because half its callers are testing exactly that;
an unadvertised scope is logged as the least-privilege observation it is. RFC 9396
`authorization_details` is the finer-grained mechanism the section points at and is
implemented for OID4VCI, where a wallet names the credential and even the subset of
claims it wants.

#### Authorization code protection (section 4.5)

The code has always been single use here — it is deleted where it is redeemed —
with one deliberate relaxation on top, described under *A redeemed authorization
code is replayed, not refused* below: without the mode, an **identical** repeat of a
Token Request gets back the tokens it already got, because *"your code_verifier does
not match"* turning into *"already-used code"* on the very next attempt is the wrong
answer at exactly the moment somebody is acting on the right one.

RFC 6749 section 4.1.2 says a real authorization server refuses that, so **in this
mode it does** — and it does the SHOULD beside it (section 10.5): the access token,
the refresh token and the ID Token that code bought are **revoked**, through the same
set `/oauth2/revoke` writes to, so they report `active: false` at introspection
immediately. The reasoning is the refresh chain's one step earlier: a code presented
twice means two holders, one of them is not the client, and nothing here can tell
which — so the answer is to invalidate what it bought rather than to guess. The
refusal says how long ago the code was redeemed, by which client, and how many tokens
went with it.

The two more specific refusals stay ahead of it in both modes, because each is worth
its own sentence: a repeat that **differs** from the request the code was redeemed
with names the field that differed, and a code whose own five-minute lifetime has run
out says so and points at the refresh token from the first redemption.

Binding the code to its client is the same check `transaction-bound` describes,
cited from both directions because the BCP raises it twice — as a property of the
code in section 4.5 and as the binding of the PKCE and nonce values in 2.1.1. Before
the mode existed, this service read the client off the **code** and never compared it
with the one presenting it.

#### Open redirectors — the part that survives a registered URI (section 4.11.2)

Refusing an unregistered `redirect_uri` closes most of this, and that landed in the
first iteration. What's left is the half that works **even when every URI is
registered**, and the BCP is unusually specific about it: *the authorization server
MUST always authenticate the user first … before redirecting the user.*

The attack needs no invalid URI at all. Send a victim to a legitimate client's
authorization request with something wrong in it — an unsupported `response_type`, a
missing parameter — and the authorization server bounces them straight to that client's
**registered** redirect URI carrying attacker-chosen `state`. Nobody signed in, nobody
clicked, and the hop through a server the victim trusts is the entire point.

So in mode an error is automatically redirected **only when there is a session**.
Otherwise the person gets a page naming the application that sent them, where it wants
them sent next, the `state` it chose, and the error — with a link they can follow if
they choose to. That is the same section's *"inform the user and rely on the user to
make the correct decision"*, and it is what stops this server being usable as a
redirector by somebody who has not signed in. The page carries **no script and no
button** — an interstitial that submitted itself would be an automatic redirect with an
extra page in front of it.

Two exceptions, both from the specification rather than convenience:

- **`prompt=none`** — the section names silent authentication itself. That flow exists
  to be answered with no interaction and `login_required` is the answer it exists to
  produce; an interstitial would break the one flow whose whole contract is that
  nothing is shown.
- **A refusal coming back from the sign-in screen** — the person was at the screen and
  pressed Cancel, so they are present and have just decided. Asking them to confirm the
  consequence would be a second question about the same answer.

A **success** is never affected: reaching one means a session exists, which means the
user was authenticated first, which is what the MUST asks for.

**And a missing `client_id` is no longer redirected.** RFC 6749 §4.1.2.1, which §4.11.2
cites, says an authorization server MUST NOT redirect for an invalid combination of
`client_id` and `redirect_uri` — and a request naming no client has no client for the
URI to belong to. This service reported that *by redirecting to the URI*, which is the
one thing that paragraph forbids. It's a `400` now, raised above the point where any
error could be redirected.

*Automatically redirect only to trusted URIs* is the exact-match list: a URI on the
client's own entry or in `oauth2.redirectUris` is one somebody put there. What the BCP
suggests beyond that — URI analytics, reputation of the content behind the URI — is not
something a mock can do or should pretend to, and the row says so: a service claiming to
have judged a destination's credibility would be teaching a client author that somebody
had.

The client-side half — *clients MUST NOT expose open redirectors* — is in the table as
`enforced: no`, because it is on the other side of the redirect.

#### The nonce is the client's job, and there is a way to check it

*The client MUST validate the nonce in the ID Token, and MUST NOT use any token until
that validation succeeds.* Neither is enforceable from here and both are in the table
saying so, because a requirement left out of a compliance report reads as one that was
met. Whether a client compares the nonce it sent with the one it got back happens
inside the client, and no observation this server can make separates a client that
checks from one that does not.

What this server can do is the half that is its own — the ID Token carries the nonce
from the authorization request, always, and the mode refuses a request that asks for
an `id_token` without one — and it can give a client author a way to find out about
the other half. **`oauth2.breakIdTokenNonce` puts a deliberately wrong nonce in every
ID Token that should carry one.** A client that accepts the result is a client that is
not checking; one that refuses it is. It is the same device as `/spnego`'s three
knobs and the reserved password `invalid`: a reachable negative, off by default, *not*
part of RFC 9700 mode — it is useful in either — reported on `GET /oauth2/rfc9700`
whichever mode is in force, and logged loudly on every token it spoils, because an ID
Token that is wrong in a way nobody remembers turning on is an expensive afternoon.

#### The implicit grant (section 2.1.2)

Any `response_type` naming `token` — `token`, `code token`, `id_token token`,
`code id_token token` — is refused with `unsupported_response_type`, and the metadata
drops all four along with the `implicit` grant type. `id_token` and `code id_token`
remain: they issue no access token from the authorization endpoint, which is the
property the section is about. The consequence is worth seeing rather than reading —
with the mode on, the debugger's implicit pane gets a protocol error where it used to
get an access token in a fragment.

#### Refresh tokens (section 2.2.2)

*Refresh tokens for public clients MUST be sender-constrained or use refresh token
rotation.* This service could not authenticate a client it had not registered, so
"public" is the safe reading of an unknown one and **rotation applies to every
client**: redeeming a refresh token retires it, through the same revocation set
`/oauth2/revoke` and the console write to, so the retired token also reports
`active: false` at `/oauth2/introspect`. Without the mode a refresh token stays
usable for the whole of its life — twenty-four hours by default, and whatever
`oauth2.refreshTokenTtlS` says — which is the state this requirement is about.

Rotation alone is half of it. The reason a retired token is *remembered* rather than
merely revoked is **replay detection**: one coming back means the chain has been
copied, and nothing here can tell whether the legitimate client or the attacker is
holding it — which is exactly why the answer is to invalidate both. Every refresh
token descended from one original grant forms a **family**, and a replay revokes the
family, naming how many and why. Two details are deliberate: the family is recorded
at *issuance*, so a chain twenty refreshes long is one family and one lookup; and the
access tokens already minted from it are left alone, because they expire in an hour
and revoking them would remove the evidence of what the lost credential was used for.

Two checks this grant never made come with it. The client presenting a refresh token
must be the client it was issued to — `client_id` is required on the request, per RFC
6749 section 6, and compared — and the requested `scope` must be a **subset** of what
was granted. Without that second one a client could ask for `openid admin` on a token
granted `openid` and be given it: privilege escalation by typing, which is the exact
opposite of section 2.3's *restricted to the minimum required*.

**Bound to the resource servers, too — and that one was a hole I had left open.** The
section says a refresh token must be bound to the authorized scope *and resource
servers*. The scope was on the token from the beginning; the resources were not, so an
access token narrowed to one resource server with RFC 8707 could be **refreshed into
one carrying this service's default audience** — a grant widening itself by being
renewed, which is the same escalation the scope check refuses one field over. The
refresh token now carries `resources`, the refreshed access token takes its audience
from them, and a refresh asking for a resource the grant does not carry is
`invalid_target`. Verified end to end: `https://api.example.com/v1` survives a refresh,
and adding `https://other.example.com` on the way through is refused.

**An idle refresh chain expires.** Section 2.2.2 says a refresh token SHOULD expire
after a period of client *inactivity* and that the period is deployment-dependent, so
`oauth2.refreshIdleSeconds` is a setting rather than a constant — measured from the
last time any token in the **chain** was redeemed, not from issuance, so a client that
refreshes regularly keeps its grant indefinitely and one that stops is cut off. It
**refuses** rather than revoking the family: an idle chain is a client that went away,
not a chain that was copied, and treating the two alike would make the replay
refusal — which says something serious — indistinguishable from an afternoon off. `0`
turns it off without touching the rest of the mode.

**Signing out revokes them.** The section's other lifetime rule is a MAY — revoke after
a security event, and it names logout — and it matters more than a MAY suggests:
without it, signing out drops a cookie and leaves a *thirty-day credential* in the
client's hands, while a person who signed out of a shared browser has every reason to
believe otherwise. It happens in `authn.js`'s `endSession()`, which is the single place
`/oauth2/logout`, WS-Federation's `wsignout1.0`, SAML 2.0's `/saml2/slo` and `/logout` all end a session — a revocation at
each would be two that could come to disagree. **Access tokens are deliberately left
alone**: they expire in an hour, and revoking them would take away the evidence of what
the session did.

The remaining MUSTs in that section were already true and now have rows saying so. A
refresh token is an RS256 JWT with a 128-bit random `jti`, signed with a key generated
per start that never leaves the process — not guessable, not forgeable, not modifiable,
and the grant verifies that signature before reading a single claim, which is what
makes the client binding and the resource list on it worth anything. *Protected in
storage* has an easy answer here: **there is no storage to protect**, because this
service keeps no copy of a refresh token — only the revocation set, which is jtis
rather than tokens. And the *risk assessment* is a process requirement, so what it can
honestly mean in code is a policy written down: a refresh token is issued only where a
grant has an end-user behind it, which is why `client_credentials` sets
`withRefresh: false` (RFC 6749 §4.4.3 — there is no resource owner to be absent, so the
long-lived credential buys nothing a fresh call would not).

#### The password grant is refused (section 2.4)

The one grant RFC 9700 rules out outright, and the reasons are worth keeping in view:
it hands the End-User's password to the client, and it cannot carry a second factor —
no WebAuthn, no step-up, nothing that needs a browser. A protocol whose whole shape
assumes a password and nothing else cannot be extended to the way people actually sign
in now.

Three things happen in this mode, and the third is the one that is easy to leave out.
`grant_type=password` is answered with `unsupported_grant_type`. It drops out of
`grant_types_supported` in **both** discovery documents. And **`POST /oauth2/register`
refuses to register a client for it** — `invalid_client_metadata`, per RFC 7591
section 3.2.2 — because a registration recording a grant the token endpoint will always
refuse is the discovery document's promise broken in the other direction: the client
keeps that document and acts on it, and would find out at its first token request
rather than at the moment it asked.

The same registration check covers what the other sections rule out, since the
argument is identical: `grant_types: ["implicit"]`, any `response_types` naming
`token`, and an `http://` redirect URI off the loopback are all refused at
registration rather than recorded and then refused in use. RFC 7591 permits a server
to return metadata different from what was asked for, and that was the alternative —
but a client that registered for `password` and got back a registration silently
without it would have to compare the two documents field by field to notice.

The grant stays available by default, because a client with code for it needs
somewhere to run that code. That is the whole reason this is a mode rather than a
deletion: *don't implement it for new systems* is advice about new systems, and the
old ones still have to be tested against something.

#### Client authentication — all six methods, all verified (section 2.5)

Everywhere else this service checks nothing: any password signs anybody in, any LDAP
bind succeeds. Section 2.5 is not a blanket *always authenticate clients* — it is
conditioned on it being feasible to have a **process for issuing credentials**, and
`POST /oauth2/register` is one. That is the row `client-credential-issuance`, and it is
what makes the rest of the section applicable at all.

A client whose entry says it is **confidential** — a `token_endpoint_auth_method` other
than `none`, with RFC 7591's `client_secret_basic` default applying when a registration
omits it — must authenticate by whichever of the six methods its entry declares:

| method | what proves the client |
|---|---|
| `client_secret_basic` / `client_secret_post` | the secret, compared in constant time |
| `client_secret_jwt` | an assertion signed HS256 with the secret |
| `private_key_jwt` | an assertion signed with the client's key, verified against its registered `jwks`, against a JWKS **this service issued it** from its own certificate authority (`oauthAssertionJwks`), or against an `x5c` chain the assertion carries that builds a path to this realm's Root CA |
| `tls_client_auth` | a client certificate whose chain **verified**, issued by this realm to this application or carrying the **one subject** it registered (RFC 8705 §2.1) |
| `self_signed_tls_client_auth` | the client certificate is the `x5c` of a key in its `jwks`, or matches its registered **thumbprint** (RFC 8705 §2.2) |

**The three asymmetric ones are the change.** `private_key_jwt` and
`client_secret_jwt` used to be advertised and *accepted without being looked at* — a
client author configured the asymmetric method and came away believing an assertion
had been checked, which is worse than not offering it. They now get the full RFC 7523
section 3 treatment: signature against the registered keys, `iss` **and** `sub` both
the client, audience (the token endpoint *or* the issuer, because RFC 7523 and OIDC
Core §9 differ and half the client libraries in the world pick one each), expiry with
a configurable skew, and a `jti` remembered until the assertion expires — a signed
assertion captured off the wire is a credential until then, so a replay is refused.
**Once, ever, since 2026-09-13**: one used-assertion history covers client
authentication and the grant and both profiles, so a JWT that authenticated a
client is refused as a grant; it persists in the `ldif` and `postgres` stores in
both modes and is claimed atomically on postgres; and an assertion is spent only
when its token request issues tokens. `/admin/used-assertions` lists it.

**AND SINCE 2026-09-10 AN ASSERTION MAY ARRIVE ENCRYPTED, WHICH IS RFC 7523
SECTION 3'S CLAIM 10.** A nested JWT — a JWE whose plaintext is the JWS — in any
of sixteen key management algorithms against six content encryption ones. Which
key opens it depends on what the sender could possibly have had: an asymmetric
algorithm is encrypted to the RSA or EC key this service publishes at
`/oauth2/jwks`, which anybody can fetch, and a symmetric one is encrypted under
the **client secret**, which is the only shared key that exists between this
service and a client. The `cty` is checked rather than assumed, and a JWE whose
plaintext is not a signed JWT is refused citing the claim it breaks —
**encryption does not stand in for a signature, because an encrypted document
says nothing about who wrote it.** `RSA1_5` is the one algorithm deliberately
absent, and the refusal names it: RFC 8017 deprecated PKCS#1 v1.5 encryption,
and implementing it safely means making an unwrap failure indistinguishable
from every later failure, which is a property of a whole code path rather than
of one function.

Two details are worth the ink. **An assertion nominating `HS256` for `private_key_jwt`
is refused, not verified** — verifying it would use the client's *public* key as an
HMAC secret, which is the classic JWT forgery and one anybody can perform, since the
key is public. And **`client_id` may be omitted entirely** with `private_key_jwt`, as
OIDC Core §9 allows: the `sub` is read from the unverified assertion to *select* which
client to check against, and the assertion is then verified against that client's keys
with `iss` and `sub` required to match — so a forged `sub` picks a client whose key
will not verify the signature.

`jwks_uri` is **recorded and never followed**. Fetching a URL somebody registered in
order to verify a credential is a server-side request forgery with a specification
citation attached — the same refusal WS-Federation's `wreqptr` gets here, and holding
that position in one file and not the other would be no position at all. A client that
registers only `jwks_uri` is told to register `jwks` by value, by name, when it tries
to authenticate.

`token_endpoint_auth_methods_supported` is **built from the list the verifier can
actually check**, and the two certificate methods appear only where there is a TLS
handshake to read one from. It used to name `private_key_jwt` while nothing verified an
assertion, which is the worst shape a metadata member can have.

What is left as a *preference* rather than a rule: a client authenticating with a
shared secret is answered and **logged** as the RECOMMENDED it did not follow — every
time, not once, because the point is that this server is holding a copy of that secret
on behalf of the client and a log line that appeared once would leave that fact where
nobody looks. A SHOULD refused is a server stricter than its specification.

A client with **nothing on its entry** to check against is left alone rather than
refused — there is nothing to compare, and inventing a refusal would be theatre — and
so is a `client_id` this service has never seen. **No end user's password is checked in
this mode or any other.**

#### Authorization server metadata, and more than one of them (section 2.6)

*Publish RFC 8414 metadata; let clients consume it; use it to discover security
capabilities, to reduce endpoint misconfiguration, and to make key rotation
possible.* The point behind all four, in the BCP's own framing: **don't make
clients hard-code what the server can advertise.**

The publishing half was already here — both documents, built from one object so
they cannot disagree, with `code_challenge_methods_supported` among them (the one
capability with *no other signal*: a server that supports PKCE and doesn't advertise
it will simply never be asked for it). What was missing is the interesting question
about a client, which is not *does it read the metadata* but **what does it do when
the metadata says something else**.

So a discovery document is now an **authorization server**, selected by the path
component both shapes already carry:

```
/.well-known/oauth-authorization-server            the default
/.well-known/oauth-authorization-server/tenant1    the tenant1 profile   (RFC 8414 §3.1 inserts)
/tenant1/.well-known/openid-configuration          the same one          (OIDC Discovery §4 appends)
```

Those two URLs are the commonest reason a discovery fetch 404s, and this service has
answered both for a long time; what is new is that the path now selects a
*configuration*. `/admin/authorization-servers` and
`GET|POST /admin-api/authorization-servers` manage them — create, set a member,
remove a member, reset a member, delete — paginated, with a drill-down per profile.

**Each one is a real authorization server, not a document about one.** Its endpoints
live under its own name — `/{id}/oauth2/authorize`, `/{id}/oauth2/token`, and the rest
of the set — which is exactly what its metadata advertises, so a client that read that
document is already using them. Its tokens carry **its** issuer and **its** audience,
and an authorization code issued by one is refused at another's token endpoint: they
are separate authorization servers that happen to share a process, and a credential
does not cross between them.

**What the document says is what that server does.** The members marked *enforced* on
the page drive behaviour — `response_types_supported`, `grant_types_supported`,
`code_challenge_methods_supported`, `token_endpoint_auth_methods_supported`,
`dpop_signing_alg_values_supported` — so narrowing one narrows that server's own
endpoints and nothing else:

```
POST /admin-api/authorization-servers/set
  {"profile":"tenant-alpha","member":"grant_types_supported","value":["authorization_code"]}

POST /oauth2/token               grant_type=client_credentials  →  access_token
POST /tenant-alpha/oauth2/token  grant_type=client_credentials  →  unsupported_grant_type
```

**Every authorization server starts equal.** One that has never been configured has
exactly the capabilities the default one has, so `tenant1` and `tenant2` behave
identically until somebody makes them differ. And **a name nobody configured is created
on first sight** — by an endpoint or by a metadata fetch, since reading the document
*is* accessing the server — so an arbitrary path works immediately and can then be
configured. The console marks which ones were *asked for* and which were *configured*,
because an authorization server somebody is using and cannot see is worse than one that
exists with nothing special about it.

**Every client may use every one of them.** Nothing restricts a client to a server;
`/admin/applications` records which ones each client has actually *used*, on
`appAuthorizationServer`, so a client that talks to two is one client with two values.

**Any configuration is valid**, and that is the feature rather than a gap. A member
this service has never heard of is stored and published, because half the value of a
mock is answering with something a client did not expect. The catalogue on the page is
*help for whoever fills the form* — what each member is and why a client cares — not a
schema. That is the deliberate opposite of the applications registry next door, which
**refuses** an attribute outside its table because that table is a published contract
about what an entry carries.

**The defaults are what this service already did.** A profile with no overrides
publishes exactly the document `asMetadata()` builds, and a path nobody has configured
publishes it too — so nothing that worked before this existed behaves differently.

**Drift changed meaning when the design did**, and the new one is narrower and more
useful. It used to mean *this document lies about this service*; that cannot happen for
the enforced members any more, because the document **is** the behaviour. What it means
now is **a member this service cannot honour however it is set** —
`id_token_signing_alg_values_supported: ["ES256"]` on a service that signs RS256, a
`token_endpoint` pointing at another host, or a member invented outright. Those are
still publishable, because producing a misconfigured document on purpose is exactly
what a client's error paths need, and they are still reported:

```
require_pushed_authorization_requests   invented   Nothing here backs it.
x_vendor                                invented   Nothing here backs it.
```

A **removal** is reported too, and for an enforced member it says the useful thing: the
check that member drives does not run, because a client cannot learn from an absent
`code_challenge_methods_supported` that PKCE is unavailable — it learns *nothing*, which
is what section 2.6 is arguing about, and a server that refused every method on the
strength of having removed the member would be enforcing something it never said.

That is why `remove` and `reset` are separate operations: reset undoes an override,
remove publishes an **absence**.

`/admin/sts-metadata` lists the authorization servers this process has actually served, with
each one's metadata URLs and endpoints — it cannot read them off the router, because
one route (`/:as/oauth2/…`) serves all of them, so they are described by hand the same
way the Kerberos and LDAP listeners are. Only the ones that have been *asked for* are
listed: a name becomes an authorization server by being asked for, so the set of
possible ones is every string and the set of real ones is that list.

One property is a fact about the mock rather than the model, and the page says so:
**every authorization server here signs with the same key**. They are separate issuers
sharing one keypair, which a real deployment would not do.

The profiles live in memory, gone on restart — they are not one of the three things *Persistence* above can keep — in the same family as the custom claim
sets and the verifier's request — not in the directory. `ou=applications` holds
applications because a relying party is a thing in the world that other systems have
opinions about; an authorization server profile is this service's own configuration.

#### TLS, and what a reverse proxy changes (section 2.6)

*Use TLS. End-to-end between client and resource server is RECOMMENDED. If TLS
terminates at a proxy, secure the proxy-to-application hop and make the proxy
sanitize inbound security-sensitive headers.*

The first two are `global.https`, which every appconfig file here sets and which
RFC 9700 mode would turn on anyway: every endpoint here —
authorization, token, both discovery documents, and the resource server at
`/oauth2/userinfo` and the three credential endpoints — is on one listener, so *end to
end* is true of everything inside this process. What it cannot be true of is a hop this
service cannot see, and that is the rest of the paragraph.

**The application's half of the reverse-proxy rule is the part this service can do,
and it was getting it wrong in two different ways at once.** `X-Forwarded-Proto` and
`X-Forwarded-Host` decide what this service thinks its own issuer, endpoints and DPoP
`htu` are. `dpop.js` believed them **unconditionally**; `baseUrlOf()` in `helpers.js`
**ignored them entirely**. Two functions in one service, answering the same question two
ways — and each answer was wrong for the deployment the other was written for:

- behind a proxy, the metadata published `http://` URLs to clients that reached the
  service over `https`, and named the last hop as the issuer;
- with no proxy, any client could set `X-Forwarded-Host` and choose the `htu` its own
  DPoP proof would be checked against — which is the whole of what binding a proof to
  an endpoint is for. A client that picks its own `htu` has unbound its own proof, and
  can replay one captured at another endpoint by naming that endpoint in a header.

There is one decision now, `global.trustProxy`, shared by both functions and **off by
default**. Off, the forwarded headers are ignored and this service describes the
connection it can see. On, they decide. Verified both ways: with it off, a request
carrying `X-Forwarded-Host: attacker.example` still gets `issuer:
http://127.0.0.1:8099`; with it on, `X-Forwarded-Host: sts.example.com` produces
`issuer: https://sts.example.com` and every endpoint with it.

**This is a behaviour change for a proxied deployment.** A DPoP proof made against the
proxy's URL is now refused unless the setting is on — so that refusal names the setting
and explains what to do, because a proof refused for a reason nobody can see is an
afternoon spent in the client.

**No client certificate is ever read from a header**, in either mode. A proxy that
terminates mTLS forwards the certificate in `X-Client-Cert`, `X-Forwarded-Client-Cert`,
`X-SSL-Client-Cert` or one of a dozen vendor spellings, and an application that believed
one would be accepting a certificate anybody can forge — a header costs nothing to
write. RFC 8705 binding and mTLS client authentication both read the certificate off
the TLS handshake itself. The cost is real and stated rather than hidden: a proxy
terminating mTLS in front of this service **cannot pass the certificate through**.

`GET /tls/forwarded` reports all of it — every forwarding header, every certificate
header, whether any of it was believed, and the effective base URL that every issuer
and every published endpoint is built from. The certificate headers a request carried
are **listed even though they are ignored**, because a mock that silently ignored a
header somebody was relying on would be as bad as one that silently trusted it.

The two things this service genuinely cannot do are in the table saying so rather than
left out: a proxy MUST strip inbound security-sensitive headers before setting its own
(otherwise a client reaches straight past it), and the proxy-to-application hop must be
protected against eavesdropping, injection and replay. Both are decisions about a link
this process has no view of.

#### CORS is withheld from the authorization endpoint (section 2.6)

CORS headers are right for the token, userinfo, metadata and JWKS endpoints an
in-browser client fetches with XHR — for the origins this service allows at all (see
*CORS: which pages may read an answer*). The authorization endpoint is a different kind
of endpoint: a browser *navigates* to it, so nothing legitimate ever read those headers
there. In this mode they are withheld from `/oauth2/authorize` for every origin,
preflight included.

#### Token leakage through the browser (section 4.3)

Three routes out, and this service was already closed on two of them.

**The `Referer` header.** Every response here carries `Referrer-Policy: no-referrer`
— the strongest of them, suppressing the header entirely rather than trimming it — and
the pages a browser lands on contain no third-party resource and no external link. That
is not just discipline: the content security policy is `default-src 'none'` with
`img-src` limited to `'self'` and `data:`, so a third-party resource could not load if
one were added by accident. Both are there because a header is something somebody can
drop and a CSP is not.

**Browser history.** An access token has never been readable from a URI query parameter
here — the token comes from the `Authorization` header and nowhere else. But *ignored*
is not *refused*, and that gap was worth closing: a client sending `?access_token=…`
got a `401` saying a token was required, which is true, unhelpful, and sends somebody
looking at their credential rather than at where they put it. In mode the query is now
inspected **only in order to refuse it**, with a message that says why — a URL goes
into history, the address bar, server logs and the `Referer` of anything the page then
fetches, so a token in one is a token in all of them. The token is never echoed back:
it has already been somewhere it should not be, and a response body would be one more
place. The audit log has redacted `access_token` and eight other query keys all along,
so it never reaches a row either.

The other direction was always right — a bare code goes in the query and anything
carrying a token goes in the fragment, which a browser never sends to a server.

**`response_mode=form_post`, which this service advertised and did not have.** The
metadata used to name it and `redirectBack()` answered every request with a `302`
regardless, so a client that asked for `form_post` sat waiting for a POST that never
came; the member had been removed and the reason written down. It is implemented now,
so the member is back. The response travels in a form body — in no URL, no history
entry, no `Referer` — and that holds for **error** responses too, because a client that
asked for `form_post` and got its failure in a query string has had the failure put in
browser history, which is the one place section 4.3 is asking for it not to be.

The page is the same shape WS-Federation's response is, deliberately: a real form with
a real submit button, plus a separate script at `/oauth2/autopost.js` that submits it.
`script-src` is `'none'` across this service, so with the script blocked **the button
is the whole mechanism** — and a named resource is the smallest exception that works,
where an inline script would need `'unsafe-inline'`, the clause that would make the
relaxation matter. `form-action` stays out of the policy for the reason `app.js`
records: the form posts to the client's `redirect_uri`, which is by definition another
origin.

It is available in **both** modes, unlike the refusals: a safety feature offered only
in compliance mode would be backwards, and a client that does not ask for it is
unaffected.

**A code exposed through history must be useless**, which is the same two mechanisms
the code-injection work put in — single use with the replay relaxation off, a second
presentation revoking what the first bought, bound to its client, and worthless without
the PKCE verifier that never left the client. `form_post` keeps it out of the URL to
begin with.

#### 307 redirects, and why this one is easy to miss (section 4.12)

A `307` **preserves the method and the body**. The redirect that follows a sign-in POST
points at a URL the calling protocol composed — so with a 307 the browser would repeat
that POST, username and password included, to the client. The authorization server hands
over the user's password and nobody has done anything wrong.

This service has never emitted a 307 or a 308 anywhere. What it emitted after the
sign-in POST was a **302**, whose behaviour after a POST is historically ambiguous: every
browser turns it into a GET and no specification says it must. The section asks for
**303**, which says it. Both sign-in screens use 303 now — `authn.js`'s
`returnToCaller()`, the single funnel the password step and the WebAuthn step both leave
through, and WS-Federation's own screen, which is separate for the reason §13.2.1 gives.

**Not mode-gated**, unlike the refusals. No client can tell the difference, so gating it
would leave the default deployment with the ambiguous one and buy nobody an exercise.

#### Telling a client apart from a person (section 4.13)

`POST /oauth2/register` generates the `client_id` and ignores any the request proposes,
so a *registered* client cannot pick an identifier that looks like a subject. But this
service issues to **any** `client_id` that asks, so an unregistered one is whatever
string a caller put in the query — which is exactly the shared namespace the section
warns about, and why the MUST beside it asks for *another mechanism allowing resource
servers to distinguish client credentials from resource-owner credentials*.

There is one in each mode, and they are **different mechanisms** — worth being exact
about, because a resource server testing for the wrong one would conclude that a client
credential belonged to a person:

| | how to tell |
|---|---|
| mode off | `sub` **equals** `client_id` on a `client_credentials` token and on nothing else. RFC 9700 suggests this comparison itself; it needs no invented claim |
| mode on | **separate namespaces** — `urn:sts:client:<id>` beside a person's `urn:uuid:<entryUUID>` (it was `urn:sts:user:<name>` until 2026-09-14), so the two cannot collide however a client is named |

The namespace is the stronger answer and it is the mode's, because changing a subject
identifier is a change and callers key on it. Note the consequence, which the row states
rather than leaving to be discovered: **with the mode on, `sub` no longer equals
`client_id`**, so a resource server written against the comparison must read the prefix
instead. A person's `sub` is untouched in either mode.

#### Clickjacking (section 4.14)

Every response carries **both** countermeasures: `X-Frame-Options: DENY` for the
browsers that still read it, and CSP Level 2's `frame-ancestors 'none'`, which is the
one that actually governs. Two rather than one because the first is obsolete and the
second is not universally old enough to rely on alone, and the cost of both is a header.
It matters most on the sign-in screen and the authorization endpoint, where the click a
framed page steals *is* the decision.

That much was already true. Auditing it against the section's own list — *apply the
protection to the relevant pages, including error pages* — turned up two ways the clause
could go missing, and the second one was live.

**`frame-ancestors` has no fallback from `default-src`.** A response that sets
`Content-Security-Policy: default-src 'none'` and nothing else is framable as far as CSP
is concerned. Five routes here relax the policy so they can load a named script, and each
one *sets the whole header* — so each could have dropped the clause with nothing failing:
the page works, the script runs, the protection is quietly gone. They all go through
`app.contentSecurityPolicy()` now, which re-adds the framing clauses **whatever the
caller asks for**. A caller cannot turn them off even by passing `frame-ancestors: *`,
deliberately: no page in an authorization server should be framable.

**And Express's own 404 handler was replacing the policy with `default-src 'none'`.** So
every unrouted path — every typo, every probe, every error page the framework generated —
came back with the framing clause gone and only the obsolete header behind it. Nothing in
this repository could have surfaced that, because the header this service set *was*
correct; it was overwritten afterwards, on the way out. The policy is re-checked when the
response is flushed and the base put back if the clause is missing — testing for *"does
it still carry the clause"* rather than *"is it the value I set"*, so the five legitimate
relaxations are untouched.

The 404 **body** is left exactly as Express writes it. `Cannot GET /path` is how the
parent project's `tests/vendored/sts_metadata.js` tells an unrouted path from an endpoint
legitimately answering 404, and a prettier 404 here would have broken that distinction
without anything saying so.

Device authorization pages get a row saying there are none — this service implements no
device grant, so there is no `user_code` page to frame. It is a row rather than an
omission because the section names those pages, and if that grant is ever added its pages
are covered without anybody doing anything, which is the point of a service-wide default
that a relaxation cannot weaken.

#### In-browser communication (section 4.17)

This section is conditional — *if the implementation uses in-browser communication* —
and establishing that the condition is false is the work, rather than assuming it.
Audited: nothing here calls `postMessage`, listens for a `message` event, opens a
`BroadcastChannel` or `MessageChannel`, touches `window.opener` or `window.parent`, or
renders an iframe. There are exactly four scripts served from this service — the WebAuthn
ceremony, two form auto-posters and the API explorer — and none of them does any of it.

So the requirements cannot be violated because the mechanism is not present, which is a
different claim from their being met, and the rows say which.

**But the audit found a live hole next door.** The response mode this section is about is
`web_message` — postMessage-based, and what SPAs use for silent renewal in a hidden
iframe. This service does not perform it, and a client asking for it got a **302** and sat
waiting for a message that never arrived. That is the identical silent failure `form_post`
had while it was advertised and missing, and the same reason that one was worth fixing:
the failure is at the client end with nothing here to point at.

`response_mode` is now checked against what **this authorization server advertises** in
`response_modes_supported`, so the document and the endpoint cannot disagree:

```
response_mode=web_message  →  invalid_request, naming the three it does perform
response_mode=query|fragment|form_post  →  answered
```

It is a capability like the others, so it is per authorization server: one configured
with `response_modes_supported: ["form_post"]` refuses `query` at its own endpoint while
the default server still answers it. And it is not gated on RFC 9700 mode — the default
document advertises everything this service does, so a request that would have worked
still works.

If `web_message` is ever added here, the rows say what it costs: the target origin of
every message must be the client's **registered** origin matched exactly — never `"*"`,
which broadcasts an authorization code to whatever document is listening — and the
exact-match machinery for that already exists, because a registered redirect URI is where
a client's trusted origin comes from. Every other authorization-response protection
applies unchanged: single-use codes, PKCE binding, `iss` on the response.

The client's half — *verify `event.origin` against the expected authorization server* —
is in the table as `enforced: no`. A listener that skips it accepts an authorization
response from any document that can reach it, which is how an injected message becomes an
injected code; nothing this service can do about it, and nothing it can even observe.

#### One row that says this service does the wrong thing

*Resource servers MUST treat access tokens as sensitive secrets and MUST NOT store them
in plaintext.* **This service does neither**, and the row says so rather than being
left out. It keeps every token it issues, in memory and in full, and prints them on
`/admin/tokens` — which is what lets the console show somebody the JWT they just
received, and is the same decision `/krb5/principals` makes about the Kerberos
passwords. What *is* true is that nothing writes a token to disk, the audit log redacts
them, and the store dies with the process. A real resource server must do the opposite,
and the row ends by saying not to copy this part.

#### What is observed rather than refused

Three requirements are the client's to keep, so this server reports them and does not
refuse. A **reused `code_challenge` or `nonce`** is described above. An **unbound
access token** is logged at issuance — section 2.2's sender-constraining is a SHOULD,
DPoP is implemented here in full and advertised, and whether a token is bound is the
client's decision because it binds by sending a proof. There is deliberately **no
"DPoP required" mode**: this service exists to exercise Bearer clients too, and a mode
that refused them would remove the thing half its callers are testing. And a client
authenticating with a **shared secret** is logged as the asymmetric recommendation it
did not follow.

#### What the mode does not cover

Stated so the flag is not read as *RFC 9700 compliant* full stop. The whole of section
2 now has rows, including the requirements this server already satisfied — `iss` on
every authorization response for mix-up defence, RFC 8414 metadata published, a
`client_id` a client cannot choose, no access token accepted in a query parameter, and
access tokens audience-restricted to a single resource server.

The two client-side nonce requirements are in the table with `enforced: no` and the
reason, rather than left out — see above for the switch that lets a client author test
the first of them anyway.

Not this mode's: **Pushed Authorization Requests** (RFC 9126), a feature in every mode
(see *Pushed authorization requests* below), and **RFC 8705** — both halves are
features in every mode (see *Mutual TLS (RFC 8705)* below). Client authentication at
`/oauth2/revoke` is likewise not enforced by this mode, and at `/oauth2/introspect` it
is not this mode's to decide: an RFC 9701 JWT request authenticates in every mode and a
JSON request in product mode — see *Introspection as a JWT* below. And
the requirements RFC 9700 places on the *client* stay the client's: this service can
detect several and fix none.

### OAuth 2.1 mode — the draft framework, as a second switch

`oauth2.oauth21` enforces **draft-ietf-oauth-v2-1-16**, which is still an
Internet-Draft; every refusal and `GET /oauth2/oauth21` name that revision,
because a later one may say something different. **It turns RFC 9700 mode on**:
OAuth 2.1 describes itself as OAuth 2.0 with the best current practices
applied, so everything in the section above is part of it and is not enforced a
second time.

It is a mode of its own rather than a new name for that one, because in two
places RFC 9700 mode refuses a client that follows OAuth 2.1 to the letter:

* **a token request with no `redirect_uri`.** RFC 6749 section 4.1.3 required
  it; OAuth 2.1 section 10.2 removed it, because PKCE binds the code instead.
  This mode accepts its absence — and still requires an identical one when it is
  sent, in every mode. The exception is a code issued without PKCE under the
  OpenID Connect nonce exemption, for which `redirect_uri` is still the binding.
* **an authorization request with no `redirect_uri`** from a client that has
  registered exactly one (section 4.1.1). With several it is refused.

And it adds what 2.1 requires beyond RFC 9700:

| Refused in OAuth 2.1 mode | Draft section |
|---|---|
| A code requested with no PKCE, unless the client is confidential **with a credential on file**, asks for `openid` and sends a `nonce` | 7.5.1.1 |
| `code_challenge` with no `code_challenge_method` | 4.1.1 |
| A client with no redirect URI of its own — `oauth2.redirectUris` is **not read** | 2.3.1 |
| A token request naming a client whose entry declares nothing a sighting would not have written | 2.5, 3.2.1 |
| A client secret or assertion that was sent and did not verify; two authentication methods in one request | 3.2.2, 2.4 |
| The client credentials grant from a client that did not authenticate | 4.2 |
| A JWT client assertion whose `aud` is not the issuer as its **sole** value | 2.4 → draft-ietf-oauth-rfc7523bis-11 |
| SAML bearer client authentication (also dropped from the metadata and refused at registration) | 2.4 → rfc7523bis |
| A repeated request parameter (`resource` and `audience` may repeat) | 3.1, 3.2 |

It also ignores `oauth2.loopbackPortWildcard` (a loopback redirect may use any
port, section 8.4.2), caps a code's lifetime at ten minutes, and limits
`error_description` to the characters section 3.2.4 allows.

**What it deliberately does not hold to the registered-client rule**: the
OpenID4VCI pre-authorized code grant, whose anonymous access is that
specification's design, and the RFC 7523 and RFC 7522 grants when they carry no
client. An OpenID4VCI wallet using the authorization code flow with a
`client_id` nobody registered **is** refused — register it, or use a realm
without this mode. Introspection and revocation still authenticate no client.

**Three changes that came with it are in every mode**, because they are fixes
rather than policy: a **private-use redirect URI** such as
`com.example.app:/callback` is accepted (a scheme with no period — `myapp:` — is
refused, and so is `response_mode=form_post` to one, since a protocol handler is
never handed a request body); a refresh that narrows `scope` or `resource`
narrows the access token and leaves the **rotated refresh token** carrying what
the presented one carried (RFC 6749 section 6); and a **client secret that fails
is rate limited** wherever this service checks one — per realm, per client and
address together, so nobody elsewhere can lock a client out.

Like RFC 9700 mode it is restart-only for the process and may be carried by a
trust realm, which is the way to run a permissive pass, an RFC 9700 pass and an
OAuth 2.1 pass against one service:

```bash
curl -k -X POST https://localhost:8081/admin-api/realms/create \
     -H 'Content-Type: application/json' \
     -d '{"id":"oauth21","name":"OAuth 2.1 mode",
          "overrides":{"oauth2.oauth21":true}}'
```

### A redeemed authorization code is replayed, not refused

RFC 6749 section 4.1.2 makes an authorization code single use and section 10.5 says a
second presentation SHOULD invalidate what the first one issued. This service used to
implement that in the shortest way there is — delete the record on the line after the
lookup — and the cost was the answer it then gave: **every** second Token Request
carrying that code was refused with *Unknown or already-used authorization code*, which
is equally true of a stolen code, a reloaded page, a double-submitted form and a client
retrying after the first attempt was refused for a bad `code_verifier`. It named none
of them. The last case is the perverse one: the check consumed the code it refused, so
the corrected request was answered by talking about reuse instead of issuing tokens.

Three things are different now, and only the second departs from the RFC.

Nothing below the lookup consumes the code: `redirect_uri`, PKCE and the RFC 9449
`dpop_jkt` binding all refuse and leave it redeemable, so the message a client acts on
is the message it gets to act on. The code is deleted where it is actually redeemed.

A redeemed code is **idempotent for the rest of its own lifetime**. The token set is
kept beside the code until the moment the code would have expired anyway
(`AUTH_CODE_TTL_MS`, five minutes), and an identical repeat of the Token Request — same
client, same `redirect_uri`, same PKCE verifier, same DPoP key — is answered with that
same token set rather than an error. Nothing is minted twice: the second answer is the
first answer, down to the `jti`. So the relaxation cannot outlive the rule it relaxes,
and a `log.warn` says each time it fires that a real authorization server would refuse.

The refusals now say what happened. A code presented with anything different is refused
with the field that differed named, and with when the code was redeemed and by which
client. A code this service never issued gets its own sentence: codes live in memory
only, so one minted before the last restart is *gone* rather than *used*, and the
message says so along with how long the process has been up. Those two states are
indistinguishable from the client, which is why the server has to be the one that tells
them apart.

The **pre-authorized code** grant is deliberately not relaxed — its single use is a
property of the Credential Offer under test, and the debugger's suite asserts it.

**RFC 9700 mode turns the relaxation off**, which is what section 4.5 asks for: the
repeat is refused and everything the code bought is revoked. See *Authorization code
protection* above. The relaxation is the default because this service exists to show
what happened rather than to be strict about it; the mode is there for when being
strict is the point.

### Token Exchange (RFC 8693), and what it deliberately does not check

`grant_type=urn:ietf:params:oauth:grant-type:token-exchange` at the token endpoint
trades one token for another: `subject_token` is who the new token is *about*, the
authenticated client is who is asking, and the exchanged token comes back with
`issued_token_type: urn:ietf:params:oauth:token-type:access_token`.

Two decisions in it are the ones worth reading. **The subject token is verified if this
server signed it and merely *read* if it did not** — `jwt.verify` first, and on failure
the payload is base64url-decoded without any signature check and the log says so in as
many words. That is the same posture as the credential endpoints and for the same
reason: the interesting exchange is the federated one, where the subject token came
from a real IdP this mock has no key for, and refusing it would make the grant
untestable. It is also exactly the behaviour that would be a critical vulnerability in
a real authorization server, which is why it is written down here rather than left as an
implementation detail. And `actor_token` becomes the RFC 8693 `act` claim — the
delegation record saying *this* client is acting for *that* subject, which is the only
part of the response a downstream resource server can reason about.

**The exchanged token carries a refresh token when the request asks for one, and
otherwise still carries none.** This paragraph said flatly that it never did — because
there is no end-user session behind an exchange to refresh against — and RFC 8693
section 2.2.1 answers that argument directly: a refresh token is worth issuing here
precisely "in cases where the client of the token exchange needs the ability to access a
resource even when the original credential is no longer valid", which is the
user-not-present case where there is no session by design. So the parameter section 2.1
gives a client for saying which token it wants is now read:
`requested_token_type=urn:ietf:params:oauth:token-type:refresh_token` adds a
`refresh_token` to the response, and an exchange that says nothing gets exactly what it
always got.

**Whether that ask is honoured is `oauth2.tokenExchangeRefreshToken`, and it has three
values rather than two.** RFC 8693 leaves the decision to the authorization server, real
ones differ, and a client written against one of them meets the others — which is the
difference this service exists to be. `when-requested` is the default and is the
paragraph above. `never` refuses the ask silently: the exchange still succeeds, with no
refresh token in it and a line in the log naming the setting, because section 2.1 makes
`requested_token_type` a request rather than an instruction and an exchange that asked
and did not get one is still well-formed. `always` hands one to every exchange whether it
asked or not. A bool could not have said this: `false` would have had to mean `never`,
leaving `true` meaning either of the other two and no way to reach the third — and the
`always` side is where the interesting client bug lives, since a credential arrives that
the client never asked for and must not leak. **`oauthTokenExchangeRefreshToken` on the
CLIENT's own entry overrides it for that client alone** — the client performing the
exchange, because the refresh token is handed to the client and because in the
interesting case the subject the exchange is *about* has no entry here at all. **What comes back is an ordinary refresh token of this service** — the same
`typ`, the same lifetime (`oauth2.refreshTokenTtlS`), redeemable at the refresh grant,
revocable at `/oauth2/revoke`, listed at `/admin/tokens`, rotated in RFC 9700 mode, and
bound to the DPoP key or client certificate the exchange was made with, because it is
minted by the one function every grant here mints one through. It also remembers the
RFC 8707 resources the exchange named, so a renewal cannot widen the audience the
exchange narrowed. `issued_token_type` still says `access_token`, because it describes
the token in the `access_token` member and that is what that member holds: the refresh
token is in `refresh_token`, where every other grant puts one, rather than in the member
a client presents at a resource server. Any other `requested_token_type` is accepted and
answered as before — the type is a request and not an instruction, and this service
refuses nothing by default.

The consequence shows up one endpoint over: an exchanged token is issued with whatever
scope was asked for, so unless that includes `openid` it gets a 403
`insufficient_scope` at UserInfo, which says in its error description that a
token-exchange or `client_credentials` token has no end-user behind it and therefore no
profile to return. Missing scopes are the usual reason a working exchange looks broken.

### Introspection as a JWT (RFC 9701)

`POST /oauth2/introspect` (and `/{as}/oauth2/introspect`) answers RFC 7662 JSON, as it
always has, unless the request's `Accept` header **names**
`application/token-introspection+jwt` with a quality at least as high as
`application/json`'s. Then the answer is a JWT, served with that media type:

```
header  {"typ": "token-introspection+jwt", "alg": "RS256", "kid": "..."}
claims  {"iss": "<this authorization server>",
         "aud": "<the resource server's client_id>",
         "iat": 1789000000,
         "token_introspection": {"active": true, "scope": "...", "sub": "...", ...}}
```

An inactive token's claim is `{"active": false}` and nothing else. The claims carry no
`sub` and no `exp`, so the response cannot be mistaken for an access token, and it is
not recorded in `/admin/tokens` — it is a response, not a credential.

**The caller must authenticate, in every mode.** The `aud` is the client that asked, so
a JWT request with no credential, from an unknown or public client, from a client with
nothing on file to verify, or with a credential that does not verify is refused
**400 `invalid_client`** (RFC 9701 section 5). Every token-endpoint method works —
`client_secret_basic`/`post`, `client_secret_jwt`, `private_key_jwt`, `saml2_bearer`
and the two RFC 8705 certificate methods — through the same check and the same secret
rate limit. A plain JSON request needs no credential in development, as before; in
**product mode** it must authenticate too and is refused **401 `invalid_client`**
otherwise (RFC 7662 section 2.3).

**What the resource server registers decides the protection** (RFC 9701 section 6):

| Member | Attribute on the application | Default |
|---|---|---|
| `introspection_signed_response_alg` | `oauthIntrospectionSignedResponseAlg` | `RS256` — any JWS algorithm in `introspection_signing_alg_values_supported`, HMAC keyed by the client secret; never `none` |
| `introspection_encrypted_response_alg` | `oauthIntrospectionEncryptedResponseAlg` | not encrypted — RSA-OAEP, RSA-OAEP-256 or ECDH-ES(+A*KW), to a key in the client's inline `jwks` (a `jwks_uri` is never fetched) |
| `introspection_encrypted_response_enc` | `oauthIntrospectionEncryptedResponseEnc` | `A128CBC-HS256` once an `alg` is set; refused without one |

Set them in an RFC 7591 registration (or RFC 7592 update, which clears a member it
omits), on the application's page on the console, or with
`POST /admin-api/applications/set`. A value this service cannot honour is refused
where it is written (`invalid_client_metadata` at registration); one written by
`ldapmodify` makes the JWT response fail **500 `server_error`** with the reason rather
than go out with different protection. An encrypted response is a Nested JWT whose
outer header carries `cty: "JWT"` and the same `typ`. The discovery documents publish
`introspection_signing_alg_values_supported`,
`introspection_encryption_alg_values_supported` and
`introspection_encryption_enc_values_supported`, and
`oauth2.introspectionCertificateHeader` decides whether the signature names its
certificate chain (`x5u` by default).

**A resource server learns only about tokens meant for it** (section 5). Wherever the
caller authenticated — every JWT request, and JSON requests in product mode — a token
is reported active only if it is the caller's own token (`client_id`), if its `aud` is
this service's default resource indicator (`<base>/resource`, or a named authorization
server's), or if its `aud` names the caller's application by `oauthClientId`,
`oauthAudience` or `oauthPermissionBaseUri`. A refresh token is reported only to the
client it was issued to. Anything else gets `{"active": false}`, exactly as an invalid
token does. An anonymous development JSON caller is not restricted.

**A named authorization server's profile can narrow it** (`/admin/authorization-servers`):
`introspection_endpoint_auth_methods_supported` refuses a client whose declared method
is not listed, and the three `introspection_*_values_supported` lists refuse a resource
server whose registered algorithm — or the RS256 default — is not listed, both with
`invalid_client`. Removing a member turns its check off. **OAuth 2.1 mode** refuses an
introspection request carrying two client authentication methods (section 2.4), as it
does at the token endpoint. What is not done: RFC 9701 section 9's legal basis for
releasing a token's data is the deployment's to establish.

### Request objects (RFC 9101, JAR)

An authorization request may carry its parameters in a **signed JWT** — `request` by
value, or `request_uri` by reference — at `/oauth2/authorize` and every named
authorization server's. The object's parameters REPLACE the query's (section 6.3): the
query's `client_id` must be present and identical, anything else in the query is ignored,
and every other check the endpoint makes — the redirect URI, PKCE, RFC 9700 mode — runs
on what was signed.

* **Signed** with any JWS algorithm this service verifies, by a key the client registered
  (`jwks`, or an issued assertion key pair) or, for HS256/384/512, its client secret. A
  `kid` must name one of those keys; a certificate on the key has its chain and revocation
  checked. A client may register `request_object_signing_alg` to pin one.
* **Unsigned** (`alg: none`, OpenID Connect Core section 6.1) is accepted in development
  and refused in product, and refused anywhere a signed object is required:
  `oauth2.requireSignedRequestObject`, the client's `require_signed_request_object`, or a
  named authorization server publishing it.
* **Encrypted** as a Nested JWT to the realm's own RSA or EC key — published in
  `/oauth2/jwks` with `use: "enc"` — or, for the symmetric algorithms, to a key derived
  from the client secret (OpenID Connect Core section 10.2). A client may register
  `request_object_encryption_alg` / `_enc`, and is then refused a plain object.
* **`iss`, `aud`, `exp`, `nbf`** are checked where present; `typ` is refused only when it
  names another kind of JWT unless `oauth2.requireRequestObjectType` is on.
* **`request_uri` is fetched only when the client REGISTERED it** (`request_uris`,
  `require_request_uri_registration: true`), so no request can make this service dial an
  address it chose. No redirects, a timeout and a size cap; `https` only and the media type
  `application/oauth-authz-req+jwt` (or `application/jwt`) in product mode. A fragment of
  43 base64url characters must be the SHA-256 of the content (OpenID Connect Core section
  6.2), and `oauth2.requestUriCacheS` caches by URI. A pushed authorization request's URN
  goes to the PAR endpoint instead and is never fetched.

Errors are RFC 9101's own: `invalid_request_object`, `invalid_request_uri`,
`request_not_supported` and `request_uri_not_supported`, answered as a 400 on this server.
Both discovery documents carry `request_parameter_supported`,
`request_uri_parameter_supported`, `require_request_uri_registration`,
`require_signed_request_object` and the three `request_object_*_values_supported` lists,
and a named authorization server's profile narrows each of them at its endpoint. The
sign-in and consent screens say when the request was a verified request object. **Not
done**: a request object's `jti` is not remembered.

### Mutual TLS (RFC 8705)

Both halves of the RFC, in every mode, wherever the main port is TLS
(`global.https`) — the listener asks for a client certificate and never requires
one.

**Client authentication (section 2).** A client whose
`token_endpoint_auth_method` is one of the two certificate methods authenticates
with the certificate on the connection, and `client_id` is required in the
request.

| method | what authenticates the client |
|---|---|
| `tls_client_auth` — **implicit** | a TLS client certificate **this realm issued to this application**: `clientAuth`, the application's identifier as CN and `urn:sts:application:<identifier>` as subjectAltName, still listed on its record. Nothing to register — issuing it was the registration |
| `tls_client_auth` — **explicit** | a certificate whose **chain verified** against the client truststore (`/tls/trust`) carrying the **one** subject parameter the client registered: `tls_client_auth_subject_dn` (compared as a name — attribute types, OIDs, escapes, case and a multi-valued RDN's order do not matter), `tls_client_auth_san_dns`, `_san_uri` (exact), `_san_ip` (by value) or `_san_email` (domain case-insensitive) |
| `self_signed_tls_client_auth` | the certificate is the `x5c[0]` of a key in the client's registered `jwks` (section 2.2.2), or matches `oauthTlsClientCertificateThumbprint`. No chain is checked — section 6.1 |

A certificate this service issued as **somebody else's** identity — another
application's, a person's — never authenticates a client, whatever subject it
registered (section 7.4). A revoked certificate does not authenticate either.
**A client that declares a certificate method is held to it in every mode**:
without a certificate that authenticates it, `/oauth2/token` and `/oauth2/par`
answer `invalid_client` even in development mode, where client authentication is
otherwise only observed.

Issue an application its certificate from the **Mutual TLS** subsection of its
*Credentials* section on `/admin/applications`, or with
`POST /admin-api/applications/issue-tls-client-certificate` (`application`,
`password`, optionally `keyAlg`, `label`, `days`). The reply carries the only copy
of the private key — a PKCS#12, an encrypted PEM key and the PEM chain, all under
`password` — and `revoke-tls-client-certificate` revokes one of the application's
own. `pki.applicationTlsClientCertificateMax` caps the valid ones. The subject
parameters are ordinary attributes (`oauthTlsClientAuthSubjectDn`,
`oauthTlsClientAuthSanDns`, `…SanUri`, `…SanIp`, `…SanEmail`), set with the
attribute editor or through RFC 7591 registration; a second one is refused. An
application's certificate presented to 8443 or 9443 **signs nobody in**.

**Certificate-bound access tokens (section 3).** A token request on a connection
carrying a client certificate — authenticated by it or not — gets
`cnf["x5t#S256"]` on the access and refresh tokens; the protected endpoints
(UserInfo, the credential endpoints, SCIM, SSF, `/admin-api` and the embedded
debugger) refuse a bound token on a connection without that certificate with 401
`invalid_token`, and `/oauth2/introspect` reports the `cnf` (section 3.2). A
client that registers `tls_client_certificate_bound_access_tokens: true` is
refused a token without a certificate (400 `invalid_request`, section 3.4) — in
every mode, because it asked; a registration asking for it while the main port is
not TLS is refused. A **public** client's refresh token is bound to its
certificate (section 4). A client that authenticated **by certificate** refreshes
with whatever certificate it now holds — its refresh token is bound through the
client authentication (section 7.1) — so a renewed certificate does not strand the
grant, and the new tokens bind to the new certificate (section 6.3).

**Not done:** `mtls_endpoint_aliases` (section 5) is not published — the endpoints
already ask for a certificate where they are; a certificate is never read from a
header behind a TLS-terminating proxy (section 6.5, see `global.trustProxy`); and
binding at the authorization endpoint's implicit flow is out of scope by the RFC
(section 6.4). The error codes are `STS-OAUTH-0480..0488`, `STS-REG-0130..0136`,
`STS-PKI-0180..0181`, `STS-ADMIN-0720..0724`, `STS-API-0110` and `STS-DBG-0030`.

### Pushed authorization requests (RFC 9126, PAR)

A client may send the parameters of an authorization request **straight to this server**
first — `POST /oauth2/par`, and `/{id}/oauth2/par` at every named authorization server —
and get back a reference to send the browser with:

```
POST /oauth2/par                 Authorization: Basic …   (as at the token endpoint)
response_type=code&redirect_uri=…&scope=openid&state=…&code_challenge=…

201 {"request_uri":"urn:ietf:params:oauth:request_uri:<256 bits>","expires_in":60}

GET /oauth2/authorize?client_id=app1&request_uri=urn:ietf:params:oauth:request_uri:…
```

* **The client authenticates exactly as at the token endpoint** (section 2): refused in
  RFC 9700 mode, OAuth 2.1 mode and product mode, observed in development. A client
  assertion may name the issuer, the token endpoint or the PAR endpoint as its audience.
* **The push is validated as an authorization request** — by the authorization endpoint's
  own checks, plus the `resource`, `claims`, `authorization_details`, permission and
  RFC 9068 audience parsers — and refused there as JSON, before any person is involved.
  `request_uri` in a push is refused (section 2.1), and so is a repeated parameter other
  than `resource`. 405 for any method but POST, 413 past `oauth2.parMaxBodyBytes`, 429 past
  `oauth2.parRequestsPerMinute`, 503 when the realm already holds `oauth2.parMaxRequests`.
* **A `request` object may carry the parameters** (section 3), verified as RFC 9101
  requires; the authenticated client must be its `client_id` claim, and nothing else may
  sit in the form beside it. Where a signed object is required a plain push is refused.
* **A DPoP proof sent with the push binds the authorization code** to its key (RFC 9449
  section 10.1); a `dpop_jkt` naming another key is refused.
* **The `request_uri` is bound to the client and the authorization server**, lives
  `oauth2.parRequestUriLifetimeS` (60 by default, 5–600), is read again on the way back from
  the sign-in and consent screens, and is **spent when an authorization response is issued
  on it**. Only the pushed parameters are used — the query's own are ignored. An unknown,
  expired, spent, other client's or other server's `request_uri` is refused
  `invalid_request_uri` as a 400 on this server, never redirected.
* **Section 2.4**: with `oauth2.parAllowUnregisteredRedirectUris` on (off by default), a
  client that AUTHENTICATED at the push may name a redirect URI it never registered. A public
  client never may, and the setting is asked again at the authorization endpoint.
* **PAR can be required** — `oauth2.requirePushedAuthorizationRequests` for a realm, the
  client's own `require_pushed_authorization_requests` (RFC 7591 registration, the console
  and `/admin-api`), or a named authorization server publishing it — and a request that was
  not pushed is then refused `invalid_request`. A client's policy is checked again when its
  `request_uri` is used, so a plain push is refused once a signed object becomes required.

Both discovery documents carry `pushed_authorization_request_endpoint` (removed with
`oauth2.pushedAuthorizationRequests` off, when the endpoint answers 404 — a `request_uri`
already issued still works) and `require_pushed_authorization_requests`.
`/admin/oauth2/monitor` counts pushes, reads, spends, expiries and refusals per client and
lists the request_uris still held.

### Step-up authentication (RFC 9470)

A resource server that finds the authentication behind a token too weak or too old says
so, and the client asks for a token that is not:

```
GET /oauth2/step-up/resource/api1          Authorization: Bearer <acr "1">
401 WWW-Authenticate: Bearer error="insufficient_user_authentication",
      error_description="…", acr_values="mfa", max_age="600"

GET /oauth2/authorize?client_id=app1&…&acr_values=mfa&max_age=600
```

* **The authorization endpoint honours `acr_values` and `max_age` in every mode**, with or
  without `openid`. A session that meets them is answered from; one that does not is sent
  to sign in again — once — with the second-factor step forced where every value the
  screen can produce needs two factors; a requirement still unmet on the way back is
  refused **`unmet_authentication_requirements`** (section 5), and `prompt=none` answers
  `login_required`. An elapsed `max_age` re-authenticates too, which OpenID Connect Core
  requires anyway.
* **The levels are ordered, `0` < `1` < `mfa`**, and are published as
  `acr_values_supported` in both discovery documents. A stronger authentication meets a
  weaker request, and **the tokens carry the most preferred requested value that was
  met** — an mfa session asked for `acr_values=1` is issued `acr: "1"`. `hwk`, `phr` and
  `phrh` are still accepted, as a password with a security key; any other value is met only
  by a sign-in reporting exactly that `acr` (a federation partner's, say).
* **`acr` and `auth_time` ride in the access token** (section 6.1, as they already did for
  RFC 9068) **and in introspection** (section 6.2), and a refresh keeps them.
* **The challenge (section 3)** is sent from two places. This service's own resource
  server — UserInfo, the OpenID4VCI credential endpoints, SCIM and Shared Signals —
  requires what `oauth2.stepUpAcrValues` and `oauth2.stepUpMaxAgeS` say (nothing, by
  default). A registered API declares its own requirement on its application entry,
  `oauthStepUpAcrValues` and `oauthStepUpMaxAge`, and
  **`/oauth2/step-up/resource/{application}`** answers for it: the token must verify, be
  this service's `at+jwt` and name the application in its `aud`, and then either the
  challenge or a 200 describing the authentication it met. A token with no `auth_time`
  does not meet a `max_age`.

`/admin/oauth2/monitor` counts it per client: requirements met by the session or by a
sign-in, people sent to sign in again, both refusals, and resource-server challenges.

### Rich authorization requests (RFC 9396)

A client may say what it wants authorized as a JSON array rather than as scope strings —
`authorization_details` — at `/oauth2/authorize`, at `/oauth2/token`, at `/oauth2/par`, and
inside a request object:

```json
[{"type": "payment_initiation",
  "locations": ["https://pay.bank.example/"],
  "actions": ["initiate"],
  "instructedAmount": {"currency": "EUR", "amount": "12.50"}}]
```

**A type is declared by the resource that understands it.** An application acting as a
resource server lists its types in `oauthAuthorizationDetailsType`, one per value: a bare
name, or a JSON definition —

```json
{"type": "payment_initiation", "description": "Initiate a payment",
 "locations": ["https://pay.bank.example/"],
 "schema": {"type": "object", "required": ["instructedAmount"]}}
```

— written on the console, through `/admin-api`, or proposed by the RFC 9728 import from a
resource's `authorization_details_types_supported`. `authorization_details_types_supported`
in both discovery documents is OpenID4VCI's built-in `openid_credential` plus every declared
type in the realm. A named authorization server may publish a narrower list, and a client
may register `authorization_details_types` (RFC 9396 section 10) to limit itself.

**Refused in every mode, with `invalid_authorization_details`:** unreadable JSON, an entry
with no `type`, a malformed common field (`locations`, `actions`, `datatypes`, `identifier`,
`privileges`), a type nobody declares (section 5), a type outside the client's or the
authorization server's list, a detail failing its type's schema, and a location the
resource does not answer to.

**The access token is addressed to the type's resource**: the detail's `locations`, or the
resource's permission base URI, `oauthAudience` or client_id. One token is for one resource,
so details of two resources, or a `resource` or scope naming a different API beside them,
are refused (`invalid_authorization_details`, `invalid_target`, `invalid_scope`).

**The consent screen draws every detail, member by member, and asks every time.** A detail
is about one transaction, so Allow is not remembered the way a scope is: it holds for
exactly that array, that person and that client, once. `prompt=none` answers
`consent_required`. `openid_credential` follows the scope rules it always did.

**What was granted travels with the token**: the access token's `authorization_details`
claim, the token response, and `/oauth2/introspect`. At the token endpoint a client may send
`authorization_details` again to ask for a **subset** (section 6) — fewer actions or
locations, the same values otherwise — on an authorization code or a refresh token. The
refresh token keeps the whole grant. A direct grant (`client_credentials`, `password`, the
assertion grants, token exchange) is granted the details it asks for.
`oauth2.authorizationDetailsMaxEntries` caps the array. **Not done**: section 7's enrichment
is added only for `openid_credential`.

### UserInfo is the one endpoint that refuses a token it did not issue

`GET`/`POST /oauth2/userinfo` (OIDC Core 5.3) is a protected resource: present the
access token from an OIDC flow and get back the claims about the person it was issued
for. Two things about it are deliberate and are the opposite of how the rest of this
service behaves.

**The response can be SIGNED, ENCRYPTED, or both**, and what a client gets is decided
entirely by what it registered at `/oauth2/register` — so the RFC 7591 support and
section 5.3.2 meet where they should. `userinfo_signed_response_alg` produces a JWS
(any of RS256/384/512 and PS256/384/512 against the RSA key, ES256/384/512, **ES256K**
and EdDSA against the P-256, P-384, P-521, secp256k1 and Ed25519 keys generated beside
it, or HS256/384/512 against that client's own `client_secret`, which is why the
symmetric ones need no published key — **fourteen** algorithms, which is every signing
algorithm the JWS registry defines, each with something in the JWKS to verify it except
the symmetric three, which need nothing); `userinfo_encrypted_response_alg` produces a JWE (RSA-OAEP, RSA-OAEP-256,
ECDH-ES and its three key-wrapping variants, over any of the six RFC 7518 content
encryption algorithms — the three AES-GCM and the three AES-CBC-HMAC); registering
both produces a **Nested JWT**, signed and THEN encrypted, with `cty: "JWT"` on the
outer header. All three lists are advertised in the metadata as
`userinfo_signing_alg_values_supported`, `userinfo_encryption_alg_values_supported`
and `userinfo_encryption_enc_values_supported`.

Four details are worth knowing. **`enc` defaults to A128CBC-HS256** when a client
registers an encryption `alg` and no `enc`, because section 2 of the registration
specification says so — which is why this service implements the CBC-HMAC family at
all, since that default is the commonest encrypted response there is. **The recipient
key is read from an INLINE `jwks` member only**, not from a `jwks_uri`: fetching a URL
a client chose, at the moment this service answers that client's request, is a
capability a mock should not have. **Every signing algorithm has a KEY, AND AN IMPLEMENTATION**: this service generates an
RSA key, P-256, P-384, P-521, secp256k1 and Ed25519 at startup and publishes all six in
`/oauth2/jwks` (the RSA one first, because tokens signed by default are RS256 and more
than one test reads `keys[0]`). ES\*, ES256K and EdDSA were all absent until 2026-08-28, for two
reasons that were each the wrong kind: no EC key was being generated, and
`jsonwebtoken` — the library that signs everything else here — has neither EdDSA nor
ES256K. Both are now signed directly on node's OpenSSL in `stsCrypto.signJws()`, which
for ES256K means converting the DER SEQUENCE OpenSSL returns into the **R||S**
concatenation RFC 7518 section 3.4 requires; hand a verifier the DER and it reports a
bad signature over a perfectly good one. A library's gaps are not this service's. **Twenty-five signing algorithms, and eleven of them are post-quantum.** Beside the
RSA, EC and Edwards keys sit ML-DSA at three parameter sets (FIPS 204, RFC 9964),
SLH-DSA at two (FIPS 205), and the six **composite** ML-DSA + traditional algorithms of
draft-ietf-jose-pq-composite-sigs — published as `kty: "AKP"` JWKs in the same JWKS.
Three things about them are worth knowing.

**They are written out in `common/pq_jose.js` rather than vendored from the debugger,
and that is the whole point of them.** This service exists to be the far end of the
debugger's JOSE code, and the value of that is INDEPENDENCE: a misunderstanding both
sides share is one neither can see. So the primitive is `@noble/post-quantum` — there is
no second implementation of ML-DSA to be had — while everything around it is written
here from the specifications, and the traditional half of every composite runs on
**node's OpenSSL** rather than on the curve library the debugger uses. The framing is
what has been wrong every time.

**They are generated LAZILY.** All eleven cost about 1.9 seconds, nearly all of it one
SLH-DSA-SHAKE keygen — twelve times the RSA key this service already makes, per realm.
So the first thing that needs one pays for it and everything else pays nothing; in
practice that is the first JWKS fetch on a realm, which is slow once and free after.

**Ed448 needed a setting.** RFC 8037 registers one `alg` for both Edwards curves and
puts the curve in the key, so a client registering `EdDSA` has no way to ask for Ed448.
`oauth2.eddsaCurve` is that way. Both keys are published whatever it says, with
different kids, so a verifier follows the kid and never reads the setting — a JWKS that
changed shape with a setting would strand every client holding a cached copy.

**These algorithms are not the UserInfo endpoint's.** The keys and the table behind
them are `common/crypto.js`'s, and every JOSE surface in this service reads them: ID
Tokens honour a registered `id_token_signed_response_alg` across the same fourteen, and
DPoP proofs, OID4VCI proofs of possession, Key Binding JWTs and client assertions accept
the eleven asymmetric ones. Each of those kept its own list before — and `dpop.js` its
own nine-row table and `crypto.verify()` call, while the OID4VCI proof check hardcoded
SHA-256, so ES384 and ES512 would have been checked against the WRONG DIGEST and
reported as bad signatures. There is now one table, one signer, one signature verifier,
one claim-checking verifier and one key-selection function, and every advertised
metadata list is DERIVED from them rather than written out — which is how
`proof_signing_alg_values_supported` came to advertise eleven while the code accepted
two. **A signed
response gains `iss` and `aud`**, which is the entire reason to want one — without them a signed profile issued for one client
is one any other client would also believe. And **an algorithm this service cannot
perform is REFUSED rather than downgraded to JSON**: a client that registered
protection and got an unprotected 200 has no way to notice, and would go on believing
it had verified something.

**It verifies the token.** The Credential, Deferred Credential and Notification
endpoints accept a token they cannot verify, because OID4VCI lets the authorization
server be somebody else and refusing a foreign token would break the flow this mock
exists to exercise. UserInfo is defined the other way round — it answers *who did YOU
authenticate* — and about the subject of a signature it cannot check this server knows
nothing whatever, so a made-up profile would be teaching the client reading its output
the wrong lesson. It is also what gives `cnf.jkt` meaning here, since a DPoP binding is
only real on a token whose signature was checked first. Four things are checked and each
gets its own answer, because "invalid_token" alone sends people looking in the wrong
place: the signature and expiry (401, saying which), the `typ` — every token here is an
RS256 JWT from one key, so nothing else tells a refresh token or an id_token apart from
an access token — revocation, since a `/oauth2/revoke` that only some endpoints honoured
would be decorative, and the `openid` scope (403 `insufficient_scope`, which is what a
`client_credentials` token gets: no end-user, no profile).

**A scope actually changes the answer.** Section 5.4 makes `profile` and `email`
requests for named claim sets *at this endpoint*, so `openid` alone returns nothing but
`sub`. The id_token still carries everything whatever was asked for — the same section
permits it, since the claims go in the id_token when there is no access token to fetch
them with, and it is the only behaviour that can serve the implicit flow this server
also offers. A client that registered `userinfo_signed_response_alg: "RS256"` (RFC 7591
registration is offered here, so the two features meet where they should) gets
`application/jwt` with `iss` and `aud` added instead of JSON; an algorithm this key
cannot produce is refused rather than silently downgraded, because a client verifying a
signature that is not there fails in the least informative way possible.

**Four layers decide what comes back, and a client controls one of them.** Since 2026-08-26 the response is more than `sub` plus whatever the scope asked for, and the order is the whole policy — later wins:

1. **the `userinfo` custom claim set**, configured on */admin/userinfo-claims*: typed claims, ticked LDAP attribute types read off `ou=users`, and the groups claim. It is what every client of this service is shown, and it is why that set is configured separately from the ID Token's rather than being one list under two names — **a UserInfo response is built on every call**, so a claim added there reaches a client that signed in an hour ago and has done nothing since, where a claim added to the ID Token set is invisible until the next sign-in. That page is the one claims page here with no "nothing already issued changes" warning on it, and that is the point of it.
2. **section 5.4's scope-driven claims** — `profile` and `email`, described above.
3. **section 5.5's individually requested claims.** `claims_parameter_supported` is `true` where it was `false`: a client may send `claims={"userinfo":{"birthdate":null,"address":null}}` at the authorization endpoint, and this service parses it, refuses a malformed one **there** with `invalid_request` (the last point at which the client is still being talked to), carries it on the authorization code and **inside the access token** as the `claims` claim — the same decision `authorization_details` records, and for the same reason: this endpoint sees the token and nothing else — and answers each name by resolving it against the LDAP attribute catalogue. A nested claim may be asked for by its flat name (`address.locality`) or by its top-level name alone (`address`), which returns the whole Address Claim of Core 5.1.1; a language tag is part of the name (Core 5.2), so `family_name#ja-Kana-JP` comes back under exactly that name with the one value this service holds. The refresh grant carries the request forward, so a renewal cannot narrow the grant any more than it can widen it.
4. **`sub`**, assigned last and unconditionally, because Core 5.3.2 says a client MUST check it against the ID Token's.

**Layer 3 beating layer 2 is the one choice that is not obvious**, so it is stated rather than left to be discovered: a scope asks for a *category* and a claims request names a *claim*, and answering `{"email":null}` with the invented `alice@sts.example` while the entry holds a real `mail` would defeat the only reason the feature is worth having. Nothing in layer 3 can reach a structural claim, by construction rather than by a guard — every name it resolves comes from the attribute catalogue or from the six claims `userFor()` invents.

**`essential`, `value` and `values` are carried and not enforced**, which is the honest reading of section 5.5.1 rather than a shortfall. That section says a server MUST NOT return an error because a requested claim is unavailable, so an essential claim this service cannot produce is simply absent and is logged at warn level. `value` and `values` could be satisfied by echoing the asked-for value back, and deliberately are not: everything this service says about a person comes from the directory or from the invented persona, and a UserInfo response that agreed with whatever a client asked it to assert would be the one surface here that could not be used to test anything. The mismatch is reported in the log and in the response's artifact.

**Non-spec, and labelled: the endpoint also takes a claims request on the request itself.** Section 5.3.1 defines no request parameters at all — an access token and nothing else — and `?claims={json}` and a repeated `?claim=name` are accepted anyway, on `GET` and on a form-encoded `POST`. The reason is what this service is for: exercising section 5.5 through the specified route means running a whole authorization flow per variation, and somebody comparing what this endpoint does with `address`, `address.locality` and a name nothing can produce wants to send three requests. It is a **union** with what the access token carries and can never take a claim away from it — what the client was authorized for is what the token says — and a malformed one is refused `invalid_request` rather than ignored, because ignoring a debugging parameter that was typed wrong produces exactly the response a parameter that was never sent produces.

`claims_supported` was deliberately **not** extended to cover any of it. That member lists what the protocol itself puts in an ID Token; it cannot honestly list what */admin/userinfo-claims* has been configured to add nor the whole catalogue a claims request can reach, because the discovery document is fetched and cached by clients and both of those change at runtime from a console page. `GET /admin-api/userinfo-claims` is the live answer and names every claim a request may ask for.

Writing it turned up a trap worth repeating: the RFC 6750 `WWW-Authenticate` challenge
carries the same `error_description` as the JSON body, an HTTP field value is ASCII, and
node's `setHeader` *throws* on anything else. The first description containing an em dash
— they all do here, the comments are prose — turned a 401 into a 500, which is the worst
place in the service for one, since the exception replaces the very message that was
explaining what went wrong. The header copy is now folded to ASCII; the body keeps the
real text.

### The authentication service

The sign-in screen is its own endpoint, `/authn/login`, and not part of any
protocol here. `GET /oauth2/authorize` used to render it in the body of a 200 at
the authorization endpoint's own URL; it now redirects to the service and is
entered a second time when the person comes back:

```
GET /oauth2/authorize?response_type=code&client_id=…      no session
  302 -> /authn/login?authn=8mQ2…                         the screen
  POST /authn/login   username=alice                      Set-Cookie: sts_session=…
  302 -> /oauth2/authorize?response_type=code&client_id=… the ORIGINAL request
  302 -> http://localhost:3000/callback?code=…            answered per spec
```

**It is not always the screen.** The same redirect goes to
`/federation/login/{id}` when the application's entry names one usable federation
relationship, and to **`/authn/select-idp`** when it names several — a page with
one button per partner and no password field. The calling protocol cannot tell
the three apart and must not: what it asked for is "get this person
authenticated and bring them back", and which identity provider does it, or
whether the person was asked which, is not its business. See *Home realm
discovery* under *Federation*.

The return URL is the request that was interrupted, whole, minus `prompt` — which
has been honoured by then and would otherwise prompt for ever. Everything else
goes back untouched, because the second pass is where the PKCE challenge, the
nonce, `authorization_details` and the rest are read. That is also why the
authorization endpoint keeps no state across the two entries: it is the same
query string both times.

Three properties are worth knowing before building on it:

* **It knows nothing about the protocol that sent anybody there.** The rows the
  screen shows about the request it interrupted — client, scope, redirect URI,
  the Credential Offer an `issuer_state` came from — are supplied by the caller,
  because only the caller knows what its own parameters mean.
* **Cancelling comes back too.** The browser returns to the caller with
  `authn_error=access_denied`, and the caller turns that into its own protocol's
  refusal — for OAuth, a redirect to the client's `redirect_uri`, or in
  `response_mode=form_post` a self-submitting form, which is not a redirect at
  all and is exactly why this service does not try to answer for it.
* **The return URL must be a path on this service**, and is checked to be one. An
  authentication service that will redirect a browser anywhere after signing
  somebody in is a credential phishing tool with a login screen in front of it.

The session cookie it establishes is the same one WS-Federation signs people into,
so single sign-on across the two protocols is unchanged. WS-Federation keeps its
own screen for now: section 13.2.1 lets its sign-in request arrive as a cross-site
form POST, `SameSite=Lax` keeps the cookie off that, and a redirect chain would
lose the request.

### Signing out of everything — `/logout`

Every family here that can sign somebody **in** has a sign-out of its own, and
each one signs them out of itself: `/oauth2/logout` is OpenID Connect's
RP-Initiated Logout, `/wsfed?wa=wsignout1.0` is WS-Federation 1.2 section
13.2.4, `/saml2/slo` is SAML 2.0 Single Logout. None of them is the question a
person actually arrives with, which is *what am I still signed into, and how do
I stop being signed into it*.

That question is protocol-independent and so is the answer. `GET /logout` lists
**everything this service is still holding for one identity, across every
family**, with a checkbox against each:

```
GET /logout                       no session -> /authn/login and back
                                  session    -> the list
POST /logout                      ends what was ticked
POST /logout   (nothing ticked)   ends EVERYTHING — the default, and the point
GET /logout?format=json           the same list, for a test
```

What it finds, and what it does about it:

| Family | What is listed | What ending it does |
|---|---|---|
| Browser sign-on session | every session held for that person | drops it through the one function `/oauth2/logout`, `wsignout1.0` and `/saml2/slo` all end a session with — so the RFC 9700 refresh revocation and the audit row happen once |
| OIDC relying parties | every client issued an authorization response on that session | loads its `frontchannel_logout_uri` in a hidden iframe, with `iss` and `sid` where it asked for them |
| WS-Federation realms | every realm signed into | sends `wa=wsignoutcleanup1.0` as a one-pixel image, with the URL printed beside it |
| SAML 2.0 service providers | every service provider signed into | builds the signed `LogoutRequest` and offers it as a link |
| Tokens | every access, refresh and ID token still revocable | adds the `jti` to the one revocation set `/oauth2/revoke` and the console write to |
| Authorization codes | codes issued and not yet redeemed | discards them, so no more tokens come from that sign-on |
| Pre-authorized codes | Credential Offer codes minted for that person | the same |
| Directory connections | every LDAP connection bound as them, on 389 and 636 | closes the socket — RFC 4511 section 4.2 makes the bind the state of a **connection**, so that is the only sign-out LDAP has |
| Kerberos tickets | the principal, and its sign-out instant | stamps the instant; a `TGS-REQ` presenting a ticket authenticated before it is refused **KDC_ERR_TGT_REVOKED (20)** |
| Issued and beyond recall | assertions, service tickets, credentials, SVIDs | **nothing** — and they are listed anyway |

**That last row is the point of the page rather than an admission at the bottom
of it.** A SAML assertion in a service provider's hands, a Kerberos service
ticket in a cache and an X509-SVID already minted cannot be ended by this
service or by a real one, and the reason is the same in all three cases:
*nothing consults the issuer when they are presented*. A relying party checks a
signature and some `Conditions` and asks nobody; a Kerberos service decrypts a
ticket with its own key; an SVID verifies against a bundle. Hiding those rows
would make a global logout look complete when it is not, which is the single
most misleading thing this endpoint could do — so each carries a dash and a
sentence saying why.

Two mechanisms did not exist before this endpoint did, and both are worth
knowing because they are the honest analogue rather than a pretence:

**Kerberos, and it is an invention rather than a specified behaviour — which is
worth knowing before relying on it.** Kerberos defines **no logout message, no
session and no revocation of any kind**: no CRL, no status query, and no list of
issued tickets anywhere, because a KDC deliberately keeps no state about what it
has issued (that is what lets one be replicated read-only). A ticket is valid
because it decrypts and its `endtime` has not passed, and a service accepts one
using its own key without ever contacting the KDC. **Short lifetimes are the
whole revocation model.** `KDC_ERR_TGT_REVOKED` (20) is a *registered* code whose
text says what is meant (RFC 4120 §7.5.9), but the specification defines no
mechanism that emits it.

What a KDC *does* see is the next `TGS-REQ` — the one moment it is back in the
loop, and the same lever that makes disabling an Active Directory account bite
within the service-ticket lifetime rather than the TGT's. So signing out records
an instant on the principal, and a request presenting a ticket whose `authtime`
is earlier is refused. It is checked on `authtime` and not on the issue time because a
renewed ticket deliberately preserves `authtime`, and checking anything else
would let a renewal launder a signed-out ticket back into a live one. **It does
not reach a service ticket already in a cache** — accepting one never contacts
the KDC — and a fresh `AS-REQ` succeeds and clears the instant, because signing
out is not being locked out. `logout.kerberosSignOut` turns it off.

**LDAP.** The connection is the session, so the sign-out is the socket closing.
What the client sees is its connection ending mid-conversation, which is what a
directory revoking a session looks like from the other end. An *Unsolicited
Notice of Disconnection* (RFC 4511 section 4.4.1) would be the polite form and
node-ldapjs has no way to send one — it is a submodule this repository uses
unmodified. `logout.ldapDisconnect` turns it off.

**No console role is needed, and that is not an oversight**: signing yourself out
must not require a role that signing in did not. With no session the browser goes
to `/authn/login` and comes back — signing out may mean signing in first, because
this service has no other way to know who is asking, and the session that creates
is listed with everything else. `?username=` names somebody else and grants
nothing that was not already true, since no password is checked at any screen
here; `logout.anyUser` turns that off for a deployment that wants the tighter
story.

**Two more doors onto the same two functions.** `/admin/logout` is the operator's
view — the same lists for a person *named*, filtered and paged, behind the
console's two roles, and with the two NON-SPEC undos this page has not (restoring
a revoked token, clearing a Kerberos sign-out instant). `GET|POST
/admin-api/logout` is the same again for a test, with four operations. All three
call one pair of functions in `logout/logout.js`, which is what stops them coming
to disagree about what a live session is.

### OpenID Connect Front-Channel Logout 1.0

The other half of a sign-out. Ending a session here drops a cookie and revokes
what this service issued; every relying party the person signed into still
believes they are signed in. Front-Channel Logout is how a provider says
otherwise, and this service implements the provider's side of it:

```
POST /oauth2/register
  { "frontchannel_logout_uri": "https://rp.example/logout",
    "frontchannel_logout_session_required": true }

GET /.well-known/openid-configuration
  "frontchannel_logout_supported": true
  "frontchannel_logout_session_required": true

id_token: { …, "sid": "EO-iqvyoBaXVAwJMzzHQuEcBlw4dcI36" }

any sign-out ->  <iframe src="https://rp.example/logout?iss=…&sid=EO-iqvy…">
```

Four things about it:

* **`sid` reverses a decision this project documented at length.** The token
  registry used to say, in as many words, that no token here carries a session
  identifier and that inventing one to make a console page easier would change
  what every client receives. That reasoning is kept and is exactly why this is
  switchable: a claim is added because a *specification* needs it, and section 3
  of Front-Channel Logout is that specification. `oauth2.frontchannelLogout` off
  restores the tokens and the metadata this service issued before the feature
  existed, byte for byte.
* **`iss` and `sid` go only to a client that registered
  `frontchannel_logout_session_required`.** Section 2 says they are otherwise
  omitted, and an RP that did not ask may well be validating the query string it
  gets. RFC 7591 section 2 makes an omitted boolean false rather than unknown.
* **Every URL is printed as a link beside its iframe.** Section 5 says the
  provider cannot know whether a notification succeeded — so a dead relying
  party, a certificate the browser will not accept and a URI somebody mistyped
  all look exactly like success. The link is the only thing that turns "nothing
  happened" into something a person can click and see. It is the same decision
  `wsignout1.0`'s cleanup pings already made.
* **It can turn a redirect into a page.** A 302 to `post_logout_redirect_uri`
  abandons the document before any iframe loads, so where there is a fan-out to
  perform `/oauth2/logout` renders it and offers the return as a link instead.
  **Where there is nothing to notify, nothing changes** — which is every
  deployment that has not registered a logout URI.

**Back-channel logout is a different specification and is not implemented.** The
metadata says so rather than claiming it because front-channel arrived.

### WebAuthn: a second factor, or the only one

The login screen carries **two** security-key boxes, because a key is two different
things here and the difference is the whole of what the tokens afterwards claim. Ticked
beside a password it is a **second factor**; ticked on its own it is the **primary
credential** and no password is read at all. An authorization request whose `acr_values`
can only be met by two factors (`mfa`, `hwk`, `phr` or `phrh`, with no weaker value beside
them) ticks the first and disables both opt-outs — and, since RFC 9470, a session that
does not meet it is sent through this screen again rather than answered — that
parameter is how a relying party *demands* a second factor, and a mock that ignored it
would let a client's step-up request appear to work while proving nothing. The
passwordless box is refused outright under that demand, and refused **server-side**:
`disabled` is a property of a browser and not of an HTTP request, and one factor does
not answer a request for two however phishing-resistant that factor is.

The step itself is `POST /authn/webauthn` in both roles: first use for a username
**enrols** a credential (section 7.1), every later sign-in **asserts** with it (section
7.2), against a challenge minted server-side and held for five minutes with the
interrupted request, which the person is returned to exactly as the password-only path
returns them. The ceremony the two roles perform is the same bytes — what differs is
what the session then says, and it is decided in one place from one boolean carried on
the pending record. Which role was chosen is not re-read from the ceremony's own POST,
because that POST is the browser's result and nothing in it says what somebody chose a
screen ago.

**This is a relying party, and the ceremony is genuinely verified**: the challenge, the
origin, the RP ID hash, the user-presence and user-verification flags, a signature
counter that must strictly advance — with the one exemption the specification asks for,
an authenticator that reports zero and always will — and the signature over
`authenticatorData ‖ SHA-256(clientDataJSON)` for ES256, RS256 and EdDSA keys. What is
*not* verified is the attestation statement — `packed`, `none` and `fido-u2f` are
decoded and no metadata service is consulted — and that line is where the "mock" in this
service's name has to stop. Everything else here is a shape without enforcement on
purpose; attesting to an authenticator's provenance is the one thing that cannot be
faked usefully, because a client that believed this service's word on it would have
learned something false about a real device.

Three details are the ones that cost time. **`webauthn.js` shares no code with the
parent project's own decoder** — not the CBOR reader, not the COSE mapping, not the
signature check — which is what makes `tests/webauthn_cross_impl.js` over there a real
result rather than an implementation agreeing with itself; the independence is not
cosmetic, since this side verifies ECDSA through node's `crypto.verify` in its native
**DER** form while the browser has to convert DER to raw `r‖s` because Web Crypto will
not. **The ceremony script is a separate resource** (`/authn/webauthn.js`) rather than
an inline `<script>`, because `app.js` sets `script-src 'none'` on every response and
that one page relaxes it to `'self'`: an inline script there simply would not run, with
the button doing nothing and no error anywhere. And **the RP ID is this origin's host
and is not configurable** — WebAuthn binds a ceremony to the calling origin, and that is
the whole of its phishing resistance.

What comes out the other side is the point: a key **after a password** records
`amr: ["pwd","hwk"]` and `acr: "mfa"` on the session, a key **instead of one** records
`amr: ["hwk"]` and `acr: "1"`, and a password alone records `amr: ["pwd"]` and
`acr: "1"`. Those (RFC 8176) go into the id_token whenever the session recorded them —
so their *absence* means something too, which is why they are not emitted
unconditionally.

**`acr: "1"` for the passwordless sign-in is the conservative reading and it is
deliberate.** This ceremony asks for user verification as `preferred` rather than
`required`, so the key proves possession and nothing about the person holding it;
calling that `mfa` because it is phishing-resistant would be exactly the fake this
service refuses in WS-Federation's `wauth`, one screen away. WS-Federation reads the
same session and now distinguishes the two demands: `wauth` asking for a **hardware
token** is answered by a key in either role, `wauth` asking for **multi-factor** is
answered only by a session that really had two factors. That test used to be "does the
session carry `hwk`", which was right while every session carrying a key had been
through a password step first and became wrong the moment one had not.

**And both roles reach the directory, differently.** A passwordless sign-in is an
authentication in its own right, so it goes through `recordAuthentication()` like every
other accepted credential and the embedded LDAP directory grows an entry for the person
exactly as a password sign-in makes one. A second factor authenticates nobody new — the
person is the one the password step named — so it creates nothing and writes a **flag**
on the entry that already exists. See the directory's own section for the three
attributes that carries.


### TOTP: the other second factor, and the one that needs no browser

RFC 6238, over RFC 4226. A WebAuthn ceremony is bound to an origin and runs in a
browser; a six-digit code is typed into a form — so this one works from a curl
script, from a test job, and from a phone standing beside a machine that has no
authenticator attached to it.

**A person enrols it themselves**, on `/portal/mfa` or while spending an
activation link, and the page hands them the secret two ways: a **QR code this
server drew** — an SVG arriving as a `data:` URI, because every page of the
portal is `script-src 'none'` and a QR library running in the browser was never
available — and the same base32 in groups of four, with the algorithm, digits
and period written out. The typed form is not a fallback nobody sees: scanning
is impossible when the phone IS the browser showing the page, when the desktop
authenticator has no camera, and when a `localhost` QR code photographed off a
screen points at a host the phone cannot reach. The last is the common case for
a mock. Any app that implements the specification works — Google Authenticator,
Microsoft Authenticator, Authy, 1Password, Bitwarden, Aegis, FreeOTP, KeePassXC
— and nothing here is tied to one.

**Enrolment is two steps and the first writes nothing.** Pressing *Set up* mints
a secret and holds it in memory; the attribute is written only when a code
proves the app really has it. An unconfirmed secret on somebody's entry would be
a second factor they cannot produce — open the page, be interrupted, come back
tomorrow, and a one-step enrolment has locked somebody out of their own account
with a form they abandoned.

**Once enrolled, a password alone stops working**, which is what a person means
by having turned this on: the sign-in screen asks for a code without anybody
ticking anything, and a checkbox cannot opt out of a factor the account is
configured for. The session that comes out records `amr ["pwd","otp"]` and `acr
"mfa"` — `otp` is RFC 8176's registered value and its registry entry names RFC
4226 and RFC 6238 by number — and `acr "mfa"` is honest here in a way it is not
for a passwordless key: two factors really were presented.

**The code is verified for real, in every mode.** That is the surprising part of
a service that accepts any password, any LDAP bind and any UsernameToken, and it
is the same argument SPNEGO makes: a permissive Kerberos acceptor is a broken
acceptor and a permissive one-time password verifier is a broken verifier —
there is nothing left of the specification once the comparison goes, and nothing
for a client author to test an authenticator integration against. What stays
permissive is everything around it: the password in front of the code is not
checked and any name may enrol. All three digests are implemented, the step and
digit count are settable, the skew window is symmetric and defaults to RFC
6238 section 5.2's recommended one step either side — and **section 5.2's
accept-once rule is enforced** against the step last accepted, so the very code
that confirmed an enrolment cannot also sign anybody in, and signing in twice
inside one window asks for the next code rather than saying the first was wrong.

**It can never be a first factor.** A WebAuthn credential can be the whole
account because the authenticator keeps a private key this service never sees; a
TOTP secret proves possession of something **this service also holds**, which is
fine for proving somebody still has the app and is not a thing to hang an
account on. There is no `primary` reading of it and no setting that adds one.

**And there is no self-service reset**, deliberately: a second factor anybody
can remove is no second factor. The shared secret lives on a device this service
cannot reach, so an operator clearing the enrolment on that person's row under
`/admin/users` — or `POST
/admin-api/mfa/clear-totp` — is the only way back for a lost phone. Clearing
drops an account to one factor and never to none.

The secret is stored where the password is, on the person's own entry as
`stsTotpCredential`, and it is **the one attribute in this directory that can
be read back and used** — verifying a code means computing it, so it cannot be
hashed the way `userPassword` is. In product mode it is sealed under the same
key-encryption key that protects the signing keys, so a directory dump shows
ciphertext; in development it is the base32, because that mode's key is
generated per run and sealing would mean an authenticator that silently stopped
working at the next restart.

### SAML 2.0 Web Browser SSO — the profile this file documented the absence of

For years the note near the top of this file said there was no SAML 2.0 Web SSO
profile here: no `SingleSignOnService`, no `AuthnRequest`, no `Response`. There
is one now, at `/saml2`, and it is a full identity provider rather than a
demonstration.

| Endpoint | What it is |
|---|---|
| `GET\|POST /saml2/sso[/{sp}]` | the Single Sign-On service. **GET is the HTTP Redirect binding** (bindings §3.4 — DEFLATE, base64, and the detached query-string signature of §3.4.4.1) and **POST is the HTTP POST binding** (§3.5). Which binding the *Response* comes back on is the AuthnRequest's own `ProtocolBinding` |
| `POST /saml2/ars[/{sp}]` | the **Artifact Resolution Service**, SOAP 1.1 over HTTP (§3.2.3). A back channel: the browser never touches it |
| `GET\|POST /saml2/slo[/{sp}]` | **Single Logout** (profiles §4.4), both directions |
| `GET /saml2/metadata[/{sp}]` | the signed `IDPSSODescriptor` — **one per service provider** |
| `GET\|POST /saml2/sp` | a **mock service provider**. Non-spec, the default assertion consumer service, and where a response is verified check by check |
| `GET /saml2` | what all of that is, for somebody who followed the link |

**The metadata is unique per service provider, and it is minted for anything
asked for.** `/saml2/metadata/{sp}` publishes an identity provider entityID of
its own — `urn:sts:idp:{slug}` — with SSO, SLO and artifact endpoints under
that same segment. That is what Okta and Ping give each application, and it means
two service providers integrated here are configured from two documents that
share nothing but a signing certificate. **It 404s for nothing**: an entityID
nobody has registered is registered *by the ask*, so a service provider can be
pointed at this service before anything at all has been provisioned. The segment
is the percent-encoded entityID, or a slug (`app-` and twelve hex characters)
where the entityID is not safe in a URL path.
`saml2.perApplicationEntityId` turns the separate entityID off, for a service
provider library that keys its trust store off the entityID and is surprised to
find a new one per application; the *endpoints* stay per-application either way.

**It has no sign-in screen of its own, and that is the one design decision here
worth reading twice.** WS-Federation below has one because its sign-in request
can arrive as a cross-site form POST, which `SameSite=Lax` keeps the session
cookie off — so that profile cannot see the session it would need in order to
skip the screen. The HTTP POST binding has exactly the same problem, and the
answer here is different: **the request is held and the browser is 303'd to a GET
on the same endpoint**, which is a top-level GET navigation and therefore *does*
carry a Lax cookie. Three things follow that WS-Federation does not get — single
sign-on with OAuth 2.0 and WS-Federation in one session, a WebAuthn ceremony
available at the screen (`/authn/login`, the same one the authorization endpoint
uses), and one fewer place asking for a username.

**Where the Response goes depends on the realm's mode (2026-09-12).** In
development the `AssertionConsumerServiceURL` the request names is used as it
stands, registered or not, and a request naming none goes to the registered
`samlAssertionConsumerService` or to the mock service provider. **In product mode
it must be one of the `samlAssertionConsumerService` values on that service
provider's own application entry, compared exactly**; a request naming another is
refused on a page (not sent a failure Response — the address is the thing in
question), and there is no fallback to `/saml2/sp`. The same rule governs SAML
1.1's `shire` and WS-Federation's `wreply` (`wsfedReplyUrl`). An empty
`saml2.entityId` is likewise not replaced with `urn:sts:idp` in product
mode: the SSO service and the metadata refuse, naming the setting. And an
assertion configured to be encrypted that cannot be is refused (a Responder
status) rather than sent in clear.

**The `AuthnContextClassRef` says how the session really authenticated**, in
every mode: `PasswordProtectedTransport` for a password (as it always did),
`multipleauthn` for two factors, `unspecified` for a key alone or for nothing,
`TLSClient` for a client certificate, `Kerberos` for a SPNEGO ticket, and a
federation partner's own class for a federated sign-in. Until 2026-09-12 every
one of those that was not two factors or a key alone was called a password, and
SAML 1.1 and WS-Federation made the same claim in their vocabularies.

**An artifact resolves exactly once.** Bindings §3.6.4.1 requires it, no lifetime
setting can express it, and it is the single easiest thing in this profile to get
wrong and the hardest to notice — the happy path passes either way. Resolving
destroys the artifact; a second `ArtifactResolve` for the same one is refused with
a status naming the reason. The artifact itself is the 44 bytes §3.6.4 specifies:
type code `0x0004`, an endpoint index, the SHA-1 of the issuer's entityID as a
`SourceID`, and twenty random bytes.

**Where a `LogoutResponse` goes is a guess unless you declare it.** A
`<samlp:LogoutRequest>` carries no return address — only SP metadata has one, in a
`SingleLogoutService` element, and this service publishes metadata and does not
consume it. So the address is looked for in three places in order: the
`samlSingleLogoutService` attribute on the application's directory entry, then
`saml2.defaultSingleLogoutService`, then the assertion consumer service URL that
service provider last used — **which is a guess, and it is logged as one**. It is
a guess that usually works, because a service provider's ACS and its SLO endpoint
are commonly the same handler, and it is the difference between Single Logout
being exercisable here and not. Declare it on `/admin/saml2`, through
`POST /admin-api/saml2/set-logout-service`, or with an `ldapmodify`.

An identity-provider-initiated logout — a bare `GET /saml2/slo` — ends the
session and **names** every service provider it signed into, with a
`LogoutRequest` built for each. It does not fan them out into hidden frames:
WS-Federation's `wsignoutcleanup1.0` is an idempotent GET that works as a
one-pixel image, and a SAML `LogoutRequest` is a signed message that a service
provider *answers*, so firing those blind would produce a page claiming a
federation-wide logout it cannot observe.

**What it does not do**, stated rather than left to be discovered: no assertion
is encrypted (WS-Trust's `/sts?encrypt=1` still is — a passive AuthnRequest
carries no recipient certificate to encrypt to unless SP metadata is consumed,
and it is not); **no AuthnRequest signature is verified**, which is why the
metadata advertises `WantAuthnRequestsSigned="false"` and why the signing
certificate off a signed request is *recorded* on the application entry — so the
check has somewhere to read from the day it is wanted; no SP metadata is
consumed; and there is no identity-provider-initiated SSO with an unsolicited
Response, no ECP profile and its PAOS binding (refused **by name** rather than
quietly answered over HTTP POST — a service provider that asked for PAOS and got
a form post would conclude that PAOS worked), no Name Identifier Management and
no Assertion Query and Request profile.

`/admin/saml2` is the console page for it, and it answers the one question
nothing else here can: **which metadata document do I configure this service
provider from** — which is not one URL, and whose slug nobody derives by hand. It
holds nothing; every row is an entry in `ou=applications`.

### SAML 1.1 — the two browser profiles, and an attribute authority

Beside the SAML 2.0 profile above sits a SAML 1.1 one at `/saml11`, and the most
useful thing to say about it first is what it is **not**: it is not the same
implementation with the version number turned down. **SAML 1.1 has no request
message.** There is no `<AuthnRequest>` — the browser profiles are
identity-provider-initiated, and a flow begins when a browser arrives at the
*inter-site transfer service* carrying a `TARGET`, the URL at the relying party
it wants to end up at.

Almost everything that reads oddly here comes out of that one fact.

| Endpoint | What it is |
|---|---|
| `GET\|POST /saml11/sso[/{rp}]` | the **inter-site transfer service** — SAML 1.1's name for what 2.0 calls the Single Sign-On service |
| `POST /saml11/responder[/{rp}]` | the **SAML responder**, SOAP over HTTP (bindings §3.1). It resolves artifacts, returns assertions by `AssertionID`, and answers `AttributeQuery` and `AuthenticationQuery` |
| `GET /saml11/metadata[/{rp}]` | signed metadata — **one document per relying party** |
| `GET\|POST /saml11/rp` | a **mock relying party**. Non-spec, the default assertion consumer, and where a response is verified check by check |
| `GET /saml11/autopost.js` | the one script the Browser/POST profile runs |
| `GET /saml11` | what all of that is, for somebody who followed the link |

**The two profiles are chosen here, not asked for.** Browser/POST (profiles §4.2)
puts the whole signed assertion in a self-submitting form; Browser/Artifact
(§4.1) sends a 42-byte reference on a redirect and the relying party fetches the
assertion from the responder over SOAP, so **the assertion never passes through
the browser at all**. Nothing in SAML 1.1 lets a relying party say which it
wants, so `saml11.defaultProfile` decides and a **non-spec** `profile=post|artifact`
parameter overrides it — the same device `/sts?encrypt=1` is, and marked as
non-spec wherever it appears.

**The confirmation method is the profile, and the two are not interchangeable.**
§4.1.1.4 requires `urn:oasis:names:tc:SAML:1.0:cm:artifact` for Browser/Artifact
and §4.2.1.4 requires `...:cm:bearer` for Browser/POST. That element is the
assertion's own statement of *how it reached the relying party*, so an
artifact-profile assertion confirmed as `bearer` claims to have travelled through
the browser when it did not. A relying party that checks refuses it; one that does
not check works with either. The mock relying party checks.

**The relying party cannot identify itself, so sometimes this service guesses.**
With no `<saml:Issuer>` to read, the audience of the assertion comes from
Shibboleth's `providerId` parameter, from the `{rp}` path segment of a scoped
endpoint, or — failing both — **from the origin of the `TARGET`**. That last one
is a guess, it is logged as one, and `/admin/saml11` marks an identifier that
looks like a bare origin as probably guessed. It matters because a relying party
expecting `urn:example:app` and handed an assertion whose audience is
`https://app.example.com` refuses it inside a signature check, with nothing
saying why. Send `providerId`.

**Shibboleth's request profile is supported and is not a standard.** Real SAML
1.1 service providers do send a request: a redirect carrying `shire`, `target`,
`providerId` and `time`, identified as
`urn:mace:shibboleth:1.0:profiles:AuthnRequest`. It is accepted, and it is
advertised in the metadata, because a mock that could not be told where to send
the assertion would be a mock nobody could point at anything.

**The metadata is a SAML 2.0 document describing a SAML 1.1 identity provider**,
which is correct rather than a compromise: SAML 1.1 never had a metadata
specification, and what every relying party consumes is an `<EntityDescriptor>`
whose `protocolSupportEnumeration` is `urn:oasis:names:tc:SAML:1.1:protocol`.
There are **two descriptors** in it — an `IDPSSODescriptor` for the browser
profiles and an `AttributeAuthorityDescriptor` for the responder's query half,
because a Shibboleth service provider looks for its attribute authority in the
second and will not find it in the first. As with the 2.0 document it is per
relying party and **minted for anything asked for**.

**The responder answers four request types where the SAML 2.0 artifact service
answers one**, and that is not scope creep: the endpoint has to exist for the
artifact profile anyway, and once it does an `<AttributeQuery>` is the same
assertion builder behind the same envelope. `AssertionArtifact` is **one-shot** —
resolving destroys it (bindings §3.2.3) and a second attempt is refused with a
status naming the reason. `AssertionIDReference` is **not** one-shot, because a
reference is not a credential: whoever holds it holds the assertion already.
`AttributeQuery` and `AuthenticationQuery` are SAML 1.1's **attribute
authority**, which is the half Shibboleth deployments leaned on hardest. The
fifth type, `AuthorizationDecisionQuery`, is refused by name — this service makes
no authorization decisions.

**Nothing authenticates a caller at that endpoint**, and it is worth stating more
loudly than the equivalent sentence about `/saml2/ars`. An artifact is protected
by twenty random bytes and the one-shot rule. An `AttributeQuery` is protected by
nothing: **in development mode** anybody who can reach this port can ask for an
assertion about anybody, by name, with no credential and no attribute release
policy. A real attribute authority uses mutual TLS and a policy. Every query is
logged saying so. **In product mode both query types are REFUSED** (2026-09-12),
outright rather than gated on a client certificate — there is no release policy
for a certificate to be checked against, so a gate would answer any holder of any
trusted certificate about anybody.

**And in both modes, since 2026-09-12, a query no longer signs something that did
not happen.** An `AuthenticationQuery` is answered from a live, authenticated
session this realm holds for that name — its method and its real authentication
instant — and with **no assertion at all** when there is none; it used to answer
`am:password` at the instant of the query for anybody. An `AttributeQuery`'s
assertion carries its attributes and **no `AuthenticationStatement`**, which it
used to carry for the same invented sign-in.

**There is no Single Logout, and that is the protocol rather than a gap.** It
arrived with SAML 2.0. There is likewise no `ForceAuthn`, no `IsPassive` and no
`RequestedAuthnContext` — none of them has a spelling in SAML 1.1 — and **no
error response**: a failure here is a page, because there is no request to answer
and no `InResponseTo` to name.

Six spellings differ from SAML 2.0 in ways that break a parser, and the
implementation notes in `saml/CLAUDE.md` list all of them; the ones worth knowing
before reading a captured document are that the id attribute is `AssertionID` (on
an assertion) or `ResponseID` (on a response) rather than `ID`, the `Issuer` is an
**attribute** rather than a child element, the status code is a **QName**
(`samlp:Success`) rather than a URI, and `ds:Signature` goes **last** inside an
assertion and **first** inside a response.

`/admin/saml11` is the console page for all of it, and `GET /admin-api/saml11`
the same thing as JSON.

### Federation — the one feature here that refuses by default

Everything above this line is this service being **asked** for something. This is
the other direction: a relationship with a foreign identity service, in five
protocols — SAML 2.0, SAML 1.1, WS-Federation 1.2, OpenID Connect and OAuth 2.0 —
with this service at **either end** of it.

| | |
|---|---|
| `GET /federation` | what all of this is, every configured relationship in both directions, and the URL to give each partner |
| `GET /federation/login/{id}` | **start.** Sends the browser to the partner — an `<AuthnRequest>`, an inter-site transfer URL, `wa=wsignin1.0`, or an OAuth 2.0 authorization request, whichever the relationship says. Takes `?returnTo=`, a path on this service to land on afterwards, and `?application=`, which names what the person is signing in TO so the relationship can count that pair — a HINT, checked against the live register before anything is written down |
| `GET\|POST /federation/acs/{id}` | **finish.** The assertion consumer service, the WS-Federation `wreply` and the OAuth 2.0 `redirect_uri`, all one path. **This is the URL to configure at the partner** |
| `GET /federation/metadata/{id}` | this service's own SAML metadata for that partner — an `SPSSODescriptor`, which is the half of this service that is a service provider |

Configure them at `/admin/federation`, or through `POST
/admin-api/federation/create` and its six siblings, or with an `ldapmodify` under
`ou=federations` — three doors onto one register, which is one entry per
relationship and no copy anywhere.

**`/admin/federation/map` draws it.** The same register as a diagram, generated
on the server and reached from a link on the table. It is **three bands, and the
bands are a claim about direction**: everything on the LEFT of the hexagon
arrives wanting somebody signed in — an application registered here, or a
foreign service provider — the hexagon is the trust realm the picture is of, and
everything on the RIGHT is a party this service asks to do the signing in. So
**an arrow is a REQUEST and not an assertion**, which is the one thing about it
that looks backwards: an identity-provider-side relationship points INWARD even
though this service asserts outward, and that inversion is what turns an
**identity broker** — one relationship authenticating through another — into a
single straight line through the middle instead of two arrows leaving the same
box with nothing joining them. A **hexagon** is an identity service and a
**rectangle** is a party that consumes what one issues; a **dashed** outline
means foreign. The lines are coloured by the relationship's state, which is the
list page's own four: green is ready, grey is disabled — how every relationship
starts — red is **enabled and not configured**, which will refuse at the moment
somebody uses it and looks finished from every other angle, and amber is a
broker whose onward partner is unusable, which is the only failure here that
still produces a working sign-in, at the password screen. It adds the three
things a table of relationships has nowhere to put, each a fact about **two
registers at once**: how many applications are configured to use each partner,
how many people have signed in through each *application and relationship* pair,
and what the identity-provider side does about authenticating somebody. Filtered
by role, protocol and free text, the one control narrowing the picture and the
tables under it; `?format=svg` is the document alone and `?format=json` is the
graph. Like every other picture here it carries no script and therefore does not
pan or zoom — the page says so, and the SVG document does.

**The per-application counts do not have to add up, and the page names the
difference rather than letting somebody find it.** A relationship's own total
counts every credential that crossed it; the rows count only the ones that named
an application this service is configured for. Three ordinary things make the
gap: the partner buttons at the foot of the sign-in screen belong to no
application, `/federation/login/{id}` needs no configuration at all to reach, and
a sign-in naming an application that does not point at that relationship is
refused a row and logged. That last one is a refusal rather than a convenience:
the parameter is a string anybody who can reach this port chose, and the
attribute it would grow is on the one entry whose contents decide whether an
assertion is verified.

#### Why this one cannot be permissive

This service checks no password, validates no access token and attests no
workload, and that is the point of it. Three surfaces are already exceptions —
SCIM, the SPIRE Server API, the admin console — and all three are **turnstiles**:
they refuse a caller so that a client can be made to exercise a refusal, and any
of them could be opened tomorrow with nothing lost but an error path.

This one is different, and the difference is worth being exact about.

`/federation/acs/{id}` receives **an unauthenticated HTTP request that claims to
be a person.** The only thing standing between "alice signed in at the partner"
and "somebody POSTed some XML" is the signature check. And the session that comes
out of it is **the same session** `/oauth2/authorize`, `/wsfed`, `/saml2/sso`,
`/saml11/sso` and `/admin` all read.

So "accept any SAML Response" would not be a permissive mock of federation. It
would be an authentication bypass for every protocol in this process, reachable
with `curl`, and the tokens minted afterwards would be indistinguishable from
real ones. There is no version of this endpoint that is both useful and
permissive.

What that costs is one sentence in the documentation and four in the code:

* nothing federated happens until a relationship is **created**;
* a relationship is created **disabled**, and enabling it is a second act;
* an enabled relationship missing a field its protocol needs **refuses and says
  which field**, rather than half-working;
* an assertion is refused unless it verifies against the certificate configured
  on that relationship — **not** against a certificate the document brought with
  it, which is the difference between a signature check and a decoration.

**Past that gate, everything is as permissive as the rest of this service.** Any
username in a verified assertion is accepted. Any attribute is mapped. Nothing
about the person is checked, and a directory entry is created for them. *The gate
is on the signer, not on the subject.*

#### What a federated sign-in leaves behind

An entry under `ou=users`, with the partner's attributes on it, and five
attributes that exist nowhere else in this directory:

```
uid=fedalice,ou=users,dc=example,dc=com
  cn: Alice Anderson              <- from the partner
  mail: alice@partner.example     <- from the partner
  federationRelationship: partner-a
  federationIssuer: https://idp.partner.example/saml
  federationSubject: alice@partner.example
  federationAttribute: cn | mail | givenName | sn
  federationLastSeen: 20260824T235014Z
```

`federationAttribute` is the useful one and has no analogue anywhere else here.
This service **invents** a persona for everybody it has never met — that is what
fills `mail` and `givenName` for a person who signed in with a name and nothing
else — so a federated `mail` and an invented `mail` are indistinguishable on the
entry. This says which is which, and it is exactly the question a person reading
a federated directory entry has.

A partner's value **overwrites** an invented one and never the other way round.
An attribute the partner has stopped sending is **left alone** — a partner that
dropped `title` from its release policy has not said the person has no title.
`uid` is never written from an assertion, because that is what the DN is built
from.

An incoming name that nothing maps is **not written under its own name.** It is
listed as unmapped on the result page, on `/admin/federation` and in the log.
That looks worse on the first run and is deliberate: this directory has no
schema, so an attribute nobody defined would be accepted silently and nothing
would ever report that the name was wrong. The ordinary OpenID Connect claims,
the SAML `urn:oid:` names and the AD FS claim URIs are mapped already —
`fedAttributeMap` is for a partner's own inventions.

#### It works in every protocol without any of them being told

The federated sign-in ends by calling the same `startSession()` the sign-in
screen calls. There is no federation session store, and no protocol module here
contains the word.

Which is why `/authn/login` grows a **button per usable partner**
(`federation.loginButtons`): a person arriving at that screen is in the middle of
something — an authorization request, a `wsignin1.0`, an `AuthnRequest`, the
console — and the button hands that whole request to the federated flow and
brings them back to it. Only relationships that would actually work are offered;
a button leading to a refusal is worse than no button, because the person has
already left the screen by the time they find out.

#### Home realm discovery: which partner, and who decides

Those buttons offer **every** relationship this service has, which is home realm
discovery performed by the user against a list they have no way to reason about.
`appFederationRelationship` on the application's entry under `ou=applications` is
the answer to that, and it holds a **list**:

| What the entry names | What a person meets |
|---|---|
| nothing | the sign-in screen, with the generic buttons under it |
| one usable relationship | **nothing at all** — the browser goes straight to that partner |
| several usable | **`/authn/select-idp`**: one button per partner, no password field |
| several, `appFederationAutoRedirect` FALSE | the sign-in screen, with those partners as its only buttons |
| only unusable values | the sign-in screen, with a banner naming what is wrong with each |

The values need not share a protocol — a SAML 2.0 partner and an OpenID Connect
one are the ordinary pair, and they arrive at the same `/federation/acs/{id}`.
**Configuration decides the set; the person decides within it**, which is the
difference between this page and the generic buttons: those ask "which of the
seven identity services this mock has heard of are you?", and this asks "which
of your employer's two".

`appFederationAutoRedirect` means *without the sign-in screen* and never *without
a page*. With one partner that is a redirect; with several it is the chooser,
which is the screen's job done without the screen. There is no value of a boolean
that can say which identity provider somebody's employer is.

**A value naming a relationship this service cannot use is printed, not dropped**
— disabled, half-configured, identity-provider-side, or absent from this realm.
A list of three with one disabled draws two buttons, and two buttons is exactly
what a correct list of two draws, so the difference has to be said in words. The
one case that shows nobody anything is one usable value with the auto-redirect
on: it works perfectly and draws no page, so the other values' problems go to the
log at INFO instead.

The four checks are made **when the attribute is read**, never when it is
written: it is a string on a directory entry that `ldapmodify` reaches, and the
relationship it names can be disabled by somebody who never looked at this
application. The chooser re-reads them again when it is drawn, because the
pending record lives ten minutes.

#### The other direction: releasing attributes to a partner

Every protocol endpoint here already issues to anybody that asks, so an
identity-provider-side relationship changes nothing about whether a partner is
**answered**. It adds two things: the partner is marked as a federation partner
rather than a test client, and `fedRelease` decides **which attributes reach it**.

The release list can only **remove**, and only from what `/admin/claims`,
`/admin/userinfo-claims`, `/admin/saml-attributes`, the groups claim and a
client's own OIDC Core section 5.5 claims request would add — the last of those
because the list is about what an audience may *see* rather than about which
mechanism produced the value, so a partner released `email` alone cannot ask for
`birthdate` and be given it. It cannot touch `sub`,
`iss`, `exp`, a `NameID` or anything else the protocol puts in an artifact
itself — those are what make the artifact verifiable, and a release list that
could drop `iss` would produce tokens that fail to verify with nothing pointing
back at the page.

**An empty release list means no policy, not "release nothing".** That is what
every partner has on the day it is registered, and treating it as the strict
reading would mean registering a partner silently stopped it receiving what it
received the day before.

#### The only outbound request this service makes

Redeeming an OpenID Connect authorization code means calling somebody else's
token endpoint. Nothing else in this repository has ever dialled anything, and
that was a position taken twice: `jwks_uri` on an application entry is *recorded
and never fetched*, and WS-Federation's `wreqptr` is refused, both for the same
reason — following a URL somebody registered, in order to verify a credential,
is a server-side request forgery with a specification citation attached.

**Both of those still stand.** The distinction is not "this feature needs it",
which is the argument every SSRF ever shipped was made with:

> Those URLs are supplied by the **caller**. These are supplied by the
> **administrator**.

`POST /oauth2/register` is unauthenticated and takes any `jwks_uri` anybody
types. A federation relationship is created through the gated console or through
`/admin-api`, and anybody who can set `fedTokenUrl` can already do worse things
than make this process issue a GET.

The mechanism that keeps that honest is the API rather than the intention.
`federation_http.js` **will not take a URL**: it takes a relationship and the
*name* of the attribute holding one, and refuses any name outside its list of
three. A caller with a URL from anywhere else cannot use it. Beside that: `https`
only unless `federation.outboundAllowInsecure` says otherwise (warned on every
request, not once at startup), **no redirects followed** — a 302 from a token
endpoint would hand the credential in the `Authorization` header to whatever
`Location` said — a capped body, a short timeout because a browser is waiting,
and no judgement at all about what comes back.

`federation.outbound` turns it off entirely. SAML, SAML 1.1 and WS-Federation
need no back channel at all, and an OpenID Connect partner can still be used with
`fedResponseType: id_token` and its keys pasted into `fedJwks` — so a deployment
with no egress can federate in four of the five protocols and most of the fifth.

#### Three checks became refusals on 2026-09-12, in every mode

This feature is documented as the one that cannot be made permissive, and three
of its checks could be skipped:

* **An `<Audience>` naming a different service provider was logged and
  accepted.** It is REFUSED now: an assertion a partner minted for any other of
  its relying parties verifies against the same key, names the same issuer and is
  inside its window, so accepting it let anybody holding one sign in here. Every
  `AudienceRestriction` must name this service (several audiences in one are an
  OR, several restrictions an AND). SAML 2.0 with no restriction at all is refused,
  because the Web Browser SSO profile requires one; SAML 1.1 and WS-Federation,
  whose profiles do not, are accepted with a warning. **The WS-Federation path
  never checked the audience at all**, and does now.
* **`fedPeer` is REQUIRED on every service-provider-side relationship.** An empty
  one skipped the issuer check with a warning, so a relationship with no peer
  accepted any issuer its configured key had signed for; it is now a missing
  field, named like the others, and the relationship is not usable without it.
  A WS-Federation assertion carrying no issuer is refused too.
* **The partner's authentication context is carried, not discarded.** A
  federated session's `amr` is `federated` followed by what the partner stated,
  and `acr` is the partner's class — which is what a SAML assertion this service
  then issues says, rather than calling every federated sign-in a password.

**What this service is called to a partner** is derived from the base URL a
browser reached it at (`<base>/federation/acs/<id>`, which `global.publicBaseUrl`
pins); `fedLocalEntityId` on the relationship sets it outright — the Issuer of
the AuthnRequest, the `wtrealm`, the SAML 1.1 `providerId` (now sent when
`fedSsoUrl` names none) and the audience an inbound assertion must name. A partner
configured with another name for this service needs it set.

#### OAuth 2.0 is listed separately, and warns

Federating over plain OAuth 2.0 means resting a sign-in on an **access token**,
which says a client was *authorized* — not that a person signed in just now. That
gap is the whole of why OpenID Connect exists. It is supported here because real
deployments do it and being able to exercise one is the point, and it logs a
warning on every sign-in, because doing it silently would be this repository
teaching the mistake.

#### What it deliberately does not do

It does not decrypt an `<EncryptedAssertion>` (a partner configured to encrypt
produces a Response with no assertion, and that cause is *named* rather than
reported as "the partner sent nothing"). It does not check the partner's
certificate against a CA or its validity dates — `fedSigningCertificate` is a
**pinned key**, which is the stronger of the two for this purpose. It does not
consume a federated **sign-out**: a `wsignout1.0` or `<LogoutRequest>` arriving at
the ACS is refused by name. It holds no refresh token belonging to anybody else's
service. And it never re-checks a person after the session exists — a partner
that revokes somebody five minutes later is not consulted, because nothing here
polls.

`federation/CLAUDE.md` argues every one of those, and carries the list of
negatives a test would have to cover. **There is no test yet, and this is the
surface where that costs most**: it is the only one here whose bugs are security
bugs rather than fidelity bugs, and a happy path proves close to nothing.

### WS-Federation — the profile that joins the pieces

`wsfed.js` is the Web (Passive) Requestor Profile of WS-Federation 1.2 section 13,
and it is the browser-facing SSO profile this service went without for a long time.
Everything it needs already existed — an assertion builder, a signer, a login screen,
a session — and what was missing was the thing that hands an assertion to a relying
party *through a browser*. Four endpoints:

| | |
|---|---|
| `GET`/`POST` `/wsfed` | the passive requestor endpoint, dispatching on `wa`. With no `wa` at all it describes itself, the way `GET /sts` does |
| `GET /wsfed/autopost.js` | the one script the sign-in response page runs |
| `GET /FederationMetadata/2007-06/FederationMetadata.xml` | signed federation metadata |
| `GET`/`POST` `/wsfed/rp` | a **mock relying party** — non-spec, and the default `wreply` |

**The sign-in response is a form POST, never a redirect** (13.2.2), and that single
fact is what makes this profile shaped differently from everything else here: the
token travels in a body, so it is not length-limited and never lands in a URL, a log
or a `Referer` header. Three things follow from it. The page needs a script to submit
itself, so it is the second response in this service to relax `script-src` to
`'self'` naming a real resource (`/wsfed/autopost.js`) — an inline script would not
run at all, silently, leaving a page that looks like it is working and never posts,
which is the identical trap the WebAuthn ceremony script above records. Its submit
button is therefore labelled for a person rather than hidden: with scripting off, the
button *is* the mechanism. And **`form-action` stays out of the policy**, here as
everywhere — the form posts to `wreply`, which is by definition another origin, and
`form-action 'self'` would block the response from ever reaching the relying party
while the sign-in still appeared to succeed.

**In product mode the `wreply` must be registered** (2026-09-12) — one of the
`wsfedReplyUrl` values on the `wtrealm`'s application entry, compared exactly —
and there is no fallback to `/wsfed/rp`; development accepts any absolute URL, as
it always did. The persona claims (given name, surname, mail, UPN) come from the
person's directory entry in product mode, or are omitted, and the signed
federation metadata describes them that way; development invents and describes
them as before. When `wsfed.entityId` and `saml.issuer` differ — the metadata
names one and every assertion names the other — `/wsfed` says so and the process
logs it at startup.

**SAML 1.1 is the default token, not SAML 2.0**, which is why `saml11.js` exists.
WS-Federation is token-type agnostic and this service has issued SAML 2.0 for years,
so 2.0 looks like the obvious default — but AD FS issues **1.1** to a WS-Federation
relying party unless told otherwise, and the RP libraries written against it (WIF,
`Microsoft.Owin.Security.WsFederation`) read 1.1 first. A mock whose default was the
rarer of the two would be exercising the wrong half of those clients. Both are
offered, and `fed:TokenTypesOffered` advertises exactly these two. SAML 1.1 is a
different specification and not a dialect of 2.0: the id attribute is `AssertionID`,
the version is two attributes, the Issuer is an attribute rather than an element, the
Subject sits inside *each* statement, `ds:Signature` is the **last** child rather than
the second, an attribute is `AttributeName` + `AttributeNamespace` rather than one
`Name`, and the condition is `AudienceRestrictionCondition`. Each of those is a
plausible thing to get wrong by writing 2.0 out of habit, so each is commented where
it happens.

Two things about the token that took a debugging session each. **`ds:Signature` lands
in three different positions in three documents here** — last in a SAML 1.1
assertion, second (after `Issuer`) in a SAML 2.0 one, and first in the federation
metadata's `EntityDescriptor` — and all three are schema-mandated rather than
stylistic. They are the three placements `common/crypto.js` names.

The second one used to be that **the signing library had to be told about
`AssertionID` and must *not* be told about `ID`** — it resolved a reference URI by
looking for attributes named Id/ID/id, so SAML 1.1's unusual name had to be added or a
perfectly good signature reported as broken, while naming `ID` for SAML 2.0 unshifted a
*duplicate* onto that list and the library then refused the document with a
signature-wrapping-attack error naming a document that had nothing wrong with it.
Symmetry between the two call sites is what produced the second one. **Since
2026-08-27 there is no such argument anywhere**: every signature and every cipher in
this service goes through `common/crypto.js`, which resolves `ID`, `AssertionID`,
`ResponseID` and `RequestID` from the document itself. It is worth knowing about
because the underlying trap is real in any XMLDSIG code — and because for months
every SAML 1.1 assertion this service issued carried an `Id="_0"` attribute the
schema does not have, verified anyway, and had to be fixed at six signers
independently.

**The session is the one `oauth2.js` owns.** `wsfed.js` is required after it in
`server.js`, so the dependency is one-way and no cycle exists, and `startSession` /
`endSession` are functions rather than four repeated lines precisely so the cookie's
name, path and `SameSite` cannot drift apart between the two protocols — two sessions
that each looked fine alone and never saw each other would be a debugging session with
no error message in it. Single sign-on across the two is the interesting behaviour:
sign in at the OIDC screen with a security key and arrive at `wsignin1.0`, and the
assertion's `AuthenticationMethod` says multiple factors *because the session recorded
`amr: ["hwk"]`*. Signing out of either signs out of both. The one consequence worth
knowing is that the cookie is `SameSite=Lax`, so a sign-in request that arrives as a
cross-site form POST — which 13.2.1 permits — carries no cookie and is shown the login
screen even though a session exists; the alternative is `SameSite=None`, which
requires `Secure` and is a change that needs its own argument rather than one
that falls out of the port's scheme. That distinction used to be hidden by the
scheme: the cookie is `Secure` when and only when the port is TLS, which every
appconfig file here now makes it, so `Secure` is no longer the obstacle — the
`Lax` is a decision, and `authn.js` says so where the cookie is set. The screen
says so too, rather than leaving it to look like a broken session.

`wauth` is the one thing this profile **refuses** that it could easily have faked. A
relying party asking for multi-factor against a password-only session is answered with
an error and two ways forward, not with an assertion claiming a second factor that did
not happen — `wauth` is how a relying party *demands* a method, and an identity
provider that ignored it would let the demand appear to have been met. In the same
spirit `wreqptr` is refused outright: it names a URL for the identity provider to
fetch the request from, and dereferencing an arbitrary URL handed over in a query
parameter is a server-side request forgery with a specification citation attached.
Send `wreq` by value instead. `wfresh` is read as **minutes** — the one place this
profile and OIDC's `max_age` differ in unit, and reading it as seconds makes every
request look fresh — and it is dropped on the way back from the login screen for the
same reason `prompt=login` is, or it would demand a fresh authentication forever.

The **mock relying party** at `/wsfed/rp` is non-spec and earns its place twice: it
is the default `wreply`, so a request that names no return address has somewhere real
to go, and it makes the profile testable from one service. It verifies the response
check by check — the assertion signature against `/sts/cert`, the issuer, the audience
against its own realm, the validity window, and the **`wctx` round trip** — and shows
every verdict rather than one boolean, on the same argument the OID4VP verifier makes.
`wctx` gets its own check because it is the relying party's own state and the
commonest thing for an identity provider to mangle by decoding and re-encoding it or
dropping it for being long, and an RP whose `wctx` comes back altered cannot tell that
from a lost session.

`wsignout1.0` ends the session and sends a `wsignoutcleanup1.0` request to every
relying party the session signed into, as `<img>` loads — which is what front-channel
logout is, and which is why that one response widens `img-src` to `*`: a cleanup ping
is by definition a third-party origin. It is the feature and not a leak, since the
URLs are ones the relying parties themselves supplied as `wreply`. They are listed
visibly on the page as links too, because a silent `<img>` that failed would leave a
person with no way to see that the cleanup did not happen, and the return to `wreply`
is a link rather than a 302 for the same reason — a redirect would abandon the pings
before they were sent. A cleanup arriving *at* this endpoint ends the session and
stops there: an identity provider that fanned out on receipt of a cleanup would loop
with whatever sent it.

The metadata is at **AD FS's path** because WS-Federation names none and that is where
every relying party in this ecosystem looks first, and it is signed, and it carries
`fed:SecurityTokenServiceType` with both the `PassiveRequestorEndpoint` and the
`SecurityTokenServiceEndpoint` — the latter pointing at `/sts`, which is the same
service answering the active profile. What it deliberately does **not** carry is an
`IDPSSODescriptor`, per the note near the top of this file: this document describes a
security token service, and the SAML 2.0 identity provider describes itself at
`/saml2/metadata`.

Not implemented, and named here rather than left to be discovered: the attribute
service (`wattr1.0`) and the pseudonym service (`wpseudo1.0`), which both answer 501
with an explanation of what they would have done; `wresultptr` (the response is always
by value); token encryption in this profile, because a passive request carries no
recipient certificate to encrypt to, where `/sts?encrypt=1` has one because a
WS-Security signature carries it; the WS-Federation metadata exchange over SOAP; and
any authorization or policy enforcement — `wp` and `wencoding` are logged and nothing
more.

### The mock STS's index of itself

`GET /admin/sts-metadata` answers "what does this thing speak, what can I call, what may I call it with, and which specification is it pretending to implement" — a page the service needed once it had grown to thirteen protocol families across twenty-six modules. `?format=json` gives the same document machine-readably, and the **Download** button at the top of the page is that URL asked for as a file (an `<a download>`, because `script-src 'none'` means nothing cleverer would work).

**It was `/sts-metadata` until 2026-08-24 and it is a page of the admin console now.** Three things changed with it and all three are the reason: it is drawn by `admin.js`'s `page()`, so it has the console's sidebar — it used to be a cul-de-sac with no way back to anything — its breadcrumb and its gate banner; it is **behind the console gate** like everything else under `/admin` — unconditionally, since `global.mode` replaced `admin.authRequired` on 2026-09-06 — so a browser with no session is sent to the sign-in screen and a `?format=json` caller is refused `401 login_required` rather than redirected; and `sts_metadata.js` now builds only the *body* of a page, because `page()` emits the console's one stylesheet and a second one inside `<body>` would be markup no validator accepts. The require goes one way only — `sts_metadata.js` requires `admin.js` for the shell, never the reverse — because this module must stay LAST in `server.js` and a require from the console would drag every console route behind it.

**Thirteen protocol cards sit at the top of it**, which is the one part of the page that cannot be derived: a family is on the router only if it is HTTP, and SAML 2.0 and SAML 1.1 register **no route at all** (their assertions travel inside a WS-Trust RSTR or a WS-Federation wresult), while Kerberos, LDAP, PKI and SPIFFE live mostly on raw sockets. So that list is hand-written, and three drift checks keep a hand-written list on a derived page honest: a card naming an endpoint group that has no rows, a card citing a specification id that does not exist, and — the direction nothing else catches — **a group of endpoints no card claims**, which is what a fourteenth family added without a card looks like. They are reported beside the other three and asserted by the same test.

**The endpoint list is read from the running Express router, not written down.** That is the whole design: a hand-kept list of endpoints in a file beside the endpoints goes stale the first time somebody adds a route, and the failure is silent in the worst direction — the page still looks complete. `app._router.stack` is walked **per request** (not at require time, where the answer would depend on module load order) and the table in `sts_metadata.js` only supplies the *name* and the *description* for a path the router reports. Both kinds of drift are then reported on the page itself and fail this repository's own `tests/vendored/sts_metadata.js`:

* a route **registered and undescribed** is listed as UNDOCUMENTED — it still appears, with its methods, because the page's first duty is to be a true list of what is callable. Adding an endpoint to this service therefore costs one entry in `sts_metadata.js`, which is the point.
* a description whose path is **not registered** is the more dangerous half: the page would advertise an endpoint that answers 404, which is what a rename produces, and a rename is exactly when nobody thinks to check the index.

The drift check earned its keep immediately: on first run it caught the `OPTIONS *` CORS preflight (registered by `app.options`, described nowhere) and a reference to a spec id that did not exist. The test additionally catches an *idle* claim — a specification listed that no endpoint links to — which found two, `rfc6750` and the RDF canonicalization used by Data Integrity, both genuinely implemented and both unlinked.

Each path is a **link to that path** — but only where that is honest, which is about half of them. A link is issued as a GET, so a path the router answers only for POST would land the reader on Express's own `Cannot GET /oauth2/token` (reads as a broken service), and a route pattern carrying a `:parameter` or a `*` is not the address of anything. Those are listed unlinked with the reason shown — "POST only", "takes :id", "wildcard" — because that reason is the most useful thing on the row. The five followable endpoints that *do* something when clicked (`/oauth2/authorize`, `/oauth2/logout`, `/oauth2/userinfo`, `/issuer/offer`, `/oid4vp/start`) carry an `effect` note; the first answers **400** when followed bare since it needs `client_id` and `redirect_uri`, and userinfo answers **401** since it is a protected resource. Links are root-relative so they follow whichever host the page was reached at, and open in a new tab so the index survives the click. That test **follows every link** and fails if one does not reach a handler, which is what stops the page advertising a dead one.

Two details worth knowing before changing the test. **A 404 is ambiguous and the distinction matters**: several endpoints answer 404 correctly for a resource that does not exist (an unknown offer id, an unknown presentation state), which *proves* the route is registered, while Express's own 404 for an unregistered path is an HTML page reading `Cannot GET /path`. Treating them alike either fails on healthy endpoints or passes on missing ones. And the **coverage notes must start `full`, `partial` or `mock`** and say what is missing, because a list of fifty specifications that did not mention that this service checks no passwords and validates no access tokens would be the most misleading thing in the repository.

**Kerberos is the one blind spot in the whole design, and it is structural.** The page is built by walking the live Express router, which is precisely why it cannot go stale — and the KDC's listeners are raw TCP and UDP sockets, as is the protected service's. A protocol family that registers no route is invisible to a router walk. Three HTTP surfaces are all the walk can see (`/KdcProxy`, `/krb5/principals`, `/krb5/service`), so the sockets are described in the text of those rows rather than left to be inferred from silence — the alternative, a described entry with no route behind it, is the *stale* half of the drift check and would have to be exempted from it by hand. Anything added later that speaks a protocol over a socket needs the same treatment.

### The mock STS's index of its own cryptography

`GET /admin/crypto-metadata` is the second metadata page and it is not a summary of the first. Where that one answers *what can I call*, this one answers the question underneath it: **when this service signs, verifies, encrypts or decrypts something, what does it actually use** — which digest, which signature algorithm, which cipher, which key, and which of the several envelopes (JOSE, XMLDSIG and XML Encryption, WS-Security, COSE, X.509, Kerberos) that primitive is wrapped in. It is drawn for **every identity service this mock advertises**, one section per protocol family, with the four verbs — signs, verifies, encrypts, decrypts — as four separate columns, because they are four different exposures and this service does a different amount of each. `?format=json` and `GET /admin-api/crypto` are the machine-readable forms.

**Every algorithm table on it is read from the module that performs the algorithm**, which is the endpoint page's design one layer down and for the same reason: a hand-kept list of algorithms is one that will disagree with the code, and it will do so silently, because a wrong list is well-formed. So the JWS rows come from `common/crypto.js`'s one algorithm table, the XML signature, digest and canonicalization tables from the vendored `xmldsig.js`, the Kerberos encryption types are read back out of the codec (those modules are vendored and cannot be edited to export a list), the SPIFFE authority key types from `spiffe_ca.js`, the COSE algorithms from the WebAuthn verifier, and so on across eleven modules. Only the per-family prose and the standards list are hand-written, and every coverage note there starts `full`, `partial` or `mock` and says what is missing — the rule the specification list already follows, and one that matters more here, because a page about cryptography that overstates what it implements is actively dangerous to somebody using it to learn.

**It checks its family list against the endpoint page's in both directions**, so a fifteenth protocol family added without a crypto profile is reported rather than quietly absent, and a profile naming a family that no longer exists — what a rename produces — is reported too.

**There is a post-quantum section, and its headline is deliberately not the flattering one: the signatures here are partly post-quantum and the key establishment is entirely classical.** ML-DSA, SLH-DSA and the six composite algorithms can sign an ID Token, a UserInfo response and a published JWK; nothing else. Every key establishment mechanism in the process — RSA-OAEP, RSAES-PKCS1-v1_5, ECDH-ES, TLS's own key exchange — is broken by Shor's algorithm, and there is no ML-KEM anywhere in it. Those two halves are reported apart because the threat differs rather than the effort: a signature is checked when it is presented, while ciphertext captured today can be kept and opened when the machine arrives. Symmetric cryptography is a third category again, where Grover costs a square root and the answer is key length — which makes **Kerberos the family here least affected by any of it**, being the only one with no public-key cryptography in it at all. The most instructive row is DPoP, whose list excludes the post-quantum algorithms on purpose: a proof is bound through the RFC 7638 thumbprint, which is defined for RSA, EC, OKP and `oct` and not for `AKP`, so a proof signed with ML-DSA would verify perfectly and bind to nothing.

**It publishes no private key and no secret** — key types, key identifiers, curve names, certificate fingerprints and validity dates, all of them already readable from `/oauth2/jwks`, `/tls/server-certificate` and the SPIFFE bundle endpoint.

### Applications — the other side of every authentication

A person who authenticates here has had a directory entry and a row on
`/admin/users` since the user observer was written. The thing on the **other**
side of those authentications had nowhere at all. It was six fragments: a
`registeredClients` Map in `oauth2.js`, a `client_id` that reached the console and
was thrown away, a `wtrealm` read and forgotten, an `AppliesTo` echoed into an
assertion, a service principal created on demand in a principal database, and a
verifier id in a config row. Each was correct where it stood, and there was no way
to ask this service *what applications have you seen?*

`ou=applications` is that place, and — this is the part that matters —
**the entries are the registry, not a copy of one.**

```
dc=example,dc=com
├── ou=users          people
├── ou=groups         groups, which grant nothing (a token carries them, see
│                     groups.claim; nothing here reads one back)
└── ou=applications   OAuth clients, OIDC relying parties, SAML 2.0 and 1.1
                      service providers, WS-Federation applications, WS-Trust
                      relying parties, the OpenID4VP verifier, Kerberos services
```

`GET /admin/ldap/applications` lists them and publishes the schema; `?format=json` is
the machine-readable form.

#### One entry per identifier

An entry appears the first time an identifier is **accepted** — a `client_id` at
the authorization or token endpoint, a `wtrealm` on a `wsignin1.0` response, an
`AppliesTo` on an issued token, a service principal name on a TGS-REP *and again
when a ticket for it is accepted*, the Verifier's own `client_id`. The key is the
identifier verbatim, not lower-cased and not namespaced by protocol, so an
application appearing under one name in two protocols is **one entry with two
kinds** rather than two entries.

The Kerberos service being recorded at both ends is not a double entry: both
halves write `SPN@REALM`, so they land on one record, and the acceptor's half is
the only one that fires for a ticket **some other KDC issued** — a real Active
Directory — where the client used to be recorded and the service it presented the
ticket to was not.

One sighting can also name **more than one kind at once**, because some
applications genuinely are two things in the same request. A `wtrealm` is a
WS-Federation application *and* the audience of the SAML 1.1 or 2.0 assertion it
was handed; an `AppliesTo` handed a SAML 2.0 assertion is a WS-Trust relying party
*and* that assertion's service provider. Recording only one of each is how
`wsfed-relying-party` came to be a kind the console offered as a filter and no
protocol path ever produced. That is the
same rule that makes `alice`, `alice@REALM` and her `urn:uuid:<entryUUID>`
subject one person on `/admin/users`, and it is the shape the federation work will need: a
relying party that federates over both OIDC and SAML is one relationship.

It is recorded where each protocol accepts it rather than at the authentication
funnel, and that difference is worth knowing. The user side has exactly one
funnel; this side cannot, because in the authorization code flow the person is
authenticated in `authn.js`, which knows nothing about OAuth by design and never
reads a `client_id`. So each protocol records its own application at the point it
decides that application is real.

#### The directory is the source of truth

There is no Map shadowing these entries. `applications.js` reads them, changes
them and writes them back; every query is a directory read and nothing is cached.
Three things follow:

**An `ldapmodify` is a configuration change.** Add a value to `oauthRedirectUri`
on a client's entry and RFC 9700 mode accepts that redirect URI by exact match on
the *next* authorization request — no restart, no reload. That is demonstrable in
four commands and it is the whole point of the arrangement.

**The RFC 7591 registrations live there too.** `POST /oauth2/register` writes an
entry; RFC 7592's read, update and delete operate on it. The whole registration
document is kept verbatim in `appRegistrationJson`, because RFC 7591 permits
arbitrary metadata and no fixed set of attributes can represent it — but when the
record is rebuilt, that document is the *starting point* and every member with an
attribute of its own is then overwritten from the attribute. Otherwise an operator
who edited `oauthRedirectUri` would find the edit ignored by the one check that
matters, which is the two-stores failure this whole arrangement exists to avoid.

**Deleting a registration keeps the entry.** `appRegistered` goes to `FALSE`, the
`client_secret` and the registration access token are removed with it, and the
history stays: this registry records what this service has *seen*, and losing that
an application was ever here because its registration was withdrawn would be
losing the fact rather than the configuration.

#### Software statements (RFC 7591 section 2.3)

A registration may carry a `software_statement`: a signed JWT of client
metadata, vouched for by whoever publishes the software rather than by the
installation registering. **A trusted statement's claims take precedence over the
registration's own JSON** (section 3.1.1) and the statement comes back unmodified
in the response (section 3.2.1).

```
POST /oauth2/register
  { "software_statement": "eyJhbGciOiJSUzI1NiIsInR5cCI6InNvZnR3YXJl…",
    "client_name": "Acme Mobile" }

201 { "redirect_uris": ["com.acme.mobile:/oauth2/cb"],   <- from the statement
      "client_name": "Acme Mobile",                      <- from the JSON
      "software_statement": "eyJhbGciOiJSUzI1NiIsInR5cCI6InNvZnR3YXJl…",
      "client_id": "sts-client-…", … }
```

**Who is trusted is declared, exactly as an RFC 7523 assertion issuer is**:

* **this realm itself**, for a statement issued from an application's own page
  (*Software statements → Issue a statement*) or
  `POST /admin-api/applications/issue-software-statement`. It is typed
  `software-statement+jwt`, names the issuer published at the address the
  request arrived on, names the application in `sub`, and is signed with the
  realm's key — so in development mode it stops verifying at the next restart;
* **an application declaring the issuer** in `oauthSoftwareStatementIssuer` —
  the software publisher — whose statements verify against its `jwks`, its
  RFC 7523 key pair from `/admin/pki`, or an `x5c` this realm issued to it.

Everything else is refused **in every mode**: a document that is not a JWS, is
unsigned or HMAC-signed, names no `iss`, does not verify, has expired, is
addressed (`aud`) to another server, or is one of this realm's OTHER JWTs is
`invalid_software_statement`; an issuer nothing declares is
`unapproved_software_statement`. `oauth2.softwareStatementRequireTrustedIssuer`
turns the second refusal off, and a statement accepted that way is recorded as
UNVERIFIED and its claims lose to the JSON.

**In product mode a trusted statement is the second door through a closed
endpoint**: with `oauth2.openRegistration` off, a registration carrying one is
accepted while `oauth2.softwareStatementOpensRegistration` is on (the default),
and `registration_endpoint` stays in the discovery documents. A client admitted
that way must present a trusted statement from the same issuer with every RFC 7592
update, so it cannot PUT the metadata the statement fixed away.
`oauth2.softwareStatementRequired` demands a statement on every registration.
**A statement is not spent**: section 2.3 expects every copy of the software to
present the same one, so no `jti` history is kept. The entry records how a
statement let a client in as `appSoftwareStatementIssuer`,
`appSoftwareStatementTrusted` and `appSoftwareStatementPublisher`.

#### The two applications that are this process

Every entry described so far arrives because somebody *presented* an identifier.
Two applications never do — the **admin console** at `/admin` and the
**management API** at `/admin-api` are surfaces of this process, so no caller
ever names them — and until they were seeded, the one question this registry
exists to answer came back with everything except the two things the reader was
standing in.

They are created at startup, under `ou=applications` with everything else, and
they are **full RFC 7591 registrations rather than labels**: `sts-admin-console`
is a confidential OpenID Connect relying party on the authorization code grant,
`sts-management-api` is a confidential OAuth client on `client_credentials`, and
each carries a `client_secret` and a registration access token minted at start.
So they are clients that can be *exercised* — `clientConfigOf()` answers for
them, RFC 9700 mode checks those secrets by the same rule it checks anybody
else's, and `GET /oauth2/register/sts-admin-console` hands back the registration
to whoever holds its token — rather than two rows on a page.

Two things about them are deliberately *not* true, and both are on the entries
rather than in a footnote, because this container is the registry and an
`ldapmodify` of either is a configuration change. **Nothing serves
`/admin/callback`**: the console's gate is a sign-on session and two directory
groups, not an OAuth flow, so that redirect URI is what the console *would* use
if the gate ever moved onto OIDC. And the management API's two scopes —
`admin:read`, `admin:write` — **grant nothing**, because nothing under
`/admin-api` is gated at all; they are named after the console's two roles and a
scope that looked like a permission without being one would be worse than no
scope.

They are seeded only where the identifier is free, which is the rule the SPIFFE
registration entries follow: an operator who deleted one of them meant it, and
re-creating it would make the delete button appear not to work. Nothing here is
persisted, so the next restart seeds them again — with new secrets.
`applications.seedInternal` turns the whole of it off, and is restart-only
because it happens once, as the directory hands the registry its store.

#### The schema, and what "schema" can honestly mean

`node-ldapjs` has **no schema subsystem**. It is protocol machinery — messages,
filters, DN parsing, a client and a server — and the only three mentions of
`objectClass` in its whole `lib/` tree are a default search filter and the names of
result codes 65 and 69, which a server would have to raise itself. It is also a
submodule this repository does not modify. So there was nothing to extend and
nothing to register with: the schema is defined in `applications.js`, published on
the page, and **enforced by nothing** — a vocabulary, not a constraint, exactly
like the rest of this deliberately schemaless directory.

Where a standard name exists it is used. `applicationProcess` (RFC 4519) is the one
registered object class that fits an application at all, and it brings `cn` and
`description`. What it does not bring is a `client_id`, a set of redirect URIs, an
`entityID` or a service principal name — no registered LDAP schema has those,
because every product that stores OAuth clients keeps them in its own database
rather than in a directory. So `stsApplication` is invented, and its attributes are
this service's own names in the way `x509subject`, `didSubject` and `authnMethod`
already are on the user entries next door.

The table is the definition: `GET /admin/ldap/applications` publishes it, the entry is
built by walking it, and an attribute that is not in it is refused rather than
written. `multi` accumulates a repeat and `single` is assigned — which is what stops
a counter growing a value per sign-in, the trap `applyVcAttributes()` writes its
second rule about. Beside the identity and the counters (`appAuthentications`,
`appSessions`, `appUsers`) sit the protocol-specific ones: `oauthClientId`,
`oauthRedirectUri`, `oauthGrantType`, `oauthTokenEndpointAuthMethod`,
`oauthConfidential`, `samlEntityId`, `samlAssertionConsumerService`, `wsfedRealm`,
`wsfedReplyUrl`, `wstrustAppliesTo`, `krb5ServicePrincipalName`, `oid4vpClientId`,
`federationPartnerId`, `ldapBindDn`, `scimClientId`, `spiffeWorkloadId`.

**Every protocol family has an identifier attribute, and all of them accumulate
bar one.** Fourteen families, eleven attributes — three families share
`oauthClientId` (an OpenID Connect relying party *is* an OAuth client, and an
OpenID4VCI wallet authenticates as one) and both SAML profiles share
`samlEntityId`, because those specifications genuinely share the identifier and two
attributes for one fact would be two spellings that disagree the first time either
was edited. They are `multi` because one application legitimately answers to two
`client_id`s or two SPNs — one per environment being exercised — and a `set` would
replace the list with one value and read afterwards as the others having been
forgotten. The exception is mutual TLS's `oauthTlsClientAuthSubjectDn`, which stays
single-valued because RFC 8705 section 2.1 matches a certificate against "the single
expected subject" — and a client registers at most one of the five subject
parameters, of which that is one.

**Four of them are declaration and only ever declaration.** Nothing in this service
writes `federationPartnerId`, `ldapBindDn`, `scimClientId` or `spiffeWorkloadId`:
LDAP and SCIM authenticate the *caller* rather than an application identifier,
SPIFFE files the identity under `ou=spiffe`, and a federation relationship lives
under `ou=federations`. They exist because *what is this application called when it
talks to us that way* is a fact an operator has and the registry had nowhere to put
— and, like everything else here, a value in one grants nothing.

Two attributes hold **credentials in the clear** — `oauthClientSecret` and
`appRegistrationAccessToken` — in a directory where every bind succeeds and whose
contents are printed on an unprotected page. That is the same decision
`/krb5/principals` makes about the Kerberos passwords and the same reasoning: a
debugger whose accounts are unusable without reading the source is worse than one
that says what they are. Be precise about what it costs now that RFC 9700 mode
*checks* that secret: anyone who can read this directory can authenticate as that
client. They are never written to the audit log — `audit.js`'s rule that no
credential is ever recorded stands untouched.

One honest limit. `appSessions` and `appUsers` are counts of distinct ids, and the
ids themselves are deliberately not on the entry — an application used by two
thousand people would otherwise carry two thousand values. So the count increments
when the id differs from the *last* one recorded, which is right for the ordinary
case and undercounts somebody alternating between two applications. That is the
trade for not putting an unbounded list in a directory entry, and it is why the
schema calls them counts rather than lists.

#### The console page and the API

`/admin/applications` is the other side of `/admin/users`: that page lists every
identity that has authenticated here, this one lists what they authenticated *to*.
Filter by identifier or name and by kind, page with `?page=` and `?per=`, and
`?application=<id>` drills into one — every attribute of its directory entry with
what the published schema says each attribute *is*, paged under `?attributesPage=`
so the control moves that list rather than the page it sits on. `?format=json` is
the same data, and `GET /admin-api/applications` is the same view again with the
same parameters.

**"Every attribute" is meant literally, and for a while it was not true.** The
registry handed these pages the record it had reconstructed rather than the entry
it had read, and a record has no room for three kinds of fact: the DN, because
that is not an attribute at all but the key the entry is stored under; the
operational attributes `createTimestamp` and `modifyTimestamp`, which the
directory sets and no schema of the registry's would ever mention; and anything an
`ldapmodify` had written by hand, which a schemaless directory permits and this one
therefore has to be able to show. On top of that, twelve attributes were read into
named members of the record — `cn`, `objectClass`, `appIdentifier`, both sighting
times, the three counters — and so were absent from a table headed *every attribute
the entry carries*. The read side of the store now hands back the whole entry, the
same shape the console already gets for a person's, and the pages show what is
there.

The DN is published as **`entryDN`** — RFC 5020's name, and the name an
`ldapsearch` filter matches it by here — and it is **synthesised on every read
rather than stored**. A stored copy would be a second definition of the same fact,
and the one that goes stale: `applicationEntry()` exists precisely because somebody
can rename one of these entries, and it finds it again by `appIdentifier`
afterwards. It appears at the top of the drill-down, on every row of the list, on
`/admin/ldap/applications`, and as `dn` on every application in the API's reply — because
these entries *are* the registry, so the DN is the address an `ldapsearch` or an
`ldapmodify` is aimed at, and a console that showed only the `cn` left an operator
reconstructing it from a naming rule published nowhere.

The names come back **canonically spelled** — `oauthClientId`, not
`oauthclientid`. The applications schema is one of the four sources the
directory's spelling table is built from; *How an attribute name is spelt*, in
the LDAP section below, is the rest of it. A page showing `oauthclientid` beside a
published schema that says `oauthClientId` reads as a bug in the page rather than
as what it is.

Both **write** as well as read: `create`, `set`, `add`, `remove`,
`revoke-registration` and `forget`, as forms on the page and as
`POST /admin-api/applications/{action}`. The console is not a third store beside
the protocol endpoints and LDAP — every action calls a function in
`applications.js` which does the same read-modify-write against the same
`ou=applications` entries, so a form post and an `ldapmodify` are one act arriving
by two routes, and each is visible to the other immediately because nothing caches.

**What may be changed is DECLARED and not DERIVED**, and that line is the whole of
the design. An entry holds both kinds. *Declared* is what this application is
allowed to do — its redirect URIs, grant types, scopes, secret, whether it is
confidential — which is configuration, is what RFC 9700 mode reads, and is
editable. *Derived* is what happened: the counters, the first and last sighting, the
kinds and protocols it has been seen in, the redirect URIs it actually used. A form
that could rewrite those would make the page lie about the service's own behaviour,
in a way indistinguishable from the recording being broken, so they are refused with
a list of what is not. `ldapmodify` still reaches every one of them — an operator
with an LDAP client is doing something deliberate, and refusing them *here* is the
difference between offering an operation and merely not preventing it.

Two consequences worth having in mind. **`create` is how you configure a relying
party before it connects** — an entry normally appears because an identifier was
*accepted*, and without this there was no way to give an unregistered client its own
redirect URIs short of `/oauth2/register` or the global `oauth2.redirectUris`
setting. It records that it was created by hand, so it cannot be mistaken for one
that turned up once and never came back. And **`forget` is the one operation that
loses a fact**, which is why it is separate from `revoke-registration` rather than
something that one does as well: revoking keeps the entry and its history and takes
only the registration, the secret and the registration access token away.

#### `/admin/applications/new`, and the protocol families an application is *declared* for

`create` has a page of its own as well as the row at the foot of the list. Name a
`client_id`, `wtrealm`, `AppliesTo`, entityID or service principal name that has
never connected, tick the **protocol families** it is declared for from a closed
list of fourteen — OAuth 2.0, OpenID Connect, SAML 2.0, SAML 1.1, WS-Federation,
WS-Trust, Kerberos v5, OpenID4VCI, OpenID4VP, Federation, LDAP, SCIM 2.0, SPIFFE
and TLS / mutual TLS — and fill in **what each protocol will call it** and **where
its responses go back to**. They land on `appAllowedProtocol` and on the schema's
own attributes, and `GET /admin-api/applications/new` answers the same vocabulary
as JSON so a caller can read what a create will accept off the service rather than
off this page. `POST /admin-api/applications/create` takes the families as
`protocols` and the attributes as `fields`, keyed by attribute name.

**It can be configured from a protected resource's own metadata (RFC 9728).**
Tick *Use a protected resource metadata document* and paste the JSON, upload the
file, or name the URL it is published at (usually
`https://<host>/.well-known/oauth-protected-resource`). The page answers with the
document in three tabs — the raw JSON, a table of its values, and the fields read
from it, editable — and the create form filled in: the document's `resource` as
the default **name**, as `oauthPermissionBaseUri` and as `oauthAudience`; one
**permission** per `scopes_supported` value, with the resource prefix taken off
(`https://api.example.com/read` under `https://api.example.com` is `read`); a
**client_id** generated at random; and OAuth 2.0 ticked. Nothing is created until
Create is pressed. The document is kept on the entry as `oauthResourceMetadata`
(and `oauthResourceMetadataUrl` where it was fetched).

* **Its `authorization_servers` are compared with this trust realm's.** Every one
  that is an issuer this realm publishes is shown green; one that is not is a
  warning, and the application can still be created.
* **A fetch follows the federation outbound policy** — `federation.outbound`,
  https unless `federation.outboundAllowInsecure`, no redirects,
  `federation.maxResponseBytes`, `federation.outboundTimeoutMs` — and needs Admin
  Write, because a URL here is one an administrator names.
* **In product mode** the URL may not resolve to a loopback, private, link-local or
  reserved address (the name is resolved once and the connection pinned to the
  checked address), and a document whose `resource` is not the identifier its
  well-known URL was built from (section 3.3), or is not https, is refused.
  Development mode reports both and imports. A malformed document is refused in
  both.
* `signed_metadata` is decoded and shown, and **not verified or applied** — this
  service holds no key for the resource.

`POST /admin-api/applications/load-resource-metadata` does the same for a JSON
caller (`document` or `url`) and answers with the proposed application in `plan`;
the create is then `POST /admin-api/applications/create` with those values.

**There is no *Kind* select, and its absence is the point rather than a tidy-up.**
The page used to carry one beside the families, and they were two vocabularies for
one question that did not line up: eight kinds against fourteen families, five of
those families having no kind at all, and a reader made to choose in both. They are
also on opposite sides of the line this registry draws everywhere else — a family is
*declared* and a kind is *derived*, written when a protocol actually recognises the
identifier — so the select let a form assert a sighting that had not happened. The
families won because they are what an operator is actually declaring; the kinds
fill themselves in as the application is used. `POST
/admin-api/applications/create` still accepts `kind`, because *Register* on
`/admin/saml2` and `/admin/saml11` passes one, and that is a protocol module's
statement rather than a person's guess in a select.

**The identifiers and the redirect URIs are the reason the page exists as much as
the families are.** Before them a create took an identifier and a name and nothing
else, so every attribute that actually *configures* an application — the
`client_id` RFC 9700 mode reads, the redirect URIs it matches against, the
`entityID`, the `wtrealm` — had to be added afterwards, one `add` at a time, from a
different page. There are eleven identifier fields for the fourteen families and
three redirect-URI fields, because only three families send a response back through
a browser: `oauthRedirectUri`, `samlAssertionConsumerService` and `wsfedReplyUrl`.
Multi-valued fields take **one value per line** — newline-separated and
deliberately not comma-separated, since a redirect URI may legally contain a comma
and may not contain a newline, and splitting on the wrong one would cut a URI into
two that each fail to match. Only the OAuth list is ever checked, and only in RFC
9700 mode; the SAML and WS-Federation ones are recorded and not checked, in the way
everything else here is.

**It is not a second store, or even a second door onto one.** The form posts
`action=create` to `/admin/applications` — the same action the list page's own row
posts, calling the same function in `applications.js` that a protocol endpoint and
an `ldapmodify` reach. What it adds is room: fourteen choices with a sentence each,
plus fourteen fields, is a set of tables rather than a form row, and the inline
version sits below the paging, so on a service with forty applications the one
control somebody came for is off the bottom of the screen. That inline row is still
there and still takes an identifier and a name — the short way in for somebody
already looking at the list.

**The entry lands in the directory of the trust realm the console is showing**, at
that realm's `ou=applications` — the console shows one realm at a time, and the
directory is a subtree per realm. An `ldapsearch` under that realm's base DN sees
exactly what this created; another realm's registry has never heard of it.

**Declaring a family grants nothing and refuses nothing**, and this is worth being
plain about because a page of checkboxes headed *protocol families it is declared
for* is the most permission-shaped thing in this console. Nothing in this service
reads `appAllowedProtocol`: an application declared for SAML 2.0 alone is still
issued an access token at `/oauth2/token`, and one declared for nothing at all is
treated exactly as it would have been. It is a record of intent on the entry — the
same claim *an entry here grants nothing* already makes about the whole registry —
and it is deliberately not a check, because a mock that refused a protocol would
remove a test case rather than add one. What *does* take effect is the
configuration underneath: the redirect URIs, the grant types and the secret, which
RFC 9700 mode reads.

**`appAllowedProtocol` and `appProtocol` sit next to each other and must not be
read as one thing.** The first is declared and editable; the second is what
happened, accumulated by the endpoints, and is refused to every form here. The
drill-down shows them side by side under *Protocol families*, with a **Declared**
column and a **Recorded** one — and the match between them is made on the entry's
*kinds* rather than on the protocol labels, because a federation partner's sighting
is recorded under whichever protocol its relationship speaks and by label is
indistinguishable from an ordinary OAuth client's. *Recorded* is also not the same
as *has authenticated*: `POST /admin-api/applications/create` and the two SAML
*Register* buttons take a kind, so a hand-made entry can be recorded in a family it
has never connected in, and the Authentications count is the figure that answers
that. No console form asks for one any more, which makes that the narrow case it
always should have been. Four families — LDAP, SCIM, SPIFFE and mutual TLS,
and OpenID4VCI beside them — have no kind at all, because this service records no
application identifier in them; those rows say *never recorded here* rather than
*no*, since the question cannot be answered rather than having a negative answer.

The page marks `oauthClientSecret` and `appRegistrationAccessToken` as credentials
where it prints them, and says on both the list and the drill-down that an entry
here **grants nothing**: the one place the registry is read is RFC 9700 mode, and
with that off these entries are a record and nothing more. Two counting caveats are
on the page rather than left to be discovered — `Sessions` and `Users` count
*changes* rather than distinct sets, and `?kind=` does not partition the list,
because a record commonly carries two kinds.

#### What it is for next

RFC 9700 mode already reads it, and reads it through `clientConfigOf()` — which
takes the **attributes** rather than the registration document, precisely because
those two stopped being the same thing once the console could create an application
and give it redirect URIs with no registration behind it. So the exact-match
redirect-URI check, the public-versus-confidential determination and the
client-secret check all resolve to attributes on an entry, and it does not matter
whether a registration, a console form, the management API or `ldapmodify` put them
there. `appRegistered` records *how* an application got here, not whether what it
holds counts.

That is what makes the switch worth having: set `oauthTokenEndpointAuthMethod` to
`none` and a client becomes public — PKCE required of it, its secret no longer
checked — and set it back and it does not. One `client_id` exercises both halves of
section 2.1.1 without restarting anything. The federation work — trust
relationships with other identity providers over OAuth 2.0, OIDC, SAML 2.0 and
WS-Federation — is the reason the key is the identifier rather than the protocol,
and the reason an application accumulates kinds instead of being filed twice.

#### CORS: which pages may read an answer

Until 2026-09-13 every response carried `Access-Control-Allow-Origin: *`. It is an
**allowlist on every path** now, in both modes, and an application's
**`appCorsOrigin`** — a list of exact origins such as `https://spa.example.com`,
no path, no wildcard — is where a third-party origin goes on it. An origin is
echoed back when:

| The request | The origin must be |
|---|---|
| comes from this service's own origin — the address it was made to, `global.publicBaseUrl`, the 8443/9443 listeners, the embedded debugger, or `global.corsOrigins` | nothing more: always allowed |
| **names a client** — a `client_id` in the query or body, a `client_assertion`'s `sub`, `/oauth2/register/{client_id}`, a Basic user name, a JWT access token's `client_id` or `azp`, a GNAP instance reference | listed in **that application's** `appCorsOrigin`. A name no application answers to gets no CORS header at all, so a page sees a CORS error rather than `invalid_client` |
| **names no client** — discovery, a JWKS, a DID document, credential issuer metadata, and **every preflight** (which carries no body and no `Authorization`) | listed by **any** application in the realm |

**An empty list allows no third-party origin.** Nothing sends
`Access-Control-Allow-Credentials`; the answer exposes `WWW-Authenticate`, `DPoP-Nonce`,
`Location`, `Link`, `Replay-Nonce` and `Retry-After`; every response carries
`Vary: Origin`; a navigation (a SAML or WS-Federation form post) is left alone; and in
RFC 9700 mode `/oauth2/authorize` still gets no CORS header for anyone. Values are
stored normalised (`HTTPS://App.Example.com:443/` is held as `https://app.example.com`),
and a path, `*`, `null` or a user name is refused (`STS-REG-0150`). Set it from the
application's page, `POST /admin-api/applications/add` with `attribute:
appCorsOrigin`, or `ldapmodify`; RFC 7591 registration has no member for it. A
withheld header is logged as `STS-HTTP-0019` (a preflight), `-0020` (no client named),
`-0021` (unknown client) or `-0022` (the client does not list the origin).

### The admin console

`GET /admin` is an operator's view of the running service, and the pages under it exist for a reason the protocol endpoints cannot serve: the interesting behaviour of a client is what it does when something changes *underneath* it. A client that gets a good token and reads it correctly is a client that has been tested against the easy half. What happens when the token it is holding stops being valid, or when the token it reads grows a claim it was not expecting, is the other half, and until now there was no way to cause either without editing this service and restarting it. Every page also answers `?format=json` and every form also accepts a JSON body, because a console reachable only by clicking is a console no test can assert against.

**Every page here carries a breadcrumb trail, and on a drill-down it goes back to the list *as you left it*.** One line under the nav — `Admin console › Applications › rfc9700-debugger` — on every page including `/admin` itself, where it is the single crumb. The nav answers *what else is there*; the trail answers *where am I and how do I get back*, and those are different questions: the tab for the section you are standing in is exactly the tab that tells you nothing about the page you are standing on. That was the whole of the original bug — the active tab is drawn as plain text, and the page it names is the section's path on the list page and on every drill-down beneath it alike, so on `/admin/applications?application=rfc9700-debugger` the one control pointing at the list of applications was the one control the shell had switched off. On a drill-down that tab is now a link too, still bold because the reader is inside that section and underlined so that *the section you are in* cannot be read as *not clickable*. The last crumb is never a link: it is the page being drawn, and a crumb that reloads the page you are on teaches a reader not to trust the ones beside it. A long leaf is cut to 44 characters with the whole of it in the tooltip, because a `did:jwk` is a few hundred characters of base64url with nowhere a browser will break a line and a trail that wraps to four lines is not a trail.

**What makes it a breadcrumb rather than a link to the section is the list state it carries.** A drill-down link is built with the filter and the page the reader is looking at — `?q=client&per=25&page=3&application=beta` — and the trail's section crumb spends exactly that, so *back* lands on page 3 of that filter instead of the top of everything. Which parameters belong to a list is a **whitelist per section** (`LIST_PARAMS`) rather than *everything that is not ours*, for the reason the tokens page rebuilds its `back` field from a list of names: what comes out of it goes into a URL this service hands to a browser. Three things would otherwise drop it and each is handled where it is. Every control on a drill-down carries the whole current query already, so paging the five tables on a user's page keeps it for free. The *rows per table* form is a GET form, which posts its own fields and nothing else, so the filter is spelt out as hidden inputs — but deliberately **not** the list's page, since `per` is the thing that form changes and page 4 of fifty-row pages is not page 4 of anything afterwards. And every form on the applications and authorization-server drill-downs carries the list as one opaque `back` field, which the POST handler **rebuilds** through the same whitelist rather than echoing — a redirect target taken out of a request body is an open redirect and one carrying a newline is a header injection, so the worst a hand-written `back` can reach is another page of the same list. Without that last one, editing an application would silently cost the reader their place, which is the one thing the trail exists to keep. Four views take a trail leaf, the four that drill in: `?user=`, `?group=`, `?application=` and `?profile=`. A parameter that only *filters* a list does not, because there the tab already goes to the unfiltered page and the filter has its own **clear** link. `?format=json` ignores all of it — a way back up is a property of a page somebody is reading, and a caller has the URL it asked for.

**`/admin/metrics`** counts endpoint calls by the route Express matched — the pattern, `/oauth2/register/:client_id`, not the URL, or every registered client would get a row of its own — with the status classes, the average and worst latency and when it was last called. Then every token by `typ`, with how many are valid, expired, revoked, not yet valid and DPoP-bound; every assertion, ticket and credential the same way. All of it is computed **when the page is drawn** rather than kept up to date as things happen, and that is the load-bearing choice: "valid" and "expired" are functions of the clock, so a counter incremented at issuance is wrong a second later and would need a sweeper to stay right.

**Sessions are reported twice, and the two numbers disagree on purpose.** A *sign-on session* is a real one — a browser holding the `sts_session` cookie, the store `oauth2.js` owns and WS-Federation shares. An *artifact-derived session* is an inference, and it is a definition rather than a measurement, so the page states it: a subject has one in a protocol family when that family has issued it at least one artifact that is still valid. A `client_credentials` token is the second and not the first (no human, no browser); a browser that has signed in but been issued nothing is the first and not the second; a Kerberos client is never the first at all. Within Kerberos a **TGT counts as the session and a service ticket does not**, because that is what they are — the TGT is the credential the session consists of, and a service ticket is one use of it, so counting both would report the same session twice.

**`/admin/users`** answers the question the other pages cannot: *who has this service seen, and what do they hold right now?* It lists every userid presented as part of an interaction that **succeeded** — the name typed at either sign-in screen, the one on a password grant, the subject of a WS-Security `UsernameToken` or of a WS-Trust `OnBehalfOf`, the client principal in a Kerberos AS-REQ or in an AP-REQ this service accepted (over a raw socket or through SPNEGO), and the subject of an exchanged token. A request that was *refused* records nothing, so this is a list of identities that got somewhere rather than of names that were tried. `?user=<name>` drills into one: the names they were seen under, every authentication with the method that performed it, each sign-on session they hold **with the tokens issued on that session underneath it**, the tokens that belong to no session, and the assertions, tickets and credentials issued to them. A `revoke-user` button invalidates everything revocable for that identity under any of its spellings.

**Two decisions there are worth stating before changing anything.** The first is what *one row* is. A single person reaches this service as `alice` at the login screen, `urn:uuid:<entryUUID>` in every token (`urn:sts:user:alice` before 2026-09-14, still read), `alice` as a SAML `NameID` and `alice@EXAMPLE.COM` as a Kerberos principal, so the identity is keyed on the **local name** — a `urn:uuid:` subject resolved through the directory to the entry's current name (so a rename does not split a user into two rows), the legacy prefix stripped, and the realm split off at the last `@`. Four rows for one name would be a worse answer than one on a service whose whole premise is that the name you type is who you are in every protocol at once. What that costs is real and is shown rather than hidden: two different people called `alice` in two Kerberos realms are one row, which is what the Realms column exists to make visible. Case is never collapsed, because nothing else here treats `Alice` and `alice` as one person. The second is that the list is built from **three** sources — the authentications recorded, plus every token's `sub`/`username`, plus every artifact's subject — because an identity can be issued something here without ever having authenticated here: a token exchange presents somebody else's token, a WS-Trust `OnBehalfOf` names a delegated subject, an anonymous RST issues an assertion for `anonymous`, and a Kerberos S4U2Self ticket is for a user who was never near this KDC. Such a row is listed and **marked as never authenticated**, because a users page that showed only the sign-ins would deny the existence of subjects the tokens page is displaying at the same moment. The same honesty runs through the methods column: "sign-in screen (password)" and "AS-REQ with PA-ENC-TIMESTAMP" are both authentications and only one of them checked anything, and an S4U row says the user was not there and names the service that asked in their stead.

**Putting a token under a session needed one thing that is not on the wire, and it is deliberately not a claim.** No token this service issues carries a session identifier — OIDC's `sid` is for front-channel logout, and inventing one for every token to make an admin page easier to draw would change what every client receives. So `signJwt()` takes an optional third argument, a `context` that is signed into nothing and sent nowhere, and the recorder stores its `sessionId` and `grant` on the token record. The link is threaded where it genuinely exists: the session id rides on the authorization code (the only route to a back-channel token request, which arrives with no cookie behind it), the token endpoint passes it on, and a **refresh** looks it up by the refresh token's own `jti` — without which the second generation of every token would show as sessionless and a session's list would quietly stop growing the moment a client refreshed. A grant that never had a session says so: `password`, `client_credentials`, the pre-authorized code and token exchange are shown as issued with no browser session at all, which is a fact about them rather than a gap in the recording. Tokens naming a session this service no longer holds get their own heading, since that is the ordinary end state rather than an error — the session expired and the tokens it produced outlived it.

**A user's page also shows that user's LDAP object, and the dependency that puts it there runs the opposite way from the call.** Every person who authenticates anywhere here already grows an entry at `uid=<name>,ou=users,<base>` (see the directory's own section below), so by the time somebody has a page in this console they usually have a directory object too — and the two are the same authentication seen from two sides, which is the reason for showing them together rather than making a reader find the object again on `/admin/ldap/directory`. What is shown is the entry itself and not a copy: its DN, where it came from (`seed` or `authentication`), its two generalized-time stamps kept in the directory's own punctuation rather than converted to the ISO 8601 the rest of the console uses, and **every attribute with every value, the operational ones included** — a search returns `createTimestamp` and `modifyTimestamp` only when they are asked for by name (RFC 4511 section 4.5.1.8, which `toSearchEntry()` honours), but this is not a search, and a dump that silently dropped two of an entry's attributes would be the one thing a dump must not do. `?format=json` carries the same object under `ldap`.

Where there is no entry the section says **which** of the five reasons it is, because four of them are facts about the user rather than about the directory and "not found" alone would send a reader looking for a bug: auto-creation is switched off, the identity is a *client* and not a person, it has never authenticated here at all (it is known only as the subject of something that was issued), everything it has ever done here is an *LDAP bind* — which presents a DN and not a user name — or the entry was there and has since been `delete`d or `modifyDN`'d through the protocol. It also lists any **other** entry whose `uid` names the same person — which is now a report about entries *outside* `ou=users`, since inside it one person is one entry and every door enforces that — and it says so loudly when the directory's listener is down: the entry can be in this process's store while no client can connect to read it, and only one of those two facts is visible from an HTTP page. The dependency is the thing to be careful with. `admin.js` does **not** require `ldap_server.js` — `server.js` requires the console first (rule 6: the directory needs `admin_stats`' identity normalisation, and the console reads `oauth2`'s sessions), so a require from the console would drag the directory's routes into the router *ahead* of its own, and `/admin/sts-metadata` is built by walking that router. So the direction is inverted the same way the user observer is: `admin.js` offers `setDirectoryReader()`, `ldap_server.js` fills it at its own require time with a function that takes the identity key the console files a person under — the same normalised local name the entry's DN was built from, so the two cannot drift — and a build of this service without the directory renders the section as "no directory is loaded", which is a different answer from an entry that is not there.

**The page has exactly one control, and since 2026-09-06 it is a door rather than a deed.** It carries a name and takes you to **`/admin/users/new`**, where the person is described. Until any of this existed `ou=users` could only be filled by authenticating or by an `ldapadd`, while `ou=applications` could be filled from three directions; a client that wanted claims read out of the directory had to sign somebody in first to make the entry it was about to read.

**`/admin/users/new`** is a box for every attribute a person in this directory can carry — the same catalogue *Credential claims* chooses from, so a value typed here is the value an issued credential asserts. **Only the username is required, and a box left empty records no value.** That is the whole of what changed: the button this replaced invented an entire person behind whatever name was typed — a full name, an email address, a date of birth, a street, a nationality — and an operator who knew the real ones had to correct the entry afterwards from outside the console. The invented person is still one press away as **Fill with example data**, which writes what this service *would* have made up into the boxes you left empty and touches nothing you have already filled in, creating nobody; it is development-mode only, and it is computed on the server, because this console is `script-src 'none'`. Leaving a field empty is not a promise it stays empty: the Populate button on *Credential claims* fills every missing selected attribute on every person and does not know which were typed.

**It is also where somebody is given a way in**, which no screen here could do before. Four choices: **a password generated and shown once** (the default since 2026-09-12, here and on `POST /admin-api/users/create` when `credential` is not sent — drawn by the `generate-password` package until it satisfies this realm's password policy); a password you type, held to that policy in product mode; no credential at all (enough in development mode, where no password is checked anywhere, and what `credential: none` still asks for); or **no credential and a single-use, time-limited activation link, shown once**, at which the person chooses a password, a security key or both at `/portal/activate`.

**The password policy is `/admin/policies`**, under Directory: a minimum length (12), how many previous passwords may not be reused (5), a minimum number of symbols (1), and whether an uppercase letter and a number are required (both yes) — the **default profile**, stored as `cn=default,ou=passwordPolicies` in the realm's directory in the shape of draft-behera-ldap-password-policy (`pwdMinLength`, `pwdInHistory`, with `pwdHistory` and `pwdChangedTime` maintained on each person), with the composition rules as this service's own `stsPwd*` attributes. Until it is saved the built-in defaults are in force. **It is enforced in product mode only**, at every door that sets a password — the console, `/admin-api`, `/portal/password`, `/portal/activate` (the first password a person sets) and an LDAP add or modify of `userPassword`, which is now hashed on the way in rather than stored as sent. Development mode checks no password, applies no rule and records the history anyway. `GET /admin-api/policies` and `POST /admin-api/policies/{save-password-policy,reset-password-policy}` are the same over HTTP. The last two are shown in the body of the page that comes back rather than in a redirect, because what is stored is a scrypt hash and the value exists exactly once — a secret in a URL is a secret in the browser's history and in every proxy log on the way. Issuing another activation link invalidates the first, which is also how one that never arrived is replaced.

**The catalogue it offers is NOT the whole schema**, and that is worth knowing before looking for a box that is not there. It is the twenty-seven claim-bearing attributes *Credential claims* chooses from; a person in this directory is filed under `inetOrgPerson`, which allows fifty. So `departmentNumber`, `roomNumber`, `manager`, `carLicense` and the rest reach an entry over **SCIM** or over **LDAP** and not through this form — and all fifty are drawn on that person's own `/portal` Overview whether or not anything set them, with the LDAP name and the RFC under each, so somebody can see what is available before going to write it.

**A username that is already there is refused**, naming the entry that holds it — the same refusal an `ldapadd` gets as `LDAP_ENTRY_ALREADY_EXISTS` (68), because both call one function in `ldap_server.js` and the console is not a second definition of what a user is. `POST /admin-api/users/create` is the same act without a browser and takes the same attributes; `GET /admin-api/users/new` publishes the catalogue it validates them against, so a caller learns what it may send from the service rather than from a copy of the list in a document. One thing the page says outright rather than leaving to be discovered: **the new person does not appear in the table above** until they authenticate somewhere — that list is who this service has *seen*, and the entry is what the directory *holds*. It is the same distinction `/admin/groups` draws when it marks a member *never here*.

**A person's page has a *Password and second factors* section (2026-09-13)**, drawn for a holder of Admin Write, with six controls — each an action on `POST /admin/users` and on `POST /admin-api/users/{action}`:

* **Reset password** generates a password this realm's policy accepts, stores it, marks it for change at the next sign-in (`pwdReset`), withdraws any reset link, signs the person out everywhere, and shows the password **once**, on the page that comes back. The administrator passes it on.
* **Send a reset link** removes the current password (it goes into the history, so it cannot be set again), signs the person out everywhere, and shows a single-use link to `/portal/reset-password` once. The link lasts `security.passwordResetTtlMinutes`; issuing another replaces it. This service sends no mail: the administrator passes the link on. The person chooses a new password there without signing in.
* **Disable passkeys** removes every security key that could sign the person in on its own, and leaves their password and second factors alone. It is offered only while they have a password, so it cannot lock anybody out.
* **Disable all MFA** removes the authenticator app, every second-factor key and the recovery codes.
* **Require MFA** / **Stop requiring MFA** marks the person (`stsMfaRequired`), so the sign-in screen makes them enrol an authenticator app or a security key at `/authn/mfa-setup` before it starts a session. `authn.mfaRequired` does the same for everybody in the realm, and only at the sign-in screen.

Every one of them sends Shared Signals to the streams that asked: a CAEP `credential-change` for each credential created, updated or removed (password, `app`, `fido2-roaming`), a RISC `account-credential-change-required` for a reset and a reset link, and a RISC `recovery-information-changed` when recovery codes go. The older per-item Clear buttons and Set password send them too, and so does completing a reset link. `caep.autoEmitTypes` and `risc.autoEmitTypes` name the new types by default.

**`/admin/groups`** is the one page in this console that reports the *directory* rather than what this service has issued. It lists every group with what it is made of, and `?group=<dn>` drills into one: every attribute the entry holds, operational ones included, and every member resolved to the entry it names. Both views come out of `groupsFor()` in `ldap_server.js` through a third inverted hook — `admin.js` offers `setGroupReader()` and the directory fills it, for the same route-order reason `setDirectoryReader()` exists — and the console renders what it is handed without deciding anything, which matters most for the first decision below.

**It writes since 2026-09-06, and what is worth knowing is how long it did not.** This page could report a dangling member, a claimed membership and the two groups that decide who may use the console, and could create none of them: `/admin/groups` was a read, `/admin-api/groups` was a read, and the only two doors onto a group in this directory were an `ldapadd` on the raw socket and `POST /scim/v2/Groups`. There are two controls now. **Create a group** is on the list, below the table — the question this page is usually open to answer is what the directory holds, and a create form at the top would answer a different one first; it puts a `groupOfNames` at `cn=<name>,ou=groups` and takes members one per line or comma-separated, each a user name or any DN, since a group can hold another group and no user name names one. **Add a member** is on the drill-down, because it needs a group in hand; a create lands you on the group it just made, since that is where the control is. `POST /admin-api/groups/create` and `POST /admin-api/groups/add-member` are the same two acts without a browser.

Three things about them are decided in `ldap_server.js` rather than on the page, and each is this directory being consistent with itself rather than an omission. **A member that names nothing is written and not refused** — this directory does no referential integrity in either direction, so refusing here would make the *dangling* state this page exists to report impossible to produce from it. **An empty group is allowed**, although RFC 4519 makes `member` MUST on a `groupOfNames`: SCIM already creates one, and a console stricter than SCIM about the same store would be two doors disagreeing about what the directory holds. **Adding somebody already in the group changes nothing and is not an error**, so a script that adds on every run does not fail on its second one. Removing a member is not here — it is an `ldapmodify`, a SCIM `PATCH`, or *Admin roles* for the two groups that grant this console — and neither is deleting a group, which is an `ldapdelete` or a SCIM `DELETE`. A group made here still grants nothing, which the page says at the moment you have just made one.

**What counts as a group is two rules and not one.** An entry under `ou=groups`, *or* an entry carrying a group `objectClass` (`groupOfNames`, `groupOfUniqueNames`, `posixGroup`, `groupOfURLs`) wherever it sits. Both, because this directory is schemaless and nothing stops a client adding a `groupOfNames` under `ou=users` or an entry with no `objectClass` at all under the groups container — either rule applied alone answers correctly for one of those and quietly loses the other. The list says which rule caught each row, since "this entry is a group because somebody put it under `ou=groups` and it carries no group class at all" is the interesting fact and "developers is a group" is not.

**Membership is read from `member`, `uniqueMember` and `memberUid` together, and the third one is not like the other two**: it holds a bare user name where they hold a DN, so it is resolved under `ou=users` rather than as written. Treating the three alike is how a page ends up reporting every `posixGroup` member as dangling. Three disagreements are then reported rather than smoothed over, and every one of them is a state a client can reach in two operations:

* a **dangling** member — a value naming an entry this directory does not hold. Deleting a user does not remove its DN from the groups that list it, because referential integrity is a directory feature and not a protocol rule (see below), so the count of membership values and the count that resolve are shown as two numbers. One combined number would report a group whose seven members resolve to five as seven members with nothing wrong, which is precisely the thing this page exists to make visible.
* a member that is itself a **group**. Nesting is shown and never expanded: the row links to that group's own page and nobody inside it is counted here, because nothing in this service walks a group tree and a flattened list would be claiming a feature that is not here.
* an entry whose own **`memberOf`** names a group that does not list it back. `memberOf` is not a standard attribute at all — it is Microsoft's and OpenLDAP's, and in the directories that have it the *server* keeps it in step with `member`. This one keeps nothing in step, so a client can write it onto a user in one `modify` and create the disagreement. Those entries are listed under their own heading rather than merged into the members, because which side of the disagreement a name came from is the only interesting thing about it.

**A member links to `/admin/users` only for somebody this service has actually seen authenticate**, and is marked *never here* otherwise. The two lists answer different questions and it is worth being deliberate about the difference: the directory holds an entry for whoever somebody wrote one for — including `alice`, `bob` and `carol`, who are seeded at startup — while the users page holds whoever has presented a credential to this process. A link drawn unconditionally would usually land on "nothing here has authenticated as alice", which reads as a broken link rather than as the answer it is.

**A group here grants nothing, with exactly two exceptions**, and both pages say so where a reader will see it rather than leaving it to be discovered. No *endpoint* in this service checks a group and nothing in any protocol decides anything on one. On a service that authenticates nobody it could hardly be otherwise — but a console that listed groups a click away from the tokens page without saying it would let somebody conclude that adding a user to `cn=directory-admins` had changed what their token could do.

**The two exceptions are `cn=admin-read` and `cn=admin-write`, and what they grant is the admin console.** They are the two roles the console gate requires — see *Who may use the console* below — and they are ordinary group entries appearing on `/admin/groups` like any other, deliberately: the alternative was a membership store the console kept for itself, which an `ldapmodify` could not see and which would drift from the directory with nothing comparing the two. Even those two grant nothing outside `/admin`: no token's scopes change, no assertion gains an attribute, no Kerberos PAC is affected, and a member of `admin-write` gets exactly the same answer from `/oauth2/token` as anybody else. `groups.claim` carries `admin-write` into an access token exactly as it carries `developers`, where still nothing reads it.

**A token can carry one, which is a different sentence and the two must not be merged.** That half of the paragraph used to read "no access token, ID Token, SAML assertion, WS-Federation token or Kerberos PAC carries a group from this directory", and `groups.claim` is what made it false. With that setting on — it is **on by default** — every OAuth 2.0 access token, OIDC ID Token, SAML 2.0 assertion and SAML 1.1 assertion this service issues carries a claim naming the groups its subject is in, read out of these entries at the moment the token is minted. It is the same distinction this service already draws between an identity being **recorded** and an identity being **authenticated**, and it is drawn here for the same reason: carrying a fact is not acting on it. No Kerberos PAC carries a group either way.

Why it is worth carrying at all is the usual argument in this repository. A groups claim is one of the two or three things a relying party actually branches on, and until `group_claims.js` existed there was no way to produce one here — so a client whose authorization code has never seen a `groups` member, or has only ever seen names where the next identity provider will send DNs, has never run that code.

Four things about it are deliberate:

* **The claim is omitted entirely for somebody in no group** — not sent as an empty array, absent. That is what makes ON a defensible default: on a fresh start the only people in a group are the three the directory seeds, so a caller who has never touched `ou=groups` gets exactly the tokens it got before. An empty array would be a new member in every token every existing client parses.
* **The membership is read per token and never cached**, the same rule the applications registry follows and for the same reason: an `ldapmodify` changes the very next token, which is the thing somebody came here to watch.
* **Both membership rules are read** — `member`, `uniqueMember` and `memberUid` from the group's side, and the person's own `memberOf` from theirs. Nothing here maintains one from the other (that disagreement is a thing this page exists to *show*), so `groups.claimFromMemberOf` is which side a token believes; it is on by default, and either way the group has to exist here, since a `memberOf` naming nothing must not invent a group to put in a token. A group listing a DN nothing is stored at still counts: that is a **dangling** member from the group's side and is still the group saying so.
* **`groups.claimValue` chooses `cn` or the whole DN.** Both are what somebody's real identity provider does — an OIDC provider usually sends names and Active Directory sends DNs — and a client that has only ever parsed one has never run the other path.

A typed custom claim and a ticked directory attribute of the same name both **win over** it, because those were named on `/admin/claims` about this service and this comes from a setting and a directory. `groups.claimName` naming something this service sets itself (`exp`, `scope`, …) is **refused at issuance** and `/admin/claims` says why — the same rule a typed claim of that name meets at configuration time, made in the only place that can reach the reserved list. The claim reaches a SAML assertion as **one `<Attribute>` with several `<AttributeValue>` children**, which is what the content model means by multi-valued; one element per group with the same name is a relying party reading the first and silently seeing one group where the person is in four.

**`/admin/tokens`** lists what was issued and invalidates what can be. What it lists is **every JWT, every SAML assertion and every Kerberos ticket, in one table, newest first** — the assertions whether WS-Trust issued them or a WS-Federation sign-in did, since both go through the two builders and both are counted there. One table rather than three because a WS-Federation sign-in that produces an ID Token and a SAML 1.1 assertion is *one event*, and three tables would leave it to be reassembled by comparing timestamps. The three families are declared in `admin_stats.js` (`ISSUED_FAMILIES`) and `issuedList()` merges them, because which artifact belongs beside a token and what "still valid" means for each are statements about the state that file holds; `admin.js` renders what it is handed. Two things had to be made common to merge them at all: the state, which comes from one function per family against one clock, and the expiry, which is **normalised to milliseconds** — a JWT's `exp` is seconds and an artifact's `expiresAt` already is not, and one table cannot sort two units. A filter for the family sits beside the one for the kind, and the kind list is grouped by family and built from that same structure, so the two cannot come to disagree about which kind is which.

**A ROW IS ONE ISSUANCE RATHER THAN ONE CREDENTIAL, since 2026-09-05, and the reason is that one protocol family here hands back several at once.** Redeeming an authorization code returns an access token, a refresh token and an ID Token in a *single reply*; `response_type=id_token token` returns two in one fragment. OAuth 2.0 and OIDC are the only families that do it — a SAML assertion, a Kerberos ticket and a SPIFFE SVID are each one credential from one act — so every other row is a *set of one* and looks exactly as it always did. The grouping comes from an identifier the **issuer** stated at the moment it built the reply and never from noticing that two rows sit close together in time: two people redeeming two codes at the same client in the same millisecond produce six credentials that agree on every column of this table, and a table that merged them would report a handover nobody received. The identifier is in no token, no client ever sees it, and it is not a claim. **A set is one response and not one grant** — refreshing makes a new set beside the old one, because a set has one issued instant and one grant and a row that grew all afternoon could have neither; what joins the generations is the refresh lineage, drawn on each credential's own page. Three columns answer differently as a result and each says so where it is drawn: **State** reads `mixed` when the members disagree, which within the hour is most sets, because an access token and the refresh token beside it have very different lifetimes and choosing one would be the column deciding which member matters; **Expires** shows the first member to go and then the last; and **Detail** is the access token's scope, which the refresh token deliberately does not share. A filter matches a set when *any* member matches and the neighbours come with it — asking for `id_token` answers with the replies that contain one. `/admin/tokens/set` opens a reply and is the old table scoped to it, member by member, with each credential's own identifier, expiry and button; **Revoke set** does every revocable member in one act, into the same revocation set `/oauth2/revoke` writes to, which is what stops somebody revoking two credentials of three and believing the grant is dead while the refresh token left behind mints another. A set holding nothing revocable is refused rather than answered "revoked 0".

**Only the JWTs have a button, and the rows that do not are the reason to list them.** Nothing consults this service about a SAML assertion or a Kerberos ticket: an assertion is valid because its signature verifies and its `Conditions` hold, and a ticket because the service it names can decrypt it with a key it already has. So the only thing that ends one is its own expiry — and until it was on this page there was no way to see when that was, or to see that a sign-in had produced one at all. Each such row carries the reason there is no button in place of it, which is the honest version of the button this console deliberately does not offer. Because most columns then mean something slightly different depending on the row — `Detail` is a scope, or whether the signature was written, or the enc-type — the page carries **a legend saying which**, and the code is written one function per *column* answering for all three families rather than one per family, so a header like "Client, audience or service" can be checked against the three answers underneath it. Two of those answers are worth stating: a Kerberos ticket has **no identifier at all** to put in the `jti` column, because none exists for anyone to quote and the KDC keeps no handle on one either; and an assertion's `Detail` says signed or unsigned, which meant correcting the record in the two builders' `catch` blocks — the assertion is counted *before* the signing attempt on purpose, so an assertion that went out unsigned was being counted as signed, and a column showing that would have agreed with the page rather than with what left. **OID4VCI credentials are not in the table**, only counted on the metrics page; that is a gap rather than a principle, and the page says so rather than letting "everything this service has issued" be read as four families.

Invalidation is one `jti`, a whole kind, everything for one subject, or everything. **It is the same revocation `/oauth2/revoke` performs** — there is one set of revoked jtis in this service, not one per page. That mattered enough to move the set out of `oauth2.js`, where it was written, and into `admin_stats.js`: two sets would each look correct alone and never see each other, so a token revoked from the console would keep introspecting as active with no error message anywhere to point at. It is the same failure the single session store exists to prevent. A token revoked here is therefore reported inactive by introspection, refused by UserInfo with `invalid_token`, and fails the refresh grant with `invalid_grant`, immediately and without a restart.

The list is **filtered by family, kind and state and then paged**, newest first, with `?page=` and `?per=` — and in that order, because paging a list and *then* filtering it gives a page 2 whose length depends on what happened to be on page 1. Paging replaced a flat cap of 300 rows that showed the most recent matches and said underneath how many it had hidden; the cap survives as the ceiling on *one* page, since `?per=` is a number a caller types and without a ceiling `?per=5000` is exactly the page the cap existed to prevent. Everything held is now reachable rather than only the newest 300. Three properties are what make that safe to click through. An **out-of-range page is clamped to the last one** rather than answered with an empty table — a revocation sweep can shorten the list between two clicks, and an empty table reads as "nothing matched" when it means "that page has gone". The **filter form carries no page number**, so changing a filter or the page size returns to page 1 instead of landing on page 6 of a two-page result. And every button on the page acts on a **`jti` and never on a row number**, so a token issued or revoked between the render and the click cannot make the wrong token the target; the most it can do is shift a row onto another page. A revoke or restore button **returns to the page and filter it was clicked on** rather than to the top of an unfiltered list, which the row forms arrange by carrying the view as a hidden `back` field — and the redirect target is *rebuilt* from that field rather than echoed, because a redirect taken from a request body is an open redirect and one carrying a newline is a header injection. Only `family`, `kind`, `state`, `per` and `page` survive the rebuild, each re-encoded — plus, on the users branch of it, any parameter whose name *ends in* `Page` and whose value parses as a positive integer, which is the one thing a whitelist could not cover: a drill-down's session blocks have a page parameter each, named after the session, so the set of names is data rather than a list. The number is rebuilt from `parseInt` rather than passed through, so what lands in the URL is a number this service produced. The worst a hand-written `back` can reach is another page of the same table — and that list has to be kept in step with the filter form, because a parameter the form offers and the rebuild drops is a filter that silently resets itself the moment somebody revokes a token, which looks like the console losing your place rather than like a missing line. The bulk buttons keep the filter and drop the page, since after "revoke everything" page 7 is a page of a different list. Both parameters work with `?format=json`, whose reply carries `page`, `pages` and `matched` so a test can walk the whole list without guessing where it ends, and whose rows are in **`issued`** — each naming its `family`, and called `issued` rather than `tokens` since the day the array stopped being only tokens. Paging is links and a query parameter with no script behind it, because `script-src 'none'` is what makes the whole family of reflected-content problems moot here and the console does not get an exception.

**The two drill-downs page too, and they need more than one page number to do it.** `?user=` answers with five lists at once — the sign-on sessions, the tokens issued on each of them, the tokens whose session has since ended, the tokens that never had one, and the assertions, tickets and credentials — and `?group=` with two, its members and the entries claiming it back. A single `?page=` cannot serve those: clicking *next* under the artifacts would silently advance the sessions above them. So each list carries a page parameter **named after the array it moves** — `sessionsPage`, `tokensOnEndedSessionsPage`, `tokensWithNoSessionPage`, `artifactsPage`, `membersPage`, `claimedPage`, the reply's own member name with `Page` on the end and the object answering it the same name with `Paging` on the end — while `?per=` stays shared, because *rows per table* is one choice a reader makes for a page rather than seven, and because `per` is the parameter with the cap on it and one capped parameter is one place to get the cap right. Every control carries the whole current query and overrides only its own key, so moving one list leaves the others where they were. One of the seven is not in that list because **its name is data**: a session's own token table is moved by `session-<the session id>Page`, since one browser session can hold most of the five thousand tokens this service remembers and is therefore the one table here that genuinely runs away. It is named after the session rather than numbered so that the link still moves the same session after the list around it has changed — an index would move whichever session had drifted into that position. The session *blocks* start at five per page rather than fifty, because each of them is itself a table. Three lists on those pages are deliberately **not** paged and it is worth knowing which: the spellings an identity has been seen under, the protocols it authenticated through, and its authentication events. The first two are bounded by how many exist and the third is capped at fifty by the registry itself; all three also live on the `user` object that goes out whole in the reply, so slicing them for the table would either corrupt that object or duplicate it, and paging the table while the JSON stayed whole is exactly the console-and-API disagreement the rest of this console is built to avoid.

**The management API pages the same way and answers with the same words.** `GET /admin-api/users` and `GET /admin-api/groups` take those parameters and reply with a `<name>Paging` object beside each array — `sessionsPaging`, `membersPaging`, and so on — carrying `page`, `pages`, `perPage`, `firstRow`, `lastRow` and `total`: the member names the three flat lists put at the top level, one level down, so a caller that has learned to walk `/admin-api/tokens` walks these without being told anything new. Each session in the reply carries its own `tokensPaging` for the same reason its parameter is named after it. Every array in a drill-down is therefore **one page and not the whole list**, which is what `users` has always been on the list beside it. The counts around them are untouched: a group's `memberCount`, `presentCount` and `danglingCount` stay counts of the whole list, because *seven members, five of which resolve* is the fact that resource exists to report and a per-page count would not be an answer to it. The `session-<id>Page` parameter is described in the operation's prose rather than listed with the others, because OpenAPI has no way to spell a query parameter whose name is built at runtime and a `session-{id}Page` in the parameter list would generate a client that sends a literal `{id}`.

Three further details of that page are worth knowing before changing it. It keeps **the claims and never the credential** — not the signed token, not the assertion XML, not the ticket — because a page rendering a thousand live credentials in a form a browser will display is a page that leaks them, and the `jti` is all any button needs. Pasting a whole token works and **its signature is not verified**, which is safe rather than sloppy: the only thing read out of it is the `jti`, which is then looked up in this service's own registry, and a forged token yields a jti this service never issued — revoking one of those invalidates nothing. RFC 7009's endpoint *does* verify, because there the token is the credential being presented. And **Restore is offered and is labelled NON-SPEC**: no authorization server can undo a revocation, since a resource server may already have cached the refusal, but without it getting back to a working token means restarting the service and losing the signing key with it.

**`/admin/applications`** is the other side of `/admin/users`, and the second page here that reports the *directory* rather than what this service has issued. Where that page lists every identity that has authenticated, this lists what they authenticated **to** — every OAuth client, OpenID Connect relying party, SAML 2.0 or 1.1 service provider, WS-Federation application, WS-Trust relying party, OpenID4VP verifier and Kerberos service, one entry per unique identifier whatever protocol brought it. Filter by identifier or name and by kind, page with `?page=` and `?per=`, and `?application=<id>` drills into one: every attribute of its directory entry, each shown with what the published schema says it *is*, paged under `?attributesPage=`. It differs from `/admin/groups` in one way worth knowing — that page reports the directory, this one reports a **registry** that lives in it, so an `ldapmodify` here changes what the protocol endpoints do. It carries forms as well: create an application before it connects, and add, remove or set the attributes that say what it is allowed to do — never the counters or the sightings, which are what happened rather than what it may do. **`/admin/applications/new`** is the create on a page of its own, with the fourteen protocol families an application may be *declared* for as checkboxes and a field for each family's own identifier and redirect URIs; the declaration is a record of intent and nothing reads it, and of the attributes only the OAuth redirect URIs are ever checked, in RFC 9700 mode. See *Applications* above.

**`/admin/authorization-servers`** decides what each discovery document *publishes*. One process serves as many authorization servers as somebody configures — the path component both discovery shapes already carry selects a profile, and each can have its own endpoints, capabilities and issuer. Any member is settable, including one this service has never heard of. It is the one page here whose whole purpose is to be able to say something untrue, so every view computes the **drift** between what a profile publishes and what this service actually does. See *Authorization server metadata* above.

**`/admin/delegation`** answers a question no other page here can, and one most identity providers cannot answer at all: *who acted on whose behalf, through what, to reach what.* Three of the protocol families in this service can delegate and each calls it something different — Kerberos has S4U2Self, two flavours of S4U2Proxy and a forwarded ticket-granting ticket; WS-Trust has `OnBehalfOf` and `ActAs`; OAuth 2.0 Token Exchange has impersonation and delegation. All eight are recorded against ONE model, because the question somebody arrives with is protocol-independent: *alice never touched the back end, so why is there a ticket to it in her name, and who asked for it?*

Every act names the three **layers of the architecture** — the *initial identity* the credential is about, the *intermediary* acting on their behalf, and the *target* being reached — and a layer can be a person, an application, or both. The middle one routinely is both: `HTTP/frontend.example.com` has an entry under `ou=users`, because it authenticates, and an entry under `ou=applications`, because tickets are issued for it, and the page links to whichever of the two exist. An application marked *not in the registry* is not an error; that registry holds what this service has been ASKED ABOUT, and an RFC 8693 `audience` nobody has otherwise mentioned is exactly that.

**Impersonation and delegation is the axis worth reading first, and it is not a matter of degree.** Under a delegation the credential CARRIES the chain — an `act` claim, a composite `ActAs`, `S4U_DELEGATION_INFO` in the PAC — so the service at the far end can see who is really asking and can decide differently because of it. Under an impersonation nothing does, which means **this page is the only place that fact will ever be visible**: no reading of the token afterwards, at the resource server or in a log, can recover that a middle tier was involved. That is the property that makes a page like this worth having on an issuer rather than a client.

**Refusals are recorded and are most of what it is for.** A delegation that worked tells you the plumbing is connected. A delegation that was refused names the two accounts, the two attributes and which of them was missing, at the moment the KDC decided — and the text shown is the KDC's own, the same sentence the client was sent. A refused delegation appears in no other list here, because nothing was accepted, so no authentication was recorded; closing that gap is why this page keeps its own store.

A second table is **configuration rather than history**: who MAY delegate to whom, out of `msDS-AllowedToDelegateTo` on the front-end account and `msDS-AllowedToActOnBehalfOfOtherIdentity` on the back-end account, with the flags that stop delegation (`NOT_DELEGATED`) or enable protocol transition (`TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION`) beside them. It answers *why would this be refused* before anybody has tried — including the expensive case that is invisible everywhere else: a front end allowed to delegate but not trusted for protocol transition gets a ticket out of S4U2Self that is simply not forwardable, so classic S4U2Proxy then fails complaining about the evidence, two steps from the attribute that caused it. **It is Kerberos only, and that is not an omission**: Kerberos is the only family here that polices delegation IN THE ACT — on every request, whatever anything is set to. WS-Trust puts no authorization on either element and this service adds none. RFC 8693 leaves the policy to the authorization server, and **since 2026-09-01 this one has one**: see *Delegated permissions* below. Every act says which of the two it was, in the same column — the same picture, policed at one end and not at the other.

### Delegated permissions: who MAY reach what, decided in advance

**A THIRD REGISTER ON THE SAME PAGE, AND IT IS THE ONE YOU TYPE.** The table above is what HAPPENED and the Kerberos table beside it is somebody else's configuration; this is configuration of this service's own, in the shape Microsoft Entra ID uses, and `/admin/delegation` draws all three under headings saying which is which.

A **resource** application exposes an API: it is given a base URI (`oauthPermissionBaseUri` — Entra calls it the Application ID URI and spells it `api://<guid>`; anything absolute works here) and a list of permissions (`oauthPermission`). A permission is identified by the two joined together — `https://example.com/` and `write` make `https://example.com/write` — and a **client** application is granted some of them (`oauthDelegatedPermission`). All three are ordinary attributes on ordinary entries in `ou=applications`, so an `ldapmodify` is a configuration change here exactly as it is for a redirect URI.

**A permission must be DEFINED before it can be GRANTED.** That is the one ordering rule, and it is checked in `applications.updateApplication()` so that the console form, `POST /admin-api/permissions/…` and the generic attribute editor on `/admin/applications` cannot disagree about it.

**FIVE ACTIONS, ON TWO PAGES, POSTING TO ONE HANDLER.** *Expose an API*, *Define a permission* and each row's *Remove* are on `/admin/delegation`, where the resource half is configured and the reader is looking at the register. **Granting is on the client application's own page** — open one under *Directory › Applications* and its *Delegated permissions* section shows what it holds, what it exposes and a form that grants it another. *Revoke* is drawn in both places, because it is a row button either way and its two halves are the row it sits on: the register is where somebody tidying up works, and the application's own list is the read-back of the grant they have just made. The reason is the shape of the control rather than the length of the page: on the register the form was two selects and the reader had to get both right, and a grant written to the resource instead of to the client still succeeds, still resolves in both directions, and is wrong only at the token endpoint, later, to somebody else. On the application's page the client half is the entry being looked at, so the half that could be silently wrong is settled by the URL. The select there offers neither the application's own permissions (a token audienced to its own asker is what an ID Token already is) nor the ones it already holds. Both forms still POST to `/admin/delegation` and both are still `POST /admin-api/permissions/{action}`: moving a form is not moving an action.

**Every table on `/admin/delegation` is paged at ten rows and they share one `?per=`.** There are seven of them — the acts, the chains, the permissions applications expose, the grants, the two Kerberos policy tables and the mechanism catalogue — so fifty rows apiece, which is what every other page in this console uses, would put the last heading tens of thousands of pixels down. Each table has a page parameter of its own (`?page=`, `?chainsPage=`, `?permissionsPage=`, `?grantsPage=`, `?pairsPage=`, `?flagsPage=`, `?mechanismsPage=`), so moving one leaves the other six where you left them. The two tables of this register also have a **search over the application name**, `?permq=` and `?grantq=`: the first matches the application that EXPOSES a permission, which is the only one a permission has, and the second matches BOTH ENDS of a grant, because a reader arrives holding one application name and does not know which of the two columns it will turn up in. Both match on the display name and on the identifier. `?format=json` still carries every list whole — the acts are the exception they always were — with `allowed.filter` and `allowed.paging` reporting what the browser was shown.

**Then a client asks for one as an ordinary OAuth scope, and the access token says both halves:**

```
scope=openid https://example.com/write https://example.com/read
   ->   "aud":   "https://example.com/"
        "scope": "openid read write"
```

The base URI becomes the audience and the permission NAME becomes the scope, which is what a resource server wants: check `aud` once, then read bare permission names. It is the same rule a scope naming another application's `client_id` already follows, one step more precise.

**IT REFUSES NOTHING BY DEFAULT.** With `oauth2.delegatedPermissionsEnforced` off — which it is unless somebody turned it on — an ungranted permission is honoured exactly as a granted one is, logged as ungranted, and marked on the console. With it on the same request is refused `invalid_scope` at the authorization endpoint, where the client can still be told, and at the token endpoint for the grants that never reach it. A grant already issued is not re-judged, so turning it on refuses the next request rather than invalidating what is outstanding. Both answers exercise a client and neither is right for every test, which is why the register is fully readable before anybody enforces anything.

**One-to-many and many-to-one both fall out of it** with no store of their own: one client granted three permissions is three values on the client's entry, and three clients granted one permission is one value on each of three entries. A grant naming a permission no application defines is shown as **dangling** rather than treated as an error, because `ldapmodify` reaches these attributes like every other and both console doors refuse to create one.

**`/admin/delegation/allowed` draws it**, and it is a SECOND picture rather than a mode of the first. Every box is an application and there is no person on it — a permission says *this client may reach that API as whoever is signed in*, and there is no whoever yet — and this service is not on it either, because not one of its lines has been issued. A line is DASHED until the client has actually asked for that permission, which is the reading a configured register exists for and the one an acts diagram can never give: a grant nobody needed draws no act at all.

**And under that picture it lists the GROUPINGS, which is what a register stops being able to draw on one canvas.** One diagram is the right document for five applications and the wrong one for eighty: past a certain size the interesting reading is never the whole of it, it is *which applications are joined to each other at all* — the API and the three front ends holding permissions on it, the batch job that reaches two of them, and the twelve applications elsewhere in the registry that have nothing to do with any of it. So the allowed picture carries a **search over every application the configured register touches**, the same twenty-at-a-time control the two choosers on `/admin/delegation` use, and a paged table of the groups themselves with the applications in each spelled out. Clicking one opens **`/admin/delegation/cluster`**, which draws that group alone — the same renderer, the same shapes, the same dash, handed a subset of the grants and nothing else changed — with the members and which side of a grant each is on, every permission the group exposes (granted or not), and every grant in it.

**A group is a set of applications that can be reached from one another by following grants, ignoring which way each grant points**, and the dropped direction is the whole decision. A grant IS directed — that is why every line has a round end and an arrowhead — but following the arrows would answer *what can this client eventually reach*, which is a question about a chain, and a permission register has no chains in it: holding a permission on an API does not grant that API's own permissions to anybody. Following a grant either way is the only reading under which an API and the front ends holding permissions on it come out as ONE group rather than as four. Membership ignores direction; the picture never does. **Three states make a group of one and each is a real answer**: an application with a base URI and permissions nobody has been granted — somebody described an API and nothing may reach it; a client holding only dangling grants, which have no far end to be joined to; and an application granted its own permission. A group is named after the member whose identifier sorts first, which is a property of the set, so adding a grant inside a group does not rename it. `GET /admin-api/permissions/groups` is the same answer without a browser — every group with its counts, or `?application=` for the one group an application is in with its rows and its graph — and both console pages answer `?format=json` and `?format=svg`.

Neither picture has a form on it: everything on them either happened or is somebody else's configuration, and the button that revokes a grant stays on the register. The same data is at `GET /admin-api/delegation`, with the acts, the distinct *chains* among them (one per edge of the picture) and the policy. It is in memory, capped by `delegation.maxRecords`, and gone on restart — like everything else this service RECORDS or MINTS. (The directory, the trust realms and the runtime settings can be kept; see *Persistence* above. A delegation record is not one of them: it is a statistic about a process.)

**`/admin/delegation/map` draws it.** The same acts as a diagram, generated on the server and reached from a link at the top of the table. It is **two bands**: the parties on one plane, in the order of the chain, and this service in a band of its own above them, centred, with its lines dropping onto whoever it issued to. That is why it reads as a line rather than a staircase — the issuer touches every line in the picture, so leaving it in the flow put the one box nothing is about in the middle of everything that is. **The plane is a real one**: every party, the person included, is on a single centreline whatever shape the graph is, which is not what a layered layout does on its own — it spreads a branch out vertically, and one person with three applications came out as four boxes at four heights. So the row owns the layout and the library is kept for the ORDER alone. A line whose two boxes are **neighbours** on the row lies along it, and everything else — a box in between, a second mechanism between the same pair — **arcs under it** in a lane of its own, which is where the crossings a flat row cannot avoid are paid for. On the parties' band there is a **stick figure** for every party with an entry under `ou=users`, a **rectangle** for every one with an entry under `ou=applications`, a **rectangle with a figure inside it** for the middle tier that is routinely both, and a **hexagon** for this service, carrying the trust realm the picture is of. Two kinds of line, because a chain makes two different claims: *acts for* is the delegation relationship — who is acting on whose behalf, coloured amber for an impersonation and green for a delegation, the pairing the table already uses — and *reaches* is the **trust** relationship, what the credential was FOR, which is *what is this token's audience* asked as a picture. A dashed grey line from the hexagon is this service having issued to whoever asked. A **broken** line jumps a party nobody named, which is what a forwarded ticket-granting ticket is: no intermediary, and none possible. **Red is a chain nothing was ever issued on**, and a party neither store has heard of is drawn dashed in the shape its role implies rather than as a registered one. A party that reached *itself* — S4U2Self asks for a ticket to yourself — is marked on the box rather than drawn as a loop on it, because an arrow leaving a box and coming back is a drawing of nothing.

Under the picture the same thing in words, because a diagram nobody can quote is a diagram nobody can put in a bug report: every party with both of its links, every relationship as a row, and **every credential that came out** — kind and identifier only, never the credential, and a Kerberos ticket genuinely has none to quote. It takes the delegation table's five filters and is drawn from **everything that matched** rather than from one page of it, since paging a diagram draws the pagination. `?format=json` is the whole graph — also in the `graph` member of `GET /admin-api/delegation`, so a test can assert what the page draws without parsing an SVG — and `?format=svg` is the document on its own.

**Three links off that table narrow it to one thing.** Every row of both tables on `/admin/delegation` carries a link to **`/admin/delegation/chain`**, which draws THAT relationship on its own with everything else in the service left out — the whole picture is the right answer to *what does this service look like* and the wrong one to *what is this row, exactly*, which on a service driven for an afternoon is forty boxes. It carries the chain's own key rather than a row number, so a link put in a ticket cannot come back describing a different relationship once the cap has dropped an act; a chain whose acts have all been dropped says so rather than answering 404.

And **`/admin/delegation/application`** asks the other question: not *what talks to what* but **what has been issued because of this application**. Search the list every act has named — the chooser is on the delegation page as well, and since 2026-08-26 it is a **search box over a scrolling pane of at most twenty matches**, where clicking a match is the choice; every spelling an act presented is searched, so a name pasted out of the acts table finds its application whichever form it was in — and get every act it took part in **regardless of the role it played**, the picture of every relationship it is in, and every delegated credential that came out, each with the role this application had in the act that produced it. That last part is the point: a middle tier is the *intermediary* of the chains it acts on and the *target* of the ones that reach it, so offering only what was issued FOR it would hide what was issued THROUGH it, which is the interesting half of a delegation. The list is built from the acts rather than from `ou=applications`, which is why an entry on it can be marked *not in the registry*. Both pages answer `?format=json` and `?format=svg`, and both link back to the table carrying whatever filter you left it with.

**And `/admin/delegation/user` is the one picture here drawn from more than this register.** It answers *what has this service done in one person's name, end to end* — a question the three pages above it cannot, because most of what happens in somebody's name is not a delegation: an authorization code grant is not an act, nor is a Kerberos AS-REQ, nor a SAML assertion, so a person who signed in nine times and holds twenty tokens is an empty picture drawn from acts alone. Search for somebody — the chooser is on the delegation page and on the map as well, the same twenty-at-a-time search the application one is, and the same rule about spellings: `alice`, `alice@STS.MOCK` and `urn:sts:user:alice` all find the one person this console files them under — and get **every credential ever issued naming them** (JWT, SAML assertion, Kerberos ticket, SVID, verifiable credential) as a line to the application holding it, **labelled with the exact OAuth 2.0 grant or OpenID Connect flow that produced it** and the section that defines it: `authorization_code` beside *Authorization Code Flow* and RFC 6749 §4.1, `refresh_token` beside RFC 6749 §6, `client_credentials`, the password grant, the implicit and hybrid halves of an authorization response, OpenID4VCI's pre-authorized code, and RFC 8693 token exchange. A **dotted** line into the hexagon is them signing in, one per protocol family with the method on it, and it is why anything else on the picture was allowed. **A solid line out of an APPLICATION is what the credential it holds is addressed to** — an access token issued to a web front end and carrying `aud: https://apigw1.example.com` is this service saying that the front end may reach the API gateway in that person's name, so the picture draws it, labelled with the grant. It is the same *reaches* line the delegation half draws and it means the same thing; what tells them apart is the mechanism on the label, an ordinary grant against `Token exchange`, because nothing was exchanged to get this one. The audience is looked up in the applications registry — by registered audience and then by `client_id`, so `https://apigw1.example.com` and the bare `apigw1` a scope produces land on ONE box rather than two — and the string the token actually carries is in the line's tooltip. An `aud` naming several resources draws several lines, which is what RFC 8707's small set of resources produces; an `aud` that is **this service's own** — a refresh token is addressed to the token endpoint, and an access token nobody named a resource for carries the `<base>/resource` stand-in — draws none, because that is not a relationship with anybody. **That line also says what the token may DO at the far end**: under the mechanism it names the DELEGATED PERMISSIONS on the token's `scope` claim — the values the resource at the far end has actually defined — or the words `default permissions` where it asked for none of them. Both spellings a client may use come out the same way, because the question is asked of the token rather than of the request: `scope=https://apigw1.example.com/read` arrives here as an audience of `https://apigw1.example.com/` and a `read` on the scope claim, and `scope=apigw1` arrives as an audience of `apigw1` with nothing on the scope claim naming a permission at all. It reports what was ISSUED and not what was granted — `/admin/delegation/allowed` is that question, and with `oauth2.delegatedPermissionsEnforced` off a token can carry a permission its client was never granted. Any delegation naming them is in the same diagram, drawn by the same code the map uses — and the delegation lines are the only ones that carry a colour for impersonation or delegation, because a grant makes neither claim.

Two things about it are worth knowing before reading one. An RFC 8693 exchange writes a row in **both** registers for one credential, so it is drawn once — on its delegation line, which says more — and the number left off is printed rather than left to be noticed; a Kerberos S4U ticket is the overlap that survives, since a ticket has no identifier in either register to collapse the two on, and the page says so. And the chooser's list is the identity register **unioned** with the delegation one, so it offers people nothing was ever issued to: an `S4U2Self` or an `OnBehalfOf` names somebody who was never present and proved nothing, and that is precisely the row worth opening. `/admin/users` links to it, and the two are not summaries of each other — that page is the ledger, where a token is revoked, and this one is the relationships.

**It runs no script, and neither does anything else in this console.** The layout is computed on the server with [`@dagrejs/dagre`](https://github.com/dagrejs/dagre) and every shape is this repository's own, so `script-src 'none'` is untouched and nothing here is the fifth scripted page. What that costs is that the picture does not pan, zoom or drag; the filter is how a busy one is made readable, and `?format=svg` is how it is opened in something that does zoom.

**`/admin/audit`** is the one page here that reports *history* rather than *state*, and that distinction is the whole reason it exists. Every other page answers a question about now: how many calls, which tokens are still valid, who is in `cn=developers`. None of them can answer *when*, or *by whom*, or *in what order*. `/admin/metrics` will tell you the directory holds eleven entries; only this page can tell you that a twelfth was created at 14:02 and deleted at 14:03 by somebody bound as `uid=carol`, over LDAPS — and that in the same minute a token was revoked from the console. Those are three rows here and three numbers that each went up by one over there.

Six categories, and the shape of them is the point rather than the count. **Authentication** is a credential having been *accepted* in any of the sixteen protocol families. **Session** is a browser sign-on session created or ended — shared between OAuth 2.0 / OIDC, WS-Federation and SAML 2.0, so a `wsignout1.0`, an `/oauth2/logout` and a `/saml2/slo` produce the same row. It also carries the two rows `/logout` writes, `logout.global` and `logout.selective`, which are **one row per act and not one per thing ended**: every session ended already wrote its own `session.end`, so a row per item would count one sign-out twice at two layers. What those two add is what none of the others can say — that these were one act, at one moment, and how much of it could *not* be ended. **Directory** is every LDAP operation over 389 and 636 alike. **Admin** and **API** are the console and `/admin-api`. **Protocol** is every other endpoint.

Each of those arrives through a funnel this service already had, which is the property worth keeping. `admin_stats.recordAuthentication()` is the single point all sixteen families pass through the moment a credential is accepted, so one line there is one line and not sixteen; `app.js`'s call log is the single place every answered request passes through, so one call there covers the console, the API and every protocol endpoint rather than a recording site in each of forty route handlers, thirty-seven of which would never have been added. Only the directory needed a site per operation, because ldapjs dispatches straight into the handler and what a row has to say genuinely differs — a modify names its changed attributes, a search names how many entries came back. What is *not* repeated across those seven is the rule that decides whether an add is a user, a group or something else: that is **placement**, since this directory is schemaless and believing the `objectClass` a client sent would file a `groupOfNames` added under `ou=users` as a group, and it lives in one function that `/admin/groups` agrees with by construction.

**No credential is ever recorded, and that constrains what the rows can say.** Not a password, not a bearer token, not an assertion, and no request or response body at all. A modify names the attributes it changed and never their values, because a modify is where a `userPassword` gets set; a compare says whether it matched and not what was tried, because comparing against `userPassword` is precisely how a client checks a password without binding; a refused bind carries the DN and not the password, not even its length. An `authorization code` or an `id_token_hint` in a query string is replaced with `(redacted)` — a query string is otherwise kept, because on this service it is page numbers, filters and client ids. The one field read out of an admin request body is `action`, by name and capped in length, and that narrowness is deliberate: those bodies carry pasted JWTs, since the tokens page revokes by pasted token.

**One act usually produces several rows, and they are not duplicates.** Signing in at `/authn/login` writes three: the HTTP call, the credential being accepted, and the session that came out of it. Which one answers your question depends on the question — a Kerberos AS-REQ authenticates somebody and starts no session at all, an LDAP bind does both with no HTTP request anywhere in it, and a `wsignout1.0` against a session that expired an hour ago is a `session.end` marked `refused` that looks, from every other page in this console, exactly like one that worked. Collapsing the three would mean choosing, once and for everybody, which of those this page can answer.

The three **outcomes** are three rather than two for the same kind of reason. A `refused` is this service working correctly and saying no, which is most of what somebody debugging a protocol client wants to see; an `error` is this service failing. Collapsing them into `ok`/`not ok` would bury the one row worth paging somebody about under the fifty that are a client getting its parameters wrong.

**The page observes itself.** Drawing it is console access, so fetching `/admin/audit` records an `admin.view` event and the list is one row longer than it was when you asked for it. That is stated on the page rather than engineered around, because suppressing it would put a blind spot exactly where the person reading the audit log stands; `?category=` is how you read past it.

Filtering is by category, action, outcome, actor and free text, and the vocabulary the filters offer is read off the same table the log records against — so an action cannot occur and be unfilterable, nor be offered as a filter and never occur. The actor filter is a **substring** rather than an equality, and that is a concession to something real: the actor on a directory row is a bind DN and the one on a Kerberos row is `alice@REALM`, and the collapse of those to one key can only be done where an identity is normalised. Where it *has* been normalised, the row carries both — the key and the form it was presented in — because that collapse is something an auditor has to be able to see rather than take on trust.

Paging is `?page=` and `?per=` as everywhere else, but **the thing to walk this list by is `seq`**. That number is monotonic and never reused, including across a drop, so "everything after 4,102" is exact where page 2 taken a second after page 1 can repeat a row that shifted onto it — the log is still being written while you read it. `?format=json` carries `oldestSeq` and `newestSeq` for that, and a gap between the last sequence number a caller saw and `oldestSeq` is precisely how many events it missed while the cap discarded them.

Two things it deliberately does not have. **No client address**: this service is reached over a compose bridge, through a published port or from the same machine, so what it would record is the bridge — a fact about docker rather than about whoever made the call, and a column that was right on a laptop and quietly wrong everywhere else is worse than no column. What a row *does* say is the channel — `http`, `ldap`, `ldaps`, `grpc` for the two SPIFFE gRPC surfaces, or `internal` for the things this service did on its own, such as the directory entry it seeds for somebody who authenticated elsewhere — which is the part that is actually knowable and is what somebody who has just turned LDAPS on wants to check. And **no clear button**, here or on the API: an erase control on an unprotected surface would make an audit log unable to answer the one question it exists for. Restarting the service is how you get an empty one, which is also what happens anyway — this is in memory and dies with the process, like the counters, the sessions and the signing key. There is no compliance story here to serve: this service checks no password anywhere, so an audit log of it is a debugging aid and not a record of anything.

Two settings on `/admin/audit` — the page itself, since 2026-08-27 — change it and both take effect immediately, because `audit.js` reads them per event rather than capturing them at require time. `audit.maxEvents` (5,000) is the cap, and what was dropped is counted and shown, so a truncated log says it was truncated instead of implying the cap is all there ever was — lowering it from 5,000 to 100 discards the excess on the very next event rather than one row per event for the next 4,900. `audit.protocolCalls` (on) is whether ordinary protocol endpoint calls get a row at all; it is far and away the noisiest category, since every JWKS poll and metadata fetch is one, and turning it off is how somebody watching the directory or the console gets a readable page. It never touches the other five categories, and `/admin/metrics` counts every call either way.

**`/admin/token-lifetimes`** decides how long what this service issues is good for, and it is the page to reach for when the question is *why has my client stopped working*. Three lifetimes and one allowance, all four in seconds: an **access token** and an **ID Token** last an hour by default, a **refresh token** twenty-four hours, and the **clock skew** — thirty seconds — is how far out a clock may be before this service stops believing a token it signed itself.

They were constants in the source until 2026-08-24 and could not be changed without a restart, which had the lifetimes exactly backwards: the reason to point a client at a mock is to make something happen on demand, and *make it expire in a minute so I can watch the refresh* is the commonest thing anybody wants of a token endpoint. Set the access token to 60 and the next one dies in a minute; set the ID Token to something different from the access token and watch which of the two your client actually notices, which is how a client that is quietly treating the ID Token as a session gives itself away.

Two things about it are worth knowing before the first surprise. **A change reaches the next token and nothing already issued** — a lifetime is stamped into a token as its `exp` claim when it is signed, so nothing on this page can shorten one already in a client's hands; `/admin/tokens` is where you take an issued token out of circulation, by revoking it. And **every lifetime is a whole number of thirty-second units**, which is not a formatting rule: below half a minute a token expires between the response being written and the client reading it, and the hour that costs is spent debugging the wrong half of the exchange. The skew is capped at 300 seconds for a related reason — five minutes is what Kerberos allows here, and a wider window has stopped being a tolerance and become a lifetime extension nobody asked for.

**The skew moves the console and the endpoints together, which is the point of its being one setting.** It is applied wherever this service reads back a token it issued — `/oauth2/introspect`, UserInfo, the refresh grant, token exchange, the DPoP-bound access token check — *and* to the state every console screen reports. So a token `/admin/tokens` calls **expired** is one introspection reports `active: false` for, in both directions and at every value: raise the skew and a token that just died is accepted again everywhere at once. A page that disagreed with the endpoint would be worse than a page with no state column, because it is believed. It is deliberately **not** the same setting as `oauth2.clientAssertionSkewS`, which is how far out a *client's* assertion may be under RFC 7523 — somebody else's clock, on a credential this service did not mint.

**The refresh default changed from thirty days to twenty-four hours** with this page. A client that held a refresh token across a long test run now meets an ordinary `invalid_grant` where it did not; `oauth2.refreshTokenTtlS: 2592000` in the appconfig file is exactly the old behaviour. It is a different setting from RFC 9700 mode's `oauth2.refreshIdleSeconds`, which is measured from the last time anything in a refresh *chain* was redeemed rather than from issuance — a busy client keeps its grant indefinitely under that one and is still walled by this one.

All four are ordinary `config.js` rows, so they are on `/admin/oauth2` too and this page writes through the same function — one store, two doors. The management API has a narrow door of its own at `GET /admin-api/token-lifetimes` and `POST /admin-api/token-lifetimes/set`, which differs from `POST /admin-api/config/set-many` in one way that matters to a test: it **refuses** a key that is not one of the four instead of ignoring it, so a misspelt `oauth2.accessTokenTtlsS` fails loudly rather than succeeding and changing nothing. `POST /admin-api/token-lifetimes/defaults` puts the four back without disturbing any other setting.

Every screen that reports token state now reports **expired** as its own answer rather than leaving it to be inferred: the users list gained an *Expired* column beside *Valid* and *Revoked*, and a person's drill-down a matching tile. The count was always there and was simply not shown, so "12 issued, 1 valid" left eleven to be guessed at — and the guess is wrong, because a revoked token, one not yet valid and one with no expiry stated all sit in that difference.

**`/admin/claims`, `/admin/userinfo-claims` and `/admin/saml-attributes`** decide what every access token, ID Token, UserInfo response, SAML 2.0 assertion and SAML 1.1 assertion carries. Five sets rather than one, because the five are genuinely different vocabularies: an access token and an ID Token go to different readers (a resource server and a client), and SAML 1.1 splits the claim URI into an `AttributeNamespace` and an `AttributeName` where SAML 2.0 has one `Name`. **Three pages onto one store**: the tokens are on *Custom claims* under OAuth2 / OIDC (2026-08-24), the assertions on *Custom SAML attributes* under the console's own SAML group (the same day) because a reader who came to change what a WS-Federation assertion carries had to read past two token sets and a page of JWT rules that do not apply to them, and the UserInfo response on *UserInfo claims* beside the first (2026-08-26). **The UserInfo page is the one with no "nothing already issued changes" warning on it, and that is the whole argument for it being a page**: that response is built on every call, so a claim added there reaches a client that signed in an hour ago and has done nothing since. It is also the only set a CLIENT can add to — see *UserInfo is the one endpoint that refuses a token it did not issue* above, where OpenID Connect Core section 5.5's claims request is described. What did not split is anything underneath — one `CLAIM_SETS` object, one `setClaimSet()`, one action function taking the set ids the door carries, and one audit row per change whichever page or API operation made it. A `set` of `saml2` posted to the claims door is refused **by name**, and the refusal says where that set lives. They are **additive** — a configured claim is added to what the protocol already puts in the artifact and never replaces one — and the names this service sets itself are **refused at configuration time** rather than silently dropped at issuance, because every one of them is load-bearing: an `exp` settable from a web form would produce tokens that fail to verify with nothing anywhere pointing back at the page, and a settable `scope` would quietly change what UserInfo answers. The reserved *list* is enforced for the two token sets and for the UserInfo one and not for the two SAML sets — `sub` is required in a UserInfo response by Core 5.3.2 and a client MUST check it against the ID Token's, and the *signed* form of that response is a JWT carrying `iss`, `aud` and `exp`, where an assertion attribute called `exp` collides with nothing — but the additive rule itself protects the SAML side just as hard, for a different reason: a WS-Federation relying party keys off the claim URIs `claimsFor()` writes, so a custom attribute that displaced one would break a sign-in somewhere that looks nothing like this console.

Values may contain `${username}`-style placeholders, because a claim that can only be a constant cannot exercise the thing worth testing — that a claim carrying the signed-in user's identity reaches the relying party. **An unknown placeholder is left exactly as written** rather than replaced with the empty string: a `${dept}` that silently became `""` is a bug that looks like a configuration mistake, and one that still says `${dept}` names itself. A JWT claim value is typed when it unambiguously looks like JSON (an object, an array, a bare `true`/`false`/`null`, a number) and is a string otherwise, which has one consequence the page states rather than leaving to be discovered: a claim whose value is genuinely the four characters `true` cannot be configured, and `"true"` is the escape. SAML attribute values are never typed — the XML content model is text — and the *placeholders* an assertion expands are a shorter list than a token's, which the SAML page states rather than leaving to be found on the wire: an assertion is built from a subject and an audience, so `${subject}`, `${audience}`, `${now}` and `${iso}` resolve and a `${username}` written there arrives as the eleven characters it was written as.

**Each of the five sets has a second half, and it is the half worth exercising.** A typed claim is a constant, or a constant with the signed-in name interpolated into it — whatever the person at the keyboard said. Underneath each set is a table of **LDAP attribute types** with a checkbox against each, and a ticked one becomes a claim whose value is read off that person's own entry under `ou=users`. So an `ldapmodify` against `uid=alice,ou=users` changes the next access token — and the next assertion, from the identical table on the SAML page — and an LDAP client, an OIDC client and a SAML relying party pointed at this service are shown the same person rather than three people with the same name. That is a thing no amount of typing into a form can demonstrate, and until now only a Verifiable Credential could do it. The controls are the ones the table implies — **Update** installs exactly the ticked boxes, **Select all** and **Delete all** are the extremes — and all three are form posts rather than script, because `script-src 'none'` covers both pages like every other one here: a browser-side "tick everything" would leave the boxes ticked and the set unchanged until somebody pressed Update, and would leave nothing in the audit log.

**The catalogue is `vc_claims.js`'s and is not a second copy of it**, which makes these the *third and fourth* pages choosing from one list of attribute types: `/admin/vc` picks what an issued credential carries, `/admin/vc-verifier-config` picks what the mock Verifier asks for, and these two pick what a token and what an assertion carry. Two catalogues would be two lists of spellings, and one of them would eventually be wrong about `schacDateOfBirth` while both looked right on their own. The four *selections*, though, are deliberately independent of each other and of the other two pages — an access token carrying `employee_number` while the ID Token carries only `email` is a normal arrangement that a single list could not express, and keeping them apart is what makes "issue a credential carrying a claim the access token does not" reachable at all. Nothing is selected on a fresh start in any of the four, because this page changes what every client of this service receives and a mock that began issuing a `birthdate` in every access token because a feature was added would break the tests of everyone who upgraded.

**Three rules decide what a claim's value actually is, and they are stated on the page because two of them only show up in the collision.** The protocol's own claim wins: an ID Token always carries `name`, `given_name`, `family_name`, `preferred_username` and `email` built from the sign-in, so ticking `cn`, `givenName`, `sn`, `uid` or `mail` *on that set* changes nothing the client sees — while the same five reach an access token from the directory, because the protocol sets none of them there. Then a typed claim beats a directory attribute of the same name, since somebody who wrote `email` by hand said something more specific than somebody who ticked `mail`. Then the attribute, read from the entry, or invented from the username where the entry has nothing — deterministically, so one username is one invented person across restarts. A nested claim stays nested in a JWT (`address.locality` is a member of an `address` object, per OIDC Core 5.1.1) and becomes the attribute's literal name in an assertion, where the content model cannot nest; both families then call one claim by one name.

**Adding the checkboxes surfaced a bug that had been reachable all along, in both assertion builders.** `saml2.js` and `saml11.js` appended the configured attributes to their own without deduplicating, so a configured claim called `name` produced *two* `<saml:Attribute Name="name">` elements and the relying party read whichever the builder happened to emit first. Typing that name was always possible; ticking `cn` made it a checkbox away. Both now filter the configured attributes against what is already there — by name for SAML 2.0, and by **namespace and name together** for SAML 1.1, since that profile splits a claim URI into the two and a filter on the local name alone would drop an attribute that collided with nothing. It is the same rule the JWT builders have always followed, written as a filter because an assertion is a list of elements and not an object: there, a duplicate name is not an overwrite.

**Every change to a claim set writes a row in the audit log**, both halves of it and refusals included, naming which set, what was added and what was removed — and never a value, because a claim value on this service is whatever somebody typed into a web form. That row is *in addition* to the `admin.change` or `api.change` row the call log writes for the same POST, which is the arrangement the audit log's own section explains: one act, several facts, at different layers. It is recorded from `setClaimSet()` and from the selection's own installer rather than at the seven action branches, because those two are the funnels every branch already passes through — the same reason `recordAuthentication()` is one line and not fourteen.

**`/admin/vc`** decides what every *future* Verifiable Credential carries, and it is the page here whose list is of **LDAP attribute types rather than of claim names**. That is the decision the rest of it follows from. Until this page existed the answer was seven lines in `vc_issuer.js` — `given_name`, `family_name`, `email`, a constant birthdate, a constant nationality and a constant address — which is enough to demonstrate one credential and not enough to exercise a wallet: what a holder actually wants to know is what their UI does with fourteen claims, what their verifier does with one it has never seen, and whether the issuer metadata really describes what arrives. None of those can be asked without changing the claim list. The catalogue is of attribute types because this service *has* a directory, so a claim can have a value something other than the credential can see: `mail` on `uid=alice,ou=users` is what a wallet is handed as `email`, and an LDAP client and an OID4VCI wallet pointed at this one process are shown the same person. Ten rows are selected on a fresh start, which is exactly the six claims the issuer carried before the page existed — `address` is five of them, one per component, because the OIDC address claim has five members and a directory has an attribute type for each. Three rows are not RFC 4519/4524/2798 and the page says so: there is no standard attribute type for a birthdate or a nationality, so the SCHAC schema's names are borrowed rather than invented, and the page shows every row's defining document so the borrowed ones are distinguishable at a glance.


**`/admin/vc-verifier-config`** is the other end of that page, and the two are deliberately separate settings. `/admin/vc` decides what an issued credential *carries*; this decides what the mock Verifier at `/oid4vp/verifier` — the pages call it *The Bar Door* — **asks for**, which reaches the wire as the `dcql_query` of the next OID4VP Authorization Request and then decides what the presentation is checked against. Keeping them apart is what makes the interesting state reachable: a Verifier asking for a claim the issuer is not minting is the negative that exercises a wallet's "I cannot satisfy this request" path, and one page setting both would make it impossible to produce. The same page chooses which of the three **credential formats** an unqualified request asks for, since a presentation cannot convert between them — a wallet holding a `jwt_vc_json` credential has nothing to answer a `dc+sd-jwt` query with, and the honest outcome is that it says so.

**Its table is of claims where `/admin/vc`'s is of attribute types, and the grouping is forced by the credential rather than chosen for tidiness.** `buildSdJwtVc()` makes one Disclosure per *top-level* claim, so `address` is one unit of disclosure however many LDAP attributes feed it: a holder cannot present the locality without the street, and a page offering six address checkboxes would be offering a choice that does not exist on the wire. So the catalogue is `vc_claims.js`'s rows grouped by claim — every row still names the attribute types behind it and their defining document, because "this is `l`, RFC 4519 2.16" is what connects the request to the directory entry the value will come from — and an *Issued now* column reports what the issuer is currently configured to mint, so that a presentation which disclosed nothing is not investigated as a wallet bug.

**Three of its behaviours are deliberate and each is the answer to a question a mock exists to let somebody ask.** A claim that is **not in the catalogue** can be asked for from a text box, and is the only way to reach "the wallet cannot satisfy this request" — nothing here issues it, so the presentation fails this Verifier's own *Requested claims* check with the name in it. Asking for **nothing at all** is a setting rather than an empty form: DCQL reads an absent `claims` member as the whole credential, so the query is built without one and the page says, in as many words, that it is now asking for everything. And the **DCQL path differs by format**, which the table shows rather than implies — `["given_name"]` for `dc+sd-jwt`, `["credentialSubject","given_name"]` for `jwt_vc_json`, and for `ldp_vc` the term the vendored JSON-LD context defines, which is `birthDate` and not `birthdate`, and which for `address` is four flat terms and not one. That last was quietly wrong before this page existed: both W3C formats were given the OIDC claim name, which coincides for `given_name` and `family_name` — the only two claims the Verifier could then ask for — and for nothing else. A claim the context defines no term for is **dropped from an `ldp_vc` query and named on the page**, because asking under a name that context does not define fails canonicalization rather than returning less.

**What a request asks for is frozen onto it, not read again when the answer arrives.** The list is editable while a presentation is in flight, and a Verifier that judged what came back against a list changed after it asked would refuse a wallet for correctly answering the question it was really asked. So `buildVpRequest()` stores the claims on the transaction and every check reads them from there — which is also what makes the verdict at `/oid4vp/result/:state` a true record of that exchange rather than of the console's current state.

**And this page admits nobody.** A presentation that verifies here starts no session, issues no token and grants no access; the door says yes and that is the whole of it. It is the same disclaimer the groups page and the TLS report carry, for the same reason — a console page a click away from the tokens page would otherwise let somebody conclude that a verified credential had become an identity somewhere in this service.
**The metadata is built from the same list the credential is**, which is the reason not to keep the claim set anywhere else. An issuer whose `credential_configurations_supported` advertises five claims while its credentials carry fourteen is teaching every wallet developer who reads it that the metadata is not worth reading, and OID4VCI's whole discovery story rests on it being worth reading. So `vciMetadata()` derives its `claims` arrays from `vc_claims.js` and `subjectClaimsFrom()` derives the credential from the same place, and drift between them is not a state this service can reach. **`ldp_vc` carries a subset, and that is the format's doing rather than a choice**: it is signed over canonicalized JSON-LD, `bbs2023.js` canonicalizes with `safe: true`, and a term the vendored context does not define does not go missing quietly — it *throws*, inside a cryptosuite, at the moment a wallet asks for a credential. So each catalogue row names the JSON-LD term to use in that format or says it has none, `buildLdpVc()` filters what it is given through the context this process actually loaded (a hand-kept list agreeing with a vendored file is a drift waiting to happen, and this is the one where it would surface as a crypto bug), and both the page and `/admin/sts-metadata` name the selected attributes that format leaves out. The context is vendored precisely because editing it would invalidate every credential already issued against it, so "add a term" is not the fix it looks like.

**A claim's value has three sources and the order between them is the whole policy.** The **access token** first, where it carries a claim of that name — that is a statement this service has already made about the person, from the sign-in or from `/admin/claims`, and a credential contradicting the token that authorised it would be indefensible. Then **the directory entry**, which is where the generated values live once an entry exists and is also where an `ldapmodify` lands: change `mail` on `uid=alice,ou=users` and the next credential says so. Then **a generated persona**, for a person with no entry, an entry without that attribute, or a directory that is not running. Nothing is ever left out because a source was missing, since a claim that silently did not arrive is indistinguishable at the wallet from a selection that never took effect.

**The generated values are garbage on purpose and deterministic on purpose**, and the second half is the one worth explaining. This service authenticates nobody, so there is no source of a real birthdate here and there had better not be; the invented street names say `Placeholder`, the mailboxes are in the RFC 2606 example domains and the telephone numbers are in the `555-01xx` fiction range, so no invented value can be mistaken for or collide with a real one. They are seeded from the username rather than drawn fresh because the alternative costs more than it looks: a random birthdate per call means the credential issued at 10:00 and the one issued at 10:01 describe two different people, the directory entry disagrees with both, and a wallet's "did this change" check fires on something that is not the thing being tested. One username is therefore one invented person for the life of the process *and across restarts* — and one **whole** person rather than a field at a time, because a `given_name` of "Ingrid" beside an email of `kwame.osei@…` is two facts that contradict each other and a reader who notices spends ten minutes deciding whether it is a bug here. The seed is the **normalised** local name, which is load-bearing rather than tidy: `alice`, `urn:sts:user:alice` and `alice@EXAMPLE.COM` reach this module from three directions, and seeding on the raw string invented three different people and then failed to find the entry any of them had — a credential whose name its own directory entry contradicted, which looks like the directory not being read at all.

**Saving a selection writes to the directory**, and that is the point of the page rather than a side effect of it. Every person under `ou=users` gains the selected attributes they are missing, invented from their username; without it, ticking `title` would change every future credential and change nothing an LDAP client could see, and the two halves of this service would quietly stop describing the same people. Three rules hold that sweep up. It **never overwrites** — an attribute already on an entry is left exactly as it is, which is why the three seeded people keep their own names and gain only what they had nothing for, and why an operator's `ldapmodify` is not undone by the next sweep. It writes **one value**, not an appended one, so an entry cannot accumulate a birthdate per sign-in. And what it walks is **entries under `ou=users`**, the container excepted — deliberately not "everything with a person `objectClass`", because this directory is schemaless, a client can add anything anywhere, and inventing a nationality for `cn=developers,ou=groups` because somebody gave it a `person` class would be a sweep doing damage where nobody asked it to look. The same fill runs when an entry is created and when a returning person authenticates, so somebody whose entry predates a selection change is covered without waiting for the button. It runs once at startup too, so the seeded three are not asserting values in credentials that their own entries lack from the first request.

**Auto-created entries now get an invented name as well**, where they used to get the login name three times over — `cn: dave`, `givenName: dave`, `mail: dave@sts.example`. Those are attributes a credential asserts, so a directory deriving all of them from the login name made every credential say the login name back, and `given_name: "dave"` is not a given name to test a wallet's rendering against. What the entry keeps from the login name is the two things that *are* the identity, the DN and the `uid` — which is also how a real directory looks, since somebody's uid rarely is their name. The `displayName` keeps its `(mock)` marker: every value on the entry is invented and the field a person reads first should say so.

**A credential claim grants nothing and nothing reads one back.** No access token, ID Token, SAML assertion or Kerberos PAC carries a claim from this page, and no endpoint makes a decision on one — it reaches a credential and stops there. The page says so, for the reason the groups page says the same thing about membership.

**The recording had to invert one dependency, and that is the only clever thing here.** Every JWT this service issues is minted by `signJwt()` in `helpers.js`, which is what makes the count a count rather than an estimate — but `admin_stats.js` requires `helpers.js` (it needs the log), so `helpers.js` cannot require it back. So the leaf offers a slot (`setJwtRecorder`) and `admin_stats.js` installs itself in it at its own require time. What makes that safe rather than fragile is *who requires `admin_stats.js`*: **`app.js` does**, which is not a trick to fix the ordering but a real dependency, since the call log lives there — and every protocol module requires `app.js`, so the recorder is installed before any route exists and therefore before any token can be minted. The recorder's return value is ignored and a throw inside it is caught and logged, because statistics must never be able to stop a token being issued. Everything that is not a JWT is recorded by an ordinary require in the other direction: the two assertion builders, `buildCredentialFor()` where all three credential formats meet, and the two points in `krb5_kdc.js` where a ticket is minted — Kerberos being the one family whose artifacts pass through neither `signJwt()` nor an assertion builder.

Everything the console holds is **in memory and dies with the process**, like the signing key. There is nothing here worth persisting, and a statistics file that outlived the key that signed the tokens it described would be actively misleading. The registries are **bounded** — the most recent 5,000 tokens and 5,000 other artifacts, 500 call paths, and 2,000 identities keeping their 50 most recent authentications each (capped per user rather than in total, because a test loop signing one name in a thousand times is the normal case here) — and what was dropped is counted and shown, because a silent truncation turns "12 tokens issued" into a number that quietly means something else. The revoked-jti set is deliberately *not* capped and is kept separately from the token records, so a token whose record has aged out stays revoked.

#### Who may use the console

**The console is protected, and every page says which of three states it is in.** Every page and every form under `/admin` needs a browser sign-on session from `/authn/login` and one of two roles: **Admin Read**, which may look at every page and change nothing, and **Admin Write**, which may post every form. **Write implies read**, because a role that could change a page it was not allowed to see would be a trap rather than a permission.

**It is a turnstile and not a lock, exactly as SCIM's authentication is.** This service still checks no password anywhere, so what the gate proves is that somebody *typed* a name that holds a role. What it buys is what a mock is for: a client, or a person, can now be driven through a 302 to a sign-in screen, a 401 with no session, a 403 with the wrong role, and a role model that can be granted and revoked — none of which was reachable here before. **There is no longer a setting that turns it off**, which there was until 2026-09-06: `admin.authRequired` is gone and `mode.gatesConsole()` answers `true` in both modes. That is the one refusal in this service which stopped being switchable, and the argument for it is `common/mode.js`'s — a deployment that required a credential at SCIM and not at the console was not partly secured, it was unsecured with a longer configuration file. What `global.mode` still changes is whether the password typed at that screen is CHECKED.

**The two roles are two ordinary groups in the embedded LDAP directory** (`admin.readGroup`, `admin.writeGroup`; `cn=admin-read` and `cn=admin-write` by default), not a store of the console's own. So there are **four doors onto one membership** — the `/admin/rbac` screen, `POST /admin-api/rbac/grant`, an `ldapmodify` on 389 or 636 (bound, in product mode, as somebody who already holds Admin Write — see `ldap.selfWritableAttributes`), and a SCIM `PATCH` of the group — and a grant made through any of them is visible through all of them. That is the point rather than a side effect: a role no test can grant is a role no test can exercise.

**There is a bootstrap administrator, and until it signs in the console is open (2026-09-13).** At startup this service makes `admin` (`admin.bootstrapUsername`) in the default realm if it is absent, puts it in both role groups, and marks a newly created account `pwdReset: TRUE`. Its first sign-in at `/authn/login` asks for a new password before anything else; in development any password gets it to that screen, and in product mode it is the account the generated password is logged for. It cannot be deleted or renamed through the console, `/admin-api`, SCIM or LDAP. **Until that account first signs in to `/admin`, anybody who signs in holds both roles**, and every page says so in a banner that cannot be missed; its first console sign-in ends that for everybody who holds no role, which is why the screen says to grant yourself one first if you will need the console afterwards. Taking `admin` out of the groups is still possible, and is on you. `admin.openWhenEmpty` turns the open window off. A deployment whose roster already had members when the bootstrap administrator was first seeded gets the window closed at once. A process that never ran the startup step keeps the older rule: the console is open while *neither* group has a member.

**`/admin-api` is not gated by any of this**, deliberately. It is what a test drives, and it is the way back out of a locked console — if nobody holding a role can sign in, the screen that grants a role is behind the gate that role opens, so `POST /admin-api/rbac/grant` is the only door. The honest consequence, stated rather than buried: **anyone who can reach this port can grant themselves both roles through the API and then use the console.** That is the same thing that was already true of `/oauth2/token`, since it will mint a token for any username asked of it. The gate exists to make a client's 302/401/403 paths runnable, not to make this service safe to expose. Do not put this service on a public address.

#### The pages, and how they are grouped

**The navigation is a grouped list down the left rather than a row of tabs across the top.** Seventeen tabs on one line wrapped to three rows on a laptop, and a reader looking for *Verifier request* had to read all seventeen labels to find out it was not *Credential claims*. The five sections are **Overview** (the console index), **Protocols** (authorization servers, token lifetimes, custom claims, the custom SAML attributes, credential claims, the verifier request, SCIM, and SPIFFE with its registration entries and agents), **Directory** (users, groups, applications), **Monitoring** (metrics, issued tokens, the audit log) and **Server configuration** (configuration, admin roles, the service metadata). Monitoring holds its three in widening detail — how much this service has done, what came out of it, and what happened in order — because those are three ways of asking one question and filing the counters away from the events they count helps nobody. **Overview** is a section of one on purpose: `/admin` is where a reader lands and the only page whose job is to point at the others, so it is the one page that cannot sit under a heading naming a kind of content. The breadcrumb trail is unchanged and deliberately does **not** gain a crumb for the section: a section has no page of its own, so its crumb could not be a link, and a dead crumb in the middle of a trail is the same mistake the last-crumb rule exists to prevent.

Two things the console deliberately does **not** do, and one it used to. It does not invalidate a SAML assertion, a Kerberos ticket or a credential: none of those has a revocation mechanism a relying party consults — an assertion is valid because its signature verifies and its `Conditions` hold, and nothing about this service is asked — so a button claiming to revoke one would change a number here and nothing at all out there. **It DOES end a sign-on session now, at `/admin/logout`, and this paragraph used to say the opposite.** The old argument was a good one: `/oauth2/logout` and `wsignout1.0` each had a fan-out written into it, so a third button here would have been a third copy that quietly notified nobody. That stopped being true when the fan-outs became functions owned by the protocol module each belongs to, and one function in `authn.js` became the only place a session actually stops existing — see *Signing out of everything*. What this console still cannot do is *deliver* the notifications: a front-channel logout is an iframe in the signed-out person's own browser, and this is not that browser. And it adds no claims to refresh tokens: a refresh token is presented back to this server and to nothing else, so a claim in one reaches no relying party and would only make the two halves of a grant disagree.

### Consent — what a person agreed an application may ask for on their behalf

**This is the one policy in this service that is ON by default**, and the reason is not the reason everything else is off. The first time a given username signs in to a given `client_id` for a given scope, `/oauth2/consent` is drawn, and nothing is issued until they press a button. Allow writes the answer into the directory and the second sign-in is silent; Deny returns `access_denied` to the client and records nothing at all.

Every other refusal here is off by default because this service exists to exercise clients and a refusal that cannot be turned off removes a test case rather than adding one. **Consent is not a refusal.** It is the screen every real authorization server draws on a first sign-in, and a client that has never met one has never run the code that survives it: the extra redirect, the second visit to the authorization endpoint, the `access_denied` when somebody says no. Off by default would have meant the interesting behaviour was the one nobody saw. `oauth2.consentRequired` turns it off, and OFF means exactly what this service did before the screen existed — nothing asked and nothing recorded. It is not "everybody consented": no agreement is written down, so turning it back on asks again.

#### Where the answer goes

**`oauthConsent`, on the person's own entry under `ou=users`, one value per (person, application, scope):**

```
oauthConsent: 20260901143000Z openid webapp1
oauthConsent: 20260901143000Z https://example.com/write webapp1
```

Three fields separated by a space — when it was agreed, the scope, and the application it was agreed for — and **the `client_id` is last because it is the only field with no rule about what it may contain.** A GeneralizedTime is digits and a `Z`; a scope cannot contain a space, and that is guaranteed by construction rather than checked, because a scope value only ever arrives by having been split out of a space-delimited `scope` parameter. A client_id may contain a space, a `|`, anything at all — the registry refuses only a line break, a NUL and 512 characters — so it takes the remainder of the value. The timestamp is *checked* against its own shape as well as split off, which is what tells a value this service wrote from a sentence somebody left on the entry with an `ldapmodify`: `this is not a consent` fits the grammar exactly and would otherwise read as a consent to `is` for a client called `not a consent`.

**One value per triple and never one per request.** A consent recorded against the whole `scope` string would make `openid profile` and `profile openid` two different agreements, and adding one scope to a client's request would throw away the agreement to the other four. What a person is asked about on a second visit is the *difference*: the scopes that are new, with the ones already agreed to under a fold so that a shorter screen explains itself.

**A delegated permission is recorded by its WHOLE identifier** — `https://example.com/write`, never the bare `write`. Two resources may each expose a permission called `read`, the person agreed to one of them, and a consent stored under the bare name would silently cover the other with nothing anywhere able to notice.

#### The override: consenting a scope for everybody

**`oauthGlobalConsent`, on the CLIENT APPLICATION's entry, one value per scope.** A scope named there is never asked about: everybody who signs in to that application skips the prompt for it, and **nothing is written about anybody**. It is how an operator says *this application's use of `openid` and `profile` is agreed for everybody here* without visiting a person's entry.

Two properties follow from it being an override rather than a record, and both are said on the console page because they are the things somebody gets wrong:

* **Removing one asks EVERYBODY again**, including the people who would have said yes — because nothing was ever written about them. Removing a person's own `oauthConsent` asks only that person.
* **It is keyed on the pair `(application, scope)` and never on the scope alone.** Consenting `read` consents it for *that* application; one registered five minutes later that spells the same word is still asked. A service-wide list of harmless scopes would be shorter to configure and would mean an application nobody has reviewed inheriting a decision made about a different one.

Both attributes are ordinary attributes on ordinary directory entries, so an `ldapmodify` is a configuration change here exactly as it is for a redirect URI, and they persist wherever the directory does.

#### What the screen does and does not do

`prompt=consent` asks again whatever is on the entry (OpenID Connect Core section 3.1.2.1) and **takes nothing away**: re-consenting adds nothing that is not already there, and somebody who cancels keeps what they had. `prompt=none` with something outstanding is **`consent_required`** — section 3.1.2.6's own error code rather than the general `interaction_required`, because a client that gets the general one cannot tell a missing session from a missing consent.

The pending consent is **server-side**: the only thing in the URL is an unguessable id, so there is no return address anybody can rewrite. The answer is a **POST** — a GET that recorded consent would be consent that anything prefetching a link could give — and the id is spent when it is answered, so a back button cannot answer it twice. The session presenting the answer is checked against the person the question was asked of, which is the one failure at that door that would write something *untrue* into the directory rather than merely letting something through.

**The screen carries no script**, so the service-wide `script-src 'none'` is untouched and it is not a fifth exception to it: it is two buttons in a form.

#### What it is not

Nothing here checks a password — that row of *what this service does not do* is unchanged, and consent is a question asked of somebody who has already been let in under any name they typed. Nothing here is re-judged either: the token endpoint asks nobody anything, so a refresh of a code obtained before the setting was turned on still works, and revoking a consent does not touch a token already issued. `/admin/tokens` is where an issued credential is revoked.

**`/admin/consent` is the register**, both halves under headings that say which is which, with four controls: consent a scope for everybody, stop consenting it, take back one person's answer, and forget everything one person agreed to. `GET /admin-api/consent` and `POST /admin-api/consent/{action}` are the same four without a browser.

### The embedded protocol debugger

The [Identity Protocol Debugger](https://idptools.com) — the project this
service was extracted from — can be served by this process, in this container,
as a feature of it. Since 2026-09-13.

**What it is, mechanically:** the debugger project builds its browser client and
its api for embedding (`embedded/build.sh` or `embedded/Dockerfile` over there),
and this service serves the result:

* **on a listener of its own**, `debugger.port` (8444), in the main port's
  scheme and with its certificate. A different ORIGIN from `/admin`, on purpose:
  the debugger's pages carry inline scripts and render tokens and assertions
  from any identity provider, and on the console's origin a flaw in either would
  be a script able to drive the console;
* **its api as a child process** on a unix socket, forwarded at `/api` with the
  prefix stripped, the browser's cookies and credentials removed, and its own
  Express, dependencies and environment. Nothing of the debugger is loaded into
  this process;
* **behind this service's own authorization server.** The debugger is an OpenID
  Connect relying party like `/admin` and `/portal` — the seeded client
  `sts-debugger-ui` — and its api is a resource server, `sts-debugger-api`, that
  exposes one delegated permission, `urn:sts:debugger-api:debugger`. The UI's
  application entry is granted that permission. **The authorization server
  issues it to console administrators — members of the Admin Read or Admin
  Write group — and to nobody else**: it is taken off the grant for any other
  person, for any application, and in any realm but the default one. The gate
  checks the token on every request, and whether its subject is STILL an
  administrator.
  **Nobody gets it while neither group has a member**: the console opens to
  everybody in that state so the first role can be granted, and the debugger
  deliberately does not — grant somebody a role on `/admin/rbac` first.

**There is no setting that opens it.** `debugger.enabled` decides whether it is
served — `auto` is on in development mode and off in product mode — and in
product mode the api is handed an allow-list and may dial only this service's
own addresses plus `debugger.allowedDestinations`, raw Kerberos, LDAP, TLS and
gRPC relays included, because a relay that dials what its caller names should
not reach an identity provider's private network.

**Running it from a checkout:**

```bash
(cd ../id-proto-debugger && embedded/build.sh --out ../iya-sts/debugger/embedded)
CONFIG_FILE=./env/local.js node server.js
# then open https://localhost:8444/ and sign in as a console administrator
```

**In a container:** build the debugger project's embedded image and pass it:

```bash
docker build -f embedded/Dockerfile -t rcbj/id-proto-debugger-embedded:dev .   # in the debugger project
DEBUGGER_IMAGE=rcbj/id-proto-debugger-embedded:dev docker compose build sts   # here
```

and publish 8444. Without a debugger image the build succeeds exactly as
before, and `/admin/debugger` says the debugger is not installed.

**What it does not change:** the debugger's own standalone deployment — its
client and api containers and the hosted site — is untouched; everything about
authentication lives on this side. `/admin/debugger` and `GET
/admin-api/debugger` report the listener, the api process and its allow-list.

### The management API

`GET /admin-api` is the console above with the HTML taken off: every page's `?format=json` view and every one of its forms, at a path a script can use, with an OpenAPI 3.1 document at `/admin-api/openapi.json` and an explorer that calls it at **`/admin/api-explorer`** — a page of the admin console since 2026-09-09, behind its session and its two roles, because this API began requiring an access token and a browser navigating to a URL carries none. **The operations themselves require an OAuth 2.0 access token** audienced to this API, carrying `admin:read` to read and `admin:write` to write; `adminApi.authRequired` turns that off and restores the open API exactly, which is the way back in when nobody can mint a token. All of them change the same state the console changes, because they call the same functions it does.

**It exists because a form is the right shape for a person and the wrong one for anything else.** Every page here has answered `?format=json` since it was written, so reading was never the problem; *changing* something was. A caller that wanted to revoke a token from a script, or narrow the issuer's claim set from a CI job before running a wallet against it, was left either parsing a 303 redirect for the message in its query string or knowing which hidden input a particular form carried. Both are ways of driving a browser without one.

**The rule the API is written under is about the future rather than about the code**: a control added to `/admin` gets an operation on `/admin-api` in the same commit. `GET /admin-api/audit` is what that rule produced for the audit page, and it is the one resource here with **no POST beside it** — not an operation nobody got round to, but the consequence of the page it mirrors having no form on it. An erase control on an unprotected audit log would make it unable to answer the one question it exists for, so there is nothing to change and therefore nothing to document as changeable. `GET /admin-api/users` grew one the day `/admin/users` grew its first form — a single
action, `create` — and `GET /admin-api/applications` **has** a POST beside it — six actions — and the thing worth knowing about them is that they are not a third store: each calls the same function in `applications.js` that a protocol path or an `ldapmodify` reaches, against the same `ou=applications` entries. An API that covers eight of nine controls is worse than one that covers none, because the ninth is discovered by somebody who has already written the code that assumed it was there. Two things make keeping that rule cheap, and the third thing is why there is a test for it in the parent project.

The first is that **this API decides nothing**. Every POST calls the same action function the console's form posts to — `tokenAction`, `usersAction`, `claimsAction`, `vcAction`, `vpConfigAction` — with the action taken from the URL instead of from a hidden field, and every GET calls the same JSON view the page's `?format=json` answers. Those views became functions in `admin.js` for this reason (`consoleJson`, `metricsJson`, `tokensView`, `auditView`, `usersView`, `groupsView`, `claimsJson`, `vcJson`, `vpConfigJson`); they had been built inline in the route handlers, which was fine while there was one caller and is exactly the shape that produces two objects that agree today and not next month. So `admin_api.js` holds no opinion about what a revocation means that `admin.js` does not, and the way to see that is not to read the code: revoke a token through the API and RFC 7662 introspection calls it inactive, because there is one set of revoked jtis in this service and it is the same one `/oauth2/revoke` writes to.

The second is that **the OpenAPI document is generated from the table that registers the routes**. `admin_api.js` holds one row per resource — the handler, the parameters, the request bodies with their examples, the prose — and `admin_api_spec.js` turns that into the document. An operation therefore cannot exist and be undocumented, nor be documented and not exist. A specification file kept beside the code it describes is wrong within a month, and the way it goes wrong is silent: somebody adds an action to the console, adds it to the API, and does not touch the YAML.

The third is the direction neither of those can check. **Nothing in this service can see a form appear on a page**, so a new console control with no operation here would go unnoticed by everything above. That is asserted from outside, by this repository's own `tests/vendored/admin_api.js`, and it reads the facts off this service rather than off a list in the test: the console's own page list comes back in `GET /admin-api/status`, and each action handler, asked to perform an action that does not exist, replies with the names of the ones that do — "Unknown action "x". The four are: add, remove, clear, replace." Add an action to a switch and that sentence grows; the test then fails until there is an operation for it. The same test checks every property the document describes against a live reply, which has already caught two names that were wrong and unnoticeable: an `expiresAt` that is really `expiresAtMs`, and a group drill-down documented with its members at the top level when they are inside `group`.

**Eight POST routes serve thirty-nine URLs**, and the shape is deliberate. Express registers `/admin-api/tokens/:action` once; the document lists `/admin-api/tokens/revoke`, `/restore`, `/revoke-kind`, `/revoke-subject`, `/revoke-user` and `/revoke-all` as the six operations they are, each with its own body schema and its own example. One pattern keeps `GET /admin/sts-metadata` to one row per resource showing the parameter — the router is what that page reads, and twenty-four rows of near-identical prose there would bury the rest of the service — while the document describes URLs a caller can actually use. An action nobody has heard of is not a 404: it reaches the console's own handler and comes back as its refusal, naming the ones that exist, which is both the friendliest error and the sentence the parity check reads.

**The explorer at `/admin/api-explorer` is the only page in this console with a script on it**, and that is the one thing this feature costs. `app.js` sets `script-src 'none'` service-wide, which is what makes the whole family of reflected-content problems moot here rather than merely unlikely, so the explorer relaxes that header on its own two routes and in exactly two clauses: `script-src 'self'`, and an added `connect-src 'self'` so the page can call the API it documents. `default-src 'none'` and everything else stay as they are, and the console next door is still `script-src 'none'` — which the test asserts, because a middleware change that widened the exception would show up there first. The script is a **separate resource rather than an inline block for precisely that reason**: `'self'` is enough for a file, an inline block would have needed `'unsafe-inline'`, and `'unsafe-inline'` is the clause that would make the relaxation matter.

**It is this repository's own explorer rather than Swagger UI**, which was weighed rather than skipped. `swagger-ui-dist` is 11.7 MB unpacked and pulls in an install-time telemetry package, in a service whose `package.json` is deliberately short and whose image is built in containers that may have no network beyond the registry. What it would have bought is a familiar look, for an API with no authentication, no OAuth flows, no polymorphic bodies and nobody generating a client from it. `admin_api_explorer.js` is about 250 lines with no dependency and does the same three things — read the document, fill a form, show the response — plus the equivalent `curl` line beside each operation, which is what an operator of a mock actually copies. It is also the one file in this repository that is **not a node module**: `admin_api_docs.js` reads it off disk and serves it verbatim, so it has no `require`, no `process`, and builds every node with `createElement` rather than assigning `innerHTML` — it renders response bodies, which are not always this service's own.

**Every operation here requires an OAuth 2.0 access token since 2026-09-09, and this paragraph said the opposite until then.** It read: *"Nothing here is protected, for the same reason nothing else is"* — because this service checks no password anywhere, so an authenticated management API would have been the only authenticated surface in a service whose premise is that it authenticates nobody, and the only one a test would have to hold a secret for. Every clause of that was true, and the last one is what the change was for: this API is every control the console has, reachable by a machine, and it was the documented way to grant yourself both console roles.

Ask this service's own token endpoint: `grant_type=client_credentials` as the seeded client `sts-management-api` — whose secret is the `adminApi.clientSecret` setting — with `scope=admin:read admin:write` and **`resource=<base>/admin-api`**, which is what puts this API in the token's `aud`. A GET needs `admin:read` and everything else needs `admin:write`; they become the built-in `ADMIN_READ` and `ADMIN_WRITE` roles, so the requirement is stated in the same access-control policy as every other access decision here, and one middleware on the base path covers all 238 operations by construction. The credential is service-wide — verified against the default realm's key and audienced without a realm prefix — for the same reason the console's two roles are groups in the default realm: a per-realm one would let anybody who can create a realm mint themselves an administrator.

**The document says all of this** (`security`, two `securitySchemes`, and the scope on every operation), which it did not for a day after the gate arrived: `security: []` is OpenAPI for *no credential is needed*, so a generated client sent none and was refused 238 ways while the prose told it the refusal was a bug. `tests/admin_api_document_security.js` and `tests/vendored/sts_admin_api_auth.js` now hold the document to the gate from both ends.

**Both things the old paragraph was defending are still true.** A test still drives this API with no secret of its own — the launchers mint one token before any job runs and hand it to every one of them — and `adminApi.authRequired=false` restores the open API exactly, which is the way back in when nobody holds a console role. What is worth stating rather than implying, in either state: whoever can call this API can revoke every token this service has issued and change what the next one contains. That was already true of `/oauth2/token`, which will mint a token for any username asked of it. Do not put this service on a public address.

### DPoP — sender-constrained access tokens (RFC 9449)

A Bearer access token (RFC 6750) is a password: whatever can read the bytes can spend them. **DPoP** binds the token to a key — the token carries `cnf.jkt`, the RFC 7638 thumbprint of a public key — and every request presenting it must carry a fresh signature from the matching private key over *that request's* method and URI. The stolen bytes are then worthless.

**Where it applies, and where it deliberately does not.** OID4VCI 1.0 names DPoP exactly three times: its Security Considerations say the use of DPoP is **RECOMMENDED** for sender-constrained access tokens (mTLS being impractical for a native-app wallet), and its Nonce Response section says the Credential Issuer **MAY** return a `DPoP-Nonce` for use "when presenting an access token at the Credential Endpoint". So it covers the Token Endpoint and every protected endpoint the issuer publishes — Credential, Deferred Credential, Notification. **OID4VP 1.0 names it zero times**, and that is structural rather than an omission: in its own words "the result of an OpenID4VP interaction is one or more Verifiable Presentations … *instead of an Access Token*". There is no token in that exchange to sender-constrain, and the presentation's own proof of possession is the Key Binding JWT. A wallet is therefore right to offer no DPoP switch on its presentation pages; the parent project's carry a pane explaining why instead, with a table comparing the two proofs side by side (`typ`, what possession is proved of, where freshness comes from, `htu` vs `aud`, `ath` vs `sd_hash`). DPoP is also **indifferent to the credential format** — it binds an OAuth token, not a credential — so it works unchanged for `dc+sd-jwt`, `jwt_vc_json` and `ldp_vc`, and nothing in the implementation reads the format.

**On the server.** `dpop.js` implements all twelve RFC 9449 section 4.3 checks, labelled by number, plus `jti` replay detection; `oauth2.js` binds the access **and refresh** tokens (section 5 — a wallet is a public client, so an unbound refresh token would be a bearer credential that mints bound access tokens for whoever holds it, which is worse than not binding because `token_type` would claim a guarantee nothing checked), advertises `dpop_signing_alg_values_supported` (section 5.1 — the *only* signal that DPoP is on offer, so a server that supports it silently is never asked), honours `dpop_jkt` on the authorization request (section 10, which closes the window PKCE does not: a thief holding the code *and* the `code_verifier` still cannot sign for the key), and reports `DPoP` rather than `Bearer` from introspection. The protected endpoints had three copies of a Bearer-only check and now share **one** `presentedAccessToken()`, because a per-endpoint copy is how one of three ends up not demanding the proof — and the one that forgot is the one an attacker would use. There are **four** of them since UserInfo, which is why that function now lives in `dpop.js` rather than in `vc_issuer.js` where it was written: the fourth caller is in `oauth2.js`, and requiring vc_issuer.js from there would either build a cycle or move OID4VCI ahead of OAuth2 in the route order, while copying the check into the OAuth2 module is exactly the mistake this paragraph records having been made once already. `dpop.js` registers no routes and requires only `helpers.js`, so it is the one place both callers can reach. Note a limitation stated in that function: this issuer accepts tokens from a foreign authorization server and cannot verify them, so for such a token `cnf.jkt` is a claim anyone could have written; the binding is real only for tokens this service issued — and `verified` in what it returns is how UserInfo, which cannot live with that, tells the difference. There is deliberately **no "DPoP required" mode** — nonce mode makes proofs fresher, not mandatory — and the two nonce-request shapes are *not* shared code, because an authorization server asks with a 400 JSON body while a resource server asks with a 401 `WWW-Authenticate`, and getting that wrong leaves a conforming wallet with no way forward. `POST /dpop/nonce-mode` is a non-spec runtime switch so the handshake can be exercised without a restart; it is listed as non-spec on `/admin/sts-metadata`. **Since 2026-09-12 it writes `oauth2.dpopNonceRequired` for the trust realm it is reached in** — it was one switch for the whole process — **and product mode refuses it** as a test control; there the setting is changed through `/admin/oauth2` or `POST /admin-api/config/set`.

### Kerberos v5 — the protocol here that is not HTTP

Everything else in this service answers a request over HTTP. Kerberos speaks DER over
TCP and UDP port 88, so the KDC's listeners are **raw sockets**, and that one fact is
behind most of the design notes above: `listen()` instead of a require-time bind,
`/KdcProxy` for a browser that cannot open a socket at all, and a `/admin/sts-metadata` page
that cannot see any of it.

**Everything below about fixture accounts, shared passwords and names created on demand
is DEVELOPMENT MODE.** In product mode (`global.mode=product`) the principal database is
built without any of it: no alice, no delegation services and their rules, no second realm
or trust, nothing created because an AS-REQ named it, and no password on
`GET /krb5/principals`. What remains is `krbtgt/<realm>` and the account
`krb5.servicePrincipal` names — each only where `krb5.krbtgtPassword` and
`krb5.servicePassword` are set to something other than their published defaults. Every
listener binds `global.host`, `krb5.enctypes` decides whether RC4 is offered, and the replay
cache refuses a new Authenticator when full rather than forgetting one still inside its
window.

**A product KDC authenticates the directory's people with their own passwords (since
2026-09-12).** This paragraph said *the directory's people are not given Kerberos accounts,
so a product KDC authenticates nobody*. A person's password is stored as a scrypt hash and
no Kerberos key can be derived from a hash, so the keys are derived at the two moments a
plaintext password is in hand — when it is **set** (the console, `/admin-api`, the portal's
form, an activation link, the bootstrap) and when a sign-in **verifies** it (the sign-in
screen, an LDAP bind, SCIM Basic, a WS-Trust UsernameToken, SSF Basic, the password grant).
RFC 3961/3962/8009 string-to-key runs for every enctype in `krb5.enctypes` with the default
salt `<REALM><name>` (`EXAMPLE.COMalice`), and the keys are stored on the person's own entry
as ONE sealed value (`stsKrb5Keys`, with the public `stsKrb5KeyInfo` beside it). So:

* **Somebody who had a password before this existed gets keys at their first sign-in
  anywhere.** Until then the KDC refuses them `KDC_ERR_C_PRINCIPAL_UNKNOWN` with the e-text
  *this principal has no Kerberos keys yet - sign in once with the password, or reset it*.
* **A password change adds one to the kvno and replaces the keys**, so an AS-REQ with the
  old password fails pre-authentication. The previous version is kept only to open tickets
  already sealed under it — see *Previous key versions* below. A TGT already issued is sealed under the krbtgt key
  and is not recalled by a password change — Kerberos has no such mechanism.
* **The keys carry a stamp of the password hash they were derived beside**, and the KDC
  refuses keys whose stamp is not the entry's current hash — so a password changed by any
  door, an `ldapmodify` included, is never answered with a key from the old one.
* **The derivation is asynchronous and lags the password by a few tens of milliseconds**;
  in that window the person is refused rather than keyed from anything older.
* **Which trust realm: the one the password was set in (2026-09-15).** A trust realm whose
  `krb5.enabled` is on has a Kerberos realm and a principal database of its own, so the
  people it keys are the people in its own directory subtree, and their keys go onto their
  own entries there. A password set in a realm with no KDC derives nothing. Until that date
  the KDC was the process's and only the default realm's people were keyed.
* `krb5.personKeys` turns it off — the setting for a deployment whose Kerberos is a real KDC
  elsewhere and which uses this service only as an acceptor.

**Service principals with random keys** are created at `/admin/kerberos/principals` (or
`POST /admin-api/kerberos/principals/create-service`): a random key per enctype, stored
sealed on the application entry for `<spn>@<realm>`, and an **MIT keytab handed over once**.
Rotate replaces the key at the next kvno; delete removes it.

**Previous key versions are kept, for a bounded window.** A rotation or a password change
keeps the version it replaced, sealed in the same value as the current keys, as a real KDC
keeps the previous kvno in its database and a service keeps it in its keytab — so a ticket
issued under the old key an instant before the change is still accepted until it could have
expired, and is refused `KRB_AP_ERR_BADKEYVER` after that:

* at most `krb5.retainedKeyVersions` previous versions (default 1; 0 keeps none), each for
  `krb5.retainedKeyTtlS` (default 0, meaning `krb5.ticketLifetimeSeconds` plus
  `krb5.clockSkew` — no ticket here outlives its lifetime, a renewal needs an unexpired
  ticket and re-seals under the current key, and an acceptor tolerates the skew). Both
  bounds are applied at every read, so lowering either takes effect on the next request.
* **A kept version only OPENS a ticket already sealed under it** — at the KDC (the ticket in
  a TGS-REQ, or an S4U2Proxy evidence ticket) and at the acceptor. The KDC always issues
  under the current kvno, and **pre-authentication uses the current key only: an old
  password never signs in.**
* A rotation's keytab carries every kept version beside the new one, as MIT's `ktadd`
  without `-k` leaves a keytab.
* `/admin/kerberos/principals` and `GET /admin-api/kerberos/principals` list each kept
  version (kvno, enctypes, expiry) and never its key; **Drop previous versions**
  (`drop-previous-service-keys`, `drop-previous-person-keys`) ends the window at once — after
  a compromise, say — leaving the current key untouched.
* The `krbtgt` key has no rotation here, so it has no previous version: a TGT sealed under
  an older `krb5.krbtgtPassword` is still refused. The KDC issues tickets for that SPN under
the stored key in both modes, and the acceptor prefers a stored key for its own SPN over
`krb5.servicePassword` — which is how the acceptor in product mode gets a key without a
password printed anywhere. **No key is ever shown**: not on any page, not in any
`/admin-api` reply but the create's and rotate's keytab, not in the audit log, and not in
an LDAP search or the directory dump, which withhold both key attributes ciphertext
included.

**The two-message dance is the interesting part, not the ticket.** A client's first
AS-REQ usually carries no pre-authentication, and a real KDC does not treat that as an
error to be logged and forgotten: it answers `KDC_ERR_PREAUTH_REQUIRED` **carrying
PA-ETYPE-INFO2**, which is where the client learns the **salt** and iteration count it
needs to turn a password into a key. A client that treats that error as a failure cannot
authenticate to Active Directory at all. Both halves are implemented, and a principal
(`noreauth`) is configured the other way so the one-message case can be seen too.

The salt is why this matters and why it is a database rather than a formula. AD's salt
for a **user** is the realm followed by the sAMAccountName with no separator —
`EXAMPLE.COMalice` — and for a **computer account** it is a different shape entirely:
`EXAMPLE.COMhostws01.example.com`. An implementation that derives the salt from the
principal name works right up to the first machine account, which is exactly the point
at which somebody is debugging a service rather than a user.

**Any username, one password.** Everything else in this service checks no password at
all: the name typed at `/authn/login` becomes the identity and that is the end of it.
Kerberos cannot work that way, and the reason is structural rather than a decision — the
password *is* the key. Pre-authentication is a timestamp encrypted under it and the
AS-REP's enc-part is encrypted under it too, so a KDC that accepted any password would
still have to choose one to encrypt the reply with, and a client that used a different
one could not read the ticket it was sent. So the nearest thing the protocol allows is
what happens here: **one password, `password!`, shared by every user account, and an
account for every username that turns up.** A name nobody configured is created on first
sight with AD's user-shaped salt (`EXAMPLE.COMzaphod`) and a PAC identity of its own,
RIDs from 5000 up so a runtime account can be told from a configured one by its SID
alone. This applies to the second realm too, with *its* realm in the salt.

Three things are deliberately *not* included in that, and each is a failure worth
keeping:

* **A service principal is created only for a host this service will answer for.**
  `KRB5_SERVICE_DOMAINS` (default: the realm's own domain, plus `localhost`, `sts` and
  `127.0.0.1`) is the list, an entry matches a host that *is* it or ends with a dot and
  it, and anything else is still `KDC_ERR_S_PRINCIPAL_UNKNOWN` — the most common
  Kerberos failure there is, and one worth keeping producible (`HTTP/app.elsewhere.invalid`
  is what the parent project's tests use). The reason a KDC must not invent services in
  general is that it hands back a ticket sealed with a key the service does not hold,
  which surfaces at the AP exchange as *decrypt integrity check failed* — the same
  message a genuinely wrong key gives, pointing nowhere near the real cause. That does
  not apply here and it is worth being precise about why: **this process is both the KDC
  and the acceptor**, the acceptor looks the presented SPN up in the same table, so a
  ticket for a name created on demand opens with the key that sealed it. The acceptor
  answers for its canonical `KRB5_SERVICE_PRINCIPAL` and for names created this way —
  and for **no other configured account**, because `HTTP/frontend.example.com` and
  `HTTP/backend.example.com` exist to be separate identities and accepting their tickets
  would make this service every service in the realm. What forced the change: a client
  derives its SPN from the URL's host (`HTTP/<host>` — RFC 4559, and what every browser
  does), so every way of reaching this stack asked for a name nobody had configured.
* **The reserved names stay unknown** (`nosuchuser`, `nobody`, or whatever
  `KRB5_UNKNOWN_USERS` says), so `KDC_ERR_C_PRINCIPAL_UNKNOWN` is still reachable. A
  client that renders it as "wrong password" sends a person off to reset a password that
  was never the problem, which is exactly the misreading a debugger exists to correct.
* **A wrong password still fails**, with `KDC_ERR_PREAUTH_FAILED` and a re-sent
  PA-ETYPE-INFO2, because the client may simply have used the wrong salt.

Service, computer and `krbtgt` accounts keep their own distinct passwords. Nobody types
those, and `krbtgt/EXAMPLE.COM`, `krbtgt/PARTNER.COM` and the trust have to hold three
*different* secrets or every assertion about which key sealed which ticket would pass for
the wrong reason.

**The misconfigured principals are the product, not padding.** `GET /krb5/principals`
lists the whole database — names, salts, offered etypes, kvno, the
pre-auth/revoked/expired/ok-as-delegate flags, which entries were created at runtime, and
a sentence on what each account is *for*. It publishes no keys and no *service*
passwords; the one user password it does publish, in `accountPolicy`, is a policy of this
mock rather than a secret — every account holds it and this paragraph states it anyway,
and a debugger whose accounts cannot be used without reading the source is worse than one
that says so on the page. Among the configured accounts: `locked` (a disabled account), `expired` (a stale password),
`aesonly` and `rc4only` (whose etype sets are chosen so that a negotiation can be made
to fail on purpose, which in 2026 is what RC4 being switched off looks like),
`sensitive` (NOT_DELEGATED, the one control that stops unconstrained delegation), a
computer account, and a set of service accounts wired for the delegation cases below. A
debugger is judged on how it renders failure, and these are the failures a real
deployment produces — each drivable deliberately instead of by breaking something. So
is the clock: `KRB5_CLOCK_OFFSET` makes the KDC lie about its own time, because
`KRB_AP_ERR_SKEW` is one of the most common Kerberos failures in the field and the error
carries the KDC's time so a client can *measure* the difference rather than guess it.

**Every ticket carries a signed PAC** ([MS-PAC]), which is the half of Kerberos that
Windows added and that RFC 4120 knows nothing about. A ticket proves *who* you are and
says nothing about your groups; a Windows service authorizes on the groups. So
"authentication succeeded but access was denied" is nearly always a question about this
structure, and a debugger that decodes a ticket and stops at `cname` has shown the less
interesting half. Two things about it are silent when wrong and are why `krb5_ndr.js`
exists as its own module: the PAC's logon information arrives in **NDR**, Windows' RPC
marshalling, which is little-endian in a protocol whose every other integer is
big-endian and aligned from the start of the stream — miss one pad byte and every field
after it reads in range and false. It also sits three layers deep, inside
`AD-IF-RELEVANT`, so a reader that looks for ad-type 128 at the top level finds nothing.
A TGT gets two signatures and a service ticket four (sections 2.8.2/2.8.3). Claims and
device info are not produced, and **SID filtering across a trust is not implemented** —
a re-signed PAC keeps every SID it arrived with, which is the one place this mock is
more permissive than a real KDC in a way that matters.

**Two realms, one shared key, and a referral that looks like success.** This KDC answers
for both `EXAMPLE.COM` and `PARTNER.COM`, which a real one never does — the
simplification hides finding the other realm's KDC (DNS and SRV records) and none of the
protocol. A trust is not a setting: it is one principal, `krbtgt/PARTNER.COM@EXAMPLE.COM`,
whose key both realms hold. Ask for a service in the other realm and this KDC does not
refuse; it issues a ticket-granting ticket for that realm sealed with the trust key and
expects the client to notice. The trap is on the client side, which is why it is worth
being able to produce: the reply is a perfectly ordinary, successful TGS-REP, and the
*only* signal that it is a referral is that its `sname` is not what was asked for.

**Delegation, all four ways, with the distinctions drawn on purpose** ([MS-SFU]):
S4U2Self (`PA-FOR-USER`), S4U2Proxy under *either* authorization, forwarded tickets for
unconstrained delegation, and renewals. The asymmetry between the two S4U2Proxy routes is
the entire security story of resource-based constrained delegation, so both accounts
exist here rather than one: classic delegation is authorized by
`msDS-AllowedToDelegateTo` on the **front-end** account, which only a domain admin can
set, while RBCD is authorized by `msDS-AllowedToActOnBehalfOfOtherIdentity` on the
**back-end** account (`HTTP/rbcd.example.com`, naming `HTTP/frontend.example.com` as
permitted to act on its behalf) — so whoever controls that object can turn "I can write
to this computer account" into "I can reach this service as anybody". Same messages, same
KDC options, opposite direction of trust. Classic additionally
requires the evidence ticket to be forwardable, which S4U2Self grants only to an account
holding TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION — so `HTTP/frontend.example.com` and
`HTTP/notrusted.example.com` differ in exactly that one attribute and nothing else,
because that flag's absence is invisible where it is set: S4U2Self still succeeds and
returns a ticket that simply is not forwardable, and classic S4U2Proxy then fails a step
later complaining about the evidence. RBCD needs
neither, but does need `PA-PAC-OPTIONS` with the RBCD bit, without which [MS-SFU] says a
KDC MUST answer `KDC_ERR_BADOPTION` — an error mentioning nothing about padata, so it is
refused here with an explanation.

**A service that will not talk to you without a ticket** is what the whole workflow is
for: until something decrypts a ticket and proves its own identity back, "the ticket
looks right" is the strongest claim available. `krb5_service.js` is a raw TCP acceptor —
deliberately, because that is the shape of the Windows services people actually debug —
and `GET /krb5/service` describes it and the ordered checks it applies: the GSS wrapper,
the ticket decrypting under *its own* key at the kvno named, the ticket being for *it*
(a ticket for another service that happens to decrypt because two accounts share a
password must still be refused), the Authenticator under the ticket's session key, the
Authenticator's `cname` matching the ticket's, the clock, **the replay cache** (the check
a mock is most tempted to skip, and the only thing between a captured AP-REQ and a free
impersonation), and the 0x8003 checksum. If mutual authentication was asked for, the
AP-REP echoes the Authenticator's `ctime` under the session key, and that echo *is* the
proof — only something holding the service's long-term key could have learned the session
key to produce it.

**The 0x8003 checksum is not a checksum**, and it is the single most commonly botched
field in Kerberos. It is a structure carrying channel bindings and the GSS flags, and
`krb5_gss.js` writes it out explicitly because it fails in the least helpful way
available: a service answers `KRB_AP_ERR_INAPP_CKSUM` and nothing anywhere says "your
flags word is in the wrong byte order". Its fields are **little-endian**, alone in a
protocol whose every other integer is not, so a mistake there produces `0x02000000` where
`0x00000002` was meant — a request for delegation where mutual authentication was
intended. The `Bnd` field is sixteen **zero** bytes when there are no channel bindings,
not absent. And per-message tokens are keyed by who is speaking: an initiator signs with
key usage 25 and seals with 24, an acceptor 23 and 22, and the wrong pair produces a token
the far end cannot verify with an error naming the checksum rather than the direction.

The encryption framework (RFC 3961) covers the etypes Kerberos actually meets now:
aes128/256-cts-hmac-sha1-96 (17, 18 — the AD workhorses), aes128/256-cts-hmac-sha256/384
(19, 20 — RFC 8009) and arcfour-hmac-md5 (23), which is included because a debugger whose
only story about RC4 is "that is deprecated" cannot help anybody still running it. DES
decodes and is never produced: Windows Server 2025 removed it and it is not coming back.

**Not implemented, and each for a reason worth knowing:** FAST (RFC 6113), PKINIT,
kpasswd, SPNEGO (`krb5_gss.js` recognises the SPNEGO OID and says it is not implemented
rather than failing opaquely — the GSS layer is separate from the AP-REQ precisely so
that this is a wrapper to add and not a rewrite), request signatures, and the SID
filtering noted above. The **AP exchange** is not missing from the KDC — it belongs to a
service rather than to a KDC, and it lives in `krb5_service.js`.

### LDAP v3 — the other protocol here that is not HTTP

RFC 4511 is BER over a TCP socket, so `ldap_server.js` opens raw ones — **389 in the
clear and 636 over TLS** — and everything in this section is invisible to the HTTP half
of this service. Five things follow, and three of them are the same ones the KDC's
section records.

**Product mode changes three things about this section.** The directory is seeded with its
containers and nothing else — no alice, bob or carol, no `cn=admin`, no `cn=remote-pep-1`
or `cn=xacml-user-1` (the groups `roles.remotePepGroup` and `roles.xacmlUserGroup` name are
seeded EMPTY) — and no credential attribute or persona value is generated onto anybody. A
named simple bind is verified against the entry's `userPassword`, and its audit row says so.
And `ldap.plainListener=false` leaves 389 unbound, which is what a deployment whose binds
are verified wants; with it on, product mode warns at startup. Both sockets bind
`global.host`, and LDAPS takes `tls.minVersion` and `tls.ciphers`.

**Requiring the module does not start the listener.** Every other module here registers
its endpoints at require time, and for a route that is harmless; binding a privileged
port is not, because it can fail and a require that throws takes the whole service down.
So `server.js` calls an exported `listen()` and reports its failure, and the service
still starts without a directory rather than not starting at all. A failure to bind is
also **published** — `listening` and `listenError` on `GET /admin/ldap/service` — because that page is
HTTP and answers 200 either way, so without those fields there is no way to tell a
running directory from one whose listener lost a race with the host's own `slapd`.

**`GET /admin/sts-metadata` cannot see a raw socket**, and there are two of them here. The five
LDAP rows it does carry — `/admin/ldap/service`, `/admin/ldap/directory` and the three
container pages beside them — are this service describing its own store; none of them is LDAP.
They are admin console pages since 2026-09-01, and grouped under LDAP on that index rather than
with the other console pages because what they describe is this family. The second is the most
useful of the five: it lists every entry with **where it came from** —
seeded, added over LDAP, or created because somebody authenticated — which is what lets a
reader tell an empty directory from a search filter that matched nothing.

**The library is a SUBMODULE and it is not modified.** `"ldapjs": "file:node-ldapjs"`
points at [`rcbj/node-ldapjs`](https://github.com/rcbj/node-ldapjs), pinned by commit.
Since this repository is itself a submodule of the parent project, that makes it a
submodule of a submodule: `git submodule update --init sts` over there stops one level
short, and **`--recursive` is required**. An uninitialised submodule is an *empty
directory*, so the image builds, npm installs a package with no `main`, and the container
dies at startup with `Cannot find module 'ldapjs'` — naming a package rather than a
submodule. Two smaller consequences: it has to sit inside this package root, because npm
installs a `file:` dependency as a symlink and node resolves that package's own requires
from where the real directory lives; and `npm install` brings its devDependencies (tap,
eslint, ~200 packages, a dozen advisories), which is why `.npmrc` carries `omit=dev`.

**Every bind succeeds**, any DN and any password, anonymous included — with the single
exception of the literal password `invalid`, which is `LDAP_INVALID_CREDENTIALS` (49).
That is the same convention the password grant, WS-Trust and the WS-Federation sign-in
screen already follow, and it is what keeps 49 reachable: a directory that could not
produce one would make "the bind failed" untestable, and 49 is the code an LDAP client's
error handling is built around.

#### LDAPS on 636 — the same directory, and what TLS does not change

Port 636 is the **same directory over TLS**: the same handlers, the same store, the same
every-bind-succeeds. What TLS adds is that the password is not on the wire in the clear.
It does not make it *checked* — this service still authenticates nobody — and saying so
is the point, because "it is over TLS" is exactly the sentence people substitute for "it
is authenticated".

**Two ports rather than StartTLS, and that is not a preference.** StartTLS is an
*extended operation* (RFC 4511 section 4.14) that upgrades a connection already in
progress, and ldapjs implements no extended operations at all — so offering it would mean
patching the submodule, which this repository does not do. Worth knowing which of the two
is the standardised one, since it is the opposite of what the port numbers suggest: RFC
4513 specifies StartTLS, and left `ldaps://` as the de-facto scheme it already was. No RFC
defines the thing every client speaks.

**Two server objects, one set of handlers.** ldapjs chooses between a `net.Server` and a
`tls.Server` **at construction**, from whether it was handed a certificate and key, so
LDAPS is a second server *object* here rather than an option on the first — and handlers
are registered per instance. The `server` that every `server.bind(...)`, `server.search(...)`
and the rest in that file is registered against is therefore **not a server**: it is a
fan-out over the eight operations plus unbind, which registers each handler on both
instances. The alternative was a second copy of three hundred lines of handlers or a reach
into ldapjs's internal `routes` map, and this repository consumes that submodule through
its public API only. The failure it exists to prevent is a handler that lands on one
listener and not the other, which presents as a search that works on 389 and fails on 636
— read as a TLS fault, which it is not. `listen`, `close` and `address` are deliberately
*not* fanned out: each socket has its own port, its own bind failure and its own answer to
"are you up".

**One certificate for every TLS socket in this process.** The LDAPS listener serves the
certificate and key `tls_server.js` generates at require time — the same pair 8443 and
9443 present — rather than a second one. That is a decision about what a *caller* has to
do rather than a saved keypair: the certificate is self-signed and regenerated on every
start, so anybody who wants to verify this service has to fetch it and trust it, and one
anchor covering all three sockets is **one fetch**. Two keypairs would mean an
`ldapsearch` that verifies perfectly against a truststore built for the HTTPS ports
failing with `unable to get local issuer certificate` — an error that names nothing and
reads as a broken directory. Fetch it from `GET /tls/server-certificate`:

```bash
curl -k -s https://localhost:8081/tls/server-certificate > /tmp/sts.pem
LDAPTLS_CACERT=/tmp/sts.pem ldapsearch -H ldaps://localhost:636 -x \
  -D "cn=admin,dc=example,dc=com" -w 'password!' \
  -b "dc=example,dc=com" "(objectClass=*)"
```

`LDAPTLS_REQCERT=never` is the habit that endpoint exists to avoid, and here it would also
hide the one thing on this listener worth checking.

**No client certificate is ever asked for on 636.** This listener proves the *server* to
the client and nothing more; a certificate offered to it is not requested and would not be
a login if it were. The HTTPS listeners next door are where client certificates are the
whole subject — and even there, a verified one is explicitly not a login. `GET /admin/ldap/service` says
this rather than leaving somebody to work out why the certificate they configured was
never sent.

**It changes the require order, and `server.js` says so out loud.** `ldap_server.js` now
requires `tls_server.js` — for the certificate, nothing else — so node loads that module
first whatever `server.js` says. Since **the require order in `server.js` is the route
order**, the line there was moved to match: `./tls_server` before `./ldap_server`. It
changes no output, because `/admin/sts-metadata` sorts its rows by path within a group; it keeps
that file honest for the next reader.

Finally, the two listeners are **published separately** on `GET /admin/ldap/service` — `listening` /
`listenError` for 389, and a `tls` object carrying `ldaps`, `port`, `listening` and `error`
for 636 — because that page is HTTP and answers 200 whichever of them is up. "389 is up and
636 is not" is the ordinary outcome of a host run, and a single flag could only report one
of them. The admin console's user page reads the same fields and warns in three cases
rather than two, for the same reason: telling somebody no client can connect while LDAPS is
answering costs them an afternoon.

#### What it enforces, and the one thing it deliberately does not

It is **schemaless on purpose** — no objectClass is enforced, no attribute is checked
against a syntax, no `must`/`may` is consulted — and `GET /admin/ldap/service` says so rather than
leaving a reader to infer a schema that is not there. A real directory would refuse most
of what this one accepts, and where that matters it is a difference somebody should be
told about rather than one a mock should hide by inventing a schema of its own.

Four rules are enforced anyway, because each is real and its absence would teach a client
something false:

* an add whose **parent does not exist** is `noSuchObject` (32). A directory is a tree,
  and a client that has never seen this refusal will write its first entry into a real
  directory and not understand the error;
* a delete of an entry that **has children** is `notAllowedOnNonLeaf` (66);
* a modify `delete` naming an **absent attribute** is `noSuchAttribute` (16);
* **deleting an attribute's last value deletes the attribute**, since an LDAP attribute
  always has at least one value (RFC 4511 section 4.1.7) — which is why a second delete of
  the same attribute is a 16 rather than a no-op.

A modify is **atomic**: the changes are applied to a copy and the copy replaces the stored
attributes only once every one of them has been accepted. Applying them in place and
rolling back on failure is the same thing written so that a bug leaves half a change
behind.

And one rule is deliberately **not** enforced, stated here rather than discovered:
**deleting a user does not remove its DN from the groups that list it as a `member`.**
Referential integrity is a feature of some directories and not of the protocol — OpenLDAP
needs an overlay for it and Active Directory does it in the DSA — so the dangling member
is the honest result, and it is what a `member`-based group search should then show. It is
also what the admin console's `/admin/groups` page counts separately from the members that
resolve, rather than reporting one number that would make a group of seven whose members
are five look untouched.

#### An LDAP object for every user who authenticates

`LDAP_AUTOCREATE_USERS`, on by default, grows an entry at
`uid=<name>,ou=users,<base>` the first time anybody authenticates through **any** of the
other twelve families here — the OAuth2 login screen, WS-Trust, WS-Federation, a Kerberos
AS-REQ, a passwordless WebAuthn assertion.

That is **one hook and not twelve**, because `admin_stats.recordAuthentication()` is
already the single funnel every one of those call sites goes through at the moment a
credential is ACCEPTED. The hook is **inverted**, exactly as `helpers.js`'s
`setJwtRecorder` is: `ldap_server.js` requires `admin_stats.js` — it needs `identityOf`'s
normalisation, so that `alice`, `alice@REALM` and her `urn:uuid:<entryUUID>` subject
seed one entry and not three — so `admin_stats.js` cannot require it back without a cycle. It offers a
slot instead, and `ldap_server.js` fills it at require time. The observer's return value is
ignored and a throw from it is caught: a directory must never be able to fail an
authentication.

**The entry also records HOW they authenticated, where the protocol says.** Most families
here say nothing: `amr` is an OIDC vocabulary and a Kerberos AS-REQ, a WS-Trust
UsernameToken and an LDAP bind have nothing to put in it, so nothing is written for them
— an absent attribute is "this service was never told", which is a different claim from
"this service checked and it was one factor" and must not be written as one. What the
sign-in screen does say arrives on the same observer as everything else and lands in
three attributes, which are separate because merging them loses one of the three:
`authnMethod`, every RFC 8176 method this person has *ever* used here, accumulated;
`mfaAuthenticated`, `TRUE` or `FALSE` for the **most recent** authentication and so
overwritten rather than appended; and `mfaLastAuthTime`, when multi-factor last happened
and never cleared. So a person who used a key yesterday and a password today reads
`FALSE` with the timestamp still there, which is the honest answer to both questions.

That is what a **WebAuthn second factor** adds to this directory and the whole of it: the
password step already named the person, their entry already exists, and the key writes
`mfaAuthenticated: TRUE` rather than a second entry for a second identity that is not
one. A **passwordless** WebAuthn sign-in is the other case and needs nothing special —
it is an authentication, so the entry is created the ordinary way, and what these
attributes then record is that the single factor was a key: `authnMethod: hwk` with no
`pwd` beside it, which is the only place a reader can tell it from a password sign-in
afterwards. Two factors means two: `["hwk"]` alone is `FALSE`. Like the `x509*` and
`did*` names these are **this service's own and not schema** — there is no standard
attribute type for "this account used more than one factor", and the nearest things in
the wild are Active Directory's `msDS-*` attributes, which name something else. And
like a group here, they **grant nothing**: no endpoint reads them and nothing decides
anything on them. Unlike a group, no token carries them either — `groups.claim` puts
membership in a token and there is no equivalent for these three.

The admin console shows each user their entry, on `/admin/users?user=<name>`, and reads it
through a **second inverted hook** — `admin.setDirectoryReader()`, filled by this module at
require time — for a reason that is about route order rather than about cycles. See the
`/admin/users` section above.

**Every operation on this directory is also an audit event**, and that is the one place in
the service where the recording is per handler rather than behind a funnel — ldapjs
dispatches straight into the handler for each operation, and what a row has to say
genuinely differs between them. `/admin/audit?category=directory` is the list: an entry
created, deleted, updated, renamed, searched, compared or bound to, over plain 389 and
LDAPS 636 alike, with the bound DN as the actor and the socket as the channel. Three
things there are worth knowing. **No value is ever recorded** — a modify names the
attributes it changed, because a modify is where a `userPassword` gets set, and a compare
says whether it matched and not what was tried, because comparing against `userPassword`
is how a client checks a password without binding. **What counts as a user is placement**,
the same rule `/admin/groups` reports by, so an add under `ou=users` is a `user.create` and
the identical add one level over is a `group.create`; believing the `objectClass` the
client sent would file both wrongly in a directory with no schema. And a delete records
**how many memberships were left dangling** by it, which is the only record of when that
happened: this directory does not enforce referential integrity, so the DN stays in every
group that listed it, and `/admin/groups` can show the resulting state but never say when
it arrived.

Two identities are skipped, and both are deliberate. **An LDAP bind** does not seed one,
because the identity a bind presents is a DN — it already names an object in this very
directory, so `uid=cn=admin\,dc=example…` would be nonsense and this service's own binds
would grow the directory without bound. **An OAuth client** does not either: a client is
not a person and `ou=users` is for people, a distinction the admin console already makes
with its `isClient` flag, which is what this reads.

**One entry per person, however many ways they get in.** `rcbj` at the login screen,
`urn:uuid:<entryUUID>` in a token (or the retired `urn:sts:user:rcbj` in an older one),
`rcbj@STS.MOCK` in a Kerberos AS-REQ and `rcbj` on a WS-Security `UsernameToken` are one
entry: `identityOf()` resolves a subject through the directory, strips the legacy prefix
and the realm before the observer sees any of them, so every name-shaped family here —
OAuth 2.0, OpenID Connect, both SAML profiles, WS-Federation, WS-Trust, Kerberos, SPNEGO
— lands on `uid=rcbj,ou=users` and simply adds a line to its `description`.

What did **not** fold was the one identity that is a DN rather than a name. A client
certificate saying `CN=rcbj` became `cn=rcbj,ou=users`, which is a second object for a
person who already had one — and the reverse order produced the same pair, since a
password sign-in after a handshake would build `uid=rcbj` beside it. `existingUserEntry()`
is the whole of the fix: before a plan names an entry it asks whether this person already
has one, matching on the two things that can carry a username under `ou=users` — the
entry's own **naming RDN value**, whatever attribute type names it, and any **`uid`** it
carries. Case-insensitively, because the store already keys DNs lower-cased. Scoped to
entries directly under `ou=users`, because this directory is schemaless and placement is
the only rule that cannot be lied to.

**The same function answers at every other door**, which is what makes it a rule rather
than a habit. An `ldapadd` under `ou=users` whose username is already here is
`LDAP_ENTRY_ALREADY_EXISTS` (68) naming the entry that holds it — so `uid=rcbj` and
`cn=rcbj` cannot both exist, and neither can `sn=someone` carrying `uid: rcbj`. The
console's create form on `/admin/users` and `POST /admin-api/users/create` get the same
refusal, because all three call one function. Without that, the fold could be undone from
the other side in a single operation, with nothing having gone wrong that a reader could
point at.

**A DID is the one identity that generally cannot fold**, and that is a fact about DIDs
rather than a gap. `did:jwk:eyJrdHkiOi…` names nobody by itself — that is why its entry is
named by a digest of it. But at the Credential Endpoint this service *does* know: it
decides who a credential is about from the access token and derives the holder's DID from
the key the wallet proved possession of, in one call, so it passes the username through as
`linkedTo` and the identifier goes onto that person's entry as a `didSubject` value beside
their name. `didSubject` is multi-valued, so a wallet holding several keys for one person
puts several DIDs on one entry rather than one each on several. When that DID is later
presented to the Verifier — with nothing saying whose it is — the entry that already
records it is found by `didSubject` and nothing new is created. A DID this service has no
link for still gets its own digest-named entry, because inventing a person to attach it to
would be worse than a digest for a name.

**And one identity is not a name at all: a verified TLS client certificate.** Its
subject is already a DN, so the entry is not `uid=<name>` and is placed by
`certificatePlan()` instead — at the subject itself where that lies under this
directory's base, and otherwise under `ou=users` named by the CN — or, where that CN is somebody
this directory already holds, **on their existing entry**, with the whole subject, the
issuer, the serial and the validity written onto it — with the subject's
other RDNs kept as attributes and the certificate's own facts written on as `x509*`
attributes that are this service's names rather than schema. The TLS section above
carries the reasoning, including what the placement costs and why `userCertificate` is
not one of those attributes. The `x509subject` value is also how the admin console
finds the entry again: an identity that is a DN is looked up by the subject the entry
recorded rather than by a name, which is exact and stays right if the naming rule ever
changes.

**And a third identity is not a name either: a DECENTRALIZED IDENTIFIER.** Three
places in this service hand one over — the subject of an issued `ldp_vc`, which is a
`did:jwk` built from the holder key the wallet proved possession of; whatever DID
presents a credential to the OID4VP Verifier; and the `did:jwk` that `/did/generate`
mints on request. None of the three used to reach `recordAuthentication()`, so none of
them had a directory entry, and the cost was visible in this issuer's own log line:
*"the credential will describe … with no directory entry to read from"*. A Credential
Issuer is exactly where that matters, because OID4VCI lets the authorization server be
somebody else — so a **foreign** access token, whose subject this service has never
seen, is the ordinary case rather than the edge one.

They are placed by `didPlan()`, and the placement is the opposite problem from a
certificate's: a certificate subject is already a DN and needs a *place*, while a DID is
neither a DN nor a name but one long opaque string. Writing it out — `uid=<the
did>,ou=users` — is correct and unusable, because a `did:jwk` carries a base64url-encoded
JWK and the DN runs to several hundred characters of key material; giving them a
container of their own, `ou=dids`, is tidy and would put them outside the two sweeps that
matter, since `populateVcAttributes()` walks `ou=users` and `/admin/groups` reports
membership from there. So the entry goes under `ou=users` with everybody else and is
**named by a short digest** — `uid=did-<12 hex of the SHA-256 of the DID>` — with the
identifier itself kept whole as `didSubject` and its method as `didMethod`. Those are
this service's own attribute names for the same reason the `x509*` ones are: DID Core
postdates the LDAP schema documents by two decades and nobody has registered one.

What that costs is worth stating plainly: **on those entries the `uid` is not the
identity**. Everywhere else here it is what the person typed; on a DID entry it is a
name this service made up. `didSubject` is the identity — the admin console finds the
entry by it, exactly as it finds a certificate's by `x509subject`, and the persona that
fills in a credential's claims is invented from it rather than from the digest, so the
startup sweep and the authentication path describe one person and not two.

**A SPIFFE identity is the fourth shape, and it is filed exactly like a DID and
for the same reasons.** `spiffePlan()` names it `uid=spiffe-<12 hex>,ou=users`,
keeps the identifier whole on the entry as a multi-valued `spiffeSubject` with
`spiffeTrustDomain` and `spiffePath` beside it, and `locateEntry()` finds the
entry by that attribute rather than by rebuilding the digest — which is what
makes one workload arriving three ways (an X509-SVID at the SPIRE Server API, an
agent attesting, a JWT-SVID validated) **one** entry with one description per
route, rather than three. Two things about it differ from the other three plans
and both are deliberate. It does **not** consult `existingUserEntry()`, so it
never folds onto a person of a similar name: the last segment of a SPIFFE path is
exactly the kind of short common word (`db`, `web`, `api`) that collides with a
username, and a workload called `db` is not the DBA. And it goes under `ou=users`
rather than `ou=applications`, which is a decision rather than an oversight —
that container holds what this service was *asked about*, where an application is
the audience of a token, and a SPIFFE identity is the **subject** of one, like the
TLS client certificate for a machine that already lands here.

**There is a fourth way onto that entry and it is not an acceptance: this trust
domain *issuing* the identity a certificate.** Every X509-SVID minted here writes
the certificate onto the holder's entry, using the **same six `x509*`
attributes** a verified TLS client certificate writes and in the same strings —
`spiffe_ca.js` reads them back off the certificate it has just issued with node's
own parser, and both DNs go through the one `dnRfc4514()`, which is why that
function now lives in `common/helpers.js` rather than in `tls_server.js`. Two
spellings of one DN would be two people on `/admin/users`. The one rule that
differs is that these six are **assigned** rather than appended, because an SVID
is minted afresh every half-lifetime and appending would grow the entry for as
long as the workload runs; `x509svidsIssued`, `x509firstIssued` and
`x509lastIssued` are what is left of the history. The SPIFFE section has the whole
of it, including why `spiffeCredentialStatus` is **not** a revocation.

**None of the three DID cases is a sign-on**, and each says so on its own record. A presentation
that verifies still starts no session and issues no token — the Verifier's own section
says why, and this is the same distinction a verified client certificate draws: it is
*recorded*, which is a narrower claim and must not be merged with the other. A credential
request records that an access token was presented, not that anybody authenticated; this
service does not verify tokens it did not issue. And `/did/generate` records an identity
this service *created*, with nothing presented at all. The one DID deliberately left out
is the `did:web` that endpoint returns for `?method=web`: that is this service's OWN
identity, already published at `/.well-known/did.json`, and an entry for it would file
the issuer among the people with an invented given name and a fictional mailbox attached
to the thing that signs every credential.

**What the entry holds is now decided partly by `/admin/vc`.** The attributes that make it
a person — its `objectClass`, `uid`, `cn`, `sn`, `givenName`, `displayName` and `mail` — are
written when it is created, and the name in them is an **invented** one rather than the
login name repeated: those are attributes an issued credential asserts, so an entry that
derived all of them from the login name made every credential say the login name back. The
`uid` and the DN stay the login name, because those two *are* the identity. On top of that,
every attribute the credential claim set selects and the entry does not already carry is
filled in — a birthdate, a nationality, the five components of an address, whatever else has
been ticked — invented from the same username seed, so an LDAP client and a wallet describe
one person. Nothing already on the entry is ever overwritten, which is why the three seeded
people keep their own names, and why an operator's `ldapmodify` survives every later sweep.
The console's own section above carries the rest of it, including what the sweep walks and
what it deliberately does not.

#### How an attribute name is spelt

The store lower-cases every attribute name, because `@ldapjs/attribute` lower-cases a
type on the way in — an entry added as `objectClass` comes back as `objectclass`. That is
harmless for matching, since LDAP attribute descriptions are case-insensitive anyway
(RFC 4512 section 2.5), and it is not harmless for *reading*: a page showing `givenname`
where every schema document says `givenName` reads as a bug in the page. So the directory
keeps a table of conventional spellings and puts them back on the way out.

The table covers about a hundred and fifty names, which is far more than this service ever
writes, and that is the point. **The directory is schemaless on purpose**, so a client can
`add` any attribute it likes to any entry; and two of the families here write entries
nobody typed — a verified TLS client certificate's subject becomes attributes RDN by RDN,
so which types arrive is decided by whoever issued the certificate. A table holding only
what this service happens to write would be right about its own entries and wrong about
everybody else's, which is worse than having none, because the reader who most needs the
conventional spelling is the one looking at an attribute this service did not write.
`seeAlso` is what made the point: an ordinary RFC 4519 type, rendering as `seealso` on the
one page whose job is to show an entry faithfully.

It is **two lists split by who defined the name** — the standard types, with the
specification named per group (RFC 4519, RFC 4524's COSINE, RFC 2798's inetOrgPerson,
RFC 2307's NIS, RFC 4512's operational and root-DSE attributes, RFC 4530, RFC 5020,
RFC 3045, PKCS#9), and this service's own inventions, which say individually why nothing
standard was used instead. `memberOf` sits in neither and is called out as such: it is
ubiquitous in the wild and was never registered by anybody, and the spelling being
conventional must not be read as the attribute being maintained — nothing here maintains
it, which is exactly what `/admin/groups` reports on.

Each name is written **once, as the canonical spelling**, and the lower-cased lookup key is
derived from it. It used to be a map of `lower: 'Mixed'` pairs, and the trouble with that
shape is that a typo in the *key* is invisible: the entry never matches, the name renders
lower-cased, and the table is failing silently at the only job it has. `toLowerCase()`
cannot disagree with itself.

Four independently maintained sets of spellings reach that table — the two lists, the
credential claim catalogue in `vc_claims.js` and the applications schema in
`applications.js` — so they all go in through one function, and a **second spelling of a
name already known is reported rather than silently resolved by merge order**. First
spelling wins; the warning names both and says which list to fix. It is a warning and not a
throw, because a table of how to capitalise a name must never be able to stop the service
starting.

#### Two ldapjs defects this code routes around

Both are in `SearchResponse.prototype.send()`, and both are worked around here rather than
patched in the submodule — the point of pinning a fork is to have a *usable* copy of
ldapjs, and a defect a real client would also hit is worth leaving visible.

The first is a **second, case-sensitive attribute filter** that runs after the handler has
already chosen what to send. It compares the entry's attribute name *lower-cased* against
the requested list held *exactly as the client sent it*, so a client asking for
`telephoneNumber` gets back everything it asked for except `telephoneNumber`. Every
attribute whose conventional spelling has a capital in it is silently dropped from a
*selective* search and from nothing else, which is why a search asking for everything looks
perfect. The trap inside the trap is that `send()`'s `nofiltering` argument does **not**
turn it off: that flag guards the two branches above this one, and this one has no guard
at all, while its documentation reads as though it covers everything.

What does turn it off is passing a `SearchResultEntry` **instance** rather than a plain
`{dn, attributes}` object — `send()` takes an early branch for one and writes it untouched.
Which leads to the second defect: **`messageId` defaults to 1**, so `send()`'s
`if (!entry.messageId)` never fires (1 is truthy) and the very next line throws
`SearchEntry messageId mismatch` for every search after the first on a connection. The
symptom is an uncaught exception in this log and a search that returns *zero entries and
then ends successfully*, which reads as an empty directory. `toSearchEntry()` builds the
instance with `res.messageId` and sidesteps both.

### SCIM 2.0 — the one family here whose purpose is to write

Every other protocol in this service answers a question about somebody who is already
there: issue this person a token, tell me who signed in, seal this ticket. SCIM (RFC
7642 for the *why*, 7643 for the schema, 7644 for the protocol) is how an identity
provider puts them there in the first place, and `/scim/v2` is a provisioning endpoint
that does it.

**What it provisions into is the LDAP directory in the section above** — the same
entries, the same cap, no second store and no cache:

```
POST /scim/v2/Users {"userName": "dave"}
    -> uid=dave,ou=users,dc=example,dc=com          the entry, not a copy of one
    -> ldapsearch -b ou=users '(uid=dave)'          finds it
    -> GET /admin/users?user=dave                   shows it
    -> /admin/vc's selection sweeps it              so a credential has something to assert
    -> an access token for dave                     carries its attributes
```

That is the whole design, and a SCIM server with a `Map` of its own beside the directory
would have been half the code and taught a provisioning client nothing. The interesting
property of a SCIM endpoint is that what it writes is what everything else then reads.
`scim_map.js` owns which LDAP attribute each SCIM member is; `ldap_server.js` owns where
the containers are, what counts as a person and what counts as a group; `scim.js` is the
boundary, which is why it is short.

**It is the fifteenth protocol family, and it became the fifteenth *authentication*
family when these endpoints started requiring a credential** (SPIFFE is the
sixteenth, and arrived after it) — which is a change from
what this document used to say, and the change is narrower than it looks. Three of the
schemes at `/scim/v2` present a credential on every request (Basic, Digest, HOBA), and
accepting one of those is an authentication like any other, so it reaches
`recordAuthentication()` and its caller appears on `/admin/users` under protocol `SCIM`.
The other three do not, because each *continues* an authentication already recorded:
an access token was accepted when it was issued, a session cookie when its session began,
and a client certificate once per connection rather than once per request.

What has **not** changed is the distinction that mattered here first: **being provisioned
is not authenticating**. The person a SCIM client creates has signed in to nothing. So a
person created here gets a directory entry with `origin: scim` and no row on
`/admin/users` until they actually turn up and authenticate — which is the honest
distinction, and the same one this service draws
everywhere else between an identity being *recorded* and an identity having *authenticated*.

#### The `id` is the entry's `entryUUID`

RFC 7643 section 3.1 asks for an opaque, server-assigned, unique identifier the client
must not parse and that is never reassigned. Since 2026-09-14 that is the entry's
**`entryUUID`** (RFC 4530): assigned when the entry is created, kept through a rename,
and new for a person deleted and created again under the same name.

```
GET /scim/v2/Users/5503c620-f13d-42e9-a841-fbfbe4cf8899
```

It is the same value a person's tokens carry in `sub`, as `urn:uuid:<entryUUID>`. Group
`members[].value`, a User's `groups[].value` and the enterprise `manager.value` are ids
too; the service stores the DNs they name, because that is what LDAP's `member` and
`manager` hold. **A DN presented as an id still resolves**, for a client that stored one
before the change, and the resource comes back with its new id.

It was the DN until that date, on the argument that the DN was already the key the entry
is stored under. That argument lost to its own stated cost: an LDAP rename gave the same
person a new SCIM id, and once a person's `sub` became stable a SCIM id that was not would
have been the one identifier here still reassigned by a rename.

#### A create goes through the directory's own door

SCIM is the **fourth** way a person can be put in `ou=users` — after an `ldapadd`, the
console's form and `POST /admin-api/users/create` — and the last two already share
`createUser()` in `ldap_server.js` so that "creating a user" cannot come to mean two
things. `scim.js` calls the same function. What it keeps for itself is only the
translation: `createUser()` returns errors for a person to read on a web page, and a
SCIM client needs a status and a `scimType`.

It was written the other way first, and all three of the home-made rules turned out to
be weaker than the one they were standing in for:

* **The DN.** It built `uid=<userName>,ou=users` directly, skipping `namePlan()`'s
  *fold* — the rule that lands a new name on the entry that is already this person's
  under a different naming attribute, a client certificate's `cn=rcbj,ou=users` say.
  Bypassing it creates a second object for one person, which is precisely what the fold
  exists to prevent.
* **Uniqueness.** It scanned for a matching `uid` *attribute*. `existingUserEntry()`
  matches the RDN value too, so somebody whose only entry a certificate had named by
  `cn` was invisible to the scan and SCIM would create them again — the "one entry per
  person at every door" rule broken at the newest door.
* **The name.** Both refused RFC 4514's reserved characters and the two lists had
  already drifted by one (`#` anywhere, versus only leading). There is now one regex,
  `nameUsableInDn()`, exported and read by all three doors; a group create has no
  `createUser()` to defer to, so the check is shared even though the door is not.

One consequence worth knowing: `createUser()` writes its own `user.create` audit row —
and now takes a `protocol`, so the row says SCIM rather than LDAP — which is why
`scim.js` records only updates and deletes. Two rows would be one act counted twice at
the same layer.

#### A PUT replaces the window, not the entry

Read strictly, RFC 7644 section 3.5.1 says a PUT replaces the resource — and against an
LDAP entry that would mean a provisioning client deleting `schacDateOfBirth`,
`authnMethod`, `mfaAuthenticated` and every `x509*` attribute the moment it updated
somebody's phone number. Those are facts SCIM never knew about, cannot send back, and
cannot restore.

So SCIM sees a **window** onto the entry: `fromScimUser()` is handed the attributes the
entry already has, removes every attribute the mapping covers, and writes the ones the
resource carried. Everything outside the window comes through untouched. A client that
means to remove a mapped value still can, by omitting it, which is what PUT semantics are
actually for.

Three attributes are deliberately dropped on the way through and not written back:
`entryDN`, `createTimestamp` and `modifyTimestamp`. None of them is really *on* the entry
— the DN is synthesised from where the entry is stored (RFC 5020) and the timestamps
belong to the entry rather than to whoever wrote it — and carrying them through wrote
them, which produced exactly the stored-copy-of-the-DN the synthesis exists to prevent.
An audit row naming `entryDN` among the attributes a SCIM PUT had just written is what
showed it.

#### Authentication — the one surface here that asks

Almost every other endpoint in this service answers anybody — the SPIRE Server
API is the one other exception, for a related reason — and these do not. The
reason is what they are: `/scim/v2` creates and **deletes** accounts in a
directory that fifteen other things then read. A provisioning endpoint that asks nobody's name is the one place
in a permissive mock where *permissive* stops being a teaching device and becomes a shape
somebody copies into a real deployment.

**RFC 7644 section 2 is shorter than people expect.** It defines no SCIM credential at
all: "The SCIM protocol is based upon HTTP and does not itself define a SCIM-specific
scheme for authentication and authorization. SCIM depends on the use of Transport Layer
Security (TLS) and/or standard HTTP authentication and authorization schemes as per
[RFC7235]." What it does is *name* six ways — TLS client authentication, HOBA, bearer
tokens, proof-of-possession tokens, cookies, and HTTP Basic, which it discourages in
those words — and state two normative sentences. **All six are implemented here**, and
both sentences are honoured:

* a provider **SHALL** indicate its supported schemes in `WWW-Authenticate`. Every 401
  from these endpoints carries one header per offered scheme.
* a provider **MUST** be able to map the authenticated client to an access control policy.
  This service has one, and it is two lines long, which is the honest length for a mock.

| Scheme | `type` in the ServiceProviderConfig | What it costs a caller |
|---|---|---|
| **OAuth 2.0 Bearer token** (RFC 6750) | `oauthbearertoken`, `primary` | An access token from this service's own token endpoint, from **any** grant, carrying `scim:read` or `scim:write`. Verified as `/oauth2/userinfo` verifies: this service's signature, not revoked, right audience |
| **DPoP / proof-of-possession** (RFC 9449) | `oauth2` | The same token, bound to a key and presented with a proof. An RFC 8705 certificate-bound token is honoured on the same path |
| **HTTP Basic** (RFC 7617) | `httpbasic` | Any username, any password except the reserved `invalid` |
| **HTTP Digest** (RFC 7616) | `httpdigest` | Any username, and **the password really is checked** — see below |
| **HOBA** (RFC 7486) | `hoba` | A signature over the server's challenge, verified against a key anybody may register |
| **Session cookie** | `httpcookie` | The browser sign-on session `/authn/login` already creates |
| **TLS client certificate** | `tlsclientauth` | A certificate that verified against an anchor POSTed to `/tls/trust` |

**The access control policy.** An OAuth credential may do what its scopes say: `scim:read`
to read and `scim:write` to write, and **neither implies the other** — a read-only
provisioning credential is a thing a client has to handle, and a server that treated one
scope as both could not produce one. **Every other scheme may do both**, because none of
them carries a scope. That is worth reading twice, because it has a consequence: a caller
who cannot get a scope can simply use Basic instead. Which is why every scheme has a
switch of its own — a deployment exercising a client's scope handling turns the other
five off, and then the only way in is the one being tested.

**These are the first OAuth scopes anywhere in this service that are read for anything.**
They are published in `scopes_supported` in both discovery documents, and this
authorization server grants what it is asked, from any grant, to any `client_id`. So what
the requirement exercises is the *client's* handling of a scope, not this service's
willingness to withhold one.

**Two schemes really verify something, and both for the same reason.** HTTP Digest hashes
the password into the response, so a server that accepted any response would not be
performing the exchange at all — and the half of a client that this exercises *is* the
part that computes that hash. So Digest does what Kerberos does, for the same reason and
with the same shape: any username authenticates and every one of them shares one password
(`scim.digestPassword`, `password!` by default — the value `KRB5_USER_PASSWORD` already
defaults to, so there is one fact to remember rather than two). HOBA is the same argument
about a signature: it is genuinely verified, RSA with SHA-256 over RFC 7486 section 5's
length-prefixed blob, and what is permissive is the *registration* — anybody may register
any key for any name at `/.well-known/hoba/register`, which is unauthenticated for the
reason `POST /tls/trust` is: it is how a caller **gets** a credential. The key lands on
that person's own directory entry as `hobaPublicKey`, so an `ldapsearch` and
`/admin/users` show it.

**In product mode (`global.mode`) neither of those permissive halves holds.** Digest is
not offered at all — RFC 7616 needs the server to hold each password or its digest hash,
and product mode holds only a salted scrypt hash, so the only Digest left would be the
shared `scim.digestPassword`, which is not a credential. And a HOBA key may be registered
to an existing account only from a browser session signed in as that account, and a
registration never creates one. **In every mode** a key id already registered to another
account is refused, because a HOBA credential names its key by id alone.

Between them those two make five negatives reachable that no permissive server can
produce: a wrong password, a stale nonce (`stale=true`, which a conforming client retries
silently and a hand-written one usually does not), a replayed nonce count (refused
*without* `stale`, because the credential was valid and has been seen before — a
different sentence deserving a different answer), a signature that does not verify, and a
replayed HOBA triple.

**The discovery endpoints are open.** `/ServiceProviderConfig`, `/ResourceTypes` and
`/Schemas` answer without a credential unless `scim.authDiscovery` says otherwise, which
is the bootstrapping argument `POST /tls/trust` already makes: the ServiceProviderConfig
is where a client *reads* which schemes exist, so demanding a credential to fetch it means
a client must already know the answer to the question it is asking. RFC 7644 section 4
says nothing either way, so both are conforming and the other one is a setting away.

**The ServiceProviderConfig publishes all seven rows and three of them have no canonical
`type`.** RFC 7644 section 2 names six schemes; RFC 7643 section 5 gives
`authenticationSchemes.type` five canonical values — `oauth`, `oauth2`,
`oauthbearertoken`, `httpbasic`, `httpdigest` — and the two lists do not cover each other:
there is no canonical value for a client certificate, a cookie or HOBA. `scimmy` enforces
the canonical five, which is a correct reading of that document, so the four it can
validate go through its config object and the other three are appended to the serialised
document with an honest type of their own. Both halves are built from one table, so the
document cannot advertise a scheme that is turned off nor omit one that is on. A
ServiceProviderConfig listing four of the seven ways in would be the most misleading
document this service publishes, and it is the first thing a SCIM client reads.

**`/Me` is an alias now, and its 501 is still reachable.** It answered 501 on every method
for one reason — "nothing here authenticates, so there is never a subject to alias" — and
that sentence stopped being true the moment these endpoints started requiring a
credential. Leaving it would have been the most easily-noticed lie on this surface: a
client reads the ServiceProviderConfig, authenticates, and is told there is nobody to be.
So `GET`, `PUT`, `PATCH` and `DELETE` resolve the caller to a directory entry and delegate
to the **same** User handlers `/Users/{id}` uses — no second read path and no second write
path. The 501 is still right in two cases and is kept for both: an **anonymous** caller
has no subject to alias, and `POST` would create a subject that by definition already
exists. A credential naming somebody with no entry — a `client_credentials` token, a
client certificate — gets `404` instead, which is the alias resolving to nothing rather
than the alias being unavailable.

**A caller that authenticates here is recorded, and three of the schemes do not do it.**
Basic, Digest and HOBA present a credential on every request, so accepting one reaches
`recordAuthentication()` — the same funnel every other family passes — and the caller
turns up on `/admin/users` under protocol `SCIM` with a directory entry of their own. A
bearer token, a session cookie and a client certificate do not, because each continues an
authentication that was already recorded where it was accepted: the token when it was
issued, the cookie when its session began, the certificate once per *connection* (which
is a decision `tls_server.js` made on purpose, and counting it per request here would
undo it from the other end).

**And in development mode it is still a turnstile rather than a lock**, which is the whole
design there. Anybody can get a token with either scope. Any password but one passes
Basic. Any username passes Digest. Anybody can register a HOBA key. Nothing here decides that a caller *should* be
allowed to delete an account — it decides that they said who they were first. Do not put
this port on a public address on the strength of it.

Every switch is a `config.js` row and therefore already on `/admin/scim` and
`POST /admin-api/config/set`: `scim.authDiscovery`, `scim.authRealm`, `scim.scopeRead`, `scim.scopeWrite`,
one flag per scheme, `scim.digestPassword`, `scim.digestNonceSeconds`,
`scim.digestMd5`, `scim.maxDigestNonces`, `scim.hobaMaxAgeSeconds`,
`scim.maxHobaChallenges` and `scim.maxHobaSeen`. **A credential that is presented and fails is refused whether or
not one was required** — otherwise a client testing its expired-token path would get a 200
because the endpoint would also have accepted nobody.

#### What it deliberately does not do

* **It authenticates, and it checks almost nothing.** This is the one surface in the
  service that refuses a caller who presents nothing, and the reason is the sentence that
  used to stand here instead: a SCIM endpoint is the most dangerous URL an identity
  provider exposes, because it creates and *deletes* accounts. All six schemes RFC 7644
  section 2 names are offered and a credential is required by default — see
  *Authentication* above. What is *not* checked is almost everything about it: anybody can
  get an access token with either scope from this service's own token endpoint with any
  grant, any username with any password but `invalid` passes Basic, any username passes
  Digest with the one shared password, and anybody can register a HOBA key for any name.
  It is a turnstile rather than a lock. What it buys is that a client's 401, 403,
  challenge-response and scope-handling paths can be exercised at all, none of which an
  open endpoint can produce.
* **`active: false` deactivates nobody.** It is stored on the entry as `scimActive` and
  read by nothing here: no bind is refused, no token withheld, no session ended. This is
  the same distinction this service draws about a group — carrying a fact is not acting on
  one — and it matters more here than anywhere else, because deprovisioning is the single
  most common thing a SCIM client is built to do and a mock that pretended to disable an
  account would let somebody ship a path that has never worked.
* **No ETag and no `changePassword`**, both advertised as unsupported rather than
  half-implemented. A version built over a `modifyTimestamp` with one-second resolution
  would be a concurrency control a client *trusts* and that is wrong, which is worse than
  none; and no password here is checked, so there is none to change. Responses go out
  through `res.end()` rather than `res.send()` for the first of those — Express computes a
  weak ETag for every `send()` body, and a document saying there is no version control on
  responses carrying a version is the drift that building the document out of the config
  object was meant to prevent.
* **A member that names nothing is accepted.** This directory does no referential
  integrity — deleting a user leaves their DN in every group that listed them — so
  refusing a dangling member here would make that state impossible to reproduce and would
  be this service enforcing in one direction what it explicitly does not enforce in the
  other. It is logged, so it is visible rather than silent, and `/admin/groups` reports it.

#### Things you can make fail

A permissive server is hard to write error handling against, so these exist on purpose —
the same device as the reserved password `invalid` everywhere else here:

| Do this | Get this |
|---|---|
| create a user with `userName` `invalid` | `400 invalidValue` |
| create a second user with a `userName` somebody already has | `409 uniqueness` |
| ask for an id that names nothing | `404` |
| send a filter this server cannot evaluate | `400 invalidFilter` — refused rather than answered with an empty list, because "no results" and "I could not read your filter" are different answers and a client can only act on the second |
| ask for anything with no credential | `401`, with one `WWW-Authenticate` header per offered scheme — RFC 7644 section 2 makes that header a *SHALL*. The three discovery endpoints are exempt unless `scim.authDiscovery` is on |
| use an access token with the wrong scope for the operation | `403` with `WWW-Authenticate: Bearer error="insufficient_scope", scope="scim:write"`. Neither scope implies the other |
| present a token this service did not issue, or one that was revoked | `401`. These endpoints verify the signature, unlike the OID4VCI credential endpoints which accept a foreign token: a scope on a token nobody verified is a permission its holder wrote for themselves |
| Basic with the password `invalid` | `401` — the same reserved value every other family here refuses |
| Digest with a wrong password, a stale nonce, or a repeated `nc` | `401` three ways. The password really is checked here; a stale nonce carries `stale=true`, which a conforming client retries silently; a replayed nonce count does **not**, because it was a valid credential and has been seen before |
| a HOBA signature that does not verify, or a reused (kid, challenge, nonce) | `401`. The signature is really verified, and the challenge may be *reused* until its max-age — so what counts as a replay is the triple |
| `GET /Me` with no credential, or any `POST /Me` | `501` — the alias is unavailable rather than the resource missing. A credential naming somebody with no entry here gets `404` instead |
| POST to `.search` without the SearchRequest schema URN | `400 invalidSyntax` |

#### Why there is a dependency, and one defect it is routed around

`scimmy` is the second npm dependency this service has taken on for a protocol, and the
reasoning is the same one that refused `swagger-ui-dist` and came out the other way: 735 KB
unpacked, **no runtime dependencies**, MIT, and it brings the three things that are
genuinely hard about SCIM and boring to get right — the RFC 7643 schema definitions with
their attribute characteristics and the coercion that enforces them, the section 3.4.2.2
filter grammar, and the section 3.5.2 PATCH path grammar. That last one is where every
hand-rolled SCIM server is subtly wrong: `emails[type eq "work"].value` is a *path*, and
treating it as a property name is the defect that makes a provisioning client's updates
land somewhere else. Writing those by hand would have been most of two thousand lines for
a mock and would have been wrong in exactly the places a client is trying to test.

Two things it does *not* do are worth knowing, because both look like they are handled:

**`Resource#read()` does not apply the filter it parsed.** It parses it, hands the
resource instance to the egress handler, and wraps whatever comes back. A handler that
ignores `.filter` returns everybody for every query — which looks like a working server
right up until somebody filters. The sort and the pagination *are* applied, by
`ListResponse`.

**`Filter#match()` throws on a nested attribute the resource does not have.** It handles
one by diving in — `new Filter([expressions]).match([actual])` — without checking that
`actual` is there, so the recursive call reaches `Object.entries(undefined)`. A filter
naming any sub-attribute (`emails.value co "@example.com"`, `name.familyName sw "Sm"`)
blows up on the first person who has no email, which in a directory is the ordinary case
and not an edge one; the exception surfaces as `400 invalidValue: Cannot convert undefined
or null to object`, which points at nothing. `toScimUser()` routes around it by **padding**
every multi-valued and complex member so the value is always at least an empty array or
object, and `prune()` takes the padding back off before the resource goes on the wire. The
two steps are separate on purpose — the padding is for the matcher and the pruning is for
the wire — and it is the same shape of workaround `toSearchEntry()` uses for ldapjs's
`SearchResponse.send()`, documented in both places because it is two lines that look like
a stylistic choice.

#### The console page

`/admin/scim` reports two different kinds of thing. The **counters**, from
`admin_stats.js`: which operation was performed how many times, on which resource type,
and what was refused with which `scimType` — with every operation and resource type drawn
*including the ones at zero*, because "does this server do PATCH" is the question somebody
arrives with and a table listing only what has happened answers it by omission. And the
**surface**, read from `scim.js` through a reader slot: the endpoints, what SCIM here
deliberately does not do, and the reachable negatives, written once in the module that
implements them rather than described a second time on a page that would eventually stop
being true.

**The bulk count deliberately does not tally with the rest**, and the page says so: one
`POST /scim/v2/Bulk` carrying five creates is one `bulk` row *and* five `create` rows,
because each of the five really is performed. A reader adding the column up would
otherwise conclude the counting is broken.

**Its one control is the eighteen `scim.*` settings, and there is still no POST beside
`GET /admin-api/scim`.** Everything about SCIM that can be changed is a `config.js` row,
and since 2026-08-27 this page is where those rows are DRAWN rather than described with a
link to `/admin/config`. The form posts to that endpoint, so `POST /admin-api/config/set`
is already the operation for it and a POST here would be a second door onto one function.
The parity rule is holding rather than being bent — see `mgmt-api/CLAUDE.md`.

One thing those settings do that is worth copying: `applyCapabilities()` is called both at
require time *and* at the top of the ServiceProviderConfig handler. Without the second
call, `scim.maxResults` would be enforced live — `queryParams()` reads it per request,
which is the rule for a runtime setting — while the published document went on advertising
the number the process started with. That is a captured `const` in disguise, and the exact
silent disagreement `config.js`'s header warns about.

### SPIFFE — three server-side surfaces, two of them authenticated differently

This service is a **SPIFFE issuing authority** for one trust domain **per trust
realm** (`spiffe.trustDomain`, `example.org` by default for the process, and
`<realm>.example.org` for every realm created under it). SPIFFE's server side is
three separate things, and they are worth separating because they have almost
nothing in common with each other:

| | |
|---|---|
| **The bundle endpoint** | plain HTTPS. One GET returning a JWK Set. This is the whole of the federation protocol's server half |
| **The Workload API** | gRPC, on a Unix socket and on TCP. What a *workload* talks to, to be given an identity |
| **The SPIRE Server API** | gRPC. What an *operator* and an *agent* talk to: registration entries, attestation, bundles, minting |

`GET /spiffe` describes all three and reports whether each socket actually bound
— which nothing else can do, because `/admin/sts-metadata` is built by walking
the Express router and a gRPC listener registers no route.

**A REALM GETS SOCKETS OF ITS OWN (2026-09-12), AND THE DISCRIMINATOR IS THE
ADDRESS.** Every other family here is told which realm it is in by a segment at
the front of the path; gRPC's path is the METHOD name, fixed by the Workload API
specification, so there is nowhere in the protocol to put one. A realm is
created with `spiffe.enabled` **off**; turning it on builds that realm's
authorities and binds a Workload API and a SPIRE Server API of its own, on the
address `spiffe.grpcHost` names for that realm and on the same ports. That is
also what a real deployment looks like — one SPIRE server is one trust domain —
and it is why `docker-compose.yml` gives the container four addresses rather
than one. Join tokens are per realm for the same reason: a join token is a
credential for joining a trust domain.

#### The two specifications say opposite things about authentication, and that is why the two surfaces differ

This looks like an inconsistency in the service and it is not. It is two
documents making two different demands, and getting either of them the other way
round breaks a real client.

**The Workload API must not authenticate anybody, and this is the specification
speaking.** The SPIFFE Workload Endpoint specification says the endpoint "MUST
NOT require any direct authentication of its clients", and that "Transport Layer
Security MUST NOT be required". The reason is bootstrapping: a workload has no
secret and no root of trust until this very call gives it one, so there is
nothing it could present. A mock that demanded a credential here would refuse
every conforming client, which is why the mutual TLS the
other surface requires deliberately does not reach it.

**The SPIRE Server API is mutual TLS with an X509-SVID, and this service does
the same.** A real `spire-server` binds a TCP port whose callers present an SVID
from the trust domain, takes the caller's SPIFFE ID off the certificate, and
authorizes every method against *what that caller is*. Its private Unix socket
is trusted outright — that is how the `spire-server` CLI works. Here: the TCP
port is TLS on this trust domain's own server SVID
(`spiffe://<trust domain>/spire/server`), the client certificate is verified
against the trust bundle and its own validity window, the SPIFFE ID comes from
the **URI subjectAltName** and never from the subject, and the method is checked
against SPIRE's own table. **It is not a setting and cannot be turned off**:
`spiffe.authRequired` was removed on 2026-09-06 with the other three gate
settings, and the socket is bound as mutual TLS on every start.

The bootstrapping case is handled the way SPIRE handles it: the port **asks for**
a client certificate and does not **require** one, because `AttestAgent` is open
to a caller that has no SVID yet. Fetch the bundle from the bundle endpoint,
verify this server against it, attest, and come back with what you were issued.

#### Nothing here attests a workload or a node, which is now a narrower sentence

In a real deployment the agent inspects the peer of its Unix socket — `SO_PEERCRED`
giving pid, uid and gid, and from the pid the executable path, its sha256, the
container, the Kubernetes pod — turns that into **selectors**, and hands the
workload only the identities whose registration entries those selectors match.
That is workload attestation.

**Node has no portable way to read peer credentials.** `net.Socket` exposes no
such call, `/proc/net/unix` does not record the peer, and the only routes to it
are native addons. So a Workload API caller here is identified by exactly three
things — the **transport** it arrived on, the **endpoint** it reached, and its
**peer address** — and by nothing else. Any caller that can reach the socket
still gets an identity: the socket's filesystem permissions are the only thing
between a process and an SVID, which is the same statement as "every LDAP bind
succeeds" one directory over, and it matters more here than anywhere else in
this repository because what comes out is a credential another service will
believe.

Four things follow, and each is deliberate:

* **Selector matching now decides which entries answer.**
  `spiffe_registry.selectorsMatch()` computes exactly what SPIRE would — the
  entry's selectors must be a **subset** of the workload's, not equal to them and
  not merely intersecting — and the Workload API uses it, which it did not
  before. `spiffe.attestWorkloads` off restores the old answer: every entry to
  every caller.
* **The selectors are spelt `transport:`, `endpoint:` and `peer:`**, and never
  `unix:` or `k8s:`. Writing `unix:uid:1000` for a uid that nothing read would be
  inventing an attested fact — the same offence as minting a credential format
  nobody specified. A caller may also **assert** its own selectors, in an
  `x-sts-workload-selector` metadata header, with
  `spiffe.acceptAssertedSelectors` on: those are passed through verbatim because
  they are the caller's claim rather than this service's invention, **nothing
  verifies them**, and the setting is off by default. It exists because selector
  matching is the interesting behaviour of a Workload API and there is otherwise
  no way to run a client's "these matched and those did not" path here at all.
* **`spiffe.autoCreateEntries` off is still the interesting setting.** With it
  off, a caller matching no entry is answered with an **empty SVID list**, which
  is exactly what a real agent does for an unregistered workload and is the only
  way to exercise a client's "I have no identity" path. That path is one most
  client libraries have and almost nobody runs. With it on, the invented entry
  carries the caller's *stable* selectors — transport and endpoint, never the
  peer, whose port is ephemeral — so the next caller of the same shape matches it
  instead of inventing another.
* **Node attestation is taken on trust.** Whatever attestor an agent names and
  whatever payload it sends are written down as claimed, which is why every agent
  entry carries a selector valued `unverified:true`: an agent's selectors here
  are claims, not attested facts. The one exception is a **join token**, which
  this server minted and therefore checks — see the refusals below.

#### Who may call the SPIRE Server API

A caller is classified as one or more of five entities, and the check asks
whether it is *any* of the ones a method allows — the `spire-server` CLI on this
host is `local`, and an agent that also holds an entry marked `admin` is both:

| Entity | What it means |
|---|---|
| `local` | the call arrived on the Unix socket, which is trusted outright (`spiffe.trustLocalSocket`) |
| `agent` | an X509-SVID whose SPIFFE ID is an agent id, naming an agent this server has attested and has not banned |
| `admin` | the SPIFFE ID is in `spiffe.adminIds` — SPIRE's own `admin_ids`, which needs no entry — or a registration entry for it is marked `admin` |
| `downstream` | a registration entry for it is marked `downstream`: a nested SPIRE server |
| anonymous | nothing was presented, or what was did not verify |

The per-method table is **SPIRE's own `policy_data.json`, row for row**, and it
is copied rather than reasoned out: a table derived from what each method
"obviously" needs disagrees with SPIRE in two or three places, and the client
author who meets the disagreement has no way to tell which end is wrong. Where a
row looks surprising — `Debug.GetInfo` is **local-only**, so even an admin SVID
over TCP is refused it — that is SPIRE's answer and the surprise is the point.
`GET /spiffe` and `/admin/spiffe` publish all forty-two rows.

Two consequences worth knowing:

* **The `admin` and `downstream` flags on an entry are now read.** They used to
  be recorded, reported, and consulted by nothing. Nothing caches them, so an
  `ldapmodify` of `spiffeAdmin` under `ou=spiffe` — or the form on
  `/admin/spiffe/entries` — changes what that identity may do on the next call.
* **`RenewAgent` stopped being unimplemented.** Its refusal used to say "nothing
  here authenticates the caller, so there is no way to know which agent to
  renew". Something does now, so it renews the agent **on the connection** and
  never one named in the request. It answered `Unimplemented` with that same
  sentence while the API could be left unauthenticated, which it no longer can.

#### An accepted SPIFFE credential is an identity, and it gets one directory entry

A credential presented here and accepted reaches
`admin_stats.recordAuthentication()` — the single funnel all sixteen protocol
families pass through — so its holder appears on `/admin/users` and the directory
seeds an entry for it. Three acceptances do that:

| What was presented | Recorded as | Verified? |
|---|---|---|
| an X509-SVID over mutual TLS at the SPIRE Server API | `X509-SVID (mTLS)`, **once per connection** — the credential was accepted at the handshake, so six RPCs on one connection are one authentication, which is the decision `tls_server.js` already made about its own listeners | signature against the trust bundle, validity window, trust-domain match |
| an agent attesting | `agent attestation (join token)` or `agent attestation (<type>, unverified)` | the join token, yes; any other payload, no — and the row says so |
| a JWT-SVID at `ValidateJWTSVID` | `JWT-SVID (validated)`, once per call, because each is a fresh presentation of a bearer credential | signature, `exp`, audience, trust domain |

Being **issued** an SVID is not one of them: receiving a credential is not
presenting one, so the Workload API's own callers do not appear as
authentications — they appear on `/admin/users` with *never* in that column,
counted under "seen only as a subject", because the SVID itself is an artifact.
**It does get them a directory entry, which is a different statement again and
the next section is about it.**

The entry is the fourth shape this directory files (see *An LDAP object for
every user who authenticates*): `uid=spiffe-<12 hex>,ou=users`, named by a digest
because a SPIFFE ID is neither a name nor a DN, with the identifier whole on the
entry as a multi-valued `spiffeSubject` and `spiffeTrustDomain` / `spiffePath`
beside it. **The entry is found by `spiffeSubject` and never by rebuilding the
digest**, which is what makes the same identity arriving all three ways one
entry rather than three. It deliberately does *not* fold onto a person of a
similar name: the last segment of a SPIFFE path is exactly the kind of short
common word (`db`, `web`, `api`) that collides with a username, and a workload
called `db` is not the DBA.

#### And every certificate this trust domain issues gets one too

That is the fourth way onto the same entry, and it is deliberately **not** a
fourth acceptance. A trust domain whose whole output is certificates ought to be
able to answer "which identities hold one, what is the current one, and can this
one still get another" from an `ldapsearch` — and until now it could not, because
the directory only heard about an identity that had *presented* something.

So an X509-SVID mint reaches the directory as well. `stats.recordSvid('X.509', …)`
is the funnel — the five mint sites already called it, so a sixth that forgets is
a mint with no artifact row on `/admin/metrics` either — and what it carries is
the certificate read back off itself with node's own parser at the moment
`spiffe_ca.js` issues it.

**It writes the same six `x509*` attributes a verified TLS client certificate
writes**, in the same strings:

| Attribute | On a SPIFFE identity's entry |
|---|---|
| `x509subject` | the SVID's subject, RFC 4514 — `O=SPIRE,C=US` by default, which is `spiffe.svidSubject` and is the same for every SVID in the domain |
| `x509issuer` | this trust domain's X.509 authority |
| `x509serialNumber` | the **current** SVID's serial |
| `x509notBefore` / `x509notAfter` | its validity window |
| `x509fingerprint256` | its SHA-256 fingerprint |
| `x509svidsIssued` | how many have been minted for this identity |
| `x509firstIssued` / `x509lastIssued` | when the first and the most recent were |

Three things about that are worth knowing before reading the code:

* **A rotation lands on the same object and nothing had to be written to make it
  so.** The entry is found by `spiffeSubject`, which keys on the SPIFFE ID and on
  nothing about the certificate, so the fiftieth SVID for `spiffe://…/sa/db`
  updates the entry the first one created.
* **The six are ASSIGNED here where the TLS path APPENDS them**, and that is the
  one rule that differs. A renewed client certificate is rare and seeing both
  serials is the point; an SVID is minted afresh at half its lifetime for as long
  as the workload runs, so appending would add six values an hour for ever. The
  three counters are what is left of the history, and the individual serials are
  all on `/admin/metrics`.
* **The identity is the SPIFFE ID and not the subject DN.** Filing an SVID the
  way a client certificate is filed — by its subject — would fold every workload
  in the trust domain onto one entry called `O=SPIRE`, because that is the subject
  they all share. The certificate is a *fact about* the identity here, not the
  identity.

#### `spiffeCredentialStatus` is not a revocation

**SPIFFE has no revocation.** There is no CRL, no OCSP and no serial list here;
the answer is a short lifetime and rotation, the `crl` field in the Workload API's
responses is empty because empty is the *conforming* value, and an SVID already in
a workload's hands verifies against the bundle until it expires. Nothing reads
this attribute back and no certificate is ever refused because of it.

What it records is the three things in the registry that end an identity's ability
to obtain a **new** credential here, on the entry of the identity they happened to:

| What happened | Status written |
|---|---|
| its **last** registration entry was deleted — the qualifier is checked, because several entries may name one SPIFFE ID and deleting one of them ends nothing | `revoked`, with the entry id in the reason |
| its **agent was banned**, which is the one refusal the registry makes: `AttestAgent` and `RenewAgent` both refuse it | `revoked` |
| its **agent was deleted**, so `RenewAgent` refuses it until it attests again | `revoked` |
| a registration entry naming it was created, its agent was unbanned, its agent attested, or an SVID was minted for it anyway | `active` |

`spiffeCredentialStatusReason` is a sentence rather than a code, because it is the
only thing that explains a status a reader did not expect. `spiffeRevokedAt` is
when it was **last** revoked and is never cleared — the history the current-state
flag deliberately does not keep, which is `mfaLastAuthTime`'s rule met again.

**The entry is never removed.** An identity this trust domain used to issue
certificates to is exactly what somebody points an LDAP client at a SPIFFE mock to
find, and deleting the object would answer "was there ever a workload called `db`?"
with silence.

#### What it does refuse, which is a short list and not an empty one

A mock that said yes to everything would be useless to the only people who call
some of these methods:

* **A Workload API call with no `workload.spiffe.io: true` metadata header.** The
  Workload Endpoint specification requires it and requires a server to refuse
  without it. It is not a security check — anybody can send a header — it exists
  so a caller cannot reach the endpoint *by accident*. It is enforced here
  because **a client that omits it has a bug and this is the only thing that will
  ever tell them**: every real implementation will refuse them, and a mock that
  accepted it would let somebody ship code that works against this and nothing
  else. `spiffe.requireSecurityHeader` turns it off.
* **`FetchJWTSVID` and `MintJWTSVID` with no audience.** A JWT-SVID is a bearer
  credential; the audience is what stops one issued for service A being replayed
  against service B, which is why the specification puts it in the request rather
  than in configuration.
* **`ValidateJWTSVID` on anything that does not really verify** — signature
  against the trust domain's JWT authorities, `exp` with no leeway, the audience,
  and that the `sub` belongs to the trust domain whose key verified it. The point
  of the call is to be told no, so this is the one method in the family that
  behaves like a real one. It is the same exception `/oauth2/userinfo` is among
  the token-reading endpoints.
* **A registration entry** whose SPIFFE ID is invalid, belongs to another trust
  domain, or sits under the reserved `/spire` path.
* **`AttestAgent` for a banned agent**, and a
  **join token** this server did not mint, one that has expired, one presented
  twice, and one minted for a named agent and presented by another. A ban that
  did not refuse would make the button on `/admin/spiffe/agents` a lie; and a
  join token is the one attestation payload here that this service *issued* and
  can therefore verify, so accepting one it never minted would be accepting a
  forgery of its own credential — a different thing from being permissive about
  a payload somebody else's attestor would have checked.
* **Every method the caller's entity is not allowed**, with `UNAUTHENTICATED`
  when nothing was presented and `PERMISSION_DENIED` when something was and it
  was not enough. Those are different instructions to a client — "authenticate"
  and "you may not" — and SPIRE distinguishes them; collapsing them sends a
  client that needs a credential looking for a permission it will never get.
* **An X509-SVID** that no authority in this trust domain or a federated one
  signed, one outside its validity window (`spiffe.clockSkew`), one with no URI
  subjectAltName, one with several — an SVID has exactly one, and choosing
  between two would be deciding which identity you have — and one whose SPIFFE
  ID names a different trust domain from the authority that signed it, which is
  precisely the cross-domain confusion a bundle exists to prevent.
* **A federated bundle whose JWKs have no `use` member.** A consumer *MUST
  IGNORE* a JWK whose `use` is missing or unknown — so a bundle full of them is
  stored happily and then verifies nothing, with no error anywhere pointing back
  at the bundle. Refusing it is the only way that failure ever gets diagnosed.

#### The SPIFFE ID grammar is stricter than a URL parser

`spiffe_id.js` checks the **raw text** and never uses `new URL()`, and that is
not fastidiousness. Four things a URL parser gets wrong here, each of which
produces an identifier that looks right in a log:

* **A trust domain is lower-case.** `spiffe://Example.org/x` is not a valid
  SPIFFE ID, and it is not another spelling of `spiffe://example.org/x` either —
  they are different identifiers. `new URL()` lower-cases the host for you, which
  *hides* the defect: the client that sent the wrong form gets an SVID naming the
  right one and never learns.
* **The path is not a URL path.** No percent-encoding, no empty segment (so no
  trailing slash and no `//`), no `.` or `..`. A URL parser accepts all of those
  and normalises three of them away.
* **No port, no userinfo, no query, no fragment.** Each is a way of writing an
  identifier that a naive `startsWith()` treats as belonging to a trust domain it
  does not — which is an authorization bug in anything that federates. Membership
  here is a comparison of the *parsed* trust domain, never a prefix test.
* **`/spire` is reserved** for the server and the agents it attests, so a
  registration entry there is refused: it would be an identifier this service
  also mints on its own account.

#### The authority comes from `/admin/pki` (2026-09-11)

**This section was headed *One process, two PKIs* and said there were two
authorities, generated per start, both in memory.** The first half of its
argument is unchanged and still load-bearing: the SPIFFE authority is **not**
the certificate that 8443, 9443, LDAPS 636 and (under `global.https`) the main
port share. That one is a leaf with `CA:FALSE` and `extKeyUsage serverAuth`; it
cannot sign anything, and a trust domain's CA and a host's TLS identity are two
unrelated trust decisions.

**What changed is that they now share an ANCHOR rather than being two trees.**
The SPIFFE authority is this realm's **SPIFFE Issuing CA** under the service
Root — a *sibling* of the TLS one, with its own key and its own Intermediate —
so narrowing trust to SPIFFE alone is still sayable, by pinning that Issuing CA
instead of the Root. It is the one Issuing CA in the hierarchy with `pathLen: 1`
rather than `0`, because `NewDownstreamX509CA` asks it for a CA and not a leaf,
and the realm Intermediate above it is widened to `2` to match.

**The bundle publishes the Root**, which is what SPIRE publishes with an
UpstreamAuthority plugin configured, and an X509-SVID carries its Issuing CA and
the realm's Intermediate in its own chain. The authority is per realm and the
anchor is not — which is what keeps that coherent with SPIFFE's four shared
sockets, since every realm's bundle is then the same document.

A realm with **no** certificate authority falls back to the self-signed
authority this service always had, generated per start and held in memory, and
says so on `/admin/spiffe` and `GET /spiffe`. `pki.autoBuild: false` reaches
that state deliberately.

The X.509 half is **EC P-256 by default**, which is what SPIRE issues and what
the X509-SVID specification recommends — `spiffe.x509KeyType` for the key in
each SVID, and a key-algorithm preference on the `spiffe` use case for the
authority's own, honoured whenever an operator has not chosen one for their
certificate authority. That is why `x509.js`, `key_material.js`,
`jose_jwe.js` and `crypto_bytes.js` are vendored here from the OAuth2/OIDC
Debugger — byte-identical, the way `bbs2023.js` already is: `node-forge`, which
`helpers.js` and `tls_server.js` use, **cannot sign with an EC key at all**. What
comes with those files is the parent project's `tests/pki_x509.js`, which drives
~240 certificates — every key algorithm against every signature algorithm, every
extension, a four-deep chain — and checks each one with **OpenSSL** rather than by
reading back what the same code just wrote. Four real defects were found that
way, and all four produced certificates that parsed perfectly and were refused
elsewhere with a message about a signature.

**Rotation is two different acts now.** Under the Root, rotating re-issues the
SPIFFE Issuing CA and leaves the anchor alone — the bundle does not change,
nothing has to be re-fetched, and SVIDs minted under the old authority go on
verifying, because their chain still reaches the same Root.

On the **self-signed** fallback it is what it always was: **rotation prepends
and never replaces.** A new authority becomes the one everything is signed with;
the old one stays published in the bundle, because an SVID minted a minute ago
has to go on verifying. Dropping it is the difference between a rotation and an
outage. Four are retained, and past that the oldest is dropped — which does
invalidate whatever it signed, and the page says so.

#### The registry is the directory

Registration entries live under `ou=entries,ou=spiffe` and attested agents under
`ou=agents,ou=spiffe`, in the embedded LDAP directory, exactly as the application
registry lives under `ou=applications`. **Nothing caches them**, so an
`ldapmodify` of `spiffeX509SvidTtl` changes the lifetime of the *next* SVID the
Workload API hands out. Three doors, one store: `ldapmodify`, the forms on
`/admin/spiffe/entries`, and the SPIRE Server API's `BatchCreateEntry` /
`BatchUpdateEntry` / `BatchDeleteEntry` — all of which call the same functions.

Two containers rather than one, because they hold different *kinds* of thing: an
entry is **configuration** deciding what will be issued, and an agent is a
**record** of something that happened. That is why what may be changed is
declared rather than derived — the SPIFFE ID, the parent, the selectors, the
lifetimes and the flags are editable, and the revision number and the SVID
counter are not. A form that could rewrite a counter would make the page lie
about this service's own behaviour, indistinguishably from the recording being
broken. `ldapmodify` still reaches everything: refusing it *there* is the
difference between offering an operation and merely not preventing it.

`GET /admin/ldap/spiffe` publishes the whole schema, because this directory is
schemaless and roughly thirty of these attribute names are this service's own
inventions — no registered LDAP schema has a SPIFFE ID or a selector on it.

#### Three entries are seeded, and the streams stay open

A fresh start seeds three registration entries — `/workload`,
`/ns/default/sa/web` (with DNS names and a `hint`) and `/ns/default/sa/db` (with
a different hint) — for the same reason the directory seeds three people: a
Workload API that answers an empty list teaches a client author nothing, and the
first thing they will do is assume they have misconfigured something. The two
hints exist so that "more than one SVID came back" is a path a client can
actually be driven down. Delete them and they stay deleted until a restart.

`FetchX509SVID` and the two bundle streams are **held open** and re-sent at half
the SVID lifetime. A Workload API that writes once and ends the stream looks
completely correct on the first fetch and puts `go-spiffe` into a reconnect loop
— and a client's rotation handling is the part most worth exercising, which
otherwise nobody would see without waiting an hour.

#### A foreign bundle is pushed in and never fetched

The federation specification puts a bundle endpoint URL in the relationship and a
real implementation polls it. This one **records the URL and refuses to follow
it** — `RefreshBundle` on the SPIRE Server API says so in terms, naming the URL
it is not fetching. Fetching a URL that somebody registered, in order to obtain a
key that will then verify credentials, is a server-side request forgery with a
specification citation attached; on a service that attests nobody — and where
anybody can obtain an SVID from the local socket and become an administrator of
this API with it — it is a blind HTTP client anybody can point anywhere.
It is the same refusal this service gives WS-Federation's `wreqptr` and a
client's `jwks_uri`, and holding the position in two files and not in a third
would be no position at all.

Push one in instead: `POST /admin-api/spiffe/federation-set`, the form on
`/admin/spiffe`, or `BatchSetFederatedBundle`.

#### The six methods that are not implemented, each with a reason

A table saying 42 of 42 would be the most misleading thing in this repository, so
`GET /spiffe` publishes every method with an `implemented` flag and the reason
where it is false.

**There were seven, and `Agent.RenewAgent` is the one that left.** Its reason was
that "a real server knows which agent is calling from the SVID on the mTLS
connection. Nothing here authenticates the caller, so answering would mean
renewing whichever agent the *caller named* — a way for anybody to obtain any
agent's identity." Something authenticates the caller now, so it renews the agent
on the connection. It answered `Unimplemented`, with that same sentence,
while that API could be left unauthenticated — which it no longer can be.

| Method | Why not |
|---|---|
| `Bundle.AppendBundle`, `Bundle.PublishJWTAuthority` | They would add an authority to *this* trust domain's bundle — a key permitted to sign identities in it — that this server holds no private key for. Every workload would trust an authority that can issue nothing. Rotate instead |
| `TrustDomain.RefreshBundle` | It would fetch a URL somebody registered. See above |
| `FetchWITSVID`, `FetchWITBundles`, `SVID.MintWITSVID`, `SVID.BatchNewWITSVID`, `Bundle.PublishWITAuthority` | WIT — the Workload Identity Token — is in the current `workloadapi.proto` and `wit-svid` is a `use` the bundle specification names, but the **token's own format is not settled** in a document this service could implement against. Minting something JWS-shaped and calling it a WIT-SVID would be inventing a credential format: code written against the invention would work here and interoperate with nothing. The same reasoning that makes WS-Federation's `wauth` a refusal rather than a fabricated second factor |

#### Why `@grpc/grpc-js` is a dependency in a package that is deliberately short

The argument this repository makes against `swagger-ui-dist` is a real argument
and it was made again here, in the other direction. This service already
hand-rolls ASN.1, NDR and a Kerberos PAC, and a hand-rolled protobuf codec with a
gRPC server over node's built-in `http2` was a genuine option — around 900 lines
and no dependency.

It was not taken, and the reason is what the service is *for*. A mock exists to
be talked to by **real clients**: `go-spiffe`, `spiffe-helper`, a SPIRE agent,
the `spire-server` CLI. An interoperability bug in a hand-rolled HTTP/2 framer
does not announce itself as a framing bug — it appears as a client that hangs, or
reports a truncated message, and the client author debugging it has no way to
tell whether the fault is theirs or ours. That is precisely the failure this
service exists to spare somebody. The explorer script traded a familiar look for
11.7 MB; this trades ~30 packages for the wire being right.

Two things that cost real time and are recorded so they cost it once:

* **`keepCase: true` does not reach the well-known types.** It tells the loader
  not to camel-case the fields of the files it *parses*, which is why the
  handlers say `spiffe_id` and `x509_svid_key`. `google/protobuf/struct.proto` is
  not one of those files — protobufjs carries the well-known types as pre-built
  descriptors whose names are already camelCase. So a `Struct` built with
  `string_value` serialises to **nothing**: no throw, no warning, a response with
  the right field names and every value empty. It has to be `stringValue`.
* **protobufjs wraps exactly one well-known type, `Any`.** A plain JavaScript
  object assigned to a `Struct` field is not converted for you; it becomes a
  Struct with no fields. `ValidateJWTSVID` answered 200 with the right
  `spiffe_id` and an empty `claims` until a real client asked for the claims.

### TLS and mutual TLS — the other side of a handshake

`tls_server.js` puts up **two HTTPS listeners of its own**, and their entire content
is what the *server* saw. Fetch `GET /tls/whoami` over either one and the reply
describes the very connection it is travelling on: the HTTPS request as it arrived
(method, path, every header, where from), what TLS negotiated underneath it (version,
cipher, SNI, ALPN, session reuse, the server certificate), and the client
certificate — presented or not, verified or not, with the whole chain the client
sent, leaf first. `GET /tls` describes the endpoint over plain HTTP, and both pages
take `?format=json`.

**The client truststore has a test control in development mode and gated doors in every
mode.** `POST /tls/trust` and `/tls/trust/clear` answer anybody in development; in product
mode both answer 403 naming the gated doors and `tls.trustAnchorsFile`, a PEM file read at
startup. **The gated doors are `/admin/tls/trust`** — a console page under Protocols listing
every anchor with its subject, issuer, serial, validity, SHA-256 fingerprint and SOURCE
(`file` or `runtime`), paged, with an add form and a Remove button per row, needing Admin
Write to change — **and `GET /admin-api/tls/trust` with `POST /admin-api/tls/trust/add` and
`/remove`**, behind that API's `admin:read` / `admin:write` token. Neither has a bulk clear,
a runtime anchor either adds is written to `ou=trustAnchors` in the default realm's directory
and so survives a restart wherever the directory is persisted (a removed `file` anchor still
comes back from the file), an add is refused whole if OpenSSL cannot read one block of it, and with
request workers both are answered by the process that holds the listeners. Every TLS
listener here — 8443, 9443, LDAPS and the main port — takes `tls.minVersion` (TLSv1.2 by
default) and `tls.ciphers` (node's list by default), and binds `global.host`.

**Why it exists, given that any client already reports its own handshake.** Because
that report is the side that already knows what it sent. What a client cannot see is
which chain the server built out of what arrived, which anchor it verified against,
what it read out of the leaf, or whether the certificate was accepted at all. Under
**TLS 1.3** it has not even been told: the client sends its Certificate and Finished
*last*, so its handshake is complete before the server has said anything, and the
verdict arrives afterwards — as a post-handshake alert, or as a bare hang-up. Node's
own TLS server does the latter. So a client that reports success on `secureConnect`
will cheerfully report a working mutual-TLS connection to a server that rejected the
certificate a millisecond later, and this endpoint is where that gets found out.

**Two listeners, because the question has two answers.**

| | |
|---|---|
| `8443` | `requestCert: true, rejectUnauthorized: false`. It always asks, accepts whatever arrives including nothing, and *reports* the verdict rather than enforcing it. Point a debugger here: a refusal at the TLS layer tells you almost nothing, and this listener can tell you which check failed and why |
| `9443` | `requestCert: true, rejectUnauthorized: true`. It refuses an unverified certificate during the handshake, the way a real server does — which is to say by closing the socket with no alert at all. Reaching it *is* the proof that the certificate verified |

That pair is what makes a caller's mutual-authentication verdicts reachable against a
real server rather than a fixture: `required` against 9443 once the issuing CA is
trusted here, `required-and-rejected` before it is (the case an operator hits most,
and the one a single connection cannot tell from the first), and `not-required`
against 8443, which is true — it asks and does not insist.

**The client truststore starts empty, and it has to.** The certificate authority
whose clients this verifies is generated in somebody's *browser*, minutes before the
connection, and exists nowhere else — so no configuration file could hold it and no
image could bake it in. `POST /tls/trust` takes one or more PEM certificates (raw, or
as the `certificates` field of a form or JSON body) and
`tls.Server.setSecureContext()` applies them; existing connections keep the truststore
they were made under, and the next handshake is judged against the new one.
`POST /tls/trust/clear` puts it back. Those two are the development test controls; the
same truststore is managed in every mode from `/admin/tls/trust` and
`/admin-api/tls/trust`, one anchor at a time, as the paragraph above describes.

Three details in there are load-bearing and each was measured rather than assumed:

* **`ca: []` means no anchors.** It is not the same as omitting `ca`, which selects
  node's bundled root store — the opposite of what is wanted, since a public root has
  no business verifying a client certificate from a private CA. The empty case is
  passed explicitly, so the starting state is "nothing verifies", which is correct and
  is what the page says.
* **The trust endpoint is on the PLAIN port**, not on 8443. That port is the one
  reachable before anything is trusted; an endpoint that could only be called by
  somebody already trusted would be a chicken-and-egg with a specification citation
  attached.
* **The server certificate is regenerated on every start**, like the signing key, and
  for the same reason — a certificate committed to a repository is a private key
  committed to a repository. Since 2026-09-11 it is **issued by this service's own Root
  CA** rather than self-signed, so one anchor covers 8443, 9443, LDAPS 636, the main
  port and every token this service signs. `GET /tls/server-certificate` hands out the
  PEM (`Cache-Control: no-store`, since a cached copy outlives the key it describes)
  so a caller can put it in its own truststore rather than switching verification off,
  which is the habit this whole workflow exists to break. **The chain and the Root come
  with it, and the leaf is first** — a truststore holding only the leaf builds no path
  now, and fails with `unable to get local issuer certificate` about a Root it was
  never given.
* **It is served on three sockets, not two.** The directory's LDAPS listener on 636
  presents this same certificate and key, read from this module rather than generated
  again — so one fetch is one anchor for 8443, 9443 *and* `ldaps://`. Two keypairs
  would have made an `ldapsearch` fail against a truststore built for the HTTPS ports
  with `unable to get local issuer certificate`, which names nothing. The private key
  crosses a module boundary to do it and does not cross a network one: it is generated
  per start, lives in memory, dies with the process, and nothing writes it to a
  response — `GET /tls/server-certificate` publishes certificates alone, never a key.
  **636 is re-keyed on its way into `listen()`** rather than at require time, because
  this module is required before the certificate authority exists: reading it once at
  the top left that one socket presenting the self-signed certificate this process had
  already replaced, while the other three presented the certified one.

**And a verified client certificate is not a login.** It means a chain was built from
what the client sent to an anchor somebody POSTed to this process, and no more: no
session is started, no token is issued, no revocation is checked, and no endpoint here
will let its holder do anything an anonymous caller cannot. The report says so in as
many words, because a mock that quietly turned a certificate into an identity would
teach a client something false about every server it will meet afterwards.

**It is, however, recorded, and that is a different claim.** `/admin/users` answers
"who has this service seen, in an interaction that succeeded", and a mutual-TLS client
whose certificate verified is exactly that — leaving it out made the console's answer
wrong by omission. So when a handshake completes with a certificate that verified, the
subject DN is filed through `stats.recordAuthentication()`, the same funnel every other
family here passes, under protocol `TLS`; and because that funnel already carries the
directory's observer, the embedded LDAP server seeds an entry for it. A record of what
happened, not a credential: nothing in this service consults either one to decide
anything, and the report and `GET /tls` both say so beside the sentence above rather
than leaving a reader to work out which of the two claims is being made.

Three details of that are decisions rather than mechanics. It is recorded **at the
handshake** (`secureConnection`) and not in the request handler, because the handshake
is where the credential was accepted — recording per request would report one
connection carrying six of them as six authentications, where the honest count is one
per handshake and a client that opens six connections did present its certificate six
times. It is recorded **only when `authorized` is true**, so the permissive listener
writes nothing down for a certificate that failed to verify or was never sent. And the
identity is the subject in **RFC 4514 form** — leaf first, no spaces after the commas,
values escaped — which is a *different string* from the display DN the report shows
next to it and than the one `openssl x509 -subject` prints. Both forms are on the
report, side by side and labelled, because the difference is the sort of thing that
otherwise gets discovered in an hour of comparing two strings that look the same.

**The directory entry is the one identity here that did not have to be invented**, and
it is worth reading `certificatePlan()` in `ldap_server.js` before changing where it
goes. A certificate subject is already a DN — X.509 and LDAP share the model — but it
usually names an object in somebody *else's* directory: `CN=alice,O=Example Corp,C=US`
is not under `dc=example,dc=com` and never was. So: a subject that already lies under
this directory's base DN (with its parent present) is created **at it, unchanged**;
anything else is named by the subject's `CN` — or its leaf RDN where there is none —
under `ou=users`, with every other RDN of the subject kept as an attribute and the
full subject, issuer, serial, validity and fingerprint written on as `x509*`
attributes. Those names are this service's own and not schema: there is no standard
attribute type for "the DN inside the certificate", and the standard one that exists
for the certificate itself, `userCertificate`, is binary and transferred as
`userCertificate;binary` — writing base64 into that name would put a value on the wire
no client could parse and would read as a bug in the directory. The CN is preferred
over the leaf RDN for a reason worth knowing: openssl puts `emailAddress` **last** in a
subject, so the leaf RDN of a typical client certificate is the address, and
`emailAddress=alice@example.com,ou=users` is not how a directory names a person. What
the reparenting costs is a collapse — two certificates whose CNs match, from two
different CAs, land on one entry — and it is made visible rather than hidden: both
subjects are listed there under `x509subject`, and the console still files them as two
identities because it keys on the whole DN. A renewed certificate for the same subject
does not make a second entry either; its serial, validity and fingerprint are appended
to the one that is there, so the entry shows the history.

One thing worth knowing about the log: a certificate refused by the strict listener
never reaches a handler, so without help it would be invisible from both ends — the
caller sees a closed socket and this service says nothing. Both listeners therefore
log `tlsClientError` with OpenSSL's own reason, and the strict one's message names the
truststore, the trust endpoint and the permissive port. It is the single most
confusing failure in mutual TLS and it is the one this service refuses to be silent
about.

### The issuer named by a DID

A credential may name its issuer by **DID** instead of by URL, and the two formats stand differently, which is the first thing to know before changing any of this. `ldp_vc` is DID-native: VC Data Model 2.0 and Data Integrity assume it. `dc+sd-jwt` is **not** — `draft-ietf-oauth-sd-jwt-vc` says in as many words that "a DID-based mechanism is not explicitly provided herein but still possible via profile/extension", and defines only `/.well-known/jwt-vc-issuer` and inline x509. So for SD-JWT VC this is an **extension and is labelled as one everywhere it appears**, and the DID identifies the **issuer only**: holder binding stays `cnf.jwk`, because a DID there would be nobody's convention and walt.id already behaves this way. (Unrelated trap: **RFC 9101 is JWT-Secured Authorization Request**, nothing to do with DIDs. It is already used here for the OID4VP request-by-reference flow; do not cite it for DID work.)

The mock issuer offers **two credential configurations whose credentials name the issuer by `did:web`** — `IdentityCredentialDid` (`dc+sd-jwt`) and `IdentityCredentialLdpVcDid` (`ldp_vc`) — beside their plain siblings, which keep the https identifier. That pairing is deliberate and is the reason it is not a server-wide switch: with a switch, a run exercises the DID route **or** the specification's own route but never both, and for `dc+sd-jwt` the route the spec actually defines is the one that must go on being tested. The two entries are **cloned from their siblings** in `vciMetadata()` rather than written out again, so a claim or proof type added to one cannot go missing from the other, and the parent project's `tests/vc_did.js` asserts they differ in nothing but scope, display name and the identifier advertised. The startup flags `OID4VCI_SD_JWT_ISSUER_DID` / `OID4VCI_LDP_VC_ISSUER_DID` still exist and switch the **plain** configurations over — what a deployment that had gone to DIDs throughout would look like — and stay off by default. `issuerDidFor(configId, req)` is the single place that decides, so the metadata and the credential cannot disagree about who issued it.

**Three documents make the DID discoverable rather than merely asserted**, and they answer different questions:

| Document | Member | Answers |
|---|---|---|
| `/.well-known/openid-credential-issuer` | `issuer_did`, and `issuer_identifier` per configuration | which DID this issuer answers to, and which identifier *this* configuration's credentials will carry. Both are **extensions** — OID4VCI registers neither |
| `/.well-known/jwt-vc-issuer` | `issuer_did` beside `jwks_uri` | the same DID, named from SD-JWT VC's own key-resolution document. Its `issuer` **stays the https identifier**: the spec has a verifier insert the well-known path into the credential's `iss` and require that this document's `issuer` equals what it started from, and a DID cannot be the subject of that rule — which is precisely why the DID route is an extension |
| `/.well-known/did-configuration.json` | DIF **Well Known DID Configuration** | why the DID should be believed to be the same entity as the origin. The only one of the three that is a real spec and is *checkable* |

That last one is the point of the exercise, and the reason is worth keeping: for `did:web` the other documents only look like an answer. Resolving `did:web:example.com` means fetching `example.com`, so reading a DID document off that origin to decide whether the DID belongs to it is **circular**. The Domain Linkage Credential is not — the DID signs, with its own key, a credential naming the origin, and a verifier resolves the DID independently, checks the signature against the keys it authorises to **assert**, and requires that `credentialSubject.origin` is the origin the document came from. A verifier must additionally insist the linkage is for **the DID asked about**: an origin that links its own DID has not vouched for anybody else's, and without that check "linked" would be a property of the file existing rather than of what it says. (The consumer side of this check lives in the parent project's wallet, not here — this service's job is to publish a document that survives it.)

The **JWT form** is served rather than the Linked Data Proof form (the spec allows either): this issuer signs RS256 JWTs everywhere else, so the same key and JWKS verify it, where the LD form would need JsonWebSignature2020 over URDNA2015 canonicalization for no additional teaching. Two details of that form are what a JWT library gets wrong **for** you, and both produce a document that looks perfectly right: the header **MUST NOT** carry `typ` (jsonwebtoken adds `typ: "JWT"` unless the header override sets it `undefined`), and the payload permits **no member beyond `iss`/`sub`/`nbf`/`exp`/`vc`** (it adds `iat` unless told `noTimestamp`). An LD-proof entry that arrives is reported as **unverifiable here, not invalid** — it is somebody else's conforming document.

### Asking for a subset of the claims

A Wallet can ask for **some** of the claims a credential can carry, and the place it asks is not where most people look first: OID4VCI 1.0 puts the optional `claims` member in the **`authorization_details`** entry of type `openid_credential` (section 5.1.1), not in the Credential Request — section 8.2 defines only `credential_identifier` / `credential_configuration_id`, `proofs` and `credential_response_encryption`, and the 1.1 editor's draft still does. So the selection is made when the issuance is **authorized**, travels inside the access token, and the Credential Endpoint reads it back off a token this service signed. A wallet cannot widen its own selection by editing anything, and no server-side state is needed to check it.

Each entry of `claims` is a **claims description object** (Appendix A.1) whose `path` is a **claims path pointer** (Appendix B) — an array, because a claim may be nested (`["address","locality"]`) and because a path may address array elements with integers or `null`. The paths are the ones the **metadata publishes** for that credential's format, which is why `vc_claims.advertisedClaims(format)` is now the single source for both: `vciMetadata()` publishes what it returns, and the authorization endpoint validates against the same list. The prefix is the format's own — nothing for `dc+sd-jwt`, whose claims sit at the top level of the payload, `credentialSubject` for `jwt_vc_json`, and for `ldp_vc` the flat context terms it is limited to.

Four things this refuses rather than ignores, all with `invalid_authorization_details`: a `claims` member that is not a non-empty array, a `path` that is not a non-empty array of strings/nulls/integers, a claim described **twice** (Appendix A.3 says a repeated description MUST abort the processing), and a path **this issuer does not advertise** for that configuration. The last is the only one that is this service's own decision, and it is the important one: a wallet whose selection was quietly dropped gets a credential carrying claims it did not ask for, or missing ones it did, with nothing anywhere saying why — and the whole value of publishing `claims` in the metadata is that a wallet can rely on it.

Two consequences worth knowing before changing this:

* **Absent is not empty.** No `claims` member means "whatever you issue" and every authorization made before this existed means exactly that, so `requestedClaimPaths()` returns `null` rather than `[]` and the full configured set goes out. An empty array is not expressible at all — A.1 requires a non-empty one — so a caller that could not tell the two apart would issue an empty credential to every wallet that authorized with a scope.
* **The Token Request accepts `authorization_details` too**, which is the only route the **pre-authorized code flow** has: it has no authorization request to have sent them in. Section 6.1.1 allows it in both flows. What the **offer** was for bounds it — a detail naming a configuration the Credential Offer did not is refused — and the refresh grant carries the granted details forward, because an access token that dropped them would make the section 14.5 refresh fail at the credential endpoint with "that identifier was not granted".

## RFC 7521 and RFC 7523: an assertion instead of a credential

Added 2026-09-10. **RFC 7521 is a framework and RFC 7523 is the only profile of
it anybody uses**, which is why they arrive together and why a reader looking
for "the RFC 7521 part" will find nothing else: 7521 defines two request
parameters, an error vocabulary and a list of checks, and 7523 says the
assertion is a JWT and names the claims. Neither is testable without the other.

**TWO USES OF ONE FORMAT, AND THEY ARE NOT THE SAME FEATURE.** Reading one and
concluding the other is covered is the mistake this section exists to prevent —
and it is exactly the mistake this service had made, because the metadata named
RFC 7523, client authentication was complete, and the grant did not exist.

| | Parameter | The `sub` is | What it replaces |
|---|---|---|---|
| **§2.2 client authentication** | `client_assertion` + `client_assertion_type` | the CLIENT, necessarily | a client secret |
| **§2.1 an authorization grant** | `grant_type=…:jwt-bearer` + `assertion` | a PERSON | an authorization code |

```bash
# Section 2.1. A trusted party signs a document saying "this is alice, issue a
# token for her", and this authorization server does.
curl -s -X POST http://localhost:8081/oauth2/token \
  -d grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer \
  -d "assertion=$ASSERTION" \
  -d scope='openid profile'
```

### What an assertion grant actually is, because it decides the refusal

There is **no browser, no password and no consent step anywhere in it**. So the
signature is the entire security of the grant, and the one thing this service
must not do is accept an assertion from anybody: "accept any signed assertion"
means anybody who can reach this port gets an access token as anybody.

That puts this feature in the same category as **federation** rather than in the
category everything else here is in — there is no permissive answer available.
So an assertion issuer must be CONFIGURED, on an application entry as
`oauthAssertionIssuer`, and `oauth2.jwtBearerRequireRegisteredIssuer` is ON by
default. Those two refusals are the only ones in this service that are.

**What is still permissive is everything around it.** The `sub` need not be
anybody this service has heard of — an assertion for a name nobody has ever
used mints that person exactly as typing the name at the sign-in screen does —
and the scope is not checked against anything. What is real is that somebody
holding a private key this service was told to trust signed the document.

### Every optional component, because "optional" is where implementations differ

| | |
|---|---|
| §3 claim 5, `nbf` | checked, against `oauth2.clientAssertionSkewS` |
| §3 claim 6, `iat` | checked, and it **bounds the lifetime** — `oauth2.jwtBearerMaxLifetimeS`, 300s, which RFC 7521 §5.2 invites and leaves to the server |
| §3 claim 7, `jti` | spent **once, ever**, against the used-assertion history — one history for client authentication and the grant, and for RFC 7522 too, persisted in every store with one, claimed atomically on postgres, and spent only when the token request issues tokens (`/admin/used-assertions`) — and **required** here. That is §3's own last paragraph read literally: it says a server MAY refuse a reused assertion, and one with no `jti` cannot be remembered — so accepting it means accepting a bearer credential this service has no way to spend |
| §3 claim 8, other claims | carried onto the issued access token. The profile's own twelve are stripped first: an `exp` copied off an assertion would be a token lifetime chosen by whoever signed it |
| §3 claim 10, **encryption** | a nested JWT, sixteen key management algorithms against six content encryption ones, to this service's own RSA or EC key or under the client secret |
| RFC 7521 §4.1, `scope` | **narrowed** against what the assertion carries and never widened. Where the assertion names none, the request decides |
| RFC 7521 §5.2 (5), `aud` | may be an array; any member may match. Both the token endpoint and the issuer are accepted, because RFC 7523 and OpenID Connect Core §9 name different ones |
| RFC 7521 §6.2, `client_id` | may be omitted where the assertion identifies the party |
| RFC 7521 §6.3, `cnf` | carried and **reported, never enforced** — this grant has no parameter in which a presenter could prove possession of the named key, so demanding one would refuse every conforming client |
| RFC 7521 §4.2 | an `error_description` on every refusal, which is most of `oauth-oidc/assertion_grant.js` |

**Every JWS algorithm this service verifies is accepted**, the eleven
post-quantum ones included; `assertion_signing_alg_values_supported` in the
metadata is that table. `alg: "none"` is refused **by name**, citing claim 9,
rather than being left to fall off the end of a list — it is the forgery every
JWT implementation has had at some point, and a caller sending one deserves to
be told which rule it broke.

### It is recorded as a delegation, because that is what it is

One party asked this service to issue a credential in **another party's name**,
so the act lands in the delegation register beside RFC 8693's two shapes and is
drawn on `/admin/delegation`. It is `delegation` rather than `impersonation`,
and the distinction is RFC 8693 §1.1's own: impersonation produces a token
indistinguishable from one the subject obtained themselves, and this one is not
— the issuer is on the assertion, the assertion's `jti` is in the register, and
a resource server can be told which trusted party asserted the subject. The
party is acting **openly**, which is what the word means.

## A certificate authority, at `/admin/pki`

The other half of the same change, and the reason it exists is one sentence: an
application can authenticate with a signed assertion instead of a shared secret,
and **a signing key nobody vouched for is a key an operator has to move by
hand**.

Protocols → PKI builds a **Root CA, an Intermediate CA and an Issuing CA** for
the trust realm it is reached in, and issues signing key pairs from the bottom
of it to applications.

```bash
# Without a browser. Both operations exist because every control on that page
# has one — the console decides nothing this API does not.
curl -s -X POST http://localhost:8081/admin-api/pki/build \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"keyAlg":"ec-p384","organisation":"Acme","country":"US"}'

curl -s -X POST http://localhost:8081/admin-api/pki/issue \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"identifier":"webapp1","days":90}'
```

**ALL THREE TIERS IN ONE ACT OR NONE.** A trust chain is only worth anything
whole: an Issuing CA with no Intermediate above it is a two-tier chain wearing a
three-tier name, and a half-built hierarchy is exactly the state in which
somebody issues a certificate that verifies here and nowhere else. A failure at
any tier stores nothing, and building again **replaces** — with everything
issued from the old hierarchy chaining to nothing the moment it does, said out
loud because there is no honest way to hide it.

**ONE ROOT FOR THE SERVICE, AN INTERMEDIATE PER REALM AND PER THE PROCESS, AND
AN ISSUING CA UNDER EACH PER USE CASE (2026-09-11).** Every key pair this
service generates is a leaf of it — the signing keys of every realm, and the
certificate the TLS listeners serve — so an operator installs ONE anchor and it
covers 8443, 9443, LDAPS 636, the main port and every token, assertion and
signed document this service issues. It is built at startup
(`pki.autoBuild`), and the key generation itself is untouched: the same keys, in
the same order, at the same moment, with a certificate added afterwards.

**THIS PARAGRAPH SAID THE OPPOSITE UNTIL THAT DATE.** It read: *IT IS PER TRUST
REALM. A realm is a logical identity service with its own signing key and its
own applications; a CA shared across realms would be one authority vouching for
several services, which is the one thing a realm boundary exists to prevent.*

That argument was about the ANCHOR, and **the realm boundary moved down a tier
when the Root was shared**: each realm has an Intermediate of its own, and a
path is checked against it. With one Root, *does this chain to our Root* is true
of every certificate this service has ever issued — so it stopped being a
boundary on the day it was shared, and a check that still relied on it would
admit every realm's clients to every other realm's token endpoint with every
signature verifying. A certificate issued in one realm still does not verify in
another.

**THE ELEVEN POST-QUANTUM KEYS PER REALM ARE LEAVES OF IT SINCE 2026-09-13**,
and this paragraph read *ONE THING IS DELIBERATELY NOT A LEAF OF IT* until then.
They are issued from the realm's own JOSE Issuing CA as they are made, and the
reason they had been left out is still honoured rather than waived: they are
generated and signed with by `common/pq_jose.js` — this service's own reading of
those constructions, independent of the vendored encoder on purpose — and only
their PUBLIC keys reach the certificate encoder, with the one layout difference
between the two readings written out and a signature from one checked under the
other. The JWKS is unchanged. An ML-DSA listener certificate is a leaf of the
TLS Issuing CA the same way.

**THE SPIFFE X.509 AUTHORITY WAS THE SECOND AND CAME UNDER THE ROOT ON
2026-09-11.** That sentence read *self-signed, because one process holds two
PKIs deliberately and because an Issuing CA here carries `pathLen: 0`*, and both
halves were answered rather than waived: the SPIFFE authority is a SIBLING of
the TLS one rather than the same certificate, so narrowing trust to SPIFFE alone
is still sayable by pinning that Issuing CA; and the `pathLen` was moved, the
`spiffe` use case carrying `1` and the realm Intermediate above it `2` — derived
from one table so they cannot drift — because `NewDownstreamX509CA` asks that
authority for a CA rather than a leaf.

So **one anchor now covers every X509-SVID as well**. The SPIFFE bundle
publishes the Root, which is what SPIRE publishes with an UpstreamAuthority
plugin configured, and an SVID carries its Issuing CA and its realm's
Intermediate in its own chain — so rotating the authority no longer changes the
bundle and nothing has to be re-fetched. The authority is PER REALM and the
anchor is not, which is what keeps that coherent with SPIFFE's four shared
sockets. A realm with no hierarchy falls back to the self-signed authority this
service always had and says so on `/admin/spiffe` and `GET /spiffe`.

**THE KEY PAIR GOES ONTO THE APPLICATION'S OWN ENTRY, AND THIS SERVICE KEEPS NO
SECOND COPY.** Seven attributes — `oauthAssertionPrivateKey` (**sealed at rest**
under the same key-encryption key as the hierarchy it was issued from, wherever
that key outlives the process, so a directory dump, an LDIF file, a database row
or a backup holds `$aesgcm$…`; the console and `/admin-api` open it for a caller
holding a credential, because the seal protects the store and not the page an
operator collects the key from. In development mode it is in the clear, where
the key-encryption key would not survive the restart the entry does — the
decision `oauthClientSecret` and `GET /krb5/principals` both make and for their
reason: a debugger whose credentials are unusable without reading the source is
worse than one that says what they are), `oauthAssertionCertificate`,
`oauthAssertionCertificateChain`, `oauthAssertionJwks` (carrying `x5c` and
`x5t#S256`), `oauthAssertionKid`, `oauthAssertionExpiresAt` and
`oauthAssertionKeySource` (`issued`, or where an uploaded certificate came
from). It is handed over once, at issuance, and forgotten. **Since 2026-09-13
the application's own page can replace the pair** — by issuing again, or by
uploading a certificate the application already holds, an external CA's with
its full chain up to a self-signed root — and regenerate its client secret; see
`docs/pki.md`. **`oauthJwks` is never overwritten**: a
client that registered its own keys and is later issued a pair has two ways to
sign, both of which somebody deliberately arranged.

**THE LEAF IS A SIGNING CERTIFICATE AND DELIBERATELY NOT A TLS ONE** —
`digitalSignature` and `nonRepudiation`, no extended key usage. What it signs is
a JWT; giving it `clientAuth` would make it usable for RFC 8705 as well, which
is a DIFFERENT credential with a different registration attribute, and one
certificate quietly doing both is how a deployment ends up unable to revoke
either.

**A KEY PAIR IS NOT A TRUST DECISION.** It lets an application SIGN, which is
all §2.2 needs. For §2.1 the `iss` it will use must also be declared. The page
draws both columns for that reason.

### Two things it does not do, and both are on the page

* **REVOCATION IS PUBLISHED AND NEVER CONSULTED**, which reversed half of this
  bullet on 2026-09-11. It read *nothing is ever revoked: this service
  publishes no CRL and answers no OCSP.* Every authority now signs an RFC 5280
  CRL and answers RFC 6960 OCSP — `/pki/crl/{scope}/{ca}`,
  `/pki/ocsp/{scope}/{ca}`, `/pki/ca/{scope}/{ca}.cer` and an index at
  `/pki/revocation`, plus a copy of each list in the directory under `ou=crl` —
  every certificate names its own over plain http and ldap, a pane on `/admin/pki`
  revokes one by hand with any of the nine RFC 5280 reasons, and anything
  rotated goes on its issuer's list as `superseded` automatically. **What this
  service does not do is CONSULT one, its own included**: a client certificate
  presented to it is checked against the anchors on `/tls/trust` and no list is
  fetched, so a certificate revoked here still authenticates here.
* **AND *TAKE THE KEY PAIR OFF* IS A THIRD ACT, NOT EITHER OF THOSE.** It stops
  this service **accepting** what that key signs, because the key is no longer
  registered against the application; it puts nothing on any revocation list
  and does not stop the certificate chaining, and the reply says so in those
  words. Somebody dealing with a compromised key pair wants both controls.
* **IN DEVELOPMENT MODE THE HIERARCHY DIES WITH THE PROCESS**, which is the rule
  the signing key already follows and for the same reason: a mock is disposable
  and its credentials are meant to die with it. In **product** mode it is
  written to `sts_keys`, sealed under the same key-encryption key as the signing
  keys, in the same row family — a store of its own would have been a second
  answer to *where does this service keep a private key*, and the second answer
  is the one nobody remembers to rotate.

### The encoder is the debugger's own, vendored byte-identical

`common/vendored/x509.js` — the same module behind that project's *PKI / X.509*
workflow page, and what `spiffe/spiffe_ca.js` already issues X509-SVIDs with. So
a certificate issued here and one issued there are built by **one** encoder, and
a difference between them is a difference in the arguments rather than in two
implementations that drifted. The three tiers are its own `root-ca`,
`intermediate-ca` and `issuing-ca` **profiles** — same `pathLen` (unconstrained,
1, 0), same key usages, same default lifetimes — rather than a second table.

**THE PAGE HAS NO SCRIPT ON IT**, and that argument is made from scratch rather
than inherited from the page next door. The debugger's PKI page needs one
because its whole point is that the key never leaves the browser; this page's
whole point is the opposite — this process holds the CA private keys and a
browser must never — so every choice is a form field, every computation is on
the server, and `script-src 'none'` is untouched.

## Versioning

The version is **M.N.O**:

```
0.1.20260906143205
│ │ └── the build number: the UTC build instant (YYYYMMDDHHMMSS), or BUILD_NUMBER
│ └──── minor ┐ from the repo-root VERSION file, the single source of M.N
└────── major ┘
```

**The build number is fixed when an image is BUILT, not when it runs.** The
Dockerfile runs `node common/version.js --stamp .` after the source is copied,
which writes a `version.json` into the image; the service reads that at startup.
A service that numbered itself at startup would report a different build every
time its container restarted, which makes *which build is this* unanswerable in
exactly the situation where it gets asked. A checkout run with `node server.js`
has no stamp, computes a number and **says so** — every surface that draws the
version reports whether it was stamped.

Seven places report it: the startup log, the front page, the foot of every
`/admin` console page, the foot of every `/portal` page, `GET /admin-api` (with
`build`, `commit`, `builtAt` and `stamped` as separate fields),
`/admin/sts-metadata` — in the page and in `?format=json` — and **the remote
XACML PEP**, on its own `GET /` and in the Version column of
`/admin/xacml/peps`, which is the row it registers with this service. The three
outbound requests this service makes carry it too, as
`User-Agent: sts/0.1.<build> (federation | ssf-transmitter |
xacml-pdp-notify)`.

**The `xacml-pep/` container is stamped separately, and that is deliberate.**
It is a second image built from this same tree: `VERSION` and
`common/version.js` are copied into it at build time — one copy of each in the
repository — so its **M.N always matches this service's**, while its **build
number is its own** unless the same `BUILD_NUMBER` is passed to both builds.
A PEP left behind across a release shows up as a different M.N on that console
row; two build numbers a few seconds apart are just two artifacts.

```bash
# One release, both images:
BUILD_NUMBER=$(date -u +%Y%m%d%H%M%S) GIT_COMMIT=$(git rev-parse HEAD) \
  docker compose --profile xacml build
```

```bash
node common/version.js                    # 0.1.20260906143205
node common/version.js --json             # the whole record, with the commit
node common/version.js --check-manifests  # non-zero if a package.json is stale
node common/version.js --sync-manifests   # fix them

# Give an image a build number and a commit of your choosing:
BUILD_NUMBER=1234 GIT_COMMIT=$(git rev-parse HEAD) docker compose build sts
```

**Cutting a release is editing `VERSION` and running `--sync-manifests`.** Both
`package.json` files carry the same M.N as `M.N.0` — semver needs three parts,
and the real build number is not one of them — and `--check-manifests` is what
stops a bump that edited `VERSION` alone from leaving them silently stale.

**Nothing about the version can stop this service starting.** An unreadable
`VERSION` file falls back to `0.0` and a corrupt stamp falls back to a computed
record, both with a message on stderr. That is the opposite of the signing key,
which is fatal to lose in product mode, and the difference is deliberate: a
wrong version misinforms a reader, a wrong key invalidates every token this
service has ever issued.

## Running the tests

```bash
npm test                          # the in-process suite: one process, under
                                  # two seconds, no port and no container
./docker-run-tests.sh             # ALL 23 jobs, ENTIRELY IN CONTAINERS: the
                                  # service AND the runner, on a host that has
                                  # docker and nothing else. What CI runs
./local-run-tests.sh              # ALL 23 jobs, with a report written: that
                                  # suite AND the protocol jobs, the latter
                                  # against a CONTAINER built from this tree
./local-run-tests.sh --only=crypto --open
./local-run-tests.sh --no-protocol  # the in-process suite alone, 3 seconds
./local-run-tests.sh --no-docker    # the protocol jobs against a service run
                                    # on this machine instead of a container
./local-run-tests.sh --keep-stack   # leave the container up afterwards, to
                                    # read /admin or re-run one job by hand
./local-run-tests.sh --modes=cluster  # a fourth mode, only when named: two
                                      # service containers active-active on one
                                      # postgres behind an HAProxy, every job's
                                      # requests alternating between them
./run-coverage.sh                 # the same run, with coverage collected —
                                  # in containers too, with the RUNNER in the
                                  # container rather than the service
./run-coverage.sh --no-docker     # ...and the same collection on this machine
```

**THE TWO LAUNCHERS RUN THE SAME TWENTY-THREE JOBS AND DIFFER ONLY IN WHERE THE
TESTS THEMSELVES RUN**, which is the whole reason both exist.
`./local-run-tests.sh` is the development loop: the service is a container, the
jobs are plain node processes on your machine driving your Chrome, so editing a
test and re-running it costs nothing. `./docker-run-tests.sh` puts the runner in
a container too — node, the browser and this working tree, built from
`tests/Dockerfile` — brings both up from `docker-compose-run-tests.yml` on a
private network, and exits with the suite's status. It needs **docker and
nothing else**: no node, no `npm install`, no Chrome, no checkout of the parent
project. That makes it what `.github/workflows/tests.yml` runs on every push,
and what to reach for when a run passes on one machine and not on another —
a difference between the two launchers is a difference in the environment and
in nothing else.

**CI RUNS BOTH LAUNCHERS, IN TWO JOBS THAT DO NOT DEPEND ON EACH OTHER** —
`tests` wraps `./docker-run-tests.sh` and `coverage` wraps `./run-coverage.sh`,
and three artifacts come out of a run: `test-report` (the plain suite's
`tests/report/latest`), `coverage-report` (the rendered `coverage/`) and
`coverage-test-report` (the instrumented run's own report). They are two jobs
rather than two steps because both launchers move the `tests/report/latest`
symlink, so in one workspace the second run would quietly relabel the first
run's artifact; two jobs are two workspaces. It also means the coverage pass
still runs when the suite goes red, which is when its report is worth most, and
that the two run in parallel. **A third job, `cluster` (2026-09-15), runs
`./docker-run-tests.sh --modes=cluster`** — the fourth mode, two active-active
nodes behind a load balancer, which no bare run includes — on a runner of its
own and uploads `cluster-test-report`. All four uploads are `if: always()`.

Neither can disturb a mock you are already running. Each is its own compose
project with its own container names, `./local-run-tests.sh` publishes a free
port found at start and `./docker-run-tests.sh` publishes none at all, so
`docker compose up`'s `sts` on 8081 is untouched by both — including by their
teardowns.

`npm test` is what `tests/` is for and is unchanged by everything below it: it
needs `npm install` to have been run and nothing else — no port, no container,
no browser, no network — and it asserts this repository's own module contracts,
which no caller over HTTP could check. `tests/CLAUDE.md` argues where the line
is.

**`./local-run-tests.sh` adds a report** — `tests/report/<timestamp>/` with
`report.html`, JUnit `report.xml`, `summary.json` and one log per job, and
`tests/report/latest` pointing at the newest. It runs each test file in a
process of its own, so a file that hangs is a job that times out rather than a
suite that never finishes, and a file that takes its process down is one red job
rather than a run with no report at all. The per-assertion detail in the report
is read out of what the tests already print, so a test written before any of
this existed is reported in full by it.

**THE PROTOCOL JOBS ARE THE HALF TO KNOW ABOUT, AND THEY RUN BY DEFAULT.**
The tests that drive this service over HTTP are authored in the parent project,
and that suite drives the `sts/` gitlink over there — which is pinned, so a
change made in this working tree is not covered by it until somebody bumps the
pin. FOURTEEN jobs live in `tests/vendored/` — nine of them byte-identical
copies of the parent's, and FIVE this repository's own: the four that drive
`/admin` and `/admin-api`, ours since 2026-08-28, and the delegated permission
example added 2026-09-01, which was never over there at all. Every
`./local-run-tests.sh` runs the lot: the metadata drift checks, the management
API and every one of its operations, the whole admin console in a real browser,
the five-application delegated permission example, DPoP, the authorization
server's endpoints, the DID-named issuer, SAML 1.1, SAML encryption, the
UserInfo endpoint and the Linked-Data credential jobs. About a minute, most of
it the browser job. `--no-protocol` is the way back to the in-process suite
alone, and it says in the report that nothing was checked about any protocol
surface.

**What they drive is a CONTAINER, built from this working tree by this
repository's own `docker-compose.yml`.** The launcher builds the image, brings
up one container — its own compose project, its own container name, a free host
port, `persistence.mode=memory`, no database — hands the runner its URL, and
LEAVES IT RUNNING when the suite finishes, printing how to reach it and how to
stop it (`--tear-down` is the way back); the tests themselves are ordinary node
scripts on this machine. What that buys is that the thing under test is the IMAGE: the same
`npm install --omit=dev` against the committed lock, the same node, the same
`COPY . ./` with `.dockerignore` deciding what is in it — so a module missing
from the build context or a submodule that was never initialised fails HERE
rather than in somebody's deployment. `--no-docker` runs the service on this
machine instead (nine ports of its own, both SPIFFE Unix sockets off, stopped
by the pid it started), which is what a machine with no docker falls back to.

**A coverage run is the one that cannot drive that container**, and the reason
is worth keeping straight from a claim about containers in general: V8 writes
its coverage from inside the process being measured, so a service reached over
HTTP can never be under the report. `./run-coverage.sh` therefore moves the
RUNNER into a container instead — `docker compose run --rm --no-deps` on
`docker-compose-run-tests.yml`'s `tests` service, which never starts the `sts`
service — and lets it start the service it measures as a child process in
there, with `./coverage` and `./tests/report` bind-mounted out. So a coverage
run needs docker and nothing else too; `./run-coverage.sh --no-docker` is the
host run, and a machine without docker falls back to it loudly.

A vendored job can be AHEAD of this tree — those jobs are developed against the
parent's own checkout of this service — and it then fails here naming a feature
this tree has not got. That is a fact about when the copy was taken rather than
a fault in the runner; `./local-run-tests.sh --vendor-check` reports the drift
when both checkouts are present, and `--vendor-sync` is the only sanctioned way
those copies change.

**`./run-coverage.sh` collects coverage with nothing installed.** It uses node's
own `NODE_V8_COVERAGE` and renders the result with `tests/tools/coverage-report.js`
— written here rather than being `c8` because `.npmrc` carries `omit=dev` and the
Dockerfile passes `--omit=dev`, so a `devDependency` added for coverage would be
silently not installed and the script would fail for everybody. It writes
`coverage/index.html` with a page per file showing which lines ran and how often,
`coverage/lcov.info` in the standard format, and `coverage/raw/` — V8's own JSON,
kept so that anybody who would rather use c8 can point it at the same data. The
report has a column per domain (the in-process suite, the protocol jobs), because
"which half of the run reached this file" is the question somebody deciding what
to test next actually has.

What those numbers mean is stated on the report itself and at the top of the
renderer: **function coverage is exact** — V8 counted the calls — **line
coverage is derived**, a line taking the count of the innermost V8 range over
its first non-blank character and counting as code when it is neither blank nor
wholly a comment, and **there are no branch numbers at all**, because V8's block
ranges are not branch arms and a percentage with no definition is worse than
none.

Both reports and `coverage/` are gitignored: a report is a claim about one run on
one machine, and a stale one committed beside the code would be read as a claim
about the code.

## Where this came from, and what did not come with it

Extracted from the OAuth2/OIDC Debugger. Two things were adapted rather than copied:

* the **Dockerfile**, whose `COPY` paths were repo-root-relative (`COPY sts/*.js`) and
  are now relative to this repo's root;
* the **JSON-LD contexts**, which live in the parent project's client tree. `bbs2023.js`
  already resolves two layouts and a sibling `contexts/` directory is its second
  candidate, so no code changed — and that is also why, when the 2026-08-23
  reorganisation moved `bbs2023.js` into `common/vendored/`, the contexts moved with
  it rather than staying at the root: keeping them a SIBLING is what let a vendored
  file stay byte-identical.

**The PROTOCOL tests did not come with it, and new ones go back there rather
than being written here.** (What does live here is `tests/`, added 2026-08-25 —
in-process assertions about this repository's own module contracts, which no
caller over HTTP could make; `npm test`, and see `tests/CLAUDE.md` for the line
between the two.) They live in the parent project's `tests/` directory, and five
of
them need only this service — `sts_metadata.js` (the drift checks described
above), `sts_dpop.js` (the RFC 9449 negatives), `oauth2_sts_endpoints.js`,
`vc_did.js`, and `saml11_sso.js`, which drives the SAML 1.1 browser profiles over
HTTP with a relying party it writes itself and 131 checks, most of them refusals.
The first four are still unported and doing that is the obvious next step; until
they are, the drift checks this README describes are documentation rather than
enforcement.

`saml11_sso.js` is also the answer to "where does a new test go". It was written
in a `tests/` directory in THIS repository on 2026-08-25 and moved to the parent
suite the same day, because a second suite here would mean a second runner, a
second report and a second place to forget. There was one exception —
`federation-e2e/`, a three-container stack, which stayed because it built a
topology out of several copies of this service rather than driving one — and it
closed on 2026-08-26: trust realms make several copies of this service out of
ONE process, so that test is `tests/federation_sso.js` in the parent suite now,
driving two realms and letting the debugger be the application tier.

The protocols added since then bring more of them into that category, and the Kerberos
and WebAuthn ones are the interesting cases because of *how* they check rather than what:
`krb5_codec.js` and `krb5_codec_sync.js` use the codec's own symmetry as a round-trip
oracle, `krb5_gss_tokens.js` pins every byte of the 0x8003 checksum, `krb5_crypto.js`
covers the RFC 3961 etypes against published test vectors, `krb5_as_exchange.js` drives
the AS exchange, and `webauthn_cross_impl.js` runs `webauthn.js` and the debugger's own
independent decoder over the same real ceremonies and requires the same verdict from
both. That last one is the reason `webauthn.js` must stay loadable on its own, with no
`./helpers` in reach.

**WS-Federation has no test in either repository**, which is worth saying plainly
because the mock relying party makes it *look* covered: `/wsfed/rp` verifies a sign-in
response check by check and shows every verdict, but a person has to click it and read
the page. What a real test would add is the negatives, which is where this profile's
value is — a `wctx` that came back altered, `wauth` demanding a factor the session
never had, `wfresh` read as seconds, an assertion whose signature reference does not
resolve because the SAML 1.1 id attribute was not named. A passive requestor that
issues a good token and posts it to a working relying party looks finished and proves
almost nothing, which is the same argument `sts_dpop.js` makes over there.

## Licence

MIT — see [LICENSE.md](LICENSE.md).
