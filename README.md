# Mock STS

A deliberately permissive **mock identity service** that speaks twelve protocol
families — one of which, Kerberos, is not HTTP at all — for exercising clients. It
authenticates nobody, checks no passwords and validates no access tokens (UserInfo
excepted, deliberately, and there is a section on why below): it exists so that a
client can be driven through a complete protocol exchange without standing up a real
identity provider. Kerberos is the one place a password is checked, because there the
password *is* the encryption key — so it takes the nearest permissive equivalent
instead: any username at all, and `password!` for every one of them.

**Authentication is intentionally fake. Protocol behavior is not.**

Mock STS exists to test identity protocol integrations, not identity security. It 
accepts essentially any identity and produces protocol-correct tokens, assertions,
tickets, and credentials. It is deliberately unsuitable for production.

If you're testing whether your application correctly speaks OAuth, OIDC, SAML, WS-Federation,
WS-Trust, WebAuthn, DPoP, OpenID4VC, or other supported protocols, Mock STS gives you a real
protocol endpoint without requiring you to deploy or configure a real identity provider.

Extracted from the [OAuth2/OIDC Debugger](https://idptools.com), where it is the
fallback identity service for the test suite. The documentation below is carried over
from that project's engineering notes, so it explains *why* things are the way they
are — most of it is the record of something having gone wrong once.

> **Not for production.** No credential is ever verified. Any username typed at the
> login screen becomes the identity in every token it issues.

## What it speaks

| | |
|---|---|
| **Kerberos v5 (RFC 4120)** | a KDC, on **raw TCP and UDP port 88** and over MS-KKDCP: the AS and TGS exchanges, pre-authentication carrying the salt in PA-ETYPE-INFO2, a signed [MS-PAC] in every ticket, two realms with a trust between them so cross-realm referrals work, and delegation all four ways ([MS-SFU] S4U2Self, S4U2Proxy under either authorization, forwarded tickets, renewals) — plus a **service** that decrypts an RFC 4121 GSS token, checks the ticket eight ways and proves itself back |
| **SPNEGO (RFC 4178) over HTTP (RFC 4559)** | a **protected web page**: `/spnego` advertises it — the SPN, the realm, the mechanisms and three knobs that break the negotiation one way each — and `/spnego/protected` answers `401 WWW-Authenticate: Negotiate` to an unauthenticated request and `200` with an AP-REP in that header to a valid one. NegTokenInit with the optimistic mechToken, NegTokenResp in all four negStates, and the mechListMIC in both directions with section 5's rule for when it is mandatory. Only Kerberos is offered: NTLM is recognised in a client's list and never selected, because advertising a mechanism this service cannot perform would be a lie a client would act on. **Every Kerberos check is the protected service's, unchanged** — this is a transport and a negotiation, and no protocol code of its own |
| **WS-Trust 1.0–1.4** | Issue / Renew / Validate / Cancel, WS-Security, WS-Addressing, optional XML-DSIG and XML-Enc |
| **SAML 2.0 and SAML 1.1** | signed assertions of both vintages, and the metadata a relying party needs. 1.1 is here because it is what a WS-Federation relying party expects by default |
| **WS-Federation 1.2** | the Web (Passive) Requestor Profile of section 13 — `wsignin1.0` with `wtrealm`, `wreply`, `wctx`, `wct`, `wfresh`, `wauth`, `whr` and `wreq`, the response as a **form POST**, `wsignout1.0` with front-channel cleanup, signed federation metadata at AD FS's path, and a mock relying party that verifies the response check by check |
| **OAuth 2.0** | a full authorization server: RFC 8414 metadata plus every endpoint it advertises — authorize (with a login screen), token, userinfo, introspect, revoke, register (RFC 7591, and the RFC 7592 read/update/delete operations), jwks. PKCE (RFC 7636), Rich Authorization Requests (RFC 9396), the `iss` authorization response parameter (RFC 9207), and every one of the seven grant types its metadata advertises — including **Token Exchange (RFC 8693)** |
| **OpenID Connect 1.0** | `id_token` with `nonce`, `at_hash` and `c_hash` across all three flows, the section 5.3 UserInfo endpoint, **Discovery 1.0** at all three URLs a client may look at, and RP-Initiated Logout |
| **WebAuthn Level 3** | the relying party's half of a second factor on the login screen: registration and assertion both verified, and `amr` / `acr` in the tokens that follow saying a hardware key was used |
| **DPoP (RFC 9449)** | all twelve section 4.3 proof checks, `cnf.jkt` on access *and* refresh tokens, `dpop_jkt`, replay detection, the nonce handshake |
| **OpenID4VCI 1.0** | a Credential Issuer: SD-JWT VC (RFC 9901), `jwt_vc_json`, `ldp_vc` with bbs-2023; Credential Offers, the pre-authorized code grant with `tx_code`, `authorization_details`, batch issuance, response encryption, deferred issuance, the Notification Endpoint |
| **OpenID4VP 1.0** | a Verifier with DCQL that **actually verifies** what it is sent, check by check |
| **W3C DID Core 1.0** | its own `did:web` document, and the DIF Well Known DID Configuration that links it to its origin |

`GET /sts-metadata` is the authoritative list — every endpoint read from the running
router, so it cannot go stale, and thirty-eight specifications with how far each one
goes. See *The index of itself* below, including the one blind spot that design has:
a protocol that registers no route, which is exactly what Kerberos is.

**WS-Federation used to be the gap here, and this note used to say so.** Until
`wsfed.js` existed, the pieces a passive-requestor profile needs — the assertion
builder, the signer, the login screen — were all present and the profile that joins
them was not, which made this an assertion *issuer* rather than an identity provider
with a browser-facing SSO profile. It now has one; see *WS-Federation* below. What
is still absent is named there rather than left to be inferred, which is the point
this paragraph was making in the first place.

**There is still no SAML 2.0 Web SSO profile**, and that is the gap that remains
beside it: no `SingleSignOnService`, no `AuthnRequest`, no `Response`. The browser
SSO profile this service has is WS-Federation's, and the federation metadata
deliberately publishes no `IDPSSODescriptor` for exactly that reason — advertising
one would be a relying party's first configuration attempt and its first 404.

## Running it

```bash
npm install
CONFIG_FILE=./env/local.js node server.js      # listens on 8081
```

`STS_PORT` overrides the port. `CONFIG_FILE` selects a configuration from `env/`,
the only setting in which is the bunyan log level — at the default `debug` the
service logs every endpoint call (path, request and response headers and bodies,
status, elapsed time) and every assertion, JWT and SD-JWT VC both before and after
signing or encryption, which is the point of a mock.

**Three listeners, not one.** 8081 is the HTTP service; the KDC also binds **TCP and
UDP 88**, and the Kerberos-protected service a TCP socket of its own (8888). The two
Kerberos listeners are started from an exported `listen()` that `server.js` calls
*after* the HTTP server is up, and a failure to bind is logged rather than thrown —
port 88 is privileged, a host
run is usually not root, and a require that throws would take the whole service down
over a protocol family the caller may not be using. Set `KRB5_KDC_PORT` to something
unprivileged for a host run.

In Docker:

```bash
docker build -t mock-sts .
docker run --rm -p 8081:8081 mock-sts
```

That publishes the HTTP port only, which is enough for everything except a raw
Kerberos client: in the container this process is root, so the KDC does bind 88, but
nothing forwards it. `-p 88:88/tcp -p 88:88/udp -p 8888:8888` adds it. The
`docker-compose.yml` here publishes 8081 alone for the same reason — an in-browser
Kerberos client reaches the KDC through `POST /KdcProxy` (MS-KKDCP) on the HTTP port,
which is the whole reason that endpoint exists.

The OIDC Discovery Metadata Endpoint:
```
http://localhost:8081/server001/.well-known/openid-configuration
```

Via Docker-Compose:
```bash
docker-compose up
```
### Environment

| Variable | What it does |
|---|---|
| `STS_PORT` | the port to listen on (default `8081`) |
| `CONFIG_FILE` | which file in `env/` to read (default `./env/local.js`) |
| `OID4VCI_WALLET_URL` | **the base URL the BROWSER uses for the wallet.** The Credential Offer pages and the verifier's request pages hand the End-User back by appending `/vc-issuance-1.html` or `/vc-presentation-1.html` to it. Its default of `http://localhost:3000` is right only when the browser and the wallet share a host; get it wrong and the hand-off lands on an unreachable origin, and because the URL still *contains* the wallet page a `urlContains` wait passes and the failure looks like an unrelated timeout |
| `OID4VP_WALLET_URL` | the same for the presentation side; falls back to `OID4VCI_WALLET_URL` |
| `OID4VCI_AUTHORIZATION_SERVER` | point the issuer metadata at a *different* authorization server (a real IdP) while the credential endpoint stays here |
| `OID4VCI_SD_JWT_ISSUER_DID` / `OID4VCI_LDP_VC_ISSUER_DID` | switch the **plain** credential configurations over to naming the issuer by DID. Off by default — see *The issuer named by a DID* |

And for Kerberos, none of which needs setting for the defaults to work:

| Variable | What it does |
|---|---|
| `KRB5_KDC_PORT` | the KDC's TCP **and** UDP port (default `88`). Both transports are bound to the *same* number on purpose — a client that fails over from UDP after `KRB_ERR_RESPONSE_TOO_BIG` retries at the address it already had. If the parent project's api is relaying to this KDC, its `krb5AllowedPorts` has to allow whatever this becomes |
| `KRB5_REALM` / `KRB5_TRUSTED_REALM` | the two realms (`EXAMPLE.COM`, `PARTNER.COM`). One KDC answering for both is the one simplification here — it hides finding the other realm's KDC and none of the protocol |
| `KRB5_TRUST_PASSWORD`, `KRB5_KRBTGT_PASSWORD`, `KRB5_TRUSTED_KRBTGT_PASSWORD` | the long-term keys behind `krbtgt/<realm>` and the trust principal. A trust is not a setting: it is one principal whose key both realms hold |
| `KRB5_USER_PASSWORD` | **the password every user account shares** (default `password!`). Not per-account, because there are no per-account secrets here — see *Any username, one password* |
| `KRB5_UNKNOWN_USERS` | the usernames that are refused rather than created (default `nosuchuser,nobody`), so `KDC_ERR_C_PRINCIPAL_UNKNOWN` is still something a test can produce on purpose |
| `KRB5_DOMAIN_SID` / `KRB5_TRUSTED_DOMAIN_SID` | the domain SIDs the PACs are built from. Fixed made-up values; what matters is that they are the same in every ticket, since a service compares SIDs and not names |
| `KRB5_CLOCK_SKEW` | the tolerance, in seconds (default `300` — AD's) |
| `KRB5_CLOCK_OFFSET` | **make the KDC lie about its clock**, in seconds (default `0`), so a client's `KRB_AP_ERR_SKEW` handling can be driven deliberately instead of by breaking a machine's time |
| `KRB5_SERVICE_PORT` / `KRB5_SERVICE_PRINCIPAL` | the ticket-protected service's TCP port (`8888`) and the principal whose key it holds (`HTTP/web.example.com`) |

## How it is put together

A mock Security Token Service used by the test suite, **split across twenty-six modules** (it was one 4,489-line `server.js` until 2026-08-03; eight protocol families in one file meant no way to see what was in it short of reading it). `server.js` is now the shell — it requires `app.js` (the express app and every middleware, which must load before any route) and `helpers.js` (the log, the keys, and the helpers more than one protocol needs), then the ten modules that register routes, and listens: `wstrust.js`, `oauth2.js`, `wsfed.js`, `vc_offers.js`, `vc_did.js`, `vc_issuer.js`, `vc_verifier.js`, `krb5_kdc.js`, `krb5_service.js`, `sts_metadata.js`. The other fourteen are reached through those rather than named there — `saml2.js`, `saml11.js`, `vc_configs.js`, `dpop.js`, `bbs2023.js`, `webauthn.js` and the eight `krb5_*.js` files under the KDC — which is not a hierarchy so much as the consequence of the rule below.

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
cycle. `webauthn.js` is a library in the same sense, and it goes one step further: it
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

### The signing key is regenerated on every start

Two consequences follow, and both are deliberate. Its `kid` is derived from the key
material (`sts-mock-<thumbprint>`) rather than being a constant, so two instances —
a stale container beside a fresh one — cannot both claim the same kid over different
keys and make "the signature does not verify" look like a corrupt document instead
of the wrong issuer. And every document that carries or describes the key (RFC 8414
metadata, OID4VCI credential issuer metadata, `jwt-vc-issuer`, the JWKS, the DID
document and the DID Configuration) is served `Cache-Control: no-store`, because a
cached copy outlives the key it describes.

All tokens are RS256 JWTs signed with that key, so they verify against the advertised
JWKS.

### The JSON-LD contexts are not optional

`bbs2023.js` reads the three files in `contexts/` **at require time**, at module
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

**What it does not say is the part worth reading.** `acr_values_supported`,
`display_values_supported`, the encryption members and `check_session_iframe` are all
absent, because none is implemented and an invented value is worse than the member's
absence, which says exactly the right thing. `end_session_endpoint` *is* advertised
because `/oauth2/logout` really does end the session — but it neither requires nor
checks `id_token_hint` and does not validate the redirect target, so it is the shape of
RP-initiated logout and not its security, and `/sts-metadata` grades it `mock`.

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
implementation detail. **The exchanged token carries no refresh token**, because there
is no end-user session behind it to refresh against, and `actor_token` becomes the
RFC 8693 `act` claim — the delegation record saying *this* client is acting for *that*
subject, which is the only part of the response a downstream resource server can
reason about.

The consequence shows up one endpoint over: an exchanged token is issued with whatever
scope was asked for, so unless that includes `openid` it gets a 403
`insufficient_scope` at UserInfo, which says in its error description that a
token-exchange or `client_credentials` token has no end-user behind it and therefore no
profile to return. Missing scopes are the usual reason a working exchange looks broken.

### UserInfo is the one endpoint that refuses a token it did not issue

`GET`/`POST /oauth2/userinfo` (OIDC Core 5.3) is a protected resource: present the
access token from an OIDC flow and get back the claims about the person it was issued
for. Two things about it are deliberate and are the opposite of how the rest of this
service behaves.

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

Writing it turned up a trap worth repeating: the RFC 6750 `WWW-Authenticate` challenge
carries the same `error_description` as the JSON body, an HTTP field value is ASCII, and
node's `setHeader` *throws* on anything else. The first description containing an em dash
— they all do here, the comments are prose — turned a 401 into a 500, which is the worst
place in the service for one, since the exception replaces the very message that was
explaining what went wrong. The header copy is now folded to ASCII; the body keeps the
real text.

### WebAuthn as the second factor a mock is allowed to have

The login screen carries a "use a security key" checkbox, and an authorization request
whose `acr_values` names `mfa`, `hwk`, `phr` or `phrh` ticks it and disables it — that
parameter is how a relying party *demands* a second factor, and a mock that ignored it
would let a client's step-up request appear to work while proving nothing. The step
itself is `POST /oauth2/webauthn`: first use for a username **enrols** a credential
(section 7.1), every later sign-in **asserts** with it (section 7.2), against a
challenge minted server-side and held for five minutes with the interrupted
authorization request.

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
not. **The ceremony script is a separate resource** (`/oauth2/webauthn.js`) rather than
an inline `<script>`, because `app.js` sets `script-src 'none'` on every response and
that one page relaxes it to `'self'`: an inline script there simply would not run, with
the button doing nothing and no error anywhere. And **the RP ID is this origin's host
and is not configurable** — WebAuthn binds a ceremony to the calling origin, and that is
the whole of its phishing resistance.

What comes out the other side is the point: a hardware-key sign-in records
`amr: ["pwd","hwk"]` and `acr: "mfa"` on the session, a password-only one
`amr: ["pwd"]` and `acr: "1"`, and those (RFC 8176) go into the id_token whenever the
session recorded them — so their *absence* means something too, which is why they are
not emitted unconditionally.

### WS-Federation — the profile that joins the pieces

`wsfed.js` is the Web (Passive) Requestor Profile of WS-Federation 1.2 section 13,
and it is the browser-facing SSO profile this service went without for a long time.
Everything it needs already existed — an assertion builder, a signer, a login screen,
a session — and what was missing was the thing that hands an assertion to a relying
party *through a browser*. Five endpoints:

| | |
|---|---|
| `GET`/`POST` `/wsfed` | the passive requestor endpoint, dispatching on `wa`. With no `wa` at all it describes itself, the way `GET /sts` does |
| `POST /wsfed/login` | where the sign-in screen posts |
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
stylistic. And **xml-crypto has to be told about `AssertionID` and must *not* be told
about `ID`**: it resolves a reference URI by looking for attributes named Id/ID/id, so
SAML 1.1's unusual name has to be added or a perfectly good signature reports as
broken, while passing `idAttribute: 'ID'` for SAML 2.0 unshifts a *duplicate* onto
that list and the library then refuses the document with a signature-wrapping-attack
error naming a document that has nothing wrong with it. Symmetry between the two call
sites is what produced the second one.

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
requires `Secure`, which this service cannot be over `http://localhost`. The screen
says so rather than leaving it to look like a broken session.

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
`IDPSSODescriptor`, per the note near the top of this file.

Not implemented, and named here rather than left to be discovered: the attribute
service (`wattr1.0`) and the pseudonym service (`wpseudo1.0`), which both answer 501
with an explanation of what they would have done; `wresultptr` (the response is always
by value); token encryption in this profile, because a passive request carries no
recipient certificate to encrypt to, where `/sts?encrypt=1` has one because a
WS-Security signature carries it; the WS-Federation metadata exchange over SOAP; and
any authorization or policy enforcement — `wp` and `wencoding` are logged and nothing
more.

### The mock STS's index of itself

`GET /sts-metadata` answers "what can I call, what may I call it with, and which specification is it pretending to implement" — a page the service needed once it had grown to eleven protocol families across twenty-six modules. `?format=json` gives the same document machine-readably.

**The endpoint list is read from the running Express router, not written down.** That is the whole design: a hand-kept list of endpoints in a file beside the endpoints goes stale the first time somebody adds a route, and the failure is silent in the worst direction — the page still looks complete. `app._router.stack` is walked **per request** (not at require time, where the answer would depend on module load order) and the table in `sts_metadata.js` only supplies the *name* and the *description* for a path the router reports. Both kinds of drift are then reported on the page itself and fail the parent project's `tests/sts_metadata.js`:

* a route **registered and undescribed** is listed as UNDOCUMENTED — it still appears, with its methods, because the page's first duty is to be a true list of what is callable. Adding an endpoint to this service therefore costs one entry in `sts_metadata.js`, which is the point.
* a description whose path is **not registered** is the more dangerous half: the page would advertise an endpoint that answers 404, which is what a rename produces, and a rename is exactly when nobody thinks to check the index.

The drift check earned its keep immediately: on first run it caught the `OPTIONS *` CORS preflight (registered by `app.options`, described nowhere) and a reference to a spec id that did not exist. The test additionally catches an *idle* claim — a specification listed that no endpoint links to — which found two, `rfc6750` and the RDF canonicalization used by Data Integrity, both genuinely implemented and both unlinked.

Each path is a **link to that path** — but only where that is honest, which is about half of them. A link is issued as a GET, so a path the router answers only for POST would land the reader on Express's own `Cannot GET /oauth2/token` (reads as a broken service), and a route pattern carrying a `:parameter` or a `*` is not the address of anything. Those are listed unlinked with the reason shown — "POST only", "takes :id", "wildcard" — because that reason is the most useful thing on the row. The five followable endpoints that *do* something when clicked (`/oauth2/authorize`, `/oauth2/logout`, `/oauth2/userinfo`, `/issuer/offer`, `/oid4vp/start`) carry an `effect` note; the first answers **400** when followed bare since it needs `client_id` and `redirect_uri`, and userinfo answers **401** since it is a protected resource. Links are root-relative so they follow whichever host the page was reached at, and open in a new tab so the index survives the click. That test **follows every link** and fails if one does not reach a handler, which is what stops the page advertising a dead one.

Two details worth knowing before changing the test. **A 404 is ambiguous and the distinction matters**: several endpoints answer 404 correctly for a resource that does not exist (an unknown offer id, an unknown presentation state), which *proves* the route is registered, while Express's own 404 for an unregistered path is an HTML page reading `Cannot GET /path`. Treating them alike either fails on healthy endpoints or passes on missing ones. And the **coverage notes must start `full`, `partial` or `mock`** and say what is missing, because a list of thirty-eight specifications that did not mention that this service checks no passwords and validates no access tokens would be the most misleading thing in the repository.

**Kerberos is the one blind spot in the whole design, and it is structural.** The page is built by walking the live Express router, which is precisely why it cannot go stale — and the KDC's listeners are raw TCP and UDP sockets, as is the protected service's. A protocol family that registers no route is invisible to a router walk. Three HTTP surfaces are all the walk can see (`/KdcProxy`, `/krb5/principals`, `/krb5/service`), so the sockets are described in the text of those rows rather than left to be inferred from silence — the alternative, a described entry with no route behind it, is the *stale* half of the drift check and would have to be exempted from it by hand. Anything added later that speaks a protocol over a socket needs the same treatment.

### DPoP — sender-constrained access tokens (RFC 9449)

A Bearer access token (RFC 6750) is a password: whatever can read the bytes can spend them. **DPoP** binds the token to a key — the token carries `cnf.jkt`, the RFC 7638 thumbprint of a public key — and every request presenting it must carry a fresh signature from the matching private key over *that request's* method and URI. The stolen bytes are then worthless.

**Where it applies, and where it deliberately does not.** OID4VCI 1.0 names DPoP exactly three times: its Security Considerations say the use of DPoP is **RECOMMENDED** for sender-constrained access tokens (mTLS being impractical for a native-app wallet), and its Nonce Response section says the Credential Issuer **MAY** return a `DPoP-Nonce` for use "when presenting an access token at the Credential Endpoint". So it covers the Token Endpoint and every protected endpoint the issuer publishes — Credential, Deferred Credential, Notification. **OID4VP 1.0 names it zero times**, and that is structural rather than an omission: in its own words "the result of an OpenID4VP interaction is one or more Verifiable Presentations … *instead of an Access Token*". There is no token in that exchange to sender-constrain, and the presentation's own proof of possession is the Key Binding JWT. A wallet is therefore right to offer no DPoP switch on its presentation pages; the parent project's carry a pane explaining why instead, with a table comparing the two proofs side by side (`typ`, what possession is proved of, where freshness comes from, `htu` vs `aud`, `ath` vs `sd_hash`). DPoP is also **indifferent to the credential format** — it binds an OAuth token, not a credential — so it works unchanged for `dc+sd-jwt`, `jwt_vc_json` and `ldp_vc`, and nothing in the implementation reads the format.

**On the server.** `dpop.js` implements all twelve RFC 9449 section 4.3 checks, labelled by number, plus `jti` replay detection; `oauth2.js` binds the access **and refresh** tokens (section 5 — a wallet is a public client, so an unbound refresh token would be a bearer credential that mints bound access tokens for whoever holds it, which is worse than not binding because `token_type` would claim a guarantee nothing checked), advertises `dpop_signing_alg_values_supported` (section 5.1 — the *only* signal that DPoP is on offer, so a server that supports it silently is never asked), honours `dpop_jkt` on the authorization request (section 10, which closes the window PKCE does not: a thief holding the code *and* the `code_verifier` still cannot sign for the key), and reports `DPoP` rather than `Bearer` from introspection. The protected endpoints had three copies of a Bearer-only check and now share **one** `presentedAccessToken()`, because a per-endpoint copy is how one of three ends up not demanding the proof — and the one that forgot is the one an attacker would use. There are **four** of them since UserInfo, which is why that function now lives in `dpop.js` rather than in `vc_issuer.js` where it was written: the fourth caller is in `oauth2.js`, and requiring vc_issuer.js from there would either build a cycle or move OID4VCI ahead of OAuth2 in the route order, while copying the check into the OAuth2 module is exactly the mistake this paragraph records having been made once already. `dpop.js` registers no routes and requires only `helpers.js`, so it is the one place both callers can reach. Note a limitation stated in that function: this issuer accepts tokens from a foreign authorization server and cannot verify them, so for such a token `cnf.jkt` is a claim anyone could have written; the binding is real only for tokens this service issued — and `verified` in what it returns is how UserInfo, which cannot live with that, tells the difference. There is deliberately **no "DPoP required" mode** — nonce mode makes proofs fresher, not mandatory — and the two nonce-request shapes are *not* shared code, because an authorization server asks with a 400 JSON body while a resource server asks with a 401 `WWW-Authenticate`, and getting that wrong leaves a conforming wallet with no way forward. `POST /dpop/nonce-mode` is a non-spec runtime switch so the handshake can be exercised without a restart; it is listed as non-spec on `/sts-metadata`.

### Kerberos v5 — the protocol here that is not HTTP

Everything else in this service answers a request over HTTP. Kerberos speaks DER over
TCP and UDP port 88, so the KDC's listeners are **raw sockets**, and that one fact is
behind most of the design notes above: `listen()` instead of a require-time bind,
`/KdcProxy` for a browser that cannot open a socket at all, and a `/sts-metadata` page
that cannot see any of it.

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
all: the name typed at `/oauth2/login` becomes the identity and that is the end of it.
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

* **A service principal is never created.** Only a single-component name — a user — is,
  which is how Kerberos itself tells the two apart. `KDC_ERR_S_PRINCIPAL_UNKNOWN` for a
  missing or misspelled SPN is the most common Kerberos failure there is, and a KDC that
  invented the service would instead hand back a ticket sealed with a key the service
  does not hold. That surfaces at the AP exchange as *decrypt integrity check failed* —
  the same message a genuinely wrong key gives, pointing nowhere near the real cause.
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

## Where this came from, and what did not come with it

Extracted from the OAuth2/OIDC Debugger. Two things were adapted rather than copied:

* the **Dockerfile**, whose `COPY` paths were repo-root-relative (`COPY sts/*.js`) and
  are now relative to this repo's root;
* the **JSON-LD contexts**, which live in the parent project's client tree. `bbs2023.js`
  already resolves two layouts and a sibling `contexts/` directory is its second
  candidate, so no code changed.

**The tests did not come with it.** They live in the parent project's `tests/`
directory, and four of them need only this service — `sts_metadata.js` (the drift
checks described above), `sts_dpop.js` (the RFC 9449 negatives), and
`oauth2_sts_endpoints.js` and `vc_did.js`. Porting those is the obvious next step;
without them the drift checks this README describes are documentation rather than
enforcement.

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
