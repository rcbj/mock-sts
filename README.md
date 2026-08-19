# Mock STS

A deliberately permissive **mock identity service** that speaks fourteen protocol
families — three of which, Kerberos, LDAP and TLS, are not HTTP over its own
listener at all — for exercising clients. It
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
| **SPNEGO (RFC 4178) over HTTP (RFC 4559)** | a **protected web page**: `/spnego` advertises it — the SPN, the realm, the mechanisms, the hosts it will answer for (`acceptsAnySpnForHosts`) and three knobs that break the negotiation one way each — and the 401 itself carries `X-Krb5-Service-Principal` and `X-Krb5-Accepts-Spn-Hosts`, which are nobody's standard and exist because SPNEGO carries no SPN at all: a client has to guess `HTTP/<url host>`, and that guess being wrong is the commonest SPNEGO failure there is — and `/spnego/protected` answers `401 WWW-Authenticate: Negotiate` to an unauthenticated request and `200` with an AP-REP in that header to a valid one. NegTokenInit with the optimistic mechToken, NegTokenResp in all four negStates, and the mechListMIC in both directions with section 5's rule for when it is mandatory. Only Kerberos is offered: NTLM is recognised in a client's list and never selected, because advertising a mechanism this service cannot perform would be a lie a client would act on. **Every Kerberos check is the protected service's, unchanged** — this is a transport and a negotiation, and no protocol code of its own |
| **WS-Trust 1.0–1.4** | Issue / Renew / Validate / Cancel, WS-Security, WS-Addressing, optional XML-DSIG and XML-Enc |
| **SAML 2.0 and SAML 1.1** | signed assertions of both vintages, and the metadata a relying party needs. 1.1 is here because it is what a WS-Federation relying party expects by default |
| **WS-Federation 1.2** | the Web (Passive) Requestor Profile of section 13 — `wsignin1.0` with `wtrealm`, `wreply`, `wctx`, `wct`, `wfresh`, `wauth`, `whr` and `wreq`, the response as a **form POST**, `wsignout1.0` with front-channel cleanup, signed federation metadata at AD FS's path, and a mock relying party that verifies the response check by check |
| **OAuth 2.0** | a full authorization server: RFC 8414 metadata plus every endpoint it advertises — authorize (which redirects to the authentication service when nobody is signed in), token, userinfo, introspect, revoke, register (RFC 7591, and the RFC 7592 read/update/delete operations), jwks. PKCE (RFC 7636), Rich Authorization Requests (RFC 9396), the `iss` authorization response parameter (RFC 9207), and every one of the seven grant types its metadata advertises — including **Token Exchange (RFC 8693)** |
| **OpenID Connect 1.0** | `id_token` with `nonce`, `at_hash` and `c_hash` across all three flows, the section 5.3 UserInfo endpoint, **Discovery 1.0** at all three URLs a client may look at, and RP-Initiated Logout |
| **WebAuthn Level 3** | the relying party's half of a second factor on the login screen: registration and assertion both verified, and `amr` / `acr` in the tokens that follow saying a hardware key was used |
| **DPoP (RFC 9449)** | all twelve section 4.3 proof checks, `cnf.jkt` on access *and* refresh tokens, `dpop_jkt`, replay detection, the nonce handshake |
| **OpenID4VCI 1.0** | a Credential Issuer: SD-JWT VC (RFC 9901), `jwt_vc_json`, `ldp_vc` with bbs-2023; Credential Offers, the pre-authorized code grant with `tx_code`, `authorization_details` (including its `claims` member, so a wallet can ask for a subset of the claims), batch issuance, response encryption, deferred issuance, the Notification Endpoint |
| **OpenID4VP 1.0** | a Verifier with DCQL that **actually verifies** what it is sent, check by check |
| **W3C DID Core 1.0** | its own `did:web` document, and the DIF Well Known DID Configuration that links it to its origin |
| **TLS / mutual TLS (RFC 8446)** | two **HTTPS listeners of its own** — 8443 asks for a client certificate and never refuses one, 9443 *requires* it — whose entire content is what the **server** saw: the request as it arrived, what TLS negotiated underneath it, and the client certificate exactly as presented, chain and all. It is the half of a handshake a client cannot report. It already knows what it sent; what it cannot know is which chain the server built out of that, which anchor it verified against, or whether the certificate was accepted at all — which, under TLS 1.3, it has not learned by the time its own handshake completes. The client truststore starts **empty** and is filled at runtime through `POST /tls/trust`, because the CA it has to verify is usually generated in a *browser* minutes before the connection and exists nowhere a file could hold it. `GET /tls` describes it; `GET /tls/whoami` over either listener is the report |
| **LDAP v3 (RFC 4511)** | an embedded **directory on two raw sockets — TCP 389 in the clear and TCP 636 over TLS (LDAPS)**, one set of handlers and one store behind both: simple bind, unbind, add, delete, modify, modifyDN, compare and search with RFC 4515 filters and all three scopes, a root DSE, and result codes 0, 2, 4, 11, 16, 32, 49, 66 and 68 all reachable. Built on the [`ldapjs`](https://github.com/rcbj/node-ldapjs) submodule and used unmodified. It is **schemaless on purpose** and says so, it enforces the four structural rules whose absence would teach a client something false, and it deliberately does not do referential integrity. `GET /ldap` describes it and `GET /ldap/directory` lists every entry. **`LDAP_AUTOCREATE_USERS`, on by default, grows an entry under `ou=users` for anybody who authenticates through any of the other twelve families** — one hook on the single funnel they all already pass |

`GET /sts-metadata` is the authoritative list — every endpoint read from the running
router, so it cannot go stale, and forty-six specifications with how far each one
goes. See *The index of itself* below, including the one blind spot that design has:
a protocol that registers no route, which is exactly what Kerberos, LDAP and the two
HTTPS listeners are.

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

**Ports 389 and 636 are both privileged**, so a host run that is not root will fail to
bind them — which is reported and is not fatal, the rest of the service being
unaffected. Set `LDAP_PORT` and `LDAPS_PORT` to something unprivileged for a host run,
and remember that the parent project's api has to allow the new ports in
`ldapAllowedPorts` (its default list carries `1389` and `1636` for exactly this). The
two sockets bind **independently**: 389 up and 636 down is the ordinary outcome of a
host run, and `GET /ldap` reports each of them separately rather than through one flag
that would have to lie about one.

`STS_PORT` overrides the port. `CONFIG_FILE` selects a configuration from `env/`,
the only setting in which is the bunyan log level — at the default `debug` the
service logs every endpoint call (path, request and response headers and bodies,
status, elapsed time) and every assertion, JWT and SD-JWT VC both before and after
signing or encryption, which is the point of a mock.

**Seven listeners, not one.** 8081 is the HTTP service; the KDC also binds **TCP and
UDP 88**, the Kerberos-protected service a TCP socket of its own (8888), the
directory **TCP 389** and — the same directory over TLS — **TCP 636**, and the TLS
endpoint **8443** and **9443**. Every one of them
is started from an exported `listen()` that `server.js` calls *after* the HTTP server
is up, and a failure to bind is logged rather than thrown — ports 88, 389 and 636 are
privileged, a host run is usually not root, and a require that throws would take the
whole service down over a protocol family the caller may not be using. Set
`KRB5_KDC_PORT`, `LDAP_PORT`, `LDAPS_PORT`, `STS_TLS_PORT` and `STS_MTLS_PORT` to
something unprivileged or unoccupied for a host run, and remember that the parent
project's api allowlists the port it will reach on each of them.

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
| `OID4VP_CLAIMS` | which claims the mock Verifier asks a wallet for (default `given_name,family_name`). It is now the value the process *starts* with rather than the value it uses: `/admin/vc-verifier-config` changes it while running, and Reset on that page comes back here |
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
| `KRB5_SERVICE_DOMAINS` | the hosts a **service principal is created on demand** for (default: the realm's domain, `localhost`, `sts`, `127.0.0.1`). An entry matches a host that is it or ends with a dot and it; an SPN outside them stays `KDC_ERR_S_PRINCIPAL_UNKNOWN`. Set it to an empty string to create nothing, which is the behaviour before 2026-08-17 |
| `KRB5_AUTO_SERVICE_PASSWORD` | the password shared by every service created that way (default `auto-service-password`), **published** by `GET /krb5/principals` like the user one — it is what lets a debugger open such a ticket and read the PAC inside it. Configured service accounts keep their own |

And LDAP's, which is the other protocol here that is not HTTP:

| Variable | What it does |
|---|---|
| `LDAP_PORT` | the directory's TCP port (default `389`). It is privileged, so the container binds it as root and a host run usually cannot — that is what this is for. If the parent project's api is opening this directory, its `ldapAllowedPorts` has to allow whatever this becomes; the same coupling `KRB5_KDC_PORT` has, and for the same reason |
| `LDAPS_PORT` | the same directory over TLS (default `636`, the IANA-assigned one). Privileged for the reason 389 is, and bound by a **second server object** rather than by an option on the first — ldapjs decides between a `net.Server` and a `tls.Server` at construction — so the two fail independently and are reported independently. There is no StartTLS to turn on instead: it is an extended operation, ldapjs implements none, and this repository does not patch that submodule |
| `LDAP_BASE_DN` | the naming context (default `dc=example,dc=com`). `ou=users` and `ou=groups` are derived from it rather than configured, because two variables that could disagree with it would put entries in a tree nobody is searching |
| `LDAP_AUTOCREATE_USERS` | **an entry under `ou=users` for anybody who authenticates through ANY protocol family here.** On by default; only an explicit `0`, `false`, `no` or `off` turns it off, so a misspelling stays safe. An LDAP bind does not seed one (the identity a bind presents is a DN, which already names an object here) and neither does an OAuth client. A verified **TLS client certificate** does, and it is the one identity that is a DN rather than a name — see the TLS section for where its entry goes |
| `LDAP_MAX_ENTRIES` | how large the directory may grow (default `2000`). It is in memory and it grows on its own, so an unbounded one is a memory leak with a protocol in front of it; new entries are then refused with `LDAP_ADMIN_LIMIT_EXCEEDED` rather than silently dropped |
| `LDAP_SIZE_LIMIT` | the largest result this server will return from one search (default `500`), on top of whatever the client asks for. A search of a directory this small will never reach it — but a client that has never seen `LDAP_SIZE_LIMIT_EXCEEDED` has never handled a paged result either |

And TLS's, the third thing here that is not on the HTTP listener:

| Variable | What it does |
|---|---|
| `STS_TLS_PORT` | the listener that **asks** for a client certificate and never refuses one (default `8443`) |
| `STS_MTLS_PORT` | the listener that **requires** one (default `9443`). Two ports rather than a flag, because "does this server require a client certificate" is a question a debugger answers by connecting twice, and it needs a server that answers each way |
| `STS_TLS_HOSTNAMES` | the dNSNames the self-signed server certificate is issued for (default `localhost,sts,sts-mock,sts.example.com`). A certificate naming only one of the ways this stack is reached produces a hostname-verification failure that is about this service rather than about anything the caller is debugging |
| `STS_TLS_IPS` | the iPAddress names on the same certificate (default `127.0.0.1`) |

## How it is put together

A mock Security Token Service used by the test suite, **split across forty files at its root** (it was one 4,489-line `server.js` until 2026-08-03; eight protocol families in one file meant no way to see what was in it short of reading it). `server.js` is now the shell — it requires `app.js` (the express app and every middleware, which must load before any route) and `helpers.js` (the log, the keys, and the helpers more than one protocol needs), then the modules that register routes, and listens: `authn.js`, `wstrust.js`, `oauth2.js`, `wsfed.js`, `vc_offers.js`, `vc_did.js`, `vc_issuer.js`, `vc_verifier.js`, `krb5_kdc.js`, `krb5_service.js`, `spnego.js`, `admin.js`, `admin_api.js`, `ldap_server.js`, `tls_server.js`, `sts_metadata.js`. The rest are reached through those rather than named there — `saml2.js`, `saml11.js`, `vc_configs.js`, `vc_claims.js`, `vc_verifier_config.js`, `dpop.js`, `admin_stats.js`, `bbs2023.js`, `webauthn.js`, `admin_api_spec.js`, `admin_api_docs.js` and the nine `krb5_*.js` files under the KDC and the negotiation — which is not a hierarchy so much as the consequence of the rule below. One file among them is **not a module at all**: `admin_api_explorer.js` is browser code, read off disk by `admin_api_docs.js` and served verbatim at `/admin-api/docs/explorer.js`, and nothing in node ever requires it.

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

### The authentication service

The sign-in screen is its own endpoint, `/authn/login`, and not part of any
protocol here. `GET /oauth2/authorize` used to render it in the body of a 200 at
the authorization endpoint's own URL; it now redirects to the service and is
entered a second time when the person comes back:

```
GET /oauth2/authorize?response_type=code&client_id=…      no session
  302 -> /authn/login?authn=8mQ2…                         the screen
  POST /authn/login   username=alice                      Set-Cookie: sts_mock_session=…
  302 -> /oauth2/authorize?response_type=code&client_id=… the ORIGINAL request
  302 -> http://localhost:3000/callback?code=…            answered per spec
```

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

### WebAuthn as the second factor a mock is allowed to have

The login screen carries a "use a security key" checkbox, and an authorization request
whose `acr_values` names `mfa`, `hwk`, `phr` or `phrh` ticks it and disables it — that
parameter is how a relying party *demands* a second factor, and a mock that ignored it
would let a client's step-up request appear to work while proving nothing. The step
itself is `POST /authn/webauthn`: first use for a username **enrols** a credential
(section 7.1), every later sign-in **asserts** with it (section 7.2), against a
challenge minted server-side and held for five minutes with the interrupted
request, which the person is returned to exactly as the password-only path returns
them.

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

Two details worth knowing before changing the test. **A 404 is ambiguous and the distinction matters**: several endpoints answer 404 correctly for a resource that does not exist (an unknown offer id, an unknown presentation state), which *proves* the route is registered, while Express's own 404 for an unregistered path is an HTML page reading `Cannot GET /path`. Treating them alike either fails on healthy endpoints or passes on missing ones. And the **coverage notes must start `full`, `partial` or `mock`** and say what is missing, because a list of forty-six specifications that did not mention that this service checks no passwords and validates no access tokens would be the most misleading thing in the repository.

**Kerberos is the one blind spot in the whole design, and it is structural.** The page is built by walking the live Express router, which is precisely why it cannot go stale — and the KDC's listeners are raw TCP and UDP sockets, as is the protected service's. A protocol family that registers no route is invisible to a router walk. Three HTTP surfaces are all the walk can see (`/KdcProxy`, `/krb5/principals`, `/krb5/service`), so the sockets are described in the text of those rows rather than left to be inferred from silence — the alternative, a described entry with no route behind it, is the *stale* half of the drift check and would have to be exempted from it by hand. Anything added later that speaks a protocol over a socket needs the same treatment.

### The admin console

`GET /admin` is an operator's view of the running service, and the pages under it exist for a reason the protocol endpoints cannot serve: the interesting behaviour of a client is what it does when something changes *underneath* it. A client that gets a good token and reads it correctly is a client that has been tested against the easy half. What happens when the token it is holding stops being valid, or when the token it reads grows a claim it was not expecting, is the other half, and until now there was no way to cause either without editing this service and restarting it. Every page also answers `?format=json` and every form also accepts a JSON body, because a console reachable only by clicking is a console no test can assert against.

**`/admin/metrics`** counts endpoint calls by the route Express matched — the pattern, `/oauth2/register/:client_id`, not the URL, or every registered client would get a row of its own — with the status classes, the average and worst latency and when it was last called. Then every token by `typ`, with how many are valid, expired, revoked, not yet valid and DPoP-bound; every assertion, ticket and credential the same way. All of it is computed **when the page is drawn** rather than kept up to date as things happen, and that is the load-bearing choice: "valid" and "expired" are functions of the clock, so a counter incremented at issuance is wrong a second later and would need a sweeper to stay right.

**Sessions are reported twice, and the two numbers disagree on purpose.** A *sign-on session* is a real one — a browser holding the `sts_mock_session` cookie, the store `oauth2.js` owns and WS-Federation shares. An *artifact-derived session* is an inference, and it is a definition rather than a measurement, so the page states it: a subject has one in a protocol family when that family has issued it at least one artifact that is still valid. A `client_credentials` token is the second and not the first (no human, no browser); a browser that has signed in but been issued nothing is the first and not the second; a Kerberos client is never the first at all. Within Kerberos a **TGT counts as the session and a service ticket does not**, because that is what they are — the TGT is the credential the session consists of, and a service ticket is one use of it, so counting both would report the same session twice.

**`/admin/users`** answers the question the other pages cannot: *who has this service seen, and what do they hold right now?* It lists every userid presented as part of an interaction that **succeeded** — the name typed at either sign-in screen, the one on a password grant, the subject of a WS-Security `UsernameToken` or of a WS-Trust `OnBehalfOf`, the client principal in a Kerberos AS-REQ or in an AP-REQ this service accepted (over a raw socket or through SPNEGO), and the subject of an exchanged token. A request that was *refused* records nothing, so this is a list of identities that got somewhere rather than of names that were tried. `?user=<name>` drills into one: the names they were seen under, every authentication with the method that performed it, each sign-on session they hold **with the tokens issued on that session underneath it**, the tokens that belong to no session, and the assertions, tickets and credentials issued to them. A `revoke-user` button invalidates everything revocable for that identity under any of its spellings.

**Two decisions there are worth stating before changing anything.** The first is what *one row* is. A single person reaches this service as `alice` at the login screen, `urn:sts-mock:user:alice` in every token, `alice` as a SAML `NameID` and `alice@EXAMPLE.COM` as a Kerberos principal, so the identity is keyed on the **local name** — the `urn:` prefix stripped (derived from `userFor()` rather than written down again, so a change there cannot silently split every user into two rows) and the realm split off at the last `@`. Four rows for one name would be a worse answer than one on a service whose whole premise is that the name you type is who you are in every protocol at once. What that costs is real and is shown rather than hidden: two different people called `alice` in two Kerberos realms are one row, which is what the Realms column exists to make visible. Case is never collapsed, because nothing else here treats `Alice` and `alice` as one person. The second is that the list is built from **three** sources — the authentications recorded, plus every token's `sub`/`username`, plus every artifact's subject — because an identity can be issued something here without ever having authenticated here: a token exchange presents somebody else's token, a WS-Trust `OnBehalfOf` names a delegated subject, an anonymous RST issues an assertion for `anonymous`, and a Kerberos S4U2Self ticket is for a user who was never near this KDC. Such a row is listed and **marked as never authenticated**, because a users page that showed only the sign-ins would deny the existence of subjects the tokens page is displaying at the same moment. The same honesty runs through the methods column: "sign-in screen (password)" and "AS-REQ with PA-ENC-TIMESTAMP" are both authentications and only one of them checked anything, and an S4U row says the user was not there and names the service that asked in their stead.

**Putting a token under a session needed one thing that is not on the wire, and it is deliberately not a claim.** No token this service issues carries a session identifier — OIDC's `sid` is for front-channel logout, and inventing one for every token to make an admin page easier to draw would change what every client receives. So `signJwt()` takes an optional third argument, a `context` that is signed into nothing and sent nowhere, and the recorder stores its `sessionId` and `grant` on the token record. The link is threaded where it genuinely exists: the session id rides on the authorization code (the only route to a back-channel token request, which arrives with no cookie behind it), the token endpoint passes it on, and a **refresh** looks it up by the refresh token's own `jti` — without which the second generation of every token would show as sessionless and a session's list would quietly stop growing the moment a client refreshed. A grant that never had a session says so: `password`, `client_credentials`, the pre-authorized code and token exchange are shown as issued with no browser session at all, which is a fact about them rather than a gap in the recording. Tokens naming a session this service no longer holds get their own heading, since that is the ordinary end state rather than an error — the session expired and the tokens it produced outlived it.

**A user's page also shows that user's LDAP object, and the dependency that puts it there runs the opposite way from the call.** Every person who authenticates anywhere here already grows an entry at `uid=<name>,ou=users,<base>` (see the directory's own section below), so by the time somebody has a page in this console they usually have a directory object too — and the two are the same authentication seen from two sides, which is the reason for showing them together rather than making a reader find the object again on `/ldap/directory`. What is shown is the entry itself and not a copy: its DN, where it came from (`seed` or `authentication`), its two generalized-time stamps kept in the directory's own punctuation rather than converted to the ISO 8601 the rest of the console uses, and **every attribute with every value, the operational ones included** — a search returns `createTimestamp` and `modifyTimestamp` only when they are asked for by name (RFC 4511 section 4.5.1.8, which `toSearchEntry()` honours), but this is not a search, and a dump that silently dropped two of an entry's attributes would be the one thing a dump must not do. `?format=json` carries the same object under `ldap`.

Where there is no entry the section says **which** of the five reasons it is, because four of them are facts about the user rather than about the directory and "not found" alone would send a reader looking for a bug: auto-creation is switched off, the identity is a *client* and not a person, it has never authenticated here at all (it is known only as the subject of something that was issued), everything it has ever done here is an *LDAP bind* — which presents a DN and not a user name — or the entry was there and has since been `delete`d or `modifyDN`'d through the protocol. It also lists any **other** entry whose `uid` names the same person, since this directory has no schema and does not require a uid to be unique, and it says so loudly when the directory's listener is down: the entry can be in this process's store while no client can connect to read it, and only one of those two facts is visible from an HTTP page. The dependency is the thing to be careful with. `admin.js` does **not** require `ldap_server.js` — `server.js` requires the console first (rule 6: the directory needs `admin_stats`' identity normalisation, and the console reads `oauth2`'s sessions), so a require from the console would drag the directory's routes into the router *ahead* of its own, and `/sts-metadata` is built by walking that router. So the direction is inverted the same way the user observer is: `admin.js` offers `setDirectoryReader()`, `ldap_server.js` fills it at its own require time with a function that takes the identity key the console files a person under — the same normalised local name the entry's DN was built from, so the two cannot drift — and a build of this service without the directory renders the section as "no directory is loaded", which is a different answer from an entry that is not there.

**`/admin/groups`** is the one page in this console that reports the *directory* rather than what this service has issued. It lists every group with what it is made of, and `?group=<dn>` drills into one: every attribute the entry holds, operational ones included, and every member resolved to the entry it names. Both views come out of `groupsFor()` in `ldap_server.js` through a third inverted hook — `admin.js` offers `setGroupReader()` and the directory fills it, for the same route-order reason `setDirectoryReader()` exists — and the console renders what it is handed without deciding anything, which matters most for the first decision below.

**What counts as a group is two rules and not one.** An entry under `ou=groups`, *or* an entry carrying a group `objectClass` (`groupOfNames`, `groupOfUniqueNames`, `posixGroup`, `groupOfURLs`) wherever it sits. Both, because this directory is schemaless and nothing stops a client adding a `groupOfNames` under `ou=users` or an entry with no `objectClass` at all under the groups container — either rule applied alone answers correctly for one of those and quietly loses the other. The list says which rule caught each row, since "this entry is a group because somebody put it under `ou=groups` and it carries no group class at all" is the interesting fact and "developers is a group" is not.

**Membership is read from `member`, `uniqueMember` and `memberUid` together, and the third one is not like the other two**: it holds a bare user name where they hold a DN, so it is resolved under `ou=users` rather than as written. Treating the three alike is how a page ends up reporting every `posixGroup` member as dangling. Three disagreements are then reported rather than smoothed over, and every one of them is a state a client can reach in two operations:

* a **dangling** member — a value naming an entry this directory does not hold. Deleting a user does not remove its DN from the groups that list it, because referential integrity is a directory feature and not a protocol rule (see below), so the count of membership values and the count that resolve are shown as two numbers. One combined number would report a group whose seven members resolve to five as seven members with nothing wrong, which is precisely the thing this page exists to make visible.
* a member that is itself a **group**. Nesting is shown and never expanded: the row links to that group's own page and nobody inside it is counted here, because nothing in this service walks a group tree and a flattened list would be claiming a feature that is not here.
* an entry whose own **`memberOf`** names a group that does not list it back. `memberOf` is not a standard attribute at all — it is Microsoft's and OpenLDAP's, and in the directories that have it the *server* keeps it in step with `member`. This one keeps nothing in step, so a client can write it onto a user in one `modify` and create the disagreement. Those entries are listed under their own heading rather than merged into the members, because which side of the disagreement a name came from is the only interesting thing about it.

**A member links to `/admin/users` only for somebody this service has actually seen authenticate**, and is marked *never here* otherwise. The two lists answer different questions and it is worth being deliberate about the difference: the directory holds an entry for whoever somebody wrote one for — including `alice`, `bob` and `carol`, who are seeded at startup — while the users page holds whoever has presented a credential to this process. A link drawn unconditionally would usually land on "nothing here has authenticated as alice", which reads as a broken link rather than as the answer it is.

**A group here grants nothing**, and both pages say so where a reader will see it rather than leaving it to be discovered. No access token, ID Token, SAML assertion, WS-Federation token or Kerberos PAC carries a group from this directory, and no endpoint checks one; they exist for an LDAP client to read, write and search. On a service that authenticates nobody it could hardly be otherwise — but a console that listed groups a click away from the tokens page without saying it would let somebody conclude that adding a user to `cn=directory-admins` had changed what their token could do.

**`/admin/tokens`** lists what was issued and invalidates what can be. What it lists is **every JWT, every SAML assertion and every Kerberos ticket, in one table, newest first** — the assertions whether WS-Trust issued them or a WS-Federation sign-in did, since both go through the two builders and both are counted there. One table rather than three because a WS-Federation sign-in that produces an ID Token and a SAML 1.1 assertion is *one event*, and three tables would leave it to be reassembled by comparing timestamps. The three families are declared in `admin_stats.js` (`ISSUED_FAMILIES`) and `issuedList()` merges them, because which artifact belongs beside a token and what "still valid" means for each are statements about the state that file holds; `admin.js` renders what it is handed. Two things had to be made common to merge them at all: the state, which comes from one function per family against one clock, and the expiry, which is **normalised to milliseconds** — a JWT's `exp` is seconds and an artifact's `expiresAt` already is not, and one table cannot sort two units. A filter for the family sits beside the one for the kind, and the kind list is grouped by family and built from that same structure, so the two cannot come to disagree about which kind is which.

**Only the JWTs have a button, and the rows that do not are the reason to list them.** Nothing consults this service about a SAML assertion or a Kerberos ticket: an assertion is valid because its signature verifies and its `Conditions` hold, and a ticket because the service it names can decrypt it with a key it already has. So the only thing that ends one is its own expiry — and until it was on this page there was no way to see when that was, or to see that a sign-in had produced one at all. Each such row carries the reason there is no button in place of it, which is the honest version of the button this console deliberately does not offer. Because most columns then mean something slightly different depending on the row — `Detail` is a scope, or whether the signature was written, or the enc-type — the page carries **a legend saying which**, and the code is written one function per *column* answering for all three families rather than one per family, so a header like "Client, audience or service" can be checked against the three answers underneath it. Two of those answers are worth stating: a Kerberos ticket has **no identifier at all** to put in the `jti` column, because none exists for anyone to quote and the KDC keeps no handle on one either; and an assertion's `Detail` says signed or unsigned, which meant correcting the record in the two builders' `catch` blocks — the assertion is counted *before* the signing attempt on purpose, so an assertion that went out unsigned was being counted as signed, and a column showing that would have agreed with the page rather than with what left. **OID4VCI credentials are not in the table**, only counted on the metrics page; that is a gap rather than a principle, and the page says so rather than letting "everything this service has issued" be read as four families.

Invalidation is one `jti`, a whole kind, everything for one subject, or everything. **It is the same revocation `/oauth2/revoke` performs** — there is one set of revoked jtis in this service, not one per page. That mattered enough to move the set out of `oauth2.js`, where it was written, and into `admin_stats.js`: two sets would each look correct alone and never see each other, so a token revoked from the console would keep introspecting as active with no error message anywhere to point at. It is the same failure the single session store exists to prevent. A token revoked here is therefore reported inactive by introspection, refused by UserInfo with `invalid_token`, and fails the refresh grant with `invalid_grant`, immediately and without a restart.

The list is **filtered by family, kind and state and then paged**, newest first, with `?page=` and `?per=` — and in that order, because paging a list and *then* filtering it gives a page 2 whose length depends on what happened to be on page 1. Paging replaced a flat cap of 300 rows that showed the most recent matches and said underneath how many it had hidden; the cap survives as the ceiling on *one* page, since `?per=` is a number a caller types and without a ceiling `?per=5000` is exactly the page the cap existed to prevent. Everything held is now reachable rather than only the newest 300. Three properties are what make that safe to click through. An **out-of-range page is clamped to the last one** rather than answered with an empty table — a revocation sweep can shorten the list between two clicks, and an empty table reads as "nothing matched" when it means "that page has gone". The **filter form carries no page number**, so changing a filter or the page size returns to page 1 instead of landing on page 6 of a two-page result. And every button on the page acts on a **`jti` and never on a row number**, so a token issued or revoked between the render and the click cannot make the wrong token the target; the most it can do is shift a row onto another page. A revoke or restore button **returns to the page and filter it was clicked on** rather than to the top of an unfiltered list, which the row forms arrange by carrying the view as a hidden `back` field — and the redirect target is *rebuilt* from that field rather than echoed, because a redirect taken from a request body is an open redirect and one carrying a newline is a header injection. Only `family`, `kind`, `state`, `per` and `page` survive the rebuild, each re-encoded, so the worst a hand-written `back` can reach is another page of the same table — and that list has to be kept in step with the filter form, because a parameter the form offers and the rebuild drops is a filter that silently resets itself the moment somebody revokes a token, which looks like the console losing your place rather than like a missing line. The bulk buttons keep the filter and drop the page, since after "revoke everything" page 7 is a page of a different list. Both parameters work with `?format=json`, whose reply carries `page`, `pages` and `matched` so a test can walk the whole list without guessing where it ends, and whose rows are in **`issued`** — each naming its `family`, and called `issued` rather than `tokens` since the day the array stopped being only tokens. Paging is links and a query parameter with no script behind it, because `script-src 'none'` is what makes the whole family of reflected-content problems moot here and the console does not get an exception.

Three further details of that page are worth knowing before changing it. It keeps **the claims and never the credential** — not the signed token, not the assertion XML, not the ticket — because a page rendering a thousand live credentials in a form a browser will display is a page that leaks them, and the `jti` is all any button needs. Pasting a whole token works and **its signature is not verified**, which is safe rather than sloppy: the only thing read out of it is the `jti`, which is then looked up in this service's own registry, and a forged token yields a jti this service never issued — revoking one of those invalidates nothing. RFC 7009's endpoint *does* verify, because there the token is the credential being presented. And **Restore is offered and is labelled NON-SPEC**: no authorization server can undo a revocation, since a resource server may already have cached the refusal, but without it getting back to a working token means restarting the service and losing the signing key with it.

**`/admin/claims`** decides what every *future* access token, ID Token, SAML 2.0 assertion and SAML 1.1 assertion carries. Four sets rather than one, because the four are genuinely different vocabularies: an access token and an ID Token go to different readers (a resource server and a client), and SAML 1.1 splits the claim URI into an `AttributeNamespace` and an `AttributeName` where SAML 2.0 has one `Name`. They are **additive** — a configured claim is added to what the protocol already puts in the artifact and never replaces one — and the names this service sets itself are **refused at configuration time** rather than silently dropped at issuance, because every one of them is load-bearing: an `exp` settable from a web form would produce tokens that fail to verify with nothing anywhere pointing back at the page, and a settable `scope` would quietly change what UserInfo answers. The same rule protects the SAML side for a different reason: a WS-Federation relying party keys off the claim URIs `claimsFor()` writes, so a custom attribute that displaced one would break a sign-in somewhere that looks nothing like this console.

Values may contain `${username}`-style placeholders, because a claim that can only be a constant cannot exercise the thing worth testing — that a claim carrying the signed-in user's identity reaches the relying party. **An unknown placeholder is left exactly as written** rather than replaced with the empty string: a `${dept}` that silently became `""` is a bug that looks like a configuration mistake, and one that still says `${dept}` names itself. A JWT claim value is typed when it unambiguously looks like JSON (an object, an array, a bare `true`/`false`/`null`, a number) and is a string otherwise, which has one consequence the page states rather than leaving to be discovered: a claim whose value is genuinely the four characters `true` cannot be configured, and `"true"` is the escape. SAML attribute values are never typed — the XML content model is text.

**`/admin/vc`** decides what every *future* Verifiable Credential carries, and it is the page here whose list is of **LDAP attribute types rather than of claim names**. That is the decision the rest of it follows from. Until this page existed the answer was seven lines in `vc_issuer.js` — `given_name`, `family_name`, `email`, a constant birthdate, a constant nationality and a constant address — which is enough to demonstrate one credential and not enough to exercise a wallet: what a holder actually wants to know is what their UI does with fourteen claims, what their verifier does with one it has never seen, and whether the issuer metadata really describes what arrives. None of those can be asked without changing the claim list. The catalogue is of attribute types because this service *has* a directory, so a claim can have a value something other than the credential can see: `mail` on `uid=alice,ou=users` is what a wallet is handed as `email`, and an LDAP client and an OID4VCI wallet pointed at this one process are shown the same person. Ten rows are selected on a fresh start, which is exactly the six claims the issuer carried before the page existed — `address` is five of them, one per component, because the OIDC address claim has five members and a directory has an attribute type for each. Three rows are not RFC 4519/4524/2798 and the page says so: there is no standard attribute type for a birthdate or a nationality, so the SCHAC schema's names are borrowed rather than invented, and the page shows every row's defining document so the borrowed ones are distinguishable at a glance.


**`/admin/vc-verifier-config`** is the other end of that page, and the two are deliberately separate settings. `/admin/vc` decides what an issued credential *carries*; this decides what the mock Verifier at `/oid4vp/verifier` — the pages call it *The Bar Door* — **asks for**, which reaches the wire as the `dcql_query` of the next OID4VP Authorization Request and then decides what the presentation is checked against. Keeping them apart is what makes the interesting state reachable: a Verifier asking for a claim the issuer is not minting is the negative that exercises a wallet's "I cannot satisfy this request" path, and one page setting both would make it impossible to produce. The same page chooses which of the three **credential formats** an unqualified request asks for, since a presentation cannot convert between them — a wallet holding a `jwt_vc_json` credential has nothing to answer a `dc+sd-jwt` query with, and the honest outcome is that it says so.

**Its table is of claims where `/admin/vc`'s is of attribute types, and the grouping is forced by the credential rather than chosen for tidiness.** `buildSdJwtVc()` makes one Disclosure per *top-level* claim, so `address` is one unit of disclosure however many LDAP attributes feed it: a holder cannot present the locality without the street, and a page offering six address checkboxes would be offering a choice that does not exist on the wire. So the catalogue is `vc_claims.js`'s rows grouped by claim — every row still names the attribute types behind it and their defining document, because "this is `l`, RFC 4519 2.16" is what connects the request to the directory entry the value will come from — and an *Issued now* column reports what the issuer is currently configured to mint, so that a presentation which disclosed nothing is not investigated as a wallet bug.

**Three of its behaviours are deliberate and each is the answer to a question a mock exists to let somebody ask.** A claim that is **not in the catalogue** can be asked for from a text box, and is the only way to reach "the wallet cannot satisfy this request" — nothing here issues it, so the presentation fails this Verifier's own *Requested claims* check with the name in it. Asking for **nothing at all** is a setting rather than an empty form: DCQL reads an absent `claims` member as the whole credential, so the query is built without one and the page says, in as many words, that it is now asking for everything. And the **DCQL path differs by format**, which the table shows rather than implies — `["given_name"]` for `dc+sd-jwt`, `["credentialSubject","given_name"]` for `jwt_vc_json`, and for `ldp_vc` the term the vendored JSON-LD context defines, which is `birthDate` and not `birthdate`, and which for `address` is four flat terms and not one. That last was quietly wrong before this page existed: both W3C formats were given the OIDC claim name, which coincides for `given_name` and `family_name` — the only two claims the Verifier could then ask for — and for nothing else. A claim the context defines no term for is **dropped from an `ldp_vc` query and named on the page**, because asking under a name that context does not define fails canonicalization rather than returning less.

**What a request asks for is frozen onto it, not read again when the answer arrives.** The list is editable while a presentation is in flight, and a Verifier that judged what came back against a list changed after it asked would refuse a wallet for correctly answering the question it was really asked. So `buildVpRequest()` stores the claims on the transaction and every check reads them from there — which is also what makes the verdict at `/oid4vp/result/:state` a true record of that exchange rather than of the console's current state.

**And this page admits nobody.** A presentation that verifies here starts no session, issues no token and grants no access; the door says yes and that is the whole of it. It is the same disclaimer the groups page and the TLS report carry, for the same reason — a console page a click away from the tokens page would otherwise let somebody conclude that a verified credential had become an identity somewhere in this service.
**The metadata is built from the same list the credential is**, which is the reason not to keep the claim set anywhere else. An issuer whose `credential_configurations_supported` advertises five claims while its credentials carry fourteen is teaching every wallet developer who reads it that the metadata is not worth reading, and OID4VCI's whole discovery story rests on it being worth reading. So `vciMetadata()` derives its `claims` arrays from `vc_claims.js` and `subjectClaimsFrom()` derives the credential from the same place, and drift between them is not a state this service can reach. **`ldp_vc` carries a subset, and that is the format's doing rather than a choice**: it is signed over canonicalized JSON-LD, `bbs2023.js` canonicalizes with `safe: true`, and a term the vendored context does not define does not go missing quietly — it *throws*, inside a cryptosuite, at the moment a wallet asks for a credential. So each catalogue row names the JSON-LD term to use in that format or says it has none, `buildLdpVc()` filters what it is given through the context this process actually loaded (a hand-kept list agreeing with a vendored file is a drift waiting to happen, and this is the one where it would surface as a crypto bug), and both the page and `/sts-metadata` name the selected attributes that format leaves out. The context is vendored precisely because editing it would invalidate every credential already issued against it, so "add a term" is not the fix it looks like.

**A claim's value has three sources and the order between them is the whole policy.** The **access token** first, where it carries a claim of that name — that is a statement this service has already made about the person, from the sign-in or from `/admin/claims`, and a credential contradicting the token that authorised it would be indefensible. Then **the directory entry**, which is where the generated values live once an entry exists and is also where an `ldapmodify` lands: change `mail` on `uid=alice,ou=users` and the next credential says so. Then **a generated persona**, for a person with no entry, an entry without that attribute, or a directory that is not running. Nothing is ever left out because a source was missing, since a claim that silently did not arrive is indistinguishable at the wallet from a selection that never took effect.

**The generated values are garbage on purpose and deterministic on purpose**, and the second half is the one worth explaining. This service authenticates nobody, so there is no source of a real birthdate here and there had better not be; the invented street names say `Placeholder`, the mailboxes are in the RFC 2606 example domains and the telephone numbers are in the `555-01xx` fiction range, so no invented value can be mistaken for or collide with a real one. They are seeded from the username rather than drawn fresh because the alternative costs more than it looks: a random birthdate per call means the credential issued at 10:00 and the one issued at 10:01 describe two different people, the directory entry disagrees with both, and a wallet's "did this change" check fires on something that is not the thing being tested. One username is therefore one invented person for the life of the process *and across restarts* — and one **whole** person rather than a field at a time, because a `given_name` of "Ingrid" beside an email of `kwame.osei@…` is two facts that contradict each other and a reader who notices spends ten minutes deciding whether it is a bug here. The seed is the **normalised** local name, which is load-bearing rather than tidy: `alice`, `urn:sts-mock:user:alice` and `alice@EXAMPLE.COM` reach this module from three directions, and seeding on the raw string invented three different people and then failed to find the entry any of them had — a credential whose name its own directory entry contradicted, which looks like the directory not being read at all.

**Saving a selection writes to the directory**, and that is the point of the page rather than a side effect of it. Every person under `ou=users` gains the selected attributes they are missing, invented from their username; without it, ticking `title` would change every future credential and change nothing an LDAP client could see, and the two halves of this service would quietly stop describing the same people. Three rules hold that sweep up. It **never overwrites** — an attribute already on an entry is left exactly as it is, which is why the three seeded people keep their own names and gain only what they had nothing for, and why an operator's `ldapmodify` is not undone by the next sweep. It writes **one value**, not an appended one, so an entry cannot accumulate a birthdate per sign-in. And what it walks is **entries under `ou=users`**, the container excepted — deliberately not "everything with a person `objectClass`", because this directory is schemaless, a client can add anything anywhere, and inventing a nationality for `cn=developers,ou=groups` because somebody gave it a `person` class would be a sweep doing damage where nobody asked it to look. The same fill runs when an entry is created and when a returning person authenticates, so somebody whose entry predates a selection change is covered without waiting for the button. It runs once at startup too, so the seeded three are not asserting values in credentials that their own entries lack from the first request.

**Auto-created entries now get an invented name as well**, where they used to get the login name three times over — `cn: dave`, `givenName: dave`, `mail: dave@sts-mock.example`. Those are attributes a credential asserts, so a directory deriving all of them from the login name made every credential say the login name back, and `given_name: "dave"` is not a given name to test a wallet's rendering against. What the entry keeps from the login name is the two things that *are* the identity, the DN and the `uid` — which is also how a real directory looks, since somebody's uid rarely is their name. The `displayName` keeps its `(mock)` marker: every value on the entry is invented and the field a person reads first should say so.

**A credential claim grants nothing and nothing reads one back.** No access token, ID Token, SAML assertion or Kerberos PAC carries a claim from this page, and no endpoint makes a decision on one — it reaches a credential and stops there. The page says so, for the reason the groups page says the same thing about membership.

**The recording had to invert one dependency, and that is the only clever thing here.** Every JWT this service issues is minted by `signJwt()` in `helpers.js`, which is what makes the count a count rather than an estimate — but `admin_stats.js` requires `helpers.js` (it needs the log), so `helpers.js` cannot require it back. So the leaf offers a slot (`setJwtRecorder`) and `admin_stats.js` installs itself in it at its own require time. What makes that safe rather than fragile is *who requires `admin_stats.js`*: **`app.js` does**, which is not a trick to fix the ordering but a real dependency, since the call log lives there — and every protocol module requires `app.js`, so the recorder is installed before any route exists and therefore before any token can be minted. The recorder's return value is ignored and a throw inside it is caught and logged, because statistics must never be able to stop a token being issued. Everything that is not a JWT is recorded by an ordinary require in the other direction: the two assertion builders, `buildCredentialFor()` where all three credential formats meet, and the two points in `krb5_kdc.js` where a ticket is minted — Kerberos being the one family whose artifacts pass through neither `signJwt()` nor an assertion builder.

Everything the console holds is **in memory and dies with the process**, like the signing key. There is nothing here worth persisting, and a statistics file that outlived the key that signed the tokens it described would be actively misleading. The registries are **bounded** — the most recent 5,000 tokens and 5,000 other artifacts, 500 call paths, and 2,000 identities keeping their 50 most recent authentications each (capped per user rather than in total, because a test loop signing one name in a thousand times is the normal case here) — and what was dropped is counted and shown, because a silent truncation turns "12 tokens issued" into a number that quietly means something else. The revoked-jti set is deliberately *not* capped and is kept separately from the token records, so a token whose record has aged out stays revoked.

**The console is not protected, and every page says so.** This service checks no password anywhere; a console with a credential on it would be the only authenticated surface in a service whose premise is that it authenticates nobody, and the only thing a test had to hold a secret for. What follows is worth stating rather than implying: anyone who can reach this port can revoke every token this service has issued and add a claim to every token it issues next — which is the same thing that was already true of `/oauth2/token`, since it will mint a token for any username asked of it. Do not put this service on a public address.

Three things the console deliberately does **not** do. It does not invalidate a SAML assertion, a Kerberos ticket or a credential: none of those has a revocation mechanism a relying party consults — an assertion is valid because its signature verifies and its `Conditions` hold, and nothing about this service is asked — so a button claiming to revoke one would change a number here and nothing at all out there. It does not end a sign-on session, because `/oauth2/logout` and `wsignout1.0` already do and the second has cleanup to fan out to every relying party the session signed into; a third way to end one would be a third way to get that wrong. And it adds no claims to refresh tokens: a refresh token is presented back to this server and to nothing else, so a claim in one reaches no relying party and would only make the two halves of a grant disagree.

### The management API

`GET /admin-api` is the console above with the HTML taken off: every page's `?format=json` view and every one of its forms, at a path a script can use, with an OpenAPI 3.1 document at `/admin-api/openapi.json` and an explorer that calls it at `/admin-api/docs`. Thirty-two operations, none of them protected, all of them changing the same state the console changes — because they call the same functions it does.

**It exists because a form is the right shape for a person and the wrong one for anything else.** Every page here has answered `?format=json` since it was written, so reading was never the problem; *changing* something was. A caller that wanted to revoke a token from a script, or narrow the issuer's claim set from a CI job before running a wallet against it, was left either parsing a 303 redirect for the message in its query string or knowing which hidden input a particular form carried. Both are ways of driving a browser without one.

**The rule the API is written under is about the future rather than about the code**: a control added to `/admin` gets an operation on `/admin-api` in the same commit. An API that covers eight of nine controls is worse than one that covers none, because the ninth is discovered by somebody who has already written the code that assumed it was there. Two things make keeping that rule cheap, and the third thing is why there is a test for it in the parent project.

The first is that **this API decides nothing**. Every POST calls the same action function the console's form posts to — `tokenAction`, `claimsAction`, `vcAction`, `vpConfigAction` — with the action taken from the URL instead of from a hidden field, and every GET calls the same JSON view the page's `?format=json` answers. Those views became functions in `admin.js` for this reason (`consoleJson`, `metricsJson`, `tokensView`, `usersView`, `groupsView`, `claimsJson`, `vcJson`, `vpConfigJson`); they had been built inline in the route handlers, which was fine while there was one caller and is exactly the shape that produces two objects that agree today and not next month. So `admin_api.js` holds no opinion about what a revocation means that `admin.js` does not, and the way to see that is not to read the code: revoke a token through the API and RFC 7662 introspection calls it inactive, because there is one set of revoked jtis in this service and it is the same one `/oauth2/revoke` writes to.

The second is that **the OpenAPI document is generated from the table that registers the routes**. `admin_api.js` holds one row per resource — the handler, the parameters, the request bodies with their examples, the prose — and `admin_api_spec.js` turns that into the document. An operation therefore cannot exist and be undocumented, nor be documented and not exist. A specification file kept beside the code it describes is wrong within a month, and the way it goes wrong is silent: somebody adds an action to the console, adds it to the API, and does not touch the YAML.

The third is the direction neither of those can check. **Nothing in this service can see a form appear on a page**, so a new console control with no operation here would go unnoticed by everything above. That is asserted from outside, by the parent project's `tests/admin_api.js`, and it reads the facts off this service rather than off a list in the test: the console's own page list comes back in `GET /admin-api/status`, and each action handler, asked to perform an action that does not exist, replies with the names of the ones that do — "Unknown action "x". The four are: add, remove, clear, replace." Add an action to a switch and that sentence grows; the test then fails until there is an operation for it. The same test checks every property the document describes against a live reply, which has already caught two names that were wrong and unnoticeable: an `expiresAt` that is really `expiresAtMs`, and a group drill-down documented with its members at the top level when they are inside `group`.

**Four POST routes serve twenty-four URLs**, and the shape is deliberate. Express registers `/admin-api/tokens/:action` once; the document lists `/admin-api/tokens/revoke`, `/restore`, `/revoke-kind`, `/revoke-subject`, `/revoke-user` and `/revoke-all` as the six operations they are, each with its own body schema and its own example. One pattern keeps `GET /sts-metadata` to one row per resource showing the parameter — the router is what that page reads, and twenty-four rows of near-identical prose there would bury the rest of the service — while the document describes URLs a caller can actually use. An action nobody has heard of is not a 404: it reaches the console's own handler and comes back as its refusal, naming the ones that exist, which is both the friendliest error and the sentence the parity check reads.

**The explorer at `/admin-api/docs` is the only page in this service with a script on it**, and that is the one thing this feature costs. `app.js` sets `script-src 'none'` service-wide, which is what makes the whole family of reflected-content problems moot here rather than merely unlikely, so the explorer relaxes that header on its own two routes and in exactly two clauses: `script-src 'self'`, and an added `connect-src 'self'` so the page can call the API it documents. `default-src 'none'` and everything else stay as they are, and the console next door is still `script-src 'none'` — which the test asserts, because a middleware change that widened the exception would show up there first. The script is a **separate resource rather than an inline block for precisely that reason**: `'self'` is enough for a file, an inline block would have needed `'unsafe-inline'`, and `'unsafe-inline'` is the clause that would make the relaxation matter.

**It is this repository's own explorer rather than Swagger UI**, which was weighed rather than skipped. `swagger-ui-dist` is 11.7 MB unpacked and pulls in an install-time telemetry package, in a service whose `package.json` is deliberately short and whose image is built in containers that may have no network beyond the registry. What it would have bought is a familiar look, for an API with no authentication, no OAuth flows, no polymorphic bodies and nobody generating a client from it. `admin_api_explorer.js` is about 250 lines with no dependency and does the same three things — read the document, fill a form, show the response — plus the equivalent `curl` line beside each operation, which is what an operator of a mock actually copies. It is also the one file in this repository that is **not a node module**: `admin_api_docs.js` reads it off disk and serves it verbatim, so it has no `require`, no `process`, and builds every node with `createElement` rather than assigning `innerHTML` — it renders response bodies, which are not always this service's own.

**Nothing here is protected, for the same reason nothing else is.** This service checks no password anywhere — the username typed at the sign-in screen becomes the identity in every token it issues — so an authenticated management API would be the only authenticated surface in a service whose premise is that it authenticates nobody, and the only one a test would have to hold a secret for. What follows is worth stating rather than implying: anyone who can reach this port can revoke every token this service has issued and change what the next one contains. That was already true of `/oauth2/token`, which will mint a token for any username asked of it. Do not put this service on a public address.

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

**Requiring the module does not start the listener.** Every other module here registers
its endpoints at require time, and for a route that is harmless; binding a privileged
port is not, because it can fail and a require that throws takes the whole service down.
So `server.js` calls an exported `listen()` and reports its failure, and the service
still starts without a directory rather than not starting at all. A failure to bind is
also **published** — `listening` and `listenError` on `GET /ldap` — because that page is
HTTP and answers 200 either way, so without those fields there is no way to tell a
running directory from one whose listener lost a race with the host's own `slapd`.

**`GET /sts-metadata` cannot see a raw socket**, and there are two of them here. The two
LDAP rows it does carry, `/ldap`
and `/ldap/directory`, are this service describing its own store; neither is LDAP. The
second is the more useful of the two: it lists every entry with **where it came from** —
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
curl -s http://localhost:8081/tls/server-certificate > /tmp/sts.pem
LDAPTLS_CACERT=/tmp/sts.pem ldapsearch -H ldaps://localhost:636 -x \
  -D "cn=admin,dc=example,dc=com" -w 'password!' \
  -b "dc=example,dc=com" "(objectClass=*)"
```

`LDAPTLS_REQCERT=never` is the habit that endpoint exists to avoid, and here it would also
hide the one thing on this listener worth checking.

**No client certificate is ever asked for on 636.** This listener proves the *server* to
the client and nothing more; a certificate offered to it is not requested and would not be
a login if it were. The HTTPS listeners next door are where client certificates are the
whole subject — and even there, a verified one is explicitly not a login. `GET /ldap` says
this rather than leaving somebody to work out why the certificate they configured was
never sent.

**It changes the require order, and `server.js` says so out loud.** `ldap_server.js` now
requires `tls_server.js` — for the certificate, nothing else — so node loads that module
first whatever `server.js` says. Since **the require order in `server.js` is the route
order**, the line there was moved to match: `./tls_server` before `./ldap_server`. It
changes no output, because `/sts-metadata` sorts its rows by path within a group; it keeps
that file honest for the next reader.

Finally, the two listeners are **published separately** on `GET /ldap` — `listening` /
`listenError` for 389, and a `tls` object carrying `ldaps`, `port`, `listening` and `error`
for 636 — because that page is HTTP and answers 200 whichever of them is up. "389 is up and
636 is not" is the ordinary outcome of a host run, and a single flag could only report one
of them. The admin console's user page reads the same fields and warns in three cases
rather than two, for the same reason: telling somebody no client can connect while LDAPS is
answering costs them an afternoon.

#### What it enforces, and the one thing it deliberately does not

It is **schemaless on purpose** — no objectClass is enforced, no attribute is checked
against a syntax, no `must`/`may` is consulted — and `GET /ldap` says so rather than
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
AS-REQ, a WebAuthn assertion.

That is **one hook and not twelve**, because `admin_stats.recordAuthentication()` is
already the single funnel every one of those call sites goes through at the moment a
credential is ACCEPTED. The hook is **inverted**, exactly as `helpers.js`'s
`setJwtRecorder` is: `ldap_server.js` requires `admin_stats.js` — it needs `identityOf`'s
normalisation, so that `alice`, `urn:sts-mock:user:alice` and `alice@REALM` seed one entry
and not three — so `admin_stats.js` cannot require it back without a cycle. It offers a
slot instead, and `ldap_server.js` fills it at require time. The observer's return value is
ignored and a throw from it is caught: a directory must never be able to fail an
authentication.

The admin console shows each user their entry, on `/admin/users?user=<name>`, and reads it
through a **second inverted hook** — `admin.setDirectoryReader()`, filled by this module at
require time — for a reason that is about route order rather than about cycles. See the
`/admin/users` section above.

Two identities are skipped, and both are deliberate. **An LDAP bind** does not seed one,
because the identity a bind presents is a DN — it already names an object in this very
directory, so `uid=cn=admin\,dc=example…` would be nonsense and this service's own binds
would grow the directory without bound. **An OAuth client** does not either: a client is
not a person and `ou=users` is for people, a distinction the admin console already makes
with its `isClient` flag, which is what this reads.

**And one identity is not a name at all: a verified TLS client certificate.** Its
subject is already a DN, so the entry is not `uid=<name>` and is placed by
`certificatePlan()` instead — at the subject itself where that lies under this
directory's base, and otherwise under `ou=users` named by the CN, with the subject's
other RDNs kept as attributes and the certificate's own facts written on as `x509*`
attributes that are this service's names rather than schema. The TLS section above
carries the reasoning, including what the placement costs and why `userCertificate` is
not one of those attributes. The `x509subject` value is also how the admin console
finds the entry again: an identity that is a DN is looked up by the subject the entry
recorded rather than by a name, which is exact and stays right if the naming rule ever
changes.

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

### TLS and mutual TLS — the other side of a handshake

`tls_server.js` puts up **two HTTPS listeners of its own**, and their entire content
is what the *server* saw. Fetch `GET /tls/whoami` over either one and the reply
describes the very connection it is travelling on: the HTTPS request as it arrived
(method, path, every header, where from), what TLS negotiated underneath it (version,
cipher, SNI, ALPN, session reuse, the server certificate), and the client
certificate — presented or not, verified or not, with the whole chain the client
sent, leaf first. `GET /tls` describes the endpoint over plain HTTP, and both pages
take `?format=json`.

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
`POST /tls/trust/clear` puts it back.

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
* **The server certificate is self-signed and regenerated on every start**, like the
  signing key, and for the same reason — a certificate committed to a repository is a
  private key committed to a repository. `GET /tls/server-certificate` hands out the
  PEM (`Cache-Control: no-store`, since a cached copy outlives the key it describes)
  so a caller can put it in its own truststore rather than switching verification off,
  which is the habit this whole workflow exists to break.
* **It is served on three sockets, not two.** The directory's LDAPS listener on 636
  presents this same certificate and key, read from this module rather than generated
  again — so one fetch is one anchor for 8443, 9443 *and* `ldaps://`. Two keypairs
  would have made an `ldapsearch` fail against a truststore built for the HTTPS ports
  with `unable to get local issuer certificate`, which names nothing. The private key
  crosses a module boundary to do it and does not cross a network one: it is generated
  per start, lives in memory, dies with the process, and nothing writes it to a
  response — `GET /tls/server-certificate` publishes the certificate alone.

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
