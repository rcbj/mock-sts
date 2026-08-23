# Mock STS

A deliberately permissive **mock identity service** that speaks sixteen protocol
families — four of which, Kerberos, LDAP, TLS and SPIFFE, are not HTTP over its own
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

## Where the code is

Since 2026-08-23 the modules live in directories by protocol family rather than in
the package root. **The files did not change; the paths did.**

| Directory | |
|---|---|
| `common/` | config, helpers, the express app, the counters, the audit log, the application registry, the claim catalogues |
| `common/vendored/` | byte-identical copies of the parent project's PKI and JSON-LD modules, plus the `contexts/` they read. **Do not edit them here.** |
| `oauth-oidc/` | the authorization server, RFC 9700 mode, DPoP, mTLS, client authentication, the multi-AS profiles |
| `authn/` | the sign-in screen and the WebAuthn relying party. Owns the session |
| `saml/` | the two assertion builders |
| `ws-trust/` · `ws-federation/` | the two WS-\* profiles |
| `kerberos/` | the KDC, the acceptor, SPNEGO, and the codec |
| `ldap/` · `scim/` · `tls/` · `spiffe/` · `oid4vc/` | one family each |
| `admin-ui/` · `mgmt-api/` | the console and the management API |
| `docs/` | the user-facing documentation, published as a GitHub Pages site |

At the package root there are exactly two modules: **`server.js`**, the shell that
requires the others and listens, and **`sts_metadata.js`**, which reads the router
to list what everything else registered and is therefore required last.

Every directory carries a `CLAUDE.md` with the reasoning for the modules in it —
that is where the engineering notes below have been distributed to. `CLAUDE.md` at
the root keeps only what is cross-cutting: the require order, the library and hook
rules, the two CSP rules, the code style and the state of the tests.

**One consequence for the parent project**, which reaches in here by flat path in
its `tests/Dockerfile` and `tests/module_paths.js`: those paths are now wrong.
Nothing over there was changed, because its `sts/` gitlink is pinned before any of
this; what the pin bump needs is written down in
[`docs/parent-project-migration.md`](docs/parent-project-migration.md).

## What it speaks

| | |
|---|---|
| **Kerberos v5 (RFC 4120)** | a KDC, on **raw TCP and UDP port 88** and over MS-KKDCP: the AS and TGS exchanges, pre-authentication carrying the salt in PA-ETYPE-INFO2, a signed [MS-PAC] in every ticket, two realms with a trust between them so cross-realm referrals work, and delegation all four ways ([MS-SFU] S4U2Self, S4U2Proxy under either authorization, forwarded tickets, renewals) — plus a **service** that decrypts an RFC 4121 GSS token, checks the ticket eight ways and proves itself back |
| **SPNEGO (RFC 4178) over HTTP (RFC 4559)** | a **protected web page**: `/spnego` advertises it — the SPN, the realm, the mechanisms, the hosts it will answer for (`acceptsAnySpnForHosts`) and three knobs that break the negotiation one way each — and the 401 itself carries `X-Krb5-Service-Principal` and `X-Krb5-Accepts-Spn-Hosts`, which are nobody's standard and exist because SPNEGO carries no SPN at all: a client has to guess `HTTP/<url host>`, and that guess being wrong is the commonest SPNEGO failure there is — and `/spnego/protected` answers `401 WWW-Authenticate: Negotiate` to an unauthenticated request and `200` with an AP-REP in that header to a valid one. NegTokenInit with the optimistic mechToken, NegTokenResp in all four negStates, and the mechListMIC in both directions with section 5's rule for when it is mandatory. Only Kerberos is offered: NTLM is recognised in a client's list and never selected, because advertising a mechanism this service cannot perform would be a lie a client would act on. **Every Kerberos check is the protected service's, unchanged** — this is a transport and a negotiation, and no protocol code of its own |
| **WS-Trust 1.0–1.4** | Issue / Renew / Validate / Cancel, WS-Security, WS-Addressing, optional XML-DSIG and XML-Enc |
| **SAML 2.0 and SAML 1.1** | signed assertions of both vintages, and the metadata a relying party needs. 1.1 is here because it is what a WS-Federation relying party expects by default |
| **WS-Federation 1.2** | the Web (Passive) Requestor Profile of section 13 — `wsignin1.0` with `wtrealm`, `wreply`, `wctx`, `wct`, `wfresh`, `wauth`, `whr` and `wreq`, the response as a **form POST**, `wsignout1.0` with front-channel cleanup, signed federation metadata at AD FS's path, and a mock relying party that verifies the response check by check |
| **OAuth 2.0** | a full authorization server: RFC 8414 metadata plus every endpoint it advertises — authorize (which redirects to the authentication service when nobody is signed in), token, userinfo, introspect, revoke, register (RFC 7591, and the RFC 7592 read/update/delete operations), jwks. PKCE (RFC 7636), Rich Authorization Requests (RFC 9396), the `iss` authorization response parameter (RFC 9207), and every one of the seven grant types its metadata advertises — including **Token Exchange (RFC 8693)**. It is permissive by design, and it can be told not to be: `oauth2.rfc9700` puts the authorization flow into **RFC 9700** mode — exact-string redirect URI matching with RFC 8252's loopback port exception, no open redirector at either redirecting endpoint, PKCE required of public clients with S256 only, the PKCE downgrade and value reuse refused, and no response type that issues an access token from the authorization endpoint, refresh token rotation with replay detection that revokes the whole chain, no password grant, no CORS at the authorization endpoint, and the one client credential this service checks — and it turns port 8081 itself into an **HTTPS** listener, on the certificate 8443, 9443 and LDAPS 636 already share, so the issuer and every endpoint in every metadata document follow. Off by default; `GET /oauth2/rfc9700` says what it does and does not enforce |
| **OpenID Connect 1.0** | `id_token` with `nonce`, `at_hash` and `c_hash` across all three flows, the section 5.3 UserInfo endpoint, **Discovery 1.0** at all three URLs a client may look at, and RP-Initiated Logout |
| **WebAuthn Level 3** | the relying party's half, on the login screen, in **both roles**: a second factor after the password, or the **primary credential** with no password at all. Registration and assertion are verified either way, and `amr` / `acr` in the tokens that follow say which happened — `["pwd","hwk"]`/`mfa` for two factors, `["hwk"]`/`1` for a passwordless sign-in, which is one factor however phishing-resistant it is |
| **DPoP (RFC 9449)** | all twelve section 4.3 proof checks, `cnf.jkt` on access *and* refresh tokens, `dpop_jkt`, replay detection, the nonce handshake |
| **mTLS client authentication (RFC 8705 §2)** | `tls_client_auth` matches the client certificate's subject DN and `self_signed_tls_client_auth` its thumbprint, beside `private_key_jwt` and `client_secret_jwt` — all six token-endpoint authentication methods are genuinely verified, and the metadata advertises only what the verifier can check |
| **mTLS-bound tokens (RFC 8705)** | the *other* sender constraint RFC 9700 names: with `global.https` on, the main listener asks for a client certificate and a Token Request made with one is answered with `cnf["x5t#S256"]` — the SHA-256 of its DER — on the access **and** refresh tokens, which the four protected endpoints then check against the certificate the connection was made with. Advertised only where it can actually be done. Section 2's mutual-TLS *client authentication* is deliberately not implemented |
| **Resource Indicators (RFC 8707)** | `resource` at the authorization and token endpoints becomes the access token's `aud`, so a token can be restricted to one resource server or a small set of them — and the resource server here refuses one issued for a different audience |
| **OpenID4VCI 1.0** | a Credential Issuer: SD-JWT VC (RFC 9901), `jwt_vc_json`, `ldp_vc` with bbs-2023; Credential Offers, the pre-authorized code grant with `tx_code`, `authorization_details` (including its `claims` member, so a wallet can ask for a subset of the claims), batch issuance, response encryption, deferred issuance, the Notification Endpoint |
| **OpenID4VP 1.0** | a Verifier with DCQL that **actually verifies** what it is sent, check by check |
| **W3C DID Core 1.0** | its own `did:web` document, and the DIF Well Known DID Configuration that links it to its origin |
| **TLS / mutual TLS (RFC 8446)** | two **HTTPS listeners of its own** — 8443 asks for a client certificate and never refuses one, 9443 *requires* it — whose entire content is what the **server** saw: the request as it arrived, what TLS negotiated underneath it, and the client certificate exactly as presented, chain and all. It is the half of a handshake a client cannot report. It already knows what it sent; what it cannot know is which chain the server built out of that, which anchor it verified against, or whether the certificate was accepted at all — which, under TLS 1.3, it has not learned by the time its own handshake completes. The client truststore starts **empty** and is filled at runtime through `POST /tls/trust`, because the CA it has to verify is usually generated in a *browser* minutes before the connection and exists nowhere a file could hold it. `GET /tls` describes it; `GET /tls/whoami` over either listener is the report |
| **SPIFFE, and the SPIRE Server API** | a **SPIFFE issuing authority** for one trust domain, in all three of its server-side shapes. The **bundle endpoint** is plain HTTPS at `/spiffe/bundle` — a JWK Set with `spiffe_sequence` and `spiffe_refresh_hint`, every key carrying the `use` a consumer must have to consider it at all. The **Workload API** is the gRPC service `SpiffeWorkloadAPI` on a **Unix socket** (SPIRE's own `/tmp/spire-agent/public/api.sock`, which is what `SPIFFE_ENDPOINT_SOCKET` means to every real client) and on TCP: X509-SVIDs with their private keys and the trust bundle, JWT-SVIDs for an audience, both bundle streams, and a `ValidateJWTSVID` that really verifies. The streams are held open and re-sent at half the SVID lifetime, so a client's **rotation** path runs without anybody waiting an hour. The **SPIRE Server API** is six gRPC services and 42 methods from the vendored `spire-api-sdk` protos — Entry, Agent, Bundle, SVID, TrustDomain, Debug — of which 36 are implemented and the other six each answer with a reason. **Its TCP port is mutual TLS**: a caller presents an X509-SVID from this trust domain and every method is authorized against SPIRE's own per-method table, with the Unix socket trusted as `local` the way a real `spire-server` trusts its private one (`spiffe.authRequired`). **Nothing is attested** either way — a Workload API caller is identified only by its transport, the endpoint it reached and its peer address, because node cannot read a socket's peer credentials, and an agent's attestation payload is taken on trust. `GET /spiffe` is all of that at length |
| **LDAP v3 (RFC 4511)** | an embedded **directory on two raw sockets — TCP 389 in the clear and TCP 636 over TLS (LDAPS)**, one set of handlers and one store behind both: simple bind, unbind, add, delete, modify, modifyDN, compare and search with RFC 4515 filters and all three scopes, a root DSE, and result codes 0, 2, 4, 11, 16, 32, 49, 66 and 68 all reachable. Built on the [`ldapjs`](https://github.com/rcbj/node-ldapjs) submodule and used unmodified. It is **schemaless on purpose** and says so, it enforces the four structural rules whose absence would teach a client something false — plus one of its own, that an add under `ou=users` whose username is already there is `LDAP_ENTRY_ALREADY_EXISTS` (68), because one person is one entry however they got in — and it deliberately does not do referential integrity. `GET /ldap` describes it and `GET /ldap/directory` lists every entry. **`LDAP_AUTOCREATE_USERS`, on by default, grows an entry under `ou=users` for anybody who authenticates through any of the other twelve families** — and `ou=applications` grows one for the CLIENT, relying party, service provider or Kerberos service on the other side of that authentication, which is a **registry rather than a record**: the RFC 7591 registrations live there, nothing caches them, and an `ldapmodify` of `oauthRedirectUri` changes which redirect URI RFC 9700 mode accepts — one hook on the single funnel they all already pass |
| **SCIM 2.0 (RFC 7642, 7643, 7644)** | a provisioning endpoint at `/scim/v2`, and **the only family here whose purpose is to write**: create, read, list, replace, PATCH (section 3.5.2 in full, `emails[type eq "work"].value` paths included), delete, both shapes of `.search`, bulk, filtering, sorting, pagination, attribute projection, and the three discovery documents. **What it provisions into is the LDAP directory above — the same entries, no second store and no cache** — so a `POST /scim/v2/Users` and an `ldapadd` create the same entry, and somebody provisioned over SCIM turns up on `/admin/users`, in an `ldapsearch`, in whatever group a client puts them in, and in the attributes their next access token carries. The SCIM `id` **is** the entry's DN, because that already is the opaque server-assigned identifier RFC 7643 asks for. **It is the one family here that requires a credential** — all six schemes RFC 7644 section 2 names are offered (OAuth 2.0 bearer and DPoP tokens with `scim:read` / `scim:write`, HTTP Basic, HTTP Digest, HOBA, the session cookie and a TLS client certificate), and every one of them is permissive, so it is a turnstile rather than a lock. `active: false` **deactivates nobody**: it is stored as `scimActive` and read by nothing, which is worth reading twice, because deprovisioning is the commonest thing a SCIM client is built to do |

`GET /sts-metadata` is the authoritative list — every endpoint read from the running
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

### Configuration

`CONFIG_FILE` selects a configuration from `env/`, and since 2026-08 that file
carries **every setting this service has** — 107 of them, 70 changeable while
running, grouped by the protocol they belong to: the three issuers, the
listeners, the OID4VCI and OID4VP tuning, the Kerberos realm, SIDs, passwords and
clock, the directory's base DN and limits, the audit log's cap, the SCIM
endpoints' authentication schemes, the SPIFFE trust domain and what its two gRPC
surfaces check, and the three that put the authorization flow into RFC 9700
mode. (The startup log line reports the count, and it is the number to trust:
this paragraph is prose and the table is the source. Three settings are
*derived* from a neighbour and are deliberately absent from the file — `global.https` from
`oauth2.rfc9700`, the Kerberos service domains from the realm, and the OID4VP
wallet from the OID4VCI one.) At the default log level `debug` the service
logs every endpoint call (path, request and response headers and bodies, status,
elapsed time) and every assertion, JWT and SD-JWT VC both before and after
signing or encryption, which is the point of a mock.

A value can arrive from four places, and **higher beats lower**:

| | |
|---|---|
| a runtime override | set on `/admin/config` or through `POST /admin-api/config/set`; in memory, gone on restart |
| an environment variable | `STS_PORT`, `KRB5_REALM`, … — one per setting, and every one that worked before still does |
| the appconfig file | the `CONFIG_FILE` module, e.g. `env/local.js` |
| the built-in default | what the expression in the module carried before the table existed |

`config.js` is the table. It is the one place that says, for each setting, what
it does, what its environment variable is, what the default is and why, and
**whether changing it while the service runs does anything**. Thirty-three of
the fifty-seven can be changed at runtime; the other twenty-four were consumed by
the time the service was listening — a bound socket, the TLS certificate's
names, the Kerberos principal database and its long-term keys, the directory's
base DN — and are refused with the reason rather than accepted and ignored.

`/admin/config` renders that table with the effective value of each setting and
**where that value came from**, which is the question it exists to answer: the
four sources are indistinguishable once a value has been read. `GET
/admin-api/config` is the same thing over JSON, and `POST
/admin-api/config/{set,set-many,reset,reset-all}` are its four actions.
`set-many` is all-or-nothing, so a section's Save cannot half-apply. **Nothing
here writes to the appconfig file** — an edit lasts for the life of the process,
the same arrangement as the custom claims next door, and `reset-all` is what a
test should call to put the service back.

**`STS_ISSUER` was one value doing three jobs** and is now three settings.
`saml.issuer` is the `<saml:Issuer>` of every SAML assertion (WS-Federation's
included, since the same two functions build them); `wstrust.issuer` is the
`iss` of the JWT this STS returns; `wsfed.entityId` is the `entityID` in the
federation metadata. They shared a default and nothing else — an entityID names
the identity provider, an Issuer names whoever signed an assertion — so a
deployment that needed one of them to be its own real name had to change all
three. All three still default to `urn:wstrust:mock:sts` and all three are still
fed by `STS_ISSUER` when it is set.

**The OAuth 2.0 / OIDC issuer identifier is new and is empty by default**, which
means each response names the base URL the request arrived on — what makes one
process answer correctly as `localhost`, as `sts` on a compose network and
through a published port. Set `oauth2.issuer` to pin it, which is how a
conforming client's "the issuer is not the one I fetched from" refusal is
produced on purpose. Only the identifier moves: every endpoint in the discovery
document stays on the request's base URL, because an endpoint has to be
reachable and a pinned issuer may not be.

**Seven listeners, not one.** 8081 is the HTTP service — or the HTTPS one, if
`global.https` or the `oauth2.rfc9700` it defaults from is set, in which case it
serves the same certificate as the three TLS sockets below and there is no plain
port left in the process; the KDC also binds **TCP and
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
| `LDAP_AUTOCREATE_USERS` | **an entry under `ou=users` for anybody who authenticates through ANY protocol family here.** On by default; only an explicit `0`, `false`, `no` or `off` turns it off, so a misspelling stays safe. An LDAP bind does not seed one (the identity a bind presents is a DN, which already names an object here) and neither does an OAuth client. A verified **TLS client certificate** does, and it is the one identity that is a DN rather than a name — see the TLS section for where its entry goes. **One entry per person whatever brought them**: every family here normalises to one key, a certificate saying `CN=rcbj` folds onto the entry `rcbj` already has, and an `ldapadd`, the console form and `POST /admin-api/users/create` all refuse a username that is taken |
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

A mock Security Token Service used by the test suite, **split across forty-nine files at its root** (it was one 4,489-line `server.js` until 2026-08-03; eight protocol families in one file meant no way to see what was in it short of reading it). `server.js` is now the shell — it requires `app.js` (the express app and every middleware, which must load before any route) and `helpers.js` (the log, the keys, and the helpers more than one protocol needs), then the modules that register routes, and listens: `authn.js`, `wstrust.js`, `oauth2.js`, `wsfed.js`, `vc_offers.js`, `vc_did.js`, `vc_issuer.js`, `vc_verifier.js`, `krb5_kdc.js`, `krb5_service.js`, `spnego.js`, `admin.js`, `admin_api.js`, `ldap_server.js`, `tls_server.js`, `sts_metadata.js`. The rest are reached through those rather than named there — `saml2.js`, `saml11.js`, `vc_configs.js`, `vc_claims.js`, `vc_verifier_config.js`, `claim_attributes.js`, `group_claims.js`, `dpop.js`, `admin_stats.js`, `audit.js`, `bbs2023.js`, `webauthn.js`, `admin_api_spec.js`, `admin_api_docs.js` and the nine `krb5_*.js` files under the KDC and the negotiation — which is not a hierarchy so much as the consequence of the rule below. One file among them is **not a module at all**: `admin_api_explorer.js` is browser code, read off disk by `admin_api_docs.js` and served verbatim at `/admin-api/docs/explorer.js`, and nothing in node ever requires it.

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
no session involved. `/sts-metadata` says that about it in both directions rather than
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

**`oauth2.rfc9700` is restart-only now.** It used to be a runtime setting and
stopped being one the moment it grew a consequence that happens before the
service is listening. A flag that was runtime for its checks and restart-only for
its socket would report the mode as *on* at `/admin/config` while every
authorization response still went out over plain HTTP — the silent disagreement
`config.js` warns about in its own header. Set it in the appconfig file or as
`STS_OAUTH2_RFC9700` and restart; `POST /admin-api/config/set` refuses it with
that reason.

**There is then no plain listener in this process at all**, and `POST /tls/trust`
and `GET /tls/server-certificate` were on one deliberately — they are what a
caller reaches *before* it trusts anything. So the first fetch has to be made
without verifying the certificate (`curl -k`), which is the ordinary bootstrap
for a certificate regenerated on every start: it is the same act as trusting the
PEM that endpoint hands back, done one step earlier. `/tls`, `/sts-metadata` and
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
by design. What is **not** here is section 2, mutual-TLS *client authentication*,
where the certificate replaces the secret; that is a different feature and its absence
is stated rather than implied.

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

**And the resource server refuses a token meant for somebody else**, which is the MUST
in that section. Ask for `resource=https://api.example.com/v1` and the token comes back
with that audience — and presenting it at `/oauth2/userinfo` is now a
`401 invalid_token` naming the audience it was for. Two details are deliberate: it
applies only to a token this service **issued**, since the `aud` of a foreign token is
a string this service cannot check and was never the audience of anyway; and "this
resource server" is matched on the **path** rather than the whole URL, because a token
minted at `localhost:8081` and presented at `127.0.0.1:8081` is in every sense that
matters a token for this service, while a token narrowed to somebody else always has a
different path.

This is a **feature**, not a mode behaviour: a request that sends no `resource` is
unaffected in either mode.

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
usable for its whole thirty days, which is the state this requirement is about.

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
`/oauth2/logout` and WS-Federation's `wsignout1.0` both end a session — a revocation at
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
| `private_key_jwt` | an assertion signed with the client's key, verified against its registered `jwks` |
| `tls_client_auth` | the client certificate's **subject DN** (RFC 8705 §2.1) |
| `self_signed_tls_client_auth` | the client certificate's **thumbprint** (RFC 8705 §2.2) |

**The three asymmetric ones are the change.** `private_key_jwt` and
`client_secret_jwt` used to be advertised and *accepted without being looked at* — a
client author configured the asymmetric method and came away believing an assertion
had been checked, which is worse than not offering it. They now get the full RFC 7523
section 3 treatment: signature against the registered keys, `iss` **and** `sub` both
the client, audience (the token endpoint *or* the issuer, because RFC 7523 and OIDC
Core §9 differ and half the client libraries in the world pick one each), expiry with
a configurable skew, and a `jti` remembered until the assertion expires — a signed
assertion captured off the wire is a credential until then, so a replay is refused.

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
`require_pushed_authorization_requests: true` with no PAR endpoint,
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

`/sts-metadata` lists the authorization servers this process has actually served, with
each one's metadata URLs and endpoints — it cannot read them off the router, because
one route (`/:as/oauth2/…`) serves all of them, so they are described by hand the same
way the Kerberos and LDAP listeners are. Only the ones that have been *asked for* are
listed: a name becomes an authorization server by being asked for, so the set of
possible ones is every string and the set of real ones is that list.

One property is a fact about the mock rather than the model, and the page says so:
**every authorization server here signs with the same key**. They are separate issuers
sharing one keypair, which a real deployment would not do.

The profiles live in memory, gone on restart, in the same family as the custom claim
sets and the verifier's request — not in the directory. `ou=applications` holds
applications because a relying party is a thing in the world that other systems have
opinions about; an authorization server profile is this service's own configuration.

#### TLS, and what a reverse proxy changes (section 2.6)

*Use TLS. End-to-end between client and resource server is RECOMMENDED. If TLS
terminates at a proxy, secure the proxy-to-application hop and make the proxy
sanitize inbound security-sensitive headers.*

The first two are `global.https`, which RFC 9700 mode turns on: every endpoint here —
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

`Access-Control-Allow-Origin: *` is right for the token, userinfo, metadata and JWKS
endpoints an in-browser client fetches with XHR — that is most of what this service is
for. The authorization endpoint is a different kind of endpoint: a browser *navigates*
to it, so nothing legitimate ever read those headers there. In this mode they are
withheld from `/oauth2/authorize` alone, preflight included.

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
| mode on | **separate namespaces** — `urn:sts-mock:client:<id>` beside `urn:sts-mock:user:<name>`, so the two cannot collide however a client is named |

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
parent project's `tests/sts_metadata.js` tells an unrouted path from an endpoint
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

Not here: **Pushed Authorization Requests** (RFC 9126), and **mutual-TLS client
authentication** (RFC 8705 section 2, where the certificate replaces the secret — the
*token binding* half of that RFC is implemented, see above). Client authentication at
`/oauth2/introspect` and `/oauth2/revoke` is likewise not enforced: those are called by
resource servers, which do not register here, so there is no credential to check. And
the requirements RFC 9700 places on the *client* stay the client's: this service can
detect several and fix none.

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

### WebAuthn: a second factor, or the only one

The login screen carries **two** security-key boxes, because a key is two different
things here and the difference is the whole of what the tokens afterwards claim. Ticked
beside a password it is a **second factor**; ticked on its own it is the **primary
credential** and no password is read at all. An authorization request whose `acr_values`
names `mfa`, `hwk`, `phr` or `phrh` ticks the first and disables both opt-outs — that
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

Two details worth knowing before changing the test. **A 404 is ambiguous and the distinction matters**: several endpoints answer 404 correctly for a resource that does not exist (an unknown offer id, an unknown presentation state), which *proves* the route is registered, while Express's own 404 for an unregistered path is an HTML page reading `Cannot GET /path`. Treating them alike either fails on healthy endpoints or passes on missing ones. And the **coverage notes must start `full`, `partial` or `mock`** and say what is missing, because a list of fifty specifications that did not mention that this service checks no passwords and validates no access tokens would be the most misleading thing in the repository.

**Kerberos is the one blind spot in the whole design, and it is structural.** The page is built by walking the live Express router, which is precisely why it cannot go stale — and the KDC's listeners are raw TCP and UDP sockets, as is the protected service's. A protocol family that registers no route is invisible to a router walk. Three HTTP surfaces are all the walk can see (`/KdcProxy`, `/krb5/principals`, `/krb5/service`), so the sockets are described in the text of those rows rather than left to be inferred from silence — the alternative, a described entry with no route behind it, is the *stale* half of the drift check and would have to be exempted from it by hand. Anything added later that speaks a protocol over a socket needs the same treatment.

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

`GET /ldap/applications` lists them and publishes the schema; `?format=json` is
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
same rule that makes `alice`, `urn:sts-mock:user:alice` and `alice@REALM` one
person on `/admin/users`, and it is the shape the federation work will need: a
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

The table is the definition: `GET /ldap/applications` publishes it, the entry is
built by walking it, and an attribute that is not in it is refused rather than
written. `multi` accumulates a repeat and `single` is assigned — which is what stops
a counter growing a value per sign-in, the trap `applyVcAttributes()` writes its
second rule about. Beside the identity and the counters (`appAuthentications`,
`appSessions`, `appUsers`) sit the protocol-specific ones: `oauthClientId`,
`oauthRedirectUri`, `oauthGrantType`, `oauthTokenEndpointAuthMethod`,
`oauthConfidential`, `samlEntityId`, `samlAssertionConsumerService`, `wsfedRealm`,
`wstrustAppliesTo`, `krb5ServicePrincipalName`, `oid4vpClientId`.

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
`/ldap/applications`, and as `dn` on every application in the API's reply — because
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

### The admin console

`GET /admin` is an operator's view of the running service, and the pages under it exist for a reason the protocol endpoints cannot serve: the interesting behaviour of a client is what it does when something changes *underneath* it. A client that gets a good token and reads it correctly is a client that has been tested against the easy half. What happens when the token it is holding stops being valid, or when the token it reads grows a claim it was not expecting, is the other half, and until now there was no way to cause either without editing this service and restarting it. Every page also answers `?format=json` and every form also accepts a JSON body, because a console reachable only by clicking is a console no test can assert against.

**Every page here carries a breadcrumb trail, and on a drill-down it goes back to the list *as you left it*.** One line under the nav — `Admin console › Applications › rfc9700-debugger` — on every page including `/admin` itself, where it is the single crumb. The nav answers *what else is there*; the trail answers *where am I and how do I get back*, and those are different questions: the tab for the section you are standing in is exactly the tab that tells you nothing about the page you are standing on. That was the whole of the original bug — the active tab is drawn as plain text, and the page it names is the section's path on the list page and on every drill-down beneath it alike, so on `/admin/applications?application=rfc9700-debugger` the one control pointing at the list of applications was the one control the shell had switched off. On a drill-down that tab is now a link too, still bold because the reader is inside that section and underlined so that *the section you are in* cannot be read as *not clickable*. The last crumb is never a link: it is the page being drawn, and a crumb that reloads the page you are on teaches a reader not to trust the ones beside it. A long leaf is cut to 44 characters with the whole of it in the tooltip, because a `did:jwk` is a few hundred characters of base64url with nowhere a browser will break a line and a trail that wraps to four lines is not a trail.

**What makes it a breadcrumb rather than a link to the section is the list state it carries.** A drill-down link is built with the filter and the page the reader is looking at — `?q=client&per=25&page=3&application=beta` — and the trail's section crumb spends exactly that, so *back* lands on page 3 of that filter instead of the top of everything. Which parameters belong to a list is a **whitelist per section** (`LIST_PARAMS`) rather than *everything that is not ours*, for the reason the tokens page rebuilds its `back` field from a list of names: what comes out of it goes into a URL this service hands to a browser. Three things would otherwise drop it and each is handled where it is. Every control on a drill-down carries the whole current query already, so paging the five tables on a user's page keeps it for free. The *rows per table* form is a GET form, which posts its own fields and nothing else, so the filter is spelt out as hidden inputs — but deliberately **not** the list's page, since `per` is the thing that form changes and page 4 of fifty-row pages is not page 4 of anything afterwards. And every form on the applications and authorization-server drill-downs carries the list as one opaque `back` field, which the POST handler **rebuilds** through the same whitelist rather than echoing — a redirect target taken out of a request body is an open redirect and one carrying a newline is a header injection, so the worst a hand-written `back` can reach is another page of the same list. Without that last one, editing an application would silently cost the reader their place, which is the one thing the trail exists to keep. Four views take a trail leaf, the four that drill in: `?user=`, `?group=`, `?application=` and `?profile=`. A parameter that only *filters* a list does not, because there the tab already goes to the unfiltered page and the filter has its own **clear** link. `?format=json` ignores all of it — a way back up is a property of a page somebody is reading, and a caller has the URL it asked for.

**`/admin/metrics`** counts endpoint calls by the route Express matched — the pattern, `/oauth2/register/:client_id`, not the URL, or every registered client would get a row of its own — with the status classes, the average and worst latency and when it was last called. Then every token by `typ`, with how many are valid, expired, revoked, not yet valid and DPoP-bound; every assertion, ticket and credential the same way. All of it is computed **when the page is drawn** rather than kept up to date as things happen, and that is the load-bearing choice: "valid" and "expired" are functions of the clock, so a counter incremented at issuance is wrong a second later and would need a sweeper to stay right.

**Sessions are reported twice, and the two numbers disagree on purpose.** A *sign-on session* is a real one — a browser holding the `sts_mock_session` cookie, the store `oauth2.js` owns and WS-Federation shares. An *artifact-derived session* is an inference, and it is a definition rather than a measurement, so the page states it: a subject has one in a protocol family when that family has issued it at least one artifact that is still valid. A `client_credentials` token is the second and not the first (no human, no browser); a browser that has signed in but been issued nothing is the first and not the second; a Kerberos client is never the first at all. Within Kerberos a **TGT counts as the session and a service ticket does not**, because that is what they are — the TGT is the credential the session consists of, and a service ticket is one use of it, so counting both would report the same session twice.

**`/admin/users`** answers the question the other pages cannot: *who has this service seen, and what do they hold right now?* It lists every userid presented as part of an interaction that **succeeded** — the name typed at either sign-in screen, the one on a password grant, the subject of a WS-Security `UsernameToken` or of a WS-Trust `OnBehalfOf`, the client principal in a Kerberos AS-REQ or in an AP-REQ this service accepted (over a raw socket or through SPNEGO), and the subject of an exchanged token. A request that was *refused* records nothing, so this is a list of identities that got somewhere rather than of names that were tried. `?user=<name>` drills into one: the names they were seen under, every authentication with the method that performed it, each sign-on session they hold **with the tokens issued on that session underneath it**, the tokens that belong to no session, and the assertions, tickets and credentials issued to them. A `revoke-user` button invalidates everything revocable for that identity under any of its spellings.

**Two decisions there are worth stating before changing anything.** The first is what *one row* is. A single person reaches this service as `alice` at the login screen, `urn:sts-mock:user:alice` in every token, `alice` as a SAML `NameID` and `alice@EXAMPLE.COM` as a Kerberos principal, so the identity is keyed on the **local name** — the `urn:` prefix stripped (derived from `userFor()` rather than written down again, so a change there cannot silently split every user into two rows) and the realm split off at the last `@`. Four rows for one name would be a worse answer than one on a service whose whole premise is that the name you type is who you are in every protocol at once. What that costs is real and is shown rather than hidden: two different people called `alice` in two Kerberos realms are one row, which is what the Realms column exists to make visible. Case is never collapsed, because nothing else here treats `Alice` and `alice` as one person. The second is that the list is built from **three** sources — the authentications recorded, plus every token's `sub`/`username`, plus every artifact's subject — because an identity can be issued something here without ever having authenticated here: a token exchange presents somebody else's token, a WS-Trust `OnBehalfOf` names a delegated subject, an anonymous RST issues an assertion for `anonymous`, and a Kerberos S4U2Self ticket is for a user who was never near this KDC. Such a row is listed and **marked as never authenticated**, because a users page that showed only the sign-ins would deny the existence of subjects the tokens page is displaying at the same moment. The same honesty runs through the methods column: "sign-in screen (password)" and "AS-REQ with PA-ENC-TIMESTAMP" are both authentications and only one of them checked anything, and an S4U row says the user was not there and names the service that asked in their stead.

**Putting a token under a session needed one thing that is not on the wire, and it is deliberately not a claim.** No token this service issues carries a session identifier — OIDC's `sid` is for front-channel logout, and inventing one for every token to make an admin page easier to draw would change what every client receives. So `signJwt()` takes an optional third argument, a `context` that is signed into nothing and sent nowhere, and the recorder stores its `sessionId` and `grant` on the token record. The link is threaded where it genuinely exists: the session id rides on the authorization code (the only route to a back-channel token request, which arrives with no cookie behind it), the token endpoint passes it on, and a **refresh** looks it up by the refresh token's own `jti` — without which the second generation of every token would show as sessionless and a session's list would quietly stop growing the moment a client refreshed. A grant that never had a session says so: `password`, `client_credentials`, the pre-authorized code and token exchange are shown as issued with no browser session at all, which is a fact about them rather than a gap in the recording. Tokens naming a session this service no longer holds get their own heading, since that is the ordinary end state rather than an error — the session expired and the tokens it produced outlived it.

**A user's page also shows that user's LDAP object, and the dependency that puts it there runs the opposite way from the call.** Every person who authenticates anywhere here already grows an entry at `uid=<name>,ou=users,<base>` (see the directory's own section below), so by the time somebody has a page in this console they usually have a directory object too — and the two are the same authentication seen from two sides, which is the reason for showing them together rather than making a reader find the object again on `/ldap/directory`. What is shown is the entry itself and not a copy: its DN, where it came from (`seed` or `authentication`), its two generalized-time stamps kept in the directory's own punctuation rather than converted to the ISO 8601 the rest of the console uses, and **every attribute with every value, the operational ones included** — a search returns `createTimestamp` and `modifyTimestamp` only when they are asked for by name (RFC 4511 section 4.5.1.8, which `toSearchEntry()` honours), but this is not a search, and a dump that silently dropped two of an entry's attributes would be the one thing a dump must not do. `?format=json` carries the same object under `ldap`.

Where there is no entry the section says **which** of the five reasons it is, because four of them are facts about the user rather than about the directory and "not found" alone would send a reader looking for a bug: auto-creation is switched off, the identity is a *client* and not a person, it has never authenticated here at all (it is known only as the subject of something that was issued), everything it has ever done here is an *LDAP bind* — which presents a DN and not a user name — or the entry was there and has since been `delete`d or `modifyDN`'d through the protocol. It also lists any **other** entry whose `uid` names the same person — which is now a report about entries *outside* `ou=users`, since inside it one person is one entry and every door enforces that — and it says so loudly when the directory's listener is down: the entry can be in this process's store while no client can connect to read it, and only one of those two facts is visible from an HTTP page. The dependency is the thing to be careful with. `admin.js` does **not** require `ldap_server.js` — `server.js` requires the console first (rule 6: the directory needs `admin_stats`' identity normalisation, and the console reads `oauth2`'s sessions), so a require from the console would drag the directory's routes into the router *ahead* of its own, and `/sts-metadata` is built by walking that router. So the direction is inverted the same way the user observer is: `admin.js` offers `setDirectoryReader()`, `ldap_server.js` fills it at its own require time with a function that takes the identity key the console files a person under — the same normalised local name the entry's DN was built from, so the two cannot drift — and a build of this service without the directory renders the section as "no directory is loaded", which is a different answer from an entry that is not there.

**The page has exactly one control, and it writes somewhere else.** A form on the list creates a person in the embedded LDAP directory — `POST /admin/users` with `action=create`, and `POST /admin-api/users/create` beside it. Until it existed `ou=users` could only be filled by authenticating or by an `ldapadd`, while `ou=applications` could be filled from three directions; a client that wanted claims read out of the directory had to sign somebody in first to make the entry it was about to read. The entry is created with the invented person behind that name already written onto it, so an issued credential and an `ldapsearch` for that entry agree from the first request. **A username that is already there is refused**, naming the entry that holds it — the same refusal an `ldapadd` gets as `LDAP_ENTRY_ALREADY_EXISTS` (68), because both call one function in `ldap_server.js` and the console is not a second definition of what a user is. Two things the message says outright rather than leaving to be discovered: **no password is set**, because none is ever checked here, and **the new person does not appear in the table above** until they authenticate somewhere — that list is who this service has *seen*, and the entry is what the directory *holds*. It is the same distinction `/admin/groups` draws when it marks a member *never here*.

**`/admin/groups`** is the one page in this console that reports the *directory* rather than what this service has issued. It lists every group with what it is made of, and `?group=<dn>` drills into one: every attribute the entry holds, operational ones included, and every member resolved to the entry it names. Both views come out of `groupsFor()` in `ldap_server.js` through a third inverted hook — `admin.js` offers `setGroupReader()` and the directory fills it, for the same route-order reason `setDirectoryReader()` exists — and the console renders what it is handed without deciding anything, which matters most for the first decision below.

**What counts as a group is two rules and not one.** An entry under `ou=groups`, *or* an entry carrying a group `objectClass` (`groupOfNames`, `groupOfUniqueNames`, `posixGroup`, `groupOfURLs`) wherever it sits. Both, because this directory is schemaless and nothing stops a client adding a `groupOfNames` under `ou=users` or an entry with no `objectClass` at all under the groups container — either rule applied alone answers correctly for one of those and quietly loses the other. The list says which rule caught each row, since "this entry is a group because somebody put it under `ou=groups` and it carries no group class at all" is the interesting fact and "developers is a group" is not.

**Membership is read from `member`, `uniqueMember` and `memberUid` together, and the third one is not like the other two**: it holds a bare user name where they hold a DN, so it is resolved under `ou=users` rather than as written. Treating the three alike is how a page ends up reporting every `posixGroup` member as dangling. Three disagreements are then reported rather than smoothed over, and every one of them is a state a client can reach in two operations:

* a **dangling** member — a value naming an entry this directory does not hold. Deleting a user does not remove its DN from the groups that list it, because referential integrity is a directory feature and not a protocol rule (see below), so the count of membership values and the count that resolve are shown as two numbers. One combined number would report a group whose seven members resolve to five as seven members with nothing wrong, which is precisely the thing this page exists to make visible.
* a member that is itself a **group**. Nesting is shown and never expanded: the row links to that group's own page and nobody inside it is counted here, because nothing in this service walks a group tree and a flattened list would be claiming a feature that is not here.
* an entry whose own **`memberOf`** names a group that does not list it back. `memberOf` is not a standard attribute at all — it is Microsoft's and OpenLDAP's, and in the directories that have it the *server* keeps it in step with `member`. This one keeps nothing in step, so a client can write it onto a user in one `modify` and create the disagreement. Those entries are listed under their own heading rather than merged into the members, because which side of the disagreement a name came from is the only interesting thing about it.

**A member links to `/admin/users` only for somebody this service has actually seen authenticate**, and is marked *never here* otherwise. The two lists answer different questions and it is worth being deliberate about the difference: the directory holds an entry for whoever somebody wrote one for — including `alice`, `bob` and `carol`, who are seeded at startup — while the users page holds whoever has presented a credential to this process. A link drawn unconditionally would usually land on "nothing here has authenticated as alice", which reads as a broken link rather than as the answer it is.

**A group here grants nothing**, and both pages say so where a reader will see it rather than leaving it to be discovered. No endpoint in this service checks a group and nothing decides anything on one. On a service that authenticates nobody it could hardly be otherwise — but a console that listed groups a click away from the tokens page without saying it would let somebody conclude that adding a user to `cn=directory-admins` had changed what their token could do.

**A token can carry one, which is a different sentence and the two must not be merged.** That half of the paragraph used to read "no access token, ID Token, SAML assertion, WS-Federation token or Kerberos PAC carries a group from this directory", and `groups.claim` is what made it false. With that setting on — it is **on by default** — every OAuth 2.0 access token, OIDC ID Token, SAML 2.0 assertion and SAML 1.1 assertion this service issues carries a claim naming the groups its subject is in, read out of these entries at the moment the token is minted. It is the same distinction this service already draws between an identity being **recorded** and an identity being **authenticated**, and it is drawn here for the same reason: carrying a fact is not acting on it. No Kerberos PAC carries a group either way.

Why it is worth carrying at all is the usual argument in this repository. A groups claim is one of the two or three things a relying party actually branches on, and until `group_claims.js` existed there was no way to produce one here — so a client whose authorization code has never seen a `groups` member, or has only ever seen names where the next identity provider will send DNs, has never run that code.

Four things about it are deliberate:

* **The claim is omitted entirely for somebody in no group** — not sent as an empty array, absent. That is what makes ON a defensible default: on a fresh start the only people in a group are the three the directory seeds, so a caller who has never touched `ou=groups` gets exactly the tokens it got before. An empty array would be a new member in every token every existing client parses.
* **The membership is read per token and never cached**, the same rule the applications registry follows and for the same reason: an `ldapmodify` changes the very next token, which is the thing somebody came here to watch.
* **Both membership rules are read** — `member`, `uniqueMember` and `memberUid` from the group's side, and the person's own `memberOf` from theirs. Nothing here maintains one from the other (that disagreement is a thing this page exists to *show*), so `groups.claimFromMemberOf` is which side a token believes; it is on by default, and either way the group has to exist here, since a `memberOf` naming nothing must not invent a group to put in a token. A group listing a DN nothing is stored at still counts: that is a **dangling** member from the group's side and is still the group saying so.
* **`groups.claimValue` chooses `cn` or the whole DN.** Both are what somebody's real identity provider does — an OIDC provider usually sends names and Active Directory sends DNs — and a client that has only ever parsed one has never run the other path.

A typed custom claim and a ticked directory attribute of the same name both **win over** it, because those were named on `/admin/claims` about this service and this comes from a setting and a directory. `groups.claimName` naming something this service sets itself (`exp`, `scope`, …) is **refused at issuance** and `/admin/claims` says why — the same rule a typed claim of that name meets at configuration time, made in the only place that can reach the reserved list. The claim reaches a SAML assertion as **one `<Attribute>` with several `<AttributeValue>` children**, which is what the content model means by multi-valued; one element per group with the same name is a relying party reading the first and silently seeing one group where the person is in four.

**`/admin/tokens`** lists what was issued and invalidates what can be. What it lists is **every JWT, every SAML assertion and every Kerberos ticket, in one table, newest first** — the assertions whether WS-Trust issued them or a WS-Federation sign-in did, since both go through the two builders and both are counted there. One table rather than three because a WS-Federation sign-in that produces an ID Token and a SAML 1.1 assertion is *one event*, and three tables would leave it to be reassembled by comparing timestamps. The three families are declared in `admin_stats.js` (`ISSUED_FAMILIES`) and `issuedList()` merges them, because which artifact belongs beside a token and what "still valid" means for each are statements about the state that file holds; `admin.js` renders what it is handed. Two things had to be made common to merge them at all: the state, which comes from one function per family against one clock, and the expiry, which is **normalised to milliseconds** — a JWT's `exp` is seconds and an artifact's `expiresAt` already is not, and one table cannot sort two units. A filter for the family sits beside the one for the kind, and the kind list is grouped by family and built from that same structure, so the two cannot come to disagree about which kind is which.

**Only the JWTs have a button, and the rows that do not are the reason to list them.** Nothing consults this service about a SAML assertion or a Kerberos ticket: an assertion is valid because its signature verifies and its `Conditions` hold, and a ticket because the service it names can decrypt it with a key it already has. So the only thing that ends one is its own expiry — and until it was on this page there was no way to see when that was, or to see that a sign-in had produced one at all. Each such row carries the reason there is no button in place of it, which is the honest version of the button this console deliberately does not offer. Because most columns then mean something slightly different depending on the row — `Detail` is a scope, or whether the signature was written, or the enc-type — the page carries **a legend saying which**, and the code is written one function per *column* answering for all three families rather than one per family, so a header like "Client, audience or service" can be checked against the three answers underneath it. Two of those answers are worth stating: a Kerberos ticket has **no identifier at all** to put in the `jti` column, because none exists for anyone to quote and the KDC keeps no handle on one either; and an assertion's `Detail` says signed or unsigned, which meant correcting the record in the two builders' `catch` blocks — the assertion is counted *before* the signing attempt on purpose, so an assertion that went out unsigned was being counted as signed, and a column showing that would have agreed with the page rather than with what left. **OID4VCI credentials are not in the table**, only counted on the metrics page; that is a gap rather than a principle, and the page says so rather than letting "everything this service has issued" be read as four families.

Invalidation is one `jti`, a whole kind, everything for one subject, or everything. **It is the same revocation `/oauth2/revoke` performs** — there is one set of revoked jtis in this service, not one per page. That mattered enough to move the set out of `oauth2.js`, where it was written, and into `admin_stats.js`: two sets would each look correct alone and never see each other, so a token revoked from the console would keep introspecting as active with no error message anywhere to point at. It is the same failure the single session store exists to prevent. A token revoked here is therefore reported inactive by introspection, refused by UserInfo with `invalid_token`, and fails the refresh grant with `invalid_grant`, immediately and without a restart.

The list is **filtered by family, kind and state and then paged**, newest first, with `?page=` and `?per=` — and in that order, because paging a list and *then* filtering it gives a page 2 whose length depends on what happened to be on page 1. Paging replaced a flat cap of 300 rows that showed the most recent matches and said underneath how many it had hidden; the cap survives as the ceiling on *one* page, since `?per=` is a number a caller types and without a ceiling `?per=5000` is exactly the page the cap existed to prevent. Everything held is now reachable rather than only the newest 300. Three properties are what make that safe to click through. An **out-of-range page is clamped to the last one** rather than answered with an empty table — a revocation sweep can shorten the list between two clicks, and an empty table reads as "nothing matched" when it means "that page has gone". The **filter form carries no page number**, so changing a filter or the page size returns to page 1 instead of landing on page 6 of a two-page result. And every button on the page acts on a **`jti` and never on a row number**, so a token issued or revoked between the render and the click cannot make the wrong token the target; the most it can do is shift a row onto another page. A revoke or restore button **returns to the page and filter it was clicked on** rather than to the top of an unfiltered list, which the row forms arrange by carrying the view as a hidden `back` field — and the redirect target is *rebuilt* from that field rather than echoed, because a redirect taken from a request body is an open redirect and one carrying a newline is a header injection. Only `family`, `kind`, `state`, `per` and `page` survive the rebuild, each re-encoded — plus, on the users branch of it, any parameter whose name *ends in* `Page` and whose value parses as a positive integer, which is the one thing a whitelist could not cover: a drill-down's session blocks have a page parameter each, named after the session, so the set of names is data rather than a list. The number is rebuilt from `parseInt` rather than passed through, so what lands in the URL is a number this service produced. The worst a hand-written `back` can reach is another page of the same table — and that list has to be kept in step with the filter form, because a parameter the form offers and the rebuild drops is a filter that silently resets itself the moment somebody revokes a token, which looks like the console losing your place rather than like a missing line. The bulk buttons keep the filter and drop the page, since after "revoke everything" page 7 is a page of a different list. Both parameters work with `?format=json`, whose reply carries `page`, `pages` and `matched` so a test can walk the whole list without guessing where it ends, and whose rows are in **`issued`** — each naming its `family`, and called `issued` rather than `tokens` since the day the array stopped being only tokens. Paging is links and a query parameter with no script behind it, because `script-src 'none'` is what makes the whole family of reflected-content problems moot here and the console does not get an exception.

**The two drill-downs page too, and they need more than one page number to do it.** `?user=` answers with five lists at once — the sign-on sessions, the tokens issued on each of them, the tokens whose session has since ended, the tokens that never had one, and the assertions, tickets and credentials — and `?group=` with two, its members and the entries claiming it back. A single `?page=` cannot serve those: clicking *next* under the artifacts would silently advance the sessions above them. So each list carries a page parameter **named after the array it moves** — `sessionsPage`, `tokensOnEndedSessionsPage`, `tokensWithNoSessionPage`, `artifactsPage`, `membersPage`, `claimedPage`, the reply's own member name with `Page` on the end and the object answering it the same name with `Paging` on the end — while `?per=` stays shared, because *rows per table* is one choice a reader makes for a page rather than seven, and because `per` is the parameter with the cap on it and one capped parameter is one place to get the cap right. Every control carries the whole current query and overrides only its own key, so moving one list leaves the others where they were. One of the seven is not in that list because **its name is data**: a session's own token table is moved by `session-<the session id>Page`, since one browser session can hold most of the five thousand tokens this service remembers and is therefore the one table here that genuinely runs away. It is named after the session rather than numbered so that the link still moves the same session after the list around it has changed — an index would move whichever session had drifted into that position. The session *blocks* start at five per page rather than fifty, because each of them is itself a table. Three lists on those pages are deliberately **not** paged and it is worth knowing which: the spellings an identity has been seen under, the protocols it authenticated through, and its authentication events. The first two are bounded by how many exist and the third is capped at fifty by the registry itself; all three also live on the `user` object that goes out whole in the reply, so slicing them for the table would either corrupt that object or duplicate it, and paging the table while the JSON stayed whole is exactly the console-and-API disagreement the rest of this console is built to avoid.

**The management API pages the same way and answers with the same words.** `GET /admin-api/users` and `GET /admin-api/groups` take those parameters and reply with a `<name>Paging` object beside each array — `sessionsPaging`, `membersPaging`, and so on — carrying `page`, `pages`, `perPage`, `firstRow`, `lastRow` and `total`: the member names the three flat lists put at the top level, one level down, so a caller that has learned to walk `/admin-api/tokens` walks these without being told anything new. Each session in the reply carries its own `tokensPaging` for the same reason its parameter is named after it. Every array in a drill-down is therefore **one page and not the whole list**, which is what `users` has always been on the list beside it. The counts around them are untouched: a group's `memberCount`, `presentCount` and `danglingCount` stay counts of the whole list, because *seven members, five of which resolve* is the fact that resource exists to report and a per-page count would not be an answer to it. The `session-<id>Page` parameter is described in the operation's prose rather than listed with the others, because OpenAPI has no way to spell a query parameter whose name is built at runtime and a `session-{id}Page` in the parameter list would generate a client that sends a literal `{id}`.

Three further details of that page are worth knowing before changing it. It keeps **the claims and never the credential** — not the signed token, not the assertion XML, not the ticket — because a page rendering a thousand live credentials in a form a browser will display is a page that leaks them, and the `jti` is all any button needs. Pasting a whole token works and **its signature is not verified**, which is safe rather than sloppy: the only thing read out of it is the `jti`, which is then looked up in this service's own registry, and a forged token yields a jti this service never issued — revoking one of those invalidates nothing. RFC 7009's endpoint *does* verify, because there the token is the credential being presented. And **Restore is offered and is labelled NON-SPEC**: no authorization server can undo a revocation, since a resource server may already have cached the refusal, but without it getting back to a working token means restarting the service and losing the signing key with it.

**`/admin/applications`** is the other side of `/admin/users`, and the second page here that reports the *directory* rather than what this service has issued. Where that page lists every identity that has authenticated, this lists what they authenticated **to** — every OAuth client, OpenID Connect relying party, SAML 2.0 or 1.1 service provider, WS-Federation application, WS-Trust relying party, OpenID4VP verifier and Kerberos service, one entry per unique identifier whatever protocol brought it. Filter by identifier or name and by kind, page with `?page=` and `?per=`, and `?application=<id>` drills into one: every attribute of its directory entry, each shown with what the published schema says it *is*, paged under `?attributesPage=`. It differs from `/admin/groups` in one way worth knowing — that page reports the directory, this one reports a **registry** that lives in it, so an `ldapmodify` here changes what the protocol endpoints do. It carries forms as well: create an application before it connects, and add, remove or set the attributes that say what it is allowed to do — never the counters or the sightings, which are what happened rather than what it may do. See *Applications* above.

**`/admin/authorization-servers`** decides what each discovery document *publishes*. One process serves as many authorization servers as somebody configures — the path component both discovery shapes already carry selects a profile, and each can have its own endpoints, capabilities and issuer. Any member is settable, including one this service has never heard of. It is the one page here whose whole purpose is to be able to say something untrue, so every view computes the **drift** between what a profile publishes and what this service actually does. See *Authorization server metadata* above.

**`/admin/audit`** is the one page here that reports *history* rather than *state*, and that distinction is the whole reason it exists. Every other page answers a question about now: how many calls, which tokens are still valid, who is in `cn=developers`. None of them can answer *when*, or *by whom*, or *in what order*. `/admin/metrics` will tell you the directory holds eleven entries; only this page can tell you that a twelfth was created at 14:02 and deleted at 14:03 by somebody bound as `uid=carol`, over LDAPS — and that in the same minute a token was revoked from the console. Those are three rows here and three numbers that each went up by one over there.

Six categories, and the shape of them is the point rather than the count. **Authentication** is a credential having been *accepted* in any of the sixteen protocol families. **Session** is a browser sign-on session created or ended — shared between OAuth 2.0 / OIDC and WS-Federation, so a `wsignout1.0` and an `/oauth2/logout` produce the same row. **Directory** is every LDAP operation over 389 and 636 alike. **Admin** and **API** are the console and `/admin-api`. **Protocol** is every other endpoint.

Each of those arrives through a funnel this service already had, which is the property worth keeping. `admin_stats.recordAuthentication()` is the single point all sixteen families pass through the moment a credential is accepted, so one line there is one line and not sixteen; `app.js`'s call log is the single place every answered request passes through, so one call there covers the console, the API and every protocol endpoint rather than a recording site in each of forty route handlers, thirty-seven of which would never have been added. Only the directory needed a site per operation, because ldapjs dispatches straight into the handler and what a row has to say genuinely differs — a modify names its changed attributes, a search names how many entries came back. What is *not* repeated across those seven is the rule that decides whether an add is a user, a group or something else: that is **placement**, since this directory is schemaless and believing the `objectClass` a client sent would file a `groupOfNames` added under `ou=users` as a group, and it lives in one function that `/admin/groups` agrees with by construction.

**No credential is ever recorded, and that constrains what the rows can say.** Not a password, not a bearer token, not an assertion, and no request or response body at all. A modify names the attributes it changed and never their values, because a modify is where a `userPassword` gets set; a compare says whether it matched and not what was tried, because comparing against `userPassword` is precisely how a client checks a password without binding; a refused bind carries the DN and not the password, not even its length. An `authorization code` or an `id_token_hint` in a query string is replaced with `(redacted)` — a query string is otherwise kept, because on this service it is page numbers, filters and client ids. The one field read out of an admin request body is `action`, by name and capped in length, and that narrowness is deliberate: those bodies carry pasted JWTs, since the tokens page revokes by pasted token.

**One act usually produces several rows, and they are not duplicates.** Signing in at `/authn/login` writes three: the HTTP call, the credential being accepted, and the session that came out of it. Which one answers your question depends on the question — a Kerberos AS-REQ authenticates somebody and starts no session at all, an LDAP bind does both with no HTTP request anywhere in it, and a `wsignout1.0` against a session that expired an hour ago is a `session.end` marked `refused` that looks, from every other page in this console, exactly like one that worked. Collapsing the three would mean choosing, once and for everybody, which of those this page can answer.

The three **outcomes** are three rather than two for the same kind of reason. A `refused` is this service working correctly and saying no, which is most of what somebody debugging a protocol client wants to see; an `error` is this service failing. Collapsing them into `ok`/`not ok` would bury the one row worth paging somebody about under the fifty that are a client getting its parameters wrong.

**The page observes itself.** Drawing it is console access, so fetching `/admin/audit` records an `admin.view` event and the list is one row longer than it was when you asked for it. That is stated on the page rather than engineered around, because suppressing it would put a blind spot exactly where the person reading the audit log stands; `?category=` is how you read past it.

Filtering is by category, action, outcome, actor and free text, and the vocabulary the filters offer is read off the same table the log records against — so an action cannot occur and be unfilterable, nor be offered as a filter and never occur. The actor filter is a **substring** rather than an equality, and that is a concession to something real: the actor on a directory row is a bind DN and the one on a Kerberos row is `alice@REALM`, and the collapse of those to one key can only be done where an identity is normalised. Where it *has* been normalised, the row carries both — the key and the form it was presented in — because that collapse is something an auditor has to be able to see rather than take on trust.

Paging is `?page=` and `?per=` as everywhere else, but **the thing to walk this list by is `seq`**. That number is monotonic and never reused, including across a drop, so "everything after 4,102" is exact where page 2 taken a second after page 1 can repeat a row that shifted onto it — the log is still being written while you read it. `?format=json` carries `oldestSeq` and `newestSeq` for that, and a gap between the last sequence number a caller saw and `oldestSeq` is precisely how many events it missed while the cap discarded them.

Two things it deliberately does not have. **No client address**: this service is reached over a compose bridge, through a published port or from the same machine, so what it would record is the bridge — a fact about docker rather than about whoever made the call, and a column that was right on a laptop and quietly wrong everywhere else is worse than no column. What a row *does* say is the channel — `http`, `ldap`, `ldaps`, `grpc` for the two SPIFFE gRPC surfaces, or `internal` for the things this service did on its own, such as the directory entry it seeds for somebody who authenticated elsewhere — which is the part that is actually knowable and is what somebody who has just turned LDAPS on wants to check. And **no clear button**, here or on the API: an erase control on an unprotected surface would make an audit log unable to answer the one question it exists for. Restarting the service is how you get an empty one, which is also what happens anyway — this is in memory and dies with the process, like the counters, the sessions and the signing key. There is no compliance story here to serve: this service checks no password anywhere, so an audit log of it is a debugging aid and not a record of anything.

Two settings on `/admin/config` change it and both take effect immediately, because `audit.js` reads them per event rather than capturing them at require time. `audit.maxEvents` (5,000) is the cap, and what was dropped is counted and shown, so a truncated log says it was truncated instead of implying the cap is all there ever was — lowering it from 5,000 to 100 discards the excess on the very next event rather than one row per event for the next 4,900. `audit.protocolCalls` (on) is whether ordinary protocol endpoint calls get a row at all; it is far and away the noisiest category, since every JWKS poll and metadata fetch is one, and turning it off is how somebody watching the directory or the console gets a readable page. It never touches the other five categories, and `/admin/metrics` counts every call either way.

**`/admin/claims`** decides what every *future* access token, ID Token, SAML 2.0 assertion and SAML 1.1 assertion carries. Four sets rather than one, because the four are genuinely different vocabularies: an access token and an ID Token go to different readers (a resource server and a client), and SAML 1.1 splits the claim URI into an `AttributeNamespace` and an `AttributeName` where SAML 2.0 has one `Name`. They are **additive** — a configured claim is added to what the protocol already puts in the artifact and never replaces one — and the names this service sets itself are **refused at configuration time** rather than silently dropped at issuance, because every one of them is load-bearing: an `exp` settable from a web form would produce tokens that fail to verify with nothing anywhere pointing back at the page, and a settable `scope` would quietly change what UserInfo answers. The same rule protects the SAML side for a different reason: a WS-Federation relying party keys off the claim URIs `claimsFor()` writes, so a custom attribute that displaced one would break a sign-in somewhere that looks nothing like this console.

Values may contain `${username}`-style placeholders, because a claim that can only be a constant cannot exercise the thing worth testing — that a claim carrying the signed-in user's identity reaches the relying party. **An unknown placeholder is left exactly as written** rather than replaced with the empty string: a `${dept}` that silently became `""` is a bug that looks like a configuration mistake, and one that still says `${dept}` names itself. A JWT claim value is typed when it unambiguously looks like JSON (an object, an array, a bare `true`/`false`/`null`, a number) and is a string otherwise, which has one consequence the page states rather than leaving to be discovered: a claim whose value is genuinely the four characters `true` cannot be configured, and `"true"` is the escape. SAML attribute values are never typed — the XML content model is text.

**Each of the four sets has a second half, and it is the half worth exercising.** A typed claim is a constant, or a constant with the signed-in name interpolated into it — whatever the person at the keyboard said. Underneath each set is a table of **LDAP attribute types** with a checkbox against each, and a ticked one becomes a claim whose value is read off that person's own entry under `ou=users`. So an `ldapmodify` against `uid=alice,ou=users` changes the next access token, and an LDAP client and an OIDC client pointed at this service are shown the same person rather than two people with the same name. That is a thing no amount of typing into a form can demonstrate, and until now only a Verifiable Credential could do it. The controls are the ones the table implies — **Update** installs exactly the ticked boxes, **Select all** and **Delete all** are the extremes — and all three are form posts rather than script, because `script-src 'none'` covers this page like every other one here: a browser-side "tick everything" would leave the boxes ticked and the set unchanged until somebody pressed Update, and would leave nothing in the audit log.

**The catalogue is `vc_claims.js`'s and is not a second copy of it**, which makes this the *third* page choosing from one list of attribute types: `/admin/vc` picks what an issued credential carries, `/admin/vc-verifier-config` picks what the mock Verifier asks for, and this picks what a token or an assertion carries. Two catalogues would be two lists of spellings, and one of them would eventually be wrong about `schacDateOfBirth` while both looked right on their own. The four *selections*, though, are deliberately independent of each other and of the other two pages — an access token carrying `employee_number` while the ID Token carries only `email` is a normal arrangement that a single list could not express, and keeping them apart is what makes "issue a credential carrying a claim the access token does not" reachable at all. Nothing is selected on a fresh start in any of the four, because this page changes what every client of this service receives and a mock that began issuing a `birthdate` in every access token because a feature was added would break the tests of everyone who upgraded.

**Three rules decide what a claim's value actually is, and they are stated on the page because two of them only show up in the collision.** The protocol's own claim wins: an ID Token always carries `name`, `given_name`, `family_name`, `preferred_username` and `email` built from the sign-in, so ticking `cn`, `givenName`, `sn`, `uid` or `mail` *on that set* changes nothing the client sees — while the same five reach an access token from the directory, because the protocol sets none of them there. Then a typed claim beats a directory attribute of the same name, since somebody who wrote `email` by hand said something more specific than somebody who ticked `mail`. Then the attribute, read from the entry, or invented from the username where the entry has nothing — deterministically, so one username is one invented person across restarts. A nested claim stays nested in a JWT (`address.locality` is a member of an `address` object, per OIDC Core 5.1.1) and becomes the attribute's literal name in an assertion, where the content model cannot nest; both families then call one claim by one name.

**Adding the checkboxes surfaced a bug that had been reachable all along, in both assertion builders.** `saml2.js` and `saml11.js` appended the configured attributes to their own without deduplicating, so a configured claim called `name` produced *two* `<saml:Attribute Name="name">` elements and the relying party read whichever the builder happened to emit first. Typing that name was always possible; ticking `cn` made it a checkbox away. Both now filter the configured attributes against what is already there — by name for SAML 2.0, and by **namespace and name together** for SAML 1.1, since that profile splits a claim URI into the two and a filter on the local name alone would drop an attribute that collided with nothing. It is the same rule the JWT builders have always followed, written as a filter because an assertion is a list of elements and not an object: there, a duplicate name is not an overwrite.

**Every change to a claim set writes a row in the audit log**, both halves of it and refusals included, naming which set, what was added and what was removed — and never a value, because a claim value on this service is whatever somebody typed into a web form. That row is *in addition* to the `admin.change` or `api.change` row the call log writes for the same POST, which is the arrangement the audit log's own section explains: one act, several facts, at different layers. It is recorded from `setClaimSet()` and from the selection's own installer rather than at the seven action branches, because those two are the funnels every branch already passes through — the same reason `recordAuthentication()` is one line and not fourteen.

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

`GET /admin-api` is the console above with the HTML taken off: every page's `?format=json` view and every one of its forms, at a path a script can use, with an OpenAPI 3.1 document at `/admin-api/openapi.json` and an explorer that calls it at `/admin-api/docs`. 55 operations, none of them protected, all of them changing the same state the console changes — because they call the same functions it does.

**It exists because a form is the right shape for a person and the wrong one for anything else.** Every page here has answered `?format=json` since it was written, so reading was never the problem; *changing* something was. A caller that wanted to revoke a token from a script, or narrow the issuer's claim set from a CI job before running a wallet against it, was left either parsing a 303 redirect for the message in its query string or knowing which hidden input a particular form carried. Both are ways of driving a browser without one.

**The rule the API is written under is about the future rather than about the code**: a control added to `/admin` gets an operation on `/admin-api` in the same commit. `GET /admin-api/audit` is what that rule produced for the audit page, and it is the one resource here with **no POST beside it** — not an operation nobody got round to, but the consequence of the page it mirrors having no form on it. An erase control on an unprotected audit log would make it unable to answer the one question it exists for, so there is nothing to change and therefore nothing to document as changeable. `GET /admin-api/users` grew one the day `/admin/users` grew its first form — a single
action, `create` — and `GET /admin-api/applications` **has** a POST beside it — six actions — and the thing worth knowing about them is that they are not a third store: each calls the same function in `applications.js` that a protocol path or an `ldapmodify` reaches, against the same `ou=applications` entries. An API that covers eight of nine controls is worse than one that covers none, because the ninth is discovered by somebody who has already written the code that assumed it was there. Two things make keeping that rule cheap, and the third thing is why there is a test for it in the parent project.

The first is that **this API decides nothing**. Every POST calls the same action function the console's form posts to — `tokenAction`, `usersAction`, `claimsAction`, `vcAction`, `vpConfigAction` — with the action taken from the URL instead of from a hidden field, and every GET calls the same JSON view the page's `?format=json` answers. Those views became functions in `admin.js` for this reason (`consoleJson`, `metricsJson`, `tokensView`, `auditView`, `usersView`, `groupsView`, `claimsJson`, `vcJson`, `vpConfigJson`); they had been built inline in the route handlers, which was fine while there was one caller and is exactly the shape that produces two objects that agree today and not next month. So `admin_api.js` holds no opinion about what a revocation means that `admin.js` does not, and the way to see that is not to read the code: revoke a token through the API and RFC 7662 introspection calls it inactive, because there is one set of revoked jtis in this service and it is the same one `/oauth2/revoke` writes to.

The second is that **the OpenAPI document is generated from the table that registers the routes**. `admin_api.js` holds one row per resource — the handler, the parameters, the request bodies with their examples, the prose — and `admin_api_spec.js` turns that into the document. An operation therefore cannot exist and be undocumented, nor be documented and not exist. A specification file kept beside the code it describes is wrong within a month, and the way it goes wrong is silent: somebody adds an action to the console, adds it to the API, and does not touch the YAML.

The third is the direction neither of those can check. **Nothing in this service can see a form appear on a page**, so a new console control with no operation here would go unnoticed by everything above. That is asserted from outside, by the parent project's `tests/admin_api.js`, and it reads the facts off this service rather than off a list in the test: the console's own page list comes back in `GET /admin-api/status`, and each action handler, asked to perform an action that does not exist, replies with the names of the ones that do — "Unknown action "x". The four are: add, remove, clear, replace." Add an action to a switch and that sentence grows; the test then fails until there is an operation for it. The same test checks every property the document describes against a live reply, which has already caught two names that were wrong and unnoticeable: an `expiresAt` that is really `expiresAtMs`, and a group drill-down documented with its members at the top level when they are inside `group`.

**Eight POST routes serve thirty-nine URLs**, and the shape is deliberate. Express registers `/admin-api/tokens/:action` once; the document lists `/admin-api/tokens/revoke`, `/restore`, `/revoke-kind`, `/revoke-subject`, `/revoke-user` and `/revoke-all` as the six operations they are, each with its own body schema and its own example. One pattern keeps `GET /sts-metadata` to one row per resource showing the parameter — the router is what that page reads, and twenty-four rows of near-identical prose there would bury the rest of the service — while the document describes URLs a caller can actually use. An action nobody has heard of is not a 404: it reaches the console's own handler and comes back as its refusal, naming the ones that exist, which is both the friendliest error and the sentence the parity check reads.

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
AS-REQ, a passwordless WebAuthn assertion.

That is **one hook and not twelve**, because `admin_stats.recordAuthentication()` is
already the single funnel every one of those call sites goes through at the moment a
credential is ACCEPTED. The hook is **inverted**, exactly as `helpers.js`'s
`setJwtRecorder` is: `ldap_server.js` requires `admin_stats.js` — it needs `identityOf`'s
normalisation, so that `alice`, `urn:sts-mock:user:alice` and `alice@REALM` seed one entry
and not three — so `admin_stats.js` cannot require it back without a cycle. It offers a
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
`urn:sts-mock:user:rcbj` in a token, `rcbj@STS.MOCK` in a Kerberos AS-REQ and `rcbj` on a
WS-Security `UsernameToken` have always been one entry: `identityOf()` strips the prefix
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

#### The `id` is the DN

RFC 7643 section 3.1 asks for an opaque, server-assigned, unique identifier the client
must not parse. The DN already is one — it is the key the entry is stored under — so that
is what a SCIM `id` is here, percent-encoded in a path segment:

```
GET /scim/v2/Users/uid%3Ddave%2Cou%3Dusers%2Cdc%3Dexample%2Cdc%3Dcom
```

Every other candidate is a *second definition of one fact*. A `uid` is not unique in this
tree (nothing stops `uid=alice,ou=users` and `cn=alice,ou=people` existing side by side);
a synthesised id would have to be stored on the entry and would go stale on a rename,
which is the failure `applicationEntry()`'s fallback exists to route around; a digest
would be unreadable in the one place a reader most wants to read one. The cost is stated
rather than hidden: **an LDAP rename gives the same person a new SCIM id**, which really
is a deviation from "stable for the lifetime of the resource" — and it is the honest
behaviour for a directory-backed server, because after a rename it *is* a different key.

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

**And it is still a turnstile rather than a lock**, which is the whole design. Anybody can
get a token with either scope. Any password but one passes Basic. Any username passes
Digest. Anybody can register a HOBA key. Nothing here decides that a caller *should* be
allowed to delete an account — it decides that they said who they were first. Do not put
this port on a public address on the strength of it.

Every switch is a `config.js` row and therefore already on `/admin/config` and
`POST /admin-api/config/set`: `scim.authRequired` (on by default; turning it **off**
restores the unauthenticated behaviour these endpoints used to have, which stays reachable
on purpose), `scim.authDiscovery`, `scim.authRealm`, `scim.scopeRead`, `scim.scopeWrite`,
one flag per scheme, `scim.digestPassword`, `scim.digestNonceSeconds` and
`scim.hobaMaxAgeSeconds`. **A credential that is presented and fails is refused whether or
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

**It has no controls, and that is the console parity rule holding rather than a gap.**
Everything about SCIM that can be changed is a `config.js` row — `scim.enabled` and three
limits — so `/admin/config` already has the form and `POST /admin-api/config/set` already
has the operation. A second form here would be a second door to one setting.
`GET /admin-api/scim` is therefore read-only, which it shares with `/admin-api/audit`, and
in both cases for the same reason.

One thing those settings do that is worth copying: `applyCapabilities()` is called both at
require time *and* at the top of the ServiceProviderConfig handler. Without the second
call, `scim.maxResults` would be enforced live — `queryParams()` reads it per request,
which is the rule for a runtime setting — while the published document went on advertising
the number the process started with. That is a captured `const` in disguise, and the exact
silent disagreement `config.js`'s header warns about.

### SPIFFE — three server-side surfaces, two of them authenticated differently

This service is a **SPIFFE issuing authority** for one trust domain
(`spiffe.trustDomain`, `example.org` by default). SPIFFE's server side is three
separate things, and they are worth separating because they have almost nothing
in common with each other:

| | |
|---|---|
| **The bundle endpoint** | plain HTTPS. One GET returning a JWK Set. This is the whole of the federation protocol's server half |
| **The Workload API** | gRPC, on a Unix socket and on TCP. What a *workload* talks to, to be given an identity |
| **The SPIRE Server API** | gRPC. What an *operator* and an *agent* talk to: registration entries, attestation, bundles, minting |

`GET /spiffe` describes all three and reports whether each of the four sockets
actually bound — which nothing else can do, because `/sts-metadata` is built by
walking the Express router and a gRPC listener registers no route.

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
every conforming client, which is why `spiffe.authRequired` — the mutual TLS the
other surface grew — deliberately does not reach it.

**The SPIRE Server API is mutual TLS with an X509-SVID, and this service does
the same.** A real `spire-server` binds a TCP port whose callers present an SVID
from the trust domain, takes the caller's SPIFFE ID off the certificate, and
authorizes every method against *what that caller is*. Its private Unix socket
is trusted outright — that is how the `spire-server` CLI works. Here: the TCP
port is TLS on this trust domain's own server SVID
(`spiffe://<trust domain>/spire/server`), the client certificate is verified
against the trust bundle and its own validity window, the SPIFFE ID comes from
the **URI subjectAltName** and never from the subject, and the method is checked
against SPIRE's own table. `spiffe.authRequired` is on by default and is
**restart-only**, because it decides how the socket is bound.

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
  `x-sts-mock-workload-selector` metadata header, with
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
  never one named in the request — and with `spiffe.authRequired` off it answers
  `Unimplemented` with that same sentence, which is still true in that mode.

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
authentications.

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
* **`AttestAgent` for a banned agent**, and — with `spiffe.authRequired` on — a
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

#### One process, two PKIs

The SPIFFE authority is **not** the certificate that 8443, 9443, LDAPS 636 and
(under `global.https`) the main port share. That one is a leaf with `CA:FALSE`
and `extKeyUsage serverAuth`; it cannot sign anything. More to the point, a
trust domain's CA and a host's TLS identity are two unrelated trust decisions,
and a service whose SPIFFE root was also its web certificate would teach exactly
the wrong lesson. So there are two, generated per start, both in memory.

The X.509 half is **EC P-256 by default**, which is what SPIRE issues and what
the X509-SVID specification recommends. That is why `x509.js`, `key_material.js`,
`jose_jwe.js` and `crypto_bytes.js` are vendored here from the OAuth2/OIDC
Debugger — byte-identical, the way `bbs2023.js` already is: `node-forge`, which
`helpers.js` and `tls_server.js` use, **cannot sign with an EC key at all**. What
comes with those files is the parent project's `tests/pki_x509.js`, which drives
~240 certificates — every key algorithm against every signature algorithm, every
extension, a four-deep chain — and checks each one with **OpenSSL** rather than by
reading back what the same code just wrote. Four real defects were found that
way, and all four produced certificates that parsed perfectly and were refused
elsewhere with a message about a signature.

**Rotation prepends and never replaces.** A new authority becomes the one
everything is signed with; the old one stays published in the bundle, because an
SVID minted a minute ago has to go on verifying. Dropping it is the difference
between a rotation and an outage. Four are retained, and past that the oldest is
dropped — which does invalidate whatever it signed, and the page says so.

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

`GET /ldap/spiffe` publishes the whole schema, because this directory is
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
on the connection. It still answers `Unimplemented`, with that same sentence,
when `spiffe.authRequired` is off.

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
  candidate, so no code changed — and that is also why, when the 2026-08-23
  reorganisation moved `bbs2023.js` into `common/vendored/`, the contexts moved with
  it rather than staying at the root: keeping them a SIBLING is what let a vendored
  file stay byte-identical.

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
