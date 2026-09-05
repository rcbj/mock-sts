# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in
this repository.

**It is the thin one.** Almost every fact about a module lives in the `CLAUDE.md`
of the directory that module is in, and this file keeps only what is genuinely
cross-cutting: the require order, the rules about libraries and hooks, the two
CSP rules, the endpoint-drift rule, the code style, the submodule warnings, and
the state of the tests. **There is one copy of each fact.** If something here
looks like a summary of a directory file, it is a bug — say so rather than
reconciling the two.

## Where things are

The 2026-08-23 reorganisation moved every module out of the package root. The
files did not change; the paths did.

| Directory | What is in it |
|---|---|
| `common/` | Everything more than one family reads: `config.js`, `helpers.js`, **`crypto.js`**, `app.js`, `realms.js`, `admin_stats.js`, `audit.js`, `applications.js`, `delegation.js`, **`app_permissions.js`** (the CONFIGURED delegation register — who MAY reach what, in Entra ID's shape, against `delegation.js`'s record of what DID), `user_graph.js`, `claim_attributes.js`, `group_claims.js`, `config_file.js`, and — since 2026-08-30 — **`worker.js` and `worker_pool.js`, the child-process pool the post-quantum signing runs in** (see *One listener process, N stateless workers* below). **`crypto.js` is THE ONE PLACE THIS SERVICE SIGNS, VERIFIES, ENCRYPTS AND DECRYPTS since 2026-08-27** — before that it did all four in about twenty places, including six XML signers and four XML signature verifiers. `common/CLAUDE.md` argues it. **And since 2026-09-01 `consent.js`, the register of what a PERSON agreed an application may ask for on their behalf** — the third register in the `delegation.js` / `app_permissions.js` family and the first whose rows have a person in them, holding no store of its own because both halves are attributes in the directory (`oauthConsent` on a person, `oauthGlobalConsent` on an application). |
| `common/vendored/` | Byte-identical copies of the parent project's files, plus the JSON-LD `contexts/`. **Do not edit them here.** Since 2026-08-27 that includes `xmldsig.js`, the parent's own XML Signature and XML Encryption module, which is now the signer behind every signed document this service emits — so both ends of a SAML exchange canonicalize with the same code. |
| `home/` | The front door: `GET /` and the one image on it. |
| `logout/` | The protocol-independent sign-out: `GET|POST /logout`, and the one model of what a live session IS across every family — for ONE identity (`inventoryFor()`, what `/admin/logout` draws) and, since 2026-09-04, for the whole service (`liveSessions()`, what **`/admin/sessions`** and `GET /admin-api/sessions` draw, with a Revoke on every row that goes through the same `terminate()`). |
| `oauth-oidc/` | The authorization server, RFC 9700 mode, DPoP, mTLS, client authentication, the multi-AS profiles, **the CONSENT SCREEN at `/oauth2/consent`** (2026-09-01 — the one thing between a signed-in person and an issued credential, and the one policy in this service that is ON by default), and **the UserInfo endpoint's four layers** — a claim set of its own configured at `/admin/userinfo-claims`, the scope-driven set, OIDC Core 5.5's claims request, and `sub`. |
| `authn/` | The authentication service and the WebAuthn relying party. Owns the SESSION. **One endpoint in its own path space lives elsewhere**: `/authn/spnego` is `kerberos/spnego_authn.js`, for a require-order reason both files argue. |
| `saml/` | The two assertion builders, and A BROWSER-FACING IDENTITY PROVIDER FOR EACH: SAML 2.0's Web Browser SSO profile (all three bindings, Single Logout, metadata per service provider) and SAML 1.1's two browser profiles (Browser/POST, Browser/Artifact, a SOAP responder that is also an attribute authority, metadata per relying party). **They are separate implementations, not one with a version flag** — SAML 1.1 has no request message, no Single Logout, and a different spelling for almost every shared element; `saml/CLAUDE.md` has the table. |
| `ws-trust/` | WS-Trust 1.0–1.4. |
| `ws-federation/` | WS-Federation 1.2, the passive requestor profile, and the mock relying party. |
| `federation/` | **Federation relationships, in either direction, in five protocols.** The register (`ou=federations` IS the store), the attribute mapping, the four endpoints, the graph the console's picture is drawn from — and the FIRST OF THREE OUTBOUND REQUESTS in this repository, in a module of its own that will not take a URL from anywhere but a relationship entry. It is the STRONGEST of the three and the other two each argue their own case rather than citing it — SSF's is `ssf/ssf_http.js` and XACML's nudge is `xacml/xacml_pep_http.js`. |
| `kerberos/` | The KDC, the acceptor, SPNEGO in three layers — the negotiation, the page that explains it, and **the SIGN-IN that turns a ticket into this service's session** — and the eight codec modules they rest on, **all eight VENDORED from the parent project and not editable here**, despite not being under `common/vendored/`. See `kerberos/CLAUDE.md`. |
| `ldap/` | The embedded directory. Also the STORE for people, groups, applications and the SPIFFE registry. **And, since 2026-09-01, the FIVE ADMIN CONSOLE PAGES that show that store** — `/admin/ldap/directory` (every entry, every attribute, paged), `/admin/ldap/applications`, `/admin/ldap/federations`, `/admin/ldap/spiffe` (each a container with the SCHEMA it uses, because this directory is schemaless) and `/admin/ldap/service` (the two raw sockets as they actually are, which nothing that walks the router can see). They were `/ldap*`, in a shell of their own, outside the console and outside its gate; a console page is a `path` and a `label` in `admin-ui/admin.js`'s `SECTIONS` whoever builds the body, which is the arrangement `/admin/sts-metadata` has had since 2026-08-24. |
| `persistence/` | **THE ONE PLACE THIS SERVICE WRITES ANYTHING DOWN, since 2026-08-27, and the first time it ever has.** Three modes — `memory` (the default, and what this service always did), `ldif` (an RFC 2849 file per realm, no database) and `postgres` — behind one driver interface. THREE THINGS PERSIST: the embedded directory, the trust realm registry, and the runtime appconfig overrides. **NOTHING THIS SERVICE MINTS EVER DOES**, in any mode, because the signing key is regenerated on every start. It is PERSISTENCE and not COORDINATION, and `persistence/CLAUDE.md` says what the second one still needs. |
| `scim/` | `/scim/v2`, its authentication, and its attribute mapping. |
| `ssf/` | **The Shared Signals Framework (OpenID SSF 1.0, final September 2025), and the one family here that TALKS BACK** — every other answers a request, and this one agrees a STREAM and then delivers a Security Event Token at the moment something happens. Six modules: the routes, an RFC 9493 subject grammar written out here rather than vendored (a grammar is a READING, and one implementation read by both ends hides the misunderstandings they share), the RFC 8417 envelope, the streams and their queues per realm, the gate, and **the SECOND outbound request in this repository** — which is a weaker case than federation's and `ssf/CLAUDE.md` argues rather than cites, because RFC 8935 push IS the receiver telling the transmitter where to post. (The THIRD is XACML's change nudge, and it is weaker still and argued in its turn: no specification asks for it at all, and what pays for it is that it is never the mechanism — a PEP pulls and converges without it.) **SSF is the PIPE and not the vocabulary**: it defines two events of its own, both about the pipe, and CAEP (what happened to a SESSION, since 2026-09-03) and RISC (what happened to an ACCOUNT, since 2026-09-04) are the two vocabularies spoken over it. **Eight modules now**: the seventh is `caep.js`, the eighth `risc.js`, and they are siblings rather than one generalized register — a session begins, is used and ends and there are many per person, and an account IS the person and outlives every session on it. Two observers, on two different stores: CAEP watches `authn.js` and RISC watches `ldap/ldap_server.js`, which is the authentication layer and the provisioning layer, and the whole difference between the two profiles is which of them the sentence is about. |
| `spiffe/` | Six libraries, one server module, and the vendored `protos/`. |
| `tls/` | The 8443 and 9443 listeners, and the certificate three other sockets share. |
| `oid4vc/` | OpenID4VCI, OpenID4VP, DID Core. |
| `admin-ui/` | The console at `/admin`, the two roles that decide who may use it, **every setting drawn on the page for the protocol it configures** (2026-08-27 — `SETTING_HOMES` is the table, `/admin/config` keeps the rows belonging to no protocol and the index of the rest), and the TWO DRAWINGS in this service — `/admin/delegation/map` and `/admin/federation/map`, both laid out on the server. They share a palette, a hexagon and a text metric and NOTHING ELSE: one flattens a layered layout on purpose and the other is a layered layout, so each has its own renderer. `admin-ui/CLAUDE.md` argues why that is not duplication. **And since 2026-08-30 the CRYPTO REPORT** (`crypto_metadata.js`, `/admin/crypto-metadata`): what this service does when it signs, verifies, encrypts or decrypts, for every identity service it advertises, with every algorithm table READ FROM THE MODULE THAT PERFORMS THE ALGORITHM — the same argument `sts_metadata.js` makes about the router, one layer down. |
| `mgmt-api/` | `/admin-api`, its generated OpenAPI document, and the explorer. |
| `tests/` | **THE ONLY TEST DIRECTORY HERE**, and since 2026-08-28 it holds BOTH halves of this service's coverage. `tests/*.js` is the in-process half — assertions about this repository's own module contracts, `npm test`, no port and no container and under a second. **`tests/vendored/` is the protocol half**: seventeen jobs driven over HTTP against a CONTAINER built from this tree by `docker-compose.yml` (a throwaway in-process copy under `--no-docker`, and under coverage), plus the wallet modules five of them verify against. NINE are byte-identical copies of the parent project's mock-only jobs and are NOT edited here; **EIGHT are this repository's own** — the ones that drive this service's `/admin` console and `/admin-api`, marked `local: true` since 2026-08-28, with no copy over there to sync from and the editing rule inverted for them. `tests/vendored/MANIFEST.js` says which is which and where each copy came from, and `--vendor-check` reports drift in the nine. See *Tests* below for what changed and `tests/CLAUDE.md` for the rules that are not optional there. **`tests/tools/` is not tests**: the report generator, the coverage renderer, the compose-stack helpers (`compose.sh`, shared by both launchers) and the throwaway-service launcher `./local-run-tests.sh`, `./docker-run-tests.sh` and `./run-coverage.sh` drive — in a subdirectory precisely so that `run.js`'s discovery rule needs no exclusion list. **`tests/Dockerfile`, its own `.dockerignore` and `tests/run-tests-in-container.sh` are not tests either**: they are the RUNNER as a container, which `docker-compose-run-tests.yml` brings up beside the service so that a host with docker and nothing else runs all forty-one jobs — see *Tests* item 5. `federation-e2e/` sat beside it until trust realms made its three-container stack unnecessary; that test is `tests/federation_sso.js` in the parent project's suite now. |
| `xacml/` | **XACML 3.0 and ALFA: the engine, the policy repository, the PIP, an embedded PEP and the PAP.** Fourteen DOM-free modules plus `xacml.js` and `xacml_admin.js`, the two that register routes — seven under `/xacml`, five console pages under `/admin/xacml`, seventeen operations under `/admin-api/xacml` — required at 23c. **`ou=policies` in the embedded directory IS the repository**, the way `ou=federations` is the federation register. **THE ONLY FAMILY HERE THAT ANSWERS A QUESTION ABOUT SOMEBODY ELSE'S BOUNDARY** — every other protocol authenticates or provisions somebody, and this one is handed a subject authenticated elsewhere and asked whether they may. Held to the VENDORED OASIS conformance suite (**454 of 455 mandatory cases**), which is **Apache-2.0 rather than this repository's MIT** and says so in `LICENSE.md`. **ONE MODEL, THREE RENDERINGS**: the core XML, the JSON Profile, and **ALFA** — which is a VIEW and never a second stored copy, and whose contract is that anything it writes it reads back *and the policy decides identically either way*, asserted on seven probes because a swapped comparison round-trips perfectly and decides the opposite. **The guided editor has NO JAVASCRIPT**: this console is `script-src 'none'`, so every "pick the next valid element" dropdown is computed on the server by the same code that validates the result. `xacml/CLAUDE.md` indexes the twelve defects the tests caught. **THE REMOTE PEP LANDED 2026-09-05 and its container is `xacml-pep/`, below** — what is in this directory is the PDP's side: `ou=peps`, three endpoints under `/xacml/pep`, a fifth console page, and the nudge, which is this repository's THIRD outbound request. |
| `xacml-pep/` | **THE ONLY DIRECTORY HERE THAT IS NOT PART OF THE MOCK.** A second container: a remote XACML Policy Enforcement Point that holds its own copy of the engine, PULLS the policy repository from `/xacml/pep/policies` and decides in its own process. `server.js` does not require it and nothing here does; `docker compose --profile xacml up` starts it. **THE PULL IS THE CONTRACT** — the nudge this service sends on a change is an optimisation over the polling interval and never a replacement for it, which is what makes a third outbound requester affordable. The engine is copied out of `xacml/` AT BUILD TIME, so there is one copy of the evaluator in this tree; `tests/xacml_pep.js` asserts the Dockerfile's COPY set against the module list. **Its thirty-line `common/helpers.js` shim is the most valuable thing in phase five** — it is what makes "the engine is a library with no I/O" a checked claim rather than a comment at the top of seven files. `xacml-pep/CLAUDE.md` argues all of it. |
| `postgres/` | **Two shell scripts the database container runs, and nothing else.** `generate-tls.sh` makes its server key pair on first start — the same decision every other key here follows, because a certificate committed to a repository is a private key committed to a repository — and `require-tls.sh` rewrites every `host` rule in `pg_hba.conf` to `hostssl` so that TLS is REQUIRED rather than merely available. Both are mounted into the image by `docker-compose.yml`; neither is run by this service. `persistence/CLAUDE.md` argues them. |
| `docs/` | The GitHub Pages site. See `docs/CLAUDE.md`. |
| `env/` | The appconfig files. `CONFIG_FILE` selects one, and it is unioned on top of `defaults.js`, which is GENERATED by `generate_defaults.js` and is not selected by anything. |

At the package root there are exactly two modules, and both earn it:
**`server.js`**, the shell that requires the others and listens, and
**`sts_metadata.js`**, which reads the router to list what everything else
registered and is therefore required last.

**Read the directory's own `CLAUDE.md` before changing anything in it.** They are
not summaries — the reasoning that used to be in this file is in them, verbatim,
and most of it is the record of something having gone wrong once.

`README.md` is the substantive document and is still at the root. `docs/` is the
user-facing half — how to USE this service — and is published as a GitHub Pages
site; this file and the directory files are the maintainer-facing half.

## Overview

A mock identity service that speaks seventeen protocol families — Kerberos v5 (a KDC on
raw TCP/UDP 88 and over MS-KKDCP, plus a Kerberos-protected service and the same
acceptor over HTTP as **SPNEGO**, RFC 4559/4178), WS-Trust
1.0–1.4, **SAML 2.0** (assertions, and the Web Browser SSO profile over all three
bindings with Single Logout and per-service-provider metadata) and **SAML 1.1**
(assertions, and BOTH browser profiles — Browser/POST and Browser/Artifact —
with a SOAP responder behind the second that is also an attribute authority,
answering AttributeQuery and AuthenticationQuery),
WS-Federation 1.2 (the passive requestor profile),
**FEDERATION** (this service as EITHER END of a relationship with a foreign
identity service, in five of those protocols — consuming somebody else's
assertions as a service provider, or asserting to a foreign service provider
with a per-partner attribute release policy),
OAuth 2.0 / OIDC (a full authorization server), WebAuthn Level 3 (the relying party's
half, on the login screen), DPoP, OpenID4VCI 1.0, OpenID4VP 1.0, W3C DID Core with
DIF domain linkage, and **LDAP v3** (RFC 4511 — an embedded directory on raw TCP 389 and,
over TLS, on raw TCP 636 as **LDAPS**, one set of handlers and one store behind
both, built on the node-ldapjs SUBMODULE and used unmodified), **SCIM 2.0**
(RFC 7642/7643/7644 — a provisioning endpoint at `/scim/v2` that writes into that
same directory, entry for entry, with no store of its own), and **TLS / mutual TLS**
(two HTTPS listeners of its own, 8443 and 9443, whose whole content is what the
SERVER saw of the connection — see README.md; and, when `global.https` is set,
the main port too, on the same certificate), and **SHARED SIGNALS** (SSF 1.0 — a TRANSMITTER: stream
management, subjects in all eight RFC 9493 formats and the complex subject,
verification, and delivery by RFC 8935 push or RFC 8936 poll, plus a receiver
of its own so that a client can be the transmitter), and **SPIFFE** (an issuing
authority
for one trust domain, in all three of its server-side shapes: the bundle endpoint
over plain HTTPS, and the **Workload API** and **SPIRE Server API** over gRPC on
FOUR MORE SOCKETS — a Unix socket and a TCP port each). It exists to exercise
*clients*: it checks no password, validates no access token and **attests no
workload**.

**FIVE surfaces are the exception to that sentence and all of them are worth
knowing before reading further — and the last two are each a different KIND of
exception from the first three.** The SCIM endpoints REQUIRE a credential, in any
of the
six schemes RFC 7644 section 2 names, and the OAuth ones must carry `scim:read`
or `scim:write`; they create and DELETE accounts, which is why. The **SPIRE
Server API** requires an **X509-SVID over mutual TLS** on its TCP port and
authorizes every method against SPIRE's own per-method table — because what
comes out of that surface is a credential another service will believe. And the
**ADMIN CONSOLE** at `/admin` requires a browser sign-on session from
`/authn/login` and one of two roles — **Admin Read** and **Admin Write**, held as
two ordinary groups in the embedded directory — because it is the one surface
here that can change what every protocol endpoint does. All three are
a turnstile rather than a lock: anybody can get a token with either SCIM scope,
any password but one passes Basic, anybody can register a HOBA key, anybody
can ask the local socket to mint an SVID, and **no password is checked at the
console's sign-in screen either** — what the gate proves is that somebody typed a
name that holds a role. None of them changes anything else, and
each can be turned off (`scim.authRequired`, `spiffe.authRequired`,
`admin.authRequired`). See `scim/CLAUDE.md`, `spiffe/CLAUDE.md` and
`admin-ui/CLAUDE.md`.

**THE FOURTH IS FEDERATION, AND IT IS NOT A TURNSTILE.** Those three refuse a
caller in order to make a client exercise a refusal; each could be made
permissive tomorrow and the only thing lost would be an error path.
`/federation/acs/{id}` cannot, because **there is no permissive answer
available**: "accept any SAML Response" means letting anybody who can reach this
port POST a document naming themselves as anybody and get a browser sign-on
session for it — and that session is the SAME one `/oauth2/authorize`,
`/wsfed`, `/saml2/sso`, `/saml11/sso` and `/admin` all read. So federation is
the one feature here that must be CONFIGURED before it does anything: a
relationship is created disabled, and an assertion is refused unless it verifies
against the certificate configured on it. **The gate is on the SIGNER, not on
the subject** — past it, any username in a verified assertion is accepted and an
entry is created for them, exactly as permissively as everywhere else.
`federation/CLAUDE.md` argues all of it, and it is the file to read before
"fixing" a refusal in that directory.

**AND THERE IS A FIFTH SINCE 2026-08-26, WHICH IS A DIFFERENT KIND AGAIN: IT IS
NOT A REFUSAL AT ALL.** `/authn/spnego` signs a person in on a KERBEROS TICKET —
integrated authentication, available to every application and registered for
none — and it is the one door here that verifies a credential rather than
accepting a name. Not because it is guarding anything: because **Kerberos cannot
be permissive the way the rest of this service is.** The password there IS the
key, so pre-authentication and the AS-REP's enc-part are both encrypted under it
and a KDC that accepted anything would still have to pick a key the client could
not guess. `krb5_principals.js` therefore does the permissive equivalent — one
password shared by every user account, an account created for any name on first
sight — and the ACCEPTOR still decrypts a real ticket under a real long-term key
and refuses a replay. So a session minted at that door rests on something
checked, while the account policy behind it is as open as everything else. **The
verification is real and the account policy is not**, and those are two
different sentences that this repository's prose has to keep apart.
`kerberos/CLAUDE.md` argues it; `krb5.spnegoAuthentication` closes the door, and
`/spnego/protected` then still performs the whole handshake and gives no
session.

**`/admin-api` is NOT gated and that is deliberate** — it is what a test drives,
and it is the way back in when nobody holds a role. Which means anybody who can
reach this port can grant themselves both roles through it; see
`mgmt-api/CLAUDE.md`, where that is argued rather than assumed.

**The Workload API is the opposite case and the distinction matters**: it
authenticates nobody because its specification says it MUST NOT — a workload has
no root of trust until that call gives it one. What it lacks there is
ATTESTATION, not authentication.

**THERE IS A SAML 2.0 WEB BROWSER SSO PROFILE SINCE 2026-08-24**, and this
paragraph used to say the opposite at some length — so if a document here still
reads as though the gap beside WS-Trust and WS-Federation is open, that document
is the one that is wrong. `/saml2` is a full identity provider: the Single
Sign-On service over HTTP Redirect and HTTP POST, the Response over HTTP POST,
HTTP Redirect or HTTP Artifact, a SOAP Artifact Resolution Service behind the
third, Single Logout, and **signed metadata PER SERVICE PROVIDER, minted for any
entityID asked for**. It accepts any entityID and creates the application entry
on first sight. **It ENCRYPTS since 2026-08-27** — an EncryptedAssertion in the
Response and an EncryptedID in a LogoutRequest, in four block ciphers and two
key transports, per application — and it DECRYPTS an EncryptedID a service
provider sends it; `saml/CLAUDE.md` has the design, and the paragraph that said
otherwise for months is gone rather than qualified. What it still does not do —
verify a
request signature, consume SP metadata, or answer an AttributeQuery — is listed
in `saml/CLAUDE.md` rather than implied.

**AND SINCE THE SAME DAY THERE IS A SAML 1.1 ONE AT `/saml11`**, which is a
SEPARATE IMPLEMENTATION rather than a mode of the above — the single most
important thing to know before reading either. SAML 1.1 has **no request
message**: the browser profiles are identity-provider-initiated, a flow begins
when a browser arrives carrying a `TARGET`, and the relying party cannot identify
itself in the protocol at all. From that one fact follow no `ForceAuthn`, no
`IsPassive`, no `RequestedAuthnContext`, no error response (a failure is a PAGE,
because there is nothing to answer), and an audience that is taken from
Shibboleth's `providerId`, from the path segment, or GUESSED from the TARGET's
origin. It has **no Single Logout** — that arrived with SAML 2.0 — and it has
something 2.0 does not: a SOAP responder answering all four SAML 1.1 request
types, which makes it an **attribute authority**. `saml/CLAUDE.md` carries the
table of the six differences.

**The WS-FEDERATION metadata still publishes no IDPSSODescriptor**, which is now
a fact about that document rather than about this service: the IDPSSODescriptors
are at `/saml2/metadata` and `/saml11/metadata`.

Extracted from the [OAuth2/OIDC Debugger](https://idptools.com). The tests that cover
this service still live in that project (see *Tests* below), which is the single most
important thing to know about this repo's current state.


## Running it

```bash
npm install
CONFIG_FILE=./env/local.js node server.js      # 8081; STS_PORT overrides
```

`CONFIG_FILE` selects a file in `env/`. At the default `debug` every endpoint
call and every artifact before and after signing is logged — that is the point of
a mock, so do not quieten it by default.

**THAT PORT IS HTTPS SINCE 2026-08-30, AND THE INVOCATION ABOVE IS UNCHANGED.**
All three appconfig files in `env/` carry `global.https: true`, and both compose
files set `STS_HTTPS` to the same answer so a container's healthcheck probes the
scheme its service is bound in. The SETTING is untouched — it is still `derived:
true` with `oauth2.rfc9700` as its default, so a service handed somebody else's
appconfig file (the parent's in-process Kerberos jobs) still gets plain HTTP, and
`tests/config_realm_layer.js` still asserts what it always did. What changed is
what the files SAY. The argument is one sentence: 8443, 9443 and LDAPS 636 were
TLS on a certificate the main port did not use, so a caller who had trusted this
service's key for three sockets still met an unencrypted fourth on the port every
protocol family actually answers on. `STS_HTTPS=false` is the way back and is a
supported configuration, not an escape hatch.

What it costs is that the FIRST fetch of the certificate cannot be verified —
there is no plain listener left and the key does not exist until the process
starts — which is `docs/configuration.md`'s `global.https` section and is not
repeated here. For a test run, `tests/tools/trust.js` is what makes that fetch
once and hands every job `NODE_EXTRA_CA_CERTS` and `STS_SPKI_PIN`; see *Tests*.

**THAT FILE IS A LAYER, NOT THE WHOLE CONFIGURATION, AND A SETTING WITH NO VALUE
ANYWHERE STOPS THE SERVICE FROM STARTING.** Since 2026-08-24 the appconfig layer
is `env/defaults.js` with the selected file unioned over it, the selected file
winning key by key; above both sit the environment variables, and above those the
runtime overrides the console and `/admin-api` set in memory — the console
draws each group of settings on the page for the protocol it configures, and
`/admin/config` is the index of that plus the rows belonging to no protocol. **There is no
sixth level** — no constant in a module underneath the table — so a row added to
`common/config.js`'s `SETTINGS` with no row in `env/defaults.js` refuses to start
and names itself. `env/defaults.js` is GENERATED from that table (`node
env/generate_defaults.js`), which is why adding a setting is still one edit: add
the row, regenerate. The union is also what keeps a config file that is NOT this
service's loadable — the parent project's in-process Kerberos jobs point
`CONFIG_FILE` at the test suite's own config, which carries exactly one of our
keys (`logLevel`, the one key every appconfig file in this ecosystem has).
`common/CLAUDE.md` argues all of it; README.md's *Configuration* lists every
setting, its environment variable and its default.


The invocation above did not change when the modules moved, and that took one new
file to keep true: `common/config_file.js` makes `CONFIG_FILE` absolute before
anything reads it, because a relative path resolves against the directory of the
module doing the requiring and thirteen modules read it directly. See
`common/CLAUDE.md`.

## Architecture, and the rules that hold it together

`server.js` is a shell: it requires the modules and listens. Nothing else lives at
the root except `sts_metadata.js`. What each directory holds is the table above;
what each module is for is that directory's `CLAUDE.md`.

1. **Requiring a module registers its endpoints.** Each calls `app.get(...)` at its
   top level against the shared app from `app.js`, rather than exporting a
   `register()`. So **the require order in `server.js` is the route order**, and the
   middleware has to live in `app.js`, because express applies middleware only to
   routes added after it.

2. **`vc_configs.js` and `vc_offers.js` exist to break require cycles, not to group
   code.** The credential configurations are read by both the issuer and the
   authorization server; the Credential Offer's pre-authorized codes are minted by
   the offer pages and redeemed at the token endpoint. A cycle in node does not fail
   loudly — it hands back a half-initialised module whose exports are `undefined`,
   and the symptom arrives later as something that is not a function.

3. **`dpop.js` is a library, not a protocol module.** It registers nothing, so its
   position in the require order does not matter, and it requires only `helpers.js`
   (plus npm leaves) so it cannot join a cycle. Keep it that way. It is also why
   `presentedAccessToken()` — the Bearer-or-DPoP check the four protected endpoints
   share — lives there rather than in `vc_issuer.js` where it was written: the
   fourth caller is in `oauth2.js`, which vc_issuer.js cannot be required from
   without building a cycle or moving OID4VCI ahead of OAuth2 in the route order.

3e. **`admin_stats.js` now has three inverted hooks and one require of a
   library, and they are four different problems rather than a pattern.**
   `helpers.js` offers `setJwtRecorder()` and this file fills it, because
   `helpers.js` cannot require the counter that `signJwt()` has to reach.
   `admin_stats.js` offers `setUserObserver()` and `ldap_server.js` fills it, so
   that seeding a directory entry cannot drag `/ldap`'s routes to the front of
   the router. `admin_stats.js` offers `setAttributeResolver()` and
   `claim_attributes.js` fills it, because `vc_claims.js` requires this file.
   `admin_stats.js` offers `setGroupResolver()` and `group_claims.js` fills it,
   because that module requires this file AND what it needs is the directory,
   which only `ldap_server.js` can answer. And `audit.js` is a plain require in
   the ordinary direction, because it requires nothing here. Each is justified
   by a specific thing that would otherwise break; **do not add a sixth by
   analogy** — a slot is what you reach for when a require would close a cycle
   or move a route, and it costs a reader an indirection every time. The group
   resolver is the one to check a new proposal against: it was added only after
   showing it failed that test BOTH ways round.

   **`admin.js`'s SIXTH slot is `setLogoutReader()`, filled by
   `logout/logout.js`, and it is the second one that passed that test both ways
   round.** That module requires `ldap/ldap_server.js` for the bound
   connections that ARE the LDAP session, and `ldap_server.js` requires
   `admin.js` — so a require in the obvious direction closes a cycle AND drags
   every `/ldap` route into the router ahead of the console's own. It carries
   ONE object, validated whole when it is installed, because a partial one
   would leave `/admin/logout` listing what is live and unable to end any of
   it. See `logout/CLAUDE.md` and `admin-ui/CLAUDE.md`.

   **`admin.js`'s SEVENTH SLOT IS `setCryptoReporter()`, filled by
   `admin-ui/crypto_metadata.js`, and it is the third to pass that test both
   ways round.** A require from `mgmt-api/admin_api.js` (19) to that module
   (20a) would MOVE ROUTES — its own page's, and `tls/tls_server.js`'s three,
   which it requires for the server certificate — ahead of the management
   API's own and of ldap, scim and spiffe; and a require from `admin.js` to it
   would CLOSE A CYCLE, because it requires `admin.js` for the shell. It
   carries ONE function, the whole report, so that the page and
   `/admin-api/crypto` cannot disagree about what this service's cryptography
   is.

   **`admin.js`'s EIGHTH SLOT IS `setSignalsReporter()`, FILLED BY
   `ssf/ssf.js`, AND IT IS THE FOURTH TO PASS THAT TEST BOTH WAYS ROUND.** A
   require from `admin.js` to that module would CLOSE A CYCLE — it requires
   `admin.js` for the page shell and the gate — and a require from
   `mgmt-api/admin_api.js` (19) to it would MOVE ROUTES: every `/ssf` endpoint
   and the `/.well-known/ssf-configuration` document ahead of the management
   API's own and of ldap, scim and spiffe. It carries ONE object, validated
   whole, because a filler that installed the reader without the action would
   leave `/admin/ssf` able to LIST streams and unable to change any of them.
   **Its `action` returns a PROMISE and it is the only slot here that does**:
   transmitting a Security Event Token signs a JWS — possibly on the worker
   pool — and then POSTs it to somebody else's endpoint, and answering before
   either had happened would be the page reporting "sent" about nothing.

   **`admin.js`'s NINTH SLOT IS `setDirectoryPages()`, FILLED BY
   `ldap/ldap_server.js`, AND IT IS THE FIFTH TO PASS THAT TEST BOTH WAYS
   ROUND.** On 2026-09-01 the five HTML pages that were `/ldap`,
   `/ldap/directory`, `/ldap/applications`, `/ldap/federations` and
   `/ldap/spiffe` became ADMIN CONSOLE PAGES under `/admin/ldap/` — drawn by
   that module still, in this console's shell through `admin.respond()`,
   exactly as `sts_metadata.js` draws `/admin/sts-metadata`. Rule 7 then owed
   each of them an operation on `/admin-api`, and this slot is how the
   management API reaches the five view functions: a require from `admin.js` to
   `ldap_server.js` would CLOSE A CYCLE (that module requires this one for the
   shell and the gate), and a require from `mgmt-api/admin_api.js` (19) to it
   would MOVE ROUTES, since it sits at 21 precisely so the management API's own
   routes are registered first. It carries FIVE functions and is validated
   whole, for `setLogoutReader()`'s reason: a filler that installed four would
   leave one operation answering "no directory is loaded" on a service whose
   directory plainly is. **What the move itself bought is a refusal**: a dump of
   every attribute of every entry prints `oauthClientSecret` and
   `fedClientSecret` in the clear, and those pages were the one surface here
   handing them to anybody who could reach the port. `/admin-api` is still
   ungated and mirrors all five, which is what a test drives.

   **THAT MODULE OFFERS A SLOT OF ITS OWN, `setProtocolFamilies()`, AND
   `sts_metadata.js` FILLS IT** — the only slot in this service that is not on
   `admin.js`. Same test, one direction: a `require('./sts_metadata')` from
   `crypto_metadata.js` would load at 20a the one module whose whole constraint
   is that it is required LAST. What crosses it is the protocol family list, so
   that "every identity service this mock advertises" means the same fourteen
   on both pages and a disagreement is REPORTED rather than reconciled.

   **`setUserObserver()` NOW CARRIES THREE KINDS OF EVENT AND IS STILL ONE
   SLOT**, which is the same rule read the other way: `ldap_server.js` is
   offered an `event` of `authentication`, `issuance` (an X509-SVID was minted
   for a SPIFFE identity) or `credential-status` (the SPIFFE registry ended or
   restored an identity's ability to obtain one). Two more slots would have been
   two more indirections for one cycle. **An absent `event` means an
   authentication**, so an older copy of either module behaves as it did. See
   `common/CLAUDE.md` and `spiffe/CLAUDE.md`.


---

---

## Trust realms: several logical copies of this service in one process

Since 2026-08-24 this service can run as more than one logical identity
service at once. A **trust realm** has its own configuration, its own signing
key, its own sessions, authorization codes, tokens, offers, artifacts,
statistics and audit log, answers on the SAME sockets as every other, and is
told apart by a segment at the front of the path:

```
http://host:8081/oauth2/token                the DEFAULT realm
http://host:8081/realm/acme/oauth2/token     the realm `acme`
```

`/admin/realms` defines them, `POST /admin-api/realms/create` does it without a
browser, and `GET /realms` is the ungated directory a client discovers them
from. The console carries a realm switcher on every page and shows ONE realm at
a time — including every settings form, which reads AND WRITES the realm it is
reached in.

**THE DEFAULT REALM HAS AN EMPTY PREFIX, AND A SERVICE WITH NO REALMS DEFINED
BEHAVES EXACTLY AS IT DID.** That is a property of one predicate in
`common/realms.js` rather than a claim spread over twenty files, and it is the
first thing to check if something here ever seems to have changed for a caller
that has never heard of realms.

**The whole design is argued in `common/CLAUDE.md`** and is not summarised here.
The three things worth knowing before touching anything, because each of them
reaches outside that file:

1. **The realm is AMBIENT**, in an `AsyncLocalStorage` that `app.js`'s FIRST
   middleware enters. That middleware also strips the prefix before the router
   sees the URL, which is why no route registration in this service carries a
   realm and no protocol module was edited. Nothing may be registered above it.
2. **A store becomes per realm at its declaration and nowhere else** —
   `const sessions = realms.map()` in place of `new Map()`, and its hundred
   readers are unchanged and correct. About thirty-five stores were converted
   this way. **The ones left process-wide were left because the DIRECTORY was
   shared, and that reason expired on 2026-08-25** when the directory became a
   subtree per realm: `admin_stats.js`'s identity register and its revocation
   set were converted on 2026-08-25 for exactly that reason, and until they
   were, every realm's `/admin/users` listed every other realm's people beside a
   directory reader that reported each of them missing. A store still declared
   `new Map()` today needs an argument that does not rest on the directory —
   `tests/realm_isolation.js` is the guard, and `common/CLAUDE.md` carries the
   reasoning.

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
3. **THE EMBEDDED DIRECTORY IS PER REALM TOO — A STORE OF ITS OWN BEHIND THE
   ONE SOCKET, and this paragraph said the opposite until 2026-08-25.** It was
   a subtree of one shared Map for two days; it is `realms.map()` now, so a
   lookup in one realm cannot reach another's entry rather than merely being
   asked not to. The DN layout below is unchanged and is what a client sees.
   The default realm is `ldap.baseDn` itself (`dc=example,dc=com`) and every other realm is `dc=<id>` beneath it, so
   `ou=users`, `ou=groups`, `ou=applications`, `ou=federations` and the two
   SPIFFE containers exist once per realm and **share nothing**: OAuth client
   registrations, SAML service provider entries and the SPIFFE registry are a
   realm's own. **The realm is in the DN because the socket has no path to put a
   segment in** — an `ldapsearch` arrives on 389 with a base DN and nothing
   else, so `-b "dc=acme,dc=example,dc=com"` is the only way a client could ever
   name a realm, and it works. **A SUBTREE SEARCH IS SCOPED TO THE REALM ITS
   BASE NAMES** — `-b "dc=example,dc=com"` is the default realm's directory and
   `-b "dc=acme,dc=example,dc=com"` is acme's — and the root DSE publishes one
   `namingContexts` value per realm so a client can still find them. That
   reverses the original decision, which was that a naming context IS the whole
   tree: it left 389 as the one door through which a realm could read another
   realm's entries while every other surface showed it only its own. An
   operation that names ONE DN is answered in the realm that DN names, and a
   modifyDN that would cross a realm is refused with `LDAP_AFFECTS_MULTIPLE_DSAS`
   — two realms here are two directories. `ldap/CLAUDE.md` argues the shape, the
   choke point every enumerator goes through, how the socket picks a store, and
   the two alternative shapes (a listener per realm, an ldapjs `Server` per
   realm) with the reason each was not taken.
4. **THE TWO ADMIN CONSOLE ROLES ARE THE ONE THING DELIBERATELY NOT SEPARATED,
   and the console's sign-on follows them.** They are groups in the **default
   realm's** `ou=groups`, read there whichever realm the console is reached in,
   and a grant made through `/realm/acme/admin-api/rbac/grant` lands there too
   and says so in its reply. One roster for the process, on purpose: a role is
   permission to change what EVERY realm does — a settings form writes the
   realm it is reached in, `/admin/realms` can delete a realm outright — so a
   per-realm roster would mean anybody who can create a realm can make
   themselves an administrator of the service. The gate agrees with the roster:
   it accepts the **default realm's session and no other**, and an
   unauthenticated reader of any realm's console is sent to the default realm's
   sign-in screen. Nothing else here reads a session across realms at all.
   `admin-ui/CLAUDE.md` and `authn/CLAUDE.md` argue both halves.
5. Kerberos, the two TLS listeners and SPIFFE's four sockets are still shared,
   because a socket has no path to put a segment in and — unlike the directory —
   no name inside it to put one in either. `realmSupport()` in
   `common/realms.js` is the index, and both `/admin/realms` and `GET /realms`
   render it so that the answer is something the service says rather than
   something a reader works out.
6. **A REALM MAY BE IN RFC 9700 MODE WHILE THE PROCESS IS NOT**, and it is the
   one setting in `config.js` that is restart-only service-wide and settable on
   a realm — the `realmRuntime` marker, which has exactly one row. The reason
   `oauth2.rfc9700` is restart-only is that `global.https` derives from it and a
   listener's scheme is settled when the socket is bound; a realm binds no
   socket, so the reason does not reach it. One process therefore answers
   permissively at `/oauth2/authorize` and enforces the BCP at
   `/realm/rfc9700/oauth2/authorize`. What a realm does NOT get is a scheme of
   its own — the main port is HTTPS for every realm or for none — which
   `GET /oauth2/rfc9700` reports rather than hides. `common/CLAUDE.md` argues the
   marker and says why there must not be a second row carrying it;
   `oauth-oidc/CLAUDE.md` argues what it means for the mode.


## One listener process, N stateless workers

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

Five things are worth knowing before touching any of it.

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

`common/CLAUDE.md` has the module-level argument; `tests/worker_pool.js` has the
four contracts and the measurement that shows the loop is free.


---

## The require order in `server.js` IS the route order

Because of rule 1. Every constraint below is a DEPENDENCY, not a preference, and
each one's argument lives in the directory `CLAUDE.md` of the module that carries
it — this table says only what the constraint is, so that somebody adding a
require can see at a glance whether they are about to break one.

| # | Required | Constraint | Argument in |
|---|---|---|---|
| 1 | `common/config_file` | First of all. Every reader of `CONFIG_FILE` is below it. | `common/CLAUDE.md` |
| 2 | `common/app` | Before every protocol module — they register against it, and middleware only applies to routes added after it. Requiring it is also what installs the JWT recorder (rule 3e). | `common/CLAUDE.md` |
| 2a | `common/realms` | Loaded BY `app` and by `helpers`, so it has no line of its own in `server.js` — but it is above every setting read and every store in this service, because requiring it is what fills `config.js`'s realm slot (rule 3m) and what installs the reserved-id provider. | `common/CLAUDE.md` |
| 3–4 | `common/helpers`, `common/config` | `config.js` is below `helpers.js` and requires nothing here. | `common/CLAUDE.md` |
| 4a | `persistence/persistence` | Below `config`, which it reads, and above everything else: requiring it fills `config.js`'s override-store slot (rule 3q) and subscribes to `realms.onChange()`. A LIBRARY — it registers no route, so its place in the ROUTE order is not a place. **It opens nothing here**: the store is opened and READ from `persistence.start()` in `server.js`, before the listener binds, because a `require` cannot await a connection pool. | `persistence/CLAUDE.md` |
| 4b | `common/crypto` | Loaded BY `helpers`, so it has no line of its own in `server.js`. A LIBRARY — it registers no route, so its place in the ROUTE order is not a place. It is a LEAF and must stay one: it requires npm packages, `common/vendored/xmldsig.js` and `config`, which requires nothing here, so `helpers` may require it and it may NEVER require `helpers` back. Every function in it takes the key it is to use as a parameter for exactly that reason. | `common/CLAUDE.md` |
| 5 | `common/claim_attributes` | Ahead of everything that ISSUES, because requiring it fills `setAttributeResolver()`. An empty slot means tokens without their configured attributes. | `common/CLAUDE.md` |
| 6 | `common/group_claims` | Same reason, for `setGroupResolver()`. | `common/CLAUDE.md` |
| 6a | `home/home` | No constraint. Two EXACT paths (`/` and `/logo.png`) and nothing but the app behind them; first among the route modules so that the page a person meets first heads the list on `/admin/sts-metadata`. | `home/CLAUDE.md` |
| 7 | `ws-trust/wstrust` | No constraint. | `ws-trust/CLAUDE.md` |
| 8 | `authn/authn` | Before `oauth-oidc/oauth2` — it owns the session that module reads, and fills `audit.js`'s `setActorResolver()`. | `authn/CLAUDE.md` |
| 8b | `oauth-oidc/consent_screen` | **After `authn`** — it reads that module's session to check that the person answering is the person the question was asked of, and draws with its stylesheet. **And before `oauth2`**, which calls its `beginConsent()` and takes the browser back afterwards: exactly the arrangement `authn.js` already has with `beginAuthentication()`, one-way in the same way. It holds the pending records and nothing else; the REGISTER is `common/consent.js`. | `oauth-oidc/CLAUDE.md` |
| 9 | `oauth-oidc/oauth2` | Before `ws-federation/wsfed` and before `admin-ui/admin`. | `oauth-oidc/CLAUDE.md` |
| 10 | `ws-federation/wsfed` | **After `oauth2`** — rule 4. Single sign-on across the two protocols. |
| 10a | `saml/saml2_sso` | **After `authn`**, and a stronger dependency than WS-Federation's: it has NO sign-in screen of its own and reaches that service's through `beginAuthentication()`. No constraint against `wsfed` either way. | `saml/CLAUDE.md` | `ws-federation/CLAUDE.md` |
| 10b | `saml/saml11_sso` | **After `authn`** for the same reason as 10a, and **after `saml2_sso`** — it takes `slugOf()` from it, because one application must have one handle across both profiles. It needs no POST-to-GET hop: a SAML 1.1 flow arrives as a top-level GET. | `saml/CLAUDE.md` |
| 10c | `federation/federation_sp` | **After `authn`**, and stronger than 10a and 10b: it has no sign-in screen AND does not go through `beginAuthentication()` either — a federated sign-in calls `startSession()` directly, because the person authenticated somewhere else. No constraint against the four profiles above it in either direction; what joins the two halves is the SESSION. Only this module is required — the other three in that directory are libraries. | `federation/CLAUDE.md` |
| 11–14 | `oid4vc/*` | `vc_offers` before `vc_issuer`; both read `vc_configs`, which is why that module exists (rule 2). | `oid4vc/CLAUDE.md` |
| 15–16 | `kerberos/krb5_kdc`, `krb5_service` | Their listeners start from `listen()`, not here. | `kerberos/CLAUDE.md` |
| 17 | `kerberos/spnego` | **After `krb5_service`** — it calls that module's `accept()` and adds no check of its own. | `kerberos/CLAUDE.md` |
| 17a | `kerberos/spnego_authn` | **After `spnego` AND after `authn/authn`.** It draws with that module's page shell and negotiates through `spnego_exchange.js`; and it calls `authn.startSession()`, which is why the endpoint is HERE and not in `authn/` — a require the other way would drag the KDC's routes ahead of `oauth2.js` and close a cycle. It needs no slot: the two things `authn.js` must know are a path it declares itself and one setting they both read. | `kerberos/CLAUDE.md`, `authn/CLAUDE.md` |
| 18 | `admin-ui/admin` | **After `oauth2`** — rule 5. And before `ldap`, `scim` and `spiffe`, which is why it offers five slots rather than requiring them. | `admin-ui/CLAUDE.md` |
| 19 | `mgmt-api/admin_api` | **After `admin-ui/admin`** — rule 7. It calls that module's action functions and JSON views. | `mgmt-api/CLAUDE.md` |
| 20 | `tls/tls_server` | **Before `ldap/ldap_server`**, which serves its certificate and key on 636. | `tls/CLAUDE.md` |
| 20a | `admin-ui/crypto_metadata` | **After `tls/tls_server`, and that is the constraint that decides the line.** It reads an algorithm table out of eleven modules — `common/crypto`, `pq_jose`, the vendored `xmldsig`, `krb5_crypto`, `webauthn`, `oauth2`/`dpop`/`client_auth`/`mtls`, `spiffe_ca`, `scim_auth` and `tls_server` — and requiring one this file has not yet loaded would REGISTER ITS ROUTES HERE (rule 1). Here every one of them is a cache hit. Also after `admin-ui/admin` for the shell and the gate. Fills `admin.setCryptoReporter()`; `sts_metadata.js` fills ITS `setProtocolFamilies()`. | `admin-ui/CLAUDE.md` |
| 21 | `ldap/ldap_server` | **After `admin-ui/admin` and after `tls/tls_server`** — rule 6. Fills SEVEN slots at require time — the newest is `consent.setDirectory()` (2026-09-01), which carries the four functions that put a person's answer on their own entry and read it back — and registers the five `/admin/ldap/*` console pages it draws. | `ldap/CLAUDE.md` |
| 22 | `scim/scim` | **After `ldap/ldap_server`** — a plain require, and rule 3e's test is why. | `scim/CLAUDE.md` |
| 23 | `spiffe/spiffe_server` | **After `ldap/ldap_server` and `tls/tls_server`.** Its registry's store is the directory. | `spiffe/CLAUDE.md` |
| 23b | `ssf/ssf` | **After `admin-ui/admin`**, whose EIGHTH and NINTH slots it fills, and whose page shell and gate it requires — so a require the other way would close a cycle, and one from `mgmt-api/admin_api.js` would move every `/ssf` route and the well-known document ahead of the management API's own. Rule 3e's test answers yes both ways. It starts nothing and holds no socket. **Since 2026-09-03 it also fills `authn.setSessionObserver()`** — the CAEP profile, where a session starting, being presented or ending sends a Security Event Token with nobody having asked. That is an INVERTED HOOK for the same reason the admin slots are: `authn` is 8, so a require the other way would register every `/ssf` route there. | `ssf/CLAUDE.md`, `authn/CLAUDE.md` |
| 23c | `xacml/xacml` | **After `admin-ui/admin`**, whose TENTH slot `xacml_admin.js` fills and whose page shell, settings block and action responder it requires — so a require the other way would close a cycle, and one from `mgmt-api/admin_api.js` would move every `/xacml` route and all five `/admin/xacml*` pages ahead of the management API's own. It requires `xacml_admin.js` ITSELF rather than `server.js` doing it, so this family has ONE line in the require order; that module requires this one back LAZILY, inside the one function that needs it. **And after `ldap/ldap_server` (21) in effect** — not as an ordering constraint, since both registers take their directory across a slot that module fills, but because a process that loaded this one and not that has an empty repository and answers NotApplicable to everything. Since 2026-09-05 it also requires `oauth-oidc/mtls` for the remote PEP's client certificate, which is a LIBRARY (rule 3) and registers nothing, so it cannot move a route or join a cycle. | `xacml/CLAUDE.md` |
| 23a | `logout/logout` | **Second to last.** It READS NINE MODULES — the session store, the token registry, the codes, the offers, the directory's connections, the principal database — so it must come after every one of them. Nine plain requires and no slot; the one exception is `admin.js`, which it fills. | `logout/CLAUDE.md` |
| 24 | `sts_metadata` | **Last, for everybody.** It reads the router to list what everything else registered. | this file, below |

### Where the numbered rules live now

The prose throughout this repository cites rules by number, and the numbering is
kept rather than renumbered — a renumber would silently invalidate every citation
in every file, including the ones in the source comments. This is the index.

| Rule | About | File |
|---|---|---|
| 1 | Requiring a module registers its endpoints | this file |
| 2 | `vc_configs.js` / `vc_offers.js` break require cycles | this file, `oid4vc/CLAUDE.md` |
| 3 | A library registers nothing (`dpop.js`) | this file |
| 3a, 3a-ii | `vc_claims.js`, `vc_verifier_config.js` | `oid4vc/CLAUDE.md` |
| 3b, 3c, 3d, 3d-ii | `admin_stats.js`, `audit.js`, `claim_attributes.js`, `group_claims.js` | `common/CLAUDE.md` |
| 3d-iii | `scim_map.js` | `scim/CLAUDE.md` |
| 3e | The inverted hooks, and the test for adding one | this file |
| 3f, 3h, 3i, 3j | `oauth2_bcp.js`, `mtls.js`, `client_auth.js`, `authorization_servers.js` | `oauth-oidc/CLAUDE.md` |
| 3g | `applications.js` | `common/CLAUDE.md` |
| 3r | `crypto.js`, why it is a leaf, why the verifier is told which element, and why XML encryption moved rather than being replaced | `common/CLAUDE.md` |
| 4a | `saml2_sso.js` after `authn.js`, and why it has no screen | `saml/CLAUDE.md` |
| 4b | `federation_sp.js` after `authn.js`, and why it needs no screen at all | `federation/CLAUDE.md` |
| 4b | `saml11_sso.js` after `authn.js` and after `saml2_sso.js`, and why the two profiles are separate implementations | `saml/CLAUDE.md` |
| 3l | `delegation.js`, and why it has no funnel | `common/CLAUDE.md` |
| 3s | `app_permissions.js`, why a CONFIGURED register is not the observed one with a flag on it, and why the ordering rule lives in `applications.js` | `common/CLAUDE.md` |
| 3t | `consent.js`, why an OVERRIDE is not a RECORD, and why the client_id is the last field of the value | `common/CLAUDE.md` |
| 4c | `consent_screen.js` after `authn.js` and before `oauth2.js`, and why the screen holds the records while the register holds none | `oauth-oidc/CLAUDE.md` |
| 3p | `user_graph.js`, and why the union of two registers is a library rather than a page | `common/CLAUDE.md` |
| 3o | `federation.js`, why four modules may require it, and why `PATHS` is not beside the routes | `federation/CLAUDE.md` |
| 3m | `realms.js`, the realm slot in `config.js`, and why the realm is ambient | `common/CLAUDE.md` |
| 3q | `persistence.js`, the override-store slot in `config.js`, the directory slot it offers, and why `realms.onChange()` is an event rather than a third slot | `persistence/CLAUDE.md` |
| 3m | `logout/logout.js` holds no state, and the reading order is not the ending order | `logout/CLAUDE.md` |
| 3n | `frontchannel_logout.js` | `oauth-oidc/CLAUDE.md` |
| 3k | SPIFFE's six modules | `spiffe/CLAUDE.md` |
| 4 | `wsfed.js` after `oauth2.js` | `ws-federation/CLAUDE.md` |
| 5 | `admin.js` after `oauth2.js` | `admin-ui/CLAUDE.md` |
| 6 | `ldap_server.js` after `admin.js` and `tls_server.js` | `ldap/CLAUDE.md` |
| 6a (SCIM), 6a-ii | `scim.js`, `scim_auth.js` | `scim/CLAUDE.md` |
| 6a (SPIFFE) | `spiffe_server.js` | `spiffe/CLAUDE.md` |
| 7, 7a | The console/API parity rule, the breadcrumb trail | `mgmt-api/CLAUDE.md`, `admin-ui/CLAUDE.md` |
| 8, 8a, 8b | The console's gate, its two roles, and the claim they qualify | `admin-ui/CLAUDE.md` |

Two rules share the number `6a` and always did — one for SCIM and one for
SPIFFE. They are now in different files, which is the first thing that has ever
made that collision harmless.

---

## Four modules start listeners from `listen()`, not at require time

The two Kerberos modules, `ldap_server.js` AND `tls_server.js` are the exception to
rule 1 in one direction only: requiring them registers their HTTP views
(`/KdcProxy`, `/krb5/principals`, the five `/admin/ldap/*` pages, `/tls`) like everything
else, but their
**own listeners are started from `listen()` in `server.js`, not at require time** —
binding a port can fail, and a `require` that throws takes the whole service down
where a route cannot. A failure to bind is RECORDED rather than thrown, and both
`ldap_server.js` and `tls_server.js` publish it (`listening` / `listenError` on
`GET /admin/ldap/service` and `GET /tls`), because the HTTP view answers 200 either way and there
is otherwise no way to tell a running listener from one whose port was already taken
— by the host's own slapd, or by a second copy of this service.

The fourth is `spiffe/spiffe_server.js`, with four sockets of its own.
Each is reported SEPARATELY, because "389 is up and 636 is not" is the
ordinary outcome of a host run and one flag could only report one of them.

**THE FIFTH IS `persistence/persistence.js` AND IT BINDS NOTHING, WHICH IS WHY
IT IS WORTH ADDING TO THIS LIST RATHER THAN A LIST OF ITS OWN.** It is here for
the same shape of reason and a different specific one: opening a PostgreSQL
connection pool is ASYNCHRONOUS, and a `require` cannot await. So the store is
opened, and the directory, the realm registry and the saved appconfig overrides
are read back, from `persistence.start()` — which `server.js` calls BEFORE the
HTTP listener binds, and before the four socket families above start.

**It goes first among the five, and that ordering is a dependency rather than
tidiness.** Between binding and restoring, this service would answer
`/oauth2/authorize` out of a seeded directory, `/admin/applications` out of an
empty registry and `/federation/acs/{id}` out of a register with no
relationships in it — and that last one is a SECURITY surface, where "not
configured yet" and "disabled" are the same refusal to a caller and very
different facts. There is no window in which that can happen.

**UNLIKE the four above it, a failure here is FATAL, and this paragraph said
the opposite until 2026-08-28.** It used to say that a store which could not be
opened or read left this service running with its seeded directory and reported
the fallback — because a mock that refused to start when a database blinked
would be the one failure mode a mock must not have.

That argument still holds for a store that breaks WHILE RUNNING: `flush()`
records the failure, puts the dirty bits back and retries on the next change,
and the service goes on answering. It was the wrong answer at STARTUP, because
the two states are not alike. A running service that loses its database has
already restored everything it was going to and is still telling the truth
about what it holds. **A process that never opened its store is answering out
of a SEEDED directory while presenting itself as the one that was configured** —
every endpoint works, the console draws, and the realms, applications and
federation partners somebody creates are thrown away by the next restart, which
is the restart they will do because they expected the work to survive it.

So a CONFIGURED store that cannot be opened or read stops the process:
`persistence.start()` rejects, `server.js` logs at FATAL naming the mode, the
cause and the way out, and exits non-zero without ever binding a listener.
`persistence.mode=memory` — the default — reaches none of this, so a service
nobody asked to persist behaves exactly as it always has. This is the only
place in this repository where a failure to open something is fatal, and the
reason is that the other four are about a SOCKET, where "389 is already taken"
is an ordinary outcome of a host run, and this one is about whether the service
is the thing it says it is.

---

## `frame-ancestors` is the one CSP clause a page may not drop

RFC 9700 section 4.14. `app.js` sets the policy on every response, and five routes
relax it to load a named script by SETTING THE WHOLE HEADER — so each of them could
lose the framing clause with nothing failing: the page works, the script runs, and
the protection is gone. **`frame-ancestors` has no fallback from `default-src`**,
which is why `default-src 'none'` alone is not enough and why this needs saying.

Two rules come out of it:

* **A relaxation goes through `app.contentSecurityPolicy(overrides)`**, which re-adds
  `frame-ancestors` and `base-uri` whatever the caller asked for. A caller cannot turn
  them off — that is deliberate, not an oversight in the API.
* **The policy is re-checked when the response is flushed.** Express's own 404 handler
  REPLACES the header with `default-src 'none'`, so every unrouted path was framable
  as far as CSP was concerned; nothing here could have shown it, because the header
  this service set was correct and something else overwrote it. The check is "does it
  still carry the clause", not "is it the value I set", so the five relaxations are
  untouched.

**Do not replace Express's 404 body.** `Cannot GET /path` is how
`tests/vendored/sts_metadata.js` tells an unrouted path from an endpoint legitimately answering
404. Fixing the header was the whole fix; a prettier 404 would break that test
silently.


## Three pages here have a script on them, and each is the same exception

`app.js` sets `script-src 'none'` for the whole service, and the reason is in its
own comment: it is what makes the family of reflected-content problems moot rather
than merely unlikely. Three pages need a script and each takes the SAME shape of
exception — `script-src 'self'` naming one resource, never `'unsafe-inline'`:

* `/authn/webauthn` and its `/authn/webauthn.js` — the ceremony cannot be performed
  without one.
* WS-Federation's sign-in response and `/wsfed/autopost.js` — section 13.2.1's form POST.
* the `response_mode=form_post` authorization response and `/oauth2/autopost.js` —
  RFC 9700 section 4.3's answer to a response that would otherwise be in a URL.

**Each of those pages carries a REAL SUBMIT BUTTON as well**, and that is not a
fallback nobody sees: with the script blocked the button is the whole mechanism, so
it is labelled for a person rather than hidden. A fourth scripted page needs the
same argument made again — do not add one by analogy.


The fourth scripted page is `/admin-api/docs` — see `mgmt-api/CLAUDE.md`,
where the same argument is made a fourth time and the dependency it replaced
is weighed.

**FEDERATION ADDS NONE, AND IT IS THE ONE PLACE THE ARGUMENT CAME OUT THE OTHER
WAY.** `federation_sp.js`'s outbound SAML HTTP-POST binding is the obvious sixth
candidate — everywhere else in this service that binding auto-submits. It is a
REAL FORM WITH A REAL BUTTON there, deliberately: those pages auto-submit
because the person has already decided and a click would be ceremony, and this
one is a person LEAVING THIS SERVICE for a foreign identity provider, which is
exactly the moment a deliberate click is worth having. So the whole feature
relaxes no CSP anywhere.

The fifth is `/saml2/autopost.js`, and the argument is made a fifth time in
`saml/saml2_sso.js` above `AUTOPOST_SCRIPT`: the SAML 2.0 HTTP POST binding IS a
self-submitting form (saml-bindings-2.0-os section 3.5), which is what keeps a
response of several kilobytes of signed XML out of a URL, a log and a Referer
header — so there is no version of that binding without a script. Same shape,
same real submit button, no wider.

The sixth is `/saml11/autopost.js`, and this is the case that shows why the rule
asks for the argument to be MADE rather than cited — the fifth is the page next
door, and "the same as that one" would have been the whole justification. It is
made a sixth time in `saml/saml11_sso.js` above its own `AUTOPOST_SCRIPT`, and it
stands alone: SAML 1.1's Browser/POST profile IS a self-submitting form in its
own older specification (saml-bindings-1.1 section 4.1.2, which describes the
identity provider returning a document containing a form that submits itself).
Two specifications arrived at the same shape independently; this one would be
here if SAML 2.0 had never been written. Same shape, same real submit button, no
wider.

**THE DELEGATION PICTURE IS THE OBVIOUS SEVENTH CANDIDATE AND IT IS NOT ONE.**
`/admin/delegation/map` draws a graph, and every graph library a person would
reach for — mermaid, cytoscape, d3 — runs in the browser and would have made it
the first scripted page in the CONSOLE. It is generated on the SERVER instead:
`@dagrejs/dagre` computes the layout, `admin-ui/delegation_map.js` emits the
shapes, and the SVG arrives inline in the page as ordinary markup. So
`script-src 'none'` is untouched and `img-src` is not even reached. What that
costs is pan and zoom, which the page says out loud rather than leaving somebody
to wonder why dragging does nothing; the filter narrows a busy picture and
`?format=svg` hands over the document for something that does zoom. The rule this
follows is the one the six above establish read backwards: the argument for a
script has to be that the page CANNOT work without one, and a diagram that does
not move can.

**THE FEDERATION PICTURE ADDED ON 2026-08-26 IS THE NINTH CANDIDATE AND IS NOT
ONE EITHER, AND IT IS THE CASE THE SEVENTH'S RULE WAS WRITTEN FOR.**
`/admin/federation/map` draws a second graph in the console, and every argument
for reaching for a browser graph library applies to it exactly as it applied to
the delegation picture — which is precisely why it does not get to cite that
one. The argument is made again from scratch in
`admin-ui/federation_diagram.js`'s header and it lands in the same place for the
same reason: the test for a script is that the page CANNOT work without one, and
a diagram that does not move can. `@dagrejs/dagre` computes the layout on the
server, that file emits the shapes, and the SVG arrives inline as ordinary
markup — so `script-src 'none'` is untouched, `img-src` is not reached, and what
it costs is pan and zoom, which the page says out loud and answers with
`?format=svg`. **The rule to take from having now refused it twice is that the
second refusal was not cheaper than the first**: the seventh candidate's whole
point is that "the same as the page next door" is not an argument.

**THE COLLAPSIBLE PROSE BLOCKS ADDED TO THE CONSOLE ON 2026-08-26 ARE THE
EIGHTH CANDIDATE AND ALSO NOT ONE**, and it is the case that shows the rule
read backwards a second time. Every page in `/admin` explains itself at length,
which put the control somebody came for several screens down a wall of
paragraphs; the fix is that prose longer than about a line is drawn as a
`<details>` whose summary is its own opening sentence. The debugger's version
of that is a checkbox and a listener — it has a collapse-all switch — and this
console cannot have one. `<details>` needs no script at all, so the whole
change leaves `script-src 'none'` untouched. What it costs is exactly that
switch, which `admin-ui/CLAUDE.md` argues is affordable and says what was done
instead. **Tooltips are the same change's other half** and carry the rule that
nothing is ever said ONLY in a `title` attribute — see that file.

---

## Adding an endpoint costs one entry in `sts_metadata.js`

`GET /admin/sts-metadata` reads the endpoint list **from the running Express router**, so
it cannot go stale — but it reports two kinds of drift and this repository's own
`tests/vendored/sts_metadata.js` fails on both: a route registered and undescribed, and a
description whose path is not registered (what a rename produces). See README.md.

It is a **console page** since 2026-08-24 (it was `/sts-metadata`), so it is
behind `admin.authRequired` and is drawn by `admin.js`'s `page()`: this module
builds the body and `admin.respond()` supplies the shell. Adding a PROTOCOL
family costs a card in that file's `PROTOCOLS` as well as the entry above —
the page reports an endpoint group no card claims, so leaving it out fails the
same test rather than going quietly.

**THERE IS A SECOND METADATA PAGE SINCE 2026-08-30 AND IT IS NOT A SUMMARY OF
THIS ONE.** `/admin/crypto-metadata` answers the question underneath the
endpoint list: when this service SIGNS, VERIFIES, ENCRYPTS or DECRYPTS
something, which digest, which algorithm, which cipher, which key, and which
envelope. It follows the same design — every algorithm table is read from the
module that performs the algorithm rather than written down — and it checks its
family list against THIS page's `PROTOCOLS` in both directions, which is why
`sts_metadata.js` requires it and hands that list over. Adding a protocol family
therefore costs a card here, an entry in `ENDPOINTS`, AND a row in
`crypto_metadata.js`'s `FAMILIES`; `tests/vendored/admin_api.js` fails on the
third being missing. See `admin-ui/CLAUDE.md`.

**`ssf/CLAUDE.md` CARRIES THE FULL LIST OF WHAT ADDING THE SEVENTEENTH FAMILY
ACTUALLY COST**, which is nine files rather than the three named above — the
config group and its regenerated defaults, the applications registry (including
a NEW attribute ROLE, because a push endpoint is where an EVENT goes and calling
it a browser redirect would make a table this repository reads literally say
something false), an audit category, the console slot and page, the crypto
report row, the management API's operations and their schema, the two OAuth
scopes, and the require. It is written down there rather than here because it is
the record of one family; this file is the rule.

Reading the router has one blind spot: **a protocol that registers no route is
invisible to it**, which is exactly what the KDC's raw TCP/UDP 88 listeners are — and
the directory's two, plain 389 and LDAPS 636. Those
have to be described by hand or they go unlisted with nothing failing.

Coverage notes in that file **must start `full`, `partial` or `mock`** and say what is
missing. A list of fifty specifications that did not mention that this service
checks no passwords and validates no access tokens would be the most misleading thing
in the repository.


## Code style

* **No one-liner `try`/`catch`.** Braces and a body, always.
* **Every function longer than about ten lines opens with
  `log.debug("Entering fn().")` and returns through `log.debug("Leaving fn().")`.**
  Several `Leaving` lines in one body is correct, not a mistake — one per exit.
* **Every swallowed `catch` explains itself in a comment.** "Not JSON; the raw text
  is what gets shown" is a reason. An empty block is not.
* Comments carry the *reasoning*, especially where something went wrong once. The
  density in this codebase is deliberate; match it rather than trimming it.


## node-ldapjs is a SUBMODULE, it is nested, and it is not modified

`ldap_server.js` is built on `ldapjs` 3.0.7, which resolves to `./node-ldapjs` —
a git submodule pinned to [`rcbj/node-ldapjs`](https://github.com/rcbj/node-ldapjs)
(`"ldapjs": "file:node-ldapjs"` in package.json). Four things follow, and three of
them have already cost something:

* **This repository is itself a submodule of the parent project, so this one is
  NESTED.** `git submodule update --init sts` over there stops one level short of
  it; `--recursive` is required, and the parent's launchers and CI workflows pass
  it. An uninitialised submodule is an EMPTY DIRECTORY, so the COPY succeeds, npm
  installs a package with no `main`, and the failure arrives at runtime as
  `Cannot find module 'ldapjs'` — which names a package.
* **It has to sit inside this package root.** npm installs a `file:` dependency as
  a symlink and node resolves that package's own requires by walking up from where
  the REAL directory lives, so a copy one level up never reaches `node_modules`
  here. The failure is `Cannot find module 'abstract-logging'` from inside ldapjs.
* **`npm install` brings its devDependencies.** ldapjs's are tap and eslint —
  about 200 packages and a dozen advisories that have nothing to do with this
  service. `.npmrc` carries `omit=dev` and the Dockerfile passes `--omit=dev` as
  well; the duplication is deliberate.

## The signing key is regenerated on every start

Deliberate, and two things depend on it: the `kid` is derived from the key material
(`sts-mock-<thumbprint>`) so two instances cannot claim the same kid over different
keys, and every document that carries or describes the key is served
`Cache-Control: no-store`. If you add a document that publishes the key, it needs
that header too.


## Tests

**A PROTOCOL TEST FOR THIS SERVICE IS STILL WRITTEN IN THE PARENT PROJECT'S
`tests/` — AND SINCE 2026-08-28 A COPY OF IT RUNS HERE.** Those are two
different claims and the second one is new; keeping them apart is the whole of
this section.

The first is unchanged and was made the hard way: `tests/saml11_sso.js` was
written here on 2026-08-25 — the first test this repository ever had, with its
own `tests/CLAUDE.md` and its own `npm test` — and moved to
`../id-proto-debugger/tests/saml11_sso.js` the same day, before a second one
could be written beside it. What the move bought is the whole argument: a second
suite means a second runner, a second report, a second thing CI has to be told
about, and a second place to forget. Over there the file is one entry in
`run-report.js`, one line in `tests/Dockerfile`, one paragraph in
`docs/test-suite-map.md`, and it runs in the containerized stack, the host stack
and `./local-run-tests.sh --saml-only=sts` without anything being invented for
it. **That is still where a new protocol test goes, and editing a copy here
instead is the one thing this arrangement cannot survive** — the copy is
overwritten by the next sync and the fix never reaches the stack that gates that
project.

**WHAT CHANGED IS WHERE THEY RUN, AND IT CLOSED A HOLE THIS FILE USED TO
DESCRIBE AS A FEATURE.** The thirteen of those jobs that a lone mock can satisfy
are in `tests/vendored/` — nine of them byte-identical copies, listed in
`tests/vendored/MANIFEST.js` with the directory each came from — and they run
against a container built from this working tree on every `./local-run-tests.sh`.
Before that, this repository's own launcher could only run them when the parent
checkout happened to be beside it, and on a machine where it was not, thirteen
of twenty-three jobs were quietly absent from a run that said "Tests passed".
A suite that reports green because it could not find two thirds of itself is
worse than one that is honestly small.

Three consequences worth knowing:

* **The parent is the SOURCE OF TRUTH for NINE of the thirteen, and those
  copies are not edited here** — the same rule `common/vendored/` carries, for
  the same reason. `./local-run-tests.sh --vendor-check` reports drift and
  `--vendor-sync` is the only sanctioned way those files change. Both need the
  parent checkout; neither is part of the suite's pass or fail, because a check
  that needs the other repository cannot be what decides whether this one is
  green.
* **THE OTHER FOUR ARE THIS REPOSITORY'S OWN AND THE RULE IS INVERTED FOR
  THEM.** `sts_metadata.js`, `admin_api.js`, `sts_admin_api_operations.js` and
  `sts_admin_console.js` drive this service's `/admin` console and its
  `/admin-api`; they ran from the parent's suite until 2026-08-28 and were
  deleted there that day, because a test asserting something about this console
  belongs in the tree where a control is ADDED to that console — the tree that
  should go red when the control loses its operation. They carry `local: true`,
  which keeps them out of `allFiles()`, so the drift check cannot report them
  GONE UPSTREAM and the sync cannot overwrite them. **They are edited here, and
  only here.** They sit in `tests/vendored/` rather than in `tests/` because of
  how they RUN — spawned as processes with that directory as their cwd — and
  for no other reason; `tests/CLAUDE.md` carries it.
* **`client/src/` is vendored too, and that is deliberate rather than
  incidental.** Five of the thirteen load the debugger's own wallet, DID, JWS,
  JWE and PQC modules — because an INDEPENDENT implementation is what makes
  "our signature verifies" mean anything, which is the same argument that keeps
  `xml-crypto` in `package.json` while no module here requires it.
* **The test dependencies are a second npm package**, `tests/package.json`,
  because `.npmrc` carries `omit=dev` and a `devDependency` added at the root
  would be silently not installed — the same trap the coverage renderer was
  written around.

**So the four ports below are still the shape to copy, and there are now five of
them.** They are plain node scripts using `assert` and `bunyan`, driven over HTTP
with no browser, taking `WSTRUST_STS_URL` / `OID4VCI_ISSUER_URL` to locate this
service — and `saml11_sso.js` is the fifth and the newest, so it is the one to
read before writing the sixth. What it demonstrates beyond the shape: it is
mostly NEGATIVES, for the reason `tests/sts_dpop.js` gives (an identity provider
that hands a working relying party a signed assertion looks finished and can be
worth nothing); it RESTORES every setting it changes, with
`/admin-api/config/reset` rather than by writing the old value back, because a
`set` leaves `source: override` behind for `tests/vendored/admin_api.js` to trip
over on the next run; it asserts the profile counters as DELTAS, because this service holds
everything in memory and never restarts between jobs, so a test that only passes
first is a test that has to be scheduled; and it was MUTATION-TESTED before it
was committed, which `docs/test-suite-map.md` over there records, because a test
that has never failed has not been shown to test anything.

**There is ONE exception, and `tests/` in this repository is it.** There were
two until 2026-08-26, and what closed the other one is worth reading before
anybody opens it again:

* **An INTEGRATION test that needs several copies of this service** — which
  `federation-e2e/` was, a three-container stack it brought up itself.
  **TRUST REALMS ended it.** A realm is a whole logical copy of this service on
  the same socket under a path prefix, so several copies no longer means several
  processes and there is nothing left that a test in the parent suite cannot
  reach over HTTP. It is `tests/federation_sso.js` over there now, driving two
  realms of one process with the debugger standing in for the application tier
  that stack had to build for itself. Before adding a directory here for the
  same reason, check whether realms already answer it.
* **An IN-PROCESS test of this repository's own MODULE CONTRACTS** — `tests/`,
  added 2026-08-25, `npm test`, no port and no container. What forced it was
  `config_realm_layer.js`: it asserts that a realm carrying `oauth2.rfc9700`
  does not thereby inherit `global.https`, and the parent suite could not have
  caught that in ANY form, because its launchers always start this service with
  `STS_HTTPS=true` and with the scheme pinned the broken and the fixed code
  return the same answer. **THAT IS NOW TRUE OF THIS REPOSITORY'S LAUNCHERS
  TOO** — since 2026-08-30 they set `STS_HTTPS` and every appconfig file carries
  `global.https: true` — which makes the argument STRONGER rather than stale:
  there is no longer a stack anywhere that could catch it, and the only reason
  it is caught is that this file deletes `CONFIG_FILE` and varies the
  environment itself. Seeing it requires varying how the PROCESS was
  started, which a test driving somebody else's running service cannot do.

  **`crypto_module.js` (2026-08-27) is the clearest case of that line yet**, and
  it is worth reading before arguing about where a test goes. Its central
  assertion is that a document this service signs is accepted by an INDEPENDENT
  implementation — xml-crypto, which is what all six signers used before
  `common/crypto.js` existed — and in the other direction that a document signed
  the old way still verifies. There is no way to ask either of those of a
  running service over HTTP: you would have to import xml-crypto and hand it the
  document, which is exactly this file, in process, with no port. The same
  applies to the three RFC 7638 thumbprints agreeing and to the algorithm
  tables. **This is also why `xml-crypto` is still in `package.json` while no
  module in the service requires it** — it is the only independent reading of
  XMLDSIG here, and it is what makes "our signature verifies" mean anything.

  What does NOT belong here is the protocol half — that `/saml2/metadata` is
  signed, that a Browser/POST response carries two separately verifiable
  signatures, that a federated assertion signed by the wrong key is refused.
  Every one of those can be driven over HTTP and belongs in the parent suite.
  **They are not written**, and this paragraph says so rather than implying the
  refactor is covered end to end.

  **`appconfig_persistence.js` (2026-08-28) is that line one step further along,
  and it is the FIRST test here that turns a store on** — which `tests/CLAUDE.md`
  anticipated and set one condition for, that it clean up a directory rather
  than a Map. The parent suite's two admin jobs go as far as an HTTP client can:
  they watch `/admin-api/persistence`'s write counter move, its dirty flag clear
  and its failure counter stay put. That is still a number the service computed
  about itself. **What is IN the file cannot be asked over HTTP at all**, and the
  failure is invisible until a restart, in a different process — a value written
  with the wrong type, or not written, is correct on every endpoint for the whole
  life of the process that made it, and the damage appears on the next start as a
  setting that has quietly gone back to its default.

So the line is: **can it be asserted by driving the running service over HTTP?**
If yes it goes in the parent suite, where it costs one entry in `run-report.js`
and runs in three stacks without anything being invented for it. Only if no does
it go here. `tests/CLAUDE.md` carries the rest, including the two rules that are
not optional there — mutation-test the guard before committing it, and restore
the process-wide state you touch.

### Running either half, and the launcher that does it (2026-08-28)

```bash
npm test                          # unchanged: one process, bunyan, under 2s
./docker-run-tests.sh             # ALL 41 jobs, ENTIRELY IN CONTAINERS — the
                                  # service AND the runner. Needs docker and
                                  # NOTHING else. What CI runs (see 5 below)
./local-run-tests.sh              # ALL 41 jobs: the in-process suite, and the
                                  # protocol jobs against a CONTAINER built
                                  # from this working tree
./local-run-tests.sh --no-docker  # the same set, with the service run on this
                                  # machine instead of in a container
./local-run-tests.sh --keep-stack # leave the container up to read /admin
./local-run-tests.sh --no-protocol  # the in-process suite alone, 3 seconds
./run-coverage.sh                 # the same run, with coverage collected —
                                  # IN CONTAINERS TOO since 2026-08-29, with
                                  # the RUNNER in the container rather than the
                                  # service (see 4 below). --no-docker is the
                                  # host run
```

`./local-run-tests.sh`, `./docker-run-tests.sh` and `./run-coverage.sh` are this
repository's answers to the three scripts of those names in the parent project,
and all three are far shorter than their counterparts for a reason worth
knowing before porting a feature from over there: those have to BUILD and
PROVISION a stack — Keycloak realms, two walt.id services, a WildFly side-car,
browser bundles — because the tests they run drive a browser against all of it.
Here there is ONE service and it provisions nothing, because it accepts any
client, any entityID and any username on first sight.
`tests/tools/run-report.js` is what all three drive;
`tests/report/<timestamp>/` and `coverage/` are what comes out, and both are
gitignored.

**THE SERVICE THOSE JOBS DRIVE IS TLS SINCE 2026-08-30, AND THAT COST THE SUITE
EXACTLY ONE NEW MODULE.** `tests/tools/trust.js` fetches the mock's certificate
once the service answers — with verification off, necessarily, since the key is
regenerated on every start and nothing that ran before it can have an anchor —
and `run-report.js` hands every protocol job `NODE_EXTRA_CA_CERTS` and
`STS_SPKI_PIN`. The second of those needed no new code at all:
`tests/vendored/browser_flags.js` has read that variable for months, because the
parent project's stacks have been https for months. **The PEM is written into
the run's own report directory**, so the certificate a run trusted is beside
that run's logs — when a job fails on a certificate the question is always which
certificate. Everything that PROBES rather than tests — the two launchers'
`stsProbe`, `run-report.js`'s own wait, `service.js`'s readiness loop, both
compose healthchecks — asks with `rejectUnauthorized: false`, because the
question there is whether the port answers and not whether it is trusted; the
JOBS get a real anchor, which is what keeps an assertion about a certificate
meaningful.

**FIVE THINGS ABOUT THEM REACH OUTSIDE `tests/CLAUDE.md`, WHICH IS WHERE THE
REST IS ARGUED.**

1. **THE PROTOCOL JOBS RUN BY DEFAULT AND ARE VENDORED HERE, BOTH SINCE
   2026-08-28, AND EACH REVERSED SOMETHING THIS FILE ASSERTED THE DAY BEFORE.**
   They answer the gitlink problem the last section of this file describes:
   their suite drives the pinned `sts/` checkout, so a change made here is not
   covered by it until somebody bumps the pin. A run brings up a copy of this
   tree and drives the seventeen jobs against it — in a CONTAINER since the
   same day, which is item 4. About a minute plus the image build.

   **`--protocol` used to be needed and is now the default**, because without
   it the bare run was ten in-process files in three seconds and said "Tests
   passed" having driven no protocol endpoint, no admin console and no browser.
   `--no-protocol` is the way back. **It runs the BROWSER jobs too, and there
   are two** — `sts_admin_console.js`, a Selenium job since 2026-08-28 which
   walks every page of the console, and `sts_xacml_editor.js` since 2026-09-05,
   which drives ONE page in depth because the guided policy editor's forty forms
   per render are markup rather than behaviour and the in-process suite that
   holds its grammar cannot see them. This runner is SERIAL, so there is never a
   second Chrome open; `--no-browser` leaves them out and says so.

   **And the jobs are COPIES here rather than read out of the parent**, so a
   machine with only this repository on it runs all forty-one. It does NOT
   replace bumping the pin, because it runs on a developer's machine and CI
   over there still drives what the gitlink names.
2. **A VENDORED JOB CAN BE AHEAD OF THIS TREE, and vendoring changed what that
   means rather than fixing it.** Those jobs are developed against the parent's
   own checkout of this service, so one can assert a feature this tree has not
   got — and it then fails here naming that feature. It used to be a fact about
   two live checkouts; it is now a fact about when the copy was taken, which is
   the same information and is answered by `--vendor-check`.

   **A JOB THAT COULD NOT BE RUN IS A FAILURE AND NOT A SKIP**, since the same
   day and for the same reason as the default flip: the throwaway service
   failing to start used to leave thirteen jobs marked `skipped`, which the
   summary counts as passing, so a run in which nothing was checked exited
   zero.
3. **THE COVERAGE RENDERER IS WRITTEN HERE RATHER THAN BEING `c8`**, and the
   reason is `.npmrc`: this repository carries `omit=dev` and the Dockerfile
   passes `--omit=dev` besides, so a `devDependency` added for coverage would
   be silently NOT installed and the script would fail for everybody. The
   collection is node's own `NODE_V8_COVERAGE`; the raw JSON is kept so anybody
   who prefers c8 can point it at the same data. Its numbers are DEFINED at the
   top of `tests/tools/coverage-report.js` — functions exact, lines derived,
   no branch percentage at all — and a number quoted out of that report without
   its definition is the failure mode that section exists to prevent.
4. **THE SERVICE THE PROTOCOL JOBS DRIVE IS A CONTAINER, FROM THIS
   REPOSITORY'S OWN `docker-compose.yml`, SINCE 2026-08-28 — AND THE TESTS ARE
   STILL PLAIN SCRIPTS ON THE HOST.** Those are two claims and only the first
   changed. `./local-run-tests.sh` builds the image from this working tree,
   brings up ONE container, hands `run-report.js` its URL through
   `--service-url`, and — since 2026-09-01 — LEAVES IT UP when the run
   finishes, because almost everything a failing run does not tell you is
   read off the service itself and a container torn down at the last line is
   gone by the time the report says to look at it. `startStack()` already
   brought its own project down before bringing it up, so the next run meets
   no leftover; `--tear-down` is the old behaviour. The seventeen jobs are node
   processes on this machine exactly as they were, which is what keeps the
   loop short, what lets the five jobs that load this service's modules IN
   PROCESS keep doing so, and what lets the browser jobs drive the Chrome that
   is already installed here.

   **What the container buys is that the thing under test is the IMAGE** — the
   same Dockerfile, the same `npm install --omit=dev` against the committed
   lock, the same node, the same `COPY . ./` with `.dockerignore` deciding
   what is in it. Three failures this repository has actually had are
   properties of the image and of nothing else: an uninitialised NESTED
   submodule that installs a package with no `main`, a module present in the
   tree and excluded from the build context, and a dependency that `omit=dev`
   quietly did not install. A suite running the source out of a developer's
   own `node_modules` cannot see any of them.

   **Four things about the stack are decisions rather than mechanics**, and
   each is argued where it lives — the launcher's header and
   `docker-compose.yml`'s. It is its own compose PROJECT (`mock-sts-tests`),
   its own container name (`sts-tests`) and a FREE host port found at start,
   so that a test run can never take, or tear down, the `sts` container a
   plain `docker compose up` in this directory gives somebody. It persists
   NOTHING — `STS_PERSISTENCE_MODE=memory` and `--no-deps`, so the postgres
   service in that file never starts — because a suite that persisted is a
   suite whose second run starts from the first run's leavings. The image is
   REBUILT every run, since an image is a snapshot of when it was built, and
   `--no-build` says out loud that it may be older than the tree. And a stack
   that will not come up is a FAILED run rather than a quiet fall back to the
   host, because a run that silently ran the source instead of the image is a
   green that does not mean what the paragraph above says it means — the one
   exception being a machine with NO DOCKER, where the fallback is loud and
   `--docker` turns even that into an error.

   **`./run-coverage.sh` STILL DOES NOT DRIVE THAT CONTAINER, AND SINCE
   2026-08-29 IT RUNS IN ONE ANYWAY — the two are not the same sentence and
   this paragraph collapsed them for a day.** The physics is unchanged: V8
   writes coverage from INSIDE the process being measured, so an instrumented
   run has to be one the runner started, and a service reached over HTTP can
   never be under the report. What that rules out is measuring the SERVICE
   CONTAINER NEXT DOOR — not containers. So the coverage run puts the RUNNER in
   `docker-compose-run-tests.yml`'s `tests` image (`run --rm --no-deps`, which
   never starts the `sts` service) and lets it start the service it measures as
   a CHILD PROCESS in there; `./coverage` and `./tests/report` are bind mounts,
   so both come out onto the host. `--no-docker` is the old host run, unchanged
   and still the fast loop, and a machine with no docker falls back to it
   loudly.

   **What it buys is what item 5 buys the suite**: the host needs docker and
   nothing else, which is why `.github/workflows/tests.yml` can run a coverage
   pass beside the suite. What it costs is an image build and output written by
   root through the bind mounts — the script says so once rather than leaving
   it to be met as a permission error on the next host run.

5. **`./docker-run-tests.sh` PUTS THE RUNNER IN A CONTAINER TOO, AND IT IS WHAT
   CI RUNS (2026-08-29).** Item 4 containerized the SERVICE and said out loud
   that the tests are still plain scripts on the host; this is the other half.
   `docker-compose-run-tests.yml` brings up two services on a private bridge —
   the mock from this repository's Dockerfile, and a runner built from
   `tests/Dockerfile` with node, a Chrome and this working tree in it — runs
   all forty-one jobs against the service by its compose DNS name, and exits
   with the suite's status (`--exit-code-from tests`).

   **WHAT IT BUYS IS THAT THE HOST NEEDS DOCKER AND NOTHING ELSE**: no node, no
   `npm install`, no Chrome, no parent checkout. That is what makes it runnable
   in `.github/workflows/tests.yml`, and it is the missing half of the
   2026-08-28 vendoring — the jobs became this repository's own files that day,
   and until this they still needed a developer's machine to run on. It is also
   what to reach for when a run is green here and red somewhere else: the two
   launchers drive the SAME forty-one jobs through the same runner, so a
   difference between them is a difference in the environment and nothing else.

   **THE TWO LAUNCHERS ARE NOT REDUNDANT AND NEITHER REPLACES THE OTHER.**
   `./local-run-tests.sh` is the development loop — editing a test and
   re-running it costs nothing there, because the jobs are node processes on
   this machine; here every edit is an image build. That is the whole trade,
   and it is why the tests image is deliberately the thing that changes least:
   Chrome and both `npm install`s sit ABOVE the `COPY . ./` so a source edit
   re-runs neither.

   **THREE DECISIONS IN THAT FILE ARE NOT MECHANICS.** It publishes NO PORT AT
   ALL — everything that talks to the service is on the bridge with it, so
   publishing could only make a test run fail because a dev stack holds 8081,
   or take that port from one. It has NO POSTGRES and `persistence.mode=memory`,
   for item 4's reason. And the tests image is built from the SAME context as
   the service image with a per-Dockerfile ignore file
   (`tests/Dockerfile.dockerignore`), because the root `.dockerignore` excludes
   `tests` — the service image must not carry the suite, and the tests image is
   nothing but the suite. That is a BuildKit behaviour, and a build that used
   the wrong ignore file is caught by a guard in the Dockerfile that says so
   rather than failing later inside node.

   **A COVERAGE RUN CANNOT BE THIS EXACT STACK, AND IS NOW A CONTAINERIZED RUN
   OF ITS OWN.** The reason it cannot be this one is item 4's: the two services
   here are a runner and a service that only speak HTTP to each other, and V8
   writes from inside the process it measures. `./run-coverage.sh` therefore
   uses HALF of this file — `run --rm --no-deps` on the `tests` service alone,
   with the runner starting the service it measures inside that container. Same
   image, same compose file, different shape, and its own compose project so
   that the two runs cannot reach each other's containers.

Twelve tests need only this service, and since 2026-08-28 they are OWNED by two
different repositories — which is the first thing to know about the table below,
because every one of them but the last ran from the parent's suite before that
date. **EIGHT are this repository's own**: `sts_metadata.js`, `admin_api.js`,
`sts_admin_api_operations.js` and `sts_admin_console.js`, deleted over there and
kept here, because each asserts something about this service's `/admin` console
or its `/admin-api` and the tree that adds a control is the tree that should
fail when the control loses its operation — and
`sts_delegated_permissions_example.js`, which was NEVER over there: it was
written here on 2026-09-01 and it drives `/admin-api` to build something for
`/admin` to draw — and `sts_consent.js`, written here the same day and here for
a THIRD reason worth keeping apart from those two. Half of it is an ordinary
protocol test and by the rule below belongs over there; the other half grants a
GLOBAL CONSENT through `/admin-api/consent` and then watches a sign-in stop
being asked, and the assertion that matters is that a console control changed
what the AUTHORIZATION ENDPOINT does. A test with the grant in one repository
and the sign-in in the other could not make it. **And `sts_xacml_endpoints.js`
and `sts_xacml_editor.js`, written here on 2026-09-05, are here for that third
reason and are the strongest case of it**: a PDP with an empty repository
answers NotApplicable to everything, so there is no question worth asking
`/xacml/pdp` until a policy exists, and the only way to put one there over HTTP
is `/admin-api/xacml`. Every assertion in either file therefore spans a console
door and a protocol door — a template built on `/admin-api` deciding at
`/xacml/pdp`, a policy disabled on the console vanishing from what a remote PEP
pulls, a rule built by pressing buttons on `/admin/xacml/editor` changing what
`/xacml/protected` allows. **The other four are still the parent's**, and this repository
holds copies of three of them — `sts_persistence_postgres.js` is not vendored,
because it needs docker.

**Seventeen jobs run from `tests/vendored/`** — the twelve below that a lone
mock can satisfy, plus five others — so they run against this working tree with
no parent checkout present. The paths in the first column are where each file is
READ FROM here; for the four the parent still owns, that copy is not the source
of truth.

| Test | What it covers |
|---|---|
| `tests/vendored/sts_metadata.js` **(ours)** | the `/admin/sts-metadata` drift checks — that the page lists exactly what the router registers, that every method reaches a handler, that every link resolves, and that no specification claim is idle |
| `tests/vendored/admin_api.js` **(ours)** | the management API at `/admin-api`: its OpenAPI document, the PARITY it exists to keep — every `/admin` page and every action of its four handlers has an operation, read off this service's own answers rather than off a list in the test — every documented schema property checked against a live reply, and that a revocation made through the API is dead at `/oauth2/introspect`. It restores everything it changes, including the tokens its bulk revocations touched |
| `tests/sts_dpop.js` | RFC 9449 end to end over HTTP: all twelve section 4.3 checks, the `cnf.jkt` binding on access and refresh tokens, `dpop_jkt`, `jti` replay, and the nonce handshake in both shapes. Almost entirely negatives, because a DPoP server that issues bound tokens and accepts good proofs looks finished and can be worth nothing |
| `tests/oauth2_sts_endpoints.js` | every endpoint the RFC 8414 metadata advertises answers, and every token verifies against the advertised JWKS |
| `tests/vc_did.js` | the DID-named issuer chain: advertisement → resolution → domain linkage → the key that actually verifies the credential |
| `tests/vendored/sts_admin_api_operations.js` **(ours)** | **the other half of that API — EVERY operation it declares, driven for real, with a LEDGER that says so.** No count is written down in it, on purpose: it was ninety operations when the file was written and it is a hundred and thirty-one now (41 reads, 90 writes). Two things are asked of that ledger at the end of the run and both are about the FILE rather than the service — **every documented operation was driven**, or holds a row in `NOT_DRIVEN_HERE` naming who drives it instead (two rows, both the explorer, which `admin_api.js` owns along with its CSP), and **every write that succeeded was read back through the resource's own GET, in the scope it was written in**. Besides that: each documented example body replayed, so that a request property the document names and the handler does not read fails HERE rather than for the first caller who copies it; each handler's refusal sentence checked against the document both ways round (that sentence is what `admin_api.js` reads for the parity, so one short by an action turns the parity check off for it); every write read back through a DIFFERENT operation; and a configuration change followed as far as the persistence store's own write counters. Almost all of it in a trust realm it creates and removes |
| `tests/user_graph_permissions.js` | **AND AN ISSUED TOKEN IS READ AGAINST THAT REGISTER, which is the same line the other way round.** A blue `reaches` line drawn from a credential now names the delegated permissions on that token's scope claim, or says `default permissions` where it asked for none — the two spellings a client may use (the whole permission identifier, or the resource's own client_id) come out as one rule because the question is asked of the TOKEN. In process for three reasons a running service will not hand over: an audience nobody answers to, a scope value that looks like a permission and is not, and a resource carrying permissions with no base URI. Mutation-tested against nine mutants, two of which survived the first round |
| `tests/app_permissions.js` | **a CONFIGURED delegated permission is drawn as intent and never as an act.** In process, and the line it draws is the one this section states: the five API operations, the ordering rule and the refusals are all driven over HTTP by `sts_admin_api_operations.js` and are not here. What is here is the two halves that cannot be — CHOOSING the graph (a dangling grant, and an application granted its own permission, which both console doors refuse to create) and the pure string rules of `base + name` and `name|description`. **Since 2026-09-02 it also owns the GROUPINGS** — `clusters()`, the partition `/admin/delegation/cluster` draws one of — and that is the same line again: the shape that tells *ignore the direction* from *follow the arrows* is TWO CLIENTS OF ONE RESOURCE, and a running service cannot be asked for the register that makes the difference visible beside a dangling grant and a self-grant. Mutation-tested against five mutants, and against nine more for the partition, one of which survived until the fixture grew a client holding permissions on two resources |
| `tests/vendored/sts_admin_console.js` **(ours)** | **the `/admin` console itself, IN A REAL BROWSER since 2026-08-28: the gate, all thirty-eight pages, every link, every GET form and every button on them — and the value that comes back afterwards.** It was an HTTP job, and the argument for that (this console has no script on it, so a control IS a form and pressing a button IS posting it) is still true; what it missed is that a hand-built submission is the TEST's reading of the markup rather than the browser's, that the twenty-two GET forms had no POST target to walk and so were never checked at all, that the nested-`<form>` guard is a PARSER question the old file had to reason about instead of asking, and that a notice is not a value. Status codes and headers come from **WebDriver BiDi**, because `default-src 'none'` blocks a `fetch()` from the page — the thing under test. Plus: every link really visited, which covers the seven routes with no nav row by construction; the five handlers nothing had ever pressed, `/admin/rbac`'s own grant and revoke among them; refusals split into what the BROWSER will not send and what the handler will not accept; the realm switcher; and the browser's own console, which on this console must be empty |
| `tests/vendored/sts_delegated_permissions_example.js` **(ours)** | **THE DELEGATED PERMISSION REGISTER AS A RING, AND THE ONE JOB HERE THAT LEAVES ITS WORK BEHIND ON PURPOSE.** `abcapp1`–`abcapp5` in the DEFAULT realm, each declared for OAuth 2.0 and OpenID Connect with its supporting fields filled in, each exposing `read` and `write` under a base URI of its own, and each granted both on THE NEXT ONE ROUND — `abcapp1`→`abcapp2`→`abcapp3`→`abcapp4`→`abcapp5`→`abcapp1`: five resources, ten permissions, ten grants. **It was a complete mesh of forty grants until 2026-09-01** and the file argues the change rather than merely recording it: the mesh was the stronger test and the weaker EXAMPLE, and this job is both — forty lines between five boxes is the one graph shape that looks the same however it is drawn and however it is wrong, and this example exists to be LOOKED at. What survives is the assertion that matters: every grant still resolves to the RIGHT resource among five whose bases differ only in a digit, so a lookup matching on a prefix, a host or the bare name is wrong for four of the five pairs. What replaced the mesh's arithmetic is an EXACT-LIST assertion per entry — `abcapp2` holding `abcapp4`'s `read` would keep every count right and be wrong about the only thing the example says. Plus the two halves landing on the right ENTRIES (a grant written to the resource instead of the client reads correctly on `/permissions` and finds nothing at the token endpoint), the PICTURE — five boxes, ten lines, `may-reach` on every one and `acts` zero everywhere, because a configured grant has been exercised nought times and the renderer colours `acts && !issued` as a refusal — and the TOKEN, audienced to the one base URI of five that was asked for (its own successor, the only one it holds anything on), carrying the bare names on its scope claim, and moving exactly two of the ten grants to `asked`. It is IDEMPOTENT (the identifiers are fixed, so every previous `abcapp*` is forgotten first) and it does not tear down, because the example exists to be READ at `/admin/delegation/allowed`. **Since 2026-09-02 it also asserts the GROUPING** — that the five are ONE group and that nothing else in the default realm is in it, which are two different failures (a partition too fine, and one too coarse) that a service with only these five configured could not tell apart, and that all five applications resolve to it, since every one of them is both a client and a resource. What it deliberately does NOT assert is the direction decision: a ring is connected whichever way you walk it |
| `tests/vendored/sts_consent.js` **(ours)** | **THE CONSENT SCREEN, AND THE OVERRIDE THAT MAKES IT NOT APPEAR.** Mostly negatives, for `sts_dpop.js`'s reason: a screen that draws, takes an Allow and hands over a code looks finished and can be worth nothing. What it asserts is that a GET of the screen records NOTHING (or anything that prefetches a link has consented for somebody), that a consent id is spendable ONCE, that a consent asked of one person cannot be drawn OR answered by another's session and that every one of those refusals leaves the pending record answerable by the person it belongs to, that Deny records nothing and the refused scope is asked again, that a second request is silent and a new scope asks about ITSELF ALONE, that `prompt=none` answers `consent_required` and `prompt=consent` asks again without destroying what was already agreed. **And the half that is not drivable from the parent's suite and is why this file is here**: a delegated permission consented globally on an application's entry stops a person who has never been here being asked — with NOTHING written about them — while a second application asking for the same permission is still asked, and removing the override asks everybody again including the people it was covering |
| `tests/vendored/sts_xacml_endpoints.js` **(ours)** | **THE SEVEN `/xacml` ENDPOINTS, IN A THROWAWAY TRUST REALM.** Until it existed every route in `xacml/xacml.js` was uncovered — the in-process XACML suite holds the ENGINE to 455 OASIS cases and makes not one HTTP request. What is here is the surface in front of it: a template built on `/admin-api` deciding at `POST /xacml/pdp` against an attribute the request never carried; four malformed requests refused **400 and never Indeterminate**, which is the distinction a PEP most needs, since an Indeterminate would be enforced by its bias; the embedded PEP's two biases disagreeing on the one answer they are supposed to disagree on (NotApplicable, reachable only in a realm whose repository is empty); an obligation this PEP cannot discharge turning a Permit into a refusal and the SAME Permit standing once it is renamed to the one it knows; a remote PEP's pull, its ETag, its 304, and a disabled policy reaching nobody; **a registration named from the client CERTIFICATE and never from the body**, on the registration and on the heartbeat alike, which is the one defect in this family that would be a security bug; a PEP an administrator disabled staying disabled when it reconnects; a policy save that does not wait on an unreachable PEP; and both off-switches answering 501 in the realm while the default realm goes on answering. Mutation-tested against six mutants |
| `tests/vendored/sts_xacml_editor.js` **(ours)** | **THE GUIDED POLICY EDITOR, IN A REAL BROWSER.** `tests/xacml_pap.js` holds the editor's GRAMMAR in process; what it cannot see is whether any of it reaches a page — forty forms in one table, a hidden `path` per row, an `action` that is sometimes hidden and sometimes a `<select>`, and a nested-`<form>` hazard that is a parser question rather than a taste one. So this presses buttons: every row's menu equals the grammar's own answer for that row and Remove is drawn exactly where something may be removed; a Match offers no Add menu and its function list is the two-argument boolean predicates rather than the library; a rule stops offering a second Condition once it has one; an edit that would leave the policy invalid is refused, explained, and **the stored document is byte-for-byte what it was**, which is the property that makes a live editor tolerable. **And the assertion the file is for**: a rule built out of four form submissions makes `/xacml/protected` permit somebody it refused, alternatives are shown to be ORed and matches ANDed by watching that decision move, and removing the rule on the page brings the refusal back. It found one defect on its first run — every refusal on the three `/admin/xacml` pages redirected with an EMPTY `error=` — and was mutation-tested against four more |
| `tests/sts_persistence_postgres.js` | **`persistence.mode=postgres`, and the only test anywhere that RESTARTS this service.** It starts its own database and its own mock, so it touches the shared one not at all. What survives — the realm registry with each realm's overrides, the directory in both realms, the appconfig overrides with their source — and, just as much, **what must not**: the signing key is regenerated, so the `kid` differs and a token minted before the restart is dead at introspection. Plus the two claims nothing else could check: that two processes on one database do NOT see each other's writes (`coordinates: false`, demonstrated rather than read back), and that a database that is not there leaves this service RUNNING out of its seeded directory. Skips, naming which, without docker or without a complete checkout to run |

They are plain node scripts using `assert` and `bunyan`, and they take
`WSTRUST_STS_URL` / `OID4VCI_ISSUER_URL` to locate the service. **All but two
are driven over HTTP with no browser; `sts_admin_console.js` and
`sts_xacml_editor.js` are the exceptions** and the first has been a Selenium job
since 2026-08-28 — the reasoning is in
its own header and in `docs/test-suite-map.md` over there, and the short version
is that a console whose every control is a form is exactly the case where the
BROWSER is the independent implementation of what a form submits.
`sts_dpop.js` writes its **own** DPoP client rather than importing the wallet's, on
purpose: if both sides of the exchange came from one implementation, a shared
misunderstanding would make the test pass and interoperate with nobody. Keep that
property when porting.

**THE DRIFT CHECKS README.md DESCRIBES ARE ENFORCEMENT NOW, AND THIS PARAGRAPH
SAID THE OPPOSITE UNTIL 2026-08-28.** It read "until they are here, they are
documentation rather than enforcement" — true while the only copy of
`sts_metadata.js` was in a checkout this repository could not count on. That
file is THIS repository's own now, it runs on every `./local-run-tests.sh`, and
a route registered and undescribed fails the suite here.

**SCIM has no test in either repository either, and it is the one that would be
cheapest to write.** It is plain JSON over HTTP with no browser, no signature and
no XML, its whole surface is seventeen routes, and the interesting half is
negatives that are hard to provoke from a permissive server and are deliberately
reachable here: `invalid` as a userName, a duplicate userName, an unevaluable
filter, a `.search` body with no schema URN, `/Me`. What a test would also pin
down is the property the feature exists for and no single request demonstrates —
that a `POST /scim/v2/Users` and an `ldapsearch` see ONE entry, that a PUT leaves
`schacDateOfBirth` alone, and that `entryDN` is never written.

**SPIFFE has no test in either repository either, and it is the newest and
largest untested surface here.** What a test would have to cover is not the happy
path — an SVID that verifies against the bundle it came with proves very little —
but the things that were actually wrong during the build and would be silently
wrong again: a `google.protobuf.Struct` whose members serialise to nothing
(`ValidateJWTSVID` answered 200 with empty `claims`), a server stream that ends
when it should stay open, an X509-SVID whose private key does not match its
certificate, `keepCase` spellings, the `MATCH_SUBSET`/`SUPERSET`/`ANY` selector
behaviours, an output mask that is ignored, paging that returns a `next_page_token`
forever, and every one of the refusals above. **The authentication half now has
its own list and it is mostly negatives**: an anonymous caller refused
`UNAUTHENTICATED` and an insufficient one refused `PERMISSION_DENIED` (they are
different instructions and collapsing them is easy); `AttestAgent` and
`GetBundle` reachable with no credential at all, because an agent has none yet;
`Debug.GetInfo` refused to an admin SVID over TCP and allowed on the socket; an
agent allowed `GetAuthorizedEntries` and refused `ListEntries`; a certificate
with no URI SAN, with two, signed by nothing here, outside its validity window,
or naming a trust domain the signing authority does not own; a join token never
minted, expired, replayed, or minted for another agent; `RenewAgent` renewing
the agent on the CONNECTION and never one named in the request; and the same run
with `spiffe.authRequired` off, which must behave exactly as the service did
before any of it existed. Also that one identity presented three ways is ONE
directory entry — **and now that one identity ISSUED a certificate fifty times
is still one entry**, with `x509serialNumber` equal to the last SVID and
`x509svidsIssued` equal to fifty, which is the assertion that catches the
append-versus-assign rule being "simplified" into agreement with
`certificatePlan()`. Beside it: that an issuance adds NOTHING to
`/admin/users`'s authentication count (an agent holding `FetchX509SVID` open
would otherwise read as hundreds of sign-ins overnight); that the `x509subject`
an SVID writes is byte-for-byte the string a client certificate with that
subject would write, because two spellings of one DN is two people; that
deleting ONE of two registration entries naming an identity leaves it active and
deleting the second marks it revoked; that a ban and an unban round-trip while
`spiffeRevokedAt` survives the unban; and that nothing anywhere is ever deleted
from `ou=users`. Drive it with `@grpc/grpc-js` as a
CLIENT — which is what `tests/sts_dpop.js` does by writing its own DPoP client
rather than importing the wallet's, and for the same reason: if both ends came
from one implementation, a shared misunderstanding passes and interoperates with
nobody.

**SAML 2.0 Web Browser SSO HAS ONE, IN THE PARENT PROJECT, AND IT IS THE FIRST
THING HERE THAT WAS COVERED ON THE DAY IT LANDED.** `tests/saml_sso.js` and
`tests/saml_logout.js` take `SAML_IDP=keycloak|sts` and drive BOTH identity
providers through the same assertions — the arrangement `tests/wsfed_sso.js`
already had, and the one that catches a mock being quietly more permissive than
the real thing. Four jobs run against this service: SSO over each of the three
bindings, and Single Logout. `./local-run-tests.sh --saml-only=sts` is the fast
loop and needs no Keycloak at all.

Two things about that pairing are worth knowing before changing either half.
**Nothing is provisioned for the `sts` side** — any entityID is accepted, the
metadata is minted on the ask, and the application entry is created by the first
valid AuthnRequest — which is why there is no `configureX` step for it anywhere
in those launchers. And **the metadata URL carries a DIGEST** of the service
provider's entityID, because the document is published per service provider; the
launchers compute that segment with `sha256sum` rather than guessing it, and a
change to `slugOf()` in `saml/saml2_sso.js` breaks three shell scripts that
nothing here can see.

`tests/saml_encrypted_sso.js` is deliberately NOT paired: this profile encrypts
no assertion, so an `sts` half could only ever fail or skip.

**SAML 1.1 HAS ONE TOO, IN THE SAME PLACE, AND IT IS A DIFFERENT KIND OF TEST.**
`tests/saml11_sso.js` over there drives `/saml11` over HTTP with a relying party
it writes itself and no browser at all — 131 checks, mostly negatives. It has no
Keycloak half and will not get one: Keycloak has spoken no SAML 1.1 for years,
and **the debugger has no SAML 1.1 service provider either** — `saml_tools.html`
composes and signs a 1.1 assertion and the WS-Trust and WS-Federation response
pages consume one, but that project's SAML workflow is SAML 2.0 SP-initiated and
returns an XML comment where a 1.x request would be. So the relying party in that
test is the only one there is, which is why it is written by hand.
`./local-run-tests.sh --saml-only=sts` runs it beside the four SAML 2.0 jobs.

**FEDERATION HAS A TEST, AND SINCE 2026-08-26 IT IS IN THE PARENT SUITE LIKE
EVERY OTHER PROTOCOL TEST.** `tests/federation_sso.js` over there drives a
federated sign-in across two TRUST REALMS of one process: the debugger's
OAuth2/OIDC workflow is the application, `federation-realm-1` is its OpenID
Provider and the SAML 2.0 service provider of the relationship, and
`federation-realm-2` is where a name is typed. It was `federation-e2e/` here —
three containers, two instances of this service and a web application written
for it — and realms made all of that scaffolding unnecessary. What the move gave
up is the front-channel / back-channel distinction, which needs two origins;
what it bought is a test that runs in the ordinary suite on every stack in about
four seconds.

**`tests/federation_choice_sso.js` JOINED IT ON 2026-08-26 AND IS THE ONLY ONE
THAT DRIVES AN APPLICATION WITH TWO PARTNERS.** `appFederationRelationship` on
an application entry holds a LIST now, so one application may name a SAML 2.0
relationship AND an OpenID Connect one, and this service then draws
`/authn/select-idp` — one button per partner, no password field — instead of
redirecting. That job signs in TWICE, once through each button, because the only
assertion that distinguishes an honoured choice from a service that took the
first usable partner is arithmetic on the two relationships' counters. See
`federation/CLAUDE.md` and `authn/CLAUDE.md`.

**It is an INTEGRATION test and it is not the list below.** What it proves is
that the pieces fit: that a federated identity satisfies a flow the application
started, that the ID Token the application verifies comes from the service
provider rather than from the partner and names the partner nowhere, and that
the directory, the counters and the applications registry all record what
actually happened. It asserts exactly ONE refusal — a forged unsigned assertion,
turned away 401 on the signature and recorded without counting as a sign-in.
**Its predecessor found a real defect on its first run** — a foreign subject
reaching `startSession()` unnormalised, so this service's own subject prefix was
applied twice and the session disagreed with the directory about who had signed
in — which is the best argument for either of them existing.

What it does NOT cover is the list below, and that list is still the gap:

**THE REFUSALS HAVE NO TEST IN EITHER REPOSITORY, AND THIS IS THE SURFACE WHERE
THAT COSTS MOST** — because it is the only one here whose bugs are SECURITY bugs
rather than fidelity bugs. Everywhere else a missing check makes this service
more permissive than it says it is, which is what it is for; at
`/federation/acs/{id}` a missing check is an authentication bypass for every
protocol in the process. And a happy path proves almost nothing: an assertion
that verifies against the key it was signed with is not evidence that anything
would have been REFUSED. The full list is in `federation/CLAUDE.md` and it is
almost entirely negatives — an assertion signed by nobody, by a different key,
naming a different issuer, with the signature over a different element, or
carrying its OWN `ds:KeyInfo` certificate (the one a naive implementation
accepts); a `RelayState` never minted, expired or replayed; an ID Token with
`alg: none`, with HS256 against an RSA key, with an unknown `kid`, or with the
wrong `aud`, `iss` or `nonce`; every refusal in `federation_http.js`; and a
relationship disabled, and half-configured. Beside those, the directory
assertions only a test can make: that a partner's `mail` OVERWRITES an invented
one and never the other way round, that `uid` is never written from an
assertion, and that a release list filters the custom claims while leaving the
protocol's own untouched. **Write the partner side rather than importing this
one**, for `tests/sts_dpop.js`'s reason — and here a shared misunderstanding
about which element a signature covers would not merely interoperate with
nobody, it would BE the hole.

**THE USERINFO ENDPOINT'S TWO NEW HALVES HAVE NO TEST IN EITHER REPOSITORY,
and by the line above they belong in the PARENT suite** — every one of the
assertions below can be made by driving the running service over HTTP, so
nothing about them justifies a directory here. What a test would have to cover
is almost entirely the CLAIMS REQUEST, because the configured `userinfo` set is
the four claim sets' behaviour on a fifth set and the one thing about it that is
its own is worth one assertion: a claim added to it reaches a client that
already holds its token, with no new sign-in. The rest is OIDC Core section 5.5,
and it is mostly negatives: a `claims` parameter that is not JSON, is not an
object, whose `userinfo` member is a string or a number, whose individual claim
request is a number, whose `essential` is not a boolean, whose `values` is not a
non-empty array, or that names more claims than the cap — each refused at the
AUTHORIZATION endpoint with `invalid_request` and the reason, which is where the
client can still be told; an unknown TOP-LEVEL member ignored rather than
refused, and named in the reply; a name nothing can resolve simply absent and
never an error; an `essential` one absent too; a `value` that does not match
answered with the value HELD. Beside those, the properties that only a test can
pin down: that the parsed request rides in the access token and survives a
REFRESH, that the ID Token honours the `id_token` member and the UserInfo
response the `userinfo` one, that `address` returns the whole Address Claim
where `address.locality` returns one member, that `family_name#ja-Kana-JP` comes
back under exactly that name, that a requested claim beats the scope-driven one
and `sub` beats everything, that the federation release policy filters a
requested claim exactly as it filters a configured one, and that the non-spec
request-level parameter is a UNION with the token's own request and can never
take a claim away from it.

**THE SPNEGO SIGN-IN HAS BOTH HALVES OF ITS TEST SINCE 2026-08-27, AND THEY ARE
IN DIFFERENT REPOSITORIES ON PURPOSE.** `tests/spnego_identity.js` here asserts
what a session minted from a ticket CLAIMS — which part of the principal becomes
the username, and the `amr`/`acr` read off the ticket's flags — and it is here
rather than in the parent's suite because the cases that matter cannot be
produced over HTTP: this KDC requires pre-authentication, so no client can
obtain a ticket claiming no factor at all, and nothing here ever sets
`hw-authent`. The other half needed a listener and is
`tests/kerberos_spnego_signin.js` over there, which drives the DEBUGGER's own
AS, TGS and SPNEGO pages to build a real service ticket, spends it at
`/authn/spnego`, and then completes an ordinary OIDC Authorization Code flow on
the session that comes back. It covers: that a real AP-REQ produces a real
session; that the session satisfies `/oauth2/authorize` with no screen drawn;
that the ID Token's `sub`, `amr` and `acr` are the ones read off the ticket;
that `appAuthnMechanism: spnego` on an application entry sends an authorization
request straight to this door instead of to the password screen; that a REPLAYED
AP-REQ is refused and mints nothing (the replay cache is the one check here
whose absence would be a security bug rather than a fidelity one); and that
`krb5.spnegoAuthentication` off answers 403 NAMING THE SETTING and signs nobody
in. Each of those three was mutation-tested against a deliberately broken mock
before it was committed.

**THE BROWSER DOES NOT ANSWER THE CHALLENGE THERE, AND THAT IS A DECISION RATHER
THAN A GAP.** RFC 4559 is answered from GSSAPI, which needs a credential cache
and a host allow-list that the suite cannot assume on the machine it runs on —
so the debugger is the Kerberos client instead, which shows more of the protocol
than a browser handing the work to GSSAPI ever would. What that costs is one
assignment: the `Set-Cookie` arrives at the api relay, and the test carries it
into the browser before driving the application flow. The file's header says so
rather than burying it.

**A REAL-GSSAPI JOB IS NOW POSSIBLE AND IS NOT WRITTEN.** It was impossible
until 2026-08-27 for a reason nothing had noticed: this KDC advertised no
PA-ENC-TIMESTAMP, so no MIT-derived client could get a ticket from it at all —
see *The KDC advertises PA-ENC-TIMESTAMP* in `kerberos/CLAUDE.md`. With that
fixed, `kinit`, `kvno` and `curl --negotiate` complete against this service end
to end, and a browser with a ccache and an allow-list entry would too. Such a
job needs `krb5-user` in the parent's `tests/Dockerfile` and a per-run
`krb5.conf`, so it would SKIP wherever that tooling is absent — which is why it
is not where the only coverage of this door lives.

Still untested at this door: that a ticket for another ACCOUNT's SPN is refused
while one for a host this service answers for is not; that a half-finished
`request-mic` exchange begun at `/spnego/protected` cannot be spent here; and
that exactly ONE authentication is recorded per sign-in rather than a ticket
acceptance beside a session start.

**WS-Federation has no test in either repository.** The mock relying party at
`/wsfed/rp` makes it look covered — it verifies a sign-in response check by check —
but a person has to click it and read the page. What a test would add is the
negatives, which is where this profile's value is: an altered `wctx`, `wauth`
demanding a factor the session never had, `wfresh` read as seconds rather than
minutes, a SAML 1.1 signature whose reference does not resolve because `AssertionID`
was not named. A passive requestor that issues a good token to a working relying party
looks finished and proves almost nothing.


## Things this service deliberately does not do

Worth knowing before "fixing" one of them. **This is an INDEX, not a summary** —
each line names the thing and points at the file that argues it, because an
argument in two places is an argument that will disagree with itself.

| It does not | Where the argument is |
|---|---|
| Enforce anything by default — `oauth2.rfc9700` is the one mode, off unless set | `oauth-oidc/CLAUDE.md` |
| Federate with anybody it was not CONFIGURED to federate with — the one place this service refuses by default, and the one refusal that is not a mode | `federation/CLAUDE.md` |
| Decrypt an assertion a federation partner encrypted, consume a federated SIGN-OUT, or re-check a federated person after the session exists | `federation/CLAUDE.md` |
| Dial any URL a CALLER supplied for this service to fetch something FROM — `jwks_uri` on an application entry and WS-Federation's `wreqptr` are still never followed, and that is the position both files argue. **THREE URLs are dialled and each is an address somebody is asking to be SENT something at**: a federation relationship's, which an administrator configured; an SSF receiver's push endpoint, which RFC 8935 defines as the receiver telling the transmitter where to post; and a registered XACML PEP's notify URL, which is the weakest of the three and pays for itself by carrying nothing — the PEP pulls and converges whether or not the nudge arrives | `federation/CLAUDE.md`, `ssf/CLAUDE.md`, `xacml/CLAUDE.md`, `oauth-oidc/CLAUDE.md` |
| ASK anybody's permission before it issues something — **this row is REVERSED since 2026-09-01 and is the one entry in this table that now reads the other way.** `/oauth2/consent` asks, and `oauth2.consentRequired` is ON by default, which no other policy here is. It is not a refusal and that is why: it is the screen every real authorization server draws on a first sign-in, and a client that has never met one has never run the code that survives it. It still checks nothing — the person has already been let in under any name they typed | `common/CLAUDE.md`, `oauth-oidc/CLAUDE.md` |
| Check any end user's password, in any protocol — **with one exception since 2026-08-26**: a Kerberos ticket presented at `/authn/spnego` is verified against a real long-term key before a session is minted, because Kerberos cannot be permissive the way everything else here is. The KDC behind it still is | `authn/CLAUDE.md`, `kerberos/CLAUDE.md` |
| Check any credential except a registered client's secret, in RFC 9700 mode only | `oauth-oidc/CLAUDE.md` |
| Refuse any LDAP bind — any DN, any password, anonymous, on 389 and 636 alike | `ldap/CLAUDE.md` |
| Check a Kerberos password, though it cannot not check the KEY | `kerberos/CLAUDE.md` |
| Verify an access token it did not issue, except at UserInfo | `oauth-oidc/CLAUDE.md` |
| Enforce `value` or `values` in an OIDC Core 5.5 claims request, or treat `essential` as an instruction — all three are carried, checked and reported, and section 5.5.1 says a server MUST NOT error for an unavailable claim | `oauth-oidc/CLAUDE.md` |
| Require DPoP — nonce mode makes proofs fresher, not mandatory | `oauth-oidc/CLAUDE.md` |
| Turn a verified client certificate into a login | `tls/CLAUDE.md` |
| Verify anything in an issued credential's values, which are invented | `oid4vc/CLAUDE.md` |
| Turn a verified presentation into a sign-on | `oid4vc/CLAUDE.md` |
| Deactivate anybody on SCIM `active: false` | `scim/CLAUDE.md` |
| Attest a workload or a node | `spiffe/CLAUDE.md` |
| Revoke a SPIFFE credential — the directory now records who may still be ISSUED one, which is a different claim | `spiffe/CLAUDE.md`, `ldap/CLAUDE.md` |
| Let a group grant anything — bar the TWO that grant the admin console and nothing else | `admin-ui/CLAUDE.md`, `common/CLAUDE.md` |
| Decide who may delegate to whom IN THE ACT, in two of the three families that can — the KDC polices S4U on every request; WS-Trust polices nothing. **RFC 8693 is no longer on this row unqualified**: since 2026-09-01 a DELEGATED PERMISSION may be configured between two OAuth application entries, and `oauth2.delegatedPermissionsEnforced` — off by default — refuses a request for one the client does not hold | `common/CLAUDE.md`, `kerberos/CLAUDE.md`, `oauth-oidc/CLAUDE.md` |
| Give a trust realm its own Kerberos KDC, TLS listeners or SPIFFE signing authority — those three socket families have no path to put a realm segment in and no name inside the protocol to put one in either. **The DIRECTORY is no longer on this list**: it is a subtree per realm since 2026-08-25, because a DN is a name a client can carry | `common/CLAUDE.md`, `ldap/CLAUDE.md` |
| Give a trust realm its own administrator — the two console roles are groups in the DEFAULT realm's directory, read there from every realm, and the console's gate accepts that realm's session only. Deliberate: a per-realm roster would let anybody who can create a realm administer the whole service | `common/CLAUDE.md`, `admin-ui/CLAUDE.md`, `ldap/CLAUDE.md` |
| Persist anything it MINTS — sessions, tokens, codes, artifacts, Kerberos tickets, the statistics, the audit log — in any mode, because the signing key is regenerated on every start and a token that outlived it would verify against nothing. **What it DOES persist since 2026-08-27, when a store is configured, is the three things somebody TYPED**: the embedded directory, the trust realm registry and the runtime appconfig overrides. This row said "persist anything at all" until that date | `persistence/CLAUDE.md`, `admin-ui/CLAUDE.md` |
| Dial its database in the clear — since 2026-08-30 the compose stack's PostgreSQL refuses a plaintext connection (`hostssl` on every rule) and the client asks for `sslmode=require`, so both ends say it. It does NOT authenticate that server: the certificate is generated in the container and signed by nobody, which `/admin/persistence` reports as two facts rather than one tick | `persistence/CLAUDE.md` |
| COORDINATE several processes through that store — two copies pointed at one database each hold their own directory in memory and never see each other's writes. Persistence is not clustering, and the store's own status says so | `persistence/CLAUDE.md` |
| Recall anything it has already ISSUED — a SAML assertion, a Kerberos service ticket, an X509-SVID. `/logout` lists them anyway, with the reason | `logout/CLAUDE.md` |
| Perform back-channel logout. Front-channel IS implemented; the metadata says which | `oauth-oidc/CLAUDE.md` |
| Fake WS-Federation's `wauth`, or dereference `wreqptr` | `ws-federation/CLAUDE.md` |
| Verify a SAML AuthnRequest's signature, or consume SP metadata — both recorded, neither checked | `saml/CLAUDE.md` |
| Encrypt an assertion **to a service provider it holds no certificate for** — it sends it in CLEAR and says so loudly, rather than refusing to issue. Encryption itself arrived 2026-08-27 and this row said the opposite until then | `saml/CLAUDE.md` |
| Dial a service provider's metadata URL WHILE ISSUING — the fetch is an explicit action that writes the certificate onto the entry, so no sign-in waits on somebody else's web server | `saml/CLAUDE.md` |

FOUR exceptions to the whole of that list, and each is worth knowing before
reading further. **The SCIM endpoints REQUIRE a credential** — in any of the six
schemes RFC 7644 section 2 names, with the OAuth ones needing `scim:read` or
`scim:write` — because they create and DELETE accounts. **The SPIRE Server
API requires an X509-SVID over mutual TLS** and authorizes every method against
SPIRE's own per-method table, because what comes out of that surface is a
credential another service will believe. And **the ADMIN CONSOLE at `/admin`
requires a sign-on session and one of two roles**, because it is the one surface
that can change what every protocol endpoint does. All three are a turnstile
rather than a lock, and each can be turned off (`scim.authRequired`,
`spiffe.authRequired`, `admin.authRequired`).

**A FOURTH IS NOT A TURNSTILE AND IS NOT GUARDING ANYTHING**: `/authn/spnego`,
where a KERBEROS TICKET is verified against a real long-term key before a
session is minted. It is on this list only because Kerberos cannot be permissive
the way the rest of this service is — the password there IS the key — so the
mock's permissiveness had to move into the KDC's ACCOUNT POLICY (one shared
password, an account for any name) and leave the verification real. The row
above about not checking passwords holds everywhere else, and the reason it
cannot hold here is `kerberos/CLAUDE.md`'s. `krb5.spnegoAuthentication` turns
that door off.

The console's is the newest and the one with the most surprising edges, all of
which are argued in `admin-ui/CLAUDE.md`: the two roles are ORDINARY DIRECTORY
GROUPS rather than a store of the console's own, so four doors write one
membership; **`/admin-api` is deliberately NOT gated**, which is what a test
drives and what somebody locked out reaches for — and also means anybody who can
reach this port can grant themselves both roles; and while NEITHER role group has
a member, anybody who signs in holds both, because this service has no password
anywhere to bootstrap an administrator with.

**The Workload API is the opposite case and the distinction matters**: it
authenticates nobody because its specification says it MUST NOT — a workload has
no root of trust until that call gives it one. What it lacks there is
ATTESTATION, not authentication.

## The parent project's paths into this repository are RIGHT, and what keeps them so

**This section said they were wrong until 2026-08-28, and the migration it
described has happened.** `../id-proto-debugger` reaches in here by path in three
places — `tests/Dockerfile`'s `COPY sts/…` block, `tests/module_paths.js`'s
`mockStsModule()`, and the two byte-compare tests — and the 2026-08-23
reorganisation broke all three. All three are fixed over there, and the `sts/`
gitlink has moved on twice since — it is at `c3b4294` on `feature/201` as of
2026-08-29, rather than the pre-reorganisation `cae2066` this file named for
five days.

One of the three came out differently from what was prescribed, and that is the
part worth knowing here: **`mockStsModule()` SEARCHES the subdirectories rather
than being handed one**, so its four Kerberos callers still pass BARE filenames
and are correct. Do not "fix" them.

What is left is not a migration but a standing obligation, and it is the one
thing about that project this file carries: **the `sts/` COPY set in
`tests/Dockerfile` is the transitive closure of what `krb5_kdc.js`,
`krb5_service.js` and `spnego.js` require, and it moves on THIS repository's
schedule.** Add a require reachable from any of those three and that project
needs a COPY line, in the commit that bumps the pin across the change — miss it
and four in-process Kerberos jobs die at load with `Cannot find module`, which
names a file nobody edited. The closure is in `docs/parent-project-migration.md`.

**THAT DOCUMENT'S ONE OUTSTANDING ITEM WAS PAID ON 2026-08-28 AND THE OBLIGATION
IS NOT.** `common/pq_jose.js` was the file the next bump owed, and the parent
committed `COPY sts/common/pq_jose.js ./sts/common/` in the same change that
moved the pin to `c3b4294` — which carries that file — so the two landed
together exactly as that document says they must. Walking the closure against
the current pin today finds all thirty files copied and nothing missing. The
obligation stands for the NEXT require added under those three entry points; it
is the walk that is standing, not any particular file.
