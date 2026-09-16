# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in
this repository.

**It is the thin one, and on 2026-09-13 it was made thin a second time.** Almost
every fact about a module lives in the `CLAUDE.md` of the directory that module
is in, and this file keeps only what is genuinely cross-cutting: where things
are, the require order and the rules about libraries and hooks, the two CSP
rules, the endpoint-drift rule, the error-code rule, the code style, the
submodule warnings, the state of the tests, and an INDEX of what this service
deliberately does not do. **There is one copy of each fact.** If something here
looks like a summary of a directory file, it is a bug — say so rather than
reconciling the two.

**It had grown back to 1957 lines in eight days**, the same way it grew the
first time: a date-stamped paragraph added here beside the directory file that
already said it, until a table cell ran to a page. The rule that stops it is the
one above, and the test for a new paragraph is short — *would a reader of the
directory's own file miss this?* If yes it goes there, and this file gets at
most a row in a table.

**Two different things happen to the text that leaves, and they are worth
telling apart.** Prose that had no home elsewhere is MOVED — verbatim, into the
directory that owns it. Prose that was a summary of a directory file is DELETED,
because the destination already says it, usually better and always in more
detail.

| What left this file | Where it is now |
|---|---|
| **2026-09-05** — the worker pool's five things to know, the realm's eleven keys, the per-realm store rule | `common/CLAUDE.md` |
| **2026-09-05** — why the main port is HTTPS, the appconfig files | `env/CLAUDE.md` |
| **2026-09-05** — `persistence.js` binding nothing and still going first | `persistence/CLAUDE.md` |
| **2026-09-05** — the job table, the TLS anchor every job gets, the launchers, the coverage run | `tests/CLAUDE.md` |
| **2026-09-05** — what a SCIM, SPIFFE, UserInfo, SPNEGO test would cover | each family's file |
| **2026-09-05** — the two shell scripts the database container runs | `postgres/CLAUDE.md` |
| **2026-09-13** — the hosted surfaces as OIDC relying parties, the realm split, the `Location` header | `common/CLAUDE.md` (`oidc_rp.js`) |
| **2026-09-13** — one listener process and N workers, `protocol_stack.js`, BOTH worker pools, the barrier, the tickets, `readYourWrite`, the measurements | `common/CLAUDE.md` |
| **2026-09-13** — LDAP as a dispatched operation, the connection mirror | `ldap/CLAUDE.md` |
| **2026-09-13** — SPIFFE's dispatched gRPC methods, per-realm trust domains | `spiffe/CLAUDE.md` |
| **2026-09-13** — the listener certificate after `build-root`, the truststore pin | `tls/CLAUDE.md` |
| **2026-09-13** — the signing key in development mode, `mode.js`, versioning, the error-code design | `common/CLAUDE.md` |
| **2026-09-13** — the remote PEP's version reporting | `xacml-pep/CLAUDE.md` |
| **2026-09-13** — the XACML gates and `POST /xacml/pip` | `xacml/CLAUDE.md` |
| **2026-09-13** — `/admin-api`'s access token | `mgmt-api/CLAUDE.md` |
| **2026-09-13** — the per-slot arguments of rule 3e, the second metadata page, the account menu and certificate dialog refusals | `admin-ui/CLAUDE.md` |
| **2026-09-13** — `portal.setDirectory()`, `/portal/keys`' script | `portal/CLAUDE.md` |
| **2026-09-13** — the parent project's Kerberos COPY closure, and what it is owed | `kerberos/CLAUDE.md` |
| **2026-09-13** — where a new test goes, the negatives note | `tests/CLAUDE.md` |
| **2026-09-13** — the prose of every row of *Things this service deliberately does not do* | the file each row names |

## Where things are

The 2026-08-23 reorganisation moved every module out of the package root. The
files did not change; the paths did.

| Directory | What is in it |
|---|---|
| `common/` | Everything more than one family reads — settings, the express app, **`crypto.js` (the one place this service signs, verifies, encrypts and decrypts)**, trust realms, both worker pools and the shared require order, the registers (applications, delegation, permissions, consent, roles, the issuance gate), the certificate authority (`pki.js`), the second factors, the password policy, the error-code table, and **`mode.js`, the one place `development` and `product` are told apart**. `common/CLAUDE.md`. |
| `common/vendored/` | Byte-identical copies of the parent project's files — `xmldsig.js`, the PKI and post-quantum encoders — plus the JSON-LD `contexts/`. **Do not edit them here.** `common/vendored/CLAUDE.md`. |
| `home/` | The front door: `GET /` and the one image on it. `home/CLAUDE.md`. |
| `logout/` | The protocol-independent sign-out at `GET|POST /logout`, and the one model of what a live session is, per identity (`/admin/logout`) and service-wide (`/admin/sessions`). `logout/CLAUDE.md`. |
| `portal/` | **The user portal**: the pages that belong to the person looking at them, where no route takes an identity from the request, behind a navigation column that is not the console's. `portal/CLAUDE.md`. |
| `oauth-oidc/` | The authorization server and OpenID provider: RFC 9700 mode, DPoP, mTLS, client authentication, both RFC 7523 and RFC 7522 assertion profiles, the multi-AS profiles, the consent screen and UserInfo. `oauth-oidc/CLAUDE.md`. |
| `authn/` | The sign-in service, which **owns the SESSION**: the WebAuthn relying party and the TOTP and recovery-code steps. `/authn/spnego` lives in `kerberos/`. `authn/CLAUDE.md`. |
| `saml/` | The SAML 2.0 and SAML 1.1 assertion builders, each with a SEPARATE browser-facing identity provider rather than one with a version flag. `saml/CLAUDE.md`. |
| `ws-trust/` | WS-Trust 1.0–1.4. `ws-trust/CLAUDE.md`. |
| `ws-federation/` | WS-Federation 1.2's passive requestor profile and a mock relying party. `ws-federation/CLAUDE.md`. |
| `federation/` | Federation relationships in either direction, in five protocols; `ou=federations` is the register, and it holds the first and strongest of the outbound requests. `federation/CLAUDE.md`. |
| `kerberos/` | The KDC, the acceptor, SPNEGO (the negotiation, the page, and the sign-in that turns a ticket into a session), and eight codec modules **VENDORED from the parent project and not editable here**, despite not being under `common/vendored/`. `kerberos/CLAUDE.md`. |
| `ldap/` | The embedded directory — the store for people, groups, applications and the SPIFFE registry — and the eight `/admin/ldap/*` console pages that show it. `ldap/CLAUDE.md`. |
| `cluster/` | **Several containers against one postgres store** (#46, 2026-09-14): membership and leases with a fencing token every write transaction checks, the gate in front of `cluster.mode` (active-passive by default in product mode on postgres; active-active refused while a capability is missing), atomic claims, the secrets every node shares, and the cross-node read barrier. Libraries — no route but `/admin/cluster`'s status block. `cluster/CLAUDE.md`. |
| `persistence/` | The one place this service writes anything down (`memory`, `ldif`, `postgres`), and the coordination of several processes through one change log — state, not sockets. `persistence/CLAUDE.md`. |
| `scim/` | `/scim/v2`, its authentication and attribute mapping, and two console pages (`/admin/scim`, `/admin/scim/monitor`). `scim/CLAUDE.md`. |
| `ssf/` | The Shared Signals Framework — the one family here that TALKS BACK — with CAEP and RISC as the two vocabularies over it and this service's own console and portal as registered receivers. `ssf/CLAUDE.md`. |
| `spiffe/` | Six libraries, one server module and the vendored `protos/`: a trust domain per realm under the service Root, bound on an address of its own when turned on. `spiffe/CLAUDE.md`. |
| `tls/` | The 8443 and 9443 listeners, and the certificate three other sockets share. `tls/CLAUDE.md`. |
| `oid4vc/` | OpenID4VCI, OpenID4VP and DID Core. `oid4vc/CLAUDE.md`. |
| `admin-core/` | What both admin surfaces DO, in a directory neither owns: `admin_actions.js`, `admin_views.js`, `certificate_views.js`. It requires route-registering modules, so it may be required at 18 or later and is not in `common/`. `admin-core/CLAUDE.md`. |
| `admin-ui/` | The console at `/admin`, its gate and two roles, every setting drawn on its protocol's page (`SETTING_HOMES`), the two server-laid-out drawings, and the pages that report on this service itself — `/admin/crypto-metadata`, `/admin/pki`, `/admin/secrets`, `/admin/api-explorer`. `admin-ui/CLAUDE.md`. |
| `mgmt-api/` | `/admin-api` — every console control, reachable by a machine (rule 7), gated by an OAuth 2.0 access token — its generated OpenAPI document, and the explorer's assets. `mgmt-api/CLAUDE.md`. |
| `tests/` | **The only test directory**: `tests/*.js` is the in-process half (`npm test`), `tests/vendored/` the protocol half driven over HTTP against a container built from this tree, with `MANIFEST.js` the count and the record of which jobs are copies and which are `local: true`; `tools/`, `Dockerfile` and `run-tests-in-container.sh` are tooling, not tests. `tests/CLAUDE.md`. |
| `xacml/` | XACML 3.0 and ALFA — the engine (held to the vendored OASIS suite, Apache-2.0), the `ou=policies` repository, the PIP, the embedded PEPs that decide this service's own issuance and access, the PAP console, and the PDP side of the remote PEP. `xacml/CLAUDE.md`. |
| `gnap/` | GNAP (RFC 9635) and its resource server connections (RFC 9767): a key-proofed authorization server per trust realm, issuing tokens in five formats. `gnap/CLAUDE.md`. |
| `acme/`, `est/`, `scep/` | **CERTIFICATE ENROLLMENT, IN THREE PROTOCOLS (2026-09-13)** — ACME (RFC 8555) at `/enroll/acme`, EST (RFC 7030) at `/.well-known/est` and SCEP (RFC 8894) at `/enroll/scep`, each with an Issuing CA of its own under the realm's Intermediate, a console page under Protocols (in a *Certificate enrollment* group) and one under Monitoring, and `/admin-api` operations declared in `<family>_api.js`. **None of the three decides who may have a certificate for whom or what goes in it**: that is `common/cert_enrollment.js` (rule 3ag) — yourself, or any person or application in the realm for a holder of Admin Write; the nine leaf profiles of `/admin/pki` and the five refused; names built from the ENTRY, a host name only when registered on it; every certificate kept on the entry it names, and a private key only when this service generated it (EST `/serverkeygen`). Authentication is protocol-native: an ACME account bound FOR LIFE by an External Account Binding key, EST's password, client secret or realm-issued certificate, a SCEP single-use challenge password. A person makes their own EAB key and challenge on `/portal/certificates`. Each directory's `CLAUDE.md` carries its RFC coverage and its documented exceptions. |
| `xacml-pep/` | **Not part of the mock**: a second container, a remote XACML PEP that pulls policy from `/xacml/pep/policies` and decides with a build-time copy of the engine. `xacml-pep/CLAUDE.md`. |
| `openbao/` | **Not part of the mock**: the files a secret-store container runs, from which the compose stack reads its key-encryption key and database password with a read-only client certificate. `openbao/CLAUDE.md`. |
| `deploy/aws/` | **Not part of the mock**: Terraform for a three-node active-active cluster on ECS Fargate behind an NLB, against RDS PostgreSQL 18 with a replica, with the key-encryption key and database password in AWS Secrets Manager — a long-lived `foundation/` (deployer identity, KMS, ECR, logs) and a per-run `environment/`, the schema-init image, the suite runner, and `.github/workflows/aws-cluster.yml`. `deploy/aws/CLAUDE.md`. |
| `debugger/` | **The embedded identity protocol debugger** (2026-09-13): the parent project's client and api served on a listener of their own (`debugger.port`), signed in to through this service's authorization server, the api a FORKED CHILD behind an access token only a console administrator is issued. `debugger/embedded/` is that project's build output, never source. `debugger/CLAUDE.md`. |
| `postgres/` | Four files the database container runs, never this service: TLS setup, TLS enforcement, the schema and the least-privilege `sts_app` role. `postgres/CLAUDE.md`. |
| `docs/` | The GitHub Pages site — how to USE this service. `docs/CLAUDE.md`. |
| `env/` | The appconfig files, each a layer over the generated `defaults.js`. `env/CLAUDE.md`. |

At the package root there are exactly two modules, and both earn it:
**`server.js`**, the shell that requires the others and listens, and
**`sts_metadata.js`**, which reads the router to list what everything else
registered and is therefore required last.

**Read the directory's own `CLAUDE.md` before changing anything in it.** They are
not summaries — the reasoning is in them, and most of it is the record of
something having gone wrong once.

`README.md` is the substantive document and is still at the root. `docs/` is the
user-facing half; this file and the directory files are the maintainer-facing
half.

## Overview

A mock identity service — and, in `product` mode, a deployable one — that speaks
these protocol families:

- **Kerberos v5**: a KDC on TCP/UDP 88 and MS-KKDCP, a protected service, and SPNEGO (RFC 4559/4178).
- **WS-Trust** 1.0–1.4.
- **SAML 2.0**: assertions, and Web Browser SSO over three bindings with Single Logout.
- **SAML 1.1**: assertions, Browser/POST and Browser/Artifact, and an attribute-authority responder.
- **WS-Federation 1.2**: the passive requestor profile.
- **Federation**: either end of a relationship with a foreign identity service, in five protocols.
- **OAuth 2.0 / OpenID Connect**: a full authorization server, with DPoP.
- **RFC 7521/7523 and RFC 7521/7522**: JWT and SAML assertions as client credentials and as grants.
- **WebAuthn Level 3, RFC 6238 TOTP and recovery codes**: the second factors on the sign-in screen.
- **OpenID4VCI 1.0, OpenID4VP 1.0**, and W3C DID Core with DIF domain linkage.
- **LDAP v3**: an embedded directory on 389 and LDAPS 636.
- **SCIM 2.0**: provisioning into that same directory, with no store of its own.
- **TLS / mutual TLS**: listeners on 8443 and 9443 whose content is what the server saw of the connection.
- **Shared Signals** (SSF 1.0, with CAEP and RISC): a transmitter, and a receiver of its own.
- **A certificate authority**: one Root, an Intermediate per realm, CRLs and OCSP (`/admin/pki`).
- **SPIFFE**: the bundle endpoint, the Workload API and the SPIRE Server API, per trust realm.
- **XACML 3.0** and **GNAP** (RFC 9635).

It exists to exercise *clients*: in development mode it checks no password,
validates no access token and **attests no workload**. The surfaces below are
the exceptions, and each is argued where it lives.

| Surface | What it requires | Argued in |
|---|---|---|
| `/scim/v2` | a credential in any of RFC 7644 section 2's six schemes; the OAuth ones need `scim:read` or `scim:write` | `scim/CLAUDE.md` |
| the SPIRE Server API | an X509-SVID over mutual TLS, authorized against SPIRE's per-method table | `spiffe/CLAUDE.md` |
| `/admin` | a session of its own, got through the OIDC code flow, and one of two roles held through directory groups | `admin-ui/CLAUDE.md` |
| `/federation/acs/{id}` | a signature verifying against the relationship's certificate — **not a turnstile, cannot be made permissive** | `federation/CLAUDE.md` |
| `/authn/spnego` | a Kerberos ticket verified against a real long-term key — **not a refusal at all** | `kerberos/CLAUDE.md` |
| `/xacml/pep/*`, `POST /xacml/pip` | a verified client certificate whose subject DN resolves to an entry holding `REMOTE_PEPS` | `xacml/CLAUDE.md` |
| `GET /xacml`, `POST /xacml/pdp`, `GET /xacml/policies`, `GET /xacml/protected` | the same chain, holding `XACML_USER` | `xacml/CLAUDE.md` |
| `/admin-api` | an OAuth 2.0 access token audienced to it, with `admin:read` / `admin:write`; `adminApi.authRequired` restores the open API | `mgmt-api/CLAUDE.md` |
| `/oauth2/introspect` | client authentication — for an RFC 9701 JWT response in every mode, for RFC 7662 JSON in product mode only | `oauth-oidc/CLAUDE.md` (3ai) |
| the debugger listener (`debugger.port`) | an access token audienced to `urn:sts:debugger-api:` carrying the debugger permission — issued to console administrators only — or the debugger client's session holding one; four landing paths excepted. **Cannot be turned off** | `debugger/CLAUDE.md` |

**The first three are turnstiles, and none of them can be turned off** — the
`*.authRequired` settings that did it were removed on 2026-09-06; what
`global.mode` changes is whether what they ask for is CHECKED
(`common/CLAUDE.md`, `mode.js`). **The Workload API is the opposite case**: it
authenticates nobody because its specification says it MUST NOT, and what it
lacks is ATTESTATION, not authentication (`spiffe/CLAUDE.md`).

Extracted from the [OAuth2/OIDC Debugger](https://idptools.com). **The protocol
suite is still WRITTEN in that project and a copy of it RUNS here** — see
*Tests* below.

## Running it

```bash
npm install
CONFIG_FILE=./env/local.js node server.js      # 8081; STS_PORT overrides
```

**That port is HTTPS** — every appconfig file in `env/` sets `global.https`, and
`STS_HTTPS=false` is the supported way back (`env/CLAUDE.md`). **The selected
file is a layer, not the whole configuration**, and a setting with no value
anywhere stops the service from starting: `common/CLAUDE.md` argues the five
levels, `env/CLAUDE.md` lists the files, and README.md's *Configuration* lists
every setting.

## Architecture, and the rules that hold it together

`server.js` is a shell: it requires the modules and listens. What each directory
holds is the table above; what each module is for is that directory's
`CLAUDE.md`.

1. **Requiring a module registers its endpoints.** Each calls `app.get(...)` at its
   top level against the shared app from `app.js`, rather than exporting a
   `register()`. So **the require order is the route order**, and the
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

   **THE TEST IS THE RULE; the slots that have passed it are an inventory, and
   each one's argument lives beside the module that offers it.** A new slot is
   validated WHOLE when installed (a filler that installs half of it leaves a
   page able to list and unable to act), and is argued both ways round — the
   require one way closes a cycle, the require the other way moves routes.

   | Offered by | Slots | Argued in |
   |---|---|---|
   | `admin-ui/admin.js` | `setLogoutReader`, `setCryptoReporter`, `setSignalsReporter`, `setCaepReporter`, `setRiscReporter`, `setDirectoryPages`, `setDirectoryReader`, `setDirectoryWriter`, `setGroupReader`, `setGroupWriter`, `setScimReader`, `setSpiffeReader`, `setXacmlPages`, `setRolePreviewer`, `setTruststore` | `admin-ui/CLAUDE.md`, and the filler's own file |
   | `admin-ui/crypto_metadata.js` | `setProtocolFamilies`, filled by `sts_metadata.js` | `admin-ui/CLAUDE.md` |
   | `portal/portal.js` | `setDirectory`, filled by `ldap/ldap_server.js` | `portal/CLAUDE.md` |
   | `authn/authn.js` | `setSessionObserver`, filled by `ssf/ssf.js` | `authn/CLAUDE.md`, `ssf/CLAUDE.md` |
   | `common/admin_stats.js` | `setUserObserver` (three kinds of event, still one slot), `setAttributeResolver`, `setGroupResolver` | `common/CLAUDE.md` |
   | `common/helpers.js` | `setSubjectResolver` (a person's `sub` from their entry's `entryUUID`, and back), filled by `ldap/ldap_server.js` (2026-09-14) | `ldap/CLAUDE.md` |

   **`setTruststore()` is the one slot not filled by the module that owns what
   it carries** — `common/protocol_stack.js` fills it, because the owner is first
   loaded from inside `admin.js`'s own require (`tls/CLAUDE.md`).

## Trust realms: several logical copies of this service in one process

A **trust realm** has its own configuration, signing key, sessions, tokens,
statistics and audit log, answers on the SAME sockets, and is told apart by a
segment at the front of the path (`/realm/acme/oauth2/token`). **The default
realm has an empty prefix, and a service with no realms defined behaves exactly
as it did.** The design is argued in `common/CLAUDE.md`; six things reach
outside it:

1. **The realm is AMBIENT**, entered by `app.js`'s first middleware, which also
   strips the prefix. **Nothing may be registered above it.** — `common/CLAUDE.md`
2. **A store becomes per realm at its DECLARATION and nowhere else**;
   `tests/realm_isolation.js` is the guard. — `common/CLAUDE.md`
3. **The embedded directory is per realm too**, `dc=<id>` beneath `ldap.baseDn`. — `ldap/CLAUDE.md`
4. **A realm has administrators of its own, CONFINED to it** (2026-09-14, #32; it
   read *deliberately NOT separated* until then). The console asks the roster of
   the realm a person signed in through; the default realm's is the service
   roster over every realm, and `admin-ui/admin_scope.js` refuses a realm's own
   everything about the process. — `admin-ui/CLAUDE.md` 8d, `mgmt-api/CLAUDE.md`
5. **The two TLS listeners are still shared**, having no path and no name
   inside the protocol to put a realm in. SPIFFE left that list on 2026-09-12 —
   a realm gets a trust domain and sockets of its own, told apart by ADDRESS —
   and **Kerberos left it on 2026-09-15 (#33)**: a KDC per realm on the shared
   port 88, told apart by the Kerberos realm NAME in the request, with the two
   sockets and the development-mode trust still the process's. —
   `tls/CLAUDE.md`, `spiffe/CLAUDE.md`, `kerberos/CLAUDE.md`
6. **A realm may be in RFC 9700 mode — or OAuth 2.1 mode, which implies it —
   while the process is not** — the `realmRuntime` marker, which must not grow
   rows by analogy. — `common/CLAUDE.md`, `oauth-oidc/CLAUDE.md`

## This service's own two surfaces are clients of its own authorization server

`/admin` and `/portal` are **OpenID Connect relying parties** of this service
(since 2026-09-06): seeded confidential clients, a real back-channel HTTP request
to `/oauth2/token`, a relying-party session that names the sign-on session it
came from and dies with it, and a Sign out on each that ends both.
`common/CLAUDE.md` (`oidc_rp.js`) carries the design, the realm split and the
`Location`-header bug; `authn/CLAUDE.md` the two kinds of session;
`admin-ui/CLAUDE.md` and `portal/CLAUDE.md` the gate exemptions and sign-out.

## What an authenticated identity is

**It is `authn/`'s session: an internal, protocol-independent record, and no
protocol's token** (2026-09-14). A subject (`urn:uuid:<entryUUID>`), a list of
authentication events, and a session with a stable `sid` and a rotating cookie
handle. Every artifact this service issues is a PROJECTION of it; every
credential it accepts is EVIDENCE on an event. A protocol module that issues or
accepts anything is bound by it. `authn/CLAUDE.md` argues it; a session needs
a directory entry to be the subject of, so federation's provisioning switches
(`federation/CLAUDE.md`) and SCIM's ids (`scim/CLAUDE.md`) follow from it.

## One front process, and what a socket cannot share

**This service is one node process that owns every listener**, and node runs all
of them on one thread. Two pools take work off it, and they are different kinds
of worker — `common/CLAUDE.md` argues both:

| | `common/worker_pool.js` | `common/request_pool.js` |
|---|---|---|
| A worker runs | a JOB TABLE — four leaf computations | THE SERVICE — the whole protocol stack |
| Forked | lazily, on the first post-quantum job | eagerly, before the listener binds |
| Setting | `workers.count` | `workers.requestCount` (0 — off by default), and `workers.surfaceCount` (0) for a second pool that runs only `/admin` and `/portal` |

**The cross-cutting rule is one sentence: a store is shared by coordination, and
anything that is NOT a row in a store — a socket, a timer, a listener, a
certificate a socket presents — is held by one process and reachable from no
other.** Each such thing needs the argument made again rather than an earlier
mechanism copied: the LDAP connection took a mirror and an instruction on the
response (`ldap/CLAUDE.md`), the TLS listener certificate took a reconcile in
the front process (`tls/CLAUDE.md`), and the client-certificate truststore took
a pin (`tls/CLAUDE.md`). **Dispatch without coordination is refused and the
service does not start**, because it answers WRONGLY rather than slowly.

## The require order IS the route order

Because of rule 1. **The sequence lives in `common/protocol_stack.js`**, which
`server.js` loads before binding sockets and `common/request_worker.js` loads
without binding any — one copy, so the two processes cannot disagree about
which handler wins. Every constraint below is a DEPENDENCY, not a preference;
this table says what the constraint is and the named file says why.

| # | Required | Constraint | Argument in |
|---|---|---|---|
| 1 | `common/config_file` | First of all; every reader of `CONFIG_FILE` is below it. | `common/CLAUDE.md` |
| 2 | `common/app` | Before every protocol module: they register against it, and middleware applies only to routes added after it. Also installs the JWT recorder (rule 3e). | `common/CLAUDE.md` |
| 2a | `common/realms` | No line of its own (loaded by `app` and `helpers`), but above every setting read and every store: requiring it fills `config.js`'s realm slot (rule 3m). | `common/CLAUDE.md` |
| 3–4 | `common/helpers`, `common/config` | `config.js` is below `helpers.js` and requires nothing here. | `common/CLAUDE.md` |
| 4a | `persistence/persistence` | Below `config`, above everything else: fills the override-store slot and subscribes to `realms.onChange()`. A library; it opens nothing here — `persistence.start()` does, before any listener binds. | `persistence/CLAUDE.md` |
| 4b | `common/crypto` | Loaded by `helpers`. A LEAF library that may never require `helpers` back. | `common/CLAUDE.md` |
| 5 | `common/claim_attributes` | Ahead of everything that ISSUES: it fills `setAttributeResolver()`. | `common/CLAUDE.md` |
| 6 | `common/group_claims` | Same reason, for `setGroupResolver()`. | `common/CLAUDE.md` |
| 6a | `home/home` | No constraint; first among the route modules. | `home/CLAUDE.md` |
| 7 | `ws-trust/wstrust` | No constraint. | `ws-trust/CLAUDE.md` |
| 8 | `authn/authn` | Before `oauth2`: it owns the session that module reads. | `authn/CLAUDE.md` |
| 8b | `oauth-oidc/consent_screen` | After `authn`, before `oauth2`. | `oauth-oidc/CLAUDE.md` |
| 9 | `oauth-oidc/oauth2` | Before `wsfed` and `admin-ui/admin`. | `oauth-oidc/CLAUDE.md` |
| 10 | `ws-federation/wsfed` | After `oauth2` (rule 4). | `ws-federation/CLAUDE.md` |
| 10a | `saml/saml2_sso` | After `authn`; it has no sign-in screen of its own. | `saml/CLAUDE.md` |
| 10b | `saml/saml11_sso` | After `authn` and after `saml2_sso` (`slugOf()`). | `saml/CLAUDE.md` |
| 10c | `federation/federation_sp` | After `authn`; it calls `startSession()` directly. | `federation/CLAUDE.md` |
| 11–14 | `oid4vc/*` | `vc_offers` before `vc_issuer` (rule 2). | `oid4vc/CLAUDE.md` |
| 15–16 | `kerberos/krb5_kdc`, `krb5_service` | Listeners start from `listen()`, not here. | `kerberos/CLAUDE.md` |
| 17 | `kerberos/spnego` | After `krb5_service`: it calls that module's `accept()`. | `kerberos/CLAUDE.md` |
| 17a | `kerberos/spnego_authn` | After `spnego` AND after `authn/authn`; it lives in `kerberos/` so the KDC's routes are not dragged ahead of `oauth2`. | `kerberos/CLAUDE.md`, `authn/CLAUDE.md` |
| 18 | `admin-ui/admin` | After `oauth2` (rule 5), and before the families whose modules would otherwise have to be required from it — which is why it offers slots (rule 3e). | `admin-ui/CLAUDE.md` |
| 18-core | `admin-core/*` | No line of its own. Registers nothing, but requires `oauth2`, `saml2`, `saml11` and `federation`, so it may be required at 18 or later and nowhere earlier. | `admin-core/CLAUDE.md` |
| 18a | `admin-ui/pki_admin` | After `admin-ui/admin`, before `mgmt-api/admin_api`, so the API's require of it is a cache hit and it needs no slot. | `admin-ui/CLAUDE.md` |
| 18e | `debugger/debugger_admin` | Beside the other report pages, before `mgmt-api/admin_api` which requires it. Reads the listener's status LAZILY, because `debugger_server` requires `tls/tls_server` (20). | `debugger/CLAUDE.md` |
| 18f | `oauth-oidc/oauth2_monitor_admin` | Beside the other report pages and for 18a's reason: it requires the console's shell and libraries already loaded, and `oauth2.js` (9) cannot require it. | `oauth-oidc/CLAUDE.md` |
| 19 | `mgmt-api/admin_api` | After `admin-ui/admin` (rule 7). | `mgmt-api/CLAUDE.md` |
| 20 | `tls/tls_server` | Before `ldap/ldap_server`, which serves its certificate on 636. | `tls/CLAUDE.md` |
| 20a | `admin-ui/crypto_metadata` | After `tls/tls_server`: it reads algorithm tables out of eleven modules and must find each already loaded. | `admin-ui/CLAUDE.md` |
| 21 | `ldap/ldap_server` | After `admin-ui/admin` and `tls/tls_server` (rule 6). Fills the directory's slots and registers the `/admin/ldap/*` pages. | `ldap/CLAUDE.md` |
| 22 | `scim/scim` | After `ldap/ldap_server`, as a plain require. | `scim/CLAUDE.md` |
| 23 | `spiffe/spiffe_server` | After `ldap/ldap_server` and `tls/tls_server`; its registry's store is the directory. | `spiffe/CLAUDE.md` |
| 23b | `ssf/ssf` | After `admin-ui/admin`, whose slots it fills; also fills `authn.setSessionObserver()`. Starts nothing. | `ssf/CLAUDE.md`, `authn/CLAUDE.md` |
| 23c | `xacml/xacml` | After `admin-ui/admin`, whose slots this family fills; one line for the family. **Requiring `xacml_role_pep.js` here is what arms every issuance site** — before this line `issuance_gate.js` answers "allowed". | `xacml/CLAUDE.md` |
| 23d | `gnap/gnap` | After `admin-ui/admin` and `ssf/ssf`; one line for the family. | `gnap/CLAUDE.md` |
| 23e–g | `acme/acme`, `est/est`, `scep/scep` | **After `admin-ui/admin`** (18), whose shell each family's `_admin.js` draws its two pages with, and after `ldap/ldap_server` (21), whose slot `common/cert_enrollment.js` reads entries through. Each requires its own `_admin.js`, so each family is one line in `common/protocol_stack.js`; `mgmt-api/admin_api.js` spreads each `<family>_api.js`, which registers no route and requires its view model lazily. No constraint between the three. | `acme/CLAUDE.md`, `est/CLAUDE.md`, `scep/CLAUDE.md` |
| 23h | `debugger/debugger_server` | A socket owner: builds its OWN express app and registers nothing on this one. After `authn`, `oauth2`, `tls/tls_server` and the console, all of which it reads. | `debugger/CLAUDE.md` |
| 23a | `logout/logout` | Second to last: it reads nine modules' stores. | `logout/CLAUDE.md` |
| 24 | `sts_metadata` | **Last, for everybody.** It reads the router to list what everything else registered. | *Adding an endpoint*, below |

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
| 3ah | `oauth21.js`, OAuth 2.1 as a mode that implies RFC 9700 mode, and why it is a mode of its own | `oauth-oidc/CLAUDE.md` |
| 3an | RFC 8705 both halves: `tls_client_auth`'s implicit (issued to the application) and explicit (one of five subject parameters) mappings over a verified chain, the declaration held in every mode, section 7.1's refresh rule | `oauth-oidc/CLAUDE.md` |
| 3g | `applications.js` | `common/CLAUDE.md` |
| 3r | `crypto.js`, why it is a leaf, why the verifier is told which element, and why XML encryption moved rather than being replaced | `common/CLAUDE.md` |
| 4a | `saml2_sso.js` after `authn.js`, and why it has no screen | `saml/CLAUDE.md` |
| 4b | `federation_sp.js` after `authn.js`, and why it needs no screen at all | `federation/CLAUDE.md` |
| 4b | `saml11_sso.js` after `authn.js` and after `saml2_sso.js`, and why the two profiles are separate implementations | `saml/CLAUDE.md` |
| 3l | `delegation.js`, and why it has no funnel | `common/CLAUDE.md` |
| 3s | `app_permissions.js`, why a CONFIGURED register is not the observed one with a flag on it, and why the ordering rule lives in `applications.js` | `common/CLAUDE.md` |
| 3t | `consent.js`, why an OVERRIDE is not a RECORD, and why the client_id is the last field of the value | `common/CLAUDE.md` |
| 4c | `consent_screen.js` after `authn.js` and before `oauth2.js`, and why the screen holds the records while the register holds none | `oauth-oidc/CLAUDE.md` |
| 3u | `roles.js`, the two relations it keeps apart (who HOLDS a role against what REQUIRES one), the six computed built-ins, and why it is a plain require rather than a fifth inverted hook | `common/CLAUDE.md` |
| 3v | `issuance_gate.js`, why an empty decider means ISSUE, and why the one case that must fail CLOSED lives in the PEP rather than here | `common/CLAUDE.md` |
| 3w | `pki.js`, why the hierarchy is three tiers or none, why it keeps no store of its own, and what a path check must refuse | `common/CLAUDE.md` |
| 3aa | `pki_authoring.js`, the Certificate & Key Configuration pane as a model: why it is not `pki.js` and not the renderer, why the FORM is the state, why the field table is a table, and why the slow key generation deliberately does not use the worker pool | `common/CLAUDE.md` |
| 3x | `assertion_grant.js`, why RFC 7521 and RFC 7523 are one file, why `client_auth.js` requires it and never the reverse, and why the issuer must be declared | `oauth-oidc/CLAUDE.md` |
| 3ab | `person_assertions.js`, a PERSON as an RFC 7523 issuer, and why their key may assert about them and about nobody else | `common/CLAUDE.md` |
| 3ac | `password_policy.js`, the password policy's default profile as a directory entry, why it is not seeded, why a save carries every field, the generator, and why `credentials.preparePassword()` is where every door — the LDAP modify included — asks it | `common/CLAUDE.md` |
| 3ad | `revocation_status.js`, revocation CONSULTED for a presented certificate: the register for this service's own, the CRL for anybody else's, the policy by mode, and why the main port is annotated rather than refused | `common/CLAUDE.md` |
| 3ak | `request_object.js`, RFC 9101: registered-only `request_uri`, the query replaced by what was signed, the round trip that carries the object, the refusal order, OIDC 10.2's symmetric key | `oauth-oidc/CLAUDE.md` |
| 3am | `authorization_details.js`, RFC 9396: types declared by resource applications, refused in every mode, the audience as an input to RFC 9068's plan, section 6's subset with the refresh token keeping the grant, consent asked every time and spent once | `oauth-oidc/CLAUDE.md` |
| 3an | `step_up.js`, RFC 9470: a session assessed against `acr_values` and `max_age` before it is answered, one sign-in then `unmet_authentication_requirements` in every mode, ordered acr levels and the requested value in the token, the challenge from the stand-in resource and this service's own resource server | `oauth-oidc/CLAUDE.md` |
| 3al | `par.js`, RFC 9126: a push validated by the authorization endpoint's own `vetAuthorizationRequest()`, client authentication as at the token endpoint, the URN resolved through JAR, spent when a response is issued, the two policies asked before vetting | `oauth-oidc/CLAUDE.md` |
| 3aj | `software_statement.js`, RFC 7591 section 2.3: who is trusted, precedence, the closed-endpoint door and the update binding | `oauth-oidc/CLAUDE.md` |
| 3ai | `introspection_jwt.js`, RFC 9701: why a JWT request authenticates in every mode, the Accept reading, what keeps the response from being a token, and refused-never-downgraded | `oauth-oidc/CLAUDE.md` |
| 3ah | `jwt_access_token.js`, RFC 9068 in every mode: the `at+jwt` header, why `issuerOf()` moved there, section 4 at every resource server, and the audience-and-scope plan behind section 3's refusals | `oauth-oidc/CLAUDE.md` |
| 3z | `saml_assertion_grant.js`, why RFC 7522 is a SECOND implementation rather than a format flag on 3x, why its two sections are one function where 3x's are two files, why a bare certificate path is not enough here, and the three items of section 3 whose lenient reading is the usual bug | `oauth-oidc/CLAUDE.md` |
| 3y | `backup_codes.js`, why a set is issued by an ACT and not a request, why ONCE is about the set rather than the account, and why the codes are ENCRYPTED where `userPassword` is hashed | `common/CLAUDE.md` |
| 3z | `inetorgperson.js`, why the account page draws a FIXED LIST rather than the entry, and the two kinds of attribute `rowFor()` refuses | `common/CLAUDE.md` |
| 3ac | `error_codes.js`, the three ways a code is recorded, why a returned refusal carries its code under a Symbol, and the three changes it made to `audit.js` | `common/CLAUDE.md` |
| 3ae | `used_assertions.js`, why an RFC 7523 or RFC 7522 assertion is accepted once EVER — one history for both uses, persisted in every store with one and in both modes, claimed atomically on postgres, and spent only when tokens are issued | `common/CLAUDE.md` |
| 3ag | `cert_enrollment.js`, the core ACME, EST and SCEP issue through: the identity rule, the profiles, the proof of possession, names from the entry, storage on the entry, the two entry-bound credentials | `common/CLAUDE.md` |
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

## Socket owners start their listeners from `listen()`, not at require time

The two Kerberos modules, `ldap/ldap_server.js`, `tls/tls_server.js`,
`spiffe/spiffe_server.js` and `debugger/debugger_server.js` are the exception to rule 1 in one direction only:
requiring them registers their HTTP views like everything else, but **their own
listeners are started from `listen()` in `server.js`** — binding a port can fail,
and a `require` that throws takes the whole service down where a route cannot. A
failure to bind is RECORDED rather than thrown and published on the family's own
view (`GET /admin/ldap/service`, `GET /tls`, SPIFFE per socket), because the HTTP
view answers 200 either way.

**`persistence/persistence.js` binds nothing and still goes first**: the store
is opened by `persistence.start()` before any listener binds, and **a failure
there is FATAL where the others are recorded** — the only place in this
repository where failing to open something stops the process.
`persistence/CLAUDE.md` argues both halves.

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


## Seven pages here have a script on them, and each is the same exception

`app.js` sets `script-src 'none'` for the whole service, and the reason is in its
own comment: it is what makes the family of reflected-content problems moot rather
than merely unlikely. Seven pages need a script and each takes the SAME shape of
exception — `script-src 'self'` naming one resource, never `'unsafe-inline'` —
and **each carries a REAL SUBMIT BUTTON as well**, because with the script
blocked the button is the whole mechanism.

| Page | Script | Argued in |
|---|---|---|
| `/authn/webauthn` | `/authn/webauthn.js` | `authn/CLAUDE.md` |
| WS-Federation's sign-in response | `/wsfed/autopost.js` | `ws-federation/CLAUDE.md` |
| `response_mode=form_post` | `/oauth2/autopost.js` | `oauth-oidc/CLAUDE.md` |
| `/admin/api-explorer` — the one console page with a script | the explorer | `mgmt-api/CLAUDE.md`, `admin-ui/CLAUDE.md` |
| the SAML 2.0 HTTP POST binding | `/saml2/autopost.js` | `saml/CLAUDE.md` |
| the SAML 1.1 Browser/POST profile | `/saml11/autopost.js` | `saml/CLAUDE.md` |
| `/portal/keys` | `/authn/webauthn.js` — the SAME resource, not a copy | `portal/CLAUDE.md` |

**The embedded debugger's pages are NOT on this list, because they are not on
this origin** (2026-09-13): `debugger/debugger_server.js` serves them on a
listener of its own with a policy that allows their inline scripts THERE, which
is the reason it is a separate origin — `debugger/CLAUDE.md` argues it.

**The test for a script is that the page CANNOT work without one**, and the
refusals are what establish it. Each is argued in its own file:

| Refused | Because | Argued in |
|---|---|---|
| federation's outbound HTTP-POST binding | a person LEAVING this service gets a real form and a real button | `federation/CLAUDE.md` |
| the delegation and federation pictures | laid out on the server, arriving as ordinary markup | `admin-ui/CLAUDE.md` |
| the console's collapsible prose | a `<details>` needs no script | `admin-ui/CLAUDE.md` |
| the one-time code screen `/authn/totp` | typing six digits needs none, and the QR code is a server-rendered SVG | `authn/CLAUDE.md` |
| the console's account menu | `<details>`/`<summary>`; the cost (it does not close on an outside click) is stated on the page | `admin-ui/CLAUDE.md` |
| the certificate details dialog | a link and a server-drawn overlay, a round trip per open | `admin-ui/CLAUDE.md` |

**A new scripted page needs the argument made again from scratch, and "the same
as the page next door" is not one.** The federation picture is the delegation
picture in every respect a reader would cite and got its own argument anyway;
`/authn/totp` sits beside a page that DOES relax the policy and still had to
argue its own case.

---

## Adding an endpoint costs one entry in `sts_metadata.js`

`GET /admin/sts-metadata` reads the endpoint list **from the running Express router**, so
it cannot go stale — but it reports two kinds of drift and this repository's own
`tests/vendored/sts_metadata.js` fails on both: a route registered and undescribed, and a
description whose path is not registered (what a rename produces). See README.md.

It is a **console page** since 2026-08-24 (it was `/sts-metadata`), so it is
behind the console gate and is drawn by `admin.js`'s `page()`: this module
builds the body and `admin.respond()` supplies the shell. Adding a PROTOCOL
family costs a card in that file's `PROTOCOLS` as well as the entry above —
the page reports an endpoint group no card claims, so leaving it out fails the
same test rather than going quietly.

**So adding a protocol family costs three things**: an entry in `ENDPOINTS`, a
card in `sts_metadata.js`'s `PROTOCOLS`, and a row in
`admin-ui/crypto_metadata.js`'s `FAMILIES` — the second metadata page,
`/admin/crypto-metadata`, checks its family list against `PROTOCOLS` in both
directions. `tests/vendored/sts_metadata.js` fails on the first two and
`tests/vendored/admin_api.js` on the third. What nothing checks, and what a
settings group also owes, is a row in `admin-ui/admin.js`'s `SETTING_HOMES`;
`admin-ui/CLAUDE.md` carries that and the second page's argument. **A new
page under Protocols also owes a row in `admin-core/protocol_endpoints.js`**
(the endpoints of its realm, drawn on the page) or an exemption with its
reason; `tests/protocol_endpoints.js` fails otherwise.

**AND A CARD IS NOT ALWAYS A PROTOCOL, WHICH IS WHY THE COUNT IN THE OVERVIEW
AND THE COUNT ON THAT PAGE ARE DIFFERENT NUMBERS.** Two cards carry
`notAProtocol` — the User portal, which is an APPLICATION, and **Recovery codes
(2026-09-10), which is a credential mechanism with an endpoint, a verifier and a
store, and simply has no document**: nobody ever wrote a specification for a
recovery code. The marker says which of those two situations a reader is looking
at, and `tests/vendored/sts_metadata.js` asserts that every other card names a
specification — so the marker is what keeps that rule strict for everything it
was written for. A card still costs all three things above whether or not it is
a protocol, because the rule the page enforces is *no endpoint group without a
card*, and paying it here is cheaper than making the rule conditional.

**Those drift checks are enforcement rather than documentation**: `sts_metadata.js`
is this repository's own job and a route registered and undescribed fails the
suite here.

Reading the router has one blind spot: **a protocol that registers no route is
invisible to it**, which is exactly what the KDC's raw TCP/UDP 88 listeners are — and
the directory's two, plain 389 and LDAPS 636. Those
have to be described by hand or they go unlisted with nothing failing.

Coverage notes in that file **must start `full`, `partial` or `mock`** and say what is
missing. A list of fifty specifications that did not mention that this service
checks no passwords and validates no access tokens would be the most misleading thing
in the repository.

## Every failure has an error code, and no client ever sees one

Every way this service can fail or refuse has a code `STS-<SUBSYSTEM>-<NNNN>` in
the ONE table in `common/error_codes.js`; `docs/error-codes.md` is generated from
it. **The code is an operator's name and is RECORDED, NEVER SENT** — it goes on
the audit row and at the front of a log line, never in a response, and it
changes no specification's error.

**A new failure is not finished until it has a code**, and that is enforced:
a row in the table, a `mark()` / `errorCode:` / `tag()` where the failure is
detected, and `node common/error_codes.js --docs`. `tests/error_codes.js` fails
otherwise. A code is never renumbered or reused. `common/CLAUDE.md` argues the
design.

## Code style

**THESE ARE THE PARENT PROJECT'S RULES SINCE 2026-09-12** — its root
`CLAUDE.md`'s *Style Notes* — adopted here and swept across the tree that day.
They bind every `.js` file except `common/vendored/`, the eight Kerberos codec
copies, the `node-ldapjs` submodule and the non-`local` copies in
`tests/vendored/`, none of which may be edited here.

* **Every named function is entered and left out loud.** Its first statement
  is `log.debug("Entering NAME().")` and every exit goes through
  `log.debug("Leaving NAME().")`, where `NAME` is its own name — declarations,
  `const f = function () {…}`, object and class methods. Several `Leaving`
  lines in one body is correct: one before each `return`, and one before a
  trailing `throw`. Anonymous inline callbacks are left alone. **The standing
  exception is a hot path, and it must say so** in a comment above the function
  naming it — a comment such as "no Entering/Leaving pair … would drown the
  log" is what the sweep honoured, and an exception without one is
  indistinguishable from an oversight. Code that runs in a browser or in a
  `node -e` child is exempt, and `common/config_file.js` (no logger exists yet)
  says why in its header; `mgmt-api/admin_api_explorer.js` carries a
  console-backed `log` of bunyan's shape instead, the parent's arrangement for
  files that cannot reach bunyan.
* **No swallowed exception.** Every `catch` does something with what it caught:
  `log.debug("Caught in NAME(): " + ((e && e.message) || e))` at the least, and
  a promise `.catch()` or `.then(ok, fail)` handler the same. A catch that runs
  before the module's logger exists records the error in a variable
  (`logLevelProblem`, `appconfigProblem`) and the line after the logger is made
  reports it; code in a `node -e` child carries it on the result it returns.
  The comment saying WHY it is handled that way is still required as well.
* **No single-line `try`/`catch`**, and no one-line block a log line has to go
  into — `if (x) { return y; }`, `case X: return y;` and a callback's
  `{ return x; }` open out. JavaScript inside a string (a script served to a
  browser, a child process's program) is data and stays as written.
* **80 columns.** Break at a comma, after a binary operator (it stays on the
  first line), after `?` and `:`, before each `.method()` of a long chain, and
  after `=` as a last resort; a long string becomes a concatenation. A
  continuation keeps the column the construct already uses. What stays long:
  a `require()` string, a regex literal, a URL, a template literal, a test
  vector that cannot be cut into fitting pieces, a comment holding a table or an
  aligned layout, and an `error-code: none —` exemption (it must stay within two
  lines of the line it exempts). About 560 lines are over for those reasons.
  **A source-inspection test must read a statement rather than a line** —
  `tests/error_codes.js` and `tests/return_address_provenance.js` both broke on
  this sweep and were fixed that way.
* **One blank line between one function and the next.**
* **The log level is `info` in every appconfig file in `env/`** (2026-09-12),
  because every function now logs its entry and exit at `debug`.
  `STS_LOG_LEVEL=debug` is the run that asks for the whole record.
* **Never read a setting as `Number(config.value(key) || n)` where `0` is a legal
  value.** `0 || n` is `n`, so the setting silently cannot be set to the one
  value its own description often calls out — `totp.window`'s "a perfectly
  synchronised clock" and `backupCodes.groupSize`'s "unbroken" were both
  unreachable until 2026-09-12, and two readers of `pki.crlLifetimeMinutes`
  floored a `min: 1` row at sixty. Let the row's `min`/`max` bound it and read the
  value directly.
* **A behaviour that differs between development and product is a `common/mode.js`
  predicate at the call site, never a literal and never `mode.isProduct()`.** An
  audit on 2026-09-12 found roughly thirty development behaviours written as
  literals with no mode check at all — fixture passwords, a persona surname in
  every ID Token, an ungated trust-anchor endpoint, a return address taken from
  the request — so product mode had shipped every one. The predicates are named
  for the QUESTION (`seedsDemoData()`, `inventsClaimValues()`,
  `acceptsUnregisteredAddresses()`, `opensTestControls()`,
  `sendsWeakerThanAsked()` beside the older four), and `mode.js`'s
  `REQUIREMENTS` is where each is described to `/admin/mode` and the API. A new
  tunable is a `config.js` row whose default is the old literal, read where it
  is used.
* **A refusal or a failure carries an error code** — see *Every failure has an
  error code* above. `errorCodes.mark(res, 'STS-…')` on the line before the
  call that sends an HTTP refusal, `errorCode: 'STS-…'` on an audit row, and
  `errorCodes.tag('STS-…')` at the front of a `log.error` that has neither.
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


## Signing keys, and any document that publishes one

**In development mode — the default — the signing keys are regenerated on every
start; in product mode they are generated once and kept in the persistence store,
sealed under a key-encryption key this service never generates.** A service that
cannot read its own signing key does not start. `common/CLAUDE.md` argues both
(`keystore.js`, `secrets.js`).

**The cross-cutting rule: every document that carries or describes a key is
served `Cache-Control: no-store`.** If you add one, it needs that header too —
`tests/vendored/sts_metadata_anonymous.js` asks it of every metadata document
and fails until the row is there.

## Versioning: M.N.O, fixed when an artifact is BUILT

`VERSION` at the repo root holds M.N; the build number is the UTC build instant,
stamped into `version.json` by the `Dockerfile` so a restarted container reports
the same build. **There is one source**, `common/version.js` (a port of the
parent project's `client/version.js`), and every surface that draws a version
reads it — `tests/version.js` asserts the source each reads, not the string it
renders. **A version may never be the thing that stops this service starting.**
`common/CLAUDE.md` argues it; `xacml-pep/CLAUDE.md` carries the remote PEP's
copy.

## Tests

**The protocol suite is WRITTEN in the parent project and a COPY of it RUNS here.**
Those are two claims and keeping them apart is the whole of this section.

```bash
npm test                # the in-process half: no port, no container
./local-run-tests.sh    # EVERY job — the development loop
./docker-run-tests.sh   # runner and service both in containers; what CI runs
./run-coverage.sh       # the same run with coverage collected
```

Where a new test goes, asked in this order:

1. **Is it about this service's own `/admin` or `/admin-api`?** Then `tests/vendored/`, `local: true` — an ownership argument, not a capability one.
2. **Can it be asserted over HTTP against a running service?** Then `../id-proto-debugger/tests/`.
3. **Otherwise here**: it chooses how the process starts, needs a second container on the service's network, or needs a socket no stack publishes.

**Never edit a vendored copy** — the next `--vendor-sync` overwrites it and the
fix never reaches the parent. The `local: true` jobs are the inversion, edited
here only. `tests/vendored/MANIFEST.js` says which is which.

`tests/CLAUDE.md` carries the job table, the launchers, the coverage run, the
rules that are not optional there, and the three kinds of test that belong here.
**What each surface still has NO test for is recorded in that surface's own
file.**

## Things this service deliberately does not do

Worth knowing before "fixing" one of them. **This is an INDEX** — each row names
the thing in one line and points at the file that argues it. A row that grows a
paragraph here is the drift this file exists to prevent; the paragraph goes in
the file the row names.

| It does not | Where the argument is |
|---|---|
| Enforce anything by default — `oauth2.rfc9700` and `oauth2.oauth21` (which turns it on) are the modes, off unless set | `oauth-oidc/CLAUDE.md` |
| Federate with anybody it was not CONFIGURED to federate with — the one place it refuses by default, and not a mode | `federation/CLAUDE.md` |
| Decrypt an assertion a federation partner encrypted, consume a federated sign-out, or re-check a federated person after the session exists | `federation/CLAUDE.md` |
| Dial a URL a CALLER supplied to fetch something FROM (`jwks_uri`, `wreqptr`) — the URLs it does dial are addresses somebody asked to be SENT something at. **The one exception is the embedded debugger's api (2026-09-13)**, a separate child process that dials what a console administrator names, allow-listed to this service's own addresses in product mode. **The second is the RFC 9728 import on `/admin/applications/new` (2026-09-13)**, an Admin Write act under the federation outbound policy that refuses internal addresses in product mode. **The third is an RFC 9101 `request_uri` (2026-09-13)** — fetched only when the client REGISTERED that exact address, so a request cannot choose it | `federation/CLAUDE.md`, `ssf/CLAUDE.md`, `xacml/CLAUDE.md`, `oauth-oidc/CLAUDE.md`, `debugger/CLAUDE.md`, `admin-ui/CLAUDE.md` |
| ~~Ask anybody's permission before it issues something~~ — **reversed 2026-09-01**: `/oauth2/consent`, with `oauth2.consentRequired` ON by default | `common/CLAUDE.md`, `oauth-oidc/CLAUDE.md` |
| Let a page on another origin read an answer (`Access-Control-Allow-Origin: *` until 2026-09-13) — unless the origin is this service's own or an application lists it in `appCorsOrigin`, per client where the request names one; in both modes, on every path | `common/CLAUDE.md` (`cors.js`) |
| Check an end user's password, **in development mode** — product verifies every presented password; a Kerberos ticket, a TOTP code and a recovery code are verified in BOTH modes | `authn/CLAUDE.md`, `kerberos/CLAUDE.md`, `common/CLAUDE.md` |
| Check any credential except a registered client's secret, in RFC 9700 mode only — and a caller's at `/oauth2/introspect` (RFC 9701 JWT in every mode, JSON in product) | `oauth-oidc/CLAUDE.md` |
| Refuse any LDAP bind, **in development mode** | `ldap/CLAUDE.md` |
| Authorize an LDAP write, **in development mode**; reads are authorized in neither mode | `ldap/CLAUDE.md` |
| Check a Kerberos password, **in development mode** — though it cannot not check the KEY | `kerberos/CLAUDE.md` |
| Verify an access token it did not issue, except at UserInfo | `oauth-oidc/CLAUDE.md` |
| Accept an RFC 7523 assertion from an issuer nobody DECLARED — a refusal ON by default; a PERSON as issuer may assert only about themselves | `oauth-oidc/CLAUDE.md`, `common/CLAUDE.md` |
| Accept an RFC 7522 assertion from an `<Issuer>` nobody DECLARED (a separate declaration), or on a certificate that merely chains to the realm's CA | `oauth-oidc/CLAUDE.md`, `common/CLAUDE.md` |
| ~~Revoke a certificate it issued~~ — **reversed 2026-09-11**: a CRL and OCSP per CA, and consulted for presented certificates since 2026-09-12 | `common/CLAUDE.md`, `admin-ui/CLAUDE.md`, `docs/pki.md` |
| Keep a certificate authority across a restart, **in development mode** | `common/CLAUDE.md` |
| Enforce `value`/`values` in an OIDC Core 5.5 claims request, or treat `essential` as an instruction | `oauth-oidc/CLAUDE.md` |
| Require DPoP — nonce mode makes proofs fresher, not mandatory | `oauth-oidc/CLAUDE.md` |
| ~~Turn a verified client certificate into a login~~ — **reversed 2026-09-05**, with revocation consulted first since 2026-09-12 | `tls/CLAUDE.md` |
| Verify anything in an issued credential's values, which are invented | `oid4vc/CLAUDE.md` |
| Turn a verified presentation into a sign-on | `oid4vc/CLAUDE.md` |
| Deactivate anybody on SCIM `active: false` | `scim/CLAUDE.md` |
| Attest a workload or a node | `spiffe/CLAUDE.md` |
| Revoke a SPIFFE credential — the directory records who may still be ISSUED one, which is a different claim | `spiffe/CLAUDE.md`, `ldap/CLAUDE.md` |
| Let a group grant anything — bar the TWO that grant the admin console and nothing else | `admin-ui/CLAUDE.md`, `common/CLAUDE.md` |
| Let an authenticator app be a FIRST factor | `common/CLAUDE.md` |
| ~~Issue a set of recovery codes on request~~ — **reversed 2026-09-11**: a person generates a set, is shown it once, and it is stored HASHED | `common/CLAUDE.md`, `portal/CLAUDE.md` |
| Offer a self-service reset of a second factor | `admin-ui/CLAUDE.md` |
| Decide who may delegate to whom IN THE ACT, in two of the three families that can | `common/CLAUDE.md`, `kerberos/CLAUDE.md`, `oauth-oidc/CLAUDE.md` |
| ~~Give every trust realm a certificate authority of its own~~ — **reversed 2026-09-11**: one Root, an Intermediate per realm, and the boundary moved down a tier | `common/CLAUDE.md`, `docs/pki.md` |
| Give a trust realm its own TLS listeners (the directory, SPIFFE and — **reversed 2026-09-15 (#33)** — Kerberos came off this row: a KDC, a Kerberos realm and keys per trust realm, routed by the realm name on the shared port 88) | `common/CLAUDE.md`, `ldap/CLAUDE.md`, `spiffe/CLAUDE.md`, `kerberos/CLAUDE.md` |
| ~~Give a trust realm its own administrator~~ — **reversed 2026-09-14 (#32)**: a realm's own roster, confined to the realm; the default realm's stays the service roster | `admin-ui/CLAUDE.md`, `mgmt-api/CLAUDE.md`, `ldap/CLAUDE.md` |
| ~~Persist anything it MINTS~~ — **reversed 2026-09-06, in product mode on postgres only** | `persistence/CLAUDE.md`, `admin-ui/CLAUDE.md` |
| Deliver a response to an address nobody registered, **in product mode** — an address development merely observed is marked and refused until confirmed | `common/applications.js`, `saml/CLAUDE.md`, `common/oidc_rp.js` |
| Start with demonstration data, invent a claim value, or open a test control to anybody, **in product mode** | `common/mode.js`, `common/CLAUDE.md` |
| Dial its database in the clear — and it does not authenticate that server either | `persistence/CLAUDE.md` |
| ~~Coordinate several processes through that store~~ — **reversed 2026-09-06**: the change log is the contract; it shares state and not sockets | `persistence/CLAUDE.md`, `common/CLAUDE.md` |
| Recall anything it has already ISSUED — it DISOWNS them, which is a different claim | `logout/CLAUDE.md`, `common/CLAUDE.md` |
| Perform back-channel logout. Front-channel IS implemented | `oauth-oidc/CLAUDE.md` |
| Fake WS-Federation's `wauth`, or dereference `wreqptr` | `ws-federation/CLAUDE.md` |
| Verify a SAML AuthnRequest's signature, or consume SP metadata — both recorded, neither checked | `saml/CLAUDE.md` |
| Encrypt an assertion to a service provider it holds no certificate for — it sends it in CLEAR and says so loudly | `saml/CLAUDE.md` |
| Dial a service provider's metadata URL WHILE ISSUING | `saml/CLAUDE.md` |

## The parent project's paths into this repository

**The `sts/` COPY set in the parent's `tests/Dockerfile` is the transitive
closure of what `krb5_kdc.js`, `krb5_service.js` and `spnego.js` require, and it
moves on THIS repository's schedule.** Add a require reachable from any of them
and the commit that bumps the `sts/` pin must add the COPY line too, or four
in-process Kerberos jobs die at load with `Cannot find module`, which names a
file nobody edited. What is owed now, and why `mockStsModule()`'s callers pass
bare filenames: `kerberos/CLAUDE.md`. The walk itself:
`docs/parent-project-migration.md`.
