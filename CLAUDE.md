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
| `common/` | Everything more than one family reads: `config.js`, `helpers.js`, `app.js`, `admin_stats.js`, `audit.js`, `applications.js`, `claim_attributes.js`, `group_claims.js`, `config_file.js`. |
| `common/vendored/` | Byte-identical copies of the parent project's files, plus the JSON-LD `contexts/`. **Do not edit them here.** |
| `oauth-oidc/` | The authorization server, RFC 9700 mode, DPoP, mTLS, client authentication, the multi-AS profiles. |
| `authn/` | The authentication service and the WebAuthn relying party. Owns the SESSION. |
| `saml/` | The two assertion builders. No Web SSO profile. |
| `ws-trust/` | WS-Trust 1.0–1.4. |
| `ws-federation/` | WS-Federation 1.2, the passive requestor profile, and the mock relying party. |
| `kerberos/` | The KDC, the acceptor, SPNEGO, and the seven codec modules they rest on. |
| `ldap/` | The embedded directory. Also the STORE for people, groups, applications and the SPIFFE registry. |
| `scim/` | `/scim/v2`, its authentication, and its attribute mapping. |
| `spiffe/` | Six libraries, one server module, and the vendored `protos/`. |
| `tls/` | The 8443 and 9443 listeners, and the certificate three other sockets share. |
| `oid4vc/` | OpenID4VCI, OpenID4VP, DID Core. |
| `admin-ui/` | The console at `/admin`, and the two roles that decide who may use it. |
| `mgmt-api/` | `/admin-api`, its generated OpenAPI document, and the explorer. |
| `docs/` | The GitHub Pages site. See `docs/CLAUDE.md`. |
| `env/` | The appconfig files. `CONFIG_FILE` selects one. |

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

A mock identity service that speaks sixteen protocol families — Kerberos v5 (a KDC on
raw TCP/UDP 88 and over MS-KKDCP, plus a Kerberos-protected service and the same
acceptor over HTTP as **SPNEGO**, RFC 4559/4178), WS-Trust
1.0–1.4, SAML 2.0 and SAML 1.1, WS-Federation 1.2 (the passive requestor profile),
OAuth 2.0 / OIDC (a full authorization server), WebAuthn Level 3 (the relying party's
half, on the login screen), DPoP, OpenID4VCI 1.0, OpenID4VP 1.0, W3C DID Core with
DIF domain linkage, and **LDAP v3** (RFC 4511 — an embedded directory on raw TCP 389 and,
over TLS, on raw TCP 636 as **LDAPS**, one set of handlers and one store behind
both, built on the node-ldapjs SUBMODULE and used unmodified), **SCIM 2.0**
(RFC 7642/7643/7644 — a provisioning endpoint at `/scim/v2` that writes into that
same directory, entry for entry, with no store of its own), and **TLS / mutual TLS**
(two HTTPS listeners of its own, 8443 and 9443, whose whole content is what the
SERVER saw of the connection — see README.md; and, when `global.https` is set,
the main port too, on the same certificate), and **SPIFFE** (an issuing authority
for one trust domain, in all three of its server-side shapes: the bundle endpoint
over plain HTTPS, and the **Workload API** and **SPIRE Server API** over gRPC on
FOUR MORE SOCKETS — a Unix socket and a TCP port each). It exists to exercise
*clients*: it checks no password, validates no access token and **attests no
workload**.

**THREE surfaces are the exception to that sentence and all of them are worth
knowing before reading further.** The SCIM endpoints REQUIRE a credential, in any
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

**`/admin-api` is NOT gated and that is deliberate** — it is what a test drives,
and it is the way back in when nobody holds a role. Which means anybody who can
reach this port can grant themselves both roles through it; see
`mgmt-api/CLAUDE.md`, where that is argued rather than assumed.

**The Workload API is the opposite case and the distinction matters**: it
authenticates nobody because its specification says it MUST NOT — a workload has
no root of trust until that call gives it one. What it lacks there is
ATTESTATION, not authentication.

**There is no SAML 2.0 Web SSO profile** — no SingleSignOnService, no AuthnRequest, no
Response. That is now the gap beside WS-Trust and WS-Federation, and it is deliberate;
see README.md rather than inferring from the absence that it was overlooked. It is also
why the federation metadata publishes no IDPSSODescriptor.

Extracted from the [OAuth2/OIDC Debugger](https://idptools.com). The tests that cover
this service still live in that project (see *Tests* below), which is the single most
important thing to know about this repo's current state.


## Running it

```bash
npm install
CONFIG_FILE=./env/local.js node server.js      # 8081; STS_PORT overrides
```

`CONFIG_FILE` selects a file in `env/`, whose only setting is the bunyan log level.
At the default `debug` every endpoint call and every artifact before and after
signing is logged — that is the point of a mock, so do not quieten it by default.


The invocation above did not change when the modules moved, and that took one new
file to keep true: `common/config_file.js` makes `CONFIG_FILE` absolute before
anything reads it, because a relative path resolves against the directory of the
module doing the requiring and fourteen modules read it directly. See
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

   **`setUserObserver()` NOW CARRIES THREE KINDS OF EVENT AND IS STILL ONE
   SLOT**, which is the same rule read the other way: `ldap_server.js` is
   offered an `event` of `authentication`, `issuance` (an X509-SVID was minted
   for a SPIFFE identity) or `credential-status` (the SPIFFE registry ended or
   restored an identity's ability to obtain one). Two more slots would have been
   two more indirections for one cycle. **An absent `event` means an
   authentication**, so an older copy of either module behaves as it did. See
   `common/CLAUDE.md` and `spiffe/CLAUDE.md`.


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
| 3–4 | `common/helpers`, `common/config` | `config.js` is below `helpers.js` and requires nothing here. | `common/CLAUDE.md` |
| 5 | `common/claim_attributes` | Ahead of everything that ISSUES, because requiring it fills `setAttributeResolver()`. An empty slot means tokens without their configured attributes. | `common/CLAUDE.md` |
| 6 | `common/group_claims` | Same reason, for `setGroupResolver()`. | `common/CLAUDE.md` |
| 7 | `ws-trust/wstrust` | No constraint. | `ws-trust/CLAUDE.md` |
| 8 | `authn/authn` | Before `oauth-oidc/oauth2` — it owns the session that module reads, and fills `audit.js`'s `setActorResolver()`. | `authn/CLAUDE.md` |
| 9 | `oauth-oidc/oauth2` | Before `ws-federation/wsfed` and before `admin-ui/admin`. | `oauth-oidc/CLAUDE.md` |
| 10 | `ws-federation/wsfed` | **After `oauth2`** — rule 4. Single sign-on across the two protocols. | `ws-federation/CLAUDE.md` |
| 11–14 | `oid4vc/*` | `vc_offers` before `vc_issuer`; both read `vc_configs`, which is why that module exists (rule 2). | `oid4vc/CLAUDE.md` |
| 15–16 | `kerberos/krb5_kdc`, `krb5_service` | Their listeners start from `listen()`, not here. | `kerberos/CLAUDE.md` |
| 17 | `kerberos/spnego` | **After `krb5_service`** — it calls that module's `accept()` and adds no check of its own. | `kerberos/CLAUDE.md` |
| 18 | `admin-ui/admin` | **After `oauth2`** — rule 5. And before `ldap`, `scim` and `spiffe`, which is why it offers five slots rather than requiring them. | `admin-ui/CLAUDE.md` |
| 19 | `mgmt-api/admin_api` | **After `admin-ui/admin`** — rule 7. It calls that module's action functions and JSON views. | `mgmt-api/CLAUDE.md` |
| 20 | `tls/tls_server` | **Before `ldap/ldap_server`**, which serves its certificate and key on 636. | `tls/CLAUDE.md` |
| 21 | `ldap/ldap_server` | **After `admin-ui/admin` and after `tls/tls_server`** — rule 6. Fills five slots at require time. | `ldap/CLAUDE.md` |
| 22 | `scim/scim` | **After `ldap/ldap_server`** — a plain require, and rule 3e's test is why. | `scim/CLAUDE.md` |
| 23 | `spiffe/spiffe_server` | **After `ldap/ldap_server` and `tls/tls_server`.** Its registry's store is the directory. | `spiffe/CLAUDE.md` |
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
(`/KdcProxy`, `/krb5/principals`, `/ldap`, `/tls`) like everything else, but their
**own listeners are started from `listen()` in `server.js`, not at require time** —
binding a port can fail, and a `require` that throws takes the whole service down
where a route cannot. A failure to bind is RECORDED rather than thrown, and both
`ldap_server.js` and `tls_server.js` publish it (`listening` / `listenError` on
`GET /ldap` and `GET /tls`), because the HTTP view answers 200 either way and there
is otherwise no way to tell a running listener from one whose port was already taken
— by the host's own slapd, or by a second copy of this service.

The fourth is `spiffe/spiffe_server.js`, with four sockets of its own.
Each is reported SEPARATELY, because "389 is up and 636 is not" is the
ordinary outcome of a host run and one flag could only report one of them.

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

**Do not replace Express's 404 body.** `Cannot GET /path` is how the parent project's
`tests/sts_metadata.js` tells an unrouted path from an endpoint legitimately answering
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

---

## Adding an endpoint costs one entry in `sts_metadata.js`

`GET /sts-metadata` reads the endpoint list **from the running Express router**, so
it cannot go stale — but it reports two kinds of drift and the parent project's
`tests/sts_metadata.js` fails on both: a route registered and undescribed, and a
description whose path is not registered (what a rename produces). See README.md.

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

**There are none in this repository yet, and that is the main gap.** Four tests in the
parent project need only this service and should be ported:

| Test | What it covers |
|---|---|
| `tests/sts_metadata.js` | the `/sts-metadata` drift checks — that the page lists exactly what the router registers, that every method reaches a handler, that every link resolves, and that no specification claim is idle |
| `tests/admin_api.js` | the management API at `/admin-api`: its OpenAPI document, the PARITY it exists to keep — every `/admin` page and every action of its four handlers has an operation, read off this service's own answers rather than off a list in the test — every documented schema property checked against a live reply, and that a revocation made through the API is dead at `/oauth2/introspect`. It restores everything it changes, including the tokens its bulk revocations touched |
| `tests/sts_dpop.js` | RFC 9449 end to end over HTTP: all twelve section 4.3 checks, the `cnf.jkt` binding on access and refresh tokens, `dpop_jkt`, `jti` replay, and the nonce handshake in both shapes. Almost entirely negatives, because a DPoP server that issues bound tokens and accepts good proofs looks finished and can be worth nothing |
| `tests/oauth2_sts_endpoints.js` | every endpoint the RFC 8414 metadata advertises answers, and every token verifies against the advertised JWKS |
| `tests/vc_did.js` | the DID-named issuer chain: advertisement → resolution → domain linkage → the key that actually verifies the credential |

They are plain node scripts using `assert` and `bunyan`, driven over HTTP with no
browser, and they take `WSTRUST_STS_URL` / `OID4VCI_ISSUER_URL` to locate the service.
`sts_dpop.js` writes its **own** DPoP client rather than importing the wallet's, on
purpose: if both sides of the exchange came from one implementation, a shared
misunderstanding would make the test pass and interoperate with nobody. Keep that
property when porting.

Until they are here, the drift checks README.md describes are documentation rather
than enforcement.

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
| Check any end user's password, in any protocol | `authn/CLAUDE.md` |
| Check any credential except a registered client's secret, in RFC 9700 mode only | `oauth-oidc/CLAUDE.md` |
| Refuse any LDAP bind — any DN, any password, anonymous, on 389 and 636 alike | `ldap/CLAUDE.md` |
| Check a Kerberos password, though it cannot not check the KEY | `kerberos/CLAUDE.md` |
| Verify an access token it did not issue, except at UserInfo | `oauth-oidc/CLAUDE.md` |
| Require DPoP — nonce mode makes proofs fresher, not mandatory | `oauth-oidc/CLAUDE.md` |
| Turn a verified client certificate into a login | `tls/CLAUDE.md` |
| Verify anything in an issued credential's values, which are invented | `oid4vc/CLAUDE.md` |
| Turn a verified presentation into a sign-on | `oid4vc/CLAUDE.md` |
| Deactivate anybody on SCIM `active: false` | `scim/CLAUDE.md` |
| Attest a workload or a node | `spiffe/CLAUDE.md` |
| Revoke a SPIFFE credential — the directory now records who may still be ISSUED one, which is a different claim | `spiffe/CLAUDE.md`, `ldap/CLAUDE.md` |
| Let a group grant anything — bar the TWO that grant the admin console and nothing else | `admin-ui/CLAUDE.md`, `common/CLAUDE.md` |
| Persist anything at all | `admin-ui/CLAUDE.md` |
| Fake WS-Federation's `wauth`, or dereference `wreqptr` | `ws-federation/CLAUDE.md` |
| Publish a SAML 2.0 Web SSO profile | `saml/CLAUDE.md` |

THREE exceptions to the whole of that list, and each is worth knowing before
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

## The parent project's paths into this repository are now wrong

`../oauth2-oidc-debugger` reaches into this one by FLAT PATH in three places, and
the 2026-08-23 reorganisation broke all three: `tests/Dockerfile` has ~20
`COPY sts/<file>.js` lines, `tests/module_paths.js`'s `mockStsModule()` resolves
`sts/<name>.js`, and `tests/krb5_codec_sync.js` and `tests/bbs2023_cryptosuite.js`
byte-compare vendored copies at fixed paths.

**Nothing over there was changed**, deliberately: its `sts/` gitlink is pinned at
`cae2066`, which is before `applications.js` existed, so its suite is not running
against current code anyway and the fix has to land in the same commit as the
gitlink bump. What that commit needs is written down in
`docs/parent-project-migration.md`. Do not bump the pin without it — four Kerberos
jobs die at load with `Cannot find module`, which names a module rather than a
reorganisation.
