# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in
this repository.

## Overview

A mock identity service that speaks fourteen protocol families — Kerberos v5 (a KDC on
raw TCP/UDP 88 and over MS-KKDCP, plus a Kerberos-protected service and the same
acceptor over HTTP as **SPNEGO**, RFC 4559/4178), WS-Trust
1.0–1.4, SAML 2.0 and SAML 1.1, WS-Federation 1.2 (the passive requestor profile),
OAuth 2.0 / OIDC (a full authorization server), WebAuthn Level 3 (the relying party's
half, on the login screen), DPoP, OpenID4VCI 1.0, OpenID4VP 1.0, W3C DID Core with
DIF domain linkage, and **LDAP v3** (RFC 4511 — an embedded directory on raw TCP 389,
built on the node-ldapjs SUBMODULE and used unmodified), and **TLS / mutual TLS**
(two HTTPS listeners of its own, 8443 and 9443, whose whole content is what the
SERVER saw of the connection — see README.md). It exists to exercise *clients*: it
authenticates nobody, checks no password and validates no access token.

**There is no SAML 2.0 Web SSO profile** — no SingleSignOnService, no AuthnRequest, no
Response. That is now the gap beside WS-Trust and WS-Federation, and it is deliberate;
see README.md rather than inferring from the absence that it was overlooked. It is also
why the federation metadata publishes no IDPSSODescriptor.

`README.md` is the substantive document — it explains why each piece is the way it
is, and most of those explanations are the record of something having gone wrong
once. Read it before changing anything. What follows is only what is not in there.

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

## Architecture, and the four rules that hold it together

`server.js` is a shell: it requires the modules and listens. The modules are
`helpers.js` (log, keys, cross-protocol helpers), `app.js` (the express app and every
middleware), `saml2.js`, `saml11.js`, `wstrust.js`, `oauth2.js`, `wsfed.js`,
`webauthn.js`, `vc_configs.js`, `vc_offers.js`, `vc_did.js`, `vc_issuer.js`,
`vc_verifier.js`, `ldap_server.js`, `tls_server.js`, `krb5_kdc.js`,
`krb5_service.js`, `spnego.js` and the `krb5_*` files they rest on (ASN.1, crypto,
messages, principals, NDR, PAC, GSS, SPNEGO), `admin.js`, `sts_metadata.js`, and the
two libraries that register nothing, `dpop.js` and `admin_stats.js`.

**`spnego.js` must stay after `krb5_service.js` in the require order**, and that is a
dependency rather than a preference: it calls that module's `accept()` for every
Kerberos check and adds none of its own. It is also the one Kerberos module that
starts NOTHING — it is HTTP all the way down, so requiring it is the whole of its
installation. Note the naming: `krb5_spnego.js` beside it is the VENDORED RFC 4178
codec (a byte-identical copy of the parent project's `common/krb5/krb5_spnego.js`,
kept honest by `tests/krb5_codec_sync.js` there), and `spnego.js` is this repo's own.
Do not merge the two — one of them is somebody else's file.

The two Kerberos modules, `ldap_server.js` AND `tls_server.js` are the exception to
rule 1 below in one direction only: requiring them registers their HTTP views
(`/KdcProxy`, `/krb5/principals`, `/ldap`, `/tls`) like everything else, but their
**own listeners are started from `listen()` in `server.js`, not at require time** —
binding a port can fail, and a `require` that throws takes the whole service down
where a route cannot. A failure to bind is RECORDED rather than thrown, and both
`ldap_server.js` and `tls_server.js` publish it (`listening` / `listenError` on
`GET /ldap` and `GET /tls`), because the HTTP view answers 200 either way and there
is otherwise no way to tell a running listener from one whose port was already taken
— by the host's own slapd, or by a second copy of this service.

`tls_server.js` is the newest of the four and the one whose sockets are easiest to
forget are sockets: they speak **HTTP**, so they look as though they belong on the
plain listener — but they are HTTPS on 8443 and 9443, and `GET /sts-metadata` walks
the plain listener's router, which cannot see them. Its four rows there are the
plain-HTTP views only, and the listeners are described in their text. Its truststore
for CLIENT certificates is empty at startup and is filled at runtime through
`POST /tls/trust`, because the CA it verifies is generated in somebody's browser
minutes before the connection; that endpoint is on the plain port on purpose, since
that is the one reachable before anything is trusted.

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

4. **`wsfed.js` must stay after `oauth2.js` in the require order**, and that is a
   dependency rather than a preference: it signs users in to the browser session
   `oauth2.js` owns, through the `startSession` / `sessionOf` / `endSession` it
   exports, so that single sign-on works across the two protocols. The dependency is
   one-way — `oauth2.js` knows nothing about WS-Federation — which is what keeps it
   out of the cycles rule 2 exists to avoid. Do not give WS-Federation a session store
   of its own to "decouple" them: two stores would each look correct alone and never
   see each other, and the symptom is a sign-on that silently is not single.

5. **`admin.js` must stay after `oauth2.js` too, for the same reason**: it reads that
   `sessions` map so the metrics page can report real sign-on sessions. And the same
   one-store rule applies to REVOCATION — the set of revoked jtis lives in
   `admin_stats.js` and serves both the console and RFC 7009's `/oauth2/revoke`. Two
   sets would each look correct alone and never see each other, and a token revoked
   from the console would keep introspecting as active with no error to point at.

6. **`ldap_server.js` must stay after `admin.js`, and it INVERTS a dependency the
   same way `helpers.js` does.** Its embedded directory grows an entry under
   `ou=users` for anybody who authenticates through any of the thirteen families
   here, and `admin_stats.recordAuthentication()` is already the single funnel all
   of them pass at the moment a credential is ACCEPTED — so one observer there is
   one place and not thirteen. But this module requires `admin_stats.js` (it needs
   `identityOf`'s normalisation, so `alice`, `urn:sts-mock:user:alice` and
   `alice@REALM` seed ONE entry), which means `admin_stats.js` cannot require it
   back: that is the cycle rule 2 exists for. So `admin_stats.js` offers
   `setUserObserver()` and this module fills it at require time. The observer's
   return value is ignored and a throw from it is caught — a directory must never
   be able to fail an authentication. Do not "simplify" that into a require in the
   other direction, and do not seed the entry at each authentication site instead:
   thirteen call sites means a fourteenth that is not.

   **A SECOND hook runs the other way, and it is the console that offers it.**
   `/admin/users?user=<name>` shows that user's directory object — every attribute,
   operational ones included — and `admin.js` must NOT require this module to get
   it: `server.js` requires `admin.js` FIRST, so a require from there would pull
   `/ldap` and `/ldap/directory` into the router ahead of the console's routes, and
   `GET /sts-metadata` is built by walking that router. So `admin.js` exports
   `setDirectoryReader()` and this module fills it with `objectFor()` at require
   time. `objectFor()` is given the identity key the console files a person under,
   which is the same normalised local name `autoCreateUser()` built the DN from —
   pass anything else and the two silently stop naming the same entry.

`userFor`, `parseBody`, `oauthError`, `vciError`, `signJwt` and
`firstByLocal`/`textByLocal` are in `helpers.js` because more than one protocol needs
them, not because they are especially general. The last two are read by three parsers
— the WS-Trust RST, WS-Federation's `wreq`, and the `wresult` the mock relying party
is POSTed — and they match on **local name with the namespace ignored** because the
trust namespace alone has four versions in use. That is what lets one parser answer
WS-Trust 1.0 through 1.4 instead of four.

## Adding an endpoint costs one entry in `sts_metadata.js`

`GET /sts-metadata` reads the endpoint list **from the running Express router**, so
it cannot go stale — but it reports two kinds of drift and the parent project's
`tests/sts_metadata.js` fails on both: a route registered and undescribed, and a
description whose path is not registered (what a rename produces). See README.md.

Reading the router has one blind spot: **a protocol that registers no route is
invisible to it**, which is exactly what the KDC's raw TCP/UDP 88 listeners are. Those
have to be described by hand or they go unlisted with nothing failing.

Coverage notes in that file **must start `full`, `partial` or `mock`** and say what is
missing. A list of thirty-eight specifications that did not mention that this service
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
* **The library is NOT patched.** Everything in `ldap_server.js` is handlers
  registered against its public API, so the submodule stays a usable copy of
  ldapjs rather than a fork nobody else can consume — and the api on the other
  side of the exchange runs the same code. Two of its defects are routed around
  rather than fixed, both in `SearchResponse.send()`: a second, case-sensitive
  attribute filter that silently drops every attribute whose conventional spelling
  has a capital in it from a SELECTIVE search (and which `nofiltering` does not
  disable, contrary to its documentation), and a `messageId` that defaults to 1 so
  the early branch which avoids that filter throws on every search after the first
  on a connection. `toSearchEntry()` builds a `SearchResultEntry` instance with the
  response's `messageId`, which sidesteps both. The comments there explain it;
  read them before "simplifying" that function back to a plain object.

## The JSON-LD contexts are load-bearing

`bbs2023.js` reads the three files in `contexts/` **at require time, at module
scope**. A missing one is not a degraded feature — the service does not start. They
are vendored rather than fetched because Data Integrity signs canonicalized
statements, so a one-byte difference in a context fails every signature later and
looks like a crypto bug.

`bbs2023.js` resolves two layouts: `../client/src/contexts` (its position in the
parent project) and `./contexts` (this repo). Do not simplify that away — it is what
let the file be copied here unchanged.

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

**WS-Federation has no test in either repository.** The mock relying party at
`/wsfed/rp` makes it look covered — it verifies a sign-in response check by check —
but a person has to click it and read the page. What a test would add is the
negatives, which is where this profile's value is: an altered `wctx`, `wauth`
demanding a factor the session never had, `wfresh` read as seconds rather than
minutes, a SAML 1.1 signature whose reference does not resolve because `AssertionID`
was not named. A passive requestor that issues a good token to a working relying party
looks finished and proves almost nothing.

## Things this service deliberately does not do

Worth knowing before "fixing" one of them:

* **It checks no password.** The username typed at `/oauth2/login` — or at
  `/wsfed/login`, which creates the same session — becomes the identity in every
  token and every assertion.
* **The LDAP directory takes that further: EVERY BIND SUCCEEDS**, any DN and any
  password, anonymous included — with the single exception of the literal password
  `invalid`, which is refused with `LDAP_INVALID_CREDENTIALS` (49). That exception
  is not a softening; it is what keeps result code 49 reachable, and 49 is the code
  an LDAP client's error handling is built around. The directory is also
  SCHEMALESS on purpose, and `GET /ldap` says so rather than leaving a reader to
  infer a schema that is not there. Four structural rules are still enforced (an
  add needs its parent, a delete needs a leaf, a modify `delete` of an absent
  attribute is 16, and an attribute's last value takes the attribute with it), and
  one is deliberately NOT: deleting a user leaves its DN in every group that lists
  it, because referential integrity is a directory feature and not a protocol rule.
* **Kerberos is the exception, and cannot not be.** The password there *is* the key:
  pre-authentication and the AS-REP's enc-part are both encrypted under it, so a KDC
  accepting anything would still have to pick a key the client could not guess. So it
  does the permissive equivalent — **any username authenticates and every user account
  shares one password** (`password!`, `KRB5_USER_PASSWORD`), with a name nobody
  configured created on first sight by `findOrCreateUser()`. Three things stay
  refusals on purpose: a **service**-shaped (multi-component) name is created only
  for a host this service is willing to BE — `KRB5_SERVICE_DOMAINS`, the realm's own
  domain plus `localhost`, `sts` and `127.0.0.1` — and anything else stays
  `KDC_ERR_S_PRINCIPAL_UNKNOWN`; the names in `KRB5_UNKNOWN_USERS` stay unknown so
  `KDC_ERR_C_PRINCIPAL_UNKNOWN` is still reachable; and a wrong password is still
  `KDC_ERR_PREAUTH_FAILED`. That service exception is new (2026-08-17) and it is not
  a softening of the argument against inventing services: this process is both the
  KDC and the acceptor, `krb5_service.js` looks the presented SPN up in the same
  table, so a name created on demand is one the service can decrypt — which was the
  whole objection. It exists because a client derives `HTTP/<url host>` and every
  way of reaching this stack produced an SPN nobody had configured. Service,
  computer and `krbtgt` accounts keep their own distinct passwords — the two krbtgts
  and the trust must be three different secrets or assertions about which key sealed
  what pass for the wrong reason.
* **It does not verify access tokens it did not issue — except at UserInfo.**
  OID4VCI lets the authorization server be somebody else, so at the three
  credential endpoints a foreign token is accepted as-is. The consequence for DPoP
  is stated in `presentedAccessToken()` (in `dpop.js`, shared by all four
  protected endpoints): for such a token, `cnf.jkt` is a claim anyone could have
  written, and the binding is real only for tokens this service issued.
  `/oauth2/userinfo` is the exception and is meant to be — it answers "who did YOU
  authenticate", so it checks the signature, the `typ`, revocation and the
  `openid` scope, and refuses anything else rather than inventing a profile.
* **There is no "DPoP required" mode.** Nonce mode makes proofs fresher, not
  mandatory; a request with no `DPoP` header is a Bearer request and is answered as
  one, so turning nonce mode on cannot break the Bearer clients this service also
  exists to exercise.
* **One password is rejected** — the literal string `invalid` on the password grant,
  on WS-Trust and at the WS-Federation sign-in screen — so a negative test has
  something to fail on in every protocol here.
* **A verified client certificate on the TLS listeners is not a login**, and no
  revocation is checked there. Verification means one thing exactly: OpenSSL built a
  chain from what the client sent to an anchor somebody POSTed to `/tls/trust`. No
  session starts, no token is issued, no other endpoint is told, and a revoked
  certificate verifies here and would not verify anywhere that matters. Both facts
  are stated in the report itself rather than left to be discovered — a mock that
  quietly turned a certificate into an identity would teach a client something false
  about every server it will ever meet.
* **The admin console at `/admin` is not protected and holds nothing on disk.** It is
  the one surface that can change what the protocol endpoints do — it revokes tokens
  through the same set `/oauth2/revoke` writes to, and it adds custom claims to every
  future access token, ID Token and SAML assertion. Custom claims are **additive**:
  the names this service sets itself are refused at configuration time, because an
  `exp` settable from a web form would produce tokens that fail to verify with nothing
  pointing back at the page. It deliberately does not invalidate assertions, tickets
  or credentials (nothing consults this service about those, so the button would be a
  lie), does not end sign-on sessions (`wsignout1.0` has cleanup to fan out), and does
  not touch refresh tokens' claims. Its `/admin/users` page lists every userid
  presented to this service in an interaction that SUCCEEDED, across all twelve
  families, and drills into one's sessions and the tokens issued on each. Two rules
  hold it up and both are easy to break by accident: **one row is one local name**
  (`alice`, `urn:sts-mock:user:alice` and `alice@REALM` are one identity — the prefix
  is derived from `userFor()` rather than written down, so changing that function
  cannot silently split every user in two), and **a token is placed under a session by
  the optional third argument to `signJwt()`**, never by a claim — no token here
  carries a session identifier and adding one would change what every client receives.
  A new authentication point needs one `stats.recordAuthentication()` call at the
  moment the credential is ACCEPTED, not when the request arrives. See README.md.
* **WS-Federation's `wauth` is refused rather than faked.** A relying party demanding
  multi-factor against a password-only session gets an error and two ways forward, not
  an assertion claiming a second factor that did not happen. It is the one thing in
  this profile that could trivially have been faked, and faking it would have taught a
  relying party something false about how a person signed in. Likewise `wreqptr` is
  never dereferenced: fetching a URL handed over in a query parameter is a
  server-side request forgery with a specification citation attached.
