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
DIF domain linkage, and **LDAP v3** (RFC 4511 — an embedded directory on raw TCP 389 and,
over TLS, on raw TCP 636 as **LDAPS**, one set of handlers and one store behind
both, built on the node-ldapjs SUBMODULE and used unmodified), and **TLS / mutual TLS**
(two HTTPS listeners of its own, 8443 and 9443, whose whole content is what the
SERVER saw of the connection — see README.md; and, when `global.https` is set,
the main port too, on the same certificate). It exists to exercise *clients*: it
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
`config.js` (every setting this service has, and the only module `helpers.js`
depends on), `helpers.js` (log, keys, cross-protocol helpers), `app.js` (the
express app and every middleware), `authn.js` (the authentication service), `saml2.js`, `saml11.js`,
`wstrust.js`, `oauth2.js`, `wsfed.js`,
`webauthn.js`, `vc_configs.js`, `vc_offers.js`, `vc_did.js`, `vc_issuer.js`,
`vc_verifier.js`, `ldap_server.js`, `tls_server.js`, `krb5_kdc.js`,
`krb5_service.js`, `spnego.js` and the `krb5_*` files they rest on (ASN.1, crypto,
messages, principals, NDR, PAC, GSS, SPNEGO), `admin.js`, `admin_api.js`,
`sts_metadata.js`, and the libraries that register nothing: `dpop.js`,
`mtls.js`, `client_auth.js`, `oauth2_bcp.js`, `applications.js`,
`authorization_servers.js`,
`admin_stats.js`, `audit.js`, `vc_claims.js`, `vc_verifier_config.js`,
`claim_attributes.js`, and
`admin_api_spec.js` and `admin_api_docs.js` beside the management API. One file in the tree is not a
node module at all — `admin_api_explorer.js` is BROWSER code, read off disk by
`admin_api_docs.js` and served verbatim; its own header says so at length.

**`authn.js` is the authentication service, and it is not part of any protocol.**
The sign-in screen used to be rendered inside `GET /oauth2/authorize`: no session
meant a 200 with the login form in the body, at the authorization endpoint's own
URL. It is now its own endpoint and its own module, and the protocol endpoints
send people to it:

```
GET /oauth2/authorize (no session)
    -> 302 /authn/login?authn=<id>          the request is stashed with a
                                            return URL built from its own query
    -> the screen; POST /authn/login        the session cookie is established
    -> 302 back to /oauth2/authorize?<the original query, minus prompt>
    -> the session is there this time, so the response goes out per spec
```

Four things about that are load-bearing:

* **The service knows nothing about OAuth.** It never reads `client_id` or
  `redirect_uri`. What the screen shows about the request it interrupted arrives
  as `details` rows the CALLER wrote, because only the caller knows what its own
  parameters mean — the `issuer_state` note, for one, which says whether the
  request came from a Credential Offer this issuer actually made.
* **A refusal comes back rather than being answered there.** Cancel returns to
  the caller with `authn_error=access_denied`, and the caller turns that into
  its own protocol's refusal. `redirectBack()` in `oauth2.js` knows about
  `response_mode`, and in `form_post` the answer is not a redirect at all but a
  self-submitting form — protocol knowledge stays in the protocol module. The
  authorization endpoint checks for that parameter BEFORE it checks the session,
  or a refusal would be answered by sending the person straight back to the
  screen they just declined.
* **`returnTo` is checked to be a path on this service.** It is built by the
  caller and never read off the query string, and it is checked anyway: an
  authentication service that will redirect a browser to an arbitrary URL after
  signing somebody in is a credential phishing tool with a login screen in front
  of it.
* **It owns the SESSION**, and `wsfed.js` and `admin.js` take it from here.
  `oauth2.js`'s old note said the session lived there "because this module owns
  the login flow the session comes out of" — which is exactly the sentence that
  moved it, now that the login flow has. `oauth2.js` reads the session and never
  writes one. The WebAuthn second factor moved with it for the same reason: it
  is the other half of one act of authentication, and it shares the pending
  record.
* **WEBAUTHN IS TWO ROLES ON ONE SCREEN and the ceremony cannot tell them
  apart.** `use_webauthn` is the second factor after a password (session
  `amr ["pwd","hwk"]`, `acr "mfa"`); `webauthn_only` is the PRIMARY credential
  with no password read at all (`amr ["hwk"]`, `acr "1"` — ONE factor, since
  the ceremony asks for user verification as `preferred` rather than
  `required`). Four things there are load-bearing. The choice is made at the
  password screen and CARRIED on the pending record, because the ceremony's own
  POST is the browser's result and nothing in it says what somebody chose a
  screen ago. `webauthn_only` WINS where a hand-made POST sets both, since the
  boxes cannot be made exclusive on a screen that runs no script. A caller that
  demanded a second factor (`forceMfa`, from `acr_values`) is refused the
  passwordless path SERVER-SIDE — `disabled` is a property of a browser and not
  of a request. And `methodPhraseFor()` exists because there are three outcomes
  now: the two-way conditional it replaced asked whether `hwk` was present and
  called a passwordless sign-in a password one. Anything downstream that reads
  `hwk` to mean "two factors" is wrong for the same reason — `wsfed.js`'s
  `authnMethodsFor()` was, and now tests for `hwk` AND `pwd`.

WS-Federation still has a sign-in screen of its own, deliberately: section
13.2.1 lets the sign-in request arrive as a cross-site form POST, which
`SameSite=Lax` keeps a session cookie off, and routing that through a redirect
chain would lose the request. It lands in the SAME session, which is what makes
single sign-on between the two protocols work. Pointing it at this service is the
obvious next move and is not done yet.

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

`ldap_server.js` starts **two** of those listeners — plain 389 and LDAPS 636 — and
they are published SEPARATELY (`listening`/`listenError`, and a `tls` object with its
own `listening`/`error`) because they bind independently and "389 is up and 636 is
not" is the ordinary outcome of a host run, which is not root. One flag could only
report one of them, and the direction it would get wrong is the expensive one: a page
saying no client can connect while LDAPS is answering. Note what LDAPS is NOT: it is
not an option on the plain server. ldapjs decides between a `net.Server` and a
`tls.Server` at CONSTRUCTION, so there is a second server object, handlers are
registered per instance, and the `server` most of that file registers against is a
FAN-OUT over the eight operations plus unbind rather than a server — see the comment
above it before adding an operation. `listen`, `close` and `address` are deliberately
not fanned out. There is no StartTLS to add instead: it is an extended operation,
ldapjs implements none, and this repository does not patch that submodule.

`tls_server.js` is the newest of the four and the one whose sockets are easiest to
forget are sockets — and there are now TWO MORE TLS sockets in this process that are
not its own, both on `serverCertificate()`'s certificate and key rather than a second
pair: the directory's LDAPS listener on 636, and — when `global.https` is set, which
`oauth2.rfc9700` does by default — THE MAIN PORT ITSELF, bound as HTTPS from
`listen()` in `server.js`. So one anchor covers 8443, 9443, 636 and 8081, and a
caller trusts this service once per start rather than four times. The LDAPS half is
what makes `ldap_server.js` require this module, and therefore what fixes their order
in `server.js` (rule 6); the main-port half needs no require order at all, because
`server.js` already has this module in hand by the time it listens. The private key
crosses a module boundary and no network one: it is generated per start, held in
memory, and `GET /tls/server-certificate` publishes the certificate alone.

**One thing that arrangement costs, and it is stated on the page rather than left to
be met as a handshake failure**: with the main port TLS there is no plain listener in
this process, so `POST /tls/trust` and `GET /tls/server-certificate` — which exist to
be reachable BEFORE anything is trusted — have to be called the first time with
verification off.

Its own sockets: they speak **HTTP**, so they look as though they belong on the
plain listener — but they are HTTPS on 8443 and 9443, and `GET /sts-metadata` walks
the plain listener's router, which cannot see them. Its four rows there are the
plain-HTTP views only, and the listeners are described in their text. Its truststore
for CLIENT certificates is empty at startup and is filled at runtime through
`POST /tls/trust`, because the CA it verifies is generated in somebody's browser
minutes before the connection; that endpoint is on the MAIN port on purpose, since
that is normally the one reachable before anything is trusted. `global.https` —
which `oauth2.rfc9700` turns on — takes that property away by making the main port
TLS as well, so the first fetch of the certificate and the first POST of an anchor
then have to be made with verification off. Every sentence in that module which
names the port goes through `mainPortPhrase()` for exactly that reason; seven of
them used to say "the plain HTTP port" outright, which would be quietly wrong in
the one place a reader goes when a handshake is failing.

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
3a. **`vc_claims.js` is a library like `dpop.js` too, and it is read from three
   different points of the require order.** It holds which claims an issued
   Verifiable Credential carries — a catalogue of LDAP ATTRIBUTE TYPES, not of claim
   names, because a claim's value is the value on that person's directory entry —
   plus the invented, DETERMINISTIC persona that fills what an entry lacks.
   `vc_issuer.js` (early), `admin.js` (late) and `ldap_server.js` (last) all read it,
   so it must stay a library: it registers no route and requires only `helpers.js`
   and `admin_stats.js` (for `identityKeyOf()`, so that `alice`,
   `urn:sts-mock:user:alice` and `alice@REALM` are one invented person and one
   entry). The DIRECTORY half is inverted the usual way — `setDirectory()` is filled
   by `ldap_server.js` at ITS require time, because that module cannot be required
   from a module `vc_issuer.js` reads without dragging every `/ldap` route to the
   front of the router. Two things there are load-bearing and easy to undo: the
   ISSUER METADATA is built from the same selection the credential is (an issuer
   advertising five claims and minting fourteen teaches every wallet author that the
   metadata is not worth reading), and `ldp_vc` carries only the terms the vendored
   JSON-LD context defines — `bbs2023.js` canonicalizes with `safe: true`, so an
   undefined term does not go missing, it THROWS inside a cryptosuite at issuance
   time. `buildLdpVc()` filters against the context it actually loaded rather than
   trusting the hand-kept list.
3a-ii. **`vc_verifier_config.js` is the same kind of library, and it holds the
   OTHER end of that catalogue.** `vc_claims.js` says what an issued credential
   CARRIES; this says what the mock Verifier — the bar door at `/oid4vp/verifier` —
   ASKS FOR, and which of the three credential formats it asks in. Both ends read
   it (`vc_verifier.js` early, `admin.js` late), so it registers no route and
   requires only `helpers.js`, `vc_claims.js` and `vc_configs.js`, none of which
   registers anything either. Four things in it are load-bearing:
   its catalogue is `vc_claims.js`'s rows GROUPED BY CLAIM rather than listed as
   attribute types, because `buildSdJwtVc()` makes one Disclosure per top-level
   claim and `address` is therefore one unit of disclosure however many attributes
   feed it; the DCQL query is built HERE and `vpDcqlQuery()` in `vc_verifier.js` is
   now only the caller that logs it, so the console's preview and the real request
   cannot drift; the ldp_vc paths use the VENDORED CONTEXT'S TERM and not the OIDC
   claim name (`birthDate`, and four flat terms where the others have `address`),
   which was silently wrong while the Verifier could only ask for the two claims
   whose spellings coincide; and `formatById()` reads a SPACE AS A PLUS, because
   `dc+sd-jwt` is a format id containing the one character a query string spells a
   space with — `?format=dc+sd-jwt` arrives as `dc sd-jwt`, which cost nothing
   while an unrecognised format fell back to a constant and costs the bar door's
   own button the moment that fallback is configuration.
   The claims a request asks for are FROZEN onto the transaction in
   `buildVpRequest()` and every check reads them from there: the list is editable
   while a presentation is in flight, and judging what came back against a list
   changed after the question was asked refuses a wallet for answering correctly.
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
   the fourteen protocol families for the same reason it covers the directory's
   user observer; `authn.js`'s `startSession`/`endSession` covers both
   protocols' sign-in and sign-out. Only `ldap_server.js` has a site per
   operation, because ldapjs dispatches straight into the handler and what a row
   says genuinely differs per operation. Do not add a recording site beside a
   funnel — that is how a category comes to be counted twice for one act.

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

   **There is no clear operation and there must not be one.** An erase control
   on an unprotected console would make an audit log unable to answer the one
   question it exists for. Restarting the service is how you get an empty one;
   it is in memory and dies with the process like everything else here.

3d. **`claim_attributes.js` is the THIRD reader of `vc_claims.js`'s catalogue,
   and it is a library like the other two.** `vc_claims.js` says what an issued
   CREDENTIAL carries and `vc_verifier_config.js` says what the mock Verifier
   ASKS FOR; this says which LDAP attributes a TOKEN or an ASSERTION carries,
   per claim set, and it is the second half of `/admin/claims`. It registers no
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

   **Nothing is selected on a fresh start, in any of the four sets.** Unlike
   `/admin/vc`'s ten defaults — which reproduce what that issuer already carried
   — this page changes what every client of this service receives, so it does
   nothing until it is asked to.

   **Precedence is three deep and two of the three are only visible in a
   collision**: the protocol's own claim wins (an ID Token always carries
   `name`, `given_name`, `family_name`, `preferred_username` and `email`, so
   ticking `cn`, `givenName`, `sn`, `uid` or `mail` on THAT set changes nothing
   a client sees), then a typed claim of the same name, then the attribute. In
   the two assertion builders that had to be written as a FILTER rather than as
   an assignment order, because an assertion is a list of elements: a duplicate
   name is not an overwrite, it is two `<Attribute>` elements with one name and
   a relying party reading whichever was emitted first. SAML 1.1 filters on
   NAMESPACE AND NAME together, since that profile splits a claim URI into the
   two.

3e. **`admin_stats.js` now has three inverted hooks and one require of a
   library, and they are four different problems rather than a pattern.**
   `helpers.js` offers `setJwtRecorder()` and this file fills it, because
   `helpers.js` cannot require the counter that `signJwt()` has to reach.
   `admin_stats.js` offers `setUserObserver()` and `ldap_server.js` fills it, so
   that seeding a directory entry cannot drag `/ldap`'s routes to the front of
   the router. `admin_stats.js` offers `setAttributeResolver()` and
   `claim_attributes.js` fills it, because `vc_claims.js` requires this file.
   And `audit.js` is a plain require in the ordinary direction, because it
   requires nothing here. Each is justified by a specific thing that would
   otherwise break; **do not add a fifth by analogy** — a slot is what you reach
   for when a require would close a cycle or move a route, and it costs a reader
   an indirection every time.

3f. **`oauth2_bcp.js` is a library like `dpop.js`, and it is a MODE rather than a
   change of behaviour.** It holds this service's model of RFC 9700 (the OAuth 2.0
   Security Best Current Practice) — the whole of that BCP's section 2, as a table
   of requirements with a check citing each by id. It registers nothing and
   requires only `crypto`, `helpers.js` and `config.js`, so it cannot join a cycle
   and its position in the require order does not matter. **`app.js` requires it
   too**, for one decision (section 2.6's "no CORS at the authorization
   endpoint"), which is safe for exactly that reason and is the only middleware
   this mode touches. Six things in it are load-bearing:

   **The flag is the whole contract, and it is RESTART-ONLY.** `oauth2.rfc9700`
   is OFF by default and every entry point in the module returns "no opinion"
   while it is, so the service behaves EXACTLY as it did before the file
   existed. That is not timidity: every existing caller of this mock uses an
   unregistered `redirect_uri`, no PKCE or the implicit grant, and a client is
   exercised by both answers — one that has only met a permissive server has
   never run its own refusal paths, and one that has only met a strict server
   cannot reproduce the behaviour it is trying to detect. It stopped being a
   runtime setting the moment it grew a consequence that happens before the
   service is listening: `global.https` derives its default from it, so it binds
   the main port as HTTPS. A flag that was runtime for its checks and
   restart-only for its socket is the silent disagreement the config.js header
   warns about — /admin/config would report the mode as on while every
   authorization response still went out over plain HTTP.

   **It decides; `oauth2.js` answers.** This module never touches `res`. What a
   refusal LOOKS like is protocol knowledge and stays there — the same split
   `authn.js` has — and the order is load-bearing rather than stylistic: the
   `redirect_uri` is matched FIRST and a failure is answered as a 400 on this
   service, because reporting `error=invalid_request` by redirecting to an
   unvalidated URI is still the browser being forwarded to an arbitrary URI, and
   an attacker does not mind which parameters ride along. Everything after that
   check may be reported to the client.

   **THREE THINGS OUTSIDE THE AUTHORIZATION ENDPOINT, and each is at a funnel
   rather than a call site.** Refresh token lineage is recorded inside
   `refreshToken()` in `oauth2.js` — the one function that mints one, so no
   grant can issue a refresh token outside its family; the sender-constraining
   note is inside `tokenSet()`, the one place a grant mints a token set; and the
   client-authentication and grant-type checks are ABOVE the grant switch at the
   token endpoint, because a client that cannot authenticate has not
   authenticated whichever grant it was about to ask for. Do not move any of
   them into a branch — five branches means a sixth added later with none, which
   is the same reasoning that keeps `signJwt()` the single counter.

   **A REFRESH TOKEN CARRIES ITS RESOURCES, and forgetting that was a hole.**
   RFC 8707 narrows an access token's audience; the refresh token has to carry
   the same list or the grant WIDENS ITSELF BY BEING RENEWED — the refreshed
   access token would get this service's default audience, which is broader than
   what was authorized. `refreshToken()` records `resources`, the refresh grant
   reads them back for the new audience, and a refresh naming one the grant does
   not carry is `invalid_target`. The same shape as the scope check one field
   over.

   **THE IDLE TIMEOUT IS ON THE FAMILY AND REFUSES RATHER THAN REVOKING.**
   `lastUsedAt` lives on the family and is touched at `noteRefreshRotated()` —
   at the SUCCESSFUL redemption, so a run of refused attempts cannot keep a
   chain alive. It refuses without revoking the family because an idle chain is
   a client that went away and a replayed one is a chain that was copied;
   collapsing the two would make the replay refusal, which says something
   serious, indistinguishable from an afternoon off.

   **REVOCATION IS STILL `stats.revoke()` AND THIS MODULE NEVER CALLS IT.**
   `checkRefreshRequest()` returns the jtis a replay should kill and `oauth2.js`
   revokes them, which keeps both rules intact at once: the one-store rule (the
   revocation set `/oauth2/revoke` and the console write to is the only one), and
   this module's own — it decides, the protocol acts. A rotated token is revoked
   through the same call, which is why a retired refresh token also reports
   inactive at `/oauth2/introspect` rather than merely failing to refresh.

   **The transaction check runs where the values are SPENT.** An authorization
   request runs through `/oauth2/authorize` twice — once before the sign-in
   screen and once on the way back with a session — so a reuse check at the top
   of that endpoint refuses every request in the service for reusing its own
   values between its own two passes. It is called from
   `issueAuthorizationResponse()` immediately before a code is minted, and the
   token endpoint marks the transaction finished when the code is redeemed. A
   value presented again BEFORE that is a reloaded tab, not a second
   transaction, and refusing it is how a check like this gets turned off.

   **What the mode refuses, the metadata stops advertising**, and it happens in
   `asMetadata()` for the reason the two discovery documents are built from one
   object at all: narrowing one of them would produce exactly the drift that
   arrangement exists to prevent.

   **A REFUSAL AT AN ENDPOINT NEEDS THE MATCHING REFUSAL AT REGISTRATION.**
   `checkClientRegistration()` refuses metadata the other endpoints would refuse
   in use — the password grant, the implicit grant, a response type naming
   `token`, an `http` redirect URI off the loopback — because a registration is
   a document the client KEEPS and acts on, and recording a permission this
   server will always refuse is the discovery document's promise broken in the
   other direction. It refuses rather than silently returning different
   metadata, which RFC 7591 also permits: a client that registered for
   `password` and got a registration quietly without it would have to diff two
   documents to notice. **When a new refusal is added to an endpoint, look for
   the registration member that would have recorded it.**

   **ONE DECISION ABOUT FORWARDED HEADERS, SHARED.** `helpers.forwardedFrom()`
   decides whether `X-Forwarded-Proto`/`X-Forwarded-Host` are believed, and both
   `baseUrlOf()` and `dpop.js`'s `htuOf()` go through it. They used to disagree
   — dpop believed them unconditionally and baseUrlOf ignored them — and each
   answer was wrong for the deployment the other was written for: behind a proxy
   the metadata published the last hop's URLs, and without one a client could
   choose the `htu` its own proof was checked against, which unbinds the proof.
   `global.trustProxy` is OFF by default and the htu refusal NAMES it. Do not
   let a third function make this decision a third way.

   **NO CLIENT CERTIFICATE IS EVER READ FROM A HEADER.** `X-Client-Cert` and its
   dozen vendor spellings are listed on `/tls/forwarded` and read by nothing:
   a certificate in a header is one anybody can forge, so RFC 8705 binding and
   mTLS client authentication both take it off the TLS handshake. The cost —
   a proxy terminating mTLS cannot pass the certificate through — is stated
   rather than hidden, and the headers a request carried are SHOWN so that
   ignoring them is visible rather than silent.

   **RESOURCE INDICATORS AND THE AUDIENCE CHECK ARE FEATURES, NOT MODE
   BEHAVIOUR.** RFC 8707 `resource` is honoured in both modes and the protected
   endpoints refuse a token issued for another audience in both, because a
   request that sends no `resource` is unaffected either way — the flag contract
   ("mode off changes nothing") is about existing callers and no existing caller
   sends it. Two details in the check are easy to get wrong: it applies only to
   a token this service VERIFIED (a foreign token's `aud` is a string nobody can
   check), and it matches on the PATH rather than the whole URL, because every
   token carries `<base>/resource` where the base is whatever URL minted it — a
   whole-URL comparison refuses a token minted at localhost and presented at
   127.0.0.1, while a token narrowed to somebody else always has a different
   path.

   **THE REPLAY RELAXATION IS THE ONE THING THE TWO MODES ANSWER DIFFERENTLY
   ABOUT A CODE.** `redeemedCodes` in `oauth2.js` answers an IDENTICAL repeat
   with the tokens it already bought, for the reason written where it is
   declared. RFC 9700 section 4.5 says a real server refuses that, so
   `checkCodeReplay()` does — and revokes the access, refresh and ID Tokens that
   code bought (RFC 6749 section 10.5), through `stats.revoke()` called by
   `oauth2.js`, never by this module. It sits BELOW the two refusals that are
   more specific — a repeat that differs, and a code whose lifetime ran out —
   because those are already refusals in both modes and each deserves its own
   sentence.

   **TWO REQUIREMENTS ARE IN THE TABLE AS `enforced: 'no'` BECAUSE THEY ARE THE
   CLIENT'S**, not because they were skipped: the client must validate the ID
   Token's nonce and must not use a token before that succeeds. Nothing this
   server observes separates a client that checks from one that does not. What
   it can do instead is `oauth2.breakIdTokenNonce` — a deliberately wrong nonce,
   off by default, NOT part of this mode (it is useful in either), reported on
   `GET /oauth2/rfc9700` and logged on every token it spoils. That is the same
   device as `/spnego`'s three knobs and the reserved password `invalid`: a
   reachable negative. Do not fold it into the mode — a compliance flag that
   also breaks tokens is a flag nobody will turn on.

   **THE TLS REQUIREMENT IS NOT A CHECK AND MUST NOT BE MADE ONE.** "An
   authorization response MUST NOT be sent over an unencrypted connection"
   cannot be refused per request — by the time anything here runs the request
   has already arrived, and refusing it would report the problem down the same
   channel. It is a property of the SOCKET, so `global.https` settles it at
   `listen()` in `server.js`, using `tls_server.js`'s ONE per-start certificate
   rather than a second pair (see rule 6: that is the same reasoning that put
   LDAPS 636 on it). The row in `REQUIREMENTS` therefore has FUNCTIONS for
   `enforced` and `note` — the only row that does — and `state()` calls them, so
   the table stays the single source rather than half of that row's meaning
   moving into the view. It reports `deployment` when the port is TLS and `no`
   with the reason when somebody has set `global.https` false to run the checks
   over plain http, which is a case that must stay reachable: a client that
   cannot trust a certificate regenerated every start should still be able to
   exercise the rest. `GET /oauth2/rfc9700` publishes every row with `enforced`
   as yes / detected / always / deployment / no, and a compliance mode that
   quietly skipped a requirement it advertises would be the most misleading
   thing in this repository. New requirements are rows in `REQUIREMENTS` and the
   checks cite them by id; do not add a check with no row.

   **The SCHEME is derived and nothing pins it.** `baseUrlOf()` builds every URL
   from `req.protocol` and the Host header, so an https.Server moves the RFC
   8414 document, the OpenID Provider Configuration, the OID4VCI and OID4VP
   metadata, the federation metadata, the DID document and the `iss` of every
   token together, with no module told about any of it. Do not "fix" that by
   hardcoding a scheme anywhere — it would be wrong on the default plain
   listener. The ONE exception is a PINNED `oauth2.issuer`: `issuerOf()` in
   `oauth2.js` upgrades an `http://` pin to `https://` when the port is TLS and
   logs it, because a client MUST reject a document whose issuer is not the
   identifier it fetched from, and that failure names the issuer rather than the
   scheme. Pinning a different HOST still produces the mismatch it exists for.

3j. **`authorization_servers.js` makes one process BE several authorization
   servers, and the document is the server rather than a description of one.**
   The path component both discovery shapes carry selects one; its endpoints
   live under that name (`/{id}/oauth2/…`, registered in one block in
   `oauth2.js` so the prefixed set cannot drift from the unprefixed one); and
   the capabilities in its document DRIVE those endpoints. A library requiring
   only `helpers.js`. Nine things:

   **EVERY AUTHORIZATION SERVER STARTS EQUAL, and every name is one.** An
   unconfigured profile has the defaults `asMetadata()` builds, and a name
   nobody has configured is CREATED on first sight — by an endpoint or by a
   metadata fetch, since reading the document is accessing the server. It is
   marked `autoCreated` so the console can tell the two apart. Bounded at
   `MAX_PROFILES`, past which a name is still SERVED with the defaults and
   simply not recorded: the id comes off a URL path, so any caller can invent
   one, and a load generator must not take the feature away from the names that
   matter.

   **`capabilitiesOf()` IS READ BY BOTH THE DOCUMENT AND THE ENDPOINTS.** That
   is the whole of how they are kept in step — there is no second table of what
   `tenant1` does that could disagree with what `tenant1` advertises. An
   enforceable member is marked `enforces` on its catalogue row; anything else
   is published and not read.

   **A REMOVED MEMBER MEANS THE CHECK DOES NOT RUN**, and that is the honest
   reading rather than a gap: a client cannot learn from an absent
   `code_challenge_methods_supported` that PKCE is unavailable, so a server that
   refused every method on the strength of having removed the member would be
   enforcing something it never said. `capabilityList()` returns null for it and
   every caller distinguishes null from an empty list.

   **A CREDENTIAL DOES NOT CROSS BETWEEN THEM.** The authorization code carries
   `authorization_server` and the token endpoint refuses one issued by another.
   They publish different capabilities and are presented to a client as separate
   servers; one process serving several must not let a credential leak between
   them.

   **`asBaseOf(req)` IS WHAT EVERY ISSUER AND AUDIENCE IS BUILT FROM.** A named
   authorization server is its own issuer, so its tokens' `iss`, their `aud`,
   and the RFC 9207 `iss` on its authorization responses all carry its path —
   and its document says the same, which is what a conforming client checks.
   **The sign-in return URL has to carry it too**: `returnTo` was hard-coded to
   `/oauth2/authorize`, which sent every named server's SECOND pass — the one
   that issues the code — to the default server, and the code came out belonging
   to somebody else with nothing on the way through looking wrong.

   And five things from before:

   **A CATALOGUE, NOT A SCHEMA.** Any member is settable, including one this
   service has never heard of, because publishing something a client did not
   expect is half the point of a mock. That is the deliberate OPPOSITE of
   `applications.js`, which refuses an attribute outside its table — that table
   is a published contract about what an entry carries, and this is a way to lie
   on purpose. Do not add validation here.

   **THE PROFILE IS APPLIED TWICE, and it has to be.** `asMetadata()` applies it,
   and then `oidcMetadata()`'s `Object.assign` overwrites every member OpenID
   Connect Discovery adds — so it is applied again at the end of that function.
   A profile that set `userinfo_endpoint` would otherwise work in the RFC 8414
   document and do nothing in the OIDC one.

   **IT IS APPLIED LAST, AFTER `bcp.applyToMetadata()`.** A profile is somebody
   saying "publish this", and a mode quietly winning would make the control
   appear not to work. A profile re-advertising the implicit grant the mode
   refuses is a document that lies about this server, which is the case the
   drift report exists for.

   **DRIFT MEANS SOMETHING NARROWER NOW.** It used to be "this document lies
   about this service", which cannot happen for an enforced member any more —
   the document IS the behaviour. `driftOf()` therefore SKIPS a member with an
   `enforces` row and reports the rest: what this service cannot honour however
   it is set. Those stay publishable, because a misconfigured document is a
   client error path worth running, and they stay reported.

   **AN UNCONFIGURED PATH IS NOT AN ERROR.** It publishes the ordinary document
   with the issuer taken from the path, which is what this service has always
   done — so adding this feature changed nothing for any existing caller, and a
   deleted profile leaves its URLs answering.

3i. **`client_auth.js` verifies all six token-endpoint methods, and it is the
   PROTOCOL half of section 2.5.** `oauth2_bcp.js` decides whether a client has
   to authenticate at all (the policy); this decides whether what arrived proves
   it (the mechanics). It registers nothing and requires `helpers.js`,
   `config.js` and `mtls.js`, so it cannot join a cycle. Four things:

   **NOTHING FALLS THROUGH UNCHECKED ANY MORE.** `private_key_jwt` and
   `client_secret_jwt` used to be advertised and ACCEPTED without an assertion
   being looked at — worse than not offering them, because a client author came
   away believing a check had happened. A method this file cannot verify is now
   REFUSED, and `token_endpoint_auth_methods_supported` is built from
   `METHODS` so the metadata cannot advertise one that would not be.

   **THE METHOD DECIDES THE ALGORITHM FAMILY, NOT THE HEADER.** An assertion
   nominating `HS256` for `private_key_jwt` is refused rather than verified —
   verifying it would use the client's PUBLIC key as an HMAC secret, which is
   the classic JWT forgery and one anybody can perform.

   **THE UNVERIFIED `sub` SELECTS, IT DOES NOT ESTABLISH.** OIDC Core section 9
   lets a `private_key_jwt` request omit `client_id`, so `clientFrom()` reads
   the assertion's `sub` unverified — safe for exactly one purpose, choosing
   which registered client to check AGAINST, because the assertion is then
   verified against that client's keys with `iss` and `sub` required to match.
   Do not read anything else out of an unverified assertion.

   **`jwks_uri` IS RECORDED AND NEVER FOLLOWED**, which is the same refusal
   `wsfed.js` gives `wreqptr`: fetching a URL somebody registered in order to
   verify a credential is a server-side request forgery with a citation
   attached. Holding that position in one file and not the other would be no
   position at all.

3h. **`mtls.js` is a library like `dpop.js`, and it is the OTHER half of RFC
   9700 section 2.2.** `dpop.js` binds a token to a KEY proved per request;
   this binds it to the CLIENT CERTIFICATE the TLS connection was made with (RFC
   8705 section 3). It registers nothing and requires only `helpers.js` and
   `config.js`, so it cannot join a cycle. Five things are load-bearing:

   **`dpop.js` REQUIRES IT, and that is where the resource-server check goes.**
   `presentedAccessToken()` there is the single check `/oauth2/userinfo` and the
   three credential endpoints share — the same reasoning that put that function
   in `dpop.js` rather than in `vc_issuer.js`. A second check beside it would be
   a fourth caller nobody updated.

   **The thumbprint is of the DER**, base64url, unpadded — not the PEM, not the
   public key, not hex. Every other spelling looks right in a log and matches
   nothing, so `thumbprintOf()` is the only place it is computed and both ends
   of the comparison go through it.

   **An UNVERIFIED certificate still binds.** `server.js` sets
   `rejectUnauthorized: false` on the main listener, and that is not a hole: RFC
   8705 section 3 binds to the CERTIFICATE and permits a self-signed one
   explicitly — the proof is that the same key completed this handshake, not
   that a CA vouched for it. Requiring verification would make the feature
   unreachable, since `/tls/trust` starts empty by design.

   **The confirmation is MERGED with the DPoP one, never replaces it.** A client
   that presented a certificate AND sent a proof demonstrated both, and a token
   recording one would discard a check somebody performed. The REFRESH token is
   bound too — otherwise the long-lived half of the grant stays a bearer
   credential that mints bound tokens for whoever holds it, which is worse than
   not binding at all because the `cnf` on what it mints implies a guarantee
   nobody checked.

   **The request reaches `accessToken()` through ONE funnel.** The token
   endpoint's `issue()` adds `request: req` to every grant's options, so six
   call sites did not have to remember it — five that would and a sixth added
   later that would not, the reasoning that keeps `signJwt()` the single counter.
   Only available where the main port is TLS, and
   `tls_client_certificate_bound_access_tokens` is advertised only there: a
   client reads a metadata member as a promise.

3g. **`applications.js` is a library like `dpop.js`, and THE DIRECTORY IS ITS
   STORE.** It holds every application this service has been asked about — an
   OAuth client, an OIDC relying party, a SAML 2.0 or 1.1 service provider, a
   WS-Federation application, a WS-Trust relying party, the OID4VP verifier, a
   Kerberos service — as entries under `ou=applications`. It registers no route
   and requires only `helpers.js` and `audit.js`, so it cannot join a cycle;
   `admin_stats.js`, `oauth2.js`, `wsfed.js`, `wstrust.js`, `krb5_kdc.js` and
   `krb5_service.js` require it in the ordinary direction, and `ldap_server.js`
   fills its `setDirectory()` slot at require time for the reason
   `vc_claims.js`'s is filled (rule 6). Six things are load-bearing:

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
   definition: the entry is built by WALKING it, `/ldap/applications` publishes
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

   **`clientConfigOf()` IS WHAT THE SECURITY CHECKS READ, NOT `registrationOf()`.**
   The two answer different questions — "what may this client do" versus "what
   did it register" — and they stopped coinciding the moment the console could
   create an application with redirect URIs and no registration behind it. So
   the RFC 9700 checks in `oauth2.js` pass `clientConfigOf()`, which is built
   from the ATTRIBUTES; `appRegistered` records how an application got here and
   not whether what it holds counts. `registrationOf()` is still what RFC 7592
   and the UserInfo signing algorithm read, because those are genuinely
   questions about the registration.

   **TWO ATTRIBUTES HOLD CREDENTIALS IN THE CLEAR** — `oauthClientSecret` and
   `appRegistrationAccessToken` — which is the `/krb5/principals` decision about
   the Kerberos passwords, made again and for the same reason. Now that RFC 9700
   mode CHECKS that secret, anyone who can read the directory can authenticate as
   that client; that is the honest state of a service that authenticates nobody.
   They are never given to `audit.js`, whose no-credential rule is untouched.

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

6. **`ldap_server.js` must stay after `admin.js` AND after `tls_server.js`, and it
   INVERTS a dependency the same way `helpers.js` does.** The second half of that is
   new and is a plain require rather than an inversion: it serves `tls_server.js`'s
   server certificate and key on 636, and neither thing that forces an inversion
   applies — that module knows nothing about this one, so there is no cycle, and its
   routes (`/tls*`) collide with nothing here. What the require DOES do is pull those
   routes into the express router at that point, so `server.js` requires
   `./tls_server` BEFORE `./ldap_server` to keep "the require order is the route
   order" true rather than a fiction node quietly corrects. It changes no output —
   `/sts-metadata` sorts its rows by path within a group. Its embedded directory grows an entry under
   `ou=users` for anybody who authenticates through any of the families here, and
   `admin_stats.recordAuthentication()` is already the single funnel all of them
   pass at the moment a credential is ACCEPTED — so one observer there is one place
   and not fourteen. **A verified TLS client certificate is one of them and is the
   odd one: its identity is not a name but a DN**, so its entry is named from the
   subject's CN (or the leaf RDN where there is none), every other RDN of the
   subject becomes an attribute, and the issuer, serial, validity and fingerprint go
   on beside them as `x509*` attributes that are this service's own names and not
   schema. `certificatePlan()` carries the placement rules and what they cost.

   **A DECENTRALIZED IDENTIFIER is the THIRD shape and there is one plan per
   shape** — `certificatePlan()`, `didPlan()`, `namePlan()`, chosen in
   `autoCreateUser()` and decided in each. A DID is neither a DN nor a name but
   one long opaque string, so its entry is named by a DIGEST of it —
   `uid=did-<12 hex>,ou=users` — with the identifier whole on the entry as
   `didSubject` and its method as `didMethod`. Written out, a `did:jwk` is a DN
   of several hundred characters of key material; given a container of its own,
   `ou=dids`, it would sit outside `populateVcAttributes()`'s sweep and
   `/admin/groups`, which both walk `ou=users`. **On those entries the `uid` is
   NOT the identity**, which is the one thing that does not generalise from the
   other two plans: `didSubject` is, `locateEntry()` finds the entry by it (the
   same way it finds a certificate's by `x509subject`), and `personaKeyOf()`
   invents the person FROM it — seed the persona from the digest instead and the
   startup sweep describes a different person from the one the authentication
   path already wrote.

   **The three DIDs come from the Decentralized Identity endpoints, and each
   reaches the funnel at the point its own credential is accepted.**
   `subjectClaimsFrom()` in `vc_issuer.js` records the person an access token
   names — HERE and not at the two credential endpoints, because it is the single
   point that decides who a credential is about, so a batch of five proofs is one
   record and a deferred issuance is not counted twice. `buildCredentialFor()`
   records the credential's SUBJECT when it is DID-shaped, one per credential,
   because a batch is several holder keys and therefore several DIDs; the `did:`
   guard is load-bearing rather than tidy — the other two formats name their
   subject with the token's own `sub`, or with a `urn:uuid:` minted fresh per
   credential, and recording those would evict real people from a store with a
   fixed maximum to hold identifiers nothing will present again.
   `/oid4vp/response` records the holder BELOW the refusal, so a presentation
   that failed a check records nothing. And `/did/generate` records what it
   MINTED, but only for `?method=jwk`: the `web` branch returns this service's
   own DID, and an entry for it would file the issuer among the people.

   But this module requires `admin_stats.js` (it needs
   `identityOf`'s normalisation, so `alice`, `urn:sts-mock:user:alice` and
   `alice@REALM` seed ONE entry), which means `admin_stats.js` cannot require it
   back: that is the cycle rule 2 exists for. So `admin_stats.js` offers
   `setUserObserver()` and this module fills it at require time. The observer's
   return value is ignored and a throw from it is caught — a directory must never
   be able to fail an authentication. Do not "simplify" that into a require in the
   other direction, and do not seed the entry at each authentication site instead:
   fourteen call sites means a fifteenth that is not.

   **A container it does NOT sweep, and that is the point of it.**
   `ou=applications` is `applications.js`'s store (rule 3g) and this module is
   what makes it one — `readApplication`, `writeApplication`, `allApplications`
   and `countApplications`, filled into that module's `setDirectory()` slot at
   require time, plus `GET /ldap/applications`. The division is exact and worth
   keeping: THAT module owns the schema and both conversions, THIS one owns
   where the container is, how an entry is created and what the cap is. Note
   that `writeApplication()` REPLACES rather than merging, which is the one
   place this file breaks `applyVcAttributes()`'s fill-only-what-is-absent rule
   — deliberately, because the record being written was read from that entry a
   moment ago, so merging would make it impossible ever to REMOVE a value and a
   redirect URI deleted with `ldapmodify` would come back on the next request.

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

   **A THIRD hook is the same direction as the second, and there is one rule it
   carries that is not obvious from the code.** `/admin/groups` lists this
   directory's groups and drills into one; `admin.js` offers `setGroupReader()`
   and this module fills it with `groupsFor()`, for exactly the route-order reason
   above. What that function decides — and what must not be reimplemented in
   `admin.js`, which renders and decides nothing — is **what counts as a group**,
   and it is two rules rather than one: an entry UNDER `ou=groups`, or an entry
   carrying a group `objectClass` wherever it sits. Both, because the directory is
   schemaless and a client can `add` a `groupOfNames` under `ou=users` or an entry
   with no `objectClass` at all under the groups container; either rule alone
   answers for one of those and silently loses the other, so each row says which
   rule caught it. The three disagreements it reports are the point of the page and
   none of them is a defect to fix: a **dangling** member (this directory does not
   do referential integrity, so a delete leaves the DN behind), a member that is
   itself a **group** (nesting is shown, never expanded — nothing here walks it),
   and an entry whose own `memberOf` names a group that does not list it back
   (nothing here maintains `memberOf`; it is not even a standard attribute). Note
   also that `memberUid` holds a bare name where `member` and `uniqueMember` hold a
   DN — resolving the three alike is how every `posixGroup` member gets reported as
   dangling.

   **A FOURTH HOOK POINTS AT `vc_claims.js` and it writes rather than reads.**
   `/admin/vc` chooses which LDAP attributes an issued Verifiable Credential
   carries, so those attributes have to exist on people: this module fills
   `vcClaims.setDirectory()` with `vcAttributesFor()` (one person's attributes, for
   a claim value) and `populateVcAttributes()` (the sweep). The sweep runs when the
   selection changes, when an entry is created, when a returning person
   authenticates, and once at startup. Three rules in it are load-bearing —
   it fills only what is ABSENT (so an operator's `ldapmodify` and the seeded
   people's own names survive), it writes ONE value rather than appending (or an
   entry accumulates a birthdate per sign-in), and it walks entries UNDER
   `ou=users` only rather than everything carrying a `person` objectClass, because
   this directory is schemaless and a client can put that class on a group.
   Auto-created entries also take their `cn`, `sn`, `givenName`, `displayName` and
   `mail` from the invented persona now rather than from the login name — those
   are attributes a credential asserts, and `given_name: "dave"` taught a wallet
   nothing — while the `uid` and the DN stay the login name, which is the identity.

   **HOW SOMEBODY AUTHENTICATED IS WRITTEN ONTO THE ENTRY THEY ALREADY HAVE,
   and that is what a WebAuthn SECOND FACTOR adds to this directory.** The two
   roles land differently and neither needs a call site of its own:
   passwordless WebAuthn is an authentication, so it reaches the funnel and
   `autoCreateUser()` creates the entry exactly as a password sign-in does; a
   second factor authenticates nobody new — the person is the one the password
   step named — so it creates nothing and `applyAuthenticationFactors()` writes
   a FLAG on the entry that exists. It reads the `amr`/`acr` that
   `recordAuthentication()` now passes through on the observer, beside
   `certificate`, and writes three of this service's own attribute names:
   `authnMethod` (every RFC 8176 method ever used here, APPENDED),
   `mfaAuthenticated` (TRUE/FALSE for the MOST RECENT authentication,
   ASSIGNED — appending would accumulate one value per sign-in, the trap
   `applyVcAttributes()`'s second rule is about) and `mfaLastAuthTime` (when
   multi-factor last happened, never cleared). Two rules: NOTHING IS WRITTEN
   WHERE NOTHING WAS STATED, because most families here set no `amr` at all and
   `mfaAuthenticated: FALSE` on everybody would turn "never told" into
   "checked, and it was one factor"; and TWO FACTORS MEANS TWO, so a
   passwordless `["hwk"]` is FALSE.

   **A GROUP HERE GRANTS NOTHING**, and both pages say so where a reader will see
   it. The same is true of those three attributes — nothing reads them back. No access token, ID Token, SAML assertion, WS-Federation token or Kerberos
   PAC carries a group from this directory and no endpoint reads one. On a service
   that authenticates nobody it could hardly be otherwise — but a console that
   listed groups beside the tokens page without saying it would let somebody
   conclude that adding a user to `cn=directory-admins` changed what their token
   could do.

`userFor`, `parseBody`, `oauthError`, `vciError`, `signJwt` and
`firstByLocal`/`textByLocal` are in `helpers.js` because more than one protocol needs
them, not because they are especially general. The last two are read by three parsers
— the WS-Trust RST, WS-Federation's `wreq`, and the `wresult` the mock relying party
is POSTed — and they match on **local name with the namespace ignored** because the
trust namespace alone has four versions in use. That is what lets one parser answer
WS-Trust 1.0 through 1.4 instead of four.

7. **`admin_api.js` must stay after `admin.js`, and the rule it carries is about
   the FUTURE rather than about load order.** The plain dependency first: it
   requires that module for the four action functions and the per-page JSON
   views, so it must come after it. Nothing else about its position matters — it
   registers no wildcard and collides with no path.

   The rule that does matter is **a control added to `/admin` gets an operation
   on `/admin-api` in the same commit** — a CONTROL, which is why a page with no
   form on it needs only its GET. Not eventually, and not when somebody
   asks: an API that covers eight of nine controls is worse than one that covers
   none, because the ninth is found by a caller who has already written the code
   that assumed it. A page with no form on it still needs its GET —
   `/admin-api/audit` is the one, and it is the audit page having nothing to
   change rather than an operation nobody got round to.

   Two things make that cheap rather than a matter of discipline, and one thing
   cannot be made cheap at all:

   * **The API decides nothing.** Every POST calls the SAME action function the
     console's form posts to — `tokenAction`, `claimsAction`, `vcAction`,
     `vpConfigAction` — with `action` taken from the URL instead of from a hidden
     input, and every GET calls the same JSON view the page's `?format=json`
     answers. Those views are now functions in `admin.js` (`consoleJson`,
     `metricsJson`, `tokensView`, `usersView`, `groupsView`, `claimsJson`,
     `vcJson`, `vpConfigJson`) for exactly this reason: they used to be built
     inline in the route handlers, which was fine while there was one caller. So
     adding an action to a console switch is most of adding it here, and what
     remains is one row of `admin_api.js`'s table.
   * **The OpenAPI document is GENERATED from that table** (`admin_api_spec.js`),
     so an operation cannot exist and be undocumented, nor be documented and not
     exist. Do not write a spec file beside the code — that is the thing that is
     wrong within a month.
   * **What no code here can check is a new console control with no row.**
     Nothing in this service can see a form appear on a page. So the parity is
     asserted from outside, by the parent project's `tests/admin_api.js`, and it
     reads the facts off the SERVICE rather than off a list in the test: the
     console's page list comes back in `GET /admin-api/status`, and each action
     handler, asked for an action that does not exist, replies naming the ones
     that do. Add an action to a switch and that sentence grows; the test then
     fails until the API has an operation for it.

   One consequence for the console side: `usersView()` and `groupsView()` build
   the HTML as well as the JSON, and `/admin-api` throws the markup away. That is
   what `/admin/users?format=json` has always done, it is a string concatenation
   on a mock, and the alternative — a second set of builders for the same data —
   is the thing this whole arrangement exists to prevent.

7a. **THE BREADCRUMB TRAIL IS IN THE SHELL AND IT IS ON EVERY PAGE.**
   `page()` draws `trailBar()` under the nav on all of them — `Admin console ›
   Applications › rfc9700-debugger`, and on `/admin` itself the one crumb. It is
   not the nav said twice: the nav answers "what else is there", the trail
   answers "where am I and how do I get back", and the tab for the section a
   reader is standing IN is exactly the tab that says nothing about the page they
   are standing ON. That was the original bug — `item.path === active` is true on
   `/admin/applications` and on `/admin/applications?application=x` alike, and the
   active tab is drawn as plain text, so the one control pointing at the list was
   the one control the shell had turned off.

   A drill-down view returns `up` — `upTo(section, leaf, listView)` — and
   `respond()` threads it to `page()`. It makes the active tab a LINK as well.
   **The section label comes from `NAV`**, so a renamed tab cannot leave a trail
   naming the old one. **The last crumb is never a link**: a crumb that reloads
   the page you are on teaches a reader not to trust the ones beside it.

   **WHAT MAKES IT A BREADCRUMB RATHER THAN A LINK TO THE SECTION IS
   `listViewOf()`.** A drill-down link carries the list's filter and page, and the
   section crumb spends it, so back lands where the reader was. `LIST_PARAMS` is a
   WHITELIST PER SECTION and must stay one — what comes out of it goes into a URL
   this service hands to a browser, which is the rule `backTo()` already follows.

   **THREE PLACES DROP IT IF NOBODY CARRIES IT, and they are already handled.**
   A drill-down's own controls carry the whole query (`pageParamsOf()`), so they
   are free. `perPageForm()` is a GET form — it posts its own fields and nothing
   else — so the filter is spelt out as hidden inputs, and its PAGE deliberately
   is not: `per` is what that form changes. And every form on the applications and
   authorization-server drill-downs carries one opaque `back` field, which the
   POST handler REBUILDS through `listViewFromBack()` rather than echoing. **A new
   form on either of those pages needs `carryBack` in it**, or an edit made
   through it silently costs the reader their place in the list.

   **A NEW DRILL-DOWN NEEDS `up` AND NOTHING CAN CHECK THAT IT HAS ONE**, the same
   gap rule 7 describes: no code here can see a page appear. The four are
   `?user=`, `?group=`, `?application=` and `?profile=`, and every branch of those
   views sets it — the not-found branches included, since a page saying "no such
   group" is the page a reader most needs a way off. A parameter that merely
   FILTERS a list is not a drill-down and must not pass `up`: the section crumb
   would then point at the page the reader is already on.

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

## `/admin-api/docs` is the only page here with an *explorer* script

`app.js` sets `script-src 'none'` for the whole service, and the reason is in its
own comment: it is what makes the family of reflected-content problems moot rather
than merely unlikely. The API explorer needs a script, so it is the one page that
relaxes that header — on two routes, in exactly two clauses (`script-src 'self'`
and an added `connect-src 'self'`), with `default-src 'none'` and everything else
untouched.

**The script is a separate resource for that reason and no other.** `'self'` is
enough for a file; an inline block would have needed `'unsafe-inline'`, which is
the clause that would make the relaxation matter. Do not inline it, and do not add
a second scripted page without asking whether it needs to be one.

It is also **this repository's own explorer rather than Swagger UI**, and that was
weighed rather than skipped: `swagger-ui-dist` is 11.7 MB unpacked with an
install-time telemetry dependency, in a service whose package.json is deliberately
short and whose image is built in containers that may have no network beyond the
registry. What it would have bought is a familiar look for an API with no
authentication, no OAuth flows and no polymorphic bodies. `admin_api_explorer.js`
is ~250 lines, has no dependency, and does the same three things — read the
document, fill a form, show the response — plus the equivalent `curl` line, which
is what an operator of a mock actually copies.

## `config.js` is the only place a setting is read

Configuration used to be forty-odd `process.env.X || 'a default'` expressions spread
over twelve modules. Each was readable where it stood and the set of them was not:
there was no way to ask this service what it was configured with, no way to change
anything without restarting it, and no list anywhere of what could be changed at all
— the answer was a grep, and the grep only found the ones spelt the way you guessed.

**A new setting is a row in `SETTINGS` and nothing else.** The row carries the key
(which is both the dot path in the appconfig file and the name every surface uses),
the environment variable, the type, the default, the prose, and `runtime`. From that
one row it appears in `/admin/config`, in `GET /admin-api/config`, in the OpenAPI
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
issued for `tls.hostnames`/`tls.ips` at boot, and the Kerberos principal database and
every long-term key in it comes from the realm, the SIDs and the passwords at require
time); and **the directory tree**, which `ldap.baseDn` is the root of. Marking a
setting runtime when the thing derived from it is not rebuilt is worse than marking
it restart-only, because the two then disagree silently.

**A runtime setting must be READ WHERE IT IS USED.** That is why so many of the
module-level `const`s became functions — `vciBatchSize()`, `clockSkewSeconds()`,
`maxEntries()`. A `const` captured at require time is the one thing `/admin/config`
cannot change, and it fails in the direction that looks like the console is broken.

**Resolution order is override, env var, LEGACY env var, appconfig file, built-in
default.** Env beating the file is what keeps every existing container and test
working: nothing in the parent project sets these variables in compose, but
`tests/krb5_spnego_http.js` sets `KRB5_REALM`, `KRB5_KDC_PORT` and
`KRB5_SERVICE_PORT` before requiring the KDC in-process, and that still wins. The
legacy level has exactly one occupant: `STS_ISSUER`, which used to be a single value
serving as the SAML assertion issuer, the WS-Trust token issuer AND the
WS-Federation entityID. Those are three different things that shared a default — an
entityID names the identity provider, an Issuer names whoever signed an assertion —
so they are now `saml.issuer`, `wstrust.issuer` and `wsfed.entityId`, all three still
fed by `STS_ISSUER` when it is set.

**It is a library (rule 3) and it sits UNDER `helpers.js`.** It requires only bunyan
and `process.env.CONFIG_FILE`, and makes a bunyan logger of its own rather than
taking the shared one, because `helpers.js` requires IT. A cycle here would hand
`helpers.js` a half-initialised module whose `value` is undefined, and the symptom
would arrive somewhere else entirely as "value is not a function".

**The three `env/*.js` files were GENERATED from the table** and carry every key with
the value the expression in the module used to have, so a run with the shipped file
behaves exactly as one with the old file that carried only `logLevel`. Two settings
are deliberately absent because their default is DERIVED from another
(`krb5.serviceDomains` from the realm, `oid4vp.walletUrl` from `oid4vci.walletUrl`);
they carry `derived: true`, which is what keeps the startup audit from reporting them
as drift. That audit — `auditAppconfig()` — logs a setting the file omits and a key
the table does not know, and does neither when the file carries none of these keys at
all, which is the ordinary case for the parent project's in-process tests: they load
this service's KDC modules with `CONFIG_FILE` pointing at the TEST suite's config.

**`tests/Dockerfile` in the parent project copies this file.** It is under
`helpers.js` in the graph, so every in-process job that loads `krb5_kdc.js`,
`app.js` or `spnego.js` needs it; missing, the failure is `Cannot find module
'./config'` before any test has run.

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
* **The library is NOT patched.** Everything in `ldap_server.js` is handlers
  registered against its public API — LDAPS included, which is a second
  `createServer({ certificate, key })` instance and a fan-out over the operation
  methods, not a reach into the internal `routes` map — so the submodule stays a usable copy of
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

* **It is permissive on purpose, and it can be told not to be.** Everything in this
  list is the default; `oauth2.rfc9700` turns the OAuth 2.0 / OIDC authorization
  flow into an RFC 9700-conforming one (see rule 3f and `oauth2_bcp.js`) and, with
  it, **turns the main port into an HTTPS listener** on the certificate 8443, 9443
  and LDAPS 636 already share — so there is then no plain listener in this process
  and `/tls/trust` has to be bootstrapped with verification off. The flag is OFF by
  default, changes nothing until it is set, and is RESTART-ONLY because of that
  socket. What it does and does not enforce is published at `GET /oauth2/rfc9700`
  rather than left to be read out of the code. Nothing else here has such a mode.
* **An OAuth client is not a person, and now it has somewhere to be.** It is still
  skipped by `autoCreateUser()` — `ou=users` is for people — but every client,
  relying party, service provider and Kerberos service gets an entry under
  `ou=applications` instead (rule 3g). That container is a REGISTRY rather than a
  record: the RFC 7591 registrations live there, nothing caches them, and an
  `ldapmodify` — or a form on `/admin/applications`, or a POST to
  `/admin-api/applications/{action}`, which are the same functions — changes what
  the protocol endpoints do. What those two will NOT change is the derived half:
  the counters and the sightings are what happened, and only LDAP reaches them.
* **It checks ONE credential, and only in RFC 9700 mode: a registered client's
  secret.** Section 2.5 conditions its requirement on a process for issuing
  credentials existing, and `POST /oauth2/register` is one — so a client that
  registered HERE as confidential must present the `client_secret` this service
  minted for it at the token endpoint. Nothing else changes: a `client_id` this
  service never registered has no credential on file and is untouched, a
  registered public client has nothing to authenticate with, and a client
  declaring `private_key_jwt` is ACCEPTED AND NOT VERIFIED (reported as such,
  because an unverified assertion that is accepted looks exactly like a verified
  one from the client's side). **No end user's password is checked in that mode
  or any other**, which is the next bullet and is not affected by this one.
* **It checks no password.** The username typed at `/authn/login` — or at
  `/wsfed/login`, which creates the same session — becomes the identity in every
  token and every assertion.
* **The LDAP directory takes that further: EVERY BIND SUCCEEDS**, any DN and any
  password, anonymous included — **on LDAPS (636) exactly as on the plain port**,
  since the two listeners share one set of handlers. TLS there keeps the password off
  the wire and does not make it checked, and a client certificate is never even asked
  for on that socket. The single exception is the literal password
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
  session starts, no token is issued, no endpoint will let its holder do anything an
  anonymous caller cannot, and a revoked certificate verifies here and would not
  verify anywhere that matters. All of that is stated in the report itself rather
  than left to be discovered — a mock that quietly turned a certificate into an
  identity would teach a client something false about every server it will ever meet.
  **It IS recorded, which is a different claim and the two must not be merged.** When
  a handshake completes with a certificate that verified, `tls_server.js` calls
  `stats.recordAuthentication()` — the same funnel every other family uses — so the
  subject DN appears on `/admin/users` under protocol `TLS` and the directory's
  observer seeds an entry for it. Three things there are load-bearing: it happens on
  `secureConnection` and **not in the request handler**, because the credential was
  accepted at the handshake and per-request counting would report one connection's six
  requests as six authentications; it happens only when `authorized` is true, so a
  certificate that failed records nothing on the permissive listener; and the identity
  is the subject in **RFC 4514 form** (leaf first, values escaped), which is a
  different string from the display DN shown beside it and is the one the directory
  builds from.
* **The values in an issued credential are invented, and nothing verifies them.**
  `/admin/vc` says which LDAP attributes a credential carries; the value is read
  from that person's directory entry, and what the entry lacks is generated from
  their username — deterministically, so one username is one invented person across
  restarts, and in obviously fictional ranges (RFC 2606 mail domains, `555-01xx`
  numbers, streets called `Placeholder`). A verifier that believed a birthdate from
  here would be believing a web form. Nothing reads a credential claim back either:
  no token, assertion or PAC carries one and no endpoint decides anything on one.
* **A presentation that VERIFIES is not a sign-on either.** The OID4VP Verifier
  checks properly — issuer signature, every Disclosure digest against `_sd`, the Key
  Binding JWT including `sd_hash`, the nonce, the audience, the validity window and
  whether the claims asked for arrived — and then says yes on a web page and stops.
  No session starts, no token is issued and nothing else in this service reads what
  was presented. **It IS recorded, which is a different claim and the two must
  not be merged** — the same distinction a verified TLS client certificate
  draws. The holder goes through `recordAuthentication()` like every other
  accepted credential, so it appears on `/admin/users` and the directory seeds
  an entry for it; what the row says is that an identity presented a credential
  here and it verified, and nothing more. What it asks for is configuration
  (`/admin/vc-verifier-config`) and
  is deliberately a SEPARATE setting from what the issuer mints (`/admin/vc`), so
  that asking for a claim no credential here carries stays reachable: that is the
  only way to exercise a wallet's "I cannot satisfy this request" path, and one page
  setting both would make it impossible to produce. Asking for NO claim is a setting
  too — DCQL reads an absent `claims` member as the whole credential.
* **The audit log at `/admin/audit` is HISTORY where the rest of the console is
  STATE**, and it is the one page here that can answer *when* and *by whom*.
  Six categories — a credential accepted in any of the fourteen families, a
  sign-on session created or ended, every LDAP operation over 389 and 636 alike,
  every console page and form, every management API call, every other endpoint
  call — recorded at the five funnels rule 3c names. **No credential is ever in
  a row** and the page says so; **one act usually produces several rows** (a
  sign-in writes three, at three layers) and the page says that too, because a
  reader counting rows will otherwise read them as duplicates; and **it observes
  itself**, since drawing it is console access, which is stated rather than
  suppressed — a blind spot exactly where the reader stands is worse than an
  extra row. What it deliberately does not record is the CLIENT'S ADDRESS: on a
  mock reached over a compose bridge that is a fact about docker, and a column
  right on a laptop and quietly wrong everywhere else is worse than none. It
  records the CHANNEL instead (`http`, `ldap`, `ldaps`, `internal`).
* **The admin console at `/admin` is not protected and holds nothing on disk.** It is
  the one surface that can change what the protocol endpoints do — it revokes tokens
  through the same set `/oauth2/revoke` writes to, and it adds custom claims to every
  future access token, ID Token and SAML assertion. Custom claims are **additive**:
  the names this service sets itself are refused at configuration time, because an
  `exp` settable from a web form would produce tokens that fail to verify with nothing
  pointing back at the page. The same page's other half puts **LDAP attributes** in
  those four, whose values come off the person's own entry rather than out of the form
  — see rule 3d, and note that the additive rule holds there too: the protocol's own
  claim wins, then a typed one, then the attribute. It deliberately does not invalidate assertions, tickets
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
  **"The observer is installed" is not the same claim as "this protocol calls the
  funnel", and WS-Trust is what that cost.** Three of its paths accepted a
  credential without ever reaching `recordAuthentication()`, so each produced
  somebody who had authenticated here and appeared on no page and in no
  directory: `Validate` and `Cancel` answered above the `authenticate()` call, a
  request carrying both a UsernameToken and an `OnBehalfOf` returned at the
  delegation branch before the UsernameToken had been looked at, and a `Renew`
  with no security header read the assertion out of its own `RenewTarget` and
  recorded that as the credential. Two rules come out of it and both generalise
  to the next family: authenticate ABOVE the branch on the operation rather than
  inside the branches that happen to need a subject, and look for a credential in
  `wsse:Security` — anywhere else, only OUTSIDE the elements that hold somebody
  else's token, since a document with four identities in it answers "which comes
  first" and not "who is asking".
  **And the funnel being reached is still not the whole chain: `ldap.autocreateUsers`
  was `false` in all three `env/*.js` files**, which beats its default, so no
  protocol seeded a directory entry anywhere any of them was loaded — while
  `config.js`'s own description for it described a BIND behaviour that has never
  existed, the default said `false` where four documents said ON, the `bool`
  coercion turned an unrecognised spelling into `false` rather than the default,
  and `tests/api_ldap.js` SKIPPED its own check with a warning whenever it found
  the feature off. An appconfig value is the last word; a default nobody reaches
  is not a default, and a test that opts out when its subject is disabled is how
  a setting stays wrong for as long as that one did.
  Its `/admin/groups` page is the one page here that reports the DIRECTORY rather
  than what this service has issued, and the difference between the two lists is
  the thing to keep straight: the directory holds an entry for whoever somebody
  wrote one for — the three people it seeds at startup included — while
  `/admin/users` holds whoever has actually presented a credential. So a member
  row links to that page only for somebody this service has seen authenticate and
  is marked *never here* otherwise; a link drawn unconditionally would usually
  land on "nothing here has authenticated as alice", which reads as a broken link
  rather than as the answer it is. See rule 6 for the rest of it.
* **WS-Federation's `wauth` is refused rather than faked.** A relying party demanding
  multi-factor against a password-only session gets an error and two ways forward, not
  an assertion claiming a second factor that did not happen. It is the one thing in
  this profile that could trivially have been faked, and faking it would have taught a
  relying party something false about how a person signed in. Likewise `wreqptr` is
  never dereferenced: fetching a URL handed over in a query parameter is a
  server-side request forgery with a specification citation attached.
