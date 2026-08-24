# oauth-oidc/

A full OAuth 2.0 authorization server and OpenID Connect provider, plus the four
libraries that decide things on its behalf.

| File | What it is |
|---|---|
| `oauth2.js` | Every endpoint. The only module here that touches `res`. |
| `oauth2_bcp.js` | RFC 9700, the Security BCP, as a table of requirements with a check citing each. A MODE. |
| `client_auth.js` | All six token-endpoint authentication methods. The mechanics half of section 2.5. |
| `dpop.js` | RFC 9449, and `presentedAccessToken()` — the Bearer-or-DPoP check four protected endpoints share. |
| `mtls.js` | RFC 8705 certificate-bound tokens. The other half of section 2.2. |
| `authorization_servers.js` | Makes one process BE several authorization servers, selected by a path component. |

**Everything but `oauth2.js` registers nothing.** They are libraries in the sense
rule 3 of the root `CLAUDE.md` means: they require only `../common` and each
other, so they cannot join a cycle and their position in the require order is not
a position at all. The split throughout is the same one: **a library decides and
`oauth2.js` answers.** What a refusal LOOKS like is protocol knowledge and stays
in the one module that has a response object.

`dpop.js` is where `presentedAccessToken()` lives rather than
`../oid4vc/vc_issuer.js`, where it was written, because the fourth caller is in
`oauth2.js` — which `vc_issuer.js` cannot be required from without building a
cycle or moving OID4VCI ahead of OAuth2 in the route order.

Two ordering facts about this directory are in the root `CLAUDE.md` because they
are facts about `server.js`: `ws-federation/wsfed.js` must be required AFTER
`oauth2.js`, and so must `admin-ui/admin.js`.

---

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


---

## `signed_metadata` is signed once a minute, not once a request

`signedMetadata()` in `oauth2.js` caches, and both discovery documents go
through it — the RFC 8414 one and the OpenID Provider Configuration. Discovery
is the most-fetched endpoint here (every client reads it first) and signing it
per request made it the slowest read-only endpoint in the service by a factor
of five; caching took it from 762 to 8,006 requests a second.

**It is the one artifact here where re-signing per request buys nothing.** RFC
8414 section 2.1 describes `signed_metadata` as something the issuer PUBLISHES:
no nonce, no `jti`, nothing bound to the caller, so two clients a second apart
are entitled to byte-identical documents. Everything that can vary — the base
URL the request arrived on, the authorization-server profile it selected, any
setting changed at runtime through `/admin/config` — varies the METADATA, and
**the metadata is the cache key**, so runtime settability is untouched: a
document differing by one member is a different key and is signed afresh.

The entry is held for a minute against a token that lives an hour, and that gap
is the point — a caller must never be handed a signature about to expire. The
map is capped because the key includes a base URL that comes off the Host
header.

## The three lifetimes and the skew are SETTINGS now, and one default changed

`ACCESS_TOKEN_TTL` (an hour), `REFRESH_TOKEN_TTL` (thirty days) and the ID
Token's reuse of the first were module-level `const`s in `oauth2.js` until
2026-08-24. They are four `config.js` rows read through four one-line functions
— `accessTokenTtl()`, `idTokenTtl()`, `refreshTokenTtl()`, `tokenClockSkew()` —
and `/admin/token-lifetimes` is the console page over them. Five things about
that, and the first is the one to read before upgrading anything that points at
this service.

* **THE REFRESH DEFAULT IS TWENTY-FOUR HOURS AND WAS THIRTY DAYS.** A client
  holding a refresh token across a long test run now meets an ordinary
  `invalid_grant` where it did not, and `oauth2.refreshTokenTtlS: 2592000` is
  exactly the old behaviour. Every sentence in this repository that asserted
  "thirty days" about a refresh token was CHANGED rather than left to be
  discovered — `oauth2_bcp.js`'s requirement table and its section 2.2.2 header,
  `oauth2.js`'s rotation comment, `config.js`'s `refreshIdleSeconds` row and
  README.md. A default that moves while five documents still name the old number
  is worse than either number.
* **THE ACCESS TOKEN AND THE ID TOKEN NO LONGER SHARE A NUMBER.** They shared a
  constant because an hour suited both, which is not the same as their being one
  setting: an ID Token is consumed once at sign-in by the client and an access
  token is presented to a resource server, and a client that treats the ID Token
  as a session is a defect this mock should be able to produce on demand. Give
  the two different lifetimes and watch which one the client notices.
* **A `const` WOULD HAVE BEEN THE BUG.** This is `common/CLAUDE.md`'s rule read
  literally — a runtime setting must be READ WHERE IT IS USED — and these are
  the settings where it bites hardest, because "make it a minute so I can watch
  my client refresh" is why somebody points a client at a mock at all. A value
  captured at require time is the one thing `/admin/config` cannot change, and
  it fails in the direction that looks like the console is broken.
* **THE GRANULARITY IS THIRTY SECONDS AND THE FLOOR IS ONE STEP**, declared as
  `min`/`max`/`step` on the row rather than checked at a call site — see
  `common/CLAUDE.md`, since the `int` type grew those for these four. It is a
  decision about what the settings are FOR: below half a minute a token expires
  between the response being written and the client reading it, and the client
  author debugs their own code for an hour. `max` is thirty days on all three
  because a ceiling that made the OLD default unreachable would be a setting
  that cannot be put back the way it was.
* **`oauth2_bcp.js`'s FAMILY WINDOW FOLLOWS THE SETTING.** `REFRESH_TTL_MS` was
  a fixed thirty days with a comment saying it matched `REFRESH_TOKEN_TTL`; it
  is `refreshFamilyWindowMs()` now, because a fixed number would have been a
  comment claiming a match nothing kept. It has a FLOOR OF ONE HOUR: the window
  is granted when a token is minted, so raising the lifetime afterwards could
  otherwise leave a family forgotten while its tokens are still presentable —
  a check silently not made rather than a false refusal, which is the safe
  direction and still not one to arrive at by accident.

## `oauth2.clockSkewS` is applied at EVERY read-back, and that is the whole point

The allowance passed to `jwt.verify()` as `clockTolerance` wherever this service
reads back a token it signed. **Six places take it and a seventh is not in this
directory**: `tokenFailure()`, the refresh grant, token exchange,
`/oauth2/introspect`, `/oauth2/revoke`, `dpop.js`'s `presentedAccessToken()` —
the check the four protected endpoints share — and `common/admin_stats.js`'s
`tokenStateOf()`, which is what every console screen reports state from.

**A verify that did not take it would be a second, stricter opinion about what
"expired" means, reachable only through whichever endpoint forgot.** The symptom
is a token that introspects active and is refused at the refresh grant thirty
seconds before it should be, which reads as a client bug from every side. That
is also why the console reads the same setting: a page saying "valid" about a
token `/oauth2/introspect` calls inactive is worse than a page with no state
column, because it is believed.

**It is NOT `oauth2.clientAssertionSkewS` and must not be merged with it.** That
one is how far out a CLIENT'S assertion may be under RFC 7523 — somebody else's
clock, on a credential this service did not mint. This one is how far out THIS
service's clock may be when reading its own. They move for different reasons,
and a deployment wanting a strict assertion check and a forgiving expiry reading
has to be able to say so. Capped at 300, which is what `krb5.clockSkew` allows,
because a window wider than that has stopped being a tolerance.

**`dpop.js` requires `config.js` for it and is still a leaf** — that module
requires nothing from this repository, so the no-cycle property rule 3 asserts
about `dpop.js` is unchanged.

## What this half deliberately does not do

* **It is permissive on purpose, and it can be told not to be.** Everything in this
  list is the default; `oauth2.rfc9700` turns the OAuth 2.0 / OIDC authorization
  flow into an RFC 9700-conforming one (see rule 3f and `oauth2_bcp.js`) and, with
  it, **turns the main port into an HTTPS listener** on the certificate 8443, 9443
  and LDAPS 636 already share — so there is then no plain listener in this process
  and `/tls/trust` has to be bootstrapped with verification off. The flag is OFF by
  default, changes nothing until it is set, and is RESTART-ONLY because of that
  socket. What it does and does not enforce is published at `GET /oauth2/rfc9700`
  rather than left to be read out of the code. Nothing else here has such a mode.
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
