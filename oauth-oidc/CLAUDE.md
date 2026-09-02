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
   warns about — /admin/oauth2 would report the mode as on while every
   authorization response still went out over plain HTTP.

   **RESTART-ONLY FOR THE PROCESS; A TRUST REALM MAY CARRY IT.** That is the
   whole of the `realmRuntime` marker, and `oauth2.rfc9700` is the only row in
   `config.js` that has it. The paragraph above is an argument about a BOUND
   SOCKET, and a realm has none — it answers on the port this process already
   opened, in the scheme that port was opened in — so the reason does not reach
   it, and `enabled()` here reads the setting per request through the realm
   layer exactly as every runtime row is read. One process therefore serves both
   passes: permissive at `/oauth2/authorize`, compliant at
   `/realm/<id>/oauth2/authorize`, with their own issuers, keys, codes and
   tokens. NOTHING IN THIS MODULE WAS EDITED FOR THAT — it is `config.value()`
   consulting the ambient realm, which is the property `common/CLAUDE.md` argues
   the whole realm design rests on.

   What a realm does not bring is a SCHEME, and `mainPortIsTls()` is where that
   shows: it reads `global.https`, which is a property of the process. A
   compliant realm on a plain-HTTP service enforces every check in
   `REQUIREMENTS` and still publishes `http://` endpoints — the combination
   `global.https` exists to make settable both ways — and it is PUBLISHED rather
   than hidden, because those four deployment rows come back `no` instead of
   `deployment` and `GET /oauth2/rfc9700` names the scheme. A stack that wants
   the compliant pass over HTTPS turns `global.https` on for the whole process
   and leaves the mode to the realm.

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

   **`resource` IS READ FOR EVERY GRANT, and it was read for two until
   2026-08-26.** Section 2 puts the parameter on *a token request* — the grant
   types RFC 6749 defines and the extensions built on them, not a chosen pair.
   Only `authorization_code` and `refresh_token` parsed it, because only they
   have something to NARROW, and the other four IGNORED IT SILENTLY: a
   `client_credentials` request asking for `https://apigw1.example.com` got
   `<base>/resource` and no error, so the restriction the client believed it had
   was never there. It is parsed ONCE now, above every grant in
   `tokenEndpoint()`, for the reason the DPoP check above it is where it is — a
   malformed `resource` is malformed whatever is being asked for. The two
   narrowing RULES stay per grant, because they are the half that depends on
   what came before; the four direct grants have no earlier decision for a rule
   to be about, and inventing one would refuse the only request they can make.

   **THE REPETITION WAS A SECOND HOLE UNDER THE FIRST.** `helpers.parseBody()`
   builds a plain object, so `resource=a&resource=b` arrived as `b` and
   `parseResourceIndicators()` — written to accept an array since the day it was
   added — could never be handed one. `bodyValues()` in `helpers.js` reads the
   repetition from the raw body, and `parseBody()` is deliberately NOT changed:
   sixty-odd call sites across fourteen modules read that object with
   `String(body.x)`. `admin-ui/admin.js`'s `listField()` is the same function
   written first, for the console's checkbox columns; the two are deliberately
   identical in shape so that folding them is a one-line delegation, which has
   to happen in THAT file because it requires this one (rule 5).

   **AND THE TOKEN EXCHANGE HAD BOTH BUGS AT ONCE.** `body.audience ||
   body.resource` discarded the resource whenever both were sent — RFC 8693
   section 2.1 says outright that they MAY be used together — and never
   validated it, so a fragment or an array went straight into `aud`. They are
   unioned now, with the resources read through the shared parse. `audience` is
   NOT put through it: section 2.1 calls it a *logical name*, which is not
   required to be a URI. Audiences come FIRST in the union, and that ordering is
   the one compatibility decision here rather than a reading of the RFC — order
   means nothing in an `aud` array, but the delegation act files an exchange
   against ONE target and `audience` winning is what it did before.

   **AND A SCOPE THAT NAMES ANOTHER APPLICATION IS AN AUDIENCE TOO — added
   2026-08-26, and it is the mechanism clients ACTUALLY use.** RFC 8707 above is
   how a client SHOULD say which resource server a token is for; a scope list
   carrying the API's name (`scope=openid email profile apigw1`, no `resource`
   parameter anywhere) is how every real deployment of the pattern does it. So
   `audienceScopes()` in `oauth2.js` reads one: a scope value that is the
   `oauthClientId` of ANOTHER application in the registry becomes the `aud` and
   comes off the scope claim, and everything else is untouched. Four rules and
   each has a reason written above the function — the match is against
   `oauthClientId` and not the audience or the entry's `cn`; the audience is the
   scope value VERBATIM rather than that application's `oauthAudience`; a
   spec-defined scope is never an audience whatever the registry says (nothing
   stops somebody registering a client called `profile`); and the client's own
   client_id is skipped.

   **TWO CONSEQUENCES ARE THE INTERESTING PART, AND BOTH WERE FOUND BY RUNNING
   IT.** The refresh token keeps the WHOLE scope while the access token loses
   the value that became its audience — the one place the two halves of a grant
   deliberately disagree, because section 2.2.2 binds a refresh token to what
   was AUTHORIZED and `oauth2_bcp.js`'s `refresh-not-wider-than-grant` compares
   a refresh request against it, so stripping it there refuses a client that
   refreshes with the scope list it originally sent. And an `openid` token gets
   the default audience APPENDED beside the derived one
   (`withOwnResource()`), because `audienceRefusal()` in `dpop.js` refuses a
   token addressed elsewhere and `/oauth2/userinfo` is one of the endpoints it
   guards: without it, the exact request this feature was written for produced a
   token that could not call UserInfo. RFC 8707's `resource` is deliberately NOT
   given that — a client that sent it narrowed its token on purpose, and a
   client that wrote a scope did not ask for anything of the sort.

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
setting changed at runtime through `/admin/oauth2` — varies the METADATA, and
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
  captured at require time is the one thing a runtime override cannot change, and
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

## THE USERINFO ENDPOINT HAS FOUR LAYERS AND A CLIENT CONTROLS ONE OF THEM

Since 2026-08-26. It was `sub` plus whatever section 5.4's scope asked for, and a
reader who still has that picture has the one this endpoint had before either of
the two things below existed.

**A CUSTOM CLAIM SET OF ITS OWN — `/admin/userinfo-claims`.** The fifth set in
`admin_stats.js`, configured exactly like the four beside it: typed claims,
ticked LDAP attribute types read off `ou=users`, and the groups claim. What
makes it worth having SEPARATELY from the ID Token's set rather than being one
list under two names is the one property no issued artefact has — **this
response is built on every call**, so a claim added there reaches a client that
signed in an hour ago and has done nothing since, where a claim added to the ID
Token set is invisible until the next sign-in. That is the difference the
console page is built around and the reason it is the one claims page with no
"nothing already issued changes" warning on it.

It carries `kind: 'userinfo'` rather than `kind: 'jwt'`, and `kind` answers
exactly one question — which page and which `/admin-api` resource carries the
set. `'jwt'` would have put it on `/admin/claims` automatically, which is the
accident `JWT_CLAIM_SET_IDS` being derived exists to prevent in the other
direction. **`SAML_CLAIM_SET_IDS` had to stop being `kind !== 'jwt'` in the same
change**: a list derived by exclusion is derived from what existed when it was
written, and that spelling would have swept the new set onto
`/admin/saml-attributes` with nothing failing anywhere.

**THE `claims` REQUEST PARAMETER — OpenID Connect Core section 5.5**, and
`claims_parameter_supported` says `true` where it said `false`. A client names
individual claims in the `userinfo` (or `id_token`) member; this server parses
it, **refuses a malformed one at the AUTHORIZATION endpoint** with
`invalid_request` — the last point at which the client is still being talked to,
the same reasoning that puts RFC 8707's `resource` refusal there — carries it on
the authorization code and **inside the access token** as the `claims` claim, and
answers it by resolving each name against the LDAP attribute catalogue.

Riding in the token is the same decision `authorization_details` records and for
the same reason: the UserInfo endpoint sees the token and nothing else — no
code, no session, no request record — so a side table keyed by `jti` would have
to be swept and would not survive a refresh. `claims` is on
`RESERVED_JWT_CLAIMS` so that no web form can decide what a request asked for,
and the refresh grant carries it forward so that a renewal cannot narrow the
grant any more than it can widen it.

**THE FOUR LAYERS, LATER WINNING**, written out at the merge in `oauth2.js`
because that is where somebody debugging an unexpected member is looking:

1. the configured `userinfo` set — what everybody gets;
2. section 5.4's scope-driven claims (`profile`, `email`);
3. section 5.5's individually requested claims, read off `ou=users`;
4. `sub`, assigned last and unconditionally (5.3.2 — a client MUST check it
   against the ID Token's).

**Layer 3 beating layer 2 is the one choice here that is not obvious.** A scope
asks for a CATEGORY and a claims request names a CLAIM, so answering
`{"email":null}` with the invented persona value while the entry holds a real
`mail` would defeat the only reason the feature is worth having. Nothing in
layer 3 can reach a structural claim, and that is by construction rather than by
a guard: every name it resolves comes from the attribute catalogue or from
`PERSONA_CLAIMS`, and no member of either is `iss`, `sub`, `aud`, `exp` or
`nonce`.

**`essential`, `value` and `values` are CARRIED AND NOT ENFORCED**, which is the
honest reading of section 5.5.1 rather than a shortfall. That section says a
server MUST NOT return an error because a requested claim is unavailable, so an
essential claim this service cannot produce is absent and logged at warn level.
`value` and `values` could be satisfied by echoing the asked-for value back and
deliberately are not: everything this service says about a person comes from the
directory or from the invented persona, and a UserInfo response that agreed with
whatever a client asked it to assert would be the one surface here that cannot
be used to test anything. The mismatch is reported instead.

**NON-SPEC: the endpoint also takes a claims request on the request itself.**
Section 5.3.1 defines no request parameters at all. `?claims={json}` and a
repeated `?claim=name` are accepted anyway, on GET and on a form-encoded POST,
because exercising section 5.5 through the specified route means running a whole
authorization flow per variation and a mock nobody can poke is a mock nobody
uses. It is a **union** with what the access token carries and can never take a
claim away from it — what the client was authorized for is what the token says —
and a malformed one is refused `invalid_request` rather than ignored, because
ignoring a debugging parameter that was typed wrong produces exactly the
response a parameter that was never sent produces.

**`claims_supported` was NOT extended to cover any of it, and the absence is the
answer.** That member lists what the protocol itself puts in an ID Token. It
cannot honestly list what `/admin/userinfo-claims` has been configured to add
nor the whole attribute catalogue section 5.5 can reach, because this document
is fetched and cached by clients and both of those change at runtime from a
console page — a list that tracked them would be stale in every cache the moment
somebody ticked a box. `GET /admin-api/userinfo-claims` is the live answer and
names every claim a request may ask for.

---

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

---

## RFC 8693 IS TWO MECHANISMS, AND THE TOKEN ENDPOINT RECORDS THEM AS TWO

Section 1.1 is explicit that impersonation and delegation are different things,
and `/admin/delegation` is where the difference is visible:

* **no `actor_token` — IMPERSONATION.** What comes back is a token for the
  subject with nothing on it about who exchanged it. The resource server cannot
  tell, and neither can anybody reading the token later, which makes that page
  the only place the fact will ever exist.
* **an `actor_token` — DELEGATION (§4.1).** What comes back carries `act` naming
  the actor, and `act` NESTS: a second hop appears underneath the first rather
  than replacing it.

The act is recorded through `../common/delegation.js` (rule 3l) AFTER `issue()`,
so the row can name the token that came out. Two details are worth keeping if it
is reworked. The `jti` is read back off the signed access token with
`jsonFromB64u()` — the same reader the `actor_token` is decoded with twelve lines
above — rather than by changing the return type of the one helper every grant
here mints through. And the INTERMEDIARY of the chain is deliberately both an
identity and an application: the client performing the exchange is the
application, always, and the actor named in the `actor_token` is the identity,
which only a delegation has. An impersonation therefore draws a chain whose
middle is an application and nobody, which is exactly what happened.

**THE TARGET IS RESOLVED THROUGH THE APPLICATIONS REGISTRY, and it is the one
place in this service that reads `oauthAudience`.** An `audience` names a
RESOURCE — `https://esb1.example.com` — and that registry is keyed by the
identifier an application PRESENTS, which for an OAuth client is its client_id.
Filing the act under the raw audience therefore draws a box on
`/admin/delegation/map` that nothing else in the picture mentions, and a
two-hop chain through a middle tier comes out as two unconnected halves: the URL
the first hop reached and the client_id the second hop exchanged AS are one
application under two names. So `applications.forAudience()` is asked first and
the application's own identifier is what the row carries, with the audience that
was actually requested kept in the sentence beside it — the raw string is a fact
about the request and must not be lost to a resolution. **Nothing is refused:**
an audience nobody has registered resolves to null and is recorded verbatim,
exactly as it was before this existed.

**Nothing authorizes either of them here**, and the row says so where a Kerberos
row names an attribute. `may_act` is the claim a real deployment would use for
it; this service neither issues nor reads one.

---

3n. **`frontchannel_logout.js` is a library (rule 3) and it exists because THREE
   sign-outs have to fan out identically.** It registers no route, so its place
   in the require order does not matter, and it requires `helpers.js`,
   `config.js`, `app.js` and `applications.js` — none of which requires it back.

   It holds four things: which clients a session signed into
   (`noteClient()`, written on the session at `issueAuthorizationResponse()`, the
   one point where both the client and the session are in scope), the
   notification URLs (`notificationsFor()`), the CSP the iframes need
   (`contentSecurityPolicyFor()`), and the block of HTML (`render()`).

   **It is a file of its own rather than code in `oauth2.js` for one reason:**
   `/oauth2/logout`, the protocol-independent `/logout` and the console all have
   to render the SAME fan-out, and `logout/logout.js` reaching into `oauth2.js`
   for it would be a require this file makes unnecessary — `oauth2.js` requires
   THIS, so the other direction would be a cycle.

   **`sid` REVERSED A DOCUMENTED DECISION AND THE REVERSAL IS THE INTERESTING
   PART.** `admin_stats.js` used to say, in as many words, that no token this
   service issues carries a session identifier and that inventing one to make a
   console page easier would change what every client receives. That was right,
   and the reasoning is kept: **a claim is added because a SPECIFICATION needs
   it, not because something here would find it convenient.** Front-Channel
   Logout section 3 is that specification — an RP holding two sessions in one
   browser cannot tell which ended without `sid`. So the ID Token carries it when
   it was issued ON a session, and `oauth2.frontchannelLogout` turns the claim,
   the two metadata members and the fan-out off together, in one place. Three
   switches would let somebody advertise a capability whose claim is off, which
   is a discovery document that lies.

   **THE IFRAMES ARE THE SIXTH CSP RELAXATION AND THE NARROWEST.** `frame-src`
   falls back from `default-src 'none'`, so an iframe to another origin is
   blocked — correct everywhere else here. The sign-out page relaxes it to THE
   ORIGINS IT IS ACTUALLY LOADING, enumerated from the URIs, rather than to `*`.
   It goes through `app.contentSecurityPolicy()` like every other relaxation, so
   `frame-ancestors` and `base-uri` cannot be dropped by it. A URI this runtime
   cannot parse is left OUT of the policy rather than widening it: the iframe
   then does not load, which is the safe direction, and the row beside it still
   shows the URL.

   **EVERY URL IS PRINTED AS A LINK BESIDE ITS IFRAME**, because section 5 says
   the provider cannot know whether a notification succeeded. A dead relying
   party, a certificate the browser will not accept and a mistyped URI all look
   exactly like success; the link is the only thing that turns "nothing
   happened" into something a person can click. Same decision `wsfed.js` made
   about its cleanup pings.

   **`/oauth2/logout` CAN NOW ANSWER WITH A PAGE INSTEAD OF A REDIRECT**, and
   only when there is a fan-out to perform: a 302 to `post_logout_redirect_uri`
   abandons the document before any iframe loads. **Where no client on the
   session registered a logout URI — every deployment that has not asked for
   this — the redirect happens exactly as it always did.** The behaviour of an
   existing caller must not turn on a feature it never opted into.

   **BACK-CHANNEL LOGOUT IS A DIFFERENT SPECIFICATION AND IS NOT IMPLEMENTED.**
   It is a signed Logout Token POSTed server-to-server, which needs this service
   to reach the RP's network rather than the browser's. `backchannel_logout_supported`
   stays `false`; advertising it because front-channel arrived would be the
   overstatement that document exists not to make.

   `outstandingCodesFor()` / `dropCode()` are exported from `oauth2.js` for the
   same feature and are FUNCTIONS rather than the `authzCodes` Map, for the
   reason `registeredClients` is no longer exported: a caller holding the Map
   would be a second place that decides what a code is, and would miss
   `redeemedCodes` beside it — so a signed-out code would still answer a REPEAT
   of the token request with the tokens it already got, and a sign-out that hands
   back a token set is not a sign-out.

---

## A scope may name a PERMISSION, not just an application, and the token says both halves

Added 2026-09-01. `audienceScopes()` already turned a scope value that is
another application's `client_id` into the access token's `aud` — the rule
`scope-named-audience` describes, one section up. This is that rule one step
more precise, and it is the OAuth half of the delegated-permission register in
`common/app_permissions.js`.

A **resource** application exposes an API: a base URI
(`oauthPermissionBaseUri`) and a list of permission names (`oauthPermission`),
joined into an identifier — `https://example.com/` and `write` make
`https://example.com/write`. A client sends that whole string as an ordinary
scope, and:

```
scope=openid https://example.com/write https://example.com/read
   ->   "aud":   "https://example.com/"
        "scope": "openid read write"
```

**THE BASE URI IS THE AUDIENCE AND THE NAME IS THE SCOPE**, which is Microsoft
Entra ID's behaviour exactly and is what a resource server wants: check `aud`
once, then read bare permission names.

**IT IS THE ONE EXCEPTION TO "THE AUDIENCE IS THE SCOPE VALUE VERBATIM"**, and
that rule's own header is where the difference is argued. A permission is a
COMPOSITE identifier this service composed out of two facts on an entry, so
taking the whole string as the audience would address the token to a PERMISSION
rather than to the API — and nothing would ever be able to check that `aud`
against anything, because no application answers to `https://example.com/write`.

**THE PERMISSION LOOKUP IS TRIED BEFORE THE CLIENT_ID ONE**, because it is the
more specific of the two: a permission identifier is a whole URI with a name on
the end and a `client_id` is a bare word, so they cannot collide in practice —
and where a registration ever managed to make them collide, the permission is
what a client that wrote a URI meant.

**THE MATCH IS EXACT AGAINST THE COMPOSED IDENTIFIER, NEVER A PREFIX TEST ON
THE BASE.** A prefix test would match `https://example.com/anything` against a
registered base whether or not that permission was ever defined — which is
precisely the case this feature exists to distinguish, and it would let any
client address a token to anybody's API by inventing a word after their base
URI. A scope naming no defined permission is an ordinary scope and is granted as
everything else here is.

### `permissionRefusal()` — the one refusal, and where it is made

**IT IS NOT PART OF RFC 9700 MODE AND MUST NEVER BE FOLDED INTO IT.** Every
check in `oauth2_bcp.js` cites a section of a published Best Current Practice; a
delegated permission cites nothing, because no RFC says an authorization server
must have one. It is a product's design rather than a standard, and putting it
behind `oauth2.rfc9700` would make `GET /oauth2/rfc9700` advertise a requirement
no document contains. It has a setting of its own —
`oauth2.delegatedPermissionsEnforced`, off by default, runtime, and settable on
a realm.

**IT IS SEPARATE FROM `audienceScopes()` FOR THE REASON THAT KEEPS `bcp.js` OUT
OF THE MINTING PATH.** That function TRANSLATES and is called from six grants; a
translation that also decided policy would make the decision six times, and one
of them would eventually get it wrong.

**IT IS CALLED IN THE TWO PLACES A CLIENT ASKS.** The AUTHORIZATION endpoint,
beside the `resource` and `claims` refusals and for their stated reason — it is
the last point at which the client is still being talked to — answering
`invalid_scope`, which is RFC 6749 section 4.1.2.1's own code for a scope that
exceeds what this client may have, so no code had to be invented. And the TOKEN
endpoint, once above the grant switch beside `parseResourceIndicators()`, for
the grants that never pass through the authorization endpoint: client
credentials, the password grant, the token exchange, and a refresh naming a
scope explicitly.

**A GRANT ALREADY ISSUED IS NEVER RE-JUDGED**, which is why the token endpoint
reads `body.scope` and nothing else. An authorization code carries what was
authorized and was judged at the authorization endpoint; a refresh with no
`scope` carries its grant's. That is the same rule federation follows about not
re-checking a person after the session exists, and it is what makes the setting
safe to turn on while something is running.

### The token endpoint now records `oauthScope`, and that is not cosmetic

`seen()` at the token endpoint writes the scope the request carried, where it
carries one. Until 2026-09-01 only the authorization endpoint did — so for the
three grants that never go near it (client credentials, the password grant, the
pre-authorized code grant) `oauthScope` on the client's entry stayed empty
however often it asked. The visible symptom was on `/admin/delegation`, whose
`asked for` column reads that attribute: a client spending a permission every
minute was reported as never having asked for it. It is CONDITIONAL on the body
carrying a scope, because an `authorization_code` redemption does not (the grant
does) and writing an empty value would record that the client asked for nothing.
