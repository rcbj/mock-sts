# scim/

SCIM 2.0 (RFC 7642/7643/7644) — a provisioning endpoint at `/scim/v2` that writes
into the LDAP directory, entry for entry, with **no store of its own**.

| File | What it is |
|---|---|
| `scim.js` | The seventeen routes, and the scimmy resources behind them. |
| `scim_auth.js` | Who is asking. The only authentication this service ENFORCES anywhere. |
| `scim_map.js` | Which LDAP attribute each SCIM member is, in both directions. |

6a. **`scim.js` must stay after `ldap_server.js`, and the interesting thing
   about it is that it is a PLAIN REQUIRE where five things in that file are
   inverted hooks.** It requires that module directly, for the twelve functions
   that make `ou=users` and `ou=groups` a store, and requiring it from anywhere
   EARLIER would pull every `/ldap` route into the express router at that point.
   Rule 3e says a slot is what you reach for when a require would close a cycle
   or move a route, and to test a new proposal BOTH WAYS ROUND before adding one.
   This proposal fails that test both ways — there is no cycle (`ldap_server.js`
   knows nothing about SCIM) and no route moves (the `/ldap` routes are already
   registered by the time this file is read) — so it is a require. It must still
   come before `sts_metadata.js`, which is last for everybody, and it starts
   NOTHING: it is HTTP all the way down, so requiring it is the whole of its
   installation.

   **IT PROVISIONS INTO THE DIRECTORY AND THERE IS NO SECOND STORE.** A
   `POST /scim/v2/Users` and an `ldapadd` create the same entry, a SCIM PATCH and
   an `ldapmodify` change it the same way, and a person provisioned over SCIM
   appears on `/admin/users`, is swept for credential-claim attributes, and lands
   in whatever group a client puts them in. That is the one-store rule (rule 5)
   with a fourth door, and it is what makes the feature worth having: the
   interesting property of a SCIM endpoint is that what it writes is what
   everything else then reads.

   **AND THE FOURTH DOOR CALLS THE SAME FUNCTION THE SECOND AND THIRD DO.** A
   SCIM create goes through `createUser()` — the one the console's form and
   `POST /admin-api/users/create` already share — so there is ONE reading of what
   creating a person means at every door but `ldapadd`. This module builds no DN,
   runs no uniqueness scan and applies no name rule of its own; it translates
   that function's refusals into a status and a `scimType`, which is the only
   part a SCIM client needs and the only part `createUser()` cannot know.

   **It was written the other way first and each of the three home-made rules was
   weaker**, which is why this is worth stating rather than assuming: the DN was
   built as `uid=<name>,ou=users` directly, skipping `namePlan()`'s FOLD onto an
   entry that is already this person's under another naming attribute — two
   objects for one person, the exact thing that fold exists to prevent; the
   uniqueness scan compared the `uid` ATTRIBUTE only, so somebody whose entry a
   client certificate had named by `cn` was invisible to it and SCIM created them
   twice; and the name-syntax list had already drifted from `createUser()`'s by
   one character. `nameUsableInDn()` and `normalizeDn()` are exported from
   `ldap_server.js` for the same reason — a group create has no `createUser()` to
   defer to, so the CHECK is shared even though the door is not.

   **ONE ACT IS ONE AUDIT ROW.** `createUser()` writes its own `user.create`, and
   it now takes a `protocol` so that row says SCIM rather than LDAP; `scim.js`
   therefore records only the update and the delete. A row from both would be one
   act counted twice at the SAME layer, which is rule 3c's warning — unlike the
   HTTP call row `app.js` writes, which is a different layer and is meant to be
   there.

   **IT IS THE FIFTEENTH PROTOCOL FAMILY, AND IT BECAME THE FIFTEENTH
   AUTHENTICATION ONE WHEN THESE ENDPOINTS STARTED REQUIRING A CREDENTIAL** —
   which is why "fourteen" became fifteen throughout this file and README.md —
   and then sixteen, when the SPIRE Server API started requiring an X509-SVID
   (rule 3k). Both counts mean "families reaching `recordAuthentication()`".
   The change is narrower than it sounds and both halves have to be kept
   straight. Three of the schemes `scim_auth.js` offers present a credential on
   EVERY REQUEST (Basic, Digest, HOBA), so accepting one is an authentication
   like a WS-Trust UsernameToken and reaches `recordAuthentication()`; the other
   three do NOT, because each continues an authentication already recorded where
   it was accepted — a token when it was issued, a cookie when its session
   began, a certificate once per CONNECTION, which is a decision
   `tls_server.js` made deliberately and which counting per request here would
   undo from the other end.

   **WHAT DID NOT CHANGE IS THAT BEING PROVISIONED IS NOT AUTHENTICATING.** The
   person a SCIM client CREATES has signed in to nothing, so they still have a
   directory entry with `origin: scim` and no row on `/admin/users` until they
   turn up and authenticate. That is the distinction this service draws
   everywhere else between an identity being RECORDED and one having
   AUTHENTICATED, and it survives intact; do not add a `recordAuthentication()`
   call for the provisioned person to make the two pages agree.


6a-ii. **`scim_auth.js` IS WHO IS ASKING AT `/scim/v2`, AND IT IS THE ONLY
   AUTHENTICATION THIS SERVICE ENFORCES ANYWHERE.** A library like `scim_map.js`
   — it registers nothing and NEVER TOUCHES `res`: it decides and `scim.js`
   answers in SCIM's own error shape, the same split `oauth2_bcp.js` has with
   `oauth2.js`. It requires `helpers.js`, `config.js`, `dpop.js`, `mtls.js`,
   `admin_stats.js`, `audit.js` by way of those, `authn.js`, `tls_server.js` and
   `ldap_server.js`; the last three register routes, and requiring them is safe
   for rule 3e's reason applied rather than assumed — `scim.js` is the only
   thing that requires this file and it already sits after all three in
   `server.js`, so there is no cycle and no route moves. Eight things:

   **THE TABLE IS THE MODULE.** `SCHEMES` is the single source for the
   WWW-Authenticate challenge, for `authenticationSchemes` in the
   ServiceProviderConfig, for `GET /scim`, and for `/admin/scim`'s per-scheme
   counters. A scheme turned off vanishes from the challenge and from the
   published document TOGETHER, which is the property that matters: a client
   reads a published scheme as a promise and a challenge as an instruction.
   **Do not add a scheme RFC 7644 section 2 does not name** — the temptation is
   an API key in a header, which is what most real integrations use, is in no
   specification, and would interoperate with nothing.

   **RFC 7644 SECTION 2 HAS EXACTLY TWO NORMATIVE SENTENCES** and both are
   implemented rather than approximated: a provider SHALL indicate its schemes
   in `WWW-Authenticate` (every 401 carries one header per offered scheme), and
   a provider MUST be able to map an authenticated client to an access control
   policy (two OAuth scopes, with every other scheme granting both). The section
   NAMES six schemes and all six are here. It defines no credential of its own.

   **THE BEARER CHECK IS `dpop.presentedAccessToken()` THROUGH A CAPTURING
   RESPONSE.** That function is the single check `/oauth2/userinfo` and the
   three credential endpoints share and it carries the DPoP proof and nonce
   handshake, the RFC 8705 certificate binding, the RFC 9700 query-string
   refusal and the audience check — so a fifth implementation was out of the
   question. What it will not do is speak SCIM: it ANSWERS, with an OAuth-shaped
   body. So it is handed a response object that records, and what it would have
   said is translated. THE HEADERS IT SET ARE KEPT VERBATIM, which is the part
   that matters — `DPoP-Nonce` and `use_dpop_nonce` are how a wallet learns to
   retry.

   **ONLY THE OAUTH SCHEMES CARRY SCOPES, AND THAT HAS A CONSEQUENCE WORTH
   STATING.** A caller who cannot get a scope can use Basic instead. Which is
   why every scheme has a switch of its own: a deployment exercising a client's
   scope handling turns the other five off. `scim:read` and `scim:write` do NOT
   imply one another, deliberately, so that a read-only provisioning credential
   is something this service can produce.

   **TWO SCHEMES REALLY VERIFY SOMETHING AND IT IS THE KERBEROS ARGUMENT BOTH
   TIMES.** Digest hashes the password into the response, so a server accepting
   anything would not be performing the exchange and the client's own digest
   code would go unexercised — hence any username, one shared password
   (`scim.digestPassword`). HOBA's signature is genuinely verified for the same
   reason; what is permissive there is the REGISTRATION, which is
   unauthenticated for the reason `POST /tls/trust` is — it is how a caller GETS
   a credential. Between them they make five negatives reachable that no
   permissive server can produce, including the one worth knowing: a replayed
   nonce count is refused WITHOUT `stale=true`, because `stale` means "your
   credential was fine, try again" and a replay is the opposite claim.

   **WHICH SCHEMES REACH THE AUTHENTICATION FUNNEL IS `recorded` ON THE ROW**,
   and the rule is the one this service applies everywhere: recorded at the
   moment a credential is ACCEPTED, never again while that act continues. See
   rule 6a above for the three and three.

   **THE DISCOVERY ENDPOINTS ARE OPEN BY DEFAULT** (`scim.authDiscovery`), which
   is `POST /tls/trust`'s bootstrapping argument: the ServiceProviderConfig is
   where a client READS which schemes exist, so demanding a credential to fetch
   it means a client must already know the answer to the question it is asking.

   **A CREDENTIAL THAT WAS PRESENTED AND FAILED IS ALWAYS A REFUSAL**, even with
   `scim.authRequired` off. A client testing its expired-token path must not get
   a 200 because the endpoint would also have accepted nobody.

   **THE ServiceProviderConfig PUBLISHES THREE SCHEMES scimmy CANNOT
   VALIDATE.** RFC 7643 section 5's five canonical `type` values do not cover
   RFC 7644 section 2's six schemes — there is none for a client certificate, a
   cookie or HOBA — and scimmy enforces the five, correctly. So the four
   canonical rows go through `SCIMMY.Config` and the other three are appended to
   the SERIALISED document by `scim.js`, from the same table. Note also that
   `authenticationSchemes` is the one scimmy property that is CUMULATIVE:
   `applyCapabilities()` resets it before setting it, or the array would grow by
   four every time somebody read the document.

   **THE ROUTES ARE REGISTERED ONE BY ONE AND NOT BEHIND `scimmy-routers`.** That
   package exists and would have done it in a line. It mounts an express
   `Router`, and `registeredRoutes()` in `sts_metadata.js` skips any layer with
   no `.route` — so every SCIM endpoint would have been INVISIBLE to the drift
   check, silently, which is the one thing that page exists to prevent. Its
   constructor also REQUIRES an authentication scheme and a handler, and what
   this service would have installed is a handler that accepts everything dressed
   as a check.

   **THE DEPENDENCY WAS WEIGHED THE OPPOSITE WAY FROM `swagger-ui-dist`.**
   `scimmy` is 735 KB unpacked with NO runtime dependencies, and it brings the
   RFC 7643 schema characteristics, the section 3.4.2.2 filter grammar and the
   section 3.5.2 PATCH path grammar — the last being where every hand-rolled SCIM
   server is subtly wrong, since `emails[type eq "work"].value` is a path and not
   a property name. TWO THINGS IT DOES NOT DO look as though it does.
   `Resource#read()` does NOT apply the filter it parsed — it hands the resource
   instance to the egress handler, so a handler ignoring `.filter` returns
   everybody for every query and looks correct until somebody filters. And
   `Filter#match()` THROWS on a nested attribute a resource lacks
   (`Object.entries(undefined)`), which for `emails.value co "…"` against anybody
   with no mail is the ordinary case; `toScimUser()` pads every multi-valued and
   complex member and `prune()` takes the padding off before the wire. Both are
   documented where they are worked around, the way `toSearchEntry()`'s ldapjs
   workaround is.

   **ANYTHING A HANDLER THROWS THAT IS NOT A `SCIMMY.Types.Error` COMES BACK AS A
   404.** `Resource#read()` and `#write()` catch and re-throw as "Resource not
   found", so an ordinary programming mistake inside an egress handler surfaces
   to the client as a missing user. `handle()` logs the original whole, which is
   the only thing that makes such a defect findable.


---

3d-iii. **`scim_map.js` is the FOURTH library over that catalogue's territory,
   and it is the only one of the four that is NOT a selection.** `vc_claims.js`
   says what a CREDENTIAL carries, `vc_verifier_config.js` what the Verifier ASKS
   FOR, `claim_attributes.js` which ATTRIBUTES a token carries, and each of those
   is a set of tick boxes. This says which LDAP attribute each SCIM MEMBER is, in
   both directions, and there is nothing to tick: RFC 7643 decides what a User
   carries, so the only question left is where each member is stored. That is a
   mapping, and a mapping is a table. It registers no route and requires
   `helpers.js` and `vc_claims.js`, neither of which requires it back.

   **THE CONVERSIONS ARE HERE RATHER THAN IN `scim.js` FOR ONE REASON**, and it
   is the route-order one: `admin.js` draws the mapping table on `/admin/scim`
   and must be able to require what it draws. A require from the console into
   `scim.js` would drag every `/scim` route — and, since that module requires
   `ldap_server.js`, every `/ldap` route — into the express router ahead of the
   console's own, and `/admin/sts-metadata` is built by walking that router. So there
   are two readers of two different halves: `scim.js` reads the CONVERSIONS on
   every request, `admin.js` reads the CATALOGUE to draw it.

   **NOTHING IN IT TOUCHES A DIRECTORY.** It is handed an entry object — the
   `{dn, origin, createdAt, modifiedAt, attributes}` shape `entryObject()`
   produces — and hands back a SCIM resource, or the reverse. The placement rules
   (where a person's entry goes, what counts as a group) stay in the one module
   that already owns them.

   **THE SPELLINGS ARE CHECKED AGAINST THE CATALOGUE, NOT COPIED FROM IT.**
   `checkSpellings()` runs at require time and WARNS where a row disagrees with
   `vc_claims.js` — the same rule `learnName()` follows, one module earlier, and
   able to name which of the two tables is wrong where that function could only
   report that a second spelling had turned up. Its two INVENTIONS,
   `scimActive` and `scimExternalId`, are merged into `CANONICAL_NAMES` through
   `learnName()` like every other name; they are a FIFTH source into that table,
   which is affordable only because the check exists.

   **FIVE DECISIONS IN IT ARE LOAD-BEARING and each is easy to undo.** The SCIM
   `id` IS THE ENTRY'S DN — RFC 7643 section 3.1 asks for an opaque
   server-assigned identifier and the DN already is one, where a `uid` is not
   unique in this tree and a synthesised id would be a stored second definition
   that goes stale on a rename; the cost, that a rename gives the same person a
   new id, is stated on the page rather than hidden. A PUT REPLACES ONLY WHAT IS
   INSIDE THE MAPPING'S WINDOW, because read strictly it would delete
   `schacDateOfBirth`, `authnMethod` and every `x509*` attribute the moment a
   client updated a phone number — facts SCIM never knew about and cannot
   restore. THREE ATTRIBUTES ARE DROPPED ON THE WAY THROUGH — `entryDN`,
   `createTimestamp`, `modifyTimestamp` — because none of them is really on the
   entry, and carrying them through WROTE `entryDN`, which is exactly the stored
   copy of the DN the synthesis exists to prevent. And A TYPE ON A MULTI-VALUED
   MEMBER IS SCIM'S IDEA: `telephoneNumber` and `mobile` are two attribute types
   and one SCIM member, so the type says which one a value came from and which
   one it goes to, and `primary` is emitted and never stored. FINALLY THE
   MAPPING IS TOTAL: `userName` is RFC 7643's one required User attribute and
   scimmy enforces it on the way OUT, so the entry a client certificate seeds —
   named `cn=<CN>,ou=users`, with no `uid` on it at all — made `GET /Users`
   answer 400 `Required attribute 'userName' is missing` for the WHOLE
   directory until somebody deleted it — a message naming an attribute and no
   entry, on a request that had nothing wrong with it. `toScimUser()` falls
   back to the RDN VALUE — `usernameOfEntry()`, exported from
   `ldap_server.js` and passed in by `scim.js` for the reason
   `normalizeDn()` is, so that the name SCIM reports is the one a create would
   collide with — and then to the DN, exactly as `toScimGroup()` already did for
   `displayName`. One unmappable entry must never be able to hide every other
   person, which is what a mapping that can throw halfway through a list does.


---

## What it deliberately does not do

* **SCIM WRITES INTO THE DIRECTORY AND IS THE ONE SURFACE HERE THAT ASKS WHO IS
  DOING IT.** The `/scim/v2` endpoints create, replace, patch and DELETE
  accounts, so they are the exception to everything above: a credential is
  REQUIRED (`scim.authRequired`), all six schemes RFC 7644 section 2 names are
  offered, and the OAuth ones must carry `scim:read` or `scim:write` — the first
  scope requirement anywhere in this service. **It is still a turnstile rather
  than a lock**, which is a different sentence and the one that matters: anybody
  can get a token with either scope from any grant, any password but `invalid`
  passes Basic, any username passes Digest with the one shared password, and
  anybody can register a HOBA key for any name. What it buys is that a client's
  401, 403, challenge-response and scope handling can be exercised at all — none
  of which an open endpoint can produce. See rule 6a-ii and `scim_auth.js`.
  **`active: false` DEACTIVATES NOBODY**: it is
  stored as `scimActive` and read by nothing, so no bind is refused, no token
  withheld and no session ended. That is the same carrying-is-not-acting
  distinction this service draws about a group, and it matters more here than
  anywhere else because deprovisioning is the single most common thing a SCIM
  client is built to do — a mock that pretended to disable an account would let
  somebody ship a path that has never worked. There is no ETag and no
  `changePassword`, both ADVERTISED as unsupported rather than half-implemented
  (a version over a one-second timestamp is a concurrency control a client
  trusts and that is wrong; and no password here is checked outside Digest).
  `/Me` is an ALIAS now that there can be an authenticated subject, delegating
  to the same User handlers, and its 501 is kept for the two cases where it is
  still right — an anonymous caller, and POST. A member naming nothing is
  ACCEPTED, because refusing it would make the
  dangling-member state `/admin/groups` exists to report impossible to produce.
