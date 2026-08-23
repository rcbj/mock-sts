# common/

The modules every other directory reads. Nothing in here belongs to a protocol,
and that is the entry test rather than a description: a file lands here because
more than one family needs it, not because it felt general.

| File | What it is |
|---|---|
| `config_file.js` | The one place that decides what `CONFIG_FILE` means. Requires nothing at all. |
| `config.js` | Every setting this service has. The only module `helpers.js` depends on. |
| `helpers.js` | Log, keys, `signJwt()`, `userFor()`, the cross-protocol parsers. |
| `app.js` | The express app and every middleware. Requiring it is how a protocol module gets somewhere to register. |
| `admin_stats.js` | The counters, the revocation set, and `recordAuthentication()` — the single authentication funnel. |
| `audit.js` | What happened, when, and to whom, as discrete events. Sits BESIDE `admin_stats.js`, not under it. |
| `applications.js` | Every application this service has been asked about, stored in the directory under `ou=applications`. |
| `claim_attributes.js` | Which LDAP attributes a token or an assertion carries, per claim set. |
| `group_claims.js` | The groups claim, in all four claim sets at once. |
| `vendored/` | Byte-identical copies of the parent project's files. **Do not edit them here** — see `common/vendored/CLAUDE.md`. |

**`config_file.js` is new with the 2026-08-23 reorganisation and it exists
because of it.** Fourteen modules read the appconfig file directly for the one
thing they need before `config.js` exists — a bunyan log level — and node
resolves a relative `require()` against the directory of the module doing the
requiring. While every module sat in the package root, `CONFIG_FILE=./env/local.js`
worked from all fourteen by accident. From `common/` it resolves to
`common/env/local.js`, which does not exist: `config.js` and `helpers.js` read it
UNGUARDED and would die with `MODULE_NOT_FOUND` naming a path nobody typed, and
the eleven guarded readers would quietly fall back to `info`. So the variable is
made absolute once, in place, before anything reads it. Three callers require it
first and between them cover every way this service is loaded — `server.js`,
`config.js` and `helpers.js` — and it is idempotent, so all three costs nothing.
Four of the fourteen readers are VENDORED files this repository may not edit,
which is why the fix is a mutation of `process.env` rather than fourteen edits.

---

## `helpers.js` holds what more than one protocol needs

`userFor`, `parseBody`, `oauthError`, `vciError`, `signJwt` and
`firstByLocal`/`textByLocal` are in `helpers.js` because more than one protocol needs
them, not because they are especially general. The last two are read by three parsers
— the WS-Trust RST, WS-Federation's `wreq`, and the `wresult` the mock relying party
is POSTed — and they match on **local name with the namespace ignored** because the
trust namespace alone has four versions in use. That is what lets one parser answer
WS-Trust 1.0 through 1.4 instead of four.


---

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


---

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
   the sixteen protocol families for the same reason it covers the directory's
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


3d-ii. **`group_claims.js` is the FOURTH library over that catalogue's
   territory, and it is the only one that reads the directory's GROUPS.**
   `vc_claims.js` says what a CREDENTIAL carries, `vc_verifier_config.js` what
   the Verifier ASKS FOR, `claim_attributes.js` which ATTRIBUTES a token
   carries; this puts the GROUPS somebody is a member of into all four claim
   sets at once. It registers no route and requires `helpers.js`, `config.js`
   and `admin_stats.js`, none of which requires it back.

   **IT IS AUTOMATIC AND THEREFORE NOT A SELECTION.** There is nothing to tick
   per user and nothing to tick per set — with `groups.claim` on, all four
   carry it. That is the deliberate opposite of `/admin/claims`'s three
   selections, and it is why the control is a `config.js` ROW rather than a
   form: four settings on `/admin/config`, which already has a page and already
   has `POST /admin-api/config/set`, so the console's parity rule (rule 7) is
   satisfied by there being no new control. **A second form on `/admin/claims`
   would be a second door to one setting**, which is the two-stores mistake
   rule 5 exists for.

   **ON BY DEFAULT IS DEFENSIBLE ONLY BECAUSE THE CLAIM IS OMITTED FOR SOMEBODY
   IN NO GROUP** — absent, not an empty array. On a fresh start the only people
   in a group are the three the directory seeds, so a caller who never touched
   `ou=groups` gets exactly the tokens it got before. An empty array would be a
   new member in every token every existing client parses, which is what
   `claim_attributes.js` defaults its selection to nothing to avoid.

   **TWO INVERSIONS, and each fails rule 3e's test in a different direction.**
   `admin_stats.js` offers `setGroupResolver()` and this module fills it (a
   require the other way closes a cycle, since this module requires that one for
   `identityKeyOf()`, the set ids and the reserved names); and this module offers
   `setDirectory()`, which `ldap_server.js` fills with `groupsOfUser()` — a
   require reaching THAT module would drag every `/ldap` route to the front of
   the router. What it buys is the thing every inversion here buys: NO ISSUANCE
   SITE CHANGED.

   **`ldap_server.js` OWNS WHAT A GROUP IS; THIS OWNS WHAT A TOKEN BELIEVES.**
   `groupsOfUser()` applies both group rules and resolves `member`,
   `uniqueMember` and `memberUid` exactly as the console's member list does —
   `memberUid` holds a bare name and the other two hold a DN, and treating them
   alike is how every `posixGroup` membership silently stops reaching a token.
   It reports BOTH directions (`via` for the group's own attributes,
   `viaMemberOf` for the person's claim) and applies neither, because which one
   a token believes is `groups.claimFromMemberOf` and that is a policy. Same
   split as `oauth2_bcp.js` and `oauth2.js`. **An entry is not required**: a
   group listing a DN nothing is stored at is a dangling member from the group's
   side and is still the group saying so.

   **PRECEDENCE IS NOW THREE DEEP IN A SECOND SENSE**, under the one rule 3d
   describes: a typed claim wins over a directory attribute, and both win over
   the groups claim — which is the only one of the three nobody named on a page.
   In `samlAttributes()` that is a FILTER for the reason stated there, and the
   groups layer is filtered against BOTH layers above it. A `groups.claimName`
   naming something this service sets itself is REFUSED AT ISSUANCE, not at
   configuration time, because `config.js` requires nothing from this repository
   and a copied reserved list is one that goes wrong.

   **A SAML ATTRIBUTE IS MULTI-VALUED and both builders now say so.** `values`
   is an array of `<AttributeValue>` children under one `<Attribute>`; `value`
   is untouched and is what every existing caller passes. One element per group
   with the same name is not a multi-valued attribute — it is a relying party
   reading the first and silently seeing one group where the person is in four,
   the exact defect `samlAttributes()`'s dedup filter exists to prevent.

   **CARRYING A GROUP IS NOT GRANTING ONE.** No endpoint here reads this claim
   and nothing decides anything on one, which is the same distinction this
   service already draws between an identity being RECORDED and one being
   AUTHENTICATED. What stopped being true is the OTHER half of the old sentence
   — "no token carries a group from this directory" — and the two halves are
   split on `/admin/groups`, on `/admin/claims` and in README.md rather than
   merged back into one claim that is now half wrong.


---

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

   **THE SPELLING TABLE IS TWO LISTS AND ONE DOOR.** `ldap_server.js`'s
   `CANONICAL_NAMES` puts the conventional capitalisation back on a name the
   store lower-cased. It is `STANDARD_NAMES` (types somebody else defined, the
   specification named per group) plus `OWN_NAMES` (this service's inventions),
   each written ONCE as the canonical spelling with the lookup key derived by
   `toLowerCase()` — never as `lower: 'Mixed'` pairs, where a typo in the key is
   invisible and the table fails silently at its only job. It covers ~150 names
   rather than the ~30 this service writes, deliberately: the directory is
   schemaless and a certificate subject arrives as attributes nobody here chose,
   so a table that knew only its own writes would be wrong exactly where a reader
   needs it. FOUR SOURCES merge — the two lists, `vc_claims.js`'s catalogue and
   `applications.js`'s schema — and all four go through `learnName()`, which
   keeps the first spelling and WARNS on a second rather than letting merge order
   decide silently. Add a name to a list, never to the map; `memberOf` is in
   neither category and says so where it sits.

   **THE STORE'S TWO DIRECTIONS ARE NOT SYMMETRICAL, and that is the fix for
   the DN.** A WRITE speaks in attribute objects — all a record has to say — but
   `readApplication()` and `allApplications()` hand back the whole ENTRY (`dn`,
   `origin`, `createdAt`, `modifiedAt`, `operational`, `attributes`), the same
   shape `objectFor()` gives the console for a person. It has to be the entry,
   because THE DN IS NOT AN ATTRIBUTE — it is the key the entry is stored under
   — so a caller handed only the attributes had no way to learn where the
   application lives, and every applications page could show the `cn` and
   nothing else. The DN is published inside `attributes` as `entryDN` (RFC 5020,
   and what `matchable()` already calls it) and SYNTHESISED on every read: a
   stored copy is a second definition of one fact and the one that goes stale,
   which `applicationEntry()`'s rename fallback shows is a case that happens.
   Two consequences to keep. `view()` exposes `attributes` as the WHOLE entry
   and `fields` as the schema half `recordFromAttributes()` understands — they
   are different questions and the narrow one was being served under the wide
   one's name. And every attribute lookup in `applications.js` goes through
   `byLowerName()`, because names now arrive canonically spelled on the way out
   and lower-cased in the store; an index assuming either produces a record with
   an empty identifier rather than an error.

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


---

## An OAuth client is not a person, and now it has somewhere to be

* **An OAuth client is not a person, and now it has somewhere to be.** It is still
  skipped by `autoCreateUser()` — `ou=users` is for people — but every client,
  relying party, service provider and Kerberos service gets an entry under
  `ou=applications` instead (rule 3g). That container is a REGISTRY rather than a
  record: the RFC 7591 registrations live there, nothing caches them, and an
  `ldapmodify` — or a form on `/admin/applications`, or a POST to
  `/admin-api/applications/{action}`, which are the same functions — changes what
  the protocol endpoints do. What those two will NOT change is the derived half:
  the counters and the sightings are what happened, and only LDAP reaches them.
