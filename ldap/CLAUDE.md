# ldap/

An embedded LDAP v3 directory (RFC 4511) on raw TCP 389 and, over TLS, on raw TCP
636 as LDAPS. One file — and it is the largest module in the service, because the
directory is also the STORE for four other things: people, groups, applications
(`../common/applications.js`) and the SPIFFE registry (`../spiffe/spiffe_registry.js`).

**It is built on the `node-ldapjs` SUBMODULE and the library is not patched.** See
the root `CLAUDE.md` for the submodule's placement rules, which have already cost
something three times.

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

---

6. **`ldap_server.js` must stay after `admin.js` AND after `tls_server.js`, and it
   INVERTS a dependency the same way `helpers.js` does.** The second half of that is
   new and is a plain require rather than an inversion: it serves `tls_server.js`'s
   server certificate and key on 636, and neither thing that forces an inversion
   applies — that module knows nothing about this one, so there is no cycle, and its
   routes (`/tls*`) collide with nothing here. What the require DOES do is pull those
   routes into the express router at that point, so `server.js` requires
   `./tls_server` BEFORE `./ldap_server` to keep "the require order is the route
   order" true rather than a fiction node quietly corrects. It changes no output —
   `/admin/sts-metadata` sorts its rows by path within a group. Its embedded directory grows an entry under
   `ou=users` for anybody who authenticates through any of the families here, and
   `admin_stats.recordAuthentication()` is already the single funnel all of them
   pass at the moment a credential is ACCEPTED — so one observer there is one place
   and not sixteen. **A verified TLS client certificate is one of them and is the
   odd one: its identity is not a name but a DN**, so its entry is named from the
   subject's CN (or the leaf RDN where there is none), every other RDN of the
   subject becomes an attribute, and the issuer, serial, validity and fingerprint go
   on beside them as `x509*` attributes that are this service's own names and not
   schema. `certificatePlan()` carries the placement rules and what they cost.

   **A DECENTRALIZED IDENTIFIER is the THIRD shape and A SPIFFE IDENTITY IS THE
   FOURTH; there is one plan per shape** — `certificatePlan()`, `didPlan()`,
   `spiffePlan()`, `namePlan()`, chosen in `autoCreateUser()` and decided in
   each. A DID is neither a DN nor a name but
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

   **A SPIFFE IDENTITY IS FILED THE SAME WAY AND FOR THE SAME REASONS, and the
   one place it differs from a DID is why it does not fold.** `spiffePlan()`
   names the entry `uid=spiffe-<12 hex>,ou=users`, puts the identifier whole on
   it as `spiffeSubject` (multi-valued) with `spiffeTrustDomain` and
   `spiffePath` beside it, and `locateEntry()` finds it by
   `entryBySpiffeSubject()` — never by rebuilding the digest, so the naming rule
   can change without orphaning anything. That lookup is the whole of "reuse the
   identity if it is already here": the same workload arriving as an X509-SVID
   at the SPIRE Server API, as an attesting agent and as a JWT-SVID at
   `ValidateJWTSVID` lands on ONE entry with one description per route.
   **It deliberately does NOT consult `existingUserEntry()`**, which is the
   opposite of what `namePlan()` does: the last segment of a SPIFFE path is
   exactly the kind of short common word (`db`, `web`, `api`) that collides with
   a person somebody signed in as, and a workload called `db` is not the DBA.
   And a workload is filed with the PEOPLE rather than under `ou=applications`,
   which is a decision: that container holds what this service was ASKED ABOUT —
   an application is the audience of a token — and a SPIFFE identity is the
   SUBJECT of one, like the TLS client certificate for a machine that already
   lands in `ou=users`.

   **AN ISSUED CERTIFICATE IS A FOURTH WAY ONTO THAT ENTRY, AND IT IS NOT AN
   AUTHENTICATION.** The three above are acceptances; this one is the trust
   domain MINTING an X509-SVID. `admin_stats.js` offers all four through the ONE
   observer slot, discriminated by `event` — `authentication`, `issuance` or
   `credential-status` — and `observeIdentity()` here is the dispatcher.
   **An absent `event` means an authentication**, deliberately, so that an older
   `admin_stats.js` behaves exactly as it did. An issuance goes through
   `autoCreateUser()` like everything else (one creation path, or the fold
   `createUser()`'s header protects is undone from a fifth door) and then
   `applySpiffeCertificate()` writes the certificate. A `credential-status`
   NEVER creates an entry: a revocation for something this directory has no
   record of issuing to is nothing to write down.

   **`applySpiffeCertificate()` WRITES THE SAME SIX `x509*` ATTRIBUTES
   `certificatePlan()` DOES, AND ASSIGNS WHERE THAT ONE APPENDS.** The same six
   on purpose — a certificate is a certificate however it arrived, and a second
   set spelt `svid*` would mean a filter written for one path silently misses
   the other. `spiffe_ca.js` reads the strings back off the certificate it has
   just issued with node's own parser and renders both DNs through the one
   `dnRfc4514()`, which is why that function now lives in `common/helpers.js`.
   The append-versus-assign difference had to happen: a renewed client
   certificate is rare and seeing both serials is the point, where an SVID is
   minted afresh at half its lifetime for as long as the workload runs, so
   appending would add six values an hour for ever — `applyVcAttributes()`'s
   second rule met in a new place. `x509svidsIssued`, `x509firstIssued` and
   `x509lastIssued` are what is left of the history; the individual serials are
   on `/admin/metrics`, where every SVID is an artifact row. A ROTATION NEEDS NO
   CODE TO LAND ON THE SAME OBJECT: `entryBySpiffeSubject()` keys on the SPIFFE
   ID and on nothing about the certificate.

   **`spiffeCredentialStatus` IS NOT A CERTIFICATE STATUS AND NOTHING READS IT
   BACK.** SPIFFE has no revocation; `applySpiffeCredentialStatus()` carries the
   whole argument and `GET /spiffe` states it as a thing this service
   deliberately does not do. The attribute records the three things in
   `spiffe_registry.js` that end an identity's ability to obtain a NEW
   credential — its LAST registration entry deleted, its agent banned, its agent
   deleted — each reversible and each reversal written the same way, so the flag
   is the current state. `spiffeRevokedAt` is never cleared, which is
   `mfaLastAuthTime`'s rule and for the same reason. **THE ENTRY IS NEVER
   REMOVED**: an identity this trust domain used to issue certificates to is
   exactly what a directory is for.

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
   sixteen call sites means a seventeenth that is not.

   **A container it does NOT sweep, and that is the point of it.**
   `ou=applications` is `applications.js`'s store (rule 3g) and this module is
   what makes it one — `readApplication`, `writeApplication`, `allApplications`
   and `countApplications`, filled into that module's `setDirectory()` slot at
   require time, plus `GET /ldap/applications`. The division is exact and worth
   keeping: THAT module owns the schema and both conversions, THIS one owns
   where the container is, how an entry is created and what the cap is.

   **AND ONE CALL IN THIS FILE PUTS TWO ENTRIES IN THAT CONTAINER.** Immediately
   after that slot is filled — the earliest moment there is somewhere to write
   to — `applications.seedInternalApplications()` seeds the two applications no
   caller will ever name, because they are surfaces of this process: the console
   at `/admin` and the management API at `/admin-api`. It is a call rather than
   two more `putEntry()` blocks in `seed()` on purpose. `seed()` builds the TREE,
   which is this file's half, while what those two entries hold is a pair of RFC
   7591 registrations, which is that module's — and it could not run in `seed()`
   anyway, thousands of lines before the slot it goes through exists.
   `applications.seedInternal` turns it off, restart-only for the same reason.

   Note
   that `writeApplication()` REPLACES rather than merging, which is the one
   place this file breaks `applyVcAttributes()`'s fill-only-what-is-absent rule
   — deliberately, because the record being written was read from that entry a
   moment ago, so merging would make it impossible ever to REMOVE a value and a
   redirect URI deleted with `ldapmodify` would come back on the next request.

   **ONE ENTRY PER PERSON, AND IT IS ENFORCED AT FOUR DOORS RATHER THAN ASSUMED
   AT ONE.** Most of it was already true by accident: `identityOf()` normalises
   `rcbj`, `urn:sts-mock:user:rcbj` and `rcbj@STS.MOCK` to one key, so every
   name-shaped family folds onto `uid=rcbj,ou=users` before this module sees
   them. What did not fold was the identity that is a DN — a certificate saying
   `CN=rcbj` became a SECOND object beside the entry `rcbj` already had, in
   either order of arrival. `existingUserEntry()` is the whole of the fix and
   BOTH plans consult it: the lookup is by the entry's own NAMING RDN VALUE and
   by any `uid` it carries, case-insensitively (the store already keys DNs
   lower-cased), scoped to entries DIRECTLY UNDER `ou=users` because placement
   is the only rule a schemaless directory cannot be lied to about. `namePlan()`
   merges a `uid` onto an entry it folds onto, since that entry was named by
   somebody else's attribute and the username was a fact nothing on it recorded.
   The other three doors are `server.add` (LDAP_ENTRY_ALREADY_EXISTS, 68, naming
   the entry that holds the name), and `createUser()`, which the console form and
   `POST /admin-api/users/create` share. **Do not add a fifth way to create an
   entry under `ou=users` without routing it through that function** — the fold
   can be undone from any door that does not.

   **A DID IS THE ONE IDENTITY THAT GENERALLY CANNOT FOLD, and where this service
   knows whose it is, it does.** A DID names nobody by itself, which is why
   `didPlan()` names its entry by a digest. But `vc_issuer.js` decides who a
   credential is about from the access token and derives the holder DID from the
   proved key in ONE call, so it passes `linkedTo` on the funnel and the
   identifier goes onto that person's entry as a `didSubject` value instead. That
   REVERSES an argument written at that call site — one wallet, several holder
   keys, "a directory that filed them all under the access token's name could not
   tell them apart" — and the reversal is sound because `didSubject` is
   multi-valued: all of them are on one entry rather than one each on several.
   Three consequences are load-bearing. `entryByDidSubject()` is consulted by the
   UNLINKED branch too, or the same DID presented later at the Verifier — where
   nothing says whose it is — creates the very entry the link avoided.
   `personaKeyOf()` prefers the DID only where the DID NAMED the entry (its uid is
   `didUid(did)`), or a folded entry would be filled from two different invented
   people. And `plan.personaKey` exists for the same reason on the way in.

   **A SECOND hook runs the other way, and it is the console that offers it.**
   `/admin/users?user=<name>` shows that user's directory object — every attribute,
   operational ones included — and `admin.js` must NOT require this module to get
   it: `server.js` requires `admin.js` FIRST, so a require from there would pull
   `/ldap` and `/ldap/directory` into the router ahead of the console's routes, and
   `GET /admin/sts-metadata` is built by walking that router. So `admin.js` exports
   `setDirectoryReader()` and this module fills it with `objectFor()` at require
   time. `objectFor()` is given the identity key the console files a person under,
   which is the same normalised local name `autoCreateUser()` built the DN from —
   pass anything else and the two silently stop naming the same entry.

   **The console's THIRD slot is the only one that WRITES.** `admin.js` offers
   `setDirectoryWriter()` and this module fills it with `createUser()`, for the
   same route-order reason the two readers exist. It carries that function and
   NOT a way to write an arbitrary entry, so what a username may be — and the
   refusal of one already here — has one definition rather than one per surface.

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

   **A GROUP HERE GRANTS NOTHING, WITH EXACTLY TWO EXCEPTIONS**, and both pages
   say so where a reader will see it. The exceptions are `cn=admin-read` and
   `cn=admin-write` (`admin.readGroup`, `admin.writeGroup`), which decide who may
   use the ADMIN CONSOLE — the SIXTH slot below is what carries this module's
   group functions to `admin-ui/admin_rbac.js` so that they can. Even those two
   grant nothing outside `/admin`: no token, assertion, ticket, PAC or credential
   is changed by being in one, and every protocol endpoint answers a member
   exactly as it answers anybody else. The general sentence is what matters and
   is why it is qualified rather than dropped everywhere it appears. No endpoint reads a group and nothing decides anything on one. The same is
   true of those three authentication-factor attributes, and of them it is true
   twice over — nothing reads them back and no token carries them either. On a
   service that authenticates nobody it could hardly be otherwise — but a console
   that listed groups beside the tokens page without saying it would let somebody
   conclude that adding a user to `cn=directory-admins` changed what their token
   could do.

   **A SIXTH HOOK IS THE FIRST THAT HANDS OVER A WRITER.** `admin_rbac.js`
   decides who may use `/admin`, out of two ordinary groups in this directory,
   and this module fills its `setDirectory()` slot at require time with
   `groupsOfUser`, `readGroupEntry`, `writeGroupEntry`, `groupDnFor`,
   `normalizeDn`, `existingUserEntry`, `usernameOfEntry`, `nameUsableInDn`,
   `allPersons` and the two container DNs. Same route-order reason as the five
   above: a require of THIS module from there would pull every `/ldap` route
   ahead of every `/admin` one.

   What crosses is this module's own FUNCTIONS and not a copy of its rules, the
   same division the five keep — which is the whole point of the arrangement: a
   role granted on `/admin/rbac`, one granted by `POST /admin-api/rbac/grant`,
   one granted with an `ldapmodify` and one granted by a SCIM PATCH all end in
   `writeGroupEntry()` and leave the IDENTICAL entry. A membership store of the
   console's own would have been a second answer to "is alice an admin" that no
   directory client could see. `writeGroupEntry()` grew an `origin` argument for
   it, defaulting to `scim` so the call site that predates the parameter says
   what it always meant.

   It is ONE object where the console's own slots are five separate functions,
   and the concern stated over there — a filler installing only half of it would
   silently disable the other half — is answered rather than ignored:
   `setDirectory()` checks every member and refuses a partial object with an
   error naming what was missing.

   **A TOKEN DOES CARRY A GROUP NOW, WHICH IS A DIFFERENT SENTENCE** — see rule
   3d-ii and `groups.claim`, which is ON by default. `groupsOfUser()` here is
   what answers it, filled into `group_claims.js`'s `setDirectory()` slot at
   require time beside the four hooks above; it is the FIFTH and the same shape
   as the fourth. Do not merge the two sentences back together: carrying a fact
   is not acting on it, and no Kerberos PAC carries a group either way.


---

## A DIRECTORY PER TRUST REALM, BEHIND ONE SOCKET

Since 2026-08-25 the directory is **per realm** — and since later the same day
it is a **STORE per realm**, not a subtree of one store. The DN layout is
unchanged and is what a client sees:

```
dc=example,dc=com                    the DEFAULT realm      (ROOT_DN, ldap.baseDn)
  ou=users, ou=groups, ou=applications, ou=federations, ou=spiffe
dc=acme,dc=example,dc=com            the realm `acme`
  ou=users, ou=groups, ou=applications, ou=federations, ou=spiffe
```

`ROOT_DN` is what the **socket** serves and never changes. `baseDn()` is what the
**ambient realm** owns, and the six container accessors — `usersDn()`,
`groupsDn()`, `applicationsDn()`, `federationsDn()`, `spiffeEntriesDn()`,
`spiffeAgentsDn()` — are built from it. They were `const` strings until that
date; **every one of them is a function now**, and the exports changed with them,
so a consumer that still reads `directory.USERS_DN` gets `undefined` rather than
quietly reading the default realm's container. That was the point of removing
them rather than leaving them beside the functions.

**WHY THE REALM IS IN THE DN.** The realm is ambient, in an AsyncLocalStorage
that `app.js`'s first middleware enters — and that middleware runs on an HTTP
request. **LDAP has no HTTP request.** An `ldapsearch` arrives on 389 carrying a
bind DN and a base DN and nothing else: no path, no header, nowhere to put a
realm segment. If the partition were a Map per realm selected by an ambient
value, an LDAP client could never reach any realm but the default one, and a
realm that exists over HTTP and not over LDAP is exactly the half-truth this
service is supposed to make impossible. Putting it in the DN is what makes
`ldapsearch -b "dc=acme,dc=example,dc=com"` mean what it says. A listener per
realm would isolate as well and would cost the thing the feature is for: a port
is bound when the process starts, so realms would stop being creatable at
runtime.

**THE BASE IS DERIVED FROM THE REALM ID AND IS NOT A SETTING.** `ldap.baseDn` is
restart-only *because the tree is built under it at startup* — the "material
derived at startup" kind that `common/CLAUDE.md` names as the case that must
never get the `realmRuntime` marker. So a realm cannot carry `ldap.baseDn`, and
its base is computed instead. That is the rule being right rather than something
worked around: a configurable base would let two realms name one subtree.

**THE SUBTREE IS BUILT WHEN THE REALM IS.** Every other per-realm store in this
service is built lazily by `realms.keyed()`, which works because every one of
them is reached through a request that has already entered the realm. This one
is not — "first touch" can be an `ldapsearch` for a base DN — so `realms.onCreate()`
was added to `realms.js` for this and has one caller. It runs the SAME `seed()`
inside the realm: the six containers, the bind account, alice, bob, carol and the
two groups, under the realm's own base. A realm is a whole logical copy of this
service, and one whose `ldapsearch` taught less than the default's would not be.
`realms.onRemove()` purges the subtree, for the reason every other store purges.

### `const entries = realms.map()`, and why it is not a subtree of one Map

**THE STORE IS PER REALM, SO THE ISOLATION IS AN INVARIANT RATHER THAN A RULE.**
`entries` is the AMBIENT realm's Map: `getEntry()` in `acme` cannot return the
default realm's entry, because it is not in the Map it is reading. Nothing has
to remember to check.

It was a subtree of one Map for two days, and the two days are the argument.
With one Map the isolation was a rule every reader had to apply, and a rule
applied at fifty call sites is a rule that will be missed. It was missed twice:

* **The walk.** `allGroupEntries()` walked the whole Map and asked
  `groupRuleFor()` about each entry, and that predicate answers `objectClass`
  for anything carrying a group class **wherever it sits** — deliberate, so a
  group somebody put outside `ou=groups` still counts. Generous with one tree;
  with a tree per realm it meant the default realm listing `acme`'s groups as
  its own. Fixed by scoping the walk, not the predicate.
* **The lookups, which is the half that was missed after the first fix.** Every
  reader starting from a DN somebody handed in still called `getEntry()`, so the
  list on a page was right and the thing it linked to was not:
  `/realm/acme/admin/groups?group=<a default-realm DN>` rendered that group in
  full, `GET /realm/acme/scim/v2/Groups/<same DN>` answered 200, and **`DELETE`
  answered 204 and the group was gone** — a cross-realm destructive write. The
  person half never had it, because `readPerson()` guards with
  `isPersonEntry()`, which tests placement under the AMBIENT realm's
  `usersDn()`; groups guard with `groupRuleFor()`, which is placement-blind on
  purpose, so nothing about a group's own definition could have caught it.

Each was patched by hand first (`inRealm()`, `realmEntry()`) and the split then
made the patch unnecessary: those two functions are gone, and `getEntry()` is
the realm's lookup because the Map is the realm's.

**`eachEntryInRealm()` IS STILL THE CHOKE POINT AND STILL HAS TWENTY-FOUR
CALLERS**, now as a one-line wrapper over `entries.forEach()`. It is kept for
its NAME: it tells a reader at the call site that a walk here is realm-scoped,
which the bare `forEach` no longer says out loud.

**Three things are still about the whole process, and each says so:**
`totalEntries()` sums every realm's store for the `ldap.maxEntries` ceiling —
the cap is on what this process holds in memory, and n realms holding n times
the ceiling was never the intention; `hasChildren()`, a question about one DN in
the realm being asked; and the realm purge, which now deletes nothing at all
because `realms.map()` drops the whole store with the realm.

### The socket picks a store, and it picks it from the DN

There is no ambient realm on port 389 — no path, no header, nothing but the
request. What the request does carry is a **DN**, and since each realm's
directory is named by its base, that DN names a realm. So the eight handlers are
wrapped **once, at registration**: `realmFor(req.dn)` resolves the realm and
`realms.run()` enters it, after which `entries` inside the handler is that
realm's store. Not one handler mentions a realm, and none should have to —
eight bodies each remembering to enter one is eight chances to forget, and what
was forgotten would be invisible (the operation would succeed against the
default realm and answer "no such object" for an entry that plainly exists).

`unbind` is the exception and is deliberately unwrapped: it ends a connection
and has no DN. It is named in `REALMLESS_OPERATIONS` so that a reader wondering
whether it was an oversight finds the answer.

Consequences, all verified by hand with an ldapjs client:

* `-b "dc=example,dc=com"` is the **default realm's** directory —
  19 entries in a seeded process, not 33. `-b "dc=acme,dc=example,dc=com"` is
  acme's. **This reverses the original decision** (that a naming context IS the
  whole tree) at rcbj's request, and the reason it is the better answer is that
  the old one left port 389 as the single door through which one realm could
  read another's, while the console, `/scim/v2` and the group claim showed each
  realm only its own.
* The **root DSE publishes one `namingContexts` value per realm**, because
  discovery is that attribute's only job and a client reading a single root
  would have no way to learn the others exist.
* An operation naming **one DN** — add, modify, delete, compare, a base-scope
  search — is answered in that DN's realm. Spelling the DN out is how a client
  names a realm on a socket with nowhere else to put one.
* **A modifyDN may not cross a realm.** It is the one operation that could,
  since it carries two DNs, and it is refused with
  `LDAP_AFFECTS_MULTIPLE_DSAS` (71) — which is what a real directory answers
  when a rename would move an entry out of the DSA holding it. Two realms here
  are two directories, so that error is true rather than borrowed.

**The alternatives, so nobody re-derives them.** A *listener per realm* works —
node binds a port whenever it likes, and the claim in this file that it would
have made realms restart-only was simply wrong, demonstrated by binding a second
ldapjs server at runtime — but it makes a realm reachable by PORT, a second
discriminator beside the DN that every client then has to be told about. An
ldapjs `Server` per realm behind one socket does not work at all: the
discriminator lives inside the protocol, per operation, and a `Server` owns its
`net.Server`.

`tests/realm_directory_lookups.js` guards the module-contract half in process
and was mutation-tested against a `getEntry()` that reaches into every realm's
store (5 assertions red) and an `eachEntryInRealm()` that walks them all (1).
The socket half needs a listener, so by `tests/CLAUDE.md`'s rule it has no test
here.

**THE DEFAULT REALM NEEDS A CARVE-OUT AND IT IS THE HALF THAT WAS MISSED FIRST.**
Every other realm's base is a sibling — `dc=acme,…` and `dc=beta,…` contain
nothing of each other's — so "under my base" is the whole test. The default
realm's base is ROOT_DN and every realm is UNDER it, so "under my base" still
listed four groups where there are two. `containedRealmBases()` answers with the
bases that lie **strictly inside** this realm's, which is the rule in both
directions and needs no special case for either. Note it is asked by
containment rather than by "every realm but me": `realms.list()` includes the
default realm, so the naive version carved ROOT_DN out of `acme` and left `acme`
reporting an empty directory.

**THE SEARCH SCOPING AND THE DEFAULT REALM'S OLD CARVE-OUT ARE BOTH ARGUED
ABOVE**, under *The socket picks a store*. They were separate mechanisms for
a few hours — a containment predicate applied to a shared Map, and a filter
in the search handler — and the store split replaced both with the same
sentence: a handler runs in the realm its DN names, and that realm's Map is
all there is to read. `containedRealmBases()` and `insideRealmContainer()`
are gone with them; if a future reader comes looking for the carve-out that
kept the default realm from listing `acme`'s groups, it is not missing — it
stopped being needed when the default realm's store stopped containing
acme's entries.

**THE GROUP INDEX IS PER REALM**, via `realms.keyed()`. `buildGroupIndex()` walks
the ambient realm and classifies with `groupRuleFor()`, which asks
`isUnder(dn, groupsDn())` — an ambient question — so a single module-level cache
would have handed the default realm's index to every other one. The symptom would
have been the worst kind: a `groups` claim in a token issued under `/realm/acme`
naming the DEFAULT realm's groups, correct-looking, verifiable and wrong.

**AND THE TWO ADMIN CONSOLE ROLES ARE PINNED TO THE DEFAULT REALM.**
`adminRbac.setDirectory()` is handed nine functions wrapped in `inDefaultRealm()`,
which is `realms.run(DEFAULT_REALM, …)`. A role is permission to change what
every realm does, so a per-realm roster would mean anybody who can create a realm
can grant themselves both roles inside it and walk back out into the default one.
`setDirectoryReader()` and `setDirectoryWriter()` are deliberately NOT pinned:
those draw the console's user pages, and `/realm/acme/admin/users` showing the
default realm's people would be a console that cannot see the realm it is pointed
at. Reading a realm is the console's job; being let in is not the realm's
decision. `authn.js`'s `consoleSession()` is the other half and has to agree.

## `ou=federations` IS THE SIXTH CONTAINER, AND THE ONLY ONE WHERE AN `ldapmodify` IS A SECURITY CHANGE

The applications container's arrangement made a third time — this file owns
WHERE an entry lives, how it is created and what the cap is, and
`../federation/federation.js` owns what an entry IS — and it is a deliberate copy
rather than a coincidence. Its `setDirectory()` slot is filled here at require
time, in the ordinary direction, for exactly the reason `applications.js`'s and
`spiffe_registry.js`'s are.

**It is a container of its own rather than a corner of `ou=applications`**, and
that needed an argument. An application entry is something this service was ASKED
ABOUT. Half these entries are FOREIGN IDENTITY PROVIDERS, which ask this service
for nothing at all — they authenticate people TO it. Filing them among the
parties that consume what this service issues would make the one question
`ou=applications` exists to answer unanswerable. (The partner is ALSO recorded
over there, once, as a `federation-identity-provider` — that record is the party,
and this one is the arrangement with it.)

**The DN is the id, with no digest case.** An application entry may be
`cn=app-<12 hex>` because its identifier is whatever a protocol presented and can
be any length; a relationship id is CONFIGURED, so `federation.js` simply
requires it to be RDN-safe and short and refuses one that is not. That is the
difference between a register that is written down and one that is observed.
There is still a walk by `fedId` for one case — an entry somebody renamed with an
`ldapmodrdn` — because the alternative is a register that loses a relationship
because somebody tidied a DN.

**And the sentence that is true of no other container here: an `ldapmodify` of
one of these entries is a SECURITY change.** Everywhere else in this directory an
edit changes what this service HANDS OUT. `fedSigningCertificate` decides whose
assertions it will BELIEVE, and `fedEnabled` turns a partner on. Every bind to
this directory succeeds, so this container is exactly as protected as the rest of
it, which is to say not at all — that is the honest state of a mock, it is said
out loud on `GET /ldap/federations`, and it is part of why federation refuses by
default rather than accepting.

`fedClientSecret` is on these entries in the clear, and it is a stronger claim
than `oauthClientSecret` one container over: that one is a secret this service
MINTED for a mock client and can mint again, and this one is this service's own
credential at a REAL foreign service. Same decision, same reason
(`/krb5/principals` prints the Kerberos passwords), worth restating because the
consequence is different.

## THE FIVE FEDERATION ATTRIBUTES ON A PERSON'S ENTRY

`applyFederatedAttributes()` runs on an entry created because somebody signed in
SOMEWHERE ELSE — the only path here of that shape — and it breaks the rule its
neighbour follows, on purpose.

**`applyVcAttributes()` fills only what is ABSENT. This one ASSIGNS, and the
partner's values win.** The two have to differ: that one writes an INVENTED
persona and this one writes what a real identity provider actually asserted. If
it merged, `alice@example.invalid` — invented the first time anybody named alice
turned up — would beat the address her employer's identity provider just sent,
permanently, with nothing on any page saying why. If it accumulated, an entry
would carry one `mail` value per sign-in.

**Only what the partner sent is touched.** An attribute on the entry that is not
in this assertion is left alone: a partner that stopped releasing `title` has not
said the person has no title, and deleting on the strength of an omission loses
data on somebody else's configuration change.

**It never writes `uid`.** That is what `namePlan()` put in the RDN, and a
partner sending a different one would leave an entry whose DN and whose `uid`
name two different people — which every lookup here that finds somebody by name
goes through one or the other of.

**`federationAttribute` is the useful one and has no analogue anywhere else in
this directory.** A federated `mail` and an invented `mail` are ordinary
attributes and look identical; this lists which of the entry's attributes came
off a foreign assertion. Nothing reads it. It is there because "is this address
real or did you make it up" is exactly the question a federated directory entry
raises, and without this there is no way to answer it.

`fedAutocreateUsers` on the relationship is checked in `autoCreateUser()` beside
`ldap.autocreateUsers`, and it is the one place a federated sign-in is treated
differently from any other kind: a federation partner is the one source of
identities whose VOLUME this service does not control, and off gives a session
and no entry.

## A WRITE MUST CALL `touchDirectory()`

`groupsOfUser()` is called ONCE PER TOKEN — every access token, every ID Token
and both SAML assertions, through `group_claims.js`. It used to answer by
walking every entry in the tree and normalising every value of every membership
attribute on each group it found, which is O(entries x members) per issuance
against a store `ldap.maxEntries` lets reach 2,000. At that size it cost 2.7ms
per token and `normalizeDn()` was the third-heaviest application function in a
CPU profile of the token endpoint. It is now a reverse index and costs 0.0016ms.

**The index is only correct while nothing has been written, so every writer
bumps `directoryVersion` by calling `touchDirectory()`.** A write that does not
leaves the index describing the directory as it was, and the symptom is a
`groups` claim one `ldapmodify` out of date inside a token that is otherwise
perfect — which reads as a claim-mapping bug and would be looked for anywhere
but here. The call sites are `putEntry()`, `addValues()`, the vc-attribute
sweep, the LDAP delete, modify and modifyDN handlers, and the four typed
deletes. Those are the only two things that can make the index wrong: replacing
an entry in the Map, or mutating a stored entry's attributes in place.

A rebuild ALSO fires when `entries.size` disagrees with the size the index was
built at. That is a net and not a design — it catches an add or a delete that
forgot to call `touchDirectory()`, and it cannot catch an in-place attribute
change, which is why the rule above is the rule.

**What was NOT done is a cache with a TTL.** The membership is read per token
and never cached precisely so that an `ldapadd` changes the very next token,
which is the thing somebody came to a mock directory to watch. This is not a
time-based cache and has no staleness window: a bumped version rebuilds on the
next read, before it answers.

### AND SINCE 2026-08-27 IT IS ALSO WHAT MAKES THE DIRECTORY PERSIST

`touchDirectory()` calls `persistence.directoryChanged()`. That is the whole
integration on this side, and the choke point is why it was affordable to add to
a file of 6,500 lines: there was already ONE function every writer had to call,
already documented, already enforced by prose, and already the thing a new
writer is told to call.

The alternative was to instrument the fifteen-odd writers individually with a
"this DN changed" call. It would be more precise and **it would be forgotten**,
and the two failures are not equally bad: a writer that forgets
`touchDirectory()` produces a stale groups claim, and a writer that forgot a
separate `persist(dn)` would produce an entry that is in the directory until the
process restarts and then is not.

**What the choke point costs is that it does not say WHICH entry changed**, and
`persistence.js` answers that with a diff against a shadow of what it last
wrote. So the rule above is unchanged and now guards two things instead of one.
In the default `memory` mode the added call returns immediately on a boolean.

## THE DIRECTORY IS WRITTEN DOWN THROUGH A SLOT

`persistence.setDirectory({realmEntries, replaceRealm})`, filled at this
module's require time. It is a slot rather than a require in the other direction
for a ROUTE-ORDER reason rather than a cycle one: `persistence.js` is required at
#4a, far above `admin.js`, and a require from there to here would drag `/ldap`
and `/ldap/directory` into the express router at that point — the exact failure
rule 1 exists to prevent. The require in THIS direction is a plain one and closes
nothing.

Two things about the pair are worth knowing before changing either.

**Neither enters the realm, and that is the opposite of what every LDAP handler
here does.** A handler resolves a realm from the DN it was given and runs its
body inside `realms.run()`, because everything below it reads `entries`
ambiently. These two are handed a realm ID, and `entries.realmMap(id)` names a
realm's store directly — so entering would buy nothing and would mean a restore
of twelve realms doing twelve `AsyncLocalStorage` entries for no reason.

**`replaceRealm()` does NOT go through `putEntry()`, and that is the point.**
`putEntry()` stamps `createTimestamp` and `modifyTimestamp` with NOW, which is
right for an entry being created and wrong for one being restored: every person
in a restored directory would report having been created the moment the process
started. The stored object is reconstructed as it was written, timestamps
included. The DN is re-normalised through this file's `normalizeDn()` rather than
trusting the key the store wrote, because that function is the one place in this
service that decides two spellings are one entry, and a stored key from an older
version of it must not be believed over the current one.

**It clears rather than merges.** A restore is "this is the directory", not
"these entries as well as the seed" — a merge would bring back an entry that was
deleted in the last run and reseeded in this one, and the person who deleted it
would find it back.

**It also refills `admin_stats.js`'s identity register, and that was a real
bug.** A restored directory came back with twenty entries — `ldapsearch` and
`/ldap/directory` showed all of them — and `/admin/users` reported `known: 0`,
because that page has never read this directory. It reads the identity register,
which until 2026-08-27 could only be filled by somebody AUTHENTICATING; a
restored directory is the first thing that ever put an entry under `ou=users`
without a sign-in. They go in through `noteKnownIdentity()` and are marked
RESTORED rather than authenticated, so `authenticatedHere` keeps counting
sign-ins rather than people.

**A SEEDED PERSON IS SKIPPED**, and that is what keeps a restored process's
`/admin/users` identical to a fresh one's. alice, bob and carol are written by
`seed()` on every start in every realm and have never been in that register —
the page's own description is "every userid this service has been given as part
of an interaction that SUCCEEDED", and being seeded is not an interaction.
Registering them would mean a fresh service listed nobody and the same service
after one restart listed three people who had still done nothing, which is a
difference somebody would reasonably read as a bug. What is registered is what a
fresh process would also have had: people somebody created, people an `ldapadd`
wrote, and people who authenticated.

**THE SAME GAP WAS ALREADY THERE ON THE CREATE PATH AND IS FIXED WITH IT.**
`createUser()` — the console's door, `POST /admin-api/users/create` and a SCIM
create, all three — wrote a directory entry and never touched the register, so a
person created by hand appeared on `/admin/users` NOWHERE until they signed in,
while that page's own blurb said "a person can be created here ahead of their
first sign-in". It calls `noteKnownIdentity(name, 'created')` now. That call is
safe on the authentication path because `recordAuthentication()` builds the
record before it reaches the observer and `autoCreateUser()`, and
`noteKnownIdentity()` returns early for a key it already has. **That pass is the one part of `replaceRealm()`
that DOES enter the realm**, because `isPersonEntry()` compares against
`usersDn()` and the register is itself a `realms.map()` — both ambient by
construction.

`persistence/CLAUDE.md` argues the rest, including why this is not a node-ldapjs
feature and could not be.

## The library is NOT patched

Everything in `ldap_server.js` is handlers
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

The rest of the submodule's rules — where it must sit, why `--recursive`
matters, and why `.npmrc` carries `omit=dev` — are in the root `CLAUDE.md`,
because they are facts about the package root rather than about this module.

---

## Every bind succeeds

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
  attribute is 16, and an attribute's last value takes the attribute with it),
  a FIFTH is this service's own rather than the protocol's (an add under
  `ou=users` whose username is already here is 68, because one person is one
  entry however they got in — LDAP has no notion of a username and a real
  directory would get this from the schema subsystem this mock does not have),
  and one is deliberately NOT: deleting a user leaves its DN in every group that lists
  it, because referential integrity is a directory feature and not a protocol rule.

---

## The connection IS the session, so a logout closes it

RFC 4511 section 4.2: a Bind establishes the authorization state of a
CONNECTION, and it lasts until the next Bind or an Unbind. There is no ticket,
no cookie and no token — so **closing the connection is the only sign-out LDAP
has**, and it is what the protocol-independent `/logout` calls through
`boundConnections()` and `dropConnectionsFor(key)`.

**This file keeps its own connection list and has to.** ldapjs's `Server`
exposes `connections`, which is node's deprecated `net.Server` **count** — a
number — and nothing that enumerates the sockets or the DNs bound on them. The
submodule is used unmodified, so the list is kept here, on the underlying
net/tls server's own `connection` / `secureConnection` event, which fires for
every socket ldapjs then sets up.

Three things about it:

* **It is a Set of the SOCKETS and nothing else.** The bound DN is read off
  `socket.ldap.bindDN` at the moment somebody asks and never copied — ldapjs
  owns that value and re-binding on one connection changes it. A copy would be a
  second store of one fact, and the one that goes stale exactly when it matters.
* **Removal is on `close`**, which node emits however a socket ended, so nothing
  is swept and a client that vanished leaves no row claiming to be signed in.
* **`destroy()` and not `end()`.** `end()` sends a FIN and waits, and a client
  mid-search can keep a half-closed connection alive as long as it likes — a
  logout that reported success and left the session up. An **Unsolicited Notice
  of Disconnection** (section 4.4.1) would be the polite form and node-ldapjs has
  no way to send one; `/logout` says so on the row rather than leaving it as a
  difference somebody discovers.

The identity a connection is filed under is `consoleKeyFor(dn, getEntry(dn))` —
the same derivation the groups page links with, with the entry passed so that
its own `uid` wins over the DN's RDN. **A row on `/logout` and a row on
`/admin/users` must name one person**, which is the same one-entry-per-person
rule this directory keeps at every other door.

`logout.ldapDisconnect` turns it off, and the connections are then LISTED as
untouched rather than hidden — a family that vanished when its setting was off
would make a global logout look complete.

---

## THREE ATTRIBUTES UNDER `ou=applications` NOW MEAN SOMETHING ONLY IN PAIRS (2026-09-01)

Every other attribute on an application entry describes the application it is
on. `oauthPermissionBaseUri` and `oauthPermission` (on the RESOURCE) and
`oauthDelegatedPermission` (on the CLIENT) do not: a grant is a fact about two
entries at once, joined by a string composed from a third attribute on the first
of them. `common/app_permissions.js` is what reads the two halves together and
`common/CLAUDE.md` argues the model.

**Nothing about this directory changed to take them.** They are rows in
`applications.js`'s `SCHEMA` like every other, so `GET /ldap/applications`
publishes them, `attributesFor()` writes them and `recordFromAttributes()` reads
them back, and they persist wherever the directory does. That is the property
that arrangement was built for, and this is the first feature to lean on it in
both directions.

**AN `ldapmodify` REACHES THEM AND IS NOT CHECKED**, exactly as it reaches a
redirect URI. That is the whole reason the console can report a **dangling**
grant — one naming a permission no application defines — as a state rather than
an error: both console doors refuse to create one, so a dangling grant is always
something that happened outside them, and this directory enforces nothing
anywhere.
