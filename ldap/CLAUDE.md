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

**Both listeners are started from `listen()` in `server.js`, not at require
time** — requiring this module registers its HTTP views (the eight
`/admin/ldap/*` pages) like everything else, but binding a port can fail, and a
`require` that throws takes the whole service down where a route cannot. A
failure to bind is RECORDED rather than thrown, and published (`listening` /
`listenError` on `GET /admin/ldap/service`), because the HTTP view answers 200
either way and there is otherwise no way to tell a running listener from one
whose port was already taken — by the host's own slapd, or by a second copy of
this service. The root `CLAUDE.md`'s *Socket owners start their listeners
from `listen()`* is the rule this is an instance of.

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
   `identityOf`'s normalisation, so `alice`, `alice@REALM` and a token's
   `urn:uuid:<entryUUID>` — or the retired `urn:sts:user:alice` — seed ONE
   entry), which means `admin_stats.js` cannot require it
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
   require time, plus `GET /admin/ldap/applications`. The division is exact and worth
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
   `rcbj`, `rcbj@STS.MOCK`, `urn:uuid:<rcbj's entryUUID>` and the retired
   `urn:sts:user:rcbj` to one key, so every
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
   every route this module registers into the router ahead of the console's routes, and
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

   **AND SINCE 2026-09-06 THAT FUNCTION TAKES THE PERSON'S DETAILS AS WELL AS
   THEIR NAME, WHICH IS WHERE THE ONE TRAP IN THIS CHANGE IS.**
   `/admin/users/new` is a form with a box for every attribute a person here
   can carry; only the username is required, and **an empty box records NO
   VALUE**. Two options carry that: `options.attributes`, checked against
   `vc_claims.js`'s catalogue by `personAttributesFrom()` — a name that is not
   on it is REFUSED and the whole create fails, so `userPassword` cannot be
   written through the attribute door and `uid` cannot contradict the DN — and
   `options.invent`, which **defaults to TRUE so that every caller written
   before this gets exactly what it always got**.

   **THE TRAP IS THAT A PERSON IS INVENTED IN TWO PLACES AND ONLY ONE OF THEM
   IS OBVIOUS.** `applyVcAttributes()` is the one anybody would find.
   `namePlan()` is the one that bites: it puts a `cn`, `sn`, `givenName`,
   `displayName` and `mail` on the entry before `createUser()` has looked at
   its options at all. An implementation that switched off only the first would
   leave a page promising "no value is recorded" while five invented facts
   landed on every person created through it — and NOTHING WOULD LOOK WRONG,
   because the create succeeds and the fiction is visible only in an
   `ldapsearch`. `invent: false` drops both; the entry then carries its object
   classes, its `uid`, a description and what was typed.
   `tests/vendored/sts_admin_console.js` reads the entry back and asserts those
   five are absent, which is the assertion that whole change rests on.

   **IT IS NOT A PROMISE THAT THE ENTRY STAYS EMPTY**, and the page says so
   rather than leaving it to be discovered. `populateVcAttributes()` — the
   sweep behind Populate on `/admin/vc`, and the one run when a realm is
   created — fills every MISSING selected attribute on every person under
   `ou=users`, and it does not know or care which of them somebody typed. That
   is right for the sweep, whose whole job is that the directory and an issued
   credential agree; it means "no value recorded" is a statement about one
   create rather than a property of the entry.

   **AND SINCE 2026-09-06 THERE IS A SECOND WRITER, `setGroupWriter()`, WHICH
   IS `admin.js`'s TWELFTH SLOT.** It carries `createGroup()` and
   `addGroupMember()` — what `createUser()` is to a person, for a group — and
   it exists because until that day there was no by-hand door onto a group at
   all: `/admin/groups` and `/admin-api/groups` were both READS, so the only
   two ways to put a group in this directory were an `ldapadd` on the socket
   and `POST /scim/v2/Groups`. Rule 7 could not have caught that; a parity
   check is satisfied when both sides are missing.

   **The reason is worth keeping**: a parity check between the console and
   the management API is SATISFIED EXACTLY WHEN BOTH SIDES ARE MISSING, so it
   reports drift and is silent about absence. What found it was a test that could not be written —
   `tests/vendored/sts_directory_bulk_load_api.js`, named "through the
   management API", two of whose three sections would have had to reach for
   SCIM.

   **IT IS A SLOT OF ITS OWN RATHER THAN A THIRD ARGUMENT TO
   `setDirectoryWriter()`.** That one carries ONE function and every caller of
   it means "put a person in the directory"; widening it would have been a
   change to a slot four callers already fill correctly, to add something none
   of them wants.

   **SCIM STILL HAS ITS OWN GROUP INGRESS AND IS NOT ROUTED THROUGH
   `createGroup()`**, which is the one place this pair differs from the person
   half. That handler is SCIMMY-shaped — handed a resource, throwing
   `SCIMMY.Types.Error` with a `scimType`, and serving PUT and PATCH as well as
   a create — so making it call this one would mean `createGroup()` growing an
   update mode and a second error vocabulary. What the two SHARE is the part
   that could disagree: `groupDnFor()`, `nameUsableInDn()` and
   `writeGroupEntry()`. They agree about the store because they are the same
   three calls, not because anybody remembered to keep them in step.

   **THREE THINGS `addGroupMember()` DELIBERATELY DOES NOT DO**, and each is a
   rule stated elsewhere in this service that doing it would contradict. It
   does not refuse a member that names nothing — the SCIM ingress gives that
   argument in full and it is the same one: refusing would make the dangling
   state `/admin/groups` exists to report impossible to produce from this door.
   It does not write `memberOf` onto the person — nothing here maintains that
   attribute and `admin_rbac.js` refuses a revoke of a membership held that
   way, so this would be the one door creating a fact no other door can undo.
   And it does not nest-expand, because nothing in this service walks a group
   tree and a function that flattened on the way in would claim a feature that
   is not here. **It is idempotent**, which is `admin_rbac.js`'s `grant()`
   rule: a script that adds on every run must not fail on its second one.

   **`createGroup()` CREATES AN EMPTY GROUP AND RFC 4519 SAYS IT SHOULD NOT.**
   `member` is MUST on `groupOfNames` and `/admin/groups`'s own note says a
   real directory refuses one. This creates it anyway when no member is named,
   for one reason: SCIM already does, and a console stricter than SCIM about
   the same store would be two doors disagreeing about what this directory
   holds.

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

**AND THE TWO ADMIN CONSOLE ROLES WERE PINNED TO THE DEFAULT REALM UNTIL
2026-09-14.** `adminRbac.setDirectory()` was handed nine functions wrapped in
`inDefaultRealm()`, because a role was permission to change what every realm
does, so a per-realm roster would have meant anybody who can create a realm
granting themselves both roles inside it and walking back out into the default
one. **Since #32 each realm has a roster of its own**: `rosterViewFor(realm)`
builds the same nine functions bound to a named realm, the default view still
answers a caller that names none, and `admin-ui/admin_scope.js` confines a
realm's administrators to their realm — which is what answers the escalation
the pinning prevented (`admin-ui/CLAUDE.md` 8d).
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
out loud on `GET /admin/ldap/federations`, and it is part of why federation refuses by
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
identities whose VOLUME this service does not control.

**Since 2026-09-14 it is asked AFTER the entry is looked up, and off means "do not
create".** It used to return before the lookup and mean "a session and no entry" — so a
person PROVISIONED ahead of time, by SCIM, was never folded onto and never had a
partner's attributes written, and a session could have no entry to be the subject of.
Now an existing entry is used and updated, and a missing one is left missing for
`authn.startSession()` to refuse (`STS-AUTHN-0180`; the relationship's own page answers
`STS-FED-0090`). **`fedUpdateUserAttributes`** (on by default) is the second switch:
`applyFederatedAttributes()` takes `{ created }` and writes the partner's values on a
returning person only while it is on, while the three facts about where the person came
from are recorded either way. `tests/federation_provisioning.js` drives both shapes
through a real OIDC federated sign-in.

## `entryUUID`: THE ONE THING ABOUT AN ENTRY THAT NEVER CHANGES, AND A PERSON'S `sub` (2026-09-14)

**A person's `sub` is `urn:uuid:<entryUUID>` in both modes**, and a SCIM resource's `id`
is the bare `entryUUID`. Until this date `sub` was `urn:sts:user:<username>` — a rename
changed it, and a person deleted and re-created under the same name inherited it — and a
SCIM id was the DN, which a rename reassigned. `authn/CLAUDE.md`, *What an authenticated
identity is here*, carries the design and rcbj's choices; this is the directory's half.

| Rule | Where |
|---|---|
| **Assigned in `putEntry()` and carried through every overwrite** — taken from the entry already at that DN, never from the attributes a caller handed in, because most writers REBUILD the attribute set | `putEntry()` |
| **A rename keeps it**: `modifyDN` moves the stored object | the modifyDN handler |
| **A delete and re-create is a new value**: nothing at the DN to carry | `putEntry()` |
| **Seeded entries get a name-based (v5) UUID** over the realm and the DN; every other entry a random (v4) one. The seed runs on every start, so a random value gave alice a new `sub` per restart in memory mode | `backfilledEntryUuid()` |
| **A restored or replicated row without one is backfilled the same way**, so every process computes the same value without writing it back | `applyEntry`, `replaceRealm` |
| **NO-USER-MODIFICATION in BOTH modes** (RFC 4530 section 2): an add or modify naming it is `STS-LDAP-0076`, a modify replacing everything keeps it, `addValues()` and `applyFederatedAttributes()` never write it | `ALWAYS_PROTECTED_OPERATIONAL` |
| **Operational**: returned on a search only when asked for by name | `OPERATIONAL` |
| **Looked up through a validating index** — a hit is checked against the store, a miss rebuilds once per directory version, so a foreign subject cannot cost a walk per lookup | `entryByUuid()` |

**THE SUBJECT RESOLVER IS A SLOT THIS FILE FILLS**, `helpers.setSubjectResolver({
subjectFor, nameFor })`: `helpers.userFor()` asks for a person's `sub` and
`admin_stats.js`'s `identityOf()` asks who a `sub` names. Rule 3e's test answers yes both
ways round — `helpers.js` is a leaf this module requires, and a require the other way
would register every `/admin/ldap/*` route at #3. Both answer in the ambient realm and
only for PERSON entries. **A process with no directory has no subjects**: `userFor()`
gives `sub: ''` there rather than the retired name-derived form.

**A SUBJECT IS NOT A USERNAME, AND NOTHING IS CREATED NAMED AFTER ONE.** `createUser()`
refuses a `urn:uuid:` or bare-UUID name (`STS-LDAP-0090`) and `autoCreateUser()` creates
nothing for one (`STS-LDAP-0091`): `identityOf()` has already resolved every subject this
realm knows, so what arrives in that shape names nobody here, and an entry named after it
would be a second person answering to somebody else's subject. `locateEntry()` looks a
`urn:uuid:` up and never says where an entry "would go".

**`deleteOldRdn` IS HONOURED SINCE THE SAME DAY** (RFC 4511 section 4.9), on the socket
and through a dispatched operation (`operationRequest()` carries it). It was ignored, so
renaming `uid=alice` to `uid=alicia` left `uid: alice` resolving to the renamed person. A
rename of a person also calls `noteAccountChange('updated', …)` now.

**SCIM's four entry points take either an id or a DN**: `readPerson()`,
`readGroupEntry()`, `deletePerson()` and `deleteGroupEntry()` begin with
`dnForResourceId()`, and `groupsFor()` does too, so `/admin-api/groups?group=` answers a
SCIM id. `resourceIdOfDn()` is the other direction, for member and manager values.

**TWO PROCESSES THAT CREATE ONE PERSON AT ONCE KEEP BOTH VALUES** (the same day).
A request worker knows only its own store until replication reaches it, so two first
sign-ins by one person on two workers each assigned a random UUID, each issued tokens
under it, and the store kept the last row. `applyEntry()` asks `mergeCreateRace()` about
the row it is replacing: two creates within `CREATE_RACE_WINDOW_S` (60s) of each other
keep the LOWER value as `entryUUID` and the other on `stsEntryUuidAlias`, and a
microtask writes that answer back as this process's own write — after the replication
applier has recorded the row it applied, before any request can read the entry. Every
process reaches the same answer in either order and writes it back once. A RE-CREATE —
created long after the entry it replaced — is not merged, so a coalesced delete cannot
alias a deleted person's subject onto a new one. The alias is carried by `putEntry()` and
a modify, indexed by `entryByUuid()`, operational and client-unwritable like `entryUUID`.
Downstream, `authn.js`'s `sameIdentity()`, `person_assertions.subjectIsSelf()` and
`oauth2.js`'s refresh (which KEEPS the aliased `sub` its relying party holds) resolve an
alias to its entry.

**A RENAME MOVES THE PERSON'S ROW IN THE IDENTITY REGISTER**: the modifyDN handler calls
`stats.renameIdentity()`, and token, session and code records are filed by
`stats.holderKeyOf()`, which prefers a resolvable subject over the name they were made
under. **A modify of a row with no `createTimestamp`** — one imported or written by hand —
used to write `undefined` into it, and every SCIM list after that threw
(`Cannot read … 'slice'`); it takes the entry's `createdAt` or stays absent.

`tests/stable_subject.js` is the contract, in two processes for the determinism claims;
sixteen mutants across this file and the others the change touched, all caught, and
twenty more for the race, the rename and the timestamp.

## A CREATE WAS A FUNCTION OF DIRECTORY SIZE, AND THE USERNAME INDEX IS WHY IT IS NOT (2026-09-07)

`existingUserEntry()` is where the one-entry-per-person rule is ENFORCED: every
door that creates somebody asks it first, and a hit is a refusal. Its fast path
is a lookup at `uid=<name>,ou=users` and answers a RETURNING person in one Map
hit — **but it misses BY DEFINITION for somebody who is not there yet, which is
exactly what a create is.** So every create fell through to a walk of the whole
realm, comparing each entry's `uid` values and RDN value against the wanted
name, and five thousand creates walked a store that was five thousand entries
long by the end of it.

**THE 2026-09-06 BULK-LOAD BASELINE HAD ALREADY MEASURED THIS AND NOBODY READ
IT AS A DEFECT.** It records a create going from 9ms at the 500th person to 54ms
at the 5,000th, through all three doors, and calls it "not constant-time in
directory size" — which is true and is the symptom rather than the cause. A
create is not supposed to be a function of directory size. Driven in process
with no HTTP in the way, the walk cost 0.73ms at the 500th person and 13.45ms at
the 5,000th: 34 seconds for the five thousand, all of it on the one thread this
process answers every socket from.

With the index it is flat at 0.025ms — **0.14 seconds for the same five
thousand** — and the last person costs what the first did.

The index holds every name an entry under `ou=users` answers to, its `uid`
values AND its RDN value, against that entry's key in the store. Both, because
that is the pair the walk compared: an entry added by hand as
`cn=Alice Example,ou=users` carrying `uid: alice` was found under either, and an
index holding one of them would have quietly narrowed the rule it enforces.
First entry wins, because the walk stopped at its first hit and the store
iterates in insertion order — so the entry the index names is the entry the walk
would have returned.

**IT IS MAINTAINED INCREMENTALLY, WHICH `groupIndexNow()` BESIDE IT DELIBERATELY
IS NOT, and the difference is the shape of the load rather than a change of
mind.** A group index is read once per token and written rarely, so rebuilding
it on the first read after any write costs nothing. A username index is read and
written by the SAME operation — a create asks it, is told no, and then adds to
it — so a rebuild-on-write cache would rebuild once per create and leave the
quadratic exactly where it was.

**AND A STALE ANSWER IS STILL IMPOSSIBLE, BY THE MECHANISM THAT WAS ALREADY
THERE.** The cache carries the `directoryVersion` it is current for, and the
section below is the reason that is enough: every writer in this service is
required to call `touchDirectory()`, which bumps it. **Only `putEntry()` updates
the index in step, and only for a DN that held nothing** — every other writer,
every delete, every modify and every overwrite simply leaves the version behind
and the next read rebuilds. So a writer nobody hooked costs a REBUILD and can
never cost a wrong answer, which is what makes hooking one site rather than
fifteen the safe choice rather than the lazy one. It is the same bargain the
group index makes, taken one step further.

The `usersDn()` it was built against is kept and compared as well, which the
group index does not do. That container moves when `ldap.baseDn` changes and **a
settings change bumps no directory version at all** — so without it, changing the
base would leave an index describing a container nothing is in any more.

### And the index was defeated by nine version bumps, on the SCIM door only

The first implementation was correct and, on the `invent: true` path, no faster
at all — 0.63ms at the 500th person and 13.03ms at the 5,000th, which is the
quadratic exactly as it was. **That path is the SCIM door**: `scim.js` calls
`createUser()` without `invent: false` while `/admin-api` sends it, so the
management API went flat and SCIM did not.

`applyVcAttributes()` was the reason and the mechanism is worth keeping,
because it is the failure mode this whole arrangement is built to have. It
fills the attributes a credential claim set needs on a person who arrived with
none, and it called **`touchDirectory()` once per attribute** — nine bumps of
`directoryVersion`, immediately after `putEntry()` had folded that person into
the index. So the index was stale before the very next create, which rebuilt it
by walking the realm.

**Nothing was ever wrong, and that is the point.** The version check did its
job: a write it did not know about cost a REBUILD and never a wrong answer. What
it cost instead was the entire benefit, silently, on one of the three doors —
which is the honest price of choosing safety over hooking every writer, and the
reason the fix is a measurement rather than a bug report.

Two changes: one `touchDirectory()` for one logical change (nine schedules of
the persistence write became one, which is worth having on its own), and the
index is told the entry has GAINED names rather than left to rebuild.
`noteUsernameIndexRefresh()` is **only valid for a mutation that adds names and
removes none**, which is a precondition rather than a caution — this function
fills attributes that are ABSENT and never replaces one, and `uid` is among the
attributes it can fill. Any other shape of write must still leave the version
behind. Flat at 0.05ms after.

### And under it was a third one, in the GROUP index, on the same door

With the create flat at 0.05ms the SCIM door was still growing — 11.1ms at the
1,000th person and 46.7ms at the 5,000th, driven over HTTP. Measured in process,
a create ALONE was flat while **a create followed by `groupsOfUser()`** went
0.379ms at the 500th to 2.567ms at the 3,000th.

**A SCIM User resource carries `groups`**, so the bulk load asks for that index
once per person — and `groupIndexNow()` rebuilds on ANY write, which is the
right policy when reads are rare relative to writes and quadratic when a write
and a read are the same operation. The LDAP door never showed it because an
`add` builds no SCIM resource, and `/admin-api` never showed it because its
create response carries no groups.

The fix is the same shape as the username index's and rests on **a narrow
invariant that has to be stated, because it is the only thing making it safe**:
`buildGroupIndex()` calls `groupRuleFor()` on every entry and returns early on a
falsy one, so a non-group entry contributes to neither half of that index — and
a person's own `memberOf` is not in there either, because `groupsOfUser()` reads
it live off the entry and looks the value up in `byDn`. So a write of an entry
that is not a group by placement or by object class **cannot have changed the
index**, and `putEntry()` stamps the cache forward instead of leaving it to
rebuild. A group write — every membership change — still rebuilds, which is the
ordinary path.

Two details that are easy to get wrong. The `size` is stamped as well as the
version: that check is documented beside the builder as a second line of defence
against a writer that forgot to bump, and leaving it alone would have made the
whole stamp a no-op, since a create changes `entries.size` by definition. And
**the cache declaration moved up beside the username index's**, because
`putEntry()` now reaches it and `putEntry()` runs while this module is still
loading — the seeding does it — so a `const` declared further down the file
would not exist yet. The builder and `groupIndexNow()` stayed where they are.

**If either half of that invariant ever stops holding, the stamp has to go.**
Flat at 0.05ms after, and a group write is still visible to the very next
read — which is the property `groupsOfUser()` exists to keep and the one thing
here worth a test of its own.

### AND A FOURTH, WHICH IS THE SAME DOOR AND THE SAME LESSON A THIRD TIME

With the create flat and the group index kept, the SCIM door was STILL growing
over HTTP — 13.7ms at the 1,000th person and 48.0ms at the 5,000th — while an
in-process probe of `createUser()` plus `groupsOfUser()` was flat at 0.05ms. The
probe was not the shape SCIM uses.

**A SCIM CREATE IS TWO WRITES.** `scim.js` calls `createUser()`, which puts the
entry, and then `writePerson()`, which puts it AGAIN with the SCIM attributes
merged over it — and `putEntry()` is a SET, so the second one is an OVERWRITE.
The first implementation of `noteUsernameIndexPut()` declined to follow an
overwrite, which was safe and left the index stale at the end of every create
through that door. `/admin-api` and the LDAP socket never showed it because
neither writes twice.

**Why declining was tempting is worth keeping, because it is the hard half.**
The names the OLD entry answered to are still in the index, pointing at somebody
who may no longer have them. So an overwrite now takes them out — but only the
ones that pointed AT THIS ENTRY, because a name mapping to a different DN
belongs to whichever entry the walk would have found first and is not this
write's to remove. Then the current names go in.

**The state that exercises the removal is an ordinary one and not a contrived
one**: an entry whose RDN is not its uid, which is what a client certificate's
entry is (`cn=<CN>,ou=users`, carrying no uid until something writes one).
Where the DN is `uid=<name>,ou=users` the old uid is ALSO the RDN value and
survives the edit either way, so nothing is removed and a test built on that
shape cannot see the branch at all — which is exactly what the first version of
`tests/directory_indexes.js` did, and why a mutant that removed the removal
passed it. The measured shape — create, read back, write, ask for groups by DN —
is flat at 0.07ms.

### AND A FIFTH, ON THE SAME DOOR, WHICH WAS NOT AN INDEX AT ALL

2026-09-07. With all four of the above fixed the SCIM door was still quadratic
over HTTP, and by a wide margin: **5,000 creates in 197.6s, 8.18ms at the 500th
person and 39.42ms at the 5,000th**, while `/admin-api` did the same five
thousand in 4.1s and LDAP in 2.2s — both flat, both against a directory
*larger* than the one SCIM started against.

**That last clause is the tell, and the bulk-load jobs tell you not to look at
it.** Each of the three prints "compare the `users.create` row with a run that
started from a similar number, not with the other two doors' rows in the same
suite", because they run one after another against one directory nothing
deletes from. Here the caveat pointed the wrong way: SCIM runs FIRST, against
227 entries, and was forty times slower than a door reading ten thousand. When
a caveat and the numbers disagree that badly it is the caveat that needs
checking.

**The cause was not an index. It was a whole-realm sweep called once per
person.** `scim.js` ended a create with `directory.populateVcAttributes()` — the
function that walks every entry under `ou=users` TWICE and fills in the
attributes the credential claim set asks for. It was there for a real reason:
`createUser()` runs `applyVcAttributes()` on the entry it makes, and the
`writePerson()` that follows REPLACES the attribute set with SCIM's window
merged over it, so an invented value the client did not send is gone again.

What was wrong is the SIZE of the hammer. That function is exported with a
comment saying a batch of fifty creates should sweep once "and the caller is
what knows the batch is over" — and **SCIM has no batch**: every POST is one
create, so every create was a batch of one that swept the entire realm.
`/admin-api` and LDAP never called it at all.

`populateVcAttributesAt(dn)` is the batch-of-one case and is what that line
calls now — the sweep's own two membership tests applied to the one entry, then
`applyVcAttributes()`. The sweep is untouched and still right for the two
callers that mean every entry: startup, and a change to WHICH attributes the
claim set asks for, which is a fact about the directory rather than about one
person. **197.6s → 58.2s** in the suite's own job.

### AND A SIXTH, WHICH WAS NOT THIS DOOR'S AT ALL: the access gate's three walks

The SCIM door was still growing after that — 4.73ms to 19.71ms across 5,000 —
so it was profiled rather than reasoned about (`node --cpu-prof` writes nothing
for this service; use an `inspector.Session` wrapper). **`normalizeDn` was 24%
of all non-idle CPU**, called from three places that each walked the whole realm
and tested every entry with `isUnder()`: `allPolicies()`, `allRoles()` and
`applicationEntry()`'s by-identifier fallback.

**None of those is SCIM's.** The XACML access gate asks for the policies and the
roles on EVERY gated request, so every call to `/scim`, `/admin`, `/admin-api`,
`/portal` and `/xacml` walked the directory three times — to read a few dozen
policies and roles out of a store holding thousands of people. The bulk load
only made it visible by doing it five thousand times against a directory that
was growing underneath it.

**IT COULD NOT BE KEYED ON `directoryVersion`, AND THAT IS THE WHOLE DESIGN.**
Every writer bumps that, so a policy listing keyed on it would be invalidated by
every person created — which is precisely the load it is expensive under. It
would have been correct and worth nothing, which is this file's own failure
twice over already. So the clock is PER CONTAINER: a write records the version
against every ANCESTOR of the DN it landed on, and a listing of `ou=policies`
stays current until something is written under `ou=policies`. Five thousand
creates bump `ou=users` and the realm root five thousand times and never touch
the policy container.

**Invalidation is safe by default and that is load-bearing.**
`touchDirectory(dn)` takes the location OPTIONALLY. A caller that names where it
wrote gets a precise invalidation; **a caller that says nothing invalidates
every listing at once.** There are about thirty callers of that function here
and they are held to it by prose rather than by the compiler, so the failure
mode of forgetting to annotate a writer — or of adding a new one later — is a
slower cache and never a wrong answer. Only the two writers on the hot path
(`putEntry()` and `applyVcAttributes()`) are annotated at all; the other
twenty-eight behave exactly as they did.

Only ANCESTORS are recorded, never the DN written to: `subtreeVersion()` is only
ever asked about containers, and recording leaves would put one key in that map
per entry in the directory for nothing.

**5,000 creates over SCIM: 254.6s before either fix, 59.6s after the fifth, 7.7s
after this one.** 1.94ms at the 500th person and 1.40ms at the 5,000th — the
cost now FALLS as the directory fills, which is the JIT warming up on a
constant-time path, and is the shape the other two doors have always had.
`normalizeDn` is absent from the profile; what is left at the top is idle time,
GC, key generation and scimmy's own coercion.

### AND A SEVENTH: `allApplications()` WAS STILL A WALK OF THE REALM (2026-09-12)

The sixth section moved `allPolicies()`, `allRoles()` and `applicationEntry()`'s
fallback onto `entriesUnder()` and left `allApplications()` and
`applicationCount()` walking every entry in the realm. That was cheap while
nothing asked for the whole registry per request. Then `ssf/ssf_streams.js`
started asking — once per event, per stream, to find a stream owner named by an
`ssfReceiverId` — and a SCIM create emits an event per person. A dispatched bulk
load profiled with half a worker's CPU in `normalizeDn()` under
`allApplications()`, thousands of barrier timeouts behind it, and creates
slowing from 11/s to 5/s as the directory filled. Both use the cached listing
now. Measured in process with ~2,000 people: 200 `applications.list()` calls in
51 ms against 518 ms for the walk.

### The mutation record, and two mutants that were equivalent rather than missed

Caught: the group-index stamp applied to group writes as well (6 assertions
red, including the headline "the very next read sees it"), and an overwrite
that folds new names in without removing departed ones (2 red, one of them the
consequence that matters at the door — the departed name can be given to
somebody else).

**Two were equivalent and are recorded rather than counted**, per
`tests/CLAUDE.md`'s rule. Both mutated the REMOVAL loop — deleting
unconditionally, and dropping the "was it ours" guard — and both are
behaviour-preserving here for the same reason: the removal is immediately
followed by the loop that re-adds the entry's current names, so a name wrongly
removed is put straight back. The guard is defensive against a shape the
directory can hold and this suite does not build (two entries claiming one name,
the index pointing at the first, the second overwritten), and it is kept for
that rather than because a mutant demanded it.

### WHAT IS STILL QUADRATIC, MEASURED AND LEFT ALONE: a membership write read back

`addGroupMember()` followed by `groupsOfUser()` measured 4.69ms at the 200th
write and 8.46ms at the 1,000th, against a directory of 4,000 people. **That one
is inherent to the current design rather than an oversight**: a membership write
IS a group write, so it genuinely changes the index and the stamp above rightly
declines — and the read that follows rebuilds by walking the realm.

**It shows on the SCIM door and nowhere else, for the same reason the create did
and it is worth stating because it looks like a contradiction of the numbers
above.** The LDAP door writes 5,000 memberships at 0.19ms each because an
`ldapmodify` never READS the index — a rebuild is triggered by a read, not by a
write, so five thousand writes with no read between them cost one rebuild at the
end. `/admin-api` is 1.32ms for the same reason. SCIM is 31ms because its
response is a resource that carries the membership, so every write is followed
by a read.

**The fix, if it is ever wanted, is a genuinely incremental group index** —
a membership write touches exactly one group entry, so its contributions to
`byMember` and `byDn` could be withdrawn and re-added rather than the whole
thing rebuilt. That is a real piece of work rather than a stamp, because the
membership is asserted from BOTH ends and this service deliberately does not
reconcile them (see `claimedMembersOf()`), so an incremental update has to
handle a group that names a person and a person who names a group as two
separate edits. It was not attempted on 2026-09-07; the three fixes above were,
and this is the measurement that says where the next one would go.

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
and `/admin/ldap/directory` into the express router at that point — the exact failure
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
`/admin/ldap/directory` showed all of them — and `/admin/users` reported `known: 0`,
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

## A SIZE-LIMITED SEARCH SENT NO RESULT AT ALL, AND HUNG EVERY CLIENT (fixed 2026-09-06)

**This is the worst defect this module has had, it survived for as long as the
search handler has existed, and nothing in either suite could have seen it.**

`ldap.sizeLimit` is 500. When a search matched more than that, the handler
logged the truncation, wrote an audit row saying `resultCode: 4`, and did
this:

```js
return next();          // no res.end(), no error
```

A bare `next()` ends the handler chain **without sending any LDAP result
message**. So this server sent five hundred `SearchResultEntry` messages and
then no `SearchResultDone` — which RFC 4511 section 4.5.2 makes mandatory,
because it is how a search finishes. The client sat on an open connection
waiting for a reply that was never coming.

**IT WAS NOT SLOW, IT WAS STOPPED**, and that is what made it hard to recognise
from the outside: this process sat at 0.3% CPU beside a client that had been
waiting twenty minutes. An `ldapsearch` against a directory with five thousand
people in it never returned.

**THE COMMENT ABOVE THE BRANCH IS THE PART TO LEARN FROM.** It said, correctly
and at length, that a truncated search must be `refused` rather than `success`
because "the client has an INCOMPLETE answer and, unless it reads result code 4,
does not know it". The audit row said `resultCode: 4`. The log line said the
limit had been reached. **Nothing sent result code 4.** Three descriptions of a
behaviour and no implementation of it, agreeing with each other and with
nothing on the wire.

**WHY NOTHING CAUGHT IT.** Two facts, and it needed both:

* The seeded directory holds about twenty-six entries and every realm's holds
  twenty-one, so no search anywhere in this repository had ever reached the
  branch. `ldap.sizeLimit` is 500.
* **Until 2026-09-06 nothing here drove the raw socket at all.** Every other
  reader of this directory — the console, `/admin-api`, SCIM, the groups claim,
  `/admin/ldap/*` — comes in over HTTP and goes through this module's
  FUNCTIONS. The BER codec, the ldapjs submodule and the search handler's own
  result path were exercised by nothing.

`tests/vendored/sts_directory_bulk_load_ldap.js` supplies both — five thousand
entries and a one-level search over them — and found it in the first minute of
its first run. It is the guard now: the search that reaches the limit must END,
and its helper carries a deadline of its own so that a recurrence is a named
failure rather than a hang. (The same ldapjs gotcha bit the test: a search that
ends in a non-success code emits `error` and NEVER `end`, so a client that
resolves from `end` hangs too. Both halves are written up in that file.)

**The fix is `return next(new ldap.SizeLimitExceededError(...))`** — ldapjs
turns an error handed to `next()` into the `SearchResultDone` carrying its
result code, and that class IS code 4. The entries already sent stay sent, which
is what section 4.5.2 requires: they are a valid partial answer and the code is
how the client knows it is partial.

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
  SCHEMALESS on purpose, and `GET /admin/ldap/service` says so rather than leaving a reader to
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

### And the process that answers `/logout` usually holds no socket (2026-09-09)

Everything above is written as though one process owned the listener, the list
and the sign-out. Since 2026-09-07 that is the exception: `workers.dispatch`
sends `/logout` — and every other page — to a REQUEST WORKER, and a worker
binds no protocol port at all. Its `liveConnections` is therefore permanently
empty.

**That did not degrade the sign-out, it inverted it.** `boundConnections()`
answered "there are none"; the driver in `logout/logout.js` ends what
`collect()` finds; nothing was found, so nothing was ended and nothing was
reported — and a global logout said it had ended everything while a bound
connection went on being signed in. It was green in two modes of the suite and
red in the third, with `sts_global_logout` reporting only that the socket was
still open.

The two halves are fixed by two different mechanisms, because they fail
differently:

* **SEEING one** is a MIRROR. The front process pushes a snapshot — on a
  connection arriving, on one closing, and on a BIND, which is the event that
  turns an anonymous socket into somebody's session — and a worker's
  `boundConnections()` answers out of it. It is allowed to be stale by the
  interval between those events and the push, and what it may never be is empty
  on a service that has connections. A request-and-wait instead of a mirror
  would mean making `boundConnections()` asynchronous, and with it
  `terminate()` and all seven of its callers. **The snapshot is taken a TICK
  after the bind handler** (`publishConnectionsSoon()`), and that looks like a
  detail and is not: ldapjs sets the bound DN only once the handler chain has
  returned, and a snapshot taken any earlier belongs to nobody.
  `tests/ldap_logout.js` pins it.
* **CLOSING one** is an ASK, and it goes out **on the response** rather than
  over the IPC channel beside it. Only the process holding the socket can close
  it; the worker names the identity in a header, and the front process closes
  the sockets before it forwards a byte of the answer. That ordering is the
  whole point: a `process.send()` would arrive on a different channel from the
  answer it belongs to, so the client could be told a connection had ended
  while it was still open — the same bug, made rarer and harder to see.
  `common/request_pool.js`'s `LDAP_DROP_HEADER` carries the argument and
  `common/request_worker.js` holds the other end.

**An ask that cannot be made THROWS**, and that is deliberate: the driver
records the row as not ended, with the reason, where returning the rows would
report "the directory connection was closed" about a socket nobody had been
asked to close. A process with neither hook installed is one that holds its own
listeners and behaves exactly as this file describes above — which is every
process this service ran in until dispatching was turned on.

`tests/ldap_logout.js` holds all of it in process, and `sts_global_logout`
drives a real bind over 389 in the containerized stack.

### And across NODES, which neither mechanism reaches (2026-09-14, #46 section 4)

The mirror and the response header both stop at the front process of ONE
container. With several nodes in `cluster.mode=active-active`, a bind held on
node A was not listed by `/admin/sessions` answered by B, and a global sign-out
answered by B ended what B could see, said so, and left A's socket bound.
`ldap_cluster_connections.js` is the fix, and it is two things for the same
reason the in-container fix was two:

* **CLOSING is an INSTRUCTION BY IDENTITY.** `dropConnectionsFor(key)` first
  writes `ldap.clusterSignOuts[key]` (a shared minted row: the key, the instant,
  the writing node), and a global sign-out writes it even when nothing was
  listed — a bind another node accepted a moment ago has not reached any list.
  It rides the minted journal of the process answering the sign-out, which is
  the commit the cluster barrier holds that answer for. Every other node's
  replication applier hands the row to the store's `reconcile.restore`, and the
  socket-holding process there closes every connection bound as that identity
  (`closeLocal()` → `dropConnectionsFor(key, { localOnly: true })`). The front
  process acting on a worker's header passes `localOnly` too, so the
  instruction is written once. **It closes what is bound when the row arrives**
  rather than comparing a bind instant on A with a sign-out instant on B —
  two clocks, and the skew would let an older bind survive — which can close a
  bind made in the replication window after the sign-out (one reconnect, the
  safe direction). A node ignores its own instruction and any older than two
  minutes.
* **LISTING is a PER-NODE TABLE.** The socket-holding process writes
  `ldap.clusterConnections[nodeId]` — its bound connections without sockets —
  250ms after a connect, close or bind (a change noted while one is pending
  publishes again after it), and **flushes the minted journal itself**, because
  a socket event is not a request and nothing else would commit it; the first
  live run missed three binds of six for exactly that. `boundConnections()` is
  now this node's (`localBoundConnections()`: sockets or mirror) followed by
  other live members' rows, marked `remote` with a node-prefixed id.
  `connectionSnapshot()` publishes only the local half, so a remote row is never
  mirrored as this node's. A row of a node the last membership read does not
  list is not shown, and maintenance (every 15s) deletes it.

**A sign-out reports another node's connection as INSTRUCTED, never as
closed** (`pending: true` on the terminated entry, `acrossCluster` on the
result): the instruction is committed before the answer; the close happens when
that node applies the change log, after it. Outside active-active nothing here
writes or lists anything.

Measured against a real postgres, two product nodes, a bind over LDAPS held on
node 5 and a global sign-out through node 6's `/admin-api`: **active-active,
10 of 10 listed on node 6 within 215–330ms and 10 of 10 sockets closed 4–22ms
after node 6 answered**, with and without two request workers per node
dispatching HTTP; **`cluster.mode=off`, 0 of 10 listed and 0 of 10 closed in
the same probe**, which closes all of them when the sign-out goes to node 5.
The dispatched-LDAP run (`workers.dispatch=*`) could not bind at the time —
another change's asynchronous bind handler — so the dispatched-operation path
was not measured. `tests/cluster_signout_signals.js` sections 1–2 hold it in
process (three mutants caught).

## AND SINCE 2026-09-12 THE WORK ITSELF GOES TO A WORKER, AS AN OPERATION

The section above is about a sign-out reaching a socket a worker does not hold.
This is the other direction: **the seven directory operations now RUN in a
request worker**, with the front process keeping the socket and the framing.
`workers.dispatch` names which — empty by default, `ldap` for all of them,
`ldap.search` for one, `*` for everything. **It is the same setting that names
the dispatched HTTP paths**, and an entry says which it is by its shape: a
leading slash is a path prefix and anything else is an operation kind. It was a
second setting, `workers.operations`, for three days; the distinction was
artificial and the merge is argued in `common/request_pool.js`'s
`dispatchList()`.

**THE ROOT `CLAUDE.md` SAID IT "cannot be dispatched" FOR AN HOUR AND THAT WAS
WRONG**: the front process holds the SOCKET, which is a reason for it to do the
framing and not a reason for it to do the WORK. An OPERATION is the
protocol-independent half — the front process accepts the connection, decodes
the BER and writes the reply, and hands a `{ kind, args }` pair to a worker.

**THE CHANNEL HAD EXISTED SINCE 2026-09-09 AND NOTHING FILLED IT.**
`common/request_pool.js` offered `runOperation()`, `common/request_worker.js`
offered `register()`, the root `CLAUDE.md` said the LDAP protocol fanned out —
and no module in the tree called either function. Naming `ldap` in that setting
dispatched nothing at all. The prose described a mechanism and there was no
caller anywhere; this file is the caller. **What was actually true for three
days is worth writing down, because it is the shape of drift the root
`CLAUDE.md` is otherwise careful about**: every sentence there described a
mechanism and none of them described a caller. `tests/ldap_operations.js` is
what stops the table and the registrations drifting apart again.

**WHAT THE OLD PROSE GAVE AS THE REASON WAS ALSO STALE**, and it is worth
knowing which argument to stop repeating. `request_pool.js` said `ldap.*` must
not be dispatched "until the store behind them is shared", because a worker's
directory is its own and an add would fork it N ways. That was the
pre-coordination state. Directory changes are rows in `sts_changes` —
`persistence.js` registers `applyDirectoryChange`, which calls
`directory.applyEntry()` in every other process — and `request_pool.start()`
REFUSES to bring the pool up unless the store coordinates, with
the operation kinds inside the same list it checks. The configuration that
argument warned about stops the service rather than forking the directory. And
`/scim/v2` is already a dispatched HTTP prefix writing this same store, entry
for entry, through this same module's functions.

### A fake `req`/`res` here is not the thing `request_worker.js` refused

That file's header spends a page rejecting a fake `req`/`res` pair for HTTP:
`http.ServerResponse` has an enormous surface, the handlers use most of it, and
`app.js`'s response-flush CSP re-check hangs off the real object. **Every one of
those arguments is about HTTP.**

An LDAP response, as these seven handlers use it, is **three methods and one
property** — `res.send(entry)`, `res.end()`, `res.end(matched)` and
`res.messageId`. A request is a DN, a filter, a list of attributes and a handful
of scalars. No chunking, no content type, no header, no middleware rewriting the
body on the way out. So the pair is reproduced rather than proxied, and what
makes it faithful is not care: **a DN and a filter travel as the STRINGS they
arrived as and are re-parsed at the far end by the same ldapjs submodule**
(`ldap.parseDN()`, `ldap.parseFilter()`). That is the HTTP path's "node's own
parser at both ends" argument, transposed.

### Four things deliberately do not cross, and each is a different reason

* **`unbind`.** It ends the connection (RFC 4511 section 4.3), and a connection
  is a file descriptor the front process holds. There is nothing in it for a
  worker to do, and it is named in `DISPATCHABLE_OPERATIONS`'s absence rather
  than left to be inferred — `tests/ldap_operations.js` asserts it is not
  registered.
* **The bind's effect on the SOCKET.** The DECISION crosses — the refused
  password, the credential check, both audit rows — and
  `req.connection.stsBoundAt` and `publishConnectionsSoon()` stay in the front
  process, applied by `applyOperationResult()` when the worker says the bind
  succeeded. **This is the mirror of the bug the section above documents,
  pointing the other way**: a worker stamping its own copy of a socket it does
  not hold would leave `/admin/sessions` unable to date the session and every
  other worker's mirror showing the socket as unbound — so a global sign-out
  would find nobody to sign out.
* **The search is COLLECTED, not streamed.** The worker fills an array and the
  front process sends it. That cost is bounded by the thing that already bounds
  it: `maxSearchResults()` caps a search at `ldap.sizeLimit` whether it ran here
  or in a worker, so the array is never larger than an answer this service was
  already willing to build.
* **The `SearchEntry` message itself.** `toSearchEntry()` decides WHICH
  attributes go back — requested, operational, canonically spelled — and that is
  store logic, so it runs in the worker. What crosses is the plain
  `{ objectName, attributes }` inside it, and the front process builds the
  message with ITS OWN `res.messageId`. Sending the worker's would be exactly
  the "SearchEntry messageId mismatch" that function's header records having
  cost an afternoon.

### An error crosses as its NAME, and never as a hand-written code table

A worker cannot send an ldapjs error object. The first implementation mapped
result codes to constructors in a table here, which is a second copy of
something the submodule already states — right on the day it is written and
wrong about the tenth error somebody adds. `ldapErrorNamed()` looks the name up
on ldapjs's own exports instead and **checks what it finds**: it must be a
constructor whose instances carry a numeric `code`. A name that fails becomes
`OperationsError` (result code 1) with the original wording, logged loudly.

The check is not paranoia about our own worker. `createServer` is a real,
callable export of that module, so a lookup that asked only "is this a function"
would hand a client an ldapjs Server where an error belongs.
`tests/ldap_operations.js` probes exactly that.

### The result code is the whole of what a client acts on

Which is why the test compares a rebuilt refusal's `code` and `name` against the
same handler's refusal called directly, rather than checking that something went
wrong. An LDAP client's error handling is built around 32 and 68, not around the
sentence — a codec that rebuilt every refusal as a generic failure would change
every negative path in every client while a search test went on passing.

### A rejection is a refusal and never a second attempt

If a worker dies part way through an add it may already have written. Running
the handler in the front process as well would then refuse with
`LDAP_ENTRY_ALREADY_EXISTS` for an entry the client had just successfully
created — or, on a modify, apply the change twice. So a worker that fails
answers `LDAP_UNAVAILABLE` (52), which says what is true. **The fallback to
running here is only for the paths where nothing ran anywhere**: no pool, the
operation not named in `workers.dispatch`, no worker to take it — all three
resolve `{ dispatched: false }`, which is what `workers.requestCount = 0` means
and is a supported configuration rather than a degraded one.

### The wrapper goes on at REGISTRATION, beside the realm wrapper

For that wrapper's reason, stated one section up: seven bodies each remembering
to offer themselves to the pool is seven chances to forget, and **what was
forgotten would be invisible** — the operation would simply run in the front
process and everything would work, slightly slower, for ever.

The order of the two is load-bearing. The realm wrapper goes on FIRST, so
`LOCAL_HANDLERS` holds the realm-entering function and a worker enters the realm
of the DN it was handed exactly as the socket does. Wrapped the other way round,
a worker would run the raw handler with no realm ambient — which answers "no
such object" for entries that plainly exist, the failure that registration point
exists to prevent, reintroduced one layer out.

`registerWorkerOperations()` is called AFTER the seven `server.*` calls, for the
reason `sts_metadata.js` is required last: it reads what everything above it
registered. Called before them it would register seven operations resolving to
nothing, and every one would throw in the worker, where the failure reaches a
client as `LDAP_OPERATIONS_ERROR` and reaches a reader as nothing at all.

### They hold affinity to the CONNECTION, where the setting used to say they fan out

The setting's own description said a directory operation "carries its own DN
and credential and nothing about one has to be remembered to answer the next". True of one operation read alone; not the whole of it. RFC 4511 section
4.2 makes the connection the unit of authorization state and a client may have
several operations outstanding on one, so two consequences neither the change
log nor a credential-per-call covers:

* **A client reads its own writes on its own connection.** Over HTTP a caller is
  a series of independent requests; on one socket an `ldapadd` and the
  `ldapsearch` after it are one conversation. So an `ldapadd` followed by an
  `ldapsearch` down one socket is one conversation rather than two callers,
  and answering the second from a worker that has not caught up is a directory
  contradicting itself inside one conversation.
* **Order within a connection is the client's to rely on.** Fanned out, two
  operations sent back to back can be answered by two workers in either order.

**Affinity is still a locality measure and never a correctness one.** What makes
a dispatched write visible is the read barrier — `runOperation()` takes a ticket
and waits on the generation exactly as a dispatched path does, which it did not
until 2026-09-12: the barrier was built for HTTP and nothing took an operation
through it, so a dispatched operation was outside read-your-write entirely.

### What is asserted, and what is not

`tests/ldap_operations.js` is the in-process half: it drives both sides of the
codec against each other and against the seven handlers, with no port, no fork
and no container. Ten mutants, nine caught; the survivor is recorded there.

**The section it needed a second pass to get right is worth knowing about.** The
first version drove only `performOperation()` — the worker's half — so a
mutation in `applyOperationResult()`, which runs in the front process, passed
all 25 assertions. **The two halves are two functions in two processes and each
has to be driven**, which is the thing to remember when the KDC or the gRPC
surfaces are wired up.

What it does not do is bind 389 or fork a worker. The first is
`tests/vendored/sts_directory_bulk_load_ldap.js`'s, over a real socket, in three
stacks — and it remains the only job in either suite that touches this
directory's own socket at all.

---

## THREE ATTRIBUTES UNDER `ou=applications` NOW MEAN SOMETHING ONLY IN PAIRS (2026-09-01)

Every other attribute on an application entry describes the application it is
on. `oauthPermissionBaseUri` and `oauthPermission` (on the RESOURCE) and
`oauthDelegatedPermission` (on the CLIENT) do not: a grant is a fact about two
entries at once, joined by a string composed from a third attribute on the first
of them. `common/app_permissions.js` is what reads the two halves together and
`common/CLAUDE.md` argues the model.

**Nothing about this directory changed to take them.** They are rows in
`applications.js`'s `SCHEMA` like every other, so `GET /admin/ldap/applications`
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


---

## The five HTML views are ADMIN CONSOLE PAGES since 2026-09-01, and there are EIGHT of them since 2026-09-05

They were `/ldap`, `/ldap/directory`, `/ldap/applications`, `/ldap/federations`
and `/ldap/spiffe`: five pages in a shell written in this file, with their own
stylesheet, no sidebar, no breadcrumb, no realm switcher and no gate. They are
`/admin/ldap/service`, `/admin/ldap/directory`, `/admin/ldap/applications`,
`/admin/ldap/federations` and `/admin/ldap/spiffe` now, drawn in the console's
own shell through `admin.respond()`. **The old paths answer nothing** —
deliberately, rather than redirecting: `/admin/sts-metadata` is built by reading
the router, and a service that keeps a path alive forever is a service whose
endpoint list stops meaning anything.

**The move was about WHERE THEY BELONG and the gate came with it.** Every one
of these pages answers a question about what is in this service's directory,
which is the question the four pages under the console's *Directory* heading
already answer; the only thing that made them a separate surface was that they
happened to have been written here. Four things follow, and each is worth
knowing before touching any of it.

* **THEY ARE STILL BUILT HERE, and that is not a leftover.** A console page is
  a `path` and a `label` in `admin-ui/admin.js`'s `SECTIONS` whoever builds the
  body — `/admin/sts-metadata` is built by `../sts_metadata.js` and has been
  since 2026-08-24. Moving these bodies into that file would mean moving
  `description()`, `eachEntryInRealm()` and `entryObject()` with them, or
  exporting all three: the directory's own store belongs to the directory's own
  module.
* **THEY ARE GATED NOW, and that is the half of the change with a security
  argument behind it.** `admin.js` registers its gate as one
  `app.use('/admin', …)` above its own routes, and this module is required at
  #21, so a route registered here under `/admin` is behind it. A dump of every
  attribute of every entry prints `oauthClientSecret` and `fedClientSecret` in
  the clear, and these were the ONE surface in this service handing those to
  anybody who could reach the port while the console next door asked for a role
  to show far less. `/admin-api` mirrors all eight and takes an access token of
  its own since 2026-09-09, which is
  what a test drives and what somebody locked out of the console reaches for.
* **THE PAGING AND THE SHORTENING ARE THE CONSOLE'S, NOT THIS FILE'S.**
  `admin.pagedRows()`, `admin.pageNavPair()`, `admin.perPageOptions()`,
  `admin.clipped()` and `admin.tile()` are the same functions `/admin/tokens`
  and `/admin/applications` use, exported for the reason `page()`, `note()` and
  `tip()` are exported to `sts_metadata.js`. A control on one of these pages
  that behaved differently from the identical-looking control on the page next
  door would be the worst possible outcome of moving them here. **Do not write
  a paging control in this file.**
* **`/admin/ldap/service` IS DELIBERATELY NOT `/admin/ldap`.** That path is the
  LDAP / LDAPS SETTINGS page under *Protocols*, and the two answer different
  questions: that one says what the sockets are SET to and lets somebody change
  it, this one says what actually happened when the process tried to bind them.
  On a host whose own slapd already holds 389 the two disagree, and the
  disagreement is the whole value of having both. Each links to the other rather
  than restating it.

**The paging on `/admin/ldap/directory` is not a convenience.** That page prints
one row per entry with EVERY attribute of that entry in the last column, and
`ldap.maxEntries` is in the hundreds — so a service driven by a test suite for an
hour answered the old path with a document several megabytes long. Its filter is
over the WHOLE ENTRY and not only the DN, which is the one thing about it worth
stating: somebody looking for the entry that carries a particular thumbprint or
secret has the VALUE and not the name.

**A value too long for its column is SHORTENED and the whole of it is one hover
away** (`admin.clipped()`). The full value is a real element rather than a
`title` attribute, because a native tooltip cannot be SELECTED and copying a
client secret or a DN is the entire reason somebody hovers one — `admin.js`'s
comment above that function carries the argument, including why the `title` is
set as well and is not redundant.

**Rule 3e's NINTH SLOT is `admin.setDirectoryPages()` and this file fills it**,
with the eight view functions, so that `mgmt-api/admin_api.js` (19) can mirror
these pages without requiring this module (21) and dragging every route
registered here ahead of its own. It is validated WHOLE, so a name added to
`DIRECTORY_PAGE_NAMES` without a view is a refused install rather than one
operation answering as though no directory were loaded. See the root
`CLAUDE.md`.

## `oauthConsent`: the seventh slot, and the one attribute here that records an answer

`common/consent.js` owns the MODEL — the value's grammar, what "outstanding"
means, the global override, the register both console halves read. This module
owns the STORE, which is `oauthConsent` on an entry under `ou=users`. That
division is `group_claims.js`'s and `applications.js`'s: neither file knows the
other's half.

It is the SEVENTH `setDirectory()`-shaped slot this module fills at require
time and the second that hands over a WRITER as well as readers. Four functions,
validated whole, for `setLogoutReader()`'s reason: a filler that installed the
two reads and neither write would leave a service that draws the consent screen,
records nothing, and draws it again on the next request — a loop with a button
in it, every part of it working.

**NOTHING HERE CREATES AN ENTRY.** A consent is written for somebody who has
just authenticated, so `observeIdentity()` made their entry on the way past.
Where it did not — `ldap.autoCreateUsers` off, or an entry deleted between the
sign-in and the button — the write is REFUSED and says why, and `consent.js`
turns that into *they will be asked again* rather than into a failed
authorization. Creating a person here in order to file their consent would put
somebody in the directory that `autoCreateUsers` had just been set to keep out.

**THE IDENTITY ARRIVES NORMALISED.** `consent.js` runs it through
`admin_stats.js`'s `identityKeyOf()` first, which is the same normalisation
`autoCreateUser()` used to place the entry — so `alice`, `alice@EXAMPLE.COM`,
her `urn:uuid:<entryUUID>` and the retired `urn:sts:user:alice` reach
`locateEntry()` as one key and find one entry. A
second normalisation here would be a second opinion about who somebody is.

**A REMOVE THAT EMPTIES THE ATTRIBUTE DELETES IT.** LDAP has no empty attribute
— RFC 4511's modify with no values IS a delete — so leaving `oauthconsent: []`
behind would put a value on the wire no client can read as anything and would
show on `/admin/ldap/directory` as an attribute with nothing in it.

**IT IS NOT A CREDENTIAL AND IT GRANTS NOTHING.** It is a record of an answer,
read only by the authorization endpoint deciding whether to draw a screen. The
other half of the feature — `oauthGlobalConsent` — is on an APPLICATION's entry
and belongs to the applications schema rather than to this module's list of its
own invented names.

## THE THREE PAGES ADDED ON 2026-09-05, AND THE BUG THEY CAME OUT OF

`/admin/ldap/roles`, `/admin/ldap/policies` and `/admin/ldap/peps`. They are
built here for the same reason the other five are, and the specific fact that
made them cheap is that **this module already requires all three of the modules
that own those containers** — `common/roles.js` (247), `xacml/xacml_store.js`
(187) and `xacml/xacml_pep_registry.js` (188) — because it fills each one's
`setDirectory()` slot. The schemas were already in scope. No new require, no
cycle, no route moved.

**They closed a claim rather than adding a feature.** Each of those three
modules exports a `SCHEMA` whose comment says it is "Published on
`/admin/ldap/*` the way every other container's is", and for three of them no
such page had ever been written — the export was dead in `xacml_store.js` since
XACML phase two, in `xacml_pep_registry.js` since phase five, and in `roles.js`
from the afternoon it was written.

### What writing them exposed, which is the reason to chase a dead export

**`learnName()` had never been given those three schemas.** The store
lower-cases every attribute name because `@ldapjs/attribute` does, and
`entryObject()` un-lower-cases it from one table that each owning module
contributes its own spellings to — a merge `applications.js` has had for months.
Without it:

* `/admin/ldap/roles` counted a role's members by reading `roleMemberUser` off
  the entry and reported **`0 user(s)` for a role somebody plainly held**,
  because the store had `rolememberuser`.
* `/admin/ldap/policies` showed every policy's kind as `(unstated)`, and — worse
  — **drew a DISABLED policy as enabled**, because a missing `xacmlEnabled` is
  not the string `FALSE`.

Both are fixed by merging the three schemas into `learnName()` rather than by
reading case-insensitively at each site. **A lookup that silently misses answers
something PLAUSIBLE**, and these pages are not the only readers of these
entries: `?format=json`, `/admin-api/ldap/*` and the directory dump all see the
canonical spellings now.

The second one is the one to remember when writing the ninth page: the booleans
in this directory are `TRUE` and `FALSE` (RFC 4517's Boolean syntax, which is
upper case, and what those modules write). A page comparing against `'false'`
does not fail loudly — it overstates what is switched on.

**`federation.SCHEMA` WAS THE OLDEST INSTANCE OF THIS AND IS MERGED TOO**, in
the same change. It had never shown, which is why it lasted: that page draws its
columns from `federation.list()` records, and `federation.js` reads an attribute
CASE-INSENSITIVELY — `valueOf()` walks the keys — so the lower-cased spellings
surfaced only in the raw entry dump, beside a published schema saying
`fedSigningCertificate`. Which is exactly the symptom the applications merge was
written for: a page that reads as though IT were wrong, when what is wrong is
that the store lower-cases a name because `@ldapjs/attribute` does.

**A module defending itself is the defence in the wrong place**, and that is the
general lesson rather than a fact about federation. `federation.js` being careful
protects `federation.js`; the next reader of one of those entries — a console
page, an `/admin-api` operation, something not yet written — asks for
`fedEnabled`, gets `undefined`, and reports something plausible. That is the bug
the three merges above hit TWICE on the day they were written, in a container
whose owning module was equally careful. The spelling belongs in the one table
every reader goes through.

### What each of the three says that its console twin does not

* **roles** — that this container is HALF the feature. Membership is here;
  the requirement (`appRequiredRole`) is on the application entry. And that the
  six built-in roles are in NO container, so an empty `ou=roles` is the ordinary
  state of a service refusing nobody.
* **policies** — that a write over LDAP **skips the typechecker**. Every write
  through `/admin/xacml` and `/admin-api/xacml` is statically validated so a
  policy that does not typecheck is refused at write time; an `ldapmodify` of
  `xacmlPolicyDocument` reaches the entry directly, and nothing caches these
  entries.
* **peps** — that almost everything in it is a RECORD rather than
  configuration, which is what it has in common with `ou=agents`; that an
  identity there came from the CLIENT CERTIFICATE and never from the body; and
  that an empty container is not a feature that is off, because a PEP pulls and
  converges without ever registering.

## `stsTotpCredential`: THE ONE ATTRIBUTE HERE THAT MAY HOLD A USABLE CREDENTIAL (2026-09-10)

The authenticator app's shared secret, beside `userPassword` and
`stsWebauthnCredential` on the person's own entry. `readTotp()` and
`writeTotp()` are the two functions `common/credentials.js` reaches through the
slot this module fills, and `persons()` beside them is what
`secondFactorHolders()` walks for the roster on `/admin/users` — which was
`/admin/mfa` for a few hours on 2026-09-10.

**SINGLE-VALUED, where the security key beside it is multi-valued**, and the
reason is in the protocol rather than in a policy: a WebAuthn assertion names
the credential that produced it, and a TOTP code is six digits and names
nothing. `writeTotp()` therefore ASSIGNS, so enrolling again replaces; a `null`
value deletes, which is what an operator's Clear and a person's own removal both
come down to.

**AND IT IS THE ONE ATTRIBUTE IN THIS DIRECTORY THAT MAY HOLD A CREDENTIAL
SOMEBODY COULD USE.** `userPassword` and `stsActivationToken` are scrypt hashes
and are no use to whoever reads them; a WebAuthn public key is published by
design. **Verifying a one-time code means COMPUTING it**, so the secret cannot
be hashed — which is arithmetic and not a lapse, and is exactly why that
mechanism is a SECOND factor and can never be made a first one.

In PRODUCT mode the value arrives here already sealed under the key-encryption
key, so `/admin/ldap/directory` prints ciphertext; in development it is the
base32, because that mode's KEK would not survive a restart and sealing would
mean an authenticator that silently stopped working.

## `stsBackupCodes`: THE SECOND ONE, AND ITS REASON IS NOT ARITHMETIC (2026-09-10)

The recovery codes, on the same entry. `readBackupCodes()` and
`writeBackupCodes()` are the pair `common/credentials.js` reaches through this
module's slot, and they are shaped exactly like the TOTP pair above:
**single-valued** — `writeBackupCodes()` ASSIGNS, because a person holds one set
and never two, and a `null` value deletes, which is what an operator's Clear
comes down to.

**SO THE HEADING ABOVE IS NOW HALF TRUE AND THIS SECTION IS WHY.** There are TWO
attributes here that may hold a credential somebody could use, and the
difference between them is the thing to keep straight:

* `stsTotpCredential` **cannot** be hashed. Verifying a one-time code means
  COMPUTING it — that is arithmetic, and no decision was available.
* `stsBackupCodes` **could** be hashed, and is not. A recovery code is compared
  against a stored string exactly as a password is, so scrypt would work. What
  decided it is a product question: **may a person look at their remaining codes
  again?** This service says yes, on `/portal/mfa`, because a list shown exactly
  once at the end of an enrolment somebody is rushing through is a list most
  people close without reading — and the moment it matters is months later.
  `common/backup_codes.js` argues it at length.

That difference matters to a reader of an ENTRY rather than to this module,
which holds no key and only ever writes whichever of the two forms it was
handed. In product mode the value arrives already sealed and
`/admin/ldap/directory` prints ciphertext; in development it is the codes as the
person was shown them, because sealing under that mode's per-run key would mean
a printed recovery list that stopped working at the next restart — which is the
precise failure the mechanism exists to prevent.

**THE COUNTS ARE OUTSIDE THE CIPHERTEXT ON PURPOSE.** The value is one JSON
object: a sealed `vault` holding the codes, and `total`, `remaining`,
`generatedAt` and `lastUsedAt` beside it in the clear. Every page that reports
on this needs the counts and almost none needs the codes, so a console can say
*7 of 10 unused* about a set this process cannot decrypt.
`common/CLAUDE.md` argues both halves. **What is sealed is a question about the
KEY, and this module has none** — which is why the decision is
`credentials.js`'s and not this file's.

### Four spellings joined the catalogue and three of them predate this change

`stsWebauthnCredential`, `stsActivationToken` and `stsActivationExpires` had
been written since 2026-09-06 and were in neither `STANDARD_NAMES` nor
`OWN_NAMES`, which is the ordinary way that table goes wrong: nothing fails, the
name simply renders lower-cased on the one page whose job is to show an entry
faithfully, and the attribute reads as something a foreign client added rather
than something this service wrote. They were added with `stsTotpCredential`
rather than left, because a table that is right about the new attribute and
wrong about its three siblings is worse than one that is wrong about all four.

## THE USER PORTAL'S SLOT, AND THE ONE HOOK HERE THAT HANDS OVER A WHOLE ENTRY (2026-09-11)

`portal.setDirectory({ personEntry })`, filled at this module's require time
like the eight before it. `/portal`'s Overview draws every standard
inetOrgPerson attribute a person holds, and this is where it gets them.

**IT IS A SLOT FOR THE ORDINARY REASON** — that module is at 8b and this one at
21, so a require from there would register every `/ldap` route and all eight
`/admin/ldap/*` pages ahead of the authorization server and the console, and a
require the other way would move every `/portal` route behind the management
API. Rule 3e's test answers yes both ways round.

**IT HANDS OVER THE WHOLE ENTRY, WHERE `credentials.persons()` DELIBERATELY
HANDS OVER ONLY NAMES**, and reading the two beside each other is the useful
part. That one gives the credential store a list to ask itself about, because a
module holding whole entries starts reading attributes off them and that is how
a second implementation of *what an enrolment is* gets written. This one's
whole purpose IS the attributes.

**What stops the portal reading something it should not is therefore not the
shape of this hook — it is the FIXED LIST at the other end.**
`common/inetorgperson.js` has no `sts`-prefixed name on it and cannot grow one
by accident, which is why handing over everything is safe here and would not be
anywhere else.

It hands over a SHALLOW COPY of the attribute map rather than the stored object:
a caller holding the real one could write through it, and this module's contract
is that the store changes through `touchDirectory()`. A shallow copy is enough
because the value arrays are read and never mutated by anything that draws them.

### And the class definition is merged into `learnName()` like every other schema

`common/inetorgperson.js` is a fourth independently maintained list of LDAP
spellings — `STANDARD_NAMES` is the first, `vc_claims.js`'s catalogue and the
SCIM mapping the others — and it names most of the same types. Merged rather
than trusted, so a disagreement between the page a PERSON reads and the page an
OPERATOR reads is reported at startup instead of one of them quietly rendering
`seealso`. It agrees today; the merge is what will say so when it stops.

## `stsAssertion*`: THE THIRD THING ON A PERSON'S ENTRY THAT CAN BE READ BACK AND USED (2026-09-11)

Seven attributes and a slot of their own —
`personAssertions.setDirectory({ read, write, persons })`, filled at this
module's require time like the nine before it. A person may hold an **RFC 7523
signing key pair** now: `stsAssertionIssuer`, `stsAssertionJwks`,
`stsAssertionCertificate`, `stsAssertionCertificateChain`, `stsAssertionKid`,
`stsAssertionExpiresAt` and `stsAssertionPrivateKey`.
`common/person_assertions.js` (rule 3ab) owns what they MEAN — including the one
refusal the feature exists for, that a person's key may assert about that person
and about nobody else — and this module owns the store they live in, which is
the division `applications.js`, `federation.js` and the two XACML registers
already have with this file.

**SO THE TWO SECTIONS ABOVE ARE NOW THREE.** `stsTotpCredential` cannot be
hashed, `stsBackupCodes` could be and deliberately is not, and
**`stsAssertionPrivateKey` is a private key**: sealed under the key-encryption
key wherever that key outlives the process, in the clear in development where it
would not survive the restart the entry does, and `/admin/ldap/directory` prints
whichever of the two it was handed — this module holds no key and never has.
The other six are PUBLIC by construction: a certificate, a chain, a JWKS, a kid
and an expiry are all things a relying party is meant to be given, and the
declaration is a name.

**THE SLOT HANDS OVER CANONICAL SPELLINGS, WHICH NEITHER OF THE TWO SLOTS
BESIDE IT DOES.** `credentials.persons()` hands over NAMES so that a credential
store cannot start reading attributes; `portal.setDirectory()` hands over the
WHOLE ENTRY because its whole purpose is the attributes; this one hands over
exactly the seven, with their `stsAssertion` capitalisation restored. The
translation is on THIS side of the slot deliberately: the register then never
learns that this directory lower-cases an attribute name, which is the fact that
made `ou=roles` report `0 user(s)` for a role somebody held and `ou=policies`
draw a disabled policy as enabled.

**AND THE WRITE IS ONE ATTRIBUTE AT A TIME**, where `writeTotp()` and
`writeBackupCodes()` each write the one they own. That is not a shape
preference: `common/pki.js` hands a key pair over ONCE and keeps no copy, so a
write that half-succeeded is a key pair that is GONE with a certificate on the
entry claiming otherwise — and the caller has to be able to say which of the
seven failed. Single-valued and assigned, like every other attribute this
service writes here: two JWKS values would be two public keys under one
`stsAssertionKid`, and a verifier reading the second would be checking a
signature against a key nobody meant.

## `stsKrb5Keys`: THE FOURTH, AND THE FIRST THIS DIRECTORY WITHHOLDS FROM ITS OWN DUMP (2026-09-12)

A person's Kerberos long-term keys, derived from their password by
`kerberos/krb5_person_keys.js` so a product-mode KDC can authenticate them —
`stsKrb5Keys` (one sealed value: name, realm, kvno, salt, a stamp of the password hash,
every enctype's key) and `stsKrb5KeyInfo` (the public half). A service principal's
random keys are the same pair under `ou=applications`, `krb5ServiceKeys` and
`krb5ServiceKeyInfo`, which are rows in `applications.js`'s schema.
`kerberos/CLAUDE.md` argues the design; three things are this file's.

* **THE SLOT FOLLOWS THE AMBIENT REALM SINCE 2026-09-15**, where all six functions
  were wrapped in `inDefaultRealm()` before it. The reason for the pin — *the KDC's
  sockets and `krb5.realm` are the process's, so its people are the default realm's
  people* — went when each trust realm got a Kerberos realm and a principal database
  of its own (#33): the KDC ENTERS the realm a request is for, so the person it then
  reads is that realm's. Six functions, validated whole — the person read and write,
  the service read and write, and the two lists.
* **THE WRITES GO STRAIGHT ONTO THE STORED ENTRY**, both halves of a pair in one
  `touchDirectory(dn)`, so the public half never describes keys the secret half does
  not hold. For an application entry that bypasses `updateApplication()` on purpose:
  that function quotes the value it wrote in its audit summary and its reply.
* **THE DIRECTORY DUMP AND AN LDAP SEARCH WITHHOLD BOTH KEY ATTRIBUTES, CIPHERTEXT
  INCLUDED.** That is one step further than `stsTotpCredential` goes, and the
  difference is the reader: a TOTP secret is read back by the service that verifies
  a code, while nothing ever reads a Kerberos key back out of a page or a search — the
  KDC reads the store. So `/admin/ldap/directory` draws a sentence naming the length,
  and `toSearchEntry()` sends the same sentence. **An `ldapmodify` replace that writes
  that sentence back destroys the keys**, which the KDC then reports as unreadable; the
  next password set or verified sign-in makes new ones.

## PRODUCT MODE SEEDS THE TREE AND NOTHING ELSE (2026-09-12)

**`seed()` builds two things and only the first is structural.** The base and the
containers — `ou=users`, `ou=groups`, `ou=applications`, `ou=federations`,
`ou=policies`, `ou=roles`, `ou=peps` and the SPIFFE pair — are what every door that
provisions somebody writes UNDER, and they are seeded in both modes. Everything below
them is demonstration data and `mode.seedsDemoData()` decides it: `cn=admin`, alice, bob
and carol (carol's `employeeType: admin` is read by the seeded XACML policy),
`cn=developers` and `cn=directory-admins`, and the two PRIVILEGED identities
`cn=remote-pep-1` and `cn=xacml-user-1`.

**The two role GROUPS are seeded in product mode, EMPTY.** A predictable common name
printed in this repository, pre-admitted to the documents this service enforces its own
access with, is not a grant a deployment should inherit; an empty group is one member
away from admitting the real one. **And they are named by `roles.remotePepGroup` and
`roles.xacmlUserGroup` now, in every mode** — the seed wrote the literals `cn=remote-peps`
and `cn=xacml-users` while `common/roles.js` read the settings, so a renamed group was a
gate reading a group nobody seeded beside a seeded one granting nothing. An empty setting
(NOBODY holds the role) seeds no group; a name carrying DN syntax is warned about and
skipped. **`DN_RESERVED` moved to the top of this file for it**: `seed()` runs at require
time, and a `const` declared four thousand lines down does not exist yet when it does.

**The mode is read in the realm being seeded** — the process's at require time, and a
realm's own inside `realms.onCreate()`'s `realms.run()` — so a product realm created at
runtime gets a product tree.

## AND NOTHING GENERATED LANDS ON A PERSON

`mode.inventsClaimValues()` false stops all of it, at the choke points rather than at the
callers:

* **`applyVcAttributes()` returns false** — the one function the startup sweep, a realm's
  creation, Populate on `/admin/vc`, a SCIM create and a returning person's sign-in all go
  through.
* **`populateVcAttributes()` does not walk** and says so in its result (`skipped`), so the
  page behind Populate reports it rather than "0 entries changed".
* **`namePlan()` omits the five persona attributes** (`cn`, `sn`, `givenName`,
  `displayName` ending "(mock)", `mail`), and **`createUser()`'s `invent` is a ceiling**
  the mode imposes and no caller can raise — SCIM calls it with the default `true`.

## THE BIND AUDIT ROW SAYS WHAT HAPPENED

It said "no password was checked" on every successful bind, including every bind product
mode verified. It reads `credentials.verify()`'s own `reason === 'verified'` now, carries
`passwordVerified`, and words an ANONYMOUS bind as RFC 4511 section 5.1.1's unauthenticated
bind — unverified in both modes, which is the specification rather than a permission.
**`REFUSED_PASSWORD` stays refused in BOTH modes, deliberately**: it can only turn a bind
that would have been verified into a refusal, never the reverse, and `common/credentials.js`
refuses the same literal first at every door.

## THE SOCKETS

Both bind `global.host` (the literal `'0.0.0.0'` until 2026-09-12 — wrong in every mode).
**`ldap.plainListener`** (default on) leaves 389 unbound when off: `whenReady` RESOLVES
with `port: null`, `listenError` records that it was switched off rather than failed, and
LDAPS is the only way in. Product mode with it on is WARNED about at startup, because a
verified simple bind on 389 is a real password in the clear. **LDAPS takes `tls.minVersion`
and `tls.ciphers`** from `tls_server.js`'s `protocolOptions()`, at construction and again
in the `setSecureContext()` re-key.

`tests/ldap_tls_product_mode.js` holds all of it in child processes (the directory is
seeded at require time in the mode the process starts in); mutation-tested against the
demo gate forced on.

**THE PROXY PROTOCOL (2026-09-14, #46).** With `global.proxyProtocol` at `v2`,
`listen()` installs `common/proxy_protocol.js` on `plainServer.server` and
`secureServer.server` — the `net.Server` and `tls.Server` ldapjs built — before
each binds, so the header comes off before the first LDAP message and, on 636,
before the handshake. Nothing in this file reads the address differently: ldapjs's
`c.ldap.id`, the bind limiter and every audit row read the connection's
`remoteAddress`, which that module has already set to the header's source.
`tests/proxy_protocol.js` 3k holds it through a real ldapjs server and a hand-built
BindRequest. Found while probing it, NOT fixed: `secureServer.once('error')` above
is still attached after a successful bind, so the first ldapjs `error` the LDAPS
server emits later — a client's malformed BindRequest is enough — is logged as
`STS-LDAP-0028` "could not bind" and sets `tlsListening` false on a listener that
is still answering.

## `ou=passwordPolicies`, `pwdHistory`, AND THE ONE DOOR THAT WROTE A PASSWORD IN THE CLEAR (2026-09-12)

**A NINTH CONTAINER**, seeded in both modes beside `ou=roles`, holding the
password policy's profiles — `cn=default` only, and only once somebody saves it.
`common/password_policy.js` owns the schema and fills nothing here but a slot:
`allPasswordPolicies`, `writePasswordPolicy` (REPLACES, and puts the container
back if a restored directory predates it) and `deletePasswordPolicy`. Its
attribute spellings — both the profile's and the two it maintains on a person —
are merged into `learnName()`, which a mutation run showed is what makes the
entry come back as `pwdMinLength` rather than `pwdminlength`; the policy's own
reader looks both ways and would not have noticed.

**`pwdHistory` AND `pwdChangedTime` ON A PERSON**, in draft-behera's
`time#syntaxOID#length#data` form holding the previous scrypt HASH. The values
are built by that module and chosen by `credentials.js`; `writeStoredPassword()`
takes `options.history` as the whole history to leave (an empty array removes the
attribute, since LDAP has no empty one), stamps `pwdChangedTime`, and touches the
directory once for both. `readPasswordHistory` is a new member of the credential
slot, checked where it is used like the TOTP pair.

**AN LDAP ADD OR MODIFY OF `userPassword` STORED THE VALUE AS SENT**, in the
clear and past every rule the other four doors apply. `passwordWriteRefusal()` is
called by both handlers on the WORKING COPY, before anything is committed, so a
refusal leaves a modify atomic (RFC 4511 section 4.6). It runs the value through
`credentials.preparePassword()` and stores the hash, in BOTH modes — storing a
password in the clear is a storage defect, not a permissiveness. What differs by
mode: in product a pre-hashed `$scrypt$` value is REFUSED (a hash cannot be held
to a policy) and a change naming `pwdHistory` or `pwdChangedTime` is refused (a
history anybody can empty is not one); in development a pre-hashed value is kept
as given, which is how a directory moves between two instances. Two values, and
an unchanged hash written back, are handled before any of that. A refusal is
**LDAP_CONSTRAINT_VIOLATION (19)**, what a ppolicy server answers.
`tests/password_policy.js` drives both handlers in process.

## WHO MAY WRITE THIS DIRECTORY OVER THE SOCKET, IN PRODUCT MODE (2026-09-12)

**Nothing did until this date.** Product mode verified a bind, and the connection
that had proved who it was could then add, modify, rename or delete any entry in
any realm — `ou=trustAnchors` (the client-certificate truststore),
`ou=federations` (whose signing certificates decide whose assertions this service
believes), `ou=policies`, `ou=roles` and every person. **One write was an
escalation rather than vandalism**: `admin-ui/admin_rbac.js` reads a person's OWN
`memberOf` when it decides whether they hold a console role, so
`memberOf: cn=admin-write,…` written on your own entry made you an administrator
of the service.

`directoryWriteRefusal()` is called at the top of the add, delete, modify and
modifyDN handlers — BEFORE the target's existence is checked, so a refusal teaches
nothing about what is there — and `mode.authorizesDirectoryWrites()` decides
whether it asks at all. Three lines:

* **an anonymous connection writes nothing** (`STS-LDAP-0052`);
* **an administrator writes anything** — somebody whose bound DN names an entry in
  the DEFAULT realm's directory whose identity holds **Admin Write**
  (`STS-LDAP-0053` otherwise). **Since 2026-09-14 a realm's own administrator
  writes anything in THAT realm** (`boundDnIsRealmAdministrator()`): a
  non-default ambient realm, a bound DN naming an entry in it, and Admin Write
  on that realm's roster — never its open bootstrap window;
* **anybody else may MODIFY THEIR OWN ENTRY, and only the attributes
  `ldap.selfWritableAttributes` names** (`STS-LDAP-0054`). No add, no delete, no
  rename.

Every refusal is `insufficientAccessRights` (50). Four decisions are in it:

* **ADMIN WRITE, NOT A GROUP OF THE DIRECTORY'S OWN.** The console, the management
  API and SCIM's write scope already answer *who may change what this service
  holds*; a second roster for the socket would drift from the first the day
  somebody was granted one and not the other.
* **THE DEFAULT REALM, AND NO SEPARATE CHECK FOR IT.** The lookup runs in the
  default realm's STORE, and a DN under another realm's base is never an entry
  there. An explicit realm test was written first, mutation-tested, could change
  no answer, and was removed rather than left looking like the thing that decides.
* **THE CONSOLE'S EMPTY-ROSTER RULE DOES NOT COUNT.** While no role group has a
  member `rolesOf()` answers `open` and everybody holds both roles, which is what
  makes a fresh console reachable at all. Carried over, it would make every bound
  connection an administrator of the directory on exactly the deployment nobody
  has set up.
* **AN ALLOWLIST, BECAUSE THE DIRECTORY IS SCHEMALESS** and the names that matter
  look ordinary: `memberOf` grants the console roles, `employeeType` is what the
  seeded XACML policy decides on, `mail` and `cn` are asserted in tokens, and every
  `sts*` attribute is a credential. The default is contact details plus
  `userPassword`, which still meets the password policy in
  `passwordWriteRefusal()` — so a weak self-service password is 19 and not 50.
  A modify naming one allowlisted and one other attribute is refused WHOLE, which
  is RFC 4511's atomicity rather than an extra rule.

**DEVELOPMENT AUTHORIZES NOTHING**, on purpose: every bind succeeds there, so the
bound DN proves nothing and a check keyed on it would refuse the suite while
protecting nothing.

**AND A PASSWORD CHANGED OVER THE SOCKET DERIVES KERBEROS KEYS NOW.**
`passwordWriteRefusal()` hands back what it accepted and both handlers call
`credentials.passwordWritten()` once they have COMMITTED — before this, the only
doors that told the Kerberos key register about a new password were
`setPassword()` and a verified sign-in, so a password set with `ldapmodify` left
the person without usable keys until they signed in somewhere else.

**WHAT IT DOES NOT COVER IS READING**, which is the next section. That paragraph
read *search and compare are unauthorized in both modes* until the same day.
`tests/directory_write_authorization.js` holds the rule in process.

## HOW A CONNECTION BINDS AND WHAT IT MAY READ, IN PRODUCT MODE (2026-09-12)

**node-ldapjs decides nothing about security**, and that is the fact to start
from: it records the DN a successful bind handler named on the connection
(`conn.ldap.bindDN`, `cn=anonymous` until then) and leaves every rule after that
to these handlers. It has no access control, no attribute visibility, no StartTLS
on the server side, no SASL and no limit on guesses. The section above is the
write half; this is the rest, and the block headed *THE DIRECTORY'S READ AND BIND
SECURITY* in `ldap_server.js` argues each rule where it is enforced. Five
`common/mode.js` predicates decide whether each asks at all, and all five are
product mode only, for the write half's reason.

**THE BIND** — four refusals that come BEFORE the password is read, in this
order, because none of them should cost a guesser anything or count against a
caller refused for another reason:

| Refused | Result code | Code |
|---|---|---|
| an anonymous bind | 48 `inappropriateAuthentication` (RFC 4513 §5.1.1) | `STS-LDAP-0070` |
| any bind on the plain listener | 13 `confidentialityRequired` | `STS-LDAP-0071` |
| a DN with an empty password | 53 `unwillingToPerform` (RFC 4513 §5.1.2) | `STS-LDAP-0072` |
| a DN or address past its failed-bind limit | 53 `unwillingToPerform` | `STS-LDAP-0073` |

**THE RATE LIMIT COUNTS FAILURES ONLY**, which is why `websecurity.blocked()`
exists beside `attempt()`: a connection pool binds on every connection it opens,
fifty at once from one address, and counting successes would lock an application
out of its own directory for being busy. A caller over a limit is refused before
its password is checked, so a right guess during a lockout teaches nothing. **A
success clears its own DN's counter and NEVER its address's** (`keepAddress`) —
otherwise anybody holding one working password could bind as themselves between
guesses and never reach the address limit. The limits are the sign-in screen's
settings, `security.rateLimitPerIdentity` and `security.rateLimitPerAddress`.
**The client's address travels in the dispatched operation** (`remoteAddress`),
because a request worker has no socket to read it off and a stub without it
would put every dispatched bind in one bucket — which is one attacker locking
out everybody.

**ONE BUDGET FOR THE CLUSTER SINCE 2026-09-14 (#46 section 2).** Where a store is
shared the buckets are read with `websecurity.blockedShared()` and failures
counted with `attemptShared()` in `sts_cluster_windows`, so N nodes are one
limit rather than N (`common/CLAUDE.md`, *Several nodes: one rate-limit
budget*). That read is a round trip, so the handler finishes in `finishBind()`
when it is in, and marks the request `stsAsyncOperation`; `performOperation()`
then answers a PROMISE, which `request_worker.js`'s `handleOperation()` already
resolves. **With no shared store the bind is synchronous exactly as before** —
every in-process caller of `performOperation()` reads its answer in the same
tick. **Since 2026-09-14 the shared count also decides the ANSWER**: a failure
is counted and awaited (`failedShared()`), and one whose increment took a bucket
past the limit is refused as a lockout (`STS-LDAP-0073`) rather than answered
49; a verified password is answered only while the buckets are under the limit
(`succeededShared({ unlessBlocked })` — a read, so a pool binding fifty
connections costs nothing), the rest of the bind in `bindAccepted()`.
`common/CLAUDE.md`, *Several nodes: one rate-limit budget*, argues why these
doors verify before they reserve. `tests/cluster_limits_challenges_retention.js`
section F, `tests/cluster_followups.js` section H.

**THE PLAIN LISTENER STILL BINDS**, and answers the root DSE and nothing else in
product mode. Refusing a bind there cannot protect the password that was just
sent in the clear; what it does is make 389 a port where a correct password
never works, so no client gets configured to send one. `ldap.plainListener` off
is still the right production setting, and the startup warning says so.

**A READ REQUIRES A BIND** (`STS-LDAP-0074`, 50) — asked before whether the
target exists, so the refusal says nothing about the tree. **The root DSE is the
one read allowed first**: a client reads it to find the naming contexts before it
knows where to bind.

**CREDENTIALS NEVER LEAVE ON THE WIRE, THROUGH THREE DOORS.** `SECRET_ATTRIBUTES`
is a list, for the allowlist's reason read the other way. A search never RETURNS
one (`toSearchEntry()`); a search FILTER cannot SEE one (`matchableForReader()`),
which is the door a naive version misses — `(oauthClientSecret=a*)`, then `ab*`,
reads a secret out one character at a time off whether an entry came back; and a
COMPARE against one is refused (`STS-LDAP-0075`), because a compare is a password
check with no bind and no rate limit. **An administrator is not excepted**: every
reader that needs a credential goes through this module's functions, and a socket
that handed an administrator every client secret would make one stolen
administrator password every application's. The compare handler also stopped
logging the compared VALUE, which had been writing passwords to the info log.

**OPERATIONAL ATTRIBUTES ARE READ-ONLY** — `createTimestamp`, `modifyTimestamp`
and `entryDN` on an add or modify, administrator included (`STS-LDAP-0076`, 19,
RFC 4512 §3.3.1's NO-USER-MODIFICATION).

**WHAT IS STILL OPEN** is narrower and is `common/mode.js`'s
`directory-read-authorization` row: a connection that has bound as ANYBODY may
read every non-credential attribute of every entry in the realm its base names.
Deciding what a person, an administrator and an application may each read is a
design question rather than a hole.

`tests/directory_read_security.js` holds all of it in process, including the
filter oracle asked in both modes so the product-mode zero is a refusal, and was
mutation-tested against thirteen mutants, all caught.

## `stsSamlAssertion*`: A PERSON'S RFC 7522 KEY PAIR (2026-09-13)

Seven more names in `OWN_NAMES` — Issuer, Certificate, CertificateChain,
PrivateKey, Thumbprint, ExpiresAt, KeySource — plus `stsAssertionKeySource` on the
JWT set, and `stssamlassertionprivatekey` in `SECRET_ATTRIBUTES`, so product mode
neither returns it on a search, lets a filter see it, nor answers a compare against
it. Nothing else here changed: the slot's `read()` walks
`personAssertions.ATTRIBUTES`, which grew, and `write()` is one attribute at a time
already. `common/CLAUDE.md` 3ab carries the design.

## `stsMfaRequired` AND THE PASSWORD RESET LINK (2026-09-13)

Three person flags, in `PERSON_FLAGS` and `OWN_NAMES`: `stsMfaRequired` (a
second factor is required of this account), `stsPasswordResetToken` (a scrypt
hash of a reset link's token — in `SECRET_ATTRIBUTES`, so never returned or
matched over the socket) and `stsPasswordResetExpires`. The credentials slot
gained `readMfaRequired`/`writeMfaRequired`, `readPasswordResetLink`/
`writePasswordResetLink`, `personExists` (the create-and-reset doors need to
know an entry is there, and `credentials.hasEntry()` deliberately answers false)
and `clearPassword`, which is `clearStoredPassword()`: it deletes
`userPassword`, writes the history `credentials.removePassword()` computed,
stamps `pwdChangedTime` and calls `touchDirectory()`. **Removing the hash is
also what retires the person's stored Kerberos keys**, because
`krb5_person_keys.js` refuses keys whose password stamp no longer matches.

## SEVERAL NODES: A CREATE CLAIMS ITS NAME (2026-09-14, #46 section 3)

Every door that creates an entry asks this directory first (`getEntry(dn)`,
`existingUserEntry(name)`) and refuses a hit. On one node the check and the
write cannot be separated; on two they can, and two `POST /scim/v2/Users` for
`dave`, one to each node, both answered 201. The flush then keeps the FIRST add
and replaces the second node's copy with it (`persistence/CLAUDE.md`, *Several
nodes writing one row*) — the right repair, and a client already holding an id
that names nothing.

So the doors that can wait claim what they are about to create BEFORE they
check, through `directory_create_claims.js` over `cluster/cluster_claims.js`:
the normalised DN, and for a person the lower-cased username, both computed by
`createClaimSpec()` here. The second of two concurrent creates waits for the
first and then meets the directory's own refusal, exactly as if the first had
been visible; only a name still claimed after the wait is `STS-LDAP-0092`,
LDAP 68 / HTTP 409 — and a store that cannot be asked refuses at once (`STS-LDAP-0093`, LDAP 52 / HTTP
503 on `/admin-api`, 500 on SCIM, whose section 3.12 has no 503). The doors: an LDAP add (`claimingTheAdd()`, the OUTERMOST wrapper at
registration, so the process holding the socket claims whichever process runs
the handler), a SCIM create of a User or a Group, and `POST
/admin-api/users/create` and `/admin-api/groups/create`.

* **The claim guards the window, not the name.** It is released when the create
  is refused, and after the write is flushed when it succeeded — and the winner
  of a claim CATCHES UP with the store before its door checks, so whoever held
  the claim before it has committed and the ordinary check refuses a duplicate
  (without that, a request that arrived before the first create committed could
  win the released claim and ask a directory not yet holding the entry), and a person deleted and created again a moment later is not
  refused by the claim of their first life. The two-minute lifetime is only the
  ceiling for a process that dies holding one.
* **A create that finds its name claimed WAITS, then asks again
  (2026-09-15).** A claim is released after its create's flush, which is
  after its response — so the SAME client's next create of that name,
  sequential and not concurrent, found it still claimed and was refused 409
  `STS-LDAP-0092` instead of the directory's own "already exists";
  `sts_admin_api_operations` hit it in a dispatch run 70ms after its own
  create. `claim()` now gives back what it holds, waits `CLAIM_RETRY_MS` and
  claims again until `CLAIM_WAIT_MS` (5s); the winner catches up and its door
  meets the entry. **Two creates that really overlap therefore get one success
  and the directory's refusal (LDAP 68, HTTP 400 on `/admin-api`, 409
  `uniqueness` on SCIM) rather than 0092**, which is left for a holder still
  there when the wait runs out. A store that cannot be asked is not waited on.
  **Answering the first create only after its release was tried first and
  measured** — `/admin-api` creates went from 11ms to 37ms in the dispatch
  bulk load and SCIM from 28ms to 46ms, because the flush is a real commit —
  so the cost was moved onto the collision instead.
  `tests/cluster_followups.js` E2, E2b, E2c, E5 and E5b.
* **Inert unless several processes write one store** (active-active, or
  dispatched request workers on a shared store): no round trip on a single node,
  so a bulk load is as fast as it was, and the console's and admin API's create
  answer synchronously as before.
* **Claimed since 2026-09-14 too**: a SCIM Bulk create (in the ingress, which
  scimmy awaits — `scim/CLAUDE.md`) and the console's own forms, `POST
  /admin/users` and `/admin/users/new` and `POST /admin/groups` with
  `action=create`, through `runClaimed()` — synchronous where nothing can race,
  as the `/admin-api` doors are. "One person at a keyboard" was the reason they
  were left, and it is two administrators on two nodes as easily.
* **Still not claimed: an entry created by a SIGN-IN**, and the reason this file
  gave is half wrong since a person's `sub` became `urn:uuid:<entryUUID>`: the
  merge keeps the FIRST entry, so the node whose copy lost has issued a session
  and tokens naming a subject that names nobody. It stays unclaimed because
  `autoCreateUser()` is `recordAuthentication()`'s SYNCHRONOUS observer inside
  every protocol's credential check, and because it is development mode only
  (`mode.autoCreates()`), reachable with several processes in a development
  dispatch run or cluster. The synchronous fix — a name-derived `entryUUID` for
  an auto-created entry, so both nodes create the same entry — reuses a subject
  for a name deleted and signed in again, which is the identity model's owner's
  call (`authn/CLAUDE.md`). `directory_create_claims.js`'s header has it.
