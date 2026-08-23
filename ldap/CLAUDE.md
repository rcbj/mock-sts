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
   `/sts-metadata` sorts its rows by path within a group. Its embedded directory grows an entry under
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
   where the container is, how an entry is created and what the cap is. Note
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
   `GET /sts-metadata` is built by walking that router. So `admin.js` exports
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

   **A GROUP HERE GRANTS NOTHING**, and both pages say so where a reader will see
   it. No endpoint reads a group and nothing decides anything on one. The same is
   true of those three authentication-factor attributes, and of them it is true
   twice over — nothing reads them back and no token carries them either. On a
   service that authenticates nobody it could hardly be otherwise — but a console
   that listed groups beside the tokens page without saying it would let somebody
   conclude that adding a user to `cn=directory-admins` changed what their token
   could do.

   **A TOKEN DOES CARRY A GROUP NOW, WHICH IS A DIFFERENT SENTENCE** — see rule
   3d-ii and `groups.claim`, which is ON by default. `groupsOfUser()` here is
   what answers it, filled into `group_claims.js`'s `setDirectory()` slot at
   require time beside the four hooks above; it is the FIFTH and the same shape
   as the fourth. Do not merge the two sentences back together: carrying a fact
   is not acting on it, and no Kerberos PAC carries a group either way.


---

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
