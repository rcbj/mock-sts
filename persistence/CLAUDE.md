# CLAUDE.md — `persistence/`

## What is in here

| File | What it is |
|---|---|
| `persistence.js` | The driver interface, the mode selection, the diff, the flush scheduler, the restore, and the status object three surfaces render. A LIBRARY — it registers no route. |
| `persistence_ldif.js` | The `ldif` driver, and the RFC 2849 codec under it. `tests/ldif_codec.js` guards the codec. |
| `persistence_postgres.js` | The `postgres` driver: three tables, one transaction per flush, and a `pg_notify` nothing listens to yet. |

## The sentence this directory reverses

Every document in this repository said, in one wording or another, that this
service **persists nothing at all** and that everything is gone on restart. That
was true until 2026-08-27. It is not true now, and the replacement sentence has
to be said exactly, because a half-remembered version of it is worse than either
version:

**Three things persist when a store is configured.**

* **The embedded LDAP directory** — every entry under every realm's base. In
  this service that is also the applications registry, the federation register,
  the SPIFFE registry and the group roster, because those *are* directory
  entries and are not copies of anything kept elsewhere.
* **The trust realm registry** — the rows, their names, descriptions and
  per-realm overrides.
* **The runtime appconfig overrides** — the top of `config.js`'s five layers,
  the one a console Save or `POST /admin-api/config/set` writes.

**Nothing this service MINTS ever persists, in any mode.** Sessions, access
tokens, ID Tokens, refresh tokens, authorization codes, pre-authorized codes,
SAML artifacts, Kerberos tickets, the replay caches, the statistics and the
audit log are all still in memory and still gone on restart.

That is deliberate rather than unfinished, and there is one fact behind it:
**the signing key is regenerated on every start.** A token restored from a disk
would verify against nothing, an assertion would be a document nobody can check,
and a statistics file that outlived the key that signed the tokens it described
would be worse than none. So the rule is: **what persists is what somebody
TYPED, and what resets is what this process MINTED or COUNTED.**

`memory` is still the default. A run that says nothing about persistence behaves
exactly as every run before this existed — which is the whole compatibility
story, and is why not one job in the parent project's suite had to be told about
any of this.

## Why this is not a node-ldapjs feature

It is the first question anybody asks and the answer is that it cannot be.
`ldapjs` is a **protocol** library: a BER codec, a client, and a `Server` that
parses an operation and routes it to a handler you wrote. It ships no storage of
any kind and never has.

`node-ldapjs/lib/persistent_search.js` is a trap on the name — it implements the
LDAP *persistent search* change-notification control, which is about telling a
connected client that something changed, and has nothing to do with a disk.

The store in this service is ours and always was: `ldap/ldap_server.js`'s
`const entries = realms.map()`, a Map of normalised DN to
`{dn, attributes, createdAt, modifiedAt, origin}`.

## Why not a real directory instead

Standing up OpenLDAP beside this service and proxying to it would give
persistence for free, and it would **end the service**. This directory is
schemaless on purpose, accepts any bind, creates a person on first sight of any
name in any protocol, and is written into DIRECTLY by six other modules
(`admin_stats.js`, `applications.js`, `federation.js`, `spiffe_registry.js`,
`scim.js`, `group_claims.js`) as ordinary function calls. Against slapd every
one of those becomes a network round trip against a schema that would refuse
half of what they write.

So the store stays ours, and it learns to write itself down.

## Three modes, and the middle one is the one most people will use

| Mode | What it is |
|---|---|
| `memory` | Nothing is written, nothing is read, this whole directory is inert. **The default.** |
| `ldif` | Local development, where there is no database and nobody wants one. An RFC 2849 LDIF file per realm, plus `realms.json` and `appconfig.json`. |
| `postgres` | The shared store. Three tables, one transaction per flush. |

**LDIF for the directory and JSON for the other two** is a split by kind rather
than a compromise. A directory has an interchange format that predates this
service by thirty years and that every other tool speaks, so the file is
something `ldapadd -f`, `slapadd`, `ldifde` and a reviewer can all read — and
the answer to "how do I get this into a real directory" is "you already have
it". A realm registry and a map of overrides have no such format, and inventing
an LDIF spelling for them would be a private format wearing a public one's
syntax.

**What LDIF costs is `origin`**, this service's marker for how an entry came to
exist. It has no home in the format and rides as an RFC 2849 COMMENT —
`# sts-origin: seed` — immediately above the record. Every other reader ignores
it. The alternative was an invented attribute, which is worse in a way that is
easy to miss: an attribute would be REAL on reload, would appear in search
results, would match filters, and would turn a private marker into directory
content. `tests/ldif_codec.js` asserts both halves.

## The write path goes through one function

`ldap/ldap_server.js` already required every writer to call `touchDirectory()` —
the rule is stated at length above that function and exists because a reverse
index of group membership goes stale otherwise. So there was already ONE choke
point that every add, modify, delete, modifyDN, attribute append and typed
delete passes through, already documented, already enforced by prose, and
already the thing a new writer is told to call. This hangs off it.

The alternative was to instrument the fifteen-odd writers individually with a
"this DN changed" call. It would be more precise and **it would be forgotten**:
a new writer that forgets `touchDirectory()` produces a stale groups claim,
which is bad; a new writer that forgets `persist(dn)` produces an entry that is
in the directory until the process restarts and then is not, which is worse and
takes a day to find.

**What the choke point costs is that it does not say which entry changed**, and
the answer is a DIFF. This module keeps a shadow of what it last wrote — one
`JSON.stringify` per entry — and compares the live stores against it on each
flush. That produces exactly the upserts and deletes a database wants, catches
an entry a writer changed in place, and catches a realm going away: the realm's
whole store is dropped by `realms.map()`'s purge, so there is nothing left to
walk and the shadow is the only remaining record that its rows were written.

### The one bug this has had, and it lived in the shadow

`primeShadow()` is "what the store already holds", and the first flush writes
the difference between it and the live directory. The obvious way to prime it is
from the live directory — and that is exactly wrong, because it declares that
the store already holds everything. **On a first run, where the store is empty
and the live directory is the seeded tree, the first diff came out empty and the
seed was never written down.** The service reported a healthy store, `lastError`
was null, and the tables had nothing in them.

It hid because the two drivers make it look different. The ldif driver rewrites
a whole FILE for any realm the diff touched at all, so the handful of entries
that change just after startup dragged all nineteen into the file and the result
looked correct. Postgres writes exactly the rows in the diff, so the same run
put three rows in the table and it was obvious.

The shadow is now primed only for realms whose contents actually came OUT of the
store. A realm that was seeded rather than loaded gets an empty shadow, so every
one of its entries is new and is written.

## When the flush happens

Both modes schedule; they differ only in the delay.

| Mode | Delay | Why |
|---|---|---|
| `postgres` | 0 | Every change made while handling one request coalesces into ONE transaction that runs the moment that request's synchronous work is done. Write-through at the granularity anybody cares about, and what stops a bulk SCIM import from becoming one transaction per entry. |
| `ldif` | `persistence.writeDelay`, 1500ms | The unit of writing there is a whole FILE. A realm build writes thirteen entries; three of those in one file rewrite is the point of the delay. |

Both flush on the way out: `server.js` traps SIGTERM and SIGINT and calls
`stop()`. `kill -9` sends SIGKILL, which cannot be trapped by anything, and what
that costs is up to `writeDelay` milliseconds in ldif mode and nothing in
postgres mode.

## A failed write is logged and never thrown

The service keeps answering out of memory, `GET /ldap` and `/admin/persistence`
both carry the error, and the next flush recomputes the same diff — **the shadow
is only advanced on success**, so nothing is lost by a failure and the retry
needs no queue.

The alternative — refusing the LDAP operation whose write failed — was
considered and rejected: it would make a database outage take down sixteen
protocol families that do not need a database, and no other refusal in this
service is that expensive. This was verified by stopping the database under a
running service: the `POST /admin-api/users/create` succeeded, `/healthcheck`
answered 200, `/ldap` reported `healthy: false` with the connection error, and
when the database came back the next change wrote the entry made during the
outage along with the new one.

### AND A FAILED OPEN IS FATAL, WHICH IS THE OPPOSITE AND IS NOT AN INCONSISTENCY

`start()` rejects, and `server.js` exits non-zero without binding a listener,
when a CONFIGURED store cannot be opened or read — a database that is not
there, a data directory that cannot be written, a driver that will not load.
The heading above still holds for every write AFTER that.

The two are opposite because the states are. **A running service that loses its
database has already restored everything it was going to restore and is still
telling the truth about what it holds**; refusing its LDAP operations would take
down sixteen protocol families that do not need a database, which is the
paragraph above. **A process that never opened its store is answering out of a
SEEDED directory while presenting itself as the one that was configured** —
every endpoint works, the console draws, and the realms, applications and
federation partners somebody creates are thrown away by the next restart, which
is the restart they will do precisely because they expected the work to survive
it. The fallback was reported on `/admin/persistence` and in the log, and
neither is where anybody is looking while the service appears to be working.

This REVERSES what this repository said until 2026-08-28 — *a mock that refused
to start because a database blinked would be the one failure mode a mock must
not have* — at rcbj's ask, and the reversal is scoped: it applies to a store
that was CONFIGURED, so `persistence.mode=memory` (the default) reaches none of
it and a service nobody asked to persist behaves exactly as it always has.
There is deliberately NO setting to turn the refusal off: the way to run
without a store is to say so, which is the same one setting.

The failure message is built rather than thrown bare, because it is the last
thing an operator sees: it names the mode, what actually went wrong, and that
`persistence.mode=memory` is the way to run without one. `server.js` logs it at
FATAL and exits 1 rather than letting the rejection escape, so a stack trace
does not print over the sentence that says what to do.

**The compose file's `depends_on: condition: service_healthy` is what keeps
this from being a startup race**, and it was already there — its comment had
anticipated exactly this and argued for the wait on the other half of the
reason. The parent project's `tests/sts_persistence_postgres.js` asserts the
whole of this: that the process exits non-zero, that it never answered a
request first, and that the message names the mode, the cause and the way out.

## The wiring: two slots, one event, one plain require

Rule 3e says a slot is what you reach for when a require would close a cycle or
move a route, and that a sixth must not be added by analogy. There are two here
and neither is an analogy.

* **`config.setOverrideStore()`** (rule 3q), filled by this module. It reads
  `persistence.mode` and four more settings through `config.value()`, so it
  requires `config.js`; a require back closes that cycle, and node answers a
  cycle with a half-initialised module whose exports are `undefined`. The
  symptom would arrive later as "notify is not a function" from inside a console
  Save — the one place nobody would look for a require-order problem. It is a
  NOTIFICATION and not a store: it takes a realm id and returns nothing, because
  which of the two places a write belongs in is the thing only `config.js` can
  say, and it already makes that decision for its own purposes.
* **`persistence.setDirectory()`**, offered here and filled by
  `ldap/ldap_server.js`. This one is about ROUTE ORDER rather than a cycle: that
  module registers `/ldap` and `/ldap/directory` at its require time, and this
  module is required at #4a — far above `admin.js`. A require from here would
  drag both routes to the front of the express router, which is the exact
  failure rule 1 exists to prevent. It carries two functions, validated WHOLE
  when installed, for `admin.js`'s logout-reader reason: a half-filled slot
  would leave this module able to READ the directory and unable to restore it,
  which looks exactly like an empty database.

**`realms.onChange()` is an EVENT, not a third slot**, and the distinction is
worth keeping. A slot is a hole one module leaves for another to fill. This is
the opposite shape: this module REQUIRES `realms.js` in the ordinary direction
and subscribes. Nothing over there knows what persistence is, and a process that
never loaded this module has an empty listener list and behaves as it did.
`onChange()` exists because `onCreate()` and `onRemove()` covered only two of
the five doors into that registry — `update()`, `setOverride()` and
`clearOverride()` had no hook, because until a realm could be written down
nothing needed to know a name had changed.

**`realms.js` itself is a plain require** and fails rule 3e's test both ways
round: it registers no route, and it does not require this module.

## Restoring, and the one property that makes it safe to do it that late

`start()` runs from `server.js` after every module has been required and before
the HTTP listener binds. The order inside is a dependency order:

1. **The appconfig overrides**, first, because everything below reads settings.
2. **The realm rows**, because a realm has to EXIST before its directory can be
   loaded into it. They go back through `realms.create()` — the same function
   `/admin/realms` calls — so that every builder registered by every module
   fires exactly as it would for a realm somebody typed, including
   `ldap_server.js`'s, which seeds the realm's subtree. Anything else would be a
   second way to make a realm, and the second way is the one that is missing a
   step. `createdAt` is put back afterwards, because `create()` stamps it with
   now and for a restore that is a lie.
3. **The directory**, last, replacing what was seeded.

**Applying settings that late is safe for a reason that is a property of the
table rather than of the ordering.** Only a `runtime: true` setting can be
overridden at all — `checkOverride()` refuses every other by name — and a
runtime setting is BY DEFINITION one that is read per call rather than captured
at require time. So there is nothing in a saved override file that any module
could already have read and cached, and `global.https`, `oauth2.rfc9700`,
`ldap.port` and `ldap.baseDn` are exactly what the environment and the appconfig
file said. **A saved file cannot change the scheme this service answers on.**

Every saved value is re-checked rather than trusted: the file was written by
this service, but possibly by an older version of it, and a setting may have
been renamed, retyped, its enum narrowed or turned restart-only since.

## The bug the restore found, and it was not in this directory

A restored directory came back with twenty entries — `ldapsearch` and
`/ldap/directory` showed all of them — and **`/admin/users` reported
`known: 0`**. It reads as a failed restore and is a page reading a different
store: `/admin/users`, `/admin-api/users` and the user drill-down are driven by
`admin_stats.js`'s identity register, not by the directory.

Until 2026-08-27 that register could only be filled by somebody
AUTHENTICATING, and that was a complete account of how a person came to be
known, because until then a person could only come to be known that way. **A
restored directory is the first thing that ever put an entry under `ou=users`
without a sign-in.**

`admin_stats.js` gained `noteKnownIdentity()` for it, and the sentence it fills
the register with is the true one: `authentications: 0`, `knownBy: 'restored'`,
and `authenticated` FALSE on the row — which is what keeps `authenticatedHere`
counting sign-ins rather than people. **The counts are deliberately not
restored**: how many times somebody signed in, when they first did, which
protocols they used and every event in their drill-down are statistics about a
process, and this service's statistics have always been per process.

**A SEEDED PERSON IS SKIPPED.** alice, bob and carol are written by `seed()` on
every start and have never been in that register, so registering them on a
restore would make a fresh service list nobody and the same service after one
restart list three people who had still done nothing. A restored process's
`/admin/users` is now identical to a fresh one's plus exactly the people
somebody created or who authenticated.

**AND THE SAME GAP WAS ALREADY THERE ON THE CREATE PATH**, which is the part
worth knowing because it was not caused by this work and was found by it.
`createUser()` — reached by the console, `POST /admin-api/users/create` and a
SCIM create — wrote a directory entry and never touched the register, so a
person created by hand appeared on `/admin/users` NOWHERE until they signed in,
while that page's own description said "a person can be created here ahead of
their first sign-in". It calls `noteKnownIdentity(name, 'created')` now. The
early return in that function is load-bearing on the authentication path:
`recordAuthentication()` builds the record before it reaches the user observer
and `autoCreateUser()`, so without it somebody signing in for the first time
would be marked as not having signed in.

## The seam: what this is deliberately not yet

The ask was persistence, and persistence is what this is. **It is not
coordination.** Two processes pointed at one database each hold their own copy
of the directory in memory, each write their own changes down, and neither sees
the other's until it restarts. That is written here so it is found now, it is
stated on `/admin/persistence`, and `status().coordinates` is `false`.

What the next phase needs is already marked. `persistence_postgres.js` emits
`pg_notify('sts_ldap_change', …)` after each committed transaction, carrying the
realm, the DNs that moved and a process id; nothing LISTENs to it yet. It is
there rather than in the later change because the notification has to be inside
the transaction that made the change, so adding it later means editing that
function anyway.

The checklist, so the phase is a checklist rather than a rediscovery:

* A `LISTEN sts_ldap_change` on a connection of its own — a pooled client cannot
  hold a LISTEN, because the pool will hand it to somebody else.
* Applying the change to the in-memory Map rather than reloading the realm, and
  doing it inside `realms.run()` so the ambient realm is right.
* Ignoring this process's OWN notifications, which is what the process id in the
  payload is for.
* A decision about `ldap.maxEntries`, which is a ceiling on what this PROCESS
  holds and stops meaning that when the store is shared.
* The `directoryVersion` counter and the group index it feeds, which are
  per-process and would need bumping on an inbound change.
* **Nothing about tokens, sessions or codes**, which are not in this database
  and are not going to be: a token minted by one process is signed by that
  process's key, and the key is regenerated per start. Sharing a directory does
  not make two of these services one.

## Adding a driver

Implement the seven-function contract `persistence.js` calls —
`open`, `close`, `loadDirectory`, `loadRealms`, `loadOverrides`,
`saveDirectory`, `saveRealms`, `saveOverrides` — and add the mode to `MODES`
here AND to `enumValues` on `persistence.mode` in `common/config.js`. Those two
lists are two copies of one fact; `start()` checks them against each other and
says so rather than trusting them.

`saveDirectory()` is handed both a per-entry diff and the whole live picture. A
database driver uses `upserts`/`deletes`; a snapshot driver uses `all` and reads
the diff only for `touched`, the list of realms something actually happened in.
Rewriting only those is what stops a change in `acme` from rewriting the default
realm's file — which matters because these files are meant to be diffable, and a
rewrite with no change is still a new mtime.

**Require the driver's own dependency LAZILY**, the way the postgres driver
requires `pg`. A person running `ldif` — or the default `memory`, which is
everybody who has not asked for any of this — must not be stopped by the absence
of a package they will never use.
