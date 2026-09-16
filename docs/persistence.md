---
title: Persistence
nav_order: 13
---

# Persistence

Until 2026-08-27 this service wrote nothing down and everything was gone on
restart. Three things are not, now, when a store is configured — and the list of
what still is not matters just as much.

**Encryption is a page of its own.** What this service seals before a value
reaches a store, and what encrypts the rest of the database underneath it —
LUKS, ZFS, the forks that have TDE — is [Encryption at rest](encryption-at-rest.md).
That page also answers the two questions this one invites: there is ONE
key-encryption key for the whole service rather than one per trust realm, and
the DATABASE PASSWORD can come out of the same secret store as that key
(`persistence.databasePasswordProvider`) rather than out of the connection
string.

## What survives, and what never can

**This section had two columns until 2026-09-06 and now has three, because the
answer stopped being the same in every configuration.**

| Survives with any store | Also survives in **product** mode on **postgres** | Never does |
|---|---|---|
| the embedded **LDAP directory** — every entry under every realm's base | sessions, access tokens, ID Tokens, refresh tokens | nothing, beyond two caches that are re-derivable |
| …which is also the **applications registry**, the **federation register**, the **SPIFFE registry** and the **group roster**, because in this service those *are* directory entries | authorization codes, pre-authorized codes, SAML artifacts | |
| the **trust realm registry** — names, descriptions, per-realm settings | Kerberos principals and tickets, the replay caches (per trust realm since 2026-09-15) | |
| the **used-assertion history** — every RFC 7523 and RFC 7522 assertion accepted and not yet expired, so none is accepted twice across a restart (both modes; its own table on postgres, a file per realm on ldif) | | |
| **runtime setting changes** — what the console and `POST /admin-api/config/set` write | the statistics, the counters and the audit log | |
| the **signing keys**, encrypted (product mode only) | | |

### The middle column rests on one fact, and so did the rule it replaced

The old rule was **what persists is what somebody typed, and what resets is what
this process minted or counted** — and it was right for one reason: *the signing
key was regenerated on every start*, so a token restored from a disk would verify
against nothing, an assertion would be a document nobody could check, and a
statistics file that outlived the key that signed the tokens it described would
be worse than none.

**That is still exactly true in development mode, which is the default.** It
stopped being true in product mode, where `keystore.js` generates a realm's keys
once and reads them back — which is why product mode requires a store. A token
restored beside the key that signed it verifies, so restoring the rest of it is
honest.

Two conditions, both required:

* **`global.mode` is `product`.** Development persists nothing it minted.
* **`persistence.mode` is `postgres`.** The `ldif` store holds none of it in
  either mode and says so once at startup, because it writes *whole files* per
  flush — right for a directory somebody types into, wrong for a session table
  and an audit ring that change on every request.

`persistence.minted` turns it off; `persistence.mintedRetention` (7 days) is how
long a row is kept.

### Every minted row is encrypted

A session id is a cookie value. An authorization code and a pre-authorized code
are redeemable. A SAML artifact handle is dereferenceable. A Kerberos principal's
long-term key *is* the password. So each row's body is AES-256-GCM under **the
same key-encryption key that already protects the signing keys** — read from a
mounted file or one of four cloud secret stores, never from the database it
protects. A dump of `sts_minted` is not a set of live sessions and usable codes.

What that costs is that nothing in that table is queryable by SQL. That is the
trade taken deliberately: what wants querying is the directory, which is JSONB
and is not sealed.

## Turning it on

It is **off by default** — `persistence.mode` is `memory` — so a service you
start today behaves exactly as it always did until you say otherwise.

### No database: `ldif`

```bash
STS_PERSISTENCE_MODE=ldif STS_PERSISTENCE_DATA_DIR=./data node server.js
```

Writes one file per trust realm plus two small JSON files:

```
data/
  realm-default.ldif     the default realm's directory, RFC 2849 LDIF
  realm-acme.ldif        one per defined trust realm
  realms.json            the realm registry: names and per-realm settings
  appconfig.json         the runtime setting changes
```

**The `.ldif` files are ordinary LDIF**, which is the whole reason that format
was chosen over a JSON dump: `ldapadd -f`, `slapadd` and `ldifde` will all load
them into a real directory, and a diff of one is readable. A
`# sts-origin:` comment above a record is this service's own marker for how the
entry came to exist; every other reader ignores it.

Editing a file by hand is fine **while the service is stopped**. While it is
running, the next change rewrites the whole file and your edit is gone.

### A shared store: `postgres`

**The connection string already has a value**, so this is one setting:

```bash
STS_PERSISTENCE_MODE=postgres node server.js
```

The default `persistence.databaseUrl` is
`postgres://sts:sts@localhost:5432/sts`, which matches the Postgres service in
this repository's `docker-compose.yml` — user, password and database all `sts`.
Bring one up to match:

```bash
docker run -d --name sts-db -p 5432:5432 \
  -e POSTGRES_USER=sts -e POSTGRES_PASSWORD=sts -e POSTGRES_DB=sts \
  postgres:18
```

That plain container speaks TLS only if you configure it to; the compose stack
below does it for you and **requires** it. Against a database of your own,
either bring your own certificate or leave `sslmode` out of the connection
string and connect in the clear — this service does whichever the string says.

Point it somewhere else with `STS_DATABASE_URL`, or by editing
`persistence.databaseUrl` in your appconfig file — all four of them carry the
same base block.

Five tables: `sts_ldap_entries` (one row per entry, attributes as JSONB, keyed
by realm and normalised DN), `sts_realms`, `sts_appconfig`, `sts_keys` (the
signing keys, as ciphertext, in product mode) and `sts_schema`. Nothing is
migrated: if the schema ever changes, drop them.

#### Building it, and the role that cannot rebuild it

Against a database with nothing in it, this service creates the tables on its
first connection exactly as it always did — which is what the command above
does, and it needs a role that may create them.

**For anything you would leave running, build the schema separately:**

```bash
psql -v ON_ERROR_STOP=1 -f postgres/schema.sql "postgres://owner@host:5432/sts"
```

That script creates the tables *and* a second role — `sts_app` by default, or
whatever `-v sts_app_role=` and `-v sts_app_password=` name — which holds
`SELECT`, `INSERT`, `UPDATE` and `DELETE` on them and `USAGE` but **not**
`CREATE` on the schema. Point `STS_DATABASE_URL` at that role and the running
service can change every row in its store and cannot add, alter, truncate or
drop a table in it. The script is idempotent, so running it again is also how
you rotate that password.

The service notices: it asks which objects exist and issues a `CREATE` only for
one that is missing, so against a schema built this way it creates nothing and
needs no privilege to. If you point it at an *empty* database with the
restricted role it refuses to start and says so, naming the script — that is the
one arrangement this split cannot paper over.

**The compose stack below does all of this for you**, on the start that creates
the database volume. See the warning there about an older volume.

### With Docker Compose

`docker compose up` in the repository root does the second for you — it brings
up a Postgres container beside this service, with a named volume under each and
the `env/` directory bind-mounted so the appconfig files stay editable from the
host.

The database container runs `postgres/schema.sql` itself, once, on the start
that creates its volume — so the stack comes up with the schema built and with
this service connecting as the restricted `sts_app` rather than as the owner.
**A volume created before 2026-09-06 has the tables and no such role**, and the
service container then restart-loops with `password authentication failed for
user "sts_app"`. `docker compose down -v` is the fix, and what it removes is the
directory, the realm registry and the appconfig overrides — never anything this
service minted.

```bash
docker compose up            # start; the directory is there again next time
docker compose down          # stop, keeping the volumes
docker compose down -v       # stop and throw the data away
```

### The compose database is TLS, and requires it

Since 2026-08-30 the Postgres container generates a server key pair on its first
start and every `host` rule in its `pg_hba.conf` is `hostssl`, so a plaintext
client is refused by the database with `no pg_hba.conf entry for host …, no
encryption`. The connection string carries `?sslmode=require` to match.

The certificate is **self-signed**, because it is generated in the container by
something that has no CA to sign it. So the connection is *encrypted* and the
server is not *authenticated*, and `/admin/persistence` says exactly that in its
**Transport** row rather than showing one tick for two different facts. Turn
`persistence.databaseTlsRejectUnauthorized` on when you point this at a real
database whose certificate chains to something `NODE_EXTRA_CA_CERTS` names.

**Upgrading from an older stack needs `docker compose down -v`.** The image is
`postgres:18` now, and a major version will not read a data directory written by
the previous one — nor will it accept the old `/var/lib/postgresql/data` mount,
which is a single mount at `/var/lib/postgresql` from 18 onwards. Throwing the
volume away costs only what somebody typed: the directory, the realm registry
and the setting overrides. Nothing this service mints was ever in there.

## The settings

| Setting | Environment variable | Default |
|---|---|---|
| `persistence.mode` | `STS_PERSISTENCE_MODE` | `memory` |
| `persistence.dataDir` | `STS_PERSISTENCE_DATA_DIR` | `./data` |
| `persistence.databaseUrl` | `STS_DATABASE_URL` | `postgres://sts:sts@localhost:5432/sts` |
| `persistence.writeDelay` | `STS_PERSISTENCE_WRITE_DELAY` | `1500` |
| `persistence.realms` | `STS_PERSISTENCE_REALMS` | `true` |
| `persistence.appconfig` | `STS_PERSISTENCE_APPCONFIG` | `true` |

All but `writeDelay` are **restart-only**, because the store is opened and read
before the HTTP listener binds.

`persistence.databaseUrl` carries a password, so **it is never echoed back**:
`/admin/persistence` and `GET /admin-api/persistence` report the host, port,
database and user parsed out of it.

## Things worth knowing before you rely on it

### A failed write never fails a request

If the database goes away, the operation that triggered the write still
succeeds, this service keeps answering out of memory, and the status turns red
with the reason. The next change recomputes the same difference and tries again,
so a failure loses nothing.

That is deliberate: a database outage taking down seventeen protocol families that
do not need a database is the one failure mode a mock must not have. The same
applies at startup — a store that cannot be opened leaves this service running
with its seeded directory and says so, rather than refusing to start.

### A restored person has not signed in

Somebody restored from the store shows on `/admin/users` as **restored** rather
than as having authenticated. They exist — an entry, searchable over 389,
readable over SCIM, and a token issued to them carries their attributes — and
they have not signed in during *this* process, so they are not counted among the
sign-ins. Their counts and their event list are statistics, and start at zero
with everything else.

### Settings come back as runtime overrides, not as a new layer

A saved setting is applied at startup through exactly the same function a
console Save uses, so the [configuration layering](configuration.md) is
unchanged: it is still a runtime override, still above the environment variable
and the appconfig file, and *Reset* still means "fall back to what the file or
the variable says". A reset is written down too.

**Nothing ever rewrites an appconfig file.** A service that edited a file
checked into a repository would leave somebody's forgotten experiment behind
permanently. The file is what a person edits; the store is what the console
writes.

Only a runtime-changeable setting can be saved at all, which is what makes
applying them that late safe — no saved value can reach a bound port, the base
DN, or the scheme this service answers on.

### Realm keys never come back

A trust realm's row, its settings and its own directory are restored. **Its
signing key is not** — every realm's key is regenerated on every start, exactly
like the default realm's, so a token minted in a realm today verifies against
nothing tomorrow.

### Processes against one store coordinate

**This section said the opposite until 2026-09-06** — *"persistence is not
coordination… one process per store"* — and that was the honest description of
what existed.

Every change is now written to a monotonic log, `sts_changes`, **inside the
transaction that made it**. Each process remembers the highest entry it has
applied and asks for everything after it — the directory, the realm registry, the
runtime settings and the minted rows alike. A `LISTEN`/`NOTIFY` nudge wakes that
ask early.

**The log is the contract and the notification is only latency.** That is the
one sentence worth keeping, because it is what makes the hard parts easy: a
process whose listener dropped for four seconds misses nothing, the 8000-byte
notification limit stops mattering (the payload is a *pointer*, never a row), and
the database can restart underneath it. It is the same trade the remote XACML PEP
already makes about its own pull.

Turn it off with `persistence.coordinate`; `persistence.pollInterval` (5s) is the
worst-case convergence lag when a notification is lost.

#### What it does *not* share

* **Sockets.** The KDC, both LDAP listeners, the two TLS ports and SPIFFE's four
  are bound per process, and always will be. Coordination is about state.
* **The replay caches and DPoP `jti` sets converge rather than synchronise.**
  Between a write in one process and its arrival in another there is a window the
  size of the poll interval in which a proof one process refused is accepted by
  another. Sticky sessions at the load balancer close it; nothing here does.
  **The RFC 7523 / RFC 7522 used-assertion history does not have that window**:
  on postgres, recording a use is one atomic `INSERT … ON CONFLICT` in the table
  `sts_used_assertions`, so two processes can never both accept one assertion.
  A database built by an older `postgres/schema.sql` has no such table — run
  that file again as the owner; it adds the table and changes nothing else.
* **A realm's signing keys are not adopted mid-life.** A key changed in another
  process is logged and ignored here: taking it would strand everything this
  process has already signed. Rotation across processes is a rolling restart.

`/admin/persistence` reports all of it, and `status.replication` carries it in
the JSON.

## Checking on it

`/admin/persistence` in the console, `GET /admin-api/persistence` over JSON, and
`GET /admin/ldap/service` — which carries the same object and is not behind the console's
sign-in — all report which mode is in force, whether it fell back to memory
because the store could not be opened, where it writes, how much it holds, when
it last wrote, and what went wrong if that failed.
