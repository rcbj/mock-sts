---
title: Persistence
nav_order: 9
---

# Persistence

Until 2026-08-27 this service wrote nothing down and everything was gone on
restart. Three things are not, now, when a store is configured — and the list of
what still is not matters just as much.

## What survives, and what never can

| Survives a restart | Never does, in any mode |
|---|---|
| the embedded **LDAP directory** — every entry under every realm's base | sessions, access tokens, ID Tokens, refresh tokens |
| …which is also the **applications registry**, the **federation register**, the **SPIFFE registry** and the **group roster**, because in this service those *are* directory entries | authorization codes, pre-authorized codes, SAML artifacts |
| the **trust realm registry** — names, descriptions, per-realm settings | Kerberos tickets and the replay caches |
| **runtime setting changes** — what the console and `POST /admin-api/config/set` write | the statistics, the audit log |
| | **the signing key** |

The right-hand column is not a to-do list. **The signing key is regenerated on
every start**, so a token restored from a disk would verify against nothing, an
assertion would be a document nobody could check, and a statistics file that
outlived the key that signed the tokens it described would be worse than none.

The rule, in one sentence: **what persists is what somebody typed, and what
resets is what this process minted or counted.**

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

Three tables, created on first connection: `sts_ldap_entries` (one row per
entry, attributes as JSONB, keyed by realm and normalised DN), `sts_realms` and
`sts_appconfig`. Nothing is migrated: if the schema ever changes, drop them.

### With Docker Compose

`docker compose up` in the repository root does the second for you — it brings
up a Postgres container beside this service, with a named volume under each and
the `env/` directory bind-mounted so the appconfig files stay editable from the
host.

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

### Persistence is not coordination

Two processes pointed at one Postgres database each hold their own copy of the
directory in memory. Each writes its own changes down, and **neither sees the
other's until it restarts.**

Running several copies against one store is not yet a way to scale this service
— it is a way to have several services quietly overwrite each other. **One
process per store.** `/admin/persistence` says so on the page, and
`status.coordinates` is `false` in the JSON.

## Checking on it

`/admin/persistence` in the console, `GET /admin-api/persistence` over JSON, and
`GET /admin/ldap/service` — which carries the same object and is not behind the console's
sign-in — all report which mode is in force, whether it fell back to memory
because the store could not be opened, where it writes, how much it holds, when
it last wrote, and what went wrong if that failed.
