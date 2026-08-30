---
title: Configuration
nav_order: 3
---

# Configuration

**There is exactly one place a setting is read**, `common/config.js`, and one
table inside it. That is not tidiness — it is what makes the next three sentences
possible.

From one row in that table, a setting appears in the admin console — on the page
for the protocol it configures — in `GET /admin-api/config`, in the management API's OpenAPI
document, and in the startup audit that logs what the appconfig file omitted and
what key it carried that the table does not know. None of those four has a list
of its own. A `process.env` read added anywhere else is invisible to all four,
which is the state this arrangement exists to end.

## How a value is resolved

Five levels, first match wins:

1. **A runtime override** — set on the console page for that setting's protocol, or through `POST /admin-api/config/set`
2. **The environment variable**
3. **A legacy environment variable** — there is exactly one, `STS_ISSUER`
4. **The appconfig file** named by `CONFIG_FILE`
5. **`env/defaults.js`** — the default appconfig file that 4 is unioned on top of

Environment beating the file is deliberate: it is what keeps existing containers
and test harnesses working when the shipped `env/*.js` files carry every key.

**There is no sixth level.** A setting with no value in 4 or 5 and no variable in
2 or 3 **stops this service from starting**, naming every such setting and both
places its value could go. A value that arrives from a constant buried in a
module is a value nobody can find, change or see on a page, which is the state
this arrangement exists to end — so there is no silent fallback underneath the
table to lead back into it.

**Levels 4 and 5 are one layer, unioned.** `env/defaults.js` carries a default
for every setting; the file `CONFIG_FILE` names is merged over it key by key and
**the operator's value wins wherever both carry a key**. So a config file may
carry as few keys as its author likes and still be complete, and a setting added
to the table tomorrow does not break every config file in the world on the day it
is added. `env/defaults.js` is GENERATED from the table — `node
env/generate_defaults.js` — and is not the file to edit; to configure a
deployment, edit the file `CONFIG_FILE` names or set the environment variable.

**Every setting has an environment variable**, and three settings are exempt from
the refusal above because their default is DERIVED from a neighbour rather than
written in a file: `global.https` from `oauth2.rfc9700`, `oid4vp.walletUrl` from
`oid4vci.walletUrl`, and `krb5.serviceDomains` from `krb5.realm`. Each still has
its own key and its own variable, and setting either replaces the derivation.

A DERIVED DEFAULT IS NOT THE SAME AS AN ABSENT VALUE, and `global.https` is the
one where the difference is visible: the appconfig files in `env/` all set it
explicitly, so the derivation is what a service reading some OTHER file falls
back to and not what any stack here runs on. See its own section below.

The README carries the full table: every appconfig key, its environment variable,
its default and whether it can be changed without a restart.

`STS_ISSUER` is the one legacy level because it used to be a single value serving
as the SAML assertion issuer, the WS-Trust token issuer AND the WS-Federation
entityID. Those are three different things that happened to share a default — an
entityID names an identity provider, an Issuer names whoever signed an assertion
— so they are now `saml.issuer`, `wstrust.issuer` and `wsfed.entityId`, all three
still fed by `STS_ISSUER` when it is set.

## Runtime versus restart-only

Every row declares whether it can change while the service is running. **A
restart-only setting is REFUSED rather than accepted**, with the reason, because
an accepted change that does nothing reads as having worked.

Three kinds are restart-only and it is worth knowing which:

- **A bound socket.** Every port above, and the main port's *scheme* — see
  `global.https` below.
- **Material derived at startup.** The TLS certificate is issued for
  `tls.hostnames` / `tls.ips` at boot; the Kerberos principal database and every
  long-term key in it come from the realm, the SIDs and the passwords at require
  time.
- **The directory tree**, which `ldap.baseDn` is the root of.

Everything else is live. That is why so much of the code reads a setting through
a function call rather than a module-level `const` — a `const` captured at
require time is the one thing a runtime override cannot change, and it fails in
the direction that looks like the console is broken.

## The settings worth knowing about first

### `oauth2.rfc9700` — the compliance mode

Off by default. On, it turns the OAuth 2.0 / OIDC authorization flow into an
RFC 9700-conforming one: registered redirect URIs, PKCE, no implicit grant, no
password grant, refresh token rotation with replay detection, sender-constrained
tokens, one-shot authorization codes.

**Off changes nothing.** Every existing caller of this mock uses an unregistered
`redirect_uri`, no PKCE, or the implicit grant, and both answers exercise a
client — so the flag has to be able to be off and the mode has to be complete.

It is **restart-only**, and only because of a socket: `global.https` derives its
default from it, so turning it on binds the main port as HTTPS. A flag that was
runtime for its checks and restart-only for its socket would report the mode as
on while every authorization response still went out over plain HTTP.

What it does and does not enforce is published at `GET /oauth2/rfc9700`, row by
row, with `enforced` as `yes`, `detected`, `always`, `deployment` or `no` — two
requirements are `no` because they are the *client's* and nothing this server
observes can tell a client that checks from one that does not.

### `global.https` — TLS on the main port

**ON in every appconfig file this repository ships, since 2026-08-30.** That is
a statement about `env/local.js`, `env/test.js` and `env/docker-tests.js`, which
each carry `global.https: true`, and NOT about the setting's own default — that
still derives from `oauth2.rfc9700` and is still `false`, which is what a
service handed somebody else's appconfig file (the parent project's Kerberos
jobs, say) gets. Both compose files here set `STS_HTTPS` to the same answer, so
the container's healthcheck probes the scheme its service is actually bound in.

Why it was turned on: 8443, 9443 and LDAPS 636 were TLS and the main port —
the one every one of the sixteen protocol families actually answers on — was
not, so a caller who had already trusted this service's key for three sockets
still met an unencrypted fourth. One certificate, one trust decision, every
port.

`STS_HTTPS=false` is the way back to a plain listener, and it is a supported
configuration rather than an escape hatch: a client that cannot be taught to
trust a certificate regenerated on every start is exactly what this service
exists to exercise.

When it is on there is **no plain HTTP listener in this process**, which costs
one thing that is stated on the page rather than left to be met as a handshake
failure: `POST /tls/trust` and `GET /tls/server-certificate` exist to be
reachable *before* anything is trusted, so the first call to each has to be made
with verification off:

```bash
curl -k https://localhost:8081/tls/server-certificate > /tmp/sts.pem
export NODE_EXTRA_CA_CERTS=/tmp/sts.pem      # node trusts it from here on
```

It uses the same per-start certificate as 8443, 9443 and LDAPS 636, so a caller
trusts this service once per start rather than four times. `NODE_EXTRA_CA_CERTS`
accepts it despite its `basicConstraints CA:FALSE` — OpenSSL takes a self-signed
leaf found in the trust store as an anchor — and without it a node client fails
with `DEPTH_ZERO_SELF_SIGNED_CERT`, or, through `fetch()`, with a bare
`TypeError: fetch failed` that names nothing.

### `ldap.autocreateUsers`

On. Every identity that authenticates through any of the sixteen families gets an
entry under `ou=users`, seeded from a single funnel rather than sixteen call
sites. Turning it off gives you a directory holding only what somebody explicitly
wrote into it.

### `groups.claim` — and the reason it is safe to have on

On by default. It puts a claim naming somebody's group membership into every
access token, ID Token and both SAML assertions.

That is only defensible as a default because **the claim is omitted entirely for
somebody in no group** — absent, not an empty array. On a fresh start the only
people in a group are the three the directory seeds, so a caller who never
touched `ou=groups` gets exactly the tokens it got before the feature existed.

Nothing reads the claim back. No endpoint checks it and nothing decides anything
on it: carrying a group is not granting one. Two groups are the exception and are
not an exception to *that* sentence — `admin.readGroup` and `admin.writeGroup`
below are read from the directory by `/admin`, never from this claim, so a token
carrying `admin-write` still does nothing a token without it cannot.

### `scim.authRequired`, `spiffe.authRequired` and `admin.authRequired`

The three places this service enforces authentication at all. All on by default,
all three can be turned off, and each is explained under
[what is not checked](what-is-not-checked.md).

### `admin.readGroup`, `admin.writeGroup` and `admin.openWhenEmpty`

The console's two roles are two ordinary groups in the embedded directory —
`cn=admin-read` and `cn=admin-write` by default — so `/admin/rbac`, `POST
/admin-api/rbac/grant`, an `ldapmodify` and a SCIM `PATCH` all write the same
membership. **Write implies read.**

`admin.openWhenEmpty` is on and decides what happens while *neither* group has a
member: anybody who signs in holds both roles, and every page says so. It is on
because there is no password anywhere in this service to bootstrap an
administrator with and the roster dies with the process — off, and a service
started with an empty roster has a console no browser can reach. `/admin-api` is
not gated by any of these, which is the way back out of that.

Renaming a role group does not move anybody: the members stay in the old group,
which stops granting anything the moment the name changes.

### The federation settings, and the one that is stricter than a mock usually is

`federation.enabled` is ON, and that is safe in a way it would not be anywhere
else here, because the endpoints do **nothing** without a relationship: a partner
is created disabled, and one that is enabled and half-configured refuses rather
than half-working. Turning it off makes every `/federation` route 404 without
changing any relationship — the blunt instrument, for taking the feature away for
one test run.

`federation.usernamePrefix` is **empty by default, and that is a real decision
rather than a default nobody thought about.** Empty means a federated `alice` and
the local `alice` are ONE directory entry, which is right for a mock being
pointed at a partner to see what comes back — a prefixed name makes every
downstream token and assertion look unfamiliar. Set it to something like `fed-`
the moment the question is whether federated identities share a namespace with
local ones, which is the question it exists for. It is applied *after* the
username is chosen, so changing it cannot change which incoming value was used.

`federation.outbound` governs **the only outbound HTTP request this service
makes** — a partner's token endpoint, UserInfo or JWKS. Turn it off for a
deployment with no egress: SAML, SAML 1.1 and WS-Federation need no back channel
at all, and an OpenID Connect partner can still be used with
`fedResponseType: id_token` and its keys pasted into `fedJwks`.

`federation.outboundAllowInsecure` is **OFF by default, which is the one place
this service is stricter than a mock would ordinarily be.** What travels on those
requests is a client secret and an authorization code, at somebody else's
service. ON accepts an `http://` endpoint and a certificate nothing here trusts —
which is what federating against another mock on localhost needs — and every
request made under it is logged as insecure, rather than the setting being logged
once at startup and forgotten.

Everything else about a relationship is not a setting at all: it is an entry
under `ou=federations`, configured at `/admin/federation`, through `POST
/admin-api/federation/*`, or with an `ldapmodify`.

### Persistence

Since 2026-08-27 three things can survive a restart. **Nothing this service
mints ever does**, in any mode, and that is deliberate rather than unfinished:
the signing key is regenerated on every start, so a token or an assertion that
outlived it would verify against nothing.

| Persists when a store is on | Never persists |
|---|---|
| the embedded LDAP directory — which is also the applications registry, the federation register and the SPIFFE registry, because in this service those *are* directory entries | sessions, access tokens, ID Tokens, refresh tokens |
| the trust realm registry: names, descriptions, per-realm settings | authorization codes, pre-authorized codes, SAML artifacts |
| runtime setting changes — what the console and `POST /admin-api/config/set` write | Kerberos tickets, the replay caches, the statistics, the audit log |

| Setting | Default | What it does |
|---|---|---|
| `persistence.mode` | `memory` | `memory` writes nothing. `ldif` writes an RFC 2849 file per realm plus two JSON files in `dataDir`, and needs no database. `postgres` writes three tables. |
| `persistence.dataDir` | `./data` | Where `ldif` writes. Relative paths resolve against the package root, not the working directory. |
| `persistence.databaseUrl` | `postgres://sts:sts@localhost:5432/sts` | The connection string `postgres` mode dials. A local development default matching this repository's `docker-compose.yml`, so turning persistence on is one setting rather than two. Inert unless `mode` is `postgres`. |
| `persistence.writeDelay` | `1500` | How long a change waits before the `ldif` files are rewritten. Postgres ignores it and commits per request. |
| `persistence.realms` | `true` | Write the realm registry down too. |
| `persistence.appconfig` | `true` | Make a setting changed at runtime survive a restart. |

`memory` is the default, so a run that says nothing about persistence behaves
exactly as every run before this existed — which is why no test in the suite had
to be told about it.

**All but `writeDelay` are restart-only**, because the store is opened and read
before the HTTP listener binds. That ordering is also what makes restoring
settings safe: only a runtime-changeable setting can be overridden at all, and a
runtime setting is by definition one that is read per call rather than captured
at startup — so nothing in a saved override file can reach `global.https`,
`oauth2.rfc9700` or a bound port.

**A failed write is logged and never thrown.** If the database goes away, the
operation that triggered the write still succeeds, this service keeps answering
out of memory, and `/admin/persistence` and `GET /ldap` both carry the error.
The next change recomputes the same difference and tries again, so a failure
loses nothing.

**Persistence is not coordination.** Two processes pointed at one Postgres
database each hold their own copy of the directory in memory: each writes its
own changes down, and neither sees the other's until it restarts. Running
several copies against one store is not yet a way to scale this service. One
process per store.

### `oauth2.breakIdTokenNonce`

Off. On, it puts a deliberately wrong `nonce` in every ID Token and logs that it
did. It is **not** part of RFC 9700 mode and must not be folded into it — a
compliance flag that also breaks tokens is a flag nobody will turn on. It exists
because "the client must validate the nonce" is a requirement no server can
check, and a reachable negative is the only way to find out whether a client
does.

### The four token lifetimes

| Setting | Default | Allowed |
|---|---|---|
| `oauth2.accessTokenTtlS` | `3600` (one hour) | 30–2592000, in steps of 30 |
| `oauth2.idTokenTtlS` | `3600` (one hour) | 30–2592000, in steps of 30 |
| `oauth2.refreshTokenTtlS` | `86400` (twenty-four hours) | 30–2592000, in steps of 30 |
| `oauth2.clockSkewS` | `30` | 0–300, in steps of 30 |

All four are runtime settings, read per token, and they are drawn twice: with
the rest of the `oauth2.*` rows on `/admin/oauth2`, and on a page of their own at
`/admin/token-lifetimes` that puts them beside a count of what has already
expired. Both write through the same function — one store, two doors.

Set one low and the next token dies on cue, which is the reason to point a client
at a mock at all:

```bash
curl -s -X POST localhost:8081/admin-api/token-lifetimes/set \
  -H 'content-type: application/json' \
  -d '{"oauth2.accessTokenTtlS": 60}'
```

**A change reaches the next token and nothing already issued.** A lifetime is
stamped into a token as its `exp` when it is signed; to take one already in a
client's hands out of circulation, revoke it at `/oauth2/revoke` or on
`/admin/tokens`.

**Every lifetime is a whole number of thirty-second units**, and that is a
decision rather than a formatting rule: below half a minute a token expires
between the response being written and the client reading it, and the hour that
costs goes on debugging the wrong half of the exchange.

`oauth2.clockSkewS` is not a lifetime. It is the allowance applied to `exp` and
`nbf` wherever this service reads back a token it signed — introspection,
UserInfo, the refresh grant, token exchange, the DPoP-bound access token check —
**and** to the state every console screen reports, so the console and the
endpoints never disagree about what has expired. It never changes what goes into
a token. It is a different setting from `oauth2.clientAssertionSkewS`, which is
how far out a *client's* assertion may be (RFC 7523): one is somebody else's
clock, the other is this service's own.

> **`oauth2.refreshTokenTtlS` changed on 2026-08-24**, from thirty days to
> twenty-four hours. Set it to `2592000` for the old behaviour. It is not
> `oauth2.refreshIdleSeconds`, which is RFC 9700 mode's inactivity timeout on a
> refresh *chain* and is measured from the last redemption rather than from
> issuance.

## Reading the current configuration

```bash
curl -s localhost:8081/admin-api/config | jq
```

Every row, with its value, where the value came from, its type, its prose, and
whether it can be set at runtime — the whole table, whichever page edits it. It
also carries `homes`: which console page draws each group.

**In the console each group is on the page for the protocol it configures** —
`/admin/kerberos`, `/admin/ldap`, `/admin/saml2`, `/admin/scim`, and so on.
`/admin/config` holds the five settings that belong to no protocol and the index
of where the other 149 are. Every one of those forms posts to the same endpoint,
so there is one store however many pages draw the door.

## Changing one at runtime

```bash
curl -s -X POST localhost:8081/admin-api/config/set \
  -H 'content-type: application/json' \
  -d '{"key":"groups.claimName","value":"roles"}'
```

A restart-only key comes back refused, naming the reason. So does a value that
does not fit the setting's type.

The change applies to the next token, assertion, ticket or search; nothing
already issued changes, because a token is a signed document.

**Whether it survives a restart is `persistence.appconfig`.** In the default
`persistence.mode=memory` it does not — the override is in memory and is gone
with the process, which is what this service did until 2026-08-27. With a store
turned on it is written down and applied again at the next start, through the
same `setOverride()` a caller uses, so nothing about the layering changes: it is
still a runtime override sitting above the environment and the appconfig file,
and a *reset* is written down too.

**Nothing writes to the appconfig FILE in either mode**, deliberately, because a
service that edited a file checked into a repository would leave a test's
forgotten change behind permanently. The durable copy goes to the persistent
store instead, which is not a place anything is checked in from. See
[the persistence settings](#persistence) below.

`POST /admin-api/config/set-many` changes a whole section at once and is
all-or-nothing: every value is checked before any is written, so a body with one
bad field changes nothing and names it.
