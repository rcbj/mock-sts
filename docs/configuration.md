---
title: Configuration
nav_order: 3
---

# Configuration

**There is exactly one place a setting is read**, `common/config.js`, and one
table inside it. That is not tidiness — it is what makes the next three sentences
possible.

From one row in that table, a setting appears in the admin console at
`/admin/config`, in `GET /admin-api/config`, in the management API's OpenAPI
document, and in the startup audit that logs what the appconfig file omitted and
what key it carried that the table does not know. None of those four has a list
of its own. A `process.env` read added anywhere else is invisible to all four,
which is the state this arrangement exists to end.

## How a value is resolved

Five levels, first match wins:

1. **A runtime override** — set through `/admin/config` or `POST /admin-api/config/set`
2. **The environment variable**
3. **A legacy environment variable** — there is exactly one, `STS_ISSUER`
4. **The appconfig file** named by `CONFIG_FILE`
5. **The built-in default**

Environment beating the file is deliberate: it is what keeps existing containers
and test harnesses working when the shipped `env/*.js` files carry every key.

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
require time is the one thing `/admin/config` cannot change, and it fails in the
direction that looks like the console is broken.

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

Derives its default from `oauth2.rfc9700`. When it is on there is **no plain HTTP
listener in this process**, which costs one thing that is stated on the page
rather than left to be met as a handshake failure: `POST /tls/trust` and
`GET /tls/server-certificate` exist to be reachable *before* anything is trusted,
so the first call to each has to be made with verification off.

It uses the same per-start certificate as 8443, 9443 and LDAPS 636, so a caller
trusts this service once per start rather than four times.

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

### `oauth2.breakIdTokenNonce`

Off. On, it puts a deliberately wrong `nonce` in every ID Token and logs that it
did. It is **not** part of RFC 9700 mode and must not be folded into it — a
compliance flag that also breaks tokens is a flag nobody will turn on. It exists
because "the client must validate the nonce" is a requirement no server can
check, and a reachable negative is the only way to find out whether a client
does.

## Reading the current configuration

```bash
curl -s localhost:8081/admin-api/config | jq
```

Every row, with its value, where the value came from, its type, its prose, and
whether it can be set at runtime. The console renders the same thing at
`/admin/config` with a form.

## Changing one at runtime

```bash
curl -s -X POST localhost:8081/admin-api/config/set \
  -H 'content-type: application/json' \
  -d '{"key":"groups.claimName","value":"roles"}'
```

A restart-only key comes back refused, naming the reason. So does a value that
does not fit the setting's type.

**The change is in memory only and is gone on restart** — nothing here writes to
the appconfig file, deliberately, because a service that edited a file checked
into a repository would leave a test's forgotten change behind permanently. It
applies to the next token, assertion, ticket or search; nothing already issued
changes, because a token is a signed document.

`POST /admin-api/config/set-many` changes a whole section at once and is
all-or-nothing: every value is checked before any is written, so a body with one
bad field changes nothing and names it.
