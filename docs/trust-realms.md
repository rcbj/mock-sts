---
title: Trust realms
nav_order: 8
---

# Trust realms

**One process, several logical identity services.** A *trust realm* has its own
configuration, its own signing key, and its own sessions, authorization codes,
access and refresh tokens, credential offers, SAML request state, artifacts,
statistics and audit log. Every realm answers on the same ports as every other,
and they are told apart by a segment at the front of the path.

```
https://localhost:8081/oauth2/token                the DEFAULT realm
https://localhost:8081/realm/acme/oauth2/token     the realm `acme`
```

The point is what a client sees. Two realms are two authorization servers with
two issuer identifiers and two JWKS documents, so a token minted in one **does
not verify** in the other. That is the property somebody defines a second realm
to get: a test that a client is checking the `issuer` it was configured with, a
test that a wallet refuses a credential from an issuer it did not ask, a staging
identity provider beside a production-shaped one on the same laptop.

> **If you are not using realms, nothing here has changed.** The default realm
> has an empty prefix. A service with no realms defined strips nothing, rewrites
> no URL and grows no control — every path this service published before realms
> existed is a path in the default realm.

## Defining one

```bash
curl -k -X POST https://localhost:8081/admin-api/realms/create \
     -H 'content-type: application/json' \
     -d '{"id":"acme","name":"Acme Corporation"}'
```

Or on **`/admin/realms`** in the console, which is also where a realm's settings,
its four discovery URLs and the identifier of its signing key are.

Realms live in memory like everything else in this service and die with the
process, so whatever starts your stack should create them — which is why the API
call above exists rather than a config-file section.

The id becomes a path segment: lower-case letters, digits and hyphens, starting
with a letter or a digit, at most 31 characters. It may not be `default`, and it
may not be the first segment of a path this service already serves —
`GET /admin-api/realms` lists those in `reserved`, read off the live router, so
the list cannot go stale.

## Finding one

`GET /realms` is the directory, and it needs no credential. The prefix segment is
a setting and the ids are whatever somebody typed, so a client being pointed at a
realm cannot build a single URL without it.

```json
{
  "pathSegment": "realm",
  "enabled": true,
  "active": true,
  "current": "default",
  "realms": [
    { "id": "default", "pathPrefix": "",            "baseUrl": "https://localhost:8081" },
    { "id": "acme",    "pathPrefix": "/realm/acme", "baseUrl": "https://localhost:8081/realm/acme" }
  ],
  "support": [ "…which families a realm separates, and which are shared…" ]
}
```

Everything follows from `baseUrl`. Point a client at
`https://localhost:8081/realm/acme` as its issuer and its discovery, token,
authorization, userinfo, JWKS, SAML and OpenID4VCI endpoints all fall out of the
metadata that base URL publishes — with no per-endpoint configuration on your
side and none on this service's.

`enabled` is the `realms.enabled` setting; `active` is whether any prefix is
actually answering, which is false when the setting is on and nobody has defined
a realm yet. They are two flags because "switched off" and "none defined yet"
send you looking for different problems.

## What a realm separates — and what it does not

**A realm separates what this service ISSUES, not who it knows.** Read this
before you build a test on it.

### Separated, completely

| | |
|---|---|
| **The signing key** | Each realm generates its own. A token minted in one does not verify against another's JWKS. Each realm's `kid` is on `/admin/realms`. |
| **The OpenID4VCI request-encryption key** | Part of the same per-realm key set since 2026-09-12. Each realm's credential issuer metadata publishes its own key in `credential_request_encryption.jwks`, and a Credential Request encrypted to one realm's key is refused by every other realm — in every process of a service running request workers, and, in product mode, across a restart. Until that date a service with request workers gave every realm one shared key. |
| **Shared Signals registers** | The CAEP session register and the RISC account register behind `/admin/caep-sessions` and `/admin/risc-accounts`, since 2026-09-12. Until then every realm's page listed every realm's rows. |
| **Every setting** | Per realm, above whatever the process is configured with. Every settings form in the console — each protocol's page, and `/admin/config` — and `POST /admin-api/config/set` reached under a realm's prefix read *and write* that realm. |
| **Sessions** | Signing in to one realm signs you in to that realm only. **The admin console is the one exception**: its gate resolves your session cookie in whichever realm minted it, so the realm switcher switches rather than asking you to sign in again — the browser has only one session cookie, and before this a switch overwrote it. Every protocol endpoint is unchanged: in the realm you switched to, `/oauth2/authorize`, `/wsfed` and the two SAML profiles see no session. The console's banner names the realm your session belongs to whenever it is not the one you are looking at. |
| **Everything in flight** | Authorization codes, access and refresh tokens, refresh families, DPoP replay and nonce state, the RFC 7523 / RFC 7522 used-assertion history, named authorization servers, credential offers, pre-authorized codes, deferred transactions and the access tokens that mark a deferred issuance, issuance nonces, presentation transactions, SAML 2.0 and 1.1 request state and artifacts, SCIM Digest nonces and HOBA challenges, and the SPIRE Server API connections an X509-SVID was recorded for (a gRPC connection belongs to the realm whose listener accepted it). |
| **What goes into a token** | The custom claim selections, the SAML attribute selections, the credential claims, the verifier's request. |
| **The statistics and the audit log** | Including the audit sequence numbers, so one realm's rows are contiguous. |
| **The six settings that are NAMES** | The SAML 2.0 entityID, the SAML 1.1 providerID, the WS-Federation entityID, the WS-Trust issuer, the SAML assertion issuer and the OpenID4VP verifier client id. A new realm is created with each suffixed with its id, because two realms carrying one entityID is two identity providers claiming one name. They are ordinary settings — change them, or unset them to go back to sharing the process's name. |

### Separated — the embedded directory, one per realm

Each realm has a directory of its own behind the one socket, named by its base:

```
dc=example,dc=com                 the DEFAULT realm  (ldap.baseDn itself)
dc=acme,dc=example,dc=com         the realm `acme`
```

with its own `ou=users`, `ou=groups`, `ou=applications`, `ou=federations` and
SPIFFE containers under each. So:

- the same name signing in to two realms is **two entries**, one per realm;
- an **OAuth client** registered under one realm is unknown to every other;
- a **SAML service provider** entry belongs to the realm it was created in;
- the **SPIFFE registry** is per realm, and **so is the X.509 signing authority
  since 2026-09-11** — each realm has a SPIFFE Issuing CA of its own on
  [`/admin/pki`](pki.md) — and **so is the trust domain itself since
  2026-09-12**: a realm is created with `spiffe.trustDomain` of
  `<realm>.<the service's>`, so `acme` issues `spiffe://acme.example.org/…`.
  See *SPIFFE* below, which is no longer on the not-separated list;
- and a realm is reachable over LDAP: `ldapsearch -b "dc=acme,dc=example,dc=com"`.

That last point is *why* the realm is in the DN rather than in a partition of its
own. LDAP answers on a socket with no path to put a segment in — a search arrives
carrying a base DN and nothing else — so a **name** is the only thing a client
could ever use to say which realm it means.

**Every operation is answered from the directory its DN names.**
`ldapsearch -b "dc=example,dc=com"` is the default realm's directory;
`ldapsearch -b "dc=acme,dc=example,dc=com"` is acme's; an entry belonging to
another realm is filtered out of a search based above it, and the number
filtered is logged rather than dropped silently. The root DSE publishes one
`namingContexts` value per realm, which is how a client discovers that the
others are there.

An operation that names **one DN** — an add, a modify, a delete, a compare, or a
base-scope search of a single entry — is answered in that DN's realm. Spelling
out `…,dc=acme,dc=example,dc=com` is how a client says which realm it means on a
socket that has nowhere else to put one, so refusing it would make a realm
unreachable rather than isolated.

The one operation that carries **two** DNs is a rename, and a rename may not
cross a realm: `modifyDN` from one realm's subtree into another is refused with
`LDAP_AFFECTS_MULTIPLE_DSAS` (71), which is what a directory answers when a
rename would move an entry out of the server holding it. Two realms here are two
directories, so that is the truth rather than a borrowed error code.

With no realms defined there is one naming context and one container, and every
byte of every answer is what it was before realms existed.

### Separated, and confined — the admin console roles (2026-09-14)

Every realm has two administrator rosters that matter to it:

- **Its own.** The realm's `cn=admin-read` and `cn=admin-write`, in its own
  `ou=groups`. A new realm is seeded with an `admin` account holding both, which
  must change its password at its first sign-in; in product mode creating the
  realm shows that password once. Until that account signs in to the realm's
  console, anybody who signs in through the realm holds both of its roles.
- **The service's.** The default realm's two groups. Their members administer
  every realm, as they always did.

A realm's own administrators are **confined to their realm**. Everything about
the whole process is hidden from them and refused if asked for: the persistence
store, the database, encryption, the secret store, the TLS listeners and client
truststore, the LDAP service page, the embedded debugger and the API explorer.
(Kerberos left that list on 2026-09-15: a realm has a KDC of its own, so its
principals and keytabs are its administrator's — what stays service-wide is the
two Kerberos sockets and the development-mode trust.) So are creating or removing a realm, reading or editing another realm,
replacing the service Root, exporting the TLS listener's key, and every setting
that belongs to the process. That confinement is what makes a per-realm roster
safe: creating a realm makes somebody an administrator of that realm and of
nothing else.

The console asks the roster of the realm a person **signed in through**. Sign in
at `/realm/acme/admin` and acme's roster decides; `admin` in acme and `admin` in
the default realm are different people. A realm administrator who opens another
realm's console is told they administer another realm, with a link back.

**Choosing a realm.** When realms are defined, the plain `/admin` and `/portal`
ask which realm you belong to before signing you in — a list of realms in
development mode, a box for the realm's id in product mode. Add `?realm=<id>` to
skip the question, or `?realm=default` to sign in to the default realm. A link
to any page below `/admin` or `/portal` never asks.

**The management API.** `/admin-api` accepts a token from the default realm's
`sts-management-api` client everywhere. Under `/realm/<id>/admin-api` it also
accepts a token that realm's own `sts-management-api` client was issued, with
the realm's issuer and audience, and refuses that token the same service-wide
operations the console refuses the realm's administrators.

### Separated — SPIFFE, by ADDRESS (2026-09-12)

SPIFFE was on the not-separated list until this date: one trust domain, one set
of four sockets, answering in the default realm. It is separated now, and the
discriminator is neither a path nor a name but the **endpoint address**.

A realm is created with SPIFFE **off** and with a trust domain of its own —
`acme.example.org` under the service's `example.org`, a common root with a
unique issuer beneath it — and with Unix socket paths of its own. Turning
`spiffe.enabled` on for that realm builds its authorities and binds a **Workload
API and a SPIRE Server API of its own** on its Unix sockets. Nothing restarts:
writing the setting is what binds the sockets.

**A realm is created with its TCP listeners OFF** (`spiffe.workloadPort` and
`spiffe.serverPort` seeded to 0) and with **no administrators**
(`spiffe.adminIds` seeded empty). The ports it would otherwise inherit are the
default realm's, already bound on `0.0.0.0`, so turning SPIFFE on used to mean
two refused binds; and nothing here can know which addresses a host has. To
serve a realm over TCP, set `spiffe.grpcHost` on the realm to an address of its
own and the two ports back to `8092` / `8181` — a client configured for those
ports then reaches every realm where it expects to.

**The address is the only thing a SPIFFE client can name a tenant with.** gRPC
has a path and it is the method name — `/SpiffeWorkloadAPI/FetchX509SVID` is
fixed by the Workload API specification — so a realm segment there would be a
method no conforming client calls. It is also what a real deployment looks like:
one SPIRE server is one trust domain, and several trust domains are several
endpoints.

So a container running several realms' SPIFFE needs several addresses, and the
compose files give it four: a static one for the service and three more added to
its own interface on the way up (`STS_EXTRA_IPS`, which needs `NET_ADMIN`).
Join tokens are per realm too — a join token is a credential for joining a trust
domain.

What is still shared is the **default realm's own four sockets**, which are
bound when the process starts and stay bound with `spiffe.enabled` off (they
answer `Unavailable`; a socket that vanished would read as a service that had
stopped). **Federated bundles are a realm's own** since 2026-09-12, and no
realm may register one under a trust domain any realm of this service serves —
until then a bundle one realm registered was trusted in every realm, including
under another realm's name.

### Separated — Kerberos, by REALM NAME (2026-09-15)

Kerberos was on the not-separated list until this date: one KDC, one principal
database and one `krb5.realm` for the whole process, answering in the default
realm. It is separated now, and the discriminator is neither a path nor an
address but the **Kerberos realm name inside every request** — which the
protocol has always carried, because Kerberos has realms of its own.

**Port 88 is still one socket.** An AS-REQ or TGS-REQ names the realm it is
for, and the KDC answers it out of that trust realm's principal database.

**A realm is created with Kerberos off, and you name it yourself.** Nothing is
seeded: `krb5.enabled` is seeded `false`, and there is no default name, because
two realms answering to one name is a request nothing can route. So:

```bash
# Give the realm a Kerberos realm of its own, then turn it on.
curl -X POST .../admin-api/realms/set \
  -d '{"realm":"acme","key":"krb5.realm","value":"ACME.EXAMPLE.COM"}'
curl -X POST .../admin-api/realms/set \
  -d '{"realm":"acme","key":"krb5.enabled","value":"true"}'
```

Turning it on builds that realm's principal database from **its own settings**:
its own `krbtgt`, its own service account, its own fixture accounts in
development mode, every key salted with its own realm name. Its people are the
people in its own directory subtree, and their Kerberos keys (product mode) are
derived onto their own entries there. Nothing restarts.

Three refusals keep the routing honest, and each is a code in
[error codes](error-codes.md):

* **Turning Kerberos on without a `krb5.realm` of its own** — `STS-KRB-0123`.
* **A name another realm already answers to** — `STS-KRB-0124`: another realm's,
  the default realm's, or `krb5.trustedRealm`. Compared without regard to case,
  because two realms that differ only in case are two realms nobody can tell
  apart in a `krb5.conf`.
* **Renaming or clearing it while Kerberos is on** — `STS-KRB-0125`. Every key
  in that realm's database is salted with the name. Turn it off, rename, turn it
  on.

**A client reaches a realm by naming it**, which is what a `krb5.conf` already
does:

```ini
[realms]
  EXAMPLE.COM      = { kdc = sts-host:88 }
  ACME.EXAMPLE.COM = { kdc = sts-host:88 }   # the same port
```

Over MS-KKDCP there are two doors. A bare `/KdcProxy` routes by the name, like
the socket. A realm's own `/realm/acme/KdcProxy` is **pinned** to that realm and
refuses another realm's name with `KDC_ERR_WRONG_REALM` (`STS-KRB-0122`) — the
prefix is an address somebody chose. The acceptor on `krb5.servicePort` and
SPNEGO follow the same two rules: a ticket is accepted in the realm that issued
it, and a ticket from another realm presented under a realm's prefix is refused
(`STS-KRB-0126`).

**Trust realms do not trust each other's Kerberos.** A realm's KDC holds no
inter-realm key for another realm, so a ticket from one is not a referral to
another — it is unknown there. The cross-realm referral this service does serve
is the development-mode second realm (`krb5.trustedRealm`, `PARTNER.COM`), which
belongs to the default realm alone.

**What is still the process's:** the two sockets (`krb5.kdcPort`,
`krb5.servicePort`), so a realm cannot move or take a port of its own, and that
development trust. A realm administrator manages their realm's Kerberos —
principals, keytabs and the settings the database is built from — and those five
settings stay service-wide.

### Not separated — the TLS listeners

The 8443 and 9443 listeners. A socket has no path in it, and what those two
endpoints publish is what the server saw of the connection. LDAP's 389 and 636
were on this list until the directory was partitioned — the sockets are still
shared, but what they serve is told apart by DN — SPIFFE's four left it on
2026-09-12 by giving each realm sockets of its own, and Kerberos left it on
2026-09-15 by routing on the realm name in the request.

### Not separated — the key-encryption key

**A realm is not a cryptographic boundary at rest.** Each realm has its own
signing keys and its own branch of the certificate authority — that is the table
above — but the key that ENCRYPTS all of it before it reaches the store is a
single one for the whole deployment, read once at startup from
`keys.kekProvider`.

So anybody who can read that key can open every realm's sealed data, and
rotating it rotates every realm at once. Per-record separation does exist (every
sealed value gets its own derived key), but it is per record and not per tenant.
[Encryption at rest](encryption-at-rest.md) argues it, and says what making it
per realm would cost.

`GET /realms` and `/admin/realms` both publish this list family by family, so it
is something the service tells you rather than something to remember.

## The console

Every page shows **one** realm — the one whose prefix it was reached under — and
carries a **Trust realm** chooser at the top of the sidebar, inside the same
card as the sections, that moves to the same page in another realm, carrying the
filter and the page you were on. It is a `<select>` and a button rather than a
select that navigates on change, because the console runs no script at all
(`script-src 'none'`) and an inline handler is the one thing that policy
forbids. It submits to `GET /admin/realm-switch`, which builds the target from
the realm registry and a path it has checked is rooted and single-slashed —
never from the query string as given.

`/admin-api` is realm-scoped by the same prefix, so `/realm/acme/admin-api/config`
is that realm's configuration and every one of its operations works per realm.
The five operations under `/admin-api/realms` manage the registry itself, which
is process-wide: there is one list of realms in a process, and `remove` refuses
to remove the realm the call arrived in — the caller would be left talking to a
prefix that had stopped existing.

## Two settings

| Setting | Environment variable | Default | What it does |
|---|---|---|---|
| `realms.enabled` | `STS_REALMS_ENABLED` | `true` | Whether defined realms answer on their prefixes. Turning it **off** leaves every definition in place and stops the paths working — which is what to reach for when a realm is answering something it should not, since nothing has to be deleted to find out whether a realm is the reason for something. |
| `realms.pathSegment` | `STS_REALMS_PATH_SEGMENT` | `realm` | The segment in front of a realm id. Set it to the empty string for the bare `/acme/oauth2/token` shape, which is what a client ported from a product that spells it that way expects. |

Neither can be set *on* a realm: a realm that could switch realms off would be
doing it from inside the request that found it, and a realm that could move its
own prefix would be changing the prefix already used to find it.

## Removing one

Removing a realm **takes everything it held with it** — its sessions,
authorization codes, tokens, offers, service provider state, statistics, audit
log and signing key. That is deliberate rather than thorough: a realm re-created
with the same id inheriting the last one's sessions would be the most surprising
thing a re-created realm could do.

The realm's **directory subtree goes too** — its people, groups, applications,
federation relationships and SPIFFE registrations — so `dc=acme,dc=example,dc=com`
answers `NoSuchObject` afterwards and a realm re-created under that id starts
with a fresh seeded tree. The default realm cannot be removed at all.
