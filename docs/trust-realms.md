---
title: Trust realms
nav_order: 5
---

# Trust realms

**One process, several logical identity services.** A *trust realm* has its own
configuration, its own signing key, and its own sessions, authorization codes,
access and refresh tokens, credential offers, SAML request state, artifacts,
statistics and audit log. Every realm answers on the same ports as every other,
and they are told apart by a segment at the front of the path.

```
http://localhost:8081/oauth2/token                the DEFAULT realm
http://localhost:8081/realm/acme/oauth2/token     the realm `acme`
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
curl -X POST http://localhost:8081/admin-api/realms/create \
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
    { "id": "default", "pathPrefix": "",            "baseUrl": "http://localhost:8081" },
    { "id": "acme",    "pathPrefix": "/realm/acme", "baseUrl": "http://localhost:8081/realm/acme" }
  ],
  "support": [ "…which families a realm separates, and which are shared…" ]
}
```

Everything follows from `baseUrl`. Point a client at
`http://localhost:8081/realm/acme` as its issuer and its discovery, token,
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
| **Every setting** | Per realm, above whatever the process is configured with. Every settings form in the console — each protocol's page, and `/admin/config` — and `POST /admin-api/config/set` reached under a realm's prefix read *and write* that realm. |
| **Sessions** | Signing in to one realm signs you in to that realm only. **The admin console is the one exception**: its gate resolves your session cookie in whichever realm minted it, so the realm switcher switches rather than asking you to sign in again — the browser has only one session cookie, and before this a switch overwrote it. Every protocol endpoint is unchanged: in the realm you switched to, `/oauth2/authorize`, `/wsfed` and the two SAML profiles see no session. The console's banner names the realm your session belongs to whenever it is not the one you are looking at. |
| **Everything in flight** | Authorization codes, access and refresh tokens, refresh families, DPoP replay and nonce state, client-assertion replay state, named authorization servers, credential offers, pre-authorized codes, deferred transactions, issuance nonces, presentation transactions, SAML 2.0 and 1.1 request state and artifacts. |
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
- the **SPIFFE registry** is per realm, though the trust domain and the signing
  authority in front of it are not;
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

### Not separated — the two admin console roles

Deliberately. They are groups in the **default realm's** `ou=groups`, read there
whichever realm the console is reached in, and a grant made through
`/realm/acme/admin-api/rbac/grant` lands there too and says so in its reply.

There is one administrator roster for the process on purpose: a role is
permission to change what *every* realm does — a settings form writes the realm
it is reached in, and `/admin/realms` can delete a realm outright — so a
per-realm roster would mean anybody who can create a realm can administer the
whole service.

The console's sign-on follows the roster. It accepts the default realm's session
and no other, and an unauthenticated reader of *any* realm's console is sent to
the **default realm's** sign-in screen — then returned to the realm page they
asked for. Sign in once, in one realm; read every realm.

### Not separated — three socket families

Kerberos (over raw UDP/TCP 88 *and* over MS-KKDCP — `/KdcProxy` is reachable
under a prefix but reaches the same KDC behind it), the two TLS listeners, and
SPIFFE's four sockets. A socket has no path in it. LDAP's 389 and 636 were on
this list until the directory was partitioned: the sockets are still shared, but
what they serve is told apart by DN.

Kerberos is the one with an obvious way forward, and it is written down here
rather than left to be rediscovered: Kerberos already *has* a realm, so the
natural design is to give each trust realm a `krb5.realm` of its own and dispatch
a request on the realm name it carries, letting the shared port serve both. What
stands in the way today is that `krb5.realm` cannot be changed while the service
runs — the principal database and every long-term key in it is built from it when
the process starts — so that database has to become per-realm and lazily built
first.

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
