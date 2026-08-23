---
title: What is not checked
nav_order: 5
---

# What is not checked

This service **checks no password, validates no access token it did not issue,
and attests no workload**. Read this page before using it for anything, and read
it again before concluding that something here is a bug.

It is permissive on purpose. A client that has only ever met a permissive server
has never run its own refusal paths; a client that has only met a strict one
cannot reproduce the behaviour it is trying to detect. So the default is
permissive, several negatives are made deliberately *reachable*, and where the
service can be told to be strict, it can.

## The permissive list

| It does not | Notes |
|---|---|
| Check any end user's password | The username typed at `/authn/login` becomes the identity in every token and every assertion |
| Refuse any LDAP bind | Any DN, any password, anonymous included — on 389 and on LDAPS 636 alike |
| Verify an access token it did not issue | Except at `/oauth2/userinfo`, which answers "who did *you* authenticate" and so must |
| Require DPoP | Nonce mode makes proofs fresher, not mandatory. A request with no `DPoP` header is a Bearer request |
| Turn a verified client certificate into a login | No session, no token, no privilege. It *is* recorded — see below |
| Turn a verified presentation into a sign-on | The OID4VP Verifier checks properly and then says yes on a web page and stops |
| Verify anything in an issued credential's values | They come off the directory entry, and what the entry lacks is *invented* from the username |
| Deactivate anybody on SCIM `active: false` | Stored as `scimActive` and read by nothing |
| Attest a workload or a node | See SPIFFE, below |
| Let a group grant anything, bar two | A token now *carries* one; no endpoint reads it. `cn=admin-read` and `cn=admin-write` are the exception and grant the admin console, nothing else |

**Recorded is not the same claim as authenticated, and the two are kept apart
everywhere.** A verified TLS client certificate, a verified presentation and an
accepted SPIFFE credential all appear on `/admin/users` and seed a directory
entry — because an identity turned up here and something about it was accepted.
None of them starts a session or issues a token. A mock that quietly promoted one
into the other would teach a client something false about every real server it
will ever meet.

## Kerberos is the exception, and cannot not be

The password there *is* the key: pre-authentication and the AS-REP's enc-part are
both encrypted under it, so a KDC accepting anything would still have to pick a
key the client could not guess. So it does the permissive equivalent — **any
username authenticates and every user account shares one password**
(`password!`, `KRB5_USER_PASSWORD`), with a name nobody configured created on
first sight.

Three things stay refusals on purpose, so the corresponding error codes are
reachable: a service-shaped name for a host this service is not willing to *be*
(`KDC_ERR_S_PRINCIPAL_UNKNOWN`), the names in `KRB5_UNKNOWN_USERS`
(`KDC_ERR_C_PRINCIPAL_UNKNOWN`), and a wrong password (`KDC_ERR_PREAUTH_FAILED`).

## The reachable negatives

A permissive server that refuses nothing is not much use for testing error paths
either, so several refusals are kept deliberately reachable:

- **The literal password `invalid`** is rejected on the password grant, on
  WS-Trust, at the WS-Federation sign-in screen, and as an LDAP bind password —
  where it is the only thing that produces `LDAP_INVALID_CREDENTIALS` (49), the
  result code an LDAP client's error handling is built around.
- **`invalid` as a SCIM `userName`** is refused, as is a duplicate one.
- **`oauth2.breakIdTokenNonce`** puts a deliberately wrong `nonce` in every ID
  Token. Off by default, and *not* part of RFC 9700 mode: a compliance flag that
  also broke tokens is a flag nobody would turn on.
- **WS-Federation's `wauth`** is refused rather than faked. A relying party
  demanding multi-factor against a password-only session gets an error and two
  ways forward, not an assertion claiming a second factor that did not happen.
- **`wreqptr` is never dereferenced**, and neither is a client's registered
  `jwks_uri`, and neither is a foreign SPIFFE bundle URL. Fetching a URL somebody
  handed you in order to verify a credential is a server-side request forgery
  with a specification citation attached.

## The three surfaces that DO require a credential

### SCIM, at `/scim/v2`

These endpoints create, replace, patch and **delete** accounts, which is why. A
credential is required (`scim.authRequired`), all six schemes RFC 7644 section 2
names are offered, and the OAuth ones must carry `scim:read` or `scim:write` —
the only scope requirement anywhere in this service.

**It is a turnstile rather than a lock**, and that is a different sentence.
Anybody can get a token with either scope from any grant, any password but
`invalid` passes Basic, any username passes Digest with the one shared password,
and anybody can register a HOBA key for any name. What it buys is that a client's
401, 403, challenge-response and scope handling can be exercised *at all* — none
of which an open endpoint can produce.

Two schemes really verify something. **Digest** hashes the password into the
response, so a server accepting anything would not be performing the exchange and
the client's own digest code would go unexercised. **HOBA**'s signature is
genuinely verified for the same reason; what is permissive there is the
registration, because that is how a caller *gets* a credential. Between them they
make five negatives reachable that no permissive server can produce — including a
replayed nonce count refused **without** `stale=true`, because `stale` means
"your credential was fine, try again" and a replay is the opposite claim.

The discovery endpoints are open by default (`scim.authDiscovery`): the
ServiceProviderConfig is where a client *reads* which schemes exist, so demanding
a credential to fetch it means a client must already know the answer to the
question it is asking.

**A credential that was presented and failed is always a refusal**, even with
`scim.authRequired` off, so a client testing its expired-token path does not get
a 200 because the endpoint would also have accepted nobody.

### The SPIRE Server API

Its TCP port is **mutual TLS**. Callers present an X509-SVID verified against the
trust bundle, and every method is authorized against SPIRE's own per-method table
— copied row for row from `pkg/server/authpolicy/policy_data.json`, not reasoned
out, so that where a row looks surprising (`Debug.GetInfo` is local-only, so an
admin SVID over TCP is refused it) the surprise is SPIRE's answer and not this
service's invention.

What comes out of that surface is a credential another service will believe,
which is why. `spiffe.authRequired` turns it off and restores the whole of the
old posture.

### The admin console, at `/admin`

`admin.authRequired` is **on by default**. Every page and every form under
`/admin` needs a browser sign-on session from `/authn/login` and one of two
roles: **Admin Read** (look at everything, change nothing) and **Admin Write**
(post every form). Write implies read.

It is the one surface that can change what every *other* surface does — it
revokes tokens through the same set `/oauth2/revoke` writes to, and it adds
claims to every token, ID Token and assertion issued from then on — which is why.

**It is a turnstile rather than a lock, and here that is sharper than it is for
SCIM: no password is checked at the sign-in screen either.** What the gate proves
is that somebody *typed* a name that holds a role. What it buys is a client, or a
person, being driven through a 302 to a sign-in screen, a 401 with no session, a
403 with the wrong role, and a role model that can be granted and revoked.

**The roles are two ordinary groups in the embedded directory** — `cn=admin-read`
and `cn=admin-write` by default (`admin.readGroup`, `admin.writeGroup`) — so
`/admin/rbac`, `POST /admin-api/rbac/grant`, an `ldapmodify` and a SCIM `PATCH`
are four doors onto one membership. A role no test can grant would be a role no
test can exercise.

**While neither group has a member, anybody who signs in holds both roles**, and
every page says so. There is no password anywhere here to bootstrap an
administrator with and the roster dies with the process, so an empty roster opens
rather than closes; `admin.openWhenEmpty` turns that off.

**`/admin-api` is not gated at all.** It is what a test drives and it is the way
back in when nobody holds a role — and it means anybody who can reach this port
can grant themselves both roles through it. Do not put this service on a public
address.

## The Workload API is the opposite case

It authenticates nobody **because its specification says it MUST NOT**. A
workload has no secret and no root of trust until that call gives it one, so the
SPIFFE Workload Endpoint specification requires that the endpoint not demand
authentication and that TLS not be required. `spiffe.authRequired` deliberately
does not reach it.

What it lacks there is **attestation, not authentication**, and the two must not
be merged. A real agent reads the peer credentials of its Unix socket —
`SO_PEERCRED`, giving pid and from that uid, gid, executable, container, pod —
and turns them into selectors. **Node has no portable way to read them.** So a
caller is identified by the transport it arrived on, the endpoint it reached and
its peer address, and by nothing else, and the selectors are spelt `transport:`,
`endpoint:` and `peer:` rather than `unix:` or `k8s:`. Writing `unix:uid:1000`
for a uid nothing read would be inventing an attested fact.

Selector matching still **decides** which entries answer a caller
(`spiffe.attestWorkloads`), which is narrowing without attesting; and
`spiffe.autoCreateEntries` **off** is the interesting setting, because a caller
matching no entry then gets an empty SVID list — what a real agent does for an
unregistered workload, and the only way to run a client's "I have no identity"
path.

## RFC 9700 mode

`oauth2.rfc9700` turns the OAuth 2.0 / OIDC flow into a conforming one. It is off
by default, changes nothing until it is set, and is restart-only because it also
binds the main port as HTTPS.

**In that mode this service checks exactly one credential**: a client that
registered *here* as confidential must present the `client_secret` this service
minted for it. Section 2.5 conditions its requirement on a process for issuing
credentials existing, and `POST /oauth2/register` is one. Nothing else changes —
a `client_id` this service never registered has no credential on file and is
untouched, a registered public client has nothing to authenticate with, and no
end user's password is checked in that mode or any other.

Everything the mode does and does not enforce is at `GET /oauth2/rfc9700`, row by
row. Two rows say `enforced: no` because the requirement is the *client's* — it
must validate the ID Token's nonce, and must not use a token before that succeeds
— and nothing this server observes separates a client that checks from one that
does not.
