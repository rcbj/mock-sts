---
title: Sessions
nav_order: 7
---

# What a session is here, and how it is tracked

Three different things in this service are called a session, and they are not
variants of one another. Two more things look like sessions and are not. Getting
this wrong is the single commonest source of confusion about `/admin/sessions`,
`/admin/metrics` and the CAEP events — so this page is the definition, and every
page and endpoint named below is a view of it rather than a separate model.

| | What it is | Where it lives | When it ends |
|---|---|---|---|
| **Browser sign-on session** | the cookie every browser protocol here shares | a map in `authn/authn.js`, in memory | absolute expiry, or a sign-out |
| **Kerberos TGT** | the ticket-granting ticket *is* the Kerberos session | nowhere — a blob in somebody's cache | its own `endtime`, sealed in by the KDC |
| **LDAP connection** | the Bind is a state of the connection (RFC 4511 §4.2) | the socket | Unbind, a re-Bind, or the socket closing |

Only the first is a **record this service keeps**. The LDAP one is the live
socket itself — there is no session object beside it, and when the socket dies
the session is gone with it. The Kerberos one this service does not hold at all:
a TGT is a blob in somebody's cache, and a KDC that kept a record of the tickets
it had issued could not be replicated read-only. Almost everything below follows
from that one difference.

---

## 1. The browser sign-on session

**One session, shared by every browser protocol.** OAuth 2.0 / OIDC,
WS-Federation, SAML 2.0, SAML 1.1 and the admin console all read the same
cookie, which is why signing in through one signs you in to all of them and why
signing out of one signs you out of all of them. There is no per-protocol
session anywhere in this service.

### The cookie

`sts_mock_session`, `Path=/`, `HttpOnly`, `SameSite=Lax`, and `Secure` **only
when the port is TLS** (`global.https`). That last one is conditional rather than
always on for a reason worth knowing: a browser silently *drops* a `Secure`
cookie that arrives over plain http, so setting it unconditionally would leave a
plain-http deployment with a sign-in that appears to succeed and a session that
is never there again — which looks exactly like a session that expired and
points nowhere near the cookie.

`SameSite=Lax` and not `None`, deliberately: WS-Federation section 13.2.1 sends
its sign-in request as a cross-site form POST, and `None` would be a change that
needs its own argument.

### What the record holds

Keyed by an opaque 24-byte id, which is also on the record — because everything
that is handed a session gets the object and not the key, and without it the
tokens issued on a session could not name the session they were issued on.

| Field | What it is |
|---|---|
| `id` | the opaque identifier; what a token records, what the CAEP subject names |
| `user` | `{ username, sub }` — the name typed, and the `urn:` subject derived from it |
| `authTime` | when the authentication happened, in seconds — OIDC's `auth_time` |
| `expires` | the absolute instant it stops being honoured, in milliseconds |
| `amr` / `acr` | how they authenticated, and to what context class. Stated rather than omitted: a relying party that asked for a second factor has to be able to see that it did not get one |
| `via` | which protocol the sign-in came **through** |
| `oidcClients` | OIDC relying parties issued an authorization response on this session |
| `wsfedRealms` | WS-Federation realms signed into, with the `wreply` each was sent to |
| `saml2ServiceProviders` | SAML 2.0 service providers signed into, with their ACS URLs |

**`via` is the protocol it was created through and not the only one it serves.**
A session started at a SAML 2.0 sign-in and then used to answer an OIDC
authorization request says `SAML 2.0` for its whole life. What is riding on it is
the three lists — which is what `/admin/sessions` shows in its *Carries* column.

**Those three lists live on the session on purpose**, rather than in maps of
their own: that is exactly the lifetime they should have. When the session goes,
so does the list, and nothing has to be swept. They are also what a sign-out has
to fan out to, so seeing them in advance is the only way to know what a sign-out
is about to do. SAML 1.1 has no such list because that profile has no Single
Logout, and SPNEGO and federation add none because neither defines one.

### Lifetime: one hour, absolute, not extended by use

Fixed when the session is created. **There is no idle timeout in this service**,
so a session in constant use dies at the same instant as one nobody has touched.
It is not configurable — it is a constant in `authn/authn.js`, which is worth
knowing before looking for a setting.

**An expiry ends the session properly**, and until 2026-09-04 it did not: the
record was deleted with no audit row and no event, and only *lazily* — when
something next looked the session up — so somebody who closed their browser was
never looked up again and the session sat in the map, counted as live, for as
long as the process ran. A sweep now runs every 30 seconds, inside every trust
realm, and an expiry writes the same `session.end` audit row and the same CAEP
`session-revoked` any other ending writes. See
[CAEP events](caep-events.md#session-revoked) for what a receiver is told.

### How one is created

Every one goes through a single funnel, which is why there is no protocol here
that can start a session without being counted, audited and reported:

| Activity | `via` |
|---|---|
| A name typed at `/authn/login`, reached from an OAuth 2.0 / OIDC authorization request | `OAuth 2.0 / OIDC` |
| The same screen reached from a WS-Federation `wsignin1.0` | `WS-Federation` |
| The same screen reached from a SAML 2.0 `AuthnRequest` | `SAML 2.0` |
| The same screen reached from a SAML 1.1 inter-site transfer | `SAML 1.1` |
| A Kerberos ticket spent at `/authn/spnego` — no screen | `Kerberos v5 (SPNEGO)` |
| A federated assertion accepted at `/federation/acs/{id}` — the person authenticated somewhere else entirely | `Federation (SAML 2.0)`, and the same for the other federation protocols |

**No password is checked at any of them** except the Kerberos one, where the
ticket is verified against a real long-term key — see
[what is not checked](what-is-not-checked.md).

A **re-authentication makes a new session** rather than refreshing this one:
`prompt=login`, SAML 2.0's `ForceAuthn` or a stale session against a freshness
demand, and a WS-Federation `wfresh` too old all end at the screen.

### How one ends

| Activity | What it reaches |
|---|---|
| `GET /oauth2/logout` | OpenID Connect RP-Initiated Logout |
| `GET\|POST /wsfed?wa=wsignout1.0` | WS-Federation 1.2 §13.2.4 |
| `GET\|POST /saml2/slo` | SAML 2.0 Single Logout |
| `GET\|POST /logout` | the protocol-independent sign-out — everything, across every family |
| `/admin/logout`, `/admin/sessions` | an operator ending somebody else's |
| the lifetime running out | the sweep, or the next lookup |

All of them go through **one function**, which is what stops four protocols'
words for one act from drifting apart. That function is also where the RFC 9700
§2.2.2 refresh-token revocation lives and where the `session.end` audit row is
written, so a sign-out that revoked nothing and logged nothing is not reachable.
[Signing out](signing-out.md) has the rest.

**Ending a session does not recall what it produced.** Access tokens, ID Tokens,
SAML assertions and Kerberos tickets issued on it stay valid — that is what
`/admin/tokens` lists, and it is the state an OIDC client is in when its ID Token
still verifies and the browser would be asked to sign in again. Refresh tokens
are the exception in RFC 9700 mode.

### One session per sign-in, several per person

Nothing here limits how many a person may hold: two browsers is two sessions.
They are folded onto one person by an **identity key** — the normalisation that
makes `alice`, `alice@REALM` and `urn:sts-mock:user:alice` one identity — which
is what `/admin/users`, `/admin/logout` and `/admin/sessions` all file rows
under.

### Per trust realm

The session store is per realm, so a session belongs to the realm it was created
in and cannot be presented in another. Removing a realm drops its sessions with
everything else it held.

**The admin console is the one exception in the whole service**: it reads the
**default realm's** session whichever realm's console you are looking at,
because the two console roles are groups in the default realm's directory. See
[trust realms](trust-realms.md).

### Nothing about it survives a restart

Sessions are held in memory in every persistence mode, deliberately, and so is
everything this service mints. The signing key is regenerated on every start, so
a token that outlived it would verify against nothing. See
[persistence](persistence.md) for the three things that *are* written down.

---

## 2. The Kerberos ticket-granting ticket

**A TGT is the Kerberos session**; a service ticket is one *use* of it. That is
not an analogy — it is why `/admin/metrics` counts TGTs and not service tickets.

This service holds **no state** for one, and neither would a real KDC: a KDC
keeps no record of the tickets it has issued, which is exactly what lets one be
replicated read-only. A ticket is valid because it decrypts and its `endtime` has
not passed, and **the service that accepts it never contacts the KDC**. Short
lifetimes are the whole of Kerberos's revocation model.

Consequences worth stating:

- its expiry is the `endtime` the KDC sealed into the ticket, and nothing here
  can move it or take it back;
- ending one is not per-ticket. `/admin/sessions` and `/logout` stamp a
  **sign-out instant on the principal**, after which a TGS-REQ presenting a
  ticket authenticated before that instant is refused `KDC_ERR_TGT_REVOKED` (20)
  — a registered code whose text says what is meant and for which the
  specification defines no mechanism, so this is an invention using it. It
  reaches **no service ticket already in a cache**;
- a fresh AS-REQ succeeds and clears the instant, because signing out is not
  being locked out;
- a Kerberos client never touches the browser session at all — **unless** the
  ticket is spent at `/authn/spnego`, which is a different act: that door mints
  a browser session *from* a ticket, and from then on there are two sessions.

The list of live TGTs on `/admin/sessions` comes from the issued register — this
service's record of what it minted — and not from any store the KDC keeps.

---

## 3. The LDAP connection

RFC 4511 §4.2 makes a Bind the authorization state of a **connection**, so in
LDAP the connection *is* the session and closing it is the only sign-out the
protocol has. It follows that:

- it has **no expiry at all** — it lasts until the next Bind, an Unbind, or the
  socket closing. `expiresAt: 0` in the API means *no expiry*, not the epoch;
- a **re-Bind on the same socket is a new session**, and `/admin/sessions` dates
  it from that Bind rather than from the first one;
- ending it closes the socket, which the client sees as its connection dropping
  mid-conversation. An unsolicited notice of disconnection (§4.4.1) would be the
  polite form, and the vendored `node-ldapjs` has no way to send one;
- an **anonymous** bind is not somebody's session and is not listed as one.
  `/admin/ldap/service` counts every connection.

It is gated: `logout.ldapDisconnect` off leaves directory connections alone, and
they are shown as untouched rather than hidden.

---

## What is *not* a session

Five things are easy to mistake for one:

- **A token, an assertion, a ticket or an SVID.** Those are things this service
  has *handed out*. They outlive every session here, several by design and one
  (a Kerberos service ticket) beyond recall entirely. They are `/admin/tokens`.
- **A pending authentication record.** Between an authorization request arriving
  and a name being typed, this service holds what to do with the person
  afterwards — for ten minutes. Nobody is signed in yet.
- **A pending MFA step** (five minutes) and **a pending consent** — the same
  shape, both halves of one ceremony, neither a session.
- **A half-finished SPNEGO exchange.** Two minutes, keyed by door and remote
  address, and it can be spent only at the door that began it.
- **A row in the CAEP register.** That is a record *about* a session, and **it
  deliberately outlives one**: the session store forgets a session the moment it
  is signed out, so a row saying `revoked` is the only remaining evidence that
  the session existed and was revoked. See below.

---

## Where a session is visible

Six views, and they answer different questions. The first two are the ones
people mix up.

### `/admin/sessions` — what is live, right now

Every session this service is holding, across all three kinds, with who is
signed in, the protocol it was started through, what it carries, when it expires
and **how that expiry is worked out** — and a Revoke button on each row that goes
through the same termination `/logout` performs.

`GET /admin-api/sessions` is the same list without a browser;
`POST /admin-api/sessions/revoke` is the button. Every row carries the two fields
that write needs, and — for a browser session — the `sessionId` that
`GET /admin-api/tokens?session=` takes.

### `/admin/metrics` — the count, both ways

That page counts sessions **twice**, and the two numbers disagree on purpose:

- **the sign-on sessions this service really holds** — the map described above;
- **the sessions implied by what it has issued**, which is a *definition* rather
  than a measurement: a subject has an artifact-derived session in a protocol
  family when that family has issued it at least one artifact that is still
  valid — unexpired, and unrevoked where revocation exists.

They differ in both directions and each direction is real. A `client_credentials`
access token has no human and no browser behind it, so it is a session in the
second sense and nothing at all in the first. A signed-in browser that has been
issued nothing yet is a session in the first sense and nothing in the second. A
Kerberos client is in the second only.

In `?format=json` they are two members with two names: **`signOnSessions`** —
`held`, `active`, and a row per session — and **`sessions`**, the derived count
broken down by family. Reading one of them as the other is the mistake this
paragraph exists to prevent.

### The other four

- **`/admin/users?user=…`** — one person: every session they hold, with the
  tokens issued **on each of them**, plus the tokens whose session has since
  ended and the tokens that never had one (`sessions`,
  `tokensOnEndedSessions`, `tokensWithNoSession` in the JSON). Those three
  buckets are the answer to "why is this token not under a session", and the
  middle one is not an error: sessions expire and are swept, and the token
  outlives the sign-on it came from.
- **`/admin/logout`** — one person, across all ten families: what is still live
  and what cannot be ended, with the reason. It is `/admin/sessions` asked the
  other way round.
- **`/admin/caep-sessions`** — what has been *said* about each session over
  Shared Signals, including sessions this service no longer holds.
- **The audit log** — `session.start` and `session.end`, one row each. They are
  deliberately separate from the `authentication` row beside them: a Kerberos
  AS-REQ and a WS-Trust UsernameToken authenticate somebody and start no session
  at all, so a log that could not tell those apart could not answer *when did
  this browser get its session*.

---

## What a receiver is told

If a Shared Signals stream is agreed, a session starting, being presented and
ending each emit a CAEP event with nobody having asked — the only place in this
service where an endpoint is not what starts the work.
[CAEP events](caep-events.md) is the whole of it: which activity fires each of
the eight, what each carries, and the three gates an event passes on its way
out.
