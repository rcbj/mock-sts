---
title: CAEP events
nav_order: 8
---

# The eight CAEP events, and what makes each one fire

This service is a **CAEP transmitter**. The Continuous Access Evaluation Profile
1.0 (final, 2 September 2025) is a vocabulary about **sessions** spoken over
[Shared Signals](https://openid.net/specs/openid-sharedsignals-framework-1_0.html);
SSF is the pipe and defines two events of its own about the pipe, and these
eight are about a session. The sentence they exist to carry is *this session is
no longer trustworthy* — which is a different sentence from RISC's *this account
is no longer trustworthy*, and the whole reason there are two profiles.

This page answers one question in depth: **what, in this service, actually
causes each of the eight to be emitted.** The catalogue of members — every
member of every event, its type, whether it is required, and what it means — is
published live at `GET /admin/caep` and `GET /admin-api/caep`, read off the same
table the code emits from; go there for the full shape rather than to a copy on
this page. What is here instead is the part no endpoint can tell you: the
trigger.

The short version:

| Event | Emitted by this service on its own? |
|---|---|
| `session-established` | **yes** — every sign-in, through every protocol that starts a session |
| `session-presented` | **yes** — single sign-on, in four browser SSO profiles |
| `session-revoked` | **yes** — every sign-out, and every expiry |
| `token-claims-change` | no — by hand only |
| `credential-change` | no — by hand only |
| `assurance-level-change` | no — by hand only |
| `device-compliance-change` | no — by hand only |
| `risk-level-change` | no — by hand only |

## Three gates every event passes, whatever fired it

An event reaching a receiver has cleared all three. Most reports of "nothing
arrived" are the third.

1. **Is CAEP on at all.** `caep.enabled` (default on). With it off the eight
   types are dropped from `events_supported`, so a stream asking for one gets it
   back missing from `events_delivered` — which is the only notice SSF gives a
   receiver, and exactly the case a receiver ought to be tested against.
   `caep.eventsSupported` narrows the eight without turning the profile off.
2. **Did something fire it.** For the three automatic ones, `caep.autoEmit`
   (default on) and `caep.autoEmitTypes` (default: all three). Naming one of the
   other five in `autoEmitTypes` is **dropped with a warning** rather than
   honoured — no code path here would ever fire it, and a setting that reads as
   configured and does nothing is worse than one that refuses.
3. **Does a stream take it.** A stream must both deliver that type *and* cover
   that subject. If none does, the event is still applied to the register and
   shown on `/admin/caep-sessions` **with nothing sent** — which is what makes
   "nothing arrived" traceable to "nobody asked" rather than to a bug. The log
   line at `info` says so once, naming the type and the subject, and the
   *Per application* table on that page says it per receiver: a row with no
   stream, or one whose *Takes* column is empty, is the answer.

**What a session IS here — the browser sign-on session these events are about,
and the two other things this service also calls a session — is
[Sessions](sessions.md).**

**A session that isn't in the register can't be the subject of anything.** The
register is capped at `caep.maxSessionsTracked` (default 200) and drops the
oldest. In practice only a **browser sign-on session** ever creates a row — a
row can also be created by an event naming a session nothing here has held, and
it is marked as such — so there is nothing to emit about an LDAP bind, a
Kerberos ticket or a WS-Trust exchange; see *What never produces one* at the
foot of this page.

## The subject: why it names two things

Every one of the eight is `subject: required`, and this transmitter composes
SSF's **complex** subject rather than a plain one:

```json
{
  "user":    { "format": "issuer_subject_id", "iss": "…", "sub": "…" },
  "session": { "format": "opaque", "id": "…" }
}
```

The person is not revoked — **one session of theirs is**. A subject naming only
the person asks a receiver to end every session they have, which is a much
larger instruction than the one that was meant. `user` is an issuer/subject pair
because that is the identifier a receiver already holds (an ID Token's `iss` and
`sub`); `session` is `opaque` because a session identifier has no shape anybody
else can parse.

**The failure this shape invites** is a receiver that reads `user`, ignores
`session`, and signs the person out everywhere. `ssf.criticalSubjectMembers`
publishes `session` as a critical member, which obliges a receiver that does not
understand it to refuse the event instead — and it **ships empty**, deliberately,
so that both behaviours can be produced. Set it to `session` to find out whether
a receiver under test honours it.

## The four claims every event may carry

CAEP section 2 gives all eight the same four, and **all four are optional**:
`event_timestamp`, `initiating_entity`, `reason_admin`, `reason_user`.

Two of them are worth knowing before you read the rest of this page:

- **`event_timestamp` being optional surprises people**, because a receiver
  deciding whether to end a session wants it more than anything else in the
  payload — and a conforming transmitter need not send one.
  `caep.omitEventTimestamp` produces exactly that event on purpose. It is *not*
  the SET's `toe` and it is *not* `iat`: a transmitter may legitimately send
  both, and a receiver reading only one of them from a transmitter that sends
  only the other reads nothing at all.
- **`reason_admin` and `reason_user` are objects keyed by a language tag** —
  `{"en": "…"}` — not strings, which is the commonest way they are got wrong.
  `caep.includeReasons` (default on) and `caep.reasonLanguage` (default `en`)
  control them.

---

# The three this service emits by itself

## `session-established`

**What fires it: every sign-in, through every protocol that starts a session.**

There is one funnel — `authn.startSession()` — so this is protocol-independent
by construction rather than by six call sites remembering to do it. The callers:

| Activity | `via` on the event |
|---|---|
| Somebody types a name at `/authn/login`, reached from an OAuth 2.0 / OIDC authorization request | `OAuth 2.0 / OIDC` |
| The same screen reached from a WS-Federation `wsignin1.0` | `WS-Federation` |
| The same screen reached from a SAML 2.0 `AuthnRequest` | `SAML 2.0` |
| The same screen reached from a SAML 1.1 inter-site transfer | `SAML 1.1` |
| A Kerberos ticket spent at `/authn/spnego` — integrated authentication, no screen | `Kerberos v5 (SPNEGO)` |
| A federated assertion accepted at `/federation/acs/{id}` — the person signed in at a *foreign* identity provider | `Federation (SAML 2.0)`, and the same for the other four federation protocols |

A re-authentication is a *new* session and therefore a new
`session-established`: `prompt=login` at the authorization endpoint, SAML 2.0's
`ForceAuthn` or a stale session against its freshness demand, and a
WS-Federation `wfresh` too old all end at the screen rather than being answered
from the session that exists.

**What it carries beyond the common four:** `acr` and `amr` off the session, and
`ext_id` — this transmitter's own identifier for the session, so a receiver can
correlate. `amr` is an **array**: a session authenticated by a password *and* a
security key has two values, and a receiver that read a string would see one.
`fp_ua` (a user-agent fingerprint) is a member of the event this service does not
compute.

**Why it matters more than it looks:** it is what closes the loop. Without it a
receiver only ever hears about sessions *ending*, so it cannot hold an inventory
of what is open and cannot notice a sign-in it did not expect.

**In the register:** sets the row's state to `established` and records `acr` and
`amr`. Establishing a session whose row is already `revoked` is carried with a
**warning** rather than refused — the same identifier can legitimately be reused,
and a receiver that kept the revocation will ignore everything about it from
here on, which is worth being able to see.

## `session-presented`

**What fires it: an existing session presented at a browser SSO endpoint and
honoured without a new authentication — which is single sign-on.**

Unlike the other two automatic events, this one has **no funnel**. A
presentation is something each endpoint decides it is doing, so it fires from
exactly four call sites, one per browser SSO profile:

| Protocol | Activity | `via` |
|---|---|---|
| OAuth 2.0 / OIDC | an authorization request at `/oauth2/authorize` answered out of a session that already existed — no screen drawn | `OAuth 2.0 / OIDC` |
| SAML 2.0 | an `AuthnRequest` at `/saml2/sso`, over any of the three bindings, that reaches the answer step on an existing session | `SAML 2.0` |
| SAML 1.1 | an arrival at the inter-site transfer service carrying a `TARGET`, answered on an existing session | `SAML 1.1` |
| WS-Federation | a `wsignin1.0` at the passive requestor endpoint answered on an existing session | `WS-Federation` |

All four go through `authn.notePresented()`, which is protocol-independent: the
event names the **session**, and `via` records which door it came back through.

**The first presentation of a brand-new session is swallowed.** Every sign-in
here ends with the browser returning to the endpoint that sent it away, which is
technically a presentation — so without this rule the simplest possible flow
would emit `session-established` and `session-presented` milliseconds apart,
every time, and the event that is supposed to mean *single sign-on happened*
would mean nothing. A flag set when the session is created is spent by the first
presentation, so it is exact rather than a time window, and it is spent **across
protocols**: a sign-in at `/saml2/sso` followed by an OIDC authorization request
reports exactly one presentation between them — the OIDC one, named
`OAuth 2.0 / OIDC`.

Per-protocol edges:

- **OIDC** — `prompt=login` skips the branch entirely (screen → a new session).
  `prompt=none` on a live session **does** emit. It fires *above* the consent
  check, deliberately: the session was presented and honoured whatever the
  person then answers about scopes.
- **SAML 2.0** — `ForceAuthn`, or a session older than the request's freshness
  demand, never reach the answer step. `IsPassive` with nothing usable, and a
  sign-in that came back carrying an authentication error, answer with a status
  `Response` and emit nothing.
- **WS-Federation** — the call sits *below* the two `wauth` refusals, because
  those end in a 400 and nothing was honoured; a `wfresh` too old never reaches
  it and re-authenticates instead.
- **SAML 1.1** — that profile has no `ForceAuthn` and no
  `RequestedAuthnContext`, so every arrival with a session is either single
  sign-on or that session's own sign-in coming back — exactly the pair the rule
  above tells apart.

**What it carries beyond the common four:** `ext_id`, and `fp_ua` — *the user
agent observed this time*, whose whole value is comparing it against the one on
the `session-established` event. The same session presented from a different
agent is the abnormality this event exists to make visible. This service
computes neither.

**In the register:** sets the state to `presented` — **except** on a session the
register holds as `revoked`, which is **the one hard refusal in the whole state
machine**. That sentence says a session this transmitter has already declared
dead was just used and honoured, which is either a transmitter contradicting
itself or a receiver about to be told to trust something it was told to stop
trusting. Everything else that looks wrong is a warning; this is an error.

## `session-revoked`

**What fires it: every way a session ends.** Like `session-established` it has a
funnel — `authn.dropSession()` — and every sign-out door in the service goes
through it:

| Activity | `initiating_entity` | `reason_admin` says |
|---|---|---|
| `GET /oauth2/logout` — OpenID Connect RP-Initiated Logout | `user` | ended at *the sign-out endpoint for this browser* |
| `GET\|POST /wsfed?wa=wsignout1.0` — WS-Federation 1.2 section 13.2.4 | `user` | the same |
| `GET\|POST /saml2/slo` — SAML 2.0 Single Logout | `user` | the same |
| `GET\|POST /logout` — the protocol-independent sign-out | `user` | ended at *the /logout endpoint* |
| `/admin/logout` — an operator signing somebody else out | **`admin`** | ended at *the admin console at /admin/logout* |
| `/admin/sessions` — the Revoke button on a row | **`admin`** | ended at *the /admin/sessions page* |
| `POST /admin-api/logout/{global,end}` | **`admin`** | ended at *the admin console at /admin/logout* — it calls the same function that page does |
| `POST /admin-api/sessions/revoke` | **`admin`** | ended at *the management API at /admin-api/sessions* |
| **the session lifetime running out** | **`policy`** | *the session lifetime ran out* |

`initiating_entity` is derived from the phrase the door calls itself by, which
is also the sentence that reaches `reason_admin` — so the two can never
disagree about who ended a session.

The last row is the one worth knowing about. An expiry used to be silent: the
session was deleted with no event, and only *lazily* — when it was next looked
up — so somebody who closed their browser was never looked up again and nothing
ever fired at all, while the receiver that had been told the session was
established was told nothing when it ended. A sweep now runs every 30 seconds,
inside every trust realm, so the event goes out whether or not anybody comes
back to look.

`initiating_entity` on that one is **`policy`** and not `user` or `system`:
nobody signed out, a lifetime this service configured ran out, and that is what
CAEP section 2 means by a policy evaluation. `reason_user` says *"Your session
expired. Sign in again to carry on."* rather than *"You have been signed
out."* — a receiver that showed the second sentence would send somebody looking
for who signed them out.

**What it carries beyond the common four: nothing at all.** There is no
event-specific member, and that is not an oversight — everything it has to say
is in the subject and in the four common claims. Where the subject is a complex
one, the revocation applies to any session matching **every** part of it at once.

**In the register:** sets the state to `revoked`. A second revocation is a
**warning** rather than an error: it is harmless, a receiver should be
idempotent about it, and that is exactly the thing worth testing.

**One thing it deliberately does not do:** revoking tokens does not end a
session here, so `POST /admin-api/tokens/revoke-user` and the bulk buttons on
`/admin/tokens` emit nothing. A session outlives its tokens; ending it is the
act this event reports.

---

# The five nobody here can cause

Five of the eight describe things this service has no way of observing. **No
device reports compliance to it, no risk engine talks to it, no credential
lifecycle is wired into it and nothing recomputes assurance behind a live
session.** They are therefore emitted **by hand**, and that is a feature rather
than a gap: they are exactly the events a receiver is hardest to test against,
because in a real deployment they arrive from systems you do not control.

Two doors, one function behind them, so a form and a script produce the same
bytes:

- **`/admin/caep`** — pick a session, pick a type, fill in a JSON payload, add
  `initiating_entity` (the form defaults it to `admin`), `reason_admin` and
  `reason_user`. The chooser offers only **live** sessions, because emitting
  about one that has already been revoked is mostly a way to produce the
  register's one hard refusal by accident.
- The API is less fussy on purpose: it will emit about any session the register
  still **holds**, revoked ones included, because reproducing exactly that
  refusal is a thing a test needs to do deliberately.
- **`POST /admin-api/caep/emit`** — `{ "session_id": "…", "type": "…",
  "payload": {…}, "initiating_entity": "…" }`. Short names are accepted as well
  as whole URIs. A type that is not one of the eight is refused *with the list
  of eight*; a session the register does not hold is refused saying so, because
  there would be nothing to compose a subject from.

Every payload is **validated before it is sent**, and the refusal names what was
wrong rather than silently sending something a receiver will drop. Refused: a
required member missing; a closed enum with a value not on it; `amr` as a bare
string where an array is meant (*a session authenticated two ways has two
values, and wrapping would hide a sender that can only ever say one*);
`event_timestamp` as a quoted number (*a quoted timestamp parses everywhere and
is compared numerically nowhere*); `reason_admin` or `reason_user` as a string
rather than a language map.

Two things are **carried with a warning** rather than refused, and both are
deliberate: an **open** enum's unlisted value, because refusing would make this
service unable to carry a vendor's own type — precisely what a mock is for — and
a member the event does not define, because an event vocabulary extends and a
receiver is expected to ignore what it does not know.

**Every one of the five also has a sensible default payload**, so an emit with an
empty body still produces a conforming event — which is what makes the form
usable before you have read the specification.

## `token-claims-change`

*A claim behind the token changed while the token is still valid — a role, a
group, a tenant.* It is the event that makes the access-token-lifetime argument
go away: the receiver does not have to wait for a refresh to find out that
somebody left the group that authorises them.

- **Required:** `claims` (an object).
- **The trap:** it is neither a whole token nor a diff. It carries **only the
  claims that moved, with their new values**, and a receiver applies them over
  what it holds. So *a group membership taken away is the new **list*** rather
  than the group that went — which catches people.
- **In the register:** the claims are **merged** into the row, not replaced,
  for that same reason. A `token-claims-change` about a session already
  `revoked` is a warning: nothing is wrong with saying so and there is nothing
  left to apply it to, which is what makes it worth noticing.
- **Default payload:** `{"groups": ["everyone"]}`.

## `credential-change`

*A credential was enrolled, renewed, revoked or deleted.* It is the event a
receiver acts on **without ending anything**: a second factor being deleted does
not invalidate the session it was used to establish, and it does change what that
session should be allowed to do next.

- **Required:** `credential_type` and `change_type`.
- `change_type` is **closed** — `create`, `revoke`, `update`, `delete`. Those
  four are the whole lifecycle and a fifth would be a receiver guessing.
- `credential_type` is **open** — `password`, `pin`, `x509`, `fido2-platform`,
  `fido2-roaming`, `fido-u2f`, `verifiable-credential`, `phone-voice`,
  `phone-sms`, `app` — and a value not on that list is carried with a warning,
  because the specification allows types two parties agree between themselves.
- **Optional and worth sending:** `friendly_name` (for a screen, not for a
  decision); `x509_issuer` and `x509_serial` together, because serial numbers are
  unique per *issuer* and not globally, so the second is useless without the
  first; `fido2_aaguid`, which names a *model* of authenticator rather than the
  individual one, which is what makes it publishable.
- **In the register:** appended to a short list of credential changes on the row
  (the last ten). It changes no state and produces no warning — nothing about
  this event contradicts anything.
- **Default payload:** `credential_type: password`, `change_type: update`.

## `assurance-level-change`

*The strength of the authentication behind this session moved.* **A decrease is
the interesting one**, and it is easy to forget it can happen at all: a second
factor that has expired, or a session carried forward past the window its step-up
was good for, both lower assurance without anybody signing in again.

- **Required:** `namespace` and `current_level`.
- `namespace` is required because **the event is useless without it**: "AAL2"
  means nothing until you know it is NIST's. The list is open —`RFC8176`,
  `RFC6711`, `ISO-IEC-29115`, `NIST-IAL`, `NIST-AAL`, `NIST-FAL` — and an
  unlisted one is carried with a warning. It defaults to
  `caep.assuranceNamespace` (`NIST-AAL`).
- `current_level` is a **free string**, precisely because the namespace decides
  its shape.
- **Optional and worth sending:** `previous_level` — without it a receiver can
  see that assurance changed and not whether it went *up*. And
  `change_direction` (`increase` / `decrease`), said outright rather than
  inferred, because a receiver cannot order two levels in a namespace it does not
  understand, which is the ordinary case across two organisations.
- **In the register:** the row's assurance is replaced. If the event's
  `previous_level` disagrees with what the register holds, a **warning** says so:
  one event about this session has been missed, or two transmitters are talking
  about it.
- **Default payload:** the configured namespace and `aal2`.

## `device-compliance-change`

*The device the session runs on fell out of, or back into, compliance with
whatever the estate's policy is.*

- **Required:** **both** `previous_status` and `current_status`, each
  `compliant` or `not-compliant` — closed.
- **Why both are required** is the most useful thing about this event: it makes
  it safe to act on **out of order**. A receiver holding `compliant` that gets an
  event whose `previous_status` is `not-compliant` knows it has missed one, and
  that gap is invisible from either event on its own.
- **The spelling trap:** the hyphen in `not-compliant` is the specification's.
  `noncompliant` is silently ignored by a conforming receiver.
- **The subject trap:** it should normally name the **device** as well as the
  person, because the same person on a second device is unaffected and a
  receiver cannot tell that from a subject naming only them. The complex subject
  this service composes has room for `device` and `tenant` members, and
  **nothing here ever fills them in** — no device is attested to this service —
  so a `device-compliance-change` from this transmitter names the person and the
  session only. That is worth knowing before testing a receiver against it: the
  event is conforming, and it is less specific than the one a real device
  management system would send.
- **In the register:** the row's compliance is replaced, with the same
  missed-event warning as above — and here that warning is the whole reason CAEP
  makes `previous_status` required.
- **Default payload:** `compliant` → `not-compliant`.

## `risk-level-change`

*A risk engine changed its mind about somebody.* It is **the only one of the
eight that is a judgement rather than a fact** — the other seven report something
that happened — which is why it carries a reason and why a receiver is expected
to weigh it rather than act on it.

- **Required:** `principal` and `current_level`.
- `principal` says **what** the risk level is about, and it is required because
  the subject alone cannot say: a complex subject names a person *and* a device
  *and* a session, and "risk went to HIGH" about the device is a different fact
  from the same sentence about the person. Values are open: `USER`, `DEVICE`,
  `SESSION`, `TENANT`, `ORG_UNIT`, `GROUP`. **They are upper case here and lower
  case in a complex subject's member names**, which catches everybody once.
- `current_level` is closed and upper case: `LOW`, `MEDIUM`, `HIGH`. It defaults
  to `caep.defaultRiskLevel` (`MEDIUM`).
- **Optional and worth sending:** `previous_level`, and `risk_reason` — which is
  *recommended* rather than required and is the member that decides whether a
  receiver can do anything but step up: "impossible travel" and "credential seen
  in a breach corpus" call for different answers.
- **In the register:** the row's risk is replaced, with the same missed-event
  warning.
- **Default payload:** `principal: SESSION` and the configured default level.

---

## What never produces a CAEP event

Only a **browser sign-on session** creates a row in the register, so nothing
below is ever the subject of one. That is not an omission — none of them is a
session in CAEP's sense:

- a **Kerberos** AS-REQ, TGS-REQ or AP-REQ, and a ticket-granting ticket
  expiring;
- an **LDAP** bind or unbind, though the connection *is* a session in RFC 4511's
  sense (`/admin/sessions` lists it as one);
- **WS-Trust**, **SCIM**, **SPIFFE**, **OpenID4VCI** and **OpenID4VP** requests;
- the **token, refresh, introspection, revocation and UserInfo** endpoints —
  including revoking every token a person holds;
- reading the **admin console**, which presents the same session on every page
  and reports nothing, because it is not a protocol SSO.

## Seeing what happened

- **`/admin/caep`** — the settings, the catalogue of all eight with every
  member, and the by-hand emit form.
- **`/admin/caep-sessions`** — one row per session this service has *held*,
  including the ones it no longer holds, with a count per event type. **The
  register outliving the session is the point:** a row saying `revoked` is the
  only remaining evidence that the session existed and was revoked.
- **`/admin/caep-sessions/session?id=…`** — one session opened out: every event
  actually sent about it, in order, with the `jti`, the stream it went out on,
  and what the register noticed as it was applied.
- **`/admin/caep-sessions`, *Per application*** — the same events counted the
  other way round: **what this transmitter has said to each RECEIVER, across
  every session**, with a count per event type, the distinct sessions it has
  been told about, and the pipe counters beside them. It is the table to read
  when more than one receiver exists and one of them is not getting what you
  expect. Two rows answer most of those questions on their own: an application
  with **no stream** (declared here, nothing agreed yet) and one whose *Takes*
  column says **none of CAEP's eight**.
- **`/admin/ssf`** — the streams. A session with a count of zero almost always
  means no stream asked for that type.
- **`GET /admin-api/caep`** and **`GET /admin-api/caep/sessions`** — the same,
  without a browser; the per-receiver rows are the `applications` member of
  both, searched with `appq` and paged with `applicationsPage`.

## The settings

| Setting | Default | What it does |
|---|---|---|
| `caep.enabled` | on | off drops all eight from `events_supported` |
| `caep.autoEmit` | on | off leaves the register accurate and sends nothing by itself |
| `caep.autoEmitTypes` | the three | which of the three observable acts emit; naming one of the other five is dropped with a warning |
| `caep.eventsSupported` | all eight | which types this transmitter will agree to deliver |
| `caep.omitEventTimestamp` | off | on produces a conforming event with **no** `event_timestamp`, to break a receiver that assumes one |
| `caep.includeReasons` | on | whether `reason_admin` / `reason_user` are sent |
| `caep.reasonLanguage` | `en` | the language tag those two are keyed by |
| `caep.assuranceNamespace` | `NIST-AAL` | the default namespace for `assurance-level-change` |
| `caep.defaultRiskLevel` | `MEDIUM` | the default level for `risk-level-change` |
| `caep.maxSessionsTracked` | 200 | how many sessions the register holds before dropping the oldest |
| `ssf.criticalSubjectMembers` | empty | publishing `session` makes a receiver that ignores it refuse the event instead of acting on the person |

All of them are runtime-settable on `/admin/caep`; see
[configuration](configuration.md).
