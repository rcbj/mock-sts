# ssf/

The Shared Signals Framework (OpenID SSF 1.0, **final 2 September 2025**), and
the four IETF documents it is assembled from. The **seventeenth** protocol
family here and the first one that TALKS BACK.

| File | What it is |
|---|---|
| `ssf.js` | The routes. The metadata document, the stream management API, status, subjects, verification, poll delivery, and the two endpoints that are not SSF at all — `POST /ssf/receive` and `GET /ssf/received`, which are this service acting as a RECEIVER so that a client can be the transmitter. |
| `ssf_subjects.js` | **RFC 9493** subject identifiers: the eight formats with their CLOSED member sets, SSF's complex subject, and the nesting ban. A LIBRARY. |
| `ssf_events.js` | The event vocabulary — SSF's two — and the **RFC 8417** Security Event Token they travel in. A LIBRARY. |
| `ssf_streams.js` | The streams, their subjects and their queues, per trust realm. A LIBRARY. |
| `ssf_http.js` | **THE SECOND OUTBOUND REQUEST IN THIS REPOSITORY.** RFC 8935 push delivery. A LIBRARY. |
| `ssf_auth.js` | Who may drive a stream: two schemes and two scopes. A LIBRARY. |
| `caep.js` | **CAEP's session register**: what state CAEP believes each session is in, and how many events of which type have been sent about it. A LIBRARY, and one of the two files here that are not vocabulary. |
| `risc.js` | **RISC's account register**: the three states RISC tracks per account, the opt-out gate, and how many events of which type have been sent. A LIBRARY, and `caep.js`'s SIBLING rather than a generalization of it — see below. |

Seven of the eight register nothing (rule 3), so their position in the route
order is not a position. `ssf.js` is required at **23b in `server.js`** — after
`admin-ui/admin.js`, whose eighth slot it fills, and before `sts_metadata.js`,
which is last for everybody.

---

## THE ONE PARAGRAPH TO READ FIRST: SSF IS THE PIPE AND NOT THE VOCABULARY

SSF says how a RECEIVER and a TRANSMITTER agree a **stream**, who the events on
it are about, what they travel in, and how they get delivered. It defines
**exactly two events of its own**, and both are about the pipe rather than
about a person:

* **verification** — the receiver asked "is this stream alive?", and this is the
  answer travelling the ordinary delivery path. It is the ONLY end-to-end test
  a stream has: a 200 from the management API says the configuration was
  accepted and says nothing whatever about whether an event can reach the
  receiver.
* **stream updated** — the stream's status changed and the receiver is being
  told IN BAND rather than having to poll. It is the one event a receiver gets
  without asking for it, and the one whose absence is hardest to notice: a
  stream quietly paused at the transmitter looks exactly like a service where
  nothing has happened lately.

The vocabularies are **CAEP** (what happened to a SESSION) and **RISC** (what
happened to an ACCOUNT). **CAEP has been here since 2026-09-03 and RISC since
2026-09-04.** The family is complete.

**THE PROMISE THIS FILE MADE WAS KEPT TWICE, AND THE SECOND TIME IS THE ONE
THAT PROVES IT.** The claim was that adding a vocabulary would be rows in
`ssf_events.js`'s table and nothing else, because the envelope, the subject
grammar, the delivery, the queues, the stream management, the console page and
the management API are all vocabulary-independent. CAEP tested it once and
this file then recorded four things outside the table that had to change.
**RISC changed NONE of those four.** `checkMember()` grew not one value type;
`transmit()`'s subject refusal was already written against the ROW and did not
move; `streamCoversSubject()`'s complex-subject rule is CAEP's and RISC's
subjects are plain, so it was not touched. Fourteen event types cost the
catalogue's machinery nothing at all, which is the only kind of evidence a
claim like that can have.

What RISC did add outside the table is one thing CAEP also added and one
genuinely new: a REGISTER of its own (`risc.js` — an account is not a session)
and an observer on a DIFFERENT store. CAEP watches `authn.js`; RISC watches
`ldap_server.js`. That is not a second copy of one mechanism, it is the
provisioning layer and the authentication layer, and the whole difference
between the two profiles is which of them the sentence is about.

Eight event types later, the things outside that table that had to change
were:

* **`caep.js`**, which is not vocabulary. A row says what an event MEANS; that
  file holds what the events are ABOUT — a session, the state CAEP believes it
  is in, and what has been said concerning it. None of that is a property of
  any event type or derivable from the catalogue.
* **one refusal in `transmit()`**, and it is written against the ROW rather
  than against a vocabulary: an event whose row says `subject: 'required'` and
  that carries none is refused. RISC's rows will be `required` too and that
  line will not change.
* **one rule in `streamCoversSubject()`**, without which CAEP would deliver
  nothing at all: a stream that names a PERSON covers a complex subject naming
  a session of theirs. That is SSF section 4's own intent rather than CAEP's,
  and it was simply unreachable while no event carried a complex subject.
* **`checkMember()` in `ssf_events.js`**, which grew four value types —
  number, array-of-strings, object and language map. That is the catalogue's
  own machinery and not a branch naming an event type.

Nothing else. If a function anywhere in this directory grows a branch that
names one of SSF's own two event types, one of CAEP's eight or one of RISC's
fourteen, that is the design going wrong.

---

## WHAT RISC COST, AND WHY `risc.js` IS `caep.js`'s SIBLING AND NOT ITS
## GENERALIZATION

* `ssf/ssf_events.js` — fourteen rows, three common members written once and
  used on ONE of them, one shared `CREDENTIAL_TYPES` array (RISC 1.0 section
  2.7 defines `credential_type` BY REFERENCE to CAEP's, so the two lists are
  one list and not two alike ones), a `subjectFormats` column, a `deprecated`
  column, `subjectAdvice()` and `nearestMember()`. **No new value type in
  `checkMember()`.**
* `ssf/risc.js` — the register, three state machines and the opt-out gate.
  NEW, and a LIBRARY.
* `ssf/ssf.js` — the require, `risc.noteTransmitted()` beside CAEP's,
  `riscAutoEmit()`, `sendOneRiscEvent()`, the observer installation and the
  tenth admin slot's filler.
* `ldap/ldap_server.js` — **`setAccountObserver()`, an INVERTED HOOK**, on the
  same terms as `authn.setSessionObserver()` and with five call sites rather
  than one. See below.
* `common/config.js` — a `RISC` group of eleven, `env/defaults.js`
  regenerated.
* `common/audit.js` — four actions in the existing `signals` category.
* `admin-ui/admin.js` — the tenth slot, `/admin/risc`, `/admin/risc-accounts`
  and `/admin/risc-accounts/account`, `riscAccountChooser()`, two `SECTIONS`
  rows, two `LIST_PARAMS` rows and a `SETTING_HOMES` row.
* `mgmt-api/admin_api.js` — two GETs and a POST with three actions;
  `mgmt-api/admin_api_spec.js` — the `Risc` schema.
* `sts_metadata.js` — one `SPECS` entry and **six** `ENDPOINTS` rows, three
  admin and three management API — which is the count the CAEP block's own
  note warns about: a family's protocol endpoints are obvious and the CONSOLE
  and MANAGEMENT API rows it also costs are the ones a checklist forgets.
* `tests/risc_register.js` — the three state machines, the gate and the
  register in process.

**WHY THE REGISTER IS A SECOND FILE.** A session and an account are not the
same kind of thing. A session begins, is used and ends, and there are many of
them per person; an account IS the person, has no beginning this service can
see, and outlives every session on it. A register serving both would have one
row that is sometimes one and sometimes the other. Three further differences
each fall out of that and none of them is a preference:

* **`observe()` answers with a LIST.** A session act is one act. A directory
  write is not: one `PUT /Users/:id` can set `active` to false AND change a
  mail address, which is two RISC events about one write, and an observer that
  returned the first would drop the second with nothing anywhere saying so.
* **The register is keyed on the PERSON and not on the subject.** A RISC
  subject is composed in whichever format `risc.subjectFormat` names, and the
  two identifier events ignore that setting and use `email` — so one account
  legitimately produces two different `subjectKey()`s, and a register keyed on
  the subject would split one person into two rows *at exactly the moment
  their identifier changed*, which is the one moment the row is worth having.
* **The state is three things.** A lifecycle, an opt-out state and a
  credential standing, moving independently: an account can be opted out and
  perfectly healthy, or compromised and still enabled. A CAEP row has one
  `state` because a session is alive or it is not.

---

## THE OPT-OUT GATE, AND THE EXCEPTION WITHOUT WHICH IT IS A TRAP

RISC section 2.8 gives an account three states — `opt-in`,
`opt-out-initiated`, `opt-out` — and says the last means it is NOT
participating in event exchange. `risc.honourOptOut` is on by default because
that is the conforming behaviour, and a suppressed event is counted on the row
(`suppressed`), which is the one number in this console that says a receiver
heard nothing **on purpose**.

**The four opt-out events are never suppressed**, and that exception is the
whole rule rather than a convenience:

* `opt-out-effective` is the event that ANNOUNCES the account has reached the
  silent state. Gating it would enter that state without telling anybody, so a
  receiver would see the signals simply stop — indistinguishable at the far end
  from a transmitter that has gone down.
* `opt-in` is sent FROM the opt-out state by definition. It is the only way a
  receiver ever learns the account came back, and gating it would make the
  opt-out permanent for every receiver in the world.

The middle state exchanges everything, and the specification says why: it
exists to stop a hijacker from opting out the moment they take an account over
and silencing the very events that would report them.

**One more asymmetry, and it looks like a bug until it is stated.** A
suppressed AUTOMATIC event still moves the register and a suppressed HAND
EMISSION does not. In `observe()` the directory really changed — somebody was
deleted, `active` really did go false — so the register follows the act whether
or not anybody was told. In `riscEmit()` the act IS the emission: nothing
happened except that somebody asked this service to say something and it did
not, and applying the state would leave a register asserting that an account
was purged on the strength of a message never sent.

---

## THE FOUR ACTS THIS SERVICE CAN OBSERVE IN ITS DIRECTORY, AND THE TEN IT
## CANNOT

| Act | Event | Where it is noticed |
|---|---|---|
| a person is deleted | `account-purged` | `deletePerson()` and the LDAP delete handler |
| `scimActive` goes false | `account-disabled` | `writePerson()` and the LDAP modify handler |
| `scimActive` goes true | `account-enabled` | the same |
| `mail` / `telephoneNumber` / `mobile` moves | `identifier-changed` | the same |

**THE OBSERVER SITS ON THE STORE AND NOT ON A DOOR**, which is why there are
five call sites in `ldap_server.js` rather than one in `scim.js`. The same act
reaches this directory over SCIM, over LDAP and from the console, and a RISC
feature that only noticed the SCIM one would report a deprovisioning done with
a PATCH and stay silent about one done with an `ldapmodify`. That is not a
smaller feature; it is a transmitter that lies by omission about half its own
traffic — **which is precisely the defect CAEP shipped with for one revision**
(`session-presented` from the OAuth2 authorization endpoint alone) and it took
a test naming every protocol to find, because a count of zero is also what
*nobody asked for that type* looks like.

**AND IT IS HANDED THE ATTRIBUTES BEFORE AND AFTER, AND `risc.js` DECIDES.**
The directory knows what a write is; it does not know that `scimActive` going
false is an `account-disabled`. That is RISC's reading and it belongs in RISC's
file — a version of `ldap_server.js` that answered "a disable happened" would
be the vocabulary leaking into the store.

**AN ABSENT ATTRIBUTE IS NOT A FALSE ONE.** `activeIn()` answers `null` for a
write that says nothing about `active`, because *nobody has ever said* and
*somebody said no* are two different facts and reading the first as the second
would emit an `account-disabled` for every person created without the
attribute.

**AND `active` STILL DEACTIVATES NOBODY HERE.** No endpoint reads it, no bind
is refused and no token is withheld; `scim_map.js` says so, because a mock that
silently pretended would teach a provisioning client that its deprovisioning
path works. What changed is that this service now SAYS so, over RISC — which is
exactly the division the profile draws: a transmitter reports and a receiver
decides.

The other ten describe things nothing here does — no breach corpus is searched
by this service and no recovery flow runs in it — so they are emitted by hand
from `/admin/risc` or `POST /admin-api/risc/emit`. **Four of those ten change
real state when they go**, because RISC section 2.8 defines each opt-out event
as *"the account is in the X state"* rather than as a report that it moved.

---

## THREE THINGS ABOUT RISC'S ROWS THAT SURPRISE SOMEBODY WHO KNOWS CAEP

* **Eleven of the fourteen have no payload members at all**, and only
  `credential-compromise` has a required one. **The subject carries the entire
  message**, so a subject naming the wrong person is not a partly wrong event —
  it is a wholly wrong one with nothing else in it to notice by. That is what
  makes `risc.subjectFormat` the consequential setting in the group.
* **The four common claims are not common here.** CAEP section 2 gives four to
  all eight of its events. RISC gives THREE — no `initiating_entity` — and
  gives them to exactly ONE of its fourteen. A reader porting CAEP's
  `withCommon()` across would attach four members to fourteen rows and produce
  thirteen events carrying members their specification does not define, which
  nothing would report.
* **One member name in the whole of Shared Signals uses a hyphen**, and it is
  `identifier-changed`'s `new-value`. `new_value` typed from habit produces an
  event that is well-formed, delivers, and tells the receiver nothing.
  `nearestMember()` in `ssf_events.js` names the near miss, and the generator
  deliberately does **not** silently correct it: a mock that quietly repaired
  the commonest mistake in an event type would be a mock that hid it.

**AND ONE OF THE FOURTEEN IS DEPRECATED BY ITS OWN SPECIFICATION.**
`sessions-revoked` — plural, every session the account has — is replaced by
CAEP's `session-revoked` — singular, the one the subject names. It is offered
by default and warned about on every event, because a transmitter that cannot
produce a deprecated event cannot be used to find out what a receiver does with
one, and receivers in the field still send and expect it.

**RISC SECTION 3.1 IS THE ONLY DELIBERATE DEFECT IN THIS SERVICE THAT A
SPECIFICATION ASKS FOR BY NAME.** Google's production RISC transmitter spells a
subject identifier's discriminator `subject_type` rather than `format`; the
specification records this, says the usage is deprecated, says new services
MUST NOT use it, and then tells relying parties they need code to work around
it anyway. `risc.googleSubjectType` renames the member on every RISC subject
this service sends, and on nothing else: CAEP and SSF's own events keep
`format`, because their specifications never had the problem.

---

## WHY THE SUBJECT GRAMMAR IS WRITTEN OUT HERE AND NOT VENDORED

`common/vendored/` holds byte-identical copies of the parent project's files,
and `kerberos/`'s eight codec modules are vendored for a reason this file's
`ssf_subjects.js` deliberately does not follow: **one wire codec must not exist
twice.**

A subject identifier is not a wire codec. It is JSON, and the defect that
matters in it is a READING — an accepted extra member, a missing required one,
a format name spelt from memory. If both ends of this project read one
implementation, a misunderstanding they SHARE is one neither can see: the round
trip passes and the workflow interoperates with nothing.

So the debugger has `client/src/ssf_client.js`'s grammar, this service has
`ssf_subjects.js`, they were written independently, and the parent project's
`tests/ssf_protocol.js` drives one against the other **over the wire** — every
one of the eight formats, the complex subject, and three refusals. That is the
argument `common/pq_jose.js` makes about the composite construction, applied to
a grammar instead of to a signature.

**THE CLOSED MEMBER SET IS THE CHECK THAT EARNS IT.** RFC 9493 section 3 gives
each format a closed set of members and every conforming receiver MUST reject
an identifier carrying one it does not recognise — it cannot tell whether the
member NARROWS the subject. A transmitter that accepted a loose subject would
teach a receiver to send documents nothing else takes, and the sender would
never find out.

---

## `ssf_http.js` IS THE SECOND OUTBOUND REQUEST, AND IT IS A WEAKER CASE THAN
## THE FIRST

`federation/federation_http.js` is the first, and its header makes an argument
this one **cannot**:

> THOSE URLS ARE SUPPLIED BY THE CALLER. THESE ARE SUPPLIED BY THE
> ADMINISTRATOR.

It enforces that by refusing to take a URL at all: `fetchJson()` takes a
relationship record and the NAME of an attribute on it, and there are three
legal names.

**A push delivery endpoint cannot work that way, and pretending otherwise would
be the dangerous version of this feature.** RFC 8935 push delivery IS the
receiver telling the transmitter where to post — that is what the delivery
method is, not an implementation choice here — so any transmitter that speaks
push takes a caller-supplied URL, including every commercial one.

So the honest statement is that this file makes an outbound request to an
address a caller chose, and these are the four bounds:

1. **`ssf.pushDelivery` turns it off entirely.** With it off this service still
   speaks the whole of SSF over POLL delivery, where nothing is dialled at all,
   and `delivery_methods_supported` then advertises only `urn:ietf:rfc:8936` —
   so a receiver finds out at stream creation rather than by never receiving
   anything.
2. **`ssf.pushAllowedHosts` is an allowlist and is EMPTY BY DEFAULT, meaning
   any.** That default is the one deliberate looseness here and it is what makes
   this usable as a mock. It is a HOST list rather than a URL list on purpose: a
   receiver legitimately moves its endpoint path and does not legitimately move
   to another host.
3. **https only unless `ssf.pushAllowInsecure`.** What travels on a push is not
   a credential, it is an EVENT — that somebody's session was revoked, that an
   account was disabled — which is somebody's security posture in transit, and
   the receiver's own `authorization_header` travels beside it. Both halves want
   TLS, and every insecure request is LOGGED rather than only the setting being
   logged once.
4. **No redirects, a capped body and a timeout.** A 302 from a push endpoint is
   not a protocol this service speaks, and following one would post the event —
   and the receiver's authorization header — wherever the Location said.

**One thing is NOT a bound and must not be mistaken for one.** The management
API is gated by `ssf.authRequired`, which ships ON, but every credential this
service accepts is a turnstile: anybody can get a token with either SSF scope,
and any username with any password but `invalid` passes Basic. "A receiver
created the stream" is therefore not evidence of much.

---

## IT DOES NOT RETRY A FAILED PUSH, AND THAT IS DELIBERATE

RFC 8935 section 2.4 lets a transmitter retry. This service does not, because a
mock that retried would make a receiver's ONE-SHOT failure invisible: a client
under test that answers 500 to the first push and 202 to the second looks, from
its own logs, like a client that works.

The failure is recorded on the stream's own log, the event stays on the queue,
and `POST /admin-api/ssf/transmit` sends another when somebody asks. It is on
`GET /ssf`'s *what it deliberately does not do* list in those words.

---

## THE THREE OUTCOMES OF A PUSH ARE THREE AND NOT TWO

A 202 is delivery. A **400 with `{err, description}`** is the receiver
REFUSING — it read the SET and would not take it — and that is a completely
different fact from a network failure. It is also the most interesting thing a
receiver ever says, and `pushSet()` reports it separately for exactly that
reason: the stream's log can then tell "nothing answered" from "the receiver
said invalid_audience".

200 and 204 are accepted as well, and **not silently**: a receiver answering one
of those is very slightly wrong, the event did arrive, and a mock that refused
would be testing the transmitter's pedantry rather than the receiver's
behaviour. The note says which it was.

---

## `aud` IS REQUIRED AND IS NOT DEFAULTED TO THE AUTHENTICATED CALLER

This is the one place in this directory that is stricter than the rest of the
service, and defaulting was written first and taken out.

A receiver whose `aud` was invented for it never finds out that the member is
required, and the first real transmitter it meets refuses every stream it
creates. Worse, the audience it checks for ITSELF in would then be a name this
service chose — so an event it ought to refuse with `invalid_audience` would be
one it accepts.

**The permissive posture everywhere else in this service is about CREDENTIALS.**
This is a protocol member with a consequence at the far end, and inventing one
teaches a client something false.

---

## A PAUSED STREAM KEEPS QUEUEING AND A DISABLED ONE DROPS

SSF 1.0 section 7.1.2's three statuses, and the difference between the middle
one and the last is the whole reason a receiver has a pause: it is "I was not
listening" against "it did not happen". `setStatus()` drops the queue on a
disable and says how many went, so that a reader can see it happen rather than
discovering later that the queue is empty.

A status change also emits a **stream-updated** event ON the stream, if the
receiver agreed that type. A disabled stream cannot carry one — `enqueue()`
refuses — and that is correct rather than a gap: there is nowhere for it to go
and nothing to poll it from.

---

## THE PATHS USE A SLASH WHERE SSF's EXAMPLES USE A COLON

SSF's own examples write `/subjects:add`, and **express reads `:add` as a route
parameter** — so a route registered that way matches
`/ssf/subjectsANYTHING` and matches the literal path only by accident.

Nothing about this is visible on the wire: SSF fixes no paths and publishes
every endpoint in its configuration metadata, so a receiver reads
`add_subject_endpoint` and never composes one. It is written down because the
next person to "fix" the paths will reach for the colon.

---

## THE METADATA DOCUMENT IS NEVER GATED, AND ANSWERS WHILE THE FAMILY IS OFF

Two separate decisions, both deliberate.

**Never gated**, whatever `ssf.authRequired` says: a receiver has to be able to
read what the endpoints are and which schemes they take BEFORE it can
authenticate to one, and a transmitter whose discovery document needs a
credential is one nothing can bootstrap against. It is the rule
`scim.authDiscovery` expresses for the ServiceProviderConfig, with the setting
left out because there is no version of this that is useful closed.

**Answers while `ssf.enabled` is off**, when every other endpoint answers 501:
a receiver that finds this document and then a 501 has learned something
specific, where a 404 would leave it unable to tell "this service does not speak
SSF" from "the path is wrong".

---

## TWO SCHEMES AND TWO SCOPES

SSF 1.0 section 8 requires these endpoints to be protected and — unlike RFC
7644, which names six schemes and leaves it there — has the transmitter
**publish** what it accepts, in `authorization_schemes`. So a receiver discovers
how to authenticate rather than guessing, and `ssf_auth.js`'s list and that
member are one table.

**Two schemes and not six, and that is a decision.** SCIM offers all six of RFC
7644's because that RFC names all six and a provisioning client meets them in
the wild. SSF names none — `authorization_schemes` is an open list of
`spec_urn` values and the only one its examples use is OAuth 2.0 — so this
offers that one and HTTP Basic beside it, which exists so that a client under
test that has not implemented a token flow yet can still reach every endpoint.

**`ssf:read` and `ssf:write` differ in what they permit**, which is the second
place in this service after SCIM where two scopes do. A read token is refused
for every write with a 403 NAMING THE SCOPE, because a refusal a caller cannot
act on is worse than none.

Basic grants BOTH, and says so: a scheme with no scope in it cannot express the
difference, and returning a read-only decision would be a refusal with nothing
a client could send to get past it.

---

## WHAT THIS FAMILY DELIBERATELY DOES NOT DO

Each of these is on `GET /ssf` in the same words, because a mock's omissions are
the half a reader cannot discover from a protocol trace.

* **~~It generates no event on its own.~~ IT DOES NOW, AND CAEP IS WHY.** That
  sentence led this list until 2026-09-03 and the reason it could is exactly
  the reason it no longer can: SSF defines no event about a session, so a
  transmitter that emitted one would have been inventing a vocabulary — and
  CAEP *is* that vocabulary. A sign-in emits `session-established`, a session
  presented again and honoured emits `session-presented`, and a sign-out emits
  `session-revoked`, on every stream that asked for the type and whose subjects
  cover that session, with nobody having typed anything.

  **THE MIDDLE ONE WAS OIDC-ONLY UNTIL 2026-09-03, and it was the one real gap
  in this feature.** The other two go through a FUNNEL — `startSession()` and
  `dropSession()`, which every browser SSO profile here reaches — so both were
  protocol-independent from the day CAEP landed. A presentation has no funnel:
  it is a thing each protocol endpoint decides it is doing, and only
  `oauth-oidc/oauth2.js` called `authn.notePresented()`. `saml2_sso.js`,
  `saml11_sso.js` and `wsfed.js` each read `sessionOf(req)` to answer a request
  out of an existing session — which *is* single sign-on — and reported
  nothing. So a receiver watching a SAML or WS-Federation session saw it start
  and end with every single sign-on between the two **missing**, and the
  evidence was a count of zero, which in this protocol is also exactly what
  *nobody asked for that type* looks like. All four call it now, each from the
  branch that HONOURS the session rather than from `sessionOf()` (which runs
  several times per request, so an event there would be several events for one
  act) and below the branches that refuse — a `wauth` this session cannot
  satisfy, an `authn_error`, an IsPassive with nothing usable — since those end
  in a refusal and nothing was honoured. `tests/caep_presented_every_protocol.js`
  holds all four to it. `caep.autoEmit` puts the old behaviour back rather
  than leaving it only in the history of this file. The other five CAEP events
  describe things nothing here does — no device reports compliance to this
  service and no risk engine talks to it — so those are still emitted only
  when asked for.
* **It never retries a failed push.** See above.
* **It verifies nothing about a subject.** A stream may name somebody who has
  never been here, which is what a receiver's "I do not know this subject" path
  needs.
* **A `verified: true` on an Add Subject request is believed.** SSF lets a
  receiver say it has already confirmed the subject; a real transmitter may then
  skip a confirmation step, and there is none here to skip.
* **Streams are in memory and die with the process**, like everything else this
  service mints. `persistence/CLAUDE.md`'s rule decides it and the reason is the
  one it gives everywhere: the signing key is regenerated on every start, so a
  queue restored from disk would be tokens nothing can verify.

---

## THE TWO DELIBERATE DEFECTS

The same device as `oauth2.breakIdTokenNonce` and the Kerberos names that stay
unknown: a permissive transmitter is hard to write error handling against, so
the errors have to be reachable on purpose.

* **`ssf.legacySubClaim`** adds the deprecated `sub` claim beside `sub_id`. RFC
  8417 section 2.2 discourages it and SSF uses `sub_id` because the thing an
  event is about may be a person AND a device AND a session at once; a client
  written against a transmitter that gets this wrong reads nothing from a
  conforming one, and this is how that client is caught.
* **`ssf.breakSetSignature`** changes ONE CHARACTER of the signature after
  signing.

**And the second one has a trap in it that cost a test run.** It changes the
**first** character of the signature and not the last, and that is not a style
choice: the last character of a base64url string usually carries PADDING BITS
the decoder discards. An RS256 signature is 256 bytes — 2048 bits in 342
base64url characters of six bits each — so its final character has four bits
nothing reads, and changing `A` to `B` there produces a token that looks
altered, **decodes to the same bytes, and verifies perfectly**. A deliberate
defect that is not a defect is worse than none at all, because a test passes
against it.

It is a character change rather than a truncation for a different reason: a
truncated signature is refused by the base64url decode and never reaches the
verify, so a client reports a MALFORMED TOKEN rather than a BAD SIGNATURE — two
different bugs for whoever is being tested.

---

## THE SIGNATURE GOES THROUGH `helpers.signJwtAs()` AND GETS THE WHOLE TABLE

`ssf_events.js` has no signer of its own, which is what gives this family every
algorithm the rest of the service has for no code at all: RS256, the PS and ES
families, EdDSA, and the **post-quantum** ones — ML-DSA at three sizes, SLH-DSA
at two, and the six composite ML-DSA + traditional algorithms.
`ssf.signingAlgorithm` picks one.

**A SET is the document in this service most worth signing that way.** It
records that something HAPPENED, RFC 8417 section 4.1.4 forbids it to expire,
and it is therefore read long after it was written — which is the case a
harvest-now-decrypt-later argument is actually about.

`signSet()` is **asynchronous and must stay that way**: an SLH-DSA-SHAKE-128s
signature measured 14.6 seconds on this service's own thread on 2026-08-29,
during which it answers nobody. `signJwtAsAsync()` routes a post-quantum
signature to the worker pool and resolves an RS256 one in place.

### IT ALSO FOUND A DEFECT IN `common/crypto.js`, AND THAT IS WORTH KEEPING

RFC 8417 section 2.2 gives a SET `typ: "secevent+jwt"`, and a receiver that
dispatches on the media type — several do — drops one without it with no error
anybody sees. `ssf_events.js` asks for that header.

`jsonwebtoken` merges `options.header`, so the library path had always honoured
it. **The other two signers did not**: the `ownSigner` branch (EdDSA and ES256K,
the two the library refuses) and the post-quantum branch each hard-coded
`typ: 'JWT'` and ignored `options.header` entirely — so the SAME call produced a
different header depending on which algorithm was chosen, and no caller could
have seen that coming. `protectedHeaderFor()` in `common/crypto.js` is the fix
and all three paths go through it now; `alg` and `kid` are still that function's
to set, because the algorithm and the key are what was actually used.

---

## THE CONSOLE AND THE MANAGEMENT API

`/admin/ssf` and `/admin-api/ssf` reach this directory through
**`admin.setSignalsReporter()`**, the eighth slot on `admin-ui/admin.js`, and
rule 3e's test answers yes in both directions at once: a require from
`admin.js` to `ssf.js` would CLOSE A CYCLE (this file requires that one for the
page shell and the gate), and a require from `mgmt-api/admin_api.js` would MOVE
ROUTES — every `/ssf` endpoint and the well-known document ahead of the
management API's own and of ldap, scim and spiffe.

The slot carries ONE object, validated whole, because a filler that installed
the reader without the action would leave that page able to LIST streams and
unable to change any of them.

**`action` returns a PROMISE and it is the only slot here that does.** Every
other action function in that console answers from memory; transmitting a
Security Event Token signs a JWS — possibly on the worker pool — and then POSTs
it to somebody else's endpoint. Neither can be done synchronously, and
pretending otherwise would mean the page reporting "sent" before anything had
been.

**There is deliberately no `create` action**, on the page or in the API, and
that is rule 7 read exactly rather than a gap. A stream carries a delivery
endpoint THIS SERVICE WILL DIAL, and the one place that URL may come from is a
receiver that authenticated at `POST /ssf/stream` and asked. A console form or a
management API operation that could mint one would be a second, ungated door
onto the outbound request `ssf_http.js` spends its header bounding — so there is
no control to mirror, and the parity holds.

---

## WHAT ADDING A PROTOCOL FAMILY COST HERE

For the next person adding one, this family's full list:

* `common/config.js` — a `SSF` group, and `env/defaults.js` regenerated with
  `node env/generate_defaults.js`;
* `common/applications.js` — a row in `PROTOCOLS`, two rows in
  `SCHEMA.attributes`, two in `EDITABLE`, and **a new `deliveryAttribute` role
  in `declarationAttributes()`**: a push endpoint is where an EVENT goes, which
  is the same question `redirectAttribute` answers for a browser family and is
  not a browser redirect, and calling it one would make a table this repository
  reads literally say something false about the one attribute here with an
  outbound request behind it;
* `common/audit.js` — a `signals` category and eight actions;
* `admin-ui/admin.js` — the eighth slot, `/admin/ssf` and its action route, a
  `SECTIONS` row with its `blurb`, and a `SETTING_HOMES` row;
* `admin-ui/crypto_metadata.js` — a row in `FAMILIES`, whose `name` must match
  the card in `sts_metadata.js`'s `PROTOCOLS` exactly, or the drift check
  reports it in both directions;
* `mgmt-api/admin_api.js` — a GET and a POST with four actions;
  `mgmt-api/admin_api_spec.js` — the `Ssf` schema;
* `sts_metadata.js` — five `SPECS` entries, **fourteen** `ENDPOINTS` rows and a
  `PROTOCOLS` card. It was eleven until 2026-09-01, and the three that were
  missing are the ones that are not `/ssf/*` at all: `/admin/ssf`,
  `/admin-api/ssf` and `/admin-api/ssf/:action`. That is worth knowing because
  it is the shape of the mistake rather than one instance of it — a family's
  own endpoints are obvious and the CONSOLE and MANAGEMENT API rows it also
  costs are the ones a checklist forgets. `tests/vendored/sts_metadata.js` is
  what caught them, in the direction only it checks: registered and described
  nowhere;
* `oauth-oidc/oauth2.js` — the two scopes in `scopes_supported`;
* `server.js` — the require, at 23b.

---

## AND WHAT ADDING A VOCABULARY OVER IT COST, WHICH IS THE MORE USEFUL LIST

CAEP is the first, RISC is the second, and the two lists are different sizes on
purpose — the point of the section above is that this one is short.

* `ssf/ssf_events.js` — eight rows, the four common claims written once, and
  four value types in `checkMember()`;
* `ssf/caep.js` — the register, the state machine and the report. NEW, and a
  LIBRARY;
* `ssf/ssf.js` — the require, the subject refusal in `transmit()`, the
  `caep.noteTransmitted()` call, `caepAutoEmit()`, the observer installation
  and the ninth admin slot's filler;
* `ssf/ssf_streams.js` — the complex-subject coverage rule;
* `authn/authn.js` — **`setSessionObserver()`, an INVERTED HOOK**, because
  `authn` is 8 in the require order and this directory is 23b. Plus
  `notePresented()`, spent once from `oauth-oidc/oauth2.js`;
* `common/config.js` — a `CAEP` group of ten, and `env/defaults.js`
  regenerated;
* `common/audit.js` — four actions in the EXISTING `signals` category, because
  a CAEP event travelling is an `ssf.event.transmit` and a second category
  would have split one delivery across two filters;
* `admin-ui/admin.js` — the ninth slot, `/admin/caep` and
  `/admin/caep-sessions` with their action routes, two `SECTIONS` rows with
  their blurbs, and a `SETTING_HOMES` row;
* `mgmt-api/admin_api.js` — a GET and a POST with three actions;
  `mgmt-api/admin_api_spec.js` — the `Caep` schema;
* `sts_metadata.js` — one `SPECS` entry and **four** `ENDPOINTS` rows, of
  which the two that are easy to forget are again the CONSOLE and MANAGEMENT
  API ones rather than the protocol's own;
* `tests/caep_register.js` — the state machine and the register in process.

**THE ONE THING THAT IS NOT A FILE**, and it is the same one the eighth slot's
section warns about: the refusal sentence is `Unknown action "x". The three
are: …`, with the count from `helpers.numberWord(CAEP_CONSOLE_ACTIONS.length)`.
It is READ by `tests/vendored/admin_api.js` and
`tests/vendored/sts_admin_api_operations.js`, and a handler that writes it its
own way turns both checks off with nothing failing.

---

## THE THREE ACTS THIS SERVICE CAN OBSERVE, AND THE FIVE IT CANNOT

`caep.autoEmitTypes` names the first three and drops anything else with a
warning, and the division is not arbitrary:

| Act | Event | Where it is noticed |
|---|---|---|
| a session is created | `session-established` | `authn.startSession()` |
| a session is presented and honoured | `session-presented` | `oauth-oidc/oauth2.js`'s authorization endpoint, through `authn.notePresented()` |
| a session ends | `session-revoked` | `authn.dropSession()`, which every sign-out door reaches |

The other five — token claims change, credential change, assurance level
change, device compliance change, risk level change — have **no act here that
could cause them**. No device reports compliance to this service and no risk
engine talks to it, so an automatic emission of one would be this service
inventing a fact. They are emitted by hand from `/admin/caep` or
`POST /admin-api/caep/emit`, and a row in `caep.autoEmitTypes` naming one is
dropped rather than honoured: honouring it would leave a setting that reads as
configured and does nothing.

**THE FIRST PRESENTATION OF A NEW SESSION IS NOT REPORTED**, and without that
rule the feature would be noise. Every sign-in here ends with the browser
coming back to the authorization endpoint, which *is* a presentation — so a
`session-established` and a `session-presented` would arrive milliseconds
apart, every time, and the event that is supposed to mean *single sign-on
happened* would mean nothing. `startSession()` sets a flag and
`notePresented()` spends it, which is exact rather than a time window.

---

## THE REGISTER OUTLIVES THE SESSION, ON PURPOSE

`authn.js` forgets a session the moment it is signed out. `caep.js` does not: a
row whose state is `revoked` is the **only remaining evidence** that the
session existed and was revoked, and *"did anything go out when I signed that
person out?"* is the entire question `/admin/caep-sessions` answers.
`caep.maxSessionsTracked` caps it and the oldest goes first.

The two can also disagree the other way — a session this service still holds
whose row says `revoked` means somebody emitted a revocation by hand — and the
page says so rather than reconciling, because which of the two is wrong is
exactly the question.

---

## THE COUNTS ARE NOT THE LIST

Each row carries `counts` (per event type, never forgotten) and `events` (a
ring of the last twenty-five). They answer different questions — *how many
session-revoked have gone out about this person* and *what were the last few
jtis* — and a page that answered the first out of the second would say
twenty-five where there were thirty. `tests/caep_register.js` sends thirty and
asserts both.

**AND ONE THING THAT IS NOT A FILE: THE REFUSAL SENTENCE HAS TO BE SPELLED THE
WAY EVERY OTHER ACTION HANDLER SPELLS IT.** `consoleAction()` answered an
unknown action with `"x" is not an action on this resource. The ones that are:
…` until 2026-09-01, which reads perfectly well and is INVISIBLE to the two
checks that depend on it: `tests/vendored/admin_api.js` requires
`/unknown action/i` before it parses the list — that is the console/API parity
check, so `/ssf`'s four actions were being compared against nothing — and
`tests/vendored/sts_admin_api_operations.js` matches `Unknown action "x".
<count phrase>: <list>.` across every documented resource, which is what caught
it. It is `Unknown action "x". The four are: …` now, with the count coming from
`CONSOLE_ACTIONS.length` through `helpers.numberWord()` rather than from a word
typed beside it. **This sentence is not prose — it is READ**, and that is the
whole reason it is worth a paragraph in this file.

---

## The CAEP page's session picker is a SEARCH, not a `<select>` (2026-09-03)

`/admin/caep`'s *Emit one by hand* form chose its session from a dropdown built
out of the whole register. That register **grows by one row per sign-in for the
life of the process and never shrinks** — `caep.js` keeps a row after the
session is signed out, deliberately, because the row is the evidence it existed
and was revoked — so a console left running for an afternoon of testing had a
dropdown of several hundred options, each labelled with a 24-character random
identifier and sorted by nothing a reader knows.

It is `chooserPane()` now, the same control `/admin/delegation` uses for its
application and user searches, with the same twenty-a-page and the same
clamping of a stale offset. Three things about it are decisions rather than
mechanics:

* **The search is over the PERSON and the results are SESSIONS.** Nobody knows
  a session identifier by heart — it is random, and it is the thing they came
  here to find — but everybody knows who they signed in as. So the searchable
  names are the username and the subject (and the session id, for a reader who
  has one from a log), and the result line carries the session with the
  **protocol that minted it** and its state beside it.
* **Only LIVE sessions are offered.** A revoked row stays in the register and
  stays on `/admin/caep-sessions`, where it is evidence; it is not offered here
  because the model's one hard refusal is a `session-presented` about a session
  already revoked, and a control that lists rows the very next click would be
  refused for is one that invites the mistake.
* **The form does not draw at all until a session is picked.** A CAEP event
  names a session; there is nothing for the form to be *about* until one is
  chosen, and a `?session=` naming a row that is gone says so rather than
  posting an identifier the register will not recognise.

`sessq`, `sessfrom` and `session` are in `LIST_PARAMS` for `/admin/caep`, so a
reader who searched a username, paged to the second twenty and picked a session
keeps all three across the reload that pressing **Emit** causes.

---

## `initiating_entity` IS NOT ALWAYS `admin` OR `user` (2026-09-04)

`observe()` chose between those two on a `revoked` act — `admin` when an
administrator did it, `user` otherwise. A SESSION THAT EXPIRED is neither: a
lifetime this service configured ran out, nobody did anything, and the event
would have gone out claiming the person signed themselves out. That is not
vague, it is false, and a receiver acting on `reason_user` would have shown them
a sentence about a sign-out that never happened.

The notice's own `initiatingEntity` now wins where it has one, validated against
CAEP section 2's four words, and `authn.js`'s expiry gives `policy` — the word
for a policy evaluation, where `system` is a maintenance activity and the other
two name a person. `reasonForUser()` takes the notice too, so an expiry says
"Your session expired" rather than "You have been signed out".

**IT IS ALSO THE FIRST TIME `session-revoked` FIRES WITH NO REQUEST BEHIND IT.**
The expiry sweep in `authn.js` runs on a timer, inside each realm, so
`issuerFor(null)` is what builds the subject — which is why that function must
go on answering without one. `authn/CLAUDE.md` argues the sweep.

**THE `admin` BRANCH WAS UNREACHABLE UNTIL THE SAME DAY, AND THAT IS THE OTHER
HALF OF THIS.** `dropSession()` decides between `admin` and `user` by testing
the `via` it is handed for `admin` or `console`, and every door went through
`logout.js`'s session family, which passed one hard-coded string. So a support
desk ending somebody's session from `/admin/logout`, the Revoke button on
`/admin/sessions` and the management API all emitted an event saying **the
person had signed themselves out** — the one distinction this member exists to
draw, got wrong in the direction that matters, with no symptom anywhere: the
event is conforming and the value is a legal one. `logout/logout.js` carries the
caller's own words on the context now, and the same phrase reaches
`reason_admin`, so the two cannot disagree about who ended a session.
`tests/caep_initiating_entity.js` is the guard, mutation-tested against five
mutants.

## PER-RECEIVER STATISTICS, AND THE COUNTER THEY NEEDED (2026-09-04)

`caepApplications()` answers what this transmitter has said to each RECEIVER
across every session — the third table on `/admin/caep-sessions`, the
`applications` member of the CAEP report, and therefore the same document
`/admin/caep` and both management API reads answer with.

**IT NEEDED A NEW COUNTER AND COULD NOT BORROW ONE.** The stream's `counters`
are about the PIPE — queued, delivered, failed, acknowledged — and none of them
knows an event TYPE. The register knows types and counts them PER SESSION,
keeping only the last twenty-five events per row, so summing its rings would
have been right until the first busy session and wrong afterwards. So
`ssf_streams.js` gained `eventCounts` on the record, incremented by
`countEvent()` from `transmit()` beside `caep.noteTransmitted()` — at the same
moment and for that function's reason: the count is of what was SAID, so it
moves when the SET is built and queued, and a poll stream nobody has polled yet
still shows what is waiting for it.

**THE JOIN IS `createdBy` AND NOT `aud`, AND THE OBVIOUS ONE IS WRONG.**
`applications.js`'s `ssf` row says a receiver's identifier is "the `aud` those
SETs carry", and that prose is loose: `normaliseAudience()` requires `aud` and
deliberately never defaults it to the authenticated caller, while
`applications.seen()` files the entry under the PRINCIPAL. They coincide for a
receiver that sends its own name and diverge for one that does not — which is
legitimate — so the table carries both and says "the same" where they agree.

**TWO ROWS ARE THE POINT OF THE TABLE RATHER THAN EDGE CASES.** An application
with NO STREAM is the commonest state a receiver under test is in, and a list
that showed only receivers with streams would answer "where is my application"
with silence. And a row for streams belonging to no application at all is what
`ssf.authRequired` off produces — no principal, nothing recorded, and the events
are real; dropping them would make this table's totals disagree with the two
above it.
