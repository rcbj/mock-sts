# federation/

Federation relationships: this service as either end of one, in five protocols.

| File | What it is |
|---|---|
| `federation.js` | **The register.** The schema, the two conversions, the CRUD, the counters, the release filter, and the broker resolver (`identityProviderFor()` / `authenticationFor()` / `usableServiceProvider()`). A library (rule 3): it registers nothing. Directory-backed — `ou=federations` IS the store. |
| `federation_map.js` | What a foreign identity provider SAID, turned into directory attributes. The default mapping table and the username rule. A library. **Not to be confused with `../admin-ui/federation_diagram.js`**, which draws the picture — the near-collision is why that file is not called `federation_map.js` too. |
| `federation_graph.js` | **This realm's register as a GRAPH**, for `/admin/federation/map`. Three bands, and the bands are a claim about direction. A library: it registers nothing, and nothing here requires it back. |
| `federation_http.js` | **The only outbound request in this repository.** A library, and the narrowest one here. |
| `federation_sp.js` | The four endpoints. The service-provider half — the one place this service CONSUMES what somebody else issued. |

---

## THE ONE FEATURE HERE THAT REFUSES BY DEFAULT, AND WHY THAT IS NOT A GAP

Read the rest of this repository first and every refusal in `federation_sp.js`
looks like something to relax. `README.md` and every directory `CLAUDE.md` say
the same thing: this service checks no password, validates no access token and
attests no workload. `/oauth2/token` mints a token for any username. `/saml2/sso`
answers any entityID. Every LDAP bind succeeds. Three surfaces are already the
exception — SCIM, the SPIRE Server API, the admin console — and each has its
argument written down.

**This is the fourth, and its argument is different from all three of theirs.**

Those three REFUSE a caller in order to make a client exercise a refusal. They
are turnstiles: anybody can get a token with either SCIM scope, any password but
one passes Basic, anybody can ask the local socket to mint an SVID. Each could
be made permissive tomorrow and the only thing lost would be a client's error
path.

This one refuses because **there is no permissive answer available.**

"Accept any SAML Response" does not mean "be generous". It means: let anybody
who can reach this port POST a document naming themselves as anybody, and get a
browser sign-on session for it. And the session that comes out is **the same
session** `/oauth2/authorize`, `/wsfed`, `/saml2/sso`, `/saml11/sso` and
`/admin` all read. The permissive version of this feature is not a mock of
federation; it is an authentication bypass for every protocol in the process,
reachable with `curl`.

So the shape of the exception is: **a relationship must be configured, and what
it configures is a KEY.**

* Nothing federated works until somebody creates a relationship.
* A relationship is created DISABLED, and enabling is a second, deliberate act.
* An enabled relationship that is missing a field the protocol needs REFUSES
  rather than half-working, and says which field.
* An assertion is refused unless it verifies against the certificate configured
  on that relationship — not against a certificate the document brought with it.

**Once past that, everything downstream is as permissive as the rest of this
service.** Any username in the assertion is accepted. Any attribute is mapped.
Nothing about the person is checked. A directory entry is created for them.
**The gate is on the SIGNER, not on the subject**, which is exactly the line
`spiffe_auth.js` draws and for the same reason.

---

## 3o. `federation.js` IS A LIBRARY (rule 3) AND ITS DIRECTORY HALF IS INVERTED (rule 6)

It registers no route, so it cannot join a cycle and its position in the require
order is not a position at all. That property is load-bearing rather than
incidental: **five modules reach it, and two of them could not reach anything
heavier.**

| Who requires it | Why | Rule 3e's test |
|---|---|---|
| `common/admin_stats.js` | the release filter, at `jwtClaims()` and `samlAttributes()` | passes both ways: no route moves, no cycle closes |
| `authn/authn.js` | the partner buttons on the sign-in screen | same, and see below |
| `admin-ui/admin.js` | `/admin/federation` | same |
| `ldap/ldap_server.js` | fills `setDirectory()` at its own require time | the ordinary direction, exactly as `applications.js` |
| `federation/federation_graph.js` | the graph `/admin/federation/map` is drawn from | the easiest of the five: it registers no route itself, and there is nothing in it this module wants |

### AND IT REQUIRES ONE THING BACK — `common/applications.js`, since 2026-08-26

This paragraph used to say the module requires only `config.js`, `helpers.js`
and `audit.js`. It requires the applications registry as well now, and the
direction is worth stating because rule 3o is otherwise entirely about who
requires THIS.

It is a plain require in the ordinary direction rather than a slot, and rule
3e's test is not reached in either direction: `applications.js` registers no
route, and it requires only `config.js`, `helpers.js` and `audit.js` — none of
which reaches back here — so nothing about requiring it can close a cycle or
move a route. A slot would have cost a reader an indirection for nothing. It is
the same argument `admin_stats.js` makes above its own require of that file.

**What it is for is ONE question and only one**: *is this application actually
configured to authenticate through this relationship, right now?* — asked at the
moment a per-application use is recorded. See `fedApplicationUse` below, where
the reason it has to be asked at all is the interesting half.

**`authn.js` requires this and NOT `federation_sp.js`, and that direction is the
arrangement rather than an accident.** `federation_sp.js` requires `authn.js` —
it has no sign-in screen of its own and calls `startSession()` directly — so a
require back from `authn.js` to that module would close a cycle. The register in
the middle is what both halves can safely reach, and it is why `PATHS` lives in
`federation.js` rather than where the routes are served (see below).

The DIRECTORY half is inverted for `applications.js`'s reason: `ldap_server.js`
is near the end of the require order because requiring it pulls every `/ldap`
route into the router at that point, and a module the SIGN-IN SCREEN reads
cannot drag those routes to the front.

The division of labour is `applications.js`'s exactly: **this module owns the
SCHEMA and both conversions, and `ldap_server.js` owns the directory
mechanics** — where the container is, how an entry is created, what the cap is.
Neither knows the other's half.

### `PATHS` is in the library and not beside the routes

Three things need `/federation/acs/{id}` and only one of them may require the
module that serves it. `admin-ui/admin.js` must not — `server.js` loads
`federation_sp.js` at position 10c, BEFORE the console, and a require in the
other direction would be the reason a route moved the day somebody reorders the
two. But the console page's whole job is to tell an operator **which URL to
configure at the partner**.

So the strings live in `federation.js`, which both sides may reach. A console
printing `/federation/acs/x` while the router serves `/federation/callback/x` is
the single most expensive mistake this feature could make: the person configures
the wrong URL at the partner, signs in successfully somewhere else, and lands on
a 404 with nothing to point at.

---

## 4b. `federation_sp.js` MUST COME AFTER `authn/authn.js`

The same dependency `saml2_sso.js` and `saml11_sso.js` have, and **stronger than
either**. Those two have no sign-in screen of their own and reach one through
`beginAuthentication()`. This one does not go through that either: a federated
sign-in ends by calling `startSession()` **directly**, because the person has
already authenticated somewhere else and there is no screen to show them.

No constraint against the four browser SSO profiles in either direction, and
that is the whole design rather than a happy accident: **they know nothing about
federation and federation knows nothing about them.** What joins the two halves
is the SESSION, which is `authn.js`'s — so a federated identity satisfies an
OAuth 2.0 authorization request, a WS-Federation `wsignin1.0` or a SAML
`AuthnRequest` without any of those modules being told this one exists.

It is placed after the four profiles so the route order and
`/admin/sts-metadata` read in the order somebody thinks about them: what this
service ISSUES, and then what it CONSUMES.

---

## ONE RELATIONSHIP IS ONE DIRECTION

A partner this service both consumes from and asserts to is **two
relationships**, not one record with two halves. Everything that configures one
differs by direction — the endpoints are theirs or ours, the certificate is
theirs or ours, the attribute mapping runs inbound or the release list runs
outbound — so a single record would need two of every field and every page and
every form would have to say which half it meant. `fedRole` says it once.

`fieldsForRole()` is the single place that decides which fields apply, and the
console's form and the action's validation both call it. A field belonging to
the other direction is refused BY NAME rather than written and ignored, because
a setting that silently does nothing is worse than one that is refused.

---

## THE SERVICE-PROVIDER HALF: SIX DECISIONS

These are in `federation_sp.js`'s header at length. The short forms, and the one
line each that matters:

1. **The person is authenticated through `authn.js`, not here.** This module
   never writes a session cookie. A session store of its own would have been the
   second store this repository refuses everywhere else, and the one
   `/admin/users` could not see.

2. **One path receives all five protocols.** A SAML assertion consumer service,
   a WS-Federation `wreply` and an OAuth 2.0 `redirect_uri` are three names for
   "where the answer comes back". Five paths would mean five URLs to configure at
   the partner and four ways to configure the wrong one.

3. **The request context is server-side and the partner carries only a handle.**
   `RelayState`, `wctx` and `state` all carry one opaque id; the `AuthnRequest`
   ID, the `nonce`, the PKCE verifier and **where the person was going** live in
   a Map here. Putting the return URL in the parameter would be an open redirect
   operated by whoever can forge a RelayState, which is everybody.

   **That Map is PER TRUST REALM since 2026-08-25 and was one Map before**, which
   meant a handle minted while `acme` was ambient could be spent at the DEFAULT
   realm's `/federation/acs/{id}` — a flow begun in one realm finishing in
   another, on the one surface in this service where a missing check is an
   authentication bypass rather than a fidelity bug. A relationship is an entry
   in the realm's own `ou=federations` and is verified against the certificate
   configured THERE, so the store had to follow the register. Nothing legitimate
   crossed: a handle is minted and spent inside one flow, and every URL in that
   flow carries its realm. The cap moved with it — MAX_CONTEXTS in flight per
   realm rather than for the process — deliberately, because a shared cap would
   let one realm's flood evict another realm's in-flight sign-ins, which is the
   denial of service the cap exists to bound arriving through the door it was
   meant to close.

4. **The return is always a path on this service**, checked the way
   `beginAuthentication()` checks its own AND stored server-side. Both, because
   they fail differently: the check catches a caller's bug and the storage
   catches an attacker.

5. **The ID Token is verified with the relationship's keys and nothing else.**
   No `alg: none` — refused BY NAME, because it is an attack with a name and
   somebody seeing it should know which one. No HMAC where an RSA key was
   configured: the algorithm family comes from the KEY, which is
   `client_auth.js`'s rule and the classic JWT forgery. An unverified value may
   SELECT (which `kid`), never ESTABLISH.

6. **A failure is shown, recorded and not redirected.** Every refusal draws a
   page naming the check and writes `fedLastError` on the relationship. The
   person's sign-in has already succeeded at the partner, so the only
   interesting question is what THIS service disliked about the answer — and
   that is unanswerable from a redirect that has thrown the detail away.

### The signature check is the line

`verifyXmlSignature()` passes `publicCert` explicitly, so a signature carrying
its own `<ds:KeyInfo>` with a certificate inside it is verified against **our**
copy and not against the one it brought. That is the difference between a
signature check and a decoration, and it is the single most important line in
this directory.

It also chooses the signature **over the element it was asked about** rather than
the first one in the document. A Response carrying a signed Assertion has two,
and taking whichever came first is how a check ends up verifying the wrong
element — and reporting success for a document whose assertion was swapped.

The `idAttribute` argument WAS `wsfed.js`'s trap, made again: SAML 1.1's is
`AssertionID`, which xml-crypto did not look for; and passing `idAttribute:
'ID'` for SAML 2.0, where it was already a default, made xml-crypto refuse a
perfectly good document with a signature-wrapping error. **Symmetry between the
two call sites is what produced that bug.**

**IT IS GONE SINCE 2026-08-27.** `common/crypto.js` resolves every SAML id
spelling from the document, so `verifyXmlSignature()` here takes the ELEMENT to
check and no id argument at all, and the three call sites that used to thread
one around no longer compute a partner's SAML version in advance.

**WHAT DID NOT MOVE IS THE POLICY, AND THAT IS THE PART TO GUARD.** Two rules
stay in this file because they are facts about a RELATIONSHIP rather than about
XML: no `fedSigningCertificate` means nothing is accepted, and the certificate
passed to the verifier is always the relationship's. The second one is load
bearing in a way that is easy to lose — the shared verifier falls back to the
certificate inside the document's own `<ds:KeyInfo>` when it is given no other,
which is correct for a general-purpose tool and would be the whole hole here,
since anybody can sign an assertion and attach the key that verifies it. **This
door reaches that fallback only if somebody stops passing `certPem`.**

---

## HOW THIS SERVICE AUTHENTICATES FOR A PARTNER — `fedAuthnMechanism`, AND THE N-LAYER CHAIN IT MAKES POSSIBLE

The identity-provider half above says it stores a POINTER and nothing else, and
until 2026-08-26 that was the whole of it. Two attributes have joined
`fedApplication`, and they answer a question no other attribute here could:

> When this partner asks this service to authenticate somebody, **what does it
> actually do?**

Before them the answer was always the same one and nothing could change it:
`authn.js`'s sign-in screen. `appFederationRelationship` on an APPLICATION
entry could redirect a sign-in to a partner — but it answers a DIFFERENT
question ("where do this application's people sign in?"), it lives on an entry
somebody registering a relying party owns, and it cannot say anything about the
other four ways this service can check a person.

| Value | What the person meets |
|---|---|
| `password` | the sign-in screen, as always |
| `password-mfa` | the same screen with the second-factor box **ticked and locked**, so the WebAuthn ceremony runs after the password step: `amr ["pwd","hwk"]`, `acr "mfa"` |
| `webauthn` | the same screen with the **passwordless** box ticked and locked: a security key alone, `amr ["hwk"]`, ONE factor |
| `spnego` | **integrated authentication.** `/authn/spnego` — a Kerberos ticket the browser already holds, no screen and nothing typed. What the session claims is read off the TICKET's flags: `amr ["pwd"]` for `pre-authent`, `["hwk"]` for `hw-authent`, both for both, and **nothing at all** for a ticket claiming neither |
| `federation` | **the broker case.** `fedAuthnRelationship` names a SERVICE-PROVIDER-side relationship in this same realm and the person goes THERE |

**The fifth is the one with a name of its own.** A relationship that answers a
SAML 2.0 partner by consuming somebody else's WS-Federation token makes this
realm an **identity bridge**: it authenticates nobody, checks nothing about the
person, and re-asserts what it was handed under its own signature and in a
protocol the party above it does not implement. Nothing bounds the depth —
the realm at the far end can broker again — and nothing in the chain but the
last hop ever draws a password field.

### `spnego` IS THE ONE THAT IS NEITHER THIS SERVICE'S SCREEN NOR SOMEBODY ELSE'S

Added 2026-08-26 with `kerberos/spnego_authn.js`, and it is worth its own note
because it breaks the shape the other four share. Three of them are a page
here; the fourth is a redirect to a partner. This one is a **credential the
browser already holds** — so a SAML 2.0 partner asking this service to
authenticate somebody can be answered by a Kerberos ticket, and the partner
never learns that Kerberos was involved. That is the same trick the broker case
plays one layer down, with a KDC in the place of a foreign identity provider.

**It is also the only value here that can be switched off service-wide.**
`krb5.spnegoAuthentication` closes that door, and a relationship declaring
`spnego` while it is closed would otherwise send somebody to a 403 in the middle
of a sign-in. `authn.js`'s `declaredMechanismFor()` therefore checks the setting
when the value is READ and reports it on the screen — the same rule
`usableServiceProvider()` follows about a disabled relationship, applied to a
setting instead of an entry. The other four cannot be switched off: the screen
is always there.

**And it is the one mechanism resting on a credential this service genuinely
verifies.** Every other sign-in here takes the name it is given;
`krb5_service.js` decrypts a real ticket under a real long-term key and refuses
a replay. The KDC behind it stays as permissive as Kerberos allows — one
password shared by every user account, an account created for any name on first
sight — so nothing about the mock's posture changes. The VERIFICATION is real
and the account policy is not, and those are two different sentences.

### AN EMPTY MECHANISM IS NOT `password`

It is "this relationship says nothing", which is what every relationship
created before the attribute existed holds. It falls through to the application
entry and then to the screen, so a service upgraded to this build behaves
EXACTLY as it did. Treating empty as `password` would have silently switched
off every `appFederationRelationship` in the field, which is a federated
application quietly authenticating people locally — the failure this directory
is most careful about everywhere else.

### THE TWO SOURCES, AND THE ORDER IS WRITTEN DOWN IN ONE PLACE

There are now two attributes that can redirect a sign-in, and pretending
otherwise would be worse than the cost of saying so. `authn.js`'s
`mechanismFor()` is the ONLY function that reads both, and it reads them in
this order:

1. **the identity-provider-side relationship naming this application**, if one
   is enabled and declares a mechanism. It wins because it is the more specific
   statement: an application entry can be a federation partner AND an ordinary
   OAuth client, registered by two different people, and only one of those
   facts is about the exchange in progress.
2. **`appAuthnMechanism` on the application entry** — the SAME closed
   vocabulary, said by whoever registered the relying party rather than by
   whoever configured the partnership. It is the generalisation of the
   attribute below it and it exists because `spnego` had no way of being asked
   for otherwise: the pair below can say "send my people to a federated
   identity provider" and cannot say "my people hold Kerberos tickets". A value
   of `federation` here means the list below, said out loud, and falls through
   to it.
3. **`appFederationRelationship` on the application entry** — home realm
   discovery by configuration. It holds a LIST since 2026-08-26, so this step
   can produce a partner, or a QUESTION: several usable values draw the chooser
   at `/authn/select-idp` rather than redirecting anywhere.
4. the sign-in screen.

`federation.js` supplies the pieces (`identityProviderFor()`,
`authenticationFor()`) and makes no decision; `authn.js` composes them. That
split is 4b's constraint again — this module must not require the sign-in path
— rather than a preference.

### THREE THINGS THAT COST A RUN IF THEY ARE GOT WRONG

* **`identityProviderFor()` walks the register and skips DISABLED entries**,
  which CHANGES WHAT A DISABLED IDENTITY-PROVIDER-SIDE RELATIONSHIP MEANS. It
  used to mean almost nothing — every protocol endpoint here answers a partner
  whether or not a relationship names it, so the flag governed only the release
  list. It now also governs the mechanism, and skipping is the safe direction:
  falling through to the password screen is what this service did before
  anybody configured any of it.
* **A half-configured broker is a MISSING FIELD, not a guess.** `federation`
  with no `fedAuthnRelationship` is named by `readinessOf()` exactly as a SAML
  relationship with no certificate is. The alternative — quietly asking for a
  password — is a broker that has stopped brokering looking precisely like one
  that is working, which is the single most expensive failure this attribute
  could have.
* **`forceMfa` beats `webauthn`, loudly.** `opts.forceMfa` does not come from
  this register: it comes from the request a protocol module is answering (a
  `RequestedAuthnContext`, a `wauth`), and a caller told two factors are
  required does not get a one-factor answer because a relationship preferred
  one. Passwordless WebAuthn is ONE factor however phishing-resistant it is.
  `beginAuthentication()` resolves that and says so in the log.

### THE ENFORCEMENT IS ON THE RECORD, NOT IN THE MARKUP

The screen renders a hidden `webauthn_only` when the mechanism demands one, and
a hidden input is a suggestion: anybody with the developer tools open deletes
it, and the POST that arrives then looks exactly like an ordinary password
sign-in. So `handleLogin()` reads `record.forcePasswordless` as well. **A
configured mechanism a client can opt out of is not a mechanism.**

---

## `fedApplicationUse`: THE SAME COUNTS, SPLIT BY THE APPLICATION THE SIGN-IN WAS FOR

Added 2026-08-26, for `/admin/federation/map`. One value per application on a
SERVICE-PROVIDER-side relationship, packed as
`application|authentications|users|lastUser|lastSeen`.

**Why it had to exist rather than be derived.** `fedAuthentications` answers
*how much has crossed this partner*, and that was the only question worth asking
while one application sat behind one relationship. `appFederationRelationship`
holds a LIST now and a partner is routinely shared, at which point the same
number is two different questions and the register could answer neither: the
relationship's entry has never known which application a sign-in was for, and
the application's entry has never known how many of its sign-ins went through
which partner.

**Nothing else in the process knew the pair either, which is the part worth
following.** A federated sign-in arrives at `/federation/acs/{id}` as a signed
document about a PERSON — it names the partner, the subject and the attributes,
and there is no field in any of the five protocols for the application at THIS
end. `authn.js` knows the pair at the moment it sends the browser away and never
again. So the application id rides on the request context beside `returnTo`
(`federation_sp.js`'s decision 3, one more field), and `completeSignIn()` spends
it. **Both halves are one function now** — `fromContext()` — because five call
sites build the result `completeSignIn()` is handed and five copies of
`returnTo: (context && context.returnTo) || ''` is five places to remember and
one to forget. A dropped `returnTo` is a sign-in that lands somebody on a page
nobody asked for; a dropped `application` is a count that is quietly short.

### THE APPLICATION IS NOT TRUSTED FROM THE REQUEST, AND THAT IS THE WHOLE DESIGN

`/federation/login/{id}` is — alone in that module — reachable with **no
configuration at all**. So the `application` parameter is a string anybody who
can reach this port chose, and an unchecked write would let them grow an
unbounded list of values of their choosing on **the one entry in this directory
whose contents decide whether an assertion is refused**. That is a smaller
problem than the one at the top of this file and it is the same shape of
problem, which is why it gets the same treatment rather than a shrug.

`recordUse()` therefore writes a value only for a pair this service is
**genuinely configured for**, and configured is read from the LIVE register at
the moment of the write rather than from whatever asked. There are exactly two
ways to be configured for one, and they are `authn.js`'s `mechanismFor()`'s two
sources rather than a third opinion about them:

1. **the application entry names it** — `appFederationRelationship`, the
   ordinary case;
2. **an identity-provider-side relationship brokers to it** — enabled, naming
   this application in `fedApplication`, declaring `fedAuthnMechanism:
   federation`, and pointing `fedAuthnRelationship` here.

**Checking only (1) would have recorded nothing for every brokered sign-in**,
which is the case the identity broker exists for — the application entry says
nothing at all in that arrangement. `applicationConfiguredFor()` answers WHICH
of the two rather than a boolean, because the picture draws them as different
lines.

A pair that is named and not configured is **logged at warn and not counted**.
That is deliberately not silence: it is the shape a mistake takes — an entry
edited after a flow began, a hand-composed login URL — and a count that silently
did not move is the thing nobody can find afterwards.

### THREE SMALLER DECISIONS, EACH OF WHICH IS A TRADE RATHER THAN A MECHANISM

* **`|` IN EITHER FREE-TEXT FIELD BECOMES `~`.** This is a packed counter drawn
  on a picture, not an identifier anything joins on, and the application a row
  is filed under is compared in the same packed spelling throughout — so a pair
  round-trips to itself whatever it is called. Stated rather than discovered,
  which is `appLastUser`'s rule about its own approximation.
* **`users` IS COUNTED AGAINST THE ROW'S OWN `lastUser`, not the
  relationship's.** That is the whole reason the field is repeated per row: two
  applications used alternately by one person would otherwise each see a change
  of user on every arrival and count them as many people. It is still `appLastUser`'s
  approximation — a CHANGE of user rather than a distinct set — and it still
  undercounts somebody alternating between two applications.
* **IT IS SERVICE-PROVIDER SIDE ONLY.** An identity-provider-side relationship
  names exactly one application, so its per-application count IS
  `fedAuthentications` — and a second attribute holding the same number under
  another name is the copy that comes to disagree. See the next section for what
  that means for the picture, where it is NOT a shrug.

### THE COUNTS DO NOT HAVE TO ADD UP, AND THE DIFFERENCE IS A FIGURE WITH A NAME

`fedAuthentications` counts every credential that crossed the relationship;
`fedApplicationUse` counts only the ones that named a configured application. So
the per-application rows sum to LESS, and there are three ordinary reasons:
somebody used the generic partner buttons at the foot of the sign-in screen,
which belong to no application; somebody reached `/federation/login/{id}`
directly; or a sign-in named an application that is not configured for this
relationship and was refused a row.

None of those is a fault, and every one of them makes a column of numbers fail
to add up on a page about counting. `federation_graph.js` therefore reports
`attributed` and `unattributed` beside the total, and `/admin/federation/map`
prints the remainder rather than leaving a reader to spot it. **Clamped at
zero**, because `ldapmodify` is a door onto these attributes like any other and
a negative remainder would be a second wrong number reported as confidently as
the first.

---

## `/admin/federation/map`: THE REGISTER AS A PICTURE, AND THE ARROW IS THE REQUEST

`federation_graph.js` builds the model and `../admin-ui/federation_diagram.js`
draws it; `admin.js` registers the route. The split is `delegation.js` /
`delegation_map.js`'s exactly, and for the same reason: what a box IS belongs to
whoever knows the registers, and it is the one question a layout engine has no
business answering.

**THREE BANDS, AND THE BANDS ARE A CLAIM ABOUT DIRECTION.** Everything on the
LEFT of the hexagon arrives wanting somebody signed in — an application here, or
a foreign service provider. The hexagon is this trust realm. Everything on the
RIGHT is a party this service asks to do the signing in.

**So an identity-provider-side relationship is drawn pointing INTO the hexagon,
which is the one thing about this picture that looks backwards.** This service
ASSERTS to that partner, so the arrow "ought" to leave. It points in because
**the arrow is the REQUEST and not the assertion** — and once it is, the
identity broker draws itself: a foreign service provider asking this realm to
authenticate somebody, and this realm consuming a foreign identity provider's
assertion in order to do it, is ONE straight left-to-right line through the
hexagon. Drawn the other way it is two arrows leaving the same box in the same
direction with nothing joining them, which is a picture of a bridge that does
not show the bridging.

**A PARTNER IS KEYED BY ROLE AND PEER**, which is neither of the two obvious
answers. By RELATIONSHIP would draw two boxes for one partner the moment
somebody registers two relationships to it — the ordinary way to point two
applications at one identity provider under two release policies. By PEER ALONE
is worse and is not obvious until it is drawn: this file is emphatic that a
partner this service both consumes from and asserts to is TWO relationships, and
collapsing those onto one box puts a party in both bands at once, which dagre
resolves by breaking the cycle somewhere arbitrary — so the picture silently
stops being left-to-right and nothing says it has.

**A BROKERED APPLICATION IS DRAWN ONCE.** `applicationsUsing()` reports it as an
application of the ONWARD relationship as well, correctly — its people really
are authenticated there — so the identity-provider side is built FIRST and the
service-provider loop skips the pairs it covered, carrying the counts onto the
arrow that was drawn rather than losing them. Two arrows between one pair of
boxes saying two true things is what a reader reads as one thing said twice.

**THE IDENTITY-PROVIDER SIDE'S OWN COUNTERS ARE NEVER PRINTED AS NUMBERS**, and
that is this file's own non-goal being honoured rather than worked around.
`fedAuthentications` there is not a figure that happens to be low, it is a
figure NOTHING WRITES — so the table shows an em dash with the reason in a
tooltip, and where the relationship BROKERS it shows the pair's counts instead,
marked as belonging to the onward relationship. A bare `0` in that column would
assert that nobody has ever signed in for the partner, in the same column that
means exactly that two rows up.

**IT ADDS NO SCRIPT**, and the argument is made again from scratch in
`../admin-ui/federation_diagram.js` rather than cited from the delegation
picture — the root `CLAUDE.md`'s rule about the seventh candidate is exactly
that "the same as the page next door" is not an argument.

### Tests

`tests/federation_map_bands.js` **in this repository**, which is the exception
this repo's `tests/CLAUDE.md` describes rather than a departure from the rule at
the top of that file. Two halves and two reasons: the DRAWING is a pure function
from a graph to an SVG document, so the cases worth asserting — four
relationship states at once, a broker whose onward partner is disabled, a pair
counted and then un-configured — are ones the running service cannot be made to
produce on demand; and the arithmetic above is a statement about two registers
that a page rounds off, so seeing it over HTTP means having already trusted the
number being checked.

It was mutation-tested against six mutants before it was committed, each caught:
the `asks` arrow reversed, the broker dedupe removed, the layout direction
flipped, a partner shape dropped, `applicationConfiguredFor()` replaced with
"believe the request", and the unattributed remainder stopped being reported.

**What it does NOT cover is the SIGN-IN PATH that fills the attribute** — that
the login endpoint carries the application across the round trip, and that the
five `completeSignIn()` call sites all pass it. That is drivable over HTTP and
belongs in the parent suite by the rule at the top of this file; it was verified
by hand against five real federated sign-ins through a SAML 2.0 partner, and the
counts, the refusal of an unconfigured pair and the resulting remainder are what
this section describes.

---

### WHAT IT DELIBERATELY DOES NOT DO

**It does not touch the counters, and `/admin/federation/map` does not quietly
give it some.** The picture reports the BROKERED PAIR's counts beside an
identity-provider-side relationship — which are `fedApplicationUse` rows on the
ONWARD service-provider-side relationship, recorded where the assertion was
actually consumed, and labelled as belonging to it. Nothing new is written on
this side and this non-goal is unchanged; what changed is that a page stopped
printing a zero as though it meant something.

`fedAuthentications` on an
identity-provider-side relationship has always read zero and still does —
nothing increments it, because what it counts is assertions CONSUMED and this
side issues them. Honouring a mechanism is not an authentication and filing it
as one would make the number mean two things. The evidence that a bridge
brokered is the chain reaching the far realm, which is what
`tests/federation_chain_sso.js` in the parent project asserts, and the mutation
test beside it. Giving this side counters of its own is a separate change with
its own argument.

### Tests

`tests/federation_chain_sso.js` **in the parent project**, beside
`federation_sso.js` and for the same reasons: an OIDC application in
`federation-realm-3`, SAML 2.0 on to `federation-realm-4`, WS-Federation on to
`federation-realm-5`, where the only password field in the whole chain is
drawn. It covers all four mechanisms — the three that draw a screen are
asserted by WHICH BOX the screen locks — plus the half-configured refusal, a
mechanism pointing at a disabled relationship, and a value that is not one of
the four. Its realms are deliberately not `federation_sso.js`'s: that test
asserts its relationship counted EXACTLY ONE sign-in, and sharing a realm
between two jobs in a pool is a flake rather than a failure.

---

## `federation_http.js`: THE ONLY OUTBOUND REQUEST, AND HOW THE OLD POSITION SURVIVES

Nothing else in this repository has ever dialled anything, and that was a
position taken twice and argued in both places:

* `oauthJwksUri` on an application entry is **recorded and never fetched** —
  `applications.js`'s schema row calls following it "a server-side request
  forgery with a specification citation attached";
* WS-Federation's `wreqptr` gets the same refusal in `wsfed.js`, and
  `client_auth.js` says holding that position in one file and not the other
  would be no position at all.

**BOTH OF THOSE STAND, UNCHANGED.** The distinction is not "this feature needs
it", which is the argument every SSRF ever shipped was made with. It is:

> **Those URLs are supplied by the CALLER. These are supplied by the
> ADMINISTRATOR.**

`POST /oauth2/register` is unauthenticated and takes any `jwks_uri` anybody
types; a `wreqptr` rides on a query string from a browser. Following either
turns this service into a request-forwarder for whoever can reach the port, with
the destination chosen by the attacker on the spot. A federation relationship is
created through the gated console or through `/admin-api`, and its `fedTokenUrl`
was written down deliberately by somebody configuring a partner. Anybody who can
set it can already do worse things than make this process issue a GET.

**The mechanism that keeps that honest is the API, not the intention.**
`fetchJson()` will not take a bare URL. It takes the relationship and the NAME
of the attribute holding the URL, looks it up itself, and refuses a name outside
`DIALLABLE` — three names, one line, loudly logged as a caller bug. A caller
that has a URL from somewhere else **cannot use this module**. If that ever
needs to change it is a separate argument in a separate function, never a fourth
name quietly added to that array.

Five more things are enforced there and each is a different failure:
`federation.outbound` turns it all off; **https only** unless
`federation.outboundAllowInsecure` says otherwise, warned per REQUEST and not
merely per setting; **no redirects are followed** (a 302 from a token endpoint
would hand the credential in the `Authorization` header to whatever `Location`
said — the same SSRF arriving through the front door); the body is capped and the
request is timed out, because a browser is waiting on it; and **nothing that
arrives is trusted** — this module returns parsed JSON and a status and makes no
judgement, because a fetcher that also validated is where both halves of a check
end up half-written.

---

## `federation_map.js`: THE OIDC HALF IS DERIVED, NOT WRITTEN

`../oid4vc/vc_claims.js`'s `VC_ATTRIBUTES` already carries, for every LDAP
attribute this service knows how to put on a person, the OpenID Connect claim
name it corresponds to — the credential issuer needed exactly that mapping in
the other direction. Writing a second table here would be writing the same
twenty-five pairs again, and the copy would be the one nobody updated when a row
was added. So the OIDC direction is **inverted from that catalogue at require
time.**

The SAML `urn:oid:` names and the AD FS claim URIs ARE written here, and they
have to be: nothing else in this repository has ever had to READ one. This
service emits attributes under names its own console chose; a partner emits them
under names its own product chose, and the two vocabularies overlap only by
accident.

### Three layers, and layer 3 is the decision most likely to be undone

1. the relationship's own `fedAttributeMap` — a statement about THIS partner, so
   it wins;
2. the default table;
3. **nothing.** An unrecognised name is NOT written to the entry. It is recorded
   as unmapped, listed on the result page, logged at INFO and shown on
   `/admin/federation`.

The tempting alternative is to write it under its own name, which would make the
feature look better on the first run. It is refused because **this directory has
no schema** — an attribute nobody defined is accepted silently everywhere here —
so nothing downstream would ever report that the name was wrong. Listing them as
unmapped is what turns a partner's fifteenth claim into a line somebody can act
on, and mapping it is one form field away.

### The username is the one mapping that cannot be got wrong quietly

Everything else on the entry is decoration; the username decides WHICH ENTRY.
Getting it wrong means either a second entry for somebody who already has one
or — far worse — a foreign partner's `alice` landing on the local `alice`.

That second case is not a bug to be fixed later. It is the whole question of
whether federated identities share a namespace with local ones, and this service
answers it with **`federation.usernamePrefix`**: empty by default, because a
mock exists to be pointed at things and a prefixed name makes every downstream
token and assertion look unfamiliar. Set it the moment the question is being
asked. It is applied AFTER the username is chosen, so changing it cannot change
WHICH incoming value was used.

---

## THE IDENTITY-PROVIDER HALF IS NARROW ON PURPOSE

Every protocol endpoint here already issues to anybody that asks, so an
identity-provider-side relationship changes nothing about whether a partner is
ANSWERED. It adds two things: the partner is marked as a federation partner
rather than a test client, and **`fedRelease` decides which attributes are
released to it.**

`releaseFilterFor(context)` is consulted by `admin_stats.js` at its two existing
funnels — `jwtClaims()` and `samlAttributes()` — **and by nothing else.** What it
can remove is exactly what those two functions ADD: the typed claims, the
directory-attribute claims and the groups claim. It cannot remove `sub`, `iss`,
`exp`, a NameID or anything else a protocol module puts in an artifact itself,
and that is not a limitation to fix later:

* those are the protocol's own, not attributes about a person, and a
  partner-specific `exp` is a lifetime rather than a release rule;
* every one of them is what makes the artifact verifiable at all, so a release
  list that could drop `iss` would be a form producing assertions that fail to
  verify with nothing pointing back at the page — which is exactly the argument
  `setClaimSet()` already makes for refusing the reserved names on the way IN.

**A relationship with NO release list declared filters nothing.** That is the
difference between "release nothing to this partner" and "this partner has no
release policy", and they must not be the same state: the second is what every
partner is on the day it is created, and treating it as the first would mean
registering a partner silently stopped it receiving what it received the day
before. The console says so where the list is empty, and so does the API.

**It applies LAST**, after the three layers that produce claims, because it is a
filter rather than a source. Applied earlier, a typed claim could lose to an
attribute claim purely because the typed one had already been filtered out.

The index is rebuilt on a five-second timer rather than kept up to date, and
both halves of that are deliberate: **rebuilt**, because there are four doors
onto these entries and only two come through this module, so an index this
module maintained would be wrong exactly when somebody had just edited the entry
by hand; **on a timer**, because the alternative is walking the register on every
token issued.

### What it deliberately does NOT store

An identity-provider-side relationship names an application (`fedApplication`)
and stops — plus, since 2026-08-26, the two attributes that say HOW this
service authenticates for that partner; see `fedAuthnMechanism` below, which is
the one thing on this side that is not a pointer and not a filter. That partner's entityID, its assertion consumer service, its redirect
URIs and its signing certificate are on the `ou=applications` entry, where every
protocol module already reads them. **Copying any of them here would be the
two-stores failure this repository is arranged to avoid, and the copy would be
the one an operator edited.**

The service-provider side is the opposite case and holds everything, because
there is nothing on the other side to hold it: `ou=applications` is "what this
service has been ASKED ABOUT", and a foreign identity provider asks this service
for nothing at all.

---

## WHAT A FEDERATED SIGN-IN WRITES, AND THE ONE FUNNEL IT GOES THROUGH

`completeSignIn()` does five things in an order that is not arbitrary: map, then
the identity funnel, then the relationship's counters, then the partner's
application record, then the session — **last**, because it is the thing that has
an effect outside this process and everything above it is a record of why.

**It calls `authn.startSession()` and NOT `stats.recordAuthentication()`.** It
was written the other way round first and produced TWO authentication records
for one federated sign-in: `/admin/users` counted every arrival twice and the
audit log carried a duplicate of each, because `startSession()` has always
recorded the authentication itself. That is what `startSession()`'s **sixth
argument** exists for, and its own header carries the reasoning:

* `methodPhraseFor()` answers "sign-in screen (password)" for an `amr` it does
  not recognise, which is exactly wrong for somebody who never saw that screen;
* the mapped attributes have to ride the funnel to the directory, and there is
  no other way in.

A caller passing nothing behaves exactly as every existing caller did.

### The `federation` field on the observer payload, and why it is not a slot

`admin_stats.js` passes `federation` through to `ldap_server.js` untouched, on
the payload the user observer already carries. That is rule 3e's test applied
rather than skipped:

* a new EVENT would be wrong on its own terms — this IS an authentication, and
  filing it as something else would take a federated sign-in off `/admin/users`,
  which is precisely where somebody looks for one;
* a new SLOT would be an indirection bought for nothing. `certificate` and
  `linkedTo` already established that a family with an extra fact about the
  identity puts it on this payload, and this is the third.

### `applyFederatedAttributes()` OVERWRITES, and that is the opposite of the sweep beside it

`applyVcAttributes()` fills only what is ABSENT. This one ASSIGNS, and the two
have to differ: that one writes an INVENTED persona and this one writes what a
real identity provider actually asserted. Merging would mean
`alice@example.invalid` — invented the first time anybody named alice — beating
the address her employer's identity provider just sent, permanently, with
nothing on any page saying why. Accumulating would mean one `mail` value per
sign-in.

It never touches `uid`: that is what `namePlan()` put in the RDN, and a partner
sending a different one would leave an entry whose DN and whose `uid` name two
different people.

An attribute that was on the entry and is NOT in this assertion is left alone. A
partner that stopped releasing `title` has not said the person has no title.

**`federationAttribute` is the useful one and has no analogue anywhere else
here.** A federated `mail` and an invented `mail` are indistinguishable on the
entry — both are ordinary directory attributes — and telling them apart is
exactly the question a person reading a federated directory entry has.

---

## THE FIVE PROTOCOLS, AND WHERE EACH IS GENUINELY DIFFERENT

**SAML 2.0** is the ordinary case: an `<AuthnRequest>` out, a `<Response>` back
on the POST binding. `ProtocolBinding` asks for HTTP-POST always, because a
Response on the Redirect binding is DEFLATEd into a URL and a signed assertion
of a few kilobytes does not reliably fit in one. The outbound request is
unsigned on the Redirect binding even when `fedSignRequest` is on, and it says
so in the log rather than dropping it silently: that binding signs the QUERY
STRING with a `Signature` parameter rather than carrying an enveloped
`ds:Signature`, which is a different construction this service does not build.

**SAML 1.1 has no request message at all**, so there is nothing for a response
to be `InResponseTo`. The browser goes to an inter-site transfer service
carrying a `TARGET`, the handle rides on that, and `fedAllowUnsolicited` is
forced ON at creation — written onto the entry rather than special-cased at the
endpoint, because a reader of the entry should not have to know that.

**WS-Federation** wraps a SAML 1.1 **or** SAML 2.0 assertion in an RSTR, and
which one decides the id attribute the signature reference resolves through. See
the trap above.

**OpenID Connect** runs the authorization code flow by default;
`fedResponseType: id_token` with `response_mode=form_post` is the shape that
needs **no back channel at all**, which is the only way to federate with an OIDC
partner from a deployment with no egress. PKCE is ALWAYS sent, in both
OAuth-shaped protocols and whatever the partner advertises, and there is no
setting to turn it off — the one thing worse than not sending PKCE is a flag
that stops. The `nonce` check is OpenID Connect Core section 3.1.3.7 step 11,
and it is the check `oauth2_bcp.js` records as `enforced: 'no'` on the ISSUING
side because nothing there can observe a client doing it. Here this service IS
the client, so it does it.

**OAuth 2.0 is a distinct protocol here rather than OIDC with a flag**, because
what identifies the person is a different artifact — and getting that wrong is
the whole of what goes wrong when people use OAuth 2.0 for authentication.
Neither of its two shapes is authentication in the sense OIDC means: an access
token says a client was AUTHORIZED, not that a person signed in just now. It is
supported because real deployments do it, and **it warns on every sign-in**,
because doing it silently would be this repository teaching the mistake.

---

## NO CSP RELAXATION, AND THE SIXTH SCRIPTED PAGE THAT IS NOT

`app.js` sets `script-src 'none'` for the whole service, and six pages relax it
by naming one resource. **This feature adds none.**

The obvious candidate is the outbound HTTP-POST binding, which everywhere else
in this service auto-submits. It is a REAL FORM WITH A REAL BUTTON here, and the
difference from the six is the argument rather than an oversight: those
auto-submit because the person has already decided and a click would be
ceremony. This one is a person **leaving this service for a foreign identity
provider**, which is exactly the moment a deliberate click is worth having.

---

## Things this half deliberately does not do

| It does not | Why |
|---|---|
| Decrypt an `<EncryptedAssertion>` | A partner configured to encrypt produces a Response with no `<Assertion>`, which is refused with that cause NAMED — the failure would otherwise read as "the partner sent nothing". Same gap `/saml2` has in the other direction. |
| Verify the partner's certificate against a CA, or check its validity dates | `fedSigningCertificate` is trusted because an administrator pasted it there. It is a pinned key, not a chain, and pinning is the stronger of the two for this purpose. |
| Consume a federated SIGN-OUT | A `wsignout1.0` or a `<LogoutRequest>` arriving at the ACS is refused with that named. This service can END sessions (`/logout`) and can FAN OUT its own sign-outs; being told by a partner that somebody signed out elsewhere is a third thing and is not built. |
| Refresh anything | The tokens a partner issues are used once, to learn who the person is, and are then discarded. Nothing here holds a refresh token belonging to somebody else's service. |
| Re-verify a person on a later request | The session is this service's from the moment it is created. A partner that revokes somebody five minutes later is not consulted, and nothing here polls. |
| Restrict WHICH people a partner may assert | Any username in a verified assertion is accepted. The gate is on the signer; see the top of this file. |
| Federate the ADMIN CONSOLE's roles | A federated sign-in produces a session like any other, so a federated identity holding `admin-write` in the directory reaches `/admin`. The partner does not decide that — `ldap_server.js` and `admin_rbac.js` do, from group membership, exactly as for a local sign-in. |

---

## Tests

**IT IS IN THE PARENT PROJECT'S SUITE, and it used to be here.**
`tests/federation_sso.js` over there drives a federated sign-in end to end: the
debugger's OAuth2/OIDC workflow stands in for an application registered in the
trust realm `federation-realm-1`, which is an OpenID Provider to it and the SAML
2.0 SERVICE PROVIDER of a relationship with `federation-realm-2`, where a name
is actually typed.

**It was `../federation-e2e/` until 2026-08-26 — three containers, two instances
of this service and a web application written for the purpose — and TRUST REALMS
are what made that unnecessary.** A realm is a whole logical copy of this
service on the same socket under a path prefix, so ONE process is both identity
services now; and the debugger is already a web application that has never heard
of federation, which is exactly the third party the old stack had to build one
to get. That leaves nothing in this repository that needs several copies of it,
so the exception that kept a test here has closed and the rule in the root
`CLAUDE.md`'s *Tests* section — a protocol test goes in the parent suite —
applies to this feature like every other. `tests/` here is unaffected: it
asserts module contracts in process and drives nothing.

**WHAT THE MOVE GAVE UP, said plainly.** The old stack had two DNS names and two
origins, so it could prove the front-channel / back-channel distinction — a URL
a BROWSER follows against a URL this SERVICE dials — which is the hard part of
federating between containers and is the thing `federation_http.js` exists to
get right. Two realms on one origin cannot make that distinction at all. What it
bought is that the test now runs in the ordinary suite, on every stack, in about
four seconds, instead of in a stack somebody has to remember to bring up.

**AND SINCE 2026-08-26 THERE IS A FOURTH JOB OVER THERE, WHICH IS THE ONLY ONE
THAT DRIVES AN APPLICATION WITH MORE THAN ONE PARTNER.**
`tests/federation_choice_sso.js` registers `webapp-sso-1` in
`federation-choice-1` naming BOTH a SAML 2.0 relationship and an OpenID Connect
one to `federation-choice-2`, so `authn.js` draws `/authn/select-idp` instead of
redirecting — and it signs in TWICE, once through each button.

**The second sign-in is the whole point.** Both relationships work, and the
three jobs above already prove that; running either again from a page with two
buttons on it would assert nothing new. What is new is that a choice was
OFFERED and HONOURED, and the only assertion that can tell those apart from a
service that ignored the click is arithmetic on the counters: after the first
sign-in the SAML relationship has counted ONE and the OpenID Connect one ZERO,
and after the second, one each. A mock that drew the page and then federated
through whichever relationship it found first passes every other assertion in
that file. It also asserts the page carries no `username`, `password`,
`kc-login` or `<form>` — the chooser is not the sign-in screen with its form
suppressed — and mutation-tests the feature by REMOVING one value, after which
no page may be drawn at all.

**It covers exactly ONE of the refusals below**, as its predecessor did. What it
proves is that the pieces fit — that a federated identity satisfies a flow the
application started, that the ID Token the application verifies comes from the
SERVICE PROVIDER rather than from the partner and names the partner NOWHERE,
that the directory entry and the counters record what actually happened, and
that a forged, unsigned assertion naming the configured partner is refused 401
on the signature, recorded, and does not count as a sign-in.

**And it covers one thing the old one could not**: both realms are the same
ORIGIN and the session cookie has one name, so a session minted at the identity
provider is PRESENTED to the service provider and must not be honoured there.
That is the per-realm session store being load-bearing rather than tidy.

**The old test found a real defect on its first run**, which is worth keeping
here because the fix is in this directory: a foreign `sub` reached
`startSession()` unnormalised, so `userFor()` applied this service's own subject
prefix a second time and every downstream token carried
`urn:sts-mock:user:urn:sts-mock:user:alice`. The doubling was the symptom; the
bug was that the identity funnel normalises and the session did not, so
`/admin/users` said `alice` while the tokens said something else. It would have
happened with any partner whose subject carried an `@`. See `usernameFor()`,
where the three steps and their order are now written down.

**What it does not cover is everything below**, and that list is still the gap:

**There are none for the refusals, in this repository or the parent, and this is
the surface where that costs most** — because it is the only one here whose bugs are
security bugs rather than fidelity bugs. What a test would have to cover is
almost entirely NEGATIVES, and a happy path proves close to nothing: an
assertion that verifies against the key it was signed with is not evidence that
anything would have been refused.

The list, in the order they would actually go wrong:

* an assertion signed by **nobody**; by a **different key**; by the right key
  but naming a **different issuer**; with the signature over a **different
  element** than the one being trusted; with its own `<ds:KeyInfo>` carrying a
  certificate that is NOT the configured one — that last is the one that must
  fail, and it is the one a naive implementation passes;
* an assertion **outside its validity window** at both ends, and one with no
  `<Conditions>` at all, which must be ACCEPTED;
* a `RelayState`/`wctx`/`state` that this service never minted, one that
  **expired**, and one **replayed** — the second use must fail even where the
  partner's own replay window is still open;
* an `InResponseTo` naming a different request, and the same run with
  `fedAllowUnsolicited` on, which must accept it;
* an ID Token with `alg: none`; one nominating **HS256 against an RSA key**;
  one whose `kid` names a key the set does not have; one with the **wrong
  `aud`**, the **wrong `iss`**, and the **wrong `nonce`**;
* the OAuth 2.0 branch with an opaque token and no `fedUserinfoUrl`, which must
  refuse rather than sign somebody in as nobody;
* every refusal in `federation_http.js`: outbound off, an `http://` URL with
  the setting off, a redirect, an oversized body, a timeout, and an attribute
  name outside `DIALLABLE`;
* a relationship **disabled**, and one **enabled and half-configured** — which
  must refuse and NAME the missing field;
* and the whole run again with `federation.enabled` off, where every route must
  404 with no relationship changed.

Beside those, the things only a test can pin down about the DIRECTORY: that one
person federating twice is ONE entry; that a partner's `mail` OVERWRITES an
invented one and an invented one never overwrites a partner's; that `uid` is
never written from an assertion; that an attribute the partner stopped sending
is LEFT ALONE; that `federationAttribute` names exactly the attributes that came
from the partner; that `fedAutocreateUsers` off gives a session and no entry;
and that `federation.usernamePrefix` changes the NAME and not which incoming
value was chosen.

And the release filter, which is the identity-provider half and needs three
assertions rather than one: **no release list changes nothing**, a list filters
the custom claims, and **the protocol's own claims are untouched in both
cases** — that third one is what catches a "simplification" that filters the
whole payload.

Drive it the way `tests/sts_dpop.js` is driven: write the partner side rather
than importing this one. If both ends of the exchange came from this
implementation, a shared misunderstanding about, say, which element the
signature covers would pass and interoperate with nobody — and on this surface
that misunderstanding is not a fidelity problem, it is the hole.

## HOME REALM DISCOVERY, and it is NOT in this directory

Nothing here decides who gets sent to a partner. A relationship says how to
talk to a foreign identity provider and, until 2026-08-26, the only thing that
said WHO should go there was a person pressing one of the buttons
`authn.js` draws at the foot of its sign-in screen — home realm discovery
performed by the user, once per sign-in.

The answer lives on the APPLICATION now: `appFederationRelationship` on an
entry under `ou=applications`, with `appFederationAutoRedirect` beside it, both
read by `authn.js`'s `federationFor()` and by nothing in this directory. See
`common/CLAUDE.md` and `authn/CLAUDE.md`.

**AND IT IS A LIST, WHICH PUT THE USER'S CHOICE BACK — NARROWED.** An
application may name SEVERAL service-provider-side relationships, in different
protocols, and when more than one is usable `authn.js` draws
`/authn/select-idp`: one button per partner, no password field. That is not a
retreat to the buttons at the foot of the sign-in screen and the difference is
the whole point of the attribute. Those offer EVERY relationship this service
has, which is a question nobody can answer sensibly about an unfamiliar
service; these offer the ones this application was configured with, which is
the question a real deployment actually asks. Configuration decides the SET;
the person decides WITHIN it.

**This directory supplies one function for it and makes no decision.**
`usableServiceProviders()` is `usableServiceProvider()`'s four checks over a
list, keeping the unusable rows with the sentence written about each — because
a list of three whose middle value is disabled draws two buttons, and two
buttons is exactly what a correct list of two draws. Which page gets drawn is
`authn.js`'s, for 4b's reason.

**There is a SECOND answer since 2026-08-26 and it is in this directory after
all** — `fedAuthnMechanism`, above — but it is not home realm discovery and
saying so matters. That attribute does not decide who gets sent to a partner;
it decides what this service does when a partner has ALREADY sent somebody
here. The two never compete for the same sign-in on their own terms, and
`authn.js`'s `mechanismFor()` is the one place their order is written down.

**It is in that direction on purpose.** This module cannot require the
registry: `federation.js` is a library that `authn.js` requires (see 4b), and
the register has to stay reachable from both halves of the sign-in path. Put
the other way round, the question "where do this application's people sign in?"
is a fact about the application, and the entry that answers it is the one an
operator is already looking at when they ask.

**What it changes here is nothing.** A relationship is still created disabled,
still refuses until it is fully configured, and still verifies every assertion
against `fedSigningCertificate` and nothing else. An application naming a
relationship that is disabled, half-configured, identity-provider-side or
absent gets an error banner rather than a silent fallback to the password box —
which is the failure worth being loud about, because a federated application
authenticating people locally looks exactly like a federated application
working. **With a list that matters MORE rather than less**, and the banner
moves with the page: on the chooser when there is still a choice to be made,
and on the sign-in screen when there is not.

**One case shows nobody anything, and it is the log's job.** One usable value
with the auto-redirect on is a redirect, so an entry naming three partners of
which two are disabled works perfectly and draws no page at all. There is no
banner to put those two problems on, and the flow succeeding is exactly why
nobody would go looking — so `beginAuthentication()` writes them at INFO.
