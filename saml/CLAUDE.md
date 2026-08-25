# saml/

The two assertion builders — and, since 2026-08-24, **a browser-facing identity
provider for each of them**.

| File | What it is |
|---|---|
| `saml2.js` | A SAML 2.0 assertion: build, sign, encrypt, and the attribute statement. Registers nothing. |
| `saml11.js` | The same for SAML 1.1, whose profile splits a claim URI into a namespace and a name. Registers nothing. |
| `saml2_sso.js` | **The SAML 2.0 Web Browser SSO profile**: the Single Sign-On service over both request bindings, the Response over all three, the SOAP Artifact Resolution Service, Single Logout, the per-service-provider metadata, and a mock service provider. **This one registers routes.** |
| `saml11_sso.js` | **The SAML 1.1 browser profiles**: the inter-site transfer service, Browser/POST and Browser/Artifact, the SOAP SAML responder behind the second (which is also an attribute authority), the per-relying-party metadata, and a mock relying party. **This one registers routes.** |

## THE TWO PROFILES ARE SEPARATE IMPLEMENTATIONS, NOT ONE WITH A VERSION FLAG

This is the first thing to know before reading either file, because everything
else follows from it and because "surely most of that is shared" is the change
somebody will propose. It was considered and it is wrong: **SAML 1.1 has no
request message at all.** There is no `<AuthnRequest>` — the browser profiles are
identity-provider-initiated, and a flow begins when a browser arrives carrying a
`TARGET`.

Six things follow, and each is a branch that would have had to exist in every
function of a merged implementation:

| | SAML 2.0 (`saml2_sso.js`) | SAML 1.1 (`saml11_sso.js`) |
|---|---|---|
| the relying party names itself | `<saml:Issuer>` on the request | it cannot — `providerId`, the path segment, or GUESSED from the TARGET's origin |
| a failure goes | to the service provider, as a Response with a status | to a PAGE — there is nothing to answer |
| Single Logout | both directions | **does not exist in the protocol** |
| `ForceAuthn`, `IsPassive`, `RequestedAuthnContext` | all three implemented | **no spelling in the protocol** |
| the artifact | 44 bytes, type 0x0004, stands for a MESSAGE | 42 bytes, type 0x0001, stands for an ASSERTION |
| the SOAP endpoint answers | ArtifactResolve | four request types, including an attribute authority |

And the spellings differ almost everywhere the two overlap: `AssertionID` not
`ID`, an `Issuer` ATTRIBUTE not an element, a status code that is a **QName**
(`samlp:Success`) not a URI, `AudienceRestrictionCondition` not
`AudienceRestriction`, and a signature that goes LAST in an assertion and FIRST
in a response.

What IS shared is shared deliberately and is exactly three things: the
application registry, the session, and `slugOf()` — which `saml11_sso.js`
requires FROM `saml2_sso.js` rather than reimplementing, because the slug is a
handle for an application and two spellings of it would make
`/saml2/metadata/app-1a2b3c` and `/saml11/metadata/app-9f8e7d` name one entry in
one directory.

## THE SENTENCE THIS FILE USED TO OPEN WITH IS GONE, AND THAT IS THE HEADLINE

It said **THERE IS NO SAML 2.0 WEB SSO PROFILE** — no SingleSignOnService, no
AuthnRequest, no Response — and that it was deliberate rather than an omission.
That was true for years and it is not true now. The same claim was asserted in
seven other places and every one of them was **qualified rather than deleted**,
because the reason each existed is still worth a reader's attention:

| Where | What it says now |
|---|---|
| `README.md` | the profile, its three bindings, and what is still absent |
| the root `CLAUDE.md` | the non-goals table row is gone; the require-order table has 10a |
| `../ws-federation/wsfed.js` | its federation metadata still publishes no `IDPSSODescriptor`, which is now a fact about THAT document — the IDPSSODescriptor is at `/saml2/metadata` |
| `../sts_metadata.js` | the `saml2` coverage note, and the protocol card that said NO ROUTE OF ITS OWN |
| `docs/` | the user-facing half |

If any of them still reads as though this service has no browser SAML profile,
that one is the bug. See `reversing-a-documented-non-goal` — the shape of this
change was mostly a prose sweep.

---

## What is still absent, and each is stated rather than left to be discovered

* **No assertion is encrypted.** `saml2.js` has `encryptAssertion()` and WS-Trust
  uses it (`/sts?encrypt=1`, where a WS-Security signature carries the recipient
  certificate). This profile does not: there is no recipient certificate in an
  AuthnRequest to encrypt to unless SP metadata is consumed, and it is not.
* **No AuthnRequest signature is verified.** It is RECORDED — whether the request
  was signed, and the certificate off its `ds:KeyInfo` — and never checked. That
  is the same posture as the rest of this service (no password, no access token,
  no workload attestation), it is why the metadata advertises
  `WantAuthnRequestsSigned="false"`, and it is why `samlSigningCertificate` is on
  the application entry: so the check has somewhere to READ FROM the day it is
  wanted.
* **No SP metadata is consumed.** This service PUBLISHES metadata and does not
  ingest it. Two consequences follow and both are visible: an assertion consumer
  service URL comes off the request rather than out of a registration, and a
  service provider's logout return address has to be DECLARED or it is guessed.
* **No identity-provider-initiated SSO**, no ECP profile and its PAOS binding, no
  Name Identifier Management, and no Assertion Query and Request profile. PAOS is
  refused BY NAME rather than quietly answered over HTTP POST — a service
  provider that asked for PAOS and got a form post would conclude that PAOS
  worked.

**And what `saml11_sso.js` does not do**, which is a shorter list because most
of what is missing there is missing from the PROTOCOL rather than from this
implementation:

* **No AuthorizationDecisionQuery**, the fifth SAML 1.1 request type. Refused by
  name at the responder: this service makes no authorization decisions, and
  answering one would be inventing a policy nothing here has.
* **No assertion is encrypted**, the same as 2.0 and for a stronger reason:
  there is no request to carry a recipient certificate in even in principle.
* **Nothing authenticates a caller at the responder**, which matters more than
  the equivalent sentence about `/saml2/ars`. An artifact is protected by its
  twenty random bytes and the one-shot rule, but **an AttributeQuery is protected
  by nothing at all** — anybody who can reach the port can ask for an assertion
  about anybody, by name. A real attribute authority uses mutual TLS and an
  attribute release policy. Every query is logged saying so.
* **No Single Logout, and it is not a gap.** SAML 1.1 has none.
  `session.saml11RelyingParties` is still recorded, and nothing reads it — it is
  there so `/admin/saml11` can show which relying parties hold an assertion
  nothing here can recall.

---

## Six decisions in `saml2_sso.js`, and the two most likely to be undone

The file's own header argues all six at length. Two of them are the ones somebody
will try to "fix":

**1. THERE IS NO SIGN-IN SCREEN IN THIS DIRECTORY, and that is the deliberate
difference from `../ws-federation/wsfed.js`.** That module has a screen of its
own because section 13.2.1 lets a WS-Federation sign-in request arrive as a
cross-site form POST, which `SameSite=Lax` keeps the session cookie off — so it
cannot read the session it would need in order to skip the screen. The HTTP POST
binding has exactly the same problem and this profile answers it differently:
**hold the request and 303 to a GET on the same endpoint**, which is a top-level
GET navigation and therefore DOES carry a Lax cookie. Three things follow that
WS-Federation does not get — single sign-on with OAuth and WS-Federation in one
session, a WebAuthn ceremony available at the screen, and one fewer place asking
for a username. Do not give this profile a screen of its own to "make it
symmetrical with wsfed": the asymmetry is the improvement.

**2. THE METADATA IS PER SERVICE PROVIDER AND IS MINTED FOR ANYTHING ASKED FOR.**
`/saml2/metadata/{sp}` names an identity provider of its own —
`urn:sts-mock:idp:{slug}` — with endpoints under that same segment, which is what
Okta and Ping do. It **404s for nothing**: an entityID nobody registered is
registered by the ask. `saml2.perApplicationEntityId` turns the separate entityID
off for a service provider library that keys its trust store off the entityID;
the ENDPOINTS stay per-application either way, because that is what makes the
documents worth having separately.

The slug is the entityID where it is safe in a URL path segment and
`app-<12 hex of its sha256>` where it is not — the same device
`../common/applications.js`'s `shortName()` uses on an RDN, with the same
consequence: **a slug is not reversible**, so resolving one means asking the
registry which application has it. That is a scan of a mock's in-memory
directory, and it is why `/admin/saml2` exists — nobody derives that digest by
hand.

The other four: any entityID is accepted and nothing is verified; the assertion
is built by `saml2.js` and not by that file; the Response is signed as well as
the assertion and both are settings; and an artifact is one-shot.

---

## `buildSamlAssertion()` GREW SEVEN OPTIONS AND IS STILL ONE BUILDER

The Web Browser SSO profile needs things WS-Trust and WS-Federation genuinely do
not: a NameID format and value, a bearer `SubjectConfirmationData` (section
4.1.4.2 makes it a MUST — a service provider that checks it, and most do, refuses
an assertion without one, and the refusal reads as a signature problem), a
session index, an authentication instant, an issuer, and the ability to return
unsigned.

They are **options rather than a second builder**, and the reason is the one this
directory always gave: one assertion writer means one place where the element
order, the namespace and the signature location are decided, and those are
exactly what a service provider's parser is strict about. It also means **the
custom SAML 2.0 attributes configured on `/admin/saml-attributes` reach an
assertion issued by this profile with no wiring at all** — the same
`stats.samlAttributes('saml2', …)` line that puts them in a WS-Trust or
WS-Federation assertion puts them in this one. A second builder would have
silently lost that, and nothing would have said so.

**`issuer` is the option most easily thought unnecessary.** It defaults to
`saml.issuer` and the two older callers want that. The Web SSO profile MUST
override it, because it publishes an entityID per service provider and a service
provider checks the assertion's `Issuer` against the entityID in the metadata it
was configured from. An assertion issued by a name that is not in that document
is refused, and the refusal reads as a trust-store problem.

---

## `buildSaml11Assertion()` GREW SEVEN OPTIONS TOO, AND ONE OF THEM IS THE PROFILE

The same growth `buildSamlAssertion()` took, for the same stated reason — one
assertion writer means one place where the element order, the attribute spelling
and the signature location are decided — and with the same payoff: **the custom
SAML 1.1 attributes configured on `/admin/saml-attributes` reach a browser-profile
assertion with no wiring at all.**

The seven: `issuer`, `nameIdFormat`, `nameIdValue`, `nameQualifier`,
`confirmationMethod`, `subjectLocality`, `doNotCache` and `sign`. Every default
reproduces what WS-Trust and WS-Federation were already getting.

**`confirmationMethod` is the one that is not a preference.**
saml-profile-1.1 section 4.1.1.4 requires `urn:oasis:names:tc:SAML:1.0:cm:artifact`
for Browser/Artifact and 4.2.1.4 requires `...:cm:bearer` for Browser/POST. The
confirmation method is the assertion's own statement of HOW it reached the
relying party, so an artifact-profile assertion confirmed as `bearer` claims to
have travelled through the browser when it did not. A relying party that checks
refuses it; one that does not check works perfectly with either — which is why
this needed a decision rather than a line of code, and why the mock relying party
checks it.

---

## THE `Id="_0"` BUG THAT WAS THERE ALL ALONG, AND WHAT SURFACED IT

Worth reading before touching either signer, because the file said the opposite
in a comment for a long time and the comment was persuasive.

`signSaml11Assertion()` used to say that SIGNING does not care that SAML 1.1's id
attribute has an unusual name and that only verification does. That is true of
the DIGEST and false of the DOCUMENT. xml-crypto's `ensureHasId()` looks for the
first of `Id`, `ID`, `id` on the node being signed; finding none — and
`AssertionID` is none of them — it **invents `Id="_0"` and rewrites the reference
URI to match**. So every SAML 1.1 assertion this service ever issued carried an
attribute the schema does not have, and a signature reference naming it instead
of the AssertionID.

It verified anyway, which is why it survived: a verifier resolving `#_0` finds
the injected attribute. **The browser profiles broke it**, because a
Browser/POST response is TWO signed documents in one — the Response and the
assertion inside it — and both got `Id="_0"`. xml-crypto then refuses to verify
either, reporting *"multiple elements with the same value for the ID / Id / Id
attributes"*: its signature-wrapping guard, firing on a document this service
built itself.

The fix is one option in each signer — `idAttribute: 'AssertionID'` in
`saml11.js`, `'ResponseID'` in `saml11_sso.js`'s `signDocument()`. Then the real
attribute is found, nothing is injected, and the reference names the id a SAML
1.1 relying party expects. **WS-Federation's assertions changed as a result and
are more correct for it**; `/wsfed/rp` verifies them check by check and was used
to prove it.

**It is only safe because neither name is already on that default list.** The
opposite case is recorded in `saml2_sso.js`: naming `ID` for SAML 2.0 unshifts a
DUPLICATE onto the list and trips the very same guard on a document that has
nothing wrong with it. Do not "make the two consistent" by naming an idAttribute
in the 2.0 signer.

---

## FOUR SETTINGS GROUPS, AND `saml.issuer` IS NOT ONE OF THE PROFILES'

`saml.issuer` (group *SAML*) governs who SIGNED an assertion and is shared by
WS-Trust and WS-Federation. The nine `saml2.*` rows (group *SAML 2.0*) and the
nine `saml11.*` rows (group *SAML 1.1*) govern how this service behaves as an
identity provider in each browser profile. Folding any of them together would
make a change to one look like a change to the assertions WS-Trust hands out,
which it is not. `wsfed.entityId` is separate from all of them for the same
reason and always was.

**The two profile groups are separate from EACH OTHER for a reason of their
own**, and it is not symmetry: a relying party that trusts this service for SAML
1.1 and not for SAML 2.0 is the ordinary case rather than an exotic one, and one
`entityId` shared between them would make that unexpressible. It also has a
consequence worth knowing: `saml11.providerId` is what every type 0x0001
artifact's SourceID is a SHA-1 of, so changing it changes every artifact this
service mints.

---

## A SAML ATTRIBUTE IS MULTI-VALUED and both builders say so

`values` is an array of `<AttributeValue>` children under one `<Attribute>`;
`value` is untouched and is what every existing caller passes. One element per
value with the same name is not a multi-valued attribute — it is a relying party
reading the first and silently seeing one where there are four. That is also why
the precedence rules in `../common/claim_attributes.js` and
`../common/group_claims.js` are written as a FILTER in these two builders rather
than as an assignment order: an assertion is a list of elements, so a duplicate
name is not an overwrite.

**WHAT EACH BUILDER PUTS IN IS CONFIGURED ON `/admin/saml-attributes`** — *Custom
SAML attributes*, under the console's SAML group; it was four sections of
`/admin/claims` before 2026-08-24. Neither file changed when it moved. Two things
about the context are worth knowing before writing prose about it anywhere: **it
is `{ subject, audience }`**, so a value carrying `${username}` reaches the
assertion as the characters it was written as — `${subject}` and `${audience}`
are the two that expand, and an unknown placeholder names itself (see
`expandValue()`) — and the RESERVED CLAIM NAMES enforced for a JWT set are **not**
enforced for these two, because `exp` collides with nothing in an assertion.

---

## The require order

`saml2.js` and `saml11.js` require only `../common/helpers`, `../common/config`
and `../common/admin_stats`, so they cannot join a cycle and their position is
not a position at all.

**`saml2_sso.js` is position 10a in `server.js` and has one real constraint**: it
must come after `../authn/authn.js`, and it is a STRONGER dependency than
WS-Federation's rather than a weaker one — that module signs users into the
session `authn.js` owns, and this one has no sign-in screen at all and reaches
that service's through `beginAuthentication()`. It has no constraint against
`wsfed.js` in either direction; the two share the session and know nothing about
each other. It sits between them and OID4VC so that the two browser SSO profiles
read together in the route order and on `/admin/sts-metadata`.

`../admin-ui/admin.js` requires it in the ORDINARY direction — a plain require,
not a sixth inverted slot — and rule 3e's test is why: `server.js` requires this
module at 10a and that one at 18, so a require from there closes no cycle and
moves no route.

**`saml11_sso.js` is position 10b and has TWO constraints**, the second of which
is the only require between the two profiles. It must come after
`../authn/authn.js`, for exactly the reason 10a must — no sign-in screen of its
own, and `beginAuthentication()` is how it reaches one. And **it must come after
`saml2_sso.js`**, because it takes `slugOf()` from it: one application must have
one handle across both profiles, or the console shows one directory entry as two.
That require is in the ordinary direction, so it closes no cycle and moves no
route. Nothing else passes between the two modules.

**It needs no POST-to-GET dance, and that is worth knowing before somebody adds
one for symmetry.** Decision 2 of the 2.0 module is one of the most load-bearing
paragraphs in this directory: the HTTP POST binding delivers an AuthnRequest as a
CROSS-SITE form POST, which `SameSite=Lax` keeps the session cookie off, so that
module holds the request and 303s to a GET. A SAML 1.1 flow arrives as a
top-level GET navigation, which Lax does carry — so the session is visible on the
first request and there is nothing to stash. The POST route exists only because
somebody's relying party will post a form at it anyway.

---

## `/saml2/autopost.js` IS THE FIFTH SCRIPTED PAGE

`../common/app.js` sets `script-src 'none'` on every response. The HTTP POST
binding (bindings section 3.5) **is** a self-submitting form — that is what keeps
a response of several kilobytes of signed XML out of a URL, a log and a Referer
header — so there is no version of this binding without a script. The exception
is the same shape as the other four and no wider: `script-src 'self'` naming ONE
resource, never `'unsafe-inline'`, and the page carries a **real submit button**
because with scripting off the button is the whole mechanism. `form-action` stays
out of the policy, here as everywhere: the form posts to the assertion consumer
service, which is by definition another origin.

The root `CLAUDE.md` asks for that argument to be made again rather than by
analogy for each new scripted page. It is made in `saml2_sso.js`, above
`AUTOPOST_SCRIPT`.

## `/saml11/autopost.js` IS THE SIXTH, AND THE ARGUMENT IS MADE A SIXTH TIME

This is the case where the rule earns its keep, because the fifth scripted page
is the one next door and "the same as that" is the most tempting and least useful
thing that could be said. It is made again in `saml11_sso.js` and it stands on
its own: the **Browser/POST profile IS a self-submitting form in its own older
specification** — saml-bindings-1.1 section 4.1.2 describes the identity provider
returning a document containing a form whose action is the assertion consumer and
which submits itself. That is a separate specification that arrived at the same
shape independently, and it would still be here if SAML 2.0 had never been
written. Same exception, same width, same real submit button.

---

## There is no test for this in either repository — but there is now a driver

Hand-verified end to end on 2026-08-24 against a throwaway instance: 90 checks
over all three bindings, the SOAP back channel, the one-shot artifact rule, the
per-application metadata, the registry entry, the custom-attribute path, the
NameID formats, `ForceAuthn`, `IsPassive`/`NoPassive`, the PAOS refusal, Single
Logout and the mock service provider's own verification. The parent project's
`tests/saml_sso.js` and `tests/saml_logout.js` now take `SAML_IDP=sts` and drive
this profile with the same assertions they drive Keycloak with, which is the
arrangement `tests/wsfed_sso.js` already had — and the one that catches a mock
being quietly more permissive than the real thing.

What a test of this repository's own would still add is the negatives that are
awkward from a browser: an artifact resolved twice, an artifact minted for one
service provider and resolved by another, a RelayState past 80 bytes, a Response
over the Redirect binding long enough to be truncated, and the `saml2.*` settings
turned off one at a time — especially `signAssertion`, since an unsigned
assertion being ACCEPTED by a service provider is the finding that matters and no
happy path shows it.
