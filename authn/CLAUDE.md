# authn/

The authentication service and the WebAuthn relying party. **This is not part of
any protocol**, which is the point of it having a directory of its own rather
than living under `oauth-oidc/` where the screen used to be rendered.

| File | What it is |
|---|---|
| `authn.js` | The sign-in screen, the session store, and the pending-authentication record. |
| `webauthn.js` | The relying party's half of WebAuthn Level 3. |

**A THIRD ENDPOINT LIVES IN `/authn/*` AND IS NOT IN THIS DIRECTORY.**
`/authn/spnego` — sign in with a Kerberos ticket — is
`kerberos/spnego_authn.js`, and the split is a dependency rather than a filing
mistake. This module is #8 in the require order because `oauth2.js` reads the
session it owns; every Kerberos module is #15 and below so that the KDC's routes
are not dragged to the front of the router. A require from here to there would do
exactly that AND close a cycle, since that module needs `startSession()`.

**It needed no inverted hook either**, which is worth saying because rule 3e's
list is six slots long and a seventh is the obvious move. The only two things
this module needs to know are the PATH — declared here, as `SPNEGO_PATH`, in a
space this module already owns — and whether the door is open, which is
`krb5.spnegoAuthentication` and is read from `config.js` by both files. Rule
3e's test is whether a require would close a cycle or move a route; here nothing
has to point anywhere.

**Three exports exist for it and for nothing else**: `SPNEGO_PATH`,
`pendingFor()` (read-only, and it sweeps an expired record on the way past
exactly as it does for the screen) and `completeAuthentication()`. The last is
one function rather than an exported `pending` and an exported
`returnToCaller()` because the two acts are one act — a record left behind is
one somebody can spend twice, and a redirect written at a second call site is a
second place for RFC 9700 section 4.12's 303-not-307 to be got wrong. It takes
no error parameter, deliberately: a Kerberos sign-in that fails draws a page
with the password screen linked from it, because the person can still sign in,
and telling the calling protocol `access_denied` would end a flow that has not
failed.

**`webauthn.js` is here and not in a directory of its own** even though WebAuthn
is one of the sixteen protocol families, because it is the other half of ONE act
of authentication: it shares the pending record, the choice between its two roles
is made at the password screen, and it owns no session of its own. Splitting them
would put the two halves of one ceremony in two places and leave the pending
record crossing a directory boundary for no gain.

**It OWNS THE SESSION.** `ws-federation/wsfed.js`, `saml/saml2_sso.js` and
`admin-ui/admin.js` take it from here through the exported `startSession` /
`sessionOf` / `endSession`, and `oauth-oidc/oauth2.js` reads the session and
never writes one. Do not give any other module a session store to "decouple" it:
two stores would each look correct alone and never see each other, and the
symptom is a sign-on that silently is not single.

**`startSession()` TOOK A SIXTH ARGUMENT FOR FEDERATION, AND IT REPLACED A
DOUBLE-COUNT RATHER THAN ADDING A FEATURE.** This function has always recorded
the authentication ITSELF — that is what makes a WS-Federation sign-in appear on
`/admin/users` without `wsfed.js` knowing the console exists. `../federation/`
broke that assumption in two places at once: `methodPhraseFor()` answers "sign-in
screen (password)" for an `amr` it does not recognise, which is exactly wrong for
somebody who never saw this screen at all, and the attributes a foreign identity
provider asserted have to ride the identity funnel to the directory with no other
way in. The obvious alternative — the caller calling
`stats.recordAuthentication()` and then this — was written first and produced TWO
authentication records for one sign-in, so `/admin/users` counted every federated
arrival twice and the audit log carried a duplicate of each. **A caller passing
nothing behaves exactly as every existing caller did**, which is the property to
keep if this is ever reworked.

**IT REQUIRES `../federation/federation.js`, AND THAT DIRECTION IS THE
ARRANGEMENT RATHER THAN AN ACCIDENT.** The sign-in screen offers a button per
usable federation partner (`federation.loginButtons`), because a person standing
at this screen is in the middle of SOMETHING — an authorization request, a
`wsignin1.0`, an `AuthnRequest`, the console — and `record.returnTo` is that
something, whole. Handing it to the federated flow is what lets a foreign
identity provider satisfy any protocol this service speaks.

The require goes to the REGISTER and never to `federation_sp.js`: that module
requires THIS file — it has no sign-in screen of its own and calls
`startSession()` directly — so a require back would close a cycle. The register
in the middle is what both halves can safely reach, and it registers no route, so
nothing about requiring it can move one. The call is wrapped: **the sign-in
screen is the last thing in this service that may fail to draw**, so a register
that throws costs the buttons and never the password field underneath them.

**FOUR DOORS END A SESSION AND `dropSession()` IS THE ONLY PLACE ONE STOPS
EXISTING.** `/oauth2/logout`, WS-Federation's `wsignout1.0`, SAML 2.0's
`/saml2/slo` and the protocol-independent `/logout` are four protocols' words
for one act. Two functions sit over that one body and the split is what the
callers need rather than a refactor:

* `endSession(req, res)` reads the cookie and clears it — the browser's own
  sign-out.
* `endSessionById(id, via)` names a session the caller has no cookie for, which
  is every session `/logout` and `/admin/logout` end that is not their own.
  `clearSessionCookie(res)` is exported beside it so that a caller ending its
  OWN session through the list can still drop the cookie.

**What `dropSession()` does BESIDES the delete is the whole reason it exists**:
the RFC 9700 section 2.2.2 refresh revocation, and the single `session.end`
audit row. A `sessions.delete()` anywhere else would be a sign-out that revoked
nothing and logged nothing, and from the outside it would look identical. That
is also why both functions RETURN the session as it was: the federated lists a
sign-out has to fan out to — `wsfedRealms`, `saml2ServiceProviders`,
`oidcClients` — live on the object being discarded.

`sessionsOf(username)` and `sessionById(id)` are the readers `/logout` needs to
draw a row for a session that is not the caller's. Neither expires anything:
`sessionOf()` stays the one that reads the cookie and sweeps what it finds
expired, because an observer that quietly ended sessions while reporting on them
would be changing the thing it describes — the same rule `audit.js`'s actor
resolver follows.

## `consoleSession()` — the one reader that crosses a realm boundary, and the ADMIN CONSOLE is its only caller

The session store is `realms.map()`, so `sessionOf()` answers out of the ambient
realm's partition and a session minted in `acme` does not satisfy the default
realm's `/oauth2/authorize`. That is right, it is what `realmSupport()` promises,
and it does not change.

**What changed is that the console asks a different question, and it had to,
because of a fact about the COOKIE rather than a change of mind about realms.**
`startSession()` writes `sts_mock_session` at `Path=/` — one name, one path, for
every protocol here, deliberately and for a reason that predates realms by
months. So a browser holds exactly ONE session id for this whole origin whatever
realm minted it, and the console's realm switcher (a link to the same page in
another realm) was not merely landing on the sign-in screen: signing in there
OVERWROTE the only cookie slot the browser has, so switching back landed there
too. **One sign-in per click, forever, with nothing expired and nothing
misconfigured** — the two realms were taking turns holding one cookie.

The function that fixed that was `sessionAnywhere(req)`: it asked the ambient
realm first, through `sessionOf()` so the common case was byte-for-byte what it
had been, and then every other realm's partition by name. **It is
`consoleSession(req)` now and it asks ONE realm** — the default — and the
paragraph below says why the change was forced rather than tidied. It still
returns `{ session, realm, foreign }`, and it still sweeps an expired session
out of the realm that holds it exactly as `sessionOf()` does.

**THE FUNCTION IS `consoleSession()` AND IT ANSWERS "THE DEFAULT REALM'S", NOT
"ANY REALM'S" — and the paragraph below this one used to say the opposite.** The
old argument was explicit about its own premise: *the authorization behind it was
never per realm, because Admin Read and Admin Write are groups in the ONE shared
directory, so `rbac.rolesOf()` returns the same answer in every realm.* **That
premise became false on 2026-08-25**, when the embedded directory became a
subtree per realm. Each realm has its own `ou=groups` now, so a session minted in
`acme` still opening the console would mean anybody who can create a realm can
grant themselves both roles inside it and walk back out into the default one —
the realm feature would have become a privilege escalation.
`ldap/ldap_server.js` pins `admin_rbac.js`'s whole directory to the default realm
for that reason, and this function is the other half of the same decision. **The
two have to agree**: a gate that accepted an `acme` session while the roster
could only name default-realm people would let somebody in and then insist they
were nobody.

**Two things make this the boundary already drawn rather than a hole in it, and
both have to stay true if anything here is reworked:**
* **It grants nothing else.** `gateStateFor()` in `admin-ui/admin.js` is the only
  caller, and the only thing it answers is "may this browser read this console".
  No token is issued on the session it finds and no assertion names it. Every
  protocol module still calls `sessionOf()` and still sees its own realm's
  partition only.
* **Ending it still ends it.** What comes back is the one object in whichever
  realm's map holds it, so `/logout`, `/admin/logout` and an expiry sweep in the
  owning realm all shut the console with it. There is nothing separate here to
  end.

**Do not give a second caller this function by analogy.** The test it passed is
the one in the first bullet — that the decision it feeds is already realm-shared
— and there is exactly one such decision in this service. A protocol endpoint
reaching for it would be single sign-on across realms, which is the thing a realm
exists to refuse.

The console SAYS which realm holds the session when it is not the one being read,
on the banner and beside the switcher. Showing it silently is how somebody comes
to believe the realms share the rest of it as well, and the next thing they
conclude is that `/oauth2/authorize` would have taken the same cookie.

---


**`authn.js` is the authentication service, and it is not part of any protocol.**
The sign-in screen used to be rendered inside `GET /oauth2/authorize`: no session
meant a 200 with the login form in the body, at the authorization endpoint's own
URL. It is now its own endpoint and its own module, and the protocol endpoints
send people to it:

```
GET /oauth2/authorize (no session)
    -> 302 /authn/login?authn=<id>          the request is stashed with a
                                            return URL built from its own query
    -> the screen; POST /authn/login        the session cookie is established
    -> 302 back to /oauth2/authorize?<the original query, minus prompt>
    -> the session is there this time, so the response goes out per spec
```

Four things about that are load-bearing:

* **The service knows nothing about OAuth.** It never reads `client_id` or
  `redirect_uri`. What the screen shows about the request it interrupted arrives
  as `details` rows the CALLER wrote, because only the caller knows what its own
  parameters mean — the `issuer_state` note, for one, which says whether the
  request came from a Credential Offer this issuer actually made.
* **A refusal comes back rather than being answered there.** Cancel returns to
  the caller with `authn_error=access_denied`, and the caller turns that into
  its own protocol's refusal. `redirectBack()` in `oauth2.js` knows about
  `response_mode`, and in `form_post` the answer is not a redirect at all but a
  self-submitting form — protocol knowledge stays in the protocol module. The
  authorization endpoint checks for that parameter BEFORE it checks the session,
  or a refusal would be answered by sending the person straight back to the
  screen they just declined.
* **`returnTo` is checked to be a path on this service.** It is built by the
  caller and never read off the query string, and it is checked anyway: an
  authentication service that will redirect a browser to an arbitrary URL after
  signing somebody in is a credential phishing tool with a login screen in front
  of it.
* **It owns the SESSION**, and `wsfed.js` and `admin.js` take it from here.
  `oauth2.js`'s old note said the session lived there "because this module owns
  the login flow the session comes out of" — which is exactly the sentence that
  moved it, now that the login flow has. `oauth2.js` reads the session and never
  writes one. The WebAuthn second factor moved with it for the same reason: it
  is the other half of one act of authentication, and it shares the pending
  record.
* **WEBAUTHN IS TWO ROLES ON ONE SCREEN and the ceremony cannot tell them
  apart.** `use_webauthn` is the second factor after a password (session
  `amr ["pwd","hwk"]`, `acr "mfa"`); `webauthn_only` is the PRIMARY credential
  with no password read at all (`amr ["hwk"]`, `acr "1"` — ONE factor, since
  the ceremony asks for user verification as `preferred` rather than
  `required`). Four things there are load-bearing. The choice is made at the
  password screen and CARRIED on the pending record, because the ceremony's own
  POST is the browser's result and nothing in it says what somebody chose a
  screen ago. `webauthn_only` WINS where a hand-made POST sets both, since the
  boxes cannot be made exclusive on a screen that runs no script. A caller that
  demanded a second factor (`forceMfa`, from `acr_values`) is refused the
  passwordless path SERVER-SIDE — `disabled` is a property of a browser and not
  of a request. And `methodPhraseFor()` exists because there are three outcomes
  now: the two-way conditional it replaced asked whether `hwk` was present and
  called a passwordless sign-in a password one. Anything downstream that reads
  `hwk` to mean "two factors" is wrong for the same reason — `wsfed.js`'s
  `authnMethodsFor()` was, and now tests for `hwk` AND `pwd`.

---

## It checks no password

* **It checks no password.** The username typed at `/authn/login` becomes the
  identity in every token and every assertion — for every protocol, since
  2026-08-26, when WS-Federation gave up the screen of its own that used to post
  to `/wsfed/login` and started arriving here through `beginAuthentication()`
  like the other three browser SSO profiles.

One password IS rejected, here and in three other places:

* **One password is rejected** — the literal string `invalid` on the password grant,
  on WS-Trust and at the WS-Federation sign-in screen — so a negative test has
  something to fail on in every protocol here.

## `beginAuthentication()` does not always answer with this module's screen

Since 2026-08-26 it takes an `application` — the identifier the caller's own
protocol presented, a `client_id` from `oauth2.js`, an entityID from
`saml2_sso.js`, a relying party id from `saml11_sso.js` — and what comes back
is now one of FOUR things:

| What the entry names | What comes back |
|---|---|
| ONE usable relationship, auto-redirect on | `/federation/login/{id}` — the partner, directly |
| SEVERAL usable, auto-redirect on | `/authn/select-idp?authn={id}` — the CHOOSER |
| the mechanism `spnego` | `/authn/spnego?authn={id}` — the KERBEROS DOOR |
| anything else | `/authn/login?authn={id}` — this module's screen |

**The caller cannot tell them apart and must not.** What a protocol module
asked for is "get this person authenticated and bring them back to `returnTo`",
and which identity provider does the authenticating — or whether the person was
asked which — is not its business. That is the property the partner buttons at
the foot of the screen have had all along. What changed is first that nobody
has to press one, and then that where there IS a choice it is between THIS
APPLICATION'S partners rather than every relationship in the register.
`federationFor()` is the whole of it, and its header carries the four checks
and why each is made at the READ rather than at the write.

**No pending record is SPENT on the first path**, and that is not an
optimisation: the browser goes to a foreign identity provider and comes back to
`/federation/acs/{id}`, which finishes the sign-in through `startSession()`
without this screen ever being drawn. A record minted there would be one nothing
could ever spend. The CHOOSER is the opposite case — it draws a page, so it
needs the record, and it reads the same one the screen would have, out of the
same store and with the same ten-minute expiry.

**THE KERBEROS DOOR IS ALSO THE OPPOSITE CASE, and for a different reason worth
knowing rather than looking like an inconsistency.** `/authn/spnego` never
LEAVES this origin: the 401 and the token are one URL fetched twice, the record
is what carries `returnTo` across those two fetches, and it is also what the
fallback link on every page of that door points back into. That is why the door
takes an `?authn=` and no `returnTo` of its own — there is no open-redirect
surface on it at all.

### The Kerberos branch, and what it loses to `forceMfa`

`mechanismFor()` can now resolve to `spnego`, from either source, and
`beginAuthentication()` then redirects to `/authn/spnego?authn={id}` instead of
drawing anything. **It loses to `forceMfa` and says so at INFO**, exactly as
`forcePasswordless` does and for the identical reason: a ticket claims whatever
its own flags claim — `amr ["pwd"]` for `pre-authent`, `["hwk"]` for
`hw-authent`, both for both, nothing for neither — so it cannot be PROMISED to
answer a caller that demanded two factors.

What that costs is not nothing and is worth stating: somebody at a domain-joined
machine holding a perfectly good hardware-backed ticket is sent to a password
box. The alternative is to send them to the door and find out — and the door
cannot refuse at that point, because by the time the flags are readable the
ticket has been accepted and the only options left are to mint a session
claiming one factor or to throw away a successful authentication. Refusing to
PROMISE is the honest half of that, and the button on the screen is withheld
under `forceMfa` for the same reason.

### `appAuthnMechanism` — the generalisation of `appFederationRelationship`

An application entry may now DECLARE how its people authenticate, from the same
closed vocabulary `fedAuthnMechanism` uses (`federation.MECHANISM_IDS`). One
table for both, because they answer the same question from two sides, and two
tables would have drifted the first time either grew a value.

It exists because `spnego` had no way of being asked for: the pair beside it can
say "send my people to a federated identity provider" and cannot say "my people
hold Kerberos tickets", which is the commonest integrated-authentication
deployment there is.

`declaredMechanismFor()` reads it, and three properties are load-bearing:

* **An empty value is not `password`** — it is "this entry says nothing". Every
  entry in the field holds an empty one, so reading it as an explicit "use the
  screen" would have switched off every `appFederationRelationship` in existence
  in one commit.
* **`federation` falls through to the list**, because it IS what naming a
  relationship already implied, said out loud. Declaring it while naming nothing
  usable is REPORTED rather than falling quietly back to a password box.
* **The checks are made at the READ**, for `federationFor()`'s reason exactly:
  it is a string on a directory entry that `ldapmodify`, the console and the
  management API can all reach, and the setting that decides whether `spnego`
  will work is settable at runtime. A check made at the write would be a check
  about the past — and `spnego` declared while `krb5.spnegoAuthentication` is
  off is exactly the state that would otherwise put somebody in front of a 403
  halfway through a sign-in.

### `/authn/select-idp`: the chooser, and why it is not the screen with its form hidden

An entry may name SEVERAL relationships — `appFederationRelationship` is
multi-valued since 2026-08-26 — and they need not share a protocol: a SAML 2.0
partner and an OpenID Connect one are the ordinary pair. When more than one of
them is usable there is a question to put to the person, and
`federationFor()` deliberately returns NO single `relationship` in that case,
so the redirect branch above cannot fire and pick the first partner for
somebody.

**It is a page of its own.** The alternative was this module's own screen with
its form suppressed, and that was refused: that page carries `username`,
`password`, `kc-login` and `kc-cancel`, it POSTs to a handler that signs
somebody in on a typed name, and every one of those element ids is what four
tests and a person's muscle memory look for. Hiding the form leaves a page that
is a sign-in screen in everything but what it shows — and the first time
somebody re-added a field to it, the chooser would grow a password box nobody
asked for.

**`appFederationAutoRedirect` still decides whether a SCREEN is drawn.** It
means what it always meant — "without the sign-in screen" — and with several
partners that is this page, which is the screen's job done without the screen.
FALSE with several named is therefore the screen itself, with one button per
partner under the password box, exactly as FALSE has always behaved with the
partners plural. What the setting never means is "pick one for them": there is
no value of a boolean that can say which identity provider somebody's employer
is.

**The unusable values are PRINTED there, one banner each.** A list of three
whose middle value names a disabled relationship draws two buttons, and two
buttons is exactly what a correct list of two draws — so the difference has to
be said in words, and each is a different entry for an operator to go and fix.

**The list is resolved AGAIN when the page is drawn**, not taken from the
redirect that produced it, and the record's copy is replaced with the answer.
The record lives ten minutes and the register has four doors; a relationship
disabled in between would otherwise be a button leading to a refusal at a
foreign service. If fewer than two partners are left, the screen is drawn
instead — and because the record was updated, the screen agrees with what the
chooser just found.

**There is no "none of these" escape**, deliberately. This page is reached
because an application was configured to authenticate its people elsewhere, and
an escape hatch to the password box would be that configuration meaning
nothing. Every relationship being unusable is the one case where this page is
not drawn at all: `federationFor()` reports no usable partner and the screen
appears with the problems on it.

**It is the ONE branch that draws no page that has to say so in the LOG.** With
the auto-redirect on and exactly one usable value, an entry naming three
partners of which two are disabled works perfectly and shows nobody anything —
so `beginAuthentication()` logs the other values' problems at INFO. There is no
banner to put them on and the flow succeeding is exactly why nobody would go
looking.

**`returnTo` is checked twice, here and again in `federation_sp.js`**, which
that module's decision 4 already argued for its own reasons. Two checks on one
value is deliberate: this one catches a caller's bug and that one catches
somebody handing the federated entry point a `returnTo` of their own.

### The screen's partner list, and the one setting it deliberately ignores

`federatedOptionsHtml()` has two halves now. An application that NAMES
relationships gets THOSE partners and only those — offering the rest of the
register beside them would put the discovery step back one line below the
configuration that narrowed it — and that half **ignores
`federation.loginButtons`**, which the generic list still respects.

**All of them, not the first.** The attribute holds a list, and this screen is
what a person meets when the auto-redirect is OFF — which is precisely the
configuration that says "let them choose". One button for a list of two would
make that setting mean the opposite of what it says.

The asymmetry is the point rather than an oversight. That setting exists so
that a service with no federation configured has a sign-in screen byte for byte
the one it always had, and an application whose entry names a partner *is*
federation configured. The auto-redirect above cannot consult a screen setting
either — it never draws a screen — so honouring it here would make one
configuration behave two ways depending on an unrelated boolean.

`federatedButtons()` renders both lists, because two copies of an anchor
carrying a `returnTo` is two chances to drop the `returnTo` from one of them,
which produces a federated sign-in that succeeds and lands the person on a page
nobody asked for.

## `mechanismFor()` — the TWO places a sign-in can be redirected from, and the one order

`federationFor()` above is no longer the only thing consulted, and the honest
way to describe the change is that this module now has to arbitrate. Since
2026-08-26 an identity-provider-side federation relationship may carry
`fedAuthnMechanism` — `password`, `password-mfa`, `webauthn`, `spnego` or
`federation` —
which says what this service does when THAT PARTNER asks it to authenticate
somebody. See `federation/CLAUDE.md`, where the attribute is argued.

The two answer different questions, which is why both exist:

* a **relationship** answers "a partner has sent somebody here; what do I do?"
* an **application entry** answers "where do this application's people sign
  in?" — in TWO attributes since 2026-08-26, `appAuthnMechanism` (the explicit
  statement) read before `appFederationRelationship` (the implicit one)

`mechanismFor()` is the ONLY function that reads both, and it reads them in one
order: **the relationship first** (it is the more specific statement — an entry
under `ou=applications` may be a federation partner AND an ordinary OAuth
client, registered by two different people), then the application entry's
`appAuthnMechanism`, then its `appFederationRelationship`, and the screen last. Nothing else in this service may consult either directly, because
two orders is no order.

**An empty mechanism is not `password`.** `authenticationFor()` returns `null`
for a relationship that declares none — which is every relationship created
before the attribute existed — and this function then behaves exactly as it did
when `federationFor()` was the whole of it. That is the entire compatibility
argument, and it is why the empty case returns null rather than a default.

### `forcePasswordless`, and why nothing a caller passes can set it

`forceMfa` is a demand the CALLING PROTOCOL made — a `RequestedAuthnContext`, a
`wauth` — and it arrives in `opts`. `forcePasswordless` is a mechanism an
OPERATOR configured, and it arrives from the register; there is deliberately no
`opts.forcePasswordless`, because a caller asking for a passwordless sign-in is
a caller choosing somebody else's authenticator for them, which is a deployment
decision and not a request parameter.

**When both would be on, `forceMfa` wins and says so at INFO.** Passwordless
WebAuthn is `amr ["hwk"]` and ONE factor, however phishing-resistant it is, and
one factor does not answer a request for two. They cannot both be on from the
register — one enum value, one mechanism — so the collision is always
protocol-versus-configuration, which is exactly the case where the protocol's
demand is the one that must not be quietly downgraded.

### The hidden input is not the enforcement

`loginPage()` renders a hidden `webauthn_only` when the mechanism demands one,
and `use_webauthn`/`webauthn_only` are drawn `checked disabled` so a person can
see what has been decided for them. **None of that is a control.** A disabled
checkbox posts nothing and a hidden one is deleted by anybody with the
developer tools open, and the POST that arrives then looks exactly like an
ordinary password sign-in — so `handleLogin()` reads `record.forcePasswordless`
as well and the record wins. A configured mechanism a client can opt out of is
not a mechanism.

### `record.mechanismProblem`, beside `record.federation`

Both sources report an unusable relationship as a `problem` string, and the
screen prints it rather than falling silently back to the password box. **Every
one of them, deduplicated.** The attribute holds a list, so an entry naming
three partners of which two are disabled has two things wrong with it — showing
one would have somebody fix it, reload, and meet the next. They overlap by
construction, though: when the application entry is what decided the sign-in,
`mechanismFor()` copies that entry's FIRST problem onto the record, so a plain
concatenation prints it twice and reads as two faults. They
fail DIFFERENTLY, though, and that is why the problem is carried on the record
and not only inside `federation`: an application entry naming an unusable
relationship still produces a `federation` object to hang it on, while a
BROKERING relationship whose onward partner is disabled produces no such object
at all — there is nothing usable to describe. Reading it from one place is what
stops the second case being the silent fallback the first was made loud to
prevent.

### `usableServiceProvider()` is federation.js's, and used to be written out here

The four checks `federationFor()` makes on a relationship id — it exists in
this realm, it is service-provider-side, it is enabled, it is fully configured
— are now one function in `federation/federation.js`, because
`fedAuthnRelationship` gave them a second caller. **`usableServiceProviders()`
beside it is the same four over a LIST**, and it is a function rather than a
`map().filter()` here for one reason: it KEEPS the unusable rows with the
sentence written about each. Filtering them out at the call site is what makes
a list of three with one disabled indistinguishable from a correct list of two. A relationship id on an
application entry and one on another relationship are the same string,
checkable the same four ways, and two implementations of "would this actually
work" would answer differently the first time one of them learned a fifth.
