# authn/

The authentication service and the WebAuthn relying party. **This is not part of
any protocol**, which is the point of it having a directory of its own rather
than living under `oauth-oidc/` where the screen used to be rendered.

| File | What it is |
|---|---|
| `authn.js` | The sign-in screen, the session store, and the pending-authentication record. |
| `webauthn.js` | The relying party's half of WebAuthn Level 3. |

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

* **It checks no password.** The username typed at `/authn/login` — or at
  `/wsfed/login`, which creates the same session — becomes the identity in every
  token and every assertion.

One password IS rejected, here and in three other places:

* **One password is rejected** — the literal string `invalid` on the password grant,
  on WS-Trust and at the WS-Federation sign-in screen — so a negative test has
  something to fail on in every protocol here.

## `beginAuthentication()` does not always answer with this module's screen

Since 2026-08-26 it takes an `application` — the identifier the caller's own
protocol presented, a `client_id` from `oauth2.js`, an entityID from
`saml2_sso.js`, a relying party id from `saml11_sso.js` — and when that
application's registry entry names a usable federation relationship with the
auto-redirect on, what comes back is `/federation/login/{id}` rather than
`/authn/login`.

**The caller cannot tell the two apart and must not.** What a protocol module
asked for is "get this person authenticated and bring them back to `returnTo`",
and which identity provider does the authenticating is not its business — which
is the property the partner buttons at the foot of the screen have had all
along. What is new is that nobody has to press one. `federationFor()` is the
whole of it, and its header carries the four checks and why each is made at the
READ rather than at the write.

**No pending record is written on that path**, and that is not an optimisation:
the browser goes to a foreign identity provider and comes back to
`/federation/acs/{id}`, which finishes the sign-in through `startSession()`
without this screen ever being drawn. A record minted there would be one nothing
could ever spend.

**`returnTo` is checked twice, here and again in `federation_sp.js`**, which
that module's decision 4 already argued for its own reasons. Two checks on one
value is deliberate: this one catches a caller's bug and that one catches
somebody handing the federated entry point a `returnTo` of their own.

### The screen's partner list, and the one setting it deliberately ignores

`federatedOptionsHtml()` has two halves now. An application that NAMES a
relationship gets that partner and only that partner — offering the others
beside it would put the discovery step back one line below the configuration
that removed it — and that half **ignores `federation.loginButtons`**, which
the generic list still respects.

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
