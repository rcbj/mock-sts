# kerberos/

Kerberos v5 — a KDC on raw TCP and UDP 88 and over MS-KKDCP, a Kerberos-protected
service, the same acceptor over HTTP as SPNEGO (RFC 4559/4178), and **a way of
signing in with it**. Fourteen files, and they divide into three groups.

**The codec**, which knows nothing about this service: `krb5_primitives.js`,
`krb5_asn1.js`, `krb5_crypto.js`, `krb5_messages.js`, `krb5_ndr.js`,
`krb5_pac.js`, `krb5_gss.js`. They require only each other and bunyan, so they
load in a test with no configuration at all — which is what the guarded
`require(process.env.CONFIG_FILE)` at the top of each is for.

**EVERY ONE OF THOSE SEVEN IS VENDORED, and so is `krb5_spnego.js` below —
eight files in this directory are somebody else's, and NONE of them may be
edited here.** They are byte-identical copies of the parent project's
`common/krb5/*.js`, written by that repository's
`common/krb5/sync-to-mock-sts.sh` and held to byte equality by its
`tests/krb5_codec_sync.js`. A change made here is reverted by the next sync and
fails that test in the meantime — which is what happened on 2026-08-25, when a
logging sweep added `log.debug()` pairs to `krb5_primitives.js`,
`krb5_asn1.js` and `krb5_messages.js`: 48 lines, no behaviour, and a red test in
a repository that does not contain them. **A sweep over this repository must
skip these eight**, the way it already skips `../common/vendored/` and
`../spiffe/protos/`.

The fix for a real defect in one of them is to change it in the parent project,
run that script, then commit here — in that order, because the script overwrites
whatever is here. Note that the behavioural half of `krb5_codec_sync.js` can
still PASS while the byte comparison fails: two copies can differ in comments or
log lines and agree perfectly on the wire, right up until the day the difference
stops being cosmetic.

**The service**: `krb5_principals.js` (the principal database and every long-term
key in it), `krb5_kdc.js` (AS and TGS, plus `/KdcProxy` and `/krb5/principals`),
`krb5_service.js` (the acceptor).

**`krb5_spnego.js` is VENDORED too**, and is called out separately only because
it is the one that reads as this service's own: `spnego.js` sits beside it and IS
ours. Like the seven above it is a byte-identical copy of the parent project's
`common/krb5/krb5_spnego.js`, kept honest by `tests/krb5_codec_sync.js` over
there. None of the eight is in `../common/vendored/` with the other five copies,
because they belong to the codec they sit beside and moving them would put the
whole Kerberos wire format in a directory that has nothing else Kerberos in it.
**Do not edit any of them here.**

**`spnego.js` must stay after `krb5_service.js` in the require order**, and that is a
dependency rather than a preference: it calls that module's `accept()` for every
Kerberos check and adds none of its own. It is also the one Kerberos module that
starts NOTHING — it is HTTP all the way down, so requiring it is the whole of its
installation. Note the naming: `krb5_spnego.js` beside it is the VENDORED RFC 4178
codec (a byte-identical copy of the parent project's `common/krb5/krb5_spnego.js`,
kept honest by `tests/krb5_codec_sync.js` there), and `spnego.js` is this repo's own.
Do not merge the two — one of them is somebody else's file.

---

## SPNEGO IS THREE FILES SINCE 2026-08-26, BECAUSE THERE ARE TWO DOORS

`spnego.js` used to be the whole of it: the negotiation, the HTML and the one
endpoint. It is now the last of four layers, and each adds exactly one thing.

| File | What it adds | Registers |
|---|---|---|
| `krb5_service.js` | the AP-REQ. Every Kerberos check, over any transport. | `/krb5/service` |
| `spnego_exchange.js` | RFC 4178 and the RFC 4559 header. No Kerberos code, no HTML, no session. **A LIBRARY** — rule 3, so its position is not a position. | nothing |
| `spnego.js` | a page that explains what happened. | `/spnego`, `/spnego/protected` |
| `spnego_authn.js` | **a session, and the identity that goes in it.** | `/authn/spnego` |

**The split was forced by the second door and it is not tidiness.**
`/spnego/protected` documents a handshake; `/authn/spnego` performs the same
handshake and mints the browser session sixteen protocol families read. Those
two have to be IDENTICAL rather than similar, because one of them is the
documentation of the other — a second copy of the negotiation would be a page
describing a check the sign-in does not make, with nothing anywhere to fail.
This is the promise `krb5_service.js`'s own header made when `spnego.js` was
written (*"the acceptor logic here is written as its own function so that phase
adds a transport and no protocol code"*), kept a second time one layer up.

**`negotiate()` RETURNS A VERDICT AND NEVER A RESPONSE.** It does not take a
`res`. Fifteen outcomes, named in that module's `OUTCOMES` table, each carrying
the HTTP status and the complete `WWW-Authenticate` value — because that header
is the part the PROTOCOL specifies and two spellings of it would be two
acceptors. Both doors are renderers over it. A branch added to `spnego.js` that
DECIDES something rather than describing it belongs one file over.

### `spnego_authn.js`: the one sign-in here that checks a real credential

Everywhere else in this service the username typed IS the identity. Kerberos
cannot work that way — the password there is the key — so this door verifies a
service ticket against a real long-term key, refuses a replay, and gives the
principal inside a session. The KDC behind it stays as permissive as the
protocol allows (see the section below); **the verification is real and the
account policy is not**, and those are two different sentences.

Five things about it are load-bearing:

* **IT NEEDS NO INVERTED HOOK, and rule 3e's list is six slots long so a
  seventh is the obvious move.** `authn.js` has to know two things about this
  door: the PATH, which is in the `/authn/*` space that module already owns, so
  it declares the constant and this file imports it; and whether the door is
  open, which is `krb5.spnegoAuthentication` and is read from `config.js` by
  both. Rule 3e's test is whether a require would close a cycle or move a
  route — here nothing has to point anywhere.
* **The require goes ONE WAY**: this file requires `authn/authn.js` for
  `startSession()`, `pendingFor()` and `completeAuthentication()`, and that
  module requires nothing in this directory and must not. `authn.js` is #8,
  ahead of `oauth2.js` which reads the session it owns; a require in the other
  direction would drag the KDC's routes to the front of the router.
* **The acceptor does not record the authentication for this caller.**
  `accept()` takes `record: false`, which has exactly one call site. The act
  here is a ticket accepted AND a session minted, `startSession()` is the funnel
  that records exactly that with the `sessionId` on it, and two records would
  make `/admin/users` count one sign-in twice — the defect federation shipped
  with and fixed the same way. Everything else (the raw socket,
  `/spnego/protected`, the parent project's real-DC jobs) still records in the
  acceptor.
* **THE REALM IS STRIPPED FROM THE PRINCIPAL, AND ONLY THE LOCAL ONE.**
  `alice@EXAMPLE.COM` becomes a session for `alice`, because the session's
  username becomes `sub: urn:sts-mock:user:<name>` in every token that follows
  and leaving the realm on would make a typed sign-in and a ticket sign-in two
  subjects for one person. A FOREIGN realm is kept whole — `bob@PARTNER.COM` is
  not this service's `bob` — and the asymmetry is deliberate:
  `admin_stats.js`'s `identityOf()` folds them onto one DIRECTORY entry anyway,
  so the directory answers "which human" while the token answers "who am I
  asserting", and they are allowed to differ.
* **`amr` AND `acr` ARE READ OFF THE TICKET'S OWN FLAGS**, which is the only
  place in this service where they are derived from something a credential
  actually says. `pre-authent` → `pwd` (RFC 4120 section 2.1: the KDC verified
  PA-ENC-TIMESTAMP, a timestamp under a key derived from a password);
  `hw-authent` → `hwk`; both → `acr "mfa"`; **neither → an EMPTY `amr` and
  `acr "0"`**, because filling in `pwd` there would be telling a relying party
  a password was checked when nothing knows whether one was. `initial` is
  reported on the page and used for nothing — it says where the credential was
  minted, not what was checked.

### It is available to every application, three ways, and none of them is registration

1. **A BUTTON ON `/authn/login`** (`krb5.spnegoLoginButton`), for whatever flow
   is already in progress — the same argument `federation.loginButtons` makes,
   and it lands harder here: whether somebody can use a ticket is a fact about
   THEIR MACHINE and not about the relying party.
2. **`appAuthnMechanism: spnego`** on an application entry — that application's
   people never see the screen.
3. **`fedAuthnMechanism: spnego`** on an identity-provider-side federation
   relationship — a foreign partner that has never heard of Kerberos is
   satisfied by a ticket.

**The button is WITHHELD from a request that demanded two factors, and says
so**, exactly as `beginAuthentication()` refuses a configured `spnego`
mechanism under `forceMfa`. A ticket claims what its own flags claim, which is
usually one factor, and by the time the flags are readable the ticket has been
accepted — so the only honest place to refuse is before the offer.

**Every refusal draws a page with the sign-in screen linked from it.** A bare
`401 WWW-Authenticate: Negotiate` is a dead end in every browser not configured
for this host (Chrome's `--auth-server-allowlist`, Firefox's
`network.negotiate-auth.trusted-uris`, plus a credential cache in the realm), and
somebody meeting that on the way into an application would be stuck. That is
why the door takes an `?authn=` and carries it through rather than spending it
on arrival — and why it takes **no `returnTo` of its own**: the return address
is on the pending record, so there is no open-redirect surface here at all.
(`/federation/login/{id}` does take one and has to; the browser leaves this
origin there and comes back to a different endpoint. This one never leaves.)

**The pending map for `request-mic` continuations is keyed by DOOR as well as
by remote address.** That stand-in for connection identity was only ever a
diagnostic while one door used it; with a sign-in door on the same map, a
continuation arriving at `/authn/spnego` could otherwise be matched against a
half-finished exchange begun at `/spnego/protected` by anybody sharing the
address — a NAT, a proxy, a container network — and the accepted client on that
entry is what the session would be minted for.

---

## The KDC's listeners start from `listen()`, not at require time

See the root `CLAUDE.md` for the rule; the reason it applies here is that
binding 88 needs root, and on a host run it usually fails.

---

## Kerberos is the exception to "it checks no password", and cannot not be

* **Kerberos is the exception, and cannot not be.** The password there *is* the key:
  pre-authentication and the AS-REP's enc-part are both encrypted under it, so a KDC
  accepting anything would still have to pick a key the client could not guess. So it
  does the permissive equivalent — **any username authenticates and every user account
  shares one password** (`password!`, `KRB5_USER_PASSWORD`), with a name nobody
  configured created on first sight by `findOrCreateUser()`. Three things stay
  refusals on purpose: a **service**-shaped (multi-component) name is created only
  for a host this service is willing to BE — `KRB5_SERVICE_DOMAINS`, the realm's own
  domain plus `localhost`, `sts` and `127.0.0.1` — and anything else stays
  `KDC_ERR_S_PRINCIPAL_UNKNOWN`; the names in `KRB5_UNKNOWN_USERS` stay unknown so
  `KDC_ERR_C_PRINCIPAL_UNKNOWN` is still reachable; and a wrong password is still
  `KDC_ERR_PREAUTH_FAILED`. That service exception is new (2026-08-17) and it is not
  a softening of the argument against inventing services: this process is both the
  KDC and the acceptor, `krb5_service.js` looks the presented SPN up in the same
  table, so a name created on demand is one the service can decrypt — which was the
  whole objection. It exists because a client derives `HTTP/<url host>` and every
  way of reaching this stack produced an SPN nobody had configured. Service,
  computer and `krbtgt` accounts keep their own distinct passwords — the two krbtgts
  and the trust must be three different secrets or assertions about which key sealed
  what pass for the wrong reason.

## The KDC advertises PA-ENC-TIMESTAMP, and it did not until 2026-08-27

`KDC_ERR_PREAUTH_REQUIRED`'s e-data is a METHOD-DATA (RFC 4120 section 5.9.1):
the list of pre-authentication methods this KDC will accept. A client READS that
list to decide what to send next. This one sent `PA-ETYPE-INFO2` and
`PA-PW-SALT` and not `PA-ENC-TIMESTAMP`, so it named the salt a client needs
without ever naming the method it wanted — and the consequence was total:

* `kinit` from MIT Kerberos could not obtain a ticket from this KDC AT ALL. Its
  trace reads `Processing preauth types: PA-ETYPE-INFO2 (19), PA-PW-SALT (3)`,
  finds no method it can run, retries the same unauthenticated AS-REQ and gives
  up with `Generic preauthentication failure while getting initial
  credentials` — a message naming neither the padata list nor this KDC.
* Chrome and Firefox answer a `Negotiate` challenge through the same GSSAPI, so
  no browser could ever have signed in at `/spnego/protected` or
  `/authn/spnego`. The note on the sign-in page telling somebody to set
  `--auth-server-allowlist` was correct and would not have been enough.

**NOTHING HERE NOTICED FOR AS LONG AS THE FEATURE HAS EXISTED**, and the reason
is the shape of every interoperability defect a mock has: the debugger's client
and this repository's tests both send PA-ENC-TIMESTAMP whether it was offered or
not, because both were written against this KDC. Both ends shared the
assumption, so both ends agreed. It took a REAL client to find it.

The fix is one entry, empty and first, in `preAuthRequiredReply()` — the value
is a zero-length octet string because in a reply it is an offer rather than
data. `kinit`, `kvno` and `curl --negotiate` now complete against this KDC end
to end.

**IT IS GUARDED NOW, AND THE GUARD IS THE ONLY KIND THAT COULD WORK.** The
parent suite's `tests/krb5_mit_client.js` drives this KDC with MIT Kerberos —
`kinit`, `klist`, `kvno`, `kdestroy` and `curl --negotiate` — and its first
section is exactly this: `kinit alice` completing at all means the method list
was honest, and the failure message says so in those words and quotes what
`kinit` printed. **No test written against our own client can guard it**, which
is why `tests/krb5_as_exchange.js` and every Kerberos job in both repositories
passed throughout: they send PA-ENC-TIMESTAMP whether it was offered or not.
That job installs `krb5-user` in the parent's `tests/Dockerfile`, so the
containerized suite always runs it, and SKIPS with a reason on a machine without
MIT Kerberos.

## Delegation is recorded, refusals included, and the policy is published

Four of the eight mechanisms `/admin/delegation` knows are this directory's:
S4U2Self, S4U2Proxy classic, S4U2Proxy resource-based, and a forwarded
ticket-granting ticket. **Kerberos is also the ONLY family in this service that
polices delegation at all** — WS-Trust puts no authorization on `OnBehalfOf` or
`ActAs` and RFC 8693 leaves it to a policy this authorization server has not got
— so this is the one place where a refusal has a reason worth publishing.

Two halves, and they live where their stores do:

* **`krb5_kdc.js` records the ACTS**, through `../common/delegation.js` (rule
  3l). `resolveS4u()` can refuse ELEVEN ways and every one of them goes through
  **`refuseS4u()`**, which attaches the `intent` built at the top of that
  function to the error it is already returning; `handleTgsReq()` then records at
  the ONE place it handles `s4u.error`. That is what keeps eleven refusal sites
  to one recording site — the same arrangement `recordAuthentication()` has for
  the sixteen families. **The reason on the row is the error's own `e-text`**,
  not a second sentence written for the console: that text is what the client is
  about to be sent, and two wordings of one refusal would eventually disagree
  about which attribute was missing. An ISSUED act is recorded at the bottom of
  `handleTgsReq()`, beside `stats.recordTicket()`, because that is the first line
  at which the ticket exists. The FORWARDED block records its own three (two
  refusals and the success) inline, because it never passes through
  `resolveS4u()` and its parties are different: the user is handing its OWN
  credentials over, and this KDC is never told to whom — which is what the empty
  intermediary on that row means and is the definition of unconstrained
  delegation.
* **`krb5_principals.js` publishes the POLICY**, as `delegationPolicy()`. It
  owns the two attributes, so it is where what they MEAN is decided; `admin.js`
  requires it and renders the answer. It reports the pairs from both
  `msDS-AllowedToDelegateTo` (front end) and
  `msDS-AllowedToActOnBehalfOfOtherIdentity` (back end) in ONE list with a field
  saying which account carries the permission — the messages and the KDC options
  are identical and that is the whole difference — plus the account flags that
  STOP delegation (`NOT_DELEGATED`) or enable protocol transition
  (`TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION`), and `ok-as-delegate`, which is
  advice to the client and not a control.

**`warning` on a pair is for something genuinely WRONG, and it got that wrong
once.** The resource-based rows used to push "this also needs PA-PAC-OPTIONS"
into it unconditionally, so every RBCD pair reported something missing for ever
and the field could never say *nothing is*. That sentence is a property of the
MECHANISM and belongs in `requires`, where it already was. What `warning` is for
is the expensive case: a front end with `msDS-AllowedToDelegateTo` set and NO
`TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION`, whose S4U2Self ticket is simply not
forwardable — so classic S4U2Proxy fails a step later complaining about the
evidence, two steps from the attribute that caused it. `HTTP/notrusted` exists in
the principal table to produce exactly that, and the page now says so before
anybody tries it.

---

## The parent project loads these modules in-process

`tests/krb5_as_exchange.js`, `tests/krb5_tgs_ap.js`, `tests/krb5_spnego_http.js`
and `tests/krb5_delegation_interop.js` require `krb5_kdc.js` and
`krb5_service.js` directly, through `tests/module_paths.js`'s `mockStsModule()`,
and `tests/Dockerfile` copies the transitive closure of what those two require
into its image. The 2026-08-23 reorganisation broke both, because they named flat
paths (`sts/krb5_kdc.js`); **both were repaired over there on 2026-08-28** and
this paragraph described the breakage as open until then.

**Those four callers still pass BARE filenames, and that is correct — do not add
directories to them.** `mockStsModule()` was fixed by making the RESOLVER search
the mock's subdirectories rather than by making every caller name one, so
`mockStsModule("krb5_kdc.js")` finds `kerberos/krb5_kdc.js` on its own and a
future move of a module between directories here costs that project nothing.

What is still live is the CLOSURE rather than the paths: give any module those
three reach a new `require()`, and `tests/Dockerfile` needs a COPY line in the
commit that bumps the `sts/` gitlink across the change, or the four jobs die at
load with `Cannot find module` naming a file nobody edited. See
`docs/parent-project-migration.md`.

`MOCK_STS_DIR=/path/to/mock-sts` still points those tests at a working copy,
unchanged; below it there is now a sibling-checkout candidate that resolves and
says loudly that the run reflects an unpushed working copy.

---

## A logout stops a ticket-granting ticket, and it is the only thing a KDC can honestly do

`/logout` — the protocol-independent sign-out — stamps a **sign-out instant** on
the principal (`krb5_principals.js`'s `signedOutAt`, with `signOut()`,
`clearSignOut()`, `signedOutAt()` and `signedOutPrincipals()` around it), and
`handleTgsReq()` refuses a request whose ticket was authenticated before it with
**KDC_ERR_TGT_REVOKED (20)**, which nothing here could produce before.

**BE PRECISE ABOUT WHAT THAT CODE IS.** RFC 4120 LISTS it in the error table at
section 7.5.9 — *"TGT has been revoked"* — and that is all it does. The
specification defines **no mechanism that emits it**, no state a KDC keeps in
order to decide it, and no way for anything to cause it; it is effectively
reserved for implementations. **Kerberos has no logout message, no session
concept and no revocation of any kind**: there is no CRL, no status query, no
list of issued tickets anywhere (the KDC is stateless about them on purpose —
that is what lets a KDC be replicated read-only), and a service validates an
AP-REQ with its own key without contacting the KDC at all. A ticket is valid
because it decrypts and its `endtime` has not passed. **Short lifetimes ARE the
revocation model.**

So the instant is an INVENTION rather than an implementation of a specified
behaviour, and any prose here that implies otherwise is wrong — this paragraph
replaced one that did. What makes it the right invention is that it is the same
lever a real KDC has: the **TGS exchange is the one moment a KDC is back in the
loop**, which is why disabling an account in Active Directory bites within the
service-ticket lifetime rather than the TGT's. Code 20 is the closest registered
code to what is happening and its text says what is meant.

The alternatives, for anyone weighing this again: changing the USER's password
invalidates nothing (the TGT is sealed under the *krbtgt* key), changing the
*krbtgt* key invalidates every TGT in the realm at once, and disabling the
account is `KDC_ERR_CLIENT_REVOKED` (18) — which refuses the AS exchange too and
is therefore being locked out rather than signed out.

**A ticket-granting ticket is an encrypted blob in somebody's cache.** There is
no list of them in this process and there could not be one on a real KDC either.
What a KDC *does* see is the next TGS-REQ, so an instant is the whole of what is
available.

**FIVE things about it are load-bearing, and four of them are ways to get it
wrong:**

* **It is checked on `authtime` and NOT on the ticket's issue time**, because a
  RENEWED ticket deliberately preserves `authtime` — the renewal block says why:
  a service reading `authtime` to decide how recently somebody proved themselves
  must not be told a renewal was a fresh proof. Checking anything else would let
  a renewal launder a signed-out ticket into a live one, which is the single most
  obvious way to break this.
* **It is in `handleTgsReq()` and NOT in `handleAsReq()`.** Signing out is not
  disabling an account. The next AS exchange must succeed — and it **CLEARS the
  instant**, which is not tidiness: Kerberos timestamps are second-granular and
  `Date.now()` is not, so a fresh ticket's `authtime` can land *before* an
  instant stamped moments earlier, and without the clear the TGS-REQ that
  immediately follows a sign-in would be refused. That case was reached in
  testing, not reasoned about.
* **It is `revoked`'s neighbour and not `revoked`.** That flag is a disabled
  account and refuses the AS exchange too. Conflating them would mean a person
  could log out and never log back in.
* **It tests the TICKET's client, not the request's `cname`** — a TGS-REQ does
  not carry one — so a ticket obtained for somebody through S4U2Self is tested
  against the person who signed out.
* **IT DOES NOT REACH A SERVICE TICKET ALREADY IN A CACHE.** The service that
  accepts one decrypts it with its own key and never contacts the KDC. That is a
  fact about Kerberos rather than a gap here, and `/logout` says so on the row
  rather than implying a completeness it has not got.

`logout.kerberosSignOut` turns the whole thing off, and then this KDC behaves
exactly as it did before the feature existed — the same switchability every
refusal in this service has, for the reason RFC 9700 mode's have it.

`signOut()` **creates nothing**: a name nobody has authenticated as has no
principal here, and stamping one into existence would put an account in the
database because somebody typed a name at a logout screen. That is the opposite
of `findOrCreateUser()`'s rule, which creates a CLIENT because an AS-REQ named
one, and `/logout` reports the absence rather than a success it did not have.

