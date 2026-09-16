# kerberos/

Kerberos v5 — a KDC on raw TCP and UDP 88 and over MS-KKDCP, a Kerberos-protected
service, the same acceptor over HTTP as SPNEGO (RFC 4559/4178), and **a way of
signing in with it**. Sixteen files, and they divide into three groups — the two
stored-key modules of 2026-09-12 belong to the service group and are described at the foot.

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

**`spnego_authn.js` must stay after `spnego.js` AND after `authn/authn.js` in the
require order.** It draws with `spnego.js`'s page shell and negotiates through
`spnego_exchange.js`; and it calls `authn.startSession()`, which is why the
endpoint is HERE and not in `authn/` — a require the other way would drag the
KDC's routes ahead of `oauth2.js` and close a cycle.

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
  username is the name the directory entry — and so the `sub`
  (`urn:uuid:<entryUUID>` since 2026-09-14) in every token that follows — is
  found under, and leaving the realm on would make a typed sign-in and a
  ticket sign-in two entries for one person. A FOREIGN realm is kept whole — `bob@PARTNER.COM` is
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

**SINCE 2026-09-14 (#46 section 5) IT IS KEYED BY A NEGOTIATION ID, NOT THE
ADDRESS** — capability `spnego.pending`, provided by `spnego_exchange.js`.
Behind a load balancer every client has the balancer's address and every
browser of a kind sends the same mechanism list, so two people's negotiations
were one key and the second overwrote the first. Neither RFC 4559's header nor
RFC 4178's NegTokenResp can carry a context handle, so:

* the `request-mic` answer sets `sts_spnego_negotiation` (HttpOnly, SameSite=Lax,
  Secure over TLS, for `krb5.spnegoPendingTtlSeconds`), and a continuation that
  carries it is matched by it — and cleared;
* a continuation WITHOUT it (a client with no cookie jar — the parent's
  `krb5_spnego_http.js` job is one) is matched by its MIC: the candidates for the
  door are tried, the caller's own address first, and the MIC verifies against
  exactly one, because it is keyed by that negotiation's session key. A MIC
  that fits none deletes nothing — the address key let one bad token from
  behind the same NAT delete somebody else's negotiation;
* the row holds its keys and mechanism list as HEX: the store was persisted
  already, and a `Uint8Array` through JSON comes back as `{"0":…}`, so a
  negotiation that reached another process could never have verified;
* the continuation is SPENT through `cluster/cluster_claims.js` before it is
  accepted (`STS-KRB-0119` another process completed it, `STS-KRB-0120` the
  store could not be asked — both the `no-pending-continuation` outcome, so no
  caller's switch changed).

`tests/cluster_limits_challenges_retention.js` section D holds all four; the
parent's `tests/krb5_spnego_http.js` passed against this tree
(`MOCK_STS_DIR`), request-mic included.

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

**THE 2026-09-15 REALM ROUTING ADDED NO FILE TO THAT CLOSURE**, which is the
thing to check whenever this directory grows a require. `krb5_kdc.js` gained
`require('../common/realms')` — already in the closure through
`krb5_principals.js`, which has required it since the store was declared there —
and `krb5_principals.js` gained nothing at all: the context, the router and the
three refusals are functions in files those four jobs already load. So the
`sts/` COPY set is exactly what it was.

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

**AND IT IS OWED AGAIN AS OF 2026-09-12: `common/error_codes.js`.** The error
code registry is required by `common/audit.js`, `config.js`, `helpers.js`,
`realms.js`, `crypto.js`, `worker_pool.js`, `worker.js`, `krb5_kdc.js`,
`krb5_service.js` and `spnego_exchange.js` — all inside that closure — so the
commit that bumps the `sts/` pin across it needs `COPY
sts/common/error_codes.js ./sts/common/` in the parent's `tests/Dockerfile`, or
the four in-process Kerberos jobs die at load with `Cannot find module
'./error_codes'`. It is a leaf and requires nothing, so it is one line and no
more.

**AND OWED AGAIN AS OF 2026-09-14: `cluster/cluster_claims.js`** (#46).
`krb5_service.js` requires it to spend an Authenticator across the cluster, so
the commit that bumps the `sts/` pin across it needs `COPY
sts/cluster/cluster_claims.js ./sts/cluster/`. Everything it requires —
`config`, `realms`, `error_codes`, `cluster_capabilities`, and
`persistence/persistence.js` LAZILY — is already in that closure through
`common/app.js`, which requires `cluster/cluster_barrier.js`; if the parent's set
does not yet carry `cluster/` at all, the whole directory is owed with it. With
no store a claim is that process's memory, so the four in-process jobs behave
exactly as before.

**AND OWED AGAIN AS OF 2026-09-14: `common/client_address.js`** (#46 section 8).
`common/helpers.js` requires it to decide whether a request's forwarded headers
are believed, so the commit that bumps the `sts/` pin across it needs `COPY
sts/common/client_address.js ./sts/common/`. It requires only `net`, bunyan and
`config`, which is already in the closure. `spnego_exchange.js`'s new requires
of `cluster/cluster_claims.js` and `cluster/cluster_capabilities.js` add nothing:
`krb5_service.js` already requires both. `common/websecurity.js` now requires
`cluster/cluster_counters.js`, which is owed only if websecurity is in the
parent's set (it is reached from `authn.js`, not from the three Kerberos
modules).

**AND NOT OWED FOR THE PROXY PROTOCOL (2026-09-14, #46), ON PURPOSE.** The
KDC's TCP listener takes a PROXY protocol v2 header when `global.proxyProtocol`
is `v2`, and `common/proxy_protocol.js` is installed on it from `server.js`
(`proxyProtocol.install(kdcListeners.tcp, …)` right after `krb5.listen()`)
rather than from `krb5_kdc.js`, so the closure gains nothing. That is not a race:
`listen()` returns before any `connection` event can be delivered. `startTcp()`
now reads `socket.remoteAddress` once per connection for its debug line and its
two refusal warnings, which is the header's source when one was read. The UDP
socket is not covered — a datagram has no stream to put a header in front of —
so behind a load balancer Kerberos clients use TCP.

`MOCK_STS_DIR=/path/to/iya-sts` still points those tests at a working copy,
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


## The SPNEGO sign-in has both halves of its test, and they are in different repositories on purpose

`tests/spnego_identity.js` in this repository asserts
what a session minted from a ticket CLAIMS — which part of the principal becomes
the username, and the `amr`/`acr` read off the ticket's flags — and it is here
rather than in the parent's suite because the cases that matter cannot be
produced over HTTP: this KDC requires pre-authentication, so no client can
obtain a ticket claiming no factor at all, and nothing here ever sets
`hw-authent`. The other half needed a listener and is
`tests/kerberos_spnego_signin.js` over there, which drives the DEBUGGER's own
AS, TGS and SPNEGO pages to build a real service ticket, spends it at
`/authn/spnego`, and then completes an ordinary OIDC Authorization Code flow on
the session that comes back. It covers: that a real AP-REQ produces a real
session; that the session satisfies `/oauth2/authorize` with no screen drawn;
that the ID Token's `sub`, `amr` and `acr` are the ones read off the ticket;
that `appAuthnMechanism: spnego` on an application entry sends an authorization
request straight to this door instead of to the password screen; that a REPLAYED
AP-REQ is refused and mints nothing (the replay cache is the one check here
whose absence would be a security bug rather than a fidelity one); and that
`krb5.spnegoAuthentication` off answers 403 NAMING THE SETTING and signs nobody
in. Each of those three was mutation-tested against a deliberately broken mock
before it was committed.

**THE BROWSER DOES NOT ANSWER THE CHALLENGE THERE, AND THAT IS A DECISION RATHER
THAN A GAP.** RFC 4559 is answered from GSSAPI, which needs a credential cache
and a host allow-list that the suite cannot assume on the machine it runs on —
so the debugger is the Kerberos client instead, which shows more of the protocol
than a browser handing the work to GSSAPI ever would. What that costs is one
assignment: the `Set-Cookie` arrives at the api relay, and the test carries it
into the browser before driving the application flow. The file's header says so
rather than burying it.

**A REAL-GSSAPI JOB IS NOW POSSIBLE AND IS NOT WRITTEN.** It was impossible
until 2026-08-27 for a reason nothing had noticed: this KDC advertised no
PA-ENC-TIMESTAMP, so no MIT-derived client could get a ticket from it at all —
see *The KDC advertises PA-ENC-TIMESTAMP* in `kerberos/CLAUDE.md`. With that
fixed, `kinit`, `kvno` and `curl --negotiate` complete against this service end
to end, and a browser with a ccache and an allow-list entry would too. Such a
job needs `krb5-user` in the parent's `tests/Dockerfile` and a per-run
`krb5.conf`, so it would SKIP wherever that tooling is absent — which is why it
is not where the only coverage of this door lives.

Still untested at this door: that a ticket for another ACCOUNT's SPN is refused
while one for a host this service answers for is not; that a half-finished
`request-mic` exchange begun at `/spnego/protected` cannot be spent here; and
that exactly ONE authentication is recorded per sign-in rather than a ticket
acceptance beside a session start.


## A KDC PER TRUST REALM, ON THE SHARED PORT 88 (2026-09-15, issue #33)

**The Kerberos realm name inside the request is the discriminator**, and that is
the whole design. Kerberos has realms of its own, every AS-REQ and TGS-REQ names
one, and until this date this service threw that away: one KDC, one principal
database, one `krb5.realm` for the process, pinned to the default trust realm.

**Where the choice is made.** `krb5_kdc.js`'s `routeOf()`, in `handleMessage()` —
the one function both sockets and `/KdcProxy` reach — picks the trust realm and
`realms.run()` answers inside it. Everything downstream then follows without
being told which realm it is in: the settings each handler reads, the database it
looks names up in, and the statistics, audit rows, delegation acts and issuance
gate it records. **Routing at each handler instead would be two places to forget,
and what is forgotten is silent — an answer from the wrong realm's database is a
ticket, not an error.**

**Two doors, two rules.** The sockets and a bare `/KdcProxy` route by NAME, which
is what a client configures (`kdc = …` per realm in `krb5.conf`). A realm's own
`/realm/<id>/KdcProxy` is PINNED to that realm and refuses another realm's name
with `KDC_ERR_WRONG_REALM` (`STS-KRB-0122`): the prefix is an address somebody
chose, so answering a different realm's request on it would make the prefix a
decoration. `krb5_service.js`'s `accept()` follows the same two rules for an
AP-REQ (step 2a), refusing with `STS-KRB-0126`.

**What a realm's context holds, and when it is built.** `krb5_principals.js`
keeps one CONTEXT per trust realm — the realm name, the domain, the SIDs, the
etypes, the kvno, the passwords, the service account, `SEEDS_DEMO`, and the set
of keys its settings configured. The default realm's is built at require time
from the process's values and never rebuilt; another realm's is built when its
Kerberos is turned on and rebuilt when a `BUILT_FROM` setting changes on it. **A
context is put in the map BEFORE its database is built**, because building
registers principals and `register()` asks `current()` for the defaults.

**The exported constants became getters.** `principals.REALM`, `KDC_ETYPES`,
`KVNO`, `USER_PASSWORD`, `SERVICE_DOMAINS`, `AUTO_SERVICE_PASSWORD`,
`DOMAIN_SID` and `seedsDemoPrincipals` answer for the AMBIENT realm, which
outside any realm is the default one — so every caller in six directories reads
the same property and gets the right realm's answer, and the parent project's
in-process jobs see exactly what they saw before.

**The three stores are per realm** (`realms.map()`, which grew the `reconcile`
hook `sharedMap()` had): `krb5.principals`, `krb5.replayCache` and
`spnego.pending`. The last of those fixed a bug rather than only satisfying a
rule — its key is `door|id` with the realm prefix already stripped, so a
negotiation begun under one realm's prefix could be continued under another's.

**Three refusals hold the routing together**, and they are in `realms.js` rather
than here because they are about a realm's OVERRIDES and must be made before
anything is built: Kerberos on with no `krb5.realm` of its own
(`STS-KRB-0123`), a name another realm answers to (`STS-KRB-0124`, compared
without regard to case, including the default realm's and `krb5.trustedRealm`),
and a rename or clear while it is on (`STS-KRB-0125`, because every key in that
realm's database is salted with the name).

**What is still the PROCESS's**, and each for a reason that has not changed: the
two sockets (`krb5.kdcPort`, `krb5.servicePort`), and the development-mode second
realm and its trust (`krb5.trustedRealm` and its three settings). **Trust realms
do not trust each other's Kerberos** — rcbj's decision — so a realm's KDC holds
no `krbtgt/<other realm>` and a service in another realm's domain is unknown
there rather than a referral.

**What has no test yet:** a person keyed in a non-default realm signing in over
SPNEGO end to end (the acceptor's realm routing is asserted in
`tests/kerberos_realm_routing.js` only through the KDC), and two nodes of a
cluster answering for the same non-default realm.

## PRODUCT MODE, AND THE LITERALS AN AUDIT FOUND IN THIS DIRECTORY (2026-09-12)

**The DEFAULT realm's principal database is built at REQUIRE TIME in the mode the
PROCESS starts in, and that is captured once as `ctx.SEEDS_DEMO`.** Its long-term keys
are material derived at startup — the kind `common/CLAUDE.md` says must never be marked
runtime — so switching the process's mode later adds and removes no principal there.
**Another trust realm's is built when its Kerberos is TURNED ON (2026-09-15), in THAT
realm's mode**, and rebuilt when a setting it was built from changes on that realm —
`global.mode` among them, because a realm's settings are exactly what may change under a
running process. `realmsServed()` and `realmForService()` read the same captured value as
the database they belong to, so the two cannot disagree.

**What product mode (`mode.seedsDemoData()` false) does NOT create**: every entry in
`DEFINITIONS` below `krbtgt` — alice, bob and the five misconfigured users, the
computer account, the four delegation services with their literal passwords and their
`msDS-*` rules — and the whole second realm (`TRUSTED_DEFINITIONS`, the trust). The
realm list is then one realm, so `PARTNER.COM` is `KDC_ERR_WRONG_REALM`.

**What it creates, and the one refusal each carries.** `krbtgt/<realm>` and the account
`krb5.servicePrincipal` names — each ONLY where its password is not the value the
settings table publishes (`publishedDefault()` reads the row's `dflt`, so the literal
is written once). A krbtgt from `krbtgt-mock-password` is a golden ticket handed out in
the README; a service key from `service-account-password` is a silver one. Refused, the
reason is carried by `serviceAccount()` / `krbtgtUnavailableReason()`, the acceptor puts
it in its refusal, and `GET /krb5/service` and `GET /krb5/principals` publish it.

**A PRODUCT KDC AUTHENTICATED NOBODY UNTIL LATER THE SAME DAY, AND NOW IT AUTHENTICATES
THE DIRECTORY'S PEOPLE.** This paragraph read: *nothing is created on demand, no fixture
user exists, and the directory's people are not given Kerberos accounts. The product use
of this directory is the ACCEPTOR … Giving directory people principals is
`common/mode.js`'s `kerberos-keys` row.* The first two clauses still hold; the third is
the section below. The acceptor use is unchanged, with one addition: a keytab minted at
`/admin/kerberos/principals` for `krb5.servicePrincipal` keys the acceptor with a random
key instead of `krb5.servicePassword` and `krb5.serviceSalt`.

**`krb5.servicePrincipal` IS WHAT THE ACCEPTOR'S ACCOUNT IS MADE FROM, IN EVERY MODE.**
It was the fixture `['HTTP', 'web.' + DOMAIN]` whatever the setting said, while
`krb5_service.js` looked for the setting — invisible at the defaults, where the two
agree. `configuredServiceDefinition()` builds the account from the setting and, at the
defaults, REPLACES the fixture entry in place with a definition identical field for
field (same salt convention, password, `okAsDelegate`, description), so a development
database is byte-for-byte what it was. When the names differ the fixture stays beside it,
because the delegation cases name it. `ok-as-delegate` is on only where the fixtures are.

**Settings that replaced literals** (defaults unchanged): `krb5.enctypes` (validated
against the vendored codec — an unimplemented number is FATAL at startup rather than
silently dropped), `krb5.kvno` (rotation is not modelled), `krb5.ticketLifetimeSeconds`,
`krb5.renewLifetimeSeconds`, `krb5.logonServer`, `krb5.maxRequestBytes` (the KDC's
inbound TCP cap — the old `MAX_REPLY_BYTES` name described a different limit from the one
it enforced), `krb5.udpMaxReplyBytes`, `krb5.serviceMaxTokenBytes`,
`krb5.replayCacheMaxEntries`, `krb5.spnegoPendingTtlSeconds`, `krb5.spnegoMaxPending`.

**THE PAC INVENTS NOTHING IN PRODUCT MODE WHERE [MS-PAC] PERMITS.** `passwordLastSet`
(authtime minus thirty days) becomes the zero FILETIME — there is no "never" encoding
for that field the way there is for PasswordMustChange — and `logonCount` becomes 0.
`passwordMustChange: 2020-01-01` is on the `expired` fixture, which product mode does
not create.

**`GET /krb5/principals` WITHHOLDS BOTH PASSWORDS unless the database was built with
fixtures AND the ambient realm opens test controls** — both, because a development realm
inside a product process must not publish the process's passwords. They are replaced by
a sentence rather than omitted. `notImplementedYet` said PAC, cross-realm referrals,
S4U2Self and S4U2Proxy for as long as all four had been implemented; it names FAST,
PKINIT, kpasswd, user-to-user, SID filtering and key rotation now.

**Two bugs wrong in every mode, fixed unconditionally.** Every listener here bound the
literal `'0.0.0.0'` rather than `global.host` (the UDP socket is `udp6` for an IPv6
address). And **the acceptor's replay cache FORGOT an Authenticator still inside its
window** when it passed its cap — `pruneReplayCache()` deleted the oldest entries on the
stated grounds that they "cannot be replayed anyway", which was true only of the entries
the loop above had already removed. An attacker holding a captured AP-REQ needed only
enough fresh valid Authenticators to push it out, and development mode gives anybody a
ticket. The cap now REFUSES the next Authenticator (`KRB_ERR_GENERIC`, naming the
setting) and prunes only by the window, whose 2 × skew bound is exactly sufficient.

**AN ON-DEMAND RID IS DERIVED FROM THE NAME (later the same day), and this paragraph
described two allocators before it.** A counter restarted at 5000 in a process whose
persisted `principals` store came back holding 5000 — two accounts, one SID. Its
replacement read one above the highest RID in the database, which fixed a restart and not
a second PROCESS: two processes creating accounts in the same instant both read the same
highest RID, and the paragraph said so and called the fix "a coordinated write". It is
`autoRidFor()` now — SHA-256 of `name@realm` into **[5000, 2^30)** (2^30 being Active
Directory's RID pool, so the SID is one a real domain could issue and nothing reading it
signed sees a negative), with a linear probe past any slot a DIFFERENT principal already
holds. Two processes creating the SAME name agree with no coordination; an existing account
is never renumbered (every caller asks only when creating, and `directoryUser()` keeps the
RID of a record it replaces); a configured RID cannot be produced. **The residual** — two
different names meeting on one slot in ~1.07 billion within one replication window, about
n²/2.1e9 for n first creations inside it — is stated in the comment above `autoRidFor()`
and judged not material enough for a `common/mode.js` row: runtime-made accounts in product
mode are directory people's first Kerberos sign-ins, and a restored or replicated
runtime-made row whose RID another principal holds is LOGGED (`STS-KRB-0114`) rather than
silent. **A collision the old allocators already made is not repaired** — renumbering would
change a SID already in somebody's ticket or ACL — and is reported by that same code the
next time the row is restored.

**NO NEW REQUIRE REACHES THE PARENT PROJECT'S COPY SET.** `krb5_kdc.js`, `krb5_service.js`
and `spnego_exchange.js` now require `common/mode.js` and `common/config.js`, both already
in that closure through `common/helpers.js`.

**A RESTORED PRINCIPAL NO LONGER OVERRIDES THE SETTINGS (later the same day), and this
paragraph called that "one thing this cannot fix from here".** It read: *a restore SETS
each stored row over the one `buildDatabase()` just registered — so a changed
`krb5.servicePassword`, `krb5.enctypes` or `krb5.kvno` does not take effect for an account
that is already in the store. That is `realms.sharedMap()`'s restore semantics and
`persistence/`'s to decide.* It was worse than that sentence: a process whose settings no
longer CREATE an account — product mode after a development run, a krbtgt refused for its
published password, a renamed SPN — had it put back with the password it was written with.

The fix is at the boundary both doors reach. `realms.sharedMap()` takes a `reconcile`
option (`common/realms.js` argues it) that its `restore` and `remove` accessors ask first —
and those two accessors are what `persistence_minted.js`'s startup restore AND its
replication applier call, so another process's write obeys the rule exactly as a restart
does. `krb5_principals.js`'s `reconcileRestored()` / `reconcileRemoved()` are the rule:

* **A CONFIGURED principal** (`CONFIGURED_KEYS`, filled by `registerConfigured()` in
  `buildDatabase()`) keeps every field its settings built and takes only `RUNTIME_FIELDS`
  from the row. **That list is ONE field, `signedOutAt`, and it is a finding**: every write
  to a configured principal after startup is `signOut()` or `clearSignOut()`; `revoked` is
  set only by the `locked` fixture's definition. A difference in anything else is logged as
  `STS-KRB-0111`, by field NAME and never by value. **A field that becomes runtime state
  later is a row in `RUNTIME_FIELDS` in the same commit as its first writer**, or a restart
  silently undoes that writer's work.
* **A RUNTIME-MADE principal** (`autoCreated`, or a `directoryKeys` person) is restored
  WHOLE — the store is its only source. That includes the shared development password an
  auto-created account was made with, so changing `krb5.userPassword` does not reach one
  already in a store; in practice only a dispatched development run persists these, and it
  does not persist them across a restart.
* **Any other row is NOT restored** (`STS-KRB-0112`) — it claims to be configured and these
  settings do not configure it.
* **A stored REMOVAL of a configured principal is refused** (`STS-KRB-0113`).
* **Nothing is written back.** A stale stored row is corrected by the next write of that key
  (a sign-out writes the whole record this process holds); rewriting from inside the applier
  would be two processes with different settings exchanging one row for ever.

`tests/kerberos_product_mode.js` holds the audit's claims, in child processes where the
claim is about how the process was started; mutation-tested against the replay refusal
removed, the RID probe removed, and (through `ldap_tls_product_mode.js`) the listeners'
bind address. **`tests/kerberos_principal_store.js` holds both of the fixes above**: the
rule at the accessors in process, the two real doors (`minted.restore()` and
`minted.applyChange()`, over sealed rows) in a product-mode child with a changed
`krb5.servicePassword` and `krb5.serviceSalt` and a development fixture left in the store,
and the RID asked of a second process. Sixteen mutants across it, `common/realms.js` and
`krb5_principals.js`, all caught — one (the probe counting a name's own record as taken)
only after the fixture asked about an account sitting on its own slot.


## STORED LONG-TERM KEYS: A PERSON'S FROM THEIR PASSWORD, A SERVICE'S AT RANDOM (2026-09-12)

Two NEW files and neither is vendored: **`krb5_person_keys.js`** (the register — derive,
store, read for the KDC, service principals, the lists) and **`krb5_keytab.js`** (an MIT
keytab 0x502 writer and reader; this repository had no keytab code before, reader or
writer, so there was nothing to reuse and the test carries an independent reader). The
directory's count above is sixteen files now.

**THE PROBLEM WAS STRUCTURAL.** A person's password is a scrypt hash on their entry, and
RFC 3961 string-to-key needs the plaintext. So the keys are derived at the two moments
`common/credentials.js` holds one — a password SET, and a password VERIFIED — and stored,
SEALED, on the person's own entry: `stsKrb5Keys` (one value: name, realm, kvno, salt, a
stamp of the password hash, and every enctype's key) and `stsKrb5KeyInfo` (the public
half). Six things about it are decisions:

* **THE ASYNC SHAPE.** `setPassword()` and `verify()` are synchronous and string-to-key is
  Web Crypto PBKDF2, so the observer QUEUES a derivation, chained per person, and returns.
  The keys lag the password by tens of milliseconds, and the KDC refuses the person in that
  window rather than keying them from anything older — which is what the STAMP makes true
  whichever door changed the password (an `ldapmodify` of `userPassword` included, which the
  observer never sees). A failed derivation is `STS-KRB-0107`, logged and audited, and never
  touches the sign-in it observed. `idle()` settles every derivation for a caller that has to
  know.
* **THE KVNO.** A first key starts at `krb5.kvno`; a new password is the stored kvno plus
  one; the SAME password adding enctypes keeps its version. A service principal starts at
  `krb5.kvno` and a Rotate adds one. `krb5.kvno` therefore means two things now and the
  settings row says both: the fixed version of every account built from a password in the
  configuration, and the STARTING version of a stored key.
* **ONE SEALED VALUE, NOT ONE PER ENCTYPE.** The authentication tag covers the name and the
  stamp beside the keys, so a value copied to another entry names the wrong person and one
  kept past a password change carries the wrong stamp. While keys persist a CLEAR value is
  refused, so an `ldapmodify` cannot plant a key of its choosing.
* **THE TRUST REALM IS THE AMBIENT ONE (2026-09-15).** This read *THE TRUST REALM IS THE
  DEFAULT ONE … the directory slot `ldap_server.js` fills is pinned to the default realm, and
  a password set in another realm derives nothing. This is NOT per-realm Kerberos*. It is
  now: the slot's six hooks lost their `inDefaultRealm()` wrapper, the observer's gate is
  `principals.enabledIn()` rather than `realms.isDefault()`, and a password set in a realm
  whose Kerberos is ON derives keys onto that person's entry in that realm's own subtree,
  salted with that realm's Kerberos realm. A realm with no KDC still derives nothing, for
  the same reason as before: keys nothing reads are password-equivalent material for
  nobody.
* **NOTHING IS SHOWN.** Both key attributes are withheld from the directory dump and from an
  LDAP search (ciphertext included), from `applications.view()`, from `/admin-api` and from
  the audit log. A service key leaves this service ONCE, as the keytab the create or rotate
  hands over; nothing reads a stored key back out.
* **THE PRINCIPAL IS A RECORD AND THE KEYS ARE NOT.** A person the KDC resolves from the
  directory is registered in `principals` (so a sign-out stamps it, the TGS handler finds it
  and `/krb5/principals` lists it with `directoryKeys: true`) with NO PASSWORD — the shared
  development password left on the record would be a second key for every person — and the
  keys go into the non-enumerable cache, refilled from the source on every AS lookup. A
  stored SERVICE key is not registered: it is built over the configured account, if any, per
  lookup, and `krbtgt/*` is never asked.

**THE SLOTS, AND RULE 3e.** `krb5_principals.js` offers `setKeySource()` and this module
fills it; `common/credentials.js` offers `setPasswordObserver()` and this module fills it;
this module offers `setDirectory()` and `ldap/ldap_server.js` fills it. A require from the
principal database to the register would close a cycle (the register requires it) and move
every `/ldap` route (the register reads the directory) — and, the reason that is particular to
this directory, **it would put `common/credentials.js`, `common/keystore.js` and the
directory into the parent project's COPY set**. A require from `common/credentials.js` would
be `common/` reaching into `kerberos/`, the layering inversion `common/CLAUDE.md` exists to
prevent.

**NO NEW REQUIRE REACHES THE PARENT PROJECT'S COPY SET.** `krb5_kdc.js`, `krb5_service.js`
and `spnego.js` gained no require; `krb5_principals.js` gained a slot and no require. The
new modules are required by `ldap/ldap_server.js` and the two `admin-core/` halves only. A
parent in-process job loads a KDC with no key source, which in development behaves exactly
as it did (and in product refuses a person with a sentence naming the missing source).

**`/admin/kerberos/principals`** is the console page and `GET /admin-api/kerberos/principals`
+ `POST /admin-api/kerberos/principals/{create-service,rotate-service,delete-service,
clear-person-keys}` its twins (rule 7). `admin-ui/CLAUDE.md` argues the page.

`tests/kerberos_person_keys.js` holds it: RFC 3962 Appendix B through the derivation path,
the keytab against an independent reader, development unchanged, and — in a product-mode
child — a real AS-REQ succeeding with the right password and failing with a wrong one, the
shared development password refused, a person with no keys refused with the sign-in-once
e-text, the upgrade on a verify, a password change moving the kvno and refusing the old
password, a password written behind the observer refused as stale, a copied sealed value
refused with the stamp matching, a planted clear value refused, no key in an audit row or a
view, and a service principal created, its keytab read independently, a ticket for it issued
by the KDC and accepted by the acceptor, rotated, and deleted. Sixteen mutants, all caught
(see `tests/CLAUDE.md`).

**What is still not done**, recorded where it bites: a superseded derivation abandoning
itself is not asserted by any test. (This paragraph also listed the LDAP add/modify door,
which since the same day reaches the observer through `credentials.passwordWritten()`, and
old kvnos not being retained, which is the section below.)

### PREVIOUS KEY VERSIONS: A PASSWORD CHANGE OR A ROTATION NO LONGER STRANDS A TICKET (2026-09-12)

Until this, a rotation or a password change threw the old key away in the write that stored
the new one, so a ticket issued an instant earlier was refused `KRB_AP_ERR_BADKEYVER` at its
very next use. A real KDC keeps the previous kvno in its database and a service keeps it in
its keytab until those tickets have expired; this is that, bounded twice.

* **WHERE THEY LIVE: INSIDE THE SAME SEALED VALUE, as `previous`, not in a companion
  attribute.** One authentication tag over the current keys and every kept version, so a
  version cannot be planted back beside a newer current key or left behind on another
  entry; one write, so there is no moment holding the new key and no previous version (or
  the reverse); and no schema change — the two key attributes are already withheld, sealed
  and on the rows a sighting preserves. `RECORD_VERSION` stays 1: `previous` is optional. The
  PUBLIC info attribute gains `retained` — kvno, enctypes, `retiredAt`, `expiresAt`, never a
  key — which is all a page lists.
* **THE BOUNDS.** `krb5.retainedKeyVersions` (default 1, 0 keeps none) and
  `krb5.retainedKeyTtlS` (default 0 = `krb5.ticketLifetimeSeconds` + `krb5.clockSkew`: no
  ticket here outlives its lifetime, a renewal needs an unexpired ticket and re-seals under
  the current key, and an acceptor tolerates the skew on its end time). A version's expiry is
  the EARLIER of the one stamped when it was retired and its retirement plus the lifetime in
  force NOW, and the count is re-applied, **at every read as well as every write** — so a
  lowered setting ends windows at the next request and a raised one resurrects nothing. What
  is past a bound is never used, never listed, and removed from storage at the next write of
  that key.
* **A KEPT VERSION ONLY OPENS A TICKET ALREADY SEALED UNDER IT.** The key source hands kept
  versions over BESIDE the current keys; `krb5_principals.js` attaches them non-enumerably as
  `retainedKeys` and never into `keys`, which is the cache pre-authentication and every
  issuance read. The one reader is `retainedKeyFor(principal, etype, kvno)`, asked by
  `krb5_kdc.js`'s `ticketKeyFor()` (the ticket in a TGS-REQ, and an S4U2Proxy evidence
  ticket) and by `krb5_service.js`'s acceptor. **So the KDC always issues under the current
  kvno and an old password never signs in.** A stored-key principal presented with a kvno
  that is neither current nor kept is refused 44 — `STS-KRB-0115` at the KDC (new, and the
  KDC never checked a kvno before), `STS-KRB-0068` at the acceptor as before. **A principal
  built from a password in the configuration is unchanged at the KDC**: its key does not
  change with its number, the KDC never refused on that number, and `ticketKeyFor()` answers
  its current key whatever kvno a ticket names.
* **`find()` READS A DIRECTORY PERSON AGAIN** before answering, because the record's key
  cache holds whatever the LAST AS lookup found — without it a TGS naming a person issued or
  decrypted under the kvno before their password change.
* **THE OUTGOING RECORD IS READ AT THE WRITE**, not before the derivation: an operator's drop
  may land in between, and retiring from the earlier read would put back what was dropped.
  The re-read and the write have no await between them.
* **A ROTATION'S KEYTAB CARRIES EVERY KEPT VERSION**, current first, as MIT's `ktadd` without
  `-k` leaves one; the reply's `keytabKvnos` and `retained` say which and until when.
* **"DROP PREVIOUS VERSIONS"** — `drop-previous-service-keys` and
  `drop-previous-person-keys`, a row button on `/admin/kerberos/principals` drawn only while a
  version is kept, and the same two operations on `/admin-api` (rule 7) — rewrites the record
  with `previous` empty and the current key untouched, audited as
  `admin.krb5.previous.dropped`. Nothing kept is `dropped: 0`; a record this process cannot
  open is refused rather than rewritten.
* **WHAT IT DOES NOT COVER.** `krbtgt` has no rotation here (its key is the restart-only
  `krb5.krbtgtPassword` at a fixed kvno), so the TGT path consults kept versions only for the
  stored-key principals that have them; a TGT under an older krbtgt password is still
  refused. And the principal's own check in `retainedKeyFor()` against the clock duplicates
  the source's (mutant M4 below survives because of it, deliberately).

`tests/kerberos_person_keys.js` sections 5 holds it in the product child with real AS-REQs,
TGS-REQs and AP-REQs: a TGT and a ticket sealed under a person's key both still accepted
after a password change, the old password refused, issuance at the new kvno, the count bound
(kvno 3 refused 44 once 4 and 5 exist), the lifetime bound (a one-second override refuses,
clearing it restores), drop-now refusing 44 while the current sign-in works; and for a
service, the rotation keytab holding both kvnos with the create's own kvno-3 keys, the
acceptor and the TGS accepting kvno 3 and 4, a second rotation keeping only 4, and drop-now
refusing 4 while 5 is accepted. Sixteen mutants, fifteen caught; **M4 (the principal-side
expiry check removed) survives** because the source filters by the same clock in the same
synchronous call — a belt-and-braces guard, recorded rather than counted. Untested: the
S4U2Proxy evidence path under a kept version, and a drop racing a derivation.

---

## THE REPLAY CACHE ACROSS THE CLUSTER (2026-09-14, #46) — capability `kerberos.replay-cache`

`replayCache` is a persisted `realms.sharedMap()`, which REPLICATES: a captured
AP-REQ delivered to a second node inside the replication window found an empty
cache there and was accepted — and with a load balancer or DNS round-robin on
the service name, delivery to another node is the default, not the attack.

`accept()` step 7 now keeps the cache check (and the full-cache refusal) first,
sets the entry before any await, and then SPENDS the Authenticator's
(client, ctime, cusec) key through `cluster/cluster_claims.js` (scope
`krb5.authenticator`, `realm: ''` — the acceptor has no realm, like the cache).
**The claim is inside `accept()` because that is the async boundary**: it is
already asynchronous (every decryption is awaited), it is the one place any
transport accepts a ticket — the raw socket and both SPNEGO doors — and it comes
after every other check, so a bad ticket takes no slot. The claim lives
`2 × krb5.clockSkew` (the cache's own window) plus 60 s of clock disagreement.
A replay seen by another node is `KRB_AP_ERR_REPEAT` with `STS-KRB-0116`; a store
that cannot be asked is refused `KRB_ERR_GENERIC` with `STS-KRB-0117` **and the
local entry is forgotten**, because an Authenticator refused unproven was not
used and its retry is not a replay. `tests/cluster_single_use_protocols.js`
section 4 holds all three, with the empty-store control.


## A SIGN-OUT INSTANT ON ANOTHER NODE (2026-09-14, #46 section 4)

`signedOutAt` is a field of a replicated `krb5.principals` row, so a TGS-REQ
that DNS round-robin sent to a node which had not yet applied a sign-out
committed elsewhere was answered from a copy without the stamp, and the
signed-out ticket was honoured. Every HTTP request is held to the cluster
barrier; these raw TCP and UDP sockets are not the express app. So
`handleMessage()` now calls `catchUpWithCluster()` before an AS-REQ or a
TGS-REQ: in active-active mode, with `logout.kerberosSignOut` on, it awaits
`cluster_barrier.syncShared()` — the barrier's rule 1, one shared read of the
change log's head — and a barrier that gave up is logged (`STS-KRB-0118`) and
the request answered anyway. The sign-out itself is HTTP, so its answer is held
until the stamp commits; a TGS-REQ that follows it on any node sees it. MS-KKDCP
goes through the same dispatcher and is already behind the HTTP barrier; the
second shared read costs nothing.

**What is left is a race, not a window**: an AS-REQ CLEARS the stamp by writing
the whole principal back, and one that caught up just before a concurrent
sign-out on another node committed can land its clear after that stamp — last
writer wins on the row, which is issue section 3's. **`signedOutAt` survives
`reconcileRestored()`**, which the issue left unverified: it is the one member
of `RUNTIME_FIELDS`, so a configured principal takes it from the incoming row
and a runtime-made one is restored whole.

The two requires are LAZY and guarded. `cluster/cluster_barrier.js` is already
in the parent project's COPY closure through `common/app.js`, and
`cluster/cluster.js` with it (the barrier requires it lazily); if that set does
not carry `cluster/` yet, it is the directory already owed above, not a new
line. Not measured on a live pair: the sign-out probe in `ldap/CLAUDE.md` ran
against LDAP only.
