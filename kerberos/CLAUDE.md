# kerberos/

Kerberos v5 — a KDC on raw TCP and UDP 88 and over MS-KKDCP, a Kerberos-protected
service, and the same acceptor over HTTP as SPNEGO (RFC 4559/4178). Twelve files,
and they divide into three groups.

**The codec**, which knows nothing about this service: `krb5_primitives.js`,
`krb5_asn1.js`, `krb5_crypto.js`, `krb5_messages.js`, `krb5_ndr.js`,
`krb5_pac.js`, `krb5_gss.js`. They require only each other and bunyan, so they
load in a test with no configuration at all — which is what the guarded
`require(process.env.CONFIG_FILE)` at the top of each is for.

**The service**: `krb5_principals.js` (the principal database and every long-term
key in it), `krb5_kdc.js` (AS and TGS, plus `/KdcProxy` and `/krb5/principals`),
`krb5_service.js` (the acceptor).

**`krb5_spnego.js` is VENDORED** — a byte-identical copy of the parent project's
`common/krb5/krb5_spnego.js`, kept honest by `tests/krb5_codec_sync.js` over
there. It is NOT in `../common/vendored/` with the other five, because it belongs
to the codec it sits beside and moving it would put half the Kerberos wire format
in a directory that has nothing else Kerberos in it. **Do not edit it here.**

**`spnego.js` must stay after `krb5_service.js` in the require order**, and that is a
dependency rather than a preference: it calls that module's `accept()` for every
Kerberos check and adds none of its own. It is also the one Kerberos module that
starts NOTHING — it is HTTP all the way down, so requiring it is the whole of its
installation. Note the naming: `krb5_spnego.js` beside it is the VENDORED RFC 4178
codec (a byte-identical copy of the parent project's `common/krb5/krb5_spnego.js`,
kept honest by `tests/krb5_codec_sync.js` there), and `spnego.js` is this repo's own.
Do not merge the two — one of them is somebody else's file.

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
into its image. **The 2026-08-23 reorganisation broke both**, because they name
flat paths (`sts/krb5_kdc.js`). Nothing was changed in that repository; what it
needs is written down in `docs/parent-project-migration.md`, and it has to land
together with the `sts/` gitlink bump.

`MOCK_STS_DIR=/path/to/mock-sts` still points those tests at a working copy, and
it will keep working once `mockStsModule()` knows about the subdirectories.

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

