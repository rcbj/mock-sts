# logout/

The protocol-independent sign-out. One file:

| File | What it is |
|---|---|
| `logout.js` | `GET|POST /logout` — the model of what a live session IS across every family, the inventory, the termination, and the page. |

It is a directory of its own rather than a file in `authn/` or in `common/`, and
each of those was considered:

* **Not `common/`.** That directory's entry test is *more than one family needs
  it*. This is the opposite shape — one module that needs EVERY family — and a
  `common/` file requiring `kerberos/` and `ldap/` would be the layering
  inversion `common/CLAUDE.md` says it exists to prevent. It is the same
  argument that keeps `delegationPolicy()` in `krb5_principals.js`.
* **Not `authn/`.** That directory owns the session and its two modules are the
  two halves of ONE ceremony, required 8th. This one is required SECOND TO LAST
  because it reads nine modules, and two files of one directory sitting at
  positions 8 and 23 in the require order is exactly the kind of thing this
  repository documents obsessively rather than the kind it should create.
  Signing in and signing out are also not one act: one is a protocol module's
  dependency and the other reaches across all of them.

---

## What it is for

Every family here that can sign somebody IN has a sign-out of its own, and each
signs them out of ITSELF:

```
/oauth2/logout          OpenID Connect RP-Initiated Logout
/wsfed?wa=wsignout1.0   WS-Federation 1.2 section 13.2.4
/saml2/slo              SAML 2.0 Single Logout
```

None of them is the question a person arrives with, which is *what am I still
signed into, and how do I stop being signed into it*. That question is
protocol-independent and so is this answer: ONE list of everything this service
is still holding for one identity, a checkbox against each, and — by default — a
button that ends all of it.

**It is the same shape `common/delegation.js` takes and for the same reason.**
Eight delegation mechanisms in three families collapse to one model because the
question is protocol-independent. So does this one.

---

## Rule 3m: it is a route module that holds NO state, and that is the rule to keep

Every row is read live from the module that OWNS that thing, and every
termination is a call into that same module:

| Family | Read from | Ended by |
|---|---|---|
| Browser sign-on session | `authn.js` | `authn.endSessionById()` |
| OIDC relying parties | `frontchannel_logout.js`, off the session | forgotten there, notified by iframe |
| WS-Federation realms | `wsfed.cleanupTargetsFor()` | forgotten, cleanup image |
| SAML 2.0 service providers | `saml2_sso.logoutTargetsFor()` | forgotten, LogoutRequest link |
| Tokens | `admin_stats.js` | `stats.revoke()` — the ONE revocation set |
| Authorization codes | `oauth2.outstandingCodesFor()` | `oauth2.dropCode()` |
| Pre-authorized codes | `vc_offers.preAuthorizedCodes` | deleted there |
| Directory connections | `ldap_server.boundConnections()` | `ldap_server.dropConnectionsFor()` |
| Kerberos tickets | `krb5_principals.signedOutAt()` | `krb5_principals.signOut()` |
| Everything already issued | `admin_stats.js`'s artifacts | **nothing can** |

**A cache here would be a second answer to "is this still live", and the wrong
half of it would be the half on the page somebody is about to act on.** That is
the one-store rule the revocation set already keeps, applied to nine stores at
once.

## It is a plain require of everything and needs no slot — except one

Rule 3e's test: a slot is what you reach for when a require would close a cycle
or move a route. Neither applies to the nine requires at the top of `logout.js`,
because `server.js` requires this module SECOND TO LAST — after every one of
them, before `sts_metadata.js` — so each is a cache hit that registers nothing,
and nothing in this service requires this file back.

**The one exception is `admin.js`, and it fails the test BOTH ways round**,
which is why `setLogoutReader()` exists and is the console's sixth slot. This
module requires `ldap_server.js`; `ldap_server.js` requires `admin.js`; so
`admin.js -> logout.js -> ldap_server.js -> admin.js` is a cycle, and it would
also drag every `/ldap` route into the router ahead of the console's own. The
slot carries ONE object — `FAMILIES`, `inventoryFor`, `terminate` — validated
whole at install time, because a partial one would leave `/admin/logout` listing
what is live and unable to end any of it.

**Do not add a second slot for a family added later. Add a row to `FAMILIES`.**

---

## Six things that are load-bearing

**A FAMILY IS ONE ROW IN `FAMILIES` AND THAT IS THE EXTENSION POINT.** Each
carries `collect(ctx)`, optionally `terminate(row, ctx)`, `endOrder`, and the
prose three surfaces print. A new protocol that grows a session is one entry.

**THE READING ORDER AND THE ENDING ORDER ARE NOT THE SAME ORDER**, and that cost
a silent bug the first time this ran. `FAMILIES` is in the order a person should
READ — the session first, because everything else hangs off it or was issued by
it. Ending in that order destroys the session BEFORE the relying parties,
service providers and clients whose lists live on it, so the first global logout
ended the session and then found nobody to notify: every federated partner went
on believing the person was signed in, and the page said so in a way that looked
like there had simply been nobody to tell. `endOrder` is the fix — federated
lists first, credentials next, **sessions last** — and a family added without one
sorts to the end, which is safe for anything that does not depend on a session
and wrong for anything that does. **State it.**

**WHAT CANNOT BE ENDED IS LISTED ANYWAY, WITH THE REASON.** A SAML assertion in
a service provider's hands, a Kerberos service ticket in a cache, an X509-SVID
already minted: none can be recalled, by this service or by a real one, because
nothing consults the issuer when they are presented. **Filtering those off the
page would make a global logout look complete when it is not**, which is the
single most misleading thing this endpoint could do. They are rows with no
checkbox and a sentence — the same decision `/admin/sts-metadata` makes about
coverage notes.

**THE DEFAULT IS GLOBAL.** A POST that selects nothing ends everything.
`/admin/logout`'s `end` action is the ONE place that differs — an empty
selection there is refused — and the difference is intent: an empty form is a
reader who ticked nothing, an empty body at `/logout` is a caller asking for
everything.

**A CREDENTIAL NEVER APPEARS IN A ROW ID.** An authorization code and a
pre-authorized code are redeemable for tokens, so a row's handle is
`sha256(code)` truncated and the value stays in this module. `inventoryFor()`
strips `secret` before returning. A code in a form field is a code in a browser
history; a code in a JSON reply is a code in a log.

**IDS ARE RE-RESOLVED AT TERMINATION AND NEVER TRUSTED FROM THE FORM.** A page
can be posted an hour after it was drawn. Acting on the list it carried would end
something that has since been reissued under the same id.

---

## Three surfaces, one behaviour

| Surface | Who | Gate | Difference |
|---|---|---|---|
| `GET|POST /logout` | a person, about themselves | none | defaults to the session cookie; **renders the notifications**, because they are iframes in that person's browser |
| `GET|POST /admin/logout` | an operator, about somebody | Admin Read / Admin Write | always names a `user`; filters, pages, and has the two **NON-SPEC undos** |
| `GET|POST /admin-api/logout[/{action}]` | a test | none | the same two functions; four actions |

The console and the API call `admin.js`'s `logoutView()` / `logoutAction()`,
which call this module — rule 7, which is what makes them one behaviour rather
than three.

**`/logout` needs no console role, and that is not an oversight.** Signing
yourself out must not require a role that signing in did not.

**`logout.anyUser` is on by default** and lets `?username=` name somebody else.
It grants nothing that was not already true: no sign-in screen here checks a
password, so anybody who can reach this port can BECOME that person in one
request and log themselves out. What it buys is a headless test.

---

## What a logout reaches, protocol by protocol — and what it does not

Two of these mechanisms did not exist before this feature and are argued where
they live rather than here:

* **Kerberos** — `krb5_principals.js`'s `signedOutAt`, checked in
  `krb5_kdc.js`'s `handleTgsReq()`. A TGS-REQ whose ticket `authtime` predates
  the instant is refused **KDC_ERR_TGT_REVOKED (20)**. It is on `authtime` and
  not on the issue time because a RENEWED ticket preserves authtime, and
  checking anything else would let a renewal launder a signed-out ticket. **It
  does not reach a service ticket already in a cache** — accepting one never
  contacts the KDC — and an AS-REQ still succeeds and CLEARS the instant,
  because signing out is not being locked out. See `kerberos/CLAUDE.md`.
* **LDAP** — `ldap_server.js`'s connection list. RFC 4511 section 4.2 makes the
  bind the authorization state of a CONNECTION, so the connection is the session
  and closing it is the only sign-out the protocol has. `destroy()` and not
  `end()`: a client mid-search can hold a half-closed socket open for as long as
  it likes. An UNSOLICITED NOTICE OF DISCONNECTION would be the polite form and
  node-ldapjs cannot send one — it is a submodule used unmodified. See
  `ldap/CLAUDE.md`.

And one that is a whole specification: **OpenID Connect Front-Channel Logout
1.0**, in `oauth-oidc/frontchannel_logout.js`. See `oauth-oidc/CLAUDE.md`.

**SPIFFE is deliberately absent from `FAMILIES` and that is an answer rather
than a gap.** A SPIFFE identity is a WORKLOAD, attested per call and holding no
session; an SVID already minted cannot be recalled any more than an assertion
can. The registry CAN end an identity's ability to obtain another one, and that
is a ban rather than a logout — a different claim, made at `/admin/spiffe`.

**OID4VP presentation transactions are absent for a different reason**: they
carry no user. The Verifier does not know who will present until a presentation
arrives, so a transaction cannot appear in a per-person inventory without
inventing a link that is not there.

---

## `liveSessions()` — the same question asked across everybody (2026-09-04)

`inventoryFor()` answers *what is alice still signed into*. `liveSessions()`
answers the other half — *who is signed in at all* — and it is what
`/admin/sessions` and `GET /admin-api/sessions` draw.

**It is HERE and not in `admin-ui/admin.js` because this module is the one model
of what a live session is.** That is this directory's whole reason to exist, and
a console page that walked `authn.sessions`, `ldap_server.boundConnections()`
and the ticket register itself would be a SECOND answer to *is this still live* —
the thing rule 3m forbids. It matters more on that page than on `/admin/logout`
because of the button: a Revoke drawn from one reading and performed by another
acts on something other than the row it sits beside. The button therefore calls
`terminate(key, [id])`, the same function a global logout goes through, with a
selection of one — same audit row, same settings honoured, same refusals.

**THREE OF THE TEN FAMILIES HAVE A SESSION AND THE OTHER SEVEN DO NOT**, and the
distinction is the page's whole subject rather than a simplification. A session
is state THIS SERVICE holds that makes somebody currently authenticated; a
token, an assertion, a code and an SVID are things it has HANDED OUT, they
outlive every session here, and they are `/admin/tokens`. The three:

| Family | Why it is a session | How its expiry is worked out |
|---|---|---|
| `session` | the cookie from `/authn/login`, which every browser family here shares | ABSOLUTE, fixed when it was created, and **not extended by use** — there is no idle timeout in this service |
| `krb5` | a TGT IS the Kerberos session; a service ticket is one use of it (`recordTicket()` says so in as many words) | the `endtime` the KDC sealed INTO the ticket, which nothing here can move |
| `ldap` | RFC 4511 section 4.2 makes a Bind the authorization state of a CONNECTION | **none** — it lasts until the next Bind, an Unbind, or the socket closing |

`SESSION_EXPIRY_RULES` carries those three sentences and they travel on the row
and in the API reply, because `expiresAt: 0` means *no expiry* and not *the
epoch*, and a column of bare timestamps would be read as one rule with three
values.

**A KERBEROS ROW'S `id` IS THE PRINCIPAL'S AND NOT THE TICKET'S**, so several
rows can share one. That is Kerberos rather than an approximation: this KDC can
stamp a sign-out instant on a principal and nothing finer exists, so ending
"this TGT" refuses every TGT that principal authenticated before now and still
reaches no service ticket already in a cache. Every row's `why` says which of
the three acts its button performs, on rows that CAN be ended as well as on
rows that cannot — the Kerberos one is the case where the button does MORE than
the row it is on, and a control that quietly did that would be worse than no
control.

An anonymous LDAP bind has no identity key and is left off: it is not somebody's
session. `/admin/ldap/service` counts every connection.

## The `via` a termination passes is the caller's own words (2026-09-04)

`contextFor()` carries `by` and the SESSION family spends it as the `via` it
hands `endSessionById()`. It was a constant — `the protocol-independent logout`
— for every door, and that string is what `authn.js`'s `dropSession()` tests for
`admin` or `console` to decide CAEP's `initiating_entity`. So the branch meaning
*an administrator revoked this* was unreachable: `/admin/logout`,
`/admin/sessions` and the management API all emitted an event saying the person
had signed themselves out.

It is worth knowing beyond the one bug, because it makes `by` **load-bearing
rather than decorative**: a door that names itself vaguely now produces a vague
event. `/admin-api/sessions` passes *the management API at /admin-api/sessions*
for exactly that reason — *the management API* alone contains neither word and
reported `user`.
