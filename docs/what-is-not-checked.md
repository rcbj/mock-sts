---
title: What is not checked
nav_order: 8
---

# What is not checked

This service **checks no password, validates no access token it did not issue,
and attests no workload**. Read this page before using it for anything, and read
it again before concluding that something here is a bug.

It is permissive on purpose. A client that has only ever met a permissive server
has never run its own refusal paths; a client that has only met a strict one
cannot reproduce the behaviour it is trying to detect. So the default is
permissive, several negatives are made deliberately *reachable*, and where the
service can be told to be strict, it can.

## The permissive list

| It does not | Notes |
|---|---|
| Check any end user's password | The username typed at `/authn/login` becomes the identity in every token and every assertion |
| Refuse any LDAP bind | Any DN, any password, anonymous included — on 389 and on LDAPS 636 alike |
| Verify an access token it did not issue | Except at `/oauth2/userinfo`, which answers "who did *you* authenticate" and so must |
| Require DPoP | Nonce mode makes proofs fresher, not mandatory. A request with no `DPoP` header is a Bearer request |
| Turn a verified client certificate into a login | No session, no token, no privilege. It *is* recorded — see below |
| Turn a verified presentation into a sign-on | The OID4VP Verifier checks properly and then says yes on a web page and stops |
| Verify anything in an issued credential's values | They come off the directory entry, and what the entry lacks is *invented* from the username |
| Deactivate anybody on SCIM `active: false` | Stored as `scimActive` and read by nothing |
| Restrict WHICH people a federation partner may assert | Any username in a verified assertion is accepted, and an entry is created for them. What IS checked is the partner's signature — see below, where that inversion is argued |
| Verify a SAML `AuthnRequest`'s signature | Whether it was signed, and the certificate off its `ds:KeyInfo`, are both **recorded** on the service provider's directory entry and neither is checked. That is why `/saml2/metadata` advertises `WantAuthnRequestsSigned="false"`: asking service providers to sign something nothing verifies is worse than not asking |
| Check which entityID a SAML service provider claims | **Any entityID is accepted**, and the first valid `AuthnRequest` from one creates its application entry. Asking for its metadata does the same — the document is minted for anything asked for |
| Attest a workload or a node | See SPIFFE, below |
| Let a group grant anything, bar two | A token now *carries* one; no endpoint reads it. `cn=admin-read` and `cn=admin-write` are the exception and grant the admin console, nothing else |
| Decide who may delegate to whom, in two of the three families that can | The KDC polices S4U properly, off the same two attributes a real domain uses. WS-Trust `OnBehalfOf`/`ActAs` and RFC 8693 token exchange are unpoliced: anybody may ask for a token about anybody. Every act says which — see below |

**Recorded is not the same claim as authenticated, and the two are kept apart
everywhere.** A verified TLS client certificate, a verified presentation and an
accepted SPIFFE credential all appear on `/admin/users` and seed a directory
entry — because an identity turned up here and something about it was accepted.
None of them starts a session or issues a token. A mock that quietly promoted one
into the other would teach a client something false about every real server it
will ever meet.

## Delegation is policed in one family out of three, and the page says which

`/admin/delegation` records every exchange in which somebody acted on somebody
else's behalf — Kerberos S4U2Self, S4U2Proxy (classic and resource-based) and a
forwarded ticket-granting ticket; WS-Trust `OnBehalfOf` and `ActAs`; RFC 8693
token exchange as impersonation and as delegation — against one model, with the
initial identity, the intermediary acting for them and the target being reached
on every row.

**Kerberos is the only one of the three that decides anything.** The KDC checks
`msDS-AllowedToDelegateTo` on the front-end account and
`msDS-AllowedToActOnBehalfOfOtherIdentity` on the back-end one, enforces the
asymmetries between them (classic needs forwardable evidence; resource-based
needs `PA-PAC-OPTIONS` and gets `KDC_ERR_BADOPTION` without it), and refuses with
a message naming both attributes and their current values. WS-Trust puts no
authorization on either element and this service adds none; RFC 8693 leaves the
policy to the authorization server and this one has none — `may_act` is neither
issued nor read here. Each act states which of the two it was in the field that
names an attribute for a Kerberos row, so the difference is visible rather than
inferred.

**Refusals are recorded, and they are the rows worth having.** A refused
delegation appears in no other list on this service — nothing was accepted, so
no authentication was recorded — which is why that page keeps a store of its
own.

One consequence worth stating on a page about what is not checked: under an
**impersonation** (S4U2Self, a forwarded TGT, `OnBehalfOf`, an RFC 8693 exchange
with no `actor_token`) nothing in the credential records that a middle tier was
involved, so the issuer is the only place that fact can ever be seen. That is not
this service being permissive — it is what impersonation *is* — but it is the
reason a page like that one belongs on an identity provider rather than on a
client.

## Kerberos is the exception, and cannot not be

The password there *is* the key: pre-authentication and the AS-REP's enc-part are
both encrypted under it, so a KDC accepting anything would still have to pick a
key the client could not guess. So it does the permissive equivalent — **any
username authenticates and every user account shares one password**
(`password!`, `KRB5_USER_PASSWORD`), with a name nobody configured created on
first sight.

Three things stay refusals on purpose, so the corresponding error codes are
reachable: a service-shaped name for a host this service is not willing to *be*
(`KDC_ERR_S_PRINCIPAL_UNKNOWN`), the names in `KRB5_UNKNOWN_USERS`
(`KDC_ERR_C_PRINCIPAL_UNKNOWN`), and a wrong password (`KDC_ERR_PREAUTH_FAILED`).

## The reachable negatives

A permissive server that refuses nothing is not much use for testing error paths
either, so several refusals are kept deliberately reachable:

- **The literal password `invalid`** is rejected on the password grant, on
  WS-Trust, at the WS-Federation sign-in screen, and as an LDAP bind password —
  where it is the only thing that produces `LDAP_INVALID_CREDENTIALS` (49), the
  result code an LDAP client's error handling is built around.
- **`invalid` as a SCIM `userName`** is refused, as is a duplicate one.
- **`oauth2.breakIdTokenNonce`** puts a deliberately wrong `nonce` in every ID
  Token. Off by default, and *not* part of RFC 9700 mode: a compliance flag that
  also broke tokens is a flag nobody would turn on.
- **WS-Federation's `wauth`** is refused rather than faked. A relying party
  demanding multi-factor against a password-only session gets an error and two
  ways forward, not an assertion claiming a second factor that did not happen.
- **A SAML 2.0 `ProtocolBinding` this service does not implement is refused by
  name.** A service provider that asked for PAOS and received a form post would
  conclude that PAOS worked.
- **`IsPassive="true"` with no usable session** is answered with a
  `<samlp:Response>` carrying `NoPassive` rather than with a sign-in screen —
  which is one of the two SAML status codes a service provider is least likely
  to have handled. A cancelled sign-in gets `AuthnFailed` at the assertion
  consumer service, which WS-Federation's passive profile has nowhere to send.
- **A SAML artifact resolves exactly once.** Resolving destroys it, so a second
  `ArtifactResolve` for the same artifact is refused with a status naming the
  reason — the easiest thing in that profile to get wrong and the hardest to
  notice, because the happy path passes either way.
- **`wreqptr` is never dereferenced**, and neither is a client's registered
  `jwks_uri`, and neither is a foreign SPIFFE bundle URL. Fetching a URL somebody
  handed you in order to verify a credential is a server-side request forgery
  with a specification citation attached.

## Federation inverts all of this, and it is not a fourth turnstile

Everything above describes this service being **asked** for something. Federation
is the other direction — it CONSUMES what a foreign identity service issued — and
there the posture is reversed.

`/federation/acs/{id}` receives an unauthenticated HTTP request that claims to be
a person. The only thing between "alice signed in at the partner" and "somebody
POSTed some XML" is the signature check, and the browser sign-on session that
comes out is **the same session** `/oauth2/authorize`, `/wsfed`, `/saml2/sso`,
`/saml11/sso` and `/admin` all read.

So "accept any SAML Response" is not a permissive mock of federation. It is an
authentication bypass for every protocol in this process, reachable with `curl`,
and the tokens minted afterwards are indistinguishable from any others. There is
no version of that endpoint which is both useful and permissive, which is why
this is the one feature here that **has to be configured before it will do
anything**:

* nothing federated happens until a relationship is created;
* a relationship is created **disabled**, and enabling it is a second act;
* an enabled relationship missing a field its protocol needs **refuses and names
  the field** rather than half-working;
* an assertion is refused unless it verifies against the certificate configured
  on that relationship — **not** against a certificate the document brought with
  it, which is the difference between a signature check and a decoration;
* the assertion's issuer must be the partner the relationship names, and the
  response must answer a request this service sent (unless
  `fedAllowUnsolicited` says otherwise, which is what
  identity-provider-initiated sign-on is).

**The gate is on the SIGNER, not on the subject.** Past it, everything is as
permissive as the rest of this service: any username in a verified assertion is
accepted, any attribute is mapped, nothing about the person is checked, and a
directory entry is created for them.

**It is also the only thing here that makes an outbound request** — a partner's
token endpoint, UserInfo or JWKS, for the OpenID Connect and OAuth 2.0 flows.
That does not soften the refusals above it: `jwks_uri` on a client registration
and WS-Federation's `wreqptr` are **still never followed**. The difference is who
supplied the URL. Those come from an unauthenticated caller; a federation
endpoint was written down by an administrator, and the module that dials it will
not accept a URL at all — only the *name* of the relationship attribute holding
one. `federation.outbound` turns it off entirely, and four of the five protocols
need no back channel.

## The three surfaces that DO require a credential

### SCIM, at `/scim/v2`

These endpoints create, replace, patch and **delete** accounts, which is why. A
credential is required (`scim.authRequired`), all six schemes RFC 7644 section 2
names are offered, and the OAuth ones must carry `scim:read` or `scim:write` —
the only scope requirement anywhere in this service.

**It is a turnstile rather than a lock**, and that is a different sentence.
Anybody can get a token with either scope from any grant, any password but
`invalid` passes Basic, any username passes Digest with the one shared password,
and anybody can register a HOBA key for any name. What it buys is that a client's
401, 403, challenge-response and scope handling can be exercised *at all* — none
of which an open endpoint can produce.

Two schemes really verify something. **Digest** hashes the password into the
response, so a server accepting anything would not be performing the exchange and
the client's own digest code would go unexercised. **HOBA**'s signature is
genuinely verified for the same reason; what is permissive there is the
registration, because that is how a caller *gets* a credential. Between them they
make five negatives reachable that no permissive server can produce — including a
replayed nonce count refused **without** `stale=true`, because `stale` means
"your credential was fine, try again" and a replay is the opposite claim.

The discovery endpoints are open by default (`scim.authDiscovery`): the
ServiceProviderConfig is where a client *reads* which schemes exist, so demanding
a credential to fetch it means a client must already know the answer to the
question it is asking.

**A credential that was presented and failed is always a refusal**, even with
`scim.authRequired` off, so a client testing its expired-token path does not get
a 200 because the endpoint would also have accepted nobody.

### The SPIRE Server API

Its TCP port is **mutual TLS**. Callers present an X509-SVID verified against the
trust bundle, and every method is authorized against SPIRE's own per-method table
— copied row for row from `pkg/server/authpolicy/policy_data.json`, not reasoned
out, so that where a row looks surprising (`Debug.GetInfo` is local-only, so an
admin SVID over TCP is refused it) the surprise is SPIRE's answer and not this
service's invention.

What comes out of that surface is a credential another service will believe,
which is why. `spiffe.authRequired` turns it off and restores the whole of the
old posture.

### The admin console, at `/admin`

`admin.authRequired` is **on by default**. Every page and every form under
`/admin` needs a browser sign-on session from `/authn/login` and one of two
roles: **Admin Read** (look at everything, change nothing) and **Admin Write**
(post every form). Write implies read.

It is the one surface that can change what every *other* surface does — it
revokes tokens through the same set `/oauth2/revoke` writes to, and it adds
claims to every token, ID Token and assertion issued from then on — which is why.

**It is a turnstile rather than a lock, and here that is sharper than it is for
SCIM: no password is checked at the sign-in screen either.** What the gate proves
is that somebody *typed* a name that holds a role. What it buys is a client, or a
person, being driven through a 302 to a sign-in screen, a 401 with no session, a
403 with the wrong role, and a role model that can be granted and revoked.

**The roles are two ordinary groups in the embedded directory** — `cn=admin-read`
and `cn=admin-write` by default (`admin.readGroup`, `admin.writeGroup`) — so
`/admin/rbac`, `POST /admin-api/rbac/grant`, an `ldapmodify` and a SCIM `PATCH`
are four doors onto one membership. A role no test can grant would be a role no
test can exercise.

**While neither group has a member, anybody who signs in holds both roles**, and
every page says so. There is no password anywhere here to bootstrap an
administrator with and the roster dies with the process, so an empty roster opens
rather than closes; `admin.openWhenEmpty` turns that off.

**`/admin-api` is not gated at all.** It is what a test drives and it is the way
back in when nobody holds a role — and it means anybody who can reach this port
can grant themselves both roles through it. Do not put this service on a public
address.

## A logout cannot recall what has already been issued

`/logout` ends every session and revokes every credential this service can still
reach — see [signing out](signing-out.md). Three things it **cannot** end, and
they are listed on the page with the reason rather than left off it:

* a **SAML assertion** already in a service provider's hands
* a **Kerberos service ticket** already in a cache
* an **X509-SVID** already minted

The reason is the same in all three cases and is not a limitation of this mock:
**nothing consults the issuer when they are presented.** A relying party verifies
a signature and some `Conditions`; a Kerberos service decrypts with its own key;
an SVID verifies against a bundle. A real identity provider cannot recall any of
them either.

What a KDC *can* do — and this one does — is refuse the next `TGS-REQ` that
presents a ticket-granting ticket authenticated before the sign-out, which is
`KDC_ERR_TGT_REVOKED` (20). That is the whole of what is available, and a
**service** ticket already issued is untouched by it.

## The Workload API is the opposite case

It authenticates nobody **because its specification says it MUST NOT**. A
workload has no secret and no root of trust until that call gives it one, so the
SPIFFE Workload Endpoint specification requires that the endpoint not demand
authentication and that TLS not be required. `spiffe.authRequired` deliberately
does not reach it.

What it lacks there is **attestation, not authentication**, and the two must not
be merged. A real agent reads the peer credentials of its Unix socket —
`SO_PEERCRED`, giving pid and from that uid, gid, executable, container, pod —
and turns them into selectors. **Node has no portable way to read them.** So a
caller is identified by the transport it arrived on, the endpoint it reached and
its peer address, and by nothing else, and the selectors are spelt `transport:`,
`endpoint:` and `peer:` rather than `unix:` or `k8s:`. Writing `unix:uid:1000`
for a uid nothing read would be inventing an attested fact.

Selector matching still **decides** which entries answer a caller
(`spiffe.attestWorkloads`), which is narrowing without attesting; and
`spiffe.autoCreateEntries` **off** is the interesting setting, because a caller
matching no entry then gets an empty SVID list — what a real agent does for an
unregistered workload, and the only way to run a client's "I have no identity"
path.

## RFC 9700 mode

`oauth2.rfc9700` turns the OAuth 2.0 / OIDC flow into a conforming one. It is off
by default, changes nothing until it is set, and is restart-only because it also
binds the main port as HTTPS.

**In that mode this service checks exactly one credential**: a client that
registered *here* as confidential must present the `client_secret` this service
minted for it. Section 2.5 conditions its requirement on a process for issuing
credentials existing, and `POST /oauth2/register` is one. Nothing else changes —
a `client_id` this service never registered has no credential on file and is
untouched, a registered public client has nothing to authenticate with, and no
end user's password is checked in that mode or any other.

Everything the mode does and does not enforce is at `GET /oauth2/rfc9700`, row by
row. Two rows say `enforced: no` because the requirement is the *client's* — it
must validate the ID Token's nonce, and must not use a token before that succeeds
— and nothing this server observes separates a client that checks from one that
does not.
