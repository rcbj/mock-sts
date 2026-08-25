---
title: Signing out
nav_order: 6
---

# Signing out of everything

Every protocol family here that can sign somebody **in** has a sign-out of its
own, and each one signs them out of itself:

| Endpoint | What it is |
|---|---|
| `GET /oauth2/logout` | OpenID Connect RP-Initiated Logout |
| `GET|POST /wsfed?wa=wsignout1.0` | WS-Federation 1.2 section 13.2.4 |
| `GET|POST /saml2/slo` | SAML 2.0 Single Logout |

None of those is the question most people arrive with, which is *what am I still
signed into, and how do I stop being signed into it*. That question is
protocol-independent, and so is `/logout`.

## `GET /logout`

Lists everything this service is still holding for one identity — across every
family — with a checkbox against each.

```
GET /logout
    no session cookie -> 302 /authn/login  -> back here signed in
    a session cookie  -> the list

GET /logout?username=alice        somebody else's list
GET /logout?format=json           the same thing, for a test
```

Signing out may mean signing in first. This service has no other way to know who
is asking, and the session that creates is listed with everything else.

## `POST /logout`

Ends what was ticked. **A POST that ticks nothing ends everything** — that is the
default and the point of the endpoint:

```bash
# global logout for whoever holds this cookie
curl -b cookies.txt -X POST http://localhost:8081/logout

# global logout for somebody named, no cookie needed
curl -X POST http://localhost:8081/logout -d 'username=alice&scope=global'

# just two things
curl -X POST http://localhost:8081/logout \
     -d 'username=alice&select=session:8Qk3…&select=token:abc…'
```

Row ids come from the GET. They look like `session:<id>`, `token:<jti>`,
`wsfed-rp:<session>|<realm>`, `code:<handle>` — and for anything whose natural
key is a **credential**, the handle is a hash of it rather than the value: an
authorization code in a form field is an authorization code in a browser
history.

## What it reaches

| Family | Ending it |
|---|---|
| Browser sign-on session | dropped, through the one function every sign-out here uses — so the RFC 9700 refresh-token revocation and the audit row happen once |
| OpenID Connect relying parties | its `frontchannel_logout_uri` loads in a hidden iframe, with `iss` and `sid` where it asked for them |
| WS-Federation realms | `wa=wsignoutcleanup1.0` as a one-pixel image, with the URL printed beside it |
| SAML 2.0 service providers | the signed `LogoutRequest`, offered as a link |
| Tokens | the `jti` joins the same revocation set `/oauth2/revoke` writes to, so `/oauth2/introspect` reports it inactive immediately |
| Authorization codes | discarded, so no more tokens come from that sign-on |
| Credential Offer pre-authorized codes | the same |
| Directory connections | the LDAP socket is closed — the bind is the state of a *connection* (RFC 4511 §4.2), so that is the only sign-out LDAP has |
| Kerberos | a sign-out instant on the principal; a `TGS-REQ` presenting a ticket authenticated before it is refused `KDC_ERR_TGT_REVOKED` (20) |

## What it cannot reach — and lists anyway

**This is the part worth reading before relying on any of it.** A SAML assertion
already in a service provider's hands, a Kerberos *service* ticket already in a
cache and an X509-SVID already minted cannot be ended — not by this service and
not by a real one. The reason is the same in all three cases: **nothing consults
the issuer when they are presented.** A relying party checks a signature and some
`Conditions` and asks nobody. A Kerberos service decrypts a ticket with its own
key. An SVID verifies against a bundle it already has.

So those rows appear on the page with a dash instead of a checkbox and a sentence
saying why. Hiding them would make a global logout look complete when it is not,
which is the most misleading thing this endpoint could do.

Two more things it does not reach, and both are honest rather than missing:

* **A Kerberos service ticket keeps working against the service that accepts
  it.** The sign-out instant is checked at the *KDC*, and accepting a service
  ticket never contacts the KDC. A fresh `AS-REQ` also succeeds and clears the
  instant — signing out is not being locked out.
* **SPIFFE is not in the list at all.** A SPIFFE identity is a workload, attested
  per call, holding no session. The registry can end an identity's ability to
  obtain *another* SVID, which is a ban rather than a logout; that lives at
  `/admin/spiffe`.

## Front-channel logout

`/logout` — and `/oauth2/logout`, and the console — perform **OpenID Connect
Front-Channel Logout 1.0** for any client that registered a
`frontchannel_logout_uri`:

```bash
curl -X POST http://localhost:8081/oauth2/register \
  -H 'Content-Type: application/json' -d '{
    "client_name": "demo",
    "redirect_uris": ["http://localhost:3000/callback"],
    "frontchannel_logout_uri": "http://localhost:3000/logout",
    "frontchannel_logout_session_required": true }'
```

With that registered, the discovery document says
`frontchannel_logout_supported: true`, an ID Token issued on a browser session
carries a `sid` naming that session, and every sign-out renders

```html
<iframe src="http://localhost:3000/logout?iss=…&sid=…">
```

plus the same URL as a visible link. The link is not decoration: the
specification says the provider **cannot know** whether a front-channel
notification succeeded, so a dead relying party, a certificate your browser will
not accept and a mistyped URI all look identical to success. Clicking it is the
only way to see which happened.

`iss` and `sid` are sent only to a client that registered
`frontchannel_logout_session_required`; the specification says they are otherwise
omitted.

**Back-channel logout is a different specification and is not implemented.** The
metadata says so.

## The other two doors

| | Who it is for | Difference |
|---|---|---|
| `/logout` | a person, about themselves | no console role needed; it is the browser that loads the notifications |
| `/admin/logout` | an operator, about somebody else | behind the console's two roles; filtered and paged; has two **NON-SPEC** undos — restoring a revoked token, and clearing a Kerberos sign-out instant |
| `GET|POST /admin-api/logout` | a test | four operations: `global`, `end`, `restore-token`, `restore-kerberos` |

All three call one pair of functions, which is what stops them coming to
disagree about what a live session is.

## Turning parts of it off

Two of these mechanisms take something away that used to keep working, and every
refusal in this service is switchable — see [configuration](configuration.md):

| Setting | Off means |
|---|---|
| `logout.kerberosSignOut` | the KDC behaves exactly as it did before this existed |
| `logout.ldapDisconnect` | directory connections are left alone, and listed as untouched rather than hidden |
| `logout.anyUser` | `?username=` is refused; `/logout` acts only on the caller's own session |
| `oauth2.frontchannelLogout` | no `sid`, no advertisement, no iframes — the tokens are byte-for-byte what this service issued before |
