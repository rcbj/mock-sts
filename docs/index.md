---
title: mock-sts
nav_order: 1
---

# mock-sts

A mock identity service that speaks **sixteen protocol families** in one small
Node process. It exists to exercise *clients*: it checks no password, validates
no access token and attests no workload.

That last sentence is the whole design, and it is worth reading twice before
using this for anything. A real identity provider refuses things; this one mostly
does not, on purpose, because a client that has only ever met a permissive server
has never run its own refusal paths — and a client that has only met a strict one
cannot reproduce the behaviour it is trying to detect. Where this service *can*
be told to be strict, it can, and [what is not checked](what-is-not-checked.md)
says exactly where the line is.

## Start here

```bash
git clone --recursive https://github.com/rcbj/mock-sts.git
cd mock-sts
npm install
CONFIG_FILE=./env/local.js node server.js
```

Then open <http://localhost:8081/> — a front page with the four things worth
having on one: this repository, its issues, this site, and the admin console on
that instance.

The page worth going to next is <http://localhost:8081/admin/sts-metadata> —
every protocol this service speaks, and every endpoint it registers, read off
the live Express router, with a sentence about each and a link to the
specification it implements. It is a page of the admin console, so it asks you
to sign in first: any username will do, because no password is checked anywhere
in this service.

[Getting started](getting-started.md) has the rest: the ports, the container, and
what to do when 389 or 88 will not bind.

## What it speaks

| Family | Where |
|---|---|
| OAuth 2.0 and OpenID Connect — a full authorization server | `/oauth2/*`, `/.well-known/openid-configuration` |
| DPoP (RFC 9449) and certificate-bound tokens (RFC 8705) | the token endpoint and the four protected endpoints |
| RFC 9700, the Security BCP, as an optional MODE | `GET /oauth2/rfc9700` |
| WS-Trust 1.0 – 1.4 | `/wstrust` |
| WS-Federation 1.2, passive requestor, with a mock relying party | `/wsfed`, `/wsfed/rp` |
| SAML 2.0 Web Browser SSO — a full identity provider, all three bindings | `/saml2`, `/saml2/metadata/{sp}`, `/saml2/sp` |
| SAML 1.1 browser profiles — Browser/POST and Browser/Artifact, and an attribute authority | `/saml11`, `/saml11/metadata/{rp}`, `/saml11/rp` |
| SAML 2.0 and SAML 1.1 assertions | inside all four above |
| **Federation** — this service as either end of a relationship with a foreign identity service, in five of those protocols | `/federation`, `/admin/federation` |
| WebAuthn Level 3, the relying party's half | the login screen |
| Kerberos v5 — a KDC, a protected service, and MS-KKDCP | TCP/UDP 88, `/KdcProxy` |
| SPNEGO (RFC 4559/4178) | `/spnego` |
| LDAP v3 (RFC 4511) and LDAPS | TCP 389 and 636 |
| SCIM 2.0 provisioning | `/scim/v2` |
| TLS and mutual TLS reporting | 8443 and 9443 |
| SPIFFE — bundle endpoint, Workload API, SPIRE Server API | `/spiffe`, four gRPC sockets |
| OpenID4VCI 1.0 — a Credential Issuer | `/oid4vci/*` |
| OpenID4VP 1.0 — a Verifier | `/oid4vp/verifier` |
| W3C DID Core with DIF domain linkage | `/.well-known/did.json` |

## The four things to know before you rely on it

**Nothing persists.** Every store is a Map in this process. The signing key is
regenerated on every start — deliberately, so that a client cannot cache a key it
should be re-fetching — and every document that carries it is served
`Cache-Control: no-store`.

**Every surface tells you what it does not do.** That is not modesty; it is the
point. `GET /oauth2/rfc9700` publishes every BCP requirement with `yes`,
`detected`, `always`, `deployment` or `no` and the reason. `GET /spiffe` names
the six of forty-two SPIRE methods that are unimplemented and why each one is.
`GET /ldap` says the directory is schemaless. A mock that quietly pretended
would teach you something false about every real server you will ever meet.

**The admin console at `/admin` asks for a sign-in and a role** — `admin.authRequired`,
on by default — and the roles are two ordinary groups in the embedded directory.
It is a turnstile and not a lock: no password is checked at that screen either,
and `/admin-api` is not gated at all, so anybody who can reach this port can
grant themselves both roles through it. The console can revoke tokens, add
claims to every future token and assertion, and create people in the directory.
Do not put this on a public address.

**Federation is the one feature that refuses by default, and that is deliberate.**
Everywhere else this service accepts what it is given. It cannot do that where it
CONSUMES somebody else's assertions: `/federation/acs/{id}` receives an
unauthenticated HTTP request claiming to be a person, and the session it would
produce is the same one every other protocol here reads — so "accept anything"
would be an authentication bypass for the whole process rather than a permissive
mock. A relationship must be configured, is created disabled, and refuses an
assertion that does not verify against the certificate configured on it. **Past
that gate everything is as permissive as the rest**: any username in a verified
assertion is accepted. See [what is not checked](what-is-not-checked.md).

## Pages

- [Getting started](getting-started.md) — running it, the ports, the container
- [Configuration](configuration.md) — every setting, and which can change at runtime
- [Endpoints](endpoints.md) — how to find out, rather than a list that goes stale
- [Trust realms](trust-realms.md) — several logical identity services in one process, told apart by a path segment: what each one separates, and what every realm shares
- [Signing out](signing-out.md) — `/logout`: one list of everything you are still signed into, across every family, and what cannot be ended
- [Persistence](persistence.md) — what survives a restart and what never can: three modes, and the reason nothing this service mints is ever written down
- [What is not checked](what-is-not-checked.md) — the permissive posture, its three exceptions, and the one feature that inverts it
- [Repository layout](layout.md) — where the code is, for contributors
