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

Then open <http://localhost:8081/sts-metadata> — every endpoint this service
registers, read off the live Express router, with a sentence about each and a
link to the specification it implements.

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
| SAML 2.0 and SAML 1.1 assertions | inside the two above — there is no Web SSO profile |
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

## The three things to know before you rely on it

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

**The admin console at `/admin` is not protected.** It can revoke tokens, add
claims to every future token and assertion, and create people in the directory.
Do not put this on a public address.

## Pages

- [Getting started](getting-started.md) — running it, the ports, the container
- [Configuration](configuration.md) — every setting, and which can change at runtime
- [Endpoints](endpoints.md) — how to find out, rather than a list that goes stale
- [What is not checked](what-is-not-checked.md) — the permissive posture, and the two exceptions
- [Repository layout](layout.md) — where the code is, for contributors
