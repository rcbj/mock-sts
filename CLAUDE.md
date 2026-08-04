# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in
this repository.

## Overview

A mock identity service that speaks eight protocol families — WS-Trust 1.0–1.4, SAML
2.0, OAuth 2.0 / OIDC (a full authorization server), DPoP, OpenID4VCI 1.0,
OpenID4VP 1.0, and W3C DID Core with DIF domain linkage. It exists to exercise
*clients*: it authenticates nobody, checks no password and validates no access token.

`README.md` is the substantive document — it explains why each piece is the way it
is, and most of those explanations are the record of something having gone wrong
once. Read it before changing anything. What follows is only what is not in there.

Extracted from the [OAuth2/OIDC Debugger](https://idptools.com). The tests that cover
this service still live in that project (see *Tests* below), which is the single most
important thing to know about this repo's current state.

## Running it

```bash
npm install
CONFIG_FILE=./env/local.js node server.js      # 8081; STS_PORT overrides
```

`CONFIG_FILE` selects a file in `env/`, whose only setting is the bunyan log level.
At the default `debug` every endpoint call and every artifact before and after
signing is logged — that is the point of a mock, so do not quieten it by default.

## Architecture, and the three rules that hold it together

`server.js` is a shell: it requires the modules and listens. The modules are
`helpers.js` (log, keys, cross-protocol helpers), `app.js` (the express app and every
middleware), `saml2.js`, `wstrust.js`, `oauth2.js`, `vc_configs.js`, `vc_offers.js`,
`vc_did.js`, `vc_issuer.js`, `vc_verifier.js`, `sts_metadata.js`, and `dpop.js`.

1. **Requiring a module registers its endpoints.** Each calls `app.get(...)` at its
   top level against the shared app from `app.js`, rather than exporting a
   `register()`. So **the require order in `server.js` is the route order**, and the
   middleware has to live in `app.js`, because express applies middleware only to
   routes added after it.
2. **`vc_configs.js` and `vc_offers.js` exist to break require cycles, not to group
   code.** The credential configurations are read by both the issuer and the
   authorization server; the Credential Offer's pre-authorized codes are minted by
   the offer pages and redeemed at the token endpoint. A cycle in node does not fail
   loudly — it hands back a half-initialised module whose exports are `undefined`,
   and the symptom arrives later as something that is not a function.
3. **`dpop.js` is a library, not a protocol module.** It registers nothing, so its
   position in the require order does not matter, and it requires only `helpers.js`
   (plus npm leaves) so it cannot join a cycle. Keep it that way. It is also why
   `presentedAccessToken()` — the Bearer-or-DPoP check the four protected endpoints
   share — lives there rather than in `vc_issuer.js` where it was written: the
   fourth caller is in `oauth2.js`, which vc_issuer.js cannot be required from
   without building a cycle or moving OID4VCI ahead of OAuth2 in the route order.

`userFor`, `parseBody`, `oauthError`, `vciError` and `signJwt` are in `helpers.js`
because more than one protocol needs them, not because they are especially general.

## Adding an endpoint costs one entry in `sts_metadata.js`

`GET /sts-metadata` reads the endpoint list **from the running Express router**, so
it cannot go stale — but it reports two kinds of drift and the parent project's
`tests/sts_metadata.js` fails on both: a route registered and undescribed, and a
description whose path is not registered (what a rename produces). See README.md.

Coverage notes in that file **must start `full`, `partial` or `mock`** and say what is
missing. A list of thirty-one specifications that did not mention that this service
checks no passwords and validates no access tokens would be the most misleading thing
in the repository.

## Code style

* **No one-liner `try`/`catch`.** Braces and a body, always.
* **Every function longer than about ten lines opens with
  `log.debug("Entering fn().")` and returns through `log.debug("Leaving fn().")`.**
  Several `Leaving` lines in one body is correct, not a mistake — one per exit.
* **Every swallowed `catch` explains itself in a comment.** "Not JSON; the raw text
  is what gets shown" is a reason. An empty block is not.
* Comments carry the *reasoning*, especially where something went wrong once. The
  density in this codebase is deliberate; match it rather than trimming it.

## The JSON-LD contexts are load-bearing

`bbs2023.js` reads the three files in `contexts/` **at require time, at module
scope**. A missing one is not a degraded feature — the service does not start. They
are vendored rather than fetched because Data Integrity signs canonicalized
statements, so a one-byte difference in a context fails every signature later and
looks like a crypto bug.

`bbs2023.js` resolves two layouts: `../client/src/contexts` (its position in the
parent project) and `./contexts` (this repo). Do not simplify that away — it is what
let the file be copied here unchanged.

## The signing key is regenerated on every start

Deliberate, and two things depend on it: the `kid` is derived from the key material
(`sts-mock-<thumbprint>`) so two instances cannot claim the same kid over different
keys, and every document that carries or describes the key is served
`Cache-Control: no-store`. If you add a document that publishes the key, it needs
that header too.

## Tests

**There are none in this repository yet, and that is the main gap.** Four tests in the
parent project need only this service and should be ported:

| Test | What it covers |
|---|---|
| `tests/sts_metadata.js` | the `/sts-metadata` drift checks — that the page lists exactly what the router registers, that every method reaches a handler, that every link resolves, and that no specification claim is idle |
| `tests/sts_dpop.js` | RFC 9449 end to end over HTTP: all twelve section 4.3 checks, the `cnf.jkt` binding on access and refresh tokens, `dpop_jkt`, `jti` replay, and the nonce handshake in both shapes. Almost entirely negatives, because a DPoP server that issues bound tokens and accepts good proofs looks finished and can be worth nothing |
| `tests/oauth2_sts_endpoints.js` | every endpoint the RFC 8414 metadata advertises answers, and every token verifies against the advertised JWKS |
| `tests/vc_did.js` | the DID-named issuer chain: advertisement → resolution → domain linkage → the key that actually verifies the credential |

They are plain node scripts using `assert` and `bunyan`, driven over HTTP with no
browser, and they take `WSTRUST_STS_URL` / `OID4VCI_ISSUER_URL` to locate the service.
`sts_dpop.js` writes its **own** DPoP client rather than importing the wallet's, on
purpose: if both sides of the exchange came from one implementation, a shared
misunderstanding would make the test pass and interoperate with nobody. Keep that
property when porting.

Until they are here, the drift checks README.md describes are documentation rather
than enforcement.

## Things this service deliberately does not do

Worth knowing before "fixing" one of them:

* **It checks no password.** The username typed at `/oauth2/login` becomes the
  identity in every token.
* **It does not verify access tokens it did not issue — except at UserInfo.**
  OID4VCI lets the authorization server be somebody else, so at the three
  credential endpoints a foreign token is accepted as-is. The consequence for DPoP
  is stated in `presentedAccessToken()` (in `dpop.js`, shared by all four
  protected endpoints): for such a token, `cnf.jkt` is a claim anyone could have
  written, and the binding is real only for tokens this service issued.
  `/oauth2/userinfo` is the exception and is meant to be — it answers "who did YOU
  authenticate", so it checks the signature, the `typ`, revocation and the
  `openid` scope, and refuses anything else rather than inventing a profile.
* **There is no "DPoP required" mode.** Nonce mode makes proofs fresher, not
  mandatory; a request with no `DPoP` header is a Bearer request and is answered as
  one, so turning nonce mode on cannot break the Bearer clients this service also
  exists to exercise.
* **One password is rejected** — the literal string `invalid` on the password grant
  and on WS-Trust — so a negative test has something to fail on.
