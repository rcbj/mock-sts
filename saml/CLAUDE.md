# saml/

The two assertion builders, and nothing else.

| File | What it is |
|---|---|
| `saml2.js` | A SAML 2.0 assertion: build, sign, and the attribute statement. |
| `saml11.js` | The same for SAML 1.1, whose profile splits a claim URI into a namespace and a name. |

**THERE IS NO SAML 2.0 WEB SSO PROFILE** — no SingleSignOnService, no
AuthnRequest, no Response — and that is deliberate rather than an omission. These
two modules exist to be CALLED: `ws-trust/wstrust.js` asks for an assertion to put
in an `RSTR`, and `ws-federation/wsfed.js` asks for one to put in a `wresult`.
Neither builder registers a route, and `GET /admin/sts-metadata` therefore lists no SAML
endpoint. It is also why the federation metadata publishes no `IDPSSODescriptor`.
See README.md before inferring from the absence that it was overlooked.

**A SAML ATTRIBUTE IS MULTI-VALUED and both builders say so.** `values` is an
array of `<AttributeValue>` children under one `<Attribute>`; `value` is untouched
and is what every existing caller passes. One element per value with the same name
is not a multi-valued attribute — it is a relying party reading the first and
silently seeing one where there are four. That is also why the precedence rules in
`../common/claim_attributes.js` and `../common/group_claims.js` are written as a
FILTER in these two builders rather than as an assignment order: an assertion is a
list of elements, so a duplicate name is not an overwrite.

They require only `../common/helpers`, `../common/config` and
`../common/admin_stats`, so they cannot join a cycle and their position in the
require order is not a position at all.

**WHAT EACH BUILDER PUTS IN IS CONFIGURED ON `/admin/saml-attributes`** —
*Custom SAML attributes*, under the console's own SAML group, since 2026-08-24;
it was four sections of `/admin/claims` before that. Neither file changed when
it moved: the one line each that calls `stats.samlAttributes('saml2' | 'saml11',
context)` is the line it always was, because the split is a fact about the
CONSOLE and the store is still one `CLAIM_SETS` object in `admin_stats.js`. Two
things about that context are worth knowing before writing prose about it
anywhere: **it is `{ subject, audience }`**, so a value carrying `${username}`
reaches the assertion as the characters it was written as (an unknown
placeholder names itself rather than becoming empty — see `expandValue()`), and
the RESERVED CLAIM NAMES enforced for a JWT set are **not** enforced for these
two, because `exp` collides with nothing in an assertion.
