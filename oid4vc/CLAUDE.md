# oid4vc/

OpenID4VCI 1.0 (the Credential Issuer), OpenID4VP 1.0 (a mock Verifier), and W3C
DID Core with DIF domain linkage.

| File | What it is |
|---|---|
| `vc_configs.js` | The credential configurations. Exists to break a require cycle. |
| `vc_offers.js` | The Credential Offer pages and the pre-authorized codes. Same reason. |
| `vc_claims.js` | Which LDAP attribute types an issued credential carries, plus the invented persona. |
| `vc_verifier_config.js` | What the mock Verifier ASKS FOR, and in which of the three formats. |
| `vc_issuer.js` | The three credential endpoints. |
| `vc_verifier.js` | The bar door at `/oid4vp/verifier`. |
| `vc_did.js` | `did:web`, `did:jwk`, and the domain linkage document. |

**`vc_configs.js` and `vc_offers.js` exist to break require cycles, not to group
code** — see rule 2 in the root `CLAUDE.md`. The credential configurations are
read by both the issuer and the authorization server; the Credential Offer's
pre-authorized codes are minted by the offer pages and redeemed at the token
endpoint.

**`vc_claims.js` is read from three different points of the require order and
from four directories** — `vc_issuer.js` here, `../admin-ui/admin.js`,
`../ldap/ldap_server.js`, `../scim/scim_map.js` and `../common/claim_attributes.js`
— so it must stay a library. It is in this directory rather than in `common/`
because the catalogue is defined by what a CREDENTIAL carries; the other three
readers are consumers of that definition, not co-owners of it.

3a. **`vc_claims.js` is a library like `dpop.js` too, and it is read from three
   different points of the require order.** It holds which claims an issued
   Verifiable Credential carries — a catalogue of LDAP ATTRIBUTE TYPES, not of claim
   names, because a claim's value is the value on that person's directory entry —
   plus the invented, DETERMINISTIC persona that fills what an entry lacks.
   `vc_issuer.js` (early), `admin.js` (late) and `ldap_server.js` (last) all read it,
   so it must stay a library: it registers no route and requires only `helpers.js`
   and `admin_stats.js` (for `identityKeyOf()`, so that `alice`,
   `urn:sts-mock:user:alice` and `alice@REALM` are one invented person and one
   entry). The DIRECTORY half is inverted the usual way — `setDirectory()` is filled
   by `ldap_server.js` at ITS require time, because that module cannot be required
   from a module `vc_issuer.js` reads without dragging every `/ldap` route to the
   front of the router. Two things there are load-bearing and easy to undo: the
   ISSUER METADATA is built from the same selection the credential is (an issuer
   advertising five claims and minting fourteen teaches every wallet author that the
   metadata is not worth reading), and `ldp_vc` carries only the terms the vendored
   JSON-LD context defines — `bbs2023.js` canonicalizes with `safe: true`, so an
   undefined term does not go missing, it THROWS inside a cryptosuite at issuance
   time. `buildLdpVc()` filters against the context it actually loaded rather than
   trusting the hand-kept list.

3a-ii. **`vc_verifier_config.js` is the same kind of library, and it holds the
   OTHER end of that catalogue.** `vc_claims.js` says what an issued credential
   CARRIES; this says what the mock Verifier — the bar door at `/oid4vp/verifier` —
   ASKS FOR, and which of the three credential formats it asks in. Both ends read
   it (`vc_verifier.js` early, `admin.js` late), so it registers no route and
   requires only `helpers.js`, `vc_claims.js` and `vc_configs.js`, none of which
   registers anything either. Four things in it are load-bearing:
   its catalogue is `vc_claims.js`'s rows GROUPED BY CLAIM rather than listed as
   attribute types, because `buildSdJwtVc()` makes one Disclosure per top-level
   claim and `address` is therefore one unit of disclosure however many attributes
   feed it; the DCQL query is built HERE and `vpDcqlQuery()` in `vc_verifier.js` is
   now only the caller that logs it, so the console's preview and the real request
   cannot drift; the ldp_vc paths use the VENDORED CONTEXT'S TERM and not the OIDC
   claim name (`birthDate`, and four flat terms where the others have `address`),
   which was silently wrong while the Verifier could only ask for the two claims
   whose spellings coincide; and `formatById()` reads a SPACE AS A PLUS, because
   `dc+sd-jwt` is a format id containing the one character a query string spells a
   space with — `?format=dc+sd-jwt` arrives as `dc sd-jwt`, which cost nothing
   while an unrecognised format fell back to a constant and costs the bar door's
   own button the moment that fallback is configuration.
   The claims a request asks for are FROZEN onto the transaction in
   `buildVpRequest()` and every check reads them from there: the list is editable
   while a presentation is in flight, and judging what came back against a list
   changed after the question was asked refuses a wallet for answering correctly.

---

## What it deliberately does not do

* **The values in an issued credential are invented, and nothing verifies them.**
  `/admin/vc` says which LDAP attributes a credential carries; the value is read
  from that person's directory entry, and what the entry lacks is generated from
  their username — deterministically, so one username is one invented person across
  restarts, and in obviously fictional ranges (RFC 2606 mail domains, `555-01xx`
  numbers, streets called `Placeholder`). A verifier that believed a birthdate from
  here would be believing a web form. Nothing reads a credential claim back either:
  no token, assertion or PAC carries one and no endpoint decides anything on one.
* **A presentation that VERIFIES is not a sign-on either.** The OID4VP Verifier
  checks properly — issuer signature, every Disclosure digest against `_sd`, the Key
  Binding JWT including `sd_hash`, the nonce, the audience, the validity window and
  whether the claims asked for arrived — and then says yes on a web page and stops.
  No session starts, no token is issued and nothing else in this service reads what
  was presented. **It IS recorded, which is a different claim and the two must
  not be merged** — the same distinction a verified TLS client certificate
  draws. The holder goes through `recordAuthentication()` like every other
  accepted credential, so it appears on `/admin/users` and the directory seeds
  an entry for it; what the row says is that an identity presented a credential
  here and it verified, and nothing more. What it asks for is configuration
  (`/admin/vc-verifier-config`) and
  is deliberately a SEPARATE setting from what the issuer mints (`/admin/vc`), so
  that asking for a claim no credential here carries stays reachable: that is the
  only way to exercise a wallet's "I cannot satisfy this request" path, and one page
  setting both would make it impossible to produce. Asking for NO claim is a setting
  too — DCQL reads an absent `claims` member as the whole credential.
