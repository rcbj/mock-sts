---
title: Caches
nav_order: 15
---

# The caches this service keeps

This service remembers some things it could work out or fetch again, and some
things it has to remember to refuse a second use. This page lists both. For each
one it gives what is held, how long it is held, the setting that bounds it, and
what makes it forget.

It matters for two reasons:

- **A cache is a window in which an answer can be out of date.** If a change you
  made does not show up at once, the entry below says how long to wait.
- **Replay stores decide whether something is refused.** They are security
  state, not a speed-up, so they are listed separately at the end.

Every setting named here can be changed while the service runs, on the page for
its protocol in the admin console or through `POST /admin-api/config/set`.
[Configuration](configuration.md) describes the settings themselves.

## Three terms

| Term | Meaning |
|---|---|
| **Per process** | One copy in each node process. With request workers turned on (`workers.requestCount` above 0) every worker has its own, so two requests answered by two workers may see two different cached answers until both expire. |
| **Per realm** | One copy for each [trust realm](trust-realms.md), in each process. Removing a realm empties its copy. |
| **Persisted** | Written to the persistence store and restored at the next start, and shared between processes that use the same store. See [Persistence](persistence.md). |

Nothing on this page is cleared by an admin console button. A restart empties
everything that is not persisted.

---

## Certificates and revocation

When a client certificate or a signed assertion names a CRL, an OCSP responder
or an issuer certificate address, the service fetches it and remembers the
answer.

| Cache | Holds | Scope | How long | Setting |
|---|---|---|---|---|
| CRLs | each fetched certificate revocation list | per process | until the CRL's own `nextUpdate`, but never longer than the setting | `pki.revocationCrlMaxAgeS` (3600) |
| OCSP answers | each fetched OCSP response | per process | until the response's `nextUpdate`, but never longer than the setting | `pki.revocationOcspMaxAgeS` (3600) |
| Issuer certificates | certificates fetched from an Authority Information Access address | per process | as for CRLs | `pki.revocationCrlMaxAgeS` |
| Failed fetches | an address that did not answer, so it is not asked again at once | per process | the setting; 0 means a failure is not remembered | `pki.revocationFailureRetryS` (60) |
| Certificate files | trust anchors read from a file named in a setting | per process | until the file's path or modification time changes | — |

The first three share one size limit, `pki.revocationCrlCacheEntries` (256);
the oldest entry is dropped first.

**If you revoke a certificate at an external authority**, this service may go on
accepting it for up to an hour, or until the list it holds reaches its
`nextUpdate`. A certificate this service issued itself is checked against its own
register on every use, with no cache.

Three smaller caches remember work already done on content that cannot change:
- parsed certificates, 256 entries;
- whether a certificate holds a given key, and whether its chain ends under the
  current service Root, 512 entries each;
- the result of mapping a TLS client certificate to an identity, 256 entries.

They need no setting because a changed certificate is a different entry.

## Signing keys

| Cache | Holds | Scope | How long | Setting |
|---|---|---|---|---|
| Decrypted signing keys | a realm's private keys, decrypted from the store | per process | depends on the policy: `timed` drops them after the idle time, `per-use` after each signature, `resident` never | `keys.plaintextRetention` (`timed`), `keys.plaintextTtlS` (300) |
| A realm's key set | the keys a realm signs with, built when first needed | per realm | for the life of the process, unless another process's copy is adopted | — |
| Post-quantum keys | the realm's ML-DSA and SLH-DSA keys, generated when first needed | per realm | as for the key set | — |
| Certificate authorities | each realm's CA hierarchy, held decrypted | per process | replaced when the hierarchy changes | — |
| Thumbprint key IDs | the RFC 9278 URI for each key ID | per process | never needed again (512 entries) | — |

The decrypted-key policy only applies where keys persist. In development mode
there is no stored copy to fall back to, so keys stay in memory.
[Encryption at rest](encryption-at-rest.md) has the full story.

## OAuth 2.0 and OpenID Connect

| Cache | Holds | Scope | How long | Setting |
|---|---|---|---|---|
| Signed metadata | the signed `signed_metadata` JWT published in the discovery document | per realm | the setting; at most the second setting's number of entries | `oauth2.signedMetadataCacheS` (60), `oauth2.maxSignedMetadataEntries` (64) |
| Request objects | JWT request objects fetched from a client's registered `request_uri` | per realm | the setting; 0 (the default) turns it off; at most 256 entries | `oauth2.requestUriCacheS` (0) |
| Authorization details types | parsed RFC 9396 type definitions and their compiled JSON Schemas | per process | until the definition text changes (512 entries) | — |
| SSF event permissions | which Shared Signals events each application may receive | per realm | until any application entry changes | — |

**After a signing key rotation**, a discovery document can carry `signed_metadata`
signed with the old key for up to `oauth2.signedMetadataCacheS` seconds. A change
to the algorithm, the certificate header or the key ID format takes effect at
once.

There is no JWKS cache for federation partners or for this service's own admin
console and portal: both fetch the key set every time they need it.

## The directory

The embedded directory keeps indexes so that a lookup does not walk every entry.

| Index | Holds | Scope | How long |
|---|---|---|---|
| Usernames | name → entry | per realm | kept current on every write |
| Groups | member → groups | per realm | rebuilt after a change that affects groups |
| entryUUIDs | UUID → entry | per realm | rebuilt when a lookup finds it stale |
| Container listings | the entries under each container | per realm | rebuilt after a write under that container |

These are exact. A write is visible to the next read whichever door made it: the
console, `/admin-api`, SCIM or LDAP on port 389.

## Other protocols

| Cache | Holds | Scope | How long | Setting |
|---|---|---|---|---|
| XACML policies | each policy document, parsed and validated | per process, shared by all realms | never evicted (see below) | — |
| Federation release policy | which attributes each application releases to its partner | per realm | the setting | `federation.releaseIndexTtlMs` (5000) |
| SPIFFE authorities | a realm's X.509 SVID authorities, unpacked | per process | until the stored authorities change | — |
| Kerberos keys | long-term keys derived for each principal | per trust realm, in the realm's own principal database | until the principal changes; never persisted | — |
| SAML 1.1 assertions | issued assertions, kept so a Browser/Artifact request can be answered | per realm, persisted | the oldest is dropped past the limit | `saml11.assertionCacheMax` (500) |
| SAML SP metadata | a service provider's metadata, stored as received | the application entry | until refreshed from the application's page | — |
| Dead-letter counts | an estimate of each Shared Signals stream's dead letters | per realm | recounted at each sweep | — |
| Remote PEP policy | the policy set a remote PEP last pulled | the PEP container | until the next successful pull | — |
| Debugger files | the embedded debugger's files with this service's address filled in | per process | until the file changes (400 entries) | — |

**XACML policy parses are never forgotten.** Each distinct policy text is kept
for the life of the process, so a policy edited many times holds one parsed copy
per version until the service restarts.

## Worker pools

| Cache | Holds | Scope | Bound |
|---|---|---|---|
| Crypto worker affinity | which crypto worker last handled a session | per process | 1,000; forgotten when a worker exits |
| Request worker affinity | which request worker a browser, credential or LDAP connection is pinned to, one map for each pool | front process | 5,000 per pool; forgotten when a worker exits |
| Unchanged-write shadow | the last copy of each directory entry written to the store, so an unchanged entry is not written again | per process | refreshed at each flush |

Affinity only decides where a request goes; losing it costs nothing but a
re-route. See [Sessions](sessions.md) for what a session pins.

---

## Replay caches and nonces

These are the stores that make a one-time value work once. Clearing one would let
something be used twice, which is why none of them has a control.

| Store | Remembers | Scope | Limit | Forgets |
|---|---|---|---|---|
| Used assertions | every RFC 7523 JWT and RFC 7522 SAML assertion accepted, for a grant or client authentication | per realm, persisted in every store mode | `oauth2.assertionReplayCacheSize` (1000); **refuses new assertions when full** | once the assertion itself expires; a request that fails releases its claim |
| Kerberos authenticators | each authenticator the protected service accepted | per trust realm (the realm whose Kerberos realm issued the ticket), persisted | `krb5.replayCacheMaxEntries` (10000); **refuses when full** | after twice the clock skew |
| DPoP proof IDs | each DPoP proof's `jti` | per realm, persisted | no size limit | after twice `oauth2.dpopIatSkewS` (300) |
| DPoP nonces | server-issued DPoP nonces | per realm, persisted | none | after `oauth2.dpopNonceTtlS` (300) |
| GNAP signatures | each signed GNAP request | per realm, persisted | none | after twice `gnap.signatureMaxAgeS` (300) |
| ACME nonces | spent ACME `Replay-Nonce` values | per realm, persisted | 100,000 | expired ones are cleared when the limit is reached |
| SCIM Digest nonces | Digest challenges handed out | per realm | `scim.maxDigestNonces` (2000) | after `scim.digestNonceSeconds` (300), then oldest first |
| SCIM HOBA challenges | HOBA challenges handed out | per realm | `scim.maxHobaChallenges` (2000) | after `scim.hobaMaxAgeSeconds` (600), then oldest first |
| SCIM HOBA signatures | HOBA signatures already seen | per realm | `scim.maxHobaSeen` (5000) | oldest first |
| OID4VCI nonces | `c_nonce` values issued to wallets | per realm, persisted | none | after `oid4vci.cNonceTtlS` (300), or when used |
| Redeemed codes | each authorization code already exchanged, and the tokens it produced | per realm, persisted | none | one code lifetime (five minutes by default) after the code would have expired |

Two behaviours are worth knowing:

- **The used-assertion and Kerberos stores refuse when full rather than forgetting.**
  Dropping a live entry would reopen a replay, so a burst that fills one is
  answered with refusals until entries expire. Raise the limit if a legitimate
  load reaches it.
- **The DPoP `jti` store has no size limit.** It is pruned by time only, so a very
  high rate of valid DPoP proofs within the skew window grows it until the window
  passes.

## Not caches

These look similar in the code but only prevent duplicate work or duplicate log
lines while something is in progress:
- a CRL fetch or certificate authority build already under way;
- a token renewal already running for a session;
- warnings that have already been logged once.

Registers that are the record of something, such as sessions, tokens, the audit
log, consent and the directory itself, are covered in their own pages.
