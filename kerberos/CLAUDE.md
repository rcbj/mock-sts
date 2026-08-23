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
