---
title: Parent project migration
nav_order: 10
---

# What `../oauth2-oidc-debugger` needs when the `sts/` pin is bumped

This repository is a git submodule of the
[OAuth2/OIDC Debugger](https://idptools.com), where it is checked out as `sts/`.
That project reaches into this one **by flat path** in three places, and the
2026-08-23 reorganisation broke all three.

**Nothing over there was changed**, deliberately. Its `sts/` gitlink is pinned at
`cae2066` — a commit from before `applications.js` existed — so its suite is not
running against current code anyway, and the fix cannot be merged before the pin
bump regardless: a `COPY sts/kerberos/krb5_kdc.js` line added ahead of the bump
fails the build with `COPY … not found`, which says nothing about a
reorganisation.

**Bump the pin and make these three edits in the same commit.** Without them four
in-process Kerberos jobs die at load with `Cannot find module`, and the message
names a module rather than the cause.

---

## 1. `tests/Dockerfile` — the sts COPY block

The set is the **transitive closure** of what `krb5_kdc.js`, `krb5_service.js`
and `spnego.js` require, and it still is: the reorganisation moved files, it did
not add dependencies. Exactly **one** new file joins the closure —
`common/config_file.js`, which `config.js` and `helpers.js` now require first so
that a relative `CONFIG_FILE` resolves against the package root rather than
against whichever subdirectory the reading module sits in.

**The subdirectories have to be preserved in the image**, and that is the part
that is easy to get wrong. `sts/kerberos/krb5_kdc.js` requires
`../common/helpers`; flattened into `sts/`, that resolves to `common/helpers`
outside the submodule and fails as a missing dependency rather than as a
misplaced file — the same trap the existing comment describes for the flat case.

Replace the `COPY sts/*.js ./sts/` lines with:

```dockerfile
# The Kerberos KDC, the acceptor, SPNEGO and the codec.
COPY sts/kerberos/krb5_kdc.js sts/kerberos/krb5_service.js \
     sts/kerberos/krb5_principals.js ./sts/kerberos/
COPY sts/kerberos/krb5_primitives.js sts/kerberos/krb5_asn1.js \
     sts/kerberos/krb5_crypto.js sts/kerberos/krb5_messages.js \
     sts/kerberos/krb5_gss.js ./sts/kerberos/
COPY sts/kerberos/krb5_ndr.js sts/kerberos/krb5_pac.js ./sts/kerberos/
COPY sts/kerberos/spnego.js sts/kerberos/krb5_spnego.js ./sts/kerberos/

# The shared modules those rest on. config_file.js is the ONE addition the
# reorganisation made to this closure: config.js and helpers.js require it
# first, so that a relative CONFIG_FILE resolves against the package root
# rather than against sts/common/.
COPY sts/common/app.js sts/common/helpers.js sts/common/config.js \
     sts/common/config_file.js ./sts/common/
COPY sts/common/admin_stats.js sts/common/audit.js \
     sts/common/applications.js sts/common/delegation.js ./sts/common/

# admin_stats.js requires the FEDERATION REGISTER, for the per-partner attribute
# release filter it consults at jwtClaims() and samlAttributes(). That module
# registers no route and requires only config.js, helpers.js and audit.js, so it
# is a leaf here — but it is a REQUIRE, so a Kerberos job that loads app.js loads
# it, and without this line dies at startup with "Cannot find module
# '../federation/federation'". Only the one file: federation_sp.js registers
# routes and is never loaded in-process, and federation_map.js and
# federation_http.js are only required by it.
COPY sts/federation/federation.js ./sts/federation/

# app.js requires oauth2_bcp.js, which pulls client_auth.js and mtls.js behind
# it. Three files, one directory now.
COPY sts/oauth-oidc/oauth2_bcp.js sts/oauth-oidc/client_auth.js \
     sts/oauth-oidc/mtls.js ./sts/oauth-oidc/

# helpers.js requires bbs2023.js, which reads its JSON-LD contexts at module
# scope through path.join(__dirname, 'contexts') — so the contexts have to sit
# BESIDE it, which is why they moved into common/vendored/ rather than staying
# at the package root. A Kerberos test has no business needing them and needs
# them anyway; the coupling is pre-existing.
COPY sts/common/vendored/bbs2023.js ./sts/common/vendored/
COPY sts/common/vendored/contexts ./sts/common/vendored/contexts

# The submodule's own env/. CONFIG_FILE is resolved against the package root,
# which in this image is ./sts — and since 2026-08-24 env/defaults.js is
# REQUIRED BY config.js ITSELF, by absolute path off that root, whatever
# CONFIG_FILE says. So this must stay a copy of the whole directory: narrowing
# it to the one file a job names (COPY sts/env/local.js) puts every in-process
# job back to dying at load with `Cannot find module` for a file nobody
# mentioned. See sts/common/CLAUDE.md.
COPY sts/env ./sts/env
```

The old `COPY sts/contexts ./sts/contexts` line goes away — `contexts/` is inside
`common/vendored/` now.

**`common/delegation.js` is a SECOND addition to the closure and it arrived after
this document was written** (2026-08-24, the delegation register). `krb5_kdc.js`
requires it — that is where four of the eight delegation mechanisms are recorded
— so every in-process Kerberos job needs it in the image. It requires only
`helpers.js`, `config.js` and `admin_stats.js`, all three of which are already
copied, so it adds one filename and nothing behind it. This is exactly the case
the closure walk below exists to catch, and it is written down here rather than
left to the walk because the symptom is `Cannot find module
'../common/delegation'` at load, which names a module rather than a missing COPY
line.

**`admin-ui/delegation_map.js` (2026-08-25, the delegation picture) adds NOTHING
to this closure, and that is worth one sentence rather than a re-walk.** Only
`admin-ui/admin.js` requires it, and that file is not copied — no in-process job
loads a console page. The same change gave `common/delegation.js` a `graph()`
function, which adds no new require either: it uses `realms`, `config` and
`admin_stats`, all three of which that module already required before it. The
new npm dependency (`@dagrejs/dagre`) is reached only from the uncopied file, so
`tests/Dockerfile` needs no line for it.

**Rerun the closure walk after the bump.** Seed it with every `sts/**/*.js`
copied, follow each `require('./x')` and `require('../y/x')`, and require the
result to be a subset of what is copied. The set moves on this repository's
schedule, not on that Dockerfile's.

---

## 2. `tests/module_paths.js` — `mockStsModule()`

It takes a bare filename and looks in three places. Two of the three are now
wrong for every file, and the third — the flattened `sts_<name>.js` form — is
still right for `bbs2023.js`.

The smallest correct change is to let callers pass a path **with its directory**
and keep the flat fallback:

```js
const candidates = [
  path.join(__dirname, "..", "sts", name),          // a checkout with the submodule
  path.join(__dirname, "sts", name),                // the tests image
  path.join(__dirname, "sts_" + path.basename(name))// the tests image, flattened
];
```

`path.basename()` is the whole of it: `mockStsModule("common/helpers.js")` then
finds `sts/common/helpers.js` in a checkout and `sts_helpers.js` where a file was
flattened with a prefix.

`MOCK_STS_DIR` keeps working unchanged — it joins the same `name`.

---

## 3. The four callers, and the two byte-compare tests

**`tests/krb5_as_exchange.js`, `tests/krb5_tgs_ap.js`, `tests/krb5_spnego_http.js`
and `tests/krb5_delegation_interop.js`** call `mockStsModule()` with bare names.
Each needs its directory:

| Was | Is now |
|---|---|
| `krb5_kdc.js` | `kerberos/krb5_kdc.js` |
| `krb5_service.js` | `kerberos/krb5_service.js` |
| `spnego.js` | `kerberos/spnego.js` |
| `app.js` | `common/app.js` |
| `helpers.js` | `common/helpers.js` |

**`tests/krb5_codec_sync.js`** compares eight vendored codec modules against
`client/src/`'s copies. All eight moved into `kerberos/`, and its `MODULES` list
is bare filenames joined to a directory it discovers — so the fix is the
directory it discovers, not the list.

**`tests/bbs2023_cryptosuite.js`** looks for `sts_bbs2023.js` beside itself and
`ROOT/sts/bbs2023.js` in a checkout. The second is now
`ROOT/sts/common/vendored/bbs2023.js`; the first is unchanged, because
`tests/Dockerfile` renames it on the way in.

---

## What did NOT change

- The container build. The parent's compose files build `./sts` with this
  repository's own Dockerfile, which copies the whole context — so the reorganised
  service builds and runs there with no edit at all.
- `CONFIG_FILE=./env/test.js` and the `KRB5_*` environment variables. The
  resolution order is the same and the environment still wins over the appconfig
  file.
- Every vendored file, byte for byte. Nothing in `common/vendored/` or
  `kerberos/krb5_spnego.js` was edited — they were moved, and the two byte-compare
  tests will still pass once they are pointed at the new paths.
