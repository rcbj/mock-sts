---
title: Parent project migration
nav_order: 10
---

# What `../id-proto-debugger` needs when the `sts/` pin is bumped

This repository is a git submodule of the
[OAuth2/OIDC Debugger](https://idptools.com), where it is checked out as `sts/`.
That project reaches into this one **by path** in three places, and for five days
this document described a migration those three paths needed and had not had.

**THE MIGRATION IS DONE, AS OF 2026-08-28, AND THIS DOCUMENT SAID THE OPPOSITE
UNTIL THEN.** All three edits landed over there, the `sts/` gitlink is at
`d2345c3` rather than at the pre-reorganisation `cae2066`, and the four
in-process Kerberos jobs load their modules out of this repository's
subdirectories without complaint. If a document here still reads as though a
reorganisation is pending, that document is the one that is wrong.

What remains is not a migration but a **standing obligation**, and it is the
whole reason this page is still here — see *The COPY set is a closure* below.

---

## What the three edits became

Worth recording rather than deleting, because one of them came out differently
from what this document prescribed, and somebody reading the old advice would
"fix" working code.

**1. `tests/Dockerfile` — done as described.** Every `COPY sts/…` line names a
folder now (`sts/kerberos/krb5_kdc.js`, `sts/common/helpers.js`,
`sts/common/vendored/bbs2023.js`), and the file's own comment records why: the
subdirectories have to be preserved in the image, because `krb5_kdc.js` requires
`../common/helpers` and a flattened copy resolves that outside the submodule and
fails as a missing dependency rather than as a misplaced file. The two modules
that are still copied flat and renamed — `sts_bbs2023.js` among them — are
loaded on their own and have no relative requires to satisfy, which the
Dockerfile says at each one.

**2. `tests/module_paths.js` — done DIFFERENTLY, and this is the paragraph that
matters.** This document proposed that callers pass a path with its directory,
`mockStsModule("kerberos/krb5_kdc.js")`. That is *not* what was built. The
resolver SEARCHES instead: `mockStsSearchDirs()` walks the mock's top-level
directories plus `common/vendored/`, so `mockStsModule("krb5_kdc.js")` still
takes a **bare filename** and finds `kerberos/krb5_kdc.js` on its own.

The consequence is the useful half: **the four callers were never edited and
must not be.** `tests/krb5_as_exchange.js`, `tests/krb5_tgs_ap.js`,
`tests/krb5_spnego_http.js` and `tests/krb5_delegation_interop.js` still name
bare filenames, correctly, and a future move of a module between directories
here costs that project nothing at all. The table of "was / is now" renames this
document used to carry has been deleted rather than corrected, because every row
of it was an edit that would now break something that works.

`MOCK_STS_DIR` keeps working unchanged, and there is a third candidate below it:
a sibling `../../mock-sts` checkout, which resolves and then says loudly that the
run reflects an unpushed working copy rather than the commit the gitlink points
at.

**3. The two byte-compare tests — done.** `tests/krb5_codec_sync.js` discovers
the directory its eight vendored codec modules live in rather than joining bare
names to a fixed one, and `tests/bbs2023_cryptosuite.js` goes through
`mockStsModule()` instead of a hardcoded `ROOT/sts/bbs2023.js`. Both comment the
change at the line.

---

## The COPY set is a closure, and it moves on THIS repository's schedule

This is the part that does not expire, and it is why bumping the pin is never
purely a bump.

The `sts/` lines in `tests/Dockerfile` are the **transitive closure** of what
`krb5_kdc.js`, `krb5_service.js` and `spnego.js` require — the modules the four
in-process Kerberos jobs load directly. That set is computed from this
repository's require graph, so **adding one `require()` to any module reachable
from those three obliges that project to add a `COPY` line**, in the commit that
bumps the pin across the change. Miss it and the job dies at load with
`Cannot find module`, which names a file nobody edited and says nothing about a
missing COPY line.

The closure has grown four times so far, and each was invisible until it wasn't:

* `common/config_file.js`, when `CONFIG_FILE` began resolving against the
  package root;
* `env/` **as a whole directory**, when `config.js` started requiring
  `env/defaults.js` by absolute path off that root whatever `CONFIG_FILE` says —
  narrowing it to the one file a job names puts every in-process job back to
  dying at load;
* `common/delegation.js`, when `krb5_kdc.js` began recording four of the eight
  delegation mechanisms there;
* `federation/federation.js`, which `admin_stats.js` requires for the
  per-partner release filter — a leaf, but a leaf on the far side of a `require`
  that `app.js` performs.

And two changes that added NOTHING, which is worth as much: `admin-ui/`'s two
diagram modules are required only by `admin.js`, which is not copied because no
in-process job loads a console page — so `@dagrejs/dagre` needs no line either.

**Rerun the walk after every bump.** Seed it with every `sts/**/*.js` the
Dockerfile copies, follow each `require('./x')` and `require('../y/x')`, and
require the result to be a subset of what is copied.

---

## What the next bump needs: exactly one file

As of 2026-08-28 the walk has one outstanding answer, and it is the live example
of everything above.

**`common/pq_jose.js`.** `common/crypto.js` requires it for the post-quantum and
composite signatures, and `crypto.js` is deep in the closure — so every
in-process Kerberos job loads it. The parent's **working tree** already carries
the line, with the reasoning at it:

```dockerfile
COPY sts/common/pq_jose.js ./sts/common/
```

Its **committed** `tests/Dockerfile` does not, and the pinned commit `d2345c3`
has no such file — those two facts are consistent with each other and with a
green build today, which is exactly why this is easy to get wrong. They stop
being consistent the moment either one moves alone: bump the pin without the
COPY line and the Kerberos jobs die at load; commit the COPY line without the
pin bump and the image fails to build with `COPY … not found`. **They land
together or not at all.**

---

## What did NOT change

* **The container build.** The parent's compose files build `./sts` with this
  repository's own Dockerfile, which copies the whole context — so this service
  builds and runs there with no edit at all, whatever moves here. Only the
  *tests* image hand-picks files, and only because it has no `.dockerignore` of
  its own.
* **`CONFIG_FILE` and the `KRB5_*` environment variables.** The resolution order
  is the same and the environment still wins over the appconfig file.
* **Every vendored file, byte for byte.** Nothing in `common/vendored/` or
  `kerberos/krb5_spnego.js` was edited for any of this — they were moved, and the
  two byte-compare tests pass against them where they now sit.
