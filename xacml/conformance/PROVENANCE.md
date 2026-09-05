# PROVENANCE — where the XACML conformance suite in this directory came from

**Nothing in this directory is this repository's work, and nothing in it is
edited here.** It is a vendored copy, and this file is the record of what was
copied, from where, under what licence, and what was changed on the way in.
`MANIFEST.js` beside it is the machine-readable half; this is the argument.

## The chain

| Link | Who | What they did | Licence |
|---|---|---|---|
| 1 | OASIS XACML Technical Committee | Wrote the original XACML 1.1 / 2.0 conformance tests. Anne Anderson is named as the author on the TC's own page. | **None stated.** See *The one link nobody can confirm*, below. |
| 2 | AT&T | Upgraded that suite to XACML 3.0, added cases for the features 3.0 introduced, and contributed the result back to the TC on the `xacml-comment` mailing list in **April 2014**. | MIT, `Copyright (c) 2014 AT&T Intellectual Property`, published at <https://github.com/att/xacml-3.0> |
| 3 | AuthzForce (OW2) | Adapted AT&T's set: fixed about thirty defects in it and split it into `mandatory/`, `optional/` and `unsupported/`. **This is the copy taken.** | **Apache-2.0**, <https://github.com/authzforce/core> |
| 4 | here | Copied verbatim. | Apache-2.0 — see *This subtree is not MIT*. |

## What was taken, and from where exactly

* Repository: `https://github.com/authzforce/core`
* Branch: `develop`
* Path: `pdp-testutils/src/test/resources/conformance/xacml-3.0-from-2.0-ct`
* Fetched: **2026-09-04**, as the branch tarball from `codeload.github.com`.

`MANIFEST.js` records the file count and the per-directory case counts as they
were on that date, so a re-sync that silently loses half the suite is reported
rather than passing with fewer tests.

## What was changed on the way in — Apache-2.0 section 4(b)

Apache-2.0 requires that modified files be marked as modified. **No test file
was modified.** Every `Policy.xml`, `Request.xml`, `Response.xml`, `.txt`,
`.properties` and `.ignore` under `mandatory/`, `optional/` and `unsupported/`
is byte-identical to the upstream copy, which is what `MANIFEST.js`'s
`checkVendored()` asserts.

Three things about the *directory* changed, and none of them touches a test:

1. Upstream's `README.md` is `UPSTREAM-README.md` here, so that the name
   `README.md` is free for this repository's own conventions and so that a
   reader cannot mistake AuthzForce's defect list for ours. **Its content is
   unchanged**, and it is worth reading before anything else in here: it is the
   list of about thirty defects in the original AT&T suite, and the reason this
   copy was taken from AuthzForce rather than from AT&T.
2. `LICENSE` was copied in from the root of `authzforce/core`, which the
   upstream conformance directory does not itself carry.
3. This file and `MANIFEST.js` were added.

The three upstream directories, the upstream `ConformanceTests.html` (the
original OASIS description of the tests) and every file beneath them are
untouched.

## This subtree is not MIT

**The rest of this repository is MIT** (`LICENSE.md` at the root,
© 2026 Iya CyberSecurity Solutions, LLC). **This directory is Apache-2.0**,
and that is a deliberate, recorded exception rather than an oversight — the
root `LICENSE.md` says so and points here.

What Apache-2.0 asks of us, all three of which are satisfied above: keep the
licence text (`LICENSE`), keep the attribution notices (this file), and state
what was changed (the section above). Apache-2.0 is one-way compatible into a
permissively licensed distribution, so shipping an MIT project that contains
this subtree is fine; what is *not* fine is quietly relicensing these files as
MIT, which is why they live in a directory of their own rather than being
scattered under `tests/`.

## The one link nobody can confirm

Link 1 in the table has **no licence statement**. The OASIS page that hosts the
original tests
(<https://www.oasis-open.org/committees/xacml/ConformanceTests/ConformanceTests.html>)
carries no copyright notice, no licence and no terms of use, and **the test
files themselves carry no header either** — open any `Policy.xml` in here and
the first line is the XML declaration.

That matters because the grant that would normally cover this does not reach
them. The OASIS IPR Policy's notice language permits copying and derivative
works "without restriction of any kind, **provided that the above copyright
notice and this section are included** on all such copies and derivative
works" — a proviso attached to documents that *carry* the notice. These do not.
OASIS also publishes no official XACML 3.0 conformance package:
`docs.oasis-open.org/xacml/` holds the schemas and the specifications, and no
test suite.

So **whether AT&T had the right to MIT-licence material derived from the TC's
2.0 tests is not something public sources establish**, and this file does not
pretend otherwise. What is established is everything downstream of it: AT&T
publishes under MIT, AuthzForce redistributes under Apache-2.0, both are
permissive, both are compatible with this repository, and the suite has been
redistributed for over a decade by AT&T, AuthzForce/OW2, WSO2 Balana and others
without any dispute that is findable. Widely done and never challenged is not
the same thing as licensed, and the distinction is written down here rather
than smoothed over, so that whoever handles IP for this project can see the
question rather than having to rediscover it.

**This is not legal advice.** It is the record of what was checked, on
2026-09-04, and of what could not be.

## Re-syncing

`node xacml/conformance/MANIFEST.js --check` reports drift against the recorded
counts and digests. To take a newer upstream: fetch the same path from the same
branch, replace the three directories and `UPSTREAM-README.md`, re-run
`--check`, and update the *Fetched* date and the counts above. Do not
cherry-pick individual cases — a suite with cases removed from the middle of it
still reports a percentage, and the percentage is what everybody reads.
