# CLAUDE.md — `xacml-pep/`

**A REMOTE XACML POLICY ENFORCEMENT POINT. PHASE FIVE, AND THE ONLY DIRECTORY
IN THIS REPOSITORY THAT IS NOT PART OF THE MOCK.**

Everything else here is required by `server.js` and runs in the identity
service's process. This is a **second container**: five files, three npm
packages, no express, no config table, no directory, no key of any kind. It
holds its own copy of the XACML engine, PULLS the policy repository from the
mock's PDP and decides locally.

```
docker compose --profile xacml up --build

curl http://localhost:9090/
curl "http://localhost:9090/protected?subject=alice&employeeType=staff&action=GET"
```

## What is here

| File | What it is |
|---|---|
| `engine.js` | Loads the seven engine modules and holds the ONE list of what "the engine" is. Pins `../common/helpers` to the shim. |
| `common/helpers.js` | **THE SHIM, AND THE POINT OF THE CONTAINER.** `log` and `xmlEscape`, thirty lines. |
| `sync.js` | The PDP client: register, pull, heartbeat. Holds what this PEP is enforcing. |
| `pep.js` | The service: four endpoints, the enforcement rule, the poll and heartbeat timers. |
| `Dockerfile` | Build context is the REPOSITORY ROOT — the engine is copied out of `xacml/` at build time. |
| `package.json` | `@xmldom/xmldom`, `bunyan`. Nothing else. |

`tests/xacml_pep.js` is its guard and lives in `tests/` with everything else.

---

## Why this exists at all, which is not obvious

The mock already has a PEP: `/xacml/protected`, in `xacml/xacml.js`. It builds
a request, asks the PDP, applies the bias and the obligation rule, and answers
200 or 403. It is a correct implementation of section 7.2 and it demonstrates
almost nothing about a distributed deployment, because it **shares a process
with the PDP**. It can never be stale. It can never hold a policy the PDP no
longer has. It can never go on enforcing while the PDP is down. It cannot
disagree with the PDP about anything, ever.

Every one of those is a state a real deployment lives in, and this container
makes all of them reachable:

* it can be STALE, and both ends say so — `GET /` here, and the row on
  `/admin/xacml/peps` over there;
* it can REFUSE a document the PDP accepted, and the two policy counts then
  disagree, which is what that column on the console is for;
* it can go on enforcing correctly with the PDP stopped, which is the trade
  `sync.js` argues and the one worth being able to watch;
* **the two ends can disagree about whether it is stale**, because they measure
  different things — this PEP counts missed polls and the PDP counts missed
  heartbeats. A PEP that is pulling happily while its heartbeats are dropped
  looks fine here and stale there, and that is a genuinely confusing deployment
  state that is far easier to recognise when both numbers are visible.

---

## THE SHIM IS THE POINT, AND IT IS A STRUCTURAL ASSERTION RATHER THAN A FEATURE

Every engine module in `xacml/` opens with a header claiming **no I/O, no DOM,
no store**. Every one of them also opens with:

```js
const { log } = require('../common/helpers');
```

and `common/helpers.js` in the mock requires `config.js`, `crypto.js`,
`pq_jose.js`, `realms.js`, node-forge, jsonwebtoken and the vendored BBS
module — which is to say the whole identity service. **So the claim had a
loophole wide enough to drive anything through**, and a module that reached
past `log` into `config.value()` or `signJwt()` would have broken nothing and
nobody would have noticed.

`common/helpers.js` here exports `log` and `xmlEscape` and nothing else, and it
is what `../common/helpers` resolves to inside this image. An engine module that
grows a dependency on the mock does not degrade here — **it throws at load**,
and `tests/xacml_pep.js` fails naming it. That test also asserts that not one of
the mock's own modules appears in the child's `require.cache` after the engine
has loaded.

So "the engine is a library" stopped being a comment at the top of seven files
and became a thing that is checked. **That is the most valuable thing in this
directory** and it is worth more than the feature it came with.

**The shim is therefore NOT a stub to be fleshed out.** A third export is not a
convenience — it is a dependency the engine grew, and the right response is to
take it back out of the engine or to argue it in `xacml/CLAUDE.md`, because it
is a change to what the engine IS.

### And `require.cache` is primed, which needs saying out loud

In the image, `/usr/src/pep/xacml/xacml_pdp.js` resolves `../common/helpers` to
`/usr/src/pep/common/helpers.js` — the shim. On a developer's machine, running
`node pep.js` out of the checkout, the same require resolves to the MOCK's
`common/helpers.js`.

That difference would make the host run and the container run **two different
programs**, and the one CI checks would be the one nobody develops against. So
`engine.js` resolves `common/helpers` relative to the engine's own directory and
installs the shim under that exact path in `require.cache` before requiring
anything. In the image the two paths are the same file and the priming is a
no-op it says so about.

Priming the module cache is a blunt instrument. It is acceptable **here** —
this process is a PEP and nothing in it wants the mock's helpers — and it is
why `tests/xacml_pep.js` drives this container as a **child process** and never
requires it: `run.js` runs every test file in one process, so a shim installed
there would be what the next test got.

---

## THE ENGINE IS COPIED AT BUILD TIME. NOT VENDORED, NOT PACKAGED.

Three ways to get seven modules into a second container, and two are wrong:

* **A checked-in copy** — the `common/vendored/` shape. Refused, and the
  difference from `common/vendored/` is the whole argument: those are ANOTHER
  REPOSITORY'S files and the drift is between two projects, with a manifest, a
  drift check and a sync command to manage it. These would be copies of files in
  the same tree, edited in the same commits, stale the first time somebody fixed
  a combining algorithm. `xacml/CLAUDE.md`'s central rule is ONE MODEL, and a
  second copy of the evaluator is the most expensive possible way to break it.
* **An npm package** — publishing `xacml/` and depending on a version. Refused
  for a mock: it puts a release step between editing a function and watching the
  PEP decide differently, which is the loop this repository is arranged around.
* **A build-time copy** — the Dockerfile copies the seven modules out of
  `xacml/`. One source of truth in the tree, and the image cannot drift from it.

**The seven are named individually rather than `COPY xacml/ ./xacml/`**, which
looks like the fragile choice and is the safe one: a whole-directory copy would
put `xacml.js`, `xacml_admin.js` and `xacml_pep_registry.js` in the image, every
one of which requires `common/app.js`, `admin-ui/admin.js` or `common/config.js`
— sitting there unloadable, waiting for a stack trace about express in a
container that has no express.

**And the list cannot go stale.** `tests/xacml_pep.js` parses the Dockerfile's
`COPY` lines and asserts they name exactly `engine.js`'s `MODULES`, in order. A
module added to the engine and not to the Dockerfile fails the suite naming
both. That is this repository's own version of the standing obligation the root
`CLAUDE.md` records the parent project having for its `sts/` COPY set —
**enforced rather than remembered.**

### What is deliberately NOT copied

`xacml_store.js` (the repository is `ou=policies` in the mock's directory; a PEP
holds what it pulled, in memory), `xacml_pip.js` (see below), `xacml_alfa.js`,
`xacml_templates.js`, `xacml_editor.js` (authoring — a PEP reads policy and
never writes it), `xacml.js` and `xacml_admin.js` (they register express routes
against the mock's app), and `xacml_pep_registry.js` / `xacml_pep_http.js` (the
PDP's side of phase five).

---

## THERE IS NO POLICY INFORMATION POINT HERE

The mock's PIP reads attributes off a person's entry in the embedded directory.
This process has no directory and should not have one. So **every attribute a
policy asks about has to be IN the request**, and one that is not produces an
empty bag — which is an ordinary XACML result rather than an error.

That is a real deployment shape rather than a limitation: most PEPs know who the
caller is and nothing else about them. `GET /protected?employeeType=staff` is
how this container lets somebody try it, and it is honest about what that means
— an attribute the SUBJECT asserted about itself, which no real deployment would
believe and which is exactly the sort of thing a mock exists to let you do.

**EACH ONE IS ASSERTED UNDER BOTH SPELLINGS**, the bare name and
`urn:sts-mock:xacml:attribute:<name>`, and that is not belt and braces. The
mock's `xacml_pip.js` answers BOTH from one directory attribute, so a policy
author over there may legitimately write either and the PDP decides identically.
A remote PEP asserting only one would decide differently for every policy that
used the other — which is precisely the disagreement this phase exists to make
impossible. **It cost a run to find**: the seeded RBAC policy names
`employeeType` bare, this container asserted only the prefixed form, and every
request was denied by a policy that was working perfectly.

---

## THE ENFORCEMENT RULE IS WRITTEN OUT, NOT IMPORTED

`xacml.js`'s `enforce()` is fifty lines and is not in the copy list. It is the
PEP's own decision — the bias and the obligation rule — and a PEP that imported
the PDP's would be demonstrating that two processes agree because they are one
program. That is the thing `tests/sts_dpop.js` refuses to do when it writes its
own DPoP client rather than importing the wallet's.

Written out, this PEP can run a DIFFERENT bias from the mock's embedded one, and
the two then disagree about exactly the answers the two biases disagree about —
which is the demonstration worth having.

**`tests/xacml_pep.js` runs both implementations over the same seven decisions
under both biases and asserts they agree** — and asserts that the two biases
disagree somewhere, so that the agreement is a real comparison rather than two
functions that both say yes.

---

## The four endpoints

```
GET  /              what this PEP is, what it holds, what it has enforced
GET  /protected     THE RESOURCE. 200 or 403, decided here
POST /notify        the PDP's nudge: pull now
GET  /healthcheck   liveness
```

**`/notify` answers 204 immediately and pulls afterwards.** The PDP times that
request out in two seconds by default, and holding it open for the length of a
pull would make a slow pull look like an unreachable PEP on somebody's console.

**Its body is not read and nothing in it is trusted.** A nudge says only that
something changed; what changed is discovered by pulling from this PEP's own
configured PDP URL. A nudge that could tell this PEP what the policy now is, or
where to fetch it, would be an unauthenticated caller supplying policy — and the
whole reason a nudge is affordable on the PDP's side is that it carries nothing.

**`/healthcheck` does not ask whether the policy is current.** A PEP holding a
stale copy is working, and a healthcheck that failed on staleness would turn a
PDP outage into a container restart loop — an outage of its own.

---

## What must work, and what is allowed to fail

**Only the pull has to work.** Everything else in `sync.js` is subordinate to
that and the file is arranged so a failure elsewhere cannot stop it:

* **Registering is optional.** It buys a row on the PDP's console and an address
  for the nudge; it is not what lets this PEP enforce —
  `GET /xacml/pep/policies` needs no credential. A PEP that fails to register
  logs why and goes on deciding. Getting that backwards would make a monitoring
  feature into a hard dependency for authorization.
* **The nudge is optional twice over**, and the poll arrives at most one interval
  later.
* **The heartbeat is optional**, and its failure is logged at `debug` rather than
  `warn`: a PEP that cannot report is still enforcing correctly, and a warning on
  a sixty-second timer would fill a log with the least important failure here.

### When the pull itself fails

**The last good policy set is KEPT and enforcement continues.** A PDP that is
down does not make this PEP stop deciding; it makes it go on deciding with what
it last pulled, and mark itself stale. The alternative — a PDP outage denying
everything everywhere — is the failure mode that makes people remove
authorization services.

That is a real trade and both surfaces say so rather than hiding it: a policy
change made during an outage is **not enforced here** until the next successful
pull. `GET /` reports `stale` and how long since the last successful pull;
`/admin/xacml/peps` reports the same thing from the other side.

**A PEP that has NEVER pulled successfully is a different state**, reported as
`loaded: false`. There is no policy, every decision is NotApplicable, and the
bias decides — which for the default deny-biased PEP means refusing everything.
"No policy" and "a policy that permits nothing" are indistinguishable from
outside and want opposite fixes, which is why they are two different reports.

---

## Configuration

All of it from the environment. No appconfig file and no settings table, and
that is not a shortcut: the mock's five-layer configuration exists to serve a
console that can change a setting while the service runs, and a PEP has no
console.

| Variable | Default | What |
|---|---|---|
| `PEP_PDP_URL` | `https://localhost:8081` | The mock. |
| `PEP_NAME` | `pep-1` | **Ignored when a client certificate is presented** — the PDP names the row from the certificate. |
| `PEP_TLS_CERT` / `PEP_TLS_KEY` | — | The client certificate. Without it the PDP refuses the registration unless `xacml.pepRequireCertificate` is off. Enforcement is unaffected either way. |
| `PEP_TLS_CA` | — | An anchor for the PDP's certificate. |
| `PEP_TLS_INSECURE` | `false` | Do not verify the PDP. **The ordinary setting against the mock**, which regenerates its key on every start and signs it itself — so there is nothing to verify against. Logged on every start, for `federation_http.js`'s reason. |
| `PEP_NOTIFY_URL` | — | Where the PDP should nudge. |
| `PEP_BIAS` | `deny-biased` | This PEP's own. |
| `PEP_POLL_INTERVAL_MS` | `15000` | **The contract.** |
| `PEP_HEARTBEAT_INTERVAL_MS` | `60000` | |
| `PEP_PORT` | `9090` | |
| `PEP_RESOURCE`, `PEP_DESCRIPTION`, `PEP_TIMEOUT_MS`, `PEP_LOG_LEVEL` | | |

**The compose service ships with no certificate**, so out of the box it
registers unauthenticated and the mock refuses it — which is the honest default
rather than a broken one. Generating one here would mean either committing a
private key to this repository (which `postgres/generate-tls.sh` exists
specifically to avoid) or a first-start script for a demonstration container.
Mount a pair to see the authenticated path. **Either way it enforces.**

**And the compose service's nudge is refused by default**: its notify URL is
plain `http` on the bridge and `xacml.pepNotifyAllowInsecure` is off. That is
the design demonstrating itself — no nudge is delivered, the PDP says why on the
PEP's row, and the PEP converges on its fifteen-second poll anyway.

---

## The two defects phase five actually had, both found by running it

1. **`certificatePlan()` takes DN fields as STRINGS and node hands back
   OBJECTS.** `getPeerCertificate()` returns `subject` and `issuer` as
   null-prototype objects of RDN types, and `String()` on one of those does not
   produce a DN — it throws `Cannot convert object to primitive value`. The
   registration answered 500 with a stack in it. Every existing caller had
   always put both through `helpers.dnRfc4514()` first, so the precondition was
   real and written down nowhere; it is written at `certificatePlan()` now. It
   was met **twice**, once per field — fixing the subject alone just moved the
   throw eighty lines down.

2. **The attribute spelling**, above. Every request denied by a policy that was
   working perfectly, which is the worst shape an authorization bug can take.

Neither would have been found by anything but running the container against the
service.
