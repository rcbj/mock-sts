# CLAUDE.md — `tests/`

## What this directory is for, and what it is NOT for

**THIS DIRECTORY HAS HELD BOTH HALVES OF THIS SERVICE'S COVERAGE SINCE
2026-08-28, AND EVERYTHING BELOW WAS WRITTEN WHEN IT HELD ONE.** Read the split
first or the rest of this file will read as though it contradicts itself:

| | What it is | Where it is authored |
|---|---|---|
| `tests/*.js` | the IN-PROCESS half — this repository's own module contracts, no port, no container, under a second | here |
| `tests/vendored/` | the PROTOCOL half — thirteen byte-identical copies of the parent's mock-only jobs, driven over HTTP against a CONTAINER built from this tree, plus the wallet modules five of them verify against | **the parent project**; not edited here |

Everything this file says about what belongs HERE is about the first row. The
second row is copies, `tests/vendored/MANIFEST.js` argues them, and the rule
that governs them is `common/vendored/`'s: **edit the parent's copy, then
`./local-run-tests.sh --vendor-sync`.** A fix made in `tests/vendored/` is
overwritten by the next sync and never reaches the stack that gates that
project.

Why they are copies at all: this repository's launcher could previously run
those jobs only when the parent checkout happened to sit beside it, so on a
machine where it did not, thirteen of twenty-three jobs were quietly absent from
a run that said "Tests passed". The suite is self-contained now — it needs no
other checkout to run any of it.

---

**This is not where the protocol suite is WRITTEN.** The suite for this service is the
parent project's `../id-proto-debugger/tests/`, and a test that drives this
service's PROTOCOL SURFACE goes there — see the "Tests" section of the
repository root's `CLAUDE.md` for the decision and how it was made. It was made
the hard way: `tests/saml11_sso.js` was written here on 2026-08-25, the first
test this repository ever had, and moved to the parent project the same day
before a second one could be written beside it.

**What lives here is a test that CANNOT live over there**, and there are now two
kinds:

| Kind | Where | Why it cannot be in the parent suite |
|---|---|---|
| An IN-PROCESS test of this repository's own MODULE CONTRACTS | here | It requires this repository's modules and `node_modules` directly, and some of what it asserts is invisible to any caller over HTTP |

There was a second row until 2026-08-26 — *an INTEGRATION test that needs
several copies of this service*, which was `../federation-e2e/` and its own
three-container stack. **TRUST REALMS closed it.** A realm is a whole logical
copy of this service on the same socket under a path prefix, so several copies
is one process now and the parent suite can reach the whole topology over HTTP:
that test is `tests/federation_sso.js` over there. Check whether realms already
answer the question before re-opening that row.

That second row is what this directory added on 2026-08-25, and the case for it
is a specific one rather than a general preference. `config_realm_layer.js`
asserts, among other things, that a trust realm carrying `oauth2.rfc9700` does
not thereby inherit `global.https`. **The parent suite could not have caught
that in any form**, because its launchers always start this service with
`STS_HTTPS=true`, and with the scheme pinned by the environment the broken and
the fixed code return the same answer. The bug is only visible with that
variable UNSET, which means varying how the process itself was started — and a
test over HTTP against a service somebody else launched cannot do that.

**So the line is: can this be asserted by driving the running service over
HTTP?** If yes, it belongs in the parent suite, where it costs one entry in
`run-report.js` and runs in the containerized stack, the host stack and the
narrowed launchers without anything being invented for it. Only if no does it
belong here.

## Running it

```bash
npm test              # from the repository root
LOG_LEVEL=debug npm test
node tests/run.js     # the same thing
node tests/run.js --only=ldif      # one file, by any part of its name
node tests/run.js --list           # what there is
```

It needs `npm install` to have been run (it uses `bunyan`, a normal dependency)
and **nothing else** — no port, no container, no browser, no network. The whole
suite is under a second. If a test here ever needs a listener, that is the
signal that it belongs in the parent suite instead.

**That paragraph is about `npm test` and the files in this directory, and it
stays exactly true.** The VENDORED half does need a port, a browser and a second
npm package (`tests/package.json` — see below); it is reached by
`./local-run-tests.sh` and never by `npm test`, which is byte for byte the run it
always was.

**`--only` IS A FILTER OVER THE DISCOVERED LIST, NOT A LIST**, which is the
distinction the design of `run.js` turns on — there is still nothing to keep up
to date — and a pattern matching nothing is an ERROR rather than an empty pass,
because a typo in a filter must never read as "everything passed".

### The report, and where the tooling lives

```bash
./local-run-tests.sh                 # ALL 23 jobs, with a report written —
                                     # the service in a container built from
                                     # this working tree
./local-run-tests.sh --no-docker     # the same, with the service run on this
                                     # machine (and what --coverage uses)
./local-run-tests.sh --keep-stack    # leave the container up afterwards
./local-run-tests.sh --no-protocol   # only the ten in-process files
./local-run-tests.sh --only=crypto --open
./local-run-tests.sh --vendor-check  # is tests/vendored/ still in sync?
./local-run-tests.sh --vendor-sync   # re-copy the parent's files over it
./docker-run-tests.sh                # the same 23 jobs with the RUNNER in a
                                     # container too: docker and nothing else
./run-coverage.sh                    # the same set, with coverage collected
```

**`./docker-run-tests.sh` IS THE SAME SUITE AND A DIFFERENT ENVIRONMENT**, and
the three files in this directory that serve it are not tests: `Dockerfile`
(node, a Chrome and this working tree), `Dockerfile.dockerignore` (which exists
only because the repository root's excludes `tests`, since the SERVICE image
must not carry the suite) and `run-tests-in-container.sh` (the image's CMD —
wait for the service, then `tools/run-report.js --service-url=http://sts:8081`).
`../docker-compose-run-tests.yml` brings the pair up.

Which to reach for: **this one when the question is the environment**, because
it needs docker and nothing else and is what CI runs, so a failure here and a
pass locally is a difference in node, in an installed package or in the image;
**`./local-run-tests.sh` when the question is a test**, because there the jobs
are node processes on this machine and re-running one costs nothing where here
it costs an image build. The jobs, the runner and the report are the same in
both.

`./local-run-tests.sh` is this repository's answer to the parent project's
launcher of the same name, and `tests/tools/run-report.js` is what it drives.
It writes `tests/report/<timestamp>/` — `report.html`, JUnit `report.xml`,
`summary.json` and one log per job — and points `tests/report/latest` at it.
Both are gitignored.

**THE TOOLING IS IN `tools/`, AND THAT IS THE ONE DECISION IN IT WORTH
ARGUING.** `run.js` discovers a test as *any `.js` file in this directory that
is not itself or `harness.js`*, so a report generator sitting beside them would
have to be added to that exclusion list — and then so would the next tool, and
the list would be exactly the "second place to forget" this directory was
designed not to have. `readdirSync` is not recursive and `/\.js$/` does not
match a directory, so a subdirectory costs the discovery rule nothing.

Three things about the report runner are decisions rather than mechanics:

* **It runs each test file in a PROCESS OF ITS OWN**, where `npm test` runs
  them all in one. That buys three things — a file that HANGS is a job that
  times out rather than a suite that never finishes, a file that takes the
  process down is one red job rather than a run with no report, and the
  process-wide state rule below stops being able to make ANOTHER file fail.
  The rule still holds, because `npm test` is what CI runs and it still shares
  one process.
* **The assertion detail is PARSED out of what the harness already prints** —
  the bunyan record whose `msg` begins with a tick or a cross. No new protocol,
  no change to `harness.js`, and every file written before the report existed
  is reported in full by it.
* **THE PROTOCOL JOBS RUN BY DEFAULT AND A JOB THAT CANNOT RUN IS A FAILURE.**
  Both changed on 2026-08-28 and both were the same mistake seen twice. The
  default used to be the ten in-process files, so a bare run answered in three
  seconds having driven no protocol endpoint, no admin console and no browser —
  and said "Tests passed". And a throwaway service that failed to start left
  thirteen jobs marked `skipped`, which the summary counts as passing, so a run
  in which nothing was checked exited zero. A skip is now only for something
  deliberately left out (`--no-browser`, `--only`); an intended job that did not
  run is red, with the reason in the row.
* **THE TEST DEPENDENCIES ARE A SECOND npm PACKAGE**, `tests/package.json`,
  carrying `commander`, `selenium-webdriver` and the `@noble`/`node-forge`
  packages the vendored wallet modules need. They are not root
  `devDependencies` because `.npmrc` carries `omit=dev` — the same trap the
  coverage renderer below was written around — and not root `dependencies`
  because a browser driver has no business in the service's production image.
  `./local-run-tests.sh` installs them when they are missing; a job that cannot
  load because they are absent FAILS naming the command, rather than skipping.
* **The VENDORED jobs run against a copy of THIS working tree, IN A CONTAINER
  since 2026-08-28.** Most of what tests this service is authored over there by
  the rule at the top of this file, and their suite drives the pinned `sts/`
  gitlink — so those jobs do not otherwise run against what you just edited.
  `./local-run-tests.sh` builds an image from this tree, brings up one
  container from the repository's own `docker-compose.yml`, and hands this
  runner its URL with `--service-url`; the jobs themselves are still plain node
  processes on this machine. About a minute plus the image build, most of the
  minute being the browser job.

  **THE LIFETIME RULE IS THAT WHOEVER STARTED IT STOPS IT**, and it is why
  `--service-url` exists rather than this runner learning to speak compose. A
  service handed in that way is never stopped here: the launcher's own trap
  owns it, which is what makes `--keep-stack` possible and what stops a run
  from tearing down a stack somebody asked to keep. `tools/service.js` — the
  throwaway process on nine ports of its own, stopped by the pid it started —
  is still what `--no-docker` uses and still the whole of what a COVERAGE run
  can use, because V8 writes its data from inside the process being measured
  and nothing here can reach into a container to collect it.

  **WHICH jobs is a LIST now, in `tests/vendored/MANIFEST.js`, and that reverses
  what this bullet said.** It used to be DERIVED — parsed out of the parent's
  own runner, so a job added or renamed over there arrived here with nothing
  edited, which is this directory's usual preference and was right while the
  files were read from over there. It stopped working when they became copies:
  the derivation's rule was "does the file mention `WSTRUST_STS_URL` or
  `OID4VCI_ISSUER_URL`", and of the nineteen files copied, `sts_applications.js`
  matches and is a HELPER while `sts_saml_encryption.js` is a job that declares
  no `--url` option at all. Two wrong answers in nineteen, and each wrong answer
  is a job that silently never runs — which is the exact failure the same day's
  other two changes were made to stop. The list is the price of vendoring; it is
  not a precedent for listing anything else here.

**A protocol job can be AHEAD of this tree** — that suite is developed against
its own checkout of this service — in which case it fails here naming a feature
this tree does not have. That is information about the two checkouts and not a
fault in the runner, which is why the report says which side every job came
from.

## Adding one

Drop a `.js` file in this directory. There is **no list to update** — `run.js`
discovers every `.js` file that is not itself or `harness.js` — and that is
deliberate: the standing objection to a second suite is that it means a second
place to forget, so this one has no such place. A test module exports:

```js
module.exports = {
  name: 'config_realm_layer',        // names its log lines
  describe: 'one line, printed before it runs',
  run: function (t) { ... }          // may be async
};
```

`t` is a harness from `harness.js`: `t.check(condition, what, detail)`,
`t.equal(actual, expected, what)`, `t.ok`, `t.bad`, and `t.log` (a bunyan
logger). **Do not throw for an ordinary failure** — a throw is reserved for a
test that could not RUN, and `run.js` reports that differently on purpose,
because a test that did not run has not passed.

Two rules that are not optional here:

* **MUTATION-TEST IT BEFORE COMMITTING IT.** Break the thing it guards, watch it
  go red, put it back. The whole reason this directory exists is that three
  defects in one day produced no error anywhere; a guard that has never failed
  has not been shown to guard anything. `config_realm_layer.js` was checked
  against four mutants — the derived-default fix reverted, `checkRealmOverride`
  dropping its `forRealm` argument, the `realmRuntime` marker deleted, and
  `create()` ignoring the overrides it was given — and each was caught by
  between four and seven assertions. `realm_isolation.js` was checked
  against two — the identity register put back to a plain `Map`, and one
  shared revocation `Set` behind the same call shape — caught by five
  assertions and by three. `realm_directory_lookups.js` was checked against
  four while the guards were per-lookup — each of the three group doors put
  back to a bare `getEntry()`, and `inRealm()` stripped of the default realm's
  carve-out — and against two more after the store was split per realm, which
  is what those guards became: a `getEntry()` that reaches into every realm's
  store (5 assertions red) and an `eachEntryInRealm()` that walks them all (1).
  **The file did not change between the two rounds**, which is the argument for
  asserting behaviour rather than mechanism: the mechanism was replaced and the
  test still guarded the thing that matters.
  `delegation_map_bands.js` was checked against four — the issuer put back into
  the dagre layout (5 assertions red), the label rows' overlap check removed so
  every label lands in one row (1), the hexagon placed at the left instead of
  centred (2), and the empty-picture case padded with the band it does not need
  (1). The third of those found a real coupling while it was being written: the
  hexagon's position was written out twice, once where it is placed and once
  where a label's line is solved for, and moving one drew every label a few
  pixels BESIDE its own line rather than drawing the hexagon in the wrong
  place. It is one `stsAt` now.
  `spnego_identity.js` was checked against six — `usernameFor()` stripping
  EVERY realm rather than only the local one (3 assertions red), `factorsFor()`
  claiming `pwd` for a ticket that claims nothing (10), reading `initial` as
  evidence that a password was checked (2), calling a lone hardware factor
  `mfa` because it is phishing-resistant (1), splitting the principal on the
  FIRST `@` rather than the last (1), and collapsing the four method sentences
  into one (1). The second of those is the case the file exists for and it is
  the one no test over HTTP could have run: this KDC requires
  pre-authentication, so no client can obtain a ticket claiming neither flag,
  and `hw-authent` is never set by anything here at all — a test over there
  would have exercised one branch of four and reported green over the rest.
* **CLEAN UP THE PROCESS-WIDE STATE YOU TOUCH.** The realm table and
  `process.env` are shared by every test in the run, so a realm left behind
  changes what a later test resolves. Use the `withEnv()` / `withRealm()` shape
  in `config_realm_layer.js`: save, act, restore in a `finally`.

  **This rule used to be justified by "and this service persists nothing", and
  that clause is gone as of 2026-08-27** — see `persistence/CLAUDE.md`. The rule
  is unchanged and is now slightly more important rather than less: leftover
  state was always visible to the rest of the run, and a test that reached a
  persistent store could leave it visible to the next RUN as well. In practice
  it cannot, because `persistence.mode` defaults to `memory` and every test here
  deletes `CONFIG_FILE` before requiring anything — so nothing in this directory
  opens a store — with ONE exception since 2026-08-28. **A test that
  deliberately turned one on would be the first, and it would have to clean up
  a directory or a database rather than a Map**; the codec test avoids that by
  testing the codec rather than the driver.

  **`appconfig_persistence.js` IS that test, and it took the condition this
  paragraph set.** It writes into a directory of its own under the system
  temporary directory, made per run with `mkdtemp`, and removes it in a
  `finally` — including when an assertion has failed, since a failing run is
  exactly the one that would otherwise leave the litter behind. It also puts
  back the five `STS_PERSISTENCE_*` variables, the override it sets and the
  realm it creates, and it STOPS the store before removing the realm, so a
  scheduled flush cannot fire against a table the realm has already gone from.

## What is in here

| File | What it guards |
|---|---|
| `config_realm_layer.js` | what a trust realm may and may not carry, at the writing end and at the reading end |
| `realm_isolation.js` | that a realm's identity register and its revocation set are its own, in both directions, and that removing a realm takes them with it |
| `realm_directory_lookups.js` | that a lookup BY DN answers about one realm — groups, people and applications — including that a refused cross-realm delete leaves the entry where it was |
| `delegation_map_bands.js` | that the delegation picture is TWO BANDS — the issuer above, centred, every party on one plane — and that no two edge labels are drawn on top of each other |
| `federation_map_bands.js` | that the federation picture is THREE BANDS — left asks, right authenticates — that the four relationship states are four distinguishable strokes, that a brokered partner is ONE arrow which keeps that pair's counts, and that the per-application counts either add up or report the difference |
| `spnego_identity.js` | what a SPNEGO sign-in claims: which part of a Kerberos principal becomes the session's username, and the `amr`/`acr` read off the ticket's own flags |
| `ldif_codec.js` | that every value this service can put in an attribute survives the RFC 2849 round trip `persistence.mode=ldif` writes — the base64 rules, the folding, `origin` riding as a comment, and a URL-valued attribute being refused rather than dereferenced |
| `appconfig_persistence.js` | that a setting change reaches the store ON DISK, comes back the way the next start puts it back, and that a realm's settings and the process's are two different files |

**`vendored/` is not in that table either, and for the opposite reason: it is
ALL tests.** Thirteen jobs and the twenty files they need, copied from the
parent project, listed and argued in `tests/vendored/MANIFEST.js`. They are not
described here one by one because they are not this repository's to describe —
`docs/test-suite-map.md` over there is where each is written down, and a
paragraph here would be a second copy of it that drifts.

`tools/` is not in that table because nothing in it is a test:
`run-report.js` (the report generator), `coverage-report.js` (the V8 coverage
renderer), `vendor-check.js` (the drift check over `vendored/`, and a TOOL
rather than a job on purpose — its own header argues why a check that needs the
other checkout must not be what decides whether this repository is green),
`service.js` (one throwaway copy of this service, started and
stopped by pid, on nine ports of its own) and `coverage_entry.js` (`server.js`
started so that its coverage survives being stopped — V8 writes on a CLEAN
exit, and a service is stopped with a signal, so without this the protocol half
of a coverage run is silently empty).

Both realm files bend the rule at the top of this file, and each says so in
its own header rather than leaving a reader to catch it.
`realm_directory_lookups.js` carries one gap worth knowing: the LDAP SOCKET
half of the same fix — a subtree search is scoped to the realm its base
names — needs a listener to test, so by this file's own rule it is not
asserted here. It was verified by hand, and `ldap/CLAUDE.md` records what
was checked.

`spnego_identity.js` passes it on the same clause `config_realm_layer.js`
does — **the cases worth asserting cannot be produced by driving the running
service.** A ticket carrying neither `pre-authent` nor `hw-authent` is where an
implementation is most tempted to fill in a plausible value, and this KDC
requires pre-authentication so no client can obtain one; `hw-authent` is set by
nothing in this repository, so the two-factor branch is unreachable from
outside the process entirely. The end-to-end claim — a real AP-REQ over a real
socket producing a real session — needs a listener and belongs in the parent
suite beside `krb5_spnego_http.js`, which already drives the acceptor that door
shares.

`delegation_map_bands.js` passes the rule at the top of this file on a
different clause from the realm files': `render()` is a pure function from a
graph to an SVG document — no store, no config, no request — so the cases worth
asserting are ones the running service cannot be made to produce on demand. A
graph whose issuer lines all end within a few pixels of each other, or an
issuer with nothing attached to it at all, would mean driving protocol traffic
until the register happened to hold the right shape. The geometry would have to
be parsed back out of the answer either way; what cannot be done from over
there is CHOOSING the graph. What it does NOT assert is the model half of the
same change — that an access token's audience becomes a line at all — because
that one IS drivable over HTTP and belongs in the parent suite by the rule
above. It was verified by hand against a four-tier chain; `common/CLAUDE.md`
rule 3p records what the rule is.

`federation_map_bands.js` passes on both of `delegation_map_bands.js`'s clauses
at once, which is why it is one file rather than two. The DRAWING half is a pure
function from a graph to an SVG document, so the cases worth asserting — a
relationship in each of the four states at once, a broker whose onward partner
is disabled — are ones the running service cannot be made to produce on demand.
The MODEL half asserts arithmetic a page rounds off: *the per-application rows
sum to less than the relationship's own total, by exactly the number of sign-ins
that named no configured application* is a statement about two registers, and
the only way to see it over HTTP is to have already trusted the number being
checked. What it does NOT assert is the SIGN-IN PATH that fills the attribute —
that the login endpoint carries the application across the round trip, and that
all five `completeSignIn()` call sites pass it — because that IS drivable over
HTTP and belongs in the parent suite by the rule at the top of this file. It was
verified by hand against five real federated sign-ins; `federation/CLAUDE.md`
records what was checked.

It was mutation-tested against SIX mutants and each was caught: the `asks` arrow
reversed in the model (5 assertions red), the broker dedupe removed so a
brokered partner is drawn twice (5), the layout flipped to `rankdir: 'RL'` (4),
a partner shape dropped so its box is never emitted (1),
`applicationConfiguredFor()` replaced with "believe whatever the request named"
(2), and the unattributed remainder stopped being computed (2). **The first of
those is worth reading**: it was caught by the BROKER assertions and not by the
band ones, because the band assertions build their graph by hand — so the two
halves guard different things and the mutants that prove it are the layout ones,
which the band assertions did catch. A guard that had only the hand-built graph
would not have noticed the renderer.

`realm_isolation.js` is the one closest to the line: the leak it guards IS
observable over HTTP. It is here because the parent project's
`sts/` gitlink is pinned at a commit from before this repository was
reorganised — so a guard written over there today does not run against this
code — and because the purge half of it cannot be seen from outside at all,
where "purged" and "never existed" look identical. If the pin is ever bumped
the first reason goes away and the second one does not.

`ldif_codec.js` passes the rule at the top of this file on the clearest clause
any file here has had: **the failure is invisible until a restart, and it
happens in a different process.** A value written wrongly — a leading space
eaten, a folded line rejoined without its fold, UTF-8 mangled — is still in
memory and still correct on every endpoint for the whole life of the process
that wrote it. Nothing an HTTP client can ask shows it. The damage appears on
the next start, as an attribute that is quietly not what it was, in a file that
is still perfectly valid LDIF. The codec is also a pure function of a string, so
a test that started a listener to reach it would be slower and no more
convincing.

`appconfig_persistence.js` passes on the same clause one step further along,
and it is the file that says what the line is FOR. The parent suite's
`sts_admin_console.js` and `sts_admin_api_operations.js` go as far as anything
driving the running service from outside can — the first of them in a real
browser since 2026-08-28, which changes nothing about this line: they watch `/admin-api/persistence`'s write counter move, its dirty
flag clear and its failure counter stay put. That is still an assertion about a
number the service computed about itself. **What is IN the file cannot be asked
over HTTP at all**, and the failure is invisible until a restart, in a different
process — a value written with the wrong type, or not written, is correct on
every endpoint for the whole life of the process that made it, and the damage
appears on the next start as a setting that has quietly gone back to its
default. So this file drives the real modules in process against a temporary
directory and then READS the files.

**It drives `ldif` and not `postgres`, and that is this directory's rule rather
than an omission.** Both modes sit behind ONE driver interface, so everything
asserted there — which of the three things is dirty, which store it belongs in,
what `applyPersistedOverrides()` does with what comes back — is the same code
path either way; what differs is the driver's own SQL, and reaching that needs a
database, which is the one thing the *Running it* section says a test here may
not need. The postgres driver is covered by
`tests/sts_persistence_postgres.js` in the parent suite, which stands up a
database and a mock of its own and RESTARTS it — the assertion no test in
either directory could make before, because every other job drives a service
somebody else started.

It fills `persistence.setDirectory()` with two functions rather than requiring
`ldap/ldap_server.js`, and that is a decision rather than a shortcut: the
directory half has its own coverage in `ldif_codec.js`, what is under test here
is the APPCONFIG and REALM halves, and requiring the real directory would mean
requiring the console, which requires the authorization server, which is most of
the service.

**Its mutation record carries the same lesson `ldif_codec.js`'s does, and found
it the same way.** Four mutants, and one of them survived the first version
TWICE, for two different reasons. `setOverride()` writing into the process-wide
map regardless of the realm was caught (2 assertions red), and `clearOverride()`
not telling the store was caught (1). The realm branch of `configChanged()`
switched off entirely was caught by NOTHING: the first version set the realm's
value through `realms.setOverride()`, which writes the realm row directly and
fires the realm change event, so it never reaches `configChanged()` at all. The
write goes through `config.setOverride()` with the realm AMBIENT now, which is
what every door a person uses actually does — and that still was not enough,
because creating a realm makes the registry dirty on its own, so the create's
write and the override's write coalesced into one and the assertion passed
whether or not the override had scheduled anything. **The line that catches it
is a `flush()` between the two**, and it is commented as such, because it reads
like tidiness and is the whole guard.

The fourth mutant — `checkOverride()` losing its `forRealm` default — is NOT
caught here and is not meant to be. `setOverride()` passes that argument
explicitly because it has the realm in hand, so in process the default is
unreachable; what it fixes is the three call sites in `admin-ui/admin.js` that
pre-validate a whole section before writing any of it, and those are only
reachable over HTTP. That mutant is caught by `tests/sts_admin_console.js` in
the parent suite, which presses the Save button those call sites are behind.
**Two halves of one fix, each guarded where it is observable**, is what this
directory's line looks like when it is working.

**`ldif_codec.js`'s mutation record is the one to read before writing the next
file here**,
because one of its four mutants SURVIVED the first version and the reason is
general. Three were caught immediately: dropping the trailing-space rule from
`needsBase64()` (1 assertion red), folding one column too wide (3), and ignoring
the `# sts-origin:` comment on the way in (2). The fourth — unfolding with
`.trim()` instead of `.slice(1)`, which eats the value's own whitespace at a
fold boundary — was caught by NOTHING, because every folded value the file tried
was a run of one repeated letter and trimming removed nothing. The assertion
that catches it had to be constructed: a value whose own space falls exactly on
the fold boundary, so the continuation line begins with two spaces. **A round
trip over convenient data is the shape that passes while proving nothing**, and
the only reason that was found before it was committed is that the mutation
round is mandatory here.

## What it does not do

No framework, no `describe`/`it`, no assertion library, no `devDependencies`.
The moment this needs a dependency to RUN, it stops being cheaper than the
parent suite and the argument for its existence goes with it.

**THAT SENTENCE SAID "no coverage, no reporter plug-in" UNTIL 2026-08-28, AND
BOTH OF THOSE NOW EXIST — WITH THE RULE ITSELF UNCHANGED**, which is the only
reason they were allowed. `npm test` is byte for byte the run it always was:
`bunyan` and node, nothing added, nothing to install. The report generator and
the coverage renderer are separate entry points in `tools/` that use node
builtins and the same one dependency, and NOTHING requires them.

The coverage renderer is the case that had to be argued rather than assumed.
The obvious answer is `c8`, which is what the parent project renders two of its
three domains with — and it is the wrong answer HERE for a specific reason:
`.npmrc` in this repository carries `omit=dev` and the Dockerfile passes
`--omit=dev` besides (it is what keeps ldapjs's ~200 test packages out), so a
`devDependency` added for coverage would be **silently not installed** by the
ordinary `npm install` and the script would fail for everybody with a message
about a missing binary. So the collection is node's own `NODE_V8_COVERAGE` —
no wrapper binary in the spawn path, nothing for a test to opt into — and
`tools/coverage-report.js` renders V8's data directly. The raw JSON is left in
`coverage/raw/` for anybody who would rather point c8 at it themselves.

**What that report can and cannot say is written at the top of that file and is
worth reading before quoting a number from it.** Function coverage is exact:
V8 counted the calls. Line coverage is DERIVED — a line's count is that of the
innermost V8 range containing its first non-blank character, and a line counts
as code when it is neither blank nor wholly a comment. There are no branch
numbers at all, because V8's block ranges are not branch arms and a percentage
with no definition is worse than none.
