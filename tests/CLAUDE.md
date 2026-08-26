# CLAUDE.md — `tests/`

## What this directory is for, and what it is NOT for

**This is not the suite for this service.** The suite for this service is the
parent project's `../oauth2-oidc-debugger/tests/`, and a test that drives this
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
```

It needs `npm install` to have been run (it uses `bunyan`, a normal dependency)
and **nothing else** — no port, no container, no browser, no network. The whole
suite is under a second. If a test here ever needs a listener, that is the
signal that it belongs in the parent suite instead.

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
* **CLEAN UP THE PROCESS-WIDE STATE YOU TOUCH.** The realm table and
  `process.env` are shared by every test in the run and this service persists
  nothing, so a realm left behind changes what a later test resolves. Use the
  `withEnv()` / `withRealm()` shape in `config_realm_layer.js`: save, act,
  restore in a `finally`.

## What is in here

| File | What it guards |
|---|---|
| `config_realm_layer.js` | what a trust realm may and may not carry, at the writing end and at the reading end |
| `realm_isolation.js` | that a realm's identity register and its revocation set are its own, in both directions, and that removing a realm takes them with it |
| `realm_directory_lookups.js` | that a lookup BY DN answers about one realm — groups, people and applications — including that a refused cross-realm delete leaves the entry where it was |
| `delegation_map_bands.js` | that the delegation picture is TWO BANDS — the issuer above, centred, every party on one plane — and that no two edge labels are drawn on top of each other |

Both realm files bend the rule at the top of this file, and each says so in
its own header rather than leaving a reader to catch it.
`realm_directory_lookups.js` carries one gap worth knowing: the LDAP SOCKET
half of the same fix — a subtree search is scoped to the realm its base
names — needs a listener to test, so by this file's own rule it is not
asserted here. It was verified by hand, and `ldap/CLAUDE.md` records what
was checked.

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

`realm_isolation.js` is the one closest to the line: the leak it guards IS
observable over HTTP. It is here because the parent project's
`sts/` gitlink is pinned at a commit from before this repository was
reorganised — so a guard written over there today does not run against this
code — and because the purge half of it cannot be seen from outside at all,
where "purged" and "never existed" look identical. If the pin is ever bumped
the first reason goes away and the second one does not.

## What it does not do

No framework, no `describe`/`it`, no coverage, no reporter plug-in, no
`devDependencies`. The moment this needs a dependency to run, it stops being
cheaper than the parent suite and the argument for its existence goes with it.
