# xacml/ — the XACML 3.0 engine

**This directory is currently the ENGINE and nothing else.** There is no route
here, no console page, no store, no PIP and no `/admin-api` operation, and
`server.js` does not require anything in it. That is phase one of a five-phase
piece of work and is deliberate: the engine is where all the risk is, and it is
checkable against somebody else's reading of the specification before a single
line of it is wired to a port. See *What is not here yet*.

## What is here

| File | What it is |
|---|---|
| `xacml_model.js` | The vocabulary: the identifiers the specification fixes, the shape of a policy tree, and the seven decision values. **No I/O.** |
| `xacml_datatypes.js` | The seventeen datatypes — parse, write, equality, ordering. The table every function is generated over. **No I/O.** |
| `xacml_functions.js` | The standard function library: 275 identifiers, about thirty implementations. **No I/O.** |
| `xacml_validate.js` | Static type checking. What a policy is REFUSED for at load, before any request. **No I/O.** |
| `xacml_xml.js` | XACML 3.0 core XML → the model, and a response back. The first of three readers. |
| `xacml_pdp.js` | Evaluation: targets, rules, conditions, the twelve combining algorithms, obligations. **No I/O.** |
| `conformance/` | The vendored OASIS suite. `PROVENANCE.md` is the argument, `MANIFEST.js` the drift check. **Not edited here, ever.** |

The test is `tests/xacml_conformance.js` — in-process, no port, no container,
about a second.

## The one rule this directory is built on

**One model; XML, JSON and ALFA are three renderings of it.**

`xacml_model.js` is what all three readers produce and what `xacml_pdp.js`
evaluates. **If a function in `xacml_pdp.js` ever asks which syntax a policy
arrived in, this separation has failed** and the fix belongs in the model
rather than in the evaluator.

The argument is `common/vendored/xmldsig.js`'s, one layer up: a grammar is a
READING, and three readings are three chances to disagree with the PDP at the
far end — which for authorization means a decision nobody can reproduce. It is
also what makes ALFA cheap when it lands: a parser and an emitter, not a second
policy system.

## Where it stands against the conformance suite

**454 of 455 mandatory cases**, with the one exception recorded in
`conformance/MANIFEST.js`'s `EXPECTED_FAILURES` and argued there.

```
IIA   attribute references     18 of 18
IIB   target matching          55 of 55
IIC   the function library    261 of 261
IID   combining algorithms     57 of 57
IIE   policy references         2 of 3    (IIE003 — see EXPECTED_FAILURES)
IIF   other mandatory           3 of 3
IIIA  obligations              58 of 58
```

**The first run scored 6 of 455 and the second 434**, and what the difference
between those two numbers records is worth more than the final one: every
defect below was found by the suite and none of them would have been found by a
test written here.

## The seven defects the suite caught, because each will be made again

Each of these produced an engine that looked correct, ran without error, and
was wrong. They are written up beside the code that fixes them; this is the
index.

1. **`errorHandler` is not a deprecated option in @xmldom/xmldom 0.9, it
   THROWS.** Passing both spellings defensively made every parse fail before a
   document was read — 449 cases reporting "could not be loaded" and naming an
   option rather than a policy. `xacml_xml.js`, `parseDocument()`.

2. **A combining algorithm CONTROLS EVALUATION; it is not handed results.** The
   specification's pseudocode returns from inside the loop, so a
   `deny-overrides` set whose fourth policy denies never evaluates the fifth.
   Evaluate all five and combine afterwards and the DECISION is identical every
   time — but the fifth policy's OBLIGATION is now in the response. Eight IID
   cases. `xacml_pdp.js`, above `COMBINERS`.

3. **NaN equals NaN.** XML Schema defines xs:double equality over a value space
   holding exactly one NaN and XACML defers to it, so `double-equal(NaN, NaN)`
   is True — the opposite of IEEE 754 and of `a === b`. IIC350, IIC358.
   `xacml_datatypes.js`, the double row.

4. **Date arithmetic is on the LOCAL components; the timezone is a label.**
   Normalising to UTC, adding, and re-labelling with the original offset shifts
   twice and lands five hours out — while still producing a well-formed
   dateTime. IIC102, IIC104. `xacml_functions.js`, `addSeconds()`.

5. **`only-one-applicable` must go through the same obligation collection as
   every other algorithm.** Returning the selected policy's result directly
   dropped the POLICY SET's own obligations and kept the policy's, which is a
   response that is right about the decision and short by half on what the PEP
   must do. IIIA025, IIIA026. `xacml_pdp.js`, `evaluatePolicySet()`.

6. **XACML is statically typed and a policy that does not typecheck must be
   REFUSED at load.** Five cases exist for this and for nothing else — a
   designator passed where a primitive is required (the commonest mistake in
   hand-written XACML), a Condition returning an integer, a string literal in
   an integer argument, a literal substring index out of range. Without the
   check all five load happily and produce a decision. `xacml_validate.js`.

7. **A rule's obligations must be resolved AT the rule.** XACML 3.0 put
   obligations on rules as well as policies, and the rule is the only place its
   variables are still in scope. `xacml_pdp.js`, `firedRule()`.

## Three things about the specification that catch everybody once

**The version segment in a function URI is not predictable.** Most standard
functions are `1.0`; every function of the two DURATION types is `3.0`, because
those types moved namespaces; and the six higher-order functions split across
both — `any-of`, `all-of` and `any-of-any` are 3.0 while `all-of-all`,
`all-of-any` and `any-of-all` are 1.0. This is the specification's own
inconsistency. It is why `xacml_model.js` spells every identifier out instead
of building one by concatenation: a wrong URI matches nothing and fails as
`NotApplicable`, which is not an error anywhere.

**There are seven decisions, not four.** `Indeterminate{P}`, `{D}` and `{DP}`
exist for the combining algorithms and for nothing else, and collapsing them
makes `deny-overrides` return Permit where the specification says Deny — a
policy that permits because an attribute lookup failed. `externalDecision()`
folds them down ONCE, at the bottom of `evaluate()`; a second call site
anywhere is a bug.

**Every value is a bag.** An `AttributeDesignator` returns a bag even when it
finds one value, which is why `string-one-and-only` exists and why IIC003 is an
invalid policy. Nothing here ever holds a bare value, so there is no code path
where somebody has to remember to wrap one.

## What is not here yet

Phases two to five, in order. Each is a separate piece of work and none of it
is started.

* **The store and the PIP.** Policies as directory entries under `ou=policies`
  — the shape `ou=federations` already has, which is what gets Postgres, LDIF
  and per-realm isolation for free. `xacml_pip.js` resolves a designator out of
  the embedded directory.
* **The PAP.** A `Protocols → XACML` group in `admin-ui/admin.js`'s `SECTIONS`,
  with a guided policy editor. **It will have no JavaScript**: this console is
  `script-src 'none'` and `admin-ui/CLAUDE.md` refuses a script nine times over,
  so the "pick the next valid element" dropdowns are a `<select>` per node whose
  options are computed on the server and whose choice is a form POST.
  `xacml_validate.js`'s `problemsIn()` is what renders beside the form.
* **ALFA.** `xacml_alfa.js`, a parser and an emitter over the same model.
* **The remote PEP.** `xacml-pep/`, its own container, registering over mutual
  TLS on the main port — which already asks for a client certificate
  (`server.js`'s `requestCert: true`), so no new listener is needed — and
  mapping the certificate through `ldap_server.js`'s existing
  `certificatePlan()` rather than a second mapping.

**When the routes land, the checklist is `ssf/CLAUDE.md`'s** *WHAT ADDING A
PROTOCOL FAMILY COST HERE*. The rows that get forgotten are not the protocol's
own endpoints — they are the console and `/admin-api` ones, and
`tests/vendored/sts_metadata.js` is what catches them.

On the require order: this directory will sit at **23c**, after
`ldap/ldap_server` (21) for the directory and after `admin-ui/admin` (18) for
the shell, and it will fill a slot on `admin.js` rather than being required by
`mgmt-api/admin_api.js` (19) — a require from 19 to 23c would drag every
`/xacml` route ahead of the management API's own. That is rule 3e's test,
answered in both directions the way SSF answered it.
