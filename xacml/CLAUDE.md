# xacml/ — the XACML 3.0 engine

**Phases one to three are here: the ENGINE, the STORE, the PIP, a service
surface and the PAP.** `server.js` requires `xacml.js` at 23c, four routes
answer under `/xacml`, four console pages under `/admin/xacml`, twelve
operations under `/admin-api/xacml`, and policies live in `ou=policies` in the
embedded directory.

**What is NOT here is ALFA and the remote PEP** — phases four and five. See
*What is not here yet*.

## What is here

| File | What it is |
|---|---|
| `xacml_model.js` | The vocabulary: the identifiers the specification fixes, the shape of a policy tree, and the seven decision values. **No I/O.** |
| `xacml_datatypes.js` | The seventeen datatypes — parse, write, equality, ordering. The table every function is generated over. **No I/O.** |
| `xacml_functions.js` | The standard function library: 275 identifiers, about thirty implementations. **No I/O.** |
| `xacml_validate.js` | Static type checking. What a policy is REFUSED for at load, before any request. **No I/O.** |
| `xacml_xml.js` | XACML 3.0 core XML → the model, and a response back. The first of three readers. |
| `xacml_pdp.js` | Evaluation: targets, rules, conditions, the twelve combining algorithms, obligations. **No I/O.** |
| `xacml_json.js` | The JSON Profile 1.1 request and response — what anybody actually sends. The second reader. **No I/O.** |
| `xacml_store.js` | The repository. Owns the policy schema; `ou=policies` IS the store. |
| `xacml_pip.js` | Attribute resolution off the subject's own directory entry. |
| `xacml.js` | The protocol routes: four under `/xacml`, plus the embedded PEP. |
| `xacml_templates.js` | RBAC and ABAC starting points. **Adding one is a row in `TEMPLATES` and nothing else.** No DOM. |
| `xacml_editor.js` | The editor's GRAMMAR: what may be added where, and how one edit is applied. **No DOM** — which is what lets the menus be asserted in node. |
| `xacml_admin.js` | The four `/admin/xacml` console pages and their actions. |
| `conformance/` | The vendored OASIS suite. `PROVENANCE.md` is the argument, `MANIFEST.js` the drift check. **Not edited here, ever.** |

Three tests, all in-process, no port, no container:
`tests/xacml_conformance.js` (the engine, against 455 cases somebody else
wrote), `tests/xacml_service.js` (the store, the PIP, the JSON Profile and the
PEP) and `tests/xacml_pap.js` (the templates, the editor grammar and the XML
writer).

## The console

```
/admin/xacml            settings, and what the PDP decides with
/admin/xacml/policies   the repository; enable, disable, root, delete,
                        create from an RBAC or ABAC template
/admin/xacml/editor     the guided editor
/admin/xacml/decide     ask the PDP and see what the PEP would do
```

**The editor has no JavaScript, and that is argued rather than assumed.** This
console is `script-src 'none'` and `admin-ui/CLAUDE.md` refuses a script nine
times over under a rule that the argument must be *made* each time — the test
being whether the page CANNOT work without one. An editor can. So every
"pick the next valid element" dropdown is a `<select>` whose options were
computed on the server by `xacml_editor.js`, and choosing one is a form POST.

*What it costs*: a round trip per element — a five-rule policy built by hand is
perhaps forty POSTs. The page says so; the templates are the answer.

*What it buys*: the menu is computed by the same process that will validate the
policy, against the real function library, so **the editor cannot offer
something the validator will then refuse**. A browser-side editor would have
needed a second copy of the grammar shipped to the page, and a second copy of a
grammar is what this whole directory is arranged to avoid.

**The editor holds no session state.** The draft IS the stored policy: every
edit loads the document, applies one change, serializes and writes back. There
is nothing to lose when a browser closes and no second copy that could disagree
with the stored one. The cost is that editing is LIVE, so the page says so and
puts the disable control one click away.

**Every element arrives complete and valid** — a new rule has a Target and an
Effect, a new Match has a function, a value and an attribute — because an
editor that produced half-built elements would hold a document that cannot be
saved, and a document that cannot be saved cannot be evaluated, which is when
you most want to look at it.

## The surface

```
GET  /xacml            what this is; ?format=json for the same as data
POST /xacml/pdp        a decision. JSON Profile in, JSON Profile out
GET  /xacml/policies   the repository as the PDP sees it, documents included
GET  /xacml/protected  the embedded PEP — 200 or 403
```

`POST /xacml/pdp` **authenticates nobody**, and for once that is not only the
house rule. A PDP is not an authorization boundary — it answers a question
about somebody else's. The identity that matters is IN the request, not on the
connection. Phase five's mutual TLS authenticates WHICH PEP is asking, which is
a different question from who the decision is about, and conflating the two is
how a PDP ends up deciding about whoever holds the client certificate.

## Where a policy lives

`ou=policies` in the embedded directory **is** the repository, the way
`ou=federations` is the federation register. That buys three things and none of
them is tidiness: persistence in all three modes with no driver change,
per-realm isolation for free, and `ldapsearch` and `/admin/ldap/directory` as
inspection tools that already exist.

The entry holds the **document as authored** and everything else on it is
derived at write time — so where the two disagree, the document wins. A write
goes through static validation, so a policy that does not typecheck is refused
while somebody is still looking at it rather than going Indeterminate on every
request for ever.

**One policy is seeded**, role-based, and the seeded directory was given
`employeeType` to match it — alice and bob are staff, carol is admin. The two
seeds have to agree or neither demonstrates anything: a policy granting on an
attribute nobody has answers Deny for everybody, which looks exactly like a
broken PDP.

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

## Four more defects, from phase two, and all four were silent

The engine's seven are below; these are from wiring it up. Every one of them
left a service that started, answered every request, logged nothing unusual,
and decided incorrectly. `tests/xacml_service.js` asserts each.

1. **LDAP ATTRIBUTE NAMES COME BACK LOWER-CASED.** RFC 4512 makes them
   case-insensitive and this directory normalises them, so a store that asks
   for the `xacmlPolicyDocument` it wrote gets `undefined`. Every field of
   every policy read back empty, `root()` found nothing, and the PDP answered
   NotApplicable to everything with a policy plainly sitting in `ou=policies`.
   `federation.js` reads `stored.attributes.fedid` in lower case for exactly
   this reason.
2. **THE SAME BUG IN THE PIP IS QUIETER AND WORSE.** A missing attribute is a
   *legitimate* answer, so there was nothing to report: the PDP simply decided
   as though the person held no roles.
3. **THE SEED RAN BEFORE THE STORE HAD ITS DIRECTORY.** `ldap_server.js` seeds
   at require time and fills the store's slot further down the same file. It is
   seeded at the slot-fill site now, guarded on the repository being EMPTY
   rather than on the container being new — those are different facts once
   persistence is in play, and the second would re-seed a policy an operator
   deleted on purpose.
4. **JSON HAS ONE NUMBER TYPE.** `5` and `5.0` both parse to `5`, so the
   integer/double distinction survives only in the source text.
   `xacml_json.js` re-scans the raw body for it.

## The seven defects the conformance suite caught, because each will be made again

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

Phases four and five. Neither is started.

* **ALFA** — `xacml_alfa.js`, a parser and an emitter over the same model, and
  a third tab on the editor. The XML writer landed in phase three, so ALFA in →
  model → XML out is now the whole of what an ALFA compiler is here. ALFA is an
  OASIS **Committee Specification Draft** rather than a ratified standard, and
  the page will say so — the way `docs/xmldsig-pqc.md` labels every draft URI.
* **The remote PEP** — `xacml-pep/`, its own container, registering over mutual
  TLS **on the main port**, which already asks for a client certificate
  (`server.js`'s `requestCert: true`), so no new listener is needed. The
  certificate maps to a directory entry through `ldap_server.js`'s existing
  `certificatePlan()` rather than a second mapping. It carries its own copy of
  the engine, because pushing *policies* to a PEP only makes sense if it
  evaluates them — otherwise you would push decisions.
* **`AttributeSelector` and the XPath functions.** A policy using one is
  Indeterminate rather than silently empty, which is the deliberate choice: an
  empty bag is a perfectly ordinary result a policy may be written to expect,
  so returning one would make an unimplemented feature look like a decision.

## What phase three actually cost outside this directory

For the next person adding a console surface, following the shape
`ssf/CLAUDE.md` records:

* `common/config.js` — the `xacml.pepBias` row needed **`enumValues`**, not
  `values`. The wrong key name is not a startup error: the setting loads, the
  service runs, and the settings form throws a 500 on the one page that draws
  it.
* `admin-ui/admin.js` — the **tenth slot** `setXacmlPages()`, a `SETTING_HOMES`
  row (its absence is what the boot warning was about), an `XACML` group of
  four in `SECTIONS` with a `blurb` each, and three helpers exported that had
  been private: `configFormsFor`, `configSettingsJson` and `respondToAction`.
* `mgmt-api/admin_api.js` — three GETs and a POST with nine documented actions;
  `mgmt-api/admin_api_spec.js` — `Xacml`, `XacmlPolicies` and `XacmlEditor`.
* `sts_metadata.js` — **eight** `ENDPOINTS` rows, four of them console pages
  and four management API, which are again the ones a checklist forgets.

**The one thing that is not a file**: `protocolSettingsJsonFor()` is NOT the
JSON counterpart of `configFormsFor()`. It is keyed by admin.js's own
`PROTOCOL_SETTINGS_PAGES` table and **throws** for a path that table does not
carry — correct for the pages that file generates, and a 500 for one drawn
anywhere else. `configSettingsJson()` is the right function and is now
exported beside the renderer it belongs to.
