# xacml/ — the XACML 3.0 engine

**All five phases are here: the ENGINE, the STORE, the PIP, a service surface,
the PAP, ALFA and the REMOTE PEP.** `server.js` requires `xacml.js` at 23c,
seven routes answer under `/xacml`, five console pages under `/admin/xacml`,
seventeen operations under `/admin-api/xacml`, policies live in `ou=policies`
in the embedded directory and registered remote enforcement points in
`ou=peps`.

**The remote PEP is a SECOND CONTAINER and it is not in this directory** — it
is `xacml-pep/`, which has a `CLAUDE.md` of its own and is the only directory
in this repository that is not part of the mock. What is here is the PDP's side
of it: the register, the three endpoints under `/xacml/pep`, the console page
and the nudge.

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
| `xacml_alfa.js` | ALFA read and written — the third rendering, and the one people want to look at. **No DOM.** |
| `xacml_pep_registry.js` | The register of REMOTE enforcement points. `ou=peps` IS the store, and the sync token is computed here. |
| `xacml_pep_http.js` | **The THIRD outbound request in this repository** — the nudge. Argued rather than cited. |
| `xacml_admin.js` | The five `/admin/xacml` console pages and their actions. |
| `conformance/` | The vendored OASIS suite. `PROVENANCE.md` is the argument, `MANIFEST.js` the drift check. **Not edited here, ever.** |

Five tests, all in-process, no port, no container:
`tests/xacml_conformance.js` (the engine, against 455 cases somebody else
wrote), `tests/xacml_service.js` (the store, the PIP, the JSON Profile and the
PEP), `tests/xacml_pap.js` (the templates, the editor grammar and the XML
writer), `tests/xacml_alfa.js` (ALFA, both directions) and — since phase five —
`tests/xacml_pep.js`, which is the odd one out: it spawns a CHILD PROCESS in
`xacml-pep/` and asks the container questions this process cannot answer about
itself.

**AND TWO OVER HTTP SINCE 2026-09-05, WHICH IS WHAT THOSE FIVE COULD NEVER
COVER.** Between them the five hold the ENGINE to 455 cases, the store, the PIP,
the JSON Profile, the editor's grammar and the container's shim — and they make
NOT ONE HTTP REQUEST, so until these two existed every route in `xacml.js` and
every form on the five console pages was uncovered. `tests/vendored/`
`sts_xacml_endpoints.js` drives the seven `/xacml` endpoints and
`sts_xacml_editor.js` drives `/admin/xacml/editor` in a real browser; both are
this repository's own (`local: true`), and both live there rather than in the
parent project's suite for one reason worth stating here, because it is a fact
about THIS family: **a PDP with an empty repository answers NotApplicable to
everything**, so there is no question worth asking `/xacml/pdp` until a policy
exists, and over HTTP the only way to put one there is `/admin-api/xacml`. Every
assertion in either file therefore spans an authoring door and a deciding door.

Both work in a THROWAWAY TRUST REALM, which is not tidiness: `ou=policies` is
per realm and a new realm's is EMPTY — the seeded policy is written once, in the
default realm, at require time — so a realm gives them a repository whose whole
contents they wrote, makes every count exact rather than "at least", makes the
no-root state reachable at all, and keeps `xacml.enabled`, `xacml.remotePeps`,
`xacml.pepBias` and `xacml.pepRequireCertificate` off the process while they are
turned off and on. **The editor job needs the realm most**: the draft IS the
stored policy, so a job editing in the default realm would be rewriting the
seeded one, live, while every other job in the run decided against it.

`sts_xacml_editor.js` found the thirteenth defect on its first run and it is
listed below with the twelve.

## ALFA

The third rendering of the model, and the one worth reading — forty lines of
XML are eight of ALFA:

```
policy staffAccess {
    apply denyUnlessPermit
    rule allowStaff {
        permit
        target clause employeeType == "staff" and actionId == "GET"
    }
}
```

**It is an OASIS Committee Specification Draft, not a ratified standard.** No
conformance suite, no schema, no second implementation to disagree with — a
completely different footing from the engine. So the contract stated and
asserted is the one that can actually be kept:

> **Anything the emitter writes, the parser reads, and the policy decides
> identically either way.**

`tests/xacml_alfa.js` checks all three halves of that over every policy the
templates build and the seeded one — stable bytes, still type-checks, **and
the same decisions on seven probes**. The third is the one a round-trip test
usually omits, and the only one that would catch a swapped comparison: `age >
18` becoming `18 > age` round-trips perfectly and decides the opposite. That is
what `mirrorOperator()` is for.

**ALFA is a VIEW, never a second stored copy.** An imported policy is parsed,
converted and stored as XACML XML; the editor renders the ALFA back from the
model. A stored ALFA text beside a stored XML one would be two documents that
could disagree.

Three places the dialect is explicit where ALFA is vague, all argued in the
file's header: **typed literals** (`date("2026-01-01")`, because ALFA has
native syntax for four datatypes and nothing agreed for the other thirteen),
**the three target levels** mapping onto `clause` / `or` / `and`, and
**attributes declared before use** — which is ALFA's own rule and the most
useful refusal in the parser, because a typo in an attribute name is otherwise
a policy that quietly matches nothing and looks exactly like one that is
working and denying you.

## The console

```
/admin/xacml            settings, and what the PDP decides with
/admin/xacml/policies   the repository; enable, disable, root, delete,
                        create from an RBAC or ABAC template
/admin/xacml/editor     the guided editor
/admin/xacml/peps       the REMOTE enforcement points, and whether they are
                        deciding with the same policy this service holds
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

## What the editor can build, and the three things it cannot

**Since 2026-09-05 the guided editor reaches the whole of the XACML 3.0 policy
syntax this engine models.** Before that it built a `Policy` — rules, targets,
matches, conditions, obligations, advice — and nothing else, while
`xacml_xml.js` read and wrote considerably more. That gap was not a missing
feature so much as **four defects, because the editor SERIALIZES THE WHOLE
DOCUMENT ON EVERY EDIT**: a part of the syntax the reader skipped was not
merely unread, it was deleted by the next rename.

| Was | Is |
|---|---|
| A `PolicySet` drew as a policy with no rules, offered `add-rule`, accepted it, said "Rule added." and wrote a document without it — the writer serializes `children` and never looks at `rules` | `policySet` is a kind of its own with its own menu: an inline `Policy`, a nested set, a `PolicyIdReference` or a `PolicySetIdReference`, and the POLICY-combining algorithm list, which is a different set of URIs from the rule-combining one it is almost spelt the same as |
| `set-expression-variable` was in the menu and there was no way to DEFINE a variable, so choosing it built `$v1`, the validator refused the document and the store declined the write | `VariableDefinition` is addable, renamable (**every reference is rewritten with it**) and removable, and the reference option is WITHDRAWN where the enclosing policy defines none |
| Choosing `any-of`, `all-of`, `map` or the other four higher-order functions built an `<AttributeValue>` where a `<Function>` belongs — an expression the validator refuses, offered by the editor's own menu | a function-parameter argument arrives as a `<Function>` reference, and `map` gets a one-argument default because its function takes one value where the other six take a predicate of two |
| An `AttributeSelector` could not be built, and a policy that HELD one lost its namespace bindings on the first edit — an unresolvable prefix is an empty bag, which is NotApplicable, which looks exactly like a policy that decided you may not | selectors are addable and editable (path, category, `ContextSelectorId`, `MustBePresent`, one namespace binding at a time), a `Match` may test one instead of a designator, and **the bindings are written back onto the element** |
| `add-assignment` had been in the menu since the editor shipped and an assignment could not be SEEN, so the only way to correct a mistyped one was to delete the whole obligation | assignments are drawn, editable (`AttributeId`, `Category`, `Issuer`) and removable, and their value is an expression node of its own |
| `Version`, `Issuer`, `ContextSelectorId`, `XPathCategory` and `MaxDelegationDepth` had no control anywhere; `MaxDelegationDepth` was read and never written | all of them are settable, and a `Version` that is not dot-separated numbers is refused HERE, because nothing else in this service would refuse it and somebody else's schema validator will |

**`MustBePresent` is a `<select>` and not a checkbox, and that is the one piece
of markup here worth arguing about.** An unchecked checkbox sends nothing, so
the handler cannot tell "unchecked" from "this form does not edit that field" —
and it has to keep the value for the second case, or the form that edits a
Match's function would clear `MustBePresent` on every save. That is the
difference between an absent attribute being an empty bag and being
Indeterminate: between a policy that quietly does not apply and one that fails
closed.

**`XPathVersion` is REPORTED and never enforced.** Section 5.14 says the
element MUST be present when a policy holds an `AttributeSelector` or an
`xpathExpression`, and `xacml_validate.js` says nothing about it and never
will — that file refuses what is CERTAINLY WRONG for every request, and this
changes no decision this PDP makes, because there is one XPath engine here and
it does not choose a dialect by URI. So the editor page names the policies that
need one, beside the field that sets it. Refusing the write would be the editor
inventing a rule the evaluator has not got; saying nothing would let somebody
build a document here that this service is happy with and a schema validator
elsewhere rejects.

**THE THREE THINGS IT DOES NOT DO, and each is a decision rather than a gap:**

* **The four combiner-parameter elements are carried, drawn and removable —
  and no menu offers to add one.** Section C of the specification says none of
  the twelve standard combining algorithms takes a parameter, so an Add button
  would be the first control on this console that provably changes no decision.
  Drawing them is a different question and comes out the other way: a document
  may arrive carrying them through ALFA, an import or an `ldapmodify` straight
  into `ou=policies`, and an element the editor did not draw would be one the
  person could neither see nor delete while the writer faithfully kept it.
* **`<PolicyIssuer>` is not implemented at all**, so a document carrying one
  loses it here. It belongs to the administrative delegation profile, which
  this PDP does not implement — and `MaxDelegationDepth` beside it is carried
  and read by nothing, which the console says out loud rather than letting the
  attribute imply otherwise.
* **A variable may not be named with a dot in it.** XACML allows one; this
  editor addresses a node by a dotted path, so `a.b` would produce a row that
  cannot be edited or removed while the document itself stayed valid. Refused
  at the point of naming, where it can still be explained.

`tests/xacml_pap.js` carries all of it — 62 assertions added with the change,
including the one that would have caught the policy-set defect: three children
added, serialized, read back, and counted.

**Every element arrives complete and valid** — a new rule has a Target and an
Effect, a new Match has a function, a value and an attribute — because an
editor that produced half-built elements would hold a document that cannot be
saved, and a document that cannot be saved cannot be evaluated, which is when
you most want to look at it.

## The surface

```
GET  /xacml                 what this is; ?format=json for the same as data
POST /xacml/pdp             a decision. JSON Profile in, JSON Profile out
GET  /xacml/policies        the repository as the PDP sees it, documents included
GET  /xacml/protected       the embedded PEP — 200 or 403
POST /xacml/pep/register    a REMOTE PEP registers, over mutual TLS
GET  /xacml/pep/policies    the enabled policies, for a remote PEP to LOAD
POST /xacml/pep/heartbeat   what a remote PEP has enforced
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

One gap in the engine, and it is the only one left.

* **`AttributeSelector` and the XPath functions.** A policy using one is
  Indeterminate rather than silently empty, which is the deliberate choice: an
  empty bag is a perfectly ordinary result a policy may be written to expect,
  so returning one would make an unimplemented feature look like a decision.

**Phase five was this list's other entry and it landed as described**, which is
worth recording because two of the three things this section predicted about it
turned out to be exactly right and one was left open: it IS `xacml-pep/`, its
own container; it DOES register over mutual TLS on the main port, which already
asks for a client certificate (`server.js`'s `requestCert: true`), so no new
listener was needed; and the certificate DOES map to a directory entry through
`ldap_server.js`'s `certificatePlan()` rather than a second mapping — though
only the NAMING is reused and no `ou=users` entry is created, because a PEP is
a component and that container counts people.

What this section did not settle was the DIRECTION, and it reads as though a
push were assumed ("policy push"). **It is a pull.** See below.

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
* `mgmt-api/admin_api.js` — three GETs and a POST with ten documented actions
  (`import-alfa` arrived in phase four);
  `mgmt-api/admin_api_spec.js` — `Xacml`, `XacmlPolicies` and `XacmlEditor`.
* `sts_metadata.js` — **eight** `ENDPOINTS` rows, four of them console pages
  and four management API, which are again the ones a checklist forgets.

**The one thing that is not a file**: `protocolSettingsJsonFor()` is NOT the
JSON counterpart of `configFormsFor()`. It is keyed by admin.js's own
`PROTOCOL_SETTINGS_PAGES` table and **throws** for a path that table does not
carry — correct for the pages that file generates, and a 500 for one drawn
anywhere else. `configSettingsJson()` is the right function and is now
exported beside the renderer it belongs to.

## And what phase four cost, which was almost nothing outside this directory

ALFA is a SYNTAX, not a second policy system — the model, the validator and the
XML writer were already there — so it landed as one new module, one console
`<details>`, one `import-alfa` action and its `/admin-api` operation. No new
setting, no new route, no metadata row beyond the action's own.

**One defect, and it is the same one twice.** The emitter first wrote a policy's
`<Description>` as a `//` comment — and the tokenizer discards comments, so
every explanation survived being read by a person and was DELETED by the next
round trip. The XML reader had had exactly this defect a phase earlier. It is a
`description = "..."` property now, which reads back.

**The one thing a round trip through ALFA can still change**: a policy naming a
LEGACY 1.0 or 1.1 combining algorithm comes back naming the 3.0 one. They share
an ALFA name and they are genuinely different functions (see `xacml_pdp.js`), so
this is a normalisation rather than a no-op. It is called out where
`ALGORITHM_NAMES` is declared.

---

# Phase five: the remote PEP

**THE PEP PULLS. THIS SERVICE DOES NOT PUSH.** Everything below follows from
that sentence, and this section's predecessor assumed the opposite — the *What
is not here yet* entry above said "policy push" and the direction was settled
the other way when the phase was built.

A remote PEP holds its own copy of the engine and evaluates locally, because a
PEP that asked this service per request would be `POST /xacml/pdp` with a
network hop in front of every access decision, and pushing *policies* to
something that could not evaluate them would make no sense at all — you would
push decisions. So something has to move policy from here to there, and it
could have gone either way. It goes by pull for three reasons:

1. **A push would be an outbound request CARRYING CONTENT.** Outbound requests
   are deliberately rare in this repository — `federation/federation_http.js`
   and `ssf/ssf_http.js` each argue their own — and a push would make policy
   DISTRIBUTION depend on this service being able to dial every PEP.
2. **A PEP knows when it is behind and this service does not.** Under push, a
   PEP that was down for a minute has a stale copy and no way to discover it;
   under pull, being current is checked on every poll. That inverts the
   failure: a partition leaves a pulling PEP KNOWINGLY stale rather than
   unknowingly wrong.
3. **It works where a PEP cannot be dialled** — behind NAT, in another cluster,
   on a laptop. A PDP that could only serve PEPs it could reach would be a PDP
   for one deployment topology.

## The nudge is the third outbound request here, and it is the weakest case

When the repository changes, this service POSTs a few bytes to each registered
PEP that gave a notify URL, saying only "something changed, pull now".

`xacml_pep_http.js`'s header makes the argument from scratch, as
`ssf_http.js`'s does rather than citing federation's — and it opens by saying
it can make NEITHER of the other two arguments. Federation's rule is *those
URLs are supplied by the caller, these by the administrator*, enforced by
refusing to take a URL at all; a notify URL is supplied by the PEP that
registers, which is a caller. SSF can say that RFC 8935 push IS the receiver
telling the transmitter where to post; there is no specification here at all,
because XACML 3.0 says nothing about how a policy reaches a PEP.

**What makes it affordable is the one thing the other two cannot say: the nudge
is never the mechanism.** It carries no policy, no decision, no event, no
credential and not even the new sync token. Every PEP converges without it. So:

* `xacml.pepNotify` can be turned off in a deployment with no egress and nothing
  breaks — not the feature, not a test, not a PEP;
* there is no retry and nothing to redeliver, because there is nothing to lose
  (where `ssf_http.js` records a failed push on the stream and offers a
  redeliver, because a lost push IS a lost event);
* a refusal is worth RECORDING and never worth escalating.

**If a future change puts something in that body a PEP cannot get any other
way, the whole argument goes with it.** The body is three members; keep it that
way or move the argument.

Its four bounds are `ssf.push*`'s four, deliberately — an off switch, a host
allowlist empty by default meaning any, an https-only rule with an escape, and
a timeout — because two families making one outbound request each should be
configured the same way or the second is a surprise to anybody who read the
first. The timeout is SHORTER (2s against SSF's 10s) and that is the difference
that follows from the argument: a lost push is a lost event, so SSF waits; a
lost nudge costs one polling interval, so waiting is the expensive mistake.

## What is authenticated, and what deliberately is not

`POST /xacml/pdp` authenticates nobody and always did — a PDP is not an
authorization boundary, and the identity that matters is IN the request.
**`GET /xacml/pep/policies` is the same**: pulling the repository needs no
credential, exactly as `GET /xacml/policies` needs none, because a policy is a
RULE and a rule nobody can read is a rule nobody can check.

**REGISTERING is the one that asks**, and it asks a different question: not who
the decision is about but WHICH PEP THIS IS — because a registration writes an
entry, puts a row on the console, and supplies an address this service will
later dial. `xacml.pepRequireCertificate` is on by default.

It is a TURNSTILE like every other gate here: the certificate need not chain to
anything, on RFC 8705 section 3's argument that what is proved is that the same
key completed the handshake. And **a registration is not a permission** — an
unregistered PEP pulls and enforces exactly as well. `xacml_pep_registry.js`
says so where the register is defined, because the shape looks like an
access-control list and is not one.

**The refusal distinguishes the two ways of arriving at it**, because they need
opposite fixes: a plain-HTTP listener cannot carry a certificate at all (turn on
`global.https`, or turn the requirement off), and an https one can (the client
sent none). A single sentence covering both would send half its readers the
wrong way.

## `ou=peps` is the register, and one certificate is one entry

The same arrangement `ou=policies` has, for the same three reasons — persistence
in all three modes, per-realm isolation, and `ldapsearch` for free.

The entry is NAMED from the client certificate through `certificatePlan()`'s
naming rule, which arrives across the slot rather than being reimplemented, so a
PEP is filed under exactly the name this service gives any certificate-borne
identity. A PEP that restarts UPDATES its row. Two instances sharing a
certificate collapse into one row, which is correct: the question the register
answers is *which PEPs am I distributing policy to, and are they current*, and a
nudge to either instance is a nudge to that deployment.

**No `ou=users` entry is created.** The NAMING is reused, the entry creation is
not — a PEP is a component and that container counts people, which is exactly
the distinction `spiffe_registry.js` had to draw between an ISSUANCE and an
AUTHENTICATION.

Three decisions on the row that each prevent a specific wrong reading:

* **A re-registration keeps the counters, the date and the DISABLED flag.** The
  last is the one that would have been a security-shaped mistake the other way
  round: a PEP an administrator stopped nudging must not re-enable itself by
  reconnecting.
* **A heartbeat SETS the counters rather than adding to them**, because a PEP
  reports its own cumulative totals — adding would count every decision once
  per heartbeat and produce a number that only goes up, looks plausible, and is
  wrong by a factor of the heartbeat interval. A PEP that restarts therefore
  makes the row go DOWN, which is honest.
* **A failed nudge does not move `lastSeen`.** A nudge that failed is evidence
  the PEP is NOT reachable, and letting it stamp liveness would make an
  unreachable PEP look freshly seen.

## The sync token is a digest of what would be SENT

`syncToken()` hashes the documents of every ENABLED policy plus which one is the
root — exactly the bytes `GET /xacml/pep/policies` answers with. Three
consequences, and the third is why it is not a modification stamp:

* a policy edited and edited BACK does not invalidate anybody's copy, because
  the repository genuinely did not change;
* DISABLING a policy moves it, because a disabled policy is not sent;
* a change through ANY door moves it — console, `/admin-api`, `ldapmodify`,
  LDIF restore — because it is computed from the store on the ask. A counter
  incremented by the write path would have been correct for the two doors that
  remembered to increment it.

`current` is therefore a COMPARISON this service performs rather than a claim
the PEP makes about itself.

## What the console page is NOT

`/admin/xacml/peps` reaches into no other process. "Stop nudging" stops this
service dialling a PEP; it does not stop it enforcing, because it already holds
the engine and the policy. "Forget" removes a row. **A control labelled
"disable" that leaves the thing running is the single most misleading thing a
console can do**, so every disabled row says so.

## What phase five cost outside this directory

* `common/config.js` — **eight** rows and the regenerated `env/defaults.js`.
* `ldap/ldap_server.js` — `ou=peps`, its three store functions, and a slot
  carrying FOUR things: the three plus `certificateIdentity`, which is the whole
  reason the register does not invent a naming rule of its own.
* `admin-ui/admin.js` — the tenth slot grew from four views to SIX, a
  `SECTIONS` row, and `xacmlPepsView` / `xacmlDecideView`.
* `mgmt-api/` — two GETs, three actions and two schemas for phase five itself,
  plus the nineteen undocumented editor actions and thirty-two request bodies
  that defect 5 below turned out to owe.
* `sts_metadata.js` — **six** `ENDPOINTS` rows.
* `admin-ui/crypto_metadata.js` — the XACML row's missing halves (see below).
* `docker-compose.yml` — a `xacml-pep` service under `profiles: [xacml]`.
* And the container itself, `xacml-pep/`, which has its own `CLAUDE.md`.

## SIX DEFECTS PHASE FIVE FOUND THAT WERE NOT PHASE FIVE'S

All six predated it, all six were in the PDP-side work of phases one to three,
and **every one of them was found by running three jobs this branch had never
run** — `sts_metadata.js`, `admin_api.js` and `sts_admin_api_operations.js`,
all three of which are THIS REPOSITORY'S OWN (`local: true` in the vendored
manifest) and all three of which would have failed the day the defect was made.

1. **`/admin-api/crypto` answered 500.** The XACML row added to
   `crypto_metadata.js`'s `FAMILIES` in phase one carried no `envelopes` and no
   `algorithms()`, and `cryptoJson()` calls both on every row without checking —
   deliberately, because a row is the whole shape or it is not a row. Three rows
   of that table say "nothing" and this one must still carry the fields.
2. **`/admin/xacml/decide` had no `/admin-api` operation**, which rule 7 requires
   in the same commit as the page. It shipped in phase three without one.
3. **`tests/vendored/sts_metadata.js`'s protocol list did not name XACML**, so
   the card added in phase one was never checked against the page.
4. **The action endpoint answered `{ ok, why }` where every other action
   resource on `/admin-api` answers `{ ok, errors: [...] }`.** That is not a
   cosmetic difference: `sts_admin_api_operations.js` reads that array on every
   resource to check that the refusal SENTENCE names the actions, and
   `admin_api.js`'s parity check reads that same sentence to find out what a
   resource can do. A resource answering `why` is invisible to both. The
   conversion is in `admin.xacmlAction()`, which is the one function the
   management API calls and the console does not.
5. **NINETEEN of the editor's twenty-three actions were undocumented, and not
   one of the thirty-two carried a request-body example.** Both halves matter
   and they fail differently: an undocumented action is a console control that
   could lose its operation with nothing failing, and an operation with no
   example is one `sts_admin_api_operations.js`'s ledger drives with nothing —
   its walk is driven off the document, so an operation arriving with no
   example and no section of its own is covered by nothing and reported by
   nothing. All thirty-two carry a documented body and an example now, and the
   ledger replays every one of them against the running service.
6. **`sts_admin_console.js` read only the FIRST console control an operation
   said it mirrored.** `/admin-api/xacml/{action}` mirrors three, so
   `/admin/xacml/editor`'s forms were never checked against the route list at
   all — and when phase five's sentence grew a comma, the greedy `\S*` swallowed
   it and even the first path stopped matching. `consolePostPathsIn()` is the
   one reader of that prose field now, it finds all of them, and it strips
   trailing punctuation. **Phase five did not cause that defect; it made the
   pre-existing one visible**, which is the ordinary way a silent guard is
   found.

## AND TWO THAT WERE

1. **`certificatePlan()` takes DN fields as STRINGS and node hands back
   OBJECTS.** `getPeerCertificate()` returns `subject` and `issuer` as
   null-prototype objects of RDN types, so `String()` on one throws `Cannot
   convert object to primitive value` rather than producing a DN. Every existing
   caller had always put both through `helpers.dnRfc4514()` first, so the
   precondition was real and written down nowhere — it is written at the
   function now. It was met TWICE, once per field: fixing the subject alone just
   moved the throw eighty lines down.
2. **The remote PEP asserted attributes under only ONE spelling.** The mock's
   PIP answers both `employeeType` and
   `urn:sts-mock:xacml:attribute:employeeType` from one directory attribute, so
   a policy author may legitimately write either; the container asserted only the
   prefixed form and the seeded RBAC policy names it bare. **Every request was
   denied by a policy that was working perfectly**, which is the worst shape an
   authorization bug can take. It asserts both now.

Neither would have been found by anything but running the container against the
service.

## THE MOST VALUABLE THING IN PHASE FIVE IS NOT THE FEATURE

`xacml-pep/common/helpers.js` is thirty lines exporting `log` and `xmlEscape`,
and it is what `../common/helpers` resolves to inside that container. Every
engine module here claims **no I/O, no DOM, no store** in its header — and every
one of them requires `../common/helpers`, which in this service pulls in the
config table, the crypto module, the realm registry, node-forge and
jsonwebtoken. The claim had a loophole wide enough to drive anything through.

An engine module that grows a dependency on this service does not degrade in
that container — **it throws at load**, and `tests/xacml_pep.js` fails naming
it. That test also asserts that not one of this service's modules is in the
child's `require.cache` once the engine has loaded, and that the engine reaches
the same decision there as here on the same policy.

So "the engine is a library with no I/O" stopped being a comment at the top of
seven files and became something that is checked. That is worth more than the
remote PEP it arrived with.

## THE THIRTEENTH DEFECT, AND THE ONLY DOOR THAT COULD HAVE SHOWN IT

`tests/vendored/sts_xacml_editor.js` found it on its first run, and it had been
there since phase three: **every refusal on the three `/admin/xacml` pages
redirected back to the page with `error=` and nothing in it.**

The three action functions here — `policyAction()`, `editorAction()` and
`pepAction()` — refuse with a single `why`, which is the shape `xacml_store.js`
and `xacml_editor.js` hand up to them. `admin.respondToAction()` built the
browser's message out of `errors`, which none of them sets. So the person got
the page they had just posted from, unchanged, with no explanation — which reads
exactly like a control that does nothing.

**It was invisible from both of the places that look.** `/admin-api` had already
been given the translation (`admin.xacmlAction()` puts `why` into `errors`), so
every refusal was fully explained there and
`tests/vendored/sts_admin_api_operations.js` was right to be satisfied. And
`tests/xacml_pap.js` asserts the refusal the FUNCTION returns, which was correct
the whole time. The defect lived in the two lines between them, and the only way
to see it was to press a button in a browser and read the page that came back.

It matters most exactly where this console leans on it hardest: the editor is
LIVE, and the thing that makes that tolerable is that an edit which would leave
a policy invalid is refused and the stored document is untouched. The sentence
saying so — which names the type error the author has to fix — was the part
being dropped.

Fixed in `admin-ui/admin.js` rather than in the three handlers, so that a fourth
handler written in that shape cannot reintroduce it and so that the console and
`/admin-api` cannot disagree about what a refusal said.

## AND SINCE 2026-09-05 IT DECIDES THIS SERVICE'S OWN ISSUANCE

`xacml_role_pep.js` is the exception to the sentence at the top of this file.
Everything else here answers a question about SOMEBODY ELSE'S boundary — that is
what a PDP is. This one turns THIS service's issuances into XACML requests and
refuses the ones the PDP will not permit.

It fills `common/issuance_gate.js`'s decider at require time, which is what arms
every issuance site in the service: nine kinds of issuance, eight `gate.check()`
calls, seven modules, all of them required BEFORE 23c. So `xacml/xacml.js`
requiring this module is the line that turns a service which answers "allowed"
to everything into one that asks a policy.

**There is no second implementation of the rule.** No `if (roles.includes(...))`
in `oauth2.js`, no membership test in the SAML builder. The reason somebody was
refused is a document an administrator can read, edit, test on
`/admin/xacml/decide` and see in the audit log — which is the whole point of
routing an internal decision through a policy engine that is already here.

### The request it builds is the contract

| Category | Attribute | What it is |
|---|---|---|
| access-subject | `subject-id` | who is being authenticated |
| | `urn:sts-mock:xacml:role` | the roles they hold |
| | `urn:sts-mock:xacml:role-from-token` | roles read out of a token they PRESENTED |
| resource | `resource-id` | the application |
| | `urn:sts-mock:xacml:required-role` | what it demands |
| action | `action-id` | `issue-access-token`, `start-session`, and the rest of `issuance_gate`'s `ISSUANCE` |

**The subject is the party being authenticated and not always a person.** In a
browser flow it is whoever signed in; in a `client_credentials` grant there is
nobody there and it is the CLIENT. That is the case `common/roles.js` exists to
be able to answer, and it is why an application is a first-class member of a
role.

**The application is the resource and also, often, the subject's employer.** A
client asking for a token for itself appears in both categories, which is not a
confusion: as a resource it is the thing being reached, as a subject it is the
party whose roles are read. A policy may name either.

### The policy is BUILT IN, called rather than seeded

The `role-issuance` template answers by being CALLED. It is not written into
`ou=policies` at startup, and that is a correction rather than a preference:
`ou=policies` is per realm, so a seed written once in the default realm left
every later realm unable to use roles at all. A repository entry named by
`xacml.issuancePolicy` overrides it, so an administrator who wants to see and
edit the document still can.

### The two ways it can fail get OPPOSITE answers

This is the part to read before changing anything in that file.

**A missing or broken issuance policy fails OPEN for an application that
requires only `EVERYBODY`, and CLOSED for one that requires anything else.**

An application that names no required role is the default state of every
application here. It requires `EVERYBODY`, everybody holds `EVERYBODY`, and the
only answer the policy could give is Permit — so a missing policy costs it
nothing, and refusing it would mean a service whose issuance policy was deleted
stops issuing ANYTHING to ANYBODY, including the session an administrator needs
to put the policy back. That is not a security posture, it is a locked room with
the key inside.

An application whose entry names `staff` is a different sentence entirely:
somebody deliberately asked for a restriction, and answering Permit because the
document implementing it is missing would be the one failure this feature must
not have — a configured refusal silently not happening. So that one is refused,
and the refusal NAMES the policy and the template that rebuilds it.

**An error is not a decision.** A throw out of the engine is a defect, and
`issuance_gate.js` answers a throw by allowing, for the locked-room reason. A
Deny, a NotApplicable and an Indeterminate are not throws — they are answers,
and every one of them refuses here, because the policy is `deny-unless-permit`
and an issuance decision must not rest on a PEP's bias. **`xacml.pepBias` is
deliberately not read here**: that setting belongs to the demo PEP at
`/xacml/protected`, which exists to SHOW what bias does, and this one is
enforcing.

### It fills `admin.js`'s eleventh slot

`setRolePreviewer()`, carrying TWO functions — the preview, and the thing that
says WHICH POLICY answered. Validated together for `setLogoutReader()`'s reason:
a preview installed without the explanation would be a page able to ask a
question and unable to explain the answer.

Rule 3e's test answers yes both ways round. A require from `admin.js` (18) to
this module would load the engine there and — much worse — fill the issuance
decider FROM THE CONSOLE, so a process that loaded the console and not
`xacml/xacml.js` would gate every issuance in the service with half this family
present. A require the other way closes a cycle, because `xacml_admin.js`
requires `admin.js` for the page shell.

## THE FOURTEENTH DEFECT: TWO CONTAINERS CLAIMING A PAGE THAT WAS NEVER WRITTEN

`xacml_store.js` and `xacml_pep_registry.js` each carry a `SCHEMA` whose comment
says it is "Published on `/admin/ldap/*` the way every other container's is".
Neither was. The export was dead in the first since phase two and in the second
since phase five, and `common/roles.js` copied the same comment on 2026-09-05
and made three.

The pages exist now — `/admin/ldap/policies` and `/admin/ldap/peps`, drawn by
`ldap/ldap_server.js` beside the other six, because that module already requires
both of these to fill their `setDirectory()` slots and therefore already holds
both schemas. No new require, no cycle, no route moved.

**What writing them exposed is the reason a dead export is worth chasing.** The
store lower-cases every attribute name (`@ldapjs/attribute` does), and
`ldap_server.js` un-lower-cases it through `learnName()` from a table each
owning module contributes to — a merge `applications.js` has had for months and
neither of these had. So the first draft of the policies page showed every
policy's kind as `(unstated)` and, worse, **drew a DISABLED policy as enabled**,
because a missing `xacmlEnabled` is not the string `FALSE`. Both are fixed by
merging the schemas rather than by reading case-insensitively at each site: a
lookup that silently misses answers something plausible, and these three pages
are not the only readers of these entries.

The booleans are `TRUE` and `FALSE` — RFC 4517's Boolean syntax, which is upper
case, and what both of these modules write. A page comparing against `'false'`
is a page that overstates what is switched on.
