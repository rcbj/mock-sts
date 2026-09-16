# mgmt-api/

The management API at `/admin-api`, its generated OpenAPI document, and the
browser-side explorer.

| File | What it is |
|---|---|
| `admin_api.js` | The table of operations. Every one that CHANGES something calls an action in `../admin-core/admin_actions.js`; every one that READS calls a view on `../admin-ui/admin.js`, which is where the JSON half of a console page is computed. **It said "every one calls a function in `../admin-ui/admin.js`" until 2026-09-12**, which was true for as long as this file existed — see *THE DECISIONS MOVED OUT OF THE CONSOLE* below. |
| `admin_api_spec.js` | The OpenAPI document, GENERATED from that table. |
| `admin_api_docs.js` | The docs page, and the route that serves the explorer. |
| `admin_api_explorer.js` | **BROWSER code.** Not a node module — read off disk by `admin_api_docs.js` and served verbatim. Its own header says so at length. |

`admin_api_docs.js` reads its sibling with `path.join(__dirname,
'admin_api_explorer.js')`, which is why the two moved together and why nothing
about that line had to change.

7. **`admin_api.js` must stay after `admin.js`, and the rule it carries is about
   the FUTURE rather than about load order.** The plain dependency first: it
   requires that module for the four action functions and the per-page JSON
   views, so it must come after it. Nothing else about its position matters — it
   registers no wildcard and collides with no path.

   **`/admin/delegation` is the second page here with no form on it and it is
   the case that shows what the rule actually asks for.** It arrived with `GET
   /admin-api/delegation` and nothing else, and that is rule 7 HOLDING rather
   than being waived: everything that page shows is an observation (an act
   happened or it did not) or somebody else's configuration (the Kerberos
   principal database, which nothing in this service can set). There is no
   control, so there is no operation to mirror. The audit log was the first such
   page and its own paragraph below argues the same thing from the other
   direction — that a clear button would be a control nobody should have.

   The rule that does matter is **a control added to `/admin` gets an operation
   on `/admin-api` in the same commit** — `/admin/users` grew its first form
   (create a person in the directory) and `POST /admin-api/users/:action` with
   its one `create` action arrived with it — — a CONTROL, which is why a page with no
   form on it needs only its GET. Not eventually, and not when somebody
   asks: an API that covers eight of nine controls is worse than one that covers
   none, because the ninth is found by a caller who has already written the code
   that assumed it. A page with no form on it still needs its GET —
   `/admin-api/audit` is the one, and it is the audit page having nothing to
   change rather than an operation nobody got round to. `/admin/users` USED to
   be a second such page and no longer is.

   Two things make that cheap rather than a matter of discipline, and one thing
   cannot be made cheap at all:

   * **The API decides nothing.** Every POST calls the SAME action function the
     console's form posts to — `tokenAction`, `usersAction`, `claimsAction`,
     `vcAction`, `vpConfigAction` — with `action` taken from the URL instead of from a hidden
     input, and every GET calls the same JSON view the page's `?format=json`
     answers. Those views are now functions in `admin.js` (`consoleJson`,
     `metricsJson`, `tokensView`, `usersView`, `groupsView`, `claimsJson`,
     `samlAttributesJson`, `vcJson`, `vpConfigJson`) for exactly this reason:
     they used to be built
     inline in the route handlers, which was fine while there was one caller. So
     adding an action to a console switch is most of adding it here, and what
     remains is one row of `admin_api.js`'s table.

     **TWO RESOURCES CAN SHARE ONE ACTION FUNCTION, and the claim sets are the
     case.** `/admin-api/claims/:action` and `/admin-api/saml-attributes/:action`
     both call `claimsAction`, differing only in the third argument — the set ids
     that door carries, `stats.JWT_CLAIM_SET_IDS` or `stats.SAML_CLAIM_SET_IDS`,
     which is exactly what the two console pages pass. That is what makes the two
     resources a mirror of the two PAGES rather than two models of one store. It
     costs fourteen operations for seven behaviours, so the seven are built once
     by `claimSetActions(family)` and the family varies the set enum, the noun and
     the reserved-names rule: fourteen hand-written descriptions would be seven
     pairs, and the half of each pair nobody edited is the half a caller believes.
     The parity check that reads the refusal sentence off each resource sees the
     same seven action names from both, which is the property that makes them
     one behaviour rather than two.
   * **The OpenAPI document is GENERATED from that table** (`admin_api_spec.js`),
     so an operation cannot exist and be undocumented, nor be documented and not
     exist. Do not write a spec file beside the code — that is the thing that is
     wrong within a month.
   * **What no code here can check is a new console control with no row.**
     Nothing in this service can see a form appear on a page. So the parity is
     asserted from outside, by this repository's own `tests/vendored/admin_api.js`, and it
     reads the facts off the SERVICE rather than off a list in the test: the
     console's page list comes back in `GET /admin-api/status`, and each action
     handler, asked for an action that does not exist, replies naming the ones
     that do. Add an action to a switch and that sentence grows; the test then
     fails until the API has an operation for it.

   One consequence for the console side: `usersView()` and `groupsView()` build
   the HTML as well as the JSON, and `/admin-api` throws the markup away. That is
   what `/admin/users?format=json` has always done, it is a string concatenation
   on a mock, and the alternative — a second set of builders for the same data —
   is the thing this whole arrangement exists to prevent.



## THE DECISIONS MOVED OUT OF THE CONSOLE ON 2026-09-12, AND THIS FILE SAID THEY WERE THERE

Every operation here that CHANGES something used to call a function on
`admin-ui/admin.js`. They call `admin-core/admin_actions.js` now, and this file
requires both modules for two different reasons.

**What was wrong with the old arrangement was not the enforcement, it was the
direction.** Rule 7 says a console control and an API operation must not be
able to disagree, and calling the console's own function is the strongest
possible way to guarantee that — they were one call. The price was that the
surface a machine drives sat downstream of the surface a person reads, and the
console was the declared home of logic that was never the console's.

**The move was possible because the functions were already right.** Not one of
the thirty-one touched `req`, `res` or markup: each took a parsed body and an
actor and returned `{ ok, errors, … }`. `admin-core/CLAUDE.md` argues the
split, including why `respondToAction()` and `listField()` stayed behind.

**THE READ HALF FOLLOWED THE SAME DAY**, into `admin-core/admin_views.js`:
thirty-eight functions that answer a question and build no markup. Forty-four
call sites here were repointed at it.

**THE INTERLEAVED VIEWS FOLLOWED, ONE FAMILY AT A TIME**, and this file now
calls exactly FOUR functions on the console module:

| | |
|---|---|
| `consoleJson()` | which pages this console has |
| `configJson()` | every setting, and which page edits each group |
| `protocolSettingsJsonFor()` | the settings one protocol page owns |
| `listField()` | the repeated-checkbox parse, which reads `req` |

The first three are the console describing ITSELF — a layer beneath it could
not know which pages exist — and the fourth is transport. **Purity was not the
test; ownership was**: all four are perfectly pure and all four belong here.

**RULE 7 IS STRONGER AFTER THE SPLIT THAN BEFORE IT, WHICH IS NOT THE OBVIOUS
OUTCOME.** Before, a page and its operation could not disagree because one
function happened to build both halves, and nothing stopped a later edit
computing the json from something else. Now the page renders the model the
resource answers from: `xListPage()` calls `adminViews.xListJson(req)` and
hands back `view.json` unchanged. The agreement is structural rather than
incidental.

**A REGRESSION HERE WOULD BE SILENT**, which is why it is pinned: adding one
`admin.somethingAction()` call back would restore the old direction for that
one operation, and nothing whatsoever would fail.
`tests/admin_actions_layer.js` is the guard.


### EIGHT MORE GETs WITH NO POST BESIDE THEM (2026-08-27), and they are the same sentence eight times

On 2026-08-27 every one of `config.js`'s setting groups moved onto the console
page for the protocol it configures, and eight pages were created for the
families that had settings and no page: `/admin/oauth2`, `/admin/oid4vci`,
`/admin/oid4vp`, `/admin/kerberos`, `/admin/ldap`, `/admin/wstrust`,
`/admin/wsfed` and `/admin/tls`. Rule 7 asks for an operation per page, so each
gained a GET here — and **no POST**, for exactly the reason the row below gives.

**Every form on those pages posts `set-many` to `/admin/config`**, which `POST
/admin-api/config/set-many` already mirrors. A POST per page would be eight more
operations over one function, and a caller handed nine ways to set
`krb5.clockSkew` would have to work out which one the service believes. So the
parity is satisfied by an operation that already existed, plus the GET every
page gets. **Twelve pages that already existed gained a settings block on the
same day and needed nothing here at all**, for the same reason — `/admin/scim`,
`/admin/spiffe`, `/admin/saml2`, `/admin/rbac`, `/admin/groups`,
`/admin/audit`, `/admin/delegation` and the rest already had their GETs.

**The eight rows are GENERATED from a table** (`PROTOCOL_SETTINGS_OPERATIONS` in
`admin_api.js`) for the reason `claimSetActions(family)` is: the operations
differ only in prose, and eight hand-written rows would be seven copies plus the
one somebody edited. `admin_api_spec.js` reads the array and cannot tell the
difference. They share one response schema, `PageSettings`, which is also what
the `settings` member of `/admin-api/saml2`, `/admin-api/saml11`,
`/admin-api/scim` and the rest now carries — one shape a caller learns once.

**Two of the paths are not the obvious ones**, and the collision is worth
knowing before somebody "fixes" them: `/admin-api/oid4vci-settings` and
`/admin-api/oid4vp-settings`, because `/admin-api/credential-claims` and
`/admin-api/verifier-request` already mirror the other two pages of those
families and the bare names would have read as theirs.

**`GET /admin-api/config` did not narrow when the page did.** It still answers
the whole table — a caller asking this API for the configuration should not have
to fetch twenty-one resources and assemble one — and it gained `homes`, which
says which console page draws each group, and `homeProblems`, which is empty
unless a group exists that no page draws. `admin-ui/CLAUDE.md` argues the whole
move; this file's half of it is the paragraph above.


### `/admin-api/users/new` is the same shape, and the users resource is the first to mirror TWO console paths

`/admin/users/new` arrived on 2026-09-06 and cost the same two things the
applications create page did: a GET that publishes what a create may say, and no
POST beside it.

**The GET earns its place for the same reason and a sharper one.** What it
answers is the CLOSED ATTRIBUTE CATALOGUE `createUser()` validates `attributes`
against — every attribute a person in this directory may be given, each naming
the claim it reaches in an issued credential and the document its name comes
from — plus the `ou=users` container the entry would land in and the four
`credential` options. The sharper reason is that **an attribute name that is not
on that list is REFUSED and the whole create fails**, rather than the value
being dropped: a caller that reads this first cannot be told afterwards that
half of what it sent was ignored, and a caller that does not gets a refusal
naming the attribute. `uid` and `userPassword` are deliberately absent — the
first IS the username, and a password goes through `credential` so that
`credentials.js` hashes it.

**THE `mirrors` FIELD ON THE USERS ACTION RESOURCE NAMES TWO CONSOLE PATHS, AND
THAT IS NOT DECORATION.** `POST /admin-api/users/{action}` mirrors `POST
/admin/users` AND `POST /admin/users/new`, because both reach one action switch
— `/admin/users/new` posts to ITSELF rather than to the list, so that a
generated password and an activation link can be answered in a page body
instead of a 303's query string. `tests/vendored/sts_admin_console.js` builds
its list of "console paths that take a POST" by parsing this field, so a page
left out of it reads as a control that reaches nothing. `/admin-api/xacml/{action}`
has named three since it was written; this is the second resource to need it.

**IT ALSO CLOSED AN OPERATION THIS SERVICE HAD BEEN DOCUMENTING AND NOT
SERVING.** `common/credentials.js` names `POST /admin-api/users/set-password`
twice — in the sentence a refused sign-in gets, and in the banner the
product-mode bootstrap prints telling an operator to change the generated
password — and no such operation existed. Somebody following either instruction
got a 404 naming an endpoint of this service's own. It is an arm of
`usersAction()` now, so the console and this API reach one function, and it is
the third action on that resource.

### `/admin-api/applications/new` is a GET WITH NO POST BESIDE IT, and that is rule 7 read exactly

`/admin/applications/new` arrived on 2026-08-25 — a console page whose one
control is a create with a checkbox column of protocol families. It gained
`GET /admin-api/applications/new` and NOTHING ELSE, and the reason is the
sentence rule 7 actually contains rather than the shape it usually takes.

**The rule is about CONTROLS.** That page's form posts `action=create` to
`/admin/applications`, which is the handler `POST
/admin-api/applications/create` already mirrors — the same function, reached
from a second door. A `POST /admin-api/applications/new` would be two operations
over one function, which is the thing this parity exists to PREVENT: a caller
handed two creates has to work out which one the service believes, and the
answer would be "both, they are the same one". So the parity here is satisfied
by an operation that already existed, plus the GET every page gets.

**The GET earns its place beyond the parity, which is worth saying because a
page-mirroring GET usually does not.** What it answers is the two CLOSED
VOCABULARIES `createApplication()` validates against — the eight kinds and the
fourteen protocol families, each with what it means — the container DN a new
entry would land in, and, since the create form grew its fields,
`declarations`: one row per ATTRIBUTE a family names as its identifier or as
where its responses go back to, with the families each serves and whether it
holds a list. That is the property `editableAttributes()` gives the
console's two selects (a form cannot offer what the action would refuse),
reached over HTTP: a caller that reads this cannot construct a create the
service will refuse. Compare the alternative, which is the enum written out in
this file's document and in the console's markup and kept in step by hand.

**`createApplication`'s `fields` MEMBER IS WHERE THAT LIST IS SPENT.** A create
takes the per-protocol identifiers and the redirect URIs as an object keyed by
attribute name — the console's form posts one flat `field.<attribute>` per box
and `applicationFieldsFrom()` in `admin.js` folds both spellings into the same
object, which is `listField()`'s arrangement for the checkbox column one field
up. A derived attribute is REFUSED by name rather than written, and so is a
single-valued one given several values.

**THE `set` AND `add` DESCRIPTIONS NAME THEIR ATTRIBUTES FROM
`editableAttributes()` NOW, AND THEY WERE TYPED OUT BEFORE.** That is a small
change with the same lesson as everything else here: making six identifier
attributes multi-valued moved six names from one sentence to the other, and
neither sentence noticed. A hand-written list of what an operation accepts is a
second definition of the `EDITABLE` table, and it goes stale in the document a
caller trusts most — the same reason the enum above is read off the service
rather than written here.

**The container it names is THIS REALM'S**, because the embedded directory is
per realm. `/realm/acme/admin-api/applications/new` answers with acme's
`ou=applications`, and an application created there is invisible to every other
realm — including to an `ldapsearch`, which reaches it only under that realm's
base DN. That is the ordinary rule for this API (see *This whole API is
realm-scoped* below) and it is stated on this operation because "where would it
land" is the question the operation exists to answer.

**One trap it shares with the claim sets.** The declared families arrive as
`protocol` repeated or as one `protocols` array, read through `namesOf()` — not
off `body`. `helpers.parseBody()` cannot see a repeated field, so a form-encoded
body copied from the console's checkbox column would otherwise create the
application with one family out of five and answer 200.

### `/admin-api/ssf` IS THE FIRST OPERATION HERE WHOSE HANDLER AWAITS, AND THE FIRST WITH A CONTROL DELIBERATELY MISSING

Added 2026-08-31. A GET and a POST with four actions — set a status, transmit an
event, delete a stream, clear what has been received — each calling the same
function the console's own form posts to, with `action` taken from the URL. The
ordinary shape.

**THE POST AWAITS, AND IT IS THE ONLY ONE IN THIS FILE THAT DOES.** Transmitting
a Security Event Token signs a JWS — possibly ML-DSA or SLH-DSA on the worker
pool — and then POSTs it to somebody else's endpoint. `sendJson()` is called
from the `then`, and a rejection is answered as a 500 naming the message rather
than becoming an unhandled rejection: `ssf/ssf.js`'s action function resolves a
refusal rather than throwing one, so a rejection there is a bug in this
repository and not something a request can cause.

**AND THERE IS NO `create` ACTION, WHICH IS RULE 7 READ EXACTLY RATHER THAN A
GAP.** A stream carries a **delivery endpoint this service will DIAL**, and the
one place that URL may come from is a receiver that authenticated at
`POST /ssf/stream` and asked. An operation here that could mint one would be a
second door onto the outbound request `ssf/ssf_http.js` spends its header
bounding — **and it would be the door with the WEAKER credential**, since this
API takes a token that anybody holding the client secret can mint and the
console takes a person's own sign-in. (It read "and it would be the UNGATED
door" until 2026-09-09, when this API stopped being ungated; the argument is
unchanged and only its sharpest word is gone.) The console has no create form
for the same reason, so there is no control to mirror and the parity holds; `ssf/CLAUDE.md` argues the outbound
request itself.

### `/admin-api/federation` is where rule 7 pays MOST, and the honest sentence is sharper here

`/admin/federation` arrived with `GET /admin-api/federation` and `POST
/admin-api/federation/:action` with all seven of its actions, in the same change.
Rule 7 as written is satisfied by that. What is worth arguing is why this
resource matters more than the parity rule alone would suggest, and what it costs.

**It is the only way the feature can be exercised automatically.** A federated
sign-in cannot be driven without a configured relationship, and a relationship
cannot be configured through a gated console by a test with no cookie jar. This
API takes a credential a test can mint rather than a browser session, so `POST
/admin-api/federation/create` is to federation what
`POST /admin-api/rbac/grant` is to the roles: not merely a mirror, but the door
that works when the other one cannot be reached.

**And the consequence is the sharpest form of the one this file already
states.** Anybody who can reach this port can configure a federation partner —
which means configuring a signing certificate this service will then BELIEVE, and
therefore minting themselves a session as anybody. That is not a new hole: the
same caller can already grant themselves both admin roles here and get a token
for any username from `/oauth2/token`. But it is the most direct expression of
it, and the operation's own description says so rather than leaving it to be
worked out.

**`fedClientSecret` is never returned by this API** — `(set — not returned)` or
empty. That is deliberately NOT claimed as a security boundary, because an
`ldapsearch` of `ou=federations` shows it, exactly as `GET /krb5/principals`
prints every Kerberos password. What it avoids is this API being a SECOND way to
read a credential that belongs to somebody else's service out of this process.

### The narrow door: `/admin-api/token-lifetimes`

Two operations that set four settings `POST /config/set-many` can already set,
and they are worth reading as a worked example of what rule 7 does and does not
ask for.

**Rule 7 as written is satisfied by their existing at all**:
`/admin/token-lifetimes` grew a form, so the form's two actions got two
operations, in the same change. What is worth arguing is that this is not a
second STORE and therefore not the mistake rule 5 exists for — the handler calls
`admin.tokenLifetimesAction`, which writes through `config.setOverride()`, the
same function against the same override map `POST /config/set` uses. Two doors
onto one thing, the way `/admin/rbac`, `POST /admin-api/rbac/grant`, an
`ldapmodify` and a SCIM PATCH are four doors onto one membership.

**What the narrow door buys a CALLER is a refusal the wide one cannot give.**
`set-many` IGNORES a key it does not know, and that is right for what it is —
a form posts fields the resource never declared, so an unknown name is ordinary
there. It is wrong for a caller that means to set a lifetime: a misspelt
`oauth2.accessTokenTtlsS` succeeds, changes nothing, and reports success. This
operation refuses anything outside its four BY NAME. **The general door must not
be narrowed to match** — that would break every form posting a section, which is
the case it exists for.

The test for a third resource of this shape is therefore not "is this setting
important" but **"does a caller of the general operation get a wrong answer
here"**. If the answer is no, the setting belongs on `/config` and nowhere else,
which is the argument `/admin/scim` and `groups.claim` both already make for
having no operation of their own.

**`/admin-api/saml-assertions` IS THAT THIRD RESOURCE, added 2026-08-27**, and
it was put to the test above rather than admitted by analogy. It sets the
assertion settings — the two lifetimes, the signing and NameID choices, the
artifact lifetimes, the SAML 2.0 encryption rows and `saml.clockSkewS` — and a
caller of `set-many` does get a wrong answer here: `saml2.assertionLifetimeMins`
succeeds, changes nothing and reports success, and the caller finds out from an
assertion that expired when it should not have. So it refuses anything outside
its own list by name, exactly as the token lifetimes door does.

**BOTH NARROW DOORS' REQUEST SCHEMAS ARE GENERATED FROM THAT LIST NOW, AND THAT
IS A FIX RATHER THAN A TIDY-UP.** They were typed out here beside a list held in
`admin.js`, and both had drifted — this document named FOUR token-lifetime
settings against six, and THREE assertion settings against sixteen, and the
paragraph above said "three" with them. On a resource whose whole claim is that
it refuses anything outside its own list BY NAME, that is the worst place for a
second copy to go stale: a caller reading the document is refused for following
it, and a caller reading the refusal finds settings the document never mentioned.
`admin.js` exports `tokenLifetimeKeys()` and `samlAssertionKeys()` — the same
arrays the refusals are built from — and `narrowDoorProperties()` here turns
either into `properties`, taking each type from `config.js`'s own row. A row
added to either table adds the property. **A fourth narrow door must do the
same**: the test above is still "does a caller of the general operation get a
wrong answer here", and the list is still not something to write down twice.

**Its GET earns its place beyond the parity**, which is the same thing to check
here as everywhere: it reports `saml2WindowS` and `saml11WindowS`, the whole
width of the window an assertion actually states. That is the lifetime plus
TWICE the skew, and **no setting in `/config` states it** — a caller assembling
it from the rows has to know that the skew is applied at both ends, which is
precisely the thing somebody gets wrong. A resource that only echoed three rows
back would not have earned anything.

---

## The explorer moved to the console on 2026-09-09

**`/admin-api/docs` IS GONE AND THE PAGE IS `/admin/api-explorer`.** It moved
for one reason: the section above. This API began requiring an OAuth 2.0 access
token, and a browser navigating to a URL carries none — so the one page in this
service whose entire purpose is to be opened in a browser became the one page a
browser could not open, and the console linked to it and got a 401.

It is behind the console's session and its two roles now, and the calls it makes
carry a token minted for the reader with exactly the scopes those roles grant.
`admin-ui/CLAUDE.md` argues the page; `admin-ui/api_explorer.js` builds it, at
19a, after this module — it needs the route table below to build its document.

**TWO FILES DID NOT MOVE AND ARE STILL HERE**: `admin_api_docs.js` and
`admin_api_explorer.js`. The stylesheet, the browser script and the
realm-prefix argument belong to THIS API's document rather than to the
console's shell, and the console requires them. The first grew a
`consoleBody()` beside its `page()`; `page()` is kept and exported and nothing
registers a route for it, because the style, the script and the prefix argument
are the same in both shapes and a second copy of any of them is what that file
exists to prevent.

**RULE 7 IS SATISFIED BY `GET /admin-api/api-explorer`**, which reports where
the document is, how many operations it describes and what the caller's console
roles would grant — and does NOT repeat the document, because
`GET /admin-api/openapi.json` is the document.

**AND THE LEDGER'S ONLY EXEMPTION WENT WITH IT.**
`tests/vendored/sts_admin_api_operations.js` kept a `NOT_DRIVEN_HERE` table
whose two rows were these two routes, the only operations on this API a JSON
walk could not drive. Every operation this API documents now answers JSON and
every one of them is driven; the table is kept, empty, because the next
operation that cannot be driven needs somewhere to say why.

The section below is the argument for the script itself, which is unchanged by
the move and is why the page is still the only scripted one in either surface.

## The explorer's script is the one relaxation of `script-src 'none'`

`app.js` sets `script-src 'none'` for the whole service, and the reason is in its
own comment: it is what makes the family of reflected-content problems moot rather
than merely unlikely. The API explorer needs a script, so it is the one page that
relaxes that header — on two routes, in exactly two clauses (`script-src 'self'`
and an added `connect-src 'self'`), with `default-src 'none'` and everything else
untouched.

**The script is a separate resource for that reason and no other.** `'self'` is
enough for a file; an inline block would have needed `'unsafe-inline'`, which is
the clause that would make the relaxation matter. Do not inline it, and do not add
a second scripted page without asking whether it needs to be one.

It is also **this repository's own explorer rather than Swagger UI**, and that was
weighed rather than skipped: `swagger-ui-dist` is 11.7 MB unpacked with an
install-time telemetry dependency, in a service whose package.json is deliberately
short and whose image is built in containers that may have no network beyond the
registry. What it would have bought is a familiar look for an API with no
authentication, no OAuth flows and no polymorphic bodies. `admin_api_explorer.js`
is ~250 lines, has no dependency, and does the same three things — read the
document, fill a form, show the response — plus the equivalent `curl` line, which
is what an operator of a mock actually copies.

---

## `/admin-api` WANTS AN ACCESS TOKEN, AND THE CONSOLE WANTS A SESSION

**THIS SECTION'S HEADING READ "`/admin-api` IS NOT GATED AND THE CONSOLE NOW
IS" UNTIL 2026-09-09, AND EVERYTHING UNDER IT WAS TRUE FOR AS LONG AS THIS FILE
EXISTED.** It is kept below rather than deleted, because the three reasons it
gives are still the argument for the OFF SWITCH — they are the reasons
`adminApi.authRequired=false` has to keep existing, and what changed is only
which way the default points.

**THE ROOT `CLAUDE.md` SAID THE OPPOSITE FOR AS LONG AS IT EXISTED, TOO.** It
read "`/admin-api` is NOT gated and that is deliberate — it is what a test
drives, and it is the way back in when nobody holds a role. Which means anybody
who can reach this port can grant themselves both roles through it." Every
clause of that was true and the last one is what the change was for. It is the
EIGHTH row on the root `CLAUDE.md`'s table of gated surfaces, and it is not a
turnstile.

**WHAT IT IS NOW.** Every call into `/admin-api` presents an OAuth 2.0 access
token this service issued, audienced to this API, carrying `admin:read` for a
read and `admin:write` for anything that changes state. One middleware on the
base path, so the 232 operations are covered by construction rather than by
232 remembered checks. The scopes become the built-in `ADMIN_READ` and
`ADMIN_WRITE` roles and the XACML `access-control` document asks for the one
the action needs — so what this surface demands is stated where every other
access decision in this service is stated, and `admin_api.js` decides the
QUESTION rather than the outcome.

**THE AUDIENCE DEFAULTS TO THIS API'S BASE URL SINCE 2026-09-13, AND THE GATE
ACCEPTS TWO AT THAT DEFAULT.** `adminApi.audience` was `''`, meaning
*`/admin-api` under the host the request arrived on* — correct, and a blank box
on `/admin/rbac`. It is a DERIVED row now: `config.managementApiBaseUrl()`,
which is `global.publicBaseUrl` + `/admin-api` where that is set and otherwise
the main port's own scheme, bound host (`localhost` for a wildcard) and port. A
default cannot see a request, so taking it as the ONLY audience would refuse
every token minted under another name for one process — `sts:8081` on the
compose network, the host port a launcher publishes. So while the row is at its
default, or set empty, `wantedAudiences()` accepts that URL AND the
request-relative one; any other value pins exactly itself, as it always did.
Where `global.publicBaseUrl` is set the two are the same string.

**IT IS A DIFFERENT CREDENTIAL FROM THE CONSOLE'S AND MUST STAY ONE.** A
console session is not an API credential; a token is not a console session.
Two surfaces, two credentials, and express still does not confuse them by
accident — `app.use('/admin', ...)` matches on segment boundaries, so
`/admin-api` never matched the console's gate and never should.

**THE THREE REASONS BELOW SURVIVE, TWO OF THEM INTACT.** A test still drives
this API — a token is minted before any job runs and handed to every one of
them, which is `tests/tools/admin-api-token.js` and its preloaded shim, so no
job holds a secret. **Who mints it depends on who started the service**: a
launcher for a container it brought up, and `tests/tools/run-report.js` itself
for the throwaway it starts — a distinction this file called "both launchers"
until the coverage run that had neither. `tests/CLAUDE.md` argues it. It is still the way back in — through
`adminApi.authRequired`, which restores the open API exactly. What is no longer
true by default is the third: anybody who can reach this port can no longer
grant themselves both roles here.

**AND IT ACQUIRED A BOOTSTRAP HOLE THAT HAS TO BE CLOSED BY CONFIGURATION.**
The seeded `sts-management-api` client's secret is minted at every start and is
readable only THROUGH the API it unlocks, so a service that has restarted is a
service nobody can get a token for. `adminApi.clientSecret` pins it, every path
that starts a service for the suite sets it per run — **before that service
starts, which is the whole of the ordering**, since the seeded client reads it
while it is being seeded — and a deployment that does not set it has an
administrative surface it cannot reach.

---

### The three reasons it was open, kept verbatim

They are why the off switch exists.

* **A test drives this API.** The parent project's `tests/vendored/admin_api.js` walks
  every operation over HTTP with no browser and no cookie jar. A credential here
  would be the only one a test had to hold a secret for, in a service whose
  premise is that it authenticates nobody.
* **It is the way back in.** When the console is closed and nobody who holds a
  role can sign in (the roster emptied after the bootstrap administrator's first
  sign-in, or `admin.openWhenEmpty` off with no role granted), NO browser can
  reach the console — the screen that grants the first role is
  behind the gate that role opens. `POST /admin-api/rbac/grant` is the only door
  out of that state, and a door that needed a role would not be one.
* **The consequence, stated rather than buried: anybody who can reach this port
  can grant themselves both roles here and then use the console.** The gate
  exists so a client can be driven through 302, 401, 403 and a role model — not
  to make this service safe to expose. No password is checked anywhere here and
  `/oauth2/token` will still mint a token for any username asked of it.

If that ever needs to change it is a SEPARATE setting and a separate argument
(`admin.apiAuthRequired` was considered and not built), never a quiet extension
of `admin.authRequired` to this path: a suite that started failing because a
console setting reached an API it never named would be the worst way to find out.

**THAT PARAGRAPH WAS FOLLOWED EXACTLY AND IS WORTH READING AS A PREDICTION THAT
HELD.** The change did come, and it came as a separate setting with a separate
argument — `adminApi.authRequired`, in its own group, with two settings beside
it — and NOT as an extension of `admin.authRequired`. The two gates are still
independent, which is the property that paragraph was protecting: turning this
API's gate off leaves the console gated. The other half of the sentence has
lapsed for a reason of its own — `admin.authRequired` was itself removed on
2026-09-06, so the console's gate can no longer be turned off at all. The name considered here was
`admin.apiAuthRequired` and the one built is `adminApi.*`, which is the same
decision spelt so that the group has somewhere to live.

**Rule 7 held for this feature and is worth noting because it is the case where
it pays most.** `/admin/rbac` arrived with `GET /admin-api/rbac` and `POST
/admin-api/rbac/:action` in the same change, and here the API half is not merely
parity — it is the only door onto the roster that works when the console cannot
be reached at all.

---

## `/admin-api/logout` — four operations, and one that differs from its console form

The sign-out resource mirrors `/admin/logout` and calls the same two functions
in `admin.js`, which call `logout/logout.js`. Rule 7 as usual: the API decides
nothing the console does not.

**One thing about it is worth stating because it is the only place three doors
onto one behaviour deliberately DISAGREE.** `POST /logout` with an empty body is
a **global** logout — that is the documented default and the point of the
endpoint. `POST /admin-api/logout/end` with an empty `select` is **refused**. The
absence is the same and the intent is opposite: an empty selection arriving at
`end` is a caller that built a list and got nothing, where an empty body at
`/logout` is a caller asking for everything. `global` is the operation that means
everything, and it is named.

**Two of the four are NON-SPEC and say so in their own summaries** —
`restore-token` and `restore-kerberos`. RFC 7009 defines no un-revoke and a real
KDC has no clear-the-instant; both exist for the reason
`POST /admin-api/tokens/restore` does, which is that restarting this service to
get back to a working credential turns a two-second test into a two-minute one.

**What this API cannot do is in the reply rather than absent from it.** A
front-channel logout notification is an iframe in the signed-out person's own
browser and a WS-Federation cleanup is an image in it; neither is something this
process performs. They come back in `notifications` and `cleanups` so a caller
can load them itself, and `/logout` is the page where a browser does it without
being asked.

## This whole API is realm-scoped, and only five operations are about realms

`/admin-api/config` is the default realm's configuration.
`/realm/acme/admin-api/config` is `acme`'s, and a `set` posted there sets it on
`acme` alone. That is not a special case anybody wrote here — it falls out of the
same path-prefix middleware in `app.js` that makes `/oauth2/token` realm-scoped,
so **every one of the ninety-odd operations already works per realm** and none of
them was edited.

The five under `/admin-api/realms` manage the REGISTRY, which is process-wide:
there is one list of realms, so `GET /admin-api/realms` answers the same list
whichever prefix it is called under. What differs is `current`, which names the
realm the CALL arrived in — and `remove` refuses to remove that one, because the
caller would be left talking to a prefix that had stopped existing.

Rule 7 is unchanged and was the reason those five exist: `/admin/realms` is a
console page with five actions, so it has five operations, driven through the
SAME `admin.realmsAction()` the form posts to.

**AND THAT SHARED FUNCTION IS WHERE `createRealm` LOST ITS `overrides` FOR
MONTHS.** The operation documents the field, gives it an example
(`{"saml2.entityId": "urn:acme:idp"}`) and says it wins over the six seeded
names; `realms.create()` validates and merges it properly. In between,
`realmsAction()` built its argument out of `id`, `name` and `description` and
dropped the fourth property, so a create carrying overrides answered 200 and
produced a realm configured differently from the one that was asked for. Fixed
2026-08-25.

**Rule 7 is what made it invisible, and it is worth knowing which half of that
rule does not hold.** Parity says every console action has an operation and both
go through one function, which is what stops the two DOORS drifting — and it
worked: neither door was more permissive than the other. What it cannot catch is
a field the API accepts and the console's form does not HAVE, because there is
then no second implementation to disagree with. `tests/vendored/admin_api.js`
checks every documented schema property against a live reply, which is the check
that would have caught this had it covered request bodies as well: a documented
request property that changes nothing is the same class of defect as a
documented response property that is never sent.

**`/admin-api/docs` is the one page in this service that needed a change**, and
the reason is worth keeping. `app.js` rewrites root-relative links in HTML to
carry the realm prefix; the explorer builds its request URLs in JavaScript from
the OpenAPI document's `path` members, and a script is not markup. So the prefix
is handed to it as `data-realm-prefix` on the root element and it prepends it.
Without that, pressing "Try it" inside a realm would call the DEFAULT realm's
API — the page would look right, the call would succeed, and it would have
changed the wrong service.

## `GET /admin-api/crypto` MIRRORS A PAGE THIS FILE CANNOT REQUIRE

Added 2026-08-30 beside the crypto report at `/admin/crypto-metadata`. The
operation calls `admin.cryptoView(req)` and computes nothing of its own, which
is rule 7 read strictly: the page and the operation must not be able to disagree
about what this service's cryptography is, and the way to make that impossible
is for there to be one function.

**The reason it goes through the console rather than through a require is the
route order.** `admin-ui/crypto_metadata.js` is required at 20a — after
`tls/tls_server`, whose certificate it reports — and this module is required at
19. A require in the obvious direction would drag that page's route and
`tls_server`'s three ahead of every route in this file and ahead of ldap, scim
and spiffe. So that module fills `admin.setCryptoReporter()` at its own require
time and this one reads it, exactly as `/admin-api/logout` reaches
`logout/logout.js` through `admin.logoutView()`. Rule 3e's test in the root
`CLAUDE.md` answers yes in both directions.

**It answers 503 and not 404 when the reporter was never installed**, and the
two are different facts: a route that exists and cannot answer is a wiring
mistake somebody can fix, and a route that does not exist is not. The message
names the module rather than saying "unavailable".

**Nothing in the reply is a secret** — key types, key identifiers, curve names,
certificate fingerprints and validity dates, all of them already readable from
`/oauth2/jwks`, `/tls/server-certificate` and the SPIFFE bundle endpoint — and
that is a rule for anything added to it later rather than an observation about
what is in it now.

---

## `/admin-api/permissions` — A RESOURCE OF ITS OWN FOR THE CONFIGURED HALF OF ONE PAGE

Added 2026-09-01, six operations: a `GET` and five actions
(`set-permission-base`, `define-permission`, `remove-permission`,
`grant-permission`, `revoke-permission`), all of them `mirrors`-ing
`/admin/delegation`. A seventh joined them on 2026-09-02 —
`GET /admin-api/permissions/groups`, the register partitioned — and it is
argued below rather than here.

**IT IS A RESOURCE OF ITS OWN RATHER THAN MORE ACTIONS ON `/delegation`**, and
the reason is the same one the console gives for putting two headings on one
page: the acts and the permissions are two registers, and an API answering both
under one path would make a caller tell them apart by the shape of a row.

**AND `GET /admin-api/delegation` DOES NOT CARRY IT, which this paragraph said
it did until 2026-09-01.** The claim was that the API reply carried the register
in an `allowed` member *because the page it mirrors carries both*. Only the
second half was ever true: `GET /admin/delegation?format=json` adds `allowed` in
the console route, and the API handler answers `delegationView(query).json`,
which is the ACTS view — the one shared with `/admin/delegation/map` — and has
never had an `allowed` member in it. The behaviour is right and the sentence was
wrong, so the sentence went rather than the behaviour: folding the configured
register into `delegationView()` would make every caller of the acts view pay
for a walk of `ou=applications` it did not ask for, which is the reason that
function does not build it, and this resource is where the register is reachable
under its own name.

**IT IS THE FIRST TIME ONE CONSOLE PAGE HAS BEEN MIRRORED BY TWO RESOURCES**,
and rule 7 is satisfied by that rather than strained by it: the rule asks that
every page and every ACTION have an operation, not that the mapping be one to
one. `/admin/delegation` was already mirrored read-only by `GET
/admin-api/delegation`; what it grew is five controls, and those five needed
somewhere to be.

**And since 2026-09-01 the FORMS are on two console pages while the ACTIONS are
still one handler.** `grant-permission` is drawn on the client application's own
page under `/admin/applications`, where the client half of a grant is the entry
being looked at rather than an option in a list; `revoke-permission` is drawn on
both, as a row button either way. That changes nothing here, and the reason it
changes nothing is the rule: every one of those forms still POSTs to
`/admin/delegation`, `PERMISSION_ACTIONS` is still all five, and the parity
check still reads that one handler's refusal sentence. **Moving a form is not
moving an action** — making it one would have wanted a
`POST /admin-api/applications/grant-permission` beside the
`/permissions/grant-permission` that already exists, which is two operations for
one write. `admin-ui/CLAUDE.md` argues the move itself.

**`GET /admin-api/permissions/groups` JOINED IT ON 2026-09-02, AND A MEMBER ON
THE `GET` ABOVE WOULD HAVE BEEN THE SHORTER CHANGE AND THE WRONG ONE.** It
answers the register PARTITIONED — a group is a set of applications that can be
reached from one another by following grants with the direction ignored, which
`common/CLAUDE.md`'s rule 3s argues — and it mirrors `GET /admin/delegation`
like the register beside it, because the two console pages it belongs to
(`/admin/delegation/allowed` and `/admin/delegation/cluster`) are drill-downs of
that tab and rule 7's parity check reads a `NAV` path. Three things decided it:

* **`graph` on the reply above is the boundary rather than the precedent.**
  That member is one document about the whole register and its size is the
  register's. A list of groups that carried its grants would repeat the whole
  register once per group; one that did not would leave a caller no way to ask
  for a single group's rows at all.
* **It needs PAGING**, and a member of somebody else's reply has nowhere to put
  a page number. The console's own list of groups is paged, and the standing
  rule here is that a new console page gets an API resource in the same change
  and both get pagination.
* **ONE OPERATION ANSWERS BOTH SHAPES**, `?application=` deciding which, because
  they are the same question at two scales and the console draws them with one
  function. Two operations would have been two places to disagree about what a
  group is. `admin.permissionGroupsView()` is that function, and this handler
  and `/admin/delegation/cluster?format=json` both go through it.

An application the register has never heard of answers **200 with `group:
null`** rather than 404: having no permissions configured is the ordinary state
of most entries in `ou=applications`, which is a fact about the register and not
a missing resource. It is the same three-state honesty the `dangling` flag on a
grant carries.

**THE FIVE ACTION NAMES STUTTER UNDER THIS PATH AND THAT IS DELIBERATE.**
`/admin-api/permissions/define-permission` reads badly and `/permissions/define`
would read well — but the names are the ones in the console's hidden `action`
inputs, where the page is `/admin/delegation` and `define` alone would say
nothing about what is being defined. And `remove` and `revoke` are two different
things here: one stops a resource exposing a permission, the other takes a grant
away from a client. One vocabulary for both doors is worth more than a shorter
URL, and the parity check reads the console's own list either way.


## The directory operations, and the slot they go through (2026-09-01, and three more on 2026-09-05)

`GET /admin-api/ldap/directory`, `/ldap/applications`, `/ldap/federations`,
`/ldap/spiffe` and `/ldap/service` mirror the five console pages that moved into
`/admin/ldap/` that day, and `/ldap/roles`, `/ldap/policies` and `/ldap/peps`
mirror the three added on 2026-09-05 — when `ou=roles`, `ou=policies` and
`ou=peps` each got the page its own module's schema comment had been claiming
for weeks. They exist because of rule 7 and for no other reason —
a page of that console gets an operation here in the same change — and the
parity check in `tests/vendored/admin_api.js` is what would have noticed if they
had not.

**They reach their views through `admin.directoryPageJson()`, which is
`admin.js`'s NINTH SLOT filled by `ldap/ldap_server.js`.** This module is
required at #19 and that one at #21, so a plain require would drag every route
registered there ahead of this API's own; and `admin.js` cannot require it
either, because that module requires `admin.js` back. The slot carries all eight
views and is validated whole — so a name added to `DIRECTORY_PAGE_NAMES`
without its view is a refused install rather than one operation answering as
though no directory were loaded. Each operation calls exactly the function that
DRAWS the page, so an operation and its page cannot come to disagree about what
is in the directory.

**`GET /admin-api/ldap` and `GET /admin-api/ldap/service` are not the same
question and neither is redundant.** The first is the six `ldap.*` SETTINGS —
what the sockets are configured to be. The second is what actually happened when
the process tried to bind them. On a host whose own slapd already holds 389 the
two disagree, and nothing else in this service can report that: the metadata
page is built by walking the express router and a raw TCP listener is not on it.

**THE GATE IS THE POINT OF THEM.** Those pages print `oauthClientSecret` and
`fedClientSecret` in the clear, which is why moving them behind the console's
gate was right; this API takes an access token rather than a browser session,
which is what keeps a test able to read the directory without signing a browser
in. Both halves of that sentence are the argument at the top of this file, not
an exception to it. **It said "deliberately not gated" until 2026-09-09** — the
sentence survived the gate by pointing at a property that was never the point:
what a test cannot do is drive a browser, and minting a token is not driving a
browser.

**Their response schemas are deliberately shallow**, and `admin_api_spec.js`
says why beside them: what they return is DIRECTORY ENTRIES, and this directory
is schemaless on purpose, so an `attributes` member written out property by
property would be a document making a promise the store does not keep. The names
are published in the one place that can keep them right — each reply carries the
container's own `schema`, read out of the module that owns it.

**THE THREE ADDED IN 2026-09-05 ARE READ-ONLY AND SAY SO**, each pointing at
the resource that writes: `/admin-api/roles` for the role register,
`/admin-api/xacml` for the repository and for PEPs. That is the same split
`/ldap/applications` and `/ldap/spiffe` already have, and it is what keeps one
door per fact.

Two of them carry a sentence their writing twin does not, which is the whole
reason they are worth their rows rather than being a shape of the existing
operations. `/ldap/roles` says that the container is HALF the register — the
requirement is `appRequiredRole` on an APPLICATION entry, so a caller wanting
both halves resolved wants `GET /admin-api/roles`. And `/ldap/policies` says
that **a write over LDAP skips the typechecker**: every write through
`/admin-api/xacml` is statically validated so a policy that does not typecheck
is refused at write time, and an `ldapmodify` reaches the entry directly.

## `/admin-api/groups/{action}` — THE HOLE RULE 7 CANNOT SEE (2026-09-06)

`POST /admin-api/groups/create` and `POST /admin-api/groups/add-member` are new,
and what makes them worth a section rather than two rows is HOW LONG THEY WERE
MISSING and WHY nothing here reported it.

`/admin-api/groups` was a read. `/admin/groups` was a read. So this API could
put a PERSON in the directory — `POST /admin-api/users/create`, driven five
thousand times by a load job — and had no way at all to put them in a GROUP;
the only two doors onto a group in this directory were an `ldapadd` on the raw
socket and `POST /scim/v2/Groups`. The console, meanwhile, could report a
dangling member, a claimed membership and the two groups that decide who may use
it, and could create none of them.

**RULE 7 IS SATISFIED EXACTLY WHEN BOTH SIDES ARE MISSING.** It is a parity
check — every control on that console has an operation here, every operation
here names a control there — so it reports DRIFT and is silent about ABSENCE.
That is not a flaw in the rule; it is the boundary of what a parity check can
be. What found this was `tests/vendored/sts_directory_bulk_load_api.js`: a job
named "through the management API" that could not be written, because two of its
three sections would have had to reach for SCIM.

**The pattern is `/groups/:action` and the switch is in `admin.groupsAction()`**,
exactly as `/users/:action`'s is in `usersAction()` — two doors onto one action
must not be two readings of what was sent. That function reaches
`ldap_server.js`'s `createGroup()` and `addGroupMember()` through **`admin.js`'s
TWELFTH SLOT**, `setGroupWriter()`, for the route-order reason every slot here
has.

Four things about their behaviour are decided in that module and are worth
knowing before calling either:

* **A member that names nothing is WRITTEN, not refused.** This directory does
  no referential integrity in either direction — deleting a person leaves their
  DN in every group that listed them — so refusing here would make the dangling
  state `/admin/groups` exists to report impossible to produce from this door.
  `create` returns them in `dangling`; `add-member` returns `present: false`.
* **An empty group is allowed and RFC 4519 says it should not be.** `member` is
  MUST on `groupOfNames`. SCIM already creates one, and an API stricter than
  SCIM about the same store would be two doors disagreeing about what this
  directory holds.
* **`add-member` is IDEMPOTENT** — `ok: true` with `changed: false` for
  somebody already listed, so a script that adds on every run does not fail on
  its second one. Membership is asked across `member`, `uniqueMember` and
  `memberUid` together, which is how `/admin/groups` and the groups claim ask
  it.
* **Nothing is ever written onto the PERSON.** `memberOf` is maintained by
  nothing in this service and is not even a standard attribute; a value written
  there is one no other door here can take away, which is why `admin_rbac.js`
  REFUSES a revoke of a membership held that way.

**REMOVING a member and DELETING a group are deliberately not here.** Both doors
exist — an `ldapmodify` or a SCIM `PATCH` for a membership, an `ldapdelete` or a
SCIM `DELETE` for a group, and `POST /admin-api/rbac` for the two console roles
— and adding operations nobody asked for would be four more things for the two
doors onto them to disagree about. What did not exist anywhere but SCIM and the
socket was CREATION, and that is what was added.

**They needed no exemption in `sts_admin_api_operations.js`'s ledger.** That
walk is driven off the document — every GET, and every POST that carries an
example — so an operation with an example is driven the day it lands. Both
carry one.

## `/admin-api/xacml/monitor` is the one XACML operation about TRAFFIC

Added 2026-09-06 with the console page it mirrors. The other six describe the
repository — what policies exist, what one says, what the PDP would decide about
a subject you name; this answers what is actually HAPPENING, and it is what a
caller reaches for when authorization is misbehaving rather than when it is
being set up.

**NO POST BESIDE IT, and that is rule 7 read exactly rather than by shape**: the
page it mirrors has no control at all. A reset was refused rather than
forgotten — a console that could zero its own monitoring would make every number
on it a number somebody might have zeroed, and the audit log, which is the
durable record of a refusal, cannot be reset either.

Two things about the reply are worth knowing before reading it, and both are
distinctions a single figure would have lost:

* **`allowed` is not `permit`.** XACML has four decisions and a PEP has two
  outcomes, and what maps between them is the PEP's bias — a deny-biased PEP
  refuses a NotApplicable that a permit-biased one allows. An obligation the PEP
  cannot discharge also turns a Permit into a refusal (section 7.2).
* **`decisions.here` and `decisions.remote` are two different kinds of
  evidence.** The first was counted by this process as it happened; the second
  is what registered PEPs REPORT on their heartbeats, in their own memory, and
  goes DOWN when one restarts. `combined` adds them and the description says it
  is arithmetic rather than a measurement.

On the `pdp` row `allowed` and `refused` are **null rather than 0** — this
service produced that decision for somebody else's enforcement point and never
saw what was done with it, and a zero would be a claim about an enforcement it
was not present for. `unenforced` in the totals is what makes the four figures
reconcile; `xacml/CLAUDE.md` argues why a total that does not add up is worse
than a missing one.

## `/admin-api/consent`: a resource of its own, and why the action names stutter

The THIRD register in this family — `/admin-api/delegation` is what HAPPENED,
`/admin-api/permissions` is what is ALLOWED between two applications, and this is
what a PERSON said yes to. A resource of its own for the reason that one is a
resource of its own rather than more actions on `/delegation`: a caller that had
to tell an act from an intent from a consent by the shape of a row would be told
nothing by any of them.

`GET` carries both halves. `globals` is the OVERRIDE —
`oauthGlobalConsent` on an application's entry, which skips the prompt for
everybody and writes nothing about anybody — and `users` is the RECORD, one row
per (person, application, scope). `globals[].resource` says which application
exposes the permission where the scope resolves to one and `globals[].granted`
whether that client also HOLDS it, which are independent questions and the one
place both are visible at once. `users[].unreadable` is a value an `ldapmodify`
put on an entry that is not in the shape this service writes: it consents nothing
and is reported rather than dropped, exactly as a dangling grant is.
`storable: false` means no directory is installed behind the register, so an
answer is honoured once and forgotten.

**THE FOUR ACTION NAMES STUTTER UNDER THIS PATH**
(`/consent/grant-global-consent`) and that is deliberate exactly as
`/permissions/define-permission`'s is. They are the names in the console's hidden
`action` inputs, where the page is `/admin/consent` and `grant` alone would not
say whether it meant the override or somebody's answer — and those two are the
pair a caller most needs kept apart, because removing the wrong one asks the
wrong people again. One vocabulary for both doors is worth more than a shorter
URL, and rule 7's parity check reads the console's own list.

## `/admin-api/sessions` IS NOT A SHAPE OF `/admin-api/logout` (2026-09-04)

Both read `logout/logout.js`, and they answer two different questions:

* `GET /admin-api/logout?user=` is *what is alice still signed into* — keyed on
  one identity, reaching all ten families, including the seven whose rows are
  things this service HANDED OUT and cannot recall.
* `GET /admin-api/sessions` is *who is signed in at all* — across everybody, in
  the three families that have a session. **A `user` parameter on the first
  could not have answered it, because the answer has no user in it.**

It exists because `/admin/sessions` does, which is rule 7, and it was written in
the same change as the page. `POST /admin-api/sessions/revoke` is
`terminate(key, [id])` — the SAME function `POST /admin-api/logout/selective`
calls — so two operations sit over one termination, which is what the parity
asks for when the console grows a button rather than a second implementation.
The row carries both fields the write needs (`key` and `id`), so a caller never
has to construct one.

Three things a caller has to be told and the description does tell:
`expiresAt: 0` means NO EXPIRY and not the epoch; `expiryRule` says which of
three arithmetics produced the number; and on a Kerberos row the revoke does
MORE than the row names, because that protocol has no per-ticket revocation.

**`GET /admin-api/tokens` grew a `session` parameter beside it**, which is the
join between the two resources: every browser-session row carries the
`sessionId` a token issued under it records.

## `/admin-api/caep/sessions`, AND THE GAP THE PARITY CHECK FOUND

`/admin/caep-sessions` is a page of the console and had no operation naming it:
the CAEP GET beside it mirrors `/admin/caep`, and **one operation cannot mirror
two pages**. Nothing noticed until `tests/vendored/admin_api.js` was run against
a tree where that page had a drill-down worth mirroring — the gap pre-dated the
change that exposed it, which is the argument for the check rather than against
it.

ONE OPERATION ANSWERS BOTH SHAPES, `?session=` deciding which, for the reason
`/admin-api/permissions/groups` gives: the register and one session's history are
the same question at two scales, drawn by one function, so two operations would
be two places to disagree.

**The console's three CAEP forms all POST to `/admin/caep` now**, wherever they
are drawn — the applications page's arrangement with `/admin/delegation`, and
for its reason: moving a form is not moving an action, and a route per page
would have wanted an operation per page over one function.

## `/admin-api/roles`: the register, the preview, and the one read that is not a page

Three shapes under one tag, added 2026-09-05 with the role register itself.

`GET /admin-api/roles` is the register whole — the six built-in roles, every
configured role with its three membership lists, and every application that has
been NARROWED. That last list is the reason this operation exists rather than
being `/admin-api/ldap/roles` with a filter: **the two halves of a role live in
two containers**, membership on the role entry and the requirement
(`appRequiredRole`) on the application entry, and this is the only surface that
resolves them together. `requiring[].unknown` is what that resolution buys — a
role an application demands that NOTHING defines, which refuses everybody,
silently and correctly, and looks exactly like the application being broken.

`POST /admin-api/roles/:action` is the five writes: `create-role`,
`delete-role`, `add-member`, `remove-member` and `describe-role`. Creating and
populating are separate on purpose, because a role is worth creating before
anybody holds it — an application can be narrowed to it first and the register
will then say so.

`GET /admin-api/roles/preview` is the one worth reading the code for. **It is
the SAME call the nine issuance sites make** — `common/issuance_gate.check()`,
through `xacml/xacml_role_pep.js`, against the policy `xacml.issuancePolicy`
names — so a preview that agreed with the enforcement only by coincidence is
impossible. That is the only reason it is worth having, and it is why the
answer arrives through `admin.js`'s ELEVENTH SLOT rather than through anything
this module could compute.

**It is not `POST /xacml/pdp`**, which asks the same engine a different
question: an arbitrary request against the repository ROOT, which is the policy
about somebody else's boundary. Two questions, two documents.

### `answered: false` is not leniency, it is the page's own shape

`preview` needs an `application` and a `subject` and declares NEITHER required.
A GET of `/admin/roles` with no parameters draws the form and no answer, so the
operation answers 200 with `answered: false` and says what was missing — this is
a READ, and a read with no question in it has nothing to refuse.

**There is deliberately no `decision` member on that reply.** The hazard is
gone by construction rather than by care: `issuance_gate.check()` ALLOWS a call
that names no application, so an operation that fell through to the gate would
hand back a Permit meaning "you did not ask". `answered` is the first thing to
read, and `available: false` is the separate fact that the XACML family is not
loaded in this process at all.

### `gated` and `enforced` are two different offs

`GET /admin-api/roles` reports both because they are reached differently and a
caller diagnosing "why is nothing being refused" needs to know which one it is.
`gated: false` means the XACML family is not loaded, so `issuance_gate.js` has
no decider and every issuance is allowed whatever the register says.
`enforced: false` means `roles.enforceIssuance` is off — the same outcome by a
different route, and the way back if a policy edit locks something out.

## THE POLICY SITS ABOVE THE ROLES, AND ONLY WHERE THIS API IS GATED AT ALL (2026-09-06)

The product-mode middleware asks the two console roles and then, for a caller
that holds one, asks `common/access_gate.js`. Three things about that.

**IT IS THE LAYER ABOVE AND NOT A REPLACEMENT.** `admin.gateStateFor()` is still
the one answer to *who may administer this service* — asking it rather than
re-deriving it is what stops this file becoming a second one — and the subject
handed to the policy is the SESSION that got the caller through it, never
anything on the request. A PDP deciding faithfully about a subject the caller
nominated is broken access control with extra steps.

**IT RUNS ONLY INSIDE THE `mode.gatesManagementApi()` BRANCH, and that is the
argument this file has always made read one layer up.** In development this API
is open by design: it is what the tests drive and the way back in when nobody
holds a role, which a service that checks no password needs because there is no
other way to bootstrap an administrator. Open means no credential, so no
session, so no subject — and asking a policy whose built-in document refuses an
unauthenticated subject would close exactly that door. **A POLICY LAYER MUST NOT
BE THE THING THAT REMOVES THE RECOVERY PATH.**

**ON AN UNEDITED PRODUCT DEPLOYMENT IT PERMITS**, because the built-in document
asks for a role only where somebody has required one and the caller has already
been shown to hold Admin Read or Admin Write. So turning product mode on does
not acquire a second refusal nobody asked for; what it acquires is somewhere to
put one.

The refusal says the caller PASSED the role check and names the roles they hold,
because "you hold the role and the policy still says no" is the one state a
reader would otherwise spend an afternoon on.

## `/admin-api/mfa`: A REPORT AND A RESET, AND DELIBERATELY NO ENROL (2026-09-10)

**THE CONSOLE PAGE THIS MIRRORED IS GONE AND THIS RESOURCE IS NOT.**
`/admin/mfa` arrived on 2026-09-10 and lasted hours: it edited the `totp.*`
settings AND drew a roster of who held a second factor, and one page cannot be
filed by both halves. The settings are `/admin/totp` and `/admin/webauthn` under
Protocols; the roster is columns on `/admin/users`, and the per-person detail
and both Clear buttons are on that person's own row.

Rule 7 says a console control owes an operation. **It says nothing about an
operation whose page moved**, and deleting a working one to tidy a table would
be a regression dressed as consistency — the same argument `GET
/admin-api/users/new` is kept on, one section up. So this stays, `mirrors`
points at the page that absorbed it, and `admin.mfaView()` answers OUT OF THAT
VIEW rather than scanning the credential store a second time: two scans would be
two answers to how many people hold a second factor, agreeing until the day they
did not.

**BOTH ACTIONS ANSWER ON TWO PATHS NOW** — here and as
`POST /admin-api/users/{clear-totp,clear-key}`, one switch reached two ways,
because the console control moved and a caller's script did not. Their request
schemas take BOTH spellings of the person (`username` and `user`) for the same
reason: a caller that followed the other path's example must not be refused with
a message about a member of the request rather than about the person.

**THE MISSING OPERATION IS THE INTERESTING ONE.** There is no `enrol`, and it is
a refusal rather than an omission: enrolling an authenticator means being SHOWN
a shared secret, so an operation here would be an administrative door that mints
a working second factor for any account — after which whoever called it holds
that account's second factor. Enrolment happens where the person is
(`/portal/mfa`) or where a credential authorises it (`/portal/activate`).

**`clear-totp` ANSWERS 400 FOR AN ENROLMENT NOBODY HOLDS**, where
`rbac/grant` answers 200 with `changed: false` for a role somebody already has.
The difference is worth stating because it looks like an inconsistency: a grant
has an idempotent reading a script wants — *make sure they hold this* — and a
clear does not. The caller asked to clear a specific thing and it was not there.

**`clear-key` GOES THROUGH `credentials.removeKey()`**, which is what carries
the refusal that matters: it will not remove the last way in. An operator must
not be able to do what the owner is stopped from doing.


## `/admin-api/tls/trust` — THE TRUSTSTORE'S GATED RUNTIME DOOR (2026-09-12)

`GET /admin-api/tls/trust` (paged with `page` / `per`) and `POST
/admin-api/tls/trust/{add,remove}`, mirroring `/admin/tls/trust` through
`adminViews.truststoreJson()` and `adminActions.truststoreAction()`, which reach
`tls/tls_server.js` through the console's thirteenth slot. **This file's own
middleware is the whole of the credential**: `admin:read` lists and
`admin:write` changes, by method, so nothing in the two rows re-checks it — and
that is exactly what `tls/tls_server.js` said the runtime door had to be built
behind rather than copied.

Four things a caller has to be told, and the descriptions tell them:

* **IT IS THE PROCESS'S TRUSTSTORE**, so every realm prefix reads and writes the
  same array; and with request workers both operations are answered by the front
  process (`NEVER_DISPATCHED`), because a worker's copy of the array configures
  no listener.
* **A RUNTIME ANCHOR IS PERSISTED** (2026-09-12; this bullet read *nothing is
  persisted* until then) — in `ou=trustAnchors` in the default realm's
  directory, so it survives a restart wherever the directory does and reaches
  every other process against the same store. `persisted` in each reply says
  whether it was written down. A removed `file` anchor still comes back.
* **NO BULK CLEAR, AND `add` IS ALL OR NOTHING** on a block OpenSSL cannot
  read. `remove` takes ONE fingerprint and a bodyless POST removes nothing —
  which matters because `tests/vendored/sts_metadata.js` posts to every route
  with no body.
* **NO PRIVATE KEY IS IN ANY REPLY** — the truststore holds certificates only.

**`sts_admin_api_operations.js` HOLDS BOTH ACTIONS OUT OF ITS EXAMPLE REPLAY**
(`REPLAY_HELD_BACK`), for the reason `spiffe/rotate` is held back: the replay
runs in a throwaway realm and this array has no realm, so an example that were
ever a real certificate would be left in every later job's handshakes. Its
`theTruststoreRoundTrips()` drives them instead, at the root, with a CA it mints,
and asserts a read-only token is refused the write.


## `/admin-api/kerberos/principals` — THE STORED KERBEROS KEYS (2026-09-12)

`GET /admin-api/kerberos/principals` (paged with `per`, `peoplePage` and
`servicesPage`) and `POST /admin-api/kerberos/principals/{create-service,
rotate-service,delete-service,clear-person-keys}`, mirroring
`/admin/kerberos/principals` through `adminViews.kerberosPrincipalsJson()` and
`adminActions.kerberosPrincipalsAction()`, which require
`kerberos/krb5_person_keys.js` in the ordinary direction — it registers no route,
so neither a cycle nor a route move is possible and no slot was added (and no
forwarded collaborator, so `tests/admin_actions_layer.js` did not change).

Four things a caller is told, and the descriptions tell them:

* **CREATE AND ROTATE ARE THE ONLY REPLIES CARRYING KEY MATERIAL**, as an MIT
  keytab in base64 under `keytab`, handed over once: nothing can read a stored
  key back afterwards, the GET included. A lost keytab is a rotation, not a read.
* **NEITHER LIST CARRIES A KEY** — people and services are enctypes, kvno, salt
  and when, which is the public half (`stsKrb5KeyInfo`, `krb5ServiceKeyInfo`).
* **IT IS THE REALM THE CALL IS IN (2026-09-15)**, and every reply says which as
  `trustRealm`. It read *IT IS THE DEFAULT TRUST REALM'S, under every prefix* while
  the KDC was the process's; each trust realm whose `krb5.enabled` is on now has a
  Kerberos realm and a principal database of its own, and a realm with none answers
  with empty lists and says so.
* **`clear-person-keys` for somebody with no keys is `ok` with `cleared: false`**
  rather than a refusal, because the state asked for is the state that holds.
* **SIX ACTIONS SINCE LATER THE SAME DAY**: `drop-previous-service-keys` (`spn`)
  and `drop-previous-person-keys` (`username`) end the window in which a ticket
  under a PREVIOUS key version is still accepted. A rotate's reply grew
  `keytabKvnos` and `retained`, and every row of the GET grew `retained` (kvno,
  enctypes, expiry — never a key), with `retention` at the top saying the bounds
  in force. A drop with nothing kept answers `dropped: 0`; one for a principal
  holding no stored key is refused. `kerberos/CLAUDE.md` argues the design.

**`sts_admin_api_operations.js` HOLDS ALL SIX OUT OF ITS EXAMPLE REPLAY**
(`REPLAY_HELD_BACK`) — for the same reason as the truststore's: the replay runs
in a throwaway realm and these write in the default one. Its
`theKerberosPrincipalsRoundTrip()` drives them at the root instead, with a read
back after every write.


## `/admin-api/pki` — FOUR OPERATIONS, AND A MODULE REQUIRED IN THE ORDINARY DIRECTION (2026-09-10)

`GET /admin-api/pki` and `POST /admin-api/pki/{build,issue,revoke,clear}`,
mirroring `/admin/pki`. Rule 7 exactly: every control on that page has an
operation and both go through the SAME functions in `admin-ui/pki_admin.js`, so
this API decides nothing that console does not.

**THE MODULE IS A PLAIN REQUIRE AND NEEDS NO SLOT**, which is the one thing
about this resource worth knowing. It sits at **18a** in
`common/protocol_stack.js` — after `admin-ui/admin` and BEFORE this file — so by
the time this require runs it is a cache hit and registers nothing; and it
requires only `admin.js` and `common/pki.js`, which is a LIBRARY (rule 3), so
there is no route it could move and no cycle it could close.
`admin-ui/crypto_metadata.js` is the contrast: it is at 20a because it reads an
algorithm table out of `tls/tls_server.js` at 20, so it needed the seventh slot.
Rule 3e says a slot is what you pay for a require that would close a cycle or
move a route, and this one would do neither.

**`pkiAction()` RESOLVES**, so this is the second action handler in this API
that awaits — `/ssf/:action` is the first, and for a related reason. A rejection
is turned into a 500 with the message rather than being left as an unhandled
one.

**NO PRIVATE KEY IS EVER IN THE REPLY.** `common/pki.js`'s `describe()` drops
every one of them on the way out, so a handler here could not leak the Root's
key by forgetting. The CERTIFICATES go out whole, because a certificate is the
half of a key pair meant to be handed around and the Root is the one thing a
relying party has to be given out of band. An application's own private key is
on its directory entry, in the clear, which is `oauthClientSecret`'s decision
and is documented as such rather than hidden.

**`revoke` IS NAMED FOR THE BUTTON AND THE DESCRIPTION KEEPS THE CLAIM
HONEST.** It takes a key pair OFF an application and puts nothing on any
revocation list. The word on the console is `revoke`; the sentence that says
what it does and does not do is in the operation's `description`, which is
where a caller reads it.

**THAT SENTENCE USED TO REST ON AN ABSENCE AND NOW RESTS ON A DISTINCTION,
WHICH MAKES IT MORE IMPORTANT RATHER THAN LESS.** It read *this service
publishes no CRL and answers no OCSP, so the operation does not revoke
anything* — true until 2026-09-11, when every certificate authority here grew
a CRL and an OCSP responder. **There are now two operations on this resource
with the word `revoke` in them and they do completely different things**:

| Operation | What it changes |
|---|---|
| `revoke` | an application's DIRECTORY ENTRY — seven attributes for `jwt`, six for `saml`. This service stops ACCEPTING what that key signs. The certificate still chains. |
| `revoke-certificate` | an issuer's REVOCATION LIST. This service's CRL and OCSP responder say `revoked` for that serial. Nobody loses a key and nothing stops chaining for a party that does not check. |

**THE OLDER NAME WAS KEPT AND THE NEW ONE WORKED AROUND IT**, which is the
decision worth recording: this action list is PUBLISHED — `GET /admin-api/pki`
carries it and a machine chooses from it — so renaming `revoke` to make room
would have broken every caller that already had it, in order to fix a confusion
two descriptions can carry instead. `release-hold` is its pair, and only a
`certificateHold` can be released.

## RECOVERY CODES: A SETTINGS RESOURCE AND A CLEAR, AND DELIBERATELY NOTHING ELSE (2026-09-10)

Rule 7 again — `/admin/backup-codes` arrived on the console and owes an
operation in the same change — and the interesting half is what this API does
NOT get.

| Operation | What it is |
|---|---|
| `GET /admin-api/backup-codes` | the four `backupCodes.*` settings, with the MECHANISM in `status`, read from `common/backup_codes.js` |
| `POST /admin-api/users/clear-backup-codes` | deletes a person's set, which re-arms the automatic issue |

**THERE IS NO OPERATION THAT ISSUES A SET AND THERE WILL NOT BE**, for the same
reason there is no `enrol` beside `clear-totp` and `clear-key`: a set is created
by the ACT of enrolling a second factor and by nothing else, and a management
API that minted one would be an administrative door handing a working second
factor to any account. `POST /users/clear-backup-codes` is the only route to a
second set, and what it does is DELETE.

**AND THERE IS NO OPERATION THAT READS A CODE.** `GET /users` reports the counts
on each row and never the strings; the person reads their own set on
`/portal/mfa` and nowhere else. That is asserted rather than trusted —
`tests/vendored/sts_portal_backup_codes.js` walks this API's own OpenAPI
document for a path that looks like a reader, and then checks that no code it
holds appears anywhere in a `GET /users` reply.

**The settings resource needs no POST**, like `/totp` and `/webauthn` beside it:
every form on the page posts `set-many` to `/admin/config`, so a write here
would be a second way to change one value.

**Unlike `/totp`, its description carries no paragraph about affecting new
enrolments only.** That one has to, because a TOTP parameter was told to an app
this service cannot reach. Nothing here is told to anybody — a recovery code is
a string compared against a stored string — so shortening `backupCodes.length`
changes what the next set looks like and leaves an existing one matching exactly
as it did.

## `/admin-api/policies`, AND `users/create` GENERATING A PASSWORD BY DEFAULT (2026-09-12)

Two operations mirroring `/admin/policies`: `GET /admin-api/policies` over
`adminViews.passwordPoliciesView()` and `POST /admin-api/policies/{save-password-policy,reset-password-policy}`
over `adminActions.passwordPoliciesAction()`. **The action names stutter** for
`/permissions/define-permission`'s reason: they are the console's hidden
`action` values, and the page will hold more than one kind of policy.

**THE SAVE'S REQUEST SCHEMA IS BUILT FROM `password_policy.FIELDS`**, for
`narrowDoorProperties()`'s reason, and each field is `oneOf` its JSON type or a
string: this file's ajv runs with `coerceTypes` off, and a body copied from the
console carries `"12"` and `"TRUE"`. The module parses both and refuses anything
else by name. `required` is published and — as everywhere here — enforced by the
handler, which says WHICH field was missing and why a save needs all of them.

**`POST /admin-api/users/create` DEFAULTS `credential` TO `generate`**, which is
a behaviour change for every caller that sent none: the reply now carries
`password` once, and each create costs one scrypt hash. rcbj chose it for both
doors. A caller that means nobody to hold anything sends `credential: "none"`;
`sts_directory_bulk_load_api.js`, `sts_second_factor_pages.js` and
`sts_portal_totp.js` were changed to say so. A typed password on this door, and
a generated one, meet the realm's password policy in product mode, and
`set-password` does the same.

## `upload-certificate` AND `regenerate-secret` (2026-09-13)

Two operations for the Credentials section of an application's console page,
in the same change as the page (rule 7):

* `POST /admin-api/pki/upload-certificate` — on the PKI resource beside `issue`
  and `revoke`, because it writes the same attributes through the same table
  (`pki_admin.js`'s `PURPOSE_WRITES`) and a key pair should be taken off with
  one act however it arrived. The chain rules are `common/pki.js`'s
  `registerCertificate()`.
* `POST /admin-api/applications/regenerate-secret` — on the applications
  resource, because the secret is an application attribute and the mint is
  `applications.regenerateClientSecret()`. **The reply is the one place this
  act hands the value out**; the audit row names the attribute. It refuses
  `sts-management-api` while `adminApi.clientSecret` pins that secret, because
  every token for this API is minted with the setting and seeding never
  rewrites an existing entry — regenerating it would be this API locking its
  own bootstrap out wherever a secret is checked.

`GET /admin-api/applications?application=` grew `credentials`, and no GET was
added: the page is the application drill-down, which already had its operation.

## `issue-tls-client-certificate` AND `revoke-tls-client-certificate` (2026-09-13)

The Mutual TLS subsection of an application's Credentials section, in the same
change as the page (rule 7), as two arms of `applicationsAction()` over
`common/tls_client_certificates.js` — issuing to an application is that module's
`issue()` with `kind: 'application'`, which a person's portal certificate already
went through. **The issue's reply is the only copy of the private key**: `files`
holds the PKCS#12 (base64), the encrypted PEM key and the chain, all under
`password`, which is neither stored nor audited. The action is a PROMISE, answered
through the handler's existing `refresh-metadata` branch. The revoke looks among
THIS application's certificates only. Codes `STS-ADMIN-0720..0723`,
`STS-PKI-0180..0181`. **`/admin-api` also checks RFC 8705's `cnf["x5t#S256"]`
since the same change** (`STS-API-0110`) — see `oauth-oidc/CLAUDE.md` 3an.

## `issue-software-statement` (2026-09-13)

`POST /admin-api/applications/issue-software-statement` mirrors the *Issue a
statement* control in the Software statements section of an application's
console page (rule 7, same change). It calls `applicationsAction()`, which calls
`oauth-oidc/software_statement.js`'s `issue()`; the reply carries the statement,
which is not a secret. **The issuer comes from the ROUTE'S context** — both
doors add `base: baseUrlOf(req)` beside `authorizationServers` — and never from
the body, because a registration must match the issuer at the address it
arrives on. `metadata` and `lifetimeSeconds` are `oneOf` object-or-string and
integer-or-string, for the console form's text. `GET
/admin-api/applications?application=` grew `softwareStatements` (declared
issuers, usable keys, the issued statement and whether it verifies now, and how
the client registered); no GET was added.

## `GET /admin-api/certificates` — THE CERTIFICATE DETAILS DIALOG, FOR A MACHINE (2026-09-13)

One operation, two shapes, `?certificate=` deciding which — the arrangement
`/permissions/groups` argues. Without it: every certificate this realm holds,
one row per certificate with every place it appears, paged and filterable by
`q`. With it: that certificate's every field and its trust chain, from
`admin-core/certificate_views.js`, the same function the dialog on `/admin/pki`
and `/admin/crypto-metadata` is drawn from. **No POST**: the dialog is a view
and has no control.

A fingerprint is looked up and never parsed from the request, so anything this
realm does not hold is refused — `400` for a value that is not a SHA-256 (`STS-ADMIN-0640`),
`404` for one not held here (`STS-ADMIN-0641`), `500` for one that could not be
described. A certificate from another realm is reached under that realm's
prefix, which is the realm boundary rather than an inconvenience.
`tests/vendored/sts_admin_api_operations.js`'s `theCertificateDetailsAnswer()`
drives both shapes, the colon spelling, and the refusal at the default realm's
door of a certificate a throwaway realm holds.

## `pqc` ON THE KEY LIST AND THE PKI KEY-PAIR ROWS (2026-09-13)

`GET /admin-api/keys` rows and `GET /admin-api/pki`'s `issued` and `persons`
rows carry `pqc` — `null` for a classical key, otherwise `{ kind, algorithm,
label, family, standard }` with `kind` one of `pq`, `composite`, `kem` or
`hybrid` — which is the answer the post-quantum icon on `/admin/keys` and
`/admin/pki` is drawn from (`common/pqc_support.js`). It is in `KeyList`'s
schema. No operation was added: the icon is a view of data both resources
already carried. `sts_admin_api_operations.js`'s
`theKeyListMarksPostQuantumKeys()` asserts every signing-key row's kind.

## `target=person` ON `issue`, `upload-certificate` AND `revoke`, AND `credentials` ON A USER (2026-09-13)

No new operation: the Credentials section of `/admin/users?user=` posts the same
three PKI actions with `target=person`, so rule 7 is paid by three schema edits.
`upload-certificate`'s `target` enum was `['application']` with
`additionalProperties: false`, which would have REFUSED a person upload at the
validator before the handler saw it; `issue` and `revoke` said a person refuses
`purpose=saml` and that `revoke` ignores `purpose` for one, both now false. `GET
/admin-api/users?user=` answers `credentials` — both profiles' key pairs, no
private key — documented on `UserDetail` beside `ldap`.

**A pre-existing mismatch noticed, not fixed**: `issue` documents `keyAlg` while
`pkiAction()` reads `leafKeyAlg` (the console's field name), so the API's `keyAlg`
is accepted by the schema and ignored.

## `GET /admin-api/rbac` PAGES EVERY LIST IN ITS REPLY (2026-09-13)

`grants` was already paged by `page` and `per`. The other two lists were not:
`candidates` (everybody a role could be granted to) and each role's `members`
and `claimed` — on a directory of thousands, thousands of rows on every read of
the roster. Now:

* **`candidates` is paged by `candidatesPage` and the shared `per`**, answered
  in `candidatesPaging` — `detailPagingParameters()`'s naming, so the request
  is spelt from the reply. Its default page size is twenty rather than
  `DEFAULT_PER_PAGE`, because the console's results pane shows twenty and the
  two should not disagree about who is on a page. `personq` narrows it;
  `personfrom`, the pane's offset, is honoured as the page it falls on when
  `candidatesPage` is absent.
* **`roles[]` carries counts and no member lists.** `members` and `claimed`
  are the same rows `grants` pages, and `?role=` narrows `grants` to one role,
  so keeping them would have been an unpaged second copy. Nothing in either
  suite read them.

`sts_admin_api_operations.js`'s `theAdminRolesRoundTrip()` asserts all three.

## `issue-pep-certificate`: THE ONE XACML ACTION THAT AWAITS (2026-09-13)

`POST /admin-api/xacml/issue-pep-certificate` issues a registered remote PEP the
key pair for its HTTPS listener, from the realm's `pep-tls` Issuing CA, and
mirrors the **Issue certificate** control on `/admin/xacml/peps` through the
same `pepAction()` — rule 7 in the ordinary way. Three things about it:

* **`/xacml/:action` SETTLES A PROMISE NOW.** This action answers one and the
  other XACML actions answer a result, so `admin-core/admin_actions.js`'s
  `xacmlAction()` converts either and the handler here `Promise.resolve()`s it,
  turning a rejection into a 500 naming the message. It is the third action
  handler here that awaits, after `/ssf/:action` and `/pki/:action`.
* **THE PRIVATE KEY IS IN THE REPLY**, once, like `/pki/issue`'s, and
  `sendJson()`'s `no-store` is what keeps it out of caches. `GET
  /admin-api/xacml/peps` carries the certificate on each row as
  `listenerCertificate` — never the key — read from `pki.js`'s register.
* **`keyAlg`'s ENUM IS READ FROM `pki.TLS_SERVER_KEY_ALGS`**, which is why
  this file requires `common/pki.js` (a library, a cache hit): the document
  cannot offer an algorithm the module refuses. The example names a PEP that is
  not registered in the replay's throwaway realm, so the ledger records it as
  refused about its referent, which is the correct reading.

## `protocolEndpoints` ON THE GET THAT MIRRORS A PROTOCOLS PAGE (2026-09-13)

Every Protocols console page lists its realm's endpoints, and rule 7 asks the
operation mirroring it to answer the same. **No handler changed.** The
registration loop wraps a GET whose `mirrors` is exactly `GET /admin/<page>`
for a page in `admin-core/protocol_endpoints.js`'s table, putting the rows on
`res.locals`; `sendJson()` adds them as `protocolEndpoints` to a 200 whose body
is a plain object. A `mirrors` naming two pages is a mirror of neither and gets
nothing — the one whose `mirrors` reads `GET /admin/pki and GET
/admin/crypto-metadata` is the case. `admin_api_spec.js`'s `operationOf()` says so in those operations'
descriptions from the same test (37 of them), rather than in each response
schema: every one is an `openObject`, and the member is added outside the view
every schema describes.

## SIX MORE USERS ACTIONS (2026-09-13)

`POST /admin-api/users/{reset-password, issue-password-reset,
disable-primary-keys, disable-mfa, require-mfa, stop-requiring-mfa}` mirror the
*Password and second factors* section of a person's console page, through the
same `usersAction()`. Each documents a `{ user }` body with an example on
`alice`, which `sts_admin_api_operations.js` replays in its throwaway realm. The
handler passes `base: baseUrlOf(req)`, so `issue-password-reset`'s `resetUrl`
names the realm the call was made in. **`reset-password` answers `password` and
`issue-password-reset` answers `resetUrl` in the JSON body, once** — neither is
retrievable afterwards, and neither is in the audit row.

## A REALM'S OWN TOKEN (2026-09-14, #32)

A trust realm has administrators of its own (`admin-ui/CLAUDE.md` 8d), and rule 7
owes them this API as well as the console. rcbj chose a realm-scoped
`sts-management-api` token per realm over reusing the service token. The gate
keeps the SERVICE credential exactly as it was and adds a second, narrower one:

* **TRIED SECOND, AND ONLY UNDER A REALM PREFIX.** A token that does not verify
  under the default realm's key is tried under the AMBIENT realm's key when the
  request is under `/realm/<id>/admin-api`, and never at `/admin-api` itself, so
  one realm's key is never asked about another realm's request.
* **THE REALM'S ISSUER AND AUDIENCE.** `realmIssuerAccepted()` asks
  `jwtAccessToken.isHostedIssuer()` against the request's realm base, and
  `realmAudienceAccepted()` wants `<base>/realm/<id>/admin-api` — what
  `resource=` at that realm's token endpoint gives. `adminApi.audience` pins the
  service's audience and is not consulted.
* **ONLY FROM THAT REALM'S `sts-management-api`** (`STS-API-0111`). The token
  endpoint does not restrict who may ask for `admin:*`, so without this any
  client registered in the realm — dynamic registration included — could mint
  itself Admin Write over the realm. **This is narrower than the service token,
  which accepts a token issued to any client carrying the scopes**; that wider
  gap is not changed here.
* **THE CONSOLE'S SCOPE, READ OFF THE OPERATION** (`STS-API-0112`).
  `consoleOperationOf()` maps the request to the console path and action it
  mirrors — `POST /admin-api/pki/build-root` is `build-root` on `/admin/pki` —
  and `admin_scope.refusalFor()` answers as it does for the console. So the two
  doors refuse a realm administrator the same things by construction.

The realm's client secret is minted per start and is not pinned by
`adminApi.clientSecret`, which is the service client's; a realm administrator
reads or regenerates it on their realm's console
(`/realm/<id>/admin/applications?application=sts-management-api`). The
pinned-secret refusal on `regenerate-secret` applies in the default realm only.
With `adminApi.authRequired` off, a console SESSION reaching this API is confined
the same way when its authority is a realm's.

## Several nodes: users/create and groups/create claim their names (2026-09-14, #46 section 3)

`runClaimed()` wraps the two action endpoints: for `action=create` where a
create can race another process (`directory_create_claims.active()`), the name
is claimed across nodes first; a create that finds it claimed waits for the
release (up to five seconds) and then meets the directory's own check, answering
409 (`STS-LDAP-0092`) only if the name is still claimed after that, or 503
when the store cannot be asked (`STS-LDAP-0093`); an action that threw after
claiming gives the claim back and answers 500 (`STS-API-0113`). Everywhere else
the handler runs synchronously as it did. The directory module is found in the
require CACHE, never required: it is below this module in the route order. The
design is `ldap/CLAUDE.md`'s, *Several nodes: a create claims its name*.
