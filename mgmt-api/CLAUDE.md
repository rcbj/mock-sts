# mgmt-api/

The management API at `/admin-api`, its generated OpenAPI document, and the
browser-side explorer.

| File | What it is |
|---|---|
| `admin_api.js` | The table of operations. Every one calls a function in `../admin-ui/admin.js`. |
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
bounding — **and it would be the UNGATED door**, since this API is not gated and
the console is. The console has no create form for the same reason, so there is
no control to mirror and the parity holds; `ssf/CLAUDE.md` argues the outbound
request itself.

### `/admin-api/federation` is where rule 7 pays MOST, and the honest sentence is sharper here

`/admin/federation` arrived with `GET /admin-api/federation` and `POST
/admin-api/federation/:action` with all seven of its actions, in the same change.
Rule 7 as written is satisfied by that. What is worth arguing is why this
resource matters more than the parity rule alone would suggest, and what it costs.

**It is the only way the feature can be exercised automatically.** A federated
sign-in cannot be driven without a configured relationship, and a relationship
cannot be configured through a gated console by a test with no cookie jar. This
API is not gated, so `POST /admin-api/federation/create` is to federation what
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

## `/admin-api/docs` is the only page here with an *explorer* script

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

## `/admin-api` IS NOT GATED AND THE CONSOLE NOW IS

`admin.authRequired` (on by default) puts a sign-on session and one of two roles
in front of every page and form under `/admin`. It puts nothing in front of
anything here, and express does not do it by accident: `app.use('/admin', ...)`
matches on segment boundaries, so `/admin-api` never matched it.

Three reasons, and the third is the one to read before "fixing" this:

* **A test drives this API.** The parent project's `tests/vendored/admin_api.js` walks
  every operation over HTTP with no browser and no cookie jar. A credential here
  would be the only one a test had to hold a secret for, in a service whose
  premise is that it authenticates nobody.
* **It is the way back in.** With `admin.openWhenEmpty` off and no role granted,
  NO browser can reach the console — the screen that grants the first role is
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
