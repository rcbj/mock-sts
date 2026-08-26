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
     asserted from outside, by the parent project's `tests/admin_api.js`, and it
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
fourteen protocol families, each with what it means — and the container DN a new
entry would land in. That is the property `editableAttributes()` gives the
console's two selects (a form cannot offer what the action would refuse),
reached over HTTP: a caller that reads this cannot construct a create the
service will refuse. Compare the alternative, which is the enum written out in
this file's document and in the console's markup and kept in step by hand.

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

* **A test drives this API.** The parent project's `tests/admin_api.js` walks
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
then no second implementation to disagree with. `tests/admin_api.js` over there
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
