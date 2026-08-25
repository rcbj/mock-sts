# admin-ui/

The admin console at `/admin`. Three files now:

| File | What it is |
|---|---|
| `admin.js` | Every page, every form, the shell they are drawn in, and the GATE in front of all of them. The largest file in the repository, because every page's HTML and every page's JSON view are built in the same function — deliberately, for the reason `../mgmt-api/CLAUDE.md` gives. |
| `admin_rbac.js` | **Who may use it.** Two roles, held as two ordinary groups in the embedded directory. A library (rule 3): it registers nothing. |
| `delegation_map.js` | **The delegation picture**, at `/admin/delegation/map`. Layout with `@dagrejs/dagre`, every shape its own SVG. A library (rule 3): it registers nothing, requires nothing in this service but `helpers.js`, and is HANDED what each box is. |

**It IS protected now, and it holds nothing on disk.** It is also the one surface
that can CHANGE what the protocol endpoints do, which is why it is the one that
grew a gate.

5. **`admin.js` must stay after `oauth2.js` too, for the same reason**: it reads that
   `sessions` map so the metrics page can report real sign-on sessions. And the same
   one-store rule applies to REVOCATION — the set of revoked jtis lives in
   `admin_stats.js` and serves both the console and RFC 7009's `/oauth2/revoke`. Two
   sets would each look correct alone and never see each other, and a token revoked
   from the console would keep introspecting as active with no error to point at.

   **THE CONSOLE ENDS SESSIONS NOW, AND THIS FILE STILL WRITES TO NEITHER
   STORE.** `/admin/logout` arrived on 2026-08-24 and reversed a non-goal this
   console documented in four places: *it does not end a sign-on session,
   because `/oauth2/logout` and `wsignout1.0` already do and the second has a
   cleanup to fan out; a third way to end one would be a third way to get that
   wrong.* That argument was correct while each sign-out had a fan-out written
   INTO it. It stopped being correct when the fan-outs became functions owned by
   the protocol module each belongs to — `wsfed.cleanupTargetsFor()`,
   `saml2_sso.logoutTargetsFor()`, `oauth-oidc/frontchannel_logout.js` — and
   `authn.js`'s `dropSession()` became the single place a session stops
   existing.

   So the rule that survives is the one that was doing the work all along: this
   file READS the session map and writes it nowhere. `/admin/logout` calls
   `logout/logout.js`, which calls `authn.js`. A `sessions.delete()` here would
   be the fourth way, and the one that skipped the RFC 9700 refresh revocation
   and the audit row.

   **What this console genuinely cannot do is DELIVER the notifications.** A
   front-channel logout is an iframe in the signed-out person's own browser and
   a WS-Federation cleanup is an image in it. `/logout` is that browser;
   `/admin/logout` is an operator looking at somebody else, so it reports what
   would be sent and does not pretend to send it.

8c. **`setLogoutReader()` IS THE SIXTH SLOT AND IT IS THE SECOND THAT FAILED
   RULE 3e'S TEST BOTH WAYS ROUND.** `logout/logout.js` requires
   `ldap_server.js` — for the bound connections that ARE the LDAP session — and
   `ldap_server.js` requires THIS file, so a require in the obvious direction
   closes a cycle AND drags every `/ldap` route into the router ahead of the
   console's own.

   It carries ONE object — `FAMILIES`, `inventoryFor`, `terminate` — and
   `setLogoutReader()` validates it whole and refuses it whole, for the reason
   the directory WRITER's slot gives: a module that filled a combined slot with
   only the readers would leave `/admin/logout` listing what is live and unable
   to end any of it, which is the worse of the two halves. It warns rather than
   throwing, like `admin_rbac.js`'s install: a console that will not start is
   worse than one page that says why it cannot answer.

   **`FAMILIES` is the PROSE and this file must not carry a second copy.** What
   a logout reaches, what it cannot, and the specification each family cites are
   written once in `logout/logout.js` and rendered here — the same division
   `/admin/groups` keeps with `ldap_server.js` and `/admin/delegation` keeps with
   `delegation.js`. A family added over there appears on this page with no edit.


It also reads the SESSION store, which `../authn/authn.js` owns.

---

7a. **THE BREADCRUMB TRAIL IS IN THE SHELL AND IT IS ON EVERY PAGE.**
   `page()` draws `trailBar()` under the nav on all of them — `Admin console ›
   Applications › rfc9700-debugger`, and on `/admin` itself the one crumb. It is
   not the nav said twice: the nav answers "what else is there", the trail
   answers "where am I and how do I get back", and the tab for the section a
   reader is standing IN is exactly the tab that says nothing about the page they
   are standing ON. That was the original bug — `item.path === active` is true on
   `/admin/applications` and on `/admin/applications?application=x` alike, and the
   active tab is drawn as plain text, so the one control pointing at the list was
   the one control the shell had turned off.

   A drill-down view returns `up` — `upTo(section, leaf, listView)` — and
   `respond()` threads it to `page()`. It makes the active tab a LINK as well.
   **The section label comes from `NAV`**, so a renamed tab cannot leave a trail
   naming the old one. **The last crumb is never a link**: a crumb that reloads
   the page you are on teaches a reader not to trust the ones beside it.

   **THE NAV IS A GROUPED LIST DOWN THE LEFT NOW AND THE TRAIL DID NOT CHANGE.**
   `SECTIONS` is the structure and `NAV` is DERIVED from it — never written by
   hand, because a page present in one and missing from the other leaves a
   drill-down whose trail names a path instead of a section. **The section a page
   is in is deliberately NOT a crumb**: a section has no page of its own, so its
   crumb could not be a link, and a dead crumb in the MIDDLE of a trail is the
   same mistake the last crumb rule exists to prevent. The section is visible
   where it is useful, which is the sidebar heading above the page you are on.

   **PROTOCOLS HAS A THIRD LEVEL AND NOTHING ELSE DOES.** An item in a section's
   `items` is either a page (`path` + `label`) or a GROUP (`title` + `what` +
   `items`), and `isNavGroup()` is the single predicate that decides which.
   There are four groups, all under Protocols — **OAuth2 / OIDC** (authorization
   servers, token lifetimes, custom claims), **SAML** (SAML 2.0 identity
   provider, custom SAML attributes), **Verifiable Credentials** (credential
   claims, verifier request) and **SPIFFE** (SPIFFE, registration entries,
   agents) — with SCIM left ungrouped beside them. **SAML USED TO BE THE
   EXCEPTION HERE and no longer is**: it held ONE page, and the argument for
   keeping the heading anyway was that it names a protocol family this service
   speaks in two versions and two profiles while the page under it configured
   one aspect of that family — where SCIM's one page IS the whole of SCIM here.
   The SAML 2.0 Web Browser SSO profile arrived on 2026-08-24 and put a second
   page under it, so the group now earns its heading the ordinary way. **Keep
   the argument rather than the precedent**: the test for the next group of one
   is still "does the heading name more than the page under it does?", and this
   group having outgrown the question is not an answer to it. Three rules, each the section rule one
   level down: a group **is not a crumb** and has no page, so `trailBar()` is
   untouched by grouping and must stay that way; `NAV` is still **derived**, now
   through `sectionPages()`, which flattens a group's pages into the section
   holding it, so `upTo()`, the trail and `consoleJson().pages` cannot tell a
   grouped page from an ungrouped one; and **nesting stops at one level** — a
   group holds pages, never another group, enforced only by `sectionPages()` not
   recursing. The markup is an `<li>` holding a heading and a `<ul>`, INSIDE the
   section's list rather than a second list beside it: a group is three of that
   list's items said together, and a sibling list would tell a screen reader the
   section ended where the group began.

   **WHAT MAKES IT A BREADCRUMB RATHER THAN A LINK TO THE SECTION IS
   `listViewOf()`.** A drill-down link carries the list's filter and page, and the
   section crumb spends it, so back lands where the reader was. `LIST_PARAMS` is a
   WHITELIST PER SECTION and must stay one — what comes out of it goes into a URL
   this service hands to a browser, which is the rule `backTo()` already follows.

   **THREE PLACES DROP IT IF NOBODY CARRIES IT, and they are already handled.**
   A drill-down's own controls carry the whole query (`pageParamsOf()`), so they
   are free. `perPageForm()` is a GET form — it posts its own fields and nothing
   else — so the filter is spelt out as hidden inputs, and its PAGE deliberately
   is not: `per` is what that form changes. And every form on the applications and
   authorization-server drill-downs carries one opaque `back` field, which the
   POST handler REBUILDS through `listViewFromBack()` rather than echoing. **A new
   form on either of those pages needs `carryBack` in it**, or an edit made
   through it silently costs the reader their place in the list.

   **A NEW DRILL-DOWN NEEDS `up` AND NOTHING CAN CHECK THAT IT HAS ONE**, the same
   gap rule 7 describes: no code here can see a page appear. The four are
   `?user=`, `?group=`, `?application=` and `?profile=`, and every branch of those
   views sets it — the not-found branches included, since a page saying "no such
   group" is the page a reader most needs a way off. A parameter that merely
   FILTERS a list is not a drill-down and must not pass `up`: the section crumb
   would then point at the page the reader is already on.


---

## `/admin/token-lifetimes` IS FOUR CONFIG ROWS ON A PAGE, AND THAT NEEDED AN ARGUMENT

The access token, ID Token and refresh token lifetimes and the clock skew
applied when one is read back. Every one of them is a `config.js` row, so
`/admin/config` already had a form for all four and `POST /admin-api/config/set`
already had the operation — which is exactly the situation `/admin/scim`'s
header cites when it says it has no form, because "a second form here would be a
second door to one setting".

**The rule that header applies is the ONE-STORE rule, and it is untouched here:
there is no store.** This page holds nothing and decides nothing; its form calls
`config.setOverride()`, the same function `/admin/config`'s Save calls, against
the same override map. What breaks the one-store rule is a second PLACE THE
VALUE LIVES. Two forms over one function are two doors, which this service has
deliberately elsewhere — four of them onto one group membership (rule 8a).

**What is different from SCIM's case is the reader's task**, and that is the
test for a third page of this shape:

* These four are a QUANTITY somebody sets to a specific number to watch
  something happen, repeatedly, within one session — *make it a minute so I can
  see my client refresh*. `/admin/config` is a table of every setting this
  service has with a text box each; finding four of them in it, every time, is
  the cost this page removes. Nothing about SCIM's thirteen settings is used
  that way.
* They INTERACT, and a page can say so where a flat table cannot.
  `tokenLifetimeWarnings()` reports the two combinations that are legal and
  surprising: an access token that outlives the refresh token (a grant that can
  never usefully be renewed) and a skew at least as long as the access token's
  own life (an access token that is never refused anywhere, introspection
  included). **Neither is refused** — this service exists to be made to
  misbehave on purpose — and both are states a real deployment reaches.
* The question the page answers, *why is my client being refused*, is usually
  answered "the token expired", so the count of what already has belongs beside
  the numbers that decided it.

**A page that started keeping its own copy of a value would be the thing both
rules exist to prevent.** That, and not the number of forms, is what to check a
fourth page of this kind against.

**EXPIRY IS REPORTED ON EVERY SCREEN THAT REPORTS TOKEN STATE, AND ONE OF THEM
WAS COUNTING IT AND NOT SHOWING IT.** `/admin/tokens` and the user drill-down's
token tables always had a state column from `stats.tokenStateOf()`. What did not
was `/admin/users`, whose row carried `tokens.expired` — computed in
`userRows()` since it was written — behind a table that printed only *Tokens*,
*Valid* and *Revoked*. So a person reading "12 issued, 1 valid" had to guess
what the other eleven were, and the difference is NOT expired: a revoked token,
one not yet valid and one with no expiry stated all sit in it, so the
subtraction is silently wrong. It is a column now, and the drill-down gained the
matching tile beside *tokens still valid* for the same reason.

**All of them count against the same clock the endpoints use**, because
`tokenStateOf()` applies `oauth2.clockSkewS` — see `oauth-oidc/CLAUDE.md`. A
console that called a token expired while `/oauth2/introspect` reported it
active would send somebody to debug the wrong half, and this page is where they
come to find out why a client was refused. `artifactStateOf()` deliberately does
NOT take that allowance: nothing here reads a SAML assertion or a Kerberos
ticket back, so there is no endpoint for it to agree with, and an OAuth setting
stretching a ticket's lifetime on a page would be inventing a tolerance the KDC
never applied.

Two more things about it worth keeping if any of it is reworked. **The bounds on
the inputs come off the settings** — `min`, `max` and `step` from
`config.describe()`, rendered into the `number` inputs — so the browser's
refusal and the server's are the same three numbers rather than two lists that
can drift; the server still checks, because an input attribute constrains a
person and not a JSON body. And **`number` was added to the shell's
`input[type=text],…` selector** when this page arrived: its four inputs were the
console's first, and without it they were the one control in the card drawn in
the browser's default chrome.

---

## ONE PAGE OF THIS CONSOLE IS NOT IN THIS DIRECTORY

`/admin/sts-metadata` — *Service metadata*, the last item in the sidebar — is
built by `../sts_metadata.js`. It moved under `/admin` on 2026-08-24 from
`/sts-metadata`, and the split of labour is worth knowing before either half is
edited:

* **That module builds the body; `page()` supplies everything around it.** It
  calls `respond()`, exported from `admin.js` for exactly this one caller, so
  the page gets the sidebar, the trail, the gate banner and the `?format=json`
  half without a second implementation of any of them.
* **Its classes are in `page()`'s style block**, marked as that page's —
  `.lead`, `.m`, `.why`, `.eff`, `.bad`, `.none`, `.protos`, `a.btn`. They are
  there because `page()` emits the console's ONLY `<style>`, and a second one
  inside `<body>` is markup no validator accepts.
* **The require goes one way and must stay that way.** `sts_metadata.js`
  requires this module; this module must never require it back. That file is
  the LAST thing `server.js` loads — it lists what every other module
  registered — so a require from here would drag every console route behind it,
  and rule 6's route order is what `/admin/sts-metadata` is built by walking.
* **It is gated by construction**, not by a check of its own: the
  `app.use('/admin', ...)` below is above every route registered after it, and
  that file's route is registered last of all.

## The layout: two columns, one card, and no script

`page()` draws `.shell` holding `.side` (the sidebar) and `.main` (the card). It
is flex rather than grid because what is wanted at a narrow width is "the sidebar
stops being a column and becomes a block above the page", which `flex-wrap` does
for nothing — and this console runs NO SCRIPT, so a layout needing one was never
an option. Two rules in that CSS are load-bearing rather than cosmetic:
`min-width:0` on `.main`, without which one long DN widens the whole page instead
of scrolling inside its cell; and the sidebar's fixed `flex-basis`, without which
a long label widens the column and squeezes every table. `page()` now closes FOUR
divs rather than two — `.meta`, `.card`, `.main`, `.shell` — and one missing tag
nests the next page's sidebar inside the last one's card, which looks like a CSS
bug rather than a markup one.

## Four reader slots and two writer slots point INTO this module

`server.js` requires this module BEFORE `../ldap/ldap_server.js`,
`../scim/scim.js` and `../spiffe/spiffe_server.js`, so this module cannot require
any of them: the require would pull `/ldap`, `/scim` and `/spiffe` into the
express router ahead of every `/admin` route, and `GET /admin/sts-metadata` is built by
walking that router. So this module OFFERS slots and they fill them at their own
require time — `setDirectoryReader()`, `setGroupReader()`, `setDirectoryWriter()`,
`setSpiffeReader()`, `setScimReader()`. The pattern and its entry test are rule 3e
in the root `CLAUDE.md`; do not add a sixth by analogy.

It DOES require `../spiffe/spiffe_ca.js`, `../spiffe/spiffe_id.js` and
`../spiffe/spiffe_registry.js` directly, because they register nothing, so neither
thing that forces a slot applies.

**This module renders and decides nothing.** What counts as a group, what a
username may be, where an entry goes — all of that is decided in the module that
owns the store, and reimplementing any of it here is how the console and an
`ldapmodify` come to disagree.

---

## The console, the audit log, and what a group does not grant

* **The admin console at `/admin` is protected now (see the section below) and holds
  nothing on disk.** It is
  the one surface that can change what the protocol endpoints do — it revokes tokens
  through the same set `/oauth2/revoke` writes to, and it adds custom claims to every
  future access token, ID Token and SAML assertion — the tokens on `/admin/claims`
  and the assertions on `/admin/saml-attributes` since 2026-08-24, **two pages onto
  one store**: one `CLAIM_SETS`, one `setClaimSet()`, one `claimsAction()` taking the
  set ids the door carries, and one audit row per change whichever door made it.
  Custom claims are **additive**:
  the names this service sets itself are refused at configuration time, because an
  `exp` settable from a web form would produce tokens that fail to verify with nothing
  pointing back at the page — and that list is a JWT rule, not enforced for a SAML
  attribute, because `exp` collides with nothing in an assertion. The other half of
  each set puts **LDAP attributes** in
  those four, whose values come off the person's own entry rather than out of the form
  — see rule 3d, and note that the additive rule holds there too: the protocol's own
  claim wins, then a typed one, then the attribute. It deliberately does not invalidate assertions, tickets
  or credentials (nothing consults this service about those, so the button would be a
  lie), does not end sign-on sessions (`wsignout1.0` has cleanup to fan out), and does
  not touch refresh tokens' claims. Its `/admin/users` page lists every userid
  presented to this service in an interaction that SUCCEEDED, across all twelve
  families, and drills into one's sessions and the tokens issued on each. Two rules
  hold it up and both are easy to break by accident: **one row is one local name**
  (`alice`, `urn:sts-mock:user:alice` and `alice@REALM` are one identity — the prefix
  is derived from `userFor()` rather than written down, so changing that function
  cannot silently split every user in two), and **a token is placed under a session by
  the optional third argument to `signJwt()`**, never by a claim — no token here
  carries a session identifier and adding one would change what every client receives.
  A new authentication point needs one `stats.recordAuthentication()` call at the
  moment the credential is ACCEPTED, not when the request arrives.
  **That page now has one control and it writes to the DIRECTORY rather than to
  the list it sits above** — create a person under `ou=users` before they
  authenticate, refusing a username that is already there. It goes through
  `ldap_server.js`'s `createUser()`, which `POST /admin-api/users/create` calls
  too and which an `ldapadd` gets the same refusal from; the message says the
  new entry will NOT appear in that page's own table until they authenticate,
  because "who this service has SEEN" and "what the directory HOLDS" are the two
  different questions this console keeps apart everywhere else. See README.md.
  **And the funnel being reached is still not the whole chain: `ldap.autocreateUsers`
  was `false` in all three `env/*.js` files**, which beats its default, so no
  protocol seeded a directory entry anywhere any of them was loaded — while
  `config.js`'s own description for it described a BIND behaviour that has never
  existed, the default said `false` where four documents said ON, the `bool`
  coercion turned an unrecognised spelling into `false` rather than the default,
  and `tests/api_ldap.js` SKIPPED its own check with a warning whenever it found
  the feature off. An appconfig value is the last word; a default nobody reaches
  is not a default, and a test that opts out when its subject is disabled is how
  a setting stays wrong for as long as that one did.
  **`/admin/delegation` is the newest page and it is the one that reads several
  of these stores at once** — the delegation register, the applications registry,
  the users page's identity keys and the Kerberos principal database — without
  keeping a fact of its own. See the section below it.
  Its `/admin/groups` page is the one page here that reports the DIRECTORY rather
  than what this service has issued, and the difference between the two lists is
  the thing to keep straight: the directory holds an entry for whoever somebody
  wrote one for — the three people it seeds at startup included — while
  `/admin/users` holds whoever has actually presented a credential. So a member
  row links to that page only for somebody this service has seen authenticate and
  is marked *never here* otherwise; a link drawn unconditionally would usually
  land on "nothing here has authenticated as alice", which reads as a broken link
  rather than as the answer it is. See rule 6 for the rest of it.
* **The audit log at `/admin/audit` is HISTORY where the rest of the console is
  STATE**, and it is the one page here that can answer *when* and *by whom*.
  Six categories — a credential accepted in any of the sixteen families, a
  sign-on session created or ended, every LDAP operation over 389 and 636 alike,
  every console page and form, every management API call, every other endpoint
  call — recorded at the five funnels rule 3c names. **No credential is ever in
  a row** and the page says so; **one act usually produces several rows** (a
  sign-in writes three, at three layers) and the page says that too, because a
  reader counting rows will otherwise read them as duplicates; and **it observes
  itself**, since drawing it is console access, which is stated rather than
  suppressed — a blind spot exactly where the reader stands is worse than an
  extra row. What it deliberately does not record is the CLIENT'S ADDRESS: on a
  mock reached over a compose bridge that is a fact about docker, and a column
  right on a laptop and quietly wrong everywhere else is worse than none. It
  records the CHANNEL instead (`http`, `ldap`, `ldaps`, `grpc`, `internal`).
* **A group in the directory now reaches a token, and still grants nothing.**
  `groups.claim` (ON by default) puts a claim naming somebody's group membership
  in every access token, ID Token and both SAML assertions; `groups.claimName`,
  `groups.claimValue` (`cn` or the whole DN) and `groups.claimFromMemberOf`
  shape it. It is the one feature here that reads `ou=groups` back out. Nothing
  reads the claim: no endpoint checks it and nothing decides anything on it, so
  the two sentences are kept apart everywhere they appear. It is defensible as
  ON by default only because the claim is OMITTED ENTIRELY for somebody in no
  group — see rule 3d-ii.


---

## `/admin/delegation` IS THE ONE PAGE HERE THAT IS DELIBERATELY NOT A PROTOCOL PAGE

Who acted on whose behalf, through what, to reach what — eight mechanisms across
three protocol families in ONE table. It is in **Monitoring**, beside the tokens
it points at, and the placement is the argument: a reader arriving here has a
chain in their head (*alice hit the portal, the portal called the API*) and wants
to know which hop invented which identity. Under Protocols it would have had to
be filed under one of the three families, which would mean choosing which two
thirds of the answer to hide.

**TWO TABLES FROM TWO STORES, and the split is the point of the page.** What
HAPPENED comes from `../common/delegation.js` (rule 3l). Who MAY DELEGATE TO WHOM
comes from `../kerberos/krb5_principals.js`'s `delegationPolicy()`, required
directly — a plain require in the ordinary direction, and both tests that would
force a slot pass: that module registers no route (the KDC's own are in
`krb5_kdc.js`) and `server.js` loads the Kerberos modules before this one, so
nothing here can be the reason a route moved. It is the same argument the two
SPIFFE libraries are required under. **The policy is interpreted THERE and
rendered here**, because what those two attributes mean is a statement about the
principal database — this module renders and decides nothing, as everywhere else.

Four things about it are decisions rather than defaults:

* **There is NO FORM, so rule 7 is satisfied by `GET /admin-api/delegation`
  alone** — the second read-only resource over there, and the audit log's own
  argument one step along. Everything on this page is an observation or somebody
  else's configuration. A control that let a person TYPE a chain would put
  invented rows in a table whose entire worth is that its rows are what actually
  happened, and the table would then need a column saying which were which.
* **The policy half is KERBEROS ONLY and the page says so loudly.** That is not
  a gap being papered over: Kerberos is the only family here that polices
  delegation at all, and each WS-Trust and RFC 8693 act says so in the same
  column that names an attribute for a Kerberos one. **That asymmetry is the
  most useful thing on the page** — the same picture, policed at one end and not
  at the other — so do not "tidy" the unpoliced rows into an em dash.
* **Ten columns, not twelve**, and the two that were merged were merged because
  the table became unreadable rather than merely wide. `td.who` breaks a long
  identifier anywhere (or one DN widens the page), so every extra column costs
  the ones beside it: `HTTP/frontend.example.com@EXAMPLE.COM` wrapped over five
  lines at twelve. The protocol went into the mechanism cell because every
  mechanism id already begins `krb5-`, `wstrust-` or `oauth-`; the two credential
  columns became one with arrows saying which direction. The policy table lost
  its *Also requires* column for a different reason — that sentence is a property
  of the MECHANISM, identical on every row of its kind, so it is said once above
  the table and kept per-pair in the JSON.
* **A party can be a person AND an application**, and `delegationPartyCell()`
  draws up to two links for that reason. `HTTP/frontend.example.com` has an entry
  under `ou=users` (it authenticates, so the funnel files it with the people) and
  one under `ou=applications` (tickets are issued FOR it). A cell that showed one
  of them would send half the readers to the wrong page. An application NOT in
  the registry is marked rather than hidden — the registry holds what this
  service was ASKED ABOUT, and an RFC 8693 `audience` nobody mentioned otherwise
  is exactly that.

---

## `/admin/delegation/map` IS THE FIRST DRAWING IN THIS SERVICE

The same acts as a diagram. It is a **DRILL-DOWN of `/admin/delegation`** — no
`NAV` row, `active` is the delegation page's path, `up` is `upTo('/admin/delegation', 'The picture', …)` — so the trail reads
`Admin console › Delegation › The picture` and the way back carries the filter
the reader came in with. Rule 7a's test is what decided it: a parameter that
merely FILTERS a list is not a drill-down, and this is not a filter, it is a
second VIEW of the same list. A nineteenth sidebar tab would have shown nothing
the tab above it does not already hold.

Six things about it are decisions rather than defaults.

* **THE MODEL IS IN `../common/delegation.js` AND THE DRAWING IS IN
  `delegation_map.js`, AND NEITHER KNOWS WHAT THE OTHER KNOWS.** `graph()` says
  what the nodes and edges ARE — it walks the acts rather than `chainList()`'s
  answer, because a chain has the credentials taken out of it on purpose and a
  picture asked to say what was issued needs them. `render()` says where a box
  GOES and what it looks like, and it is **handed a `resolve(node)`** rather than
  reaching for the directory itself. That split is the whole reason there are two
  files: what a party IS belongs to this console, where `directoryReader` and
  `applications` are, and it is the one question a layout engine has no business
  answering. `admin.js` is still the only place that knows both.

* **IT IS `delegationView()`'s GRAPH, NOT A SECOND CALL.** That function builds
  it beside `chainList()` and puts it in `json.graph`, so this page, the
  delegation page's `?format=json` and `GET /admin-api/delegation` are all
  describing one graph. Three calls with three ideas about which acts to pass
  would have been three answers that each looked right alone — which is the
  reason `delegationView()` exists at all.

* **THE PICTURE IS OF `filtered`, THE TABLE IS OF `shown`.** Paging a diagram
  draws the boxes that happen to be on page 2 and the lines that happen to join
  them, which is a picture of the pagination. The page says so where the count
  is printed, because the two numbers otherwise look like a bug.

* **NO SCRIPT, AND THAT IS THE ROOT `CLAUDE.md`'s SECOND CSP RULE HOLDING RATHER
  THAN BEING WAIVED.** A client-side graph library — mermaid, cytoscape, d3 —
  would have made this the fifth scripted page in the service and the first in
  the console, to draw a picture that does not move. The SVG is generated on the
  server and arrives inline as markup, so `script-src 'none'` is untouched and
  `img-src` is not even reached. What it costs is pan and zoom; the filter and
  `?format=svg` are the answers to that, and both are said on the page.

* **`?format=svg` IS THE DOCUMENT ALONE AND IT CARRIES NO LINKS.** `app.js`
  rewrites root-relative `href`s into the current realm on the way out of a
  `text/html` response ONLY — which is exactly why the inline copy's anchors work
  inside a realm with nothing threaded through them, and exactly why a link in an
  `image/svg+xml` body would be one that silently leaves the realm. In a saved
  file it would be a link to somebody else's machine. That format gets the gate's
  302 rather than a 401, which is the gate's own rule (it looks for JSON to
  decide) and is right here: the link is clicked in a browser.

* **THE DEPENDENCY WAS WEIGHED, in `delegation_map.js`'s own header, the way
  `scimmy` and `swagger-ui-dist` were.** `@dagrejs/dagre` is 1.4 MB unpacked with
  one dependency and no install script, and what it brings is the half that is
  actually hard: ranking, and ORDERING each rank so the lines cross as few times
  as possible. It brings no markup at all, which is why it is the right library
  rather than Graphviz — a stick figure is not one of Graphviz's shapes, and the
  alternative to a layout library was not *draw it by hand*, it was *invent a
  layout algorithm*.

**The one thing in the drawing that needed a judgement is the `both` shape.**
`HTTP/frontend.example.com` is a person AND an application, which is the fact
`delegationPartyCell()` draws two links for and the fact a shape-per-kind picture
has no room for. It is a rectangle with a figure inside it — the application's
shape, with the person in it — because choosing one of the two would send half
the readers to the wrong page. The picture can only put a shape inside ONE
anchor, so the party table under it draws the cell and offers both.

**And one thing in the MODEL needed a judgement, which is where a box's identity
comes from.** `nodeIdOf()` in `delegation.js` normalises the application
identifier as well as the presented one, which `chainKeyOf()` does not do and does
not need to: a party carries `key` only when something was PRESENTED, so an
S4U2Self names `HTTP/frontend@REALM` normalised as the intermediary and raw as
the target, and unnormalised the picture drew the requester and the service it
asked for a ticket to ITSELF as two boxes with a line between them. Two spellings
of one identity is two people — the rule `dnRfc4514()` and `userFor()` already
follow, one layer up. The TABLE is deliberately left alone, since it shows both
spellings in two columns where seeing them is the point.

---

## `/admin/federation` IS THE ONE PAGE HERE THAT CONFIGURES A REFUSAL

Every other page in this console either REPORTS what happened or WIDENS what this
service will accept. This one is the opposite in both directions, and the page
says so at the top rather than leaving it to be found: a relationship is created
DISABLED, an assertion is refused unless it verifies against the certificate
configured on it, and an enabled-but-half-configured relationship refuses rather
than half-working. `../federation/CLAUDE.md` argues why that inversion is
necessary rather than cautious.

Three things about it are decisions rather than defaults.

* **IT IS IN PROTOCOLS, UNGROUPED, BESIDE SCIM**, and the placement needed the
  same argument `/admin/delegation` needed. Federation spans FIVE protocol
  families, so under any of the four groups it would mean choosing which four
  fifths of the answer to hide — which is exactly what kept delegation out of
  them. It does not go where delegation went either: **that page is an
  OBSERVATION and this one is CONFIGURATION.** A section of its own was
  considered and fails this console's own test for one (the heading would name
  nothing the page under it does not).

* **THE FORM IS BUILT FROM THE SCHEMA, through `federation.fieldsForRole()` —
  the same call the action validates against.** That is what stops the page
  offering a field the action would refuse, and it matters here more than
  anywhere else in this file because the fields differ by ROLE and by PROTOCOL:
  a service-provider-side relationship has a token endpoint and an
  identity-provider-side one has a release list, and neither has the other's.
  A hand-written form would have had to encode that twice.

  **The four booleans get a two-button control rather than a text box**, and
  that is not cosmetic: a text box somebody types `TRUE` into is one somebody
  types `true`, `yes` and `1` into, and one of those is how a relationship stays
  disabled while the page says it is on. `federation.js` normalises them anyway
  — two defences, because the console is not the only door.

* **IT RENDERS AND DECIDES NOTHING**, like every other page here. Every branch
  of `federationAction()` calls `federation.js`. A validation written in this
  file would be a second opinion about what a relationship may hold, and the one
  an `ldapmodify` never saw.

**One field is never printed.** `fedClientSecret` is this service's own
credential AT the partner — a real secret at a real foreign service, which is a
stronger statement than `oauthClientSecret` can make about a secret this service
minted for a mock client. It is not shown here and never reaches the audit log,
and the page says out loud that an `ldapsearch` shows it anyway. That is not a
security boundary and must not be presented as one; it is this console not being
a second way to read somebody else's credential out of the process.

## 8. THE GATE, AND WHY THE OLD SENTENCE IS QUALIFIED RATHER THAN DELETED

`admin.authRequired` is ON by default. Every page and every form under `/admin`
needs a browser sign-on session from `../authn/authn.js` and one of two roles.
The rest of the numbered rules are unchanged by it; this is the eighth because
nothing it says was true before.

**It is ONE `app.use('/admin', ...)` in `admin.js`, above every route in that
file.** Express applies middleware only to routes added after it (rule 1), so
that placement is the whole mechanism — a console page added below the guard is
guarded and one added above it would not be. There are none above it, and there
is nowhere else in the file a route could go.

**It authenticates nothing itself.** `authn.js` owns the session and the sign-in
screen; the guard asks `sessionOf()` who is here and hands
`beginAuthentication()` the page they wanted. A login screen of this console's
own would be a second authentication service. The good consequence of sharing the
first is that signing in with a security key at `/authn/login` is visible here,
because it is the same session WS-Federation and the authorization endpoint read.

**A BROWSER IS REDIRECTED AND A PROGRAM IS REFUSED.** Every page here answers
`?format=json` and every form takes a JSON body precisely so a test can drive
this console without a browser — and a 302 to an HTML login screen is not an
answer such a caller can read; it arrives as a 200 full of markup where JSON was
expected. So `?format=json`, a JSON content-type or a JSON-only `Accept` gets 401
or 403 with a body, and everything else gets the screen. **A POST with no session
is never redirected either**: a 303 turns the method into GET by definition, so
the form's fields would be gone and "revoke everything" would come back as a page
view with the click silently discarded.

**IT GUARDS `/admin` AND NOT `/admin-api`.** Express matches a `use` path on
segment boundaries, so `/admin-api` does not match — and that is the arrangement
rather than an accident being relied on. `../mgmt-api/CLAUDE.md` carries the
argument and the honest consequence: anybody who can reach this port can grant
themselves both roles through the API. The gate exists so a client can be driven
through 302/401/403 and a role model, not to make this service safe to expose.

**THREE STATES, AND EVERY PAGE SAYS WHICH.** `gateBanner()` — off (the old
open-console warning, unchanged and still true of the port), on with an EMPTY
ROSTER (anybody who signs in holds both roles, said loudly), and on and enforced
(who you are and what you hold). They are different enough that one banner with a
detail changed would have been the wrong shape. `gateStateFor()` computes it and
the guard's decision from ONE call, because the two were written separately at
first and disagreed within the hour.

## 8a. THE ROLES ARE DIRECTORY GROUPS, AND THAT IS THE DECISION MOST LIKELY TO BE UNDONE

`cn=admin-read` and `cn=admin-write` under `ou=groups`, both renameable. NOT a
store of `admin_rbac.js`'s own, and the reason is the one-store rule this service
follows everywhere it has been tempted otherwise: a second membership store would
be a second answer to "is alice an admin" that an `ldapmodify`, a SCIM PATCH and
`/admin/groups` could not see, drifting silently because nothing compares two
stores that were never meant to disagree. So there are **four doors onto one
membership** — `/admin/rbac`, `POST /admin-api/rbac/…`, an `ldapmodify` on 389 or
636, and a SCIM PATCH — which is the point rather than a leak: a role no test can
grant is a role no test can exercise.

`ldap_server.js` fills `admin_rbac.js`'s `setDirectory()` slot at its own require
time, for the route-order reason the five slots below have (rule 3e). **That slot
takes ONE OBJECT where the five here take separate functions**, and the concern
stated there — a filler installing half of it would silently disable the other
half — is answered rather than ignored: it checks every member it needs and
refuses a partial object with an error naming what was missing.

**WRITE IMPLIES READ**, expressed as `implies` on the role table rather than as an
`if`, so a page asking "may this person read" gets the same answer wherever it
asks from. A role that could post a form to a page it could not see would be a
trap rather than a permission.

**THE EMPTY ROSTER OPENS.** While NEITHER group has a member, anybody who signs
in holds both roles. This service has no password anywhere and the roster dies
with the process, so there is no bootstrap administrator and no way to make one
out of band: a service started with the gate on and an empty roster would
otherwise have a console no browser could ever reach. `admin.openWhenEmpty` turns
it off for somebody who wants the locked case, and `/admin-api` is the way back
out of it. **"No members" and "no group at all" are deliberately the same state** —
the group is created by the first grant, and treating the empty group a revoke
leaves behind as *closed* would mean the console locking itself the moment
somebody tidied up.

**A grant to somebody who does not exist is allowed and dangles.** That is the
interesting case for a mock — grant the role, then watch them arrive already
holding it — and it is why the roster counts membership VALUES rather than
resolvable members.

## 8b. "A GROUP HERE GRANTS NOTHING" IS NOW QUALIFIED IN EIGHT PLACES

It was asserted in `README.md`, three `CLAUDE.md` files, `sts_metadata.js`,
`group_claims.js`, `ldap_server.js`, `docs/` and on `/admin/groups` itself. Every
one of them was QUALIFIED and none deleted, because the general claim is still
the one that matters: it is true of every group but these two, and true of these
two everywhere except this console. Deleting it would leave a reader believing
that adding somebody to `cn=developers` changed what their token could do.

The exact shape of the qualification is worth keeping if any of it is reworded:
these two groups grant **this console and nothing else** — no token's scopes
change, no assertion gains an attribute, no Kerberos PAC is affected, no protocol
endpoint reads them, and `groups.claim` carries `admin-write` into an access token
exactly as it carries any other group, where still nothing reads it.

## Every page here shows ONE trust realm

Since 2026-08-24 this service can run several logical copies of itself at once,
told apart by a segment at the front of the path (`common/CLAUDE.md` argues the
whole design). Four consequences for this file, and the third is the one that
would cost an afternoon:

* **THE SIDEBAR'S SECOND LINE NAMES THE REALM, and it used to name the WS-Trust
  issuer.** `wstrust.issuer` was never the name of this service — it is what ONE
  of sixteen families puts in an `<Issuer>` element — and in the corner of a
  console the other fifteen never mention it read as this service's identity.
  It is `Mock STS · <realm name>` now, which is true of the whole page and is
  the fact a reader most needs before they act, since `/admin/config` writes the
  realm it is read in. It is deliberately NOT the switcher said twice: the
  switcher appears only when a realm has been DEFINED, which is exactly the
  ordinary case where that corner was saying nothing useful. **Nothing was
  lost** — the issuer is still under the heading on every page, and it is in
  this line's tooltip so that somebody who had learnt to read it out of the
  corner finds it where they look.

* **`page()` draws a realm switcher above the nav**, on every page — but only
  when a realm has actually been defined. A permanent "default" would be a
  control that only ever says the same thing, and this console had no such
  control before realms existed.
* **The switcher's links are ABSOLUTE URLs and must stay that way.** `app.js`
  rewrites every root-relative `href`, `action` and `src` in an HTML response to
  carry the current realm's prefix, which is what makes this file's several
  hundred hand-written links work inside a realm without one of them being
  edited. That rewrite is exactly wrong for the one control whose job is to
  LEAVE the current realm, and an absolute URL is what passes through it.
* **`/admin/config` WRITES the realm it is read in.** `config.setOverride()`
  lands on the ambient realm — see rule 3m — so the Save button on this console
  changes one realm, and `/admin/token-lifetimes` and every other page that
  writes a setting does the same without knowing it. That is why the switcher
  says so on every page: a form that read one realm and wrote another is the
  surprise this arrangement exists to avoid, and the only way a reader can tell
  which realm they are in is if it is named where they are looking.
* **THE TWO ROLES ARE NOT PER REALM.** They are groups in the embedded
  directory, which is shared by every realm in the process, so somebody who
  holds Admin Write holds it everywhere. `/admin/rbac` reached under a realm
  prefix is the same roster as the one reached without. Rule 8 is unchanged and
  there is deliberately no per-realm administrator; if there is ever to be one,
  it is a per-realm container in the directory rather than a second store here.

`/admin/realms` is the page for all of it, and it keeps nothing of its own: the
registry is `common/realms.js`'s and a realm's settings go through the same
`config.setOverride()` every other page uses.

**ITS OFF-BANNER TOLD A LIE FOR TWO STATES AND NOW TELLS THE TRUTH FOR EACH.**
`realms.active()` is `realms.size > 0 && config.value('realms.enabled')`, and the
banner was drawn on `!active()` while SAYING "`realms.enabled` is false". On the
ordinary service — the flag on, no realm yet defined — that is a console
asserting something untrue about a setting the reader can go and look at, and it
sent people to `/admin/config` to turn on a thing already on. The two causes are
told apart now, and the second is a NOTE rather than a warning: "the flag is on
and nothing has been defined" is this service's normal state, not a fault. **The
lesson generalises past this page**: a predicate that is false for two reasons
must not be rendered as a message that names one of them.
