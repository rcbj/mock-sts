# admin-ui/

The admin console at `/admin`. Three files now:

| File | What it is |
|---|---|
| `admin.js` | Every page, every form, the shell they are drawn in, and the GATE in front of all of them. The largest file in the repository, because every page's HTML and every page's JSON view are built in the same function — deliberately, for the reason `../mgmt-api/CLAUDE.md` gives. |
| `admin_rbac.js` | **Who may use it.** Two roles, held as two ordinary groups in the embedded directory. A library (rule 3): it registers nothing. |
| `delegation_map.js` | **The delegation picture**, at `/admin/delegation/map` — and, since 2026-08-26, one person's whole picture at `/admin/delegation/user`, which is the same renderer over a graph carrying two more kinds of line. Layout with `@dagrejs/dagre`, every shape its own SVG. A library (rule 3): it registers nothing, requires nothing in this service but `helpers.js`, and is HANDED what each box is. |

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
   provider, SAML 1.1 identity provider, custom SAML attributes),
   **Verifiable Credentials** (credential
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

## `/admin/applications/new` IS A SECOND FORM OVER ONE FUNCTION, AND THAT NEEDED THE SAME ARGUMENT `/admin/token-lifetimes` MADE

Added 2026-08-25. It creates an application entry in the embedded directory of
the realm the console is showing, and it is the first page here whose main
control is a set of CHECKBOXES: fourteen protocol families, from
`applications.js`'s `PROTOCOLS` table, landing on the entry's
`appAllowedProtocol`.

**The Applications list already had an *Add an application* row, and it stays.**
Both post `action=create` to `/admin/applications`, both reach
`applications.createApplication()`, and there is one store behind them — so this
is the case the token-lifetimes header settles rather than a new question:
**two forms over one function are two doors; what breaks the one-store rule is
a second PLACE THE VALUE LIVES**, and there is none. Four doors onto one group
membership (rule 8a) is the same shape at twice the count.

What is different is the READER'S TASK, which is the test that header sets:

* **The families do not fit in a `.formrow`.** Fourteen choices with a sentence
  each is a table, and a table at the foot of the applications list would have
  had to become a link to somewhere anyway.
* **NOR DO THE IDENTIFIERS AND THE REDIRECT URIS**, which is the 2026-08-25
  addition and the half that makes this the only place a whole application can
  be configured in one post. Fourteen more fields — eleven identifiers and three
  return addresses — drawn from `applications.declarationAttributes()`.
* **Creating one is a different errand from reading the list.** The inline form
  sits BELOW the paging, so on a service with forty applications the one control
  somebody came for is off the bottom of the page.

**THE KIND SELECT WAS REMOVED AND THAT IS THE MOST INSTRUCTIVE THING ON THIS
PAGE.** It sat beside the family checkboxes and asked the same question in a
vocabulary that did not line up with theirs: eight kinds against fourteen
families, five of those families having no kind at all, and a reader made to
choose in both. Worse, the two are on opposite sides of the line
`applications.js`'s `EDITABLE` header draws and this file repeats everywhere — a
family is DECLARED and a kind is DERIVED, written by `seen()` when a protocol
recognises the identifier — so the select was a console form asserting a
sighting that had not happened, which is exactly what every other form here is
refused. It is also why `view()`'s `recordedProtocols` had to carry a paragraph
saying it was not evidence of traffic. **`createApplication()` still TAKES a
kind and the API still documents one**: `saml2Action()` and `saml11Action()`
pass one when *Register* creates a service provider, and that is a protocol
module's statement rather than a guess in a select. The rule to take from it:
**when two controls on one form are two vocabularies for one question, the one
that survives is the one on the DECLARED side of the line.**

**THE FIELD NAMES ARE THE SCHEMA'S OWN, PREFIXED `field.`**, and both halves of
that are deliberate. The prefix is what lets `applicationFieldsFrom()` tell an
attribute from `name` or `action` without scanning the body for schema names, so
a field added to this form tomorrow cannot collide with one. The attribute name
itself is on the label, unfriendly as it is, because it is the same name an
`ldapsearch` shows and the same name `POST /admin-api/applications/create` takes
in its `fields` object — one vocabulary across the page, the directory and the
API, so a person who learns the form can drive the API.

**A MULTI-VALUED FIELD IS A TEXTAREA SPLIT ON NEWLINES, NOT ON COMMAS.** A
redirect URI may legally contain a comma and may not contain a newline; splitting
on the wrong one cuts a URI into two that each fail an RFC 9700 exact match,
silently, and only in that mode. The protocol checkboxes one section up DO split
on commas and spaces, because a family id is a short lower-case word — the two
are different for a reason rather than by accident.

**THE FIELD LIST IS `applications.declarationAttributes()` AND NOT A LIST IN
THIS FILE.** It is one walk of the `PROTOCOLS` table, deduped by attribute, so
this page and `GET /admin-api/applications/new` cannot offer different fields and
neither can offer one `createApplication()` would refuse — the property
`editableAttributes()` already gives the two edit selects on the list page. It is
deduped rather than one field per family because three families name
`oauthClientId` and two name `samlEntityId`: two boxes writing one attribute
would be a form that silently kept whichever was filled in second.

**THE DECLARATION GRANTS NOTHING AND THE PAGE SAYS SO THREE TIMES.** Nothing in
this service reads `appAllowedProtocol`: an application declared for SAML 2.0
alone is still issued an access token at `/oauth2/token`. That is the same
sentence `APPLICATIONS_CAVEAT` already makes about the entry as a whole, and it
is repeated here because a page of checkboxes headed *protocol families it is
declared for* is the single most likely thing in this console to be read as a
permission. The argument for it not being one is `applications.js`'s: a mock
that refused a protocol would remove a test case rather than add one.

Three things about it are decisions rather than mechanics:

* **A create now lands on the entry it made.** Every other action on
  `/admin/applications` names its application in `application`, and `create`
  cannot — its field is `identifier`, because the entry does not exist yet — so
  a create went back to the top of the list. That was survivable while the form
  was ON the list; from a page of its own it left the reader with nothing to
  look at. The redirect takes the identifier off the RESULT, so it cannot point
  at an entry that was refused.
* **The checkbox column goes through `listField()`, not `parseBody()`.**
  `helpers.parseBody()` builds a plain object, so a repeated field arrives as
  whichever value came last and every other one is silently gone — the create
  would have recorded one family out of five and looked like it worked. That is
  why `applicationsAction()` takes the list as a SECOND ARGUMENT, exactly as
  `claimsAction()` does, and why `admin_api.js` computes it the same way.
* **The drill-down grew a *Protocol families* section, and it matches on KINDS.**
  It reads the declared list against what the entry has been recorded as. The
  first version matched on the protocol LABELS in `appProtocol` and was wrong in
  a way that looked right: a federation partner's sighting is written under the
  protocol its relationship speaks, so every ordinary OAuth client read as a
  federation partner. The column is called *Recorded* rather than *Seen*
  because a create can still be given a kind through the API and by the two SAML
  *Register* buttons — the Authentications tile is the figure that answers
  whether anything has actually happened.

**No new POST, and that is rule 7 read exactly.** The rule is about CONTROLS:
this page's one control posts to a handler that already has its operation
(`createApplication`), so what `/admin-api` gained is the GET —
`/admin-api/applications/new`, which answers the two closed vocabularies the
create validates against and, since the fields arrived, the `declarations` list
they are drawn from. See `../mgmt-api/CLAUDE.md`.

**ONE THING THIS PAGE FIXED THAT WAS NOT ITS OWN BUG.** `createApplication()`
had never read the `fields` member of its argument, and `saml2Action()` and
`saml11Action()` have passed `fields: { samlEntityId: identifier }` since they
were written — so *Register* on `/admin/saml2` and `/admin/saml11` produced an
entry with no `samlEntityId` on it, and the attribute only appeared later when a
real AuthnRequest arrived and `seen()` wrote it. Nothing failed, which is why it
survived: the entry existed, the page rendered, and the missing attribute looked
like an application that had not been used yet. Wiring the create form's fields
through the same member fixed it, and both buttons now write the entityID they
always claimed to.

---

## `/admin`'s OWN LIST OF THE PAGES IS DERIVED NOW, AND THE BUG IT FIXES IS THE ONE THIS REPOSITORY WARNS ABOUT EVERYWHERE ELSE

*What this console is* on the Overview page was a hand-written `<ul>` in the
index route from the day the console had four pages. On 2026-08-25 it described
SEVEN of twenty-five — every page added since had been added to `SECTIONS` (so
it appeared in the sidebar, in the trail and in `consoleJson().pages`) and to
nothing else. So the one page in this console whose entire job is to point at
the others had become the least complete description of it in the repository,
and **nothing could have shown that**: a list of links reads as correct whatever
it leaves out. It is exactly the failure `/admin/sts-metadata` exists to make
impossible for endpoints, sitting undetected two clicks away from it.

Three things about the fix are decisions rather than mechanics:

* **Every page row in `SECTIONS` carries a `blurb`, and `consoleGuide()`
  renders the list from that table.** The blurb is prose about ONE page and
  lives beside that page's `path` and `label` for the reason its label does. A
  separate `PAGE_BLURBS` map keyed by path was the obvious alternative and is
  the same bug with a lookup in front of it — two tables that each look right
  alone and are never compared.
* **A page with no `blurb` is DRAWN, marked.** Skipping it would be the
  original bug with a mechanism behind it. The marker is the only report
  anything in this service makes about an undescribed console page, and it
  warns rather than throwing, like `admin_rbac.js`'s install: a console that
  will not start is worse than one line saying what is missing. **It has been
  mutation-tested** — a blurb was removed, the marker appeared on that row and
  on no other, and the blurb was put back — because a check that has never
  fired has not been shown to check anything.
* **The GROUPS are kept, where `sectionPages()` flattens them.** Grouping is a
  fact about the sidebar everywhere else in this file; here it is not, because
  this list IS the sidebar explained, and a reader looking for *Registration
  entries* needs the same "these three are SPIFFE" that made the group worth
  having. `consoleGuide()` therefore walks `SECTIONS` itself rather than `NAV`,
  and it is the only reader of that table that does.

**The page being drawn on is dropped, and a section emptied by that drop goes
with it.** That is `trailBar()`'s last-crumb rule one level out — a link that
reloads the page you are standing on teaches a reader not to trust the ones
beside it — and it is why the `/admin` row in `SECTIONS` deliberately has no
`blurb`: a description of the Overview page, on the Overview page, would be
text nothing renders and everybody keeps editing.

**What still cannot be checked from here is the same gap rule 7 and rule 7a
both describe**: no code in this process can see that a blurb has gone STALE.
The marker catches a missing one; a blurb describing what a page did last month
is invisible, exactly as a `sts_metadata.js` coverage note is.

### *What it deliberately does not do* is about THIS CONSOLE, not about the service

The section under the list is the second half of the same edit and the
distinction is worth keeping when adding to it: the root `CLAUDE.md` carries a
table of what this SERVICE does not do, and this section is what an operator
standing in the console will look for a control for and not find. The overlap
is real and deliberate — persistence, the password nobody checks, the workload
nobody attests — but the sentence has to be about the console for the entry to
belong here. "This service checks no password" belongs in the root table; "the
gate proves that somebody typed a name that holds a role, and `/admin-api` is
not gated at all" belongs on the page, because it is the thing a person
locked out of the console needs and the thing somebody about to expose the port
must not miss.

**One entry states the opposite of its own heading and must keep doing so.**
*It DOES end a sign-on session now, and it used to say it did not* is kept in a
list of non-goals rather than deleted, for the reason 8b keeps the qualified
group sentence: the four places that said otherwise were read by people, and a
reversal that leaves no trace is a reversal a reader cannot tell from a
misremembering.

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

### The head row, and the one control that is on every page

Under `.card` the first thing is `.pagehead`: the page's `<h1>`, and a
**Refresh** link pushed to the far end of it. Three things about it are
deliberate.

**It is a LINK and it has to be.** `script-src 'none'` means there is no
`location.reload()` available anywhere in this console, and a
`<form method="get">` back to the same path would drop the query string it was
submitted with unless every parameter were re-emitted as a hidden field. An
`<a>` to the current URL is a real fetch either way, because `respond()` sends
every page `Cache-Control: no-store`.

**Its href is the REALM-RELATIVE path, not `req.originalUrl`.** `app.js`
rewrites every root-relative `href` on the way out to carry the realm being
read, so the obvious version produces `/realm/acme/realm/acme/admin/tokens` and
a 404 a long way from `refreshHref()`. That function starts from
`realmRelativePath()` — the same path with the prefix taken off — which is what
the realm switcher already sends.

**It SUBTRACTS `notice` and `error` and keeps everything else.**
`respondToAction()` puts those on the redirect after a form POST; they describe
something that has already happened, and a Refresh carrying them would
re-announce "12 tokens revoked" over a page where nothing had been revoked this
time. The filter, the page number and the search are what the reader is looking
AT and have to survive, which is why it is a subtraction rather than a bare
path.

**The issuer line that used to sit here is gone**, and the argument is under
*Every page here shows ONE trust realm* below, because it is the second half of
that same decision.

### PROSE LONGER THAN A LINE IS COLLAPSED, AND THREE FUNCTIONS DECIDE IT

Added 2026-08-26. `note()`, `warn()` and `bullet()` in `admin.js` take a
fragment of prose and hand back either the paragraph it always was or a
`<details>` whose `<summary>` is that paragraph's own opening sentence.
`tip()` beside them returns a `title` attribute. Every page here goes through
them: about 340 notes, 30 warning boxes, 20 prose bullets, the config table's
152 descriptions and the endpoint table's ~250 on `/admin/sts-metadata`.

**What it fixes was never that the prose was wrong.** The reasoning IS the
point of a mock — it is the half a person cannot read off a protocol trace, and
this file argues everywhere else that it should be written down rather than
trimmed. What it cost was the other half: on most pages here the control
somebody came for sat several screens down a wall of paragraphs, and the page
read as documentation with a form hidden in it. `/admin/config` was the extreme
case — 152 settings, a median description of 384 characters, so about forty
screens of prose with 112 inputs buried in them. The folds took the visible
text of that page down by 71% and of `/admin` by 76% WITHOUT DELETING A WORD,
which is the property to keep if any of this is reworked.

Six things about it are decisions rather than mechanics.

* **IT IS NATIVE `<details>` AND NOTHING ELSE COULD BE.** This console is
  served under `script-src 'none'`, so the debugger's collapse-all switch — a
  checkbox and a listener — has no equivalent here, and the whole change adds
  no seventh exception to the rule in `../CLAUDE.md`. What that costs is the
  *expand everything* control, which is why every summary is a full sentence:
  a reader skimming for one paragraph has to be able to find it without opening
  all of them.
* **THE SUMMARY IS DERIVED, NOT WRITTEN BESIDE THE PROSE.** A hand-written
  label over a paragraph is a second copy of that paragraph's point, and the
  two drift — the bug the section on `consoleGuide()` above describes, where
  the one page whose job is listing the others described seven of twenty-five.
  So the label is the note's own opening: the bolded headline if it has one,
  else the first sentence, else a truncation of it. A caller MAY pass a label
  and two do, both for the same reason: the text is a value out of another
  module (`config.describe()`'s `label`) rather than prose written here.
* **THE TEST IS ON THE RENDERED TEXT, NOT ON THE CALLER'S JUDGEMENT.** A caller
  deciding "this one is short enough" decides it once, against a paragraph that
  then grows. So a note added to this console tomorrow starts folding itself
  when it passes about a line, with no edit anywhere — which is the same
  property `consoleGuide()` and `sts_metadata.js` have and for the same reason.
* **A LIST ITEM THAT OPENS WITH A LINK IS NEVER FOLDED, AND ONE THAT OPENS WITH
  A CODE PATH KEEPS IT IN THE SUMMARY.** `bullet()` enforces both. The Overview
  page's index and the machine-readable lists are rows whose POINT is the link
  or the URL; folding one puts the only control in the row behind a summary
  made of text. It is also why `guideItem()` composes its row by hand — link on
  the row, `note(blurb)` under it — rather than handing the whole thing to
  `bullet()`.
* **A FOLDED WARNING KEEPS ITS BOX.** `warn()` returns
  `<details class="warn fold">`, so a page with a caveat on it still looks like
  one when the caveat is closed. Folding a warning into something that looked
  like body text would be the one place this change hid a fact rather than
  tidying one. `sts_metadata.js`'s drift report is not folded at all, and says
  in a comment why: it appears only when that page disagrees with the router,
  and a report that has to be opened is one somebody can close and forget.
* **NOTHING IS EVER SAID ONLY IN A TOOLTIP.** A `title` is unreachable from a
  keyboard, invisible on a touch screen and unread by most screen readers, so
  everything `tip()` carries is also on the page — usually in the fold directly
  under the control. `label[title]` gets a dotted underline and a help cursor
  from an ATTRIBUTE SELECTOR in `page()`, so a caller that adds a tooltip
  cannot forget to add the sign that there is one. `shortened()` set the
  precedent long before this and set it the right way round: the full value in
  the title, the truncation on the page.

**The one place the two are used oppositely is worth knowing before adding a
third.** `/admin/config` folds each setting's description and puts its short
label in the summary; `/admin/token-lifetimes` puts the same description in a
tooltip and folds nothing. The pages have different jobs — one is the whole
table of 152 settings, the other is four rows somebody sets a number in
repeatedly — and that is the test to apply, not which page came first.

**Two mechanical traps, both of which bit.** The constants the folds are
measured against are declared at the TOP of `admin.js`, not beside `note()`,
because several of this file's module-level constants are built by calling
`note()` at require time and a `const` in its temporal dead zone throws while
the module is still loading — which takes the whole service down rather than
one page. And **a summary is emitted UNESCAPED on purpose**: what goes into one
is text taken out of markup the caller already built, so escaping it again
turned `&apos;` into `&amp;apos;` and printed the entity. `tip()` is the
exception and resolves entities instead, because a `title` is text rather than
markup. The rule is in the comment above `plainTextOf()`.

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

Seven things about it are decisions rather than defaults.

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

* **IT IS TWO BANDS, AND THE ISSUER IS NOT IN THE LAYOUT AT ALL.** Until
  2026-08-26 the hexagon was one node among the others and dagre gave it a rank
  of its own, so it sat IN the flow: a person on the left, this service in the
  second column, and the applications strung out to the right of it. Two things
  were wrong with that and only one was ever going to be noticed by eye. The
  parties of one delegation came out at four different heights, because the
  issuer's own edges were competing with the chain for the ranking — a staircase
  where the thing being drawn is a line. And the hexagon, the box every single
  line touches, was in the middle of the picture rather than over it. So the
  parties are laid out by dagre ALONE and the issuer is put back above them,
  centred, with its lines drawn as straight segments by hand. What that buys is
  that a CHAIN comes out as the single horizontal line it should always have
  been — read the next bullet before believing anything stronger, because
  "every application is on one plane" is what this bullet claimed on the day it
  was written and it was only ever true of a chain — and that the dashed issuer
  lines all run the same way, so they read as one statement rather than as a
  relationship competing with the ones that matter.

  What it COST is the label placement dagre used to do for those lines, and it
  is the fiddly half of the change. Every one of them starts at the same point,
  so two labels at one fraction along are only as far apart as their boxes are —
  the first version of the band wrote `signed in` across `issued to`. They are
  given ROWS in the gap instead, a label drawn where its own line crosses its
  row: two in one row are separated horizontally by construction, two in
  different rows cannot touch, and the gap is made as deep as the number of rows
  actually needed. A picture whose lines fan out widely comes back with one row
  and a gap no deeper than it ever was. `tests/delegation_map_bands.js` guards
  all of it — the bands, the one plane, the centring, and that no two label
  panels overlap — because none of it fails loudly.

* **AND SINCE LATER THE SAME DAY THE ROW OWNS BOTH COORDINATES, so the plane is
  real rather than a property of chains.** Taking the issuer out bought half of
  it. The moment a graph BRANCHES it stops being a chain and dagre goes back to
  spreading the parties vertically, because that is what a layered layout is
  for: a person who signed in at one application and was delegated through two
  others came out as four boxes at four heights, all of them the same KIND of
  thing, with a reader hunting up and down a staircase to compare them. So the
  y is taken away from dagre as well and every party — the person included —
  goes on ONE CENTRELINE.

  **THE X HAD TO GO WITH IT, and that is the part that is not obvious.** In
  `rankdir: 'LR'` the RANK is the x, so dagre gives every node on one rank the
  SAME x and tells them apart by the y alone — the coordinate just discarded.
  Flattening the y by itself is perfect on a chain (one node per rank) and draws
  a FAN of four applications exactly on top of each other. The
  `tests/delegation_map_bands.js` fixture for that existed already and caught
  it, which is the best argument for the file. So the boxes are packed left to
  right instead, and dagre is left with the one thing it is being kept for: the
  ORDER — its ranking is the depth of the chain and its ordering pass is the
  arrangement that crosses fewest lines, so sorting by (x, then y) is that whole
  result read off as a sequence. The GAP between two boxes is then the label of
  the line that lies between them, which inverts what `ranksep` was doing:
  dagre reserved a rank for a label and hoped it fitted, and this measures it.

  **WHAT IT COSTS IS PAID IN THE LINES, and that is the trade.** Crossings do
  not disappear because the boxes lined up. A line whose ends are NEIGHBOURS on
  the row lies along it and reads as a chain; everything else — a box in
  between, a second mechanism between the same pair — arcs UNDER the row, in
  lanes assigned greedily by x-overlap, which is the same problem the issuer's
  label rows solve and the same answer. Under rather than over because over is
  where the issuer's band is. The lane DEPTHS come from the labels in them for
  the reason the rows do: the first version used a constant and the picture came
  back with one arc's label written across the arc below it. Two assertions in
  that test file guard it and both were mutation-tested — the parties of a FAN
  share one plane, AND no two of them overlap, because `spread` alone is
  satisfied by the bug.

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

## THREE MORE DRILL-DOWNS UNDER `/admin/delegation`, AND THEY ASK DIFFERENT QUESTIONS

`/admin/delegation/chain` and `/admin/delegation/application` joined the map on
2026-08-25. Both hang under the delegation page exactly as the map does — no
`NAV` row, `active` is `/admin/delegation`, `up` carries the filter the reader
came in with — and both answer `?format=json` and `?format=svg`. Neither has a
form, so neither needs an operation on `/admin-api`: rule 7 held here the way it
held for the page above them, and `applications` was added to
`delegationView()`'s JSON so that what the new chooser is built from is
reachable without a browser.

**`/admin/delegation/chain?chain=…` is ONE relationship drawn alone**, and every
row of BOTH tables on the delegation page links to it. The whole picture is the
right answer to *what does this service look like* and the wrong one to *what is
this row, exactly*: on a service driven for an afternoon it is forty boxes.

* **It is `delegation.graph()` over a subset and nothing more.** That function
  takes the acts it is to draw, so this route hands it one chain's and the
  shapes, the labels and the tables are the map's own — through
  `delegationLooks()`, `delegationDrawing()`, `delegationTokenRow()` and
  `sendDelegationSvg()`, which were extracted from the map route the day this
  page was written because there were suddenly three callers. A second drawing
  routine for one chain would have been a second answer to what a box is CALLED,
  and a reader comparing the two pages could not have told that from two boxes
  that really are different parties.
* **The URL carries the `chainKey` and not an index.** An index into a capped
  list moves when the cap bites, so a link somebody put in a ticket would come
  back describing a DIFFERENT relationship rather than nothing — the one failure
  mode a stale link must not have. The key is long; that is the price.
* **A chain with no acts held is not a 404**, which is `/admin/logout`'s lookup
  rule and matters more here: the store drops the oldest, so an old link coming
  back empty is ORDINARY. The page says which of the two happened.
* **The acts table on it has no `chain` link**, because every row on it belongs
  to the chain being drawn. `delegationRow()` takes `chainLink: false` for that
  one caller.

**`/admin/delegation/application?application=…` is the other question:** not
*what talks to what* but WHAT HAS BEEN ISSUED BECAUSE OF THIS APPLICATION —
which is what somebody wants before turning a middle tier off, or when a resource
server is seeing tokens it did not expect.

* **REGARDLESS OF ROLE, and that is the page.** A middle tier is the
  INTERMEDIARY of the chains it acts on and the TARGET of the ones that reach it.
  Offering only the targets — the easy half — would hide what was issued THROUGH
  it, which is the interesting half of a delegation, so the credentials table
  carries a ROLE column rather than being filtered by one. `rolesBySeq` is keyed
  on the act's sequence number, which is monotonic and never reused, so a role
  cannot end up beside the wrong credential.
* **The choice is from THIS SERVICE'S OWN LIST and not from a free text box,
  which is where it departs from `/admin/logout`.** That page takes an identity
  and any name a person can type is a legitimate thing to ask about. Here the
  question means something only for an application some act NAMED, so the
  console offers what it has rather than inviting somebody to guess a spelling
  and be told nothing matched. The chooser is drawn in three places by one
  function — the delegation page, the bare application page, and again under a
  selected one so that comparing two is one click — and the same list IS drawn
  as links, below, where it is content rather than a control.
* **IT WAS A `<select>` UNTIL 2026-08-26 AND IT IS A SEARCH NOW**
  (`chooserPane()`, which the person chooser shares). A select holding every
  entry is fine at thirty and is what a register looks like after an afternoon;
  it is not what one looks like after a week, and the two things a reader
  actually does with a long list — type the first few letters, or read the
  handful that match — are the two a native select does worst. Four decisions,
  and the first is the one that decides the rest:
  * **There is no script and there must not be one.** `script-src 'none'` holds
    over the whole service (`../common/app.js`) and the parent suite asserts it
    against this console's live headers (`tests/admin_api.js`), so there is no
    keystroke handler, no fetch and no debounce to build a type-ahead out of —
    and anything written as though there were would be a control that silently
    does nothing rather than one that half works. What a browser gives free is a
    GET form submitted by the Enter key: type, press Enter, and the page comes
    back around the matches. A round trip per attempt instead of per keystroke,
    and the reader types again until the list is what they wanted.
  * **A result is a link and the link IS the selection.** The select needed its
    button because a `<select>` chooses nothing until a form is submitted. A
    list of matches does not, so clicking a row is choosing that application —
    one click where there were two.
  * **Twenty at a time, in a pane that scrolls.** The complaint the select
    answered was screen real estate, and a wall of matching links would be that
    complaint with the browser's scrolling taken away: the pane has a fixed
    `max-height` and a scrollbar of its own, so the control is the same size
    showing one match or twenty. The line under it says how many matched and
    offers the next twenty — a list that silently stops at twenty is one that
    has told the reader the twenty-first does not exist.
  * **Every SPELLING is searched and the newest is shown.** An application
    arrives as `HTTP/backend@EXAMPLE.COM` and as `HTTP/backend`, a person under
    three forms, and each pane draws one of them. A reader searching for a name
    they pasted out of the acts table four inches up the page is pasting the
    other one about half the time, and a search that answers *nothing matches*
    to a string printed on the same page is worse than no search.

  The two searches are independent (`appq`/`appfrom` and `userq`/`userfrom`),
  each rides in the OTHER's form and in the acts table's filter form
  (`chooserCarry()`) so that no control on the page clears a control the reader
  is still using, and all four are in `LIST_PARAMS` so a drill-down comes back
  to the page they were on rather than to an unsearched one. **A stale offset is
  clamped rather than obeyed**: `?appfrom=40` narrowed to six matches would
  otherwise draw an empty pane under a line saying six matched, which reads as
  the search being broken by the term that worked.
* **The chooser follows the filter and the page it opens does not**, which the
  page says out loud. `applicationList()` is called on `filtered` for the reason
  `chainList()` is; the page then shows everything that application has ever been
  part of, because *what exists because of this thing* is not a question a
  half-answer is useful for.
* **What an application IS lives in `../common/delegation.js`**, not here — it is
  keyed on the IDENTIFIER rather than on a box in the picture, and that file
  argues why. This one only draws it.

**`/admin/delegation/user?user=…` is the FOURTH, it arrived on 2026-08-26, and it
is THE ONLY PICTURE IN THIS CONSOLE DRAWN FROM MORE THAN THE DELEGATION
REGISTER.** That sentence is the whole of why it needed a page rather than a
parameter, and it is the first thing to check any change to it against.

* **Most of what happens in somebody's name is not a delegation.** An
  authorization code grant is not an act; nor is an AS-REQ, nor a SAML
  assertion. So *what has this service done in alice's name* — the question
  somebody actually arrives with — cannot be answered by narrowing these acts:
  narrowed to a person who merely signed in and holds twenty tokens, the picture
  is EMPTY. It is a union of the delegation register and the issued one, and
  **the union is in `../common/user_graph.js`** (rule 3p), not here, for the
  reason every other view function is down there: what counts as one credential
  seen twice is a statement about the stores.
* **It is the same renderer, the same shapes and the same tables.** `graphFor()`
  hands back `delegation.graph()`'s shape with three fields added, so
  `delegationLooks()`, `delegationDrawing()`, `sendDelegationSvg()` and
  `delegationMapKey()` serve it unchanged — a fourth caller of the four
  functions the chain page extracted. What this page adds is `userNodeRow()` and
  `userEdgeRow()`, and they exist because ACTS AND CREDENTIALS ARE DIFFERENT
  UNITS: a box that received four tokens and took part in no delegation would be
  a row of zeroes under the map's columns, with the interesting number nowhere
  on it.
* **TWO NEW KINDS OF LINE, in `delegation_map.js`** — `signed-in` (dotted, into
  the hexagon, one per protocol family) and `issued-for` (solid indigo, labelled
  with the exact grant). Neither takes a MODE colour, deliberately: amber and
  green are this console's judgement about impersonation versus delegation and an
  ordinary grant makes neither claim. **`delegationMapKey()` takes
  `{ issuance: true }`** to add their rows and the other three picture pages
  do not pass it — a legend must describe the diagram BESIDE it, and a key
  listing a line the page never draws teaches a reader to stop trusting it.
* **AND A THIRD SOLID INDIGO LINE, WHICH IS `reaches` AND NOT A THIRD
  RELATION.** What a credential is ADDRESSED to is a relationship this service
  granted — an access token issued to a web front end and carrying `aud:
  https://apigw1.example.com` says the front end may reach the API gateway in
  that person's name — and until 2026-08-26 it was drawn only where a token
  EXCHANGE had produced it, so the first hop of every chain was missing from
  this page. `user_graph.js` emits it with the delegation half's own `relation`
  and the grant on the label (rule 3p), which is why nothing in this file
  changed for it beyond the key's third row and the sentence above the picture.
  Two things about it belong here rather than there. The tooltip names the
  AUDIENCE the token carries whenever the box is not called that — the box is
  the application that registered the audience, so without it nothing on the
  page connects `apigw1` to the URL — and `edgeTitle()` no longer prints
  `0 act(s): 0 issued, 0 refused` under a line that carries credentials and no
  acts, which read as a delegation that was tried and came to nothing. That
  second one was already wrong on the grey `issued to` line and nobody had said
  so.
* **`issued-for` runs from the person where somebody else holds the credential
  and FROM THE HEXAGON where nobody does.** `client_credentials` is the case
  that settled it: the token is about the client itself, so the subject and the
  holder are one box, there is no person-to-application line to label, and the
  grey `issued to` line alone left the picture of a client credentials grant
  silent about which grant it was — on the page whose whole ask is that the
  grant be named. An X509-SVID with no audience is the same shape.
* **A `client_credentials` subject is drawn as an APPLICATION**, and only where
  neither store has an opinion. `delegationNodeLook()`'s fallback is the shape
  the ROLE implies and the subject of this page is an initial identity, so a
  client came out as a stick figure; the route corrects the FALLBACK in its own
  look pass and leaves the directory's and the registry's answers alone.
* **The chooser's list includes people nothing was ever issued to**, which is
  the half worth keeping: an S4U2Self subject who has never been near this
  service is exactly the row worth opening. Everything else about it follows the
  application chooser's rules — the same `chooserPane()` search, drawn in three
  places by one function, a bare page that is the chooser rather than a 404 —
  with ONE departure argued at the function: **the RESULT'S LINK carries the
  NORMALISED KEY and not a spelling**, because a person has no identifier of
  their own and every other link in this console files them under that key. The
  search still reads every spelling, which is the half that makes the departure
  survivable: `alice@STS.MOCK` is a form this very page prints and is not the
  key it would link to.
* **`/admin/users?user=…` links to it and the link says which question the other
  page answers.** That page is the LEDGER — every token with its state and its
  revoke button, grouped by session — and this is the RELATIONSHIPS. Neither is
  the other's summary, and **this page changes nothing**: it has no form, so no
  operation on `/admin-api`, exactly as the three drill-downs beside it satisfy
  rule 7.

---

## `/admin/tokens/credential?id=…` IS THE TOKENS PAGE'S FIRST DRILL-DOWN, AND IT IS THE DELEGATION PICTURE ASKED BACKWARDS

Added 2026-08-26. Every identifier in the tokens table's last column is now a
link to it, and it draws ONE credential: who held it, in whose name, to reach
what — and, when it came out of a token exchange, the credential handed in to get
it, and the one behind that, back to the issuance the whole line rests on.

* **THE MODEL IS `../common/credential_graph.js` AND THE DRAWING IS EVERYBODY
  ELSE'S** (rule 3l, the division `/admin/delegation/map` already lives on). That
  file returns a graph in `delegation.graph()`'s shape, so `delegation_map.js`
  draws it, the party table is `delegationNodeRow()` and the line table is
  `userEdgeRow()` — the one written for `/admin/delegation/user`, which already
  knows the two relations an ISSUANCE uses. **This route draws nothing of its
  own**, which is what keeps a party on this page the same party, drawn the same
  way, as on the five pages that had it first.
* **IT HANGS UNDER `/admin/tokens`, WHICH MEANT GIVING THAT PAGE A `LIST_PARAMS`
  ROW.** No `NAV` entry, `active` is `/admin/tokens`, `up` is
  `upTo('/admin/tokens', 'One credential', …)` — the arrangement the three
  delegation drill-downs have. The list row (`family`, `kind`, `state`, `per`,
  `page`) is new: without it the way back landed on page 1 of an unfiltered list
  of everything this service has ever issued, rather than on the row the reader
  clicked.
* **THE COMMON ANSWER IS "NOTHING IS BEHIND IT", AND THAT IS NOT AN EMPTY
  PAGE.** Most credentials were issued directly: one generation, three boxes and
  the grant that produced them. The page leads with which of the two states it
  is in, because a picture of a chain and a picture of a single issuance look
  alike at a glance and mean opposite things.
* **A ROW WITH NO IDENTIFIER HAS NO LINK, and the cell already had to say so.**
  A Kerberos ticket carries no `jti` and no `ID` — the protocol has none — so
  there is nothing to look a lineage up BY, and offering a link that could only
  answer "nothing is known" would be worse than the dash that is there. The
  signed UserInfo response and the WS-Trust JWT are the same case for a different
  reason, and the tooltip names it.
* **A CREDENTIAL THIS SERVICE NO LONGER HOLDS IS NOT A 404.** Both registers
  behind the page are capped and drop the oldest, and they are capped
  SEPARATELY — so a lineage can know an identifier existed, because an act names
  it, and nothing else about it. The page says which of those two states each
  generation is in rather than leaving a blank row to be read as a bug.
* **No form, so no operation on `/admin-api`** — rule 7, satisfied exactly as the
  drill-downs above satisfy it. `?format=json` is the lineage and the graph;
  `?format=svg` is the document alone.

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
screen; the guard asks `consoleSession()` who is here and hands
`beginAuthentication()` the page they wanted. A login screen of this console's
own would be a second authentication service. The good consequence of sharing the
first is that signing in with a security key at `/authn/login` is visible here,
because it is the same session WS-Federation and the authorization endpoint read.

**`consoleSession()` AND NOT `sessionOf()`, AND THIS GUARD IS ITS ONLY CALLER.**
The ordinary reader answers out of the ambient realm's partition, which is right
for `/oauth2/authorize` and was wrong here: the realm chooser on every page of
this console is a link to the same page in another realm, and each click landed
on the sign-in screen — then overwrote the browser's only session cookie, so
clicking back landed there too. The argument for why the console may ask a
question no other module here may is in `../authn/CLAUDE.md`, beside the
function.

**WHAT IT ASKS IS "DOES THE DEFAULT REALM HOLD THIS SESSION", NOT "DOES ANY
REALM"**, and this paragraph said the second until 2026-08-25. The embedded
directory became a subtree per realm on that date, so the two roles this guard
decides from are groups in the DEFAULT realm's `ou=groups` and nowhere else —
`ldap_server.js` pins the whole RBAC directory there. If an `acme` session still
opened this console, anybody who can create a realm could grant themselves both
roles inside it and walk back out into the default realm. So an unauthenticated
reader of ANY realm's console is sent to the DEFAULT realm's sign-in screen:
`sendToConsoleSignIn()` runs both `beginAuthentication()` and the redirect inside
`realms.run(DEFAULT_REALM, …)`, which is what stops `app.js` prefixing the
Location and what puts the pending transaction in the store the default realm's
screen will look in. `returnTo` is deliberately NOT run that way — it is
`req.originalUrl`, which `app.js` leaves alone precisely so it still carries the
realm, so signing in once returns the reader to the realm page they asked for.

The banner names the realm holding the session when it is not the realm being
read — which is now every page under a realm prefix — because the protocol
endpoints in this realm still see none.

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
  ordinary case where that corner was saying nothing useful.

  **AND ON 2026-08-25 THE ISSUER CAME OFF THE SHELL ENTIRELY**, which is the
  same argument read once more rather than a reversal of it. It had moved from
  the corner into the line under the heading — `Mock STS admin console — issuer
  <code>…</code>`, drawn on every page of the console — where it was still a
  name that ONE of sixteen protocol families uses, sitting at the top of the
  seventy-odd pages the other fifteen never mention it on. **Nothing is lost**,
  and it is worth knowing where each half of it went before putting it back:
  it is on `/admin/sts-metadata`, the one page whose subject is what this
  service IS; it is on `/admin/config` under WS-Trust, which is where it is
  SET; and it is in this line's tooltip, so that somebody who had learnt to
  read it off the shell finds it where they look. What is at the top of every
  page instead is the Refresh control — see *The head row* above.

* **`navBar()` draws a realm chooser as the FIRST thing inside the nav card**,
  on every page — but only when a realm has actually been defined. A permanent
  "default" would be a control that only ever says the same thing, and this
  console had no such control before realms existed. It was its own card above
  the nav until 2026-08-25, and that was one surface too many in a column whose
  whole job is to be one list: a reader looking for where they are should find
  it at the top of the thing they are already reading. It carries a label and a
  `<select>` and nothing else — the prose that used to sit under it said what
  `/admin/realms` says at length.
* **It is a FORM, and it must stay one, because this console runs no script.**
  `script-src 'none'` (common/app.js) is what makes the whole js/reflected-xss
  family moot here rather than merely unlikely. A `<select>` that navigated on
  change would need an inline handler the browser refuses to run, so the control
  would silently do nothing — which is why it is a `<select>` and a button, the
  same shape every filter on this console already uses.
* **Its action, and the redirect the route it submits to makes, are ABSOLUTE
  URLs and must stay that way.** `app.js` rewrites every root-relative `href`,
  `action` and `src` in an HTML response to carry the current realm's prefix —
  and wraps `res.location()` to do the same to a root-relative redirect target.
  Both are what make this file's several hundred hand-written links work inside
  a realm without one of them being edited, and both are exactly wrong for the
  one control whose job is to LEAVE the current realm. An absolute URL names a
  host, so it passes through both untouched.
* **AN ABSOLUTE URL THIS CONSOLE PRINTS FOR SOMEBODY TO COPY IS BUILT WITH
  `baseUrlOf(req)`, ALWAYS**, and that helper is the only thing that knows all
  three of the parts: the scheme (`global.https`, and forwarded headers when
  `global.trustProxy` is on), the host, and the ambient realm's prefix. The
  rewrite in the bullets above does NOT cover this case — it touches
  root-relative `href`/`action`/`src` in an HTML body, so an absolute URL, and
  anything at all in a JSON reply, is on its own.

  **`/admin/federation`'s detail page got this wrong until 2026-08-26**, and it
  is worth reading because of WHICH URLs they were: the assertion consumer
  service and the federation metadata address — the two strings whose entire
  purpose is to be copied into somebody else's identity service. It built its
  base as `'http://' + req.get('host')`, the one expression in this file not
  going through the helper, and so was wrong three ways at once. No realm
  prefix, so the URL named a path that 404s while the AuthnRequest this service
  actually sends carried the right one (`federation_sp.js` does use
  `baseUrlOf()`) — the page and the wire disagreed, and the page is the half a
  person acts on. Always `http://`, on a service that binds TLS whenever
  `global.https` is set, which every launcher in the parent project's suite
  does. And no forwarded headers, so a deployment behind a proxy was handed its
  own internal address. **None of the three is visible from this service**: each
  fails at the far end, days later, as a partner that will not federate.
  `tests/federation_sso.js` in the parent suite now compares the address this
  page advertises against the one the flow actually uses, which is the only
  check that can see it at all.

  The one thing NOT to do while fixing such a case is to prefix a
  root-relative link before rendering: `app.js`'s rewrite has no idempotence
  guard, so a pre-prefixed `href` comes out as
  `/realm/acme/realm/acme/…`. That page therefore keeps its sign-in link
  root-relative for the HTML and passes it through `realms.href()` — which does
  have the guard — for the JSON, and says so where the two are built.
* **`GET /admin/realm-switch` BUILDS its target and never echoes one.** `to`
  arrives in a query string and ends up in a `Location` header, which is the
  shape of every open redirect there has ever been. It is accepted only as a
  single-slash-rooted path with no whitespace — `//host` and `https://host` are
  refused rather than corrected — and the realm id is looked up in the registry
  rather than trusted, with `/admin` as the answer to both refusals. It is not
  in `NAV`, so it is not one of the console's pages and `tests/admin_api.js`'s
  page parity does not ask for a `/admin-api` operation mirroring it.
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
* **AND NEITHER IS THE CONSOLE'S SIGN-ON, which follows from the line above.**
  The guard resolves the one session cookie in the DEFAULT realm — that is
  `consoleSession()`, and the name it had while it accepted any realm's session
  was `sessionAnywhere()`. Switching realm therefore switches rather than asking
  somebody to sign in again, and a session minted inside `acme` opens nothing:
  the gate has to agree with the roster, which is the default realm's
  `ou=groups`, or creating a realm would be a way to grant yourself both roles.
  Only this console reads a session across a realm boundary at all — in the
  realm switched to, `/oauth2/authorize`, `/wsfed` and the two SAML profiles see
  none, and the banner says so.

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
