# admin-ui/

The admin console at `/admin`. Two files now:

| File | What it is |
|---|---|
| `admin.js` | Every page, every form, the shell they are drawn in, and the GATE in front of all of them. The largest file in the repository, because every page's HTML and every page's JSON view are built in the same function — deliberately, for the reason `../mgmt-api/CLAUDE.md` gives. |
| `admin_rbac.js` | **Who may use it.** Two roles, held as two ordinary groups in the embedded directory. A library (rule 3): it registers nothing. |

**It IS protected now, and it holds nothing on disk.** It is also the one surface
that can CHANGE what the protocol endpoints do, which is why it is the one that
grew a gate.

5. **`admin.js` must stay after `oauth2.js` too, for the same reason**: it reads that
   `sessions` map so the metrics page can report real sign-on sessions. And the same
   one-store rule applies to REVOCATION — the set of revoked jtis lives in
   `admin_stats.js` and serves both the console and RFC 7009's `/oauth2/revoke`. Two
   sets would each look correct alone and never see each other, and a token revoked
   from the console would keep introspecting as active with no error to point at.


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
   There are three groups, all under Protocols — **OAuth2 / OIDC** (authorization
   servers, custom claims), **Verifiable Credentials** (credential claims,
   verifier request) and **SPIFFE** (SPIFFE, registration entries, agents) —
   with SCIM left ungrouped beside them. Three rules, each the section rule one
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
  future access token, ID Token and SAML assertion. Custom claims are **additive**:
  the names this service sets itself are refused at configuration time, because an
  `exp` settable from a web form would produce tokens that fail to verify with nothing
  pointing back at the page. The same page's other half puts **LDAP attributes** in
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
