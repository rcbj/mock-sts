# admin-ui/

The admin console at `/admin`. Four files now:

| File | What it is |
|---|---|
| `admin.js` | Every page, every form, the shell they are drawn in, and the GATE in front of all of them. The largest file in the repository, because every page's HTML and every page's JSON view are built in the same function — deliberately, for the reason `../mgmt-api/CLAUDE.md` gives. |
| `admin_rbac.js` | **Who may use it.** Two roles, held as two ordinary groups in the embedded directory. A library (rule 3): it registers nothing. |
| `delegation_map.js` | **The delegation picture**, at `/admin/delegation/map` — and, since 2026-08-26, one person's whole picture at `/admin/delegation/user`, which is the same renderer over a graph carrying two more kinds of line. Layout with `@dagrejs/dagre`, every shape its own SVG. A library (rule 3): it registers nothing, requires nothing in this service but `helpers.js`, and is HANDED what each box is. |
| `pki_admin.js` | **The certificate authority**, at `/admin/pki` — Root, Intermediate and Issuing per trust realm, the signing key pairs it issues to applications and (since 2026-09-11) to PEOPLE, and since 2026-09-10 **the Certificate & Key Configuration pane**: the parent project's *PKI / X.509* workflow as one form of a hundred and fifteen fields, over `common/pki_authoring.js`. It draws its own page (like `crypto_metadata.js`) and is required at **18a**, which is why it needs no slot. |
| `crypto_metadata.js` | **The crypto report**, at `/admin/crypto-metadata` — what this service does when it signs, verifies, encrypts or decrypts, for every identity service it advertises. It draws its own page (like `../sts_metadata.js`, not like everything else here) and fills `setCryptoReporter()` so `/admin-api/crypto` can mirror it. See the section below. |
| `federation_diagram.js` | **The federation picture**, at `/admin/federation/map`. The SECOND drawing in this console and a SEPARATE renderer — see the section below, where the case for not reusing the one above it is made. A library on the same terms, and the only thing it takes from this service beyond `helpers.js` is `delegation_map.js`'s palette, hexagon and text metric. |

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
   Under Protocols the groups are **OAuth2 / OIDC** (authorization
   servers, token lifetimes, custom claims), **SAML** (SAML 2.0 identity
   provider, SAML 1.1 identity provider, custom SAML attributes),
   **Verifiable Credentials** (credential
   claims, verifier request), **SPIFFE** (SPIFFE, registration entries,
   agents), **XACML**, and — since 2026-09-13 — **Kerberos** (Kerberos
   settings, principals; the settings page was renamed from `Kerberos` so the
   heading does not say its label twice) — with SCIM left ungrouped beside
   them. **SAML USED TO BE THE
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

## THE ACTIONS LEFT THIS DIRECTORY ON 2026-09-12

Thirty-one of them, with the tables they dispatch on and the pure helpers they
share — about 3,100 lines with their comments — to
`admin-core/admin_actions.js`. `admin.js` went from 36,197 lines to 33,125.

**They were not moved because they were wrong.** Not one of them had ever
touched `req`, `res` or markup; each took a parsed body and an actor and
returned a result object. They were a shared logic layer already, and this
directory was simply the wrong address for it — `mgmt-api/admin_api.js`
required this module to reach them, which made the surface a machine drives
downstream of the surface a person reads.

**WHAT STAYED IS TRANSPORT, AND THE LINE IS WORTH KNOWING.**
`respondToAction()` turns a result into a 303 back to the page or into JSON;
`respondToApplicationAction()` does the same and reaches for this console's
paging; `listField()` reads `req` for the repeated-checkbox parse that
`helpers.parseBody()` cannot answer. All three belong to the surface that has
a page. **`listField()` staying is the fact the whole move rested on**:
`applicationsAction(body, protocols)` takes those parsed values as a parameter
because the route parses them and hands them down — a boundary somebody drew
long before there was anywhere to move to.

**AND THEN THE INTERLEAVED ONES WERE SPLIT, FAMILY BY FAMILY.** Every page that
computed a dozen facts, drew markup from them and assembled a json at the
bottom now takes the facts from `admin-core/admin_views.js` in one call and
renders them — its markup untouched, its json handed back as `view.json`. The
page a person reads and the resource a machine fetches are one computation.
`mfaView()` left entirely: the page it belonged to had split into
`/admin/totp` and `/admin/webauthn` and its columns had moved onto
`/admin/users`, so nothing here drew from it any more.

**THE PURE VIEWS WENT FIRST, AND THE LINE THERE WAS A MEASUREMENT.** Of the
eighty-nine view-shaped functions here, forty-six return a json half and **only
three separate at a clean boundary** — the rest build row markup part-way
through the computation. So what moved to `admin-core/admin_views.js` is the
thirty-eight that were already pure: they answer a question and reach no markup
at all. The forty-three that render stayed, because `{ json, inner }` computed
in one pass is the strongest form of rule 7 there is and splitting it is
bespoke work on interleaved code.

**AND SO DID THIS CONSOLE'S OWN STRUCTURE, WHICH IS PURE AND STILL BELONGS
HERE**: `consoleJson()` (which pages exist, out of `NAV`), `configJson()` and
`settingsGroupsFor()` (where a settings group is edited, out of
`SETTING_HOMES`), `protocolSettingsJsonFor()` and `configSettingsJson()`. A
caller asking what pages this console has is asking the console about itself.
Purity was not the test; ownership was. `configSettingsJson` is handed to the
read layer, because `scimJson()` embeds this console's settings block and the
alternative was for the page and `/admin-api/scim` to build it separately.

**THEY ARE ALIASED BACK RATHER THAN REWRITTEN AT EVERY CALL SITE**, in one
block under the requires. This file calls those names several hundred times —
from the routes, from the views that draw the buttons an action dispatches on,
and from each other — so rewriting each into `adminActions.x` would have made
the move a diff nobody could read, in which a behaviour change and a rename
look identical. **They are deliberately not RE-EXPORTED**: aliasing keeps this
file's own call sites working, and re-exporting would publish a second way to
reach the same function.

**`api_explorer.js` REQUIRES THE READ LAYER DIRECTLY**, and that is the one
console page that does. It asks `gateStateFor()` which roles the reader holds,
so the token it mints carries those scopes and no others — and that function
moved. It called `admin.gateStateFor()` for a while after it stopped existing:
the module loaded fine and threw a `TypeError` when somebody opened the page.

The seven inverted hooks that the actions need — `setLogoutReader()`,
`setDirectoryWriter()`, `setGroupWriter()`, the three signals reporters and
`setXacmlPages()` — **stay here**, and forward what they were handed from
inside the setter the filler already calls. Every filler in the tree names this
module, and so does every rule 3e sentence in the root file; moving the slots
would have meant editing four fillers to say something no more useful.
`admin-core/CLAUDE.md` argues the rest.


## `/admin/database`: EVERYTHING POSTGRESQL WILL SAY, AND THE SCHEMA IN IT (2026-09-11)

Filed under **Monitoring** and not beside `/admin/persistence`, on this file's
own rule that a page goes where the QUESTION it answers goes. That page is
under Settings and answers *what is this service configured to write down,
where, and is the connection encrypted* — configuration, plus the eighteen
`persistence.*` settings, and it reads the same on a service that started a
second ago. This one answers *what has that database been DOING*, and the
numbers move while a reader watches. Same argument as `/admin/xacml/monitor`,
`/admin/scim/monitor` and `/admin/encryption`, made a fourth time rather than
cited.

**THE PAGE HOLDS NO SQL, NO COLUMN NAMES AND NO CONNECTION**, and each of those
is a separation rather than a coincidence — `persistence/CLAUDE.md` argues the
first and the third. The second is this file's: **the columns drawn are the
keys the server handed back, in its order**, so the shape of the page is
decided by the database it is pointed at. That is what lets "pull everything
available" stay true across a major version, and it is why the renderer has a
`cell()` function that has to handle a value it has never heard of — a `null`
that is not a zero, a `bigint` that arrives as a string because it does not fit
in a double, a `Date`, and PostgreSQL's own `<insufficient privilege>` string,
which is the one value on the page that would otherwise be mistaken for
somebody's query.

**FOUR NUMBERS ARE COMPUTED HERE AND NOT READ**, and they are the four a reader
would otherwise do in their head and get wrong: cache hit, rollback share,
dead-tuple share, and indexes nothing has ever scanned. PostgreSQL keeps
counters and not ratios on purpose — a counter can be subtracted between two
readings and a ratio cannot — so the page computes them and says, once and
prominently, that every one of them is cumulative since `stats_reset`. A cache
hit ratio over the life of a server tells you nothing about the last hour, and
a reader taking it for a current figure is the one misunderstanding this page
can actually cause.

**A PRIMARY KEY WITH NO SCANS IS NEVER CALLED AN UNUSED INDEX.** It is an
ordinary state, and flagging it would make the one actionable number on the
page noise.

**AND ONE BLOCK IS AN ASSERTION RATHER THAN A MEASUREMENT**: the schema drift
check, which compares the objects the driver DECLARES against the ones the
server actually has. Nothing else in this service makes it —
`tests/postgres_schema.js` compares the driver against `postgres/schema.sql`
character for character, and neither of those is ever compared against a
RUNNING SERVER, so a database built by an older copy of that file satisfies
both and is missing a table. The reverse is deliberately not reported: a table
in that schema the driver never heard of is an operator's business, and a page
calling it an error would be this service claiming a namespace it does not own.



## `/admin/secrets`: WHERE THE PRIMORDIAL SECRETS COME FROM (2026-09-12)

Filed under **Monitoring**, and it is the page this file's filing rule was
hardest to apply to, because **three** pages touch the subject and each answers
a different question:

| Page | Section | The question |
|---|---|---|
| `/admin/config` | Server configuration | What is this service SET UP to read, and from where? The `keys.*` rows. |
| `/admin/encryption` | Monitoring | What is SEALED, and with what? The key-encryption key is one paragraph in it, because there the key is a fact about the sealing rather than the subject. |
| `/admin/secrets` | Monitoring | What is at the other end of that paragraph, and is it working? |

**AND THE THIRD QUESTION IS THE ONE NOTHING COULD ANSWER.** Everything on this
page can be broken while every settings row is right: the file may not be
there, the store may be sealed, the client certificate may have expired, the
policy may have been widened, the secret may have been rotated to a version
nothing here can read. `/admin/config` reads identically in all of those cases
and so does `/admin/encryption`.

**THERE ARE TWO SECRETS AND THERE IS NO THIRD**: the key-encryption key, and
the database password. Both are READ from outside — this service generates
neither and writes neither down — so they are the one part of its configuration
whose correctness depends on a system nobody here controls.

### The page holds no probe, no SDK and no credential

`common/secrets.js` owns the providers, the client and the login; this page
asks it for `storeReport()` and draws what comes back. That is
`/admin/database`'s separation, and it is load-bearing here for a second reason
beyond the first: **the login a probe makes must be the same login a startup
read makes**, or the page is right about something nobody is running. It is one
function (`vaultConnect()`), extracted from the read path on the day this page
was written and shared by both.

### What is drawn, per provider

* **`file`** — the path, whether it is there, its mode, owner and mtime, its
  symlink target where it has one (a Kubernetes Secret mount is a symlink into
  a `..data` directory that is REPLACED on rotation, so the target is how an
  operator sees that a rotation landed), and whether it holds a JSON object —
  **the member NAMES and never the values**.
* **`vault`** — the whole state the store will publish: seal status and seal
  TYPE, initialised or not, the version and build, the cluster and its leader,
  the health summary with **the store's clock against this process's**, the
  certificate this service presents and when it expires, the token the login
  produced, the engines the identity can see, and **what that identity may
  ACTUALLY do, asked of the store rather than quoted from a policy file**.
* **`aws`, `gcp`, `azure`** — the metadata each publishes about the secret:
  rotation and the KMS key, version states, staging labels, replication.
  Through `DescribeSecret`, `getSecretVersion` and
  `listPropertiesOfSecretVersions` — never through the call that returns the
  value.

### Three refusals, and each is the page

* **NO SECRET VALUE, and the guard is asserted twice.** Every probe names the
  fields it returns, and `secrets.js` then deletes a deny-list of member names
  from whatever came out. That duplication is deliberate: this is the one page
  in this console where being wrong is unrecoverable — a key-encryption key
  drawn once is a key that has to be rotated, and rotating it means everything
  sealed under it is gone. **The guard has fired in anger once already**: the
  `mounts` probe answered `{}` against a store with four engines mounted,
  because it had named its members `secret` and `auth` and both are on the
  list. The rule that came out of it is that a probe names its OWN members and
  never echoes a provider's.
* **NO CONTROL.** No reveal, no rotate, no test-read. A reveal is the end of
  the key. A rotate is a deployment act and this service has no re-sealing
  pass, which is why `openbao/seed.js` writes the key once and refuses to
  replace it. And a test-read would be this console causing the one thing the
  whole design avoids — the key in this process's memory because somebody
  opened a page.
* **NO PROBE READS A SECRET.** Every one is metadata: a stat, a `sys`
  endpoint, a KV version history, a describe. Opening a page must not change
  what this process is holding.

### A failed probe is a row, and here half of them are supposed to fail

`/admin/database`'s rule, and it matters more here. The identity this service
holds in a secret store is deliberately bound to two read paths and nothing
else, so **a 403 against anything else is the policy working** — and a page
that hid the refusal would be hiding the evidence for the claim
`openbao/read-only.hcl` makes. The page says that at the top, in amber, rather
than leaving a reader to conclude that the store is broken.

**THE BOUND IS A TIMER, WHERE `/admin/database`'s DELIBERATELY IS NOT ONE.**
There it had to be PostgreSQL's own `statement_timeout`, because abandoning the
promise left a statement running and a connection pinned out of a pool every
protocol endpoint writes through. Nothing here is pooled and there is no
equivalent to ask for: an abandoned HTTPS request to somebody else's store
closes its own socket. `keys.storeProbeTimeoutMs` bounds ONE probe, and they
run in parallel — measured against a store that was down: **100ms for all nine,
not nine times the bound.**

### Two things the report does once that it would naturally do twice

Both were measured against a real OpenBao rather than reasoned about:

* **ONE LOGIN PER RENDER.** Each of the eight Vault probes made its own
  certificate login at first — eight round trips and eight service tokens
  minted in the store, each with an hour to live, every time somebody opened
  the page. A `session` object is threaded through every probe and memoizes
  the connection.
* **ONE PROBE PER LOCATION, NOT PER SECRET.** The commonest configuration
  there is — the compose stack — keeps both secrets at `secret/data/sts`, and
  the version history of that path is one answer, not two. **The scope is the
  PROVIDER's to declare** (`PROBES.<id>.scope()`), because the report cannot
  know what a probe's answer depends on: the file provider's is per MEMBER and
  every other is per stored object, and a key guessed centrally would silently
  either ask twice or answer the wrong question once.

`tests/secret_store_report.js` holds everything about this page that needs no
store, and `common/CLAUDE.md` argues the module underneath it.

## EVERY SETTING IS DRAWN ON THE PAGE FOR THE PROTOCOL IT CONFIGURES (2026-08-27)

Until this date `/admin/config` drew all 154 of `config.js`'s settings and
every protocol page that cared about its own showed them as READINGS with a
link to that page. `/admin/saml2`, `/admin/saml11` and `/admin/scim` each said
so in its own words, and the three sets of words had already begun to disagree.

Now each of `config.js`'s 22 GROUPS is drawn on the console page for the family
it configures, `/admin/config` keeps the one group that belongs to no protocol
(`Global`) and becomes the INDEX of where the rest are, and eight pages were
created for the families that had settings and no page at all.

### The table is the whole of it

`SETTING_HOMES` in `admin.js` — one row per group, naming the page or pages
that draw it. Four properties, and each is why it is a table rather than a
placement made in twenty-one route handlers:

* **A group is the unit, and a page never names a key.** `group` is already
  what `config.js` declares, what `config.groups()` buckets by, and what
  somebody means by "the Kerberos settings". A page that wanted half a group
  would be asking for the group to be SPLIT in `config.js`, where the reasoning
  for what belongs with what lives.
* **A row may name two pages, and exactly one does.** `saml.issuer` is the
  Issuer of every assertion this service builds — SAML 2.0's, SAML 1.1's and
  WS-Federation's, out of the same two builders — so there is no one page it
  belongs to. It is drawn on both SAML pages and `configFormsFor()` says so on
  each, because a value that silently appeared somewhere else would be the
  worst version of this. The WS-Federation page LINKS to it instead: three
  forms onto one setting is where "shown where it is relevant" stops being
  useful.
* **`/admin/config` is not special in the code.** It is a row in that table
  like the other twenty-one, so moving `Global` somewhere else one day is an
  edit to the table and to nothing else.
* **Drift is checked at startup.** `checkSettingHomes()` runs at require time
  and reports a group with no page, a group with two rows, a row naming a group
  `config.js` does not declare, and a row naming a path that is not in
  `SECTIONS`. It logs, and `/admin/config` prints what it found — the same
  spirit as `/admin/sts-metadata` naming a route nobody described. A setting
  that is READ by the service and appears on no page is worse than one that is
  missing, because nothing about the service's behaviour tells you it is there.

### Why this is not a second store, and why that question is the only one

Every form these pages draw is `configSection()`, which posts `set-many` to
`POST /admin/config` — the same action function, the same validation, the same
override map — with a hidden `from` naming the page to return to.
`configReturnTo()` checks that value against `SETTING_HOMES` rather than merely
escaping it, because it ends up in a `Location` header; an unrecognised `from`
is not an error, it is `/admin/config`.

So the rule `/admin/token-lifetimes` argued when it was the FIRST page to take
config rows onto a page of its own is the rule this follows twenty-one times: a
second DOOR onto one value is fine, a second PLACE THE VALUE LIVES is not.
What changed on 2026-08-27 is that the door moved to where the reader already
is. **`/admin/token-lifetimes` still earns its place, and the test for it has
narrowed rather than gone**: it is not "these are settings on a page", which is
now every page, but that those four are a QUANTITY somebody types repeatedly
inside one session, that they INTERACT in two ways a flat table cannot report,
and that the count of what has already expired belongs beside the numbers that
decided it. Its own section above is unchanged and is still the argument.

### THE RESET BUTTON WAS A NESTED `<form>`, AND SAVE PERFORMED A RESET

Found while moving the block onto twenty-one pages, and it had been wrong on
`/admin/config` since that page was written.

Each overridden row drew its own `<form>` for Reset, INSIDE the section's form,
with a comment saying it had to be its own form because a second submit button
would post the whole section. **No browser ever created that form.** The HTML
parser drops a `<form>` start tag inside another form: the element is never
created and its children are adopted by the OUTER form. So the row's
`action=reset` and `key` hidden inputs became fields of the section's form,
`parseBody()` keeps the LAST value of a repeated name — and the section's Save
button therefore performed a RESET of the last overridden key instead of
saving. The page reloaded with a cheerful message about the thing it had just
done instead of the thing it was asked to do.

**It is a `formaction` now**, which needs no script: the button submits the same
form to `/admin/config?reset=<key>`, and the key rides in the URL where it
cannot be confused with a field. Two details are load-bearing:

* **The hidden `action=set-many` stays and the buttons carry no `name`.** A form
  with two NAMED submit buttons and no hidden action submits the FIRST button's
  name and value when somebody presses Enter in a text box — which would be a
  Reset. As written, Enter posts to the form's own action and saves.
* **`form-action` is deliberately absent from this service's CSP**
  (`common/app.js` says why, and it is about the authorization response's
  redirect chain rather than about this). So nothing was relaxed to allow it.

**The lesson is the method rather than the markup**: this was found by dumping
the PARSED DOM (`google-chrome --headless --dump-dom`) and counting the forms,
not by reading the markup, which looked correct and had a comment explaining why
it was correct. Every other page in this console was checked the same way and
none nests a form.

### What `/admin/config` is now

The `Global` form, and the index: every group, its size, how many of its
settings are restart-only, how many carry a runtime override right now, and the
page that draws it. Two things deliberately did NOT move:

* **`Reset all`**, because it clears every override in the SERVICE and not only
  the ones under it. A button that reached that far from the Kerberos page
  would be the one control in this console whose blast radius was invisible
  from where it was pressed.
* **`?format=json`**, which still answers the whole table. `GET
  /admin-api/config` is the API's configuration resource and a caller asking it
  for the configuration should not have to visit twenty-one pages to assemble
  one. It gained `homes` (where each group is drawn) and `homeProblems` (what
  `checkSettingHomes()` found, normally empty). **The page narrowed; the
  resource did not.**

### The eight new pages, and why they are a table and a loop

`PROTOCOL_SETTINGS_PAGES` — OAuth 2.0 / OIDC, OpenID4VCI, OpenID4VP, Kerberos,
LDAP / LDAPS, WS-Trust, WS-Federation, TLS / mutual TLS. Every one of them is
the same page: a paragraph or two saying what the family is, its caveats, the
links to the surfaces it already has, and `configFormsFor()`. The differences
are PROSE, so the prose is a table and the handler is written once — eight
copies of one four-line body is eight chances for the copy nobody edited to be
the one a reader believes.

Three things about them:

* **Registration is still at the top level.** The loop runs while the module is
  being required, so the routes are registered in order, below the gate, and
  visible to `sts_metadata.js` reading the router. Rule 1 is held, not bent.
* **A row carries what its family does NOT do.** These are the pages somebody
  lands on while deciding whether this service can stand in for a real one, and
  "it speaks the protocol" without "it checks nothing" is the misleading half
  of a true sentence. Kerberos's page says the verification is real and the
  account policy is not; LDAP's says no bind is ever refused and that no
  setting is missing; TLS's says a verified client certificate is not a login.
* **There is deliberately NO ENDPOINT LIST on them.** Every one of these
  families answers on paths this file would have to keep in step by hand, and
  `/admin/sts-metadata` already derives exactly that list from the running
  router. A table here would be the drift that page exists to catch, on a page
  nothing can check. **REVERSED 2026-09-13, AND THE ARGUMENT IS WHAT SHAPED
  THE REVERSAL**: rcbj asked for every Protocols page to list its realm's
  concrete endpoints, as `/admin/gnap` did. So the list is not in this file
  and not hand-kept: see *Every Protocols page lists its realm's endpoints*
  at the foot, where the table names ROUTES, the names and methods come from
  `sts_metadata.js` and the router, and a test fails on both drifts.

**Where the two grouped families' pages went in the sidebar** is argued in
`SECTIONS` beside the rows: the OAuth 2.0 / OIDC settings page is FIRST in its
group, because the other four are about one aspect each and this one is the
family's own configuration; the two Verifiable Credentials pages are
interleaved — OpenID4VCI, Credential claims, OpenID4VP, Verifier request — so
each protocol sits beside the page saying what goes through it. The five
ungrouped ones sit beside SCIM and Federation, because a group of one is a
heading that says the label twice.

### Rule 7 costs eight GETs and no POST

Each new page gets `GET /admin-api/<name>` — built from a table in
`admin_api.js` for the same reason the pages are — and **no POST beside it**.
That is the rule read exactly rather than a gap: every form on those pages
posts `set-many` to `/admin/config`, which `POST /admin-api/config/set-many`
already mirrors, so a POST per page would be eight more doors onto one
function. It is the same answer `/admin-api/scim` and
`/admin-api/applications/new` give.

Two operation names are not the obvious ones and the reason is a collision:
`/admin-api/oid4vci-settings` and `/admin-api/oid4vp-settings`, because
`/admin-api/credential-claims` and `/admin-api/verifier-request` already mirror
the other two pages of those families and the bare names would have read as
theirs.

**What no code here can check is still the same gap rule 7 names.** Nothing in
this service can see a form appear on a page, so the parity is asserted from
outside by this repository's own `tests/vendored/admin_api.js` — and that test's page
list comes back in `GET /admin-api/status`, which now names eight more.

### What this cost on the pages that already existed

Twelve pages gained a settings block and three lost prose that had been
explaining where their settings were instead:

* `/admin/saml2` and `/admin/saml11` lost their *What every assertion this
  profile issues is governed by* readings tables, and with them
  `SAML2_SETTINGS`, `SAML11_SETTINGS` and the two row builders — two
  hand-maintained lists of keys that `SETTING_HOMES` makes redundant. Their
  `settings` member in JSON changed shape from a flat key-to-value map to the
  described block every page now answers with, which is the shape that can say
  where a value CAME FROM.
* `/admin/rbac` lost its four-row *How the gate is set* table, whose
  descriptions and `config.js`'s own had already begun to differ. The two
  sentences that were only ever in that table — a renamed role group moves
  nobody, and `/admin-api` is gated by a TOKEN rather than by any of the four
  — are a note under
  the form now, because they are about this console rather than about the
  settings.
* `/admin/scim` stopped saying it has no controls. The argument that sentence
  made is intact and is the one above; what changed is which page draws the
  door.

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

## `/admin/applications/new` SHOWS A FIELD ONLY WHEN ITS PROTOCOL IS TICKED, AND IT DOES IT IN CSS

2026-08-27, and it is the tenth candidate for a script on a console page and the
tenth refusal.

That form offers a field for every protocol family this service has. Somebody
registering an OAuth client was reading past a SAML entityID, a Kerberos service
principal name and twenty per-application settings to reach the two boxes they
came for. So a field is drawn only when the family it belongs to is ticked.

**THE OBVIOUS IMPLEMENTATION IS A CHANGE LISTENER AND THIS IS NOT ONE.** It is
`:has()`: the checkboxes are already in the same `<form>` as the fields and
already carry `id="proto-<family>"`, so one selector per family does the whole
thing and `script-src 'none'` is untouched. The rules live in `page()`'s
stylesheet — the console's ONLY `<style>`, for the reason the service metadata
page's classes live there — and are GENERATED from `applications.PROTOCOLS`, so
a family added to that table gets its rule for nothing and cannot get a checkbox
without one.

**THE FALLBACK IS TO SHOW EVERYTHING**, which is why the rules sit inside
`@supports selector(:has(*))`. A browser without `:has()` gets exactly the form
that existed before this, and **the page says so on itself** rather than leaving
somebody to wonder why nothing hides. That direction is the safe one and the
reason is worth stating: no control a person needs is ever missing, and nothing
they type is ever dropped, because the SERVER reads what was posted and has no
idea what was visible. A rule that hid a field the server then ignored would be
the dangerous version of this feature.

**`display:revert`, not `display:block`.** These rules apply to `<tr>` as well
as to `<div>`, and `block` on a table row makes a block box that no longer lines
up with the header above it.

**A SECTION CARRIES THE UNION OF ITS ROWS' FAMILIES.** Without that, a table
whose every row was hidden left a heading and a bare header row behind, which
reads as data having gone missing rather than as nothing applying.

**IT WAS VERIFIED IN A BROWSER AND COULD NOT HAVE BEEN VERIFIED ANY OTHER WAY.**
The markup is identical whether the rules work or not — the whole mechanism is a
selector — so it was driven over CDP with headless Chrome. The first probe
reported every field visible and was WRONG: `getComputedStyle(el).display` on a
child of a `display:none` ancestor is still the child's own value.
`el.checkVisibility()` is the call that answers the question actually being
asked, and it is the one to use for the next page like this.

**HIDING IS NOT REFUSING, AND SINCE 2026-09-02 ONE FIELD ON THIS FORM IS BOTH.**
Everything above is presentation: the server reads what was posted and has no
idea what was visible, which is exactly why the fallback can safely be to show
everything. `oauthTokenExchangeRefreshToken` is the first attribute this
registry REFUSES on an entry of the wrong family — it decides what the token
endpoint does for one `client_id`, so on an application declared for neither
OAuth 2.0 nor OpenID Connect it would sit there reading like a policy in force
rather than lying inert like every other override. Three consequences worth
keeping apart:

* The CSS above still does the hiding, unchanged, and is still only
  presentation. A browser with no `:has()` shows the field, somebody fills it
  in without ticking the family, and the SERVER answers with a sentence naming
  what to tick. That is the right failure and it is why the refusal could not
  have been left to the stylesheet.
* **`editableOptions()` on `/admin/applications` takes the ENTRY now**, and
  filters the Set and Add selects through `applications.familyRefusal()`. That
  is the rule that function has always existed for — a form cannot offer a
  field the action would refuse — extended to the second thing that can make an
  action refuse. The REMOVE select is deliberately not filtered: the family rule
  refuses a set and an add and never a remove, so filtering it would shut the
  one door that could take off a value an `ldapmodify` had put there.
* **The bool control grew an enum sibling rather than a branch of its own.**
  `samlOverrideFieldRow()` draws a `<select>` for a bool because an unticked
  checkbox posts nothing and "leave it alone" has to be expressible; an enum is
  the same control with more options, read off the setting row's `enumValues`.
  A text box would have been the wrong answer for a value that is parsed back
  through `config.parseAs()`, where a typo is a warning in the log and the
  service-wide value silently in force.

---

## `/admin/saml-assertions` IS THE THIRD PAGE OF THAT SHAPE, AND IT WAS CHECKED AGAINST THE TEST ABOVE RATHER THAN CITING IT

Added 2026-08-27, under Protocols > SAML. Three `config.js` rows: the two
assertion lifetimes — `saml2.assertionLifetimeMin` and
`saml11.assertionLifetimeMin`, which already existed and are still drawn on
`/admin/saml2` and `/admin/saml11` — and `saml.clockSkewS`, which is new.

**It passes the three-part test above**, and the specific answers matter because
"it is like Token lifetimes" is exactly the argument the section above says is
not one:

* They are a QUANTITY somebody types repeatedly inside one session — *make it a
  minute and see whether that service provider checks `NotOnOrAfter` at all*.
* They INTERACT, and `samlAssertionWarnings()` reports both directions. A skew
  at least as long as a lifetime is an assertion valid for more than three times
  what its lifetime claims, which silently removes the test somebody set a short
  lifetime to run. **And a skew of ZERO is also reported**, which is the one
  warning here with no equivalent on the token page: it is the default, it is
  what this service always did, and it is the cause of the single most
  misdiagnosed failure in this protocol family — an assertion refused as
  not-yet-valid by a relying party whose clock is behind, which reads from both
  ends as a signature or trust-store problem.
* **The reason peculiar to this page**, and the one that is not borrowed: the
  two lifetimes are SEPARATE SETTINGS on SEPARATE PAGES, because SAML 2.0 and
  SAML 1.1 are separate implementations here. This is the only place both are
  visible at once, which is what makes "are these two the same?" a question a
  reader can answer by looking.

**There is no store**, and the four doors onto these three values are this page,
`/admin/saml2`, `/admin/saml11` and `/admin/config` — all of them calling
`config.setOverride()` against one override map.

**WHY THE SKEW IS ONE SETTING WHERE THE LIFETIMES ARE TWO.** A lifetime is a
property of how a profile is consumed, and this repository argues in
`common/config.js` why the two must be settable apart. A skew is a property of
the CLOCKS IN THE ESTATE this service issues into, which a deployment decides
once. It is applied inside the two builders rather than at their callers, so
WS-Trust and WS-Federation get it without either module knowing it exists —
the same choke-point argument `recordAssertion()` makes two lines away in
`saml/saml2.js`.

**IT BECAME THE DEFAULTS PAGE ON 2026-08-27, AND THAT IS WHY IT HOLDS ELEVEN
ROWS RATHER THAN THREE.** The five settings each SAML profile had on its
identity provider page — the assertion lifetime, the two signature switches, the
NameID format and the artifact lifetime — are now PER APPLICATION, and this page
is where the default every application inherits is set. They left
`/admin/saml2` and `/admin/saml11` because those pages configure this service as
an identity provider, and a value an application can overrule is not that: it is
what this service does for an application nobody has configured.

**THE MOVE WAS A GROUP MOVE, WHICH IS THE WHOLE OF WHY IT WAS CHEAP.** The ten
rows changed `group` in `config.js` — to `SAML 2.0 assertions` and `SAML 1.1
assertions` — and gained two rows in `SETTING_HOMES` naming this page. Nothing
else was needed to take them off the two identity provider pages, because a
group is drawn where its row says and nowhere else. **No KEY and no environment
variable changed**, so every appconfig file and every `STS_SAML*` variable
works exactly as it did. That property is what makes a settings move safe here,
and it is the first thing to check for the next one.

**THE PAGE NAMES THE ATTRIBUTE THAT OVERRIDES EACH ROW**, in a column of its
own, read from `applications.overridableSettings()`. That is the one thing a
reader needs that neither the setting nor the application page can tell them on
its own: the default is here and the exception is typed there, and without the
attribute name the connection is a paragraph somebody has to find.

**AND IT IS NOT `oauth2.clockSkewS`, WHICH IS THE THING TO CHECK BEFORE
"SIMPLIFYING" THE TWO INTO ONE.** That one is a TOLERANCE applied wherever this
service READS a document back — including an inbound federation partner's SAML
assertion, where `federation/federation_sp.js` argues that a reading tolerance
is decided once and reuses it deliberately. `saml.clockSkewS` is what this
service WRITES into a document it issues. One is about somebody else's clock;
the other is about how much of somebody else's clock this service pays for in
advance. A deployment wanting a strict reading and a forgiving issuance has to
be able to say so, and with one setting it could not.

**THE SKEW IS ALSO THE ONE ROW ON THIS PAGE WITH NO PER-APPLICATION FORM**, and
the two facts are the same fact. A lifetime, a signature and a NameID format are
things two service providers in one estate legitimately disagree about. How far
out the CLOCKS are is a property of the estate, and a per-application answer to
it would be a question nobody could answer differently for two applications
without meaning something else.

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

## `/admin/users/new` REPLACED A BUTTON THAT INVENTED A WHOLE PERSON

Added 2026-09-06. What was there before is the point of it: `/admin/users`
carried one text box and a Create button, and pressing it put somebody in the
directory with a full name, a family name, a given name, a display name, an
email address, a date of birth, a street, a locality, a region, a postal code
and a nationality — **every one of them invented**, none of them asked for.

That was a defensible design while a directory entry's only job was to give an
issued credential something to assert: `vc_claims.js` invents a consistent
person per username, so the entry and the credential agreed and nobody had to
type twenty-five fields to get a usable test subject. It stopped being enough
for two reasons, and only the first is about typing.

* **An operator who knows a person's actual email address or employee number
  had no way to say so at creation.** The entry appeared carrying fictions and
  had to be corrected afterwards, one `ldapmodify` at a time, from outside this
  console.
* **A person created here had no way IN.** `common/credentials.js` has been able
  to set a password and issue a single-use activation link since it was written,
  and NEITHER WAS REACHABLE FROM ANY SCREEN — `usersAction()` even had the
  `issue-activation` arm, with nothing in this console pressing it. That was a
  gap rather than a decision.

**THE LIST PAGE'S BUTTON IS NOW A GET FORM**, which is what makes it a link with
a text box in front of it: it writes nothing, and the typed name arrives as
`?user=` on the page that does. `POST /admin/users` is unchanged and still
creates — it is what `POST /admin-api/users/create` mirrors, and what a test
drives.

**IT IS NOT A SECOND STORE**, which is `/admin/applications/new`'s argument
below applied unchanged: the form reaches `usersAction()`, which reaches
`ldap_server.js`'s `createUser()`, which is also where an `ldapadd` under
`ou=users`, a SCIM create and the management API are answered. Two forms over
one function are two doors; what would break the one-store rule is a second
place the value lives, and there is none.

### Four things about it that are decisions rather than details

**AN EMPTY BOX RECORDS NO VALUE, AND MAKING THAT TRUE TOOK TWO CHANGES RATHER
THAN ONE.** `../ldap/CLAUDE.md` carries the trap in full: a person is invented
in `applyVcAttributes()` AND in `namePlan()`, and switching off only the first
leaves the page promising one thing while five invented facts land on every
entry — invisibly, because the create succeeds. The page sends `invent=no`;
`createUser()` drops both. **The page also says out loud that this is not a
promise the entry stays empty**, because the Populate sweep on `/admin/vc`
fills every missing selected attribute on every person and does not know which
were typed.

**THE INVENTED PERSON IS A BUTTON, AND IT IS COMPUTED ON THE SERVER.** *Fill
with example data* writes what this service WOULD have made up into the boxes
left EMPTY and touches nothing already typed — `applyVcAttributes()`'s
absent-only rule, applied to a form. It is the SAME persona, seeded from the
username, which is the whole value of it: an operator sees what accepting the
invention would have got them and edits it, rather than choosing between a
fiction and an empty form. A generator of its own here would have produced a
plausible person matching nothing, and the difference would have shown up in an
`ldapsearch` weeks later.

It is a round trip because this console is `script-src 'none'`, and the
refusals recorded under *Six pages here have a script on them* are what settle
that: "a field could be filled in without a reload" is not the argument that
rule asks for. It is the same answer the XACML guided editor gives to the same
question.

**IT IS DEVELOPMENT-MODE ONLY, AND IT IS REFUSED AS WELL AS UNDRAWN.** Inventing
somebody's date of birth and address is a development convenience; on a service
running as a product it would put fictions into a directory somebody else reads
as fact, with nothing on the entry afterwards to say which values were made up.
A POST that arrives anyway is answered rather than obeyed — **a control that is
only hidden is not a control that is off.**

**A CREATE ANSWERS WITH A PAGE, WHERE EVERY OTHER CONTROL ON THIS CONSOLE
ANSWERS WITH A 303.** Two reasons, and the first is not negotiable: a generated
password and an activation link EXIST ONCE, because what is stored is a scrypt
hash. `respondToAction()` puts its message in a query parameter and slices it to
500 characters — so the value would be in the browser's history, in the referrer
of anything clicked next, in every proxy log on the way, and possibly cut in
half. It is in the BODY of a response this console already marks `no-store`
instead. The second reason is ordinary and still worth having: a refusal comes
back with all twenty-five boxes still filled in, and a redirect loses them.

**The result page NAMES the two attributes that hold a verifier rather than
printing them.** `userPassword` and `stsActivationToken` carry a hash rather
than a value, so printing them leaks nothing — but on a page whose subject is
what somebody just typed, beside the one-time value itself, a second opaque
string is noise a reader has to work out. `/admin/ldap/directory` still shows
both in full, because what THAT page is for is exactly what the store holds.

### Two forms post `action=create` and only one carries it as a button

Worth knowing before editing that form. `action=create` is a HIDDEN FIELD and
Create is an unnamed submit; *Fill* carries `fill=yes` of its own and the
handler reads that FIRST. Two buttons both named `action` looks tidier and
breaks two things: `form.elements.action` is then a `RadioNodeList` whose
`.value` is empty, so anything finding a form by the action it posts — which is
how `tests/vendored/sts_admin_console.js` finds every form it presses — stops
finding this one; and a hidden field plus a named button posts `action` TWICE,
which is the ambiguity `common/validation.js` refuses everywhere else rather
than resolving.

### What it cost outside this file

Rule 7 and the endpoint-drift rule, both paid in the same change: `GET
/admin-api/users/new` publishes the attribute catalogue (`../mgmt-api/CLAUDE.md`
argues why that GET earns its place beyond the parity), `POST
/admin-api/users/create` grew `attributes`, `invent` and `credential`, and the
users action resource now names TWO console paths in its `mirrors` — the list
page and this one — because both reach one action switch and the console suite
reads that field to tell a control that posts somewhere from a control that
reaches nothing.

**AND IT CLOSED A DOCUMENTED ENDPOINT THAT HAD NEVER EXISTED.**
`common/credentials.js` names `POST /admin-api/users/set-password` twice — in
the sentence a refused sign-in gets and in the product-mode bootstrap banner
that tells an operator to change the generated password — and no such operation
had ever been written. Somebody following either instruction got a 404 naming
an endpoint this service documents. It is `usersAction()`'s third arm now.

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
is real and deliberate — the password nobody checks, the workload nobody
attests — but the sentence has to be about the console for the entry to
belong here.

**PERSISTENCE USED TO BE ON THAT LIST OF OVERLAPS AND IS NOW A WORKED EXAMPLE OF
WHY THE DISTINCTION MATTERS.** Since 2026-08-27 this service can write three
things down (`persistence/CLAUDE.md`), so the SERVICE sentence changed — the
root table's "persist anything at all" row became "persist anything it MINTS" —
and the CONSOLE sentence changed differently: what an operator standing here
needs is *whether the change I am about to make will still be here tomorrow*,
which is a per-process, per-setting answer rather than a property of the
service. That is why `/admin/persistence` exists as a page and why
`configFormsFor()`'s footer is computed rather than asserted: the same edit
that made the service sentence conditional made the console's sentence
conditional in a different way, and one sentence could not have carried both. "This service checks no password" belongs in the root table; "the
gate proves that somebody typed a name that holds a role, and `/admin-api`
takes an access token instead" belongs on the page, because it is the thing a person
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

(Two, since 2026-08-30 — `/admin/crypto-metadata` is drawn by
`./crypto_metadata.js`, which is in this directory but is not `admin.js`. It
borrows the shell on exactly the terms below and the section above argues the
rest.)

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

### The foot of every page says what this process is running as (2026-09-13)

Under the version line, `runtimeFooter()` draws four facts: whether requests are
DISPATCHED to request workers or answered by a single process
(`workers.requestCount` and `workers.dispatch`, and which worker drew the page),
the realm's MODE (`mode.current()`), the PERSISTENCE store that is open
(`persistence.status()` — host, port and database for postgres, the data
directory for ldif), and where the two primordial secrets come from
(`secrets.describe()` for the key-encryption key — or *not read* where
`keystore.persists()` is false — and `secrets.describeDatabasePassword()`).

* **Every fact is read from the module that owns it, per render**, so the line
  cannot disagree with `/admin/persistence` or `/admin/secrets`, which it links
  to. It says WHERE a secret comes from and never WHAT it is.
* **The store fact is the OPEN store**: `status().mode` is `memory` until the
  configured store has opened, and a store that cannot open stops the service,
  so a mismatch is only a process that has not opened it — and it is said.
* **It is not drawn for a reader with no session** (`gate.enforced &&
  !gate.session`), for `refreshLink()`'s rule: the shell draws the sign-out
  page and the 401s, and a database host and secret-store paths belong to people
  who may read those two pages.
* **A fact that throws is drawn as `unknown`**; a footer must not cost a page.

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

## `/admin/crypto-metadata` IS THE SECOND PAGE OF THIS CONSOLE THIS FILE DOES NOT DRAW

Added 2026-08-30, in `crypto_metadata.js`, under **Server configuration** beside
*Service metadata* — and the two sit together because each is a REPORT about the
whole service rather than a control over one part of it.

`/admin/sts-metadata` answers *what can I call, and what specification is it
pretending to implement*. This answers the question underneath it, which nothing
here could answer before: **when this service signs, verifies, encrypts or
decrypts something, what does it actually use** — which digest, which signature
algorithm, which cipher, which key, and which of the several envelopes (JOSE,
XMLDSIG and XML Encryption, WS-Security, COSE, X.509, Kerberos, SPIFFE) that
primitive is wrapped in.

**It was worth a page because `common/crypto.js` centralised the CODE and not
the DESCRIPTION.** Since 2026-08-27 there is one module that signs, verifies,
encrypts and decrypts; *which algorithms does this thing speak* was still
answered by reading six tables in four files, and this console — which exists so
that nobody has to — said nothing about any of them.

### EVERY TABLE IS READ FROM THE MODULE THAT PERFORMS THE ALGORITHM

That is `sts_metadata.js`'s argument one layer down, and it is the design rather
than a nicety. That page walks the live router because a hand-kept list of
routes goes stale the first time somebody adds one and the failure is silent in
the worst direction — the page still looks complete. An algorithm table is the
same shape of thing. So the JWS rows are `stsCrypto.JWS_ALGS`, the XML ones are
the vendored `xmldsig.js`'s three tables, the Kerberos encryption types are read
back through the codec's own `etypeName()` (those modules are VENDORED and
cannot be edited to export a list), the SPIFFE key types are `spiffeCa.KEY_TYPES`,
and so on for eleven modules.

**`crypto_metadata.js` is required at 20a, after `tls/tls_server`, and that is
the constraint that decides the line.** It reads an algorithm table out of
eleven modules — `common/crypto`, `pq_jose`, the vendored `xmldsig`,
`krb5_crypto`, `webauthn`, `oauth2`/`dpop`/`client_auth`/`mtls`, `spiffe_ca`,
`scim_auth` and `tls_server` — and requiring one it has not yet loaded would
REGISTER ITS ROUTES THERE (rule 1). At 20a every one of them is a cache hit.
Also after `admin-ui/admin` for the shell and the gate.

**Only two things on the page are written by hand, and both are things no table
can hold**: the per-family prose in `FAMILIES` (what each identity service signs,
and why) and `STANDARDS` (which document an envelope comes from, and how much of
it is really implemented). Both follow `sts_metadata.js`'s rule — every
`coverage` starts `full`, `partial` or `mock` and says what is missing — and it
is worth more here than there, because a page about cryptography that overstates
what it implements is actively dangerous to somebody using it to learn.

### THE FAMILY LIST IS CHECKED AGAINST `sts_metadata.js` RATHER THAN AGREED WITH IT

The page reports on the identity services this mock ADVERTISES, so the list of
them has to be the list `/admin/sts-metadata` draws its cards from. Two tables
naming fourteen protocol families are two tables that will disagree the first
time a fifteenth arrives — invisibly, because each page would look complete on
its own. So `sts_metadata.js` requires this module and hands `PROTOCOLS` over at
its own require time (`setProtocolFamilies()`), and the page reports BOTH
directions of drift the way that page reports both directions of endpoint drift:
a family advertised with no crypto profile, a profile naming a family that is
not advertised, and — a third direction that page has no equivalent of — a
family citing an envelope with no row in `STANDARDS`.

**A slot rather than a require, and the direction is forced.** A
`require('../sts_metadata')` from here would load, at 20a, the one module whose
whole constraint is that it is required LAST. With the slot unfilled the page
draws its own table and SAYS the check did not run, rather than rendering two
empty lists that look like a clean bill of health.

### THE FOUR VERBS ARE SEPARATE COLUMNS, AND THAT IS THE POINT OF THE TABLE

Signing is minting something a relying party will believe; verifying is a
decision that can be got wrong; encrypting uses somebody else's key; decrypting
means holding a private key a caller can aim ciphertext at. Those are four
different exposures and this service does a different amount of each — federation
verifies and barely signs, SAML 2.0 does all four, SCIM and LDAP and WebAuthn
sign nothing at all. A column that collapsed them into *uses cryptography* would
hide the one distinction a reader came for. An empty cell is drawn as *does not*
rather than blank, because every one of them is a documented non-goal and a
blank cell and an unwritten cell look identical.

### THE POST-QUANTUM SECTION, AND WHY IT IS IN THREE PARTS

Asked for on the day the page was written, and the headline is deliberately not
the flattering one: **the signatures are partly post-quantum and the key
establishment is entirely classical.** A page that said "supports ML-DSA"
without separating them would be making exactly the claim this repository exists
not to make.

The two halves are reported apart because the THREAT differs, not the effort. A
signature is verified at the moment it is presented, so a signature algorithm
that falls in 2035 is a problem in 2035; a key agreement is not, because
ciphertext captured today can be kept and opened when the machine arrives. So
the surface that most needs a post-quantum answer here is the one that has none
— there is no ML-KEM in this process, in JWE, in XML Encryption or on any TLS
socket — and that row says so rather than letting the post-quantum signatures
above it imply otherwise.

**Symmetric cryptography is a third category and is the one people get wrong.**
Grover costs a square root rather than breaking anything outright, so the answer
is key length: AES-256 and SHA-384 are unaffected in any practical sense, and
what is wrong with RC4-HMAC, MD5 and MD4 has nothing to do with quantum
computers. **Kerberos is therefore the family here least affected by any of it**
— the only one with no public-key cryptography in it at all — which is the
opposite of what its reputation suggests, and is the sentence most likely to be
"corrected" by somebody skimming.

**The most instructive row is DPoP.** Its list excludes the post-quantum
algorithms deliberately: a proof is bound through `cnf.jkt`, the RFC 7638
thumbprint, which is defined for RSA, EC, OKP and oct and not for `AKP` — so a
proof signed with ML-DSA would verify perfectly and bind to NOTHING. The gap is
in the BINDING, not in the signature, and the page says which.

### FOUR SMALLER DECISIONS

* **IT PUBLISHES NO PRIVATE KEY AND NO SECRET.** Key types, key identifiers,
  curve names, certificate fingerprints and validity dates — everything already
  readable from `/oauth2/jwks`, `/tls/server-certificate` and the SPIFFE bundle
  endpoint. That is a rule for anything added here later rather than an
  observation about what is here now: this is exactly the page somebody would
  think to put a private key on.
* **IT DOES NOT CALL `allSigningKeys()`.** The post-quantum keys are made on
  FIRST USE — one SLH-DSA keygen is most of two seconds — so a metadata page
  that reached for them would spend that on every view, in a realm where nobody
  had asked for a post-quantum signature. It reads `keys.pqKeys`, which exists
  only once something has brought them into being, and reports honestly which
  of the two states the realm is in.
* **NO SCRIPT, and it did not need the argument made again.** Everything on it
  is a table and prose through `note()`/`warn()`, so `script-src 'none'` is
  untouched and this is not a candidate for the exception at all — unlike the
  two drawings, which had to argue it twice.
* **The prose carries `backticks` and the RENDERER turns them into `<code>`.**
  The same strings are served as JSON at `?format=json` and on
  `/admin-api/crypto`, where markdown is the convention every description in
  this service follows. Escaping happens FIRST and the substitution second,
  which is the order that matters.

### WHAT IT COSTS TO ADD A PROTOCOL FAMILY, NOW

A card in `sts_metadata.js`'s `PROTOCOLS`, an entry in its `ENDPOINTS`, **and a
row in `crypto_metadata.js`'s `FAMILIES`**. The third is enforced:
`tests/vendored/admin_api.js` — this repository's own — fails on the drift
report being non-empty in either direction, on a coverage note that does not
start `full`/`partial`/`mock`, and on any of five algorithm lists differing from
what this service advertises in its own discovery documents. That last check is
the one that makes "every table is derived" mean something: reading the report
on its own says nothing, because a hand-written list is well-formed too. All
three assertions were mutation-tested before they were committed.

**The nineteenth family is PKI (2026-09-10)** and it paid all three;
what it also owed, and what nothing checks, is a row in `admin-ui/admin.js`'s
`SETTING_HOMES` — `checkSettingHomes()` refuses a settings GROUP with no page,
so a `pki.*` group with no `/admin/pki` row would have been reported at startup
and drawn nowhere. **`ssf/CLAUDE.md` carries the full
list of what adding the seventeenth family actually cost, which was nine files
rather than three** — it is the record of one family, where this is the rule.

## `/admin/keys` IS THE ONE PAGE HERE WHERE READING IS TAKING (2026-08-30)

Added in `crypto_metadata.js` — the same module, because it already requires
`tls_server`, `spiffe_ca`, `helpers` and `admin`, already sits at 20a, and
already computes the key inventory for the page next door. A module of its own
would have cost an eighth slot and a new require-order constraint for nothing.

**IT IS THE DELIBERATE OPPOSITE OF `/admin/crypto-metadata`.** That page
publishes key types, identifiers, curve names and fingerprints and says twice
that it publishes no key material. This one hands the private half over. Both
statements are true and the split is the design: a report about what this
service can do is something to leave lying around, and a private key is not.

**Why it is defensible here and would not be anywhere else.** Every key in this
process is generated at start, lives only in memory, and dies with the process.
None protects anything — the service checks no password and validates no token
it did not mint. What a person constantly needs is the far end of an exchange: a
keystore for a Java truststore, a PEM for `openssl s_client`, a JWK to paste
into a client. Making them re-derive that from `/oauth2/jwks` and a screenshot
is the friction this removes.

**It needs Admin Write**, which is a stronger requirement than any other READ on
this console, and `mayWrite()` exists for that one caller. It goes through
`gateStateFor()` so the answer is the one every page's banner is drawn from.

### Four decisions

* **The exporter is `common/vendored/key_material.js`, not a second one.** That
  is the debugger's own keystore code, already vendored, already doing PEM, DER,
  JWK and PKCS#12 with a password. A second exporter would be the worse copy.
  **There are now THREE things in this file with names in that neighbourhood**
  — `keyMaterial()` reports on the keys, `keystore` exports them, and
  `stsKeystore` is `common/keystore.js`, which decides whether they persist and
  how long a decrypted one stays in memory. The collision section below records
  what getting this wrong already cost.
* **PKCS#12 only where there is a certificate**, and the refusal is the vendored
  module's own. A `.p12` wraps a key in a certificate and this service holds one
  for the signing key and the TLS key and nothing else. Minting a throwaway so
  the format "worked" would hand somebody a keystore this service has never
  presented.
* **The post-quantum keys are JWK and public-half only**, which is RFC 9964
  rather than a gap: an ML-DSA key is `kty: "AKP"`, there is no PKCS#8 encoding
  for it here, and the private seed handling is still moving. A file no library
  reads is worse than a refusal that says why. They are also not GENERATED by
  this page — they are made on first use, and a metadata screen costing two
  seconds a view is one people learn not to open. **Since 2026-09-13 each is a
  leaf of the realm's JOSE Issuing CA**, so its row carries `certifiedBy` like
  the curve keys' and the export returns the certificate and its chain as a
  SECOND file — which `/admin-api` hands over and the page's one-file download
  does not, and the status line says so. Still no PKCS#12: that format wraps a
  PRIVATE key, and having a certificate does not give an AKP key an encoding.
* **The POST answers with the FILE**, which is the only form in this console
  that does not come back as a page. A download IS the response body; a 303 to a
  page saying "your key is ready" would be a page with nothing on it. A REFUSAL
  is still a page, so a bad password reads like every other refusal here.

### AND SINCE 2026-09-06 IT REPORTS HOW LONG A PRIVATE KEY STAYS DECRYPTED

Where key material persists, this process holds the CIPHERTEXT and decrypts a
realm's signing key only while something signs with it. `common/CLAUDE.md`
argues the mechanism; two things about it are this page's.

**IT IS A REPORT AND DELIBERATELY NOT A CONTROL, which is rule 7 read exactly
rather than a gap.** Everything on it is either a SETTING —
`keys.plaintextRetention` and `keys.plaintextTtlS`, drawn on `/admin/config`
with the rest of the `Key material` group, because that is where that group's
`SETTING_HOMES` row sends it — or an observation. A *Purge now* button was
considered and refused for a reason peculiar to this page: **its one POST
answers with a FILE rather than a page**, so a second action here would be the
only form in this console whose two buttons answer in two different shapes, and
what it would buy is shortening a window the timer shortens anyway.

**THE NUMBER IS THE POINT.** A page naming only the policy would be describing a
promise. It names the realms whose key is decrypted RIGHT NOW, which a reader
can watch change — the only way an operator can tell this is working rather than
configured. The table says `no` for a realm until something signs for it and
goes back to `no` on its own, and the note says that reading this page decrypts
nothing while exporting a key does.

**THE SAME CHANGE FIXED TWO SENTENCES THAT HAD BEEN FALSE SINCE THE KEYSTORE
LANDED, and they are the two that matter most on this page.** `keysJson()`
carried `regeneratedEveryStart: true` as a CONSTANT, and the warning that makes
handing a private key to a browser defensible said these keys are "generated at
start, held only in memory, dead when the process exits". On a product-mode
service the signing key OUTLIVES the process — so the page was offering the
reassurance a reader acts on, about a key for which it was not true. Both are
computed from `keystore.report()` now, and the persisted branch says the
opposite out loud: a key exported here goes on signing after a restart and
anything signed with a copy goes on verifying against the live JWKS. **The TLS certificate and the SPIFFE
JWT authority really are per start**, which is why the rows carry the
distinction rather than the report as a whole. **The SPIFFE X.509 authority
stopped being one of them on 2026-09-11**: it is this realm's SPIFFE Issuing CA
under the service Root now, so it persists wherever the rest of the hierarchy
does.

### TWO NAME COLLISIONS IN ONE FILE, AND THE SECOND ONE WAS A 500

`keyMaterial()` was already this file's REPORT on the keys, so the vendored
import had to be `keystore`. That was caught at parse time. What was not is that
`renderKeys()` already existed too — the key-material SECTION of
`/admin/crypto-metadata` — and a second function declaration of that name
silently replaced it, so the page next door started calling the wrong one and
threw `report.keys.map is not a function`. It is `renderKeyPairs()` now.

**The lesson is that the first rename fixed the symptom rather than teaching the
lesson.** A file this long holds names nine hundred lines apart, `node --check`
catches a duplicate `const` and says nothing about a duplicate `function`, and
the browser suite is what found it. Check for the name before adding one.

## `/admin/pki` IS THE THIRD PAGE THIS FILE DOES NOT DRAW, AND THE FIRST THAT NEEDED NO SLOT (2026-09-10)

`admin-ui/pki_admin.js`, under **Protocols → PKI**, ungrouped, next to TLS. It
builds a certificate authority for the trust realm it is reached in and issues
signing key pairs from the bottom of it to applications — which is what makes
[RFC 7521 and RFC 7523](../oauth-oidc/CLAUDE.md) usable here without an operator
moving key material by hand.

### IT SHOWS ONE REALM'S AUTHORITIES, AND FOR A DAY IT SHOWED EVERY REALM'S (2026-09-11)

The page draws the **Root**, the **process branch** and **this realm's
Intermediate** with its Issuing CAs — and no other realm's. `GET
/admin-api/pki` answers exactly the same, because the page and the API are one
function (`pkiJson()`), and a view that answered more than the page drew would
be two answers to *what is this realm's certificate authority*.

**WHAT WAS WRONG WITH THE WHOLE-TREE PAGE IS NOT THAT IT WAS BIG.** Every other
surface on this console shows ONE REALM AT A TIME and the switcher is how you
change it; this page read the whole process, so an operator in one realm was
handed a **Rebuild** button for another realm's certificate authority and a
**Revoke** for certificates issued in it. A revocation is permanent and is made
BY AN ISSUER — the issuer's name on the row is the only thing that says which
realm is about to change — so that was the row where the leak was more than
untidy. Nothing failed while it was there: every tier was correct and every
path verified, which is why it read as thoroughness.

**THE PROCESS BRANCH IS DRAWN IN EVERY REALM AND THAT IS DELIBERATE.** The TLS
authority certifies sockets every realm answers on, so it is this realm's front
door as much as anybody's; it belongs to no realm, so no realm's page is more
its home than another's; and it has no other surface anywhere, so hiding it from
every realm would make that authority unreadable and unmanageable from this
console. (**It carried the SPIFFE authority too until 2026-09-11**, when that
one moved to a realm's branch — a realm signs its own X509-SVIDs, and the four
SPIFFE sockets do not prevent it because the anchor those SVIDs verify against
is the service Root that every realm shares.) The Root is there for the same kind of reason and a stronger one:
narrowing the branches must not narrow the ANCHOR, or the page shows an
Intermediate signed by nothing.

**THE WRITE PATH HAD TO MOVE WITH THE DRAWING, AND THAT IS THE HALF WORTH
COPYING.** `SCOPED_ACTIONS` is the seven actions that carry a `scope`, and one
naming a realm this page does not draw is REFUSED — not silently redirected to
this realm's own branch, because a caller that named `acme` meant `acme` and
quietly rebuilding something else is the one outcome worse than saying no. The
refusal names the realm switcher, because switching is how to do what was
asked. **A page that hides a branch while its actions still edit it is worse
than the leak it replaced**: the operator cannot see what they changed.

**THE NARROWING IS IN `pki_admin.js` AND NOT IN `common/pki.js`.** That module
is handed scope ids and has no opinion about which exist — the same reason
`rebuildEveryScope()` lives on this side — so *which branches does a reader in
this realm get* is asked exactly once, where the page is.

#### A rebuild re-mints what the old branch certified for the realm's keys — all THREE doors (2026-09-15, #46)

`build-scope` and *Replace the Root* (`rebuildEveryScope()`) always followed the
build with `recertifyScope()`. **`build` — the action `POST /admin-api/pki/build`
reaches — did not**, and `common/pki.js`'s `buildScopeNow()` carries the row's
recorded certificates over the rebuild (so the workbench's objects survive). So
the realm's JWKS `x5c`, its SAML metadata and its signature headers went on
publishing the signing keys' certificates from the SUPERSEDED Issuing CAs, with
the old Intermediate in the chain — and the old Issuing CAs name the same
`intermediate.crl` as the new ones, so one list was named by two issuers.
`tests/vendored/sts_pki_distribution_points.js` failed on it in every mode.

**It was there on `develop` and was hidden by timing.** A runtime realm's keys
were made by the first handler that read them, which for a realm created and
immediately rebuilt came AFTER the rebuild, so nothing had been certified from
the old branch. #46's `app.js` makes the request realm's key set BEFORE the
handler, so the realm watcher's `certifyKeySet()` finds them held and certifies
them from the branch the rebuild then replaces. The fix is the missing
`recertifyScope()` in `build`, and `certify()`'s refusal to record a certificate
from an authority replaced while it was being signed (`common/CLAUDE.md`) for
the certification still in flight. `tests/pki_rebuild_recertifies.js`.

#### And the store spells the default realm `default`, not `''`

Found in the same change and worth more than the narrowing. `common/pki.js`'s
`realmIdOf()` resolves an empty scope to the **ambient** realm, so `''` does not
name the default realm there — it names *whichever realm is asking*. The page's
realm list converted `default` to `''`, which is invisible in the default realm
(the two coincide) and wrong everywhere else.

It bit on the REBUILD: *Replace the Root* walks every branch, and pressed while
in `acme` it walked `['*process', '', 'acme']` — `''` was acme again, so acme's
branch was rebuilt twice and **the default realm's was never rebuilt at all**,
leaving it chained to a Root that no longer exists. `realms.DEFAULT_ID` is the
store's own spelling and resolves to the same row from every realm.

### It is at 18a, and that is the whole of why there is no thirteenth slot

Rule 3e's test is whether a require would close a cycle **or move a route**. A
require from `admin.js` to that module WOULD close a cycle — it requires this
one for the shell — so the obvious direction is out. But a require from
`mgmt-api/admin_api.js` (19) to it moves NOTHING: the only route it registers is
`/admin/pki`, and it requires only `admin.js` and `common/pki.js`, which is a
LIBRARY (rule 3).

So it is required in `common/protocol_stack.js` at **18a**, immediately after
this file and BEFORE the management API — which makes that module's own require
a cache hit that registers nothing.

**`crypto_metadata.js` COULD NOT DO THIS AND THAT IS THE CONTRAST TO KEEP.** It
sits at 20a because it reads an algorithm table out of `tls/tls_server.js` at 20,
so requiring it from `admin_api.js` would drag every `/tls*` route in front of
the management API's own — which is why that one has the seventh slot and this
one has none. **A slot costs a reader an indirection every time**, and rule 3e
says not to pay for one by analogy.

### The `script-src` argument is made from scratch, for the tenth time

`admin-ui/CLAUDE.md`'s standing rule is that the argument has to be MADE each
time and that "the page next door does it" is not one. The test is whether the
page CANNOT work without a script.

It plainly can. Generating a key pair and issuing a certificate are things this
process does far better than a browser — **it holds the CA private keys, and a
browser must never** — so the button is a POST and the result is a re-rendered
page. That is the exact inversion of the parent project's *PKI / X.509* page,
whose whole point is that the key never leaves the browser; what is mirrored
here is the MODEL (the same three tiers, the same profiles, the same encoder,
from `common/vendored/x509.js` byte-identical) and not the mechanism.

### The two columns are two different facts, and the page says which

Holding a key pair and being TRUSTED TO ASSERT are separate acts, and an
application commonly has one and not the other. A key pair lets it SIGN, which
is all RFC 7523 section 2.2 needs; a declared `iss` on `oauthAssertionIssuer` is
what section 2.1 needs. Drawing one column would have made the page say
something untrue about whichever half was missing.

### A THIRD FACT ARRIVED WITH RFC 7522: WHICH PROFILE (2026-09-11)

The Issue control takes a **Profile** — RFC 7523's JWT assertion or RFC 7522's
SAML 2.0 one — and they are two key pairs on two disjoint attribute sets. An
application may hold both.

**THE TABLE IS ONE ROW PER APPLICATION PER PROFILE, so an application holding
both appears twice.** A single row with a pair of columns was the first shape of
this and was wrong for a reason worth keeping: **every fact on such a row is per
profile** — the key handle, the expiry, the declared issuer, and the *Take the
key pair off* button — so one row would have had to say which of two things each
of its controls meant. Taking one profile's key pair off leaves the other
working, and the reply says so; a control that cleared both would be a button
whose label said one thing and did two.

**The key handle column is headed differently per row and that is not a
cosmetic difference**: a `kid` for the JWT profile and a THUMBPRINT for the SAML
one, because those are the handles the two formats actually carry — a JWS header
names a `kid` and an XML Signature carries the certificate itself, so what
matches a presented `<ds:KeyInfo>` against what is registered is a thumbprint.
`admin-ui/pki_admin.js`'s `PURPOSE_WRITES` is the one table that says which
attributes each profile writes; `oauth-oidc/CLAUDE.md` 3z argues why the two
sets may never be merged.

### THE TWO KEY-PAIR TABLES ARE PAGED (2026-09-13)

*Applications* and *People* drew every row they had. They page now, separately,
on `issuedPage` and `personsPage` with one shared `per` (twenty-five by default,
not the console's fifty, because this page carries eight sections), with one
*Rows per table* control under the Applications heading. `keyPairPaging()` in
`pki_admin.js` is the one slice both the page and the JSON use.

* **THE NAMES ARE THE JSON MEMBERS'** — `issued` and `persons` with `Page` on
  the end, answered by `issuedPaging` and `personsPaging` — which is
  `/admin-api`'s one-name-per-list rule rather than the table headings.
* **APPLICATIONS PAGES ROWS AND PEOPLE PAGES PEOPLE.** `issued` is already a row
  per application per profile; `persons` is a member per person with the SAML
  key pair nested, drawn as up to two rows. Paging drawn rows there would give
  `personsPaging` numbers that index into nothing the reply holds.
* **THE REPLY KEEPS BOTH LISTS WHOLE**, `/admin/delegation`'s rule: the tiles
  count them, and `sts_jwt_bearer_grant.js` looks its client up in `issued` by
  identifier.
* **EVERY TAKE-OFF BUTTON CARRIES BOTH TABLES' STATE AS `back`**, and
  `pkiReturnTo()` rebuilds it — the three names, positive integers only — into a
  303 to the same pages at `#pki-applications` or `#pki-people`. A control that
  carries no `back` (Build, the pane, the revocation pane) still gets the bare
  page.

`tests/pki_key_pair_paging.js` pins all of it.

### Two limits, drawn as a `warn()` rather than left as absences

**THE FIRST OF THEM REVERSED ON 2026-09-11 AND THE `warn()` DID NOT GO AWAY.**
It read *nothing is ever revoked — no CRL, no OCSP.* Every authority on this
page now signs one and answers the other, and the page grew a REVOCATION PANE
(below). What the warning says instead is the narrower thing, which is the one
a reader can be hurt by: **revocation here is PUBLISHED and never CONSULTED**,
so a certificate revoked on this page still authenticates to this service.

**AND THE PAGE NOW CARRIES TWO CONTROLS WITH THE WORD *REVOKE* ON THEM.** The
older one, in the Applications table, takes a key pair OFF an application's
directory entry: this service stops ACCEPTING what that key signs, the
certificate goes on chaining, and nothing lands on any list. The newer one, in
the revocation pane, puts a SERIAL on an issuer's list: nothing changes about
who holds what, and what changes is what this service's CRL and OCSP responder
say from that moment. Somebody dealing with a compromised key pair wants both,
and they are two buttons because they are two acts with different blast radii —
the first is undone by issuing again and the second only for a
`certificateHold`. The pane says all of that where an operator reads it; the
reply of each says what it did rather than reporting a success that would be
read as more than it is, which is the same distinction `/admin/logout` draws
about an assertion already issued.

**And in development mode the hierarchy dies with the process**, which is the
rule the signing key already follows. Both sentences come from
`common/pki.js`'s `report()` rather than being written here, so every surface
that draws them repeats one wording.

### Four actions, and the refusal sentence is read by a test

`PKI_ACTIONS` is `build`, `clear`, `issue` and `revoke`, and the count in the
refusal comes from that list rather than being written out. **The sentence is
read** — `tests/vendored/sts_admin_api_operations.js` matches `Unknown action
"x". <prose>: a, b, c.` out of `errors` on every action resource, and
`tests/vendored/admin_api.js` reads the same sentence for the parity check — so
a handler that phrased it its own way, or answered with a `why` alone, turns
both of those off for its own resource with nothing failing. **The first version
of this file did exactly that and went red on its first run**, which is what the
check is for. `refuse()` is the one place both shapes are built, from one string.

### THE CERTIFICATE & KEY CONFIGURATION PANE (2026-09-10)

The page above is the hierarchy this SERVICE maintains for itself. The pane
below it is the parent project's *PKI / X.509* workflow — an arbitrary
certificate, from any authority whose private key is here, with every field and
every extension exposed. `common/pki_authoring.js` (rule 3aa) is the model and
argues it; what belongs here is the four decisions the PAGE makes.

**IT IS ONE FORM, AND THAT IS LOAD-BEARING RATHER THAN TIDY.** A hundred and
fifteen fields, three columns, twenty-two extension cards AND the store table,
all inside one `<form>`. Two things need it. *Apply the profile* has to rewrite
twenty-two boxes with nothing kept between requests, which it can only do if the
browser hands the whole form back. And *Use this key pair*, in the store, has to
load a key into the boxes WITHOUT discarding the subject somebody has been
typing — a second form around the table would have made that impossible.

**THE BUTTONS DO NOT SHARE A NAME, and `/admin/users/new` is why.** That page
records what two submit buttons both called `action` cost: `form.elements.action`
becomes a `RadioNodeList` whose value is empty, and the console suite — which
finds a form by the action it posts — reads the page's main button as a control
that reaches nothing. So the Issue button is UNNAMED behind a hidden
`action=issue-certificate`, and `defaults`, `generate`, `generatealt`, `use`,
`remove` and `clearstore` each have a name of their own that `paneActionFrom()`
reads FIRST.

**THE DOWNLOAD BUTTON USES `formaction`**, which is markup rather than script:
it posts the same form, with the same CSRF token, to `/admin/pki/export`. A
form has one `action`, and the alternative was a second form around the export
row — which would have cost it the key boxes it exports when nothing is
selected.

#### `POST /admin/pki/certificate` ANSWERS WITH A PAGE, WHICH ALMOST NOTHING HERE DOES

Every other control in this console goes through `respondToAction()`, which 303s
back with a message on the query string. **This one cannot**: what it has to hand
back is the FORM — the profile applied, the key pair generated, the refusal with
every field still in it — and a query string is not where a hundred and fifteen
fields go. `/admin/users/new` made exactly this argument first and for the same
reason.

A JSON caller still gets JSON, so `/admin-api` is unchanged and a test may drive
either door.

**A REFUSAL CARRIES THE DRAFT.** A form of that size redrawn empty because one
line of a `subjectAltName` would not parse is not a refusal anybody can act on.

#### `POST /admin/pki/person` IS THE SECOND, AND ITS REASON IS THE OPPOSITE ONE (2026-09-11)

That page issues a signing key pair to a PERSON now as well as to an
application — the same `issue` action with a `target` field, because the two
differ in exactly two things (which subjectAltName the certificate carries, and
which entry the result is written onto) and a second action would be a second
answer to *how does this service issue a signing key pair*.

**IT HAS A POST ROUTE OF ITS OWN BECAUSE WHAT IT HANDS BACK IS A PRIVATE KEY.**
The pane's route above renders a page because its answer is a FORM; this one
renders a page because `respondToAction()` 303s with its message on the query
string, and a private key on a query string is a private key in the browser
history, in this service's own access log, and in the `Referer` header of the
next request the browser makes. It is shown ONCE, in a block under the banner
that says so, and there is no read door for it afterwards — the value is sealed
on the entry and nothing in this console or in `/admin-api` opens it.

**AND THAT IS A DELIBERATE DIFFERENCE FROM THE APPLICATION ARM**, which returns
no key at all. An application's private key is readable through
`applications.view()`, which opens the seal for `/admin/applications` and
`GET /admin-api/applications`; a person's entry is drawn through no module that
would. The alternatives were a console page that prints somebody's private key
on every visit, or a key this service holds that no human can collect.
`common/person_assertions.js` (rule 3ab) argues it, along with the one refusal
the feature exists for: a person's key may assert about that person and about
nobody else.

**THE TAKE-OFF CONTROL IS THE SAME `revoke` ACTION with the same `target`**, and
it clears the `stsAssertionIssuer` declaration with the key pair where the
application arm deliberately leaves `oauthAssertionIssuer` alone. An application
may hold a JWKS it registered itself beside the one this service issued; a
person may not, so leaving the declaration would leave somebody declared as an
issuer with no key to issue with. Both say, in as many words, that this is NOT
revocation.

#### It is `script-src 'none'`, and the argument is made from scratch

The rule in this file is that the argument has to be made each time and that
"the page next door does it" is not one. The test is whether the page CANNOT
work without a script, and this one plainly can: generating a key pair and
issuing a certificate are things this process does far better than a browser —
it holds the CA private keys, and a browser must never — so every button is a
POST and every answer is a re-rendered page.

**The debugger's page needs a script because its whole point is that the key
never leaves the browser. This page's whole point is the opposite.** What the
refusal costs is written down rather than hidden: two *Apply* buttons where that
page has an event handler, no Copy buttons (a textarea selects), and an
algorithm menu that is narrowed by a round trip.

#### The ten CSS rules are in `admin.js` and not here

This console has ONE stylesheet. A page with a `<style>` of its own would be the
second place a reader has to look for why something is laid out as it is, and
`script-src 'none'` is already the reason there is no third.

Two of the ten are decisions rather than appearance. **`.pki-cols` is a grid
with an `auto-fit` 22rem floor**, so the three blocks drop to two columns and
then to one on a narrow window with no media query — stacked at full width, the
button at the top of the second column is nine screens above the extensions it
applies to. **`.pki-extlist` is a COLUMN FLOW and not a grid**, because a grid
lays its items out in ROW order and twenty-two cards of different heights leave
a ragged gap under every short one.

The third is an override and has to be: this console's default textarea is
`min-height: 7rem`, which is right for a policy document and wrong for twenty-odd
one-item-per-line boxes — at 7rem each the pane is about four screens of empty
box.

### `pkiAction()` RESOLVES, which only one other action function here does

Issuing a certificate is Web Crypto all the way down. `ssfAction` is the first
that resolves and the reason is related — it signs and then POSTs — and both
call sites `await` and turn a rejection into a refusal: Express 4 does not look
at what a handler returns, so an unhandled rejection is a request that never
gets an answer.

## `/admin/ssf` IS THE FIRST PAGE HERE WHOSE ACTION HANDLER AWAITS

Added 2026-08-31 with the Shared Signals family. Everything about it follows the
shapes already here — a `SECTIONS` row with a `blurb`, a `SETTING_HOMES` row, a
GET and a POST on `/admin-api`, `configFormsFor()` at the foot — with two
exceptions worth recording.

**THE EIGHTH SLOT'S `action` RETURNS A PROMISE, AND NO OTHER ACTION FUNCTION IN
THIS CONSOLE DOES.** Every other one answers from memory: a revocation, a claim,
a realm. Transmitting a Security Event Token **signs a JWS** — which may be
ML-DSA or SLH-DSA on the worker pool, seconds of computation — and then **POSTs
it to somebody else's endpoint**. Neither can be done synchronously, and
pretending otherwise would mean this page reporting "sent" before anything had
been. So `app.post('/admin/ssf')` awaits and `respondToAction()` is called from
the `then`; a rejection is turned into a refusal naming the message, because
`consoleAction()` resolves a refusal rather than throwing one and a rejection
here would be a bug in `ssf/ssf.js` rather than anything a request can cause.

**THERE IS DELIBERATELY NO CREATE FORM, AND THAT IS RULE 7 READ EXACTLY RATHER
THAN A GAP.** Every other registry page here can create the thing it lists. A
Shared Signals stream carries a **delivery endpoint this service will DIAL**, and
the one place that URL may come from is a receiver that authenticated at
`POST /ssf/stream` and asked for it. A form here that could mint one would be a
second door onto the outbound request `ssf/ssf_http.js` spends its whole header
bounding — and this console takes a person's sign-in while `/admin-api` takes a
token anybody holding the seeded client's secret can mint, so the second door
would be the one reached with the weaker credential. (That read "while
`/admin-api` is not [gated], so the second door would be the ungated one" until
2026-09-09; the gate arrived and the ordering it describes did not change.) There is no control, so there is no operation to
mirror, and the parity holds. The page says so where the create form would have
been rather than leaving its absence to be noticed.

The four actions that DO exist — set a status, transmit an event, delete a
stream, clear what has been received — each have their operation on
`/admin-api/ssf/:action`, through the same function.

---

## `/admin/tls/trust` AND THE THIRTEENTH SLOT (2026-09-12)

The client-certificate truststore: every anchor 8443, 9443, LDAPS 636 and the main port
verify a client certificate against, with its subject, issuer, serial, validity, SHA-256
fingerprint and SOURCE (`file` from `tls.trustAnchorsFile`, `runtime` otherwise), paged,
with an add form (a textarea of PEM blocks) and a Remove button on every row. It is the
runtime door product mode did not have — `POST /tls/trust` needs no credential, so product
mode refuses it — and `GET /admin-api/tls/trust` / `POST /admin-api/tls/trust/{add,remove}`
mirror it (rule 7). `tls/CLAUDE.md` argues what the truststore does; four things are this
file's.

* **FILED UNDER PROTOCOLS, DIRECTLY BENEATH `/admin/tls`, UNGROUPED.** It is configuration
  of those listeners, which is the question that section answers. A `TLS` group heading over
  `TLS / mutual TLS` would say the label twice, which is `SECTIONS`' test for a group.
* **THERE IS DELIBERATELY NO CLEAR BUTTON**, and the page says why where one would be: a
  clear's reach is every client certificate every other caller relies on. The controls are
  drawn for a reader holding Admin Write; the GATE refuses a POST without it whatever the
  page drew. Removing a `file` anchor is allowed and the reply says it comes back.
* **THE SLOT IS `setTruststore()` AND IT PASSES RULE 3e'S TEST BOTH WAYS ROUND.** A require
  from this file to `tls/tls_server.js` would move `/tls*` routes on the documented order
  and make the console the reason they are where they are; a require from that module back
  to this one at its top level is a REAL cycle, not a theoretical one — `tls_server.js` is
  first loaded from inside this file's own require, through `admin-core/admin_views.js` →
  `spiffe/spiffe_auth.js`, so it would find no `setTruststore` on the half-built exports.
  **So it is the one slot here NOT filled by the module that owns what it carries**:
  `common/protocol_stack.js` fills it on the line after it requires `tls_server.js`. It
  carries one object (`list`, `add`, `remove`), is validated whole for `setLogoutReader()`'s
  reason, and forwards to both `admin-core/` halves from inside the setter;
  `tests/admin_actions_layer.js`'s `FORWARDED` holds the single writer in each.
* **WITH REQUEST WORKERS THE PAGE IS ANSWERED BY THE FRONT PROCESS**, pinned in
  `common/request_pool.js`'s `NEVER_DISPATCHED`, because the array is configuration of
  listeners only that process holds. It therefore takes that process's session, read out of
  the store after the barrier the front process runs for a non-dispatched request.

`tests/vendored/sts_admin_console.js`'s `theTruststorePageAddsAndRemoves()` presses both
controls in a browser with a CA it mints — the Remove it presses is the one on the row
carrying THAT CA's subject, which is what catches a button rendered with the wrong
fingerprint — and asserts the truststore afterwards is exactly what it was before.

---

## Four reader slots and FOUR writer slots point INTO this module

`server.js` requires this module BEFORE `../ldap/ldap_server.js`,
`../scim/scim.js` and `../spiffe/spiffe_server.js`, so this module cannot require
any of them: the require would pull `/ldap`, `/scim` and `/spiffe` into the
express router ahead of every `/admin` route, and `GET /admin/sts-metadata` is built by
walking that router. So this module OFFERS slots and they fill them at their own
require time — `setDirectoryReader()`, `setGroupReader()`, `setDirectoryWriter()`,
`setSpiffeReader()`, `setScimReader()`. The pattern and its entry test are rule 3e
in the root `CLAUDE.md`; do not add another by analogy.

**`setLogoutReader()` is the sixth and `setCryptoReporter()` is the seventh**,
and both passed that test in BOTH directions rather than one — which is the bar
a proposal should be held to. The crypto one: a require from
`../mgmt-api/admin_api.js` (19) to `./crypto_metadata.js` (20a) would move that
page's route and `../tls/tls_server.js`'s three ahead of the management API's
own and of ldap, scim and spiffe; and a require from THIS file to it would close
a cycle, because it requires this one for the shell. `cryptoView(req)` is what
`admin_api.js` calls, and it carries the WHOLE report as one function so that
the page and the API cannot come to disagree about what this service's
cryptography is.

**`setGroupWriter()` IS THE TWELFTH SLOT (2026-09-06) AND IT IS THE SECOND
WRITER FROM `ldap_server.js`.** It carries `createGroup()` and
`addGroupMember()`, and it is a slot of its own rather than a third argument to
`setDirectoryWriter()`: that one carries ONE function and every caller of it
means "put a person in the directory", so widening it would have been a change
to a slot four callers already fill correctly in order to add something none of
them wants. It passes rule 3e's test both ways round for
`setDirectoryWriter()`'s reasons exactly — a require from here would close a
cycle, and one from `../mgmt-api/admin_api.js` (19) to `ldap_server.js` (21)
would move every `/ldap` route ahead of the management API's own.

**IT IS VALIDATED WHOLE**, for `setLogoutReader()`'s reason: a filler that
installed `createGroup` alone would leave the Add member control answering "no
directory is loaded" on a service whose directory plainly is. And it holds
NEITHER a delete NOR a remove, deliberately — taking a member out of a group is
`admin_rbac.js`'s `revoke()` for the two console roles and an `ldapmodify` or a
SCIM `PATCH` for every other group, and deleting a group is a SCIM `DELETE` or
an `ldapdelete`. Those doors exist and work; what did not exist anywhere but
SCIM and the raw socket was CREATION.

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
  future access token, ID Token, UserInfo response and SAML assertion — the tokens on
  `/admin/claims`, the UserInfo response on `/admin/userinfo-claims` since 2026-08-26
  and the assertions on `/admin/saml-attributes` since 2026-08-24, **three pages onto
  one store**: one `CLAIM_SETS`, one `setClaimSet()`, one `claimsAction()` taking the
  set ids the door carries, and one audit row per change whichever door made it.
  **`/admin/userinfo-claims` is the one of the three with no "nothing already issued
  changes" warning on it, and that is the whole argument for it being a page.** A
  UserInfo response is built on EVERY call rather than signed once, so a claim added
  there reaches a client that signed in an hour ago and has done nothing since — which
  is a thing to be able to demonstrate that no issued artefact can express. It is also
  the only claim set a CLIENT can add to: OpenID Connect Core section 5.5's `claims`
  request parameter names individual claims and they are answered off that person's
  entry under `ou=users`, which is why that page carries a section the other two do
  not — the vocabulary a request may use, the four layers of precedence, and a preview
  built by the functions `/oauth2/userinfo` itself calls.
  Custom claims are **additive**:
  the names this service sets itself are refused at configuration time, because an
  `exp` settable from a web form would produce tokens that fail to verify with nothing
  pointing back at the page — and that list is a JWT rule, not enforced for a SAML
  attribute, because `exp` collides with nothing in an assertion. The other half of
  each set puts **LDAP attributes** in
  those five, whose values come off the person's own entry rather than out of the form
  — see rule 3d, and note that the additive rule holds there too: the protocol's own
  claim wins, then a typed one, then the attribute. It deliberately does not invalidate assertions, tickets
  or credentials (nothing consults this service about those, so the button would be a
  lie), does not end sign-on sessions (`wsignout1.0` has cleanup to fan out), and does
  not touch refresh tokens' claims. Its `/admin/users` page lists every userid
  presented to this service in an interaction that SUCCEEDED, across all twelve
  families, and drills into one's sessions and the tokens issued on each. Two rules
  hold it up and both are easy to break by accident: **one row is one local name**
  (`alice`, `alice@REALM` and her `urn:uuid:<entryUUID>` are one identity — a
  subject is resolved through the directory's subject resolver rather than
  parsed, so a rename cannot silently split a user in two, and the retired
  `urn:sts:user:alice` is still read), and **a token is placed under a session by
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
  **IT WRITES SINCE 2026-09-06 AND UNTIL THEN IT DID NOT**, which is worth
  saying because of what the absence looked like: this page could report a
  dangling member, a claimed membership and the two groups that decide who may
  use the console, and could not create any of them — the only two doors onto a
  group in this directory were an `ldapadd` on the raw socket and
  `POST /scim/v2/Groups`. **Rule 7 could not have found that.** It is a parity
  check against `/admin-api`, and it is satisfied exactly when both are
  missing; what found it was a test that had to reach for SCIM to make fifty
  groups on a service whose own management API creates users five thousand at a
  time. There are two controls: **Create a group** on the LIST, below the table
  because the question this page is usually open to answer is what the
  directory holds; and **Add a member** on the DRILL-DOWN, because it needs a
  group in hand. A create lands the reader on the group it just made, since the
  next thing anybody does with a new group is put somebody in it and that
  control is only there. Both decide NOTHING: the name rule, the refusal of a
  group that is already there, what a membership value points at and the choice
  to write a dangling one rather than refuse it are all in `ldap_server.js`,
  reached through the twelfth slot — the same split `usersAction()` keeps with
  `createUser()`, and the reason `POST /admin-api/groups/{action}` can call
  straight into `groupsAction()` without a second reading of any of it. **A
  group made here still grants nothing**, which the page says at the moment
  somebody has just made one.
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

Eight things about it are decisions rather than defaults.

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

* **A BOX CARRIES THE IDENTIFIER A PROTOCOL WOULD HAVE TO PRESENT, AND NOT ONLY
  THE NAME SOMEBODY GAVE IT.** Added 2026-08-27, and it is the rule two
  paragraphs up read forwards: the label is the `cn` or the `appName` where
  there is one — what a person CALLED this thing — and until then a rectangle
  reading `Acme Web` said nowhere on the diagram what a request would have to
  carry to reach it. That string was in the tooltip, which is not a place a
  picture pasted into a ticket keeps. So `delegationNodeLook()` now returns a
  third line, `look.identifier`, and `delegation_map.js` draws it under the
  kind: `client_id: acme-web`, `AppliesTo: https://esb.example.com`,
  `SPN: HTTP/frontend.example.com@EXAMPLE.COM`. Four things about it were
  decided rather than fallen into:

  * **The list comes from `applications.identifiersOf()` and not from a walk of
    the entry here.** Which attribute holds a family's identifier is the
    PROTOCOLS table's statement and `identifierName` — what the specification
    spells it — is the SCHEMA row's; a picture with its own copy of either would
    disagree with the registry the first time a family was added. See
    `../common/CLAUDE.md`.
  * **They are grouped by VALUE, not by attribute**, because one string is
    commonly two families' identifier and the box has room for one line. An
    application declared for WS-Trust and SAML 2.0 carries
    `https://esb.example.com` on `wstrustAppliesTo` AND on `samlEntityId`, and
    naming the first would be picking one of two true answers —
    `entityID / AppliesTo: https://esb.example.com` is the whole fact.
  * **The one drawn is the one the ACT carried**, because that is the string on
    the line the reader is following. Where the act carried something no
    identifier attribute holds — the registry key of an entry made by hand, or
    an application reached through an audience it registered — the first
    declared identifier is drawn instead AND THE TOOLTIP SAYS SO in capitals,
    because a box quietly showing a name nothing in the picture presented is
    worse than one showing the key. Every name it answers to is in that tooltip
    either way.
  * **Where the label IS the identifier only the WORD is drawn** — `client_id`
    under `acme-web` — because the value is already on the box and a second line
    repeating it is one fact drawn twice. Where no family claims the name and it
    is already the label, there is no third line at all.

  It costs a line of height on every application box in EVERY picture drawn
  from `delegationLooks()` — this one, the three delegation drill-downs and
  `/admin/tokens/credential` — which is the point of that function rather than a
  side effect: one answer to "what is this box" is what keeps a party the same
  party on all five. And the identifier gets TWO wrapped lines where the kind
  gets one: a kind is a
  word from a closed list and an identifier is whatever a protocol allows, so at
  one line `entityID / AppliesTo: https://esb.example.com` was cut to
  `entityID / AppliesTo: https://…`, which keeps the half a reader already knew.
  The two party TABLES draw it under the label as well
  (`delegationNodeRow()`, `userNodeRow()`), so the table and the picture cannot
  come to say different things, and the key has a row of its own explaining that
  the two small lines are different sentences.

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

* **ONE SIGN-IN LINE PER PERSON, WITH THE FAMILIES LISTED ON IT — and the bug
  that forced it is the best example in this file of a picture lying without
  drawing anything wrong.** `user_graph.js` drew one `signed-in` line per
  protocol family somebody had authenticated with, on the argument that the
  families are what a reader looks for. But those lines JOIN THE SAME TWO BOXES,
  and an issuer line is a straight segment clipped to the boxes at its ends — so
  two of them are one segment computed twice, one path exactly over the other,
  one arrowhead exactly over the other. Their labels meanwhile were seated in
  separate ROWS by the paragraph above, precisely so that labels do not collide.
  `bob_end_user`'s page therefore showed ONE line saying `signed in / OAuth 2.0
  / OIDC / 1 time` in one place and `signed in / OAuth 2.0 / 2 times` in
  another: one relationship contradicting itself, when the truth is that he
  signed in once at the screen and was named in two RFC 8693 exchanges — which
  `oauth2.js` records as authentications under the bare `OAuth 2.0` family.

  So the fold is in the GRAPH, where it belongs: one line, `authentications` on
  it as a list of `{protocol, method, count}`, one entry per family and method,
  ordered by the family's `firstAt` — which `admin_stats.js` had always kept and
  began handing out for this — so the sign-in everything else rests on is read
  before the exchanges that quote it. `edgeLabelLines()` draws `signed in` and
  then the entries: `1 × OAuth 2.0 / OIDC (sign-in screen)`, `2 × OAuth 2.0
  (token exchange)`. The old `N times` line is GONE — a total across a sign-in
  and two exchanges is arithmetic rather than a fact, and it was the number that
  read as N sign-ins. It is one entry PER METHOD rather than per family for
  exactly that reason: `OAuth 2.0 ×2` is true and misleads, and the mechanism is
  the word that stops it. The sign-in line is the one label allowed more than
  three lines (`SIGNED_IN_ENTRIES`, then the rest are counted), which costs
  nothing: it absorbed lines that had three each.

  **AND THE RENDERER STILL FANS COINCIDENT ISSUER LINES, because the fold
  cannot reach every case.** A party can hold a line INTO the hexagon and
  another back OUT of it — a client that authenticated as itself is `signed in`
  one way and `issued for` the other; the middle tier of a Kerberos chain both
  authenticates and is issued to — and those are the same segment with the
  arrowheads at opposite ends. So the lines of one party are aimed at points
  spread `STS_FAN_SEP` apart about the issuer's centre. THE HEXAGON END is the
  end that spreads, because the label rows are in the band directly under it;
  they converge on the one party below. The aim is capped by the hexagon's own
  half-width, and `crossingPoint()` exists because a fanned ray no longer passes
  through that centre, so `boundaryPoint()` cannot scale it and the segment is
  clipped against the shape instead — get that wrong and you do not draw a wrong
  line, you draw a correct line that stops a few pixels short of the hexagon it
  points at. `fitLabels()` interpolates along the SAME aim, so a label still
  sits on the line it belongs to. Nothing in the renderer may assume the graph
  handed to it has folded anything.

  `tests/user_graph_signin.js` holds the fold AND the join — it records a
  sign-in and two exchanges through the real funnel, then asserts the graph has
  one line and the emitted SVG carries both entries, because either half is
  green on its own while the page is still wrong.
  `tests/delegation_map_bands.js`'s `TWICE` fixture holds the fan: two lines
  rather than one path drawn twice, both meeting the hexagon, one label on each.

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
    against this console's live headers (`tests/vendored/admin_api.js`), so there is no
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
  the hexagon, ONE PER PERSON with the protocol families listed on it — it was
  one line per family until 2026-08-26; see the bullet on the fold below) and
  `issued-for` (solid indigo, labelled with the exact grant). Neither takes a
  MODE colour, deliberately: amber and green are this console's judgement about
  impersonation versus delegation and an ordinary grant makes neither claim. **`delegationMapKey()` takes
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
* **AND SINCE 2026-09-02 THAT `reaches` LINE SAYS WHAT THE TOKEN MAY DO AT THE
  FAR END.** It carried who it is as, the mechanism and a credential count, and
  nothing about the PERMISSION — so the page next door drew a configured grant
  with its permission on it and this one drew the same relationship, actually
  exercised, and could not say what it was exercised FOR. `user_graph.js`'s
  `permissionsAddressedTo()` is the rule (rule 3p, argued there); three things
  about how it is DRAWN belong here.

  **`edge.permissions` IS TESTED, NOT `edge.relation`.** The delegation register
  emits the identical `reaches` relation for an ACT, which has no scope claim
  behind it and carries no such member — so an act line says nothing, rather
  than saying `default permissions` about a Kerberos ticket.

  **AN EMPTY ARRAY IS DRAWN AS `default permissions` AND NOT AS A BLANK.** A
  scope naming a resource by its client_id takes that value off the scope claim,
  so an empty list is the commonest state there is; drawing nothing would make
  it indistinguishable from a line this renderer has not been taught about,
  which is exactly the distinction `never asked for` makes on the configured
  picture.

  **IT IS THE SECOND EXCEPTION TO THE THREE-LINE LABEL CAP, and it is earned
  rather than granted by analogy with the first.** The sign-in line gets a
  fourth because it ABSORBED lines that used to be drawn on top of each other;
  this one gets a fourth because the permission is the answer to what the
  relationship IS, and the three already there — who it is as, the mechanism,
  the credential count — are each somebody's reason for reading the picture and
  none of them implies it. Four lines is 44px, which is what the sign-in line
  already occupies, so the bands measure it and nothing new was needed.

  The tooltip carries the list in FULL, because the label is capped at 26
  characters, and the scope claim beside it — a reader asking why a line says
  `default permissions` is asking what the token did carry. `userEdgeRow()`
  prints the same names uncapped, because the picture and the table under it are
  drawn from ONE graph and a reader comparing them must not find them
  disagreeing.
* **`issued-for` runs from the person where somebody else holds the credential
  and FROM THE HEXAGON where nobody does.** `client_credentials` is the case
  that settled it: the token is about the client itself, so the subject and the
  holder are one box, there is no person-to-application line to label, and the
  grey `issued to` line alone left the picture of a client credentials grant
  silent about which grant it was — on the page whose whole ask is that the
  grant be named. An X509-SVID with no audience is the same shape.
  **What that case ALSO lacked until 2026-09-02 is a `reaches` line at all**:
  the audience block sat inside the same `if (holder)` guard, so a
  machine-to-machine token drew its grant and said nothing about the API it was
  addressed to. It is drawn from the client's own box now — see the permissions
  bullet above, where that is the half that is not about a label.
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

## `/admin/federation/map` IS THE SECOND DRAWING, AND IT IS NOT THE FIRST ONE REUSED

Added 2026-08-26. A **DRILL-DOWN of `/admin/federation`** on exactly the terms
`/admin/delegation/map` is one of its own list page — no `NAV` row, `active` is
the federation page's path, `up` is
`upTo('/admin/federation', 'The picture', …)`, so the trail reads
`Admin console › Federation › The picture` and the way back carries the filter
the reader came in with. Rule 7a's test decides it the same way: a parameter
that merely FILTERS a list is not a drill-down, and this is not a filter, it is
a second VIEW of the same register.

**No form, so no operation on `/admin-api`** — rule 7 satisfied exactly as the
four delegation drill-downs and the credential lineage satisfy it.
`?format=json` is the graph, the relationships and the per-application counts;
`?format=svg` is the document alone.

### WHY IT EARNED A PAGE: THREE QUESTIONS A TABLE OF RELATIONSHIPS CANNOT HOLD

`/admin/federation` has one row per relationship and no row can say anything
about another. All three of these are facts about **two registers at once**:

* **How many applications are behind this partner, and which.** It is
  `appFederationRelationship` on entries under `ou=applications` pointing BACK
  at a relationship, so the relationship's own entry has never known.
* **How many people have come through it, PER APPLICATION.**
  `fedAuthentications` answered the first half; the split is
  `fedApplicationUse`, which exists because a partner shared by two
  applications turns one number into two different questions.
* **What an arriving foreign service provider actually meets** —
  `fedAuthnMechanism`, and the onward relationship when it says `federation`. A
  table can print the attribute; only a picture can show that the onward
  relationship is the one two rows down and that the two together are a BRIDGE.

### THE ARROW IS THE REQUEST, WHICH IS THE ONE THING THAT LOOKS BACKWARDS

Three bands: everything LEFT of the hexagon arrives wanting somebody signed in,
the hexagon is this trust realm, everything RIGHT is a party this service asks
to do the signing in. So an identity-provider-side relationship points INTO the
hexagon even though this service asserts outward — and that inversion is what
turns an identity broker into a single straight line instead of two arrows
leaving the same box in the same direction with nothing joining them.
`../federation/CLAUDE.md` argues it; the page says it in a note above the
picture and again in the key, because it is the one thing a reader will
otherwise read as a bug.

### AND IT IS A SEPARATE RENDERER, WHICH NEEDED THE ARGUMENT MADE

Reusing `delegation_map.render()` was the first thing tried, and its vocabulary
is close enough to be tempting — a hexagon for this service, a rectangle for an
application, labelled edges. Two things stop it, and the first is the
interesting one:

* **THAT RENDERER'S LAYOUT IS A DELIBERATE SPECIALISATION AND THE
  SPECIALISATION IS WRONG HERE.** It takes the hexagon OUT of dagre's layout
  and puts it in a band above, then puts every party on one centreline —
  because a delegation chain is a chain and the issuer is the box every line
  touches. This graph is the opposite shape: the hexagon is the MIDDLE RANK of
  a three-rank flow, and which side of it a box sits on is the entire claim.
  Hoisting it into a band deletes the thing being said.
* **AND ITS EDGE VOCABULARY IS DELEGATION'S.** `edgeLook()` there switches on
  `acts-for`, `issued`, `reaches` and colours by
  impersonation-versus-delegation — a judgement that means nothing about a
  federation relationship. Teaching it a second vocabulary makes one function
  that is really two, and the amber/green pairing a reader has learnt from
  `/admin/delegation` starts meaning something else on this page.

**What IS shared is the arithmetic and the palette**, and that is the half that
matters for the console looking assembled rather than designed:
`delegation_map.js` now exports `textWidth`, `wrapLabel` and `MAX_LABEL_CHARS`
beside `COLOURS`, `hexPath` and `personGlyph`. Two estimates of how wide
`HTTP/frontend.example.com` is would be two pictures whose boxes are different
sizes for one string, and `wrapLabel` in particular would be got wrong a second
time — it is not a word-wrap, it breaks after the characters an IDENTIFIER is
built out of, because there are no spaces in a service principal name.

**The name is `federation_diagram.js` and not `federation_map.js` on purpose**:
`../federation/federation_map.js` already exists and maps a partner's ATTRIBUTE
NAMES onto directory attributes. Two files with one name doing unrelated things
is a bug waiting for somebody to open the wrong one.

### FOUR SMALLER DECISIONS

* **THE SHAPE IS DECIDED FROM THE NODE'S KIND AND IS NOT THE CALLER'S TO
  CHANGE.** `options.resolve` may add an `href` and override a label — the
  console passes one so a box links to that party's page — but a caller that
  could set the shape would eventually draw a partner as a local box, which is
  the one distinction this picture is built to carry. A hexagon is an identity
  service, a rectangle is a party that consumes what one issues, and a DASHED
  outline means foreign: two independent properties rather than four shapes to
  memorise.
* **THE LABELS ARE GIVEN TO DAGRE RATHER THAN PLACED AFTERWARDS**, which is why
  this file has none of the lane-and-row assignment `delegation_map.js` needs.
  That file took the coordinate pass away from dagre, so dagre no longer knows
  where anything is and cannot reserve room; this one keeps dagre's
  coordinates, so it says how big each label is and dagre routes around it.
  `ranksep` is generous because that gap is where the labels live.
* **A PARTNER WITH TWO RELATIONSHIPS LINKS TO THE FIRST**, which is a real
  limitation and is the delegation picture's own: an SVG anchor wraps one shape
  and has one href. The table under the picture lists every relationship a
  partner has, which is where a reader with two goes.
* **THE PER-APPLICATION COUNTS DO NOT HAVE TO ADD UP, AND THE PAGE NAMES THE
  DIFFERENCE.** A relationship's own total counts every credential that crossed
  it; the rows count only the ones that named a configured application. Three
  ordinary things make the difference, none of them a fault, and on a page about
  counting a column that does not add up is worse than one that explains itself.
  `../federation/CLAUDE.md` carries the three.

**A guard exists and it is in THIS repository**: `tests/federation_map_bands.js`
asserts the bands, that the four relationship states are four distinguishable
strokes, that a broker is one arrow that keeps its counts, and the remainder
arithmetic. It is in `tests/` rather than the parent suite for the reason
`delegation_map_bands.js` is, and `tests/CLAUDE.md` records the six mutants it
was checked against.

---

## 8. THE GATE, AND WHY THE OLD SENTENCE IS QUALIFIED RATHER THAN DELETED

The console gate is UNCONDITIONAL — `mode.gatesConsole()`, where this read
`admin.authRequired` until that setting was removed on 2026-09-06. Every page
and every form under `/admin` needs a session and one of two roles. The rest of the numbered rules are
unchanged by it; this is the eighth because nothing it says was true before.

**AND SINCE 2026-09-06 THE SESSION IS THIS CONSOLE'S OWN, GOT THROUGH THE
AUTHORIZATION CODE FLOW.** That sentence used to read *a browser sign-on
session from `../authn/authn.js`*, and the console read the identity
provider's cookie directly. It is a RELYING PARTY now — `sts-admin-console`,
an ordinary entry under `ou=applications` — so a gated request with no console
session is answered with a redirect to `/oauth2/authorize`, and what comes back
is a code that buys an ID Token that establishes a session of the console's
own, in a cookie of its own (`sts_admin`). `common/oidc_rp.js` runs the
flow and argues it; four things about it are this file's.

* **THE ROLES DID NOT MOVE.** `gateStateFor()` still asks `admin_rbac.js`
  about the two directory groups, and the whole of 8a is untouched. What
  changed is where the NAME comes from: an ID Token this service issued and
  verified, rather than a session object read out of another module's store.
  Everything 8 says about what the gate proves — that somebody typed a name
  that holds a role — is unchanged, and so is `admin.openWhenEmpty`.
* **THE REALM RULE DID NOT MOVE EITHER, and it is why the flow is run in the
  DEFAULT realm.** `oidc_rp.js` wraps this surface's whole flow in
  `realms.run(DEFAULT_REALM, …)`, so the session it mints lands in the realm
  the roster lives in. A flow run in `acme` would mint a session this gate then
  refuses, which reads as a sign-in that silently did nothing.
* **`/admin/callback` IS THE ONE PATH UNDER `/admin` THIS GATE DOES NOT
  GUARD**, and it cannot be: somebody arriving there has no console session
  yet, which is what they are about to get. It is an EXEMPTION IN THE GATE and
  not a route registered above it, deliberately — the gate's whole mechanism is
  that everything below it is guarded by construction, and a route above it
  would break that invariant for every reader who came after.
* **`consoleSession()` STILL HAS EXACTLY ONE CALLER AND IT IS NO LONGER THE
  GATE.** That function reads the SIGN-ON session and the console now reports
  on it rather than being let in by it. `consoleRpSession()` is what the gate
  and every page read.
* **THIS CONSOLE AUTHENTICATES IN THE AMBIENT REALM SINCE 2026-09-11 AND ITS
  SESSION IS STILL THE DEFAULT REALM'S.** Those are two questions and this
  console used to answer both with "default", which cost the thing the move onto
  the code flow was supposed to buy: an authorization endpoint can only answer
  out of the realm it is reached in, so a console authorizing in the default
  realm and a portal authorizing in `acme` could not see each other's sign-on
  session — **two sign-ins for one person in one browser, in both directions,
  everywhere but the default realm.** The FLOW moved; the SESSION did not, which
  is what keeps one console session readable from every realm and the realm
  switcher switching without a prompt. The ROLE check did not move either: the
  roster is still the default realm's `ou=groups`, so a realm nobody could
  create still makes nobody an administrator. `common/oidc_rp.js`'s surface
  table argues the split, `sts-admin-console` is seeded in every realm now
  because the ambient authorization server has to be able to find the client,
  and `tests/cross_surface_sso.js` pins the partitions.
* **AND THERE IS A WAY OUT SINCE 2026-09-06: `POST /admin/signout`**, the Sign
  out button in the shell. It is the second exemption in this gate and the
  section below argues it.
* **AND A THIRD SINCE 2026-09-10: `POST /admin/signals/receive`.** This console
  is a Shared Signals RECEIVER now (see *Signals received*, below), and that is
  where its own stream's Security Event Tokens are POSTed. A push is a
  server-to-server request and carries no console session **by construction**
  — it must not present a browser's credentials, which is the same thing the
  OIDC back channel says about itself — so the gate could only ever refuse it,
  and the symptom would be an inbox page that stays empty while the stream's
  log fills with 401s.

  **IT IS NOT A HOLE, AND THE REASON IS NOT "IT IS ONLY A READ" — IT IS A
  WRITE.** What guards it is the stream's own `delivery.authorization_header`:
  a bearer token minted per stream and per start, compared in constant time,
  that nothing but this service's own transmitter is ever given. The endpoint
  refuses without it, refuses a SET addressed to another audience with
  `invalid_audience`, and records both. **The check moved rather than went
  away, and that is the test a fourth exemption has to pass.**

  It is exempt from the CSRF check too, which is the half `/admin/signout`
  deliberately does not take: a CSRF token defends a form submitted by a
  browser holding a cookie, and there is neither here. It is an exemption IN
  the gate for `/admin/callback`'s reason.

**WHAT THE MOVE COST is one thing and it is worth naming**: the four `details`
the old redirect handed the sign-in screen — what you are signing in to, the
page you asked for, that two groups decide access, and that it is the default
realm's `ou=groups` that decides — have no equivalent in an authorization
request, which carries a CLIENT rather than a sentence. A person now sees
`Admin console` and the scopes it asked for, which is what every other
application in this registry gets. The two sentences that were load-bearing
survive on the 403 for somebody holding no role, which is the page they
actually reach and the page where that sentence is actionable.

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
REALM"**, and this paragraph said the second until 2026-08-25. (Since
2026-09-14 the ROSTER is the one of the realm the session was signed in through,
confined to that realm — 8d. The session store is unchanged.) The embedded
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

## 8c. THE SIGN OUT BUTTON, AND THE THREE THINGS IT COST (2026-09-06)

Every page of this console draws a **Sign out** form in its shell, and it posts
to `POST /admin/signout`. It is drawn only when somebody is signed in — a button
that signs nobody out is a control whose only outcome is a refusal, which is the
same test `newUserPage()` applies to a form on a process with no directory.

**IT SAT BARE BESIDE REFRESH UNTIL 2026-09-10 AND IS THE SECOND ROW OF THE
ACCOUNT MENU NOW.** Nothing below changed with the move — it is the same form,
the same POST, the same CSRF token, the same exemption in the gate — and 8c-iii
argues the menu. What did change is that a test has to OPEN the menu before it
can press the button, because a control inside a closed `<details>` is not
displayed.

**A FORM AND NOT A LINK, WHICH IS THE OPPOSITE OF `refreshLink()` BESIDE IT.**
The two are worth reading together. A refresh is a GET of the page you are on:
safe, repeatable, and something a prefetcher may follow for nothing. A sign-out
CHANGES STATE, and a GET that ends a session is one a link prefetcher, a mail
scanner or a `<link rel=prefetch>` fires without anybody clicking. So it is a
POST carrying this session's CSRF token, which `withCsrf()` puts into it like
every other form here.

**IT ENDS TWO SESSIONS AND THAT IS THE WHOLE DESIGN.** The console's own
relying-party session goes first, and then the SIGN-ON session it was derived
from. Ending only the console's would be a Sign out button that does not sign
anybody out: the next request runs the authorization code flow, meets the
sign-on session that is still live, gets an ID Token with nothing typed, and
draws the console again. `dropSession()` then cascades to everything else
derived from that sign-on session — the user portal included — and **the page
says so**, because a sign-out that quietly reaches further than its label is the
same defect as one that does not reach far enough. It is not `/logout`: that
ends everything an identity holds in every protocol, it is linked from this
console in half a dozen places, and it refuses when there is no sign-on session
to act on — which would leave somebody holding a live console session looking at
a 401 saying there is nobody to sign out.

Three things it cost, and each is the kind that goes wrong quietly:

1. **IT IS THE ONE NON-GET ON THIS CONSOLE THAT DOES NOT NEED `Admin Write`.**
   The gate's rule is "anything that is not a read needs Write", and under it
   every reader — and everybody the roles refuse, who still gets a refusal page
   drawn in this shell with the button on it — would be refused their own
   sign-out. Ending your own session is the one act here that needs no
   permission, because the alternative is a console somebody can enter and
   cannot leave. **The CSRF check is NOT skipped with it**: a sign-out fired
   from another site is the classic "harmless" CSRF that is not, so it runs in
   front of the exemption rather than after it. The role and the policy are what
   is skipped, and only those.
2. **IT MIRRORS NO `/admin-api` OPERATION, WHICH IS A DEPARTURE FROM RULE 7.**
   That rule exists so a program can drive every control here; this control ends
   the session of the browser that pressed it, and `/admin-api` authenticates
   with a token rather than a session and is
   sessionless, so an operation there would have nothing to end.
   `tests/vendored/sts_admin_console.js` carries the exemption — in
   `NOT_A_CONSOLE_CONTROL`, with that sentence in it — so the check that reads
   the API's index for "every console POST reaches a mirrored route" does not go
   quietly amber.
3. **`authn.clearSessionCookie()` HAD TO LEARN TWO THINGS**, and the second was
   a live bug found by writing this: it ignored the cookie NAME it was already
   being passed by `oidc_rp.js`'s `endSessionFor()` — so a hosted surface
   signing somebody out cleared the sign-on cookie and left its own in place —
   and it SET the header where it now appends, because a sign-out here clears
   two cookies on one response and `res.set()` threw the first away.
   `authn/CLAUDE.md` carries it.

The button is pressed by the console test as the LAST thing it does, which is a
dependency and not a preference: pressing it closes the console against that
run's session. What it asserts is where the browser stops afterwards — the
sign-in screen, and not the console — because that, and nothing on the page it
lands on, is what tells the two-session sign-out from the one-session one.

### 8c-iii. THE ACCOUNT MENU (2026-09-10)

**THE HEAD ROW HOLDS TWO CONTROLS AND ONE OF THEM IS NOW A MENU.** Refresh is
still a link beside the heading; the Sign out form moved into a drop-down whose
summary is the username and whose first row is a link to this person's own
account in the **user portal**.

**WHAT IT IS FOR IS THE LINK RATHER THAN THE MENU.** `/portal` is where an
administrator changes their OWN password, enrols their OWN authenticator app,
removes their OWN security key and sees which applications they can be signed in
to — and until now this console named that surface in prose on a page or two and
linked it from nowhere in its shell, so the way there was to know the path. The
menu exists because the link needed somewhere to live: these two are the only
controls on this console that are about the READER, and everything else on every
page here changes what some protocol endpoint does for somebody else.

**IT IS A `<details>`, WHICH IS TO SAY IT IS NOT A SCRIPT.** This console is
`script-src 'none'` on every page but `/admin/api-explorer`, and the test for an
exception is that the page CANNOT work without one — which a menu plainly can.
It is the same answer the collapsible prose got, and the root `CLAUDE.md` lists
it beside the other refusals: **"it is a menu and menus have scripts" is not an
argument**, and neither is "the page next door relaxes the policy".

**WHAT THAT COSTS IS SAID OUT LOUD**: an open `<details>` does not close when
you click elsewhere on the page, because closing it would take a listener on the
document. It closes on a second click of the summary and is closed on every page
load, since nothing remembers it. That is the trade the two pictures made when
they lost pan and zoom.

**THE PORTAL LINK IS THE DEFAULT REALM'S IN EVERY REALM, AND IT IS THE ONLY
PART OF THIS THAT CAN BE WRONG WHILE LOOKING RIGHT.** The console's session is
the default realm's whichever realm the page is read in — `consoleRpSession()`,
and the rule that the role roster lives in one realm — while `/portal` runs in
the AMBIENT one. So a link written `/portal` is rewritten by `app.js` to
`/realm/<id>/portal` on a realm's console page, which is a portal this person
holds no session in: following it runs the code flow in that realm, meets
nothing, and asks them to sign in again as an account that is not theirs.
`realmRoot()` takes the prefix back off and the href is ABSOLUTE, which is the
one form that rewrite cannot prefix again. `theAccountMenuIsTheReaderSOwnCorner()`
in `tests/vendored/sts_admin_console.js` asserts it in the realm that run
creates — and asserts that **Refresh beside it still carries the prefix**, so
the check cannot pass because the rewrite stopped working.

**ONE MEASUREMENT IS WORTH KEEPING, BECAUSE THE OBVIOUS ASSERTION IS WRONG.** A
closed `<details>` in Chrome does not hide its children with `display:none` — it
uses `content-visibility:hidden` — so the panel of a CLOSED menu reports a
non-null `offsetParent` and a bounding box 113px tall. Measured while writing
that test: `{open:false, offsetParent:true, rects:1, h:113}`. The signal that
tells the truth is `checkVisibility({contentVisibilityAuto:true,
visibilityProperty:true})`, which answers false. A check written the obvious way
fails against a menu that is behaving perfectly.

### 8c-ii. THE SHELL WITH NOBODY IN IT (2026-09-10)

**THE SIGN-OUT PAGE IS DRAWN BY THE SAME `page()` AS EVERY OTHER, AND FOR AN
HOUR AFTER THE BUTTON SHIPPED IT DREW THE WHOLE CONSOLE AROUND IT.** The gate
state is read again before it is drawn, which is right and is what takes the
button out of the corner — and everything ELSE the shell puts on a page went on
being drawn: the navigation column, the realm switcher inside it, and Refresh.

That is the same test the button already passed, applied one control further
out. **A control whose only possible outcome is a refusal does not belong on the
page**, and in this state every one of those is:

* **the navigation column** — forty links, every one a console page behind the
  gate, so every one of them answers a redirect to the sign-in screen. `nav`
  goes with the `<aside>` rather than being emptied, because `.main` is
  `flex:1 1 32rem` and the card simply takes the width; a column keeping its two
  brand lines would be an inch of white space saying which REALM some absent
  pages are about.
* **the realm switcher in it**, which is worse than the links and is why this is
  not cosmetic: it is a FORM, so using it POSTed to a console that no longer had
  a session for it.
* **Refresh**, whose href is the page you are on — and this page is the answer to
  a POST, so following it is a GET of `/admin/signout`, which has no GET: the
  gate sees no session and starts a fresh sign-in. A control labelled *load this
  page again* that instead signs you in is worse than one that is missing.
* **and the banner acquired a FOURTH state rather than losing one.**
  `gateBanner()` had three and none of them was "nobody is signed in", so this
  page fell through to the last and read **"Signed in as `(nobody)`, holding no
  console role. This is a READ-ONLY view"** — directly above a page whose whole
  text is that you have just signed out. The navigation goes and the SENTENCE
  stays, which is the difference between a control that cannot work and a fact
  about why.

**THREE PAGES ARE DRAWN IN THIS STATE AND ONLY ONE OF THEM IS ABOUT IT**: the
sign-out confirmation, the OIDC callback's refusal, and the 401 a form POSTed
without a session gets. The other two had the same shell and the same empty
breadcrumb leaf — `Admin console ›` with nothing after it, because `active` is
`''` on a page that is not in `NAV` — which is now the page's title.

**WHAT DECIDES IT IS THE GATE AND NOT THE SESSION.** `gate.enforced &&
!gate.session`, in that order: a service with the console gate off has no
session either and every page in that nav is reachable. `sideColumn()`,
`refreshLink()` and `gateBanner()` each apply it, and
`tests/vendored/sts_admin_console.js` asserts the column's absence beside the
button's, off the survey's own `nav` count — with the count on the page BEFORE
the sign-out asserted too, because a check that only reads zero passes just as
well on a console that has lost its nav everywhere.

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

**THE CONSOLE IS OPEN UNTIL THE BOOTSTRAP ADMINISTRATOR SIGNS IN (2026-09-13).**
This rule replaced *the empty roster opens*. That rule had a trap: the first
grant closed the console for everybody. Somebody who granted themselves only
Admin Read then had a console on which they could change nothing. rcbj's
design:

* `seedBootstrapAdministrator()` runs from `server.js` inside the default realm,
  before `credentials.bootstrap()`. It creates `admin.bootstrapUsername` if
  absent, marks it `stsBootstrapAdministrator`, and grants both roles
  (`via: 'bootstrap'`). It sets `pwdReset: TRUE` **only on an account it
  created**, so a restart does not force a password change again, and neither
  does an existing `admin`.
* **The window is open until `stsConsoleClaimedAt` is written**, which
  `noteConsoleSignIn()` does at that account's first console sign-in, from a
  session derived in the default realm. It is a directory attribute and not a
  process flag, so it persists wherever the directory does.
* **A roster that already named somebody else closes the window at seed time.**
  An upgraded deployment with administrators already in place must not re-open.
* **Undeletable, not un-demotable.** `deletePerson()` and the LDAP delete and
  modifyDN handlers refuse that entry (`STS-LDAP-0077`), and SCIM turns the
  refusal into a 403. Revoking its roles is still allowed. The account is the
  way in, and the roster stays an operator's to edit.
* **`rolesOf()` keeps the older rule where nothing was seeded**
  (`bootstrap.seeded` false), which is every in-process test that never runs
  `server.js`. Those tests still see *an empty roster opens*.

Why this and not "the first person to sign in gets both roles": every
development test job signs in under a random username. The first of them would
have become the administrator, and the next job would have been refused. No job
signs in as `admin`, so the window stays open for the whole suite.
`tests/admin_bootstrap.js` holds it (`authn/CLAUDE.md` has the forced password
change). **"No members" and "no group at all" are deliberately the same state** —
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

## 8d. A TRUST REALM HAS ADMINISTRATORS OF ITS OWN (2026-09-14, #32)

**THIS REVERSED A DOCUMENTED NON-GOAL**, *give a trust realm its own
administrator*, whose argument was that a per-realm roster would let anybody who
can create a realm administer the service. That argument was about what a
realm's roster could REACH, and it is answered by narrowing the reach rather
than by refusing the roster. rcbj's four decisions are the design:

| Question | Answer |
|---|---|
| Who is on a realm's roster | the realm's own `cn=admin-read` and `cn=admin-write`, and a seeded `admin` with a forced password change |
| What a realm administrator reaches | their realm; service pages, actions and settings are hidden and refused |
| How the plain `/admin` and `/portal` pick a realm | a chooser — a list in development, a text box in product |
| The machine door | a realm-scoped `sts-management-api` token per realm |

**THE DEFAULT REALM'S ROSTER IS STILL THE SERVICE ROSTER** and administers every
realm exactly as before, which rcbj stated as a requirement in its own right.

### Two authorities, decided in `gateStateFor()` from the SESSION

`admin-core/admin_views.js`'s `gateStateFor()` reads the realm the session was
SIGNED IN THROUGH (`session.derivedFromRealm`, empty meaning the default) and
asks THAT realm's roster: `authority` is `service` for the default realm and
`realm` otherwise, and `identityRealm` names it. The name alone decides nothing
— `admin` in `acme` and `admin` in the default realm are two people, asked two
rosters, and `tests/realm_administrators.js` holds that collision. The console's
session still lives in the default realm's partition, as 8 argues; only the
roster it is asked against moved.

A realm authority reading ANOTHER realm is `outsideRealm`: every role is zeroed
and the gate answers 403 `outside_realm` (`STS-ADMIN-0786`) with a link to their
own realm's console, before the role check, so the page says the true reason.

### `admin_scope.js` IS THE ONE PLACE THE LINE IS DRAWN

For the console AND `/admin-api`, so rule 7 cannot come apart here. Three
tables, each refused only to a realm authority (`refusalFor()`):

* **`SERVICE_PAGES`** — persistence, database, encryption, secrets, debugger,
  TLS (and its truststore), the LDAP service page, the API explorer. Hidden from
  the nav and `consoleGuide()` (`pageVisible()`), refused whatever the method
  (`STS-ADMIN-0787`). **KERBEROS LEFT THIS LIST ON 2026-09-15 (#33)**: a trust
  realm has a Kerberos realm, a principal database and keys of its own, so
  `/admin/kerberos` and `/admin/kerberos/principals` show that realm's and a
  realm administrator manages them. What is still the process's is refused per
  SETTING below.
* **`SERVICE_ACTIONS`** — creating or removing a realm, or naming another realm
  on `/admin/realms`; `build-root` or a `*` scope on `/admin/pki`; exporting the
  `tls-server` key. `REALM_READS` refuses `/admin/realms?realm=<another>`.
* **SETTINGS** — every `perProcess` row (a realm write of one lands PROCESS-WIDE
  in `config.setOverride()`, so a Save on a realm's page would change the
  process), the `admin.`, `adminApi.`, `realms.`, `workers.`, `persistence.`,
  `debugger.`, `tls.`, `keys.` prefixes, `security.passwordHash*`, and a short
  key list (`global.mode`, `global.publicBaseUrl`, listener and file settings).
  Any field of a body naming one is refused (`STS-ADMIN-0788`). **The `krb5.`
  PREFIX BECAME SIX KEYS on 2026-09-15**, for the reason Kerberos left
  `SERVICE_PAGES`: the ten rows a realm's principal database is built from are
  the realm administrator's, and what stays the service's is the two sockets
  (`krb5.kdcPort`, `krb5.servicePort`) and the development-mode trust
  (`krb5.trustedRealm` and its three).
  **The `admin.*` and `adminApi.*` gate settings were made `perProcess` for the
  same reason** — a realm override of the console's own groups would otherwise
  be a way round the roster.

**A NEW SERVICE PAGE OWES A ROW IN `SERVICE_PAGES`.** Nothing detects a missing
one; the page is simply visible and reachable to every realm administrator.

### The bootstrap `admin`, per realm

`admin_rbac.seedBootstrapAdministrator(realmId)` runs for every realm at startup
(`server.js`) and when a realm is created (`realmsAction()`), with the same
rules as the default realm's (8a): both roles, `pwdReset` on an account it
created, and a window open until THAT account signs in through its realm —
`noteConsoleSignIn()` closes the window of `session.derivedFromRealm`. While a
realm's window is open, anybody signed in through that realm holds both of that
realm's roles, and nothing outside it. A realm whose roster already named
somebody seeds with its window closed. **In product mode a create generates the
password** (`STS-ADMIN-0789` if it cannot), and `POST /admin/realms` answers a
one-time page carrying it rather than a redirect, for `/admin/users/new`'s
reason. The account is protected from deletion in its realm
(`isBootstrapAdministratorEntry()`).

### The realm chooser, `common/realm_chooser.js`

A GET of exactly `/admin` or `/portal`, in the default realm, with no session,
while realms are defined, draws a chooser (`STS-ADMIN-0790` / `STS-PORTAL-0074`
for an unknown id). `?realm=<id>` 303s to that realm's surface, BUILT from the
registry and never echoed; `?realm=default` signs in where it is. A deep link is
never asked. **`mode.listsRealmsBeforeSignIn()`** decides list versus text box,
because listing every tenant's name to anonymous readers is a development
convenience. **Every owned job signs in through `?realm=default`** since the
suite nearly always has realms — the doors are named constants in each job.

### What it does not do yet

The API explorer mints only the SERVICE token, so it is a service page. The LDAP
socket's write authorization recognises a realm administrator in their realm
(`ldap_server.js`'s `boundDnIsRealmAdministrator()`), and certificate
enrollment (`common/cert_enrollment.js`'s `adminFor()` and `sessionIsAdmin()`)
asks the ambient realm's roster after the service's; no other protocol door was
widened, and SCIM changed only the wording of the bootstrap account's delete
refusal. `tests/realm_administrators.js` holds the in-process half
(ten mutants, all caught); `sts_realm_administrators.js` over HTTP is not
written yet.

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
  service IS; it is on `/admin/wstrust`, which is where it is SET — it was
  `/admin/config` under WS-Trust until the settings moved to their protocols'
  pages on 2026-08-27; and it is in this line's tooltip, so that somebody who had learnt to
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
* **It is a FORM, and it must stay one, because the page it is on runs no
  script.** `script-src 'none'` (common/app.js) is what makes the whole
  js/reflected-xss family moot here rather than merely unlikely. (That sentence
  said "this console runs no script" until 2026-09-09, when the API explorer
  moved in and became the ONE page here with one — see *The API explorer is a
  page of this console now* below. The switcher is drawn on that page too and
  is still a form there, because a control that worked differently on one page
  out of sixty is worse than one that works the same way everywhere.) A `<select>` that navigated on
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
  in `NAV`, so it is not one of the console's pages and `tests/vendored/admin_api.js`'s
  page parity does not ask for a `/admin-api` operation mirroring it.
* **A SETTINGS FORM WRITES THE REALM IT IS READ IN, wherever it is drawn.**
  `config.setOverride()` lands on the ambient realm — see rule 3m — so the Save
  button on `/admin/kerberos` under a realm prefix changes THAT realm's
  Kerberos settings, and `/admin/config`, `/admin/token-lifetimes` and the
  other nineteen do the same without knowing it. Nothing about the 2026-08-27
  move touched this: the forms multiplied and the function under them did not. That is why the switcher
  says so on every page: a form that read one realm and wrote another is the
  surprise this arrangement exists to avoid, and the only way a reader can tell
  which realm they are in is if it is named where they are looking.
* **THE TWO ROLES ARE PER REALM SINCE 2026-09-14, AND THE DEFAULT REALM'S ARE
  THE SERVICE ROSTER.** This bullet said *there is deliberately no per-realm
  administrator; if there is ever to be one, it is a per-realm container in the
  directory rather than a second store here* — and that is what was built: each
  realm's own `cn=admin-read` and `cn=admin-write`, no second store, confined to
  the realm by `admin_scope.js`. `/admin/rbac` under a realm prefix is that
  realm's roster. 8d argues it.
* **THE CONSOLE'S SESSION IS STILL THE DEFAULT REALM'S, AND WHICH ROSTER IT IS
  ASKED IS THE REALM IT WAS SIGNED IN THROUGH (8d).** The paragraph below
  predates both that and the 2026-09-11 move of the flow to the ambient realm,
  and is kept for its account of `consoleSession()`.
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

---

## `/admin/delegation` HAS A FORM NOW, AND THAT REVERSES A DECISION THIS FILE ARGUED

Added 2026-09-01. That route's header said **"NO FORM, AND THAT IS A DECISION"**
at length, and it was right about what it was talking about: everything on the
page WAS an observation — an act happened or it did not, and a control that let
somebody TYPE a chain would put invented rows in a table whose whole worth is
that its rows are what actually happened. That sentence is untouched and still
governs the acts table, the chains and the picture drawn from them. None of them
has a control and none ever will.

**What is new is a SECOND REGISTER on the same page**, and it is configuration
rather than observation: a delegated permission is something somebody DECIDES,
like a redirect URI or a federation relationship, and configuration with no way
to type it is configuration only an `ldapmodify` can reach. So the rule the old
header states is intact and sharper: **nothing that records what HAPPENED has a
control, and the thing that records what is ALLOWED is nothing but controls.**
The two are drawn under headings that say which is which, because a reader who
confused them would draw exactly the wrong conclusion from the difference
between them — which is the most useful thing on the page.

**FIVE ACTIONS, AND THEY ARE THIN ON PURPOSE.** `PERMISSION_ACTIONS` is built
from the switch rather than typed, for `APPLICATION_ACTIONS`'s reason: this
repository's own `tests/vendored/admin_api.js` READS the refusal sentence to
check that every console action has an `/admin-api` operation, so a list short by
one turns the parity check off for that action. Each action calls
`common/app_permissions.js`, which calls `applications.updateApplication()`,
which is where the RULES are — so this form, `POST /admin-api/permissions/…` and
the generic attribute editor on `/admin/applications` all go through one
implementation of *a permission must be defined before it can be granted*.

**THE KERBEROS SECTION'S HEADING AND ITS FIRST PARAGRAPH CHANGED, and the change
is recorded rather than made quietly.** It read *this half is configuration
rather than history, and it is Kerberos only*, which stopped being true the
moment the register above it existed. What is still true is the sentence
underneath: **Kerberos is the one family here that polices delegation IN THE
ACT**, on every request, whatever anything is set to. The permissions above are
policy this service was configured with and refuse only when
`oauth2.delegatedPermissionsEnforced` is set.

## EVERY LIST ON `/admin/delegation` IS PAGED AT TEN, AND THAT IS A NUMBER ABOUT THE PAGE

Changed 2026-09-01, when the configured register made it seven tables. Before
that this page had ONE paged list — the acts, at `DEFAULT_PER_PAGE`, fifty —
and six that drew every row they had.

`DELEGATION_PER_PAGE` is ten and it is deliberately a tenth of the
console-wide default. **The number is a property of the PAGE and not of the
data.** Every other page in this console is one list under one heading, where
fifty rows is a table somebody scrolls; this one is seven — the acts, the
chains, the permissions applications expose, the grants, the two Kerberos
policy tables and the mechanism catalogue — with several screens of folded
prose between them. Fifty rows apiece is a document tens of thousands of pixels
long in which the seventh heading is reachable only by dragging the scrollbar.
Ten keeps each section's control within a screen of its heading.

**Four things about it are decisions rather than mechanics.**

* **They share one `per` and each has a page parameter of its own** —
  `?page=`, `?chainsPage=`, `?permissionsPage=`, `?grantsPage=`, `?pairsPage=`,
  `?flagsPage=`, `?mechanismsPage=`. That is the arrangement the drill-downs
  already have and `perPageForm()` argues; what is new is that seven controls
  now share one page, so every one of them takes `pageParamsOf(req.query)` and
  overrides only its own name. **The acts nav used to carry five NAMED keys and
  now carries the whole query**, because a hand-written set is the thing that
  comes to be short by one — and short by one here means `next ›` on the acts
  table silently resetting the grants table and clearing the search that
  produced it, three screens further down where nobody is looking.
* **The mechanism catalogue is paged although it holds eight rows and will draw
  no control until it holds eleven.** It is read off `delegation.TYPES` rather
  than written down, so its length is decided by somebody adding a ninth
  mechanism who has no reason to be reading this page's layout. One line makes
  the cap true by construction instead of true today.
* **The two chooser panes were left at twenty and that is not an oversight.**
  `CHOOSER_HITS` is a scrolling pane with `max-height:13.5em`, so it does not
  lengthen the page at all, and it already pages. The rule this section applies
  is about tables that grow the document.
* **`?format=json` still carries every list WHOLE**, and the acts are the
  exception they always were. Everything else — `chains`, `policy` and the
  whole of `allowed` — is derived from something already bounded, and
  `GET /admin-api/permissions` answers with that same register under its own
  name; a caller made to walk seven pagings would be paying for this page's
  layout. What the reply gained is `allowed.filter` and `allowed.paging`, so
  the difference between what the browser was shown and what the caller gets is
  REPORTED rather than silent. `permissionsListState()` is one pure function
  called by the section and by the reply, for exactly that reason.

**AND THE TWO TABLES OF THE CONFIGURED REGISTER HAVE A SEARCH EACH**, `permq`
and `grantq`, through `sectionSearchForm()`. It is deliberately NOT
`chooserPane()`: that control searches for ONE THING and every hit is a link
away from the page, and this one narrows a table the reader is going to stay and
read — one function with a mode flag deciding which it was would be two controls
wearing one name. The fragment trick is the same and for the same reason
(`script-src 'none'`, so nothing can restore a scroll offset after a GET form's
reload).

**The two boxes answer differently and that is the interesting half.** A
permission has ONE application in it, so `permq` searches the application that
EXPOSES it and there is no second column it could have meant. A grant has TWO,
so `grantq` searches BOTH ENDS — the acts table's own text box makes the same
argument: a reader arrives holding one application name and does not know, and
should not have to guess, which column it will turn up in. Both match on the
display NAME and on the IDENTIFIER, because half the entries in this registry
have a name that is not their identifier and a reader pastes whichever one the
page showed them last.

## THE `Grant a permission` FORM MOVED TO THE APPLICATION'S OWN PAGE

Moved 2026-09-01, and **the reason is the shape of the control rather than the
length of the page it was on.**

On `/admin/delegation` it was two `<select>`s — every application beside every
permission — and the reader had to get BOTH right. That is the one write in this
whole register where choosing the wrong option still SUCCEEDS and stays
plausible: a grant is a value on the CLIENT's entry, so writing it to the
resource instead produces a row that resolves in both directions, reads
correctly on the delegation page's own grants table, and is wrong only at the
token endpoint, later, to somebody else.
`tests/vendored/sts_delegated_permissions_example.js` asserts exactly that pair
of halves landing on the right entries, which is how much care the distinction
is worth.

On `/admin/applications?application=…` the first select does not exist: the
client is the entry the reader is standing on, and the page cannot be reached
without having named it. **A control that could be half wrong became one that
cannot be.**

**`revoke-permission` IS DRAWN IN BOTH PLACES and that is not a leftover.** It
is a ROW BUTTON, so its two halves are the row it sits on and neither can be got
wrong — which is exactly what was wrong with the grant form's two selects. The
register lists every grant in the service and somebody tidying it up should not
have to open five application pages; the application's own list is the read-back
of the grant just made, and a table with no way to undo the write above it is
half a control.

**IT POSTS TO `/admin/delegation` AND THAT IS THE WHOLE TRICK.** A
`grant-permission` on the applications handler would mean a sixth entry in
`APPLICATION_ACTIONS`, and rule 7's parity check reads that list off the
handler's refusal sentence — so it would then want a
`POST /admin-api/applications/grant-permission` beside the
`POST /admin-api/permissions/grant-permission` that already exists, which is two
API operations for one write. **Moving a FORM is not moving an ACTION.**
`PERMISSION_ACTIONS` is unchanged, all five, and every mirror with it. The
settings forms on twenty-one pages already do this: drawn where the setting
belongs, posted to `/admin/config`, returned to the page the form was on.

`permissionsReturnTo()` is that return and it is `configReturnTo()`'s argument
made a second time. **`from` is a NAME and not a URL**: it is matched against the
two paths this file wrote, and the application page's destination is REBUILT
from `client` — which the action has just validated as an identifier in the
registry — rather than echoed. A redirect target taken out of a request body is
an open redirect, and one carrying a newline is a header injection. The worst a
hand-written `from` can reach is the delegation page.

**What is drawn beside it is what makes it a section rather than a stray
button.** `applicationPermissionsSection()` shows what the application HOLDS
(with a Revoke on each row, posting the same way) and what it EXPOSES, both
paged at ten. A write whose result you cannot see on the page that took it is a
write you have to go somewhere else to trust. **The exposing half is read-only
here on purpose**: giving an application a base URI and defining permissions on
it is configuration of the RESOURCE, and those two forms stay on
`/admin/delegation`, where the reader is looking at the register rather than at
one entry.

**Three things are left OUT of the select rather than refused by it**, because
an option whose only outcome is a refusal is a control that can only fail: this
application's own permissions (the token would be audienced to itself, which is
what an ID Token already is, and `app_permissions.js` refuses it however it
arrives), the ones it already holds (granting a value an entry carries writes
nothing), and any with no identifier (nothing can ever ask for one).

**And the row buttons of the register grew a `back`.** It cost nothing while
`/admin/delegation` drew every row it had; with seven paged tables and two
searches it is the difference between a Revoke that answers where you were
standing and one that throws you to page 1 of an unfiltered list three screens
up. One opaque field, rebuilt through `listViewOf()`'s whitelist, for
`carryBack`'s reason on `/admin/applications`.

## `/admin/delegation/allowed` — THE THIRD PICTURE, AND WHY IT IS NOT A MODE OF THE FIRST

A drill-down of `/admin/delegation` exactly as `/admin/delegation/map` is: no
`NAV` row, an `up`, the delegation page's own tab active, and rule 7a's test
answering the same way — this is a second VIEW of a register on that page rather
than a filter over one.

**DRAWING CONFIGURED GRANTS AND RECORDED ACTS ON ONE CANVAS WAS THE OBVIOUS
THING AND IT IS WRONG.** An act has three layers and the first of them is a
PERSON — a stick figure, somebody on whose behalf something happened. A
permission has nobody in it at all: it says *this client may reach that API as
whoever is signed in*, and there is no whoever yet. One canvas would put a
drawing of what MAY happen and a drawing of what DID happen in one frame with no
way to tell a box that has been used from a box that has merely been described,
which is the single distinction both pictures exist to make. They are
cross-linked in both directions instead, and each says in its first paragraph
what the other one is.

**IT COSTS ONE NEW RELATION AND NOTHING ELSE.** The graph arrives in
`delegation.graph()`'s shape, so `delegation_map.js` draws it with the same
`delegationLooks()` resolver, the same shapes and the same palette. What it draws
differently comes off `may-reach` in `edgeLook()`, `edgeLabelLines()` and
`edgeTitle()` — the third relation a caller has added after `user_graph.js`'s
two, and like both of those it takes **no mode colour**: amber and green are this
console's judgement about impersonation versus delegation, which are properties
of a MECHANISM, and a permission that has never been exercised has performed
none.

**A LINE IS DASHED UNTIL THE CLIENT HAS ASKED FOR THAT PERMISSION.** That one
bit is the most useful thing on the picture and it is the reading an acts diagram
can never give — a grant nobody needed draws no act at all, so it is invisible
over there. It is said in WORDS on the label as well (`never asked for`), because
a picture whose most useful fact was carried only in a line style is one nobody
reads it off.

**A DANGLING GRANT IS NOT DRAWN**, and the page says how many were left out. It
names a permission no application defines, so there is no box at the far end to
reach, and a line to nowhere would be a drawing of a resource that is there. That
state belongs on the register's table, which is where it is.

**IT HAS ONE CONTROL SINCE 2026-09-02 AND IT NARROWS NOTHING ON THE PAGE.** The
page used to say, correctly, that there was no control on it and no filter — a
picture of forty boxes being the whole answer to *what may reach what*, and this
register having no dimension to narrow on the way the acts have a mechanism, a
mode and an outcome. Half of that is still true and half of it was a gap: the
one division this register DOES have is which applications can reach each other
at all, and it is a LIST rather than a filter. So the page gained a search over
every application the configured register touches, and a paged table of the
GROUPS under it; a result opens `/admin/delegation/cluster`, which is the
section below. The drawing at the top is untouched, and the closing note now
says all of that rather than the sentence it replaced.

**IT IS THE FOURTH TIME THE NO-SCRIPT ARGUMENT HAS COME OUT THE SAME WAY**, and
the root `CLAUDE.md`'s rule is that the argument has to be MADE rather than
cited. It is made in that route's header from scratch and lands where the
delegation and federation pictures landed: the test for a script is that the page
CANNOT work without one, and a diagram that does not move can. `@dagrejs/dagre`
lays it out on the server, the SVG arrives inline as ordinary markup,
`script-src 'none'` is untouched, and `?format=svg` is what answers the pan and
zoom it does not have.

## `/admin/delegation/cluster` — THE GROUPINGS, AND WHY THE WHOLE-REGISTER PICTURE NEEDED A SECOND ONE

Added 2026-09-02. `/admin/delegation/allowed` draws the whole configured
register on one canvas, and that is the right document for five applications and
the wrong one for eighty. Past a certain size the interesting reading of a
permission register is never the whole of it: it is **which applications are
joined to each other at all** — the API and the three front ends holding
permissions on it, the batch job that reaches two of them, and the twelve
applications elsewhere in the registry that have nothing to do with any of it.
So the allowed picture gained a SEARCH and this page draws the answer.

**A GROUP IS A CONNECTED COMPONENT OF THE GRANT GRAPH WITH THE DIRECTION
IGNORED, AND THAT IS THE ONLY DECISION ON THE PAGE.** A grant is directed — a
CLIENT is granted a permission a RESOURCE exposes, which is exactly why every
line carries a round end and an arrowhead — and following the arrows would
answer *what can this client eventually reach*, which is a question about a
CHAIN. **A permission register has no chains in it**: holding a permission on an
API does not grant that API's own permissions to anybody, so the transitive
reading is a claim about the model that the model does not make. Following a
grant either way answers the question a reader actually arrives with, and it is
the only reading under which an API and the three front ends holding permissions
on it come out as ONE group rather than as four. **Membership ignores direction;
the picture does not** — every line is still drawn with both marks, because
which way a grant points is a fact about the grant and this page changes nothing
about it. `common/app_permissions.js`'s `clusters()` carries the argument; this
page cites it rather than restating it, which is the rule this file follows
about `delegation.js` everywhere else.

**THE SEARCH IS `chooserPane()` AGAIN AND ITS PARAMETERS ARE ITS OWN.**
`permappq` / `permappfrom`, never `appq` / `appfrom`. Those two belong to the
ACTS chooser, they are in `LIST_PARAMS` for `/admin/delegation`, and every
drill-down of that page carries them through untouched so that the way back
lands on the search the reader left — a second control writing the same two
names would overwrite it on every search. The catalogue is different too, which
is why `allowedApplicationChooser()` is a second function rather than an
argument to the first: `delegationApplicationChooser()` offers what some ACT
named, spellings and all, and this one offers what the CONFIGURED register
touches. The two lists overlap and neither contains the other, and a reader
searching here for something they saw on the acts picture must be told it is not
in this register rather than shown a group it is not in.

**IT IS A DRILL-DOWN OF `/admin/delegation` AND NOT OF THE PAGE IT IS REACHED
FROM.** `upTo()` takes a `NAV` path and the allowed picture is not one, so the
trail reads *Admin console › Delegation › One group of applications* and the way
back to the picture is a BUTTON at the top carrying this page's own search.
`allowedChooserState()` is why those two carriers are different: the crumb
spends the acts LIST's state and the button spends this page's search, and
putting the search in `LIST_PARAMS` would have made the crumb carry state the
page it points at cannot use.

**THREE STATES MAKE A GROUP OF ONE AND EACH IS A REAL ANSWER.** A resource
nobody holds anything on — an API somebody described and nothing may reach,
which is the most interesting group of one there is and the reason the
membership universe is every RESOURCE and not just the two ends of a grant; a
client holding only DANGLING grants, which name permissions no application
defines, so there is no far end to be in a group with; and an application
granted its OWN permission, which is one application however it is drawn. The
page says which of the three it is looking at rather than drawing an empty
canvas — an early version said *every grant here is dangling* about an
application that held no grants at all, which is the page inventing rows to
explain their absence.

**NOTHING ON IT CHANGES ANYTHING, AND THAT IS WHY `permissionGrantRow()` AND
`permissionDefinitionRow()` TOOK AN `options.readOnly`.** The picture pages are
documents; `/admin/delegation/allowed` says so in as many words. A Revoke drawn
here would be the one control on a page whose text says it has none, and it
would answer by throwing the reader back to a table three screens up on a
different page, because `permissionsReturnTo()` has nowhere else to send it. One
row function with a flag rather than two row functions, for `chooserPane()`'s
reason: the six cells before the last one are the whole of what a grant IS, and
two copies of them are two tables that come to disagree about what the access
token will say.

**IT COSTS NO NEW OPERATION AND IT GOT ONE ANYWAY.** Rule 7 asks for an
operation per FORM and there is no form here, which is how the other picture
pages satisfy it. `GET /admin-api/permissions/groups` exists because a new
console page gets a management API resource in the same change and both get
pagination, and because a member on `GET /admin-api/permissions` could not have
carried either: a list of groups holding its grants would repeat the register
once per group, and one that did not would leave a caller no way to ask for a
single group's rows at all. `permissionGroupsView()` is the one function both
that operation and this page's `?format=json` go through — `delegationView()`'s
arrangement, for its reason.

## `respondToAction()` PUTS THE QUERY BEFORE THE FRAGMENT

One line, and it is here because it was a real defect found by pressing the
button. That function appended `?notice=…` to the target, and
`/admin/delegation`'s configured half posts back to `#allowed` — because that
section is four screens down the longest page in this console and a reader who
has just granted a permission should land on it. Appended the naive way the
`?notice=` became part of the FRAGMENT: the browser scrolled nowhere and the
message the action came back with was never shown, which reads exactly like the
form having done nothing. Every target without a `#` is unaffected, which is
every other target in this console.


---

## Five pages this file does not draw, and the furniture it lends them

`/admin/sts-metadata` has been built by `../sts_metadata.js` since 2026-08-24,
and since 2026-09-01 five more pages are built somewhere else:
`/admin/ldap/service`, `/admin/ldap/directory`, `/admin/ldap/applications`,
`/admin/ldap/federations` and `/admin/ldap/spiffe`, all drawn by
`ldap/ldap_server.js`. They were `/ldap*` — outside this console, in a shell of
their own, and outside the gate. `ldap/CLAUDE.md` argues the move; three things
about it are this file's.

**THEY ARE A GROUP INSIDE `Directory`, AND THE SECOND GROUP IN THIS CONSOLE.**
Until now only `Protocols` had a third level. The test is the one stated beside
SAML in `SECTIONS` — *does the heading name more than the page under it does?* —
and it does: the four pages above them are each ONE KIND OF THING this service
has seen, drawn the way this console draws things, and these five are the STORE
UNDERNEATH all four, entry by entry and attribute by attribute. Ungrouped they
would have doubled that section with rows reading as alternatives to Users and
Applications rather than as the layer beneath them.

**THE LIST FURNITURE IS EXPORTED, AND WHAT CROSSES IS FURNITURE AND NEVER
DATA.** `pagedRows`, `pageNavPair`, `perPageOptions`, `queryWith`, `pagingJson`,
`esc`, `tile`, `clipped` and `clippedValues` go over the boundary for the reason
`page()`, `note()`, `warn()`, `bullet()` and `tip()` already do: a page drawn in
this shell with a paging control of its own invention would be the one control
here that behaves differently, and a reader would have no way to know which one
it was. Nothing in that list decides what a page CONTAINS.

**`clipped()` IS A SECOND TRUNCATION HELPER BESIDE `shortened()` AND THAT IS
DELIBERATE.** `shortened()` is one identifier in a narrow column with a native
tooltip, and it has been right for `/admin/tokens` for as long as that page has
existed. `clipped()` is for a cell holding tens of values at once, where three
things are different at the same time: wrapping made rows five lines deep and
not wrapping pushed the table past the white card; the value is the point, so it
must be recoverable; and it must be COPYABLE, which a `title` attribute is not.
So the full value is a real element — `.trunc > .full`, shown on `:hover` and
`:focus-within`, with `user-select:all` on the `code` inside it — that the
pointer can travel into. The `title` is set as well and is not redundant: it is
what a keyboard user and most screen readers get, which keeps the rule that
**nothing is ever said only in a tooltip**. There is no script in any of it;
`script-src 'none'` is untouched, and a hover popup was available where a
collapse-all switch was not.

**THE SHELL IS 104rem WIDE RATHER THAN 92rem** since the same day, and the
reason is one column on one page rather than a taste for wide layouts:
`/admin/ldap/directory` draws every attribute of every entry, which is the
widest thing in this console by a distance. `.main` is `flex:1 1 32rem`, so a
page whose content is narrower is unaffected.

## `/admin/consent`: the third register, and the first with a person in it

A page of its own rather than a fourth heading on `/admin/delegation`, and the
first reason is enough: **every row there is about two APPLICATIONS and every
row here has a PERSON in it.** The whole argument for keeping the acts picture
and the permissions picture on separate canvases is that a drawing with a person
in it and a drawing without one must not share a frame; this is the same
argument one layer up. The second reason is arithmetic — that page already
carries seven tables.

**TWO SECTIONS, AND THEY ARE NOT THE SAME KIND OF THING**, which both headings
say out loud because a reader who confused them would draw exactly the wrong
conclusion from an empty second table (which is what a service with everything
under global consent correctly looks like):

* **Global consent is CONFIGURATION.** One row per (application, scope), held as
  `oauthGlobalConsent` on the application's entry. Nobody is asked about a scope
  named there and nothing is written about anybody — so removing a row asks
  EVERYBODY again, including the people who would have said yes.
* **Recorded consent is a RECORD.** One row per (person, application, scope),
  held as `oauthConsent` on the person's entry. Removing a row asks that person
  and nobody else.

**FOUR ACTIONS, and `CONSENT_ACTIONS` is built from the switch rather than
typed**, for `PERMISSION_ACTIONS`' reason: `tests/vendored/admin_api.js` reads
the refusal sentence to check that every console action has an `/admin-api`
operation, so a list short by one turns the parity check off for that action.
Two of the four go through `applications.updateApplication()` like every other
attribute write in this console, so the schema rules, the `application.update`
audit row and the `ldapmodify` equivalence all come for free.

**THE TWO REVOKES ARE NAMED APART ON PURPOSE.** `revoke-global-consent` and
`revoke-consent` are one word apart and do very different things — one asks
everybody again and the other asks one person — which is exactly the pair a
caller most needs kept distinct, because pressing the wrong one is invisible
until somebody is asked again a week later. `revoke-consent` requires all three
of `username`, `client` and `scope` for the same reason.

**THE AUDIT ROWS ARE WRITTEN HERE AND NOT IN `common/consent.js`**, which is the
division `rbacAction()` already has: the actor is the person whose session got
them through the gate, and the module underneath has no request to read one
from. `oauth-oidc/consent_screen.js` writes its own rows from the other side,
where the actor is the person consenting. Both use `consent.grant` /
`consent.deny` / `consent.revoke` under the **Applications** category rather than
a category of its own — a tenth category would have separated *webapp1 was
created* from *alice let webapp1 read her profile*, which are the two halves of
one question. The GLOBAL half writes no row of its own: it goes through
`updateApplication()` and is recorded as `application.update` naming the
attribute, and a second row for one write would make the count on
`/admin/metrics` wrong.

**THE SEARCH IS OVER THE RECORDED HALF ONLY.** The overrides table is one row
per thing somebody typed and is short by construction; the recorded table grows
by one row for every scope every person agrees to. It matches the person, the
application OR the scope, because a reader arrives holding exactly one of the
three and does not know which column it is in. Both tables page separately and
share one `per`, which is `/admin/delegation`'s arrangement.

---

## `/admin/sessions` — WHAT IS LIVE, BESIDE THE PAGE THAT SAYS WHAT WAS ISSUED (2026-09-04)

Monitoring gained a page that lists every session this service is HOLDING,
across the three protocols that have one. It sits above `/admin/tokens` in that
section and the order is the argument: a session is what is live now and a token
is what came out of one, so a reader working out what is going on reads them in
that direction.

**IT DRAWS NOTHING OF ITS OWN.** Every row comes from
`logout/logout.js`'s `liveSessions()` through the SIXTH SLOT, which grew that
function and `SESSION_EXPIRY_RULES` in the same change; the slot is still
validated whole, so a reader carrying the inventory and not this is refused
rather than half installed. `logout/CLAUDE.md` argues why the enumeration lives
there and not here, and it is the same reason the Revoke button calls
`terminate()` rather than ending anything itself.

**THE EXPIRES COLUMN CARRIES A RULE AS WELL AS A TIME**, and that is the one
thing about the page worth defending. The three kinds work their expiry out
differently — absolute and not extended by use, sealed into a Kerberos ticket,
and *none at all* for an LDAP connection — so a column of timestamps would be
read as one rule with three values. The sentence is a `title` on the cell AND
the three are written out in the prose above the table, which is this console's
standing rule that nothing is ever said only in a tooltip.

**THE REVOKE BUTTON IS NOT ONE ACT AND THE PAGE SAYS SO BEFORE IT IS PRESSED.**
On a browser session it ends the session and everything hanging off it; on an
LDAP row it closes a socket; on a Kerberos row it stamps an instant on the
PRINCIPAL and refuses every ticket that principal authenticated before now,
which is more than the row it is on. Each row's `why` is the button's `title`.

**IT HAS NO ROLE CHECK OF ITS OWN**, and that is deliberate rather than an
omission: the gate is MIDDLEWARE and refuses every non-GET without Admin Write
with a 403 and a page naming the group. A second check in the handler would have
been a second refusal in a different shape — a 303 carrying a message — for one
act, and `tests/vendored/sts_admin_console.js` asserts the 403.

`GET /admin-api/sessions` and `POST /admin-api/sessions/revoke` mirror it, in
the same change, which is rule 7; `mgmt-api/CLAUDE.md` argues why it is a
separate resource from `/admin-api/logout` rather than a shape of it.

**`/admin/tokens` GREW A `session` FILTER IN THE SAME CHANGE**, because every
row here links to the credentials issued on it and there was no way to ask for
them. It matches the session id EXACTLY, so everything issued with no session
behind it — both direct grants, a pre-authorized code, a token exchange, every
assertion and every ticket — is absent by construction rather than missing, and
the page says so where the filter is in force.

---

## `/admin/caep-sessions` GAVE ITS DETAIL A PAGE OF ITS OWN (2026-09-04)

That page drew a card per tracked session under its table, each with an event
table inside it. `caep.maxSessionsTracked` is 200 by default and settable
higher, so a service driven for an afternoon answered with a couple of hundred
nested tables under the one table anybody had come to read — and the sessions
table was off the top of the screen for the whole of it.

The detail is `/admin/caep-sessions/session?id=…` now, a drill-down of the same
shape `/admin/tokens/credential` has: no `NAV` row, `active` is the list's path,
`up` carries the search and the page the reader left. The list gained the
console's ordinary furniture — `sectionSearchForm` over `sessq`, `pagedRows`
named `sessions`, `pageNavPair` head and foot, `perPageForm` — and the JSON
reports `filter` and `paging` beside the WHOLE list, which is the arrangement
`/admin/delegation`'s configured half already has.

**A SESSION THIS REGISTER NO LONGER HOLDS IS NOT A 404.** The register is capped
and the clear button empties it, so an old link coming back empty is an ordinary
outcome; the page says which of the two states it is in.

**THE THREE CAEP FORMS NOW POST TO `/admin/caep` FROM WHEREVER THEY ARE DRAWN**,
and that is the applications page's arrangement with `/admin/delegation`: a form
may live on one page and post to another's handler, and MOVING A FORM IS NOT
MOVING AN ACTION. There is one CAEP action handler and one operation over it; a
route per page would have wanted an operation per page over the same function.
`from` (an ENUM, never a path) and `back` are what send the reader back to the
page the button was on, through `caepSessionsBackTo()`.

`GET /admin-api/caep/sessions` mirrors the page — the list, or one session with
`?session=`. It exists because rule 7's parity check found `/admin/caep-sessions`
mirrored by nothing: the GET beside it names `/admin/caep`, and one operation
cannot mirror two pages. **That gap pre-dated this change and was invisible until
the check named it**, which is the whole argument for the check.

**The catalogue on `/admin/caep` is a collapsed `<details>`**, and it is the one
place in this console where a SECTION rather than a paragraph is behind a
disclosure. Eight cards of member tables sat between the settings above them and
the links below, so the controls somebody came for were off the bottom of the
page on every visit. `details.fold.section` styles the summary as the `<h2>` it
replaces, so the heading is still in its place; native `<details>`, so
`script-src 'none'` is untouched — the same answer `note()` gives one level up.

## `/admin/caep-sessions` HAS A THIRD TABLE, AND IT IS A THIRD QUESTION (2026-09-04)

Per SESSION, per STREAM, and now per APPLICATION. The third is the one an
operator actually arrives with once more than one receiver exists — *is the
application I am testing getting anything, and what* — and neither of the other
two could answer it: the register counts per session and the streams table says
only what a stream WOULD take.

**It is computed in `ssf/ssf.js` and not here**, on the report the slot already
carries, for rule 7's reason: `/admin/caep` and `GET /admin-api/caep` answer
with that same report, so a second aggregation in this file would be a second
answer to "what has been said to whom". `caepApplicationsState()` here is the
SEARCH and the SLICE only, the same shape `caepSessionsState()` has.

**The eight count columns are the sessions table's own, off the same
`caepShortNames()`.** A reader moving between the two tables is reading one
vocabulary, and a column that moved between them would be worse than a column
too many.

**The `aud` column is `shortened()` and that is not cosmetic.** An `aud` is
routinely a URL, `code` is `word-break: break-all`, and a fifteen-column table
gives it about three characters of width — so the untruncated value wrapped to
six lines and made every row that tall.

## `/admin/roles` — the fourth register, and the ELEVENTH SLOT (2026-09-05)

The page has two tables because a role has two relations, and drawing them as
one is the mistake this page exists to avoid: **MEMBERSHIP** — who holds a role,
stored on the role entry under `ou=roles` and edited here — and
**REQUIREMENT** — which roles an application demands before anything is issued
for it, stored as `appRequiredRole` on the APPLICATION entry and edited on the
application's own page. An application appears in both and means opposite things
in each. `common/CLAUDE.md` argues the split; this file's job is that the page
never implies one is the other.

Five actions: `create-role`, `delete-role`, `add-member`, `remove-member`,
`describe-role`. Creating and populating are separate because a role is worth
creating before anybody holds it.

**The six BUILT-IN roles are drawn and are not editable**, because they are
computed from the context of the decision rather than stored. That is worth a
table of its own rather than a footnote: an empty `ou=roles` is the ORDINARY
state of a service that is deciding every issuance against `EVERYBODY` and
refusing nobody, and a page that showed nothing at all would read as a feature
that had failed to load.

### The preview is the same call the nine issuance sites make

"Would alice be issued a token for this application" is answered by
`common/issuance_gate.check()` through `xacml/xacml_role_pep.js` — the exact
call `/oauth2/token` makes — so the page cannot drift from the enforcement. It
arrives through **the ELEVENTH SLOT, `setRolePreviewer()`**, and that slot passed
rule 3e's test in BOTH directions, which is the bar a proposal is held to:

* A require from THIS file (18) to `xacml/xacml_role_pep.js` would load the
  XACML engine here and — much worse — **fill `issuance_gate.js`'s DECIDER from
  the console**, so a process that loaded the console and not `xacml/xacml.js`
  would gate every issuance in the service with half that family present.
* A require the other way closes a cycle, because `xacml_admin.js` requires this
  module for the page shell.

It carries TWO functions, validated together for `setLogoutReader()`'s reason: a
preview installed without the thing that says WHICH POLICY answered would be a
page able to ask a question and unable to explain the answer.

**The preview's four query parameters are deliberately NOT in `LIST_PARAMS`.**
They are a question somebody asked once, not a view — carrying them through a
Remove button would re-ask the question on every write and put a stale answer
above the table, which is the same reasoning `notice` and `error` are excluded
under.

### Nothing on this page is what makes a refusal happen

Worth stating because the page invites the opposite reading. Whether anything is
refused at all is `roles.enforceIssuance` and whether the XACML family is loaded
at all — the two different "offs" `GET /admin-api/roles` reports as `enforced`
and `gated`. This page narrows and populates; the decision is a policy, and the
document that implements it is on `/admin/xacml`.

## The directory group grew to EIGHT pages (2026-09-05)

`/admin/ldap/roles`, `/admin/ldap/policies` and `/admin/ldap/peps` joined the
five that moved in on 2026-09-01. They are `SECTIONS` rows with a `path`, a
`label` and a `blurb` like every other page, and they are DRAWN by
`ldap/ldap_server.js` — the arrangement `/admin/sts-metadata` has had since
2026-08-24, and the reason `DIRECTORY_PAGE_NAMES` is checked WHOLE when
`setDirectoryPages()` is filled.

They are the layer beneath three pages that already exist — `/admin/roles`,
`/admin/xacml` and `/admin/xacml/peps` — which is exactly the test the group
heading was written for: *does the heading name more than the page under it
does?* Each of the three publishes the container's SCHEMA, which is the thing
its console twin has no room for and which this schemaless directory has nowhere
else to say.

`ldap/CLAUDE.md` carries what writing them exposed, and it is worth knowing here
too because it is a hazard for the ninth: the store lower-cases attribute names,
so a page reading `xacmlEnabled` off an entry gets `undefined` — and a
comparison against `'false'` then draws a DISABLED policy as enabled. The fix is
in `learnName()`, not at the reading site.

## `/admin/sessions` GREW A SECTION FOR UNAUTHENTICATED SESSIONS (2026-09-05)

A session where nobody authenticated — somebody pressed *Continue without
signing in* at `/authn/login`. `authn/CLAUDE.md` argues the feature; this is
what the console does with it.

### A SECTION AND NOT A COLUMN, and that is the decision

A column on the live-sessions table would say the same thing on every row for
weeks at a time, and a column like that stops being read. A section that is
empty says so in one line, and a section with rows in it is the thing somebody
notices.

### It is NOT filtered and NOT paged, unlike the table above it

The two lists answer different questions. The main one is *what is live*, which
is long and needs narrowing. This one is *is anybody in here without having
signed in*, which is a question about the whole service — and a search box
somebody had left set could hide the one row that matters. That is worth the
inconsistency of two tables on one page behaving differently, and the section
says so out loud rather than leaving it to be discovered.

### It draws whether or not the setting is on

`authn.unauthenticatedSessions` is off by default. The section still draws,
because a service that had it on this morning may still be holding sessions it
minted then, and a section that disappeared with the setting would hide exactly
those. **What changes with the setting is the sentence, not the presence** — a
`note()` when it is on, a `warn()` naming the setting and linking to
`/admin/roles` when it is off.

### The fifth tile is a SLICE and not a fifth kind

`live sessions`, `browser sign-on`, `Kerberos TGTs`, `LDAP connections` still
add up. `unauthenticated` does not join that sum — it is a subset of the first
four. It earns a tile anyway: it is the number somebody scans this page for,
and a zero on it is as informative as a non-zero.

### Rule 7 cost no new operation

`GET /admin-api/sessions` grew `unauthenticatedHeld` and
`unauthenticatedSessions` rather than the page growing a door the API did not
have. Both the count and the rows, because *are there any* and *which ones* are
two different questions and deriving the first from the second would make an
empty list and an absent field look alike.

### Why the page is worth having at all, in one sentence

It is the only place in this console where the difference between two built-in
roles is visible: every session in the main table holds `EVERYBODY` **and**
`ALL_AUTHENTICATED_USERS`, and every session in this one holds `EVERYBODY` and
`ALL_UNAUTHENTICATED_USERS` instead. The section says that, and links to
`/admin/roles` where it is configured.

## `/admin/roles`: THREE REASONS AN APPLICATION COULD NOT BE FOUND ON IT (2026-09-05)

The capability was never missing. `ROLE_MEMBER_KINDS` has held `application`
since the page was written, the *Give somebody a role* form has always offered
it, and the table has always had a **Held by an application** column with a
Remove on it. What was missing was any way to FIND it, and three separate
things hid it. They are worth keeping written down because each is a general
trap on a console with no script on it.

**1. The heading and the fold's summary were both about people.** The heading
read *Give somebody a role*, and the note under it was the three
`ROLE_MEMBER_KINDS` joined with `<br>` — so `note()` derived the fold's summary
from the FIRST of them and it read `a person — A username.` The one sentence
saying an application may hold a role as itself was inside a collapsed block
whose opening words were about people, under a heading that was also about
people. **This is the collapsing rule's own failure mode**: a summary is the
first sentence, so a list rendered into a note is summarised by its first item
and the rest of the list is invisible until somebody opens it. A note that is a
LIST needs a lead sentence naming the whole list, which is what it has now.

**2. The Role `<select>` is empty on a service where nobody has made a role**,
because the six built-in roles are computed and have no membership. So the form
rendered complete and was inert: a `required` select with no options means the
browser silently blocks the submit, which looks like a broken button rather
than an unmet precondition. The button carries `disabled` now and a `warn()`
above it links to `#create` — the fix and the reason, where the reader is.

**3. The member Name field had no suggestions**, on a page that was already
building a datalist of every application in the realm for the preview form four
sections below. An application's identifier is whatever it registered itself
as, so it is the one member kind nobody can guess.

### The datalist is applications and only applications, and that is deliberate

A datalist SUGGESTS and never constrains, which is what makes one field serving
three kinds tolerable — a person or a group is still typed by hand and still
need not exist yet, which is this service's rule everywhere. Applications are
the kind with a knowable set and the kind that cannot be guessed; a person need
not exist, and a group lives in the directory behind a hook this page has no
reader for. The `title` on the label says exactly that rather than leaving
somebody to infer that only the suggestions are valid.

**It is its own `<datalist>` rather than the preview form's
`role-preview-apps`.** Both render the same `applicationOptions` — one
computation, two renderings, so they cannot disagree — but referencing an id
another section owns would make this field's suggestions vanish silently if
that section were ever made conditional or moved.

### What it is NOT: the other relation

This is MEMBERSHIP — who **holds** a role, stored on the role entry under
`ou=roles`. What an application **requires** is `appRequiredRole` on the
application's own entry, edited on that application's page, and drawn read-only
further down this one. `common/CLAUDE.md` argues why collapsing the two is the
mistake; the page draws both precisely so a reader meets the distinction.

## TOOLTIPS ON EVERY FIELD AND EVERY SECTION, DERIVED (2026-09-05)

Coverage before this: `tip()` was called 18 times in the whole file, and of the
156 `<label>` elements this console emits exactly ONE carried a tooltip. The
settings rows were the exception and they were already right — that is where
the shape came from.

Coverage after: **61 of 64 section headings and 133 of 136 fields**, measured
across fourteen pages. The three misses in each are elements with no prose
anywhere near them to derive from, which is the honest answer rather than a
wrong tooltip.

### `withDerivedTips()` is a pass over the RENDERED body, not 391 edited call sites

It runs in `page()`, on `inner`, just before the shell wraps it. That is the
same decision the folds made and for the same reason: **the test is on the
rendered text, not on the caller's judgement**, so a page written tomorrow gets
its tooltips with nothing added to it and none of them can drift from the prose
they are taken from — they ARE that prose, read at render time. The alternative
was 391 hand-written hints, which is a second copy of every explanation on this
console and exactly the drift the derived-summary rule exists to prevent.

Two rules, because the two things differ:

* **A HEADING** takes the opening sentence of the first note that FOLLOWS it,
  bounded by the next heading so a section with no prose borrows nothing from
  the one below.
* **A FIELD** takes the nearest note ABOVE it. A hand-built form is explained by
  the paragraph introducing it rather than per control, so every field in one
  form shares a tooltip. That is honest: the paragraph is genuinely what all of
  them are for, and a per-field sentence does not exist to be derived.

**IT ONLY EVER ADDS.** An element already carrying a `title` is skipped whole,
so every hand-placed tooltip still wins and this can never overwrite a better
one. That is also what keeps the settings rows — which set their own, from
`config.describe()` — untouched.

### THE ONE PLACE SOMETHING IS SAID ONLY IN A TOOLTIP, AND WHAT PAYS FOR IT

The rule above this section says nothing is ever said only in a `title`,
because a title is unreachable from a keyboard, invisible on a touch screen and
unread by most screen readers. **That rule is now qualified rather than
deleted**, and the qualification is narrow: a SETTING's description is in its
tooltip and nowhere else on the page. `configRow()` used to draw it as a fold
with the setting's short label as the summary; that fold is gone.

What pays for it is that a setting's description has **three other doors** —
`/admin/config?format=json`, `GET /admin-api/config`, and README.md's table —
so the text is reachable without a mouse even though this page no longer draws
it. Both were checked rather than assumed. **A field whose prose has NO other
door does not get this treatment**, which is why the derived tooltips above add
a title and remove nothing.

`tip()` therefore takes an optional `max`, and a caller passing one is saying
*this tooltip is the only copy*. The default 190-character teaser was right
while a tooltip previewed a fold the reader could open; where there is no fold,
truncating would not hide the rest of the sentence, it would DELETE it — the
median setting description is 384 characters. The settings rows pass
`Infinity`.

### What it did NOT buy, measured

Visible text fell by 2–7% on the pages that changed, and that is worth writing
down because the intuition says otherwise. The per-setting folds were already
hidden by the 2026-08-26 change, so removing them reclaimed only their one-line
summaries. What is left visible on a settings page is **37% table data and 23%
sidebar**, neither of which is prose.

**The remaining lever is the fold summaries**, and it is a big one: on `/admin`
they are 8182 of 11271 visible characters — 73%. Each is a full opening
sentence, and there are hundreds across the console. Shortening them to a few
words each would now cost nothing that was not already recoverable, because
every heading carries the whole first sentence as a tooltip. That is a
deliberate next step rather than something done here: the summaries are what
lets a reader skim for a paragraph without opening all of them, which is the
property the folds were built around and which has no script to replace it.

## THE SIDEBAR SCROLLS TO THE PAGE YOU ARE ON (2026-09-05)

`nav` is its own scroll container — `.side` is sticky, the card inside it has
`overflow-y:auto` — and a scroll container starts at the TOP on every load. The
list overflows by about 1200px, so navigating to a page low in it left that
page's own entry below the fold: the reader arrived somewhere and the list did
not show where.

**`autofocus` is the whole mechanism and it needs no script**, which is the
only reason this console can have it: a browser scrolls a focused element into
view, including scrolling the ancestor container it lives in. `script-src
'none'` is untouched and there is no seventh scripted page.

Three things about it are decisions:

* **`tabindex="-1"` and not `0`.** The active item is a `<span>` when it is the
  page being drawn, and a span is not focusable without it — so autofocus alone
  would do nothing. `-1` makes it focusABLE without joining the TAB ORDER,
  which is right: it is the page you are already on, so a keyboard user tabbing
  the nav should reach the links they can GO to and not stop on the one they
  are standing on.
* **It is the only `autofocus` in this console**, checked rather than assumed —
  two of them and the first in document order wins, so one added to a form
  field later would silently stop working. A page that needs to focus a field
  on load has to opt this one out rather than compete with it.
* **`scroll-margin:4.5rem`** keeps the revealed item off the container's top
  edge, where it would read as the first item in the list rather than one in
  the middle. What tells a reader where they are is the item's NEIGHBOURS.

Measured over CDP on five pages: the nav scrolls to 0, 351, 497, 787 and 1197
respectively, the active item is inside the visible box on every one, and
`window.scrollY` stays 0 — only the container moved, not the document.

**And the highlight was a whisper.** `.here` was `background:#eceaf6`, a
lavender four shades off the card's own white, which on a list of thirty-odd
links read as *very slightly different* rather than as *here*. It takes the
solid brand fill `.pagenav .here` has had all along, so the two "you are here"
markers in this console finally look alike. `aria-current="page"` says the same
thing to a screen reader.

**`tests/vendored/sts_metadata.js` pins all three** — the span, the
`aria-current` and the `autofocus`+`tabindex` pair — because all three are
invisible: nothing about the rendered page looks wrong if one is dropped, and
the sidebar would quietly go back to starting at the top on every navigation.
That assertion was an exact-string match on the whole `<li>` and had to be
loosened to tolerate attributes; its INTENT, that the active item is text and
not a link, is unchanged and still asserted.

## `/admin/tokens` LISTS ISSUANCES NOW, NOT CREDENTIALS (2026-09-05)

**A row of that table used to be one credential and is now one REPLY.** Nothing
was removed: every JWT, every SAML assertion, every Kerberos ticket and every
SPIFFE SVID is still there, and three families out of four look exactly as they
did — because three families out of four issue ONE credential per act.

**OAuth 2.0 and OIDC are the only families this service speaks that hand back
several at once.** Redeeming an authorization code returns an access token, a
refresh token and an ID Token in a single reply; `response_type=id_token token`
returns two in one fragment. Drawn as three rows and two rows, the one thing the
protocol handed over whole was left to be reassembled by comparing timestamps —
and worse, to be GUESSED, because two people redeeming two codes at the same
client in the same millisecond produce six records that agree on every field
this console records.

### The grouping is a fact the ISSUER stated, and that is the whole design

`admin_stats.js`'s `setId` is the third thing the token registry is told that no
token carries as a claim, beside `sessionId` and `grant`, and it arrives the
same way: through `signJwt()`'s third parameter, from the call site that built
the reply. There are exactly TWO such call sites and `oauth-oidc/CLAUDE.md`
argues them — `tokenSet()`, which every grant that issues a token set goes
through, and `issueAuthorizationResponse()`, which is where implicit and hybrid
mint on the spot without going through `tokenSet()` at all.

**Nothing here derives it, and the reason is the simultaneous-redemption case
above.** A heuristic over `sub`, `client_id`, `scope`, `grant` and `issuedAt`
would merge two replies into one that nobody ever received — a page reporting a
credential handover that did not happen, which is worse than the three rows it
replaced. `tests/issued_sets.js` asserts exactly that case, in process, because
producing it over HTTP means winning a race against the clock on purpose.

**The set id is in NO TOKEN.** No client sees it, it is not a claim, and it is
not `sid` — that one exists because OpenID Connect Front-Channel Logout section 3
requires it, which is the standard this repository holds a new claim to.

### A SET IS ONE RESPONSE AND NOT ONE GRANT

Refreshing produces a NEW set beside the old one rather than a fourth member of
it. A set has one issued instant and one grant, and a row that grew over an
afternoon could have neither. What joins the generations of a grant is the
refresh lineage, which is a DIFFERENT RELATION and is already drawn as one at
`/admin/tokens/credential` — this page is what arrived *together*, and that page
is what one credential descends *from*. Keeping the two apart is what stops this
becoming a second, worse drawing of the lineage.

### Three columns answer differently now, and each says so on the page

| Column | What it does |
|---|---|
| **State** | the state every member shares, or `mixed`. An access token expires in fifteen minutes and the refresh token beside it in a day, so within the hour most sets are neither valid nor expired — and reporting either would be the column deciding which member matters. The one that matters is usually the one the reader has not thought of: the refresh token that outlived the access token and will mint another. `states` carries the breakdown. |
| **Expires** | the EARLIEST member's, then the latest. One column cannot carry both and the earlier one is what somebody debugging a refused call has arrived to find. |
| **Detail** | the ACCESS TOKEN's scope, which the refresh token beside it deliberately does not share — see `tokenSet()`, where the refresh token keeps what was AUTHORIZED. The set page shows each, and says why they differ. |

**A FILTER MATCHES A SET WHEN ANY MEMBER MATCHES, and the neighbours come with
it.** `?kind=id_token` answers with the replies that CONTAIN an ID Token, access
token and refresh token included. That is the one behaviour of this page a
reader would otherwise call a bug, so it is said under the filter form rather
than left to be discovered — a filter that hid the neighbours would be the old
per-credential table wearing this one's name.

### `/admin/tokens/set?id=…` IS THE SECOND DRILL-DOWN, AND IT IS THE OLD TABLE SCOPED TO ONE REPLY

Same shape as `/admin/tokens/credential`: no `NAV` row, `active` is
`/admin/tokens`, `up` carries the filter and the page the reader left. Its member
table is drawn by **`issuedRow()` — the very function the list used to call** —
so the column legend on the list describes it without a word changing, and
somebody chasing one token gets back its own jti, its own expiry and its own
button.

**It is addressed by `setKey` and never by the set id.** A grouped set's key is
`set:<id>`; a set of one has no issuance id at all and its key is `one:<this
service's own row handle>`. The list only links here from a group — for one
credential this page would be a click that added nothing, so those rows still
open the lineage — but the KEY SPACE covers every row, which is what lets
`GET /admin-api/tokens/set` open any of them without a caller knowing which kind
it holds. **That is what `recordArtifact()`'s `key` was added for**: a Kerberos
ticket carries no identifier anybody can quote, so without a handle of this
service's own there would be nothing to address its row by at all.

### Revoke set writes nowhere new

Each revocable member goes through `stats.revoke()` exactly as its own button
would send it, into the same set of revoked jtis `/oauth2/revoke` writes to. What
it saves is the mistake this reshaping exists to prevent: **revoking two
credentials of three and believing the grant is dead**, when the refresh token
left behind mints a new access token on request.

**A set holding nothing revocable is REFUSED rather than answered "revoked 0"**,
which is the answer `revoke-kind` already gives for an unrevocable kind. Nothing
consults this service about a SAML assertion, a Kerberos ticket or an SVID —
an assertion is valid because its signature verifies and its `Conditions` hold, a
ticket because the service it names can decrypt it — so a success would be a
claim about the world that is not true.

**The members are re-read at the moment of the act** and never taken from the
form, which is `terminate()`'s rule for `terminate()`'s reason: a page can be
posted an hour after it was drawn, and acting on the list it drew would revoke a
jti since forgotten to the cap while missing one issued since. The form carries
the set key and nothing else.

### What the JSON did, and the one thing it deliberately did not do

`GET /admin-api/tokens` lists `sets`. **`issued` is the FLATTEN of that array —
the same rows, the same order, ungrouped — so every caller written against the
per-credential shape reads exactly what it read**, and the two can never disagree
because one is built out of the other rather than gathered again. What changed
under it is the paging: a page is a whole number of REPLIES, so `issued` holds
between `perPage` and three times it.

`page`, `pages`, `matched` and `shown` count SETS. `held`,
`matchedCredentials`, `shownCredentials` and `heldByFamily` count CREDENTIALS —
`held` because it has meant that since the resource existed and quietly changing
an old name's unit is the worst kind of breaking change, and `heldByFamily` so
that it goes on agreeing with `/admin/metrics`. The line under the table carries
both units and says which is which, for that reason.

### One bug this cost, and it is the ordinary one

`shortened()` returns MARKUP — a `<code>` carrying the whole value in its title
so a truncated identifier can still be read — and the first draft of
`setIdentifierCell()` passed it through `esc()`, which printed the tag. It is
worth noting only because `identifierCell()` two lines above makes the same call
correctly, which is the shape of mistake that survives a reading of the diff.

### And one it fixed on the way past

`backTo()`'s whitelist did not carry `session`, though the filter form has
offered it since 2026-09-04 and the comment on that function says the two must
be kept in step. Arriving from `/admin/sessions`, narrowing to one session and
revoking anything sent the reader back to the unfiltered list — which reads as
the console losing your place rather than as a missing line in a whitelist.

## THE USERS PAGE HAD ONE BUTTON THAT PROMISED A GLOBAL SIGN-OUT AND PERFORMED A TOKEN REVOCATION (2026-09-05)

`/admin/users?user=…` carried a single control labelled **"Revoke everything for
`<name>`"**. It called `tokenAction({ action: 'revoke-user' })`, which is
`stats.revokeWhere()` over the JWT registry — access tokens, ID Tokens and
refresh tokens, under every spelling of the identity — and it did nothing else.

**Measured against the ten families `logout/logout.js`'s `terminate()` walks, it
touched one.** The other nine, in that module's own `endOrder`:

| Family | What the button did |
|---|---|
| `oidc-rp`, `wsfed-rp`, `saml2-sp` | nothing — no front-channel notification reached any relying party, realm or service provider |
| `token` | **the whole of what it did** |
| `code`, `vci-code` | nothing — authorization codes and OID4VCI pre-authorized codes stayed redeemable |
| `ldap` | nothing — bound connections stayed open |
| `krb5` | nothing — no sign-out instant, so TGTs went on working at the KDC |
| `session` | **nothing, and this is the one that mattered** |

That last row is why the label was the defect rather than the behaviour. **The
browser sign-on session survived**, so the person was still signed in and the
next `/oauth2/authorize`, `/wsfed`, `/saml2/sso`, `/saml11/sso` or `/admin`
request minted a fresh set of tokens on the spot. From outside this service that
is close to a no-op — and an operator who pressed it believing they had signed
somebody out had been told so by the button.

The page's own note was honest about the narrow half ("Every access token, ID
Token and refresh token… Assertions and tickets are untouched"), which is the
shape of this kind of bug: **the prose was right and the label was the thing
anybody read.**

### Two buttons now, and the global one is first

The narrow act stayed — "take these credentials out of circulation and leave the
session alone" is a real thing to want, and it is what `/oauth2/revoke` does —
renamed to **"Revoke every token for `<name>`"**, with a note saying in as many
words that it does not sign them out and that the next authorization request will
mint a fresh set.

What was added is the act the old label promised, and **it is not a second
implementation**: the form posts to `/admin/logout` with `action=global`, so it
reaches `logoutReader.terminate(key, [], …)` — the same function, through the
sixth slot, walking the same ten families in the same `endOrder`. A sign-out
built here would have been a SECOND answer to "what is a live session", which is
exactly what rule 3m exists to prevent, and it would have got the order wrong the
same way `terminate()` did the first time: the notifications are built off the
session, so ending it first leaves every federated partner believing the person
is still signed in.

**Rule 7 was already satisfied and no new operation was written.**
`POST /admin-api/logout/global` has taken a `user` since that resource existed;
the new control mirrors it rather than needing a mirror of its own.

**`POST /admin/logout` now serves two pages**, so `from` says which to return to.
It is read as an ENUM with both targets written out in the handler — `backTo()`'s
rule on the tokens page, for `backTo()`'s reason: a `back` field carrying
`//evil.example` must not be able to become a redirect off this service.

### What the new button still cannot do, and both are said on the page

* **A front-channel notification is an iframe in the signed-out person's own
  browser, and this console is not that browser.** So the relying party is
  forgotten here and the notification is REPORTED rather than sent; `/logout` is
  where those actually load. `logoutAction()` already said this and the sentence
  is now in front of the operator pressing the button.
* **Nothing recalls a SAML assertion, a Kerberos service ticket or an SVID.**
  Each is valid because somebody else can verify it without asking this service,
  so the only thing that ends one is its own expiry. The Kerberos sign-out
  instant is the nearest thing that exists and it is a different claim: it
  refuses a TGS-REQ presenting an older TGT rather than recalling tickets already
  issued.

## `/admin/sessions` SHOWS API CALLERS NOW, AND THIS FILE DID NOT CHANGE FOR IT (2026-09-06)

The management API, SCIM and the SPIRE Server API hold sessions since that date,
and they appear on this page with **no edit to `admin.js` at all**. That is the
sixth slot's design working rather than a coincidence worth mentioning in
passing: this page draws whatever `logout/logout.js`'s `liveSessions()` returns,
and a console that had its own idea of what a session is would have needed one.

Two things a reader of this page should know, both decided in `logout/CLAUDE.md`
and rendered here:

* **The `kind` column tells them apart** — `SCIM session`, `SPIRE Server API
  session` — because one store does not mean one kind of row, and a SCIM client
  drawn as a *Browser sign-on session* would be the page saying something untrue
  about the one thing it exists to report.
* **The Expires column's rule differs for them**, and this is exactly what that
  column was built to carry: theirs is the FOURTH rule and the only one
  **extended by use**. The three that were there are absolute, sealed into a
  ticket, and none at all; a column of bare timestamps would read as one rule
  with four values, which is why the sentence travels on the row.

**AND THE REVOKE BUTTON MEANS SOMETHING WEAKER ON THESE ROWS, WHICH THE ROW'S
OWN `why` SAYS BEFORE IT IS PRESSED.** Ending an API session revokes nothing:
the token, password or certificate behind it is accepted without consulting any
register, so the next call authenticates again and the row comes back. That is
the third thing this button already does differently per row — a browser session
ends everything hanging off it, an LDAP row closes a socket, a Kerberos row
stamps an instant on the PRINCIPAL — and it is why each row carries its own
sentence rather than the page carrying one.

## THE XACML MONITOR IS IN `Monitoring`, AND THAT IS A RULE RATHER THAN A MOVE (2026-09-06)

`/admin/xacml/monitor` shipped inside the **XACML** group under Protocols,
beside the settings, the repository, the editor, the remote PEPs and the
what-if. It was in the wrong section for one day and it is worth writing down
why, because the mistake is available to every page this console does not draw
itself.

**THE SECTION IS DECIDED BY THE QUESTION A PAGE ANSWERS.** *Monitoring* says
"what this service has done: how much of it, what came out, and what happened in
order", and that is exactly what a page counting decisions, allows and refusals
per enforcement point reports. Everything else in the XACML group is what
authorization is CONFIGURED to do. Two pages in this section already made the
same argument against the same pull — `/admin/delegation` is beside the tokens
it points at rather than under one of the three protocol families it spans, and
`/admin/caep-sessions` is here rather than beside the CAEP settings — so this is
the third instance of one rule rather than a new judgement.

**WHAT DECIDED IT WRONG THE FIRST TIME WAS THE PATH AND THE MODULE**, and
neither is evidence. The page lives under `/admin/xacml/` and is drawn by
`xacml/xacml_admin.js`, so filing it with the other five looked like tidiness.
But a console page is a `path` and a `label` in `SECTIONS` **whoever builds the
body** — that is the arrangement `/admin/sts-metadata` has had since 2026-08-24
and the eight `/admin/ldap/*` pages have had since 2026-09-01, and those eight
are the counter-example that settles it: they are drawn by `ldap_server.js`,
they live under `/admin/ldap/`, and they are in **Directory** because that is
what they are about.

Three smaller consequences of the move:

* **The path did not change.** Nothing outside `SECTIONS` needed editing:
  `NAV` is derived, the breadcrumb reads its label from `NAV`, `GET
  /admin-api/xacml/monitor` still mirrors it, and `sts_metadata.js`'s
  `ENDPOINTS` row keeps its `XACML` group, which is about the path space rather
  than about the sidebar.
* **The label is `XACML decisions` and not `Monitor`.** Under a heading that
  already says Monitoring, `Monitor` names the section rather than the subject.
  Its neighbours `CAEP sessions` and `RISC accounts` are the same shape: the
  family, then what is counted. The page's own `<h1>` was changed with it, since
  the crumb takes the label from `NAV` and a heading disagreeing with the crumb
  above it is the drift this console derives `NAV` to avoid.
* **It passes no `up` any more.** It is a page of a section now, not a
  drill-down of `/admin/xacml`, and rule 7a's `up` is for the second kind only.

**AND IT EXPOSED A LATENT DEFECT IN THE FIVE PAGES LEFT BEHIND, WHICH IS NOT
FIXED HERE.** All five pass the STRING `'/admin/xacml'` as `respond()`'s `up`,
where that parameter is `upTo()`'s OBJECT — so `up.href` is `undefined`, the
crumb is drawn as dead text, and the trail reads `Admin console › Policies ›
Policies` with the middle crumb unclickable. They are pages of a group, so the
right value is no `up` at all. Recorded rather than swept in with a placement
change.

## `SCIM metrics` IS THE FOURTH INSTANCE OF THAT RULE, AND THE FIRST APPLIED IN ADVANCE (2026-09-06)

`/admin/scim/monitor` is a page of this console drawn by this file, filed under
**Monitoring** with the label `SCIM metrics`. It answers how many calls the
provisioning surface has taken, how many succeeded, how many failed, WHO IS
CALLING, and the breakdown by API call type — with the latency and the bytes
each returned — plus the by-resource-type, by-scheme and by-status tables and
the last fifty requests individually.

**IT WAS NEVER IN THE SCIM GROUP, AND THAT IS THE ONLY new thing about the
placement.** The section above records a page filed under Protocols and moved a
day later; this one applied the rule while it was being written, which is what
the rule is for. Everything else on `/admin/scim` is what the surface IS — the
six schemes, the endpoints, the mapping, the eighteen settings — and this is
what it has DONE. The path is under `/admin/scim/` and the module is this one,
and neither is evidence, exactly as the paragraph above says.

**ONE STORE, TWO VIEWS, WHICH IS THE PART WORTH COPYING.** `/admin/scim` keeps
its headline counts — a page about a surface with no evidence that anything ever
called it is a page about a hypothesis — and everything past them is on the
monitor. Both come out of `common/admin_stats.js` through `scimSnapshot()` and
`scimMonitorSnapshot()`, which are two functions over ONE set of counters. A
second tally would have been a second answer to "how many SCIM calls have there
been", and each page carries a sentence pointing at the other rather than
leaving a reader to find out.

Three things the page itself is careful about, argued at length in
`scim/CLAUDE.md` and named here because they are what its markup is shaped by:

* **A client is an authenticated principal, not a connection**, so the client
  count never goes down and the page says so.
* **A caller the gate refused is not a client** and appears in no row, even when
  the credential carried a name. It is counted in a figure of its own beside the
  anonymous calls.
* **An absent measurement is drawn as `—` and never as `0`.** An operation
  nothing has called has a null average, and the success rate is null rather
  than 100% before anything has happened.

**AND IT HAS NO RESET BUTTON**, for `/admin/xacml/monitor`'s reason, made again
rather than cited: a console that could zero its own monitoring would make every
number on it a number somebody might have zeroed. `GET
/admin-api/scim/monitor` mirrors it and has no POST beside it, which is rule 7
read exactly rather than by shape.

**ONE SENTENCE OF ITS PROSE IS WRITTEN WITHOUT AN HTML ENTITY ON PURPOSE.**
`withDerivedTips()` builds an `<h2>`'s tooltip from the first note under it
through `plainTextOf()` and `esc()`, and an entity that survives into that
attribute shows as its own source text. Every other note in this console happens
to be cut before its first one; the *What it wrote* note was the first that was
not, and rewording it was cheaper than teaching the tooltip pass to decode.

## `/admin/users/new` LOST ITS NAV ROW AND BECAME A DRILL-DOWN (2026-09-06)

It shipped with a row in **Directory**, between *Users* and *Groups*, and it was
there for one day. What a row there said is that **creating a person is a PLACE
in this console** — a destination you go to and come back from, like *Groups* or
*Audit log*. It is not: it is the next step from the list you are already
looking at. The Create box on `/admin/users` is a GET form that carries the typed
name to it, and the *Create another* link on its own success page is the only
other way in.

**THE RULE IS THE ONE `sectionPages()` ALREADY IMPLIED AND NOBODY HAD WRITTEN
DOWN.** A row in `SECTIONS` is a DESTINATION; a page that only makes sense as
the next step from another page is a DRILL-DOWN, and this console already had
seven of those with no row — the three delegation drill-downs, the three
pictures, `/admin/tokens/credential` and `/admin/tokens/set`. The neighbouring
sections make the same distinction without needing it said: **Groups and Roles
both create from a form on the list page and neither has a *New group* tab.**

It is the same test the section above applies to `SCIM metrics`, read the other
way round. There, the question a page answers put it in a different section;
here, the question it answers — *what do I do next with this list* — means it is
not a section item at all.

Three consequences, and each is done rather than assumed:

* **It is drawn with `active` = `/admin/users` and an `up`.** That marks the
  Users tab and — because `up` is what `navItem()` reads — draws it as a LINK
  rather than as the dead text an active tab would otherwise be, so the way back
  is on the page. The trail reads `Admin console › Users › New user`.
  **All SEVEN `respond()` calls on that path pass it**, which is why they go
  through a `newUserUp(leaf)` helper rather than seven literals: two refusals
  redraw the form, Fill redraws it, and the success page shows a generated
  password ONCE — the single response a reader must not be stranded on, and the
  one a seventh literal would have missed. The leaf is a parameter because that
  success page is titled `User created`, and `trailBar()` puts the leaf where
  the `<h1>` says the same thing.
* **`/admin` stops listing it**, because `consoleGuide()` is derived from
  `SECTIONS`. So the *Users* blurb now carries what the removed row said: the
  Overview page still describes the create flow, on the page it belongs to.
  A blurb is prose about one page, and this is the case where the page that owns
  the prose is the list rather than the form.
* **`GET /admin-api/users/new` STAYS.** Rule 7 requires an operation for every
  console PAGE and says nothing against one for a drill-down — `/admin/delegation/map`
  has none and that is fine too. The catalogue this one publishes is what a
  script builds a create from, and `tests/vendored/bulk_load.js` reads it.
  Deleting a working operation to tidy a table would be a regression dressed as
  consistency.

**`/admin/applications/new` LOST ITS ROW THE SAME DAY**, asked for separately
rather than swept in by analogy, and it is the CLEARER of the two cases.
`/admin/users/new` is the only way to create a person, so a reader could at
least argue its row was a destination. This one is not even that: the
Applications list has carried a short *Add an application* row since it grew its
six actions, and both it and this page POST to `/admin/applications` with
`action=create` and reach one `createApplication()`. **The sidebar was offering
a tab for the LONGER OF TWO FORMS ON ONE PAGE**, which is a fact about that
page's layout and not a place in this console.

Two things differ from the Users move and both are worth knowing:

* **Its door is a BUTTON (`a.btn`), not a GET form.** The Users page has a box
  that carries the typed username onward; this page has nothing to carry,
  because a bare identifier is what the short row below the button is for. So
  the door is a link that looks like the next action, which is what it is. What
  it replaced was a `<p class="sub">` with a link inside it — fine while the
  sidebar also offered the page, and not fine as the only way to it: a sub
  paragraph is what a reader skims, and skimming it now means never finding the
  protocol families, the per-protocol identifiers or the redirect URIs.
* **It has ONE `respond()` where the Users page has seven**, so it needs no
  `newUserUp()`-style helper. It POSTs to `/admin/applications`, so a refusal
  and a success are that page's 303 with a message; there is no redraw here to
  lose a trail on.

`GET /admin-api/applications/new` stays, on the same reasoning as the Users one:
the catalogue it publishes is what a script builds a create from.

---

## The API explorer is a page of this console now (2026-09-09)

`/admin/api-explorer`, built by **`admin-ui/api_explorer.js`** at 19a. It is the
third page in this console that this file does not draw — `sts_metadata.js` and
`crypto_metadata.js` are the others — and it is the first with a **script** on
it.

**IT MOVED RATHER THAN BEING WRITTEN.** It was `GET /admin-api/docs`, hanging
off the management API it documents, and that was right for as long as that API
was open to anybody. On 2026-09-09 it stopped being: `/admin-api` requires an
OAuth 2.0 access token now, and **a browser navigating to a URL carries none**.
So the one page in this service whose entire purpose is to be opened in a
browser became the one page a browser could not open — this console linked to
it, and the link answered 401.

**So "this console is `script-src 'none'`" is now "every page of this console
except one"** — the claim is qualified wherever it is made, and the XACML
editor's version of it is unaffected because that page genuinely has no script
and would still not have one if this page had never moved.

**THE MOVE IS A STRONGER GATE AND NOT A WEAKER ONE**, which is worth saying
because "we moved it out of the authenticated API" reads the other way round.
Before: no credential at all. After: a sign-on session, plus Admin Read or Admin
Write, plus — for every call the page makes — an access token carrying only what
those roles grant.

### The token the page is handed, and the line it must not cross

The explorer's whole value is the Try it button, and Try it calls `/admin-api`,
which requires a token. So the page mints one, through `oauth2.accessToken()` —
the same function the token endpoint calls, so there is one place in this
service where an access token is built — carrying the scopes the reader's OWN
console roles grant and no others: `admin:read` for Admin Read, `admin:write`
for Admin Write.

**IT IS NOT A BYPASS AND MUST NEVER BECOME ONE.** The API still checks that
token on every call, against the same `access-control` document that decides
every other access here. A reader holding Admin Read gets a token that reads,
presses Try it on a POST, and is refused 403 by the policy — the same answer
they would get from a terminal. What the console removes is the step where a
person copies a credential out of a shell and into a form; it removes no check.

**MINTED IN THE DEFAULT REALM WHEREVER THE PAGE IS READ**, for the reason the
two console roles are pinned to that realm: `admin_api.js` verifies against the
default realm's key and computes the audience outside any realm, because that
credential is service-wide. A page that minted with the ambient realm's key
would hand out a token its own API refuses, inside every realm but one.

**THE TOKEN IS IN THE PAGE AND NOT IN `?format=json`.** A page handing a
credential to a browser it has already authenticated is a different act from an
API handing one to whoever asked; `tokenInReply: false` is on the JSON view so
that its absence is a statement rather than an omission.

### Three routes, and the two that are not the page

`/admin/api-explorer/explorer.js` is the script, a separate resource rather than
an inline block precisely so that `script-src 'self'` suffices and
`'unsafe-inline'` is never needed — the rule the root `CLAUDE.md`'s table of six
scripted pages states, applied here for the sixth time.

`/admin/api-explorer/openapi.json` is the document, **served from the console's
own path rather than fetched from `/admin-api/openapi.json`**, and that is not
cosmetic. The API path needs a token, and the page's first act is to fetch its
document — so the explorer would need its credential before it could draw
anything at all, and a missing one would mean a page that fails to render rather
than a page that renders and says so. On this path it arrives on the session the
page was already drawn with. It is BUILT by `admin_api_spec.buildSpec()` from
`admin_api.js`'s own route table, so it is the same document by construction.

### The realm prefix is applied by two different mechanisms and exactly once each

This is the part to get right, and getting it backwards fails in exactly one
realm out of two. `app.js` rewrites every root-relative `href`, `action` and
`src` in an HTML response to carry the current realm's prefix. So:

* the **script URL** goes into the markup BARE, because that rewrite will add
  the prefix — writing it in as well produces `/realm/acme/realm/acme/…` and a
  page whose script 404s in every realm but the default;
* the **document URL** is a `data-` attribute, which the rewrite does not touch
  — it is a string a script reads rather than markup a browser resolves — so it
  carries the prefix explicitly.

That is the same split the page had at `/admin-api/docs` and it is restated in
`api_explorer.js` beside the code, because neither half is guessable from the
other.

### What did not move

`mgmt-api/admin_api_docs.js` and `mgmt-api/admin_api_explorer.js` are still in
that directory: the stylesheet, the browser script and the realm-prefix argument
belong to that API's document rather than to this console's shell, and this page
requires them. `admin_api_docs.js` grew a `consoleBody()` beside its `page()` —
the old whole-document builder is kept and exported, because the STYLE, the
SCRIPT and the prefix argument are the same in both shapes and a second copy of
any of them is what that file exists to prevent. Nothing registers a route for
`page()` any more.

## THE TWO SECOND FACTORS: `/admin/totp`, `/admin/webauthn`, AND THE ROSTER ON `/admin/users` (2026-09-10)

**THIS SECTION DESCRIBED ONE PAGE, `/admin/mfa`, AND THAT PAGE LASTED HOURS.**
It is the shortest life anything in this console has had, and the record of why
is worth more than the page was: it did TWO things and could only be filed by
one of them.

  * It edited the eight `totp.*` settings. `config.js` declared a group called
    `Multi-factor authentication` and `checkSettingHomes()` refuses a group with
    no page, so those rows had to live somewhere.
  * It drew a ROSTER — who holds a second factor, across this realm — with a
    Clear button on every row, because nothing else in the service could answer
    *who is configured for MFA*.

The old section argued at length that the page belonged under Identities,
because *where a page is FILED is decided by the question it answers* and this
one answered a question about PEOPLE. **That argument was right about the roster
and wrong about the settings**, and one page cannot be filed by both halves: a
reader looking for the skew window and a reader looking for *who has no second
factor* landed on the same screen and read past each other.

So it split along the question each half answers, which is the same rule applied
properly:

| Half | Where it went | The question |
|---|---|---|
| the `totp.*` settings | **`/admin/totp`**, Protocols | what does the MECHANISM do |
| the `webauthn.*` settings — **which did not exist** | **`/admin/webauthn`**, Protocols | the same, for the other one |
| the roster, the counts, the filter | columns on **`/admin/users`**, Directory | who holds what |
| the per-person detail and both Clear buttons | that person's own row under `/admin/users` | what does THIS person hold |

### WebAuthn had no settings at all, and the sentence that explained why was wrong

The old section said it plainly: *what a ceremony does is decided by the
specification and by the browser*, so there was nothing to put on a page.
`common/config.js` said the same thing above the TOTP rows.

**It is true of the cryptography and false of the ceremony.** What a browser
does with `navigator.credentials.create()` is decided almost entirely by the
`PublicKeyCredentialCreationOptions` the relying party hands it — the RP name,
the algorithms offered, the user verification requirement, the attestation
conveyance, the timeout, the CTAP2 attachment and resident-key preferences —
and every one of those was a literal inside a string in `authn/authn.js`. A
client author trying to find out what their client does with `attestation:
"none"`, or with a discoverable credential, had no way to ask this service for
one.

There are thirteen rows now, in three kinds, and `/admin/webauthn` says which
kind each is because the difference decides what it means:

  * **CEREMONY** — handed to the browser and no more.
  * **CTAP2** — handed to the browser, and translated by it into what it asks
    the AUTHENTICATOR for. Same standing: a request, not a check.
  * **POLICY** — `enabled`, `primaryAllowed`, `mfaAllowed`, `maxKeysPerPerson`.
    Not WebAuthn at all: what THIS service will do with a key once the ceremony
    is over.

**ONE OF THEM IS ENFORCED AND THE REST ARE REQUESTS**, which is the sentence to
keep. `webauthn.userVerification` is sent to the browser AND checked against the
UV flag when the ceremony returns, because that flag is inside the bytes the
authenticator signed. Nothing signed says what the browser was asked about
attestation, the resident key or the attachment — so a check on those would be a
comparison against a value this service itself supplied. What it does instead is
RECORD what came back.

**RAISING USER VERIFICATION DOES NOT CHANGE WHAT A SESSION CLAIMS.** A
passwordless sign-in still records `amr ["hwk"]` and `acr "1"` even under
`required`. RFC 8176 has no value for *the authenticator verified the user* that
this service could honestly assert, and claiming `mfa` because the ceremony was
phishing-resistant would be the exact fake this profile refuses everywhere else.
The page says so rather than leaving it to be discovered.

### The mechanism report is the reason either page is worth having

Both pages carry a `status` block — the same optional member `/admin/persistence`
has, and invented for its reason: a settings page describes what this service is
CONFIGURED to do, and these two also have to say what the MECHANISM is. Which
digests exist as against which one is in use; which COSE algorithms this relying
party can VERIFY as against which two it is offering.

**Every table in it is read from the module that performs the algorithm** —
`common/totp.js`'s `report()` and `authn/webauthn_policy.js`'s — which is the
rule `/admin/crypto-metadata` is built on, one layer down. A page that wrote the
list out would describe something this service does not do the first time one
was added. `tests/vendored/sts_second_factor_pages.js` is what makes that mean
something: it CHANGES a setting and requires the report to move with it, because
reading the report on its own says nothing — a hand-written table is well-formed
too.

### The roster widened the Users page's POPULATION, and that was not optional

`/admin/users` listed identities this service had SEEN authenticate, and its own
lead paragraph said so. The roster it absorbed is the union of that with this
realm's DIRECTORY people — and the difference is exactly the people the roster
is for, because **the people most likely to hold no second factor are the ones
who have never signed in.**

The gap is smaller than it looks and it is not zero. Every door that creates a
directory person — the console, `POST /admin-api/users/create`, a SCIM create,
an LDAP add, a restore from the store — calls `stats.noteKnownIdentity()`, so on
a small service the union adds nothing at all. **But the registry is capped at
`stats.MAX_USERS` and the directory is not**: two thousand against
`ldap.maxEntries`, so a realm that has been bulk loaded has thousands of people
invisible to every console page that asks a question about people. `peopleRows()`
is the union and it is keyed by the IDENTITY KEY rather than by the name, because
this page's premise is that one row is one local name across every protocol.

**And the drill-down had to learn to answer for somebody the registry has never
seen.** Until it did, clicking one of the new rows landed on *nothing here has
authenticated as alice* — a true sentence and a useless page, since that is
exactly the person whose second factor an operator came to look at, and both
Clear buttons are on it.

### The reset is the point of the write half, and it is not a convenience

Unchanged from the old page, and it is now on the person's own row.

A one-time password secret lives on a DEVICE. **There is no *forgot my
authenticator* flow anywhere in this service and there cannot be one** — a
self-service reset of a second factor is a second factor anybody can remove,
which is no second factor. So when somebody loses their phone, an operator
clearing the enrolment is the ONLY way back, and a service that enforces a
factor it cannot clear has a support queue rather than a security control. It is
`credentials.removeKey()`'s argument about the last way in, made from the other
end.

**The two removals are not the same act and the buttons say so.** Clearing an
authenticator CANNOT lock anybody out: a one-time code is never a primary
credential, so it drops an account to one factor and never to none. Removing a
security KEY can — it may be the only credential there is — so it goes through
`credentials.removeKey()`, which refuses to remove the last way in. An operator
must not be able to do what the owner is stopped from doing.

**There is deliberately NO enrol action**, here or on `/admin-api`. Enrolling an
authenticator means being SHOWN a shared secret, and an administrative door that
handed one out would mint a working second factor for any account. A WebAuthn
ceremony happens in the person's own browser against their own authenticator,
which no console can stand in for. Both are `/portal`, or an activation link.

### The unreadable row is the one to look for

`totpUsable: false` means an enrolment exists that this process cannot read —
almost always a secret sealed under a key-encryption key that has since been
rotated. Those people are REFUSED at the code step rather than let through on
one factor, so they cannot sign in AT ALL until it is cleared. `/admin/users`
says so in a banner with a link to `?factor=unreadable`, rather than in a
column, because it is the one state on the page that needs acting on.

### The refusal sentence has to name the actions, and the first version did not

`mfaAction()` checked for a missing `username` before it checked the action, so
a probe posting an unknown action with no body was answered *name the person*.
**`tests/vendored/sts_admin_api_operations.js` reads the refusal sentence from
every action resource** to check that it NAMES the actions it knows — which is
how `tests/vendored/admin_api.js`'s parity check discovers what to look for — so
a resource that answers something else turns that check off for itself with
nothing failing. It went red immediately, which is the whole reason that
assertion exists.

**The rule outlived the function.** `mfaAction()` is `usersAction()`'s
`clear-totp` and `clear-key` now, and that switch's refusal is built from
`USERS_ACTIONS` rather than typed — so the five it knows are named by
construction and a sixth added tomorrow cannot be short by one.

### `GET /admin-api/mfa` is kept and its page is gone

Rule 7 says a console control owes an API operation. It says nothing about an
operation whose page moved, and deleting a working one to tidy a table would be
a regression dressed as consistency — the argument `mgmt-api/CLAUDE.md` already
makes about `GET /admin-api/users/new`.

**It answers OUT OF THE USERS VIEW**, so there is ONE tally: a second scan of the
credential store would be a second answer to how many people hold a second
factor, and the two would agree until the day they did not. The reply keeps its
own flat `people` shape, because a caller reading `people[].mfaRequired` is not a
caller who should have to learn that a console page moved. `GET
/admin-api/users` is where the rows carry `factors` instead, and both clear
actions answer on both paths.

---

## `/admin/signals` — THIS CONSOLE IS A SHARED SIGNALS RECEIVER (2026-09-10)

It has a **stream of its own** — `sts-admin-console`, seeded in every trust
realm — asking for every CAEP and every RISC event type; each event is POSTed
to `/admin/signals/receive` over RFC 8935 push carrying that stream's own
bearer token; and this page draws what arrived. `ssf/ssf_receivers.js` holds the
design and `ssf/CLAUDE.md` argues it. Four things belong here.

**IT IS FILED UNDER `Monitoring`, WHICH IS THE FIFTH INSTANCE OF THE RULE AND
NEEDED NO DELIBERATION.** Where a page is filed is decided by the question it
answers. This one answers *what has this console been told* — traffic, in
memory, since the process started, with the audit log as the durable half —
which is the same shape of question `/admin/xacml/monitor` and `/admin/scim`'s
metrics page answer. The Shared Signals settings and every stream, including
this one, stay at `/admin/ssf` under Protocols: that is where somebody goes to
change what arrives here rather than to read it.

**IT IS THE ONE PAGE IN THIS CONSOLE ABOUT SOMETHING THIS CONSOLE WAS SENT.**
Every other page here reads a store this process holds. This one reads a queue
delivered to it over HTTP, signed, addressed to it by name, which it verified —
and that is the whole difference between a console showing its own notes and an
application that is a receiver. **It is therefore the only one of the four
Shared Signals pages that goes empty when delivery is broken, and so the only
one that can report that it is.** `/admin/ssf` shows what was SENT;
`/admin/caep-sessions` and `/admin/risc-accounts` show what this service
BELIEVES about a session and an account; all three are full and correct while
nothing reaches anybody.

**AN EMPTY PAGE HAS FIVE CAUSES AND ONLY ONE OF THEM IS "NOTHING HAS
HAPPENED",** so the ones that apply are drawn above the table rather than left
to be guessed: `ssf.enabled` off, `ssf.internalReceivers` off, the stream
deleted, `ssf.pushDelivery` off, or `caep.enabled` / `risc.enabled` off under
it. That is `status().why` and it is drawn even when rows ARE present, because a
stream paused since this morning explains a page that STOPS rather than a page
that is empty. It is the same argument `caep.js`'s "no stream takes it" line
makes: *nothing arrived* is the commonest report about any Shared Signals
deployment and it is almost never what it looks like.

**ITS ONE CONTROL CLEARS WHAT IS HELD AND NEVER THE STREAM.** Clearing what a
receiver has been shown and tearing down the agreement to send it more are two
different acts, and the second is `/admin/ssf`'s. The audit log's
`ssf.event.receive` row for every delivery stays either way, there being no
clear operation for that anywhere — which is what makes it the durable half.

**Rule 7 is paid by `GET /admin-api/signals` and `POST
/admin-api/signals/:action`**, both over the same two functions this page uses.
The portal's copy of this page has **no** management API operation and that is
deliberate: it is a person's own account page, narrowed to them by their
session, and an administrative door onto "what was alice shown" would be a
second answer to a question `/admin/signals` already answers completely.

## MONITORING → SHARED SIGNALS: A GROUP, AND `/admin/ssf/dead-letters` (2026-09-14)

**THE FIRST GROUP UNDER MONITORING.** CAEP sessions, RISC accounts and Signals
received were three loose rows, each filed there on its own argument; a
dead-letter page made four answers to one family's *what happened*, and rcbj
asked for it as Monitoring → SSF, which did not exist. So `SECTIONS` grew a
`Shared Signals` group where the first two were, beside Delegation, and Signals
received moved into it from after SCIM metrics. **No path moved** — `NAV` is
derived, so nothing but that table changed for the three pages. The filing rule
is untouched: Protocols → Shared Signals is what the streams are configured to
do and holds every control; the group is what happened.

**`/admin/ssf/dead-letters` IS READ-ONLY** (rcbj's choice). Revive and Drop its
dead letters act on one stream and stay on that stream's card, which every
stream row links to at `/admin/ssf#stream-<id>` — the card's `<h3>` carries that
id now, and its dead-letter note links back filtered to the stream. Rule 7 is
`GET /admin-api/ssf/dead-letters` with no POST beside it. `ssf/CLAUDE.md` argues
the numbers.

**IT DRAWS THE FIRST CHART IN THIS CONSOLE**, and three choices were made rather
than inherited:

* **A stacked column per time bucket, one colour per CAUSE** (four), not per
  error code (more than a dozen). The colours were checked with a colour-vision
  validator: worst adjacent pair ΔE 9.1 under protanopia, 22.9 in normal vision.
  Two are under 3:1 against the white card, so no value is carried by colour
  alone — the legend names each cause and count in text, and the same numbers
  are a table under the chart.
* **No script, so the hover is an SVG `<title>`** on a hit area the full height
  of the plot, and the SVG has `role="img"` with a sentence for `aria-label`.
* **Laid out on the server** like the delegation and federation pictures; the
  stylesheet gained only `.chart`, `.legend` and `code.ec` (an error code that
  never breaks inside itself).

The page's own `LIST_PARAMS` row carries `dlq`, `dlstream`, `dlcause`, `per` and
`lettersPage`, spent by its links between tables.

## `/admin/backup-codes`: THE THIRD MECHANISM PAGE, AND THE ONLY ONE ON THIS CONSOLE THAT IMPLEMENTS NO SPECIFICATION (2026-09-10)

Recovery codes — the way back in when the second factor is not to hand. A page
of its own beside `/admin/totp` and `/admin/webauthn`, under Protocols, with the
group `Backup codes` in `SETTING_HOMES`.

**It is not a section of `/admin/totp`**, and the reason is the filing rule this
console already applies: a recovery code stands in for EITHER of the two
mechanisms above it, so putting its settings under one of them would put them
where half the people looking would not look. The question this page answers —
*how does somebody get back in* — is neither of those pages' question.

**THE `status` BLOCK HAS NO SPECIFICATION COLUMN BECAUSE THERE IS NO
SPECIFICATION.** Every other mechanism block here reports what a document says
this service does; nobody ever wrote one for a recovery code. So every field in
`backupCodesMechanismBlock()` is a decision this service made, read from
`common/backup_codes.js` — the module that generates and compares a code — the
way every `status` block on this page is read from the module that performs the
thing. `bitsPerCode` is the field to read first: it is the number that decides
whether the mechanism is worth anything, and a length and an alphabet size left
for a reader to multiply is a number nobody works out.

### The per-person block on `/admin/users`, and what this console must never draw

A third block on that person's row, beside the authenticator and the keys, built
entirely from `credentials.mechanismsFor().backupCodes` — a STATUS object that
carries counts and no codes.

**THERE IS NO CALL ANYWHERE IN THIS CONSOLE TO `credentials.revealBackupCodes()`
AND THERE MUST NOT BE.** Showing a set here would hand a working second factor
to whoever holds Admin Read, which is the same door this console already refuses
to open for an authenticator enrolment: *enrolling means being shown a shared
secret, and an administrative door that handed one out would mint a working
second factor for any account.* The person reads their own set on
`/portal/mfa`, and `common/credentials.js` splits the two questions into two
functions precisely so that a page which wanted the count cannot render the
codes by accident.

### The Clear is an ISSUING control as well as a removal, which the other two are not

Clearing an authenticator app or a key takes a factor away and that is all it
does. **Clearing the recovery codes takes the way BACK away and, by doing so,
re-arms the automatic issue**: `credentials.ensureBackupCodes()` does nothing
while a set exists, so the next second factor that person enrols creates a new
one. That is the whole route to a second set, and it is deliberately an
operator's act — a way back a person can reissue for themselves is one an
attacker who reached their session can reissue too.

It cannot lock anybody out: a recovery code is never a way in on its own. What
it removes is the thing that stops a lost phone being final, which is why the
button says so and why the act is audited like the other two
(`admin.mfa.backup-codes.cleared`).

**`USERS_ACTIONS` gained `clear-backup-codes` in the same change**, which is not
cosmetic: `tests/vendored/sts_admin_api_operations.js` reads the refusal
sentence that list builds in order to discover what to check for, so a list
short by one turns the parity check off for that action.

## `/admin/policies`: DIRECTORY → POLICIES, AND A GENERATED PASSWORD BY DEFAULT (2026-09-12)

Asked for by rcbj as *Directory → Policies*, with the password policy as the
first kind of policy it configures. `common/CLAUDE.md` 3ac argues the model and
the store; three things are this console's.

**IT IS IN DIRECTORY BECAUSE ITS STORE IS, AND IT IS A DESTINATION.** Every page
in that section draws something the directory holds, and this draws
`ou=passwordPolicies`. It is not a drill-down — nothing else here leads to it as
a next step — which is the test the two `/new` pages failed and this one passes.
**The label is shared with `/admin/xacml/policies` and the `/admin/ldap/policies`
group row**, and the blurb says the difference on the Overview rather than
renaming what rcbj asked for: those draw `ou=policies`, documents a PDP
evaluates; this draws profiles `credentials.setPassword()` checks.

**THE FORM IS THE FIELD TABLE, AND THE RESET IS A SECOND FORM.** Every row of
`password_policy.FIELDS` is one input — a `number` carrying the field's `min` and
`max`, or a checkbox — so the browser's refusal and the server's are the same
numbers. A save REPLACES the profile and posts every field; the action is told
`via: 'console'` so an unticked checkbox (which posts nothing) reads as "no"
there and as a missing field from an API caller. **Put the built-in defaults
back** is its own `<form>` rather than a second submit button, for
`/admin/users/new`'s two-buttons trap. The page shows, beside the form, the rules
as the portal prints them, every door the policy is enforced at, what the history
costs in scrypt comparisons, the generator, the paged profile list and the
container's schema.

**THE NEW-USER FORM PRESELECTS `generate`**, and `DEFAULT_CREDENTIAL` is declared
in `admin-core/admin_actions.js` because the action is what applies it and the
require between the two layers goes views to actions; `admin_views.js`
re-exports it and `newUserJson()` publishes it with the rules. The note under
the password boxes said *there is no strength rule and that is deliberate* and
now says which rules apply and whether this realm enforces them.

Rule 7 is `GET /admin-api/policies` and `POST /admin-api/policies/{action}`, in
the same change, over the same two functions.


## `/admin/error-codes`: THE ERROR CODE TABLE, UNDER MONITORING (2026-09-12)

The table is `common/error_codes.js` (rule 3ac in `common/CLAUDE.md`) and
`docs/error-codes.md` is generated from it, so this page is not a third copy of
the catalogue: it is the table FILTERED and PAGED with the one column a
document cannot have — how many rows in this realm's held audit log carry each
code, each count a link to `/admin/audit?code=`. **That column is why it is
filed under Monitoring beside the audit log** and not under Server
configuration: a reader arrives holding a code off a row or a log line, and the
page answers both *what does it mean* and *which failures has this service been
producing*.

Three things about it are decisions:

* **The count is of the HELD rows in the ambient realm**, the ones
  `/admin/audit` lists, so it falls as that ring's cap discards the oldest, and
  it is zero for a failure recorded only as a log line — a startup refusal, and
  everything the remote PEP container logs. The page says so, because a zero
  reads as "never happens" otherwise.
* **A code on a held row that the table does not hold is listed**, never
  dropped: `mark()` and `audit()` record an unregistered code as given exactly
  so that this row survives.
* **No control.** A code's meaning is source; renumbering one at runtime would
  make every alert rule written against it describe a different condition.

`admin-core/admin_views.js`'s `errorCodesView()` builds it and
`GET /admin-api/error-codes` answers from the same function — rule 7 with no
POST beside the GET, because the page has nothing to change.

## `/admin/kerberos/principals`: WHO THE KDC HOLDS A STORED KEY FOR (2026-09-12)

Under Protocols, directly beside `/admin/kerberos`, and **Admin Write** for its
controls. Two tables — directory people whose keys were derived from their own
password, and service principals created here with a random key — each paged on
a parameter of its own (`peoplePage`, `servicesPage`) because one `page` cannot
page two lists. **Until 2026-09-13 neither was read**: the view passed
`pagedRows()` a `param` option, which `pagingOf()` does not read (it builds the
name from `name`), so both lists followed a bare `?page=` while the links wrote
the other two, and every next link reloaded page 1
(`tests/kerberos_principals_paging.js`). A row carries enctypes, kvno, salt and when; **never a key**.
`kerberos/CLAUDE.md` argues the feature; three decisions are this page's.

* **A CREATE OR A ROTATE ANSWERS WITH A PAGE AND NOT A DOWNLOAD.** The keytab is
  the one time key material leaves this service, and a raw `application/octet-
  stream` reply would be a file with nothing beside it saying which kvno it
  holds, which enctypes, or that it cannot be fetched again. So the reply is a
  "Kerberos keytab" page — the warning that it is shown once, the principal and
  kvno, a `data:` link to save it and the base64 in a read-only textarea — which
  is `/admin/pki/person`'s arrangement for a person's private key, and for its
  reason: `respondToAction()` 303s with a message on the query string, and key
  material on a query string lands in history, logs and the next `Referer`. It
  is also what lets `sts_admin_console.js` assert the page rather than a
  download the browser would swallow.
* **A JSON CALLER GETS THE ACTION RESULT**, keytab included, through
  `respondToAction()` exactly as before; only a browser form gets the page.
* **THE TRUST REALM IS THE ONE THE PAGE IS READ IN, SINCE 2026-09-15 (#33)**, and
  the page says which. This read *THE TRUST REALM IS THE DEFAULT ONE WHEREVER THE
  PAGE IS REACHED … the KDC is one process-wide socket family, and drawing a realm
  prefix's own directory here would describe people the KDC will never ask about*.
  That KDC is per realm now, told apart by the Kerberos realm name on the shared
  port, so the people drawn here are exactly the ones this realm's KDC asks about.
  **A realm whose Kerberos is OFF says so** rather than showing two empty tables
  that read as a service holding nothing, and the page left
  `admin_scope.js`'s SERVICE_PAGES the same day: a realm administrator manages
  their own realm's principals and keytabs. What stayed service-only is per
  SETTING — the two sockets and the development-mode trust.

`encryption_admin.js`'s `DATA_CLASSES` gained a `kerberos-keys` row, because the
two key attributes are sealed under that label and the encryption report refuses
a label with no row.

**PREVIOUS KEY VERSIONS (later the same day).** Each table grew a *Previous
versions* column — kvno, enctypes and when each stops being accepted — and each
row a **Drop previous versions** button, drawn only while a version is kept,
because a button that could only ever answer `dropped: 0` is a control that
reads as broken. The keytab page a rotate answers with names every version in
the keytab. The note above the tiles states the bounds as they stand now, with
zero in `krb5.retainedKeyTtlS` already turned into the seconds it means, since a
reader of that page is deciding whether to press Drop.

## `/admin/applications?application=…` HAS A CREDENTIALS SECTION (2026-09-13)

Asked for by rcbj: the application's page shows its client secret and the key
pairs mapped to it, and replaces a key pair either by issuing one from the
realm's CA or by uploading a certificate — an external CA's with its full
chain. `common/CLAUDE.md` 3w argues the chain rules; four things are this
console's.

* **THREE KEY-PAIR CONTROLS PER PROFILE AND ONE NEW ACTION.** Issue and Take off
  post to `/admin/pki`'s existing `issue` and `revoke`; Upload posts the new
  `upload-certificate` beside them. All three carry `from=/admin/applications`,
  and `pki_admin.js`'s `pkiReturnTo()` sends the reader back through the new
  export `admin.applicationReturnTo()` — which rebuilds the destination from
  the identifier and the `back` list state rather than echoing a URL, for
  `permissionsReturnTo()`'s reason. **Moving a form is not moving an action**,
  so `/admin-api/pki/{issue,revoke,upload-certificate}` mirror all three with no
  second operation. The Issue control is not drawn where the realm has no CA,
  because its only outcome there is a refusal; Upload still is.
* **MUTUAL TLS (RFC 8705) IS THE THIRD SUBSECTION** (2026-09-13),
  `applicationMtlsSection()` over `adminViews.applicationMtlsState()` (JSON as
  `credentials.mtls`): the declared method, the TLS client certificates this
  realm issued the application with a Revoke form each, the Issue form, the five
  subject parameters and the bound-tokens flag. Drawn only where `oauthDeclared`,
  for the assertion profiles' reason. **An ISSUE is answered with a PAGE and
  never a redirect** — `answerIssuedTlsClientCertificate()`, three `data:`
  downloads under `no-store` — because the reply carries the only copy of the
  private key; the route catches the promise and redirects a refusal as every
  other action does (`STS-ADMIN-0724` for a throw). `oauth-oidc/CLAUDE.md` 3an
  argues the feature.
* **THE SECRET IS REGENERATED THROUGH THE APPLICATIONS HANDLER** —
  `regenerate-secret`, an arm of `applicationsAction()` over
  `applications.regenerateClientSecret()` — and the redirect carries the
  message only, landing on `#credentials`. The new value is on the page behind
  the same `<details>` the old one was, and in the API reply; a secret in a
  query string would be in the history and every log on the way.
* **THE SECTION RENDERS `adminViews.applicationCredentialsState()`**, whose
  JSON half is `credentials` on `GET /admin-api/applications?application=` and
  deliberately carries NO secret and NO private key — both are already in that
  reply's `fields`, and a second copy is one more place to pick them up. The
  attribute names per profile come from `applications.KEY_PAIR_ATTRIBUTES`,
  which `pki_admin.js`'s `PURPOSE_WRITES` reads too, because the view layer
  cannot require `pki_admin.js` (it would close a cycle through this file).
* **IT SITS ABOVE THE RAW ENTRY TABLE**, which still prints every attribute,
  private keys and secrets included, as it always has.
* **`POST /admin/pki` NOW MAPS A SUCCESS'S `why` TO `message`.** Every PKI
  action says what it did in `why`, and `respondToAction()` redirects with
  `message` — so every notice from that handler was `notice=undefined`.
  `/admin/pki` draws no notice and nobody saw it; the application page does.

`tests/vendored/sts_admin_console.js` presses every button it finds, and on an
application page that now includes Regenerate and Take off: both are safe to
press on any entry the walk reaches (the console's and portal's own clients
read their secret fresh on every sign-in, and `sts-management-api` is refused
while `adminApi.clientSecret` pins it).

## THE CERTIFICATE DETAILS DIALOG, ON `/admin/pki` AND `/admin/crypto-metadata` (2026-09-13)

Every certificate row on both pages carries a **View details** link, and it
opens a dialog over the page — in the same tab, with an **X** at the top and a
**Close** button at the foot — holding the certificate's every X.509 field and
its trust chain. `certificate_dialog.js` is the ONE renderer both pages call;
`admin-core/certificate_views.js` decides which certificates may be opened and
`common/certificate_details.js` is the model.

**IT HAS NO SCRIPT, AND THE ROOT CLAUDE.md'S TEST FOR ONE WAS PASSED RATHER
THAN ARGUED AROUND.** A dialog is the thing a reader most expects a script
behind, and this one needs none: the link adds `?certificate=<SHA-256>&from=<section>`
to the page it is on, the route resolves that certificate and draws the page
with the dialog over it, and the X and the Close button both go back to the page
without the parameter, at the section the link was pressed in. So both pages are
still `script-src 'none'`, the URL is the open dialog (bookmarkable, reloadable,
closed by Back), and only the certificate asked for is parsed. **The CSS
`:target` alternative was refused** because it pre-renders every dialog on every
render, and `/admin/pki` holds dozens of certificates.

**THE CLOSE BUTTON IS A REAL `<button>` IN A GET FORM**, because a button was
asked for and a keyboard and a screen reader announce one; its address gains a
bare `?`, which is what a GET form with no fields submits. The X is a labelled
link. Neither carries a `target`.

**WHAT IT COSTS**: a round trip per open, which every control here already pays.
And the dialog is drawn at the foot of the page's own body, after every form, so
it cannot be adopted into an open `<form>` by the parser — `--dump-dom` is the
check, and `formsInDialog` is one.

**`renderPki()` TAKES A SIXTH ARGUMENT** — the resolved view — and
`/admin/crypto-metadata`'s route does the same inline. Both put the answer on
their JSON as `certificateDetails`, so `?format=json&certificate=` answers for a
page exactly as `GET /admin-api/certificates?certificate=` does. The crypto
report grew `certificateFingerprint` on the signing key, every curve key and
every post-quantum key, `tls.certificates[]` and `spiffe.authorityFingerprint`;
the signing key's `certificate` string had said *self-signed, SHA-256, serial 02,
five years* since before the hierarchy existed, and says which it is now.

A refused open (a fingerprint not held, or not a fingerprint) still draws the
dialog, saying why, and marks the response `STS-ADMIN-0640`/`0641`; a link that
did nothing would read as a broken control. `tests/certificate_details.js` pins
the renderer in a child process.

## THE POST-QUANTUM ICON ON `/admin/pki` AND `/admin/keys` (2026-09-13)

Every key pair that uses a post-quantum algorithm carries a small lattice icon
with a word beside it: `PQC` (ML-DSA, SLH-DSA), `PQC+` (a composite),
`PQC KEM` (ML-KEM) and a dashed `PQC alt` (a classical key whose certificate
carries an alternative post-quantum key). Hovering names the algorithm and the
standard. On `/admin/pki` it is on every row of the tree, the three-tier view,
the workbench store, and the application and person key-pair tables; on
`/admin/keys` it is in each key's Type cell and heading; and the certificate
details dialog shows it beside the key.

**WHETHER is `common/pqc_support.js` and HOW IT LOOKS is `pqc_badge.js`**, and
nothing else decides or draws either — a page that classified for itself would
classify with whichever of four spellings it happened to hold. Each page draws
`pqcBadge.legend()` once, and the legend draws its samples WITH the renderer so
it cannot describe a mark the rows do not use.

Four decisions, each argued in the file:

* **A LATTICE AND NOT A SHIELD OR PADLOCK.** The icon says "a different kind of
  mathematics"; a shield would claim "secure", which an algorithm choice does
  not make a key pair.
* **THE HYBRID IS DRAWN WEAKER** (white, dashed), because its key is not
  post-quantum and a reader who saw the same mark as an ML-DSA key would be told
  something false.
* **THE KEY DECIDES, NOT THE CERTIFICATE'S SIGNATURE** — which is also why a
  certificate is asked first where there is one: only the certificate can show
  an alternative key.
* **NO SCRIPT, NO STYLESHEET, NO IMAGE REQUEST.** An inline SVG with its style
  on the element, so both pages stay `script-src 'none'` and a page that forgot
  a `<style>` block could not render the badge unstyled. `title` for a pointer,
  `aria-label` with `role="img"` for a screen reader.

**`pqc` IS ON THE JSON AS WELL AS THE PAGE**, so rule 7 holds for the icon:
every row of `GET /admin-api/keys` (`keyInventory()` adds it), and every
application and person key-pair row of `GET /admin-api/pki` (`pkiJson()`). The
tree and workbench rows carry their certificates already, and their icon is read
off those — the same function, so the JSON and the page cannot disagree.

## `/admin/users?user=…` HAS A CREDENTIALS SECTION TOO (2026-09-13)

The application page's section, for a person: `userCredentialsSection()` draws
`adminViews.personCredentialsState()` — per profile, RFC 7523 and RFC 7522, the
certificate, chain, handle, source, whether a private key is HELD, and the issuer
asserted as — after the second factors and before the sign-out buttons. Four
differences from the application's, each a fact about the holder:

* **NO PRIVATE KEY, EVER.** A person's has no read door; the model reports
  `privateKeyHeld` and nothing else, and the attribute table the application page
  points at does not exist here.
* **ISSUE POSTS TO `/admin/pki/person`**, because what comes back is the private
  key. That route, given `from=/admin/users`, answers in the console shell — the
  key once, and a *Back to <name>* link built by the new export `userReturnTo()` —
  rather than drawing the PKI page. Upload and Take off post to `/admin/pki` with
  `target=person`, and `pkiReturnTo()` sends them back through `userReturnTo()`.
  `upTo` is exported for that page's trail.
* **THE CONTROLS ARE DRAWN FOR ADMIN WRITE ONLY**, the second-factor section's
  rule beside it.
* **`/admin/pki`'s person table is a row per profile held**, and its person form
  gained a Profile select.

`sts_admin_console.js`'s `thePersonCredentialsSectionIsPressed()` presses all
three and asserts where the browser lands, including that the Issue page's way
back names this person in this realm.

## `/admin/used-assertions`: WHAT THIS REALM WAS HANDED AND SPENT (2026-09-13)

Under **Monitoring**, immediately after **Tokens**, and the pair is the filing
argument: that page is what this service HANDED OUT and this one is what it was
HANDED and spent — every RFC 7523 JWT and RFC 7522 SAML assertion accepted, as
client authentication or as a grant, and not yet expired. It answers *has this
assertion been used, as what, by whom, and until when is that remembered*,
which is a question about what happened rather than about how either profile is
configured. `common/CLAUDE.md` 3ae argues the history; three things are this
page's.

* **IT HAS NO CONTROL, AND THAT IS THE PAGE.** A Forget button would make an
  assertion still inside its validity usable a second time, which is the one
  thing the history exists to prevent. A row goes when the assertion expires.
  Rule 7 is `GET /admin-api/used-assertions` with no POST beside it.
* **THE ROUTE AWAITS A PROMISE.** On a postgres store the history is the
  database's rather than this process's, so `adminViews.usedAssertionsView()`
  is a query and the page and the operation both `.then` it; a store that
  cannot be read is a page saying so (`STS-ADMIN-0643`) rather than a request
  that never answers.
* **IT SAYS WHETHER THE HISTORY SURVIVES A RESTART**, as a note where it does
  and a warning where it does not — the one thing an operator reading a list of
  spent assertions most needs to know about the list.

## `/admin/rbac`'s PERSON PICKER IS A SEARCH, NOT A `<select>` (2026-09-13)

The *Grant a role* form picked the person from a `<select>` holding every
candidate — everybody in the default realm's directory unioned with everybody
who has signed in (`admin_rbac.candidates()`). Once that directory held
thousands of people the control could not be used. It is `chooserPane()` now,
the search and paged results pane `/admin/delegation` uses for people and
applications: `personq` searches, `personfrom` pages twenty at a time with a
stale offset clamped, and **a result is a link that picks** — `person=<name>`,
which opens a grant form (`#grant-picked`) for that person with the name in a
hidden input and a role select beside it. The typed-name form below it is
unchanged, and the header comment's two-forms argument is unchanged with it.

Three things are decisions:

* **`person` is resolved against the candidates, never echoed.** A name the
  list does not hold gets a sentence pointing at the typed form, because the
  picked form's whole promise is that it names somebody the list offered.
* **`personq` and `personfrom` are in `LIST_PARAMS`; `person` is not.** A grant
  or a Revoke lands back on the results the reader was working through, and
  not on a grant form for somebody who now holds the role. The grants table's
  filter form and its pager carry all three, so narrowing the table does not
  clear the search.
* **`GET /admin-api/rbac`'s `candidates` is paged**, by `candidatesPage` and
  the shared `per`, answered in `candidatesPaging` — twenty by default, the
  pane's size, so without `per` the reply and the pane show the same people;
  `personfrom` is honoured as the page it falls on. `candidateSearch` (total,
  matched) and `picked` sit beside it. It was the whole list, which on a large
  directory was thousands of rows on every read of the roster. `CHOOSER_HITS`
  moved to `admin-core/admin_views.js` so the pane and the reply share one
  number. **`roles` lost `members` and `claimed` in the same change**: every
  membership, unpaged, and the same rows `grants` pages (`?role=` narrows it).

`tests/vendored/sts_admin_console.js` searches for the person on the pane's own
form, clicks the result, and grants on the form that opens.

## EVERY PROTOCOLS PAGE LISTS ITS REALM'S ENDPOINTS (2026-09-13)

rcbj asked that each page under Protocols list the concrete endpoints the
current trust realm answers on for that protocol, using `/admin/gnap`'s
*Endpoints* table as the model. Thirty-seven pages have one now; GNAP keeps its
own, which `gnap/gnap_console.js` writes.

**THE TABLE IS `admin-core/protocol_endpoints.js` AND NOT THIS FILE**, which is
how the paragraph that refused an endpoint list (under *The eight new pages*)
was answered rather than ignored. A row names Express ROUTES; the name comes
from `sts_metadata.js`'s `ENDPOINTS`, the methods from the router, the URL from
`baseUrlOf(req)` so it carries the realm prefix. Sockets the router cannot see
(KDC, Kerberos service, LDAP/LDAPS at the realm's base DN, 8443/9443, SPIFFE's
gRPC bindings for this realm) are built from their settings. `:param` is shown
as `{param}`, and a named authorization server's routes are repeated per server
by id.

Four decisions belong to this file:

* **IT IS DRAWN IN `respond()`, NOT BY FORTY PAGES.** `withProtocolEndpoints()`
  adds `protocolEndpoints` to the JSON of any page the table names and splices
  the section in before the page's first `<h2>` — GNAP's place, after the lead
  notes. A page added to the table needs no edit of its own.
* **ONLY WHEN `req.path` IS THE PAGE.** A page drawn under another page's tab
  with a path of its own (the keytab, a PEP's listener certificate) gets
  nothing.
* **A DRILL-DOWN KEEPS THE JSON AND LOSES THE SECTION**, where a drill-down is
  `up` as `upTo()`'s OBJECT. The XACML sub-pages pass a path STRING as `up` on
  the page itself (the latent defect recorded under *THE XACML MONITOR*), and
  must not lose the section for it.
* **`/admin/scim`'S OWN TABLE IS "What each operation does" NOW.** It was also
  headed *Endpoints*, and it describes operations by path under `/scim/v2`
  rather than the realm's addresses.

`protocolEndpointDrift()` is exported for `tests/protocol_endpoints.js`, which
fails on a Protocols page with neither a row nor an exemption and on a row
naming a page not under Protocols. **A new page under Protocols therefore owes
a row in that table**, or an entry in its `EXEMPT` with the reason.

## `/admin/applications/new` IMPORTS RFC 9728 PROTECTED RESOURCE METADATA (2026-09-13)

A checkbox reveals three ways to give a protected resource's metadata document
— paste, upload, URL — and Load answers with the page redrawn: the document in
three tabs (raw JSON, a table of values, the fields read from it, editable) and
the create form filled in from `oauth-oidc/protected_resource_metadata.js`'s
plan. The `resource` is the default name, `oauthPermissionBaseUri` and
`oauthAudience`; `scopes_supported` becomes `oauthPermission` with the resource
prefix taken off; `oauthClientId` and the identifier are a random client_id in
the registration shape; OAuth 2.0 is ticked. rcbj chose all four recommended
answers: Admin Write plus the outbound policy with internal addresses refused in
product, section 3.3 refused in product and warned in development, the document
kept on the entry (`oauthResourceMetadata`, `oauthResourceMetadataUrl`), and
the prefix stripped.

Five decisions are this file's:

* **THE PATH TAKES A POST NOW.** Load and the create from a loaded document both
  post to `/admin/applications/new`, because a refused create has to come back
  HERE with the document and every edit kept, which the list page's 303 cannot
  carry. The ordinary form with nothing loaded still posts to
  `/admin/applications`. Both reach `applicationsAction()`, whose third argument
  (`context`: the realm's authorization servers, computed by the route from the
  request) is the one thing the load needs that a body cannot carry.
* **THE UPLOAD IS multipart/form-data AND `helpers.parseBody()` READS IT**, so
  the gate's CSRF check finds the token in an upload; `multipartParts()` gives
  the route the filename.
* **THE TABS ARE CSS AND THE RADIOS POST NOTHING.** Three radios carry
  `form="prm-tabs-not-a-form"` (no form owner, still one group) and the general
  sibling combinator shows a panel — no `:has()`, so no fallback. The third
  tab's boxes are fields of the create form whichever tab shows; a redraw after
  a refusal opens that tab.
* **THE PANE OWNS SIX ATTRIBUTES** (`RESOURCE_METADATA_OWNED`), and the
  declarations section omits `oauthClientId` while it is drawn: two boxes with
  one name post twice and `parseBody()` keeps the last, the empty one.
* **THE BANNERS ARE NOT `warn()`.** The authorization-server comparison, the
  section 3.3 verdict and the warnings are plain `div.warn`/`div.ok`, because a
  fold would hide the unmatched issuers behind a summary. A matching issuer is
  green in the table (`state-valid`), a foreign one amber, and a mismatch never
  refuses the create.

The third tab edits only members the document carried; `documentFromForm()`
rebuilds the stored document from the original plus those boxes, keeps
extension members and never touches `signed_metadata`.

`POST /admin-api/applications/load-resource-metadata` mirrors Load (rule 7),
and that resource's `mirrors` names both console paths.
`tests/protected_resource_metadata.js` holds the library, the fetch policy in
both modes against a local server, multipart parsing and the create-time
checks (13 mutants, 12 caught, 1 equivalent). **No owned over-HTTP job presses
the import yet**: it was driven end to end by hand against a throwaway
instance (API paste and URL, console sign-in, upload, refused and accepted
create, read-back) and the tab states were checked by screenshot.

## `/admin/users?user=…` HAS A *PASSWORD AND SECOND FACTORS* SECTION (2026-09-13)

Asked for as a reset-password button whose password the administrator notes, an
option to generate a reset link to send to the person, buttons to disable
passkeys as a primary mechanism, to disable all MFA and to force enrolment, and
the CAEP and RISC signals each owes. `userCredentialControlsSection()` draws it
after the Credentials section; the six actions are `usersAction()`'s and
`admin-core/admin_actions.js`'s `credentialAdminAction()` argues each. Four
things are this console's.

* **A STATE TABLE COMES FIRST AND THE CONTROLS ARE CONDITIONAL ON IT.** Whether
  a password is held, whether it must be changed, whether a reset link is
  outstanding (and until when), how many keys can sign in on their own, and
  whether a second factor is required (by the account, by the realm, or both).
  **Disable passkeys** is drawn only while the person holds a primary key AND a
  password — without the password it would lock them out, so the section warns
  instead; **Disable all MFA** only while a second factor is held; **Require**
  and **Stop requiring** swap on the account flag. Everything is for Admin
  Write only, the rule the two sections above follow.
* **A RESET AND A RESET LINK ANSWER WITH A PAGE.** `credentialResetPage()`, from
  the `POST /admin/users` handler, whenever the result carries `password` or
  `resetUrl` and the request is not JSON — `/admin/users/new`'s argument: a
  generated password and a reset link exist once, and a 303's query string is
  the browser history and every log on the way. A JSON caller gets the result.
* **`from=user` BRINGS EVERY OTHER CONTROL BACK TO THE PERSON**, through
  `userReturnTo(body, who, '#credential-controls')`, which gained that anchor
  (and `#credentials`) beside the ones it already allowed.
* **`base: baseUrlOf(req)` IS HANDED TO THE ACTION**, so the reset link names
  the address the administrator is using. `mgmt-api/admin_api.js` passes the
  same, which is what keeps the link realm-prefixed from both doors.

`tests/admin_credential_controls.js` drives the actions, the portal page and the
enrolment step in a child process; no owned browser job presses the section yet.
