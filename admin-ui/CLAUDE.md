# admin-ui/

The admin console at `/admin`. One file, and it is the largest in the repository
because every page's HTML and every page's JSON view are built in the same
function — deliberately, for the reason `../mgmt-api/CLAUDE.md` gives.

**It is not protected and holds nothing on disk.** It is also the one surface that
can CHANGE what the protocol endpoints do.

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

## Four reader slots and two writer slots point INTO this module

`server.js` requires this module BEFORE `../ldap/ldap_server.js`,
`../scim/scim.js` and `../spiffe/spiffe_server.js`, so this module cannot require
any of them: the require would pull `/ldap`, `/scim` and `/spiffe` into the
express router ahead of every `/admin` route, and `GET /sts-metadata` is built by
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

* **The admin console at `/admin` is not protected and holds nothing on disk.** It is
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
