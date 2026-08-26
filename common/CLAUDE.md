# common/

The modules every other directory reads. Nothing in here belongs to a protocol,
and that is the entry test rather than a description: a file lands here because
more than one family needs it, not because it felt general.

| File | What it is |
|---|---|
| `config_file.js` | The one place that decides what `CONFIG_FILE` means. Requires nothing at all. |
| `config.js` | Every setting this service has, and the refusal to start without one. The only module `helpers.js` depends on. |
| `helpers.js` | Log, keys, `signJwt()`, `userFor()`, the cross-protocol parsers. |
| `app.js` | The express app and every middleware. Requiring it is how a protocol module gets somewhere to register. |
| `admin_stats.js` | The counters, the revocation set, and `recordAuthentication()` — the single authentication funnel. |
| `audit.js` | What happened, when, and to whom, as discrete events. Sits BESIDE `admin_stats.js`, not under it. |
| `applications.js` | Every application this service has been asked about, stored in the directory under `ou=applications`. |
| `delegation.js` | Who acted on whose behalf, through what, to reach what — eight mechanisms across three protocol families in ONE model. |
| `claim_attributes.js` | Which LDAP attributes a token or an assertion carries, per claim set. |
| `group_claims.js` | The groups claim, in all four claim sets at once. |
| `vendored/` | Byte-identical copies of the parent project's files. **Do not edit them here** — see `common/vendored/CLAUDE.md`. |

**`config_file.js` is new with the 2026-08-23 reorganisation and it exists
because of it.** Fourteen modules read the appconfig file directly for the one
thing they need before `config.js` exists — a bunyan log level — and node
resolves a relative `require()` against the directory of the module doing the
requiring. While every module sat in the package root, `CONFIG_FILE=./env/local.js`
worked from all fourteen by accident. From `common/` it resolves to
`common/env/local.js`, which does not exist: `config.js` and `helpers.js` read it
UNGUARDED and would die with `MODULE_NOT_FOUND` naming a path nobody typed, and
the eleven guarded readers would quietly fall back to `info`. So the variable is
made absolute once, in place, before anything reads it. Three callers require it
first and between them cover every way this service is loaded — `server.js`,
`config.js` and `helpers.js` — and it is idempotent, so all three costs nothing.
Four of the fourteen readers are VENDORED files this repository may not edit,
which is why the fix is a mutation of `process.env` rather than fourteen edits.

---

## `helpers.js` holds what more than one protocol needs

`userFor`, `parseBody`, `oauthError`, `vciError`, `signJwt` and
`firstByLocal`/`textByLocal` are in `helpers.js` because more than one protocol needs
them, not because they are especially general. The last two are read by three parsers
— the WS-Trust RST, WS-Federation's `wreq`, and the `wresult` the mock relying party
is POSTed — and they match on **local name with the namespace ignored** because the
trust namespace alone has four versions in use. That is what lets one parser answer
WS-Trust 1.0 through 1.4 instead of four.

**`dnRfc4514()` IS THE NEWEST OF THEM AND IT MOVED HERE RATHER THAN BEING WRITTEN
TWICE.** It renders a certificate subject the way LDAP and RFC 4514 write one —
leaf first, no spaces after the commas, values escaped — which is a DIFFERENT
string from the most-significant-first form node and `openssl x509 -subject`
print, and it is the form this service files an identity under. It was in
`tls/tls_server.js`, which still re-exports it, because `scim_auth.js` and
`spiffe_auth.js` require that module for it and have done since before it moved.
What forced the move is `spiffe_ca.js`: the directory now records the
certificate every X509-SVID mint produces, using the same six `x509*` attributes
a verified TLS client certificate writes, so the two paths must render a DN
identically — **two spellings of one DN is two people on `/admin/users`** — and
that module CANNOT require `tls_server.js`. Rule 3e's test says why:
`admin-ui/admin.js` requires `spiffe_ca.js`, and `server.js` requires `admin.js`
at 18 and `tls_server.js` at 20, so the require would pull every `/tls*` route
into the router ahead of the console's and `GET /admin/sts-metadata` walks that router.
A leaf here moves no route and closes no cycle. **It takes BOTH shapes of DN node
produces** — the object from `getPeerCertificate()` and the newline-separated
string from `crypto.X509Certificate` — which is the whole reason it is one
function and not two that agree today.


---

## The signing key is parsed ONCE, and `privateKeyPem` is still there

`helpers.js` builds `STS.privateKey` — a `crypto.KeyObject` — beside the
`STS.privateKeyPem` it has always exported, and **every `jwt.sign()` in this
repository takes the KeyObject**. Handing jsonwebtoken the PEM string made node
re-parse it into a key on every signature, which measured 21% of this service's
non-idle CPU against 48% for the RSA signature it was preparing for: a third of
the cost of issuing a token was re-reading a key that has not changed since
startup. One signature went from 1.08ms to 0.48ms and the token endpoint's
throughput rather more than doubled.

`privateKeyPem` is KEPT and is not deprecated — the three XML signers
(`saml2.js`, `saml11.js`, `wsfed.js`) pass it to xml-crypto, which wants a PEM.
**A new signer picks by library**: jsonwebtoken gets `STS.privateKey`,
xml-crypto gets `STS.privateKeyPem`. They are the same key and are derived from
each other, so they cannot drift.

## `realms.js`: several logical copies of this service, in one process

A **trust realm** is a whole mock identity service — its own configuration, its
own signing key, its own sessions, authorization codes, tokens, offers,
artifacts, statistics and audit log — answering on the SAME sockets as every
other and told apart by a segment at the front of the path:

```
http://host:8081/oauth2/token                the DEFAULT realm
http://host:8081/realm/acme/oauth2/token     the realm `acme`
```

**THE DEFAULT REALM HAS AN EMPTY PREFIX AND THAT IS THE WHOLE CONTRACT.** A
service with no realms defined behaves exactly as it did before this module
existed — nothing is stripped, no URL is rewritten, no store is partitioned
differently, no page grows a control. That is a property of ONE predicate,
`active()`, rather than a claim spread over twenty files, and it is what keeps
every test, container and client that predates realms working unchanged.

### Forty modules became realm-aware without being edited

The obvious implementation threads a realm argument through every function that
reads a setting, mints a token or touches a store — several hundred call sites,
every one of them a chance to drop the argument silently. A token minted for the
wrong realm looks exactly like a token minted for the right one.

So the realm is **AMBIENT**, held in an `AsyncLocalStorage` that `app.js`'s front
middleware enters for the whole life of a request. Four consequences, and they
are why this module is short:

* **`config.value(key)`** consults the current realm's overrides first, so every
  one of the 200-odd setting reads in this service is realm-aware where it
  stands. Rule 3m, below.
* **`helpers.baseUrlOf(req)`** appends the realm's prefix, so every issuer
  identifier, metadata document, entityID, `did:web`, DPoP `htu`, redirect and
  form action this service builds names the realm it was built in. That one line
  brought eighty call sites with it.
* **`helpers.STS`** is a Proxy onto the CURRENT realm's key set, generated
  lazily. Eight modules destructure it and read `STS.kid`, `STS.certPem`,
  `STS.privateKey`; not one of them changed.
* **A store declared `realms.map()`, `realms.arr()` or `realms.obj()`** is
  partitioned by realm behind an unchanged Map/Array/Object interface, so
  converting one was a one-line edit at the declaration and no edit at all at its
  hundred readers.

`AsyncLocalStorage` is the right primitive rather than a convenient one. A
request here is a chain of awaits and callbacks — an LDAP search, an RSA
signature, a gRPC call — and a module-level `currentRealm` variable would be
correct only until two requests for two realms overlapped: correct in every test
and wrong in every use, with the failure being a token signed with another
realm's key under load and nothing else.

**The one place it does not propagate is an EventEmitter listener**, which runs
in the async context of whatever emitted the event rather than the one it was
added in. `app.js`'s call log and audit row are written from `res.on('finish')`,
so that handler re-enters `req.realm` EXPLICITLY. It is not belt and braces:
without it the statistics land in whichever realm the process happened to be in,
which under load is a different one.

### Rule 3m: the realm's overrides are an inverted hook into `config.js`

`realms.js` requires `config.js` in the ordinary direction — it validates a
realm's settings through `checkOverride()` and reads its own two settings
through `value()`. `config.js` needs the current realm's overrides and cannot
require this module back, so it offers `setRealmContext()` and this fills it at
require time. That is rule 3e's shape and it passes rule 3e's test in the one
direction that matters: a require here would close a cycle.

The slot answers the REALM RECORD rather than its overrides, because
**`config.js` writes through it too**. `setOverride()` in a realm sets the
REALM's value — which is what makes `/admin/config`, `/admin/token-lifetimes`
and `POST /admin-api/config/set` realm-aware without one of them being edited.
Setting a value while `acme` is ambient means setting it for `acme`; anything
else would be a console page that reads one realm and writes another.

**TWO SETTINGS ARE EXEMPT IN BOTH DIRECTIONS** and it is not caution:
`realms.enabled` and `realms.pathSegment` are read below the realm layer,
always. A realm that could switch realms off would be doing it from inside the
request that found it, and a realm that could move its own prefix would change
the prefix that had already been used to find it. They are refused at the writing
end as well, but the reading end is the lock that cannot be got around.

**THE WRITING-END LOCK WAS MISSING UNTIL 2026-08-25, AND THE SENTENCE ABOVE
DESCRIBED IT ANYWAY** — which is the whole lesson. `realms.setOverride()` went
straight to `config.checkOverride()`, which knows only whether a setting exists
and is runtime-settable, so `POST /admin-api/realms/set` with
`realms.pathSegment` answered `ok: true` and stored it on the realm. Nothing
MISBEHAVED, because `realmFor()` at the reading end returns null for any
`realms.` key and the value was never consulted — the second lock did its job
alone, exactly as the sentence above claims it can. What was wrong is subtler
and worse than a wrong value: `GET /admin-api/realms` lists a realm's overrides,
so this API asserted that a realm carried a prefix setting no reader would ever
look at. **A dead write is not harmless when something publishes what was
written.**

The lock is `checkRealmOverride()` in `realms.js`, and two things about it are
deliberate. It matches by PREFIX rather than naming the two settings, so a third
`realms.*` setting is refused the day it is added rather than the day somebody
remembers this function. And **every writing path goes through it** —
`setOverride()`, and `checkOverrides()`, which is what `create()` and `update()`
validate a whole object with — because the two were written separately at first
and that is exactly how one of them came to be missing.

**One door still accepts those two keys and must**: `POST
/realm/acme/admin-api/config/set` goes through `config.setOverride()`, where
`realmFor()` answers null and the write lands PROCESS-WIDE. That is the
documented behaviour rather than a hole — it is the same exemption read from
the other side — and the reply names no realm, which is what tells the caller
where it went. Do not "fix" that one to match: refusing it would leave
`realms.enabled` unsettable from inside any realm, which is every request in a
process where realms are switched on.

### A new realm is born with its own names for the things that are NAMES

Six settings here are identifiers rather than behaviour — the SAML 2.0 entityID,
the SAML 1.1 providerID, the WS-Federation entityID, the WS-Trust issuer, the
SAML assertion issuer and the OpenID4VP verifier client id — and each defaults to
a fixed string. Two realms carrying one of those strings is not a configuration
choice: it is two identity providers claiming one entityID, which a service
provider is entitled to refuse. So `create()` seeds each with the realm id
appended.

They are **ORDINARY SETTINGS ON THE REALM**, listed as such on `/admin/realms`,
which is the whole reason this is done at creation rather than inside the six
reads: an operator can see what was chosen, change it, or unset it and go back to
sharing the process's name — a realm deliberately impersonating another being a
case worth building on a mock. A derivation buried in a getter would give six
values that could not be seen and could not be changed.

`oauth2.issuer` is deliberately NOT seeded: it defaults to empty, meaning "name
the base URL this request arrived on", and that already carries the prefix.

### What a realm does NOT separate, and why saying so is the feature

`realmSupport()` is the index, and both `/admin/realms` and `GET /realms` render
it, so the answer is something this service tells you rather than something a
reader derives from four directory files. The short version:

* **What a realm separates completely** is what this service ISSUES and
  everything it holds while issuing it: keys, sessions, authorization codes,
  tokens, refresh families, DPoP and client-assertion replay state, offers,
  pre-authorized codes, presentation transactions, SAML request state and
  artifacts, the claim selections, the verifier's request, the statistics and
  the audit log.
* **THE DIRECTORY IS SEPARATED TOO — A STORE PER REALM BEHIND ONE SOCKET — AND
  THIS BULLET SAID THE OPPOSITE UNTIL 2026-08-25.** Each realm's directory is
  its own `realms.map()` partition, named by `dc=<id>` beneath `ldap.baseDn`,
  with its own `ou=users`, `ou=groups`, `ou=applications`, `ou=federations` and
  SPIFFE containers — so OAuth client registrations, SAML service provider
  entries and the SPIFFE registry are a realm's own. The realm is in the DN
  because the socket has no path to put a segment in, and the DN is therefore
  also how the socket picks which store to answer from. It was a subtree of one
  shared Map for two days, and `../ldap/CLAUDE.md` argues why that was one day
  too many: the isolation was a rule every reader had to remember, and two
  readers did not. **The TWO ADMIN CONSOLE ROLES are the exception and are pinned to the
  DEFAULT realm's `ou=groups`** — one roster for the process, on purpose, since
  a per-realm roster would let anybody who can create a realm administer the
  service. **The console's SIGN-ON follows the roster**: its gate is
  `consoleSession()`, which accepts the DEFAULT realm's session and no other, so
  the realm switcher switches without a second sign-in and a session minted in
  `acme` opens nothing. That is argued in `../authn/CLAUDE.md`, and it changes
  nothing for a protocol endpoint — `/oauth2/authorize` in the realm switched to
  still sees no session, and still should.
* **WHAT IS LEFT PROCESS-WIDE NEEDS AN ARGUMENT THAT IS NOT "THE DIRECTORY IS
  SHARED".** That sentence justified two stores in `admin_stats.js` — the
  identity register and the revocation set — and it was true for one day. Both
  are `realms.map()`/`realms.keyed()` since 2026-08-25, and what they were doing
  before is worth knowing because neither raised anything: every realm's
  `/admin/users` listed every other realm's people, while the realm's own
  directory reader reported each of those entries as missing (which, in that
  realm, they were); and one realm's `tokens.revoked` appeared under every realm
  beside a correctly partitioned `tokens.held`, with
  `POST /realm/acme/oauth2/revoke` able to kill a jti the default realm issued.
  `tests/realm_isolation.js` guards both directions and the purge.
* **Kerberos, the two TLS listeners and SPIFFE's four sockets are shared**, for
  the same reason. Kerberos is the one with an obvious way forward, and it is
  written down in `realmSupport()` rather than left to be rediscovered: Kerberos
  already HAS a realm, so give each trust realm a `krb5.realm` of its own and
  dispatch a request on the realm name it carries. What stands in the way is
  that `krb5.realm` is not runtime-settable — the principal database and its
  long-term keys are built from it at require time — so that database has to
  become per-realm and lazily built first.

### An id is a path segment, so it is narrower than a name

Lower-case letters, digits and hyphens, starting with a letter or a digit, at
most 31 characters. It may not be `default`, and **it may not be the first
segment of a path this service already serves** — that list is read off the LIVE
ROUTER through a provider `app.js` installs, so a family added tomorrow protects
itself. The refusal stands whatever `realms.pathSegment` is set to, precisely
because that setting is runtime-settable: a realm created under a segment and
legal there would otherwise become a shadow over the console the moment somebody
cleared it, and the failure would arrive as "the console stopped existing".

### `onCreate()`: the one store that cannot be built lazily

`keyed()`, `map()`, `arr()` and `obj()` all build a realm's value on FIRST TOUCH,
and that works because every one of their readers is reached through a request
that has already entered the realm. **The embedded directory is the exception and
`realms.onCreate()` exists for it.** It is one tree keyed by DN, served by a
socket with no path in it, and a realm's isolation is a subtree
(`dc=acme,dc=example,dc=com`) — so "first touch" can be an `ldapsearch` arriving
on 389 for a base DN with no realm ambient at all, and the honest answer for a
subtree that was never built is `LDAP_NO_SUCH_OBJECT`. A realm that exists over
HTTP and not over LDAP is the kind of half-truth this service exists to make
impossible, so the subtree exists from the moment the realm does.

It fires AFTER the registry row is written, so a builder may read the realm back
through `get()`, and a builder that throws leaves a realm that exists rather than
half of one — the mirror of `onRemove()`, whose purges run after the row is
deleted. The asymmetry is deliberate in both directions: a realm with an unbuilt
subtree is recoverable, and a create that failed half way is not.

**One caller.** Adding a second is the same test `keyed()` fails: it has to be
something a request cannot build on demand.

### Removing a realm takes its state with it

Every store made here registers a purge and `remove()` calls them all. If removal
only dropped the registry row, a realm re-created with the same id would inherit
the last one's sessions and tokens — the single most surprising thing a
re-created realm could do. **The directory purges too, and that is new**: it is a
subtree per realm since 2026-08-25, so `ldap_server.js` registers a purge like
every other store and removal takes the realm's people, groups, applications,
federation relationships and SPIFFE registrations with it. That sentence used to
read "nothing is removed from the directory, because nothing there belongs to a
realm", and it is worth knowing why the reversal does not break the rule it
looks like it breaks: *nothing is ever deleted from `ou=users`* is about a PERSON
being removed while their realm stands, and it still holds. This is the realm
itself going away, and leaving its subtree behind would leak a tree nobody can
reach — every path to it, HTTP and LDAP alike, named a realm that is gone.

**A realm cannot remove ITSELF.** The response is a 303 to `/admin/realms`, which
`app.js` is about to rewrite into the realm being deleted; the reader would be
redirected into a prefix that stopped existing one instruction earlier.
Everything else about the removal would have worked, which is what makes it worth
refusing rather than special-casing.

### The HTML rewrite in `app.js`, and its one honest limitation

Every root-relative `href`, `action` and `src` in a `text/html` response is
rewritten to carry the current realm's prefix. That is what makes the console's
several hundred hand-written links, the login screen's form and the four autopost
pages work inside a realm without one of them being edited — and a missed link
would be one that silently LEAVES the realm rather than one that breaks, which is
why it is done once at the choke point rather than at the call sites. It runs in
a non-default realm only, so the default realm's bytes are not merely unchanged
but untouched.

**A URL built inside a SCRIPT is not markup and is not rewritten.** There is one
such page — `/admin-api/docs`, whose explorer builds request URLs from the
OpenAPI document's `path` members — and it is handled by being HANDED the prefix
as `data-realm-prefix` rather than by having its markup rewritten. Without that,
pressing "Try it" inside a realm would call the DEFAULT realm's API: the page
would look right, the call would succeed, and it would have changed the wrong
service. A fifth scripted page would need the same treatment and would not get it
for free.

## `config.js` is the only place a setting is read

Configuration used to be forty-odd `process.env.X || 'a default'` expressions spread
over twelve modules. Each was readable where it stood and the set of them was not:
there was no way to ask this service what it was configured with, no way to change
anything without restarting it, and no list anywhere of what could be changed at all
— the answer was a grep, and the grep only found the ones spelt the way you guessed.

**A new setting is a row in `SETTINGS` and a regenerated `env/defaults.js`** —
`node env/generate_defaults.js`, and the service tells you when you have forgotten
by refusing to start and naming the row. The row carries the key
(which is both the dot path in the appconfig file and the name every surface uses),
the environment variable, the type, the default, the prose, and `runtime`. From that
one row it appears in `/admin/config`, in `GET /admin-api/config`, in the OpenAPI
document's `Config` schema, and in the startup audit — none of which has a list of
its own to update. A `process.env` read added anywhere else is invisible to all four,
which is the state this file exists to end.

**`runtime: false` is a claim you have to be able to defend.** It means the value was
consumed before the service was listening, so changing it now would do nothing — and
`set` refuses it with the `restartReason` rather than accepting it, because an
accepted change that does nothing reads as having worked. Three kinds qualify and it
is worth knowing which: a **bound socket** (the HTTP port AND ITS SCHEME — see
`global.https`, which is why `oauth2.rfc9700` is restart-only — both TLS ports,
both LDAP ports, both Kerberos ports); **material derived at startup** (the TLS certificate is
issued for `tls.hostnames`/`tls.ips` at boot, and the Kerberos principal database and
every long-term key in it comes from the realm, the SIDs and the passwords at require
time); and **the directory tree**, which `ldap.baseDn` is the root of. Marking a
setting runtime when the thing derived from it is not rebuilt is worse than marking
it restart-only, because the two then disagree silently.

**`realmRuntime` IS THE ONE EXEMPTION AND IT IS AN APPLICATION OF THAT RULE
RATHER THAN A HOLE IN IT.** One row carries it — `oauth2.rfc9700` — and the
argument is short: that flag is restart-only for exactly one reason, that
`global.https` derives its default from it and a listener's scheme is settled
when the socket is bound. **A realm binds no socket.** It answers on the port
this process already opened, in the scheme that port was opened in, so nothing
about a realm was consumed at startup and `oauth2_bcp.js`'s `enabled()` reads
the setting per request through the realm layer like any runtime row. So
`checkOverride(key, raw, forRealm)` takes a third argument, `realms.js`'s
`checkRealmOverride()` is the only caller that passes it, and the refusal a
person meets at `/admin/config` in the default realm — and at `POST
/admin-api/config/set` outside a realm — is unchanged. `describe()` decides
`editable` the same way, so the console under a realm's prefix offers the
control the same page in the default realm correctly refuses.

What that buys is the thing two processes used to be needed for: `/oauth2/authorize`
permissive and `/realm/<id>/oauth2/authorize` enforcing the BCP, in one service.
What a realm does NOT get is a scheme of its own — the main port is HTTPS or it is
not, for every realm at once — and that is REPORTED rather than hidden:
`mainPortIsTls()` is false, `GET /oauth2/rfc9700` says so, and the four
requirements that are properties of the deployment come back `no` rather than
`deployment`.

**Do not add a second `realmRuntime` row by analogy.** The test is the paragraph
above: the restart reason has to be something a realm demonstrably does not have.
Anything whose value was consumed at startup to build MATERIAL — the TLS
certificate, the Kerberos principal database, the directory tree — was consumed
for the whole process, realms included, so marking one of those would be exactly
the silent disagreement this section warns about. `krb5.realm` is the one
somebody will reach for first and it is the clearest no; `NAMED_BY_REALM` in
`realms.js` says the same thing from the other end.

**A ROW MAY NARROW ITS TYPE, and only the `int` type can so far.** `min`, `max`
and `step` are OPTIONAL members of a row that `TYPES.int.check()` applies; a row
carrying none of them behaves exactly as every int row did before they existed,
which is what kept the forty-odd existing ones untouched. They arrived for the
four token-lifetime settings (`oauth-oidc/CLAUDE.md` argues the numbers), where
the bounds are part of what the setting MEANS rather than a validation nicety: a
lifetime of nine seconds and a clock skew of a fortnight are both typeable, both
pass "is it a whole number", and both produce a service whose tokens are wrong
in a way that reads as a client bug. **`step` is a MULTIPLE-OF rather than a
slider increment**, counted from `min` so that a floor which is not itself a
multiple of the step is still reachable. `describe()` publishes all three, so
`/admin/config`, the console's own pages and the OpenAPI `ConfigSetting` schema
render the same three numbers the check enforces — the bound is declared once
and nothing repeats it. **Put a new constraint here rather than at the call
site**: this is the only place one refusal can serve the console form, the
management API and an environment variable read at startup, and the last of
those has nowhere else to be caught.

**A runtime setting must be READ WHERE IT IS USED.** That is why so many of the
module-level `const`s became functions — `vciBatchSize()`, `clockSkewSeconds()`,
`maxEntries()`. A `const` captured at require time is the one thing `/admin/config`
cannot change, and it fails in the direction that looks like the console is broken.

**Resolution order is override, env var, LEGACY env var, the appconfig file
`CONFIG_FILE` names, `env/defaults.js`.** Env beating the file is what keeps every
existing container and test working: nothing in the parent project sets these
variables in compose, but
`tests/krb5_spnego_http.js` sets `KRB5_REALM`, `KRB5_KDC_PORT` and
`KRB5_SERVICE_PORT` before requiring the KDC in-process, and that still wins. The
legacy level has exactly one occupant: `STS_ISSUER`, which used to be a single value
serving as the SAML assertion issuer, the WS-Trust token issuer AND the
WS-Federation entityID. Those are three different things that shared a default — an
entityID names the identity provider, an Issuer names whoever signed an assertion —
so they are now `saml.issuer`, `wstrust.issuer` and `wsfed.entityId`, all three still
fed by `STS_ISSUER` when it is set.

**AND THERE IS NO SIXTH LEVEL — `requireComplete()` REFUSES TO START INSTEAD.**
A setting with no value in either appconfig file and no environment variable
stops the process, by name, listing both places its value could go. That is the
2026-08-24 change and it is the point of the table rather than a strictness bolted
onto it: a value arriving from a constant buried in a module is a value nobody
can find, change or see on a page, which is the state this file exists to end,
and a silent fallback underneath it was one way back in. The `dflt` column is
still there and is still where a default is WRITTEN DOWN — beside the paragraph
saying why it is the default — but it is documentation and a generator input
rather than a source the service leans on. `process.exit(1)` rather than a throw,
because a throw out of a require lands as a stack trace whose top frame is node's
module loader and the reason ends up three screens above where anybody looks.

**WHAT THAT REFUSAL CAN ACTUALLY CATCH IS A MAINTAINER'S MISTAKE, NOT AN
OPERATOR'S**, and knowing which is the difference between the rule being useful
and being a trap. **The appconfig layer is TWO FILES unioned**: `env/defaults.js`
carries a default for every non-derived row, and the file `CONFIG_FILE` names is
merged over it key by key with the operator's value winning. So an operator's
file can never be incomplete — only smaller — and three things follow, each of
which had to be true at once:

* a config file that is NOT this service's still loads every module here, which
  is what the parent project's in-process Kerberos jobs need (`CONFIG_FILE`
  pointing at the TEST suite's config, which carries `logLevel` and nothing else
  of ours);
* a row added to `SETTINGS` tomorrow does not break every config file in the
  world on the day it is added;
* so the refusal fires on the one case left — a row here with no row in
  `env/defaults.js`, which is a setting somebody added and did not finish adding,
  caught at the first start after the mistake.

**`env/defaults.js` IS GENERATED AND MUST NOT BE HAND-EDITED.** `node
env/generate_defaults.js` writes it from the `dflt` column. Two copies of a
default is one copy that will be wrong, and wrong in the quietest way — the
service running on one value while `/admin/config`, the OpenAPI document's
`default` property and README.md's table all report the other. That generator
neutralises `process.exit` for the length of its own `require` of this module,
because regenerating the file is the one moment when an incomplete
`env/defaults.js` is EXPECTED; the bypass is in the build tool and deliberately
not a flag here, since a flag in the service is a flag somebody can leave on.

**`resolve()` READS THE TWO FILES SEPARATELY EVEN THOUGH THEY ARE UNIONED**, and
that is not redundancy: `appconfig` is the union and is what the bootstrap logger
reads, while `resolve()` digs the operator's file and then `env/defaults.js` so
it can say WHICH — `source: 'appconfig'` against `source: 'defaults'`. A value
from the operator's file and the same value from the defaults are
indistinguishable once merged, and "where did this come from?" is the question
`/admin/config` exists to answer. `auditAppconfig()` reads the operator's file
alone for the same reason: audited against the union it would answer "nothing is
missing" every time and be dead code that looked alive.

**`logLevel` IS THE ONE KEY THAT IS NOT DISTINCTIVE OF THIS SERVICE** and the
audit's "somebody else's file" branch has to exclude it. Every appconfig file in
this ecosystem has one — the parent's api, its client, its test suites — because
it is the only setting that predates this table. Counting it made that branch
almost unreachable for the very case it was written for, and the result was a
hundred-and-fourteen-name warning on every in-process Kerberos run. Both drift
warnings now cap their name list at twelve and a count, for the same reason: a
list long enough to scroll is a list nobody reads.

**It is a library (rule 3) and it sits UNDER `helpers.js`.** It requires only bunyan
and `process.env.CONFIG_FILE`, and makes a bunyan logger of its own rather than
taking the shared one, because `helpers.js` requires IT. A cycle here would hand
`helpers.js` a half-initialised module whose `value` is undefined, and the symptom
would arrive somewhere else entirely as "value is not a function".

**The three `env/*.js` files were GENERATED from the table** and carry every key with
the value the expression in the module used to have, so a run with the shipped file
behaves exactly as one with the old file that carried only `logLevel`. THREE settings
are deliberately absent from all four files, `env/defaults.js` included, because
their default is DERIVED from another (`krb5.serviceDomains` from the realm,
`oid4vp.walletUrl` from `oid4vci.walletUrl`, `global.https` from `oauth2.rfc9700`);
they carry `derived: true`, which keeps the startup audit from reporting them as
drift AND exempts them from the refusal above — a literal in a file would freeze the
derivation at whatever it evaluated to the day the file was written, so demanding one
would be demanding the one thing that is wrong. That audit — `auditAppconfig()` —
logs a setting the file omits and a key the table does not know, and does neither
when the file carries none of this service's DISTINCTIVE keys, which is the ordinary
case for the parent project's in-process tests: they load this service's KDC modules
with `CONFIG_FILE` pointing at the TEST suite's config.

**`tests/Dockerfile` in the parent project copies this file.** It is under
`helpers.js` in the graph, so every in-process job that loads `krb5_kdc.js`,
`app.js` or `spnego.js` needs it; missing, the failure is `Cannot find module
'./config'` before any test has run. **IT NOW NEEDS `env/defaults.js` TOO**, and
that is a new line in a file the pin bump has to touch anyway (see
`docs/parent-project-migration.md`): this module requires it by absolute path off
the package root, so without it every in-process job dies at load with `Cannot
find module` naming a file the operator never mentioned.


---

3b. **`admin_stats.js` is a library like `dpop.js`, and one dependency into it is
   INVERTED.** It registers nothing and requires only `helpers.js`, which it needs to
   stay that way more than `dpop.js` does: it is called from `app.js`'s call log,
   `helpers.js`'s `signJwt()`, both assertion builders, the KDC and the credential
   issuer. Because `helpers.js` cannot require it back (that is the cycle rule 2
   exists for), `helpers.js` offers a slot — `setJwtRecorder()` — and `admin_stats.js`
   installs itself in it at require time. **`app.js` is what requires
   `admin_stats.js`**, which is a real dependency (the call log is there) and also
   what makes the ordering safe: every protocol module requires `app.js`, so the
   recorder is installed before any route exists. Do not "simplify" that into a
   require in the other direction, and do not count tokens at their call sites
   instead — `signJwt()` is the single funnel, and five counted call sites means a
   sixth that is not.

   **ITS ONE OBSERVER SLOT NOW CARRIES THREE KINDS OF EVENT, AND THAT IS NOT A
   SIXTH HOOK.** `setUserObserver()` is still one slot filled by one module at
   its require time; what changed is that `ldap_server.js` is offered an `event`
   of `authentication`, `issuance` or `credential-status` through it.
   `recordAuthentication()` sends the first, `recordSvid('X.509', …)` sends the
   second when an X509-SVID is minted, and `recordCredentialStatus()` — which
   `spiffe_registry.js` calls by a plain require — sends the third. Keeping them
   on one slot rather than adding two more is what rule 3e asks for: a slot is
   the price you pay when a require would close a cycle or move a route, and one
   cycle does not become three. **AN ABSENT `event` MEANS AN AUTHENTICATION**,
   so an older `ldap_server.js` behaves exactly as it did, and only that event
   is counted on `/admin/users` or written to the audit log as one — an issuance
   that inflated the authentication count would make this page's central number
   mean two things at once.

   **AND THE PAYLOAD CARRIES A `federation` FIELD, WHICH IS A THIRD THING AGAIN
   AND STILL NOT A NEW SLOT.** A federated sign-in — `../federation/federation_sp.js`
   — puts the attributes a FOREIGN identity provider asserted onto the observer's
   detail, already mapped to this directory's own names, and `ldap_server.js`
   writes them onto the entry. It is not a fourth `event`, and that is rule 3e's
   test rather than convenience: this IS an authentication, and filing it as
   something else would take a federated sign-in off `/admin/users`, which is
   precisely where somebody looks for one. It is not a sixth slot either —
   `certificate` and `linkedTo` already established that a family with an extra
   fact about the identity puts it on THIS payload, and this is the third. What
   would justify a slot is a require that closes a cycle or moves a route, and
   there is none: `federation.js` registers nothing.

   **`recordAuthentication()` is NOT what a federated sign-in calls, and the
   reason belongs here because it is about this funnel.** It calls
   `authn.startSession()`, which records the authentication itself — so calling
   both produced TWO records for one sign-in, `/admin/users` counted every
   federated arrival twice, and the audit log carried a duplicate of each. That
   is what `startSession()`'s sixth argument exists for. The rule to keep: **one
   act is one row at this funnel**, and a caller that starts a session must not
   also record the authentication that started it.

3c. **`audit.js` is a library too, it sits BESIDE `admin_stats.js` rather than
   under it, and one dependency into it is inverted.** `admin_stats.js` answers
   "how much"; this answers "what, when, and to whom", as a list of discrete
   events. It requires `helpers.js` and `config.js` and NOTHING ELSE in this
   repository, and that has to stay true: it is called from `app.js`'s call log,
   from `admin_stats.js`'s `recordAuthentication()`, from `authn.js`'s session
   store and from every LDAP handler, which between them are most of the
   service. In particular it must not require `admin_stats.js`, because that
   module requires THIS one — so the identity normalisation an audit row wants
   is passed IN by the one caller that has already done it.

   **Five recording points, and four of them are funnels this service already
   had.** `app.js`'s call log covers three of the six categories (the console,
   the management API and every protocol endpoint) because it is the single
   place every answered request passes through; `recordAuthentication()` covers
   the sixteen protocol families for the same reason it covers the directory's
   user observer; `authn.js`'s `startSession`/`endSession` covers both
   protocols' sign-in and sign-out. Only `ldap_server.js` has a site per
   operation, because ldapjs dispatches straight into the handler and what a row
   says genuinely differs per operation. Do not add a recording site beside a
   funnel — that is how a category comes to be counted twice for one act.

   **One request is deliberately not an event: a `/healthcheck` that answered
   200** (`QUIET_WHEN_OK` / `isQuietProbe()` in `recordHttp()`). It is asked
   every few seconds for the whole life of the service — the compose
   healthcheck, the CI wait loop, every launcher in the parent project — and it
   always answers the same thing, so recorded it is by a wide margin the most
   common row here and it pushes everything a person came to the page to read
   off the end of a capped list. Note what the rule matches on: a probe that
   answered anything ELSE is still recorded, because a failing healthcheck is
   precisely the event somebody hunting a start-up failure is looking for, and
   it happens once rather than every five seconds. **The counters are
   untouched** — `/admin/metrics` counts the call as it always did, since a
   counter is one row however often it goes up. This is a rule about the event
   log, where one act is one line, and not about how much the service was asked
   to do. Anything added to that list needs the same two properties: constant,
   and uninteresting when it succeeds.

   **The one inverted dependency is the ACTOR.** An HTTP row wants the
   signed-in user's name and only `authn.js` can supply it, but `authn.js`
   requires `app.js` and `app.js` requires this — so `audit.js` offers
   `setActorResolver()` and `authn.js` fills it at require time, the same shape
   `setJwtRecorder()` and `setUserObserver()` have. The resolver it installs is
   deliberately NOT `sessionOf()`: that function deletes an expired session as
   it finds it, and an observer that quietly ended sessions while reporting on
   them would be changing the thing it describes.

   **Three properties are load-bearing and each is easy to undo.** `audit()`
   CANNOT THROW — it is wrapped, and a caller must never guard it, because an
   audit log that could fail a bind is a worse bug than a missing row. **NO
   CREDENTIAL IS EVER RECORDED** — no password, bearer token, assertion, or
   request/response body; a modify names the attributes it changed and never
   their values, a compare says whether it matched and not what was tried, and
   the query string redacts `code`, `id_token_hint` and the rest of
   `REDACTED_QUERY_KEYS`. The one field read out of an admin body is `action`,
   by name and capped, and widening that would put a pasted JWT on a web page.
   And the VOCABULARY IS A TABLE — `CATEGORIES` and `ACTIONS` — from which the
   console's filter selects and the API's `actions` member are both built, so an
   action cannot occur and be unfilterable nor be offered and never occur. A new
   action is a row there and nothing else.

   **Both its settings are read per event, not captured at require time**
   (`maxEvents()`, `protocolCallsRecorded()`), which is what the `runtime: true`
   on `audit.maxEvents` and `audit.protocolCalls` claims — see the config
   section below for why a captured `const` is the one thing `/admin/config`
   cannot reach.

   **`logout.global` and `logout.selective` are ONE ROW PER ACT and not one per
   thing ended**, which is this rule read from the other side. A global logout
   ends sessions, revokes tokens, discards codes, drops directory connections
   and stamps a Kerberos principal — and every session it ends already writes
   its own `session.end` through `dropSession()`. A row per item would count one
   sign-out twice at two layers. What those two actions add is the fact none of
   the others can carry: that these were one act, asked for by one person, at
   one moment, and how much of it could NOT be ended. They are in the `session`
   category rather than a seventh, because a category per family would be six
   categories for one act.

   **There is no clear operation and there must not be one.** An erase control
   on an unprotected console would make an audit log unable to answer the one
   question it exists for. Restarting the service is how you get an empty one;
   it is in memory and dies with the process like everything else here.


3d. **`claim_attributes.js` is the THIRD reader of `vc_claims.js`'s catalogue,
   and it is a library like the other two.** `vc_claims.js` says what an issued
   CREDENTIAL carries and `vc_verifier_config.js` says what the mock Verifier
   ASKS FOR; this says which LDAP attributes a TOKEN or an ASSERTION carries,
   per claim set, and it is the second half of BOTH claim-set pages —
   `/admin/claims` for the two JWT sets and `/admin/saml-attributes` for the two
   SAML ones, which is a split of the CONSOLE and not of anything here: this
   file still holds one selection per set and answers both pages through it. It
   registers no
   route and requires `helpers.js`, `admin_stats.js`, `vc_claims.js` and
   `audit.js`, none of which requires it back.

   **The catalogue is not copied and the three selections are not shared**, and
   both halves of that matter. One catalogue, because two lists of spellings is
   one list that will eventually be wrong about `schacDateOfBirth` while both
   look right alone. Three selections, because "issue a credential carrying a
   claim the access token does not" and "ask for a claim nothing here issues"
   are the mismatches a client's error paths are built for, and a single page
   setting all three would make both impossible to produce.

   **The merge into a token is INVERTED, and that is what keeps the four
   issuance sites unchanged.** `admin_stats.js` offers `setAttributeResolver()`
   and this module fills it at ITS require time; `jwtClaims()` and
   `samlAttributes()` then merge what comes back. It has to be that direction —
   `vc_claims.js` requires `admin_stats.js`, so a require the other way closes a
   loop (rule 2). Do not "simplify" it by calling this module from `oauth2.js`
   and the two assertion builders instead: four edited call sites are four that
   drift and a fifth added later with none. **`server.js` requires this module
   itself**, ahead of the modules that issue, because an unfilled slot means
   tokens issued without their configured attributes and `admin.js` requiring it
   would only make that true by accident.

   **Nothing is selected on a fresh start, in any of the four sets.** Unlike
   `/admin/vc`'s ten defaults — which reproduce what that issuer already carried
   — this page changes what every client of this service receives, so it does
   nothing until it is asked to.

   **Precedence is three deep and two of the three are only visible in a
   collision**: the protocol's own claim wins (an ID Token always carries
   `name`, `given_name`, `family_name`, `preferred_username` and `email`, so
   ticking `cn`, `givenName`, `sn`, `uid` or `mail` on THAT set changes nothing
   a client sees), then a typed claim of the same name, then the attribute. In
   the two assertion builders that had to be written as a FILTER rather than as
   an assignment order, because an assertion is a list of elements: a duplicate
   name is not an overwrite, it is two `<Attribute>` elements with one name and
   a relying party reading whichever was emitted first. SAML 1.1 filters on
   NAMESPACE AND NAME together, since that profile splits a claim URI into the
   two.


3d-ii. **`group_claims.js` is the FOURTH library over that catalogue's
   territory, and it is the only one that reads the directory's GROUPS.**
   `vc_claims.js` says what a CREDENTIAL carries, `vc_verifier_config.js` what
   the Verifier ASKS FOR, `claim_attributes.js` which ATTRIBUTES a token
   carries; this puts the GROUPS somebody is a member of into all four claim
   sets at once. It registers no route and requires `helpers.js`, `config.js`
   and `admin_stats.js`, none of which requires it back.

   **IT IS AUTOMATIC AND THEREFORE NOT A SELECTION.** There is nothing to tick
   per user and nothing to tick per set — with `groups.claim` on, all four
   carry it — which is also why it is REPORTED by both claim-set pages and
   owned by neither. That is the deliberate opposite of `/admin/claims`'s three
   selections, and it is why the control is a `config.js` ROW rather than a
   form: four settings on `/admin/config`, which already has a page and already
   has `POST /admin-api/config/set`, so the console's parity rule (rule 7) is
   satisfied by there being no new control. **A second form on `/admin/claims`
   or on `/admin/saml-attributes` would be a second door to one setting** —
   three doors now that there are two pages — which is the two-stores mistake
   rule 5 exists for.

   **ON BY DEFAULT IS DEFENSIBLE ONLY BECAUSE THE CLAIM IS OMITTED FOR SOMEBODY
   IN NO GROUP** — absent, not an empty array. On a fresh start the only people
   in a group are the three the directory seeds, so a caller who never touched
   `ou=groups` gets exactly the tokens it got before. An empty array would be a
   new member in every token every existing client parses, which is what
   `claim_attributes.js` defaults its selection to nothing to avoid.

   **TWO INVERSIONS, and each fails rule 3e's test in a different direction.**
   `admin_stats.js` offers `setGroupResolver()` and this module fills it (a
   require the other way closes a cycle, since this module requires that one for
   `identityKeyOf()`, the set ids and the reserved names); and this module offers
   `setDirectory()`, which `ldap_server.js` fills with `groupsOfUser()` — a
   require reaching THAT module would drag every `/ldap` route to the front of
   the router. What it buys is the thing every inversion here buys: NO ISSUANCE
   SITE CHANGED.

   **`ldap_server.js` OWNS WHAT A GROUP IS; THIS OWNS WHAT A TOKEN BELIEVES.**
   `groupsOfUser()` applies both group rules and resolves `member`,
   `uniqueMember` and `memberUid` exactly as the console's member list does —
   `memberUid` holds a bare name and the other two hold a DN, and treating them
   alike is how every `posixGroup` membership silently stops reaching a token.
   It reports BOTH directions (`via` for the group's own attributes,
   `viaMemberOf` for the person's claim) and applies neither, because which one
   a token believes is `groups.claimFromMemberOf` and that is a policy. Same
   split as `oauth2_bcp.js` and `oauth2.js`. **An entry is not required**: a
   group listing a DN nothing is stored at is a dangling member from the group's
   side and is still the group saying so.

   **PRECEDENCE IS NOW THREE DEEP IN A SECOND SENSE**, under the one rule 3d
   describes: a typed claim wins over a directory attribute, and both win over
   the groups claim — which is the only one of the three nobody named on a page.
   In `samlAttributes()` that is a FILTER for the reason stated there, and the
   groups layer is filtered against BOTH layers above it. A `groups.claimName`
   naming something this service sets itself is REFUSED AT ISSUANCE, not at
   configuration time, because `config.js` requires nothing from this repository
   and a copied reserved list is one that goes wrong.

   **A SAML ATTRIBUTE IS MULTI-VALUED and both builders now say so.** `values`
   is an array of `<AttributeValue>` children under one `<Attribute>`; `value`
   is untouched and is what every existing caller passes. One element per group
   with the same name is not a multi-valued attribute — it is a relying party
   reading the first and silently seeing one group where the person is in four,
   the exact defect `samlAttributes()`'s dedup filter exists to prevent.

   **CARRYING A GROUP IS NOT GRANTING ONE.** No endpoint here reads this claim
   and nothing decides anything on one, which is the same distinction this
   service already draws between an identity being RECORDED and one being
   AUTHENTICATED. What stopped being true is the OTHER half of the old sentence
   — "no token carries a group from this directory" — and the two halves are
   split on `/admin/groups`, on both claim-set pages and in README.md rather than
   merged back into one claim that is now half wrong.


---

3g. **`applications.js` is a library like `dpop.js`, and THE DIRECTORY IS ITS
   STORE.** It holds every application this service has been asked about — an
   OAuth client, an OIDC relying party, a SAML 2.0 or 1.1 service provider, a
   WS-Federation application, a WS-Trust relying party, the OID4VP verifier, a
   Kerberos service — as entries under `ou=applications`. It registers no route
   and requires only `helpers.js`, `audit.js` and `config.js`, so it cannot join
   a cycle;
   `admin_stats.js`, `oauth2.js`, `wsfed.js`, `wstrust.js`, `krb5_kdc.js` and
   `krb5_service.js` require it in the ordinary direction, and `ldap_server.js`
   fills its `setDirectory()` slot at require time for the reason
   `vc_claims.js`'s is filled (rule 6). Seven things are load-bearing:

   **A SIGHTING MAY NAME SEVERAL KINDS, AND TWO PROTOCOLS NEED IT TO.** `seen()`
   takes a list as readily as a string and accumulates them. A `wtrealm` is a
   WS-FEDERATION application AND the audience of whichever assertion it was
   handed; an `AppliesTo` handed a SAML 2.0 assertion is a WS-Trust relying party
   AND that assertion's service provider. Recording only the second of each left
   `wsfed-relying-party` a kind NO code path produced — offered by the console's
   filter and by the management API's enum, and matching nothing, forever. Pass a
   list rather than calling `seen()` twice: two calls count two authentications
   for one act, which is what `counts: false` exists to prevent one field over.

   **A KERBEROS SERVICE IS RECORDED AT BOTH ENDS, AND THAT IS NOT A DOUBLE
   ENTRY.** The KDC records an SPN when it ISSUES a service ticket
   (`krb5_kdc.js`'s TGS handler) and `krb5_service.js` records it again when it
   ACCEPTS one, under the same `SPN@REALM` identifier, so the two land on one
   entry with two descriptions. The acceptor's half is not redundant: it is the
   only one that fires for a ticket some OTHER KDC issued — a real Active
   Directory, which the parent project's real-DC and relay jobs use — where the
   client was recorded and the service was not. It goes in `accept()` and NOT in
   `spnego.js`, which calls that function for every check it makes and adds none
   of its own; a second call there would count one ticket twice.

   **THERE IS NO MAP SHADOWING THE ENTRIES.** Every read is a directory read and
   nothing is cached, which is what makes an `ldapmodify` of `oauthRedirectUri`
   change what RFC 9700 mode accepts on the NEXT request. A cache added for
   speed would quietly undo the whole design, and on a mock whose store is a Map
   in this process there is nothing to gain by one. `oauth2.js`'s
   `registeredClients` Map is GONE for the same reason — the RFC 7591
   registrations are entries, reached through `registrationOf()`.

   **THE SPELLING TABLE IS TWO LISTS AND ONE DOOR.** `ldap_server.js`'s
   `CANONICAL_NAMES` puts the conventional capitalisation back on a name the
   store lower-cased. It is `STANDARD_NAMES` (types somebody else defined, the
   specification named per group) plus `OWN_NAMES` (this service's inventions),
   each written ONCE as the canonical spelling with the lookup key derived by
   `toLowerCase()` — never as `lower: 'Mixed'` pairs, where a typo in the key is
   invisible and the table fails silently at its only job. It covers ~150 names
   rather than the ~30 this service writes, deliberately: the directory is
   schemaless and a certificate subject arrives as attributes nobody here chose,
   so a table that knew only its own writes would be wrong exactly where a reader
   needs it. FOUR SOURCES merge — the two lists, `vc_claims.js`'s catalogue and
   `applications.js`'s schema — and all four go through `learnName()`, which
   keeps the first spelling and WARNS on a second rather than letting merge order
   decide silently. Add a name to a list, never to the map; `memberOf` is in
   neither category and says so where it sits.

   **THE STORE'S TWO DIRECTIONS ARE NOT SYMMETRICAL, and that is the fix for
   the DN.** A WRITE speaks in attribute objects — all a record has to say — but
   `readApplication()` and `allApplications()` hand back the whole ENTRY (`dn`,
   `origin`, `createdAt`, `modifiedAt`, `operational`, `attributes`), the same
   shape `objectFor()` gives the console for a person. It has to be the entry,
   because THE DN IS NOT AN ATTRIBUTE — it is the key the entry is stored under
   — so a caller handed only the attributes had no way to learn where the
   application lives, and every applications page could show the `cn` and
   nothing else. The DN is published inside `attributes` as `entryDN` (RFC 5020,
   and what `matchable()` already calls it) and SYNTHESISED on every read: a
   stored copy is a second definition of one fact and the one that goes stale,
   which `applicationEntry()`'s rename fallback shows is a case that happens.
   Two consequences to keep. `view()` exposes `attributes` as the WHOLE entry
   and `fields` as the schema half `recordFromAttributes()` understands — they
   are different questions and the narrow one was being served under the wide
   one's name. And every attribute lookup in `applications.js` goes through
   `byLowerName()`, because names now arrive canonically spelled on the way out
   and lower-cased in the store; an index assuming either produces a record with
   an empty identifier rather than an error.

   **THE ATTRIBUTES WIN OVER THE STORED DOCUMENT.** RFC 7591 permits arbitrary
   metadata and RFC 7592's read must return what was registered, which no fixed
   attribute set can represent — so the whole registration is kept verbatim in
   `appRegistrationJson`. When the record is rebuilt that document is the
   STARTING POINT and every member with an attribute of its own is overwritten
   from the attribute. Reverse those and an operator's edit is silently ignored
   by the one check that matters, which is the two-stores failure in miniature.

   **THE SCHEMA IS A TABLE AND IT IS A VOCABULARY, NOT A CONSTRAINT.** node-ldapjs
   has no schema subsystem (its whole `lib/` mentions objectClass three times: a
   default filter and two result-code names) and it is a submodule this repo does
   not modify, so there was nothing to register with. `SCHEMA.attributes` is the
   definition: the entry is built by WALKING it, `/ldap/applications` publishes
   it, and an attribute not in it is REFUSED rather than written. `multi`
   accumulates and `single` is assigned — get that backwards on a counter and the
   entry grows a value per sign-in, which is `applyVcAttributes()`'s second rule.
   Where a registered class fits it is used (`applicationProcess`, RFC 4519);
   `stsApplication` is invented because nothing standard has a `client_id`.

   **THE APPLICATION FUNNEL IS NOT THE USER FUNNEL, and cannot be.** A person is
   recorded at `recordAuthentication()`; an application is recorded where its own
   protocol accepts it, because in the authorization code flow the person is
   authenticated in `authn.js`, which knows nothing about OAuth and never reads a
   `client_id`. `counts: true` exactly where a credential was accepted FOR that
   application — the authorization endpoint counts, the token endpoint does not,
   since redeeming the code is the same transaction continuing.

   **`ou=applications` IS ITS OWN CONTAINER AND MUST STAY OUT OF THE ou=users
   SWEEPS.** `populateVcAttributes()` would give an OAuth client a birthdate and
   `/admin/groups` reports membership from there; both already walk `ou=users`
   only. This is the OPPOSITE decision from `didPlan()`, where being outside
   those sweeps was the bug because a DID names a person.

   **THE CONSOLE IS NOT A THIRD DOOR.** `/admin/applications` and
   `POST /admin-api/applications/{action}` both call functions in THIS module —
   `createApplication`, `updateApplication`, `deleteApplication`,
   `forgetRegistration` — which do the same read-modify-write `seen()` does
   against the same entries. A form post and an `ldapmodify` are one act
   arriving by two routes, which is what keeps the one-store rule intact with
   three ways in. `applicationsView()` builds the HTML and the JSON together and
   the API throws the markup away, the way `usersView()`/`groupsView()` already
   do; the drill-down pages its ATTRIBUTE list under `attributesPage` rather
   than the bare `page`, which is `pagingOf()`'s convention for a view holding a
   list that is not the top-level one.

   **WHAT MAY BE CHANGED IS DECLARED AND NOT DERIVED, and the line is the
   `EDITABLE` table here rather than a judgement at each call site.** Declared is
   what the application may DO — redirect URIs, grant types, scopes, secret,
   auth method — which is configuration and is what RFC 9700 mode reads. Derived
   is what HAPPENED — the counters, the sightings, the kinds, the protocols,
   `appRedirectUriObserved` — and a form that could rewrite it would make the
   page lie about this service's own behaviour, indistinguishably from the
   recording being broken. `ldapmodify` still reaches everything: refusing it
   HERE is the difference between offering an operation and merely not
   preventing it. The console's selects are built from the same table the
   actions validate against, so a form cannot offer a field the action refuses.

   **`appAllowedProtocol` IS THE DECLARED TWIN OF `appProtocol`, AND IT IS THE
   ONE PLACE IN THIS MODULE WHERE TWO ATTRIBUTES HOLD ONE NOUN ON PURPOSE.**
   Added 2026-08-25 with `/admin/applications/new`. `appProtocol` is DERIVED —
   the families this application has appeared in, accumulated by `seen()` — and
   `appAllowedProtocol` is DECLARED: the families somebody ticked on that page
   before it had connected to anything. It is editable and the other is not,
   which is the `EDITABLE` line above applied to a pair that would otherwise
   look like a duplicate to anybody tidying up.

   **DECLARING A FAMILY GRANTS AND REFUSES NOTHING, and the sentence to change
   if that ever stops being true is the one in `PROTOCOLS`'s header rather than
   a page's.** No endpoint reads the attribute: an application declared for
   `saml2` alone is still issued an access token, because a mock that refused a
   protocol would remove a test case rather than add one. It is a record of
   intent, exactly as being in this registry at all is — the same claim
   `/admin/applications`'s caveat already makes about the whole entry.

   **THE VOCABULARY IS CLOSED AND VALIDATED IN TWO PLACES BECAUSE THERE ARE TWO
   DOORS.** `createApplication()` refuses an unknown family, and
   `updateApplication()` refuses one on an `add` — but NOT on a `remove`,
   deliberately: a remove names a value that is already on the entry and
   `ldapmodify` can have put anything there, so refusing it would shut the one
   door that could tidy that up.

   **THE MATCH BETWEEN THE TWO LISTS IS ON KINDS AND NOT ON PROTOCOL LABELS**,
   and that is the one thing here that was wrong first and is worth keeping
   written down. `view()` answers `recordedProtocols` beside `allowedProtocols`
   so a page can read them against each other; the first attempt derived it from
   `appProtocol`'s prose labels, and a FEDERATION partner's sighting is recorded
   under whichever protocol its relationship speaks — so every ordinary OAuth
   client read as a federation partner, because both write `OAuth 2.0`. The
   kinds are a closed vocabulary and `federation-identity-provider` is a thing
   an application IS. One consequence is stated on the page rather than hidden:
   a kind can also be given at CREATE time, so `recordedProtocols` is not
   "has authenticated" and `appAuthentications` is the figure that is.

   **`clientConfigOf()` IS WHAT THE SECURITY CHECKS READ, NOT `registrationOf()`.**
   The two answer different questions — "what may this client do" versus "what
   did it register" — and they stopped coinciding the moment the console could
   create an application with redirect URIs and no registration behind it. So
   the RFC 9700 checks in `oauth2.js` pass `clientConfigOf()`, which is built
   from the ATTRIBUTES; `appRegistered` records how an application got here and
   not whether what it holds counts. `registrationOf()` is still what RFC 7592
   and the UserInfo signing algorithm read, because those are genuinely
   questions about the registration.

   **THE TWO APPLICATIONS THAT ARE THIS PROCESS ARE SEEDED AT STARTUP, AND
   THEY ARE REGISTRATIONS RATHER THAN LABELS.** Every other entry arrives
   because a caller PRESENTED an identifier; the admin console and the
   management API are surfaces of this process, so nobody ever does, and the
   registry answered "what applications have you seen?" with everything except
   the two things the reader was standing in. `seedInternalApplications()` at
   the foot of this file writes `sts-admin-console` (a confidential OIDC
   relying party on the code grant) and `sts-management-api` (a confidential
   client on `client_credentials`), each with a secret and an RFC 7592
   registration access token minted at startup — so `clientConfigOf()` answers
   for them, RFC 9700 mode checks those secrets, and `GET
   /oauth2/register/{id}` reads back. Four rules on it. The call sits in
   `ldap_server.js` IMMEDIATELY AFTER `setDirectory()` — the earliest moment
   there is a container, and the reason it cannot live in that file's `seed()`,
   which builds the tree and does not know this schema. It is seeded ONLY WHERE
   THE IDENTIFIER IS FREE (`spiffe_registry.js`'s rule: an operator who deleted
   one meant it). Nothing serves `/admin/callback` and the API's two scopes
   grant nothing — the console's gate is a sign-on session and two directory
   groups, `/admin-api` is not gated at all, and both facts are on the entry
   rather than in a comment because an `ldapmodify` of them is a configuration
   change. And `applications.seedInternal` turns it off, restart-only because
   this runs once at require time.

   **TWO ATTRIBUTES HOLD CREDENTIALS IN THE CLEAR** — `oauthClientSecret` and
   `appRegistrationAccessToken` — which is the `/krb5/principals` decision about
   the Kerberos passwords, made again and for the same reason. Now that RFC 9700
   mode CHECKS that secret, anyone who can read the directory can authenticate as
   that client; that is the honest state of a service that authenticates nobody.
   They are never given to `audit.js`, whose no-credential rule is untouched.


---

3l. **`delegation.js` is a library like `audit.js`, it sits BESIDE
   `admin_stats.js` too, and THERE IS NO FUNNEL FOR IT — which is the one thing
   about it that breaks a pattern this repository otherwise keeps.**
   `admin_stats.js` answers "how much", `audit.js` answers "what, when and to
   whom", and this answers *who acted on whose behalf, through what, to reach
   what* — one model over Kerberos S4U2Self, S4U2Proxy (classic and
   resource-based) and a forwarded TGT, WS-Trust `OnBehalfOf` and `ActAs`, and
   RFC 8693 token exchange in both its shapes.

   It requires `helpers.js`, `config.js` and `admin_stats.js` — that last one
   for `identityKeyOf()`'s normalisation only, so that `alice`, `alice@REALM`
   and `urn:sts-mock:user:alice` are one person on a chain rather than three.
   `admin_stats.js` requires nothing here, so there is no cycle and none of
   rule 3e's slots is needed. Keep it that way: it is called from the KDC, from
   WS-Trust and from the token endpoint, and anything it required all three
   would require transitively.

   **THE MISSING FUNNEL IS THE THING TO UNDERSTAND BEFORE CHANGING ANY OF IT.**
   `signJwt()` is the single point every JWT passes and
   `recordAuthentication()` is the single point every accepted credential
   passes, so each of those is counted in one place and a new call site cannot
   be forgotten. Delegation has no such point and cannot be given one: it
   happens in three modules that share no code path, and the moment it becomes
   visible is different in each — a padata in a TGS-REQ, an element in an RST,
   a form field on a token request. So this file is called from several places
   ON PURPOSE. What the shape buys instead is that all of them produce the same
   row, and each caller is as close as possible to a funnel of its own:
   `krb5_kdc.js` records ELEVEN refusal paths at ONE site, by carrying an
   `intent` out of `resolveS4u()` through `refuseS4u()`.

   **REFUSALS ARE RECORDED AND THAT IS MOST OF THE POINT.** A delegation that
   succeeded is also an accepted credential, so it already has an
   `authentication` row and a `/admin/users` row. A delegation that was REFUSED
   has neither — nothing was accepted — so this is the only list it is in, and
   it is the one somebody hunting a misconfiguration actually wants. The reason
   on the row is the KDC's OWN `e-text`, the same sentence the client was sent,
   rather than a second wording that could come to disagree with it.

   **NOTHING HERE WRITES AN AUDIT ROW, deliberately.** A successful act would
   get a second row for one act, which is the double-count rule 3c warns about;
   a refused one writes none because nothing was accepted, and closing that gap
   is what this store is for rather than a seventh audit category. Cite this
   paragraph before adding an `audit()` call to it.

   **`record()` CANNOT THROW.** The whole body is wrapped and a caller must
   never guard it — the fourth place that rule applies (after `audit()`,
   `signJwt()`'s recorder and the directory's user observer), and the first
   where the thing it protects is a Kerberos ticket already half built.

   **A ROW IS AN ACT, NOT A RELATIONSHIP**, and `chainKey` is what collapses
   them: the mechanism and the three parties, with the time, the credentials
   and — deliberately — the OUTCOME left out, so a chain refused nine times and
   then fixed is ONE edge that changes colour rather than two that never meet.
   `chainList()` is where the collapse lives, here rather than in `admin.js`,
   because what counts as one chain is a statement about this store.

   One thing it deliberately does NOT do: create an application entry for a
   layer it names. `ou=applications` holds what this service was ASKED ABOUT,
   and a delegation naming something nobody has otherwise mentioned — an RFC
   8693 `audience`, typically — is an ordinary and interesting outcome. The
   page resolves the name against that registry and reports which of the two it
   found; writing the entry from here would be a fifth door onto it and would
   make the page unable to report the difference.

   **`graph()` IS THE PICTURE'S MODEL AND IT IS NOT `chainList()` WITH BOXES.**
   `/admin/delegation/map` draws it and `../admin-ui/delegation_map.js` lays it
   out; this file says what the nodes and edges ARE, for the reason every other
   view function is here — what counts as one party is a statement about this
   store. It walks the ACTS rather than that function's answer, deliberately: a
   chain has three parties and therefore up to TWO edges, the boxes are SHARED
   between chains (which is the whole reason to draw one), and it needs the two
   things `chainList()` drops on purpose — the CREDENTIALS, since the picture is
   asked to say what was issued, and the spread of one identity across roles.
   Reading them back off a chain would have meant putting them into a chain and
   making that shape a worse answer to the question it does answer.

   Four judgements are in it and each is argued at length above the function. A
   NODE IS AN IDENTITY rather than a role, so a party that is the target of one
   chain and the intermediary of the next is ONE box with a line in and a line
   out. AN ABSENT PARTY IS NOT A BOX and the edge jumps it, carrying `skipped` —
   a shared "(nobody named)" node would make every unconstrained delegation in
   the process appear to converge on a party they have in common. A SELF-EDGE IS
   A FACT ABOUT THE BOX (`selfTarget`) and not a loop on it, because S4U2Self is
   a ticket to yourself and an arrow leaving a box and coming back draws nothing.
   And THE ISSUER IS IN THE PICTURE and is not a party: one node carrying the
   TRUST REALM, with an edge to whoever ASKED — the intermediary where a chain
   has one, the initial identity where it does not.

   **`nodeIdOf()` is `chainKeyOf()`'s expression with the APPLICATION normalised
   too**, and that difference is not an oversight in either. A party carries
   `key` — `identityKeyOf()`'s answer — only when something was PRESENTED, so a
   target names an application and its identifier arrives exactly as the protocol
   spelled it. On an S4U2Self that is one principal twice, and unnormalised the
   picture drew the requester and the service it asked for a ticket to ITSELF as
   two boxes with a line between them. **Two spellings of one identity is two
   people** — the rule `dnRfc4514()` and `userFor()` follow one layer down. The
   TABLE is deliberately left alone: it shows both spellings side by side, where
   seeing them is the point, and changing `chainKey` would change what
   `/admin-api/delegation` calls a chain.

   **`actsOfChain()`, `applicationList()`, `applicationRolesIn()` and
   `actsForApplication()` are the same rule again, for the two drill-downs the
   console grew on 2026-08-25.** They are here, beside `chainList()`, because
   each answers a question about what the STORE holds rather than about how a
   page looks: which acts belong to one chain, which applications appear in
   these acts, and what role a given application played in a given act. A
   `filter()` in `admin.js` would have been a second opinion about the last of
   those and would have drifted from the first.

   **The APPLICATION is keyed on its IDENTIFIER and deliberately NOT on
   `nodeIdOf()`'s answer**, which is the one thing to understand before touching
   any of them. A node is what a party IS — its normalised identity where it
   presented one — and for a Kerberos front end that is the same string as its
   application. For an RFC 8693 exchange it is not: the intermediary's box is
   the ACTOR named in the actor_token, and the application it acted THROUGH is
   the `client_id` beside it. So a chooser built on node ids would offer that
   client under a person's name or not at all, and *show me everything delegated
   through this client* is the question `/admin/delegation/application` exists to
   answer. The identifier is normalised the way `nodeIdOf()` normalises one, so
   two spellings are one application, and every spelling is kept beside the key —
   the collapse has to be something a reader can SEE, which is `party()`'s reason
   for keeping `presented` next to `key`.

   **The CONFIGURED half of `/admin/delegation` is NOT in this file.** Who may
   delegate to whom is `krb5_principals.js`'s `delegationPolicy()`, because
   what those two attributes mean is a statement about the principal database
   and that store is over there. A `common/` module reaching into `kerberos/`
   would have been the layering inversion this directory's entry test exists to
   prevent; `admin.js` requires both and renders them side by side.

---

## An OAuth client is not a person, and now it has somewhere to be

* **An OAuth client is not a person, and now it has somewhere to be.** It is still
  skipped by `autoCreateUser()` — `ou=users` is for people — but every client,
  relying party, service provider and Kerberos service gets an entry under
  `ou=applications` instead (rule 3g). That container is a REGISTRY rather than a
  record: the RFC 7591 registrations live there, nothing caches them, and an
  `ldapmodify` — or a form on `/admin/applications`, or a POST to
  `/admin-api/applications/{action}`, which are the same functions — changes what
  the protocol endpoints do. What those two will NOT change is the derived half:
  the counters and the sightings are what happened, and only LDAP reaches them.
  Since 2026-08-25 there is a THIRD door onto the create, `/admin/applications/new`,
  and it is not a third store either: it posts `action=create` to the same
  endpoint the list page's own row does.
