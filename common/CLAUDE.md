# common/

The modules every other directory reads. Nothing in here belongs to a protocol,
and that is the entry test rather than a description: a file lands here because
more than one family needs it, not because it felt general.

| File | What it is |
|---|---|
| `config_file.js` | The one place that decides what `CONFIG_FILE` means. Requires nothing at all. |
| `config.js` | Every setting this service has, and the refusal to start without one. The only module `helpers.js` depends on. |
| `helpers.js` | Log, keys, `signJwt()`, `userFor()`, the cross-protocol parsers. |
| `crypto.js` | **EVERY SIGNATURE AND EVERY CIPHER IN THIS SERVICE, since 2026-08-27.** XML Signature and XML Encryption, JWS, JWE, key and certificate generation, thumbprints, constant-time comparison. A LEAF — it sits UNDER `helpers.js` and may never require it back. See below. |
| `app.js` | The express app and every middleware. Requiring it is how a protocol module gets somewhere to register. |
| `admin_stats.js` | The counters, the revocation set, and `recordAuthentication()` — the single authentication funnel. |
| `audit.js` | What happened, when, and to whom, as discrete events. Sits BESIDE `admin_stats.js`, not under it. |
| `applications.js` | Every application this service has been asked about, stored in the directory under `ou=applications`. |
| `delegation.js` | Who acted on whose behalf, through what, to reach what — eight mechanisms across three protocol families in ONE model. What HAPPENED. |
| `app_permissions.js` | **Who MAY reach what, decided in advance** — delegated permissions between two OAuth application entries, in Microsoft Entra ID's shape. The CONFIGURED twin of the file above it, and never to be drawn as one register with it. |
| `user_graph.js` | ONE PERSON, END TO END: that register UNIONED with the issued one, so a picture can show every grant, flow, assertion, ticket and SVID in somebody's name beside every delegation naming them. |
| `credential_graph.js` | ONE CREDENTIAL, END TO END: where it came from — who held it, in whose name, to reach what — and every generation of exchange behind it, back to the issuance the line rests on. |
| `claim_attributes.js` | Which LDAP attributes a token or an assertion carries, per claim set. |
| `group_claims.js` | The groups claim, in all five claim sets at once. |
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

`userFor`, `parseBody`, `bodyValues`, `oauthError`, `vciError`, `signJwt` and
`firstByLocal`/`textByLocal` are in `helpers.js` because more than one protocol needs
them, not because they are especially general. The last two are read by three parsers
— the WS-Trust RST, WS-Federation's `wreq`, and the `wresult` the mock relying party
is POSTed — and they match on **local name with the namespace ignored** because the
trust namespace alone has four versions in use. That is what lets one parser answer
WS-Trust 1.0 through 1.4 instead of four.

**`bodyValues()` IS THE NEWEST OF THEM AND IT EXISTS BECAUSE `parseBody()` IS NOT
GOING TO CHANGE.** That function builds a PLAIN OBJECT, so a repeated field keeps
only its last value: `resource=a&resource=b` on a Token Request arrived as `b`
and the first was silently gone. Two specifications say the parameter may repeat
— RFC 8707 section 2's `resource` and RFC 8693 section 2.1's `audience` — so
until 2026-08-26 neither could actually be repeated here whatever the RFC said.
The fix is a second reader beside the first rather than a new shape for it:
sixty-odd call sites across fourteen modules read that object with
`String(body.x)`, and giving them an array for a repeat would change what every
one of them sees to serve two parameters. **The authorization endpoint needs none
of it** — it reads `req.query`, and express gives an array for a repeat already,
which is worth knowing before somebody looks for the same bug there.
`admin-ui/admin.js`'s `listField()` is the same function, written first, for the
console's checkbox columns; neither calls the other because that module requires
`oauth2.js` (rule 5) and nothing below it can require back. The shapes are
deliberately identical, so folding them is a one-line delegation in THAT file.

**`dnRfc4514()` MOVED HERE RATHER THAN BEING WRITTEN
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

`privateKeyPem` is KEPT and is not deprecated — `crypto.js`'s XML signer hands
it to node-forge, which wants a PEM. **A caller picks by what it is doing**:
`signJws()` takes `STS.privateKey`, `signXml()` takes `STS.privateKeyPem`. They
are the same key and are derived from each other, so they cannot drift.

That sentence used to name three files and xml-crypto. There is one signer now
and this service requires xml-crypto nowhere — see below.

---

## `crypto.js`: one signer, one verifier, one cipher

**It replaced six XML signers, four XML signature verifiers, two hand-rolled JWE
halves, three RFC 7638 thumbprints, two self-signed certificate builders and two
`timingSafeEqual` wrappers.** None of those was carelessness: each was written
where it was needed and the copies agreed on the day they were made. What the
copies cost is recorded in `saml/CLAUDE.md` — the `Id="_0"` defect, where every
SAML 1.1 assertion this service ever issued carried an attribute the schema does
not have, it verified anyway so it survived for months, and the fix had to be
applied to EACH SIGNER SEPARATELY.

**The mechanism is `common/vendored/xmldsig.js` and the policy is here**, and
that split is the design rather than tidiness. The vendored file is the parent
project's own XML security module, copied byte-identical, and it is the OTHER
END of most of these exchanges: `tests/xmlsec_interop.js` over there already
drives it against xml-crypto AND xml-encryption across all three SAML versions.
What `crypto.js` adds is what is true of THIS service — which placements its
documents use, that a verifier must be TOLD which element it is checking, that a
decryption answers rather than throws, that a token read back against our own
certificate gets the configured clock skew.

**IT IS A LEAF AND MUST STAY ONE.** It requires npm packages, the vendored
signer and `config.js` — which requires nothing here — so the require is
downward and no cycle is possible. `helpers.js` requires IT. Concretely that
means **nothing in it reads `STS`, the ambient realm or a session**: every
function takes the key it is to use as a parameter, and the realm-aware half
stays in `helpers.js`. It also means `logArtifact()` is out of reach, which is
why `encryptElement()` takes the logger as an ORDINARY PARAMETER that
`saml/saml2.js` fills in — not a sixth inverted slot, because rule 3e is for a
require that would close a cycle or move a route, and a caller that already has
the function can simply hand it over.

**THE VERIFIER TAKES THE ELEMENT'S NAME AND THAT IS NOT A CONVENIENCE.** A SAML
Response carrying a signed assertion has two signatures. Three of the four
implementations this replaced took the FIRST `<ds:Signature>` in the document,
so a caller asking "is this Response signed by us" was answered about the
ASSERTION — a confident yes about a different element, one step from accepting a
response whose assertion was swapped for another validly-signed one. The shared
verifier is told which element, takes the signature that is that element's own
DIRECT CHILD, and additionally refuses a signature whose reference names
something else, which none of the four ever checked. `tests/crypto_module.js`
asserts all of it and was mutation-tested against eight mutants.

**XML ENCRYPTION MOVED RATHER THAN BEING REPLACED**, and it is the one place the
vendored file did not win. It was never duplicated — one implementation, two
callers — and the vendored `encryptXml()` produces a byte-compatible document,
so there was no interop gap to close. What this one has is the DIAGNOSIS: it
answers rather than throwing, names an unknown cipher and an unknown key
transport separately, checks the unwrapped key's LENGTH (RSA-1_5 unwraps a wrong
key to plausible garbage rather than failing), parses the plaintext before
calling CBC a success, and tells a NamespaceError in a good NameID apart from a
wrong certificate. Those messages are the product.

**THE PROTECTED HEADER IS THIS FILE'S TO BUILD, AND FOR THREE YEARS TWO OF THE
THREE SIGNING PATHS DID NOT HONOUR A CALLER'S.** `jsonwebtoken` merges
`options.header` into the header it makes, so the library path had always taken
a caller's `typ`. The other two — the `ownSigner` branch (EdDSA and ES256K, the
two the library refuses) and the post-quantum branch — each hard-coded
`typ: 'JWT'` and ignored `options.header` entirely. **The same call therefore
produced a different header depending on which algorithm was chosen**, and no
caller could have seen that coming from the outside.

It was found on 2026-08-31 by the Shared Signals family, which is the first
thing here that mints a JWT that is not an ordinary one: RFC 8417 section 2.2
gives a Security Event Token `typ: "secevent+jwt"`, and a receiver that
dispatches on the media type — several do — drops one without it with no error
anybody sees. On RS256 it got the header it asked for; on EdDSA, ES256K and
every post-quantum algorithm it silently did not.

`protectedHeaderFor()` is the fix and all three paths go through it.
**`alg` and `kid` remain this file's to set and a caller may not override
them**: the algorithm is what was actually used and the kid names the key that
was actually used, so a caller that could change either would be labelling a
signature as something it is not. Everything else in `options.header` is merged.
`helpers.signJwtAs()` and `signJwtAsAsync()` thread it through, which is how the
one caller that needs it reaches it.

**xml-crypto IS STILL A DEPENDENCY AND NOTHING IN THE SERVICE REQUIRES IT.** It
is there for `tests/crypto_module.js`, which is the only independent reading of
XMLDSIG in this repository — the thing that makes "our signature verifies"
mean something. Removing it saves a package and costs that.

## `applications.js` GREW A FOURTH ATTRIBUTE ROLE, AND THE NAME IS THE ARGUMENT

`declarationAttributes()` walks the `PROTOCOLS` table for an `identifier`, a
`redirect`, a `logout` and a `secret`. Shared Signals added a fifth kind of
attribute and it was given a **`delivery`** role of its own rather than being
folded into `redirect`.

The temptation is obvious — both answer "where does the answer go?" — and it is
wrong in a way this repository is otherwise careful about. **A redirect is where
a BROWSER is sent back to after a protocol hop. `ssfDeliveryEndpoint` is a URL
this service OPENS A CONNECTION TO.** Calling it a redirect would make a table
that is read literally, by the console and by `GET /admin-api/applications/new`,
say something false about the one attribute here with an outbound request behind
it.

The attribute itself is DECLARATION ONLY and nothing reads it: a push goes to
the endpoint on the STREAM, which the receiver named when it created one, and
this service will not take a URL to dial from an application entry. That is the
same position `federation/federation_http.js` takes about `oauthJwksUri` one
family along — a URL recorded here is a note about what a receiver IS, and a URL
on a stream is a URL this service dials. The two are deliberately not one store.

Its sibling `ssfReceiverId` is the opposite and is worth the contrast: it is one
of the few declaration attributes a PROTOCOL also writes, because a receiver
authenticating and being agreed a stream is exactly the kind of event this
registry exists to hold.

## `worker.js` and `worker_pool.js`: the computation that must not run here

Node runs this service's six listener families on ONE THREAD, so a synchronous
computation does not slow it down, it STOPS it. Post-quantum signing is that
computation — stalls of 14.6, 15.4, 17.8 and 23.3 seconds were measured on
2026-08-29 — and the root `CLAUDE.md` has the argument, the table and the five
things to know. This is the module-level half.

**`worker.js` is the child process AND the job table**, and it is one file for
that reason: the table it exports is what the pool runs in THIS process when
`workers.count` is 0, so "a pooled signature and an unpooled one are the same
bytes" is true by construction rather than by a test that happens to pass. The
wiring that makes a process a worker is guarded on `require.main === module`, so
requiring this file to reach the table does not turn the requiring process into
a worker. Three jobs: `pq.sign`, `pq.verify`, `pq.generate`. Each is
**synchronous on purpose** — blocking is what a worker is for, and a table of
promises would invite a second job onto a process that is already computing,
which does not make it finish sooner and makes the pool's idea of "least loaded"
a fiction.

**`worker_pool.js` is fork, route, restart and drain**, and four of its
decisions are worth knowing before changing any of them.

* **The pool is lazy and re-read per job.** Nothing is forked until the first
  post-quantum job, which is what keeps every in-process loader of this tree —
  the parent project's Kerberos jobs, `npm test`, `env/generate_defaults.js` —
  free of children they would never use. Re-reading `workers.count` on every
  call is what makes it genuinely runtime rather than runtime-in-the-table.

* **A worker is REFERENCED only while it is owed an answer, and BOTH halves have
  to be** — the child process handle and the IPC channel. This is the one that
  cost an afternoon: with the process handle left unreferenced, node drained its
  event loop the instant a worker was SIGKILLed, so the `exit` that fails that
  worker's jobs was never delivered and the promise never settled. It looked
  like a hang, and it was **LOG-LEVEL DEPENDENT** — at `debug`, bunyan's writes
  to a piped stdout were themselves enough to hold the loop open, so the same
  code passed at one level and hung at another.

* **A worker that dies FAILS its jobs, with a sentence.** A promise nobody
  settles is a request that hangs, which is the symptom this whole module
  exists to remove. The replacement is forked by the next job rather than
  immediately, and after `QUICK_EXIT_LIMIT` short-lived exits in a row the pool
  **gives up on children and computes here** — a child that cannot start is a
  broken `CONFIG_FILE` or a machine out of memory, and forking it forever would
  turn a service that works slowly into one that does nothing but fork. One
  finished job resets the count.

* **Affinity is a preference and never a correctness requirement.** A worker
  remembers nothing, so forgetting a session costs a re-route and nothing else —
  which is why the map is capped and drops its oldest entry rather than growing
  for as long as a test suite mints sessions.

**Requiring `worker_pool.js` is what arms `pq_jose.js`.** The reference is
handed down from the foot of that file, because the pool requires `worker.js`
which requires `pq_jose.js` and a require back up would close a cycle (rule 2).
The side effect is the point, and it is the same shape as rule 1 — requiring a
protocol module is what registers its routes. **A worker is never armed**,
because a child requires `worker.js` and `worker.js` does not require the pool.

`common/crypto.js` is what requires it, because that is the module that routes
an `alg` to `pq_jose.js` in the first place. `crypto.js` gained
`signJwsAsync()`, `verifyCompactJwsAsync()` and `verifyJwsAsync()` beside their
synchronous namesakes rather than in place of them: every other caller in this
service verifies RS256 in microseconds and has nothing to gain from a promise.
`verifyCompactJws()` was split into `prepareVerification()` / `verifyBytes()` /
`finishVerification()` so that both entry points run the same reading of the
token and refuse in the same ORDER — a token whose `alg` is not in the caller's
list is refused for that and never for its signature, whichever was used.

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
REALM's value — which is what makes every settings form in the console,
`/admin/token-lifetimes` and `POST /admin-api/config/set` realm-aware without
one of them being edited, including the twenty-one drawn on protocol pages
since 2026-08-27.
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

### `onChange()`: a realm row changed, and it is an EVENT rather than a slot

Added 2026-08-27 for persistence. `onCreate()` and `onRemove()` already covered
two of the five doors into this registry; the other three — `update()`,
`setOverride()` and `clearOverride()` — had no hook at all, because until a realm
could be written down nothing needed to know that a name or an override had
changed.

**It is not another inverted hook, and the distinction is worth keeping.** Rule
3e's slots exist because a require in the obvious direction would close a cycle
or move a route, and the module on the far end fills a hole this one left. This
is the opposite shape: `persistence/persistence.js` REQUIRES this file, in the
ordinary direction, and subscribes. Nothing here knows what persistence is or
whether any exists, and a process that never loaded that module has an empty
listener list and behaves exactly as it did.

It fires AFTER the change, for the reason `built()` runs after the registry row
is written — a listener that reads the registry back must see what the caller
just did. **`remove()` fires it after the PURGES**, and that ordering is the
whole of what makes a removal persist correctly: a listener fired before them
would walk stores that still held the realm's entries and write them all back
down. A listener that throws is logged and does not fail the operation: the realm
IS renamed, and a persistence layer that could not write it down has not made
that less true.

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
one row it appears in the admin console — on the page for the protocol it
configures, which since 2026-08-27 is where each group is drawn — in
`GET /admin-api/config`, in the OpenAPI
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
`checkOverride(key, raw, forRealm)` takes a third argument, and the refusal a
person meets at `/admin/oauth2` in the default realm — and at `POST
/admin-api/config/set` outside a realm — is unchanged. `describe()` decides
`editable` the same way, so the console under a realm's prefix offers the
control the same page in the default realm correctly refuses.

**OMITTING THAT ARGUMENT MEANS "WHEREVER THIS WRITE WOULD LAND", SINCE
2026-08-28, AND UNTIL THEN IT MEANT "NOWHERE".** `realms.js`'s
`checkRealmOverride()` passes `true` explicitly, because it validates a realm's
overrides before any realm is ambient — it is the only caller that can know the
answer without asking. Every OTHER caller is inside a request, so the realm is
the ambient one, and every one of them passed nothing: `setOverride()` here,
and the three places in `admin-ui/admin.js` that pre-validate a whole section
before writing any of it. **So the exemption was unreachable through the four
doors a person actually uses**, and the symptom was worse than the rule being
absent. The console draws this control ENABLED inside a realm — correctly — and
a settings section's Save posts `set-many`, which is ALL-OR-NOTHING, so pressing
Save on `/realm/acme/admin/oauth2` was refused BY NAME every time, including
when nothing on the page had been changed, with a refusal that explained that a
realm may carry the setting it was refusing. The whole page was unusable inside
a realm. `checkOverride()` now defaults the argument from `realmFor(key)`, which
fixes all four call sites at once and leaves an explicit `true` and an explicit
`false` meaning exactly what they did. The parent project's
`tests/vendored/sts_admin_console.js` presses that Save button and is the guard; the
in-process half is `tests/appconfig_persistence.js`, which asserts the rule
itself.

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
every settings form in the console and the OpenAPI `ConfigSetting` schema
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
service running on one value while the console, the OpenAPI document's
`default` property and README.md's table all report the other. That generator
neutralises `process.exit` for the length of its own `require` of this module,
because regenerating the file is the one moment when an incomplete
`env/defaults.js` is EXPECTED; the bypass is in the build tool and deliberately
not a flag here, since a flag in the service is a flag somebody can leave on.

**3q. THE RUNTIME OVERRIDE LAYER IS DURABLE SINCE 2026-08-27, AND IT IS STILL
ONE LAYER.** `setOverrideStore()` is an inverted hook filled by
`persistence/persistence.js`, and it passes rule 3e's test on the same clause the
realm slot above it does: that module reads `persistence.mode` and four more
settings through `value()`, so it requires this file, and a require back closes
the cycle — node answers a cycle with a half-initialised module whose exports are
`undefined`, and the symptom would arrive later as "notify is not a function"
from inside a console Save.

**IT IS A NOTIFICATION AND NOT A STORE**, which is why it takes a realm id and
returns nothing. This file does not know what persistence is, whether it is on,
or where it writes; it knows that something changed and IN WHICH REALM, because
that is the thing only this file can say — a process-wide override and a realm's
override are written to different places by the module on the far end, and
`setOverride()` already makes exactly that decision for its own purposes.
**`clearOverride()` and `clearAllOverrides()` fire it too**, and that is the half
that is easy to miss: a store told only about writes would still hold a cleared
override and would put it back on the next start, which is worse than no reset at
all.

**THERE IS STILL NO SIXTH LAYER**, and the reason is `applyPersistedOverrides()`:
saved values are put back through the same `setOverride()` path a caller uses, so
what comes out of the store is a layer-1 runtime override and nothing else. The
ordering above is untouched, and an environment variable still does NOT beat a
saved override — because a saved override is a runtime override, and layer 1 has
always beaten layer 2.

**RE-APPLYING THEM AFTER EVERY MODULE HAS LOADED IS SAFE, and it is a property of
the table rather than of the ordering.** Only a `runtime: true` setting can be
overridden at all — `checkOverride()` refuses every other by name — and a runtime
setting is BY DEFINITION one that is read per call rather than captured at
require time; that is what the column means and what `restartReason` documents
the absence of. So nothing in a saved file can reach `global.https`,
`oauth2.rfc9700`, `ldap.port` or `ldap.baseDn`, and **a saved file cannot change
the scheme this service answers on**. Every value is re-checked on the way back
in rather than trusted: the file was written by this service, but possibly by an
older version of it, and a setting may have been renamed, retyped, had its enum
narrowed or been made restart-only since.

`persistence/CLAUDE.md` argues the rest. A REALM's overrides are not in this
layer's file at all — they live on the realm row and are written down with the
realm registry, because that is where they live in memory too.

**`resolve()` READS THE TWO FILES SEPARATELY EVEN THOUGH THEY ARE UNIONED**, and
that is not redundancy: `appconfig` is the union and is what the bootstrap logger
reads, while `resolve()` digs the operator's file and then `env/defaults.js` so
it can say WHICH — `source: 'appconfig'` against `source: 'defaults'`. A value
from the operator's file and the same value from the defaults are
indistinguishable once merged, and "where did this come from?" is the question
the *Source* column on every settings form exists to answer. `auditAppconfig()` reads the operator's file
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
'./config'` before any test has run. **IT NEEDS `env/` AS A WHOLE DIRECTORY
TOO**, and that line is in place over there since the 2026-08-28 repair (see
`docs/parent-project-migration.md`): this module requires `env/defaults.js` by
absolute path off the package root whatever `CONFIG_FILE` says, so narrowing the
copy to the one file a job names puts every in-process job back to dying at load
with `Cannot find module` naming a file the operator never mentioned.


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
   question it exists for. Restarting the service is how you get an empty one:
   the ring is in memory and dies with the process, and **it stays that way now
   that some things do not** — see `persistence/CLAUDE.md`. An audit log is
   something this process RECORDED rather than something somebody TYPED, which
   is the line that decides what is written down, and it is on the resetting
   side of it. Persisting it would also make "restart to clear" stop being
   true, which is the only clear operation there is.


3d. **`claim_attributes.js` is the THIRD reader of `vc_claims.js`'s catalogue,
   and it is a library like the other two.** `vc_claims.js` says what an issued
   CREDENTIAL carries and `vc_verifier_config.js` says what the mock Verifier
   ASKS FOR; this says which LDAP attributes a TOKEN or an ASSERTION carries,
   per claim set, and it is the second half of ALL THREE claim-set pages —
   `/admin/claims` for the two JWT sets, `/admin/userinfo-claims` for the
   UserInfo one and `/admin/saml-attributes` for the two SAML ones, which is a
   split of the CONSOLE and not of anything here: this file still holds one
   selection per set and answers all three pages through it. **Adding the fifth
   set on 2026-08-26 edited nothing in this module**, which is what `SET_IDS`
   being read off `admin_stats.js` rather than written out again is for. It
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

   **Nothing is selected on a fresh start, in any of the five sets.** Unlike
   `/admin/vc`'s ten defaults — which reproduce what that issuer already carried
   — this page changes what every client of this service receives, so it does
   nothing until it is asked to.

   **Precedence is three deep — four at the UserInfo endpoint — and most of it
   is only visible in a collision**: the protocol's own claim wins (an ID Token always carries
   `name`, `given_name`, `family_name`, `preferred_username` and `email`, so
   ticking `cn`, `givenName`, `sn`, `uid` or `mail` on THAT set changes nothing
   a client sees), then a typed claim of the same name, then the attribute. In
   the two assertion builders that had to be written as a FILTER rather than as
   an assignment order, because an assertion is a list of elements: a duplicate
   name is not an overwrite, it is two `<Attribute>` elements with one name and
   a relying party reading whichever was emitted first. SAML 1.1 filters on
   NAMESPACE AND NAME together, since that profile splits a claim URI into the
   two.

   **THE USERINFO ENDPOINT HAS A FOURTH LAYER ABOVE ALL THREE, and it is the
   only one a CLIENT controls.** OpenID Connect Core section 5.5's claims
   request names individual claims, and `requestedClaimsFor()` in this module
   resolves them off the same catalogue — indexed the other way round, by claim
   name rather than by LDAP attribute type, including the top-level name of a
   nested claim (`address` returns the whole Address Claim of Core 5.1.1) and a
   language tag as part of the name (Core 5.2). It wins over the three above it
   BY DESIGN and the reason is written at the merge in `oauth-oidc/oauth2.js`: a
   scope asks for a category and a request names a claim, so answering
   `{"email":null}` with the invented persona value while the entry holds a real
   `mail` would defeat the only reason the feature exists. Nothing it can
   resolve is a structural claim — every name comes from this catalogue or from
   `PERSONA_CLAIMS` — so `sub`, `iss` and `exp` are out of its reach by
   construction rather than by a guard.


3d-ii. **`group_claims.js` is the FOURTH library over that catalogue's
   territory, and it is the only one that reads the directory's GROUPS.**
   `vc_claims.js` says what a CREDENTIAL carries, `vc_verifier_config.js` what
   the Verifier ASKS FOR, `claim_attributes.js` which ATTRIBUTES a token
   carries; this puts the GROUPS somebody is a member of into all four claim
   sets at once. It registers no route and requires `helpers.js`, `config.js`
   and `admin_stats.js`, none of which requires it back.

   **IT IS AUTOMATIC AND THEREFORE NOT A SELECTION.** There is nothing to tick
   per user and nothing to tick per set — with `groups.claim` on, all five
   carry it — which is also why it is REPORTED by all three claim-set pages and
   owned by none of them. That is the deliberate opposite of `/admin/claims`'s
   three selections, and it is why the control is a `config.js` ROW rather than a
   form: four settings in `config.js`'s table, drawn by the console on
   `/admin/groups` — where the membership they name is — and already served by
   `POST /admin-api/config/set`, so the console's parity rule (rule 7) is
   satisfied by there being no new control. **A second form on `/admin/claims`,
   `/admin/userinfo-claims` or `/admin/saml-attributes` would be a second door
   to one setting** — four doors now that there are three pages — which is the
   two-stores mistake rule 5 exists for.

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
   definition: the entry is built by WALKING it, `/admin/ldap/applications` publishes
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

   **EVERY PROTOCOL FAMILY NOW NAMES THE ATTRIBUTES ITS CONFIGURATION LANDS
   ON**, and that is what removed the KIND select from the create form rather
   than a second table being added beside it. A `PROTOCOLS` row carries
   `identifierAttribute` and `redirectAttribute`; `declarationAttributes()`
   walks them, DEDUPES BY ATTRIBUTE, and is what `/admin/applications/new` draws
   its fields from and `GET /admin-api/applications/new` publishes as
   `declarations`. Several families naming one attribute is the point rather
   than a shortcut: OAuth 2.0, OpenID Connect and OpenID4VCI all name
   `oauthClientId` because a relying party IS an OAuth client and a wallet
   authenticates as one, and both SAML profiles name `samlEntityId` — the
   specifications share the identifier, so two attributes would be two spellings
   of one fact that disagree the first time either is edited.

   **THEY ARE ALL `multi` BAR ONE, AND THE EXCEPTION IS THE ONE SOMETHING
   ENFORCES.** `oauthClientId`, `samlEntityId`, `wsfedRealm`,
   `wstrustAppliesTo`, `krb5ServicePrincipalName` and `oid4vpClientId` were
   `single` until 2026-08-25 and now accumulate, because one application
   legitimately answers to two client_ids or two SPNs. `oauthTlsClientAuthSubjectDn`
   stays `single`: `client_auth.js` compares it to a certificate's subject by
   exact string equality for RFC 8705 section 2.1, so a list would stringify to
   `dn1,dn2` and match nothing — widening it means first deciding what "any of
   these" should mean to a security check, which is a different change from
   giving a form a field. **Flipping a row's `kind` also means flipping its
   `EDITABLE` mode**, `set` to `multi`, or the console offers a `set` the action
   refuses.

   **EACH IDENTIFIER ATTRIBUTE ALSO CARRIES `identifierName` — THE PROTOCOL'S
   OWN WORD FOR IT — AND `identifiersOf()` IS WHAT READS THE PAIR.** Added
   2026-08-27 for the delegation pictures, which draw an application by the
   name somebody GAVE it and said nowhere on the diagram what a request would
   have to present to reach it. The attribute is unfriendly by design (an
   `ldapsearch` and `/admin-api` share its spelling), so `oauthClientId` carries
   `client_id`, `samlEntityId` carries `entityID`, `wsfedRealm` carries
   `wtrealm`, `wstrustAppliesTo` carries `AppliesTo`,
   `krb5ServicePrincipalName` carries `SPN`, and so on for all eleven.
   `identifiersOf()` takes a `view()`, a record or a bare fields object and
   returns one row per identifier attribute the entry actually carries a value
   in — the attribute, that word, the FAMILIES it serves as labels, and the
   values — in table order, skipping the empty ones.

   **IT IS HERE RATHER THAN IN THE RENDERER FOR THE REASON EVERYTHING ELSE IN
   THIS MODULE IS.** Which attribute is a family's identifier is the `PROTOCOLS`
   table's statement and what the specification spells it is the `SCHEMA` row's;
   a page building either list for itself would be a second opinion about the
   store, and the first time a family was added it would be a second opinion
   that disagreed. The families come back as LABELS and as a list because
   several families share one attribute — naming only the first of OAuth 2.0,
   OpenID Connect and OpenID4VCI would be picking one of three true answers.
   `admin-ui/CLAUDE.md` argues what the picture then does with the rows,
   including why it groups them by VALUE rather than by attribute.

   **`oauthAudience` IS DECLARED AND IT IS READ, WHICH MAKES IT THE ONE OF ITS
   KIND.** Added 2026-08-26. It is the audience an access token addressed to this
   application carries — a URI, the resource rather than the client that calls
   it — and it is the OAuth spelling of a fact `wstrustAppliesTo` and
   `samlEntityId` already record for their own families. Nothing presents an
   audience as its own name, so nothing here writes it and it cannot be derived.
   What makes it different from the four declaration-only attributes below is
   that `oauth-oidc/oauth2.js` LOOKS IT UP: `forAudience()` turns the `audience`
   on an RFC 8693 exchange into the application that registered it, so a
   delegation reaching `https://esb1.example.com` is filed against `esb1` and
   `/admin/delegation/map` draws one chain instead of two halves that share
   nothing. **It is a lookup and not a permission** — an audience nobody
   registered is exchanged for exactly as before and recorded verbatim, which is
   the same sentence `appAllowedProtocol` gets and for the same reason. Do not
   give it a fallback to the identifier: `get()` already answers that question,
   and a lookup trying both would make `audience=esb1` and
   `audience=https://esb1.example.com` indistinguishable in the one place the
   difference is the point.

   **`forPermissionBase()` IS THE FIFTH LOOKUP, added 2026-09-02, and it is
   `forPermission()` asked one level up.** That one takes a whole permission
   identifier and answers which application defines it; this takes the BASE
   ALONE. It exists for a reader holding an ISSUED TOKEN rather than a request:
   `audienceScopes()` writes the base URI onto the `aud` and the bare names onto
   the `scope`, so what a picture has is a base and nothing else — and none of
   the four lookups above it can turn that back into an entry.
   `forAudience()` reads `oauthAudience`, a different attribute a resource is
   under no obligation to have set; `forClientId()` reads a bare name; and
   `forPermission()` needs a name on the end that the reader is trying to work
   out. `common/user_graph.js`'s `permissionsAddressedTo()` is its one caller.

   **IT NORMALISES BOTH SIDES, WHICH IS ITS ONE DIFFERENCE FROM `forAudience()`
   AND IS NOT A SOFTENING OF THAT RULE.** An `ldapmodify` is not normalised, so
   an entry can hold `https://example.com` while every identifier this service
   composed from it — and therefore every `aud` a token addressed to it carries
   — ends in the separator. `permissionBaseOf()` is what added that separator,
   so comparing through it is comparing a value this module composed with
   itself. Get that wrong in the ENTRY direction and the entry is unreachable
   from its own tokens, which reads as the feature quietly not working rather
   than as an error; `tests/user_graph_permissions.js` caught exactly that
   mutant on its second round. It is still not case-folded, and **an entry with
   no base is never matched** — `permissionBaseOf('')` is empty, so a lookup
   without that guard answers with the first entry that has none, which is the
   one entry it must never be.

   **`forClientId()` IS THE SECOND LOOKUP THAT IS NOT BY IDENTIFIER, added
   2026-08-26 beside it, and the paragraph above is exactly why it is a separate
   function.** It matches `oauthClientId`, and `oauth-oidc/oauth2.js`'s
   `audienceScopes()` is its one caller: a scope value that names another
   application becomes that access token's audience, and a scope is a BARE NAME
   where an `aud` from RFC 8707 is a URI. Folding the two into one lookup would
   be the fallback the paragraph above refuses, one function along — the caller
   knows which question it is asking, so it asks it. Same three properties as
   its neighbour: not a permission, not case-folded, a walk rather than an index.

   **FOUR ATTRIBUTES HERE ARE DECLARATION AND NOTHING EVER WRITES THEM** —
   `federationPartnerId`, `ldapBindDn`, `scimClientId`, `spiffeWorkloadId` —
   because those surfaces authenticate the CALLER rather than an application
   (LDAP, SCIM), file the identity in a container of their own (SPIFFE), or keep
   the arrangement under `ou=federations` (Federation). They are the same claim
   `appAllowedProtocol` is, narrowed to a name: a fact an operator has, in the
   place the rest of what that application is already lives. Do not "fix" one by
   wiring a protocol module to write it — check first that the module has an
   application identifier at all, which is what the empty `kinds` on those
   `PROTOCOLS` rows records.

   **`wsfedReplyUrl` SPLIT OFF `samlAssertionConsumerService` ON 2026-08-25**,
   and the reason is worth keeping: that attribute is READ. `/admin/saml2` and
   `/admin/saml11` take the last value on it as the assertion consumer service
   and as the Single Logout fallback, and `wsfed.js` had been writing its
   `wreply` into it — so a WS-Federation application appeared to have named a
   SAML ACS it had never heard of, and a LogoutResponse could have been handed to
   a WS-Federation endpoint. One attribute per fact.

   **`createApplication()` TAKES `fields`, AND IT WAS IGNORING THEM.** The
   member had been in the argument since `saml2Action()` and `saml11Action()`
   were written — both pass `fields: { samlEntityId: identifier }` — and nothing
   read it, so *Register* on either SAML page produced an entry with no entityID
   until a real request arrived and `seen()` wrote one. Nothing failed, which is
   why it survived. `normaliseFields()` is now the one gate: an attribute has to
   be in the schema AND `editable`, so a create cannot assert a counter or a
   sighting, and a `single` attribute given several values is REFUSED rather than
   truncated to the first.

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

3s. **`app_permissions.js` is a library, and the whole of it is the argument
   for why a CONFIGURED register is not the observed one with a flag on it.**
   `delegation.js` above holds ACTS — one row per exchange, at a moment, with a
   credential in it. This holds GRANTS: which client applications have been
   given which permissions on which resource applications, typed in before
   anybody asked for anything. It requires `helpers.js` and `applications.js`
   and nothing else; neither requires it back, so there is no cycle and none of
   rule 3e's slots is needed.

   **THE TWO MUST NEVER BE DRAWN AS ONE REGISTER**, and this repository already
   keeps exactly that distinction one file over: `appProtocol` is what happened
   and `appAllowedProtocol` is what somebody declared, and `applications.js`'s
   PROTOCOLS header spends a page on why collapsing them would be wrong.
   `/admin/delegation` shows both and says which is which on every heading,
   because the interesting reading is the DIFFERENCE — a grant nobody has used,
   and a delegation nobody granted.

   **THE MODEL IS ENTRA ID'S, DELIBERATELY AND BY NAME.** A resource
   application exposes an API (`oauthPermissionBaseUri`, their Application ID
   URI; `oauthPermission`, their `oauth2PermissionScopes`) and a client is
   granted some of them (`oauthDelegatedPermission`, their
   `requiredResourceAccess`). A permission is identified by the base URI
   followed by its name, and a client asks for it by putting that whole string
   in an OAuth `scope`. **One-to-many and many-to-one both fall out of that one
   identifier with no container of their own** — three permissions granted to
   one client is three values on one entry, and one permission granted to three
   clients is one value on each of three — which is why there is no
   `ou=delegations` and why there should not be.

   **`ou=applications` IS THE STORE AND THERE IS NO SECOND ONE HERE.** Every
   function is a read of the registry or a write through
   `applications.updateApplication()`. That is `applications.js`'s own rule
   applied again: a Map in this file would look correct alone and would be the
   one that silently disagreed. It also means an `ldapmodify` IS a
   configuration change here, exactly as it is for a redirect URI.

   **THE DIVISION OF LABOUR WITH `applications.js` IS EXACT**, and it is the
   split `delegation.js`/`delegation_map.js` already have. THAT module owns the
   SCHEMA — how a permission is spelled (`name` or `name|description`), how base
   and name are joined (`permissionIdOf()`), which spellings are legal, and the
   two lookups a reader of ONE entry needs (`forPermission()`,
   `holdsPermission()`). THIS module owns what the two halves MEAN read against
   each other: the register in both directions, the five actions, and the graph.

   **THE ORDERING RULE IS ENFORCED IN `applications.js` AND NOT HERE**, and
   that is worth stating because this is where somebody will look for it. A
   permission must be DEFINED before it can be GRANTED, and the check lives in
   `updateApplication()` because that is the ONE door the console form, the
   management API's generic `update` operation and the five actions below all
   go through. A copy here would be a second opinion, and the generic attribute
   editor would be the way around it.

   **`graph()` RETURNS `delegation.graph()`'s SHAPE**, so `delegation_map.js`
   draws it with no argument about which graph it is looking at — which is the
   property that file's header says it was split out to keep. Three things
   about it are claims rather than mechanics, and `tests/app_permissions.js`
   asserts all three: **every box is an application and there is no person on
   it** (a permission says *this client may reach that API as whoever is signed
   in*, and there is no whoever yet); **this service is not on it either**, so
   no hexagon, because every line on the acts picture exists because something
   was issued and none of these has been asked for; and **`acts` stays zero on
   every box**, which is load-bearing rather than tidy — `edgeLook()` paints an
   edge RED when `acts && !issued`, so a box claiming an act would draw every
   configured grant in the refusal colour.

   **ONE EDGE PER PERMISSION, NOT PER PAIR**, for `delegation.graph()`'s reason
   about two mechanisms joining the same boxes. And a line is DASHED until the
   client has actually asked for that permission — read off its own
   `oauthScope` — which is the single most useful thing a configured picture can
   say and the one thing an acts diagram can never say, because a grant nobody
   needed draws no act at all.

3p. **`user_graph.js` is a library over TWO registers, and the whole of it is
   the argument for why the union is here rather than in the console.** It
   requires `helpers.js`, `admin_stats.js` and `delegation.js`; nothing requires
   it but `../admin-ui/admin.js`, which renders it at `/admin/delegation/user`.
   It registers no route, so rule 3e's test is not even reached — a plain
   require in the ordinary direction closes no cycle and moves nothing.

   **THE QUESTION IT ANSWERS CANNOT BE ASKED OF EITHER REGISTER ALONE.**
   `/admin/delegation/application` next door narrows the ACTS and hands them to
   `delegation.graph()`, because both halves of *what has been delegated through
   this application* live in one store. *What has this service done in alice's
   name* does not: an act is by definition a request carrying two credentials,
   and an authorization code grant is not one, nor is a Kerberos AS-REQ, nor a
   SAML assertion. Drawn from the delegation register alone, somebody who signed
   in nine times and holds twenty tokens is an EMPTY PICTURE. So this file
   unions that register with `admin_stats.js`'s — the tokens, the artifacts and
   the authentication events — and it is a file rather than a `filter()` in
   `admin.js` for the reason every other view function moved down here: the join
   is a statement about what the two stores MEAN, and a renderer holding a
   second opinion about any of it is drift nothing can see.

   **IT EXTENDS `delegation.graph()`'s SHAPE AND DOES NOT INVENT A SECOND ONE.**
   `graphFor()` starts by calling that function for the acts naming this person
   — so the delegation half is drawn by the code that owns it, byte for byte as
   `/admin/delegation/map` draws it — and folds the issuance on top as nodes and
   edges carrying the same fields plus three (`credentials`, `flows`,
   `isSubject` on a node; `credentials` on an edge). `../admin-ui/delegation_map.js`
   therefore draws this picture with no idea it is different. A second shape
   would have meant a second renderer, and two renderers agreeing about what a
   box means is a thing that stays true for about a month.

   **TWO NEW `relation` VALUES, AND NEITHER TAKES A MODE COLOUR.** `signed-in`
   runs from the person INTO the hexagon, one line per protocol family, labelled
   with the methods — it is the authentication half, and without it the picture
   shows tokens beside somebody who as far as the drawing goes has never been
   here. `issued-for` is a credential going to whoever holds it, LABELLED WITH
   THE GRANT. Amber and green are this console's judgement about impersonation
   versus delegation, which are properties of a DELEGATION mechanism; an
   ordinary grant claims neither, so colouring one green would tell a reader who
   learnt the pairing from the table something false.

   **AND SINCE 2026-08-26 A THIRD LINE, WHICH IS NOT A THIRD RELATION.** An
   access token issued to `webapp1` and addressed to `apigw1` is this service
   saying that webapp1 may reach apigw1 in that person's name — which is exactly
   what a token exchange's `reaches` line says, with no exchange in it. It was
   drawn only where an exchange had happened until then, so the FIRST HOP of
   every chain was missing: the picture showed `apigw1 → esb1` and `esb1 → sp1`
   and nothing at all about how apigw1 came to hold a token. So the audience of
   every credential drawn here gets a `reaches` line from whoever HOLDS it,
   keyed on the grant the way the `issued-for` line is, carrying the SAME
   relation value the delegation half emits rather than a fifth one — the fact
   being stated is identical, and the mechanism on the label is what tells them
   apart. A second relation would have been a second colour and a second row in
   the legend for one idea.

   Three consequences, and each is a place this could have gone wrong quietly.
   The audience is resolved through the applications registry
   (`audienceParties()`, exported for `credential_graph.js`, which had a copy of
   it), so a token addressed to `https://apigw1.example.com` lands on the BOX
   for apigw1 — the failure the exchange's own lookup already exists to prevent.
   **It is TWO lookups since 2026-08-26** — `forAudience()` then
   `forClientId()` — because an audience here is as often a bare NAME as a URI:
   that is what `oauth2.js`'s `audienceScopes()` writes when a client names the
   API it wants in its scope list instead of through RFC 8707, and `apigw1` and
   `https://apigw1.example.com` have to land on ONE box or this console has
   invented a party.
   An `aud` naming SEVERAL resources draws several lines, because RFC 7519
   section 4.1.3 allows a list and RFC 8707 section 2.3 is how one gets here,
   and `recordJwt()` joins them with a space: a single lookup of the joined
   string finds nothing and draws one box named after two URLs. And an audience
   that is **this service's own** is not a party and is dropped — a refresh
   token is addressed to the token endpoint and an access token nobody named a
   resource for carries `<base>/resource`, so without that rule every plain
   sign-in gained a box called `http://localhost:8081/resource`. That last check
   is why `recordJwt()` keeps `iss`: `oauth2.issuer` is empty by default so one
   process answers correctly under every name it is reached by, which makes the
   base a property of the REQUEST — by the time a page reads the record there is
   no request to ask, so the token has to have remembered it.

   **`FLOWS` IS KEYED ON THE STRING `oauth2.js` ALREADY RECORDS, VERBATIM.**
   `issuanceContext()` over there puts a `grant` on every signed JWT and
   `recordJwt()` keeps it; those strings are the ids here rather than a tidier
   vocabulary, because a translation that misses a value fails SILENTLY. An
   unknown one comes back NAMED AFTER ITSELF with a warning — the choice
   `delegation.js`'s `recordUnguarded()` makes about a type it does not know —
   so a grant added to `oauth2.js` and not to this table shows up as a bug
   report rather than as an empty cell. **Adding a grant there is a row here**,
   and nothing else.

   **A CREDENTIAL BOTH REGISTERS KNOW IS DRAWN ONCE, DEDUPED ON THE IDENTIFIER
   AND NOTHING ELSE.** An RFC 8693 exchange writes a delegation act AND a token
   record for one access token, so the issuance half skips any JWT whose `jti`
   the delegation half already carries, and the count of what was skipped is
   REPORTED rather than left to be noticed. Matching on anything softer — a
   subject and a kind within a time window — would eventually collapse two real
   credentials into one, which is worse than listing one twice. **The Kerberos
   overlap therefore survives on purpose**: an S4U service ticket is in both
   registers and has no identifier in either, so it is drawn on both lines and
   the page says which register each came from.

   **AND SINCE 2026-09-02 THAT LINE SAYS WHAT THE TOKEN MAY DO AT THE FAR END,
   which is the one thing the ACTS picture could never say and the CONFIGURED
   one always could.** A `may-reach` line on `/admin/delegation/allowed` carries
   the permission it is a grant of, because a configured grant IS a permission;
   a `reaches` line drawn from an issued token carried the mechanism and a
   credential count and nothing else — so the picture showing what a client DID
   was the one that could not say what it did it WITH.
   `permissionsAddressedTo()` is the rule, and it is three sentences.

   **IT IS ASKED OF THE TOKEN AND NOT OF THE REQUEST, which is what makes the
   two spellings a client may use come out as one rule.** `oauth2.js`'s
   `audienceScopes()` turns `scope=https://api.example.com/read` into
   `aud: https://api.example.com/` and `scope: read`, and turns `scope=apigw1`
   into `aud: apigw1` with that value taken OFF the scope claim. Whichever was
   sent, what arrives here is an audience and a scope claim — so the rule is
   *the scope values that name a permission THIS resource defines*, resolved
   through `applications.forPermissionBase()` beside the two lookups
   `audienceParties()` already makes. The first spelling answers with names; the
   second answers with none, and **an EMPTY ARRAY is an answer** — the picture
   draws it as `default permissions`, which is the commonest state there is.

   **THE INTERSECTION IS WHAT MAKES IT SAFE.** A scope claim carries the
   protocol's own words and anything else a client cared to send, so a label
   built from the scope claim alone would name a resource with `openid`. Only
   names the resolved resource has DEFINED are reported, which also means a
   permission removed from the register since the token was minted drops off the
   line — the same reading `audienceParties()` makes when it resolves an `aud`
   against the CURRENT registry.

   **AND NOTHING HERE ASKS WHETHER THE GRANT WAS HELD.** `holdsPermission()` is
   that question and it belongs to the configured register;
   `oauth2.delegatedPermissionsEnforced` is off by default, so a token carrying
   a permission its client was never granted is an ordinary outcome here and the
   line reports what was ISSUED. Colouring it as a refusal would be this model
   deciding a policy the token endpoint declined to decide.

   **THE ARRAY'S PRESENCE IS THE DISCRIMINATOR, and that is load-bearing rather
   than incidental.** `delegation.graph()` emits the identical `reaches` relation
   for a delegation ACT, which has no scope claim anywhere behind it and carries
   no such member — so `delegation_map.js` tests for the member rather than for
   the relation, and an act line says nothing instead of saying `default
   permissions` about a Kerberos ticket. An edge seeded without it would be
   drawn as an act.

   **IT ALSO MOVED THE AUDIENCE BLOCK OUT OF `if (holder)`.** `holder` is null
   when the credential's `client_id` IS the box the page is about, which is what
   the CLIENT CREDENTIALS grant looks like here — so that guard drew the grant
   line and threw away the only interesting thing about a machine-to-machine
   token: which API it was for. The line now runs from the holder, or from the
   person where there is no separate holder.

   **`credential_graph.js` DRAWS THE SAME LINE AND TAKES THE SAME ANSWER**,
   through an export, for the reason `holderOf()`, `detailOf()` and
   `audienceParties()` are already exported to it: two answers to *which
   permissions does this token carry* would be two labels on one relationship on
   two pages of one console.

   **`userList()` UNIONS THE TWO REGISTERS TOO, and that is the half worth
   keeping.** An identity named only by a delegation — an S4U2Self subject, an
   `OnBehalfOf` — has never authenticated and may have been issued nothing, and
   *there is no such person* and *somebody was impersonated who has never signed
   in* are opposite answers to one question. The chooser offers both and each
   row says which side it came from.

---

3q. **`credential_graph.js` is the same union asked a NARROWER question, and it
   is a file for the same reason `user_graph.js` is.** It requires `helpers.js`,
   `admin_stats.js`, `delegation.js`, `user_graph.js` and `applications.js`;
   nothing requires it but `../admin-ui/admin.js`, which renders it at
   `/admin/tokens/credential` — the first drill-down the tokens page has ever
   had, reached from every identifier in its last column. It registers no route,
   so rule 3e's test is not reached.

   **A LINE, NOT A FAN, WHICH IS WHY IT IS NOT A FILTER ON THE PERSON'S
   PICTURE.** `user_graph.js` answers *what has this service done in alice's
   name*; this answers *where did THIS credential come from*, and the answer is
   an ancestry. A token exchange consumes one credential and produces another,
   so the identifiers form a chain, and following it is the only way to get from
   an access token that reaches `sp1` back to the browser sign-in three tiers
   away that everything after it rests on. Filtering the person's picture cannot
   do it: that picture is every credential ever issued in their name, with
   nothing to say which four are this one's ancestors.

   **THE JOIN IS THE IDENTIFIER AND NOTHING ELSE.** An act records what it
   CONSUMED and what it PRODUCED, each with the identifier its protocol gives it
   — a `jti`, an `AssertionID` — and that is the one thing both registers hold
   about the same object. `stats.issuedById()` (added with this file, for the
   same reason `issuedList()` lives over there rather than in a caller) turns
   one into a row. Anything cleverer — a subject and a time window, a kind and a
   client — would eventually join two credentials that merely look alike, and a
   lineage that is WRONG is worse than one that is short, because the whole page
   is an assertion about causation.

   **A WALL IS NOT AN ORIGIN, and they are reported separately.** Two mechanisms
   here consume a credential with nothing to quote: WS-Trust consumes the
   requester's WS-Security credential, which this service never issued, and a
   Kerberos ticket has no identifier in the protocol at all. So a trail can stop
   because it has reached the beginning, or because the thing handed in cannot
   be named — and those are opposite answers. `walls` carries the second.

   **THE ORIGIN IS DRAWN AS AN ISSUANCE, IN `user_graph.js`'s VOCABULARY.**
   `issued-for` from the person to the application, labelled with the GRANT, plus
   the dashed `issued` line from this service — not `acts-for`, which would
   colour an authorization code grant amber for impersonation and claim a
   mechanism that was not involved. The two pages therefore agree about what an
   issuance looks like, which is what lets somebody read both. It is also why
   `holderOf()` and `detailOf()` are exported from that file rather than written
   again here: two answers to *whose token is this* would be two pictures of one
   issuance on two pages of one console.

   **THE AUDIENCE IS RESOLVED THROUGH THE REGISTRY, exactly as the token
   exchange resolves one** (`applications.forAudience()`, and see the
   `oauthAudience` note in 3g). A box for `https://esb1.example.com` beside a box
   for `esb1` would be two parties for one, which is the failure that lookup
   exists to prevent. And the audience is drawn ONLY for the credential at the
   head of the line: everything below it was produced by an act, and the act
   already says where it went. **The lookup itself moved to `user_graph.js` on
   2026-08-26** — `audienceParties()`, required from here the way `holderOf()`
   and `detailOf()` already are — because the person's picture draws the same
   resource at the end of the same line, and two answers to *what is this token
   for* would be two pictures of one issuance on two pages of one console. This
   file's own copy had two bugs the shared one does not: an `aud` naming several
   resources came back as one box named after a joined string, and an audience
   that is this service's own was drawn as a party. `applications.js` is no
   longer required here at all.

   **IT WALKS BACKWARDS ONLY.** *What was later made from this* is a tree rather
   than a line — one subject token can be exchanged by any number of clients —
   and drawing both would make the common case, a credential with no ancestry and
   no descendants, into a page explaining itself in two directions. The forward
   direction is what `/admin/delegation` and its map are for.

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

## AN APPLICATION ENTRY CAN NOW CARRY ITS OWN SAML SETTINGS, AND THAT IS A THIRD KIND OF ATTRIBUTE

Added 2026-08-27. Ten attributes — five per SAML profile — each naming one
`config.js` setting in an `overrides` member on its SCHEMA row and, where the
entry carries a value, winning over that setting for that application alone.

**IT IS A THIRD KIND, AND THE SECTION BELOW'S TWO-WAY SPLIT IS WHY THAT NEEDS
SAYING.** Every attribute here used to be either RECORDED (what happened) or
DECLARED (what somebody said, which nothing reads). These are declared AND read:
`saml/saml2_sso.js` and `saml/saml11_sso.js` resolve every one of their five
settings through `settingFor()` on every assertion. They join
`appFederationRelationship` and `appAuthnMechanism` on the short list of
declarations that actually do something — and unlike those two, what they change
is not WHERE somebody signs in but what the document they get looks like.

**THE MAPPING IS BUILT FROM THE SCHEMA, ONCE, AND THERE IS NO SECOND TABLE.**
`OVERRIDE_ATTRIBUTES` is derived from the rows' own `overrides` members at
require time; `settingFor()` reads it, `overridableSettings()` publishes it, and
`/admin/saml-assertions` and `/admin/applications/new` both draw from that.
Adding an eleventh override is a row in `SCHEMA.attributes` and nothing else — a
map written by hand here would be the first thing to disagree with the schema.

**`config` IS PASSED IN RATHER THAN REQUIRED**, which keeps this module's near-
empty require list true (rule 3g) and keeps the resolver testable with a stub.

**ALL TEN ARE `single`, AGAINST THE GRAIN OF EVERY IDENTIFIER HERE.** Those are
`multi` because an application answering to two client_ids is one application. A
SETTING is the opposite case: there is one answer to "sign the assertion?", and
a list would be a question with no rule for which value won.

**IT IS TWENTY ATTRIBUTES ACROSS FOUR PROTOCOLS SINCE THE SECOND PASS**, and
the mechanism did not change to take them: five OAuth 2.0 / OIDC per-client
settings, the SAML ten, WS-Federation's assertion lifetime, and the group
claim's four. Each is a row in `SCHEMA.attributes` carrying `overrides`, and
that is the whole of what adding one costs — `settingFor()`, the New Application
form, both defaults pages and `GET /admin-api/saml-assertions` all read the same
derived table.

**THE GROUP CLAIM'S FOUR ARE THE ONE SET THAT IS NOT A PROTOCOL'S**, and they
are the reason `appOf(context)` in `group_claims.js` looks at `client_id` OR
`audience`: those four reach an access token, an ID Token, a SAML 2.0 assertion
and a SAML 1.1 one from a single resolver, so one application entry has to be
findable from whichever of the four is being built. An application declared for
two protocols therefore gets the same claim name in both, which is what a claim
mapping should do.

**WHAT IS DELIBERATELY NOT OVERRIDABLE is worth reading before adding a
twenty-first.** Not `oauth2.issuer` or `oauth2.rfc9700` — those describe the
authorization SERVER, and a per-client issuer produces tokens that fail
discovery. Not any clock skew, in any protocol: `oauth2.clockSkewS`,
`oauth2.clientAssertionSkewS` and `saml.clockSkewS` are facts about the clocks in
the estate this service issues into, decided once, and a per-application answer
would be a question two applications could not meaningfully answer differently.
And not a socket, a port, a key or a limit anywhere.

**AN APPLICATION DECLARED FOR SAML GETS AN ENTITYID.** `createApplication()`
fills `samlEntityId` from the identifier when `saml2` or `saml11` is ticked and
no entityID was given — because that is what the same application would have got
by ARRIVING on its own, where the registry files a service provider under its
entityID. Without it the declaration was a note and nothing more: `samlEntityId`
is what both SAML modules file an application under and what their
per-service-provider metadata is published for. It is a default and not a rule —
an explicit value wins, and nothing is refused, because this service accepts any
entityID on sight everywhere else.

---

## An application entry now says WHERE ITS PEOPLE SIGN IN, and that is the first thing on one anybody reads

Every attribute on an application entry is one of two things, and the schema's
own comments have said so for a while: it RECORDS what happened (the counters,
the sightings, `appProtocol`, `appRedirectUriObserved`) or it DECLARES something
— and of the declarations, `appAllowedProtocol` and the four per-family
identifiers say in capitals that nothing in this service reads them.

**`appFederationRelationship` is read.** Each value holds the `fedId` of a
service-provider-side relationship in THIS realm, and `authn.js` consults it on
the way to the sign-in screen: with one named and `appFederationAutoRedirect`
left at its default, the browser is sent straight to that partner and the
screen is never drawn. With the auto-redirect off, the screen appears and those
partners are the ONLY ones offered on it.

**IT HOLDS A LIST SINCE 2026-08-26, AND IT USED TO HOLD ONE VALUE.** An
application with two identity providers is the ordinary case in a real
deployment — a workforce partner and a customer one, or one partner reached over
two protocols during a migration — and while this attribute was single-valued
the only way to say it was to configure nothing and let the person choose from
the WHOLE register. Naming several is the middle answer: the choice is still
made by a person, and the list they choose from is this application's own. The
values need not share a protocol, because what the list names is where somebody
can be authenticated and not how.

**With more than one usable, `authn.js` draws `/authn/select-idp`** — one button
per partner, no password field, and a banner per value that names something this
service cannot use. `appFederationAutoRedirect` still means "without the sign-in
screen" and never "without a page"; that page IS the screen's job done without
the screen, and FALSE still keeps the screen with the buttons under the password
box. `authn/CLAUDE.md` argues the chooser and why it is not the screen with its
form hidden.

**Its EDITABLE mode changed with its kind, from `set` to `multi`.** A caller
that used to write it with `POST /admin-api/applications/set` now uses
`/applications/add` and `/applications/remove` — which is the same rule every
other identifier attribute here follows, and for the same reason: a `set` would
replace the list with one value and read afterwards as the others having been
forgotten.

**What it answers is a question this registry could not answer before.** A
relationship under `ou=federations` says how to talk to a foreign identity
provider and says nothing about WHO should be sent there; an application entry
said what the application is and nothing about how its people sign in. So the
only home realm discovery available was a person choosing a button at the foot
of the screen, once per sign-in — which is not what a deployment with one
federated identity provider does, and it meant every federated flow in this
service began with a step no real user performs.

**FOUR CHECKS, AND ALL FOUR ARE MADE WHEN IT IS READ.** The relationship must
exist in this realm, be service-provider-side, be enabled, and be fully
configured. None of them is made at the write, and that is deliberate rather
than lax: the attribute is a string on a directory entry that `ldapmodify`
reaches, and the relationship it names can be disabled or deleted afterwards by
somebody who never looked at this application — so a check made at the write
would be a check about the past.

**A failure of any of them is SHOWN, on the sign-in screen, in the error banner
the password step already had.** The alternative is the one that had to be
avoided: falling silently back to the password box means a federated
application quietly authenticating people locally, which looks exactly like it
working.

**It grants and refuses nothing**, which keeps it consistent with everything
else here. Nothing stops a person reaching the screen by another route and
typing a name; clearing the attribute takes the shortcut away rather than
locking anybody out. What it changes is the DEFAULT ROUTE, and `federation/`
still owns every decision about what is then accepted.

**`appFederationAutoRedirect` defaults to TRUE once a relationship is named**,
which is the opposite of RFC 7591 section 2's rule that an omitted boolean is
FALSE. Both rules meet on one entry, so it is said out loud here and in the
schema row: naming a partner and then having to press a button is the state
nobody wants, and with no relationship named the attribute does nothing at all
rather than being an error.

### `appAuthnMechanism` — the THIRD of that group, and the generalisation of the other two

Added 2026-08-26. The pair above can say "send my people to a federated identity
provider" and can say nothing else, because until then there was nothing else to
say: every way of authenticating somebody here was either this service's own
screen or somebody else's service. **The SPNEGO sign-in is neither** — it is a
credential the browser already holds — so an application had no way of asking
for the commonest integrated-authentication deployment there is.

It is a single value from the SAME closed vocabulary `fedAuthnMechanism` uses:
`password`, `password-mfa`, `webauthn`, `spnego`, `federation`. **One table for
both**, because the two attributes answer the same question from two sides —
this one says where THIS APPLICATION's people sign in, that one says what to do
when THAT PARTNER asks — and two tables would have drifted the first time either
grew a value. **The list is deliberately NOT imported into `applications.js`**:
`federation.js` requires that file, so a require back would close a cycle. It is
checked where it is READ, in `authn.js`'s `declaredMechanismFor()`, which is
where `appFederationRelationship`'s four checks are made too and for the same
reason.

Three properties are load-bearing and each is the same rule the pair above
follows:

* **An empty value is not `password`** — it is "this entry says nothing". Every
  entry in the field holds an empty one, so reading it as an explicit "use the
  screen" would have switched off every `appFederationRelationship` in existence
  in one commit.
* **`federation` falls through to the list below it**, because that is what
  naming a relationship already implied, said out loud — so it changes nothing.
  Declaring it while naming nothing usable is REPORTED on the screen rather than
  falling quietly back to a password box.
* **A value this service cannot honour is REPORTED, not dropped** — a mechanism
  it does not have, or `spnego` while `krb5.spnegoAuthentication` is off. The
  second is why the setting is checked at the read rather than the write: it is
  settable at runtime, and without the check somebody meets a 403 halfway
  through a sign-in.

**It grants and refuses nothing either.** The Kerberos button is on the sign-in
screen for every application whether or not one declares this, so what the
attribute changes is the DEFAULT ROUTE and nothing about what is then
accepted — exactly what `appFederationRelationship` changes.

## WHERE THE ONE CRYPTO MODULE IS DESCRIBED TO A READER

`crypto.js` is the one place this service signs, verifies, encrypts and
decrypts (rule 3r above). Since 2026-08-30 there is a console page that REPORTS
it — `/admin/crypto-metadata`, built by `admin-ui/crypto_metadata.js` — and the
one thing worth knowing here is the direction: **that page reads this module's
tables and this module knows nothing about it.** `JWS_ALGS`, `JWE_ALGS`,
`JWE_ENCS`, `BLOCK_CIPHERS`, `KEY_TRANSPORTS` and the re-exported `xmldsig`
tables are already exported, so nothing here changed for it, and nothing here
should: `crypto.js` is a LEAF and a require back would end that.

The rule it puts on this file is small and worth stating, because it is the one
that will be broken by accident: **an algorithm this service performs must be in
a TABLE here rather than in a literal at a call site.** A `switch` in a
protocol module is invisible to that page, so the page would go on looking
complete while being wrong — which is the failure `sts_metadata.js` exists to
prevent for endpoints and this arrangement extends to algorithms.

## WHERE A SIGN-OUT GOES, AND THE CLIENT SECRET, ON THE NEW-APPLICATION FORM (2026-08-30)

`PROTOCOLS` gained two optional members beside `identifierAttribute` and
`redirectAttribute`, and `declarationAttributes()` walks both:

* **`logoutAttribute`** — `oauthPostLogoutRedirectUri` (OAuth 2.0, OpenID
  Connect), `samlSingleLogoutService` (SAML 2.0) and `wsfedSignOutUri`
  (WS-Federation, the one attribute this schema did not have). All three are
  `multi`, so the form draws a textarea and several addresses are one per line
  — which is what a service provider with an endpoint per binding actually has.
* **`secretAttribute`** — `oauthClientSecret`, on the two OAuth families. The
  attribute already existed; what it did not have was a door on the create
  form, so an application made by hand could not be given one.

**THE ABSENCES ARE THE INTERESTING HALF AND EACH IS A FACT ABOUT THE PROTOCOL.**
SAML 1.1 has no Single Logout at all — that arrived with 2.0 — so a field for it
would be a control whose value nothing could ever read. WS-Trust issues a token
and holds no session to end; Kerberos hands out a ticket this service cannot
recall; federation deliberately does not consume a partner's sign-out. The rule
is the one the identifiers already follow: a field is offered where an attribute
exists to hold it, and nowhere else.

**Adding them to the WALK rather than to the form is what made this one edit.**
The form, `GET /admin-api/applications/new` and `createApplication()`'s accepted
set all read `declarationAttributes()`, so a field that exists on one exists on
all three, and `DECLARATION_ATTRIBUTE_NAMES` picked the two new roles up for
free.

**`wsfedSignOutUri` IS DECLARED AND NOT YET READ, and the schema row says so.**
`cleanupTargetsFor()` builds its ping list from `session.wsfedRealms` — the
`wreply` each sign-in response actually went to — so what this service pings is
what it OBSERVED, and this attribute is what an operator DECLARED. They are two
different facts. Wiring it in as the fallback for a realm signed into with no
wreply is the obvious next step and is deliberately not taken: storing it is one
change, and changing where a cleanup goes is a change to what the protocol does.

## `consent.js`: what a person AGREED to, which is neither an act nor an intent

Rule 3t. It is the THIRD register in this directory that looks like the other
two and answers a different question, and saying which is which is most of what
this file has to do. `delegation.js` holds ACTS — one row per exchange, evidence
that something happened. `app_permissions.js` holds INTENT — what an operator
allowed between two applications, typed before anybody asked for anything.
**`consent.js` holds neither: it holds what somebody SAID YES TO**, and every row
in it has a person in it, which is what stops it being a fourth heading on
`/admin/delegation`.

**IT IS A LIBRARY (rule 3) AND IT HOLDS NO STORE.** It registers no route, so
its place in the require order is not a place. The store is the DIRECTORY in
both halves — `oauthConsent` on a person under `ou=users`, `oauthGlobalConsent`
on an application under `ou=applications` — for the reason `applications.js`
states about the registry: a Map here would be a second store that looked right
on its own and silently disagreed with an `ldapsearch`. It also means an
`ldapmodify` IS a configuration change here, exactly as it is for a redirect
URI.

It requires `helpers.js`, `config.js`, `applications.js` and `admin_stats.js`
(for `identityKeyOf()`, so that `alice`, `alice@EXAMPLE.COM` and
`urn:sts-mock:user:alice` are one person here exactly as they are one entry in
the directory), and nothing requires it back. **The directory arrives through
`setDirectory()`, which `ldap_server.js` fills at ITS require time** — the same
inversion `group_claims.js`, `applications.js`, `federation.js`,
`spiffe_registry.js`, `vc_claims.js` and `admin_rbac.js` all use, and for their
reason: that module is required at 21 precisely so its routes are registered
last.

### The unit is (person, application, scope) and it is ONE VALUE

Not a snapshot of the `scope` string, and not a list hanging off a pair. Both
were considered and both answer the wrong question. A SNAPSHOT makes
`openid profile` and `profile openid` two different agreements, and adding one
scope to a client's request throws away the agreement to the other four. A LIST
inside one attribute value is a value that grows, which a directory cannot add
to or remove from a member of — every change would be a read, a rewrite and a
race.

One value per triple makes every operation an `add` or a `remove` of exactly the
thing being talked about, and makes the question the authorization endpoint asks
— *which of these five scopes has this person not agreed to for this client* — a
set difference rather than a parse.

### Why the client_id is the LAST field of the value

    oauthConsent: 20260901143000Z openid webapp1

Three fields, space-separated, and the order is the only order this value can be
parsed in without a rule somebody can break. The TIMESTAMP is a GeneralizedTime
— digits and a `Z` — and cannot contain a space. The SCOPE cannot either, and
that is guaranteed by CONSTRUCTION rather than by a check: a scope value only
ever reaches this module by having been split out of a space-delimited `scope`
parameter (RFC 6749 section 3.3), so a value with a space in it is not one
scope. The CLIENT_ID is the one field with no rule at all —
`identifierProblem()` refuses only a line break, a NUL and 512 characters — so
it goes last and takes the remainder.

That is also why the delimiter is a SPACE rather than this repository's usual
`|`. The `|` convention works on `oauthPermission` (`name|description`) because
the unconstrained field is last there too; here the unconstrained field contains
`|` as happily as anything else.

**THE TIMESTAMP IS CHECKED AGAINST ITS OWN SHAPE AND NOT MERELY SPLIT OFF**, and
that check is what tells a value this service wrote from a sentence somebody
left on an entry. `this is not a consent` fits a space-counting grammar exactly
and would otherwise read as a consent to `is` for a client called
`not a consent` — a permission granted to nobody, invented by a parser out of
prose. Fourteen digits and a `Z` is what `generalizedTime()` emits; anything
else is reported as unreadable and consents nothing.

**A DELEGATED PERMISSION IS STORED WHOLE.** `https://example.com/write` is what
the client put in its `scope`, so it is what is recorded. Storing the resolved
permission NAME instead was refused for the reason the feature exists: two
resources may both expose `read`, the person agreed to one of them, and a
consent recorded as `read` would silently cover the other.

### The override is not a record, and that decides what removing it does

`oauthGlobalConsent` on the CLIENT APPLICATION's entry, one value per scope. A
scope named there is never asked about: everybody who signs in to that
application skips the prompt for it and **nothing is written about anybody**.

Two consequences follow and both are said on the console page, because they are
what somebody gets wrong:

* **Removing one asks EVERYBODY again**, including the people who would have
  said yes — there is no record of who they were. Removing a person's own
  `oauthConsent` asks one person.
* **It is keyed on (application, scope) and never on the scope alone.** A
  service-wide list of harmless scopes would be shorter to configure and would
  mean an application registered five minutes ago inheriting a decision made
  about a different one.

### Two more things

**THE RULE ABOUT WHAT A SCOPE MAY BE LIVES IN `applications.js`.** RFC 6749
section 3.3's `scope-token` is `scopeTokenProblem()` over there, beside
`permissionNameProblem()` which is that rule plus a refusal of `|`. That module
owns the SCHEMA, so it owns what a value of one of its attributes may be, and a
second copy of the grammar here would be the thing that eventually disagreed.
This file delegates in one line.

**A SERVICE WHOSE SLOT WAS NEVER FILLED PROMPTS EVERY TIME AND SAYS SO.** Not
"consents to everything": an agreement that cannot be remembered is one nobody
gave, and the honest behaviour is to ask again. `record()` answers
`{ ok: true, stored: false }` so that a directory which cannot hold the answer
never fails an authorization request — a mock that stopped issuing because it
could not file the paperwork would be a mock that stopped answering.

**IT IS PER REALM FOR FREE.** Both halves live in the directory, the directory
is a subtree per realm, and `applications.js`'s registry is that subtree's
`ou=applications`. So a consent agreed in `acme` is invisible in the default
realm without one line in this file mentioning a realm — which is the property
to check a new store against, answered here by having no store.
