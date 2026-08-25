# federation-e2e/

**One of the two tests in this repository, and the integration one** — the
other is `../tests/`, which asserts this repository's own module contracts in
process, needs no port and no container, and drives nothing. Three
containers, two identity services and one application that has never heard of
federation, and one sign-in driven across all three with 56 assertions on the
way.

It earns its place here because it builds a TOPOLOGY out of this service — a
protocol test that drives ONE copy of it goes in the parent project's suite
instead, beside `tests/sts_dpop.js` and `tests/saml11_sso.js`. The root
`CLAUDE.md`'s *Tests* section argues that line; `saml11_sso.js` was written in a
`tests/` directory here on 2026-08-25 and moved over there the same day, which is
what settled it.

| File | What it is |
|---|---|
| `docker-compose.yml` | The three containers, and the front-channel/back-channel argument. |
| `webapp/` | The mock web application: a hello-world page behind an OIDC sign-in. **No OIDC library**, and one dependency: bunyan. |
| `config.js` | Where the three services are, in BOTH of the two addresses each one has. |
| `configure.js` | Turns the two identity services into a federation, through `/admin-api`. Idempotent. |
| `drive.js` | Stands in for a browser. Three cookie jars, one form, every hop asserted. |
| `http_client.js` | A browser, roughly, in a hundred lines. |
| `run.sh` | Build, wait, configure, drive, report. Leaves the stack up. |
| `run-host.sh` | The same test with no docker at all. |

```
browser ──▶ webapp:3000          an ordinary OIDC relying party
          └─▶ sts-sp:8081        an OIDC PROVIDER to the webapp, and an OIDC
                                 CLIENT of sts-idp. The SERVICE PROVIDER of the
                                 federation relationship.
            └─▶ sts-idp:8082     the upstream OpenID Provider. The IDENTITY
                                 PROVIDER of the relationship, and the only
                                 place a name is ever typed.
```

---

## WHY THREE TIERS RATHER THAN TWO

Two instances of the mock STS with a relationship between them would exercise
every line of `federation/`. It would prove nothing about the property the
feature exists for, which is this:

> **The application asks ONE provider ONE question and gets ONE answer, and the
> fact that a second identity service actually authenticated the person is
> invisible to it.**

That can only be asserted from a third party that is not in on it. So the web
application is a separate container, has no dependency on this repository, and
contains the string "federation" exactly once — in a sentence saying it has
never heard of it. `drive.js` asserts directly that the ID Token it verified
carries `iss: sts-sp`, not `iss: sts-idp`.

It is also the reason `sts-idp` runs with `STS_FEDERATION_LOGIN_BUTTONS=true`
and no relationships configured: an identity service with no federation must
look **exactly** as it always did, and the driver asserts its sign-in screen
offers no partners.

---

## THE TWO ADDRESSES, WHICH ARE THE WHOLE REASON THIS RUNS IN CONTAINERS

Every service here has two addresses and they are not interchangeable:

| | |
|---|---|
| `http://sts-idp:8081` | what another CONTAINER dials — the **back channel** |
| `http://localhost:8082` | what the BROWSER visits — the **front channel** |

A federated OIDC sign-in uses **both, for one partner, in one flow**:

| Field | Followed by | Must be |
|---|---|---|
| `fedSsoUrl` | a browser | front channel |
| `fedTokenUrl` | sts-sp | back channel |
| `fedJwksUri` | sts-sp | back channel |

Get either backwards and the failure is silent until it is baffling, because the
request never arrives anywhere that logs: a front-channel URL in `fedTokenUrl`
makes sts-sp dial a name docker will not resolve for it, and a back-channel URL
in `fedSsoUrl` sends the browser to `sts-idp`, which the host cannot resolve at
all.

### And the consequence that bites after that one is fixed

The mock STS derives every published URL — **including the `iss` of every
token** — from the Host header of the request it is answering. That is exactly
right for a service reached at one address. Here it means an ID Token minted on
a browser-facing request would say `iss: http://localhost:8082` while the same
service's discovery document, fetched back-channel, says `iss:
http://sts-idp:8081`. Two truths, one provider, and every conforming client
refuses the mismatch — correctly.

**`STS_OAUTH2_ISSUER` pins it**, which is what a real deployment behind a proxy
does and what `config.js`'s own description of that setting warns about. Both
identity services pin theirs; `fedPeer` is set to the pinned value rather than
to either URL; and `configure.js` prints a NOTE if the published issuer is not
the pinned one, because "it was issued by somebody else" is a correct refusal
about a real mismatch and takes a while to recognise.

The web application meets the same problem one tier down and solves it the same
way: it fetches discovery back-channel and rewrites only the endpoints a BROWSER
visits onto `OIDC_BROWSER_BASE`. That is Keycloak's `frontendUrl` and every
other product's equivalent.

---

## THE COOKIE JAR IS PER ORIGIN, AND A FLAT ONE PASSES FOR THE WRONG REASON

The flow crosses three origins and **two of them set a session cookie under the
same name** — the mock STS calls its cookie `sts_session`, and both instances
are the same image. A single flat jar sends the service provider's session to
the identity provider and back, and each reads a session id the other minted.

What that produces is the worst kind of green: the flow completes, somebody
appears to be signed in, and the reason has nothing to do with federation.
`http_client.js` keys its jars by `scheme://host:port`, which is what a browser
does, and `jarFor()` is the only way in.

---

## WHAT IT ASSERTS, AND WHY NOT "DID THE PAGE LOAD"

A federated sign-in that ends on a hello-world page is not evidence of much.
Every interesting failure produces a green page: a shared cookie jar, a skipped
signature check, an ID Token from the wrong issuer. So the assertions are about
the **shape of the flow** and the **state left behind**:

* the trail crosses `webapp → sts-sp → sts-idp` and returns
  `sts-idp → sts-sp → webapp`, in that order, through
  `/federation/acs/{id}`;
* both hops sent **PKCE and a nonce** — sts-sp's is not configurable off;
* the sign-in screen's federation button carries **the whole authorization
  request** as `returnTo`, which is how a federated identity satisfies a flow
  already in progress;
* the application's ID Token says `iss: sts-sp`;
* sts-sp's relationship counted **exactly one** sign-in and recorded no refusal;
* sts-sp's directory entry names the relationship, the foreign issuer, and
  **which of its attributes came from the partner rather than being invented** —
  including one that only a per-partner `fedAttributeMap` could have written;
* `uid` was **not** overwritten by the partner;
* sts-idp filed sts-sp as an ordinary OIDC client and **has no relationships at
  all** — the two services run one image and differ only in configuration;
* and an unsolicited callback is **refused 401**, recorded on the relationship,
  and does not count as a sign-in.

That last one matters more than the fifty before it. A happy path proves almost
nothing about a surface whose bugs are security bugs; see
`../federation/CLAUDE.md`, which carries the full list of negatives this test
still does not cover.

### The `groups=employeeType` mapping is deliberate

The mock STS puts a `groups` claim in every token it issues and nothing in
`federation_map.js`'s default table maps that name — so without a per-partner
mapping it arrives, is reported as unmapped, and is thrown away. Configuring it
is what makes the test prove that per-partner mapping works **at all**, rather
than only that the defaults do.

---

## WHAT THIS TEST FOUND ON ITS FIRST RUN

**A foreign subject reached `startSession()` unnormalised**, so `userFor()`
applied this service's subject prefix a second time and every downstream token
carried `sub: urn:sts-mock:user:urn:sts-mock:user:alice`.

The doubling was the symptom rather than the bug. The identity funnel ALREADY
normalises — `recordAuthentication()` runs `presented` through `identityOf()`,
which is what makes `alice`, `urn:sts-mock:user:alice` and `alice@REALM` one
person and one directory entry — so an unnormalised name reaching the SESSION
meant the session and the directory disagreed about who signed in.
`/admin/users` said `alice` while the tokens said something else. It would have
happened with **any** partner whose subject carried an `@`, not only with one
that shares this service's URN format.

Fixed in `federation_map.js`'s `usernameFor()`, which now chooses, then
normalises, then applies `federation.usernamePrefix` — in that order, because a
prefix applied before normalisation separates a person from themselves on their
next sign-in.

**Two bugs in the harness itself are worth keeping in mind**, because both
produced confident green output. `env('USERNAME', 'alice')` read the
`USERNAME` already in every interactive shell's environment and signed in as
whoever was running the test — every variable here is prefixed `FED_` now. And
`Object.keys(user.protocols)` on an ARRAY gave `"0"`, which read as "the
protocol was not recorded".

---

## Running it

```bash
./run.sh              # containers: build, configure, drive, leave the stack up
./run.sh --down       # and tear it down
./run.sh --logs       # print each service's log if the drive fails

./run-host.sh         # the same test as three node processes, no docker
```

`run.sh` **leaves the stack up on purpose**: what the three services now hold is
the interesting part, and every one of them has a console. `/admin/federation`
on sts-sp shows the relationship and its counters; `/admin/users` on sts-sp
shows somebody who has never had a credential checked there; `/admin/users` on
sts-idp shows the same person where a name actually was typed.

### Running it without docker

`run-host.sh` starts the three as plain node processes on 3000, 8081 and 8082.
It exists because docker is not always reachable — an unprivileged Linux user
cannot open `/var/run/docker.sock` without being in the `docker` group — and
because it is the faster loop: about six seconds from a code change to an
assertion.

**What it cannot exercise is the one thing the container stack exists for.**
There is no docker DNS, so the back channel is `127.0.0.1` and the front channel
is `localhost`. That is still a real split — two different Host headers, so
`iss` would still differ between the channels without the pin, and this run does
prove that pin is load-bearing. What it cannot prove is that a service NAME
resolves from inside one container and not from the host.

Every listener each STS instance opens beyond its HTTP port is moved out of the
way (`KRB5_KDC_PORT`, `LDAP_PORT`, the SPIFFE sockets), because a sibling stack
on the same machine is usually already holding the defaults.

The three ports it does need — 3000, 8081 and 8082 — are hard-coded in that
script, but nothing else here is: `config.js` reads `FED_SP_BACK`,
`FED_IDP_BACK`, `FED_SP_FRONT`, `FED_IDP_FRONT` and `FED_APP_FRONT`, so a run
on other ports is a copy of `run-host.sh` with those five exported. That is how
this test was run on 2026-08-25 while another stack held the defaults.

### The output is bunyan, like everything else here

**Every file here that says anything logs through bunyan, and none of them calls
`console`** — that is `configure.js`, `drive.js`, `http_client.js` and
`webapp/server.js`; `config.js` prints nothing and has no logger. It is the same
shape as `tests/*.js` in the parent project, which is the suite this one would
have joined if it did not need three containers. A run is therefore JSON lines,
one per assertion, and `./node_modules/.bin/bunyan` prettifies it:

```bash
node drive.js | ../node_modules/.bin/bunyan     # ✓/✗ per line, coloured
LOG_LEVEL=debug node drive.js                   # every Entering/Leaving as well
```

A failing assertion is logged at `error` and a passing one at `info`, so
`LOG_LEVEL=error node drive.js` prints the failures and nothing else. The exit
status is what `run.sh` and CI read, and it is unchanged: nothing parses this
text.

**The web application logs through bunyan too, and that is the one place it
costs something**: its image now runs `npm install`, where it used to need no
registry at build time. The stack already pays for that on the STS image, so
what changed is a property of this one Dockerfile rather than of the stack —
argued in the Dockerfile's own header. The application still has **no OIDC
library**, which is the claim that was ever load-bearing: a relying party built
out of one would prove less about the provider it is pointed at, and bunyan sees
no protocol.

---

## Things this test deliberately does not do

| It does not | Why |
|---|---|
| Use a real browser | Every page in this stack is server-rendered and runs no script — the mock STS sets `script-src 'none'` service-wide — so a browser engine would add a hundred megabytes and answer no question `http_client.js` cannot. |
| Test the other four protocols | SAML 2.0, SAML 1.1 and WS-Federation need no back channel, so they exercise strictly less of the interesting machinery than OIDC does. They deserve their own runs; this one is the hardest case. |
| Cover the refusals `federation/CLAUDE.md` lists | It asserts ONE of them — an unsolicited callback. The rest (a wrong key, `alg: none`, HS256 against an RSA key, a wrong `aud`/`iss`/`nonce`, a replayed state) need a partner that can be told to misbehave, which this stack has no way to ask for. |
| Register anything at the identity provider | The mock accepts any `client_id`, which is its ordinary permissiveness and is exactly what a real partner would NOT do. Reading this against a real partner, that is the first thing to arrange. |
| Sign out | The application's `/logout` ends its own session and nothing else, and says so. RP-initiated logout at sts-sp, and a federated sign-out onward to sts-idp, are a different act — and this service does not consume a federated sign-out at all. |
