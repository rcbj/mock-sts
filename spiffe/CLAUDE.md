# spiffe/

An issuing authority for one trust domain, in all three of its server-side
shapes: the bundle endpoint over plain HTTPS, and the Workload API and SPIRE
Server API over gRPC on FOUR MORE SOCKETS — a Unix socket and a TCP port each.

`protos/` holds the SPIFFE project's own `workloadapi.proto` and the
`spire-api-sdk`'s, VERBATIM. `spiffe_grpc.js` reads them at module scope through
`path.join(__dirname, 'protos')`, so they moved into this directory with it; a
missing one is not a degraded SPIFFE feature, it is a service that does not start.
The wire matching what a real client expects is the entire reason
`@grpc/grpc-js` is a dependency here, so a local edit to one of these would give
that up silently.

3k. **SPIFFE IS SIX MODULES AND THE SPLIT IS BY WHAT WOULD OTHERWISE DRIFT.**
   `spiffe_id.js` (the ID grammar), `spiffe_ca.js` (the authorities, minting,
   the bundle), `spiffe_registry.js` (entries and agents, directory-backed),
   `spiffe_grpc.js` (loading the protos, binding, the wrappers),
   `spiffe_workload.js`, `spiffe_api.js` (the handlers) and `spiffe_auth.js`
   (who is calling) are all LIBRARIES — they register nothing — and only
   `spiffe_server.js` registers routes and starts listeners. Nine things are
   load-bearing:

   **THE TWO SURFACES ARE AUTHENTICATED DIFFERENTLY BECAUSE THEIR
   SPECIFICATIONS SAY OPPOSITE THINGS, and reading that as an inconsistency is
   the mistake to avoid.** The SPIFFE Workload Endpoint specification says the
   endpoint "MUST NOT require any direct authentication of its clients" and that
   "Transport Layer Security MUST NOT be required" — bootstrapping: a workload
   has no secret and no root of trust until this call gives it one. A real SPIRE
   *server*, by contrast, binds a TCP port whose callers present an X509-SVID
   over mutual TLS and authorizes every method against what the caller IS. So:
   `spiffe.authRequired` reaches the SPIRE Server API and DELIBERATELY NOT the
   Workload API. Do not "fix" the asymmetry.

   **NOTHING ATTESTS A WORKLOAD OR A NODE, WHICH IS A DIFFERENT CLAIM FROM
   "NOBODY IS AUTHENTICATED" AND THE TWO MUST STAY APART.** A real agent reads
   the peer credentials of its Unix socket — `SO_PEERCRED`, giving pid and from
   that uid, gid, executable, container, pod — and turns them into selectors.
   **Node has no portable way to read them**: `net.Socket` exposes no such call
   and `/proc/net/unix` does not record the peer. So `spiffe_auth.js` identifies
   a Workload API caller by the TRANSPORT it arrived on, the ENDPOINT it reached
   and its PEER ADDRESS, and by nothing else. Two consequences:

   * **Selector matching now DECIDES the answer** (`spiffe.attestWorkloads`,
     on by default). `selectorsMatch()` computes exactly what SPIRE would — the
     entry's selectors a SUBSET of the workload's, not equal, not intersecting —
     and the Workload API uses it, which it did not before. An INVENTED entry
     carries the caller's STABLE selectors (transport and endpoint, never
     `peer:` — its port is ephemeral and a fresh entry would be invented per
     connection until the registry hit its cap).
   * **The selectors are spelt `transport:`, `endpoint:` and `peer:`** and never
     `unix:` or `k8s:`. Writing `unix:uid:1000` for a uid nothing read would be
     inventing an attested fact, which is the `wauth` argument again. An
     ASSERTED selector — `spiffe.acceptAssertedSelectors`, OFF by default, sent
     in an `x-sts-mock-workload-selector` header — is passed through VERBATIM,
     because it is the caller's own claim rather than this service's invention,
     and it exists so that a client's "these matched and those did not" path can
     be exercised at all.

   **THE SPIRE SERVER API'S AUTHORIZATION TABLE IS SPIRE'S OWN, COPIED ROW FOR
   ROW.** `POLICY` in `spiffe_auth.js` is `pkg/server/authpolicy/policy_data.json`
   restricted to the forty-two methods here, and it is copied rather than
   reasoned out: a table derived from what each method "obviously" needs
   disagrees with SPIRE in two or three places and the client author who meets
   the disagreement cannot tell which end is wrong. Where a row looks surprising
   — `Debug.GetInfo` is LOCAL-ONLY, so an admin SVID over TCP is refused it —
   that is SPIRE's answer and the surprise is the point. A method with NO ROW is
   REFUSED and logged as a defect here; the other default fails silently
   forever. **It decides and never answers**: `spiffe_auth.js` returns a
   `{ status, message }` descriptor and `spiffe_grpc.js` maps it, the same split
   `oauth2_bcp.js` has with `oauth2.js`. **The check is in the wrapper**, so
   there is no authorization code in any of the forty-two handlers and there
   must not be.

   **THE `admin` AND `downstream` FLAGS ON AN ENTRY ARE NOW READ.** They were
   recorded, reported, and consulted by nothing, and this file said so. They are
   read on every call and never cached, so an `ldapmodify` of `spiffeAdmin`
   changes what that identity may do on the NEXT one. `spiffe.adminIds` is the
   other way in and is SPIRE's own `admin_ids`: it needs no entry.

   **`Agent.RenewAgent` STOPPED BEING UNIMPLEMENTED because of it**, and the
   refusal it replaced is the argument to keep in view: "nothing here
   authenticates the caller, so answering would mean renewing whichever agent
   the caller named". Something does now, so the method renews the agent on the
   CONNECTION and never one named in the request — and with `spiffe.authRequired`
   off it answers `Unimplemented` with that same sentence.

   **AN ACCEPTED CREDENTIAL IS AN IDENTITY**, through the funnel every other
   family uses. Three acceptances reach it: an X509-SVID over mutual TLS (ONCE
   PER CONNECTION — the credential was accepted at the handshake, which is
   `tls_server.js`'s decision made again), an agent attesting, and a JWT-SVID
   verified at `ValidateJWTSVID`. Being ISSUED an SVID is not one of them.
   `ldap_server.js`'s `spiffePlan()` is the fourth placement plan (rule 6) and
   `entryBySpiffeSubject()` is what makes the same identity arriving three ways
   ONE entry.

   **`spiffe.autoCreateEntries` OFF IS THE INTERESTING SETTING**, and it is the
   one thing here that must not be quietly removed: with it off, a caller
   matching no entry gets an EMPTY SVID LIST, which is what a real agent does
   for an unregistered workload and the only way to run a client's "I have no
   identity" path.

   **THE STREAMS STAY OPEN.** Four Workload API methods are server streams and a
   real client holds `FetchX509SVID` for the life of the process. `serverStream()`
   in `spiffe_grpc.js` deliberately does NOT call `end()`, and
   `pushOnRotation()` re-sends at half the SVID lifetime. A Workload API that
   writes once and ends looks perfect on the first fetch and puts `go-spiffe`
   into a reconnect loop — and re-sending is what makes a client's ROTATION path
   run without anybody waiting an hour. The push callback returns false once the
   peer has gone, which is what stops the timer; a timer that outlived its stream
   writes to a dead one and grpc-js reports that as an unhandled server error.

   **THE REGISTRY IS THE DIRECTORY, exactly as `applications.js`'s is** (rule
   3g). Two containers, because they hold different KINDS of thing: an entry
   under `ou=entries,ou=spiffe` is CONFIGURATION deciding what gets issued, and
   an entry under `ou=agents,ou=spiffe` is a RECORD of something that happened —
   which is why `EDITABLE` covers the first and nothing about an agent is
   editable. NO MAP SHADOWS THEM, so an `ldapmodify` of `spiffeX509SvidTtl`
   changes the next SVID. `ldap_server.js` fills `setDirectory()` at its require
   time and the dependency is NOT inverted (rule 3e's test fails both ways
   round: no cycle, no route moves).

   **TWO PKIs IN ONE PROCESS, ON PURPOSE.** The SPIFFE CA is not
   `tls_server.js`'s certificate and must not become it: that one is a leaf with
   `CA:FALSE` and `serverAuth`, and a trust domain's root and a host's TLS
   identity are unrelated trust decisions. The X.509 authority is **EC P-256 by
   default** — what SPIRE issues — which is why the four PKI modules are
   VENDORED from the debugger: `node-forge`, which `helpers.js` and
   `tls_server.js` use, cannot sign with an EC key at all. **`spiffe_ca.js`'s
   initialisation is ASYNC** (Web Crypto), which nothing else in this service is:
   one promise started at require time, and every entry point awaits `ready()`
   itself so no caller can forget. `state()` is the one synchronous exception and
   says why.

   **A FOREIGN BUNDLE IS PUSHED IN AND NEVER FETCHED.** `RefreshBundle` refuses,
   naming the URL it is not fetching. Same refusal as `wreqptr` and `jwks_uri`,
   and holding it in two files and not a third would be no position at all. The
   bundle document IS checked — every JWK needs a `use`, because a consumer MUST
   IGNORE one without it, so an unchecked bundle verifies nothing and reports no
   error.

   **SIX OF THE 42 SPIRE METHODS ARE UNIMPLEMENTED AND EACH PUBLISHES A
   REASON**, in `NOT_IMPLEMENTED` and on `GET /spiffe`. A table saying 42 of 42
   would be the most misleading thing in this repository — the same rule
   `oauth2_bcp.js` follows by publishing its `enforced: 'no'` rows. It was SEVEN
   until `RenewAgent` became answerable; the note above that table records what
   its reason was and why it no longer holds. **Do not implement a WIT method by
   inventing the token format**: that is the `wauth`-is-a-refusal argument, and
   code written against the invention would work here and interoperate with
   nothing.

   **TWO gRPC TRAPS, BOTH ALREADY PAID FOR.** `keepCase: true` does not reach
   protobufjs's built-in well-known types, so a `google.protobuf.Struct` is built
   with **camelCase** members (`stringValue`, not `string_value`) while every
   other field in the family is snake_case — the wrong spelling serialises to
   NOTHING, with no throw and no warning. And protobufjs wraps exactly one
   well-known type, `Any`: a plain object assigned to a Struct field becomes a
   Struct with no fields. `ValidateJWTSVID` answered 200 with empty `claims`
   until a real client asked for them.


---

6a. **`spiffe_server.js` must stay after `ldap_server.js` AND after
   `tls_server.js`, and it INVERTS one dependency the way `ldap_server.js`
   inverts five.** The `tls_server.js` half is the newer of the two and is a
   plain require rather than an inversion, arrived at by rule 3e's test applied
   both ways round: `spiffe_auth.js` needs `dnRfc4514()` — the ONE spelling of a
   certificate subject, which `scim_auth.js` requires for the same reason, since
   two spellings of one DN is two people on `/admin/users` — and that module
   knows nothing about SPIFFE, so there is no cycle, and its `/tls*` routes are
   already registered by the time this is read, so no route moves. The plain half first: the
   SPIFFE registry's store is the directory under `ou=spiffe`, and that module
   fills `spiffe_registry.js`'s `setDirectory()` slot at ITS require time — so
   requiring this any earlier leaves the registry with no store at the moment
   `listen()` writes the seed entries. It is the FOURTH module whose own
   listeners start from `listen()` in `server.js` rather than at require time,
   and for the reason the other three carry: binding can fail, and a `require`
   that throws takes the whole service down where a route cannot. FOUR sockets,
   each reported SEPARATELY (`GET /spiffe`, `/admin/spiffe`), because "the
   Workload API socket is up and the SPIRE Server API port is not" is an
   ordinary outcome and one flag could only report one of them — the lesson
   `ldap_server.js` records about 389 and 636, applied before it had to be learnt
   again.

   **The inversion is the CONSOLE.** `/admin/spiffe` must report which listeners
   bound, and only this module knows — but `admin.js` cannot require it, because
   `server.js` requires `admin.js` FIRST and the require would pull `/spiffe` and
   the bundle endpoint into the router ahead of every `/admin` route, which
   `GET /sts-metadata` walks. So `admin.js` offers `setSpiffeReader()` and this
   module fills it at require time — the same shape `setDirectoryReader()`,
   `setGroupReader()` and `setScimReader()` have. `admin.js` DOES require
   `spiffe_ca.js` and `spiffe_registry.js` directly: they register nothing, so
   neither thing that forces a slot applies.

   **THE UNIX SOCKET IS THE ONE THING THIS SERVICE PUTS ON A FILESYSTEM**, and
   the distinction is worth keeping: it is a rendezvous point, it holds no bytes,
   it is unlinked on close, and a fresh process makes a fresh one. TCP-only would
   have been filesystem-clean and unreachable by every real client, because
   `SPIFFE_ENDPOINT_SOCKET` means a `unix://` path to `go-spiffe`,
   `spiffe-helper` and the SPIRE agent. A STALE socket is unlinked before
   binding; something at that path that is NOT a socket is left alone and
   reported, because deleting a file named in configuration on the strength of a
   typo is not this service's decision to make.


---

## Nothing here is attested, and that is a narrower sentence than it was

* **NOTHING IN SPIFFE IS ATTESTED, AND THAT IS NOW A NARROWER SENTENCE THAN IT
  WAS.** No workload and no node: a Workload API caller is identified by its
  transport, the endpoint it reached and its peer address — node cannot read a
  Unix socket's peer credentials — so any caller that reaches the socket still
  gets an identity, and an agent's attestation payload is written down as
  claimed, which is why every agent entry carries a selector valued
  `unverified:true`. **What changed is the OTHER half**: the SPIRE Server API's
  TCP port is MUTUAL TLS, its callers present an X509-SVID verified against the
  trust bundle, and every method is authorized against SPIRE's own table. Those
  are two different claims and merging them back into one gets both wrong.
  Selector matching also DECIDES which entries answer a Workload API caller
  now (`spiffe.attestWorkloads`), which is narrowing without attesting.
  What IS refused: a Workload API call with no `workload.spiffe.io: true` header
  (every conforming implementation refuses it, and a client that omits it has a
  bug nothing else will report), a JWT-SVID with no audience, a
  `ValidateJWTSVID` that does not really verify, an entry in another trust
  domain or under `/spire`, a banned agent, a join token this server did not
  mint or that has expired or been spent or was minted for another agent, an
  X509-SVID that no authority here signed or that is outside its validity
  window, every method the caller's entity is not allowed, and a federated
  bundle whose JWKs have no `use`. `spiffe.authRequired` off restores the whole
  of the old posture. See rule 3k, `spiffe_auth.js` and `GET /spiffe`.
