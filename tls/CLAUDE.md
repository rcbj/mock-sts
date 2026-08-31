# tls/

TLS and mutual TLS: two HTTPS listeners of its own, 8443 and 9443, whose whole
content is what the SERVER saw of the connection. One file — and it is the source
of the certificate and key that THREE other sockets in this process use.

`tls_server.js` is the newest of the four and the one whose sockets are easiest to
forget are sockets — and there are now TWO MORE TLS sockets in this process that are
not its own, both on `serverCertificate()`'s certificate and key rather than a second
pair: the directory's LDAPS listener on 636, and — when `global.https` is set, which
`oauth2.rfc9700` does by default — THE MAIN PORT ITSELF, bound as HTTPS from
`listen()` in `server.js`. So one anchor covers 8443, 9443, 636 and 8081, and a
caller trusts this service once per start rather than four times. The LDAPS half is
what makes `ldap_server.js` require this module, and therefore what fixes their order
in `server.js` (rule 6); the main-port half needs no require order at all, because
`server.js` already has this module in hand by the time it listens. The private key
crosses a module boundary and no network one: it is generated per start, held in
memory, and `GET /tls/server-certificate` publishes the certificate alone.

**One thing that arrangement costs, and it is stated on the page rather than left to
be met as a handshake failure**: with the main port TLS there is no plain listener in
this process, so `POST /tls/trust` and `GET /tls/server-certificate` — which exist to
be reachable BEFORE anything is trusted — have to be called the first time with
verification off.

Its own sockets: they speak **HTTP**, so they look as though they belong on the
plain listener — but they are HTTPS on 8443 and 9443, and `GET /admin/sts-metadata` walks
the plain listener's router, which cannot see them. Its four rows there are the
plain-HTTP views only, and the listeners are described in their text. Its truststore
for CLIENT certificates is empty at startup and is filled at runtime through
`POST /tls/trust`, because the CA it verifies is generated in somebody's browser
minutes before the connection; that endpoint is on the MAIN port on purpose, since
that is normally the one reachable before anything is trusted. `global.https` —
which `oauth2.rfc9700` turns on — takes that property away by making the main port
TLS as well, so the first fetch of the certificate and the first POST of an anchor
then have to be made with verification off. Every sentence in that module which
names the port goes through `mainPortPhrase()` for exactly that reason; seven of
them used to say "the plain HTTP port" outright, which would be quietly wrong in
the one place a reader goes when a handshake is failing.

---

## A verified client certificate is not a login

* **A verified client certificate on the TLS listeners is not a login**, and no
  revocation is checked there. Verification means one thing exactly: OpenSSL built a
  chain from what the client sent to an anchor somebody POSTed to `/tls/trust`. No
  session starts, no token is issued, no endpoint will let its holder do anything an
  anonymous caller cannot, and a revoked certificate verifies here and would not
  verify anywhere that matters. All of that is stated in the report itself rather
  than left to be discovered — a mock that quietly turned a certificate into an
  identity would teach a client something false about every server it will ever meet.
  **It IS recorded, which is a different claim and the two must not be merged.** When
  a handshake completes with a certificate that verified, `tls_server.js` calls
  `stats.recordAuthentication()` — the same funnel every other family uses — so the
  subject DN appears on `/admin/users` under protocol `TLS` and the directory's
  observer seeds an entry for it. Three things there are load-bearing: it happens on
  `secureConnection` and **not in the request handler**, because the credential was
  accepted at the handshake and per-request counting would report one connection's six
  requests as six authentications; it happens only when `authorized` is true, so a
  certificate that failed records nothing on the permissive listener; and the identity
  is the subject in **RFC 4514 form** (leaf first, values escaped), which is a
  different string from the display DN shown beside it and is the one the directory
  builds from.

* **`dnRfc4514()` NOW LIVES IN `common/helpers.js` and is re-exported from here.**
  It was written in this module and the export stays, because `scim_auth.js` and
  `spiffe_auth.js` require this module for it. What forced the move is a FOURTH
  producer of that string: the SPIFFE authority records the certificate behind
  every X509-SVID it mints onto the holder's directory entry, using **the same six
  `x509*` attributes this path writes**, and `spiffe_ca.js` cannot require this
  module — `admin.js` requires that one and is required first, so the require
  would move every `/tls*` route ahead of the console's and `GET /admin/sts-metadata`
  walks that router. Two spellings of one DN is two people on `/admin/users`,
  which is the sentence the export comment here has always carried; there are now
  four callers of it rather than two. `common/CLAUDE.md` has the argument,
  including the second shape of DN the function learnt for that caller.

* **The SPIFFE path ASSIGNS those six where this one APPENDS, and the difference
  is not a disagreement.** A renewed client certificate is a new serial for the
  same person and is rare, so appending is what makes both visible. An X509-SVID
  is minted afresh at half its lifetime for as long as the workload runs, so
  appending there would add six values an hour for ever. See
  `applySpiffeCertificate()` in `ldap/ldap_server.js`, which says so beside
  `certificatePlan()` for exactly this reason: the two functions look alike
  enough to be "fixed" into agreement by somebody reading only one.

## Post-quantum certificates

`tls.certificateAlgorithms` (`STS_TLS_CERT_ALGS`) decides what the two
listeners present. It is `rsa` alone by default and takes any of `ml-dsa-44`,
`ml-dsa-65` and `ml-dsa-87` beside it, comma separated.

**More than one is the setting worth having.** node takes parallel `key`/`cert`
arrays and OpenSSL serves whichever certificate matches the signature
algorithms the CLIENT offered — so `rsa,ml-dsa-65` answers an ordinary client
with RSA and a post-quantum one with ML-DSA over the same port and the same
listener. That is what a migration looks like, and it is a property of OpenSSL
rather than of this code, which is why `tests/pq_certificates.js` asserts it
rather than describing it.

The ML-DSA certificate comes from `common/crypto.js`'s
`selfSignedMlDsaCertificate()`. **node-forge cannot build it** — it has no
ML-DSA and cannot represent the key — so the key and the signature come from
node's own OpenSSL 3.5 and the DER is written out there against RFC 9881 and
RFC 5280. It is deliberately not vendored from the debugger: this service is
the far end of that code, and two copies of one reading of a specification
agree with each other and interoperate with nothing. `common/pq_jose.js` makes
the same argument at greater length.

Three consequences are worth knowing before turning it on:

* **`GET /tls/server-certificate` returns every certificate**, concatenated. A
  truststore built from the first one alone fails to verify the connection it
  actually gets, and which one it gets is the caller's own doing.
* **The `openssl` binary in these images is 3.0 and cannot read any of it.**
  `openssl x509 -in ml-dsa.pem -text` prints `Unable to load certificate`. Node
  reads it perfectly; so does anything else linked against 3.5 or later.
* **`/tls/whoami` reports the post-quantum posture in two independent halves**,
  the key exchange and the certificates, because they answer different
  questions on different timescales and a single boolean would be wrong for
  almost every connection made today. Node cannot NAME a hybrid ML-KEM group —
  `getEphemeralKeyInfo()` knows ECDH and DH only — so an unnamed group is
  reported as unnamed, with both readings (a hybrid group, or a resumed
  session) rather than a guess.

LDAPS on 636 keeps serving the FIRST certificate, which is the RSA one unless
the setting says otherwise: no LDAP client in reach speaks ML-DSA, and the
point of that listener is that one anchor covers 8443, 9443 and 636.
