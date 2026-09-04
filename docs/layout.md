---
title: Repository layout
nav_order: 11
---

# Repository layout

For contributors. Until 2026-08-23 every module sat in the package root — 84
files, no grouping. They are now in directories by protocol family, and the files
themselves did not change; the paths did.

```
server.js            the shell: requires the modules and listens
sts_metadata.js      reads the router to list what everything else registered

common/              config, helpers, the express app, the counters, the audit
                     log, the application registry, the claim catalogues
common/vendored/     byte-identical copies of the parent project's PKI and
                     JSON-LD modules, plus the contexts they read
oauth-oidc/          the authorization server, RFC 9700 mode, DPoP, mTLS,
                     client authentication, the multi-AS profiles
authn/               the sign-in screen and the WebAuthn relying party
saml/                the two assertion builders
ws-trust/            WS-Trust 1.0-1.4
ws-federation/       WS-Federation 1.2 and the mock relying party
kerberos/            the KDC, the acceptor, SPNEGO, and the codec
ldap/                the embedded directory
persistence/         the only place this service writes anything down:
                     memory | ldif (RFC 2849) | postgres
scim/                /scim/v2, its authentication, its attribute mapping
ssf/                 Shared Signals: the transmitter, the RFC 9493 subject
                     grammar, the RFC 8417 envelope, the streams, the gate,
                     and the second outbound request in this repository
spiffe/              six libraries, one server module, the vendored protos
tls/                 the 8443 and 9443 listeners
oid4vc/              OpenID4VCI, OpenID4VP, DID Core
admin-ui/            the console at /admin
mgmt-api/            /admin-api and its generated OpenAPI document
home/                the front door: GET / and the logo on it

env/                 the appconfig files; CONFIG_FILE selects one
docs/                this site
node-ldapjs/         a git SUBMODULE
```

Each directory carries a `CLAUDE.md` with the reasoning for the modules in it.
Those are the maintainer-facing documents; this site is the user-facing one.

## Four things about the layout that are load-bearing

**The require order in `server.js` is the route order.** Every module calls
`app.get(...)` at its top level rather than exporting a `register()`, so express
applies middleware only to routes added after it and the order of the requires in
`server.js` decides everything. There is a table of the ordering constraints in
the root `CLAUDE.md`; each one is a real dependency rather than a preference.

**`common/vendored/` is not to be edited.** Those files are byte-identical copies
of files in the [OAuth2/OIDC Debugger](https://idptools.com), and two of that
project's tests exist to keep them that way. `contexts/` sits inside that
directory rather than at the root precisely so that `bbs2023.js` — which resolves
`path.join(__dirname, 'contexts')` — did not have to be edited when it moved.

**`node-ldapjs` is a submodule and must sit inside this package root.** npm
installs a `file:` dependency as a symlink and node resolves that package's own
requires by walking up from where the *real* directory lives, so a copy one level
up never reaches `node_modules` here. The failure is `Cannot find module
'abstract-logging'` from inside ldapjs.

**`CONFIG_FILE` is made absolute before anything reads it.** Fourteen modules
read the appconfig file directly for a log level, and node resolves a relative
`require()` against the directory of the module doing the requiring — which was
harmless while every module was in the package root and is not now.
`common/config_file.js` is the one place that decides it, and it is required
first by `server.js`, `common/config.js` and `common/helpers.js`.

## Adding an endpoint

Costs one entry in `sts_metadata.js`. That page reads the endpoint list off the
live router so it cannot go stale by omission, but it reports two kinds of drift
and the parent project's test fails on both: a route registered and undescribed,
and a description whose path is not registered (what a rename produces).

Coverage notes there must start `full`, `partial` or `mock` and say what is
missing. A list of fifty specifications that did not mention that this service
checks no passwords would be the most misleading thing in the repository.

## Adding a console page

A control added to `/admin` gets an operation on `/admin-api` **in the same
change**, and both get pagination. An API that covers eight of nine controls is
worse than one that covers none, because the ninth is found by a caller who has
already written the code that assumed it.

That is cheap rather than a matter of discipline: every API operation calls the
*same* action function the console's form posts to, every API GET calls the same
JSON view the page's `?format=json` answers, and the OpenAPI document is
generated from the operation table — so an operation cannot exist and be
undocumented, nor be documented and not exist.

What no code here can check is a new console control with **no** row. Nothing in
this service can see a form appear on a page, so the parity is asserted from
outside by this repository's own `tests/vendored/admin_api.js`, which reads the facts off
the *service* rather than off a list in the test.

## Tests

**There are none in this repository yet, and that is the main gap.** The tests
that cover this service live in the parent project. The root `CLAUDE.md` lists
which ones should be ported and what each covers, and names the two surfaces with
no test in either repository — SCIM, which would be the cheapest to write, and
SPIFFE, which is the largest untested surface here.
