---
title: Getting started
nav_order: 2
---

# Getting started

## Clone it with `--recursive`

```bash
git clone --recursive https://github.com/rcbj/mock-sts.git
```

The LDAP directory is built on [`rcbj/node-ldapjs`](https://github.com/rcbj/node-ldapjs),
which is a git **submodule** pinned as `"ldapjs": "file:node-ldapjs"` in
`package.json`. Without `--recursive` the directory exists but is empty, `npm
install` installs a package with no `main`, and the failure arrives at startup as
`Cannot find module 'ldapjs'` — a message that names a package rather than a
submodule.

If you have already cloned:

```bash
git submodule update --init --recursive
```

`--recursive` rather than `--init` alone matters if you reached this repository
through the [OAuth2/OIDC Debugger](https://idptools.com), where it is itself a
submodule: a plain `--init` there stops one level short of this one.

## Run it

```bash
npm install
CONFIG_FILE=./env/local.js node server.js
```

`CONFIG_FILE` selects a file in `env/` — `local.js`, `test.js` or
`docker-tests.js`. At the default `debug` level every endpoint call and every
artifact before and after signing is logged. That is the point of a mock, so
resist quietening it; `env/test.js` is the quiet one if you need it.

The path is relative to the repository root, wherever you run node from and
whichever module reads it. That has been true since the modules moved into
subdirectories, and it is `common/config_file.js` that keeps it true.

## The ports

Only the first is HTTP. The rest are separate listeners, and several of them
will not bind on an ordinary user account.

| Port | What | Setting | Environment |
|---|---|---|---|
| 8081 | The HTTP service — every protocol endpoint, the console, the API | `global.port` | `STS_PORT` |
| 88 (TCP+UDP) | The Kerberos KDC | `krb5.kdcPort` | `KRB5_KDC_PORT` |
| 8888 | The Kerberos-protected test service | `krb5.servicePort` | `KRB5_SERVICE_PORT` |
| 389 | The LDAP directory | `ldap.port` | `LDAP_PORT` |
| 636 | The same directory over TLS (LDAPS) | `ldap.tlsPort` | `LDAPS_PORT` |
| 8443 | TLS, asking for a client certificate | `tls.port` | `STS_TLS_PORT` |
| 9443 | Mutual TLS, requiring one | `tls.mutualPort` | `STS_MTLS_PORT` |
| 8092 | The SPIFFE Workload API over gRPC | `spiffe.workloadPort` | `STS_SPIFFE_WORKLOAD_PORT` |
| 8181 | The SPIRE Server API over gRPC | `spiffe.serverPort` | `STS_SPIFFE_SERVER_PORT` |
| — | The Workload API's **Unix socket**, at `/tmp/spire-agent/public/api.sock` | `spiffe.workloadSocket` | `STS_SPIFFE_WORKLOAD_SOCKET` |

**A port that will not bind does not stop the service.** 88, 389 and 636 all need
root, and a host run is usually not root. The failure is RECORDED rather than
thrown — a `require` that throws would take the whole service down where a route
cannot — and each listener publishes its own result, because "389 is up and 636
is not" is the ordinary outcome and one flag could only report one of them:

- `GET /ldap` — `listening` / `listenError`, and a `tls` object with its own pair
- `GET /tls` — the same for 8443 and 9443
- `GET /spiffe` — all four SPIFFE sockets, separately
- `GET /krb5/principals` — the KDC

So a page answering 200 is not evidence that the listener behind it came up. Read
the flag.

## Running two copies

Everything is in memory and nothing is shared, so a second instance is just a
second process — but every default port collides. Give the second one its own:

```bash
CONFIG_FILE=./env/local.js \
  STS_PORT=8091 LDAP_PORT=3891 LDAPS_PORT=6391 \
  KRB5_KDC_PORT=8891 KRB5_SERVICE_PORT=8891 \
  STS_TLS_PORT=8493 STS_MTLS_PORT=9493 \
  STS_SPIFFE_WORKLOAD_PORT=8093 STS_SPIFFE_SERVER_PORT=8182 \
  STS_SPIFFE_WORKLOAD_SOCKET=/tmp/spire-agent-2/public/api.sock \
  node server.js
```

The SPIFFE Unix socket is the one thing this service puts on a filesystem, and
two instances sharing a path is the one collision that is not a bind error: the
second unlinks the first's socket as "stale" and takes it over. It says so in the
log when it does.

## In a container

```bash
docker build -t rcbj/sts .
docker run --rm -p 8081:8081 rcbj/sts
```

The image copies the whole build context (`.dockerignore` decides what is in it)
so that adding a protocol directory cannot be forgotten, installs with
`--omit=dev`, and defaults `CONFIG_FILE` to `./env/local.js`. `EXPOSE` documents
every port above; publishing them is the caller's decision.

The Workload API's Unix socket is inside the container. To reach it from the host
or another container, mount its directory as a volume — publishing 8092 is the
alternative and needs the client pointed at `tcp://host:8092` explicitly.

## Confirming it works

```bash
curl -s localhost:8081/healthcheck
curl -s -L localhost:8081/admin/sts-metadata | head -40
```

The second one is **behind the console gate** (`admin.authRequired`, on by
default): with no session it answers a 302 to the sign-in screen, which is why
the `-L` is there and why what comes back is that screen rather than the page.
Open it in a browser and sign in — any username, since this service checks no
password — or read the same service through `/admin-api`, which is not gated.
`ADMIN_AUTH_REQUIRED=false` turns the gate off entirely.

`/admin/sts-metadata` is the sharper of the two. It reads the endpoint list off the
live Express router, so it answers only once every protocol module has registered
its routes — a module that loaded but registered nothing shows up there and not
in the liveness probe. Add `?format=json` and look at `undocumentedPaths`,
`stalePaths` and `unknownSpecIds`: all three empty is the service agreeing with
its own description of itself.
