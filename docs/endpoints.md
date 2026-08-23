---
title: Endpoints
nav_order: 4
---

# Endpoints

**There is no list of endpoints in this documentation, and that is deliberate.**
There are 144 of them, they change, and a list written here would be wrong within
a month with nothing to say so.

Ask the service instead:

```bash
curl -s localhost:8081/sts-metadata            # a page
curl -s 'localhost:8081/sts-metadata?format=json' | jq
```

## What that page is

It reads the endpoint list **off the running Express router**, so it cannot go
stale by omission. Each row carries the method, the path, a sentence about what
the endpoint is for, and a link to the specification it implements.

It also reports **drift**, in three arrays, and the parent project's
`tests/sts_metadata.js` fails on all three:

| Field | Means |
|---|---|
| `undocumentedPaths` | A route is registered and nothing describes it |
| `stalePaths` | Something describes a path that is not registered — what a rename produces |
| `unknownSpecIds` | A description cites a specification the page does not know |

All three empty is the service agreeing with its own description of itself. That
is the check worth running after any change that adds or renames a route.

## Its one blind spot

**A protocol that registers no HTTP route is invisible to the router walk.** Four
things here are exactly that:

- the Kerberos KDC on raw TCP and UDP 88
- the LDAP directory on 389
- the same directory over TLS on 636
- the SPIFFE gRPC listeners — a Unix socket and a TCP port each for the Workload
  API and the SPIRE Server API

Those are described by hand in the page's own table. If you add one, describe it
there or it goes unlisted with nothing failing.

The TLS listeners on 8443 and 9443 are a milder version of the same thing: they
speak HTTP, so they look as though they belong on the plain listener, but
`/sts-metadata` walks the *plain* listener's router and cannot see them. Their
rows there are the plain-HTTP views only, and the listeners are described in the
text.

## The other things the service publishes about itself

Each of these is generated from the same table the behaviour reads, so none of
them can drift from what the service does:

| Ask | Get |
|---|---|
| `GET /.well-known/openid-configuration` | The OpenID Provider Configuration |
| `GET /.well-known/oauth-authorization-server` | The RFC 8414 document |
| `GET /oauth2/rfc9700` | Every Security BCP requirement, with what is and is not enforced |
| `GET /admin-api/openapi.json` | The management API, generated from its operation table |
| `GET /admin-api/docs` | The same, in a small explorer that also shows the `curl` line |
| `GET /spiffe` | The trust domain, the four sockets, and all 42 SPIRE methods with a reason for each of the six that are unimplemented |
| `GET /ldap` | The directory's state, both listeners separately, and the fact that it is schemaless |
| `GET /tls` | Both TLS listeners, and what a verified client certificate does and does not mean |
| `GET /scim` | The SCIM authentication schemes that are switched on |
| `GET /krb5/principals` | The principal database, passwords included, for the reason that page gives |
| `GET /admin-api/status` | Which console pages exist — what the parity test reads |

## Named authorization servers

One process is several authorization servers. Any path component works and is
created on first sight:

```bash
curl -s localhost:8081/tenant1/.well-known/oauth-authorization-server | jq .issuer
```

Its endpoints live under that name (`/tenant1/oauth2/token`), its tokens carry it
in `iss` and `aud`, and **a credential does not cross between them** — an
authorization code issued by one is refused by another's token endpoint. The
capabilities in its document *drive* those endpoints rather than describing them,
so there is no second table that could disagree.
