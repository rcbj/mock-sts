#!/usr/bin/env bash
#
# File: postgres/require-tls.sh
#
# ---------------------------------------------------------------------------
# MAKE TLS REQUIRED RATHER THAN MERELY AVAILABLE.
#
# `ssl=on` lets a client use TLS. It does not make one. A stack that turned TLS
# on and left `host` rules in `pg_hba.conf` would accept a plaintext connection
# from anything on the bridge and report itself as encrypted — which is the
# worst of the two states, because it reads as done.
#
# So every `host` rule becomes `hostssl`. A client that connects without TLS is
# then refused BY THE SERVER, with `no pg_hba.conf entry for host ... , no
# encryption`, which names the cause.
#
# WHY THIS RUNS AS AN initdb SCRIPT. `docker-entrypoint.sh` runs initdb, brings
# a TEMPORARY server up on a unix socket, runs everything in
# /docker-entrypoint-initdb.d, stops it, and only then starts the real server.
# So an edit to $PGDATA/pg_hba.conf made here is in force for every connection
# the container ever accepts — and it happens exactly once, on the start that
# creates the cluster, rather than on every boot.
#
# `local` RULES ARE LEFT ALONE ON PURPOSE. They are unix-socket connections
# inside the container, which is what the entrypoint's own health check and
# `psql` use; TLS on a socket that never leaves the process's own filesystem
# buys nothing and would break the healthcheck this stack waits on.
# ---------------------------------------------------------------------------
set -euo pipefail

HBA="${PGDATA:?PGDATA is not set}/pg_hba.conf"

if [ ! -f "${HBA}" ]; then
  echo "postgres-tls: no ${HBA} to harden; leaving it." >&2
  exit 0
fi

# Only lines that BEGIN with `host` and a space — not `hostssl`, not
# `hostnossl`, not a comment. `hostnossl` is left as it is: a rule that says
# "plaintext only" is an explicit statement somebody made, and silently turning
# it into its opposite would be worse than leaving it to be noticed.
sed -i -E 's/^host[[:space:]]+/hostssl /' "${HBA}"

echo "postgres-tls: every host rule in pg_hba.conf now requires TLS:"
grep -E '^(host|hostssl|hostnossl|local)' "${HBA}" | sed 's/^/  /'
