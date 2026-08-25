#!/usr/bin/env bash
#
# The same test with NO DOCKER: three node processes on this machine.
#
# It exists for two reasons and the second is the one that matters. Docker is
# not always reachable — an unprivileged user on Linux cannot open
# /var/run/docker.sock without being in the `docker` group. And this is the
# faster loop: no image build, no healthcheck poll, about six seconds from a
# code change to an assertion.
#
# WHAT IT DOES NOT EXERCISE is the one thing the container stack exists for:
# there is no docker DNS here, so the "back channel" is 127.0.0.1 and the
# "front channel" is localhost. That is still a REAL split — the two are
# different Host headers, so `iss` would differ between the channels without
# STS_OAUTH2_ISSUER pinned, and this run proves that pin is load-bearing. What
# it cannot prove is that a service NAME resolves from inside one container and
# not from the host.
#
# Ports 3000, 8081 and 8082 have to be free. Every other listener each STS
# instance opens is moved out of the way, because a sibling stack on this
# machine is usually already holding the defaults.
set -euo pipefail
cd "$(dirname "$0")"
ROOT="$(cd .. && pwd)"
LOGDIR="${TMPDIR:-/tmp}/federation-e2e-$$"
mkdir -p "$LOGDIR"

PIDS=()
cleanup() {
  echo
  echo "Stopping the three processes…"
  for pid in "${PIDS[@]:-}"; do
    [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
  done
  wait 2>/dev/null || true
}
trap cleanup EXIT

for port in 3000 8081 8082; do
  if ss -ltn 2>/dev/null | awk '{print $4}' | grep -qE "[:.]$port\$"; then
    echo "Port $port is already in use. This script needs 3000, 8081 and 8082." >&2
    exit 1
  fi
done

echo "== Starting the upstream identity provider (sts-idp) on 8082 ======="
(
  cd "$ROOT"
  STS_PORT=8082 STS_TLS_PORT=18443 STS_MTLS_PORT=19443 \
  KRB5_KDC_PORT=10088 KRB5_SERVICE_PORT=18888 \
  LDAP_PORT=10389 LDAPS_PORT=10636 \
  STS_SPIFFE_WORKLOAD_PORT=18092 STS_SPIFFE_SERVER_PORT=18181 \
  STS_SPIFFE_WORKLOAD_SOCKET_ENABLED=false STS_SPIFFE_SERVER_SOCKET_ENABLED=false \
  ADMIN_AUTH_REQUIRED=false \
  STS_OAUTH2_ISSUER=http://127.0.0.1:8082 \
  CONFIG_FILE=./env/local.js exec node server.js
) > "$LOGDIR/sts-idp.log" 2>&1 &
PIDS+=($!)

echo "== Starting the service provider (sts-sp) on 8081 =================="
(
  cd "$ROOT"
  STS_PORT=8081 STS_TLS_PORT=28443 STS_MTLS_PORT=29443 \
  KRB5_KDC_PORT=20088 KRB5_SERVICE_PORT=28888 \
  LDAP_PORT=20389 LDAPS_PORT=20636 \
  STS_SPIFFE_WORKLOAD_PORT=28092 STS_SPIFFE_SERVER_PORT=28181 \
  STS_SPIFFE_WORKLOAD_SOCKET_ENABLED=false STS_SPIFFE_SERVER_SOCKET_ENABLED=false \
  ADMIN_AUTH_REQUIRED=false \
  STS_OAUTH2_ISSUER=http://127.0.0.1:8081 \
  STS_FEDERATION_OUTBOUND_ALLOW_INSECURE=true \
  CONFIG_FILE=./env/local.js exec node server.js
) > "$LOGDIR/sts-sp.log" 2>&1 &
PIDS+=($!)

echo "== Starting the web application on 3000 ============================"
(
  PORT=3000 APP_NAME="Hello World" \
  OIDC_ISSUER=http://127.0.0.1:8081 \
  OIDC_BROWSER_BASE=http://localhost:8081 \
  OIDC_CLIENT_ID=hello-world-app \
  OIDC_REDIRECT_URI=http://localhost:3000/callback \
  OIDC_SCOPE="openid profile email" \
  exec node webapp/server.js
) > "$LOGDIR/webapp.log" 2>&1 &
PIDS+=($!)

echo "   logs are in $LOGDIR"
echo
echo "== Configuring the federation relationship ========================="
export FED_HOST_RUN=1
node configure.js

echo
echo "== Driving one sign-in, end to end ================================="
set +e
node drive.js
STATUS=$?
set -e

if [ "$STATUS" != "0" ]; then
  for name in webapp sts-sp sts-idp; do
    echo
    echo "== $name (last 40 lines) ==========================================="
    tail -40 "$LOGDIR/$name.log" || true
  done
fi

exit "$STATUS"
