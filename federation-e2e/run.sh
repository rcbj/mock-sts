#!/usr/bin/env bash
#
# The whole test, in containers: build, wait, configure, drive, report.
#
#   ./run.sh            build if needed, run the test, LEAVE THE STACK UP
#   ./run.sh --down     the same, then tear it down
#   ./run.sh --logs     the same, and print each service's log on a failure
#
# The stack is left up on purpose. The interesting thing about this test is not
# whether it passes — it is what the three services now hold, and every one of
# them has a console:
#
#   http://localhost:3000              the application, signed in
#   http://localhost:8081/admin/federation   the relationship, and its counters
#   http://localhost:8081/admin/users        somebody who never had a credential checked here
#   http://localhost:8082/admin/users        the same person, where a name WAS typed
#
set -euo pipefail
cd "$(dirname "$0")"

DOWN=0
LOGS=0
for arg in "$@"; do
  case "$arg" in
    --down) DOWN=1 ;;
    --logs) LOGS=1 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

# `docker compose` (v2) where it exists, `docker-compose` (v1) where it does not.
if docker compose version >/dev/null 2>&1; then
  COMPOSE="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE="docker-compose"
else
  echo "Neither 'docker compose' nor 'docker-compose' is available." >&2
  exit 1
fi

# A DAEMON THIS USER CANNOT REACH is the commonest way this script fails, and
# the error docker prints for it names a socket rather than the fix.
if ! docker info >/dev/null 2>&1; then
  cat >&2 <<'MSG'
Cannot reach the docker daemon.

  * on Linux, add yourself to the `docker` group and log in again:
        sudo usermod -aG docker "$USER"
    or run this script with sudo;
  * or run the same test with no docker at all — see ./run-host.sh, which starts
    the three services as plain node processes and asserts exactly the same
    things.
MSG
  exit 1
fi

cleanup() {
  if [ "$DOWN" = "1" ]; then
    echo
    echo "Tearing the stack down…"
    $COMPOSE down -v >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

echo "== Building and starting three containers =========================="
$COMPOSE up --build -d

echo
echo "== Waiting for them to report healthy =============================="
# compose's own `depends_on: condition: service_healthy` already orders the
# startup; this waits for the PUBLISHED PORTS, which is a different thing and is
# what the scripts below actually use.
for i in $(seq 1 60); do
  if curl -fsS http://localhost:8082/healthcheck >/dev/null 2>&1 \
     && curl -fsS http://localhost:8081/healthcheck >/dev/null 2>&1 \
     && curl -fsS http://localhost:3000/healthz >/dev/null 2>&1; then
    echo "  all three are answering."
    break
  fi
  sleep 2
  if [ "$i" = "60" ]; then
    echo "  they did not all come up." >&2
    $COMPOSE ps
    exit 1
  fi
done

echo
echo "== Configuring the federation relationship ========================="
node configure.js

echo
echo "== Driving one sign-in, end to end ================================="
set +e
node drive.js
STATUS=$?
set -e

if [ "$STATUS" != "0" ] && [ "$LOGS" = "1" ]; then
  for service in webapp sts-sp sts-idp; do
    echo
    echo "== $service ========================================================"
    $COMPOSE logs --no-color --tail 80 "$service" || true
  done
fi

if [ "$STATUS" = "0" ] && [ "$DOWN" != "1" ]; then
  cat <<'MSG'

The stack is still up. What it now holds is the interesting part:

  http://localhost:3000                     the application, signed in
  http://localhost:8081/admin/federation    the relationship, its counters, and
                                            everything it is configured with
  http://localhost:8081/admin/users         somebody who has never had a
                                            credential checked on that service
  http://localhost:8081/ldap/federations    the register as the directory holds it
  http://localhost:8082/admin/users         the same person, on the service where
                                            a name was actually typed

  ./run.sh --down    to tear it down.
MSG
fi

exit "$STATUS"
