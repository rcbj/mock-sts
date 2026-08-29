#!/bin/bash
#
# tests/run-tests-in-container.sh — the tests image's CMD.
#
# IT RUNS INSIDE THE `tests` CONTAINER, on the compose network brought up by
# ../docker-compose-run-tests.yml, where the service under test answers at its
# compose DNS name (http://sts:8081) and this container has a Chrome of its own.
# Do NOT run it from a host shell: there is no `sts` name there, the report would
# be written into the working tree by whatever user ran it, and the browser job
# would drive the machine's own Chrome — which is ./local-run-tests.sh's job and
# is a different (deliberately different) run.
#
# It is this repository's answer to ../id-proto-debugger/tests/run-tests-in-container.sh
# and is very much shorter, for the reason its launcher is: that script has to
# provision Keycloak realms, a WS-Federation side-car and two walt.id services
# before a test can run. Here the only thing to wait for is one mock, and
# nothing has to be provisioned at all — this service accepts any entityID, any
# client and any username on first sight, which is what it is for.
#
# WHAT IT RUNS IS THE WHOLE SUITE: the ten in-process jobs AND the thirteen
# vendored protocol jobs, the Selenium admin-console job among them. That is
# run-report.js's own default; nothing is selected here, so a job added to
# either half arrives in this container with nothing edited.
#
# Arguments given to the container are passed straight through to
# run-report.js, so a hand-run can narrow the set the same way the host
# launcher does:
#
#   docker compose -f docker-compose-run-tests.yml run --rm tests \
#     ./tests/run-tests-in-container.sh --only=crypto --no-browser
#
set -u -o pipefail

cd "$(dirname "$(realpath "$0")")/.." || exit 1

# WHERE THE SERVICE IS. The compose file sets this and the image defaults it;
# both say the same thing, and the duplication is deliberate — a `docker run`
# on the same network with no environment at all still finds the service, and
# a stack that renames the service only has to say so in one place.
STS_URL="${STS_TEST_SERVICE_URL:-http://sts:8081}"
# Trailing slashes off: every job appends an absolute path to this, and
# `http://sts:8081/` + `/oauth2/token` is a 404 whose message names a path that
# looks right.
STS_URL="${STS_URL%/}"

# ---------------------------------------------------------------------------
# WAIT FOR IT, ALTHOUGH COMPOSE ALREADY DID.
#
# The compose file makes this container `depends_on` the service's HEALTHCHECK,
# so in the ordinary case this loop passes on its first turn. It is here for the
# two cases where that is not true and the failure would otherwise be read as a
# broken test: a stack brought up by hand with `docker compose run`, which
# honours depends_on but not the health condition of a service somebody started
# separately; and a service that answered its healthcheck and then died, where
# the difference between "not listening yet" and "not listening any more" is the
# whole diagnosis.
#
# node rather than curl, because this suite already requires node and requires
# curl nowhere; `rejectUnauthorized: false` because this service regenerates a
# self-signed certificate on every start, so nothing can have an anchor for it —
# the question here is whether the port answers, not whether it is trusted.
probe()
{
  node -e '
    var url = new URL(process.argv[1]);
    var m = url.protocol === "https:" ? require("https") : require("http");
    var req = m.get({ host: url.hostname, port: url.port, path: url.pathname,
                      rejectUnauthorized: false, timeout: 5000 },
      function (res) { process.stdout.write(String(res.statusCode)); process.exit(0); });
    req.on("error", function () { process.stdout.write("000"); process.exit(0); });
    req.on("timeout", function () { req.destroy(); process.stdout.write("000"); process.exit(0); });
  ' "$1" 2> /dev/null
}

waitForTheService()
{
  local deadline code
  deadline=$(( $(date +%s) + ${STS_TEST_READY_SECONDS:-180} ))
  echo "Waiting for the mock STS at ${STS_URL} ..."
  while :;
  do
    code="$(probe "${STS_URL}/healthcheck")"
    if [ "${code}" = "200" ];
    then
      echo "The mock STS is answering at ${STS_URL}."
      return 0
    fi
    if [ "$(date +%s)" -ge "${deadline}" ];
    then
      echo ""
      echo "ERROR: nothing is answering at ${STS_URL}/healthcheck (last" >&2
      echo "       status ${code:-000}). Nothing was run." >&2
      # The one diagnosis worth making by hand, because it reaches a test as a
      # closed socket and never names itself: in this service the SCHEME
      # follows the mode — oauth2.rfc9700 derives global.https — so a service
      # configured for RFC 9700 serves HTTPS on the port a permissive one
      # serves HTTP on.
      if [ "$(probe "https://${STS_URL#http://}/healthcheck")" = "200" ];
      then
        echo "       SOMETHING IS ANSWERING HTTPS THERE INSTEAD. In this" >&2
        echo "       service the scheme follows the mode: oauth2.rfc9700" >&2
        echo "       derives global.https. Check CONFIG_FILE / STS_HTTPS on" >&2
        echo "       the sts service in docker-compose-run-tests.yml." >&2
      fi
      return 1
    fi
    sleep 2
  done
}

# ---------------------------------------------------------------------------
# THE RUN.
#
# --service-url is what makes this container drive the `sts` one instead of
# starting a throwaway service of its own. run-report.js's rule is that
# WHOEVER STARTED IT STOPS IT, so nothing here takes that container down —
# compose does, when this process exits and docker-run-tests.sh's
# --abort-on-container-exit fires.
#
# A CHROME IS PRESENT, so the browser job runs. It is the admin console's only
# coverage, and leaving it out would be a green run that says nothing about the
# one surface here that can change what every protocol endpoint does. Pass
# --no-browser as an argument to this script to leave it out anyway.
# ---------------------------------------------------------------------------
runTheSuite()
{
  echo "Running the whole suite against ${STS_URL}."
  node tests/tools/run-report.js "--service-url=${STS_URL}" "$@"
  return $?
}

# THE ARGUMENTS COMPOSE CAN PASS, and why they arrive as a STRING.
#
# A compose file substitutes a variable into `command:` as one shell word, so a
# stack that wants `--only=crypto --no-browser` cannot express it there without
# an entrypoint that splits it. STS_TEST_ARGS is that entrypoint's half: it is
# split HERE, on purpose and with the quoting off, and it goes in front of the
# arguments given to this script so that a hand-run argument still wins by
# being later. Unset, nothing is added and the whole suite runs — which is what
# every ordinary run does.
EXTRA=()
if [ -n "${STS_TEST_ARGS:-}" ];
then
  read -r -a EXTRA <<< "${STS_TEST_ARGS}"
  echo "STS_TEST_ARGS: ${STS_TEST_ARGS}"
fi

waitForTheService || exit 1
runTheSuite ${EXTRA[@]+"${EXTRA[@]}"} "$@"
RC=$?

# The report is on a bind mount, so it outlives this container; saying where it
# landed ON THE HOST rather than in here is the difference between a person
# finding it and a person re-running the suite.
echo ""
echo "Report:   tests/report/latest/report.html   (on the host: ./tests/report/latest/)"
echo "JUnit:    tests/report/latest/report.xml"
echo "Logs:     tests/report/latest/logs/"

if [ "${RC}" -ne 0 ];
then
  echo "Tests FAILED (exit ${RC})."
else
  echo "Tests passed."
fi
exit ${RC}
