#!/bin/bash
#
# local-run-tests.sh — run this repository's tests, on this machine.
#
# It is this project's answer to ../id-proto-debugger/local-run-tests.sh, and it
# is a great deal shorter than that one for a reason worth knowing before
# reaching for a feature from over there: that script has to BUILD and PROVISION
# a whole stack — Keycloak realms, two walt.id services, a WildFly side-car,
# browser bundles, an extension — because the tests it runs drive a browser
# against all of it. Here there is ONE container and it is this service.
#
# The tests are in two halves and only the FIRST needs nothing at all: the
# in-process suite in tests/ asserts this repository's own module contracts and
# needs `npm install` and no more — no port, no container, no browser, no
# network. The second half is the parent project's protocol jobs, driven over
# HTTP against a RUNNING copy of this service, and one of those drives a
# browser. See tests/CLAUDE.md for where the line between the halves is and
# what belongs on each side of it.
#
# ---------------------------------------------------------------------------
# THE SERVICE THE PROTOCOL JOBS DRIVE IS A CONTAINER SINCE 2026-08-28, BROUGHT
# UP FROM THIS REPOSITORY'S OWN docker-compose.yml.
#
# It used to be a throwaway `node server.js` started on nine ports of its own,
# and that still exists behind `--no-docker`. What the container buys is that
# THE THING UNDER TEST IS THE IMAGE: the same Dockerfile, the same
# `npm install --omit=dev` against the committed lock, the same node version,
# the same `COPY . ./` with .dockerignore deciding what is in it. Several of
# the failures this repository has actually had are properties of the image and
# not of the source — an uninitialised nested submodule that installs a package
# with no `main`, a module that is present in the tree and excluded from the
# build context, a devDependency that .npmrc's `omit=dev` quietly did not
# install — and every one of them is invisible to a suite that runs the source
# out of a developer's own node_modules. The container is also how the run
# stops depending on which node happens to be on the PATH.
#
# THE TESTS THEMSELVES ARE STILL PLAIN SCRIPTS ON THIS MACHINE. Nothing is
# containerized but the service. They are node processes started by
# tests/tools/run-report.js with this repository as their cwd, which is what
# keeps the loop short (edit a test, re-run it, no image), what lets the five
# jobs that load this service's modules IN PROCESS keep doing so, and what lets
# the browser job drive the Chrome that is already installed here.
#
# FOUR THINGS ABOUT THE STACK ARE DECISIONS RATHER THAN MECHANICS:
#
#   IT IS ITS OWN COMPOSE PROJECT, ON ITS OWN PORT, UNDER ITS OWN CONTAINER
#   NAMES. `docker compose up` in this directory gives you `sts` on 8081, and
#   that is somebody's dev stack — very likely the same person's, in another
#   terminal. A test run that took that name would refuse to start while it was
#   held, and a test run that took that PORT would fail to bind; worse, the
#   teardown at the end of this script would remove the container somebody was
#   using. So the run is `mock-sts-tests`, the container is `sts-tests`, and the
#   host port is a FREE one found at start rather than a fixed number.
#
#   IT PERSISTS NOTHING. `STS_PERSISTENCE_MODE=memory`, and `--no-deps` so the
#   postgres service in that file is never started. A suite that persisted
#   would be a suite whose second run started from the first run's leavings,
#   which is the failure that looks like a flaky test and is not one.
#
#   THE IMAGE IS REBUILT EVERY RUN, because the whole point is to test what is
#   in the working tree, and an image is a snapshot of when it was built. That
#   is the run's largest fixed cost after the browser job, and `--no-build` is
#   there for the loop where nothing in the service changed — it says out loud
#   that the image may be older than the tree, because a stale service that
#   answers every request has already cost this project a page of false passes.
#
#   A STACK THAT WILL NOT COME UP IS A FAILED RUN, not a skip and not a quiet
#   fallback to running the service on the host. Which of those it is matters:
#   a run that silently ran the source instead of the image is a run whose
#   green does not mean what the last three paragraphs say it means. The one
#   exception is a machine with NO DOCKER AT ALL, where this falls back to the
#   in-process service and says so in three lines — because there the choice is
#   between the old suite and no suite. Passing `--docker` makes even that an
#   error.
# ---------------------------------------------------------------------------
#
# What this adds over `npm test` is a REPORT — tests/report/<timestamp>/ with
# report.html, JUnit report.xml and one log per test file — and the OTHER half
# of this service's coverage:
#
#   THE PROTOCOL JOBS, AGAINST THIS WORKING TREE. Thirteen jobs that drive a
#   RUNNING service over HTTP — the Selenium admin-console job among them.
#   This builds an image from this tree, brings up one container from
#   docker-compose.yml, runs them against it, and takes it down again.
#
# THE SUITE IS SELF-CONTAINED AS OF 2026-08-28, AND THAT WAS UNTRUE THE DAY
# BEFORE.
#
# Those thirteen jobs used to be READ OUT OF the parent project's tests/ — the
# decision the root CLAUDE.md argues — so this script could only run them on a
# machine that had both checkouts, and a machine with only this repository on
# it silently ran ten in-process files instead. They are VENDORED now:
# byte-identical copies under tests/vendored/, this repository's own files,
# with tests/vendored/MANIFEST.js recording where each came from and which are
# jobs. Nothing in a test run reaches outside this checkout any more.
#
# AND THEY RUN BY DEFAULT, which reverses what this script did for its first
# three days. They used to need `--protocol`, so the bare run was ten files in
# about three seconds — which says "Tests passed" having driven no protocol
# endpoint, no admin console and no browser at all. A default that hides
# thirteen of twenty-three jobs behind a flag is a default that gets trusted
# wrongly. The whole set is what you get; it takes about a minute, most of it
# the browser job.
#
# A JOB THAT CANNOT RUN IS REPORTED AS A FAILURE, not a skip. The throwaway
# service failing to start used to leave thirteen jobs marked `skipped`, which
# the summary counts as passing — so a run in which nothing was checked exited
# zero and said so in small grey text.
#
# THE PARENT IS STILL THE SOURCE OF TRUTH FOR THOSE FILES. They are not edited
# here — the rule `common/vendored/` carries. Fix the parent's copy, then
# `--vendor-sync`. `--vendor-check` reports drift and needs both checkouts.
#
# Options:
#   --only=<substr>[,<substr>...]
#                    Only the test files (and protocol jobs) whose name
#                    contains one of these. A bare word means the same.
#   --list           Name what would run, and run none of it.
#   --protocol       Run the parent project's mock-only jobs as well. The
#                    DEFAULT since 2026-08-28; the flag is kept because
#                    scripts and fingers still pass it.
#   --no-protocol    Leave them out: the in-process suite only, three seconds,
#                    and nothing said about any protocol surface or /admin.
#   --unit-only      The same as --no-protocol.
#   --no-browser     Leave out the jobs that drive a browser. One does:
#                    tests/sts_admin_console.js, which is the admin console's
#                    only coverage against this working tree — so a run with
#                    this flag says nothing about /admin. Browser jobs are run
#                    one at a time like everything else here; this runner is
#                    serial, so there is never a second Chrome open.
#   --protocol-only  Run only those.
#   --no-docker      Run the service the OLD way: a throwaway `node server.js`
#   --host-service   started by tests/tools/service.js on nine ports of its
#                    own, out of this working tree and this machine's
#                    node_modules. Faster by however long an image build takes,
#                    and blind to everything about the image — see the section
#                    above. It is also what --coverage uses, of necessity.
#   --docker         The default, spelt. What it adds is that a missing or
#                    broken docker is then an ERROR rather than a fall back to
#                    --no-docker: pass it in CI, where a silent change of what
#                    was under test is worse than a red run.
#   --no-build       Do not rebuild the image before starting the container.
#                    The image may then be OLDER than this working tree, which
#                    this says out loud every time, because a service that
#                    answers every request while being a week old is the most
#                    expensive kind of green there is.
#   --keep-stack     Leave the container running when the run finishes, and
#                    print how to reach it and how to stop it. For reading
#                    /admin, or re-running one job by hand against the same
#                    service.
#   --sts-port=N     Publish the container's 8081 on this host port instead of
#                    a free one chosen at start. Only useful when something
#                    outside this run has to reach the service at a known
#                    address.
#   --vendor-check   Compare tests/vendored/ against the parent checkout and
#                    report drift; run nothing else. Needs both checkouts, and
#                    says so and exits 0 when there is no parent beside this
#                    one, because the suite does not need one.
#   --vendor-sync    Re-copy the parent's files over tests/vendored/, then run
#                    nothing else. The ONLY sanctioned way those files change.
#   --parent=<dir>   Where the parent project is, for the two commands above.
#                    Default: the sibling ../id-proto-debugger, then
#                    ../oauth2-oidc-debugger. It no longer affects a test run.
#   --coverage       Hand over to ./run-coverage.sh, passing everything else on.
#   --no-report      Plain `npm test`: one process, bunyan on the terminal, no
#                    report written. The fastest loop there is. It runs the
#                    in-process suite only — starting and stopping a service is
#                    the report runner's work — so it implies --no-protocol
#                    rather than refusing, and says so as it goes.
#   --log-level=L    LOG_LEVEL for the tests (trace|debug|info|warn|error|fatal).
#   --sts-log-level=L
#                    STS_LOG_LEVEL for the service the protocol jobs drive —
#                    the container or, under --no-docker, the in-process copy;
#                    it reaches both. Unset, its appconfig file decides and
#                    that is `debug` — every request and every signed artifact
#                    written down, which is what a failing protocol job is read
#                    from, and about half of that service's CPU.
#   --timeout=MS     Per-job watchdog. Default 300000. 0 disables it.
#   --quiet          Do not echo each job's output as it runs; the logs still
#                    have all of it.
#   --open           Open the report when it has been written.
#   --verbose        set -x, for debugging this script.
#   -h|--help        This.
#
# Exit code is the suite's: non-zero if anything failed.
#
set -u -o pipefail

CURRENT_DIR="$(cd "$(dirname "$(realpath "$0")")" && pwd)"
cd "${CURRENT_DIR}" || exit 1

ONLY=""
LIST=0
PROTOCOL="on"
PROTOCOL_ASKED=0
PARENT=""
VENDOR=""
COVERAGE=0
NO_REPORT=0
LOG_LEVEL_ARG=""
STS_LOG_LEVEL_ARG=""
TIMEOUT_ARG=""
QUIET=0
BROWSER=1
OPEN=0
PASSTHROUGH=()

# ---------------------------------------------------------------------------
# THE CONTAINER. Every one of these is either a name that must not collide with
# a dev stack or a value docker-compose.yml substitutes; the header argues each.
#
# SERVICE is `docker` or `host`, and SERVICE_ASKED separates "the default" from
# "somebody asked for this" — the same distinction --no-report/--protocol
# already make below, and for the same reason: a default may fall back with a
# warning, an explicit request must fail instead.
# ---------------------------------------------------------------------------
SERVICE="docker"
SERVICE_ASKED=0
BUILD=1
KEEP_STACK=0
STS_PORT_ARG=""
COMPOSE_FILE="docker-compose.yml"
# Overridable so that two runs on one machine (a CI agent with two workspaces)
# do not share a project — compose scopes containers, networks and volumes by
# it, so two runs sharing one would tear down each other's stack.
COMPOSE_PROJECT="${STS_TEST_COMPOSE_PROJECT:-mock-sts-tests}"
STS_TEST_CONTAINER="sts-tests"
STS_TEST_PG_CONTAINER="sts-tests-postgres"
# The appconfig layer the CONTAINER reads. Deliberately not exported into this
# shell: `CONFIG_FILE` is a variable the in-process tests read too, and one
# exported here would reach every unit job as well as compose.
STS_TEST_CONFIG_FILE="${STS_TEST_CONFIG_FILE:-./env/local.js}"
# Filled in by the lifecycle below. STACK_UP gates the teardown, so that a run
# that never started a container cannot tear down somebody else's.
STACK_UP=0
STS_URL=""
STS_HOST_PORT=""
COMPOSE_CMD=""
DOCKER_SUDO=""
COMPOSE_ENV=()

# The header of this file IS the usage, printed by reading it back rather than
# by keeping a second copy of it in a here-document — which is the only way the
# two cannot drift apart.
usage()
{
  awk 'NR > 1 { if ($0 !~ /^#/) { exit } sub(/^# ?/, ""); print }' "$0"
}

while [ $# -gt 0 ];
do
  case "$1" in
    --only=*)          ONLY="${1#--only=}"; PASSTHROUGH+=("$1") ;;
    --list)            LIST=1; PASSTHROUGH+=("$1") ;;
    --protocol)        PROTOCOL="on"; PROTOCOL_ASKED=1 ;;
    --protocol-only)   PROTOCOL="only"; PROTOCOL_ASKED=1 ;;
    --no-protocol)     PROTOCOL="off" ;;
    --unit-only)       PROTOCOL="off" ;;
    --parent=*)        PARENT="${1#--parent=}" ;;
    --vendor-check)    VENDOR="check" ;;
    --vendor-sync)     VENDOR="sync" ;;
    --coverage)        COVERAGE=1 ;;
    --no-report)       NO_REPORT=1 ;;
    --log-level=*)     LOG_LEVEL_ARG="${1#--log-level=}" ;;
    --sts-log-level=*) STS_LOG_LEVEL_ARG="${1#--sts-log-level=}" ;;
    --timeout=*)       TIMEOUT_ARG="${1#--timeout=}" ;;
    --quiet)           QUIET=1 ;;
    --no-browser)      BROWSER=0 ;;
    --docker)          SERVICE="docker"; SERVICE_ASKED=1 ;;
    --no-docker)       SERVICE="host"; SERVICE_ASKED=1 ;;
    --host-service)    SERVICE="host"; SERVICE_ASKED=1 ;;
    --no-build)        BUILD=0 ;;
    --keep-stack)      KEEP_STACK=1 ;;
    --sts-port=*)      STS_PORT_ARG="${1#--sts-port=}" ;;
    --open)            OPEN=1 ;;
    --verbose)         set -x ;;
    -h|--help)         usage; exit 0 ;;
    *)
      echo "Unknown option: $1"
      usage
      exit 2
      ;;
  esac
  shift
done

# ---------------------------------------------------------------------------
# The vendor commands. They run INSTEAD of a suite and exit — they are about
# the two checkouts rather than about this service, which is the same reason
# tools/vendor-check.js is a tool and not a job in the report.
# ---------------------------------------------------------------------------
if [ -n "${VENDOR}" ];
then
  VARGS=()
  [ "${VENDOR}" = "sync" ] && VARGS+=("--sync")
  [ -n "${PARENT}" ] && VARGS+=("--parent=${PARENT}")
  node tests/tools/vendor-check.js ${VARGS[@]+"${VARGS[@]}"}
  exit $?
fi

# ---------------------------------------------------------------------------
# --coverage is a different script rather than a flag here, and that is the
# parent project's shape too (run-coverage.sh beside local-run-tests.sh). It
# collects into ./coverage and renders, which is a longer run with a different
# output; the flag exists only so that nobody has to remember two names.
# ---------------------------------------------------------------------------
if [ "${COVERAGE}" = "1" ];
then
  # COVERAGE RUNS THE SERVICE ON THIS MACHINE, NOT IN THE CONTAINER, AND IT IS
  # NOT AN OVERSIGHT. V8 writes its coverage from INSIDE the process being
  # measured, into a directory that process can write; there is no way to
  # collect it from a container this script only talks HTTP to. So a coverage
  # run uses the in-process service — which is also the right instrument for
  # the question, since what is being measured is which LINES OF THIS TREE ran.
  # Said out loud because the two runs otherwise differ in what they test and
  # nothing would say which one you got.
  if [ "${SERVICE}" = "docker" ] && [ "${PROTOCOL}" != "off" ];
  then
    echo "Coverage collects from a service started on THIS machine, not from"
    echo "the container: V8 writes its data from inside the process it"
    echo "measures. The protocol jobs will drive an in-process instance."
    echo ""
  fi
  ARGS=()
  [ -n "${ONLY}" ] && ARGS+=("--only=${ONLY}")
  ARGS+=("--protocol=${PROTOCOL}")
  [ -n "${PARENT}" ] && ARGS+=("--parent=${PARENT}")
  [ -n "${LOG_LEVEL_ARG}" ] && ARGS+=("--log-level=${LOG_LEVEL_ARG}")
  [ -n "${STS_LOG_LEVEL_ARG}" ] && ARGS+=("--sts-log-level=${STS_LOG_LEVEL_ARG}")
  [ "${QUIET}" = "1" ] && ARGS+=("--quiet")
  [ "${BROWSER}" = "0" ] && ARGS+=("--no-browser")
  [ "${OPEN}" = "1" ] && ARGS+=("--open")
  exec "${CURRENT_DIR}/run-coverage.sh" ${ARGS[@]+"${ARGS[@]}"}
fi

# ---------------------------------------------------------------------------
# THE CONTAINER'S LIFECYCLE.
#
# Six functions, and the shape is the parent project's — resolve the compose
# command once, forward the variables compose substitutes EXPLICITLY, bring the
# service up, prove it is answering before anything is run against it, collect
# its log, take it down. What is deliberately NOT copied from over there is the
# unconditional `sudo`: that stack needs it because its CI runs as a user with
# no docker group, and paying a sudo prompt on a machine where docker already
# answers is a cost for nothing.
# ---------------------------------------------------------------------------

# Which docker compose, and does it need sudo? Both answered by RUNNING the
# thing rather than by looking for a group in `id -nG`, which is neither
# necessary (a rootless daemon needs no group) nor sufficient (a group added
# since this shell logged in is not in this shell's credentials).
resolveCompose()
{
  if docker info > /dev/null 2>&1;
  then
    DOCKER_SUDO=""
  elif sudo -n docker info > /dev/null 2>&1;
  then
    # PASSWORDLESS sudo only. An interactive `sudo` here would sit waiting for
    # a password in the middle of what a person started and walked away from,
    # and would hang a CI agent outright.
    DOCKER_SUDO="yes"
  else
    return 1
  fi

  if [ -n "${DOCKER_SUDO}" ];
  then
    if sudo -n docker compose version > /dev/null 2>&1;
    then
      COMPOSE_CMD="docker compose"
      return 0
    fi
  elif docker compose version > /dev/null 2>&1;
  then
    COMPOSE_CMD="docker compose"
    return 0
  fi
  # The v1 standalone binary, still what some machines have.
  if command -v docker-compose > /dev/null 2>&1;
  then
    COMPOSE_CMD="docker-compose"
    return 0
  fi
  return 1
}

# ---------------------------------------------------------------------------
# One compose command, with the variables docker-compose.yml substitutes.
#
# THEY ARE NAMED ON THE COMMAND LINE RATHER THAN EXPORTED, and that is two
# decisions in one. `sudo` EMPTIES the environment, so an exported variable
# reaches compose as unset and the file substitutes its default with nothing
# said — which is how the parent project's stack spent months ignoring every
# tuning variable it was handed. And `CONFIG_FILE` is a variable the tests in
# this repository read too, so exporting the container's copy of it would
# change what every in-process job loads.
# ---------------------------------------------------------------------------
docker_compose()
{
  if [ -n "${DOCKER_SUDO}" ];
  then
    sudo ${COMPOSE_ENV[@]+"${COMPOSE_ENV[@]}"} ${COMPOSE_CMD} "$@"
    return $?
  fi
  env ${COMPOSE_ENV[@]+"${COMPOSE_ENV[@]}"} ${COMPOSE_CMD} "$@"
  return $?
}

# A free TCP port at or above $1, answered by BINDING it — the only question
# that matters, and the one tests/tools/service.js asks for the same reason.
# 0.0.0.0 because that is where docker publishes, so a port free only on
# loopback is not free for this.
freePort()
{
  node -e '
    var net = require("net");
    var start = Number(process.argv[1]);
    (function next(p) {
      if (p > start + 500) { process.exit(1); }
      var s = net.createServer();
      s.once("error", function () { next(p + 1); });
      s.once("listening", function () {
        s.close(function () { process.stdout.write(String(p)); });
      });
      s.listen(p, "0.0.0.0");
    })(start);
  ' "$1"
}

# The HTTP status the service gives, or 000 if the socket said nothing. node
# rather than curl, because this suite already requires node 18 and requires
# curl nowhere; `rejectUnauthorized: false` because the certificate is
# self-signed and regenerated on every start, so nothing can have an anchor for
# it — this asks whether the port answers, not whether it is trusted.
stsProbe()
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

# Write the container's own log where the run's other logs are, and say where.
# Called after the run and on every failure path: the service's account of what
# it did is what a failing protocol job is read from, and a container that is
# about to be removed takes it with it.
captureContainerLog()
{
  local dest="$1"
  if [ "${STACK_UP}" != "1" ];
  then
    return 0
  fi
  docker_compose -f "${COMPOSE_FILE}" logs --no-color sts > "${dest}" 2>&1 || true
  echo "Service log: ${dest}"
}

# ---------------------------------------------------------------------------
# Bring the service up and do not return until it ANSWERS.
#
# `up -d` reports success for a container that was created and then exited
# seconds later — which is exactly how this service fails when a port is taken
# or a module is missing from the image — so being up is asked separately from
# being answering, and neither is inferred from the other.
# ---------------------------------------------------------------------------
composeUp()
{
  STS_HOST_PORT="${STS_PORT_ARG}"
  if [ -z "${STS_HOST_PORT}" ];
  then
    STS_HOST_PORT="$(freePort 18081)"
    if [ -z "${STS_HOST_PORT}" ];
    then
      echo "No free host port could be found above 18081 for the service."
      return 1
    fi
  fi
  STS_URL="http://localhost:${STS_HOST_PORT}"

  COMPOSE_ENV=(
    "COMPOSE_PROJECT_NAME=${COMPOSE_PROJECT}"
    "STS_HOST_PORT=${STS_HOST_PORT}"
    "STS_CONTAINER_NAME=${STS_TEST_CONTAINER}"
    "STS_POSTGRES_CONTAINER_NAME=${STS_TEST_PG_CONTAINER}"
    "CONFIG_FILE=${STS_TEST_CONFIG_FILE}"
    # NOT A TUNING CHOICE — see docker-compose.yml's header. A suite that
    # persisted would be a suite whose second run started from the first run's
    # leavings.
    "STS_PERSISTENCE_MODE=memory"
  )
  # Only when it HAS a value: an empty STS_LOG_LEVEL makes bunyan throw
  # `unknown level name: ""` while this service is still loading its modules,
  # so it never listens and the run reports a service that would not answer
  # rather than a log level.
  if [ -n "${STS_LOG_LEVEL:-}" ];
  then
    COMPOSE_ENV+=("STS_LOG_LEVEL=${STS_LOG_LEVEL}")
  fi

  # A stack left behind by an interrupted run holds the container name and the
  # volumes this one is about to ask for. Removing it is safe BECAUSE of the
  # project name: this touches `mock-sts-tests` and can never reach the `sts`
  # container a `docker compose up` in this directory creates.
  docker_compose -f "${COMPOSE_FILE}" down --remove-orphans --volumes \
    > /dev/null 2>&1 || true

  if [ "${BUILD}" = "1" ];
  then
    echo "Building the mock STS image from this working tree..."
    if ! docker_compose -f "${COMPOSE_FILE}" build sts;
    then
      echo "The image would not build. Nothing was run."
      return 1
    fi
  else
    echo "NOT rebuilding the image (--no-build): the container may be running"
    echo "code OLDER than this working tree, and it will answer every request"
    echo "either way. Drop --no-build if a result surprises you."
  fi

  echo "Starting the mock STS container on ${STS_URL} (project"
  echo "${COMPOSE_PROJECT}, container ${STS_TEST_CONTAINER}, persistence off)."
  # --no-deps: the postgres service in that file is for an operator keeping a
  # mock around for a week, and this run persists nothing. --force-recreate so
  # that a container from a previous run is never reused with a new image.
  if ! docker_compose -f "${COMPOSE_FILE}" up -d --no-deps --force-recreate sts;
  then
    echo "The stack would not start."
    STACK_UP=1   # something may exist; let the teardown and the log reach it
    return 1
  fi
  STACK_UP=1

  # ---- is it answering? ---------------------------------------------------
  local deadline code
  deadline=$(( $(date +%s) + ${STS_TEST_READY_SECONDS:-180} ))
  while :;
  do
    code="$(stsProbe "${STS_URL}/healthcheck")"
    if [ "${code}" = "200" ];
    then
      echo "The mock STS is answering on ${STS_URL}."
      return 0
    fi
    if [ "$(date +%s)" -ge "${deadline}" ];
    then
      echo ""
      echo "ERROR: the mock STS container is not answering on ${STS_URL}"
      echo "       (last status: ${code:-000})."
      # The one diagnosis worth making by hand, because it reaches a test as a
      # closed socket and never names itself: in this service the scheme
      # follows the mode — oauth2.rfc9700 derives global.https — so an
      # appconfig file with RFC 9700 on serves HTTPS where this asked http.
      local other
      other="$(stsProbe "https://localhost:${STS_HOST_PORT}/healthcheck")"
      if [ "${other}" = "200" ];
      then
        echo "       SOMETHING IS ANSWERING HTTPS THERE INSTEAD. In this"
        echo "       service the scheme follows the mode: oauth2.rfc9700"
        echo "       derives global.https, so an instance in RFC 9700 mode"
        echo "       serves HTTPS on the port a permissive one serves HTTP on."
        echo "       ${STS_TEST_CONFIG_FILE} is what this container was told to read."
      fi
      return 1
    fi
    sleep 2
  done
}

# The teardown, and it is a TRAP rather than a line at the end of the script:
# an interrupted run (^C, a failing preflight, `set -e` in a future edit) would
# otherwise leave a container and a network behind, and the next run would then
# be the one that had to explain them.
stackTeardown()
{
  if [ "${STACK_UP}" != "1" ];
  then
    return 0
  fi
  if [ "${KEEP_STACK}" = "1" ];
  then
    echo ""
    echo "The stack is still up, as asked (--keep-stack):"
    echo "  service:  ${STS_URL}    console: ${STS_URL}/admin"
    echo "  logs:     ${COMPOSE_CMD} -p ${COMPOSE_PROJECT} -f ${COMPOSE_FILE} logs -f sts"
    echo "  stop it:  ${COMPOSE_CMD} -p ${COMPOSE_PROJECT} -f ${COMPOSE_FILE} down -v"
    echo "  one job:  (cd tests/vendored && WSTRUST_STS_URL=${STS_URL} \\"
    echo "             OID4VCI_ISSUER_URL=${STS_URL} MOCK_STS_DIR=${CURRENT_DIR} \\"
    echo "             CONFIG_FILE=./env/local.js node sts_metadata.js)"
    return 0
  fi
  docker_compose -f "${COMPOSE_FILE}" down --remove-orphans --volumes \
    > /dev/null 2>&1 || true
  STACK_UP=0
}
trap stackTeardown EXIT

# ---------------------------------------------------------------------------
# THE PREFLIGHT, and every check here is one that has already cost somebody an
# afternoon in this repository.
# ---------------------------------------------------------------------------
preflight()
{
  if ! command -v node > /dev/null 2>&1;
  then
    echo "node is not on the PATH. This suite runs on node 18 or newer (it"
    echo "uses the global fetch() to wait for the service under --protocol)."
    return 1
  fi
  local major
  major="$(node -p 'process.versions.node.split(".")[0]')"
  if [ "${major}" -lt 18 ];
  then
    echo "node ${major} is too old: the runner uses global fetch(), which"
    echo "arrived in node 18."
    return 1
  fi

  # node_modules. `bunyan` is an ordinary dependency and the tests require the
  # service's real modules, so there is no run without it.
  if [ ! -d "${CURRENT_DIR}/node_modules" ];
  then
    echo "node_modules is missing; running npm install once."
    echo "(.npmrc carries omit=dev on purpose — see the root CLAUDE.md: it is"
    echo "what keeps ldapjs's ~200 test packages out of this tree.)"
    npm install || return 1
  fi

  # THE NESTED SUBMODULE. This repository is itself a submodule of the parent
  # project, so node-ldapjs is one level deeper than `--init` reaches: an
  # uninitialised one is an EMPTY DIRECTORY, npm installs a package with no
  # `main`, and the failure arrives at runtime as `Cannot find module 'ldapjs'`
  # — which names a package and not a checkout. Two of this suite's files reach
  # modules that require it.
  if [ ! -f "${CURRENT_DIR}/node-ldapjs/package.json" ];
  then
    echo "node-ldapjs/ is empty — it is a git SUBMODULE and this repository is"
    echo "itself one, so it needs:"
    echo ""
    echo "    git submodule update --init --recursive"
    echo ""
    echo "(and then npm install again, since ldapjs is installed from it)."
    return 1
  fi
  if [ ! -d "${CURRENT_DIR}/node_modules/ldapjs" ];
  then
    echo "node_modules/ldapjs is missing although node-ldapjs/ is checked out;"
    echo "run npm install."
    return 1
  fi

  # THE TEST DEPENDENCIES, WHICH ARE A SECOND PACKAGE ON PURPOSE. The vendored
  # protocol jobs need `commander` and `selenium-webdriver`, and those are in
  # tests/package.json rather than the root one because .npmrc carries
  # `omit=dev` — a devDependency added at the root would be SILENTLY not
  # installed and thirteen jobs would die with a stack trace naming a package
  # instead of a command. See tests/package.json.
  #
  # Installed here rather than merely reported, because this is the one
  # preflight whose fix is a command with no decision in it. A run that is
  # missing them still FAILS the affected jobs rather than skipping them —
  # run-report.js says so before it spawns anything — so nothing is hidden if
  # this install cannot be done.
  if [ "${PROTOCOL}" != "off" ] && [ ! -d "${CURRENT_DIR}/tests/node_modules" ];
  then
    echo "tests/node_modules is missing; installing the test dependencies once."
    echo "(they are a separate package from the service's — see"
    echo " tests/package.json for the .npmrc reason.)"
    npm install --prefix "${CURRENT_DIR}/tests" || return 1
  fi
  return 0
}

preflight || exit 1

# ---------------------------------------------------------------------------
# DOCKER, OR THE OLD IN-PROCESS SERVICE?
#
# The default is the container and the fallback is loud, because the two runs
# do not test the same thing — one drives the IMAGE and one drives this
# machine's node_modules — and a run that quietly became the other one is a
# green that does not mean what the header says it means. `--docker` turns the
# fallback into an error, which is what CI should pass.
# ---------------------------------------------------------------------------
resolveServiceMode()
{
  if [ "${SERVICE}" != "docker" ];
  then
    return 0
  fi
  if resolveCompose;
  then
    return 0
  fi
  if [ "${SERVICE_ASKED}" = "1" ];
  then
    echo "--docker was asked for and there is no usable docker here."
    echo "Either the daemon is not running, or this user cannot reach it and"
    echo "sudo would need a password (this script never prompts for one)."
    echo "Drop --docker to run the service on this machine instead."
    return 1
  fi
  echo "No usable docker here, so the protocol jobs will drive a service"
  echo "started on THIS machine out of this working tree — the way they ran"
  echo "before 2026-08-28. Every job still runs; what is not covered is"
  echo "anything that is a property of the IMAGE rather than of the source."
  echo "(\`--docker\` makes this an error instead, for CI.)"
  echo ""
  SERVICE="host"
  return 0
}

# ---------------------------------------------------------------------------
# Would this run drive a service at all? Asked of the RUNNER rather than
# guessed from the flags, because `--only=crypto` matches four in-process files
# and no protocol job — and building an image for a run that has nothing to
# point it at is a minute spent on nothing. `--list` is the runner's own answer
# to exactly this question, so the two can never disagree.
# ---------------------------------------------------------------------------
needsService()
{
  local listing
  listing="$(node tests/tools/run-report.js ${LIST_ARGS[@]+"${LIST_ARGS[@]}"} \
               --list 2> /dev/null)" || return 1
  printf '%s\n' "${listing}" | grep -q '^protocol'
}

# ---------------------------------------------------------------------------
# The plain run. `npm test` is the one every contributor already knows and it
# stays exactly what it was — one process, bunyan on the terminal, under two
# seconds — so --no-report is a passthrough and not a second implementation.
# ---------------------------------------------------------------------------
if [ "${NO_REPORT}" = "1" ];
then
  # --no-report cannot run the protocol jobs: they need a service to be started
  # and stopped, which is the report runner's work. Now that those jobs are the
  # DEFAULT this can no longer be a refusal — it would refuse every bare
  # `--no-report` — so an unasked-for default is dropped with a line saying so,
  # and an EXPLICIT --protocol is still an error, because that one is somebody
  # asking for two things that cannot both happen.
  if [ "${PROTOCOL_ASKED}" = "1" ];
  then
    echo "--no-report cannot run the protocol jobs: they need a service to be"
    echo "started and stopped, which is the report runner's work. Drop one of"
    echo "the two flags."
    exit 2
  fi
  if [ "${PROTOCOL}" != "off" ];
  then
    echo "--no-report runs the in-process suite only; the protocol jobs need"
    echo "the report runner. Drop --no-report for the whole set."
  fi
  [ -n "${LOG_LEVEL_ARG}" ] && export LOG_LEVEL="${LOG_LEVEL_ARG}"
  if [ -n "${ONLY}" ];
  then
    node tests/run.js "--only=${ONLY}"
  else
    node tests/run.js
  fi
  exit $?
fi

# ---------------------------------------------------------------------------
# The reported run.
# ---------------------------------------------------------------------------
# The arguments that decide WHICH jobs run, and only those: needsService()
# hands them to the runner's own --list so that the question "is a service
# wanted" is answered by the same code that will answer "which jobs ran".
LIST_ARGS=()
[ -n "${ONLY}" ] && LIST_ARGS+=("--only=${ONLY}")
LIST_ARGS+=("--protocol=${PROTOCOL}")
[ "${BROWSER}" = "0" ] && LIST_ARGS+=("--no-browser")

ARGS=()
[ -n "${ONLY}" ] && ARGS+=("--only=${ONLY}")
[ "${LIST}" = "1" ] && ARGS+=("--list")
ARGS+=("--protocol=${PROTOCOL}")
[ -n "${PARENT}" ] && ARGS+=("--parent=${PARENT}")
[ -n "${TIMEOUT_ARG}" ] && ARGS+=("--timeout=${TIMEOUT_ARG}")
[ "${QUIET}" = "1" ] && ARGS+=("--quiet")
[ "${BROWSER}" = "0" ] && ARGS+=("--no-browser")

[ -n "${LOG_LEVEL_ARG}" ] && export LOG_LEVEL="${LOG_LEVEL_ARG}"
# EXPORTED ONLY WHEN IT HAS A VALUE, and the guard is not decoration: an EMPTY
# STS_LOG_LEVEL is not a harmless default. bunyan throws `unknown level name:
# ""` while the service is still loading its modules, so it never starts, and
# the run then reports a service that would not answer rather than a log level.
if [ -n "${STS_LOG_LEVEL_ARG}" ];
then
  export STS_LOG_LEVEL="${STS_LOG_LEVEL_ARG}"
fi

# ---------------------------------------------------------------------------
# THE SERVICE, IF THIS RUN HAS ANYTHING TO POINT AT IT.
#
# `--list` runs nothing, so it starts nothing. Everything else asks the runner
# whether a protocol job survived the filters, and only then pays for an image.
#
# In `host` mode this does nothing at all: run-report.js starts and stops its
# own throwaway process, exactly as it did before any of this existed. The two
# modes meet at one variable — STS_TEST_SERVICE_URL, which means "somebody else
# started this and somebody else will stop it".
# ---------------------------------------------------------------------------
# UNSET first, always. run-report.js reads STS_TEST_SERVICE_URL as the
# environment fallback for --service-url, so one left exported in this shell —
# by an interrupted --keep-stack run, most likely — would decide what a
# --no-docker run drove, silently and against the flag that was passed. In this
# script the flags decide; the environment fallback is for somebody calling the
# runner directly.
unset STS_TEST_SERVICE_URL

if [ "${LIST}" != "1" ] && needsService;
then
  resolveServiceMode || exit 1
  if [ "${SERVICE}" = "docker" ];
  then
    if ! composeUp;
    then
      captureContainerLog "${CURRENT_DIR}/tests/report/mock-sts-container.log"
      echo ""
      echo "Tests FAILED: the service under the protocol jobs never came up,"
      echo "so nothing was checked. This is a failure and not a skip on"
      echo "purpose — a run in which nothing ran must never read as a pass."
      exit 1
    fi
    # The one variable the two halves meet at. Exported rather than passed as
    # an argument so that ./run-coverage.sh, which builds its own argument
    # list, cannot pick it up by accident — it never exports this, and a
    # coverage run must not be handed a container it cannot measure.
    export STS_TEST_SERVICE_URL="${STS_URL}"
  fi
fi

node tests/tools/run-report.js ${ARGS[@]+"${ARGS[@]}"}
RC=$?

# The container's own account of what it did, kept beside the jobs' logs and
# named as the in-process service's log is, so a report reads the same either
# way. It has to happen HERE: the teardown below removes the container, and a
# removed container takes its log with it.
if [ "${STACK_UP}" = "1" ] && [ -d "${CURRENT_DIR}/tests/report/latest/logs" ];
then
  captureContainerLog \
    "${CURRENT_DIR}/tests/report/latest/logs/00-mock-sts-service.log"
fi

REPORT="${CURRENT_DIR}/tests/report/latest/report.html"
if [ "${LIST}" != "1" ] && [ -f "${REPORT}" ];
then
  echo ""
  echo "Report:   ${REPORT}"
  echo "Logs:     ${CURRENT_DIR}/tests/report/latest/logs/"
  echo "JUnit:    ${CURRENT_DIR}/tests/report/latest/report.xml"
  if [ "${OPEN}" = "1" ];
  then
    # Best effort and quiet: a headless machine has no opener, and failing to
    # open a report must not change the exit code of the run it describes.
    (xdg-open "${REPORT}" > /dev/null 2>&1 &) || true
  fi
fi

if [ "${RC}" -ne 0 ];
then
  echo "Tests FAILED (exit ${RC})."
else
  echo "Tests passed."
fi
exit ${RC}
