#!/bin/bash
#
# docker-run-tests.sh — the WHOLE suite, in containers, on a host that has
# nothing but docker.
#
# It builds and brings up docker-compose-run-tests.yml: the `sts` service from
# this repository's own Dockerfile, and a `tests` container with node, a Chrome
# and this working tree in it. The tests container runs
# tests/run-tests-in-container.sh — all twenty-seven jobs, the Selenium
# admin-console one included — against the service by its compose DNS name, and
# compose exits when it does. This script's exit code is that container's
# (`--exit-code-from tests`), and the stack is always torn down.
#
# THIS IS THE COMMAND CI RUNS (.github/workflows/tests.yml). It is this
# repository's answer to ../id-proto-debugger/docker-run-tests.sh, and the two
# differ in one way worth knowing before porting anything between them: that
# stack has ten services and has to PROVISION most of them — Keycloak realms, a
# WS-Federation side-car, two walt.id services, browser bundles — before a test
# can run. This one has two services and provisions nothing at all, because the
# service under test accepts any client, any entityID and any username on first
# sight. That is what it is for.
#
# ---------------------------------------------------------------------------
# WHICH LAUNCHER TO USE, AND WHY THERE ARE TWO.
#
#   ./local-run-tests.sh   the DEVELOPMENT loop. The service in a container,
#                          the tests as plain node processes on this machine,
#                          driving this machine's Chrome. Edit a test, re-run
#                          it, no image rebuild. Needs node, npm install, a
#                          Chrome and docker.
#   ./docker-run-tests.sh  THIS. Everything in containers. Needs docker and
#                          nothing else — no node, no npm install, no Chrome —
#                          which is what makes it the CI command and what makes
#                          it the thing to reach for when a run passes locally
#                          and somebody else cannot reproduce it.
#
# They run the SAME twenty-seven jobs through the same runner, so a difference
# between them is a difference in the environment and nothing else, which is
# the whole point of having both.
#
# ---------------------------------------------------------------------------
# WHAT IT WILL NOT TOUCH.
#
# `docker compose up` in this directory gives somebody a mock called `sts` on
# port 8081, quite possibly in another terminal of the same person's. This run
# is its own compose PROJECT (`mock-sts-docker-tests`), its own container names
# (`sts-docker-tests`, `mock-sts-test-runner`) and publishes NO PORT AT ALL, so
# the teardown at the end of this script can never reach that container and the
# start of it can never fail because that container holds the port. The two
# variables at the top are there for a CI agent with two workspaces, where even
# two runs of THIS script must not share a project.
#
# Usage:
#   ./docker-run-tests.sh
#   ./docker-run-tests.sh --no-build          # reuse the images already built
#   ./docker-run-tests.sh --keep-stack        # leave it up to look at
#   ./docker-run-tests.sh --only=crypto --no-browser
#                                             # anything else is passed straight
#                                             # to tests/tools/run-report.js
#   STS_LOG_LEVEL=debug ./docker-run-tests.sh # the service's full record back;
#                                             # this stack runs it at info. See
#                                             # below
#   CONFIG_FILE=./env/docker-tests.js ./docker-run-tests.sh
#                                             # or name the file, which then
#                                             # decides the level by itself
#
# Exit code is the suite's.
#
set -u -o pipefail

CURRENT_DIR="$(cd "$(dirname "$(realpath "$0")")" && pwd)"
cd "${CURRENT_DIR}" || exit 1

# resolveCompose() and docker_compose(), shared with ./local-run-tests.sh. See
# that file for why they are not duplicated and tests/tools/compose.sh for the
# globals they read.
COMPOSE_SH="${CURRENT_DIR}/tests/tools/compose.sh"
if [ ! -r "${COMPOSE_SH}" ];
then
  echo "Cannot find ${COMPOSE_SH}." >&2
  exit 1
fi
. "${COMPOSE_SH}"

COMPOSE_FILE="${COMPOSE_FILE:-docker-compose-run-tests.yml}"
# Overridable so that two runs on one machine — a CI agent with two workspaces —
# do not share a project: compose scopes containers, networks and images by it,
# so two runs sharing one would tear down each other's stack.
COMPOSE_PROJECT="${STS_DOCKER_TEST_PROJECT:-mock-sts-docker-tests}"
STS_CONTAINER_NAME="${STS_CONTAINER_NAME:-sts-docker-tests}"
STS_TESTS_CONTAINER_NAME="${STS_TESTS_CONTAINER_NAME:-mock-sts-test-runner}"
# The appconfig layer the SERVICE reads. EMPTY here and resolved after the
# arguments are parsed, by THE SERVICE'S LOG LEVEL below: which file this stack
# wants is decided by the level, because the candidates differ in nothing else.
# env/docker-tests.js exists for this stack and names it in its own header —
# env/local.js with the log level kept at debug, which is what a failing
# protocol job is read from — and env/test.js is the same file at `info`.
# Setting CONFIG_FILE in the environment pins one and that block leaves it be.
CONFIG_FILE="${CONFIG_FILE:-}"

BUILD=1
KEEP_STACK=0
STS_TEST_ARGS="${STS_TEST_ARGS:-}"
DOCKER_SUDO=""
COMPOSE_CMD=""
COMPOSE_ENV=()
STACK_UP=0

# The header of this file IS the usage, printed by reading it back rather than
# by keeping a second copy of it in a here-document — which is the only way the
# two cannot drift apart. The same trick as ./local-run-tests.sh's.
usage()
{
  awk 'NR > 1 { if ($0 !~ /^#/) { exit } sub(/^# ?/, ""); print }' "$0"
}

# ---------------------------------------------------------------------------
# ARGUMENTS. Two are this script's own and everything else is the SUITE's —
# collected into STS_TEST_ARGS, which the compose file hands to the tests
# container and its entrypoint splits. That is what keeps this launcher from
# growing a copy of run-report.js's option list, which would then be a second
# place for an option to be added and forgotten.
# ---------------------------------------------------------------------------
while [ $# -gt 0 ];
do
  case "$1" in
    --no-build)   BUILD=0 ;;
    --keep-stack) KEEP_STACK=1 ;;
    --verbose)    set -x ;;
    -h|--help)    usage; exit 0 ;;
    *)            STS_TEST_ARGS="${STS_TEST_ARGS} $1" ;;
  esac
  shift
done
STS_TEST_ARGS="${STS_TEST_ARGS# }"

# ---------------------------------------------------------------------------
# PREFLIGHT. Each of these is a failure this repository has actually had, and
# each of them would otherwise arrive minutes later naming something else.
# ---------------------------------------------------------------------------
preflight()
{
  if ! resolveCompose;
  then
    echo "No usable docker here. This launcher containerizes EVERYTHING —" >&2
    echo "the service and the tests — so there is no fallback to fall back" >&2
    echo "to: without docker there is nothing to run. Either the daemon is" >&2
    echo "not running, or this user cannot reach it and sudo would need a" >&2
    echo "password (this script never prompts for one)." >&2
    echo "" >&2
    echo "./local-run-tests.sh --no-docker runs the same jobs on this" >&2
    echo "machine, if node and a Chrome are installed." >&2
    return 1
  fi

  # THE NESTED SUBMODULE, checked here although both Dockerfiles also guard it.
  # This repository is itself a submodule of the parent project, so node-ldapjs
  # is one level deeper than `git submodule update --init` reaches, and an
  # uninitialised submodule is an EMPTY DIRECTORY: the COPY succeeds, npm
  # installs a package with no `main`, both images build, and the failure
  # arrives at container start as `Cannot find module 'ldapjs'` — a message
  # naming a package rather than a checkout. Catching it before a five-minute
  # build is worth three lines.
  if [ ! -f "${CURRENT_DIR}/node-ldapjs/package.json" ];
  then
    echo "node-ldapjs/ is empty — it is a git SUBMODULE, and this repository" >&2
    echo "is itself one, so it needs:" >&2
    echo "" >&2
    echo "    git submodule update --init --recursive" >&2
    echo "" >&2
    echo "Without it both images build and the service dies at startup with" >&2
    echo "Cannot find module 'ldapjs'." >&2
    return 1
  fi

  # The report's bind mount. Created HERE, by this user, rather than left to
  # docker: the daemon creates a missing mount point as root, and the next
  # `./local-run-tests.sh` on this machine then cannot write its own report
  # into it. It is still written by root INSIDE the container — which is why
  # the workflow chowns it before uploading — but the directory itself stays
  # the developer's.
  mkdir -p "${CURRENT_DIR}/tests/report" || return 1
  return 0
}

preflight || exit 1

# ---------------------------------------------------------------------------
# THE SERVICE'S LOG LEVEL, WHICH IS `info` ON THIS STACK, AND TAKES TWO KNOBS.
#
# THIS BLOCK ARGUED THE OPPOSITE UNTIL IT WAS CHANGED. It forwarded
# STS_LOG_LEVEL only when somebody had set it and said that quietening the
# service was "a choice a run makes rather than one that should be made for
# it". What that missed is that this stack makes the choice cost something a
# hand run does not: the mock logs every request, every response and every
# artifact both before and after signing at `debug`, which is about half of its
# CPU, and on a run that passes the whole record goes into a container that is
# removed at the end. So `info` is the default of THIS SCRIPT and of nothing
# else — no appconfig file is edited and a service started any other way is
# untouched — and `STS_LOG_LEVEL=debug ./docker-run-tests.sh` is the run that
# is being read asking for the record back.
#
# THE SECOND KNOB IS THE APPCONFIG FILE, AND WITHOUT IT THIS WOULD LOOK LIKE IT
# WORKED WHILE DOING ALMOST NOTHING. STS_LOG_LEVEL reaches the loggers
# config.js registers — its own, and the `sts` logger in helpers.js that every
# protocol module destructures. It does NOT reach the six VENDORED modules
# under common/vendored/, which each build a bunyan logger at load from
# `require(process.env.CONFIG_FILE).logLevel` and cannot be edited here. On the
# run that measured this, the level alone left 3,869 debug lines of 3,951 —
# 3,582 of them from `xmldsig`, which is every canonicalization of every signed
# document. `common/config.js`'s registerLogger() header says the same thing
# about the krb5_* codec modules.
#
# So the level picks the FILE too: trace or debug gets env/docker-tests.js and
# therefore the whole record, anything else gets env/test.js, and those two
# differ in one key and a header comment. And it goes the other way round as
# well — a CONFIG_FILE named in the environment with no level beside it turns
# this default OFF rather than being half-overridden, because naming a file
# says something more specific than a level does and a service logging at
# `info` out of a file that says `debug` is nobody's idea of an answer.
#
# The branches rather than a `:-`: an EMPTY STS_LOG_LEVEL is not a harmless
# default, because bunyan throws `unknown level name: ""` from config.js while
# the service is still loading its modules — so it never listens, and on this
# stack that arrives as a healthcheck timeout that names nothing. An exported
# empty one is therefore treated as unset.
#
# LOG_LEVEL — the SUITE's, forwarded below — gets no default because it already
# has one that is `info`: run-report.js reads it as
# `process.env.LOG_LEVEL || 'info'`, so there is nothing here to set.
# ---------------------------------------------------------------------------
STS_LEVEL="${STS_LOG_LEVEL:-}"
if [ -n "${STS_LEVEL}" ];
then
  # A level was asked for. It decides the file too, so that debug means the
  # WHOLE record rather than two thirds of it.
  if [ -z "${CONFIG_FILE}" ];
  then
    case "${STS_LEVEL}" in
      trace|debug) CONFIG_FILE="./env/docker-tests.js" ;;
      *)           CONFIG_FILE="./env/test.js" ;;
    esac
  fi
elif [ -n "${CONFIG_FILE}" ];
then
  # A FILE was named and no level was. The file decides, both halves of it, and
  # this script forwards no level of its own — otherwise pinning the debug file
  # would have produced a service logging at info out of one that says debug,
  # which is the confusing half-answer this whole block exists to avoid.
  :
else
  STS_LEVEL="info"
  CONFIG_FILE="./env/test.js"
fi

COMPOSE_ENV=(
  "COMPOSE_PROJECT_NAME=${COMPOSE_PROJECT}"
  "STS_CONTAINER_NAME=${STS_CONTAINER_NAME}"
  "STS_TESTS_CONTAINER_NAME=${STS_TESTS_CONTAINER_NAME}"
  "CONFIG_FILE=${CONFIG_FILE}"
  "STS_TEST_ARGS=${STS_TEST_ARGS}"
  # ---------------------------------------------------------------------
  # TLS ON THE MAIN PORT (2026-08-30), and the URL the runner dials with it.
  #
  # BOTH, because they are two variables in the compose file and a stack where
  # they disagree is a stack where thirteen protocol jobs fail on a closed
  # socket. The compose file defaults each to the same answer; naming them
  # here is what makes an operator's `STS_HTTPS=false ./docker-run-tests.sh`
  # actually reach compose, since `sudo` empties the environment — see
  # tests/tools/compose.sh.
  #
  # `sts` and not `localhost`: this runner publishes no port at all, and that
  # hostname is one of the certificate's SANs (common/crypto.js: localhost,
  # sts, sts-mock, sts.example.com, 127.0.0.1). A different name here would be
  # a certificate error in every job rather than a connection error in one.
  # ---------------------------------------------------------------------
  "STS_HTTPS=${STS_HTTPS:-true}"
  "STS_TEST_SERVICE_URL=$([ "${STS_HTTPS:-true}" = "true" ] && echo https || echo http)://sts:8081"
)
if [ -n "${STS_LEVEL}" ];
then
  COMPOSE_ENV+=("STS_LOG_LEVEL=${STS_LEVEL}")
fi
# The SUITE's level, forwarded only when it has one; see the block above for
# why it needs no default of its own.
if [ -n "${LOG_LEVEL:-}" ];
then
  COMPOSE_ENV+=("LOG_LEVEL=${LOG_LEVEL}")
fi

# ---------------------------------------------------------------------------
# THE SERVICE'S OWN LOG, KEPT BESIDE THE JOBS'.
#
# It has to be collected BEFORE the teardown, because a removed container takes
# its log with it — and that log is the only account of what the mock actually
# issued, which is what a failing protocol job is read from. Named `00-` so it
# sorts above the jobs in the report's logs directory, exactly as the
# in-process service's log is named by run-report.js.
# ---------------------------------------------------------------------------
captureServiceLog()
{
  if [ "${STACK_UP}" != "1" ];
  then
    return 0
  fi
  # BESIDE THE JOBS' LOGS IF THAT IS POSSIBLE, AND ONE DIRECTORY UP IF IT IS
  # NOT. The report is written from inside the tests container, which runs as
  # ROOT through the bind mount, so `tests/report/latest/logs` belongs to root
  # and this script does not. `tests/report` itself was made by the preflight
  # as the user running this, so a file can always be put there. Both cases are
  # ordinary rather than exceptional — the second is also what a run that
  # failed before writing any report at all gets, which is precisely when the
  # service's own log is the only evidence there is.
  local dest="${CURRENT_DIR}/tests/report/latest/logs/00-mock-sts-service.log"
  if ! ( [ -d "${CURRENT_DIR}/tests/report/latest/logs" ] && \
         touch "${dest}" 2> /dev/null );
  then
    dest="${CURRENT_DIR}/tests/report/mock-sts-container.log"
  fi
  docker_compose -f "${COMPOSE_FILE}" logs --no-color sts > "${dest}" 2>&1 || true
  echo "Service log: ${dest}"
}

# Always tear the stack down, even when the tests fail, so the next run starts
# clean. A TRAP rather than a line at the end: an interrupted run (^C, a failing
# step) would otherwise leave two containers and a network behind, and the next
# run would be the one that had to explain them.
teardown()
{
  if [ "${KEEP_STACK}" = "1" ] && [ "${STACK_UP}" = "1" ];
  then
    echo ""
    echo "The stack is still up, as asked (--keep-stack):"
    echo "  logs:    ${COMPOSE_CMD} -p ${COMPOSE_PROJECT} -f ${COMPOSE_FILE} logs -f sts"
    echo "  a shell: ${COMPOSE_CMD} -p ${COMPOSE_PROJECT} -f ${COMPOSE_FILE} exec sts bash"
    echo "  the port is NOT published — to reach the console, add"
    echo "           --service-ports to a \`run\` of the sts service."
    echo "  stop it: ${COMPOSE_CMD} -p ${COMPOSE_PROJECT} -f ${COMPOSE_FILE} down -v"
    return 0
  fi
  docker_compose -f "${COMPOSE_FILE}" down --remove-orphans --volumes \
    > /dev/null 2>&1 || true
}
trap teardown EXIT

# A stack left behind by an interrupted run holds the container names this one
# is about to ask for. Removing it is safe BECAUSE of the project name: this
# reaches `mock-sts-docker-tests` and can never reach the `sts` container a
# plain `docker compose up` in this directory creates.
docker_compose -f "${COMPOSE_FILE}" down --remove-orphans --volumes \
  > /dev/null 2>&1 || true

# ---------------------------------------------------------------------------
# BUILD, THEN RUN.
#
# The build is a step of its own rather than `up --build` so that an image that
# will not build says so as itself: with `--abort-on-container-exit` a failed
# build inside `up` is reported as the stack coming down, and the reason
# scrolls past above it. Both images are rebuilt every run, because the whole
# point is to test what is in the working tree and an image is a snapshot of
# when it was built.
# ---------------------------------------------------------------------------
if [ "${BUILD}" = "1" ];
then
  echo "Building the service and test images from this working tree..."
  if ! docker_compose -f "${COMPOSE_FILE}" build;
  then
    echo "" >&2
    echo "The images would not build. Nothing was run." >&2
    exit 1
  fi
else
  echo "NOT rebuilding (--no-build): the images may be OLDER than this working"
  echo "tree, and they will answer every request either way. Drop --no-build if"
  echo "a result surprises you."
fi

echo "Bringing up ${COMPOSE_PROJECT}: the mock STS and the test runner."
if [ -n "${STS_TEST_ARGS}" ];
then
  echo "Passing to the suite: ${STS_TEST_ARGS}"
fi

# --abort-on-container-exit stops the stack as soon as the tests container
# finishes; --exit-code-from tests makes compose — and therefore this script —
# exit with ITS status rather than with the service's, which is always 0 or 137
# and says nothing about the suite.
STACK_UP=1
docker_compose -f "${COMPOSE_FILE}" up \
  --abort-on-container-exit --exit-code-from tests
RC=$?

captureServiceLog

REPORT="${CURRENT_DIR}/tests/report/latest/report.html"
if [ -f "${REPORT}" ];
then
  echo ""
  echo "Report:   ${REPORT}"
  echo "Logs:     ${CURRENT_DIR}/tests/report/latest/logs/"
  echo "JUnit:    ${CURRENT_DIR}/tests/report/latest/report.xml"
  # Said once, plainly, because the first thing anybody does with a report is
  # try to delete the old ones. It is written from inside the container, which
  # is root; the workflow chowns it before uploading and a person can too:
  #   sudo chown -R "$(id -u):$(id -g)" tests/report
fi

if [ "${RC}" -ne 0 ];
then
  echo "Tests FAILED (exit ${RC})."
  exit "${RC}"
fi

cat <<'EOF'
   _   _ _   _            _                                  _
  / \ | | | | |_ ___  ___| |_ ___   _ __   __ _ ___ ___  ___| |
 / _ \| | | | __/ _ \/ __| __/ __| | '_ \ / _` / __/ __|/ _ \ |
/ ___ \ | | | ||  __/\__ \ |_\__ \ | |_) | (_| \__ \__ \  __/_|
/_/   \_\_|_|  \__\___||___/\__|___/ | .__/ \__,_|___/___/\___(_)
                                     |_|
EOF

exit 0
