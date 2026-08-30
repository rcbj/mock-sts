#!/bin/bash
#
# run-coverage.sh — run the suite with code-coverage collection enabled and
# render the report.
#
# Output (gitignored):
#   ./coverage/index.html       every file, with a page per file showing which
#                               lines ran and how often
#   ./coverage/lcov.info        the same thing in the standard format
#   ./coverage/summary.json     the totals
#   ./coverage/raw/             V8's own JSON, kept so that anybody who would
#                               rather point c8 or another renderer at it can
#
# It is this project's answer to ../id-proto-debugger/run-coverage.sh, and it
# differs from that one in three ways that are worth knowing:
#
#   IT NEEDS NOTHING INSTALLED. That script collects three domains — the
#   browser bundles through Istanbul, the api process through c8, the
#   in-container node jobs through NODE_V8_COVERAGE — and renders two of them
#   with c8 and nyc, which are devDependencies of the images that run them.
#   This repository carries `omit=dev` in .npmrc and passes `--omit=dev` in its
#   Dockerfile (see the root CLAUDE.md — it is what keeps ldapjs's ~200 test
#   packages out), so a devDependency added for coverage would be silently NOT
#   installed and this script would fail for everybody. So the collection is
#   node's own NODE_V8_COVERAGE and the renderer is tests/tools/coverage-report.js,
#   which is written against V8's data directly: no install, works offline.
#
#   THERE ARE TWO DOMAINS HERE AND THEY ARE VERY DIFFERENT SIZES.
#     unit      — the in-process suite in tests/. Deep coverage of a few
#                 modules: the realm layer, the LDIF codec, the two map
#                 renderers, the crypto module.
#     protocol  — a throwaway copy of THIS WORKING TREE (of the tests IMAGE
#                 built from it, in a containerized run — which is the same
#                 tree one `COPY . ./` later), driven over HTTP by
#                 the thirteen jobs in tests/vendored/ (nine vendored from the
#                 parent, four this repository's own). This is where
#                 the sixteen protocol families are actually exercised, and it
#                 is ON BY DEFAULT since 2026-08-28. It used to need
#                 --protocol, on the argument that it wanted the parent
#                 checkout beside this one — an argument that expired the same
#                 day, when those jobs were vendored and stopped needing one.
#                 A coverage report whose default omitted the half where the
#                 protocols actually run is a report that gets read wrongly.
#                 --no-protocol is the way back.
#   The report has a column per domain, so "which half of the run reached this
#   file" is answerable — which is the question somebody deciding what to test
#   next actually has.
#
#   IT RUNS IN A CONTAINER, AND THE THING IN THE CONTAINER IS THE WHOLE RUN
#   RATHER THAN THE SERVICE. This is the one place where the arrangement the
#   other two launchers use cannot be copied, and the reason is physics rather
#   than preference: V8 writes coverage from INSIDE the process being measured,
#   into a directory that process can write, so a runner that only speaks HTTP
#   to a service container learns NOTHING about which of its lines ran. That is
#   why ./local-run-tests.sh --coverage cannot simply point at
#   docker-compose.yml's `sts`, and this script's header said for one day that
#   coverage therefore could not be containerized at all.
#
#   IT CAN. What moves into the container is not the service but the RUNNER: a
#   `docker compose run` on docker-compose-run-tests.yml's `tests` service —
#   the image that already carries node, a Chrome, both node_modules trees and
#   this whole tree — executing run-report.js with COVERAGE=true and NO
#   --service-url, so the throwaway service it starts is a child process inside
#   that same container. Everything V8 writes is written by processes this run
#   started, exactly as it was on the host; `--no-deps` means the `sts`
#   container is never started, because measuring it is the thing that cannot
#   work. ./coverage and ./tests/report are bind mounts, so both come out onto
#   the host.
#
#   WHAT THAT BUYS is the property ./docker-run-tests.sh has: the host needs
#   DOCKER AND NOTHING ELSE — no node, no `npm install`, no Chrome — which is
#   what lets .github/workflows/tests.yml run a coverage pass beside the suite.
#   What it COSTS is an image build and root-owned output; both are named
#   below.
#
#   --no-docker IS THE HOST RUN AND IS UNCHANGED — node processes on this
#   machine, the fast loop when the thing being iterated on is a test. A machine
#   with no docker falls back to it LOUDLY rather than silently, and --docker
#   turns that fallback into an error.
#
# Options: the same as ./local-run-tests.sh, which is what usually calls this,
# plus the three this script's own container needs.
#   --only=<substr>[,...]  --protocol[=on|off|only]  --no-protocol / --unit-only
#   --parent=<dir>
#   --docker / --no-docker  where the run happens. Default: docker, with a loud
#                           fallback to the host when there is none.
#   --no-build              reuse the tests image already built. It may be older
#                           than this working tree, which is the whole point of
#                           rebuilding by default. If there is no such image at
#                           all, compose builds one anyway — this skips the
#                           rebuild, it cannot run without an image.
#   --log-level=L  --sts-log-level=L  --quiet  --open  --verbose  -h|--help
#
set -u -o pipefail

CURRENT_DIR="$(cd "$(dirname "$(realpath "$0")")" && pwd)"
cd "${CURRENT_DIR}" || exit 1

ONLY=""
PROTOCOL="on"
PARENT=""
LOG_LEVEL_ARG=""
STS_LOG_LEVEL_ARG=""
QUIET=0
OPEN=0

# WHERE THE RUN HAPPENS, and WHERE_ASKED separates "the default" from "somebody
# asked for this" — the same distinction ./local-run-tests.sh's SERVICE_ASKED
# makes, and for the same reason: a default may fall back with a warning, an
# explicit request must fail instead.
WHERE="docker"
WHERE_ASKED=0
BUILD=1
# Its OWN compose project, so that a coverage run and a ./docker-run-tests.sh
# run on one machine cannot tear down or reuse each other's containers. The
# images are named in the compose file (`image:`), so the two still share a
# build rather than each keeping one.
COMPOSE_FILE="docker-compose-run-tests.yml"
COMPOSE_PROJECT="${STS_COVERAGE_PROJECT:-mock-sts-coverage}"
COMPOSE_CMD=""
DOCKER_SUDO=""
COMPOSE_ENV=()

usage()
{
  awk 'NR > 1 { if ($0 !~ /^#/) { exit } sub(/^# ?/, ""); print }' "$0"
}

while [ $# -gt 0 ];
do
  case "$1" in
    --only=*)          ONLY="${1#--only=}" ;;
    --protocol)        PROTOCOL="on" ;;
    --protocol=*)      PROTOCOL="${1#--protocol=}" ;;
    --protocol-only)   PROTOCOL="only" ;;
    --no-protocol)     PROTOCOL="off" ;;
    --unit-only)       PROTOCOL="off" ;;
    --parent=*)        PARENT="${1#--parent=}" ;;
    --docker)          WHERE="docker"; WHERE_ASKED=1 ;;
    --no-docker)       WHERE="host";   WHERE_ASKED=1 ;;
    --host)            WHERE="host";   WHERE_ASKED=1 ;;
    --no-build)        BUILD=0 ;;
    --log-level=*)     LOG_LEVEL_ARG="${1#--log-level=}" ;;
    --sts-log-level=*) STS_LOG_LEVEL_ARG="${1#--sts-log-level=}" ;;
    --quiet)           QUIET=1 ;;
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

# resolveCompose() and docker_compose(), shared with the other two launchers.
# See tests/tools/compose.sh for the globals they read; it is sourced even for a
# host run, because nothing in it runs at source time.
COMPOSE_SH="${CURRENT_DIR}/tests/tools/compose.sh"
if [ ! -r "${COMPOSE_SH}" ];
then
  echo "Cannot find ${COMPOSE_SH}." >&2
  exit 1
fi
. "${COMPOSE_SH}"

# ---------------------------------------------------------------------------
# WHICH RUN THIS IS, DECIDED ONCE.
#
# A machine with no docker falls back to the host run and SAYS SO — the two
# collect the same data from the same code, so the fallback is honest rather
# than a quiet substitution of one thing for another. --docker refuses instead,
# because a run that asked for the container and got the host would be a green
# that does not mean what it says.
# ---------------------------------------------------------------------------
if [ "${WHERE}" = "docker" ] && ! resolveCompose;
then
  if [ "${WHERE_ASKED}" = "1" ];
  then
    echo "--docker was asked for and there is no docker compose on this machine." >&2
    exit 1
  fi
  echo "No docker compose here — collecting coverage on this machine instead."
  echo "(That is ./run-coverage.sh --no-docker, and it measures the same code.)"
  echo ""
  WHERE="host"
fi

if [ "${WHERE}" = "host" ] && [ ! -d "${CURRENT_DIR}/node_modules" ];
then
  echo "node_modules is missing. Run ./local-run-tests.sh once, or npm install."
  echo "(A containerized run needs neither: ./run-coverage.sh --docker.)"
  exit 1
fi

export COVERAGE=true
export COVERAGE_DIR="${COVERAGE_DIR:-${CURRENT_DIR}/coverage}"

# CREATED HERE, BEFORE ANY MOUNT. Docker creates a missing bind-mount source
# itself and creates it owned by ROOT, so the next host run of this script
# would fail to write into its own output directory — and the message would be
# about a permission on a path rather than about a container that ran days ago.
mkdir -p "${COVERAGE_DIR}" "${CURRENT_DIR}/tests/report"

# UNSET rather than merely not set: run-report.js reads STS_TEST_SERVICE_URL as
# the environment fallback for --service-url, so one left exported in somebody's
# shell (by an interrupted --keep-stack run, say) would point this run at a
# CONTAINER — and the protocol half of the coverage would come out empty, which
# reads as "the protocols are untested" rather than as "this run could not
# look". The runner warns when it happens; this makes it not happen.
unset STS_TEST_SERVICE_URL

# ---------------------------------------------------------------------------
# THE SERVICE'S LOG LEVEL UNDER --protocol, and why this run wants it lower
# than the service's own default.
#
# `STS_LOG_LEVEL` is a setting of this service (common/config.js) and an
# environment variable OUTRANKS whatever appconfig file CONFIG_FILE selects, so
# this one name turns the level down without either file being edited. The
# service's own default is `debug` — every request, every response and every
# artifact both before and after signing — which is the point of a mock and is
# what a failing job is read from.
#
# Under coverage it is also pure cost twice over: it is about half of this
# service's CPU, and every one of those lines goes through the same log calls
# whose coverage this run is measuring, so turning it down changes the numbers
# hardly at all while making the run visibly quicker.
#
# `info` IS THE DEFAULT HERE, AND IT WAS `error` UNTIL IT WAS CHANGED. That
# made this the one launcher of the three whose service said less than the
# other two — a coverage run that failed showed less about why than the run
# somebody would repeat it with. The three agree at `info` now, which is also
# what the suite's own LOG_LEVEL defaults to in run-report.js, and
# --sts-log-level=debug still puts the whole record back for a run where the
# service's own account of what it did is the thing being read.
#
# THE APPCONFIG FILE IS THE OTHER HALF OF THE LEVEL and this block cannot set
# it: run-report.js starts the service in process here, and the six VENDORED
# modules under common/vendored/ each build a bunyan logger at load from
# `require(process.env.CONFIG_FILE).logLevel`, never seeing STS_LOG_LEVEL. So
# the file is chosen the same way ./local-run-tests.sh chooses it, and by the
# same rule — the level picks it, a STS_TEST_CONFIG_FILE named in the
# environment wins, and trace or debug asks for the whole record and gets the
# `debug` file with it.
# ---------------------------------------------------------------------------
STS_TEST_CONFIG_FILE="${STS_TEST_CONFIG_FILE:-}"
[ -n "${STS_LOG_LEVEL_ARG}" ] && STS_LOG_LEVEL="${STS_LOG_LEVEL_ARG}"
if [ -n "${STS_LOG_LEVEL:-}" ];
then
  export STS_LOG_LEVEL
  if [ -z "${STS_TEST_CONFIG_FILE}" ];
  then
    case "${STS_LOG_LEVEL}" in
      trace|debug) STS_TEST_CONFIG_FILE="./env/local.js" ;;
      *)           STS_TEST_CONFIG_FILE="./env/test.js" ;;
    esac
  fi
elif [ -n "${STS_TEST_CONFIG_FILE}" ];
then
  # A FILE was named and no level was: it decides both halves, and this script
  # exports no level of its own. ./local-run-tests.sh does the same, and the
  # reason is there — a service logging at `info` out of a file that says
  # `debug` is nobody's idea of an answer.
  :
else
  export STS_LOG_LEVEL="info"
  STS_TEST_CONFIG_FILE="./env/test.js"
fi
export STS_TEST_CONFIG_FILE

[ -n "${LOG_LEVEL_ARG}" ] && export LOG_LEVEL="${LOG_LEVEL_ARG}"

ARGS=()
[ -n "${ONLY}" ] && ARGS+=("--only=${ONLY}")
[ -n "${PROTOCOL}" ] && ARGS+=("--protocol=${PROTOCOL}")
[ -n "${PARENT}" ] && ARGS+=("--parent=${PARENT}")
[ "${QUIET}" = "1" ] && ARGS+=("--quiet")

# ---------------------------------------------------------------------------
# A LONGER PER-JOB WATCHDOG, BECAUSE INSTRUMENTATION IS WHY THIS RUN IS SLOW.
#
# run-report.js defaults to 300000ms, and that is the right number for the
# PLAIN suite: it is far above the slowest real job and it catches one that has
# genuinely hung. This run is the same jobs under V8 coverage collection on
# whatever CI gives us — two cores on a GitHub runner — where every one of them
# takes several times longer for a reason that is not a hang.
#
# `sts_userinfo_protected` is the job that made this necessary and it is worth
# naming. It asks the service for a signed UserInfo response for EVERY
# algorithm the metadata advertises, and two of those are SLH-DSA: about two
# seconds for the SHA-2 parameter set and twelve for the SHAKE one, of
# straight-line CPU, per signature. The worker pool moved that cost off the
# service's event loop — which is what stopped it failing OTHER jobs — but it
# did not make it smaller, and it cannot: that is the algorithm. Instrumented,
# on two cores, the job went past 300000ms and was killed, and a job that is
# killed asserts nothing.
#
# The caller's own --timeout wins, so a run that wants the short watchdog back
# can still ask for it.
# ---------------------------------------------------------------------------
case " ${ARGS[*]-} ${STS_COVERAGE_EXTRA_ARGS-} " in
  *--timeout=*) ;;
  *) ARGS+=("--timeout=${STS_COVERAGE_JOB_TIMEOUT_MS:-900000}") ;;
esac

# The check is against "off" and not against an empty string, because the
# default is "on" now: an unset PROTOCOL is no longer how somebody says they
# want half a report.
if [ "${PROTOCOL}" = "off" ];
then
  echo "Collecting coverage from the in-process suite only, because"
  echo "--no-protocol was passed. The sixteen protocol families are NOT"
  echo "reached by this run, so every number below is about ten files' worth"
  echo "of module contracts and not about this service."
  echo ""
fi

# ---------------------------------------------------------------------------
# THE RUN. Both branches drive the SAME command — run-report.js with
# COVERAGE=true and no --service-url — and differ only in where it runs.
#
# The runner collects into ${COVERAGE_DIR}/raw and renders when the last job is
# done. The render has to happen after the throwaway service has EXITED, since
# that is when V8 writes what it collected, so it is not a separate step here
# and cannot be one in the container either.
# ---------------------------------------------------------------------------
if [ "${WHERE}" = "host" ];
then
  node tests/tools/run-report.js ${ARGS[@]+"${ARGS[@]}"}
  RC=$?
else
  # The compose file substitutes these; they are named on the command line
  # rather than exported for the reason tests/tools/compose.sh's header gives.
  # STS_TEST_ARGS is EMPTY on purpose: this run passes its arguments to
  # run-report.js directly below, and a leftover value in somebody's shell
  # would otherwise be spliced in front of them by the image's entrypoint —
  # which this run does not use anyway, but the variable is substituted before
  # anything decides that.
  COMPOSE_ENV=(
    "COMPOSE_PROJECT_NAME=${COMPOSE_PROJECT}"
    "STS_TESTS_CONTAINER_NAME=mock-sts-coverage-runner"
    "STS_CONTAINER_NAME=sts-coverage-unused"
    "CONFIG_FILE=${STS_TEST_CONFIG_FILE}"
    "STS_TEST_ARGS="
  )

  if [ "${BUILD}" = "1" ];
  then
    echo "Building the tests image from this working tree..."
    if ! docker_compose -f "${COMPOSE_FILE}" build tests;
    then
      echo "The tests image would not build; nothing was measured." >&2
      exit 1
    fi
  else
    echo "--no-build: using the tests image as it already is, which may be"
    echo "older than this working tree — and a coverage report of code that is"
    echo "not the code in front of you is worse than none."
  fi

  # -----------------------------------------------------------------------
  # WHY `run --no-deps` AND NOT `up`.
  #
  # --no-deps leaves the `sts` service alone: this run measures a service it
  # starts ITSELF, in this container, because V8 writes coverage from inside
  # the process being measured and a container spoken to over HTTP is a
  # process this run did not start. Starting it as well would cost an image
  # build and a healthcheck to produce a service nothing in this run talks to.
  #
  # STS_TEST_SERVICE_URL is emptied for exactly that reason — the compose file
  # AND the image both set it to https://sts:8081, and run-report.js reads it as
  # the environment fallback for --service-url. Left alone, this run would
  # drive a container that --no-deps never started, and the protocol half of
  # the report would come out empty: "the protocols are untested" rather than
  # "this run could not look". It is the same trap the host branch avoids with
  # `unset` above, arriving by a different route.
  #
  # The volume is named here rather than in the compose file so that an
  # ordinary ./docker-run-tests.sh run — which shares that file — never mounts
  # a coverage directory it does not write.
  # -----------------------------------------------------------------------
  # STS_LOG_LEVEL IS ADDED ONLY WHEN IT HAS A VALUE, and `-e NAME=` is not a
  # harmless way to say "unset": it sets the variable to the EMPTY STRING in
  # the container, bunyan throws `unknown level name: ""` while the service is
  # still loading its modules, and the run reports a service that would not
  # start rather than a log level. That is the one case this script leaves it
  # unset — a CONFIG_FILE named with no level beside it, where the file
  # decides.
  RUN_ENV=(
    -e COVERAGE=true
    -e COVERAGE_DIR=/usr/src/sts/coverage
    # EMPTY ON PURPOSE, and the opposite of the case above: run-report.js reads
    # this as `process.env.STS_TEST_SERVICE_URL || ''`, so empty is how this
    # run says "start your own service" over the compose file's and the image's
    # own https://sts:8081.
    -e STS_TEST_SERVICE_URL=
    -e "STS_TEST_CONFIG_FILE=${STS_TEST_CONFIG_FILE}"
    -e "LOG_LEVEL=${LOG_LEVEL:-info}"
  )
  if [ -n "${STS_LOG_LEVEL:-}" ];
  then
    RUN_ENV+=(-e "STS_LOG_LEVEL=${STS_LOG_LEVEL}")
  fi
  # TLS ON THE SERVICE THIS RUN STARTS FOR ITSELF, forwarded ONLY when the
  # operator asked for something. tests/tools/service.js defaults it to `true`
  # exactly as every appconfig file and both compose files do, so an ordinary
  # coverage run needs nothing here; `-e STS_HTTPS=` would set it to the EMPTY
  # STRING, which is neither `true` nor an absent variable and would quietly
  # produce a plain-HTTP service under a report that says nothing about it.
  if [ -n "${STS_HTTPS:-}" ];
  then
    RUN_ENV+=(-e "STS_HTTPS=${STS_HTTPS}")
  fi

  docker_compose -f "${COMPOSE_FILE}" run --rm --no-deps \
    -v "${COVERAGE_DIR}:/usr/src/sts/coverage" \
    "${RUN_ENV[@]}" \
    tests node tests/tools/run-report.js ${ARGS[@]+"${ARGS[@]}"}
  RC=$?

  # -----------------------------------------------------------------------
  # HAND THE OUTPUT BACK, AND DO IT WITH DOCKER RATHER THAN WITH sudo.
  #
  # The container runs as root, so everything it wrote through the two bind
  # mounts is root-owned on this machine. That is not a tidiness problem: the
  # NEXT HOST RUN of this script dies in run-report.js clearing
  # coverage/raw/protocol with `EACCES: permission denied, rmdir` — a message
  # about a path, from a run that has nothing to do with the container run that
  # caused it days earlier. This was found by doing exactly that.
  #
  # A second throwaway container does the chown, because it is already root
  # inside and this script is not: `sudo` here would prompt in the middle of
  # something somebody walked away from, and passwordless sudo is not
  # something to require for a coverage run. It costs about a second.
  #
  # || true, and the notice below, because a machine where this fails must say
  # what to do rather than fail a run whose tests passed.
  # -----------------------------------------------------------------------
  # THE SAME -v AS THE RUN ABOVE, and leaving it off is the mistake this
  # comment exists to prevent: without the mount, `chown` cheerfully succeeds
  # against the image's OWN empty /usr/src/sts/coverage and the host directory
  # stays root-owned, with nothing said.
  docker_compose -f "${COMPOSE_FILE}" run --rm --no-deps \
    -v "${COVERAGE_DIR}:/usr/src/sts/coverage" \
    --entrypoint chown tests -R "$(id -u):$(id -g)" \
    /usr/src/sts/coverage /usr/src/sts/tests/report > /dev/null 2>&1 || true

  # The network `run` created, and nothing else — this project has its own
  # name, so `down` here can never reach the stack ./docker-run-tests.sh or a
  # `docker compose up` in this directory is holding.
  docker_compose -f "${COMPOSE_FILE}" down --remove-orphans > /dev/null 2>&1 || true

  if [ -n "$(find "${COVERAGE_DIR}" -user root -print -quit 2>/dev/null)" ];
  then
    echo ""
    echo "Some of ./coverage is still owned by root — the chown-back container"
    echo "did not run. To read or delete it as yourself:"
    echo "    sudo chown -R \"$(id -u):$(id -g)\" coverage tests/report"
  fi
fi

echo ""
if [ -f "${COVERAGE_DIR}/index.html" ];
then
  echo "Coverage:  ${COVERAGE_DIR}/index.html"
  echo "LCOV:      ${COVERAGE_DIR}/lcov.info"
  echo "Raw V8:    ${COVERAGE_DIR}/raw/"
  if [ -f "${COVERAGE_DIR}/summary.json" ];
  then
    node -e '
      const s = require(process.argv[1]);
      console.log("           " + s.linesPct + "% of lines in the " + s.files +
                  " files loaded, " + s.functionsPct + "% of functions; " +
                  s.neverLoaded + " file(s) loaded by nothing.");
    ' "${COVERAGE_DIR}/summary.json"
  fi
  if [ "${OPEN}" = "1" ];
  then
    # Best effort: a headless machine has no opener, and failing to open the
    # report must not change the exit code of the run it describes.
    (xdg-open "${COVERAGE_DIR}/index.html" > /dev/null 2>&1 &) || true
  fi
else
  echo "No coverage report was written; see the run output above."
fi
echo "Report:    ${CURRENT_DIR}/tests/report/latest/report.html"

# Propagate the suite result: a coverage run that passed is still a test run
# that passed, and a failing one must not go green because the picture rendered.
if [ "${RC}" -ne 0 ];
then
  echo "Test suite FAILED (exit ${RC})."
else
  echo "Test suite passed."
fi
exit ${RC}
