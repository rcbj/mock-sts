#!/bin/bash
#
# local-run-tests.sh — run this repository's tests, on this machine, with no
# container and (for the default run) no listener.
#
# It is this project's answer to ../id-proto-debugger/local-run-tests.sh, and it
# is a great deal shorter than that one for a reason worth knowing before
# reaching for a feature from over there: that script has to BUILD and PROVISION
# a stack — Keycloak realms, two walt.id services, a WildFly side-car, browser
# bundles, an extension — because the tests it runs drive a browser against all
# of it. The tests HERE assert this repository's own module contracts in
# process. They need `npm install` to have been run and nothing else: no port,
# no container, no browser, no network. See tests/CLAUDE.md for why that is the
# line and what belongs on the other side of it.
#
# What this adds over `npm test` is a REPORT — tests/report/<timestamp>/ with
# report.html, JUnit report.xml and one log per test file — and the ability to
# run one test, or to run the OTHER half of this service's coverage:
#
#   THE PARENT PROJECT'S PROTOCOL JOBS, AGAINST THIS WORKING TREE. Most of what
#   tests this service lives in ../id-proto-debugger/tests/ by the decision the
#   root CLAUDE.md argues, and those jobs drive a RUNNING service. Their own
#   suite drives the `sts/` gitlink over there, which is pinned — so they do not
#   normally run against what you just edited. `--protocol` starts a throwaway
#   copy of THIS tree on ports of its own, runs the jobs a lone mock can
#   satisfy against it, and stops it. Fifteen seconds, no docker.
#
# Options:
#   --only=<substr>[,<substr>...]
#                    Only the test files (and protocol jobs) whose name
#                    contains one of these. A bare word means the same.
#   --list           Name what would run, and run none of it.
#   --protocol       Run the parent project's mock-only jobs as well.
#   --no-browser     Leave out the jobs that drive a browser. One does:
#                    tests/sts_admin_console.js, which is the admin console's
#                    only coverage against this working tree — so a run with
#                    this flag says nothing about /admin. Browser jobs are run
#                    one at a time like everything else here; this runner is
#                    serial, so there is never a second Chrome open.
#   --protocol-only  Run only those.
#   --parent=<dir>   Where the parent project is. Default: the sibling
#                    ../id-proto-debugger, then ../oauth2-oidc-debugger.
#   --coverage       Hand over to ./run-coverage.sh, passing everything else on.
#   --no-report      Plain `npm test`: one process, bunyan on the terminal, no
#                    report written. The fastest loop there is.
#   --log-level=L    LOG_LEVEL for the tests (trace|debug|info|warn|error|fatal).
#   --sts-log-level=L
#                    STS_LOG_LEVEL for the throwaway service under --protocol.
#                    Unset, its appconfig file decides and that is `debug` —
#                    every request and every signed artifact written down,
#                    which is what a failing protocol job is read from, and
#                    about half of that service's CPU.
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
PROTOCOL=""
PARENT=""
COVERAGE=0
NO_REPORT=0
LOG_LEVEL_ARG=""
STS_LOG_LEVEL_ARG=""
TIMEOUT_ARG=""
QUIET=0
BROWSER=1
OPEN=0
PASSTHROUGH=()

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
    --protocol)        PROTOCOL="on" ;;
    --protocol-only)   PROTOCOL="only" ;;
    --parent=*)        PARENT="${1#--parent=}" ;;
    --coverage)        COVERAGE=1 ;;
    --no-report)       NO_REPORT=1 ;;
    --log-level=*)     LOG_LEVEL_ARG="${1#--log-level=}" ;;
    --sts-log-level=*) STS_LOG_LEVEL_ARG="${1#--sts-log-level=}" ;;
    --timeout=*)       TIMEOUT_ARG="${1#--timeout=}" ;;
    --quiet)           QUIET=1 ;;
    --no-browser)      BROWSER=0 ;;
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
# --coverage is a different script rather than a flag here, and that is the
# parent project's shape too (run-coverage.sh beside local-run-tests.sh). It
# collects into ./coverage and renders, which is a longer run with a different
# output; the flag exists only so that nobody has to remember two names.
# ---------------------------------------------------------------------------
if [ "${COVERAGE}" = "1" ];
then
  ARGS=()
  [ -n "${ONLY}" ] && ARGS+=("--only=${ONLY}")
  [ -n "${PROTOCOL}" ] && ARGS+=("--protocol=${PROTOCOL}")
  [ -n "${PARENT}" ] && ARGS+=("--parent=${PARENT}")
  [ -n "${LOG_LEVEL_ARG}" ] && ARGS+=("--log-level=${LOG_LEVEL_ARG}")
  [ -n "${STS_LOG_LEVEL_ARG}" ] && ARGS+=("--sts-log-level=${STS_LOG_LEVEL_ARG}")
  [ "${QUIET}" = "1" ] && ARGS+=("--quiet")
  [ "${BROWSER}" = "0" ] && ARGS+=("--no-browser")
  [ "${OPEN}" = "1" ] && ARGS+=("--open")
  exec "${CURRENT_DIR}/run-coverage.sh" ${ARGS[@]+"${ARGS[@]}"}
fi

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
  return 0
}

preflight || exit 1

# ---------------------------------------------------------------------------
# The plain run. `npm test` is the one every contributor already knows and it
# stays exactly what it was — one process, bunyan on the terminal, under two
# seconds — so --no-report is a passthrough and not a second implementation.
# ---------------------------------------------------------------------------
if [ "${NO_REPORT}" = "1" ];
then
  if [ -n "${PROTOCOL}" ];
  then
    echo "--no-report cannot run the protocol jobs: they need a service to be"
    echo "started and stopped, which is the report runner's work. Drop one of"
    echo "the two flags."
    exit 2
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
ARGS=()
[ -n "${ONLY}" ] && ARGS+=("--only=${ONLY}")
[ "${LIST}" = "1" ] && ARGS+=("--list")
[ -n "${PROTOCOL}" ] && ARGS+=("--protocol=${PROTOCOL}")
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

node tests/tools/run-report.js ${ARGS[@]+"${ARGS[@]}"}
RC=$?

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
