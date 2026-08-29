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
# differs from that one in two ways that are worth knowing:
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
#     protocol  — a throwaway copy of THIS WORKING TREE, driven by the parent
#                 project's mock-only jobs over HTTP. This is where the
#                 sixteen protocol families are actually exercised, and it is
#                 off unless --protocol is passed, because it needs the parent
#                 checkout beside this one.
#   The report has a column per domain, so "which half of the run reached this
#   file" is answerable — which is the question somebody deciding what to test
#   next actually has.
#
# Options: the same as ./local-run-tests.sh, which is what usually calls this.
#   --only=<substr>[,...]  --protocol[=on|only]  --parent=<dir>
#   --log-level=L  --sts-log-level=L  --quiet  --open  --verbose  -h|--help
#
set -u -o pipefail

CURRENT_DIR="$(cd "$(dirname "$(realpath "$0")")" && pwd)"
cd "${CURRENT_DIR}" || exit 1

ONLY=""
PROTOCOL=""
PARENT=""
LOG_LEVEL_ARG=""
STS_LOG_LEVEL_ARG=""
QUIET=0
OPEN=0

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
    --parent=*)        PARENT="${1#--parent=}" ;;
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

if [ ! -d "${CURRENT_DIR}/node_modules" ];
then
  echo "node_modules is missing. Run ./local-run-tests.sh once, or npm install."
  exit 1
fi

export COVERAGE=true
export COVERAGE_DIR="${COVERAGE_DIR:-${CURRENT_DIR}/coverage}"

# ---------------------------------------------------------------------------
# THE SERVICE'S LOG LEVEL UNDER --protocol, and why this run wants it lower
# than the suite does.
#
# `STS_LOG_LEVEL` is a setting of this service (common/config.js) and an
# environment variable OUTRANKS whatever appconfig file CONFIG_FILE selects, so
# this one name turns the level down without either file being edited. Its
# default is `debug` — every request, every response and every artifact both
# before and after signing — which is the point of a mock and is what a failing
# job is read from.
#
# Under coverage it is also pure cost twice over: it is about half of this
# service's CPU, and every one of those lines goes through the same log calls
# whose coverage this run is measuring, so turning it down changes the numbers
# hardly at all while making the run visibly quicker. `error` is the default
# HERE and nowhere else; --sts-log-level=debug puts it back for a run where the
# service's own account of what it did is the thing being read.
# ---------------------------------------------------------------------------
if [ -n "${STS_LOG_LEVEL_ARG}" ];
then
  export STS_LOG_LEVEL="${STS_LOG_LEVEL_ARG}"
elif [ -z "${STS_LOG_LEVEL:-}" ];
then
  export STS_LOG_LEVEL="error"
fi

[ -n "${LOG_LEVEL_ARG}" ] && export LOG_LEVEL="${LOG_LEVEL_ARG}"

ARGS=()
[ -n "${ONLY}" ] && ARGS+=("--only=${ONLY}")
[ -n "${PROTOCOL}" ] && ARGS+=("--protocol=${PROTOCOL}")
[ -n "${PARENT}" ] && ARGS+=("--parent=${PARENT}")
[ "${QUIET}" = "1" ] && ARGS+=("--quiet")

if [ -z "${PROTOCOL}" ];
then
  echo "Collecting coverage from the in-process suite only."
  echo "The sixteen protocol families are reached by --protocol, which drives"
  echo "the parent project's jobs against a throwaway copy of this tree."
  echo ""
fi

# The runner collects into ${COVERAGE_DIR}/raw and renders when the last job is
# done — the render has to happen after the throwaway service has EXITED, since
# that is when V8 writes what it collected, so it is not a separate step here.
node tests/tools/run-report.js ${ARGS[@]+"${ARGS[@]}"}
RC=$?

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
