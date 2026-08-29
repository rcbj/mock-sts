'use strict';
//
// File: tests/tools/coverage_entry.js
//
// ===========================================================================
// SERVER.JS, STARTED SO THAT ITS COVERAGE SURVIVES BEING STOPPED.
//
// `NODE_V8_COVERAGE=<dir> node server.js` collects nothing useful for a
// SERVICE, and the reason is easy to miss: V8 writes what it collected when
// the process exits CLEANLY, and a service is stopped with a signal. The
// default disposition of SIGTERM terminates the process without running any
// exit hook, so the directory stays empty — no error, no warning, just a
// coverage report with the whole protocol half missing. This repository has
// met the same shape of problem before with `node --cpu-prof`, which writes
// its profile on a clean exit only and leaves `--cpu-prof-dir` empty after any
// signal (see the benchmark notes in the memory of that work).
//
// So the run starts THIS instead: it installs a handler that asks V8 for the
// coverage explicitly (`v8.takeCoverage()`, node 14.8+) and only then exits,
// and requires server.js so that everything else about the process — the
// module graph, the require ORDER that is also the route order, the nine
// listeners — is byte for byte what a plain start does.
//
// It is in `tools/` rather than beside the tests for the reason that directory
// exists: `tests/run.js` discovers every `.js` file next to it as a test, and
// this one exports no `run()`.
//
// A FORCED EXIT IS DELIBERATE. Four listener families keep the event loop
// alive, so returning from the handler would hang; and `process.exit(0)` after
// `takeCoverage()` has already written the file loses nothing.
// ===========================================================================

const v8 = require('v8');
const path = require('path');

let stopping = false;

// Longer than ten lines, so it says so at both ends like everything else here.
function flushAndExit(signal) {
  if (stopping) {
    return;
  }
  stopping = true;
  process.stdout.write('coverage_entry: ' + signal +
                       ' — writing V8 coverage before exit.\n');
  try {
    v8.takeCoverage();
  } catch (e) {
    // Not fatal to the RUN: the tests have already been driven and their
    // results are the report's subject. Saying which signal lost the data is
    // the only thing worth doing here.
    process.stdout.write('coverage_entry: takeCoverage() failed on ' +
                         signal + ': ' + e.message + '\n');
  }
  process.exit(0);
}

process.on('SIGTERM', function () { flushAndExit('SIGTERM'); });
process.on('SIGINT', function () { flushAndExit('SIGINT'); });

// The service itself, from the repository root, exactly as `node server.js`
// would load it.
require(path.resolve(__dirname, '..', '..', 'server.js'));
