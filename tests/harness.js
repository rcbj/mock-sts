'use strict';
//
// File: harness.js
//
// ===========================================================================
// THE COUNTERS AND THE LOGGER EVERY TEST IN THIS DIRECTORY SHARES.
//
// It is deliberately not a test framework. There is no describe/it, no
// discovery of assertions inside a file, no reporter plug-in: a test here is a
// plain function that is handed one of these and calls `check()`. The reason is
// the reason this directory exists at all (see CLAUDE.md) — these tests assert
// module CONTRACTS in process, they run in under a second, and the moment they
// need a dependency to run they stop being cheaper than the parent project's
// suite, which is where everything driven over HTTP already lives.
//
// The shape is `federation-e2e/drive.js`'s, on purpose: bunyan rather than
// console so a run reads like the parent project's tests/*.js and can be
// filtered by level, a tick or a cross per assertion, and the failures repeated
// at the end so a long run does not have to be scrolled.
// ===========================================================================

const bunyan = require('bunyan');

// ---------------------------------------------------------------------------
// One harness per test file, so the name on every line is the file that made
// the assertion rather than the runner.
// ---------------------------------------------------------------------------
function createHarness(name) {
  const log = bunyan.createLogger({ name: name,
                                    level: process.env.LOG_LEVEL || 'info' });
  const failures = [];
  let passed = 0;

  function ok(what, detail) {
    passed++;
    log.info('  ✓ ' + what + (detail ? '  — ' + detail : ''));
  }

  function bad(what, detail) {
    failures.push(name + ': ' + what + (detail ? ' — ' + detail : ''));
    log.error('  ✗ ' + what + (detail ? '  — ' + detail : ''));
  }

  // The one assertion. `detail` is not decoration: it is what the line says
  // when the assertion FAILS, so it should carry the values rather than restate
  // the claim.
  function check(condition, what, detail) {
    if (condition) {
      ok(what, detail);
    } else {
      bad(what, detail);
    }
    return !!condition;
  }

  // Equality, with the two values put into the detail automatically — the form
  // nearly every check below wants, and writing it out by hand is how a failure
  // message ends up saying less than the assertion knew.
  function equal(actual, expected, what) {
    return check(actual === expected, what,
                 'expected ' + JSON.stringify(expected) +
                 ', got ' + JSON.stringify(actual));
  }

  return {
    log: log,
    name: name,
    ok: ok,
    bad: bad,
    check: check,
    equal: equal,
    passed: function () { return passed; },
    failures: function () { return failures.slice(); }
  };
}

module.exports = { createHarness: createHarness };
