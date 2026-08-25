'use strict';
//
// File: run.js
//
// ===========================================================================
// THE RUNNER. `npm test`.
//
// It DISCOVERS rather than holding a list, and that is the whole design. The
// argument against a second test suite in this repository (CLAUDE.md, "Tests")
// is that a second suite means a second place to forget — a list in a runner, a
// line in a Dockerfile, a paragraph in a map. So there is no list: a test here
// is any .js file in this directory that is not this file or `harness.js`, and
// adding one is dropping a file in. Nothing else to update, nothing to forget.
//
// A test module exports:
//
//   module.exports = {
//     name: 'config_realm_layer',      // what its log lines are named
//     describe: 'one line, printed before it runs',
//     run: function (t) { ... }        // t is a harness (see harness.js)
//   };
//
// `run` may be async. It asserts through `t.check()` / `t.equal()` and does NOT
// throw for an ordinary failure — a throw is reserved for a test that could not
// RUN, which is reported differently below because it means the run proved
// nothing rather than that the service is wrong.
// ===========================================================================

const fs = require('fs');
const path = require('path');
const bunyan = require('bunyan');
const harness = require('./harness');

const log = bunyan.createLogger({ name: 'run',
                                  level: process.env.LOG_LEVEL || 'info' });

// This file and the harness are not tests. Everything else here is.
const NOT_A_TEST = ['run.js', 'harness.js'];

function testFiles() {
  log.debug('Entering testFiles().');
  const here = __dirname;
  const files = fs.readdirSync(here)
    .filter(function (f) { return /\.js$/.test(f); })
    .filter(function (f) { return NOT_A_TEST.indexOf(f) < 0; })
    .sort();
  log.debug('Leaving testFiles(). ' + files.length + ' found.');
  return files;
}

// ---------------------------------------------------------------------------
// One test file. Returns its harness, or null when the module could not be run
// at all — which the caller reports as a HARD failure rather than as an
// assertion failure, because a test that did not run has not passed.
// ---------------------------------------------------------------------------
async function runOne(file) {
  log.debug('Entering runOne(). file=' + file);
  let mod;
  try {
    mod = require(path.join(__dirname, file));
  } catch (e) {
    // A require that throws is a broken test rather than a broken service, and
    // saying which is most of the value of catching it here.
    log.error('COULD NOT LOAD ' + file + ': ' + (e && e.stack ? e.stack : e));
    log.debug('Leaving runOne(). Load failed.');
    return null;
  }
  if (!mod || typeof mod.run !== 'function') {
    log.error(file + ' exports no run() function; see the header of run.js.');
    log.debug('Leaving runOne(). Not a test module.');
    return null;
  }
  log.info(mod.name || file + ' — ' + (mod.describe || ''));
  const t = harness.createHarness(mod.name || file.replace(/\.js$/, ''));
  try {
    await mod.run(t);
  } catch (e) {
    // Reserved for a test that could not finish. It is counted as a failure on
    // the harness so the exit code is right, and the stack is printed because
    // this is the case where the stack is the information.
    t.bad('the test itself threw', e && e.stack ? e.stack : String(e));
  }
  log.debug('Leaving runOne().');
  return t;
}

async function main() {
  log.debug('Entering main().');
  const files = testFiles();
  if (!files.length) {
    // Not an error to have none, but it must not read as a pass: an empty
    // suite exiting 0 is the failure mode this whole directory is about.
    log.warn('No tests found in ' + __dirname + '. Nothing was checked.');
    log.debug('Leaving main(). Empty.');
    process.exit(1);
  }
  let passed = 0;
  const failures = [];
  for (const file of files) {
    const t = await runOne(file);
    if (!t) {
      failures.push(file + ': did not run');
      continue;
    }
    passed += t.passed();
    failures.push.apply(failures, t.failures());
  }
  log.info('---------------------------------------------------------------');
  log.info(files.length + ' test file(s), ' + passed +
           ' assertion(s) passed, ' + failures.length + ' failed.');
  if (failures.length) {
    failures.forEach(function (f) {
      log.error('FAILED: ' + f);
    });
    log.debug('Leaving main(). Failures.');
    process.exit(1);
  }
  log.debug('Leaving main(). All passed.');
  process.exit(0);
}

main();
