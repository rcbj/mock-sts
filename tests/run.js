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
//
// ---------------------------------------------------------------------------
// THE THREE ARGUMENTS, ADDED 2026-08-28, AND WHY THEY DO NOT BREAK THE RULE
// ABOVE.
//
//   node tests/run.js                     every test (what `npm test` runs)
//   node tests/run.js --only=crypto,ldif  the ones whose FILE NAME contains
//                                         one of those, comma-separated
//   node tests/run.js --list              name them and run nothing
//   node tests/run.js --help              this, in short
//
// `--only` is a FILTER over the discovered list rather than a list of its own,
// which is the distinction the design above turns on: there is still nothing
// to keep up to date, and a name that matches nothing is an ERROR rather than
// an empty pass — a typo in a filter must not read as "everything passed".
//
// It exists because `tests/tools/run-report.js` runs each file in a PROCESS OF
// ITS OWN, and this is how it names the one it wants. `npm test` passes no
// arguments and behaves exactly as it did.
// ===========================================================================

const fs = require('fs');
const path = require('path');
const bunyan = require('bunyan');
const harness = require('./harness');

const log = bunyan.createLogger({ name: 'run',
                                  level: process.env.LOG_LEVEL || 'info' });

// This file and the harness are not tests. Everything else here is — and
// `tools/` is a DIRECTORY, so the report generator and the coverage renderer
// that live there need no entry here and cannot go stale into one. That is why
// they are in a subdirectory rather than beside this file: `readdirSync` is not
// recursive and `/\.js$/` does not match a directory name, so the discovery
// rule below is untouched by tooling being added.
const NOT_A_TEST = ['run.js', 'harness.js'];

// `patterns` is the `--only` filter: a file is kept when its name contains any
// one of them. Empty means every file, which is what `npm test` asks for.
function testFiles(patterns) {
  log.debug('Entering testFiles(). patterns=' + JSON.stringify(patterns || []));
  const here = __dirname;
  let files = fs.readdirSync(here)
    .filter(function (f) { return /\.js$/.test(f); })
    .filter(function (f) { return NOT_A_TEST.indexOf(f) < 0; })
    .sort();
  if (patterns && patterns.length) {
    files = files.filter(function (f) {
      return patterns.some(function (p) { return f.indexOf(p) >= 0; });
    });
  }
  log.debug('Leaving testFiles(). ' + files.length + ' found.');
  return files;
}

// ---------------------------------------------------------------------------
// The arguments. Hand-parsed because this directory takes no dependency to run
// — see CLAUDE.md — and three flags do not justify the first one.
// ---------------------------------------------------------------------------
function parseArgs(argv) {
  log.debug('Entering parseArgs().');
  const opts = { only: [], list: false, help: false, unknown: [] };
  argv.forEach(function (a) {
    if (a === '--list') {
      opts.list = true;
    } else if (a === '--help' || a === '-h') {
      opts.help = true;
    } else if (a.indexOf('--only=') === 0) {
      a.slice('--only='.length).split(',').forEach(function (p) {
        if (p.trim()) {
          opts.only.push(p.trim());
        }
      });
    } else if (a.indexOf('-') === 0) {
      opts.unknown.push(a);
    } else {
      // A bare word is the same thing as --only=<word>, because that is what
      // everybody types first.
      opts.only.push(a);
    }
  });
  log.debug('Leaving parseArgs().');
  return opts;
}

const USAGE = [
  'Usage: node tests/run.js [--only=<substring>[,<substring>...]] [--list]',
  '',
  '  --only=  run only the test files whose name contains one of these.',
  '           A bare word means the same thing. A pattern matching nothing',
  '           is an error, not an empty pass.',
  '  --list   name the test files that would run, and run none of them.',
  '',
  '  LOG_LEVEL=debug in the environment turns up every line, including the',
  '  service modules the tests drive in process.'
].join('\n');

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
  const opts = parseArgs(process.argv.slice(2));
  if (opts.help) {
    process.stdout.write(USAGE + '\n');
    log.debug('Leaving main(). Usage.');
    process.exit(0);
  }
  if (opts.unknown.length) {
    // Named rather than ignored: a flag this runner does not know is most
    // often one the REPORT generator takes, and silently running the whole
    // suite instead of what was asked for is the wrong answer to that.
    process.stdout.write('Unknown option(s): ' + opts.unknown.join(' ') +
                         '\n' + USAGE + '\n');
    log.debug('Leaving main(). Unknown option.');
    process.exit(2);
  }
  const files = testFiles(opts.only);
  if (!files.length) {
    // Not an error to have none, but it must not read as a pass: an empty
    // suite exiting 0 is the failure mode this whole directory is about. A
    // filter that matched nothing is the same failure with a likelier cause,
    // so it says which of the two happened.
    if (opts.only.length) {
      log.error('No test file matches ' + opts.only.join(', ') +
                '. Nothing was checked. `--list` names what there is.');
    } else {
      log.warn('No tests found in ' + __dirname + '. Nothing was checked.');
    }
    log.debug('Leaving main(). Empty.');
    process.exit(1);
  }
  if (opts.list) {
    files.forEach(function (f) {
      process.stdout.write(f + '\n');
    });
    log.debug('Leaving main(). Listed.');
    process.exit(0);
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

// Required by `tests/tools/run-report.js` for the discovery rule, which must
// have ONE implementation or the report and `npm test` can disagree about what
// the suite is. Requiring this file therefore must not run it.
module.exports = { testFiles: testFiles };

if (require.main === module) {
  main();
}
