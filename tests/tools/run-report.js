#!/usr/bin/env node
'use strict';
//
// File: tests/tools/run-report.js
//
// ===========================================================================
// THE REPORT GENERATOR. `./local-run-tests.sh`, or `npm run report`.
//
// `npm test` (tests/run.js) runs every test in ONE process and prints bunyan
// lines. That is the right shape for the thing it is — under two seconds, no
// port, no dependency — and it is the wrong shape for three questions somebody
// asks the moment a run is longer than the terminal:
//
//   * which FILE was slow, and which one failed;
//   * what did the failing one actually print, without scrolling past nine
//     others that passed;
//   * what did the run look like LAST time.
//
// So this runner answers those and changes nothing about the other one. It
// writes tests/report/<timestamp>/ containing:
//
//   report.html          the run, per job and per assertion
//   report.xml           JUnit XML, one <testcase> per ASSERTION
//   summary.json         the same numbers for anything that wants to read them
//   logs/NN-<job>.log    the complete output of one job
//
// and points tests/report/latest at it.
//
// ---------------------------------------------------------------------------
// A PROCESS PER TEST FILE, WHICH IS THE ONE REAL DIFFERENCE FROM run.js.
//
// It runs `node tests/run.js --only=<file>` per file rather than requiring the
// modules itself, and that is worth the ~60ms of process start each time:
//
//   * a test that HANGS is a job that times out and a report that says which,
//     where in one process it is a suite that never finishes;
//   * a test that takes the process down (an uncaught rejection, an exit) is
//     one red job rather than a run with no report at all;
//   * the process-wide state rule in tests/CLAUDE.md — restore the realm
//     table, restore process.env — stops being able to make ANOTHER file fail,
//     which is exactly the failure that is hardest to read. The rule still
//     holds, because `npm test` still runs them together and is what CI runs.
//
// The assertion detail comes from PARSING what the harness already prints —
// bunyan JSON on stdout, one record per `✓` or `✗`. No new protocol, no change
// to harness.js, and a test file written before this existed reports in full.
//
// ---------------------------------------------------------------------------
// THE SECOND HALF: THE PARENT PROJECT'S JOBS, AGAINST THE WORKING TREE.
//
// Most of what covers this service is not in this repository at all — a
// protocol test goes in ../id-proto-debugger/tests/ by the decision the root
// CLAUDE.md argues. Those jobs drive a RUNNING service over HTTP, and the one
// they normally drive is the `sts/` gitlink over there, which is pinned. So
// with `--protocol` this runner starts a throwaway copy of THIS WORKING TREE
// on ports of its own and runs against that instead — the same jobs, the code
// you just edited, no submodule bump, no container.
//
// WHICH jobs is DERIVED and not listed, for the reason this whole directory is
// list-free. A job qualifies when the parent's own runner registers it, its
// script does not require selenium-webdriver, it reads WSTRUST_STS_URL or
// OID4VCI_ISSUER_URL — and it names no OTHER service's environment (walt.id,
// Keycloak, the debugger's api). That last clause is what keeps this to the
// jobs a lone mock can satisfy.
//
// A job of theirs may be AHEAD of this tree — their suite is developed against
// their own checkout — and it then fails here naming a feature this tree does
// not have. That is information rather than a fault in this runner, and the
// report says which side each job came from so it can be read that way.
//
// ---------------------------------------------------------------------------
// THE DEFAULT IS THE WHOLE SET, SINCE 2026-08-28, AND THAT REVERSES WHAT THIS
// FILE DID FOR ITS FIRST THREE DAYS.
//
// The protocol half used to be off unless `--protocol` was passed, on the
// argument that it needs the parent checkout beside this one and a run that
// needs nothing installed is a better default. That argument was wrong in the
// way that costs the most: the in-process half is TEN FILES about the realm
// layer, the LDIF codec, the two map renderers and the crypto module, and it
// finishes in under three seconds. So the default run answered in five
// seconds, said "Tests passed", and had exercised NO protocol endpoint, NO
// admin console and NO browser — which reads as a green suite and is a green
// tenth of one. Somebody has to already know about a flag to find that out,
// and a default that hides the other thirteen jobs behind one is a default
// that will be trusted wrongly.
//
// So the whole set runs unless it is turned off. What that costs is about a
// minute instead of three seconds, and — until the same day — a parent
// checkout beside this one. THAT SECOND COST IS GONE: the thirteen protocol
// jobs are VENDORED into tests/vendored/ and are this repository's own files
// now, so there is no checkout that can be missing and no job that can
// silently not run. See tests/vendored/MANIFEST.js for what is copied and
// why the copies are not edited here.
//
// `--no-protocol` is the way back to the old default, and the report says so
// in its own banner rather than leaving a green page to be read as more than
// it is.
//
// Usage:
//   node tests/tools/run-report.js [options]
//
//   --only=<substr>[,...]  only these test files / job names
//   --list                 name the jobs that would run; run none
//   --protocol[=on|off|only]
//                          also (or only) run the parent project's mock-only
//                          jobs against a throwaway instance. DEFAULT ON, as
//                          of 2026-08-28 — see THE DEFAULT IS THE WHOLE SET
//                          above. `--protocol=off` (or --no-protocol) leaves
//                          them out.
//   --no-protocol          the same as --protocol=off.
//   --parent=<dir>         ACCEPTED AND IGNORED. It named the checkout the
//                          protocol jobs were read out of, and since they are
//                          vendored into tests/vendored/ there is no such
//                          checkout. It is still parsed so that a script or a
//                          habit passing it does not die on an unknown option;
//                          tools/vendor-check.js is what takes it now.
//   --service-url=<url>    DRIVE A SERVICE SOMEBODY ELSE STARTED, at this URL,
//                          instead of starting a throwaway one. This is how
//                          ./local-run-tests.sh hands over the CONTAINER it
//                          brought up with docker-compose.yml — see THE
//                          SERVICE UNDER THE PROTOCOL JOBS below. The URL is
//                          checked before any job runs, and a service that
//                          does not answer FAILS the protocol jobs rather
//                          than skipping them, exactly as a throwaway one
//                          that would not start does.
//   --report-dir=<dir>     where to write (default tests/report)
//   --timeout=<ms>         per-job watchdog (default 300000; 0 disables)
//   --quiet                do not echo each job's output as it runs
//   --help
//
// ---------------------------------------------------------------------------
// THE SERVICE UNDER THE PROTOCOL JOBS COMES FROM ONE OF TWO PLACES, AND THIS
// RUNNER STARTS ONLY THE SECOND.
//
//   A CONTAINER, brought up from docker-compose.yml by ./local-run-tests.sh
//   and handed here as --service-url (or STS_TEST_SERVICE_URL). This is the
//   DEFAULT way the launcher runs, since 2026-08-28, and what it buys is that
//   the thing under test is the IMAGE — the same Dockerfile, the same
//   `npm install --omit=dev`, the same node — rather than whatever the
//   developer's own `node_modules` and node version happen to be. Several
//   things this service does are properties of its image and not of its
//   source, and a suite that never builds one cannot see them.
//
//   A THROWAWAY PROCESS, started by tools/service.js on nine ports of its
//   own. Still here, still what --no-docker uses, and still what a COVERAGE
//   run uses — because V8 writes its coverage from inside the process being
//   measured, and this runner cannot reach inside a container to collect it.
//
// The lifetime rule is the same one that governs everything else here: WHOEVER
// STARTED IT STOPS IT. A service handed in through --service-url is never
// stopped by this file, because the launcher's teardown owns it and two owners
// of one container is how a run ends by killing a stack somebody was reading.
// ---------------------------------------------------------------------------
//
// Environment:
//   LOG_LEVEL       this runner's and the unit jobs' bunyan level.
//   STS_TEST_SERVICE_URL
//                   the same thing --service-url says, for a caller that would
//                   rather export than pass an argument. The option wins.
//   STS_LOG_LEVEL   the throwaway service's level. Unset means its appconfig
//                   file decides, and that is `debug` — every request and
//                   every signed artifact written down, which is what a
//                   failing protocol job is read from, and about half of that
//                   service's CPU.
//   STS_TEST_CONFIG_FILE
//                   the appconfig file that service reads (default
//                   ./env/local.js, resolved by tests/tools/service.js). It is
//                   the OTHER half of the log level: the vendored modules
//                   under common/vendored/ build their loggers from this file
//                   and never see STS_LOG_LEVEL, so a quiet run needs both.
//                   ./local-run-tests.sh sets it from --sts-log-level.
//   COVERAGE=true   collect V8 coverage from every job AND from the throwaway
//                   service, then render it. `./run-coverage.sh` is the way in.
//   COVERAGE_DIR    where the raw data and the rendered report go
//                   (default ./coverage).
// ===========================================================================

const { spawn, execFileSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const bunyan = require('bunyan');

const service = require('./service');
const manifest = require('../vendored/MANIFEST.js');
const coverage = require('./coverage-report');
const { testFiles } = require('../run');

const log = bunyan.createLogger({ name: 'run-report',
                                  level: process.env.LOG_LEVEL || 'info' });

const REPO_ROOT = path.resolve(__dirname, '..', '..');
const TESTS_DIR = path.join(REPO_ROOT, 'tests');
const VENDORED_DIR = path.join(TESTS_DIR, 'vendored');
// A filesystem-safe ISO stamp, the parent project's shape: 2026-08-28T17-45-00.
const RUN_ID = new Date().toISOString().replace(/:/g, '-').replace(/\..+$/, '');

// ---------------------------------------------------------------------------
// Arguments. Hand-parsed, like tests/run.js's, and for the same reason: this
// directory takes no dependency to run.
// ---------------------------------------------------------------------------
function parseArgs(argv) {
  log.debug('Entering parseArgs().');
  const opts = { only: [], list: false, protocol: 'on', parent: '',
                 reportDir: path.join(TESTS_DIR, 'report'),
                 timeoutMs: 300000, quiet: false, help: false,
                 browser: true,
                 // The environment is the FALLBACK and the option is the
                 // answer, which is the same precedence every other setting
                 // in this repository has.
                 serviceUrl: process.env.STS_TEST_SERVICE_URL || '',
                 unknown: [] };
  argv.forEach(function (a) {
    if (a === '--list') {
      opts.list = true;
    } else if (a === '--help' || a === '-h') {
      opts.help = true;
    } else if (a === '--quiet') {
      opts.quiet = true;
    } else if (a === '--no-browser') {
      opts.browser = false;
    } else if (a === '--protocol') {
      opts.protocol = 'on';
    } else if (a === '--no-protocol') {
      opts.protocol = 'off';
    } else if (a.indexOf('--protocol=') === 0) {
      opts.protocol = a.slice('--protocol='.length);
    } else if (a.indexOf('--parent=') === 0) {
      // Accepted and ignored — see the usage note above.
      opts.parent = a.slice('--parent='.length);
    } else if (a.indexOf('--service-url=') === 0) {
      // Trailing slashes are stripped because every job appends an absolute
      // path to this and `http://host:1/` + `/oauth2/token` is a 404 whose
      // message names a path that looks right.
      opts.serviceUrl = a.slice('--service-url='.length).replace(/\/+$/, '');
    } else if (a.indexOf('--report-dir=') === 0) {
      opts.reportDir = path.resolve(a.slice('--report-dir='.length));
    } else if (a.indexOf('--timeout=') === 0) {
      opts.timeoutMs = Number(a.slice('--timeout='.length));
    } else if (a.indexOf('--only=') === 0) {
      a.slice('--only='.length).split(',').forEach(function (p) {
        if (p.trim()) {
          opts.only.push(p.trim());
        }
      });
    } else if (a.indexOf('-') === 0) {
      opts.unknown.push(a);
    } else {
      opts.only.push(a);
    }
  });
  log.debug('Leaving parseArgs().');
  return opts;
}


// The environments of the OTHER services in the parent's stack. A job naming
// any of them needs more than a lone mock, so it is not one of ours.
const OTHER_SERVICE_ENV =
  /process\.env\.(WALTID[A-Z_]*|KEYCLOAK[A-Z_]*|DEBUGGER_BASE_URL|API_[A-Z_]*|WSFED_[A-Z_]*|STS_TEST_POSTGRES_URL|MOCK_STS_DIR)/;
// A job that drives a BROWSER, and — separately — one that drives the
// DEBUGGER'S OWN SITE.
//
// Until 2026-08-28 the first of these was used as the second, and it was right
// by accident: every browser job in that suite drove the debugger's pages, so
// "requires selenium" and "needs more than a lone mock" picked out the same
// set. tests/sts_admin_console.js broke that — it became a browser job that
// drives THIS SERVICE'S OWN CONSOLE and needs a Chrome and nothing else — and
// dropping the selenium exclusion on its own let all twenty-three of the
// others back in, where they failed against a stack that is not running.
//
// So the two questions are asked separately now. A browser job runs unless
// --no-browser; a job that names the debugger's client (port 3000) is not ours
// whether it needs a browser or not. The port is the discriminator because it
// is what those jobs actually reach for: each declares
// `var baseUrl = "http://localhost:3000"` and drives pages under it, while a
// job of ours locates the mock through WSTRUST_STS_URL / OID4VCI_ISSUER_URL
// and never mentions 3000.
const SELENIUM_REQUIRE = /require\(\s*["']selenium-webdriver/;
const DEBUGGER_SITE = /localhost:3000|127\.0\.0\.1:3000/;
const NEEDS_THE_MOCK = /WSTRUST_STS_URL|OID4VCI_ISSUER_URL/;

// ---------------------------------------------------------------------------
// The parent's jobs that a lone copy of this service can satisfy. DERIVED from
// their own runner — the file that already decides what a job is over there —
// so a test added or renamed in that suite arrives here with nothing edited.
// ---------------------------------------------------------------------------
function vendoredJobs(options) {
  log.debug('Entering vendoredJobs().');
  // A caller with no options gets the default, which is that browser jobs RUN.
  // This function is exported, so a second caller passing nothing must not
  // silently mean "leave the console's only coverage out".
  const opts = options || { browser: true };
  const skippedBrowserJobs = [];
  const jobs = [];
  manifest.JOBS.forEach(function (entry) {
    if (entry.browser && !opts.browser) {
      skippedBrowserJobs.push(entry.file);
      return;
    }
    jobs.push({ suite: 'protocol', name: entry.file.replace(/\.js$/, ''),
                file: entry.file, dir: VENDORED_DIR, browser: !!entry.browser });
  });
  const browserJobs = jobs.filter(function (j) { return j.browser; });
  if (browserJobs.length) {
    log.info(browserJobs.length + ' of these need a BROWSER (' +
             browserJobs.map(function (j) { return j.name; }).join(', ') +
             '). They are run ONE AT A TIME like every other job here — this ' +
             'runner is serial — and they are the slowest jobs in the run. ' +
             '--no-browser leaves them out.');
  }
  if (skippedBrowserJobs.length) {
    log.warn('SKIPPING ' + skippedBrowserJobs.length + ' browser job(s) on ' +
             '--no-browser: ' + skippedBrowserJobs.join(', ') + '. The admin ' +
             'console has NO other coverage against this working tree, so ' +
             'this run says nothing about /admin.');
  }
  log.debug('Leaving vendoredJobs(). ' + jobs.length + ' job(s).');
  return jobs;
}

// ---------------------------------------------------------------------------
// THE TEST DEPENDENCIES, and why their absence is a FAILURE rather than a skip.
//
// The vendored jobs need `commander` and `selenium-webdriver`, which live in
// tests/package.json rather than the root one — see that file for the .npmrc
// reason. A checkout that has not run `npm install --prefix tests` therefore
// has jobs that cannot LOAD, and node reports that as MODULE_NOT_FOUND at
// startup: a non-zero exit, so the runner already calls it a failure.
//
// This check exists to make that failure READABLE. Thirteen jobs each dying
// with a stack trace about `commander` is a wall of noise that names a package
// and not a command; one line naming the command, before anything is spawned,
// is the difference between a five-second fix and an afternoon.
//
// It does NOT skip the jobs and does not stop the run. They are still spawned,
// they still fail, and the report still counts thirteen failures — because a
// run that quietly declined to check anything is the exact thing this file was
// changed on 2026-08-28 to stop doing.
// ---------------------------------------------------------------------------
function checkTestDependencies() {
  log.debug('Entering checkTestDependencies().');
  const missing = [];
  ['commander', 'selenium-webdriver'].forEach(function (m) {
    if (!fs.existsSync(path.join(TESTS_DIR, 'node_modules', m))) {
      missing.push(m);
    }
  });
  if (missing.length) {
    log.error('the vendored protocol jobs need ' + missing.join(' and ') +
              ', which is not installed. They will FAIL to load. Fix it with:' +
              '\n\n    npm install --prefix tests\n\n' +
              '(those packages are in tests/package.json and not the root one ' +
              'because .npmrc carries omit=dev — see tests/package.json.)');
  }
  log.debug('Leaving checkTestDependencies(). ' + missing.length + ' missing.');
  return missing;
}

// ---------------------------------------------------------------------------
// One job, in a process of its own. Its output is TEED — written to the log
// file as it arrives and echoed to the console unless --quiet — so a long job
// is watchable and a finished one is readable.
// ---------------------------------------------------------------------------
function runJob(job, opts) {
  log.debug('Entering runJob(). job=' + job.name);
  return new Promise(function (resolve) {
    const started = Date.now();
    const stream = fs.createWriteStream(job.logFile, { flags: 'a' });
    stream.write('# ' + job.name + '\n# ' + job.cmd.join(' ') +
                 '\n# cwd=' + job.cwd + '\n\n');
    const child = spawn(job.cmd[0], job.cmd.slice(1), {
      cwd: job.cwd,
      env: job.env,
      stdio: ['ignore', 'pipe', 'pipe']
    });
    let buffered = '';
    const assertions = [];
    function onData(chunk) {
      const text = chunk.toString();
      stream.write(text);
      if (!opts.quiet) {
        process.stdout.write(text);
      }
      buffered += text;
      // Whole lines only: a bunyan record split across two reads is not JSON
      // yet, and half of one parsed as a failure would be a fiction.
      const lines = buffered.split('\n');
      buffered = lines.pop();
      lines.forEach(function (line) {
        const a = assertionOf(line);
        if (a) {
          assertions.push(a);
        }
      });
    }
    child.stdout.on('data', onData);
    child.stderr.on('data', onData);
    let timer = null;
    let timedOut = false;
    if (opts.timeoutMs > 0) {
      timer = setTimeout(function () {
        timedOut = true;
        // SIGKILL rather than SIGTERM: a job that has already ignored its
        // watchdog is not the one to trust with a clean shutdown.
        try {
          child.kill('SIGKILL');
        } catch (e) {
          // It finished between the timer firing and this line. Nothing to do.
        }
      }, opts.timeoutMs);
    }
    child.on('error', function (e) {
      if (timer) {
        clearTimeout(timer);
      }
      stream.end('\n# could not spawn: ' + e.message + '\n');
      log.debug('Leaving runJob(). Could not spawn.');
      resolve(Object.assign({}, job, {
        status: 'failed', ms: Date.now() - started, code: null,
        assertions: assertions,
        failures: ['could not spawn ' + job.cmd[0] + ': ' + e.message]
      }));
    });
    child.on('close', function (code, signal) {
      if (timer) {
        clearTimeout(timer);
      }
      if (buffered) {
        const a = assertionOf(buffered);
        if (a) {
          assertions.push(a);
        }
      }
      const ms = Date.now() - started;
      const failures = assertions.filter(function (a) { return !a.ok; })
        .map(function (a) { return a.what; });
      if (timedOut) {
        failures.push('the job did not finish within ' + opts.timeoutMs +
                      'ms and was killed');
      } else if (code !== 0 && !failures.length) {
        // The exit code is the only evidence there is: a parent-project job
        // reports through `assert` rather than through this repository's
        // harness, so a red one usually leaves no ✗ line to have parsed.
        failures.push('exited ' + (signal ? 'on ' + signal : 'with code ' +
                      code) + '; see ' + path.basename(job.logFile));
      }
      stream.end('\n# exit code ' + code + (signal ? ' (' + signal + ')' : '') +
                 ' after ' + ms + 'ms\n');
      log.debug('Leaving runJob(). ' + job.name + ' exited ' + code + '.');
      resolve(Object.assign({}, job, {
        status: (code === 0 && !timedOut && !failures.length) ? 'passed'
                                                             : 'failed',
        ms: ms, code: code, signal: signal || null,
        assertions: assertions, failures: failures
      }));
    });
  });
}

// ---------------------------------------------------------------------------
// TWO FUNCTIONS BELOW CARRY NO `Entering`/`Leaving` PAIR AND SAY SO HERE
// RATHER THAN LEAVING IT TO BE NOTICED — the repository's pattern is that the
// exemption is argued in the file that takes it. `assertionOf()` is called
// once per LINE of every job's output, which is tens of thousands of times in
// an ordinary run, and the HTML helpers are called once per row; a debug line
// each would bury the log those lines exist to make readable. Everything that
// runs a bounded number of times per run is instrumented as usual.
//
// One line of a job's output, read for an assertion. The harness prints bunyan
// JSON whose `msg` begins with two spaces and a tick or a cross (harness.js),
// so this reads what is already there rather than asking the tests to report
// twice — which is what keeps every test file written before this existed
// fully reported by it.
// ---------------------------------------------------------------------------
function assertionOf(line) {
  const trimmed = line.trim();
  if (!trimmed || trimmed[0] !== '{') {
    return null;
  }
  let rec;
  try {
    rec = JSON.parse(trimmed);
  } catch (e) {
    // Not a bunyan record. The service modules under test print plenty that
    // is not, and a parse failure here is the ordinary case rather than a
    // problem.
    return null;
  }
  if (!rec || typeof rec.msg !== 'string') {
    return null;
  }
  const m = /^\s*([✓✗])\s+([\s\S]*)$/.exec(rec.msg);
  if (!m) {
    return null;
  }
  return { ok: m[1] === '✓', what: m[2], test: rec.name || '' };
}

function escapeHtml(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function escapeXml(s) {
  return escapeHtml(s).replace(/'/g, '&apos;')
    // Control characters are not legal in XML 1.0 at all, and a stack trace
    // carrying one makes the whole document unparseable for a CI dashboard —
    // which is the one consumer this file has.
    .replace(/[\x00-\x08\x0b\x0c\x0e-\x1f]/g, '');
}

function slug(s) {
  return String(s).toLowerCase().replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '').slice(0, 60);
}

// ---------------------------------------------------------------------------
// What this run was OF, which is most of what makes an old report worth
// keeping: a green report against a tree with uncommitted changes is a
// different claim from a green report against a commit.
// ---------------------------------------------------------------------------
function describeTree(dir) {
  log.debug('Entering describeTree(). dir=' + dir);
  const out = { commit: '', subject: '', dirty: null };
  function git(args) {
    return execFileSync('git', args, { cwd: dir, encoding: 'utf8',
                                       stdio: ['ignore', 'pipe', 'ignore'] })
      .trim();
  }
  try {
    out.commit = git(['rev-parse', '--short', 'HEAD']);
    out.subject = git(['log', '-1', '--pretty=%s']);
    out.dirty = git(['status', '--porcelain']).length > 0;
  } catch (e) {
    // Not a checkout, or no git. The report then says the commit is unknown,
    // which is honest and costs nothing else.
    log.debug('describeTree() could not read git: ' + e.message);
  }
  log.debug('Leaving describeTree().');
  return out;
}

// ---------------------------------------------------------------------------
// THE HTML. Self-contained and with NO SCRIPT on it, which is not an accident
// carried over from the console's rule (app.js sets `script-src 'none'` and
// three pages argue their way past it one at a time): a report is read from a
// file:// URL, from a CI artifact server, and from whatever a person pastes it
// into, and `<details>` folds every long list without needing any of them to
// allow one.
// ---------------------------------------------------------------------------
const STYLE = [
  ':root{color-scheme:light dark;--fg:#1a1a1a;--bg:#fbfbfa;--muted:#6b6b6b;',
  '--line:#e3e3e0;--card:#fff;--pass:#1a7f37;--fail:#b3261e;--skip:#8a6d00;}',
  '@media (prefers-color-scheme:dark){:root{--fg:#e6e6e6;--bg:#171717;',
  '--muted:#a0a0a0;--line:#333;--card:#1f1f1f;--pass:#4ac26b;--fail:#ff7b72;',
  '--skip:#d4a72c;}}',
  'body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 -apple-system,',
  'BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;}',
  '.wrap{max-width:1100px;margin:0 auto;padding:24px 20px 64px;}',
  'h1{font-size:20px;margin:0 0 4px;} h2{font-size:16px;margin:32px 0 8px;}',
  '.sub{color:var(--muted);margin:0 0 20px;}',
  '.cards{display:flex;flex-wrap:wrap;gap:12px;margin:16px 0 8px;}',
  '.card{background:var(--card);border:1px solid var(--line);border-radius:8px;',
  'padding:10px 14px;min-width:110px;}',
  '.card .n{font-size:22px;font-weight:600;} .card .l{color:var(--muted);font-size:12px;}',
  'table{border-collapse:collapse;width:100%;background:var(--card);',
  'border:1px solid var(--line);border-radius:8px;overflow:hidden;}',
  'th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line);',
  'vertical-align:top;} th{font-size:12px;color:var(--muted);font-weight:600;}',
  'tr:last-child td{border-bottom:none;} td.num{text-align:right;',
  'font-variant-numeric:tabular-nums;white-space:nowrap;}',
  '.pass{color:var(--pass);} .fail{color:var(--fail);} .skip{color:var(--skip);}',
  'code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;',
  'font-size:12px;}',
  'pre{background:var(--card);border:1px solid var(--line);border-radius:6px;',
  'padding:10px;overflow-x:auto;}',
  'details{margin:6px 0;} summary{cursor:pointer;}',
  'ul.assertions{list-style:none;margin:6px 0 12px;padding:0 0 0 4px;}',
  'ul.assertions li{padding:2px 0;border-bottom:1px dotted var(--line);}',
  '.detail{color:var(--muted);}',
  '.banner{padding:10px 14px;border-radius:8px;border:1px solid var(--line);',
  'background:var(--card);margin:16px 0;}'
].join('');

function jobRow(j) {
  const status = j.status === 'passed'
    ? '<span class="pass">passed</span>'
    : (j.status === 'skipped' ? '<span class="skip">skipped</span>'
                              : '<span class="fail">FAILED</span>');
  const ok = j.assertions.filter(function (a) { return a.ok; }).length;
  const bad = j.assertions.length - ok;
  const counts = j.assertions.length
    ? ok + ' ✓' + (bad ? ' / <span class="fail">' + bad + ' ✗</span>' : '')
    : '<span class="detail">—</span>';
  return '<tr><td><code>' + escapeHtml(j.name) + '</code>' +
    (j.describe ? '<div class="detail">' + escapeHtml(j.describe) + '</div>'
                : '') +
    (j.why ? '<div class="detail">' + escapeHtml(j.why) + '</div>' : '') +
    '</td><td>' + status + '</td><td class="num">' + counts +
    '</td><td class="num">' + (j.status === 'skipped' ? '—' : j.ms + ' ms') +
    '</td><td>' + (j.logName
      ? '<a href="logs/' + escapeHtml(j.logName) + '">log</a>' : '') +
    '</td></tr>';
}

function assertionList(j) {
  if (!j.assertions.length) {
    return '';
  }
  const items = j.assertions.map(function (a) {
    return '<li>' + (a.ok ? '<span class="pass">✓</span> '
                          : '<span class="fail">✗</span> ') +
      escapeHtml(a.what) + '</li>';
  }).join('');
  return '<details><summary>' + j.assertions.length + ' assertion(s) — ' +
    escapeHtml(j.name) + '</summary><ul class="assertions">' + items +
    '</ul></details>';
}

function writeHtml(runDir, results, meta) {
  log.debug('Entering writeHtml().');
  const failed = results.filter(function (j) { return j.status === 'failed'; });
  const skipped = results.filter(function (j) { return j.status === 'skipped'; });
  const passed = results.filter(function (j) { return j.status === 'passed'; });
  const asserted = results.reduce(function (n, j) {
    return n + j.assertions.length;
  }, 0);
  const assertFailed = results.reduce(function (n, j) {
    return n + j.assertions.filter(function (a) { return !a.ok; }).length;
  }, 0);
  const bySuite = {};
  results.forEach(function (j) {
    bySuite[j.suite] = bySuite[j.suite] || [];
    bySuite[j.suite].push(j);
  });
  const SUITE_TITLE = {
    unit: 'In-process module contracts (this repository\'s tests/)',
    protocol: 'Protocol jobs from the parent project, against this working ' +
              'tree'
  };
  let html = '<!doctype html><html lang="en"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width,initial-scale=1">' +
    '<title>mock STS tests — ' + escapeHtml(meta.runId) + '</title>' +
    '<style>' + STYLE + '</style></head><body><div class="wrap">';
  html += '<h1>mock STS test report</h1>';
  html += '<p class="sub">' + escapeHtml(meta.runId) + ' · ' +
    escapeHtml(meta.host) + ' · node ' + escapeHtml(meta.node) + ' · ' +
    (meta.wallMs / 1000).toFixed(1) + 's wall</p>';
  html += '<div class="cards">' +
    '<div class="card"><div class="n ' +
      (failed.length ? 'fail' : 'pass') + '">' +
      (failed.length ? 'FAILED' : 'passed') + '</div>' +
      '<div class="l">overall</div></div>' +
    '<div class="card"><div class="n">' + results.length + '</div>' +
      '<div class="l">jobs</div></div>' +
    '<div class="card"><div class="n pass">' + passed.length + '</div>' +
      '<div class="l">passed</div></div>' +
    '<div class="card"><div class="n ' + (failed.length ? 'fail' : '') + '">' +
      failed.length + '</div><div class="l">failed</div></div>' +
    (skipped.length ? '<div class="card"><div class="n skip">' +
      skipped.length + '</div><div class="l">skipped</div></div>' : '') +
    '<div class="card"><div class="n">' + asserted + '</div>' +
      '<div class="l">assertions</div></div>' +
    (assertFailed ? '<div class="card"><div class="n fail">' + assertFailed +
      '</div><div class="l">assertions failed</div></div>' : '') +
    '</div>';

  html += '<div class="banner"><strong>What was under test.</strong> ' +
    'This tree at <code>' + escapeHtml(meta.tree.commit || 'unknown') +
    '</code>' + (meta.tree.subject ? ' — ' + escapeHtml(meta.tree.subject)
                                   : '') +
    (meta.tree.dirty ? ', <span class="fail">with uncommitted changes</span>'
                     : ', clean') + '.';
  if (meta.vendored) {
    html += ' Protocol jobs are the VENDORED copies in <code>' +
      escapeHtml(meta.vendored) + '</code> — this tree\'s own files, at the ' +
      'commit above — driven against ' +
      (meta.serviceKind === 'container'
        ? 'a CONTAINER built from this tree by <code>docker-compose.yml</code>'
        : 'a throwaway in-process instance') +
      ' on <code>' +
      escapeHtml(meta.serviceUrl || '?') + '</code>. They are byte-identical ' +
      'copies of the parent project\'s jobs and are not edited here; ' +
      '<code>./local-run-tests.sh --vendor-check</code> reports drift when ' +
      'both checkouts are present.';
  } else if (meta.protocolWhy) {
    html += ' Protocol jobs were not run: ' + escapeHtml(meta.protocolWhy) +
      '.';
  } else {
    html += ' Protocol jobs were TURNED OFF for this run ' +
      '(<code>--no-protocol</code>), so nothing here says anything about ' +
      'this service\'s protocol surface or its admin console.';
  }
  html += '</div>';

  if (failed.length) {
    html += '<h2 class="fail">Failures</h2><table><tr><th>job</th>' +
      '<th>what failed</th></tr>';
    failed.forEach(function (j) {
      html += '<tr><td><code>' + escapeHtml(j.name) + '</code><div>' +
        (j.logName ? '<a href="logs/' + escapeHtml(j.logName) + '">log</a>'
                   : '') + '</div></td><td><ul class="assertions">' +
        j.failures.map(function (f) {
          return '<li class="fail">' + escapeHtml(f) + '</li>';
        }).join('') + '</ul></td></tr>';
    });
    html += '</table>';
  }

  Object.keys(bySuite).forEach(function (suite) {
    html += '<h2>' + escapeHtml(SUITE_TITLE[suite] || suite) + '</h2>';
    html += '<table><tr><th>job</th><th>result</th><th>assertions</th>' +
      '<th>time</th><th></th></tr>';
    bySuite[suite].forEach(function (j) {
      html += jobRow(j);
    });
    html += '</table>';
    const withAssertions = bySuite[suite].filter(function (j) {
      return j.assertions.length;
    });
    if (withAssertions.length) {
      html += '<h3 style="font-size:14px;margin:16px 0 4px;">Every assertion' +
        '</h3>';
      withAssertions.forEach(function (j) {
        html += assertionList(j);
      });
    }
  });

  if (meta.coverage) {
    html += '<h2>Coverage</h2><p>' +
      '<a href="' + escapeHtml(meta.coverage) + '">' +
      escapeHtml(meta.coverage) + '</a></p>';
  }

  html += '<h2>How this was run</h2><pre>' +
    escapeHtml(meta.commandLine) + '</pre>';
  html += '</div></body></html>';
  fs.writeFileSync(path.join(runDir, 'report.html'), html);
  log.debug('Leaving writeHtml().');
}

// ---------------------------------------------------------------------------
// JUnit XML, one <testcase> per ASSERTION where there are assertions to have,
// and one per job where there are not. Per assertion because that is what this
// suite actually knows — a CI dashboard then names the check that broke rather
// than the file it was in.
// ---------------------------------------------------------------------------
function writeXml(runDir, results, meta) {
  log.debug('Entering writeXml().');
  let xml = '<?xml version="1.0" encoding="UTF-8"?>\n<testsuites name="mock-sts"' +
    ' time="' + (meta.wallMs / 1000).toFixed(3) + '">\n';
  results.forEach(function (j) {
    const cases = [];
    if (j.assertions.length) {
      j.assertions.forEach(function (a) {
        cases.push('    <testcase classname="' + escapeXml(j.suite + '.' + j.name) +
          '" name="' + escapeXml(a.what) + '">' +
          (a.ok ? '' : '<failure message="' + escapeXml(a.what) + '"/>') +
          '</testcase>\n');
      });
    }
    if (!cases.length || j.status !== 'passed') {
      const body = j.status === 'skipped'
        ? '<skipped message="' + escapeXml(j.why || '') + '"/>'
        : (j.status === 'failed'
            ? '<failure message="' + escapeXml(j.failures.join('; ')) + '"/>'
            : '');
      cases.push('    <testcase classname="' + escapeXml(j.suite + '.' + j.name) +
        '" name="' + escapeXml(j.name + ' (the job)') + '" time="' +
        (j.ms / 1000).toFixed(3) + '">' + body + '</testcase>\n');
    }
    const failures = j.assertions.filter(function (a) { return !a.ok; }).length +
      (j.status === 'failed' ? 1 : 0);
    xml += '  <testsuite name="' + escapeXml(j.suite + '.' + j.name) +
      '" tests="' + cases.length + '" failures="' + failures +
      '" skipped="' + (j.status === 'skipped' ? 1 : 0) + '" time="' +
      (j.ms / 1000).toFixed(3) + '">\n' + cases.join('') + '  </testsuite>\n';
  });
  xml += '</testsuites>\n';
  fs.writeFileSync(path.join(runDir, 'report.xml'), xml);
  log.debug('Leaving writeXml().');
}

// ---------------------------------------------------------------------------
// tests/report/latest, so the launcher and a person both have one path that
// does not change. A symlink where the platform allows it, and a file naming
// the run where it does not — Windows without developer mode being the case
// that made a plain symlink throw here.
// ---------------------------------------------------------------------------
function pointLatestAt(reportDir, runDir) {
  log.debug('Entering pointLatestAt().');
  const link = path.join(reportDir, 'latest');
  try {
    if (fs.existsSync(link) || fs.lstatSync(link)) {
      fs.rmSync(link, { recursive: true, force: true });
    }
  } catch (e) {
    // Nothing there. That is the ordinary first run.
  }
  try {
    fs.symlinkSync(path.basename(runDir), link, 'dir');
  } catch (e) {
    fs.writeFileSync(link + '.txt', path.basename(runDir) + '\n');
    log.debug('pointLatestAt() could not symlink: ' + e.message);
  }
  log.debug('Leaving pointLatestAt().');
}

// The usage is the header of this file, read back rather than kept a second
// time in a string — which is the only way the two cannot drift apart. From
// the `Usage:` line to the end of the comment block, and no further: an
// earlier attempt filtered by indentation and printed half the design notes.
const USAGE = (function () {
  const lines = fs.readFileSync(__filename, 'utf8').split('\n');
  const from = lines.findIndex(function (l) { return /^\/\/ Usage:/.test(l); });
  if (from < 0) {
    return 'see the header of ' + __filename;
  }
  const out = [];
  for (let i = from; i < lines.length; i++) {
    if (lines[i].indexOf('//') !== 0) {
      break;
    }
    if (/^\/\/ =====/.test(lines[i])) {
      break;
    }
    out.push(lines[i].replace(/^\/\/ ?/, ''));
  }
  return out.join('\n');
})();

// ---------------------------------------------------------------------------
// IS THE SERVICE SOMEBODY ELSE STARTED ACTUALLY ANSWERING?
//
// The launcher already waited for its container to answer before it got here,
// so this ordinarily returns on its first request — and it is not therefore
// decoration. It answers a DIFFERENT question from the one the launcher asked,
// and the difference has cost the parent project a whole run: the launcher
// asked whether something answers on that port, and this asks whether it is
// still answering NOW, from this process, with the environment these jobs will
// actually use. A container that aborted between the two, a URL typed by hand
// into --service-url, a stale STS_TEST_SERVICE_URL exported in a shell weeks
// ago and forgotten — each of those reaches the jobs as thirteen failures
// about tokens and metadata, and reaches this as one line naming the URL.
//
// A NON-200 IS AS GOOD AS AN ANSWER, deliberately. /healthcheck is what a
// caller usually points at and it answers 200, but the URL handed in is the
// service's ROOT and this asks for `/`, which any of the redirects and shells
// this service serves may answer with. What is being distinguished here is a
// socket that answers from one that does not.
// ---------------------------------------------------------------------------
async function waitForExternalService(url, log, timeoutMs) {
  log.debug('Entering waitForExternalService().');
  const deadline = Date.now() + (timeoutMs || 30000);
  let lastError = 'it never answered';
  while (Date.now() < deadline) {
    try {
      /* eslint-disable no-await-in-loop */
      const res = await fetch(url + '/', { redirect: 'manual' });
      /* eslint-enable no-await-in-loop */
      if (res.status > 0) {
        log.debug('Leaving waitForExternalService(). Answering.');
        return true;
      }
    } catch (e) {
      // The ordinary case for as long as it takes the socket to come up, and
      // the loop is the whole handling. The message is kept for the ONE time
      // it matters — the failure below, where a bare "did not answer" would
      // hide an ECONNREFUSED behind a DNS failure behind a bad scheme.
      lastError = e && e.message ? e.message : String(e);
    }
    /* eslint-disable no-await-in-loop */
    await new Promise(function (r) { setTimeout(r, 500); });
    /* eslint-enable no-await-in-loop */
  }
  log.debug('Leaving waitForExternalService(). It did not answer.');
  throw new Error('the service at ' + url + ' did not answer (' + lastError +
                  '). It was handed to this runner with --service-url, so ' +
                  'nothing here started it and nothing here can restart it.');
}

async function main() {
  log.debug('Entering main().');
  const opts = parseArgs(process.argv.slice(2));
  if (opts.help || opts.unknown.length) {
    if (opts.unknown.length) {
      process.stdout.write('Unknown option(s): ' + opts.unknown.join(' ') + '\n');
    }
    process.stdout.write(USAGE + '\n');
    process.exit(opts.unknown.length ? 2 : 0);
  }
  const wantUnit = opts.protocol !== 'only';
  const wantProtocol = opts.protocol === 'on' || opts.protocol === 'only';

  // ---- the jobs ---------------------------------------------------------
  const jobs = [];
  if (wantUnit) {
    testFiles(opts.only).forEach(function (file) {
      jobs.push({ suite: 'unit', name: file.replace(/\.js$/, ''), file: file,
                  dir: TESTS_DIR });
    });
  }
  // THE PROTOCOL JOBS ARE VENDORED HERE SINCE 2026-08-28 and are no longer
  // read out of a parent checkout, so there is no longer any way for them to
  // be absent: the files are in this repository. What used to be a warning
  // that thirteen jobs would be skipped is gone with the condition that
  // produced it.
  let missingDeps = [];
  if (wantProtocol) {
    let theirs = vendoredJobs(opts);
    if (opts.only.length) {
      theirs = theirs.filter(function (j) {
        return opts.only.some(function (p) { return j.file.indexOf(p) >= 0; });
      });
    }
    jobs.push.apply(jobs, theirs);
    if (theirs.length && !opts.list) {
      missingDeps = checkTestDependencies();
    }
  }
  if (!jobs.length) {
    // An empty run must never read as a pass — the same rule tests/run.js
    // holds, for the same reason.
    log.error('No jobs to run' + (opts.only.length
      ? ' matching ' + opts.only.join(', ') : '') + '. Nothing was checked.');
    process.exit(1);
  }
  if (opts.list) {
    jobs.forEach(function (j) {
      process.stdout.write(j.suite + '  ' + j.name + '\n');
    });
    process.exit(0);
  }

  // ---- where it is written ----------------------------------------------
  const runDir = path.join(opts.reportDir, RUN_ID);
  const logsDir = path.join(runDir, 'logs');
  fs.mkdirSync(logsDir, { recursive: true });

  // ---- coverage, if it was asked for ------------------------------------
  const wantCoverage = String(process.env.COVERAGE || '') === 'true';
  const coverageDir = path.resolve(process.env.COVERAGE_DIR ||
                                   path.join(REPO_ROOT, 'coverage'));
  const rawUnit = path.join(coverageDir, 'raw', 'unit');
  const rawProtocol = path.join(coverageDir, 'raw', 'protocol');
  if (wantCoverage) {
    // Emptied rather than added to: V8 names each file with a pid and a
    // timestamp, so an old run's files would merge into this one's report and
    // nothing would say they had.
    fs.rmSync(path.join(coverageDir, 'raw'), { recursive: true, force: true });
    fs.mkdirSync(rawUnit, { recursive: true });
    fs.mkdirSync(rawProtocol, { recursive: true });
    log.info('collecting V8 coverage into ' + path.join(coverageDir, 'raw'));
  }

  // ---- the service the protocol jobs drive ------------------------------
  //
  // Two shapes, and only the second is started here — see THE SERVICE UNDER
  // THE PROTOCOL JOBS in the header. `external` is what the rest of this
  // function reads to decide who stops it and what the report should say the
  // jobs ran against, because "a container the launcher owns" and "a process
  // this runner owns" are different sentences to a person reading a failure.
  let instance = null;
  let protocolWhy = '';
  const haveProtocolJobs = jobs.some(function (j) {
    return j.suite === 'protocol';
  });
  if (haveProtocolJobs && opts.serviceUrl) {
    // COVERAGE CANNOT COME OUT OF A SERVICE THIS RUNNER ONLY SPEAKS HTTP TO,
    // and saying so here is the whole handling. V8 writes its data from INSIDE
    // the process being measured, to a directory that process can write — so an
    // instrumented run has to be one this runner started. `./run-coverage.sh`
    // never passes --service-url for exactly this reason; somebody who set
    // STS_TEST_SERVICE_URL in their shell and then asked for coverage would
    // otherwise get a report whose protocol column was silently empty, which
    // reads as "the protocols are untested" rather than as "this run could not
    // look".
    //
    // IT IS NOT A STATEMENT ABOUT CONTAINERS, which is a distinction
    // ./run-coverage.sh's own containerized mode rests on: that run puts THIS
    // RUNNER in a container and lets it start the service as a child process
    // in there, so everything measured is again something this process
    // started. What cannot be measured is the service container NEXT DOOR.
    if (wantCoverage) {
      log.warn('coverage was asked for AND a service was handed in with ' +
               '--service-url. The protocol half of the coverage will be ' +
               'EMPTY: V8 collects from inside the process it measures, and ' +
               'this runner cannot reach into a container. Drop ' +
               '--service-url (or use ./run-coverage.sh, which does not pass ' +
               'it) for a coverage run.');
    }
    try {
      await waitForExternalService(opts.serviceUrl, log,
                                   Number(process.env.STS_TEST_SERVICE_WAIT_MS ||
                                          30000));
      instance = { url: opts.serviceUrl, external: true };
      log.info('driving the mock STS at ' + opts.serviceUrl +
               ' (started elsewhere; this runner will not stop it)');
    } catch (e) {
      log.error(e.message);
      protocolWhy = e.message;
      instance = null;
    }
  } else if (haveProtocolJobs) {
    try {
      instance = await service.start({
        log: log,
        logFile: path.join(logsDir, '00-mock-sts-service.log'),
        logLevel: process.env.STS_LOG_LEVEL || '',
        // The appconfig file that service reads, when the caller named one.
        // STS_LOG_LEVEL alone does NOT quieten a run: the six vendored modules
        // under common/vendored/ each build their own bunyan logger at load
        // from the CONFIG_FILE's logLevel, so a `debug` file goes on writing
        // every canonicalization however low this level is. ./local-run-tests.sh
        // picks the file from the level and exports it under this name.
        configFile: process.env.STS_TEST_CONFIG_FILE || '',
        coverageDir: wantCoverage ? rawProtocol : '',
        portBase: process.env.STS_TEST_PORT_BASE || ''
      });
    } catch (e) {
      log.error('could not start a mock STS for the protocol jobs: ' +
                e.message);
      protocolWhy = e.message;
      instance = null;
    }
  }

  // ---- run them ---------------------------------------------------------
  const started = Date.now();
  const results = [];
  let n = 0;
  for (const job of jobs) {
    n++;
    const logName = String(n).padStart(2, '0') + '-' + slug(job.name) + '.log';
    job.logFile = path.join(logsDir, logName);
    job.logName = logName;
    // A JOB THAT COULD NOT BE RUN IS A FAILURE, NOT A SKIP, and this used to
    // be the other way round. The throwaway service failing to start left
    // thirteen jobs marked `skipped`, which the summary counts as passing —
    // so a run in which NOTHING was checked exited zero and said so in small
    // grey text. A skip is for something deliberately left out (--no-browser,
    // --only); an intended job that did not run is a failure, because the
    // thing it was going to check is unchecked either way and only one of
    // those two words makes somebody look.
    if (job.suite === 'protocol' && !instance) {
      const why = protocolWhy || 'no service to drive';
      results.push(Object.assign({}, job, {
        status: 'failed', ms: 0, code: null, assertions: [],
        failures: ['did not run: ' + why],
        why: why
      }));
      continue;
    }
    if (job.suite === 'unit') {
      job.cwd = REPO_ROOT;
      job.cmd = [process.execPath, path.join(TESTS_DIR, 'run.js'),
                 '--only=' + job.file];
      job.env = Object.assign({}, process.env);
      if (wantCoverage) {
        job.env.NODE_V8_COVERAGE = rawUnit;
      }
    } else {
      job.cwd = job.dir;
      job.cmd = [process.execPath, path.join(job.dir, job.file)];
      job.env = Object.assign({}, process.env, {
        // These jobs read an appconfig file of their own for a log level, and
        // `./env/local.js` resolves against the cwd above — which is
        // tests/vendored/, where the vendored copy of that file sits.
        CONFIG_FILE: process.env.PARENT_CONFIG_FILE || './env/local.js',
        // THE MOCK UNDER TEST IS THIS REPOSITORY, WHICH IS THE ONE THING
        // VENDORING CHANGED FOR THESE JOBS.
        //
        // Five of them load the service's own modules in process rather than
        // driving them over HTTP — vc_did.js and the two ldp_vc jobs read the
        // DID and credential modules, sts_jws_verification.js the crypto one.
        // `module_paths.js` finds those by looking for an `sts/` directory
        // BESIDE the tests, because over there this repository is a submodule
        // at that path. Vendored here, there is no such directory: the modules
        // are at the repository root, one level up from tests/.
        //
        // `MOCK_STS_DIR` is that module's own documented override and takes
        // precedence over the submodule search, so this needs no edit to a
        // vendored file — which matters, because an edit here is overwritten
        // by the next --vendor-sync and would come back as four jobs failing
        // at load with a message about a gitlink.
        //
        // It warns that a run with this set "reflects a working copy rather
        // than the commit the gitlink points at". That sentence is written for
        // the parent's stack and reads oddly here, where a working copy is
        // exactly what is under test — ignore it rather than editing it out.
        MOCK_STS_DIR: REPO_ROOT,
        WSTRUST_STS_URL: instance.url,
        OID4VCI_ISSUER_URL: instance.url
      });
      // OURS, not theirs: NODE_V8_COVERAGE on a protocol job would collect the
      // coverage of the parent project's own test code, which is not what this
      // report is about. The service is the instrumented process there.
      delete job.env.NODE_V8_COVERAGE;
    }
    log.info('[' + n + '/' + jobs.length + '] ' + job.suite + ' — ' + job.name);
    /* eslint-disable no-await-in-loop */
    const result = await runJob(job, opts);
    /* eslint-enable no-await-in-loop */
    results.push(result);
    log.info('    ' + (result.status === 'passed' ? 'passed' : 'FAILED') +
             ' in ' + result.ms + 'ms' +
             (result.assertions.length ? ', ' + result.assertions.length +
              ' assertion(s)' : ''));
  }
  const wallMs = Date.now() - started;

  // The service goes down BEFORE the coverage is rendered, because under
  // coverage it writes its data as it exits and rendering before that would
  // report a protocol half that had not been written yet.
  //
  // AN EXTERNAL ONE IS NOT STOPPED HERE. Whoever started it stops it — the
  // launcher's own teardown, which also collects the container's log into
  // this run's logs directory. A second owner is how a run ends by taking
  // down a stack somebody had asked to keep (`--keep-stack`), and the
  // coverage ordering this comment is about does not apply to it anyway,
  // since nothing instrumented is inside it.
  if (instance && !instance.external) {
    await service.stop(instance, log);
  }

  // ---- coverage ---------------------------------------------------------
  let coverageLink = '';
  if (wantCoverage) {
    try {
      const rendered = coverage.render({
        log: log,
        inputs: [{ label: 'unit', dir: rawUnit },
                 { label: 'protocol', dir: rawProtocol }],
        outDir: coverageDir,
        root: REPO_ROOT
      });
      coverageLink = path.relative(runDir, rendered.htmlFile);
      log.info('coverage: ' + rendered.htmlFile);
    } catch (e) {
      // Never fatal. Coverage is a picture OF a run, and a run that passed
      // did not stop being a run that passed because the picture failed.
      log.error('could not render coverage: ' +
                (e && e.stack ? e.stack : e));
    }
  }

  // ---- the reports ------------------------------------------------------
  const meta = {
    runId: RUN_ID,
    host: os.hostname(),
    node: process.version,
    wallMs: wallMs,
    tree: describeTree(REPO_ROOT),
    // The protocol jobs are VENDORED COPIES in tests/vendored/ since
    // 2026-08-28, so they are at this tree's commit like everything else and
    // there is no second checkout to describe. `parentDir` and `parentTree`
    // are kept as empty strings rather than removed, so that an older
    // summary.json and this one have the same shape for anything reading both.
    parentDir: '',
    parentTree: { commit: '' },
    vendored: instance ? path.relative(REPO_ROOT, VENDORED_DIR) : '',
    serviceUrl: instance ? instance.url : '',
    // WHICH OF THE TWO SHAPES ran, so that a report read a week later says
    // what the jobs were actually pointed at rather than leaving it to be
    // inferred from a port number.
    serviceKind: instance ? (instance.external ? 'container' : 'in-process')
                          : '',
    protocolWhy: protocolWhy,
    coverage: coverageLink,
    commandLine: [path.basename(process.argv[0])].concat(
      process.argv.slice(1).map(function (a) {
        return a.indexOf(REPO_ROOT) === 0 ? path.relative(REPO_ROOT, a) : a;
      })).join(' ')
  };
  writeHtml(runDir, results, meta);
  writeXml(runDir, results, meta);
  fs.writeFileSync(path.join(runDir, 'summary.json'),
    JSON.stringify({ meta: meta, jobs: results.map(function (j) {
      return { suite: j.suite, name: j.name, status: j.status, ms: j.ms,
               code: j.code, assertions: j.assertions.length,
               assertionsFailed: j.assertions.filter(function (a) {
                 return !a.ok;
               }).length,
               failures: j.failures, why: j.why || '', log: j.logName };
    }) }, null, 2) + '\n');
  pointLatestAt(opts.reportDir, runDir);

  // ---- say what happened ------------------------------------------------
  const failed = results.filter(function (j) { return j.status === 'failed'; });
  const skipped = results.filter(function (j) { return j.status === 'skipped'; });
  const asserted = results.reduce(function (s, j) {
    return s + j.assertions.length;
  }, 0);
  log.info('---------------------------------------------------------------');
  log.info(results.length + ' job(s), ' + (results.length - failed.length -
           skipped.length) + ' passed, ' + failed.length + ' failed, ' +
           skipped.length + ' skipped, ' + asserted +
           ' assertion(s), ' + (wallMs / 1000).toFixed(1) + 's.');
  failed.forEach(function (j) {
    log.error('FAILED: ' + j.name + ' — ' + j.failures.join('; '));
  });
  skipped.forEach(function (j) {
    log.warn('SKIPPED: ' + j.name + ' — ' + j.why);
  });
  log.info('report: ' + path.join(runDir, 'report.html'));
  log.debug('Leaving main().');
  process.exit(failed.length ? 1 : 0);
}

if (require.main === module) {
  main().catch(function (e) {
    log.error(e && e.stack ? e.stack : String(e));
    process.exit(2);
  });
}

module.exports = { vendoredJobs: vendoredJobs, assertionOf: assertionOf };
