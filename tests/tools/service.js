'use strict';
//
// File: tests/tools/service.js
//
// ===========================================================================
// ONE THROWAWAY COPY OF THIS SERVICE, STARTED AND STOPPED BY A TEST RUN.
//
// Nothing in `tests/` needs this — the whole point of that directory is that
// it drives modules IN PROCESS and binds no port (see tests/CLAUDE.md). This
// module exists for the report generator's OTHER half: the parent project's
// jobs that drive this service over HTTP, which `tests/tools/run-report.js`
// can run against the WORKING TREE rather than against the `sts/` gitlink the
// parent's own suite is pinned to. Those need a listener, and somebody has to
// own its lifetime.
//
// THREE THINGS HERE ARE NOT INCIDENTAL, and each is a mistake this repository
// has already made once:
//
//  1. **NINE PORTS, NOT ONE.** `STS_PORT` alone leaves the KDC, both TLS
//     listeners, LDAP, LDAPS and SPIFFE's two gRPC sockets on their defaults,
//     and a sibling stack is usually already holding them. A run that took
//     8081 from somebody's local stack would be a test suite that breaks the
//     machine it runs on.
//  2. **THE TWO SPIFFE UNIX SOCKETS ARE TURNED OFF RATHER THAN MOVED.** A
//     socket has ONE binder and the default path is shared; this service
//     removes a socket it finds there, warning that it might belong to another
//     copy, and leaves a dead file behind on exit — which leaves the other
//     instance listening on an orphaned inode that only a restart fixes.
//     `..._SOCKET_ENABLED=false` cannot do that; a path that is ignored
//     (because the variable was misspelled) falls back to the shared default,
//     which is exactly how that was discovered.
//  3. **IT IS STOPPED BY THE PID IT STARTED**, never by a pattern. `pkill -f`
//     on anything as generic as `node server.js` reaches into whatever else is
//     running on this machine, and matches the shell issuing it besides.
//
// `persistence.mode` is left at its default of `memory` deliberately: a run
// that persisted would be a run whose second pass started from the first
// pass's leavings.
//
// ---------------------------------------------------------------------------
// THIS IS NO LONGER THE ORDINARY WAY THAT SERVICE IS STARTED, SINCE 2026-08-28.
//
// `./local-run-tests.sh` brings up a CONTAINER from the repository's own
// docker-compose.yml and hands run-report.js its URL, so that the thing under
// test is the IMAGE rather than this machine's node_modules — its header
// argues that at length and it is not repeated here. This module is what
// `--no-docker` uses, what a machine with no docker falls back to, and what a
// COVERAGE run uses of necessity: V8 writes its data from inside the process
// being measured, into a directory that process can write, so an instrumented
// service has to be one this runner started.
//
// So the three numbered decisions above are still live — a coverage run and a
// dockerless run both take every one of them — and the lifetime rule is
// unchanged in both directions: this module's caller stops what this module
// started, and never touches a service it was merely handed.
// ===========================================================================

const { spawn } = require('child_process');
const fs = require('fs');
const net = require('net');
const path = require('path');
const dgram = require('dgram');
const http = require('http');
const https = require('https');

const bunyan = require('bunyan');

const REPO_ROOT = path.resolve(__dirname, '..', '..');

// This module is handed the caller's logger for the lines a PERSON reads (the
// ports it chose, the pid it started) and keeps one of its own for the
// Entering/Leaving pair, so that a function called before the caller's logger
// is in scope still says so.
const log = bunyan.createLogger({ name: 'service',
                                  level: process.env.LOG_LEVEL || 'info' });

// The nine listeners, in the order the offsets are handed out. The NAME is the
// environment variable this service reads for it — README.md's *Configuration*
// table is the authority for these spellings, and a misspelt one is SILENT: it
// is ignored and the listener takes its default port, which is the shared one.
const PORT_VARS = [
  'STS_PORT',
  'STS_TLS_PORT',
  'STS_MTLS_PORT',
  'KRB5_KDC_PORT',
  'KRB5_SERVICE_PORT',
  'LDAP_PORT',
  'LDAPS_PORT',
  'STS_SPIFFE_WORKLOAD_PORT',
  'STS_SPIFFE_SERVER_PORT'
];

// The KDC is the one that binds UDP as well as TCP (RFC 4120 section 7.2.1),
// so a port that is free for TCP is not necessarily free for it.
const UDP_TOO = { KRB5_KDC_PORT: true };

// ---------------------------------------------------------------------------
// Is this port free, on this protocol? Answered by BINDING it, because that is
// the only question that matters and any other way of asking (parsing `ss`,
// keeping a registry) can disagree with the kernel.
// ---------------------------------------------------------------------------
function tcpFree(port) {
  return new Promise(function (resolve) {
    const s = net.createServer();
    s.once('error', function () { resolve(false); });
    s.once('listening', function () {
      s.close(function () { resolve(true); });
    });
    s.listen(port, '0.0.0.0');
  });
}

function udpFree(port) {
  return new Promise(function (resolve) {
    const s = dgram.createSocket('udp4');
    s.once('error', function () { resolve(false); });
    s.once('listening', function () {
      s.close(function () { resolve(true); });
    });
    s.bind(port, '0.0.0.0');
  });
}

// ---------------------------------------------------------------------------
// A block of nine consecutive ports that are ALL free, or null after enough
// tries. Consecutive rather than nine independent ones so that a person
// reading `ss` while a run is going can see at a glance which ports belong to
// it — and so the log line that reports them is one range rather than a list.
// ---------------------------------------------------------------------------
async function findPortBlock(preferredBase, log) {
  log.debug('Entering findPortBlock().');
  const bases = [];
  if (preferredBase) {
    bases.push(Number(preferredBase));
  }
  // A spread of candidates well above the service's own defaults (8081, 88,
  // 389, 636, 8443, 9443, 8092, 8181) so a plain local stack is never touched.
  for (let i = 0; i < 40; i++) {
    bases.push(18100 + Math.floor(Math.random() * 400) * 10);
  }
  for (const base of bases) {
    let allFree = true;
    for (let i = 0; i < PORT_VARS.length; i++) {
      const port = base + i;
      /* eslint-disable no-await-in-loop */
      if (!(await tcpFree(port))) {
        allFree = false;
        break;
      }
      if (UDP_TOO[PORT_VARS[i]] && !(await udpFree(port))) {
        allFree = false;
        break;
      }
      /* eslint-enable no-await-in-loop */
    }
    if (allFree) {
      log.debug('Leaving findPortBlock(). base=' + base);
      return base;
    }
  }
  log.debug('Leaving findPortBlock(). Nothing free.');
  return null;
}

// ---------------------------------------------------------------------------
// The environment one throwaway instance runs under. Everything this service
// binds is moved, both Unix sockets are turned OFF, and the log level is the
// caller's choice — `debug` is this service's default and is what a failing
// job is read from, but it is also about half of its CPU, so a run that is
// only collecting coverage will usually want less.
//
// THE LEVEL TAKES TWO OPTIONS AND NOT ONE, which is easy to get wrong: opts.
// logLevel reaches the loggers config.js registers, and the six VENDORED
// modules under common/vendored/ each build their own from
// `require(process.env.CONFIG_FILE).logLevel` at load and never see it. So a
// caller that wants a quiet service passes opts.configFile as well —
// ./env/test.js is ./env/local.js with `logLevel: "info"` and nothing else
// different. Left empty, the fallback below is the `debug` file and those
// modules write every canonicalization of every signed document.
// ---------------------------------------------------------------------------
function environmentFor(base, opts) {
  log.debug('Entering environmentFor(). base=' + base);
  const env = Object.assign({}, process.env);
  PORT_VARS.forEach(function (name, i) {
    env[name] = String(base + i);
  });
  env.STS_SPIFFE_WORKLOAD_SOCKET_ENABLED = 'false';
  env.STS_SPIFFE_SERVER_SOCKET_ENABLED = 'false';
  env.CONFIG_FILE = opts.configFile || './env/local.js';
  // ---------------------------------------------------------------------
  // TLS ON THE MAIN PORT, DECIDED HERE RATHER THAN LEFT TO THE APPCONFIG
  // FILE (2026-08-30) — and the difference is not tidiness.
  //
  // start() below has to build a URL, and a URL has a SCHEME in it. If this
  // were left to `global.https` in whichever file `opts.configFile` names,
  // this module would be guessing what that file says: a caller pointing at
  // an appconfig file of their own would get a service on https and a URL
  // saying http, which reaches every one of the thirteen protocol jobs as a
  // closed socket. Setting it makes the environment variable — which wins
  // over every appconfig file — the single statement, and schemeFor() below
  // reads back exactly what was set.
  //
  // The DEFAULT is on, matching env/local.js, env/test.js and
  // env/docker-tests.js, and a caller's own STS_HTTPS still wins so that
  // `STS_HTTPS=false ./local-run-tests.sh --no-docker` is a plain-port run.
  // ---------------------------------------------------------------------
  env.STS_HTTPS = String(process.env.STS_HTTPS === undefined
    ? 'true'
    : process.env.STS_HTTPS);
  if (opts.logLevel) {
    // The mock's own level. An EMPTY value is not a harmless default here:
    // bunyan throws `unknown level name: ""` while the service is still
    // loading, so it never starts and nothing names a log level.
    env.STS_LOG_LEVEL = opts.logLevel;
  }
  if (opts.coverageDir) {
    env.NODE_V8_COVERAGE = opts.coverageDir;
  }
  log.debug('Leaving environmentFor().');
  return env;
}

// The scheme the environment above just decided on. One reader of one
// variable, so that the URL this module publishes and the listener the child
// binds can never disagree.
function schemeFor(env) {
  return String(env.STS_HTTPS) === 'true' ? 'https' : 'http';
}

// Liveness over either scheme, with the certificate unjudged — see the note at
// the call site. `https.get`/`http.get` rather than fetch() because fetch's
// dispatcher takes no per-request `rejectUnauthorized`, and a service that
// regenerates its key every start can be trusted by nothing that ran before it.
function probe(url) {
  return new Promise(function (resolve) {
    let target;
    try {
      target = new URL(url);
    } catch (e) {
      resolve(0);
      return;
    }
    const mod = target.protocol === 'https:' ? https : http;
    const req = mod.get({
      host: target.hostname,
      port: target.port,
      path: target.pathname + target.search,
      rejectUnauthorized: false,
      timeout: 5000
    }, function (res) {
      res.resume();
      resolve(res.statusCode || 0);
    });
    req.on('error', function () {
      resolve(0);
    });
    req.on('timeout', function () {
      req.destroy();
      resolve(0);
    });
  });
}

// ---------------------------------------------------------------------------
// Start it, and do not return until it ANSWERS. `up` is a request that got a
// response, not a process that was spawned: this service binds nine listeners
// and reads its store before the first of them, so "the child exists" and "the
// service is ready" are seconds and several failure modes apart.
// ---------------------------------------------------------------------------
async function start(opts) {
  const log = opts.log;
  log.debug('Entering start().');
  const base = await findPortBlock(opts.portBase, log);
  if (!base) {
    log.debug('Leaving start(). No free ports.');
    throw new Error('no block of ' + PORT_VARS.length +
                    ' free ports could be found for a throwaway instance');
  }
  const env = environmentFor(base, opts);
  const url = schemeFor(env) + '://localhost:' + base;
  // Under coverage the entry point is a WRAPPER rather than server.js, and the
  // reason is in that file: V8 writes its coverage when the process exits
  // cleanly, and a service killed with SIGTERM does not exit cleanly, so the
  // whole protocol half of the report would be empty with nothing saying so.
  const entry = opts.coverageDir
    ? path.join(__dirname, 'coverage_entry.js')
    : path.join(REPO_ROOT, 'server.js');
  const out = fs.openSync(opts.logFile, 'a');
  const child = spawn(process.execPath, [entry], {
    cwd: REPO_ROOT,
    env: env,
    stdio: ['ignore', out, out]
  });
  let exited = null;
  child.on('exit', function (code, signal) {
    exited = { code: code, signal: signal };
  });
  log.info('starting a throwaway mock STS on ' + url + ' (ports ' + base +
           '-' + (base + PORT_VARS.length - 1) + ', pid ' + child.pid + ')');
  const deadline = Date.now() + (opts.readyTimeoutMs || 60000);
  while (Date.now() < deadline) {
    if (exited) {
      log.debug('Leaving start(). The child exited.');
      throw new Error('the mock STS exited before it answered (code ' +
                      exited.code + ', signal ' + exited.signal + '); see ' +
                      opts.logFile);
    }
    // `fetch()` until 2026-08-30, and it could not survive this service
    // serving TLS: the certificate is self-signed and regenerated on every
    // start, so the first request would fail verification for the whole
    // timeout and the service would be reported as never having answered.
    // The question here is whether the port answers, not whether it is
    // trustworthy — the JOBS get a real anchor, from tests/tools/trust.js.
    /* eslint-disable no-await-in-loop */
    const answered = (await probe(url + '/')) > 0;
    /* eslint-enable no-await-in-loop */
    if (answered) {
      log.info('the throwaway mock STS is answering on ' + url);
      log.debug('Leaving start(). Up.');
      return { base: base, url: url, child: child, pid: child.pid,
               logFile: opts.logFile };
    }
    await new Promise(function (r) { setTimeout(r, 200); });
  }
  try {
    process.kill(child.pid, 'SIGKILL');
  } catch (e) {
    // Already gone. Nothing to do, and failing here would replace the useful
    // message below with a useless one.
  }
  log.debug('Leaving start(). Timed out.');
  throw new Error('the mock STS did not answer on ' + url + ' in time; see ' +
                  opts.logFile);
}

// ---------------------------------------------------------------------------
// Stop it, BY PID, and wait for it to actually go. SIGTERM first because that
// is what the coverage wrapper listens for; SIGKILL only after a grace period,
// and if it comes to that under coverage the protocol half of the report will
// be short, which the caller is told.
// ---------------------------------------------------------------------------
async function stop(instance, log) {
  log.debug('Entering stop().');
  if (!instance || !instance.child) {
    log.debug('Leaving stop(). Nothing to stop.');
    return true;
  }
  const child = instance.child;
  if (child.exitCode !== null || child.signalCode !== null) {
    log.debug('Leaving stop(). Already gone.');
    return true;
  }
  const gone = new Promise(function (resolve) {
    child.once('exit', function () { resolve(true); });
  });
  try {
    process.kill(instance.pid, 'SIGTERM');
  } catch (e) {
    log.debug('Leaving stop(). It was already gone: ' + e.message);
    return true;
  }
  const graceful = await Promise.race([
    gone,
    new Promise(function (r) { setTimeout(function () { r(false); }, 10000); })
  ]);
  if (graceful) {
    log.info('the throwaway mock STS (pid ' + instance.pid + ') has stopped');
    log.debug('Leaving stop(). Graceful.');
    return true;
  }
  log.warn('pid ' + instance.pid + ' did not stop on SIGTERM; killing it. ' +
           'Under coverage its data may be short.');
  try {
    process.kill(instance.pid, 'SIGKILL');
  } catch (e) {
    // Raced with its own exit, which is the outcome we wanted anyway.
  }
  await Promise.race([
    gone,
    new Promise(function (r) { setTimeout(r, 5000); })
  ]);
  log.debug('Leaving stop(). Killed.');
  return false;
}

module.exports = {
  PORT_VARS: PORT_VARS,
  REPO_ROOT: REPO_ROOT,
  findPortBlock: findPortBlock,
  environmentFor: environmentFor,
  schemeFor: schemeFor,
  start: start,
  stop: stop
};
