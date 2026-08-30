'use strict';
//
// File: worker_pool.js
//
// ---------------------------------------------------------------------------
// THE FRONT PROCESS'S END OF THE POOL: FORK, ROUTE, RESTART, DRAIN.
//
// `worker.js` says why this exists and what a worker may not hold. This file is
// the half that runs where the sockets are, and everything in it follows from
// one sentence: **the front process owns all the state, so a worker is a place
// to put a computation and nothing else.** That is what makes the routing below
// a preference rather than a correctness requirement, what makes a dead worker
// a thing to replace rather than to recover, and what makes `workers.count = 0`
// — compute in this process — a supported configuration rather than a
// degraded one.
//
// ---------------------------------------------------------------------------
// NOTHING IS FORKED UNTIL THE FIRST JOB, and that is deliberate.
//
// A process that never signs a post-quantum token never pays for a pool, which
// matters in more places than it looks: the parent project loads these modules
// IN PROCESS to drive the KDC, `env/generate_defaults.js` requires config.js on
// its way to writing a file, and this repository's own tests require crypto.js
// to assert a contract. A pool forked at require time would leave child
// processes behind every one of those, and the first symptom would be a test
// runner that never exits — which names nothing.
//
// It also means the pool re-reads `workers.count` on every call, so the setting
// is genuinely runtime: raising it from /admin/config forks the difference on
// the next signature, lowering it retires the surplus, and setting it to 0
// drains the pool and computes here. A table that said `runtime: true` and
// meant "on restart" is the lie config.js refuses to tell about a bound port,
// and it would be the same lie here.
//
// ---------------------------------------------------------------------------
// ROUTING: AFFINITY WHEN A SESSION IS NAMED, LEAST-LOADED OTHERWISE.
//
// Jobs belonging to one authenticated session go to one worker. Since a worker
// remembers nothing, this buys locality and predictability rather than
// correctness — the same session's signatures queue behind each other instead
// of interleaving across the pool, so a slow one is slow for that caller and
// not for a stranger. Everything else goes to the worker with the fewest jobs
// in flight, ties broken by the one that has done the least work, which spreads
// a burst (the eleven keys of a first JWKS fetch) across the pool instead of
// piling it on whichever child was forked first.
//
// THE AFFINITY MAP IS CAPPED AND FORGETS THE OLDEST, and it can be: forgetting
// an entry re-routes the next job and loses nothing, because there was nothing
// in that worker to lose. An uncapped map keyed by session id on a service
// whose sessions are minted by a test suite is a leak with a slow fuse.
//
// ---------------------------------------------------------------------------
// A WORKER THAT DIES TAKES ITS JOBS' PROMISES WITH IT, AND SAYS SO.
//
// Every job in flight on a child that exits is rejected with a sentence naming
// the pid and how it went, because the alternative — a promise that never
// settles — is a request that hangs, which is precisely the symptom this whole
// change exists to remove. The worker is dropped and the next job forks a
// replacement.
//
// **What is NOT done is restarting in a loop.** A child that exits immediately
// and repeatedly is a worker that cannot start — a broken CONFIG_FILE, a
// missing dependency, a machine out of memory — and forking it again forever
// would turn a service that works slowly into a service that does nothing but
// fork. After `QUICK_EXIT_LIMIT` short-lived exits in a row the pool gives up
// on children and computes in the front process, which is `workers.count = 0`
// behaviour: slower, blocking, and CORRECT. It says so at `error` level once,
// with the reason, and one successful job resets the count.
// ---------------------------------------------------------------------------

const path = require('path');
const child_process = require('child_process');
const bunyan = require('bunyan');
const config = require('./config');
const worker = require('./worker');

const log = bunyan.createLogger({
  name: 'worker_pool',
  level: (function () {
    try {
      return config.value('global.logLevel') || 'info';
    } catch (e) {
      return 'info';
    }
  })()
});

const WORKER_MODULE = path.join(__dirname, 'worker.js');

// A worker that exits within this long of being forked, having finished no
// job, did not fail — it never started. Two seconds is far longer than a fork
// and a require take and far shorter than any job here.
const QUICK_EXIT_MS = 2000;
const QUICK_EXIT_LIMIT = 3;

// How many sessions the affinity map remembers. See the header: forgetting one
// costs a re-route and nothing else.
const AFFINITY_MAX = 1000;

// The live children. Each is
//   { child, pid, inFlight: Map(id -> {resolve, reject, kind}), startedAt,
//     jobsDone }
let workers = [];

// session id -> pid. Insertion-ordered, which is what makes the cap a
// least-recently-ADDED eviction without a second structure.
const affinity = new Map();

let nextJobId = 1;
let quickExits = 0;
let givenUpOnChildren = false;
let stopped = false;

// ---------------------------------------------------------------------------
// The configured size. `workers.count` is `perProcess`, so a realm cannot carry
// one — see the flag in config.js's table and checkRealmOverride() in
// realms.js. A pool is a property of the PROCESS, and a realm that could resize
// it would be resizing every other realm's too.
// ---------------------------------------------------------------------------
function size() {
  log.debug('Entering size().');
  let wanted = 0;
  try {
    wanted = parseInt(config.value('workers.count'), 10);
  } catch (e) {
    // A module loaded with no configuration at all — which is how the parent
    // project's in-process jobs load this tree. Computing here is the right
    // answer for one of those and not a fallback that hides anything.
    log.debug('Leaving size(). No configuration; 0.');
    return 0;
  }
  if (!(wanted >= 0)) {
    wanted = 0;
  }
  log.debug('Leaving size(). ' + wanted + '.');
  return wanted;
}

// ---------------------------------------------------------------------------
// Forking one worker, and everything that has to be true about it afterwards.
//
// THE CHANNEL IS UNREFERENCED WHILE THE WORKER IS IDLE, which is the property
// that keeps this pool from changing when the front process exits. An IPC
// channel is a referenced handle, so a pool of two idle children would hold
// `node -e "require('./common/crypto')"` open for ever. It is referenced again
// the moment a job goes out and unreferenced when the last one comes back, so a
// process is only ever held open by work it is actually waiting for.
// ---------------------------------------------------------------------------
function fork() {
  log.debug('Entering fork().');
  const child = child_process.fork(WORKER_MODULE, [], {
    // The structured clone, so a Buffer crosses as a Buffer. Under node's
    // default JSON serialization a 32,000-byte SLH-DSA signature becomes a JSON
    // array of 32,000 numbers, which is about four times the bytes and a parse
    // at each end — on the exact path this pool exists to make cheap.
    serialization: 'advanced',
    // stdout and stderr are the front process's, so a worker's bunyan lines
    // land in the same stream as everything else and a reader does not have to
    // be told where they went. They carry the pid; see worker.js.
    stdio: ['ignore', 'inherit', 'inherit', 'ipc']
  });
  const entry = { child: child, pid: child.pid, inFlight: new Map(),
                  startedAt: Date.now(), jobsDone: 0 };
  child.unref();
  if (child.channel) {
    child.channel.unref();
  }
  child.on('message', function (message) {
    receive(entry, message);
  });
  child.on('error', function (err) {
    // An error on the channel is not necessarily fatal to the child, but it is
    // fatal to anything this process is waiting on: it means a message did not
    // get there or did not come back.
    log.warn('worker_pool: the channel to worker ' + entry.pid +
             ' failed: ' + err.message);
  });
  child.on('exit', function (code, signal) {
    reap(entry, code, signal);
  });
  workers.push(entry);
  log.info('worker_pool: forked worker ' + child.pid + '. ' + workers.length +
           ' of ' + size() + ' running.');
  log.debug('Leaving fork().');
  return entry;
}

// One worker's answer. `id` is the pool's, so a reply for a job this process
// has already given up on (its worker died and it was rejected, and the child
// answered on its way out) is dropped rather than resolving a settled promise.
function receive(entry, message) {
  log.debug('Entering receive(). id=' + (message ? message.id : '(none)'));
  const pending = entry.inFlight.get(message.id);
  if (!pending) {
    log.debug('Leaving receive(). Nothing is waiting for that id.');
    return;
  }
  entry.inFlight.delete(message.id);
  entry.jobsDone++;
  // One job that finished is proof that forking works here, whatever happened
  // before it. See the header.
  quickExits = 0;
  unrefIfIdle(entry);
  if (message.ok) {
    pending.resolve(message.result);
    log.debug('Leaving receive(). Resolved.');
    return;
  }
  const err = new Error(message.error);
  err.name = message.errorName || 'Error';
  pending.reject(err);
  log.debug('Leaving receive(). Rejected.');
}

// A child that has gone. Everything it was carrying is rejected HERE, because a
// promise nobody settles is a request that hangs.
function reap(entry, code, signal) {
  log.debug('Entering reap(). pid=' + entry.pid);
  workers = workers.filter(function (one) { return one !== entry; });
  affinity.forEach(function (pid, session) {
    if (pid === entry.pid) {
      affinity.delete(session);
    }
  });
  const lost = Array.from(entry.inFlight.values());
  entry.inFlight.clear();
  const how = signal ? 'was killed with ' + signal
                     : 'exited with code ' + code;
  const shortLived = (Date.now() - entry.startedAt) < QUICK_EXIT_MS &&
                     entry.jobsDone === 0;
  if (shortLived && !stopped) {
    quickExits++;
  }
  lost.forEach(function (pending) {
    pending.reject(new Error('the worker process computing this ' +
      pending.kind + ' ' + how + ' before it answered. Nothing was left in ' +
      'it — a worker holds no state — so this request can simply be made ' +
      'again.'));
  });
  if (lost.length) {
    log.warn('worker_pool: worker ' + entry.pid + ' ' + how + ' with ' +
             lost.length + ' job(s) in flight; all of them were failed.');
  } else {
    log.info('worker_pool: worker ' + entry.pid + ' ' + how + '.');
  }
  if (quickExits >= QUICK_EXIT_LIMIT && !givenUpOnChildren) {
    givenUpOnChildren = true;
    log.error('worker_pool: ' + quickExits + ' worker processes in a row ' +
      'exited within ' + QUICK_EXIT_MS + 'ms without finishing a job, so ' +
      'this service has STOPPED FORKING THEM and is computing post-quantum ' +
      'signatures in the process that holds the sockets — which is what ' +
      'workers.count=0 means: correct, and blocking for as long as each one ' +
      'takes. A worker that cannot start is usually a CONFIG_FILE it cannot ' +
      'read or a machine out of memory; ' + WORKER_MODULE + ' run by hand ' +
      'says which. One job finishing resets this.');
  }
  log.debug('Leaving reap().');
}

// ---------------------------------------------------------------------------
// A worker is REFERENCED only while it is owed an answer, and BOTH halves have
// to be — the child process handle and the IPC channel.
//
// Referencing the channel alone is not enough and the way that failed is worth
// keeping: with the process handle left unreferenced, node drained its event
// loop the instant a worker was SIGKILLed, so the `exit` that fails that
// worker's jobs was never delivered and the promise never settled. It looked
// like a hang. It was also LOG-LEVEL DEPENDENT — at `debug`, bunyan's writes to
// a piped stdout were themselves enough to hold the loop open, so the same code
// passed at one level and hung at another, which is the shape of bug that
// survives a test suite.
// ---------------------------------------------------------------------------
function refWhileWorking(entry) {
  log.debug('Entering refWhileWorking(). pid=' + entry.pid);
  entry.child.ref();
  if (entry.child.channel) {
    entry.child.channel.ref();
  }
  log.debug('Leaving refWhileWorking().');
}

function unrefIfIdle(entry) {
  log.debug('Entering unrefIfIdle(). pid=' + entry.pid);
  if (entry.inFlight.size === 0) {
    entry.child.unref();
    if (entry.child.channel) {
      entry.child.channel.unref();
    }
  }
  log.debug('Leaving unrefIfIdle().');
}

// ---------------------------------------------------------------------------
// Bring the pool to the configured size. Called from run() and nowhere else,
// which is what makes the whole thing lazy.
// ---------------------------------------------------------------------------
function ensurePool() {
  log.debug('Entering ensurePool().');
  const wanted = (stopped || givenUpOnChildren) ? 0 : size();
  while (workers.length > wanted) {
    // The idlest first, so shrinking the pool costs the fewest in-flight jobs.
    // A worker still carrying work is disconnected rather than killed: it
    // answers what it has and then exits on `disconnect`. See worker.js.
    const idlest = workers.slice().sort(function (a, b) {
      return a.inFlight.size - b.inFlight.size;
    })[0];
    retire(idlest);
  }
  while (workers.length < wanted) {
    fork();
  }
  log.debug('Leaving ensurePool(). ' + workers.length + ' worker(s).');
  return workers;
}

// Take a worker out of the pool and let it finish. It stays in `workers` until
// its `exit` arrives — reap() removes it — so a job already sent to it is
// still tracked and still answered.
function retire(entry) {
  log.debug('Entering retire(). pid=' + entry.pid);
  workers = workers.filter(function (one) { return one !== entry; });
  affinity.forEach(function (pid, session) {
    if (pid === entry.pid) {
      affinity.delete(session);
    }
  });
  if (entry.inFlight.size === 0) {
    entry.child.disconnect();
    log.debug('Leaving retire(). Disconnected an idle worker.');
    return;
  }
  // Still working. Disconnecting now would close the channel under the answer
  // it is about to send, so it is left to reap() — which is reached either way,
  // because a worker whose last job comes back is a worker nothing will send to
  // again.
  entry.retiring = true;
  log.debug('Leaving retire(). ' + entry.inFlight.size + ' job(s) to finish.');
}

// Fewest in flight, then least work done. Both halves matter: the first keeps a
// long signature from being queued behind another, and the second stops a burst
// of eleven jobs landing on one child because they were all dispatched before
// any of them started.
function leastLoaded() {
  log.debug('Entering leastLoaded().');
  const choice = workers.slice().sort(function (a, b) {
    if (a.inFlight.size !== b.inFlight.size) {
      return a.inFlight.size - b.inFlight.size;
    }
    return a.jobsDone - b.jobsDone;
  })[0];
  log.debug('Leaving leastLoaded(). pid=' + (choice ? choice.pid : '(none)'));
  return choice;
}

// The worker this session's jobs go to, remembered. A session whose worker has
// gone gets a new one, which is the whole of the recovery story.
function workerFor(session) {
  log.debug('Entering workerFor(). session=' + (session || '(none)'));
  if (!session) {
    log.debug('Leaving workerFor(). No session named.');
    return leastLoaded();
  }
  const key = String(session);
  const pid = affinity.get(key);
  const held = pid ? workers.filter(function (one) {
    return one.pid === pid;
  })[0] : null;
  if (held) {
    log.debug('Leaving workerFor(). Held affinity to ' + held.pid + '.');
    return held;
  }
  const chosen = leastLoaded();
  if (chosen) {
    if (affinity.size >= AFFINITY_MAX) {
      affinity.delete(affinity.keys().next().value);
    }
    affinity.delete(key);
    affinity.set(key, chosen.pid);
  }
  log.debug('Leaving workerFor(). New affinity to ' +
            (chosen ? chosen.pid : '(none)') + '.');
  return chosen;
}

// ---------------------------------------------------------------------------
// THE ONE ENTRY POINT. `opts.session` names an authenticated session for
// affinity and may be omitted.
//
// It always returns a promise, whether the work went to a child or was done
// here, because a caller that had to know which would be a caller that has to
// know what `workers.count` is set to.
// ---------------------------------------------------------------------------
function run(kind, job, opts) {
  log.debug('Entering run(). kind=' + kind);
  const options = opts || {};
  if (worker.JOB_KINDS.indexOf(kind) === -1) {
    log.debug('Leaving run(). No such job kind.');
    return Promise.reject(new Error('worker_pool: there is no "' + kind +
      '" job. The pool runs ' + worker.JOB_KINDS.join(', ') + '.'));
  }
  ensurePool();
  const entry = workerFor(options.session);
  if (!entry) {
    // workers.count is 0, the pool has given up on children, or this process is
    // shutting down. The SAME job table runs, in this process — see the note at
    // the foot of worker.js. Blocking, and the only thing that changes about
    // the answer is how long the event loop was busy producing it.
    log.debug('Leaving run(). Computing in this process.');
    try {
      return Promise.resolve(worker.runJob(kind, job));
    } catch (e) {
      return Promise.reject(e);
    }
  }
  const id = nextJobId++;
  const promise = new Promise(function (resolve, reject) {
    entry.inFlight.set(id, { resolve: resolve, reject: reject, kind: kind });
  });
  refWhileWorking(entry);
  try {
    entry.child.send({ id: id, kind: kind, job: job });
  } catch (e) {
    // The channel closed between the choice and the send — a worker that died
    // in that window. reap() has not run yet or it would not be in the pool, so
    // the rejection is made here and the entry cleaned up.
    const pending = entry.inFlight.get(id);
    entry.inFlight.delete(id);
    unrefIfIdle(entry);
    if (pending) {
      pending.reject(new Error('the worker process this ' + kind + ' was ' +
        'sent to had already gone: ' + e.message + '. A worker holds no ' +
        'state, so this request can simply be made again.'));
    }
  }
  log.debug('Leaving run(). id=' + id + ' on worker ' + entry.pid + '.');
  return promise;
}

// ---------------------------------------------------------------------------
// DRAIN, for shutdown. Every worker is disconnected; one still holding a job is
// left to answer it first, and killed if it will not.
//
// It resolves rather than rejects on a worker that had to be killed: this is
// called from the SIGTERM handler, where the caller's only remaining move is to
// exit, and a rejection there would replace the sentence that says what was
// flushed with a stack trace.
// ---------------------------------------------------------------------------
function stop(timeoutMs) {
  log.debug('Entering stop().');
  stopped = true;
  const limit = timeoutMs === undefined ? 5000 : timeoutMs;
  const going = workers.slice();
  if (!going.length) {
    log.debug('Leaving stop(). Nothing was running.');
    return Promise.resolve({ stopped: 0, killed: 0 });
  }
  log.info('worker_pool: draining ' + going.length + ' worker(s).');
  return new Promise(function (resolve) {
    let killed = 0;
    // NOT unreferenced, for the same reason the children are referenced below:
    // this timer is the only thing that will kill a worker which will not go,
    // and a timer that let the process exit first would leave one behind.
    // done() clears it, so it holds nothing open a moment longer than the
    // drain does.
    const timer = setTimeout(function () {
      going.forEach(function (entry) {
        if (entry.child.exitCode === null && entry.child.signalCode === null) {
          killed++;
          log.warn('worker_pool: worker ' + entry.pid + ' did not finish ' +
                   'within ' + limit + 'ms and was killed. Whatever it was ' +
                   'computing is lost, which costs nothing: a worker holds ' +
                   'no state.');
          entry.child.kill('SIGKILL');
        }
      });
      done();
    }, limit);
    let left = going.length;
    function done() {
      left = 0;
      clearTimeout(timer);
      workers = [];
      affinity.clear();
      log.debug('Leaving stop().');
      resolve({ stopped: going.length - killed, killed: killed });
    }
    going.forEach(function (entry) {
      // REFERENCED FOR THE LENGTH OF THE DRAIN, and this is the one place that
      // has to be. Everything above unreferences a child so that an idle pool
      // never holds the front process open — which means that with nothing else
      // on the event loop, the front process would exit here BEFORE the
      // children it is waiting for, and this promise would never settle. It
      // did exactly that the first time it was run.
      refWhileWorking(entry);
      entry.child.on('exit', function () {
        left--;
        if (left === 0) {
          done();
        }
      });
      if (entry.inFlight.size === 0) {
        entry.child.disconnect();
      }
    });
  });
}

// What the pool is doing, for the tests and for anything that wants to report
// it. A copy, so a reader cannot reach into the live entries.
function stats() {
  log.debug('Entering stats().');
  const out = {
    configured: size(),
    running: workers.length,
    inProcess: workers.length === 0,
    gaveUp: givenUpOnChildren,
    affinities: affinity.size,
    workers: workers.map(function (one) {
      return { pid: one.pid, inFlight: one.inFlight.size,
               jobsDone: one.jobsDone };
    })
  };
  log.debug('Leaving stats(). ' + out.running + ' worker(s).');
  return out;
}

// Forget that the pool gave up, and let a drained pool be used again. It exists
// for the tests, which have to drive the give-up path and then keep going, and
// for nothing else — the service itself gives up once and says so.
function reset() {
  log.debug('Entering reset().');
  givenUpOnChildren = false;
  quickExits = 0;
  stopped = false;
  log.debug('Leaving reset().');
}

module.exports = {
  size: size,
  run: run,
  stop: stop,
  stats: stats,
  reset: reset
};

// ---------------------------------------------------------------------------
// AND THE LAST LINE ARMS pq_jose.js. **REQUIRING THIS MODULE IS WHAT MAKES
// ITS ASYNCHRONOUS HALF USE A POOL**, which is the same shape as rule 1 in the
// root CLAUDE.md — requiring a protocol module is what registers its routes.
//
// It is here rather than at whichever call site happened to want it first, and
// that is a correction rather than a preference: common/crypto.js filled the
// slot for one afternoon, and a process that required pq_jose.js WITHOUT
// crypto.js — which is every test of the post-quantum code, and was the first
// draft of tests/worker_pool.js — then computed everything in itself while
// reporting no pool and no error. A capability that is present or absent
// depending on which unrelated module was loaded first is not a capability.
//
// The direction is the one pq_jose.js's own header argues for: this module
// requires worker.js, which requires pq_jose.js, so the reference has to be
// handed DOWN rather than required back up. And a WORKER PROCESS never reaches
// this line, because a child requires worker.js and worker.js does not require
// this file — so `signAsync()` inside a worker computes in the worker, which is
// what a worker is for.
// ---------------------------------------------------------------------------
require('./pq_jose').setWorkerPool(module.exports);
