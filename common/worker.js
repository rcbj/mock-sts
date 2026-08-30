'use strict';
//
// File: worker.js
//
// ---------------------------------------------------------------------------
// ONE CHILD PROCESS OF THE POOL, AND THE TABLE OF EVERYTHING IT WILL DO.
//
// This service is one node process and it owns six listener families — the
// express app, the KDC on TCP and UDP 88, the Kerberos service on 8888, the
// LDAP directory, two gRPC surfaces and two HTTPS endpoints. Node runs all of
// them on ONE THREAD, so a synchronous computation does not slow this service
// down, it STOPS it.
//
// Post-quantum signing is that computation. Stalls of 14.6, 15.4, 17.8 and 23.3
// seconds were measured on 2026-08-29 while the parent project's suite ran
// against this service — an SLH-DSA-SHAKE-128s signature and two composite
// verifications — and for those seconds this service answered nobody. A KDC
// that does not answer looks from the outside exactly like a KDC that is not
// there, which is why NOT ONE of the failures those stalls caused named one:
// they were a Kerberos reply that never came, a Populate button never drawn, a
// login screen that never arrived, and a refresh request whose socket this
// service closed on its way back out.
//
// So the computation moved here. `worker_pool.js` forks copies of this file and
// feeds them jobs; this file does the work and hands the bytes back.
//
// ---------------------------------------------------------------------------
// A WORKER HOLDS NO STATE, AND THAT IS LOAD-BEARING RATHER THAN A
// SIMPLIFICATION.
//
// The state this service keeps is read and written ACROSS sessions, not within
// one: `operatorConfig` (common/config.js), `realms` (common/realms.js), the
// KDC `replayCache` (kerberos/krb5_service.js), `digestNonces` /
// `hobaChallenges` / `hobaSeen` (scim/scim_auth.js), `principals`
// (kerberos/krb5_principals.js), the SPIFFE registry, and the tokens this
// service mints — minted on one worker and introspected from another. Split N
// ways those fail SILENTLY: replay detection that stops detecting, a config
// change that lands on one worker of four, an introspection 404 for a token
// that exists.
//
// Session affinity does not fix that; it only narrows the window. So the front
// process keeps every one of them and a worker is handed everything it needs in
// the job and hands back everything it produced. **Two workers can never
// disagree about anything because neither remembers anything** — which is also
// why a worker that dies is replaced rather than recovered: there is nothing in
// it to recover.
//
// ---------------------------------------------------------------------------
// WHY A PROCESS AND NOT A worker_thread.
//
// The primitives are @noble's, which is pure JavaScript with no native binding,
// so a thread would run them perfectly well and would cost less to start. What
// a thread does not give is the isolation this change exists for: a worker
// thread shares the process, so its own out-of-memory or stack overflow ends
// the service — the exact failure being engineered away — and a thread wedged
// in a tight loop cannot be killed, only asked. A child can be killed and
// replaced without the front process letting go of a single socket, which is
// the property that makes the restart path in `worker_pool.js` a paragraph
// rather than a design.
//
// ---------------------------------------------------------------------------
// THE JOB TABLE IS EXPORTED, AND THE POOL RUNS THIS SAME TABLE IN PROCESS when
// `workers.count` is 0. That is what makes "a pooled signature and an unpooled
// one are the same bytes" true BY CONSTRUCTION rather than by a test that
// happens to pass: there is one implementation of each job and the only
// question is which process it runs in. The wiring below is guarded on
// `require.main === module` for that reason — requiring this file to reach the
// table must not turn the requiring process into a worker.
// ---------------------------------------------------------------------------

// FIRST, and for the reason server.js gives: this process was forked, so it
// inherited a CONFIG_FILE that may still be the relative path the operator
// typed, and a relative require resolves against the directory of the module
// doing the requiring. Idempotent, so the parent having done it costs nothing.
require('./config_file').resolveConfigFile();

const bunyan = require('bunyan');
const config = require('./config');
const pqJose = require('./pq_jose');

// The module's own logger, made the way pq_jose.js makes its own. A worker's
// lines are named `worker` and carry the pid, because the whole point of
// several of them is that a reader has to be able to tell which one spoke.
const log = bunyan.createLogger({
  name: 'worker',
  level: (function () {
    try {
      return config.value('global.logLevel') || 'info';
    } catch (e) {
      return 'info';
    }
  })()
});

// ---------------------------------------------------------------------------
// THE JOBS. One entry per unit of work the front process may hand out.
//
// Each takes the job object and returns its result, both of which cross the IPC
// channel — so everything in either must survive `serialization: 'advanced'`,
// which is what `worker_pool.js` forks with. That is the reason binary travels
// as a Buffer here rather than as base64: the structured clone carries a Buffer
// whole, while the JSON serialization node uses by default would turn a
// 32,000-byte SLH-DSA signature into a JSON array of 32,000 numbers — about
// four times the bytes and a parse at each end.
//
// A job function is SYNCHRONOUS on purpose. Blocking is what a worker is for,
// and a table of promises here would invite a second job onto a process that is
// already computing — which does not make it finish sooner and makes the pool's
// idea of "least loaded" a fiction.
// ---------------------------------------------------------------------------
const JOBS = {

  // A post-quantum or composite signature. `priv` is the private key AS
  // pq_jose.js defines it — a 32-byte ML-DSA seed, an SLH-DSA secret key, or a
  // composite's seed || traditional key.
  'pq.sign': function (job) {
    log.debug('Entering pq.sign(). alg=' + job.alg);
    const signature = pqJose.sign(job.alg, job.priv, job.message);
    log.debug('Leaving pq.sign(). ' + signature.length + ' bytes.');
    return { signature: signature };
  },

  // A verification. It answers `ok: false` for a signature that does not hold
  // up and THROWS only for one it could not attempt — an unknown algorithm —
  // which is exactly what pq_jose.verify() does, and the difference matters to
  // the caller: a bad signature is an answer and an unreadable algorithm is a
  // defect.
  'pq.verify': function (job) {
    log.debug('Entering pq.verify(). alg=' + job.alg);
    const ok = pqJose.verify(job.alg, job.pub, job.message, job.signature);
    log.debug('Leaving pq.verify(). ok=' + ok);
    return { ok: ok };
  },

  // A key pair. Eleven of these are what a realm's first JWKS fetch costs, and
  // nearly all of the 1.9 seconds is one SLH-DSA-SHAKE keygen.
  'pq.generate': function (job) {
    log.debug('Entering pq.generate(). alg=' + job.alg);
    const pair = pqJose.generate(job.alg);
    log.debug('Leaving pq.generate(). pub=' + pair.pub.length + ' bytes.');
    return { pub: pair.pub, priv: pair.priv };
  }
};

// The kinds this table answers to, so the pool can refuse an unknown one
// BEFORE forking anything and name what it does know.
const JOB_KINDS = Object.keys(JOBS);

// ---------------------------------------------------------------------------
// Run one job, in whichever process is asking. The pool calls this directly
// when `workers.count` is 0, and the message handler below calls it in a child.
//
// It does not catch: the two callers want the failure in different shapes — a
// rejected promise in one process, a message on the channel in the other — and
// a catch here would have to invent a third to hand them both.
// ---------------------------------------------------------------------------
function runJob(kind, job) {
  log.debug('Entering runJob(). kind=' + kind);
  const fn = JOBS[kind];
  if (!fn) {
    log.debug('Leaving runJob(). No such job.');
    throw new Error('worker: there is no "' + kind + '" job. This process ' +
      'does ' + JOB_KINDS.join(', ') + '.');
  }
  const result = fn(job);
  log.debug('Leaving runJob(). kind=' + kind);
  return result;
}

// ---------------------------------------------------------------------------
// THE CHILD HALF. Everything below runs only in a forked copy.
//
// The protocol is deliberately tiny and has no version in it: both ends are
// this repository at the same commit, forked from the same file by the module
// beside it, so a mismatch is not a thing that can happen at run time.
//
//   in    { id, kind, job }
//   out   { id, ok: true, result }  |  { id, ok: false, error, errorName }
//
// A FAILED JOB IS A MESSAGE AND NOT A CRASH. A signature this service cannot
// make is an answer the caller has to turn into a 400 with a sentence in it,
// and a worker that exited instead would turn every one of those into a
// restart plus a request that never got a reply.
// ---------------------------------------------------------------------------
function handleMessage(message) {
  log.debug('Entering handleMessage(). kind=' +
            (message && message.kind ? message.kind : '(none)'));
  const id = message ? message.id : null;
  let result = null;
  try {
    result = runJob(message.kind, message.job);
  } catch (e) {
    log.warn('worker ' + process.pid + ': the ' +
             (message && message.kind ? message.kind : 'unknown') +
             ' job failed: ' + e.message);
    process.send({ id: id, ok: false, error: e.message,
                   errorName: e.name || 'Error' });
    log.debug('Leaving handleMessage(). Failed.');
    return;
  }
  process.send({ id: id, ok: true, result: result });
  log.debug('Leaving handleMessage(). Answered.');
}

function startWorker() {
  log.debug('Entering startWorker().');
  process.on('message', handleMessage);
  // The front process closing the channel is how a worker is told to go: see
  // `drain()` in worker_pool.js. Exiting here rather than waiting to be killed
  // means a drained worker leaves no zombie behind and the pool's kill is only
  // ever the backstop for one that would not.
  process.on('disconnect', function () {
    log.debug('worker ' + process.pid + ': the channel closed; exiting.');
    process.exit(0);
  });
  log.info('worker ' + process.pid + ': ready. ' + JOB_KINDS.length +
           ' job kind(s): ' + JOB_KINDS.join(', ') + '.');
  log.debug('Leaving startWorker().');
}

if (require.main === module) {
  startWorker();
}

module.exports = {
  JOBS: JOBS,
  JOB_KINDS: JOB_KINDS,
  runJob: runJob
};
