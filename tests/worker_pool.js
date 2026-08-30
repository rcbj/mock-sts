'use strict';
//
// File: worker_pool.js
//
// ===========================================================================
// THE WORKER POOL'S FOUR CONTRACTS.
//
// `common/worker.js` and `common/worker_pool.js` moved post-quantum signing,
// verification and key generation OFF the thread that owns every listener this
// service has. Stalls of 14.6, 15.4, 17.8 and 23.3 seconds were measured on
// 2026-08-29 while the parent project's suite ran, and for those seconds this
// service answered nobody at all — not another HTTP caller, not the KDC on
// port 88. Not one of the failures they caused named one.
//
// Moving a computation into another process can go wrong in four ways, and this
// file is one section per way:
//
//   A. IT COMPUTES SOMETHING ELSE.       The bytes a worker produces must be
//      the bytes this process would have produced. Nine of the eleven
//      algorithms sign DETERMINISTICALLY, so for those it is literal byte
//      equality; the three composite ECDSA ones cannot be — node's ECDSA is
//      randomized, and two signatures over one message differ by design — so
//      those are held to the only thing that is true of them, which is
//      that each side verifies what the other made.
//
//   B. IT BLOCKS ANYWAY.                 The whole point. A signature taking
//      two seconds in a child must leave this process free for those two
//      seconds, and the only honest way to assert that is to count timer ticks
//      while it happens. This section is why this file takes seconds rather
//      than the milliseconds every other test here takes, and the cost is
//      deliberate: an assertion that the loop is free, made with a fast
//      algorithm, would pass on a pool that did not work.
//
//   C. IT SPREADS WORK THE WRONG WAY.    A session's jobs go to one worker;
//      jobs with no session go to the least loaded.
//
//   D. IT LOSES A JOB WHEN A WORKER DIES. A promise nobody settles is a request
//      that hangs, which is the symptom the whole change exists to remove. A
//      killed worker must FAIL its jobs with a sentence naming what happened,
//      and the pool must go on working afterwards.
//
// WHY IT IS HERE AND NOT IN THE PARENT SUITE, which is the question
// `tests/CLAUDE.md` says to answer first: every one of the four compares this
// service against ITSELF — the same function in two processes, a timer in this
// one, which worker a job landed on, a child killed on purpose. None of them
// can be observed over HTTP, and the parent suite has no way to reach inside a
// process it started with docker-compose.
//
// The PROTOCOL half — that a UserInfo response signed with SLH-DSA still comes
// back as `application/jwt` and still verifies — is a different test and it is
// over there, in `tests/sts_userinfo_protected.js`.
// ===========================================================================

const pool = require('../common/worker_pool');
const pqJose = require('../common/pq_jose');
const crypto = require('../common/crypto');
const config = require('../common/config');
const realms = require('../common/realms');

// One message for everything below, so a difference is never the input.
const MESSAGE = Buffer.from('the worker pool signs exactly what this ' +
                            'process would have signed', 'utf8');

// The three composites whose traditional half is ECDSA. Node's ECDSA is
// randomized (RFC 6979's deterministic variant is not what OpenSSL does), so
// two signatures over one message differ and MUST — a deterministic ECDSA
// nonce leaking would be a private key leaking. They are held to
// cross-verification instead, which is the strongest thing that is true.
const RANDOMIZED = ['ML-DSA-44-ES256', 'ML-DSA-65-ES256', 'ML-DSA-87-ES384'];

// Section B's algorithm. SLH-DSA-SHA2-128s takes about two seconds to sign —
// slow enough that a blocked event loop is unmistakable, and six times faster
// than the SHAKE variant that produced the 15-second stalls. It is the
// cheapest algorithm that can prove the claim at all.
const SLOW_ALG = 'SLH-DSA-SHA2-128s';

// ---------------------------------------------------------------------------
// SECTION A DRIVES TEN OF THE ELEVEN, AND THE ONE IT LEAVES OUT IS THE
// EXPENSIVE ONE. **This is a budget decision and it is worth stating, because
// the omitted algorithm is the one this whole change set exists for.**
//
// SLH-DSA-SHAKE-128s costs about five seconds to generate a key and twelve to
// sign, and section A signs TWICE — once here and once in a worker — so it
// alone was 30 of this file's 37 seconds on a 20-core machine. In this
// repository's CI that file runs under c8 instrumentation on a two-core
// runner, where it went past the runner's 300-second per-job budget and was
// killed. A test that is killed asserts nothing.
//
// What is lost by leaving it out is nothing: section A's claim is about the
// TRANSPORT — that a Buffer crossing the IPC channel comes back as the bytes
// that went in — and that is a property of the job table and the serialization,
// not of the lattice. SLH-DSA-SHA2-128s stays in, and it is the one that
// matters for this claim because its 7,856-byte signature is the largest
// payload of the ten. Its SHAKE twin produces a signature of EXACTLY THE SAME
// SIZE by a different hash, so it would exercise the same transport for
// twenty-four more seconds.
//
// The algorithm itself is not untested: section B signs with SLH-DSA and
// tests/pqc_engines.js over in the parent project drives every FIPS 205
// parameter set against the standard's own vectors.
// ---------------------------------------------------------------------------
const TOO_SLOW_FOR_SECTION_A = ['SLH-DSA-SHAKE-128s'];
const DRIVEN_IN_A = pqJose.PQ_ALGS.filter(function (alg) {
  return TOO_SLOW_FOR_SECTION_A.indexOf(alg) === -1;
});

// `workers.count` is read per job, so a section can choose its own pool size
// by setting an override and clearing it afterwards. Every section that does
// puts it back, for the reason the parent suite's saml11_sso.js gives: a `set`
// left behind is the next test's mystery.
function withWorkers(count, run) {
  config.setOverride('workers.count', String(count));
  return Promise.resolve()
    .then(run)
    .then(function (value) {
      config.clearOverride('workers.count');
      return value;
    }, function (err) {
      config.clearOverride('workers.count');
      throw err;
    });
}

module.exports = {
  name: 'worker_pool',
  describe: 'the same bytes, off this thread, on the right worker, and ' +
            'nothing lost when one dies',

  run: async function (t) {

    // -----------------------------------------------------------------------
    t.log.info('A. a worker computes what this process would have computed');
    // -----------------------------------------------------------------------
    await withWorkers(2, async function () {
      for (const alg of DRIVEN_IN_A) {
        const pair = pqJose.generate(alg);
        const here = pqJose.sign(alg, pair.priv, MESSAGE);
        const there = await pqJose.signAsync(alg, pair.priv, MESSAGE);
        if (RANDOMIZED.indexOf(alg) === -1) {
          t.check(Buffer.compare(Buffer.from(here), Buffer.from(there)) === 0,
                  alg + ': a pooled signature is byte-identical',
                  here.length + ' bytes');
        } else {
          t.check(here.length === there.length,
                  alg + ': a pooled signature is the same length — its ECDSA ' +
                  'half is randomized, so it cannot be the same bytes',
                  here.length + ' bytes');
        }
        // Each side verifies what the other made. For the randomized three
        // this is the whole assertion; for the other eight it is the check
        // that byte equality was not two identical wrong answers.
        t.check(await pqJose.verifyAsync(alg, pair.pub, MESSAGE, here),
                alg + ': a worker verifies what this process signed');
        t.check(pqJose.verify(alg, pair.pub, MESSAGE, there),
                alg + ': and this process verifies what a worker signed');
      }
    });

    // The same claim one level up, where the callers actually are: the JWS
    // framing must not differ between the two entry points either.
    await withWorkers(2, async function () {
      const pair = pqJose.generate('ML-DSA-44');
      const payload = { sub: 'alice', iat: 1700000000 };
      const opts = { algorithm: 'ML-DSA-44', keyid: 'k1' };
      const here = crypto.signJws(payload, pair.priv, opts);
      const there = await crypto.signJwsAsync(payload, pair.priv, opts);
      t.equal(there, here,
              'signJwsAsync() produces the same compact JWS as signJws()');
      const read = await crypto.verifyCompactJwsAsync(here, pair.pub,
        { algorithms: ['ML-DSA-44'] });
      t.equal(read.claims.sub, 'alice',
              'and verifyCompactJwsAsync() reads it back');
    });

    // A signature that does not hold up is an ANSWER and not a failure of the
    // pool: it must come back as the same refusal the synchronous verifier
    // gives, and not as a worker error.
    await withWorkers(2, async function () {
      const pair = pqJose.generate('ML-DSA-44');
      const other = pqJose.generate('ML-DSA-44');
      const jws = crypto.signJws({ sub: 'mallory' }, pair.priv,
                                 { algorithm: 'ML-DSA-44' });
      let message = '';
      try {
        await crypto.verifyCompactJwsAsync(jws, other.pub,
          { algorithms: ['ML-DSA-44'] });
      } catch (e) {
        message = e.message;
      }
      t.check(/does not verify/.test(message),
              'a signature made with another key is refused for not ' +
              'verifying, not for anything about the pool', message);
    });

    // -----------------------------------------------------------------------
    t.log.info('B. and this process stays free while it does — the point');
    // -----------------------------------------------------------------------
    // Two runs of the SAME signature, one pooled and one not, each with a 25ms
    // timer running. The unpooled one is what this service did before the pool
    // existed and it is here as the CONTROL: without it, "the timer fired" is
    // not evidence of anything.
    const measure = async function (workers) {
      return withWorkers(workers, async function () {
        const pair = pqJose.generate(SLOW_ALG);
        let ticks = 0;
        const timer = setInterval(function () { ticks++; }, 25);
        const started = Date.now();
        await pqJose.signAsync(SLOW_ALG, pair.priv, MESSAGE);
        const elapsed = Date.now() - started;
        clearInterval(timer);
        return { ticks: ticks, elapsed: elapsed };
      });
    };
    const blocked = await measure(0);
    const free = await measure(2);
    t.check(blocked.elapsed > 500,
            'the control signature is slow enough to prove anything with',
            blocked.elapsed + 'ms in this process');
    t.check(blocked.ticks <= 1,
            'WITH NO POOL THE EVENT LOOP IS DEAD for the whole of it — this ' +
            'is what a Kerberos reply that never came looked like',
            blocked.ticks + ' timer tick(s) in ' + blocked.elapsed + 'ms');
    t.check(free.ticks > 10,
            'WITH A POOL IT IS FREE THROUGHOUT, which is the entire change',
            free.ticks + ' timer tick(s) in ' + free.elapsed + 'ms');

    // -----------------------------------------------------------------------
    t.log.info('C. routing: one session to one worker, otherwise least loaded');
    // -----------------------------------------------------------------------
    // A FRESH POOL FIRST, and this is not tidiness: both assertions below count
    // the workers that did any work, and the workers from section A are still
    // running with jobsDone on them. Without this, "six jobs went to one
    // worker" reads the other section's counters and fails — which is what it
    // did the first time it was run.
    await pool.stop();
    pool.reset();
    await withWorkers(2, async function () {
      const pair = pqJose.generate('ML-DSA-44');
      // Sequential, so that "least loaded" cannot be what put them together:
      // with nothing in flight, the tie-break is the worker that has done the
      // least work, which alternates. Affinity has to beat that.
      for (let i = 0; i < 6; i++) {
        await pqJose.signAsync('ML-DSA-44', pair.priv, MESSAGE,
                               { session: 'session-one' });
      }
      const busy = pool.stats().workers.filter(function (one) {
        return one.jobsDone > 0;
      });
      t.equal(busy.length, 1,
              'six jobs naming one session all went to one worker');
      t.equal(pool.stats().affinities, 1,
              'and the pool is remembering exactly one session');
    });

    await pool.stop();
    pool.reset();
    await withWorkers(2, async function () {
      const pair = pqJose.generate('ML-DSA-44');
      // Together rather than one after another, so both workers have something
      // in flight and the split is by load rather than by tie-break.
      await Promise.all([0, 1, 2, 3].map(function () {
        return pqJose.signAsync('ML-DSA-44', pair.priv, MESSAGE);
      }));
      const spread = pool.stats().workers.filter(function (one) {
        return one.jobsDone > 0;
      });
      t.equal(spread.length, 2,
              'four jobs naming no session were spread over both workers');
    });

    // -----------------------------------------------------------------------
    t.log.info('D. a worker that dies fails its jobs and is replaced');
    // -----------------------------------------------------------------------
    await pool.stop();
    pool.reset();
    await withWorkers(1, async function () {
      const pair = pqJose.generate(SLOW_ALG);
      // One worker, so the job below is certainly on the one being killed.
      const inFlight = pqJose.signAsync(SLOW_ALG, pair.priv, MESSAGE);
      // Long enough for the job to have been sent and started.
      await new Promise(function (resolve) { setTimeout(resolve, 200); });
      const before = pool.stats().workers[0];
      t.check(before && before.inFlight === 1,
              'the job is in flight on the only worker there is',
              before ? 'pid ' + before.pid : 'no worker');
      process.kill(before.pid, 'SIGKILL');
      let message = '';
      try {
        await inFlight;
      } catch (e) {
        message = e.message;
      }
      t.check(/SIGKILL/.test(message),
              'THE PROMISE IS REJECTED AND SAYS WHAT HAPPENED — a promise ' +
              'nobody settles is a request that hangs, which is the symptom ' +
              'this whole change removes', message);
      t.check(/made again/.test(message),
              'and it says the request can simply be retried, because a ' +
              'worker held no state to lose', message);
      // And the pool goes on working: the next job forks a replacement.
      const after = await pqJose.signAsync('ML-DSA-44',
        pqJose.generate('ML-DSA-44').priv, MESSAGE);
      t.check(after && after.length > 0,
              'and the next job forks a replacement and is answered',
              pool.stats().running + ' worker(s) running again');
    });

    // -----------------------------------------------------------------------
    t.log.info('E. workers.count = 0 is a supported configuration, not a ' +
               'degraded one');
    // -----------------------------------------------------------------------
    // Section D left a worker running, which is the interesting starting point:
    // the pool is reconciled with the setting ON THE NEXT JOB and not when the
    // setting changes, so this asserts that `workers.count` is runtime in the
    // sense config.js's table claims — a value that only took effect at the
    // next restart would be the lie that file refuses to tell about a port.
    const runningBefore = pool.stats().running;
    await withWorkers(0, async function () {
      t.check(runningBefore > 0,
              'a worker is running when the setting is lowered to 0',
              runningBefore + ' worker(s)');
      const pair = pqJose.generate('ML-DSA-44');
      const here = pqJose.sign('ML-DSA-44', pair.priv, MESSAGE);
      const there = await pqJose.signAsync('ML-DSA-44', pair.priv, MESSAGE);
      t.equal(pool.stats().running, 0,
              'and the next signature drains it rather than waiting for a ' +
              'restart');
      t.check(pool.stats().inProcess, 'the pool says it is computing here');
      t.check(Buffer.compare(Buffer.from(here), Buffer.from(there)) === 0,
              'and signAsync() still answers, with the same bytes, in this ' +
              'process');
    });

    // An unknown job kind is refused by the pool rather than forked out to a
    // worker that would have to invent a failure for it.
    let unknown = '';
    try {
      await pool.run('pq.encrypt', {});
    } catch (e) {
      unknown = e.message;
    }
    t.check(/no "pq.encrypt" job/.test(unknown),
            'an unknown job kind is refused by name, with the list of what ' +
            'the pool does run', unknown);

    // -----------------------------------------------------------------------
    t.log.info('F. a realm may not carry workers.count — it is perProcess');
    // -----------------------------------------------------------------------
    // The reading end and the writing end of one rule. They were written
    // separately for `realms.*` and disagreed within the hour, which is why
    // both go through config.js's own predicate.
    t.check(config.isPerProcess('workers.count'),
            'workers.count is marked perProcess');
    t.check(!config.isPerProcess('oauth2.issuer'),
            'and an ordinary setting is not');
    const made = realms.create({ id: 'wp-test-realm',
                                name: 'worker pool test' });
    if (t.check(made.ok, 'a realm can be made to try it on',
                JSON.stringify(made.errors || []))) {
      const refused = realms.setOverride('wp-test-realm', 'workers.count', '4');
      t.check(!refused.ok,
              'AND THE REALM IS REFUSED THE SETTING — a pool belongs to the ' +
              'process, and one realm resizing it would resize every other ' +
              'realm\'s too', JSON.stringify(refused.errors || []));
      t.check(/every other realm/.test((refused.errors || []).join(' ')),
              'with the reason in the sentence rather than a bare refusal',
              (refused.errors || []).join(' '));
      realms.remove('wp-test-realm');
    }

    // Nothing this file forked outlives it. Without this the runner's process
    // would sit with two idle children until it exited — which it would, since
    // the pool unreferences an idle channel, but a test that leaves work
    // running is a test the next one has to reason about.
    await pool.stop();
    t.equal(pool.stats().running, 0, 'and the pool drains at the end');
  }
};
