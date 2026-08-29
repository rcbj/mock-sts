// ===========================================================================
// vendor-check.js — is tests/vendored/ still byte-identical to the parent
// project's tests/, and re-copy it when it is not.
//
//   node tests/tools/vendor-check.js              report drift; exit 1 if any
//   node tests/tools/vendor-check.js --sync       copy the parent's over ours
//   node tests/tools/vendor-check.js --parent=DIR name the parent explicitly
//
// ---------------------------------------------------------------------------
// WHY THIS IS A TOOL AND NOT A TEST, WHICH IS THE ONE DECISION IN THIS FILE
// WORTH ARGUING.
//
// Everything in tests/ is a job in the report, and as of 2026-08-28 a job that
// could not be RUN is a FAILURE rather than a skip — because a skip is counted
// as a pass and a run in which nothing was checked must never exit zero.
//
// This check cannot live under that rule, because it is the one thing here
// that genuinely needs the other checkout. Made a job, it would have exactly
// two possible behaviours on a machine with only this repository on it, and
// both are wrong:
//
//   * FAIL — and then the suite is not self-contained after all. The whole
//     point of vendoring was that this repository's tests run on their own;
//     a red job on every clean checkout would undo it in the report if not in
//     the code.
//   * PASS — and then it is a green check that checked nothing, which is the
//     precise failure mode that got the default flipped in the first place.
//     "23 jobs, 23 passed" would include one that compared zero files.
//
// So it is neither. It is a MAINTENANCE command, run by somebody who has both
// checkouts, and the suite's own pass/fail says nothing about drift. What
// makes that honest rather than convenient is that drift cannot break this
// service: a vendored copy that has fallen behind still tests this tree, and
// it tests it with the assertions that were true when it was copied. What it
// can do is MISS a newer assertion — which is a reason to sync before a
// release, not a reason to fail a developer's run.
//
// `./local-run-tests.sh --vendor-check` and `--vendor-sync` are the way in.
// ===========================================================================

const fs = require('fs');
const path = require('path');
const bunyan = require('bunyan');

const manifest = require('../vendored/MANIFEST.js');

const log = bunyan.createLogger({ name: 'vendor-check',
                                  level: process.env.LOG_LEVEL || 'info' });

const REPO_ROOT = path.resolve(__dirname, '..', '..');
const VENDORED_DIR = path.join(REPO_ROOT, 'tests', 'vendored');

// Two names because the directory has had two: the repository is
// `oauth2-oidc-debugger` and the working copy here is `id-proto-debugger`.
const PARENT_CANDIDATES = ['id-proto-debugger', 'oauth2-oidc-debugger'];

// ---------------------------------------------------------------------------
// Where the parent project is. Named explicitly, or the sibling directory
// under either name. Unlike the version this replaced, it does NOT require the
// parent's tests/node_modules: nothing here runs their code, it only reads
// their files.
// ---------------------------------------------------------------------------
function findParent(named) {
  log.debug('Entering findParent().');
  const tries = named ? [path.resolve(named)]
                      : PARENT_CANDIDATES.map(function (n) {
                          return path.resolve(REPO_ROOT, '..', n);
                        });
  for (const dir of tries) {
    if (fs.existsSync(path.join(dir, manifest.SOURCE_DIR)) &&
        fs.existsSync(path.join(dir, manifest.CLIENT_SOURCE_DIR))) {
      log.debug('Leaving findParent(). ' + dir);
      return { dir: dir, found: true, why: '' };
    }
  }
  log.debug('Leaving findParent(). Not found.');
  return { dir: '', found: false,
           why: 'no parent project beside this one (looked for ' +
                PARENT_CANDIDATES.join(', ') + '); --parent=<dir> names it' };
}

// One file's state: same, different, missing over there, or missing here.
// `entry.source` is the parent-relative directory it was copied FROM — two of
// them, because the jobs come from tests/ and the wallet modules they verify
// against come from client/src/. See tests/vendored/MANIFEST.js.
function compareOne(parentDir, entry) {
  const rel = entry.rel;
  const theirs = path.join(parentDir, entry.source, rel);
  const ours = path.join(VENDORED_DIR, rel);
  if (!fs.existsSync(theirs)) {
    return { rel: rel, source: entry.source, state: 'gone-upstream' };
  }
  if (!fs.existsSync(ours)) {
    return { rel: rel, source: entry.source, state: 'missing-here' };
  }
  const a = fs.readFileSync(theirs);
  const b = fs.readFileSync(ours);
  return { rel: rel, source: entry.source,
           state: a.equals(b) ? 'same' : 'differs' };
}

function main() {
  log.debug('Entering main().');
  const argv = process.argv.slice(2);
  const sync = argv.indexOf('--sync') >= 0;
  let named = '';
  argv.forEach(function (a) {
    if (a.indexOf('--parent=') === 0) {
      named = a.slice('--parent='.length);
    }
  });

  const parent = findParent(named);
  if (!parent.found) {
    // NOT an error. This repository's suite does not need the parent — that is
    // the whole point of vendoring — so "there is nothing to compare against"
    // is an ordinary state of a clean checkout and exits zero.
    log.info('no parent checkout to compare against: ' + parent.why + '.');
    log.info('tests/vendored/ is this repository\'s own copy and the suite ' +
             'runs without it; nothing is wrong.');
    log.debug('Leaving main(). No parent.');
    return 0;
  }

  const files = manifest.allFiles();
  const results = files.map(function (entry) {
    return compareOne(parent.dir, entry);
  });
  const differs = results.filter(function (r) { return r.state === 'differs'; });
  const goneUpstream = results.filter(function (r) {
    return r.state === 'gone-upstream';
  });
  const missingHere = results.filter(function (r) {
    return r.state === 'missing-here';
  });

  log.info('comparing ' + files.length + ' vendored file(s) against ' +
           parent.dir + ' (' + manifest.SOURCE_DIR + ' and ' +
           manifest.CLIENT_SOURCE_DIR + ').');

  if (sync) {
    let copied = 0;
    differs.concat(missingHere).forEach(function (r) {
      const from = path.join(parent.dir, r.source, r.rel);
      const to = path.join(VENDORED_DIR, r.rel);
      fs.mkdirSync(path.dirname(to), { recursive: true });
      fs.copyFileSync(from, to);
      log.info('  synced ' + r.rel + '  (from ' + r.source + ')');
      copied++;
    });
    if (goneUpstream.length) {
      // NOT deleted automatically. A file that has vanished from the parent
      // may have been renamed, in which case the manifest needs the new name
      // and deleting the old copy first would lose the only reference to what
      // it was.
      goneUpstream.forEach(function (r) {
        log.warn('  ' + r.rel + ' NO LONGER EXISTS upstream. It was not ' +
                 'deleted here: check whether it was renamed, fix ' +
                 'tests/vendored/MANIFEST.js, and remove it by hand.');
      });
    }
    log.info(copied + ' file(s) synced, ' + goneUpstream.length +
             ' needing a decision.');
    log.debug('Leaving main(). Synced.');
    return goneUpstream.length ? 1 : 0;
  }

  if (!differs.length && !goneUpstream.length && !missingHere.length) {
    log.info('all ' + files.length + ' file(s) are byte-identical.');
    log.debug('Leaving main(). Clean.');
    return 0;
  }
  differs.forEach(function (r) {
    log.error('  DIFFERS       ' + r.rel + '  (' + r.source + ')');
  });
  missingHere.forEach(function (r) {
    log.error('  MISSING HERE  ' + r.rel + '  (' + r.source + ')');
  });
  goneUpstream.forEach(function (r) {
    log.error('  GONE UPSTREAM ' + r.rel + '  (' + r.source + ')');
  });
  log.error(differs.length + ' differ, ' + missingHere.length +
            ' missing here, ' + goneUpstream.length + ' gone upstream.');
  log.error('The parent is the source of truth: edit there, then run ' +
            '`./local-run-tests.sh --vendor-sync`. A fix made in ' +
            'tests/vendored/ is overwritten by the next sync and never ' +
            'reaches the stack that gates that project.');
  log.debug('Leaving main(). Drift.');
  return 1;
}

process.exit(main());
