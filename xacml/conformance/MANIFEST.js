'use strict';
//
// File: MANIFEST.js
//
// ---------------------------------------------------------------------------
// WHAT IS VENDORED IN THIS DIRECTORY, AND THE DRIFT CHECK OVER IT.
//
// `PROVENANCE.md` beside this file is the argument — where the suite came
// from, under what licence, and the one link in its chain that public sources
// do not establish. This file is the machine-readable half, and it exists for
// the same reason `tests/vendored/MANIFEST.js` does: these files are COPIES,
// and a copy needs an ORIGIN so that drift can be detected.
//
// The drift this guards against is not somebody editing a test on purpose. It
// is the quiet kind:
//
//   * a re-sync that takes a newer upstream and loses cases from the middle of
//     the suite. The runner would report a percentage either way, and the
//     percentage is what everybody reads — so 455 of 455 and 455 of 402 look
//     identical unless something is holding the denominator.
//   * a case edited HERE to make a failing test pass. That is the failure this
//     whole directory exists to prevent: a conformance suite you are allowed
//     to edit is a suite that agrees with your implementation by construction
//     and with nobody else's parser.
//   * a partial checkout or a truncated copy, which produces a suite that runs
//     and proves less than it says.
//
// So the counts and the digests below are the denominator, written down.
// `node xacml/conformance/MANIFEST.js --check` recomputes them.
//
// ---------------------------------------------------------------------------
// THESE FILES ARE NOT EDITED HERE. EVER.
//
// The same rule `common/vendored/` and `tests/vendored/` carry, and here it is
// stronger rather than weaker, because there is no "edit the parent's copy and
// re-sync" path available: upstream is somebody else's project. A defect found
// in a case is reported to AuthzForce, or recorded in EXPECTED_FAILURES below
// with the reason. It is never fixed in place.
//
// ---------------------------------------------------------------------------
// THE THREE DIRECTORIES ARE THREE DIFFERENT CLAIMS, AND THE RUNNER TREATS THEM
// DIFFERENTLY.
//
//   mandatory/     features XACML 3.0 REQUIRES. A failure here is a defect in
//                  this implementation. 455 cases.
//   optional/      optional features and profiles — XPath expressions, the
//                  Hierarchical Resource and Multiple Decision profiles.
//                  Split by upstream into `xml/` (XML-only, e.g. the
//                  xpathExpression datatype) and `xml+json/` (applies to both
//                  the XML and JSON representations). A failure here is a
//                  feature not implemented, which is a different sentence.
//   unsupported/   cases AuthzForce deliberately does not support, kept so
//                  that the reason is visible rather than the case merely
//                  being absent. FLAT — `IIA010Policy.xml` rather than
//                  `IIA010/Policy.xml` — because it is the older naming, and
//                  the runner has to know that.
//
// ---------------------------------------------------------------------------
// FOUR SHAPES OF CASE, AND THREE OF THEM ARE NOT `Policy + Request + Response`.
//
// A runner written against the common shape alone passes on the ordinary cases
// and skips the interesting ones with nothing failing, so the shapes are
// enumerated here rather than discovered:
//
//   1. THE ORDINARY ONE. `Policy.xml`, `Request.xml`, `Response.xml`.
//   2. AN INVALID POLICY. `Request.xml.ignore` and `Response.xml.ignore` —
//      upstream renamed them precisely so a runner would not evaluate them.
//      The assertion is that loading `Policy.xml` FAILS. Six cases. A runner
//      that ignores the `.ignore` suffix and evaluates anyway gets a decision
//      out of a policy that should never have loaded, and calls it a pass.
//   3. AN INVALID REQUEST. The mirror image — `Policy.xml.ignore` and
//      `Response.xml.ignore`, and the assertion is that parsing the request
//      fails.
//   4. POLICY REFERENCES. The three IIE cases carry a `Policies/` directory
//      of documents the root policy reaches by `PolicyIdReference` /
//      `PolicySetIdReference`, plus a `Repository.properties.ignore` naming
//      AT&T's own way of configuring a repository, which is not ours. The
//      `Policies/` directory IS the repository here.
//
// `Special.txt` appears in some cases and is a note to a human. It is never
// read by the runner and never gates anything.
// ---------------------------------------------------------------------------

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const bunyan = require('bunyan');

// A LOGGER OF ITS OWN RATHER THAN `common/helpers`'s, and the reason is that
// this file has to run with nothing else loaded — `node
// xacml/conformance/MANIFEST.js --check` is documented in PROVENANCE.md and
// must work in a bare checkout, before CONFIG_FILE is set and without the
// service's module graph. `tests/tools/vendor-check.js` is the precedent and
// takes its level the same way.
const log = bunyan.createLogger({ name: 'xacml-conformance-manifest',
                                  level: process.env.LOG_LEVEL || 'info' });

const HERE = __dirname;

// ---------------------------------------------------------------------------
// WHERE IT CAME FROM. Every field here is a fact somebody will need in order to
// take a newer copy, and the DATE is the one that is useless to guess.
// ---------------------------------------------------------------------------
const SOURCE = {
  repository: 'https://github.com/authzforce/core',
  branch: 'develop',
  path: 'pdp-testutils/src/test/resources/conformance/xacml-3.0-from-2.0-ct',
  licence: 'Apache-2.0',
  fetched: '2026-09-04',
  // The chain above AuthzForce, in one line each, because a reader who finds
  // this file first should not have to open PROVENANCE.md to learn that these
  // are not AuthzForce's tests either.
  upstreamOf: [
    'OASIS XACML TC — the original 1.1/2.0 conformance tests, no licence ' +
      'statement anywhere on them',
    'AT&T — upgraded to XACML 3.0 and contributed back in April 2014; ' +
      'published under MIT at https://github.com/att/xacml-3.0',
    'AuthzForce — fixed ~30 defects and split mandatory/optional/unsupported'
  ]
};

// ---------------------------------------------------------------------------
// THE DENOMINATOR. Recomputed by --check; a mismatch is reported rather than
// silently accepted, because every one of these numbers is something a
// percentage is divided by.
//
// `cases` counts DIRECTORIES holding a case, so it is 0 for `unsupported`,
// which is flat. That is not a bug and is why `flat` is recorded beside it:
// a runner that assumed one layout for all three would find no cases at all
// in the third and report nothing missing.
// ---------------------------------------------------------------------------
const TREES = [
  { dir: 'mandatory', flat: false, files: 1380, cases: 455,
    sha256:
      'edffee67f746fc18e19bac01322f0eff80b842f18d19a2ad1096b72ccc0b5b2a',
    what: 'Features XACML 3.0 requires. A failure here is our defect.' },
  { dir: 'optional', flat: false, files: 64, cases: 2,
    sha256:
      '3fdad2f56f9a5b4748618cb5257563fd8713bede4fed96b233a285b7556feb0f',
    what: 'Optional features and profiles, under xml/ and xml+json/. The ' +
          '`cases` count is 2 because those two subdirectories are what ' +
          'sits at case depth here; the cases are one level further down.' },
  { dir: 'unsupported', flat: true, files: 49, cases: 0,
    sha256:
      '74fcb6bce0739cf2015f530a13ea99a3dd009f788f9baf52f72f134444052a9b',
    what: 'Deliberately unsupported upstream, kept so the reason is ' +
          'visible. FLAT layout — IIA010Policy.xml, not IIA010/Policy.xml.' }
];

// The digest over all three trees together, so that one number answers "is
// this suite the one the counts above were taken from".
const OVERALL_SHA256 =
  '81eeedd5f901769f3e2ab7739f874f2c2adbc48fa162394f249f89b462838c8c';

// The three files that are not test material. `UPSTREAM-README.md` is
// AuthzForce's own — renamed on the way in, content untouched — and is the
// list of about thirty defects in the AT&T suite. Read it before deciding a
// failing case is our bug.
const DOCUMENTS = [
  { file: 'UPSTREAM-README.md',
    sha256:
      '65288d17bffce34ceda1d6a5f7e703b33f5d9bffad62e0f9412e9507c3a5ba9f',
    what: "AuthzForce's README, renamed. The defect list." },
  { file: 'ConformanceTests.html',
    sha256:
      '8ec7f6ce0974bc329d3021272dbb9b3675e0febce5afdc913cebbdfa6b290837',
    what: 'The original OASIS description of the tests.' },
  { file: 'LICENSE',
    sha256:
      'cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30',
    what: 'Apache-2.0, from the root of authzforce/core.' }
];

// ---------------------------------------------------------------------------
// CASES THIS IMPLEMENTATION IS NOT EXPECTED TO PASS, EACH WITH ITS REASON.
//
// ONE ROW, and the rule for adding a second is the one that makes the list
// worth having: a row says WHY the case cannot pass, in terms of a feature
// that is not implemented, a defect in the case itself, or — as here — a
// disagreement between the vendored fixture and the specification it came
// from. "It fails" is not a reason, and a row without one is
// indistinguishable from a bug being filed away.
//
// A case listed here still RUNS. It is reported separately rather than
// skipped, so that a case which starts passing is noticed — an expectation
// that has quietly become true is as much drift as one that has become false.
// ---------------------------------------------------------------------------
const EXPECTED_FAILURES = [
  { case: 'IIE003',
    why: 'This case\'s own Special.txt says the referenced policies "must ' +
         'not be evaluated (or syntax- and type-checked) until the ' +
         'evaluation of the PolicySet calls for" them — the set combines by ' +
         'first-applicable, policy1 decides it, and policy2 (which does not ' +
         'typecheck) is never reached. THIS PDP BEHAVES THAT WAY: ' +
         'xacml_validate.js does not follow a PolicyIdReference, and ' +
         'xacml_pdp.js resolves one only when the combining algorithm asks ' +
         'for that child. So the policy set loads, which is what the OASIS ' +
         'case describes.\n\n' +
         'It is listed here because AuthzForce loads its whole repository ' +
         'eagerly and therefore REFUSES this set at initialisation, and it ' +
         'renamed the case\'s Request.xml and Response.xml to .ignore to say ' +
         'so. That renaming is what the runner reads as "the policy must be ' +
         'rejected", so the expectation recorded in this vendored copy is ' +
         'AuthzForce\'s behaviour rather than the specification\'s. We are ' +
         'failing the fixture and agreeing with the test\'s stated intent.\n\n' +
         'The way to settle it would be to run the case from its .ignore ' +
         'files and compare against the response OASIS originally recorded. ' +
         'That is worth doing and is not done yet.' }
];

// ---------------------------------------------------------------------------
// WALK ONE TREE AND DIGEST IT.
//
// The digest is over the sorted (relative path, content digest) pairs rather
// than over a concatenation of the contents, so that a file being RENAMED or
// MOVED changes it. A digest of contents alone would not notice
// `IIA001/Policy.xml` becoming `IIA002/Policy.xml`, which is exactly the shape
// a bad re-sync takes.
// ---------------------------------------------------------------------------
function digestTree(dir) {
  log.debug('Entering digestTree(). dir=' + dir);
  const root = path.join(HERE, dir);
  const found = [];
  function walk(current) {
    const entries = fs.readdirSync(current, { withFileTypes: true });
    entries.forEach(function (entry) {
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) {
        walk(full);
        return;
      }
      found.push(path.relative(root, full));
    });
  }
  if (!fs.existsSync(root)) {
    log.debug('Leaving digestTree(). No such tree.');
    return null;
  }
  walk(root);
  found.sort();
  const hash = crypto.createHash('sha256');
  found.forEach(function (relative) {
    hash.update(relative);
    hash.update(Buffer.from([0]));
    hash.update(crypto.createHash('sha256')
                      .update(fs.readFileSync(path.join(root, relative)))
                      .digest());
  });
  const cases = {};
  found.forEach(function (relative) {
    const parts = relative.split(path.sep);
    if (parts.length > 1) {
      cases[parts[0]] = true;
    }
  });
  const result = { files: found.length,
                   cases: Object.keys(cases).length,
                   sha256: hash.digest('hex'),
                   digestBytes: null };
  log.debug('Leaving digestTree(). ' + result.files + ' file(s).');
  return result;
}

// ---------------------------------------------------------------------------
// RECOMPUTE EVERYTHING AND REPORT WHAT DIFFERS.
//
// Returns an object rather than throwing or exiting, because two callers want
// it: the CLI below, which prints and sets an exit code, and
// `tests/xacml_conformance.js`, which asserts on it. A function that exited
// would be usable by only one of them.
// ---------------------------------------------------------------------------
function check() {
  log.debug('Entering check().');
  const problems = [];
  const overall = crypto.createHash('sha256');
  const trees = TREES.map(function (tree) {
    const actual = digestTree(tree.dir);
    if (!actual) {
      problems.push(tree.dir + '/ is missing entirely. The suite has not ' +
                    'been vendored, or a checkout is partial.');
      return { dir: tree.dir, missing: true };
    }
    overall.update(tree.dir);
    overall.update(Buffer.from(actual.sha256, 'hex'));
    if (actual.files !== tree.files) {
      problems.push(tree.dir + '/ holds ' + actual.files + ' file(s); the ' +
                    'manifest records ' + tree.files + '. A re-sync that ' +
                    'changed the suite must update this file.');
    }
    if (actual.cases !== tree.cases) {
      problems.push(tree.dir + '/ holds ' + actual.cases + ' case ' +
                    'director(ies); the manifest records ' + tree.cases + '.');
    }
    if (actual.sha256 !== tree.sha256) {
      problems.push(tree.dir + '/ digest is ' + actual.sha256 + '; the ' +
                    'manifest records ' + tree.sha256 + '. Something in ' +
                    'here was edited, and these files are not edited here.');
    }
    return { dir: tree.dir, actual: actual, expected: tree };
  });
  DOCUMENTS.forEach(function (document) {
    const full = path.join(HERE, document.file);
    if (!fs.existsSync(full)) {
      problems.push(document.file + ' is missing.');
      return;
    }
    const actual = crypto.createHash('sha256')
                         .update(fs.readFileSync(full)).digest('hex');
    if (actual !== document.sha256) {
      problems.push(document.file + ' digest is ' + actual + '; the ' +
                    'manifest records ' + document.sha256 + '.');
    }
  });
  const overallHex = overall.digest('hex');
  if (overallHex !== OVERALL_SHA256) {
    problems.push('The overall digest is ' + overallHex + '; the manifest ' +
                  'records ' + OVERALL_SHA256 + '.');
  }
  log.debug('Leaving check(). ' + problems.length + ' problem(s).');
  return { ok: problems.length === 0, problems: problems, trees: trees,
           overall: overallHex };
}

// ---------------------------------------------------------------------------
// THE CLI. Documented in PROVENANCE.md, so it has to keep working.
// ---------------------------------------------------------------------------
function main() {
  log.debug('Entering main().');
  const report = check();
  report.trees.forEach(function (tree) {
    if (tree.missing) {
      log.error(tree.dir + '/  MISSING');
      return;
    }
    log.info(tree.dir + '/  ' + tree.actual.files + ' file(s), ' +
             tree.actual.cases + ' case director(ies)');
  });
  if (report.ok) {
    log.info('The vendored conformance suite is intact. Overall digest ' +
             report.overall + '.');
    log.debug('Leaving main(). Clean.');
    return 0;
  }
  report.problems.forEach(function (problem) {
    log.error(problem);
  });
  log.error(report.problems.length + ' problem(s). See PROVENANCE.md for ' +
            'what this directory is and how to re-sync it.');
  log.debug('Leaving main(). Drift reported.');
  return 1;
}

module.exports = { SOURCE: SOURCE, TREES: TREES, DOCUMENTS: DOCUMENTS,
                   OVERALL_SHA256: OVERALL_SHA256,
                   EXPECTED_FAILURES: EXPECTED_FAILURES,
                   HERE: HERE, digestTree: digestTree, check: check };

// Guarded, so that requiring this module from the test suite does not run the
// CLI — the same guard `common/worker.js` carries and for the same reason.
if (require.main === module) {
  process.exit(main());
}
