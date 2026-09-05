'use strict';
//
// File: xacml_conformance.js
//
// ---------------------------------------------------------------------------
// THE OASIS XACML 3.0 CONFORMANCE SUITE, RUN AGAINST THIS SERVICE'S PDP.
//
// 455 mandatory cases, each a policy, a request and the response a conforming
// PDP must produce. `xacml/conformance/PROVENANCE.md` says where they came
// from and under what licence; `xacml/conformance/MANIFEST.js` holds the
// denominator and is checked here first, because a suite that has quietly lost
// half its cases still reports a percentage and the percentage is what
// everybody reads.
//
// ---------------------------------------------------------------------------
// WHY THIS IS AN IN-PROCESS TEST AND NOT A PROTOCOL ONE.
//
// A PDP is a pure function: a policy and a request in, a decision out. It
// needs no port, no container, no directory and no clock beyond the one the
// context carries. So this runs in `npm test` alongside the other in-process
// jobs, in about a second, and every developer gets it on every change rather
// than only when they remember to bring a stack up.
//
// That is also what makes it worth having. The defects this catches are not
// crashes — they are a combining algorithm that returns Permit where the
// specification says Deny, and the only way to see one is to compare against
// somebody else's reading of the same document. A test written here by the
// same person who wrote the engine would encode the same misunderstanding.
//
// ---------------------------------------------------------------------------
// WHAT IS COMPARED, AND WHAT DELIBERATELY IS NOT.
//
// THE DECISION, always. That is the assertion.
//
// THE OBLIGATIONS, by identifier, for the 58 IIIA cases — which exist for
// nothing else, so a runner that ignored them would report those 58 as passing
// on the strength of a Permit they share with half the suite.
//
// NOT the Status code. The specification lets a PDP choose between
// `processing-error` and `missing-attribute` in several places, real PDPs
// disagree, and upstream's own README records cases where the recorded
// Response is not schema-valid. Comparing it would fail cases over a message
// rather than over a decision. It is REPORTED on a failure, because when a
// decision is wrong the status is the first thing worth reading.
//
// NOT the XML serialization. Two conforming PDPs emit different whitespace,
// attribute order and namespace prefixes for the same answer.
// ---------------------------------------------------------------------------

const fs = require('fs');
const path = require('path');

const model = require('../xacml/xacml_model');
const xml = require('../xacml/xacml_xml');
const pdp = require('../xacml/xacml_pdp');
const MANIFEST = require('../xacml/conformance/MANIFEST');

const SUITE = MANIFEST.HERE;

// ---------------------------------------------------------------------------
// READ ONE CASE OFF DISK.
//
// The four shapes are enumerated in MANIFEST.js's header rather than
// discovered here, because a runner that handled only the common one would
// skip the interesting cases with nothing failing.
// ---------------------------------------------------------------------------
function readCase(directory) {
  const files = fs.readdirSync(directory);
  const has = function (name) {
    return files.indexOf(name) >= 0;
  };
  const read = function (name) {
    return fs.readFileSync(path.join(directory, name), 'utf8');
  };
  // THE ROOT POLICY IS NOT ALWAYS AT THE TOP OF THE CASE. The three IIE cases
  // put `Policy.xml` INSIDE `Policies/` alongside the documents it references,
  // because AT&T's own runner was pointed at a repository directory rather than
  // at a file. A runner that looks only at the top level finds no policy and
  // reports the case as malformed — which is what happened here, and it reads
  // exactly like a broken checkout rather than like a layout it did not know.
  const nestedRoot = !has('Policy.xml') &&
                     files.indexOf('Policies') >= 0 &&
                     fs.existsSync(path.join(directory, 'Policies',
                                             'Policy.xml'));
  const shape = {
    name: path.basename(directory),
    directory: directory,
    policy: has('Policy.xml') ? read('Policy.xml')
      : (nestedRoot
          ? fs.readFileSync(path.join(directory, 'Policies', 'Policy.xml'),
                            'utf8')
          : null),
    request: has('Request.xml') ? read('Request.xml') : null,
    response: has('Response.xml') ? read('Response.xml') : null,
    // An INVALID POLICY case: upstream renamed the request and the response so
    // that no runner would evaluate them, and the whole assertion is that
    // loading the policy fails.
    // A nested root is still a policy the case HAS, so a case with one is not
    // an "invalid policy" case merely because it lacks a top-level Policy.xml.
    expectsPolicyRejected: has('Request.xml.ignore') &&
                           has('Response.xml.ignore'),
    // The mirror: an invalid REQUEST.
    expectsRequestRejected: has('Policy.xml.ignore') &&
                            has('Response.xml.ignore'),
    // The three IIE cases: a repository of referenced documents.
    repositoryDir: has('Policies')
      ? path.join(directory, 'Policies') : null
  };
  return shape;
}

// The referenced policies an IIE case needs, keyed by the identifier a
// PolicyIdReference names — which is the PolicyId inside the document, not the
// file name. Keying on the file name would work for this suite and break on
// the first repository whose files are named anything else.
function readRepository(directory) {
  const repository = {};
  fs.readdirSync(directory).forEach(function (file) {
    if (!/\.xml$/.test(file)) {
      return;
    }
    try {
      const parsed = xml.parsePolicy(
        fs.readFileSync(path.join(directory, file), 'utf8'));
      repository[parsed.id] = parsed;
    } catch (error) {
      // A malformed document in the repository is not this case's assertion,
      // so it is skipped rather than failing the case — but it is not silent:
      // the case will fail on its unresolvable reference and say so.
      repository['__error__' + file] = error.message;
    }
  });
  return repository;
}

// ---------------------------------------------------------------------------
// RUN ONE CASE.
//
// Returns a verdict object rather than asserting, so that the caller can count
// and group them — 455 individual harness lines would bury the summary that is
// the only thing anybody reads.
// ---------------------------------------------------------------------------
function runCase(testCase) {
  if (testCase.expectsPolicyRejected) {
    try {
      xml.parsePolicy(testCase.policy);
      return { ok: false, why: 'the policy is invalid and was accepted' };
    } catch (error) {
      return { ok: true, why: 'the invalid policy was refused' };
    }
  }
  if (testCase.expectsRequestRejected) {
    try {
      xml.parseRequest(testCase.request);
      return { ok: false, why: 'the request is invalid and was accepted' };
    } catch (error) {
      return { ok: true, why: 'the invalid request was refused' };
    }
  }
  if (!testCase.policy || !testCase.request || !testCase.response) {
    return { ok: false, why: 'the case is missing one of its three files' };
  }
  let policy;
  let request;
  let expected;
  try {
    policy = xml.parsePolicy(testCase.policy);
    request = xml.parseRequest(testCase.request);
    expected = xml.parseResponse(testCase.response);
  } catch (error) {
    return { ok: false, why: 'could not be loaded: ' + error.message };
  }
  const repository = testCase.repositoryDir
    ? readRepository(testCase.repositoryDir) : null;
  let actual;
  try {
    actual = pdp.evaluate(policy, request, { repository: repository });
  } catch (error) {
    return { ok: false, why: 'the PDP threw: ' + error.message };
  }
  const wanted = expected.results.length ? expected.results[0] : null;
  if (!wanted) {
    return { ok: false, why: 'the expected Response holds no Result' };
  }
  if (actual.decision !== wanted.decision) {
    return { ok: false,
             why: 'expected ' + wanted.decision + ', got ' + actual.decision +
                  (actual.status && actual.status.message
                    ? ' (' + actual.status.message + ')' : ''),
             expected: wanted.decision, actual: actual.decision };
  }
  const obligationVerdict = compareObligations(wanted, actual);
  if (!obligationVerdict.ok) {
    return obligationVerdict;
  }
  return { ok: true, why: actual.decision };
}

// Obligations by IDENTIFIER and by count. Not by their attribute assignments:
// several IIIA cases carry assignments whose recorded values upstream's README
// lists as not schema-valid, and failing on those would be failing on the
// fixture rather than on the engine.
function compareObligations(wanted, actual) {
  const expectedIds = (wanted.obligations || []).map(function (item) {
    return item.id;
  }).sort();
  const actualIds = (actual.obligations || []).map(function (item) {
    return item.id;
  }).sort();
  if (expectedIds.length !== actualIds.length ||
      expectedIds.join('|') !== actualIds.join('|')) {
    return { ok: false,
             why: 'obligations differ: expected [' + expectedIds.join(', ') +
                  '], got [' + actualIds.join(', ') + ']' };
  }
  return { ok: true };
}

// ---------------------------------------------------------------------------
// THE CASE GROUPS.
//
// The suite's own prefixes, which are what the specification's conformance
// section groups them by — so a failure summary says "every IID case fails",
// which names a combining algorithm, rather than "57 cases fail", which names
// nothing.
// ---------------------------------------------------------------------------
const GROUPS = [
  { prefix: 'IIA', what: 'attribute references' },
  { prefix: 'IIB', what: 'target matching' },
  { prefix: 'IIC', what: 'the function library' },
  { prefix: 'IID', what: 'combining algorithms' },
  { prefix: 'IIE', what: 'policy references' },
  { prefix: 'IIF', what: 'other mandatory features' },
  { prefix: 'IIIA', what: 'obligations' }
];

function groupOf(name) {
  // Longest prefix first, so that `IIIA001` is not filed under `IIA`.
  const sorted = GROUPS.slice().sort(function (a, b) {
    return b.prefix.length - a.prefix.length;
  });
  for (let i = 0; i < sorted.length; i += 1) {
    if (name.indexOf(sorted[i].prefix) === 0) {
      return sorted[i];
    }
  }
  return { prefix: 'other', what: 'ungrouped' };
}

function checkManifest(t) {
  const report = MANIFEST.check();
  t.check(report.ok,
          'the vendored conformance suite is intact and unedited',
          report.ok ? MANIFEST.TREES[0].cases + ' mandatory cases'
                    : report.problems.join('; '));
  return report.ok;
}

function runMandatory(t) {
  const root = path.join(SUITE, 'mandatory');
  const names = fs.readdirSync(root).filter(function (entry) {
    return fs.statSync(path.join(root, entry)).isDirectory();
  }).sort();
  const tally = {};
  const failures = [];
  // Kept apart from `failures` on purpose: an EXPECTED failure is a decision
  // somebody wrote down with a reason, and folding the two lists together
  // would make the count of real defects depend on how many decisions had been
  // recorded.
  const expectedFailures = [];
  const stalePasses = [];
  names.forEach(function (name) {
    const group = groupOf(name);
    if (!tally[group.prefix]) {
      tally[group.prefix] = { pass: 0, fail: 0, expected: 0,
                              what: group.what };
    }
    let verdict;
    try {
      verdict = runCase(readCase(path.join(root, name)));
    } catch (error) {
      verdict = { ok: false, why: 'the runner threw: ' + error.message };
    }
    const expected = MANIFEST.EXPECTED_FAILURES.filter(function (entry) {
      return entry.case === name;
    })[0] || null;
    if (verdict.ok) {
      tally[group.prefix].pass += 1;
      if (expected) {
        // A case listed as an expected failure that has started PASSING is
        // drift too, and the direction nobody checks. Recorded here and
        // asserted below rather than quietly counted as a win.
        stalePasses.push(name);
      }
    } else if (expected) {
      tally[group.prefix].expected += 1;
      expectedFailures.push(name + ': ' + verdict.why);
    } else {
      tally[group.prefix].fail += 1;
      failures.push(name + ': ' + verdict.why);
    }
  });
  let totalPass = 0;
  let totalFail = 0;
  let totalExpected = 0;
  GROUPS.forEach(function (group) {
    const row = tally[group.prefix];
    if (!row) {
      return;
    }
    totalPass += row.pass;
    totalFail += row.fail;
    totalExpected += row.expected;
    t.check(row.fail === 0,
            group.prefix + ' — ' + group.what,
            row.pass + ' of ' + (row.pass + row.fail + row.expected) +
            ' pass' +
            (row.expected ? ', ' + row.expected + ' expected failure(s)'
                          : ''));
  });
  // The failing cases themselves, capped: a wall of 455 lines hides the
  // summary, and the first twenty are enough to see the shape of a defect.
  failures.slice(0, 20).forEach(function (failure) {
    t.log.error('    ' + failure);
  });
  if (failures.length > 20) {
    t.log.error('    … and ' + (failures.length - 20) + ' more.');
  }
  expectedFailures.forEach(function (entry) {
    t.log.info('    (expected) ' + entry);
  });
  t.check(totalFail === 0,
          'every mandatory XACML 3.0 conformance case passes, bar the ' +
          'recorded exceptions',
          totalPass + ' of ' + (totalPass + totalFail + totalExpected) +
          ', with ' + totalExpected + ' recorded in EXPECTED_FAILURES');
  // EXPECTED_FAILURES is asserted in BOTH directions, which is the half that
  // is easy to leave out: a case listed there which has started passing is as
  // much drift as one that has stopped.
  t.check(stalePasses.length === 0,
          'no case in EXPECTED_FAILURES has quietly started passing',
          stalePasses.length ? stalePasses.join(', ')
                             : MANIFEST.EXPECTED_FAILURES.length +
                               ' recorded, all still failing for their ' +
                               'recorded reason');
}

function run(t) {
  if (!checkManifest(t)) {
    // Without an intact suite the counts below would be meaningless, and a
    // percentage of an unknown denominator is worse than no percentage.
    return;
  }
  runMandatory(t);
}

module.exports = {
  name: 'xacml_conformance',
  describe: 'the OASIS XACML 3.0 conformance suite against this PDP',
  run: run,
  // Exported so that a developer iterating on one group can drive it directly
  // rather than through the whole runner.
  runCase: runCase,
  readCase: readCase
};
