const path = require('path');

// ===========================================================================
// MANIFEST.js — what is vendored here, where each file came from, and which of
// them are JOBS rather than the helpers the jobs share.
//
// ---------------------------------------------------------------------------
// WHY THERE IS A LIST HERE AT ALL, WHEN THE REST OF tests/ HAS NONE.
//
// `run.js` discovers a test as *any .js file in tests/ that is not itself or
// harness.js*, and `tests/CLAUDE.md` argues that at length: the standing
// objection to a second suite is that it is a second place to forget, so the
// in-process suite has no such place. Nothing about that changes here, because
// the files in THIS directory are not this repository's to discover. They are
// COPIES, and a copy needs two things a discovered file does not:
//
//   1. AN ORIGIN, so drift can be detected. `tools/vendor-check.js` byte-
//      compares every entry below against the parent checkout when there is
//      one beside this repository. Without a list there is nothing to compare.
//   2. A JOB/HELPER SPLIT, because it cannot be derived from the content any
//      more. The rule the runner used while these files lived over there was
//      "does it mention WSTRUST_STS_URL or OID4VCI_ISSUER_URL" — and
//      `sts_applications.js` mentions both and is a HELPER, while
//      `sts_saml_encryption.js` is a job that declares no `--url` option and
//      would be missed by a guard looking for one. Two misclassifications in
//      nineteen files is a derivation that does not work, and a wrong answer
//      here is a job that silently never runs, which is the exact failure this
//      whole directory was created to stop.
//
// So the list is the price of vendoring, and it buys the drift check. It is
// NOT a precedent for listing anything else in tests/.
//
// ---------------------------------------------------------------------------
// THESE FILES ARE NOT EDITED HERE, AND THAT IS THE SAME RULE `common/vendored/`
// CARRIES.
//
// The parent project's `tests/` is the source of truth: those jobs are
// developed against that suite's own conventions, run in its containerized
// stack and its host stack, and are what its CI drives. A fix made HERE would
// be overwritten by the next sync and would never reach the stack that
// actually gates that project. **Edit the parent's copy, then re-sync** —
// `./local-run-tests.sh --vendor-sync` does the copy and
// `--vendor-check` reports what differs.
//
// THE EXCEPTION IS THE SIX JOBS MARKED `local: true` BELOW — this service's
// own `/admin` console and `/admin-api`. Those are NOT copies of anything: the
// parent deleted its own on 2026-08-28 and they are edited here and only here.
// The rule above applies to every other file in this directory.
//
// What vendoring buys is that this repository's suite RUNS with no parent
// checkout beside it. Before 2026-08-28 a machine with only this repository on
// it ran ten in-process files and reported the other thirteen jobs as absent;
// now it runs all twenty-seven. The drift check is the part that needs both
// checkouts, and it is therefore a TOOL rather than a job — see
// `tools/vendor-check.js` for why that distinction is deliberate.
// ===========================================================================

// ---------------------------------------------------------------------------
// TWO SOURCE DIRECTORIES, AND THE SECOND ONE IS THE SURPRISE.
//
// `tests/` is the obvious half: the jobs and the helpers they share.
//
// `client/src/` is the DEBUGGER'S OWN WALLET AND CRYPTO CODE, and five of the
// fifteen jobs load it deliberately. That is not an accident of layout — it
// is the POINT of those tests. `vc_did.js` checks that a credential this
// service issued verifies under the wallet's DID resolver;
// `sts_jws_verification.js` checks a signature against the debugger's PQC
// engine; `sts_userinfo_protected.js` opens an encrypted UserInfo response
// with the debugger's JWE engine. Each is the same argument `tests/CLAUDE.md`
// makes for keeping `xml-crypto` in package.json while no module requires it:
// an INDEPENDENT implementation is what makes "our signature verifies" mean
// something, and a test where both ends came from one implementation passes on
// a shared misunderstanding and interoperates with nobody.
//
// So those modules are vendored too, FLAT — `did.js` beside the job that reads
// it — which needs no edit to any vendored file, because `module_paths.js`
// already looks for exactly that layout as its second candidate. It is what
// the parent's own tests image does.
// ---------------------------------------------------------------------------
const SOURCE_DIR = 'tests';
const CLIENT_SOURCE_DIR = path.join('client', 'src');

// ---------------------------------------------------------------------------
// THE JOBS. Each is spawned as its own process by `tools/run-report.js`, with
// this directory as its cwd — which is what makes `CONFIG_FILE=./env/local.js`
// resolve, and what makes each job's `require('./random_username.js')` find the
// copy beside it rather than one over there.
//
// `browser: true` means the job drives Chrome through selenium-webdriver. There
// is exactly one, and it is the admin console's ONLY coverage against this
// working tree, which is why `--no-browser` names it when it leaves it out.
// ---------------------------------------------------------------------------
//
// `local: true` means THIS REPOSITORY OWNS THE FILE and there is no copy of it
// over there to compare against. SIX jobs are marked so, and they are the
// six that drive this service's OWN `/admin` console and its `/admin-api`:
// `sts_metadata.js`, `admin_api.js`, `sts_admin_api_operations.js`,
// `sts_admin_console.js`, `sts_delegated_permissions_example.js` and
// `sts_consent.js` — the last two of which are newer than the argument below
// and are covered by it for the same reason: one builds an example THROUGH
// `/admin-api` for somebody to read on `/admin`, and the other grants a GLOBAL
// CONSENT through `/admin-api/consent` and then watches a sign-in stop being
// asked, which is a console control with a protocol consequence and could not
// be asserted at all from a repository holding only one half of it. Read the
// paragraph below as though it said both: it builds an example THROUGH
// `/admin-api` for somebody to
// read on `/admin`, so the tree that changes those doors is the tree that
// should go red when it stops working. They ran from the parent project's `tests/` until
// 2026-08-28 and were removed there on that date, on the argument that a test
// asserting something about this console belongs in the tree where a control
// is added to that console — the tree that should go red when the control
// loses its operation. They still SIT here rather than in `tests/` because
// nothing about how they run changed: they are spawned as processes by
// `tools/run-report.js` with this directory as their cwd, and they
// `require('./random_username.js')` and the rest out of it. `run.js` discovers
// `tests/*.js` and runs it IN PROCESS against harness.js, which is a different
// kind of file entirely.
//
// What `local` buys is that `tools/vendor-check.js` does not compare them:
// `allFiles()` leaves them out, so a parent checkout beside this one reports
// clean instead of four GONE UPSTREAM, and `--vendor-sync` cannot overwrite
// them. THE EDITING RULE IS THEREFORE INVERTED FOR THESE FOUR — they are
// changed HERE, and only here.
// ---------------------------------------------------------------------------
const JOBS = [
  { file: 'admin_api.js',                browser: false, local: true },
  { file: 'ldp_vc_issuance.js',          browser: false },
  { file: 'ldp_vc_refresh.js',           browser: false },
  { file: 'oauth2_sts_endpoints.js',     browser: false },
  { file: 'sts_admin_api_operations.js', browser: false, local: true },
  { file: 'sts_admin_console.js',        browser: true,  local: true },
  { file: 'sts_consent.js',              browser: false, local: true },
  { file: 'sts_delegated_permissions_example.js', browser: false, local: true },
  { file: 'sts_dpop.js',                 browser: false },
  { file: 'sts_jws_verification.js',     browser: false },
  { file: 'sts_metadata.js',             browser: false, local: true },
  { file: 'sts_saml11.js',               browser: false },
  { file: 'sts_saml_encryption.js',      browser: false },
  { file: 'sts_userinfo_protected.js',   browser: false },
  { file: 'vc_did.js',                   browser: false }
];

// ---------------------------------------------------------------------------
// THE HELPERS, and `env/local.js`. None of these is a job; every one of them is
// reached by a `require` from at least one job above, which is the whole reason
// it is here. The set was computed as the transitive local-require closure of
// the fifteen jobs, not chosen — so a job that grows a new `require('./x.js')`
// over there arrives here as a MISSING MODULE at load time, which is a failed
// job with a name in it rather than a silent gap.
// ---------------------------------------------------------------------------
const HELPERS = [
  'browser_flags.js',
  'consent_screen.js',
  'expectation.js',
  'jwt_vc_json_common.js',
  'module_paths.js',
  'random_username.js',
  'sts_applications.js',
  'wait_for.js',
  'env/local.js'
];

// ---------------------------------------------------------------------------
// THE WALLET AND CRYPTO MODULES, from client/src/. The first seven are named
// by a job; the last six are their transitive requires, computed rather than
// chosen — so a module that grows a new `require('./x.js')` over there arrives
// here as MODULE_NOT_FOUND at load, which is a failed job with a name in it.
//
// The modules the jobs reach in THIS repository — `bbs2023.js` in
// common/vendored/, `client_auth.js` in oauth-oidc/ — are NOT vendored and
// must not be: they are the code under test. `run-report.js` points
// MOCK_STS_DIR at the repository root so `module_paths.js` finds them where
// they actually live.
// ---------------------------------------------------------------------------
const CLIENT_MODULES = [
  // named directly by a job
  'did.js',
  'jose_jwe.js',
  'jws.js',
  'metadata_client.js',
  'pqc.js',
  'sd_jwt_vc.js',
  'vci_wallet.js',
  // reached only through the seven above
  'crypto_bytes.js',
  'dpop.js',
  'op_metadata.js',
  'pk_encryption.js',
  'symmetric_crypto.js',
  'vci_metadata.js'
];

// Everything under version control here THAT CAME FROM OVER THERE, for the
// drift check: each entry says which of the parent's directories it came from,
// because the two halves are copied from different places into one flat
// directory. A `local` job is skipped — it has no upstream to differ from, and
// listing it would report it GONE UPSTREAM for ever. See the note on JOBS.
function allFiles() {
  const out = [];
  JOBS.forEach(function (j) {
    if (j.local) {
      return;
    }
    out.push({ rel: j.file, source: SOURCE_DIR });
  });
  HELPERS.forEach(function (h) {
    out.push({ rel: h, source: SOURCE_DIR });
  });
  CLIENT_MODULES.forEach(function (c) {
    out.push({ rel: c, source: CLIENT_SOURCE_DIR });
  });
  return out;
}

module.exports = { SOURCE_DIR: SOURCE_DIR, CLIENT_SOURCE_DIR: CLIENT_SOURCE_DIR,
                   JOBS: JOBS, HELPERS: HELPERS,
                   CLIENT_MODULES: CLIENT_MODULES, allFiles: allFiles };
