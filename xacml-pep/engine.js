'use strict';
//
// File: xacml-pep/engine.js
//
// ===========================================================================
// LOADING THE ENGINE, AND THE ONE LIST OF WHAT THE ENGINE IS.
//
// A remote PEP carries its own copy of the XACML engine and evaluates locally.
// That is the whole reason for having one: a PEP that asked the PDP per
// request would be `POST /xacml/pdp` with a network hop in front of every
// access decision, and pushing POLICIES to something that cannot evaluate them
// makes no sense at all — you would push decisions instead.
//
// So this container needs seven modules out of `xacml/`, and there are three
// ways to get them here. Two of them are wrong and the reasons are worth
// keeping:
//
//   * **A CHECKED-IN COPY** — vendoring them into `xacml-pep/` the way
//     `common/vendored/` holds the parent project's files. Refused: those are
//     copies of ANOTHER REPOSITORY'S files and the drift is between two
//     projects. These would be copies of files in the same tree, edited in the
//     same commits, and the copy would be stale the first time somebody fixed
//     a combining algorithm. `xacml/CLAUDE.md`'s central rule is ONE MODEL,
//     and a second copy of the evaluator is the most expensive possible way to
//     break it.
//   * **AN npm PACKAGE** — publishing `xacml/` and depending on a version.
//     Refused for a mock: it puts a release step between editing a function
//     and seeing the PEP decide differently, which is the loop this whole
//     repository is arranged around.
//
// What is left is a BUILD-TIME COPY: the Dockerfile copies the seven modules
// out of `xacml/` into the image, and there is exactly one source of truth in
// the tree. `MODULES` below is the list, and it is EXPORTED so that
// `tests/xacml_pep.js` can assert the Dockerfile's `COPY` lines name the same
// seven — which is the standing obligation `CLAUDE.md` records the parent
// project having for its own `sts/` copy set, ENFORCED here rather than
// written down.
//
// ---------------------------------------------------------------------------
// THE SHIM, AND WHY `require.cache` IS PRIMED.
//
// The engine modules require `../common/helpers`. Inside the image that
// resolves to `xacml-pep/common/helpers.js` — thirty lines providing `log` and
// `xmlEscape`, and the point of the container, as that file argues. On a
// DEVELOPER'S MACHINE, running this file straight out of the repository, the
// same require resolves to the mock's own `common/helpers.js`, which drags in
// the config table, the crypto module, the realm registry and the whole
// identity service.
//
// **THAT DIFFERENCE WOULD MAKE THE HOST RUN AND THE CONTAINER RUN TWO
// DIFFERENT PROGRAMS**, and the one that is checked in CI would be the one
// nobody develops against. So the resolution is pinned rather than left to the
// layout: this file resolves `common/helpers` from the engine's own directory
// and installs the shim under that exact path in `require.cache` BEFORE the
// first engine module is required. In the image the two paths are the same
// file and the priming changes nothing; on the host it is what makes the
// engine load against the shim exactly as it does in the image.
//
// Priming the module cache is a blunt instrument and it is bounded here:
// this process is a PEP and nothing in it wants the mock's helpers. It would
// NOT be acceptable inside the mock, or in a test file that runs beside
// others in one process — which is why `tests/xacml_pep.js` drives this
// container as a CHILD PROCESS rather than requiring this module.
// ===========================================================================

const path = require('path');
const fs = require('fs');

// THE ENGINE. Seven modules, in dependency order, and the order is not
// decoration: it is the order the Dockerfile copies them in and the order the
// test checks, so a reader comparing the three lists reads them the same way.
const MODULES = [
  'xacml_model.js',
  'xacml_datatypes.js',
  'xacml_functions.js',
  'xacml_validate.js',
  'xacml_xml.js',
  'xacml_pdp.js',
  'xacml_json.js'
];

// WHAT IS DELIBERATELY NOT IN THAT LIST, because "why is this not here" is the
// question a reader arrives with:
//
//   xacml_store.js         the repository is ou=policies in the mock's
//                          directory. A PEP holds what it PULLED, in memory,
//                          and has no store — see `sync.js`.
//   xacml_pip.js           attributes come off a person's directory entry,
//                          which is the mock's directory. A remote PEP has no
//                          directory and asserts its attributes in the
//                          request, which is what a real PEP does.
//   xacml_alfa.js,         authoring. A PEP reads policy and never writes it.
//   xacml_templates.js,
//   xacml_editor.js
//   xacml.js,              they register express routes against the mock's
//   xacml_admin.js         own app. This container has an app of its own.
//   xacml_pep_registry.js, the PDP's side of phase five.
//   xacml_pep_http.js
//
// A PEP with no PIP is the interesting half of that list: it means every
// attribute a policy asks about must be IN the request, and an attribute that
// is not simply produces an empty bag. That is a real deployment shape rather
// than a limitation of this container — most PEPs know who the caller is and
// nothing else about them.

// Where the engine modules are. The image puts them beside this file; a
// developer's checkout has them one level up. Tried in that order so the
// container never depends on a repository being present.
function engineDir() {
  const here = path.join(__dirname, 'xacml');
  if (fs.existsSync(path.join(here, 'xacml_pdp.js'))) {
    return here;
  }
  const repo = path.join(__dirname, '..', 'xacml');
  if (fs.existsSync(path.join(repo, 'xacml_pdp.js'))) {
    return repo;
  }
  // FATAL AND SAID PLAINLY. A PEP with no engine cannot decide anything, and
  // the failure mode to avoid is one that starts, answers, and refuses
  // everything on its bias — which from outside looks exactly like a policy
  // that denies.
  throw new Error(
    'The XACML engine is not here. Looked in ' + here + ' and ' + repo +
    '. In the image the Dockerfile copies ' + MODULES.length + ' modules ' +
    'from xacml/ into ./xacml; on a developer machine this file expects to ' +
    'be run from inside the mock-sts checkout.');
}

// THE SHIM, INSTALLED UNDER THE PATH THE ENGINE WILL ASK FOR. See the header.
function installShim(dir) {
  const wanted = path.resolve(dir, '..', 'common', 'helpers.js');
  const shim = require('./common/helpers');
  if (require.resolve('./common/helpers') === wanted) {
    // The image: the engine already resolves to the shim and there is nothing
    // to pin. Said out loud rather than left as a silent no-op, because "the
    // priming did nothing" and "the priming was not reached" look the same in
    // a log otherwise.
    shim.log.debug('The engine resolves ../common/helpers to the shim ' +
                   'directly; nothing to pin.');
    return shim;
  }
  require.cache[wanted] = {
    id: wanted,
    filename: wanted,
    path: path.dirname(wanted),
    loaded: true,
    exports: shim,
    children: [],
    paths: []
  };
  shim.log.debug('Pinned ' + wanted + ' to this container\'s shim, so the ' +
                 'engine loads here exactly as it does in the image.');
  return shim;
}

const dir = engineDir();
const helpers = installShim(dir);

const loaded = {};
MODULES.forEach(function (file) {
  // The key is the module name without its extension — `model`, `pdp`, `json`
  // — because that is what the rest of this container calls them, and because
  // a key of `xacml_pdp.js` inside a directory whose every file is an XACML
  // module reads as a stutter.
  const key = file.replace(/^xacml_/, '').replace(/\.js$/, '');
  loaded[key] = require(path.join(dir, file));
});

helpers.log.info('The XACML engine is loaded from ' + dir + ': ' +
                 MODULES.length + ' modules, against a helpers shim ' +
                 'exporting log and xmlEscape and nothing else. Anything the ' +
                 'engine needed beyond those two would have thrown here ' +
                 'rather than working.');

module.exports = {
  MODULES: MODULES,
  engineDir: engineDir,
  log: helpers.log,
  model: loaded.model,
  datatypes: loaded.datatypes,
  functions: loaded.functions,
  validate: loaded.validate,
  xml: loaded.xml,
  pdp: loaded.pdp,
  json: loaded.json
};
