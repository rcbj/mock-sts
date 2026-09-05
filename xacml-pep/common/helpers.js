'use strict';
//
// File: xacml-pep/common/helpers.js
//
// ===========================================================================
// THE WHOLE OF THE XACML ENGINE'S DEPENDENCY ON THE IDENTITY SERVICE, IN
// THIRTY LINES. THIS FILE IS THE POINT OF THE CONTAINER.
//
// The seven engine modules — `xacml_model.js`, `xacml_datatypes.js`,
// `xacml_functions.js`, `xacml_validate.js`, `xacml_xml.js`, `xacml_pdp.js`
// and `xacml_json.js` — each open with a header claiming NO I/O, NO DOM and no
// store. Every one of them also opens with `require('../common/helpers')`, and
// that require is the claim's one loophole: `common/helpers.js` in the mock
// pulls in `config.js`, `crypto.js`, `pq_jose.js`, `realms.js`, node-forge,
// jsonwebtoken and the vendored BBS module, which is to say the whole identity
// service. A module that quietly reached past `log` into any of that would
// break nothing and nobody would notice.
//
// **THIS FILE IS WHAT MAKES THAT CLAIM FALSIFIABLE.** It provides exactly two
// names, `log` and `xmlEscape`, and it is what the engine resolves
// `../common/helpers` to inside this container. An engine module that grew a
// call to `config.value()`, `signJwt()` or `realms.map()` does not degrade
// here — it throws at load, and `tests/xacml_pep.js` fails naming the module.
// So "the engine is a library with no I/O" stops being a comment at the top of
// seven files and becomes a thing that is checked.
//
// It is therefore NOT a stub to be fleshed out. Growing a third export because
// some engine module wanted one is exactly the change this file exists to
// make visible: the right response to that is to take the dependency back out
// of the engine, or — if it genuinely belongs — to argue it here and in
// `xacml/CLAUDE.md`, because it is a change to what the engine IS.
//
// ---------------------------------------------------------------------------
// THE LOGGER IS BUNYAN AND THE SHAPE IS THE MOCK'S, deliberately: the engine
// calls `log.debug()` on entry and exit of every function longer than about
// ten lines (this repository's style rule), and a logger that did not answer
// `debug`, `info`, `warn` and `error` would make the engine throw somewhere
// unpredictable rather than fail to load.
// ===========================================================================

const bunyan = require('bunyan');

const log = bunyan.createLogger({
  name: 'xacml-pep',
  level: process.env.PEP_LOG_LEVEL || 'info'
});

// Byte-for-byte the mock's, because the engine's XML writer uses it and a
// second spelling of an escaper is a second set of edge cases. The five
// characters are the ones XML 1.0 section 2.4 requires escaping in content or
// in an attribute value; escaping the two quote forms unconditionally is what
// makes the same function safe in both positions.
function xmlEscape(value) {
  return String(value === undefined || value === null ? '' : value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

module.exports = { log: log, xmlEscape: xmlEscape };
