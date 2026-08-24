// File: common/config_file.js
//
// ---------------------------------------------------------------------------
// One place that decides what CONFIG_FILE means.
//
// Thirteen modules in this service read the appconfig file directly —
// `require(process.env.CONFIG_FILE)` — for one thing each: the bunyan log level
// they need before config.js exists. (It was fourteen until 2026-08-24:
// helpers.js's read had been dead for some time and was removed when CONFIG_FILE
// became optional, since `require(undefined)` throws.) That was harmless while every module sat
// in the package root, because node resolves a RELATIVE require against the
// directory of the module doing the requiring, and every one of them was in the
// same directory the `./env` tree hangs off.
//
// The 2026-08-23 reorganisation moved those modules into common/, kerberos/,
// common/vendored/ and so on, and it took that property away silently. The
// documented invocation is
//
//     CONFIG_FILE=./env/local.js node server.js
//
// and the Dockerfile bakes the same string in as an ENV. Read from
// common/config.js that path is `common/env/local.js`, which does not exist —
// so config.js, whose read is the only UNGUARDED one left, would die with
// MODULE_NOT_FOUND naming a path nobody typed, and the twelve guarded reads
// (the vendored PKI modules and the Kerberos codec, which fall back to "info"
// so a test can load them with no configuration at all) would quietly log at
// the wrong level with nothing to point at.
//
// So the variable is made ABSOLUTE once, before anything reads it, and every
// later `require(process.env.CONFIG_FILE)` in any directory then resolves to
// the same file. It is a mutation of process.env on purpose: the alternative is
// changing thirteen read sites, four of which are VENDORED files this
// repository may not edit (see common/vendored/CLAUDE.md).
//
// Three callers require this first and between them cover every way the service
// is loaded: server.js (the whole service), common/config.js and
// common/helpers.js (a module loaded in-process by a test, which is how the
// parent project drives the KDC). It is idempotent, so all three calling costs
// nothing.
//
// It is a LIBRARY under config.js — it requires nothing at all, not even
// bunyan, because config.js requires IT and a cycle there would hand back a
// half-initialised module (rule 2 in the root CLAUDE.md).
// ---------------------------------------------------------------------------

const path = require('path');
const fs = require('fs');

// The package root: this file is common/config_file.js, so one level up.
const ROOT = path.join(__dirname, '..');

// Resolve CONFIG_FILE to an absolute path, in place, and return it.
//
// Left alone when: it is unset (a test loading a leaf module with no
// configuration — the guarded readers fall back to "info"), it is already
// absolute, or it names a PACKAGE rather than a path. That last case is why the
// test is `startsWith('.')` rather than `!path.isAbsolute()`: a bare specifier
// is somebody's installed module and rewriting it into a filesystem path would
// break a resolution that works.
function resolveConfigFile() {
  const given = process.env.CONFIG_FILE;
  if (!given) {
    return null;
  }
  if (path.isAbsolute(given)) {
    return given;
  }
  if (!given.startsWith('.')) {
    return given;
  }
  // Two candidates, in this order. The package root is what the documented
  // invocation and the Dockerfile's ENV mean. The current working directory is
  // the fallback for a caller that started somewhere else and pointed at its
  // own file — the parent project's in-process Kerberos tests do exactly that,
  // with CONFIG_FILE naming the TEST suite's config rather than one of ours.
  const candidates = [ path.resolve(ROOT, given), path.resolve(process.cwd(), given) ];
  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) {
      process.env.CONFIG_FILE = candidate;
      return candidate;
    }
  }
  // Nothing found. Deliberately NOT a throw: the guarded readers must still be
  // able to load, and the unguarded ones will fail on their own require with
  // the path the operator typed, which is a better message than anything this
  // function could invent about a file it never saw.
  return given;
}

module.exports = { resolveConfigFile, ROOT };
