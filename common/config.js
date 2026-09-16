'use strict';
//
// File: config.js
//
// ---------------------------------------------------------------------------
// EVERY SETTING THIS SERVICE HAS, IN ONE TABLE.
//
// Until this file existed, configuration was forty-odd `process.env.X || 'a
// default'` expressions spread over twelve modules. Each was readable where it
// stood and the set of them was not: there was no way to ask this service what
// it was configured with, no way to change anything without restarting it, and
// no list anywhere of what could be changed at all — the answer was a grep, and
// the grep only found the ones spelt the way you guessed.
//
// So the reads moved here. `SETTINGS` below is the whole surface: one row per
// setting, carrying its name, where it may come from, what it means and — the
// part that could not be expressed at all before — whether changing it while
// the service runs does anything.
//
// ---------------------------------------------------------------------------
// WHERE A VALUE COMES FROM, highest wins:
//
//   1. a RUNTIME OVERRIDE          set through /admin/config or the management
//                                  API; in memory only, gone on restart
//   2. the setting's ENV VAR       STS_PORT, KRB5_REALM, ...
//   3. its LEGACY env var, if any  STS_ISSUER still feeds the three issuers
//                                  that were carved out of it
//   4. the APPCONFIG file          the CONFIG_FILE module, e.g. env/local.js
//   5. env/defaults.js             the DEFAULT appconfig file, which 4 is
//                                  unioned on top of
//
// AND THERE IS NO SIXTH. A setting with no value in 4 or 5 and no variable in
// 2 or 3 STOPS THIS SERVICE FROM STARTING — see requireComplete() at the foot
// of this file. That is the 2026-08-24 change and it is the point of the whole
// arrangement: a value nobody configured, arriving from a constant somewhere in
// a module, is exactly what made "what is this service configured with?"
// unanswerable before this table existed, and leaving a silent fallback under
// the table would have kept one way of asking the question wrong.
//
// 4 AND 5 ARE ONE LAYER, UNIONED, and that is what makes the refusal above
// affordable. `appconfig` below is env/defaults.js with the operator's file
// merged over it key by key, the operator's value winning wherever the two
// carry the same key. So:
//
//   * a config file may carry as few keys as it likes and still be complete —
//     which is what keeps the parent project's in-process Kerberos jobs
//     working, since they point CONFIG_FILE at the TEST suite's own config and
//     it carries none of this service's keys;
//   * a setting added to this table tomorrow does not break every config file
//     in the world on the day it is added, so long as env/defaults.js gains its
//     row — and env/defaults.js is GENERATED from the `dflt` column here, so
//     that is one edit rather than two;
//   * the refusal then fires on the one case it is for: a row in this table
//     with no row in env/defaults.js, which is a setting somebody added and did
//     not finish adding.
//
// The order is what makes this backwards compatible rather than merely similar:
// every env var that worked before works now and still beats the file, and a
// service started with no env vars at all and the shipped appconfig behaves
// exactly as it did — the shipped files were seeded with the built-in defaults,
// so 4 and 5 agree wherever both carry a key.
//
// FOUR SETTINGS ARE EXEMPT from the refusal, and they are the four marked
// `derived`: `global.https` comes from `oauth2.rfc9700`, `oid4vp.walletUrl`
// from `oid4vci.walletUrl`, `krb5.serviceDomains` from `krb5.realm`, and — since
// 2026-09-13 — `adminApi.audience` from `global.publicBaseUrl`, `global.https`,
// `global.host` and `global.port`. Their
// default is a FUNCTION of a neighbour, so writing a literal for them in
// env/defaults.js would freeze the derivation at whatever it evaluated to the
// day the file was written — which is why they are deliberately absent from
// every appconfig file here, and why demanding one would be demanding the one
// thing that is wrong.
//
// ---------------------------------------------------------------------------
// RUNTIME vs RESTART, and why the distinction is honest rather than cautious.
//
// `runtime: true` means the value is READ WHERE IT IS USED — per assertion, per
// request, per search — so changing it changes the next one. `runtime: false`
// means it was consumed at startup and nothing would happen if this file let
// you change it, so it does not: `set` refuses with the reason, which is on
// every one of those rows as `restartReason`.
//
// Three kinds of setting are restart-only and they are not the same kind:
//
//   * A BOUND SOCKET. The HTTP port, the two TLS ports, both LDAP ports and the
//     two Kerberos ports are held by a listener that started once. Rebinding in
//     place was considered and rejected: a failed rebind leaves the service
//     unreachable on the port the caller used to reach it, and that includes
//     this API.
//   * MATERIAL DERIVED AT STARTUP. The TLS certificate is issued for the names
//     in `tls.hostnames`/`tls.ips` when the process starts; the Kerberos
//     principal database and every long-term key in it are derived from the
//     realm, the SIDs and the passwords at require time. Changing the input
//     afterwards would leave the derived thing untouched and the two
//     disagreeing — which is worse than refusing, because it reads as having
//     worked.
//   * THE DIRECTORY TREE. `ldap.baseDn` is the root every entry was built
//     under.
//
// A row that is restart-only still appears everywhere a runtime one does, with
// its effective value and its reason. Hiding them would answer "what is this
// service configured with?" with three quarters of the answer.
//
// ---------------------------------------------------------------------------
// `realmRuntime`: RESTART-ONLY FOR THE PROCESS, SETTABLE ON A REALM.
//
// ELEVEN ROWS CARRY IT SINCE 2026-09-13 — `oauth2.rfc9700`, `oauth2.oauth21`
// (whose argument is made at its row) and the SPIFFE rows a realm's own
// listeners are bound from (whose argument is at the head of that group). This
// paragraph said ONE ROW until then and the rest of it is the first row's
// argument, kept as written. It is not a softening of the rule
// above but an application of it. That flag is restart-only for exactly one
// reason: `global.https` derives its default from it, so turning it on binds
// the main port as HTTPS, and a bound socket is the first of the three kinds
// listed above. A REALM CANNOT BIND A SOCKET. It answers on the port the
// process already opened, in the scheme that port was opened in, so the reason
// the flag is restart-only cannot apply to it: nothing about a realm's
// existence was consumed at startup, and `enabled()` in `oauth2_bcp.js` reads
// the setting per request, through the realm layer, like every other runtime
// row here.
//
// So `checkOverride(key, raw, true)` — the form `realms.js` calls, and the only
// caller that passes the third argument — admits a `realmRuntime` row where the
// process-wide form still refuses it. The refusal a person meets on
// /admin/config in the DEFAULT realm is unchanged, and so is the one at
// `POST /admin-api/config/set` outside a realm.
//
// What that buys, and it is the reason the marker exists rather than the flag
// simply being made runtime again: one process can now serve BOTH the
// permissive pass and the compliant one — `/oauth2/authorize` and
// `/realm/rfc9700/oauth2/authorize` — which is what a client-exercising matrix
// wants and what two instances used to be needed for.
//
// AND IT HAS A SECOND HALF, which was missing until 2026-08-25: a realm that
// may carry the mode must not thereby carry a conclusion ABOUT the socket.
// `global.https` derives its default from this row, so reading that default
// through the realm layer handed the realm an answer only the process can give.
// See processValue() further down — the fix is that the derived read is made
// process-wide, not that the marker is any narrower.
//
// DO NOT ADD A SECOND ONE BY ANALOGY. The test is the paragraph above: the
// restart reason has to be something a realm demonstrably does not have. A
// setting whose value was consumed at startup to build MATERIAL — the TLS
// certificate, the Kerberos principal database, the directory tree — is
// consumed for the whole process, realms included, so `realmRuntime` on one of
// those would be the silent disagreement this file warns about rather than an
// exemption from it.
//
// **THIS PARAGRAPH CALLED `krb5.realm` "THE CLEAREST NO", AND ON 2026-09-15 IT
// STOPPED BEING ONE — BY THE TEST ABOVE, NOT AGAINST IT.** The objection was
// that the principal database is built for the whole process at startup. That
// was the fact to change rather than the rule: a trust realm now builds a
// principal database of its OWN, lazily, when its Kerberos is turned on —
// SPIFFE made the same move for its authorities on 2026-09-12 — so for a realm
// nothing
// was consumed at startup, and the nine rows that database is built from are
// `realmRuntime`. What is still consumed for the process stays refused on a
// realm: the sockets (`krb5.kdcPort`, `krb5.servicePort`) and the
// development-mode trust with `krb5.trustedRealm`. The test is still the rule;
// a setting whose material stays process-wide is still a no.
//
// ---------------------------------------------------------------------------
// This module is a LIBRARY (rule 3): it registers no route, and it requires
// nothing from this repository — not even `helpers.js`, which requires IT. That
// is why it makes a bunyan logger of its own rather than taking the shared one:
// a require cycle here would hand `helpers.js` a half-initialised module whose
// `value` is undefined, and the symptom would arrive somewhere else entirely as
// "value is not a function".
//
// IT PUBLISHES THE KERBEROS PASSWORDS, and that is deliberate and not new:
// `GET /krb5/principals` already prints them, for the reason written there — a
// debugger whose accounts are unusable without reading the source is worse than
// one that says what they are.
//
// Where they are published now needs one distinction. `/admin/config` is behind
// the console gate, which is unconditional, and `GET /admin-api/config` is
// behind a credential of its own — an OAuth 2.0 access token carrying
// `admin:read` (`adminApi.authRequired`, on by default since 2026-09-09). Both
// of those are turnstiles for exercising a client rather than locks: in the
// default `development` mode no password anywhere in this service is checked,
// so what either gate proves is that somebody typed a name. The settings,
// passwords included, are readable by anybody who gets through one. Do not put
// this port on a public address.
// ---------------------------------------------------------------------------

// CONFIG_FILE is made ABSOLUTE before it is read. This module lives in a
// subdirectory now, and a relative `./env/local.js` resolves against THIS
// directory rather than the package root — see common/config_file.js, which is
// required first for that reason and requires nothing itself.
const configFile = require('./config_file');
configFile.resolveConfigFile();
// The registry of failure codes. A LEAF that requires nothing, so this module
// stays under helpers.js. It must NOT be audit.js, which requires this file:
// every failure here is logged with `errorCodes.tag()` instead, and the two
// that stop the process are written before any audit ring could hold them
// anyway.
const errorCodes = require('./error_codes');
const path = require('path');
const bunyan = require('bunyan');

// ---------------------------------------------------------------------------
// THE APPCONFIG LAYER, which is TWO FILES unioned rather than one.
//
// env/defaults.js is the base and is not selected by anything: it carries the
// `dflt` of every non-derived row in the table below, and is GENERATED from
// that column so the two cannot drift. The operator's file — whatever
// CONFIG_FILE names — is merged over it, and the operator's value wins wherever
// both carry a key. See the header: it is the union that makes the startup
// refusal affordable, because it means no config file can be INCOMPLETE, only
// smaller than this one.
//
// CONFIG_FILE MAY NOW BE UNSET, which it could not be before:
// `require(undefined)` threw a TypeError naming an "id" argument nobody typed.
// With a base file there is something to fall back to, so an unset variable
// means "the defaults" and says so. (helpers.js still requires CONFIG_FILE
// unguarded, so that is a property of THIS module rather than of the whole
// service — a leaf module loaded by a test can now be loaded with no
// configuration at all.)
//
// A file that cannot be loaded is FATAL and is not swallowed. Every other
// failure here is reported and carried on from, because a stale key must not
// stop a service starting; a config file that does not parse is different in
// kind — every value the operator meant to set is missing, and continuing would
// mean starting a service configured as nobody asked for.
// ---------------------------------------------------------------------------
const DEFAULTS_FILE = path.join(configFile.ROOT, 'env', 'defaults.js');
const defaults = require(DEFAULTS_FILE);

// A two-file union. Plain objects merge key by key; everything else — a scalar,
// an array, a Date — is REPLACED wholesale by the override, because a merged
// array is neither file's list and an operator writing `tls: { hostnames: [...]
// }` means that list rather than that list appended to ours.
function isPlainObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

function union(base, over) {
  const out = {};
  Object.keys(base || {}).forEach(function (key) { out[key] = base[key]; });
  Object.keys(over || {}).forEach(function (key) {
    if (isPlainObject(out[key]) && isPlainObject(over[key])) {
      out[key] = union(out[key], over[key]);
      return;
    }
    out[key] = over[key];
  });
  return out;
}

// What the operator's file actually carried, kept SEPARATELY from the union.
// auditAppconfig() reads this one: the union can never be missing a key, so an
// audit against it could not answer the question that audit exists to answer —
// "does the file I am editing still list the whole surface?".
let operatorConfig = {};
if (process.env.CONFIG_FILE) {
  try {
    operatorConfig = require(process.env.CONFIG_FILE);
  } catch (err) {
    // Fatal, and deliberately before any logger exists — bunyan would need a
    // level out of the file that just failed to load.
    process.stderr.write(errorCodes.tag('STS-CORE-0001') + 'config: FATAL — ' +
        'the appconfig file ' +
      process.env.CONFIG_FILE + ' could not be loaded: ' + err.message +
        '\nCONFIG_FILE ' +
      'names a JavaScript module, resolved against this package root and ' +
      'then against the working directory (see common/config_file.js).\n');
    process.exit(1);
  }
}

const appconfig = union(defaults, operatorConfig);

const log = bunyan.createLogger({ name: 'sts-config',
                                  level: appconfig.logLevel || 'info' });

// ---------------------------------------------------------------------------
// Types.
//
// A value arrives here as a string when it came from the environment or from a
// form, and as whatever the author wrote when it came from the appconfig file.
// Both have to end up as the same thing, so every type coerces from either —
// `parse` — and renders back to the single-line form the console's input shows
// and the environment would carry — `text`.
//
// `check` returns an error STRING or null. It is separate from `parse` because
// the two are asked at different times: a value from the file is parsed and
// used, while a value from a caller is checked first and refused by name.
// ---------------------------------------------------------------------------
const TYPES = {
  string: {
    parse: function (raw) {
      log.debug("Entering parse().");
      log.debug("Leaving parse().");
      return raw === undefined ? '' : String(raw);
    },
    text: function (v) {
      log.debug("Entering text().");
      log.debug("Leaving text().");
      return String(v == null ? '' : v);
    },
    check: function () {
      log.debug("Entering check().");
      log.debug("Leaving check().");
      return null;
    }
  },

  // An integer. Rejects the empty string rather than reading it as 0, because
  // "" is what an emptied form field sends and 0 is a port.
  //
  // A ROW MAY NARROW IT with `min`, `max` and `step`, and all three are
  // OPTIONAL — a row that carries none of them behaves exactly as every int row
  // did before they existed, which is what keeps the forty-odd existing ones
  // untouched. They arrived for the four token-lifetime settings, where the
  // bounds are part of what the setting MEANS rather than a validation nicety:
  // a lifetime of nine seconds and a clock skew of a fortnight are both
  // typeable, both accepted by "is it a whole number", and both produce a
  // service whose tokens are wrong in a way that reads as a client bug.
  // Refusing them BY NAME here is the only place the refusal can be made once
  // for the console form, the management API and an environment variable read
  // at startup.
  //
  // `step` is a MULTIPLE-OF rather than a slider increment: 30 means the value
  // must be a whole number of thirty-second units. It is checked against `min`
  // rather than against zero, so a row whose floor is not itself a multiple of
  // the step still has a reachable floor.
  int: {
    parse: function (raw) {
      log.debug("Entering parse().");
      const n = parseInt(String(raw), 10);
      log.debug("Leaving parse().");
      return Number.isFinite(n) ? n : 0;
    },
    text: function (v) {
      log.debug("Entering text().");
      log.debug("Leaving text().");
      return String(v);
    },
    check: function (raw, setting) {
      log.debug("Entering check().");
      const s = String(raw).trim();
      if (!s) {
        log.debug("Leaving check().");
        return 'must be a number';
      }
      if (!/^-?\d+$/.test(s)) {
        log.debug("Leaving check().");
        return 'must be a whole number, got "' + raw + '"';
      }
      const n = parseInt(s, 10);
      const min = setting && setting.min;
      const max = setting && setting.max;
      const step = setting && setting.step;
      if (typeof min === 'number' && n < min) {
        log.debug("Leaving check().");
        return 'must be at least ' + min + ', got ' + n;
      }
      if (typeof max === 'number' && n > max) {
        log.debug("Leaving check().");
        return 'must be at most ' + max + ', got ' + n;
      }
      if (typeof step === 'number' && step > 1 &&
          (n - (typeof min === 'number' ? min : 0)) % step !== 0) {
        log.debug("Leaving check().");
        return 'must be a multiple of ' + step +
               (typeof min === 'number' && min % step !== 0 ? ' above ' + min :
                '') +
               ', got ' + n;
      }
      log.debug("Leaving check().");
      return null;
    }
  },

  // A TCP port. 0 is allowed and means "any free port", which is what
  // tests/krb5_spnego_http.js uses to start the KDC without claiming 88.
  port: {
    parse: function (raw) {
      log.debug("Entering parse().");
      const n = parseInt(String(raw), 10);
      log.debug("Leaving parse().");
      return Number.isFinite(n) ? n : 0;
    },
    text: function (v) {
      log.debug("Entering text().");
      log.debug("Leaving text().");
      return String(v);
    },
    check: function (raw) {
      log.debug("Entering check().");
      const s = String(raw).trim();
      if (!/^\d+$/.test(s)) {
        log.debug("Leaving check().");
        return 'must be a port number, got "' + raw + '"';
      }
      const n = parseInt(s, 10);
      if (n > 65535) {
        log.debug("Leaving check().");
        return 'must be 0-65535, got ' + n;
      }
      log.debug("Leaving check().");
      return null;
    }
  },

  // Truthy spellings, matching what the modules accepted before: LDAP read
  // /^(1|true|yes|on)$/i and OID4VCI compared against the literal 'true'. The
  // union is accepted so neither spelling regressed.
  //
  // A value that is NEITHER spelling falls back to the setting's own DEFAULT,
  // and that is the half worth explaining. This used to be a truthy allow-list
  // alone — anything unrecognised was false — which reads as harmless until a
  // setting whose default is ON meets a typo: `LDAP_AUTOCREATE_USERS=treu`
  // silently turned off the feature docs/ldap.md says only an explicit
  // 0/false/no/off turns off. check() catches a misspelling on the admin
  // console's Save, but nothing checks an environment variable at startup, so
  // the only place that asymmetry could be fixed is here. A value nobody can
  // read is WARNED about rather than swallowed: falling back silently is how a
  // typo survives to be discovered as a missing feature.
  bool: {
    parse: function (raw, setting) {
      log.debug("Entering parse().");
      if (typeof raw === 'boolean') {
        log.debug("Leaving parse().");
        return raw;
      }
      const text = String(raw).trim();
      if (/^(1|true|yes|on)$/i.test(text)) {
        log.debug("Leaving parse().");
        return true;
      }
      if (/^(0|false|no|off)$/i.test(text)) {
        log.debug("Leaving parse().");
        return false;
      }
      const fallback = !!(setting && setting.dflt);
      log.warn('config: "' + text + '" is not a true/false value' +
               (setting && setting.env ? ' for ' + setting.env : '') +
               '; using the default (' + fallback + ').');
      log.debug("Leaving parse().");
      return fallback;
    },
    text: function (v) {
      log.debug("Entering text().");
      log.debug("Leaving text().");
      return v ? 'true' : 'false';
    },
    check: function (raw) {
      log.debug("Entering check().");
      if (typeof raw === 'boolean') {
        log.debug("Leaving check().");
        return null;
      }
      if (/^(1|0|true|false|yes|no|on|off)$/i.test(String(raw).trim())) {
        log.debug("Leaving check().");
        return null;
      }
      log.debug("Leaving check().");
      return 'must be true or false, got "' + raw + '"';
    }
  },

  // A comma-separated list, trimmed, with the empty entries dropped. An array
  // in the appconfig file is accepted as itself: writing a list as a list is
  // the obvious thing to do in a JavaScript file and it would be perverse to
  // demand a string there because the environment can only carry one.
  csv: {
    parse: function (raw) {
      log.debug("Entering parse().");
      const parts = Array.isArray(raw) ? raw :
                    String(raw === undefined ? '' : raw).split(',');
      log.debug("Leaving parse().");
      return parts.map(function (part) { return String(part).trim(); })
                  .filter(function (part) { return part.length > 0; });
    },
    text: function (v) {
      log.debug("Entering text().");
      log.debug("Leaving text().");
      return (Array.isArray(v) ? v : [v]).join(',');
    },
    check: function () {
      log.debug("Entering check().");
      log.debug("Leaving check().");
      return null;
    }
  },

  // One of a fixed set. The set is on the setting rather than on the type,
  // since every enum here has a different one.
  enum: {
    parse: function (raw) {
      log.debug("Entering parse().");
      log.debug("Leaving parse().");
      return String(raw === undefined ? '' : raw).trim();
    },
    text: function (v) {
      log.debug("Entering text().");
      log.debug("Leaving text().");
      return String(v == null ? '' : v);
    },
    check: function (raw, setting) {
      log.debug("Entering check().");
      const s = String(raw).trim();
      if (setting.enumValues.indexOf(s) >= 0) {
        log.debug("Leaving check().");
        return null;
      }
      log.debug("Leaving check().");
      return 'must be one of ' + setting.enumValues.join(', ') + ', got "' +
             raw + '"';
    }
  }
};

// ---------------------------------------------------------------------------
// THE TABLE.
//
// `key` is the dot path in the appconfig file as well as the name used
// everywhere else — `oid4vci.batchSize` is `appconfig.oid4vci.batchSize` — so
// there is one name for a setting rather than one per surface. Where the two
// had to differ there is an explicit `path`, and there is exactly one: the log
// level was `logLevel` at the top of the appconfig file before this table
// existed and it stays there, because moving it would have broken every
// existing config file for no gain.
//
// `dflt` may be a FUNCTION where the default depends on another setting. Two do
// — the Kerberos service domains are derived from the realm, and the OID4VP
// wallet falls back to the OID4VCI one — and both were expressions in their
// modules before, which is why they are expressions here rather than duplicated
// constants that could drift from what they mirror.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// ONE ROW PER KIND OF SIGNED TOKEN, SAYING WHETHER ITS HEADER CARRIES `x5c` OR
// `x5u` (2026-09-13). Twelve rows in six groups, so that each is drawn on the
// console page of the protocol whose tokens it governs — and one function,
// because they share every sentence but the first and twelve copies of a
// paragraph is twelve places for one of them to go stale.
// `common/jose_certificate_header.js` is the policy and holds the list of use
// cases; `tests/jose_certificate_header.js` holds the list and these rows to
// each other. The enum is that module's `MODES` written out, because this file
// requires nothing from the repository that could require it back.
// ---------------------------------------------------------------------------
function certificateHeaderSetting(key, group, env, label, what) {
  log.debug("Entering certificateHeaderSetting(). key=" + key);
  log.debug("Leaving certificateHeaderSetting().");
  return {
    key: key, group: group, label: label, env: env, type: 'enum',
    enumValues: ['none', 'x5c', 'x5u', 'both'],
    dflt: 'x5u', runtime: true,
    description: what + ' `x5u` — the default — is the address of the ' +
                 'chain on this service, ' +
                 '`/pki/chain/{scope}/{sha256}.pem`, about a hundred bytes; ' +
                 '`x5c` is the chain inline, leaf first and the service Root ' +
                 'last, base64 DER, several kilobytes; `both` is both and ' +
                 '`none` neither. Either way it is what a relying party ' +
                 'holding only the token needs to reach every certificate\'s ' +
                 'CRL distribution points, OCSP responder and caIssuers ' +
                 'address. A key not yet certified under this realm\'s JOSE ' +
                 'Issuing CA, and an HMAC signature, get neither. RFC 7515 ' +
                 'section 4.1.5 requires the `x5u` fetch to use TLS: with ' +
                 'global.https off the address is `http://` and a strict ' +
                 'verifier will refuse to follow it. JWE headers are never ' +
                 'given one — no certified key of this service encrypts ' +
                 'anything. Settable per realm.'
  };
}

// The sentence every Kerberos row a trust realm's principal database is built
// from adds to its restart reason (2026-09-15). One copy, because nine rows
// saying it nine slightly different ways is how one of them ends up wrong.
const REALM_BUILDS_ITS_OWN = '. A TRUST REALM may carry it even so: a ' +
  'realm\'s principal database is built when its Kerberos is turned on and ' +
  'rebuilt when this changes, so nothing about the realm\'s value was ' +
  'consumed at startup';

const SETTINGS = [
  // --- Global --------------------------------------------------------------
  { key: 'global.host', group: 'Global', label: 'HTTP bind address',
    env: 'STS_HOST', type: 'string', dflt: '0.0.0.0', runtime: false,
    restartReason: 'the listener is bound when the process starts',
    description: 'The address the HTTP listener binds. 0.0.0.0 is every ' +
                 'interface, which is what a container needs; 127.0.0.1 ' +
                 'confines this service to the machine it runs on.' },

  { key: 'global.port', group: 'Global', label: 'HTTP port',
    env: 'STS_PORT', type: 'port', dflt: 8081, runtime: false,
    restartReason: 'the listener is bound when the process starts',
    description: 'The port everything HTTP here answers on: the protocol ' +
                 'endpoints, the console and this API. The two TLS listeners ' +
                 'are separate and are the tls.* settings, which the console ' +
                 'draws on its own TLS page.' },

  // ---------------------------------------------------------------------
  // The scheme the port above answers on, and it is DERIVED (`derived: true`,
  // so the shipped env/*.js files do not carry it): its default is whatever
  // `oauth2.rfc9700` is, because RFC 9700 section 2.1 says an authorization
  // response must not be sent over an unencrypted connection and this service's
  // authorization endpoint lives on this port.
  //
  // It is a row of its own rather than a line inside server.js for the two
  // reasons that make anything a row here: it can be set INDEPENDENTLY, both
  // ways round, and each direction is a real case. HTTPS with the checks off
  // exercises a client's TLS handling against a certificate it has to fetch and
  // trust; the checks on over plain HTTP is for a client that cannot be taught
  // to trust a certificate regenerated on every start, and it is why the mode
  // does not simply refuse an insecure request instead of publishing the fact.
  // `GET /oauth2/rfc9700` reports which of the two is in force.
  //
  // WHAT IT COSTS, because it is not free: there is then NO plain listener in
  // this process at all, and `POST /tls/trust` and `GET
  // /tls/server-certificate` were on one deliberately — they are what a caller
  // reaches BEFORE it trusts anything. The certificate is self-signed and
  // regenerated every start, so the first fetch has to be made without
  // verification (`curl -k`), which is the ordinary bootstrap for a mock and is
  // stated on /tls rather than left to be discovered.
  { key: 'global.https', group: 'Global', label: 'HTTPS on the main port',
    env: 'STS_HTTPS', type: 'bool', derived: true,
    // processValue() and not value(): a realm may carry `oauth2.rfc9700`, and
    // this default is a statement about a bound socket, which no realm bound.
    // `oauth2.oauth21` implies RFC 9700 mode (2026-09-13), so it moves the
    // socket the same way and is read the same way.
    dflt: function () {
      log.debug("Entering dflt().");
      log.debug("Leaving dflt().");
      return !!(processValue('oauth2.rfc9700') ||
                processValue('oauth2.oauth21'));
    },
    runtime: false,
    restartReason: 'the listener is bound when the process starts, and its ' +
                   'scheme is decided there',
    description: 'Serve the main port over HTTPS, with the SAME certificate ' +
                 'and key the 8443, 9443 and LDAPS 636 listeners use — one ' +
                 'self-signed pair generated per start, so a caller trusts ' +
                 'this service once rather than four times. Defaults to on ' +
                 'when oauth2.rfc9700 or oauth2.oauth21 is; set it ' +
                 'explicitly to run RFC 9700 mode over plain http (for a ' +
                 'client that cannot trust a per-start certificate) or to ' +
                 'serve HTTPS without the mode\'s refusals. Fetch the ' +
                 'certificate from /tls/server-certificate — with ' +
                 'verification off the first time, since with this on there ' +
                 'is no plain port left to fetch it from.' },

  // ---------------------------------------------------------------------
  // WHETHER A FORWARDED HEADER IS BELIEVABLE, which is the server's half of
  // RFC 9700 section 2.6's reverse-proxy paragraph.
  //
  // `X-Forwarded-Proto` and `X-Forwarded-Host` are how a TLS-terminating proxy
  // tells the application what the CLIENT actually used. Believing them is
  // necessary behind a proxy and dangerous without one, because they are
  // ordinary request headers: with no proxy in front, any client can set them
  // and choose what this service thinks its own URLs are.
  //
  // What that changes here: the `iss` of every token and every URL in both
  // discovery documents (baseUrlOf), and the `htu` a DPoP proof is checked
  // against (dpop.js). The second is the one with teeth — if a client controls
  // the expected htu, it can replay a proof captured from another endpoint by
  // naming that endpoint in a header, and RFC 9449's binding of a proof to its
  // target stops meaning anything.
  //
  // OFF by default, which is the secure reading and a CHANGE: dpop.js used to
  // honour those headers unconditionally. A deployment behind a proxy turns it
  // on, and until it does, a DPoP refusal names this setting rather than
  // leaving somebody to guess.
  { key: 'global.trustProxy', group: 'Global', label: 'Trust forwarded headers',
    env: 'STS_TRUST_PROXY', type: 'bool', dflt: false, runtime: true,
    description: 'Believe X-Forwarded-Proto and X-Forwarded-Host — which is ' +
                 'what a TLS-terminating reverse proxy sets to say what the ' +
                 'CLIENT used. Turn it ON when something is in front of this ' +
                 'service, or the metadata will publish http:// URLs to ' +
                 'clients that reached it over https and every DPoP proof ' +
                 'will be refused for naming the real endpoint. Leave it OFF ' +
                 'when nothing is: with no proxy, those are ordinary headers ' +
                 'any client can set, and believing them lets a caller ' +
                 'choose what this service thinks its own issuer and ' +
                 'endpoints are. GET /tls/forwarded shows what a request ' +
                 'actually carried and what was believed of it. NOTE that ' +
                 'this service never reads a client certificate out of a ' +
                 'header (X-Client-Cert and its relatives) in either mode — ' +
                 'a forwarded certificate is a certificate anybody can ' +
                 'forge.' },

  // Added 2026-09-14 (#46 section 8). `global.trustProxy` alone believed a
  // forwarded header from anybody who could reach a node, including past the
  // load balancer; `common/client_address.js` argues the boundary.
  { key: 'global.trustedProxies', group: 'Global',
    label: 'Trusted proxy addresses',
    env: 'STS_TRUSTED_PROXIES', type: 'csv', dflt: '', runtime: true,
    description: 'The addresses or CIDR ranges this deployment\'s own ' +
                 'proxies and load balancers connect from, comma-separated ' +
                 '(10.0.0.0/8, fd00::/8). Read only when global.trustProxy ' +
                 'is on. EMPTY, the default, keeps the old rule: forwarded ' +
                 'headers are believed from any caller, and the rate ' +
                 'limiter takes the left-most X-Forwarded-For entry, which ' +
                 'the client writes itself. SET, X-Forwarded-For, ' +
                 'X-Forwarded-Proto and X-Forwarded-Host are believed only ' +
                 'from a connection whose peer is in one of these ranges, ' +
                 'and the client is the right-most X-Forwarded-For entry ' +
                 'that is not — so a caller reaching a node directly can ' +
                 'neither pick its own rate-limit address nor this ' +
                 'service\'s idea of its own URL. A value that is not an ' +
                 'address or a range is ignored and logged, never widened. ' +
                 'With global.proxyProtocol on it is ALSO the list a PROXY ' +
                 'protocol header is believed from, whatever ' +
                 'global.trustProxy says — and there an empty list trusts ' +
                 'nobody, so the service refuses to start.' },

  // Added 2026-09-14 (#46). Behind an L4 load balancer with TLS passthrough —
  // an AWS Network Load Balancer is the case — the peer of every connection is
  // the balancer, and no forwarded header can exist below TLS.
  // `common/proxy_protocol.js` argues the three kinds of peer and where the
  // address is put.
  { key: 'global.proxyProtocol', group: 'Global',
    label: 'PROXY protocol on the TCP listeners',
    env: 'STS_PROXY_PROTOCOL', type: 'enum', enumValues: ['off', 'v2'],
    dflt: 'off', runtime: false, perProcess: true,
    restartReason: 'it is installed on each listener when that listener ' +
                   'binds, and a connection half-way through a header ' +
                   'cannot be told the rules changed',
    description: 'Whether every TCP listener this service owns expects a ' +
                 'HAProxy PROXY protocol version 2 header at the front of ' +
                 'each connection: the main port, 8443 and 9443, LDAP 389 ' +
                 'and LDAPS 636, the KDC\'s TCP 88 (not UDP), the embedded ' +
                 'debugger and the plain-HTTP revocation listener. `off`, ' +
                 'the default, reads no header. `v2` reads it BEFORE TLS, ' +
                 'so the client\'s address reaches the rate limiter, the ' +
                 'audit, LDAP and /tls/whoami while TLS — and mutual TLS — ' +
                 'still terminates here; it is what an AWS Network Load ' +
                 'Balancer sends with the target group attribute ' +
                 'proxy_protocol_v2.enabled, and HAProxy with send-proxy-v2. ' +
                 'A connection from global.trustedProxies MUST begin with a ' +
                 'valid header (a LOCAL header, which health checks send, ' +
                 'keeps the balancer\'s address); a connection from any ' +
                 'other address is CLOSED, except one from this host itself, ' +
                 'which is served plain because the service dials its own ' +
                 'main port. Version 1 is refused. The SPIFFE gRPC listeners ' +
                 'are not covered.' },

  { key: 'global.proxyProtocolTimeoutMs', group: 'Global',
    label: 'PROXY protocol header timeout (ms)',
    env: 'STS_PROXY_PROTOCOL_TIMEOUT_MS', type: 'int', dflt: 5000,
    min: 100, max: 60000, runtime: true, perProcess: true,
    description: 'How long a connection from a trusted proxy may take to ' +
                 'send its complete PROXY protocol header before it is ' +
                 'closed. A balancer writes the header in the first segment, ' +
                 'so this bounds a slow or stalled sender holding a socket ' +
                 'open, not a real client. Read only with ' +
                 'global.proxyProtocol on.' },

  // Added 2026-09-12. `baseUrlOf()` read the request's Host header and nothing
  // else could pin it, so a caller chose what this service believed its own
  // issuer, callback addresses and WebAuthn origin were — and `/admin` wrote a
  // callback on an invented Host permanently onto its own client entry.
  { key: 'global.publicBaseUrl', group: 'Global', label: 'Public base URL',
    env: 'STS_PUBLIC_BASE_URL', type: 'string', dflt: '', runtime: true,
    description: 'The scheme, host and port this service is reached at, as a ' +
                 'client should name it — https://idp.example.com, with no ' +
                 'path. Empty (the default) reads it off each request, which ' +
                 'is what lets one process answer correctly under every name ' +
                 'it is reached by. Set, it is the base of every issuer, ' +
                 'metadata URL, redirect and origin this service builds, ' +
                 'whatever Host header a request carried — which is what a ' +
                 'deployed identity provider wants, and it also beats ' +
                 'global.trustProxy. A trust realm\'s path prefix is still ' +
                 'appended.' },

  // Added 2026-09-13 with the CORS allowlist (`common/cors.js`). An origin
  // listed here is one this DEPLOYMENT calls its own — exactly as the main
  // listener, `global.publicBaseUrl` and the embedded debugger are — so it is
  // allowed on every path without being on any application. What it is FOR is
  // a page this service does not serve and an operator vouches for anyway: the
  // parent project's debugger on its own port in a test stack, or a
  // deployment's own administration front end. A third party's page belongs on
  // its application's `appCorsOrigin`, where the per-client rule applies.
  { key: 'global.corsOrigins', group: 'Global',
    label: 'Origins treated as this service\'s own',
    env: 'STS_CORS_ORIGINS', type: 'csv', dflt: '', runtime: true,
    description: 'Origins — scheme, host and port, no path — that CORS treats ' +
                 'as this deployment\'s OWN, comma-separated, beside the ' +
                 'addresses this service listens on, global.publicBaseUrl ' +
                 'and the embedded debugger. An origin here may read every ' +
                 'answer this service gives a browser, whichever client the ' +
                 'request names. EMPTY, the default, adds none: every other ' +
                 'origin is allowed only where an application lists it in ' +
                 'appCorsOrigin. A value that is not an origin is ignored ' +
                 'and logged, never widened.' },

  // -------------------------------------------------------------------------
  // THE MODE. What this service IS, rather than what any one surface requires.
  //
  // **IT IS ONE SETTING BECAUSE "IS AUTHENTICATION REQUIRED HERE" MUST HAVE
  // ONE ANSWER.** Until 2026-09-06 it had four — `admin.authRequired`,
  // `scim.authRequired`, `spiffe.authRequired` and, by omission, every other
  // surface that simply never checked anything. Those three rows are gone and
  // this replaces them, because a service that required a credential at SCIM
  // and not at the console was not "partly secured", it was unsecured with a
  // longer configuration file.
  //
  // `development` IS EVERYTHING THIS SERVICE HAS EVER DONE and is the default,
  // so an unedited process behaves exactly as it did: no password is checked
  // anywhere, an unknown user or application is created on first sight, a
  // public client needs no secret, and `/admin-api` is open. That is what makes
  // it a mock, and a mock is what exercises a client.
  //
  // `product` is the same protocol implementations with the permissiveness
  // taken out: a credential is verified against a stored `userPassword`, every
  // referenced object must already exist, an OAuth client must hold a secret,
  // and `/admin-api` is gated like every other door. **The protocol code is the
  // same code** — see common/mode.js, which is the one place either answer is
  // given.
  //
  // RUNTIME-SETTABLE AND PER REALM, following `oauth2.rfc9700` exactly and for
  // the same reason: a realm binds no socket, so one process can host a
  // development realm and a product realm at once and a client can be exercised
  // against both without a second service. That is also what lets a test flip
  // to `product`, assert what is now refused, and flip back.
  // -------------------------------------------------------------------------
  { key: 'admin.bootstrapUsername', group: 'Admin console',
    label: 'Bootstrap administrator account',
    path: 'admin.bootstrapUsername', env: 'STS_ADMIN_BOOTSTRAP_USERNAME',
    type: 'string', dflt: 'admin', runtime: false,
    // PROCESS-WIDE SINCE 2026-09-14 (#32): a realm may not carry it, because it
    // decides who administers the service — see admin-ui/admin_scope.js.
    perProcess: true,
    restartReason: 'the bootstrap runs once, between the persistence store ' +
                   'opening and the listener binding, so a change after that ' +
                   'has nothing left to name',
    description: 'The bootstrap administrator\'s username (2026-09-13), in ' +
                 'the DEFAULT realm and, since 2026-09-14, in every trust ' +
                 'realm, where it administers that realm only: ' +
                 'made at startup if absent, a member of both console roles, ' +
                 'forced to change its password at its first sign-in, and ' +
                 'impossible to delete or rename. Until it first signs in to ' +
                 '/admin, every signed-in person may use the console ' +
                 '(admin.openWhenEmpty). In development any password signs ' +
                 'it in, as for everybody. IN PRODUCT MODE it is also who ' +
                 'gets a generated password when this service starts and ' +
                 'NOBODY in the realm holds a credential; that password is ' +
                 'logged once and never again, and is the only way into a ' +
                 'fresh product deployment. The generated password is never ' +
                 'written where somebody already holds a credential, so it ' +
                 'cannot overwrite a password. The forced change applies ' +
                 'only to an account this step CREATED — an existing ' +
                 'account of this name keeps its password and is only ' +
                 'given the two roles.' },

  // -------------------------------------------------------------------------
  // KEY MATERIAL. Where this service's signing keys come from, and what
  // protects them when they are written down.
  //
  // **DEVELOPMENT GENERATES ON EVERY START AND THAT IS A FEATURE**, not an
  // omission: a mock is disposable, its tokens are meant to die with it, and a
  // key regenerated per start is what makes two instances impossible to confuse
  // (the `kid` is derived from the key material — see helpers.js).
  //
  // **PRODUCT GENERATES ONCE.** A token issued yesterday has to verify today,
  // so the keys are written to the persistence store — which is why product
  // mode REQUIRES a store — encrypted with AES-256-GCM under a key this service
  // never generates and never stores. See common/keystore.js and
  // common/secrets.js.
  // -------------------------------------------------------------------------
  // -------------------------------------------------------------------------
  // GNAP (RFC 9635 and RFC 9767), 2026-09-12. Every row is runtime and every
  // row may be set per trust realm, because each realm runs its own GNAP
  // authorization server. The list-valued rows are the DEFAULTS of section 9's
  // discovery document; a named authorization server's profile may override or
  // remove each one (/admin/authorization-servers), and what it then publishes
  // is what its grant endpoint enforces. See gnap/CLAUDE.md.
  // -------------------------------------------------------------------------
  { key: 'gnap.enabled', group: 'GNAP', label: 'Run the GNAP authorization ' +
                                               'server',
    path: 'gnap.enabled', env: 'STS_GNAP_ENABLED', type: 'bool', dflt: true,
    runtime: true,
    description: 'Off makes every /gnap endpoint, the RS-facing discovery ' +
                 'document and the resource-owner pages answer that GNAP is ' +
                 'turned off in this realm. Grants and tokens already issued ' +
                 'are kept, and are usable again when it is back on.' },
  { key: 'gnap.accessTokenFormat', group: 'GNAP', label: 'Default access ' +
      'token format',
    path: 'gnap.accessTokenFormat', env: 'STS_GNAP_ACCESS_TOKEN_FORMAT',
    type: 'enum',
    enumValues: ['jwt-signed', 'jwt-encrypted', 'macaroon', 'biscuit', 'zcap'],
    dflt: 'jwt-signed', runtime: true,
    description: 'The RFC 9767 token format issued when nothing more ' +
                 'specific decides. In order, what decides is: a registered ' +
                 'resource set that names the formats its resource server ' +
                 'accepts, the resource server\'s gnapAccessTokenFormat, the ' +
                 'client\'s gnapAccessTokenFormat, then this.' },
  { key: 'gnap.tokenFormats', group: 'GNAP', label: 'Token formats offered',
    path: 'gnap.tokenFormats', env: 'STS_GNAP_TOKEN_FORMATS', type: 'csv',
    dflt: 'jwt-signed,jwt-encrypted,macaroon,biscuit,zcap', runtime: true,
    description: 'RFC 9767 section 3.1\'s token_formats_supported. A format ' +
                 'not listed is never issued, and a resource set that ' +
                 'accepts only unlisted formats is refused at registration.' },
  { key: 'gnap.accessTokenLifetimeS', group: 'GNAP', label: 'Access token ' +
      'lifetime (seconds)',
    path: 'gnap.accessTokenLifetimeS', env: 'STS_GNAP_ACCESS_TOKEN_LIFETIME_S',
    type: 'int',
    dflt: 3600, min: 1, max: 31536000, runtime: true,
    description: 'The expires_in of every access token, and the exp of the ' +
                 'formats that carry one. A client application may override ' +
                 'it with its own gnapAccessTokenLifetimeS.' },
  { key: 'gnap.interactionLifetimeS', group: 'GNAP', label: 'Interaction ' +
      'lifetime (seconds)',
    path: 'gnap.interactionLifetimeS', env: 'STS_GNAP_INTERACTION_LIFETIME_S',
    type: 'int',
    dflt: 600, min: 30, max: 86400, runtime: true,
    description: 'How long the interaction start URIs and user codes of a ' +
                 'pending grant stay usable (RFC 9635 section 3.3\'s ' +
                 'expires_in). Section 3.3.3 says a user code SHOULD be ' +
                 'short-lived, "such as several minutes".' },
  { key: 'gnap.continueWaitS', group: 'GNAP', label: 'Continuation wait ' +
                                                     '(seconds)',
    path: 'gnap.continueWaitS', env: 'STS_GNAP_CONTINUE_WAIT_S', type: 'int',
    dflt: 5, min: 0, max: 3600, runtime: true,
    description: 'The wait of every continuation response. A client that ' +
                 'continues sooner is told too_fast (section 5). Section 3.1 ' +
                 'says it SHOULD NOT be less than five seconds; zero is ' +
                 'allowed so a test can run a grant without sleeping.' },
  { key: 'gnap.maxPolls', group: 'GNAP', label: 'Polls allowed before ' +
                                                'too_many_attempts',
    path: 'gnap.maxPolls', env: 'STS_GNAP_MAX_POLLS', type: 'int', dflt: 60,
    min: 1, max: 100000,
    runtime: true,
    description: 'How many continuation polls a pending grant accepts before ' +
                 'it is finalized with too_many_attempts (section 5.2).' },
  { key: 'gnap.signatureMaxAgeS', group: 'GNAP', label: 'Key proof freshness ' +
                                                        '(seconds)',
    path: 'gnap.signatureMaxAgeS', env: 'STS_GNAP_SIGNATURE_MAX_AGE_S',
    type: 'int',
    dflt: 300, min: 1, max: 86400, runtime: true,
    description: 'How far a key proof\'s created time may be from now, ' +
                 'either way (sections 7.3.1, 7.3.3 and 7.3.4). Nonces and ' +
                 'JWS proofs are remembered for twice this.' },
  { key: 'gnap.interactionStartModes', group: 'GNAP', label: 'Interaction ' +
      'start modes',
    path: 'gnap.interactionStartModes', env: 'STS_GNAP_INTERACTION_START_MODES',
    type: 'csv',
    dflt: 'redirect,app,user_code,user_code_uri', runtime: true,
    description: 'Section 9\'s interaction_start_modes_supported. A client ' +
                 'application may narrow it further with ' +
                 'gnapInteractionStartModes.' },
  { key: 'gnap.finishMethods', group: 'GNAP', label: 'Interaction finish ' +
                                                     'methods',
    path: 'gnap.finishMethods', env: 'STS_GNAP_FINISH_METHODS', type: 'csv',
    dflt: 'redirect,push', runtime: true,
    description: 'Section 9\'s interaction_finish_methods_supported. push is ' +
                 'also switched by gnap.pushFinish.' },
  { key: 'gnap.keyProofs', group: 'GNAP', label: 'Key proofing methods',
    path: 'gnap.keyProofs', env: 'STS_GNAP_KEY_PROOFS', type: 'csv',
    dflt: 'httpsig,mtls,jwsd,jws', runtime: true,
    description: 'Section 9\'s key_proofs_supported. mtls needs the main ' +
                 'port to be HTTPS (global.https) so that a client ' +
                 'certificate can arrive at all.' },
  { key: 'gnap.subIdFormats', group: 'GNAP',
    label: 'Subject identifier formats',
    path: 'gnap.subIdFormats', env: 'STS_GNAP_SUB_ID_FORMATS', type: 'csv',
    dflt: 'opaque,iss_sub,email,account,uri,phone_number,aliases', runtime:
                                                                     true,
    description: 'Section 9\'s sub_id_formats_supported, in RFC 9493\'s own ' +
                 'spellings. A format is released only when the person\'s ' +
                 'entry holds the fact it needs.' },
  { key: 'gnap.assertionFormats', group: 'GNAP', label: 'Subject assertion ' +
                                                        'formats',
    path: 'gnap.assertionFormats', env: 'STS_GNAP_ASSERTION_FORMATS',
    type: 'csv',
    dflt: 'id_token,saml2', runtime: true,
    description: 'Section 9\'s assertion_formats_supported: an OpenID ' +
                 'Connect ID Token and a SAML 2.0 assertion, built by the ' +
                 'same code the OIDC and SAML families use.' },
  { key: 'gnap.assertionMaxAgeS', group: 'GNAP', label: 'Grace for an ' +
                                                        'expired user ' +
                                                        'assertion (seconds)',
    path: 'gnap.assertionMaxAgeS', env: 'STS_GNAP_ASSERTION_MAX_AGE_S',
    type: 'int',
    dflt: 300, min: 0, max: 86400, runtime: true,
    description: 'Section 2.4 lets an AS "accept a recently expired ' +
                 'assertion in order to help bootstrap a new session". An ' +
                 'assertion this realm signed is accepted as a user hint for ' +
                 'this long past its exp.' },
  { key: 'gnap.keyRotation', group: 'GNAP', label: 'Allow access token key ' +
                                                   'rotation',
    path: 'gnap.keyRotation', env: 'STS_GNAP_KEY_ROTATION', type: 'bool',
    dflt: true, runtime: true,
    description: 'Section 9\'s key_rotation_supported, and section 6.1.1. ' +
                 'Off answers key_rotation_not_supported. MTLS keys never ' +
                 'rotate (section 7.3.2.1).' },
  { key: 'gnap.tokenManagement', group: 'GNAP', label: 'Offer token management',
    path: 'gnap.tokenManagement', env: 'STS_GNAP_TOKEN_MANAGEMENT',
    type: 'bool', dflt: true,
    runtime: true,
    description: 'Whether access tokens carry a manage URI and management ' +
                 'token (section 6).' },
  { key: 'gnap.bearerTokens', group: 'GNAP', label: 'Issue bearer tokens on ' +
                                                    'request',
    path: 'gnap.bearerTokens', env: 'STS_GNAP_BEARER_TOKENS', type: 'bool',
    dflt: true, runtime: true,
    description: 'Off refuses the bearer flag with invalid_flag for every ' +
                 'client (section 2.1.1). A client application can be ' +
                 'refused alone with gnapBearerTokens FALSE.' },
  { key: 'gnap.durableTokens', group: 'GNAP', label: 'Mark access tokens ' +
                                                     'durable',
    path: 'gnap.durableTokens', env: 'STS_GNAP_DURABLE_TOKENS', type: 'bool',
    dflt: false,
    runtime: true,
    description: 'Section 3.2.1\'s durable flag: a token survives the grant ' +
                 'being modified. Off means a modification revokes the ' +
                 'grant\'s earlier tokens (gnap.revokeOnModify).' },
  { key: 'gnap.revokeOnModify', group: 'GNAP', label: 'Revoke earlier tokens ' +
                                                      'on modification',
    path: 'gnap.revokeOnModify', env: 'STS_GNAP_REVOKE_ON_MODIFY', type: 'bool',
    dflt: true,
    runtime: true,
    description: 'Section 5.3: "The AS MAY revoke previously issued access ' +
                 'tokens after a modification has occurred" — unless they ' +
                 'were issued durable.' },
  { key: 'gnap.instanceIds', group: 'GNAP', label: 'Issue instance identifiers',
    path: 'gnap.instanceIds', env: 'STS_GNAP_INSTANCE_IDS', type: 'bool',
    dflt: true, runtime: true,
    description: 'Section 3.5: a client that sent its key by value is handed ' +
                 'an instance_id it can send by reference next time.' },
  { key: 'gnap.continueAfterApproval', group: 'GNAP', label: 'Keep approved ' +
      'grants continuable',
    path: 'gnap.continueAfterApproval', env: 'STS_GNAP_CONTINUE_AFTER_APPROVAL',
    type: 'bool',
    dflt: true, runtime: true,
    description: 'Whether an approved grant\'s response carries a continue ' +
                 'member, so the client can modify (section 5.3) or revoke ' +
                 '(section 5.4) it later.' },
  { key: 'gnap.consentRequired', group: 'GNAP', label: 'Ask the resource owner',
    path: 'gnap.consentRequired', env: 'STS_GNAP_CONSENT_REQUIRED',
    type: 'bool', dflt: true,
    runtime: true,
    description: 'Off approves every interactive grant as soon as the ' +
                 'resource owner has signed in, with no approval page. On is ' +
                 'the default, like oauth2.consentRequired.' },
  { key: 'gnap.rememberApprovals', group: 'GNAP', label: 'Remember approvals',
    path: 'gnap.rememberApprovals', env: 'STS_GNAP_REMEMBER_APPROVALS',
    type: 'bool', dflt: true,
    runtime: true,
    description: 'Write what a resource owner approved into the consent ' +
                 'register on their own entry (as gnap:<digest> values), so ' +
                 'the same rights are not asked for again.' },
  { key: 'gnap.allowCrossUser', group: 'GNAP', label: 'Allow a different ' +
                                                      'person to approve',
    path: 'gnap.allowCrossUser', env: 'STS_GNAP_ALLOW_CROSS_USER', type: 'bool',
    dflt: false,
    runtime: true,
    description: 'Section 2.4: when the request named a user and somebody ' +
                 'else signs in, the AS SHOULD answer unknown_user. On lets ' +
                 'whoever signs in approve.' },
  { key: 'gnap.userCodeLength', group: 'GNAP', label: 'User code length',
    path: 'gnap.userCodeLength', env: 'STS_GNAP_USER_CODE_LENGTH', type: 'int',
    dflt: 8, min: 6,
    max: 8, runtime: true,
    description:
      'Section 3.3.3: RECOMMENDED between six and eight characters.' },
  { key: 'gnap.unknownAccessReferences', group: 'GNAP', label: 'Unregistered ' +
      'access references',
    path: 'gnap.unknownAccessReferences',
    env: 'STS_GNAP_UNKNOWN_ACCESS_REFERENCES', type: 'enum',
    enumValues: ['accept', 'refuse'], dflt: 'accept', runtime: true,
    description: 'What an access reference string (section 8.1) that names ' +
                 'no registered resource set, and is not in the client\'s ' +
                 'gnapAllowedAccess, does: carried onto the token as it ' +
                 'stands, or refused with request_denied.' },
  { key: 'gnap.introspection', group: 'GNAP',
    label: 'Offer token introspection',
    path: 'gnap.introspection', env: 'STS_GNAP_INTROSPECTION', type: 'bool',
    dflt: true, runtime: true,
    description: 'RFC 9767 section 3.3.' },
  { key: 'gnap.resourceRegistration', group: 'GNAP', label: 'Offer resource ' +
      'set registration',
    path: 'gnap.resourceRegistration', env: 'STS_GNAP_RESOURCE_REGISTRATION',
    type: 'bool', dflt: true,
    runtime: true,
    description: 'RFC 9767 section 3.4.' },
  { key: 'gnap.tokenDerivation', group: 'GNAP', label: 'Allow downstream ' +
                                                       'token derivation',
    path: 'gnap.tokenDerivation', env: 'STS_GNAP_TOKEN_DERIVATION',
    type: 'bool', dflt: true,
    runtime: true,
    description: 'RFC 9767 section 4: a resource server presents a token it ' +
                 'was given as existing_access_token and receives a token ' +
                 'for a downstream resource server.' },
  { key: 'gnap.pushFinish', group: 'GNAP', label: 'Deliver push interaction ' +
                                                  'finishes',
    path: 'gnap.pushFinish', env: 'STS_GNAP_PUSH_FINISH', type: 'bool',
    dflt: true, runtime: true,
    description: 'Section 4.2.2: an HTTP POST to a URI the CLIENT supplied. ' +
                 'Off makes no outbound request at all and stops advertising ' +
                 'push.' },
  { key: 'gnap.pushAllowInsecure', group: 'GNAP', label: 'Allow http:// and ' +
      'untrusted TLS for push',
    path: 'gnap.pushAllowInsecure', env: 'STS_GNAP_PUSH_ALLOW_INSECURE',
    type: 'bool', dflt: false,
    runtime: true,
    description: 'Push to a plain http URI, or to an https one whose ' +
                 'certificate does not verify. Every such request is logged ' +
                 'as a warning.' },
  { key: 'gnap.pushAllowedHosts', group: 'GNAP', label: 'Push host allowlist',
    path: 'gnap.pushAllowedHosts', env: 'STS_GNAP_PUSH_ALLOWED_HOSTS',
    type: 'csv', dflt: '',
    runtime: true,
    description: 'Host names a push finish may go to. Empty means any host a ' +
                 'finish URI names (which product mode already restricts to ' +
                 'registered URIs).' },
  { key: 'gnap.pushTimeoutMs', group: 'GNAP', label: 'Push timeout (ms)',
    path: 'gnap.pushTimeoutMs', env: 'STS_GNAP_PUSH_TIMEOUT_MS', type: 'int',
    dflt: 5000, min: 100,
    max: 60000, runtime: true,
    description: 'How long a push interaction finish may take.' },
  { key: 'gnap.jweEnc', group: 'GNAP',
    label: 'jwt-encrypted content encryption',
    path: 'gnap.jweEnc', env: 'STS_GNAP_JWE_ENC', type: 'enum',
    enumValues: ['A128GCM', 'A192GCM', 'A256GCM', 'A128CBC-HS256',
                 'A192CBC-HS384', 'A256CBC-HS512'],
    dflt: 'A256GCM', runtime: true,
    description: 'The enc of a jwt-encrypted token encrypted to a resource ' +
                 'server\'s own key. A token encrypted to this authorization ' +
                 'server is always dir with A256GCM.' },
  certificateHeaderSetting('gnap.accessTokenCertificateHeader', 'GNAP',
    'STS_GNAP_ACCESS_TOKEN_CERTIFICATE_HEADER',
    'JWT access token certificate header',
    'Whether a GNAP access token in the jwt-signed or jwt-encrypted format ' +
    'names the certificate chain of the key that signed it — on the JWS in ' +
    'both, never on the JWE around jwt-encrypted, which is encrypted to a ' +
    'resource server\'s key or a secret. Macaroons, biscuits and ZCAP-LD ' +
    'capabilities are not JWSs and are not affected.'),
  { key: 'gnap.demoResourceServer', group: 'GNAP', label: 'Run the ' +
      'demonstration resource server',
    path: 'gnap.demoResourceServer', env: 'STS_GNAP_DEMO_RESOURCE_SERVER',
    type: 'bool', dflt: true,
    runtime: true,
    description: 'GET/POST /gnap/rs/resource: judges a presented token in ' +
                 'any of the five formats and answers the RS-first challenge ' +
                 'of section 9.1.' },
  { key: 'gnap.caepEvents', group: 'GNAP', label: 'Emit CAEP for grants and ' +
                                                  'tokens',
    path: 'gnap.caepEvents', env: 'STS_GNAP_CAEP_EVENTS', type: 'bool',
    dflt: true, runtime: true,
    description: 'A grant or token revoked sends session-revoked, and a ' +
                 'grant modified onto different access sends ' +
                 'token-claims-change, to every stream that takes them.' },
  { key: 'gnap.scopedSignals', group: 'GNAP', label: 'Scope a GNAP web ' +
                                                     'application\'s streams',
    path: 'gnap.scopedSignals', env: 'STS_GNAP_SCOPED_SIGNALS', type: 'bool',
    dflt: true,
    runtime: true,
    description: 'A Shared Signals stream owned by a GNAP client application ' +
                 'with a finish URI carries events only about people who ' +
                 'approved a grant to that application. gnapScopedSignals ' +
                 'FALSE on the entry opts one application out.' },
  // -------------------------------------------------------------------------
  // WEB SECURITY. The controls that protect the browser-facing surfaces — the
  // sign-in screen, the consent screen, the admin console and the User Portal
  // — against the OWASP Top Ten. See common/websecurity.js.
  // -------------------------------------------------------------------------
  { key: 'xacml.enforceAccess', group: 'XACML',
    label: 'Decide access with policy',
    path: 'xacml.enforceAccess', env: 'STS_XACML_ENFORCE_ACCESS',
    type: 'bool', dflt: true, runtime: true,
    description: 'Whether the admin console, the management API, the User ' +
                 'Portal, SCIM and the SPIRE Server API ask the embedded PDP ' +
                 'before letting a subject through. ON by default, and it ' +
                 'changes nothing on an unedited service: the built-in ' +
                 '`access-control` policy permits a subject that holds a ' +
                 'required role, permits when the resource requires none — ' +
                 'which is every surface nobody has narrowed — and permits ' +
                 'somebody acting on a resource they OWN, which is the User ' +
                 'Portal\'s rule.\n\nTurning it off does NOT open the doors: ' +
                 'the roles the console and SCIM already enforce are ' +
                 'unaffected, because this is the POLICY layer above them. ' +
                 'What it removes is the ability to write a rule — a ' +
                 'helpdesk role that may manage somebody else\'s account, ' +
                 'say — that no handler implements.' },

  { key: 'xacml.accessPolicy', group: 'XACML',
    label: 'Access policy name',
    path: 'xacml.accessPolicy', env: 'STS_XACML_ACCESS_POLICY',
    type: 'string', dflt: 'access-control', runtime: true,
    description: 'The policy the embedded access PEP evaluates. A repository ' +
                 'entry of this name in `ou=policies` OVERRIDES the built-in ' +
                 'one, which is how a deployment writes its own; deleting ' +
                 'that entry puts the built-in one back. The built-in policy ' +
                 'is CALLED rather than seeded, for the reason the issuance ' +
                 'policy is: `ou=policies` is per realm, and seeding once in ' +
                 'the default realm would leave every realm created later ' +
                 'unable to decide anything.' },

  { key: 'security.rateLimitWindowS', group: 'Web security',
    label: 'Rate-limit window (seconds)',
    path: 'security.rateLimitWindowS', env: 'STS_SECURITY_RATE_WINDOW_S',
    type: 'int', dflt: 60, runtime: true, min: 1, max: 3600,
    description: 'How long a rate-limit window lasts. A FIXED WINDOW rather ' +
                 'than a token bucket, deliberately: what it has to stop is ' +
                 'thousands of guesses a second, the refill semantics do not ' +
                 'matter for that, and "5 in 60 seconds" is something an ' +
                 'operator can reason about.' },

  { key: 'security.rateLimitPerIdentity', group: 'Web security',
    label: 'Attempts per identity per window',
    path: 'security.rateLimitPerIdentity',
    env: 'STS_SECURITY_RATE_PER_IDENTITY',
    type: 'int', dflt: 5, runtime: true, min: 1, max: 1000,
    description: 'How many credential attempts one IDENTITY may make in a ' +
                 'window, counted across every address — so an account ' +
                 'cannot be ground down from a botnet. Applies to the ' +
                 'sign-in screen, an activation URL and a password change.' },

  { key: 'security.rateLimitPerAddress', group: 'Web security',
    label: 'Attempts per address per window',
    path: 'security.rateLimitPerAddress',
    env: 'STS_SECURITY_RATE_PER_ADDRESS',
    type: 'int', dflt: 20, runtime: true, min: 1, max: 10000,
    description: 'How many credential attempts one ADDRESS may make in a ' +
                 'window, counted across every identity — so one address ' +
                 'cannot grind down many accounts. Both buckets are needed: ' +
                 'either alone is the half an attacker does not use. It is ' +
                 'higher than the per-identity limit because an address is ' +
                 'often a proxy carrying many legitimate people; ' +
                 'global.trustProxy decides whether X-Forwarded-For is read.' },

  { key: 'security.activationTtlMinutes', group: 'Web security',
    label: 'Activation link lifetime (minutes)',
    path: 'security.activationTtlMinutes',
    env: 'STS_SECURITY_ACTIVATION_TTL_MINUTES',
    type: 'int', dflt: 1440, runtime: true, min: 1, max: 43200,
    description: 'How long an activation URL stays valid. It is the one ' +
                 'credential in this service that can complete an account ' +
                 'setup on its own, so a leaked one is an account takeover — ' +
                 'which is why it is single-use, hashed at rest like a ' +
                 'password, and expires. A day is the default because the ' +
                 'link is delivered by hand here (there is no mail channel), ' +
                 'and an hour would strand most of them.' },

  // A PASSWORD RESET LINK (2026-09-13), the administrator's second way to
  // reset a password on a person's /admin/users page. It is its own setting
  // rather than the activation link's, because the two are different risks:
  // issuing a reset link REMOVES the password the person had, so until they
  // spend it they cannot sign in with a password at all, and a day of that is
  // a day locked out rather than a day to get round to setting up.
  { key: 'security.passwordResetTtlMinutes', group: 'Web security',
    label: 'Password reset link lifetime (minutes)',
    path: 'security.passwordResetTtlMinutes',
    env: 'STS_SECURITY_PASSWORD_RESET_TTL_MINUTES',
    type: 'int', dflt: 60, runtime: true, min: 1, max: 43200,
    description: 'How long a password reset link an administrator issued on ' +
                 'a person\'s /admin/users page (or through POST ' +
                 '/admin-api/users/issue-password-reset) stays valid. ' +
                 'Issuing one REMOVES the person\'s current password and ' +
                 'signs them out everywhere, so the link is the only way ' +
                 'back to a password until it is spent. It is single-use, ' +
                 'hashed at rest like a password, and delivered by hand ' +
                 '(there is no mail channel). A link that expires unused is ' +
                 'replaced by issuing another.' },

  // ---------------------------------------------------------------------
  // SESSIONS AND THE SIGN-IN CLOCKS (2026-09-12). Four literals in
  // `authn/authn.js` and three in `common/oidc_rp.js` that an audit for what
  // was hard-coded found: an absolute session lifetime of an hour with no
  // idle timeout at all, the ten minutes a sign-in waits at the screen, the
  // five minutes a second-factor step waits, and the bounds on this service's
  // own OpenID Connect client. Every default is the literal it replaces, so an
  // unedited service behaves exactly as it did.
  //
  // **THEY ARE IN `Web security` BECAUSE THAT IS THE GROUP ABOUT THE BROWSER-
  // FACING SURFACES**, and a session lifetime is the first thing a deployment's
  // security review asks for. The keys say which module reads them.
  // ---------------------------------------------------------------------
  { key: 'authn.sessionLifetimeS', group: 'Web security',
    label: 'Session lifetime (seconds)',
    env: 'STS_AUTHN_SESSION_LIFETIME_S',
    type: 'int', dflt: 3600, runtime: true, min: 60, max: 2592000,
    description: 'How long a sign-on session lasts from the moment it is ' +
                 'created — and with it the admin console\'s and the user ' +
                 'portal\'s own sessions, which expire when the sign-on ' +
                 'session they came from would. ABSOLUTE for a browser: ' +
                 'using the session does not extend it. The one exception is ' +
                 'a session a management API, SCIM or SPIRE Server API ' +
                 'client holds, which is extended by this much on every call ' +
                 'because it exists only while the client is calling. Read ' +
                 'when a session is created, so a change applies to the next ' +
                 'one and leaves a live one as it was.' },

  { key: 'authn.sessionIdleTimeoutS', group: 'Web security',
    label: 'Session idle timeout (seconds, 0 = none)',
    env: 'STS_AUTHN_SESSION_IDLE_TIMEOUT_S',
    type: 'int', dflt: 0, runtime: true, min: 0, max: 2592000,
    description: 'How long a session may go UNUSED before it ends, on top of ' +
                 'the absolute lifetime above. **Zero, the default, means no ' +
                 'idle timeout**, which is what this service has always ' +
                 'done. Set, a session somebody stops using ends that many ' +
                 'seconds after its last request, whichever of the two ' +
                 'limits comes first — and a request to the admin console or ' +
                 'the user portal counts as use of the sign-on session ' +
                 'behind it, so an operator working in the console is not ' +
                 'signed out of it by an idle clock on a session they are ' +
                 'not presenting. It is live: it applies to sessions that ' +
                 'already exist, because it is checked where a session is ' +
                 'read rather than stamped where one is made.' },

  { key: 'authn.pendingTtlS', group: 'Web security',
    label: 'How long a sign-in waits at the screen (seconds)',
    env: 'STS_AUTHN_PENDING_TTL_S',
    type: 'int', dflt: 600, runtime: true, min: 30, max: 86400,
    description: 'How long an interrupted request waits at the sign-in ' +
                 'screen before it has to be started again — and, ' +
                 'deliberately, the same clock for three other things that ' +
                 'wait on that screen: an arrival session a browser is given ' +
                 'at a protocol\'s front door (as an INACTIVITY window), and ' +
                 'a sign-in the admin console or the user portal started ' +
                 'through this service\'s own authorization server. They are ' +
                 'one setting because a flow that outlived the screen it is ' +
                 'waiting on would be a state this service accepts and an ' +
                 'authorization endpoint that has nothing left to answer ' +
                 'with.' },

  { key: 'authn.mfaStepTtlS', group: 'Web security',
    label: 'How long a second-factor step waits (seconds)',
    env: 'STS_AUTHN_MFA_STEP_TTL_S',
    type: 'int', dflt: 300, runtime: true, min: 30, max: 3600,
    description: 'How long somebody who has passed the password step has to ' +
                 'present their second factor — a security key, a code from ' +
                 'an authenticator app or a recovery code — before the step ' +
                 'expires and the sign-in has to be started again. It is the ' +
                 'window in which a guessed code can be tried at all, which ' +
                 'is why it is shorter than the screen\'s own clock; the ' +
                 'rate limiter bounds the attempts inside it.' },

  { key: 'oidcRp.maxFlows', group: 'Web security',
    label: 'Console and portal sign-ins in flight, per realm',
    env: 'STS_OIDC_RP_MAX_FLOWS',
    type: 'int', dflt: 200, runtime: true, min: 1, max: 100000,
    description: 'How many authorization code flows the admin console and ' +
                 'the user portal may have started and not yet finished, per ' +
                 'trust realm. Past it the OLDEST is dropped and somebody ' +
                 'part way through is sent round again — a bound on memory, ' +
                 'since every unauthenticated request to either surface ' +
                 'starts one.' },

  { key: 'oidcRp.backChannelTimeoutS', group: 'Web security',
    label: 'Console and portal back-channel timeout (seconds)',
    env: 'STS_OIDC_RP_BACK_CHANNEL_TIMEOUT_S',
    type: 'int', dflt: 10, runtime: true, min: 1, max: 120,
    description: 'How long the admin console and the user portal wait for ' +
                 'this service\'s own token endpoint and JWKS when they ' +
                 'redeem a sign-in over the loopback interface. A browser is ' +
                 'waiting on the far end of that request, which is why it is ' +
                 'bounded at all.' },

  { key: 'oidcRp.maxRedirectUris', group: 'Web security',
    label: 'Most redirect URIs the console and portal clients may learn',
    env: 'STS_OIDC_RP_MAX_REDIRECT_URIS',
    type: 'int', dflt: 20, runtime: true, min: 1, max: 1000,
    description: 'The most redirect URIs `sts-admin-console` and ' +
                 '`sts-user-portal` may carry before a sign-in at a new ' +
                 'address stops ADDING that address\'s callback to the ' +
                 'entry. Learning happens only where global.publicBaseUrl is ' +
                 'empty and only in development mode — see README.md — and ' +
                 'this is what keeps even that from growing an entry without ' +
                 'bound when the service is reached under many names. A ' +
                 'sign-in at an address past the cap still works unless ' +
                 'oauth2.rfc9700 is on, where redirect URIs are matched by ' +
                 'exact string.' },

  { key: 'oidcRp.renewBeforeExpiryS', group: 'Web security',
    label: 'Console and portal token renewal lead time (seconds)',
    env: 'STS_OIDC_RP_RENEW_BEFORE_EXPIRY_S',
    type: 'int', dflt: 60, runtime: true, min: 0, max: 86400,
    description: 'How long before its ID Token or access token runs out the ' +
                 'admin console or the user portal renews them with the ' +
                 'refresh token grant, on the next request that session ' +
                 'makes. The renewal happens inside the SAME session — the ' +
                 'same cookie, the same page, no sign-in — and the session ' +
                 'lasts at most as long as the refresh token it was issued ' +
                 'at sign-in (oauth2.refreshTokenTtlS, or the client\'s own ' +
                 'oauthRefreshTokenTtlS). 0 renews only once they have ' +
                 'expired; a value at or above the token lifetime renews on ' +
                 'every request, which is how a test watches it happen. Read ' +
                 'in the realm the sign-in ran in.' },

  // ---------------------------------------------------------------------
  // PASSWORDS (2026-09-12). The cost of the hash a new password is stored
  // under.
  //
  // **THE MINIMUM LENGTH IS NOT A SETTING ANY MORE.**
  // `security.passwordMinLength` was a row here for a few hours and was retired
  // the same day into the PASSWORD POLICY — `pwdMinLength` on
  // `cn=default,ou=passwordPolicies` in each realm's directory, beside the
  // history and composition rules, edited on /admin/policies.
  // `common/password_policy.js` argues why that is a directory entry rather
  // than a group of rows: one rule in two places would be two answers to what a
  // password must be.
  //
  // **THE HASH PARAMETERS APPLY TO NEW HASHES ONLY.** The stored form is
  // `$scrypt$N$r$p$salt$hash`, so a value written under yesterday's cost
  // verifies against the cost IT names and nothing already stored is touched.
  // N is set as its base-2 logarithm because scrypt requires a power of two,
  // and a setting that could be given 30000 would be a setting that fails at
  // the first sign-in.
  // ---------------------------------------------------------------------
  { key: 'security.passwordHashLogN', group: 'Web security',
    label: 'Password hash cost (log2 of scrypt N)',
    env: 'STS_SECURITY_PASSWORD_HASH_LOG_N',
    type: 'int', dflt: 15, runtime: true, min: 14, max: 20,
    description: 'scrypt\'s CPU and memory cost for a NEWLY stored password, ' +
                 'client secret, activation token or recovery code, as a ' +
                 'power of two: 15 is N=32768, about 70ms a hash on an ' +
                 'ordinary machine. The floor of 14 is the least this ' +
                 'service will write. Raising it makes a stolen store slower ' +
                 'to attack and every sign-in slower in proportion. Already ' +
                 'stored hashes carry their own parameters and are ' +
                 'unaffected.' },

  { key: 'security.passwordHashR', group: 'Web security',
    label: 'Password hash block size (scrypt r)',
    env: 'STS_SECURITY_PASSWORD_HASH_R',
    type: 'int', dflt: 8, runtime: true, min: 8, max: 16,
    description: 'scrypt\'s block size for a newly stored hash. Memory is ' +
                 'about 128 × N × r bytes, so doubling it doubles what each ' +
                 'hash needs. Eight is RFC 7914\'s recommendation.' },

  { key: 'security.passwordHashP', group: 'Web security',
    label: 'Password hash parallelism (scrypt p)',
    env: 'STS_SECURITY_PASSWORD_HASH_P',
    type: 'int', dflt: 1, runtime: true, min: 1, max: 8,
    description: 'scrypt\'s parallelism for a newly stored hash. Node ' +
                 'computes it on one thread, so a higher value costs time ' +
                 'rather than cores.' },

  { key: 'credentials.factorScanLimit', group: 'Web security',
    label: 'People read for the second-factor roster',
    env: 'STS_CREDENTIALS_FACTOR_SCAN_LIMIT',
    type: 'int', dflt: 5000, runtime: true, min: 1, max: 1000000,
    description: 'How many directory entries the second-factor columns on ' +
                 '/admin/users and GET /admin-api/mfa read before they stop. ' +
                 'Each person costs a read of several attributes on the one ' +
                 'thread that answers every socket this service holds, and a ' +
                 'directory of fifty thousand is a state the bulk-load jobs ' +
                 'create on purpose. The reply says when it stopped.' },

  // ---------------------------------------------------------------------
  // A SECOND FACTOR REQUIRED OF EVERYBODY IN THE REALM (2026-09-13).
  //
  // **A GROUP OF ITS OWN, DRAWN ON BOTH MECHANISM PAGES**, and the rename
  // below is why it is not called `Multi-factor authentication`: that group
  // named a category and mixed two mechanisms' settings on one screen. This is
  // one POLICY that either mechanism satisfies, so it is drawn on `/admin/totp`
  // AND `/admin/webauthn` — `saml.issuer`'s arrangement on the two SAML pages —
  // and a reader of either page sees that it is in force.
  //
  // It is `authn.` because what it changes is the SIGN-IN SCREEN, which asks
  // for enrolment when a person holds no second factor.
  // ---------------------------------------------------------------------
  { key: 'authn.mfaRequired', group: 'Second-factor requirement',
    label: 'Require a second factor of everybody',
    path: 'authn.mfaRequired', env: 'STS_AUTHN_MFA_REQUIRED',
    type: 'bool', dflt: false, runtime: true,
    description: 'When on, every person who signs in at this realm\'s ' +
                 'sign-in screen must use a second factor — an ' +
                 'authenticator app (TOTP) or a security key in the mfa ' +
                 'role. Somebody who holds neither is shown a set-up step ' +
                 'after their password is accepted, and no session is ' +
                 'started until one is enrolled. A passwordless security-key ' +
                 'sign-in is REFUSED while it is on, because a key on its ' +
                 'own is one factor (amr ["hwk"]). The same requirement ' +
                 'can be placed on one person from their /admin/users ' +
                 'page. **What ' +
                 'it does not reach**: a sign-in that never meets this ' +
                 'screen — a federated assertion, a SPNEGO ticket, a TLS ' +
                 'client certificate, the OAuth password grant, an LDAP ' +
                 'bind, WS-Trust and SCIM Basic — and a session that already ' +
                 'exists. Nothing is enrolled if both mechanisms are ' +
                 'switched off (totp.enabled, webauthn.enabled or ' +
                 'webauthn.mfaAllowed), and then the screen refuses the ' +
                 'sign-in and names those settings rather than letting a ' +
                 'required second factor quietly not be asked for.' },

  // ---------------------------------------------------------------------
  // TOTP MFA (2026-09-10). RFC 6238's eight parameters.
  //
  // The digest, the number of digits, the length of a step and how much clock
  // skew is forgiven are all parameters the specification leaves open, they
  // all have to be told to the authenticator app when it scans the QR code,
  // and a client author testing an integration will want to move every one of
  // them.
  //
  // They are `totp.` and not `authn.` because the group is what decides the
  // console page (`SETTING_HOMES` in `admin-ui/admin.js`), and what they
  // configure is a MECHANISM rather than the sign-in screen that offers it.
  // `authn.unauthenticatedSessions` is in the `Roles` group for the mirror
  // image of the same reason.
  //
  // **THE GROUP WAS CALLED `Multi-factor authentication` UNTIL 2026-09-10 AND
  // THE RENAME IS THE WHOLE OF WHAT CHANGED HERE.** It named a CATEGORY where
  // every other group in this table names a mechanism or a family, and the
  // page it sent a reader to was filed under Identities and mixed these eight
  // rows in with a roster of people. There are two mechanisms and each has its
  // own group and its own page now — this one and `WebAuthn` below — so a
  // reader looking for the skew window and a reader looking for the resident
  // key policy no longer land on the same screen and read past each other.
  // ---------------------------------------------------------------------

  { key: 'totp.enabled', group: 'TOTP MFA',
    label: 'Offer authenticator apps (TOTP)',
    path: 'totp.enabled', env: 'STS_TOTP_ENABLED',
    type: 'bool', dflt: true, runtime: true,
    description: 'Whether a person may enrol an RFC 6238 authenticator app ' +
                 'as a second factor, on `/portal/mfa` or while spending an ' +
                 'activation link. **Turning it off does NOT disable a ' +
                 'secret somebody already enrolled** — that account is still ' +
                 'configured for two factors and the sign-in screen still ' +
                 'asks for the code. A setting that silently downgraded ' +
                 'every enrolled account to a password alone would be a ' +
                 'security control whose off switch does something other ' +
                 'than what it says. What it stops is new enrolments; an ' +
                 'existing one is removed on that person\'s own row under ' +
                 '`/admin/users`.' },

  { key: 'totp.issuer', group: 'TOTP MFA',
    label: 'Authenticator app label',
    path: 'totp.issuer', env: 'STS_TOTP_ISSUER',
    type: 'string', dflt: '', runtime: true,
    description: 'The name an authenticator app shows beside the account — ' +
                 'the `issuer` of the otpauth Key Uri Format, written both ' +
                 'as a prefix on the label and as a parameter because older ' +
                 'apps read one and newer ones the other. **Empty means this ' +
                 'realm\'s own host**, with the realm id after it where ' +
                 'there is one, which is deliberate: two realms of one ' +
                 'process are two identity providers, and a phone showing ' +
                 'two accounts with the same name beside them is a list ' +
                 'nobody can use.' },

  { key: 'totp.algorithm', group: 'TOTP MFA',
    label: 'HMAC digest', path: 'totp.algorithm',
    env: 'STS_TOTP_ALGORITHM', type: 'enum',
    enumValues: ['SHA1', 'SHA256', 'SHA512'],
    dflt: 'SHA1', runtime: true,
    description: 'RFC 6238 section 1.2 defines all three and names ' +
                 'HMAC-SHA-1 as the default. **LEAVE IT AT SHA1 UNLESS YOU ' +
                 'ARE TESTING EXACTLY THIS.** Several widely used ' +
                 'authenticator apps — Google Authenticator among them — ' +
                 'IGNORE the `algorithm` parameter in the QR code and always ' +
                 'compute SHA-1, so any other value produces a code that ' +
                 'scans perfectly and then generates codes this service ' +
                 'refuses, with nothing anywhere saying why. SHA-1 is not a ' +
                 'weakness here: this is a keyed MAC over a counter, not a ' +
                 'collision-resistant digest. Changing it affects NEW ' +
                 'enrolments only — an existing secret is verified with the ' +
                 'algorithm it was enrolled under, which is the one the app ' +
                 'was told.' },

  { key: 'totp.digits', group: 'TOTP MFA',
    label: 'Digits in a code', path: 'totp.digits',
    env: 'STS_TOTP_DIGITS', type: 'int', dflt: 6, runtime: true,
    min: 6, max: 8,
    description: 'Six is what every authenticator app shows and what RFC ' +
                 '4226 section 5.3 recommends; eight is defined and is worth ' +
                 'setting only to find out what a client does with it. NEW ' +
                 'enrolments only, for the reason the digest gives.' },

  { key: 'totp.period', group: 'TOTP MFA',
    label: 'Seconds in a step', path: 'totp.period',
    env: 'STS_TOTP_PERIOD', type: 'int', dflt: 30, runtime: true,
    min: 15, max: 300,
    description: 'RFC 6238 section 4.1\'s time step X. Thirty seconds is the ' +
                 'default and what every app assumes. NEW enrolments only.' },

  { key: 'totp.window', group: 'TOTP MFA',
    label: 'Steps of clock skew forgiven', path: 'totp.window',
    env: 'STS_TOTP_WINDOW', type: 'int', dflt: 1, runtime: true,
    min: 0, max: 10,
    description: 'How many steps either side of now are accepted. RFC 6238 ' +
                 'section 5.2 recommends at most one, which is the default ' +
                 'and makes a code good for about ninety seconds. **This one ' +
                 'IS live** and applies to every existing enrolment — how ' +
                 'much a deployment forgives a phone with a drifting clock ' +
                 'is a policy rather than something the QR code told the ' +
                 'app. Zero demands a perfectly synchronised clock and is ' +
                 'the setting to reach for when demonstrating what happens ' +
                 'without one.' },

  { key: 'totp.secretBytes', group: 'TOTP MFA',
    label: 'Shared secret length (bytes)', path: 'totp.secretBytes',
    env: 'STS_TOTP_SECRET_BYTES', type: 'int', dflt: 20, runtime: true,
    min: 16, max: 64,
    description: 'RFC 4226 section 4 requirement R6 says at least 128 bits ' +
                 'and recommends 160, which is the 20 bytes here and the ' +
                 'length of an HMAC-SHA-1 key. Longer is allowed and is ' +
                 'transcribed by hand by anybody who cannot scan the QR ' +
                 'code — 20 bytes is already 32 base32 characters.' },

  { key: 'totp.enrolmentTtlMinutes', group: 'TOTP MFA',
    label: 'Unconfirmed enrolment lifetime (minutes)',
    path: 'totp.enrolmentTtlMinutes', env: 'STS_TOTP_ENROLMENT_TTL_MINUTES',
    type: 'int', dflt: 10, runtime: true, min: 1, max: 1440,
    description: 'How long a secret that has been SHOWN but not yet ' +
                 'confirmed with a code stays available. It is held in ' +
                 'memory and never written to the directory until a code ' +
                 'proves the app really has it — an unconfirmed secret on ' +
                 'somebody\'s entry would be a second factor they cannot ' +
                 'produce, which is a lockout rather than a control. Ten ' +
                 'minutes is long enough to find a phone and short enough ' +
                 'that an abandoned enrolment does not sit in memory.' },

  // ---------------------------------------------------------------------
  // RECOVERY CODES (2026-09-10). THE THIRD SECOND FACTOR, AND THE ONLY
  // MECHANISM IN THIS SERVICE THAT NO SPECIFICATION DEFINES.
  //
  // A short list of single-use strings that stands in for whichever second
  // factor a person is configured for when they cannot produce it — the phone
  // is lost or flat, the security key is in a drawer at home. There is no RFC
  // for it; `common/backup_codes.js` makes every decision that is left and
  // argues each one.
  //
  // **THERE ARE ONLY FOUR ROWS AND THREE OF THEM ARE THE SHAPE OF A CODE**,
  // which is the whole difference from the eight `totp.*` rows above. A TOTP
  // parameter has to be TOLD TO AN APP this service cannot reach, so every one
  // of those rows carries a paragraph about affecting NEW enrolments only.
  // Nothing here is told to anybody: a recovery code is a string compared
  // against a stored string, so shortening `backupCodes.length` changes what
  // the next set looks like and leaves an existing set matching exactly as it
  // did.
  //
  // **THERE IS DELIBERATELY NO "ISSUE THEM AUTOMATICALLY" SETTING.** Issuing
  // is not a policy an operator chooses: a second factor with no way back is
  // an account that a lost phone ends, so the set is created by the act of
  // enrolling a second factor and by nothing else. `backupCodes.enabled` off
  // is the one way to have none, and it is the whole switch.
  // ---------------------------------------------------------------------
  { key: 'backupCodes.enabled', group: 'Backup codes',
    label: 'Issue recovery codes with a second factor',
    path: 'backupCodes.enabled', env: 'STS_BACKUP_CODES_ENABLED',
    type: 'bool', dflt: true, runtime: true,
    description: 'Whether a person may generate a set of single-use recovery ' +
                 'codes on /portal/mfa — shown once, and stored as scrypt ' +
                 'hashes only when they confirm they have kept it. (Until ' +
                 '2026-09-11 a set was issued automatically the first time a ' +
                 'second factor was enrolled; that was reversed with the ' +
                 'hashing, and this sentence was updated on 2026-09-12.) ' +
                 '**Turning it off does NOT invalidate a set somebody ' +
                 'already holds**, and that is the contract `totp.enabled` ' +
                 'and `webauthn.enabled` both keep: a person issued ten ' +
                 'codes still holds ten and the sign-in door still accepts ' +
                 'one. A setting that silently took away the only way back ' +
                 'into an account whose phone is lost would be the worst ' +
                 'knob in this service. What it stops is a new set being ' +
                 'issued.' },

  { key: 'backupCodes.count', group: 'Backup codes',
    label: 'Codes in a set', path: 'backupCodes.count',
    env: 'STS_BACKUP_CODES_COUNT', type: 'int', dflt: 10, runtime: true,
    min: 1, max: 50,
    description: 'How many codes are issued. Ten is what almost every ' +
                 'identity provider settles on and is enough that losing a ' +
                 'printed copy of one does not end the account, while being ' +
                 'few enough to fit on a card in a wallet. **A set is never ' +
                 'topped up**: when it runs low the person generates a new ' +
                 'one, which REPLACES the old set whole.' },

  { key: 'backupCodes.length', group: 'Backup codes',
    label: 'Characters in a code', path: 'backupCodes.length',
    env: 'STS_BACKUP_CODES_LENGTH', type: 'int', dflt: 10, runtime: true,
    min: 8, max: 32,
    description: 'Out of an alphabet of thirty-two, so ten characters is ' +
                 'fifty bits — which is the number that matters rather than ' +
                 'the length. The alphabet is the thirty-two characters RFC ' +
                 '4648 base32 uses and it is NOT shared with `totp.*`: this ' +
                 'one is chosen because it contains no confusable pair (no ' +
                 '`0` beside `O`, no `1` beside `I`), because a recovery ' +
                 'code is the one credential here that somebody writes on ' +
                 'paper and types back months later.' },

  // ---------------------------------------------------------------------
  // HOW LONG A GENERATED-BUT-UNCONFIRMED SET WAITS (2026-09-11).
  //
  // A set is shown, and stored only when the person says they have kept it.
  // Between those two presses it lives in this process's memory and nowhere
  // else — a live credential that is not yet a credential — so it expires,
  // for an authorization code's reason: the window in which it can be
  // confirmed should be the window in which somebody is actually looking at
  // the page.
  //
  // **EXPIRING ONE CHANGES NOTHING ABOUT A SET ALREADY CONFIRMED.** Somebody
  // who walked away mid-flow comes back to whatever they had, which is the
  // property that makes a short default safe.
  // ---------------------------------------------------------------------
  { key: 'backupCodes.pendingTtlS', group: 'Backup codes',
    label: 'How long an unconfirmed set of recovery codes waits (seconds)',
    env: 'STS_BACKUP_CODES_PENDING_TTL_S', type: 'int',
    dflt: 900, min: 60, max: 3600, runtime: true,
    description: 'A set of recovery codes is generated when somebody asks to ' +
                 'see one and is stored only when they confirm they have ' +
                 'kept it. This is how long the generated set waits in ' +
                 'memory for that confirmation. It is never written down, so ' +
                 'an expired one leaves no trace and leaves any set the ' +
                 'person already had exactly as it was — they simply have to ' +
                 'ask again.' },
  { key: 'backupCodes.groupSize', group: 'Backup codes',
    label: 'Characters between the dashes', path: 'backupCodes.groupSize',
    env: 'STS_BACKUP_CODES_GROUP_SIZE', type: 'int', dflt: 5, runtime: true,
    min: 0, max: 16,
    description: 'Purely presentational: `A2CDE-FGH3J` rather than ' +
                 '`A2CDEFGH3J`, so that a person transcribing one does not ' +
                 'lose their place. Every door strips the dashes and the ' +
                 'spaces back out before comparing, so a code typed either ' +
                 'way is the same code. Zero prints it unbroken.' },

  // ---------------------------------------------------------------------
  // WEBAUTHN AND CTAP (2026-09-10). THE OTHER MECHANISM, WHICH HAD NO
  // SETTINGS AT ALL UNTIL THIS DAY.
  //
  // **THE SENTENCE THIS BLOCK REPLACES WAS "WHAT IT DOES IS DECIDED BY THE
  // SPECIFICATION AND BY THE BROWSER, AND THERE IS NOTHING AN OPERATOR COULD
  // USEFULLY TURN."** It was written above the TOTP rows to explain why
  // WebAuthn had no group beside them, and it was wrong in the way that is
  // hardest to notice: it is true of the CRYPTOGRAPHY and false of the
  // CEREMONY. What a browser does with `navigator.credentials.create()` is
  // decided almost entirely by the `PublicKeyCredentialCreationOptions` the
  // relying party hands it, and every one of those was a literal in a string
  // in `authn/authn.js` — the RP name, the algorithms offered, the user
  // verification requirement, the attestation conveyance, the timeout. An
  // operator could not move any of them, and a client author trying to find
  // out what their client does with `attestation: "none"` or with a resident
  // key had no way to ask this service for one.
  //
  // ---------------------------------------------------------------------
  // THREE KINDS OF ROW, AND KNOWING WHICH IS WHICH IS HOW TO READ THE PAGE.
  //
  //   * **THE CEREMONY** — `rpName`, `rpId`, `algorithms`, `timeoutMs`,
  //     `attestation`, `userVerification`. These go to the BROWSER, in the
  //     options this service hands it, and what happens to them after that is
  //     the browser's and the authenticator's business.
  //   * **CTAP2** — `authenticatorAttachment`, `residentKey`, `credProps`.
  //     These are the ones a browser translates into what it asks the
  //     AUTHENTICATOR for: which kind of authenticator may answer, whether the
  //     credential is discoverable (a CTAP2 resident key, which is what makes
  //     usernameless sign-in possible), and whether the browser is asked to
  //     report back which it made.
  //   * **POLICY** — `enabled`, `primaryAllowed`, `mfaAllowed`,
  //     `maxKeysPerPerson`. These are not WebAuthn at all: they are what THIS
  //     service will do with a key once the ceremony is over, and they are
  //     decided here rather than by any specification.
  //
  // **TWO OF THEM ARE ENFORCED IN THIS SERVICE AND NOT ONLY REQUESTED**, and
  // that distinction is the one to keep: `userVerification` is sent to the
  // browser AND checked in `authn/webauthn.js` when the ceremony comes back,
  // so `required` really does refuse an authenticator that did not verify the
  // person. `attestation`, `residentKey` and `authenticatorAttachment` are
  // REQUESTS — this service records what came back and refuses nothing on
  // them, which is the position the row below states rather than implying a
  // check that is not there.
  // ---------------------------------------------------------------------
  { key: 'webauthn.enabled', group: 'WebAuthn',
    label: 'Offer security keys (WebAuthn)',
    path: 'webauthn.enabled', env: 'STS_WEBAUTHN_ENABLED',
    type: 'bool', dflt: true, runtime: true,
    description: 'Whether this service offers a WebAuthn ceremony at all — ' +
                 'the two boxes on the sign-in screen, the enrolment on ' +
                 '`/portal/keys`, and the `/authn/webauthn` screen itself. ' +
                 '**Turning it off does NOT remove a key somebody already ' +
                 'enrolled**, exactly as `totp.enabled` does not remove a ' +
                 'shared secret: an account configured for two factors is ' +
                 'still configured for two, and a setting that silently ' +
                 'downgraded it would be a security control whose off switch ' +
                 'does something other than what it says. What it stops is ' +
                 'new ceremonies. An enrolled key is removed on that ' +
                 'person\'s row under Users, or by them on `/portal/keys`.' },

  { key: 'webauthn.rpName', group: 'WebAuthn',
    label: 'Relying party name', path: 'webauthn.rpName',
    env: 'STS_WEBAUTHN_RP_NAME', type: 'string',
    dflt: 'Mock authorization server', runtime: true,
    description: 'The `rp.name` handed to `navigator.credentials.create()`. ' +
                 'It is what a browser and a password manager show the ' +
                 'person while they decide whether to create a credential, ' +
                 'and it is stored with the credential on a platform ' +
                 'authenticator — so this is the string somebody sees in ' +
                 'their key list a month later. It has NO security meaning: ' +
                 'WebAuthn binds a credential to the RP ID below and to ' +
                 'nothing else, and two services sharing an RP ID share ' +
                 'credentials however differently they name themselves.' },

  { key: 'webauthn.rpId', group: 'WebAuthn',
    label: 'RP ID override', path: 'webauthn.rpId',
    env: 'STS_WEBAUTHN_RP_ID', type: 'string', dflt: '', runtime: true,
    description: '**EMPTY MEANS THE HOST THIS SERVICE WAS REACHED ON**, ' +
                 'which is almost always the right answer and is what it did ' +
                 'before this setting existed. A value here overrides it, ' +
                 'and WebAuthn allows exactly one useful kind of override: a ' +
                 'REGISTRABLE DOMAIN SUFFIX of the origin — `example.com` ' +
                 'when reached at `sts.example.com`, so one credential works ' +
                 'across the sibling hosts of a deployment. **Anything else ' +
                 'is refused by the browser, not by this service**, with a ' +
                 '`SecurityError` the ceremony reports as one of its several ' +
                 'indistinguishable failures — so a wrong value here looks ' +
                 'like a broken authenticator. Set it only to widen the ' +
                 'scope deliberately, and note that widening it means every ' +
                 'host under that suffix can assert these credentials. **In ' +
                 'product mode a value that is not the host or a suffix of ' +
                 'it REFUSES the ceremony**, by name; development falls back ' +
                 'to the host and logs why, as it always did.' },

  // Added 2026-09-12. The origin a ceremony's clientDataJSON must carry was
  // derived from the request's Host header and nothing else could say it.
  { key: 'webauthn.allowedOrigins', group: 'WebAuthn',
    label: 'Allowed origins', path: 'webauthn.allowedOrigins',
    env: 'STS_WEBAUTHN_ALLOWED_ORIGINS', type: 'csv', dflt: '',
    runtime: true,
    description: 'The origins — scheme, host and port, no path — a WebAuthn ' +
                 'ceremony is accepted from, comma-separated. **EMPTY, the ' +
                 'default, derives the one origin from the address this ' +
                 'service was reached at**, which is what it has always done ' +
                 'and which global.publicBaseUrl already pins when it is ' +
                 'set. Set, it is the whole list: a clientDataJSON whose ' +
                 'origin is not on it is refused whatever Host the request ' +
                 'carried. Name several where one credential is used from ' +
                 'sibling hosts under a shared webauthn.rpId.' },

  { key: 'webauthn.algorithms', group: 'WebAuthn',
    label: 'Algorithms offered', path: 'webauthn.algorithms',
    env: 'STS_WEBAUTHN_ALGORITHMS', type: 'csv', dflt: 'ES256,RS256',
    runtime: true,
    description: '`pubKeyCredParams`, in preference order — the COSE ' +
                 'algorithms this service will accept a credential in. The ' +
                 'names are JOSE spellings and are mapped to COSE ' +
                 'identifiers by `authn/webauthn.js`\'s own table, which is ' +
                 'the module that verifies the signature: `ES256` (-7), ' +
                 '`ES384` (-35), `ES512` (-36), `EdDSA` (-8), `RS256` ' +
                 '(-257), `RS384` (-258), `RS512` (-259). A name outside ' +
                 'that table is dropped with a warning rather than sent, ' +
                 'because offering an algorithm this service cannot verify ' +
                 'produces a credential that enrols and then never works. ' +
                 '**ES256 and RS256 are the two every authenticator ' +
                 'implements** and are the default; the rest are here to ' +
                 'find out what a client does when the list is unusual.' },

  { key: 'webauthn.userVerification', group: 'WebAuthn',
    label: 'User verification', path: 'webauthn.userVerification',
    env: 'STS_WEBAUTHN_USER_VERIFICATION', type: 'enum',
    enumValues: ['discouraged', 'preferred', 'required'],
    dflt: 'preferred', runtime: true,
    description: 'Whether the authenticator must verify the PERSON — a PIN, ' +
                 'a fingerprint, a face — as well as prove possession of the ' +
                 'key. **THIS IS THE ONE CEREMONY SETTING THIS SERVICE ALSO ' +
                 'ENFORCES**: `required` is sent to the browser and the UV ' +
                 'flag in the authenticator data is then CHECKED when the ' +
                 'ceremony comes back, so an authenticator that did not ' +
                 'verify is refused rather than quietly accepted. **Raising ' +
                 'it does not change what a session CLAIMS.** A passwordless ' +
                 'sign-in still records `amr ["hwk"]` and `acr "1"` — one ' +
                 'factor — even with `required`, because RFC 8176 has no ' +
                 'value for *the authenticator verified the user* that this ' +
                 'service could honestly assert, and inventing the stronger ' +
                 'claim is the exact fake this profile refuses everywhere ' +
                 'else. `/admin/webauthn` says so on the page.' },

  { key: 'webauthn.attestation', group: 'WebAuthn',
    label: 'Attestation conveyance', path: 'webauthn.attestation',
    env: 'STS_WEBAUTHN_ATTESTATION', type: 'enum',
    enumValues: ['none', 'indirect', 'direct', 'enterprise'],
    dflt: 'direct', runtime: true,
    description: 'How much the browser is asked to tell this service about ' +
                 'the authenticator that made the credential. `direct` is ' +
                 'the default here because this is a DEBUGGING service and ' +
                 'the attestation object is one of the things worth looking ' +
                 'at; a real deployment with no attestation policy should ' +
                 'send `none`, which is what the specification recommends ' +
                 'and what avoids a browser consent prompt about the ' +
                 'authenticator model. **THIS SERVICE VERIFIES NO ' +
                 'ATTESTATION STATEMENT WHATEVER IT ASKS FOR** — there is no ' +
                 'metadata service here, no trust anchor for an ' +
                 'authenticator vendor, and no model allow-list — so the ' +
                 'statement is parsed, reported and believed. Asking for ' +
                 '`enterprise` and getting nothing back is the browser ' +
                 'refusing, not this service.' },

  { key: 'webauthn.timeoutMs', group: 'WebAuthn',
    label: 'Ceremony timeout (ms)', path: 'webauthn.timeoutMs',
    env: 'STS_WEBAUTHN_TIMEOUT_MS', type: 'int', dflt: 60000, runtime: true,
    min: 10000, max: 600000,
    description: 'The `timeout` in the options handed to the browser. It is ' +
                 'a HINT — the specification says a client MAY clamp it, and ' +
                 'browsers do — so a value here is what this service asks ' +
                 'for rather than what will happen. Note that the pending ' +
                 'step this service holds expires on its own five-minute ' +
                 'clock, so a timeout longer than that buys a ceremony that ' +
                 'succeeds in the browser and is then refused here.' },

  { key: 'webauthn.authenticatorAttachment', group: 'WebAuthn',
    label: 'Authenticator attachment (CTAP)',
    path: 'webauthn.authenticatorAttachment',
    env: 'STS_WEBAUTHN_ATTACHMENT', type: 'enum',
    enumValues: ['any', 'platform', 'cross-platform'],
    dflt: 'any', runtime: true,
    description: 'Which kind of authenticator may answer. `platform` is the ' +
                 'one built into the machine — Touch ID, Windows Hello, an ' +
                 'Android screen lock; `cross-platform` is a roaming CTAP2 ' +
                 'authenticator reached over USB, NFC or BLE. `any` sends no ' +
                 'preference at all, which is the default and is what leaves ' +
                 'the choice to the person. **It is a FILTER IN THE BROWSER ' +
                 'AND NOT A CHECK HERE**: the browser offers only what ' +
                 'matches, and this service does not refuse a credential ' +
                 'whose attachment turned out to be the other one. What it ' +
                 'does do is RECORD what came back, where the browser said.' },

  { key: 'webauthn.residentKey', group: 'WebAuthn',
    label: 'Discoverable credential (CTAP resident key)',
    path: 'webauthn.residentKey', env: 'STS_WEBAUTHN_RESIDENT_KEY',
    type: 'enum', enumValues: ['discouraged', 'preferred', 'required'],
    dflt: 'discouraged', runtime: true,
    description: 'Whether the credential is stored ON the authenticator — a ' +
                 'CTAP2 *resident key* — so that it can be found without ' +
                 'this service naming it first. That is what makes a ' +
                 'usernameless sign-in possible, and it is what a passkey ' +
                 'is. `discouraged` is the default because a resident key ' +
                 'consumes one of the small number of slots a roaming ' +
                 'authenticator has and CANNOT ALWAYS BE DELETED FROM IT — a ' +
                 'debugging service should not fill somebody\'s security key ' +
                 'without being asked. **This service does not offer a ' +
                 'usernameless flow**, so `required` buys a slot on the key ' +
                 'and nothing else here; it is worth setting to find out ' +
                 'what a client does when the browser prompts differently.' },

  { key: 'webauthn.credProps', group: 'WebAuthn',
    label: 'Ask for the credProps extension',
    path: 'webauthn.credProps', env: 'STS_WEBAUTHN_CRED_PROPS',
    type: 'bool', dflt: true, runtime: true,
    description: 'Sends `extensions: { credProps: true }` on registration, ' +
                 'which asks the browser to report whether the credential it ' +
                 'made is actually discoverable. It is the only way to find ' +
                 'out: `residentKey: "preferred"` may or may not produce one ' +
                 'and nothing in the attestation says which. This service ' +
                 'RECORDS the answer beside the key and decides nothing on ' +
                 'it. Off is the way to see what a client does with no ' +
                 'extension results at all.' },

  // -------------------------------------------------------------------
  // THE POLICY ROWS. Not WebAuthn — what THIS service does with a key.
  // -------------------------------------------------------------------
  { key: 'webauthn.primaryAllowed', group: 'WebAuthn',
    label: 'Allow a key as a PRIMARY credential',
    path: 'webauthn.primaryAllowed', env: 'STS_WEBAUTHN_PRIMARY_ALLOWED',
    type: 'bool', dflt: true, runtime: true,
    description: 'Whether a security key may be the ONLY credential on an ' +
                 'account — a passwordless sign-in, `amr ["hwk"]`. Turning ' +
                 'it off leaves keys working as a SECOND factor and refuses ' +
                 'the passwordless path at the sign-in screen and the ' +
                 '`primary` choice in the portal. **It does not disable a ' +
                 'primary key somebody already holds**, for ' +
                 '`webauthn.enabled` ’s reason — and there is a sharper edge ' +
                 'here: somebody whose only credential is a primary key ' +
                 'would be locked out of their own account by an operator ' +
                 'flipping a switch, which is not a thing a setting should ' +
                 'be able to do.' },

  { key: 'webauthn.mfaAllowed', group: 'WebAuthn',
    label: 'Allow a key as a SECOND factor',
    path: 'webauthn.mfaAllowed', env: 'STS_WEBAUTHN_MFA_ALLOWED',
    type: 'bool', dflt: true, runtime: true,
    description: 'Whether a security key may be enrolled as a second factor ' +
                 'beside a password. Off, the remaining second factor is the ' +
                 'authenticator app (`totp.enabled`), and a deployment with ' +
                 'both off offers no second factor at all — which is a ' +
                 'supported configuration and is what this service did ' +
                 'before either existed. **An enrolled `mfa` key goes on ' +
                 'being demanded at the sign-in screen**, because that ' +
                 'account is still configured for two factors; see ' +
                 '`webauthn.enabled`.' },

  { key: 'webauthn.maxKeysPerPerson', group: 'WebAuthn',
    label: 'Keys per person', path: 'webauthn.maxKeysPerPerson',
    env: 'STS_WEBAUTHN_MAX_KEYS', type: 'int', dflt: 10, runtime: true,
    min: 1, max: 50,
    description: 'How many security keys one person may hold. Several is the ' +
                 'ordinary case and the specification expects it — a key at ' +
                 'the desk and one on the keyring — and unlike a shared ' +
                 'secret there is no ambiguity in having more than one, ' +
                 'because an assertion NAMES the credential that produced ' +
                 'it. The limit is here so that an enrolment loop cannot ' +
                 'grow an unbounded attribute on a directory entry; it ' +
                 'refuses the ENROLMENT and never an authentication.' },

  { key: 'keys.source', group: 'Key material', label: 'Where signing keys ' +
                                                      'come from',
    path: 'keys.source', env: 'STS_KEYS_SOURCE', type: 'enum',
    enumValues: ['auto', 'generated', 'persisted'],
    dflt: 'auto', runtime: false,
    restartReason: 'the signing keys are loaded once, before the listener ' +
                   'binds; changing where they come from after that would ' +
                   'mean a running service holding keys from one source and ' +
                   'reporting another',
    description: '`auto` follows the MODE — generated in development, ' +
                 'persisted in product — and is what almost every deployment ' +
                 'wants. The other two override it: `generated` makes a new ' +
                 'key on every start (a product-mode service that does this ' +
                 'invalidates every token it issued the moment it restarts), ' +
                 'and `persisted` reads and writes the store in development ' +
                 'too, which is the setting to use when TESTING the key ' +
                 'store without turning on everything else product mode ' +
                 'does.' },

  // -------------------------------------------------------------------------
  // HOW LONG A DECRYPTED PRIVATE KEY MAY STAY IN MEMORY (2026-09-06).
  //
  // Where key material PERSISTS it is held in this process as CIPHERTEXT, and
  // the plaintext exists only while something is signing with it. These two
  // rows are how long "while" is. `common/keystore.js` carries the argument,
  // including — importantly — what this does NOT defend against.
  // -------------------------------------------------------------------------
  { key: 'keys.plaintextRetention', group: 'Key material',
    label: 'How long a decrypted private key is kept',
    path: 'keys.plaintextRetention', env: 'STS_KEYS_PLAINTEXT_RETENTION',
    type: 'enum', enumValues: ['timed', 'per-use', 'resident'],
    dflt: 'timed', runtime: true,
    description: 'THREE WORDS RATHER THAN A FLAG, because the middle one is ' +
                 'the default and a boolean could only have reached two of ' +
                 'them. `timed` decrypts a realm\'s signing key on first use ' +
                 'and purges it once it has gone unused for ' +
                 '`keys.plaintextTtlS`; `per-use` purges it at the end of ' +
                 'the turn of the event loop that needed it, so the ' +
                 'plaintext is resident for microseconds and every signature ' +
                 'pays a decrypt and a key parse; `resident` decrypts once ' +
                 'and keeps it for the life of the process, which is what ' +
                 'this service did before the setting existed. **It only ' +
                 'means anything where keys PERSIST** — a development ' +
                 'service generates its key in memory and has no ciphertext ' +
                 'to fall back to, so there is nothing to purge to.' },

  { key: 'keys.plaintextTtlS', group: 'Key material',
    label: 'Decrypted key idle timeout (seconds)',
    path: 'keys.plaintextTtlS', env: 'STS_KEYS_PLAINTEXT_TTL_S',
    type: 'int', dflt: 300, min: 0, max: 86400, step: 1, runtime: true,
    description: 'Under `keys.plaintextRetention: timed`, how long a ' +
                 'decrypted signing key may sit unused before it is dropped. ' +
                 'The clock restarts on every use, so a busy realm keeps its ' +
                 'key and an idle one lets it go. Zero behaves as `per-use`. ' +
                 'Read under any other retention word, it means nothing and ' +
                 'the console says so.' },

  // THE `kid` A SIGNED TOKEN CARRIES (2026-09-13). In this group rather than
  // on a protocol page because it names the realm's SIGNING KEYS, which every
  // family here signs with; `common/jose_kid.js` argues the rest. Runtime,
  // so a realm may carry it — a `kid` is read per signature.
  { key: 'keys.kidFormat', group: 'Key material',
    label: 'Signed token kid format',
    path: 'keys.kidFormat', env: 'STS_KEYS_KID_FORMAT', type: 'enum',
    enumValues: ['internal', 'jwk-thumbprint-uri'],
    dflt: 'internal', runtime: true,
    description: 'What the `kid` header of every JWT this realm signs names ' +
                 'its key by. `internal` — the default — is this service\'s ' +
                 'own name (`sts-…`), an opaque string a verifier can only ' +
                 'look up. `jwk-thumbprint-uri` is RFC 9278\'s JWK ' +
                 'Thumbprint URI, ' +
                 '`urn:ietf:params:oauth:jwk-thumbprint:sha-256:<RFC 7638 ' +
                 'thumbprint>`, which anybody holding the public key can ' +
                 'compute. It names the KEY, not its certificate — that is ' +
                 '`x5c`/`x5u`. While it is on, the realm\'s JWKS carries ' +
                 'every signing key twice, under both names, so a token ' +
                 'signed before it was turned on still finds its key; ' +
                 'turning it off again drops the second entries, and a ' +
                 'token signed while it was on then names a key no JWKS ' +
                 'lists until it expires. ' +
                 'Tokens this service verifies itself are accepted under ' +
                 'either name. HMAC-signed tokens carry no kid either way. ' +
                 'Settable per realm.' },

  { key: 'keys.kekProvider', group: 'Key material',
    label: 'Key-encryption key provider',
    path: 'keys.kekProvider', env: 'STS_KEYS_KEK_PROVIDER', type: 'enum',
    enumValues: ['file', 'aws', 'gcp', 'azure', 'vault'],
    dflt: 'file', runtime: false,
    restartReason: 'the key-encryption key is read once, at startup, before ' +
                   'the signing keys are decrypted',
    description: 'Where the AES-256 key that protects the stored signing ' +
                 'keys is READ FROM. This service never generates it and ' +
                 'never writes it anywhere. `file` is the default because it ' +
                 'needs nothing — Kubernetes and Docker both mount a secret ' +
                 'as a file — and the other four are that same idea with a ' +
                 'cloud provider\'s access control in front of it. Each of ' +
                 'those lazily requires its official SDK, which is ' +
                 'deliberately NOT a dependency of this service: it is a ' +
                 'mock first, and four cloud SDKs nobody uses would be ' +
                 'carried by every install. A missing one is reported with ' +
                 'the package name to install.' },

  { key: 'keys.kekFile', group: 'Key material',
    label: 'Key-encryption key file',
    path: 'keys.kekFile', env: 'STS_KEYS_KEK_FILE', type: 'string',
    dflt: '/run/secrets/sts-kek', runtime: false,
    restartReason: 'read once at startup',
    description: 'The path the `file` provider reads. At least 32 bytes, as ' +
                 'raw bytes, hex or base64 — `openssl rand -base64 32 > ' +
                 '/run/secrets/sts-kek`. A file readable by group or other ' +
                 'is REPORTED rather than refused: the fix may be impossible ' +
                 'inside a container whose mount the operator does not ' +
                 'control, and a service that will not start is one somebody ' +
                 'works around by putting the key in an environment ' +
                 'variable.' },

  { key: 'keys.kekRef', group: 'Key material', label: 'Key-encryption key ' +
                                                      'reference',
    path: 'keys.kekRef', env: 'STS_KEYS_KEK_REF', type: 'string',
    dflt: '', runtime: false,
    restartReason: 'read once at startup',
    description: 'What the cloud providers name the secret by: an AWS ' +
                 'Secrets Manager name or ARN, a GCP resource name ' +
                 '(projects/<p>/secrets/<s>, with /versions/latest added ' +
                 'when no version is given), an Azure Key Vault secret name, ' +
                 'or a HashiCorp Vault read path. Unused by the `file` ' +
                 'provider.' },

  { key: 'keys.kekVault', group: 'Key material',
    label: 'Vault or Key Vault URL',
    path: 'keys.kekVault', env: 'STS_KEYS_KEK_VAULT', type: 'string',
    dflt: '', runtime: false,
    restartReason: 'read once at startup',
    description: 'The Azure Key Vault URL (https://<name>.vault.azure.net) ' +
                 'or the HashiCorp Vault endpoint. Empty lets the Vault SDK ' +
                 'fall back to VAULT_ADDR, which is what an agent sidecar ' +
                 'sets.' },

  // ---------------------------------------------------------------------
  // HOW THIS SERVICE PROVES WHO IT IS TO THE SECRET STORE (2026-09-12).
  //
  // A token in a configuration file is a bearer credential: whoever reads the
  // file is the identity, it does not expire, and rotating it is an outage.
  // **A CLIENT CERTIFICATE IS THE OTHER answer** — the store's own `auth/cert`
  // method, where the certificate is issued BY the store, bound to a policy
  // BY the store, and the private key never leaves this container.
  //
  // These three rows are about the CONNECTION rather than about either secret,
  // which is why they are `keys.vault*` and not `keys.kek*`: one deployment
  // has one secret store, and the key-encryption key and the database password
  // reach it the same way.
  //
  // Empty means what it always did — `keys.kekToken`, or the SDK's own
  // VAULT_TOKEN handling, which is what an agent sidecar writes.
  // ---------------------------------------------------------------------
  { key: 'keys.vaultClientCert', group: 'Key material',
    label: 'Client certificate for the secret store',
    path: 'keys.vaultClientCert', env: 'STS_KEYS_VAULT_CLIENT_CERT',
    type: 'string', dflt: '', runtime: false,
    restartReason: 'the secret store is read once at startup',
    description: 'A PEM certificate this service presents to Vault or ' +
                 'OpenBao, authenticating through the `cert` auth method ' +
                 'instead of with a token. Set it together with ' +
                 '`keys.vaultClientKey`; a token is not needed when both are ' +
                 'set, and is not used. **The certificate should be issued ' +
                 'BY the store** — that is what makes the identity the ' +
                 'store\'s to grant and to revoke rather than a file ' +
                 'somebody copied in.' },

  { key: 'keys.vaultClientKey', group: 'Key material',
    label: 'Client key for the secret store',
    path: 'keys.vaultClientKey', env: 'STS_KEYS_VAULT_CLIENT_KEY',
    type: 'string', dflt: '', runtime: false,
    restartReason: 'the secret store is read once at startup',
    description: 'The PEM private key for `keys.vaultClientCert`. It is read ' +
                 'from the path at startup and never logged.' },

  { key: 'keys.vaultCaCert', group: 'Key material',
    label: 'Trust anchor for the secret store',
    path: 'keys.vaultCaCert', env: 'STS_KEYS_VAULT_CA_CERT',
    type: 'string', dflt: '', runtime: false,
    restartReason: 'the secret store is read once at startup',
    description: 'A PEM certificate this service verifies the secret ' +
                 'store\'s TLS listener against. Empty uses this process\'s ' +
                 'own trust anchors, which is right for a public certificate ' +
                 'authority and wrong for a store whose listener certificate ' +
                 'it generated for itself. **This is a different question ' +
                 'from who signed the client certificate** and usually a ' +
                 'different certificate: one is the connection, the other is ' +
                 'the identity.' },

  { key: 'keys.vaultCertRole', group: 'Key material',
    label: 'Certificate auth role',
    path: 'keys.vaultCertRole', env: 'STS_KEYS_VAULT_CERT_ROLE',
    type: 'string', dflt: '', runtime: false,
    restartReason: 'the secret store is read once at startup',
    description: 'Which `auth/cert` certificate role to log in against. ' +
                 'Empty lets the store try every trusted certificate, which ' +
                 'is what a store with one of them wants. Naming it is ' +
                 'stricter and is what a store with several needs.' },

  // Added 2026-09-12. The login path was the literal `/auth/cert/login`, so a
  // store that mounted the cert method anywhere but its default path could not
  // be logged in to by certificate at all.
  { key: 'keys.vaultCertAuthMount', group: 'Key material',
    label: 'Certificate auth mount path',
    path: 'keys.vaultCertAuthMount', env: 'STS_KEYS_VAULT_CERT_AUTH_MOUNT',
    type: 'string', dflt: 'cert', runtime: false,
    restartReason: 'the secret store is read once at startup',
    description: 'Where the `cert` auth method is MOUNTED on the store, ' +
                 'which is `cert` unless whoever set the store up enabled it ' +
                 'with `-path=`. The login goes to `auth/<this>/login`. ' +
                 'Letters, digits, `-`, `_`, `.` and `/` only — anything ' +
                 'else is refused at the login rather than spliced into a ' +
                 'URL.' },

  { key: 'keys.kekField', group: 'Key material', label: 'Vault secret field',
    path: 'keys.kekField', env: 'STS_KEYS_KEK_FIELD', type: 'string',
    dflt: 'value', runtime: false,
    restartReason: 'read once at startup',
    description: 'Which field of a HashiCorp Vault secret holds the key. ' +
                 'Both KV engine versions are handled without a setting — v2 ' +
                 'nests the data one level deeper than v1 and the answer is ' +
                 'unwrapped by shape, because a deployment usually does not ' +
                 'know which engine it is on.' },

  { key: 'keys.kekToken', group: 'Key material', label: 'Vault token',
    path: 'keys.kekToken', env: 'STS_KEYS_KEK_TOKEN', type: 'string',
    dflt: '', runtime: false, secret: true,
    restartReason: 'read once at startup',
    description: 'A HashiCorp Vault token, when one is not coming from the ' +
                 'environment. Empty is the ordinary case: the SDK reads ' +
                 'VAULT_TOKEN, which is what an agent sidecar or an auth ' +
                 'method writes.' },

  // ---------------------------------------------------------------------
  // HOW LONG ONE SECRET-STORE PROBE MAY RUN (2026-09-12), for
  // `/admin/secrets`.
  //
  // **A TIMER HERE, WHERE `persistence.metricsTimeoutMs` DELIBERATELY IS
  // NOT ONE**, and the difference is worth knowing because the two settings
  // look alike. There the bound had to be PostgreSQL's own
  // `statement_timeout`, because abandoning the promise left a statement
  // running and a connection pinned out of a pool every protocol endpoint
  // writes through. A secret store has no equivalent to ask for and nothing
  // here is pooled: an abandoned HTTPS request closes its own socket.
  //
  // It bounds ONE probe rather than the page, and the probes run in
  // parallel — so a store that is entirely unreachable costs this once
  // rather than once per question asked of it. Runtime, because it is read
  // per render.
  // ---------------------------------------------------------------------
  { key: 'keys.storeProbeTimeoutMs', group: 'Key material',
    label: 'Secret store probe timeout (ms)',
    path: 'keys.storeProbeTimeoutMs', env: 'STS_KEYS_STORE_PROBE_TIMEOUT_MS',
    type: 'int', dflt: 5000, min: 250, max: 60000, runtime: true,
    description: 'How long any one probe behind /admin/secrets may wait for ' +
                 'a secret store to answer. Every one of them is a READ of ' +
                 'metadata — a stat of the key file, a sys endpoint, a KV ' +
                 'version history, a DescribeSecret — and none of them ever ' +
                 'fetches a secret value. The bound is there so that opening ' +
                 'a console page can never hang on somebody else\'s store; a ' +
                 'probe that runs out is drawn as a row saying so, exactly ' +
                 'like one that was refused.' },

  { key: 'keys.kekRegion', group: 'Key material', label: 'AWS region',
    path: 'keys.kekRegion', env: 'STS_KEYS_KEK_REGION', type: 'string',
    dflt: '', runtime: false,
    restartReason: 'read once at startup',
    description: 'The AWS region for Secrets Manager. Empty uses the SDK\'s ' +
                 'own resolution (AWS_REGION, the shared config file, the ' +
                 'instance metadata service), which is what an in-cluster ' +
                 'deployment relies on.' },

  { key: 'global.mode', group: 'Global', label: 'Mode',
    path: 'mode', env: 'STS_MODE', type: 'enum',
    enumValues: ['development', 'product'],
    // RUNTIME-SETTABLE AND NOT `realmRuntime`, which is the marker's whole
    // point: that one means "restart-only for the PROCESS, but a realm may
    // carry it anyway", and it exists for `oauth2.rfc9700` because that row
    // decides whether a SOCKET is bound as TLS. Nothing about the mode is a
    // property of a listener — every predicate in common/mode.js is read per
    // request — so the process can change it at runtime like any ordinary
    // runtime row, and a realm can carry one of its own because that is what
    // every runtime row already allows. `tests/config_realm_layer.js` asserts
    // that `realmRuntime` has exactly the holders it names, which is how each
    // one stays a decision rather than a copied line.
    dflt: 'development', runtime: true,
    description: 'What this service is. `development` is the mock every ' +
                 'release before 2026-09-06 was: no password is checked in ' +
                 'any protocol, an unknown user, application, service ' +
                 'principal or authorization server is created the first ' +
                 'time it is named, an OAuth client needs no secret, and ' +
                 '/admin-api is open so that a test can drive it and so that ' +
                 'somebody who holds no role can get back in. `product` runs ' +
                 'the SAME protocol implementations with the permissiveness ' +
                 'removed: a presented credential is verified against the ' +
                 'hashed `userPassword` on the person\'s directory entry, ' +
                 'every referenced object must have been created ahead of ' +
                 'time, every OAuth 2.0 and OpenID Connect application must ' +
                 'hold a client secret, and /admin-api requires the same ' +
                 'sign-in and roles the console does. It is settable per ' +
                 'trust realm, so one process can serve both at once. GET ' +
                 '/admin/mode lists every requirement and says which answer ' +
                 'each is given in each mode.\n\nIT CAN BE CHANGED WHILE ' +
                 'RUNNING, and the order matters when it is: /admin-api is ' +
                 'open right up until the moment it is set to `product`, so ' +
                 'provision the credentials FIRST and switch second. A realm ' +
                 'switched with nobody holding a credential has no way in — ' +
                 'the startup bootstrap runs at startup and not on a change, ' +
                 'deliberately, because a service that minted an ' +
                 'administrator every time a setting moved would be a ' +
                 'service with an administrator nobody asked for.' },

  { key: 'global.logLevel', group: 'Global', label: 'Log level',
    path: 'logLevel', env: 'STS_LOG_LEVEL', type: 'enum',
    enumValues: ['trace', 'debug', 'info', 'warn', 'error', 'fatal'],
    dflt: 'info', runtime: true,
    description: 'debug is the useful level for a mock whose job is to show ' +
                 'what it did: every endpoint call, and every token and ' +
                 'assertion both before and after it was signed. Changing it ' +
                 'here takes effect on the next line written, EXCEPT in the ' +
                 'eight vendored krb5_* codec modules: those are ' +
                 'byte-identical copies of the parent project\'s ' +
                 'common/krb5/* files and cannot be given a line to register ' +
                 'their logger, so they keep the level the process started ' +
                 'with. That is ASN.1 and crypto tracing rather than this ' +
                 'service\'s account of what it did.' },

  // --- The worker pool -----------------------------------------------------
  //
  // THE ONLY SETTING HERE THAT CHANGES HOW MANY PROCESSES THIS SERVICE IS.
  //
  // Node runs this service's six listener families on one thread, so a
  // synchronous computation does not slow it down, it STOPS it — and
  // post-quantum signing is that computation. Stalls of 14.6, 15.4, 17.8 and
  // 23.3 seconds were measured on 2026-08-29, during which this service
  // answered nobody at all: not another HTTP caller, not the KDC on port 88.
  // See common/worker.js.
  //
  // TWO, and not the core count. The property being bought is that the front
  // process's event loop stays FREE, and one worker buys all of it; the second
  // is what stops a caller's SLH-DSA signature queueing behind a stranger's.
  // Beyond that the return falls off quickly and the cost does not — each
  // worker is a node process — and this is a mock that commonly runs several
  // to a machine under a test suite. Raising it is one setting, and the pool
  // resizes on the next signature rather than at the next restart.
  //
  // NOTHING IS FORKED UNTIL THE FIRST POST-QUANTUM JOB, whatever this says, so
  // a process that never signs one never pays for a pool. That is what keeps
  // the parent project's in-process Kerberos jobs, this repository's own tests
  // and `node env/generate_defaults.js` free of child processes they would
  // never use and would have to wait for.
  { key: 'workers.count', group: 'Global', label: 'Worker processes',
    // FIVE SINCE 2026-09-06, where it was two. The pool is what keeps a
    // post-quantum signature off the thread holding six listener families —
    // an SLH-DSA sign measured at 15 SECONDS on this hardware — and two
    // workers means the third concurrent one waits behind them. Five is a
    // working default for a machine with more than four cores and still costs
    // nothing until the first post-quantum job, because the pool is lazy and
    // forks nothing before then.
    env: 'STS_WORKERS_COUNT', type: 'int', dflt: 5, min: 0, max: 32,
    runtime: true, perProcess: true,
    description: 'How many child processes the post-quantum signing, ' +
                 'verification and key generation are handed to, so that the ' +
                 'process holding the sockets is never the one computing an ' +
                 'SLH-DSA signature — which takes SECONDS, during which node ' +
                 'answers nothing at all. 0 means compute in this process, ' +
                 'which is what this service did before the pool existed: ' +
                 'correct, identical byte for byte, and blocking for as long ' +
                 'as each signature takes. The pool is forked lazily, so a ' +
                 'process that never signs post-quantum never forks anything ' +
                 'whatever this is set to, and it is re-read per job, so ' +
                 'changing it here takes effect on the next signature. A ' +
                 'REALM MAY NOT CARRY THIS: a pool belongs to the process, ' +
                 'and a realm resizing it would be resizing every other ' +
                 'realm\'s too.' },

  // ---------------------------------------------------------------------
  // THE SECOND POOL, AND IT IS A DIFFERENT KIND OF WORKER FROM THE ONE ABOVE.
  //
  // `workers.count` forks children that run a JOB TABLE — four leaf
  // computations handed everything they need. These three configure children
  // that run THE SERVICE: each loads the whole protocol stack in the same
  // order, binds no protocol port, and answers HTTP on a unix socket the front
  // process proxies to. `common/request_pool.js` argues it.
  //
  // All three are `perProcess` for `workers.count`'s reason, and
  // restart-only rather than runtime: a request worker takes seconds to start
  // because it loads the service, and the pool is brought up BEFORE the
  // listener binds so that cost is paid where nobody is waiting. A table that
  // said `runtime: true` and meant "on restart" is the lie this file refuses
  // to tell about a bound port.
  // ---------------------------------------------------------------------
  // ---------------------------------------------------------------------
  // HOW LONG A POST-QUANTUM JOB MAY TAKE BEFORE THE POOL GIVES UP ON IT
  // (2026-09-11).
  //
  // **`worker_pool.js` HAD NO BOUND AT ALL, AND ITS OWN HEADER SAYS WHY THAT
  // IS THE WORST AVAILABLE FAILURE.** It rejects every job on a worker that
  // DIES — "a promise nobody settles is a request that hangs" — and covers
  // nothing for a worker that stays alive and simply never answers. One was
  // observed doing exactly that: five idle children, no CPU anywhere, the
  // service answering everything else in eleven milliseconds, and one HTTP
  // request parked for ever. The suite's own 300s watchdog was the only thing
  // that ended it, which is five minutes per occurrence and says nothing about
  // what happened.
  //
  // **IT IS A BACKSTOP AND NOT A DIAGNOSIS.** Why a reply goes missing is not
  // known; what this does is turn an unbounded hang into a named failure the
  // caller can report, which is the same trade `reap()` already makes for the
  // death case.
  //
  // **THE DEFAULT IS GENEROUS ON PURPOSE.** The stalls this pool was built to
  // move off the event loop were measured at 15 to 23 seconds — a composite
  // verify, an SLH-DSA-SHAKE-128s signature — and a machine running the whole
  // suite under docker is slower than the one they were measured on. Two
  // minutes is far beyond any of them and far short of a watchdog. Zero turns
  // the bound off and restores the old behaviour exactly.
  { key: 'workers.jobTimeoutS', group: 'Global',
    label: 'Worker job timeout (seconds)',
    path: 'workers.jobTimeoutS', env: 'STS_WORKERS_JOB_TIMEOUT_S',
    type: 'int', dflt: 120, runtime: true, min: 0, max: 3600,
    description: 'How long the post-quantum worker pool waits for a job it ' +
                 'has sent to a child before failing it. **It exists because ' +
                 'there was no bound**: a worker that dies has its jobs ' +
                 'rejected, and a worker that stays alive and never answers ' +
                 'left the request hanging for ever — observed, with an idle ' +
                 'pool and a service answering everything else normally. A ' +
                 'failed job is reported to the caller and the request fails ' +
                 'with a reason; nothing is retried, because a worker holds ' +
                 'no state and the caller can simply ask again.\n\n' +
                 '**Generous on purpose.** The stalls this pool exists to ' +
                 'move off the event loop were 15 to 23 seconds, so two ' +
                 'minutes is far beyond any real job and far short of a test ' +
                 'runner\'s watchdog. `0` turns the bound off.' },

  { key: 'workers.requestCount', group: 'Global',
    label: 'Request worker processes',
    env: 'STS_WORKERS_REQUEST_COUNT', type: 'int', dflt: 0, min: 0, max: 32,
    runtime: false, perProcess: true,
    restartReason: 'the pool is forked before the listener binds, and the ' +
                   'check that refuses to dispatch without a coordinating ' +
                   'store runs once, there',
    description: 'How many child processes REQUESTS are handled in, so that ' +
                 'the process holding the sockets is doing request and ' +
                 'response I/O and not running handlers. Each worker loads ' +
                 'the whole protocol stack in the same order and binds no ' +
                 'protocol port. 0 — the default — means every request is ' +
                 'handled in the process that holds the sockets, which is ' +
                 'what this service has always done. Nothing is dispatched ' +
                 'whatever this is set to until workers.dispatch names a ' +
                 'path.' },

  // ---------------------------------------------------------------------
  // WHAT IS HANDLED IN A WORKER, AND IT WAS TWO SETTINGS UNTIL 2026-09-12.
  //
  // `workers.operations` held the non-HTTP half and is GONE. The distinction
  // was artificial: a dispatched thing is a dispatched thing, and an operator
  // naming what should leave the front process has no reason to care whether
  // this service reaches it over HTTP or over a raw socket. What it cost was
  // two places to look, two things to forget, and a coordination guard that
  // had to remember to check both lists.
  //
  // An entry says what it IS by its shape — a leading slash means a path
  // prefix, anything else is an operation kind, and `*` is everything. No
  // migration was needed because every value this setting has ever held is a
  // path beginning with `/` or the wildcard.
  // ---------------------------------------------------------------------
  { key: 'workers.dispatch', group: 'Global',
    label: 'Handled in a request worker',
    env: 'STS_WORKERS_DISPATCH', type: 'string', dflt: '',
    runtime: false, perProcess: true,
    restartReason: 'dispatching is REFUSED at startup unless this process is ' +
                   'coordinating, and that check runs once, before the ' +
                   'listener binds — anything named afterwards would be ' +
                   'dispatched without it having run at all',
    description: 'A comma-separated list of what goes to a request worker ' +
                 'instead of being handled in the process that owns the ' +
                 'sockets. An entry is one of three things and says which by ' +
                 'its shape:\n\n- a **path prefix**, which begins with a ' +
                 'slash — "/scim/v2,/admin-api". Matched after the realm ' +
                 'segment is removed, so naming /scim/v2 covers every ' +
                 'realm.\n- an **operation kind**, which does not — "ldap" ' +
                 'for every directory operation, or "ldap.search" for one of ' +
                 'them. These are the work behind the sockets that do not ' +
                 'speak HTTP: the front process keeps the socket and the ' +
                 'framing (it accepts the connection, decodes the BER and ' +
                 'writes the reply) and the worker does the work.\n- ' +
                 '**"*"**, which is EVERYTHING of both kinds — how "run the ' +
                 'service in the pool" is said, and the only spelling that ' +
                 'cannot go stale the next time a family is added.\n\nEMPTY ' +
                 'IS THE DEFAULT AND MEANS NOTHING IS DISPATCHED, which is ' +
                 'what makes the pool inert until it is asked for. /tls is ' +
                 'never dispatched whatever this says, because its whole ' +
                 'content is what the server saw of the connection the ' +
                 'request arrived on.\n\n**Nothing is dispatched unless this ' +
                 'process is coordinating**: an entry here with a store that ' +
                 'has no change log stops the service at startup, naming ' +
                 'this setting, rather than letting each worker hold a ' +
                 'private copy of the directory, the sessions and the ' +
                 'settings. A PATH named here when no worker is serving is ' +
                 'REFUSED 503 rather than handled here, because the same ' +
                 'path answered by whichever of two processes was available ' +
                 'is the failure this pool exists to avoid; an OPERATION is ' +
                 'done by the caller instead, because failing one would take ' +
                 'a protocol listener down for what is a performance ' +
                 'measure.' },

  // ---------------------------------------------------------------------
  // THE ROUTING POLICY, AND THE LIST IS OF THE EXCEPTIONS ON PURPOSE.
  //
  // Everything dispatched holds affinity unless it is named here, which is the
  // right way round: a protocol subsystem carries a browser flow across several
  // requests and belongs on one worker, and the surfaces that do not are few
  // enough to write down. Naming the affinity side instead would mean every new
  // protocol family had to be added to a list or would silently lose its flow.
  // ---------------------------------------------------------------------
  { key: 'workers.fanout', group: 'Global',
    label: 'Dispatched paths with no session affinity',
    env: 'STS_WORKERS_FANOUT', type: 'string',
    dflt: '/scim,/xacml,/admin-api',
    runtime: false, perProcess: true,
    restartReason: 'the workers this spreads requests across are forked ' +
                   'before the listener binds',
    description: 'A comma-separated list of path prefixes that go to the ' +
                 'least-loaded request worker instead of being stuck to the ' +
                 'session or flow they belong to. These three carry their ' +
                 'own credential on every request and name their own target, ' +
                 'so nothing about one request has to be remembered to ' +
                 'answer the next. EVERYTHING ELSE DISPATCHED HOLDS AFFINITY ' +
                 '— every protocol family, the admin console and the user ' +
                 'portal — because a browser flow spans several requests ' +
                 'whose state lives in the worker that made it. LDAP is not ' +
                 'here and cannot be: its protocol is a raw socket the front ' +
                 'process holds, and its only HTTP views are console pages ' +
                 'under /admin/ldap, which are the console. Affinity is a ' +
                 'LOCALITY measure and never a correctness one — what makes ' +
                 'a dispatched path correct is that every store its handlers ' +
                 'touch is reachable from a worker.' },

  // ---------------------------------------------------------------------
  // A SECOND POOL FOR THIS SERVICE'S OWN TWO HOSTED SURFACES (2026-09-13).
  //
  // The console and the portal are pages a PERSON is waiting on, and with
  // one pool they queue behind whatever the protocols are doing — a bulk load
  // over SCIM, a CAEP storm of loopback pushes — on the same workers. A pool
  // of their own isolates them in both directions: a console page walking the
  // directory does not hold a protocol worker, and a protocol storm does not
  // hold the console.
  //
  // **WHICH POOL, NOT WHETHER.** `workers.dispatch` is still the one list of
  // what leaves the front process (see the note above it about why there is
  // one); these two rows only decide where a dispatched path named in
  // `workers.surfaces` goes. With `workers.surfaceCount` at 0 — the default —
  // those paths go to the protocol pool exactly as before.
  // ---------------------------------------------------------------------
  { key: 'workers.surfaceCount', group: 'Global',
    label: 'Hosted-surface worker processes',
    env: 'STS_WORKERS_SURFACE_COUNT', type: 'int', dflt: 0, min: 0, max: 32,
    runtime: false, perProcess: true,
    restartReason: 'the pool is forked before the listener binds, and the ' +
                   'checks that refuse it without coordination and without ' +
                   'read-your-write run once, there',
    description: 'How many request workers are kept for this service\'s OWN ' +
                 'two hosted surfaces — the admin console and the user ' +
                 'portal, or whatever workers.surfaces names — separately ' +
                 'from the workers.requestCount workers that run the ' +
                 'protocols. A console page or a portal page then never ' +
                 'queues behind protocol traffic on the same worker, and a ' +
                 'console page walking the directory never holds a protocol ' +
                 'worker. 0 — the default — means there is no second pool ' +
                 'and those paths go wherever the rest of workers.dispatch ' +
                 'goes. Nothing is sent to these workers unless ' +
                 'workers.dispatch names the paths too. **It REQUIRES ' +
                 'workers.readYourWrite**: signing in to the console now ' +
                 'crosses two processes (the sign-in in a protocol worker, ' +
                 'the console session in one of these), and without the ' +
                 'barrier the second would intermittently read a store the ' +
                 'first had not yet written — so the service refuses to ' +
                 'start rather than answer wrongly.' },

  { key: 'workers.surfaces', group: 'Global',
    label: 'Paths handled by the hosted-surface workers',
    env: 'STS_WORKERS_SURFACES', type: 'string', dflt: '/admin,/portal',
    runtime: false, perProcess: true,
    restartReason: 'the pool that answers these is forked before the ' +
                   'listener binds',
    description: 'A comma-separated list of path prefixes that go to the ' +
                 'hosted-surface workers (workers.surfaceCount) instead of ' +
                 'the protocol workers. Matched after the realm segment is ' +
                 'removed and at a segment boundary, so /admin covers ' +
                 '/realm/acme/admin/users and does NOT cover /admin-api — ' +
                 'the management API is a machine\'s door and stays with the ' +
                 'protocols by default, so that a bulk load through it ' +
                 'cannot hold the console. Everything under a prefix goes, ' +
                 'including the console\'s and the portal\'s own Shared Signals ' +
                 'receivers, which belong to those surfaces. Ignored while ' +
                 'workers.surfaceCount is 0.' },

  // ---------------------------------------------------------------------
  // READ-YOUR-WRITE ACROSS WORKERS. Off by default, and the cost is the reason.
  // ---------------------------------------------------------------------
  // ---------------------------------------------------------------------
  // HOW MANY CONNECTIONS THE FRONT PROCESS MAY HAVE OPEN TO ONE WORKER
  // (2026-09-12).
  //
  // The dispatch path used node's global agent, whose `maxSockets` is
  // Infinity, so nothing limited how many unix-socket connections the front
  // process could have open to one worker. An unbounded proxy in front of a
  // single-threaded worker is a bug whether or not it has been observed, and
  // past this number a request WAITS for a connection rather than opening
  // another.
  //
  // **IT IS NOT WHAT FIXED THE EAGAIN**, and `request_pool.js` carries that
  // at length: the job that measured one `connect EAGAIN` in five thousand
  // creates issues them ONE AT A TIME, so no per-worker cap was near being
  // reached by it. What fixes that is the explicit listen backlog on the
  // worker's own socket. This bounds the other end.
  //
  // A worker is ONE THREAD, so a bound in the tens costs nothing real — but
  // it must not be SMALL: this service makes requests to itself (the
  // OpenID Connect back channel), so a worker whose connections are all held
  // by requests awaiting a reentrant call needs one more to make progress.
  //
  // Restart-only because an agent is built per worker at fork.
  // ---------------------------------------------------------------------
  // -------------------------------------------------------------------------
  // THE BATCH LANE (2026-09-14). A SCIM bulk load, and the Shared Signals
  // pushes each write makes to this service's own console and portal
  // receivers, took every worker of a dispatched service and nothing else was
  // answered for fourteen minutes. Batch traffic is confined to a share of each
  // pool's workers and a number of requests in flight; the rest waits in the
  // front process. common/CLAUDE.md argues it under request_pool.js.
  // -------------------------------------------------------------------------
  { key: 'workers.batch', group: 'Global',
    label: 'Batch traffic paths',
    env: 'STS_WORKERS_BATCH', type: 'string',
    dflt: '/scim,/admin/signals/receive,/portal/signals/receive',
    runtime: true, perProcess: true,
    description: 'A comma-separated list of path prefixes whose requests are ' +
                 'BATCH traffic: routed only to a share of each pool\'s ' +
                 'workers (workers.batchWorkerShare) and held to a number in ' +
                 'flight (workers.batchConcurrency), so a bulk load cannot ' +
                 'take every worker and other requests go on being answered. ' +
                 'Matched after the realm segment is removed and at a segment ' +
                 'boundary. The default is SCIM and this service\'s own two ' +
                 'Shared Signals receive endpoints, which every directory ' +
                 'write pushes to. Empty turns the lane off. Only read when ' +
                 'requests are dispatched (workers.requestCount).' },

  { key: 'workers.batchWorkerShare', group: 'Global',
    label: 'Share of workers batch traffic may use (%)',
    env: 'STS_WORKERS_BATCH_WORKER_SHARE', type: 'int', dflt: 50, min: 1,
    max: 100, runtime: true, perProcess: true,
    description: 'The percentage of a pool\'s workers batch traffic is routed ' +
                 'to — at least one, and one fewer than the pool unless the ' +
                 'pool has one worker or this is 100. A request already bound ' +
                 'to a worker (a write to one SCIM resource, a session) keeps ' +
                 'its worker, because that binding is what stops two ' +
                 'read-modify-writes of one resource losing an update.' },

  { key: 'workers.batchConcurrency', group: 'Global',
    label: 'Batch requests in flight per lane worker',
    env: 'STS_WORKERS_BATCH_CONCURRENCY', type: 'int', dflt: 8, min: 0,
    max: 10000, runtime: true, perProcess: true,
    description: 'How many batch requests may be in flight per worker of the ' +
                 'lane, per pool. Past it a batch request waits in the front ' +
                 'process, in order. 0 keeps the lane (the share of workers) ' +
                 'and removes this cap.' },

  { key: 'workers.batchQueueLimit', group: 'Global',
    label: 'Batch requests waiting',
    env: 'STS_WORKERS_BATCH_QUEUE_LIMIT', type: 'int', dflt: 5000, min: 1,
    max: 1000000, runtime: true, perProcess: true,
    description: 'How many batch requests may wait for the lane, per pool. ' +
                 'Past it a batch request is answered 503 with Retry-After at ' +
                 'once, which bounds the memory a burst can take in the front ' +
                 'process.' },

  { key: 'workers.batchQueueTimeoutS', group: 'Global',
    label: 'Longest a batch request waits (seconds)',
    env: 'STS_WORKERS_BATCH_QUEUE_TIMEOUT_S', type: 'int', dflt: 60, min: 1,
    max: 3600, runtime: true, perProcess: true,
    description: 'A batch request that has waited this long for the lane is ' +
                 'answered 503 with Retry-After instead of being dispatched.' },

  { key: 'workers.maxSockets', group: 'Global',
    label: 'Connections per request worker',
    path: 'workers.maxSockets', env: 'STS_WORKERS_MAX_SOCKETS',
    type: 'int', dflt: 64, min: 1, max: 4096, runtime: false,
    restartReason: 'each worker\'s connection agent is built when it is forked',
    description: 'How many connections the front process may have open to ' +
                 'ONE request worker at a time. Past it a dispatched request ' +
                 'waits for a connection rather than opening another, so the ' +
                 'front process cannot have an unbounded number of ' +
                 'connections open to a worker that is one thread. Do NOT ' +
                 'make it small: this service makes requests to itself (the ' +
                 'OpenID Connect back channel), and a worker whose ' +
                 'connections are all held by requests waiting on a ' +
                 'reentrant call needs one more to make progress. Ignored ' +
                 'when workers.requestCount is 0.' },

  { key: 'workers.readYourWrite', group: 'Global',
    label: 'Read-your-write across request workers',
    env: 'STS_WORKERS_READ_YOUR_WRITE', type: 'bool', dflt: false,
    runtime: true, perProcess: true,
    description: 'Whether a request worker must catch up with what the other ' +
                 'workers have written before it serves. Coordination makes ' +
                 'workers CONVERGE — measured at half a second to a second — ' +
                 'and convergence is not read-your-write: with this off, a ' +
                 'caller that writes through one worker and reads through ' +
                 'another may be answered by one that has not caught up, ' +
                 'which matters most for the fanout surfaces (SCIM, XACML, ' +
                 'the management API) precisely because consecutive requests ' +
                 'there land anywhere. With it on, the pool counts writes ' +
                 'and a worker that is behind pulls before it answers — so ' +
                 'the cost falls on the first read after a write on each ' +
                 'worker, and on nothing while nothing is being written. OFF ' +
                 'BY DEFAULT because that is the behaviour that existed ' +
                 'before it, and because whether the wait is worth it is a ' +
                 'question about the callers rather than about the pool.' },

  { key: 'workers.socketDir', group: 'Global',
    label: 'Request worker socket directory',
    env: 'STS_WORKERS_SOCKET_DIR', type: 'string', dflt: '',
    runtime: false, perProcess: true,
    restartReason: 'the owner-only directory is created once, when the pool ' +
                   'starts, and removed on the way out',
    description: 'Where the unix sockets request workers listen on are ' +
                 'created. Empty means the system temporary directory. One ' +
                 'owner-only directory is made per process and removed on ' +
                 'the way out, so two copies of this service on one machine ' +
                 'cannot meet. A socket here is a door into this service ' +
                 'that skips every check the front process makes, which is ' +
                 'why both the directory and the socket are narrowed to the ' +
                 'owner.' },

  // --- Trust realms --------------------------------------------------------
  // Two settings, and they are the only two in this table that a realm cannot
  // set on itself: a realm that could turn realms off, or move the prefix it
  // was found under, would be doing it half way through the request that found
  // it. Refused at both ends — see realms.js's setOverride() and this file's
  // realmOverrideOf().
  { key: 'realms.enabled', group: 'Trust realms', label: 'Trust realms enabled',
    env: 'STS_REALMS_ENABLED', type: 'bool', dflt: true, runtime: true,
    description: 'Whether the realms defined on /admin/realms answer on ' +
                 'their path prefixes. Turning it OFF leaves every ' +
                 'definition in place and stops the paths working, which is ' +
                 'what to reach for when a realm is answering something it ' +
                 'should not: nothing has to be deleted to find out whether ' +
                 'a realm is the reason for something. It has NO effect at ' +
                 'all until at least one realm is defined — with only the ' +
                 'built-in default realm this service behaves exactly as it ' +
                 'did before realms existed, and that is a property rather ' +
                 'than a coincidence.' },

  { key: 'realms.pathSegment', group: 'Trust realms', label: 'Realm path ' +
      'segment',
    env: 'STS_REALMS_PATH_SEGMENT', type: 'string', dflt: 'realm',
    runtime: true,
    description: 'The segment in front of a realm id, so that the realm ' +
                 '`acme` is reached at /realm/acme/oauth2/token. Set it to ' +
                 'the empty string for the bare /acme/oauth2/token shape, ' +
                 'which is what a client ported from a product that spells ' +
                 'it that way expects. A realm may never be named after the ' +
                 'first segment of a path this service already serves, ' +
                 'WHATEVER this is set to, precisely so that clearing it ' +
                 'cannot turn an existing realm into a shadow over the ' +
                 'console or the authorization server.' },

  // --- OAuth 2.0 / OpenID Connect -----------------------------------------
  { key: 'oauth2.issuer', group: 'OAuth 2.0 / OIDC', label: 'Issuer identifier',
    env: 'STS_OAUTH2_ISSUER', type: 'string', dflt: '', runtime: true,
    description: 'The `issuer` in the RFC 8414 and OpenID Provider metadata, ' +
                 'and the `iss` of every token signed here. LEAVE IT EMPTY ' +
                 'unless you mean to pin it: empty means each response names ' +
                 'the base URL the request arrived on, which is what makes ' +
                 'the same process answer correctly as localhost, as sts on ' +
                 'a compose network and through a published port. A pinned ' +
                 'value is returned whatever the request was — useful for ' +
                 'reproducing a mismatch on purpose, and a conforming client ' +
                 'MUST reject a document whose issuer is not the one it ' +
                 'fetched from.' },

  // --- RFC 9700, the OAuth 2.0 Security Best Current Practice --------------
  //
  // Three rows rather than one, and the two below the flag are not sub-flags of
  // it: `redirectUris` is the DATA the mode compares against and is useless
  // without it, and `loopbackPortWildcard` is the one exception RFC 9700 itself
  // carves out, which a native-app client author needs to be able to remove in
  // order to see what their code does against a server that got it wrong.
  //
  // All three are runtime, and they have to be: `oauth2_bcp.js` reads each one
  // per request for exactly the reason the runtime rule at the top of this file
  // gives. A mode you have to restart to turn on is one nobody turns on twice.
  //
  // RESTART-ONLY, and that is new: this flag used to be runtime and stopped
  // being one the moment it grew a consequence that happens before the service
  // is listening. `global.https` derives its default from it, so turning it on
  // turns the MAIN PORT into an HTTPS listener — a bound socket, which is the
  // first of the three restart-only kinds at the top of this file. A flag that
  // was runtime for its checks and restart-only for its socket would be the
  // exact silent disagreement the note up there warns about: /admin/config
  // would report the mode as on while every authorization response still went
  // out over plain HTTP.
  //
  // AND `realmRuntime`, WHICH IS THE OTHER HALF OF THAT SAME ARGUMENT. The
  // paragraph above is about a SOCKET, and a realm has none: it answers on the
  // port this process already bound, in the scheme that port was bound in. So
  // the one reason this row is restart-only does not reach a realm, and a realm
  // may carry it — which is how one process serves the permissive pass at
  // /oauth2/authorize and the compliant one at /realm/<id>/oauth2/authorize.
  //
  // What a realm does NOT get with it is a scheme of its own. With the process
  // on plain http, a realm in this mode enforces every check in oauth2_bcp.js
  // and still publishes http endpoints — which is the combination
  // `global.https` exists to make settable both ways, and it is REPORTED rather
  // than hidden: mainPortIsTls() is false, GET /oauth2/rfc9700 says so, and the
  // four requirements that are properties of the deployment come back `no`
  // instead of `deployment`. A stack that wants the compliant pass over https
  // turns `global.https` on for the PROCESS; see the note on that row.
  { key: 'oauth2.rfc9700', group: 'OAuth 2.0 / OIDC', label: 'RFC 9700 mode',
    env: 'STS_OAUTH2_RFC9700', type: 'bool', dflt: false, runtime: false,
    realmRuntime: true,
    restartReason: 'it decides whether the main port is bound as HTTPS ' +
                   '(global.https), and a listener is bound when the process ' +
                   'starts. A REALM may carry it even so — a realm binds no ' +
                   'socket, so it answers in whatever scheme this process ' +
                   'was started in and only the mode\'s checks change',
    description: 'Enforce RFC 9700 (OAuth 2.0 Security Best Current ' +
                 'Practice) on the authorization flow: exact-string redirect ' +
                 'URI matching with the loopback port exception, no open ' +
                 'redirects, no http redirect URI off the loopback, PKCE ' +
                 'required of public clients with S256 only, PKCE downgrade ' +
                 'and value-reuse refused, a nonce required with any ' +
                 'id_token, and no response type that issues an access token ' +
                 'from the authorization endpoint. OFF by default: this ' +
                 'service exists to exercise clients, and a client is ' +
                 'exercised by both answers — with the mode on it also stops ' +
                 'advertising in both discovery documents what it would now ' +
                 'refuse. It also turns THE MAIN PORT INTO AN HTTPS LISTENER ' +
                 '— see global.https, whose default it is — because section ' +
                 '2.1 says an authorization response must not be sent over ' +
                 'an unencrypted connection, and that was the one ' +
                 'requirement this mode could not enforce while its own ' +
                 'endpoint was only reachable over http. GET /oauth2/rfc9700 ' +
                 'lists every requirement and says which are enforced, which ' +
                 'are only detected, and which are true of the deployment ' +
                 'rather than of a request.' },

  // ---------------------------------------------------------------------
  // OAUTH 2.1 MODE (2026-09-13), AND IT IMPLIES THE ROW ABOVE.
  //
  // `realmRuntime` ON A SECOND OAUTH ROW, AND THE ARGUMENT IS MADE HERE RATHER
  // THAN BORROWED. The marker's test is that the restart reason must be
  // something a realm demonstrably does not have. This row's ONLY consequence
  // that happens before the service is listening is the one `oauth2.rfc9700`
  // has, and for the same reason: `global.https` derives its default from it
  // (see that row — `processValue()` of either flag), so turning it on for the
  // PROCESS binds the main port as HTTPS. Nothing else is consumed at startup:
  // `oauth-oidc/oauth21.js`'s `enabled()` and `oauth2_bcp.js`'s read the
  // setting per request, through the realm layer, and no material is built from
  // it. A realm binds no socket, so the reason does not reach it — which is the
  // same sentence, proved about a different row, rather than the same line
  // copied. `tests/config_realm_layer.js` lists it, and its generic check that
  // flipping a realmRuntime row in a realm moves no derived row holds because
  // both derivations read below the realm layer.
  { key: 'oauth2.oauth21', group: 'OAuth 2.0 / OIDC', label: 'OAuth 2.1 mode',
    env: 'STS_OAUTH2_OAUTH21', type: 'bool', dflt: false, runtime: false,
    realmRuntime: true,
    restartReason: 'it turns RFC 9700 mode on, which decides whether the ' +
                   'main port is bound as HTTPS (global.https), and a ' +
                   'listener is ' +
                   'bound when the process starts. A REALM may carry it even ' +
                   'so — a realm binds no socket, so only the mode\'s checks ' +
                   'change',
    description: 'Enforce the OAuth 2.1 Authorization Framework ' +
                 '(draft-ietf-oauth-v2-1-16, still an Internet-Draft). It ' +
                 'turns RFC 9700 mode on — everything that mode enforces is ' +
                 'part of 2.1 — and adds: PKCE for confidential clients too ' +
                 '(unless one relies on the OpenID Connect nonce), ' +
                 'code_challenge_method required, a client that must have ' +
                 'registered its own redirect URI (oauth2.redirectUris is ' +
                 'not read), a token request naming a client that declares ' +
                 'nothing refused, a presented credential that must verify, ' +
                 'one client authentication method per request, the client ' +
                 'credentials grant for authenticated clients only, a JWT ' +
                 'client assertion addressed to the issuer alone ' +
                 '(draft-ietf-oauth-rfc7523bis-11), no SAML client ' +
                 'authentication, no repeated parameters, a ten-minute cap ' +
                 'on a code, and error_description limited to its grammar. ' +
                 'And two RFC 9700 behaviours step aside: a token request ' +
                 'may omit redirect_uri, and an authorization request may ' +
                 'omit it when the client registered one. OFF by default. ' +
                 'GET /oauth2/oauth21 lists every requirement.' },

  // ---------------------------------------------------------------------------
  // THE ONE SETTING IN THIS FILE THAT DEFAULTS TO ON, AND THE ARGUMENT IS NOT
  // THE USUAL ONE.
  //
  // Every other policy here is off by default because this service exists to
  // exercise clients and a refusal that cannot be turned off removes a test
  // case rather than adding one. Consent is not a refusal. It is the SCREEN
  // every real authorization server draws the first time somebody signs in to
  // an application, and a client that has never met one has never run the code
  // that survives it — the extra redirect, the second visit to the
  // authorization endpoint, the `access_denied` when somebody says no. Off by
  // default would have meant the interesting behaviour was the one nobody saw.
  //
  // OFF MEANS EXACTLY WHAT THIS SERVICE DID BEFORE THE FEATURE EXISTED: no
  // screen, nothing recorded, and `prompt=consent` honoured no differently from
  // any other prompt value. It is NOT "consent to everything" — no agreement is
  // written to anybody's entry, so turning it back on asks again.
  //
  // `runtime: true` and settable on a realm, for
  // `delegatedPermissionsEnforced`'s reason: there is no listener and no key
  // involved, so nothing here is decided when a socket is bound.
  { key: 'oauth2.consentRequired', group: 'OAuth 2.0 / OIDC',
    label: 'Ask for consent',
    env: 'STS_OAUTH2_CONSENT_REQUIRED', type: 'bool', dflt: true,
    runtime: true,
    description: 'ASK THE PERSON before the authorization endpoint issues ' +
                 'anything for a scope they have not already agreed to for ' +
                 'that application. The first time a given username signs in ' +
                 'to a given client_id for a given scope, /oauth2/consent is ' +
                 'drawn listing the scopes that are new; nothing is issued ' +
                 'until they press Allow, and Deny returns `access_denied` ' +
                 'to the client. The answer is written to `oauthConsent` on ' +
                 'that person\'s own entry under ou=users — one value per ' +
                 '(person, application, scope) — so the second sign-in is ' +
                 'silent and an `ldapsearch` can read what somebody agreed ' +
                 'to. A delegated permission is recorded by its WHOLE ' +
                 'identifier (`https://example.com/write`), never by the ' +
                 'bare permission name, because two resources may both ' +
                 'expose `read`. `oauthGlobalConsent` on an APPLICATION\'s ' +
                 'entry consents a scope for everybody who signs in to it ' +
                 'and writes nothing about anybody — an override rather than ' +
                 'a record, so removing it asks everybody again. ' +
                 '`prompt=consent` asks again whatever is on the entry; ' +
                 '`prompt=none` with something outstanding is ' +
                 '`consent_required`, which is what OIDC Core section ' +
                 '3.1.2.6 defines it for. With this OFF nothing is asked and ' +
                 'nothing is recorded, which is what this service did before ' +
                 'the screen existed. It does not re-judge a grant already ' +
                 'issued: the token endpoint asks nobody anything, so a ' +
                 'refresh of a code obtained before this was turned on still ' +
                 'works. /admin/consent is the register.' },

  // THE SECOND MODE IN THIS FILE, AND IT IS DELIBERATELY NOT PART OF THE FIRST.
  // RFC 9700 mode enforces a published Best Current Practice and every one of
  // its checks cites a section; a delegated permission is nothing of the kind —
  // it is a policy this service was CONFIGURED with, in the shape Microsoft
  // Entra ID uses, and no RFC says an authorization server must have one.
  // Rolling it into `oauth2.rfc9700` would have made `GET /oauth2/rfc9700` list
  // a requirement no document contains, which is the one thing that page must
  // never do.
  //
  // OFF BY DEFAULT, for the reason every refusal in this service is off by
  // default: it exists to exercise clients, and a client is exercised by both
  // answers. With it off a permission scope still becomes an audience and a
  // scope claim and the console still says which requests were not backed by a
  // grant — so the register is fully usable, and readable, before anybody turns
  // this on. `runtime: true` and settable on a realm, so one realm can enforce
  // while another does not: there is no listener and no key involved, which is
  // what makes `oauth2.rfc9700` restart-only and does not apply here.
  { key: 'oauth2.delegatedPermissionsEnforced', group: 'OAuth 2.0 / OIDC',
    label: 'Enforce delegated permissions',
    env: 'STS_OAUTH2_DELEGATED_PERMISSIONS_ENFORCED', type: 'bool', dflt: false,
    runtime: true,
    description: 'REFUSE an authorization or token request that asks for a ' +
                 'permission the client has not been granted. A permission ' +
                 'is defined on a resource application — a base URI and a ' +
                 'name, joined into `https://example.com/write` — and ' +
                 'granted to a client application on its own entry; ' +
                 '/admin/delegation is the register and defines both. With ' +
                 'this OFF (the default) an ungranted permission is still ' +
                 'honoured: the token is audienced to the base URI and ' +
                 'carries the permission name on its scope claim exactly as ' +
                 'a granted one would, the request is logged as ungranted ' +
                 'and the console marks it. With it ON the same request is ' +
                 'refused `invalid_scope` at the AUTHORIZATION endpoint — ' +
                 'where the client can still be told — and at the token ' +
                 'endpoint for the grants that never reach it. A scope that ' +
                 'names no defined permission is unaffected in both modes: ' +
                 'it is an ordinary scope, granted as everything else here ' +
                 'is. It does NOT re-judge a grant already issued, so a ' +
                 'refresh of a code obtained before the setting was turned ' +
                 'on still works.' },

  // ---------------------------------------------------------------------------
  // RFC 8693 SECTION 2.2.1'S OPTIONAL `refresh_token`, AS A POLICY RATHER THAN
  // A YES OR A NO.
  //
  // The section says when one is worth issuing from a token exchange — "in
  // cases where the client of the token exchange needs the ability to access a
  // resource even when the original credential is no longer valid", the
  // user-not-present case — and leaves whether to do it to the authorization
  // server. Real ones differ, and a client written against one of them meets
  // the others; that difference is the thing this service exists to be.
  //
  // SO IT IS AN ENUM AND NOT A BOOL, and the three values are three servers a
  // client can be pointed at:
  //
  //   * `never`          — no refresh token from an exchange, whatever the
  //                        request said. What this service did before
  //                        2026-09-01, kept because a client that copes with a
  //                        refresh token and not with its absence is exactly
  //                        the bug a mock is for.
  //   * `when-requested` — RFC 8693 section 2.1 read literally: the client asks
  //                        with `requested_token_type`, and gets one if it did.
  //                        THE DEFAULT, so nothing changes for anybody.
  //   * `always`         — every exchange response carries one, asked for or
  //                        not. Several deployed authorization servers behave
  //                        this way and a client written against one of them
  //                        has never run the other path.
  //
  // A BOOL COULD NOT HAVE SAID THIS. `false` would have had to mean `never`,
  // which leaves `true` meaning either of the other two and no way to ask for
  // the third — and the interesting client bug is on the `always` side, where
  // a credential arrives that the client did not ask for and must not leak.
  //
  // PER APPLICATION, through `oauthTokenExchangeRefreshToken` on the CLIENT's
  // own entry — the client performing the exchange, since it is the party the
  // refresh token is handed to. That attribute applies to the OAuth 2.0 and
  // OpenID Connect families and to no other, and `common/applications.js`
  // refuses to write it on an entry declared for neither; see its `families`
  // member, which is the first of its kind in that schema.
  //
  // `runtime: true` and settable on a realm, for `consentRequired`'s reason:
  // there is no listener and no key involved, so nothing here is decided when a
  // socket is bound.
  { key: 'oauth2.tokenExchangeRefreshToken', group: 'OAuth 2.0 / OIDC',
    label: 'Refresh token from a token exchange',
    env: 'STS_OAUTH2_TOKEN_EXCHANGE_REFRESH_TOKEN', type: 'enum',
    enumValues: ['never', 'when-requested', 'always'],
    dflt: 'when-requested', runtime: true,
    description: 'WHETHER AN RFC 8693 TOKEN EXCHANGE HANDS BACK A ' +
                 '`refresh_token` BESIDE THE EXCHANGED ACCESS TOKEN. Section ' +
                 '2.2.1 makes it OPTIONAL and names the case it is for: a ' +
                 'client that must keep reaching a resource "even when the ' +
                 'original credential is no longer valid" — the ' +
                 'user-not-present case, where there is no session by ' +
                 'design. `when-requested` is the default and is section 2.1 ' +
                 'read literally: the client asks with ' +
                 '`requested_token_type=urn:ietf:params:oauth:token-type:refresh_token` ' +
                 'and gets one only if it did. `never` is what this service ' +
                 'did before that was implemented and refuses the ask ' +
                 'silently — the exchange still succeeds, with no refresh ' +
                 'token in it. `always` hands one to every exchange whether ' +
                 'it asked or not, which is how several deployed ' +
                 'authorization servers behave and is the path a client ' +
                 'written against the other two has never run. What comes ' +
                 'back is an ORDINARY refresh token of this service in every ' +
                 'case: redeemable at the refresh grant, revocable, subject ' +
                 'to `oauth2.refreshTokenTtlS`, rotated in RFC 9700 mode, ' +
                 'and bound to the DPoP key or client certificate the ' +
                 'exchange was made with. `issued_token_type` says ' +
                 '`access_token` throughout, because it describes the token ' +
                 'in the `access_token` member and that is what that member ' +
                 'holds. `oauthTokenExchangeRefreshToken` on the CLIENT ' +
                 'application\'s entry overrides this for that client alone ' +
                 '— it is an OAuth 2.0 / OpenID Connect attribute and this ' +
                 'registry refuses it on an application declared for neither ' +
                 'family. It does not re-judge anything already issued: a ' +
                 'refresh token handed out while this said `always` goes on ' +
                 'working after it is set to `never`, and /oauth2/revoke is ' +
                 'how to end one.' },

  // NOT part of RFC 9700 mode, and deliberately separate from it: it is a
  // testing aid rather than a policy, and it is useful in both modes. It is the
  // only way this service can help with a requirement it cannot enforce — the
  // CLIENT must validate the ID Token's nonce, and nothing observable from here
  // distinguishes a client that does from one that does not.
  { key: 'oauth2.breakIdTokenNonce', group: 'OAuth 2.0 / OIDC',
    label: 'Break the ID Token nonce',
    env: 'STS_OAUTH2_BREAK_ID_TOKEN_NONCE', type: 'bool', dflt: false,
    runtime: true,
    description: 'Put a DELIBERATELY WRONG nonce in every ID Token that ' +
                 'should carry one. RFC 9700 sections 2.1.1 and 4.5.3.2 make ' +
                 'validating it the CLIENT\'s job and this server cannot see ' +
                 'whether it happens — so this is how to find out: a client ' +
                 'that accepts the result is not checking, and one that ' +
                 'refuses it is. The same device as /spnego\'s three knobs ' +
                 'and the reserved password "invalid". OFF by default, ' +
                 'reported on GET /oauth2/rfc9700 whichever mode is in ' +
                 'force, and every spoiled token is logged as spoiled — an ' +
                 'ID Token that is wrong in a way nobody remembers turning ' +
                 'on is an expensive afternoon.' },

  // RFC 9700 section 2.2.2's lifetime paragraph. Read only in RFC 9700 mode —
  // like every other refusal that mode adds — because a refresh token that
  // stops working after a quiet afternoon is a surprise nobody asked for on a
  // service whose default is to be permissive.
  { key: 'oauth2.refreshIdleSeconds', group: 'OAuth 2.0 / OIDC per-client',
    label: 'Refresh token idle timeout (s)',
    env: 'STS_OAUTH2_REFRESH_IDLE_SECONDS', type: 'int', dflt: 86400,
    runtime: true,
    description: 'In RFC 9700 mode, how long a refresh CHAIN may go unused ' +
                 'before it stops working — section 2.2.2 says a refresh ' +
                 'token SHOULD expire after a period of client inactivity, ' +
                 'and says the period is deployment-dependent, which is why ' +
                 'this is a setting rather than a constant. It is measured ' +
                 'from the last time any token in the chain was redeemed, ' +
                 'not from issuance, so a client that refreshes every hour ' +
                 'keeps its grant indefinitely and one that stops is cut off ' +
                 'a day later. 0 turns it off while leaving the rest of the ' +
                 'mode alone. The ABSOLUTE expiry on the token itself is a ' +
                 'different setting (oauth2.refreshTokenTtlS, twenty-four ' +
                 'hours by default) and is unaffected by this one and ' +
                 'applies in both modes: this is a wall measured from the ' +
                 'last redemption, that one is a wall measured from ' +
                 'issuance, and a chain stops working at whichever comes ' +
                 'first.' },

  // Also section 2.2.2, and its own setting because "expire after inactivity"
  // and "revoke after a security event" are different policies a deployment
  // chooses separately — one is about a client that went away and the other
  // about a person who signed out.
  { key: 'oauth2.revokeRefreshOnLogout', group: 'OAuth 2.0 / OIDC per-client',
    label: 'Revoke refresh tokens on sign-out',
    env: 'STS_OAUTH2_REVOKE_REFRESH_ON_LOGOUT', type: 'bool', dflt: true,
    runtime: true,
    description: 'In RFC 9700 mode, end a browser sign-on session and every ' +
                 'refresh token issued ON that session is revoked — the ' +
                 'section MAY that names logout and a password change as the ' +
                 'examples. It is what makes /oauth2/logout and ' +
                 'WS-Federation\'s wsignout1.0 mean something to the back ' +
                 'channel: without it, signing out ends the cookie and ' +
                 'leaves a thirty-day credential in the client\'s hands. ON ' +
                 'by default WITHIN that mode, which is off by default — so ' +
                 'nothing changes until the mode is turned on. A token is ' +
                 'found by the session it was ISSUED on, which is recorded ' +
                 'beside it rather than carried as a claim.' },

  { key: 'oauth2.eddsaCurve', group: 'OAuth 2.0 / OIDC',
    label: 'EdDSA curve', env: 'STS_OAUTH2_EDDSA_CURVE', type: 'string',
    dflt: 'Ed25519', runtime: true, choices: ['Ed25519', 'Ed448'],
    description: 'Which Edwards curve an EdDSA signature is made on. RFC ' +
                 '8037 registers ONE algorithm value for both curves and ' +
                 'puts the curve in the key itself, so a client that ' +
                 'registers id_token_signed_response_alg="EdDSA" has no way ' +
                 'to say which it wants — this is that way. BOTH keys are ' +
                 'published in the JWKS whatever this is set to, with ' +
                 'different kids, so a verifier follows the kid in the ' +
                 'header and needs to know nothing about this setting; ' +
                 'changing it would otherwise strand every client holding a ' +
                 'cached JWKS.' },
  // -------------------------------------------------------------------
  // RFC 7521 / RFC 7523's AUTHORIZATION GRANT (2026-09-10). Three rows, and
  // the middle one is the only refusal in this service that is on by default
  // besides federation's — `oauth-oidc/assertion_grant.js` argues why there is
  // no permissive answer available for this grant.
  // -------------------------------------------------------------------
  { key: 'oauth2.jwtBearerGrant', group: 'OAuth 2.0 / OIDC',
    label: 'JWT bearer authorization grant (RFC 7523 section 2.1)',
    env: 'STS_OAUTH2_JWT_BEARER_GRANT', type: 'bool', dflt: true,
    runtime: true,
    description: 'Whether the token endpoint performs ' +
                 'grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer — a ' +
                 'trusted party signs an assertion naming a person, and this ' +
                 'authorization server issues an access token for them. It ' +
                 'is ON, and the metadata advertises the grant only while it ' +
                 'is: a grant_types_supported member is a promise. Turning ' +
                 'it off is how a client author tests what their code does ' +
                 'against a server that does not offer it. It does NOT ' +
                 'affect RFC 7523 section 2.2 — client authentication by ' +
                 'assertion — which is a different feature sharing a ' +
                 'document format.' },
  { key: 'oauth2.jwtBearerRequireRegisteredIssuer', group: 'OAuth 2.0 / OIDC',
    label: 'Require a registered assertion issuer',
    env: 'STS_OAUTH2_JWT_BEARER_REQUIRE_REGISTERED_ISSUER', type: 'bool',
    dflt: true, runtime: true,
    description: 'Whether an RFC 7523 authorization grant is refused when no ' +
                 'application in the realm declares its `iss` on ' +
                 'oauthAssertionIssuer. ON, and it is one of only two ' +
                 'refusals in this service that default to on — federation ' +
                 'is the other, for the same reason. An assertion IS the ' +
                 'whole authorization for that grant: there is no browser, ' +
                 'no password and no consent step in it, so accepting one ' +
                 'from anybody means anybody who can reach this port getting ' +
                 'an access token as anybody. Turning it off does NOT make ' +
                 'the grant accept unsigned assertions — the signature still ' +
                 'has to verify against a key registered for the issuer, or ' +
                 'against a certificate this service issued — it removes the ' +
                 'requirement that somebody declared the issuer first.' },
  { key: 'oauth2.jwtBearerMaxLifetimeS', group: 'OAuth 2.0 / OIDC',
    label: 'Longest assertion lifetime accepted (s)',
    env: 'STS_OAUTH2_JWT_BEARER_MAX_LIFETIME_S', type: 'int', dflt: 300,
    min: 0, max: 86400, runtime: true,
    description: 'The most seconds between an assertion\'s `iat` and its ' +
                 '`exp` that this authorization server will accept in an RFC ' +
                 '7523 grant. RFC 7521 section 5.2 invites a server to ' +
                 'refuse an assertion whose lifetime is unreasonable and ' +
                 'leaves "unreasonable" to it; a short life is the whole ' +
                 'difference between an assertion and a long-lived ' +
                 'credential somebody has to be able to revoke. ZERO ' +
                 'switches the check off, which is the way to exercise a ' +
                 'client that mints day-long assertions. An assertion with ' +
                 'no `iat` is measured from NOW to its `exp` — until ' +
                 '2026-09-12 it was not checked at all, so leaving out the ' +
                 'optional claim was the way round the ceiling. IN PRODUCT ' +
                 'MODE the same ceiling also applies to an RFC 7523 CLIENT ' +
                 'assertion (private_key_jwt, client_secret_jwt), which ' +
                 'there must carry an `exp` as well; development leaves ' +
                 'client assertions uncapped, as it always did.' },

  // -------------------------------------------------------------------
  // RFC 7522's SAML 2.0 PROFILE OF THE SAME FRAMEWORK. Three rows that
  // MIRROR the three above and are deliberately not shared with them: RFC
  // 7522 and RFC 7523 are two profiles of RFC 7521 and a deployment
  // legitimately offers one and not the other — a single switch would make
  // "turn the JWT grant off" also turn off a grant a SAML deployment
  // depends on. The SKEW is shared, because it answers "how far out may
  // somebody else's clock be" and that question has one answer whatever
  // the document format is.
  // -------------------------------------------------------------------
  { key: 'oauth2.saml2BearerGrant', group: 'OAuth 2.0 / OIDC',
    label: 'SAML 2.0 bearer authorization grant (RFC 7522 section 2.1)',
    env: 'STS_OAUTH2_SAML2_BEARER_GRANT', type: 'bool', dflt: true,
    runtime: true,
    description: 'Whether the token endpoint performs ' +
                 'grant_type=urn:ietf:params:oauth:grant-type:saml2-bearer — ' +
                 'a trusted party signs a SAML 2.0 assertion naming a ' +
                 'person, and this authorization server issues an access ' +
                 'token for them. It is ON, and the metadata advertises the ' +
                 'grant only while it is: a grant_types_supported member is ' +
                 'a promise. It does NOT affect RFC 7522 section 2.2 — ' +
                 'client authentication by SAML assertion — which is a ' +
                 'different feature sharing a document format, exactly as ' +
                 'the JWT row above does not affect private_key_jwt.' },
  { key: 'oauth2.saml2BearerRequireRegisteredIssuer', group: 'OAuth 2.0 / OIDC',
    label: 'Require a registered SAML assertion issuer',
    env: 'STS_OAUTH2_SAML2_BEARER_REQUIRE_REGISTERED_ISSUER', type: 'bool',
    dflt: true, runtime: true,
    description: 'Whether an RFC 7522 authorization grant is refused when no ' +
                 'application in the realm declares its <Issuer> on ' +
                 'oauthSamlAssertionIssuer. ON, for the reason the JWT row ' +
                 'above is on and federation is: an assertion IS the whole ' +
                 'authorization for that grant — no browser, no password, no ' +
                 'consent step — so accepting one from anybody means anybody ' +
                 'who can reach this port getting an access token as ' +
                 'anybody. Turning it off does NOT make the grant accept ' +
                 'unsigned assertions, and it does NOT make it accept a ' +
                 'certificate it holds no registration for: a SAML assertion ' +
                 'is only ever verified against a certificate registered ' +
                 'against the asserting party under the RFC 7522 attributes, ' +
                 'and there is no setting that changes that.' },
  { key: 'oauth2.saml2BearerMaxLifetimeS', group: 'OAuth 2.0 / OIDC',
    label: 'Longest SAML assertion lifetime accepted (s)',
    env: 'STS_OAUTH2_SAML2_BEARER_MAX_LIFETIME_S', type: 'int', dflt: 300,
    min: 0, max: 86400, runtime: true,
    description: 'The most seconds between a SAML assertion\'s IssueInstant ' +
                 'and its expiry that this authorization server will accept ' +
                 'in an RFC 7522 grant. Item 6 of section 3 says a server ' +
                 'may reject an assertion whose NotOnOrAfter is ' +
                 '"unreasonably far in the future" and leaves "unreasonable" ' +
                 'to it. ZERO switches the check off. The expiry it measures ' +
                 'to is the <Conditions> NotOnOrAfter where there is one and ' +
                 'the <SubjectConfirmationData> NotOnOrAfter otherwise, ' +
                 'which is item 4\'s own ordering.' },

  { key: 'oauth2.clientAssertionSkewS', group: 'OAuth 2.0 / OIDC',
    label: 'Client assertion clock skew (s)',
    env: 'STS_OAUTH2_CLIENT_ASSERTION_SKEW_S', type: 'int', dflt: 60,
    runtime: true,
    description: 'How far out a client assertion\'s exp, nbf and iat may be ' +
                 'and still be accepted (RFC 7523 section 3, private_key_jwt ' +
                 'and client_secret_jwt). Sixty seconds is the usual ' +
                 'allowance for two machines that are not synchronised. It ' +
                 'is also how long past its expiry an assertion\'s jti is ' +
                 'remembered, so the replay cache and the expiry check cover ' +
                 'exactly the same span with no gap between them.' },

  // -------------------------------------------------------------------------
  // THE 2026-09-12 HARD-CODED-VALUE SWEEP OF oauth-oidc/ AND oid4vc/.
  //
  // Every row from here to the end of this group was a LITERAL at a call site
  // until that day, and every `dflt` is exactly the literal it replaced — so a
  // service with none of them set behaves byte for byte as it did. Three of
  // them are more than a number and say so in their own descriptions:
  // `oauth2.dpopNonceRequired` moved a process-wide switch onto a realm,
  // `oauth2.openRegistration` is the product-mode door onto RFC 7591, and
  // `oauth2.assertionReplayCacheSize` changed what happens when the cache is
  // FULL — it refuses a new assertion rather than forgetting a live one.
  // -------------------------------------------------------------------------
  { key: 'oauth2.assertionReplayCacheSize', group: 'OAuth 2.0 / OIDC',
    label: 'Assertion replay cache size (per realm)',
    env: 'STS_OAUTH2_ASSERTION_REPLAY_CACHE_SIZE', type: 'int', dflt: 1000,
    min: 10, max: 1000000, runtime: true,
    description: 'How many unexpired rows the USED-ASSERTION HISTORY holds ' +
                 'per trust realm: every RFC 7523 JWT and RFC 7522 SAML ' +
                 'assertion accepted, as client authentication or as a ' +
                 'grant, in ONE history (it was three caches until ' +
                 '2026-09-13). The history persists in the ldif and postgres ' +
                 'stores in both modes, so this bounds a file or a table as ' +
                 'well as memory. **A FULL HISTORY REFUSES THE NEXT ASSERTION ' +
                 'RATHER THAN FORGETTING A LIVE ONE**: until 2026-09-12 the ' +
                 'caches dropped their oldest entry whether or not it had ' +
                 'expired, which let a captured assertion be replayed as soon ' +
                 'as a thousand newer ones had pushed it out. Expired rows ' +
                 'are swept first, so the refusal is reached only by that ' +
                 'many assertions being live at once — raise this, or shorten ' +
                 'oauth2.jwtBearerMaxLifetimeS, rather than accept a replay ' +
                 'window. /admin/used-assertions lists what is held.' },

  { key: 'oauth2.dpopNonceRequired', group: 'OAuth 2.0 / OIDC',
    label: 'Require a DPoP server nonce',
    env: 'STS_OAUTH2_DPOP_NONCE_REQUIRED', type: 'bool', dflt: false,
    runtime: true,
    description: 'Require every DPoP proof to carry a nonce this server ' +
                 'supplied (RFC 9449 sections 8 and 9), which turns the ' +
                 'first request of a session into a 401 or 400 and a retry. ' +
                 'It makes proofs FRESHER and never makes them mandatory: a ' +
                 'request with no DPoP header is still a Bearer request. PER ' +
                 'TRUST REALM since 2026-09-12 — it was one switch for the ' +
                 'whole process, so a realm turning it on turned it on for ' +
                 'every other. In development POST /dpop/nonce-mode writes ' +
                 'this setting for the realm it is reached in; in product ' +
                 'that endpoint refuses and this row — through /admin/oauth2 ' +
                 'or POST /admin-api/config/set, both behind a credential — ' +
                 'is the only way to change it.' },

  { key: 'oauth2.dpopIatSkewS', group: 'OAuth 2.0 / OIDC',
    label: 'DPoP proof iat window (s)',
    env: 'STS_OAUTH2_DPOP_IAT_SKEW_S', type: 'int', dflt: 300,
    min: 5, max: 3600, runtime: true,
    description: 'How far a DPoP proof\'s `iat` may be from now, either way ' +
                 '(RFC 9449 section 11.1). It is how long a captured proof ' +
                 'stays useful for the same method and URI, so it is short; ' +
                 'the jti replay cache remembers a proof for twice this, so ' +
                 'the two cover the same span.' },

  { key: 'oauth2.dpopNonceTtlS', group: 'OAuth 2.0 / OIDC',
    label: 'DPoP server nonce lifetime (s)',
    env: 'STS_OAUTH2_DPOP_NONCE_TTL_S', type: 'int', dflt: 300,
    min: 5, max: 3600, runtime: true,
    description: 'How long a server-supplied DPoP nonce is accepted after it ' +
                 'was handed out. Only read while oauth2.dpopNonceRequired ' +
                 'is on.' },

  { key: 'oauth2.openRegistration', group: 'OAuth 2.0 / OIDC',
    label: 'Open dynamic client registration (product mode)',
    env: 'STS_OAUTH2_OPEN_REGISTRATION', type: 'bool', dflt: false,
    runtime: true,
    description: 'Whether POST /oauth2/register (RFC 7591) accepts a ' +
                 'registration from anybody who can reach it IN PRODUCT ' +
                 'MODE. Development always does — it is how a client under ' +
                 'test registers itself — and this setting changes nothing ' +
                 'there. In product it is OFF, the endpoint refuses with ' +
                 '`access_denied` naming this setting, and ' +
                 '`registration_endpoint` is left out of both discovery ' +
                 'documents: a published endpoint that refuses every caller ' +
                 'is a promise broken. Create applications through /admin or ' +
                 '/admin-api instead, which require a credential. Turning it ' +
                 'on is a decision to let the internet mint confidential ' +
                 'clients on this authorization server. A registration ' +
                 'carrying a TRUSTED software statement is the other door ' +
                 'through a closed endpoint: see ' +
                 'oauth2.softwareStatementOpensRegistration.' },

  // -------------------------------------------------------------------------
  // SOFTWARE STATEMENTS (RFC 7591 section 2.3), 2026-09-13 — four rows, argued
  // in `oauth-oidc/software_statement.js`. The issuer refusal is ON in both
  // modes, as the RFC 7523 and RFC 7522 issuer refusals are, because a
  // statement trusted from anybody fixes a client's metadata for anybody.
  // -------------------------------------------------------------------------
  { key: 'oauth2.softwareStatementRequireTrustedIssuer',
    group: 'OAuth 2.0 / OIDC',
    label: 'Refuse a software statement from an undeclared issuer',
    env: 'STS_OAUTH2_SOFTWARE_STATEMENT_REQUIRE_TRUSTED_ISSUER', type: 'bool',
    dflt: true, runtime: true,
    description: 'Whether POST /oauth2/register (and an RFC 7592 update) ' +
                 'refuses a software_statement whose `iss` nothing in this ' +
                 'realm trusts, with unapproved_software_statement (RFC 7591 ' +
                 'section 3.2.2). Trusted means this realm issued it (from ' +
                 'an application\'s page or POST ' +
                 '/admin-api/applications/issue-software-statement) or an ' +
                 'application declares the issuer in ' +
                 'oauthSoftwareStatementIssuer and holds the key that signed ' +
                 'it. ON in both modes. Turned OFF, a statement from an ' +
                 'undeclared issuer is accepted UNVERIFIED — there is no key ' +
                 'to check it with — its claims lose to the JSON members ' +
                 'rather than taking precedence, the entry records it as ' +
                 'untrusted, and it never opens a closed registration ' +
                 'endpoint. A statement that is malformed, unsigned, badly ' +
                 'signed or expired is refused either way.' },

  { key: 'oauth2.softwareStatementOpensRegistration',
    group: 'OAuth 2.0 / OIDC',
    label: 'A trusted software statement opens a closed registration endpoint',
    env: 'STS_OAUTH2_SOFTWARE_STATEMENT_OPENS_REGISTRATION', type: 'bool',
    dflt: true, runtime: true,
    description: 'Whether a registration carrying a TRUSTED software ' +
                 'statement is accepted where POST /oauth2/register is ' +
                 'otherwise closed — in product mode with ' +
                 'oauth2.openRegistration off. That is what RFC 7591 section ' +
                 '3 offers statements for: the operator decided who may ' +
                 'register by deciding whose statements to trust. While it ' +
                 'is on, `registration_endpoint` stays in both discovery ' +
                 'documents, and a client registered this way must present ' +
                 'a trusted statement from the SAME issuer with every RFC ' +
                 '7592 update, so that it cannot PUT away the metadata the ' +
                 'statement fixed. Off, a closed endpoint refuses every ' +
                 'registration and the statement only supplies metadata ' +
                 'where registration is open anyway.' },

  { key: 'oauth2.softwareStatementRequired', group: 'OAuth 2.0 / OIDC',
    label: 'Require a software statement on every registration',
    env: 'STS_OAUTH2_SOFTWARE_STATEMENT_REQUIRED', type: 'bool', dflt: false,
    runtime: true,
    description: 'Whether POST /oauth2/register and RFC 7592 updates refuse a ' +
                 'registration that carries no software_statement, with ' +
                 'invalid_software_statement. OFF by default, because RFC ' +
                 '7591 section 2.3 makes a statement optional and every ' +
                 'client under test registers without one. Combine with ' +
                 'oauth2.openRegistration on and ' +
                 'oauth2.softwareStatementRequireTrustedIssuer off to accept ' +
                 'any statement while still demanding one.' },

  { key: 'oauth2.softwareStatementLifetimeS', group: 'OAuth 2.0 / OIDC',
    label: 'Issued software statement lifetime (s)',
    env: 'STS_OAUTH2_SOFTWARE_STATEMENT_LIFETIME_S', type: 'int',
    dflt: 31536000, min: 0, max: 315360000, runtime: true,
    description: 'How long a software statement this realm ISSUES is valid ' +
                 '— its `exp`, in seconds after it is issued — unless the ' +
                 'issue request names a lifetime of its own. A year by ' +
                 'default, because a statement ships with a release of the ' +
                 'software rather than being fetched per registration. ZERO ' +
                 'issues a statement with no `exp` at all, which RFC 7591 ' +
                 'permits. Changing this does not move a statement already ' +
                 'issued; its `exp` is inside its signature.' },

  { key: 'oauth2.registeredSecretLifetimeS', group: 'OAuth 2.0 / OIDC',
    label: 'Dynamically registered secret lifetime (s)',
    env: 'STS_OAUTH2_REGISTERED_SECRET_LIFETIME_S', type: 'int', dflt: 0,
    min: 0, max: 31536000, runtime: true,
    description: 'The `client_secret_expires_at` RFC 7591 section 3.2.1 ' +
                 'publishes for a client registered at POST ' +
                 '/oauth2/register, as seconds after registration. ZERO, the ' +
                 'default, is that section\'s own "never", which is what ' +
                 'this service always said. It is stamped when the client ' +
                 'registers and is not moved by a later change.' },

  { key: 'oauth2.registeredClientIdPrefix', group: 'OAuth 2.0 / OIDC',
    label: 'Dynamically registered client_id prefix',
    env: 'STS_OAUTH2_REGISTERED_CLIENT_ID_PREFIX', type: 'string',
    dflt: 'sts-client-', runtime: true,
    description: 'What a client_id minted by POST /oauth2/register starts ' +
                 'with, before its random part. RFC 7591 leaves the shape to ' +
                 'the server; a prefix is how an operator tells a ' +
                 'dynamically registered client from one created by hand in ' +
                 'a list.' },

  { key: 'oauth2.registeredClientIdBytes', group: 'OAuth 2.0 / OIDC',
    label: 'Dynamically registered client_id random bytes',
    env: 'STS_OAUTH2_REGISTERED_CLIENT_ID_BYTES', type: 'int', dflt: 8,
    min: 4, max: 64, runtime: true,
    description: 'How many random bytes follow the prefix in a registered ' +
                 'client_id, base64url-encoded. A client_id is not a secret, ' +
                 'so this is about collisions and not about guessing.' },

  { key: 'oauth2.registeredSecretBytes', group: 'OAuth 2.0 / OIDC',
    label: 'Dynamically registered secret random bytes',
    env: 'STS_OAUTH2_REGISTERED_SECRET_BYTES', type: 'int', dflt: 24,
    min: 16, max: 128, runtime: true,
    description: 'How many random bytes make a registered client\'s ' +
                 '`client_secret` and its RFC 7592 ' +
                 '`registration_access_token`. Both ARE secrets, which is ' +
                 'why the floor is 16 bytes (128 bits).' },

  { key: 'oauth2.authorizationCodeTtlS', group: 'OAuth 2.0 / OIDC',
    label: 'Authorization code lifetime (s)',
    env: 'STS_OAUTH2_AUTHORIZATION_CODE_TTL_S', type: 'int', dflt: 300,
    min: 30, max: 3600, runtime: true,
    description: 'How long an authorization code may wait to be redeemed. ' +
                 'RFC 6749 section 4.1.2 recommends at most ten minutes. It ' +
                 'is ALSO what RFC 9700 mode\'s transaction memory is ' +
                 'measured from — a PKCE challenge or nonce is remembered ' +
                 'for twice this — so the two cannot drift apart. A code ' +
                 'already issued keeps the expiry it was minted with.' },

  { key: 'oauth2.maxPendingTransactions', group: 'OAuth 2.0 / OIDC',
    label: 'RFC 9700: remembered transactions (per realm)',
    env: 'STS_OAUTH2_MAX_PENDING_TRANSACTIONS', type: 'int', dflt: 500,
    min: 50, max: 1000000, runtime: true,
    description: 'How many authorization transactions RFC 9700 mode ' +
                 'remembers to refuse a reused PKCE challenge or nonce. Past ' +
                 'it the oldest is forgotten, and a forgotten one is a reuse ' +
                 'check NOT made rather than a false refusal — which is the ' +
                 'safe direction for this cache, because what it protects ' +
                 'against is a client bug and not a captured credential.' },

  { key: 'oauth2.maxRefreshTokenFamilies', group: 'OAuth 2.0 / OIDC',
    label: 'RFC 9700: remembered refresh tokens (per realm)',
    env: 'STS_OAUTH2_MAX_REFRESH_TOKEN_FAMILIES', type: 'int', dflt: 2000,
    min: 100, max: 1000000, runtime: true,
    description: 'How many refresh tokens RFC 9700 mode tracks for rotation ' +
                 'and replay detection. When it is full, EXPIRED ones are ' +
                 'forgotten first, then ROTATED ones (already revoked, so a ' +
                 'replay of one is still refused — what is lost is the ' +
                 'whole-family revocation that replay would trigger), and ' +
                 'only then the oldest live one, with a warning. A live one ' +
                 'forgotten still works; its next rotation starts a new ' +
                 'family. Raise it for a deployment with more concurrently ' +
                 'live refresh tokens than this.' },

  { key: 'oauth2.signedMetadataAlgorithm', group: 'OAuth 2.0 / OIDC',
    label: 'Algorithm signed_metadata is signed with',
    env: 'STS_OAUTH2_SIGNED_METADATA_ALGORITHM', type: 'enum',
    enumValues: ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512',
                 'ES256', 'ES384', 'ES512', 'ES256K', 'EdDSA'],
    dflt: 'RS256', runtime: true,
    description: 'The JWS algorithm of the `signed_metadata` member of the ' +
                 'RFC 8414 document, the OpenID Provider Configuration and ' +
                 'the OID4VCI issuer metadata. Every value is one this realm ' +
                 'holds a key for, and every key is in /oauth2/jwks under ' +
                 'its own kid. The post-quantum algorithms are deliberately ' +
                 'not offered: discovery is the most-fetched endpoint here ' +
                 'and is signed on the request thread.' },

  certificateHeaderSetting('oauth2.accessTokenCertificateHeader',
    'OAuth 2.0 / OIDC', 'STS_OAUTH2_ACCESS_TOKEN_CERTIFICATE_HEADER',
    'Access token certificate header',
    'Whether an ACCESS TOKEN names the certificate chain of the key that ' +
    'signed it — every grant, the management API\'s tokens included. An ' +
    'access token rides in an Authorization header, so `x5c` here is ' +
    'several kilobytes per request past every proxy on the way.'),

  certificateHeaderSetting('oauth2.idTokenCertificateHeader',
    'OAuth 2.0 / OIDC', 'STS_OAUTH2_ID_TOKEN_CERTIFICATE_HEADER',
    'ID Token certificate header',
    'Whether an ID TOKEN names the certificate chain of the key that signed ' +
    'it, in RS256 and in whatever id_token_signed_response_alg a client ' +
    'registered — the post-quantum keys included, once certified.'),

  certificateHeaderSetting('oauth2.refreshTokenCertificateHeader',
    'OAuth 2.0 / OIDC', 'STS_OAUTH2_REFRESH_TOKEN_CERTIFICATE_HEADER',
    'Refresh token certificate header',
    'Whether the signed JWT INSIDE a refresh token names the certificate ' +
    'chain of the key that signed it. The JWE around it gets nothing, and ' +
    'only this service ever opens one, so this changes the size of the ' +
    'token a client stores and nothing a client can read.'),

  certificateHeaderSetting('oauth2.userinfoCertificateHeader',
    'OAuth 2.0 / OIDC', 'STS_OAUTH2_USERINFO_CERTIFICATE_HEADER',
    'Signed UserInfo certificate header',
    'Whether a SIGNED USERINFO RESPONSE (userinfo_signed_response_alg) names ' +
    'the certificate chain of the key that signed it.'),

  certificateHeaderSetting('oauth2.introspectionCertificateHeader',
    'OAuth 2.0 / OIDC', 'STS_OAUTH2_INTROSPECTION_CERTIFICATE_HEADER',
    'JWT introspection response certificate header',
    'Whether an RFC 9701 JWT INTROSPECTION RESPONSE names the certificate ' +
    'chain of the key that signed it, in RS256 and in whatever ' +
    'introspection_signed_response_alg a resource server registered. The JWE ' +
    'around an encrypted one gets nothing; the header is on the JWS inside.'),

  certificateHeaderSetting('oauth2.signedMetadataCertificateHeader',
    'OAuth 2.0 / OIDC', 'STS_OAUTH2_SIGNED_METADATA_CERTIFICATE_HEADER',
    'signed_metadata certificate header',
    'Whether the `signed_metadata` of the RFC 8414 document and the OpenID ' +
    'Provider Configuration names the certificate chain of the key that ' +
    'signed it. The OID4VCI issuer metadata has a setting of its own.'),

  { key: 'oauth2.signedMetadataCacheS', group: 'OAuth 2.0 / OIDC',
    label: 'signed_metadata cache (s)',
    env: 'STS_OAUTH2_SIGNED_METADATA_CACHE_S', type: 'int', dflt: 60,
    min: 0, max: 1800, runtime: true,
    description: 'How long one signature over an unchanged metadata document ' +
                 'is served before it is signed again. ZERO signs per ' +
                 'request. The ceiling is half the signature\'s own hour, so ' +
                 'a caller is never handed one about to expire.' },

  { key: 'oauth2.maxSignedMetadataEntries', group: 'OAuth 2.0 / OIDC',
    label: 'signed_metadata cache entries',
    env: 'STS_OAUTH2_MAX_SIGNED_METADATA_ENTRIES', type: 'int', dflt: 64,
    min: 1, max: 10000, runtime: true,
    description: 'How many distinct signed metadata documents are cached. ' +
                 'The key includes the base URL a request arrived on, which ' +
                 'comes off the Host header, so it has to be bounded.' },

  { key: 'oauth2.basicAuthRealm', group: 'OAuth 2.0 / OIDC',
    label: 'Token endpoint Basic realm',
    env: 'STS_OAUTH2_BASIC_AUTH_REALM', type: 'string', dflt: 'sts',
    runtime: true,
    description: 'The `realm` in the `WWW-Authenticate: Basic` challenge the ' +
                 'token endpoint answers a failed client_secret_basic with ' +
                 '(RFC 7617 section 2). A browser shows it in its credential ' +
                 'prompt, which is why a deployment names itself here.' },

  { key: 'oauth2.maxAuthorizationServerProfiles', group: 'OAuth 2.0 / OIDC',
    label: 'Named authorization servers (per realm)',
    env: 'STS_OAUTH2_MAX_AUTHORIZATION_SERVER_PROFILES', type: 'int', dflt: 200,
    min: 1, max: 100000, runtime: true,
    description: 'How many path-selected authorization server profiles are ' +
                 'RECORDED. A name past it is still served with the defaults ' +
                 'and simply not recorded, because the name comes off a URL ' +
                 'path and a load generator must not take the feature away ' +
                 'from the names that matter.' },

  { key: 'oauth2.maxRequestedClaims', group: 'OAuth 2.0 / OIDC',
    label: 'Claims one claims request may name',
    env: 'STS_OAUTH2_MAX_REQUESTED_CLAIMS', type: 'int', dflt: 64,
    min: 1, max: 4096, runtime: true,
    description: 'The most claims one OpenID Connect Core section 5.5 claims ' +
                 'request may name, across its members. The request rides ' +
                 'inside the access token, so this also bounds the token.' },

  // ---------------------------------------------------------------------
  // THE CERTIFICATE AUTHORITY (2026-09-10). Four rows, and every one of them
  // is a DEFAULT for a form rather than a policy: `/admin/pki` takes each as a
  // field, and what is stored on a hierarchy is what was chosen when it was
  // built. A change here therefore reaches the NEXT build and never a
  // certificate that exists — which is the same rule /admin/claims follows
  // about tokens already issued, and for the same reason: a certificate is a
  // signed document and no setting can reach inside one.
  // ---------------------------------------------------------------------
  { key: 'pki.crlLifetimeMinutes', group: 'PKI',
    label: 'How long a CRL claims to be fresh',
    env: 'PKI_CRL_LIFETIME_MINUTES', type: 'int', dflt: 60,
    min: 1, max: 10080, runtime: true,
    description: 'The gap between `thisUpdate` and `nextUpdate` on every CRL ' +
                 'this service publishes, and the `nextUpdate` on every OCSP ' +
                 'answer.\n\n**SHORT ON PURPOSE.** The interesting thing to ' +
                 'do with a revocation list here is revoke something and ' +
                 'watch a client notice — and a client that cached a ' +
                 'twenty-four hour list will not notice for twenty-four ' +
                 'hours. An hour is long enough to be realistic and short ' +
                 'enough to be testable; raise it to find out what your ' +
                 'stack does with a stale list.' },
  { key: 'pki.httpPort', group: 'PKI',
    label: 'Plain-HTTP revocation listener port',
    env: 'PKI_HTTP_PORT', type: 'port', dflt: 8082, runtime: false,
    restartReason: 'the listener is bound when the process starts',
    description: 'A second HTTP listener, PLAIN rather than TLS, that ' +
                 'answers the revocation endpoints under `/pki/` and refuses ' +
                 'every other path. Every certificate this service issues ' +
                 'names it for its CRL, its OCSP responder and its issuer\'s ' +
                 'certificate.\n\n**WHY PLAIN.** RFC 5280 section 8 says a ' +
                 'CA SHOULD NOT put an https URI in an extension — a client ' +
                 'that checks revocation before trusting a connection cannot ' +
                 'fetch the answer over the connection it is checking — and ' +
                 'RFC 5019 section 5 says an OCSP responder MUST support ' +
                 'plain HTTP. Nothing it serves needs the transport: a CRL and ' +
                 'an OCSP response are signed, and a CA certificate is used ' +
                 'only if it chains to an anchor the client already holds.' +
                 '\n\n0 binds nothing, and the addresses then name the main ' +
                 'port in its own scheme instead.' },
  { key: 'pki.distributionBaseUrl', group: 'PKI',
    label: 'Base URL published in CRL and OCSP addresses',
    env: 'PKI_DISTRIBUTION_BASE_URL', type: 'string', dflt: '',
    runtime: true,
    description: 'The base that goes INSIDE certificates, in their ' +
                 'cRLDistributionPoints and authorityInfoAccess ' +
                 'extensions — `http://pki.example.com`, with no path.\n\n' +
                 '**IT CANNOT BE DERIVED FROM A REQUEST AND THAT IS WHY IT IS ' +
                 'A SETTING.** A certificate is minted at startup, before any ' +
                 'request exists, and it is a durable document — an address ' +
                 'in it must not depend on which Host header happened to be ' +
                 'on the request that triggered the issue. Empty means ' +
                 '`http://`, the first of `tls.hostnames`, and ' +
                 '`pki.distributionPort` (or `pki.httpPort`) — or, where ' +
                 '`pki.httpPort` is 0, the main port in its own scheme.\n\n' +
                 '**A CONTAINER IS THE CASE THAT GETS THIS WRONG.** The ' +
                 'listener inside it is on 8082 and the host publishes it ' +
                 'somewhere else, and nothing inside the container can see ' +
                 'the host side of that mapping. Every compose file in this ' +
                 'repository therefore passes the published port as ' +
                 '`PKI_DISTRIBUTION_PORT`, and a stack reached by a ' +
                 'container name passes a whole base URL here.' },
  { key: 'pki.distributionPort', group: 'PKI',
    label: 'Port published in HTTP CRL and OCSP addresses',
    env: 'PKI_DISTRIBUTION_PORT', type: 'port', dflt: 0, runtime: true,
    description: 'The port in the CRL, OCSP and caIssuers addresses built ' +
                 'when `pki.distributionBaseUrl` is empty. 0 (the default) ' +
                 'means the port the listener those addresses name is bound ' +
                 'to — `pki.httpPort`, or `global.port` where that is 0 — ' +
                 'which is the wrong answer exactly when the service is ' +
                 'reached through a port mapping, since a certificate is read ' +
                 'from OUTSIDE it. A change reaches certificates issued ' +
                 'afterwards and never one that exists.' },
  { key: 'pki.distributionLdapHost', group: 'PKI',
    label: 'Host published in ldap:// CRL addresses',
    env: 'PKI_DISTRIBUTION_LDAP_HOST', type: 'string', dflt: '',
    runtime: true,
    description: 'The host in the `ldap://` CRL distribution point; the ' +
                 'port is `pki.distributionLdapPort`. Empty means the first ' +
                 'of `tls.hostnames`, for `pki.distributionBaseUrl`\'s ' +
                 'reason.\n\n**THERE IS NO `ldaps://` ADDRESS, AND THERE WAS ' +
                 'ONE UNTIL 2026-09-13.** RFC 5280 section 8 says a CA SHOULD ' +
                 'NOT put an ldaps URI in an extension, and RFC 4516 defines ' +
                 'only the `ldap` scheme. The LDAPS listener is unaffected; ' +
                 'what it serves is simply not an address a certificate ' +
                 'names.' },
  { key: 'pki.distributionLdapPort', group: 'PKI',
    label: 'Port published in ldap:// CRL addresses',
    env: 'PKI_DISTRIBUTION_LDAP_PORT', type: 'port', dflt: 0, runtime: true,
    description: 'The port in the `ldap://` CRL distribution point. 0 (the ' +
                 'default) means `ldap.port`. Set it to the host port when ' +
                 'the directory is published through a port mapping, for ' +
                 '`pki.distributionPort`\'s reason.' },
  { key: 'pki.publishCrlToDirectory', group: 'PKI',
    label: 'Publish every CRL into the embedded directory',
    env: 'PKI_PUBLISH_CRL_TO_DIRECTORY', type: 'bool', dflt: true,
    runtime: true,
    description: 'Write each authority\'s CRL into the embedded directory as ' +
                 '`certificateRevocationList;binary` on a ' +
                 '`cRLDistributionPoint` entry under `ou=crl`, so the ' +
                 '`ldap://` address in every certificate ' +
                 'this service issues actually resolves (RFC 4523 section ' +
                 '4).\n\nOff, that address is still WRITTEN into ' +
                 'certificates and fetches nothing — which is a legitimate ' +
                 'thing to test a client against and is why it is a switch ' +
                 'rather than a consequence of the directory being there.' },
  { key: 'pki.autoBuild', group: 'PKI',
    label: 'Build the certificate authority at startup',
    env: 'PKI_AUTO_BUILD', type: 'bool', dflt: true,
    runtime: false,
    restartReason: 'The hierarchy is built before the listener binds, ' +
                   'because a key pair can only be issued by an authority ' +
                   'that exists when the key is made — and the keys are made ' +
                   'at startup. Turning it off while the service runs would ' +
                   'leave the authority that has already certified them ' +
                   'standing.',
    description: 'ON by default, and turning it off is how this service ' +
                 'behaves as it did before 2026-09-11.\n\nWith it on, a Root ' +
                 'CA is built for the SERVICE at startup, an Intermediate CA ' +
                 'for the process and one per trust realm, and an Issuing CA ' +
                 'under each for every use case — and every key pair this ' +
                 'service generates is certified under it. The key ' +
                 'generation itself is untouched: the same RSA key, the same ' +
                 'six curve keys, the same eleven post-quantum keys made ' +
                 'lazily, in the same order and at the same moment. What is ' +
                 'added happens afterwards and only ever adds a ' +
                 'certificate.\n\nWith it off, nothing is built until ' +
                 'somebody presses Build on /admin/pki, and this service\'s ' +
                 'own keys carry the self-signed certificates they were born ' +
                 'with.' },
  { key: 'pki.keyAlgorithm', group: 'PKI',
    label: 'Default CA key algorithm',
    env: 'STS_PKI_KEY_ALGORITHM', type: 'string', dflt: 'rsa-2048',
    runtime: true,
    description: 'Which key algorithm a new certificate authority is built ' +
                 'with when the form names none: rsa-2048, rsa-3072, ' +
                 'rsa-4096, ec-p256, ec-p384, ec-p521 or ed25519. RSA 2048 ' +
                 'is the default because the LEAF this hierarchy exists to ' +
                 'issue signs a client assertion that somebody else\'s OAuth ' +
                 'library has to verify, and RS256 is the one algorithm ' +
                 'every such library has. The list is read from ' +
                 'common/vendored/key_material.js — the module that ' +
                 'generates the key — so a value it does not know is refused ' +
                 'at the build with the list beside it.' },
  { key: 'pki.signatureAlgorithm', group: 'PKI',
    label: 'Default CA signature algorithm',
    env: 'STS_PKI_SIGNATURE_ALGORITHM', type: 'string', dflt: '',
    runtime: true,
    description: 'Which signature algorithm the tiers sign each other with. ' +
                 'EMPTY means "the right one for the key algorithm", which ' +
                 'is what almost every deployment wants and is why it is the ' +
                 'default: an EC key\'s digest is decided by its CURVE (a ' +
                 'P-384 key wants SHA-384), and a fixed value here would ' +
                 'hand a P-521 key SHA-256 — legal, verifying, and nobody\'s ' +
                 'intention. Set it to name one of sha256-rsa, sha384-rsa, ' +
                 'sha512-rsa, sha256-rsapss, sha384-rsapss, sha512-rsapss, ' +
                 'sha256-ecdsa, sha384-ecdsa, sha512-ecdsa or ed25519 — and ' +
                 'the two deliberately weak ones, sha1-rsa and sha1-ecdsa, ' +
                 'which are here because "does my stack refuse a SHA-1 ' +
                 'certificate?" is a question a debugger should be able to ' +
                 'ask.' },
  { key: 'pki.organisation', group: 'PKI',
    label: 'Default organisation name (O=)',
    env: 'STS_PKI_ORGANISATION', type: 'string', dflt: 'sts',
    runtime: true,
    description: 'The O= every tier of a new hierarchy carries, and the O= ' +
                 'of every leaf issued from it. It is also what the tiers ' +
                 'are NAMED after when the form gives no common names — "<O> ' +
                 'Root CA (<realm>)" and so on — so that a certificate read ' +
                 'out of context says which service and which trust realm it ' +
                 'belongs to.' },
  // ---------------------------------------------------------------------
  // SELF-SERVICE (2026-09-12). A person may issue THEMSELVES an RFC 7523
  // signing key pair from `/portal/signing-key`, which is the same act
  // `/admin/pki` performs for an operator and writes the same seven
  // attributes.
  //
  // **IT HAS A SWITCH BECAUSE EVERY OTHER SELF-SERVICE MECHANISM IN THE
  // PORTAL HAS ONE** — `totp.enabled` and `backupCodes.enabled` are the two
  // beside it — and for their reason rather than by analogy: what a person may
  // hand themselves is a deployment's decision, and an operator who wants keys
  // issued only by an administrator has nowhere else to say so.
  //
  // **ON BY DEFAULT**, which is what every self-service door here defaults to.
  // The key it issues can only assert about the person who holds it
  // (`common/person_assertions.js`), so what it hands out is a credential for
  // an account that person is already signed in to — the same bar the password
  // form and the security-key enrolment clear.
  //
  // **TURNING IT OFF DOES NOT TAKE ANYBODY'S KEY PAIR AWAY**, which is
  // `totp.enabled`'s contract word for word: a key already on an entry goes on
  // verifying, because a setting that silently stopped honouring credentials
  // it had issued would be an off switch that does something other than what
  // it says. What it stops is new ones, from the portal only — `/admin/pki`
  // and `POST /admin-api/pki/issue` are an operator's door and are unaffected.
  // ---------------------------------------------------------------------
  { key: 'pki.personSelfService', group: 'PKI',
    label: 'Let a person issue their own signing key pair',
    env: 'STS_PKI_PERSON_SELF_SERVICE', type: 'bool', dflt: true,
    runtime: true,
    description: 'Whether the Signing keys page in the user portal offers ' +
                 'to issue an RFC 7523 or an RFC 7522 key pair to the ' +
                 'person looking at it — one switch for both profiles. ' +
                 'The key may only assert about its own holder, so it is a ' +
                 'credential for an account they are already signed in to — ' +
                 'the same bar the password form and the security-key ' +
                 'enrolment clear. **Turning it off does NOT take away a key ' +
                 'pair somebody already holds**: one on an entry goes on ' +
                 'verifying, exactly as `totp.enabled` leaves an enrolled ' +
                 'authenticator working. It stops new ones FROM THE PORTAL ' +
                 'only — an operator issuing from /admin/pki or POST ' +
                 '/admin-api/pki/issue is unaffected, which is the point of ' +
                 'having the switch.' },

  { key: 'pki.leafLifetimeDays', group: 'PKI',
    label: 'Default lifetime of an issued key pair (days)',
    env: 'STS_PKI_LEAF_LIFETIME_DAYS', type: 'int', dflt: 365,
    min: 1, max: 3650, runtime: true,
    description: 'How long a signing certificate issued to an application is ' +
                 'good for when the form names no lifetime. It is CLAMPED to ' +
                 'the Issuing CA\'s own expiry rather than refused where it ' +
                 'would overshoot: the ordinary cause is a five-year Issuing ' +
                 'CA in its fifth year, and an operator who asked for a year ' +
                 'should get eleven months rather than an error about ' +
                 'arithmetic. The tiers\' own lifetimes come from the ' +
                 'certificate profiles in common/vendored/x509.js — twenty ' +
                 'years, ten and five — and are overridable on the form and ' +
                 'by the three pki.*LifetimeYears rows below.' },

  // ---------------------------------------------------------------------
  // THE CA TIERS' LIFETIMES, FOR THE BUILDS NOBODY TYPED A NUMBER INTO
  // (2026-09-12).
  //
  // The console's Build form has always taken years per tier. The startup
  // auto-build, a realm created at runtime and the repair `certify()` makes
  // on a stale branch take no form, so until these rows they could only ever
  // build the vendored profiles' twenty, ten and five. ZERO means exactly that
  // — the profile's own number — so an unedited service builds what it did,
  // and a change to what an Intermediate CA IS still reaches this service from
  // the parent project's table rather than being frozen in a default here.
  // ---------------------------------------------------------------------
  { key: 'pki.rootLifetimeYears', group: 'PKI',
    label: 'Root CA lifetime (years, 0 = the profile\'s)',
    env: 'STS_PKI_ROOT_LIFETIME_YEARS', type: 'int', dflt: 0,
    min: 0, max: 100, runtime: true,
    description: 'How long a Root CA this service builds is good for when ' +
                 'the build names no lifetime. Zero is the `root-ca` ' +
                 'profile\'s own twenty years. Applies to the NEXT build; a ' +
                 'Root already held keeps the expiry it was issued with.' },

  { key: 'pki.intermediateLifetimeYears', group: 'PKI',
    label: 'Intermediate CA lifetime (years, 0 = the profile\'s)',
    env: 'STS_PKI_INTERMEDIATE_LIFETIME_YEARS', type: 'int', dflt: 0,
    min: 0, max: 100, runtime: true,
    description: 'How long an Intermediate CA is good for when the build ' +
                 'names no lifetime — at startup, for a realm created at ' +
                 'runtime, and for a branch rebuilt under a replaced Root. ' +
                 'Zero is the `intermediate-ca` profile\'s ten years. ' +
                 'Clamped to the Root\'s own expiry.' },

  { key: 'pki.issuingLifetimeYears', group: 'PKI',
    label: 'Issuing CA lifetime (years, 0 = the profile\'s)',
    env: 'STS_PKI_ISSUING_LIFETIME_YEARS', type: 'int', dflt: 0,
    min: 0, max: 100, runtime: true,
    description: 'How long each Issuing CA is good for when the build names ' +
                 'no lifetime. Zero is the `issuing-ca` profile\'s five ' +
                 'years. Clamped to its Intermediate\'s expiry.' },

  { key: 'pki.maxStoredObjects', group: 'PKI',
    label: 'Certificates and keys the workbench store keeps, per realm',
    env: 'STS_PKI_MAX_STORED_OBJECTS', type: 'int', dflt: 200,
    min: 1, max: 100000, runtime: true,
    description: 'How many objects the Certificate & Key Configuration pane ' +
                 'on /admin/pki may keep in one realm. **A FULL STORE ' +
                 'REFUSES THE NEXT ONE**; it used to discard the oldest, and ' +
                 'the oldest carries a private key somebody chose to keep. ' +
                 'Delete what is no longer wanted, or raise this.' },

  { key: 'pki.personSelfServicePerIdentity', group: 'PKI',
    label: 'Self-issued key pairs one person may ask for per window',
    env: 'STS_PKI_PERSON_SELF_SERVICE_PER_IDENTITY', type: 'int', dflt: 5,
    min: 1, max: 1000, runtime: true,
    description: 'How many times one person may press Generate on ' +
                 '/portal/signing-key in a security.rateLimitWindowS window. ' +
                 'Generating a key pair is hundreds of milliseconds of CPU ' +
                 'on the thread every protocol here is answered on, which is ' +
                 'why it is limited at all.' },

  { key: 'pki.personSelfServicePerAddress', group: 'PKI',
    label: 'Self-issued key pairs one address may ask for per window',
    env: 'STS_PKI_PERSON_SELF_SERVICE_PER_ADDRESS', type: 'int', dflt: 5,
    min: 1, max: 10000, runtime: true,
    description: 'The same limit counted per client ADDRESS across everybody ' +
                 'behind it. It is its own row because a deployment whose ' +
                 'people reach it through one NAT or proxy shares one ' +
                 'address, and five for an entire office is a different ' +
                 'number from five for one person.' },

  // A PERSON'S TLS CLIENT CERTIFICATES (2026-09-13), issued on
  // /portal/signing-key — `common/tls_client_certificates.js`. The cap counts
  // VALID certificates only, so revoking an old device's makes room for the
  // new one's.
  { key: 'pki.personTlsClientCertificateMax', group: 'PKI',
    label: 'TLS client certificates one person may hold',
    env: 'STS_PKI_PERSON_TLS_CLIENT_CERTIFICATE_MAX', type: 'int', dflt: 5,
    min: 1, max: 100, runtime: true,
    description: 'How many still-valid TLS client certificates one person may ' +
                 'issue themselves on the user portal — one per browser or ' +
                 'device. A revoked or expired certificate does not count. ' +
                 'Past it the portal refuses (STS-PKI-0170) rather than ' +
                 'revoking an older certificate somebody may still be using. ' +
                 'Issuing one is also held to pki.personSelfService and to ' +
                 'the two self-service rate limits above.' },
  // THE SAME CAP FOR AN APPLICATION (2026-09-13), which holds one to
  // authenticate at the token endpoint under RFC 8705 section 2.1 and to bind
  // its tokens under section 3. A setting of its own because the reason for
  // several differs: a person has several devices, an application has several
  // instances or a rotation in progress.
  { key: 'pki.applicationTlsClientCertificateMax', group: 'PKI',
    label: 'TLS client certificates one application may hold',
    env: 'STS_PKI_APPLICATION_TLS_CLIENT_CERTIFICATE_MAX', type: 'int',
    dflt: 5, min: 1, max: 100, runtime: true,
    description: 'How many still-valid TLS client certificates an ' +
                 'administrator may issue one application from its ' +
                 'Credentials section on /admin/applications or ' +
                 'POST /admin-api/applications/issue-tls-client-certificate ' +
                 '— one per instance, or two while a certificate is being ' +
                 'rotated. A revoked or expired certificate does not count. ' +
                 'Past it the issue is refused (STS-PKI-0180) rather than ' +
                 'revoking a certificate a running instance may still be ' +
                 'presenting.' },

  // ---------------------------------------------------------------------
  // REVOCATION, CONSULTED (2026-09-12). Seven rows for
  // `common/revocation_status.js`: the policy, the one rule hard-fail does NOT
  // include by default, and the five bounds on the one outbound request it
  // makes. All runtime, all per realm — the doors read them per certificate —
  // and `auto` is how the POLICY defaults by mode through
  // `mode.refusesUnknownRevocationStatus()` rather than through a literal.
  // ---------------------------------------------------------------------
  { key: 'pki.revocationCheck', group: 'PKI',
    label: 'Revocation check on a presented certificate',
    env: 'STS_PKI_REVOCATION_CHECK', type: 'enum',
    enumValues: ['auto', 'off', 'soft-fail', 'hard-fail'],
    dflt: 'auto', runtime: true,
    description: 'Whether a certificate PRESENTED to this service — on 8443 ' +
                 'and 9443, on the main port (XACML, SCIM, RFC 8705 client ' +
                 'authentication), at the SPIRE Server API or in an ' +
                 'assertion\'s x5c — is checked for revocation. One this ' +
                 'service issued is looked up in its own register; one from ' +
                 'another authority against the CRL it names. `off` consults ' +
                 'nothing. `soft-fail` refuses a REVOKED certificate and ' +
                 'accepts one whose status could not be established. ' +
                 '`hard-fail` refuses that too, which is what stops an ' +
                 'attacker who can block the CRL fetch turning revoked into ' +
                 'accepted. **`auto` is hard-fail in product mode and ' +
                 'soft-fail in development.**' },
  { key: 'pki.revocationRequireDistributionPoint', group: 'PKI',
    label: 'Hard-fail refuses a certificate whose issuer names no CRL',
    env: 'STS_PKI_REVOCATION_REQUIRE_DISTRIBUTION_POINT', type: 'bool',
    dflt: false, runtime: true,
    description: 'Under hard-fail, a foreign certificate naming no http or ' +
                 'https cRLDistributionPoints is ACCEPTED by default, ' +
                 'because there is no fetch an attacker could block — the ' +
                 'issuer simply publishes no list — and refusing it would ' +
                 'make every private CA without one unusable. Turn this on ' +
                 'to refuse it too.' },
  { key: 'pki.revocationFetchTimeoutMs', group: 'PKI',
    label: 'CRL fetch timeout (milliseconds)',
    env: 'STS_PKI_REVOCATION_FETCH_TIMEOUT_MS', type: 'int', dflt: 3000,
    min: 100, max: 60000, runtime: true,
    description: 'How long a fetch of a foreign CRL may take. A request ' +
                 'carrying that certificate waits on it the first time, so ' +
                 'it is short.' },
  { key: 'pki.revocationMaxCrlBytes', group: 'PKI',
    label: 'Largest CRL fetched (bytes)',
    env: 'STS_PKI_REVOCATION_MAX_CRL_BYTES', type: 'int', dflt: 1048576,
    min: 1024, max: 67108864, runtime: true,
    description: 'A distribution point that answers with more than this is ' +
                 'refused as unreachable rather than read into memory.' },
  { key: 'pki.revocationCrlCacheEntries', group: 'PKI',
    label: 'Foreign CRLs kept in memory',
    env: 'STS_PKI_REVOCATION_CRL_CACHE_ENTRIES', type: 'int', dflt: 256,
    min: 1, max: 100000, runtime: true,
    description: 'How many verified foreign CRLs are cached, and how many ' +
                 'failures are remembered. The oldest goes first.' },
  { key: 'pki.revocationCrlMaxAgeS', group: 'PKI',
    label: 'Longest a fetched CRL is believed (seconds)',
    env: 'STS_PKI_REVOCATION_CRL_MAX_AGE_S', type: 'int', dflt: 3600,
    min: 1, max: 604800, runtime: true,
    description: 'A cached CRL is used until its own nextUpdate or this long ' +
                 'after it was fetched, whichever comes first. The list says ' +
                 'how long it is fresh; this is how much of that is ' +
                 'believed.' },
  { key: 'pki.revocationFailureRetryS', group: 'PKI',
    label: 'Wait before retrying a CRL that failed (seconds)',
    env: 'STS_PKI_REVOCATION_FAILURE_RETRY_S', type: 'int', dflt: 60,
    min: 0, max: 86400, runtime: true,
    description: 'An unreachable or unusable CRL is remembered for this ' +
                 'long, so a dead server costs one timeout per window rather ' +
                 'than one per request. Zero retries on every request.' },
  // FIVE MORE ROWS THE SAME DAY, for OCSP and for delta and indirect CRLs. Each
  // is a decision the code cannot make for a deployment: the ORDER of the two
  // mechanisms, how long a response with no nextUpdate is believed, whether a
  // responder that ignores the nonce is still believed, how far out a clock may
  // be, and which certificates may sign a list on another authority's behalf.
  // The fetch bounds above (timeout, size, cache, failure memory) are SHARED by
  // both mechanisms rather than doubled: they bound an outbound request, and
  // an OCSP request is one more of those.
  { key: 'pki.revocationOcsp', group: 'PKI',
    label: 'OCSP for a foreign certificate',
    env: 'STS_PKI_REVOCATION_OCSP', type: 'enum',
    enumValues: ['first', 'after-crl', 'off'],
    dflt: 'first', runtime: true,
    description: 'Whether the OCSP responder a foreign certificate names in ' +
                 'its Authority Information Access is asked (RFC 6960). ' +
                 '`first` asks it before the CRL and falls back to the CRL ' +
                 'when it cannot be reached or its answer cannot be trusted; ' +
                 '`after-crl` asks it only when the CRL gave no answer; ' +
                 '`off` uses the CRL alone. A signed `unknown` from the ' +
                 'responder is never upgraded to good by a CRL, while a CRL ' +
                 'that REVOKES still wins.' },
  { key: 'pki.revocationOcspMaxAgeS', group: 'PKI',
    label: 'Longest an OCSP response is believed (seconds)',
    env: 'STS_PKI_REVOCATION_OCSP_MAX_AGE_S', type: 'int', dflt: 3600,
    min: 1, max: 604800, runtime: true,
    description: 'A response carrying no nextUpdate is fresh for this long ' +
                 'after its thisUpdate, and no response is cached for longer ' +
                 'than this whatever its nextUpdate says.' },
  { key: 'pki.revocationOcspRequireNonce', group: 'PKI',
    label: 'Refuse an OCSP response that does not echo the nonce',
    env: 'STS_PKI_REVOCATION_OCSP_REQUIRE_NONCE', type: 'bool',
    dflt: false, runtime: true,
    description: 'Every request carries a nonce, and a response that echoes ' +
                 'a DIFFERENT one is always refused. A response that echoes ' +
                 'none is believed by default, because the pre-produced ' +
                 'responses RFC 5019 describes — which most large responders ' +
                 'serve — cannot carry one; its freshness window is then the ' +
                 'replay bound. Turn this on for a responder known to sign ' +
                 'per request.' },
  { key: 'pki.revocationClockSkewS', group: 'PKI',
    label: 'Clock skew allowed on CRL and OCSP freshness (seconds)',
    env: 'STS_PKI_REVOCATION_CLOCK_SKEW_S', type: 'int', dflt: 300,
    min: 0, max: 3600, runtime: true,
    description: 'How far a CRL\'s or an OCSP response\'s nextUpdate may be ' +
                 'in the past, and an OCSP thisUpdate in the future, before ' +
                 'it is refused. Zero is legal and means the clocks agree ' +
                 'exactly.' },
  { key: 'pki.revocationCrlIssuersFile', group: 'PKI',
    label: 'Certificates that may sign an indirect CRL',
    env: 'STS_PKI_REVOCATION_CRL_ISSUERS_FILE', type: 'string', dflt: '',
    runtime: true,
    description: 'A PEM file of certificates for the CRL issuers a ' +
                 'certificate\'s cRLDistributionPoints may name in ' +
                 'cRLIssuer. Such a signer is also looked for in the ' +
                 'presented chain and among this service\'s own authorities, ' +
                 'and in every case it must be allowed to sign CRLs and ' +
                 'chain to an authority the presented chain itself passes ' +
                 'through. Read again when the file changes. Empty means ' +
                 'none beyond those two places — and the caIssuers address ' +
                 'the CRL itself names.' },
  // THREE MORE FOR LDAP, which is a second outbound protocol and argued as one
  // in `common/revocation_status.js`'s header. The scheme is a policy rather
  // than a boolean because `off` is a real answer — a deployment that never
  // wants this service opening an LDAP session — and plain `ldap` is the
  // weaker of the two it may open.
  { key: 'pki.revocationLdap', group: 'PKI',
    label: 'LDAP revocation addresses',
    env: 'STS_PKI_REVOCATION_LDAP', type: 'enum',
    enumValues: ['ldaps', 'ldaps-and-ldap', 'off'],
    dflt: 'ldaps', runtime: true,
    description: 'Whether an ldap: or ldaps: CRL distribution point or ' +
                 'caIssuers address is dialled. `ldaps` (the default) opens ' +
                 'LDAP over TLS only, with the directory\'s certificate ' +
                 'VERIFIED against node\'s CA store and ' +
                 'pki.revocationLdapCaFile; `ldaps-and-ldap` also opens ' +
                 'plain LDAP; `off` dials neither. An address not dialled ' +
                 'counts as no address at all.' },
  { key: 'pki.revocationLdapCaFile', group: 'PKI',
    label: 'CA certificates for ldaps revocation directories',
    env: 'STS_PKI_REVOCATION_LDAP_CA_FILE', type: 'string', dflt: '',
    runtime: true,
    description: 'A PEM file of CA certificates an ldaps directory\'s ' +
                 'certificate may chain to, BESIDE node\'s own CA store. A ' +
                 'directory certified by a private CA is refused until its ' +
                 'CA is here.' },
  { key: 'pki.revocationLdapDirectory', group: 'PKI',
    label: 'Directory for CRL names relative to their issuer',
    env: 'STS_PKI_REVOCATION_LDAP_DIRECTORY', type: 'string', dflt: '',
    runtime: true,
    description: 'An ldaps:// (or, with pki.revocationLdap allowing it, ' +
                 'ldap://) address — scheme, host and port only — that a ' +
                 'distribution point named RELATIVE TO ITS CRL ISSUER is ' +
                 'looked up in. Such a name is an unambiguous DN and says ' +
                 'nothing about which directory holds it, so without this it ' +
                 'is not dialled.' },
  { key: 'pki.enrollmentMaxCertificatesPerEntry', group: 'PKI',
    label: 'Enrolled certificates one entry may hold',
    env: 'STS_PKI_ENROLLMENT_MAX_CERTIFICATES_PER_ENTRY', type: 'int',
    dflt: 20, min: 1, max: 500, runtime: true,
    description: 'How many certificates issued over ACME, EST or SCEP one ' +
                 'person or application entry may carry at once. An expired ' +
                 'certificate is dropped from the entry before this is ' +
                 'counted; past it a request is refused (STS-ENROLL-0040) ' +
                 'rather than an older certificate being forgotten, because ' +
                 'a certificate somebody is still using must not disappear ' +
                 'from the entry that says who it belongs to.' },

  // -------------------------------------------------------------------------
  // CERTIFICATE ENROLLMENT: ACME (RFC 8555), EST (RFC 7030), SCEP (RFC 8894),
  // 2026-09-13. Three groups, one per protocol, each homed on its own console
  // page, and every row realm-settable because each realm issues from Issuing
  // CAs of its own. What is common to the three — who may have a certificate
  // for whom, what goes in it, where it is kept — is common/cert_enrollment.js
  // and has no setting that would let one protocol answer it differently.
  // -------------------------------------------------------------------------
  { key: 'acme.enabled', group: 'ACME', label: 'Run the ACME server',
    env: 'STS_ACME_ENABLED', type: 'bool', dflt: true, runtime: true,
    description: 'Off makes every /enroll/acme endpoint answer that ACME is ' +
                 'turned off in this realm (HTTP 503, an RFC 7807 ' +
                 'serverInternal problem naming the setting). Accounts, ' +
                 'orders and certificates already issued are kept.' },
  { key: 'acme.allowedProfiles', group: 'ACME',
    label: 'Certificate profiles ACME may issue',
    env: 'STS_ACME_ALLOWED_PROFILES', type: 'csv',
    dflt: 'tls-server,tls-client,tls-server-client,digital-signature,' +
          'key-encipherment,code-signing,email,timestamping,smartcard-logon',
    runtime: true,
    description: 'The /admin/pki profiles an order may name in its `profile` ' +
                 'member (draft-ietf-acme-profiles) and the directory ' +
                 'advertises. Root CA, Intermediate CA, Issuing CA, OCSP ' +
                 'Responder and Kerberos KDC are never issued over an ' +
                 'enrollment protocol whatever this says: their holder could ' +
                 'issue certificates, answer OCSP for this authority or ' +
                 'impersonate the KDC.' },
  { key: 'acme.defaultProfile', group: 'ACME',
    label: 'Profile when an order names none',
    env: 'STS_ACME_DEFAULT_PROFILE', type: 'enum',
    enumValues: ['tls-server', 'tls-client', 'tls-server-client',
                 'digital-signature', 'key-encipherment', 'code-signing',
                 'email', 'timestamping', 'smartcard-logon'],
    dflt: 'tls-client', runtime: true,
    description: 'Most ACME clients never name a profile. It must also be in ' +
                 'acme.allowedProfiles, or an order naming none is refused.' },
  { key: 'acme.certificateLifetimeDays', group: 'ACME',
    label: 'Certificate lifetime (days)',
    env: 'STS_ACME_CERTIFICATE_LIFETIME_DAYS', type: 'int', dflt: 90,
    min: 1, max: 825, runtime: true,
    description: 'The validity of a certificate issued at finalize, ' +
                 'shortened to the ACME Issuing CA\'s own notAfter.' },
  { key: 'acme.maxRequestBytes', group: 'ACME',
    label: 'Largest request body (bytes)',
    env: 'STS_ACME_MAX_REQUEST_BYTES', type: 'int', dflt: 65536,
    min: 1024, max: 1048576, runtime: true,
    description: 'A flattened JWS larger than this is refused (HTTP 413) ' +
                 'before it is parsed. A finalize carrying a post-quantum CSR ' +
                 'is the largest legitimate request; SLH-DSA\'s signatures ' +
                 'are tens of kilobytes.' },
  { key: 'acme.attemptsPerIdentity', group: 'ACME',
    label: 'Failed requests per account a window',
    env: 'STS_ACME_ATTEMPTS_PER_IDENTITY', type: 'int', dflt: 30,
    min: 1, max: 100000, runtime: true,
    description: 'Refused requests one account (or EAB key id) may make in ' +
                 'one web-security window before ACME answers rateLimited.' },
  { key: 'acme.attemptsPerAddress', group: 'ACME',
    label: 'Failed requests per address a window',
    env: 'STS_ACME_ATTEMPTS_PER_ADDRESS', type: 'int', dflt: 120,
    min: 1, max: 100000, runtime: true,
    description: 'Refused requests one client address may make in one ' +
                 'web-security window before ACME answers rateLimited.' },
  { key: 'acme.nonceLifetimeS', group: 'ACME',
    label: 'Replay nonce lifetime (seconds)',
    env: 'STS_ACME_NONCE_LIFETIME_S', type: 'int', dflt: 300,
    min: 5, max: 86400, runtime: true,
    description: 'How long a Replay-Nonce may wait before it is presented. ' +
                 'Each is accepted once.' },
  { key: 'acme.orderLifetimeS', group: 'ACME',
    label: 'Order lifetime (seconds)',
    env: 'STS_ACME_ORDER_LIFETIME_S', type: 'int', dflt: 86400,
    min: 60, max: 2592000, runtime: true,
    description: 'How long an order stays pending or ready before it expires ' +
                 'with its authorizations.' },
  { key: 'acme.eabLifetimeS', group: 'ACME',
    label: 'External account binding key lifetime (seconds)',
    env: 'STS_ACME_EAB_LIFETIME_S', type: 'int', dflt: 604800,
    min: 60, max: 31536000, runtime: true,
    description: 'How long an EAB key issued on the console, through ' +
                 '/admin-api or on the user portal may wait before it binds ' +
                 'an account. Each binds one account and no other.' },

  { key: 'est.enabled', group: 'EST', label: 'Run the EST server',
    env: 'STS_EST_ENABLED', type: 'bool', dflt: true, runtime: true,
    description: 'Off makes every /.well-known/est endpoint answer 503 in ' +
                 'this realm. Certificates already issued are kept.' },
  { key: 'est.allowedProfiles', group: 'EST',
    label: 'Certificate profiles EST may issue',
    env: 'STS_EST_ALLOWED_PROFILES', type: 'csv',
    dflt: 'tls-server,tls-client,tls-server-client,digital-signature,' +
          'key-encipherment,code-signing,email,timestamping,smartcard-logon',
    runtime: true,
    description: 'The /admin/pki profiles an EST label may name ' +
                 '(/.well-known/est/<profile>/…). The five CA, OCSP and KDC ' +
                 'profiles are never issued over an enrollment protocol.' },
  { key: 'est.defaultProfile', group: 'EST',
    label: 'Profile at the unlabelled path',
    env: 'STS_EST_DEFAULT_PROFILE', type: 'enum',
    enumValues: ['tls-server', 'tls-client', 'tls-server-client',
                 'digital-signature', 'key-encipherment', 'code-signing',
                 'email', 'timestamping', 'smartcard-logon'],
    dflt: 'tls-client', runtime: true,
    description: 'What /.well-known/est/simpleenroll issues, with no label.' },
  { key: 'est.certificateLifetimeDays', group: 'EST',
    label: 'Certificate lifetime (days)',
    env: 'STS_EST_CERTIFICATE_LIFETIME_DAYS', type: 'int', dflt: 365,
    min: 1, max: 825, runtime: true,
    description: 'The validity of an EST certificate, shortened to the EST ' +
                 'Issuing CA\'s own notAfter.' },
  { key: 'est.maxRequestBytes', group: 'EST',
    label: 'Largest request body (bytes)',
    env: 'STS_EST_MAX_REQUEST_BYTES', type: 'int', dflt: 65536,
    min: 1024, max: 1048576, runtime: true,
    description: 'A PKCS#10 body larger than this is refused (HTTP 413) ' +
                 'before it is decoded.' },
  { key: 'est.attemptsPerIdentity', group: 'EST',
    label: 'Failed requests per identity a window',
    env: 'STS_EST_ATTEMPTS_PER_IDENTITY', type: 'int', dflt: 10,
    min: 1, max: 100000, runtime: true,
    description: 'Refused authentications or enrollments one username, ' +
                 'client_id or certificate may make in one web-security ' +
                 'window before EST answers 429.' },
  { key: 'est.attemptsPerAddress', group: 'EST',
    label: 'Failed requests per address a window',
    env: 'STS_EST_ATTEMPTS_PER_ADDRESS', type: 'int', dflt: 60,
    min: 1, max: 100000, runtime: true,
    description: 'Refused requests one client address may make in one ' +
                 'web-security window before EST answers 429.' },
  { key: 'est.basicAuthentication', group: 'EST',
    label: 'Accept HTTP Basic',
    env: 'STS_EST_BASIC_AUTHENTICATION', type: 'bool', dflt: true,
    runtime: true,
    description: 'A person\'s directory password or an application\'s ' +
                 'client_id and client_secret (RFC 7030 section 3.2.3). ' +
                 'Whether the password is CHECKED is global.mode\'s answer, ' +
                 'as it is everywhere in this service.' },
  { key: 'est.certificateAuthentication', group: 'EST',
    label: 'Accept a TLS client certificate',
    env: 'STS_EST_CERTIFICATE_AUTHENTICATION', type: 'bool', dflt: true,
    runtime: true,
    description: 'A client certificate THIS REALM issued, verified to its ' +
                 'Intermediate and mapped to its entry by the ' +
                 'urn:sts:person: or urn:sts:application: name in it ' +
                 '(RFC 7030 section 3.3.2). Required for simplereenroll ' +
                 'with no Basic credential.' },
  { key: 'est.serverKeyGeneration', group: 'EST',
    label: 'Offer /serverkeygen',
    env: 'STS_EST_SERVER_KEY_GENERATION', type: 'bool', dflt: true,
    runtime: true,
    description: 'Whether this service generates the key pair (RFC 7030 ' +
                 'section 4.4) — the one enrollment path in which it holds a ' +
                 'private key, which it then keeps, sealed, on the entry the ' +
                 'certificate names.' },

  { key: 'scep.enabled', group: 'SCEP', label: 'Run the SCEP server',
    env: 'STS_SCEP_ENABLED', type: 'bool', dflt: true, runtime: true,
    description: 'Off makes every /enroll/scep request answer 503 in this ' +
                 'realm. Certificates already issued are kept.' },
  { key: 'scep.allowedProfiles', group: 'SCEP',
    label: 'Certificate profiles SCEP may issue',
    env: 'STS_SCEP_ALLOWED_PROFILES', type: 'csv',
    dflt: 'tls-server,tls-client,tls-server-client,digital-signature,' +
          'key-encipherment,code-signing,email,timestamping,smartcard-logon',
    runtime: true,
    description: 'The /admin/pki profiles a challenge password may be issued ' +
                 'for. The five CA, OCSP and KDC profiles are never issued ' +
                 'over an enrollment protocol.' },
  { key: 'scep.defaultProfile', group: 'SCEP',
    label: 'Profile a new challenge defaults to',
    env: 'STS_SCEP_DEFAULT_PROFILE', type: 'enum',
    enumValues: ['tls-server', 'tls-client', 'tls-server-client',
                 'digital-signature', 'key-encipherment', 'code-signing',
                 'email', 'timestamping', 'smartcard-logon'],
    dflt: 'tls-client', runtime: true,
    description: 'The profile preselected when a challenge password is made.' },
  { key: 'scep.certificateLifetimeDays', group: 'SCEP',
    label: 'Certificate lifetime (days)',
    env: 'STS_SCEP_CERTIFICATE_LIFETIME_DAYS', type: 'int', dflt: 365,
    min: 1, max: 825, runtime: true,
    description: 'The validity of a SCEP certificate, shortened to the SCEP ' +
                 'Issuing CA\'s own notAfter.' },
  { key: 'scep.maxRequestBytes', group: 'SCEP',
    label: 'Largest PKIOperation message (bytes)',
    env: 'STS_SCEP_MAX_REQUEST_BYTES', type: 'int', dflt: 262144,
    min: 1024, max: 4194304, runtime: true,
    description: 'A pkiMessage larger than this — POSTed, or base64 in the ' +
                 'GET binding\'s message parameter — is refused before it is ' +
                 'decoded.' },
  { key: 'scep.attemptsPerIdentity', group: 'SCEP',
    label: 'Failed requests per challenge a window',
    env: 'STS_SCEP_ATTEMPTS_PER_IDENTITY', type: 'int', dflt: 10,
    min: 1, max: 100000, runtime: true,
    description: 'Refused PKIOperations one challenge id may cause in one ' +
                 'web-security window before SCEP answers 429.' },
  { key: 'scep.attemptsPerAddress', group: 'SCEP',
    label: 'Failed requests per address a window',
    env: 'STS_SCEP_ATTEMPTS_PER_ADDRESS', type: 'int', dflt: 60,
    min: 1, max: 100000, runtime: true,
    description: 'Refused requests one client address may make in one ' +
                 'web-security window before SCEP answers 429.' },
  { key: 'scep.challengeLifetimeS', group: 'SCEP',
    label: 'Challenge password lifetime (seconds)',
    env: 'STS_SCEP_CHALLENGE_LIFETIME_S', type: 'int', dflt: 3600,
    min: 60, max: 2592000, runtime: true,
    description: 'How long a challenge password may wait before it is ' +
                 'redeemed. Each is redeemed once.' },
  { key: 'scep.raKeyAlgorithm', group: 'SCEP',
    label: 'RA certificate key algorithm',
    env: 'STS_SCEP_RA_KEY_ALGORITHM', type: 'enum',
    enumValues: ['rsa-2048', 'rsa-3072', 'rsa-4096'], dflt: 'rsa-2048',
    runtime: true,
    description: 'SCEP encrypts the request to the RA with RSA key transport ' +
                 '(RFC 8894 section 3.1), so the RA certificate is RSA ' +
                 'whatever the SCEP Issuing CA is. Changing it re-issues the ' +
                 'RA certificate on its next use.' },

  // ---------------------------------------------------------------------
  // HOW LONG WHAT THIS SERVICE ISSUES IS GOOD FOR, and how far out a clock may
  // be before it stops believing its own tokens.
  //
  // Four rows, added 2026-08-24, replacing three module-level `const`s in
  // `oauth-oidc/oauth2.js` (`ACCESS_TOKEN_TTL`, `REFRESH_TOKEN_TTL` and the
  // ID Token's reuse of the first). Everything about the shape of them is the
  // runtime rule at the top of this file read literally: a lifetime captured
  // in a `const` at require time is the one thing /admin/config cannot change,
  // and this is the setting a person most wants to change without restarting —
  // "make it expire in a minute so I can watch my client refresh" is the whole
  // reason somebody points a client at a mock.
  //
  // WHY THREE ROWS RATHER THAN ONE. The access token and the ID Token shared a
  // constant and are not the same thing: the access token is presented to a
  // resource server and the ID Token is consumed once, at sign-in, by the
  // client — and a client that treats the ID Token as a session is exactly the
  // mistake a mock should be able to produce on demand. The refresh token is
  // the third because it is the long-lived half of the grant, and the
  // interesting states are the ones where the three DISAGREE.
  //
  // THE GRANULARITY IS THIRTY SECONDS (`step: 30`), which is a decision about
  // what these settings are FOR rather than a formatting rule. They exist to be
  // set to something short and watched; below half a minute a token expires
  // between the response being written and the client reading it, and the
  // client author debugs their own code for an hour. `min` is one step for the
  // same reason. `max` is thirty days on all three lifetimes because that is
  // what `REFRESH_TOKEN_TTL` was before these rows existed — a ceiling that
  // made the OLD default unreachable would be a setting that cannot be put
  // back the way it was.
  //
  // THE REFRESH DEFAULT IS A BEHAVIOUR CHANGE AND IS THE ONE THING HERE TO
  // KNOW BEFORE UPGRADING: it was thirty days and is now twenty-four hours. A
  // client holding a refresh token across two days of a test run will be
  // refused where it was not, and the refusal is an ordinary `invalid_grant`
  // from the refresh grant. Set `oauth2.refreshTokenTtlS` to 2592000 to have
  // exactly the old behaviour back. It is stated in the description below as
  // well as here, because the person who meets it is reading the console
  // rather than this file.
  { key: 'oauth2.accessTokenTtlS', group: 'OAuth 2.0 / OIDC per-client',
    label: 'Access token lifetime (s)',
    env: 'STS_OAUTH2_ACCESS_TOKEN_TTL_S', type: 'int', dflt: 3600,
    min: 30, max: 2592000, step: 30, runtime: true,
    description: 'How long an access token is good for: its `exp` is this ' +
                 'many seconds after it was signed, and it is the ' +
                 '`expires_in` of every token response that carries one. One ' +
                 'hour by default. Read PER TOKEN, so a change here applies ' +
                 'to the next one issued and to nothing already in a ' +
                 'client\'s hands — a token is a signed statement about its ' +
                 'own expiry and cannot be shortened after the fact. Must be ' +
                 'a whole number of THIRTY-SECOND units: these settings ' +
                 'exist to be set short and watched, and a lifetime under ' +
                 'half a minute expires between the response being written ' +
                 'and the client reading it. Set it low to exercise a ' +
                 'client\'s refresh path on demand; the tokens page reports ' +
                 'what has already expired.' },

  { key: 'oauth2.idTokenTtlS', group: 'OAuth 2.0 / OIDC per-client',
    label: 'ID Token lifetime (s)',
    env: 'STS_OAUTH2_ID_TOKEN_TTL_S', type: 'int', dflt: 3600,
    min: 30, max: 2592000, step: 30, runtime: true,
    description: 'How long an ID Token is good for. One hour by default, and ' +
                 'SEPARATE from the access token\'s even though the two ' +
                 'shared one constant until 2026-08-24 — an ID Token is ' +
                 'consumed once, at sign-in, by the client itself, and a ' +
                 'client that keeps presenting it as though it were a ' +
                 'session is the defect this row makes reproducible: give ' +
                 'the two different lifetimes and watch which one the client ' +
                 'actually notices. Thirty-second granularity, like the ' +
                 'other two.' },

  { key: 'oauth2.refreshTokenTtlS', group: 'OAuth 2.0 / OIDC per-client',
    label: 'Refresh token lifetime (s)',
    env: 'STS_OAUTH2_REFRESH_TOKEN_TTL_S', type: 'int', dflt: 86400,
    min: 30, max: 2592000, step: 30, runtime: true,
    description: 'The ABSOLUTE lifetime of a refresh token — the `exp` on ' +
                 'the token itself, enforced in both modes by the refresh ' +
                 'grant. TWENTY-FOUR HOURS by default, and that IS A CHANGE: ' +
                 'it was thirty days, so a client that held one across a ' +
                 'long test run now meets an invalid_grant where it did not. ' +
                 'Set this to 2592000 for exactly the old behaviour. It is ' +
                 'not the same setting as oauth2.refreshIdleSeconds, which ' +
                 'is RFC 9700 mode\'s INACTIVITY timeout on a refresh CHAIN ' +
                 'and is measured from the last redemption rather than from ' +
                 'issuance: this one is a wall a chain cannot be refreshed ' +
                 'past however busy it is.' },

  // The fourth is not a lifetime, and it is deliberately NOT folded into
  // `oauth2.clientAssertionSkewS` beside it: that one is how far out a CLIENT'S
  // assertion may be (RFC 7523, a credential somebody else's clock stamped),
  // and this is how far out THIS SERVICE'S OWN clock may be when it reads back
  // a token it signed. They move for different reasons — one is about the
  // client's machine and one is about this one — and a deployment that wants a
  // strict assertion check and a forgiving expiry reading, or the reverse, has
  // to be able to say so.
  { key: 'oauth2.clockSkewS', group: 'OAuth 2.0 / OIDC',
    label: 'Token clock skew (s)',
    env: 'STS_OAUTH2_CLOCK_SKEW_S', type: 'int', dflt: 30,
    min: 0, max: 300, step: 30, runtime: true,
    description: 'The allowance applied to `exp` and `nbf` EVERYWHERE this ' +
                 'service reads back a token it issued: introspection, ' +
                 'UserInfo, the refresh grant, token exchange, the ' +
                 'DPoP-bound access token check, and the expiry every ' +
                 'console screen reports. Thirty seconds by default, capped ' +
                 'at 300 — five minutes is the allowance Kerberos uses (see ' +
                 'krb5.clockSkew) and a window wider than that stops being a ' +
                 'tolerance and starts being a lifetime extension nobody ' +
                 'asked for. 0 means no allowance at all, which is the ' +
                 'strict reading and is useful for showing a client exactly ' +
                 'when a token dies. It never changes what is PUT in a token ' +
                 '— only what this service believes when it reads one back.' },

  { key: 'oauth2.redirectUris', group: 'OAuth 2.0 / OIDC',
    label: 'Registered redirect URIs',
    env: 'STS_OAUTH2_REDIRECT_URIS', type: 'csv', dflt: '', runtime: true,
    description: 'The redirect URIs RFC 9700 mode compares an authorization ' +
                 'request against, by EXACT STRING MATCH — for every client ' +
                 'that did not register its own redirect_uris at ' +
                 'POST /oauth2/register, which is every client this service ' +
                 'has only ever seen at the authorization endpoint. Read ' +
                 'only when oauth2.rfc9700 is on, and EMPTY by default, so ' +
                 'turning the mode on with nothing here refuses every ' +
                 'authorization request — the refusal names this setting. ' +
                 'There is no pattern syntax and there must not be one: a ' +
                 'matcher that supports wildcards and is configured not to ' +
                 'use them is one mistake away from an open redirector.' },

  { key: 'oauth2.loopbackPortWildcard', group: 'OAuth 2.0 / OIDC',
    label: 'Loopback port wildcard',
    env: 'STS_OAUTH2_LOOPBACK_PORT_WILDCARD', type: 'bool', dflt: true,
    runtime: true,
    description: 'In RFC 9700 mode, allow a registered LOOPBACK redirect URI ' +
                 '(127.0.0.1, [::1] or localhost) to match on any port — RFC ' +
                 '8252 section 7.3, because a native application cannot ' +
                 'reserve one. Everything else about the URI must still ' +
                 'match exactly, and the host must be the same literal. ON ' +
                 'by default because RFC 9700 says an authorization server ' +
                 'MUST allow it; turning it OFF makes this server ' +
                 'deliberately non-compliant, which is how a native-app ' +
                 'client is shown what happens when it meets a server that ' +
                 'got this wrong.' },

  // ---------------------------------------------------------------------
  // OPENID CONNECT FRONT-CHANNEL LOGOUT 1.0, WHICH IS ONE SETTING OVER THREE
  // BEHAVIOURS, AND THAT IS WHY IT IS ONE ROW.
  //
  // The claim, the advertisement and the fan-out are the same feature seen from
  // three sides — an ID Token carrying `sid`, a discovery document saying
  // `frontchannel_logout_supported`, and a sign-out page loading each relying
  // party's `frontchannel_logout_uri` in an iframe. Three switches would let
  // somebody advertise a capability whose claim is turned off, which is a
  // discovery document that lies.
  //
  // ON by default, and that is a CAPABILITY rather than a refusal: nothing is
  // rejected by it and no existing call fails. What it does change is what
  // every OIDC client receives — an ID Token issued on a browser session grows
  // a `sid` — which reverses a decision this service documented at length
  // (admin_stats.js's note that no token here carries a session identifier).
  // The reasoning behind that note is kept and is why this is switchable: a
  // claim is added because a specification needs it, and Front-Channel Logout
  // section 3 is that specification. Turning this OFF restores the tokens and
  // the metadata this service issued before the feature existed, exactly.
  // ---------------------------------------------------------------------
  // REFRESH-TOKEN ENCRYPTION (2026-09-12). Every refresh token is a signed JWT
  // encrypted to its own realm (`oauth-oidc/refresh_token_crypto.js`). The two
  // ALGORITHM rows are read on every issuance and may change at any time: a
  // token already issued was sealed under what was in force then, and the
  // realm holds a key of every kind, so a change never strands one. The two
  // KEY rows reach key sets made after them and never keys that exist.
  //
  // The enum lists are `common/crypto.js`'s JWE_ALGS and JWE_ENCS written out,
  // because this file requires nothing from this repository;
  // `tests/refresh_token_encryption.js` fails if the two ever differ.
  // ---------------------------------------------------------------------
  { key: 'oauth2.refreshTokenEncryptionAlg', group: 'OAuth 2.0 / OIDC',
    label: 'Refresh token encryption: key management (alg)',
    env: 'STS_OAUTH2_REFRESH_TOKEN_ENCRYPTION_ALG', type: 'enum',
    enumValues: ['RSA-OAEP-256', 'RSA-OAEP', 'ECDH-ES', 'ECDH-ES+A128KW',
                 'ECDH-ES+A192KW', 'ECDH-ES+A256KW', 'A128KW', 'A192KW',
                 'A256KW',
                 'A128GCMKW', 'A192GCMKW', 'A256GCMKW', 'PBES2-HS256+A128KW',
                 'PBES2-HS384+A192KW', 'PBES2-HS512+A256KW', 'dir'],
    dflt: 'RSA-OAEP-256', runtime: true,
    description: 'The JWE key management algorithm every refresh token is ' +
                 'encrypted under. A refresh token is a signed JWT sealed to ' +
                 'THIS realm\'s own keys and is opaque to its client, so the ' +
                 'choice is invisible outside this service. The RSA-OAEP ' +
                 'algorithms use the realm\'s RSA key, the ECDH-ES ones its ' +
                 'EC key, and the rest a secret of the realm\'s own. ' +
                 'Changing it affects tokens issued from then on; tokens ' +
                 'already issued still open, because the realm holds a key ' +
                 'of every kind. RSA1_5 is not offered.' },

  { key: 'oauth2.refreshTokenEncryptionEnc', group: 'OAuth 2.0 / OIDC',
    label: 'Refresh token encryption: content (enc)',
    env: 'STS_OAUTH2_REFRESH_TOKEN_ENCRYPTION_ENC', type: 'enum',
    enumValues: ['A128GCM', 'A192GCM', 'A256GCM', 'A128CBC-HS256',
                 'A192CBC-HS384', 'A256CBC-HS512'],
    dflt: 'A256GCM', runtime: true,
    description: 'The JWE content encryption algorithm for refresh tokens. ' +
                 'Like the alg above, it is read on every issuance and a ' +
                 'change strands no token already issued.' },

  { key: 'oauth2.refreshTokenEncryptionKeyBits', group: 'OAuth 2.0 / OIDC',
    label: 'Refresh token encryption: RSA key size (bits)',
    env: 'STS_OAUTH2_REFRESH_TOKEN_ENCRYPTION_KEY_BITS', type: 'int',
    dflt: 2048,
    min: 2048, max: 4096, step: 1024, runtime: true,
    description: 'The modulus of the RSA key each realm encrypts refresh ' +
                 'tokens to under RSA-OAEP. Each realm has its own, made ' +
                 'with its key set, so a change reaches keys made AFTER it ' +
                 'and never a key that exists — rotating the realm\'s keys ' +
                 'is how to apply it.' },

  { key: 'oauth2.refreshTokenEncryptionCurve', group: 'OAuth 2.0 / OIDC',
    label: 'Refresh token encryption: EC curve',
    env: 'STS_OAUTH2_REFRESH_TOKEN_ENCRYPTION_CURVE', type: 'enum',
    enumValues: ['P-256', 'P-384', 'P-521'], dflt: 'P-256', runtime: true,
    description: 'The curve of the EC key each realm encrypts refresh tokens ' +
                 'to under ECDH-ES. Like the key size, a change reaches keys ' +
                 'made after it.' },

  // RFC 9101, THE JWT-SECURED AUTHORIZATION REQUEST (2026-09-13). Five rows,
  // and `oauth-oidc/request_object.js` argues each. Every one is runtime and
  // may be carried by a realm: the three about a REQUEST are read per request,
  // and the two about the ENCRYPTION KEY are read when a realm's key set is
  // made, exactly as the refresh-token key's two above are.
  { key: 'oauth2.requireSignedRequestObject', group: 'OAuth 2.0 / OIDC',
    label: 'Require a signed request object (RFC 9101)',
    env: 'STS_OAUTH2_REQUIRE_SIGNED_REQUEST_OBJECT', type: 'bool',
    dflt: false, runtime: true,
    description: 'RFC 9101 section 10.5\'s require_signed_request_object, ' +
                 'for every client of this authorization server: an ' +
                 'authorization request that is not a JWT-secured one — no ' +
                 '`request` and no `request_uri` — is refused with ' +
                 'invalid_request, and so is a request object signed with ' +
                 '`none`. It is published in the discovery documents. OFF ' +
                 'by default, because every client that sends plain query ' +
                 'parameters would be refused. A client can ask the same of ' +
                 'itself with oauthRequireSignedRequestObject on its entry ' +
                 '(require_signed_request_object at registration), and a ' +
                 'named authorization server\'s profile can publish it.' },

  { key: 'oauth2.authorizationDetailsMaxEntries', group: 'OAuth 2.0 / OIDC',
    label: 'Most authorization_details entries in one request (RFC 9396)',
    env: 'STS_OAUTH2_AUTHORIZATION_DETAILS_MAX_ENTRIES', type: 'int',
    dflt: 20, min: 1, max: 200, runtime: true,
    description: 'How many objects one RFC 9396 authorization_details array ' +
                 'may carry, at the authorization, token and pushed ' +
                 'authorization request endpoints. A longer array is ' +
                 'refused invalid_authorization_details rather than checked ' +
                 'against every type\'s JSON Schema, because the array comes ' +
                 'from whoever sent the request (section 11.2).' },

  { key: 'oauth2.requestUriTimeoutMs', group: 'OAuth 2.0 / OIDC',
    label: 'request_uri fetch timeout (ms)',
    env: 'STS_OAUTH2_REQUEST_URI_TIMEOUT_MS', type: 'int', dflt: 5000,
    min: 250, max: 60000, runtime: true,
    description: 'How long the authorization endpoint waits for a ' +
                 'registered request_uri (RFC 9101 section 5.2) to answer ' +
                 'before refusing the request with invalid_request_uri. A ' +
                 'browser is waiting on it, which is why it is short; section ' +
                 '10.4 asks for a timeout by name.' },

  { key: 'oauth2.requestUriMaxBytes', group: 'OAuth 2.0 / OIDC',
    label: 'request_uri largest response (bytes)',
    env: 'STS_OAUTH2_REQUEST_URI_MAX_BYTES', type: 'int', dflt: 65536,
    min: 1024, max: 1048576, runtime: true,
    description: 'The most a registered request_uri may answer with. A ' +
                 'request object is a few kilobytes; a response past this is ' +
                 'refused with invalid_request_uri and the connection closed, ' +
                 'so a request_uri cannot be used to make this service read ' +
                 'an unbounded body.' },

  { key: 'oauth2.requireRequestObjectType', group: 'OAuth 2.0 / OIDC',
    label: 'Require typ oauth-authz-req+jwt on a request object',
    env: 'STS_OAUTH2_REQUIRE_REQUEST_OBJECT_TYPE', type: 'bool', dflt: false,
    runtime: true,
    description: 'RFC 9101 section 10.8: require every request object to be ' +
                 'explicitly typed `oauth-authz-req+jwt`. OFF by default, ' +
                 'because the section itself says requiring it "will break ' +
                 'most existing deployments"; with it off, an object that is ' +
                 'not typed or is typed `JWT` is accepted and one typed as ' +
                 'another kind of JWT is refused in every mode.' },

  { key: 'oauth2.requireRequestObjectIssuerAudience',
    group: 'OAuth 2.0 / OIDC',
    label: 'Require iss and aud in a request object',
    env: 'STS_OAUTH2_REQUIRE_REQUEST_OBJECT_ISSUER_AUDIENCE', type: 'bool',
    dflt: false, runtime: true,
    description: 'RFC 9101 section 4 says a signed request object SHOULD ' +
                 'contain `iss` and `aud`. ON refuses one that lacks either ' +
                 'with invalid_request_object. OFF by default; with it off, ' +
                 'each is checked where present — `iss` must be the client ' +
                 'and `aud` this authorization server.' },

  { key: 'oauth2.requestUriCacheS', group: 'OAuth 2.0 / OIDC',
    label: 'request_uri content cache (s)',
    env: 'STS_OAUTH2_REQUEST_URI_CACHE_S', type: 'int', dflt: 0,
    min: 0, max: 3600, runtime: true,
    description: 'OpenID Connect Core section 6.2: how long the content a ' +
                 'registered request_uri answered with is reused before it ' +
                 'is fetched again, keyed by the whole URI including its ' +
                 'fragment. ZERO fetches on every request. A URI whose ' +
                 'content may change should carry the base64url SHA-256 of ' +
                 'that content as its fragment; such a fragment is checked ' +
                 'against what was fetched whatever this says.' },

  { key: 'oauth2.requestObjectEncryptionKeyBits', group: 'OAuth 2.0 / OIDC',
    label: 'Request object encryption: RSA key size (bits)',
    env: 'STS_OAUTH2_REQUEST_OBJECT_ENCRYPTION_KEY_BITS', type: 'int',
    dflt: 2048,
    min: 2048, max: 4096, step: 1024, runtime: true,
    description: 'The modulus of the RSA key each realm publishes in ' +
                 '/oauth2/jwks (use: enc) for a client to encrypt a request ' +
                 'object to under RSA-OAEP (RFC 9101 section 6.1). Made with ' +
                 'the realm\'s key set, so a change reaches keys made AFTER ' +
                 'it — rotating the realm\'s keys is how to apply it.' },

  { key: 'oauth2.requestObjectEncryptionCurve', group: 'OAuth 2.0 / OIDC',
    label: 'Request object encryption: EC curve',
    env: 'STS_OAUTH2_REQUEST_OBJECT_ENCRYPTION_CURVE', type: 'enum',
    enumValues: ['P-256', 'P-384', 'P-521'], dflt: 'P-256', runtime: true,
    description: 'The curve of the EC key each realm publishes in ' +
                 '/oauth2/jwks (use: enc) for ECDH-ES request object ' +
                 'encryption. Like the key size, a change reaches keys made ' +
                 'after it.' },

  // RFC 9126 — PUSHED AUTHORIZATION REQUESTS (2026-09-13). Six rows, all
  // runtime and so all settable on a trust realm; `oauth-oidc/par.js` and the
  // PAR endpoint in `oauth-oidc/oauth2.js` read each where it is used.
  { key: 'oauth2.pushedAuthorizationRequests', group: 'OAuth 2.0 / OIDC',
    label: 'Pushed authorization requests (RFC 9126)',
    env: 'STS_OAUTH2_PUSHED_AUTHORIZATION_REQUESTS', type: 'bool', dflt: true,
    runtime: true,
    description: 'Offer the pushed authorization request endpoint, ' +
                 'POST /oauth2/par, and publish it as ' +
                 'pushed_authorization_request_endpoint in both discovery ' +
                 'documents. A client pushes the parameters of an ' +
                 'authorization request over the back channel, ' +
                 'authenticating as it would at the token endpoint, and ' +
                 'gets a one-time request_uri to send the browser with. OFF ' +
                 'removes the member and answers the endpoint 404, so a ' +
                 'client\'s fallback to a plain authorization request can be ' +
                 'exercised. A request_uri already issued stays usable until ' +
                 'it expires (RFC 9126 section 5).' },

  { key: 'oauth2.requirePushedAuthorizationRequests',
    group: 'OAuth 2.0 / OIDC',
    label: 'Require pushed authorization requests',
    env: 'STS_OAUTH2_REQUIRE_PUSHED_AUTHORIZATION_REQUESTS', type: 'bool',
    dflt: false, runtime: true,
    description: 'RFC 9126 section 4\'s global policy: the authorization ' +
                 'endpoint refuses, with invalid_request and a 400 on this ' +
                 'server, any request that does not carry a request_uri this ' +
                 'service issued at /oauth2/par. Published as ' +
                 'require_pushed_authorization_requests. OFF by default, ' +
                 'because every client sending a plain authorization request ' +
                 'would be refused. A client can ask the same of itself with ' +
                 'oauthRequirePushedAuthorizationRequests on its entry ' +
                 '(require_pushed_authorization_requests at registration), ' +
                 'and a named authorization server\'s profile can publish ' +
                 'it.' },

  { key: 'oauth2.parRequestUriLifetimeS', group: 'OAuth 2.0 / OIDC',
    label: 'Pushed request_uri lifetime (seconds)',
    env: 'STS_OAUTH2_PAR_REQUEST_URI_LIFETIME_S', type: 'int', dflt: 60,
    min: 5, max: 600, runtime: true,
    description: 'How long a request_uri issued at /oauth2/par may be ' +
                 'used at the authorization endpoint — the expires_in of the ' +
                 'push response. RFC 9126 section 2.2\'s "between 5 and 600 ' +
                 'seconds" is the range. It is the whole sign-in: the ' +
                 'request_uri is read again when the person comes back from ' +
                 'the sign-in and consent screens, and is spent when the ' +
                 'authorization response is issued, so a person slower than ' +
                 'this is refused invalid_request_uri on the way back.' },

  { key: 'oauth2.parMaxRequests', group: 'OAuth 2.0 / OIDC',
    label: 'Pushed requests held at once',
    env: 'STS_OAUTH2_PAR_MAX_REQUESTS', type: 'int', dflt: 10000,
    min: 10, max: 1000000, runtime: true,
    description: 'The most pushed authorization requests one trust realm ' +
                 'holds at once. Expired ones are swept first; A FULL STORE ' +
                 'REFUSES THE NEXT PUSH (503 temporarily_unavailable) RATHER ' +
                 'THAN FORGETTING A LIVE ONE, because a request_uri forgotten ' +
                 'while a person is signing in is a sign-in that fails for ' +
                 'nothing they did.' },

  { key: 'oauth2.parMaxBodyBytes', group: 'OAuth 2.0 / OIDC',
    label: 'Largest pushed authorization request (bytes)',
    env: 'STS_OAUTH2_PAR_MAX_BODY_BYTES', type: 'int', dflt: 65536,
    min: 1024, max: 1048576, runtime: true,
    description: 'The largest request body /oauth2/par accepts. A larger ' +
                 'one is answered 413 Payload Too Large, which RFC 9126 ' +
                 'section 2.3 names. An authorization request, a claims ' +
                 'request and a request object together are a few ' +
                 'kilobytes.' },

  { key: 'oauth2.parRequestsPerMinute', group: 'OAuth 2.0 / OIDC',
    label: 'Pushed requests per client per window',
    env: 'STS_OAUTH2_PAR_REQUESTS_PER_MINUTE', type: 'int', dflt: 600,
    min: 1, max: 100000, runtime: true,
    description: 'How many pushed authorization requests one client_id may ' +
                 'make from one address in one security.rateLimitWindowS ' +
                 'window before /oauth2/par answers 429 Too Many Requests ' +
                 '(RFC 9126 section 2.3). Every push is counted, successful ' +
                 'or not, because each one holds a row in the store; the ' +
                 'address bucket is ten times this.' },

  { key: 'oauth2.parAllowUnregisteredRedirectUris', group: 'OAuth 2.0 / OIDC',
    label: 'Pushed requests may name an unregistered redirect_uri',
    env: 'STS_OAUTH2_PAR_ALLOW_UNREGISTERED_REDIRECT_URIS', type: 'bool',
    dflt: false, runtime: true,
    description: 'RFC 9126 section 2.4: let a client that AUTHENTICATED at ' +
                 '/oauth2/par push a redirect_uri it never registered, which ' +
                 'the exact-match check of RFC 9700 and OAuth 2.1 mode would ' +
                 'otherwise refuse. Section 7.2\'s rule is kept whatever this ' +
                 'says: a public client, or one whose credential did not ' +
                 'verify, is held to its registered list, and the URI is ' +
                 'still refused for its shape. Asked again at the ' +
                 'authorization endpoint, so turning it off stops a ' +
                 'request_uri already issued from using one (section 7.4). ' +
                 'OFF by default.' },

  // RFC 9470 — STEP-UP AUTHENTICATION (2026-09-13). Two rows, both runtime and
  // so both settable on a trust realm: what THIS SERVICE'S OWN resource server
  // requires of the authentication behind an access token. A registered API's
  // requirement is on its application entry instead (`oauthStepUpAcrValues`,
  // `oauthStepUpMaxAge`); `oauth-oidc/step_up.js` argues why there are two.
  { key: 'oauth2.stepUpAcrValues', group: 'OAuth 2.0 / OIDC',
    label: 'Step-up: acr values this service\'s resource server requires',
    env: 'STS_OAUTH2_STEP_UP_ACR_VALUES', type: 'string', dflt: '',
    runtime: true,
    description: 'RFC 9470 section 3, at this service\'s own protected ' +
                 'endpoints — UserInfo, the OpenID4VCI credential, deferred ' +
                 'credential and notification endpoints, SCIM and the Shared ' +
                 'Signals stream management API, whenever they are presented ' +
                 'an access token. Space-separated acr values in order of ' +
                 'preference: a token whose acr meets none of them is ' +
                 'answered 401 with WWW-Authenticate: Bearer ' +
                 'error="insufficient_user_authentication" and these ' +
                 'acr_values, which a client repeats in a new authorization ' +
                 'request. The levels are ordered, 0 < 1 < mfa, so "1" is met ' +
                 'by an mfa token too. EMPTY requires nothing, which is the ' +
                 'default.' },

  { key: 'oauth2.stepUpMaxAgeS', group: 'OAuth 2.0 / OIDC',
    label: 'Step-up: oldest authentication this service\'s resource server ' +
           'accepts (s)',
    env: 'STS_OAUTH2_STEP_UP_MAX_AGE_S', type: 'int', dflt: -1,
    min: -1, max: 315360000, runtime: true,
    description: 'RFC 9470 section 3\'s max_age, at the same endpoints as ' +
                 'the acr values above: a token whose auth_time is more than ' +
                 'this many seconds ago, or which has none, is answered 401 ' +
                 'insufficient_user_authentication with max_age in the ' +
                 'challenge. -1 requires nothing and is the default; 0 is a ' +
                 'real requirement (an authentication this very second), ' +
                 'which is why "off" is not spelt 0.' },

  { key: 'oauth2.frontchannelLogout', group: 'OAuth 2.0 / OIDC',
    label: 'OpenID Connect Front-Channel Logout',
    env: 'STS_OAUTH2_FRONTCHANNEL_LOGOUT', type: 'bool', dflt: true,
    runtime: true,
    description: 'Advertise and perform OpenID Connect Front-Channel Logout ' +
                 '1.0. With it on: the discovery document says ' +
                 'frontchannel_logout_supported, an ID Token issued on a ' +
                 'browser sign-on session carries the `sid` claim naming ' +
                 'that session, and every sign-out — /oauth2/logout, ' +
                 '/logout, and the console\'s — renders a hidden iframe per ' +
                 'relying party that registered a frontchannel_logout_uri, ' +
                 'with iss and sid on it where the client registered ' +
                 'frontchannel_logout_session_required. Off, none of the ' +
                 'three happens and the tokens are byte-for-byte what this ' +
                 'service issued before the feature existed. A client that ' +
                 'registers no logout URI is never notified either way, and ' +
                 '/logout says so on its row rather than leaving it out.' },

  // --- The admin console ---------------------------------------------------
  //
  // FOUR SETTINGS AND THEY ARE ONE FEATURE. The console at /admin used to be
  // open, and every document here said so at length. It now asks for a session
  // from the authentication service and for one of two roles held in the
  // embedded directory.
  //
  // The roles ARE two ordinary groups under ou=groups — cn=admin-read and
  // cn=admin-write by default — rather than a store of this console's own, for
  // the one-store reason every other part of this service follows: an
  // `ldapmodify`, a SCIM PATCH, the /admin/rbac screen and the management API
  // all write membership, and two stores would each look right alone and never
  // see each other. It is also why these two are the FIRST groups in this
  // service that grant anything, and why the sentence "a group here grants
  // nothing" is now qualified everywhere it appears rather than deleted: it is
  // still true of every OTHER group, and of these two everywhere except this
  // console.
  { key: 'admin.readGroup', group: 'Admin console', label: 'Admin Read role',
    env: 'ADMIN_READ_GROUP', type: 'string', dflt: 'admin-read', runtime: true,
    // PROCESS-WIDE SINCE 2026-09-14 (#32): a realm may not carry it, because it
    // decides who administers the service — see admin-ui/admin_scope.js.
    perProcess: true,
    description: 'The cn of the directory group whose members may READ the ' +
                 'console — every page, and every ?format=json view of one. ' +
                 'It is an ordinary group under ou=groups, so an ldapmodify, ' +
                 'a SCIM PATCH and the /admin/rbac screen are three doors ' +
                 'onto the same membership. The group need not exist: while ' +
                 'NEITHER role group has a member, admin.openWhenEmpty ' +
                 'decides what happens.' },

  { key: 'admin.writeGroup', group: 'Admin console', label: 'Admin Write role',
    env: 'ADMIN_WRITE_GROUP', type: 'string', dflt: 'admin-write',
    // PROCESS-WIDE SINCE 2026-09-14 (#32): a realm may not carry it, because it
    // decides who administers the service — see admin-ui/admin_scope.js.
    perProcess: true,
    runtime: true,
    description: 'The cn of the directory group whose members may POST a ' +
                 'console form — revoke a token, add a claim, change a ' +
                 'setting, grant a role. WRITE IMPLIES READ: a member of ' +
                 'this group does not also need the read group, because a ' +
                 'role that could change a page it could not see would be a ' +
                 'trap rather than a permission.' },

  // -------------------------------------------------------------------------
  // THE MANAGEMENT API'S OWN GATE (2026-09-09), which is a different question
  // from the console's two roles above.
  //
  // `/admin-api` is a machine surface: there is no browser, no session and no
  // sign-in screen, so it is reached with an OAuth 2.0 access token. What the
  // token must carry is an AUDIENCE naming this API — so a token minted for
  // some other resource cannot be replayed at it — and a SCOPE saying what it
  // may do, which `common/roles.js` turns into the built-in ADMIN_READ and
  // ADMIN_WRITE roles that the XACML access policy asks for.
  // -------------------------------------------------------------------------
  { key: 'adminApi.authRequired', group: 'Management API',
    label: 'Require an access token on /admin-api',
    env: 'ADMIN_API_AUTH_REQUIRED', type: 'bool', dflt: true,
    // PROCESS-WIDE SINCE 2026-09-14 (#32): a realm may not carry it, because it
    // decides who administers the service — see admin-ui/admin_scope.js.
    perProcess: true,
    runtime: true,
    description: 'Every call into /admin-api must present a Bearer access ' +
                 'token this service issued, audienced to this API, carrying ' +
                 '`admin:read` for a read and `admin:write` for anything ' +
                 'that changes state. OFF restores what this surface did ' +
                 'before the token was required — open to anybody who can ' +
                 'reach the port — which is the recovery path when nobody ' +
                 'can mint a token, and is exactly as dangerous as it ' +
                 'sounds.' },

  { key: 'adminApi.clientSecret', group: 'Management API',
    label: 'The management API client\'s secret',
    env: 'ADMIN_API_CLIENT_SECRET', type: 'string', dflt: '',
    // PROCESS-WIDE SINCE 2026-09-14 (#32): a realm may not carry it, because it
    // decides who administers the service — see admin-ui/admin_scope.js.
    perProcess: true,
    secret: true,
    restartReason: 'the seeded registration is written once, at startup, so ' +
                   'a secret changed while running would be a value nothing ' +
                   'reads until the next start — and the client would go on ' +
                   'authenticating with the old one meanwhile.',
    description: 'The `client_secret` of the seeded `sts-management-api` ' +
                 'client, which is what a caller exchanges for an access ' +
                 'token. EMPTY means one is minted at every start — fine ' +
                 'while this API was open, and a BOOTSTRAP HOLE now that it ' +
                 'is not: the secret is only readable THROUGH the API it ' +
                 'unlocks, so a restart would leave nobody able to get in. ' +
                 'Set it and the client keeps that secret across restarts, ' +
                 'which is what a deployment and every test launcher need.' },

  // DERIVED SINCE 2026-09-13, and it was `dflt: ''` until then. Empty meant
  // "/admin-api under the host the request arrived on", which was correct and
  // told a reader of /admin/rbac nothing: the one setting on that page naming
  // an address drew a blank box. The default is now the base URL of the
  // management API itself — global.publicBaseUrl where that is pinned, and
  // otherwise the scheme, bound host and port this process listens on.
  //
  // WHAT A DEFAULT CANNOT DO IS SEE A REQUEST, which is why it is derived and
  // why the gate reads the source as well as the value. A literal URL taken
  // as the ONLY audience would refuse every token minted under another name
  // for the same process — `sts:8081` on the compose network, the random host
  // port the local launcher publishes — so while this row is still at its
  // default (or set empty), mgmt-api/admin_api.js accepts this value AND
  // `/admin-api` under the request's own base. Set to anything else, it pins
  // exactly that one value, as it always did.
  { key: 'adminApi.audience', group: 'Management API',
    label: 'The audience an /admin-api token must carry',
    env: 'ADMIN_API_AUDIENCE', type: 'string', derived: true,
    // PROCESS-WIDE SINCE 2026-09-14 (#32): a realm may not carry it, because it
    // decides who administers the service — see admin-ui/admin_scope.js.
    perProcess: true,
    dflt: function () {
      log.debug("Entering dflt().");
      log.debug("Leaving dflt().");
      return managementApiBaseUrl();
    },
    runtime: true,
    description: 'What the `aud` claim must name for a token to be accepted ' +
                 'here. Defaults to the base URL of the management API — ' +
                 'global.publicBaseUrl followed by /admin-api where that is ' +
                 'set, and otherwise this process\'s own scheme, host and ' +
                 'port. While it is at that default, a token audienced to ' +
                 '/admin-api under the host the request arrived on is ' +
                 'accepted as well, which is what a client gets by asking ' +
                 'for `resource=<base>/admin-api` at the token endpoint (RFC ' +
                 '8707) under whatever name it reached this service by. Set ' +
                 'it to pin a single value where a deployment is reached ' +
                 'under several names.' },

  { key: 'admin.openWhenEmpty', group: 'Admin console',
    label: 'Open until the bootstrap administrator signs in',
    env: 'ADMIN_OPEN_WHEN_EMPTY', type: 'bool', dflt: true, runtime: true,
    // PROCESS-WIDE SINCE 2026-09-14 (#32): a realm may not carry it, because it
    // decides who administers the service — see admin-ui/admin_scope.js.
    perProcess: true,
    description: 'SINCE 2026-09-13, on a service that seeded its bootstrap ' +
                 'administrator (admin.bootstrapUsername): ON, every ' +
                 'signed-in person may use the whole console UNTIL that ' +
                 'account first signs in to /admin, after which only members ' +
                 'of the two role groups may; OFF, only members may from the ' +
                 'start. Where no bootstrap administrator was seeded (a ' +
                 'process that never ran the startup step) the older rule ' +
                 'below applies. The older rule: what happens while NEITHER ' +
                 'role group has a single member: ' +
                 'ON, anybody who signs in holds both roles and the console ' +
                 'says so in a banner on every page; OFF, nobody can get in ' +
                 'at all. The moment the FIRST grant is made the older rule ' +
                 'enforces the roster. With the bootstrap administrator ' +
                 'seeded, turning this off is safe — that account is a ' +
                 'member of both roles. If you are locked out anyway, ' +
                 '/admin-api is the way back in: POST /admin-api/rbac/grant ' +
                 'with an access token carrying admin:write, or — if nobody ' +
                 'can get one of those either — adminApi.authRequired=false ' +
                 'and then that same call.' },

  // --- Protocol debugger ---------------------------------------------------
  //
  // THE EMBEDDED IDENTITY PROTOCOL DEBUGGER (2026-09-13). Every row that
  // decides a socket, a directory or the child's environment is restart-only,
  // because the listener is bound and the api process forked once, before the
  // service is reachable. The GATE is not a row and must never become one:
  // `debugger/CLAUDE.md` argues why a relay that dials what a caller names is
  // not a surface that may be opened.
  { key: 'debugger.enabled', group: 'Protocol debugger',
    label: 'Embed the protocol debugger',
    env: 'STS_DEBUGGER_ENABLED', type: 'enum',
    enumValues: ['auto', 'on', 'off'], dflt: 'auto', runtime: false,
    perProcess: true,
    restartReason: 'the listener is bound and the api process forked when ' +
                   'the service starts',
    description: 'Whether this process serves the identity protocol debugger ' +
                 'on a listener of its own. `auto` — the default — is ON in ' +
                 'development mode and OFF in product mode, where a relay ' +
                 'that dials what a signed-in administrator names should be ' +
                 'turned on deliberately. `on` and `off` decide regardless of ' +
                 'the mode.\n\nWhat it serves is the debugger\'s built user ' +
                 'interface, and at `/api` its api, forked as a child process ' +
                 'on a unix socket. Every request needs a console ' +
                 'administrator signed in through this service\'s own ' +
                 'authorization server; there is no setting that removes ' +
                 'that.' },
  { key: 'debugger.port', group: 'Protocol debugger',
    label: 'Debugger listener port',
    env: 'STS_DEBUGGER_PORT', type: 'port', dflt: 8444, runtime: false,
    perProcess: true,
    restartReason: 'the listener is bound when the process starts',
    description: 'The port the debugger is served on, in the main port\'s ' +
                 'scheme and with its certificate. It is a separate ORIGIN ' +
                 'from the admin console on purpose: the debugger\'s pages ' +
                 'carry inline scripts and render tokens and assertions from ' +
                 'any identity provider, and on the console\'s origin a flaw ' +
                 'in either would be a script able to drive the console.' },
  { key: 'debugger.publicBaseUrl', group: 'Protocol debugger',
    label: 'Debugger public base URL',
    env: 'STS_DEBUGGER_PUBLIC_BASE_URL', type: 'string', dflt: '',
    runtime: false, perProcess: true,
    restartReason: 'the debugger client\'s redirect URI is seeded at startup',
    description: 'The scheme, host and port the debugger is reached at — ' +
                 '`https://debugger.example.com`, with no path. Empty reads ' +
                 'it off each request, and development mode then teaches the ' +
                 'seeded client the callback address it was reached at. In ' +
                 'product mode a callback is never learnt, so a deployment ' +
                 'reached by name sets this.' },
  { key: 'debugger.uiDirectory', group: 'Protocol debugger',
    label: 'Built debugger UI',
    env: 'STS_DEBUGGER_UI_DIRECTORY', type: 'string',
    dflt: 'debugger/embedded/ui', runtime: false,
    perProcess: true,
    restartReason: 'the listener checks the directory when it starts',
    description: 'Where the debugger\'s built static site is, relative to ' +
                 'this package\'s root unless absolute. The image copies it ' +
                 'from the debugger project\'s embedded build; a checkout ' +
                 'builds it with `embedded/build.sh` there. A missing ' +
                 'directory leaves the debugger OFF and says why on ' +
                 '/admin/debugger rather than stopping the service.' },
  { key: 'debugger.apiDirectory', group: 'Protocol debugger',
    label: 'Built debugger api',
    env: 'STS_DEBUGGER_API_DIRECTORY', type: 'string',
    dflt: 'debugger/embedded/api', runtime: false,
    perProcess: true,
    restartReason: 'the api process is forked when the service starts',
    description: 'Where the debugger\'s api tree is — its `server.js`, its ' +
                 'own `node_modules` and `env/embedded.js`. It is never ' +
                 'required into this process: it is forked, so its ' +
                 'dependencies, its Express and its globals stay its own.' },
  { key: 'debugger.allowedDestinations', group: 'Protocol debugger',
    label: 'Extra destinations the api may dial in product mode',
    env: 'STS_DEBUGGER_ALLOWED_DESTINATIONS', type: 'csv', dflt: '',
    runtime: false, perProcess: true,
    restartReason: 'the allow-list is handed to the api process when it is ' +
                   'forked',
    description: 'CIDR ranges (`203.0.113.0/24`, `10.1.2.3/32`) the embedded ' +
                 'api may dial IN PRODUCT MODE, beside the ones this service ' +
                 'is itself reachable at — its loopback addresses, its ' +
                 'network interfaces, and whatever global.publicBaseUrl and ' +
                 'debugger.publicBaseUrl resolve to. Development mode passes ' +
                 'no allow-list. An entry that is not a range is refused at ' +
                 'startup and named, never widened.' },
  { key: 'debugger.startTimeoutS', group: 'Protocol debugger',
    label: 'Seconds the api process has to start',
    env: 'STS_DEBUGGER_START_TIMEOUT_S', type: 'int', dflt: 30, min: 1,
    max: 600, runtime: true, perProcess: true,
    description: 'How long a forked api process has to report that it is ' +
                 'listening before it is killed and counted as a failed ' +
                 'start.' },
  { key: 'debugger.restartLimit', group: 'Protocol debugger',
    label: 'Failed starts before the api is given up on',
    env: 'STS_DEBUGGER_RESTART_LIMIT', type: 'int', dflt: 5, min: 1,
    max: 100, runtime: true, perProcess: true,
    description: 'An api process that exits is forked again after a delay ' +
                 'that doubles each time, up to a minute. This many exits in ' +
                 'a row without one staying up for a minute leaves it ' +
                 'stopped: every /api call then answers 502 naming the last ' +
                 'failure, and /admin/debugger says the same.' },
  { key: 'debugger.proxyTimeoutS', group: 'Protocol debugger',
    label: 'Seconds an /api call may take',
    env: 'STS_DEBUGGER_PROXY_TIMEOUT_S', type: 'int', dflt: 120, min: 1,
    max: 3600, runtime: true, perProcess: true,
    description: 'How long the gate waits on the api process for one ' +
                 'response. It is generous because a debugger call is often ' +
                 'itself waiting on a slow identity provider or a KDC, and ' +
                 'the api has timeouts of its own inside it.' },
  { key: 'debugger.maxRequestBytes', group: 'Protocol debugger',
    label: 'Largest /api request body',
    env: 'STS_DEBUGGER_MAX_REQUEST_BYTES', type: 'int', dflt: 5242880, min: 1,
    runtime: true, perProcess: true,
    description: 'The largest request body the gate forwards to the api ' +
                 'process. Larger is refused with 413 before a byte reaches ' +
                 'it. The api\'s own parser allows 5 MB, which is this ' +
                 'default.' },

  // --- Applications --------------------------------------------------------
  { key: 'applications.max', group: 'Applications',
    label: 'Applications remembered',
    env: 'STS_APPLICATIONS_MAX', type: 'int', dflt: 500, runtime: true,
    description: 'How many entries may live under ou=applications — an OAuth ' +
                 'client_id, a WS-Federation wtrealm, a SAML entityID, a ' +
                 'WS-Trust AppliesTo, a Kerberos SPN. The registry IS that ' +
                 'container, so this is a directory limit and behaves like ' +
                 'one: past it a new application is REFUSED and warned about ' +
                 'rather than an old one being evicted, because a directory ' +
                 'that quietly dropped entries would be the worst possible ' +
                 'source of truth. It is separate from ldap.maxEntries, ' +
                 'which caps the whole tree, so a runaway client_id ' +
                 'generator cannot fill the directory and stop people being ' +
                 'created.' },

  // Added 2026-09-12. It was a module constant whose comment called it "a
  // guard and not a setting"; an operator whose registry is past it had no
  // way to move it short of editing the source.
  { key: 'portal.applicationScanLimit', group: 'Applications',
    label: 'Applications the user portal evaluates for one person',
    env: 'STS_PORTAL_APPLICATION_SCAN_LIMIT', type: 'int', dflt: 1000,
    min: 1, max: 1000000, runtime: true,
    description: 'How many registry entries /portal/applications asks the ' +
                 'issuance policy about before it stops. Each entry costs a ' +
                 'policy evaluation per issuance kind on the thread every ' +
                 'socket here is answered on, so this bounds how long one ' +
                 'person opening that page can hold the service. The page ' +
                 'says how many entries it did not look at.' },

  // Two applications nothing external ever names, because they are surfaces of
  // THIS process: the console and this API. Every other entry in the registry
  // arrives because a caller presented an identifier, so without this the one
  // question the registry exists to answer — what applications have you seen? —
  // came back with everything except the two things the reader was standing in.
  { key: 'applications.seedInternal', group: 'Applications',
    label: 'Seed the console and this API as applications',
    env: 'STS_APPLICATIONS_SEED_INTERNAL', type: 'bool', dflt: true,
    runtime: false,
    restartReason: 'the two entries are written once, as ldap_server.js is ' +
                   'required and fills the registry\'s directory slot',
    description: 'Create an application entry for the ADMIN CONSOLE at ' +
                 '/admin and one for the MANAGEMENT API at /admin-api when ' +
                 'this service starts, under ou=applications with everything ' +
                 'else. They are seeded as FULL RFC 7591 registrations ' +
                 'rather than as labels: the console as a confidential ' +
                 'OpenID Connect relying party on the authorization code ' +
                 'grant, this API as a confidential OAuth client on ' +
                 'client_credentials, each with a secret minted at startup — ' +
                 'so they are clients that can be exercised rather than rows ' +
                 'on a page. Nothing serves /admin/callback: the console\'s ' +
                 'gate is a sign-on session and two directory groups, so ' +
                 'that redirect URI is what it WOULD use, and it is on the ' +
                 'entry rather than in a comment because this container is ' +
                 'the registry — an ldapmodify of it is a configuration ' +
                 'change. ON by default. Seeded only where the identifier is ' +
                 'free, so an operator who deleted one has it stay deleted ' +
                 'until the next restart.' },

  // --- Federation ----------------------------------------------------------
  //
  // The one feature here that REFUSES by default rather than accepting, and the
  // settings say so in the direction that matters: the feature is on, every
  // relationship is off, and a relationship is created disabled. See
  // federation/CLAUDE.md, where the argument for that inversion is made — a
  // permissive federation endpoint is not a mock of federation, it is a hole
  // underneath every other protocol in this service.
  { key: 'federation.enabled', group: 'Federation',
    label: 'Federation endpoints answer',
    env: 'STS_FEDERATION_ENABLED', type: 'bool', dflt: true, runtime: true,
    description: 'Whether /federation answers at all. ON by default, and ' +
                 'that is safe in a way it would not be anywhere else here ' +
                 'because the endpoints do NOTHING without a relationship: a ' +
                 'partner is created disabled, and one that is enabled and ' +
                 'half-configured refuses rather than half-works. Turning ' +
                 'this OFF is the blunt instrument — every federation route ' +
                 'answers 404 and no partner appears on the sign-in screen, ' +
                 'without any relationship being changed, which is how to ' +
                 'take the feature away for one test run and put it back.' },

  { key: 'federation.max', group: 'Federation',
    label: 'Relationships remembered',
    env: 'STS_FEDERATION_MAX', type: 'int', dflt: 50, min: 1, max: 5000,
    runtime: true,
    description: 'How many entries may live under ou=federations. A ' +
                 'directory limit, so past it a new relationship is REFUSED ' +
                 'rather than an old one being evicted — the same rule ' +
                 'applications.max follows, and it matters more here: an ' +
                 'evicted federation relationship is a partner that silently ' +
                 'stopped being trusted. The default is small because these ' +
                 'are CONFIGURED by hand rather than created by traffic, so ' +
                 'fifty is a large number of them and a thousand would mean ' +
                 'something has gone wrong.' },

  { key: 'federation.usernamePrefix', group: 'Federation',
    label: 'Prefix for federated usernames',
    env: 'STS_FEDERATION_USERNAME_PREFIX', type: 'string', dflt: '',
    runtime: true,
    description: 'Put in front of every username a foreign identity provider ' +
                 'supplies, so a federated `alice` and the local `alice` are ' +
                 'two entries. EMPTY by default, which means they are ONE ' +
                 'entry — and that is a real decision rather than a default ' +
                 'nobody thought about. Empty is right for a mock being ' +
                 'pointed at a partner to see what comes back, because a ' +
                 'prefixed name makes every downstream token and assertion ' +
                 'look unfamiliar. Set it to something like `fed-` the ' +
                 'moment the question is whether federated identities share ' +
                 'a namespace with local ones, which is the question this ' +
                 'setting exists for. It is applied AFTER the username is ' +
                 'chosen, so changing it cannot change WHICH incoming value ' +
                 'was used.' },

  { key: 'federation.loginButtons', group: 'Federation',
    label: 'Offer partners at the sign-in screen',
    env: 'STS_FEDERATION_LOGIN_BUTTONS', type: 'bool', dflt: true,
    runtime: true,
    description: 'Show a button per usable service-provider-side ' +
                 'relationship on /authn/login, so a federated identity can ' +
                 'satisfy ANY flow already in progress — an OAuth 2.0 ' +
                 'authorization request, a WS-Federation sign-in, a SAML ' +
                 'AuthnRequest, the admin console. That is the whole reason ' +
                 'the buttons are there rather than only at ' +
                 '/federation/login/{id}. Only relationships that would ' +
                 'actually work are offered — a button leading to a refusal ' +
                 'would be worse than no button.' },

  { key: 'federation.outbound', group: 'Federation',
    label: 'Make back-channel requests to partners',
    env: 'STS_FEDERATION_OUTBOUND', type: 'bool', dflt: true, runtime: true,
    description: 'Whether this service may make an HTTP request OUT, to a ' +
                 'partner\'s token endpoint, UserInfo endpoint or JWKS. This ' +
                 'is the only outbound request in the whole repository and ' +
                 'federation/federation_http.js argues it at length: a URL ' +
                 'an ADMINISTRATOR configured on a relationship is a ' +
                 'different thing from a URL an unauthenticated caller ' +
                 'REGISTERED, which is why oauthJwksUri on an application ' +
                 'entry is still never followed and wreqptr is still ' +
                 'refused. Turn it OFF for a deployment with no egress: ' +
                 'SAML, SAML 1.1 and WS-Federation need no back channel at ' +
                 'all, and an OIDC partner can still be used with ' +
                 'fedResponseType=id_token and its keys pasted into fedJwks.' },

  { key: 'federation.outboundTimeoutMs', group: 'Federation',
    label: 'Back-channel timeout (ms)',
    env: 'STS_FEDERATION_OUTBOUND_TIMEOUT_MS', type: 'int', dflt: 15000,
    min: 250, max: 60000, runtime: true,
    description: 'How long to wait for a partner to answer before giving up. ' +
                 'It matters more than a timeout usually does because the ' +
                 'browser is WAITING on it — a federated sign-in is a person ' +
                 'looking at a blank tab while this service redeems a code — ' +
                 'so it is short enough that a dead partner produces an ' +
                 'error page rather than a hang, and the error names the ' +
                 'timeout. ' +
                 'It was 5000 until 2026-08-30, and what changed is that the ' +
                 'partner here is USUALLY THIS PROCESS: a trust realm is a ' +
                 'logical copy of this service, and the first thing anybody ' +
                 'asks a brand-new realm for is its JWKS — which is what ' +
                 'brings that realm\'s eleven post-quantum keys into being, ' +
                 'one of which is an SLH-DSA-SHAKE-128s key generation of ' +
                 'about five seconds. 5000 was a budget that only ever ' +
                 'worked because this service USED TO BLOCK while it ' +
                 'answered: with the event loop stopped, the timer ' +
                 'enforcing that budget could not fire until the response ' +
                 'was already made. The keys are ' +
                 'generated in worker processes now (common/worker.js) and ' +
                 'warmed when a realm is created, so the ordinary fetch is ' +
                 'milliseconds — this is the budget for the one that arrives ' +
                 'while a realm is still being born.' },

  { key: 'federation.outboundAllowInsecure', group: 'Federation',
    label: 'Allow http:// and untrusted TLS to a partner',
    env: 'STS_FEDERATION_OUTBOUND_ALLOW_INSECURE', type: 'bool', dflt: false,
    runtime: true,
    description: 'OFF by default, which is the one place this service is ' +
                 'stricter than a mock would ordinarily be: what travels on ' +
                 'these requests is a client secret and an authorization ' +
                 'code, at somebody else\'s service. ON accepts an http:// ' +
                 'endpoint and a certificate nothing here trusts, which is ' +
                 'what federating against another mock on localhost needs — ' +
                 'and it is logged on every request rather than only here, ' +
                 'because a setting that quietly disabled certificate ' +
                 'checking would be the worst kind of leftover.' },

  { key: 'federation.requestTtlMin', group: 'Federation',
    label: 'Outbound request lifetime (minutes)',
    env: 'STS_FEDERATION_REQUEST_TTL_MIN', type: 'int', dflt: 10, min: 1,
    max: 120, runtime: true,
    description: 'How long this service remembers that it sent somebody to a ' +
                 'partner. The record holds the request id an <AuthnRequest> ' +
                 'has to be answered against, the OAuth `state` and `nonce`, ' +
                 'the PKCE verifier and where the person was going before ' +
                 'any of it started — so when it expires the response is ' +
                 'refused as unsolicited, which is what a person who left a ' +
                 'sign-in open over lunch will see. Ten minutes is longer ' +
                 'than any identity provider takes and short enough that a ' +
                 'replayed response outlives nothing.' },

  // --- Federation: the bounds that were literals until 2026-09-12 ----------
  // An audit for hard-coded values found five numbers and one list in
  // federation/ that no deployment could change. Every default below is the
  // literal it replaced, so an unedited service behaves exactly as it did.
  { key: 'federation.maxContexts', group: 'Federation',
    label: 'Sign-ins in flight per realm',
    env: 'STS_FEDERATION_MAX_CONTEXTS', type: 'int', dflt: 500, min: 1,
    max: 100000, runtime: true,
    description: 'How many outbound federated sign-ins this service holds a ' +
                 'request context for at once, PER TRUST REALM. Past it the ' +
                 'OLDEST is dropped rather than a new one refused, because ' +
                 '/federation/login/{id} is reachable by anybody and a login ' +
                 'endpoint that stopped working once it was hit enough times ' +
                 'would be a denial of service. Whoever was dropped is told ' +
                 'their response was unsolicited. Was the constant ' +
                 'MAX_CONTEXTS in federation_sp.js.' },

  { key: 'federation.maxApplicationLength', group: 'Federation',
    label: 'Longest application a sign-in may name',
    env: 'STS_FEDERATION_MAX_APPLICATION_LENGTH', type: 'int', dflt: 256,
    min: 16, max: 4096, runtime: true,
    description: 'The longest ?application= a federated login will carry ' +
                 'across the round trip. It is a query parameter on an ' +
                 'endpoint that needs no configuration to reach, and it ends ' +
                 'up in a directory attribute, so it is bounded where it is ' +
                 'ACCEPTED. 256 is generous — the longest identifier ' +
                 'anything here files an application under is a SAML ' +
                 'entityID.' },

  { key: 'federation.maxApplicationUse', group: 'Federation',
    label: 'Per-application counters kept per relationship',
    env: 'STS_FEDERATION_MAX_APPLICATION_USE', type: 'int', dflt: 64,
    min: 1, max: 4096, runtime: true,
    description: 'How many fedApplicationUse rows one relationship keeps. ' +
                 'Past it the busiest are kept and the rest dropped, which ' +
                 'the map page says rather than leaving a number to stop ' +
                 'moving.' },

  { key: 'federation.releaseIndexTtlMs', group: 'Federation',
    label: 'Release-policy index lifetime (ms)',
    env: 'STS_FEDERATION_RELEASE_INDEX_TTL_MS', type: 'int', dflt: 5000,
    min: 0, max: 600000, runtime: true,
    description: 'How long the index of identity-provider-side release lists ' +
                 'is reused before the register is walked again. It is ' +
                 'rebuilt rather than maintained because two of the four ' +
                 'doors onto those entries (ldapmodify, ldapadd) never come ' +
                 'through federation.js. 0 rebuilds it on every token, which ' +
                 'is right for a test changing a release list and watching ' +
                 'the next token, and wrong for a load test.' },

  { key: 'federation.maxResponseBytes', group: 'Federation',
    label: 'Largest back-channel response (bytes)',
    env: 'STS_FEDERATION_MAX_RESPONSE_BYTES', type: 'int', dflt: 262144,
    min: 1024, max: 16777216, runtime: true,
    description: 'The cap on a partner\'s token response, UserInfo document ' +
                 'or JWKS. A token response is a few hundred bytes and a ' +
                 'JWKS a few kilobytes, so 256 KiB is two orders of ' +
                 'magnitude of headroom and still a bound on what a hostile ' +
                 'partner can make this process hold.' },

  { key: 'federation.jwtAlgorithms', group: 'Federation',
    label: 'Algorithms accepted on a partner\'s JWT',
    env: 'STS_FEDERATION_JWT_ALGORITHMS', type: 'csv',
    dflt: 'RS256,RS384,RS512,PS256,PS384,PS512,ES256,ES384,ES512',
    runtime: true,
    description: 'The JWS algorithms an ID Token or a JWT access token from ' +
                 'a federation partner may be signed with. It NARROWS rather ' +
                 'than widens: the algorithm family still comes from the ' +
                 'partner\'s KEY (an RSA key admits only RS*/PS*, an EC key ' +
                 'only ES*), which is the rule that stops a token nominating ' +
                 'HS256 being verified with a public key as its secret, and ' +
                 'no value here can reintroduce `none` or an HMAC. Remove ' +
                 'RS256 to require a partner to use something stronger.' },

  { key: 'federation.spNameIdFormat', group: 'Federation',
    label: 'NameIDFormat in this service\'s SP metadata',
    env: 'STS_FEDERATION_SP_NAMEID_FORMAT', type: 'string',
    dflt: 'urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified',
    runtime: true,
    description: 'The <md:NameIDFormat> published in ' +
                 '/federation/metadata/{id}, which is what a partner ' +
                 'configured from that document sends a subject in. The ' +
                 'default is the literal this service has always published.' },

  // --- SAML ----------------------------------------------------------------
  { key: 'saml.issuer', group: 'SAML', label: 'Assertion issuer',
    env: 'STS_SAML_ISSUER', legacyEnv: 'STS_ISSUER', type: 'string',
    dflt: 'urn:wstrust:mock:sts', runtime: true,
    description: 'The <saml:Issuer> of every SAML 2.0 assertion and the ' +
                 'Issuer attribute of every SAML 1.1 one. WS-Federation\'s ' +
                 'assertions are built by the same two functions, so this is ' +
                 'their issuer too, and it is what /wsfed/rp checks a ' +
                 'presented assertion against.' },

  // The one setting on this page that changes what goes INTO an assertion's
  // validity window rather than how long that window is. It is deliberately
  // NOT oauth2.clockSkewS: that one is a TOLERANCE applied when this service
  // READS a token or an assertion back — federation/federation_sp.js applies
  // it to an inbound partner assertion and argues there that a deployment
  // decides its reading tolerance once — and this one is what this service
  // WRITES into a document it issues. One is about somebody else's clock and
  // one is about how much of somebody else's clock this service is willing to
  // pay for in advance, and a deployment wanting a strict reading and a
  // forgiving issuance has to be able to say so.
  { key: 'saml.clockSkewS', group: 'SAML', label: 'Assertion clock skew (s)',
    env: 'STS_SAML_CLOCK_SKEW_S', type: 'int', dflt: 0,
    min: 0, max: 300, step: 30, runtime: true,
    description: 'How far to widen the validity window of every assertion ' +
                 'this service ISSUES, at both ends: NotBefore is backdated ' +
                 'by this many seconds and NotOnOrAfter is extended by it. ' +
                 'Both SAML 2.0 and SAML 1.1 assertions are built by the two ' +
                 'functions WS-Trust and WS-Federation also come through, so ' +
                 'this reaches all four. 0 by default, which is what this ' +
                 'service has always done: NotBefore is stamped at exactly ' +
                 'the moment of issue. That is the strict reading and it is ' +
                 'the one that breaks against a service provider whose clock ' +
                 'is a few seconds behind — the assertion is not yet valid ' +
                 'when it arrives, and the refusal reads as a signature or a ' +
                 'trust-store problem from both ends. Capped at 300 for the ' +
                 'reason oauth2.clockSkewS is: five minutes is what Kerberos ' +
                 'allows here (krb5.clockSkew), and wider than that the ' +
                 'window has stopped being a tolerance and become a lifetime ' +
                 'nobody chose. It is NOT a lifetime — the assertion ' +
                 'lifetimes are saml2.assertionLifetimeMin and ' +
                 'saml11.assertionLifetimeMin, and this is added to both ' +
                 'ends of whatever they decide.' },

  // THE XML SIGNATURE EVERY SAML DOCUMENT CARRIES, and WS-Federation's metadata
  // and a federated AuthnRequest besides. Until 2026-09-12 no signer passed an
  // algorithm to common/crypto.js, which accepts one — so RSA-SHA256 and
  // exclusive c14n were decided by an absence. In the SAML group because every
  // signer in saml/, ws-federation/ and federation/ reads them: one estate, one
  // answer, the same argument saml.clockSkewS makes.
  { key: 'saml.signatureAlgorithm', group: 'SAML',
    label: 'XML signature algorithm',
    env: 'STS_SAML_SIGNATURE_ALGORITHM', type: 'enum',
    enumValues: ['rsa-sha256', 'rsa-sha384', 'rsa-sha512', 'rsa-sha1'],
    dflt: 'rsa-sha256', runtime: true,
    description: 'The SignatureMethod of every enveloped XML signature this ' +
                 'service makes over a SAML 2.0 or SAML 1.1 assertion or ' +
                 'response, a SAML metadata document, the WS-Federation ' +
                 'metadata and a signed federated AuthnRequest — and the ' +
                 'SigAlg of the HTTP Redirect binding\'s query-string ' +
                 'signature. The digest follows the algorithm. RSA only, ' +
                 'because the key these are made with is RSA. `rsa-sha1` is ' +
                 'BROKEN and offered for the reason rsa-1_5 is: deployed ' +
                 'service providers still demand it and a client library is ' +
                 'entitled to be tested against them.' },

  { key: 'saml.canonicalizationAlgorithm', group: 'SAML',
    label: 'XML canonicalization',
    env: 'STS_SAML_CANONICALIZATION_ALGORITHM', type: 'enum',
    enumValues: ['exclusive', 'exclusive-with-comments'],
    dflt: 'exclusive', runtime: true,
    description: 'The CanonicalizationMethod of those signatures. Only the ' +
                 'two EXCLUSIVE methods are offered and that is a property ' +
                 'of the documents rather than a missing option: an ' +
                 'assertion is signed standalone and then embedded in a ' +
                 'Response, an RSTR or a wresult that declares prefixes of ' +
                 'its own, so an inclusive canonicalization would pull those ' +
                 'declarations into the digest at verification time and fail ' +
                 'at every relying party — and this service\'s own verifier ' +
                 'refuses inclusive c14n on a nested element for that ' +
                 'reason.' },

  { key: 'saml.organizationName', group: 'SAML',
    label: 'Metadata OrganizationName',
    env: 'STS_SAML_ORGANIZATION_NAME', type: 'string', dflt: 'sts',
    runtime: true,
    description: 'The <md:OrganizationName> in /saml2/metadata and ' +
                 '/saml11/metadata. EMPTY OMITS THE WHOLE <md:Organization> ' +
                 'element, in either mode, because the metadata schema ' +
                 'requires a name, a display name and a URL together and an ' +
                 'organisation with no name is not one. A product deployment ' +
                 'sets its own or empties it; the default is the product ' +
                 'name, `sts` (it was `mock-sts` until 2026-09-12).' },

  { key: 'saml.organizationDisplayName', group: 'SAML',
    label: 'Metadata OrganizationDisplayName',
    env: 'STS_SAML_ORGANIZATION_DISPLAY_NAME', type: 'string',
    dflt: 'Mock security token service', runtime: true,
    description: 'The <md:OrganizationDisplayName> beside the name above. ' +
                 'Empty omits the element for the reason given there.' },

  { key: 'saml.organizationUrl', group: 'SAML',
    label: 'Metadata OrganizationURL',
    env: 'STS_SAML_ORGANIZATION_URL', type: 'string', dflt: '', runtime: true,
    description: 'The <md:OrganizationURL>. Empty means this service\'s own ' +
                 'base URL as the request reached it (global.publicBaseUrl ' +
                 'when that is set), which is what was always published.' },

  // --- SAML 2.0 Web Browser SSO --------------------------------------------
  // The profile arrived on 2026-08-24 and brought its own group, which is a
  // decision rather than a formality: `saml.issuer` above governs what SIGNED
  // an assertion and is shared by WS-Trust and WS-Federation, and every row
  // here governs how this service behaves as an IDENTITY PROVIDER in a browser
  // profile. Folding the two together would have made a change to one of these
  // look like a change to the assertions WS-Trust hands out, which it is not.
  { key: 'saml2.entityId', group: 'SAML 2.0', label: 'Identity provider ' +
                                                     'entityID',
    env: 'STS_SAML2_ENTITY_ID', type: 'string', dflt: 'urn:sts:idp',
    runtime: true,
    description: 'The entityID this identity provider publishes in its SAML ' +
                 '2.0 metadata, and the <saml:Issuer> of every Response and ' +
                 'Assertion the Web Browser SSO profile issues. It is NOT ' +
                 'the SAML issuer above: that one names whoever signed an ' +
                 'assertion and is shared with WS-Trust and WS-Federation, ' +
                 'and a service provider checks THIS one against the ' +
                 'metadata it was configured from. They are separate for the ' +
                 'reason wsfed.entityId is separate from it.' },

  { key: 'saml2.perApplicationEntityId', group: 'SAML 2.0',
    label: 'An entityID per service provider',
    env: 'STS_SAML2_PER_APPLICATION_ENTITY_ID', type: 'bool', dflt: true,
    runtime: true,
    description: 'ON by default, and it is what makes the metadata at ' +
                 '/saml2/metadata/{sp} UNIQUE PER APPLICATION: the identity ' +
                 'provider names itself <entityID>:{sp} in that document and ' +
                 'in everything it issues to that service provider, the way ' +
                 'Okta and Ping give each application its own identity ' +
                 'provider. OFF makes every document carry the entityID ' +
                 'above and differ only in its endpoint URLs, which is what ' +
                 'a service provider library that keys its trust store off ' +
                 'the entityID expects. Both are real deployments, which is ' +
                 'why it is a setting and not a decision.' },

  { key: 'saml2.assertionLifetimeMin', group: 'SAML 2.0 assertions',
    label: 'Assertion lifetime (minutes)',
    env: 'STS_SAML2_ASSERTION_LIFETIME_MIN', type: 'int', dflt: 60,
    runtime: true,
    description: 'How long an issued assertion is valid for: it becomes ' +
                 'Conditions/NotOnOrAfter and the bearer ' +
                 'SubjectConfirmationData/NotOnOrAfter alike. Set it to 1 to ' +
                 'watch a service provider refuse a stale assertion, which ' +
                 'is the check most of them get wrong.' },

  { key: 'saml2.signAssertion', group: 'SAML 2.0 assertions', label: 'Sign ' +
      'the assertion',
    env: 'STS_SAML2_SIGN_ASSERTION', type: 'bool', dflt: true, runtime: true,
    description: 'Sign the <saml:Assertion> itself. ON by default because a ' +
                 'service provider that verifies anything verifies this, and ' +
                 'because an assertion that travels on its own — out of an ' +
                 'ArtifactResponse, say — has nothing else carrying a ' +
                 'signature. Turning it OFF is a test case rather than a ' +
                 'mistake: a service provider that accepts an unsigned ' +
                 'assertion has a hole, and this is how to find out.' },

  { key: 'saml2.signResponse', group: 'SAML 2.0 assertions', label: 'Sign ' +
      'the response',
    env: 'STS_SAML2_SIGN_RESPONSE', type: 'bool', dflt: true, runtime: true,
    description: 'Sign the <samlp:Response> around the assertion as well, ' +
                 'which is what AD FS and Keycloak do by default. Both ' +
                 'signatures are ordinary: the response is signed AFTER the ' +
                 'assertion inside it, so the assertion\'s own signature is ' +
                 'part of what the response signature covers. On the HTTP ' +
                 'Redirect binding this ALSO controls the query-string ' +
                 'signature of section 3.4.4.1, which is the one a redirect ' +
                 'response is really verified by.' },

  { key: 'saml2.nameIdFormat', group: 'SAML 2.0 assertions', label: 'Default ' +
      'NameID format',
    env: 'STS_SAML2_NAMEID_FORMAT', type: 'string',
    dflt: 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
    runtime: true,
    description: 'The Format on the NameID when the AuthnRequest\'s ' +
                 'NameIDPolicy asks for none. A request that DOES name one ' +
                 'is answered with the one it named — any of them, including ' +
                 'a format this service has never heard of, because a ' +
                 'service provider being told its own format back is the ' +
                 'behaviour worth exercising and refusing with ' +
                 'InvalidNameIDPolicy would remove the test case.' },

  { key: 'saml2.artifactTtlS', group: 'SAML 2.0 assertions',
    label: 'Artifact ' +
      'lifetime (seconds)',
    env: 'STS_SAML2_ARTIFACT_TTL_S', type: 'int', dflt: 300, runtime: true,
    description: 'How long a SAML artifact can be resolved for at the ' +
                 'Artifact Resolution Service. An artifact is ALSO one-shot ' +
                 '— resolving it destroys it, which section 3.6.4.1 requires ' +
                 'and which no lifetime can express — so a second ' +
                 'ArtifactResolve for the same artifact is refused however ' +
                 'long this is.' },

  // --- SAML 2.0 encryption -------------------------------------------------
  // Four rows in the `SAML 2.0 assertions` group, so they are drawn on
  // /admin/saml-assertions with the rest of what goes into a document and can
  // be answered per application. Encryption is exactly the kind of thing two
  // service providers in one estate disagree about: one is a modern library
  // that wants GCM, the next is an appliance that speaks aes128-cbc and rsa-1_5
  // and nothing else.
  //
  // ALL FOUR ARE OFF-BY-DEFAULT OR MODERN-BY-DEFAULT, which is this service's
  // rule everywhere: `encryptAssertion` is false, so a service provider that
  // has never heard of these gets exactly the document it got before they
  // existed, and the two algorithm rows default to the pair
  // `encryptAssertion()` was fixed at when only WS-Trust used it.
  { key: 'saml2.encryptAssertion', group: 'SAML 2.0 assertions',
    label: 'Encrypt the assertion',
    env: 'STS_SAML2_ENCRYPT_ASSERTION', type: 'bool', dflt: false,
    runtime: true,
    description: 'Wrap the <saml:Assertion> in a <saml:EncryptedAssertion> ' +
                 'inside the Response. OFF by default, because it needs a ' +
                 'RECIPIENT CERTIFICATE and a service provider that has not ' +
                 'given this service one cannot read what comes back. Where ' +
                 'no certificate can be found the assertion is sent in CLEAR ' +
                 'and the reason is logged and shown on /admin/saml2 — a ' +
                 'refusal to issue would be a mock that stopped answering, ' +
                 'and silently sending plaintext while a page said ' +
                 '"encrypted" would be worse than either. The certificate is ' +
                 'taken from the service provider\'s metadata if this ' +
                 'service holds any, then samlEncryptionCertificate on its ' +
                 'entry, then samlSigningCertificate — which is captured off ' +
                 'a signed AuthnRequest, so a service provider that signs ' +
                 'its requests needs no configuration at all. The assertion ' +
                 'is SIGNED FIRST and then encrypted, which is the order ' +
                 'every service provider expects: the signature is inside ' +
                 'the ciphertext and is what survives decryption.' },

  { key: 'saml2.encryptionAlgorithm', group: 'SAML 2.0 assertions',
    label: 'Encryption algorithm',
    env: 'STS_SAML2_ENCRYPTION_ALGORITHM', type: 'enum',
    enumValues: ['aes256-gcm', 'aes128-gcm', 'aes256-cbc', 'aes128-cbc'],
    dflt: 'aes256-gcm', runtime: true,
    description: 'The block cipher every encrypted element is encrypted ' +
                 'with. The two GCM ones are AUTHENTICATED: an altered ' +
                 'ciphertext fails its tag and is refused. The two CBC ones ' +
                 'are NOT, and that is not a defect in this service — it is ' +
                 'the property CBC has, real service providers require it, ' +
                 'and a mock that offered only the safe choice could not be ' +
                 'used to show what the unsafe one does. What this service ' +
                 'does about it when READING is parse the result and refuse ' +
                 'anything that is not well-formed XML, which catches the ' +
                 'ordinary corruption and is not integrity.' },

  { key: 'saml2.keyTransportAlgorithm', group: 'SAML 2.0 assertions',
    label: 'Key transport algorithm',
    env: 'STS_SAML2_KEY_TRANSPORT_ALGORITHM', type: 'enum',
    enumValues: ['rsa-oaep-mgf1p', 'rsa-1_5'],
    dflt: 'rsa-oaep-mgf1p', runtime: true,
    description: 'How the one-time content key is wrapped to the ' +
                 'recipient\'s RSA public key. `rsa-1_5` is RSAES-PKCS1-v1_5 ' +
                 'and is BROKEN — Bleichenbacher\'s adaptive ' +
                 'chosen-ciphertext attack is against exactly this — and it ' +
                 'is offered because a great many deployed service providers ' +
                 'accept nothing else, which is a fact about the world that ' +
                 'a client library is entitled to be tested against. Nothing ' +
                 'this service encrypts is a real secret.' },

  { key: 'saml2.encryptLogoutNameId', group: 'SAML 2.0 assertions',
    label: 'Encrypt the NameID in a LogoutRequest',
    env: 'STS_SAML2_ENCRYPT_LOGOUT_NAMEID', type: 'bool', dflt: false,
    runtime: true,
    description: 'Send <saml:EncryptedID> instead of <saml:NameID> in the ' +
                 'LogoutRequest this identity provider sends a service ' +
                 'provider during Single Logout. It is the only thing in a ' +
                 'SAML 2.0 REQUEST that can be encrypted — there is no ' +
                 'EncryptedAuthnRequest in the specification — and it uses ' +
                 'the same certificate and the same two algorithms as the ' +
                 'assertion. Reading one is not gated by this or by ' +
                 'anything: an <saml:EncryptedID> arriving in a service ' +
                 'provider\'s own LogoutRequest is always decrypted, because ' +
                 'refusing to understand a message this service published an ' +
                 'encryption key for would make that key a lie.' },

  { key: 'saml2.autocreateApplications', group: 'SAML 2.0',
    label: 'Register a service provider on sight',
    env: 'STS_SAML2_AUTOCREATE_APPLICATIONS', type: 'bool', dflt: true,
    runtime: true,
    description: 'ON by default: an entityID this service has not seen ' +
                 'before gets an application entry under ou=applications the ' +
                 'moment it appears in a valid AuthnRequest — or the moment ' +
                 'somebody asks for its metadata — so nothing has to be ' +
                 'provisioned before a service provider can be pointed here. ' +
                 'OFF still ANSWERS the request; it simply records nothing, ' +
                 'which is what somebody driving a fuzzer at this endpoint ' +
                 'wants before their directory has ten thousand entries in ' +
                 'it.' },

  { key: 'saml2.defaultSingleLogoutService', group: 'SAML 2.0',
    label: 'Fallback logout return address',
    env: 'STS_SAML2_DEFAULT_SLO_SERVICE', type: 'string', dflt: '',
    runtime: true,
    description: 'Where a <samlp:LogoutResponse> goes when the service ' +
                 'provider has no SingleLogoutService recorded on its ' +
                 'application entry. A LogoutRequest carries no return ' +
                 'address of its own — only SP metadata has one, and this ' +
                 'service does not consume SP metadata — so without this the ' +
                 'fallback is the assertion consumer service URL that ' +
                 'application last used, which is stated on the page rather ' +
                 'than done quietly. Set it to remove the guess.' },

  { key: 'saml2.requestTtlMin', group: 'SAML 2.0',
    label: 'Held AuthnRequest lifetime (minutes)',
    env: 'STS_SAML2_REQUEST_TTL_MIN', type: 'int', dflt: 10, min: 1, max: 120,
    runtime: true,
    description: 'How long an AuthnRequest is held while the browser is at ' +
                 'the sign-in screen, or between a POST-binding request and ' +
                 'the GET it is turned into. Past it the return trip is ' +
                 'refused with a page naming this value. Was the constant ' +
                 'REQUEST_TTL_MS in saml2_sso.js.' },

  { key: 'saml2.mockSpContextTtlMin', group: 'SAML 2.0',
    label: 'Mock service provider RelayState lifetime (minutes)',
    env: 'STS_SAML2_MOCK_SP_CONTEXT_TTL_MIN', type: 'int', dflt: 30, min: 1,
    max: 1440, runtime: true,
    description: 'How long /saml2/sp — the NON-SPEC mock service provider — ' +
                 'remembers a RelayState it minted so it can check the round ' +
                 'trip. It is that page\'s own state and nothing to do with ' +
                 'the identity provider\'s.' },

  { key: 'saml2.redirectWarnLength', group: 'SAML 2.0',
    label: 'Redirect-binding length warning (characters)',
    env: 'STS_SAML2_REDIRECT_WARN_LENGTH', type: 'int', dflt: 8000,
    min: 256, max: 1000000, runtime: true,
    description: 'A Response sent on the HTTP Redirect binding longer than ' +
                 'this is logged at WARN. It is sent anyway — section 4.1.2 ' +
                 'says the binding MUST NOT carry a response for exactly ' +
                 'this reason, and a service provider with no server behind ' +
                 'its ACS has no other way to receive one — so this is where ' +
                 'somebody lowers the number to match the CDN in front of ' +
                 'their SP.' },

  { key: 'saml2.spMetadataMaxBytes', group: 'SAML 2.0',
    label: 'Largest SP metadata document fetched (bytes)',
    env: 'STS_SAML2_SP_METADATA_MAX_BYTES', type: 'int', dflt: 524288,
    min: 1024, max: 16777216, runtime: true,
    description: 'The cap on a service provider\'s metadata fetched by the ' +
                 'refresh action (samlSpMetadataUrl). A metadata document is ' +
                 'kilobytes; the cap is what stops an endless response being ' +
                 'read into this process.' },

  // --- SAML 1.1 browser profiles -------------------------------------------
  // A group of its own, for the reason the SAML 2.0 rows above have one and for
  // one more besides. The shared reason: `saml.issuer` (group SAML) governs who
  // SIGNED an assertion and is read by WS-Trust and WS-Federation, and these
  // rows govern how this service behaves as an identity provider in a BROWSER
  // profile. The reason peculiar to this group: SAML 1.1 and SAML 2.0 are
  // different specifications rather than two dialects, their profiles differ in
  // what they can express, and a single set of rows shared between them would
  // make `signResponse` mean two things — over there it is an XML signature or
  // a signed query string depending on the binding, and here there is no
  // redirect binding for a response at all.
  { key: 'saml11.providerId', group: 'SAML 1.1', label: 'Identity provider ' +
                                                        'providerID',
    env: 'STS_SAML11_PROVIDER_ID', type: 'string', dflt: 'urn:sts:idp:saml11',
    runtime: true,
    description: 'What this identity provider calls itself in the SAML 1.1 ' +
                 'browser profiles: the `Issuer` ATTRIBUTE of every ' +
                 'assertion they issue, the `entityID` of the metadata ' +
                 'document at /saml11/metadata, and the string whose SHA-1 ' +
                 'becomes the SourceID inside every type 0x0001 artifact. ' +
                 'SAML 1.1 calls it a providerID and SAML 2.0 metadata calls ' +
                 'the same thing an entityID; they are one value and this ' +
                 'row is it. It is deliberately NOT saml2.entityId — a ' +
                 'relying party that trusts this service for 1.1 and not for ' +
                 '2.0 is the ordinary case, and one value would make that ' +
                 'unexpressible.' },

  { key: 'saml11.perApplicationProviderId', group: 'SAML 1.1',
    label: 'A providerID per relying party',
    env: 'STS_SAML11_PER_APPLICATION_PROVIDER_ID', type: 'bool', dflt: true,
    runtime: true,
    description: 'Give every relying party its own providerID — ' +
                 '`{providerID}:{slug}` — and its own endpoints under the ' +
                 'same path segment, which is what /saml11/metadata/{rp} ' +
                 'publishes. Turn it off for a relying party whose trust ' +
                 'store is keyed off the providerID and which is surprised ' +
                 'to meet a new one per application. THE ENDPOINTS STAY ' +
                 'PER-APPLICATION either way, because that is what makes the ' +
                 'documents worth having separately. It also changes every ' +
                 'artifact this service mints: the SourceID is a hash of the ' +
                 'providerID, so turning this off makes one SourceID where ' +
                 'there were many.' },

  { key: 'saml11.assertionLifetimeMin', group: 'SAML 1.1 assertions',
    label: 'Assertion lifetime (minutes)',
    env: 'STS_SAML11_ASSERTION_LIFETIME_MIN', type: 'int', dflt: 60,
    runtime: true,
    description: 'How long the browser profiles\' assertions are valid for, ' +
                 'in the NotBefore and NotOnOrAfter of <saml:Conditions>. It ' +
                 'is separate from the WS-Federation lifetime for the same ' +
                 'reason the SAML 2.0 one is: a browser profile assertion is ' +
                 'consumed within seconds of being issued and a short ' +
                 'lifetime here is a realistic test, where the same value ' +
                 'would make a WS-Federation session expire while somebody ' +
                 'was reading it.' },

  { key: 'saml11.signAssertion', group: 'SAML 1.1 assertions', label: 'Sign ' +
      'the assertion',
    env: 'STS_SAML11_SIGN_ASSERTION', type: 'bool', dflt: true, runtime: true,
    description: 'Sign the <saml:Assertion> itself, with ds:Signature as its ' +
                 'LAST child and the reference naming AssertionID — which is ' +
                 'where the 1.1 schema puts it and is not where SAML 2.0 ' +
                 'does. ON by default because the Browser/POST profile ' +
                 'REQUIRES a signed assertion (saml-profile-1.1 section ' +
                 '4.2.1.4): the assertion passes through the browser, so ' +
                 'nothing else authenticates it. Turning it off is a test ' +
                 'case rather than a mistake — a relying party that accepts ' +
                 'it anyway has a hole in it, and this is how somebody finds ' +
                 'that out.' },

  { key: 'saml11.signResponse', group: 'SAML 1.1 assertions', label: 'Sign ' +
      'the response',
    env: 'STS_SAML11_SIGN_RESPONSE', type: 'bool', dflt: true, runtime: true,
    description: 'Sign the <samlp:Response> around the assertion as well, ' +
                 'with the reference naming ResponseID. Real identity ' +
                 'providers differ here and both are worth exercising, which ' +
                 'is why it is a setting: the profile requires the RESPONSE ' +
                 'to be signed in Browser/POST and says nothing about it for ' +
                 'the assertion pulled back over the artifact channel, where ' +
                 'the SOAP exchange is what a relying party is trusting.' },

  { key: 'saml11.nameIdFormat', group: 'SAML 1.1 assertions',
    label: 'Default ' +
      'NameIdentifier format',
    env: 'STS_SAML11_NAMEID_FORMAT', type: 'string',
    dflt: 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
    runtime: true,
    description: 'The Format on the <saml:NameIdentifier> when the request ' +
                 'asks for none — which in SAML 1.1 is ALWAYS, because the ' +
                 'profile has no request message to carry a NameIDPolicy in. ' +
                 'That is the difference from saml2.nameIdFormat, which is a ' +
                 'default a request routinely overrides: this one is the ' +
                 'answer unless the non-spec `format` parameter overrides ' +
                 'it.' },

  { key: 'saml11.defaultProfile', group: 'SAML 1.1', label: 'Default browser ' +
      'profile',
    env: 'STS_SAML11_DEFAULT_PROFILE', type: 'enum',
    enumValues: ['post', 'artifact'],
    dflt: 'post', runtime: true,
    description: 'Which profile the inter-site transfer service uses when ' +
                 'the request does not say: Browser/POST (section 4.2), ' +
                 'where the assertion travels through the browser in a form ' +
                 'POST, or Browser/Artifact (section 4.1), where a reference ' +
                 'travels through the browser and the relying party fetches ' +
                 'the assertion over SOAP. POST is the default because it ' +
                 'needs no server behind the relying party\'s assertion ' +
                 'consumer, so it is the one that works when somebody points ' +
                 'this at a URL and watches. A request naming `profile` or ' +
                 'carrying `SAMLart` overrides it.' },

  { key: 'saml11.artifactTtlS', group: 'SAML 1.1 assertions',
    label: 'Artifact ' +
      'lifetime (seconds)',
    env: 'STS_SAML11_ARTIFACT_TTL_S', type: 'int', dflt: 300, runtime: true,
    description: 'How long an artifact can be resolved for at the SAML ' +
                 'responder before it is swept. It is an UPPER bound and not ' +
                 'the rule that matters: an artifact is resolvable exactly ' +
                 'ONCE (saml-bindings-1.1 section 3.2.3), so resolving one ' +
                 'destroys it whatever this says, and no lifetime setting ' +
                 'can express that. Five minutes is what the profile ' +
                 'recommends and is generous for an exchange that takes ' +
                 'milliseconds.' },

  { key: 'saml11.autocreateApplications', group: 'SAML 1.1',
    label: 'Register relying parties on sight',
    env: 'STS_SAML11_AUTOCREATE_APPLICATIONS', type: 'bool', dflt: true,
    runtime: true,
    description: 'Create an application entry under ou=applications the ' +
                 'first time a relying party is named — by a TARGET ' +
                 'arriving, by a metadata document being fetched, or by an ' +
                 'artifact being resolved. Off means the browser profiles ' +
                 'still work and /admin/saml11 stays empty, which is what ' +
                 'somebody driving a load test wants and nobody else does.' },

  { key: 'saml11.requestTtlMin', group: 'SAML 1.1',
    label: 'Held flow lifetime (minutes)',
    env: 'STS_SAML11_REQUEST_TTL_MIN', type: 'int', dflt: 10, min: 1, max: 120,
    runtime: true,
    description: 'How long the parameters a SAML 1.1 browser flow arrived ' +
                 'with are held while the browser is at the sign-in screen. ' +
                 'Past it the return trip is refused with a page naming this ' +
                 'value. Was the constant REQUEST_TTL_MS in saml11_sso.js.' },

  { key: 'saml11.assertionCacheMax', group: 'SAML 1.1',
    label: 'Assertions kept for AssertionIDReference',
    env: 'STS_SAML11_ASSERTION_CACHE_MAX', type: 'int', dflt: 500, min: 1,
    max: 100000, runtime: true,
    description: 'How many issued assertions the SAML responder keeps, per ' +
                 'trust realm, so a relying party can ask for one again by ' +
                 'AssertionIDReference. Oldest out first. Was the constant ' +
                 'ASSERTION_CACHE_MAX in saml11_sso.js.' },

  // --- WS-Trust ------------------------------------------------------------
  { key: 'wstrust.issuer', group: 'WS-Trust', label: 'Token issuer',
    env: 'STS_WSTRUST_ISSUER', legacyEnv: 'STS_ISSUER', type: 'string',
    dflt: 'urn:wstrust:mock:sts', runtime: true,
    description: 'The `iss` of the JWT this STS returns in a ' +
                 'RequestSecurityTokenResponse, and the issuer named on GET ' +
                 '/sts. A SAML token requested through WS-Trust is built by ' +
                 'the SAML modules and carries saml.issuer instead, which ' +
                 'the console draws on its two SAML pages. When the two ' +
                 'differ GET /sts says so and the process logs it at ' +
                 'startup, because one STS naming itself two ways is ' +
                 'something a relying party configured from one of them ' +
                 'finds out about as a refused token.' },

  { key: 'wstrust.tokenLifetimeMin', group: 'WS-Trust',
    label: 'Token lifetime (minutes)',
    env: 'STS_WSTRUST_TOKEN_LIFETIME_MIN', type: 'int', dflt: 60, min: 1,
    max: 43200, runtime: true,
    description: 'How long an issued or renewed token is valid for when the ' +
                 'RST carries no wst:Lifetime. Was the literal 60 in ' +
                 'wstrust.js.' },

  { key: 'wstrust.maxTokenLifetimeMin', group: 'WS-Trust',
    label: 'Longest lifetime a request may ask for (minutes)',
    env: 'STS_WSTRUST_MAX_TOKEN_LIFETIME_MIN', type: 'int', dflt: 1440,
    min: 1, max: 525600, runtime: true,
    description: 'The ceiling on a wst:Lifetime a CLIENT requests. Until ' +
                 '2026-09-12 a requested lifetime replaced the default with ' +
                 'no bound, so any caller could mint a year-long bearer ' +
                 'token by asking — which is wrong in every mode, because ' +
                 'WS-Trust 1.4 section 4.1 makes wst:Lifetime a REQUEST the ' +
                 'STS decides on. Longer requests are clamped, in both ' +
                 'modes, and the RSTR\'s own wst:Lifetime states what was ' +
                 'actually issued.' },

  { key: 'wstrust.jwtAlgorithm', group: 'WS-Trust',
    label: 'JWT signature algorithm',
    env: 'STS_WSTRUST_JWT_ALGORITHM', type: 'enum',
    enumValues: ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512',
                 'ES256', 'ES384', 'ES512', 'EdDSA'],
    dflt: 'RS256', runtime: true,
    description: 'The alg of the JWT this STS returns for TokenType ' +
                 'urn:ietf:params:oauth:token-type:jwt, signed with this ' +
                 'realm\'s key for that algorithm and published in ' +
                 '/oauth2/jwks under the kid in the header. Asymmetric and ' +
                 'classical only: an HMAC would need a secret this exchange ' +
                 'does not have, and a post-quantum signature is computed on ' +
                 'the worker pool, which this synchronous endpoint does not ' +
                 'reach.' },

  certificateHeaderSetting('wstrust.jwtCertificateHeader', 'WS-Trust',
    'STS_WSTRUST_JWT_CERTIFICATE_HEADER', 'JWT certificate header',
    'Whether a JWT this STS returns in a RequestSecurityTokenResponse names ' +
    'the certificate chain of the key that signed it. A SAML assertion ' +
    'carries its certificate in its own XML Signature and is not affected.'),

  // --- WS-Federation -------------------------------------------------------
  // --- WS-Federation assertions --------------------------------------------
  // A GROUP OF ONE, and it earns that the way the two SAML assertion groups do:
  // it is a DEFAULT an application may overrule, and the page it is drawn on is
  // the page that says so. `wsfed.entityId` beside it is this service's own
  // name and no application can have an opinion about it, which is the line
  // between the two groups.
  //
  // IT IS DRAWN ON /admin/saml-assertions rather than on /admin/wsfed, and that
  // is not filing it under the wrong protocol: a WS-Federation sign-in response
  // CARRIES A SAML 1.1 ASSERTION, built by the same buildSaml11Assertion() the
  // SAML 1.1 profiles use, so this row and `saml11.assertionLifetimeMin` decide
  // the same kind of document. Putting it on the WS-Federation page would have
  // separated it from every other setting that governs an assertion's validity.
  //
  // UNTIL 2026-08-27 THIS WAS A MODULE-LEVEL `const lifetimeMin = 60` in
  // ws-federation/wsfed.js and could not be changed at all — which is why the
  // default is 60 rather than something better argued: it is what this service
  // has always issued, and a new default would have changed every existing
  // caller's tokens on an upgrade.
  { key: 'wsfed.assertionLifetimeMin', group: 'WS-Federation assertions',
    label: 'Assertion lifetime (minutes)',
    env: 'STS_WSFED_ASSERTION_LIFETIME_MIN', type: 'int', dflt: 60,
    min: 1, max: 43200, runtime: true,
    description: 'How long the SAML 1.1 assertion inside a WS-Federation ' +
                 'sign-in response is valid for, and the wsu:Lifetime of the ' +
                 'RequestSecurityTokenResponse around it. It is separate ' +
                 'from saml11.assertionLifetimeMin for the reason that ' +
                 'setting\'s own description gives: a browser-profile ' +
                 'assertion is consumed within seconds and a short lifetime ' +
                 'there is a realistic test, where the same value would ' +
                 'expire a WS-Federation session while somebody was reading ' +
                 'the page it signed them into. An application may overrule ' +
                 'it with wsfedAssertionLifetimeMin on its entry.' },

  { key: 'wsfed.entityId', group: 'WS-Federation', label: 'Entity ID',
    env: 'STS_WSFED_ENTITY_ID', legacyEnv: 'STS_ISSUER', type: 'string',
    dflt: 'urn:wstrust:mock:sts', runtime: true,
    description: 'The entityID in the federation metadata at ' +
                 '/FederationMetadata/2007-06/FederationMetadata.xml. Split ' +
                 'from the SAML issuer because the two are different things ' +
                 'that happened to share a value: this names the IdP, that ' +
                 'names whoever signed an assertion.' },

  { key: 'wsfed.mockRpContextTtlMin', group: 'WS-Federation',
    label: 'Mock relying party wctx lifetime (minutes)',
    env: 'STS_WSFED_MOCK_RP_CONTEXT_TTL_MIN', type: 'int', dflt: 30, min: 1,
    max: 1440, runtime: true,
    description: 'How long /wsfed/rp — the NON-SPEC mock relying party — ' +
                 'remembers a wctx it minted so it can check the round trip. ' +
                 'Its own state and nobody else\'s. Was the constant ' +
                 'RP_CONTEXT_TTL_MS in wsfed.js.' },

  // --- TLS -----------------------------------------------------------------
  { key: 'tls.port', group: 'TLS', label: 'TLS port',
    env: 'STS_TLS_PORT', type: 'port', dflt: 8443, runtime: false,
    restartReason: 'the listener is bound when the process starts',
    description: 'The permissive listener: it always asks for a client ' +
                 'certificate, never refuses one, and reports what it saw.' },

  { key: 'tls.mutualPort', group: 'TLS', label: 'Mutual-TLS port',
    env: 'STS_MTLS_PORT', type: 'port', dflt: 9443, runtime: false,
    restartReason: 'the listener is bound when the process starts',
    description: 'The strict listener: node refuses an unverified client ' +
                 'certificate during the handshake, so nothing in this ' +
                 'service runs for one.' },

  { key: 'tls.trustIssuedClientCertificates', group: 'TLS',
    label: 'Trust TLS client certificates issued on the user portal',
    env: 'STS_TLS_TRUST_ISSUED_CLIENT_CERTIFICATES', type: 'bool', dflt: true,
    runtime: false,
    restartReason: 'the service Root is put into the listeners\' client ' +
                   'truststore when their TLS context is built',
    description: 'On adds this service\'s own Root CA to the client ' +
                 'truststore of 8443, 9443 and the main port, so a TLS client ' +
                 'certificate a person issues themselves on /portal/signing-key ' +
                 'verifies and signs them in — in the realm whose TLS client ' +
                 'Issuing CA signed it. A chain through that Root is an ' +
                 'IDENTITY only when the leaf came from a TLS client Issuing ' +
                 'CA with clientAuth: every other key pair this service issues ' +
                 'chains to the same Root and is refused as one (see ' +
                 'common/tls_client_certificates.js). Off leaves the ' +
                 'truststore to /tls/trust and tls.trustAnchorsFile, as it ' +
                 'was before; the portal still issues, and says the ' +
                 'listeners will not accept what it issues.' },

  { key: 'tls.hostnames', group: 'TLS', label: 'Certificate hostnames',
    env: 'STS_TLS_HOSTNAMES', type: 'csv',
    dflt: 'localhost,sts,sts-mock,sts.example.com', runtime: false,
    restartReason:
      'the server certificate is issued at startup for these names',
    description: 'The subjectAltName DNS entries on the certificate both TLS ' +
                 'listeners present. A caller reaches this stack as ' +
                 'localhost from a host run and as sts from a compose ' +
                 'network, so a certificate naming only one of them fails ' +
                 'hostname verification for a reason that is about this ' +
                 'setting rather than about anything being debugged.' },

  { key: 'tls.ips', group: 'TLS', label: 'Certificate IP addresses',
    env: 'STS_TLS_IPS', type: 'csv', dflt: '127.0.0.1', runtime: false,
    restartReason: 'the server certificate is issued at startup for these ' +
                   'addresses',
    description: 'The subjectAltName IP entries on the same certificate.' },

  { key: 'tls.certificateAlgorithms', group: 'TLS',
    label: 'Server certificate algorithms', env: 'STS_TLS_CERT_ALGS',
    type: 'csv', dflt: 'rsa', runtime: false,
    restartReason: 'the certificates are issued when the listeners are bound',
    description: 'Which server certificates the two TLS listeners present: ' +
                 '"rsa" (the default), and any of ml-dsa-44, ml-dsa-65 and ' +
                 'ml-dsa-87. MORE THAN ONE IS THE INTERESTING SETTING — ' +
                 'OpenSSL 3.5 serves whichever certificate matches the ' +
                 'signature algorithms the CLIENT offered, so ' +
                 '"rsa,ml-dsa-65" answers an ordinary client with RSA and a ' +
                 'post-quantum one with ML-DSA over the same port, which is ' +
                 'exactly how a real migration is run. It is not the default ' +
                 'because an ML-DSA certificate is refused by everything ' +
                 'older than OpenSSL 3.5, including the openssl binary in ' +
                 'these images.' },

  { key: 'tls.certificateFile', group: 'TLS',
    label: 'Server certificate file', env: 'STS_TLS_CERT_FILE',
    type: 'string', dflt: '', runtime: false,
    restartReason: 'the certificate is read when the listeners are bound',
    description: 'Serve a certificate somebody else issued instead of the ' +
                 'self-signed one this service makes at every start. Set it ' +
                 'with tls.keyFile; either one alone is refused, because a ' +
                 'certificate and a key that do not go together fail at the ' +
                 'handshake with a message about neither. THE POINT IS THE ' +
                 'NUMBER OF TRUST DECISIONS A CALLER MAKES: a self-signed ' +
                 'certificate regenerated per start is a new anchor every ' +
                 'restart, on a THIRD origin beside the two the debugger ' +
                 'already serves. Handed a leaf that chains to the same root ' +
                 'as those two, one trusted root covers all three and ' +
                 'survives restarts. The file may be a CHAIN — leaf first, ' +
                 'issuers after — and all of it is sent. Unset, which is ' +
                 'the default and what a bare `docker run` gets, nothing ' +
                 'changes.' },

  { key: 'tls.keyFile', group: 'TLS', label: 'Server private key file',
    env: 'STS_TLS_KEY_FILE', type: 'string', dflt: '', runtime: false,
    restartReason: 'the key is read when the listeners are bound',
    description: 'The PKCS#8 or PKCS#1 private key for tls.certificateFile, ' +
                 'unencrypted — this service is never given a passphrase to ' +
                 'prompt for. Set both or neither.' },

  // ---------------------------------------------------------------------
  // THE PROTOCOL FLOOR AND THE CIPHER LIST, FOR EVERY TLS SOCKET THIS PROCESS
  // OWNS (2026-09-12): 8443, 9443, LDAPS 636 and — when global.https is on —
  // the main port. There were none, so each listener took node's defaults
  // silently, which is a policy nobody could see or change.
  //
  // THE DEFAULTS ARE NODE'S OWN, WRITTEN DOWN, so an unedited service
  // negotiates exactly what it did: `tls.DEFAULT_MIN_VERSION` is TLSv1.2 and
  // an empty cipher string means `tls.DEFAULT_CIPHERS`. Restart-only because
  // the secure contexts are built when the listeners are created, and a
  // runtime value would reach a listener only at the next truststore change —
  // the silent disagreement `runtime: false` exists to prevent.
  // ---------------------------------------------------------------------
  { key: 'tls.minVersion', group: 'TLS', label: 'Minimum TLS version',
    env: 'STS_TLS_MIN_VERSION', type: 'enum',
    enumValues: ['TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3'],
    dflt: 'TLSv1.2', runtime: false,
    restartReason: 'the TLS contexts are built when the listeners are created',
    description: 'The lowest protocol version 8443, 9443, LDAPS and the main ' +
                 'HTTPS port will negotiate. TLSv1.2 is node\'s own default ' +
                 'and what this service always did; TLSv1.3 refuses every ' +
                 'client that cannot speak it, which is the setting a ' +
                 'deployment usually wants and a debugger of old clients ' +
                 'usually does not. The two older values exist so a ' +
                 'client\'s downgrade handling can be exercised, and need an ' +
                 'OpenSSL security level that still allows them.' },

  { key: 'tls.ciphers', group: 'TLS', label: 'TLS cipher list',
    env: 'STS_TLS_CIPHERS', type: 'string', dflt: '', runtime: false,
    restartReason: 'the TLS contexts are built when the listeners are created',
    description: 'An OpenSSL cipher list for the TLS 1.2 suites (and, with ' +
                 'TLS_ prefixed names, the TLS 1.3 ones) on the same four ' +
                 'listeners. Empty means node\'s default list, which is what ' +
                 'this service always used. A list matching NO cipher stops ' +
                 'the service at startup naming this setting, rather than ' +
                 'leaving listeners that complete no handshake.' },

  { key: 'tls.trustAnchorsFile', group: 'TLS',
    label: 'Client certificate trust anchors file',
    env: 'STS_TLS_TRUST_ANCHORS_FILE', type: 'string', dflt: '',
    runtime: false,
    restartReason: 'the anchors are read when the listeners are created',
    description: 'A PEM file of CA certificates that client certificates on ' +
                 '8443, 9443 and the main port are verified against, loaded ' +
                 'at startup. It is the PRODUCT-MODE way to fill the ' +
                 'truststore: POST /tls/trust and /tls/trust/clear answer ' +
                 'anybody in development and are refused in product mode, ' +
                 'because an anchor anybody can add is a client certificate ' +
                 'anybody can make verify. Empty means the truststore starts ' +
                 'empty, which is what it always did.' },

  // THE SELF-SIGNED FALLBACK CERTIFICATE'S THREE LITERALS. Used only when
  // neither tls.certificateFile nor this service's own certificate authority
  // supplies the listener certificate; the defaults are the literals the code
  // carried.
  { key: 'tls.selfSignedKeyBits', group: 'TLS',
    label: 'Self-signed certificate RSA key size',
    env: 'STS_TLS_SELF_SIGNED_KEY_BITS', type: 'int', dflt: 2048,
    min: 2048, max: 8192, step: 1024, runtime: false,
    restartReason: 'the certificate is generated when the process starts',
    description: 'The RSA modulus size of the self-signed listener ' +
                 'certificate this service makes at startup. 2048 is the ' +
                 'floor every current client accepts; larger keys cost ' +
                 'startup time and every handshake.' },

  { key: 'tls.selfSignedValidityYears', group: 'TLS',
    label: 'Self-signed certificate validity (years)',
    env: 'STS_TLS_SELF_SIGNED_YEARS', type: 'int', dflt: 2,
    min: 1, max: 30, runtime: false,
    restartReason: 'the certificate is generated when the process starts',
    description: 'How long the self-signed listener certificate is valid. ' +
                 'Short on purpose: it is the certificate a person is told ' +
                 'to trust by hand.' },

  { key: 'tls.selfSignedOrganization', group: 'TLS',
    label: 'Self-signed certificate organization',
    env: 'STS_TLS_SELF_SIGNED_ORGANIZATION', type: 'string',
    dflt: 'sts', runtime: false,
    restartReason: 'the certificate is generated when the process starts',
    description: 'The O= of the self-signed listener certificate\'s subject. ' +
                 'The CN is the first of tls.hostnames.' },

  // --- OID4VCI -------------------------------------------------------------
  { key: 'oid4vci.walletUrl', group: 'OID4VCI', label: 'Wallet URL',
    env: 'OID4VCI_WALLET_URL', type: 'string', dflt: 'http://localhost:3000',
    runtime: true,
    description: 'Where the wallet lives, as a URL the BROWSER can use. The ' +
                 'Credential Offer pages send the End-User here, so it is ' +
                 'the debugger\'s own address rather than anything this ' +
                 'service serves.' },

  { key: 'oid4vci.authorizationServer', group: 'OID4VCI',
    label: 'Authorization server', env: 'OID4VCI_AUTHORIZATION_SERVER',
    type: 'string', dflt: '', runtime: true,
    description: 'Set this to advertise a SEPARATE authorization server in ' +
                 'the credential issuer metadata\'s authorization_servers. ' +
                 'Empty — the default — means this service is its own, which ' +
                 'is the arrangement every test here uses.' },

  { key: 'oid4vci.batchSize', group: 'OID4VCI', label: 'Batch size',
    env: 'OID4VCI_BATCH_SIZE', type: 'int', dflt: 4, runtime: true,
    description: 'batch_credential_issuance.batch_size in the issuer ' +
                 'metadata: how many proofs one credential request may ' +
                 'carry, and therefore how many credentials come back from ' +
                 'it.' },

  { key: 'oid4vci.deferredReadyMs', group: 'OID4VCI',
    label: 'Deferred: ready after (ms)', env: 'OID4VCI_DEFERRED_READY_MS',
    type: 'int', dflt: 4000, runtime: true,
    description: 'How long a deferred credential stays issuance_pending ' +
                 'before it is ready. Long enough that a wallet has to poll ' +
                 'and short enough that a test does not time out.' },

  { key: 'oid4vci.deferredIntervalS', group: 'OID4VCI',
    label: 'Deferred: poll interval (s)', env: 'OID4VCI_DEFERRED_INTERVAL_S',
    type: 'int', dflt: 2, runtime: true,
    description: 'The `interval` this issuer asks a wallet to wait between ' +
                 'deferred polls.' },

  { key: 'oid4vci.offerUsername', group: 'OID4VCI', label: 'Offer username',
    env: 'OID4VCI_OFFER_USERNAME', type: 'string', dflt: 'diploma.student',
    runtime: true,
    description: 'Whose credential the issuer-initiated offer pages build. ' +
                 'The claims come from that person\'s directory entry.' },

  { key: 'oid4vci.requestEncryptionRequired', group: 'OID4VCI',
    label: 'Require encrypted credential requests',
    env: 'OID4VCI_REQUEST_ENCRYPTION_REQUIRED', type: 'bool', dflt: false,
    runtime: true,
    description: 'When on, a credential request that is not a JWE is ' +
                 'refused. The negative worth having: a wallet cannot prove ' +
                 'it encrypts by encrypting when the issuer accepts ' +
                 'plaintext too.' },

  // -------------------------------------------------------------------------
  // THE 2026-09-12 SWEEP, OID4VCI HALF. Every `dflt` below is the literal it
  // replaced. The two that are policy rather than a number —
  // `oid4vci.txCodeMaxAttempts` and `oid4vci.allowedWalletUrls` — are READ
  // ONLY IN PRODUCT MODE, and say so.
  // -------------------------------------------------------------------------
  { key: 'oid4vci.txCodeLength', group: 'OID4VCI',
    label: 'Transaction Code length (digits)',
    env: 'OID4VCI_TX_CODE_LENGTH', type: 'int', dflt: 5, min: 4, max: 12,
    runtime: true,
    description: 'How many digits the Transaction Code a pre-authorized ' +
                 'offer shows on the issuer\'s screen has. Drawn from a ' +
                 'CSPRNG whatever this is — it was Math.random() until ' +
                 '2026-09-12, which is predictable from other values it ' +
                 'produced.' },

  { key: 'oid4vci.txCodeMaxAttempts', group: 'OID4VCI',
    label: 'Wrong Transaction Codes before the code is spent (product)',
    env: 'OID4VCI_TX_CODE_MAX_ATTEMPTS', type: 'int', dflt: 5, min: 1,
    max: 100, runtime: true,
    description: 'IN PRODUCT MODE, how many wrong Transaction Codes a ' +
                 'pre-authorized code survives. The last one SPENDS it, so a ' +
                 'five-digit code cannot be guessed at the token endpoint ' +
                 'inside the offer\'s lifetime; the End-User asks the issuer ' +
                 'for a new offer. Development counts nothing, so a wallet ' +
                 'can be driven through its wrong-code path as often as a ' +
                 'test likes.' },

  { key: 'oid4vci.offerTtlS', group: 'OID4VCI',
    label: 'Credential Offer lifetime (s)',
    env: 'OID4VCI_OFFER_TTL_S', type: 'int', dflt: 600, min: 60, max: 86400,
    runtime: true,
    description: 'How long a Credential Offer, its issuer_state, its ' +
                 'pre-authorized code and a notification_id stay usable.' },

  { key: 'oid4vci.preAuthorizedPollIntervalS', group: 'OID4VCI',
    label: 'Pre-authorized grant: interval (s)',
    env: 'OID4VCI_PRE_AUTHORIZED_POLL_INTERVAL_S', type: 'int', dflt: 5,
    min: 1, max: 3600, runtime: true,
    description: 'The `interval` a pre-authorized_code grant in an offer ' +
                 'names — the seconds a wallet waits between token requests.' },

  { key: 'oid4vci.walletIssuancePath', group: 'OID4VCI',
    label: 'Wallet issuance page',
    env: 'OID4VCI_WALLET_ISSUANCE_PATH', type: 'string',
    dflt: '/vc-issuance-1.html', runtime: true,
    description: 'The page under the wallet URL that a Credential Offer is ' +
                 'handed to. The default is the debugger\'s own wallet page.' },

  { key: 'oid4vci.allowedWalletUrls', group: 'OID4VCI',
    label: 'Other wallet URLs an offer link may name (product)',
    env: 'OID4VCI_ALLOWED_WALLET_URLS', type: 'csv', dflt: '', runtime: true,
    description: 'IN PRODUCT MODE, the wallet URLs besides oid4vci.walletUrl ' +
                 'that the `wallet` query parameter on /issuer/offer may ' +
                 'name. Any other is refused, because an offer link that ' +
                 'sends the End-User wherever its query string says is an ' +
                 'open redirect carrying a pre-authorized code. Development ' +
                 'accepts any URL, which is how a wallet on a laptop is ' +
                 'pointed at this service.' },

  { key: 'oid4vci.requestEncryptionKeyBits', group: 'OID4VCI',
    label: 'Request encryption key size (bits)',
    env: 'OID4VCI_REQUEST_ENCRYPTION_KEY_BITS', type: 'int', dflt: 2048,
    min: 2048, max: 4096, step: 1024, runtime: true,
    description: 'The RSA modulus of the key credential_request_encryption ' +
                 'publishes. Each trust realm has its own key, made when the ' +
                 'realm first needs one, so a change reaches keys made AFTER ' +
                 'it and never a key that exists.' },

  { key: 'oid4vci.requestEncryptionEncValues', group: 'OID4VCI',
    label: 'Request encryption: enc values',
    env: 'OID4VCI_REQUEST_ENCRYPTION_ENC_VALUES', type: 'csv',
    dflt: 'A128GCM,A256GCM', runtime: true,
    description: 'The content encryption algorithms ' +
                 'credential_request_encryption advertises and accepts. Only ' +
                 'A128GCM and A256GCM are implemented; anything else named ' +
                 'here is ignored with a warning rather than advertised, ' +
                 'because metadata that overstates is worse than metadata ' +
                 'that says little.' },

  { key: 'oid4vci.responseEncryptionEncValues', group: 'OID4VCI',
    label: 'Response encryption: enc values',
    env: 'OID4VCI_RESPONSE_ENCRYPTION_ENC_VALUES', type: 'csv',
    dflt: 'A128GCM,A256GCM', runtime: true,
    description: 'The content encryption algorithms ' +
                 'credential_response_encryption advertises and accepts. ' +
                 'Same rule as the request row: A128GCM and A256GCM are ' +
                 'implemented and nothing else is advertised. The key ' +
                 'transport is RSA-OAEP-256, which is the only one ' +
                 'implemented and is not a setting.' },

  { key: 'oid4vci.responseEncryptionRequired', group: 'OID4VCI',
    label: 'Require encrypted credential responses',
    env: 'OID4VCI_RESPONSE_ENCRYPTION_REQUIRED', type: 'bool', dflt: false,
    runtime: true,
    description: 'When on, a credential request that does not ask for an ' +
                 'encrypted response (credential_response_encryption) is ' +
                 'refused, and the metadata says encryption_required: true.' },

  { key: 'oid4vci.credentialLifetimeS', group: 'OID4VCI',
    label: 'Issued credential lifetime (s)',
    env: 'OID4VCI_CREDENTIAL_LIFETIME_S', type: 'int', dflt: 2592000,
    min: 60, max: 315360000, runtime: true,
    description: 'How long every credential this issuer mints is valid — the ' +
                 '`exp` of a dc+sd-jwt and a jwt_vc_json credential and the ' +
                 '`validUntil` of an ldp_vc one. Thirty days by default.' },

  { key: 'oid4vci.credentialSigningAlgorithm', group: 'OID4VCI',
    label: 'Algorithm credentials are signed with',
    env: 'OID4VCI_CREDENTIAL_SIGNING_ALGORITHM', type: 'enum',
    enumValues: ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512',
                 'ES256', 'ES384', 'ES512', 'ES256K', 'EdDSA'],
    dflt: 'RS256', runtime: true,
    description: 'The JWS algorithm dc+sd-jwt and jwt_vc_json credentials ' +
                 'are signed with, and the one the DID Configuration\'s ' +
                 'Domain Linkage Credential and /did/generate\'s did:web ' +
                 'credential use. The metadata\'s ' +
                 'credential_signing_alg_values_supported names it, ' +
                 '/oauth2/jwks and /.well-known/did.json publish the key, ' +
                 'and the mock Verifier checks against it. ldp_vc is ' +
                 'bbs-2023 and is not affected. A credential already issued ' +
                 'keeps the algorithm it was signed with.' },

  certificateHeaderSetting('oid4vci.credentialCertificateHeader', 'OID4VCI',
    'OID4VCI_CREDENTIAL_CERTIFICATE_HEADER', 'Credential certificate header',
    'Whether an issued dc+sd-jwt or jwt_vc_json CREDENTIAL names the ' +
    'certificate chain of the key that signed it. SD-JWT VC names `x5c` as ' +
    'one of the ways a verifier may find an issuer\'s key, so a wallet or ' +
    'verifier that never fetches this issuer\'s metadata can still check ' +
    'the signature against a trust anchor. ldp_vc is not a JWS and is not ' +
    'affected.'),

  certificateHeaderSetting('oid4vci.signedMetadataCertificateHeader',
    'OID4VCI', 'OID4VCI_SIGNED_METADATA_CERTIFICATE_HEADER',
    'Issuer signed_metadata certificate header',
    'Whether the credential issuer metadata\'s `signed_metadata` names the ' +
    'certificate chain of the key that signed it.'),

  { key: 'oid4vci.proofIatWindowS', group: 'OID4VCI',
    label: 'Proof of possession iat window (s)',
    env: 'OID4VCI_PROOF_IAT_WINDOW_S', type: 'int', dflt: 600, min: 30,
    max: 86400, runtime: true,
    description: 'How far a wallet\'s openid4vci-proof+jwt `iat` may be from ' +
                 'now, either way. The c_nonce is what makes a proof single ' +
                 'use; this is what stops one minted long ago being used at ' +
                 'all.' },

  { key: 'oid4vci.cNonceTtlS', group: 'OID4VCI',
    label: 'c_nonce lifetime (s)',
    env: 'OID4VCI_C_NONCE_TTL_S', type: 'int', dflt: 300, min: 30,
    max: 86400, runtime: true,
    description: 'How long a c_nonce from the Nonce Endpoint may be quoted ' +
                 'in a proof; `c_nonce_expires_in` says the same number.' },

  { key: 'oid4vci.issuerDisplayName', group: 'OID4VCI',
    label: 'Issuer display name',
    env: 'OID4VCI_ISSUER_DISPLAY_NAME', type: 'string',
    dflt: 'IdP Tools Mock Credential Issuer', runtime: true,
    description: 'The `display.name` of the credential issuer metadata — ' +
                 'what a wallet shows as who is offering the credential. The ' +
                 'credential configurations\' own display names and colours ' +
                 'are part of the catalogue in oid4vc/vc_issuer.js and are ' +
                 'not settings.' },

  { key: 'oid4vci.domainLinkageLifetimeS', group: 'OID4VCI',
    label: 'Domain Linkage Credential lifetime (s)',
    env: 'OID4VCI_DOMAIN_LINKAGE_LIFETIME_S', type: 'int', dflt: 31536000,
    min: 3600, max: 315360000, runtime: true,
    description: 'How long the Domain Linkage Credential at ' +
                 '/.well-known/did-configuration.json says it is valid. It ' +
                 'is signed per request, so this is the window a cached copy ' +
                 'may be believed for.' },

  { key: 'oid4vci.generatedDidCredentialLifetimeS', group: 'OID4VCI',
    label: '/did/generate credential lifetime (s)',
    env: 'OID4VCI_GENERATED_DID_CREDENTIAL_LIFETIME_S', type: 'int',
    dflt: 3600, min: 60, max: 31536000, runtime: true,
    description: 'How long the SD-JWT VC that /did/generate signs with the ' +
                 'DID it hands back is valid.' },

  // ---------------------------------------------------------------------
  // THE TWO DID FLAGS, which were the last two environment variables in this
  // service with no row here.
  //
  // They were read in `oid4vc/vc_did.js` as
  // `didFlag('OID4VCI_SD_JWT_ISSUER_DID')` — a module-level const, compared
  // against the literal string 'true' — which is the shape every setting in
  // this table used to have. Two consequences, and the second is why they moved
  // rather than being left alone: they were undocumentable as appconfig entries
  // because they were not appconfig entries, and `OID4VCI_LDP_VC_ISSUER_DID=1`
  // did nothing at all while `=true` worked, because that comparison was not
  // the `bool` type's.
  //
  // Restart-only, and honestly so: `vc_did.js` reads them once at require time
  // into the two constants its metadata is built from, so a runtime change
  // would leave the credential and the metadata describing it disagreeing
  // about how the issuer is named — which is the "reads as having worked"
  // failure the header warns about.
  { key: 'oid4vci.sdJwtIssuerDid', group: 'OID4VCI',
    label: 'Name the SD-JWT VC issuer by DID',
    env: 'OID4VCI_SD_JWT_ISSUER_DID', type: 'bool', dflt: false,
    runtime: false,
    restartReason: 'vc_did.js reads it once at require time, and the issuer ' +
                   'metadata is built from what it read',
    description: 'Switch the PLAIN dc+sd-jwt credential configuration over ' +
                 'to naming its issuer by did:web instead of by https URL — ' +
                 'what a deployment that had gone to DIDs throughout would ' +
                 'look like. OFF, because draft-ietf-oauth-sd-jwt-vc defines ' +
                 'no DID-based issuer signature mechanism, so this is an ' +
                 'extension and the spec\'s own route ' +
                 '(/.well-known/jwt-vc-issuer) is what the plain ' +
                 'configuration must go on exercising. The ' +
                 'IdentityCredentialDid configuration always names the ' +
                 'issuer by DID whatever this is, so both routes can be ' +
                 'compared in one issuer.' },

  { key: 'oid4vci.ldpVcIssuerDid', group: 'OID4VCI',
    label: 'Name the ldp_vc issuer by DID',
    env: 'OID4VCI_LDP_VC_ISSUER_DID', type: 'bool', dflt: false,
    runtime: false,
    restartReason: 'vc_did.js reads it once at require time, and the issuer ' +
                   'metadata is built from what it read',
    description: 'The same for the PLAIN ldp_vc configuration. VC Data Model ' +
                 '2.0 and Data Integrity are DID-native and naming the ' +
                 'issuer by DID is ordinary there, so this one is off for a ' +
                 'narrower reason: ldp_vc\'s verificationMethod is an https ' +
                 'URL that existing tests dereference, and switching it to a ' +
                 'DID URL breaks them silently.' },

  // --- OID4VP --------------------------------------------------------------
  { key: 'oid4vp.clientId', group: 'OID4VP', label: 'Verifier client ID',
    env: 'OID4VP_CLIENT_ID', type: 'string', dflt: 'sts-verifier',
    runtime: true,
    description: 'The client_id the mock Verifier presents in its ' +
                 'Authorization Request, and the `aud` the Key Binding JWT ' +
                 'must name.' },

  { key: 'oid4vp.walletUrl', group: 'OID4VP', label: 'Wallet URL',
    env: 'OID4VP_WALLET_URL', type: 'string',
    dflt: function () {
      log.debug("Entering dflt().");
      log.debug("Leaving dflt().");
      return value('oid4vci.walletUrl');
    }, runtime: true,
    derived: true,
    description: 'Where the Verifier sends the holder to present. Falls back ' +
                 'to the OID4VCI wallet URL, since it is the same wallet in ' +
                 'every arrangement this service is used in.' },

  certificateHeaderSetting('oid4vp.requestObjectCertificateHeader', 'OID4VP',
    'OID4VP_REQUEST_OBJECT_CERTIFICATE_HEADER',
    'Request Object certificate header',
    'Whether the mock Verifier\'s signed REQUEST OBJECT (RFC 9101, a request ' +
    'by reference) names the certificate chain of the key that signed it.'),

  { key: 'oid4vp.kbMaxAgeS', group: 'OID4VP', label: 'Key Binding max age (s)',
    env: 'OID4VP_KB_MAX_AGE_S', type: 'int', dflt: 600, runtime: true,
    description: 'How old a Key Binding JWT\'s `iat` may be before the ' +
                 'Verifier rejects the presentation as a replay.' },

  { key: 'oid4vp.claims', group: 'OID4VP', label: 'Requested claims',
    env: 'OID4VP_CLAIMS', type: 'csv', dflt: 'given_name,family_name',
    runtime: true,
    description: 'The mock Verifier\'s STARTING request, and — this is the ' +
                 'part worth knowing — the target its Reset returns to. It ' +
                 'is not the live list: /admin/vc-verifier-config owns that, ' +
                 'and copies this at startup. So changing it here changes ' +
                 'what the next Reset produces, and the request on the wire ' +
                 'only once that Reset is pressed (or POST ' +
                 '/admin-api/verifier-request/reset is called). It is a ' +
                 'reset target rather than a live value on purpose: a ' +
                 'deployment that configured this should get ITS list back ' +
                 'from Reset and not the catalogue\'s defaults. A claim this ' +
                 'issuer does not mint is a legitimate thing to ask for and ' +
                 'is how the "not satisfied" path is reached.' },

  // THE 2026-09-12 SWEEP, OID4VP HALF. Every `dflt` is the literal it replaced;
  // `oid4vp.allowedWalletUrls` is read only in product mode.
  { key: 'oid4vp.presentationRequestTtlS', group: 'OID4VP',
    label: 'Presentation request lifetime (s)',
    env: 'OID4VP_PRESENTATION_REQUEST_TTL_S', type: 'int', dflt: 600,
    min: 60, max: 86400, runtime: true,
    description: 'How long a presentation request — its nonce, state and ' +
                 'Request Object — may wait for a wallet\'s response.' },

  { key: 'oid4vp.walletPresentationPath', group: 'OID4VP',
    label: 'Wallet presentation page',
    env: 'OID4VP_WALLET_PRESENTATION_PATH', type: 'string',
    dflt: '/vc-presentation-1.html', runtime: true,
    description: 'The page under the wallet URL a presentation request is ' +
                 'handed to. The default is the debugger\'s own wallet page.' },

  { key: 'oid4vp.allowedWalletUrls', group: 'OID4VP',
    label: 'Other wallet URLs a request link may name (product)',
    env: 'OID4VP_ALLOWED_WALLET_URLS', type: 'csv', dflt: '', runtime: true,
    description: 'IN PRODUCT MODE, the wallet URLs besides oid4vp.walletUrl ' +
                 'that the `wallet` query parameter on the Verifier\'s start ' +
                 'page may name; any other is refused as an open redirect. ' +
                 'Development accepts any URL.' },

  { key: 'oid4vp.trustedIssuerCertificates', group: 'OID4VP',
    label: 'Other trusted credential issuers (PEM)',
    env: 'OID4VP_TRUSTED_ISSUER_CERTIFICATES', type: 'string', dflt: '',
    runtime: true,
    description: 'PEM certificates, concatenated, whose keys the mock ' +
                 'Verifier accepts an SD-JWT VC or jwt_vc_json credential ' +
                 'signature from IN ADDITION to this realm\'s own issuer. ' +
                 'Empty — the default — trusts this issuer alone, which is ' +
                 'what it always did. A certificate is used as a KEY: no ' +
                 'chain is built and no revocation is checked.' },

  { key: 'oid4vp.expectedVct', group: 'OID4VP',
    label: 'Expected SD-JWT VC type (vct)',
    env: 'OID4VP_EXPECTED_VCT', type: 'string',
    dflt: 'urn:idptools:sd-jwt-vc:identity', runtime: true,
    description: 'The `vct` the Verifier requires of a presented SD-JWT VC. ' +
                 'The default is the type this issuer mints; set it to ' +
                 'accept a credential another issuer mints under its own ' +
                 'type.' },

  { key: 'oid4vp.maxRequestedClaims', group: 'OID4VP',
    label: 'Claims one request may ask for',
    env: 'OID4VP_MAX_REQUESTED_CLAIMS', type: 'int', dflt: 40, min: 1,
    max: 1000, runtime: true,
    description: 'The most claims /admin/vc-verifier-config lets the ' +
                 'Verifier\'s request name.' },

  // --- Kerberos ------------------------------------------------------------
  //
  // **A TRUST REALM HAS A KERBEROS OF ITS OWN SINCE 2026-09-15**, on the same
  // port 88, routed by the Kerberos realm name inside each request. The rows a
  // realm's principal database is BUILT from are `realmRuntime`: restart-only
  // for the process, whose database is built when it starts, and settable on a
  // realm, whose database is built when its Kerberos is turned on and again
  // whenever one of them changes (kerberos/krb5_principals.js). The sockets and
  // the development-mode trust with krb5.trustedRealm stay the process's.
  { key: 'krb5.enabled', group: 'Kerberos', label: 'Enable Kerberos',
    env: 'KRB5_ENABLED', type: 'bool', dflt: true, runtime: true,
    description: 'Whether this realm\'s KDC answers. ON THE SERVICE AS A ' +
                 'WHOLE it is on, which is the service this repository has ' +
                 'always been; the sockets on krb5.kdcPort stay bound either ' +
                 'way. **ON A TRUST REALM it decides whether that realm ' +
                 'has a Kerberos realm at all**, and a realm is CREATED WITH ' +
                 'IT OFF. Turning it on is refused until the realm has a ' +
                 'krb5.realm of its own that no other realm answers to — ' +
                 'port 88 routes a request by that name — and it builds that ' +
                 'realm\'s principal database from its own settings.' },

  { key: 'krb5.realm', group: 'Kerberos', label: 'Realm',
    env: 'KRB5_REALM', type: 'string', dflt: 'EXAMPLE.COM', runtime: false,
    realmRuntime: true,
    restartReason: 'the principal database and every long-term key in it ' +
                   'are derived from the realm at startup. A TRUST REALM may ' +
                   'carry it even so: a realm is created with Kerberos off ' +
                   'and ' +
                   'builds its database when it is turned on, so nothing ' +
                   'about a realm\'s name was consumed at startup — and it ' +
                   'cannot be changed while that realm\'s Kerberos is on',
    description: 'The realm this KDC serves. Its lower-cased form is the ' +
                 'domain, which is where the default service domains and the ' +
                 'PAC\'s domain name come from. On a trust realm it is the ' +
                 'name port 88 routes that realm\'s requests by: it must be ' +
                 'set before krb5.enabled, no two realms may share it (nor ' +
                 'krb5.trustedRealm), and it is compared without regard to ' +
                 'case when that is checked.' },

  { key: 'krb5.kdcPort', group: 'Kerberos', label: 'KDC port',
    env: 'KRB5_KDC_PORT', type: 'port', dflt: 88, runtime: false,
    restartReason: 'the TCP and UDP sockets are bound when the process starts',
    description: 'The KDC listens on TCP and UDP alike. 88 is privileged, so ' +
                 'a host run that is not root fails to bind it — which is ' +
                 'recorded rather than thrown, and reported by GET ' +
                 '/krb5/principals. 0 asks for any free port.' },

  { key: 'krb5.servicePort', group: 'Kerberos', label: 'Test service port',
    env: 'KRB5_SERVICE_PORT', type: 'port', dflt: 8888, runtime: false,
    restartReason: 'the socket is bound when the process starts',
    description: 'The Kerberized test service that accepts an AP-REQ.' },

  { key: 'krb5.servicePrincipal', group: 'Kerberos', label: 'Service principal',
    env: 'KRB5_SERVICE_PRINCIPAL', type: 'string',
    dflt: 'HTTP/web.example.com', runtime: false,
    realmRuntime: true,
    restartReason: 'the account and its long-term keys are created at startup' +
                   REALM_BUILDS_ITS_OWN,
    description: 'The SPN that test service holds, in the usual ' +
                 'service/hostname form. The account the acceptor decrypts ' +
                 'with is created FROM this name, with krb5.servicePassword ' +
                 'and krb5.serviceSalt — until 2026-09-12 it was always ' +
                 'HTTP/web.<realm domain> whatever this said.' },

  { key: 'krb5.servicePassword', group: 'Kerberos',
    label: 'Service principal password', env: 'KRB5_SERVICE_PASSWORD',
    type: 'string', dflt: 'service-account-password', runtime: false,
    realmRuntime: true,
    restartReason: 'the service account\'s long-term keys are derived from ' +
                   'it at startup' +
                   REALM_BUILDS_ITS_OWN,
    description: 'The password of the account krb5.servicePrincipal names — ' +
                 'the equivalent of a keytab. In PRODUCT MODE the shipped ' +
                 'default is refused: that value is printed in this ' +
                 'repository, so a service key derived from it is a key ' +
                 'anybody can forge a ticket to. With it unset the service ' +
                 'account is not created, the acceptor on ' +
                 'krb5.servicePort and /authn/spnego accept no ticket, and ' +
                 'GET /krb5/service says why. Set it to the password of the ' +
                 'SPN\'s account in the KDC that issues its tickets.' },

  { key: 'krb5.serviceSalt', group: 'Kerberos', label: 'Service principal salt',
    env: 'KRB5_SERVICE_SALT', type: 'string', dflt: '', runtime: false,
    realmRuntime: true,
    restartReason: 'the service account\'s long-term keys are derived from ' +
                   'it at startup' +
                   REALM_BUILDS_ITS_OWN,
    description: 'The string-to-key salt for that account. Empty means this ' +
                 'service\'s convention — the realm followed by the service ' +
                 'name and the host\'s first label (EXAMPLE.COMHTTPweb). A ' +
                 'real Active Directory account is salted with the realm and ' +
                 'its sAMAccountName, which nothing in the SPN reveals, so ' +
                 'an acceptor for tickets from a real KDC needs this set.' },

  { key: 'krb5.enctypes', group: 'Kerberos', label: 'Encryption types',
    env: 'KRB5_ENCTYPES', type: 'csv', dflt: '18,17,20,19,23',
    runtime: false,
    realmRuntime: true,
    restartReason: 'every principal\'s supported encryption types are fixed ' +
                   'at startup' +
                   REALM_BUILDS_ITS_OWN,
    description: 'The encryption types this KDC and acceptor use at all, as ' +
                 'RFC 3961 numbers, strongest first: 18 ' +
                 'aes256-cts-hmac-sha1-96, 17 aes128-cts-hmac-sha1-96, 20 ' +
                 'aes256-cts-hmac-sha384-192, 19 aes128-cts-hmac-sha256-128, ' +
                 '23 rc4-hmac. The default includes RC4 so a client that ' +
                 'still needs it can be exercised; removing 23 is what a ' +
                 'hardened domain does, and then the rc4only account stops ' +
                 'working exactly as it would there. A number the Kerberos ' +
                 'codec does not implement stops the service at startup ' +
                 'naming it.' },

  { key: 'krb5.kvno', group: 'Kerberos', label: 'Key version number',
    env: 'KRB5_KVNO', type: 'int', dflt: 3, min: 1, max: 2147483647,
    runtime: false,
    realmRuntime: true,
    restartReason: 'every principal\'s key version is fixed at startup' +
                   REALM_BUILDS_ITS_OWN,
    description: 'The key version number every account BUILT FROM A PASSWORD ' +
                 'IN THIS CONFIGURATION holds — krbtgt, the acceptor\'s ' +
                 'account, and in development every fixture and on-demand ' +
                 'account — which is what KRB_AP_ERR_BADKEYVER compares. For ' +
                 'those, rotation is not modelled and changing this makes ' +
                 'every ticket issued under the old one fail that check. ' +
                 'Since 2026-09-12 it is also the STARTING kvno of the two ' +
                 'kinds of principal whose keys are stored rather than ' +
                 'configured: a directory person\'s first keys (product ' +
                 'mode) and a service principal created at ' +
                 '/admin/kerberos/principals. Those two DO rotate — a ' +
                 'password change and a Rotate each add one to the stored ' +
                 'kvno — and changing this setting later moves neither.' },

  { key: 'krb5.ticketLifetimeSeconds', group: 'Kerberos',
    label: 'Ticket lifetime (s)', env: 'KRB5_TICKET_LIFETIME_S', type: 'int',
    dflt: 36000, min: 60, max: 31536000, runtime: true,
    description: 'The longest a ticket this KDC issues is valid for when the ' +
                 'client asks for more (or names no till). Ten hours is ' +
                 'Active Directory\'s default.' },

  { key: 'krb5.renewLifetimeSeconds', group: 'Kerberos',
    label: 'Renewable lifetime (s)', env: 'KRB5_RENEW_LIFETIME_S', type: 'int',
    dflt: 604800, min: 60, max: 31536000, runtime: true,
    description: 'How far renew-till reaches for a ticket issued renewable. ' +
                 'Seven days is Active Directory\'s default.' },

  { key: 'krb5.logonServer', group: 'Kerberos', label: 'PAC logon server',
    env: 'KRB5_LOGON_SERVER', type: 'string', dflt: 'DC01', runtime: true,
    description: 'The LogonServer name in every PAC\'s KERB_VALIDATION_INFO ' +
                 '([MS-PAC] 2.5): the NetBIOS name of the domain controller ' +
                 'that authenticated the user.' },

  { key: 'krb5.maxRequestBytes', group: 'Kerberos',
    label: 'Largest KDC request over TCP (bytes)',
    env: 'KRB5_MAX_REQUEST_BYTES', type: 'int', dflt: 131072,
    min: 1024, max: 16777216, runtime: true,
    description: 'The most a client may send on one TCP connection to the ' +
                 'KDC before it is closed. A cap on memory an ' +
                 'unauthenticated caller controls.' },

  { key: 'krb5.udpMaxReplyBytes', group: 'Kerberos',
    label: 'Largest KDC reply over UDP (bytes)',
    env: 'KRB5_UDP_MAX_REPLY_BYTES', type: 'int', dflt: 1465,
    min: 512, max: 65507, runtime: true,
    description: 'A reply larger than this over UDP is answered ' +
                 'KRB_ERR_RESPONSE_TOO_BIG so the client retries over TCP, ' +
                 'which is what a real KDC does. 1465 is the MIT default.' },

  { key: 'krb5.serviceMaxTokenBytes', group: 'Kerberos',
    label: 'Largest AP-REQ the acceptor reads (bytes)',
    env: 'KRB5_SERVICE_MAX_TOKEN_BYTES', type: 'int', dflt: 65536,
    min: 1024, max: 16777216, runtime: true,
    description: 'The acceptor on krb5.servicePort, and SPNEGO over HTTP, ' +
                 'refuse a token larger than this.' },

  { key: 'krb5.replayCacheMaxEntries', group: 'Kerberos',
    label: 'Replay cache size', env: 'KRB5_REPLAY_CACHE_MAX_ENTRIES',
    type: 'int', dflt: 10000, min: 100, max: 10000000, runtime: true,
    description: 'How many Authenticators the acceptor remembers inside the ' +
                 'replay window. When it is full of entries still inside the ' +
                 'window the acceptor REFUSES a new Authenticator rather ' +
                 'than forgetting one that could still be replayed.' },

  { key: 'krb5.spnegoPendingTtlSeconds', group: 'Kerberos',
    label: 'Unfinished SPNEGO negotiation lifetime (s)',
    env: 'KRB5_SPNEGO_PENDING_TTL_S', type: 'int', dflt: 120,
    min: 1, max: 3600, runtime: true,
    description: 'How long a request-mic exchange may sit between its two ' +
                 'HTTP requests.' },

  { key: 'krb5.spnegoMaxPending', group: 'Kerberos',
    label: 'Unfinished SPNEGO negotiations held',
    env: 'KRB5_SPNEGO_MAX_PENDING', type: 'int', dflt: 64,
    min: 1, max: 100000, runtime: true,
    description: 'How many of those are held at once; past it the oldest is ' +
                 'dropped and that client has to start again.' },

  { key: 'krb5.clockSkew', group: 'Kerberos', label: 'Clock skew (s)',
    env: 'KRB5_CLOCK_SKEW', type: 'int', dflt: 300, runtime: true,
    description: 'How far apart the KDC will let its clock and a client\'s ' +
                 'be. RFC 4120 suggests five minutes and this is where ' +
                 'KRB_AP_ERR_SKEW comes from.' },

  { key: 'krb5.clockOffset', group: 'Kerberos', label: 'Clock offset (s)',
    env: 'KRB5_CLOCK_OFFSET', type: 'int', dflt: 0, runtime: true,
    description: 'Moves this KDC\'s clock deliberately, so a skew failure ' +
                 'can be produced on purpose rather than by changing the ' +
                 'machine\'s time.' },

  { key: 'krb5.userPassword', group: 'Kerberos', label: 'User password',
    env: 'KRB5_USER_PASSWORD', type: 'string', dflt: 'password!',
    runtime: false,
    realmRuntime: true,
    restartReason:
      'every user\'s long-term keys are derived from it at startup' +
                   REALM_BUILDS_ITS_OWN,
    description: 'The password every user account here has. It is PUBLISHED ' +
                 'by GET /krb5/principals on purpose: a debugger whose ' +
                 'accounts are unusable without reading the source is worse ' +
                 'than one that says what they are.' },

  { key: 'krb5.unknownUsers', group: 'Kerberos', label: 'Names that stay ' +
                                                        'unknown',
    env: 'KRB5_UNKNOWN_USERS', type: 'csv', dflt: 'nosuchuser,nobody',
    runtime: true,
    description: 'Usernames this KDC refuses to create on demand, so ' +
                 'KDC_ERR_C_PRINCIPAL_UNKNOWN stays reachable. It is one of ' +
                 'the errors most worth producing on purpose, because a ' +
                 'client that renders it as "wrong password" sends somebody ' +
                 'off to reset a password that was never the problem.' },

  { key: 'krb5.serviceDomains', group: 'Kerberos', label: 'Auto-created ' +
      'service domains',
    env: 'KRB5_SERVICE_DOMAINS', type: 'csv', derived: true,
    dflt: function () {
      log.debug("Entering dflt().");
      log.debug("Leaving dflt().");
      return value('krb5.realm').toLowerCase() + ',localhost,sts,127.0.0.1';
    },
    runtime: false,
    restartReason: 'the service accounts are created at startup',
    description: 'The host domains a service principal is created on demand ' +
                 'for. Setting it to an empty string creates nothing, which ' +
                 'is the behaviour this service had before the setting ' +
                 'existed.' },

  { key: 'krb5.autoServicePassword', group: 'Kerberos',
    label: 'Auto-created service password', env: 'KRB5_AUTO_SERVICE_PASSWORD',
    type: 'string', dflt: 'auto-service-password', runtime: false,
    realmRuntime: true,
    restartReason: 'those accounts\' long-term keys are derived from it at ' +
                   'startup' +
                   REALM_BUILDS_ITS_OWN,
    description: 'One password for every service created on demand, and it ' +
                 'is published for the same reason the user password is: it ' +
                 'is what lets a reader decrypt a service ticket this mock ' +
                 'issued and read the PAC inside it. The CONFIGURED service ' +
                 'accounts keep their own separate passwords.' },

  { key: 'krb5.krbtgtPassword', group: 'Kerberos', label: 'krbtgt password',
    env: 'KRB5_KRBTGT_PASSWORD', type: 'string', dflt: 'krbtgt-mock-password',
    runtime: false,
    realmRuntime: true,
    restartReason: 'the krbtgt keys are derived from it at startup' +
                   REALM_BUILDS_ITS_OWN,
    description: 'The key that seals every Ticket-Granting Ticket this realm ' +
                 'issues.' },

  { key: 'krb5.domainSid', group: 'Kerberos', label: 'Domain SID',
    env: 'KRB5_DOMAIN_SID', type: 'string',
    dflt: 'S-1-5-21-1004336348-1177238915-682003330', runtime: false,
    realmRuntime: true,
    restartReason: 'every principal\'s PAC identity is built at startup' +
                   REALM_BUILDS_ITS_OWN,
    description: 'The domain SID every account\'s PAC is built under. A ' +
                 'Kerberos ticket says who you are; a Windows service ' +
                 'authorizes on the SIDs in the PAC.' },

  { key: 'krb5.trustedRealm', group: 'Kerberos', label: 'Trusted realm',
    env: 'KRB5_TRUSTED_REALM', type: 'string', dflt: 'PARTNER.COM',
    runtime: false,
    restartReason: 'the second realm and the trust between them are built at ' +
                   'startup',
    description: 'The second realm, for cross-realm referrals. A trust is ' +
                 'not a flag: it is a shared key held by one principal in ' +
                 'each realm.' },

  { key: 'krb5.trustPassword', group: 'Kerberos', label: 'Trust password',
    env: 'KRB5_TRUST_PASSWORD', type: 'string',
    dflt: 'inter-realm-trust-password', runtime: false,
    restartReason: 'the inter-realm key is derived from it at startup',
    description: 'The shared secret both realms hold for the cross-realm ' +
                 'trust.' },

  { key: 'krb5.trustedDomainSid', group: 'Kerberos',
    label: 'Trusted domain SID',
    env: 'KRB5_TRUSTED_DOMAIN_SID', type: 'string',
    dflt: 'S-1-5-21-2035427030-2118130302-1178042555', runtime: false,
    restartReason: 'the trusted realm\'s principals are built at startup',
    description: 'The other realm\'s domain SID. It differs from this one on ' +
                 'purpose: SID filtering across a trust is about whose ' +
                 'domain a SID belongs to.' },

  { key: 'krb5.trustedKrbtgtPassword', group: 'Kerberos',
    label: 'Trusted realm krbtgt password',
    env: 'KRB5_TRUSTED_KRBTGT_PASSWORD', type: 'string',
    dflt: 'partner-krbtgt-password', runtime: false,
    restartReason: 'that realm\'s krbtgt keys are derived from it at startup',
    description: 'The krbtgt password of the trusted realm.' },

  // ---------------------------------------------------------------------
  // THE TWO THAT TURN A KERBEROS TICKET INTO A SIGN-IN, and they are two
  // rather than one because they answer different questions. The first is
  // whether /authn/spnego will mint a SESSION; the second is whether the
  // sign-in screen advertises it. A deployment that wants the door for a
  // scripted client and not for people at a browser sets the second false, and
  // a screen offering a button to a closed door is what the first prevents.
  //
  // BOTH ARE `runtime: true` AND DEFAULT ON. On, because a mock whose newest
  // authentication mechanism has to be switched on before it can be exercised
  // is one nobody exercises — and because nothing here becomes more permissive
  // by it: past that door a person still has to hold a ticket this service's
  // own acceptor accepts, which is the one credential check in this repository
  // that is real. Runtime, because both are read at the moment they are used
  // and neither binds a socket or derives a key.
  // ---------------------------------------------------------------------
  { key: 'krb5.spnegoAuthentication', group: 'Kerberos',
    label: 'Sign in with a Kerberos ticket',
    env: 'KRB5_SPNEGO_AUTHENTICATION', type: 'bool', dflt: true,
    runtime: true,
    description: 'Whether /authn/spnego turns a Kerberos ticket into a ' +
                 'browser session — integrated authentication, available to ' +
                 'every application and to none in particular. With it off ' +
                 'that endpoint answers 403 saying which setting it was, and ' +
                 '/spnego/protected still performs the whole handshake and ' +
                 'shows you both halves of it; what it will not do is give ' +
                 'you a session. An application or a federation relationship ' +
                 'that names the `spnego` mechanism while this is off is ' +
                 'REPORTED on the sign-in screen rather than meeting a 403 ' +
                 'halfway through a flow.' },

  // ---------------------------------------------------------------------
  // A DIRECTORY PERSON'S KERBEROS KEYS (2026-09-12). The one setting the
  // feature needed, and it is a switch rather than a tuning knob: whether a
  // product-mode service puts PASSWORD-EQUIVALENT key material on people's
  // directory entries at all. A deployment whose Kerberos is a real KDC
  // somewhere else — which uses this service only as an ACCEPTOR — has no
  // reason to hold one, and should be able to say so.
  // ---------------------------------------------------------------------
  { key: 'krb5.personKeys', group: 'Kerberos',
    label: 'Kerberos keys for directory people',
    env: 'KRB5_PERSON_KEYS', type: 'bool', dflt: true,
    runtime: true,
    description: 'PRODUCT MODE ONLY. Whether a person\'s Kerberos long-term ' +
                 'keys are derived from their password — when it is set, and ' +
                 'when a sign-in verifies it — and stored, sealed under the ' +
                 'key-encryption key, on their own directory entry, so that ' +
                 'this KDC authenticates them with that password. Off, no ' +
                 'new keys are derived and the KDC refuses every person, ' +
                 'naming this setting; keys already stored stay until they ' +
                 'are cleared at /admin/kerberos/principals. The keys are as ' +
                 'good as the password to whoever can open them, which is ' +
                 'why this can be switched off. Development mode never reads ' +
                 'it: its KDC keys every user from krb5.userPassword.' },

  // ---------------------------------------------------------------------------
  // PREVIOUS KEY VERSIONS (2026-09-12). A password change or a service-key
  // rotation used to strand every ticket issued under the old key at once —
  // KRB_AP_ERR_BADKEYVER at the very next AP-REQ — where a real KDC keeps the
  // previous kvno in its database and a service keeps it in its keytab until
  // the tickets under it have expired. These two rows are that window, and they
  // bound it in the two ways it has to be bounded: how MANY old versions, and
  // how LONG each. Both are read at every write AND every read, so lowering
  // either takes effect on the next request; raising one never brings back a
  // version already past the bound it was retired under.
  // ---------------------------------------------------------------------------
  { key: 'krb5.retainedKeyVersions', group: 'Kerberos',
    label: 'Previous key versions kept',
    env: 'KRB5_RETAINED_KEY_VERSIONS', type: 'int', dflt: 1, min: 0, max: 10,
    runtime: true,
    description: 'How many PREVIOUS key versions a stored Kerberos key keeps ' +
                 'beside the current one — a directory person\'s after a ' +
                 'password change, a service principal\'s after a rotation. ' +
                 'A kept version is used ONLY to decrypt a ticket already ' +
                 'issued under it (a TGS-REQ\'s ticket, or a service ticket ' +
                 'at the acceptor): the KDC always issues under the current ' +
                 'kvno, and pre-authentication accepts the CURRENT key only, ' +
                 'so an old password never signs in. 0 keeps none, which is ' +
                 'what this service did before the setting existed: a ticket ' +
                 'under the previous kvno is refused KRB_AP_ERR_BADKEYVER at ' +
                 'once. A rotation\'s keytab carries every kept version, as ' +
                 'MIT\'s ktadd does. Operators end the window early with ' +
                 '"Drop previous versions" at /admin/kerberos/principals.' },

  { key: 'krb5.retainedKeyTtlS', group: 'Kerberos',
    label: 'Previous key version lifetime (s)',
    env: 'KRB5_RETAINED_KEY_TTL_S', type: 'int', dflt: 0, min: 0, max: 31536000,
    runtime: true,
    description: 'How long a previous key version is kept after it stops ' +
                 'being current. ZERO — the default — means ' +
                 'krb5.ticketLifetimeSeconds plus krb5.clockSkew, read at ' +
                 'the moment the version is checked: that is the longest a ' +
                 'ticket issued under the old key an instant before the ' +
                 'change can still be presented, because no ticket here ' +
                 'outlives the ticket lifetime (a renewal needs an unexpired ' +
                 'ticket and re-encrypts under the current key), and an ' +
                 'acceptor tolerates the clock skew on its end time. A ' +
                 'number is that many seconds instead. A version past its ' +
                 'lifetime is never used again, is left out of every list, ' +
                 'and is removed from storage at the next write of that key. ' +
                 'To keep no previous version at all, set ' +
                 'krb5.retainedKeyVersions to 0.' },

  { key: 'krb5.spnegoLoginButton', group: 'Kerberos',
    label: 'Offer Kerberos at the sign-in screen',
    env: 'KRB5_SPNEGO_LOGIN_BUTTON', type: 'bool', dflt: true,
    runtime: true,
    description: 'Show a "Sign in with Kerberos" button on /authn/login, so ' +
                 'a ticket can satisfy ANY flow already in progress — an ' +
                 'OAuth 2.0 authorization request, a WS-Federation sign-in, ' +
                 'a SAML AuthnRequest, the admin console. That is the same ' +
                 'reason federation.loginButtons exists and it needs no ' +
                 'registration at all here: whether a person can use a ' +
                 'ticket is a fact about their machine and not about the ' +
                 'relying party. The button is withheld from a request that ' +
                 'demanded two factors, and says so, because a ticket claims ' +
                 'whatever its own flags claim.' },

  { key: 'krb5.s2kparams', group: 'Kerberos', label: 'Send s2kparams',
    env: 'KRB5_S2KPARAMS', type: 'enum', enumValues: ['omit', 'send'],
    dflt: 'omit', runtime: true,
    description: 'Whether PA-ETYPE-INFO2 carries s2kparams. Windows Server ' +
                 'omits it and this mock sent it, which is the one ' +
                 'difference the captured real-DC exchange found; omit is ' +
                 'therefore the default and send is kept so a client that ' +
                 'reads it can be exercised.' },

  // --- LDAP ----------------------------------------------------------------
  { key: 'ldap.port', group: 'LDAP', label: 'LDAP port',
    env: 'LDAP_PORT', type: 'port', dflt: 389, runtime: false,
    restartReason: 'the socket is bound when the process starts',
    description: 'The plain LDAP listener. 389 is privileged, so a host run ' +
                 'that is not root fails to bind it — recorded rather than ' +
                 'thrown, and reported by GET /admin/ldap/service.' },

  { key: 'ldap.tlsPort', group: 'LDAP', label: 'LDAPS port',
    env: 'LDAPS_PORT', type: 'port', dflt: 636, runtime: false,
    restartReason: 'the socket is bound when the process starts',
    description: 'The LDAPS listener, which serves the certificate the TLS ' +
                 'module generated. It binds independently of 389, so "389 ' +
                 'is up and 636 is not" is an ordinary outcome and each ' +
                 'reports itself separately.' },

  { key: 'ldap.baseDn', group: 'LDAP', label: 'Base DN',
    env: 'LDAP_BASE_DN', type: 'string', dflt: 'dc=example,dc=com',
    runtime: false,
    restartReason: 'the directory tree is built under it at startup',
    description: 'The root of the embedded directory. ou=users and ou=groups ' +
                 'hang off it.' },

  // ON, and the description below is what it actually does. It used to be off
  // with a description about BINDS — "a bind as a name with no entry creates
  // one" — and that behaviour does not exist and never did: the bind handler
  // does not consult this setting, autoCreateUser() skips `protocol === 'ldap'`
  // outright (a bind presents a DN, which already names an object here), and
  // every bind succeeds regardless except the password "invalid". So the stated
  // reason for the default protected nothing, while the default itself turned
  // off the one thing this setting does control.
  //
  // What it cost is worth recording, because it was invisible from every
  // direction: ldap_server.js's own header, docs/ldap.md, docs/mock-sts.md and
  // tests/api_ldap.js all said "on by default", so a directory that stayed
  // empty after somebody signed in read as a broken hook rather than as a
  // setting doing exactly what it was set to.
  { key: 'ldap.autocreateUsers', group: 'LDAP', label: 'Auto-create users',
    env: 'LDAP_AUTOCREATE_USERS', type: 'bool', dflt: true, runtime: true,
    description: 'When on, an entry appears at uid=<name>,ou=users,<base> ' +
                 'the first time anybody authenticates to this service ' +
                 'through ANY protocol. On by default: a directory that ' +
                 'fills up as you use the other protocols is the thing this ' +
                 'one is here to show. An LDAP bind never seeds an entry ' +
                 'either way — the identity a bind presents is a DN, which ' +
                 'already names an object here.' },

  { key: 'ldap.maxEntries', group: 'LDAP', label: 'Maximum entries',
    env: 'LDAP_MAX_ENTRIES', type: 'int', dflt: 2000, runtime: true,
    description: 'How large the directory may grow. A ceiling rather than a ' +
                 'target: entries appear for anybody who authenticates ' +
                 'through any protocol here.' },

  { key: 'ldap.sizeLimit', group: 'LDAP', label: 'Search size limit',
    env: 'LDAP_SIZE_LIMIT', type: 'int', dflt: 500, runtime: true,
    description: 'The server-side size limit for a search, which is what ' +
                 'produces LDAP_SIZE_LIMIT_EXCEEDED.' },

  { key: 'ldap.plainListener', group: 'LDAP', label: 'Plain LDAP listener',
    env: 'LDAP_PLAIN_LISTENER', type: 'bool', dflt: true, runtime: false,
    restartReason: 'the socket is bound when the process starts',
    description: 'Whether the unencrypted listener on ldap.port is started ' +
                 'at all. On by default, which is what this service always ' +
                 'did. Off leaves LDAPS on ldap.tlsPort as the only way in — ' +
                 'which is what a deployment whose binds are VERIFIED ' +
                 '(product mode) wants, since a simple bind on 389 sends the ' +
                 'password in the clear. Product mode with it on logs a ' +
                 'warning at startup saying exactly that.' },

  // WHAT A PERSON MAY CHANGE ON THEIR OWN ENTRY OVER THE SOCKET, in product
  // mode (2026-09-12). An ALLOWLIST because the directory is schemaless and the
  // names that matter look ordinary — `memberOf` grants the console roles,
  // `employeeType` is what the seeded XACML policy decides on, `mail` and `cn`
  // are asserted in tokens. `ldap/ldap_server.js`'s `directoryWriteRefusal()`
  // argues the rule this list is one half of. Per realm, like every runtime
  // setting, since it is read in the realm of the entry being written.
  { key: 'ldap.selfWritableAttributes', group: 'LDAP',
    label: 'Attributes a person may change on their own entry',
    env: 'LDAP_SELF_WRITABLE_ATTRIBUTES', type: 'csv',
    dflt: 'telephoneNumber,mobile,homePhone,displayName,preferredLanguage,' +
          'postalAddress,street,l,st,postalCode,userPassword',
    runtime: true,
    description: 'In PRODUCT mode, the attributes a connection bound as a ' +
                 'person may change on that person\'s OWN entry with an LDAP ' +
                 'modify, comma-separated and matched case-insensitively. ' +
                 'Everything else — every other entry, every add, delete and ' +
                 'rename, and any attribute not named here — needs a ' +
                 'connection bound as somebody holding Admin Write in the ' +
                 'default realm. userPassword still meets the password ' +
                 'policy. Think before adding an attribute a token carries ' +
                 '(mail, cn, givenName, sn) or one a policy reads ' +
                 '(employeeType, memberOf): a person who can write it can ' +
                 'assert it about themselves. Empty lets nobody change ' +
                 'anything on their own entry. Development authorizes no ' +
                 'LDAP write at all.' },

  // --- SCIM ----------------------------------------------------------------
  //
  // SCIM 2.0 provisions into the SAME directory the four settings above
  // describe: there is no separate store and no cap of its own, so
  // `ldap.maxEntries` is what a POST /scim/v2/Users runs out of. That is why
  // there are only four rows here rather than the eight a second store would
  // have needed.
  //
  // All four are RUNTIME, and the two limits are runtime only because
  // `applyCapabilities()` in scim.js is called again at the top of the
  // ServiceProviderConfig handler. Without that they would be captured at
  // require time and the published document would go on advertising the number
  // this process started with while a different one was enforced — a `const` in
  // disguise, and exactly the silent disagreement this file's header warns
  // about.
  { key: 'scim.enabled', group: 'SCIM', label: 'SCIM enabled',
    env: 'SCIM_ENABLED', type: 'bool', dflt: true, runtime: true,
    description: 'When on, the SCIM 2.0 endpoints under /scim/v2 create, ' +
                 'read, replace, patch and delete entries in the embedded ' +
                 'directory. On by default, like every other protocol family ' +
                 'here. Turning it off leaves the routes REGISTERED and ' +
                 'makes them answer 501 rather than 404 — the feature is ' +
                 'off, the URL is not wrong, and those are different ' +
                 'sentences to a client. Nothing on these endpoints checks a ' +
                 'credential; do not put this port on a public address.' },

  { key: 'scim.maxResults', group: 'SCIM', label: 'Maximum results per page',
    env: 'SCIM_MAX_RESULTS', type: 'int', dflt: 200, runtime: true,
    description: 'The largest page a list or a search will return, published ' +
                 'as filter.maxResults in the ServiceProviderConfig and used ' +
                 'as the page size when a client asks for none. A ?count ' +
                 'larger than this is clamped rather than refused, which RFC ' +
                 '7644 section 3.4.2.4 permits — the ListResponse says what ' +
                 'actually happened in itemsPerPage.' },

  { key: 'scim.bulkMaxOperations', group: 'SCIM', label: 'Bulk operation limit',
    env: 'SCIM_BULK_MAX_OPERATIONS', type: 'int', dflt: 100, runtime: true,
    description: 'How many operations one POST /scim/v2/Bulk may carry, ' +
                 'published as bulk.maxOperations. A request carrying more ' +
                 'is refused with 413 and the payloadTooLarge scimType, ' +
                 'which is a reachable negative worth having.' },

  { key: 'scim.bulkMaxPayloadSize', group: 'SCIM', label: 'Bulk payload limit',
    env: 'SCIM_BULK_MAX_PAYLOAD_SIZE', type: 'int', dflt: 1048576,
    runtime: true,
    description: 'The largest BulkRequest body in bytes, published as ' +
                 'bulk.maxPayloadSize and CHECKED against that number rather ' +
                 'than against the express body parser\'s service-wide 5 MB. ' +
                 'A client reads a published limit as a promise, so a ' +
                 'request refused at a different size than the document ' +
                 'names would be the drift this arrangement exists to ' +
                 'prevent.' },

  // --- SCIM authentication -------------------------------------------------
  //
  // The SCIM endpoints are the ONE surface in this service that refuses a
  // caller who presents nothing, and the reason is what they do: they create
  // and delete accounts in a directory fifteen other things read. RFC 7644
  // section 2 defines no credential of its own — it delegates to RFC 7235 and
  // names six schemes — so what these rows configure is which of those six are
  // offered, and what the access control policy behind them is. All of it is
  // still permissive: anybody can get a token, any password but one works over
  // Basic, anybody can register a HOBA key. It is a turnstile rather than a
  // lock, and GET /scim says so in those words.
  //
  // Every row is RUNTIME, which is only true because scim_auth.js reads each
  // one through a function called per request rather than capturing it in a
  // const at require time. Turning a scheme off removes it from the
  // WWW-Authenticate challenge AND from the published ServiceProviderConfig
  // together, because both are built from one table.
  { key: 'scim.authDiscovery', group: 'SCIM', label: 'Authenticate discovery ' +
                                                     'too',
    env: 'SCIM_AUTH_DISCOVERY', type: 'bool', dflt: false, runtime: true,
    description: 'Whether /ServiceProviderConfig, /ResourceTypes and ' +
                 '/Schemas need a credential as well. OFF by default, which ' +
                 'is the bootstrapping argument /tls/trust already makes: ' +
                 'the ServiceProviderConfig is where a client READS which ' +
                 'authentication schemes exist, so requiring a credential to ' +
                 'fetch it means a client must already know the answer to ' +
                 'the question it is asking. RFC 7644 section 4 says nothing ' +
                 'either way, so both are conforming and both are worth ' +
                 'being able to try.' },

  { key: 'scim.authRealm', group: 'SCIM', label: 'Authentication realm',
    env: 'SCIM_AUTH_REALM', type: 'string', dflt: 'SCIM', runtime: true,
    description: 'The protection space named in every WWW-Authenticate ' +
                 'challenge, and — for HTTP Digest and HOBA — a value that ' +
                 'is hashed or signed OVER, so changing it invalidates every ' +
                 'credential computed against the old one. Quotes and ' +
                 'non-ASCII are stripped before it reaches a header, because ' +
                 'node throws on the second and the first would close the ' +
                 'quoted string early.' },

  { key: 'scim.scopeRead', group: 'SCIM', label: 'OAuth scope to read',
    env: 'SCIM_SCOPE_READ', type: 'string', dflt: 'scim:read', runtime: true,
    description: 'The OAuth 2.0 scope an access token must carry to read at ' +
                 '/scim/v2 — the first scope requirement anywhere in this ' +
                 'service. It is published in scopes_supported in both ' +
                 'discovery documents, so a client can find the name it ' +
                 'needs rather than being told it out of band. Any grant ' +
                 'will get it: this authorization server grants what it is ' +
                 'asked, so what the requirement exercises is the CLIENT\'s ' +
                 'handling of a scope rather than this service\'s ' +
                 'willingness to withhold one.' },

  { key: 'scim.scopeWrite', group: 'SCIM', label: 'OAuth scope to write',
    env: 'SCIM_SCOPE_WRITE', type: 'string', dflt: 'scim:write', runtime: true,
    description: 'The scope needed to create, replace, patch, delete or ' +
                 'bulk. It does NOT imply the read scope and the read scope ' +
                 'does not imply it, deliberately: a read-only provisioning ' +
                 'credential is a thing a client has to handle and a server ' +
                 'that treated one scope as both could not produce it.' },

  { key: 'scim.authBearer', group: 'SCIM', label: 'Offer OAuth 2.0 tokens',
    env: 'SCIM_AUTH_BEARER', type: 'bool', dflt: true, runtime: true,
    description: 'Whether an access token is accepted, as Bearer (RFC 6750) ' +
                 'or — when it is bound — as DPoP (RFC 9449). Both are ' +
                 'checked by the same function /oauth2/userinfo and the ' +
                 'three OID4VCI credential endpoints use, so an RFC 8705 ' +
                 'certificate-bound token and the DPoP nonce handshake work ' +
                 'here exactly as they do there. This is the only scheme ' +
                 'with scopes behind it; the others authenticate and may ' +
                 'then do everything.' },

  { key: 'scim.authBasic', group: 'SCIM', label: 'Offer HTTP Basic',
    env: 'SCIM_AUTH_BASIC', type: 'bool', dflt: true, runtime: true,
    description: 'Any username with any password except the reserved ' +
                 '"invalid", which is refused so that a 401 stays reachable. ' +
                 'RFC 7644 section 2 DISCOURAGES this scheme in those words, ' +
                 'and it is offered anyway because it is what a provisioning ' +
                 'client most often meets. No password is checked, so what ' +
                 'it authenticates is a name — and that name is recorded as ' +
                 'an authentication, so it appears on /admin/users and gains ' +
                 'a directory entry like any other identity here.' },

  { key: 'scim.authDigest', group: 'SCIM', label: 'Offer HTTP Digest',
    env: 'SCIM_AUTH_DIGEST', type: 'bool', dflt: true, runtime: true,
    description: 'RFC 7616, with SHA-256, SHA-512-256 and MD5 offered in ' +
                 'that order and the -sess variants accepted. This is the ' +
                 'one scheme here where the password really is checked, ' +
                 'because the response IS a hash over it — so it does what ' +
                 'Kerberos does for the same reason: any username, one ' +
                 'shared password. It makes three otherwise unreachable ' +
                 'negatives available: a wrong password, a stale nonce, and ' +
                 'a replayed nonce count.' },

  { key: 'scim.digestPassword', group: 'SCIM', label: 'The shared Digest ' +
                                                      'password',
    env: 'SCIM_DIGEST_PASSWORD', type: 'string', dflt: 'password!',
    runtime: true,
    description: 'The password every username shares for HTTP Digest — the ' +
                 'same value KRB5_USER_PASSWORD defaults to, so that there ' +
                 'is one fact to remember rather than two. It cannot be ' +
                 '"anything goes" the way a bind or a Basic credential can: ' +
                 'a digest response is a hash over the password, so a server ' +
                 'with no password would not be performing the exchange at ' +
                 'all and a client\'s digest code would go unexercised.' },

  { key: 'scim.digestNonceSeconds', group: 'SCIM', label: 'Digest nonce ' +
      'lifetime',
    env: 'SCIM_DIGEST_NONCE_SECONDS', type: 'int', dflt: 300, runtime: true,
    min: 1,
    description: 'How long a Digest nonce stays usable. After it a ' +
                 'credential is refused with stale=true, which RFC 7616 ' +
                 'section 3.3 says a client should retry with the same ' +
                 'credentials rather than prompting a person — a path most ' +
                 'hand-written clients have never run. Lower it to a few ' +
                 'seconds to make it happen on demand.' },

  { key: 'scim.digestMd5', group: 'SCIM', label: 'Offer MD5 for Digest',
    env: 'SCIM_DIGEST_MD5', type: 'bool', dflt: true, runtime: true,
    description: 'Whether HTTP Digest offers and accepts MD5 beside SHA-256 ' +
                 'and SHA-512-256. On by default because most Digest clients ' +
                 'speak nothing else; RFC 7616 keeps MD5 for backward ' +
                 'compatibility only, and a deployment whose clients speak ' +
                 'SHA-256 should turn it off. Off, an MD5 credential is ' +
                 'refused naming this setting. (Digest itself is never ' +
                 'offered in product mode — see scim.authDigest.)' },

  { key: 'scim.maxDigestNonces', group: 'SCIM', label: 'Digest nonces held',
    env: 'SCIM_MAX_DIGEST_NONCES', type: 'int', dflt: 2000, runtime: true,
    min: 1, max: 1000000,
    description: 'How many issued Digest nonces are remembered. Anybody can ' +
                 'make this service issue one by sending an unauthenticated ' +
                 'request, so it is bounded; past it the oldest is ' +
                 'forgotten. Forgetting a live nonce does NOT re-open a ' +
                 'replay — its nonce-count record goes with it, so a ' +
                 'credential naming it is refused with stale=true and a ' +
                 'conforming client retries.' },

  { key: 'scim.authHoba', group: 'SCIM', label: 'Offer HOBA',
    env: 'SCIM_AUTH_HOBA', type: 'bool', dflt: true, runtime: true,
    description: 'HTTP Origin-Bound Authentication (RFC 7486), the ' +
                 'signature-based scheme RFC 7644 section 2 names and the ' +
                 'only one of the six with no shared secret in it. Also ' +
                 'turns POST /.well-known/hoba/register on or off. The ' +
                 'signature is REALLY verified — RSA with SHA-256, algorithm ' +
                 '0 — for the reason the Digest password really is checked; ' +
                 'what is permissive is that anybody may register any key ' +
                 'for any name.' },

  { key: 'scim.hobaMaxAgeSeconds', group: 'SCIM', label: 'HOBA challenge ' +
      'lifetime',
    env: 'SCIM_HOBA_MAX_AGE_SECONDS', type: 'int', dflt: 600, runtime: true,
    min: 1,
    description: 'The max-age published in the HOBA challenge and enforced ' +
                 'on the signature. RFC 7486 lets a client reuse a challenge ' +
                 'until it expires, so a repeat is NOT a replay here — what ' +
                 'is refused is a repeated (key id, challenge, nonce) ' +
                 'triple, which is a copied credential.' },

  { key: 'scim.maxHobaChallenges', group: 'SCIM', label: 'HOBA challenges held',
    env: 'SCIM_MAX_HOBA_CHALLENGES', type: 'int', dflt: 2000, runtime: true,
    min: 1, max: 1000000,
    description: 'How many issued HOBA challenges are remembered; past it ' +
                 'the oldest is forgotten, and a signature over a forgotten ' +
                 'challenge is refused with a fresh one on the response.' },

  { key: 'scim.maxHobaSeen', group: 'SCIM', label: 'HOBA signatures remembered',
    env: 'SCIM_MAX_HOBA_SEEN', type: 'int', dflt: 5000, runtime: true,
    min: 1, max: 1000000,
    description: 'How many accepted (key id, challenge, nonce) triples are ' +
                 'remembered for replay detection. Triples whose challenge ' +
                 'has already expired are forgotten first; past the bound ' +
                 'the oldest is forgotten AND ITS CHALLENGE WITH IT, so the ' +
                 'copied signature is refused rather than accepted twice. A ' +
                 'low bound therefore costs a client a fresh challenge, ' +
                 'never a replay.' },

  { key: 'scim.authCookie', group: 'SCIM', label: 'Offer the session cookie',
    env: 'SCIM_AUTH_COOKIE', type: 'bool', dflt: true, runtime: true,
    description: 'Whether the browser sign-on session this service already ' +
                 'has — the one /authn/login creates and WS-Federation ' +
                 'shares — authenticates a SCIM request. RFC 7644 section 2 ' +
                 'names cookies explicitly. There is no challenge for it, ' +
                 'because a server cannot ask for a cookie in ' +
                 'WWW-Authenticate, and it is consulted only when there is ' +
                 'no Authorization header: a request that presents a ' +
                 'credential is judged on that credential rather than ' +
                 'quietly falling back.' },

  { key: 'scim.authClientCert', group: 'SCIM', label: 'Offer TLS client ' +
                                                      'certificates',
    env: 'SCIM_AUTH_CLIENT_CERT', type: 'bool', dflt: true, runtime: true,
    description: 'Mutual TLS, the first scheme RFC 7644 section 2 names. It ' +
                 'applies only where the request arrived over TLS with a ' +
                 'certificate that VERIFIED against an anchor POSTed to ' +
                 '/tls/trust, so on the main port only when global.https is ' +
                 'on. This is the first place in this service where a client ' +
                 'certificate is a CREDENTIAL rather than an observation — ' +
                 'on the /tls listeners a verified certificate is reported ' +
                 'and grants nothing; here it authenticates somebody who may ' +
                 'then write to the directory.' },


  // --- Shared Signals Framework (SSF) --------------------------------------
  //
  // The seventeenth protocol family, and the first one here that TALKS BACK:
  // every other family answers a request, and this one delivers an event
  // nobody asked for at the moment it happens. Two consequences run through
  // every row below.
  //
  // THE FIRST IS THAT THIS SERVICE DIALS OUT. Push delivery (RFC 8935) posts
  // each Security Event Token to a URL the RECEIVER chose, which is a weaker
  // position than federation's outbound request and `ssf/ssf_http.js` says so
  // at length rather than citing it. `ssf.pushDelivery`, `ssf.pushAllowedHosts`
  // and `ssf.pushAllowInsecure` are the bounds. Poll delivery (RFC 8936) dials
  // nothing at all — the receiver comes here — so a deployment that wants none
  // of it turns push off and still speaks the whole of SSF.
  //
  // THE SECOND IS THAT A SET IS A DURABLE RECORD. It says something HAPPENED,
  // RFC 8417 section 4.1.4 forbids it to expire, and it is therefore read long
  // after it was written — which is the case a harvest-now-decrypt-later
  // argument is actually about. `ssf.signingAlgorithm` is the one setting here
  // that reaches the whole post-quantum table, because the signature goes
  // through `helpers.signJwtAs()` like every other JWT this service mints.
  // ---------------------------------------------------------------------
  // XACML 3.0.
  //
  // The engine is `xacml/`, the store is ou=policies in the embedded
  // directory, and the decision endpoint is POST /xacml/pdp. Two things about
  // this group are worth knowing before adding a row to it.
  //
  // FIRST, `xacml.enabled` LEAVES THE ROUTES REGISTERED and makes them answer
  // 501, exactly as `ssf.enabled` does — the feature is off, the URL is not
  // wrong, and those are different sentences to a client that is trying to
  // work out whether this service speaks XACML at all.
  //
  // SECOND, THERE IS NO SETTING THAT MAKES THE PDP MORE PERMISSIVE, and that
  // is deliberate in a service whose every other surface is a turnstile. A
  // PDP's whole output is a decision; a flag that made it answer Permit when
  // it could not decide would not be a mock of anything, it would be a broken
  // PDP. What IS configurable is what happens at the PEP — see
  // `xacml.pepBias`, which is the PEP's decision and not the PDP's.
  { key: 'xacml.enabled', group: 'XACML', label: 'XACML enabled',
    env: 'STS_XACML_ENABLED', type: 'bool', dflt: true, runtime: true,
    description: 'When on, the XACML 3.0 endpoints under /xacml answer. ' +
                 'Turning it off leaves the routes REGISTERED and makes ' +
                 'them answer 501 rather than 404 — the feature is off, the ' +
                 'URL is not wrong. The policy repository in ou=policies is ' +
                 'untouched either way, so turning this back on decides ' +
                 'against the same policies it did before.' },

  { key: 'xacml.maxPolicies', group: 'XACML',
    label: 'Policies the repository may hold',
    env: 'STS_XACML_MAX_POLICIES', type: 'int', dflt: 200, runtime: true,
    description: 'How many entries may live under ou=policies. The same ' +
                 'kind of limit ou=federations and ou=applications carry, ' +
                 'and for the same reason: this directory is in memory in ' +
                 'the default persistence mode, and a caller that can create ' +
                 'entries without bound can exhaust it. Reaching the limit ' +
                 'refuses the CREATE and logs; it never evicts.' },

  { key: 'xacml.pepBias', group: 'XACML',
    label: 'What the embedded PEP does with a non-Permit',
    env: 'STS_XACML_PEP_BIAS', type: 'enum',
    enumValues: ['deny-biased', 'permit-biased'], dflt: 'deny-biased',
    runtime: true,
    description: 'THIS IS THE PEP\'S DECISION AND NOT THE PDP\'S, which is ' +
                 'the whole reason it is a setting. XACML section 7.2 lets a ' +
                 'PEP be deny-biased (anything that is not Permit is a ' +
                 'refusal) or permit-biased (anything that is not Deny is ' +
                 'allowed), and real deployments differ. Deny-biased is the ' +
                 'default because it is what a PEP protecting anything ' +
                 'should be; permit-biased exists so that a client can see ' +
                 'what the other choice does to an Indeterminate, which is ' +
                 'the case the two disagree about and the one nobody tests.' },

  { key: 'xacml.returnPolicyIdList', group: 'XACML',
    label: 'Always return the applicable policy identifiers',
    env: 'STS_XACML_RETURN_POLICY_ID_LIST', type: 'bool', dflt: false,
    runtime: true,
    description: 'A request asks for the list of policies that applied by ' +
                 'setting ReturnPolicyIdList; turning this on returns it ' +
                 'whether or not the request asked. Off by default because ' +
                 'it is what the specification says, and on is what makes a ' +
                 'debugger useful — a decision you cannot trace to a policy ' +
                 'is a decision you cannot argue with.' },

  // ---------------------------------------------------------------------
  // THE REMOTE PEP (phase five). SEVEN ROWS, AND THEY DIVIDE IN TWO.
  //
  // The first three are about the REGISTRATION SURFACE — what a remote Policy
  // Enforcement Point may do when it dials this service. The last four are
  // about the NUDGE, which is the one outbound request this family makes, and
  // they are deliberately the same four `ssf.push*` carries: an off switch, a
  // host allowlist, an insecure escape and a timeout. Two families making one
  // outbound request each should be configured the same way, or the second one
  // is a surprise to anybody who has already read the first.
  //
  // WHAT IS NOT HERE IS A SETTING THAT CHANGES A REMOTE PEP'S BIAS. A remote
  // PEP is a SEPARATE PROCESS with its own configuration, and `xacml.pepBias`
  // governs the EMBEDDED one at /xacml/protected and nothing else. A row here
  // that appeared to set a remote PEP's bias would be a control that silently
  // did nothing, which is worse than no control: the remote one reports the
  // bias it is actually running with on every heartbeat, and the console shows
  // that rather than what this service would have chosen for it.
  { key: 'xacml.remotePeps', group: 'XACML',
    label: 'Remote Policy Enforcement Points may register',
    env: 'STS_XACML_REMOTE_PEPS', type: 'bool', dflt: true, runtime: true,
    description: 'When on, the three endpoints under /xacml/pep answer: a ' +
                 'remote PEP registers, PULLS the policy repository, and ' +
                 'reports what it has enforced. Turning it off leaves the ' +
                 'routes registered and answering 501, like every other ' +
                 'switch here, and leaves the register in ou=peps untouched ' +
                 '— so a PEP that was registered is still listed, still ' +
                 'shown as stale, and comes back the moment this goes on ' +
                 'again. THE PULL IS THE CONTRACT: a PEP that cannot reach ' +
                 'this endpoint has stale policy and says so on its own ' +
                 'surface, which is the failure mode this whole design is ' +
                 'arranged to make visible.' },

  { key: 'xacml.pepRequireCertificate', group: 'XACML',
    label: 'A registering PEP must present a client certificate',
    env: 'STS_XACML_PEP_REQUIRE_CERTIFICATE', type: 'bool', dflt: true,
    runtime: true,
    description: 'ON by default. It was once the ONE refusal in this family; ' +
                 'every /xacml endpoint asks for a certificate now, and what ' +
                 'this setting still governs is the REGISTRATION ' +
                 'specifically — it writes an entry, it is what the console ' +
                 'lists, and it is the address a nudge is sent to, so "which ' +
                 'PEP is this" is exactly the question there and a client ' +
                 'certificate is the answer. The access-policy layer above ' +
                 'it is a different and stronger check ' +
                 '(roles.remotePepGroup, and xacml.enforceAccess to turn it ' +
                 'off); this one is about whether a registration with NO ' +
                 'certificate is accepted at all and marked unauthenticated. ' +
                 'Like every other gate in this service it is a TURNSTILE: ' +
                 'the certificate is not required to chain to anything, ' +
                 'because RFC 8705\'s argument applies unchanged — what is ' +
                 'proved is that the same key completed the handshake. ' +
                 'Turning it off lets a PEP register over plain HTTP, which ' +
                 'is what a run with global.https off needs; such a ' +
                 'registration is marked UNAUTHENTICATED on its entry and on ' +
                 'the console rather than being quietly indistinguishable ' +
                 'from one that proved something.' },

  { key: 'xacml.pipMaxPerWindow', group: 'XACML',
    label: 'PIP queries one caller may make per rate-limit window',
    env: 'STS_XACML_PIP_MAX_PER_WINDOW', type: 'int', dflt: 600,
    min: 1, max: 100000, runtime: true,
    description: 'How many POST /xacml/pip queries one enforcement point — ' +
                 'and one address — may make in a security.rateLimitWindowS ' +
                 'window. IT IS ITS OWN NUMBER RATHER THAN ' +
                 'security.rateLimitPerIdentity, and that is the point: that ' +
                 'setting is FIVE, because it guards a SIGN-IN, where five ' +
                 'attempts a minute is generous and a sixth is somebody ' +
                 'guessing. A PIP query is the opposite rhythm — a remote ' +
                 'Policy Enforcement Point makes one per access decision, so ' +
                 'a busy one makes several a second and every one of them is ' +
                 'legitimate. Sharing the sign-in limiter\'s number would ' +
                 'have turned this endpoint off for its only caller, which ' +
                 'is worse than not limiting it: the PEP falls back to ' +
                 'deciding on what the request asserts and says nothing is ' +
                 'wrong. The default is ten a second over the default ' +
                 'sixty-second window. What it bounds is a caller this ' +
                 'service ADMITTED reading directory attributes in a loop; ' +
                 'an unadmitted one is refused by the access policy before ' +
                 'it gets here.' },

  // Added 2026-09-12, beside the rate it multiplies: this bounds one query and
  // that bounds how many queries. It was the module constant
  // `PIP_MAX_DESIGNATORS`.
  { key: 'xacml.pipMaxDesignators', group: 'XACML',
    label: 'Attributes one PIP query may ask about',
    env: 'STS_XACML_PIP_MAX_DESIGNATORS', type: 'int', dflt: 50,
    min: 1, max: 10000, runtime: true,
    description: 'How many attribute designators one POST /xacml/pip query ' +
                 'may name. The endpoint walks the list the caller supplies ' +
                 'on the thread every socket here is answered on, so the ' +
                 'list is bounded; a query over it is refused whole, with ' +
                 'the number. Fifty is far more than any real policy ' +
                 'designates about one subject — raise it for a policy that ' +
                 'genuinely does.' },

  { key: 'xacml.maxPeps', group: 'XACML',
    label: 'Remote PEPs the register may hold',
    env: 'STS_XACML_MAX_PEPS', type: 'int', dflt: 50, runtime: true,
    description: 'How many entries may live under ou=peps, for the same ' +
                 'reason xacml.maxPolicies bounds ou=policies: this ' +
                 'directory is in memory in the default persistence mode and ' +
                 'a caller that can create entries without bound can ' +
                 'exhaust it. Reaching the limit refuses the REGISTRATION ' +
                 'and logs; it never evicts, because evicting a PEP would ' +
                 'stop nudging a component that is still enforcing.' },

  { key: 'xacml.pepStaleAfterS', group: 'XACML',
    label: 'Seconds before a registered PEP is reported stale',
    env: 'STS_XACML_PEP_STALE_AFTER_S', type: 'int', dflt: 300,
    min: 10, max: 86400, runtime: true,
    description: 'A remote PEP heartbeats; this is how long since the last ' +
                 'one before the console calls it stale. It changes NOTHING ' +
                 'this service does — no entry is removed, no nudge is ' +
                 'withheld — it is purely what the word "stale" means on the ' +
                 'page. That is the point: a PEP whose sync has stopped is ' +
                 'still enforcing, against whatever policy it last pulled, ' +
                 'and a register that hid it would hide exactly the ' +
                 'situation somebody needs to see.' },

  { key: 'xacml.pepNotify', group: 'XACML',
    label: 'Nudge a registered PEP when the repository changes',
    env: 'STS_XACML_PEP_NOTIFY', type: 'bool', dflt: true, runtime: true,
    description: 'THE NUDGE IS AN OPTIMISATION AND NEVER THE MECHANISM. A ' +
                 'remote PEP PULLS on its own interval; when a policy ' +
                 'changes, this service additionally POSTs a few bytes to ' +
                 'each registered PEP that gave a notify URL, saying only ' +
                 '"something changed, pull now". Turning it off costs ' +
                 'LATENCY and nothing else — every PEP still converges on ' +
                 'its next poll — which is what makes it safe to turn off ' +
                 'in a deployment with no egress. It is the third outbound ' +
                 'request in this repository and xacml/xacml_pep_http.js ' +
                 'argues it rather than citing the other two.' },

  { key: 'xacml.pepNotifyAllowedHosts', group: 'XACML',
    label: 'Notify endpoint allowlist',
    env: 'STS_XACML_PEP_NOTIFY_ALLOWED_HOSTS', type: 'csv', dflt: '',
    runtime: true,
    description: 'Host names this service will nudge. EMPTY MEANS ANY, ' +
                 'which is the default and matches ssf.pushAllowedHosts ' +
                 'exactly — a deployment reachable by anybody it does not ' +
                 'trust sets the list, and every other host is refused BY ' +
                 'NAME on the PEP\'s own row. Hosts rather than URLs, for ' +
                 'the reason SSF gives: a component legitimately moves its ' +
                 'path and does not legitimately move to another host.' },

  { key: 'xacml.pepNotifyAllowInsecure', group: 'XACML',
    label: 'Allow http:// and untrusted TLS for a nudge',
    env: 'STS_XACML_PEP_NOTIFY_ALLOW_INSECURE', type: 'bool', dflt: false,
    runtime: true,
    description: 'OFF by default, like federation\'s and SSF\'s equivalents ' +
                 '— and what travels here is WEAKER than either of those, ' +
                 'which is worth saying rather than leaving to be assumed. ' +
                 'A nudge carries no credential and no event: its whole ' +
                 'body says that the repository changed, which the PEP is ' +
                 'about to find out anyway. It is still off by default, ' +
                 'because the URL is one somebody configured and a request ' +
                 'this service makes in the clear is a request somebody can ' +
                 'answer for.' },

  { key: 'xacml.pepNotifyTimeoutMs', group: 'XACML',
    label: 'Nudge timeout (ms)',
    env: 'STS_XACML_PEP_NOTIFY_TIMEOUT_MS', type: 'int', dflt: 2000,
    min: 100, max: 30000, runtime: true,
    description: 'How long to wait for a PEP to answer a nudge. SHORTER ' +
                 'THAN SSF\'S TEN SECONDS ON PURPOSE, and the reason is the ' +
                 'thing that makes a nudge a nudge: a lost push is a lost ' +
                 'event, so SSF waits; a lost nudge costs one polling ' +
                 'interval of latency and nothing at all, so waiting is the ' +
                 'expensive mistake. What IS waiting on it is the console ' +
                 'form of whoever just saved a policy.' },

  { key: 'ssf.enabled', group: 'SSF', label: 'SSF enabled',
    env: 'STS_SSF_ENABLED', type: 'bool', dflt: true, runtime: true,
    description: 'When on, the Shared Signals Framework endpoints under ' +
                 '/ssf agree streams, deliver Security Event Tokens and ' +
                 'receive them. On by default, like every other protocol ' +
                 'family here. Turning it off leaves the routes REGISTERED ' +
                 'and makes them answer 501 rather than 404 — the feature ' +
                 'is off, the URL is not wrong, and those are different ' +
                 'sentences to a client. The transmitter configuration ' +
                 'metadata at /.well-known/ssf-configuration goes on ' +
                 'answering, so a receiver can still discover that this ' +
                 'service speaks SSF and is not currently doing it.' },

  { key: 'ssf.issuer', group: 'SSF', label: 'Transmitter issuer identifier',
    env: 'STS_SSF_ISSUER', type: 'string', dflt: '', runtime: true,
    description: 'The `iss` of every SET this service transmits and of the ' +
                 'transmitter configuration metadata. EMPTY means "this ' +
                 'realm\'s base URL", which is the right answer almost ' +
                 'always and is why it is the default — a receiver matches ' +
                 'the `iss` of an arriving SET against the issuer it ' +
                 'discovered, so the two have to be the same string and ' +
                 'deriving both from the request is how they stay so. Set ' +
                 'it where this service sits behind a name it cannot see.' },

  { key: 'ssf.signingAlgorithm', group: 'SSF',
    label: 'Algorithm SETs are signed with',
    env: 'STS_SSF_SIGNING_ALGORITHM', type: 'string', dflt: 'RS256',
    runtime: true,
    description: 'Which JWS algorithm every Security Event Token is signed ' +
                 'with. It goes through the same signer every other JWT ' +
                 'here does, so the whole table is available — RS256 and ' +
                 'the PS/ES families, EdDSA, and the POST-QUANTUM ones: ' +
                 'ML-DSA-44/65/87 (FIPS 204), SLH-DSA (FIPS 205) and the ' +
                 'six composite ML-DSA + traditional algorithms. This is ' +
                 'the document in this service most worth signing that way: ' +
                 'a SET records that something happened and RFC 8417 ' +
                 'section 4.1.4 forbids it to expire, so it is read long ' +
                 'after it was written. Note an SLH-DSA signature takes ' +
                 'seconds — it runs on the worker pool, so this service ' +
                 'answers throughout, but the receiver waits.' },

  certificateHeaderSetting('ssf.setCertificateHeader', 'SSF',
    'STS_SSF_SET_CERTIFICATE_HEADER', 'SET certificate header',
    'Whether a SECURITY EVENT TOKEN — SSF\'s own, CAEP\'s and RISC\'s, ' +
    'pushed or polled — names the certificate chain of the key that signed ' +
    'it. A receiver that cannot reach this service back can use only `x5c`.'),

  { key: 'ssf.deliveryMethods', group: 'SSF', label: 'Delivery methods offered',
    env: 'STS_SSF_DELIVERY_METHODS', type: 'csv',
    dflt: 'urn:ietf:rfc:8935,urn:ietf:rfc:8936', runtime: true,
    description: 'Which of SSF\'s two delivery methods this transmitter ' +
                 'will agree to, published in delivery_methods_supported ' +
                 'and enforced at stream creation. The values are the RFC ' +
                 'numbers AS URNS — urn:ietf:rfc:8935 is push and ' +
                 'urn:ietf:rfc:8936 is poll — which catches everybody once, ' +
                 'so "push" and "poll" are accepted here as shorthand and ' +
                 'normalised. Narrowing it to one is how a client\'s "this ' +
                 'transmitter will not do push" path becomes reachable.' },

  { key: 'ssf.defaultSubjects', group: 'SSF',
    label: 'What an empty subject list means',
    env: 'STS_SSF_DEFAULT_SUBJECTS', type: 'enum',
    enumValues: ['ALL', 'NONE'], dflt: 'ALL', runtime: true,
    description: 'Published as default_subjects and it decides the OPPOSITE ' +
                 'of what it sounds like it decides: with ALL, a stream ' +
                 'that names no subjects is about EVERYBODY and adding one ' +
                 'narrows nothing; with NONE it is about nobody until a ' +
                 'subject is added. A receiver that guesses wrong gets ' +
                 'every event in the estate or gets none, and both look ' +
                 'like a broken transmitter — which is why SSF makes it ' +
                 'discoverable rather than leaving it to be inferred.' },

  { key: 'ssf.streamStatusOnCreate', group: 'SSF',
    label: 'Status a new stream is created in',
    env: 'STS_SSF_STREAM_STATUS_ON_CREATE', type: 'enum',
    enumValues: ['enabled', 'paused', 'disabled'], dflt: 'enabled',
    runtime: true,
    description: 'SSF does not say, so this is a choice and it is worth ' +
                 'knowing which one was made: a stream here is ENABLED the ' +
                 'moment it is created, which is the permissive answer this ' +
                 'service gives everywhere. Set it to paused to exercise a ' +
                 'receiver that has to enable its own stream before ' +
                 'anything arrives — a step several real transmitters ' +
                 'require and most clients have never run.' },

  { key: 'ssf.minVerificationInterval', group: 'SSF',
    label: 'Minimum verification interval (s)',
    env: 'STS_SSF_MIN_VERIFICATION_INTERVAL', type: 'int', dflt: 60,
    min: 0, max: 86400, runtime: true,
    description: 'Published on every stream configuration as ' +
                 'min_verification_interval: how often this transmitter is ' +
                 'willing to be asked for a verification event. It is the ' +
                 'TRANSMITTER\'s statement rather than the receiver\'s ' +
                 'request, which is why a stream asking for something ' +
                 'smaller is REFUSED rather than accepted and quietly ' +
                 'ignored. Zero accepts any rate, which is what the test ' +
                 'suite runs at.' },

  { key: 'ssf.verificationRateLimit', group: 'SSF',
    label: 'Enforce the verification interval',
    env: 'STS_SSF_VERIFICATION_RATE_LIMIT', type: 'bool', dflt: false,
    runtime: true,
    description: 'OFF by default, and the pair with the row above is the ' +
                 'point: this service PUBLISHES an interval and does not ' +
                 'hold callers to it, so a receiver can verify as often as ' +
                 'it likes while still seeing a realistic value in the ' +
                 'stream configuration. Turning it on answers 429 to a ' +
                 'verification request that arrives too soon, which is the ' +
                 'negative a client cannot otherwise reach.' },

  { key: 'ssf.criticalSubjectMembers', group: 'SSF',
    label: 'Critical complex-subject members',
    env: 'STS_SSF_CRITICAL_SUBJECT_MEMBERS', type: 'csv', dflt: '',
    runtime: true,
    description: 'Published as critical_subject_members: the members of a ' +
                 'COMPLEX subject a receiver of this transmitter\'s events ' +
                 'MUST understand. The six SSF defines are user, device, ' +
                 'session, tenant, org_unit and group. Naming one here is a ' +
                 'promise, so this service also refuses to ADD a complex ' +
                 'subject that omits it — a transmitter that published a ' +
                 'critical member and then left it out would be producing ' +
                 'events nothing acts on. Empty is the ordinary case.' },

  { key: 'ssf.eventsSupported', group: 'SSF', label: 'Event types offered',
    env: 'STS_SSF_EVENTS_SUPPORTED', type: 'csv',
    dflt: 'https://schemas.openid.net/secevent/ssf/event-type/verification,' +
          'https://schemas.openid.net/secevent/ssf/event-type/stream-updated',
    runtime: true,
    description: 'Which of SSF\'S OWN TWO event types this transmitter will ' +
                 'agree to deliver. It is not the whole offered list any ' +
                 'more: SSF is a PIPE and the vocabularies over it have ' +
                 'settings of their own, so CAEP\'s eight are governed by ' +
                 'caep.eventsSupported and the two lists are unioned into ' +
                 'the events_supported a receiver discovers and into the ' +
                 'intersection with events_requested that becomes ' +
                 'events_delivered. Narrowing this is how a receiver\'s ' +
                 '"you did not agree to the type I asked for" path is ' +
                 'reached for the pipe\'s own events; an entry naming a ' +
                 'type this service does not implement is dropped with a ' +
                 'warning rather than advertised, and a short name works as ' +
                 'well as a whole URI.' },

  { key: 'ssf.pushDelivery', group: 'SSF', label: 'Make outbound push requests',
    env: 'STS_SSF_PUSH_DELIVERY', type: 'bool', dflt: true, runtime: true,
    description: 'Whether this service may POST a Security Event Token OUT, ' +
                 'to the delivery endpoint a receiver named on its stream. ' +
                 'This is the SECOND outbound request in this repository ' +
                 'and a weaker case than federation\'s: RFC 8935 push IS ' +
                 'the receiver telling the transmitter where to post, so ' +
                 'the URL is caller-supplied by construction. ' +
                 'ssf/ssf_http.js argues it rather than citing federation. ' +
                 'Turning it off leaves the whole of SSF working over POLL ' +
                 'delivery, which dials nothing — and ' +
                 'delivery_methods_supported then advertises only poll, so ' +
                 'a receiver finds out at stream creation rather than by ' +
                 'never receiving anything.' },

  { key: 'ssf.pushAllowedHosts', group: 'SSF', label: 'Push endpoint allowlist',
    env: 'STS_SSF_PUSH_ALLOWED_HOSTS', type: 'csv', dflt: '', runtime: true,
    description: 'Host names this service will push to. EMPTY MEANS ANY, ' +
                 'which is the default and the one deliberate looseness in ' +
                 'the outbound path — it is what makes this usable as a ' +
                 'mock. A deployment reachable by anybody it does not trust ' +
                 'sets the list, and every other host is refused BY NAME on ' +
                 'the stream\'s own log. Hosts rather than URLs on purpose: ' +
                 'a receiver legitimately moves its endpoint path and does ' +
                 'not legitimately move to another host.' },

  { key: 'ssf.pushAllowInsecure', group: 'SSF',
    label: 'Allow http:// and untrusted TLS to a receiver',
    env: 'STS_SSF_PUSH_ALLOW_INSECURE', type: 'bool', dflt: false,
    runtime: true,
    description: 'OFF by default, like federation\'s equivalent and for a ' +
                 'reason that is different in kind: what travels on a push ' +
                 'is not a credential but an EVENT — that somebody\'s ' +
                 'session was revoked, that an account was disabled — which ' +
                 'is somebody\'s security posture in transit, and the ' +
                 'receiver\'s own authorization_header travels beside it. ' +
                 'ON accepts an http:// endpoint and a certificate nothing ' +
                 'here trusts, and every request made under it is LOGGED as ' +
                 'insecure rather than only the setting being logged once.' },

  { key: 'ssf.pushTimeoutMs', group: 'SSF', label: 'Push timeout (ms)',
    env: 'STS_SSF_PUSH_TIMEOUT_MS', type: 'int', dflt: 10000,
    min: 250, max: 60000, runtime: true,
    description: 'How long to wait for a receiver to answer a push. Nothing ' +
                 'is WAITING on it the way a browser waits on a federated ' +
                 'sign-in, so it is longer than federation\'s — but it is ' +
                 'still bounded, because a receiver that never answers ' +
                 'would otherwise hold a socket and a queued event ' +
                 'indefinitely.' },

  { key: 'ssf.pushMaxResponseBytes', group: 'SSF',
    label: 'Largest push response read (bytes)',
    env: 'STS_SSF_PUSH_MAX_RESPONSE_BYTES', type: 'int', dflt: 65536,
    min: 1024, max: 16777216, runtime: true,
    description: 'How much of a receiver\'s answer to a push is read before ' +
                 'the push is recorded as failed. RFC 8935 makes a success ' +
                 'an EMPTY 202 and a failure a small JSON object, so 64 KiB ' +
                 'is generous; it is a bound because the address was chosen ' +
                 'by a caller.' },

  { key: 'ssf.pushRetries', group: 'SSF', label: 'Push retries',
    env: 'STS_SSF_PUSH_RETRIES', type: 'int', dflt: 0, min: 0, max: 10,
    runtime: true,
    description: 'How many times a failed push is tried again. 0 — the ' +
                 'default — is what this service has always done, on ' +
                 'purpose: a transmitter that retried would hide a ' +
                 'receiver\'s one-shot failure from whoever is testing it ' +
                 '(ssf/CLAUDE.md). A deployment wants a few. Only a failure ' +
                 'that could go differently is retried — no connection, a ' +
                 'timeout, a 5xx or a 429 — and never a receiver\'s 400 ' +
                 'refusal, which RFC 8935 section 2.4 makes final.' },

  { key: 'ssf.pushRetryDelayMs', group: 'SSF', label: 'Push retry delay (ms)',
    env: 'STS_SSF_PUSH_RETRY_DELAY_MS', type: 'int', dflt: 1000, min: 0,
    max: 60000, runtime: true,
    description: 'The wait before a retry, multiplied by the attempt number ' +
                 '— one delay before the second attempt, two before the ' +
                 'third. Only read when ssf.pushRetries is above 0.' },

  // -------------------------------------------------------------------------
  // THE PUSH CAP, DEAD STREAMS AND THE DEAD-LETTER QUEUE (2026-09-14).
  //
  // A dispatch run's SCIM bulk load emitted two events per create to forty-two
  // push streams, every push went out at once, and the service stopped
  // answering for fourteen minutes. The cap bounds how much one process sends
  // at a time; a stream that has only failed for `deadStreamTimeoutS` stops
  // being pushed to; and an undeliverable SET is kept for inspection on a
  // dead-letter queue rather than on the live queue, where it was re-scanned on
  // every event and kept for ever. ssf/CLAUDE.md argues all four.
  // -------------------------------------------------------------------------
  { key: 'ssf.pushConcurrency', group: 'SSF', label: 'Concurrent pushes',
    env: 'STS_SSF_PUSH_CONCURRENCY', type: 'int', dflt: 8, min: 0, max: 1000,
    runtime: true,
    description: 'How many RFC 8935 pushes one process of this service makes ' +
                 'at once. The rest wait for a slot in the order they were ' +
                 'asked for. 0 removes the cap. A push this service makes to ' +
                 'its own console or portal receiver is a request to one of ' +
                 'its own workers, so an unbounded burst is load on the ' +
                 'service itself.' },

  { key: 'ssf.pushBacklog', group: 'SSF', label: 'Pushes waiting for a slot',
    env: 'STS_SSF_PUSH_BACKLOG', type: 'int', dflt: 2000, min: 1,
    max: 1000000, runtime: true,
    description: 'How many pushes may wait for a slot under ' +
                 'ssf.pushConcurrency. Past it a push is not made: the SET is ' +
                 'put on the stream\'s dead-letter queue with that reason, ' +
                 'which bounds the memory a burst can take.' },

  { key: 'ssf.deadStreamTimeoutS', group: 'SSF',
    label: 'Dead stream timeout (seconds)',
    env: 'STS_SSF_DEAD_STREAM_TIMEOUT_S', type: 'int', dflt: 300, min: 0,
    max: 604800, runtime: true,
    description: 'A push stream whose pushes have all failed for this long ' +
                 'is declared DEAD: nothing more is pushed to it, what was ' +
                 'waiting and every later SET for it go to its dead-letter ' +
                 'queue, and once per this period one dead letter is pushed ' +
                 'as a probe — a success revives the stream. An operator can ' +
                 'revive it too. 0 turns the check off. A poll stream is never ' +
                 'declared dead: nothing is pushed to one.' },

  { key: 'ssf.deadLetterRetentionS', group: 'SSF',
    label: 'Dead letters kept (seconds)',
    env: 'STS_SSF_DEAD_LETTER_RETENTION_S', type: 'int', dflt: 3600, min: 60,
    max: 2592000, runtime: true,
    description: 'How long an undeliverable SET stays on its stream\'s ' +
                 'dead-letter queue, with the reason it could not be ' +
                 'delivered, for inspection on /admin/ssf and GET ' +
                 '/admin-api/ssf. A sweep deletes older ones and logs one ' +
                 'summary line — never a line per SET.' },

  { key: 'ssf.deadLetterMaxPerStream', group: 'SSF',
    label: 'Dead letters per stream',
    env: 'STS_SSF_DEAD_LETTER_MAX_PER_STREAM', type: 'int', dflt: 1000,
    min: 1, max: 100000, runtime: true,
    description: 'The most dead letters one stream keeps. Past it the OLDEST ' +
                 'is deleted, for ssf.maxQueuedEvents\' reason: what failed ' +
                 'lately is what somebody inspecting the queue wants.' },

  { key: 'ssf.deadLetterSweepS', group: 'SSF',
    label: 'Dead-letter sweep interval (seconds)',
    env: 'STS_SSF_DEAD_LETTER_SWEEP_S', type: 'int', dflt: 60, min: 5,
    max: 3600, runtime: true,
    description: 'How often each process deletes expired dead letters, ' +
                 'probes dead streams that are due and logs its summary of ' +
                 'what was dead-lettered since the last sweep.' },

  { key: 'ssf.authBasic', group: 'SSF', label: 'Offer HTTP Basic',
    env: 'STS_SSF_AUTH_BASIC', type: 'bool', dflt: true, runtime: true,
    description: 'Whether the SSF endpoints accept HTTP Basic beside OAuth ' +
                 '2.0 access tokens, and publish it in ' +
                 'authorization_schemes. In development any username with ' +
                 'any password but "invalid" passes; in product mode the ' +
                 'password is verified against the person\'s hashed ' +
                 'userPassword. Either way a Basic principal holds both ' +
                 'scopes, because Basic carries none — so a deployment that ' +
                 'wants ssf:read and ssf:write enforced for every caller ' +
                 'turns this off.' },

  // -------------------------------------------------------------------------
  // THIS SERVICE'S OWN TWO SURFACES AS RECEIVERS (2026-09-10).
  //
  // It is RESTART-ONLY and that is a fact about where the seeding runs rather
  // than a decision: the two streams are created as `ssf/ssf.js` is required
  // and again as each realm is built, so turning this off at runtime would
  // leave the streams that already exist and turning it on would create none.
  // What it does answer at runtime is `accept()`, which refuses a push at
  // either receive endpoint while it is off — so a service started with it off
  // has no streams AND no endpoints that take anything, which is the state the
  // setting names.
  // -------------------------------------------------------------------------
  { key: 'ssf.internalReceivers', group: 'SSF',
    label: 'Register the console and the portal as receivers',
    env: 'STS_SSF_INTERNAL_RECEIVERS', type: 'bool', dflt: true,
    runtime: false,
    restartReason: 'the two streams are seeded as ssf/ssf.js is required and ' +
                   'again as each realm is built, so turning this off in ' +
                   'place would leave the streams that already exist and ' +
                   'turning it on would create none',
    description: 'Whether this service seeds a Shared Signals stream for its ' +
                 'OWN admin console and user portal, so that each takes ' +
                 'delivery of every CAEP and RISC event over RFC 8935 push ' +
                 'at an endpoint of its own and draws what arrived at ' +
                 '/admin/signals and /portal/signals. They are ORDINARY ' +
                 'streams — pause one, narrow it or delete it at /admin/ssf ' +
                 'and it stays that way until a restart. Note that ' +
                 'ssf.pushDelivery governs this delivery like any other: ' +
                 'with it off the events queue on the two streams and reach ' +
                 'neither page.' },

  { key: 'ssf.maxStreams', group: 'SSF', label: 'Streams per realm',
    env: 'STS_SSF_MAX_STREAMS', type: 'int', dflt: 25, min: 1, max: 1000,
    runtime: true,
    description: 'How many streams one trust realm may hold. A create past ' +
                 'it is refused NAMING THIS SETTING, which is the point of ' +
                 'having a limit on a mock at all: every ceiling here is a ' +
                 'reachable negative a receiver cannot otherwise exercise.' },

  { key: 'ssf.maxSubjectsPerStream', group: 'SSF', label: 'Subjects per stream',
    env: 'STS_SSF_MAX_SUBJECTS_PER_STREAM', type: 'int', dflt: 100, min: 1,
    max: 10000, runtime: true,
    description: 'How many subjects one stream may name before Add Subject ' +
                 'is refused. Same reasoning as the row above.' },

  { key: 'ssf.maxQueuedEvents', group: 'SSF', label: 'Queued events per stream',
    env: 'STS_SSF_MAX_QUEUED_EVENTS', type: 'int', dflt: 200, min: 1,
    max: 10000, runtime: true,
    description: 'How many undelivered SETs one stream holds. Past it the ' +
                 'OLDEST is dropped and the stream\'s log says so — not the ' +
                 'newest, because a receiver that has stopped reading most ' +
                 'wants what has happened lately, and a queue that refused ' +
                 'new events would make a transmitter stop recording ' +
                 'because a receiver stopped listening.' },

  { key: 'ssf.pollMaxEvents', group: 'SSF', label: 'Events per poll',
    env: 'STS_SSF_POLL_MAX_EVENTS', type: 'int', dflt: 20, min: 1, max: 1000,
    runtime: true,
    description: 'The most SETs one RFC 8936 poll returns, whatever the ' +
                 'receiver\'s maxEvents asked for. The response says ' +
                 'moreAvailable so a receiver knows to come back — a client ' +
                 'that ignores that member and assumes one poll drains the ' +
                 'queue is a common enough defect to be worth being able to ' +
                 'produce on demand: set this to 1.' },

  { key: 'ssf.maxReceivedEvents', group: 'SSF', label: 'Received events kept',
    env: 'STS_SSF_MAX_RECEIVED_EVENTS', type: 'int', dflt: 200, min: 1,
    max: 10000, runtime: true,
    description: 'How many SETs POST /ssf/receive keeps for /admin/ssf to ' +
                 'show. That endpoint is this service acting as a RECEIVER, ' +
                 'which is what the debugger pushes to when the roles are ' +
                 'the other way round; the oldest are dropped past this.' },

  { key: 'ssf.maxStreamLogEntries', group: 'SSF', label: 'Log lines per stream',
    env: 'STS_SSF_MAX_STREAM_LOG_ENTRIES', type: 'int', dflt: 200, min: 1,
    max: 10000, runtime: true,
    description: 'How many lines of its own history a stream keeps for ' +
                 '/admin/ssf. It is prose for a person and nothing reads it ' +
                 'back; the cap exists because a stream nobody deletes ' +
                 'would otherwise grow without bound in a process that ' +
                 'never restarts.' },

  { key: 'ssf.authScopeRead', group: 'SSF', label: 'Scope to read a stream',
    env: 'STS_SSF_AUTH_SCOPE_READ', type: 'string', dflt: 'ssf:read',
    runtime: true,
    description: 'The OAuth scope an access token must carry to READ a ' +
                 'stream configuration, its status or the poll queue. ' +
                 'Published in scopes_supported in both discovery ' +
                 'documents, exactly as the two SCIM scopes are.' },

  { key: 'ssf.authScopeWrite', group: 'SSF', label: 'Scope to change a stream',
    env: 'STS_SSF_AUTH_SCOPE_WRITE', type: 'string', dflt: 'ssf:write',
    runtime: true,
    description: 'The scope required to create, update or delete a stream, ' +
                 'to add or remove a subject, to change a status or to ask ' +
                 'for a verification event. A read scope is not enough for ' +
                 'any of those, which is the first place in this service ' +
                 'besides SCIM where two scopes differ in what they permit.' },

  { key: 'ssf.receiveEnabled', group: 'SSF', label: 'Accept pushed events',
    env: 'STS_SSF_RECEIVE_ENABLED', type: 'bool', dflt: true, runtime: true,
    description: 'Whether POST /ssf/receive accepts a Security Event Token ' +
                 'pushed AT this service — the roles reversed, with the ' +
                 'debugger as the transmitter. It verifies the signature ' +
                 'when it can find a key and reports what it read either ' +
                 'way, because a receiver that refused an unverifiable ' +
                 'event would be unable to show a person WHY it was ' +
                 'unverifiable. Off answers 501.' },

  { key: 'ssf.receiveRequireSignature', group: 'SSF',
    label: 'Refuse a SET whose signature does not verify',
    env: 'STS_SSF_RECEIVE_REQUIRE_SIGNATURE', type: 'bool', dflt: false,
    runtime: true,
    description: 'OFF by default, which is this service\'s ordinary posture ' +
                 'and is exactly right for a debugger: an event whose ' +
                 'signature fails is ACCEPTED and reported as failing, so a ' +
                 'person can see what arrived and why it did not verify. ' +
                 'Turning it on answers 400 with err=invalid_key instead, ' +
                 'which is what a real receiver does and is the negative a ' +
                 'transmitter needs to be able to reach.' },

  { key: 'ssf.legacySubClaim', group: 'SSF',
    label: 'Also emit the deprecated `sub` claim',
    env: 'STS_SSF_LEGACY_SUB_CLAIM', type: 'bool', dflt: false, runtime: true,
    description: 'MAKES THIS SERVICE WRONG ON PURPOSE, like ' +
                 'oauth2.breakIdTokenNonce and the Kerberos names that stay ' +
                 'unknown. RFC 8417 section 2.2 discourages `sub` on a SET ' +
                 'and SSF carries the subject in `sub_id` (RFC 9493) ' +
                 'because the thing an event is about may be a person AND a ' +
                 'device AND a session at once. Turning this on adds a ' +
                 '`sub` beside it, so a client written against a ' +
                 'transmitter that gets this wrong can be tested against ' +
                 'one.' },

  { key: 'ssf.breakSetSignature', group: 'SSF',
    label: 'Sign every SET badly',
    env: 'STS_SSF_BREAK_SET_SIGNATURE', type: 'bool', dflt: false,
    runtime: true,
    description: 'The second deliberate defect. One character of the ' +
                 'signature is changed AFTER signing, so a receiver that ' +
                 'does not verify accepts an event nothing signed. It is a ' +
                 'character rather than a truncation on purpose: a ' +
                 'truncated signature fails the base64url decode and is ' +
                 'reported as a MALFORMED token, which is a different bug ' +
                 'from a bad signature for whoever is being tested.' },

  // --- CAEP ----------------------------------------------------------------
  //
  // The Continuous Access Evaluation Profile (OpenID CAEP 1.0, final 2
  // September 2025), which is a VOCABULARY over the SSF group above rather
  // than a family of its own. Its events go out on SSF streams, are signed by
  // the SSF signer, are queued by the SSF queues and are delivered by the two
  // SSF deliveries — so nothing here duplicates a setting up there, and
  // ssf.enabled turning off takes CAEP with it.
  //
  // WHAT IS ACTUALLY NEW, AND IT IS ONE THING: this service now GENERATES AN
  // EVENT ON ITS OWN. Every other protocol family here answers a request, and
  // SSF's own list of what it deliberately does not do led with "it generates
  // no event on its own — every SET was asked for". That was honest while the
  // only vocabulary was the pipe's own, because SSF defines no event about a
  // session and a transmitter that invented one would be inventing a
  // vocabulary. CAEP is that vocabulary, so the sentence changes, and
  // `caep.autoEmit` is the switch that puts the old behaviour back rather than
  // leaving it only in the history of this file.
  { key: 'caep.enabled', group: 'CAEP', label: 'CAEP enabled',
    env: 'STS_CAEP_ENABLED', type: 'bool', dflt: true, runtime: true,
    description: 'When on, this transmitter offers CAEP\'s eight session ' +
                 'event types, tracks the CAEP state of every session it ' +
                 'holds, and reports both on /admin/caep-sessions. Turning ' +
                 'it off leaves SSF entirely alone — the pipe, its own two ' +
                 'events and every stream go on working — and drops the ' +
                 'eight types from what a stream may request, so a ' +
                 'receiver\'s "this transmitter will not deliver the type I ' +
                 'asked for" path becomes reachable without narrowing ' +
                 'ssf.eventsSupported by hand.' },

  { key: 'caep.autoEmit', group: 'CAEP',
    label: 'Emit events when something really happens',
    env: 'STS_CAEP_AUTO_EMIT', type: 'bool', dflt: true, runtime: true,
    description: 'THE SETTING THAT CHANGES WHAT THIS SERVICE IS. With it on, ' +
                 'a sign-in emits session-established, an authorization ' +
                 'request answered from a session that already existed ' +
                 'emits session-presented, and a sign-out emits ' +
                 'session-revoked — on every stream that asked for the type ' +
                 'and whose subjects cover that session, with nobody having ' +
                 'typed anything. That is what CAEP is FOR, and it is the ' +
                 'only place in this service where an endpoint is not what ' +
                 'starts the work. Off restores the older and equally ' +
                 'honest behaviour: every SET this service sends was asked ' +
                 'for, at /ssf/verify, on /admin/ssf, on /admin/caep or ' +
                 'through the management API.' },

  { key: 'caep.autoEmitTypes', group: 'CAEP',
    label: 'Which acts emit automatically',
    env: 'STS_CAEP_AUTO_EMIT_TYPES', type: 'csv',
    dflt: 'session-established,session-presented,session-revoked,' +
          'credential-change,assurance-level-change',
    runtime: true,
    description: 'The SHORT NAMES of the CAEP events this service emits by ' +
                 'itself, out of the five acts it can actually observe: a ' +
                 'session starting, a session being presented, a session ' +
                 'ending, a person re-authenticating on a session they ' +
                 'already hold with a different acr (a step-up or ' +
                 'step-down, since 2026-09-14, which emits ' +
                 'assurance-level-change on the urn:sts:acr scale), and — ' +
                 'since 2026-09-13 — an administrator changing ' +
                 'a person\'s credentials on their /admin/users page or ' +
                 'through /admin-api/users (a password set or reset, a ' +
                 'security key, an authenticator app or every second factor ' +
                 'removed), or the person spending a password reset link, ' +
                 'which emits credential-change. The other three are things ' +
                 'nothing here does — no device reports compliance to this ' +
                 'service and no risk engine talks to it — so they are ' +
                 'emitted BY HAND from /admin/caep or POST ' +
                 '/admin-api/caep/emit, and a row naming one of them here is ' +
                 'dropped with a warning rather than producing an event ' +
                 'nothing can cause.' },

  { key: 'caep.eventsSupported', group: 'CAEP',
    label: 'CAEP event types offered', env: 'STS_CAEP_EVENTS_SUPPORTED',
    type: 'csv',
    dflt: 'session-revoked,session-established,session-presented,' +
          'token-claims-change,credential-change,assurance-level-change,' +
          'device-compliance-change,risk-level-change',
    runtime: true,
    description: 'Which of CAEP\'s eight this transmitter will agree to ' +
                 'deliver, unioned with ssf.eventsSupported into the ' +
                 'events_supported a receiver discovers. SHORT NAMES are ' +
                 'accepted as well as whole URIs, because these URIs are ' +
                 'sixty characters long and a setting nobody can type is a ' +
                 'setting nobody narrows. Narrowing it is how a receiver ' +
                 'meets the case that matters most in this profile: SSF has ' +
                 'NO REFUSAL for an event type a transmitter will not send, ' +
                 'so the type\'s absence from events_delivered is the only ' +
                 'notice there is, and a receiver that reads back what it ' +
                 'asked for instead waits for ever.' },

  { key: 'caep.assuranceNamespace', group: 'CAEP',
    label: 'Assurance namespace', env: 'STS_CAEP_ASSURANCE_NAMESPACE',
    type: 'string', dflt: 'NIST-AAL', runtime: true,
    description: 'Which scale an assurance-level-change event\'s levels are ' +
                 'on, when the caller does not say. CAEP makes `namespace` ' +
                 'REQUIRED on that event and the reason is that the event ' +
                 'is useless without it: "aal2" means nothing until you ' +
                 'know it is NIST\'s. RFC8176, RFC6711, ISO-IEC-29115, ' +
                 'NIST-IAL, NIST-AAL and NIST-FAL are the values CAEP ' +
                 'lists, and the list is OPEN — an alias two parties agreed ' +
                 'is carried with a warning rather than refused.' },

  { key: 'caep.defaultRiskLevel', group: 'CAEP',
    label: 'Default risk level', env: 'STS_CAEP_DEFAULT_RISK_LEVEL',
    type: 'string', dflt: 'MEDIUM', runtime: true,
    description: 'What a risk-level-change event says when the caller does ' +
                 'not. LOW, MEDIUM or HIGH, UPPER CASE — which is CAEP\'s ' +
                 'own spelling and is the opposite of the complex ' +
                 'subject\'s lower-case member names, a difference that ' +
                 'catches everybody once.' },

  { key: 'caep.reasonLanguage', group: 'CAEP',
    label: 'Language tag on reason_admin / reason_user',
    env: 'STS_CAEP_REASON_LANGUAGE', type: 'string', dflt: 'en',
    runtime: true,
    description: 'The BCP 47 tag this service keys its reason messages ' +
                 'under. Those two members are OBJECTS keyed by a language ' +
                 'tag rather than strings, which is the commonest mistake ' +
                 'in the whole profile — a receiver indexing by language ' +
                 'reads nothing from a string and reports no error — so ' +
                 'this service always sends the object shape and this is ' +
                 'the key it uses.' },

  { key: 'caep.includeReasons', group: 'CAEP',
    label: 'Send reason_admin and reason_user',
    env: 'STS_CAEP_INCLUDE_REASONS', type: 'bool', dflt: true, runtime: true,
    description: 'Whether an automatically emitted event carries the two ' +
                 'reason members saying why. Both are optional in CAEP, so ' +
                 'turning this off is how a receiver that assumes a reason ' +
                 'is always there gets to fail in a test rather than in ' +
                 'production. It does not touch an event emitted by hand ' +
                 'with reasons filled in.' },

  { key: 'caep.maxSessionsTracked', group: 'CAEP',
    label: 'Sessions tracked', env: 'STS_CAEP_MAX_SESSIONS_TRACKED',
    type: 'int', dflt: 200, runtime: true,
    description: 'How many sessions the CAEP register holds before the ' +
                 'oldest is dropped. The register is what /admin/caep-' +
                 'sessions draws and it outlives the SESSION it describes ' +
                 'on purpose — a revoked session is gone from the session ' +
                 'store and its row is the only remaining evidence that it ' +
                 'was revoked at all, which is the question that page ' +
                 'exists to answer.' },

  { key: 'caep.eventsPerSession', group: 'CAEP',
    label: 'Events remembered per session', env: 'STS_CAEP_EVENTS_PER_SESSION',
    type: 'int', dflt: 25, min: 1, max: 1000, runtime: true,
    description: 'How many of the latest events a row of the CAEP register ' +
                 'lists. A RING, not a total: the per-type counts beside it ' +
                 'never forget, so a session with thirty events says thirty ' +
                 'and lists the last this many.' },

  { key: 'caep.historyPerSession', group: 'CAEP',
    label: 'Credential changes remembered per session',
    env: 'STS_CAEP_HISTORY_PER_SESSION', type: 'int', dflt: 10, min: 1,
    max: 1000, runtime: true,
    description: 'How many credential-change events a row keeps the details ' +
                 'of, newest first.' },

  { key: 'caep.omitEventTimestamp', group: 'CAEP',
    label: 'Leave event_timestamp out',
    env: 'STS_CAEP_OMIT_EVENT_TIMESTAMP', type: 'bool', dflt: false,
    runtime: true,
    description: 'THE DELIBERATE DEFECT FOR THIS PROFILE, and the one that ' +
                 'is not a defect at all — which is what makes it worth ' +
                 'having. `event_timestamp` is OPTIONAL in CAEP 1.0 section ' +
                 '2, so an event without one is perfectly conforming, and ' +
                 'every receiver that assumes it is there breaks on a ' +
                 'transmitter that omits it. Turning this on produces those ' +
                 'events, so a receiver under test meets the case here ' +
                 'rather than the first time it is pointed at somebody ' +
                 'else\'s transmitter.' },

  // --- RISC ----------------------------------------------------------------
  //
  // The Risk Incident Sharing and Coordination profile (OpenID RISC Profile
  // Specification 1.0, published 29 August 2025 and final on 2 September
  // 2025), which is the SECOND vocabulary over the SSF group above and is a
  // group of its own for the reason CAEP is: its events go out on SSF
  // streams, are signed by the SSF signer, are queued by the SSF queues and
  // are delivered by the two SSF deliveries, so nothing here duplicates a
  // setting up there and ssf.enabled turning off takes RISC with it.
  //
  // WHAT IS NEW HERE THAT CAEP DID NOT BRING. CAEP made this service emit
  // without being asked; RISC makes it emit about something it does not
  // otherwise act on. Setting `active` to false over SCIM has always
  // DEACTIVATED NOBODY here — no endpoint reads the attribute, no bind is
  // refused, no token is withheld, and /admin/scim says so on purpose,
  // because a mock that silently pretended would teach a provisioning client
  // that its deprovisioning path works. That is unchanged. What changes is
  // that the service now SAYS SO, over RISC, which is exactly the division
  // the profile draws: a transmitter reports and a receiver decides.
  { key: 'risc.enabled', group: 'RISC', label: 'RISC enabled',
    env: 'STS_RISC_ENABLED', type: 'bool', dflt: true, runtime: true,
    description: 'When on, this transmitter offers RISC\'s fourteen account ' +
                 'event types, tracks the RISC state of every account it ' +
                 'has been told anything about, and reports both on ' +
                 '/admin/risc-accounts. Turning it off leaves SSF and CAEP ' +
                 'entirely alone and drops the fourteen types from what a ' +
                 'stream may request, so a receiver\'s "this transmitter ' +
                 'will not deliver the type I asked for" path becomes ' +
                 'reachable for this vocabulary without narrowing ' +
                 'ssf.eventsSupported by hand.' },

  { key: 'risc.autoEmit', group: 'RISC',
    label: 'Emit events when the directory really changes',
    env: 'STS_RISC_AUTO_EMIT', type: 'bool', dflt: true, runtime: true,
    description: 'With it on, a person deleted from the directory emits ' +
                 'account-purged, `active` going false or true emits ' +
                 'account-disabled or account-enabled, and a changed mail ' +
                 'or telephone number emits identifier-changed — on every ' +
                 'stream that asked for the type and covers that account, ' +
                 'with nobody having typed anything. Those four acts reach ' +
                 'the directory through SCIM, through LDAP and through the ' +
                 'console alike, because the observer sits on the WRITE ' +
                 'rather than on any one door. Off restores the behaviour ' +
                 'in which every RISC event was asked for, at /admin/risc ' +
                 'or through the management API.' },

  { key: 'risc.autoEmitTypes', group: 'RISC',
    label: 'Which acts emit automatically',
    env: 'STS_RISC_AUTO_EMIT_TYPES', type: 'csv',
    dflt: 'account-purged,account-disabled,account-enabled,' +
          'identifier-changed,account-credential-change-required,' +
          'recovery-information-changed',
    runtime: true,
    description: 'The SHORT NAMES of the RISC events this service emits by ' +
                 'itself, out of the six acts it can actually observe: the ' +
                 'four in its own directory, and — since 2026-09-13 — the ' +
                 'two ' +
                 'an administrator performs on a person\'s /admin/users page ' +
                 'or through /admin-api/users. A password reset or a reset ' +
                 'link emits account-credential-change-required, and ' +
                 'clearing somebody\'s recovery codes (alone, or with every ' +
                 'other second factor) emits recovery-information-changed. ' +
                 'Four of the remaining eight — the opt-out set — are ' +
                 'emitted by hand and CHANGE REAL STATE here when they are, ' +
                 'because RISC defines each of them as "the account is in ' +
                 'this state" rather than as a report that it moved. The ' +
                 'other four describe things nothing here does: no breach ' +
                 'corpus is searched by this service. A row naming one of ' +
                 'the eight is dropped with a warning rather than producing ' +
                 'an event nothing can cause.' },

  { key: 'risc.eventsSupported', group: 'RISC',
    label: 'RISC event types offered', env: 'STS_RISC_EVENTS_SUPPORTED',
    type: 'csv',
    dflt: 'account-credential-change-required,account-purged,' +
          'account-disabled,account-enabled,identifier-changed,' +
          'identifier-recycled,credential-compromise,opt-in,' +
          'opt-out-initiated,opt-out-cancelled,opt-out-effective,' +
          'recovery-activated,recovery-information-changed,sessions-revoked',
    runtime: true,
    description: 'Which of RISC\'s fourteen this transmitter will agree to ' +
                 'deliver, unioned with ssf.eventsSupported and ' +
                 'caep.eventsSupported into the events_supported a receiver ' +
                 'discovers. SHORT NAMES are accepted as well as whole ' +
                 'URIs. The default OFFERS sessions-revoked even though ' +
                 'RISC 1.0 section 2.11 deprecates it in favour of CAEP\'s ' +
                 'session-revoked, deliberately: a transmitter that could ' +
                 'not produce a deprecated event could not be used to find ' +
                 'out what a receiver does with one, and receivers in the ' +
                 'field still send and expect it. Drop it from this list to ' +
                 'be the conforming-and-strict transmitter instead.' },

  { key: 'risc.subjectFormat', group: 'RISC',
    label: 'How an account subject is named',
    env: 'STS_RISC_SUBJECT_FORMAT', type: 'string', dflt: 'iss_sub',
    runtime: true,
    description: 'WHICH RFC 9493 FORMAT this service composes an account ' +
                 'subject in — iss_sub, email or opaque — and it is the ' +
                 'most consequential setting in this group. A RISC event ' +
                 'about an account carries almost nothing but its type and ' +
                 'its subject, so the subject IS the message. iss_sub is ' +
                 'the identifier a receiver already holds (an ID Token\'s ' +
                 'iss and sub said it) and is what this service defaults ' +
                 'to; email is what a receiver keying on an address ' +
                 'expects, and identifier-recycled exists precisely because ' +
                 'that key is unsafe. RISC\'s two identifier events ignore ' +
                 'this and use email regardless, because their subject ' +
                 'carries the identifier that changed.' },

  { key: 'risc.honourOptOut', group: 'RISC',
    label: 'Stop sending about an account that opted out',
    env: 'STS_RISC_HONOUR_OPT_OUT', type: 'bool', dflt: true, runtime: true,
    description: 'RISC section 2.8 gives an account three opt-out states, ' +
                 'and the middle one exists to stop a hijacker silencing ' +
                 'the events that would report them: opt-out-initiated ' +
                 'KEEPS EXCHANGING for a while. With this on, an account ' +
                 'in the final opt-out state has its events suppressed and ' +
                 'the suppression is recorded on /admin/risc-accounts — ' +
                 'except for the four opt-out events themselves, which are ' +
                 'never suppressed, because opt-out-effective is an event ' +
                 'announcing that there will be no more events and opt-in ' +
                 'is the only way a receiver learns the account came back. ' +
                 'Off carries everything, which is how a receiver that ' +
                 'ignores an opt-out gets to be shown doing it.' },

  { key: 'risc.googleSubjectType', group: 'RISC',
    label: 'Write subject_type instead of format',
    env: 'STS_RISC_GOOGLE_SUBJECT_TYPE', type: 'bool', dflt: false,
    runtime: true,
    description: 'THE DELIBERATE DEFECT FOR THIS PROFILE, and it is the one ' +
                 'the specification itself names. RISC 1.0 section 3.1 ' +
                 'records that Google\'s production RISC transmitter spells ' +
                 'the subject identifier\'s discriminator `subject_type` ' +
                 'rather than `format`, says the usage is deprecated and ' +
                 'that new services MUST NOT use it — and then tells ' +
                 'relying parties they need code to work around it anyway, ' +
                 'because that is the transmitter their users\' accounts ' +
                 'live behind. Turning this on renames the member on every ' +
                 'RISC subject this service sends, which is how a receiver ' +
                 'finds out whether it has that code before it is pointed ' +
                 'at Google. It does not touch CAEP or SSF events, whose ' +
                 'specifications never had the problem.' },

  { key: 'risc.reasonLanguage', group: 'RISC',
    label: 'Language tag on reason_admin / reason_user',
    env: 'STS_RISC_REASON_LANGUAGE', type: 'string', dflt: 'en',
    runtime: true,
    description: 'The BCP 47 tag this service keys the two reason members ' +
                 'under on a credential-compromise event, which is the only ' +
                 'one of the fourteen that has them. RISC 1.0 does not ' +
                 'repeat CAEP\'s requirement that they be language maps ' +
                 'rather than strings, which makes a bare string arguably ' +
                 'conforming to RISC and certainly unreadable to a receiver ' +
                 'built against CAEP; this service sends the map, because ' +
                 'that is the reading that is right under both.' },

  { key: 'risc.includeReasons', group: 'RISC',
    label: 'Send reason_admin and reason_user',
    env: 'STS_RISC_INCLUDE_REASONS', type: 'bool', dflt: true, runtime: true,
    description: 'Whether a credential-compromise event carries the two ' +
                 'reason members. Both are optional, so turning this off is ' +
                 'how a receiver that assumes a reason is always there gets ' +
                 'to fail in a test rather than in production. It reaches ' +
                 'ONE of the fourteen event types, unlike its CAEP ' +
                 'namesake, which reaches all eight — RISC gives those ' +
                 'members to credential-compromise alone.' },

  { key: 'risc.omitEventTimestamp', group: 'RISC',
    label: 'Leave event_timestamp out',
    env: 'STS_RISC_OMIT_EVENT_TIMESTAMP', type: 'bool', dflt: false,
    runtime: true,
    description: 'The same deliberate-and-conforming omission ' +
                 'caep.omitEventTimestamp produces, on the one RISC event ' +
                 'that defines the member. It matters differently here: ' +
                 'RISC words event_timestamp as when the transmitter ' +
                 'DISCOVERED the compromise rather than when it happened, ' +
                 'so a receiver reading it as an occurrence time dates the ' +
                 'incident from the wrong end whether or not it is sent.' },

  { key: 'risc.maxAccountsTracked', group: 'RISC',
    label: 'Accounts tracked', env: 'STS_RISC_MAX_ACCOUNTS_TRACKED',
    type: 'int', dflt: 200, runtime: true,
    description: 'How many accounts the RISC register holds before the ' +
                 'oldest is dropped. It outlives the ACCOUNT it describes ' +
                 'on purpose and more starkly than CAEP\'s register does: a ' +
                 'purged account is gone from the directory entirely, and ' +
                 'its row is the only remaining evidence that this service ' +
                 'ever told anybody it was purged.' },

  { key: 'risc.eventsPerAccount', group: 'RISC',
    label: 'Events remembered per account', env: 'STS_RISC_EVENTS_PER_ACCOUNT',
    type: 'int', dflt: 25, min: 1, max: 1000, runtime: true,
    description: 'How many of the latest events a row of the RISC register ' +
                 'lists. A ring beside counts that never forget, as in CAEP.' },

  { key: 'risc.historyPerAccount', group: 'RISC',
    label: 'Credential and identifier changes remembered per account',
    env: 'STS_RISC_HISTORY_PER_ACCOUNT', type: 'int', dflt: 10, min: 1,
    max: 1000, runtime: true,
    description: 'How many credential-compromise and identifier-change ' +
                 'records a row keeps, each list separately, newest first.' },

  // --- The group claim -----------------------------------------------------
  //
  // The one feature in this service that reads the directory's GROUPS back out
  // and puts them somewhere a protocol client can see. Everything else about a
  // group here is still true — see /admin/groups: a group GRANTS nothing, no
  // endpoint checks one, and nothing decides anything on the claim. What
  // changed is that a token can now CARRY it, which is a different sentence
  // and the two must not be merged; it is the same distinction this service
  // already draws between an identity being RECORDED and an identity being
  // authenticated.
  //
  // All four are runtime and honestly so: group_claims.js reads each of them
  // per token rather than capturing it at require time, which is the rule a
  // runtime setting has to be able to defend. There is nothing derived at
  // startup here — the membership is read out of the live directory at the
  // moment a token is minted, so an `ldapadd` of a member changes the very next
  // one.
  { key: 'groups.claim', group: 'Group claim', label: 'Carry a groups claim',
    env: 'STS_GROUPS_CLAIM', type: 'bool', dflt: true, runtime: true,
    description: 'When on, every OAuth 2.0 access token, OIDC ID Token, SAML ' +
                 '2.0 assertion and SAML 1.1 assertion this service issues ' +
                 'carries a claim naming the directory groups the person is ' +
                 'a member of. ON by default and yet it changes nothing for ' +
                 'most callers: the claim is OMITTED ENTIRELY for anybody ' +
                 'who is in no group, which on a fresh start is everybody ' +
                 'except the seeded people, so a client that never touched ' +
                 'ou=groups sees the tokens it saw before. Turning it off is ' +
                 'how a client\'s "no groups claim" path stays reachable. ' +
                 'The membership is read from the live directory per token, ' +
                 'so an ldapmodify changes the next one.' },

  { key: 'groups.claimName', group: 'Group claim', label: 'Claim name',
    env: 'STS_GROUPS_CLAIM_NAME', type: 'string', dflt: 'groups', runtime: true,
    description: 'What the claim is called: the JWT member name, the SAML ' +
                 '2.0 Attribute Name and the SAML 1.1 AttributeName. ' +
                 '`groups` is the conventional spelling and what most ' +
                 'relying parties look for, but `roles` and a URI are both ' +
                 'common and both worth being able to produce. A name this ' +
                 'service sets itself is REFUSED at issuance time rather ' +
                 'than allowed to collide — see the reserved list on ' +
                 '/admin/claims, which is the same rule a typed custom claim ' +
                 'follows.' },

  { key: 'groups.claimValue', group: 'Group claim', label: 'What names a group',
    env: 'STS_GROUPS_CLAIM_VALUE', type: 'enum', enumValues: ['cn', 'dn'],
    dflt: 'cn', runtime: true,
    description: 'Whether each value is the group\'s common name ' +
                 '(`developers`) or its whole DN ' +
                 '(`cn=developers,ou=groups,dc=example,dc=com`). Both are ' +
                 'what somebody\'s real identity provider does — an OIDC ' +
                 'provider usually sends names and Active Directory sends ' +
                 'DNs — and a client that has only ever parsed one of them ' +
                 'has never run the other path.' },

  { key: 'groups.claimFromMemberOf', group: 'Group claim',
    label: 'Believe an entry\'s own memberOf',
    env: 'STS_GROUPS_CLAIM_FROM_MEMBEROF', type: 'bool', dflt: true,
    runtime: true,
    description: 'Whether a group named by the PERSON\'S own `memberOf` ' +
                 'counts as membership when the group entry does not list ' +
                 'them back. Nothing in this directory maintains memberOf — ' +
                 'it is not even a standard attribute — so a client that ' +
                 'writes it creates exactly that disagreement, and ' +
                 '/admin/groups exists partly to SHOW it. This setting is ' +
                 'which side of it a token believes. On by default, because ' +
                 'a client that wrote memberOf and got no claim has been ' +
                 'told nothing about why; off is how the group entry stays ' +
                 'the only authority. Either way the group has to EXIST here ' +
                 '— a memberOf naming nothing does not invent a group to put ' +
                 'in a token.' },

  // --- Roles ---------------------------------------------------------------
  //
  // A role is the one thing here a user, a group AND an application can all be
  // mapped into, and it has two halves that are configured in different
  // places: MEMBERSHIP lives on the role entry (/admin/roles) and the
  // REQUIREMENT lives on the application entry (its own page). These four
  // settings are about the halves that belong to neither — the claim, and
  // whether the decision is asked for at all.
  { key: 'roles.claim', group: 'Roles', label: 'Carry a roles claim',
    env: 'STS_ROLES_CLAIM', type: 'bool', dflt: true, runtime: true,
    description: 'When on, every access token, ID Token, SAML 2.0 assertion ' +
                 'and SAML 1.1 assertion names the roles its subject holds. ' +
                 'ON by default and it still changes nothing for most ' +
                 'callers, for the reason the groups claim is on by default: ' +
                 'the claim is OMITTED ENTIRELY for anybody holding no ' +
                 'CONFIGURED role, and the six built-in roles are never in ' +
                 'it — EVERYBODY and ALL_AUTHENTICATED_USERS are true of ' +
                 'almost every token here, so carrying them would add two ' +
                 'meaningless members to every token every existing client ' +
                 'parses and tell a relying party nothing it did not know ' +
                 'from holding the token. They exist to be REQUIRED, not to ' +
                 'be carried.' },

  { key: 'roles.claimName', group: 'Roles', label: 'Role claim name',
    env: 'STS_ROLES_CLAIM_NAME', type: 'string', dflt: 'roles', runtime: true,
    description: 'What the claim is called, and ALSO what is looked for on ' +
                 'the way IN: the embedded PEP reads this member out of a ' +
                 'token a caller presented and unions what it finds with the ' +
                 'register\'s own answer. So changing it changes both ' +
                 'directions at once, which is the point — a deployment that ' +
                 'calls them `groups` or `http://schemas.../role` should be ' +
                 'able to say so once.' },

  { key: 'roles.enforceIssuance', group: 'Roles',
    label: 'Decide issuance on roles',
    env: 'STS_ROLES_ENFORCE_ISSUANCE', type: 'bool', dflt: true,
    runtime: true,
    description: 'Whether an issuance asks the PDP whether the party being ' +
                 'authenticated holds a role the application requires. ON by ' +
                 'default AND OFF PER APPLICATION, which is not a ' +
                 'contradiction: an application that names no required role ' +
                 'requires EVERYBODY, everybody holds EVERYBODY, and the ' +
                 'answer is Permit — exactly what this service did before ' +
                 'roles existed. Turning THIS off stops the question being ' +
                 'asked at all, which is the way back if a policy edit ' +
                 'locks something out. What is refused is refused in the ' +
                 'protocol\'s own words: access_denied at an OAuth endpoint, ' +
                 'a page at a browser one.' },

  // THE SETTING THAT MAKES TWO OF THE SIX BUILT-IN ROLES REACHABLE AT ALL.
  //
  // `ALL_UNAUTHENTICATED_USERS` names a person who has NOT authenticated, and
  // until 2026-09-05 there was no such person for any issuance to be about:
  // every session this service held was one somebody had signed into, so the
  // role was a name a policy could match and nothing could ever hold at an
  // issuance site. The sign-in screen's Cancel button is not it — that returns
  // `access_denied` to the calling protocol and creates nothing, which is the
  // OAuth contract and is deliberately untouched.
  //
  // With this on, the sign-in screen grows a THIRD button — "Continue without
  // signing in" — and pressing it mints a real session that says
  // `authenticated: false`. Everything downstream then reads that flag instead
  // of assuming what it used to assume, so an application requiring
  // ALL_AUTHENTICATED_USERS refuses that session and one requiring EVERYBODY
  // does not. That difference IS the distinction between the two roles, and it
  // was not observable before.
  //
  // OFF BY DEFAULT, unlike `roles.enforceIssuance` beside it, and the reason is
  // that this one changes a SCREEN. Enforcement on by default changes nothing
  // for an unedited service because everybody holds EVERYBODY; a third button
  // on every sign-in screen in the service would change what every existing
  // caller's user sees, which is not something a default should do.
  //
  // The group is `Roles` and the key is `authn.` on purpose, and the split is
  // the one the WS-Federation assertion setting already makes: the key says
  // which module OWNS the behaviour, and the group says which page a person
  // reasoning about it is on. Somebody reading ALL_UNAUTHENTICATED_USERS on
  // /admin/roles and wondering how anything could ever hold it is the reader
  // this row is for.
  { key: 'authn.unauthenticatedSessions', group: 'Roles',
    label: 'Offer "Continue without signing in"',
    env: 'STS_AUTHN_UNAUTHENTICATED_SESSIONS', type: 'bool', dflt: false,
    runtime: true,
    description: 'Show a third button on /authn/login that starts a session ' +
                 'for somebody who declines to authenticate. The session is ' +
                 'real — it has a cookie, it satisfies a flow already in ' +
                 'progress, and it appears on /admin/sessions in a section ' +
                 'of its own — but it is marked `authenticated: false`, so ' +
                 'an application requiring ALL_AUTHENTICATED_USERS refuses ' +
                 'it and one requiring EVERYBODY does not. That is the only ' +
                 'place in this service where the difference between those ' +
                 'two built-in roles can be seen. The person is the stable ' +
                 '`anonymous` principal, which gets a directory entry like ' +
                 'anybody else and can therefore hold configured roles too. ' +
                 'Cancel is unchanged and still answers access_denied.' },

  { key: 'roles.maxRoles', group: 'Roles', label: 'Maximum roles',
    env: 'STS_ROLES_MAX', type: 'int', dflt: 200, runtime: true,
    description: 'How many entries ou=roles may hold. The same cap every ' +
                 'other container here carries and for the same reason: this ' +
                 'directory is a Map in one process, and an unbounded ' +
                 'register reachable from an ungated /admin-api is a way to ' +
                 'exhaust it.' },

  { key: 'roles.remotePepGroup', group: 'Roles',
    label: 'Group granting the REMOTE_PEPS role',
    env: 'STS_ROLES_REMOTE_PEP_GROUP', type: 'string', dflt: 'remote-peps',
    runtime: true,
    description: 'The directory group whose members hold the built-in ' +
                 'REMOTE_PEPS role, which is what the three /xacml/pep ' +
                 'endpoints require. A remote Policy Enforcement Point ' +
                 'presenting a client certificate this service VERIFIED is ' +
                 'somebody it can name; membership of this group is what ' +
                 'makes them somebody it lets in, and the two are kept apart ' +
                 'on purpose — a certificate proves an identity and a group ' +
                 'grants a permission. Setting it to the empty string means ' +
                 'NOBODY holds the role, which closes those three endpoints ' +
                 'to every caller including a correctly configured PEP.' },

  { key: 'roles.xacmlUserGroup', group: 'Roles',
    label: 'Group granting the XACML_USER role',
    env: 'STS_ROLES_XACML_USER_GROUP', type: 'string', dflt: 'xacml-users',
    runtime: true,
    description: 'The directory group whose members hold the built-in ' +
                 'XACML_USER role, which is what the four XACML endpoints ' +
                 'proper require — GET /xacml, POST /xacml/pdp, GET ' +
                 '/xacml/policies and GET /xacml/protected. A caller ' +
                 'presenting a client certificate this service VERIFIED is ' +
                 'somebody it can name; membership of this group is what ' +
                 'makes them somebody it lets in, and the two are kept apart ' +
                 'for the reason roles.remotePepGroup above is: a ' +
                 'certificate proves an identity and a group grants a ' +
                 'permission. IT IS A SECOND GROUP AND NOT THE SAME ONE: ' +
                 'REMOTE_PEPS reaches the three /xacml/pep endpoints, which ' +
                 'hand out the documents this service enforces its own ' +
                 'access with, and one group granting both would make ' +
                 'admitting a caller to the demonstration surface silently ' +
                 'admit it to those. Setting it to the empty string means ' +
                 'NOBODY holds the role, which closes those four endpoints ' +
                 'to every caller; that is the way to take the XACML surface ' +
                 'away without turning xacml.enabled off and losing the ' +
                 'embedded issuance and access PEPs with it.' },

  { key: 'xacml.issuancePolicy', group: 'XACML',
    label: 'The policy issuance decisions are made with',
    env: 'STS_XACML_ISSUANCE_POLICY', type: 'string', dflt: 'role-issuance',
    runtime: true,
    description: 'The directory entry name of the policy the EMBEDDED PEP ' +
                 'evaluates for this service\'s own issuance decisions. It ' +
                 'is deliberately NOT the repository root: the root answers ' +
                 'questions about somebody else\'s boundary — that is what a ' +
                 'PDP is for and what /xacml/pdp and every remote PEP ask it ' +
                 '— and this one answers a question about THIS service. Two ' +
                 'questions, two documents, so that editing the demo policy ' +
                 'cannot change who may sign in and narrowing a role cannot ' +
                 'change what /xacml/pdp answers. It is created from the ' +
                 '`role-issuance` template and seeded on first start.' },

  // --- Audit log -----------------------------------------------------------
  //
  // Both are runtime and both are honestly so: audit.js reads them per event
  // rather than capturing them at require time, which is the rule a runtime
  // setting has to be able to defend. Lowering the cap trims on the very next
  // event rather than one row per event thereafter.
  { key: 'audit.maxEvents', group: 'Audit log', label: 'Maximum events held',
    env: 'AUDIT_MAX_EVENTS', type: 'int', dflt: 5000, runtime: true,
    description: 'How many audit events /admin/audit keeps before the oldest ' +
                 'are dropped. What was dropped is COUNTED and shown, so a ' +
                 'truncated log says it was truncated rather than implying ' +
                 'the cap is all there ever was. Lowering it takes effect on ' +
                 'the next event and discards the excess immediately.' },

  { key: 'audit.protocolCalls', group: 'Audit log',
    label: 'Record protocol endpoint calls',
    env: 'AUDIT_PROTOCOL_CALLS', type: 'bool', dflt: true, runtime: true,
    description: 'Whether every call into a protocol endpoint gets an audit ' +
                 'event. On by default, because "everything this service was ' +
                 'asked to do" is the point of the log — but it is by far ' +
                 'the noisiest source (every JWKS poll and metadata fetch is ' +
                 'one), so turning it off is how somebody watching the ' +
                 'directory or the console gets a readable page. It never ' +
                 'affects the other five categories, and /admin/metrics ' +
                 'counts every call either way.' },

  // --- Delegation ----------------------------------------------------------
  //
  // ONE setting, and the absence of a second is deliberate.
  // `audit.protocolCalls` exists because that log's noisiest source drowns the
  // rest of it; delegation has no noisy source — an act is a service asking to
  // be somebody, which is rare and is the thing a person came to the page for —
  // so there is nothing an off switch would rescue. Runtime and honestly so:
  // delegation.js reads the cap per act rather than capturing it at require
  // time.
  { key: 'delegation.maxRecords', group: 'Delegation',
    label: 'Maximum delegation acts held',
    env: 'DELEGATION_MAX_RECORDS', type: 'int', dflt: 2000, runtime: true,
    description: 'How many delegation acts /admin/delegation keeps before ' +
                 'the oldest are dropped. An act is one exchange in which ' +
                 'somebody acted on somebody else\'s behalf — a Kerberos S4U ' +
                 'request or forwarded ticket, a WS-Trust OnBehalfOf or ' +
                 'ActAs, an RFC 8693 token exchange — and REFUSED attempts ' +
                 'are recorded too, which is where most of the value is. ' +
                 'What was dropped is COUNTED and shown, so a truncated list ' +
                 'says so rather than implying the cap is all there ever ' +
                 'was. Lowering it takes effect on the next act and discards ' +
                 'the excess immediately.' },

  // --- Logout --------------------------------------------------------------
  //
  // FOUR SETTINGS AND THEY ARE ONE FEATURE: `GET /logout`, the protocol-
  // independent sign-out at the root of this service. Three of them exist
  // because this feature is the first thing here that TAKES SOMETHING AWAY
  // across families — a Kerberos ticket-granting ticket stops working at the
  // KDC, an LDAP connection is dropped underneath a client that is using it —
  // and every refusal in this service is switchable for the reason the RFC 9700
  // mode is: a client is exercised by both answers, and a refusal that cannot
  // be turned off removes a test case.
  //
  // The fourth (`logout.anyUser`) is not a refusal at all but the opposite: it
  // is what makes the endpoint drivable by a test that holds no cookie, and
  // turning it OFF is the tightening rather than the loosening.
  { key: 'logout.anyUser', group: 'Logout',
    label: 'Allow /logout to name somebody else',
    env: 'LOGOUT_ANY_USER', type: 'bool', dflt: true, runtime: true,
    description: 'Whether GET|POST /logout honours a `username` parameter ' +
                 'naming somebody other than whoever the session cookie ' +
                 'names. ON by default, and IN DEVELOPMENT MODE it grants ' +
                 'nothing that was not already true: no password is checked ' +
                 'at any sign-in screen there, so anybody who can reach this ' +
                 'port can already BECOME that person in one request and log ' +
                 'themselves out. What it buys is a headless test — the ' +
                 'inventory and the termination are drivable with no browser ' +
                 'and no cookie. **IN PRODUCT MODE IT IS IGNORED**: a ' +
                 'password is verified there, so naming somebody else would ' +
                 'let an anonymous caller end any person\'s sessions and ' +
                 'revoke their tokens, and /logout names only the signed-in ' +
                 'caller whatever this says. Turning it OFF makes /logout ' +
                 'act on the caller\'s own session and nothing else, and ' +
                 '403s a request that names another name; /admin/logout and ' +
                 '/admin-api/logout are unaffected, because those are the ' +
                 'operator\'s door and are behind the console\'s two roles.' },

  { key: 'logout.kerberosSignOut', group: 'Logout',
    label: 'A logout stops older Kerberos tickets at the KDC',
    env: 'LOGOUT_KERBEROS_SIGN_OUT', type: 'bool', dflt: true, runtime: true,
    description: 'Whether logging somebody out stamps a SIGN-OUT INSTANT on ' +
                 'their Kerberos principal, after which a TGS-REQ carrying a ' +
                 'ticket whose authtime is EARLIER is refused ' +
                 'KDC_ERR_TGT_REVOKED (20). It is the only thing a KDC can ' +
                 'honestly do about a credential it handed out and cannot ' +
                 'recall. KDC_ERR_TGT_REVOKED is a REGISTERED code whose ' +
                 'text says what is meant (RFC 4120 section 7.5.9) — but the ' +
                 'specification defines no mechanism that emits it, and ' +
                 'Kerberos has no logout, no session and no revocation at ' +
                 'all, so this instant is an invention rather than a spec\'d ' +
                 'behaviour. It is the same lever a real KDC has: the TGS ' +
                 'exchange is the one moment the KDC is back in the loop. ' +
                 'What it does NOT do is stop a service ticket already in a ' +
                 'cache from working against the service that accepts it — ' +
                 'nothing contacts the KDC on that exchange — which is a ' +
                 'fact about Kerberos rather than a gap here, and /logout ' +
                 'says so on the row. An AS-REQ still succeeds: signing out ' +
                 'is not disabling an account, and the next authentication ' +
                 'clears the instant. Turning it OFF leaves the KDC behaving ' +
                 'exactly as it did before this feature existed.' },

  { key: 'logout.ldapDisconnect', group: 'Logout',
    label: 'A logout drops LDAP connections bound as that person',
    env: 'LOGOUT_LDAP_DISCONNECT', type: 'bool', dflt: true, runtime: true,
    description: 'Whether logging somebody out closes every connection to ' +
                 'the embedded directory — 389 and LDAPS 636 alike — whose ' +
                 'bind DN names them. RFC 4511 section 4.2 makes a bind the ' +
                 'authorization state of a CONNECTION, so the connection is ' +
                 'the session and dropping it is the only sign-out LDAP has. ' +
                 'The client sees its socket close mid-conversation, which ' +
                 'is what a directory server that revokes a session looks ' +
                 'like from the other end and is worth being able to point a ' +
                 'client at. Turning it OFF leaves the connections alone and ' +
                 'lists them on /logout as untouched rather than hiding ' +
                 'them.' },

  { key: 'logout.maxRows', group: 'Logout',
    label: 'Maximum rows in one logout inventory',
    env: 'LOGOUT_MAX_ROWS', type: 'int', dflt: 500, runtime: true,
    description: 'How many live sessions and credentials /logout will list ' +
                 'for one person before it stops counting them individually. ' +
                 'Past it the page says how many were not listed and a ' +
                 'global logout still ends ALL of them — the cap is on what ' +
                 'is drawn and offered as a checkbox, never on what a ' +
                 'termination reaches, because a sign-out that silently ' +
                 'missed the five-hundred-and-first token would be the worst ' +
                 'kind of wrong here.' },

  // --- SPIFFE / SPIRE ------------------------------------------------------
  //
  // The three server-side surfaces of SPIFFE: the bundle endpoint (plain
  // HTTPS), the Workload API (gRPC, on a Unix socket and/or TCP) and the SPIRE
  // Server API (gRPC, likewise). What is restart-only here and why is the
  // ordinary split the header of this file describes: a BOUND SOCKET (all four
  // listeners) and MATERIAL DERIVED AT STARTUP (the trust domain, which every
  // authority's certificate names, and the two key types those authorities are
  // generated with). Everything else is read where it is used.
  //
  // -------------------------------------------------------------------------
  // **AND SIX OF THESE ROWS CARRY `realmRuntime` SINCE 2026-09-12, WHICH IS
  // THE SECOND HOLDER OF THAT MARKER AND THE ARGUMENT IS MADE HERE RATHER THAN
  // CITED FROM `oauth2.rfc9700`.**
  //
  // The marker's test — the paragraph at the top of this file — is that *the
  // restart reason has to be something a realm demonstrably does not have*.
  // For `oauth2.rfc9700` that was a SOCKET: a realm binds none. **For SPIFFE a
  // realm now DOES bind sockets, and that is exactly why these rows pass the
  // test rather than failing it.** The reason the six are restart-only is that
  // this process binds four listeners and builds one trust domain's
  // authorities WHEN IT STARTS. A realm's SPIFFE is not started then: it is
  // OFF when the realm is created (see `realms.js`'s seeded overrides), its
  // authorities are built on FIRST USE, and its listeners are bound when
  // `spiffe.enabled` is turned on for it — `spiffe_server.js` reconciles on
  // `realms.onChange()`, which `realms.setOverride()` fires. So for a realm
  // there is no startup at which any of this was consumed.
  //
  // **THE DISAGREEMENT THAT MARKER USUALLY CAUSES IS CLOSED RATHER THAN
  // ACCEPTED.** Two of the six decide MATERIAL that outlives the change:
  // `spiffe.trustDomain` is named by every certificate a realm's authority has
  // issued, and the two key types are what it was generated with. Changing one
  // for a realm whose authority has already been built would be /admin/config
  // reporting one trust domain while the CA went on issuing another — so
  // `spiffe_ca.js` records the trust domain each realm's authority was BUILT
  // with, keeps using it, and reports the disagreement on `GET /spiffe` and in
  // the log. The way to change it is the way to change any other identity a
  // realm has already used: turn that realm's SPIFFE off, which discards its
  // authorities, and turn it on again.
  //
  // The DEFAULT realm is unchanged in every respect: its listeners are bound
  // at startup, its authorities are built there, and every one of these rows
  // is refused at runtime process-wide exactly as before.
  // -------------------------------------------------------------------------
  { key: 'spiffe.enabled', group: 'SPIFFE', label: 'Enable SPIFFE',
    env: 'STS_SPIFFE_ENABLED', type: 'bool', dflt: true, runtime: true,
    description: 'Whether the three SPIFFE surfaces answer. Off, the routes ' +
                 'are still registered — so /admin/sts-metadata still ' +
                 'describes them and /spiffe still says what this is — but ' +
                 'the bundle endpoint answers 404 and every gRPC call is ' +
                 'refused with Unavailable. Read per request, so it can be ' +
                 'turned off without a restart. **ON a REALM it decides ' +
                 'whether that realm has SPIFFE sockets at all**, and a ' +
                 'realm is CREATED WITH IT OFF: turning it on builds that ' +
                 'realm\'s authorities and binds its own Workload API and ' +
                 'SPIRE Server API listeners, on the address spiffe.grpcHost ' +
                 'names for it. This process\'s own four listeners are bound ' +
                 'at startup for the default realm and are not taken away by ' +
                 'turning this off — they answer Unavailable instead, ' +
                 'because a socket that vanished would be indistinguishable ' +
                 'from a service that had stopped.' },

  { key: 'spiffe.trustDomain', group: 'SPIFFE', label: 'Trust domain',
    env: 'STS_SPIFFE_TRUST_DOMAIN', type: 'string', dflt: 'example.org',
    runtime: false, realmRuntime: true,
    restartReason: 'the X.509 and JWT authorities are generated at startup ' +
                   'and every certificate they hold names this trust domain. ' +
                   'A REALM may carry it even so — a realm is created with ' +
                   'SPIFFE off and builds its authorities when it is turned ' +
                   'on, so nothing about a realm\'s trust domain was ' +
                   'consumed at startup. Once that realm HAS built them the ' +
                   'name is fixed and spiffe_ca.js says so',
    description: 'The trust domain this service is the issuing authority ' +
                 'for: the authority part of every SPIFFE ID it mints, so ' +
                 'spiffe://example.org/… by default. LOWER-CASE, and only ' +
                 'letters, digits, dots, dashes and underscores — an ' +
                 'upper-case trust domain is not a valid SPIFFE ID and is ' +
                 'not another spelling of the lower-case one either. **IT IS ' +
                 'ALSO THE COMMON ROOT EVERY OTHER REALM\'S IS BUILT FROM**: ' +
                 'a realm created here is given `<realm>.<this value>` as ' +
                 'its own — acme.example.org — the way it is given an ' +
                 'entityID of its own, because two realms sharing a trust ' +
                 'domain are two issuing authorities claiming one name and ' +
                 'every SVID either mints is then ambiguous. Set it on a ' +
                 'realm to name that realm\'s domain outright; a realm does ' +
                 'not have to sit under this root, and a realm deliberately ' +
                 'sharing another\'s is a thing worth being able to build on ' +
                 'a mock.' },

  { key: 'spiffe.x509KeyType', group: 'SPIFFE', label: 'X.509 authority key',
    env: 'STS_SPIFFE_X509_KEY_TYPE', type: 'enum',
    enumValues: ['ec-p256', 'ec-p384', 'ec-p521', 'rsa-2048', 'rsa-4096',
                 'ed25519'],
    dflt: 'ec-p256', runtime: false, realmRuntime: true,
    restartReason: 'the X.509 authority is generated with this key type at ' +
                   'startup',
    description: 'The key the trust domain\'s X.509 authority is generated ' +
                 'with, and therefore the key type of every X509-SVID it ' +
                 'signs. EC P-256 by default because that is what SPIRE ' +
                 'issues and what the X509-SVID specification recommends. ' +
                 'RSA 4096 takes several seconds to generate at startup, ' +
                 'which is worth knowing before wondering why the bundle ' +
                 'endpoint is not answering yet.' },

  { key: 'spiffe.jwtKeyType', group: 'SPIFFE', label: 'JWT authority key',
    env: 'STS_SPIFFE_JWT_KEY_TYPE', type: 'enum',
    enumValues: ['ec-p256', 'ec-p384', 'ec-p521', 'rsa-2048', 'rsa-4096'],
    dflt: 'ec-p256', runtime: false, realmRuntime: true,
    restartReason: 'the JWT authority is generated with this key type at ' +
                   'startup. A REALM builds its own when its SPIFFE is ' +
                   'turned on, so it may carry this — see the block at the ' +
                   'head of this group',
    description: 'The key the trust domain\'s JWT authority is generated ' +
                 'with, which decides the `alg` of every JWT-SVID: ES256, ' +
                 'ES384, ES512 or RS256. Ed25519 is DELIBERATELY ABSENT here ' +
                 'and present for X.509 — jsonwebtoken, this service\'s JWS ' +
                 'implementation, does not sign EdDSA, so offering it would ' +
                 'be a setting that fails at the first FetchJWTSVID rather ' +
                 'than at startup.' },

  { key: 'spiffe.caTtl', group: 'SPIFFE', label: 'Authority lifetime (seconds)',
    env: 'STS_SPIFFE_CA_TTL', type: 'int', dflt: 86400, runtime: false,
    restartReason: 'the authority certificate is issued for this long at ' +
                   'startup',
    description: 'How long the X.509 authority\'s own certificate is valid. ' +
                 'An SVID is never issued past it — a leaf outliving its ' +
                 'issuer works until it suddenly does not, and nothing in ' +
                 'that failure names the CA — so a short authority lifetime ' +
                 'silently shortens every SVID with it.' },

  { key: 'spiffe.svidTtl', group: 'SPIFFE', label: 'X509-SVID lifetime ' +
                                                   '(seconds)',
    env: 'STS_SPIFFE_SVID_TTL', type: 'int', dflt: 3600, runtime: true,
    description: 'The default lifetime of an X509-SVID. A registration entry ' +
                 'may name its own and that wins; this is what an entry with ' +
                 'no `x509SvidTtl` gets. SPIRE\'s default is an hour and so ' +
                 'is this: rotation is the interesting behaviour to exercise ' +
                 'in a client, and a long-lived SVID never rotates.' },

  { key: 'spiffe.jwtSvidTtl', group: 'SPIFFE', label: 'JWT-SVID lifetime ' +
                                                      '(seconds)',
    env: 'STS_SPIFFE_JWT_SVID_TTL', type: 'int', dflt: 300, runtime: true,
    description: 'The default lifetime of a JWT-SVID. Much shorter than the ' +
                 'X.509 one on purpose and in both SPIRE and here: a ' +
                 'JWT-SVID is a bearer credential — whoever holds it can ' +
                 'present it — where an X509-SVID is bound to a private key.' },

  { key: 'spiffe.refreshHint', group: 'SPIFFE', label: 'Bundle refresh hint ' +
                                                       '(seconds)',
    env: 'STS_SPIFFE_REFRESH_HINT', type: 'int', dflt: 300, runtime: true,
    description: 'The `spiffe_refresh_hint` published in the bundle: how ' +
                 'often a consumer should come back for it. It matters more ' +
                 'against this service than against a real one, because the ' +
                 'whole bundle is regenerated on every restart — a consumer ' +
                 'that never refreshes will fail to verify every SVID minted ' +
                 'after one, with nothing in the failure naming the bundle.' },

  { key: 'spiffe.svidSubject', group: 'SPIFFE', label: 'SVID subject DN',
    env: 'STS_SPIFFE_SVID_SUBJECT', type: 'string', dflt: 'C=US,O=SPIRE',
    runtime: true,
    description: 'The X.501 subject written into every X509-SVID. The SPIFFE ' +
                 'ID is in a URI subjectAltName and IS the identity; this is ' +
                 'decoration, and it is SPIRE\'s own value by default so ' +
                 'that an SVID from here looks like one from there. It ' +
                 'cannot be empty: an empty subject is refused by the ' +
                 'certificate builder and is rendered as a blank line by ' +
                 'every tool a person might inspect one with.' },

  { key: 'spiffe.caSubject', group: 'SPIFFE', label: 'CA subject DN template',
    env: 'STS_SPIFFE_CA_SUBJECT', type: 'string',
    dflt: 'CN=sts SPIFFE {kind} ({trustDomain}),O=sts',
    runtime: true,
    description: 'The X.501 subject of a CA certificate this service builds ' +
                 'for SPIFFE itself: the SELF-SIGNED authority a realm with ' +
                 'no certificate authority falls back to, and every ' +
                 'downstream CA NewDownstreamX509CA mints. {kind} becomes ' +
                 '"CA" or "downstream CA" and {trustDomain} the realm\'s ' +
                 'trust domain. A realm whose authority is its SPIFFE ' +
                 'Issuing CA under the service Root takes that subject from ' +
                 '/admin/pki instead. spiffe.svidSubject is the leaves\' ' +
                 'subject.' },

  { key: 'spiffe.retainedAuthorities', group: 'SPIFFE',
    label: 'Authorities kept published after a rotation',
    env: 'STS_SPIFFE_RETAINED_AUTHORITIES', type: 'int', dflt: 4, min: 2,
    max: 64, runtime: true,
    description: 'How many authorities a rotation keeps in the bundle, the ' +
                 'new one included, for the SELF-SIGNED X.509 authority and ' +
                 'for the JWT authority. Past it the oldest is dropped and ' +
                 'everything it signed stops verifying. At least 2, because ' +
                 'keeping only the new one makes every rotation an outage. A ' +
                 'rotation under the certificate authority retains nothing: ' +
                 'the bundle is the Root, which a rotation does not move.' },

  { key: 'spiffe.agentSvidTtl', group: 'SPIFFE', label: 'Agent SVID lifetime ' +
                                                        '(seconds)',
    env: 'STS_SPIFFE_AGENT_SVID_TTL', type: 'int', dflt: 0, min: 0,
    runtime: true,
    description: 'The lifetime of the X509-SVID an agent is issued by ' +
                 'AttestAgent and RenewAgent. 0 — the default — means ' +
                 'spiffe.svidTtl, which is what this service has always ' +
                 'given an agent; 0 is a meaning here and not "unset". SPIRE ' +
                 'gives agents their own, usually longer, lifetime.' },

  { key: 'spiffe.joinTokenTtl', group: 'SPIFFE', label: 'Join token lifetime ' +
                                                        '(seconds)',
    env: 'STS_SPIFFE_JOIN_TOKEN_TTL', type: 'int', dflt: 600, min: 1,
    runtime: true,
    description: 'How long a join token from CreateJoinToken lives when the ' +
                 'request names no ttl. A request\'s own ttl still wins.' },

  { key: 'spiffe.maxJoinTokens', group: 'SPIFFE', label: 'Unspent join ' +
      'tokens held',
    env: 'STS_SPIFFE_MAX_JOIN_TOKENS', type: 'int', dflt: 256, min: 1,
    max: 100000, runtime: true,
    description: 'How many unexpired, unspent join tokens a realm holds. ' +
                 'Expired tokens are swept first; at the bound a NEW ' +
                 'CreateJoinToken is refused with RESOURCE_EXHAUSTED rather ' +
                 'than a token already handed to an agent being evicted — ' +
                 'the caller asking can see a refusal, an agent holding an ' +
                 'evicted token could not.' },

  { key: 'spiffe.maxPageSize', group: 'SPIFFE', label: 'Largest page a List* ' +
                                                       'returns',
    env: 'STS_SPIFFE_MAX_PAGE_SIZE', type: 'int', dflt: 1000, min: 1,
    max: 100000, runtime: true,
    description: 'The cap on page_size for every SPIRE Server API List* ' +
                 'method. A request with no page_size still gets every row.' },

  { key: 'spiffe.maxRecordedConnections', group: 'SPIFFE',
    label: 'mTLS connections remembered',
    env: 'STS_SPIFFE_MAX_RECORDED_CONNECTIONS', type: 'int', dflt: 512,
    min: 1, max: 1000000, runtime: true, perProcess: true,
    description: 'How many SPIRE Server API connections are remembered so ' +
                 'that an X509-SVID is recorded as ONE authentication per ' +
                 'connection rather than one per call. Past it the oldest is ' +
                 'forgotten, which costs one duplicate row on a long-lived ' +
                 'connection. Each realm remembers its own listeners\' ' +
                 'connections, up to this many; it is per process so that no ' +
                 'realm sets the cap for the others.' },

  { key: 'spiffe.autoCreateEntries', group: 'SPIFFE',
    label: 'Invent a registration entry on first sight',
    env: 'STS_SPIFFE_AUTOCREATE_ENTRIES', type: 'bool', dflt: true,
    runtime: true,
    description: 'THIS IS THE SETTING THAT MAKES THIS A MOCK. On, a workload ' +
                 'that asks the Workload API for an SVID and matches no ' +
                 'registration entry gets one created for it and is issued ' +
                 'an SVID anyway — no attestation, no selectors, nothing ' +
                 'checked — which is the same permissive posture every other ' +
                 'family here has. Off, an unregistered workload is answered ' +
                 'with an empty SVID list, which is what a real SPIRE agent ' +
                 'does and is the ONLY way to exercise a client\'s "I have ' +
                 'no identity" path. Both answers are worth having; neither ' +
                 'is the safe one.' },

  { key: 'spiffe.requireSecurityHeader', group: 'SPIFFE',
    label: 'Require the workload.spiffe.io header',
    env: 'STS_SPIFFE_REQUIRE_SECURITY_HEADER', type: 'bool', dflt: true,
    runtime: true,
    description: 'The Workload Endpoint specification says a client MUST ' +
                 'send `workload.spiffe.io: true` on every call and a server ' +
                 'MUST refuse one without it. It is a conformance check ' +
                 'rather than a security one — it exists so that a caller ' +
                 'cannot reach the endpoint by accident — and it is ON here ' +
                 'even though nothing else in this service refuses anything, ' +
                 'because a client that omits it has a bug this is the only ' +
                 'thing that will ever tell them about. Off is for the case ' +
                 'where you are deliberately testing something else.' },

  { key: 'spiffe.trustLocalSocket', group: 'SPIFFE',
    label: 'Trust the SPIRE Server API socket as local',
    env: 'STS_SPIFFE_TRUST_LOCAL_SOCKET', type: 'bool', dflt: true,
    runtime: true,
    description: 'A real SPIRE server trusts its private Unix socket ' +
                 'outright — the access control is the socket\'s filesystem ' +
                 'permissions — and a caller there is the `local` entity, ' +
                 'which may do everything an admin may and two things an ' +
                 'admin may not. Off, the socket demands an X509-SVID like ' +
                 'the TCP port, which is the only way to exercise a ' +
                 'client\'s "I was refused on the local socket" path. Read ' +
                 'per call, so it needs no restart.' },

  { key: 'spiffe.adminIds', group: 'SPIFFE', label: 'Administrator SPIFFE IDs',
    env: 'STS_SPIFFE_ADMIN_IDS', type: 'string', dflt: '', runtime: true,
    description: 'SPIFFE IDs whose holders are administrators of the SPIRE ' +
                 'Server API, separated by commas or spaces — SPIRE\'s own ' +
                 '`admin_ids`, and like SPIRE\'s it needs NO registration ' +
                 'entry behind it. The other way to make an administrator is ' +
                 'to mark a registration entry `admin`, which is what the ' +
                 'form on /admin/spiffe/entries does; both are read on every ' +
                 'call, so either takes effect at once. An id here that is ' +
                 'not in this trust domain or a federated one can never ' +
                 'match, because nothing else would verify its certificate.' },

  { key: 'spiffe.clockSkew', group: 'SPIFFE', label: 'Clock skew (s)',
    env: 'STS_SPIFFE_CLOCK_SKEW', type: 'int', dflt: 60, runtime: true,
    description: 'How far out a caller\'s clock may be when its X509-SVID is ' +
                 'checked for validity. It matters more here than it looks: ' +
                 'an SVID lives for spiffe.svidTtl — an hour by default — so ' +
                 'a machine a few minutes fast meets the not-yet-valid ' +
                 'refusal constantly, and a refusal that did not name the ' +
                 'skew reads as a broken certificate.' },

  { key: 'spiffe.attestWorkloads', group: 'SPIFFE',
    label: 'Match Workload API callers on selectors',
    env: 'STS_SPIFFE_ATTEST_WORKLOADS', type: 'bool', dflt: true,
    runtime: true,
    description: 'ON, a Workload API caller is IDENTIFIED from what this ' +
                 'service can actually see about it — the transport, the ' +
                 'endpoint it reached, its peer address — and is answered ' +
                 'with the registration entries whose selectors that ' +
                 'identification matches, which is what a real agent does. ' +
                 'OFF, every caller is answered with every entry, which is ' +
                 'what this service did before. **NOTHING KERNEL-LEVEL IS ' +
                 'READ EITHER WAY**: node cannot read a Unix socket\'s peer ' +
                 'credentials, so there is no uid, no pid, no container and ' +
                 'no pod here, and the selectors this service produces are ' +
                 'spelt `transport:`, `endpoint:` and `peer:` so that they ' +
                 'cannot be mistaken for an attestor\'s. ' +
                 'spiffe.autoCreateEntries still invents an entry for a ' +
                 'caller that matches nothing, so the default experience is ' +
                 'unchanged.' },

  { key: 'spiffe.acceptAssertedSelectors', group: 'SPIFFE',
    label: 'Believe selectors a workload asserts',
    env: 'STS_SPIFFE_ACCEPT_ASSERTED_SELECTORS', type: 'bool', dflt: false,
    runtime: true,
    description: 'OFF by default, and it is the one setting here that is not ' +
                 'attestation of any kind. On, a Workload API caller may ' +
                 'send the metadata header `x-sts-workload-selector: ' +
                 'unix:uid:1000` (repeatable, or comma-separated) and those ' +
                 'selectors are matched against registration entries as ' +
                 'though something had verified them. NOTHING HAS. It exists ' +
                 'because selector matching is the interesting behaviour of ' +
                 'a Workload API and there is otherwise no way to exercise a ' +
                 'client\'s "these matched and those did not" path on a ' +
                 'service that cannot read peer credentials. The header is ' +
                 'deliberately spelt like nothing in any specification.' },

  { key: 'spiffe.maxEntries', group: 'SPIFFE', label: 'Maximum registration ' +
                                                      'entries',
    env: 'STS_SPIFFE_MAX_ENTRIES', type: 'int', dflt: 500, runtime: true,
    description: 'How many entries may live under ou=spiffe. Past it a new ' +
                 'one is REFUSED and the SVID request that would have ' +
                 'created it is answered without one — the registry is a ' +
                 'directory container and a container has a size, the same ' +
                 'cap ou=applications has.' },

  { key: 'spiffe.maxAgents', group: 'SPIFFE', label: 'Maximum attested agents',
    env: 'STS_SPIFFE_MAX_AGENTS', type: 'int', dflt: 200, runtime: true,
    description: 'How many attested agents are held. The agent id comes off ' +
                 'whatever the caller sent, so any caller can invent one; ' +
                 'past the cap the oldest is dropped rather than the newest ' +
                 'refused, because an agent that cannot attest is an agent ' +
                 'that cannot do anything at all.' },

  { key: 'spiffe.maxFederatedBundles', group: 'SPIFFE',
    label: 'Maximum federated bundles',
    env: 'STS_SPIFFE_MAX_FEDERATED_BUNDLES', type: 'int', dflt: 32,
    runtime: true,
    description: 'How many foreign trust domains\' bundles are held. They ' +
                 'are PASTED IN and never fetched — see /spiffe — so this ' +
                 'bounds what an operator or the SPIRE Server API can add, ' +
                 'not what any polling loop could accumulate.' },

  { key: 'spiffe.bundlePath', group: 'SPIFFE', label: 'Bundle endpoint path',
    env: 'STS_SPIFFE_BUNDLE_PATH', type: 'string', dflt: '/spiffe/bundle',
    runtime: false,
    restartReason: 'the route is registered at require time, and the require ' +
                   'order is the route order',
    description: 'Where the trust bundle is published. A real federation ' +
                 'partner is configured with this URL and polls it. It is ' +
                 'restart-only for the reason every path here is: requiring ' +
                 'a module registers its endpoints, so the path is fixed by ' +
                 'the time anything could change it.' },

  { key: 'spiffe.workloadSocketEnabled', group: 'SPIFFE',
    label: 'Workload API on a Unix socket',
    env: 'STS_SPIFFE_WORKLOAD_SOCKET_ENABLED', type: 'bool', dflt: true,
    runtime: false, realmRuntime: true,
    restartReason: 'the listener is bound when the process starts; a ' +
                   'REALM\'s is bound when its SPIFFE is turned on',
    description: 'Whether the Workload API is served on a Unix domain ' +
                 'socket. ON by default because that is what ' +
                 'SPIFFE_ENDPOINT_SOCKET means to every real client — ' +
                 'go-spiffe, spiffe-helper, the SPIRE agent — so without it ' +
                 'nothing connects unconfigured. It is the ONE thing this ' +
                 'service puts on a filesystem: a socket is a rendezvous ' +
                 'point rather than state, nothing is persisted through it, ' +
                 'and it is unlinked when the listener closes.' },

  { key: 'spiffe.workloadSocket', group: 'SPIFFE', label: 'Workload API ' +
      'socket path',
    env: 'STS_SPIFFE_WORKLOAD_SOCKET', type: 'string',
    dflt: '/tmp/spire-agent/public/api.sock', runtime: false,
    realmRuntime: true,
    restartReason: 'the listener is bound when the process starts. A ' +
                   'REALM\'s is bound when its SPIFFE is turned on, so it ' +
                   'may carry this — and it is given a path of its own when ' +
                   'it is created, because two realms cannot share one socket',
    description: 'Where that socket lives. SPIRE\'s own default path, so a ' +
                 'client that was pointed at a SPIRE agent needs no change. ' +
                 'The directory is created if it is missing and the socket ' +
                 'is removed on a clean shutdown; a stale one left by a ' +
                 'killed process is unlinked before binding, which is the ' +
                 'ordinary thing every Unix socket server does and the ' +
                 'ordinary way two copies of this service fight over one ' +
                 'path.' },

  { key: 'spiffe.workloadPort', group: 'SPIFFE', label: 'Workload API TCP port',
    env: 'STS_SPIFFE_WORKLOAD_PORT', type: 'port', dflt: 8092, runtime: false,
    realmRuntime: true,
    restartReason: 'the listener is bound when the process starts; a ' +
                   'REALM\'s is bound when its SPIFFE is turned on. A realm ' +
                   'ordinarily keeps this port and takes an ADDRESS of its ' +
                   'own instead (spiffe.grpcHost), so every realm is reached ' +
                   'where a client expects to reach it',
    description: 'The Workload API over TCP, which the Workload Endpoint ' +
                 'specification permits (tcp://host:port) and which is how ' +
                 'this is reached from another container or from a host that ' +
                 'cannot share the socket. 0 turns it off and leaves the ' +
                 'Unix socket alone.' },

  { key: 'spiffe.serverPort', group: 'SPIFFE', label: 'SPIRE Server API TCP ' +
                                                      'port',
    env: 'STS_SPIFFE_SERVER_PORT', type: 'port', dflt: 8181, runtime: false,
    realmRuntime: true,
    restartReason: 'the listener is bound when the process starts; a ' +
                   'REALM\'s is bound when its SPIFFE is turned on, on its ' +
                   'own address',
    description: 'The SPIRE Server API — Entry, Agent, Bundle, SVID, ' +
                 'TrustDomain and Debug — over gRPC. SPIRE\'s own default is ' +
                 '8081, which is this service\'s HTTP port, so the default ' +
                 'here is 8181 and a client configured for a real SPIRE ' +
                 'server has one thing to change. 0 turns it off.' },

  { key: 'spiffe.serverSocketEnabled', group: 'SPIFFE',
    label: 'SPIRE Server API on a Unix socket',
    env: 'STS_SPIFFE_SERVER_SOCKET_ENABLED', type: 'bool', dflt: false,
    runtime: false, realmRuntime: true,
    restartReason: 'the listener is bound when the process starts; a ' +
                   'REALM\'s is bound when its SPIFFE is turned on',
    description: 'Whether the SPIRE Server API is also served on a Unix ' +
                 'socket, which is where a real spire-server keeps its ' +
                 'administrative API. OFF by default — unlike the Workload ' +
                 'API\'s, which is on — because `spire-server entry create` ' +
                 'and friends are the only things that reach for it, where ' +
                 'the Workload API socket is what every workload reaches ' +
                 'for.' },

  { key: 'spiffe.serverSocket', group: 'SPIFFE', label: 'SPIRE Server API ' +
                                                        'socket path',
    env: 'STS_SPIFFE_SERVER_SOCKET', type: 'string',
    dflt: '/tmp/spire-server/private/api.sock', runtime: false,
    realmRuntime: true,
    restartReason: 'the listener is bound when the process starts; a REALM ' +
                   'is given a path of its own when it is created, because ' +
                   'two realms cannot share one socket',
    description: 'Where that socket lives when it is on. SPIRE\'s own ' +
                 'default path, for the same reason the Workload API\'s is.' },

  { key: 'spiffe.grpcHost', group: 'SPIFFE', label: 'gRPC bind address',
    env: 'STS_SPIFFE_GRPC_HOST', type: 'string', dflt: '0.0.0.0',
    runtime: false, realmRuntime: true,
    restartReason: 'the listeners are bound when the process starts. A ' +
                   'REALM\'s are bound when its SPIFFE is turned on, and ' +
                   'THIS IS THE ROW THAT KEEPS TWO REALMS APART on one ' +
                   'machine: each takes an address of its own and keeps the ' +
                   'ports, because the endpoint address is the only thing a ' +
                   'SPIFFE client has to name a tenant with',
    description: 'The address both TCP gRPC listeners bind. 0.0.0.0 is every ' +
                 'interface, which is what a container needs; 127.0.0.1 ' +
                 'confines them to the machine this runs on. Worth a thought ' +
                 'here rather than elsewhere: the SPIRE Server API can ' +
                 'create registration entries granting any identity in this ' +
                 'trust domain. Its TCP port demands an X509-SVID and ' +
                 'authorizes every method, unconditionally; on the Workload ' +
                 'API port anybody who can reach the address is answered, ' +
                 'which that specification requires.' },

  // -------------------------------------------------------------------------
  // PERSISTENCE. The newest group, 2026-08-27, and the one that reverses the
  // oldest claim in this repository: that this service writes nothing down.
  //
  // FOUR OF THE FIVE ARE RESTART-ONLY, and it is the same reason each time
  // rather than five: the store is chosen, opened and READ AT STARTUP, before
  // the HTTP listener binds, and a mode changed at runtime would leave a
  // service whose directory came from one place and whose writes went to
  // another. `persistence.writeDelay` is the exception because it is read on
  // the way in to each flush and changing it changes only when the next one
  // happens.
  //
  // THE DEFAULT IS memory AND THAT IS THE WHOLE COMPATIBILITY STORY. A run
  // that says nothing about persistence behaves exactly as every run before
  // this group existed, which is why not one job in the parent project's test
  // suite had to be told about any of it.
  // -------------------------------------------------------------------------
  { key: 'persistence.mode', group: 'Persistence', label: 'Persistence mode',
    env: 'STS_PERSISTENCE_MODE', type: 'enum',
    enumValues: ['memory', 'ldif', 'postgres'], dflt: 'memory',
    runtime: false,
    restartReason: 'the store is opened and read before the listener binds',
    description: 'Where the embedded directory, the trust realm registry and ' +
                 'the runtime appconfig overrides are written down. memory ' +
                 'writes nothing and is what this service always did — ' +
                 'everything is gone on restart. ldif writes an RFC 2849 ' +
                 'file per realm plus two JSON files in persistence.dataDir, ' +
                 'which is the local-development answer and needs no ' +
                 'database. postgres writes six tables and is the shared ' +
                 'store. WHAT THIS SERVICE MINTS — sessions, tokens, codes, ' +
                 'artifacts, Kerberos principals, the replay caches, the ' +
                 'counters and the audit log — is persisted in PRODUCT mode ' +
                 'on postgres and in no other configuration; see ' +
                 'persistence.minted. Development mode persists none of it, ' +
                 'because the signing key is regenerated on every start ' +
                 'there and a token that outlived it would verify against ' +
                 'nothing. The ldif store holds none of it in either mode ' +
                 'and says so at startup, because it writes whole files per ' +
                 'flush.' },

  // ---------------------------------------------------------------------
  // HOW LONG A METRICS PROBE MAY RUN (2026-09-11), for `/admin/database`.
  //
  // It becomes `statement_timeout` on the ONE connection that page borrows.
  // Every statement behind it is a catalog read and they measured 107ms for
  // all twenty together on a local PostgreSQL 18 — but `pg_stat_activity` on
  // a server with thousands of backends and `pg_total_relation_size` over a
  // large schema are not free, and the pool this borrows from has a `max` of
  // 4 and is the same one every protocol endpoint here writes through.
  //
  // **SO THE BOUND IS ON THE DATABASE'S SIDE AND NOT ON A TIMER HERE.** A
  // `setTimeout` in this process would abandon the promise and leave the
  // statement running and the connection held, which is the opposite of what
  // is wanted: `statement_timeout` makes the SERVER stop and hand the
  // connection back. Runtime, because it is read per render.
  // ---------------------------------------------------------------------
  { key: 'persistence.metricsTimeoutMs', group: 'Persistence',
    label: 'Database metrics statement timeout (ms)',
    env: 'STS_PERSISTENCE_METRICS_TIMEOUT_MS', type: 'int',
    dflt: 5000, min: 250, max: 60000, runtime: true,
    description: 'How long any one statement behind /admin/database may run, ' +
                 'as PostgreSQL\'s own statement_timeout on the single ' +
                 'connection that page borrows. Every one of them is a read ' +
                 'of a catalog view; the bound is there so that opening a ' +
                 'console page can never pin a connection out of a pool this ' +
                 'service answers protocol traffic from. It is set on the ' +
                 'server rather than as a timer here, because a timer would ' +
                 'abandon the promise and leave both the statement and the ' +
                 'connection exactly where they were.' },
  { key: 'persistence.dataDir', group: 'Persistence', label: 'Data directory',
    env: 'STS_PERSISTENCE_DATA_DIR', type: 'string', dflt: './data',
    runtime: false,
    restartReason: 'the store is opened and read before the listener binds',
    description: 'Where persistence.mode=ldif writes. A relative path is ' +
                 'resolved against this package root rather than the working ' +
                 'directory, for the reason CONFIG_FILE is (common/' +
                 'config_file.js): thirteen modules read it from thirteen ' +
                 'different directories. Ignored in memory and postgres ' +
                 'modes. In a container this is what a volume mounts over.' },

  // ---------------------------------------------------------------------
  // THIS ROW HAD NO DEFAULT UNTIL 2026-08-27 AND THE ARGUMENT FOR THAT WAS
  // WRONG, WHICH IS WORTH RECORDING RATHER THAN QUIETLY CORRECTING.
  //
  // It shipped empty with the reasoning "a localhost guess would connect to
  // whatever real database happened to be there". That reads as caution and is
  // not: **this value is never dialled unless `persistence.mode` is
  // `postgres`**, which is not the default and never has been. So the empty
  // string protected nobody — the only run it could affect is one where
  // somebody had already asked for Postgres — while costing every such run the
  // step of looking up what to type.
  //
  // It is now the local development connection string, and it matches
  // docker-compose.yml's Postgres service exactly (user `sts`, password `sts`,
  // database `sts`) so that the two cannot drift into disagreeing about what a
  // base configuration looks like. That stack sets STS_DATABASE_URL anyway —
  // its host is `postgres`, the service name on the compose network — so the
  // variable wins there and this value is what a HOST run gets.
  //
  // WHAT THE CHANGE COSTS is one clear error message:
  // `persistence.mode=postgres` with nothing configured used to be refused by
  // name ("set persistence.databaseUrl"), and now it attempts a connection to
  // localhost and reports whatever that says. persistence.js puts the guidance
  // back on that path — when a Postgres store cannot be opened AND the URL came
  // from the defaults layer, it says so and names this setting. See its
  // start().
  //
  // THE PASSWORD IS IN A FILE IN PLAIN TEXT and that is correct here for the
  // reason docker-compose.yml gives: it guards a throwaway database of mock
  // identities, and this repository's whole premise is that nothing in it is a
  // real credential. An operator with a real one sets the environment variable.
  //
  // ---------------------------------------------------------------------
  // AND SINCE 2026-09-06 THIS DEFAULT NAMES A DIFFERENT ROLE FROM THE ONE THE
  // COMPOSE STACK DIALS, WHICH LOOKS LIKE DRIFT AND IS NOT.
  //
  // The stack's database is built by `postgres/schema.sql`, which creates the
  // five tables as the owner `sts` and a second role `sts_app` that may read
  // and write the rows and may NOT create, alter, truncate or drop a table —
  // and STS_DATABASE_URL there dials `sts_app`. That is the arrangement to
  // want for anything left running.
  //
  // THIS value is the other case: a local database with NOTHING IN IT, which
  // no script has been run against, where the driver creates what is missing
  // exactly as it always did. An `sts_app` here would be a role that does not
  // exist yet, so the default names the owner and the two are answers to two
  // different questions. `persistence/CLAUDE.md` argues the split.
  // ---------------------------------------------------------------------
  { key: 'persistence.databaseUrl', group: 'Persistence',
    label: 'Database connection string',
    env: 'STS_DATABASE_URL', type: 'string',
    dflt: 'postgres://sts:sts@localhost:5432/sts', runtime: false,
    restartReason: 'the connection pool is opened before the listener binds',
    description: 'The PostgreSQL connection string persistence.mode=postgres ' +
                 'dials — postgres://user:password@host:5432/database. The ' +
                 'default is a LOCAL DEVELOPMENT one matching the Postgres ' +
                 'service in this repository\'s docker-compose.yml (user, ' +
                 'password and database all "sts"), so turning persistence ' +
                 'on against a local database is one setting rather than ' +
                 'two. It is never dialled unless persistence.mode is ' +
                 'postgres, which is not the default — so this value is ' +
                 'inert on an ordinary run. The compose stack sets ' +
                 'STS_DATABASE_URL itself, with `postgres` as the host, ' +
                 'because that is the service name on its network. IT ' +
                 'CARRIES A PASSWORD, so /admin/persistence and GET ' +
                 '/admin-api/persistence report the host, port, database and ' +
                 'user parsed out of it and never the string itself. THE ' +
                 'DEFAULT NAMES AN OWNER AND THE COMPOSE STACK DOES NOT: ' +
                 'this value is for a local database with nothing in it, ' +
                 'which this service builds for itself, while the stack ' +
                 'dials the least-privileged role postgres/schema.sql ' +
                 'creates — read and write on the rows, no CREATE on the ' +
                 'schema.' },

  // ---------------------------------------------------------------------
  // TLS TO THE DATABASE, and the one knob that is about TRUST rather than
  // about encryption.
  //
  // The connection string carries `sslmode`, which is postgres's own spelling
  // and is where the ENCRYPTION decision belongs — `?sslmode=require` is in
  // the compose default and the database refuses a plaintext connection
  // anyway, because every `host` rule in its pg_hba.conf is `hostssl`.
  //
  // What a connection string cannot say is whether to BELIEVE the certificate,
  // because node's `pg` takes that as a TLS option rather than as a URL
  // parameter. That is this setting, and it is separate on purpose: encryption
  // and authentication are two decisions, a self-signed pair gives the first
  // and not the second, and a service that conflated them would be one where
  // turning verification off looked like turning TLS off.
  // ---------------------------------------------------------------------
  // =====================================================================
  // THE DATABASE PASSWORD, FROM WHEREVER THE KEY-ENCRYPTION KEY COMES FROM
  // (2026-09-12).
  //
  // `persistence.databaseUrl` above carries a password in plain text, in a
  // file, and the row says why that is correct for a throwaway database of
  // mock identities. These three rows are the other case: a deployment with a
  // real database, whose password belongs in the same secret store as
  // everything else this service reads at startup.
  //
  // **IT IS THE KEK'S MECHANISM AND NOT A SECOND ONE.** The same five
  // providers, the same SDKs, the same failure sentences, in
  // `common/secrets.js` — which takes a SECRET DESCRIPTOR now rather than
  // knowing only about the key. What is deliberately NOT repeated here is how
  // to REACH the store: `keys.kekVault`, `keys.kekRegion` and `keys.kekToken`
  // are one deployment's Vault endpoint, AWS region and token, and a second
  // copy of them per secret would be two answers to one question.
  //
  // **OFF BY DEFAULT AND INERT WHEN OFF.** `none` means the password is where
  // it always was — in the connection string — and nothing is read, nothing
  // is injected and no provider SDK is touched.
  // =====================================================================
  { key: 'persistence.databasePasswordProvider', group: 'Persistence',
    label: 'Where the database password is read from',
    env: 'STS_DATABASE_PASSWORD_PROVIDER', type: 'enum',
    enumValues: ['none', 'file', 'aws', 'gcp', 'azure', 'vault'],
    dflt: 'none', runtime: false,
    restartReason: 'the connection pool is opened before the listener binds',
    description: 'Read the database password from a secret store at startup ' +
                 'and inject it into `persistence.databaseUrl`, instead of ' +
                 'the password that string carries. The five providers are ' +
                 'the ones `keys.kekProvider` offers and the mechanism is ' +
                 'the same one — a mounted file, AWS Secrets Manager, Google ' +
                 'Secret Manager, Azure Key Vault or HashiCorp Vault. ' +
                 '`none`, the default, changes nothing: the connection ' +
                 'string is dialled exactly as written.\n\nWhen this is set ' +
                 'and the read FAILS, this service does not start — the same ' +
                 'refusal an unreachable store gets, and for its reason: a ' +
                 'process that was told where the password lives and carried ' +
                 'on with the one in the URL would be ignoring the ' +
                 'configuration that exists to keep it out of the URL.' },

  { key: 'persistence.databasePasswordRef', group: 'Persistence',
    label: 'The database password\'s location',
    env: 'STS_DATABASE_PASSWORD_REF', type: 'string', dflt: '',
    runtime: false,
    restartReason: 'read once at startup, before the pool is opened',
    description: 'Where the password is, in whichever provider ' +
                 '`persistence.databasePasswordProvider` names: a PATH for ' +
                 '`file`, a name or ARN for `aws`, a resource name for ' +
                 '`gcp`, a secret name for `azure`, a read path for ' +
                 '`vault`.\n\n**EMPTY MEANS THE SAME PLACE AS THE ' +
                 'KEY-ENCRYPTION KEY** — `keys.kekFile` or `keys.kekRef` — ' +
                 'which is the arrangement most deployments want: one ' +
                 'mounted file, or one cloud secret, holding both. What ' +
                 'tells the two apart inside it is ' +
                 '`persistence.databasePasswordField`, and a SHARED location ' +
                 'holding something that is not a JSON object is REFUSED ' +
                 'rather than read: what is there is then the key itself, ' +
                 'and handing that to a database as a password is the one ' +
                 'mistake this refusal exists to prevent.' },

  { key: 'persistence.databasePasswordField', group: 'Persistence',
    label: 'The field the password is in',
    env: 'STS_DATABASE_PASSWORD_FIELD', type: 'string',
    dflt: 'databasePassword', runtime: false,
    restartReason: 'read once at startup, before the pool is opened',
    description: 'The member to take out of the stored secret when it is a ' +
                 'JSON object — `{"kek": "…", "databasePassword": "…"}` in ' +
                 'one file, or the `{"username": …, "password": …}` shape ' +
                 'AWS Secrets Manager writes for a database credential (set ' +
                 'this to `password` for one of those).\n\nA secret of its ' +
                 'own that is NOT JSON is taken whole, so a Vault path or a ' +
                 'file holding nothing but the password needs no field at ' +
                 'all. Leave it EMPTY to take the value whole even where it ' +
                 'is JSON.' },

  // ---------------------------------------------------------------------
  // HOW TO REACH THE STORE THE PASSWORD IS IN, WHEN IT IS NOT THE KEY'S
  // (2026-09-12).
  //
  // The paragraph above these rows says a second copy of `keys.kekVault`,
  // `keys.kekRegion` and `keys.kekToken` per secret "would be two answers to
  // one question" — and for the deployment it describes, one store holding
  // both, that is still true, which is why all three are EMPTY BY DEFAULT and
  // empty means *the key's*. What it did not allow for is the deployment where
  // the database credential is owned by a different team in a different Vault,
  // region or Key Vault, which had no way to be configured at all. These are
  // overrides of the key's rows rather than rows of their own, so the shared
  // store stays the default and a second one is something somebody says.
  // ---------------------------------------------------------------------
  { key: 'persistence.databasePasswordVault', group: 'Persistence',
    label: 'Vault or Key Vault URL for the database password',
    env: 'STS_DATABASE_PASSWORD_VAULT', type: 'string', dflt: '',
    runtime: false,
    restartReason: 'read once at startup, before the pool is opened',
    description: 'The HashiCorp Vault endpoint or Azure Key Vault URL the ' +
                 'database password is read from. **EMPTY MEANS THE SAME ' +
                 'STORE AS THE KEY-ENCRYPTION KEY** (`keys.kekVault`), which ' +
                 'is the arrangement most deployments want. The client ' +
                 'certificate settings (`keys.vaultClient*`) are shared ' +
                 'either way: they are this service\'s identity, not the ' +
                 'store\'s.' },

  { key: 'persistence.databasePasswordRegion', group: 'Persistence',
    label: 'AWS region for the database password',
    env: 'STS_DATABASE_PASSWORD_REGION', type: 'string', dflt: '',
    runtime: false,
    restartReason: 'read once at startup, before the pool is opened',
    description: 'The AWS Secrets Manager region the database password is ' +
                 'read from. Empty means `keys.kekRegion`, and that one ' +
                 'empty means the SDK\'s own resolution.' },

  { key: 'persistence.databasePasswordToken', group: 'Persistence',
    label: 'Vault token for the database password',
    env: 'STS_DATABASE_PASSWORD_TOKEN', type: 'string', dflt: '',
    runtime: false, secret: true,
    restartReason: 'read once at startup, before the pool is opened',
    description: 'A HashiCorp Vault token for reading the database password. ' +
                 'Empty means `keys.kekToken`, and that one empty means the ' +
                 'SDK\'s VAULT_TOKEN. Ignored where a client certificate is ' +
                 'configured, exactly as the key\'s token is.' },

  { key: 'persistence.databaseTlsRejectUnauthorized', group: 'Persistence',
    label: 'Verify the database certificate',
    env: 'STS_DATABASE_TLS_REJECT_UNAUTHORIZED', type: 'bool', dflt: false,
    runtime: false,
    restartReason: 'the connection pool is opened before the listener binds',
    description: 'Whether the PostgreSQL server\'s certificate must verify ' +
                 'against a trust anchor this process holds. OFF by default, ' +
                 'and that is a statement about the STACK rather than a ' +
                 'weakened default: the certificate is generated inside the ' +
                 'postgres container on its first start and is signed by ' +
                 'nobody, so there is nothing for a client to verify it ' +
                 'against and turning this on would refuse every connection ' +
                 'with a message about a self-signed certificate. THE ' +
                 'CONNECTION IS STILL ENCRYPTED either way — `sslmode` in ' +
                 'persistence.databaseUrl decides that, the database\'s own ' +
                 'pg_hba.conf requires it, and this decides only whether the ' +
                 'server is AUTHENTICATED. Turn it on when you point this at ' +
                 'a real database whose certificate chains to something ' +
                 'NODE_EXTRA_CA_CERTS names.' },

  { key: 'persistence.writeDelay', group: 'Persistence',
    label: 'Write delay (ms)',
    env: 'STS_PERSISTENCE_WRITE_DELAY', type: 'int', dflt: 1500,
    runtime: true,
    description: 'How long a change waits before the ldif store is ' +
                 'rewritten, so that a burst — a realm build writes thirteen ' +
                 'entries — costs one file write rather than thirteen. What ' +
                 'it risks is this many milliseconds of writes on a kill -9, ' +
                 'which no process can trap; SIGTERM and SIGINT flush first. ' +
                 'POSTGRES IGNORES IT and uses 0, because the unit of ' +
                 'writing there is a transaction rather than a file: every ' +
                 'change made while handling one request commits as one ' +
                 'transaction the moment that request is done.' },

  { key: 'persistence.realms', group: 'Persistence',
    label: 'Persist the realm registry',
    env: 'STS_PERSISTENCE_REALMS', type: 'bool', dflt: true, runtime: false,
    restartReason: 'the realm rows are restored before the listener binds',
    description: 'Whether trust realm definitions — their names, ' +
                 'descriptions and per-realm overrides — are written down ' +
                 'beside the directory. ON, and turning it off is a ' +
                 'half-persisted service rather than a smaller one: a realm ' +
                 'holds its own directory, so its entries would be stored ' +
                 'with no realm to restore them into, and the first write of ' +
                 'the next run would remove them. The service says so at ' +
                 'startup rather than letting it be discovered.' },

  { key: 'persistence.appconfig', group: 'Persistence',
    label: 'Persist runtime setting changes',
    env: 'STS_PERSISTENCE_APPCONFIG', type: 'bool', dflt: true, runtime: false,
    restartReason: 'the saved overrides are applied before the listener binds',
    description: 'Whether a setting changed through the console or the ' +
                 'management API survives a restart. ON. It adds no LAYER — ' +
                 'the saved values are re-applied at startup through the ' +
                 'same setOverride() a caller uses, so the five layers below ' +
                 'are unchanged and a runtime override is simply durable ' +
                 'now. Only a runtime-changeable setting can be saved, ' +
                 'because only a runtime-changeable setting can be set: that ' +
                 'is what makes applying them after every module has loaded ' +
                 'safe.' },

  // -------------------------------------------------------------------------
  // WHAT THIS PROCESS MINTED, IN PRODUCT MODE. The two settings below are the
  // only configuration the 2026-09-06 change added, and the first one is worth
  // reading as a REFUSAL rather than a feature switch: turning it off is a
  // product-mode service that loses every session, token and audit row on
  // every restart, which is what development mode is for.
  // -------------------------------------------------------------------------
  { key: 'persistence.minted', group: 'Persistence',
    label: 'Persist sessions, tokens and the audit log',
    env: 'STS_PERSISTENCE_MINTED', type: 'bool', dflt: true, runtime: false,
    restartReason: 'the minted rows are restored before the listener binds, ' +
                   'so turning this on or off part-way through a run would ' +
                   'leave a process writing rows it never read',
    description: 'Whether the things this service MINTS — sessions, access, ' +
                 'ID and refresh tokens, authorization codes, pre-authorized ' +
                 'codes, SAML artifacts, Kerberos principals and tickets, ' +
                 'the replay caches, the counters and the audit log — ' +
                 'survive a restart. ON, and it reaches nothing at all ' +
                 'unless BOTH global.mode is "product" AND persistence.mode ' +
                 'is "postgres". Development mode ignores it, because the ' +
                 'signing key is regenerated on every start there and a ' +
                 'restored token would verify against nothing; the ldif ' +
                 'store ignores it too and says so at startup, because it ' +
                 'writes whole files per flush and these rows change on ' +
                 'every request. Every row is encrypted with the same ' +
                 'key-encryption key that protects the signing keys, because ' +
                 'a session id is a cookie value and an authorization code ' +
                 'is redeemable.' },

  { key: 'persistence.mintedRetention', group: 'Persistence',
    label: 'Minted state retention (ms)',
    env: 'STS_PERSISTENCE_MINTED_RETENTION', type: 'int',
    dflt: 7 * 24 * 60 * 60 * 1000, runtime: true,
    description: 'How long a persisted session, token, code, artifact or ' +
                 'audit row is kept. A row older than this is neither ' +
                 'restored nor left behind — it is deleted on the start that ' +
                 'skipped it. Seven days by default, which is longer than ' +
                 'every lifetime this service issues and short enough that a ' +
                 'long-running store does not read a month of dead sessions ' +
                 'on the way up. 0 keeps everything for ever, which is a ' +
                 'supported answer for a deployment whose audit log is the ' +
                 'point and which prunes the table itself.' },

  // -------------------------------------------------------------------------
  // SEVERAL PROCESSES AGAINST ONE STORE. Until 2026-09-06 this service said,
  // in several files, that persistence was NOT coordination — two processes
  // each held their own copy and never saw each other's writes. These two
  // settings are that sentence being reversed.
  // -------------------------------------------------------------------------
  { key: 'persistence.coordinate', group: 'Persistence',
    label: 'Coordinate with other processes',
    env: 'STS_PERSISTENCE_COORDINATE', type: 'bool', dflt: true, runtime: false,
    restartReason: 'the change log\'s high-water mark is taken once the ' +
                   'store has been restored, so starting or stopping ' +
                   'part-way through a run would leave a process applying ' +
                   'changes from a point it was never at',
    description: 'Whether this process applies changes other processes ' +
                 'committed to the same store. ON, and it needs the postgres ' +
                 'store: every change is written to a monotonic log INSIDE ' +
                 'the transaction that made it, and each process reads what ' +
                 'it has not yet applied. A LISTEN/NOTIFY nudge wakes that ' +
                 'read early, so a missed notification costs latency and ' +
                 'never a change — the same trade the remote XACML PEP makes ' +
                 'about its own pull. Turning it off is what this service ' +
                 'did before this existed: correct, and each process alone ' +
                 'with its own copy. IT SHARES STATE AND NOT SOCKETS — the ' +
                 'KDC, the LDAP listeners, the two TLS ports and SPIFFE\'s ' +
                 'four are bound per process — and the replay caches ' +
                 'CONVERGE rather than synchronise, so between a write in ' +
                 'one process and its arrival in another there is a window ' +
                 'in which a proof one refused is accepted by the other.' },

  { key: 'persistence.pollInterval', group: 'Persistence',
    label: 'Change poll interval (ms)',
    env: 'STS_PERSISTENCE_POLL_INTERVAL', type: 'int', dflt: 5000,
    runtime: true,
    description: 'How often this process asks the change log what other ' +
                 'processes have committed. This is the CONTRACT and the ' +
                 'LISTEN/NOTIFY nudge is only an optimisation over it, so ' +
                 'this is the worst-case convergence lag when a notification ' +
                 'is lost — a dropped listener, a database restart — and the ' +
                 'typical lag is a few milliseconds. Five seconds because ' +
                 'the nudge normally arrives first and a shorter interval ' +
                 'buys nothing but queries; 250ms is the floor. It is also ' +
                 'the size of the replay-cache window described under ' +
                 'persistence.coordinate.' },

  // Added 2026-09-14 (#46 section 8): `sts_changes` was never trimmed.
  // `persistence/persistence_replication.js` argues the bound this is half of.
  { key: 'persistence.changeLogRetentionS', group: 'Persistence',
    label: 'Change log retention (s)',
    env: 'STS_PERSISTENCE_CHANGE_LOG_RETENTION_S', type: 'int', dflt: 3600,
    min: 0, runtime: true,
    description: 'How long a row of the change log (sts_changes) is kept ' +
                 'at least, by the database clock. A row is removed only ' +
                 'when it is older than this AND below the lowest position ' +
                 'every process still reading the log has reported — a ' +
                 'process that has not reported for this long, or whose ' +
                 'cluster node is no longer a member, is taken to be gone. ' +
                 'Keep it well above the longest pause a live process could ' +
                 'survive and above ten minutes, which is how long a reader ' +
                 'waits for a change that committed late. 0 turns the trim ' +
                 'off, and the log grows for ever, which is what it did ' +
                 'before 2026-09-14.' },

  // -------------------------------------------------------------------------
  // THE CLUSTER (2026-09-14, #46): several containers against one postgres
  // store. `cluster/CLAUDE.md` argues every one of these; they are all
  // restart-only, because membership is decided before the store is restored
  // and a node that changed its mind part-way would be a different node.
  // -------------------------------------------------------------------------
  { key: 'cluster.mode', group: 'Cluster', label: 'Cluster mode',
    env: 'STS_CLUSTER_MODE', type: 'enum',
    enumValues: ['auto', 'off', 'active-passive', 'active-active'],
    dflt: 'auto', runtime: false, perProcess: true,
    restartReason: 'a node joins the cluster, and in active-passive mode ' +
                   'waits for the service lease, before anything is restored ' +
                   'from the store or any listener binds',
    description: 'How several copies of this service against ONE postgres ' +
                 'store behave. `off`: nothing is coordinated beyond the ' +
                 'change log, which is correct for one container and gives ' +
                 'wrong answers silently for two. `active-passive`: every ' +
                 'node joins, ONE holds the service lease and serves, and the ' +
                 'others wait before restoring or binding anything — so a ' +
                 'second container is a standby rather than a second writer, ' +
                 'and takes over within one heartbeat of a clean stop or ' +
                 'cluster.nodeTtlMs of a crash. `active-active`: every node ' +
                 'serves; it needs persisted keys under an operator ' +
                 'key-encryption key and REFUSES TO START while any capability ' +
                 'it depends on is missing from this build (see ' +
                 'cluster.acceptMissingCapabilities). `auto`, the default, is ' +
                 'active-passive in product mode on a postgres store and off ' +
                 'everywhere else. Every write a clustered node makes is ' +
                 'FENCED: it checks that the node is still a member, and in ' +
                 'active-passive mode that it still holds the service lease, ' +
                 'and a node that has lost either exits.' },

  { key: 'cluster.nodeName', group: 'Cluster', label: 'Node name',
    env: 'STS_CLUSTER_NODE_NAME', type: 'string', dflt: '',
    runtime: false, perProcess: true,
    restartReason: 'the name is written on the membership row when the node ' +
                   'joins',
    description: 'What /admin/cluster calls this node. Empty means the host ' +
                 'name, which in a container is the container id. It ' +
                 'identifies nothing: membership is a UUID made at every ' +
                 'start, so two nodes given one name are still two nodes.' },

  { key: 'cluster.heartbeatMs', group: 'Cluster',
    label: 'Heartbeat interval (ms)',
    env: 'STS_CLUSTER_HEARTBEAT_MS', type: 'int', dflt: 2000, min: 250,
    runtime: false, perProcess: true,
    restartReason: 'the heartbeat timer is started when the node joins',
    description: 'How often a node renews its membership row and every lease ' +
                 'it holds, in one statement. It must be well under ' +
                 'cluster.nodeTtlMs — a third or less — or one slow ' +
                 'round trip costs a node its membership.' },

  { key: 'cluster.nodeTtlMs', group: 'Cluster',
    label: 'Node lifetime (ms)',
    // 30000 SINCE 2026-09-14 (it was 10000), for a measured reason: a
    // heartbeat is a JavaScript timer, and anything that holds this thread
    // longer than the lifetime less one heartbeat costs the node its
    // membership. The largest such computation a supported console action
    // still makes on the thread is an SLH-DSA-SHAKE-128s signature on
    // /admin/pki's authoring pane — 13.7s measured with the vendored signer
    // — past 10000 − 2000 and inside 30000 − 2000 with twice its length to
    // spare. The cost is a crashed ACTIVE-PASSIVE node's takeover (up to 30s
    // rather than 10s); a clean stop hands its lease over in one heartbeat
    // either way. `cluster/CLAUDE.md`, *A node's thread and its lifetime*.
    env: 'STS_CLUSTER_NODE_TTL_MS', type: 'int', dflt: 30000, min: 1000,
    runtime: false, perProcess: true,
    restartReason: 'the lifetime is written with every heartbeat and checked ' +
                   'by every fenced write',
    description: 'How long a membership row and a lease stay valid after ' +
                 'their last renewal, by the DATABASE\'s clock. It is the ' +
                 'longest a crashed node\'s leases block a takeover, and the ' +
                 'longest a node that cannot reach the store keeps serving ' +
                 'before it exits. Must be at least three heartbeats. It is ' +
                 'ALSO the longest this node\'s event loop may be blocked: a ' +
                 'heartbeat cannot run while it is, so a stall longer than ' +
                 'this less one heartbeat costs the node its membership and ' +
                 'it exits (a stall of a heartbeat or more is logged as ' +
                 'STS-CLUSTER-0025).' },

  { key: 'cluster.acceptMissingCapabilities', group: 'Cluster',
    label: 'Capabilities accepted as missing',
    env: 'STS_CLUSTER_ACCEPT_MISSING_CAPABILITIES', type: 'csv', dflt: '',
    runtime: false, perProcess: true,
    restartReason: 'the capability check runs once, when the node joins',
    description: 'Active-active mode refuses to start while a capability it ' +
                 'depends on is missing from this build. Each one is a known ' +
                 'way two nodes disagree — a single-use value accepted twice, ' +
                 'a signing key one node does not publish — and /admin/cluster ' +
                 'lists them with the section of issue #46 that describes the ' +
                 'failure. Naming a capability id here accepts THAT failure ' +
                 'and nothing else; the node starts, and says at every start ' +
                 'which ones it is running without. There is no "accept all": ' +
                 'a list somebody has to write is a list somebody has read.' }
];

// Indexed once. A linear scan per read would be invisible on a mock and the
// index is one line, but `byKey` is also what makes an unknown key an error at
// the point it is asked for rather than an undefined that travels.
const byKey = {};
SETTINGS.forEach(function (setting) {
  if (byKey[setting.key]) {
    throw new Error('config.js: duplicate setting key ' + setting.key);
  }
  byKey[setting.key] = setting;
});

// The runtime overrides, by key, holding the RAW value a caller supplied. Raw
// rather than parsed so that `text()` can show it back exactly as it was set
// and the environment's string and the file's number stay interchangeable.
const overrides = {};

// ---------------------------------------------------------------------------
// AND WHERE THAT MAP IS WRITTEN DOWN, SINCE 2026-08-27. Rule 3q.
//
// `persistence/persistence.js` fills this at ITS require time, and it is an
// INVERTED HOOK rather than a require in the other direction for rule 3e's
// reason — the same reason the realm slot above it is one, and it is worth
// checking rather than assuming, because rule 3e says a sixth must not be
// added by analogy. That module reads `persistence.mode` and four more
// settings through `value()`, so it requires THIS file; a require back closes
// the cycle, and node answers a cycle with a half-initialised module whose
// exports are `undefined`. The symptom would arrive later as "notify is not a
// function" from inside a console Save — which is to say, from the one place
// nobody would look for a require-order problem.
//
// IT IS A NOTIFICATION AND NOT A STORE, which is why it takes a realm id and
// returns nothing. This file does not know what persistence is, whether it is
// on, or where it writes; it knows that something changed and in which realm,
// because THAT is the thing only this file can say. A process-wide override
// and a realm's override are written to different places by the module on the
// other end, and deciding which is setOverride()'s job below — it already
// makes exactly that decision for its own purposes.
//
// The slot is EMPTY in a process that never required that module, which is
// every test that loads this file on its own, and an empty slot means the
// overrides are what they always were: in memory, gone on restart.
// ---------------------------------------------------------------------------
let overrideStore = null;

function setOverrideStore(fn) {
  log.debug("Entering setOverrideStore().");
  overrideStore = fn;
  log.debug("Leaving setOverrideStore().");
}

// Called after every successful write below. Wrapped, because a persistence
// layer that throws must not turn a successful configuration change into a
// failed one: the value IS set, the caller was right, and the only thing that
// went wrong is that it will not survive a restart.
function overridesChanged(realmId) {
  log.debug("Entering overridesChanged().");
  if (!overrideStore) {
    log.debug("Leaving overridesChanged().");
    return;
  }
  try {
    overrideStore(realmId || null);
  } catch (err) {
    log.error(errorCodes.tag('STS-CORE-0003') +
              'config: the override could not be handed to persistence: ' +
              err.message + '. The setting IS changed and is in force; it ' +
              'may not survive a restart.');
  }
  log.debug("Leaving overridesChanged().");
}

// ---------------------------------------------------------------------------
// LAYER 0: WHAT THE CURRENT TRUST REALM SETS. Rule 3m.
//
// `realms.js` fills this at ITS require time, and it is an INVERTED HOOK rather
// than a require in the other direction for rule 3e's reason: that module
// requires this one — it validates a realm's overrides through checkOverride()
// and reads its own two settings through value() — so a require back would
// close a cycle, and node answers a cycle with a half-initialised module whose
// exports are undefined rather than with an error.
//
// The slot answers the CURRENT realm's overrides, or null when there is no
// realm context, when realms are off, or when the ambient realm is the default
// one. Null rather than an empty object because this is on the hot path of
// every setting read in this service.
//
// WHAT IT DOES **NOT** COVER, and the reason is not caution: the two `realms.*`
// settings themselves are read below the realm layer, always. A realm that
// could set `realms.enabled` could switch realms off from inside a realm, and a
// realm that could set `realms.pathSegment` would change the prefix that was
// used to find it — half way through the request that found it. Both are
// refused at the writing end too (see realms.js's setOverride), so this is the
// second of two locks on one door; it is here because this is the end that is
// on the reading path and therefore the end that cannot be got around.
// ---------------------------------------------------------------------------
// The id this file reports when nothing is ambient. Spelt here rather than
// required from realms.js, because that module requires this one — see
// setRealmContext() below.
const DEFAULT_REALM_ID = 'default';

let realmContext = null;

// Set while a DERIVED default is being resolved for the process rather than for
// the ambient realm. Declared here rather than beside processValue() below,
// which is the function that owns it, because `let` is not initialised until
// its own line runs and realmFor() is called during module evaluation: down
// there it would be a temporal dead zone rather than a flag. See processValue()
// for what it is for and why a plain boolean is the right primitive.
let suppressRealmLayer = false;

function setRealmContext(fn) {
  log.debug("Entering setRealmContext().");
  realmContext = fn;
  log.debug("Leaving setRealmContext().");
}

// The realm whose overrides apply right now, or null: outside a request, with
// realms off, in the default realm, for a setting a realm may not carry, or
// while processValue() is resolving something the PROCESS is being asked about.
// Every reader and every writer below goes through this, so the exemption
// cannot be true in one direction and false in the other.
//
// THERE ARE NOW TWO REASONS A REALM MAY NOT CARRY A SETTING, and they are
// different rules rather than one spelt twice.
//
//   * the `realms.*` PREFIX — whether realms exist and where they are found. A
//     realm carrying one of those would be changing how it was reached half way
//     through the request that reached it. It matches by prefix on purpose, so
//     that a third `realms.*` setting is exempt the day it is added rather than
//     the day somebody remembers this function.
//   * `perProcess` on the row — a setting that is a property of the OS PROCESS
//     rather than of the service's behaviour, so that one realm's value would
//     silently be every realm's. `workers.count` is the first: a pool of child
//     processes is forked once, by this process, and a realm resizing it would
//     be resizing every other realm's too.
//
// The flag is read off the table rather than matched by name, which is what
// makes the second rule as forgettable as the first. `byKey` rather than
// settingFor(), because this is on the read path for every setting in the
// service and an unknown key here is not this function's to refuse.
function realmFor(key) {
  log.debug("Entering realmFor().");
  if (!realmContext || suppressRealmLayer ||
      String(key).indexOf('realms.') === 0 || isPerProcess(key)) {
    log.debug("Leaving realmFor().");
    return null;
  }
  log.debug("Leaving realmFor().");
  return realmContext() || null;
}

// Whether a realm may carry this setting at all. Exported, because the WRITING
// end of the rule is in realms.js — see checkRealmOverride() there — and two
// copies of a predicate is how the two ends come to disagree.
function isPerProcess(key) {
  log.debug("Entering isPerProcess().");
  const setting = byKey[key];
  log.debug("Leaving isPerProcess().");
  return !!(setting && setting.perProcess);
}

function realmOverrideOf(key) {
  log.debug("Entering realmOverrideOf().");
  const realm = realmFor(key);
  if (!realm || !Object.prototype.hasOwnProperty.call(realm.overrides, key)) {
    log.debug("Leaving realmOverrideOf().");
    return undefined;
  }
  log.debug("Leaving realmOverrideOf().");
  return realm.overrides[key];
}

// ---------------------------------------------------------------------------
// Reading.
// ---------------------------------------------------------------------------

// A dot path into an appconfig module. Returns undefined for any missing hop,
// so a config file that omits a whole section — every file shipped before this
// table existed omitted all of them — falls through to the next layer rather
// than throwing on `krb5.realm` where `krb5` is not there.
//
// It takes the ROOT as an argument rather than closing over one, because the
// two appconfig files are read separately and the difference between them is
// reportable: a value from the operator's file and the same value from
// env/defaults.js are indistinguishable once unioned, and "where did this come
// from?" is the question /admin/config exists to answer.
function dig(root, dotted) {
  log.debug("Entering dig().");
  let node = root;
  const parts = String(dotted).split('.');
  for (let i = 0; i < parts.length; i++) {
    if (node === null || typeof node !== 'object') {
      log.debug("Leaving dig().");
      return undefined;
    }
    node = node[parts[i]];
  }
  log.debug("Leaving dig().");
  return node;
}

// NOTE that nothing digs the UNION. `appconfig` exists for the bootstrap logger
// at the top of this file, which needs a log level before the table it would
// otherwise ask; every other read goes through resolve(), which digs the two
// files in order precisely so it can report WHICH. A dig-the-union helper was
// here and was removed rather than left: it returned the same value resolve()
// does and would have been the obvious thing for a later caller to reach for,
// which is how a surface loses the ability to say where a value came from.

function settingFor(key) {
  log.debug("Entering settingFor().");
  const setting = byKey[key];
  if (!setting) {
    throw new Error('config.js: no such setting "' + key + '"');
  }
  log.debug("Leaving settingFor().");
  return setting;
}

// The default, resolved. Written as a function because two of them are, and a
// caller should not have to know which.
function defaultOf(setting) {
  log.debug("Entering defaultOf().");
  if (typeof setting.dflt === 'function') {
    log.debug("Leaving defaultOf().");
    return setting.dflt();
  }
  log.debug("Leaving defaultOf().");
  return setting.dflt;
}

// Where this setting's value comes from right now, and what the raw form is.
// One function rather than two because the two answers must agree: a `source`
// computed separately from a `value` is the kind of pair that goes wrong when
// somebody adds a level and updates one of them.
function resolve(key) {
  log.debug("Entering resolve().");
  const setting = settingFor(key);
  // The current trust realm, above everything — including the service-wide
  // runtime override, because a realm's value is the more specific statement of
  // the two and the whole point of a realm is to differ from what the process
  // as a whole is configured with. See setRealmOverrides() above for the two
  // keys this layer deliberately cannot carry.
  const fromRealm = realmOverrideOf(key);
  if (fromRealm !== undefined) {
    log.debug("Leaving resolve().");
    return { raw: fromRealm, source: 'realm' };
  }
  if (Object.prototype.hasOwnProperty.call(overrides, key)) {
    log.debug("Leaving resolve().");
    return { raw: overrides[key], source: 'override' };
  }
  if (setting.env && process.env[setting.env] !== undefined) {
    log.debug("Leaving resolve().");
    return { raw: process.env[setting.env], source: 'env' };
  }
  if (setting.legacyEnv && process.env[setting.legacyEnv] !== undefined) {
    log.debug("Leaving resolve().");
    return { raw: process.env[setting.legacyEnv], source: 'env-legacy' };
  }
  // The appconfig layer, read as its two files rather than as the union, so
  // that the answer says WHICH. `appconfig` is the union of exactly these two
  // in exactly this order, so this is the same value either way.
  const dotted = setting.path || setting.key;
  const fromFile = dig(operatorConfig, dotted);
  if (fromFile !== undefined) {
    log.debug("Leaving resolve().");
    return { raw: fromFile, source: 'appconfig' };
  }
  const fromDefaultsFile = dig(defaults, dotted);
  if (fromDefaultsFile !== undefined) {
    log.debug("Leaving resolve().");
    return { raw: fromDefaultsFile, source: 'defaults' };
  }
  // NOWHERE. For a `derived` setting this is the answer — its default is a
  // function of a neighbour and env/defaults.js deliberately carries no row for
  // it. For any other, requireComplete() has already stopped the process, so
  // this line is only reached in a module loaded on its own by a test.
  log.debug("Leaving resolve().");
  return { raw: defaultOf(setting), source: 'default' };
}

// THE function every module calls. Coerced to the setting's type, so a caller
// never has to know whether the value arrived from a string environment or a
// typed file.
function value(key) {
  log.debug("Entering value().");
  const setting = settingFor(key);
  log.debug("Leaving value().");
  return TYPES[setting.type].parse(resolve(key).raw, setting);
}

// ---------------------------------------------------------------------------
// THE SAME READ WITH THE REALM LAYER SUPPRESSED, for a DERIVED default that is
// a statement about the PROCESS. One caller: `global.https`.
//
// That row is restart-only and carries no `realmRuntime`, so a realm can never
// SET it — and that was taken for the whole of the lock until 2026-08-25. It is
// not: a default is resolved by CALLING it, `global.https`'s default is
// `oauth2.rfc9700`, and that one a realm can set. Through the ordinary value()
// the closure would answer the realm's question ("is this realm enforcing the
// BCP?") with the process's ("is this port TLS?"), and the realm would inherit
// a claim about a socket IT DID NOT BIND: mainPortIsTls() reports sections 2.1
// and 2.6 as met over a plain connection, and issuerOf() upgrades a pinned
// http:// issuer to https:// on an http:// port — a discovery document a
// conforming client MUST reject, whose error names the issuer and never the
// realm. Nothing was misconfigured for that to happen; it needed only a mock
// started without STS_HTTPS, which is every mock started without STS_HTTPS,
// since `derived: true` keeps the row out of the shipped env/*.js files.
//
// This is the same reasoning as the realmRuntime paragraph at the top of this
// file, run the other way: a realm binds no socket, so it may CARRY the mode —
// and, for that same reason, it may not carry a conclusion ABOUT the socket.
//
// A plain boolean and not an AsyncLocalStorage, deliberately: every step
// between here and the default — settingFor(), resolve(), dig(), the dflt
// itself — is SYNCHRONOUS. The realm layer needs an ALS because a realm spans
// awaits; this must not span one at all, and a flag that could would be the
// bug it exists to prevent. Saved and restored rather than cleared, so a
// derived default that reads another one nests correctly.
//
// No Entering/Leaving pair, for the reason nothing else on this reading path
// has one: it is reached for every setting read in the service.
// ---------------------------------------------------------------------------
function processValue(key) {
  const was = suppressRealmLayer;
  suppressRealmLayer = true;
  try {
    return value(key);
  } finally {
    suppressRealmLayer = was;
  }
}

// ---------------------------------------------------------------------------
// THE BASE URL OF THE MANAGEMENT API, AS THE PROCESS KNOWS IT WITHOUT A
// REQUEST. `adminApi.audience`'s derived default, and what
// mgmt-api/admin_api.js compares a token's `aud` against beside the
// request-relative base.
//
// Read process-wide, for the reason the audience itself is computed outside
// any realm there: this credential is service-wide, so a realm carrying
// `oauth2.rfc9700` (and through it `global.https`) must not move it.
//
// A wildcard bind is not a name a client can dial, so it is drawn as
// `localhost`; a specific bound address is used as itself. The scheme's
// standard port is left off, which is what `baseUrlOf()` gives a request that
// carried a Host header without one.
// ---------------------------------------------------------------------------
function managementApiBaseUrl() {
  log.debug("Entering managementApiBaseUrl().");
  const pinned = String(processValue('global.publicBaseUrl') || '').trim()
    .replace(/\/+$/, '');
  if (pinned) {
    log.debug("Leaving managementApiBaseUrl().");
    return pinned + '/admin-api';
  }
  const https = !!processValue('global.https');
  const port = Number(processValue('global.port'));
  const bound = String(processValue('global.host') || '')
    .replace(/^\[|\]$/g, '');
  let host = bound;
  if (bound === '' || bound === '0.0.0.0' || bound === '::') {
    host = 'localhost';
  } else if (bound.indexOf(':') >= 0) {
    host = '[' + bound + ']';
  }
  const standard = https ? 443 : 80;
  log.debug("Leaving managementApiBaseUrl().");
  return (https ? 'https' : 'http') + '://' + host +
    (port === standard ? '' : ':' + port) + '/admin-api';
}

function sourceOf(key) {
  log.debug("Entering sourceOf().");
  log.debug("Leaving sourceOf().");
  return resolve(key).source;
}

// The value as a single line: what the console's input shows, and what the
// equivalent environment variable would carry.
function text(key) {
  log.debug("Entering text().");
  const setting = settingFor(key);
  log.debug("Leaving text().");
  return TYPES[setting.type].text(value(key), setting);
}

// ---------------------------------------------------------------------------
// Writing.
//
// Every refusal comes back as a list of strings rather than a thrown error,
// because both callers — the console's form handler and the management API —
// have to turn it into a reply rather than a stack trace, and both already
// speak that shape.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// The loggers, so that `global.logLevel` is a setting rather than a claim.
//
// A bunyan logger takes its level when it is CREATED, so a table that says the
// log level is runtime-settable and does nothing about it is exactly the lie
// this file refuses to tell about a bound port. Every module that owns a logger
// registers it here and `applyLogLevel()` sets the level on all of them after
// any change.
//
// TWO of them are registered, and they cover everything this service writes:
// this module's own, and the `sts` logger in helpers.js that every protocol
// module destructures. **The eight `krb5_*` codec modules are the exception and
// cannot be included**: they are byte-identical copies of the parent project's
// `common/krb5/*` files, kept honest by its `tests/krb5_codec_sync.js`, so a
// line added to them here would fail that test. Each builds its own logger from
// CONFIG_FILE at load and therefore keeps the level the process STARTED with —
// which is ASN.1 and crypto tracing, not the service's account of what it did.
// Say so rather than quietly leaving a gap: somebody who turns the level down
// to quieten a run and still sees krb5_asn1 lines is looking at this paragraph.
// ---------------------------------------------------------------------------
const loggers = [];

function registerLogger(logger) {
  log.debug("Entering registerLogger().");
  loggers.push(logger);
  logger.level(value('global.logLevel'));
  log.debug("Leaving registerLogger().");
}

function applyLogLevel() {
  log.debug("Entering applyLogLevel().");
  const level = value('global.logLevel');
  loggers.forEach(function (logger) {
    logger.level(level);
  });
  log.debug("Leaving applyLogLevel().");
  return level;
}

// Whether this value WOULD be accepted, without accepting it. Separate from
// setOverride() for one caller: the console's Save posts a whole section, and a
// section that applied its first three fields and then refused the fourth would
// leave the service in a state nobody asked for. So every field is checked
// through here first and only then written.
//
// Returns an error STRING or null, which is the shape the callers join into
// their `errors` array.
// `forRealm` is passed by exactly one caller — `realms.js`'s
// checkRealmOverride(), which every writing path into a realm's overrides goes
// through — and it admits the `realmRuntime` rows. See the paragraph on that
// marker at the top of this file for why that is an application of the
// restart-only rule rather than a hole in it: a realm binds no socket, so the
// reason those rows are restart-only is not a reason a REALM cannot carry them.
// The process-wide form is unchanged and still refuses.
function checkOverride(key, raw, forRealm) {
  log.debug("Entering checkOverride().");
  // `forRealm` OMITTED MEANS "WHEREVER THIS WRITE WOULD LAND", which is what
  // every caller inside this service means and what none of them was saying.
  //
  // The third argument admits the `realmRuntime` rows — restart-only for the
  // process, settable on a realm, because a realm binds no socket. realms.js
  // passes `true` explicitly, because it is validating a realm's overrides
  // before any realm is ambient. The FIVE OTHER CALLERS pass nothing: three in
  // admin-ui/admin.js, which pre-validate a whole section before writing any of
  // it, and setOverride() here. All of them are inside a request, so the realm
  // the write lands in is the ambient one — and by not saying so they made the
  // marker unreachable through every door a person actually uses.
  //
  // What that looked like: the console draws `oauth2.rfc9700` as an EDITABLE
  // control inside a realm, correctly, and the section's Save posts `set-many`,
  // which is ALL-OR-NOTHING — so pressing Save on /realm/acme/admin/oauth2 was
  // refused by name every time, including when nothing had been changed, with
  // a refusal that explained that a realm may carry the setting it was
  // refusing. Defaulting here fixes all four call sites at once and leaves the
  // explicit `true` and the explicit `false` meaning exactly what they did.
  const inRealm = forRealm === undefined ? !!realmFor(key) : !!forRealm;
  log.debug("Entering checkOverride(). forRealm=" + inRealm);
  const setting = byKey[key];
  if (!setting) {
    log.debug("Leaving checkOverride().");
    return 'Unknown setting "' + key + '".';
  }
  if (!setting.runtime && !(inRealm && setting.realmRuntime)) {
    log.debug("Leaving checkOverride().");
    return '"' + key + '" cannot be changed while this service is running: ' +
      setting.restartReason + '. Set it in the appconfig file or as ' +
      (setting.env || 'its environment variable') + ' and restart.';
  }
  const problem = TYPES[setting.type].check(raw, setting);
  log.debug("Leaving checkOverride().");
  return problem ? '"' + key + '" ' + problem + '.' : null;
}

// WHICH CONDITION checkOverride() REFUSED FOR, as an error code, or '' where it
// accepts. Beside it rather than inside it because checkOverride() answers a
// STRING that six callers render, and changing its shape to carry a code would
// change what each of them sees. The order of the tests is checkOverride()'s
// own, so the two cannot name different conditions for one refusal.
function checkOverrideCode(key, raw, forRealm) {
  log.debug("Entering checkOverrideCode().");
  const inRealm = forRealm === undefined ? !!realmFor(key) : !!forRealm;
  const setting = byKey[key];
  if (!setting) {
    log.debug("Leaving checkOverrideCode().");
    return 'STS-CORE-0004';
  }
  if (!setting.runtime && !(inRealm && setting.realmRuntime)) {
    log.debug("Leaving checkOverrideCode().");
    return 'STS-CORE-0005';
  }
  log.debug("Leaving checkOverrideCode().");
  return TYPES[setting.type].check(raw, setting) ? 'STS-CORE-0006' : '';
}

function setOverride(key, raw) {
  log.debug("Entering setOverride(). key=" + key);
  // WHICH REALM THIS WRITE LANDS IN IS DECIDED FIRST, BECAUSE THE CHECK
  // DEPENDS ON IT.
  //
  // `checkOverride()` takes a third argument — `forRealm` — that admits the
  // `realmRuntime` rows: restart-only for the PROCESS, because they decide
  // something a listener was bound with, and settable on a REALM, because a
  // realm binds no socket. This function computed the realm four lines further
  // down and called the check WITHOUT it, so a realm could never carry one.
  //
  // What that looked like from outside is worse than the rule being absent: the
  // console draws `oauth2.rfc9700` as an EDITABLE control inside a realm (it is
  // right to — a realm may carry it) and the section's Save posts `set-many`,
  // which is all-or-nothing, so pressing Save on /realm/acme/admin/oauth2 was
  // refused BY NAME every time — including when nothing on the page had been
  // changed. The whole page was unusable inside a realm and the refusal
  // explained, correctly, that a realm may carry the setting it was refusing.
  //
  // `realmFor()` answers null when realms are off, when the ambient realm is
  // the default one, and always for the two `realms.*` rows — so this is the
  // process-wide behaviour unchanged everywhere else.
  const realm = realmFor(key);
  const problem = checkOverride(key, raw, !!realm);
  // (Passed explicitly here because the realm is already in hand; the default
  // above would compute the same answer.)
  if (problem) {
    log.debug("Leaving setOverride(). Refused: " + problem);
    return errorCodes.mark({ ok: false, errors: [problem] },
                           checkOverrideCode(key, raw, !!realm));
  }
  // ---------------------------------------------------------------------
  // A WRITE LANDS WHEREVER IT WAS MADE, AND THAT IS THE WHOLE OF WHAT MAKES
  // /admin/config REALM-AWARE.
  //
  // Setting a value while the `acme` realm is ambient means setting it FOR
  // `acme` — anything else would be a console page that reads one realm and
  // writes another, which is the surprise that costs a whole afternoon. So the
  // write goes to the realm's own override object when there is one and to the
  // process-wide map otherwise, and every caller — the console's Save, the
  // token-lifetimes page, POST /admin-api/config/set and whatever is added next
  // — is realm-correct without knowing this exists.
  //
  // The two `realms.*` settings are the exception in both directions:
  // realmFor() answers null for them, so they always land process-wide. A realm
  // that could turn realms off, or move its own prefix, would be doing it from
  // inside the request that found it.
  // ---------------------------------------------------------------------
  if (realm) {
    realm.overrides[key] = raw;
  } else {
    overrides[key] = raw;
  }
  // Before the log line, so that a change to the level is in force for the
  // line that announces it rather than one line late.
  applyLogLevel();
  log.info('config: ' + key + ' is now ' + JSON.stringify(text(key)) +
           (realm ? ' in the "' + realm.id + '" realm.' :
            ' (runtime override).'));
  // After the write and after the log line, so that a store which reads the
  // value back reads the new one. See setOverrideStore() above.
  overridesChanged(realm ? realm.id : null);
  log.debug("Leaving setOverride().");
  return { ok: true, errors: [], key: key, realm: realm ? realm.id : null };
}

// Drop one override, so the setting falls back to the environment, the file or
// the default — whichever it would have used had nothing ever been set.
function clearOverride(key) {
  log.debug("Entering clearOverride(). key=" + key);
  const setting = byKey[key];
  if (!setting) {
    log.debug("Leaving clearOverride(). Unknown key.");
    return errorCodes.mark({ ok: false,
                             errors: ['Unknown setting "' + key + '".'] },
                           'STS-CORE-0004');
  }
  // The same rule as setOverride(): a reset undoes the override that was made
  // HERE. In a realm that is the realm's, and the value then falls back to
  // whatever the process as a whole is configured with — which may itself be a
  // runtime override, and is left alone.
  const realm = realmFor(key);
  const where = realm ? realm.overrides : overrides;
  if (!Object.prototype.hasOwnProperty.call(where, key)) {
    log.debug("Leaving clearOverride(). Nothing was overridden.");
    return errorCodes.mark({ ok: false, errors: ['"' + key + '" has no ' +
      (realm ? 'value set in the "' + realm.id + '" realm' :
       'runtime override') +
      ' to reset; it is already coming from ' + sourceOf(key) + '.'] },
                           'STS-CORE-0007');
  }
  delete where[key];
  applyLogLevel();
  log.info('config: ' + key + ' is back to its ' + sourceOf(key) + ' value' +
           (realm ? ' in the "' + realm.id + '" realm.' : '.'));
  // A RESET IS A CHANGE, and forgetting this is the subtle half of persisting
  // configuration: the override is gone from memory, and a store that was only
  // told about writes would still hold it and would put it back on the next
  // start. A reset that does not survive a restart is worse than no reset.
  overridesChanged(realm ? realm.id : null);
  log.debug("Leaving clearOverride().");
  return { ok: true, errors: [], key: key, realm: realm ? realm.id : null };
}

function clearAllOverrides() {
  log.debug("Entering clearAllOverrides().");
  // In a realm this clears the REALM's settings and leaves the process-wide
  // overrides alone, which is the same rule the two functions above follow: a
  // "reset everything" button on a realm's configuration page that also reset
  // every other realm would be the worst button in this console. `realmFor()`
  // is asked with a key that is not a realms.* one, since the exemption is per
  // setting and this is per realm.
  const realm = realmFor('global.logLevel');
  const where = realm ? realm.overrides : overrides;
  const keys = Object.keys(where);
  keys.forEach(function (key) { delete where[key]; });
  applyLogLevel();
  log.info('config: ' + keys.length +
           (realm ? ' setting(s) cleared in the "' + realm.id + '" realm.'
                  : ' runtime override(s) cleared.'));
  // Unconditionally, even when `keys` is empty: the store's copy is the thing
  // being brought into line, and "nothing was cleared here" is not evidence
  // that nothing is written down over there.
  overridesChanged(realm ? realm.id : null);
  log.debug("Leaving clearAllOverrides(). " + keys.length + " cleared.");
  return { ok: true, errors: [], cleared: keys,
           realm: realm ? realm.id : null };
}

// ---------------------------------------------------------------------------
// THE PROCESS-WIDE OVERRIDES, TO BE WRITTEN DOWN AND READ BACK. Both halves are
// here rather than in persistence.js, and it is the same argument twice: this
// map is this file's, `overrides` is not exported and must not become so, and a
// module that reached in to copy it would be a second thing that knows what an
// override is.
//
// A REALM'S OVERRIDES ARE NOT HERE. They live on the realm row —
// `realm.overrides` — and are written down with the realm registry, because
// that is where they live in memory too. Copying them into this map would
// create the one thing the realm layer exists to prevent: a realm's value in a
// process-wide place.
// ---------------------------------------------------------------------------
function persistableOverrides() {
  log.debug("Entering persistableOverrides().");
  const out = {};
  Object.keys(overrides).forEach(function (key) { out[key] = overrides[key]; });
  log.debug("Leaving persistableOverrides().");
  return out;
}

// ---------------------------------------------------------------------------
// PUTTING THEM BACK AT STARTUP, AND THE ONE PROPERTY THAT MAKES IT SAFE TO DO
// IT THIS LATE.
//
// This runs from `persistence.start()`, which `server.js` calls after every
// module has been required and before the HTTP listener binds. That is very
// late to be changing configuration, and it is safe for a reason that is a
// property of the table rather than of the ordering:
//
//   **ONLY A `runtime: true` SETTING CAN BE OVERRIDDEN AT ALL.** checkOverride()
//   refuses every other by name and says why. And a runtime setting is BY
//   DEFINITION one that is read per call rather than captured at require time —
//   that is what the column means and what `restartReason` documents the
//   absence of. So there is nothing in a saved override file that any module
//   could already have read and cached.
//
// The corollary is the one worth stating: `global.https`, `oauth2.rfc9700`,
// `ldap.port`, `ldap.baseDn` and every other restart-only setting are exactly
// what the environment and the appconfig file said, and no persisted value can
// reach them. A saved file cannot change the scheme this service answers on.
//
// EVERY VALUE IS RE-CHECKED rather than trusted. The file was written by this
// service, but it was written by a possibly older version of it — a setting may
// have been renamed, retyped, its enum narrowed, or turned restart-only since —
// and a saved value that is no longer valid must be reported and skipped rather
// than smuggled past the validation every other caller goes through.
// ---------------------------------------------------------------------------
function applyPersistedOverrides(saved) {
  log.debug("Entering applyPersistedOverrides().");
  const applied = [];
  Object.keys(saved || {}).forEach(function (key) {
    const problem = checkOverride(key, saved[key]);
    if (problem) {
      log.warn(errorCodes.tag('STS-CORE-0008') +
               'config: the saved override for "' + key + '" was not ' +
               'applied: ' + problem + ' It is left in the store; nothing is ' +
               'deleted on the strength of one start refusing it.');
      return;
    }
    overrides[key] = saved[key];
    applied.push(key);
  });
  // ------------------------------------------------------------------------
  // AND WHAT IS NO LONGER THERE IS CLEARED (2026-09-08). This function used to
  // only ADD, which is correct at STARTUP — `overrides` is empty then, so
  // there is nothing to clear — and silently wrong for the OTHER caller.
  //
  // `persistence.js`'s `applyAppconfigChange()` calls it with the whole stored
  // set every time another process changes the configuration, and a RESET is
  // the absence of a key. Only ever merging meant a reset made in one process
  // never reached any other: `POST /admin-api/config/reset` answered ok, the
  // store no longer held the row, and every other process went on serving the
  // overridden value for ever. It cost two jobs in the dispatch suite —
  // `admin_api` read a batch size back as 7 after resetting it to 4, and
  // `sts_roles` was refused 400 resetting a setting the worker it reached had
  // never been told was set.
  //
  // A KEY THAT IS PRESENT AND REFUSED IS LEFT ALONE, which is why this walks
  // `saved` rather than `applied`: a refusal above says nothing was applied
  // for that key, and treating it as an absence would clear an override this
  // process is legitimately running with because another process's build
  // validates it differently.
  // ------------------------------------------------------------------------
  const cleared = [];
  Object.keys(overrides).forEach(function (key) {
    if (!Object.prototype.hasOwnProperty.call(saved || {}, key)) {
      delete overrides[key];
      cleared.push(key);
    }
  });
  if (cleared.length) {
    log.info('config: ' + cleared.length + ' runtime override(s) are no ' +
             'longer in the store and have been cleared here: ' +
             cleared.join(', ') + '.');
  }
  // Once, after all of them, rather than per setting: applyLogLevel() walks
  // every registered logger, and doing that per key would be n times the work
  // for the same answer.
  applyLogLevel();
  log.debug("Leaving applyPersistedOverrides(). " + applied.length +
            " applied.");
  return applied;
}

// ---------------------------------------------------------------------------
// Describing.
//
// One shape, used by the console page, by the management API and by the
// OpenAPI document's example. A second shape for any of them is how a console
// and an API start disagreeing about what the service is configured with.
// ---------------------------------------------------------------------------
function describe(setting) {
  log.debug("Entering describe().");
  const state = resolve(setting.key);
  log.debug("Leaving describe().");
  return {
    key: setting.key,
    group: setting.group,
    label: setting.label,
    description: setting.description,
    type: setting.type,
    enumValues: setting.enumValues || undefined,
    // The int bounds, where a row narrows them. `undefined` is dropped by
    // JSON.stringify, so a row that carries none of them describes exactly as
    // it did before they existed — which is what keeps the management API's
    // Config schema and its example true of every other row.
    min: typeof setting.min === 'number' ? setting.min : undefined,
    max: typeof setting.max === 'number' ? setting.max : undefined,
    step: typeof setting.step === 'number' ? setting.step : undefined,
    value: value(setting.key),
    text: text(setting.key),
    source: state.source,
    // EDITABLE IS ASKED OF THE REALM THE READER IS IN, not of the process. A
    // `realmRuntime` row is restart-only service-wide and settable on a realm
    // (see the paragraph on that marker at the top of this file), so
    // /admin/config drawn under a realm's prefix must offer the control the
    // same page in the default realm correctly refuses — otherwise the console
    // would report a setting as unchangeable while POST /admin-api/config/set
    // on the same path changed it.
    editable: !!setting.runtime ||
              !!(setting.realmRuntime && realmFor(setting.key)),
    restartReason: (setting.runtime ||
                    (setting.realmRuntime && realmFor(setting.key)))
      ? undefined
      : setting.restartReason,
    env: setting.env,
    legacyEnv: setting.legacyEnv,
    appconfigPath: setting.path || setting.key,
    default: defaultOf(setting),
    // WHETHER A REALM MAY CARRY IT, reported rather than left to be discovered
    // by a refusal. A management API that describes a setting as `editable`
    // and then refuses it under a realm prefix is telling half the truth, and
    // it is the half a caller acts on: `tests/vendored/
    // sts_admin_api_operations.js` walks this table for a runtime integer to
    // drive a realm override with, and picked `workers.count` the day it was
    // added — a setting a realm may not carry, so the write landed on the
    // process and the row it read back said so.
    //
    // `perProcess` and the `realms.*` prefix are the two reasons, and both are
    // config.js's own to state — see realmFor() and realms.js's
    // checkRealmOverride().
    realmSettable: !isPerProcess(setting.key) &&
                   String(setting.key).indexOf('realms.') !== 0,
    overridden: Object.prototype.hasOwnProperty.call(overrides, setting.key)
  };
}

// Every group, in the order the table declares them, with their settings in it.
// Order matters here in a way it does not for most lists: the console renders
// one section per group and a reader looking for the Kerberos realm should find
// it where the Kerberos endpoints are described everywhere else.
function groups() {
  log.debug("Entering groups().");
  const order = [];
  const bucket = {};
  SETTINGS.forEach(function (setting) {
    if (!bucket[setting.group]) {
      bucket[setting.group] = [];
      order.push(setting.group);
    }
    bucket[setting.group].push(describe(setting));
  });
  const out = order.map(function (name) {
    return { group: name, settings: bucket[name] };
  });
  log.debug("Leaving groups(). " + out.length + " group(s).");
  return out;
}

function snapshot() {
  log.debug("Entering snapshot().");
  // WHICH REALM THIS SNAPSHOT IS OF, and what it sets. Reported rather than
  // implied, because the same URL answers differently under a realm prefix and
  // a reader with a JSON body in front of them has no other way to tell which
  // one they asked.
  const realm = realmFor('global.logLevel');
  const overridden = Object.keys(overrides);
  const out = {
    realm: realm ? realm.id : DEFAULT_REALM_ID,
    realmSettings: realm ? Object.keys(realm.overrides) : [],
    configFile: process.env.CONFIG_FILE || null,
    // The base every appconfig file is unioned on top of. Reported beside the
    // operator's file rather than left implicit, because a value whose source
    // is `defaults` names no file otherwise and "where did this come from?" is
    // the question this whole shape exists to answer.
    defaultsFile: DEFAULTS_FILE,
    settingCount: SETTINGS.length,
    editableCount: SETTINGS.filter(function (s) { return s.runtime; }).length,
    overridden: overridden,
    groups: groups()
  };
  log.debug("Leaving snapshot(). " + out.settingCount + " setting(s), " +
            overridden.length + " overridden.");
  return out;
}


// ---------------------------------------------------------------------------
// Does the OPERATOR'S appconfig file still match this table?
//
// The three files shipped in env/ were GENERATED from it, so they agree the day
// they are written. Nothing keeps them agreeing: a setting added below and not
// added to the files is no longer LISTED there (it resolves through
// env/defaults.js, which is correct but leaves the file claiming to be the
// whole surface when it is not), and a key left in a file after the setting is
// removed is read by nobody and says otherwise.
//
// Neither is fatal, so neither throws — a stale config file must not stop a
// service from starting. What IS fatal is a setting with no value ANYWHERE, and
// that is requireComplete() below rather than this: the two questions look
// alike and are not the same one. "Your file no longer lists everything" is
// about the file you are editing. "Nothing anywhere has a value for this" is
// about the service being unable to say what it is configured with.
//
// IT READS `operatorConfig`, NOT THE UNION, and that is the whole reason the
// two are kept apart at the top of this file. The union can never be missing a
// key — env/defaults.js carries every non-derived row — so an audit against it
// would answer "nothing is missing" every time and the warning would be dead
// code that looked alive.
// ---------------------------------------------------------------------------
function auditAppconfig() {
  log.debug("Entering auditAppconfig().");
  // `derived` settings are left OUT of every appconfig file on purpose,
  // env/defaults.js included: their default is computed from another setting,
  // and a literal in a file would freeze the derivation at whatever it
  // evaluated to the day it was written. Counting them as drift would mean
  // warning on every start about the one thing that is correct.
  const missing = SETTINGS.filter(function (setting) {
    return !setting.derived &&
           dig(operatorConfig, setting.path || setting.key) === undefined;
  }).map(function (setting) { return setting.key; });

  // Every dot path the file actually carries, so a key the table does not know
  // can be named. Only the two levels this table uses are walked; a deeper
  // object under a known group is somebody's own note and is left alone.
  const present = [];
  Object.keys(operatorConfig || {}).forEach(function (top) {
    const node = operatorConfig[top];
    if (node && typeof node === 'object' && !Array.isArray(node)) {
      Object.keys(node)
            .forEach(function (leaf) { present.push(top + '.' + leaf); });
      return;
    }
    present.push(top);
  });
  const known = {};
  SETTINGS.forEach(function (setting) {
    known[setting.path || setting.key] = true;
  });
  const unknown = present.filter(function (path) { return !known[path]; });

  log.debug("Leaving auditAppconfig(). " + missing.length + " missing, " +
            unknown.length + " unknown.");
  return { missing: missing, unknown: unknown };
}

// ---------------------------------------------------------------------------
// EVERY SETTING HAS A VALUE, OR THIS SERVICE DOES NOT START.
//
// The rule, stated once: a setting's value must come from the appconfig layer
// (the operator's file, or env/defaults.js under it) or from an environment
// variable. There is no sixth source, and a `dflt` in the table above is
// DOCUMENTATION of what env/defaults.js was generated from rather than a
// fallback the service quietly leans on.
//
// WHAT THIS CAN ACTUALLY CATCH, since it is not what it looks like. The union
// means an operator's file cannot cause this — a file carrying nothing at all
// still resolves every key through env/defaults.js. What it catches is a row
// added to the table with no row in env/defaults.js: a setting somebody added
// and did not finish adding, which before this check would have shipped as a
// value nobody could see in any file, on any page, and would have been
// discovered as a default that could not be changed by editing the file that
// claims to list it. That is a MAINTAINER'S mistake caught at the first start
// after it is made, which is where it is cheapest.
//
// It refuses BY NAME and says both places the value could go, because a
// service that exits saying "configuration error" has told nobody anything.
//
// process.exit(1) rather than a throw. A throw out of a require lands as a
// stack trace whose top frame is node's module loader, and the reason ends up
// three screens above where anybody looks; the exit code is the same either
// way, and this is a message meant to be read.
// ---------------------------------------------------------------------------
function requireComplete() {
  log.debug("Entering requireComplete().");
  const orphans = SETTINGS.filter(function (setting) {
    return !setting.derived && resolve(setting.key).source === 'default';
  });
  if (!orphans.length) {
    log.debug("Leaving requireComplete(). Every setting has a value.");
    return;
  }
  const width = orphans.reduce(function (w, s) {
    return Math.max(w, s.key.length);
  }, 0);
  process.stderr.write(
    '\n' + errorCodes.tag('STS-CORE-0002') + 'config: FATAL — ' +
    orphans.length + ' ' +
    'setting(s) have no value in the appconfig layer and no environment ' +
    'variable:\n\n' +
    orphans.map(function (setting) {
      return '  ' + setting.key + ' '.repeat(width - setting.key.length + 2) +
             setting.env;
    }).join('\n') +
    '\n\nEach must be set in ' + (process.env.CONFIG_FILE || 'the appconfig ' +
    'file CONFIG_FILE ' +
    'names') + ', in ' + DEFAULTS_FILE + ' (the default ' +
    'appconfig file every other one is unioned on top of), or as the ' +
    'environment variable beside it.\n\nIf one of these was just added to ' +
    'SETTINGS in common/config.js, env/defaults.js is generated from that ' +
    'table and has not been regenerated.\n\n');
  log.debug("Leaving requireComplete(). Refusing to start.");
  process.exit(1);
  log.debug("Leaving requireComplete().");
}

log.info('config: ' + SETTINGS.length + ' settings from ' +
         (process.env.CONFIG_FILE || '(no CONFIG_FILE)') + ' over ' +
         DEFAULTS_FILE + ', ' +
         SETTINGS.filter(function (s) { return s.runtime; }).length +
         ' of them changeable while running. /admin/config shows them all.');

// This module's own logger joins the registry last, after the table it reads
// from is built.
registerLogger(log);

// BEFORE the drift warnings, because there is no point telling somebody their
// file is one key short of the table when the service is about to refuse to
// start over a different key entirely.
requireComplete();

const audit = auditAppconfig();

// IS THIS FILE EVEN THIS SERVICE'S? The test is whether it carries any key of
// ours that is DISTINCTIVE, and `logLevel` is the one that is not: every
// appconfig file in this ecosystem has one — the parent project's api, its
// client and its test suites included — because it is the only setting that
// predates this table. Counting it made the branch below almost unreachable for
// the very case it was written for, since the parent's in-process Kerberos jobs
// point CONFIG_FILE at a test config that sets exactly that one key and nothing
// else. The result was a hundred-and-fourteen-name warning on every such run,
// which is the shape of message people learn to scroll past.
const DISTINCTIVE = SETTINGS.filter(function (s) {
  return !s.derived && (s.path || s.key) !== 'logLevel';
});
const settable = SETTINGS.filter(function (s) { return !s.derived; }).length;
const distinctiveMissing = DISTINCTIVE.filter(function (s) {
  return audit.missing.indexOf(s.key) >= 0;
}).length;

// A name list long enough to scroll is a name list nobody reads. Twelve and a
// count, in the table's own order, so the first few are enough to recognise
// which section of the file went stale.
function nameList(keys) {
  log.debug("Entering nameList().");
  const shown = keys.slice(0, 12).join(', ');
  log.debug("Leaving nameList().");
  return keys.length > 12
    ? shown + ', and ' + (keys.length - 12) + ' more'
    : shown;
}

if (distinctiveMissing === DISTINCTIVE.length) {
  // NOT drift, and not worth a warning: a config file carrying none of these
  // keys is somebody else's file, which is the ordinary case for the parent
  // project's in-process tests — they load this service's KDC modules with
  // CONFIG_FILE pointing at the TEST suite's config. Every value then comes
  // from env/defaults.js or from the environment, which is what those jobs had
  // before this table existed, and the KRB5_* variables they set still win.
  //
  // THIS IS THE CASE THE UNION EXISTS FOR. Before env/defaults.js, such a file
  // meant every value fell through to a built-in default; with the startup
  // refusal above and no base file, it would instead have meant those jobs
  // could not load these modules at all.
  log.debug('config: ' + (process.env.CONFIG_FILE || 'the appconfig file') +
            ' carries none of this service\'s settings, so every value comes ' +
            'from ' + DEFAULTS_FILE + ' or from the environment.');
} else if (audit.missing.length) {
  log.warn('config: ' + audit.missing.length + ' setting(s) are not in ' +
           (process.env.CONFIG_FILE || 'the appconfig file') + ' and are ' +
           'coming from ' + DEFAULTS_FILE + ' instead: ' +
           nameList(audit.missing) + '. That is not an error — the union is ' +
           'what that file is for, and the value is the same either way — ' +
           'but a file that is meant to list the whole surface no longer ' +
           'does.');
}
// Guarded the same way, and for the same reason: every key in somebody
// else's config file is one this service does not know, and saying so
// forty-five times would bury the case this warning is for — a misspelt
// key in a file that IS this service's.
if (audit.unknown.length && distinctiveMissing !== DISTINCTIVE.length) {
  log.warn('config: ' + (process.env.CONFIG_FILE || 'the appconfig file') +
           ' carries ' + audit.unknown.length + ' key(s) this service does ' +
           'not know and is not reading: ' + nameList(audit.unknown) +
           '. A misspelt key looks exactly like this.');
}

// ---------------------------------------------------------------------------
// PARSE A VALUE THAT DID NOT COME FROM ANY OF THE FIVE LAYERS.
//
// Added 2026-08-27 for the per-application SAML overrides. An application entry
// in the embedded directory may carry `saml2SignAssertion: "false"`, and the
// module reading it needs the same string turned into the same JavaScript value
// that `value()` would have produced for `saml2.signAssertion` — a boolean, not
// the truthy string "false", which is the bug this function exists to make
// impossible.
//
// IT IS NOT A SIXTH LAYER. Nothing here is consulted by value(), no override is
// recorded, and the setting's own five layers are untouched: this only lends
// out the TYPE. The caller decides whether it had something to parse and what
// to do when it did not, which is why the answer is `{ ok, value, problem }`
// rather than a value with a silent fallback hidden inside it.
//
// A VALUE THAT WILL NOT PARSE IS REPORTED, NOT THROWN, and the caller logs it
// and falls back. An `ldapmodify` can put any string on any attribute, and an
// identity provider that stopped issuing because somebody typed "yes" would be
// a mock that stopped answering — which `applications.js`'s own header argues
// at length about this directory being a vocabulary rather than a constraint.
function parseAs(key, raw) {
  log.debug("Entering parseAs(). key=" + key);
  const setting = byKey[key];
  if (!setting) {
    log.debug("Leaving parseAs(). Unknown setting.");
    return errorCodes.mark({ ok: false,
                             problem: 'Unknown setting "' + key + '".' },
                           'STS-CORE-0004');
  }
  if (raw === undefined || raw === null || String(raw).trim() === '') {
    log.debug("Leaving parseAs(). Nothing to parse.");
    return { ok: false, problem: 'no value' };
  }
  // The SAME check the console form and the management API run, so a value a
  // person could not type into /admin/config is not one an ldapmodify can
  // smuggle past by another door. Bounds included: an artifact lifetime of a
  // fortnight is refused here exactly as it is there.
  const problem = TYPES[setting.type].check(raw, setting);
  if (problem) {
    log.debug("Leaving parseAs(). Refused: " + problem);
    return errorCodes.mark({ ok: false, problem: '"' + key + '" ' + problem },
                           'STS-CORE-0006');
  }
  const parsed = TYPES[setting.type].parse(raw, setting);
  log.debug("Leaving parseAs(). Parsed.");
  return { ok: true, value: parsed };
}

module.exports = {
  SETTINGS: SETTINGS,
  parseAs: parseAs,
  setRealmContext: setRealmContext,
  DEFAULTS_FILE: DEFAULTS_FILE,
  value: value,
  text: text,
  sourceOf: sourceOf,
  managementApiBaseUrl: managementApiBaseUrl,
  registerLogger: registerLogger,
  checkOverride: checkOverride,
  checkOverrideCode: checkOverrideCode,
  setOverride: setOverride,
  clearOverride: clearOverride,
  clearAllOverrides: clearAllOverrides,
  setOverrideStore: setOverrideStore,
  persistableOverrides: persistableOverrides,
  applyPersistedOverrides: applyPersistedOverrides,
  describe: describe,
  groups: groups,
  snapshot: snapshot,
  auditAppconfig: auditAppconfig,
  isPerProcess: isPerProcess
};
