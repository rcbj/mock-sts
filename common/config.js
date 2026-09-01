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
// THREE SETTINGS ARE EXEMPT from the refusal, and they are the three marked
// `derived`: `global.https` comes from `oauth2.rfc9700`, `oid4vp.walletUrl`
// from `oid4vci.walletUrl`, and `krb5.serviceDomains` from `krb5.realm`. Their
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
//     afterwards would leave the derived thing untouched and the two disagreeing
//     — which is worse than refusing, because it reads as having worked.
//   * THE DIRECTORY TREE. `ldap.baseDn` is the root every entry was built under.
//
// A row that is restart-only still appears everywhere a runtime one does, with
// its effective value and its reason. Hiding them would answer "what is this
// service configured with?" with three quarters of the answer.
//
// ---------------------------------------------------------------------------
// `realmRuntime`: RESTART-ONLY FOR THE PROCESS, SETTABLE ON A REALM.
//
// One row carries it — `oauth2.rfc9700` — and it is not a softening of the rule
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
// exemption from it. `krb5.realm` is the one somebody will reach for first, and
// it is the clearest no: see `realms.js`'s NAMED_BY_REALM, which says the same
// thing from the other end.
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
// the console gate (`admin.authRequired`, on by default), but `GET
// /admin-api/config` is NOT, because nothing under `/admin-api` is — so the
// settings, passwords included, are still readable by anybody who can reach
// this port. The gate is a turnstile for exercising a client and not a lock,
// and no password anywhere in this service is checked. Do not put this port on
// a public address.
// ---------------------------------------------------------------------------

// CONFIG_FILE is made ABSOLUTE before it is read. This module lives in a
// subdirectory now, and a relative `./env/local.js` resolves against THIS
// directory rather than the package root — see common/config_file.js, which is
// required first for that reason and requires nothing itself.
const configFile = require('./config_file');
configFile.resolveConfigFile();
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
// CONFIG_FILE MAY NOW BE UNSET, which it could not be before: `require(undefined)`
// threw a TypeError naming an "id" argument nobody typed. With a base file there
// is something to fall back to, so an unset variable means "the defaults" and
// says so. (helpers.js still requires CONFIG_FILE unguarded, so that is a
// property of THIS module rather than of the whole service — a leaf module
// loaded by a test can now be loaded with no configuration at all.)
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
// array is neither file's list and an operator writing `tls: { hostnames: [...] }`
// means that list rather than that list appended to ours.
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
    process.stderr.write('config: FATAL — the appconfig file ' +
      process.env.CONFIG_FILE + ' could not be loaded: ' + err.message + '\n' +
      'CONFIG_FILE names a JavaScript module, resolved against this package ' +
      'root and then against the working directory (see common/config_file.js).\n');
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
    parse: function (raw) { return raw === undefined ? '' : String(raw); },
    text: function (v) { return String(v == null ? '' : v); },
    check: function () { return null; }
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
  // service whose tokens are wrong in a way that reads as a client bug. Refusing
  // them BY NAME here is the only place the refusal can be made once for the
  // console form, the management API and an environment variable read at
  // startup.
  //
  // `step` is a MULTIPLE-OF rather than a slider increment: 30 means the value
  // must be a whole number of thirty-second units. It is checked against `min`
  // rather than against zero, so a row whose floor is not itself a multiple of
  // the step still has a reachable floor.
  int: {
    parse: function (raw) {
      const n = parseInt(String(raw), 10);
      return Number.isFinite(n) ? n : 0;
    },
    text: function (v) { return String(v); },
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
               (typeof min === 'number' && min % step !== 0 ? ' above ' + min : '') +
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
      const n = parseInt(String(raw), 10);
      return Number.isFinite(n) ? n : 0;
    },
    text: function (v) { return String(v); },
    check: function (raw) {
      const s = String(raw).trim();
      if (!/^\d+$/.test(s)) {
        return 'must be a port number, got "' + raw + '"';
      }
      const n = parseInt(s, 10);
      if (n > 65535) {
        return 'must be 0-65535, got ' + n;
      }
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
    text: function (v) { return v ? 'true' : 'false'; },
    check: function (raw) {
      if (typeof raw === 'boolean') {
        return null;
      }
      if (/^(1|0|true|false|yes|no|on|off)$/i.test(String(raw).trim())) {
        return null;
      }
      return 'must be true or false, got "' + raw + '"';
    }
  },

  // A comma-separated list, trimmed, with the empty entries dropped. An array
  // in the appconfig file is accepted as itself: writing a list as a list is
  // the obvious thing to do in a JavaScript file and it would be perverse to
  // demand a string there because the environment can only carry one.
  csv: {
    parse: function (raw) {
      const parts = Array.isArray(raw) ? raw : String(raw === undefined ? '' : raw).split(',');
      return parts.map(function (part) { return String(part).trim(); })
                  .filter(function (part) { return part.length > 0; });
    },
    text: function (v) { return (Array.isArray(v) ? v : [v]).join(','); },
    check: function () { return null; }
  },

  // One of a fixed set. The set is on the setting rather than on the type,
  // since every enum here has a different one.
  enum: {
    parse: function (raw) { return String(raw === undefined ? '' : raw).trim(); },
    text: function (v) { return String(v == null ? '' : v); },
    check: function (raw, setting) {
      const s = String(raw).trim();
      if (setting.enumValues.indexOf(s) >= 0) {
        return null;
      }
      return 'must be one of ' + setting.enumValues.join(', ') + ', got "' + raw + '"';
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
  // this process at all, and `POST /tls/trust` and `GET /tls/server-certificate`
  // were on one deliberately — they are what a caller reaches BEFORE it trusts
  // anything. The certificate is self-signed and regenerated every start, so
  // the first fetch has to be made without verification (`curl -k`), which is
  // the ordinary bootstrap for a mock and is stated on /tls rather than left to
  // be discovered.
  { key: 'global.https', group: 'Global', label: 'HTTPS on the main port',
    env: 'STS_HTTPS', type: 'bool', derived: true,
    // processValue() and not value(): a realm may carry `oauth2.rfc9700`, and
    // this default is a statement about a bound socket, which no realm bound.
    dflt: function () { return processValue('oauth2.rfc9700'); },
    runtime: false,
    restartReason: 'the listener is bound when the process starts, and its ' +
                   'scheme is decided there',
    description: 'Serve the main port over HTTPS, with the SAME certificate ' +
                 'and key the 8443, 9443 and LDAPS 636 listeners use — one ' +
                 'self-signed pair generated per start, so a caller trusts ' +
                 'this service once rather than four times. Defaults to ' +
                 'whatever oauth2.rfc9700 is; set it explicitly to run RFC ' +
                 '9700 mode over plain http (for a client that cannot trust a ' +
                 'per-start certificate) or to serve HTTPS without the mode\'s ' +
                 'refusals. Fetch the certificate from ' +
                 '/tls/server-certificate — with verification off the first ' +
                 'time, since with this on there is no plain port left to ' +
                 'fetch it from.' },

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
                 'clients that reached it over https and every DPoP proof will ' +
                 'be refused for naming the real endpoint. Leave it OFF when ' +
                 'nothing is: with no proxy, those are ordinary headers any ' +
                 'client can set, and believing them lets a caller choose what ' +
                 'this service thinks its own issuer and endpoints are. ' +
                 'GET /tls/forwarded shows what a request actually carried and ' +
                 'what was believed of it. NOTE that this service never reads ' +
                 'a client certificate out of a header (X-Client-Cert and its ' +
                 'relatives) in either mode — a forwarded certificate is a ' +
                 'certificate anybody can forge.' },

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
    env: 'STS_WORKERS_COUNT', type: 'int', dflt: 2, min: 0, max: 32,
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

  // --- Trust realms --------------------------------------------------------
  // Two settings, and they are the only two in this table that a realm cannot
  // set on itself: a realm that could turn realms off, or move the prefix it
  // was found under, would be doing it half way through the request that found
  // it. Refused at both ends — see realms.js's setOverride() and this file's
  // realmOverrideOf().
  { key: 'realms.enabled', group: 'Trust realms', label: 'Trust realms enabled',
    env: 'STS_REALMS_ENABLED', type: 'bool', dflt: true, runtime: true,
    description: 'Whether the realms defined on /admin/realms answer on their ' +
                 'path prefixes. Turning it OFF leaves every definition in ' +
                 'place and stops the paths working, which is what to reach ' +
                 'for when a realm is answering something it should not: ' +
                 'nothing has to be deleted to find out whether a realm is ' +
                 'the reason for something. It has NO effect at all until at ' +
                 'least one realm is defined — with only the built-in default ' +
                 'realm this service behaves exactly as it did before realms ' +
                 'existed, and that is a property rather than a coincidence.' },

  { key: 'realms.pathSegment', group: 'Trust realms', label: 'Realm path segment',
    env: 'STS_REALMS_PATH_SEGMENT', type: 'string', dflt: 'realm', runtime: true,
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
                 'the same process answer correctly as localhost, as sts on a ' +
                 'compose network and through a published port. A pinned ' +
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
  // and still publishes http endpoints — which is the combination `global.https`
  // exists to make settable both ways, and it is REPORTED rather than hidden:
  // mainPortIsTls() is false, GET /oauth2/rfc9700 says so, and the four
  // requirements that are properties of the deployment come back `no` instead
  // of `deployment`. A stack that wants the compliant pass over https turns
  // `global.https` on for the PROCESS; see the note on that row.
  { key: 'oauth2.rfc9700', group: 'OAuth 2.0 / OIDC', label: 'RFC 9700 mode',
    env: 'STS_OAUTH2_RFC9700', type: 'bool', dflt: false, runtime: false,
    realmRuntime: true,
    restartReason: 'it decides whether the main port is bound as HTTPS ' +
                   '(global.https), and a listener is bound when the process ' +
                   'starts. A REALM may carry it even so — a realm binds no ' +
                   'socket, so it answers in whatever scheme this process was ' +
                   'started in and only the mode\'s checks change',
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
                 '— see global.https, whose default it is — because ' +
                 'section 2.1 says an authorization response must not be sent ' +
                 'over an unencrypted connection, and that was the one ' +
                 'requirement this mode could not enforce while its own ' +
                 'endpoint was only reachable over http. GET /oauth2/rfc9700 ' +
                 'lists every requirement and says which are enforced, which ' +
                 'are only detected, and which are true of the deployment ' +
                 'rather than of a request.' },

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
                 'reported on GET /oauth2/rfc9700 whichever mode is in force, ' +
                 'and every spoiled token is logged as spoiled — an ID Token ' +
                 'that is wrong in a way nobody remembers turning on is an ' +
                 'expensive afternoon.' },

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
                 'from the last time any token in the chain was redeemed, not ' +
                 'from issuance, so a client that refreshes every hour keeps ' +
                 'its grant indefinitely and one that stops is cut off a day ' +
                 'later. 0 turns it off while leaving the rest of the mode ' +
                 'alone. The ABSOLUTE expiry on the token itself is a ' +
                 'different setting (oauth2.refreshTokenTtlS, twenty-four ' +
                 'hours by default) and is unaffected by this one and applies ' +
                 'in both modes: this is a wall measured from the last ' +
                 'redemption, that one is a wall measured from issuance, and ' +
                 'a chain stops working at whichever comes first.' },

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
                 'channel: without it, signing out ends the cookie and leaves ' +
                 'a thirty-day credential in the client\'s hands. ON by ' +
                 'default WITHIN that mode, which is off by default — so ' +
                 'nothing changes until the mode is turned on. A token is ' +
                 'found by the session it was ISSUED on, which is recorded ' +
                 'beside it rather than carried as a claim.' },

  { key: 'oauth2.eddsaCurve', group: 'OAuth 2.0 / OIDC',
    label: 'EdDSA curve', env: 'STS_OAUTH2_EDDSA_CURVE', type: 'string',
    dflt: 'Ed25519', runtime: true, choices: ['Ed25519', 'Ed448'],
    description: 'Which Edwards curve an EdDSA signature is made on. RFC 8037 ' +
                 'registers ONE algorithm value for both curves and puts the ' +
                 'curve in the key itself, so a client that registers ' +
                 'id_token_signed_response_alg="EdDSA" has no way to say ' +
                 'which it wants — this is that way. BOTH keys are published ' +
                 'in the JWKS whatever this is set to, with different kids, ' +
                 'so a verifier follows the kid in the header and needs to ' +
                 'know nothing about this setting; changing it would ' +
                 'otherwise strand every client holding a cached JWKS.' },
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
    description: 'How long an access token is good for: its `exp` is this many ' +
                 'seconds after it was signed, and it is the `expires_in` of ' +
                 'every token response that carries one. One hour by default. ' +
                 'Read PER TOKEN, so a change here applies to the next one ' +
                 'issued and to nothing already in a client\'s hands — a token ' +
                 'is a signed statement about its own expiry and cannot be ' +
                 'shortened after the fact. Must be a whole number of ' +
                 'THIRTY-SECOND units: these settings exist to be set short and ' +
                 'watched, and a lifetime under half a minute expires between ' +
                 'the response being written and the client reading it. ' +
                 'Set it low to exercise a client\'s refresh path on demand; ' +
                 'the tokens page reports what has already expired.' },

  { key: 'oauth2.idTokenTtlS', group: 'OAuth 2.0 / OIDC per-client',
    label: 'ID Token lifetime (s)',
    env: 'STS_OAUTH2_ID_TOKEN_TTL_S', type: 'int', dflt: 3600,
    min: 30, max: 2592000, step: 30, runtime: true,
    description: 'How long an ID Token is good for. One hour by default, and ' +
                 'SEPARATE from the access token\'s even though the two shared ' +
                 'one constant until 2026-08-24 — an ID Token is consumed once, ' +
                 'at sign-in, by the client itself, and a client that keeps ' +
                 'presenting it as though it were a session is the defect this ' +
                 'row makes reproducible: give the two different lifetimes and ' +
                 'watch which one the client actually notices. Thirty-second ' +
                 'granularity, like the other two.' },

  { key: 'oauth2.refreshTokenTtlS', group: 'OAuth 2.0 / OIDC per-client',
    label: 'Refresh token lifetime (s)',
    env: 'STS_OAUTH2_REFRESH_TOKEN_TTL_S', type: 'int', dflt: 86400,
    min: 30, max: 2592000, step: 30, runtime: true,
    description: 'The ABSOLUTE lifetime of a refresh token — the `exp` on the ' +
                 'token itself, enforced in both modes by the refresh grant. ' +
                 'TWENTY-FOUR HOURS by default, and that IS A CHANGE: it was ' +
                 'thirty days, so a client that held one across a long test run ' +
                 'now meets an invalid_grant where it did not. Set this to ' +
                 '2592000 for exactly the old behaviour. It is not the same ' +
                 'setting as oauth2.refreshIdleSeconds, which is RFC 9700 ' +
                 'mode\'s INACTIVITY timeout on a refresh CHAIN and is measured ' +
                 'from the last redemption rather than from issuance: this one ' +
                 'is a wall a chain cannot be refreshed past however busy it is.' },

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
                 'UserInfo, the refresh grant, token exchange, the DPoP-bound ' +
                 'access token check, and the expiry every console screen ' +
                 'reports. Thirty seconds by default, capped at 300 — five ' +
                 'minutes is the allowance Kerberos uses (see krb5.clockSkew) ' +
                 'and a window wider than that stops being a tolerance and ' +
                 'starts being a lifetime extension nobody asked for. 0 means ' +
                 'no allowance at all, which is the strict reading and is ' +
                 'useful for showing a client exactly when a token dies. ' +
                 'It never changes what is PUT in a token — only what this ' +
                 'service believes when it reads one back.' },

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
                 '(127.0.0.1, [::1] or localhost) to match on any port — ' +
                 'RFC 8252 section 7.3, because a native application cannot ' +
                 'reserve one. Everything else about the URI must still match ' +
                 'exactly, and the host must be the same literal. ON by ' +
                 'default because RFC 9700 says an authorization server MUST ' +
                 'allow it; turning it OFF makes this server deliberately ' +
                 'non-compliant, which is how a native-app client is shown ' +
                 'what happens when it meets a server that got this wrong.' },

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
  { key: 'oauth2.frontchannelLogout', group: 'OAuth 2.0 / OIDC',
    label: 'OpenID Connect Front-Channel Logout',
    env: 'STS_OAUTH2_FRONTCHANNEL_LOGOUT', type: 'bool', dflt: true, runtime: true,
    description: 'Advertise and perform OpenID Connect Front-Channel Logout ' +
                 '1.0. With it on: the discovery document says ' +
                 'frontchannel_logout_supported, an ID Token issued on a ' +
                 'browser sign-on session carries the `sid` claim naming that ' +
                 'session, and every sign-out — /oauth2/logout, /logout, and ' +
                 'the console\'s — renders a hidden iframe per relying party ' +
                 'that registered a frontchannel_logout_uri, with iss and sid ' +
                 'on it where the client registered ' +
                 'frontchannel_logout_session_required. Off, none of the three ' +
                 'happens and the tokens are byte-for-byte what this service ' +
                 'issued before the feature existed. A client that registers ' +
                 'no logout URI is never notified either way, and /logout says ' +
                 'so on its row rather than leaving it out.' },

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
  { key: 'admin.authRequired', group: 'Admin console',
    label: 'Require a sign-in for /admin',
    env: 'ADMIN_AUTH_REQUIRED', type: 'bool', dflt: true, runtime: true,
    description: 'When on, every /admin page and every /admin form needs a ' +
                 'browser sign-on session from the authentication service at ' +
                 '/authn/login, and the person signed in needs a console ' +
                 'role: admin.readGroup to READ a page, admin.writeGroup to ' +
                 'POST a form. A browser with no session is sent to the ' +
                 'sign-in screen and returned to the page it asked for; a ' +
                 'caller asking for ?format=json, or posting JSON, is refused ' +
                 '401 or 403 rather than redirected, because a redirect to an ' +
                 'HTML login screen is not an answer a program can read. ' +
                 'Turning it OFF restores the behaviour this console had ' +
                 'before any of this existed — completely open — which stays ' +
                 'reachable on purpose, for the reason every refusal here is ' +
                 'switchable: a client is exercised by both answers. It does ' +
                 'NOT gate /admin-api, which is open either way and is ' +
                 'deliberately the way back in for somebody who has locked ' +
                 'themselves out; see admin.openWhenEmpty.' },

  { key: 'admin.readGroup', group: 'Admin console', label: 'Admin Read role',
    env: 'ADMIN_READ_GROUP', type: 'string', dflt: 'admin-read', runtime: true,
    description: 'The cn of the directory group whose members may READ the ' +
                 'console — every page, and every ?format=json view of one. ' +
                 'It is an ordinary group under ou=groups, so an ldapmodify, ' +
                 'a SCIM PATCH and the /admin/rbac screen are three doors ' +
                 'onto the same membership. The group need not exist: while ' +
                 'NEITHER role group has a member, admin.openWhenEmpty ' +
                 'decides what happens.' },

  { key: 'admin.writeGroup', group: 'Admin console', label: 'Admin Write role',
    env: 'ADMIN_WRITE_GROUP', type: 'string', dflt: 'admin-write',
    runtime: true,
    description: 'The cn of the directory group whose members may POST a ' +
                 'console form — revoke a token, add a claim, change a ' +
                 'setting, grant a role. WRITE IMPLIES READ: a member of this ' +
                 'group does not also need the read group, because a role ' +
                 'that could change a page it could not see would be a trap ' +
                 'rather than a permission.' },

  { key: 'admin.openWhenEmpty', group: 'Admin console',
    label: 'Open while no role has a member',
    env: 'ADMIN_OPEN_WHEN_EMPTY', type: 'bool', dflt: true, runtime: true,
    description: 'What happens while NEITHER role group has a single member: ' +
                 'ON, anybody who signs in holds both roles and the console ' +
                 'says so in a banner on every page; OFF, nobody can get in ' +
                 'at all. ON by default because the roster lives in memory ' +
                 'and dies with the process, so a service that started with ' +
                 'admin.authRequired on and this off would have a console no ' +
                 'browser could ever reach — there is no bootstrap admin and ' +
                 'no password anywhere in this service to be one. The moment ' +
                 'the FIRST grant is made the roster is enforced, so turning ' +
                 'this off is a thing to do after granting yourself a role ' +
                 'and not before. If it is off and you are locked out, ' +
                 '/admin-api is not gated: POST /admin-api/rbac/grant, or ' +
                 'POST /admin-api/config/set with admin.authRequired=false.' },

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
                 'source of truth. It is separate from ldap.maxEntries, which ' +
                 'caps the whole tree, so a runaway client_id generator ' +
                 'cannot fill the directory and stop people being created.' },

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
    description: 'Whether /federation answers at all. ON by default, and that ' +
                 'is safe in a way it would not be anywhere else here because ' +
                 'the endpoints do NOTHING without a relationship: a partner ' +
                 'is created disabled, and one that is enabled and ' +
                 'half-configured refuses rather than half-works. Turning ' +
                 'this OFF is the blunt instrument — every federation route ' +
                 'answers 404 and no partner appears on the sign-in screen, ' +
                 'without any relationship being changed, which is how to ' +
                 'take the feature away for one test run and put it back.' },

  { key: 'federation.max', group: 'Federation',
    label: 'Relationships remembered',
    env: 'STS_FEDERATION_MAX', type: 'int', dflt: 50, min: 1, max: 5000,
    runtime: true,
    description: 'How many entries may live under ou=federations. A directory ' +
                 'limit, so past it a new relationship is REFUSED rather than ' +
                 'an old one being evicted — the same rule applications.max ' +
                 'follows, and it matters more here: an evicted federation ' +
                 'relationship is a partner that silently stopped being ' +
                 'trusted. The default is small because these are CONFIGURED ' +
                 'by hand rather than created by traffic, so fifty is a large ' +
                 'number of them and a thousand would mean something has gone ' +
                 'wrong.' },

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
                 'look unfamiliar. Set it to something like `fed-` the moment ' +
                 'the question is whether federated identities share a ' +
                 'namespace with local ones, which is the question this ' +
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
                 'federation/federation_http.js argues it at length: a URL an ' +
                 'ADMINISTRATOR configured on a relationship is a different ' +
                 'thing from a URL an unauthenticated caller REGISTERED, ' +
                 'which is why oauthJwksUri on an application entry is still ' +
                 'never followed and wreqptr is still refused. Turn it OFF ' +
                 'for a deployment with no egress: SAML, SAML 1.1 and ' +
                 'WS-Federation need no back channel at all, and an OIDC ' +
                 'partner can still be used with fedResponseType=id_token and ' +
                 'its keys pasted into fedJwks.' },

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

  // --- SAML 2.0 Web Browser SSO --------------------------------------------
  // The profile arrived on 2026-08-24 and brought its own group, which is a
  // decision rather than a formality: `saml.issuer` above governs what SIGNED
  // an assertion and is shared by WS-Trust and WS-Federation, and every row
  // here governs how this service behaves as an IDENTITY PROVIDER in a browser
  // profile. Folding the two together would have made a change to one of these
  // look like a change to the assertions WS-Trust hands out, which it is not.
  { key: 'saml2.entityId', group: 'SAML 2.0', label: 'Identity provider entityID',
    env: 'STS_SAML2_ENTITY_ID', type: 'string', dflt: 'urn:sts-mock:idp',
    runtime: true,
    description: 'The entityID this identity provider publishes in its SAML ' +
                 '2.0 metadata, and the <saml:Issuer> of every Response and ' +
                 'Assertion the Web Browser SSO profile issues. It is NOT the ' +
                 'SAML issuer above: that one names whoever signed an ' +
                 'assertion and is shared with WS-Trust and WS-Federation, ' +
                 'and a service provider checks THIS one against the metadata ' +
                 'it was configured from. They are separate for the reason ' +
                 'wsfed.entityId is separate from it.' },

  { key: 'saml2.perApplicationEntityId', group: 'SAML 2.0',
    label: 'An entityID per service provider',
    env: 'STS_SAML2_PER_APPLICATION_ENTITY_ID', type: 'bool', dflt: true,
    runtime: true,
    description: 'ON by default, and it is what makes the metadata at ' +
                 '/saml2/metadata/{sp} UNIQUE PER APPLICATION: the identity ' +
                 'provider names itself <entityID>:{sp} in that document and ' +
                 'in everything it issues to that service provider, the way ' +
                 'Okta and Ping give each application its own identity ' +
                 'provider. OFF makes every document carry the entityID above ' +
                 'and differ only in its endpoint URLs, which is what a ' +
                 'service provider library that keys its trust store off the ' +
                 'entityID expects. Both are real deployments, which is why ' +
                 'it is a setting and not a decision.' },

  { key: 'saml2.assertionLifetimeMin', group: 'SAML 2.0 assertions',
    label: 'Assertion lifetime (minutes)',
    env: 'STS_SAML2_ASSERTION_LIFETIME_MIN', type: 'int', dflt: 60,
    runtime: true,
    description: 'How long an issued assertion is valid for: it becomes ' +
                 'Conditions/NotOnOrAfter and the bearer ' +
                 'SubjectConfirmationData/NotOnOrAfter alike. Set it to 1 to ' +
                 'watch a service provider refuse a stale assertion, which is ' +
                 'the check most of them get wrong.' },

  { key: 'saml2.signAssertion', group: 'SAML 2.0 assertions', label: 'Sign the assertion',
    env: 'STS_SAML2_SIGN_ASSERTION', type: 'bool', dflt: true, runtime: true,
    description: 'Sign the <saml:Assertion> itself. ON by default because a ' +
                 'service provider that verifies anything verifies this, and ' +
                 'because an assertion that travels on its own — out of an ' +
                 'ArtifactResponse, say — has nothing else carrying a ' +
                 'signature. Turning it OFF is a test case rather than a ' +
                 'mistake: a service provider that accepts an unsigned ' +
                 'assertion has a hole, and this is how to find out.' },

  { key: 'saml2.signResponse', group: 'SAML 2.0 assertions', label: 'Sign the response',
    env: 'STS_SAML2_SIGN_RESPONSE', type: 'bool', dflt: true, runtime: true,
    description: 'Sign the <samlp:Response> around the assertion as well, ' +
                 'which is what AD FS and Keycloak do by default. Both ' +
                 'signatures are ordinary: the response is signed AFTER the ' +
                 'assertion inside it, so the assertion\'s own signature is ' +
                 'part of what the response signature covers. On the HTTP ' +
                 'Redirect binding this ALSO controls the query-string ' +
                 'signature of section 3.4.4.1, which is the one a redirect ' +
                 'response is really verified by.' },

  { key: 'saml2.nameIdFormat', group: 'SAML 2.0 assertions', label: 'Default NameID format',
    env: 'STS_SAML2_NAMEID_FORMAT', type: 'string',
    dflt: 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
    runtime: true,
    description: 'The Format on the NameID when the AuthnRequest\'s ' +
                 'NameIDPolicy asks for none. A request that DOES name one is ' +
                 'answered with the one it named — any of them, including a ' +
                 'format this service has never heard of, because a service ' +
                 'provider being told its own format back is the behaviour ' +
                 'worth exercising and refusing with InvalidNameIDPolicy ' +
                 'would remove the test case.' },

  { key: 'saml2.artifactTtlS', group: 'SAML 2.0 assertions', label: 'Artifact lifetime (seconds)',
    env: 'STS_SAML2_ARTIFACT_TTL_S', type: 'int', dflt: 300, runtime: true,
    description: 'How long a SAML artifact can be resolved for at the ' +
                 'Artifact Resolution Service. An artifact is ALSO one-shot — ' +
                 'resolving it destroys it, which section 3.6.4.1 requires and ' +
                 'which no lifetime can express — so a second ArtifactResolve ' +
                 'for the same artifact is refused however long this is.' },

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
    env: 'STS_SAML2_ENCRYPT_ASSERTION', type: 'bool', dflt: false, runtime: true,
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
                 'a signed AuthnRequest, so a service provider that signs its ' +
                 'requests needs no configuration at all. The assertion is ' +
                 'SIGNED FIRST and then encrypted, which is the order every ' +
                 'service provider expects: the signature is inside the ' +
                 'ciphertext and is what survives decryption.' },

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
                 'and is BROKEN — Bleichenbacher\'s adaptive chosen-ciphertext ' +
                 'attack is against exactly this — and it is offered because ' +
                 'a great many deployed service providers accept nothing ' +
                 'else, which is a fact about the world that a client library ' +
                 'is entitled to be tested against. Nothing this service ' +
                 'encrypts is a real secret.' },

  { key: 'saml2.encryptLogoutNameId', group: 'SAML 2.0 assertions',
    label: 'Encrypt the NameID in a LogoutRequest',
    env: 'STS_SAML2_ENCRYPT_LOGOUT_NAMEID', type: 'bool', dflt: false, runtime: true,
    description: 'Send <saml:EncryptedID> instead of <saml:NameID> in the ' +
                 'LogoutRequest this identity provider sends a service ' +
                 'provider during Single Logout. It is the only thing in a ' +
                 'SAML 2.0 REQUEST that can be encrypted — there is no ' +
                 'EncryptedAuthnRequest in the specification — and it uses ' +
                 'the same certificate and the same two algorithms as the ' +
                 'assertion. Reading one is not gated by this or by anything: ' +
                 'an <saml:EncryptedID> arriving in a service provider\'s own ' +
                 'LogoutRequest is always decrypted, because refusing to ' +
                 'understand a message this service published an encryption ' +
                 'key for would make that key a lie.' },

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
                 'wants before their directory has ten thousand entries in it.' },

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
  { key: 'saml11.providerId', group: 'SAML 1.1', label: 'Identity provider providerID',
    env: 'STS_SAML11_PROVIDER_ID', type: 'string', dflt: 'urn:sts-mock:idp:saml11',
    runtime: true,
    description: 'What this identity provider calls itself in the SAML 1.1 ' +
                 'browser profiles: the `Issuer` ATTRIBUTE of every assertion ' +
                 'they issue, the `entityID` of the metadata document at ' +
                 '/saml11/metadata, and the string whose SHA-1 becomes the ' +
                 'SourceID inside every type 0x0001 artifact. SAML 1.1 calls ' +
                 'it a providerID and SAML 2.0 metadata calls the same thing ' +
                 'an entityID; they are one value and this row is it. It is ' +
                 'deliberately NOT saml2.entityId — a relying party that ' +
                 'trusts this service for 1.1 and not for 2.0 is the ordinary ' +
                 'case, and one value would make that unexpressible.' },

  { key: 'saml11.perApplicationProviderId', group: 'SAML 1.1',
    label: 'A providerID per relying party',
    env: 'STS_SAML11_PER_APPLICATION_PROVIDER_ID', type: 'bool', dflt: true,
    runtime: true,
    description: 'Give every relying party its own providerID — ' +
                 '`{providerID}:{slug}` — and its own endpoints under the same ' +
                 'path segment, which is what /saml11/metadata/{rp} publishes. ' +
                 'Turn it off for a relying party whose trust store is keyed ' +
                 'off the providerID and which is surprised to meet a new one ' +
                 'per application. THE ENDPOINTS STAY PER-APPLICATION either ' +
                 'way, because that is what makes the documents worth having ' +
                 'separately. It also changes every artifact this service ' +
                 'mints: the SourceID is a hash of the providerID, so turning ' +
                 'this off makes one SourceID where there were many.' },

  { key: 'saml11.assertionLifetimeMin', group: 'SAML 1.1 assertions',
    label: 'Assertion lifetime (minutes)',
    env: 'STS_SAML11_ASSERTION_LIFETIME_MIN', type: 'int', dflt: 60, runtime: true,
    description: 'How long the browser profiles\' assertions are valid for, in ' +
                 'the NotBefore and NotOnOrAfter of <saml:Conditions>. It is ' +
                 'separate from the WS-Federation lifetime for the same reason ' +
                 'the SAML 2.0 one is: a browser profile assertion is consumed ' +
                 'within seconds of being issued and a short lifetime here is ' +
                 'a realistic test, where the same value would make a ' +
                 'WS-Federation session expire while somebody was reading it.' },

  { key: 'saml11.signAssertion', group: 'SAML 1.1 assertions', label: 'Sign the assertion',
    env: 'STS_SAML11_SIGN_ASSERTION', type: 'bool', dflt: true, runtime: true,
    description: 'Sign the <saml:Assertion> itself, with ds:Signature as its ' +
                 'LAST child and the reference naming AssertionID — which is ' +
                 'where the 1.1 schema puts it and is not where SAML 2.0 does. ' +
                 'ON by default because the Browser/POST profile REQUIRES a ' +
                 'signed assertion (saml-profile-1.1 section 4.2.1.4): the ' +
                 'assertion passes through the browser, so nothing else ' +
                 'authenticates it. Turning it off is a test case rather than ' +
                 'a mistake — a relying party that accepts it anyway has a ' +
                 'hole in it, and this is how somebody finds that out.' },

  { key: 'saml11.signResponse', group: 'SAML 1.1 assertions', label: 'Sign the response',
    env: 'STS_SAML11_SIGN_RESPONSE', type: 'bool', dflt: true, runtime: true,
    description: 'Sign the <samlp:Response> around the assertion as well, with ' +
                 'the reference naming ResponseID. Real identity providers ' +
                 'differ here and both are worth exercising, which is why it ' +
                 'is a setting: the profile requires the RESPONSE to be signed ' +
                 'in Browser/POST and says nothing about it for the assertion ' +
                 'pulled back over the artifact channel, where the SOAP ' +
                 'exchange is what a relying party is trusting.' },

  { key: 'saml11.nameIdFormat', group: 'SAML 1.1 assertions', label: 'Default NameIdentifier format',
    env: 'STS_SAML11_NAMEID_FORMAT', type: 'string',
    dflt: 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
    runtime: true,
    description: 'The Format on the <saml:NameIdentifier> when the request ' +
                 'asks for none — which in SAML 1.1 is ALWAYS, because the ' +
                 'profile has no request message to carry a NameIDPolicy in. ' +
                 'That is the difference from saml2.nameIdFormat, which is a ' +
                 'default a request routinely overrides: this one is the ' +
                 'answer unless the non-spec `format` parameter overrides it.' },

  { key: 'saml11.defaultProfile', group: 'SAML 1.1', label: 'Default browser profile',
    env: 'STS_SAML11_DEFAULT_PROFILE', type: 'enum', enumValues: ['post', 'artifact'],
    dflt: 'post', runtime: true,
    description: 'Which profile the inter-site transfer service uses when the ' +
                 'request does not say: Browser/POST (section 4.2), where the ' +
                 'assertion travels through the browser in a form POST, or ' +
                 'Browser/Artifact (section 4.1), where a reference travels ' +
                 'through the browser and the relying party fetches the ' +
                 'assertion over SOAP. POST is the default because it needs no ' +
                 'server behind the relying party\'s assertion consumer, so it ' +
                 'is the one that works when somebody points this at a URL and ' +
                 'watches. A request naming `profile` or carrying `SAMLart` ' +
                 'overrides it.' },

  { key: 'saml11.artifactTtlS', group: 'SAML 1.1 assertions', label: 'Artifact lifetime (seconds)',
    env: 'STS_SAML11_ARTIFACT_TTL_S', type: 'int', dflt: 300, runtime: true,
    description: 'How long an artifact can be resolved for at the SAML ' +
                 'responder before it is swept. It is an UPPER bound and not ' +
                 'the rule that matters: an artifact is resolvable exactly ' +
                 'ONCE (saml-bindings-1.1 section 3.2.3), so resolving one ' +
                 'destroys it whatever this says, and no lifetime setting can ' +
                 'express that. Five minutes is what the profile recommends ' +
                 'and is generous for an exchange that takes milliseconds.' },

  { key: 'saml11.autocreateApplications', group: 'SAML 1.1',
    label: 'Register relying parties on sight',
    env: 'STS_SAML11_AUTOCREATE_APPLICATIONS', type: 'bool', dflt: true,
    runtime: true,
    description: 'Create an application entry under ou=applications the first ' +
                 'time a relying party is named — by a TARGET arriving, by a ' +
                 'metadata document being fetched, or by an artifact being ' +
                 'resolved. Off means the browser profiles still work and ' +
                 '/admin/saml11 stays empty, which is what somebody driving a ' +
                 'load test wants and nobody else does.' },

  // --- WS-Trust ------------------------------------------------------------
  { key: 'wstrust.issuer', group: 'WS-Trust', label: 'Token issuer',
    env: 'STS_WSTRUST_ISSUER', legacyEnv: 'STS_ISSUER', type: 'string',
    dflt: 'urn:wstrust:mock:sts', runtime: true,
    description: 'The `iss` of the JWT this STS returns in a ' +
                 'RequestSecurityTokenResponse, and the issuer named on GET ' +
                 '/sts. A SAML token requested through WS-Trust is built by ' +
                 'the SAML modules and carries saml.issuer instead, which the ' +
                 'console draws on its two SAML pages.' },

  // --- WS-Federation -------------------------------------------------------
  // --- WS-Federation assertions --------------------------------------------
  // A GROUP OF ONE, and it earns that the way the two SAML assertion groups do:
  // it is a DEFAULT an application may overrule, and the page it is drawn on is
  // the page that says so. `wsfed.entityId` beside it is this service's own name
  // and no application can have an opinion about it, which is the line between
  // the two groups.
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
                 'RequestSecurityTokenResponse around it. It is separate from ' +
                 'saml11.assertionLifetimeMin for the reason that setting\'s ' +
                 'own description gives: a browser-profile assertion is ' +
                 'consumed within seconds and a short lifetime there is a ' +
                 'realistic test, where the same value would expire a ' +
                 'WS-Federation session while somebody was reading the page it ' +
                 'signed them into. An application may overrule it with ' +
                 'wsfedAssertionLifetimeMin on its entry.' },

  { key: 'wsfed.entityId', group: 'WS-Federation', label: 'Entity ID',
    env: 'STS_WSFED_ENTITY_ID', legacyEnv: 'STS_ISSUER', type: 'string',
    dflt: 'urn:wstrust:mock:sts', runtime: true,
    description: 'The entityID in the federation metadata at ' +
                 '/FederationMetadata/2007-06/FederationMetadata.xml. Split ' +
                 'from the SAML issuer because the two are different things ' +
                 'that happened to share a value: this names the IdP, that ' +
                 'names whoever signed an assertion.' },

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

  { key: 'tls.hostnames', group: 'TLS', label: 'Certificate hostnames',
    env: 'STS_TLS_HOSTNAMES', type: 'csv',
    dflt: 'localhost,sts,sts-mock,sts.example.com', runtime: false,
    restartReason: 'the server certificate is issued at startup for these names',
    description: 'The subjectAltName DNS entries on the certificate both TLS ' +
                 'listeners present. A caller reaches this stack as localhost ' +
                 'from a host run and as sts from a compose network, so a ' +
                 'certificate naming only one of them fails hostname ' +
                 'verification for a reason that is about this setting rather ' +
                 'than about anything being debugged.' },

  { key: 'tls.ips', group: 'TLS', label: 'Certificate IP addresses',
    env: 'STS_TLS_IPS', type: 'csv', dflt: '127.0.0.1', runtime: false,
    restartReason: 'the server certificate is issued at startup for these addresses',
    description: 'The subjectAltName IP entries on the same certificate.' },

  { key: 'tls.certificateAlgorithms', group: 'TLS',
    label: 'Server certificate algorithms', env: 'STS_TLS_CERT_ALGS',
    type: 'csv', dflt: 'rsa', runtime: false,
    restartReason: 'the certificates are issued when the listeners are bound',
    description: 'Which server certificates the two TLS listeners present: ' +
                 '"rsa" (the default), and any of ml-dsa-44, ml-dsa-65 and ' +
                 'ml-dsa-87. MORE THAN ONE IS THE INTERESTING SETTING — ' +
                 'OpenSSL 3.5 serves whichever certificate matches the ' +
                 'signature algorithms the CLIENT offered, so "rsa,ml-dsa-65" ' +
                 'answers an ordinary client with RSA and a post-quantum one ' +
                 'with ML-DSA over the same port, which is exactly how a real ' +
                 'migration is run. It is not the default because an ML-DSA ' +
                 'certificate is refused by everything older than OpenSSL ' +
                 '3.5, including the openssl binary in these images.' },

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

  // --- OID4VCI -------------------------------------------------------------
  { key: 'oid4vci.walletUrl', group: 'OID4VCI', label: 'Wallet URL',
    env: 'OID4VCI_WALLET_URL', type: 'string', dflt: 'http://localhost:3000',
    runtime: true,
    description: 'Where the wallet lives, as a URL the BROWSER can use. The ' +
                 'Credential Offer pages send the End-User here, so it is the ' +
                 'debugger\'s own address rather than anything this service ' +
                 'serves.' },

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
                 'metadata: how many proofs one credential request may carry, ' +
                 'and therefore how many credentials come back from it.' },

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
    description: 'When on, a credential request that is not a JWE is refused. ' +
                 'The negative worth having: a wallet cannot prove it ' +
                 'encrypts by encrypting when the issuer accepts plaintext ' +
                 'too.' },

  // ---------------------------------------------------------------------
  // THE TWO DID FLAGS, which were the last two environment variables in this
  // service with no row here.
  //
  // They were read in `oid4vc/vc_did.js` as `didFlag('OID4VCI_SD_JWT_ISSUER_DID')`
  // — a module-level const, compared against the literal string 'true' — which
  // is the shape every setting in this table used to have. Two consequences,
  // and the second is why they moved rather than being left alone: they were
  // undocumentable as appconfig entries because they were not appconfig
  // entries, and `OID4VCI_LDP_VC_ISSUER_DID=1` did nothing at all while
  // `=true` worked, because that comparison was not the `bool` type's.
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
    description: 'Switch the PLAIN dc+sd-jwt credential configuration over to ' +
                 'naming its issuer by did:web instead of by https URL — what ' +
                 'a deployment that had gone to DIDs throughout would look ' +
                 'like. OFF, because draft-ietf-oauth-sd-jwt-vc defines no ' +
                 'DID-based issuer signature mechanism, so this is an ' +
                 'extension and the spec\'s own route ' +
                 '(/.well-known/jwt-vc-issuer) is what the plain ' +
                 'configuration must go on exercising. The ' +
                 'IdentityCredentialDid configuration always names the issuer ' +
                 'by DID whatever this is, so both routes can be compared in ' +
                 'one issuer.' },

  { key: 'oid4vci.ldpVcIssuerDid', group: 'OID4VCI',
    label: 'Name the ldp_vc issuer by DID',
    env: 'OID4VCI_LDP_VC_ISSUER_DID', type: 'bool', dflt: false,
    runtime: false,
    restartReason: 'vc_did.js reads it once at require time, and the issuer ' +
                   'metadata is built from what it read',
    description: 'The same for the PLAIN ldp_vc configuration. VC Data Model ' +
                 '2.0 and Data Integrity are DID-native and naming the issuer ' +
                 'by DID is ordinary there, so this one is off for a ' +
                 'narrower reason: ldp_vc\'s verificationMethod is an https ' +
                 'URL that existing tests dereference, and switching it to a ' +
                 'DID URL breaks them silently.' },

  // --- OID4VP --------------------------------------------------------------
  { key: 'oid4vp.clientId', group: 'OID4VP', label: 'Verifier client ID',
    env: 'OID4VP_CLIENT_ID', type: 'string', dflt: 'sts-mock-verifier',
    runtime: true,
    description: 'The client_id the mock Verifier presents in its ' +
                 'Authorization Request, and the `aud` the Key Binding JWT ' +
                 'must name.' },

  { key: 'oid4vp.walletUrl', group: 'OID4VP', label: 'Wallet URL',
    env: 'OID4VP_WALLET_URL', type: 'string',
    dflt: function () { return value('oid4vci.walletUrl'); }, runtime: true,
    derived: true,
    description: 'Where the Verifier sends the holder to present. Falls back ' +
                 'to the OID4VCI wallet URL, since it is the same wallet in ' +
                 'every arrangement this service is used in.' },

  { key: 'oid4vp.kbMaxAgeS', group: 'OID4VP', label: 'Key Binding max age (s)',
    env: 'OID4VP_KB_MAX_AGE_S', type: 'int', dflt: 600, runtime: true,
    description: 'How old a Key Binding JWT\'s `iat` may be before the ' +
                 'Verifier rejects the presentation as a replay.' },

  { key: 'oid4vp.claims', group: 'OID4VP', label: 'Requested claims',
    env: 'OID4VP_CLAIMS', type: 'csv', dflt: 'given_name,family_name',
    runtime: true,
    description: 'The mock Verifier\'s STARTING request, and — this is the ' +
                 'part worth knowing — the target its Reset returns to. It is ' +
                 'not the live list: /admin/vc-verifier-config owns that, and ' +
                 'copies this at startup. So changing it here changes what ' +
                 'the next Reset produces, and the request on the wire only ' +
                 'once that Reset is pressed (or POST ' +
                 '/admin-api/verifier-request/reset is called). It is a ' +
                 'reset target rather than a live value on purpose: a ' +
                 'deployment that configured this should get ITS list back ' +
                 'from Reset and not the catalogue\'s defaults. A claim this ' +
                 'issuer does not mint is a legitimate thing to ask for and ' +
                 'is how the "not satisfied" path is reached.' },

  // --- Kerberos ------------------------------------------------------------
  { key: 'krb5.realm', group: 'Kerberos', label: 'Realm',
    env: 'KRB5_REALM', type: 'string', dflt: 'EXAMPLE.COM', runtime: false,
    restartReason: 'the principal database and every long-term key in it are ' +
                   'derived from the realm at startup',
    description: 'The realm this KDC serves. Its lower-cased form is the ' +
                 'domain, which is where the default service domains and the ' +
                 'PAC\'s domain name come from.' },

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
    restartReason: 'the account and its long-term keys are created at startup',
    description: 'The SPN that test service holds, in the usual ' +
                 'service/hostname form.' },

  { key: 'krb5.clockSkew', group: 'Kerberos', label: 'Clock skew (s)',
    env: 'KRB5_CLOCK_SKEW', type: 'int', dflt: 300, runtime: true,
    description: 'How far apart the KDC will let its clock and a client\'s ' +
                 'be. RFC 4120 suggests five minutes and this is where ' +
                 'KRB_AP_ERR_SKEW comes from.' },

  { key: 'krb5.clockOffset', group: 'Kerberos', label: 'Clock offset (s)',
    env: 'KRB5_CLOCK_OFFSET', type: 'int', dflt: 0, runtime: true,
    description: 'Moves this KDC\'s clock deliberately, so a skew failure can ' +
                 'be produced on purpose rather than by changing the ' +
                 'machine\'s time.' },

  { key: 'krb5.userPassword', group: 'Kerberos', label: 'User password',
    env: 'KRB5_USER_PASSWORD', type: 'string', dflt: 'password!',
    runtime: false,
    restartReason: 'every user\'s long-term keys are derived from it at startup',
    description: 'The password every user account here has. It is PUBLISHED ' +
                 'by GET /krb5/principals on purpose: a debugger whose ' +
                 'accounts are unusable without reading the source is worse ' +
                 'than one that says what they are.' },

  { key: 'krb5.unknownUsers', group: 'Kerberos', label: 'Names that stay unknown',
    env: 'KRB5_UNKNOWN_USERS', type: 'csv', dflt: 'nosuchuser,nobody',
    runtime: true,
    description: 'Usernames this KDC refuses to create on demand, so ' +
                 'KDC_ERR_C_PRINCIPAL_UNKNOWN stays reachable. It is one of ' +
                 'the errors most worth producing on purpose, because a ' +
                 'client that renders it as "wrong password" sends somebody ' +
                 'off to reset a password that was never the problem.' },

  { key: 'krb5.serviceDomains', group: 'Kerberos', label: 'Auto-created service domains',
    env: 'KRB5_SERVICE_DOMAINS', type: 'csv', derived: true,
    dflt: function () {
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
    restartReason: 'those accounts\' long-term keys are derived from it at startup',
    description: 'One password for every service created on demand, and it ' +
                 'is published for the same reason the user password is: it ' +
                 'is what lets a reader decrypt a service ticket this mock ' +
                 'issued and read the PAC inside it. The CONFIGURED service ' +
                 'accounts keep their own separate passwords.' },

  { key: 'krb5.krbtgtPassword', group: 'Kerberos', label: 'krbtgt password',
    env: 'KRB5_KRBTGT_PASSWORD', type: 'string', dflt: 'krbtgt-mock-password',
    runtime: false,
    restartReason: 'the krbtgt keys are derived from it at startup',
    description: 'The key that seals every Ticket-Granting Ticket this realm ' +
                 'issues.' },

  { key: 'krb5.domainSid', group: 'Kerberos', label: 'Domain SID',
    env: 'KRB5_DOMAIN_SID', type: 'string',
    dflt: 'S-1-5-21-1004336348-1177238915-682003330', runtime: false,
    restartReason: 'every principal\'s PAC identity is built at startup',
    description: 'The domain SID every account\'s PAC is built under. A ' +
                 'Kerberos ticket says who you are; a Windows service ' +
                 'authorizes on the SIDs in the PAC.' },

  { key: 'krb5.trustedRealm', group: 'Kerberos', label: 'Trusted realm',
    env: 'KRB5_TRUSTED_REALM', type: 'string', dflt: 'PARTNER.COM',
    runtime: false,
    restartReason: 'the second realm and the trust between them are built at startup',
    description: 'The second realm, for cross-realm referrals. A trust is not ' +
                 'a flag: it is a shared key held by one principal in each ' +
                 'realm.' },

  { key: 'krb5.trustPassword', group: 'Kerberos', label: 'Trust password',
    env: 'KRB5_TRUST_PASSWORD', type: 'string',
    dflt: 'inter-realm-trust-password', runtime: false,
    restartReason: 'the inter-realm key is derived from it at startup',
    description: 'The shared secret both realms hold for the cross-realm ' +
                 'trust.' },

  { key: 'krb5.trustedDomainSid', group: 'Kerberos', label: 'Trusted domain SID',
    env: 'KRB5_TRUSTED_DOMAIN_SID', type: 'string',
    dflt: 'S-1-5-21-2035427030-2118130302-1178042555', runtime: false,
    restartReason: 'the trusted realm\'s principals are built at startup',
    description: 'The other realm\'s domain SID. It differs from this one on ' +
                 'purpose: SID filtering across a trust is about whose domain ' +
                 'a SID belongs to.' },

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

  { key: 'krb5.spnegoLoginButton', group: 'Kerberos',
    label: 'Offer Kerberos at the sign-in screen',
    env: 'KRB5_SPNEGO_LOGIN_BUTTON', type: 'bool', dflt: true,
    runtime: true,
    description: 'Show a "Sign in with Kerberos" button on /authn/login, so a ' +
                 'ticket can satisfy ANY flow already in progress — an OAuth ' +
                 '2.0 authorization request, a WS-Federation sign-in, a SAML ' +
                 'AuthnRequest, the admin console. That is the same reason ' +
                 'federation.loginButtons exists and it needs no registration ' +
                 'at all here: whether a person can use a ticket is a fact ' +
                 'about their machine and not about the relying party. The ' +
                 'button is withheld from a request that demanded two ' +
                 'factors, and says so, because a ticket claims whatever its ' +
                 'own flags claim.' },

  { key: 'krb5.s2kparams', group: 'Kerberos', label: 'Send s2kparams',
    env: 'KRB5_S2KPARAMS', type: 'enum', enumValues: ['omit', 'send'],
    dflt: 'omit', runtime: true,
    description: 'Whether PA-ETYPE-INFO2 carries s2kparams. Windows Server ' +
                 'omits it and this mock sent it, which is the one difference ' +
                 'the captured real-DC exchange found; omit is therefore the ' +
                 'default and send is kept so a client that reads it can be ' +
                 'exercised.' },

  // --- LDAP ----------------------------------------------------------------
  { key: 'ldap.port', group: 'LDAP', label: 'LDAP port',
    env: 'LDAP_PORT', type: 'port', dflt: 389, runtime: false,
    restartReason: 'the socket is bound when the process starts',
    description: 'The plain LDAP listener. 389 is privileged, so a host run ' +
                 'that is not root fails to bind it — recorded rather than ' +
                 'thrown, and reported by GET /ldap.' },

  { key: 'ldap.tlsPort', group: 'LDAP', label: 'LDAPS port',
    env: 'LDAPS_PORT', type: 'port', dflt: 636, runtime: false,
    restartReason: 'the socket is bound when the process starts',
    description: 'The LDAPS listener, which serves the certificate the TLS ' +
                 'module generated. It binds independently of 389, so "389 is ' +
                 'up and 636 is not" is an ordinary outcome and each reports ' +
                 'itself separately.' },

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
    description: 'When on, an entry appears at uid=<name>,ou=users,<base> the ' +
                 'first time anybody authenticates to this service through ' +
                 'ANY protocol. On by default: a directory that fills up as ' +
                 'you use the other protocols is the thing this one is here ' +
                 'to show. An LDAP bind never seeds an entry either way — the ' +
                 'identity a bind presents is a DN, which already names an ' +
                 'object here.' },

  { key: 'ldap.maxEntries', group: 'LDAP', label: 'Maximum entries',
    env: 'LDAP_MAX_ENTRIES', type: 'int', dflt: 2000, runtime: true,
    description: 'How large the directory may grow. A ceiling rather than a ' +
                 'target: entries appear for anybody who authenticates ' +
                 'through any protocol here.' },

  { key: 'ldap.sizeLimit', group: 'LDAP', label: 'Search size limit',
    env: 'LDAP_SIZE_LIMIT', type: 'int', dflt: 500, runtime: true,
    description: 'The server-side size limit for a search, which is what ' +
                 'produces LDAP_SIZE_LIMIT_EXCEEDED.' },

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
                 'here. Turning it off leaves the routes REGISTERED and makes ' +
                 'them answer 501 rather than 404 — the feature is off, the ' +
                 'URL is not wrong, and those are different sentences to a ' +
                 'client. Nothing on these endpoints checks a credential; do ' +
                 'not put this port on a public address.' },

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
                 'published as bulk.maxOperations. A request carrying more is ' +
                 'refused with 413 and the payloadTooLarge scimType, which is ' +
                 'a reachable negative worth having.' },

  { key: 'scim.bulkMaxPayloadSize', group: 'SCIM', label: 'Bulk payload limit',
    env: 'SCIM_BULK_MAX_PAYLOAD_SIZE', type: 'int', dflt: 1048576, runtime: true,
    description: 'The largest BulkRequest body in bytes, published as ' +
                 'bulk.maxPayloadSize and CHECKED against that number rather ' +
                 'than against the express body parser\'s service-wide 5 MB. A ' +
                 'client reads a published limit as a promise, so a request ' +
                 'refused at a different size than the document names would be ' +
                 'the drift this arrangement exists to prevent.' },

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
  { key: 'scim.authRequired', group: 'SCIM', label: 'Require authentication',
    env: 'SCIM_AUTH_REQUIRED', type: 'bool', dflt: true, runtime: true,
    description: 'When on, every SCIM endpoint refuses a request that carries ' +
                 'no credential with 401 and a WWW-Authenticate header per ' +
                 'offered scheme (RFC 7644 section 2 makes that header a ' +
                 'SHALL). Turning it OFF restores the behaviour these ' +
                 'endpoints had before authentication existed — unauthenticated ' +
                 'provisioning — which stays reachable on purpose, because a ' +
                 'client is exercised by both answers and because a mock that ' +
                 'could not reproduce the permissive case would have lost ' +
                 'something. A credential that IS presented is still checked ' +
                 'either way: a broken token is a 401 whether or not one was ' +
                 'required, or a client testing its expired-token path would ' +
                 'get a 200.' },

  { key: 'scim.authDiscovery', group: 'SCIM', label: 'Authenticate discovery too',
    env: 'SCIM_AUTH_DISCOVERY', type: 'bool', dflt: false, runtime: true,
    description: 'Whether /ServiceProviderConfig, /ResourceTypes and /Schemas ' +
                 'need a credential as well. OFF by default, which is the ' +
                 'bootstrapping argument /tls/trust already makes: the ' +
                 'ServiceProviderConfig is where a client READS which ' +
                 'authentication schemes exist, so requiring a credential to ' +
                 'fetch it means a client must already know the answer to the ' +
                 'question it is asking. RFC 7644 section 4 says nothing ' +
                 'either way, so both are conforming and both are worth being ' +
                 'able to try.' },

  { key: 'scim.authRealm', group: 'SCIM', label: 'Authentication realm',
    env: 'SCIM_AUTH_REALM', type: 'string', dflt: 'SCIM', runtime: true,
    description: 'The protection space named in every WWW-Authenticate ' +
                 'challenge, and — for HTTP Digest and HOBA — a value that is ' +
                 'hashed or signed OVER, so changing it invalidates every ' +
                 'credential computed against the old one. Quotes and ' +
                 'non-ASCII are stripped before it reaches a header, because ' +
                 'node throws on the second and the first would close the ' +
                 'quoted string early.' },

  { key: 'scim.scopeRead', group: 'SCIM', label: 'OAuth scope to read',
    env: 'SCIM_SCOPE_READ', type: 'string', dflt: 'scim:read', runtime: true,
    description: 'The OAuth 2.0 scope an access token must carry to read at ' +
                 '/scim/v2 — the first scope requirement anywhere in this ' +
                 'service. It is published in scopes_supported in both ' +
                 'discovery documents, so a client can find the name it needs ' +
                 'rather than being told it out of band. Any grant will get ' +
                 'it: this authorization server grants what it is asked, so ' +
                 'what the requirement exercises is the CLIENT\'s handling of ' +
                 'a scope rather than this service\'s willingness to withhold ' +
                 'one.' },

  { key: 'scim.scopeWrite', group: 'SCIM', label: 'OAuth scope to write',
    env: 'SCIM_SCOPE_WRITE', type: 'string', dflt: 'scim:write', runtime: true,
    description: 'The scope needed to create, replace, patch, delete or bulk. ' +
                 'It does NOT imply the read scope and the read scope does not ' +
                 'imply it, deliberately: a read-only provisioning credential ' +
                 'is a thing a client has to handle and a server that treated ' +
                 'one scope as both could not produce it.' },

  { key: 'scim.authBearer', group: 'SCIM', label: 'Offer OAuth 2.0 tokens',
    env: 'SCIM_AUTH_BEARER', type: 'bool', dflt: true, runtime: true,
    description: 'Whether an access token is accepted, as Bearer (RFC 6750) ' +
                 'or — when it is bound — as DPoP (RFC 9449). Both are ' +
                 'checked by the same function /oauth2/userinfo and the three ' +
                 'OID4VCI credential endpoints use, so an RFC 8705 ' +
                 'certificate-bound token and the DPoP nonce handshake work ' +
                 'here exactly as they do there. This is the only scheme with ' +
                 'scopes behind it; the others authenticate and may then do ' +
                 'everything.' },

  { key: 'scim.authBasic', group: 'SCIM', label: 'Offer HTTP Basic',
    env: 'SCIM_AUTH_BASIC', type: 'bool', dflt: true, runtime: true,
    description: 'Any username with any password except the reserved ' +
                 '"invalid", which is refused so that a 401 stays reachable. ' +
                 'RFC 7644 section 2 DISCOURAGES this scheme in those words, ' +
                 'and it is offered anyway because it is what a provisioning ' +
                 'client most often meets. No password is checked, so what it ' +
                 'authenticates is a name — and that name is recorded as an ' +
                 'authentication, so it appears on /admin/users and gains a ' +
                 'directory entry like any other identity here.' },

  { key: 'scim.authDigest', group: 'SCIM', label: 'Offer HTTP Digest',
    env: 'SCIM_AUTH_DIGEST', type: 'bool', dflt: true, runtime: true,
    description: 'RFC 7616, with SHA-256, SHA-512-256 and MD5 offered in that ' +
                 'order and the -sess variants accepted. This is the one ' +
                 'scheme here where the password really is checked, because ' +
                 'the response IS a hash over it — so it does what Kerberos ' +
                 'does for the same reason: any username, one shared password. ' +
                 'It makes three otherwise unreachable negatives available: a ' +
                 'wrong password, a stale nonce, and a replayed nonce count.' },

  { key: 'scim.digestPassword', group: 'SCIM', label: 'The shared Digest password',
    env: 'SCIM_DIGEST_PASSWORD', type: 'string', dflt: 'password!', runtime: true,
    description: 'The password every username shares for HTTP Digest — the ' +
                 'same value KRB5_USER_PASSWORD defaults to, so that there is ' +
                 'one fact to remember rather than two. It cannot be "anything ' +
                 'goes" the way a bind or a Basic credential can: a digest ' +
                 'response is a hash over the password, so a server with no ' +
                 'password would not be performing the exchange at all and a ' +
                 'client\'s digest code would go unexercised.' },

  { key: 'scim.digestNonceSeconds', group: 'SCIM', label: 'Digest nonce lifetime',
    env: 'SCIM_DIGEST_NONCE_SECONDS', type: 'int', dflt: 300, runtime: true,
    description: 'How long a Digest nonce stays usable. After it a credential ' +
                 'is refused with stale=true, which RFC 7616 section 3.3 says ' +
                 'a client should retry with the same credentials rather than ' +
                 'prompting a person — a path most hand-written clients have ' +
                 'never run. Lower it to a few seconds to make it happen on ' +
                 'demand.' },

  { key: 'scim.authHoba', group: 'SCIM', label: 'Offer HOBA',
    env: 'SCIM_AUTH_HOBA', type: 'bool', dflt: true, runtime: true,
    description: 'HTTP Origin-Bound Authentication (RFC 7486), the ' +
                 'signature-based scheme RFC 7644 section 2 names and the only ' +
                 'one of the six with no shared secret in it. Also turns ' +
                 'POST /.well-known/hoba/register on or off. The signature is ' +
                 'REALLY verified — RSA with SHA-256, algorithm 0 — for the ' +
                 'reason the Digest password really is checked; what is ' +
                 'permissive is that anybody may register any key for any ' +
                 'name.' },

  { key: 'scim.hobaMaxAgeSeconds', group: 'SCIM', label: 'HOBA challenge lifetime',
    env: 'SCIM_HOBA_MAX_AGE_SECONDS', type: 'int', dflt: 600, runtime: true,
    description: 'The max-age published in the HOBA challenge and enforced on ' +
                 'the signature. RFC 7486 lets a client reuse a challenge ' +
                 'until it expires, so a repeat is NOT a replay here — what is ' +
                 'refused is a repeated (key id, challenge, nonce) triple, ' +
                 'which is a copied credential.' },

  { key: 'scim.authCookie', group: 'SCIM', label: 'Offer the session cookie',
    env: 'SCIM_AUTH_COOKIE', type: 'bool', dflt: true, runtime: true,
    description: 'Whether the browser sign-on session this service already ' +
                 'has — the one /authn/login creates and WS-Federation shares ' +
                 '— authenticates a SCIM request. RFC 7644 section 2 names ' +
                 'cookies explicitly. There is no challenge for it, because a ' +
                 'server cannot ask for a cookie in WWW-Authenticate, and it ' +
                 'is consulted only when there is no Authorization header: a ' +
                 'request that presents a credential is judged on that ' +
                 'credential rather than quietly falling back.' },

  { key: 'scim.authClientCert', group: 'SCIM', label: 'Offer TLS client certificates',
    env: 'SCIM_AUTH_CLIENT_CERT', type: 'bool', dflt: true, runtime: true,
    description: 'Mutual TLS, the first scheme RFC 7644 section 2 names. It ' +
                 'applies only where the request arrived over TLS with a ' +
                 'certificate that VERIFIED against an anchor POSTed to ' +
                 '/tls/trust, so on the main port only when global.https is on. ' +
                 'This is the first place in this service where a client ' +
                 'certificate is a CREDENTIAL rather than an observation — on ' +
                 'the /tls listeners a verified certificate is reported and ' +
                 'grants nothing; here it authenticates somebody who may then ' +
                 'write to the directory.' },


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
    description: 'Which event types this transmitter will agree to deliver, ' +
                 'published on every stream as events_supported and ' +
                 'intersected with a receiver\'s events_requested to ' +
                 'produce events_delivered. SSF 1.0 itself defines only the ' +
                 'two above — it is a PIPE, and the vocabularies are CAEP ' +
                 'and RISC. Narrowing this list is how a receiver\'s "you ' +
                 'did not agree to the type I asked for" path is reached; ' +
                 'an entry naming a type this service does not implement is ' +
                 'dropped with a warning rather than advertised.' },

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

  { key: 'ssf.authRequired', group: 'SSF', label: 'Require authentication',
    env: 'STS_SSF_AUTH_REQUIRED', type: 'bool', dflt: true, runtime: true,
    description: 'When on, the stream management, status, subject, ' +
                 'verification and poll endpoints refuse a request carrying ' +
                 'no credential with 401 and a WWW-Authenticate header. SSF ' +
                 '1.0 section 8 says these endpoints MUST be protected and ' +
                 'publishes what they accept in authorization_schemes. It ' +
                 'is the same turnstile SCIM is: anybody can get a token ' +
                 'with the ssf scope from this service\'s own token ' +
                 'endpoint with any grant, and any username with any ' +
                 'password but "invalid" passes Basic. What it buys is that ' +
                 'a client\'s 401 path can be run at all. The transmitter ' +
                 'metadata stays OPEN either way — a receiver has to be ' +
                 'able to read what the endpoints are before it can ' +
                 'authenticate to one.' },

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
                 'carries a claim naming the directory groups the person is a ' +
                 'member of. ON by default and yet it changes nothing for most ' +
                 'callers: the claim is OMITTED ENTIRELY for anybody who is in ' +
                 'no group, which on a fresh start is everybody except the ' +
                 'seeded people, so a client that never touched ou=groups sees ' +
                 'the tokens it saw before. Turning it off is how a client\'s ' +
                 '"no groups claim" path stays reachable. The membership is ' +
                 'read from the live directory per token, so an ldapmodify ' +
                 'changes the next one.' },

  { key: 'groups.claimName', group: 'Group claim', label: 'Claim name',
    env: 'STS_GROUPS_CLAIM_NAME', type: 'string', dflt: 'groups', runtime: true,
    description: 'What the claim is called: the JWT member name, the SAML 2.0 ' +
                 'Attribute Name and the SAML 1.1 AttributeName. `groups` is ' +
                 'the conventional spelling and what most relying parties look ' +
                 'for, but `roles` and a URI are both common and both worth ' +
                 'being able to produce. A name this service sets itself is ' +
                 'REFUSED at issuance time rather than allowed to collide — ' +
                 'see the reserved list on /admin/claims, which is the same ' +
                 'rule a typed custom claim follows.' },

  { key: 'groups.claimValue', group: 'Group claim', label: 'What names a group',
    env: 'STS_GROUPS_CLAIM_VALUE', type: 'enum', enumValues: ['cn', 'dn'],
    dflt: 'cn', runtime: true,
    description: 'Whether each value is the group\'s common name ' +
                 '(`developers`) or its whole DN ' +
                 '(`cn=developers,ou=groups,dc=example,dc=com`). Both are what ' +
                 'somebody\'s real identity provider does — an OIDC provider ' +
                 'usually sends names and Active Directory sends DNs — and a ' +
                 'client that has only ever parsed one of them has never run ' +
                 'the other path.' },

  { key: 'groups.claimFromMemberOf', group: 'Group claim',
    label: 'Believe an entry\'s own memberOf',
    env: 'STS_GROUPS_CLAIM_FROM_MEMBEROF', type: 'bool', dflt: true,
    runtime: true,
    description: 'Whether a group named by the PERSON\'S own `memberOf` counts ' +
                 'as membership when the group entry does not list them back. ' +
                 'Nothing in this directory maintains memberOf — it is not even ' +
                 'a standard attribute — so a client that writes it creates ' +
                 'exactly that disagreement, and /admin/groups exists partly to ' +
                 'SHOW it. This setting is which side of it a token believes. ' +
                 'On by default, because a client that wrote memberOf and got no ' +
                 'claim has been told nothing about why; off is how the ' +
                 'group entry stays the only authority. Either way the group ' +
                 'has to EXIST here — a memberOf naming nothing does not ' +
                 'invent a group to put in a token.' },

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
                 'asked to do" is the point of the log — but it is by far the ' +
                 'noisiest source (every JWKS poll and metadata fetch is one), ' +
                 'so turning it off is how somebody watching the directory or ' +
                 'the console gets a readable page. It never affects the ' +
                 'other five categories, and /admin/metrics counts every call ' +
                 'either way.' },

  // --- Delegation ----------------------------------------------------------
  //
  // ONE setting, and the absence of a second is deliberate. `audit.protocolCalls`
  // exists because that log's noisiest source drowns the rest of it; delegation
  // has no noisy source — an act is a service asking to be somebody, which is
  // rare and is the thing a person came to the page for — so there is nothing an
  // off switch would rescue. Runtime and honestly so: delegation.js reads the cap
  // per act rather than capturing it at require time.
  { key: 'delegation.maxRecords', group: 'Delegation',
    label: 'Maximum delegation acts held',
    env: 'DELEGATION_MAX_RECORDS', type: 'int', dflt: 2000, runtime: true,
    description: 'How many delegation acts /admin/delegation keeps before the ' +
                 'oldest are dropped. An act is one exchange in which somebody ' +
                 'acted on somebody else\'s behalf — a Kerberos S4U request or ' +
                 'forwarded ticket, a WS-Trust OnBehalfOf or ActAs, an RFC 8693 ' +
                 'token exchange — and REFUSED attempts are recorded too, which ' +
                 'is where most of the value is. What was dropped is COUNTED and ' +
                 'shown, so a truncated list says so rather than implying the ' +
                 'cap is all there ever was. Lowering it takes effect on the ' +
                 'next act and discards the excess immediately.' },

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
                 'naming somebody other than whoever the session cookie names. ' +
                 'ON by default, and it grants nothing that was not already ' +
                 'true: no password is checked at any sign-in screen here, so ' +
                 'anybody who can reach this port can already BECOME that ' +
                 'person in one request and log themselves out. What it buys ' +
                 'is a headless test — the inventory and the termination are ' +
                 'drivable with no browser and no cookie. Turning it OFF makes ' +
                 '/logout act on the caller\'s own session and nothing else, ' +
                 'and 403s a request that names another name; /admin/logout ' +
                 'and /admin-api/logout are unaffected, because those are the ' +
                 'operator\'s door and are behind the console\'s two roles.' },

  { key: 'logout.kerberosSignOut', group: 'Logout',
    label: 'A logout stops older Kerberos tickets at the KDC',
    env: 'LOGOUT_KERBEROS_SIGN_OUT', type: 'bool', dflt: true, runtime: true,
    description: 'Whether logging somebody out stamps a SIGN-OUT INSTANT on ' +
                 'their Kerberos principal, after which a TGS-REQ carrying a ' +
                 'ticket whose authtime is EARLIER is refused ' +
                 'KDC_ERR_TGT_REVOKED (20). It is the only thing a KDC can ' +
                 'honestly do about a credential it handed out and cannot ' +
                 'recall. KDC_ERR_TGT_REVOKED is a REGISTERED code whose text ' +
                 'says what is meant (RFC 4120 section 7.5.9) — but the ' +
                 'specification defines no mechanism that emits it, and ' +
                 'Kerberos has no logout, no session and no revocation at all, ' +
                 'so this instant is an invention rather than a spec\'d ' +
                 'behaviour. It is the same lever a real KDC has: the TGS ' +
                 'exchange is the one moment the KDC is back in the loop. ' +
                 'What it ' +
                 'does NOT do is stop a service ticket already in a cache from ' +
                 'working against the service that accepts it — nothing ' +
                 'contacts the KDC on that exchange — which is a fact about ' +
                 'Kerberos rather than a gap here, and /logout says so on the ' +
                 'row. An AS-REQ still succeeds: signing out is not disabling ' +
                 'an account, and the next authentication clears the instant. ' +
                 'Turning it OFF leaves the KDC behaving exactly as it did ' +
                 'before this feature existed.' },

  { key: 'logout.ldapDisconnect', group: 'Logout',
    label: 'A logout drops LDAP connections bound as that person',
    env: 'LOGOUT_LDAP_DISCONNECT', type: 'bool', dflt: true, runtime: true,
    description: 'Whether logging somebody out closes every connection to the ' +
                 'embedded directory — 389 and LDAPS 636 alike — whose bind DN ' +
                 'names them. RFC 4511 section 4.2 makes a bind the ' +
                 'authorization state of a CONNECTION, so the connection is ' +
                 'the session and dropping it is the only sign-out LDAP has. ' +
                 'The client sees its socket close mid-conversation, which is ' +
                 'what a directory server that revokes a session looks like ' +
                 'from the other end and is worth being able to point a client ' +
                 'at. Turning it OFF leaves the connections alone and lists ' +
                 'them on /logout as untouched rather than hiding them.' },

  { key: 'logout.maxRows', group: 'Logout',
    label: 'Maximum rows in one logout inventory',
    env: 'LOGOUT_MAX_ROWS', type: 'int', dflt: 500, runtime: true,
    description: 'How many live sessions and credentials /logout will list for ' +
                 'one person before it stops counting them individually. Past ' +
                 'it the page says how many were not listed and a global ' +
                 'logout still ends ALL of them — the cap is on what is drawn ' +
                 'and offered as a checkbox, never on what a termination ' +
                 'reaches, because a sign-out that silently missed the ' +
                 'five-hundred-and-first token would be the worst kind of ' +
                 'wrong here.' },

  // --- SPIFFE / SPIRE ------------------------------------------------------
  //
  // The three server-side surfaces of SPIFFE: the bundle endpoint (plain
  // HTTPS), the Workload API (gRPC, on a Unix socket and/or TCP) and the SPIRE
  // Server API (gRPC, likewise). What is restart-only here and why is the
  // ordinary split the header of this file describes: a BOUND SOCKET (all four
  // listeners) and MATERIAL DERIVED AT STARTUP (the trust domain, which every
  // authority's certificate names, and the two key types those authorities are
  // generated with). Everything else is read where it is used.
  { key: 'spiffe.enabled', group: 'SPIFFE', label: 'Enable SPIFFE',
    env: 'STS_SPIFFE_ENABLED', type: 'bool', dflt: true, runtime: true,
    description: 'Whether the three SPIFFE surfaces answer. Off, the routes ' +
                 'are still registered and the gRPC listeners still bound — ' +
                 'so /admin/sts-metadata still describes them and /spiffe ' +
                 'still ' +
                 'says what this is — but the bundle endpoint answers 404 and ' +
                 'every gRPC call is refused with Unavailable. Read per ' +
                 'request, so it can be turned off without a restart; the ' +
                 'sockets are a separate question and are restart-only below.' },

  { key: 'spiffe.trustDomain', group: 'SPIFFE', label: 'Trust domain',
    env: 'STS_SPIFFE_TRUST_DOMAIN', type: 'string', dflt: 'example.org',
    runtime: false,
    restartReason: 'the X.509 and JWT authorities are generated at startup ' +
                   'and every certificate they hold names this trust domain',
    description: 'The trust domain this service is the issuing authority for: ' +
                 'the authority part of every SPIFFE ID it mints, so ' +
                 'spiffe://example.org/… by default. LOWER-CASE, and only ' +
                 'letters, digits, dots, dashes and underscores — an ' +
                 'upper-case trust domain is not a valid SPIFFE ID and is not ' +
                 'another spelling of the lower-case one either. Restart-only ' +
                 'because changing it now would leave a CA whose certificates ' +
                 'name the old one, which is the silent disagreement this ' +
                 'file exists to prevent.' },

  { key: 'spiffe.x509KeyType', group: 'SPIFFE', label: 'X.509 authority key',
    env: 'STS_SPIFFE_X509_KEY_TYPE', type: 'enum',
    enumValues: ['ec-p256', 'ec-p384', 'ec-p521', 'rsa-2048', 'rsa-4096',
                 'ed25519'],
    dflt: 'ec-p256', runtime: false,
    restartReason: 'the X.509 authority is generated with this key type at ' +
                   'startup',
    description: 'The key the trust domain\'s X.509 authority is generated ' +
                 'with, and therefore the key type of every X509-SVID it ' +
                 'signs. EC P-256 by default because that is what SPIRE ' +
                 'issues and what the X509-SVID specification recommends. RSA ' +
                 '4096 takes several seconds to generate at startup, which is ' +
                 'worth knowing before wondering why the bundle endpoint is ' +
                 'not answering yet.' },

  { key: 'spiffe.jwtKeyType', group: 'SPIFFE', label: 'JWT authority key',
    env: 'STS_SPIFFE_JWT_KEY_TYPE', type: 'enum',
    enumValues: ['ec-p256', 'ec-p384', 'ec-p521', 'rsa-2048', 'rsa-4096'],
    dflt: 'ec-p256', runtime: false,
    restartReason: 'the JWT authority is generated with this key type at startup',
    description: 'The key the trust domain\'s JWT authority is generated ' +
                 'with, which decides the `alg` of every JWT-SVID: ES256, ' +
                 'ES384, ES512 or RS256. Ed25519 is DELIBERATELY ABSENT here ' +
                 'and present for X.509 — jsonwebtoken, this service\'s JWS ' +
                 'implementation, does not sign EdDSA, so offering it would ' +
                 'be a setting that fails at the first FetchJWTSVID rather ' +
                 'than at startup.' },

  { key: 'spiffe.caTtl', group: 'SPIFFE', label: 'Authority lifetime (seconds)',
    env: 'STS_SPIFFE_CA_TTL', type: 'int', dflt: 86400, runtime: false,
    restartReason: 'the authority certificate is issued for this long at startup',
    description: 'How long the X.509 authority\'s own certificate is valid. ' +
                 'An SVID is never issued past it — a leaf outliving its ' +
                 'issuer works until it suddenly does not, and nothing in ' +
                 'that failure names the CA — so a short authority lifetime ' +
                 'silently shortens every SVID with it.' },

  { key: 'spiffe.svidTtl', group: 'SPIFFE', label: 'X509-SVID lifetime (seconds)',
    env: 'STS_SPIFFE_SVID_TTL', type: 'int', dflt: 3600, runtime: true,
    description: 'The default lifetime of an X509-SVID. A registration entry ' +
                 'may name its own and that wins; this is what an entry with ' +
                 'no `x509SvidTtl` gets. SPIRE\'s default is an hour and so ' +
                 'is this: rotation is the interesting behaviour to exercise ' +
                 'in a client, and a long-lived SVID never rotates.' },

  { key: 'spiffe.jwtSvidTtl', group: 'SPIFFE', label: 'JWT-SVID lifetime (seconds)',
    env: 'STS_SPIFFE_JWT_SVID_TTL', type: 'int', dflt: 300, runtime: true,
    description: 'The default lifetime of a JWT-SVID. Much shorter than the ' +
                 'X.509 one on purpose and in both SPIRE and here: a JWT-SVID ' +
                 'is a bearer credential — whoever holds it can present it — ' +
                 'where an X509-SVID is bound to a private key.' },

  { key: 'spiffe.refreshHint', group: 'SPIFFE', label: 'Bundle refresh hint (seconds)',
    env: 'STS_SPIFFE_REFRESH_HINT', type: 'int', dflt: 300, runtime: true,
    description: 'The `spiffe_refresh_hint` published in the bundle: how often ' +
                 'a consumer should come back for it. It matters more against ' +
                 'this service than against a real one, because the whole ' +
                 'bundle is regenerated on every restart — a consumer that ' +
                 'never refreshes will fail to verify every SVID minted after ' +
                 'one, with nothing in the failure naming the bundle.' },

  { key: 'spiffe.svidSubject', group: 'SPIFFE', label: 'SVID subject DN',
    env: 'STS_SPIFFE_SVID_SUBJECT', type: 'string', dflt: 'C=US,O=SPIRE',
    runtime: true,
    description: 'The X.501 subject written into every X509-SVID. The SPIFFE ' +
                 'ID is in a URI subjectAltName and IS the identity; this is ' +
                 'decoration, and it is SPIRE\'s own value by default so that ' +
                 'an SVID from here looks like one from there. It cannot be ' +
                 'empty: an empty subject is refused by the certificate ' +
                 'builder and is rendered as a blank line by every tool a ' +
                 'person might inspect one with.' },

  { key: 'spiffe.autoCreateEntries', group: 'SPIFFE',
    label: 'Invent a registration entry on first sight',
    env: 'STS_SPIFFE_AUTOCREATE_ENTRIES', type: 'bool', dflt: true,
    runtime: true,
    description: 'THIS IS THE SETTING THAT MAKES THIS A MOCK. On, a workload ' +
                 'that asks the Workload API for an SVID and matches no ' +
                 'registration entry gets one created for it and is issued an ' +
                 'SVID anyway — no attestation, no selectors, nothing checked ' +
                 '— which is the same permissive posture every other family ' +
                 'here has. Off, an unregistered workload is answered with an ' +
                 'empty SVID list, which is what a real SPIRE agent does and ' +
                 'is the ONLY way to exercise a client\'s "I have no ' +
                 'identity" path. Both answers are worth having; neither is ' +
                 'the safe one.' },

  { key: 'spiffe.requireSecurityHeader', group: 'SPIFFE',
    label: 'Require the workload.spiffe.io header',
    env: 'STS_SPIFFE_REQUIRE_SECURITY_HEADER', type: 'bool', dflt: true,
    runtime: true,
    description: 'The Workload Endpoint specification says a client MUST send ' +
                 '`workload.spiffe.io: true` on every call and a server MUST ' +
                 'refuse one without it. It is a conformance check rather than ' +
                 'a security one — it exists so that a caller cannot reach ' +
                 'the endpoint by accident — and it is ON here even though ' +
                 'nothing else in this service refuses anything, because a ' +
                 'client that omits it has a bug this is the only thing that ' +
                 'will ever tell them about. Off is for the case where you ' +
                 'are deliberately testing something else.' },

  { key: 'spiffe.authRequired', group: 'SPIFFE',
    label: 'Authenticate the SPIRE Server API',
    env: 'STS_SPIFFE_AUTH_REQUIRED', type: 'bool', dflt: true,
    runtime: false,
    restartReason: 'the SPIRE Server API\'s TCP port is bound as mutual TLS ' +
                   'or as plain gRPC when the process starts, and a setting ' +
                   'that changed the checks without changing the socket ' +
                   'would report a mode this service was not in',
    description: 'ON, the SPIRE Server API behaves the way a real ' +
                 'spire-server does: its TCP port is MUTUAL TLS, a caller ' +
                 'presents an X509-SVID from this trust domain, and every ' +
                 'method is authorized against SPIRE\'s own table — local, ' +
                 'agent, admin, downstream — which GET /spiffe publishes in ' +
                 'full. The Unix socket stays plain and is the `local` ' +
                 'entity, which is how the spire-server CLI reaches a real ' +
                 'one. OFF, the port is plain gRPC and every method is open ' +
                 'to everybody, which is what this service did before this ' +
                 'setting existed. **This does not touch the Workload API**, ' +
                 'whose specification says a client MUST NOT be required to ' +
                 'authenticate — see spiffe.attestWorkloads for the only ' +
                 'thing that decides who gets what there.' },

  { key: 'spiffe.trustLocalSocket', group: 'SPIFFE',
    label: 'Trust the SPIRE Server API socket as local',
    env: 'STS_SPIFFE_TRUST_LOCAL_SOCKET', type: 'bool', dflt: true,
    runtime: true,
    description: 'A real SPIRE server trusts its private Unix socket ' +
                 'outright — the access control is the socket\'s filesystem ' +
                 'permissions — and a caller there is the `local` entity, ' +
                 'which may do everything an admin may and two things an ' +
                 'admin may not. Off, the socket demands an X509-SVID like ' +
                 'the TCP port, which is the only way to exercise a client\'s ' +
                 '"I was refused on the local socket" path. Read per call, so ' +
                 'it needs no restart.' },

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
                 'credentials, so there is no uid, no pid, no container and no ' +
                 'pod here, and the selectors this service produces are spelt ' +
                 '`transport:`, `endpoint:` and `peer:` so that they cannot ' +
                 'be mistaken for an attestor\'s. spiffe.autoCreateEntries ' +
                 'still invents an entry for a caller that matches nothing, ' +
                 'so the default experience is unchanged.' },

  { key: 'spiffe.acceptAssertedSelectors', group: 'SPIFFE',
    label: 'Believe selectors a workload asserts',
    env: 'STS_SPIFFE_ACCEPT_ASSERTED_SELECTORS', type: 'bool', dflt: false,
    runtime: true,
    description: 'OFF by default, and it is the one setting here that is not ' +
                 'attestation of any kind. On, a Workload API caller may send ' +
                 'the metadata header `x-sts-mock-workload-selector: ' +
                 'unix:uid:1000` (repeatable, or comma-separated) and those ' +
                 'selectors are matched against registration entries as ' +
                 'though something had verified them. NOTHING HAS. It exists ' +
                 'because selector matching is the interesting behaviour of a ' +
                 'Workload API and there is otherwise no way to exercise a ' +
                 'client\'s "these matched and those did not" path on a ' +
                 'service that cannot read peer credentials. The header is ' +
                 'deliberately spelt like nothing in any specification.' },

  { key: 'spiffe.maxEntries', group: 'SPIFFE', label: 'Maximum registration entries',
    env: 'STS_SPIFFE_MAX_ENTRIES', type: 'int', dflt: 500, runtime: true,
    description: 'How many entries may live under ou=spiffe. Past it a new ' +
                 'one is REFUSED and the SVID request that would have created ' +
                 'it is answered without one — the registry is a directory ' +
                 'container and a container has a size, the same cap ' +
                 'ou=applications has.' },

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
    description: 'How many foreign trust domains\' bundles are held. They are ' +
                 'PASTED IN and never fetched — see /spiffe — so this bounds ' +
                 'what an operator or the SPIRE Server API can add, not what ' +
                 'any polling loop could accumulate.' },

  { key: 'spiffe.bundlePath', group: 'SPIFFE', label: 'Bundle endpoint path',
    env: 'STS_SPIFFE_BUNDLE_PATH', type: 'string', dflt: '/spiffe/bundle',
    runtime: false,
    restartReason: 'the route is registered at require time, and the require ' +
                   'order is the route order',
    description: 'Where the trust bundle is published. A real federation ' +
                 'partner is configured with this URL and polls it. It is ' +
                 'restart-only for the reason every path here is: requiring a ' +
                 'module registers its endpoints, so the path is fixed by the ' +
                 'time anything could change it.' },

  { key: 'spiffe.workloadSocketEnabled', group: 'SPIFFE',
    label: 'Workload API on a Unix socket',
    env: 'STS_SPIFFE_WORKLOAD_SOCKET_ENABLED', type: 'bool', dflt: true,
    runtime: false,
    restartReason: 'the listener is bound when the process starts',
    description: 'Whether the Workload API is served on a Unix domain socket. ' +
                 'ON by default because that is what SPIFFE_ENDPOINT_SOCKET ' +
                 'means to every real client — go-spiffe, spiffe-helper, the ' +
                 'SPIRE agent — so without it nothing connects unconfigured. ' +
                 'It is the ONE thing this service puts on a filesystem: a ' +
                 'socket is a rendezvous point rather than state, nothing is ' +
                 'persisted through it, and it is unlinked when the listener ' +
                 'closes.' },

  { key: 'spiffe.workloadSocket', group: 'SPIFFE', label: 'Workload API socket path',
    env: 'STS_SPIFFE_WORKLOAD_SOCKET', type: 'string',
    dflt: '/tmp/spire-agent/public/api.sock', runtime: false,
    restartReason: 'the listener is bound when the process starts',
    description: 'Where that socket lives. SPIRE\'s own default path, so a ' +
                 'client that was pointed at a SPIRE agent needs no change. ' +
                 'The directory is created if it is missing and the socket is ' +
                 'removed on a clean shutdown; a stale one left by a killed ' +
                 'process is unlinked before binding, which is the ordinary ' +
                 'thing every Unix socket server does and the ordinary way ' +
                 'two copies of this service fight over one path.' },

  { key: 'spiffe.workloadPort', group: 'SPIFFE', label: 'Workload API TCP port',
    env: 'STS_SPIFFE_WORKLOAD_PORT', type: 'port', dflt: 8092, runtime: false,
    restartReason: 'the listener is bound when the process starts',
    description: 'The Workload API over TCP, which the Workload Endpoint ' +
                 'specification permits (tcp://host:port) and which is how ' +
                 'this is reached from another container or from a host that ' +
                 'cannot share the socket. 0 turns it off and leaves the Unix ' +
                 'socket alone.' },

  { key: 'spiffe.serverPort', group: 'SPIFFE', label: 'SPIRE Server API TCP port',
    env: 'STS_SPIFFE_SERVER_PORT', type: 'port', dflt: 8181, runtime: false,
    restartReason: 'the listener is bound when the process starts',
    description: 'The SPIRE Server API — Entry, Agent, Bundle, SVID, ' +
                 'TrustDomain and Debug — over gRPC. SPIRE\'s own default is ' +
                 '8081, which is this service\'s HTTP port, so the default ' +
                 'here is 8181 and a client configured for a real SPIRE ' +
                 'server has one thing to change. 0 turns it off.' },

  { key: 'spiffe.serverSocketEnabled', group: 'SPIFFE',
    label: 'SPIRE Server API on a Unix socket',
    env: 'STS_SPIFFE_SERVER_SOCKET_ENABLED', type: 'bool', dflt: false,
    runtime: false,
    restartReason: 'the listener is bound when the process starts',
    description: 'Whether the SPIRE Server API is also served on a Unix ' +
                 'socket, which is where a real spire-server keeps its ' +
                 'administrative API. OFF by default — unlike the Workload ' +
                 'API\'s, which is on — because `spire-server entry create` ' +
                 'and friends are the only things that reach for it, where ' +
                 'the Workload API socket is what every workload reaches for.' },

  { key: 'spiffe.serverSocket', group: 'SPIFFE', label: 'SPIRE Server API socket path',
    env: 'STS_SPIFFE_SERVER_SOCKET', type: 'string',
    dflt: '/tmp/spire-server/private/api.sock', runtime: false,
    restartReason: 'the listener is bound when the process starts',
    description: 'Where that socket lives when it is on. SPIRE\'s own default ' +
                 'path, for the same reason the Workload API\'s is.' },

  { key: 'spiffe.grpcHost', group: 'SPIFFE', label: 'gRPC bind address',
    env: 'STS_SPIFFE_GRPC_HOST', type: 'string', dflt: '0.0.0.0',
    runtime: false,
    restartReason: 'the listeners are bound when the process starts',
    description: 'The address both TCP gRPC listeners bind. 0.0.0.0 is every ' +
                 'interface, which is what a container needs; 127.0.0.1 ' +
                 'confines them to the machine this runs on. Worth a thought ' +
                 'here rather than elsewhere: the SPIRE Server API can create ' +
                 'registration entries granting any identity in this trust ' +
                 'domain. Its TCP port demands an X509-SVID and authorizes ' +
                 'every method while spiffe.authRequired is on, which is the ' +
                 'default; with it off, or on the Workload API port either ' +
                 'way, anybody who can reach these addresses is answered.' },

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
                 'everything is gone on restart. ldif writes an RFC 2849 file ' +
                 'per realm plus two JSON files in persistence.dataDir, which ' +
                 'is the local-development answer and needs no database. ' +
                 'postgres writes three tables and is the shared store. ' +
                 'NOTHING THIS SERVICE MINTS IS EVER PERSISTED in any mode: ' +
                 'sessions, tokens, codes, artifacts, Kerberos tickets and ' +
                 'the signing key are in memory always, because the key is ' +
                 'regenerated on every start and a token that outlived it ' +
                 'would verify against nothing.' },

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
  // WHAT THE CHANGE COSTS is one clear error message: `persistence.mode=postgres`
  // with nothing configured used to be refused by name ("set persistence.databaseUrl"),
  // and now it attempts a connection to localhost and reports whatever that says.
  // persistence.js puts the guidance back on that path — when a Postgres store
  // cannot be opened AND the URL came from the defaults layer, it says so and
  // names this setting. See its start().
  //
  // THE PASSWORD IS IN A FILE IN PLAIN TEXT and that is correct here for the
  // reason docker-compose.yml gives: it guards a throwaway database of mock
  // identities, and this repository's whole premise is that nothing in it is a
  // real credential. An operator with a real one sets the environment variable.
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
                 'password and database all "sts"), so turning persistence on ' +
                 'against a local database is one setting rather than two. It ' +
                 'is never dialled unless persistence.mode is postgres, which ' +
                 'is not the default — so this value is inert on an ordinary ' +
                 'run. The compose stack sets STS_DATABASE_URL itself, with ' +
                 '`postgres` as the host, because that is the service name on ' +
                 'its network. IT CARRIES A PASSWORD, so /admin/persistence ' +
                 'and GET /admin-api/persistence report the host, port, ' +
                 'database and user parsed out of it and never the string ' +
                 'itself.' },

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
    description: 'How long a change waits before the ldif store is rewritten, ' +
                 'so that a burst — a realm build writes thirteen entries — ' +
                 'costs one file write rather than thirteen. What it risks is ' +
                 'this many milliseconds of writes on a kill -9, which no ' +
                 'process can trap; SIGTERM and SIGINT flush first. POSTGRES ' +
                 'IGNORES IT and uses 0, because the unit of writing there is ' +
                 'a transaction rather than a file: every change made while ' +
                 'handling one request commits as one transaction the moment ' +
                 'that request is done.' },

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
                 'the saved values are re-applied at startup through the same ' +
                 'setOverride() a caller uses, so the five layers below are ' +
                 'unchanged and a runtime override is simply durable now. ' +
                 'Only a runtime-changeable setting can be saved, because ' +
                 'only a runtime-changeable setting can be set: that is what ' +
                 'makes applying them after every module has loaded safe.' }
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
  overrideStore = fn;
}

// Called after every successful write below. Wrapped, because a persistence
// layer that throws must not turn a successful configuration change into a
// failed one: the value IS set, the caller was right, and the only thing that
// went wrong is that it will not survive a restart.
function overridesChanged(realmId) {
  if (!overrideStore) {
    return;
  }
  try {
    overrideStore(realmId || null);
  } catch (err) {
    log.error('config: the override could not be handed to persistence: ' +
              err.message + '. The setting IS changed and is in force; it ' +
              'may not survive a restart.');
  }
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
  realmContext = fn;
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
  if (!realmContext || suppressRealmLayer ||
      String(key).indexOf('realms.') === 0 || isPerProcess(key)) {
    return null;
  }
  return realmContext() || null;
}

// Whether a realm may carry this setting at all. Exported, because the WRITING
// end of the rule is in realms.js — see checkRealmOverride() there — and two
// copies of a predicate is how the two ends come to disagree.
function isPerProcess(key) {
  const setting = byKey[key];
  return !!(setting && setting.perProcess);
}

function realmOverrideOf(key) {
  const realm = realmFor(key);
  if (!realm || !Object.prototype.hasOwnProperty.call(realm.overrides, key)) {
    return undefined;
  }
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
  let node = root;
  const parts = String(dotted).split('.');
  for (let i = 0; i < parts.length; i++) {
    if (node === null || typeof node !== 'object') {
      return undefined;
    }
    node = node[parts[i]];
  }
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
  const setting = byKey[key];
  if (!setting) {
    throw new Error('config.js: no such setting "' + key + '"');
  }
  return setting;
}

// The default, resolved. Written as a function because two of them are, and a
// caller should not have to know which.
function defaultOf(setting) {
  if (typeof setting.dflt === 'function') {
    return setting.dflt();
  }
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
  const setting = settingFor(key);
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

function sourceOf(key) {
  return resolve(key).source;
}

// The value as a single line: what the console's input shows, and what the
// equivalent environment variable would carry.
function text(key) {
  const setting = settingFor(key);
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
  loggers.push(logger);
  logger.level(value('global.logLevel'));
}

function applyLogLevel() {
  const level = value('global.logLevel');
  loggers.forEach(function (logger) {
    logger.level(level);
  });
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
    return { ok: false, errors: [problem] };
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
  // The two `realms.*` settings are the exception in both directions: realmFor()
  // answers null for them, so they always land process-wide. A realm that could
  // turn realms off, or move its own prefix, would be doing it from inside the
  // request that found it.
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
           (realm ? ' in the "' + realm.id + '" realm.' : ' (runtime override).'));
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
    return { ok: false, errors: ['Unknown setting "' + key + '".'] };
  }
  // The same rule as setOverride(): a reset undoes the override that was made
  // HERE. In a realm that is the realm's, and the value then falls back to
  // whatever the process as a whole is configured with — which may itself be a
  // runtime override, and is left alone.
  const realm = realmFor(key);
  const where = realm ? realm.overrides : overrides;
  if (!Object.prototype.hasOwnProperty.call(where, key)) {
    log.debug("Leaving clearOverride(). Nothing was overridden.");
    return { ok: false, errors: ['"' + key + '" has no ' +
      (realm ? 'value set in the "' + realm.id + '" realm' : 'runtime override') +
      ' to reset; it is already coming from ' + sourceOf(key) + '.'] };
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
  return { ok: true, errors: [], cleared: keys, realm: realm ? realm.id : null };
}

// ---------------------------------------------------------------------------
// THE PROCESS-WIDE OVERRIDES, TO BE WRITTEN DOWN AND READ BACK. Both halves are
// here rather than in persistence.js, and it is the same argument twice: this
// map is this file's, `overrides` is not exported and must not become so, and a
// module that reached in to copy it would be a second thing that knows what an
// override is.
//
// A REALM'S OVERRIDES ARE NOT HERE. They live on the realm row — `realm.overrides`
// — and are written down with the realm registry, because that is where they
// live in memory too. Copying them into this map would create the one thing the
// realm layer exists to prevent: a realm's value in a process-wide place.
// ---------------------------------------------------------------------------
function persistableOverrides() {
  const out = {};
  Object.keys(overrides).forEach(function (key) { out[key] = overrides[key]; });
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
      log.warn('config: the saved override for "' + key + '" was not ' +
               'applied: ' + problem + ' It is left in the store; nothing is ' +
               'deleted on the strength of one start refusing it.');
      return;
    }
    overrides[key] = saved[key];
    applied.push(key);
  });
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
      Object.keys(node).forEach(function (leaf) { present.push(top + '.' + leaf); });
      return;
    }
    present.push(top);
  });
  const known = {};
  SETTINGS.forEach(function (setting) { known[setting.path || setting.key] = true; });
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
    '\nconfig: FATAL — ' + orphans.length + ' setting(s) have no value in the ' +
    'appconfig layer and no environment variable:\n\n' +
    orphans.map(function (setting) {
      return '  ' + setting.key + ' '.repeat(width - setting.key.length + 2) +
             setting.env;
    }).join('\n') +
    '\n\nEach must be set in ' + (process.env.CONFIG_FILE || 'the appconfig file ' +
    'CONFIG_FILE names') + ', in ' + DEFAULTS_FILE + ' (the default appconfig ' +
    'file every other one is unioned on top of), or as the environment ' +
    'variable beside it.\n\nIf one of these was just added to SETTINGS in ' +
    'common/config.js, env/defaults.js is generated from that table and has ' +
    'not been regenerated.\n\n');
  log.debug("Leaving requireComplete(). Refusing to start.");
  process.exit(1);
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
  const shown = keys.slice(0, 12).join(', ');
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
           'what that file is for, and the value is the same either way — but ' +
           'a file that is meant to list the whole surface no longer does.');
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
    return { ok: false, problem: 'Unknown setting "' + key + '".' };
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
    return { ok: false, problem: '"' + key + '" ' + problem };
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
  registerLogger: registerLogger,
  checkOverride: checkOverride,
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
