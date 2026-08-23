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
//   5. the BUILT-IN DEFAULT        the value the expression in the module used
//                                  to carry, unchanged
//
// The order is what makes this backwards compatible rather than merely similar:
// every env var that worked before works now and still beats the file, and a
// service started with no env vars at all and the shipped appconfig behaves
// exactly as it did — the appconfig files were seeded with the built-in
// defaults, so 4 and 5 agree.
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
// This module is a LIBRARY (rule 3): it registers no route, and it requires
// nothing from this repository — not even `helpers.js`, which requires IT. That
// is why it makes a bunyan logger of its own rather than taking the shared one:
// a require cycle here would hand `helpers.js` a half-initialised module whose
// `value` is undefined, and the symptom would arrive somewhere else entirely as
// "value is not a function".
//
// NOT PROTECTED, and it publishes the Kerberos passwords. That is deliberate
// and it is not new: `GET /krb5/principals` already prints them, for the reason
// written there — a debugger whose accounts are unusable without reading the
// source is worse than one that says what they are. Nothing in this service
// checks a credential. Do not put this port on a public address.
// ---------------------------------------------------------------------------

// CONFIG_FILE is made ABSOLUTE before it is read. This module lives in a
// subdirectory now, and a relative `./env/local.js` resolves against THIS
// directory rather than the package root — see common/config_file.js, which is
// required first for that reason and requires nothing itself.
require('./config_file').resolveConfigFile();
const bunyan = require('bunyan');
const appconfig = require(process.env.CONFIG_FILE);

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
  int: {
    parse: function (raw) {
      const n = parseInt(String(raw), 10);
      return Number.isFinite(n) ? n : 0;
    },
    text: function (v) { return String(v); },
    check: function (raw) {
      const s = String(raw).trim();
      if (!s) {
        return 'must be a number';
      }
      if (!/^-?\d+$/.test(s)) {
        return 'must be a whole number, got "' + raw + '"';
      }
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
      if (typeof raw === 'boolean') {
        return raw;
      }
      const text = String(raw).trim();
      if (/^(1|true|yes|on)$/i.test(text)) {
        return true;
      }
      if (/^(0|false|no|off)$/i.test(text)) {
        return false;
      }
      const fallback = !!(setting && setting.dflt);
      log.warn('config: "' + text + '" is not a true/false value' +
               (setting && setting.env ? ' for ' + setting.env : '') +
               '; using the default (' + fallback + ').');
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
                 'are separate and are under TLS below.' },

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
    dflt: function () { return value('oauth2.rfc9700'); },
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
  { key: 'oauth2.rfc9700', group: 'OAuth 2.0 / OIDC', label: 'RFC 9700 mode',
    env: 'STS_OAUTH2_RFC9700', type: 'bool', dflt: false, runtime: false,
    restartReason: 'it decides whether the main port is bound as HTTPS ' +
                   '(global.https), and a listener is bound when the process ' +
                   'starts',
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
  { key: 'oauth2.refreshIdleSeconds', group: 'OAuth 2.0 / OIDC',
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
                 'alone. The absolute thirty-day expiry on the token itself ' +
                 'is unaffected and still applies in both modes.' },

  // Also section 2.2.2, and its own setting because "expire after inactivity"
  // and "revoke after a security event" are different policies a deployment
  // chooses separately — one is about a client that went away and the other
  // about a person who signed out.
  { key: 'oauth2.revokeRefreshOnLogout', group: 'OAuth 2.0 / OIDC',
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

  // --- SAML ----------------------------------------------------------------
  { key: 'saml.issuer', group: 'SAML', label: 'Assertion issuer',
    env: 'STS_SAML_ISSUER', legacyEnv: 'STS_ISSUER', type: 'string',
    dflt: 'urn:wstrust:mock:sts', runtime: true,
    description: 'The <saml:Issuer> of every SAML 2.0 assertion and the ' +
                 'Issuer attribute of every SAML 1.1 one. WS-Federation\'s ' +
                 'assertions are built by the same two functions, so this is ' +
                 'their issuer too, and it is what /wsfed/rp checks a ' +
                 'presented assertion against.' },

  // --- WS-Trust ------------------------------------------------------------
  { key: 'wstrust.issuer', group: 'WS-Trust', label: 'Token issuer',
    env: 'STS_WSTRUST_ISSUER', legacyEnv: 'STS_ISSUER', type: 'string',
    dflt: 'urn:wstrust:mock:sts', runtime: true,
    description: 'The `iss` of the JWT this STS returns in a ' +
                 'RequestSecurityTokenResponse, and the issuer named on GET ' +
                 '/sts. A SAML token requested through WS-Trust is built by ' +
                 'the SAML modules and carries the SAML issuer above.' },

  // --- WS-Federation -------------------------------------------------------
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
                 'so /sts-metadata still describes them and /spiffe still ' +
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
                 'way, anybody who can reach these addresses is answered.' }
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
// Reading.
// ---------------------------------------------------------------------------

// A dot path into the appconfig module. Returns undefined for any missing hop,
// so a config file that omits a whole section — every file shipped before this
// table existed omitted all of them — falls through to the built-in defaults
// rather than throwing on `appconfig.krb5.realm` where `krb5` is not there.
function fromAppconfig(path) {
  let node = appconfig;
  const parts = String(path).split('.');
  for (let i = 0; i < parts.length; i++) {
    if (node === null || typeof node !== 'object') {
      return undefined;
    }
    node = node[parts[i]];
  }
  return node;
}

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
  const setting = settingFor(key);
  if (Object.prototype.hasOwnProperty.call(overrides, key)) {
    return { raw: overrides[key], source: 'override' };
  }
  if (setting.env && process.env[setting.env] !== undefined) {
    return { raw: process.env[setting.env], source: 'env' };
  }
  if (setting.legacyEnv && process.env[setting.legacyEnv] !== undefined) {
    return { raw: process.env[setting.legacyEnv], source: 'env-legacy' };
  }
  const fromFile = fromAppconfig(setting.path || setting.key);
  if (fromFile !== undefined) {
    return { raw: fromFile, source: 'appconfig' };
  }
  return { raw: defaultOf(setting), source: 'default' };
}

// THE function every module calls. Coerced to the setting's type, so a caller
// never has to know whether the value arrived from a string environment or a
// typed file.
function value(key) {
  const setting = settingFor(key);
  return TYPES[setting.type].parse(resolve(key).raw, setting);
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
function checkOverride(key, raw) {
  const setting = byKey[key];
  if (!setting) {
    return 'Unknown setting "' + key + '".';
  }
  if (!setting.runtime) {
    return '"' + key + '" cannot be changed while this service is running: ' +
      setting.restartReason + '. Set it in the appconfig file or as ' +
      (setting.env || 'its environment variable') + ' and restart.';
  }
  const problem = TYPES[setting.type].check(raw, setting);
  return problem ? '"' + key + '" ' + problem + '.' : null;
}

function setOverride(key, raw) {
  log.debug("Entering setOverride(). key=" + key);
  const problem = checkOverride(key, raw);
  if (problem) {
    log.debug("Leaving setOverride(). Refused: " + problem);
    return { ok: false, errors: [problem] };
  }
  overrides[key] = raw;
  // Before the log line, so that a change to the level is in force for the
  // line that announces it rather than one line late.
  applyLogLevel();
  log.info('config: ' + key + ' is now ' + JSON.stringify(text(key)) +
           ' (runtime override).');
  log.debug("Leaving setOverride().");
  return { ok: true, errors: [], key: key };
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
  if (!Object.prototype.hasOwnProperty.call(overrides, key)) {
    log.debug("Leaving clearOverride(). Nothing was overridden.");
    return { ok: false, errors: ['"' + key + '" has no runtime override to ' +
      'reset; it is already coming from ' + sourceOf(key) + '.'] };
  }
  delete overrides[key];
  applyLogLevel();
  log.info('config: ' + key + ' is back to its ' + sourceOf(key) + ' value.');
  log.debug("Leaving clearOverride().");
  return { ok: true, errors: [], key: key };
}

function clearAllOverrides() {
  log.debug("Entering clearAllOverrides().");
  const keys = Object.keys(overrides);
  keys.forEach(function (key) { delete overrides[key]; });
  applyLogLevel();
  log.info('config: ' + keys.length + ' runtime override(s) cleared.');
  log.debug("Leaving clearAllOverrides(). " + keys.length + " cleared.");
  return { ok: true, errors: [], cleared: keys };
}

// ---------------------------------------------------------------------------
// Describing.
//
// One shape, used by the console page, by the management API and by the
// OpenAPI document's example. A second shape for any of them is how a console
// and an API start disagreeing about what the service is configured with.
// ---------------------------------------------------------------------------
function describe(setting) {
  const state = resolve(setting.key);
  return {
    key: setting.key,
    group: setting.group,
    label: setting.label,
    description: setting.description,
    type: setting.type,
    enumValues: setting.enumValues || undefined,
    value: value(setting.key),
    text: text(setting.key),
    source: state.source,
    editable: !!setting.runtime,
    restartReason: setting.runtime ? undefined : setting.restartReason,
    env: setting.env,
    legacyEnv: setting.legacyEnv,
    appconfigPath: setting.path || setting.key,
    default: defaultOf(setting),
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
  const overridden = Object.keys(overrides);
  const out = {
    configFile: process.env.CONFIG_FILE || null,
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
// Does the appconfig file still match this table?
//
// The three files shipped here were GENERATED from it, so they agree the day
// they are written. Nothing keeps them agreeing: a setting added below and not
// added to the files is invisible (it falls through to its built-in default,
// which is correct but leaves the file claiming to be the whole surface when it
// is not), and a key left in a file after the setting is removed is read by
// nobody and says otherwise.
//
// Neither is fatal, so neither throws — a stale config file must not stop a
// service from starting. Both are logged at startup, which is where somebody
// who has just changed one of them is looking.
// ---------------------------------------------------------------------------
function auditAppconfig() {
  log.debug("Entering auditAppconfig().");
  // `derived` settings are left OUT of the shipped files on purpose: their
  // default is computed from another setting, and a literal in the file would
  // freeze the derivation at whatever it evaluated to the day it was written.
  // Counting them as drift would mean warning on every start about the one
  // thing that is correct.
  const missing = SETTINGS.filter(function (setting) {
    return !setting.derived &&
           fromAppconfig(setting.path || setting.key) === undefined;
  }).map(function (setting) { return setting.key; });

  // Every dot path the file actually carries, so a key the table does not know
  // can be named. Only the two levels this table uses are walked; a deeper
  // object under a known group is somebody's own note and is left alone.
  const present = [];
  Object.keys(appconfig || {}).forEach(function (top) {
    const node = appconfig[top];
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

log.info('config: ' + SETTINGS.length + ' settings from ' +
         (process.env.CONFIG_FILE || '(no CONFIG_FILE)') + ', ' +
         SETTINGS.filter(function (s) { return s.runtime; }).length +
         ' of them changeable while running. /admin/config shows them all.');

// This module's own logger joins the registry last, after the table it reads
// from is built.
registerLogger(log);

const audit = auditAppconfig();
const settable = SETTINGS.filter(function (s) { return !s.derived; }).length;
if (audit.missing.length === settable) {
  // NOT drift, and not worth a warning: a config file carrying none of these
  // keys is somebody else's file, which is the ordinary case for the parent
  // project's in-process tests — they load this service's KDC modules with
  // CONFIG_FILE pointing at the TEST suite's config. Every value is a built-in
  // default, which is what those jobs had before this table existed, and the
  // KRB5_* variables they set still win over it.
  log.debug('config: ' + (process.env.CONFIG_FILE || 'the appconfig file') +
            ' carries none of this service\'s settings, so every value is a ' +
            'built-in default or comes from the environment.');
} else if (audit.missing.length) {
  log.warn('config: ' + audit.missing.length + ' setting(s) are not in ' +
           (process.env.CONFIG_FILE || 'the appconfig file') + ' and are ' +
           'falling back to their built-in defaults: ' +
           audit.missing.join(', ') + '. That is not an error — the value is ' +
           'the same either way — but a file that is meant to list the whole ' +
           'surface no longer does.');
}
// Guarded the same way, and for the same reason: every key in somebody
// else's config file is one this service does not know, and saying so
// forty-five times would bury the case this warning is for — a misspelt
// key in a file that IS this service's.
if (audit.unknown.length && audit.missing.length !== settable) {
  log.warn('config: ' + (process.env.CONFIG_FILE || 'the appconfig file') +
           ' carries ' + audit.unknown.length + ' key(s) this service does ' +
           'not know and is not reading: ' + audit.unknown.join(', ') +
           '. A misspelt key looks exactly like this.');
}

module.exports = {
  SETTINGS: SETTINGS,
  value: value,
  text: text,
  sourceOf: sourceOf,
  registerLogger: registerLogger,
  checkOverride: checkOverride,
  setOverride: setOverride,
  clearOverride: clearOverride,
  clearAllOverrides: clearAllOverrides,
  describe: describe,
  groups: groups,
  snapshot: snapshot,
  auditAppconfig: auditAppconfig
};
