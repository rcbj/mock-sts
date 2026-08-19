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
                 'either way.' }
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
