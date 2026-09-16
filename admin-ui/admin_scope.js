'use strict';
//
// File: admin_scope.js
//
// ---------------------------------------------------------------------------
// WHAT A REALM ADMINISTRATOR MAY NOT REACH (2026-09-14, ticket #32).
//
// A trust realm has an administrator roster of its own since #32 — its own
// `cn=admin-read` and `cn=admin-write` — beside the DEFAULT realm's, which is
// the SERVICE roster and administers everything. rcbj's rule for the realm
// roster is that its members are CONFINED to their realm: every page and action
// about the realm they signed in through, and nothing that belongs to the whole
// process.
//
// **THIS FILE IS THE ONE PLACE THAT LINE IS DRAWN**, for the console and the
// management API alike. `admin-core/admin_views.js`'s `gateStateFor()` decides
// WHO holds which authority; this decides WHAT a realm authority may not touch.
// A second copy of either half is how the console and `/admin-api` would
// come to disagree about what a realm administrator can do, which is rule 7's
// subject read as a security property.
//
// Three kinds of thing are service-wide, and each is a table below:
//
//   * PAGES whose subject is the process — the store, the database, the secret
//     store, the listeners and their truststore, the shared KDC, the embedded
//     debugger. Refused whatever the method, and hidden from the navigation.
//   * ACTIONS on a realm-scoped page that reach past the realm — creating or
//     removing a realm, editing another realm's row, replacing the service Root
//     or the process branch, exporting the TLS listener's private key.
//   * SETTINGS a realm administrator may not write, wherever the form that
//     posts them is drawn. `config.setOverride()` sends a write for a row a
//     realm may not carry to the PROCESS-WIDE map even while a realm is
//     ambient, so a Save on `/realm/acme/admin/config` would otherwise change
//     the process; and a handful of rows a realm may carry still name the
//     whole service (the console's own roles, the management API's gate, file
//     paths and listener addresses).
//
// **A LIBRARY** (rule 3): no route, and it requires only `config.js` and the
// logger, neither of which requires it.
// ---------------------------------------------------------------------------

const { log } = require('../common/helpers');
const config = require('../common/config');

// Pages whose whole subject is the process. A prefix ends at a segment
// boundary, so `/admin/tls` covers `/admin/tls/trust` and not `/admin/tlsx`.
const SERVICE_PAGES = [
  '/admin/persistence',
  '/admin/cluster',
  '/admin/database',
  '/admin/encryption',
  '/admin/secrets',
  '/admin/debugger',
  '/admin/tls',
  // `/admin/kerberos` and `/admin/kerberos/principals` LEFT THIS LIST on
  // 2026-09-15, when a trust realm got a Kerberos realm and a principal
  // database of its own: what those pages show is then the realm's own, and a
  // realm administrator managing their realm's people and service principals
  // is exactly #32's rule. The settings that are still the PROCESS's — the two
  // sockets and the development-mode trust — are refused by
  // SERVICE_SETTING_KEYS below, per key rather than by the `krb5.` prefix this
  // used to carry.
  '/admin/ldap/service',
  // The explorer mints a DEFAULT-realm token for whoever holds the session,
  // which would hand a realm administrator a service credential. It is a
  // realm page only once it mints a realm token for a realm authority.
  '/admin/api-explorer'
];

// Settings a realm administrator may not write. A row a realm may not carry at
// all (`perProcess`, the two `realms.*` rows) is refused by
// `settingIsServiceOnly()` without being listed; these are the prefixes and
// keys a realm CAN carry that still name the whole service.
const SERVICE_SETTING_PREFIXES = [
  'admin.', 'adminApi.', 'realms.', 'workers.', 'persistence.', 'debugger.',
  'tls.', 'keys.', 'security.passwordHash'
];

const SERVICE_SETTING_KEYS = [
  'global.logLevel', 'global.mode', 'global.trustProxy', 'global.publicBaseUrl',
  'pki.revocationCrlIssuersFile', 'pki.revocationLdapCaFile',
  'pki.revocationLdapDirectory', 'pki.distributionPort',
  'pki.distributionBaseUrl', 'pki.distributionLdapHost',
  'pki.distributionLdapPort', 'pki.httpPort',
  'spiffe.workloadSocket', 'spiffe.serverSocket', 'spiffe.grpcHost',
  'spiffe.workloadPort', 'spiffe.serverPort',
  // KERBEROS, PER KEY SINCE 2026-09-15 (it was the `krb5.` prefix). A realm
  // carries its own Kerberos realm, principal database and keys, so the rows
  // those are built from are the realm administrator's. These five are not:
  // the two SOCKETS are bound once for the process, and the development-mode
  // trust is the DEFAULT realm's second Kerberos realm — no other realm has
  // one, so setting them on a realm would say something untrue.
  'krb5.kdcPort', 'krb5.servicePort', 'krb5.trustedRealm',
  'krb5.trustPassword', 'krb5.trustedDomainSid', 'krb5.trustedKrbtgtPassword'
];

// The realm-scoped pages whose ACTIONS can reach past the realm, and what each
// refuses. Each rule is handed the parsed body and the realm the administrator
// signed in through and answers a sentence when the action is service-wide.
const SERVICE_ACTIONS = {
  '/admin/realms': function (body, realmId) {
    log.debug("Entering the realms action rule.");
    const action = String((body && body.action) || '').trim();
    if (action === 'create' || action === 'remove') {
      log.debug("Leaving the realms action rule. Service-wide.");
      return 'Creating or removing a trust realm is a service ' +
             'administrator\'s act.';
    }
    const id = String((body && body.id) || '').trim();
    if (id && id !== realmId) {
      log.debug("Leaving the realms action rule. Another realm.");
      return 'That action names the "' + id + '" realm, and a realm ' +
             'administrator of "' + realmId + '" may change that realm only.';
    }
    log.debug("Leaving the realms action rule. Allowed.");
    return '';
  },
  '/admin/pki': function (body) {
    log.debug("Entering the PKI action rule.");
    const action = String((body && body.action) || '').trim();
    const scope = String((body && body.scope) || '').trim();
    if (action === 'build-root') {
      log.debug("Leaving the PKI action rule. The Root.");
      return 'Replacing the service Root re-certifies every realm\'s branch, ' +
             'so it is a service administrator\'s act.';
    }
    if (scope.charAt(0) === '*') {
      log.debug("Leaving the PKI action rule. A service branch.");
      return 'That action names the "' + scope + '" branch, which belongs to ' +
             'the whole service rather than to a realm.';
    }
    log.debug("Leaving the PKI action rule. Allowed.");
    return '';
  },
  '/admin/keys/export': tlsServerKeyRule,
  // The management API's spelling of the same export: `POST
  // /admin-api/keys/export` is an `export` action on `/admin/keys`.
  '/admin/keys': function (body) {
    log.debug("Entering the key action rule.");
    log.debug("Leaving the key action rule.");
    return String((body && body.action) || '') === 'export'
      ? tlsServerKeyRule(body) : '';
  }
};

// The one key on `/admin/keys` that is not a realm's.
function tlsServerKeyRule(body) {
  log.debug("Entering tlsServerKeyRule().");
  const key = String((body && body.key) || '').trim();
  log.debug("Leaving tlsServerKeyRule().");
  return key === 'tls-server'
    ? 'The TLS listener\'s private key belongs to the process, which every ' +
      'realm shares.'
    : '';
}

// The realm-scoped pages whose QUERY can name another realm, and what each
// refuses to a realm administrator: `/admin/realms?realm=<id>` draws that
// realm's row, its settings and its overrides.
const REALM_READS = {
  '/admin/realms': function (query, realmId) {
    log.debug("Entering the realms read rule.");
    const raw = query ? query.realm : '';
    const id = String((Array.isArray(raw) ? raw[0] : raw) || '').trim();
    log.debug("Leaving the realms read rule.");
    return id && id !== realmId
      ? 'That page names the "' + id + '" realm, and a realm administrator ' +
        'of "' + realmId + '" may read that realm only.'
      : '';
  }
};

// Whether `path` is `prefix` or under it, at a segment boundary.
function under(path, prefix) {
  log.debug("Entering under().");
  const p = String(path || '');
  log.debug("Leaving under().");
  return p === prefix || p.indexOf(prefix + '/') === 0;
}

function pageIsService(path) {
  log.debug("Entering pageIsService(). " + path);
  const hit = SERVICE_PAGES.some(function (prefix) {
    return under(path, prefix);
  });
  log.debug("Leaving pageIsService(). " + hit);
  return hit;
}

function knownSetting(key) {
  log.debug("Entering knownSetting().");
  const hit = config.SETTINGS.some(function (setting) {
    return setting.key === key;
  });
  log.debug("Leaving knownSetting().");
  return hit;
}

function settingIsServiceOnly(key) {
  log.debug("Entering settingIsServiceOnly(). " + key);
  const name = String(key || '');
  const hit = config.isPerProcess(name) ||
    SERVICE_SETTING_KEYS.indexOf(name) >= 0 ||
    SERVICE_SETTING_PREFIXES.some(function (prefix) {
      return name.indexOf(prefix) === 0;
    });
  log.debug("Leaving settingIsServiceOnly(). " + hit);
  return hit;
}

// Every setting a body names that a realm administrator may not write: the
// `key` of a `set` or `reset`, and every field of a `set-many` that is a
// setting's key.
function serviceSettingsIn(body) {
  log.debug("Entering serviceSettingsIn().");
  const named = [];
  const add = function (key) {
    log.debug("Entering add().");
    if (knownSetting(key) && settingIsServiceOnly(key) &&
        named.indexOf(key) < 0) {
      named.push(key);
    }
    log.debug("Leaving add().");
  };
  Object.keys(body || {}).forEach(add);
  if (body && typeof body.key === 'string') {
    add(body.key.trim());
  }
  log.debug("Leaving serviceSettingsIn(). " + named.length + ".");
  return named;
}

// ---------------------------------------------------------------------------
// THE DECISION. `state` is `gateStateFor()`'s answer; `path` is the console
// path the request is for, realm prefix already stripped; `body` is the parsed
// body of a write, or null for a read; `query` is the query string. Answers
// null when nothing here refuses, or `{ code, reason, detail }`.
//
// A SERVICE authority is never refused here — a service administrator reaches
// everything, in every realm, exactly as before #32. Nor is an unauthenticated
// request: the gate has already sent that one to sign in.
// ---------------------------------------------------------------------------
function refusalFor(state, path, body, query) {
  log.debug("Entering refusalFor(). " + path);
  if (!state || state.authority !== 'realm') {
    log.debug("Leaving refusalFor(). Not a realm authority.");
    return null;
  }
  if (pageIsService(path)) {
    log.debug("Leaving refusalFor(). A service page.");
    return { code: 'STS-ADMIN-0787', reason: 'service_page',
             detail: path + ' is about the whole service, which a realm ' +
                     'administrator of "' + state.identityRealm + '" does ' +
                     'not administer.' };
  }
  const reads = REALM_READS[path];
  const named = reads ? reads(query, state.identityRealm) : '';
  if (named) {
    log.debug("Leaving refusalFor(). Another realm named.");
    return { code: 'STS-ADMIN-0787', reason: 'service_action', detail: named };
  }
  if (body) {
    const rule = SERVICE_ACTIONS[path];
    const why = rule ? rule(body, state.identityRealm) : '';
    if (why) {
      log.debug("Leaving refusalFor(). A service action.");
      return { code: 'STS-ADMIN-0787', reason: 'service_action', detail: why };
    }
    const settings = serviceSettingsIn(body);
    if (settings.length) {
      log.debug("Leaving refusalFor(). Service settings.");
      return { code: 'STS-ADMIN-0788', reason: 'service_setting',
               settings: settings,
               detail: 'A realm administrator may not change ' +
                       settings.join(', ') + ': ' +
                       (settings.length === 1 ? 'it names' : 'they name') +
                       ' the whole service rather than the "' +
                       state.identityRealm + '" realm.' };
    }
  }
  log.debug("Leaving refusalFor(). Allowed.");
  return null;
}

// Whether a navigation row is drawn for this state. Only service pages are
// hidden, and only from a realm authority.
function pageVisible(state, path) {
  log.debug("Entering pageVisible().");
  const visible = !(state && state.authority === 'realm' &&
                    pageIsService(path));
  log.debug("Leaving pageVisible(). " + visible);
  return visible;
}

module.exports = {
  SERVICE_PAGES: SERVICE_PAGES,
  SERVICE_SETTING_PREFIXES: SERVICE_SETTING_PREFIXES,
  SERVICE_SETTING_KEYS: SERVICE_SETTING_KEYS,
  pageIsService: pageIsService,
  settingIsServiceOnly: settingIsServiceOnly,
  serviceSettingsIn: serviceSettingsIn,
  actionRuleFor: function (path) {
    log.debug("Entering actionRuleFor().");
    log.debug("Leaving actionRuleFor().");
    return SERVICE_ACTIONS[path] || null;
  },
  refusalFor: refusalFor,
  pageVisible: pageVisible
};
