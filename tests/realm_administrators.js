'use strict';

// ===========================================================================
// tests/realm_administrators.js — A ROSTER PER TRUST REALM BESIDE THE SERVICE'S
// (2026-09-14, ticket #32).
//
// A trust realm has console administrators of its own — `cn=admin-read` and
// `cn=admin-write` in its own `ou=groups`, and a bootstrap `admin` — confined
// to that realm, while the default realm's roster stays the SUPER administrator
// over every realm. The claims, each one a thing no request over HTTP can
// choose the state for:
//
//   1. THE ROSTER IS PER REALM. A grant named with a realm lands in that
//      realm's groups and the default realm's roster does not move; the
//      default realm is still what a caller naming no realm reads.
//   2. EVERY REALM SEEDS ITS OWN BOOTSTRAP ADMINISTRATOR, flagged and forced
//      to change its password, and its first console sign-in closes THAT
//      realm's window and no other.
//   3. A REALM'S SEEDED ACCOUNT CANNOT BE DELETED IN ITS REALM; an unflagged
//      person of the same name elsewhere can.
//   4. AUTHORITY FOLLOWS THE REALM THE PERSON SIGNED IN THROUGH
//      (`admin_views.gateStateFor()`): a default-realm identity is a service
//      authority everywhere; a realm identity is a realm authority in its
//      realm and holds nothing in any other; and a realm person who shares a
//      service administrator's NAME is asked their own realm's roster — the
//      hole #32 closed.
//   5. THE SCOPE TABLE (`admin-ui/admin_scope.js`) refuses a realm authority
//      the service pages, actions, settings and another realm's reads, and
//      refuses a service authority nothing.
//   6. THE REALM CHOOSER (`common/realm_chooser.js`) asks only at a bare
//      /admin or /portal of the default realm with realms defined, redirects a
//      choice to the realm's own prefix, and signs the default realm in where
//      it is.
//   7. CERTIFICATE ENROLLMENT asks the AMBIENT realm's roster of a session.
//
// In a CHILD PROCESS, for `admin_bootstrap.js`'s reason: it loads the whole
// protocol stack, creates realms and writes rosters that every other file in
// `run.js`'s one process would otherwise meet.
//
// NOT HERE: the console gate's HTTP answers, the realm token at /admin-api and
// the chooser page in a browser — those need the service's own port and were
// driven against an isolated instance; `tests/vendored/sts_admin_api_auth.js`
// and `sts_admin_api_operations.js` hold the API half over HTTP.
// ===========================================================================

delete process.env.CONFIG_FILE;

const path = require('path');
const os = require('os');
const fs = require('fs');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'realm_administrators',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  const ROOT = process.env.RA_ROOT;
  const OUT = process.env.RA_OUT;
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const realms = require(ROOT + '/common/realms');
    const rbac = require(ROOT + '/admin-ui/admin_rbac');
    const scope = require(ROOT + '/admin-ui/admin_scope');
    const chooser = require(ROOT + '/common/realm_chooser');
    const views = require(ROOT + '/admin-core/admin_views');
    const oidcRp = require(ROOT + '/common/oidc_rp');
    const ldapServer = require(ROOT + '/ldap/ldap_server');
    const enrollment = require(ROOT + '/common/cert_enrollment');

    // THE CHOOSER BEFORE ANY REALM EXISTS — asked first, while there is still
    // only one realm to choose: a bare /admin signs in where it is.
    const noRealmsYet = require(ROOT + '/common/realm_chooser').decide({
      method: 'GET', originalUrl: '/admin', query: {},
      headers: { host: 'localhost' }, protocol: 'https',
      get: function () { return 'localhost'; } }, 'admin');

    const R = 'ra' + process.pid;
    const S = 'rb' + process.pid;
    const T = 'rc' + process.pid;
    realms.create({ id: R, name: 'Realm administrators' });
    realms.create({ id: S, name: 'Another realm' });
    realms.create({ id: T, name: 'A freshly seeded realm' });
    const inRealm = function (id, fn) {
      return realms.run(realms.get(id) || realms.DEFAULT_REALM, fn);
    };

    // ---------------------------------------------------------------------
    // 1. THE ROSTER IS PER REALM.
    // ---------------------------------------------------------------------
    const serviceBefore = rbac.describe();
    const granted = rbac.grant('realmboss', 'write', { via: 'test',
                                                      realm: R });
    note(granted.ok && String(granted.dn).indexOf('dc=' + R) >= 0,
         'a grant naming a realm lands in THAT realm\'s groups',
         JSON.stringify(granted.dn));
    note(rbac.describe().grantCount === serviceBefore.grantCount,
         'and the default realm\'s roster — the service\'s — does not move',
         rbac.describe().grantCount + ' against ' + serviceBefore.grantCount);
    // By MEMBERSHIP (`groups`), because a roster with nobody in it is open to
    // everybody while its window is: the default realm's is, in this child.
    note(rbac.rolesOf('realmboss', R).groups.length === 1 &&
         rbac.rolesOf('realmboss').groups.length === 0 &&
         rbac.rolesOf('realmboss', S).groups.length === 0,
         'the role is held in that realm and in no other, the default realm ' +
         'included', JSON.stringify([rbac.rolesOf('realmboss', R).groups,
                                     rbac.rolesOf('realmboss').groups]));
    const described = rbac.describe(R);
    note(described.realm === R && described.authority === 'realm' &&
         rbac.describe().authority === 'service' &&
         String(described.groupsDn).indexOf('dc=' + R) >= 0,
         'describe() says whose roster it is: the realm\'s own, or the ' +
         'service\'s for the default realm',
         JSON.stringify({ realm: described.realm,
                          authority: described.authority }));
    note(rbac.describe('no-such-realm-' + process.pid).available === false,
         'a realm that does not exist has no roster to grant anything from');

    // ---------------------------------------------------------------------
    // 2. A BOOTSTRAP ADMINISTRATOR PER REALM, AND ITS OWN WINDOW.
    // ---------------------------------------------------------------------
    // T has nobody in its roster when it is seeded; R already had a grant, so
    // its window closes at once — `seedBootstrapAdministrator()`'s
    // already-administered rule, one realm down.
    const seeded = rbac.seedBootstrapAdministrator(T);
    const state = rbac.bootstrapState(T);
    const seededR = rbac.seedBootstrapAdministrator(R);
    note(seeded.ran && seeded.created && seeded.realm === T &&
         state.seeded && !state.claimedAt &&
         rbac.rolesOf('admin', T).groups.length === 2,
         'seeding a realm makes its own `admin`, flagged, in both of its roles',
         JSON.stringify({ seeded: seeded, state: state }));
    note(seededR.ran && seededR.windowClosed === true,
         'and a realm whose roster already named somebody is seeded with its ' +
         'window closed', JSON.stringify(seededR));
    const openBefore = rbac.rolesOf('passerby', T).open;
    const defaultOpenBefore = rbac.describe().openToAnyone;
    note(openBefore === true,
         'until that account signs in, a person holding no role in the realm ' +
         'is OPEN there', String(openBefore));
    note(rbac.noteConsoleSignIn('admin', { derivedFromRealm: S },
                                realms.DEFAULT_ID) === false &&
         rbac.rolesOf('passerby', T).open === true,
         'another realm\'s `admin` signing in does not close this realm\'s ' +
         'window');
    note(rbac.noteConsoleSignIn('admin', { derivedFromRealm: T },
                                realms.DEFAULT_ID) === true,
         'the realm\'s own `admin` signing in closes it');
    note(rbac.rolesOf('passerby', T).open === false &&
         rbac.describe().openToAnyone === defaultOpenBefore,
         'after which the realm\'s roster is enforced — and the default ' +
         'realm\'s window is exactly as it was',
         JSON.stringify({ realm: rbac.rolesOf('passerby', T).open,
                          service: rbac.describe().openToAnyone }));

    // ---------------------------------------------------------------------
    // 3. THE REALM'S SEEDED ACCOUNT CANNOT BE DELETED THERE.
    // ---------------------------------------------------------------------
    const seededDn = rbac.bootstrapState(T).dn;
    const refusedDelete = inRealm(T, function () {
      return ldapServer.deletePerson(seededDn);
    });
    note(refusedDelete.ok === false && refusedDelete.reason === 'protected',
         'a realm\'s bootstrap administrator cannot be deleted in its realm',
         JSON.stringify(refusedDelete));
    const unflagged = inRealm(S, function () {
      ldapServer.createUser('admin', {});
      return ldapServer.deletePerson('uid=admin,' + ldapServer.usersDn());
    });
    note(unflagged.ok === true,
         'an unflagged person called `admin` in a realm nobody seeded is an ' +
         'ordinary person there', JSON.stringify(unflagged));

    // ---------------------------------------------------------------------
    // 4. AUTHORITY FOLLOWS THE REALM THE PERSON SIGNED IN THROUGH.
    // ---------------------------------------------------------------------
    rbac.grant('svcboss', 'write', { via: 'test' });
    const realSessionFor = oidcRp.sessionFor;
    const gateAs = function (username, fromRealm, ambient) {
      oidcRp.sessionFor = function () {
        return { id: 'test-session', user: { username: username },
                 derivedFromRealm: fromRealm === realms.DEFAULT_ID
                   ? '' : fromRealm };
      };
      try {
        return inRealm(ambient, function () {
          return views.gateStateFor({ query: {}, headers: {} });
        });
      } finally {
        oidcRp.sessionFor = realSessionFor;
      }
    };
    const svcInRealm = gateAs('svcboss', realms.DEFAULT_ID, R);
    note(svcInRealm.authority === 'service' && svcInRealm.write === true &&
         !svcInRealm.outsideRealm,
         'a service administrator is a SERVICE authority reading any realm',
         JSON.stringify({ authority: svcInRealm.authority,
                          write: svcInRealm.write }));
    const bossHome = gateAs('realmboss', R, R);
    note(bossHome.authority === 'realm' && bossHome.identityRealm === R &&
         bossHome.write === true && !bossHome.outsideRealm,
         'a realm administrator is a REALM authority in their realm',
         JSON.stringify({ authority: bossHome.authority,
                          write: bossHome.write }));
    const bossAway = gateAs('realmboss', R, realms.DEFAULT_ID);
    const bossElsewhere = gateAs('realmboss', R, S);
    note(bossAway.outsideRealm && !bossAway.read && !bossAway.write &&
         bossElsewhere.outsideRealm && !bossElsewhere.read,
         'and holds NOTHING in the default realm or another realm',
         JSON.stringify({ away: bossAway.roles,
                          elsewhere: bossElsewhere.roles }));
    // The collision: a person in realm S called `svcboss`, who holds nothing
    // in S (S's window is open only while its roster is empty — so give S's
    // roster a member first).
    rbac.grant('someone-else', 'read', { via: 'test', realm: S });
    const collision = gateAs('svcboss', S, S);
    note(collision.authority === 'realm' && collision.write !== true &&
         collision.read !== true,
         'A REALM PERSON WHO SHARES A SERVICE ADMINISTRATOR\'S NAME HOLDS ' +
         'NOTHING OF THEIRS — their own realm\'s roster is asked',
         JSON.stringify({ authority: collision.authority,
                          roles: collision.roles }));

    // ---------------------------------------------------------------------
    // 5. THE SCOPE TABLE.
    // ---------------------------------------------------------------------
    const realmState = { authority: 'realm', identityRealm: R };
    const serviceState = { authority: 'service', identityRealm: 'default' };
    const refused = function (st, p, body, query) {
      return scope.refusalFor(st, p, body || null, query || {});
    };
    // `/admin/kerberos/principals` LEFT THE SERVICE PAGES on 2026-09-15: a
    // trust realm has a Kerberos realm, a principal database and keys of its
    // own, so its people and service principals are the realm administrator's
    // to manage. What is still the service's is per SETTING — the two sockets
    // and the development trust — and is asserted below.
    note(refused(realmState, '/admin/tls/trust') &&
         refused(realmState, '/admin/persistence') &&
         !refused(realmState, '/admin/kerberos/principals') &&
         !refused(realmState, '/admin/tokens') &&
         !refused(realmState, '/admin/tlsx'),
         'service pages are refused a realm authority at a segment boundary, ' +
         'and realm pages are not');
    note(refused(realmState, '/admin/realms', { action: 'create', id: 'x' }) &&
         refused(realmState, '/admin/realms', { action: 'update', id: S }) &&
         !refused(realmState, '/admin/realms', { action: 'update', id: R }) &&
         refused(realmState, '/admin/realms', null, { realm: S }) &&
         !refused(realmState, '/admin/realms', null, { realm: R }),
         'the realm registry: no create or remove, and no other realm\'s row ' +
         'to read or change');
    note(refused(realmState, '/admin/pki', { action: 'build-root' }) &&
         refused(realmState, '/admin/pki',
                 { action: 'reissue-use-case', scope: '*service' }) &&
         !refused(realmState, '/admin/pki', { action: 'issue' }),
         'the PKI: the Root and the service branches refused, a realm\'s ' +
         'issue allowed');
    note(refused(realmState, '/admin/keys/export', { key: 'tls-server' }) &&
         refused(realmState, '/admin/keys',
                 { action: 'export', key: 'tls-server' }) &&
         !refused(realmState, '/admin/keys/export', { key: 'rs256' }),
         'the TLS listener\'s private key is refused through both spellings ' +
         'of its export');
    const settings = refused(realmState, '/admin/config',
      { action: 'set-many', 'workers.count': '2', 'admin.readGroup': 'x',
        'oauth2.accessTokenTtlS': '600' });
    note(settings && settings.code === 'STS-ADMIN-0788' &&
         settings.settings.indexOf('workers.count') >= 0 &&
         settings.settings.indexOf('admin.readGroup') >= 0 &&
         settings.settings.indexOf('oauth2.accessTokenTtlS') < 0 &&
         !refused(realmState, '/admin/config',
                  { action: 'set', key: 'oauth2.accessTokenTtlS' }) &&
         refused(realmState, '/admin/config',
                 { action: 'reset', key: 'global.mode' }) &&
         // A per-process row that no prefix above names: the rule reads the
         // table's own `perProcess` flag rather than a list.
         refused(realmState, '/admin/config',
                 { action: 'set', key: 'spiffe.maxRecordedConnections' }) &&
         // KERBEROS, PER KEY SINCE 2026-09-15. The rows a realm's principal
         // database is built from are the realm administrator's — it has a
         // Kerberos realm of its own — and the two SOCKETS and the
         // development-mode trust are still the service's. This was the
         // `krb5.` prefix until that date, which refused all of them.
         !refused(realmState, '/admin/config',
                  { action: 'set', key: 'krb5.realm' }) &&
         !refused(realmState, '/admin/config',
                  { action: 'set', key: 'krb5.enabled' }) &&
         refused(realmState, '/admin/config',
                 { action: 'set', key: 'krb5.kdcPort' }) &&
         refused(realmState, '/admin/config',
                 { action: 'set', key: 'krb5.trustedRealm' }),
         'settings naming the service are refused by name wherever they are ' +
         'posted, and a realm\'s own are not',
         JSON.stringify(settings && settings.settings));
    note(!refused(serviceState, '/admin/tls/trust') &&
         !refused(serviceState, '/admin/pki', { action: 'build-root' }) &&
         !refused(serviceState, '/admin/config', { 'workers.count': '2' }) &&
         !refused(null, '/admin/persistence'),
         'a service authority, and a request with no authority, are refused ' +
         'nothing here');
    note(!scope.pageVisible(realmState, '/admin/secrets') &&
         scope.pageVisible(realmState, '/admin/users') &&
         scope.pageVisible(serviceState, '/admin/secrets'),
         'service pages are hidden from a realm authority\'s navigation only');

    // ---------------------------------------------------------------------
    // 6. THE REALM CHOOSER.
    // ---------------------------------------------------------------------
    const ask = function (method, url, ambient) {
      const query = {};
      new URL('http://x' + url).searchParams.forEach(function (v, k) {
        query[k] = v;
      });
      return inRealm(ambient || realms.DEFAULT_ID, function () {
        return chooser.decide({ method: method, originalUrl: url, query: query,
                                headers: { host: 'localhost' },
                                protocol: 'https',
                                get: function () { return 'localhost'; } },
                              url.indexOf('/portal') === 0 ? 'portal'
                                                           : 'admin');
      });
    };
    const bare = ask('GET', '/admin');
    const slash = ask('GET', '/portal/');
    const chosen = ask('GET', '/admin?realm=' + R);
    const portalChosen = ask('GET', '/portal?realm=' + R);
    note(bare && bare.kind === 'page' && !bare.error &&
         slash && slash.kind === 'page',
         'a bare /admin or /portal/ in the default realm draws the chooser',
         JSON.stringify([bare, slash]));
    note(chosen && chosen.kind === 'redirect' &&
         /\/realm\/[^/]+\/admin$/.test(chosen.location) &&
         chosen.location.indexOf(R) >= 0 &&
         portalChosen && /\/portal$/.test(portalChosen.location),
         'a realm chosen is a redirect to that realm\'s own surface, built ' +
         'from its prefix', JSON.stringify([chosen, portalChosen]));
    const unknown = ask('GET', '/admin?realm=%3Cscript%3E');
    note(ask('GET', '/admin?realm=default') === null &&
         unknown && unknown.kind === 'page' && !!unknown.error,
         'the default realm signs in where it is, and an id that is not a ' +
         'realm is the page again with a sentence', JSON.stringify(unknown));
    note(noRealmsYet === null,
         'with no realm defined there is nothing to choose, and a bare ' +
         '/admin ' +
         'signs in where it is', JSON.stringify(noRealmsYet));
    note(ask('GET', '/admin/tokens') === null &&
         ask('POST', '/admin') === null &&
         ask('GET', '/admin', R) === null,
         'a deep link, a POST and a request already under a realm are not ' +
         'the chooser\'s question');
    const drawn = inRealm(realms.DEFAULT_ID, function () {
      return chooser.form({ headers: { host: 'localhost' }, protocol: 'https',
                            get: function () { return 'localhost'; } },
                          'admin', 'a <b>sentence</b>');
    });
    note(drawn.indexOf('<select') >= 0 &&
         drawn.indexOf('value="' + R + '"') >= 0 &&
         drawn.indexOf('<script') < 0 && drawn.indexOf('<b>sentence') < 0 &&
         /<button type="submit">/.test(drawn),
         'development lists every realm in a form with a real button, no ' +
         'script, and an escaped sentence');

    // ---------------------------------------------------------------------
    // 7. ENROLLMENT ASKS THE AMBIENT REALM'S ROSTER OF A SESSION.
    // ---------------------------------------------------------------------
    const inR = inRealm(R, function () {
      return enrollment.sessionPrincipal('realmboss', 'test').admin;
    });
    const svcFromR = inRealm(R, function () {
      return enrollment.sessionPrincipal('svcboss', 'test').admin;
    });
    note(inR === true && svcFromR === false,
         'a portal session in a realm is an enrollment administrator by that ' +
         'realm\'s roster, not by a service administrator\'s name',
         JSON.stringify({ realmboss: inR, svcboss: svcFromR }));

    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    note(false, 'the child ran to the end', e && e.stack);
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'sts-realm-admins-' + process.pid + '-' +
                                     Date.now() + '.json');
  const env = Object.assign({}, process.env, {
    RA_ROOT: ROOT, RA_OUT: out, LOG_LEVEL: 'fatal', STS_LOG_LEVEL: 'fatal',
    STS_SPIFFE_WORKLOAD_SOCKET_ENABLED: 'false',
    STS_SPIFFE_SERVER_SOCKET_ENABLED: 'false' });
  delete env.CONFIG_FILE;
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      cwd: ROOT, env: env, encoding: 'utf8', timeout: 240000,
      maxBuffer: 64 * 1024 * 1024 });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    // The child died before writing its findings; said below with its status.
    findings = null;
  }
  try {
    fs.rmSync(out, { force: true });
  } catch (e) {
    // A temporary file left behind is not a failed assertion.
    log.debug("Caught in run(): " + ((e && e.message) || e));
  }
  if (t.check(Array.isArray(findings),
              'the child process reported its findings',
              'status=' + result.status + ' ' +
              String(result.stderr || '').slice(-2000))) {
    findings.forEach(function (one) { t.check(one.ok, one.what, one.detail); });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'realm_administrators',
  describe: 'a trust realm\'s own administrator roster beside the ' +
            'service\'s: ' +
            'per-realm grants and bootstrap, authority by sign-in realm, the ' +
            'scope table, the realm chooser and enrollment',
  run: run
};
