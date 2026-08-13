'use strict';
//
// File: krb5_principals.js
//
// ---------------------------------------------------------------------------
// The mock KDC's principal database.
//
// A Kerberos KDC is, at bottom, a table of principals and their long-term keys.
// This is that table, held in memory and derived on first use from passwords in
// configuration — because a key committed to a repository is a key, and this
// service is started fresh for every test run anyway.
//
// **The misconfigured principals are the point, not padding.** A debugger is
// judged on how it renders failure, and the failures worth rendering are the ones
// a real deployment produces: an account whose supported encryption types no
// longer overlap with the client's (which in 2026 means RC4 being disabled), an
// account that is locked out, a password that has expired, a principal that does
// not exist, and a clock outside the tolerance. Each of those has an entry here
// so a test can drive it deliberately rather than by breaking something.
//
// Two facts about salt that this file exists to make concrete, because they are
// where an implementation that works against its own mock stops working against
// Active Directory:
//
//  * **The salt is not the principal name.** AD's default for a USER is the realm
//    followed by the sAMAccountName — `EXAMPLE.COMalice` — with no separator and
//    the realm upper case.
//  * **For a COMPUTER account it is a different shape entirely**: the realm, then
//    the literal `host`, then the short name in lower case, then the DNS domain —
//    `EXAMPLE.COMhostws01.example.com`. An implementation that derives the salt
//    from the principal name works until the first machine account, which is
//    exactly the point at which somebody is debugging a service and not a user.
//
// Both are produced here, and the KDC hands whichever applies to the client in
// PA-ETYPE-INFO2. That is the only way a client can know it.
// ---------------------------------------------------------------------------

const kcrypto = require('./krb5_crypto.js');
const prim = require('./krb5_primitives.js');
const { log } = require('./helpers');

const REALM = process.env.KRB5_REALM || 'EXAMPLE.COM';
const DOMAIN = REALM.toLowerCase();

// The etypes this KDC will use at all, strongest first. arcfour is included
// because the workflow has to be able to exercise it — Microsoft is retiring it
// and a debugger whose only story is "that is deprecated" cannot help anybody
// still running it.
const KDC_ETYPES = [18, 17, 20, 19, 23];

// AD's salt for a user account: realm + sAMAccountName, no separator.
function userSalt(realm, name) {
  return realm + name;
}

// AD's salt for a computer account: realm + "host" + short name (lower case) +
// the DNS domain. Nothing about this is derivable from the principal string, which
// is why ETYPE-INFO2 exists.
function hostSalt(realm, shortName, dnsDomain) {
  return realm + 'host' + String(shortName).toLowerCase() + '.' + String(dnsDomain).toLowerCase();
}

// The table. `name` is the principal's components; everything else is the
// behaviour a test may want to drive.
const DEFINITIONS = [
  {
    name: ['krbtgt', REALM],
    type: 2,                                   // NT-SRV-INST
    password: process.env.KRB5_KRBTGT_PASSWORD || 'krbtgt-mock-password',
    salt: userSalt(REALM, 'krbtgt'),
    description: 'the ticket-granting service, whose key seals every TGT'
  },
  {
    name: ['alice'],
    type: 1,                                   // NT-PRINCIPAL
    password: 'hunter2',
    salt: userSalt(REALM, 'alice'),
    description: 'an ordinary user; pre-authentication required, as Active Directory requires it'
  },
  {
    name: ['bob'],
    type: 1,
    password: 'correct horse battery staple',
    salt: userSalt(REALM, 'bob'),
    description: 'a second user, for impersonation and delegation cases'
  },
  {
    // The account whose UF_DONT_REQUIRE_PREAUTH is set. A KDC answers its AS-REQ
    // with a ticket rather than with KDC_ERR_PREAUTH_REQUIRED, which is worth
    // being able to SEE: it is the difference between the two-message dance and
    // the one-message one, and a client has to handle both.
    name: ['noreauth'],
    type: 1,
    password: 'no-preauth-here',
    salt: userSalt(REALM, 'noreauth'),
    requiresPreAuth: false,
    description: 'pre-authentication NOT required, so the AS-REQ is answered directly'
  },
  {
    name: ['locked'],
    type: 1,
    password: 'irrelevant',
    salt: userSalt(REALM, 'locked'),
    revoked: true,
    description: 'a disabled or locked-out account (KDC_ERR_CLIENT_REVOKED)'
  },
  {
    name: ['expired'],
    type: 1,
    password: 'stale-password',
    salt: userSalt(REALM, 'expired'),
    passwordExpired: true,
    description: 'a password past its expiry (KDC_ERR_KEY_EXPIRED)'
  },
  {
    // The 2026 case. An account whose msDS-SupportedEncryptionTypes has had RC4
    // removed will refuse a client that offers only RC4, and the error is
    // KDC_ERR_ETYPE_NOSUPP — which reads as "the KDC is broken" unless you know
    // what it means.
    name: ['aesonly'],
    type: 1,
    password: 'aes-please',
    salt: userSalt(REALM, 'aesonly'),
    etypes: [18, 17],
    description: 'AES only — offers no RC4, which is what a hardened AD account looks like'
  },
  {
    // ...and its opposite, an old account that has only ever had an RC4 key. On a
    // Windows Server 2025 domain controller this is the one that stops working.
    name: ['rc4only'],
    type: 1,
    password: 'legacy',
    salt: userSalt(REALM, 'rc4only'),
    etypes: [23],
    description: 'arcfour-hmac-md5 only — the legacy account that a 2025 baseline breaks'
  },
  {
    // A computer account, present so the host-shaped salt is exercised by
    // something rather than only described.
    name: ['host', 'ws01.' + DOMAIN],
    type: 3,                                   // NT-SRV-HST
    password: 'machine-account-password',
    salt: hostSalt(REALM, 'ws01', DOMAIN),
    description: 'a computer account, whose salt is host-shaped rather than name-shaped'
  },
  {
    // The service a ticket gets requested FOR in phase 3.
    name: ['HTTP', 'web.' + DOMAIN],
    type: 3,
    password: 'service-account-password',
    salt: userSalt(REALM, 'HTTPweb'),
    okAsDelegate: true,
    description: 'an HTTP service principal, flagged ok-as-delegate'
  }
];

// Keys are derived once, lazily, and cached: string-to-key is thousands of PBKDF2
// rounds per etype per principal, and deriving them all at startup would make the
// service slow to start for keys most runs never use.
const principals = new Map();

function keyOf(principal) {
  return principal.name.join('/');
}

function register(def) {
  const principal = {
    name: def.name,
    type: def.type,
    realm: REALM,
    password: def.password,
    salt: def.salt,
    etypes: def.etypes || KDC_ETYPES.slice(),
    requiresPreAuth: def.requiresPreAuth !== false,
    revoked: !!def.revoked,
    passwordExpired: !!def.passwordExpired,
    okAsDelegate: !!def.okAsDelegate,
    description: def.description,
    kvno: 3,
    keys: new Map()
  };
  principals.set(keyOf(principal), principal);
  return principal;
}

DEFINITIONS.forEach(register);
log.info('krb5: principal database for realm ' + REALM + ' — ' +
  Array.from(principals.keys()).join(', '));

function find(nameComponents) {
  if (!nameComponents || !nameComponents.length) return null;
  return principals.get(nameComponents.join('/')) || null;
}

// The long-term key for one etype. Derived on demand and cached.
async function longTermKey(principal, etype) {
  if (principal.keys.has(etype)) return principal.keys.get(etype);
  const profile = kcrypto.etypeById(etype);
  const key = await profile.stringToKey(principal.password, prim.utf8(principal.salt), null);
  principal.keys.set(etype, key);
  log.debug('krb5: derived the ' + profile.name + ' key for ' + keyOf(principal) +
            ' with salt ' + JSON.stringify(principal.salt));
  return key;
}

// What this principal can offer, in the KDC's preference order rather than the
// order the definition happened to list.
function supportedEtypes(principal) {
  return KDC_ETYPES.filter(function (id) { return principal.etypes.indexOf(id) !== -1; });
}

// Negotiate: the FIRST etype the client asked for that this principal supports.
// The client's order is its preference and a KDC honours it — which is why the
// debugger's etype list is ordered and why that order is worth displaying.
function chooseEtype(principal, requested) {
  const supported = supportedEtypes(principal);
  for (const id of requested || []) {
    if (supported.indexOf(id) !== -1) return id;
  }
  return null;
}

// The ETYPE-INFO2 entries for a principal: one per supported etype, each with the
// salt the client must use. arcfour carries NO salt, and that absence is
// meaningful — its string-to-key ignores the salt entirely.
function etypeInfo2For(principal) {
  return supportedEtypes(principal).map(function (id) {
    if (id === 23) return { etype: id, salt: null, s2kparams: null };
    const profile = kcrypto.etypeById(id);
    const iterations = profile.defaultIterations;
    return {
      etype: id,
      salt: principal.salt,
      s2kparams: new Uint8Array([
        (iterations >>> 24) & 255, (iterations >>> 16) & 255,
        (iterations >>> 8) & 255, iterations & 255])
    };
  });
}

module.exports = {
  REALM: REALM,
  DOMAIN: DOMAIN,
  KDC_ETYPES: KDC_ETYPES,
  find: find,
  all: function () { return Array.from(principals.values()); },
  longTermKey: longTermKey,
  supportedEtypes: supportedEtypes,
  chooseEtype: chooseEtype,
  etypeInfo2For: etypeInfo2For,
  userSalt: userSalt,
  hostSalt: hostSalt
};
