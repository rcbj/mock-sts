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

// ---------------------------------------------------------------------------
// The domain SID, and the account data that goes into the PAC.
//
// A Kerberos ticket says WHO you are; a Windows service authorizes on the groups in
// the PAC. So every principal here carries the identity a real AD account would —
// a RID, a primary group, group memberships and UserAccountControl flags — and the
// KDC assembles that into a PAC ([MS-PAC]) inside each ticket it issues. Without it
// the workflow can show a ticket for alice and nothing at all about what alice may
// do, which is the question people actually arrive with.
//
// The domain SID is a fixed made-up one. Real ones are random per domain, and the
// only thing that matters here is that it is the same in every ticket, since a
// service compares SIDs and not names.
// ---------------------------------------------------------------------------
const DOMAIN_SID = process.env.KRB5_DOMAIN_SID || 'S-1-5-21-1004336348-1177238915-682003330';

// ---------------------------------------------------------------------------
// The second realm, and the trust between them.
//
// A cross-realm trust is not a configuration flag: it is a SHARED KEY, held as an
// ordinary principal named krbtgt/<the other realm> in each realm's database. That is
// the whole mechanism, and it is why a referral works at all — the issuing KDC seals a
// ticket-granting ticket with a key the OTHER realm's KDC can open, and nothing else
// passes between them.
//
// This mock serves both realms from one process, which a real deployment never does.
// The simplification is worth naming because it hides one class of problem (finding the
// other realm's KDC, which is DNS and SRV records) and none of the protocol.
//
// Its own domain SID differs, which is the point of having it: SID filtering across a
// trust is about whose domain a SID belongs to.
// ---------------------------------------------------------------------------
const TRUSTED_REALM = process.env.KRB5_TRUSTED_REALM || 'PARTNER.COM';
const TRUSTED_DOMAIN = TRUSTED_REALM.toLowerCase();
const TRUST_PASSWORD = process.env.KRB5_TRUST_PASSWORD || 'inter-realm-trust-password';
const TRUSTED_DOMAIN_SID = process.env.KRB5_TRUSTED_DOMAIN_SID ||
  'S-1-5-21-2035427030-2118130302-1178042555';

// [MS-SAMR] section 2.2.1.13's USER_ACCOUNT codes — NOT the LDAP userAccountControl
// bits, which share most of these names and none of their values.
const UAC = {
  NORMAL_ACCOUNT: 0x00000010,
  WORKSTATION_TRUST_ACCOUNT: 0x00000080,
  SERVER_TRUST_ACCOUNT: 0x00000100,
  DONT_EXPIRE_PASSWORD: 0x00000200,
  ACCOUNT_DISABLED: 0x00000001,
  ACCOUNT_AUTO_LOCKED: 0x00000400,
  TRUSTED_FOR_DELEGATION: 0x00002000,
  NOT_DELEGATED: 0x00004000,
  DONT_REQUIRE_PREAUTH: 0x00010000,
  PASSWORD_EXPIRED: 0x00020000,
  TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION: 0x00040000,
  USE_DES_KEY_ONLY: 0x00008000
};

// Well-known RIDs. 513 is Domain Users, which every account belongs to.
const RID = {
  DOMAIN_USERS: 513,
  DOMAIN_ADMINS: 512,
  DOMAIN_COMPUTERS: 515,
  DOMAIN_CONTROLLERS: 516,
  PROTECTED_USERS: 525
};

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
    description: 'an ordinary user; pre-authentication required, as Active Directory requires it',
    pac: {
      rid: 1104,
      fullName: 'Alice Example',
      groups: [RID.DOMAIN_USERS, RID.DOMAIN_ADMINS],
      userAccountControl: UAC.NORMAL_ACCOUNT,
      // The two well-known SIDs that record HOW an identity was established. A real
      // AD puts the first one in every PAC it issues from a password logon, and a
      // service can refuse an identity the KDC merely asserted — which is why they
      // are here rather than being tidied away as noise.
      extraSids: ['S-1-18-1', 'S-1-5-11']
    }
  },
  {
    name: ['bob'],
    type: 1,
    password: 'correct horse battery staple',
    salt: userSalt(REALM, 'bob'),
    description: 'a second user, for impersonation and delegation cases',
    pac: {
      rid: 1105,
      fullName: 'Bob Example',
      groups: [RID.DOMAIN_USERS],
      userAccountControl: UAC.NORMAL_ACCOUNT,
      extraSids: ['S-1-18-1', 'S-1-5-11']
    }
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
    description: 'pre-authentication NOT required, so the AS-REQ is answered directly',
    pac: {
      rid: 1106,
      groups: [RID.DOMAIN_USERS],
      // The flag that MAKES this account behave differently, in the PAC as well as in
      // the KDC's behaviour. Two views of one setting: a debugger should show both,
      // because seeing DONT_REQUIRE_PREAUTH in the PAC is what explains the exchange
      // the reader just watched happen in one message instead of two.
      userAccountControl: UAC.NORMAL_ACCOUNT | UAC.DONT_REQUIRE_PREAUTH,
      extraSids: ['S-1-18-1', 'S-1-5-11']
    }
  },
  {
    name: ['locked'],
    type: 1,
    password: 'irrelevant',
    salt: userSalt(REALM, 'locked'),
    revoked: true,
    description: 'a disabled or locked-out account (KDC_ERR_CLIENT_REVOKED)',
    pac: {
      rid: 1107,
      groups: [RID.DOMAIN_USERS],
      userAccountControl: UAC.NORMAL_ACCOUNT | UAC.ACCOUNT_DISABLED | UAC.ACCOUNT_AUTO_LOCKED
    }
  },
  {
    name: ['expired'],
    type: 1,
    password: 'stale-password',
    salt: userSalt(REALM, 'expired'),
    passwordExpired: true,
    description: 'a password past its expiry (KDC_ERR_KEY_EXPIRED)',
    pac: {
      rid: 1108,
      groups: [RID.DOMAIN_USERS],
      userAccountControl: UAC.NORMAL_ACCOUNT | UAC.PASSWORD_EXPIRED,
      passwordMustChange: new Date('2020-01-01T00:00:00Z')
    }
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
    description: 'AES only — offers no RC4, which is what a hardened AD account looks like',
    pac: {
      rid: 1109,
      groups: [RID.DOMAIN_USERS, RID.PROTECTED_USERS],
      userAccountControl: UAC.NORMAL_ACCOUNT
    }
  },
  {
    // ...and its opposite, an old account that has only ever had an RC4 key. On a
    // Windows Server 2025 domain controller this is the one that stops working.
    name: ['rc4only'],
    type: 1,
    password: 'legacy',
    salt: userSalt(REALM, 'rc4only'),
    etypes: [23],
    description: 'arcfour-hmac-md5 only — the legacy account that a 2025 baseline breaks',
    pac: {
      rid: 1110,
      groups: [RID.DOMAIN_USERS],
      userAccountControl: UAC.NORMAL_ACCOUNT | UAC.USE_DES_KEY_ONLY
    }
  },
  {
    // A computer account, present so the host-shaped salt is exercised by
    // something rather than only described.
    name: ['host', 'ws01.' + DOMAIN],
    type: 3,                                   // NT-SRV-HST
    password: 'machine-account-password',
    salt: hostSalt(REALM, 'ws01', DOMAIN),
    description: 'a computer account, whose salt is host-shaped rather than name-shaped',
    pac: {
      rid: 1111,
      // A machine account is not a user: its primary group is Domain Computers and
      // its UAC says WORKSTATION_TRUST_ACCOUNT. An implementation that assumes every
      // PAC describes a person gets this wrong in a way no user account reveals.
      primaryGroupRid: RID.DOMAIN_COMPUTERS,
      groups: [RID.DOMAIN_COMPUTERS],
      userAccountControl: UAC.WORKSTATION_TRUST_ACCOUNT
    }
  },
  {
    // The service a ticket gets requested FOR in phase 3.
    name: ['HTTP', 'web.' + DOMAIN],
    type: 3,
    password: 'service-account-password',
    salt: userSalt(REALM, 'HTTPweb'),
    okAsDelegate: true,
    description: 'an HTTP service principal, flagged ok-as-delegate'
  },
  {
    // ---------------------------------------------------------------------------
    // THE TRUST. This one principal IS the cross-realm relationship.
    //
    // krbtgt/PARTNER.COM@EXAMPLE.COM: the inter-realm ticket-granting account. When a
    // client of EXAMPLE.COM asks for a service in PARTNER.COM, this realm's KDC has no
    // such service and does NOT refuse — it issues a ticket-granting ticket for
    // krbtgt/PARTNER.COM sealed with THIS key, and the client presents that to the other
    // realm's KDC. Both realms hold the same key, which is what makes it openable there
    // and nowhere else.
    //
    // Its salt is name-shaped like any other account, and its etypes are deliberately
    // AES-only: a trust that still had an RC4 key is the configuration that breaks on a
    // 2025 domain controller, and the KDC's etype negotiation for a referral has to be
    // driven by THIS account rather than by the service the client actually asked for.
    // ---------------------------------------------------------------------------
    name: ['krbtgt', TRUSTED_REALM],
    type: 2,
    password: TRUST_PASSWORD,
    salt: userSalt(REALM, 'krbtgt'),
    etypes: [18, 17],
    description: 'the inter-realm trust with ' + TRUSTED_REALM + ' — a shared key, held as a principal',
    pac: {
      rid: 1112,
      groups: [RID.DOMAIN_USERS],
      // ok-as-delegate on the ticket and TRUSTED_FOR_DELEGATION in the PAC are the
      // same setting seen from the two ends: [MS-SAMR] says this bit is what makes
      // the KDC set that flag. Keeping them consistent here means the workflow can
      // show the cause beside the effect.
      userAccountControl: UAC.NORMAL_ACCOUNT | UAC.TRUSTED_FOR_DELEGATION |
        UAC.DONT_EXPIRE_PASSWORD
    }
  }
];

// The trusted realm's own database. It holds the same trust key (the other half of the
// relationship), its own ticket-granting service, and a service to reach — which is the
// destination a referral is FOR.
// There is deliberately NO second copy of the trust key here.
//
// The inter-realm account is krbtgt/PARTNER.COM@EXAMPLE.COM — one principal, whose realm
// is the ISSUING realm — and both KDCs consult that same entry: the issuer to seal the
// referral, and the target because the arriving ticket's own `realm` field says
// EXAMPLE.COM, which is what handleTgsReq looks it up by. Holding a second copy under
// PARTNER.COM would be two secrets that have to stay equal, and the failure when they
// drift is "the ticket does not decrypt" at the second KDC — a message about a ticket for
// a problem about a trust. One entry cannot drift from itself.
//
// What PARTNER.COM does need is its OWN ticket-granting service, whose key is a different
// secret from the trust: it signs the PAC and seals tickets for its own services. Giving
// it the trust password would have made the two indistinguishable, and every assertion
// about which key signed what would have passed for the wrong reason.
const TRUSTED_DEFINITIONS = [
  {
    name: ['krbtgt', TRUSTED_REALM],
    type: 2,
    password: process.env.KRB5_TRUSTED_KRBTGT_PASSWORD || 'partner-krbtgt-password',
    salt: userSalt(TRUSTED_REALM, 'krbtgt'),
    realm: TRUSTED_REALM,
    description: TRUSTED_REALM + "'s own ticket-granting service — NOT the trust key"
  },
  {
    // A user native to the trusted realm. Without one, the second realm is only ever a
    // referral TARGET and the code path where a ticket-granting ticket is looked up in
    // its own realm is never exercised — krbtgt/PARTNER.COM exists in both databases, so
    // a lookup that defaults to the local realm finds the TRUST key instead of this
    // realm's own, and every ticket issued inside PARTNER.COM would be sealed with the
    // wrong secret. A referral test cannot catch that, because there the ticket's realm
    // and the default happen to agree.
    name: ['carol'],
    type: 1,
    password: 'partner-user-password',
    salt: userSalt(TRUSTED_REALM, 'carol'),
    realm: TRUSTED_REALM,
    description: 'a user in ' + TRUSTED_REALM + ', so that realm is a realm and not just a target',
    pac: {
      rid: 2104,
      fullName: 'Carol Partner',
      groups: [RID.DOMAIN_USERS],
      userAccountControl: UAC.NORMAL_ACCOUNT,
      extraSids: ['S-1-18-1', 'S-1-5-11']
    }
  },
  {
    name: ['HTTP', 'app.' + TRUSTED_DOMAIN],
    type: 3,
    password: 'partner-service-password',
    salt: userSalt(TRUSTED_REALM, 'HTTPapp'),
    realm: TRUSTED_REALM,
    description: 'a service in ' + TRUSTED_REALM + ', reachable only by following a referral',
    pac: {
      rid: 2101,
      groups: [RID.DOMAIN_USERS],
      userAccountControl: UAC.NORMAL_ACCOUNT
    }
  }
];

// Which realms this process answers for. A real KDC answers for exactly one; this one
// answers for two so the whole referral chase is reachable without a second container.
function realmsServed() {
  return [REALM, TRUSTED_REALM];
}

function domainSidFor(realm) {
  return realm === TRUSTED_REALM ? TRUSTED_DOMAIN_SID : DOMAIN_SID;
}

// Which realm a service principal belongs to, decided from its HOST NAME.
//
// This is the piece that does not look like protocol and is: a client asks for
// HTTP/app.partner.com without knowing which realm that is, and its own KDC has to work
// it out. Windows does it by looking the SPN up in the forest and, failing that, by
// matching the host's DNS suffix against the trusted domains — which is exactly the
// suffix match below, and exactly why a service whose DNS name does not match its realm
// is such a persistent source of "the KDC says the principal is unknown" on hosts that
// plainly exist.
//
// Returns null when nothing claims it, which is a genuine KDC_ERR_S_PRINCIPAL_UNKNOWN
// rather than a referral.
function realmForService(nameComponents) {
  if (!nameComponents || nameComponents.length < 2) return null;
  const host = String(nameComponents[nameComponents.length - 1]).toLowerCase();
  if (host === TRUSTED_DOMAIN || host.endsWith('.' + TRUSTED_DOMAIN)) return TRUSTED_REALM;
  if (host === DOMAIN || host.endsWith('.' + DOMAIN)) return REALM;
  return null;
}

// Keys are derived once, lazily, and cached: string-to-key is thousands of PBKDF2
// rounds per etype per principal, and deriving them all at startup would make the
// service slow to start for keys most runs never use.
const principals = new Map();

// The map key carries the REALM, because two realms are served here and
// krbtgt/PARTNER.COM exists in BOTH of them with different meanings — in EXAMPLE.COM it
// is the trust, and in PARTNER.COM it is that realm's own ticket-granting service. Keyed
// by name alone, the second registration would silently overwrite the first and every
// cross-realm ticket would be sealed with the wrong key.
function keyOf(principal) {
  return principal.name.join('/') + '@' + principal.realm;
}

function register(def) {
  const principal = {
    name: def.name,
    type: def.type,
    realm: def.realm || REALM,
    password: def.password,
    salt: def.salt,
    etypes: def.etypes || KDC_ETYPES.slice(),
    requiresPreAuth: def.requiresPreAuth !== false,
    revoked: !!def.revoked,
    passwordExpired: !!def.passwordExpired,
    okAsDelegate: !!def.okAsDelegate,
    description: def.description,
    // The PAC identity, with the parts every account shares defaulted here rather
    // than repeated nine times. An account with no `pac` block still gets one, so a
    // principal added later cannot silently produce PAC-less tickets.
    pac: Object.assign({
      rid: 1100,
      primaryGroupRid: RID.DOMAIN_USERS,
      groups: [RID.DOMAIN_USERS],
      userAccountControl: UAC.NORMAL_ACCOUNT,
      extraSids: [],
      fullName: null,
      passwordMustChange: null
    }, def.pac || {}),
    kvno: 3,
    keys: new Map()
  };
  principals.set(keyOf(principal), principal);
  return principal;
}

DEFINITIONS.forEach(register);
TRUSTED_DEFINITIONS.forEach(register);
log.info('krb5: principal database for realm ' + REALM + ' — ' +
  Array.from(principals.keys()).join(', '));

// `realm` defaults to this KDC's own, so every existing single-realm caller keeps
// working unchanged. A caller that means "in the realm this ticket came from" has to
// say so — and in handleTgsReq that is the difference between opening a cross-realm
// ticket-granting ticket and failing to.
function find(nameComponents, realm) {
  if (!nameComponents || !nameComponents.length) return null;
  return principals.get(nameComponents.join('/') + '@' + (realm || REALM)) || null;
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
  hostSalt: hostSalt,
  DOMAIN_SID: DOMAIN_SID,
  TRUSTED_REALM: TRUSTED_REALM,
  TRUSTED_DOMAIN: TRUSTED_DOMAIN,
  TRUSTED_DOMAIN_SID: TRUSTED_DOMAIN_SID,
  realmsServed: realmsServed,
  domainSidFor: domainSidFor,
  realmForService: realmForService,
  UAC: UAC,
  RID: RID
};
