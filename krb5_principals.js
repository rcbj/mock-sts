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
//
// **Anybody can authenticate, and everybody's password is the same.** See
// USER_PASSWORD below for why Kerberos cannot simply check no password the way the
// rest of this service does not, and findOrCreateUser() for the accounts that are
// not in the table until somebody asks for one.
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
// One password, and an account for anybody who asks.
//
// Everything else in this service checks no password at all — the username typed at
// /oauth2/login becomes the identity and that is the end of it. Kerberos cannot be
// made to work that way, and the reason is structural rather than a decision: the
// password IS the key. Pre-authentication is a timestamp encrypted under it, and the
// AS-REP's enc-part is encrypted under it too, so a KDC that accepted any password
// would still have to pick one to encrypt the reply with, and a client that used a
// different one could not read the ticket it was sent.
//
// So the nearest thing the protocol allows is what happens here: ONE password, shared
// by every user account, and an account for every username that turns up.
//
//  * Every USER principal in the table below has this password. None of them carries a
//    secret of its own any more — the accounts differ in the BEHAVIOUR they exist to
//    drive (locked, expired, aesonly, rc4only, sensitive, noreauth), which is what they
//    were ever for, and a test no longer has to look a password up before it can drive
//    one.
//  * A username that is not in the table at all is created on first sight by
//    findOrCreateUser(), with AD's user-shaped salt and a PAC identity of its own.
//
// SERVICE, computer and krbtgt principals keep their own distinct passwords, and that
// is deliberate: nobody types them, and krbtgt/EXAMPLE.COM, krbtgt/PARTNER.COM and the
// trust have to hold three DIFFERENT secrets or every assertion about which key sealed
// which ticket would pass for the wrong reason.
// ---------------------------------------------------------------------------
const USER_PASSWORD = process.env.KRB5_USER_PASSWORD || 'password!';

// The usernames that stay unknown, so KDC_ERR_C_PRINCIPAL_UNKNOWN is still reachable.
//
// Creating an account for whoever asks removes the obvious way to produce that error —
// name somebody who does not exist — and it is one of the errors most worth being able
// to produce on purpose, because a client that renders it as "wrong password" sends a
// person off to reset a password that was never the problem. These names are therefore
// refused rather than created, and they are configurable so a test can name its own.
const RESERVED_UNKNOWN = String(process.env.KRB5_UNKNOWN_USERS || 'nosuchuser,nobody')
  .split(',')
  .map(function (name) { return name.trim().toLowerCase(); })
  .filter(function (name) { return name.length > 0; });

// ---------------------------------------------------------------------------
// THE HOSTS THIS MOCK WILL BE A SERVICE FOR, and why services are created on
// demand here when findOrCreateUser()'s own header argues they must not be.
//
// That argument stands and is not being overturned: a KDC that invents a service
// hands back a ticket sealed with a key the service does not hold, and the
// failure then surfaces at the AP exchange as "decrypt integrity check failed" —
// the same message a genuinely wrong key gives, pointing nowhere near the missing
// SPN. What removes it is that the invented key is NOT unknown to the service
// here: this process is both the KDC and the acceptor, krb5_service.js looks the
// presented SPN up in this same table, and so a ticket for a host created on
// demand opens with the key that sealed it. The objection was never to creating
// the principal; it was to creating one nobody can decrypt.
//
// WHY IT IS NEEDED. A client derives the SPN from the URL's host — that is what
// RFC 4559 clients do, browsers included — so it asks for HTTP/localhost,
// HTTP/sts or HTTP/127.0.0.1 depending on how this stack was reached, while the
// configured account is HTTP/web.example.com. Every one of those was
// KDC_ERR_S_PRINCIPAL_UNKNOWN, which is a real error with a real cause and
// exactly the wrong first experience of a workflow that is trying to teach the
// protocol rather than this mock's principal table.
//
// WHAT STAYS REFUSED, because the error has to remain reachable on purpose:
// anything whose host matches none of these entries. `HTTP/app.elsewhere.invalid`
// is the case tests/krb5_tgs_ap.js relies on as the control for its cross-realm
// referrals, and it must keep failing. So must a name in the TRUSTED realm's
// domain, which is answered with a REFERRAL long before this is reached — see
// realmForService() and handleTgsReq().
//
// The matching rule is one list with one rule: a host matches an entry when it IS
// that entry or ends with a dot and that entry. So `example.com` covers
// `web.example.com` and `anything.example.com`, and a bare `localhost` or `sts`
// covers only itself. The default list is the realm's own domain plus the three
// names this project's own defaults reach the mock by; KRB5_SERVICE_DOMAINS
// replaces it entirely, and setting it to an empty string restores the old
// behaviour of creating nothing.
// ---------------------------------------------------------------------------
const SERVICE_DOMAINS = String(process.env.KRB5_SERVICE_DOMAINS === undefined
    ? DOMAIN + ',localhost,sts,127.0.0.1' : process.env.KRB5_SERVICE_DOMAINS)
  .split(',')
  .map(function (name) { return name.trim().toLowerCase(); })
  .filter(function (name) { return name.length > 0; });

// One password for every service created on demand, and it is PUBLISHED by
// GET /krb5/principals for the same reason USER_PASSWORD is: a debugger whose
// accounts are unusable without reading the source is worse than one that says
// what they are. It is what lets a reader decrypt a service ticket this mock
// issued — the ticket's own EncTicketPart, the PAC inside it, the four signatures
// — which is otherwise the one thing a client can never see. The CONFIGURED
// service accounts keep their own separate passwords, so nothing about this
// weakens an assertion about which key sealed which ticket.
const AUTO_SERVICE_PASSWORD = process.env.KRB5_AUTO_SERVICE_PASSWORD ||
    'auto-service-password';

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
//
// A USER entry carries no `password`: register() gives it USER_PASSWORD, the one every
// user here shares. A service, computer or krbtgt entry names its own.
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
    // "Account is sensitive and cannot be delegated" — [MS-SAMR]'s USER_ACCOUNT code
    // NOT_DELEGATED (0x4000). It is the ONE control that stops unconstrained delegation
    // taking a privileged account's ticket-granting ticket, and it lives on the account
    // being protected rather than on any service. A KDC must refuse to issue this account
    // a forwardable ticket at all, which is what makes the protection work no matter which
    // service the user visits.
    name: ['sensitive'],
    type: 1,
    salt: userSalt(REALM, 'sensitive'),
    notDelegated: true,
    description: 'flagged sensitive and cannot be delegated — the KDC refuses it a forwardable ' +
                 'ticket, so no service can forward its TGT',
    pac: {
      rid: 1130,
      groups: [RID.DOMAIN_USERS, RID.DOMAIN_ADMINS, RID.PROTECTED_USERS],
      userAccountControl: UAC.NORMAL_ACCOUNT | UAC.NOT_DELEGATED
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
    // The ordinary service a ticket gets requested for — the AP exchange's target, and the
    // one used as an UNAUTHORIZED delegation target by the tests, since nothing permits
    // the front end to reach it.
    name: ['HTTP', 'web.' + DOMAIN],
    type: 3,
    password: 'service-account-password',
    salt: userSalt(REALM, 'HTTPweb'),
    okAsDelegate: true,
    description: 'an HTTP service principal, flagged ok-as-delegate'
  },
  {
    // ---------------------------------------------------------------------------
    // DELEGATION, configured two DIFFERENT WAYS on purpose.
    //
    // `frontend` is trusted for CLASSIC constrained delegation: the permission lives on
    // the FRONT-END account, as msDS-AllowedToDelegateTo, and only a domain admin can set
    // it. `backend-rbcd` authorizes RESOURCE-BASED constrained delegation: the permission
    // lives on the BACK-END account, as msDS-AllowedToActOnBehalfOfOtherIdentity, and
    // whoever controls that object can set it themselves.
    //
    // That difference is the entire security story of RBCD, and it is why both are here.
    // Same protocol messages, same KDC options, opposite direction of trust — and the
    // second one turns "I can write to this computer object" into "I can reach this
    // service as anybody".
    // ---------------------------------------------------------------------------
    name: ['HTTP', 'frontend.' + DOMAIN],
    type: 3,
    password: 'frontend-service-password',
    salt: userSalt(REALM, 'HTTPfrontend'),
    okAsDelegate: true,
    // TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION is what lets it get a FORWARDABLE ticket out
    // of S4U2Self — the protocol-transition half. Without it S4U2Self still works and
    // returns a ticket that is not forwardable, so classic S4U2Proxy then fails for a
    // reason that looks nothing like a missing flag on the front-end account.
    trustedToAuthenticateForDelegation: true,
    // Classic constrained delegation: the list of services this one may reach as anybody.
    // Note it names a SERVICE, not an account — and the SPN has to match exactly.
    allowedToDelegateTo: ['HTTP/backend.' + DOMAIN],
    description: 'a front-end service trusted for CLASSIC constrained delegation (S4U2Self + ' +
                 'S4U2Proxy to HTTP/backend), and for protocol transition',
    pac: {
      rid: 1120,
      groups: [RID.DOMAIN_USERS],
      userAccountControl: UAC.NORMAL_ACCOUNT | UAC.TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION |
        UAC.DONT_EXPIRE_PASSWORD
    }
  },
  {
    name: ['HTTP', 'backend.' + DOMAIN],
    type: 3,
    password: 'backend-service-password',
    salt: userSalt(REALM, 'HTTPbackend'),
    description: 'the back-end reached by CLASSIC constrained delegation — it authorizes ' +
                 'nothing itself; the permission is on the front end',
    pac: { rid: 1121, groups: [RID.DOMAIN_USERS], userAccountControl: UAC.NORMAL_ACCOUNT }
  },
  {
    // The same classic configuration as `frontend` MINUS
    // TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION. This account exists because that flag's
    // absence is invisible where it is set: S4U2Self still succeeds and returns a ticket
    // that simply is not forwardable, and classic S4U2Proxy then fails a step later
    // complaining about the evidence. Two accounts differing in exactly one attribute is
    // the only way to show which attribute did it.
    name: ['HTTP', 'notrusted.' + DOMAIN],
    type: 3,
    password: 'notrusted-service-password',
    salt: userSalt(REALM, 'HTTPnotrusted'),
    trustedToAuthenticateForDelegation: false,
    allowedToDelegateTo: ['HTTP/backend.' + DOMAIN],
    description: 'allowed to delegate to HTTP/backend but NOT trusted for protocol transition, ' +
                 'so its S4U2Self ticket is not forwardable and classic S4U2Proxy fails',
    pac: { rid: 1123, groups: [RID.DOMAIN_USERS], userAccountControl: UAC.NORMAL_ACCOUNT }
  },
  {
    name: ['HTTP', 'rbcd.' + DOMAIN],
    type: 3,
    password: 'rbcd-service-password',
    salt: userSalt(REALM, 'HTTPrbcd'),
    // RESOURCE-based: this account names who may act on ITS behalf. The list is on the
    // TARGET, which is the inversion that matters.
    allowedToActOnBehalfOf: ['HTTP/frontend.' + DOMAIN],
    description: 'a back-end that authorizes RESOURCE-BASED constrained delegation itself, ' +
                 'naming HTTP/frontend as permitted to act on its behalf',
    pac: { rid: 1122, groups: [RID.DOMAIN_USERS], userAccountControl: UAC.NORMAL_ACCOUNT }
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

// RIDs for the accounts findOrCreateUser() makes, from 5000 up. Well clear of the
// configured ones (the 1100s here, the 2100s in PARTNER.COM) on purpose: a service
// authorizing on the PAC sees a SID and nothing else, so the range is the only way to
// tell an account that was configured from one that turned up at runtime.
const AUTO_RID_BASE = 5000;
let autoRidNext = AUTO_RID_BASE;

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
    // A user entry names no password; it gets the one every user shares. A service,
    // computer or krbtgt entry names its own and keeps it — see USER_PASSWORD.
    password: def.password || USER_PASSWORD,
    salt: def.salt,
    etypes: def.etypes || KDC_ETYPES.slice(),
    requiresPreAuth: def.requiresPreAuth !== false,
    revoked: !!def.revoked,
    passwordExpired: !!def.passwordExpired,
    okAsDelegate: !!def.okAsDelegate,
    // Delegation, kept as two SEPARATE lists because they are configured on opposite
    // accounts and conflating them would hide the only thing about RBCD worth knowing.
    trustedToAuthenticateForDelegation: !!def.trustedToAuthenticateForDelegation,
    notDelegated: !!def.notDelegated,
    allowedToDelegateTo: def.allowedToDelegateTo || [],
    allowedToActOnBehalfOf: def.allowedToActOnBehalfOf || [],
    description: def.description,
    // Whether findOrCreateUser() made this one at runtime rather than it being
    // configured. Reported by GET /krb5/principals, because a table that grows while a
    // person is reading it is confusing unless it says which entries did that.
    autoCreated: !!def.autoCreated,
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

// ---------------------------------------------------------------------------
// The account for whoever asks: find(), and create the user if there is nothing there.
//
// This is what makes "any username authenticates" true, and it is deliberately NOT what
// find() does, because the difference between the two is the difference between a user
// and a service:
//
//  * A CLIENT principal is created. That is the AS exchange's cname, and the user
//    S4U2Self names — the two places where a person or a front-end says who somebody is.
//  * A SERVICE principal is not, and must not be. KDC_ERR_S_PRINCIPAL_UNKNOWN for a
//    service nobody registered is the most common Kerberos failure there is (a missing
//    or misspelled SPN), and a KDC that invented the service instead would hand back a
//    ticket sealed with a key the service does not hold — a failure that then surfaces
//    at the AP exchange as "decrypt integrity check failed", which is the same message a
//    genuinely wrong key gives and points nowhere near the missing SPN.
//
// The shape of the name is what tells them apart, which is exactly how Kerberos itself
// distinguishes them: one component is a user, two or more is service/host. So only a
// single-component name is created here.
//
// Names are compared exactly, so `Alice` and `alice` are two accounts with two salts.
// That is MIT's behaviour rather than AD's (AD folds case on the sAMAccountName), and it
// is left alone because a case-sensitive mock cannot teach a client the habit of
// assuming case folding that MIT realms will then not honour.
//
// The map grows by one entry per distinct username seen, and nothing evicts. Bounded in
// practice by a process that is restarted for every test run, and each entry is a name,
// a salt and lazily-derived keys.
// ---------------------------------------------------------------------------
function findOrCreateUser(nameComponents, realm) {
  log.debug('Entering findOrCreateUser().');
  const inRealm = realm || REALM;
  const existing = find(nameComponents, inRealm);
  if (existing) {
    log.debug('Leaving findOrCreateUser(). ' + keyOf(existing) + ' was already known.');
    return existing;
  }
  if (realmsServed().indexOf(inRealm) === -1) {
    // Not our realm, so not our account to invent. handleAsReq refuses a foreign realm
    // before it gets here; this is for any caller that does not.
    log.debug('Leaving findOrCreateUser(). ' + inRealm + ' is not a realm this KDC serves.');
    return null;
  }
  if (!nameComponents || nameComponents.length !== 1 || !nameComponents[0]) {
    log.debug('Leaving findOrCreateUser(). ' + (nameComponents || []).join('/') +
      ' is service-shaped, and services are not created on demand.');
    return null;
  }
  const name = String(nameComponents[0]);
  if (RESERVED_UNKNOWN.indexOf(name.toLowerCase()) !== -1) {
    log.info('krb5: ' + name + ' is a reserved name and stays unknown, so ' +
      'KDC_ERR_C_PRINCIPAL_UNKNOWN can still be produced on purpose');
    log.debug('Leaving findOrCreateUser(). reserved.');
    return null;
  }
  const created = register({
    name: [name],
    type: 1,                                   // NT-PRINCIPAL
    realm: inRealm,
    salt: userSalt(inRealm, name),
    autoCreated: true,
    description: 'created on first sight — every username authenticates here, with the ' +
                 'one password every user shares',
    pac: {
      rid: autoRidNext++,
      groups: [RID.DOMAIN_USERS],
      userAccountControl: UAC.NORMAL_ACCOUNT,
      // The same two well-known SIDs the configured users carry: S-1-18-1 says the
      // identity came from a password logon rather than being asserted, and S-1-5-11 is
      // Authenticated Users. An account created here went through the same AS exchange
      // as alice, so it would be wrong for its PAC to say otherwise.
      extraSids: ['S-1-18-1', 'S-1-5-11']
    }
  });
  log.info('krb5: created ' + keyOf(created) + ' on demand — RID ' + created.pac.rid +
    ', salt ' + JSON.stringify(created.salt) + ', the shared user password');
  log.debug('Leaving findOrCreateUser(). created.');
  return created;
}

// ---------------------------------------------------------------------------
// The service account for a host this mock is willing to be, created on first
// sight. See SERVICE_DOMAINS above for why this exists and what it must not do.
//
// Called only AFTER the referral path has had its say, so a name in the trusted
// realm's domain has already been answered with a ticket-granting ticket for that
// realm rather than created here. Returns null for everything it declines, and
// every caller treats null as KDC_ERR_S_PRINCIPAL_UNKNOWN exactly as before.
// ---------------------------------------------------------------------------
function findOrCreateService(nameComponents, realm) {
  log.debug('Entering findOrCreateService().');
  const inRealm = realm || REALM;
  const existing = find(nameComponents, inRealm);
  if (existing) {
    log.debug('Leaving findOrCreateService(). ' + keyOf(existing) + ' was known.');
    return existing;
  }
  if (realmsServed().indexOf(inRealm) === -1) {
    log.debug('Leaving findOrCreateService(). ' + inRealm + ' is not served here.');
    return null;
  }
  if (!nameComponents || nameComponents.length < 2 ||
      !nameComponents.every(function (part) { return part && String(part).length; })) {
    // One component is a user (findOrCreateUser's job), and an empty component is
    // not a name at all.
    log.debug('Leaving findOrCreateService(). Not service-shaped.');
    return null;
  }
  const host = String(nameComponents[nameComponents.length - 1]).toLowerCase();
  const matched = SERVICE_DOMAINS.filter(function (entry) {
    return host === entry || host.endsWith('.' + entry);
  })[0];
  if (!matched) {
    log.info('krb5: ' + nameComponents.join('/') + ' names a host this service is ' +
      'not willing to be (' + host + ' matches none of ' +
      (SERVICE_DOMAINS.join(', ') || '(nothing configured)') + '), so it stays ' +
      'KDC_ERR_S_PRINCIPAL_UNKNOWN');
    log.debug('Leaving findOrCreateService(). Host not covered.');
    return null;
  }
  // The salt is AD's for a service account: realm + sAMAccountName, and the
  // sAMAccountName of a service is not its SPN. Real deployments make it the
  // account's own name, which nothing in the SPN reveals — so this is a
  // convention of the mock's, published like every other salt in
  // GET /krb5/principals and in ETYPE-INFO2, and NOT something a client should
  // ever try to derive. Same shape as the configured HTTP/web.example.com entry,
  // which salts as REALM + "HTTPweb".
  const short = String(nameComponents[nameComponents.length - 1]).split('.')[0];
  const created = register({
    name: nameComponents.map(String),
    type: 3,                                   // NT-SRV-HST
    realm: inRealm,
    password: AUTO_SERVICE_PASSWORD,
    salt: userSalt(inRealm, nameComponents.slice(0, -1).join('') + short),
    autoCreated: true,
    description: 'created on first sight because ' + host + ' matches ' + matched +
                 ' — the shared auto-service password, published by this endpoint',
    pac: {
      rid: autoRidNext++,
      groups: [RID.DOMAIN_COMPUTERS],
      userAccountControl: UAC.WORKSTATION_TRUST_ACCOUNT
    }
  });
  log.info('krb5: created the service ' + keyOf(created) + ' on demand — salt ' +
    JSON.stringify(created.salt) + ', the shared auto-service password. This ' +
    'process is also the acceptor, so the ticket it seals is one it can open.');
  log.debug('Leaving findOrCreateService(). created.');
  return created;
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
// ---------------------------------------------------------------------------
// Whether PA-ETYPE-INFO2 carries s2kparams, and why this is a switch rather
// than a constant.
//
// s2kparams is OPTIONAL (RFC 4120 section 5.2.7.5). When it is absent the
// client applies the etype's own default, which for the AES profiles is the
// 4096 iterations RFC 3962 section 4 specifies.
//
// This mock used to send it always. Real Active Directory does not: a capture
// from Windows Server 2025 on 2026-08-16 shows the field omitted entirely
// (tests/captures/windows-server-2025.json in the debugger repository). That
// difference matters more than it looks, because it is the direction that
// hides a bug: a client which REQUIRES s2kparams -- dereferences it, or
// refuses an entry without one -- passed every test against this mock and
// would then fail against every real domain in the world, reporting a wrong
// password. The mock was teaching the client a habit no real KDC supports.
//
// So the default is now AD's behaviour, and the old behaviour is one env var
// away so that both paths stay covered:
//
//   KRB5_S2KPARAMS=omit   (default) no s2kparams, as Active Directory does
//   KRB5_S2KPARAMS=send             an explicit 4096, as this mock used to
//
// The KEY DERIVATION is unaffected either way: longTermKey() above passes null
// s2kparams and therefore already uses the profile default, so what changes is
// only what the KDC advertises.
// ---------------------------------------------------------------------------
const S2KPARAMS_MODE =
  String(process.env.KRB5_S2KPARAMS || 'omit').toLowerCase() === 'send'
    ? 'send' : 'omit';

function etypeInfo2For(principal) {
  return supportedEtypes(principal).map(function (id) {
    // arcfour ignores the salt entirely, so its entry carries neither a salt
    // nor s2kparams whatever the mode.
    if (id === 23) return { etype: id, salt: null, s2kparams: null };
    if (S2KPARAMS_MODE === 'omit') {
      return { etype: id, salt: principal.salt, s2kparams: null };
    }
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
  findOrCreateUser: findOrCreateUser,
  findOrCreateService: findOrCreateService,
  USER_PASSWORD: USER_PASSWORD,
  AUTO_SERVICE_PASSWORD: AUTO_SERVICE_PASSWORD,
  SERVICE_DOMAINS: SERVICE_DOMAINS,
  RESERVED_UNKNOWN: RESERVED_UNKNOWN,
  all: function () { return Array.from(principals.values()); },
  longTermKey: longTermKey,
  supportedEtypes: supportedEtypes,
  chooseEtype: chooseEtype,
  etypeInfo2For: etypeInfo2For,
  S2KPARAMS_MODE: S2KPARAMS_MODE,
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
