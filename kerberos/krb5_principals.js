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
const { log } = require('../common/helpers');
const config = require('../common/config');

const REALM = config.value('krb5.realm');
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
// /authn/login becomes the identity and that is the end of it. Kerberos cannot be
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
const USER_PASSWORD = config.value('krb5.userPassword');

// The usernames that stay unknown, so KDC_ERR_C_PRINCIPAL_UNKNOWN is still reachable.
//
// Creating an account for whoever asks removes the obvious way to produce that error —
// name somebody who does not exist — and it is one of the errors most worth being able
// to produce on purpose, because a client that renders it as "wrong password" sends a
// person off to reset a password that was never the problem. These names are therefore
// refused rather than created, and they are configurable so a test can name its own.
function reservedUnknown() {
  return config.value('krb5.unknownUsers')
    .map(function (name) { return name.toLowerCase(); });
}

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
// config.js derives the default from krb5.realm, and an explicitly empty
// value still creates nothing — the distinction between "unset" and "set to
// nothing" that this expression used to make with `=== undefined` is now the
// distinction between a setting with no value anywhere and one set to ''.
const SERVICE_DOMAINS = config.value('krb5.serviceDomains')
  .map(function (name) { return name.toLowerCase(); });

// One password for every service created on demand, and it is PUBLISHED by
// GET /krb5/principals for the same reason USER_PASSWORD is: a debugger whose
// accounts are unusable without reading the source is worse than one that says
// what they are. It is what lets a reader decrypt a service ticket this mock
// issued — the ticket's own EncTicketPart, the PAC inside it, the four signatures
// — which is otherwise the one thing a client can never see. The CONFIGURED
// service accounts keep their own separate passwords, so nothing about this
// weakens an assertion about which key sealed which ticket.
const AUTO_SERVICE_PASSWORD = config.value('krb5.autoServicePassword');

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
const DOMAIN_SID = config.value('krb5.domainSid');

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
const TRUSTED_REALM = config.value('krb5.trustedRealm');
const TRUSTED_DOMAIN = TRUSTED_REALM.toLowerCase();
const TRUST_PASSWORD = config.value('krb5.trustPassword');
const TRUSTED_DOMAIN_SID = config.value('krb5.trustedDomainSid');

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
    password: config.value('krb5.krbtgtPassword'),
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
    password: config.value('krb5.trustedKrbtgtPassword'),
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
  log.debug('Entering register().');
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
    // WHEN THIS PRINCIPAL LAST SIGNED OUT, as a Date, or null for never.
    //
    // It is the only thing a KDC can honestly do about a credential it has
    // already handed out. A ticket-granting ticket is an encrypted blob in
    // somebody's cache; there is no list of them here and there could not be
    // one on a real KDC either. What a KDC DOES see is the next TGS-REQ that
    // presents it — so a sign-out records an INSTANT, and handleTgsReq()
    // refuses a ticket whose `authtime` is earlier than it with
    // KDC_ERR_TGT_REVOKED (20).
    //
    // BE PRECISE ABOUT WHAT THAT CODE IS, because it is easy to overclaim and
    // this comment used to. RFC 4120 LISTS it in the error table at section
    // 7.5.9 — "TGT has been revoked" — and that is ALL it does: the
    // specification defines no mechanism that emits it, no state a KDC keeps in
    // order to decide it, and no way for anything to cause it. Kerberos has no
    // logout message, no session, and no revocation of any kind; a ticket is
    // valid because it decrypts and its endtime has not passed, and the KDC is
    // not consulted when a service accepts one. Short lifetimes ARE the
    // revocation model.
    //
    // So the instant below is an INVENTION, not an implementation of a spec'd
    // behaviour. What makes it the right invention is that it is the same lever
    // a real KDC has: the TGS exchange is the one moment a KDC is back in the
    // loop, which is why disabling an account in Active Directory bites within
    // the service-ticket lifetime rather than the TGT's. Code 20 is the closest
    // registered code to what is happening and its text says what we mean.
    //
    // Three things it deliberately is not. It is NOT `revoked`, one field up:
    // that is a disabled account and it refuses the AS exchange as well, where
    // this leaves a fresh authentication working — signing out is not being
    // locked out, and conflating them would mean a person could log out and
    // never log back in. It does NOT reach a SERVICE TICKET already in a cache,
    // because the service that accepts one never contacts the KDC; that is a
    // fact about Kerberos rather than a gap here, and /logout says so on the
    // row rather than implying a completeness it has not got. And it is CLEARED
    // by the next successful AS exchange, in handleAsReq(), because the ticket
    // that exchange mints is newer than the instant and leaving a stale one
    // behind would refuse the TGS-REQ that immediately follows it.
    signedOutAt: null,
    keys: new Map()
  };
  principals.set(keyOf(principal), principal);
  log.debug('Leaving register().');
  return principal;
}

DEFINITIONS.forEach(register);
TRUSTED_DEFINITIONS.forEach(register);
log.info('krb5: principal database for realm ' + REALM + ' — ' +
  Array.from(principals.keys()).join(', '));

// ---------------------------------------------------------------------------
// SIGNING OUT, WHICH IS A STATEMENT ABOUT TICKETS AND NOT ABOUT THE ACCOUNT.
//
// `signOut()` stamps the instant described on `signedOutAt` above;
// `clearSignOut()` removes it, which is what a fresh AS exchange does and what
// the console's undo does. `signedOut()` is the reader the KDC's TGS handler
// calls, and it answers with the DATE rather than a boolean so that the refusal
// can say when — "the ticket was issued at X and this principal signed out at
// Y" is a sentence somebody can act on, and "revoked" on its own is not.
//
// It creates nothing. A name nobody has ever authenticated as has no principal
// here, and stamping one into existence would put an account in the database
// because somebody typed a name at a logout screen — the opposite of
// findOrCreateUser()'s rule, which creates a CLIENT because an AS-REQ named
// one. So a sign-out for an unknown principal is reported as having reached
// nothing, and /logout prints that rather than a success it did not have.
// ---------------------------------------------------------------------------
function signOut(nameComponents, realm, at) {
  log.debug("Entering signOut(). principal=" + (nameComponents || []).join('/'));
  const principal = find(nameComponents, realm);
  if (!principal) {
    log.debug("Leaving signOut(). No such principal.");
    return null;
  }
  principal.signedOutAt = at || new Date();
  log.info('krb5: ' + principal.name.join('/') + '@' + principal.realm + ' signed out at ' +
           principal.signedOutAt.toISOString() + '. A TGS-REQ presenting a ticket issued ' +
           'before that is now refused KDC_ERR_TGT_REVOKED (20). A service ticket already ' +
           'in a cache still works against the service that accepts it — nothing contacts ' +
           'this KDC on that exchange.');
  log.debug("Leaving signOut(). Stamped " + principal.signedOutAt.toISOString() + ".");
  return principal;
}

function clearSignOut(nameComponents, realm) {
  log.debug("Entering clearSignOut(). principal=" + (nameComponents || []).join('/'));
  const principal = find(nameComponents, realm);
  if (!principal || !principal.signedOutAt) {
    log.debug("Leaving clearSignOut(). Nothing was stamped.");
    return null;
  }
  const was = principal.signedOutAt;
  principal.signedOutAt = null;
  log.info('krb5: the sign-out instant on ' + principal.name.join('/') + '@' + principal.realm +
           ' (' + was.toISOString() + ') is cleared; tickets issued before it are accepted again.');
  log.debug("Leaving clearSignOut(). Cleared.");
  return was;
}

// The instant, or null. Without entering/leaving logs: the TGS handler calls it
// on every request it answers, and a pair of lines there would be most of the
// Kerberos log on a busy run.
function signedOutAt(nameComponents, realm) {
  const principal = find(nameComponents, realm);
  return (principal && principal.signedOutAt) || null;
}

// Every principal currently carrying one, for the console and for /logout's
// inventory. Read off the database rather than kept in a second list beside it,
// which is the one-store rule this service applies everywhere else.
function signedOutPrincipals() {
  log.debug("Entering signedOutPrincipals().");
  const out = [];
  principals.forEach(function (principal) {
    if (principal.signedOutAt) {
      out.push({ name: principal.name.slice(0), realm: principal.realm,
                 principal: principal.name.join('/') + '@' + principal.realm,
                 signedOutAt: principal.signedOutAt });
    }
  });
  log.debug("Leaving signedOutPrincipals(). " + out.length + " principal(s).");
  return out;
}

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
  if (reservedUnknown().indexOf(name.toLowerCase()) !== -1) {
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
function s2kparamsMode() {
  return String(config.value('krb5.s2kparams')).toLowerCase() === 'send'
    ? 'send' : 'omit';
}

function etypeInfo2For(principal) {
  return supportedEtypes(principal).map(function (id) {
    // arcfour ignores the salt entirely, so its entry carries neither a salt
    // nor s2kparams whatever the mode.
    if (id === 23) return { etype: id, salt: null, s2kparams: null };
    if (s2kparamsMode() === 'omit') {
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

// ---------------------------------------------------------------------------
// WHO MAY DELEGATE TO WHOM — the CONFIGURED half of /admin/delegation.
//
// The rest of that page is a log of acts that have happened. This is the
// policy behind them, and it is here rather than in common/delegation.js or in
// admin.js for the reason every store rule in this repository is where it is:
// what these two attributes MEAN is a statement about the principal database,
// and a second opinion about it in the renderer is the drift the console's own
// text keeps warning about. That store is here; so is this.
//
// It answers the question a person arrives at that page with BEFORE they have
// tried anything — *why would this be refused?* — and it can answer it because
// the whole of the KDC's authorization decision rests on two attributes on two
// opposite accounts:
//
//   * `msDS-AllowedToDelegateTo` on the FRONT END, listing the services it may
//     reach as anybody. CLASSIC constrained delegation, and only a domain admin
//     can set it.
//   * `msDS-AllowedToActOnBehalfOfOtherIdentity` on the BACK END, listing who
//     may act on its behalf. RESOURCE-BASED, and whoever controls that object
//     can set it themselves — which is the entire security story of RBCD.
//
// Two things this deliberately does NOT do. It does not merge the two lists:
// they are configured on opposite accounts and conflating them would hide the
// only thing about RBCD worth knowing, which is the same reason register()
// keeps them apart. And it does not report a pair as workable merely because an
// attribute names it — `warning` is where the three ways a correctly configured
// pair still fails are stated, and the most expensive of them (a front end with
// no TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION, whose S4U2Self ticket is simply
// not forwardable, so classic S4U2Proxy fails a step later complaining about
// the evidence) is invisible everywhere else.
//
// Returns { pairs, accounts }. A pair is one (front end, target, mechanism); an
// account is one principal carrying a flag that changes what delegation can do
// to it or with it, whether or not any pair names it.
// ---------------------------------------------------------------------------
function delegationPolicy() {
  log.debug('Entering delegationPolicy().');
  const pairs = [];
  const accounts = [];
  const all = Array.from(principals.values());

  // Does this KDC know the principal an attribute names? A misspelt SPN in
  // either list is the ordinary configuration mistake and it fails at TGS time
  // with an error about authorization rather than about spelling, so the table
  // says so here instead. Both lists hold bare SPNs with no realm — which is
  // what the KDC compares against — so the account's own realm is what to look
  // them up in.
  const knows = function (spn, realm) {
    return !!find(String(spn || '').split('/'), realm);
  };

  all.forEach(function (principal) {
    const name = principal.name.join('/');

    // CLASSIC — the permission is on THIS account and names what it may reach.
    (principal.allowedToDelegateTo || []).forEach(function (target) {
      const targetPrincipal = find(String(target).split('/'), principal.realm);
      const warnings = [];
      if (!principal.trustedToAuthenticateForDelegation) {
        warnings.push('This account is NOT trusted for protocol transition ' +
          '(TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION), so the ticket it gets ' +
          'back from S4U2Self is not FORWARDABLE — and classic constrained ' +
          'delegation requires forwardable evidence. S4U2Self will succeed and ' +
          'S4U2Proxy will then fail complaining about the evidence ticket, ' +
          'which is two steps from the attribute that caused it. Resource-based ' +
          'delegation would not have needed either flag.');
      }
      if (!targetPrincipal) {
        warnings.push('This KDC has no principal called ' + target + ' in ' +
          principal.realm + '. The attribute names a SERVICE and the SPN has to ' +
          'match exactly; a ticket request for a name this KDC does not know is ' +
          'refused before the authorization is ever consulted.');
      }
      pairs.push({
        mechanism: 'classic',
        // The delegation store's own type id, so the observed table and this
        // one can be read against each other without a lookup written twice.
        type: 'krb5-s4u2proxy-classic',
        frontEnd: name + '@' + principal.realm,
        target: target + '@' + principal.realm,
        realm: principal.realm,
        attribute: 'msDS-AllowedToDelegateTo',
        // WHICH ACCOUNT the permission lives on. It is the whole difference
        // between the two mechanisms and it is the column to read first.
        setOn: name + '@' + principal.realm,
        setOnRole: 'front end',
        requires: 'a FORWARDABLE evidence ticket, which S4U2Self only returns ' +
                  'to an account flagged TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION',
        targetKnown: !!targetPrincipal,
        warning: warnings.join(' '),
        note: principal.description || ''
      });
    });

    // RESOURCE-BASED — the permission is on THIS account and names who may act
    // on its behalf, so the pair is built the other way round.
    (principal.allowedToActOnBehalfOf || []).forEach(function (requester) {
      const requesterPrincipal = find(String(requester).split('/'), principal.realm);
      const warnings = [];
      if (!requesterPrincipal) {
        warnings.push('This KDC has no principal called ' + requester + ' in ' +
          principal.realm + '. Whoever the attribute meant to authorize cannot ' +
          'present a ticket here under that name.');
      }
      // The PA-PAC-OPTIONS requirement is NOT a warning and used to be pushed
      // here unconditionally, which meant every resource-based pair reported
      // something missing for ever and the field could never say "nothing is".
      // It is a property of the mechanism, so it belongs in `requires` — where
      // it already was — and a warning that fires on every row is a warning
      // nobody reads by the third one.
      pairs.push({
        mechanism: 'rbcd',
        type: 'krb5-s4u2proxy-rbcd',
        frontEnd: requester + '@' + principal.realm,
        target: name + '@' + principal.realm,
        realm: principal.realm,
        attribute: 'msDS-AllowedToActOnBehalfOfOtherIdentity',
        setOn: name + '@' + principal.realm,
        setOnRole: 'back end',
        requires: 'PA-PAC-OPTIONS with the resource-based bit. It needs NO ' +
                  'forwardable evidence and no flag on the front end, which is ' +
                  'why it is the easier path',
        targetKnown: knows(name, principal.realm),
        warning: warnings.join(' '),
        note: principal.description || ''
      });
    });

    // The account-level flags. Reported whether or not a pair names the
    // account, because two of the three are what STOP delegation rather than
    // permit it, and an account that appears in no pair is precisely the one
    // somebody is wondering about.
    if (principal.notDelegated || principal.trustedToAuthenticateForDelegation ||
        principal.okAsDelegate) {
      accounts.push({
        principal: name + '@' + principal.realm,
        realm: principal.realm,
        notDelegated: !!principal.notDelegated,
        trustedToAuthenticateForDelegation:
          !!principal.trustedToAuthenticateForDelegation,
        okAsDelegate: !!principal.okAsDelegate,
        autoCreated: !!principal.autoCreated,
        description: principal.description || '',
        // What each flag DOES, said once here rather than in the page: these
        // are the three sentences people get wrong, and the last of them is the
        // one that is not a control at all.
        effects: [
          principal.notDelegated
            ? 'NOT_DELEGATED — "sensitive and cannot be delegated". The KDC ' +
              'refuses this account a forwardable ticket at all, so no service ' +
              'anywhere can forward its TGT. It is the one control that lives ' +
              'on the account being PROTECTED rather than on any service, which ' +
              'is what makes it work no matter which service the user visits.'
            : '',
          principal.trustedToAuthenticateForDelegation
            ? 'TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION — protocol transition. ' +
              'This account gets a FORWARDABLE ticket out of S4U2Self, which is ' +
              'what classic constrained delegation then needs as evidence. ' +
              'Without it S4U2Self still works and simply returns a ticket that ' +
              'is not forwardable.'
            : '',
          principal.okAsDelegate
            ? 'ok-as-delegate — ADVICE TO THE CLIENT and not a control. The ' +
              'flag on a service ticket tells the client this service may be ' +
              'trusted with forwarded credentials; a client is free to ignore ' +
              'it, and this KDC enforces nothing by it.'
            : ''
        ].filter(Boolean)
      });
    }
  });

  // Stable order, so two readings of the page put the rows in the same places:
  // by target, then by front end. Not by insertion, which is the order the
  // definitions happen to be written in and would change under an edit that
  // changed nothing else.
  pairs.sort(function (a, b) {
    return a.target.localeCompare(b.target) || a.frontEnd.localeCompare(b.frontEnd);
  });
  accounts.sort(function (a, b) { return a.principal.localeCompare(b.principal); });

  log.debug('Leaving delegationPolicy(). ' + pairs.length + ' pair(s), ' +
            accounts.length + ' account(s).');
  return { pairs: pairs, accounts: accounts };
}

module.exports = {
  REALM: REALM,
  DOMAIN: DOMAIN,
  KDC_ETYPES: KDC_ETYPES,
  find: find,
  delegationPolicy: delegationPolicy,
  findOrCreateUser: findOrCreateUser,
  findOrCreateService: findOrCreateService,
  USER_PASSWORD: USER_PASSWORD,
  AUTO_SERVICE_PASSWORD: AUTO_SERVICE_PASSWORD,
  SERVICE_DOMAINS: SERVICE_DOMAINS,
  reservedUnknown: reservedUnknown,
  all: function () { return Array.from(principals.values()); },
  longTermKey: longTermKey,
  supportedEtypes: supportedEtypes,
  chooseEtype: chooseEtype,
  etypeInfo2For: etypeInfo2For,
  s2kparamsMode: s2kparamsMode,
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
  RID: RID,
  // The sign-out instant. Four functions rather than an exported field, because
  // this is a database and the callers are in three other directories: the KDC
  // reads it on every TGS-REQ, /logout writes it, the console reports it. See
  // the block above them.
  signOut: signOut,
  clearSignOut: clearSignOut,
  signedOutAt: signedOutAt,
  signedOutPrincipals: signedOutPrincipals
};
