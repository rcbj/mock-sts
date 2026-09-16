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
// judged on how it renders failure, and the failures worth rendering are the
// ones a real deployment produces: an account whose supported encryption types
// no longer overlap with the client's (which in 2026 means RC4 being disabled),
// an account that is locked out, a password that has expired, a principal that
// does not exist, and a clock outside the tolerance. Each of those has an entry
// here so a test can drive it deliberately rather than by breaking something.
//
// Two facts about salt that this file exists to make concrete, because they are
// where an implementation that works against its own mock stops working against
// Active Directory:
//
//  * **The salt is not the principal name.** AD's default for a USER is the
//    realm followed by the sAMAccountName — `EXAMPLE.COMalice` — with no
//    separator and the realm upper case.
//  * **For a COMPUTER account it is a different shape entirely**: the realm,
//    then the literal `host`, then the short name in lower case, then the DNS
//    domain — `EXAMPLE.COMhostws01.example.com`. An implementation that derives
//    the salt from the principal name works until the first machine account,
//    which is exactly the point at which somebody is debugging a service and
//    not a user.
//
// Both are produced here, and the KDC hands whichever applies to the client in
// PA-ETYPE-INFO2. That is the only way a client can know it.
//
// **Anybody can authenticate, and everybody's password is the same.** See
// USER_PASSWORD below for why Kerberos cannot simply check no password the way
// the rest of this service does not, and findOrCreateUser() for the accounts
// that are not in the table until somebody asks for one.
//
// **ALL OF THAT IS DEVELOPMENT MODE (2026-09-12).** In product mode the fixture
// accounts, their literal passwords, the delegation rules and the second realm
// are not created, nothing is created on demand, and the two accounts the
// service needs — krbtgt and `krb5.servicePrincipal` — exist only where their
// passwords are set to something other than the value this repository
// publishes. See SEEDS_DEMO and buildDatabase().
//
// **AND SINCE LATER THE SAME DAY A PRODUCT KDC AUTHENTICATES THE DIRECTORY'S
// PEOPLE.** The sentence here read *what product mode does NOT yet do is give
// the people in the directory Kerberos accounts: a product KDC here
// authenticates nobody*. A person's long-term keys are now derived from their
// real password at the moment a plaintext one is in hand — when it is SET, and
// when a sign-in VERIFIES it — and stored, sealed, on their own directory
// entry. This file does not know how: it offers `setKeySource()`, which
// `krb5_person_keys.js` fills, and a user principal in product mode is resolved
// through it rather than from `krb5.userPassword`. The same slot answers a
// SERVICE principal an operator created with a random key. See KEY SOURCE
// below, and `kerberos/CLAUDE.md`.
// ---------------------------------------------------------------------------

const kcrypto = require('./krb5_crypto.js');
const prim = require('./krb5_primitives.js');
// node's own, for the SHA-256 an on-demand RID is derived from (see
// autoRidFor()). A builtin, so it adds nothing to the parent project's COPY
// set.
const nodeCrypto = require('crypto');
const { log } = require('../common/helpers');
const config = require('../common/config');
// The mode. A LEAF (rule 3) that registers nothing and requires only `config`,
// which this module already requires — so it can neither move a route nor
// close a cycle.
const mode = require('../common/mode');
// PER TRUST REALM SINCE 2026-09-15 — the store below is a partition per realm,
// and this is also what `contextOf()` enters to build one. A LEAF that
// registers no route, so this cannot move a route or join a cycle, and it was
// already in the parent project's copy set before that change.
const realms = require('../common/realms');
// ERROR CODES. A LEAF requiring nothing, already in the parent project's copy
// set through common/audit.js. Only tag() is used: every failure here happens
// while the principal database is built at require time, before a request or
// an audit ring exists to hold a row.
const errorCodes = require('../common/error_codes');

// ---------------------------------------------------------------------------
// ONE PRINCIPAL DATABASE PER TRUST REALM (2026-09-15).
//
// Until this date everything below the requires was a constant read at require
// time — `REALM`, the domain SID, the etypes, the kvno, every password —
// because the KDC was one of the socket families a trust realm did not get:
// port 88 has no path to put a realm segment in, so the database was the
// PROCESS's and was pinned to the default trust realm. **The Kerberos realm
// name inside every request is a discriminator the protocol already carries**,
// and the KDC now routes on it: each trust realm whose Kerberos is on has a
// `krb5.realm` of its own, a principal database of its own (a partition of the
// store below) and keys of its own, on the same port.
//
// So those values are a CONTEXT per trust realm — see `contextOf()` below —
// built from that realm's settings inside that realm:
//
//   * **THE DEFAULT REALM'S IS BUILT HERE, AT REQUIRE TIME, EXACTLY AS THE
//     CONSTANTS WERE**, from the process's values, and is never rebuilt — so a
//     process with no realms defined has the database it always had, and the
//     parent project's in-process jobs (which set KRB5_REALM and require this
//     file) see nothing different;
//   * **ANOTHER REALM'S IS BUILT ON FIRST USE**, only while its `krb5.enabled`
//     is on, and REBUILT when a setting it was built from changes on that realm
//     (`realms.onChange`). A realm whose Kerberos is off has an INACTIVE
//     context: no principal, and no name the KDC routes to it.
//
// `REALM`, `KDC_ETYPES` and the rest are still exported under the same names,
// as getters answering for the AMBIENT realm — the realm `realms.run()`
// entered, or the default one outside any. The KDC enters the realm a request
// is for before it looks anything up, which is what makes every reader below
// right without being told which realm it is in.
//
// **WHAT A REALM DOES NOT GET, by rcbj's decision:** a trust with another trust
// realm. The development-mode second realm and its trust (`krb5.trustedRealm`)
// stay the DEFAULT realm's, and a realm's KDC holds no `krbtgt/<other realm>`.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// WHETHER THIS DATABASE CARRIES THE FIXTURE ACCOUNTS, DECIDED ONCE
// (2026-09-12).
//
// Every account below `krbtgt` in DEFINITIONS — alice, bob, the locked and
// expired ones, the computer account, the four delegation services and their
// rules, the whole second realm and its trust — is DEMONSTRATION DATA, and the
// service accounts among them carry passwords written in this file. In
// development that is the point: each one drives a failure a client has to
// render. In product mode (`mode.seedsDemoData()` false) a fixture account with
// a password printed in a public repository is an account anybody can use, and
// a delegation rule nobody configured is a permission nobody granted, so none
// of it is created. What is left is what the service NEEDS: this realm's
// `krbtgt` and the account `krb5.servicePrincipal` names — each only where its
// password is not the published default (see `publishedDefault()` below).
//
// **CAPTURED WHEN THE DATABASE IS BUILT AND NOT READ PER REQUEST**, and that is
// the honest shape rather than a shortcut: the database and every long-term key
// in it are built at that moment. For the DEFAULT realm that is require time,
// in the PROCESS's mode, and changing `global.mode` later adds and removes no
// principal. For another trust realm (2026-09-15) it is when that realm's
// Kerberos is turned on, in THAT realm's mode — and a change to the realm's
// `global.mode` rebuilds its database, because a realm's settings are exactly
// what may change under a running process. `realmsServed()` reads the same
// captured value, `ctx.SEEDS_DEMO`, so the database and the realms it answers
// for cannot disagree.
// ---------------------------------------------------------------------------

// The value a setting ships with, read off its row rather than written out a
// second time here. A password equal to it is a password printed in this
// repository, whoever typed it.
function publishedDefault(key) {
  log.debug("Entering publishedDefault().");
  const row =
      config.SETTINGS.filter(function (one) { return one.key === key; })[0];
  log.debug("Leaving publishedDefault().");
  return row ? row.dflt : undefined;
}

// ---------------------------------------------------------------------------
// The etypes this KDC will use at all, strongest first — `krb5.enctypes`, whose
// default is the literal this line used to carry. arcfour is in that default
// because the workflow has to be able to exercise it — Microsoft is retiring it
// and a debugger whose only story is "that is deprecated" cannot help anybody
// still running it — and taking 23 out is what a hardened deployment does.
//
// A number the vendored codec does not implement is REFUSED rather than
// dropped: a list that silently lost an entry would be a KDC offering less than
// its configuration says, and the first symptom would be KDC_ERR_ETYPE_NOSUPP
// for a client that asked for exactly what the operator wrote down.
// ---------------------------------------------------------------------------
function parseEtypes(list) {
  log.debug('Entering parseEtypes().');
  const ids = [];
  const problems = [];
  (Array.isArray(list) ? list : String(list || '').split(',')).forEach(
      function (raw) {
    const text = String(raw).trim();
    if (!text) {
      return;
    }
    const id = Number(text);
    if (!/^\d+$/.test(text) || !kcrypto.isSupportedEtype(id)) {
      problems.push(text);
      return;
    }
    if (ids.indexOf(id) === -1) {
      ids.push(id);
    }
  });
  if (!ids.length && !problems.length) {
    problems.push('(an empty list)');
  }
  log.debug('Leaving parseEtypes(). ' + ids.length + ' etype(s), ' +
            problems.length + ' problem(s).');
  return { ids: ids, problems: problems };
}

// The etypes, for the realm being built. FATAL for the DEFAULT realm, whose
// database is built at require time, for `config.js`'s reason: a KDC answering
// with a narrower list than it was configured with is wrong in a way no page
// shows, and a throw out of a require lands as a stack trace whose top frame is
// node's loader. **For another trust realm it is NOT fatal** (2026-09-15): that
// value came from a realm override under a running process, and one realm's
// typo must not stop the service every other realm is on — so the realm's
// context is left inactive, with the sentence as its reason, and its name is
// not routed.
function configuredEtypes(realmId) {
  log.debug("Entering configuredEtypes().");
  const parsed = parseEtypes(config.value('krb5.enctypes'));
  if (parsed.problems.length) {
    const sentence = 'krb5.enctypes (KRB5_ENCTYPES) names ' +
      parsed.problems.join(', ') + ', which the Kerberos codec here ' +
      'does not implement. It performs 17, 18, 19, 20 and 23 ' +
      '(aes128-cts-hmac-sha1-96, aes256-cts-hmac-sha1-96, ' +
      'aes128-cts-hmac-sha256-128, aes256-cts-hmac-sha384-192, ' +
      'rc4-hmac); DES is decode-only.';
    if (realmId === realms.DEFAULT_ID) {
      log.fatal(errorCodes.tag('STS-KRB-0058') + 'krb5: NOT STARTING. ' +
                sentence);
      process.exit(1);
    }
    log.error(errorCodes.tag('STS-KRB-0058') + 'krb5: realm "' + realmId +
              '" has no KDC: ' + sentence);
    log.debug("Leaving configuredEtypes(). Refused for a realm.");
    return { ids: null, problem: sentence };
  }
  log.debug("Leaving configuredEtypes().");
  return { ids: parsed.ids, problem: '' };
}

// AD's salt for a user account: realm + sAMAccountName, no separator.
function userSalt(realm, name) {
  log.debug("Entering userSalt().");
  log.debug("Leaving userSalt().");
  return realm + name;
}

// ---------------------------------------------------------------------------
// One password, and an account for anybody who asks.
//
// Everything else in this service checks no password at all — the username
// typed at /authn/login becomes the identity and that is the end of it.
// Kerberos cannot be made to work that way, and the reason is structural rather
// than a decision: the password IS the key. Pre-authentication is a timestamp
// encrypted under it, and the AS-REP's enc-part is encrypted under it too, so a
// KDC that accepted any password would still have to pick one to encrypt the
// reply with, and a client that used a different one could not read the ticket
// it was sent.
//
// So the nearest thing the protocol allows is what happens here: ONE password,
// shared by every user account, and an account for every username that turns
// up.
//
//  * Every USER principal in the table below has this password. None of them
//    carries a secret of its own any more — the accounts differ in the
//    BEHAVIOUR they exist to drive (locked, expired, aesonly, rc4only,
//    sensitive, noreauth), which is what they were ever for, and a test no
//    longer has to look a password up before it can drive one.
//  * A username that is not in the table at all is created on first sight by
//    findOrCreateUser(), with AD's user-shaped salt and a PAC identity of its
//    own.
//
// SERVICE, computer and krbtgt principals keep their own distinct passwords,
// and that is deliberate: nobody types them, and krbtgt/EXAMPLE.COM,
// krbtgt/PARTNER.COM and the trust have to hold three DIFFERENT secrets or
// every assertion about which key sealed which ticket would pass for the wrong
// reason.
//
// Read into each realm's context (`ctx.USER_PASSWORD`) when its database is
// built — see contextOf().
// ---------------------------------------------------------------------------

// The usernames that stay unknown, so KDC_ERR_C_PRINCIPAL_UNKNOWN is still
// reachable.
//
// Creating an account for whoever asks removes the obvious way to produce that
// error — name somebody who does not exist — and it is one of the errors most
// worth being able to produce on purpose, because a client that renders it as
// "wrong password" sends a person off to reset a password that was never the
// problem. These names are therefore refused rather than created, and they are
// configurable so a test can name its own.
function reservedUnknown() {
  log.debug("Entering reservedUnknown().");
  log.debug("Leaving reservedUnknown().");
  return config.value('krb5.unknownUsers')
    .map(function (name) { return name.toLowerCase(); });
}

// ---------------------------------------------------------------------------
// THE HOSTS THIS MOCK WILL BE A SERVICE FOR, and why services are created on
// demand here when findOrCreateUser()'s own header argues they must not be.
//
// That argument stands and is not being overturned: a KDC that invents a
// service hands back a ticket sealed with a key the service does not hold, and
// the failure then surfaces at the AP exchange as "decrypt integrity check
// failed" — the same message a genuinely wrong key gives, pointing nowhere near
// the missing SPN. What removes it is that the invented key is NOT unknown to
// the service here: this process is both the KDC and the acceptor,
// krb5_service.js looks the presented SPN up in this same table, and so a
// ticket for a host created on demand opens with the key that sealed it. The
// objection was never to creating the principal; it was to creating one nobody
// can decrypt.
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
// anything whose host matches none of these entries.
// `HTTP/app.elsewhere.invalid` is the case tests/krb5_tgs_ap.js relies on as
// the control for its cross-realm referrals, and it must keep failing. So must
// a name in the TRUSTED realm's domain, which is answered with a REFERRAL long
// before this is reached — see realmForService() and handleTgsReq().
//
// The matching rule is one list with one rule: a host matches an entry when it
// IS that entry or ends with a dot and that entry. So `example.com` covers
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
//
// **AND IT IS THE ONE DERIVED SETTING A TRUST REALM'S VALUE MOVES**
// (2026-09-15). Its default is `<krb5.realm lower-cased>,localhost,sts,
// 127.0.0.1`, read where the context is built — inside the realm — so a realm
// named ACME.EXAMPLE.COM is willing to be `HTTP/web.acme.example.com` and not
// another realm's `HTTP/web.example.com`. `tests/config_realm_layer.js` carries
// that decision as the exemption to its rule about derived rows, which is where
// that file says such a decision gets written down.
function serviceDomainsFor() {
  log.debug("Entering serviceDomainsFor().");
  log.debug("Leaving serviceDomainsFor().");
  return config.value('krb5.serviceDomains').map(function (name) {
    return String(name).toLowerCase();
  });
}

// One password for every service created on demand
// (`ctx.AUTO_SERVICE_PASSWORD`), and it is PUBLISHED by GET /krb5/principals
// for the same reason USER_PASSWORD is: a debugger whose accounts are unusable
// without reading the source is worse than one that says what they are. It is
// what lets a reader decrypt a service ticket this mock issued — the ticket's
// own EncTicketPart, the PAC inside it, the four signatures — which is
// otherwise the one thing a client can never see. The CONFIGURED service
// accounts keep their own separate passwords, so nothing about this weakens an
// assertion about which key sealed which ticket.

// ---------------------------------------------------------------------------
// The domain SID, and the account data that goes into the PAC.
//
// A Kerberos ticket says WHO you are; a Windows service authorizes on the
// groups in the PAC. So every principal here carries the identity a real AD
// account would — a RID, a primary group, group memberships and
// UserAccountControl flags — and the KDC assembles that into a PAC ([MS-PAC])
// inside each ticket it issues. Without it the workflow can show a ticket for
// alice and nothing at all about what alice may do, which is the question
// people actually arrive with.
//
// The domain SID is a fixed made-up one. Real ones are random per domain, and
// the only thing that matters here is that it is the same in every ticket,
// since a service compares SIDs and not names.
//
// Per trust realm (`ctx.DOMAIN_SID`, 2026-09-15): a realm that inherits the
// process's SID and a realm that sets its own are both things worth being able
// to build, and a service authorizing on the PAC is exactly where the
// difference shows.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// The second realm, and the trust between them.
//
// A cross-realm trust is not a configuration flag: it is a SHARED KEY, held as
// an ordinary principal named krbtgt/<the other realm> in each realm's
// database. That is the whole mechanism, and it is why a referral works at all
// — the issuing KDC seals a ticket-granting ticket with a key the OTHER realm's
// KDC can open, and nothing else passes between them.
//
// This mock serves both realms from one process, which a real deployment never
// does. The simplification is worth naming because it hides one class of
// problem (finding the other realm's KDC, which is DNS and SRV records) and
// none of the protocol.
//
// Its own domain SID differs, which is the point of having it: SID filtering
// across a trust is about whose domain a SID belongs to.
//
// **THE DEFAULT TRUST REALM'S ALONE** (2026-09-15). These four are the
// PROCESS's values, read here at require time outside any realm, and only the
// default realm's database holds the trust or answers for the second realm.
// Another trust realm's KDC stands alone: rcbj's decision was that trust realms
// do not trust each other's Kerberos.
// ---------------------------------------------------------------------------
const TRUSTED_REALM = config.value('krb5.trustedRealm');
const TRUSTED_DOMAIN = TRUSTED_REALM.toLowerCase();
const TRUST_PASSWORD = config.value('krb5.trustPassword');
const TRUSTED_DOMAIN_SID = config.value('krb5.trustedDomainSid');

// [MS-SAMR] section 2.2.1.13's USER_ACCOUNT codes — NOT the LDAP
// userAccountControl bits, which share most of these names and none of their
// values.
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
// the DNS domain. Nothing about this is derivable from the principal string,
// which is why ETYPE-INFO2 exists.
function hostSalt(realm, shortName, dnsDomain) {
  log.debug("Entering hostSalt().");
  log.debug("Leaving hostSalt().");
  return realm + 'host' + String(shortName).toLowerCase() + '.' +
         String(dnsDomain).toLowerCase();
}

// The table. `name` is the principal's components; everything else is the
// behaviour a test may want to drive.
//
// A USER entry carries no `password`: register() gives it USER_PASSWORD, the
// one every user here shares. A service, computer or krbtgt entry names its
// own.
//
// **THE FIRST ENTRY IS INFRASTRUCTURE AND EVERY OTHER ONE IS A FIXTURE** (see
// SEEDS_DEMO above). The HTTP/web entry among the fixtures is REPLACED by the
// account `krb5.servicePrincipal` names when the two are the same name, which
// they are at the default settings — see `configuredServiceDefinition()`.
//
// **BUILT PER REALM, FROM THAT REALM'S NAME** (2026-09-15):
// `definitionsFor(ctx)` returns `{ krbtgt, fixtures, trusted }`, so a realm
// named ACME.EXAMPLE.COM has `alice@ACME.EXAMPLE.COM` salted
// `ACME.EXAMPLE.COMalice` and `HTTP/web.acme.example.com`, and only the DEFAULT
// realm's list carries the trust with krb5.trustedRealm and that realm's own
// accounts.
function definitionsFor(ctx) {
  log.debug("Entering definitionsFor(). realm=" + ctx.REALM);
  const REALM = ctx.REALM;
  const DOMAIN = ctx.DOMAIN;
  const KRBTGT_DEFINITION = {
    name: ['krbtgt', REALM],
    type: 2,                                 // NT-SRV-INST
    password: ctx.KRBTGT_PASSWORD,
    salt: userSalt(REALM, 'krbtgt'),
    description: 'the ticket-granting service, whose key seals every TGT'
  };

  const DEFINITIONS = [
    KRBTGT_DEFINITION,
    {
      name: ['alice'],
      type: 1,                                   // NT-PRINCIPAL
      salt: userSalt(REALM, 'alice'),
      description: 'an ordinary user; pre-authentication required, as Active ' +
                   'Directory requires it',
      pac: {
        rid: 1104,
        fullName: 'Alice Example',
        groups: [RID.DOMAIN_USERS, RID.DOMAIN_ADMINS],
        userAccountControl: UAC.NORMAL_ACCOUNT,
        // The two well-known SIDs that record HOW an identity was established.
        // A real AD puts the first one in every PAC it issues from a password
        // logon, and a service can refuse an identity the KDC merely asserted —
        // which is why they are here rather than being tidied away as noise.
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
      // The account whose UF_DONT_REQUIRE_PREAUTH is set. A KDC answers its
      // AS-REQ with a ticket rather than with KDC_ERR_PREAUTH_REQUIRED, which
      // is worth being able to SEE: it is the difference between the
      // two-message dance and the one-message one, and a client has to handle
      // both.
      name: ['noreauth'],
      type: 1,
      salt: userSalt(REALM, 'noreauth'),
      requiresPreAuth: false,
      description: 'pre-authentication NOT required, so the AS-REQ is ' +
                   'answered directly',
      pac: {
        rid: 1106,
        groups: [RID.DOMAIN_USERS],
        // The flag that MAKES this account behave differently, in the PAC as
        // well as in the KDC's behaviour. Two views of one setting: a debugger
        // should show both, because seeing DONT_REQUIRE_PREAUTH in the PAC is
        // what explains the exchange the reader just watched happen in one
        // message instead of two.
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
        userAccountControl:
          UAC.NORMAL_ACCOUNT | UAC.ACCOUNT_DISABLED | UAC.ACCOUNT_AUTO_LOCKED
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
      // The 2026 case. An account whose msDS-SupportedEncryptionTypes has had
      // RC4 removed will refuse a client that offers only RC4, and the error is
      // KDC_ERR_ETYPE_NOSUPP — which reads as "the KDC is broken" unless you
      // know what it means.
      name: ['aesonly'],
      type: 1,
      salt: userSalt(REALM, 'aesonly'),
      etypes: [18, 17],
      description: 'AES only — offers no RC4, which is what a hardened AD ' +
                   'account looks like',
      pac: {
        rid: 1109,
        groups: [RID.DOMAIN_USERS, RID.PROTECTED_USERS],
        userAccountControl: UAC.NORMAL_ACCOUNT
      }
    },
    {
      // ...and its opposite, an old account that has only ever had an RC4 key.
      // On a Windows Server 2025 domain controller this is the one that stops
      // working.
      name: ['rc4only'],
      type: 1,
      salt: userSalt(REALM, 'rc4only'),
      etypes: [23],
      description: 'arcfour-hmac-md5 only — the legacy account that a 2025 ' +
                   'baseline breaks',
      pac: {
        rid: 1110,
        groups: [RID.DOMAIN_USERS],
        userAccountControl: UAC.NORMAL_ACCOUNT | UAC.USE_DES_KEY_ONLY
      }
    },
    {
      // "Account is sensitive and cannot be delegated" — [MS-SAMR]'s
      // USER_ACCOUNT code NOT_DELEGATED (0x4000). It is the ONE control that
      // stops unconstrained delegation taking a privileged account's
      // ticket-granting ticket, and it lives on the account being protected
      // rather than on any service. A KDC must refuse to issue this account a
      // forwardable ticket at all, which is what makes the protection work no
      // matter which service the user visits.
      name: ['sensitive'],
      type: 1,
      salt: userSalt(REALM, 'sensitive'),
      notDelegated: true,
      description: 'flagged sensitive and cannot be delegated — the KDC ' +
                   'refuses it a forwardable ticket, so no service can ' +
                   'forward its TGT',
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
      description: 'a computer account, whose salt is host-shaped rather ' +
                   'than name-shaped',
      pac: {
        rid: 1111,
        // A machine account is not a user: its primary group is Domain
        // Computers and its UAC says WORKSTATION_TRUST_ACCOUNT. An
        // implementation that assumes every PAC describes a person gets this
        // wrong in a way no user account reveals.
        primaryGroupRid: RID.DOMAIN_COMPUTERS,
        groups: [RID.DOMAIN_COMPUTERS],
        userAccountControl: UAC.WORKSTATION_TRUST_ACCOUNT
      }
    },
    {
      // The ordinary service a ticket gets requested for — the AP exchange's
      // target, and the one used as an UNAUTHORIZED delegation target by the
      // tests, since nothing permits the front end to reach it.
      name: ['HTTP', 'web.' + DOMAIN],
      type: 3,
      password: 'service-account-password',
      salt: userSalt(REALM, 'HTTPweb'),
      okAsDelegate: true,
      description: 'an HTTP service principal, flagged ok-as-delegate'
    },
    {
      // -----------------------------------------------------------------------
      // DELEGATION, configured two DIFFERENT WAYS on purpose.
      //
      // `frontend` is trusted for CLASSIC constrained delegation: the
      // permission lives on the FRONT-END account, as msDS-AllowedToDelegateTo,
      // and only a domain admin can set it. `backend-rbcd` authorizes
      // RESOURCE-BASED constrained delegation: the permission lives on the
      // BACK-END account, as msDS-AllowedToActOnBehalfOfOtherIdentity, and
      // whoever controls that object can set it themselves.
      //
      // That difference is the entire security story of RBCD, and it is why
      // both are here. Same protocol messages, same KDC options, opposite
      // direction of trust — and the second one turns "I can write to this
      // computer object" into "I can reach this service as anybody".
      // -----------------------------------------------------------------------
      name: ['HTTP', 'frontend.' + DOMAIN],
      type: 3,
      password: 'frontend-service-password',
      salt: userSalt(REALM, 'HTTPfrontend'),
      okAsDelegate: true,
      // TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION is what lets it get a
      // FORWARDABLE ticket out of S4U2Self — the protocol-transition half.
      // Without it S4U2Self still works and returns a ticket that is not
      // forwardable, so classic S4U2Proxy then fails for a reason that looks
      // nothing like a missing flag on the front-end account.
      trustedToAuthenticateForDelegation: true,
      // Classic constrained delegation: the list of services this one may reach
      // as anybody. Note it names a SERVICE, not an account — and the SPN has
      // to match exactly.
      allowedToDelegateTo: ['HTTP/backend.' + DOMAIN],
      description: 'a front-end service trusted for CLASSIC constrained ' +
                   'delegation (S4U2Self + S4U2Proxy to HTTP/backend), and ' +
                   'for protocol transition',
      pac: {
        rid: 1120,
        groups: [RID.DOMAIN_USERS],
        userAccountControl:
          UAC.NORMAL_ACCOUNT | UAC.TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION |
          UAC.DONT_EXPIRE_PASSWORD
      }
    },
    {
      name: ['HTTP', 'backend.' + DOMAIN],
      type: 3,
      password: 'backend-service-password',
      salt: userSalt(REALM, 'HTTPbackend'),
      description: 'the back-end reached by CLASSIC constrained delegation — ' +
                   'it authorizes nothing itself; the permission is on the ' +
                   'front end',
      pac: { rid: 1121, groups: [RID.DOMAIN_USERS],
             userAccountControl: UAC.NORMAL_ACCOUNT }
    },
    {
      // The same classic configuration as `frontend` MINUS
      // TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION. This account exists because
      // that flag's absence is invisible where it is set: S4U2Self still
      // succeeds and returns a ticket that simply is not forwardable, and
      // classic S4U2Proxy then fails a step later complaining about the
      // evidence. Two accounts differing in exactly one attribute is the only
      // way to show which attribute did it.
      name: ['HTTP', 'notrusted.' + DOMAIN],
      type: 3,
      password: 'notrusted-service-password',
      salt: userSalt(REALM, 'HTTPnotrusted'),
      trustedToAuthenticateForDelegation: false,
      allowedToDelegateTo: ['HTTP/backend.' + DOMAIN],
      description: 'allowed to delegate to HTTP/backend but NOT trusted for ' +
                   'protocol transition, so its S4U2Self ticket is not ' +
                   'forwardable and classic S4U2Proxy fails',
      pac: { rid: 1123, groups: [RID.DOMAIN_USERS],
             userAccountControl: UAC.NORMAL_ACCOUNT }
    },
    {
      name: ['HTTP', 'rbcd.' + DOMAIN],
      type: 3,
      password: 'rbcd-service-password',
      salt: userSalt(REALM, 'HTTPrbcd'),
      // RESOURCE-based: this account names who may act on ITS behalf. The list
      // is on the TARGET, which is the inversion that matters.
      allowedToActOnBehalfOf: ['HTTP/frontend.' + DOMAIN],
      description: 'a back-end that authorizes RESOURCE-BASED constrained ' +
                   'delegation itself, naming HTTP/frontend as permitted to ' +
                   'act on its behalf',
      pac: { rid: 1122, groups: [RID.DOMAIN_USERS],
             userAccountControl: UAC.NORMAL_ACCOUNT }
    },
    {
      // -----------------------------------------------------------------------
      // THE TRUST. This one principal IS the cross-realm relationship.
      //
      // krbtgt/PARTNER.COM@EXAMPLE.COM: the inter-realm ticket-granting
      // account. When a client of EXAMPLE.COM asks for a service in
      // PARTNER.COM, this realm's KDC has no such service and does NOT refuse —
      // it issues a ticket-granting ticket for krbtgt/PARTNER.COM sealed with
      // THIS key, and the client presents that to the other realm's KDC. Both
      // realms hold the same key, which is what makes it openable there and
      // nowhere else.
      //
      // Its salt is name-shaped like any other account, and its etypes are
      // deliberately AES-only: a trust that still had an RC4 key is the
      // configuration that breaks on a 2025 domain controller, and the KDC's
      // etype negotiation for a referral has to be driven by THIS account
      // rather than by the service the client actually asked for.
      // -----------------------------------------------------------------------
      name: ['krbtgt', TRUSTED_REALM],
      type: 2,
      password: TRUST_PASSWORD,
      salt: userSalt(REALM, 'krbtgt'),
      etypes: [18, 17],
      description: 'the inter-realm trust with ' + TRUSTED_REALM + ' — a ' +
          'shared key, held as a principal',
      pac: {
        rid: 1112,
        groups: [RID.DOMAIN_USERS],
        // ok-as-delegate on the ticket and TRUSTED_FOR_DELEGATION in the PAC
        // are the same setting seen from the two ends: [MS-SAMR] says this bit
        // is what makes the KDC set that flag. Keeping them consistent here
        // means the workflow can show the cause beside the effect.
        userAccountControl: UAC.NORMAL_ACCOUNT | UAC.TRUSTED_FOR_DELEGATION |
          UAC.DONT_EXPIRE_PASSWORD
      }
    }
  ];

  // The trusted realm's own database. It holds the same trust key (the other
  // half of the relationship), its own ticket-granting service, and a service
  // to reach — which is the destination a referral is FOR. There is
  // deliberately NO second copy of the trust key here.
  //
  // The inter-realm account is krbtgt/PARTNER.COM@EXAMPLE.COM — one principal,
  // whose realm is the ISSUING realm — and both KDCs consult that same entry:
  // the issuer to seal the referral, and the target because the arriving
  // ticket's own `realm` field says EXAMPLE.COM, which is what handleTgsReq
  // looks it up by. Holding a second copy under PARTNER.COM would be two
  // secrets that have to stay equal, and the failure when they drift is "the
  // ticket does not decrypt" at the second KDC — a message about a ticket for a
  // problem about a trust. One entry cannot drift from itself.
  //
  // What PARTNER.COM does need is its OWN ticket-granting service, whose key is
  // a different secret from the trust: it signs the PAC and seals tickets for
  // its own services. Giving it the trust password would have made the two
  // indistinguishable, and every assertion about which key signed what would
  // have passed for the wrong reason.
  const TRUSTED_DEFINITIONS = [
    {
      name: ['krbtgt', TRUSTED_REALM],
      type: 2,
      password: config.value('krb5.trustedKrbtgtPassword'),
      salt: userSalt(TRUSTED_REALM, 'krbtgt'),
      realm: TRUSTED_REALM,
      description: TRUSTED_REALM + "'s own ticket-granting service — NOT the " +
                                   "trust key"
    },
    {
      // A user native to the trusted realm. Without one, the second realm is
      // only ever a referral TARGET and the code path where a ticket-granting
      // ticket is looked up in its own realm is never exercised —
      // krbtgt/PARTNER.COM exists in both databases, so a lookup that defaults
      // to the local realm finds the TRUST key instead of this realm's own, and
      // every ticket issued inside PARTNER.COM would be sealed with the wrong
      // secret. A referral test cannot catch that, because there the ticket's
      // realm and the default happen to agree.
      name: ['carol'],
      type: 1,
      salt: userSalt(TRUSTED_REALM, 'carol'),
      realm: TRUSTED_REALM,
      description: 'a user in ' + TRUSTED_REALM + ', so that realm is a ' +
                   'realm and not just a target',
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
      description: 'a service in ' + TRUSTED_REALM + ', reachable only by ' +
                                                     'following a referral',
      pac: {
        rid: 2101,
        groups: [RID.DOMAIN_USERS],
        userAccountControl: UAC.NORMAL_ACCOUNT
      }
    }
  ];

  // The trust — `krbtgt/<trusted realm>@<this realm>`, the last fixture above —
  // and the trusted realm's own database are the DEFAULT realm's alone. Another
  // trust realm's KDC holds no inter-realm key, so a service in another realm's
  // domain is simply unknown there rather than a referral.
  const fixtures = DEFINITIONS.filter(function (def) {
    return def !== KRBTGT_DEFINITION &&
           (ctx.isDefault || String(def.name[0]) !== 'krbtgt');
  });
  log.debug("Leaving definitionsFor().");
  return { krbtgt: KRBTGT_DEFINITION, fixtures: fixtures,
           trusted: ctx.isDefault ? TRUSTED_DEFINITIONS : [] };
}

// Which realms this KDC answers for, AS THE AMBIENT TRUST REALM. A real KDC
// answers for exactly one; the default realm's answers for two so the whole
// referral chase is reachable without a second container.
//
// **ONE IN PRODUCT MODE.** The second realm, its krbtgt, its user and the trust
// are all fixtures (`ctx.SEEDS_DEMO`), so a KDC that went on answering for
// PARTNER.COM would be answering for a realm it holds nothing in.
// KDC_ERR_WRONG_REALM is the true answer to a request naming it.
//
// **ONE, OR NONE, IN ANOTHER TRUST REALM** (2026-09-15): its own name while its
// Kerberos is on, and nothing while it is off.
function realmsServed() {
  log.debug("Entering realmsServed().");
  const ctx = current();
  log.debug("Leaving realmsServed().");
  return servedBy(ctx);
}

function servedBy(ctx) {
  log.debug("Entering servedBy().");
  // `enabledIn()` as well as `active`: the default realm's context is built
  // once and stays active, and `krb5.enabled` is runtime on the service.
  if (!ctx || !ctx.active || !enabledIn(ctx.id)) {
    log.debug("Leaving servedBy(). Inactive.");
    return [];
  }
  log.debug("Leaving servedBy().");
  return ctx.isDefault && ctx.SEEDS_DEMO ? [ctx.REALM, TRUSTED_REALM] :
                                           [ctx.REALM];
}

function domainSidFor(realm) {
  log.debug("Entering domainSidFor().");
  const ctx = current();
  log.debug("Leaving domainSidFor().");
  return ctx.isDefault && realm === TRUSTED_REALM ? TRUSTED_DOMAIN_SID :
                                                    ctx.DOMAIN_SID;
}

// Which realm a service principal belongs to, decided from its HOST NAME.
//
// This is the piece that does not look like protocol and is: a client asks for
// HTTP/app.partner.com without knowing which realm that is, and its own KDC has
// to work it out. Windows does it by looking the SPN up in the forest and,
// failing that, by matching the host's DNS suffix against the trusted domains —
// which is exactly the suffix match below, and exactly why a service whose DNS
// name does not match its realm is such a persistent source of "the KDC says
// the principal is unknown" on hosts that plainly exist.
//
// Returns null when nothing claims it, which is a genuine
// KDC_ERR_S_PRINCIPAL_UNKNOWN rather than a referral.
function realmForService(nameComponents) {
  log.debug("Entering realmForService().");
  if (!nameComponents || nameComponents.length < 2) {
    log.debug("Leaving realmForService().");
    return null;
  }
  const ctx = current();
  if (!ctx.active) {
    log.debug("Leaving realmForService(). No KDC in this realm.");
    return null;
  }
  const host = String(nameComponents[nameComponents.length - 1]).toLowerCase();
  // No trust exists in product mode (see realmsServed()), nor in any trust
  // realm but the default, so no host belongs to the trusted realm there and
  // the name is simply unknown.
  if (ctx.isDefault && ctx.SEEDS_DEMO &&
      (host === TRUSTED_DOMAIN || host.endsWith('.' + TRUSTED_DOMAIN))) {
    log.debug("Leaving realmForService().");
    return TRUSTED_REALM;
  }
  if (host === ctx.DOMAIN || host.endsWith('.' + ctx.DOMAIN)) {
    log.debug("Leaving realmForService().");
    return ctx.REALM;
  }
  log.debug("Leaving realmForService().");
  return null;
}

// Keys are derived once, lazily, and cached: string-to-key is thousands of
// PBKDF2 rounds per etype per principal, and deriving them all at startup would
// make the service slow to start for keys most runs never use.
// -------------------------------------------------------------------------
// PERSISTED (2026-09-06), AND PER TRUST REALM SINCE 2026-09-15.
// It was `realms.sharedMap()` — one row set for the process, `scope: 'shared'`
// — while the KDC was one of the socket families a trust realm did not get.
// Each realm's principal database is now a PARTITION of a `realms.map()`, so a
// realm removed takes its principals with it and `tests/realm_isolation.js`
// holds it to the same rule as every other per-realm store. The map key still
// carries the Kerberos realm (see keyOf()), because the default realm's
// partition holds two Kerberos realms in development.
// -------------------------------------------------------------------------
// **A LONG-TERM KEY IS THE PASSWORD**, which is why every row here is sealed
// before it reaches the store.
//
// ---------------------------------------------------------------------------
// A RESTORED ROW DOES NOT GET TO OVERRIDE THE SETTINGS (2026-09-12).
//
// This store holds two kinds of row, and until this date a restore treated
// them as one. A CONFIGURED principal — krbtgt, the acceptor's account built
// from `krb5.servicePrincipal` / `krb5.servicePassword` / `krb5.serviceSalt`,
// every fixture — is BUILT FROM SETTINGS AND CODE by buildDatabase() at require
// time, and only then written down. A RUNTIME-MADE principal — one
// findOrCreateUser()/findOrCreateService() invented (`autoCreated`), or a
// directory person directoryUser() registered (`directoryKeys`) — exists
// nowhere BUT the store.
//
// The restore put back whole rows. So a configured account came back with the
// password, salt, etypes and kvno it had when the row was written, and a
// changed `krb5.servicePassword` (or `krb5.enctypes`, or `krb5.kvno`) silently
// did not take effect for as long as that row lived. Worse, a process whose
// settings no longer create an account — product mode after a development run,
// a krbtgt refused for its published password, a renamed SPN — had it put
// back anyway, with whatever password it was written with.
//
// **THE RULE, AT THE ONE BOUNDARY BOTH DOORS REACH.** `reconcile` below is
// asked by the store's `restore` and `remove` accessors, which are what the
// startup restore AND the replication applier call — so another process's
// write obeys it exactly as a restart does. **It is asked about the realm the
// row belongs to** (2026-09-15), and answers from that realm's context:
//
//   * a key THIS PROCESS CONFIGURED in that realm (`ctx.configuredKeys`) keeps
//     every field its settings built and takes only RUNTIME_FIELDS from the
//     row. A difference
//     in anything else is LOGGED (STS-KRB-0111), by field name and never by
//     value, so an operator can see that a stored row was stale;
//   * a RUNTIME-MADE row is restored WHOLE — it has no other source;
//   * any other row is NOT restored (STS-KRB-0112): it claims to be configured
//     and this process's settings do not configure it;
//   * a replicated REMOVAL of a configured key is refused (STS-KRB-0113) — a
//     configured account exists because the settings build it, and nothing in
//     this service deletes one.
//
// **WHAT IS RUNTIME STATE ON A CONFIGURED PRINCIPAL IS EXACTLY ONE FIELD**, and
// that is a finding rather than a guess: every write to a configured principal
// after buildDatabase() is signOut() and clearSignOut() (called from
// `logout/logout.js`, `admin-core/admin_actions.js` and `krb5_kdc.js`'s AS
// handler), and both write `signedOutAt`. `revoked` looks like runtime state
// and is not — it is set only by the `locked` fixture's definition and nothing
// mutates it. directoryUser() moves `kvno`, `salt` and `etypes`, but only on a
// `directoryKeys` record, which is restored whole. A field that becomes runtime
// state later is a row added to RUNTIME_FIELDS, in the same commit as its first
// writer — or a restart silently undoes that writer's work.
//
// **NOTHING IS WRITTEN BACK.** A stale stored row is corrected the next time
// anything writes that key (a sign-out writes the WHOLE record this process
// holds, which carries the current settings). Rewriting from inside the
// applier would be two processes with different settings exchanging one row
// for ever — the one unbounded failure `persistence/CLAUDE.md` warns about.
// ---------------------------------------------------------------------------
const RUNTIME_FIELDS = ['signedOutAt'];

// The keys buildDatabase() registered from settings and code are
// `ctx.configuredKeys`, one set per realm's context. The default realm's is
// filled at require time, before any restore can run, and never shrunk: a
// configured account does not stop being configured while the process that
// configured it is running. Another realm's is filled when its database is
// built and REPLACED when it is rebuilt — see rebuildContext().

// The fields, by name, on which a stored row differs from what this process
// built. JSON on both sides because the stored row has been through JSON —
// `passwordMustChange` is a Date here and an ISO string there, and the key
// cache is non-enumerable so it is compared by neither.
function configDrift(incoming, held) {
  log.debug("Entering configDrift().");
  const names = new Set(Object.keys(held).concat(Object.keys(incoming)));
  const differing = [];
  names.forEach(function (name) {
    if (RUNTIME_FIELDS.indexOf(name) !== -1) {
      return;
    }
    if (JSON.stringify(incoming[name]) !== JSON.stringify(held[name])) {
      differing.push(name);
    }
  });
  log.debug("Leaving configDrift().");
  return differing.sort();
}

// A different principal already holding this row's RID, or null. Asked of a
// runtime-made row on the way in, so that a collision the allocator did not
// make — one left by the allocator before autoRidFor(), or the residual it
// states — is SEEN rather than silently restored beside its twin.
function ridHolderOtherThan(key, rid, partition) {
  log.debug("Entering ridHolderOtherThan().");
  let holder = null;
  (partition || principals).forEach(function (principal, otherKey) {
    if (!holder && otherKey !== key && principal && principal.pac &&
        Number(principal.pac.rid) === Number(rid)) {
      holder = otherKey;
    }
  });
  log.debug("Leaving ridHolderOtherThan().");
  return holder;
}

function reconcileRestored(key, incoming, held, realmId, partition) {
  log.debug('Entering reconcileRestored(). key=' + key + ' realm=' + realmId);
  if (!incoming || typeof incoming !== 'object' ||
      !Array.isArray(incoming.name)) {
    log.warn(errorCodes.tag('STS-KRB-0112') + 'krb5: a stored row under "' +
             key +
             '" is not a principal record, so it was not restored.');
    log.debug('Leaving reconcileRestored(). Not a record.');
    return undefined;
  }
  // THE REALM'S CONTEXT, built now if it has not been. A row for a realm this
  // process has not heard of yet — replication can deliver a principal before
  // the realm it belongs to — has no settings to judge it by, so it is judged
  // as a realm with nothing configured: a runtime-made row is kept whole and
  // waits in the partition the realm will use, and a configured one is not
  // restored, because it will be BUILT when that realm's Kerberos is.
  const ctx = contextOf(realmId);
  // **`held` IS READ AGAIN AFTER THE CONTEXT IS BUILT, AND THAT IS NOT
  // BELT-AND-BRACES** (2026-09-15). The caller evaluates `target.get(key)` on
  // the way in, and for a realm whose database has not been built yet that is
  // `undefined` — then `contextOf()` above BUILDS it, registering exactly the
  // configured principals this row might be one of. Reading the argument would
  // therefore take the branch below on the first restored row of every
  // non-default realm, discarding the row's runtime state: a sign-out stamped
  // on that realm's krbtgt or acceptor account would silently not survive a
  // restart, which is the one field this reconciler exists to carry across.
  const here = partition ? partition.get(key) : held;
  if (ctx.configuredKeys.has(key)) {
    if (!here) {
      // Unreachable while the removal half refuses a configured key, and
      // answered the safe way if it is ever reached: a configured account is
      // built from settings, so there is nothing in the row to build it from.
      log.debug('Leaving reconcileRestored(). Configured and not held.');
      return undefined;
    }
    const differing = configDrift(incoming, here);
    if (differing.length) {
      log.warn(errorCodes.tag('STS-KRB-0111') + 'krb5: the stored row for ' +
               'the configured principal ' + key + ' differs from what this ' +
               'process\'s settings build, in ' + differing.join(', ') + '. ' +
               'The settings were kept; ' +
               'only ' + RUNTIME_FIELDS.join(', ') + ' ' +
               'was taken from the row. The stored row is corrected the next ' +
               'time this principal is written.');
    }
    RUNTIME_FIELDS.forEach(function (field) {
      here[field] = incoming[field] === undefined ? null : incoming[field];
    });
    log.debug('Leaving reconcileRestored(). Configured; runtime state taken.');
    return here;
  }
  if (incoming.autoCreated || incoming.directoryKeys) {
    const rid = incoming.pac && incoming.pac.rid;
    const twin = rid === undefined || rid === null ? null :
                 ridHolderOtherThan(key, rid, partition);
    if (twin) {
      log.warn(errorCodes.tag('STS-KRB-0114') +
               'krb5: the restored principal ' +
               key + ' carries RID ' + rid + ', which ' + twin + ' already ' +
               'holds here. Neither was renumbered — an existing account ' +
               'keeps its SID — but a service authorizing on the PAC cannot ' +
               'tell the two apart.');
    }
    log.debug('Leaving reconcileRestored(). Runtime-made; restored whole.');
    return withKeyCache(incoming);
  }
  log.warn(errorCodes.tag('STS-KRB-0112') + 'krb5: the stored principal ' +
           key +
           ' was not restored: it is not auto-created or directory-keyed, ' +
           'and this process\'s settings do not configure it (a different ' +
           'mode, a refused published password, or a renamed principal).');
  log.debug('Leaving reconcileRestored(). Not configured here.');
  return undefined;
}

function reconcileRemoved(key, held, realmId) {
  log.debug("Entering reconcileRemoved().");
  if (contextOf(realmId).configuredKeys.has(key)) {
    log.warn(errorCodes.tag('STS-KRB-0113') + 'krb5: a stored removal of the ' +
             'configured principal ' + key + ' was refused; it exists ' +
             'because this process\'s settings build it.');
    log.debug("Leaving reconcileRemoved().");
    return false;
  }
  log.debug("Leaving reconcileRemoved().");
  return true;
}

const principals = realms.map({ persist: 'krb5.principals',
                                reconcile: { restore: reconcileRestored,
                                             remove: reconcileRemoved } });

// ---------------------------------------------------------------------------
// RIDs FOR THE ACCOUNTS MADE AT RUNTIME, DERIVED FROM THE NAME (2026-09-12).
//
// From 5000 up, well clear of the configured ones (the 1100s here, the 2100s in
// PARTNER.COM, the well-known RIDs below 1000) on purpose: a service
// authorizing on the PAC sees a SID and nothing else, so the range is the only
// way to tell an account that was configured from one that turned up at
// runtime.
//
// **IT HAS BEEN THREE THINGS AND THE FIRST TWO COLLIDED.** A counter
// (`let autoRidNext = 5000`) restarted at 5000 in a process whose store came
// back holding 5000, 5001 and 5002. Its replacement read one above the highest
// RID in the database, which fixed a restart and not a second PROCESS: two
// processes creating accounts in the same instant both read the same highest
// RID before either write replicated, and handed one SID to two accounts. A
// service authorizing on the PAC cannot tell two accounts with one SID apart,
// so that is an impersonation rather than a cosmetic collision.
//
// **NOW A RID IS A FUNCTION OF THE PRINCIPAL'S OWN NAME.** SHA-256 over
// `name@realm`, the first 48 bits reduced into [AUTO_RID_BASE, AUTO_RID_LIMIT),
// then a linear probe past any slot a DIFFERENT principal in this database
// already holds. What that buys, and what the tests pin:
//
//   * two processes creating the SAME name compute the same RID with no
//     coordination at all — which is the concurrent case that actually happens,
//     a client retrying an AS-REQ against two workers;
//   * an EXISTING account keeps whatever RID it has — nothing here renumbers,
//     so a SID already in somebody's ticket, ACL or log still means what it did
//     (every caller asks only when creating, and directoryUser() keeps the RID
//     of a record it replaces);
//   * a configured RID is never produced: the range starts above all of them.
//
// **THE RANGE ENDS AT 2^30**, the size of Active Directory's global RID pool
// (the 31st bit is reserved and unlocked only by an explicit domain operation),
// so a SID minted here is one a real domain could have issued, and nothing
// reading the value as a signed 32-bit integer — [MS-PAC]'s NDR is unsigned,
// not every consumer is — sees a negative. The span is ~1.07 billion slots.
//
// **THE PROBE TERMINATES BY PIGEONHOLE, NOT BY LUCK.** It looks at most one
// slot more than there are principals, and at most that many slots can be
// taken — a JavaScript Map cannot hold a thousandth of the span.
//
// **THE RESIDUAL, AND WHY IT IS NOT A `common/mode.js` ROW.** Two DIFFERENT
// names whose hashes land on the same slot, created in two processes inside one
// replication window, get one RID — as does one name whose probe path differs
// between two processes because one of them already holds a principal on the
// slot and the other has not replicated it yet. Both need two names to meet on
// one slot in ~1.07 billion within ONE replication window
// (`persistence.pollInterval`, and 0.5–1s with LISTEN/NOTIFY): the expected
// number of such meetings among n accounts first created inside one window is
// about n²/2.1e9 — one in two thousand for a thousand simultaneous first
// sign-ins, one in twenty for ten thousand — against a CERTAINTY for any two
// concurrent creations under the allocator this replaced. Accounts created in
// different windows cannot meet at all, because the probe sees the replicated
// one. Runtime-made accounts are, in product mode, a directory person's first
// Kerberos sign-in, so ten thousand inside one second is not a shape a
// deployment produces. And it is not SILENT: a restored or replicated
// runtime-made row whose RID another principal holds is logged as STS-KRB-0114
// (see reconcileRestored()). A collision-proof allocator is a coordinated
// write, which is a store feature this service does not have; the remaining
// window is not worth a design an operator would have to run.
// ---------------------------------------------------------------------------
const AUTO_RID_BASE = 5000;
const AUTO_RID_LIMIT = 0x40000000;

function autoRidFor(nameComponents, realm) {
  log.debug('Entering autoRidFor().');
  const key = keyOf({ name: (nameComponents || []).map(String),
                      realm: realm || current().REALM });
  const span = AUTO_RID_LIMIT - AUTO_RID_BASE;
  // A label in front of the name, so this digest is never the same bytes as
  // any other SHA-256 of a principal name something else computes.
  const digest = nodeCrypto.createHash('sha256')
    .update('sts-krb5-auto-rid:' + key, 'utf8').digest();
  // 48 bits is an exact integer in a double, and 2^48 mod ~2^30 leaves a bias
  // of about one part in a quarter of a million — nothing a SID can show.
  const start = digest.readUIntBE(0, 6) % span;
  const taken = new Map();
  principals.forEach(function (principal, otherKey) {
    const rid = Number(principal && principal.pac && principal.pac.rid);
    if (otherKey !== key && Number.isFinite(rid) && !taken.has(rid)) {
      taken.set(rid, otherKey);
    }
  });
  for (let step = 0; step <= taken.size; step++) {
    const rid = AUTO_RID_BASE + ((start + step) % span);
    if (!taken.has(rid)) {
      if (step) {
        log.info('krb5: ' + key + ' hashes to RID ' + (AUTO_RID_BASE + start) +
                 ', which ' + taken.get(AUTO_RID_BASE + start) + ' holds; it ' +
                 'was given ' + rid + ', ' + step + ' slot(s) on.');
      }
      log.debug('Leaving autoRidFor(). ' + rid);
      return rid;
    }
  }
  log.debug("Leaving autoRidFor().");
  // Unreachable: `taken.size + 1` distinct slots cannot all be among
  // `taken.size` taken ones. Said as code rather than left as a fall-through
  // that would register an account with no RID.
  throw new Error('krb5: no free RID for ' + key + ' after ' +
                  (taken.size + 1) +
                  ' slots, which cannot happen');
}

// The map key carries the REALM, because two realms are served here and
// krbtgt/PARTNER.COM exists in BOTH of them with different meanings — in
// EXAMPLE.COM it is the trust, and in PARTNER.COM it is that realm's own
// ticket-granting service. Keyed by name alone, the second registration would
// silently overwrite the first and every cross-realm ticket would be sealed
// with the wrong key.
function keyOf(principal) {
  log.debug("Entering keyOf().");
  log.debug("Leaving keyOf().");
  return principal.name.join('/') + '@' + principal.realm;
}

// Into the AMBIENT realm's partition, with that realm's defaults — which is
// the realm `contextOf()` entered while it builds, and the realm the KDC
// entered for the request everywhere else.
function register(def) {
  log.debug('Entering register().');
  const ctx = current();
  const principal = {
    name: def.name,
    type: def.type,
    realm: def.realm || ctx.REALM,
    // A user entry names no password; it gets the one every user shares. A
    // service, computer or krbtgt entry names its own and keeps it — see
    // USER_PASSWORD.
    //
    // **A DIRECTORY-KEYED PRINCIPAL GETS NO PASSWORD AT ALL, AND THAT IS THE
    // SECURITY OF THE FEATURE RATHER THAN A DETAIL OF IT.** Its keys come from
    // the key source (see KEY SOURCE below), and the shared development
    // password left on the record would be a second key for the same account:
    // a cache miss in `longTermKey()` would derive from it, and a product KDC
    // would quietly accept `password!` for every person in the directory.
    password: def.directoryKeys ? null :
      (def.password || ctx.USER_PASSWORD),
    // Whether the long-term keys come from the KEY SOURCE rather than from a
    // password on this record. Persisted with the record (it is not a secret)
    // so a restored principal is never mistaken for one to derive.
    directoryKeys: !!def.directoryKeys,
    salt: def.salt,
    etypes: def.etypes || ctx.KDC_ETYPES.slice(),
    requiresPreAuth: def.requiresPreAuth !== false,
    revoked: !!def.revoked,
    passwordExpired: !!def.passwordExpired,
    okAsDelegate: !!def.okAsDelegate,
    // Delegation, kept as two SEPARATE lists because they are configured on
    // opposite accounts and conflating them would hide the only thing about
    // RBCD worth knowing.
    trustedToAuthenticateForDelegation:
      !!def.trustedToAuthenticateForDelegation,
    notDelegated: !!def.notDelegated,
    allowedToDelegateTo: def.allowedToDelegateTo || [],
    allowedToActOnBehalfOf: def.allowedToActOnBehalfOf || [],
    description: def.description,
    // Whether findOrCreateUser() made this one at runtime rather than it being
    // configured. Reported by GET /krb5/principals, because a table that grows
    // while a person is reading it is confusing unless it says which entries
    // did that.
    autoCreated: !!def.autoCreated,
    // The PAC identity, with the parts every account shares defaulted here
    // rather than repeated nine times. An account with no `pac` block still
    // gets one, so a principal added later cannot silently produce PAC-less
    // tickets.
    pac: Object.assign({
      rid: 1100,
      primaryGroupRid: RID.DOMAIN_USERS,
      groups: [RID.DOMAIN_USERS],
      userAccountControl: UAC.NORMAL_ACCOUNT,
      extraSids: [],
      fullName: null,
      passwordMustChange: null
    }, def.pac || {}),
    // `krb5.kvno`, one version for every account. Rotation is not modelled.
    kvno: ctx.KVNO,
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
    signedOutAt: null
  };
  // THE DERIVED-KEY CACHE IS ATTACHED SEPARATELY AND IS NOT ENUMERABLE — see
  // withKeyCache() below for why.
  withKeyCache(principal);
  principals.set(keyOf(principal), principal);
  log.debug('Leaving register().');
  return principal;
}

// ---------------------------------------------------------------------------
// THE ACCOUNT THE ACCEPTOR HOLDS, BUILT FROM `krb5.servicePrincipal`
// (2026-09-12).
//
// It was the fixture entry `['HTTP', 'web.' + DOMAIN]` with a literal password,
// whatever `krb5.servicePrincipal` said — while `krb5_service.js` looked for
// the SETTING's name. At the default settings the two agree
// (HTTP/web.example.com) and nothing could show the gap; set the SPN to
// anything else and the acceptor's own account did not exist, so every ticket
// for it was "another account's SPN" or unknown. That is wrong in every mode,
// which is why this is not behind the mode: the account is made from the name
// the acceptor is configured to be.
//
// At the default settings the definition built here is the fixture entry field
// for field — same name, same password, same salt, same `okAsDelegate`, same
// description — so an unedited development service's database is unchanged.
//
// **IN PRODUCT MODE THE PUBLISHED PASSWORD IS REFUSED**, and so is an empty
// one. `service-account-password` is printed in this file; a service key
// derived from it lets anybody who has read the repository mint a ticket this
// acceptor will accept as anybody. The account is then not created and
// `serviceAccount()` carries the reason, which the acceptor puts in its refusal
// and GET /krb5/service publishes. The salt is `krb5.serviceSalt` when set,
// because an account in a real KDC is salted with its sAMAccountName and
// nothing here can derive that.
//
// `ok-as-delegate` is ON only where the fixtures are. It is advice to a client
// that it may forward a TGT to this service — which is unconstrained delegation
// on the client's side — and a product deployment that wants that says so in
// its KDC rather than inheriting it from a demonstration.
// ---------------------------------------------------------------------------
// `ctx.serviceAccount` — `{ spn, available, reason }` — is filled here, for the
// realm whose database is being built.
function configuredServiceDefinition(ctx) {
  log.debug('Entering configuredServiceDefinition().');
  const account = ctx.serviceAccount;
  const REALM = ctx.REALM;
  const spn = String(config.value('krb5.servicePrincipal') || '').trim();
  account.spn = spn;
  const parts = spn.split('/');
  if (parts.length < 2 ||
      !parts.every(function (part) { return part.length; })) {
    account.reason = 'krb5.servicePrincipal is "' + spn + '", which ' +
      'is not a service/host name — an SPN has at least two components, so ' +
      'no account was created for the acceptor.';
    log.warn(errorCodes.tag('STS-KRB-0059') + 'krb5: ' + account.reason);
    log.debug('Leaving configuredServiceDefinition(). Not an SPN.');
    return null;
  }
  const password = String(config.value('krb5.servicePassword') || '');
  if (!password) {
    account.reason = 'krb5.servicePassword (KRB5_SERVICE_PASSWORD) ' +
      'is empty, so the ' +
      'account ' + spn + '@' + REALM + ' was not created and ' +
      'the acceptor holds no key to decrypt a ticket with.';
    log.warn(errorCodes.tag('STS-KRB-0060') + 'krb5: ' + account.reason);
    log.debug('Leaving configuredServiceDefinition(). No password.');
    return null;
  }
  if (!ctx.SEEDS_DEMO &&
      password === publishedDefault('krb5.servicePassword')) {
    account.reason = 'product mode refuses the published default ' +
      'krb5.servicePassword: that value is written in this service\'s ' +
      'source, so a key derived from it would let anybody mint a ticket this ' +
      'acceptor accepts. The ' +
      'account ' + spn + '@' + REALM + ' was NOT created, so ' +
      'the acceptor on krb5.servicePort and /authn/spnego accept no ticket. ' +
      'Set KRB5_SERVICE_PASSWORD to the password of that SPN\'s account in ' +
      'the KDC that issues its tickets (and KRB5_SERVICE_SALT to its salt).';
    log.warn(errorCodes.tag('STS-KRB-0061') + 'krb5: ' + account.reason);
    log.debug('Leaving configuredServiceDefinition(). Published default ' +
              'refused.');
    return null;
  }
  const host = parts[parts.length - 1];
  const configuredSalt = String(config.value('krb5.serviceSalt') || '');
  account.available = true;
  account.reason = '';
  log.debug('Leaving configuredServiceDefinition(). ' + spn);
  return {
    name: parts,
    type: 3,
    password: password,
    // The convention the fixture always used: realm + the service name + the
    // host's first label, which for HTTP/web.example.com is EXAMPLE.COMHTTPweb.
    salt: configuredSalt ||
      userSalt(REALM, parts.slice(0, -1).join('') + host.split('.')[0]),
    okAsDelegate: ctx.SEEDS_DEMO,
    description: 'an HTTP service principal, flagged ok-as-delegate'
  };
}

// The fixture HTTP/web entry this replaces when the names match.
function sameName(a, b) {
  log.debug("Entering sameName().");
  log.debug("Leaving sameName().");
  return a.join('/') === b.join('/');
}

// ---------------------------------------------------------------------------
// THE KRBTGT, AND THE ONE REFUSAL IT CARRIES IN PRODUCT MODE.
//
// Its key seals every TGT, so a krbtgt derived from the published
// `krbtgt-mock-password` is a key anybody can forge a ticket-granting ticket
// with — a golden ticket, handed out in the README. Product mode refuses to
// create it; the KDC then issues nothing, which is the truthful state of a KDC
// nobody gave a key. The reason is `ctx.krbtgtReason`.
// ---------------------------------------------------------------------------

// A principal built from settings and code, which a restore may not override.
// See `ctx.configuredKeys` and reconcileRestored() above.
//
// **A REBUILT REALM KEEPS WHAT IS RUNTIME STATE ON IT** (2026-09-15): a
// trust realm's database is rebuilt when a setting it was built from changes,
// and a sign-out instant stamped on a configured account before that must still
// be there after it — so the RUNTIME_FIELDS of a record already held under the
// same key are carried onto the new one.
function registerConfigured(def) {
  log.debug("Entering registerConfigured().");
  const ctx = current();
  const key = keyOf({ name: def.name, realm: def.realm || ctx.REALM });
  const held = principals.get(key);
  const principal = register(def);
  if (held) {
    RUNTIME_FIELDS.forEach(function (field) {
      if (held[field] !== undefined) {
        principal[field] = held[field];
      }
    });
    principals.set(key, principal);
  }
  ctx.configuredKeys.add(key);
  log.debug("Leaving registerConfigured().");
  return principal;
}

function buildDatabase(ctx) {
  log.debug('Entering buildDatabase(). realm=' + ctx.REALM);
  const defs = definitionsFor(ctx);
  const service = configuredServiceDefinition(ctx);
  let serviceRegistered = false;
  if (!ctx.SEEDS_DEMO &&
      defs.krbtgt.password === publishedDefault('krb5.krbtgtPassword')) {
    ctx.krbtgtReason = 'product mode refuses the published default ' +
      'krb5.krbtgtPassword (KRB5_KRBTGT_PASSWORD): a krbtgt key derived from ' +
      'it would let anybody forge a ticket-granting ticket. ' +
      'krbtgt/' + ctx.REALM + ' ' +
      'was NOT created, so this KDC issues no ticket until it is set.';
    log.warn(errorCodes.tag('STS-KRB-0062') + 'krb5: ' + ctx.krbtgtReason);
  } else {
    registerConfigured(defs.krbtgt);
  }
  if (ctx.SEEDS_DEMO) {
    defs.fixtures.forEach(function (def) {
      if (service && !serviceRegistered && sameName(def.name, service.name)) {
        // In place, so the database lists its accounts in the order it always
        // did.
        registerConfigured(service);
        serviceRegistered = true;
        return;
      }
      registerConfigured(def);
    });
    defs.trusted.forEach(registerConfigured);
  } else {
    log.info('krb5: product mode, so the fixture accounts (alice, bob, ' +
             'locked, expired, the computer account, the delegation services ' +
             'and their rules' +
             (ctx.isDefault ? ', and the ' + TRUSTED_REALM + ' realm and ' +
                              'trust' : '') + ') were NOT ' +
             'created. This KDC holds krbtgt/' + ctx.REALM + ' and ' +
             (ctx.serviceAccount.spn || 'no service account') + ' where ' +
             'their passwords are configured, and nothing else.');
  }
  if (service && !serviceRegistered) {
    registerConfigured(service);
  }
  log.debug('Leaving buildDatabase().');
}

// ---------------------------------------------------------------------------
// THE CONTEXTS: ONE PER TRUST REALM, BUILT FROM THAT REALM'S SETTINGS
// (2026-09-15).
//
// See the header of this file for why. The mechanics, each of which is what
// something below depends on:
//
//   * **A CONTEXT IS PUT IN THE MAP BEFORE ITS DATABASE IS BUILT**, because
//     building registers principals and register() asks current() for the
//     defaults — which must find the context being built rather than start
//     building it a second time.
//   * **THE DEFAULT REALM'S IS BUILT ONCE, AT REQUIRE TIME**, from the
//     process's values (`realms.run()` there reads no realm layer), and is
//     never rebuilt: its settings are restart-only for the process.
//   * **ANOTHER REALM'S IS BUILT ON FIRST USE WHILE ITS KERBEROS IS ON**, and a
//     realm whose Kerberos is off gets an INACTIVE context — no principal, no
//     name served — which is cached too, so it is not recomputed per request.
//   * **A REALM'S CONTEXT IS REBUILT WHEN ONE OF `BUILT_FROM` CHANGES ON IT**,
//     compared as a signature over the realm's own overrides. A change to any
//     other setting — a runtime row such as krb5.clockSkew, which is read per
//     request — leaves the database alone. A rebuild removes the configured
//     accounts the new settings no longer build (a renamed SPN, a realm turned
//     off) and keeps every runtime-made one; see rebuildContext().
// ---------------------------------------------------------------------------
const contexts = new Map();

const BUILT_FROM = ['krb5.enabled', 'krb5.realm', 'krb5.domainSid',
                    'krb5.krbtgtPassword', 'krb5.servicePrincipal',
                    'krb5.servicePassword', 'krb5.serviceSalt', 'krb5.kvno',
                    'krb5.enctypes', 'krb5.userPassword',
                    'krb5.autoServicePassword', 'global.mode'];

function builtFromSignature(realm) {
  log.debug("Entering builtFromSignature().");
  const own = (realm && realm.overrides) || {};
  log.debug("Leaving builtFromSignature().");
  return JSON.stringify(BUILT_FROM.map(function (key) {
    return [key, own[key] === undefined ? null : own[key]];
  }));
}

function idOf(realmId) {
  log.debug("Entering idOf().");
  log.debug("Leaving idOf().");
  return !realmId || realmId === realms.DEFAULT_ID ? realms.DEFAULT_ID :
                                                     String(realmId);
}

// The Kerberos realm a trust realm answers as: the process's for the default
// realm, and the realm's OWN `krb5.realm` for any other — never an inherited
// one, since two realms answering to one name is a request nothing can route.
// Empty for a realm that names none.
function nameOf(realmId) {
  log.debug("Entering nameOf().");
  const id = idOf(realmId);
  if (id === realms.DEFAULT_ID) {
    log.debug("Leaving nameOf(). The default realm.");
    return String(realms.run(realms.DEFAULT_REALM, function () {
      return config.value('krb5.realm');
    }) || '');
  }
  const realm = realms.get(id);
  const raw = realm && realm.overrides ? realm.overrides['krb5.realm'] :
                                         undefined;
  log.debug("Leaving nameOf().");
  return raw === undefined || raw === null ? '' : String(raw).trim();
}

// Whether a trust realm's KDC answers. The default realm reads `krb5.enabled`,
// which is on unless somebody turned the service's Kerberos off. Another realm
// reads its OWN override — as `spiffe_server.js` does for `spiffe.enabled` — so
// clearing it is off rather than an inherited on, and it counts only with a
// name of its own beside it (realms.js refuses the one without the other; a
// realm restored from before that rule is held to it here).
function enabledIn(realmId) {
  log.debug("Entering enabledIn().");
  const id = idOf(realmId);
  if (id === realms.DEFAULT_ID) {
    log.debug("Leaving enabledIn(). The default realm.");
    return !!realms.run(realms.DEFAULT_REALM, function () {
      return config.value('krb5.enabled');
    });
  }
  const realm = realms.get(id);
  const own = (realm && realm.overrides) || {};
  if (!Object.prototype.hasOwnProperty.call(own, 'krb5.enabled')) {
    log.debug("Leaving enabledIn(). Not set on the realm.");
    return false;
  }
  const parsed = config.parseAs('krb5.enabled', own['krb5.enabled']);
  log.debug("Leaving enabledIn().");
  return !!(parsed.ok && parsed.value === true) && !!nameOf(id);
}

function inactiveContext(id, reason) {
  log.debug("Entering inactiveContext(). realm=" + id);
  const name = nameOf(id);
  log.debug("Leaving inactiveContext().");
  return {
    id: id, isDefault: false, active: false, inactiveReason: reason,
    REALM: name, DOMAIN: name.toLowerCase(), SEEDS_DEMO: false,
    KDC_ETYPES: [], KVNO: null, USER_PASSWORD: null,
    AUTO_SERVICE_PASSWORD: null, SERVICE_DOMAINS: [], DOMAIN_SID: '',
    KRBTGT_PASSWORD: null,
    serviceAccount: { spn: '', available: false, reason: reason },
    krbtgtReason: reason, configuredKeys: new Set(),
    signature: builtFromSignature(realms.get(id))
  };
}

function buildContext(realm) {
  log.debug("Entering buildContext(). realm=" + realm.id);
  const isDefault = realm.id === realms.DEFAULT_ID;
  const ctx = realms.run(realm, function () {
    const name = isDefault ? String(config.value('krb5.realm')) :
                             nameOf(realm.id);
    const etypes = configuredEtypes(realm.id);
    const built = {
      id: realm.id, isDefault: isDefault, active: true, inactiveReason: '',
      REALM: name,
      DOMAIN: name.toLowerCase(),
      SEEDS_DEMO: mode.seedsDemoData(),
      KDC_ETYPES: etypes.ids || [],
      // Every account's key version. One per account: rotation is not
      // modelled — see `krb5.kvno`.
      KVNO: config.value('krb5.kvno'),
      USER_PASSWORD: config.value('krb5.userPassword'),
      AUTO_SERVICE_PASSWORD: config.value('krb5.autoServicePassword'),
      SERVICE_DOMAINS: serviceDomainsFor(),
      DOMAIN_SID: config.value('krb5.domainSid'),
      KRBTGT_PASSWORD: config.value('krb5.krbtgtPassword'),
      serviceAccount: { spn: '', available: false, reason: '' },
      krbtgtReason: '',
      configuredKeys: new Set(),
      signature: builtFromSignature(isDefault ? null : realm)
    };
    contexts.set(realm.id, built);
    if (!etypes.ids) {
      built.active = false;
      built.inactiveReason = etypes.problem;
      built.serviceAccount.reason = etypes.problem;
      built.krbtgtReason = etypes.problem;
      return built;
    }
    buildDatabase(built);
    return built;
  });
  if (ctx.active) {
    log.info('krb5: principal database for ' +
             (isDefault ? 'realm ' + ctx.REALM
                        : 'Kerberos realm ' + ctx.REALM + ' (trust realm "' +
                          realm.id + '")') + ' — ' +
             Array.from(principals.realmMap(realm.id).keys()).join(', '));
  }
  log.debug("Leaving buildContext().");
  return ctx;
}

// THE CONTEXT FOR A TRUST REALM, built if it has not been. A realm this process
// does not hold — removed, or not yet replicated here — gets an inactive
// context that is NOT cached, so the realm is built properly once it arrives.
function contextOf(realmId) {
  const id = idOf(realmId);
  const held = contexts.get(id);
  if (held) {
    return held;
  }
  log.debug("Entering contextOf(). Building for realm " + id);
  const realm = realms.get(id);
  if (!realm) {
    log.debug("Leaving contextOf(). No such realm here.");
    return inactiveContext(id, 'there is no trust realm "' + id + '" in ' +
                                'this process');
  }
  if (!enabledIn(id)) {
    const off = inactiveContext(id, 'Kerberos is off in trust realm "' + id +
      '" (krb5.enabled, with a krb5.realm of its own)');
    contexts.set(id, off);
    log.debug("Leaving contextOf(). Kerberos is off there.");
    return off;
  }
  log.debug("Leaving contextOf().");
  return buildContext(realm);
}

// The AMBIENT realm's context. On the hot path — the KDC asks it several times
// for every request it answers — so no Entering/Leaving pair here, which would
// drown the log; contextOf() logs the one call that builds anything.
function current() {
  return contextOf(realms.currentId());
}

// A REBUILD, for a realm whose `BUILT_FROM` settings changed. The configured
// accounts the new settings no longer build are removed from the realm's
// partition, through the journalling view so every other process sees it; a
// runtime-made account — somebody who authenticated, a directory person — is
// kept, because nothing but the store holds it.
function rebuildContext(realm, old) {
  log.debug("Entering rebuildContext(). realm=" + realm.id);
  contexts.delete(realm.id);
  const fresh = contextOf(realm.id);
  const partition = principals.realmMap(realm.id);
  let removed = 0;
  old.configuredKeys.forEach(function (key) {
    if (!fresh.configuredKeys.has(key) && partition.has(key)) {
      partition.delete(key);
      removed++;
    }
  });
  // **AND EVERY ROW FOR A KERBEROS REALM THIS ONE NO LONGER ANSWERS AS.** The
  // supported way to rename a realm's Kerberos realm is to turn it off, rename
  // it and turn it on, and the runtime-made principals — a directory person
  // keyed at their first sign-in, a service created on demand — are keyed
  // `name@OLD.REALM`. Pruning only the CONFIGURED keys left those behind: rows
  // `find()` can never reach again, carrying a salt and a kvno for a realm that
  // no longer exists, listed on /admin/kerberos/principals beside the live ones
  // and re-journalled for ever. A realm serves exactly one Kerberos realm, so
  // any row naming another is dead by construction.
  if (fresh.active) {
    const served = servedBy(fresh);
    partition.forEach(function (principal, key) {
      if (principal && served.indexOf(String(principal.realm)) === -1) {
        partition.delete(key);
        removed++;
      }
    });
  }
  log.info('krb5: trust realm "' + realm.id + '" changed a setting its ' +
           'principal database is built from, so the database was rebuilt: ' +
           (fresh.active ? 'Kerberos realm ' + fresh.REALM + ', ' +
                           fresh.configuredKeys.size + ' configured account(s)'
                         : 'no KDC (' + fresh.inactiveReason + ')') +
           (removed ? '; ' + removed + ' account(s) the new settings no ' +
                      'longer build, or naming a Kerberos realm this one no ' +
                      'longer answers as, were removed' : '') + '.');
  log.debug("Leaving rebuildContext().");
  return fresh;
}

realms.onChange(function (id, what) {
  log.debug("Entering a realms.onChange listener in krb5_principals.js.");
  const realmId = idOf(id);
  if (realmId === realms.DEFAULT_ID) {
    log.debug("Leaving the listener. The default realm is never rebuilt.");
    return;
  }
  const held = contexts.get(realmId);
  const realm = realms.get(realmId);
  if (what === 'remove' || !realm) {
    contexts.delete(realmId);
    log.debug("Leaving the listener. The realm is gone.");
    return;
  }
  // **A REALM THAT ARRIVES WITH KERBEROS ON IS BUILT NOW, NOT ON FIRST USE**
  // (2026-09-15). A realm restored from the store or replicated from another
  // node is created before its principals are restored — persistence restores
  // realms, then the directory, then what was minted — so building here means
  // the reconciler below almost never has to build one WHILE a row is being
  // restored. It still can (a realm whose rows arrive before the realm does),
  // and that path is correct; what it is not is free, because registering a
  // configured principal is a write, and a write during a replicated apply is
  // journalled. Doing it here moves those writes to the moment the realm
  // appears, where they are exactly the writes a realm's first start makes.
  if (!held && enabledIn(realmId)) {
    contextOf(realmId);
    log.debug("Leaving the listener. Built for a realm that arrived.");
    return;
  }
  if (!held || builtFromSignature(realm) === held.signature) {
    log.debug("Leaving the listener. Nothing it was built from changed.");
    return;
  }
  rebuildContext(realm, held);
  log.debug("Leaving the listener. Rebuilt.");
});

// ROUTING (2026-09-15): the trust realm a Kerberos realm name in a request is
// for, or null when no realm whose Kerberos is on answers to it. Compared
// EXACTLY, as the KDC always compared a request's realm: Kerberos names are
// case-sensitive on the wire, and realms.js refuses two realms whose names
// differ only in case, so an exact miss is a genuine miss.
//
// The default realm is asked first — for its own name and, in development, the
// trusted realm it answers for. A restored or replicated realm that shares a
// name with another (realms.js judges neither) loses to the first, and that is
// LOGGED ONCE per name rather than on every request that meets it.
const collisionsLogged = new Set();

function trustRealmFor(krbName) {
  log.debug("Entering trustRealmFor(). name=" + krbName);
  const name = String(krbName || '');
  if (!name) {
    log.debug("Leaving trustRealmFor(). No name.");
    return null;
  }
  if (servedBy(contexts.get(realms.DEFAULT_ID)).indexOf(name) !== -1) {
    log.debug("Leaving trustRealmFor(). The default realm.");
    return realms.DEFAULT_REALM;
  }
  const matching = realms.list().filter(function (realm) {
    return realm.id !== realms.DEFAULT_ID && nameOf(realm.id) === name &&
           enabledIn(realm.id);
  });
  if (matching.length > 1 && !collisionsLogged.has(name)) {
    collisionsLogged.add(name);
    log.warn(errorCodes.tag('STS-KRB-0127') + 'krb5: the Kerberos realm ' +
             name + ' is claimed by trust realms ' +
             matching.map(function (realm) {
               return '"' + realm.id + '"';
             }).join(', ') + '; requests naming it reach "' +
             matching[0].id + '" only. Give the others a name of their own.');
  }
  log.debug("Leaving trustRealmFor(). " +
            (matching.length ? matching[0].id : 'none'));
  return matching.length ? matching[0] : null;
}

// The Kerberos realms a trust realm's KDC answers for, by id.
function servedIn(realmId) {
  log.debug("Entering servedIn().");
  log.debug("Leaving servedIn().");
  return servedBy(contextOf(realmId));
}

buildContext(realms.DEFAULT_REALM);

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
  log.debug("Entering signOut(). principal=" +
            (nameComponents || []).join('/'));
  const principal = find(nameComponents, realm);
  if (!principal) {
    log.debug("Leaving signOut(). No such principal.");
    return null;
  }
  principal.signedOutAt = asDate(at) || new Date();
  // WRITTEN BACK THROUGH THE STORE, and not merely mutated (2026-09-08). The
  // principal is an object HELD in `principals`, so stamping a field on it
  // changes this process's memory and nothing else: `realms.map()`
  // journals a write when `set()` is called, so an in-place mutation is
  // invisible to the persistence store, never becomes a change row and never
  // reaches another process. With request workers that is a global sign-out
  // that worked on the worker it ran on — and `GET /admin-api/sessions`, which
  // fans out, went on listing the Kerberos ticket as live from a worker that
  // had never heard about it. The same write was lost in one process too: it
  // simply never persisted.
  principals.set(keyOf(principal), principal);
  log.info('krb5: ' + principal.name.join('/') + '@' + principal.realm + ' ' +
      'signed out at ' +
           principal.signedOutAt.toISOString() + '. A TGS-REQ presenting a ' +
           'ticket issued before that is now refused KDC_ERR_TGT_REVOKED ' +
           '(20). A service ticket already in a cache still works against ' +
           'the service that accepts it — nothing contacts this KDC on that ' +
           'exchange.');
  log.debug("Leaving signOut(). Stamped " +
            principal.signedOutAt.toISOString() + ".");
  return principal;
}

function clearSignOut(nameComponents, realm) {
  log.debug("Entering clearSignOut(). principal=" +
            (nameComponents || []).join('/'));
  const principal = find(nameComponents, realm);
  if (!principal || !principal.signedOutAt) {
    log.debug("Leaving clearSignOut(). Nothing was stamped.");
    return null;
  }
  const was = asDate(principal.signedOutAt) || new Date(0);
  principal.signedOutAt = null;
  // Through the store, for signOut()'s reason above — and this direction
  // matters just as much: a CLEARED stamp that never replicated would leave
  // another process refusing every TGS-REQ from somebody who has signed back
  // in, with KDC_ERR_TGT_REVOKED and nothing anywhere to explain it.
  principals.set(keyOf(principal), principal);
  log.info('krb5: the sign-out instant on ' + principal.name.join('/') + '@' +
           principal.realm +
           ' (' + was.toISOString() + ') is cleared; tickets issued before ' +
                                      'it are accepted again.');
  log.debug("Leaving clearSignOut(). Cleared.");
  return was;
}

// The instant, or null. Without entering/leaving logs: the TGS handler calls it
// on every request it answers, and a pair of lines there would be most of the
// Kerberos log on a busy run.
// ---------------------------------------------------------------------------
// THE STAMP AS A `Date`, WHATEVER IT IS ON THE ENTRY (2026-09-08).
//
// `principals` is persisted and replicated, and both of those round-trip a
// value through JSON — where a `Date` becomes an ISO STRING and comes back as
// one. Every reader of this field calls `.toISOString()` or `.getTime()` on
// it, so a principal that arrived from the store or from another process blew
// up in whichever handler read it first. It surfaced as `logout: the krb5
// family could not be read while terminating: already.getTime is not a
// function` — and, because `/admin-api/sessions` reads that inventory, as an
// HTML 500 where two jobs expected JSON.
//
// Coerced on the way OUT rather than repaired on the way in: a restore and a
// replicated apply are two different doors and there will be a third, and the
// one thing every reader shares is this accessor. Callers reading the field
// directly are the two below and `logout.js`'s row builder, which take a
// principal from `find()` and are given the same treatment.
// ---------------------------------------------------------------------------
function asDate(value) {
  if (!value) {
    return null;
  }
  if (value instanceof Date) {
    return value;
  }
  const at = new Date(value);
  // An unparseable stamp is treated as no stamp. The alternative is an
  // Invalid Date, which formats as "Invalid Date" and compares false against
  // everything — a principal that is signed out and cannot be seen to be.
  return isNaN(at.getTime()) ? null : at;
}

function signedOutAt(nameComponents, realm) {
  log.debug("Entering signedOutAt().");
  const principal = find(nameComponents, realm);
  log.debug("Leaving signedOutAt().");
  return asDate(principal && principal.signedOutAt);
}

// Every principal currently carrying one, for the console and for /logout's
// inventory. Read off the database rather than kept in a second list beside it,
// which is the one-store rule this service applies everywhere else.
function signedOutPrincipals() {
  log.debug("Entering signedOutPrincipals().");
  // Built first, for `all()`'s reason: this reads the realm's partition.
  current();
  const out = [];
  principals.forEach(function (principal) {
    if (asDate(principal.signedOutAt)) {
      out.push({ name: principal.name.slice(0), realm: principal.realm,
                 principal: principal.name.join('/') + '@' + principal.realm,
                 signedOutAt: asDate(principal.signedOutAt) });
    }
  });
  log.debug("Leaving signedOutPrincipals(). " + out.length + " principal(s).");
  return out;
}

// `realm` defaults to this KDC's own, so every existing single-realm caller
// keeps working unchanged. A caller that means "in the realm this ticket came
// from" has to say so — and in handleTgsReq that is the difference between
// opening a cross-realm ticket-granting ticket and failing to.
// ---------------------------------------------------------------------------
// THE DERIVED LONG-TERM KEYS ARE A CACHE, AND THEY MUST NOT BE PERSISTED
// (2026-09-08).
//
// `longTermKey()` derives one key per etype from `password` + `salt` and keeps
// it in a `Map` on the principal. That was harmless while a principal only ever
// lived in this process's memory. `principals` is a PERSISTED, REPLICATED store
// though — and since `signOut()` began writing the principal back, every
// principal round-trips through JSON, where a `Map` becomes `{}` and a `Buffer`
// becomes `{"type":"Buffer","data":[…]}`. The next `longTermKey()` then called
// `.has` on a plain object: `principal.keys.has is not a function`, which took
// out the whole AS exchange with `KRB_ERR_GENERIC could not decode the
// request` — a message that points at the client's bytes and had nothing to do
// with them.
//
// So the cache is attached NON-ENUMERABLY. `JSON.stringify` skips it, which
// fixes both halves at once: nothing derived is written down (the stored form
// carries the password and the salt, so a cache adds exposure without adding
// anything), and no reader can be handed a broken one. A principal that arrives
// from the store or from another process simply has no cache, and gets an empty
// one here — the keys are re-derived on demand, which is what a cache means.
// ---------------------------------------------------------------------------
function withKeyCache(principal) {
  log.debug("Entering withKeyCache().");
  if (!principal) {
    log.debug("Leaving withKeyCache().");
    return principal;
  }
  if (!(principal.keys instanceof Map)) {
    Object.defineProperty(principal, 'keys', {
      value: new Map(), enumerable: false, writable: true, configurable: true
    });
  }
  log.debug("Leaving withKeyCache().");
  return principal;
}

// ---------------------------------------------------------------------------
// KEY SOURCE (2026-09-12): WHERE A LONG-TERM KEY COMES FROM WHEN IT IS NOT A
// PASSWORD IN THIS FILE.
//
// Two kinds of principal keep their keys somewhere other than this database:
//
//   * A PERSON, in product mode. Their password is a scrypt hash on their
//     directory entry, and a Kerberos key cannot be derived from a hash — so
//     `krb5_person_keys.js` derives the keys when a plaintext password is in
//     hand (set, or verified at a sign-in) and stores them, sealed, on that
//     entry. This file asks for them by name.
//   * A SERVICE an operator created at `/admin/kerberos/principals`, with a
//     RANDOM key rather than a password, stored on its application entry
//     under `ou=applications`. Asked for by SPN, in EVERY mode, and preferred
//     over an account this file built from `krb5.servicePassword` — which is
//     what lets an operator give the acceptor's own SPN a real keytab.
//
// **AN INVERTED HOOK, AND RULE 3e's TEST ANSWERS YES THREE WAYS ROUND.** The
// source reads the directory, which is `ldap/ldap_server.js` at 21, and the
// credential store, which is `common/credentials.js`; this file is required by
// `krb5_kdc.js` at 15. A require from here to either would register every
// `/ldap` route ahead of the KDC's own (rule 1). And the source requires THIS
// file, so a require back closes a cycle. The third reason is not about route
// order at all and is the one worth keeping: **the parent project's in-process
// Kerberos jobs load this file, `krb5_kdc.js` and `krb5_service.js` and copy
// their require closure into an image** — a require from here to the source
// would drag `common/credentials.js`, `common/keystore.js` and the directory
// into that copy set for a feature those jobs never use. With the slot, the
// closure is exactly what it was.
//
// ONE OBJECT, VALIDATED WHOLE, for `admin.js`'s `setLogoutReader()` reason: a
// source that answered services and not people would give a product KDC a
// keytab path and leave every person refused with nothing saying why.
//
// **A PROCESS WITH NO SOURCE BEHAVES EXACTLY AS IT DID**, which is every
// in-process caller that never loads the directory: development mode keys users
// from `krb5.userPassword`, and product mode refuses a user with a sentence
// saying the source is missing rather than one about reserved names.
// ---------------------------------------------------------------------------
let keySource = null;

function setKeySource(source) {
  log.debug('Entering setKeySource().');
  const needed = ['personKeys', 'serviceKeys'];
  const missing = needed.filter(function (name) {
    return !source || typeof source[name] !== 'function';
  });
  if (missing.length) {
    log.error(errorCodes.tag('STS-KRB-0100') +
              'krb5: setKeySource() was given something without ' +
              missing.join(', ') + ', so it was refused whole. A product KDC ' +
              'will authenticate no person and no stored service key will be ' +
              'used.');
    log.debug('Leaving setKeySource(). Refused.');
    return false;
  }
  keySource = source;
  log.debug('Leaving setKeySource(). Installed.');
  return true;
}

// Whether a name, in a realm, is one the PERSON half of the source answers:
// product mode, one component, this KDC's own realm. The realm check is not
// caution — the source reads the AMBIENT trust realm's directory, whose people
// are this Kerberos realm's users; a name in the trusted realm is nobody there.
function personShaped(nameComponents, realm) {
  log.debug("Entering personShaped().");
  const ctx = current();
  log.debug("Leaving personShaped().");
  return ctx.active && !ctx.SEEDS_DEMO && Array.isArray(nameComponents) &&
         nameComponents.length === 1 && !!nameComponents[0] &&
         (realm || ctx.REALM) === ctx.REALM;
}

// The e-texts, one per state the source can report. No em dash and nothing
// non-ASCII, for handleAsReq()'s reason: a KerberosString is a GeneralString
// and a client decoding it as Latin-1 renders UTF-8 as mojibake in the one
// field whose whole job is to be read by a person.
const PERSON_REFUSALS = {
  'no-source': { errorCode: 'STS-KRB-0101',
    eText: 'this KDC has no directory to read Kerberos keys from, so no user ' +
           'principal can authenticate in product mode' },
  'off': { errorCode: 'STS-KRB-0102',
    eText: 'krb5.personKeys is off, so no directory person has Kerberos keys ' +
           'on this KDC' },
  'unknown': { errorCode: 'STS-KRB-0103',
    eText: 'no such principal: there is nobody by that name in the directory' },
  'none': { errorCode: 'STS-KRB-0104',
    eText: 'this principal has no Kerberos keys yet - sign in once with the ' +
           'password, or reset it' },
  'stale': { errorCode: 'STS-KRB-0104',
    eText: 'this principal\'s Kerberos keys were derived from a password it ' +
           'no longer has - sign in once with the current password, or reset ' +
           'it' },
  'unreadable': { errorCode: 'STS-KRB-0105',
    eText: 'this principal\'s stored Kerberos keys cannot be opened on this ' +
           'KDC - reset the password to derive new ones' }
};

// ---------------------------------------------------------------------------
// A PERSON AS A PRINCIPAL. `{ principal, refusal }`.
//
// **THE PRINCIPAL IS A RECORD IN THIS DATABASE AND THE KEYS ARE NOT.** It is
// registered here — a name, a salt, the etypes and kvno the stored keys carry,
// a RID and no password — so that everything else a principal is used for
// works unchanged: `signOut()` stamps it, `handleTgsReq()` finds it, and
// `/krb5/principals` lists it. The KEYS go into the non-enumerable cache and
// nowhere else, so they are never persisted with the record, never replicated
// and never published; they are fetched afresh from the source on every lookup,
// which is what makes a password change reach the very next AS-REQ.
// ---------------------------------------------------------------------------
function directoryUser(name) {
  log.debug('Entering directoryUser(). name=' + name);
  const REALM = current().REALM;
  if (!keySource) {
    log.info('krb5: product mode and no key source is installed, so ' + name +
             '@' + REALM + ' cannot authenticate.');
    log.debug('Leaving directoryUser(). No source.');
    return { principal: null, refusal: PERSON_REFUSALS['no-source'] };
  }
  let answer = null;
  try {
    answer = keySource.personKeys(name) || {};
  } catch (e) {
    // A source that threw is a source with nothing to offer. Refused, with the
    // unreadable sentence, rather than let through: the alternative for a
    // PRODUCT KDC is no key at all, and there is no permissive answer to that.
    log.error(errorCodes.tag('STS-KRB-0105') + 'krb5: reading the Kerberos ' +
              'keys for ' + name + ' threw: ' + e.message);
    answer = { state: 'unreadable' };
  }
  if (answer.state !== 'ok') {
    const refusal = PERSON_REFUSALS[answer.state] || PERSON_REFUSALS.unreadable;
    log.info('krb5: ' + name + '@' + REALM + ' was refused before ' +
             'pre-authentication (' + (answer.state || 'unknown state') +
             '): ' + refusal.eText +
             (answer.detail ? ' — ' + answer.detail : ''));
    log.debug('Leaving directoryUser(). ' + answer.state);
    return { principal: null, refusal: refusal };
  }
  const key = name + '@' + REALM;
  let record = principals.get(key);
  const wantedEtypes = answer.keys.map(function (pair) { return pair[0]; });
  if (!record || !record.directoryKeys) {
    const kept = record || null;
    record = register({
      name: [name],
      type: 1,
      realm: REALM,
      salt: answer.salt,
      etypes: wantedEtypes,
      directoryKeys: true,
      description: 'a person in the directory, keyed from their own password',
      pac: {
        rid: kept && kept.pac && kept.pac.rid ? kept.pac.rid :
             autoRidFor([name], REALM),
        groups: [RID.DOMAIN_USERS],
        userAccountControl: UAC.NORMAL_ACCOUNT,
        // S-1-18-1 says the identity came from a password logon, which is
        // exactly what the keys this principal holds were derived from.
        extraSids: ['S-1-18-1', 'S-1-5-11']
      }
    });
    if (kept && kept.signedOutAt) {
      record.signedOutAt = kept.signedOutAt;
    }
    record.kvno = answer.kvno;
    principals.set(key, record);
    log.info('krb5: ' + key + ' is keyed from the directory (kvno ' +
             answer.kvno + ', ' + wantedEtypes.length + ' etype(s)).');
  } else if (record.kvno !== answer.kvno || record.salt !== answer.salt ||
             record.etypes.join(',') !== wantedEtypes.join(',')) {
    // WRITTEN BACK THROUGH THE STORE when it moved, for signOut()'s reason:
    // a field mutated in place is invisible to persistence and to every other
    // process.
    record.kvno = answer.kvno;
    record.salt = answer.salt;
    record.etypes = wantedEtypes;
    principals.set(key, record);
  }
  withKeyCache(record);
  record.keys = new Map(answer.keys);
  attachRetained(record, answer);
  log.debug('Leaving directoryUser(). kvno ' + record.kvno + '.');
  return { principal: record, refusal: null };
}

// ---------------------------------------------------------------------------
// PREVIOUS KEY VERSIONS (2026-09-12). The key source hands over, beside the
// current keys, the previous versions `krb5_person_keys.js` still keeps after a
// password change or a rotation; they are attached NON-ENUMERABLY, for the key
// cache's reason, and in a property of their own — **never in `keys`**, which
// is the cache pre-authentication and every issuance read. So an old password
// can never sign in and nothing is ever ISSUED under an old kvno: the one
// reader is `retainedKeyFor()`, which a caller decrypting a ticket ALREADY
// sealed under that kvno asks by number.
// ---------------------------------------------------------------------------
function attachRetained(principal, answer) {
  log.debug("Entering attachRetained().");
  const versions = ((answer && answer.retained) || []).map(function (version) {
    return { kvno: Number(version.kvno), expiresAt: Number(version.expiresAt),
             keys: new Map(version.keys) };
  });
  Object.defineProperty(principal, 'retainedKeys', {
    value: versions, enumerable: false, writable: true, configurable: true
  });
  log.debug("Leaving attachRetained().");
}

// The key for `etype` at the PREVIOUS key version `kvno` of a stored-key
// principal, or null: `{ key, kvno, expiresAt }`. Read afresh from the source,
// for `longTermKey()`'s reason — a drop or an expiry must reach the very next
// ticket — and checked against the clock here as well as by the source, so a
// version that expires between the two reads is not used. A principal built
// from a password in the configuration has no previous versions: its key does
// not change when its number does.
function retainedKeyFor(principal, etype, kvno) {
  log.debug("Entering retainedKeyFor().");
  if (!principal || !principal.directoryKeys || kvno === null ||
      kvno === undefined) {
    log.debug("Leaving retainedKeyFor().");
    return null;
  }
  log.debug('Entering retainedKeyFor(). ' + keyOf(principal) + ' kvno=' + kvno);
  const fresh = principal.storedServiceKey
    ? storedService(principal.name, principal.realm)
    : (principal.type === 1 ?
       directoryUser(String(principal.name[0])).principal : null);
  const nowMs = Date.now();
  const version = ((fresh && fresh.retainedKeys) || []).filter(function (one) {
    return one.kvno === Number(kvno) && one.expiresAt > nowMs &&
           one.keys.has(etype);
  })[0];
  if (!version) {
    log.debug('Leaving retainedKeyFor(). Not kept.');
    return null;
  }
  log.debug('Leaving retainedKeyFor(). Kept until ' +
            new Date(version.expiresAt).toISOString() + '.');
  return { key: version.keys.get(etype), kvno: version.kvno,
           expiresAt: version.expiresAt };
}

// Which previous versions a stored-key principal still keeps, as numbers — for
// the sentence a refusal carries.
function retainedKvnosOf(principal) {
  log.debug("Entering retainedKvnosOf().");
  log.debug("Leaving retainedKvnosOf().");
  return ((principal && principal.retainedKeys) || []).filter(function (one) {
    return one.expiresAt > Date.now();
  }).map(function (one) { return one.kvno; });
}

// The whole lookup an AS exchange makes, with the REASON beside a refusal.
// `findOrCreateUser()` is this with the reason thrown away, for its four other
// callers.
function lookupUser(nameComponents, realm) {
  log.debug('Entering lookupUser().');
  if (personShaped(nameComponents, realm)) {
    const answer = directoryUser(String(nameComponents[0]));
    log.debug('Leaving lookupUser(). From the directory.');
    return answer;
  }
  const principal = findOrCreateUserInDatabase(nameComponents, realm);
  log.debug('Leaving lookupUser(). From the database.');
  return { principal: principal, refusal: null };
}

// ---------------------------------------------------------------------------
// A STORED SERVICE KEY, AS A PRINCIPAL. Null when there is none.
//
// **NOT REGISTERED**, where a directory person is: a service principal is never
// signed out and never auto-created, so there is nothing a record would carry
// that the application entry does not. It is built afresh per lookup over the
// configured account where one exists — so a stored key for the acceptor's own
// SPN keeps that account's `okAsDelegate`, delegation rules and PAC identity
// and replaces only its KEY — and over a plain service shape where none does.
//
// `krbtgt/*` is never asked: the ticket-granting key is the one key an operator
// may not replace from a console, because every TGT in the realm is sealed
// under it.
// ---------------------------------------------------------------------------
function storedService(nameComponents, realm) {
  log.debug("Entering storedService().");
  const ctx = current();
  const REALM = ctx.REALM;
  if (!keySource || !ctx.active || !Array.isArray(nameComponents) ||
      nameComponents.length < 2 ||
      String(nameComponents[0]).toLowerCase() === 'krbtgt' ||
      (realm || REALM) !== REALM) {
    log.debug("Leaving storedService().");
    return null;
  }
  log.debug('Entering storedService(). spn=' + nameComponents.join('/'));
  let answer = null;
  try {
    answer = keySource.serviceKeys(nameComponents.join('/'));
  } catch (e) {
    // Reported and treated as no stored key: the configured account, if any,
    // still answers — which is what the service did before a key was stored.
    log.error(errorCodes.tag('STS-KRB-0106') + 'krb5: reading the stored key ' +
              'for ' + nameComponents.join('/') + ' threw: ' + e.message);
    log.debug('Leaving storedService(). The source threw.');
    return null;
  }
  if (!answer || !answer.keys || !answer.keys.length) {
    log.debug('Leaving storedService(). None stored.');
    return null;
  }
  const base = principals.get(nameComponents.join('/') + '@' + REALM);
  const principal = Object.assign({
    name: nameComponents.map(String),
    type: 3,
    realm: REALM,
    requiresPreAuth: true,
    revoked: false,
    passwordExpired: false,
    okAsDelegate: false,
    trustedToAuthenticateForDelegation: false,
    notDelegated: false,
    allowedToDelegateTo: [],
    allowedToActOnBehalfOf: [],
    description: 'a service principal with a stored random key',
    autoCreated: false,
    pac: { rid: 1100, primaryGroupRid: RID.DOMAIN_COMPUTERS,
           groups: [RID.DOMAIN_COMPUTERS],
           userAccountControl: UAC.WORKSTATION_TRUST_ACCOUNT, extraSids: [],
           fullName: null, passwordMustChange: null },
    signedOutAt: null
  }, base || {});
  principal.password = null;
  principal.directoryKeys = true;
  principal.storedServiceKey = true;
  principal.salt = principal.salt ||
    userSalt(REALM, nameComponents.join(''));
  principal.kvno = answer.kvno;
  principal.etypes = answer.keys.map(function (pair) { return pair[0]; });
  Object.defineProperty(principal, 'keys', {
    value: new Map(answer.keys), enumerable: false, writable: true,
    configurable: true
  });
  attachRetained(principal, answer);
  log.debug('Leaving storedService(). kvno ' + principal.kvno + '.');
  return principal;
}

function find(nameComponents, realm) {
  log.debug("Entering find().");
  const ctx = current();
  // A trust realm whose Kerberos is off holds no principal (2026-09-15).
  if (!nameComponents || !nameComponents.length || !ctx.active) {
    log.debug("Leaving find().");
    return null;
  }
  // A STORED SERVICE KEY WINS over the database, and is asked first. See
  // storedService().
  const stored = storedService(nameComponents, realm);
  if (stored) {
    log.debug("Leaving find().");
    return stored;
  }
  // EVERY READER COMES THROUGH HERE, which is why the cache is repaired here
  // rather than at each of the two places that use it.
  const held = withKeyCache(
    principals.get(nameComponents.join('/') + '@' +
                   (realm || ctx.REALM))) || null;
  // A DIRECTORY PERSON IS READ AGAIN FROM THE SOURCE (2026-09-12). Their
  // record's key cache holds whatever the LAST AS lookup found, so a TGS naming
  // them — as the service a ticket is for, or the ticket being presented —
  // would otherwise issue or decrypt under the kvno before a password change.
  // Refused by the source (no keys, stale, unreadable), the record is still
  // returned, for sign-out and the PAC, with an EMPTY cache: every key use then
  // asks the source again and is refused.
  if (held && held.directoryKeys && !held.storedServiceKey &&
      personShaped(nameComponents, realm)) {
    const fresh = directoryUser(String(nameComponents[0])).principal;
    if (fresh) {
      log.debug("Leaving find().");
      return fresh;
    }
    held.keys = new Map();
    attachRetained(held, null);
  }
  log.debug("Leaving find().");
  return held;
}

// ---------------------------------------------------------------------------
// The account for whoever asks: find(), and create the user if there is nothing
// there.
//
// This is what makes "any username authenticates" true, and it is deliberately
// NOT what find() does, because the difference between the two is the
// difference between a user and a service:
//
//  * A CLIENT principal is created. That is the AS exchange's cname, and the
//    user S4U2Self names — the two places where a person or a front-end says
//    who somebody is.
//  * A SERVICE principal is not, and must not be. KDC_ERR_S_PRINCIPAL_UNKNOWN
//    for a service nobody registered is the most common Kerberos failure there
//    is (a missing or misspelled SPN), and a KDC that invented the service
//    instead would hand back a ticket sealed with a key the service does not
//    hold — a failure that then surfaces at the AP exchange as "decrypt
//    integrity check failed", which is the same message a genuinely wrong key
//    gives and points nowhere near the missing SPN.
//
// The shape of the name is what tells them apart, which is exactly how Kerberos
// itself distinguishes them: one component is a user, two or more is
// service/host. So only a single-component name is created here.
//
// Names are compared exactly, so `Alice` and `alice` are two accounts with two
// salts. That is MIT's behaviour rather than AD's (AD folds case on the
// sAMAccountName), and it is left alone because a case-sensitive mock cannot
// teach a client the habit of assuming case folding that MIT realms will then
// not honour.
//
// The map grows by one entry per distinct username seen, and nothing evicts.
// Bounded in practice by a process that is restarted for every test run, and
// each entry is a name, a salt and lazily-derived keys.
// ---------------------------------------------------------------------------
function findOrCreateUser(nameComponents, realm) {
  log.debug("Entering findOrCreateUser().");
  log.debug("Leaving findOrCreateUser().");
  // PRODUCT MODE RESOLVES A PERSON FROM THE DIRECTORY (2026-09-12). See
  // lookupUser(), which is this plus the reason for a refusal.
  return lookupUser(nameComponents, realm).principal;
}

function findOrCreateUserInDatabase(nameComponents, realm) {
  log.debug('Entering findOrCreateUser().');
  const inRealm = realm || current().REALM;
  const existing = find(nameComponents, inRealm);
  if (existing) {
    log.debug('Leaving findOrCreateUser(). ' + keyOf(existing) + ' was ' +
        'already known.');
    return existing;
  }
  if (realmsServed().indexOf(inRealm) === -1) {
    // Not our realm, so not our account to invent. handleAsReq refuses a
    // foreign realm before it gets here; this is for any caller that does not.
    log.debug('Leaving findOrCreateUser(). ' + inRealm + ' is not a realm ' +
        'this KDC serves.');
    return null;
  }
  // PRODUCT MODE CREATES NOBODY (2026-09-06). An AS-REQ naming a principal
  // this KDC has never heard of is answered KDC_ERR_C_PRINCIPAL_UNKNOWN, which
  // is what a real KDC does and what makes the principal database a statement
  // about the deployment rather than a log of every name anybody has tried.
  //
  // It is checked HERE and not at the caller for the reason every predicate in
  // common/mode.js is centralised: this function has four callers and a
  // check at each is three chances to forget.
  if (!mode.autoCreates()) {
    log.info('krb5: product mode, so ' + (nameComponents || []).join('/') +
             '@' + inRealm + ' was NOT created on demand. Principals must be ' +
             'provisioned ahead of time.');
    log.debug('Leaving findOrCreateUser(). Product mode creates nobody.');
    return null;
  }
  if (!nameComponents || nameComponents.length !== 1 || !nameComponents[0]) {
    log.debug('Leaving findOrCreateUser(). ' +
      (nameComponents || []).join('/') +
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
    description: 'created on first sight — every username authenticates ' +
                 'here, with the one password every user shares',
    pac: {
      rid: autoRidFor([name], inRealm),
      groups: [RID.DOMAIN_USERS],
      userAccountControl: UAC.NORMAL_ACCOUNT,
      // The same two well-known SIDs the configured users carry: S-1-18-1 says
      // the identity came from a password logon rather than being asserted, and
      // S-1-5-11 is Authenticated Users. An account created here went through
      // the same AS exchange as alice, so it would be wrong for its PAC to say
      // otherwise.
      extraSids: ['S-1-18-1', 'S-1-5-11']
    }
  });
  log.info('krb5: created ' + keyOf(created) + ' on demand — RID ' +
    created.pac.rid +
    ', salt ' + JSON.stringify(created.salt) + ', the shared user password');
  log.debug('Leaving findOrCreateUser(). created.');
  return created;
}

// ---------------------------------------------------------------------------
// The service account for a host this mock is willing to be, created on first
// sight. See SERVICE_DOMAINS above for why this exists and what it must not do.
//
// Called only AFTER the referral path has had its say, so a name in the trusted
// realm's domain has already been answered with a ticket-granting ticket for
// that realm rather than created here. Returns null for everything it declines,
// and every caller treats null as KDC_ERR_S_PRINCIPAL_UNKNOWN exactly as
// before.
// ---------------------------------------------------------------------------
function findOrCreateService(nameComponents, realm) {
  log.debug('Entering findOrCreateService().');
  const ctx = current();
  const inRealm = realm || ctx.REALM;
  const existing = find(nameComponents, inRealm);
  if (existing) {
    log.debug('Leaving findOrCreateService(). ' + keyOf(existing) + ' was ' +
        'known.');
    return existing;
  }
  if (realmsServed().indexOf(inRealm) === -1) {
    log.debug('Leaving findOrCreateService(). ' + inRealm + ' is not served ' +
        'here.');
    return null;
  }
  // PRODUCT MODE CREATES NOTHING (2026-09-06) — see findOrCreateUser(). A
  // service principal invented on demand is how a TGS-REQ for any name at all
  // gets a ticket, which is exactly the mock behaviour product mode removes.
  if (!mode.autoCreates()) {
    log.info('krb5: product mode, so the service principal ' +
             (nameComponents || []).join('/') + '@' + inRealm + ' was NOT ' +
             'created on demand.');
    log.debug('Leaving findOrCreateService(). Product mode creates nothing.');
    return null;
  }
  if (!nameComponents || nameComponents.length < 2 ||
      !nameComponents.every(function (part) {
        return part && String(part).length;
      })) {
    // One component is a user (findOrCreateUser's job), and an empty component
    // is not a name at all.
    log.debug('Leaving findOrCreateService(). Not service-shaped.');
    return null;
  }
  const host = String(nameComponents[nameComponents.length - 1]).toLowerCase();
  const matched = ctx.SERVICE_DOMAINS.filter(function (entry) {
    return host === entry || host.endsWith('.' + entry);
  })[0];
  if (!matched) {
    log.info('krb5: ' + nameComponents.join('/') + ' names a host this ' +
      'service is not willing to be (' + host + ' matches none of ' +
      (ctx.SERVICE_DOMAINS.join(', ') || '(nothing configured)') + '), so ' +
      'it ' +
      'stays KDC_ERR_S_PRINCIPAL_UNKNOWN');
    log.debug('Leaving findOrCreateService(). Host not covered.');
    return null;
  }
  // The salt is AD's for a service account: realm + sAMAccountName, and the
  // sAMAccountName of a service is not its SPN. Real deployments make it the
  // account's own name, which nothing in the SPN reveals — so this is a
  // convention of the mock's, published like every other salt in GET
  // /krb5/principals and in ETYPE-INFO2, and NOT something a client should ever
  // try to derive. Same shape as the configured HTTP/web.example.com entry,
  // which salts as REALM + "HTTPweb".
  const short = String(nameComponents[nameComponents.length - 1]).split('.')[0];
  const created = register({
    name: nameComponents.map(String),
    type: 3,                                   // NT-SRV-HST
    realm: inRealm,
    password: ctx.AUTO_SERVICE_PASSWORD,
    salt: userSalt(inRealm, nameComponents.slice(0, -1).join('') + short),
    autoCreated: true,
    description: 'created on first sight because ' + host + ' matches ' +
                 matched +
                 ' — the shared auto-service password, published by this ' +
                 'endpoint',
    pac: {
      rid: autoRidFor(nameComponents.map(String), inRealm),
      groups: [RID.DOMAIN_COMPUTERS],
      userAccountControl: UAC.WORKSTATION_TRUST_ACCOUNT
    }
  });
  log.info('krb5: created the service ' + keyOf(created) +
    ' on demand — salt ' +
    JSON.stringify(created.salt) + ', the shared auto-service password. This ' +
    'process is also the acceptor, so the ticket it seals is one it can open.');
  log.debug('Leaving findOrCreateService(). created.');
  return created;
}

// The long-term key for one etype. Derived on demand and cached.
//
// **A DIRECTORY-KEYED PRINCIPAL IS NEVER DERIVED**, whatever its record says:
// its keys come from the key source and a miss is asked of the source again
// and then REFUSED. Deriving would mean a password, and the only password this
// file could reach for is the shared development one — see register().
async function longTermKey(principal, etype) {
  log.debug("Entering longTermKey().");
  withKeyCache(principal);
  if (principal.keys.has(etype)) {
    log.debug("Leaving longTermKey().");
    return principal.keys.get(etype);
  }
  if (principal.directoryKeys) {
    const again = principal.storedServiceKey
      ? storedService(principal.name, principal.realm)
      : (principal.type === 1 ?
         directoryUser(String(principal.name[0])).principal : null);
    if (again && again.keys && again.keys.has(etype)) {
      log.debug("Leaving longTermKey().");
      return again.keys.get(etype);
    }
    throw new Error('krb5: ' + keyOf(principal) + ' holds no stored key for ' +
                    kcrypto.etypeName(etype) + ', and a directory-keyed ' +
                    'principal is never derived from a password here');
  }
  const profile = kcrypto.etypeById(etype);
  const key = await profile.stringToKey(principal.password,
                                        prim.utf8(principal.salt), null);
  principal.keys.set(etype, key);
  log.debug('krb5: derived the ' + profile.name + ' key for ' +
            keyOf(principal) +
            ' with salt ' + JSON.stringify(principal.salt));
  log.debug("Leaving longTermKey().");
  return key;
}

// What this principal can offer, in the KDC's preference order rather than the
// order the definition happened to list.
function supportedEtypes(principal) {
  log.debug("Entering supportedEtypes().");
  log.debug("Leaving supportedEtypes().");
  return current().KDC_ETYPES.filter(function (id) {
    return principal.etypes.indexOf(id) !== -1;
  });
}

// Negotiate: the FIRST etype the client asked for that this principal supports.
// The client's order is its preference and a KDC honours it — which is why the
// debugger's etype list is ordered and why that order is worth displaying.
function chooseEtype(principal, requested) {
  log.debug("Entering chooseEtype().");
  const supported = supportedEtypes(principal);
  for (const id of requested || []) {
    if (supported.indexOf(id) !== -1) {
      log.debug("Leaving chooseEtype().");
      return id;
    }
  }
  log.debug("Leaving chooseEtype().");
  return null;
}

// The ETYPE-INFO2 entries for a principal: one per supported etype, each with
// the salt the client must use. arcfour carries NO salt, and that absence is
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
  log.debug("Entering s2kparamsMode().");
  log.debug("Leaving s2kparamsMode().");
  return String(config.value('krb5.s2kparams')).toLowerCase() === 'send'
    ? 'send' : 'omit';
}

function etypeInfo2For(principal) {
  log.debug("Entering etypeInfo2For().");
  log.debug("Leaving etypeInfo2For().");
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
    log.debug("Entering knows().");
    log.debug("Leaving knows().");
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
          'delegation requires forwardable evidence. S4U2Self will succeed ' +
          'and S4U2Proxy will then fail complaining about the evidence ' +
          'ticket, which is two steps from the attribute that caused it. ' +
          'Resource-based delegation would not have needed either flag.');
      }
      if (!targetPrincipal) {
        warnings.push('This KDC has no principal called ' + target + ' in ' +
          principal.realm + '. The attribute names a SERVICE and the SPN has ' +
          'to match exactly; a ticket request for a name this KDC does not ' +
          'know is refused before the authorization is ever consulted.');
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
        requires: 'a FORWARDABLE evidence ticket, which S4U2Self only ' +
                  'returns to an account flagged ' +
                  'TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION',
        targetKnown: !!targetPrincipal,
        warning: warnings.join(' '),
        note: principal.description || ''
      });
    });

    // RESOURCE-BASED — the permission is on THIS account and names who may act
    // on its behalf, so the pair is built the other way round.
    (principal.allowedToActOnBehalfOf || []).forEach(function (requester) {
      const requesterPrincipal = find(String(requester).split('/'),
                                      principal.realm);
      const warnings = [];
      if (!requesterPrincipal) {
        warnings.push('This KDC has no principal called ' + requester + ' in ' +
          principal.realm + '. Whoever the attribute meant to authorize ' +
          'cannot present a ticket here under that name.');
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
                  'forwardable evidence and no flag on the front end, which ' +
                  'is why it is the easier path',
        targetKnown: knows(name, principal.realm),
        warning: warnings.join(' '),
        note: principal.description || ''
      });
    });

    // The account-level flags. Reported whether or not a pair names the
    // account, because two of the three are what STOP delegation rather than
    // permit it, and an account that appears in no pair is precisely the one
    // somebody is wondering about.
    if (principal.notDelegated ||
        principal.trustedToAuthenticateForDelegation ||
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
              'refuses this account a forwardable ticket at all, so no ' +
              'service anywhere can forward its TGT. It is the one control ' +
              'that lives on the account being PROTECTED rather than on any ' +
              'service, which is what makes it work no matter which service ' +
              'the user visits.'
            : '',
          principal.trustedToAuthenticateForDelegation
            ? 'TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION — protocol transition. ' +
              'This account gets a FORWARDABLE ticket out of S4U2Self, which ' +
              'is what classic constrained delegation then needs as ' +
              'evidence. Without it S4U2Self still works and simply returns ' +
              'a ticket that is not forwardable.'
            : '',
          principal.okAsDelegate
            ? 'ok-as-delegate — ADVICE TO THE CLIENT and not a control. The ' +
              'flag on a service ticket tells the client this service may be ' +
              'trusted with forwarded credentials; a client is free to ' +
              'ignore it, and this KDC enforces nothing by it.'
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
    return a.target.localeCompare(b.target) ||
           a.frontEnd.localeCompare(b.frontEnd);
  });
  accounts.sort(function (a, b) {
    return a.principal.localeCompare(b.principal);
  });

  log.debug('Leaving delegationPolicy(). ' + pairs.length + ' pair(s), ' +
            accounts.length + ' account(s).');
  return { pairs: pairs, accounts: accounts };
}

module.exports = {
  parseEtypes: parseEtypes,
  // The acceptor's account in the AMBIENT realm: its SPN, whether it exists,
  // and if not, why. A copy, so a caller cannot change what the next caller is
  // told.
  serviceAccount: function () {
    log.debug("Entering serviceAccount().");
    const ctx = current();
    // `storedKey` since 2026-09-12: whether an operator stored a RANDOM key
    // for this SPN at /admin/kerberos/principals, which the acceptor prefers
    // over the password-derived account. An account refused for its published
    // password is then keyed anyway, which is the way out that refusal names.
    const stored = !!ctx.serviceAccount.spn &&
      !!storedService(ctx.serviceAccount.spn.split('/'), ctx.REALM);
    log.debug("Leaving serviceAccount().");
    return { spn: ctx.serviceAccount.spn,
             available: ctx.serviceAccount.available || stored,
             storedKey: stored,
             reason: stored ? '' : ctx.serviceAccount.reason };
  },
  // The SPN the acceptor holds in the AMBIENT realm, as components — what
  // `krb5_service.js` read once from `krb5.servicePrincipal` until that became
  // a setting a trust realm carries (2026-09-15).
  servicePrincipal: function () {
    log.debug("Entering servicePrincipal().");
    const ctx = current();
    log.debug("Leaving servicePrincipal().");
    return String(ctx.serviceAccount.spn ||
                  config.value('krb5.servicePrincipal') || '').split('/');
  },
  // PER TRUST REALM (2026-09-15) — see ONE PRINCIPAL DATABASE PER TRUST REALM
  // at the top of this file. `trustRealmFor()` is the KDC's router,
  // `servedIn()` what a realm's own /KdcProxy and acceptor check a name
  // against, and `kerberosRealmOf()` what a page says about the realm it is
  // read in.
  enabledIn: enabledIn,
  nameOf: nameOf,
  trustRealmFor: trustRealmFor,
  servedIn: servedIn,
  kerberosRealmOf: function (realmId) {
    log.debug("Entering kerberosRealmOf().");
    const ctx = contextOf(realmId === undefined ? realms.currentId() :
                                                  realmId);
    log.debug("Leaving kerberosRealmOf().");
    return { trustRealm: ctx.id, kerberosRealm: ctx.REALM || null,
             enabled: enabledIn(ctx.id), active: ctx.active,
             reason: ctx.active ? '' : ctx.inactiveReason,
             served: servedBy(ctx) };
  },
  // The key source (see KEY SOURCE). `lookupUser()` is the AS exchange's
  // lookup, with the reason for a refusal beside a null principal.
  setKeySource: setKeySource,
  keySourceInstalled: function () {
    log.debug("Entering keySourceInstalled().");
    log.debug("Leaving keySourceInstalled().");
    return !!keySource;
  },
  lookupUser: lookupUser,
  // Previous key versions (see PREVIOUS KEY VERSIONS).
  retainedKeyFor: retainedKeyFor,
  retainedKvnosOf: retainedKvnosOf,
  // Empty unless product mode refused to create krbtgt/<realm>.
  krbtgtUnavailableReason: function () {
    log.debug("Entering krbtgtUnavailableReason().");
    log.debug("Leaving krbtgtUnavailableReason().");
    return current().krbtgtReason;
  },
  publishedDefault: publishedDefault,
  find: find,
  delegationPolicy: delegationPolicy,
  findOrCreateUser: findOrCreateUser,
  findOrCreateService: findOrCreateService,
  reservedUnknown: reservedUnknown,
  all: function () {
    log.debug("Entering all().");
    // `current()` FIRST, so the realm's database is built before its partition
    // is read (2026-09-15). A realm's context is built on first use, and this
    // reader would otherwise answer with the empty partition of a realm nothing
    // had asked about yet — which is what `GET /realm/<id>/krb5/principals`
    // did on a freshly enabled realm: an empty table beside a `realm` field
    // naming a KDC that was about to work.
    current();
    log.debug("Leaving all().");
    return Array.from(principals.values());
  },
  // The RID an account made at runtime under this name would be given, and
  // the range it is drawn from — see autoRidFor(). Exported so a test can ask
  // two processes the same question without creating anything.
  autoRidFor: autoRidFor,
  AUTO_RID_BASE: AUTO_RID_BASE,
  AUTO_RID_LIMIT: AUTO_RID_LIMIT,
  // Whether a principal was built from this process's settings and code, which
  // decides what a restored row may change on it — see reconcileRestored().
  isConfigured: function (nameComponents, realm) {
    log.debug("Entering isConfigured().");
    log.debug("Leaving isConfigured().");
    const ctx = current();
    return ctx.configuredKeys.has((nameComponents || []).join(
        '/') + '@' + (realm || ctx.REALM));
  },
  RUNTIME_FIELDS: RUNTIME_FIELDS.slice(),
  longTermKey: longTermKey,
  supportedEtypes: supportedEtypes,
  chooseEtype: chooseEtype,
  etypeInfo2For: etypeInfo2For,
  s2kparamsMode: s2kparamsMode,
  userSalt: userSalt,
  hostSalt: hostSalt,
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

// ---------------------------------------------------------------------------
// THE NAMES THAT WERE CONSTANTS, AS GETTERS FOR THE AMBIENT REALM (2026-09-15).
//
// Every one of these was a value read at require time and exported as such,
// and callers in six directories read them as properties. They keep the
// property shape — `principals.REALM` — and answer for the realm the caller is
// in, which outside any realm is the default one and therefore exactly what
// the constant was. Enumerable, so a caller that spreads or lists the module
// still sees them.
// ---------------------------------------------------------------------------
[
  ['REALM', 'REALM'], ['DOMAIN', 'DOMAIN'], ['KDC_ETYPES', 'KDC_ETYPES'],
  ['KVNO', 'KVNO'], ['USER_PASSWORD', 'USER_PASSWORD'],
  ['AUTO_SERVICE_PASSWORD', 'AUTO_SERVICE_PASSWORD'],
  ['SERVICE_DOMAINS', 'SERVICE_DOMAINS'], ['DOMAIN_SID', 'DOMAIN_SID'],
  // Whether the fixture accounts are in this realm's database — captured when
  // it was built, see SEEDS_DEMO.
  ['seedsDemoPrincipals', 'SEEDS_DEMO']
].forEach(function (pair) {
  Object.defineProperty(module.exports, pair[0], {
    enumerable: true,
    get: function () { return current()[pair[1]]; }
  });
});

