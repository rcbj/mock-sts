'use strict';
//
// File: krb5_person_keys.js
//
// ===========================================================================
// STORED KERBEROS LONG-TERM KEYS: A DIRECTORY PERSON'S, AND A SERVICE
// PRINCIPAL'S (2026-09-12).
//
// A PRODUCT-MODE KDC AUTHENTICATED NOBODY UNTIL THIS FILE, and the reason was
// structural rather than an omission. Development keys every user from ONE
// shared password (`krb5.userPassword`) and creates accounts on demand; product
// mode turns both off, and what it has instead is a person's REAL password —
// stored as a scrypt hash on their directory entry by `common/credentials.js`.
// A Kerberos key is RFC 3961's string-to-key over the PLAINTEXT and a salt, and
// no key can be derived from a hash. So there were no keys, and there was no
// account a person could use.
//
// THE DESIGN IS ONE SENTENCE: **DERIVE THE KEYS AT THE MOMENTS A PLAINTEXT
// PASSWORD IS IN HAND, AND STORE THEM ON THE PERSON'S OWN ENTRY.** There are
// exactly two such moments and `credentials.js` reports both through its
// password observer (rule 3e, argued there):
//
//   * the password is SET — the console, `/admin-api`, the portal's form, an
//     activation link, the product-mode bootstrap. The keys REPLACE any held
//     and the kvno moves up by one, so an AS-REQ with the old password fails
//     pre-authentication.
//   * the password is VERIFIED — the sign-in screen, an LDAP bind, SCIM Basic,
//     a WS-Trust UsernameToken, SSF Basic, the password grant. This is the
//     UPGRADE PATH for everybody who had a password before this file existed:
//     their first sign-in anywhere derives their keys. It derives only when the
//     keys are missing, cover fewer enctypes than `krb5.enctypes`, or were made
//     from a password the entry no longer holds.
//
// ---------------------------------------------------------------------------
// THE WINDOW, SAID RATHER THAN DISCOVERED.
//
// `setPassword()` and `verify()` are synchronous and RFC 3961 string-to-key is
// not — it is PBKDF2 through Web Crypto, 4096 iterations for the SHA-1 AES
// profiles and 32768 for RFC 8009's — so the derivation is kicked off AFTER the
// act and runs on its own. **A PASSWORD SET NOW HAS NO KEYS FOR A FEW TENS OF
// MILLISECONDS**, and in that window the KDC refuses the person with "sign in
// once" rather than accepting anything. The window can never be the dangerous
// way round: the keys carry a STAMP of the password hash they were derived
// beside, and the KDC refuses keys whose stamp is not the entry's current hash
// — so a key made from an OLD password is never used after the password
// changes, however the change arrived. An LDAP modify of `userPassword`
// included, which never passes through the observer at all and is caught by the
// stamp at the next AS-REQ and repaired at the next sign-in.
//
// A derivation that FAILS is logged and audited (`STS-KRB-0107`) and changes
// nothing about the act it observed: a sign-in is never delayed and never
// refused because a key could not be made.
//
// The plaintext is held by the closure of that one derivation and nowhere
// else, and is dropped when it settles. A JavaScript string cannot be wiped —
// `common/keystore.js` says the same thing about a decrypted signing key — so
// the claim is about the window, not about memory.
//
// ---------------------------------------------------------------------------
// WHERE THE KEYS LIVE, AND WHY TWO ATTRIBUTES RATHER THAN ONE PER ENCTYPE.
//
// On a person: `stsKrb5Keys` and `stsKrb5KeyInfo`. On a service principal's
// application entry under `ou=applications`: `krb5ServiceKeys` and
// `krb5ServiceKeyInfo`. The first of each pair is ONE value — a JSON document
// carrying the NAME, the REALM, the KVNO, the password STAMP and every
// enctype's key — SEALED as a whole under the key-encryption key wherever that
// key outlives the process (`keystore.persists()`, which is
// `writeTotpRecord()`'s rule and for its reason: development's key is
// ephemeral, and a directory attribute sealed under it is permanent garbage
// after a restart).
//
// **ONE SEALED VALUE IS THE SECURITY OF THE STORAGE.** The authentication tag
// covers the name and the stamp beside the keys, so a sealed value copied onto
// somebody else's entry names the wrong person, and one copied back after a
// password change carries the wrong stamp — both are refused by the reader.
// One value per enctype could have been spliced. In product mode a CLEAR value
// is refused outright, so an `ldapmodify` cannot plant a key it chose.
//
// The second of each pair is PUBLIC — the kvno, the enctypes, when, and how —
// so every page listing principals can say what is held without opening a key.
//
// ---------------------------------------------------------------------------
// WHICH TRUST REALM: THE AMBIENT ONE, SINCE 2026-09-15.
//
// This read *the KDC answers in no trust realm, so this file reads and writes
// the DEFAULT trust realm's directory* — pinned there by `ldap_server.js`'s
// slot — and *a password set or verified inside another trust realm derives
// NOTHING*. Both halves are gone: a trust realm whose Kerberos is on has a
// Kerberos realm and a principal database of its own, so a person in THAT
// realm's directory is a principal of THAT realm's KDC, and their keys belong
// on their own entry in their own realm.
//
// So every function here works in the AMBIENT realm — the realm a password was
// set in, or the realm the KDC entered for the request it is answering — and
// `principals.REALM` answers for that realm. What decides whether keys are
// derived at all is no longer "is this the default realm" but
// `principals.enabledIn()`: a realm with no KDC has nothing to hold keys for,
// which is the same sentence the old rule made about every realm but one.
//
// ---------------------------------------------------------------------------
// SERVICE PRINCIPALS, AND THE ONE TIME A KEY LEAVES THIS SERVICE.
//
// A service does not type a password. An operator creates one at
// `/admin/kerberos/principals` (or `POST /admin-api/kerberos/principals/
// create-service`), this file makes a RANDOM key per enctype, stores it sealed
// on the application entry for `<spn>@<realm>`, and hands back an MIT keytab
// (`krb5_keytab.js`) — ONCE, as the answer to that request. Nothing reads a
// key back out afterwards; a service that has lost its keytab is ROTATED, which
// adds one to the kvno and hands over a new keytab carrying the previous kvno
// too, and tickets issued under the old key go on being accepted until they
// could have expired (PREVIOUS KEY VERSIONS, below) and are then refused
// KRB_AP_ERR_BADKEYVER. The KDC and
// this service's own acceptor prefer a stored key over one built from
// `krb5.servicePassword`, so the acceptor's SPN can be given a real keytab too.
//
// ---------------------------------------------------------------------------
// WHAT IT REQUIRES, AND WHAT IT MUST NOT BE REQUIRED BY.
//
// A LIBRARY (rule 3): it registers no route. It requires the principal
// database, the codec, the keytab writer and six `common/` leaves — none of
// which requires it back. Two slots point INTO it and two OUT of it:
//
//   * `credentials.setPasswordObserver()` and `principals.setKeySource()` are
//     filled HERE, at require time. See each for its rule-3e argument.
//   * `setDirectory()` is filled by `ldap/ldap_server.js`, for the reason every
//     directory slot in this service is.
//
// **IT IS REACHABLE FROM NONE OF `krb5_kdc.js`, `krb5_service.js` AND
// `spnego.js`**, which is what leaves the parent project's `tests/Dockerfile`
// COPY set exactly as it was: the principal database reaches it only through a
// slot, and the modules that require it are `ldap/ldap_server.js` and the two
// `admin-core/` halves.
// ===========================================================================

const nodeCrypto = require('crypto');
const { log } = require('../common/helpers');
const config = require('../common/config');
const realms = require('../common/realms');
const keystore = require('../common/keystore');
const credentials = require('../common/credentials');
const applications = require('../common/applications');
const audit = require('../common/audit');
const errorCodes = require('../common/error_codes');
const kcrypto = require('./krb5_crypto.js');
const prim = require('./krb5_primitives.js');
const principals = require('./krb5_principals.js');
const keytab = require('./krb5_keytab.js');

// What `keystore.seal()` counts these under, for `/admin/encryption`.
const SEAL_LABEL = 'kerberos-keys';

const PERSON_KEYS_ATTRIBUTE = 'stsKrb5Keys';
const PERSON_INFO_ATTRIBUTE = 'stsKrb5KeyInfo';
const SERVICE_KEYS_ATTRIBUTE = 'krb5ServiceKeys';
const SERVICE_INFO_ATTRIBUTE = 'krb5ServiceKeyInfo';

// The two that are never drawn anywhere, ciphertext included. `ldap_server.js`
// withholds them from the directory dump and from an LDAP search, and
// `applications.js` from every application view.
const WITHHELD_ATTRIBUTES = [PERSON_KEYS_ATTRIBUTE, SERVICE_KEYS_ATTRIBUTE];

// The record format, so that a value written by a later shape is refused by
// name rather than read wrongly.
const RECORD_VERSION = 1;

let directory = null;

function setDirectory(hooks) {
  log.debug('Entering setDirectory().');
  if (hooks === null) {
    // CLEARED, which only a test does: `tests/CLAUDE.md`'s rule is that a slot
    // somebody stubbed is put back to what was there, and in a process that
    // never loaded the directory what was there is nothing.
    directory = null;
    log.debug('Leaving setDirectory(). Cleared.');
    return true;
  }
  const needed = ['readPerson', 'writePerson', 'personKeyInfos',
                  'readService', 'writeService', 'serviceKeyInfos'];
  const missing = needed.filter(function (name) {
    return !hooks || typeof hooks[name] !== 'function';
  });
  if (missing.length) {
    // WHOLE, for `admin.js`'s `setLogoutReader()` reason: a register that could
    // read people and not write them would derive keys it could never store,
    // on every sign-in, for ever.
    log.error(errorCodes.tag('STS-KRB-0110') +
              'krb5-keys: setDirectory() was given something without ' +
              missing.join(', ') + ', so it was refused whole. No person ' +
              'will get Kerberos keys and no service principal can be stored.');
    log.debug('Leaving setDirectory(). Refused.');
    return false;
  }
  directory = hooks;
  log.debug('Leaving setDirectory(). Installed.');
  return true;
}

function installed() {
  log.debug("Entering installed().");
  log.debug("Leaving installed().");
  return !!directory;
}

// What is installed, so a test that stubs the slot can put back exactly that.
function currentDirectory() {
  log.debug("Entering currentDirectory().");
  log.debug("Leaving currentDirectory().");
  return directory;
}

// Whether the KDC in this process is a product one — decided when the principal
// database was built, which is the only mode the KDC answers in.
function productKdc() {
  log.debug("Entering productKdc().");
  log.debug("Leaving productKdc().");
  return !principals.seedsDemoPrincipals;
}

function personKeysEnabled() {
  log.debug("Entering personKeysEnabled().");
  log.debug("Leaving personKeysEnabled().");
  return config.value('krb5.personKeys') !== false;
}

// A short, one-way fingerprint of the STORED password hash. It is what binds a
// set of keys to the password they were derived beside: the hash changes on
// every password set (scrypt salts it), so a stamp that no longer matches is a
// key made from a password the person no longer has. Not a secret — it is a
// digest of a digest — but it is only ever TRUSTED from inside the seal.
function stampOf(storedHash) {
  log.debug("Entering stampOf().");
  log.debug("Leaving stampOf().");
  return nodeCrypto.createHash('sha256').update(String(storedHash || ''))
    .digest('hex').slice(0, 32);
}

function saltFor(name) {
  log.debug("Entering saltFor().");
  log.debug("Leaving saltFor().");
  return principals.userSalt(principals.REALM, name);
}

// A principal name this file will key: one component, printable, and nothing
// that `ldap_server.js`'s lookup would read as a DN or a DID.
function personNameProblem(name) {
  log.debug("Entering personNameProblem().");
  const text = String(name == null ? '' : name);
  if (!text) {
    log.debug("Leaving personNameProblem().");
    return 'no name';
  }
  if (text.length > 255 || /[\s\/@=,\\\x00-\x1f]/.test(text)) {
    log.debug("Leaving personNameProblem().");
    return 'not a single-component principal name';
  }
  log.debug("Leaving personNameProblem().");
  return '';
}

function isSealedValue(value) {
  log.debug("Entering isSealedValue().");
  log.debug("Leaving isSealedValue().");
  return String(value || '').indexOf('$aesgcm$') === 0;
}

// Seal a record for storage, or say it could not be.
function sealRecord(record) {
  log.debug("Entering sealRecord().");
  const plaintext = JSON.stringify(record);
  if (!keystore.persists()) {
    log.debug("Leaving sealRecord().");
    return { value: plaintext, sealed: false };
  }
  const value = keystore.seal(plaintext, SEAL_LABEL);
  log.debug("Leaving sealRecord().");
  return value ? { value: value, sealed: true } : null;
}

// Open a stored value: `{ ok, record }` or `{ ok: false, why }`.
function openRecord(value) {
  log.debug("Entering openRecord().");
  const text = String(value || '');
  let plaintext = '';
  if (isSealedValue(text)) {
    plaintext = keystore.open(text, SEAL_LABEL) || '';
    if (!plaintext) {
      log.debug("Leaving openRecord().");
      return { ok: false, why: 'sealed under a different key-encryption key' };
    }
  } else if (keystore.persists()) {
    log.debug("Leaving openRecord().");
    // A CLEAR VALUE WHERE A SEALED ONE IS REQUIRED. This service never writes
    // one while keys persist, so it came from somewhere else — an `ldapmodify`
    // — and a key somebody chose is exactly what the seal exists to refuse.
    return { ok: false, why: 'stored in the clear, which this service never ' +
                             'writes while its key-encryption key persists' };
  } else {
    plaintext = text;
  }
  try {
    const record = JSON.parse(plaintext);
    if (!record || record.v !== RECORD_VERSION ||
        typeof record.keys !== 'object') {
      log.debug("Leaving openRecord().");
      return { ok: false, why: 'not a record this service wrote' };
    }
    log.debug("Leaving openRecord().");
    return { ok: true, record: record };
  } catch (e) {
    log.debug("Caught in openRecord(): " + ((e && e.message) || e));
    log.debug("Leaving openRecord().");
    // Not JSON: reported as unreadable rather than thrown, because the caller
    // is the KDC answering a request.
    return { ok: false, why: 'not JSON' };
  }
}

function parseInfo(value) {
  log.debug("Entering parseInfo().");
  try {
    log.debug("Leaving parseInfo().");
    return value ? JSON.parse(String(value)) : null;
  } catch (e) {
    log.debug("Caught in parseInfo(): " + ((e && e.message) || e));
    log.debug("Leaving parseInfo().");
    // A public info value nothing can read describes nothing; the KEYS are
    // judged from the seal, never from this.
    return null;
  }
}

// ---------------------------------------------------------------------------
// STRING-TO-KEY, the one path every derivation here takes. `s2kparams` is null
// for everything this file stores — the enctype's own default iteration count,
// which is what `krb5_principals.js`'s `longTermKey()` uses and what a client
// applies when PA-ETYPE-INFO2 carries none — and is a parameter only so that
// the RFC 3962 Appendix B vectors can be run through this same function.
// ---------------------------------------------------------------------------
async function deriveKey(etype, password, salt, s2kparams) {
  log.debug("Entering deriveKey().");
  const profile = kcrypto.etypeById(etype);
  log.debug("Leaving deriveKey().");
  return profile.stringToKey(String(password), prim.utf8(String(salt)),
                             s2kparams || null);
}

// ---------------------------------------------------------------------------
// PREVIOUS KEY VERSIONS (2026-09-12).
//
// A password change and a rotation both move the kvno up by one, and until this
// section they threw the old key away in the same write — so a ticket issued an
// instant earlier, still well inside its lifetime, was refused
// KRB_AP_ERR_BADKEYVER at its very next use. A real KDC keeps the previous kvno
// in its database and a service keeps it in its keytab until those tickets have
// expired; this is that, bounded twice — `krb5.retainedKeyVersions` says how
// many, `krb5.retainedKeyTtlS` how long each.
//
// **THEY LIVE INSIDE THE SAME SEALED VALUE, AS `previous`, AND NOT IN A
// COMPANION ATTRIBUTE.** Three reasons, and the first is the one that decides:
//
//   * ONE AUTHENTICATION TAG. The seal already binds the keys to a name and a
//     password stamp; a companion attribute would be a second sealed value that
//     could be copied, kept or restored independently of the first — an old
//     version planted back beside a new current key, or a current key written
//     while its previous versions are left on another entry. Inside the record
//     they are replaced, pruned and cleared in the one write that replaces the
//     current key, and a drop, a clear and a delete cannot miss them.
//   * ONE WRITE. A password change retires the old current key and stores the
//     new one atomically; two attributes would have a moment holding the new
//     key and no previous version, or the reverse.
//   * NO SCHEMA CHANGE. `stsKrb5Keys` and `krb5ServiceKeys` are already
//     withheld everywhere, sealed, and on the schema rows a sighting preserves;
//     a third and fourth attribute would have to be added to all of that and
//     would be the one a future change forgot. `RECORD_VERSION` stays 1:
//     `previous` is optional, a record without it has none, and an older reader
//     ignores it.
//
// **A PREVIOUS VERSION IS NEVER A WAY IN.** It is handed to the KDC for ONE
// purpose — decrypting a ticket already sealed under it — and
// pre-authentication reads the current keys only (`krb5_principals.js`'s
// `directoryUser()` puts those, and only those, in the key cache). An old
// password cannot sign in.
//
// **THE BOUNDS ARE APPLIED ON READ AS WELL AS ON WRITE.** A version's expiry is
// the EARLIER of the one stamped when it was retired and its retirement plus
// the lifetime in force NOW, so shortening the setting ends windows at once and
// lengthening it never resurrects one; the count is re-applied too. What is
// past either bound is never used and never listed, and the next write of that
// key removes it from storage.
// ---------------------------------------------------------------------------
function retainedVersionsLimit() {
  log.debug("Entering retainedVersionsLimit().");
  const n = Number(config.value('krb5.retainedKeyVersions'));
  log.debug("Leaving retainedVersionsLimit().");
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : 0;
}

// Seconds a retired version is kept. Zero in the setting means the longest a
// ticket issued under it can still be presented — see the settings row.
function retainedTtlSeconds() {
  log.debug("Entering retainedTtlSeconds().");
  const configured = Number(config.value('krb5.retainedKeyTtlS'));
  if (Number.isFinite(configured) && configured > 0) {
    log.debug("Leaving retainedTtlSeconds().");
    return configured;
  }
  log.debug("Leaving retainedTtlSeconds().");
  return Number(config.value('krb5.ticketLifetimeSeconds')) +
         Number(config.value('krb5.clockSkew'));
}

// When one retired version stops being usable, in epoch milliseconds; 0 for an
// entry that says nothing readable about when it was retired.
function retainedUntilMs(entry) {
  log.debug("Entering retainedUntilMs().");
  const retired = Date.parse(String((entry || {}).retiredAt || ''));
  if (!Number.isFinite(retired)) {
    log.debug("Leaving retainedUntilMs().");
    return 0;
  }
  const byNow = retired + retainedTtlSeconds() * 1000;
  const stamped = Date.parse(String(entry.expiresAt || ''));
  log.debug("Leaving retainedUntilMs().");
  return Number.isFinite(stamped) ? Math.min(stamped, byNow) : byNow;
}

// The entries of a `previous` list (sealed, with keys) or a `retained` list
// (public, without) that are inside both bounds at `nowMs`: newest first, at
// most the limit.
function withinBounds(list, nowMs) {
  log.debug("Entering withinBounds().");
  const limit = retainedVersionsLimit();
  if (!limit || !Array.isArray(list)) {
    log.debug("Leaving withinBounds().");
    return [];
  }
  log.debug("Leaving withinBounds().");
  return list.filter(function (entry) {
    return entry && Number.isFinite(Number(entry.kvno)) &&
           retainedUntilMs(entry) > nowMs;
  }).sort(function (a, b) {
    return Number(b.kvno) - Number(a.kvno);
  }).slice(0, limit);
}

// What `previous` becomes when `outgoing` — the record being replaced — stops
// being current at `nowMs`. An outgoing record at the SAME kvno as the one
// replacing it is not retired (the same password adding enctypes is the same
// version), so only the pruning happens.
function retire(outgoing, newKvno, nowMs) {
  log.debug("Entering retire().");
  const kept = withinBounds(outgoing && outgoing.previous, nowMs);
  if (!outgoing || Number(outgoing.kvno) === Number(newKvno) ||
      !retainedVersionsLimit()) {
    log.debug("Leaving retire().");
    return kept;
  }
  const entry = {
    kvno: Number(outgoing.kvno),
    salt: outgoing.salt || '',
    createdAt: outgoing.derivedAt || outgoing.createdAt || '',
    retiredAt: new Date(nowMs).toISOString(),
    expiresAt: new Date(nowMs + retainedTtlSeconds() * 1000).toISOString(),
    keys: outgoing.keys
  };
  log.debug("Leaving retire().");
  return withinBounds([entry].concat(kept.filter(function (one) {
    return Number(one.kvno) !== entry.kvno;
  })), nowMs);
}

// The public half of a sealed `previous` list, for the info attribute: kvno,
// enctypes and the two dates, never a key.
function retainedInfo(previous, nowMs) {
  log.debug("Entering retainedInfo().");
  log.debug("Leaving retainedInfo().");
  return withinBounds(previous, nowMs).map(function (entry) {
    return {
      kvno: Number(entry.kvno),
      etypes: Object.keys(entry.keys || {}).map(Number).filter(Number.isFinite),
      retiredAt: entry.retiredAt,
      expiresAt: new Date(retainedUntilMs(entry)).toISOString()
    };
  });
}

// The public `retained` list of an info attribute, as a page lists it: inside
// both bounds NOW, with the expiry the bounds give now.
function retainedRows(infoRetained, nowMs) {
  log.debug("Entering retainedRows().");
  log.debug("Leaving retainedRows().");
  return withinBounds(infoRetained, nowMs).map(function (entry) {
    return {
      kvno: Number(entry.kvno),
      etypes: (Array.isArray(entry.etypes) ? entry.etypes : []).map(
          function (etype) {
        return { etype: Number(etype), name: kcrypto.etypeName(Number(etype)) };
      }),
      retiredAt: String(entry.retiredAt || ''),
      expiresAt: new Date(retainedUntilMs(entry)).toISOString()
    };
  });
}

// `{ "18": "<base64>" }` into the `[[etype, bytes]]` pairs the KDC takes, in
// this KDC's own enctype order and only for enctypes it offers.
function keyPairs(keys) {
  log.debug("Entering keyPairs().");
  log.debug("Leaving keyPairs().");
  return principals.KDC_ETYPES.filter(function (etype) {
    return keys && typeof keys[etype] === 'string';
  }).map(function (etype) {
    return [etype, Uint8Array.from(Buffer.from(keys[etype], 'base64'))];
  });
}

// The retained versions of a record as the KDC's key source hands them over.
function retainedForKdc(record, nowMs) {
  log.debug("Entering retainedForKdc().");
  log.debug("Leaving retainedForKdc().");
  return withinBounds(record.previous, nowMs).map(function (entry) {
    return { kvno: Number(entry.kvno), expiresAt: retainedUntilMs(entry),
             keys: keyPairs(entry.keys) };
  }).filter(function (entry) {
    return entry.keys.length > 0;
  });
}

// ---------------------------------------------------------------------------
// THE KDC'S KEY SOURCE — the two functions `principals.setKeySource()` takes.
// Synchronous, because the principal lookup is: a directory read and a seal
// opened, no derivation.
// ---------------------------------------------------------------------------
function personKeys(name) {
  log.debug('Entering personKeys(). name=' + name);
  if (!directory) {
    log.debug('Leaving personKeys(). No directory.');
    return { state: 'no-source' };
  }
  if (!personKeysEnabled()) {
    log.debug('Leaving personKeys(). Switched off.');
    return { state: 'off' };
  }
  if (personNameProblem(name)) {
    log.debug('Leaving personKeys(). Not a usable name.');
    return { state: 'unknown' };
  }
  const current = directory.readPerson(name);
  if (!current) {
    log.debug('Leaving personKeys(). Nobody by that name.');
    return { state: 'unknown' };
  }
  if (!current.keys) {
    log.debug('Leaving personKeys(). No keys yet.');
    return { state: 'none' };
  }
  const opened = openRecord(current.keys);
  if (!opened.ok) {
    log.debug('Leaving personKeys(). Unreadable: ' + opened.why);
    return { state: 'unreadable', detail: opened.why };
  }
  const record = opened.record;
  if (record.name !== name || record.realm !== principals.REALM) {
    // Exact, as Kerberos names are: the salt carries the name as it was, and a
    // key for `Alice` is not a key for `alice`.
    log.debug('Leaving personKeys(). Bound to ' + record.name + '@' +
              record.realm + '.');
    return { state: 'unknown', detail: 'the stored keys are bound to another ' +
                                       'name' };
  }
  if (!current.passwordHash || record.stamp !== stampOf(current.passwordHash)) {
    log.debug('Leaving personKeys(). Derived from an older password.');
    return { state: 'stale' };
  }
  const keys = keyPairs(record.keys);
  if (!keys.length) {
    log.debug('Leaving personKeys(). No key for any enctype this KDC offers.');
    return { state: 'none' };
  }
  // THE PREVIOUS VERSIONS RIDE BESIDE THE CURRENT KEYS AND NEVER AMONG THEM:
  // `krb5_principals.js` keeps them apart, so pre-authentication can only ever
  // be checked against `keys`.
  const retained = retainedForKdc(record, Date.now());
  log.debug('Leaving personKeys(). kvno ' + record.kvno + ', ' + keys.length +
            ' key(s), ' + retained.length + ' previous version(s).');
  return { state: 'ok', kvno: record.kvno, salt: record.salt, keys: keys,
           retained: retained };
}

function serviceKeys(spn) {
  log.debug("Entering serviceKeys().");
  if (!directory) {
    log.debug("Leaving serviceKeys().");
    return null;
  }
  log.debug('Entering serviceKeys(). spn=' + spn);
  const current = directory.readService(String(spn) + '@' + principals.REALM);
  if (!current || !current.keys) {
    log.debug('Leaving serviceKeys(). None stored.');
    return null;
  }
  const opened = openRecord(current.keys);
  if (!opened.ok || opened.record.spn !== String(spn) ||
      opened.record.realm !== principals.REALM) {
    // Treated as NO stored key — the configured account, if there is one,
    // answers as it did before — and said at warn, because an operator made
    // this key and it has stopped working.
    log.warn('krb5-keys: the stored key for ' + spn + ' cannot be used (' +
             (opened.ok ? 'it is bound to another principal' : opened.why) +
             '). Rotate it at /admin/kerberos/principals.');
    log.debug('Leaving serviceKeys(). Unusable.');
    return null;
  }
  const record = opened.record;
  const keys = keyPairs(record.keys);
  log.debug('Leaving serviceKeys(). kvno ' + record.kvno + '.');
  return keys.length
    ? { kvno: record.kvno, keys: keys,
        retained: retainedForKdc(record, Date.now()) }
    : null;
}

// ---------------------------------------------------------------------------
// THE DERIVATION, which the password observer starts.
//
// ONE AT A TIME PER PERSON, chained: two sign-ins racing would otherwise derive
// twice and write last-wins, and a set racing a verify of the PREVIOUS password
// could write keys for the old one after the new one's. The chain makes them
// sequential and the re-read before the write — is the hash still the one this
// derivation started beside? — makes a superseded one abandon itself.
// ---------------------------------------------------------------------------
// KEYED BY REALM AND NAME SINCE 2026-09-15. It was the name alone, which was
// one queue per person while there was one KDC; with a KDC per trust realm the
// same username exists in several realms as several people, and a derivation
// for one would serialise behind — and be waited on by — another realm's.
const inFlight = new Map();

function inFlightKey(name) {
  log.debug("Entering inFlightKey().");
  log.debug("Leaving inFlightKey().");
  return realms.currentId() + '|' + String(name);
}

function observePassword(name, password, info) {
  log.debug('Entering observePassword(). name=' + name);
  const event = (info && info.event) || 'verified';
  if (!productKdc() || !directory || !personKeysEnabled() ||
      personNameProblem(name) || !principals.enabledIn(realms.currentId())) {
    // Nothing to do, and deliberately said at debug: this is called on every
    // verified sign-in in the service.
    log.debug('Leaving observePassword(). Not deriving (' +
              (!productKdc() ? 'development KDC'
                : !directory ? 'no directory'
                : !personKeysEnabled() ? 'krb5.personKeys is off'
                : personNameProblem(name) ? 'not a principal name'
                : 'this trust realm has no KDC') + ').');
    return;
  }
  const queue = inFlightKey(name);
  const previous = inFlight.get(queue) || Promise.resolve();
  const next = previous.then(function () {
    return derive(name, password, event);
  }).catch(function (e) {
    log.error(errorCodes.tag('STS-KRB-0107') + 'krb5-keys: deriving the ' +
              'Kerberos keys for ' + name + ' failed: ' +
              (e.stack || e.message));
    audit.failure('STS-KRB-0107', {
      action: 'service.failure', protocol: 'Kerberos', channel: 'internal',
      target: name + '@' + principals.REALM, outcome: 'error',
      summary: 'Kerberos keys could not be derived for ' + name + ' after a ' +
               'password was ' + event + '; the ' + event + ' itself was ' +
               'unaffected'
    });
  });
  inFlight.set(queue, next);
  next.then(function () {
    if (inFlight.get(queue) === next) {
      inFlight.delete(queue);
    }
  });
  log.debug('Leaving observePassword(). A derivation is queued.');
}

// Every derivation now running, settled — in EVERY realm, which is what a
// caller of this wants: a test, or a console action that clears keys and must
// not race a derivation writing them back, cares that nothing is still in
// flight rather than that one realm's queue is empty.
function idle() {
  log.debug("Entering idle().");
  log.debug("Leaving idle().");
  return Promise.all(Array.from(inFlight.values()));
}

async function derive(name, password, event) {
  log.debug('Entering derive(). name=' + name + ' event=' + event);
  const current = directory.readPerson(name);
  if (!current || !current.passwordHash) {
    log.info('krb5-keys: ' + name + ' has no entry or no stored password, so ' +
             'no Kerberos keys were derived.');
    log.debug('Leaving derive(). Nothing to key.');
    return { derived: false, why: 'no-password' };
  }
  const stamp = stampOf(current.passwordHash);
  const wanted = principals.KDC_ETYPES.slice();
  const opened = current.keys ? openRecord(current.keys) : { ok: false };
  const record = opened.ok ? opened.record : null;
  const info = parseInfo(current.info);
  if (event !== 'set' && record && record.name === name &&
      record.stamp === stamp &&
      wanted.every(function (etype) {
        return typeof record.keys[etype] === 'string';
      })) {
    log.debug('Leaving derive(). The keys are already current.');
    return { derived: false, why: 'current' };
  }
  // THE KVNO. The same password adding enctypes keeps its version — those keys
  // did not change. A different password is a new key and a new version, and
  // a first key starts at `krb5.kvno`.
  let kvno;
  if (record && record.stamp === stamp) {
    kvno = Number(record.kvno);
  } else if (record || (info && info.kvno)) {
    kvno = Number((record || info).kvno) + 1;
  } else {
    kvno = Number(config.value('krb5.kvno'));
  }
  const salt = saltFor(name);
  const keys = {};
  for (const etype of wanted) {
    const key = await deriveKey(etype, password, salt, null);
    keys[etype] = Buffer.from(key).toString('base64');
  }
  // SUPERSEDED? A newer password landed while this one was being derived.
  const again = directory.readPerson(name);
  if (!again || again.passwordHash !== current.passwordHash) {
    log.info('krb5-keys: the password for ' + name + ' changed while its ' +
             'Kerberos keys were being derived, so these were thrown away; ' +
             'the newer password\'s derivation writes its own.');
    log.debug('Leaving derive(). Superseded.');
    return { derived: false, why: 'superseded' };
  }
  const nowMs = Date.now();
  const derivedAt = new Date(nowMs).toISOString();
  // THE OUTGOING RECORD IS THE ONE ON THE ENTRY NOW, not the one read before
  // the derivation: an operator's "drop previous versions" may have landed in
  // between, and retiring from the older read would put back what they dropped.
  // `again` is read and this write is made with no await between them.
  const againOpened = again.keys ? openRecord(again.keys) : { ok: false };
  const outgoing = againOpened.ok && againOpened.record.name === name
    ? againOpened.record : null;
  const previous = retire(outgoing, kvno, nowMs);
  const sealed = sealRecord({ v: RECORD_VERSION, name: name,
                              realm: principals.REALM, kvno: kvno, salt: salt,
                              stamp: stamp, derivedAt: derivedAt, keys: keys,
                              previous: previous });
  if (!sealed) {
    log.error(errorCodes.tag('STS-KRB-0108') + 'krb5-keys: the Kerberos keys ' +
              'for ' + name + ' could not be sealed, so they were NOT ' +
              'stored. Storing them in the clear would put a ' +
              'password-equivalent key in every directory dump.');
    audit.failure('STS-KRB-0108', {
      action: 'service.failure', protocol: 'Kerberos', channel: 'internal',
      target: name + '@' + principals.REALM, outcome: 'error',
      summary: 'Kerberos keys for ' + name + ' could not be sealed and were ' +
                                             'not stored'
    });
    log.debug('Leaving derive(). Not sealed.');
    return { derived: false, why: 'seal' };
  }
  const infoValue = JSON.stringify({ kvno: kvno, etypes: wanted,
                                     derivedAt: derivedAt,
                                     sealed: sealed.sealed, event: event,
                                     stamp: stamp,
                                     retained: retainedInfo(previous, nowMs) });
  if (!directory.writePerson(name, sealed.value, infoValue)) {
    log.error(errorCodes.tag('STS-KRB-0109') + 'krb5-keys: the Kerberos keys ' +
              'for ' + name + ' could not be written to their entry.');
    audit.failure('STS-KRB-0109', {
      action: 'service.failure', protocol: 'Kerberos', channel: 'internal',
      target: name + '@' + principals.REALM, outcome: 'error',
      summary: 'Kerberos keys for ' + name + ' could not be written to the ' +
                                             'directory'
    });
    log.debug('Leaving derive(). Not written.');
    return { derived: false, why: 'write' };
  }
  audit.audit({
    action: 'krb5.keys.derived', actor: name, protocol: 'Kerberos',
    channel: 'internal', target: name + '@' + principals.REALM,
    summary: 'Kerberos keys for ' + name + ' were derived from the password ' +
                                           'just ' +
             (event === 'set' ? 'set' : 'verified') + ' (kvno ' + kvno + ', ' +
             wanted.map(kcrypto.etypeName).join(', ') + ')',
    // No key, no salt beyond what ETYPE-INFO2 publishes anyway, no password.
    detail: { kvno: kvno, etypes: wanted, event: event, sealed: sealed.sealed,
              retainedKvnos: previous.map(function (one) { return one.kvno; }) }
  });
  log.info('krb5-keys: ' + name + '@' + principals.REALM + ' now has ' +
           'Kerberos keys at ' +
           'kvno ' + kvno + ' (' + (sealed.sealed ? 'sealed' : 'clear, ' +
           'development key ' +
           'store') + '), derived from the password just ' + event +
           (previous.length ?
            '; keeping previous kvno ' + previous.map(function (one) {
             return one.kvno;
           }).join(', ') + ' for tickets already issued under it' : '') + '.');
  log.debug('Leaving derive(). kvno ' + kvno + '.');
  return { derived: true, kvno: kvno };
}

// ---------------------------------------------------------------------------
// SERVICE PRINCIPALS.
// ---------------------------------------------------------------------------

// `HTTP/web.example.com` or `HTTP/web.example.com@EXAMPLE.COM`, refused
// otherwise with a sentence. The realm, when given, must be this KDC's: a key
// stored for another realm's principal is a key nothing here would ask for.
function normaliseSpn(raw) {
  log.debug('Entering normaliseSpn().');
  let text = String(raw == null ? '' : raw).trim();
  const at = text.lastIndexOf('@');
  if (at >= 0) {
    const realm = text.slice(at + 1);
    if (realm !== principals.REALM) {
      log.debug('Leaving normaliseSpn(). Foreign realm.');
      return { ok: false, error: '"' + text + '" names the realm ' + realm +
               ', and this KDC is ' + principals.REALM + '.' };
    }
    text = text.slice(0, at);
  }
  const components = text.split('/');
  if (components.length < 2 || components.some(function (c) {
    return !c || /[\s@\\\x00-\x1f]/.test(c);
  }) || text.length > 255) {
    log.debug('Leaving normaliseSpn(). Not a service principal name.');
    return { ok: false, error: '"' + text + '" is not a service principal ' +
             'name: one is two or more non-empty components separated by ' +
             '"/", like HTTP/web.example.com, with no spaces and no "@" ' +
             'inside it.' };
  }
  if (components[0].toLowerCase() === 'krbtgt') {
    log.debug('Leaving normaliseSpn(). krbtgt.');
    return { ok: false, error: 'krbtgt is the ticket-granting key every TGT ' +
             'in the realm is sealed under, and it is set by ' +
             'krb5.krbtgtPassword rather than stored here.' };
  }
  log.debug('Leaving normaliseSpn().');
  return { ok: true, components: components, spn: text,
           identifier: text + '@' + principals.REALM };
}

function refusal(code, message) {
  log.debug("Entering refusal().");
  log.debug("Leaving refusal().");
  return errorCodes.mark({ ok: false, errors: [message] }, code);
}

// ---------------------------------------------------------------------------
// NO KDC IN THIS TRUST REALM, NO KEYS IN IT (2026-09-15).
//
// Every act below writes key material for a principal of the AMBIENT realm's
// KDC, and a realm whose `krb5.enabled` is off has no such KDC: no Kerberos
// realm name, no principal database, no etypes. Without this guard those acts
// did not refuse — they SUCCEEDED emptily, which is worse than either: the SPN
// was stored as `HTTP/web.acme.test@` (the realm name is the empty string), the
// key list was built from an empty etype list, and the caller was handed a
// keytab with no entries and told it was created. `observePassword()` has asked
// the same question since the split; these six had been left with the
// register's older assumption that there was always exactly one KDC.
// ---------------------------------------------------------------------------
function noKdcHere() {
  log.debug("Entering noKdcHere().");
  const state = principals.kerberosRealmOf();
  if (state.enabled && state.active) {
    log.debug("Leaving noKdcHere(). This realm has a KDC.");
    return null;
  }
  log.debug("Leaving noKdcHere(). No KDC here.");
  return refusal('STS-KRB-0128', 'Trust realm "' + state.trustRealm + '" ' +
    'has no KDC, so there is nothing here to hold a Kerberos key for: ' +
    (state.reason || 'krb5.enabled is off for it') + '. Give the realm a ' +
    'krb5.realm of its own and turn krb5.enabled on, and its principals ' +
    'become the people and applications in its own directory.');
}

// Random keys, sealed, written, and the keytab that carries them. The one
// function a create and a rotate share, so that they cannot disagree about what
// a stored service key is.
//
// `outgoing` is the opened record a ROTATE replaces (null for a create): its
// key becomes a previous version, and **THE KEYTAB CARRIES EVERY VERSION STILL
// KEPT**, current first — what MIT's `ktadd` without `-k` leaves in a keytab,
// and what a service needs so that a ticket issued under the old kvno a moment
// before the rotation is still accepted once the new keytab is installed.
function mintServiceKeys(spn, kvno, act, context, outgoing) {
  log.debug('Entering mintServiceKeys(). spn=' + spn.spn + ' kvno=' + kvno);
  const etypes = principals.KDC_ETYPES.slice();
  const now = new Date();
  const keys = {};
  const entries = [];
  etypes.forEach(function (etype) {
    const key = kcrypto.randomBytes(kcrypto.etypeById(etype).keyBytes);
    keys[etype] = Buffer.from(key).toString('base64');
    entries.push({ realm: principals.REALM, components: spn.components,
                   nameType: keytab.NAME_TYPE_PRINCIPAL, timestamp: now,
                   kvno: kvno, etype: etype, key: key });
  });
  const kept = retire(outgoing || null, kvno, now.getTime());
  kept.forEach(function (version) {
    const made = Date.parse(String(version.createdAt || ''));
    keyPairs(version.keys).forEach(function (pair) {
      entries.push({ realm: principals.REALM, components: spn.components,
                     nameType: keytab.NAME_TYPE_PRINCIPAL,
                     timestamp: Number.isFinite(made) ? new Date(made) : now,
                     kvno: Number(version.kvno), etype: pair[0],
                     key: pair[1] });
    });
  });
  const previous = parseInfo((directory.readService(spn.identifier) ||
                              {}).info);
  const sealed = sealRecord({ v: RECORD_VERSION, spn: spn.spn,
                              realm: principals.REALM,
                              kvno: kvno, createdAt: now.toISOString(), keys:
                                                                          keys,
                              previous: kept });
  if (!sealed) {
    log.error(errorCodes.tag('STS-KRB-0108') + 'krb5-keys: the key for ' +
              spn.spn + ' could not be sealed, so nothing was stored.');
    log.debug('Leaving mintServiceKeys(). Not sealed.');
    return refusal('STS-ADMIN-0607', 'The new key for ' + spn.spn + ' could ' +
                   'not be encrypted under the key-encryption key, so ' +
                   'nothing was stored and no keytab was made.');
  }
  const info = { kvno: kvno, etypes: etypes, sealed: sealed.sealed,
                 createdAt: previous && previous.createdAt ? previous.createdAt
                                                           : now.toISOString(),
                 rotatedAt: act === 'rotated' ? now.toISOString() : '',
                 retained: retainedInfo(kept, now.getTime()) };
  if (!directory.writeService(spn.identifier, sealed.value,
                              JSON.stringify(info))) {
    log.debug('Leaving mintServiceKeys(). Not written.');
    return refusal('STS-ADMIN-0607', 'The key for ' + spn.spn + ' could not ' +
                   'be written to its application entry, so no keytab was ' +
                   'made.');
  }
  const bytes = keytab.writeKeytab(entries);
  audit.audit({
    action: 'admin.krb5.service.' + act,
    actor: String((context || {}).actor || ''),
    protocol: 'Kerberos', channel: 'internal', target: spn.identifier,
    summary: 'The Kerberos service principal ' + spn.identifier + ' was ' +
             act +
             ' with a random key (kvno ' + kvno + ') through the ' +
             String((context || {}).via || 'console'),
    detail: { kvno: kvno, etypes: etypes,
              via: String((context || {}).via || 'console'),
              retainedKvnos: kept.map(function (one) { return one.kvno; }) }
  });
  log.info('krb5-keys: ' + spn.identifier + ' ' + act + ' at kvno ' + kvno +
           (kept.length ? ', keeping previous kvno ' + kept.map(function (one) {
             return one.kvno;
           }).join(', ') : '') +
           '; its keytab was handed to the caller and is not kept.');
  log.debug('Leaving mintServiceKeys().');
  const retained = retainedRows(retainedInfo(kept, now.getTime()),
                                now.getTime());
  log.debug("Leaving mintServiceKeys().");
  return {
    ok: true, act: act, spn: spn.spn, principal: spn.identifier, kvno: kvno,
    etypes: etypes, sealed: sealed.sealed, retained: retained,
    keytabKvnos: [kvno].concat(kept.map(function (
        one) { return Number(one.kvno); })),
    keytabFilename: spn.spn.replace(/[^A-Za-z0-9.-]+/g, '_') + '.kvno' + kvno +
                    '.keytab',
    keytab: bytes.toString('base64'),
    message: 'The Kerberos service principal ' + spn.identifier + ' was ' +
             act +
             ' at kvno ' + kvno + '. Its keytab is in this answer and is not ' +
             'kept: it cannot be downloaded again, only replaced by rotating.' +
             (kept.length
               ? ' The keytab also carries the previous kvno ' +
                 kept.map(function (one) {
                   return one.kvno;
                 }).join(', ') + ', which this KDC and its acceptor still ' +
                 'accept for tickets already issued under it until ' +
                 retained.map(function (one) { return one.expiresAt; })
                         .join(', ') +
                 ' (krb5.retainedKeyTtlS).'
               : '')
  };
}

function createServicePrincipal(raw, context) {
  log.debug('Entering createServicePrincipal().');
  const noKdc = noKdcHere();
  if (noKdc) {
    log.debug('Leaving createServicePrincipal(). No KDC in this trust realm.');
    return noKdc;
  }
  const spn = normaliseSpn(raw);
  if (!spn.ok) {
    log.debug('Leaving createServicePrincipal(). Not an SPN.');
    return refusal('STS-ADMIN-0603', spn.error);
  }
  if (!directory) {
    log.debug('Leaving createServicePrincipal(). No directory.');
    return refusal('STS-ADMIN-0609', 'There is no directory in this process, ' +
                   'so there is nowhere to store a service principal\'s key.');
  }
  const existing = directory.readService(spn.identifier);
  if (existing && existing.keys) {
    log.debug('Leaving createServicePrincipal(). Already keyed.');
    return refusal('STS-ADMIN-0604', spn.identifier + ' already holds a ' +
                   'stored key. Rotate it to get a new keytab; creating it ' +
                   'again would silently strand every service holding the ' +
                   'current one.');
  }
  if (!existing) {
    // THE APPLICATION ENTRY, in the AMBIENT trust realm since 2026-09-15 — the
    // realm whose KDC will issue tickets for this SPN, which is the realm this
    // request is in. Created through the registry's own door, so it is the same
    // entry a ticket for this SPN would have made.
    const created = applications.createApplication({
      identifier: spn.identifier, kind: 'kerberos-service',
      protocols: ['krb5'],
      fields: { krb5ServicePrincipalName: spn.identifier },
      actor: String((context || {}).actor || '')
    });
    if (!created.ok || !directory.readService(spn.identifier)) {
      log.debug('Leaving createServicePrincipal(). No application entry.');
      return refusal('STS-ADMIN-0606',
                     'No application entry could be made for ' +
                     spn.identifier + ': ' + ((created.errors || []).join(
                         ' ') ||
                     'the directory did not hold it afterwards') + '.');
    }
  }
  const result = mintServiceKeys(spn, Number(config.value('krb5.kvno')),
                                 'created',
                                 context);
  log.debug('Leaving createServicePrincipal().');
  return result;
}

function rotateServicePrincipal(raw, context) {
  log.debug('Entering rotateServicePrincipal().');
  const noKdc = noKdcHere();
  if (noKdc) {
    log.debug('Leaving rotateServicePrincipal(). No KDC in this trust realm.');
    return noKdc;
  }
  const spn = normaliseSpn(raw);
  if (!spn.ok) {
    log.debug('Leaving rotateServicePrincipal(). Not an SPN.');
    return refusal('STS-ADMIN-0603', spn.error);
  }
  if (!directory) {
    log.debug('Leaving rotateServicePrincipal(). No directory.');
    return refusal('STS-ADMIN-0609', 'There is no directory in this process.');
  }
  const existing = directory.readService(spn.identifier);
  if (!existing || !existing.keys) {
    log.debug('Leaving rotateServicePrincipal(). Nothing stored.');
    return refusal('STS-ADMIN-0605', spn.identifier + ' holds no stored key ' +
                   'to rotate. Create it first.');
  }
  const opened = openRecord(existing.keys);
  const info = parseInfo(existing.info);
  const was = opened.ok ? Number(opened.record.kvno)
                        : Number((info && info.kvno) || config.value(
                            'krb5.kvno'));
  // A record this process cannot open is rotated with nothing retained: a key
  // that cannot be read is no key a ticket could be opened with.
  const outgoing = opened.ok && opened.record.spn === spn.spn ? opened.record :
                   null;
  const result = mintServiceKeys(spn, was + 1, 'rotated', context, outgoing);
  log.debug('Leaving rotateServicePrincipal().');
  return result;
}

function deleteServicePrincipal(raw, context) {
  log.debug('Entering deleteServicePrincipal().');
  const noKdc = noKdcHere();
  if (noKdc) {
    log.debug('Leaving deleteServicePrincipal(). No KDC in this trust realm.');
    return noKdc;
  }
  const spn = normaliseSpn(raw);
  if (!spn.ok) {
    log.debug('Leaving deleteServicePrincipal(). Not an SPN.');
    return refusal('STS-ADMIN-0603', spn.error);
  }
  if (!directory) {
    log.debug('Leaving deleteServicePrincipal(). No directory.');
    return refusal('STS-ADMIN-0609', 'There is no directory in this process.');
  }
  const existing = directory.readService(spn.identifier);
  if (!existing || !existing.keys) {
    log.debug('Leaving deleteServicePrincipal(). Nothing stored.');
    return refusal('STS-ADMIN-0605', spn.identifier + ' holds no stored key.');
  }
  const info = parseInfo(existing.info);
  if (!directory.writeService(spn.identifier, null, null)) {
    log.debug('Leaving deleteServicePrincipal(). Not written.');
    return refusal('STS-ADMIN-0607', 'The stored key for ' + spn.identifier +
                   ' could not be removed from its application entry.');
  }
  audit.audit({
    action: 'admin.krb5.service.deleted',
    actor: String((context || {}).actor || ''),
    protocol: 'Kerberos', channel: 'internal', target: spn.identifier,
    summary: 'The stored key for the Kerberos service principal ' +
             spn.identifier +
             ' was deleted through the ' + String(
                 (context || {}).via || 'console'),
    detail: { kvno: info ? info.kvno : null,
              via: String((context || {}).via || 'console') }
  });
  log.debug('Leaving deleteServicePrincipal().');
  return { ok: true, spn: spn.spn, principal: spn.identifier,
           message: 'The stored key for ' + spn.identifier + ' is gone. The ' +
                    'application entry stays, as every entry this registry ' +
                    'records does; a ticket for that SPN is now keyed as it ' +
                    'was before a key was stored — from krb5.servicePassword ' +
                    'if it is the acceptor\'s own name, and not at all in ' +
                    'product mode otherwise.' };
}

function clearPersonKeys(name, context) {
  log.debug('Entering clearPersonKeys(). name=' + name);
  const noKdc = noKdcHere();
  if (noKdc) {
    log.debug('Leaving clearPersonKeys(). No KDC in this trust realm.');
    return noKdc;
  }
  const who = String(name == null ? '' : name).trim();
  if (!directory) {
    log.debug('Leaving clearPersonKeys(). No directory.');
    return refusal('STS-ADMIN-0609', 'There is no directory in this process.');
  }
  if (!who || personNameProblem(who)) {
    log.debug('Leaving clearPersonKeys(). No usable name.');
    return refusal('STS-ADMIN-0608', 'Name the person whose Kerberos keys to ' +
                   'clear, as `username`.');
  }
  const current = directory.readPerson(who);
  if (!current) {
    log.debug('Leaving clearPersonKeys(). Nobody by that name.');
    return refusal('STS-ADMIN-0608', 'There is nobody called "' + who + '" ' +
                   'in this trust realm\'s directory, which is the ' +
                   'one its KDC reads.');
  }
  if (!current.keys && !current.info) {
    log.debug('Leaving clearPersonKeys(). Nothing held.');
    return { ok: true, cleared: false, username: who,
             message: who + ' holds no Kerberos keys, so there was nothing ' +
                            'to clear.' };
  }
  if (!directory.writePerson(who, null, null)) {
    log.debug('Leaving clearPersonKeys(). Not written.');
    return refusal('STS-ADMIN-0607', 'The Kerberos keys on ' + who + '\'s ' +
                   'entry could not be removed.');
  }
  audit.audit({
    action: 'admin.krb5.keys.cleared',
    actor: String((context || {}).actor || ''),
    protocol: 'Kerberos', channel: 'internal', target: who + '@' +
                                                       principals.REALM,
    summary: 'The Kerberos keys of ' + who + ' were cleared through the ' +
             String((context || {}).via || 'console'),
    detail: { via: String((context || {}).via || 'console') }
  });
  log.debug('Leaving clearPersonKeys(). Cleared.');
  return { ok: true, cleared: true, username: who,
           message: 'The Kerberos keys of ' + who + ' are cleared, previous ' +
                    'versions included. Their next AS-REQ is refused with ' +
                    '"sign in once"; their next verified sign-in derives new ' +
                    'keys at the next kvno.' };
}

// ---------------------------------------------------------------------------
// DROP THE PREVIOUS VERSIONS NOW — an operator ending the window early, which
// is what somebody does after a compromise: the old password or the old keytab
// is in the wrong hands, and a ticket issued under it must stop being accepted
// before its lifetime is out.
//
// It REWRITES the record with `previous` empty and the current key untouched,
// so the person still signs in and the service keeps its current keytab.
// Somebody holding nothing to drop is answered `dropped: 0` rather than
// refused, for `clearPersonKeys()`'s reason. A record this process cannot OPEN
// is refused: rewriting it would mean writing a current key it cannot read.
//
// `write(keysValue, infoValue)` is the one thing a person and a service differ
// in beyond how they are located, so both go through this.
// ---------------------------------------------------------------------------
function dropPrevious(kind, label, current, context, write) {
  log.debug('Entering dropPrevious(). ' + kind + '=' + label);
  if (!current || !current.keys) {
    log.debug('Leaving dropPrevious(). No stored key.');
    return refusal('STS-ADMIN-0605', label + ' holds no stored Kerberos key, ' +
                   'so there are no previous versions to drop.');
  }
  const opened = openRecord(current.keys);
  if (!opened.ok) {
    log.debug('Leaving dropPrevious(). Unreadable.');
    return refusal('STS-ADMIN-0607', 'The stored Kerberos key for ' + label +
                   ' cannot be opened on this service (' + opened.why + '), ' +
                   'so its previous versions cannot be dropped without ' +
                   'rewriting a key it cannot read. Clear or rotate it ' +
                   'instead.');
  }
  const nowMs = Date.now();
  const stored = Array.isArray(opened.record.previous) ?
                 opened.record.previous : [];
  const live = withinBounds(stored, nowMs);
  if (!stored.length) {
    log.debug('Leaving dropPrevious(). Nothing kept.');
    return { ok: true, dropped: 0, kvnos: [], principal: label,
             message: label + ' keeps no previous key version, so there was ' +
                      'nothing to drop.' };
  }
  const sealed = sealRecord(Object.assign({}, opened.record, { previous: [] }));
  const info = Object.assign({}, parseInfo(current.info) || {},
                             { retained: [] });
  if (!sealed || !write(sealed.value, JSON.stringify(info))) {
    log.debug('Leaving dropPrevious(). Not written.');
    return refusal('STS-ADMIN-0607', 'The previous Kerberos key versions of ' +
                   label + ' could not be removed from its entry.');
  }
  const kvnos = live.map(function (one) { return Number(one.kvno); });
  audit.audit({
    action: 'admin.krb5.previous.dropped',
    actor: String((context || {}).actor || ''),
    protocol: 'Kerberos', channel: 'internal', target: label,
    summary: 'The previous Kerberos key versions of ' + label + ' (' +
             (kvnos.length ? 'kvno ' + kvnos.join(', ') : 'none still in ' +
                 'their window') +
             ') were dropped through the ' +
             String((context || {}).via || 'console'),
    detail: { kind: kind, kvnos: kvnos,
              via: String((context || {}).via || 'console') }
  });
  log.info('krb5-keys: dropped the previous key versions of ' + label + ' (' +
           (kvnos.join(', ') || 'only expired ones were left') + '); a ' +
           'ticket under any of them is now refused KRB_AP_ERR_BADKEYVER.');
  log.debug('Leaving dropPrevious(). ' + kvnos.length + ' dropped.');
  return { ok: true, dropped: kvnos.length, kvnos: kvnos, principal: label,
           currentKvno: Number(opened.record.kvno),
           message: kvnos.length
             ? 'Dropped previous kvno ' + kvnos.join(', ') + ' of ' + label +
               '. ' +
               'A ticket issued ' +
               'under ' + (kvnos.length === 1 ? 'it' : 'any of ' +
                   'them') +
               ' is now refused KRB_AP_ERR_BADKEYVER; kvno ' +
               opened.record.kvno +
               ' is untouched.'
             : label + ' kept only previous versions already past their ' +
               'window; they are removed from storage now.' };
}

function dropPreviousPersonKeys(name, context) {
  log.debug('Entering dropPreviousPersonKeys(). name=' + name);
  const noKdc = noKdcHere();
  if (noKdc) {
    log.debug('Leaving dropPreviousPersonKeys(). No KDC in this trust realm.');
    return noKdc;
  }
  const who = String(name == null ? '' : name).trim();
  if (!directory) {
    log.debug('Leaving dropPreviousPersonKeys(). No directory.');
    return refusal('STS-ADMIN-0609', 'There is no directory in this process.');
  }
  if (!who || personNameProblem(who)) {
    log.debug('Leaving dropPreviousPersonKeys(). No usable name.');
    return refusal('STS-ADMIN-0608', 'Name the person whose previous ' +
                   'Kerberos key versions to drop, as `username`.');
  }
  const current = directory.readPerson(who);
  if (!current) {
    log.debug('Leaving dropPreviousPersonKeys(). Nobody by that name.');
    return refusal('STS-ADMIN-0608', 'There is nobody called "' + who + '" ' +
                   'in this trust realm\'s directory, which is the ' +
                   'one its KDC reads.');
  }
  const result = dropPrevious('person', who + '@' + principals.REALM, current,
    context,
    function (keysValue, infoValue) {
      return directory.writePerson(who, keysValue, infoValue);
    });
  if (result.ok) {
    result.username = who;
  }
  log.debug('Leaving dropPreviousPersonKeys(). ok=' + result.ok);
  return result;
}

function dropPreviousServiceKeys(raw, context) {
  log.debug('Entering dropPreviousServiceKeys().');
  const noKdc = noKdcHere();
  if (noKdc) {
    log.debug('Leaving dropPreviousServiceKeys(). No KDC in this trust realm.');
    return noKdc;
  }
  const spn = normaliseSpn(raw);
  if (!spn.ok) {
    log.debug('Leaving dropPreviousServiceKeys(). Not an SPN.');
    return refusal('STS-ADMIN-0603', spn.error);
  }
  if (!directory) {
    log.debug('Leaving dropPreviousServiceKeys(). No directory.');
    return refusal('STS-ADMIN-0609', 'There is no directory in this process.');
  }
  const result = dropPrevious('service', spn.identifier,
    directory.readService(spn.identifier), context,
    function (keysValue, infoValue) {
      return directory.writeService(spn.identifier, keysValue, infoValue);
    });
  if (result.ok) {
    result.spn = spn.spn;
  }
  log.debug('Leaving dropPreviousServiceKeys(). ok=' + result.ok);
  return result;
}

// ---------------------------------------------------------------------------
// WHAT IS HELD, WITHOUT A KEY IN IT — for `/admin/kerberos/principals` and its
// operation. Built from the PUBLIC info attributes only; nothing is opened.
// ---------------------------------------------------------------------------
function listPeople() {
  log.debug('Entering listPeople().');
  if (!directory) {
    log.debug('Leaving listPeople(). No directory.');
    return [];
  }
  const nowMs = Date.now();
  const rows = directory.personKeyInfos().map(function (one) {
    const info = parseInfo(one.info) || {};
    return {
      // THE PREVIOUS VERSIONS STILL ACCEPTED for tickets issued under them —
      // kvno, enctypes and expiry, from the public info — inside both bounds as
      // they stand NOW, so a shortened lifetime shows at once.
      retained: retainedRows(info.retained, nowMs),
      username: one.username,
      principal: one.username + '@' + principals.REALM,
      kvno: info.kvno == null ? null : Number(info.kvno),
      etypes: (info.etypes || []).map(function (etype) {
        return { etype: Number(etype), name: kcrypto.etypeName(Number(etype)) };
      }),
      derivedAt: info.derivedAt || '',
      derivedOn: info.event || '',
      sealed: !!info.sealed,
      // Whether the keys match the password the entry holds NOW. From the
      // public stamp, which is a hint for this page and nothing more — the KDC
      // judges the stamp inside the seal.
      current: !!one.passwordHash && info.stamp === stampOf(one.passwordHash)
    };
  });
  rows.sort(function (a, b) { return a.username.localeCompare(b.username); });
  log.debug('Leaving listPeople(). ' + rows.length + ' person(s).');
  return rows;
}

function listServices() {
  log.debug('Entering listServices().');
  if (!directory) {
    log.debug('Leaving listServices(). No directory.');
    return [];
  }
  const nowMs = Date.now();
  const rows = directory.serviceKeyInfos().map(function (one) {
    const info = parseInfo(one.info) || {};
    const principal = String(one.identifier);
    return {
      retained: retainedRows(info.retained, nowMs),
      principal: principal,
      spn: principal.replace(/@[^@]*$/, ''),
      kvno: info.kvno == null ? null : Number(info.kvno),
      etypes: (info.etypes || []).map(function (etype) {
        return { etype: Number(etype), name: kcrypto.etypeName(Number(etype)) };
      }),
      createdAt: info.createdAt || '',
      rotatedAt: info.rotatedAt || '',
      sealed: !!info.sealed,
      held: !!one.hasKeys
    };
  });
  rows.sort(function (a, b) { return a.principal.localeCompare(b.principal); });
  log.debug('Leaving listServices(). ' + rows.length +
            ' service principal(s).');
  return rows;
}

// Replace the value of a withheld attribute for display. `ldap_server.js`
// calls it with the LOWER-CASED names the store uses.
function withheldValues(attribute, values) {
  log.debug("Entering withheldValues().");
  const lower = String(attribute || '').toLowerCase();
  if (!WITHHELD_ATTRIBUTES.some(function (one) {
    return one.toLowerCase() === lower;
  })) {
    log.debug("Leaving withheldValues().");
    return values;
  }
  log.debug("Leaving withheldValues().");
  return (values || []).map(function (value) {
    return '(withheld: Kerberos key material, ' + String(value || '').length +
           ' characters, never shown)';
  });
}

// ---------------------------------------------------------------------------
// THE TWO SLOTS THIS FILE FILLS, AT REQUIRE TIME.
// ---------------------------------------------------------------------------
if (typeof credentials.setPasswordObserver === 'function') {
  credentials.setPasswordObserver(observePassword);
} else {
  log.warn('krb5-keys: common/credentials.js offers no ' +
           'setPasswordObserver(), so no person will get Kerberos keys from ' +
           'a password. That is the older credential store and is not an ' +
           'error.');
}
if (typeof principals.setKeySource === 'function') {
  principals.setKeySource({ personKeys: personKeys, serviceKeys: serviceKeys });
} else {
  log.warn('krb5-keys: kerberos/krb5_principals.js offers no setKeySource(), ' +
           'so stored Kerberos keys are never read. That is the older ' +
           'principal database and is not an error.');
}

module.exports = {
  SEAL_LABEL: SEAL_LABEL,
  PERSON_KEYS_ATTRIBUTE: PERSON_KEYS_ATTRIBUTE,
  PERSON_INFO_ATTRIBUTE: PERSON_INFO_ATTRIBUTE,
  SERVICE_KEYS_ATTRIBUTE: SERVICE_KEYS_ATTRIBUTE,
  SERVICE_INFO_ATTRIBUTE: SERVICE_INFO_ATTRIBUTE,
  ATTRIBUTES: [PERSON_KEYS_ATTRIBUTE, PERSON_INFO_ATTRIBUTE],
  WITHHELD_ATTRIBUTES: WITHHELD_ATTRIBUTES,
  setDirectory: setDirectory,
  installed: installed,
  currentDirectory: currentDirectory,
  productKdc: productKdc,
  personKeysEnabled: personKeysEnabled,
  stampOf: stampOf,
  deriveKey: deriveKey,
  personKeys: personKeys,
  serviceKeys: serviceKeys,
  observePassword: observePassword,
  idle: idle,
  normaliseSpn: normaliseSpn,
  createServicePrincipal: createServicePrincipal,
  rotateServicePrincipal: rotateServicePrincipal,
  deleteServicePrincipal: deleteServicePrincipal,
  clearPersonKeys: clearPersonKeys,
  dropPreviousPersonKeys: dropPreviousPersonKeys,
  dropPreviousServiceKeys: dropPreviousServiceKeys,
  retainedVersionsLimit: retainedVersionsLimit,
  retainedTtlSeconds: retainedTtlSeconds,
  listPeople: listPeople,
  listServices: listServices,
  withheldValues: withheldValues
};
