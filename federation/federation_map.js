'use strict';
//
// File: federation_map.js
//
// ===========================================================================
// WHAT A FOREIGN IDENTITY PROVIDER SAID, TURNED INTO A DIRECTORY ENTRY.
//
// A federated sign-in arrives as a BAG OF NAMED VALUES and nothing else: an
// `<AttributeStatement>` full of `<saml:Attribute>` elements, or the claims of
// an ID Token, or a UserInfo response. Every one of those names belongs to
// somebody else's vocabulary. This module is the one place that decides what
// each of them becomes on an entry under `ou=users`, and it is a module of its
// own rather than fifty lines inside `federation_sp.js` for one reason: the
// FIVE PROTOCOLS PRODUCE ONE BAG, so the mapping has to be written once or it
// will be written five times and disagree four ways.
//
// ---------------------------------------------------------------------------
// THE OIDC HALF IS NOT WRITTEN HERE. IT IS DERIVED.
//
// `../oid4vc/vc_claims.js`'s `VC_ATTRIBUTES` already carries, for every LDAP
// attribute this service knows how to put on a person, the OpenID Connect
// claim name it corresponds to — because the credential issuer needed exactly
// that mapping in the other direction. Writing a second table here would be
// writing the same twenty-five pairs again, and the copy would be the one
// nobody updated when a row was added.
//
// So the OIDC direction is INVERTED from that catalogue at require time, and
// the only thing this file adds for OIDC is the handful of claims that are not
// attributes about a person at all (`sub`, `preferred_username`) and the
// spellings that are not in anybody's specification but are in half the
// deployments (`firstName`, `lastName`, `emailAddress`).
//
// The SAML and WS-Federation halves ARE written here, and they have to be:
// nothing else in this repository has ever had to READ a `urn:oid:` attribute
// name or one of AD FS's claim URIs. This service EMITS attributes under names
// its own console chose; a partner emits them under names its own product
// chose, and the two vocabularies only overlap by accident.
//
// ---------------------------------------------------------------------------
// THREE LAYERS, AND THE ORDER IS THE POINT.
//
//   1. THE RELATIONSHIP'S OWN `fedAttributeMap`. What an operator wrote down
//      for this partner. It wins over everything, because it is the only layer
//      that is a statement about THIS partner rather than about a protocol in
//      general.
//   2. THE DEFAULT TABLE BELOW. The names everybody uses.
//   3. NOTHING. An incoming name that matches neither is NOT invented into an
//      attribute — it is recorded as unmapped and reported, on the relationship
//      page and in the sign-in log.
//
// **Layer 3 is a decision and it is the one most likely to be undone.** The
// tempting alternative is to write an unrecognised claim onto the entry under
// its own name, which would make the feature look better on the first run: a
// partner sending `department_code` would produce an entry carrying
// `department_code`. It is refused because THIS DIRECTORY HAS NO SCHEMA — an
// attribute nobody defined is accepted silently everywhere here — so nothing
// downstream would ever report that the name was wrong. `/admin/federation`
// listing them as unmapped is what turns a partner's fifteenth claim into a
// line somebody can act on, and mapping it is one form field away.
//
// ---------------------------------------------------------------------------
// THE USERNAME IS THE ONE MAPPING THAT CANNOT BE GOT WRONG QUIETLY.
//
// Everything else on the entry is decoration; the username decides WHICH ENTRY,
// and getting it wrong means either a second entry for somebody who already has
// one or — far worse — a foreign partner's `alice` landing on the local
// `alice`. That second case is not a bug to be fixed later, it is the whole
// question of whether federated identities share a namespace with local ones,
// and this service answers it with `federation.usernamePrefix`: OFF by default
// because a mock exists to be pointed at things and a prefixed name makes every
// downstream assertion look unfamiliar, ON for anybody who wants the two kept
// apart. Either way the answer is one setting read in one function, and both
// the log line and the relationship page say which happened.
// ===========================================================================

const config = require('./../common/config');
const { log } = require('./../common/helpers');
const vcClaims = require('./../oid4vc/vc_claims');

// ---------------------------------------------------------------------------
// LAYER 2, PART ONE: the OIDC claims, inverted from the credential catalogue.
//
// `VC_ATTRIBUTES` rows carry `claim` as an ARRAY, because one LDAP attribute
// can correspond to several claim names and to a member of the OIDC `address`
// object. A row whose first member is `address` is the compound one — `street`
// is `address.street_address` rather than a claim called `address` — and the
// second member is the name to match on. That shape is read here rather than
// reimplemented: getting it wrong would map every address component onto
// whichever attribute happened to be last.
// ---------------------------------------------------------------------------
const DEFAULT_MAP = [];
const seenIncoming = new Set();

function addDefault(incoming, ldap, where) {
  const key = String(incoming).toLowerCase();
  // FIRST WINS. The catalogue is walked before the hand-written rows below it,
  // so a name in both keeps the catalogue's attribute — which is the one the
  // rest of this service already uses for it.
  if (seenIncoming.has(key)) return;
  seenIncoming.add(key);
  DEFAULT_MAP.push({ incoming: String(incoming), ldap: String(ldap), where: where });
}

vcClaims.VC_ATTRIBUTES.forEach(function (row) {
  const claims = Array.isArray(row.claim) ? row.claim : [row.claim];
  if (!claims.length) return;
  if (claims[0] === 'address') {
    // The compound one. A partner sending a flat `street_address` is the
    // ordinary case and is what is matched; one sending the whole `address`
    // object is handled by flatten() below, which turns it into the same flat
    // names before anything gets here.
    if (claims[1]) addDefault(claims[1], row.ldap, 'OpenID Connect Core 1.0 address claim');
    return;
  }
  claims.forEach(function (claim) {
    addDefault(claim, row.ldap, 'OpenID Connect Core 1.0 / ' + (row.schema || 'the credential catalogue'));
  });
});

// LAYER 2, PART TWO: the spellings that are in no specification and in half the
// deployments. Every one of these has been seen in the wild; none is guessed.
[
  ['firstName', 'givenName'], ['first_name', 'givenName'], ['fname', 'givenName'],
  ['lastName', 'sn'], ['last_name', 'sn'], ['surname', 'sn'], ['lname', 'sn'],
  ['emailAddress', 'mail'], ['email_address', 'mail'], ['Email', 'mail'],
  ['fullName', 'cn'], ['full_name', 'cn'], ['displayname', 'displayName'],
  ['username', 'uid'], ['user_name', 'uid'], ['login', 'uid'], ['userid', 'uid'],
  ['phone', 'telephoneNumber'], ['phoneNumber', 'telephoneNumber'],
  ['mobilePhone', 'mobile'], ['jobTitle', 'title'], ['job_title', 'title'],
  ['company', 'o'], ['organization', 'o'], ['department', 'departmentNumber'],
  ['country', 'c'], ['city', 'l'], ['state', 'st'], ['zip', 'postalCode'],
  ['zipcode', 'postalCode'], ['postcode', 'postalCode']
].forEach(function (pair) {
  addDefault(pair[0], pair[1], 'a common non-standard spelling');
});

// LAYER 2, PART THREE: the SAML `urn:oid:` names.
//
// This is `urn:oasis:names:tc:SAML:2.0:attrname-format:uri`, which is what
// Shibboleth, SimpleSAMLphp and most European federations emit, and the OIDs
// are X.500's — so an attribute name here is the SAME NAME as the LDAP
// attribute, said in the other of the two ways a directory says it. Which is
// why this table is a translation rather than a mapping and why every row of it
// can be checked against RFC 4519 rather than against somebody's product.
[
  ['urn:oid:2.5.4.3', 'cn', 'RFC 4519 2.3 commonName'],
  ['urn:oid:2.5.4.4', 'sn', 'RFC 4519 2.32 surname'],
  ['urn:oid:2.5.4.42', 'givenName', 'RFC 4519 2.6'],
  ['urn:oid:2.5.4.6', 'c', 'RFC 4519 2.2 countryName'],
  ['urn:oid:2.5.4.7', 'l', 'RFC 4519 2.16 localityName'],
  ['urn:oid:2.5.4.8', 'st', 'RFC 4519 2.33 stateOrProvinceName'],
  ['urn:oid:2.5.4.9', 'street', 'RFC 4519 2.34'],
  ['urn:oid:2.5.4.10', 'o', 'RFC 4519 2.19 organizationName'],
  ['urn:oid:2.5.4.11', 'ou', 'RFC 4519 2.20 organizationalUnitName'],
  ['urn:oid:2.5.4.12', 'title', 'RFC 4519 2.38'],
  ['urn:oid:2.5.4.16', 'postalAddress', 'RFC 4519 2.23'],
  ['urn:oid:2.5.4.17', 'postalCode', 'RFC 4519 2.24'],
  ['urn:oid:2.5.4.20', 'telephoneNumber', 'RFC 4519 2.35'],
  ['urn:oid:0.9.2342.19200300.100.1.1', 'uid', 'RFC 4519 2.39 userId'],
  ['urn:oid:0.9.2342.19200300.100.1.3', 'mail', 'RFC 4524 2.16'],
  ['urn:oid:2.16.840.1.113730.3.1.241', 'displayName', 'RFC 2798 2.3'],
  ['urn:oid:2.16.840.1.113730.3.1.39', 'preferredLanguage', 'RFC 2798 2.7'],
  ['urn:oid:2.16.840.1.113730.3.1.2', 'departmentNumber', 'RFC 2798 2.4'],
  ['urn:oid:2.16.840.1.113730.3.1.3', 'employeeNumber', 'RFC 2798 2.5'],
  ['urn:oid:2.16.840.1.113730.3.1.4', 'employeeType', 'RFC 2798 2.6'],
  ['urn:oid:1.3.6.1.4.1.250.1.57', 'labeledURI', 'RFC 2079'],
  // eduPerson and SCHAC. A research federation sends these and nothing else,
  // and eduPersonPrincipalName is its USERNAME rather than one of its
  // attributes — which is why the note says so: somebody federating with an
  // InCommon or GEANT partner sets fedUsernameSource to this name.
  ['urn:oid:1.3.6.1.4.1.5923.1.1.1.6', 'uid',
   'eduPerson 2020-01 eduPersonPrincipalName — usually the USERNAME'],
  ['urn:oid:1.3.6.1.4.1.5923.1.1.1.1', 'employeeType', 'eduPerson eduPersonAffiliation'],
  ['urn:oid:1.3.6.1.4.1.25178.1.2.3', 'schacDateOfBirth', 'SCHAC 1.5.0'],
  ['urn:oid:1.3.6.1.4.1.25178.1.2.5', 'schacCountryOfCitizenship', 'SCHAC 1.5.0']
].forEach(function (row) {
  addDefault(row[0], row[1], row[2]);
});

// LAYER 2, PART FOUR: the WS-Federation / AD FS claim URIs.
//
// `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/…` is what AD FS, and
// therefore most of the WS-Federation deployments anybody will point this
// service at, puts in a SAML 1.1 assertion. `saml11.js` already EMITS several
// of these; this is the same list read in the other direction, and the two are
// deliberately not shared — that module's list is what this service asserts and
// this one is what it will accept, and they are allowed to differ.
const WSFED_CLAIMS = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/';
const MS_CLAIMS = 'http://schemas.microsoft.com/ws/2008/06/identity/claims/';
[
  [WSFED_CLAIMS + 'emailaddress', 'mail'],
  [WSFED_CLAIMS + 'givenname', 'givenName'],
  [WSFED_CLAIMS + 'surname', 'sn'],
  [WSFED_CLAIMS + 'name', 'cn'],
  [WSFED_CLAIMS + 'upn', 'uid'],
  [WSFED_CLAIMS + 'country', 'c'],
  [WSFED_CLAIMS + 'locality', 'l'],
  [WSFED_CLAIMS + 'stateorprovince', 'st'],
  [WSFED_CLAIMS + 'postalcode', 'postalCode'],
  [WSFED_CLAIMS + 'streetaddress', 'street'],
  [WSFED_CLAIMS + 'homephone', 'telephoneNumber'],
  [WSFED_CLAIMS + 'otherphone', 'telephoneNumber'],
  [WSFED_CLAIMS + 'mobilephone', 'mobile'],
  [WSFED_CLAIMS + 'dateofbirth', 'schacDateOfBirth'],
  [WSFED_CLAIMS + 'webpage', 'labeledURI'],
  [MS_CLAIMS + 'role', 'employeeType']
].forEach(function (pair) {
  addDefault(pair[0], pair[1], 'WS-Federation / AD FS claim URI');
});

const DEFAULT_BY_INCOMING = new Map();
DEFAULT_MAP.forEach(function (row) {
  DEFAULT_BY_INCOMING.set(row.incoming.toLowerCase(), row);
});

log.debug('federation_map: ' + DEFAULT_MAP.length + ' default mappings, ' +
          vcClaims.VC_ATTRIBUTES.length + ' of them derived from the credential catalogue.');

// ---------------------------------------------------------------------------
// A RELATIONSHIP'S OWN MAP, parsed from `fedAttributeMap`.
//
// One value per mapping, written `<incoming>=<LDAP attribute>`. The FIRST `=`
// splits it, and the rest of the value is the attribute name — which matters,
// because an incoming name can be a URL and a URL can hold an `=`. Splitting on
// the last one, or on all of them, produces a mapping that works for every
// short name and silently fails for exactly the WS-Federation claim URIs this
// feature exists to handle.
// ---------------------------------------------------------------------------
function relationshipMap(record) {
  log.debug('Entering relationshipMap().');
  const map = new Map();
  ((record && record.fedAttributeMap) || []).forEach(function (value) {
    const text = String(value);
    const at = text.indexOf('=');
    if (at <= 0) {
      log.warn('federation: "' + text + '" is not a mapping on ' +
               (record.fedId || '?') + '. A mapping is <incoming name>=<LDAP attribute>, ' +
               'split at the FIRST equals sign. It was ignored.');
      return;
    }
    const incoming = text.slice(0, at).trim();
    const ldap = text.slice(at + 1).trim();
    if (!incoming || !ldap) return;
    map.set(incoming.toLowerCase(), { incoming: incoming, ldap: ldap, where: 'this relationship' });
  });
  log.debug('Leaving relationshipMap(). ' + map.size + ' mapping(s) of its own.');
  return map;
}

// Which LDAP attribute an incoming name becomes, and where that was decided.
// Null for a name nothing knows, which is layer 3 — see the header.
function resolve(name, own) {
  const key = String(name || '').toLowerCase();
  if (own.has(key)) return own.get(key);
  if (DEFAULT_BY_INCOMING.has(key)) return DEFAULT_BY_INCOMING.get(key);
  return null;
}

// ---------------------------------------------------------------------------
// FLATTENING WHAT ARRIVED.
//
// An ID Token is JSON and can nest; a SAML AttributeStatement cannot. The one
// nested shape that matters is OpenID Connect's `address`, whose members are
// claims in their own right — so it is flattened into `street_address`,
// `locality`, `region`, `postal_code`, `country` and `formatted`, which is
// exactly the set the catalogue's compound rows match on.
//
// Everything else that is an object is turned into its JSON text and mapped as
// one value, rather than being dropped or walked. A partner sending a nested
// object under a name somebody mapped has said something; showing it as JSON on
// the entry is a fact about what arrived, and walking it would be inventing
// attribute names that no partner sent.
// ---------------------------------------------------------------------------
function flatten(bag) {
  log.debug('Entering flatten().');
  const out = {};
  const put = function (name, value) {
    if (value == null) return;
    const key = String(name);
    const values = Array.isArray(value) ? value : [value];
    const flat = values.map(function (one) {
      if (one == null) return '';
      if (typeof one === 'object') {
        try {
          return JSON.stringify(one);
        } catch (e) {
          // A cycle, which JSON cannot represent. It cannot come off the wire —
          // JSON.parse never produces one — so this can only be a caller's own
          // object, and String() of it is more use than throwing here.
          return String(one);
        }
      }
      return String(one);
    }).filter(function (one) { return one !== ''; });
    if (!flat.length) return;
    out[key] = (out[key] || []).concat(flat);
  };
  Object.keys(bag || {}).forEach(function (name) {
    const value = bag[name];
    if (name === 'address' && value && typeof value === 'object' && !Array.isArray(value)) {
      Object.keys(value).forEach(function (member) { put(member, value[member]); });
      return;
    }
    put(name, value);
  });
  log.debug('Leaving flatten(). ' + Object.keys(out).length + ' name(s).');
  return out;
}

// ---------------------------------------------------------------------------
// THE USERNAME.
//
// `fedUsernameSource` names the incoming value to use; empty means the subject
// the protocol itself carried — a SAML NameID, or `sub`. The prefix is applied
// LAST and to whatever was chosen, so that turning it on cannot change WHICH
// value was picked, only what it is called here.
// ---------------------------------------------------------------------------
function usernameFor(record, flat, subject) {
  log.debug('Entering usernameFor(). source=' +
            ((record && record.fedUsernameSource) || '(the subject)'));
  const source = String((record && record.fedUsernameSource) || '').trim();
  let raw = '';
  let from = '';
  if (source) {
    const values = flat[source] ||
      flat[Object.keys(flat).filter(function (k) {
        return k.toLowerCase() === source.toLowerCase();
      })[0]];
    raw = (values && values[0]) || '';
    from = source;
    if (!raw) {
      // Reported rather than silently falling back, because a partner that
      // stopped sending the attribute the username comes from would otherwise
      // start creating a second set of entries named by NameID, and the two
      // sets would look like two populations rather than one bug.
      log.warn('federation: ' + (record.fedId || '?') + ' is configured to take the ' +
               'username from "' + source + '", which this assertion did not carry. ' +
               'Falling back to the subject, which means this sign-in may land on a ' +
               'different entry from the last one.');
      raw = String(subject || '');
      from = 'the subject (' + source + ' was not sent)';
    }
  } else {
    raw = String(subject || '');
    from = 'the subject';
  }
  raw = raw.trim();
  const prefix = String(config.value('federation.usernamePrefix') || '');
  const username = prefix && raw ? prefix + raw : raw;
  log.debug('Leaving usernameFor(). username=' + username + ' from ' + from);
  return { username: username, raw: raw, from: from, prefixed: !!(prefix && raw) };
}

// ---------------------------------------------------------------------------
// THE WHOLE MAPPING, for one federated sign-in.
//
// Returns everything a caller needs to both ACT and EXPLAIN, because both the
// directory write and the relationship page read this one result and a second
// pass over the bag would be a second answer:
//
//   username     what to file them under
//   attributes   { ldapName: [values] }, ready for the directory
//   mapped       [{ incoming, ldap, where, values }] — what happened, in order
//   unmapped     [{ incoming, values }] — layer 3, the useful half
//
// TWO INCOMING NAMES CAN MAP TO ONE ATTRIBUTE and the values are CONCATENATED
// rather than one overwriting the other. That is the honest answer for a
// directory attribute, which is multi-valued by nature — `telephoneNumber` from
// both `homephone` and `otherphone` is two telephone numbers, and picking one
// would be picking one.
// ---------------------------------------------------------------------------
function mapIncoming(record, bag, subject) {
  log.debug('Entering mapIncoming(). id=' + ((record && record.fedId) || '?'));
  const flat = flatten(bag);
  const own = relationshipMap(record);
  const attributes = {};
  const mapped = [];
  const unmapped = [];
  Object.keys(flat).forEach(function (name) {
    const values = flat[name];
    const row = resolve(name, own);
    if (!row) {
      unmapped.push({ incoming: name, values: values });
      return;
    }
    attributes[row.ldap] = (attributes[row.ldap] || []).concat(values);
    mapped.push({ incoming: name, ldap: row.ldap, where: row.where, values: values });
  });
  const who = usernameFor(record, flat, subject);
  if (unmapped.length) {
    // At INFO rather than DEBUG: this is the line somebody reads when a
    // federated entry came out emptier than they expected, and it names every
    // attribute the partner sent that this service threw away.
    log.info('federation: ' + ((record && record.fedId) || '?') + ' sent ' +
             unmapped.length + ' attribute(s) nothing maps: ' +
             unmapped.map(function (one) { return one.incoming; }).join(', ') +
             '. They are NOT written to the directory — add a mapping on the ' +
             'relationship to keep one.');
  }
  log.debug('Leaving mapIncoming(). ' + mapped.length + ' mapped, ' +
            unmapped.length + ' unmapped, username=' + who.username);
  return {
    username: who.username, usernameRaw: who.raw, usernameFrom: who.from,
    usernamePrefixed: who.prefixed,
    attributes: attributes, mapped: mapped, unmapped: unmapped, flat: flat
  };
}

module.exports = {
  DEFAULT_MAP: DEFAULT_MAP,
  relationshipMap: relationshipMap,
  flatten: flatten,
  usernameFor: usernameFor,
  mapIncoming: mapIncoming
};
