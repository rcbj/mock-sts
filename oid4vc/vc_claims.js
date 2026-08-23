'use strict';
//
// File: vc_claims.js
//
// ---------------------------------------------------------------------------
// WHAT AN ISSUED CREDENTIAL SAYS ABOUT A PERSON, and where each of those facts
// comes from.
//
// Until this file existed, the answer was seven lines in vc_issuer.js:
// given_name, family_name, email, birthdate, nationality and an address, four of
// them constants written into the source. That is enough to demonstrate one
// credential and not enough to exercise a wallet — the interesting questions a
// holder asks are "what happens when the credential carries fourteen claims",
// "what does the verifier do with one it has never seen" and "does the issuer
// metadata really describe what arrives", and none of them can be asked without
// changing the claim list.
//
// So the claim list is CONFIGURATION, /admin/vc is the page that sets it, and
// this module is where it lives. It is a LIBRARY in the sense dpop.js and
// admin_stats.js are: it registers no route, so its position in the require
// order does not matter, and it requires only helpers.js (plus node's crypto) so
// it cannot join a cycle. That matters more here than usual, because THREE
// modules read it and they sit at three different points of the require order —
// vc_issuer.js (early), admin.js (late) and ldap_server.js (last).
//
// ---------------------------------------------------------------------------
// THE CATALOGUE IS OF LDAP ATTRIBUTES, NOT OF CLAIMS, and that is the decision
// everything else here follows from.
//
// A claim name is this service's own invention until something backs it. An
// attribute type is a name a directory already knows, and this service HAS a
// directory — ldap_server.js seeds an entry for everybody who authenticates
// through any of the sixteen families. So the page offers what a person's entry
// can hold, each row saying which claim it becomes, and the value in the
// credential is the value in the directory. Two things fall out of that which
// were the point of doing it this way:
//
//   * the same fact is visible in two protocols. `mail` on uid=alice,ou=users is
//     what a wallet gets as `email`, so an LDAP client and an OID4VCI wallet can
//     be pointed at one service and shown the same person.
//   * "populate the fields" has an obvious meaning. A selected attribute that an
//     entry does not carry gets generated at the entry, once, and everything
//     downstream reads it from there.
//
// Three rows are NOT RFC 4519/4524/2798 and say so on the page: birthdate and
// nationality have no standard attribute type in those documents, so the SCHAC
// schema's names are borrowed (urn:mace:terena.org:schac), and they are borrowed
// rather than invented so that somebody who exports this directory into a real
// one has a name that already means what they want.
//
// ---------------------------------------------------------------------------
// THE GENERATED VALUES ARE GARBAGE, AND THEY ARE DETERMINISTIC.
//
// Garbage because nothing here is a real person and a mock that invented
// plausible-looking real data would eventually have one of those values believed.
// Deterministic — seeded from the username — because the alternative costs more
// than it looks: a random birthdate per call means the credential issued at
// 10:00 and the credential issued at 10:01 describe two different people, the
// directory entry disagrees with both, and a wallet's "did this change" check
// fires on something that is not the thing being tested. So alice is the same
// invented person for the life of the process AND across restarts, which also
// means the directory can be off entirely and the claims still hold still.
//
// One persona per user, not one value per field, for the same reason: a
// given_name of "Ingrid" beside an email of "kwame.osei@..." is two facts that
// contradict each other, and a reader who notices spends the next ten minutes
// deciding whether it is a bug here.
// ---------------------------------------------------------------------------

const crypto = require('crypto');
const { log } = require('../common/helpers');
// For ONE function: identityKeyOf(), which turns every spelling of a person into
// the one local name this service files them under. It is the same normalisation
// ldap_server.js uses to build `uid=<name>,ou=users` and that /admin/users files a
// row under, and using anything else here would be the bug CLAUDE.md's "one row is
// one local name" rule exists to prevent — see personaFor() for what it looked
// like: an access token whose sub is `urn:sts-mock:user:alice` inventing a second
// alice, with her directory entry sitting right there unread.
//
// admin_stats.js is a library that requires only helpers.js, so this is no cycle
// and no ordering constraint. It is also already required by vc_issuer.js and
// app.js, so nothing is loaded here that was not loaded anyway.
const stats = require('../common/admin_stats');

// ---------------------------------------------------------------------------
// THE CATALOGUE.
//
// Per row:
//   ldap       the attribute type, spelled the way its schema document spells it
//   claim      the claim path it becomes — ['address','locality'] is nested
//   label      what the page and the credential's `display` call it
//   schema     where the attribute type is defined; shown on the page, because
//              the three non-standard ones have to be distinguishable from the
//              twenty-one standard ones at a glance
//   from       which member of the generated persona fills it
//   toClaim    the LDAP value -> claim value conversion, where the two differ.
//              Only two do, and both differ in punctuation only: a generalized
//              date is YYYYMMDD where a claim is YYYY-MM-DD (OIDC Core 5.1 says
//              ISO 8601 / RFC 3339), and a postalAddress separates lines with
//              '$' (RFC 4517 3.3.28) where the OIDC `formatted` member uses a
//              newline. Absent means the value passes through unchanged.
//   ldpTerm    the term to use in an ldp_vc credential, or null. See LDP below —
//              this is the one place where a claim cannot simply be added.
//   byDefault  whether it is selected on a fresh start. The ten that are
//              reproduce exactly the six claims this issuer carried before this
//              page existed.
//
// `claim` values are strings throughout. A directory attribute is a string (this
// store holds no syntaxes), and a credential whose `birthdate` was sometimes a
// number would be a different interoperability problem than the one this service
// is for.
// ---------------------------------------------------------------------------
const VC_ATTRIBUTES = [
  { ldap: 'givenName', claim: ['given_name'], label: 'Given name',
    schema: 'RFC 4519 2.6', from: 'given', ldpTerm: 'given_name', byDefault: true },
  { ldap: 'sn', claim: ['family_name'], label: 'Family name',
    schema: 'RFC 4519 2.32', from: 'family', ldpTerm: 'family_name', byDefault: true },
  { ldap: 'mail', claim: ['email'], label: 'Email address',
    schema: 'RFC 4524 2.16', from: 'email', ldpTerm: 'email', byDefault: true },
  { ldap: 'schacDateOfBirth', claim: ['birthdate'], label: 'Date of birth',
    schema: 'SCHAC 1.5.0 (not RFC 4519)', from: 'birth', ldpTerm: 'birthDate',
    byDefault: true,
    // YYYYMMDD in the directory, YYYY-MM-DD in the credential. SCHAC defines the
    // attribute with the generalized-time-like syntax; OIDC Core 5.1 defines
    // `birthdate` as ISO 8601-2004 YYYY-MM-DD. Neither side is being corrected
    // here — they are two documents that spell one date differently.
    toClaim: function (value) {
      const digits = String(value).replace(/[^0-9]/g, '');
      if (digits.length < 8) {
        return String(value);
      }
      return digits.slice(0, 4) + '-' + digits.slice(4, 6) + '-' + digits.slice(6, 8);
    } },
  { ldap: 'schacCountryOfCitizenship', claim: ['nationality'], label: 'Nationality',
    schema: 'SCHAC 1.5.0 (not RFC 4519)', from: 'country', ldpTerm: 'nationality',
    byDefault: true },
  { ldap: 'street', claim: ['address', 'street_address'], label: 'Street address',
    schema: 'RFC 4519 2.34', from: 'street', ldpTerm: 'streetAddress', byDefault: true },
  { ldap: 'l', claim: ['address', 'locality'], label: 'Locality',
    schema: 'RFC 4519 2.16', from: 'locality', ldpTerm: 'locality', byDefault: true },
  { ldap: 'st', claim: ['address', 'region'], label: 'Region',
    schema: 'RFC 4519 2.33', from: 'region', ldpTerm: 'region', byDefault: true },
  { ldap: 'postalCode', claim: ['address', 'postal_code'], label: 'Postal code',
    schema: 'RFC 4519 2.24', from: 'postalCode', ldpTerm: null, byDefault: true },
  { ldap: 'c', claim: ['address', 'country'], label: 'Country',
    schema: 'RFC 4519 2.2', from: 'country', ldpTerm: 'country', byDefault: true },

  // --- not selected on a fresh start ---------------------------------------
  { ldap: 'postalAddress', claim: ['address', 'formatted'], label: 'Formatted address',
    schema: 'RFC 4519 2.23', from: 'formatted', ldpTerm: null, byDefault: false,
    // RFC 4517 3.3.28: the lines of a postal address are separated by '$'. The
    // OIDC `formatted` member is "full mailing address, formatted for display",
    // with newlines. Same address, two punctuations.
    toClaim: function (value) { return String(value).split('$').join('\n'); } },
  { ldap: 'cn', claim: ['name'], label: 'Full name',
    schema: 'RFC 4519 2.3', from: 'display', ldpTerm: null, byDefault: false },
  { ldap: 'displayName', claim: ['nickname'], label: 'Display name',
    schema: 'RFC 2798 2.3', from: 'given', ldpTerm: null, byDefault: false },
  { ldap: 'uid', claim: ['preferred_username'], label: 'User id',
    schema: 'RFC 4519 2.39', from: 'username', ldpTerm: null, byDefault: false },
  { ldap: 'telephoneNumber', claim: ['phone_number'], label: 'Telephone number',
    schema: 'RFC 4519 2.35', from: 'phone', ldpTerm: null, byDefault: false },
  { ldap: 'mobile', claim: ['mobile_phone_number'], label: 'Mobile number',
    schema: 'RFC 4524 2.18', from: 'mobile', ldpTerm: null, byDefault: false },
  { ldap: 'title', claim: ['title'], label: 'Title',
    schema: 'RFC 4519 2.38', from: 'title', ldpTerm: null, byDefault: false },
  { ldap: 'o', claim: ['organization'], label: 'Organization',
    schema: 'RFC 4519 2.19', from: 'organization', ldpTerm: null, byDefault: false },
  { ldap: 'ou', claim: ['organizational_unit'], label: 'Organizational unit',
    schema: 'RFC 4519 2.20', from: 'unit', ldpTerm: null, byDefault: false },
  { ldap: 'departmentNumber', claim: ['department'], label: 'Department',
    schema: 'RFC 2798 2.4', from: 'department', ldpTerm: null, byDefault: false },
  { ldap: 'employeeNumber', claim: ['employee_number'], label: 'Employee number',
    schema: 'RFC 2798 2.6', from: 'employeeNumber', ldpTerm: null, byDefault: false },
  { ldap: 'employeeType', claim: ['employee_type'], label: 'Employee type',
    schema: 'RFC 2798 2.7', from: 'employeeType', ldpTerm: null, byDefault: false },
  { ldap: 'preferredLanguage', claim: ['locale'], label: 'Locale',
    schema: 'RFC 2798 2.10', from: 'locale', ldpTerm: null, byDefault: false },
  { ldap: 'labeledURI', claim: ['website'], label: 'Web page',
    schema: 'RFC 2079 2', from: 'website', ldpTerm: null, byDefault: false },
  { ldap: 'description', claim: ['description'], label: 'Description',
    schema: 'RFC 4519 2.5', from: null, ldpTerm: null, byDefault: false },
  { ldap: 'employeeStatus', claim: ['employee_status'], label: 'Employee status',
    schema: "this service's own (no standard type)", from: 'employeeStatus',
    ldpTerm: null, byDefault: false }
];

// Lower-cased attribute name -> row. The store in ldap_server.js lower-cases
// every attribute name on the way in (@ldapjs/attribute does it, and LDAP
// attribute descriptions are case-insensitive anyway), so every lookup that
// starts from a stored entry has to start from the lower-cased name.
const BY_LDAP = new Map();
VC_ATTRIBUTES.forEach(function (row) {
  BY_LDAP.set(row.ldap.toLowerCase(), row);
});

// What the directory should CALL each of these when it shows them. ldap_server.js
// merges this into its own CANONICAL_NAMES table rather than repeating the
// spellings, because a page showing `schacdateofbirth` where the schema document
// says `schacDateOfBirth` reads as a bug in the page.
const CANONICAL_NAMES = {};
VC_ATTRIBUTES.forEach(function (row) {
  CANONICAL_NAMES[row.ldap.toLowerCase()] = row.ldap;
});

// ---------------------------------------------------------------------------
// LDP_VC IS THE ONE FORMAT WHERE A CLAIM CANNOT SIMPLY BE ADDED.
//
// The other two formats are JOSE-secured: a claim is a member of a JSON object
// and any name works. An ldp_vc credential is JSON-LD, signed over CANONICALIZED
// RDF, and bbs2023.js canonicalizes with `safe: true` — so a term the vendored
// context does not define is not dropped quietly, it THROWS, and the throw
// arrives at issuance time inside a cryptosuite rather than on this page.
//
// The vendored context (contexts/idptools_identity_v1.json) is signed over, so
// it cannot be edited to add a term without invalidating every credential issued
// against the old one — which is exactly why it is vendored rather than fetched.
// So each row names the term to use in that format or null, and vc_issuer.js
// filters the subject through the context it actually loaded. A selected
// attribute with no term is simply absent from an ldp_vc credential; the page
// says which those are, because "the same configuration produces different
// credentials in different formats" is a surprise if it is discovered rather
// than stated.
// ---------------------------------------------------------------------------
function ldpTermFor(row) {
  return row.ldpTerm || '';
}

// ---------------------------------------------------------------------------
// The selection.
//
// A Set of lower-cased attribute names. Held in memory like every other piece of
// configuration in this service — the signing key is regenerated on every start,
// so a selection that outlived it would describe credentials nothing can verify.
// ---------------------------------------------------------------------------
// Canonically spelled, because this list is published — /admin/vc answers it in
// its JSON — and a page reporting `schacdateofbirth` as the default beside
// `schacDateOfBirth` as the selection would read as two different attributes.
// The Set below holds the lower-cased form, which is what every lookup uses.
const DEFAULT_SELECTION = VC_ATTRIBUTES.filter(function (row) { return row.byDefault; })
                                       .map(function (row) { return row.ldap; });

let selection = new Set(DEFAULT_SELECTION.map(function (name) { return name.toLowerCase(); }));

// The selected rows, in CATALOGUE order rather than in the order they were
// chosen. The order reaches the credential (it is the order of the Disclosures
// and of the metadata's claims array), and a claims list that reordered itself
// because somebody unticked and reticked a box would look like a different
// credential to anything diffing them.
function selectedRows() {
  return VC_ATTRIBUTES.filter(function (row) {
    return selection.has(row.ldap.toLowerCase());
  });
}

function isSelected(ldapName) {
  return selection.has(String(ldapName || '').toLowerCase());
}

function selectedNames() {
  return selectedRows().map(function (row) { return row.ldap; });
}

// Install a whole selection at once. Returns the errors rather than throwing,
// because the caller is a form handler that has to redisplay them — the same
// contract admin_stats.setClaimSet() has.
//
// An unknown attribute is an ERROR and not a silent omission: the page offers a
// fixed list, so an unknown name means either a hand-written request (which
// deserves an answer) or a rename here that left a caller behind. Both are worth
// a message.
function setSelection(names) {
  log.debug("Entering setSelection(). " + (names || []).length + " name(s) offered.");
  const errors = [];
  const wanted = new Set();
  (names || []).forEach(function (name) {
    const key = String(name == null ? '' : name).trim().toLowerCase();
    if (!key) {
      return;
    }
    if (!BY_LDAP.has(key)) {
      errors.push('There is no attribute called "' + name + '" in the catalogue.');
      return;
    }
    wanted.add(key);
  });
  if (errors.length) {
    log.debug("Leaving setSelection(). " + errors.length + " error(s); nothing changed.");
    return { ok: false, errors: errors };
  }
  const before = selection;
  const added = [];
  const removed = [];
  wanted.forEach(function (key) {
    if (!before.has(key)) added.push(BY_LDAP.get(key).ldap);
  });
  before.forEach(function (key) {
    if (!wanted.has(key)) removed.push(BY_LDAP.get(key).ldap);
  });
  selection = wanted;
  log.info('vc: the credential claim set is now ' + (selectedNames().join(', ') || '(empty)') +
           '. Added: ' + (added.join(', ') || 'nothing') + '. Removed: ' +
           (removed.join(', ') || 'nothing') + '.');
  log.debug("Leaving setSelection(). " + wanted.size + " attribute(s) selected.");
  return { ok: true, selected: selectedNames(), added: added, removed: removed };
}

function resetSelection() {
  log.debug("Entering resetSelection().");
  const result = setSelection(DEFAULT_SELECTION);
  log.debug("Leaving resetSelection().");
  return result;
}

// ---------------------------------------------------------------------------
// THE INVENTED PEOPLE.
//
// A seeded PRNG rather than Math.random(), for the reason in the header: one
// username is one invented person, for the life of this process and across
// restarts. The seed is the first four bytes of SHA-256 over the name, which is
// a hash used as a hash and not as a security boundary — there is nothing to
// protect here, and saying so is cheaper than leaving a reader to wonder.
//
// mulberry32, written out rather than taken from a dependency: it is eight lines
// and a dependency whose only job is to be deterministic is a dependency whose
// version bump silently changes every generated value.
// ---------------------------------------------------------------------------
function randomFor(seedText) {
  const digest = crypto.createHash('sha256').update(String(seedText), 'utf8').digest();
  let state = digest.readUInt32LE(0);
  return function () {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

// Deliberately not a real-looking set of names from one place: a mock whose
// invented people were all from one country teaches somebody's test suite that
// names look like that.
const GIVEN_NAMES = ['Ada', 'Kwame', 'Ingrid', 'Hiroshi', 'Rosa', 'Tariq', 'Mei',
                     'Olof', 'Priya', 'Diego', 'Yusuf', 'Freya', 'Nadia', 'Emeka',
                     'Sofia', 'Jonas'];
const FAMILY_NAMES = ['Lovelace', 'Osei', 'Lindqvist', 'Tanaka', 'Marquez', 'Haddad',
                      'Chen', 'Nilsen', 'Raman', 'Duarte', 'Demir', 'Halvorsen',
                      'Farouk', 'Okonkwo', 'Ferrari', 'Weber'];
const STREETS = ['Fictitious Way', 'Placeholder Street', 'Example Avenue', 'Sample Road',
                 'Mock Lane', 'Nowhere Terrace', 'Specimen Close', 'Dummy Boulevard'];
// Locality, region, country and a postal code SHAPE that belongs to that country,
// kept together in one row so that an address cannot be assembled out of parts
// that contradict each other. `postal` is a template: # is a digit, @ a letter.
const PLACES = [
  { locality: 'Springfield', region: 'IL', country: 'US', postal: '#####' },
  { locality: 'Fairview', region: 'OR', country: 'US', postal: '#####' },
  { locality: 'Riverton', region: 'NJ', country: 'US', postal: '#####' },
  { locality: 'Kingsford', region: 'ON', country: 'CA', postal: '@#@ #@#' },
  { locality: 'Eastgate', region: 'Greater Manchester', country: 'GB', postal: '@@# #@@' },
  { locality: 'Nordhavn', region: 'Hovedstaden', country: 'DK', postal: '####' },
  { locality: 'Sudbury', region: 'Victoria', country: 'AU', postal: '####' },
  { locality: 'Westerveld', region: 'Utrecht', country: 'NL', postal: '#### @@' }
];
const TITLES = ['Principal Engineer', 'Support Analyst', 'Directory Administrator',
                'Field Technician', 'Product Manager', 'Security Architect',
                'Staff Researcher', 'Service Desk Lead'];
const DEPARTMENTS = ['0001', '0042', '1120', '3300', '7250', '8800'];
const UNITS = ['Engineering', 'Operations', 'Research', 'Support', 'Security'];
const EMPLOYEE_TYPES = ['Full time', 'Contractor', 'Intern', 'Part time'];
const EMPLOYEE_STATUSES = ['Active', 'On leave', 'Probation'];
const LOCALES = ['en-US', 'en-GB', 'sv-SE', 'ja-JP', 'pt-BR', 'nl-NL'];
// example.com, example.org and example.net are reserved for exactly this by
// RFC 2606, so an invented address cannot be somebody's real mailbox.
const MAIL_DOMAINS = ['example.com', 'example.org', 'example.net'];

function pick(random, list) {
  return list[Math.floor(random() * list.length) % list.length];
}

function digits(random, count) {
  let out = '';
  for (let i = 0; i < count; i++) {
    out += String(Math.floor(random() * 10));
  }
  return out;
}

// A postal code from one of the PLACES templates. '#' is a digit and '@' an
// upper-case letter; everything else is copied. It produces the SHAPE of that
// country's codes and not a code that exists, which is the whole intent.
function postalCode(random, template) {
  const letters = 'ABCDEFGHJKLMNPRSTUVWXYZ';
  return String(template).split('').map(function (ch) {
    if (ch === '#') {
      return String(Math.floor(random() * 10));
    }
    if (ch === '@') {
      return letters.charAt(Math.floor(random() * letters.length));
    }
    return ch;
  }).join('');
}

// One invented person. Every field is derived from the same stream, so they are
// consistent with each other: the email is built from the given and family names
// that are also in the entry, the postal code belongs to the country, and the
// display name is the two names in the order the entry's cn uses.
//
// The username is NOT invented — it is the name the person authenticated as. An
// invented `uid` would disagree with the DN the entry sits at (`uid=<name>`,
// which autoCreateUser() builds from the same string), and two names for one
// object is the one kind of garbage this file must not produce.
function personaFor(name) {
  log.debug("Entering personaFor(). name=" + name);
  // NORMALISED first, and this line is load-bearing. The three spellings of one
  // person reach this module from three directions — `alice` from the directory
  // sweep, `urn:sts-mock:user:alice` from an access token's sub,
  // `alice@EXAMPLE.COM` from a Kerberos-authenticated one — and the seed is the
  // string. Seeding on the raw value invented a different person per spelling and
  // then failed to find the entry any of them had, so a credential for alice
  // asserted a name her own directory entry contradicted. It looked like the
  // directory was not being read at all, which is the wrong thing to go looking at.
  const username = stats.identityKeyOf(name) || 'somebody';
  const random = randomFor(username);
  const given = pick(random, GIVEN_NAMES);
  const family = pick(random, FAMILY_NAMES);
  const place = pick(random, PLACES);
  const street = digits(random, 3) + ' ' + pick(random, STREETS);
  const postal = postalCode(random, place.postal);
  // A four-digit discriminator so that two users who drew the same pair of names
  // do not draw the same mailbox as well. Collisions are otherwise certain: there
  // are 256 name pairs and a mock can easily see more users than that.
  const mailbox = (given + '.' + family).toLowerCase() + '.' + digits(random, 4);
  const persona = {
    username: username,
    given: given,
    family: family,
    display: given + ' ' + family,
    email: mailbox + '@' + pick(random, MAIL_DOMAINS),
    // 1955-01-01 through 2004-12-31 or thereabouts, written the way SCHAC writes
    // it. The day is capped at 28 so that no invented person is born on the 30th
    // of February — a date a strict consumer rejects, which would make this
    // service look broken for a reason that has nothing to do with credentials.
    birth: String(1955 + Math.floor(random() * 50)) +
           String(1 + Math.floor(random() * 12)).padStart(2, '0') +
           String(1 + Math.floor(random() * 28)).padStart(2, '0'),
    country: place.country,
    street: street,
    locality: place.locality,
    region: place.region,
    postalCode: postal,
    formatted: street + '$' + place.locality + '$' + place.region + ' ' + postal + '$' + place.country,
    // +1-555-01xx is the North American fiction range (555-0100 to 555-0199 is
    // reserved for exactly this), so no invented person is given a working line.
    phone: '+1-555-01' + digits(random, 2),
    mobile: '+1-555-01' + digits(random, 2),
    title: pick(random, TITLES),
    organization: 'Example Corporation',
    unit: pick(random, UNITS),
    department: pick(random, DEPARTMENTS),
    employeeNumber: 'E' + digits(random, 6),
    employeeType: pick(random, EMPLOYEE_TYPES),
    employeeStatus: pick(random, EMPLOYEE_STATUSES),
    locale: pick(random, LOCALES),
    website: 'https://www.example.com/~' + username.toLowerCase()
  };
  log.debug("Leaving personaFor(). " + username + " is " + persona.display + ".");
  return persona;
}

// The values the SELECTED attributes would take for this person, keyed by the
// LOWER-CASED attribute name — which is the key the directory's store uses, so
// the caller can compare against an entry without normalising anything.
//
// A row with no `from` produces nothing. There is one: `description`, which this
// service already writes on every entry (it records which protocols that person
// has authenticated through), and inventing a second description would overwrite
// a fact with a fiction.
function generatedFor(name) {
  log.debug("Entering generatedFor(). name=" + name);
  const persona = personaFor(name);
  const out = {};
  selectedRows().forEach(function (row) {
    if (!row.from) {
      return;
    }
    const value = persona[row.from];
    if (value === undefined || value === null || value === '') {
      return;
    }
    out[row.ldap.toLowerCase()] = String(value);
  });
  log.debug("Leaving generatedFor(). " + Object.keys(out).length + " value(s).");
  return out;
}

// ---------------------------------------------------------------------------
// THE DIRECTORY, WHICH THIS MODULE MUST NOT REQUIRE.
//
// ldap_server.js is the LAST module server.js requires, and the reasons are in
// CLAUDE.md rule 6 — requiring it from here would drag its routes into the
// express router ahead of every console route, and /sts-metadata is built by
// walking that router. vc_issuer.js requiring it would be worse still: that is
// module 88 of 142 in the require order.
//
// So the dependency is inverted exactly as admin_stats.js's user observer and
// admin.js's directory reader are: this module offers a slot, and ldap_server.js
// fills it at ITS require time with two functions —
//
//   attributesFor(key)   the lower-cased attributes of that person's entry, or
//                        null when the directory holds nothing for them
//   populate()           fill every existing person's missing selected
//                        attributes, and say what it did
//
// Both are wrapped where they are called. A directory that threw must not be able
// to fail an issuance — the same rule the user observer follows in the other
// direction, and for the same reason: this service's job is to hand a wallet a
// credential, and a store it consults is not allowed to prevent that.
// ---------------------------------------------------------------------------
let directory = null;

function setDirectory(hooks) {
  directory = hooks || null;
  log.debug("A directory was installed; credential claims will now be read from " +
            "entries and populated on them.");
}

function directoryAttributes(name) {
  if (!directory || typeof directory.attributesFor !== 'function') {
    return null;
  }
  try {
    // Normalised for the reason personaFor() gives: the directory files a person
    // under their local name, and an access token's `urn:sts-mock:user:alice`
    // would otherwise look up an entry nothing ever created.
    return directory.attributesFor(stats.identityKeyOf(name)) || null;
  } catch (e) {
    log.error('the directory threw while being read for credential claims and ' +
              'was ignored; the credential is unaffected: ' + e.message);
    return null;
  }
}

// Fill in what the current selection needs, on every person already in the
// directory. Returned rather than logged only, because the page that triggers it
// has to be able to say what happened: "nothing to do" and "the directory is not
// loaded" look identical from the outside and are entirely different answers.
function populateDirectory() {
  log.debug("Entering populateDirectory().");
  if (!directory || typeof directory.populate !== 'function') {
    log.debug("Leaving populateDirectory(). There is no directory loaded.");
    return { ok: false, loaded: false, examined: 0, changed: 0, values: 0,
             errors: ['The embedded LDAP directory is not loaded, so there are no ' +
                      'entries to populate. Nothing else is affected: the claims below ' +
                      'still reach every credential, generated per user.'] };
  }
  try {
    const result = directory.populate() || {};
    log.debug("Leaving populateDirectory(). " + (result.changed || 0) + " entry/entries changed.");
    return { ok: true, loaded: true, examined: result.examined || 0,
             changed: result.changed || 0, values: result.values || 0,
             attributes: result.attributes || [] };
  } catch (e) {
    // Reported rather than thrown: this is called from a form handler and from
    // the moment the selection changes, and neither of those is allowed to fail
    // because a directory did.
    log.error('populating the directory for credential claims threw: ' + e.message);
    log.debug("Leaving populateDirectory(). It threw.");
    return { ok: false, loaded: true, examined: 0, changed: 0, values: 0,
             errors: ['The directory threw while being populated: ' + e.message] };
  }
}

// ---------------------------------------------------------------------------
// THE CLAIMS THEMSELVES.
//
// Three sources, in this order, and the order is the whole of the policy:
//
//   1. the ACCESS TOKEN, where it carries a claim of that name. A token claim is
//      a statement this service already made about the person — it came from the
//      sign-in or from the custom claims page — and a credential that contradicted
//      the token that authorised it would be indefensible.
//   2. the DIRECTORY entry. This is where the generated values live once an entry
//      exists, and it is also where a value somebody set through LDAP lives: an
//      operator who does `ldapmodify` on alice's `mail` expects the next
//      credential to say so, and this is the line that makes that true.
//   3. the GENERATED persona. Reached when the directory is off, when the person
//      has no entry yet, or when the entry does not carry that attribute.
//
// Nothing is ever left absent because a source was missing. A selected claim that
// silently did not arrive would be indistinguishable, at the wallet, from a
// selection that never took effect.
// ---------------------------------------------------------------------------
function setPath(target, path, value) {
  let node = target;
  for (let i = 0; i < path.length - 1; i++) {
    if (!node[path[i]] || typeof node[path[i]] !== 'object') node[path[i]] = {};
    node = node[path[i]];
  }
  node[path[path.length - 1]] = value;
}

// The claim value a row takes, and where it came from. The `source` half is not
// decoration: it is what /admin/vc shows in its preview, and "this came from the
// entry" versus "this was invented just now" is the difference between a
// populated directory and one that silently is not.
function valueFor(row, name, tokenClaims, attributes, persona) {
  const flat = row.claim.join('.');
  // A token claim only counts when it is at the TOP level and scalar. The nested
  // ones (address.locality) would need the token to carry an `address` object of
  // this shape, and a token that carried a partial one would produce an address
  // assembled out of two sources — which is worse than either.
  if (row.claim.length === 1 && tokenClaims &&
      typeof tokenClaims[row.claim[0]] === 'string' && tokenClaims[row.claim[0]] !== '') {
    return { value: tokenClaims[row.claim[0]], source: 'access token', flat: flat };
  }
  const stored = attributes ? attributes[row.ldap.toLowerCase()] : null;
  if (stored && stored.length && String(stored[0]) !== '') {
    // The FIRST value. LDAP attributes are multi-valued and claims are not, and
    // picking the first is the only rule that does not depend on insertion order
    // being meaningful — which it is not, in this store or in a real directory.
    const raw = String(stored[0]);
    return { value: row.toClaim ? row.toClaim(raw) : raw, source: 'directory', flat: flat };
  }
  if (!row.from) {
    return null;
  }
  const raw = persona[row.from];
  if (raw === undefined || raw === null || raw === '') {
    return null;
  }
  return { value: row.toClaim ? row.toClaim(String(raw)) : String(raw),
           source: 'generated', flat: flat };
}

// The subject claims for one person, as the credential builders want them: a
// plain object, nested where the catalogue nests, with no `sub` — that is the
// caller's, because each format names its subject differently (a `sub` claim, a
// credentialSubject.id, a did:jwk) and this module should not have an opinion
// about which.
//
// `report` rides along for the console: same values, but flat and annotated with
// where each came from.
// `rows` is which of the selected rows to build, and it exists for one caller:
// a wallet that asked for a SUBSET of the claims in its authorization_details
// (OID4VCI section 5.1.1). Absent means all of them, which is what every other
// caller wants and what an authorization carrying no `claims` member means.
function subjectClaimsFor(name, tokenClaims, rows) {
  log.debug("Entering subjectClaimsFor(). name=" + name +
            (rows ? ", restricted to " + rows.length + " requested claim(s)." : "."));
  const persona = personaFor(name);
  const attributes = directoryAttributes(name);
  const claims = {};
  const report = [];
  (rows || selectedRows()).forEach(function (row) {
    const found = valueFor(row, name, tokenClaims, attributes, persona);
    if (!found) {
      return;
    }
    setPath(claims, row.claim, found.value);
    report.push({ ldap: row.ldap, claim: found.flat, value: found.value,
                  source: found.source, ldpTerm: ldpTermFor(row) });
  });
  log.debug("Leaving subjectClaimsFor(). " + report.length + " claim(s), " +
            (attributes ? "the directory has an entry for them." : "no directory entry."));
  return { claims: claims, report: report, entryFound: !!attributes };
}

// ---------------------------------------------------------------------------
// What the issuer METADATA advertises, built from the same selection the
// credential is built from.
//
// This is not tidiness. An issuer whose metadata lists five claims and whose
// credentials carry fourteen is teaching every wallet developer who reads it that
// the metadata is not worth reading, and OID4VCI's whole discovery story rests on
// it being worth reading. So there is one list and both sides derive from it.
//
// `prefix` is where the claims sit in that format: nothing for dc+sd-jwt, whose
// claims are at the top level of the payload, and ['credentialSubject'] for the
// two W3C formats.
// ---------------------------------------------------------------------------
function metadataClaims(prefix) {
  log.debug("Entering metadataClaims(). prefix=" + (prefix || []).join('.'));
  const out = selectedRows().map(function (row) {
    return { path: (prefix || []).concat(row.claim),
             display: [{ locale: 'en-US', name: row.label }] };
  });
  log.debug("Leaving metadataClaims(). " + out.length + " claim(s) advertised.");
  return out;
}

// The same, for ldp_vc: only the rows whose term the vendored context defines,
// and FLAT — the context defines `streetAddress` and `locality` as terms of their
// own, not as members of an `address` object, so that is where they go.
function ldpMetadataClaims() {
  log.debug("Entering ldpMetadataClaims().");
  const out = selectedRows().filter(ldpTermFor).map(function (row) {
    return { path: ['credentialSubject', row.ldpTerm],
             display: [{ locale: 'en-US', name: row.label }] };
  });
  log.debug("Leaving ldpMetadataClaims(). " + out.length + " claim(s) advertised.");
  return out;
}

// ---------------------------------------------------------------------------
// THE CLAIM PATHS THIS ISSUER PUBLISHES FOR ONE FORMAT, and the rows a wallet's
// request selects out of them.
//
// OID4VCI section 5.1.1 lets the Wallet put a `claims` member in its
// authorization_details, an array of claims description objects (Appendix A.1)
// each carrying a claims path pointer (Appendix B) into the credential. So the
// wallet asks in the vocabulary the METADATA published — which is why the
// validation and the filtering below both go through advertisedClaims() rather
// than through the catalogue directly. A path that is not one this issuer
// advertises selects nothing, and the authorization endpoint refuses it rather
// than issuing a credential quietly missing a claim somebody asked for.
//
// The prefix is the format's, exactly as the metadata builder needs it: an
// SD-JWT VC keeps its claims at the top level of the payload, the two W3C
// formats keep them under credentialSubject, and ldp_vc is additionally FLAT and
// limited to the terms the vendored context defines.
// ---------------------------------------------------------------------------
function advertisedClaims(format) {
  log.debug("Entering advertisedClaims(). format=" + format);
  if (format === 'ldp_vc') {
    log.debug("Leaving advertisedClaims(). The ldp_vc list.");
    return ldpMetadataClaims();
  }
  log.debug("Leaving advertisedClaims().");
  return metadataClaims(format === 'jwt_vc_json' ? ['credentialSubject'] : []);
}

// Where one catalogue row's claim sits in a credential of this format, or null
// when this format cannot carry it at all (ldp_vc, whose context defines no term
// for it). The mirror image of advertisedClaims(), and the two must agree: a row
// whose path here is absent from the metadata would be requestable and never
// issued.
function pathOfRow(row, format) {
  log.debug("Entering pathOfRow(). " + row.ldap);
  if (format === 'ldp_vc') {
    log.debug("Leaving pathOfRow().");
    return ldpTermFor(row) ? ['credentialSubject', ldpTermFor(row)] : null;
  }
  log.debug("Leaving pathOfRow().");
  return (format === 'jwt_vc_json' ? ['credentialSubject'] : []).concat(row.claim);
}

// A claims path pointer as one comparable string. JSON rather than a join,
// because a pointer may hold nulls and integers as well as strings (Appendix B)
// and "a.0.b" would not tell those apart from the strings "0" and "b".
function pathKey(path) {
  log.debug("Entering pathKey().");
  log.debug("Leaving pathKey().");
  return JSON.stringify(path);
}

// The selected rows a set of requested paths names, in CATALOGUE order rather
// than request order: the order claims appear in a credential is this issuer's,
// and section A.3 makes request order a display concern of the wallet's.
function rowsForPaths(paths, format) {
  log.debug("Entering rowsForPaths(). " + (paths || []).length + " path(s), format=" + format);
  const wanted = new Set((paths || []).map(pathKey));
  const out = selectedRows().filter(function (row) {
    const path = pathOfRow(row, format);
    return path && wanted.has(pathKey(path));
  });
  log.debug("Leaving rowsForPaths(). " + out.length + " row(s) selected.");
  return out;
}

// Which of the requested paths this issuer does not advertise for this format.
// Returned rather than thrown: the caller is the authorization endpoint, which
// has to name all of them in one error_description.
function unknownPaths(paths, format) {
  log.debug("Entering unknownPaths(). format=" + format);
  const advertised = new Set(advertisedClaims(format).map(function (c) { return pathKey(c.path); }));
  const out = (paths || []).filter(function (path) { return !advertised.has(pathKey(path)); });
  log.debug("Leaving unknownPaths(). " + out.length + " unknown.");
  return out;
}

// The ldp_vc credentialSubject members, read out of the claims object
// subjectClaimsFor() built. Returned as {term: value} so the caller can drop any
// term its loaded context turns out not to define — see the LDP note above; the
// list here is derived from that file by hand and the caller checks it against
// the file itself.
function ldpSubjectFrom(claims) {
  log.debug("Entering ldpSubjectFrom().");
  const out = {};
  selectedRows().forEach(function (row) {
    if (!row.ldpTerm) {
      return;
    }
    let node = claims;
    for (let i = 0; i < row.claim.length && node && typeof node === 'object'; i++) {
      node = node[row.claim[i]];
    }
    if (node === undefined || node === null || node === '') {
      return;
    }
    out[row.ldpTerm] = String(node);
  });
  log.debug("Leaving ldpSubjectFrom(). " + Object.keys(out).length + " member(s).");
  return out;
}

// Which selected attributes an ldp_vc credential cannot carry. The page states
// them; so does this function's one caller in the metadata, because a wallet
// author comparing the three configurations will notice the difference and
// should not have to guess whether it is deliberate.
function ldpOmitted() {
  return selectedRows().filter(function (row) { return !row.ldpTerm; })
                       .map(function (row) { return row.ldap; });
}

module.exports = {
  VC_ATTRIBUTES: VC_ATTRIBUTES,
  CANONICAL_NAMES: CANONICAL_NAMES,
  DEFAULT_SELECTION: DEFAULT_SELECTION,
  selectedRows: selectedRows,
  selectedNames: selectedNames,
  isSelected: isSelected,
  setSelection: setSelection,
  resetSelection: resetSelection,
  personaFor: personaFor,
  generatedFor: generatedFor,
  // Filled by ldap_server.js at its require time; see the note above it.
  setDirectory: setDirectory,
  populateDirectory: populateDirectory,
  subjectClaimsFor: subjectClaimsFor,
  metadataClaims: metadataClaims,
  ldpMetadataClaims: ldpMetadataClaims,
  advertisedClaims: advertisedClaims,
  pathOfRow: pathOfRow,
  pathKey: pathKey,
  rowsForPaths: rowsForPaths,
  unknownPaths: unknownPaths,
  ldpSubjectFrom: ldpSubjectFrom,
  ldpOmitted: ldpOmitted
};
