'use strict';
//
// File: ssf_subjects.js
//
// ---------------------------------------------------------------------------
// SUBJECT IDENTIFIERS FOR SECURITY EVENT TOKENS (RFC 9493), AND THE COMPLEX
// SUBJECT THE SHARED SIGNALS FRAMEWORK LAYERS ON TOP OF THEM.
//
// A Security Event Token says that something happened; a Subject Identifier is
// the part that says WHO it happened to. RFC 9493 gives eight formats and the
// whole of the specification's substance is that each one has a CLOSED set of
// members and every one of them is REQUIRED. That sounds like a formality and
// it is the thing implementations get wrong: a subject with an extra member is
// not a subject with an extra member, it is a subject a conforming receiver
// MUST reject, because the receiver cannot tell whether the member it does not
// recognise narrows the identifier.
//
// So this module refuses, by name, and says which member was the problem. A
// mock that accepted a loose subject would let somebody ship a transmitter
// that no real receiver will take.
//
// ---------------------------------------------------------------------------
// WHY THIS IS WRITTEN OUT HERE RATHER THAN VENDORED FROM THE DEBUGGER.
//
// It is the argument `common/pq_jose.js` makes, and it applies more sharply to
// a grammar than to a signature. This service exists to be the far end of the
// debugger's own SSF code: the debugger BUILDS a subject and this service
// READS it. If both ends read one implementation, a misunderstanding they
// share is one neither can see — and the round trip would pass while
// interoperating with nothing.
//
// So the debugger has `client/src/ssf_client.js`'s own grammar, this file is
// this service's, and `tests/ssf_protocol.js` in the parent project drives one
// against the other OVER THE WIRE. That is the only arrangement in which a
// disagreement surfaces as a failure rather than as agreement.
//
// It is the opposite decision from `common/krb5`, which IS vendored, and the
// difference is worth stating: a Kerberos codec is bytes with one legal
// encoding, so two implementations is two chances to be wrong about the same
// bytes with nothing to gain. A subject identifier is JSON, where the
// interesting defect is a READING — an accepted extra member, a missing
// required one, a format name spelt from memory — and two readings is exactly
// what makes that visible.
//
// ---------------------------------------------------------------------------
// IT IS A LIBRARY (rule 3). It registers no route, so its position in the
// route order is not a position. It requires `helpers.js` for the logger and
// NOTHING ELSE in this repository, so it cannot join a cycle and a test can
// drive it with plain objects.
// ---------------------------------------------------------------------------

const { log } = require('../common/helpers');

// ---------------------------------------------------------------------------
// THE EIGHT FORMATS OF RFC 9493 SECTION 3, EACH WITH ITS CLOSED MEMBER SET.
//
// `members` is what the format defines; `required` is which of them a
// conforming subject MUST carry. For seven of the eight those two lists are
// the same, which is the specification's own shape rather than a shortcut
// here: RFC 9493 defines no optional member on any format except the
// `Aliases` one, whose `identifiers` is required and whose CONTENTS are the
// variable part.
//
// `what` is prose for the console and for `GET /ssf`; `example` is a real
// value of that format, used by the page and by the test as a fixture. Neither
// is read by the validator.
// ---------------------------------------------------------------------------
const FORMATS = [
  { format: 'account',
    members: ['uri'], required: ['uri'],
    what: 'An "acct" URI (RFC 7565) — a user at a service, the identifier ' +
          'form WebFinger uses.',
    example: { format: 'account', uri: 'acct:alice@example.com' } },
  { format: 'email',
    members: ['email'], required: ['email'],
    what: 'An email address (RFC 5322 addr-spec). The commonest subject in ' +
          'practice and the one most likely to be RECYCLED, which is why ' +
          'RISC has an event type about exactly that.',
    example: { format: 'email', email: 'alice@example.com' } },
  { format: 'issuer_subject_id',
    members: ['iss', 'sub'], required: ['iss', 'sub'],
    what: 'The pair an OpenID Connect ID Token is identified by — the ' +
          'issuer and the subject within it. The only format that is ' +
          'globally unique by construction rather than by convention.',
    example: { format: 'issuer_subject_id',
               iss: 'https://issuer.example.com/', sub: '145234573' } },
  { format: 'opaque',
    members: ['id'], required: ['id'],
    what: 'A string meaningful only to the parties that agreed it. It says ' +
          'nothing about what kind of thing it names, which is the point: a ' +
          'transmitter that must not leak an email address uses this.',
    example: { format: 'opaque', id: '11112222333344445555' } },
  { format: 'phone_number',
    members: ['phone_number'], required: ['phone_number'],
    what: 'A phone number in E.164 form. RFC 9493 requires the leading "+" ' +
          'and digits only — no spaces, no punctuation, no extension.',
    example: { format: 'phone_number', phone_number: '+12065550100' } },
  { format: 'decentralized_identifier',
    members: ['url'], required: ['url'],
    what: 'A DID or a DID URL (W3C DID Core). The identifier resolves to a ' +
          'document rather than to a record at the transmitter.',
    example: { format: 'decentralized_identifier',
               url: 'did:example:123456789abcdefghi' } },
  { format: 'uri',
    members: ['uri'], required: ['uri'],
    what: 'Any URI. The escape hatch, and the one to reach for LAST — a ' +
          'receiver can do nothing with it but compare it, so a format that ' +
          'says what kind of thing this is is always better.',
    example: { format: 'uri', uri: 'https://example.com/users/1234' } },
  { format: 'aliases',
    members: ['identifiers'], required: ['identifiers'],
    what: 'SEVERAL identifiers for ONE subject, so a receiver that knows the ' +
          'person by any of them can act. It MUST NOT contain another ' +
          'aliases identifier — RFC 9493 section 3.2.8 forbids the nesting ' +
          'outright, and this service refuses it rather than flattening, ' +
          'because flattening would accept a document a conforming receiver ' +
          'rejects.',
    example: { format: 'aliases', identifiers: [
      { format: 'email', email: 'alice@example.com' },
      { format: 'phone_number', phone_number: '+12065550100' }
    ] } }
];

const FORMAT_BY_NAME = {};
FORMATS.forEach(function (row) {
  FORMAT_BY_NAME[row.format] = row;
});

const FORMAT_NAMES = FORMATS.map(function (row) {
  return row.format;
});

// ---------------------------------------------------------------------------
// THE COMPLEX SUBJECT, which is the Shared Signals Framework's own addition
// and not RFC 9493's.
//
// SSF 1.0 section 4 lets the `sub_id` of a SET be an object whose members are
// each themselves a Subject Identifier, so one event can name the person AND
// the device AND the session it is about. That is what makes "this session was
// revoked" expressible at all: the person is not revoked, one session of
// theirs is.
//
// THE SIX NAMES ARE CLOSED and there is no ninth. A member this service does
// not recognise is refused for the same reason an unrecognised member of a
// simple identifier is: a receiver cannot know whether it narrows the subject.
//
// `critical_subject_members` in the transmitter's metadata names the ones a
// receiver is REQUIRED to understand, which is a different list and is
// configuration rather than grammar — see `ssf.criticalSubjectMembers`.
// ---------------------------------------------------------------------------
const COMPLEX_MEMBERS = [
  { name: 'user', what: 'The person.' },
  { name: 'device', what: 'The device they are on.' },
  { name: 'session', what: 'The one session, of possibly many.' },
  { name: 'tenant', what: 'The tenant, in a multi-tenant service.' },
  { name: 'org_unit', what: 'The organizational unit within the tenant.' },
  { name: 'group', what: 'The group membership the event is about.' }
];

const COMPLEX_MEMBER_NAMES = COMPLEX_MEMBERS.map(function (row) {
  return row.name;
});

// E.164: a plus and between 1 and 15 digits. Deliberately no punctuation and
// no extension — RFC 9493 section 3.2.5 says the value is the number in that
// form, and a receiver comparing "+1 206 555 0100" to "+12065550100" finds two
// different subjects.
const E164 = /^\+[1-9][0-9]{1,14}$/;

// An addr-spec, checked loosely on purpose: this is a mock, and a grammar
// strict enough to be interesting about email addresses would refuse valid
// ones. What is checked is what a comparison depends on — one "@", something
// on each side of it, and no whitespace.
const ADDR_SPEC = /^[^\s@]+@[^\s@]+$/;

// An "acct" URI (RFC 7565): the scheme, then the same shape as an addr-spec.
const ACCT_URI = /^acct:[^\s@]+@[^\s@]+$/;

// A DID or DID URL: "did:", a lower-case method name, a colon, and at least
// one character of method-specific identifier. What follows (a path, a query,
// a fragment) is the URL half and is not constrained here.
const DID_URL = /^did:[a-z0-9]+:[^\s]+$/;

// Any absolute URI: a scheme, a colon and something. Deliberately not a URL
// parser — RFC 9493's `uri` format accepts a URI and `new URL()` would refuse
// several that are perfectly legal (a bare `urn:`, a `tag:`).
const ABSOLUTE_URI = /^[A-Za-z][A-Za-z0-9+.-]*:[^\s]+$/;

// ---------------------------------------------------------------------------
// The per-format value checks, one function each, keyed by MEMBER name rather
// than by format so that `uri` on the `uri` format and `uri` on the `account`
// format can differ — which they do, and the difference is the whole of what
// tells those two formats apart on the wire.
// ---------------------------------------------------------------------------
const VALUE_CHECKS = {
  'account.uri': function (value) {
    return ACCT_URI.test(value)
      ? null
      : 'is not an "acct" URI (RFC 7565) — it has to begin "acct:" and ' +
        'carry a user and a host, as in acct:alice@example.com';
  },
  'email.email': function (value) {
    return ADDR_SPEC.test(value)
      ? null
      : 'is not an email address — one "@", something either side of it, ' +
        'and no whitespace';
  },
  'phone_number.phone_number': function (value) {
    return E164.test(value)
      ? null
      : 'is not an E.164 number — RFC 9493 section 3.2.5 wants a leading ' +
        '"+" and digits only, so "+1 206 555 0100" is a DIFFERENT subject ' +
        'from "+12065550100" to any receiver that compares them';
  },
  'decentralized_identifier.url': function (value) {
    return DID_URL.test(value)
      ? null
      : 'is not a DID or a DID URL — it has to begin "did:", name a method ' +
        'and carry a method-specific identifier';
  },
  'uri.uri': function (value) {
    return ABSOLUTE_URI.test(value)
      ? null
      : 'is not an absolute URI — it needs a scheme and a colon';
  },
  'issuer_subject_id.iss': function (value) {
    return ABSOLUTE_URI.test(value)
      ? null
      : 'is not an absolute URI. An issuer identifier is one, always — it ' +
        'is the same string the ID Token carries';
  }
};

// Every member that has no check of its own is a non-empty string and nothing
// more. `opaque.id` is the case that matters: it is opaque BY DEFINITION, so a
// check on its shape would be this service inventing a rule.
function checkMemberValue(format, member, value) {
  log.debug('Entering checkMemberValue(). ' + format + '.' + member);
  if (typeof value !== 'string' || value === '') {
    log.debug('Leaving checkMemberValue(). Not a non-empty string.');
    return 'must be a non-empty string';
  }
  const check = VALUE_CHECKS[format + '.' + member];
  if (!check) {
    log.debug('Leaving checkMemberValue(). No shape rule for this member.');
    return null;
  }
  const problem = check(value);
  log.debug('Leaving checkMemberValue(). ' + (problem ? 'refused' : 'ok'));
  return problem;
}

// ---------------------------------------------------------------------------
// VALIDATE ONE SIMPLE SUBJECT IDENTIFIER.
//
// Returns `{ ok, format, errors }`. Every problem is collected rather than the
// first one thrown, because a subject built by hand on a debugger's form is
// usually wrong in more than one way at once and a validator that reports one
// error per attempt is a validator somebody stops reading.
//
// `path` is where this identifier sits in the document ("sub_id",
// "sub_id.user", "sub_id.identifiers[1]"), so the message names the member the
// caller can actually find.
// ---------------------------------------------------------------------------
function validateSubject(subject, path, options) {
  log.debug('Entering validateSubject(). ' + (path || 'sub_id'));
  const where = path || 'sub_id';
  const settings = options || {};
  const errors = [];
  if (!subject || typeof subject !== 'object' || Array.isArray(subject)) {
    errors.push(where + ' must be a JSON object.');
    log.debug('Leaving validateSubject(). Not an object.');
    return { ok: false, format: '', errors: errors };
  }
  const format = subject.format;
  if (typeof format !== 'string' || format === '') {
    errors.push(where + ' has no "format" member. RFC 9493 makes it ' +
        'REQUIRED on every Subject Identifier — without it a receiver ' +
        'cannot know which members to read. The eight formats are: ' +
        FORMAT_NAMES.join(', ') + '.');
    log.debug('Leaving validateSubject(). No format.');
    return { ok: false, format: '', errors: errors };
  }
  const row = FORMAT_BY_NAME[format];
  if (!row) {
    errors.push(where + ' names the format "' + format + '", which RFC 9493 ' +
        'does not define. The eight are: ' + FORMAT_NAMES.join(', ') + '.');
    log.debug('Leaving validateSubject(). Unknown format.');
    return { ok: false, format: format, errors: errors };
  }

  // THE CLOSED MEMBER SET, and this is the check that catches the defect
  // nothing else does. A subject with an extra member looks fine in a log and
  // is refused by a conforming receiver.
  Object.keys(subject).forEach(function (name) {
    if (name === 'format') {
      return;
    }
    if (row.members.indexOf(name) < 0) {
      errors.push(where + ' carries "' + name + '", which the "' + format +
          '" format does not define. RFC 9493 section 3 gives each format a ' +
          'CLOSED set of members — a receiver that met an unrecognised one ' +
          'could not tell whether it narrows the subject, so it must reject ' +
          'the identifier rather than ignore the member. This format has: ' +
          row.members.join(', ') + '.');
    }
  });

  row.required.forEach(function (name) {
    if (!Object.prototype.hasOwnProperty.call(subject, name)) {
      errors.push(where + ' has no "' + name + '", which the "' + format +
          '" format requires.');
    }
  });

  if (format === 'aliases') {
    validateAliases(subject, where, errors, settings);
  } else {
    row.members.forEach(function (name) {
      if (!Object.prototype.hasOwnProperty.call(subject, name)) {
        return;
      }
      const problem = checkMemberValue(format, name, subject[name]);
      if (problem) {
        errors.push(where + '.' + name + ' ' + problem + '.');
      }
    });
  }

  log.debug('Leaving validateSubject(). ' + errors.length + ' problem(s).');
  return { ok: errors.length === 0, format: format, errors: errors };
}

// The Aliases format's own rules, split out because they are the only ones
// that recurse and the only ones with a NESTING ban to enforce.
function validateAliases(subject, where, errors, options) {
  log.debug('Entering validateAliases().');
  const list = subject.identifiers;
  if (!Array.isArray(list)) {
    errors.push(where + '.identifiers must be an array of Subject ' +
        'Identifiers.');
    log.debug('Leaving validateAliases(). Not an array.');
    return;
  }
  if (!list.length) {
    errors.push(where + '.identifiers is empty. An Aliases identifier that ' +
        'names nobody identifies nobody.');
    log.debug('Leaving validateAliases(). Empty.');
    return;
  }
  list.forEach(function (one, index) {
    const inner = where + '.identifiers[' + index + ']';
    if (one && typeof one === 'object' && one.format === 'aliases') {
      errors.push(inner + ' is itself an "aliases" identifier. RFC 9493 ' +
          'section 3.2.8 forbids the nesting outright. This service refuses ' +
          'it rather than flattening it, because flattening would accept a ' +
          'document a conforming receiver rejects — and the sender would ' +
          'never find out.');
      return;
    }
    const verdict = validateSubject(one, inner, options);
    verdict.errors.forEach(function (message) {
      errors.push(message);
    });
  });
  log.debug('Leaving validateAliases().');
}

// ---------------------------------------------------------------------------
// VALIDATE A `sub_id`, WHICH MAY BE SIMPLE OR COMPLEX.
//
// The two are told apart by the presence of `format`: SSF 1.0 section 4 says a
// complex subject has no `format` member and simple one always does. That is
// the whole discriminator and it is worth being explicit about, because the
// obvious alternative — "does it have a member named `user`?" — is wrong for
// an `opaque` subject whose id happens to be spelt that way.
//
// `criticalMembers` is the transmitter's `critical_subject_members`: names a
// RECEIVER must understand. A complex subject that carries none of them is
// refused HERE, at the transmitter, rather than being sent and refused there,
// because a transmitter that publishes a critical member and then omits it is
// producing events nothing will act on.
// ---------------------------------------------------------------------------
function validateSubjectId(subject, options) {
  log.debug('Entering validateSubjectId().');
  const settings = options || {};
  const where = settings.path || 'sub_id';
  if (!subject || typeof subject !== 'object' || Array.isArray(subject)) {
    log.debug('Leaving validateSubjectId(). Not an object.');
    return { ok: false, complex: false, format: '',
      errors: [where + ' must be a JSON object.'] };
  }
  if (Object.prototype.hasOwnProperty.call(subject, 'format')) {
    const simple = validateSubject(subject, where, settings);
    log.debug('Leaving validateSubjectId(). Simple.');
    return { ok: simple.ok, complex: false, format: simple.format,
      errors: simple.errors };
  }

  const errors = [];
  const names = Object.keys(subject);
  if (!names.length) {
    errors.push(where + ' is an empty object. A complex subject with no ' +
        'members names nobody, and a SIMPLE one would have carried a ' +
        '"format".');
  }
  names.forEach(function (name) {
    if (COMPLEX_MEMBER_NAMES.indexOf(name) < 0) {
      errors.push(where + ' carries "' + name + '", which is neither one of ' +
          'the six complex subject members SSF 1.0 section 4 defines (' +
          COMPLEX_MEMBER_NAMES.join(', ') + ') nor the "format" member a ' +
          'SIMPLE Subject Identifier would carry. If this was meant to be a ' +
          'simple identifier, it is missing its "format".');
      return;
    }
    const verdict = validateSubject(subject[name], where + '.' + name,
                                    settings);
    verdict.errors.forEach(function (message) {
      errors.push(message);
    });
  });

  const critical = settings.criticalMembers || [];
  critical.forEach(function (name) {
    if (!Object.prototype.hasOwnProperty.call(subject, name)) {
      errors.push(where + ' has no "' + name + '" member, and this ' +
          'transmitter publishes "' + name + '" in ' +
          'critical_subject_members — which is a promise that every complex ' +
          'subject it sends carries one. A receiver is entitled to refuse ' +
          'an event without it.');
    }
  });

  log.debug('Leaving validateSubjectId(). Complex, ' + errors.length +
            ' problem(s).');
  return { ok: errors.length === 0, complex: true, format: '',
    errors: errors };
}

// ---------------------------------------------------------------------------
// A STABLE STRING FOR ONE SUBJECT, so that "is this the same subject" can be
// answered by a Map lookup.
//
// It is NOT a canonical serialization of the JSON and must not be read as one:
// the members are sorted and joined with characters that cannot appear in a
// member name, which is enough to key a store and nothing more. An `aliases`
// identifier keys on its SORTED members, so the same two identifiers in the
// other order are one subject — which is what the format means.
// ---------------------------------------------------------------------------
function subjectKey(subject) {
  log.debug('Entering subjectKey().');
  if (!subject || typeof subject !== 'object') {
    log.debug('Leaving subjectKey(). Not an object.');
    return '';
  }
  if (Object.prototype.hasOwnProperty.call(subject, 'format')) {
    if (subject.format === 'aliases' && Array.isArray(subject.identifiers)) {
      const parts = subject.identifiers.map(subjectKey).sort();
      log.debug('Leaving subjectKey(). Aliases.');
      return 'aliases[' + parts.join('|') + ']';
    }
    const row = FORMAT_BY_NAME[subject.format];
    const members = (row ? row.members : Object.keys(subject).filter(
      function (name) {
        return name !== 'format';
      })).slice().sort();
    const body = members.map(function (name) {
      return name + '=' + String(subject[name] == null ? '' : subject[name]);
    }).join(';');
    log.debug('Leaving subjectKey(). Simple.');
    return subject.format + '{' + body + '}';
  }
  const complex = Object.keys(subject).slice().sort().map(function (name) {
    return name + '=' + subjectKey(subject[name]);
  }).join(';');
  log.debug('Leaving subjectKey(). Complex.');
  return 'complex{' + complex + '}';
}

// A one-line rendering for a page, a log line or an audit entry. It is for
// PEOPLE and nothing reads it back.
function describeSubject(subject) {
  log.debug('Entering describeSubject().');
  if (!subject || typeof subject !== 'object') {
    log.debug('Leaving describeSubject(). Nothing.');
    return '(no subject)';
  }
  if (!Object.prototype.hasOwnProperty.call(subject, 'format')) {
    const parts = Object.keys(subject).map(function (name) {
      return name + ': ' + describeSubject(subject[name]);
    });
    log.debug('Leaving describeSubject(). Complex.');
    return parts.join(', ') || '(empty complex subject)';
  }
  if (subject.format === 'aliases') {
    const inner = Array.isArray(subject.identifiers)
      ? subject.identifiers.map(describeSubject).join(' = ')
      : '(no identifiers)';
    log.debug('Leaving describeSubject(). Aliases.');
    return inner;
  }
  const row = FORMAT_BY_NAME[subject.format];
  const values = (row ? row.members : []).map(function (name) {
    return String(subject[name] == null ? '' : subject[name]);
  }).filter(Boolean);
  log.debug('Leaving describeSubject(). Simple.');
  return values.join(' / ') || subject.format;
}

// The subject this service uses for a person it knows by name, in whichever
// format a stream asked for. `format` comes off the stream configuration's own
// `format` member (SSF 1.0's "default subjects" arrangement), so a receiver
// that asked for `opaque` never sees an email address.
function subjectForUser(userid, format, issuer) {
  log.debug('Entering subjectForUser(). ' + format);
  const name = String(userid || '');
  const chosen = FORMAT_BY_NAME[format] ? format : 'issuer_subject_id';
  if (chosen === 'email') {
    log.debug('Leaving subjectForUser(). email.');
    return { format: 'email', email: name.indexOf('@') > 0
      ? name : name + '@example.com' };
  }
  if (chosen === 'account') {
    log.debug('Leaving subjectForUser(). account.');
    return { format: 'account', uri: 'acct:' + (name.indexOf('@') > 0
      ? name : name + '@example.com') };
  }
  if (chosen === 'opaque') {
    log.debug('Leaving subjectForUser(). opaque.');
    return { format: 'opaque', id: name };
  }
  if (chosen === 'uri') {
    log.debug('Leaving subjectForUser(). uri.');
    return { format: 'uri', uri: String(issuer || '') + '/users/' + name };
  }
  if (chosen === 'decentralized_identifier') {
    log.debug('Leaving subjectForUser(). did.');
    return { format: 'decentralized_identifier',
      url: 'did:example:' + name };
  }
  if (chosen === 'phone_number') {
    // There is no phone number on a directory entry here and inventing one
    // per user would be inventing a fact. A stream that asked for this format
    // gets the issuer/subject pair and the caller says so — see
    // ssf.js's defaultSubjectNote().
    log.debug('Leaving subjectForUser(). No number; issuer_subject_id.');
    return { format: 'issuer_subject_id', iss: String(issuer || ''),
      sub: name };
  }
  if (chosen === 'aliases') {
    log.debug('Leaving subjectForUser(). aliases.');
    return { format: 'aliases', identifiers: [
      { format: 'issuer_subject_id', iss: String(issuer || ''), sub: name },
      { format: 'email', email: name.indexOf('@') > 0
        ? name : name + '@example.com' }
    ] };
  }
  log.debug('Leaving subjectForUser(). issuer_subject_id.');
  return { format: 'issuer_subject_id', iss: String(issuer || ''),
    sub: name };
}

module.exports = {
  FORMATS: FORMATS,
  FORMAT_NAMES: FORMAT_NAMES,
  COMPLEX_MEMBERS: COMPLEX_MEMBERS,
  COMPLEX_MEMBER_NAMES: COMPLEX_MEMBER_NAMES,
  validateSubject: validateSubject,
  validateSubjectId: validateSubjectId,
  subjectKey: subjectKey,
  describeSubject: describeSubject,
  subjectForUser: subjectForUser
};
