'use strict';
//
// File: ssf_events.js
//
// ---------------------------------------------------------------------------
// THE EVENT TYPES THIS TRANSMITTER SPEAKS, AND THE SECURITY EVENT TOKEN THEY
// TRAVEL IN (RFC 8417).
//
// The Shared Signals Framework is a PIPE. It defines how two parties agree a
// stream, who the events are about and how they get delivered, and it defines
// almost no events of its own — the vocabularies are CAEP (what happened to a
// session) and RISC (what happened to an account), which are separate
// specifications layered over this one.
//
// SSF 1.0 itself defines exactly two, and both are about the pipe rather than
// about the person:
//
//   verification     the receiver asked "is this stream alive?" and this is
//                    the answer travelling the ordinary delivery path. It is
//                    the ONLY end-to-end test of a stream that exists — a
//                    200 from the management API says the configuration was
//                    accepted and says nothing about whether an event can
//                    reach the receiver.
//   stream updated   the stream's own status changed, and the receiver is
//                    being told IN BAND rather than having to poll the status
//                    endpoint.
//
// **THIS FILE IS DELIBERATELY THE WHOLE OF THE VOCABULARY AND IT IS SHORT.**
// CAEP's five session events and RISC's account-lifecycle events are the
// second and third parts of this work, and each will add rows to `EVENTS`
// below and nothing else: the SET envelope, the subject grammar, the delivery
// and the stream management are all here already and are the same for every
// vocabulary. That is the point of SSF being a separate specification, and a
// design that made this table's shape specific to its two rows would have to
// be undone twice.
//
// ---------------------------------------------------------------------------
// WHAT A SET IS, AND THE THREE THINGS IMPLEMENTATIONS GET WRONG.
//
// A SET is a JWT (RFC 8417) whose payload carries an `events` object — a map
// from event-type URI to that event's own payload. Not an array, and not a
// single event: the map is what lets one token carry a set of events that
// happened together, and it is why the media type says "secevent" rather than
// "event".
//
//   * **`typ` IS `secevent+jwt` AND IT MATTERS.** RFC 8417 section 2.2 makes
//     it a SHOULD, and a receiver that dispatches on it — several do — drops a
//     token without it on the floor with no error anybody sees.
//   * **THERE IS NO `exp` AND THAT IS NOT AN OVERSIGHT.** RFC 8417 section
//     4.1.4 says a SET MUST NOT be considered to expire: it records that
//     something HAPPENED, and a fact does not stop being true. An
//     implementation that adds one is asking receivers to discard history.
//   * **`sub` IS NOT THE SUBJECT.** RFC 8417 section 2.2 says the `sub` claim
//     is discouraged and SSF uses `sub_id` (RFC 9493) instead, because `sub`
//     is a string and the thing an event is about is a structured identifier
//     that may name a person, a device and a session at once. This service
//     emits `sub_id` and never `sub`, and `ssf.legacySubClaim` puts one back
//     for a client that has to be tested against a transmitter that gets this
//     wrong.
//
// ---------------------------------------------------------------------------
// IT IS A LIBRARY (rule 3). It registers no route. It requires `helpers.js`
// (for the logger and for `signJwtAs`, which is where every algorithm this
// service can sign with already lives), `config.js` and `ssf_subjects.js`, and
// nothing else here — so it cannot join a cycle.
//
// **THE SIGNATURE GOES THROUGH `helpers.signJwtAs()` AND NOT THROUGH A SIGNER
// OF ITS OWN**, which is what gives this family every algorithm the rest of
// the service has, POST-QUANTUM ONES INCLUDED, for no code at all: ML-DSA at
// three sizes, SLH-DSA at two and the six composite ML-DSA + traditional
// algorithms are already in that table because a client can ask for them on an
// ID Token. `ssf.signingAlgorithm` picks one. A SET is exactly the document
// where that matters most — it is a durable record of something that happened,
// so it is read long after it was written, which is the case a
// harvest-now-decrypt-later argument is actually about.
// ---------------------------------------------------------------------------

const { log, signJwtAs, signJwtAsAsync, randomId, nowSec, STS } =
  require('../common/helpers');
const config = require('../common/config');
const subjects = require('./ssf_subjects');

// The URI prefix every SSF-defined event type shares. Written once because the
// two rows below and the two vocabularies that come after it all hang off it,
// and a typo in one of them produces an event a receiver silently ignores.
const SSF_PREFIX = 'https://schemas.openid.net/secevent/ssf/event-type/';

// The `typ` of a Security Event Token (RFC 8417 section 2.3). It is the media
// type without the `application/` prefix, which is what a JWT header carries.
const SET_MEDIA_TYPE = 'secevent+jwt';

// ---------------------------------------------------------------------------
// THE CATALOGUE.
//
//   uri        the event type, which is the KEY in the SET's `events` map
//   family     which specification defines it — 'ssf' today; 'caep' and
//              'risc' are the second and third parts of this work
//   subject    'none' | 'optional' | 'required'. THE VERIFICATION EVENT IS
//              THE ONLY ONE IN ANY OF THE THREE VOCABULARIES WITH NO SUBJECT
//              AT ALL, and it is worth knowing why: it is about the STREAM,
//              not about anybody, so a receiver that insists on a subject
//              cannot be verified.
//   members    the event payload's own members. `required` says which a
//              conforming event carries; the rest are optional.
//   generate   builds a payload from the values a caller supplied, filling
//              what it can. Every row has one so that "send me one of these"
//              is one call from the console, the management API and the
//              debugger alike.
// ---------------------------------------------------------------------------
const EVENTS = [
  {
    uri: SSF_PREFIX + 'verification',
    family: 'ssf',
    name: 'Verification',
    subject: 'none',
    members: [
      { name: 'state', required: false, type: 'string',
        what: 'Whatever the receiver put in its verification request, ' +
              'echoed back UNCHANGED. It is the only thing that ties this ' +
              'event to the request that asked for it — without it a ' +
              'receiver watching two streams cannot tell which one just ' +
              'answered.' }
    ],
    required: [],
    what: 'THE ONLY END-TO-END TEST A STREAM HAS. Everything else a ' +
          'receiver can do — create the stream, read it back, add a subject ' +
          '— exercises the management API and proves nothing about whether ' +
          'an event can actually be delivered. This travels the ordinary ' +
          'delivery path, so a 202 from the receiver\'s push endpoint (or a ' +
          'poll that returns it) is the first evidence the pipe works.',
    generate: function (values) {
      const payload = {};
      if (values && typeof values.state === 'string' && values.state !== '') {
        payload.state = values.state;
      }
      return payload;
    }
  },
  {
    uri: SSF_PREFIX + 'stream-updated',
    family: 'ssf',
    name: 'Stream Updated',
    subject: 'none',
    members: [
      { name: 'status', required: true, type: 'enum',
        values: ['enabled', 'paused', 'disabled'],
        what: 'The stream\'s new status.' },
      { name: 'reason', required: false, type: 'string',
        what: 'Why, in words, for a person reading a log. Nothing parses it.' }
    ],
    required: ['status'],
    what: 'The stream\'s status changed and the receiver is being told IN ' +
          'BAND. It is the one event a receiver gets without asking for it, ' +
          'and the one whose absence is hardest to notice: a stream quietly ' +
          'paused at the transmitter looks exactly like a service where ' +
          'nothing has happened lately.',
    generate: function (values) {
      const asked = values || {};
      const payload = {
        status: STATUSES.indexOf(asked.status) >= 0 ? asked.status : 'enabled'
      };
      if (typeof asked.reason === 'string' && asked.reason !== '') {
        payload.reason = asked.reason;
      }
      return payload;
    }
  }
];

// The three stream statuses of SSF 1.0 section 7.1.2, in the order a stream
// moves through them. Exported because the status endpoint, the console and
// the stream-updated event above all have to agree on the spelling.
const STATUSES = ['enabled', 'paused', 'disabled'];

const EVENT_BY_URI = {};
EVENTS.forEach(function (row) {
  EVENT_BY_URI[row.uri] = row;
});

const EVENT_URIS = EVENTS.map(function (row) {
  return row.uri;
});

// ---------------------------------------------------------------------------
// WHICH EVENT TYPES THIS TRANSMITTER SUPPORTS, which is a CONFIGURATION
// question and not a code one.
//
// `ssf.eventsSupported` is a list, defaulting to every URI above, so that a
// deployment can advertise a narrower set and a client's "you offered me an
// event type you will not deliver" path becomes reachable. An entry naming an
// event this service does not implement is dropped with a warning rather than
// advertised — advertising one would produce a stream whose `events_delivered`
// promises something nothing can send.
// ---------------------------------------------------------------------------
function supportedEventUris() {
  log.debug('Entering supportedEventUris().');
  const asked = config.value('ssf.eventsSupported');
  const list = Array.isArray(asked)
    ? asked
    : String(asked || '').split(',');
  const chosen = [];
  list.map(function (one) {
    return String(one).trim();
  }).filter(Boolean).forEach(function (uri) {
    if (!EVENT_BY_URI[uri]) {
      log.warn('ssf.eventsSupported names "' + uri + '", which this ' +
               'service does not implement. It is NOT advertised — a ' +
               'transmitter that offered it would agree a stream it can ' +
               'never deliver on.');
      return;
    }
    if (chosen.indexOf(uri) < 0) {
      chosen.push(uri);
    }
  });
  const out = chosen.length ? chosen : EVENT_URIS.slice();
  log.debug('Leaving supportedEventUris(). ' + out.length + ' type(s).');
  return out;
}

// ---------------------------------------------------------------------------
// VALIDATE ONE EVENT PAYLOAD AGAINST ITS CATALOGUE ROW.
//
// Collected errors again, and for the reason `ssf_subjects.js` gives: an event
// built on a form is usually wrong in more than one way.
//
// **AN UNRECOGNISED MEMBER IS A WARNING AND NOT AN ERROR, WHICH IS THE
// OPPOSITE OF THE SUBJECT RULE, AND THE DIFFERENCE IS THE
// SPECIFICATIONS' OWN.**
// RFC 9493 closes a Subject Identifier's member set because an unrecognised
// member might NARROW the subject. An event payload has no such rule — the
// vocabularies extend, and a receiver is expected to ignore what it does not
// know. Refusing here would make this service unable to carry a vendor's own
// extension, which is exactly what a debugger is for.
// ---------------------------------------------------------------------------
function validateEvent(uri, payload) {
  log.debug('Entering validateEvent(). ' + uri);
  const errors = [];
  const warnings = [];
  const row = EVENT_BY_URI[uri];
  if (!row) {
    errors.push('"' + uri + '" is not an event type this service knows. ' +
        'The ones it does are: ' + EVENT_URIS.join(', ') + '.');
    log.debug('Leaving validateEvent(). Unknown type.');
    return { ok: false, errors: errors, warnings: warnings };
  }
  const body = (payload && typeof payload === 'object' &&
                !Array.isArray(payload)) ? payload : null;
  if (!body) {
    errors.push('The payload of "' + uri + '" must be a JSON object. An ' +
        'event with nothing to say still carries {} — the event TYPE is the ' +
        'key in the events map and the payload is its value.');
    log.debug('Leaving validateEvent(). Not an object.');
    return { ok: false, errors: errors, warnings: warnings };
  }
  const known = {};
  row.members.forEach(function (member) {
    known[member.name] = member;
  });
  row.required.forEach(function (name) {
    if (!Object.prototype.hasOwnProperty.call(body, name)) {
      errors.push('"' + uri + '" requires a "' + name + '" member.');
    }
  });
  Object.keys(body).forEach(function (name) {
    const member = known[name];
    if (!member) {
      warnings.push('"' + name + '" is not a member "' + uri + '" defines. ' +
          'It is CARRIED rather than refused: an event vocabulary extends, ' +
          'and a receiver is expected to ignore what it does not know.');
      return;
    }
    const value = body[name];
    if (member.type === 'string' && typeof value !== 'string') {
      errors.push('"' + name + '" must be a string.');
      return;
    }
    if (member.type === 'enum') {
      if (member.values.indexOf(value) < 0) {
        errors.push('"' + name + '" must be one of ' +
            member.values.join(', ') + '.');
      }
    }
  });
  log.debug('Leaving validateEvent(). ' + errors.length + ' problem(s).');
  return { ok: errors.length === 0, errors: errors, warnings: warnings };
}

// ---------------------------------------------------------------------------
// BUILD THE CLAIM SET OF ONE SET.
//
// `stream` supplies `iss` and `aud`; the rest is the event. Returned UNSIGNED,
// because two callers want it that way for different reasons: the console
// shows what is about to be sent, and `signSet()` below signs it. A builder
// that only ever returned a signed token would make "show me what you are
// going to send" impossible without signing something nobody asked for.
//
// `jti` IS THE DEDUPLICATION KEY and it is what a poll acknowledgement names,
// so it is generated here and never taken from a caller: a transmitter that
// let somebody choose one could be made to overwrite an event a receiver had
// not read.
// ---------------------------------------------------------------------------
function buildSet(options) {
  log.debug('Entering buildSet().');
  const asked = options || {};
  const events = {};
  events[asked.uri] = asked.payload || {};
  const claims = {
    iss: String(asked.issuer || ''),
    jti: randomId(16),
    iat: nowSec(),
    aud: asked.audience,
    events: events
  };
  if (asked.subject) {
    claims.sub_id = asked.subject;
  }
  if (asked.txn) {
    claims.txn = String(asked.txn);
  }
  if (typeof asked.toe === 'number') {
    // The Time Of Event (RFC 8417 section 2.2), which is NOT `iat`: a token
    // minted now may report something that happened an hour ago, and a
    // receiver deciding whether to end a session cares about the second one.
    claims.toe = asked.toe;
  }
  if (config.value('ssf.legacySubClaim') && asked.subject &&
      typeof asked.subject.sub === 'string') {
    // The deliberate defect. RFC 8417 discourages `sub` on a SET and SSF uses
    // `sub_id`; a client written against a transmitter that emits `sub`
    // anyway will silently read nothing here, which is precisely the failure
    // worth being able to reproduce. See ssf.legacySubClaim.
    claims.sub = asked.subject.sub;
  }
  log.debug('Leaving buildSet(). jti=' + claims.jti);
  return claims;
}

// Which algorithm a SET is signed with. It is a setting rather than a
// constant because this is the document in this service most worth signing
// post-quantum: a SET is a durable record read long after it was written.
function signingAlgorithm() {
  log.debug('Entering signingAlgorithm().');
  const alg = String(config.value('ssf.signingAlgorithm') || 'RS256');
  log.debug('Leaving signingAlgorithm(). ' + alg);
  return alg;
}

// ---------------------------------------------------------------------------
// SIGN ONE SET.
//
// **IT IS ASYNCHRONOUS AND MUST STAY THAT WAY.** `ssf.signingAlgorithm` can
// name SLH-DSA, and an SLH-DSA-SHAKE-128s signature measured 14.6 seconds on
// this service's own thread — during which it answers nobody. `signJwtAsAsync`
// routes a post-quantum signature to the worker pool and resolves an RS256 one
// in place, so the cost is paid only where it is real. See common/worker.js.
//
// `ssf.breakSetSignature` is the deliberate defect for this family, the same
// device as `oauth2.breakIdTokenNonce`: it flips one byte of the signature
// AFTER signing, so a receiver that does not verify accepts an event that
// nothing signed. That path is unreachable against a correct transmitter,
// which is exactly why a debugger needs it.
// ---------------------------------------------------------------------------
function signSet(claims, options) {
  log.debug('Entering signSet().');
  const settings = options || {};
  const alg = settings.algorithm || signingAlgorithm();
  return signJwtAsAsync(claims, alg, null, { session: settings.session,
    // RFC 8417 section 2.2's media type, and it is a SHOULD that behaves
    // like a MUST: a receiver that dispatches on `typ` — and several do —
    // drops a token without it with no error anybody sees. It is asked for
    // HERE rather than being a default in the signer, because everything
    // else this service mints is an ordinary JWT and would be wrong to
    // relabel.
    header: { typ: SET_MEDIA_TYPE } })
    .then(function (token) {
      if (!config.value('ssf.breakSetSignature')) {
        log.debug('Leaving signSet(). Signed with ' + alg + '.');
        return token;
      }
      log.debug('Leaving signSet(). Signed with ' + alg +
                ', then BROKEN on purpose.');
      return breakSignature(token);
    });
}

// Change one base64url character of the signature. It has to be a CHARACTER
// change rather than a truncation, because a truncated signature is refused by
// the base64url decode and never reaches the verify — a client would then
// report a MALFORMED TOKEN rather than a BAD SIGNATURE, and those are two
// different bugs for whoever is being tested.
//
// **IT IS THE FIRST CHARACTER AND NOT THE LAST, AND THAT IS NOT A STYLE
// CHOICE.** The last character of a base64url string usually carries PADDING
// BITS that the decoder discards: an RS256 signature is 256 bytes, which is
// 2048 bits in 342 base64url characters of 6 bits each, so the final character
// has four bits nothing reads. Changing `A` to `B` there produces a token that
// looks altered, decodes to THE SAME BYTES, and verifies perfectly — a
// deliberate defect that is not a defect, which is worse than none at all
// because a test would pass against it. The first character is always
// significant.
function breakSignature(token) {
  log.debug('Entering breakSignature().');
  const parts = String(token).split('.');
  if (parts.length !== 3 || !parts[2].length) {
    log.debug('Leaving breakSignature(). Nothing to break.');
    return token;
  }
  const first = parts[2].charAt(0);
  const replacement = first === 'A' ? 'B' : 'A';
  parts[2] = replacement + parts[2].slice(1);
  log.debug('Leaving breakSignature(). One character changed.');
  return parts.join('.');
}

// The synchronous signer, for the two places that cannot await: the console's
// preview and a test fixture. It refuses a post-quantum algorithm by name
// rather than blocking the thread for fifteen seconds, and says which call to
// use instead.
function signSetSync(claims, options) {
  log.debug('Entering signSetSync().');
  const settings = options || {};
  const alg = settings.algorithm || signingAlgorithm();
  const token = signJwtAs(claims, alg, null,
                          { header: { typ: SET_MEDIA_TYPE } });
  log.debug('Leaving signSetSync(). ' + alg);
  return token;
}

// What a SET this service signed says about itself, for the pages that show
// one. It parses rather than verifies — the token was made here.
function describeSet(claims) {
  log.debug('Entering describeSet().');
  const uris = Object.keys((claims && claims.events) || {});
  const row = uris.length ? EVENT_BY_URI[uris[0]] : null;
  const out = {
    jti: String((claims && claims.jti) || ''),
    iat: Number((claims && claims.iat) || 0),
    issuer: String((claims && claims.iss) || ''),
    audience: (claims && claims.aud) || '',
    types: uris,
    name: row ? row.name : (uris[0] || '(no event)'),
    subject: (claims && claims.sub_id)
      ? subjects.describeSubject(claims.sub_id)
      : ''
  };
  log.debug('Leaving describeSet(). ' + out.name);
  return out;
}

module.exports = {
  SSF_PREFIX: SSF_PREFIX,
  EVENTS: EVENTS,
  EVENT_URIS: EVENT_URIS,
  EVENT_BY_URI: EVENT_BY_URI,
  STATUSES: STATUSES,
  supportedEventUris: supportedEventUris,
  validateEvent: validateEvent,
  buildSet: buildSet,
  signSet: signSet,
  signSetSync: signSetSync,
  signingAlgorithm: signingAlgorithm,
  describeSet: describeSet,
  SET_MEDIA_TYPE: SET_MEDIA_TYPE,
  STS: STS
};
