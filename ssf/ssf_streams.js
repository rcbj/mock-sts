'use strict';
//
// File: ssf_streams.js
//
// ---------------------------------------------------------------------------
// THE STREAMS, THEIR SUBJECTS AND THEIR EVENT QUEUES.
//
// A STREAM is the whole of the relationship between a transmitter and a
// receiver: who the events are about, which types are delivered, and by which
// of the two delivery methods. Everything the Shared Signals Framework's
// management API does is a read or a write of one of these records, so this is
// where they live and it is the only place they live.
//
// ---------------------------------------------------------------------------
// IT IS PER REALM, AND THAT IS A DECISION RATHER THAN A CONVENTION.
//
// `realms.map()` rather than `new Map()`, for the reason `common/CLAUDE.md`
// gives and for one specific to this family: a stream carries an `iss`, and
// the issuer of a realm is that realm's own. A process-wide stream store would
// let a receiver create a stream in the default realm and read it back at
// `/realm/acme/ssf/stream` with a different issuer on it, which is not a
// tidiness problem — it is one receiver reading another tenant's delivery
// endpoint and authorization header.
//
// **AND THE SAME GOES FOR THE QUEUES.** They are on the stream record, so they
// are partitioned by construction rather than by a second call to `realms`.
// That is the shape `common/CLAUDE.md` warns about getting half right: the two
// halves of one claim set were held in two modules and only one was per realm.
//
// ---------------------------------------------------------------------------
// WHAT THIS SERVICE KEEPS AND WHAT IT DOES NOT.
//
// Streams are IN MEMORY and die with the process, like every other thing this
// service mints. `persistence/CLAUDE.md`'s rule decides it and the reason is
// the same one it gives everywhere: the signing key is regenerated on every
// start, so a queue of SETs restored from disk would be a queue of tokens
// nothing can verify. A receiver that reconnects after a restart creates its
// stream again, which is what a receiver has to be able to do anyway.
//
// ---------------------------------------------------------------------------
// EVERY LIMIT HERE IS A SETTING AND EVERY ONE OF THEM IS A REACHABLE
// NEGATIVE.
//
// A mock's job is to let a client's error paths run. `ssf.maxStreams`,
// `ssf.maxSubjectsPerStream` and `ssf.maxQueuedEvents` each produce a specific
// refusal a receiver would otherwise never see, and each says which setting it
// was — because "409" with no explanation is the least useful thing a mock can
// answer.
//
// ---------------------------------------------------------------------------
// IT IS A LIBRARY (rule 3). It registers no route. It requires `helpers.js`,
// `config.js`, `realms.js`, `ssf_subjects.js` and `ssf_events.js`, none of
// which requires it, so it cannot join a cycle.
// ---------------------------------------------------------------------------

const { log, randomId, iso } = require('../common/helpers');
const config = require('../common/config');
const realms = require('../common/realms');
const subjects = require('./ssf_subjects');
const events = require('./ssf_events');

// stream_id -> stream record, one partition per trust realm.
const streams = realms.map();

// What this service has RECEIVED, when the debugger is the transmitter and
// this service is the receiver. Also per realm, and capped the same way.
const received = realms.arr();

// The two delivery method URNs of SSF 1.0 section 7.1.1. They are the RFC
// numbers as URNs rather than names, which catches everybody once: a stream
// asking for "push" is asking for nothing this specification defines.
const DELIVERY_PUSH = 'urn:ietf:rfc:8935';
const DELIVERY_POLL = 'urn:ietf:rfc:8936';

const DELIVERY_METHODS = [
  { method: DELIVERY_PUSH, name: 'Push (RFC 8935)',
    what: 'The transmitter POSTs each SET to a URL the receiver gave it. ' +
          'The receiver has to be reachable, which is what makes this the ' +
          'hard one for a browser: a page cannot be an HTTP server, so the ' +
          'debugger hosts its receiver endpoint in its api layer.' },
  { method: DELIVERY_POLL, name: 'Poll (RFC 8936)',
    what: 'The receiver POSTs to the transmitter and is handed whatever has ' +
          'queued up, acknowledging what it read. Nothing has to be ' +
          'reachable but the transmitter, which is why a browser can be a ' +
          'receiver over this method and not over the other one.' }
];

function limit(key, fallback) {
  log.debug('Entering limit(). ' + key);
  const value = Number(config.value(key));
  const out = (Number.isFinite(value) && value > 0) ? value : fallback;
  log.debug('Leaving limit(). ' + out);
  return out;
}

// ---------------------------------------------------------------------------
// CREATE.
//
// `asked` is the Stream Configuration the receiver posted. What comes back is
// `{ ok, stream, errors }` — the record as this service will keep it, with
// every member the transmitter owns filled in by this service and never by the
// caller:
//
//   * `stream_id` is minted here. A receiver that could choose one could
//     overwrite somebody else's stream.
//   * `iss` is this realm's issuer. A stream whose issuer the receiver chose
//     would produce SETs claiming to come from wherever it said.
//   * `events_delivered` is the INTERSECTION of what the receiver requested
//     and what this transmitter supports, which is the specification's own
//     arrangement and the member most often confused with `events_requested`:
//     one is the ask and the other is the answer, and a receiver that reads
//     the first back as the second believes it will get event types nothing
//     will send.
// ---------------------------------------------------------------------------
function createStream(asked, context) {
  log.debug('Entering createStream().');
  const body = (asked && typeof asked === 'object') ? asked : {};
  const ctx = context || {};
  const errors = [];
  const store = streams;

  const max = limit('ssf.maxStreams', 25);
  if (store.size >= max) {
    errors.push('This transmitter is holding ' + store.size + ' stream(s) ' +
        'and ssf.maxStreams is ' + max + '. Delete one, or raise the ' +
        'setting on /admin/ssf.');
    log.debug('Leaving createStream(). At the stream limit.');
    return { ok: false, stream: null, errors: errors };
  }

  const delivery = normaliseDelivery(body.delivery, errors);
  const audience = normaliseAudience(body.aud, ctx, errors);
  const requested = normaliseEventList(body.events_requested);
  const supported = events.supportedEventUris();
  const delivered = requested.length
    ? requested.filter(function (uri) {
        return supported.indexOf(uri) >= 0;
      })
    : supported.slice();

  requested.forEach(function (uri) {
    if (supported.indexOf(uri) < 0) {
      // NOT an error. SSF 1.0 section 7.1.1 says the transmitter answers with
      // what it WILL deliver, so an unsupported request is answered by its
      // absence from events_delivered rather than by a refusal — and a
      // receiver that compares the two lists finds out exactly this.
      log.debug('createStream(): "' + uri + '" was requested and is not ' +
                'supported, so it is absent from events_delivered.');
    }
  });

  const format = String(body.format || '');
  if (format && subjects.FORMAT_NAMES.indexOf(format) < 0) {
    errors.push('"format" is "' + format + '", which is not one of RFC ' +
        '9493\'s eight Subject Identifier formats: ' +
        subjects.FORMAT_NAMES.join(', ') + '. It is the format this ' +
        'transmitter will name a DEFAULT subject in.');
  }

  const interval = Number(body.min_verification_interval);
  const configured = limit('ssf.minVerificationInterval', 60);
  if (Number.isFinite(interval) && interval > 0 && interval < configured) {
    errors.push('"min_verification_interval" is ' + interval + ' seconds ' +
        'and this transmitter will not go below ' + configured +
        ' (ssf.minVerificationInterval). The member is the TRANSMITTER\'s ' +
        'statement rather than the receiver\'s request, which is why a ' +
        'smaller value is refused instead of being accepted and ignored.');
  }

  if (errors.length) {
    log.debug('Leaving createStream(). ' + errors.length + ' problem(s).');
    return { ok: false, stream: null, errors: errors };
  }

  const now = iso();
  const record = {
    stream_id: 'ssf-' + randomId(12),
    iss: String(ctx.issuer || ''),
    aud: audience,
    delivery: delivery,
    events_supported: supported.slice(),
    events_requested: requested.slice(),
    events_delivered: delivered,
    format: format,
    min_verification_interval: configured,
    description: String(body.description || ''),
    status: String(config.value('ssf.streamStatusOnCreate') || 'enabled'),
    statusReason: 'created',
    createdAt: now,
    updatedAt: now,
    createdBy: String(ctx.principal || '(unauthenticated)'),
    subjects: [],
    queue: [],
    log: [],
    counters: { queued: 0, delivered: 0, failed: 0, acknowledged: 0,
      pollCalls: 0, pushCalls: 0, receiverErrors: 0 },
    lastPushError: '',
    lastPushAt: '',
    lastVerificationAt: 0
  };
  store.set(record.stream_id, record);
  note(record, 'created', 'The stream was created with ' +
       record.events_delivered.length + ' event type(s) and ' +
       deliveryName(record.delivery.method) + ' delivery.');
  log.debug('Leaving createStream(). ' + record.stream_id);
  return { ok: true, stream: record, errors: [] };
}

function deliveryName(method) {
  log.debug('Entering deliveryName().');
  const row = DELIVERY_METHODS.filter(function (one) {
    return one.method === method;
  })[0];
  log.debug('Leaving deliveryName().');
  return row ? row.name : String(method || '(none)');
}

// ---------------------------------------------------------------------------
// The `delivery` member, which is the one part of a Stream Configuration a
// receiver genuinely owns and the one with a security consequence: its
// `endpoint_url` is a URL THIS SERVICE WILL DIAL. `ssf_http.js` argues that at
// length; what happens HERE is the shape check.
// ---------------------------------------------------------------------------
function normaliseDelivery(asked, errors) {
  log.debug('Entering normaliseDelivery().');
  const offered = offeredDeliveryMethods();
  const body = (asked && typeof asked === 'object' && !Array.isArray(asked))
    ? asked : {};
  const method = String(body.method || '');
  if (!method) {
    // SSF 1.0 makes `delivery` optional on a create and says the transmitter
    // picks. Poll is the safe default and the honest one: it dials nothing.
    const fallback = offered.indexOf(DELIVERY_POLL) >= 0
      ? DELIVERY_POLL : offered[0];
    log.debug('Leaving normaliseDelivery(). Defaulted to ' + fallback + '.');
    return { method: fallback, endpoint_url: '', authorization_header: '' };
  }
  if (offered.indexOf(method) < 0) {
    errors.push('"delivery.method" is "' + method + '". This transmitter ' +
        'offers ' + offered.join(' and ') + ' (ssf.deliveryMethods). Note ' +
        'the values are the RFC numbers as URNs — "push" and "poll" are not ' +
        'method identifiers, which catches everybody once.');
    log.debug('Leaving normaliseDelivery(). Unoffered method.');
    return { method: method, endpoint_url: '', authorization_header: '' };
  }
  if (method === DELIVERY_POLL) {
    if (body.endpoint_url) {
      // RFC 8936's poll endpoint is the TRANSMITTER's, published in the
      // stream configuration by the transmitter. A receiver sending one is
      // describing an endpoint of its own that nothing will ever call, which
      // is worth saying rather than ignoring.
      errors.push('"delivery.endpoint_url" was sent with a POLL method. On ' +
          'poll delivery the endpoint is the TRANSMITTER\'s and this ' +
          'service publishes it in the stream configuration it hands back — ' +
          'a receiver-supplied one would be a URL nothing calls.');
    }
    log.debug('Leaving normaliseDelivery(). Poll.');
    return { method: DELIVERY_POLL, endpoint_url: '',
      authorization_header: '' };
  }
  const url = String(body.endpoint_url || '');
  if (!url) {
    errors.push('"delivery.endpoint_url" is required for push delivery — it ' +
        'is where this transmitter POSTs each SET.');
  }
  log.debug('Leaving normaliseDelivery(). Push.');
  return { method: DELIVERY_PUSH, endpoint_url: url,
    authorization_header: String(body.authorization_header || '') };
}

// Which delivery methods this deployment offers. A list, so that a client's
// "you do not do push" path is reachable by configuration rather than by a
// second service.
function offeredDeliveryMethods() {
  log.debug('Entering offeredDeliveryMethods().');
  const asked = config.value('ssf.deliveryMethods');
  const list = Array.isArray(asked) ? asked : String(asked || '').split(',');
  const chosen = [];
  list.map(function (one) {
    return String(one).trim();
  }).filter(Boolean).forEach(function (name) {
    const urn = name === 'push' ? DELIVERY_PUSH
      : name === 'poll' ? DELIVERY_POLL : name;
    const known = DELIVERY_METHODS.some(function (row) {
      return row.method === urn;
    });
    if (!known) {
      log.warn('ssf.deliveryMethods names "' + name + '", which is not a ' +
               'delivery method SSF defines. It is ignored.');
      return;
    }
    if (chosen.indexOf(urn) < 0) {
      chosen.push(urn);
    }
  });
  const out = chosen.length ? chosen : [DELIVERY_PUSH, DELIVERY_POLL];
  log.debug('Leaving offeredDeliveryMethods(). ' + out.length + '.');
  return out;
}

// The `aud` of every SET on this stream. A string or an array, exactly as the
// receiver sent it, because RFC 8417's `aud` is JWT's `aud` and a receiver
// that registered an array checks for itself in an array.
//
// **IT IS REQUIRED AND IT IS NOT DEFAULTED TO THE AUTHENTICATED CALLER**,
// which is a decision rather than an omission and it is the one place this
// module is stricter than the rest of this service. Defaulting was written
// first and taken out: a receiver whose `aud` was invented for it never finds
// out that the member is required, and the first real transmitter it meets
// refuses every stream it creates. Worse, the audience a receiver checks for
// ITSELF in would then be a name this service chose — so an event it should
// refuse with `invalid_audience` would be one it accepts.
//
// The permissive posture everywhere else in this service is about
// CREDENTIALS. This is a protocol member with a consequence at the far end,
// and inventing one teaches a client something false.
function normaliseAudience(asked, context, errors) {
  log.debug('Entering normaliseAudience().');
  if (typeof asked === 'string' && asked !== '') {
    log.debug('Leaving normaliseAudience(). One string.');
    return asked;
  }
  if (Array.isArray(asked)) {
    const list = asked.map(function (one) {
      return String(one);
    }).filter(Boolean);
    if (!list.length) {
      errors.push('"aud" is an empty array. Every SET on this stream would ' +
          'be addressed to nobody.');
    }
    log.debug('Leaving normaliseAudience(). ' + list.length + ' value(s).');
    return list;
  }
  errors.push('"aud" is required — it is who the SETs on this stream are ' +
      'addressed to, and a receiver checks for ITSELF in it. It is not ' +
      'defaulted to whoever authenticated: an audience this transmitter ' +
      'invented would be one the receiver never learns it has to send, and ' +
      'an event it ought to refuse with invalid_audience would be one it ' +
      'accepts.');
  log.debug('Leaving normaliseAudience(). Missing.');
  return '';
}

function normaliseEventList(asked) {
  log.debug('Entering normaliseEventList().');
  const list = Array.isArray(asked) ? asked : [];
  const out = list.map(function (one) {
    return String(one);
  }).filter(Boolean);
  log.debug('Leaving normaliseEventList(). ' + out.length + '.');
  return out;
}

function getStream(id) {
  log.debug('Entering getStream(). ' + id);
  const record = streams.get(String(id || '')) || null;
  log.debug('Leaving getStream(). ' + (record ? 'found' : 'not found'));
  return record;
}

function listStreams() {
  log.debug('Entering listStreams().');
  const out = [];
  streams.forEach(function (record) {
    out.push(record);
  });
  out.sort(function (a, b) {
    return String(a.createdAt).localeCompare(String(b.createdAt));
  });
  log.debug('Leaving listStreams(). ' + out.length + '.');
  return out;
}

function removeStream(id) {
  log.debug('Entering removeStream(). ' + id);
  const gone = streams.delete(String(id || ''));
  log.debug('Leaving removeStream(). ' + gone);
  return gone;
}

// ---------------------------------------------------------------------------
// UPDATE, in the two shapes SSF 1.0 section 7.1.1 gives it.
//
//   'replace'  (PUT)   every member the receiver may set is taken from the
//                      body, and one it omits goes back to its default.
//   'merge'    (PATCH) only the members present are changed.
//
// The distinction is the one every REST API has and the one every REST API
// gets wrong in the same direction: a PUT that behaved like a PATCH would let
// a receiver believe it had cleared `events_requested` when it had not, and
// the symptom is event types still arriving after they were "removed".
// ---------------------------------------------------------------------------
function updateStream(id, asked, mode, context) {
  log.debug('Entering updateStream(). ' + id + ' ' + mode);
  const record = getStream(id);
  if (!record) {
    log.debug('Leaving updateStream(). No such stream.');
    return { ok: false, stream: null,
      errors: ['No stream with stream_id "' + String(id) + '".'] };
  }
  const body = (asked && typeof asked === 'object') ? asked : {};
  const replace = mode === 'replace';
  const errors = [];
  const has = function (name) {
    return Object.prototype.hasOwnProperty.call(body, name);
  };

  if (replace || has('delivery')) {
    const delivery = normaliseDelivery(body.delivery, errors);
    record.delivery = delivery;
  }
  if (replace || has('aud')) {
    record.aud = normaliseAudience(body.aud, context, errors);
  }
  if (replace || has('events_requested')) {
    const requested = normaliseEventList(body.events_requested);
    const supported = events.supportedEventUris();
    record.events_requested = requested;
    record.events_supported = supported.slice();
    record.events_delivered = requested.length
      ? requested.filter(function (uri) {
          return supported.indexOf(uri) >= 0;
        })
      : supported.slice();
  }
  if (replace || has('format')) {
    const format = String(body.format || '');
    if (format && subjects.FORMAT_NAMES.indexOf(format) < 0) {
      errors.push('"format" is "' + format + '", which is not one of RFC ' +
          '9493\'s eight Subject Identifier formats.');
    } else {
      record.format = format;
    }
  }
  if (replace || has('description')) {
    record.description = String(body.description || '');
  }

  if (errors.length) {
    log.debug('Leaving updateStream(). ' + errors.length + ' problem(s).');
    return { ok: false, stream: null, errors: errors };
  }
  record.updatedAt = iso();
  note(record, 'updated', (replace ? 'Replaced' : 'Merged') +
       ' — now delivering ' + record.events_delivered.length +
       ' event type(s) over ' + deliveryName(record.delivery.method) + '.');
  log.debug('Leaving updateStream(). Updated.');
  return { ok: true, stream: record, errors: [] };
}

// ---------------------------------------------------------------------------
// STATUS.
//
// Three values, and the middle one is the one worth knowing about: a PAUSED
// stream keeps QUEUEING and delivers nothing, so the events that happened
// while it was paused are still there when it is enabled again. A DISABLED one
// drops them. SSF 1.0 section 7.1.2 says exactly that, and it is the
// difference between "I was not listening" and "it did not happen" — which is
// the whole reason a Shared Signals receiver has a pause at all.
// ---------------------------------------------------------------------------
function setStatus(id, status, reason) {
  log.debug('Entering setStatus(). ' + id + ' -> ' + status);
  const record = getStream(id);
  if (!record) {
    log.debug('Leaving setStatus(). No such stream.');
    return { ok: false, stream: null,
      errors: ['No stream with stream_id "' + String(id) + '".'] };
  }
  if (events.STATUSES.indexOf(status) < 0) {
    log.debug('Leaving setStatus(). Unknown status.');
    return { ok: false, stream: null,
      errors: ['"' + String(status) + '" is not a stream status. SSF 1.0 ' +
        'section 7.1.2 defines ' + events.STATUSES.join(', ') + '.'] };
  }
  const before = record.status;
  record.status = status;
  record.statusReason = String(reason || '');
  record.updatedAt = iso();
  if (status === 'disabled' && record.queue.length) {
    // Deliberate, and the sentence above is why. A disabled stream is not a
    // paused one: what was waiting is dropped, and the count is reported so
    // that a reader can see it happen rather than discovering later that the
    // queue is empty.
    note(record, 'status', 'Disabled — ' + record.queue.length +
         ' queued event(s) were DROPPED. A paused stream would have kept ' +
         'them; that is the whole difference between the two.');
    record.queue.length = 0;
  } else {
    note(record, 'status', before + ' -> ' + status +
         (reason ? ' (' + reason + ')' : ''));
  }
  log.debug('Leaving setStatus(). ' + before + ' -> ' + status);
  return { ok: true, stream: record, errors: [] };
}

// ---------------------------------------------------------------------------
// SUBJECTS.
//
// A stream's subject list is who it is about. `ssf.defaultSubjects` decides
// what an empty list MEANS, and the two answers are opposites:
//
//   ALL    the stream is about everybody, and the list NARROWS nothing —
//          adding a subject to it is redundant.
//   NONE   the stream is about nobody until somebody is added.
//
// This service publishes the value in its metadata (`default_subjects`),
// because a receiver that guesses wrong either gets every event in the estate
// or gets none, and both look like a broken transmitter.
// ---------------------------------------------------------------------------
function addSubject(id, subject, verified, options) {
  log.debug('Entering addSubject(). ' + id);
  const record = getStream(id);
  if (!record) {
    log.debug('Leaving addSubject(). No such stream.');
    return { ok: false, errors: ['No stream with stream_id "' +
      String(id) + '".'] };
  }
  const verdict = subjects.validateSubjectId(subject, {
    path: 'subject',
    criticalMembers: (options || {}).criticalMembers || []
  });
  if (!verdict.ok) {
    log.debug('Leaving addSubject(). Invalid subject.');
    return { ok: false, errors: verdict.errors };
  }
  const max = limit('ssf.maxSubjectsPerStream', 100);
  const key = subjects.subjectKey(subject);
  const existing = record.subjects.filter(function (one) {
    return one.key === key;
  })[0];
  if (existing) {
    existing.verified = verified !== false;
    existing.updatedAt = iso();
    log.debug('Leaving addSubject(). Already present.');
    return { ok: true, errors: [], added: false, subject: existing };
  }
  if (record.subjects.length >= max) {
    log.debug('Leaving addSubject(). At the subject limit.');
    return { ok: false, errors: ['This stream already names ' +
      record.subjects.length + ' subject(s) and ssf.maxSubjectsPerStream ' +
      'is ' + max + '.'] };
  }
  const entry = {
    key: key,
    subject: subject,
    // RFC-wise this is the `verified` member of the Add Subject request: the
    // receiver saying it has already checked that the subject is one it cares
    // about. This service records it and refuses nothing on it, which is the
    // posture the rest of the service takes — see ssf/CLAUDE.md.
    verified: verified !== false,
    addedAt: iso(),
    updatedAt: iso()
  };
  record.subjects.push(entry);
  record.updatedAt = iso();
  note(record, 'subject', 'Added ' + subjects.describeSubject(subject) +
       (entry.verified ? '' : ' (unverified)'));
  log.debug('Leaving addSubject(). Added.');
  return { ok: true, errors: [], added: true, subject: entry };
}

function removeSubject(id, subject) {
  log.debug('Entering removeSubject(). ' + id);
  const record = getStream(id);
  if (!record) {
    log.debug('Leaving removeSubject(). No such stream.');
    return { ok: false, errors: ['No stream with stream_id "' +
      String(id) + '".'] };
  }
  const verdict = subjects.validateSubjectId(subject, { path: 'subject' });
  if (!verdict.ok) {
    log.debug('Leaving removeSubject(). Invalid subject.');
    return { ok: false, errors: verdict.errors };
  }
  const key = subjects.subjectKey(subject);
  const before = record.subjects.length;
  record.subjects = record.subjects.filter(function (one) {
    return one.key !== key;
  });
  record.updatedAt = iso();
  const removed = before !== record.subjects.length;
  note(record, 'subject', (removed ? 'Removed ' : 'Asked to remove ') +
       subjects.describeSubject(subject) +
       (removed ? '' : ', which was not on this stream. SSF 1.0 says a ' +
        'remove is idempotent, so this is a 204 rather than a 404.'));
  log.debug('Leaving removeSubject(). ' + removed);
  return { ok: true, errors: [], removed: removed };
}

// Whether an event about this subject belongs on this stream. `defaultSubjects`
// is what decides it when the list is empty; see the header above.
function streamCoversSubject(record, subject) {
  log.debug('Entering streamCoversSubject().');
  if (!subject) {
    // An event with no subject — the two SSF events — is about the STREAM and
    // goes to it whatever its subject list says.
    log.debug('Leaving streamCoversSubject(). No subject; always.');
    return true;
  }
  if (record.subjects.length) {
    const key = subjects.subjectKey(subject);
    const covered = record.subjects.some(function (one) {
      return one.key === key;
    });
    if (covered) {
      log.debug('Leaving streamCoversSubject(). Named exactly.');
      return true;
    }
    // -------------------------------------------------------------------
    // A COMPLEX SUBJECT IS COVERED BY A STREAM THAT NAMES ANY ONE OF ITS
    // MEMBERS, AND WITHOUT THIS RULE CAEP WOULD DELIVER NOTHING.
    //
    // A receiver adds the PERSON to a stream — that is the subject it has,
    // and the only one it can name in advance. A CAEP event about that
    // person names a SESSION of theirs, which SSF 1.0 section 4 expresses as
    // a complex subject whose `user` member is exactly the identifier the
    // receiver added. Those two are different `subjectKey()`s, so an
    // exact-match test refuses every session event to the receiver that
    // asked for the person — silently, because a transmitter's refusal to
    // send is not a message anybody receives.
    //
    // It is deliberately ONE LEVEL and not recursive: a complex subject may
    // not nest another (SSF section 4), so a member is always a plain
    // identifier and there is nothing below it to walk.
    // -------------------------------------------------------------------
    if (!subject.format) {
      const members = subjects.COMPLEX_MEMBER_NAMES.filter(function (name) {
        return subject[name] && typeof subject[name] === 'object';
      });
      const viaMember = members.some(function (name) {
        const memberKey = subjects.subjectKey(subject[name]);
        return record.subjects.some(function (one) {
          return one.key === memberKey;
        });
      });
      log.debug('Leaving streamCoversSubject(). By member: ' + viaMember);
      return viaMember;
    }
    log.debug('Leaving streamCoversSubject(). false');
    return false;
  }
  const all = String(config.value('ssf.defaultSubjects') || 'ALL')
    .toUpperCase() === 'ALL';
  log.debug('Leaving streamCoversSubject(). Empty list; ' + all);
  return all;
}

// ---------------------------------------------------------------------------
// THE QUEUE.
//
// Every SET goes on the stream's queue whatever the delivery method is, and
// push takes it off again straight away. That is one path rather than two, and
// it is what makes a stream that FAILS to push recoverable: the event is still
// there, `counters.failed` says what happened, and the console can show it.
// A push implementation that signed and posted in one breath would lose the
// event on the first refused connection with nothing to show for it.
// ---------------------------------------------------------------------------
function enqueue(record, entry) {
  log.debug('Entering enqueue(). ' + record.stream_id);
  if (record.status === 'disabled') {
    log.debug('Leaving enqueue(). The stream is disabled.');
    return { ok: false, reason: 'the stream is disabled' };
  }
  const max = limit('ssf.maxQueuedEvents', 200);
  if (record.queue.length >= max) {
    // The OLDEST goes, not the newest. A receiver that has stopped reading is
    // most likely to want what has happened LATELY, and a queue that refused
    // new events would make a transmitter stop recording because a receiver
    // stopped listening.
    const dropped = record.queue.shift();
    note(record, 'queue', 'The queue was full (ssf.maxQueuedEvents=' + max +
         '), so the oldest event (' + dropped.jti + ') was dropped.');
  }
  record.queue.push(entry);
  record.counters.queued += 1;
  log.debug('Leaving enqueue(). ' + record.queue.length + ' waiting.');
  return { ok: true, reason: '' };
}

// RFC 8936's poll. `ack` names what the receiver has now stored, so those come
// off the queue; `setErrs` names what it REFUSED, and those come off too — a
// receiver that cannot process an event will not process it next time either,
// and a transmitter that kept redelivering would poll-loop forever. The error
// is recorded on the stream so the refusal is visible to a person.
function poll(record, request) {
  log.debug('Entering poll(). ' + record.stream_id);
  const asked = (request && typeof request === 'object') ? request : {};
  record.counters.pollCalls += 1;
  const acks = Array.isArray(asked.ack) ? asked.ack.map(String) : [];
  const errs = (asked.setErrs && typeof asked.setErrs === 'object')
    ? asked.setErrs : {};
  acks.forEach(function (jti) {
    const before = record.queue.length;
    record.queue = record.queue.filter(function (one) {
      return one.jti !== jti;
    });
    if (before !== record.queue.length) {
      record.counters.acknowledged += 1;
    }
  });
  Object.keys(errs).forEach(function (jti) {
    const problem = errs[jti] || {};
    record.queue = record.queue.filter(function (one) {
      return one.jti !== jti;
    });
    record.counters.receiverErrors += 1;
    note(record, 'error', 'The receiver REFUSED ' + jti + ': ' +
         String(problem.err || '(no err)') + ' — ' +
         String(problem.description || '(no description)') + '. It is off ' +
         'the queue: a receiver that could not process an event will not ' +
         'process it next time either, and redelivering would poll-loop.');
  });

  if (record.status !== 'enabled') {
    log.debug('Leaving poll(). The stream is ' + record.status + '.');
    return { sets: {}, moreAvailable: false, status: record.status };
  }

  const cap = limit('ssf.pollMaxEvents', 20);
  const wanted = Number(asked.maxEvents);
  const take = (Number.isFinite(wanted) && wanted >= 0)
    ? Math.min(wanted, cap) : cap;
  const sets = {};
  record.queue.slice(0, take).forEach(function (one) {
    sets[one.jti] = one.token;
    one.deliveredAt = iso();
    if (!one.counted) {
      one.counted = true;
      record.counters.delivered += 1;
    }
  });
  const more = record.queue.length > take;
  log.debug('Leaving poll(). ' + Object.keys(sets).length + ' set(s), more=' +
            more);
  return { sets: sets, moreAvailable: more, status: record.status };
}

// One line on a stream's own log, which is what the console draws. Capped for
// the reason the queue is: a stream nobody deletes would otherwise grow
// without bound in a process that never restarts.
function note(record, kind, text) {
  log.debug('Entering note(). ' + kind);
  record.log.push({ at: iso(), kind: kind, text: String(text) });
  const max = limit('ssf.maxStreamLogEntries', 200);
  if (record.log.length > max) {
    record.log.splice(0, record.log.length - max);
  }
  log.debug('Leaving note().');
}

// ---------------------------------------------------------------------------
// WHAT THIS SERVICE HAS RECEIVED, when the roles are the other way round.
//
// The debugger can be a TRANSMITTER, and something has to be at the far end of
// its push. `POST /ssf/receive` is that, and this is where what arrives is
// kept — so a person can see, on `/admin/ssf`, that the thing they sent
// actually landed. It is deliberately NOT a stream: nothing was configured,
// nothing is delivered onwards, and treating it as one would invite the
// question of which stream a bare SET belongs to, which has no answer.
// ---------------------------------------------------------------------------
function recordReceived(entry) {
  log.debug('Entering recordReceived().');
  const list = received;
  list.push(entry);
  const max = limit('ssf.maxReceivedEvents', 200);
  if (list.length > max) {
    list.splice(0, list.length - max);
  }
  log.debug('Leaving recordReceived(). ' + list.length + ' held.');
  return entry;
}

function listReceived() {
  log.debug('Entering listReceived().');
  const out = received.slice();
  log.debug('Leaving listReceived(). ' + out.length + '.');
  return out;
}

function clearReceived() {
  log.debug('Entering clearReceived().');
  const list = received;
  const gone = list.length;
  list.length = 0;
  log.debug('Leaving clearReceived(). ' + gone + ' dropped.');
  return gone;
}

// The wire form of a stream configuration — what a receiver gets back from the
// management API. It is NOT the record: `subjects`, the queue, the log and the
// counters are this service's own bookkeeping and no member of SSF 1.0's
// Stream Configuration, so sending them would be inventing members a receiver
// might come to depend on.
function streamConfiguration(record, options) {
  log.debug('Entering streamConfiguration(). ' + record.stream_id);
  const settings = options || {};
  const delivery = { method: record.delivery.method };
  if (record.delivery.method === DELIVERY_PUSH) {
    delivery.endpoint_url = record.delivery.endpoint_url;
    if (record.delivery.authorization_header && settings.includeSecrets) {
      // ONLY back to the receiver that set it, and never on a console page or
      // in the management API's listing: it is a credential belonging to
      // somebody else's endpoint. `includeSecrets` is set by exactly one
      // caller for that reason.
      delivery.authorization_header = record.delivery.authorization_header;
    }
  } else {
    delivery.endpoint_url = settings.pollEndpoint || '';
  }
  const out = {
    stream_id: record.stream_id,
    iss: record.iss,
    aud: record.aud,
    events_supported: record.events_supported,
    events_requested: record.events_requested,
    events_delivered: record.events_delivered,
    delivery: delivery,
    min_verification_interval: record.min_verification_interval,
    format: record.format,
    description: record.description
  };
  log.debug('Leaving streamConfiguration().');
  return out;
}

module.exports = {
  DELIVERY_PUSH: DELIVERY_PUSH,
  DELIVERY_POLL: DELIVERY_POLL,
  DELIVERY_METHODS: DELIVERY_METHODS,
  offeredDeliveryMethods: offeredDeliveryMethods,
  deliveryName: deliveryName,
  createStream: createStream,
  getStream: getStream,
  listStreams: listStreams,
  updateStream: updateStream,
  removeStream: removeStream,
  setStatus: setStatus,
  addSubject: addSubject,
  removeSubject: removeSubject,
  streamCoversSubject: streamCoversSubject,
  enqueue: enqueue,
  poll: poll,
  note: note,
  recordReceived: recordReceived,
  listReceived: listReceived,
  clearReceived: clearReceived,
  streamConfiguration: streamConfiguration
};
