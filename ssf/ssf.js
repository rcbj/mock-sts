'use strict';
//
// File: ssf.js
//
// ---------------------------------------------------------------------------
// THE SHARED SIGNALS FRAMEWORK (OpenID SSF 1.0, final 2 September 2025), AND
// THE FOUR IETF SPECIFICATIONS IT IS ASSEMBLED FROM.
//
// The seventeenth protocol family here, and the first one that TALKS BACK.
// Every other family in this service answers a request; this one delivers an
// event nobody asked for, at the moment it happens, to somebody who agreed in
// advance to be told.
//
// THE PROBLEM IT SOLVES, because it is not obvious from the endpoints. SAML
// and OpenID Connect authenticate at ONE INSTANT. After that the relying party
// holds a session or a token that stays good for its lifetime — often hours —
// whatever happens next. Fire somebody at ten and their session works until
// the token expires. Shortening lifetimes trades security for load and
// friction; Shared Signals inverts it, and the identity provider says when
// something changed.
//
// **SSF IS THE PIPE AND NOT THE VOCABULARY**, which is the single most
// important thing to know before reading this file. It defines how two parties
// agree a stream, who the events are about (RFC 9493 subject identifiers), what
// they travel in (RFC 8417 Security Event Tokens) and how they get there (RFC
// 8935 push, RFC 8936 poll) — and it defines exactly TWO events of its own,
// both about the pipe. The vocabularies are CAEP (what happened to a session)
// and RISC (what happened to an account), and they are the second and third
// parts of this work. **Everything in this directory is written so that adding
// one is rows in `ssf_events.js`'s table and nothing else**: the envelope, the
// subject grammar, the delivery, the queues, the stream management and the
// console are all vocabulary-independent, and a design that made any of them
// specific to the two rows there would have to be undone twice.
//
// ---------------------------------------------------------------------------
// THE ENDPOINTS, AND WHY THE PATHS ARE THIS SERVICE'S CHOICE.
//
// SSF publishes every endpoint in its configuration metadata rather than
// fixing a path, so a receiver DISCOVERS them and none of these names is
// normative:
//
//   GET  /.well-known/ssf-configuration   the transmitter's metadata. NEVER
//                                         gated — a receiver has to read what
//                                         the endpoints are before it can
//                                         authenticate to one.
//   GET  /ssf                             a page about this family. Not an
//                                         SSF endpoint; a real transmitter
//                                         publishes nothing like it.
//   POST/GET/PATCH/PUT/DELETE /ssf/stream the stream management API
//   GET/POST /ssf/status                  read and set a stream's status
//   POST /ssf/subjects/add                add a subject
//   POST /ssf/subjects/remove             remove one
//   POST /ssf/verify                      ask for a verification event
//   POST /ssf/poll                        RFC 8936 delivery
//   POST /ssf/receive                     THE ROLES REVERSED: a SET pushed AT
//                                         this service, so the debugger can be
//                                         the transmitter
//   GET  /ssf/received                    what has arrived that way
//
// **THE SUBJECT PATHS USE A SLASH AND NOT A COLON.** SSF's own examples write
// `/subjects:add`, and express reads `:add` as a ROUTE PARAMETER — so a route
// registered that way matches `/ssf/subjectsANYTHING` and matches the literal
// path only by accident. The metadata publishes what is actually registered,
// which is what a receiver reads, so nothing about this is visible on the
// wire; it is written down because the next person to "fix" the paths will
// reach for the colon.
//
// ---------------------------------------------------------------------------
// WHERE IT SITS IN THE REQUIRE ORDER, WHICH IS A DEPENDENCY AND NOT A
// PREFERENCE.
//
// **After `oauth-oidc/oauth2.js`**, transitively: `ssf_auth.js` requires
// `oauth-oidc/dpop.js` for `presentedAccessToken()`, and although that module
// registers no route it is loaded by oauth2.js anyway — requiring it first
// from here would be harmless, and requiring it first is not what decides the
// line. **After `admin-ui/admin.js`**, which is what does: the console page
// and the settings block come from that module, exactly as `scim.js`'s do, and
// requiring it earlier would drag every `/admin` route ahead of the protocol
// endpoints. **Before `sts_metadata.js`**, which is last for everybody.
//
// It is NOT one of the inverted hooks (rule 3e). Both directions were tested,
// as that rule requires: there is no cycle — `admin.js` knows nothing about
// SSF — and no route moves, because `/admin` is already registered by the time
// this file is read. So it is a plain require.
//
// ---------------------------------------------------------------------------
// WHAT THIS FAMILY DELIBERATELY DOES NOT DO.
//
// **IT DOES NOT RETRY A FAILED PUSH.** RFC 8935 permits it; `ssf_http.js`
// argues at length why a mock must not. A client that answers 500 to the first
// push and 202 to the second would look, from its own logs, like a client that
// works.
//
// **IT GENERATES NO EVENT ON ITS OWN.** Nothing here watches a session and
// emits when it changes — every SET this service transmits was asked for, at
// `/ssf/verify`, on `/admin/ssf` or through the management API. That is
// deliberate and it is the honest shape for part one: SSF defines no event
// about a session, so a transmitter that invented one would be inventing a
// vocabulary. It changes with CAEP.
//
// **IT VERIFIES NOTHING ABOUT A SUBJECT.** A stream may name a person who has
// never been here, and this service will happily transmit about them. That is
// the same posture as everywhere else — see the front page — and it is what a
// receiver's "I do not know this subject" path needs.
//
// **A `verified: true` ON AN ADD SUBJECT REQUEST IS RECORDED AND BELIEVED.**
// SSF lets a receiver say it has already confirmed the subject is one it cares
// about, and a real transmitter may then skip a confirmation step. There is no
// confirmation step here to skip, so the member is kept and shown and refuses
// nothing.
// ---------------------------------------------------------------------------

const nodeCrypto = require('crypto');
const app = require('../common/app');
const { log, xmlEscape, baseUrlOf, iso, nowSec, allSigningKeys, numberWord,
        STS } = require('../common/helpers');
const stsCrypto = require('../common/crypto');
const config = require('../common/config');
const realms = require('../common/realms');
const stats = require('../common/admin_stats');
const audit = require('../common/audit');
const applications = require('../common/applications');
const adminConsole = require('../admin-ui/admin');
const authn = require('../authn/authn');
const subjects = require('./ssf_subjects');
const events = require('./ssf_events');
// The CAEP session register. A LIBRARY, and the require goes THIS WAY ONLY:
// that module holds the register and answers what an event WOULD be, and this
// one holds transmit(), the streams and the deliveries and therefore decides
// where it goes. A require the other way would be a cycle. See its header.
const caep = require('./caep');
const streams = require('./ssf_streams');
const transport = require('./ssf_http');
const ssfAuth = require('./ssf_auth');

// The well-known suffix RFC 8414's registry carries for this document. It is
// `ssf-configuration` and NOT `ssf-configuration.json`, and not under
// `/openid-configuration` either — a receiver fetches this exact path.
const WELL_KNOWN = '/.well-known/ssf-configuration';

function enabled() {
  log.debug('Entering enabled().');
  const on = config.value('ssf.enabled') !== false;
  log.debug('Leaving enabled(). ' + on);
  return on;
}

// The `iss` of this transmitter. Empty configuration means this realm's base
// URL, which is the right answer almost always — see ssf.issuer.
function issuerFor(req) {
  log.debug('Entering issuerFor().');
  const configured = String(config.value('ssf.issuer') || '').trim();
  const value = configured || baseUrlOf(req) + realms.currentPrefix();
  log.debug('Leaving issuerFor(). ' + value);
  return value;
}

function ssfBase(req) {
  log.debug('Entering ssfBase().');
  const value = baseUrlOf(req) + realms.currentPrefix() + '/ssf';
  log.debug('Leaving ssfBase(). ' + value);
  return value;
}

function criticalMembers() {
  log.debug('Entering criticalMembers().');
  const asked = config.value('ssf.criticalSubjectMembers');
  const list = Array.isArray(asked) ? asked : String(asked || '').split(',');
  const out = list.map(function (one) {
    return String(one).trim();
  }).filter(function (name) {
    if (!name) {
      return false;
    }
    if (subjects.COMPLEX_MEMBER_NAMES.indexOf(name) < 0) {
      log.warn('ssf.criticalSubjectMembers names "' + name + '", which is ' +
               'not one of the six complex subject members SSF defines. It ' +
               'is not published — a critical member a receiver cannot ' +
               'recognise would make every complex subject refusable.');
      return false;
    }
    return true;
  });
  log.debug('Leaving criticalMembers(). ' + out.length + '.');
  return out;
}

// ---------------------------------------------------------------------------
// THE REFUSAL SHAPE.
//
// RFC 8935 section 2.4 gives `{err, description}` and this family uses it for
// every refusal on every endpoint, not only on a push — one document a
// receiver learns once. The err values are the SET Error Codes registry's:
// `invalid_request`, `invalid_key`, `invalid_issuer`, `invalid_audience`,
// `authentication_failed`, `access_denied`.
// ---------------------------------------------------------------------------
function fail(res, status, err, description, headers) {
  log.debug('Entering fail(). ' + status + ' ' + err);
  const extra = headers || {};
  Object.keys(extra).forEach(function (name) {
    res.set(name, extra[name]);
  });
  res.status(status).type('application/json').set('Cache-Control', 'no-store')
     .send(JSON.stringify({ err: err, description: description }, null, 2));
  log.debug('Leaving fail().');
}

// Answers 501 rather than 404 when the family is switched off: the feature is
// off, the URL is not wrong, and those are different sentences to a client.
function offCheck(res) {
  log.debug('Entering offCheck().');
  if (enabled()) {
    log.debug('Leaving offCheck(). On.');
    return false;
  }
  fail(res, 501, 'invalid_request',
    'The Shared Signals Framework is turned off on this service ' +
    '(ssf.enabled). The routes stay registered and answer 501 rather than ' +
    '404, because the feature being off and the URL being wrong are ' +
    'different sentences to a client. ' + WELL_KNOWN + ' still answers, so ' +
    'a receiver can discover that this service speaks SSF and is not ' +
    'currently doing it.');
  log.debug('Leaving offCheck(). Off.');
  return true;
}

// The credential check every protected endpoint makes. Returns the decision,
// or null having already answered.
function gate(req, res, need) {
  log.debug('Entering gate(). need=' + need);
  const decision = ssfAuth.authenticate(req, need);
  if (decision.ok) {
    log.debug('Leaving gate(). Allowed.');
    return decision;
  }
  fail(res, decision.status, decision.err, decision.description,
       decision.headers);
  log.debug('Leaving gate(). Refused.');
  return null;
}

function jsonBody(req) {
  log.debug('Entering jsonBody().');
  const raw = req.body;
  if (raw && typeof raw === 'object' && !Buffer.isBuffer(raw)) {
    log.debug('Leaving jsonBody(). Already parsed.');
    return raw;
  }
  const text = Buffer.isBuffer(raw) ? raw.toString('utf8')
    : String(raw == null ? '' : raw);
  if (!text.trim()) {
    log.debug('Leaving jsonBody(). Empty.');
    return {};
  }
  try {
    const parsed = JSON.parse(text);
    log.debug('Leaving jsonBody(). Parsed.');
    return (parsed && typeof parsed === 'object') ? parsed : {};
  } catch (e) {
    // Not JSON. The caller reports it as a refusal naming the body rather
    // than throwing, because a 500 on a malformed body tells a client
    // nothing about what it sent.
    log.debug('Leaving jsonBody(). Not JSON.');
    return null;
  }
}

// ---------------------------------------------------------------------------
// TRANSMIT ONE EVENT ON ONE STREAM.
//
// The one path both delivery methods take, which is what makes a failed push
// recoverable: the SET is built, signed, queued, and only THEN — for a push
// stream — taken off the queue and posted. A push implementation that signed
// and posted in one breath would lose the event on the first refused
// connection with nothing to show for it.
//
// Returns a promise of a report; it never rejects, because two of its three
// callers are answering an HTTP request that must not become a 500 over a
// receiver being down.
// ---------------------------------------------------------------------------
function transmit(record, options) {
  log.debug('Entering transmit(). ' + record.stream_id);
  const asked = options || {};
  const uri = String(asked.uri || '');
  if (record.events_delivered.indexOf(uri) < 0) {
    log.debug('Leaving transmit(). Not an agreed type.');
    return Promise.resolve({ ok: false, delivered: false, jti: '',
      why: 'This stream does not deliver "' + uri + '". It delivers ' +
           (record.events_delivered.length
             ? record.events_delivered.join(', ')
             : 'nothing at all') + ' — the intersection of what the ' +
           'receiver requested and what this transmitter supports.' });
  }
  const verdict = events.validateEvent(uri, asked.payload);
  if (!verdict.ok) {
    log.debug('Leaving transmit(). The payload is invalid.');
    return Promise.resolve({ ok: false, delivered: false, jti: '',
      why: verdict.errors.join(' ') });
  }
  // ---------------------------------------------------------------------
  // AN EVENT WHOSE ROW SAYS IT MUST NAME SOMEBODY, THAT NAMES NOBODY.
  //
  // Every CAEP event is `subject: 'required'` and SSF's own two are
  // `subject: 'none'` — they are about the STREAM, and a receiver that
  // insisted on a subject could not be verified. So this is a check on the
  // ROW rather than a branch naming a vocabulary, which is what keeps
  // `ssf_events.js`'s promise: RISC's rows will be `required` too and this
  // line will not change.
  //
  // It is refused rather than carried because of what the omission MEANS. A
  // session-revoked with no `sub_id` says a session was revoked and does not
  // say whose; a receiver cannot act on it and cannot report anything useful
  // about it, so it is dropped at the far end with no error anybody sees —
  // which is the failure this whole family exists to make visible.
  // ---------------------------------------------------------------------
  const row = events.EVENT_BY_URI[uri];
  if (row && row.subject === 'required' && !asked.subject) {
    log.debug('Leaving transmit(). No subject on an event that needs one.');
    return Promise.resolve({ ok: false, delivered: false, jti: '',
      why: '"' + uri + '" must carry a subject and this one carries none. ' +
           'A ' + row.name + ' with no sub_id says something happened and ' +
           'does not say to whom, so a receiver drops it with no error ' +
           'anybody sees. CAEP\'s subject is normally SSF\'s COMPLEX one — ' +
           'the person is not revoked, one session of theirs is.' });
  }
  if (asked.subject && !streams.streamCoversSubject(record, asked.subject)) {
    log.debug('Leaving transmit(). Not a subject on this stream.');
    return Promise.resolve({ ok: false, delivered: false, jti: '',
      why: 'This stream names ' + record.subjects.length + ' subject(s) and ' +
           subjects.describeSubject(asked.subject) + ' is not one of them. ' +
           'A stream with an EMPTY list is about everybody or nobody ' +
           'depending on ssf.defaultSubjects, which this transmitter ' +
           'publishes as default_subjects.' });
  }

  const claims = events.buildSet({
    issuer: record.iss,
    audience: record.aud,
    uri: uri,
    payload: asked.payload || {},
    subject: asked.subject || null,
    txn: asked.txn || '',
    toe: typeof asked.toe === 'number' ? asked.toe : undefined
  });

  return events.signSet(claims).then(function (token) {
    // COUNTED HERE, which is after the SET exists and before anybody knows
    // whether it will be delivered — because what /admin/caep-sessions
    // reports is what this transmitter SAID about a session, and a queued
    // event on a poll stream has been said. Whether it arrived is the
    // stream's own counters, three lines down, and conflating the two would
    // make a poll stream look like a transmitter that never says anything.
    caep.noteTransmitted(record, claims);
    const entry = { jti: claims.jti, token: token, claims: claims,
      queuedAt: iso(), deliveredAt: '', counted: false };
    const queued = streams.enqueue(record, entry);
    if (!queued.ok) {
      log.debug('Leaving transmit(). Not queued.');
      return { ok: false, delivered: false, jti: claims.jti, token: token,
        claims: claims,
        why: 'The event was built and signed and NOT queued, because ' +
             queued.reason + '. A disabled stream drops what is waiting; a ' +
             'PAUSED one would have kept this.' };
    }
    audit.audit({ action: 'ssf.event.transmit', category: 'signals',
      protocol: 'SSF', channel: 'http', outcome: 'success',
      target: record.stream_id,
      summary: 'Queued ' + (events.EVENT_BY_URI[uri] || {}).name +
        ' on ' + record.stream_id,
      detail: { jti: claims.jti, type: uri,
        subject: asked.subject
          ? subjects.describeSubject(asked.subject) : '' } });
    if (record.delivery.method !== streams.DELIVERY_PUSH) {
      streams.note(record, 'queued', 'Queued ' + claims.jti +
        ' for the receiver to poll.');
      log.debug('Leaving transmit(). Queued for poll.');
      return { ok: true, delivered: false, jti: claims.jti, token: token,
        claims: claims,
        why: 'Queued. This is a poll stream, so nothing is sent until the ' +
             'receiver asks at ' + '/ssf/poll.' };
    }
    record.counters.pushCalls += 1;
    return transport.pushSet(record.delivery.endpoint_url, token, {
      authorizationHeader: record.delivery.authorization_header
    }).then(function (result) {
      record.lastPushAt = iso();
      if (result.ok) {
        record.counters.delivered += 1;
        entry.counted = true;
        entry.deliveredAt = iso();
        record.queue = record.queue.filter(function (one) {
          return one.jti !== entry.jti;
        });
        record.lastPushError = '';
        streams.note(record, 'push', 'Delivered ' + claims.jti + ' to ' +
          record.delivery.endpoint_url +
          (result.why ? ' — ' + result.why : ''));
        log.debug('Leaving transmit(). Pushed.');
        return { ok: true, delivered: true, jti: claims.jti, token: token,
          claims: claims, status: result.status, why: result.why };
      }
      record.counters.failed += 1;
      record.lastPushError = result.why;
      streams.note(record, 'error', 'The push of ' + claims.jti + ' failed: ' +
        result.why + ' The event is STILL ON THE QUEUE — nothing here ' +
        'retries, so it stays until somebody asks for it again.');
      audit.audit({ action: 'ssf.event.refused', category: 'signals',
        protocol: 'SSF', channel: 'http', outcome: 'failure',
        target: record.stream_id,
        summary: 'A receiver refused ' + claims.jti,
        detail: { why: result.why, err: result.err,
          status: result.status } });
      log.debug('Leaving transmit(). The push failed.');
      return { ok: false, delivered: false, jti: claims.jti, token: token,
        claims: claims, status: result.status, err: result.err,
        why: result.why };
    });
  }).catch(function (e) {
    log.error('ssf: a Security Event Token could not be signed: ' + e.message);
    log.debug('Leaving transmit(). The signature failed.');
    return { ok: false, delivered: false, jti: '',
      why: 'The event could not be signed with ' +
           events.signingAlgorithm() + ': ' + e.message +
           '. Check ssf.signingAlgorithm.' };
  });
}

// ---------------------------------------------------------------------------
// THE TRANSMITTER CONFIGURATION METADATA (SSF 1.0 section 6).
//
// NEVER GATED. See ssf_auth.js's header — a transmitter whose discovery
// document needs a credential is one nothing can bootstrap against.
//
// It answers whether or not `ssf.enabled` is on, and that is deliberate: a
// receiver that finds this document and then a 501 has learned something
// specific, where a 404 would leave it unable to tell "this service does not
// speak SSF" from "the path is wrong".
// ---------------------------------------------------------------------------
function metadata(req) {
  log.debug('Entering metadata().');
  const base = ssfBase(req);
  const doc = {
    spec_version: '1_0-final',
    issuer: issuerFor(req),
    jwks_uri: baseUrlOf(req) + realms.currentPrefix() + '/oauth2/jwks',
    delivery_methods_supported: streams.offeredDeliveryMethods(),
    configuration_endpoint: base + '/stream',
    status_endpoint: base + '/status',
    add_subject_endpoint: base + '/subjects/add',
    remove_subject_endpoint: base + '/subjects/remove',
    verification_endpoint: base + '/verify',
    critical_subject_members: criticalMembers(),
    default_subjects: String(config.value('ssf.defaultSubjects') || 'ALL')
      .toUpperCase(),
    authorization_schemes: ssfAuth.schemesForMetadata()
  };
  log.debug('Leaving metadata().');
  return doc;
}

app.get(WELL_KNOWN, function (req, res) {
  log.debug('Entering GET ' + WELL_KNOWN + '.');
  res.status(200).type('application/json').set('Cache-Control', 'no-store')
     .send(JSON.stringify(metadata(req), null, 2));
  log.debug('Leaving GET ' + WELL_KNOWN + '.');
});

// ---------------------------------------------------------------------------
// THE STREAM MANAGEMENT API (SSF 1.0 section 7.1.1).
//
// One path, five methods, which is the specification's own shape: the
// `configuration_endpoint` IS the resource. `?stream_id=` selects one on the
// three methods that need one; a GET without it lists every stream this
// caller could reach, which is what SSF says a transmitter answers.
//
// **PATCH AND PUT ARE NOT THE SAME AND THE DIFFERENCE IS REAL.** PUT replaces
// — a member the receiver omits goes back to its default — and PATCH merges.
// A PUT that behaved like a PATCH would let a receiver believe it had cleared
// `events_requested` when it had not, and the symptom is event types still
// arriving after they were removed.
// ---------------------------------------------------------------------------
function contextOf(req, decision) {
  log.debug('Entering contextOf().');
  const out = { issuer: issuerFor(req),
    principal: String((decision || {}).principal || '') };
  log.debug('Leaving contextOf().');
  return out;
}

function streamView(req, record, decision) {
  log.debug('Entering streamView().');
  const view = streams.streamConfiguration(record, {
    pollEndpoint: ssfBase(req) + '/poll',
    // The receiver's own authorization_header goes back ONLY to a caller that
    // just wrote it, and never onto a console page or into the management
    // API's listing: it is a credential belonging to somebody else's endpoint.
    includeSecrets: !!(decision && !decision.anonymous)
  });
  log.debug('Leaving streamView().');
  return view;
}

app.post('/ssf/stream', function (req, res) {
  log.debug('Entering POST /ssf/stream.');
  if (offCheck(res)) {
    log.debug('Leaving POST /ssf/stream. Off.');
    return;
  }
  const decision = gate(req, res, 'write');
  if (!decision) {
    log.debug('Leaving POST /ssf/stream. Refused.');
    return;
  }
  const body = jsonBody(req);
  if (!body) {
    fail(res, 400, 'invalid_request',
      'The request body is not JSON. A Stream Configuration is a JSON ' +
      'object; see ' + WELL_KNOWN + ' for what this transmitter supports.');
    log.debug('Leaving POST /ssf/stream. Not JSON.');
    return;
  }
  // The push endpoint is checked HERE as well as at push time, and that is the
  // half that matters to a receiver: a stream whose endpoint can never be
  // dialled is refused when it is created rather than accepted and then
  // silently delivering nothing.
  if (body.delivery && body.delivery.method === streams.DELIVERY_PUSH) {
    const problem = transport.urlProblem(body.delivery.endpoint_url);
    if (problem) {
      fail(res, 400, 'invalid_request',
        'delivery.endpoint_url cannot be dialled by this transmitter: ' +
        problem + '. It is refused now rather than at delivery time, ' +
        'because a stream that is accepted and then silently delivers ' +
        'nothing is the worst outcome available here.');
      log.debug('Leaving POST /ssf/stream. Undiallable endpoint.');
      return;
    }
  }
  const created = streams.createStream(body, contextOf(req, decision));
  if (!created.ok) {
    fail(res, 400, 'invalid_request', created.errors.join(' '));
    log.debug('Leaving POST /ssf/stream. Refused.');
    return;
  }
  // The receiver as an APPLICATION. It is a sighting rather than a
  // declaration — somebody presented an identifier and it was accepted — so
  // it goes through seen() like every other family's, under a kind of its
  // own. What an operator DECLARES about a receiver ahead of time is the
  // `ssf` checkbox and the two fields on /admin/applications/new.
  if (decision.principal) {
    applications.seen({
      identifier: String(decision.principal),
      kind: 'ssf-receiver',
      protocol: 'SSF',
      fields: { ssfReceiverId: String(decision.principal) }
    });
  }
  audit.audit({ action: 'ssf.stream.create', category: 'signals',
    protocol: 'SSF', channel: 'http', actor: decision.principal,
    target: created.stream.stream_id,
    summary: 'A Shared Signals stream was created over ' +
      streams.deliveryName(created.stream.delivery.method),
    detail: { events: created.stream.events_delivered,
      endpoint: created.stream.delivery.endpoint_url } });
  res.status(201).type('application/json').set('Cache-Control', 'no-store')
     .send(JSON.stringify(streamView(req, created.stream, decision), null, 2));
  log.debug('Leaving POST /ssf/stream. ' + created.stream.stream_id);
});

app.get('/ssf/stream', function (req, res) {
  log.debug('Entering GET /ssf/stream.');
  if (offCheck(res)) {
    log.debug('Leaving GET /ssf/stream. Off.');
    return;
  }
  const decision = gate(req, res, 'read');
  if (!decision) {
    log.debug('Leaving GET /ssf/stream. Refused.');
    return;
  }
  const id = String(req.query.stream_id || '');
  if (!id) {
    const list = streams.listStreams().map(function (record) {
      return streamView(req, record, decision);
    });
    res.status(200).type('application/json').set('Cache-Control', 'no-store')
       .send(JSON.stringify(list, null, 2));
    log.debug('Leaving GET /ssf/stream. ' + list.length + ' stream(s).');
    return;
  }
  const record = streams.getStream(id);
  if (!record) {
    fail(res, 404, 'invalid_request',
      'No stream with stream_id "' + id + '". A GET with no stream_id lists ' +
      'every stream this transmitter holds.');
    log.debug('Leaving GET /ssf/stream. No such stream.');
    return;
  }
  res.status(200).type('application/json').set('Cache-Control', 'no-store')
     .send(JSON.stringify(streamView(req, record, decision), null, 2));
  log.debug('Leaving GET /ssf/stream. ' + id);
});

function updateRoute(req, res, mode) {
  log.debug('Entering updateRoute(). ' + mode);
  if (offCheck(res)) {
    log.debug('Leaving updateRoute(). Off.');
    return;
  }
  const decision = gate(req, res, 'write');
  if (!decision) {
    log.debug('Leaving updateRoute(). Refused.');
    return;
  }
  const body = jsonBody(req);
  if (!body) {
    fail(res, 400, 'invalid_request', 'The request body is not JSON.');
    log.debug('Leaving updateRoute(). Not JSON.');
    return;
  }
  const id = String(body.stream_id || req.query.stream_id || '');
  const record = streams.getStream(id);
  if (!record) {
    fail(res, 404, 'invalid_request',
      'No stream with stream_id "' + id + '". The id goes in the body as ' +
      'stream_id, or in the query string.');
    log.debug('Leaving updateRoute(). No such stream.');
    return;
  }
  const updated = streams.updateStream(id, body, mode,
                                       contextOf(req, decision));
  if (!updated.ok) {
    fail(res, 400, 'invalid_request', updated.errors.join(' '));
    log.debug('Leaving updateRoute(). Refused.');
    return;
  }
  audit.audit({ action: 'ssf.stream.update', category: 'signals',
    protocol: 'SSF', channel: 'http', actor: decision.principal, target: id,
    summary: 'A Shared Signals stream was ' +
      (mode === 'replace' ? 'replaced' : 'merged'),
    detail: { events: updated.stream.events_delivered } });
  res.status(200).type('application/json').set('Cache-Control', 'no-store')
     .send(JSON.stringify(streamView(req, updated.stream, decision), null, 2));
  log.debug('Leaving updateRoute(). ' + id);
}

app.put('/ssf/stream', function (req, res) {
  log.debug('Entering PUT /ssf/stream.');
  updateRoute(req, res, 'replace');
  log.debug('Leaving PUT /ssf/stream.');
});

app.patch('/ssf/stream', function (req, res) {
  log.debug('Entering PATCH /ssf/stream.');
  updateRoute(req, res, 'merge');
  log.debug('Leaving PATCH /ssf/stream.');
});

app.delete('/ssf/stream', function (req, res) {
  log.debug('Entering DELETE /ssf/stream.');
  if (offCheck(res)) {
    log.debug('Leaving DELETE /ssf/stream. Off.');
    return;
  }
  const decision = gate(req, res, 'write');
  if (!decision) {
    log.debug('Leaving DELETE /ssf/stream. Refused.');
    return;
  }
  const body = jsonBody(req) || {};
  const id = String(body.stream_id || req.query.stream_id || '');
  if (!streams.getStream(id)) {
    fail(res, 404, 'invalid_request',
      'No stream with stream_id "' + id + '".');
    log.debug('Leaving DELETE /ssf/stream. No such stream.');
    return;
  }
  streams.removeStream(id);
  audit.audit({ action: 'ssf.stream.delete', category: 'signals',
    protocol: 'SSF', channel: 'http', actor: decision.principal, target: id,
    summary: 'A Shared Signals stream was deleted' });
  res.status(204).set('Cache-Control', 'no-store').end();
  log.debug('Leaving DELETE /ssf/stream. ' + id);
});

// ---------------------------------------------------------------------------
// THE STATUS ENDPOINT (SSF 1.0 section 7.1.2).
//
// The three values and what separates them: a PAUSED stream keeps queueing and
// delivers nothing, so what happened while it was paused is still there when
// it is enabled again; a DISABLED one drops it. That is the difference between
// "I was not listening" and "it did not happen", which is the whole reason a
// Shared Signals receiver has a pause at all.
//
// A change here emits a **stream-updated** event on the stream itself, if the
// receiver agreed that type — which is the one event a receiver gets without
// asking for it, and the one whose absence is hardest to notice.
// ---------------------------------------------------------------------------
app.get('/ssf/status', function (req, res) {
  log.debug('Entering GET /ssf/status.');
  if (offCheck(res)) {
    log.debug('Leaving GET /ssf/status. Off.');
    return;
  }
  const decision = gate(req, res, 'read');
  if (!decision) {
    log.debug('Leaving GET /ssf/status. Refused.');
    return;
  }
  const id = String(req.query.stream_id || '');
  const record = streams.getStream(id);
  if (!record) {
    fail(res, 404, 'invalid_request',
      'No stream with stream_id "' + id + '".');
    log.debug('Leaving GET /ssf/status. No such stream.');
    return;
  }
  res.status(200).type('application/json').set('Cache-Control', 'no-store')
     .send(JSON.stringify({ stream_id: record.stream_id,
       status: record.status, reason: record.statusReason }, null, 2));
  log.debug('Leaving GET /ssf/status. ' + record.status);
});

app.post('/ssf/status', function (req, res) {
  log.debug('Entering POST /ssf/status.');
  if (offCheck(res)) {
    log.debug('Leaving POST /ssf/status. Off.');
    return;
  }
  const decision = gate(req, res, 'write');
  if (!decision) {
    log.debug('Leaving POST /ssf/status. Refused.');
    return;
  }
  const body = jsonBody(req);
  if (!body) {
    fail(res, 400, 'invalid_request', 'The request body is not JSON.');
    log.debug('Leaving POST /ssf/status. Not JSON.');
    return;
  }
  const id = String(body.stream_id || '');
  const changed = streams.setStatus(id, String(body.status || ''),
                                    String(body.reason || ''));
  if (!changed.ok) {
    const status = streams.getStream(id) ? 400 : 404;
    fail(res, status, 'invalid_request', changed.errors.join(' '));
    log.debug('Leaving POST /ssf/status. Refused.');
    return;
  }
  audit.audit({ action: 'ssf.stream.status', category: 'signals',
    protocol: 'SSF', channel: 'http', actor: decision.principal, target: id,
    summary: 'The stream is now ' + changed.stream.status,
    detail: { reason: changed.stream.statusReason } });
  const answer = { stream_id: changed.stream.stream_id,
    status: changed.stream.status, reason: changed.stream.statusReason };
  // Tell the receiver IN BAND as well, if it agreed the type. A disabled
  // stream cannot carry it — enqueue() refuses — and that is correct rather
  // than a gap: there is nowhere for it to go and nothing to poll it from.
  transmit(changed.stream, {
    uri: events.SSF_PREFIX + 'stream-updated',
    payload: { status: changed.stream.status,
      reason: changed.stream.statusReason || 'set at ' + iso() }
  }).then(function (report) {
    log.debug('POST /ssf/status: the stream-updated event was ' +
              (report.ok ? 'transmitted' : 'not transmitted: ' + report.why));
  });
  res.status(200).type('application/json').set('Cache-Control', 'no-store')
     .send(JSON.stringify(answer, null, 2));
  log.debug('Leaving POST /ssf/status. ' + changed.stream.status);
});

// ---------------------------------------------------------------------------
// ADD AND REMOVE SUBJECT (SSF 1.0 sections 7.1.3 and 7.1.4).
//
// Both answer 204 with no body on success, which is what the specification
// says and is worth not "improving": a receiver that gets a 200 with a
// document has been given something to depend on that no transmitter has to
// send.
//
// A REMOVE IS IDEMPOTENT — removing a subject that is not there is a 204 and
// not a 404. That is the specification's own rule and it is the right one: a
// receiver tidying up after a crash must not have to know what it had already
// removed.
// ---------------------------------------------------------------------------
app.post('/ssf/subjects/add', function (req, res) {
  log.debug('Entering POST /ssf/subjects/add.');
  if (offCheck(res)) {
    log.debug('Leaving POST /ssf/subjects/add. Off.');
    return;
  }
  const decision = gate(req, res, 'write');
  if (!decision) {
    log.debug('Leaving POST /ssf/subjects/add. Refused.');
    return;
  }
  const body = jsonBody(req);
  if (!body) {
    fail(res, 400, 'invalid_request', 'The request body is not JSON.');
    log.debug('Leaving POST /ssf/subjects/add. Not JSON.');
    return;
  }
  const id = String(body.stream_id || '');
  if (!streams.getStream(id)) {
    fail(res, 404, 'invalid_request',
      'No stream with stream_id "' + id + '".');
    log.debug('Leaving POST /ssf/subjects/add. No such stream.');
    return;
  }
  const added = streams.addSubject(id, body.subject, body.verified !== false,
                                   { criticalMembers: criticalMembers() });
  if (!added.ok) {
    fail(res, 400, 'invalid_request', added.errors.join(' '));
    log.debug('Leaving POST /ssf/subjects/add. Refused.');
    return;
  }
  audit.audit({ action: 'ssf.subject.change', category: 'signals',
    protocol: 'SSF', channel: 'http', actor: decision.principal, target: id,
    summary: 'A subject was added to ' + id,
    detail: { subject: subjects.describeSubject(body.subject),
      verified: body.verified !== false } });
  res.status(204).set('Cache-Control', 'no-store').end();
  log.debug('Leaving POST /ssf/subjects/add.');
});

app.post('/ssf/subjects/remove', function (req, res) {
  log.debug('Entering POST /ssf/subjects/remove.');
  if (offCheck(res)) {
    log.debug('Leaving POST /ssf/subjects/remove. Off.');
    return;
  }
  const decision = gate(req, res, 'write');
  if (!decision) {
    log.debug('Leaving POST /ssf/subjects/remove. Refused.');
    return;
  }
  const body = jsonBody(req);
  if (!body) {
    fail(res, 400, 'invalid_request', 'The request body is not JSON.');
    log.debug('Leaving POST /ssf/subjects/remove. Not JSON.');
    return;
  }
  const id = String(body.stream_id || '');
  if (!streams.getStream(id)) {
    fail(res, 404, 'invalid_request',
      'No stream with stream_id "' + id + '".');
    log.debug('Leaving POST /ssf/subjects/remove. No such stream.');
    return;
  }
  const removed = streams.removeSubject(id, body.subject);
  if (!removed.ok) {
    fail(res, 400, 'invalid_request', removed.errors.join(' '));
    log.debug('Leaving POST /ssf/subjects/remove. Refused.');
    return;
  }
  audit.audit({ action: 'ssf.subject.change', category: 'signals',
    protocol: 'SSF', channel: 'http', actor: decision.principal, target: id,
    summary: 'A subject was removed from ' + id,
    detail: { subject: subjects.describeSubject(body.subject),
      wasThere: removed.removed } });
  res.status(204).set('Cache-Control', 'no-store').end();
  log.debug('Leaving POST /ssf/subjects/remove. ' + removed.removed);
});

// ---------------------------------------------------------------------------
// THE VERIFICATION ENDPOINT (SSF 1.0 section 7.1.5).
//
// THE ONLY END-TO-END TEST A STREAM HAS. Everything else a receiver can do —
// create the stream, read it back, add a subject — exercises the management
// API and proves nothing about whether an event can actually be delivered.
//
// The `state` a receiver sends comes back UNCHANGED in the event, and it is
// the only thing tying the event to the request: a receiver watching two
// streams cannot otherwise tell which one just answered.
//
// **THE RATE LIMIT IS PUBLISHED AND NOT ENFORCED BY DEFAULT**, which is the
// pair `ssf.minVerificationInterval` and `ssf.verificationRateLimit` make: a
// receiver sees a realistic interval in its stream configuration and may
// verify as often as it likes, and turning the second one on makes the 429
// reachable.
// ---------------------------------------------------------------------------
app.post('/ssf/verify', function (req, res) {
  log.debug('Entering POST /ssf/verify.');
  if (offCheck(res)) {
    log.debug('Leaving POST /ssf/verify. Off.');
    return;
  }
  const decision = gate(req, res, 'write');
  if (!decision) {
    log.debug('Leaving POST /ssf/verify. Refused.');
    return;
  }
  const body = jsonBody(req);
  if (!body) {
    fail(res, 400, 'invalid_request', 'The request body is not JSON.');
    log.debug('Leaving POST /ssf/verify. Not JSON.');
    return;
  }
  const id = String(body.stream_id || '');
  const record = streams.getStream(id);
  if (!record) {
    fail(res, 404, 'invalid_request',
      'No stream with stream_id "' + id + '".');
    log.debug('Leaving POST /ssf/verify. No such stream.');
    return;
  }
  const interval = Number(record.min_verification_interval) || 0;
  const since = nowSec() - Number(record.lastVerificationAt || 0);
  if (config.value('ssf.verificationRateLimit') && interval > 0 &&
      record.lastVerificationAt && since < interval) {
    res.set('Retry-After', String(interval - since));
    fail(res, 429, 'invalid_request',
      'This stream was verified ' + since + ' second(s) ago and its ' +
      'min_verification_interval is ' + interval + '. That interval is ' +
      'published on every stream configuration and is normally NOT ' +
      'enforced here — ssf.verificationRateLimit turns the refusal on, so ' +
      'that a receiver\'s back-off path is reachable at all.');
    log.debug('Leaving POST /ssf/verify. Too soon.');
    return;
  }
  record.lastVerificationAt = nowSec();
  transmit(record, {
    uri: events.SSF_PREFIX + 'verification',
    payload: typeof body.state === 'string' && body.state !== ''
      ? { state: body.state } : {}
  }).then(function (report) {
    if (!report.ok) {
      // A 202 was already the wrong answer here: the receiver asked whether
      // the pipe works and the answer is no. The refusal names why, which is
      // the whole value of the request.
      fail(res, 400, 'invalid_request',
        'The verification event was not delivered: ' + report.why);
      log.debug('Leaving POST /ssf/verify. Not delivered.');
      return;
    }
    res.status(204).set('Cache-Control', 'no-store').end();
    log.debug('Leaving POST /ssf/verify. ' + report.jti);
  });
});

// ---------------------------------------------------------------------------
// POLL DELIVERY (RFC 8936).
//
// The receiver comes HERE, so nothing is dialled and a browser can be a
// receiver over this method — which is exactly why the debugger's page works
// with no api behind it on poll and needs one on push.
//
// `ack` names what the receiver has stored and `setErrs` what it REFUSED, and
// both come off the queue. The second one catches people out and is worth the
// sentence: a receiver that could not process an event will not process it
// next time either, so redelivering would poll-loop forever. The refusal is
// recorded on the stream instead, where a person can see it.
//
// `returnImmediately` is honoured as "yes" always: this service does not hold
// a request open. RFC 8936 permits a transmitter to answer immediately in any
// case, and long-polling a mock would tie up a socket to demonstrate nothing.
// ---------------------------------------------------------------------------
app.post('/ssf/poll', function (req, res) {
  log.debug('Entering POST /ssf/poll.');
  if (offCheck(res)) {
    log.debug('Leaving POST /ssf/poll. Off.');
    return;
  }
  const decision = gate(req, res, 'read');
  if (!decision) {
    log.debug('Leaving POST /ssf/poll. Refused.');
    return;
  }
  const body = jsonBody(req);
  if (!body) {
    fail(res, 400, 'invalid_request', 'The request body is not JSON.');
    log.debug('Leaving POST /ssf/poll. Not JSON.');
    return;
  }
  const id = String(body.stream_id || req.query.stream_id || '');
  const record = streams.getStream(id);
  if (!record) {
    fail(res, 404, 'invalid_request',
      'No stream with stream_id "' + id + '". RFC 8936 has no stream_id ' +
      'member — a real poll endpoint is per stream, and this transmitter ' +
      'publishes one URL, so the id goes in the body or the query string. ' +
      'The stream configuration says so in delivery.endpoint_url.');
    log.debug('Leaving POST /ssf/poll. No such stream.');
    return;
  }
  if (record.delivery.method !== streams.DELIVERY_POLL) {
    fail(res, 400, 'invalid_request',
      'Stream ' + id + ' is a PUSH stream (' + record.delivery.method +
      '), so its events are POSTed to ' + record.delivery.endpoint_url +
      ' and there is nothing here to collect. Change the delivery method ' +
      'on the stream first.');
    log.debug('Leaving POST /ssf/poll. Not a poll stream.');
    return;
  }
  const result = streams.poll(record, body);
  res.status(200).type('application/json').set('Cache-Control', 'no-store')
     .send(JSON.stringify({ sets: result.sets,
       moreAvailable: result.moreAvailable }, null, 2));
  log.debug('Leaving POST /ssf/poll. ' + Object.keys(result.sets).length +
            ' set(s).');
});

// ---------------------------------------------------------------------------
// THE ROLES REVERSED: A SET PUSHED **AT** THIS SERVICE.
//
// The debugger can be a transmitter, and something has to be at the far end of
// its push. This is that, and it is what makes the debugger's "send an event"
// half testable at all.
//
// **IT ACCEPTS A SET WHOSE SIGNATURE DOES NOT VERIFY, BY DEFAULT, AND REPORTS
// WHY.** That is this service's ordinary posture and it is exactly right for a
// debugger: a receiver that refused an unverifiable event could not show
// anybody WHAT arrived or WHY it did not verify, which is the question being
// asked. `ssf.receiveRequireSignature` turns the 400 on, which is what a real
// receiver does and is the negative a transmitter needs to be able to reach.
//
// The verification is against THIS SERVICE'S OWN key, because that is the only
// key it has. A SET signed by somebody else is reported as "not verifiable
// here" rather than as invalid — those are different sentences and conflating
// them would be a receiver blaming a transmitter for its own missing key.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// THE PUBLIC KEY A RECEIVED SET IS CHECKED AGAINST, and the reason this is a
// function rather than one line.
//
// This service can only verify a signature made with a key IT HOLDS — it
// follows no `jwks_uri`, here or anywhere else, for the reason
// `applications.js` gives about `oauthJwksUri` and `federation_http.js`
// repeats: fetching a URL a caller supplied in order to verify a credential is
// a server-side request forgery with a specification citation attached. So the
// key is looked up in this realm's own key set, BY `kid` FIRST and by
// algorithm second.
//
// **BY kid FIRST IS THE PART THAT MATTERS.** Two of this service's keys share
// an `alg` — the Ed25519 and Ed448 pair, because RFC 8037 registers one
// algorithm value for both curves and puts the curve in the key — so an
// algorithm-only lookup would pick one of them and report a perfectly good
// Ed448 signature as not verifying.
//
// A SET signed by anybody else resolves to no key, and that is reported as NOT
// VERIFIABLE HERE rather than as invalid. Those are different sentences and
// conflating them would be a receiver blaming a transmitter for its own
// missing key.
// ---------------------------------------------------------------------------
function publicKeyForHeader(header) {
  log.debug('Entering publicKeyForHeader().');
  const kid = String((header || {}).kid || '');
  const alg = String((header || {}).alg || '');
  if (alg === 'RS256' || kid === STS.kid) {
    // The RSA key is not in the list below — it is `STS.privateKey`/`STS.kid`,
    // where eight modules already read it — so it is resolved separately from
    // the certificate this service publishes for it.
    try {
      log.debug('Leaving publicKeyForHeader(). The service RSA key.');
      return { key: nodeCrypto.createPublicKey(STS.certPem), pq: false };
    } catch (e) {
      log.debug('Leaving publicKeyForHeader(). The certificate would not ' +
                'load: ' + e.message);
      return null;
    }
  }
  const list = allSigningKeys();
  const found = list.filter(function (one) {
    return kid ? one.publicJwk.kid === kid : one.alg === alg;
  })[0];
  if (!found) {
    log.debug('Leaving publicKeyForHeader(). No key of ours matches.');
    return null;
  }
  if (found.publicJwk.kty === 'AKP') {
    // A post-quantum key. `verifyCompactJws()` wants the raw public bytes,
    // which the AKP JWK carries in `pub`.
    log.debug('Leaving publicKeyForHeader(). A post-quantum key.');
    return { key: { pub: found.publicJwk.pub }, pq: true };
  }
  try {
    log.debug('Leaving publicKeyForHeader(). ' + found.alg + '.');
    return { key: nodeCrypto.createPublicKey({ key: found.publicJwk,
      format: 'jwk' }), pq: false };
  } catch (e) {
    log.debug('Leaving publicKeyForHeader(). The JWK would not load: ' +
              e.message);
    return null;
  }
}

function verifyReceivedSet(token, header) {
  log.debug('Entering verifyReceivedSet().');
  if (!header) {
    log.debug('Leaving verifyReceivedSet(). No readable header.');
    return { verified: false,
      note: 'there is no readable protected header, so there is nothing to ' +
            'look a key up by' };
  }
  const resolved = publicKeyForHeader(header);
  if (!resolved) {
    log.debug('Leaving verifyReceivedSet(). No key.');
    return { verified: false,
      note: 'not verifiable here: this service holds no key matching kid "' +
            String(header.kid || '(none)') + '" / alg "' +
            String(header.alg || '(none)') + '". It follows no jwks_uri — ' +
            'fetching a URL a caller supplied in order to verify a ' +
            'credential is the request forgery this repository refuses ' +
            'everywhere — so a SET signed by anybody else is UNVERIFIABLE ' +
            'here rather than invalid. Those are different sentences.' };
  }
  try {
    stsCrypto.verifyCompactJws(token, resolved.key,
      { algorithms: stsCrypto.JWS_ASYMMETRIC_ALGS });
    log.debug('Leaving verifyReceivedSet(). Verified.');
    return { verified: true,
      note: 'verified against this service\'s own ' +
            String(header.alg) + ' key' };
  } catch (e) {
    // A signature that does not verify, or one this build cannot check. Both
    // are reported rather than thrown: the whole point of this endpoint is to
    // say what arrived, and "it did not verify" IS what arrived.
    log.debug('Leaving verifyReceivedSet(). It did not verify.');
    return { verified: false,
      note: 'the signature did not verify against this service\'s own key: ' +
            e.message };
  }
}

function readSetForDisplay(token) {
  log.debug('Entering readSetForDisplay().');
  const parts = String(token || '').split('.');
  const out = { header: null, claims: null, problem: '' };
  if (parts.length !== 3) {
    out.problem = 'This is not a compact JWS — a Security Event Token has ' +
      'three dot-separated parts and this has ' + parts.length + '.';
    log.debug('Leaving readSetForDisplay(). Not a compact JWS.');
    return out;
  }
  try {
    out.header = JSON.parse(Buffer.from(parts[0], 'base64url')
      .toString('utf8'));
    out.claims = JSON.parse(Buffer.from(parts[1], 'base64url')
      .toString('utf8'));
  } catch (e) {
    // Undecodable. Reported rather than thrown: the whole point of this
    // endpoint is to say what arrived, and "it would not decode" IS what
    // arrived.
    out.problem = 'The header or the payload would not decode as base64url ' +
      'JSON: ' + e.message;
  }
  log.debug('Leaving readSetForDisplay(). ' + (out.problem || 'read'));
  return out;
}

app.post('/ssf/receive', function (req, res) {
  log.debug('Entering POST /ssf/receive.');
  if (offCheck(res)) {
    log.debug('Leaving POST /ssf/receive. Off.');
    return;
  }
  if (!config.value('ssf.receiveEnabled')) {
    fail(res, 501, 'invalid_request',
      'This service is not accepting pushed events (ssf.receiveEnabled). ' +
      'It is a RECEIVER only for the debugger\'s benefit — the roles ' +
      'reversed — and turning it off leaves the transmitter half working.');
    log.debug('Leaving POST /ssf/receive. Off.');
    return;
  }
  const raw = Buffer.isBuffer(req.body) ? req.body.toString('utf8')
    : (typeof req.body === 'string' ? req.body
      : String((req.body && req.body.token) || ''));
  const token = raw.trim();
  if (!token) {
    fail(res, 400, 'invalid_request',
      'The body is empty. RFC 8935 section 2.1 puts the Security Event ' +
      'Token in the body as application/secevent+jwt, with no form ' +
      'encoding and no JSON wrapper around it.');
    log.debug('Leaving POST /ssf/receive. Empty body.');
    return;
  }
  const contentType = String((req.headers || {})['content-type'] || '')
    .split(';')[0].trim().toLowerCase();
  const read = readSetForDisplay(token);
  const verdict = verifyReceivedSet(token, read.header);
  const verified = verdict.verified;
  const verificationNote = verdict.note;
  if (!verified && config.value('ssf.receiveRequireSignature')) {
    fail(res, 400, 'invalid_key', verificationNote);
    log.debug('Leaving POST /ssf/receive. Signature required.');
    return;
  }
  const entry = {
    at: iso(),
    token: token,
    contentType: contentType,
    correctMediaType: contentType === transport.SET_MEDIA_TYPE,
    header: read.header,
    claims: read.claims,
    problem: read.problem,
    verified: verified,
    verificationNote: verificationNote,
    summary: read.claims ? events.describeSet(read.claims) : null
  };
  streams.recordReceived(entry);
  audit.audit({ action: 'ssf.event.receive', category: 'signals',
    protocol: 'SSF', channel: 'http',
    outcome: read.problem ? 'failure' : 'success',
    target: String((read.claims || {}).jti || ''),
    summary: 'A Security Event Token was pushed at this service' +
      (verified ? ' and verified' : ''),
    detail: { types: Object.keys((read.claims || {}).events || {}),
      contentType: contentType } });
  if (read.problem) {
    fail(res, 400, 'invalid_request', read.problem +
      ' It has been recorded anyway and is on /admin/ssf, because what ' +
      'arrived is the question being asked.');
    log.debug('Leaving POST /ssf/receive. Malformed.');
    return;
  }
  // 202 with an EMPTY body, which is what RFC 8935 section 2.3 says. A
  // document here would be something a transmitter could come to depend on
  // that no receiver has to send.
  res.status(202).set('Cache-Control', 'no-store').end();
  log.debug('Leaving POST /ssf/receive. Accepted.');
});

app.get('/ssf/received', function (req, res) {
  log.debug('Entering GET /ssf/received.');
  if (offCheck(res)) {
    log.debug('Leaving GET /ssf/received. Off.');
    return;
  }
  const decision = gate(req, res, 'read');
  if (!decision) {
    log.debug('Leaving GET /ssf/received. Refused.');
    return;
  }
  res.status(200).type('application/json').set('Cache-Control', 'no-store')
     .send(JSON.stringify({ received: streams.listReceived() }, null, 2));
  log.debug('Leaving GET /ssf/received.');
});

// ---------------------------------------------------------------------------
// WHAT THIS SURFACE IS, AS DATA. Shared by the page below and by
// `?format=json`, so the two cannot disagree — the same reason
// /admin/sts-metadata reads the router.
// ---------------------------------------------------------------------------
function description(req) {
  log.debug('Entering description().');
  const base = ssfBase(req);
  const out = {
    enabled: enabled(),
    issuer: issuerFor(req),
    metadataUrl: baseUrlOf(req) + realms.currentPrefix() + WELL_KNOWN,
    metadata: metadata(req),
    signingAlgorithm: events.signingAlgorithm(),
    delivery: streams.DELIVERY_METHODS.map(function (row) {
      return { method: row.method, name: row.name, what: row.what,
        offered: streams.offeredDeliveryMethods().indexOf(row.method) >= 0 };
    }),
    push: {
      allowed: transport.pushAllowed(),
      allowInsecure: transport.allowInsecure(),
      allowedHosts: transport.allowedHosts(),
      retries: false,
      note: 'Nothing here retries a failed push, deliberately: a client ' +
            'that answers 500 to the first and 202 to the second would ' +
            'look, from its own logs, like a client that works.'
    },
    eventTypes: events.EVENTS.map(function (row) {
      return { uri: row.uri, name: row.name, family: row.family,
        subject: row.subject, what: row.what,
        offered: events.supportedEventUris().indexOf(row.uri) >= 0,
        members: row.members.map(function (member) {
          return { name: member.name, required: member.required,
            what: member.what };
        }) };
    }),
    subjectFormats: subjects.FORMATS.map(function (row) {
      return { format: row.format, members: row.members, what: row.what,
        example: row.example };
    }),
    complexSubjectMembers: subjects.COMPLEX_MEMBERS,
    criticalSubjectMembers: criticalMembers(),
    authentication: ssfAuth.describe(),
    streams: streams.listStreams().map(function (record) {
      return { stream_id: record.stream_id, status: record.status,
        delivery: record.delivery.method,
        events_delivered: record.events_delivered,
        subjects: record.subjects.length, queued: record.queue.length,
        counters: record.counters, createdAt: record.createdAt,
        lastPushError: record.lastPushError };
    }),
    received: streams.listReceived().length,
    endpoints: [
      { method: 'GET', path: WELL_KNOWN,
        what: 'The transmitter configuration metadata. NEVER gated — a ' +
              'receiver has to read what the endpoints are before it can ' +
              'authenticate to one.' },
      { method: 'POST', path: base + '/stream',
        what: 'Create a stream. The transmitter mints the stream_id, sets ' +
              'the iss, and answers with events_delivered — the ' +
              'INTERSECTION of what was requested and what is supported.' },
      { method: 'GET', path: base + '/stream',
        what: 'Read one stream (?stream_id=) or list them all.' },
      { method: 'PUT', path: base + '/stream',
        what: 'REPLACE a stream configuration. A member omitted goes back ' +
              'to its default.' },
      { method: 'PATCH', path: base + '/stream',
        what: 'MERGE into a stream configuration. Only what is present ' +
              'changes.' },
      { method: 'DELETE', path: base + '/stream',
        what: 'Delete a stream.' },
      { method: 'GET', path: base + '/status',
        what: 'Read a stream\'s status.' },
      { method: 'POST', path: base + '/status',
        what: 'Set it to enabled, paused or disabled, and emit a ' +
              'stream-updated event on the stream itself.' },
      { method: 'POST', path: base + '/subjects/add',
        what: 'Add a subject. 204, no body. A SLASH and not a colon — SSF\'s ' +
              'examples write subjects:add, and express reads :add as a ' +
              'route parameter.' },
      { method: 'POST', path: base + '/subjects/remove',
        what: 'Remove one. 204, and IDEMPOTENT: removing a subject that is ' +
              'not there is a 204 rather than a 404.' },
      { method: 'POST', path: base + '/verify',
        what: 'Ask for a verification event. The only end-to-end test a ' +
              'stream has.' },
      { method: 'POST', path: base + '/poll',
        what: 'RFC 8936 poll delivery. ack what you stored, setErrs what ' +
              'you refused.' },
      { method: 'POST', path: base + '/receive',
        what: 'THE ROLES REVERSED: a SET pushed AT this service, so a ' +
              'client can be the transmitter. Not an SSF endpoint.' },
      { method: 'GET', path: base + '/received',
        what: 'What has arrived that way. Not an SSF endpoint either.' }
    ],
    reachableNegatives: [
      { what: 'Create a stream asking for delivery.method "push"',
        answer: '400 invalid_request — the values are the RFC numbers as ' +
                'URNs (urn:ietf:rfc:8935), which catches everybody once' },
      { what: 'Add a subject with an extra member',
        answer: '400 invalid_request naming the member. RFC 9493 closes ' +
                'each format\'s member set' },
      { what: 'Nest an aliases identifier inside another',
        answer: '400 invalid_request — RFC 9493 section 3.2.8 forbids it' },
      { what: 'Poll a PUSH stream',
        answer: '400 invalid_request naming the endpoint its events go to' },
      { what: 'Verify a disabled stream',
        answer: '400 invalid_request — a disabled stream drops what is ' +
                'queued, so there is nowhere for the event to go' },
      { what: 'Ask for an event type the stream does not deliver',
        answer: '400 invalid_request listing what it does deliver' },
      { what: 'Read a stream with a token carrying only ' +
              ssfAuth.scopeRead() + ', then change it',
        answer: '403 access_denied naming the scope' },
      { what: 'Set ssf.verificationRateLimit and verify twice',
        answer: '429 with Retry-After' },
      { what: 'Set ssf.breakSetSignature',
        answer: 'Every SET is signed and then broken by one character, so a ' +
                'receiver that does not verify accepts an unsigned event' },
      { what: 'Set ssf.legacySubClaim',
        answer: 'A deprecated `sub` claim appears beside `sub_id`' }
    ],
    doesNotDo: [
      'It never retries a failed push. RFC 8935 permits a retry; a mock ' +
        'that retried would make a receiver\'s one-shot failure invisible.',
      'It generates no event on its own. Nothing watches a session — every ' +
        'SET was asked for. SSF defines no event about a session, so a ' +
        'transmitter that invented one would be inventing a vocabulary. ' +
        'That changes with CAEP.',
      'It verifies nothing about a subject. A stream may name somebody who ' +
        'has never been here, which is what a receiver\'s "I do not know ' +
        'this subject" path needs.',
      'A `verified: true` on an Add Subject request is believed. There is ' +
        'no confirmation step here to skip.',
      'Streams are in memory and die with the process, like everything ' +
        'else this service mints — the signing key is regenerated on every ' +
        'start, so a restored queue would be tokens nothing can verify.'
    ]
  };
  log.debug('Leaving description().');
  return out;
}

function pageShell(title, inner) {
  log.debug('Entering pageShell().');
  log.debug('Leaving pageShell().');
  return '<!DOCTYPE html>\n<html lang="en"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width, initial-scale=1">' +
    '<title>' + xmlEscape(title) + '</title><style>' +
    'body{font-family:system-ui,-apple-system,"Segoe UI",Arial,sans-serif;' +
    'background:#f4f4f7;margin:0;padding:2rem;color:#222;line-height:1.45}' +
    '.card{background:#fff;border:1px solid #d5d5dd;border-radius:10px;' +
    'padding:24px 28px;max-width:60rem;margin:0 auto;' +
    'box-shadow:0 6px 24px rgba(0,0,0,.08)}' +
    'h1{font-size:1.3em;margin:0 0 4px;color:#12107c}' +
    'h2{font-size:1em;margin:1.4em 0 .4em}' +
    'p.sub{color:#666;font-size:.85em;margin:0 0 18px}' +
    '.warn{background:#fff8e1;border:1px solid #ffe082;padding:9px 12px;' +
    'border-radius:5px;font-size:.82em;margin:0 0 16px}' +
    'table{border-collapse:collapse;width:100%;margin:.5rem 0 1rem;' +
    'font-size:.85em}' +
    'th,td{border:1px solid #ddd;padding:.35rem .55rem;text-align:left;' +
    'vertical-align:top}th{background:#f0f0f5}' +
    'code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;' +
    'font-size:.85em;background:#f4f4f8;padding:.1rem .25rem;' +
    'border-radius:3px;word-break:break-all}a{color:#12107c}' +
    'ul{margin:.3em 0;padding-left:1.2em}li{margin:.2em 0}' +
    '</style></head><body><div class="card">' + inner +
    '</div></body></html>\n';
}

app.get('/ssf', function (req, res) {
  log.debug('Entering GET /ssf.');
  const info = description(req);
  if (String(req.query.format || '').toLowerCase() === 'json') {
    res.status(200).set('Cache-Control', 'no-store').json(info);
    log.debug('Leaving GET /ssf. JSON.');
    return;
  }
  const endpointRows = info.endpoints.map(function (row) {
    return '<tr><td><code>' + xmlEscape(row.method) + '</code></td><td><code>' +
      xmlEscape(row.path) + '</code></td><td>' + xmlEscape(row.what) +
      '</td></tr>';
  }).join('');
  const eventRows = info.eventTypes.map(function (row) {
    return '<tr><td>' + xmlEscape(row.name) + '</td><td><code>' +
      xmlEscape(row.uri) + '</code></td><td>' +
      (row.offered ? 'offered' : 'NOT offered') + '</td><td>' +
      xmlEscape(row.what) + '</td></tr>';
  }).join('');
  const formatRows = info.subjectFormats.map(function (row) {
    return '<tr><td><code>' + xmlEscape(row.format) + '</code></td><td><code>' +
      xmlEscape(row.members.join(', ')) + '</code></td><td>' +
      xmlEscape(row.what) + '</td></tr>';
  }).join('');
  const streamRows = info.streams.length
    ? info.streams.map(function (row) {
        return '<tr><td><code>' + xmlEscape(row.stream_id) +
          '</code></td><td>' + xmlEscape(row.status) + '</td><td>' +
          xmlEscape(streams.deliveryName(row.delivery)) + '</td><td>' +
          row.subjects + '</td><td>' + row.queued + '</td><td>' +
          row.counters.delivered + ' delivered, ' + row.counters.failed +
          ' failed</td></tr>';
      }).join('')
    : '<tr><td colspan="6">No streams. A receiver creates one by POSTing a ' +
      'Stream Configuration to the configuration endpoint above.</td></tr>';
  const negativeRows = info.reachableNegatives.map(function (row) {
    return '<tr><td>' + xmlEscape(row.what) + '</td><td>' +
      xmlEscape(row.answer) + '</td></tr>';
  }).join('');
  const schemeRows = info.authentication.schemes.map(function (row) {
    return '<tr><td>' + xmlEscape(row.name) + '</td><td><code>' +
      xmlEscape(row.spec_urn) + '</code></td><td>' + xmlEscape(row.what) +
      '</td></tr>';
  }).join('');

  const inner = '<h1>Shared Signals — a transmitter lives here</h1>' +
    '<p class="sub">OpenID SSF 1.0 (final, 2 September 2025) over RFC 8417 ' +
    'Security Event Tokens, RFC 9493 subject identifiers, and RFC 8935 / ' +
    '8936 delivery. The issuer is <code>' + xmlEscape(info.issuer) +
    '</code>. ' + (info.enabled ? '' : '<strong>Turned off</strong> ' +
      '(<code>ssf.enabled</code>) — every endpoint but the metadata answers ' +
      '501. ') + 'This page is not an SSF endpoint; a real transmitter ' +
    'publishes nothing like it.</p>' +
    '<div class="warn"><strong>SSF is the PIPE and not the ' +
    'vocabulary.</strong> ' +
    'It defines how two parties agree a stream, who the events are about, ' +
    'what they travel in and how they get there &mdash; and exactly TWO ' +
    'events of its own, both about the pipe. The vocabularies are CAEP ' +
    '(what happened to a session) and RISC (what happened to an account), ' +
    'and neither is here yet. <strong>Nothing generates an event on its ' +
    'own</strong>: every SET this service transmits was asked for, at the ' +
    'verification endpoint, on <a href="/admin/ssf">the console page</a> or ' +
    'through the management API.</div>' +
    '<h2>Discovery</h2>' +
    '<p>Everything below is published at <code>' +
    xmlEscape(info.metadataUrl) + '</code>, which is <strong>never ' +
    'gated</strong> &mdash; a receiver has to be able to read what the ' +
    'endpoints are before it can authenticate to one.</p>' +
    '<h2>Endpoints</h2>' +
    '<table><tr><th>Method</th><th>Path</th><th>What</th></tr>' +
    endpointRows + '</table>' +
    '<h2>Event types</h2>' +
    '<table><tr><th>Name</th><th>URI</th><th>State</th><th>What</th></tr>' +
    eventRows + '</table>' +
    '<p>Every SET is signed with <code>' +
    xmlEscape(info.signingAlgorithm) + '</code> (<code>' +
    'ssf.signingAlgorithm</code>), through the same signer every other JWT ' +
    'here goes through &mdash; so the post-quantum algorithms are available: ' +
    'ML-DSA at three sizes, SLH-DSA at two, and the six composite ML-DSA + ' +
    'traditional ones. This is the document most worth signing that way: a ' +
    'SET records that something happened and RFC 8417 section 4.1.4 forbids ' +
    'it to expire, so it is read long after it was written.</p>' +
    '<h2>Subject identifier formats (RFC 9493)</h2>' +
    '<table><tr><th>format</th><th>Members</th><th>What</th></tr>' +
    formatRows + '</table>' +
    '<p>A <strong>complex</strong> subject has no <code>format</code> and ' +
    'carries any of <code>' +
    xmlEscape(info.complexSubjectMembers.map(function (row) {
      return row.name;
    }).join('</code>, <code>')) + '</code>, each itself a subject ' +
    'identifier. That is what makes &ldquo;this session was revoked&rdquo; ' +
    'expressible: the person is not revoked, one session of theirs is. ' +
    'Critical members here: <code>' +
    xmlEscape(info.criticalSubjectMembers.join(', ') || '(none)') +
    '</code>.</p>' +
    '<h2>Authentication</h2>' +
    '<p>SSF 1.0 section 8 requires these endpoints to be protected and has ' +
    'the transmitter PUBLISH what it accepts, in ' +
    '<code>authorization_schemes</code> &mdash; so a receiver discovers how ' +
    'to authenticate rather than guessing. It is ' +
    (info.authentication.required ? 'ON' : 'OFF (<code>ssf.authRequired' +
      '</code>)') + '. ' + xmlEscape(info.authentication.note) + '</p>' +
    '<table><tr><th>Scheme</th><th>spec_urn</th><th>What</th></tr>' +
    schemeRows + '</table>' +
    '<h2>Streams right now</h2>' +
    '<table><tr><th>stream_id</th><th>Status</th><th>Delivery</th>' +
    '<th>Subjects</th><th>Queued</th><th>Events</th></tr>' + streamRows +
    '</table>' +
    '<h2>What it deliberately does not do</h2><ul>' +
    info.doesNotDo.map(function (text) {
      return '<li>' + xmlEscape(text) + '</li>';
    }).join('') + '</ul>' +
    '<h2>Things you can make fail</h2>' +
    '<table><tr><th>Do this</th><th>Get this</th></tr>' + negativeRows +
    '</table>' +
    '<p class="sub"><a href="/ssf?format=json">This page as JSON</a> ' +
    '&middot; <a href="' + xmlEscape(info.metadataUrl) + '">the transmitter ' +
    'metadata</a> &middot; <a href="/admin/ssf">the console page</a> ' +
    '&middot; <a href="/oauth2/jwks">the key every SET is signed with</a></p>';
  res.status(200).type('html').set('Cache-Control', 'no-store')
     .send(pageShell('Shared Signals Framework', inner));
  log.debug('Leaving GET /ssf.');
});

// ---------------------------------------------------------------------------
// WHAT THE CONSOLE AND THE MANAGEMENT API CALL.
//
// `admin-ui/admin.js` cannot require this module — it is loaded before it, and
// a require the other way would move every SSF route ahead of the console's
// own (rule 1). So this fills a slot on `admin.js`, exactly as `ldap_server.js`
// and `crypto_metadata.js` do, and it carries ONE object: the reader and the
// four actions together, validated whole when it is installed, because a
// partial one would leave `/admin/ssf` able to list streams and unable to
// change any of them.
//
// Rule 3e's test was applied both ways round, as it requires. A require from
// `admin.js` to here CLOSES A CYCLE (this file requires that one for the page
// shell and the gate). A require from here to `admin.js` is what already
// happens and is fine. So a slot is the answer rather than an indirection
// added by analogy.
// ---------------------------------------------------------------------------
function consoleReport(req) {
  log.debug('Entering consoleReport().');
  const info = description(req);
  info.streamDetail = streams.listStreams().map(function (record) {
    return {
      stream_id: record.stream_id,
      iss: record.iss,
      aud: record.aud,
      status: record.status,
      statusReason: record.statusReason,
      delivery: { method: record.delivery.method,
        // NEVER the authorization_header: it is a credential belonging to
        // somebody else's endpoint, and a console page is the one place it
        // must not appear. streamConfiguration()'s `includeSecrets` is what
        // guards the other direction.
        endpoint_url: record.delivery.endpoint_url },
      events_delivered: record.events_delivered,
      events_requested: record.events_requested,
      format: record.format,
      description: record.description,
      createdAt: record.createdAt,
      updatedAt: record.updatedAt,
      createdBy: record.createdBy,
      counters: record.counters,
      lastPushError: record.lastPushError,
      lastPushAt: record.lastPushAt,
      subjects: record.subjects.map(function (one) {
        return { text: subjects.describeSubject(one.subject),
          verified: one.verified, addedAt: one.addedAt,
          subject: one.subject };
      }),
      queue: record.queue.map(function (one) {
        return { jti: one.jti, queuedAt: one.queuedAt,
          deliveredAt: one.deliveredAt,
          summary: events.describeSet(one.claims) };
      }),
      log: record.log.slice().reverse()
    };
  });
  info.receivedDetail = streams.listReceived().slice().reverse();
  log.debug('Leaving consoleReport().');
  return info;
}

// The four actions the console's forms and `POST /admin-api/ssf/:action` share
// — one function, so the two doors cannot disagree about what happened.
function consoleAction(name, body, req) {
  log.debug('Entering consoleAction(). ' + name);
  const asked = body || {};
  const id = String(asked.stream_id || '');
  if (name === 'delete') {
    if (!streams.getStream(id)) {
      log.debug('Leaving consoleAction(). No such stream.');
      return Promise.resolve({ ok: false,
        errors: ['No stream with stream_id "' + id + '".'] });
    }
    streams.removeStream(id);
    audit.audit({ action: 'ssf.stream.delete', category: 'signals',
      protocol: 'SSF', channel: 'http', target: id,
      summary: 'A Shared Signals stream was deleted from the console' });
    log.debug('Leaving consoleAction(). Deleted.');
    return Promise.resolve({ ok: true, message: 'Stream ' + id + ' deleted.',
      errors: [] });
  }
  if (name === 'status') {
    const changed = streams.setStatus(id, String(asked.status || ''),
                                      String(asked.reason || ''));
    if (!changed.ok) {
      log.debug('Leaving consoleAction(). Refused.');
      return Promise.resolve({ ok: false, errors: changed.errors });
    }
    audit.audit({ action: 'ssf.stream.status', category: 'signals',
      protocol: 'SSF', channel: 'http', target: id,
      summary: 'The stream is now ' + changed.stream.status });
    return transmit(changed.stream, {
      uri: events.SSF_PREFIX + 'stream-updated',
      payload: { status: changed.stream.status,
        reason: changed.stream.statusReason || 'set from the console' }
    }).then(function (report) {
      log.debug('Leaving consoleAction(). Status set.');
      return { ok: true, errors: [],
        message: 'Stream ' + id + ' is now ' + changed.stream.status + '. ' +
          (report.ok
            ? 'A stream-updated event was ' + (report.delivered
              ? 'delivered.' : 'queued for the receiver to poll.')
            : 'No stream-updated event went with it: ' + report.why),
        report: report };
    });
  }
  if (name === 'transmit') {
    const record = streams.getStream(id);
    if (!record) {
      log.debug('Leaving consoleAction(). No such stream.');
      return Promise.resolve({ ok: false,
        errors: ['No stream with stream_id "' + id + '".'] });
    }
    let payload = asked.payload;
    if (typeof payload === 'string') {
      try {
        payload = JSON.parse(payload || '{}');
      } catch (e) {
        log.debug('Leaving consoleAction(). The payload is not JSON.');
        return Promise.resolve({ ok: false,
          errors: ['The event payload is not JSON: ' + e.message] });
      }
    }
    let subject = asked.subject;
    if (typeof subject === 'string' && subject.trim()) {
      try {
        subject = JSON.parse(subject);
      } catch (e) {
        log.debug('Leaving consoleAction(). The subject is not JSON.');
        return Promise.resolve({ ok: false,
          errors: ['The subject is not JSON: ' + e.message] });
      }
    } else if (typeof subject === 'string') {
      subject = null;
    }
    return transmit(record, { uri: String(asked.type || ''),
      payload: payload || {}, subject: subject || null,
      txn: String(asked.txn || '') }).then(function (report) {
      log.debug('Leaving consoleAction(). Transmitted.');
      return { ok: report.ok, errors: report.ok ? [] : [report.why],
        message: report.ok
          ? (report.delivered
            ? 'Delivered ' + report.jti + ' to the receiver.'
            : 'Queued ' + report.jti + ' for the receiver to poll.')
          : report.why,
        report: report };
    });
  }
  if (name === 'clear-received') {
    const gone = streams.clearReceived();
    log.debug('Leaving consoleAction(). Cleared.');
    return Promise.resolve({ ok: true, errors: [],
      message: gone + ' received event(s) dropped.' });
  }
  // THE REFUSAL IS SPELLED THE WAY EVERY OTHER ACTION HANDLER HERE SPELLS IT,
  // AND IT WAS NOT UNTIL 2026-09-01. It said `"x" is not an action on this
  // resource. The ones that are: …`, which reads perfectly well and is
  // INVISIBLE to the two checks that actually depend on this sentence:
  // `tests/vendored/admin_api.js` requires /unknown action/i before it will
  // parse the list — that is the console/API parity check, so /ssf's four
  // actions were being compared against nothing — and
  // `tests/vendored/sts_admin_api_operations.js` matches `Unknown action "x".
  // <count phrase>: <list>.` across every documented resource, which is what
  // caught it. The lesson is the one `helpers.numberWord()`'s header already
  // states: this sentence is not prose, it is READ, and a handler that writes
  // it its own way turns a check off with nothing failing.
  //
  // The count comes from the LIST rather than from a word typed beside it, for
  // the same reason: `applicationsAction()` said "The six are" over seven for
  // a fortnight.
  log.debug('Leaving consoleAction(). Unknown action.');
  return Promise.resolve({ ok: false,
    errors: ['Unknown action "' + String(name) + '". The ' +
      numberWord(CONSOLE_ACTIONS.length) + ' are: ' +
      CONSOLE_ACTIONS.join(', ') + '.'] });
}

const CONSOLE_ACTIONS = ['status', 'delete', 'transmit', 'clear-received'];

adminConsole.setSignalsReporter({
  report: consoleReport,
  action: consoleAction,
  actions: CONSOLE_ACTIONS,
  eventTypes: function () {
    return events.EVENTS.map(function (row) {
      return { uri: row.uri, name: row.name,
        offered: events.supportedEventUris().indexOf(row.uri) >= 0 };
    });
  },
  statuses: events.STATUSES,
  subjectFormats: subjects.FORMATS
});

// ---------------------------------------------------------------------------
// AUTOMATIC EMISSION — THE ONE PLACE IN THIS SERVICE WHERE AN ENDPOINT IS NOT
// WHAT STARTS THE WORK.
//
// Every other protocol family here answers a request. This function is called
// because somebody signed in, presented a session or signed out, and it makes
// a Security Event Token go out to whoever agreed to be told. That is what
// CAEP is FOR, and it is the sentence on `GET /ssf`'s *what it deliberately
// does not do* list that had to change: while the only vocabulary was the
// pipe's own, "this service generates no event on its own" was honest, because
// SSF defines no event about a session and a transmitter that invented one
// would have been inventing a vocabulary. CAEP is that vocabulary.
//
// `caep.autoEmit` puts the old behaviour back rather than leaving it only in
// the history of this file, and `GET /ssf` reads the setting rather than
// asserting either sentence.
//
// **THE DIVISION OF LABOUR.** `caep.js` decides WHAT the event would be and
// updates the register whether or not anything is sent; this decides WHERE it
// goes. That is why the register shows a session with a count of zero — which
// is the answer to "why did nothing arrive?" nine times out of ten, and the
// answer is *nobody asked for that type*.
//
// **IT RETURNS A PROMISE AND NOBODY AWAITS IT.** `authn.js` calls this from
// inside a sign-out and does not wait, deliberately: a push delivery takes as
// long as somebody else's endpoint does, and a sign-out that blocked on a
// receiver's TCP timeout would be a sign-out that hangs. Every outcome is
// logged and recorded on the stream, which is where a person looks anyway.
// ---------------------------------------------------------------------------
function caepAutoEmit(notice) {
  log.debug('Entering caepAutoEmit().');
  if (!enabled()) {
    log.debug('Leaving caepAutoEmit(). SSF is off.');
    return Promise.resolve({ sent: 0, streams: 0 });
  }
  // THE ISSUER IS ADDED HERE AND NOT IN `authn.js`, because it is an SSF fact
  // and that module has no business knowing one. It matters more than it
  // looks: the subject names the person by ISSUER and subject, and a receiver
  // matches that `iss` against the issuer it discovered — so an event built
  // with the wrong one names somebody the receiver has never heard of and is
  // refused, which reads at the far end as a bad subject rather than as a
  // misconfigured transmitter.
  const due = caep.observe(Object.assign({}, notice || {},
      { issuer: issuerFor((notice || {}).req || null) }));
  if (!due) {
    log.debug('Leaving caepAutoEmit(). Nothing is due.');
    return Promise.resolve({ sent: 0, streams: 0 });
  }
  const candidates = streams.listStreams().filter(function (record) {
    return record.events_delivered.indexOf(due.uri) >= 0 &&
           streams.streamCoversSubject(record, due.subject);
  });
  if (!candidates.length) {
    // SAID ONCE, AT INFO, AND IT IS THE MOST USEFUL LINE THIS FEATURE
    // PRODUCES. "Nothing arrived" is the commonest report about any Shared
    // Signals deployment and its commonest cause is this: the event happened,
    // the transmitter built it, and no stream had asked for that type or
    // covered that subject. The register carries the same fact for the page.
    log.info('caep: a ' + due.uri.slice(events.CAEP_PREFIX.length) + ' is ' +
             'due for session ' + due.row.sessionId + ' and NO STREAM ' +
             'takes it — ' + streams.listStreams().length + ' stream(s) ' +
             'exist, and none both delivers that type and covers ' +
             subjects.describeSubject(due.subject) + '. The event is ' +
             'recorded on /admin/caep-sessions with nothing sent.');
    due.row.notes.push('A ' + due.uri.slice(events.CAEP_PREFIX.length) +
        ' was due and no stream takes it.');
    due.row.notes = due.row.notes.slice(-5);
    log.debug('Leaving caepAutoEmit(). No stream takes it.');
    return Promise.resolve({ sent: 0, streams: 0 });
  }
  return Promise.all(candidates.map(function (record) {
    return transmit(record, { uri: due.uri, payload: due.payload,
      subject: due.subject, toe: due.payload.event_timestamp });
  })).then(function (reports) {
    const sent = reports.filter(function (one) {
      return one.ok;
    }).length;
    log.info('caep: ' + due.uri.slice(events.CAEP_PREFIX.length) + ' for ' +
             'session ' + due.row.sessionId + ' went to ' + sent + ' of ' +
             candidates.length + ' stream(s).');
    log.debug('Leaving caepAutoEmit(). ' + sent + ' sent.');
    return { sent: sent, streams: candidates.length, reports: reports };
  }).catch(function (e) {
    // Swallowed HERE as well as in authn.js, and not redundantly: that catch
    // covers this function throwing synchronously and this one covers a
    // rejected promise nobody is waiting on, which node reports as an
    // unhandled rejection and — depending on the flags — ends the process.
    log.error('caep: automatic emission failed: ' + e.message);
    log.debug('Leaving caepAutoEmit(). Failed.');
    return { sent: 0, streams: candidates.length, why: e.message };
  });
}

// The inverted hook, filled at require time. `authn.js` is 8 in the require
// order and this module is 23b, so this is the only direction that works —
// see setSessionObserver()'s header over there.
authn.setSessionObserver(caepAutoEmit);

// ---------------------------------------------------------------------------
// THE CAEP CONSOLE AND MANAGEMENT API.
//
// `/admin/caep`, `/admin/caep-sessions` and `/admin-api/caep` reach this
// directory through `admin.setCaepReporter()`, the NINTH slot, for exactly the
// reasons the eighth exists: a require from `admin.js` to this file would
// close a cycle, and one from `mgmt-api/admin_api.js` would move every `/ssf`
// route ahead of the management API's own.
//
// `action` returns a PROMISE, like the signals slot's and for the same reason:
// emitting an event signs a JWS — possibly on the worker pool — and then POSTs
// it to somebody else's endpoint.
// ---------------------------------------------------------------------------
function caepReport(req) {
  log.debug('Entering caepReport().');
  const report = caep.report();
  report.issuer = issuerFor(req);
  report.ssfEnabled = enabled();
  // WHICH STREAMS WOULD TAKE A CAEP EVENT AT ALL, computed rather than
  // configured, because it is the question the page exists to answer second:
  // a reader who has seen a session with a count of zero wants to know
  // whether ANY stream would have taken one.
  report.streams = streams.listStreams().map(function (record) {
    const takes = events.CAEP_EVENT_URIS.filter(function (uri) {
      return record.events_delivered.indexOf(uri) >= 0;
    });
    return { stream_id: record.stream_id, aud: record.aud,
      status: record.status, delivery: record.delivery.method,
      subjects: record.subjects.length,
      takes: takes.map(function (uri) {
        return uri.slice(events.CAEP_PREFIX.length);
      }) };
  });
  log.debug('Leaving caepReport(). ' + report.tracked + ' session(s).');
  return report;
}

// Emit one CAEP event BY HAND. Five of the eight describe things nothing here
// does — no device reports compliance to this service and no risk engine talks
// to it — so this is the only way they are ever produced, and it is why the
// action exists rather than the page being read-only.
function caepEmit(asked) {
  log.debug('Entering caepEmit().');
  const uri = String(asked.type || '').indexOf(events.CAEP_PREFIX) === 0
    ? String(asked.type)
    : events.CAEP_PREFIX + String(asked.type || '');
  const row = events.EVENT_BY_URI[uri];
  if (!row || row.family !== 'caep') {
    log.debug('Leaving caepEmit(). Not a CAEP event type.');
    return Promise.resolve({ ok: false, errors: [
      '"' + String(asked.type || '') + '" is not one of CAEP\'s eight event ' +
      'types. They are: ' + events.CAEP_EVENT_URIS.map(function (one) {
        return one.slice(events.CAEP_PREFIX.length);
      }).join(', ') + '.'] });
  }
  const sessionId = String(asked.session_id || '');
  const known = caep.get(sessionId);
  if (!known) {
    log.debug('Leaving caepEmit(). No such session.');
    return Promise.resolve({ ok: false, errors: [
      'No session "' + sessionId + '" is tracked here. A CAEP event is ' +
      'ABOUT a session — the subject names one — so there is nothing to ' +
      'compose a subject from. Sign somebody in, or pick a row from ' +
      '/admin/caep-sessions.'] });
  }
  let values = asked.payload;
  if (typeof values === 'string' && values.trim()) {
    try {
      values = JSON.parse(values);
    } catch (e) {
      log.debug('Leaving caepEmit(). The payload is not JSON.');
      return Promise.resolve({ ok: false,
        errors: ['The event payload is not JSON: ' + e.message] });
    }
  }
  const payload = caep.buildPayload(uri, values || {}, {
    initiatingEntity: String(asked.initiating_entity || 'admin'),
    reasonAdmin: String(asked.reason_admin || '') ||
      'Emitted by hand from the console.',
    reasonUser: String(asked.reason_user || '')
  });
  const verdict = events.validateEvent(uri, payload);
  if (!verdict.ok) {
    log.debug('Leaving caepEmit(). The payload is invalid.');
    return Promise.resolve({ ok: false, errors: verdict.errors });
  }
  const subject = caep.subjectFor(known);
  const candidates = streams.listStreams().filter(function (record) {
    return record.events_delivered.indexOf(uri) >= 0 &&
           streams.streamCoversSubject(record, subject);
  });
  audit.audit({ action: 'caep.event.emit', category: 'signals',
    protocol: 'CAEP', channel: 'http', target: sessionId,
    summary: 'A CAEP ' + row.name + ' was emitted by hand for session ' +
      sessionId,
    detail: { type: uri, streams: candidates.length } });
  if (!candidates.length) {
    // The register is still told, so the page shows the state change even
    // though nothing was sent — which is the honest report and is what makes
    // "nothing arrived" traceable to "nobody asked" rather than to a bug.
    const applied = caep.applyToState(known, uri, payload);
    log.debug('Leaving caepEmit(). No stream takes it.');
    return Promise.resolve({ ok: applied.ok, errors: applied.errors,
      warnings: applied.warnings,
      message: applied.ok
        ? 'Nothing was sent: no stream both delivers "' +
          uri.slice(events.CAEP_PREFIX.length) + '" and covers ' +
          subjects.describeSubject(subject) + '. The session\'s state was ' +
          'still updated, so the change is on this page.'
        : applied.errors.join(' ') });
  }
  return Promise.all(candidates.map(function (record) {
    return transmit(record, { uri: uri, payload: payload, subject: subject,
      toe: payload.event_timestamp });
  })).then(function (reports) {
    const sent = reports.filter(function (one) {
      return one.ok;
    }).length;
    log.debug('Leaving caepEmit(). ' + sent + ' of ' + reports.length + '.');
    return { ok: sent > 0,
      errors: sent > 0 ? [] : reports.map(function (one) {
        return one.why;
      }),
      message: sent + ' of ' + reports.length + ' stream(s) took the ' +
        row.name + '.',
      reports: reports };
  });
}

function caepAction(name, body) {
  log.debug('Entering caepAction(). ' + name);
  const asked = body || {};
  if (name === 'emit') {
    return caepEmit(asked);
  }
  if (name === 'reset-session') {
    const row = caep.reset(String(asked.session_id || ''));
    if (!row) {
      log.debug('Leaving caepAction(). No such session.');
      return Promise.resolve({ ok: false,
        errors: ['No session "' + String(asked.session_id || '') + '" is ' +
                 'tracked here.'] });
    }
    log.debug('Leaving caepAction(). Reset.');
    return Promise.resolve({ ok: true, errors: [],
      message: 'The CAEP state of session ' + row.sessionId + ' was reset. ' +
        'The sign-in itself is untouched — this page is about what has been ' +
        'SAID about that session, and nobody has been signed out.' });
  }
  if (name === 'clear') {
    const gone = caep.clear();
    log.debug('Leaving caepAction(). Cleared.');
    return Promise.resolve({ ok: true, errors: [],
      message: gone + ' session row(s) dropped. Nothing was signed out: ' +
        'this register is a record of what was said, and clearing it ' +
        'forgets the record rather than ending anything.' });
  }
  // Spelled the way every other action handler here spells it, with the count
  // from the list rather than from a word typed beside it. That sentence is
  // READ — `tests/vendored/admin_api.js` requires /unknown action/i before it
  // will parse the list, and `sts_admin_api_operations.js` matches the whole
  // shape — so a handler that writes it its own way turns two checks off with
  // nothing failing.
  log.debug('Leaving caepAction(). Unknown action.');
  return Promise.resolve({ ok: false,
    errors: ['Unknown action "' + String(name) + '". The ' +
      numberWord(CAEP_CONSOLE_ACTIONS.length) + ' are: ' +
      CAEP_CONSOLE_ACTIONS.join(', ') + '.'] });
}

const CAEP_CONSOLE_ACTIONS = ['emit', 'reset-session', 'clear'];

adminConsole.setCaepReporter({
  report: caepReport,
  action: caepAction,
  actions: CAEP_CONSOLE_ACTIONS,
  eventTypes: function () {
    return events.CAEP_EVENTS.map(function (row) {
      return { uri: row.uri, name: row.name,
        short: row.uri.slice(events.CAEP_PREFIX.length),
        subject: row.subject,
        offered: events.supportedEventUris().indexOf(row.uri) >= 0,
        members: row.members.map(function (member) {
          return { name: member.name, required: !!member.required,
            type: member.type, values: member.values || [],
            what: member.what };
        }),
        required: row.required.slice(),
        what: row.what };
    });
  }
});

module.exports = {
  WELL_KNOWN: WELL_KNOWN,
  metadata: metadata,
  description: description,
  transmit: transmit,
  consoleReport: consoleReport,
  consoleAction: consoleAction,
  CONSOLE_ACTIONS: CONSOLE_ACTIONS,
  caepAutoEmit: caepAutoEmit,
  caepReport: caepReport,
  caepAction: caepAction,
  CAEP_CONSOLE_ACTIONS: CAEP_CONSOLE_ACTIONS
};
