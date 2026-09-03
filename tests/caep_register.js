'use strict';
//
// File: caep_register.js
//
// ===========================================================================
// THE CAEP SESSION REGISTER AND ITS STATE MACHINE, DRIVEN IN PROCESS.
//
// `ssf/caep.js` is what the eight CAEP event types are ABOUT: a session, the
// state CAEP believes it is in, and how many events of which type have been
// sent concerning it. It has no DOM, no socket and no route, which is what
// makes it drivable here.
//
// ---------------------------------------------------------------------------
// WHY IN PROCESS, WHICH IS THE QUESTION tests/CLAUDE.md ASKS FIRST.
//
// Most of this profile belongs over HTTP and is not here. That a sign-in
// really does put a Security Event Token on a stream, that a stream asking for
// the eight gets the eight back in `events_delivered`, that turning
// `caep.autoEmit` off stops it — all of that is driven against a running
// service by the parent project's `tests/caep_protocol.js`, with a real
// receiver at the far end. What is here is the four things that CANNOT be:
//
//   * **THE STATE MACHINE'S ONE HARD REFUSAL.** A `session-presented` about a
//     session that has already been revoked is a transmitter contradicting
//     itself, and there is no way to make a running service produce one: the
//     session is gone from the session store, so nothing can present it. It
//     is reachable only by applying the event to the register directly, which
//     is exactly what a receiver under test would be sent by a transmitter
//     that had this wrong.
//
//   * **THE MISSED-EVENT WARNINGS.** `device-compliance-change` and
//     `risk-level-change` both carry the PREVIOUS value, and comparing it
//     against what the register holds is the only way to notice that an event
//     went missing. Producing that over HTTP would mean dropping a delivery on
//     purpose and hoping the gap landed where it was wanted.
//
//   * **THE COUNTERS AGAINST THE RING.** `counts` never forgets and `events`
//     keeps the last twenty-five, and the defect worth catching is the two
//     being conflated — a page that answered "how many" from the ring would
//     say three where there were nine. Reaching that over HTTP means sending
//     twenty-six events.
//
//   * **THE REGISTER OUTLIVING THE SESSION.** A row saying `revoked` for a
//     session the service no longer holds is the whole point of the page, and
//     over HTTP it is indistinguishable from a row for a session that is
//     merely idle.
//
// The LANGUAGE MAP case is the one worth reading first. CAEP makes
// `reason_admin` and `reason_user` objects keyed by a BCP 47 tag, a string
// there is the commonest mistake in the profile, and it has NO SYMPTOM: a
// receiver indexing by language reads nothing from a string and reports no
// error. Every other assertion in this file is about a defect that at least
// looks like something.
// ===========================================================================

// Deleted rather than set, for the reason config_realm_layer.js gives: nothing
// here should depend on a developer's exported appconfig.
delete process.env.CONFIG_FILE;

const config = require('../common/config');
const events = require('../ssf/ssf_events');
const caep = require('../ssf/caep');

const P = events.CAEP_PREFIX;

// A sign-in, in the shape `authn.js`'s observer hands one over.
function signIn(id, username) {
  return { kind: 'established', via: 'OAuth 2.0 / OIDC',
    issuer: 'https://sts.example.com',
    session: { id: id, user: { sub: 'u-' + username, username: username },
      acr: 'urn:example:silver', amr: ['pwd'] } };
}

// What `ssf.js`'s transmit() hands back to the register once the SET exists.
function transmitted(row, uri, payload, streamId) {
  caep.noteTransmitted({ stream_id: streamId || 'st-1' }, {
    jti: 'jti-' + Math.random().toString(16).slice(2, 10),
    iss: 'https://sts.example.com',
    sub_id: caep.subjectFor(row),
    events: (function () {
      const map = {};
      map[uri] = payload;
      return map;
    })()
  });
}

function run(t) {
  caep.clear();

  // -----------------------------------------------------------------------
  t.log.info('A. a sign-in makes an event due, and the payload conforms');
  // -----------------------------------------------------------------------
  const due = caep.observe(signIn('sess-a', 'alice'));
  t.check(!!due, 'a sign-in makes something due — this is the one place in ' +
          'this service where an endpoint is not what starts the work');
  t.equal(due.uri, P + 'session-established',
          'and it is session-established, which is the event that CLOSES THE ' +
          'LOOP: without it a receiver only ever hears about sessions ' +
          'ending, so it can never hold an inventory of what is open');
  const verdict = events.validateEvent(due.uri, due.payload);
  t.equal(verdict.ok, true,
          'the payload this service composes validates against its own ' +
          'catalogue — ' + verdict.errors.join(' '));
  t.equal(typeof due.payload.event_timestamp, 'number',
          'event_timestamp is a NUMBER of seconds. A quoted timestamp parses ' +
          'everywhere and is compared numerically nowhere');
  t.equal(due.payload.amr.join(','), 'pwd',
          'amr crosses as an ARRAY. A session authenticated a second way has ' +
          'two values, and a receiver reading a bare string would see one');

  // -----------------------------------------------------------------------
  t.log.info('B. reason_admin and reason_user are LANGUAGE MAPS, which is ' +
             'the mistake in this profile with no symptom');
  // -----------------------------------------------------------------------
  t.equal(typeof due.payload.reason_admin, 'object',
          'reason_admin is an object and not a string');
  t.equal(typeof due.payload.reason_admin.en, 'string',
          'keyed by the BCP 47 tag caep.reasonLanguage names, so a receiver ' +
          'indexing by language finds something. A string here reads as ' +
          'nothing at the far end and reports no error, which is why this ' +
          'is checked rather than assumed');
  const asString = events.validateEvent(P + 'session-revoked',
    { reason_admin: 'a plain string' });
  t.equal(asString.ok, false,
          'and a string is REFUSED rather than carried, because carrying it ' +
          'would produce a document that is accepted, ignored and never ' +
          'reported');

  // -----------------------------------------------------------------------
  t.log.info('C. the subject is COMPLEX — the person is not revoked, one ' +
             'session of theirs is');
  // -----------------------------------------------------------------------
  t.equal(due.subject.format, undefined,
          'a complex subject is told from a plain one by the ABSENCE of ' +
          '`format`, which is SSF section 4\'s own discriminator');
  t.equal(due.subject.user.format, 'issuer_subject_id',
          'the person is named by the identifier a receiver already holds — ' +
          'an ID Token\'s iss and sub');
  t.equal(due.subject.session.id, 'sess-a',
          'and the SESSION is named beside them. A subject naming only the ' +
          'person asks a receiver to end every session they have, which is a ' +
          'much larger instruction than the one that was meant');

  // -----------------------------------------------------------------------
  t.log.info('D. the counters count what was minted, and the state follows');
  // -----------------------------------------------------------------------
  const row = caep.get('sess-a');
  transmitted(row, due.uri, due.payload);
  t.equal(row.counts[P + 'session-established'], 1,
          'one session-established has been sent about this session');
  t.equal(row.total, 1, 'and the total agrees');
  t.equal(row.state, 'established', 'the state followed the event');

  const presented = caep.observe({ kind: 'presented', via: 'OAuth 2.0 / OIDC',
    session: signIn('sess-a', 'alice').session });
  transmitted(row, presented.uri, presented.payload);
  t.equal(row.state, 'presented',
          'single sign-on moved it to presented — the one CAEP event about ' +
          'something entirely ordinary, and the one that lets a receiver see ' +
          'a live session it is not itself being asked about');

  const revoked = caep.observe({ kind: 'revoked', via: 'the sign-out endpoint',
    session: signIn('sess-a', 'alice').session });
  transmitted(row, revoked.uri, revoked.payload);
  t.equal(row.state, 'revoked', 'and a sign-out revoked it');
  t.equal(row.total, 3, 'three events have been sent about this session');

  // -----------------------------------------------------------------------
  t.log.info('E. THE ONE HARD REFUSAL: a revoked session cannot have been ' +
             'presented and honoured');
  // -----------------------------------------------------------------------
  const contradiction = caep.applyToState(row, P + 'session-presented', {});
  t.equal(contradiction.ok, false,
          'refused outright. That sentence says a session this transmitter ' +
          'has already declared dead was just used and honoured, which is ' +
          'either a transmitter contradicting itself or a receiver about to ' +
          'be told to trust something it was told to stop trusting');
  t.equal(row.state, 'revoked',
          'and the state did not move, which is the half that matters: a ' +
          'refusal that still applied the change would be worse than none');

  const again = caep.applyToState(row, P + 'session-revoked', {});
  t.equal(again.ok, true,
          'a SECOND revocation is not refused — a receiver should be ' +
          'idempotent about it, and that is exactly the thing worth testing');
  t.check(again.warnings.length > 0,
          'it is noted rather than passed over in silence');

  // -----------------------------------------------------------------------
  t.log.info('F. the register OUTLIVES the session, which is the whole ' +
             'reason /admin/caep-sessions exists');
  // -----------------------------------------------------------------------
  const report = caep.report();
  const still = report.sessions.filter(function (one) {
    return one.sessionId === 'sess-a';
  })[0];
  t.check(!!still,
          'the row is still there after the sign-out. The session store ' +
          'forgot the session; this row is the only remaining evidence that ' +
          'it existed and was revoked, and nothing else in this service ' +
          'records it');
  t.equal(still.state, 'revoked', 'saying what happened to it');

  // -----------------------------------------------------------------------
  t.log.info('G. previous_status and previous_level are how a MISSED event ' +
             'becomes visible, and nothing else can see it');
  // -----------------------------------------------------------------------
  caep.observe(signIn('sess-b', 'bob'));
  const bob = caep.get('sess-b');
  caep.applyToState(bob, P + 'device-compliance-change',
    { previous_status: 'compliant', current_status: 'not-compliant' });
  t.equal(bob.compliance, 'not-compliant', 'the device fell out of policy');
  const gap = caep.applyToState(bob, P + 'device-compliance-change',
    { previous_status: 'compliant', current_status: 'not-compliant' });
  t.check(gap.warnings.some(function (one) {
    return /has been missed|register holds/.test(one);
  }), 'a second event claiming the device WAS compliant is noticed: this ' +
      'register holds "not-compliant", so one event about this session never ' +
      'arrived. THAT GAP IS INVISIBLE FROM EITHER EVENT ON ITS OWN, and it ' +
      'is the whole reason CAEP makes previous_status required');

  caep.applyToState(bob, P + 'risk-level-change',
    { principal: 'SESSION', current_level: 'HIGH', previous_level: 'LOW' });
  t.equal(bob.risk.level, 'HIGH', 'the risk level moved');
  const riskGap = caep.applyToState(bob, P + 'risk-level-change',
    { principal: 'SESSION', current_level: 'MEDIUM', previous_level: 'LOW' });
  t.check(riskGap.warnings.length > 0,
          'and the same comparison catches a missed risk event');

  // -----------------------------------------------------------------------
  t.log.info('H. token-claims-change MERGES, because `claims` carries only ' +
             'what moved');
  // -----------------------------------------------------------------------
  caep.applyToState(bob, P + 'token-claims-change',
    { claims: { groups: ['staff'], department: 'ops' } });
  caep.applyToState(bob, P + 'token-claims-change',
    { claims: { groups: [] } });
  t.equal(bob.claims.department, 'ops',
          'a claim the second event did not mention SURVIVES. A receiver ' +
          'that replaced rather than merged would drop every claim the event ' +
          'was silent about, which is most of them');
  t.equal(bob.claims.groups.length, 0,
          'and the one it did mention took its new value');

  // -----------------------------------------------------------------------
  t.log.info('I. THE COUNTS ARE NOT THE LIST');
  // -----------------------------------------------------------------------
  for (let i = 0; i < 30; i += 1) {
    transmitted(bob, P + 'session-presented', { ext_id: 'sess-b' });
  }
  t.equal(bob.counts[P + 'session-presented'], 30,
          'thirty presentations were counted');
  t.equal(bob.events.length, 25,
          'and the ring kept the last twenty-five. A page that answered "how ' +
          'many" out of this list would say twenty-five where there were ' +
          'thirty — which is why the two are separate rather than derived');

  // -----------------------------------------------------------------------
  t.log.info('J. a plain subject counts against no row, and says so');
  // -----------------------------------------------------------------------
  const before = caep.list().length;
  const noRow = caep.noteTransmitted({ stream_id: 'st-1' }, {
    jti: 'jti-plain',
    sub_id: { format: 'email', email: 'alice@example.com' },
    events: (function () {
      const map = {};
      map[P + 'session-revoked'] = {};
      return map;
    })()
  });
  t.equal(noRow, null,
          'an event whose subject names a PERSON rather than a session ' +
          'legitimately matches nothing here — this register is about ' +
          'sessions — and it answers null rather than inventing a row');
  t.equal(caep.list().length, before,
          'and no row was created for it');

  // -----------------------------------------------------------------------
  t.log.info('K. caep.enabled off drops the eight from what is offered');
  // -----------------------------------------------------------------------
  t.equal(caep.supportedEventUris().length, 8,
          'eight types while the profile is on');
  config.setOverride('caep.enabled', 'false');
  t.equal(caep.supportedEventUris().length, 0,
          'and none while it is off');
  t.equal(events.supportedEventUris().filter(function (uri) {
    return uri.indexOf(P) === 0;
  }).length, 0,
          'AND THE TRANSMITTER STOPS ADVERTISING THEM, which is the half ' +
          'that matters: a stream asking for one then gets it back MISSING ' +
          'from events_delivered, and that absence is the only notice SSF ' +
          'gives a receiver');
  t.equal(caep.observe(signIn('sess-c', 'carol')), null,
          'and nothing becomes due while it is off');
  config.setOverride('caep.enabled', 'true');

  // -----------------------------------------------------------------------
  t.log.info('L. autoEmit off keeps the register honest and sends nothing');
  // -----------------------------------------------------------------------
  config.setOverride('caep.autoEmit', 'false');
  const quiet = caep.observe(signIn('sess-d', 'dave'));
  t.equal(quiet, null, 'nothing is due — this service\'s older behaviour, ' +
          'where every Security Event Token it sends was asked for');
  const dave = caep.get('sess-d');
  t.check(!!dave,
          'AND THE SESSION IS STILL TRACKED. A page that showed nothing here ' +
          'would leave "why did no event arrive" unanswerable; a row with a ' +
          'count of zero answers it');
  t.equal(dave.state, 'established', 'with the state that really happened');
  config.setOverride('caep.autoEmit', 'true');

  // -----------------------------------------------------------------------
  t.log.info('M. omitEventTimestamp produces a CONFORMING event without one');
  // -----------------------------------------------------------------------
  config.setOverride('caep.omitEventTimestamp', 'true');
  const bare = caep.buildPayload(P + 'session-revoked', {}, {});
  t.equal(Object.prototype.hasOwnProperty.call(bare, 'event_timestamp'), false,
          'no event_timestamp');
  t.equal(events.validateEvent(P + 'session-revoked', bare).ok, true,
          'AND IT IS STILL VALID. CAEP section 2 makes the member optional, ' +
          'so this is a perfectly conforming transmitter — and it is what ' +
          'every receiver that assumes a timestamp breaks on, which is the ' +
          'only reason the setting exists');
  config.setOverride('caep.omitEventTimestamp', 'false');

  // -----------------------------------------------------------------------
  t.log.info('N. an OPEN enumeration warns and a CLOSED one refuses');
  // -----------------------------------------------------------------------
  const vendor = events.validateEvent(P + 'credential-change',
    { credential_type: 'acme-smartcard', change_type: 'create' });
  t.equal(vendor.ok, true,
          'a credential type CAEP does not list is CARRIED — the ' +
          'specification lets two parties agree their own, and refusing ' +
          'would make this service unable to mock a vendor\'s');
  t.check(vendor.warnings.length > 0, 'with a warning saying so');
  const bogus = events.validateEvent(P + 'credential-change',
    { credential_type: 'password', change_type: 'mutate' });
  t.equal(bogus.ok, false,
          'and change_type is CLOSED: those four are the whole lifecycle, ' +
          'and a fifth would be a receiver guessing');

  // -----------------------------------------------------------------------
  t.log.info('O. reset keeps the row and clears what was said about it');
  // -----------------------------------------------------------------------
  caep.reset('sess-b');
  const afterReset = caep.get('sess-b');
  t.equal(afterReset.total, 0, 'the counters are zero');
  t.equal(afterReset.state, 'established', 'the state is back to the start');
  t.equal(afterReset.compliance, '', 'and so is the device compliance');
  t.check(!!afterReset,
          'THE ROW SURVIVES. A delete would take it off the page, which ' +
          'reads as the session having gone — and nobody was signed out: ' +
          'this register is a record of what was SAID');

  const gone = caep.clear();
  t.check(gone > 0, 'clearing drops every row, and says how many');
  t.equal(caep.list().length, 0, 'the register is empty');
}

module.exports = {
  name: 'caep_register',
  describe: 'what CAEP believes about a session, and the one sentence it ' +
            'refuses to carry',
  run: run
};
