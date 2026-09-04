'use strict';
//
// File: risc_register.js
//
// ===========================================================================
// THE RISC ACCOUNT REGISTER AND ITS THREE STATE MACHINES, DRIVEN IN PROCESS.
//
// `ssf/risc.js` is what the fourteen RISC event types are ABOUT: an ACCOUNT,
// the states RISC believes it is in, and how many events of which type have
// been sent concerning it. It has no DOM, no socket and no route, which is
// what makes it drivable here.
//
// ---------------------------------------------------------------------------
// WHY IN PROCESS, WHICH IS THE QUESTION tests/CLAUDE.md ASKS FIRST.
//
// Most of this profile belongs over HTTP and is not here. That a SCIM write
// really does put a Security Event Token on a stream, that a stream asking
// for the fourteen gets the fourteen back in `events_delivered`, that turning
// `risc.autoEmit` off stops it — all of that is driven against a running
// service by the parent project's `tests/risc_protocol.js`, with a real
// receiver at the far end. What is here is the six things that CANNOT be:
//
//   * **ONE DIRECTORY WRITE PRODUCING TWO EVENTS.** A `PUT /Users/:id` that
//     sets `active` to false AND changes a mail address is two RISC events
//     about one act, and the defect worth catching is an observer that
//     answers with the first — which over HTTP is indistinguishable from a
//     service where only one thing changed.
//
//   * **THE OPT-OUT GATE AND ITS EXCEPTION.** RISC section 2.8 says an
//     opted-out account is not participating, so its events are suppressed —
//     except for the four opt-out events themselves, without which
//     `opt-out-effective` could never be delivered and `opt-in` could never
//     bring an account back. Reaching that over HTTP means driving an account
//     into a state where, by construction, nothing arrives.
//
//   * **THE ONE HARD REFUSAL.** `account-enabled` about an account this
//     transmitter has declared PURGED. There is no way to make a running
//     service produce one: the directory entry is gone, so nothing can
//     enable it.
//
//   * **THE REGISTER FOLLOWING AN ACT NOBODY WAS TOLD ABOUT.** Deleting a
//     person from a service with no RISC stream agreed must still leave a row
//     saying `purged`. Over HTTP that is indistinguishable from a row for an
//     account nothing has happened to, which is exactly the confusion
//     /admin/risc-accounts exists to end.
//
//   * **THE COUNTERS AGAINST THE RING**, for `caep_register.js`'s reason.
//
//   * **THE SUBJECT FORMAT SWITCHING PER EVENT TYPE.** Eleven of the fourteen
//     use `risc.subjectFormat` and the two identifier events ignore it, and a
//     transmitter that honoured the setting there would send an `iss_sub`
//     subject on an event whose entire content is an email address.
//
// The NEAR-MISS MEMBER NAME is the one worth reading first. `new-value` is
// the only hyphenated member name in any of the three vocabularies, so
// `new_value` typed from habit produces an event that validates, delivers,
// and tells the receiver nothing — with no symptom at either end.
// ===========================================================================

// Deleted rather than set, for the reason config_realm_layer.js gives.
delete process.env.CONFIG_FILE;

const config = require('../common/config');
const events = require('../ssf/ssf_events');
const risc = require('../ssf/risc');

const P = events.RISC_PREFIX;

// A directory write, in the shape `ldap_server.js`'s observer hands one over.
// The attribute names are LOWER CASE because that is how the store keys them,
// and getting that wrong is a comparison that silently never fires.
function wrote(username, before, after) {
  return { kind: 'updated', dn: 'uid=' + username + ',ou=users,dc=example,' +
    'dc=com', username: username, realm: 'default',
    before: before, after: after };
}

function deleted(username, before) {
  return { kind: 'deleted:' + username,
    dn: 'uid=' + username + ',ou=users,dc=example,dc=com',
    username: username, realm: 'default', before: before, after: {} };
}

// What `ssf.js`'s transmit() hands back to the register once the SET exists.
function transmitted(row, uri, payload, streamId) {
  risc.noteTransmitted({ stream_id: streamId || 'st-1' }, {
    jti: 'jti-' + Math.random().toString(16).slice(2, 10),
    iss: 'https://sts.example.com',
    sub_id: risc.subjectFor(row, uri),
    events: (function () {
      const map = {};
      map[uri] = payload;
      return map;
    })()
  });
}

function run(t) {
  risc.clear();
  config.setOverride('risc.enabled', 'true');
  config.setOverride('risc.autoEmit', 'true');
  config.setOverride('risc.honourOptOut', 'true');
  config.setOverride('risc.googleSubjectType', 'false');
  config.setOverride('risc.subjectFormat', 'iss_sub');

  // -----------------------------------------------------------------------
  t.log.info('A. the fourteen event types, and what is different about them');
  // -----------------------------------------------------------------------
  t.equal(events.RISC_EVENTS.length, 14,
          'RISC 1.0 defines fourteen event types and the catalogue holds ' +
          'fourteen rows — the vocabulary is rows in that table and nothing ' +
          'else, which is the promise ssf/CLAUDE.md made when it had two');

  const noMembers = events.RISC_EVENTS.filter(function (row) {
    return row.members.length === 0;
  });
  t.equal(noMembers.length, 11,
          'ELEVEN OF THE FOURTEEN HAVE NO PAYLOAD MEMBERS AT ALL, so for ' +
          'those the SUBJECT IS THE ENTIRE MESSAGE — which is why a subject ' +
          'naming the wrong person is not a partly wrong event but a wholly ' +
          'wrong one with nothing else in it to notice by');

  const withRequired = events.RISC_EVENTS.filter(function (row) {
    return row.required.length > 0;
  });
  t.equal(withRequired.length, 1,
          'and exactly ONE has a required member, where every CAEP event ' +
          'but two does');
  t.equal(withRequired[0].uri, P + 'credential-compromise',
          'it is credential-compromise, and its credential_type is defined ' +
          'BY REFERENCE to CAEP\'s credential-change — so the two lists are ' +
          'one list here and not two alike ones');
  const shared = withRequired[0].members.filter(function (m) {
    return m.name === 'credential_type';
  })[0];
  t.equal(shared.values, events.CREDENTIAL_TYPES,
          'literally the same array object, so a value added to CAEP\'s ' +
          'list cannot fail to reach RISC\'s');

  t.equal(events.RISC_COMMON_MEMBERS.length, 3,
          'RISC gives THREE claims to credential-compromise where CAEP ' +
          'gives four to all eight of its own');
  t.equal(events.RISC_COMMON_MEMBERS.filter(function (m) {
    return m.name === 'initiating_entity';
  }).length, 0,
          'and initiating_entity is NOT among them. A reader porting CAEP\'s ' +
          'withCommon() across would attach four members to fourteen rows ' +
          'and produce thirteen events carrying members their specification ' +
          'does not define — which nothing would report, because an ' +
          'unrecognised member is carried and ignored');

  const deprecated = events.RISC_EVENTS.filter(function (row) {
    return row.deprecated;
  });
  t.equal(deprecated.length, 1,
          'one of the fourteen is deprecated BY ITS OWN SPECIFICATION');
  t.equal(deprecated[0].uri, P + 'sessions-revoked',
          'sessions-revoked — PLURAL — which RISC section 2.11 says new ' +
          'implementations must replace with CAEP\'s session-revoked. The ' +
          'two names differ by one letter and mean different things');
  t.equal(deprecated[0].deprecated, events.CAEP_PREFIX + 'session-revoked',
          'and the row says which one, so a warning can name it');
  const depVerdict = events.validateEvent(P + 'sessions-revoked', {});
  t.equal(depVerdict.ok, true,
          'it is still BUILT — a transmitter that could not produce a ' +
          'deprecated event could not be used to find out what a receiver ' +
          'does with one');
  t.check(depVerdict.warnings.join(' ').indexOf('DEPRECATED') >= 0,
          'and every one of them says so');

  // -----------------------------------------------------------------------
  t.log.info('B. the near-miss member name, which is the trap in this ' +
             'vocabulary');
  // -----------------------------------------------------------------------
  const hyphenated = [];
  events.EVENTS.forEach(function (row) {
    row.members.forEach(function (member) {
      if (member.name.indexOf('-') >= 0) {
        hyphenated.push(row.uri.split('/').pop() + '.' + member.name);
      }
    });
  });
  t.equal(hyphenated.join(','), 'identifier-changed.new-value',
          'EXACTLY ONE member name in all three vocabularies uses a hyphen. ' +
          'Everything else is snake_case, which is what makes new_value the ' +
          'mistake somebody makes once and never sees');

  const nearMiss = events.validateEvent(P + 'identifier-changed',
    { new_value: 'alice.roe@example.com' });
  t.equal(nearMiss.ok, true,
          'the underscore spelling is CARRIED rather than refused: an event ' +
          'vocabulary extends and a receiver ignores what it does not know');
  t.check(nearMiss.warnings.join(' ').indexOf('"new-value"') >= 0,
          'and it is named — the warning says which member it nearly is, ' +
          'because "unknown member" alone would not tell anybody they had ' +
          'typed one character wrong');

  const generated = events.EVENT_BY_URI[P + 'identifier-changed']
    .generate({ new_value: 'alice.roe@example.com' });
  t.equal(Object.keys(generated).length, 0,
          'AND THE GENERATOR DOES NOT SILENTLY CORRECT IT. This service ' +
          'exists so that somebody can find out what their transmitter is ' +
          'sending, and a mock that quietly repaired the commonest mistake ' +
          'in this event type would be a mock that hid it');

  // -----------------------------------------------------------------------
  t.log.info('C. ONE directory write, TWO events');
  // -----------------------------------------------------------------------
  const both = risc.observe(wrote('alice',
    { scimactive: ['true'], mail: ['alice@example.com'] },
    { scimactive: ['false'], mail: ['alice.roe@example.com'] }));
  t.equal(both.length, 2,
          'a PUT that disables an account AND changes its mail address is ' +
          'TWO RISC events about one write. An observer that answered with ' +
          'the first would drop the second silently, and in a protocol with ' +
          'no missing-event error that is a transmitter lying by omission');
  const kinds = both.map(function (one) {
    return one.uri.slice(P.length);
  }).sort().join(',');
  t.equal(kinds, 'account-disabled,identifier-changed',
          'and they are the two RISC has words for');

  const idEvent = both.filter(function (one) {
    return one.uri === P + 'identifier-changed';
  })[0];
  t.equal(idEvent.subject.format, 'email',
          'THE IDENTIFIER EVENT IGNORES risc.subjectFormat and uses email, ' +
          'because for that event the identifier IS the message and an ' +
          'iss_sub subject would carry none of it');
  t.equal(idEvent.subject.email, 'alice@example.com',
          'and it carries the OLD value, which is the reverse of every ' +
          'other event in all three vocabularies');
  t.equal(idEvent.payload['new-value'], 'alice.roe@example.com',
          'the new one is in the payload, under the hyphenated name');

  const disabled = both.filter(function (one) {
    return one.uri === P + 'account-disabled';
  })[0];
  t.equal(disabled.subject.format, 'issuer_subject_id',
          'while account-disabled uses the configured format — the ' +
          'identifier a receiver already holds, because an ID Token\'s iss ' +
          'and sub said it');

  // -----------------------------------------------------------------------
  t.log.info('D. an absent attribute is not a false one');
  // -----------------------------------------------------------------------
  const noActive = risc.actsFor({ mail: ['x@example.com'] },
                                { mail: ['x@example.com'] });
  t.equal(noActive.length, 0,
          'a write that says nothing about `active` produces nothing. ' +
          '"Nobody has ever said" and "somebody said no" are two different ' +
          'facts, and reading the first as the second would emit an ' +
          'account-disabled for every person created without the attribute');

  const added = risc.actsFor({}, { mail: ['new@example.com'] });
  t.equal(added.length, 0,
          'and an identifier ADDED where there was none is not a change: ' +
          'identifier-changed\'s subject has to carry the OLD value, and ' +
          'there is none, so the event could not be composed. A provider ' +
          'announcing the addition sends recovery-information-changed');

  // -----------------------------------------------------------------------
  t.log.info('E. the register follows the act even when NOTHING goes out');
  // -----------------------------------------------------------------------
  risc.clear();
  config.setOverride('risc.autoEmit', 'false');
  risc.observe(deleted('bob', { mail: ['bob@example.com'] }));
  const bob = risc.get('bob');
  t.check(!!bob, 'a row appears for a deleted person even with emission off');
  t.equal(bob.lifecycle, 'purged',
          'AND IT SAYS PURGED. The state follows the ACT rather than the ' +
          'event, so a service with no stream agreed still answers "did ' +
          'anything happen to that person" correctly — which is the whole ' +
          'question /admin/risc-accounts is for');
  t.check(bob.notes.join(' ').indexOf('NOT emitted') >= 0,
          'and the row says why nothing was sent, rather than leaving a ' +
          'count of zero to be read as "nobody asked"');
  config.setOverride('risc.autoEmit', 'true');

  // -----------------------------------------------------------------------
  t.log.info('F. the register outlives the account, which the directory ' +
             'cannot');
  // -----------------------------------------------------------------------
  t.equal(risc.list().filter(function (row) {
    return row.accountId === 'bob';
  }).length, 1,
          'the row for a person who no longer exists anywhere in this ' +
          'service is still here. Nothing else records that receivers were ' +
          'told the account was purged — the directory entry is gone');

  // -----------------------------------------------------------------------
  t.log.info('G. the opt-out state machine is RISC section 2.8\'s figure');
  // -----------------------------------------------------------------------
  risc.clear();
  const carol = risc.rowFor('carol', { iss: 'https://sts.example.com' });
  t.equal(carol.optOut, 'opt-in', 'an account starts participating');

  let v = risc.applyToState(carol, P + 'opt-out-effective', {});
  t.equal(carol.optOut, 'opt-out',
          'a state this transmitter DECLARES is applied even when the ' +
          'diagram has no arrow for it — the receiver will believe it, and ' +
          'a register that refused to follow would report something the far ' +
          'end does not think');
  t.check(v.warnings.join(' ').indexOf('no opt-out-effective out of the ' +
          '"opt-in" state') >= 0,
          'and it is warned about, naming the transition');
  t.check(v.warnings.join(' ').indexOf('hijacker') >= 0,
          'with the reason the middle state exists at all: it stops a ' +
          'hijacker opting out the moment they take an account over and ' +
          'silencing the events that would report them');

  // -----------------------------------------------------------------------
  t.log.info('H. the gate, and the exception without which it is a trap');
  // -----------------------------------------------------------------------
  const stopped = risc.gate(carol, P + 'account-disabled');
  t.equal(stopped.send, false,
          'an opted-out account has its ordinary events SUPPRESSED. RISC ' +
          'section 2.8 says it is not participating in event exchange');
  t.check(stopped.why.indexOf('risc.honourOptOut') >= 0,
          'and the reason names the setting that would carry it anyway, ' +
          'which is how a receiver that IGNORES an opt-out gets to be shown ' +
          'doing it');

  Object.keys(risc.OPT_OUT_EVENTS).forEach(function (short) {
    t.equal(risc.gate(carol, P + short).send, true,
            short + ' is NEVER suppressed');
  });
  t.log.info('     — and that exception is the whole rule: ' +
             'opt-out-effective is an event announcing that there will be ' +
             'no more events, so gating it would enter the silent state ' +
             'without telling anybody, which at the far end is ' +
             'indistinguishable from a transmitter that has gone down. ' +
             'opt-in is sent FROM that state by definition.');

  config.setOverride('risc.honourOptOut', 'false');
  t.equal(risc.gate(carol, P + 'account-disabled').send, true,
          'turning the setting off carries everything, which is the ' +
          'non-conforming transmitter this mock is for');
  config.setOverride('risc.honourOptOut', 'true');

  risc.applyToState(carol, P + 'opt-in', {});
  t.equal(carol.optOut, 'opt-in', 'opt-in brings the account back');
  t.equal(risc.gate(carol, P + 'account-disabled').send, true,
          'and the gate opens again');

  // -----------------------------------------------------------------------
  t.log.info('I. the ONE hard refusal, asked BEFORE anything is built');
  // -----------------------------------------------------------------------
  const dead = risc.rowFor('dan', {});
  risc.applyToState(dead, P + 'account-purged', {});
  t.equal(dead.lifecycle, 'purged', 'RISC calls a purge permanent deletion');

  t.equal(risc.refusals(dead, P + 'account-enabled').length, 1,
          'account-enabled about a purged account is REFUSED. That sentence ' +
          'says an account this transmitter declared permanently deleted is ' +
          'usable again — either a transmitter contradicting itself or a ' +
          'receiver about to be told to restore access to something that ' +
          'does not exist');
  t.equal(risc.refusals(dead, P + 'credential-compromise').length, 0,
          'and nothing else is: a compromise can perfectly well be ' +
          'DISCOVERED after a deletion, so refusing it would remove the ' +
          'ability to reproduce the ordinary case');
  const late = risc.applyToState(dead, P + 'credential-compromise',
    { credential_type: 'password' });
  t.equal(late.ok, true, 'it is carried');
  t.check(late.warnings.join(' ').indexOf('PURGED') >= 0,
          'with a warning, because a receiver that has already removed the ' +
          'account has nothing left to apply it to');

  t.equal(risc.refusals(dead, P + 'account-enabled').length,
          risc.applyToState(dead, P + 'account-enabled', {}).errors.length,
          'THE PRE-FLIGHT CHECK AND THE APPLIED ONE ARE THE SAME RULE. Two ' +
          'spellings would be two chances to disagree, and the ' +
          'disagreement would be invisible: the emit path asks the first ' +
          'and the register writes from the second');

  // -----------------------------------------------------------------------
  t.log.info('J. the counters are not the ring');
  // -----------------------------------------------------------------------
  risc.clear();
  const busy = risc.rowFor('erin', { iss: 'https://sts.example.com' });
  for (let i = 0; i < 30; i += 1) {
    transmitted(busy, P + 'account-credential-change-required', {});
  }
  const after = risc.get('erin');
  t.equal(after.total, 30,
          '`total` never forgets: thirty events were sent about this account');
  t.equal(after.counts[P + 'account-credential-change-required'], 30,
          'and the per-type count says thirty too');
  t.equal(after.events.length, risc.EVENTS_PER_ACCOUNT,
          'while the ring keeps the last ' + risc.EVENTS_PER_ACCOUNT +
          '. They answer different questions — "how many" and "which were ' +
          'the last few" — and a page that answered the first out of the ' +
          'second would say ' + risc.EVENTS_PER_ACCOUNT + ' where there ' +
          'were thirty');

  // -----------------------------------------------------------------------
  t.log.info('K. an identifier change does not split one person into two ' +
             'rows');
  // -----------------------------------------------------------------------
  risc.clear();
  const moved = risc.rowFor('frank', { iss: 'https://sts.example.com' });
  moved.email = 'frank@example.com';
  risc.applyToState(moved, P + 'identifier-changed',
    { 'new-value': 'frank.roe@example.com' });
  t.equal(moved.email, 'frank.roe@example.com', 'the row follows the change');
  t.equal(moved.formerIdentifiers.join(','), 'frank@example.com',
          'and remembers what it was');
  t.equal(risc.accountIdOf({ format: 'email', email: 'frank@example.com' }),
          'frank',
          'AN EVENT NAMING THE SUPERSEDED ADDRESS STILL FINDS THIS ROW. ' +
          'That is what the register being keyed on the PERSON buys: keyed ' +
          'on the subject, one person would become two rows at exactly the ' +
          'moment their identifier changed, which is the moment the row is ' +
          'worth having');
  t.equal(risc.list().length, 1, 'so there is still one row');

  // -----------------------------------------------------------------------
  t.log.info('L. RISC section 3.1: the defect the specification asks for');
  // -----------------------------------------------------------------------
  const ordinary = risc.subjectFor(moved, P + 'account-disabled');
  t.equal(ordinary.format, 'issuer_subject_id',
          'ordinarily the discriminator is `format`, as RFC 9493 says');
  config.setOverride('risc.googleSubjectType', 'true');
  const google = risc.subjectFor(moved, P + 'account-disabled');
  t.equal(google.subject_type, 'issuer_subject_id',
          'with risc.googleSubjectType on it is `subject_type` — which RISC ' +
          'section 3.1 records as a production transmitter\'s spelling, ' +
          'says new services MUST NOT use, and then tells relying parties ' +
          'they need code to work around anyway');
  t.equal(google.format, undefined, 'and `format` is gone rather than beside');
  t.equal(risc.accountIdOf(google), 'frank',
          'this register reads BOTH spellings back, because a subject that ' +
          'came home through noteTransmitted() went out under whatever the ' +
          'setting said at the time');
  config.setOverride('risc.googleSubjectType', 'false');

  // -----------------------------------------------------------------------
  t.log.info('M. reset keeps the row and clears what was said about it');
  // -----------------------------------------------------------------------
  risc.reset('frank');
  const reset = risc.get('frank');
  t.equal(reset.total, 0, 'the counters are zero');
  t.equal(reset.lifecycle, 'active', 'the lifecycle is back to the start');
  t.equal(reset.optOut, 'opt-in', 'and so is the opt-out state');
  t.check(!!reset,
          'THE ROW SURVIVES. A delete would take it off the page, which ' +
          'reads as the account having gone — and that is what ' +
          'account-purged MEANS, so faking it here would be the one ' +
          'confusion this page cannot afford');

  const gone = risc.clear();
  t.check(gone > 0, 'clearing drops every row, and says how many');
  t.equal(risc.list().length, 0, 'the register is empty');
}

module.exports = {
  name: 'risc_register',
  describe: 'what RISC believes about an account, the opt-out gate, and the ' +
            'one sentence it refuses to carry',
  run: run
};
