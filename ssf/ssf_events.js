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
// **THIS FILE IS DELIBERATELY THE WHOLE OF THE VOCABULARY**, and as of
// 2026-09-03 it carries TWO of the three: SSF's two rows and CAEP's eight.
// The promise this header made while it had two rows in it was that adding a
// vocabulary would be rows in `EVENTS` below and nothing else, and that is
// what happened — the SET envelope, the subject grammar, the queues, the
// deliveries and the stream management were not touched, because none of them
// names an event type. Two things outside this file did change, and neither is
// vocabulary: `caep.js` holds the SESSION REGISTER, which is what a CAEP event
// is ABOUT, and `transmit()` gained the refusal for an event whose row says it
// must carry a subject. RISC's account-lifecycle events are the third part and
// only its prefix is here.
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

// The two VOCABULARY prefixes. Both have rows in the table below now — CAEP's
// eight since 2026-09-03 and RISC's fourteen since 2026-09-04 — and they are
// written once each because a prefix is the thing most likely to be typed
// from memory and got subtly wrong: there is no "unknown event type" error in
// this protocol, so a receiver silently ignores a type it does not recognise
// and nobody finds out.
const CAEP_PREFIX = 'https://schemas.openid.net/secevent/caep/event-type/';
const RISC_PREFIX = 'https://schemas.openid.net/secevent/risc/event-type/';

// The `typ` of a Security Event Token (RFC 8417 section 2.3). It is the media
// type without the `application/` prefix, which is what a JWT header carries.
const SET_MEDIA_TYPE = 'secevent+jwt';

// ---------------------------------------------------------------------------
// THE CATALOGUE.
//
//   uri        the event type, which is the KEY in the SET's `events` map
//   family     which specification defines it — 'ssf', 'caep' or 'risc'
//   subject    'none' | 'optional' | 'required'. SSF's TWO ARE THE ONLY ONES
//              IN ANY OF THE THREE VOCABULARIES WITH NO SUBJECT AT ALL, and
//              it is worth knowing why: they are about the STREAM,
//              not about anybody, so a receiver that insists on a subject
//              cannot be verified.
//   subjectFormats
//              WHICH RFC 9493 FORMATS THE SUBJECT MAY BE IN, where the
//              specification narrows it. Only RISC's two identifier events
//              have one — they say the subject MUST be an email address or a
//              phone number, because the identifier IS the message — and it
//              is a property of the ROW rather than a branch naming an event
//              type, which is what keeps `checkSubjectFormat()` below from
//              being the vocabulary leaking out of this table.
//   deprecated the event type that replaces this one, where its own
//              specification deprecates it. One row has it: RISC's
//              `sessions-revoked` points at CAEP's `session-revoked`.
//   members    the event payload's own members. `required` says which a
//              conforming event carries; the rest are optional.
//   generate   builds a payload from the values a caller supplied, filling
//              what it can. Every row has one so that "send me one of these"
//              is one call from the console, the management API and the
//              debugger alike.
// ---------------------------------------------------------------------------
const SSF_EVENTS = [
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

// ---------------------------------------------------------------------------
// CAEP — THE SESSION VOCABULARY (OpenID Continuous Access Evaluation Profile
// 1.0, final 2 September 2025), AND IT IS ROWS IN THIS TABLE AND NOTHING ELSE.
//
// That was the promise `ssf/CLAUDE.md` and the header of this file made while
// the table had two rows in it, and it is worth stating what kept it: the SET
// envelope, the RFC 9493 subject grammar, the queues, the deliveries and the
// stream management did not have to be touched to add eight event types,
// because none of them names an event type. The only things that CHANGED
// outside this file are the two that are genuinely not vocabulary — the
// SESSION REGISTER (`caep.js`, which is what a CAEP event is ABOUT) and the
// refusal in `transmit()` for an event whose row says it must carry a subject.
//
// **WHAT CAEP SAYS THAT SSF DOES NOT.** SSF's two events are about the PIPE.
// These eight are about a SESSION, and the sentence they exist to carry is
// *this session is no longer trustworthy* — which is a different sentence from
// RISC's *this account is no longer trustworthy*, and the whole reason there
// are two profiles rather than one.
//
// **THE SUBJECT IS THE HALF PEOPLE GET WRONG.** Every one of these is
// `subject: 'required'`, and the subject a conforming transmitter sends is
// normally SSF's COMPLEX subject rather than a plain one: the person is not
// revoked, one session of theirs is, and a subject identifier naming only the
// person asks a receiver to end every session that person has. `caep.js`
// composes it and `transmit()` refuses an event that arrives without one.
// ---------------------------------------------------------------------------

// The four claims CAEP section 2 gives EVERY event, all of them optional.
// Written once and concatenated onto each row below, because eight copies of
// four member descriptions is eight places for a spelling to drift and there
// is no "unknown member" error in this protocol — a receiver reading
// `reason-admin` for `reason_admin` finds nothing and says nothing.
//
// `event_timestamp` IS NOT THE SET's `toe` AND IT IS NOT `iat`. RFC 8417's
// `toe` is a claim on the token; this is a member of the event payload, and
// CAEP is the specification that defines it. A transmitter may legitimately
// send both, and a receiver that reads only one of them from a transmitter
// that sends only the other reads nothing at all.
const CAEP_COMMON_MEMBERS = [
  { name: 'event_timestamp', required: false, type: 'number',
    what: 'When the thing described actually happened, in seconds since the ' +
          'epoch. OPTIONAL in CAEP 1.0 section 2 — which surprises people, ' +
          'because a receiver deciding whether to end a session wants it ' +
          'more than it wants anything else in the payload. ' +
          'caep.omitEventTimestamp leaves it out on purpose, so a receiver ' +
          'that assumes one can be shown falling over.' },
  { name: 'initiating_entity', required: false, type: 'enum',
    values: ['admin', 'user', 'policy', 'system'],
    what: 'Who invoked it. It is the member that lets a receiver tell "an ' +
          'administrator revoked this" from "a risk engine did" — two facts ' +
          'that call for two different responses, and which are ' +
          'indistinguishable without it.' },
  { name: 'reason_admin', required: false, type: 'langmap',
    what: 'Why, for a log and for an auditor. **It is an OBJECT KEYED BY A ' +
          'LANGUAGE TAG** — {"en": "Policy 4.2 was violated"} — and not a ' +
          'string, which is the commonest way this member is got wrong. A ' +
          'string here is refused rather than carried, because a receiver ' +
          'indexing it by language reads nothing from one.' },
  { name: 'reason_user', required: false, type: 'langmap',
    what: 'The same, in words meant for the person it happened to. Two ' +
          'members rather than one because what an auditor needs to read ' +
          'and what may be shown on a screen are rarely the same sentence.' }
];

// One row's own members, plus the four above. A function rather than a spread
// at each call site so that the ORDER is the same on every row — the console
// draws them in this order, and a table whose columns move between rows is
// harder to read than one with a column too many.
function withCommon(members) {
  return (members || []).concat(CAEP_COMMON_MEMBERS);
}

// ---------------------------------------------------------------------------
// THE CREDENTIAL TYPES, WRITTEN ONCE BECAUSE TWO SPECIFICATIONS SHARE THEM BY
// REFERENCE RATHER THAN BY COINCIDENCE.
//
// CAEP 1.0 defines this list for `credential-change`. RISC 1.0 section 2.7
// then says that `credential-compromise`'s `credential_type` "must be one of
// the values specified for the similarly named field in the Credential Change
// event defined in the CAEP Specification" — so the two lists are not merely
// alike, they are the SAME list, and a second copy of it here would be a copy
// that can drift out of a relationship the specification states outright.
//
// It is OPEN in both places: the specification allows types two parties agree
// between themselves, so a value outside it is carried with a warning.
// ---------------------------------------------------------------------------
const CREDENTIAL_TYPES = ['password', 'pin', 'x509', 'fido2-platform',
  'fido2-roaming', 'fido-u2f', 'verifiable-credential', 'phone-voice',
  'phone-sms', 'app'];

const CAEP_EVENTS = [
  {
    uri: CAEP_PREFIX + 'session-revoked',
    family: 'caep',
    name: 'Session Revoked',
    subject: 'required',
    members: withCommon([]),
    required: [],
    what: 'THE EVENT THE WHOLE PROFILE EXISTS FOR. The session named by the ' +
          'subject is no longer good, whatever its token says its lifetime ' +
          'is. It carries NO event-specific member at all — everything it ' +
          'has to say is in the subject and in the four common claims — and ' +
          'that is not an oversight: there is nothing to qualify. Where the ' +
          'subject is a COMPLEX one, the revocation applies to any session ' +
          'matching every part of it at once.',
    generate: function () {
      return {};
    }
  },
  {
    uri: CAEP_PREFIX + 'session-established',
    family: 'caep',
    name: 'Session Established',
    subject: 'required',
    members: withCommon([
      { name: 'fp_ua', required: false, type: 'string',
        what: 'A fingerprint of the user agent, computed by the ' +
              'transmitter. Its value is comparing two of them, so what it ' +
              'is made of is the transmitter\'s business and no receiver ' +
              'should parse one.' },
      { name: 'acr', required: false, type: 'string',
        what: 'The authentication context class, with OpenID Connect\'s own ' +
              'meaning.' },
      { name: 'amr', required: false, type: 'strings',
        what: 'The authentication methods, as an ARRAY of strings — OpenID ' +
              'Connect\'s `amr`. A bare string here is refused: a session ' +
              'authenticated by a password AND a security key has two ' +
              'values, and a receiver that read a string would see one.' },
      { name: 'ext_id', required: false, type: 'string',
        what: 'The transmitter\'s own identifier for this session, for a ' +
              'receiver correlating with something it already holds.' }
    ]),
    required: [],
    what: 'A session was created. It is what CLOSES THE LOOP — without it a ' +
          'receiver only ever hears about sessions ending, so it cannot ' +
          'hold an inventory of what is open and cannot notice a sign-in it ' +
          'did not expect. This service emits one on every sign-in unless ' +
          'caep.autoEmit is off.',
    generate: function (values) {
      const asked = values || {};
      const payload = {};
      if (typeof asked.fp_ua === 'string' && asked.fp_ua !== '') {
        payload.fp_ua = asked.fp_ua;
      }
      if (typeof asked.acr === 'string' && asked.acr !== '') {
        payload.acr = asked.acr;
      }
      if (Array.isArray(asked.amr) && asked.amr.length) {
        payload.amr = asked.amr.slice();
      }
      if (typeof asked.ext_id === 'string' && asked.ext_id !== '') {
        payload.ext_id = asked.ext_id;
      }
      return payload;
    }
  },
  {
    uri: CAEP_PREFIX + 'session-presented',
    family: 'caep',
    name: 'Session Presented',
    subject: 'required',
    members: withCommon([
      { name: 'fp_ua', required: false, type: 'string',
        what: 'The user agent fingerprint observed THIS time. Comparing it ' +
              'with the one on the session-established event is the whole ' +
              'point of the member: the same session presented from a ' +
              'different agent is the abnormality this event exists to ' +
              'make visible.' },
      { name: 'ext_id', required: false, type: 'string',
        what: 'The transmitter\'s own identifier for the session.' }
    ]),
    required: [],
    what: 'The session was USED — presented at the transmitter and honoured. ' +
          'It is the one CAEP event about something entirely ordinary, and ' +
          'it is there so that a receiver can see a live session it is not ' +
          'itself being asked about, and can spot the same session in two ' +
          'places at once. This service emits one when an authorization ' +
          'request is answered from a session that already existed, which ' +
          'is exactly single sign-on.',
    generate: function (values) {
      const asked = values || {};
      const payload = {};
      if (typeof asked.fp_ua === 'string' && asked.fp_ua !== '') {
        payload.fp_ua = asked.fp_ua;
      }
      if (typeof asked.ext_id === 'string' && asked.ext_id !== '') {
        payload.ext_id = asked.ext_id;
      }
      return payload;
    }
  },
  {
    uri: CAEP_PREFIX + 'token-claims-change',
    family: 'caep',
    name: 'Token Claims Change',
    subject: 'required',
    members: withCommon([
      { name: 'claims', required: true, type: 'object',
        what: 'The claims that changed, with their NEW values — an object, ' +
              'and only the ones that moved. It is not a whole token and it ' +
              'is not a diff: a receiver applies what is here over what it ' +
              'holds. A group membership taken away is therefore the new ' +
              'LIST rather than the group that went, which catches people.' }
    ]),
    required: ['claims'],
    what: 'A claim behind the token changed while the token is still valid ' +
          '— a role, a group, a tenant. It is the event that makes the ' +
          'access-token lifetime argument go away: the receiver does not ' +
          'have to wait for a refresh to find out that somebody left the ' +
          'group that authorises them.',
    generate: function (values) {
      const asked = values || {};
      const claims = (asked.claims && typeof asked.claims === 'object' &&
                      !Array.isArray(asked.claims))
        ? asked.claims
        : { groups: ['everyone'] };
      return { claims: claims };
    }
  },
  {
    uri: CAEP_PREFIX + 'credential-change',
    family: 'caep',
    name: 'Credential Change',
    subject: 'required',
    members: withCommon([
      { name: 'credential_type', required: true, type: 'openenum',
        values: CREDENTIAL_TYPES,
        what: 'Which kind of credential. The list is CAEP\'s own and it is ' +
              'OPEN — the specification allows types two parties agree ' +
              'between themselves — so a value not on it is carried with a ' +
              'warning rather than refused. Refusing would make this ' +
              'service unable to carry a vendor\'s own type, which is ' +
              'precisely what a mock is for.' },
      { name: 'change_type', required: true, type: 'enum',
        values: ['create', 'revoke', 'update', 'delete'],
        what: 'What happened to it. CLOSED, unlike the type above: these ' +
              'four are the whole lifecycle and a fifth would be a ' +
              'receiver guessing.' },
      { name: 'friendly_name', required: false, type: 'string',
        what: 'What the person calls it — "my work phone". For a screen, ' +
              'not for a decision.' },
      { name: 'x509_issuer', required: false, type: 'string',
        what: 'The certificate\'s issuer (RFC 5280), where the credential ' +
              'is an X.509 one.' },
      { name: 'x509_serial', required: false, type: 'string',
        what: 'The certificate\'s serial number (RFC 5280). Serial numbers ' +
              'are unique per ISSUER and not globally, which is why this ' +
              'member is useless without the one above it.' },
      { name: 'fido2_aaguid', required: false, type: 'string',
        what: 'The authenticator\'s AAGUID, where the credential is a ' +
              'FIDO2 one. It names a MODEL of authenticator rather than ' +
              'the individual one, which is what makes it publishable.' }
    ]),
    required: ['credential_type', 'change_type'],
    what: 'A credential was enrolled, renewed, revoked or deleted. It is ' +
          'the event a receiver acts on WITHOUT ending anything: a second ' +
          'factor being deleted does not invalidate the session it was used ' +
          'to establish, and it does change what that session should be ' +
          'allowed to do next.',
    generate: function (values) {
      const asked = values || {};
      const payload = {
        credential_type: typeof asked.credential_type === 'string' &&
          asked.credential_type !== '' ? asked.credential_type : 'password',
        change_type: ['create', 'revoke', 'update', 'delete']
          .indexOf(asked.change_type) >= 0 ? asked.change_type : 'update'
      };
      ['friendly_name', 'x509_issuer', 'x509_serial', 'fido2_aaguid']
        .forEach(function (name) {
          if (typeof asked[name] === 'string' && asked[name] !== '') {
            payload[name] = asked[name];
          }
        });
      return payload;
    }
  },
  {
    uri: CAEP_PREFIX + 'assurance-level-change',
    family: 'caep',
    name: 'Assurance Level Change',
    subject: 'required',
    members: withCommon([
      { name: 'namespace', required: true, type: 'openenum',
        values: ['RFC8176', 'RFC6711', 'ISO-IEC-29115', 'NIST-IAL',
                 'NIST-AAL', 'NIST-FAL'],
        what: 'WHICH SCALE THE TWO LEVELS BELOW ARE ON, and it is required ' +
              'for the reason the whole event would otherwise be useless: ' +
              '"AAL2" means nothing until you know it is NIST\'s. The list ' +
              'is open — two parties may agree an alias — so an unlisted ' +
              'namespace is carried with a warning.' },
      { name: 'current_level', required: true, type: 'string',
        what: 'The level the session is at NOW, spelt the way the ' +
              'namespace above spells it. It is a free string precisely ' +
              'because the namespace decides its shape.' },
      { name: 'previous_level', required: false, type: 'string',
        what: 'Where it was before. Optional, and worth sending: without ' +
              'it a receiver can see that assurance changed and not ' +
              'whether it went UP.' },
      { name: 'change_direction', required: false, type: 'enum',
        values: ['increase', 'decrease'],
        what: 'Which way, said outright rather than inferred. It exists ' +
              'because a receiver cannot order two levels it does not ' +
              'understand the namespace of — which is the ordinary case ' +
              'across two organisations.' }
    ]),
    required: ['namespace', 'current_level'],
    what: 'The strength of the authentication behind this session moved. ' +
          'A DECREASE is the interesting one and it is easy to forget it ' +
          'can happen at all: a second factor that has expired, or a ' +
          'session carried forward past the window its step-up was good ' +
          'for, both lower assurance without anybody signing in again.',
    generate: function (values) {
      const asked = values || {};
      const payload = {
        namespace: typeof asked.namespace === 'string' &&
          asked.namespace !== ''
          ? asked.namespace
          : String(config.value('caep.assuranceNamespace') || 'NIST-AAL'),
        current_level: typeof asked.current_level === 'string' &&
          asked.current_level !== '' ? asked.current_level : 'aal2'
      };
      if (typeof asked.previous_level === 'string' &&
          asked.previous_level !== '') {
        payload.previous_level = asked.previous_level;
      }
      if (['increase', 'decrease'].indexOf(asked.change_direction) >= 0) {
        payload.change_direction = asked.change_direction;
      }
      return payload;
    }
  },
  {
    uri: CAEP_PREFIX + 'device-compliance-change',
    family: 'caep',
    name: 'Device Compliance Change',
    subject: 'required',
    members: withCommon([
      { name: 'previous_status', required: true, type: 'enum',
        values: ['compliant', 'not-compliant'],
        what: 'What the device was. REQUIRED, and that is the member that ' +
              'makes this event safe to act on out of order: a receiver ' +
              'holding "compliant" that gets an event whose previous ' +
              'status is "not-compliant" knows it has missed one.' },
      { name: 'current_status', required: true, type: 'enum',
        values: ['compliant', 'not-compliant'],
        what: 'What it is now. The hyphen in "not-compliant" is the ' +
              'specification\'s and is worth checking against: ' +
              '"noncompliant" is silently ignored by a conforming ' +
              'receiver.' }
    ]),
    required: ['previous_status', 'current_status'],
    what: 'The device the session runs on fell out of, or back into, ' +
          'compliance with whatever the estate\'s policy is. The subject ' +
          'is normally a COMPLEX one naming the device as well as the ' +
          'person, because the same person on a second device is ' +
          'unaffected and a receiver cannot tell that from a subject ' +
          'naming only them.',
    generate: function (values) {
      const asked = values || {};
      const allowed = ['compliant', 'not-compliant'];
      return {
        previous_status: allowed.indexOf(asked.previous_status) >= 0
          ? asked.previous_status : 'compliant',
        current_status: allowed.indexOf(asked.current_status) >= 0
          ? asked.current_status : 'not-compliant'
      };
    }
  },
  {
    uri: CAEP_PREFIX + 'risk-level-change',
    family: 'caep',
    name: 'Risk Level Change',
    subject: 'required',
    members: withCommon([
      { name: 'principal', required: true, type: 'openenum',
        values: ['USER', 'DEVICE', 'SESSION', 'TENANT', 'ORG_UNIT', 'GROUP'],
        what: 'WHAT the risk level is about, and it is required because the ' +
              'subject alone cannot say: a complex subject names a person ' +
              'AND a device AND a session, and "risk went to HIGH" about ' +
              'the device is a different fact from the same sentence about ' +
              'the person. The values are UPPER CASE here and lower case ' +
              'in a complex subject\'s member names, which catches ' +
              'everybody once.' },
      { name: 'current_level', required: true, type: 'enum',
        values: ['LOW', 'MEDIUM', 'HIGH'],
        what: 'The level now. Three values, upper case, closed.' },
      { name: 'previous_level', required: false, type: 'enum',
        values: ['LOW', 'MEDIUM', 'HIGH'],
        what: 'The level before.' },
      { name: 'risk_reason', required: false, type: 'string',
        what: 'What contributed. RECOMMENDED rather than required, and it ' +
              'is the member that decides whether a receiver can do ' +
              'anything but step up: "impossible travel" and "credential ' +
              'seen in a breach corpus" call for different answers.' }
    ]),
    required: ['principal', 'current_level'],
    what: 'A risk engine changed its mind about somebody. It is the only ' +
          'CAEP event that is a JUDGEMENT rather than a fact — the other ' +
          'seven report something that happened — which is why it carries ' +
          'a reason and why a receiver is expected to weigh it rather than ' +
          'act on it.',
    generate: function (values) {
      const asked = values || {};
      const levels = ['LOW', 'MEDIUM', 'HIGH'];
      const payload = {
        principal: typeof asked.principal === 'string' &&
          asked.principal !== '' ? asked.principal : 'SESSION',
        current_level: levels.indexOf(asked.current_level) >= 0
          ? asked.current_level
          : String(config.value('caep.defaultRiskLevel') || 'MEDIUM')
      };
      if (levels.indexOf(asked.previous_level) >= 0) {
        payload.previous_level = asked.previous_level;
      }
      if (typeof asked.risk_reason === 'string' && asked.risk_reason !== '') {
        payload.risk_reason = asked.risk_reason;
      }
      return payload;
    }
  }
];

// ---------------------------------------------------------------------------
// RISC — THE ACCOUNT VOCABULARY (OpenID RISC Profile Specification 1.0,
// published 29 August 2025 and final on 2 September 2025), AND IT IS ROWS IN
// THIS TABLE AND NOTHING ELSE.
//
// CAEP was the first vocabulary over this pipe and its arrival cost four value
// types in `checkMember()` and one refusal in `transmit()`. **RISC COST THIS
// FILE'S MACHINERY NOTHING AT ALL** — not one value type, not one branch. That
// is the sentence `ssf/CLAUDE.md` has been promising since the table had two
// rows in it, and fourteen event types later it is finally testable rather
// than merely asserted.
//
// **WHAT RISC SAYS THAT CAEP DOES NOT.** CAEP's eight are about a SESSION and
// carry *this session is no longer trustworthy*. These fourteen are about an
// ACCOUNT and carry *this account is no longer trustworthy*. Those are two
// different sentences and the difference is the whole reason there are two
// profiles: a revoked session is one sign-in of one person at one relying
// party, and a disabled account is every session that person has anywhere, for
// ever. CAEP is aimed WITHIN an enterprise and RISC ACROSS providers — its
// origin is Google noticing that a consumer account was taken over and telling
// every site that account signs in to.
//
// ---------------------------------------------------------------------------
// THE FOUR THINGS ABOUT THESE ROWS THAT SURPRISE SOMEBODY WHO KNOWS CAEP.
//
// **ELEVEN OF THE FOURTEEN HAVE NO PAYLOAD MEMBERS AT ALL, AND ONLY ONE HAS A
// REQUIRED ONE.** A CAEP row is mostly members; a RISC row is mostly `{}`. The
// consequence is the one worth stating: **the subject carries the entire
// message.** `account-purged` says nothing but its own type and who it is
// about, so a subject naming the wrong person is not a partly-wrong event, it
// is a completely wrong one with nothing else in it to notice by.
//
// **THE FOUR COMMON CLAIMS ARE NOT COMMON HERE.** CAEP section 2 gives
// `event_timestamp`, `initiating_entity`, `reason_admin` and `reason_user` to
// every one of its eight. RISC gives THREE of them — no `initiating_entity` —
// and gives them to exactly ONE of its fourteen, `credential-compromise`. A
// reader porting CAEP's `withCommon()` across would attach four members to
// fourteen rows and produce thirteen events carrying members their
// specification does not define. Nothing would fail: an unrecognised member is
// carried and ignored by a conforming receiver, which is why this is written
// down rather than left to the table.
//
// **ONE MEMBER NAME IN THE WHOLE OF SHARED SIGNALS USES A HYPHEN**, and it is
// `identifier-changed`'s `new-value`. Every other member of every event in all
// three vocabularies is `snake_case`. A transmitter that writes `new_value`
// from habit produces an event that is well-formed, delivers, and tells the
// receiver nothing about what the identifier changed TO — silently, because
// the member is optional and its absence is legal.
//
// **AND ONE OF THE FOURTEEN IS DEPRECATED BY ITS OWN SPECIFICATION.**
// `sessions-revoked` — plural — says every session of the account is gone, and
// RISC 1.0 says new implementations MUST use CAEP's `session-revoked` —
// singular — instead. The two names differ by one letter and mean different
// things, which is exactly the pair a person types from memory. It is in this
// table, offered, and warned about: leaving it out would make this service
// unable to reproduce the traffic of the many deployments that still send one.
// ---------------------------------------------------------------------------

// The three claims RISC gives to `credential-compromise` and to nothing else.
// A named list of three rather than four inlined members, because the COUNT is
// the fact worth being able to check: `tests/risc_register.js` asserts that it
// is three and that `initiating_entity` is not among them.
const RISC_COMMON_MEMBERS = [
  { name: 'event_timestamp', required: false, type: 'number',
    what: 'When the transmitter DISCOVERED the compromise, in seconds since ' +
          'the epoch. RISC section 2.7 words it as discovery rather than as ' +
          'occurrence, which is not pedantry: a credential found in a breach ' +
          'corpus was compromised long before anybody noticed, and a ' +
          'receiver that read this as "when it happened" would date the ' +
          'incident from the wrong end.' },
  { name: 'reason_admin', required: false, type: 'langmap',
    what: 'Why, for an administrator. THIS SERVICE SENDS THE LANGUAGE-MAP ' +
          'SHAPE CAEP DEFINES — {"en": "..."} — and RISC 1.0 does not ' +
          'actually repeat that requirement, which makes a bare string ' +
          'arguably conforming to RISC and certainly unreadable to a ' +
          'receiver built against CAEP. Sending the map is the reading that ' +
          'is right under both.' },
  { name: 'reason_user', required: false, type: 'langmap',
    what: 'The same, in words meant for the person it happened to.' }
];

const RISC_EVENTS = [
  {
    uri: RISC_PREFIX + 'account-credential-change-required',
    family: 'risc',
    name: 'Account Credential Change Required',
    subject: 'required',
    members: [],
    required: [],
    what: 'The account named by the subject was REQUIRED to change a ' +
          'credential — a forced password reset, most often. It is not a ' +
          'report that a credential changed: nothing here says one did, and ' +
          'the person may never comply. What a receiver learns is that this ' +
          'provider no longer trusts what it currently holds.',
    generate: function () {
      return {};
    }
  },
  {
    uri: RISC_PREFIX + 'account-purged',
    family: 'risc',
    name: 'Account Purged',
    subject: 'required',
    members: [],
    required: [],
    what: 'The account was PERMANENTLY DELETED. It is the one terminal ' +
          'event in the vocabulary and the register treats it as one: ' +
          'nothing can be said about a purged account afterwards except by ' +
          'contradiction. The distinction from account-disabled is the ' +
          'whole of its meaning — a disabled account may come back, and ' +
          'this one may not.',
    generate: function () {
      return {};
    }
  },
  {
    uri: RISC_PREFIX + 'account-disabled',
    family: 'risc',
    name: 'Account Disabled',
    subject: 'required',
    members: [
      { name: 'reason', required: false, type: 'openenum',
        values: ['hijacking', 'bulk-account'],
        what: 'Why, as one of two words RISC names — and it is worth ' +
              'knowing what those two are FOR. "hijacking" says this one ' +
              'account was taken over, which is a signal about a person. ' +
              '"bulk-account" says it was one of a population created by a ' +
              'script, which is a signal about the PROVIDER and asks a ' +
              'receiver to look at everything else that arrived at the same ' +
              'time. The specification says "possible values" rather than ' +
              'closing the list, so a third word is carried with a warning.' }
    ],
    required: [],
    what: 'The account was disabled and MAY BE ENABLED AGAIN. It is the ' +
          'ordinary account-takeover signal, and the pair it forms with ' +
          'account-enabled is what makes it different from a purge.',
    generate: function (values) {
      const asked = values || {};
      const payload = {};
      if (typeof asked.reason === 'string' && asked.reason !== '') {
        payload.reason = asked.reason;
      }
      return payload;
    }
  },
  {
    uri: RISC_PREFIX + 'account-enabled',
    family: 'risc',
    name: 'Account Enabled',
    subject: 'required',
    members: [],
    required: [],
    what: 'The account was enabled. It is RISC\'s only GOOD NEWS and it is ' +
          'the one everybody forgets to implement: a receiver that acts on ' +
          'account-disabled and ignores this one has locked somebody out ' +
          'permanently on the strength of an incident that was resolved.',
    generate: function () {
      return {};
    }
  },
  {
    uri: RISC_PREFIX + 'identifier-changed',
    family: 'risc',
    name: 'Identifier Changed',
    subject: 'required',
    // THE SUBJECT NAMES THE OLD VALUE, WHICH IS THE OPPOSITE OF EVERY OTHER
    // EVENT HERE. See the note on subjectFormats below.
    subjectFormats: ['email', 'phone_number'],
    members: [
      { name: 'new-value', required: false, type: 'string',
        what: 'What the identifier became. **THE ONLY HYPHENATED MEMBER ' +
              'NAME IN ANY OF THE THREE VOCABULARIES** — everything else in ' +
              'SSF, CAEP and RISC is snake_case — so `new_value` typed from ' +
              'habit produces an event that delivers and says nothing. It ' +
              'is OPTIONAL, and a transmitter that leaves it out is telling ' +
              'a receiver that an address it holds is stale without telling ' +
              'it what to hold instead, which is legal and nearly useless.' }
    ],
    required: [],
    what: 'The identifier IN THE SUBJECT changed, and the subject carries ' +
          'the OLD value — which is the reverse of every other event here ' +
          'and the thing that catches everybody. RISC says only the ' +
          'provider AUTHORITATIVE over the identifier should send this: an ' +
          'email provider may say john.doe@ became john.roe@, and a site ' +
          'where that address is merely a username may not — it sends ' +
          'recovery-information-changed instead.',
    generate: function (values) {
      const asked = values || {};
      const payload = {};
      // **IT READS THE SPECIFICATION'S SPELLING AND ONLY THAT ONE, AND
      // ACCEPTING `new_value` HERE WAS THE FIRST THING THIS ROW DID WRONG.**
      // Correcting the underscore silently makes the console kind to a caller
      // and useless to one: this service exists so that somebody can find out
      // what their own transmitter is sending, and a mock that quietly repairs
      // the commonest mistake in this event type is a mock that hides it.
      // `validateEvent()` warns about the near-miss by name instead, which
      // says what happened rather than making it not have happened.
      if (typeof asked['new-value'] === 'string' && asked['new-value']) {
        payload['new-value'] = asked['new-value'];
      }
      return payload;
    }
  },
  {
    uri: RISC_PREFIX + 'identifier-recycled',
    family: 'risc',
    name: 'Identifier Recycled',
    subject: 'required',
    subjectFormats: ['email', 'phone_number'],
    members: [],
    required: [],
    what: 'The identifier in the subject was RECYCLED and now belongs to ' +
          'somebody else. It is the event whose absence causes the quietest ' +
          'account takeover there is: a mail provider reissues a lapsed ' +
          'address, a relying party keyed on the address by itself lets the ' +
          'new owner into the old owner\'s account, and nothing anywhere ' +
          'was compromised. It is the whole argument for keying on ' +
          'iss_sub rather than on an email address.',
    generate: function () {
      return {};
    }
  },
  {
    uri: RISC_PREFIX + 'credential-compromise',
    family: 'risc',
    name: 'Credential Compromise',
    subject: 'required',
    members: [
      { name: 'credential_type', required: true, type: 'openenum',
        values: CREDENTIAL_TYPES,
        what: 'Which kind of credential was found compromised. **RISC ' +
              'SECTION 2.7 DEFINES THIS BY REFERENCE TO CAEP\'s ' +
              'credential-change**, so the two lists are the same list ' +
              'rather than two alike ones — which is why there is one ' +
              'CREDENTIAL_TYPES here and not a copy per vocabulary.' }
    ].concat(RISC_COMMON_MEMBERS),
    required: ['credential_type'],
    what: 'A credential belonging to this account was FOUND compromised — ' +
          'seen in a breach corpus, or reported. THE ONLY ONE OF THE ' +
          'FOURTEEN WITH A REQUIRED MEMBER, and the only one carrying any ' +
          'of the claims CAEP gives all eight of its own. A receiver acts ' +
          'on it differently by type: a compromised password is a reset, ' +
          'and a compromised hardware key is a revocation.',
    generate: function (values) {
      const asked = values || {};
      return {
        credential_type: typeof asked.credential_type === 'string' &&
          asked.credential_type !== '' ? asked.credential_type : 'password'
      };
    }
  },
  {
    uri: RISC_PREFIX + 'opt-in',
    family: 'risc',
    name: 'Opt In',
    subject: 'required',
    members: [],
    required: [],
    what: 'The account is participating in RISC exchange again. It is one ' +
          'of the four events that ARE a state transition rather than a ' +
          'report of one — RISC section 2.8 defines each of them as "the ' +
          'account is in the X state" — and it is the only event that may ' +
          'be sent about an account which has opted OUT, because without it ' +
          'a receiver would never learn that one came back.',
    generate: function () {
      return {};
    }
  },
  {
    uri: RISC_PREFIX + 'opt-out-initiated',
    family: 'risc',
    name: 'Opt Out Initiated',
    subject: 'required',
    members: [],
    required: [],
    what: 'The person asked to stop RISC exchange, AND IT CARRIES ON FOR A ' +
          'WHILE ANYWAY. That delay is the point of the state existing at ' +
          'all: RISC section 2.8 says it is there to stop a hijacker from ' +
          'opting out the moment they take an account over and silencing ' +
          'the very events that would report them.',
    generate: function () {
      return {};
    }
  },
  {
    uri: RISC_PREFIX + 'opt-out-cancelled',
    family: 'risc',
    name: 'Opt Out Cancelled',
    subject: 'required',
    members: [],
    required: [],
    what: 'The opt-out was called off and the account is back in the opt-in ' +
          'state. **THE SPELLING IS BRITISH AND IT IS THE SPECIFICATION\'S** ' +
          '— "cancelled" with two Ls — where a transmitter writing ' +
          '"opt-out-canceled" produces a URI a conforming receiver silently ' +
          'ignores, because there is no unknown-event-type error in this ' +
          'protocol.',
    generate: function () {
      return {};
    }
  },
  {
    uri: RISC_PREFIX + 'opt-out-effective',
    family: 'risc',
    name: 'Opt Out Effective',
    subject: 'required',
    members: [],
    required: [],
    what: 'The opt-out has taken effect and no further RISC events will be ' +
          'sent about this account. IT IS THE LAST ONE — an event announcing ' +
          'that there will be no more events — which is what makes it the ' +
          'one the opt-out gate in risc.js must never suppress. Suppressing ' +
          'it would leave a receiver waiting for signals that stopped ' +
          'without notice.',
    generate: function () {
      return {};
    }
  },
  {
    uri: RISC_PREFIX + 'recovery-activated',
    family: 'risc',
    name: 'Recovery Activated',
    subject: 'required',
    members: [],
    required: [],
    what: 'The account went through a recovery flow. It is a signal about ' +
          'RISK rather than about a change: a recovery is how a legitimate ' +
          'owner gets back in and it is also how an attacker who controls ' +
          'the recovery channel takes over, and the transmitter cannot tell ' +
          'which. A receiver is expected to weigh it, not act on it.',
    generate: function () {
      return {};
    }
  },
  {
    uri: RISC_PREFIX + 'recovery-information-changed',
    family: 'risc',
    name: 'Recovery Information Changed',
    subject: 'required',
    members: [],
    required: [],
    what: 'A recovery address or number was added, changed or removed. It ' +
          'is what a provider sends about an identifier IT IS NOT ' +
          'AUTHORITATIVE OVER — RISC says so where identifier-changed says ' +
          'the opposite — so the pair of them is the same act reported by ' +
          'two different kinds of provider. It carries no member saying ' +
          'WHICH information moved, deliberately: that would be publishing ' +
          'somebody\'s recovery address to every receiver on the stream.',
    generate: function () {
      return {};
    }
  },
  {
    uri: RISC_PREFIX + 'sessions-revoked',
    family: 'risc',
    name: 'Sessions Revoked',
    // RISC 1.0 section 2.11 deprecates this in favour of CAEP's
    // `session-revoked`. It is here, offered and warned about, because a
    // transmitter that cannot produce a deprecated event cannot be used to
    // find out what a receiver does with one — and receivers in the field
    // still send and expect this.
    deprecated: CAEP_PREFIX + 'session-revoked',
    subject: 'required',
    members: [],
    required: [],
    what: 'EVERY session the account has, everywhere, is gone — which is a ' +
          'far larger instruction than CAEP\'s session-revoked, whose ' +
          'subject names ONE of them. **DEPRECATED by RISC 1.0 section ' +
          '2.11**, which says new implementations MUST use CAEP\'s ' +
          'singular event instead. The two names differ by one letter and ' +
          'mean different things, so this is the pair to check when a ' +
          'receiver ends more sessions than anybody intended.',
    generate: function () {
      return {};
    }
  }
];

// THE THREE VOCABULARIES IN ONE TABLE. SSF's own first, because they are about
// the pipe every one of the others travels on; then CAEP's eight about a
// SESSION, then RISC's fourteen about an ACCOUNT.
const EVENTS = SSF_EVENTS.concat(CAEP_EVENTS).concat(RISC_EVENTS);

const CAEP_EVENT_URIS = CAEP_EVENTS.map(function (row) {
  return row.uri;
});

const RISC_EVENT_URIS = RISC_EVENTS.map(function (row) {
  return row.uri;
});


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
  const chosen = chooseFrom('ssf.eventsSupported', SSF_EVENTS,
                            'ssf.eventsSupported');
  const caep = config.value('caep.enabled')
    ? chooseFrom('caep.eventsSupported', CAEP_EVENTS, 'caep.eventsSupported')
    : [];
  const risc = config.value('risc.enabled')
    ? chooseFrom('risc.eventsSupported', RISC_EVENTS, 'risc.eventsSupported')
    : [];
  const out = chosen.concat(caep).concat(risc);
  log.debug('Leaving supportedEventUris(). ' + out.length + ' type(s).');
  return out;
}

// One vocabulary's offered list, from the setting that governs THAT
// vocabulary. THREE settings rather than one, and the reason is the same one
// that put CAEP and RISC in groups of their own: `ssf.eventsSupported` is
// about the pipe's own two events, `caep.eventsSupported` is about the
// profile's eight and `risc.eventsSupported` about RISC's fourteen, so
// turning a profile off or narrowing it is a decision belonging to THAT
// profile. A single list would have made `caep.enabled` and `risc.enabled`
// unable to do anything a reader could see in the metadata.
//
// **AN ENTRY IS ACCEPTED AS A SHORT NAME AS WELL AS A FULL URI**, because
// these URIs are 60 characters long and a setting nobody can type is a setting
// nobody narrows. `session-revoked` and the whole URI mean the same thing
// here; a name that matches no row in this vocabulary is DROPPED WITH A
// WARNING rather than advertised — advertising one would agree a stream this
// service can never deliver on, and SSF has no refusal for that, so the
// receiver's only notice would be events that never arrive.
function chooseFrom(setting, rows, label) {
  log.debug('Entering chooseFrom(). ' + setting);
  const asked = config.value(setting);
  const list = Array.isArray(asked) ? asked : String(asked || '').split(',');
  const byUri = {};
  const byShort = {};
  rows.forEach(function (row) {
    byUri[row.uri] = row.uri;
    byShort[row.uri.slice(row.uri.lastIndexOf('/') + 1)] = row.uri;
  });
  const chosen = [];
  list.map(function (one) {
    return String(one).trim();
  }).filter(Boolean).forEach(function (name) {
    const uri = byUri[name] || byShort[name] || '';
    if (!uri) {
      log.warn(label + ' names "' + name + '", which is not an event type ' +
               'in that vocabulary. It is NOT advertised — a transmitter ' +
               'that offered it would agree a stream it can never deliver ' +
               'on, and SSF has no refusal for an event type a transmitter ' +
               'will not send, so the receiver would simply wait for ever.');
      return;
    }
    if (chosen.indexOf(uri) < 0) {
      chosen.push(uri);
    }
  });
  const out = chosen.length ? chosen : rows.map(function (row) {
    return row.uri;
  });
  log.debug('Leaving chooseFrom(). ' + out.length + ' type(s).');
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
// ---------------------------------------------------------------------------
// ONE MEMBER'S VALUE AGAINST ITS ROW.
//
// It was three lines inside validateEvent() while every member was a string or
// a closed enum. CAEP needs four more shapes, and each of the four is a defect
// this service would otherwise carry silently to a receiver:
//
//   number    `event_timestamp` as the STRING "1757000000" is accepted by
//             every JSON parser and compared numerically by nobody.
//   strings   `amr` as a bare string. A session authenticated by a password
//             AND a security key has two values, and a receiver reading a
//             string sees one.
//   object    `claims`, which is the entire payload of token-claims-change.
//             An array here parses and means nothing.
//   langmap   `reason_admin` / `reason_user`. CAEP makes these objects keyed
//             by a BCP 47 language tag, and a plain string is the commonest
//             mistake in the whole profile — a receiver indexing by language
//             reads NOTHING from one and reports no error.
//
// **AND ONE THAT IS A WARNING RATHER THAN AN ERROR.** `openenum` is a list the
// specification says two parties may extend — `credential_type`, `namespace`,
// `principal` — so a value outside it is CARRIED and noted. Refusing would
// make this service unable to mock a vendor's own credential type, which is
// exactly what it is for. A closed `enum` is still refused.
// ---------------------------------------------------------------------------
function checkMember(member, value, errors, warnings) {
  log.debug('Entering checkMember(). ' + member.name);
  if (member.type === 'string' && typeof value !== 'string') {
    errors.push('"' + member.name + '" must be a string.');
    log.debug('Leaving checkMember(). Not a string.');
    return;
  }
  if (member.type === 'number' && typeof value !== 'number') {
    errors.push('"' + member.name + '" must be a NUMBER of seconds since ' +
        'the epoch, not a string. A quoted timestamp parses everywhere and ' +
        'is compared numerically nowhere.');
    log.debug('Leaving checkMember(). Not a number.');
    return;
  }
  if (member.type === 'strings') {
    if (!Array.isArray(value) ||
        value.some(function (one) { return typeof one !== 'string'; })) {
      errors.push('"' + member.name + '" must be an ARRAY of strings. A ' +
          'bare string is refused rather than wrapped: a session ' +
          'authenticated two ways has two values, and wrapping would hide ' +
          'a sender that can only ever say one.');
    }
    log.debug('Leaving checkMember(). strings.');
    return;
  }
  if (member.type === 'object') {
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      errors.push('"' + member.name + '" must be a JSON object.');
    }
    log.debug('Leaving checkMember(). object.');
    return;
  }
  if (member.type === 'langmap') {
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      errors.push('"' + member.name + '" must be an OBJECT KEYED BY A ' +
          'LANGUAGE TAG — {"en": "..."} — and not a string. That is CAEP ' +
          'section 2, and a receiver indexing it by language reads nothing ' +
          'from a string and reports no error.');
      log.debug('Leaving checkMember(). Not a language map.');
      return;
    }
    Object.keys(value).forEach(function (tag) {
      if (typeof value[tag] !== 'string') {
        errors.push('"' + member.name + '.' + tag + '" must be a string.');
      }
      if (!/^[A-Za-z]{2,8}(-[A-Za-z0-9]{1,8})*$/.test(tag)) {
        warnings.push('"' + tag + '" is not shaped like a BCP 47 language ' +
            'tag. It is carried — nothing here owns the registry — and a ' +
            'receiver looking for "en" will not find it.');
      }
    });
    log.debug('Leaving checkMember(). langmap.');
    return;
  }
  if (member.type === 'enum' && member.values.indexOf(value) < 0) {
    errors.push('"' + member.name + '" must be one of ' +
        member.values.join(', ') + '.');
    log.debug('Leaving checkMember(). Outside a closed enum.');
    return;
  }
  if (member.type === 'openenum' && member.values.indexOf(value) < 0) {
    warnings.push('"' + String(value) + '" is not one of the values CAEP ' +
        'lists for "' + member.name + '" (' + member.values.join(', ') +
        '). That list is OPEN — two parties may agree their own — so it is ' +
        'CARRIED rather than refused, and a receiver that has not been told ' +
        'about it will ignore the event.');
  }
  log.debug('Leaving checkMember(). ' + member.name + ' checked.');
}

// A member name that differs from one this row defines only by hyphen versus
// underscore. It is one comparison rather than a table of known typos, so it
// stays true for a vocabulary nobody has written yet.
function nearestMember(name, members) {
  log.debug('Entering nearestMember(). ' + name);
  const flat = String(name).replace(/[-_]/g, '_');
  let found = '';
  (members || []).forEach(function (member) {
    if (!found && member.name !== name &&
        String(member.name).replace(/[-_]/g, '_') === flat) {
      found = member.name;
    }
  });
  log.debug('Leaving nearestMember(). ' + (found || '(none)'));
  return found;
}

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
  // A ROW THAT ITS OWN SPECIFICATION DEPRECATES SAYS SO, ON EVERY EVENT, AND
  // IT IS A WARNING RATHER THAN A REFUSAL. RISC 1.0 section 2.11 deprecates
  // `sessions-revoked` in favour of CAEP's `session-revoked`; a transmitter
  // that could not produce the deprecated one could not be used to find out
  // what a receiver does with it, and receivers in the field still send and
  // expect it. Written against `row.deprecated` rather than against the URI,
  // so the next deprecation is a field and not a branch.
  if (row.deprecated) {
    warnings.push('"' + uri + '" is DEPRECATED by its own specification, ' +
        'which says new implementations must use "' + row.deprecated + '" ' +
        'instead. It is still built and still sent — a transmitter that ' +
        'could not produce one could not be used to find out what a ' +
        'receiver does with it — and the two names differ by one letter and ' +
        'mean different things, so this is the pair to check when a ' +
        'receiver ends more sessions than anybody intended.');
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
      // A NEAR MISS IS NAMED, and it is worth a sentence of its own rather
      // than the general one below. Every member in SSF and CAEP is
      // snake_case and exactly one in RISC is not — `identifier-changed`'s
      // `new-value` — so `new_value` typed from habit is an event that
      // validates, delivers, and tells the receiver nothing. It is written
      // against the ROW's own member names rather than against that one
      // spelling, so it catches the reverse mistake too and needs no
      // maintenance when a vocabulary adds a member.
      const nearMiss = nearestMember(name, row.members);
      warnings.push('"' + name + '" is not a member "' + uri + '" defines. ' +
          (nearMiss
            ? 'It differs from "' + nearMiss + '", which IS one, only in a ' +
              'hyphen or an underscore — and this is the one place in the ' +
              'three vocabularies where that matters, because ' +
              '"new-value" is the only hyphenated member name in any of ' +
              'them. What you sent is CARRIED as an extension and the ' +
              'member the specification defines is absent, so a conforming ' +
              'receiver reads nothing and reports no error. '
            : '') +
          'It is CARRIED rather than refused: an event vocabulary extends, ' +
          'and a receiver is expected to ignore what it does not know.');
      return;
    }
    const value = body[name];
    checkMember(member, value, errors, warnings);
  });
  log.debug('Leaving validateEvent(). ' + errors.length + ' problem(s).');
  return { ok: errors.length === 0, errors: errors, warnings: warnings };
}

// ---------------------------------------------------------------------------
// WHAT IS WRONG WITH THE SUBJECT OF ONE EVENT, WHERE THE ROW NARROWS IT.
//
// `transmit()` already refuses an event whose row says `subject: 'required'`
// and that carries none, and that refusal is MECHANICAL: there is nothing to
// match against a stream's subjects, so the event can be delivered to nobody
// or to everybody and neither is what was meant.
//
// **THIS IS THE OTHER KIND, AND IT IS A WARNING FOR EXACTLY THAT REASON.**
// RISC's two identifier events say the subject MUST be an email address or a
// phone number, because for those two the identifier IS the message — the
// subject carries the OLD value and the payload carries at most the new one.
// An `iss_sub` subject there is perfectly deliverable and merely wrong, and
// refusing to send one would remove the ability to find out what a receiver
// does with it, which is the whole reason this service exists.
//
// It is driven by `row.subjectFormats` rather than by the URI, so it is a
// property of the table and not a branch naming a vocabulary.
// ---------------------------------------------------------------------------
function subjectAdvice(uri, subject) {
  log.debug('Entering subjectAdvice(). ' + uri);
  const warnings = [];
  const row = EVENT_BY_URI[uri];
  if (!row || !Array.isArray(row.subjectFormats) || !subject) {
    log.debug('Leaving subjectAdvice(). Nothing to say.');
    return warnings;
  }
  const format = String((subject || {}).format || '');
  if (!format) {
    warnings.push('"' + uri + '" wants a subject in one of these formats: ' +
        row.subjectFormats.join(', ') + '. This one is a COMPLEX subject — ' +
        'it has no `format` of its own — which names a person and possibly ' +
        'a session, and this event is about an IDENTIFIER rather than about ' +
        'either.');
    log.debug('Leaving subjectAdvice(). Complex subject.');
    return warnings;
  }
  if (row.subjectFormats.indexOf(format) < 0) {
    warnings.push('"' + uri + '" says its subject MUST be one of ' +
        row.subjectFormats.join(' or ') + ' and this one is "' + format +
        '". It is SENT anyway — the event is perfectly deliverable and ' +
        'merely wrong, and refusing would remove the ability to find out ' +
        'what a receiver does with it. What is lost is the message itself: ' +
        'the subject of these two events carries the identifier that ' +
        'changed, so a subject naming the person instead says that ' +
        'something about them moved without saying what.');
  }
  log.debug('Leaving subjectAdvice(). ' + warnings.length + ' warning(s).');
  return warnings;
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
  CAEP_PREFIX: CAEP_PREFIX,
  RISC_PREFIX: RISC_PREFIX,
  EVENTS: EVENTS,
  SSF_EVENTS: SSF_EVENTS,
  CAEP_EVENTS: CAEP_EVENTS,
  CAEP_EVENT_URIS: CAEP_EVENT_URIS,
  CAEP_COMMON_MEMBERS: CAEP_COMMON_MEMBERS,
  RISC_EVENTS: RISC_EVENTS,
  RISC_EVENT_URIS: RISC_EVENT_URIS,
  RISC_COMMON_MEMBERS: RISC_COMMON_MEMBERS,
  CREDENTIAL_TYPES: CREDENTIAL_TYPES,
  subjectAdvice: subjectAdvice,
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
