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

// The two VOCABULARY prefixes. CAEP's rows are in the table below; RISC's are
// the third part of this work and its prefix is written down here anyway,
// because it is the thing most likely to be typed from memory and got subtly
// wrong — there is no "unknown event type" error in this protocol, so a
// receiver silently ignores a type it does not recognise and nobody finds out.
const CAEP_PREFIX = 'https://schemas.openid.net/secevent/caep/event-type/';
const RISC_PREFIX = 'https://schemas.openid.net/secevent/risc/event-type/';

// The `typ` of a Security Event Token (RFC 8417 section 2.3). It is the media
// type without the `application/` prefix, which is what a JWT header carries.
const SET_MEDIA_TYPE = 'secevent+jwt';

// ---------------------------------------------------------------------------
// THE CATALOGUE.
//
//   uri        the event type, which is the KEY in the SET's `events` map
//   family     which specification defines it — 'ssf' or 'caep'; 'risc' is
//              the third part of this work and has no rows yet
//   subject    'none' | 'optional' | 'required'. SSF's TWO ARE THE ONLY ONES
//              IN ANY OF THE THREE VOCABULARIES WITH NO SUBJECT AT ALL, and
//              it is worth knowing why: they are about the STREAM,
//              not about anybody, so a receiver that insists on a subject
//              cannot be verified.
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
        values: ['password', 'pin', 'x509', 'fido2-platform',
                 'fido2-roaming', 'fido-u2f', 'verifiable-credential',
                 'phone-voice', 'phone-sms', 'app'],
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

// The two vocabularies in one table. SSF's own first, because they are about
// the pipe every one of the others travels on.
const EVENTS = SSF_EVENTS.concat(CAEP_EVENTS);

const CAEP_EVENT_URIS = CAEP_EVENTS.map(function (row) {
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
  const out = chosen.concat(caep);
  log.debug('Leaving supportedEventUris(). ' + out.length + ' type(s).');
  return out;
}

// One vocabulary's offered list, from the setting that governs THAT
// vocabulary. Two settings rather than one, and the reason is the same one
// that put CAEP in a group of its own: `ssf.eventsSupported` is about the
// pipe's own two events and `caep.eventsSupported` is about the profile's
// eight, so turning the profile off or narrowing it is a CAEP decision and
// narrowing SSF's two is an SSF one. A single list would have made
// `caep.enabled` unable to do anything a reader could see in the metadata.
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
    checkMember(member, value, errors, warnings);
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
  CAEP_PREFIX: CAEP_PREFIX,
  RISC_PREFIX: RISC_PREFIX,
  EVENTS: EVENTS,
  SSF_EVENTS: SSF_EVENTS,
  CAEP_EVENTS: CAEP_EVENTS,
  CAEP_EVENT_URIS: CAEP_EVENT_URIS,
  CAEP_COMMON_MEMBERS: CAEP_COMMON_MEMBERS,
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
