'use strict';
//
// File: spiffe_auth.js
//
// ---------------------------------------------------------------------------
// WHO IS CALLING THE TWO gRPC SURFACES — the SPIFFE half of what `scim_auth.js`
// is to `/scim/v2`, and the second surface in this service that enforces
// anything at all.
//
// A LIBRARY: it registers no route, starts no listener and NEVER TOUCHES A
// `call` TO ANSWER ONE. It decides and `spiffe_grpc.js` answers — the same
// split `oauth2_bcp.js` has with `oauth2.js` and `scim_auth.js` has with
// `scim.js` — which is why every refusal below is returned as a plain
// `{ status, message }` descriptor rather than as a gRPC error. It requires
// `crypto`, `helpers.js`, `config.js`, `audit.js`, `admin_stats.js`,
// `spiffe_id.js`, `spiffe_ca.js` and `spiffe_registry.js`; `spiffe_grpc.js`
// requires THIS, in the ordinary direction, so it cannot join a cycle.
//
// ---------------------------------------------------------------------------
// THE TWO SURFACES ARE AUTHENTICATED DIFFERENTLY BECAUSE THE SPECIFICATIONS
// SAY OPPOSITE THINGS, AND THAT IS THE FIRST THING TO KNOW
//
// It reads like an inconsistency and it is not. They are two different
// documents making two different demands, and getting them the same way round
// would break a real client either way.
//
//   **The Workload API MUST NOT authenticate its clients.** The SPIFFE Workload
//   Endpoint specification says so in terms: the endpoint "MUST NOT require any
//   direct authentication of its clients", and "Transport Layer Security MUST
//   NOT be required". The reason is bootstrapping — a workload has no secret
//   and no root of trust until this call gives it one, so a credential cannot
//   be asked for. The endpoint instead ASCERTAINS the caller out of band, by
//   asking the kernel about the peer of the Unix socket, and turns what it
//   learns into SELECTORS. A mock that demanded a credential here would refuse
//   every conforming client.
//
//   **The SPIRE Server API is mutual TLS with an X509-SVID.** A real
//   `spire-server` binds a TCP port whose clients present an SVID from this
//   trust domain, takes the caller's SPIFFE ID off the certificate, and
//   authorizes each method against WHAT THAT CALLER IS — local, agent, admin,
//   downstream. Its private Unix socket is `local` and needs no credential,
//   which is how the `spire-server` CLI works on the same host.
//
// So: the Workload API gains ATTESTATION here and no credential; the Server API
// gains a CREDENTIAL and an authorization table. Neither is a softening of the
// other.
//
// ---------------------------------------------------------------------------
// WHAT THIS SERVICE CAN AND CANNOT ATTEST, SAID PLAINLY
//
// A real agent reads the peer credentials of its Unix socket — `SO_PEERCRED`,
// giving pid, uid and gid — and from the pid derives the executable path, its
// sha256, the container, the Kubernetes pod. **Node has no portable way to read
// `SO_PEERCRED`**: `net.Socket` exposes no such call, `/proc/net/unix` does not
// record the peer, and the only routes to it are native addons. So the honest
// list of what a caller can be identified BY here is short, and it is published
// rather than implied:
//
//   * the TRANSPORT it arrived on — the Unix socket or TCP;
//   * the ENDPOINT it reached — which socket path, or which address and port;
//   * for TCP, the peer address;
//   * and, only when `spiffe.acceptAssertedSelectors` is on, whatever the
//     caller SAID about itself.
//
// The first three are facts about the connection and are real. The fourth is
// not attestation at all and is named so that nobody can mistake it for any:
// it exists because SELECTOR MATCHING IS THE INTERESTING BEHAVIOUR and there is
// otherwise no way to exercise it. A client library's "these selectors matched
// and those did not" path is a real path with real bugs in it, and a mock that
// hands every caller every identity can never run it.
//
// **THE SELECTORS THIS SERVICE PRODUCES ARE NOT SPELT LIKE SPIRE'S.** They are
// `transport:`, `endpoint:` and `peer:`, which are types no attestor plugin
// defines. Writing `unix:uid:1000` for a uid nothing read would be inventing an
// attested fact, which is the same offence as minting a WIT-SVID against no
// specification. An ASSERTED selector, by contrast, is passed through VERBATIM
// — if a caller says `unix:uid:1000` that is what it is matched on — because
// the whole point of the affordance is to reproduce a real match, and it is the
// caller's own claim rather than this service's invention.
//
// ---------------------------------------------------------------------------
// THE AUTHORIZATION TABLE IS SPIRE'S OWN, ROW FOR ROW
//
// `POLICY` below is `pkg/server/authpolicy/policy_data.json` from the SPIRE
// source, restricted to the forty-two methods this service implements. It is
// COPIED rather than reasoned out, deliberately: a table somebody derived from
// what each method "obviously" needs is a table that disagrees with SPIRE in
// two or three places, and the client author who meets the disagreement has no
// way to tell which end is wrong. Where a row here looks surprising — `Debug.
// GetInfo` is local-only, so an admin SVID over TCP is refused it — that is
// SPIRE's answer and the surprise is the point.
//
// ---------------------------------------------------------------------------
// WHAT IS STILL NOT CHECKED, BECAUSE THE LIST MATTERS MORE THAN THE ADDITIONS
//
// The Workload API still hands out identities to anybody who can reach the
// socket; there is no attestation of a workload's identity, only of which
// entries its observable selectors match. Node attestation at `AttestAgent` is
// still taken on trust — the payload is not verified and every agent entry
// still carries `unverified:true`. And with `spiffe.authRequired` off, all of
// this stands down and the service behaves exactly as it did before this file
// existed. See `GET /spiffe`, which publishes the whole of it.
// ---------------------------------------------------------------------------

const crypto = require('crypto');
const { log, nowSec } = require('../common/helpers');
const config = require('../common/config');
const audit = require('../common/audit');
const stats = require('../common/admin_stats');
const spiffeId = require('./spiffe_id');
const ca = require('./spiffe_ca');
const registry = require('./spiffe_registry');
// The RFC 4514 form of a certificate subject. Required rather than
// reimplemented for the reason that module's export note gives — two spellings
// of one DN is two people on /admin/users — and `scim_auth.js` requires it for
// exactly this. Safe by rule 3e's test applied rather than assumed: this file
// is reached through `spiffe_grpc.js` from `spiffe_server.js`, which
// `server.js` requires LAST and long after `./tls_server`, so no route moves,
// and that module knows nothing about SPIFFE, so there is no cycle.
const tls = require('../tls/tls_server');

// ---------------------------------------------------------------------------
// THE ENTITIES. A CALLER MAY BE SEVERAL AT ONCE.
//
// SPIRE's authorizers are not exclusive and this must not make them so: the
// `spire-server` CLI on the same host is `local`, an agent that also holds an
// entry marked admin is both, and a caller over TCP with no certificate is
// none of them. `authorize()` therefore asks "is the caller ANY of the
// entities this method allows", which is what the rego does.
//
// The prose is here rather than on the pages because both `GET /spiffe` and
// `/admin/spiffe` draw it, and two copies of an explanation is one that will
// eventually be wrong on one page.
// ---------------------------------------------------------------------------
const ENTITIES = [
  { id: 'local', label: 'Local',
    what: 'The call arrived on the Unix domain socket. A real SPIRE server ' +
          'trusts its private socket outright — that is how the spire-server ' +
          'CLI works — and the access control is the socket\'s filesystem ' +
          'permissions. `spiffe.trustLocalSocket` turns that off, which makes ' +
          'the socket demand an SVID like the TCP port and is the only way to ' +
          'exercise a client\'s "I was refused on the socket" path.' },
  { id: 'agent', label: 'Agent',
    what: 'The caller presented an X509-SVID whose SPIFFE ID is an agent id ' +
          '(/spire/agent/...) and which names an agent this server has ' +
          'attested and has not banned. A banned agent is refused here rather ' +
          'than at AttestAgent alone, which is what makes the ban on ' +
          '/admin/spiffe/agents mean something for a caller that already ' +
          'holds an SVID.' },
  { id: 'admin', label: 'Admin',
    what: 'The caller\'s SPIFFE ID is named in `spiffe.adminIds`, or a ' +
          'registration entry for that identity is marked `admin`. Both, ' +
          'because SPIRE has both: admin_ids needs no entry, and the flag on ' +
          'an entry is what an operator sets from the console. This is the ' +
          'thing that lets a remote caller manage registration entries.' },
  { id: 'downstream', label: 'Downstream',
    what: 'A registration entry for the caller\'s identity is marked ' +
          '`downstream` — a nested SPIRE server, which may ask for an ' +
          'intermediate CA and publish an authority and may do nothing else.' },
  { id: 'anonymous', label: 'Anonymous',
    what: 'No credential was presented, or one was and it did not verify. ' +
          'Two methods are still open to it, and both have to be: AttestAgent, ' +
          'because an agent has no SVID until that call gives it one, and ' +
          'GetBundle, because the trust bundle is public by design.' }
];

// ---------------------------------------------------------------------------
// THE POLICY TABLE — SPIRE's `policy_data.json`, the forty-two rows this
// service has methods for.
//
// `any` is `allow_any` in that file and means the method is open, which is a
// different statement from "this service does not check it": AttestAgent and
// GetBundle are open in a real SPIRE server too, for the reasons in ENTITIES
// above.
//
// A method with NO ROW is refused rather than allowed. That is the safer
// direction and it is also the one that fails visibly: a method added without
// a row is refused for everybody the first time it is called, where a default
// of "allow" would leave it unauthorized forever with nothing to notice.
// ---------------------------------------------------------------------------
const POLICY = {
  // Entry
  'Entry.CountEntries':        { admin: true, local: true },
  'Entry.ListEntries':         { admin: true, local: true },
  'Entry.GetEntry':            { admin: true, local: true },
  'Entry.BatchCreateEntry':    { admin: true, local: true },
  'Entry.BatchUpdateEntry':    { admin: true, local: true },
  'Entry.BatchDeleteEntry':    { admin: true, local: true },
  'Entry.GetAuthorizedEntries':  { agent: true },
  'Entry.SyncAuthorizedEntries': { agent: true },
  // Agent
  'Agent.CountAgents':         { admin: true, local: true },
  'Agent.ListAgents':          { admin: true, local: true },
  'Agent.GetAgent':            { admin: true, local: true },
  'Agent.DeleteAgent':         { admin: true, local: true },
  'Agent.BanAgent':            { admin: true, local: true },
  'Agent.CreateJoinToken':     { admin: true, local: true },
  'Agent.AttestAgent':         { any: true },
  'Agent.RenewAgent':          { agent: true },
  'Agent.PostStatus':          { agent: true },
  // Bundle
  'Bundle.GetBundle':          { any: true },
  'Bundle.CountBundles':       { admin: true, local: true },
  'Bundle.AppendBundle':       { admin: true, local: true },
  'Bundle.PublishJWTAuthority': { downstream: true },
  'Bundle.PublishWITAuthority': { downstream: true },
  'Bundle.ListFederatedBundles': { admin: true, local: true },
  'Bundle.GetFederatedBundle': { admin: true, local: true, agent: true },
  'Bundle.BatchCreateFederatedBundle': { admin: true, local: true },
  'Bundle.BatchUpdateFederatedBundle': { admin: true, local: true },
  'Bundle.BatchSetFederatedBundle':    { admin: true, local: true },
  'Bundle.BatchDeleteFederatedBundle': { admin: true, local: true },
  // SVID
  'SVID.MintX509SVID':         { admin: true, local: true },
  'SVID.MintJWTSVID':          { admin: true, local: true },
  'SVID.MintWITSVID':          { admin: true, local: true },
  'SVID.BatchNewX509SVID':     { agent: true },
  'SVID.NewJWTSVID':           { agent: true },
  'SVID.BatchNewWITSVID':      { agent: true },
  'SVID.NewDownstreamX509CA':  { downstream: true },
  // TrustDomain
  'TrustDomain.ListFederationRelationships':       { admin: true, local: true },
  'TrustDomain.GetFederationRelationship':         { admin: true, local: true },
  'TrustDomain.BatchCreateFederationRelationship': { admin: true, local: true },
  'TrustDomain.BatchUpdateFederationRelationship': { admin: true, local: true },
  'TrustDomain.BatchDeleteFederationRelationship': { admin: true, local: true },
  'TrustDomain.RefreshBundle':                     { admin: true, local: true },
  // Debug. Local ONLY, in SPIRE and therefore here: an admin SVID over TCP is
  // refused it. That reads like an omission and is not — it is a health check
  // for whoever is standing on the host.
  'Debug.GetInfo':             { local: true }
};

// The order the entities are named in a refusal message, so two refusals for
// the same method read the same way.
const ENTITY_ORDER = ['local', 'admin', 'agent', 'downstream'];

// ---------------------------------------------------------------------------
// SETTINGS, read per call rather than captured. Every one of these is
// `runtime: true` except `spiffe.authRequired`, which binds a socket — see
// config.js's header for why a captured `const` is the one thing
// /admin/config cannot reach.
// ---------------------------------------------------------------------------
function authRequired() { return !!config.value('spiffe.authRequired'); }
function trustLocalSocket() { return !!config.value('spiffe.trustLocalSocket'); }
function attestWorkloads() { return !!config.value('spiffe.attestWorkloads'); }
function acceptAssertedSelectors() {
  return !!config.value('spiffe.acceptAssertedSelectors');
}

// The admin ids, as a list. A string in configuration because it is a list of
// URIs and every other list-shaped setting here is one; parsed on every read so
// that adding one on /admin/config takes effect on the next call.
function adminIds() {
  const raw = String(config.value('spiffe.adminIds') || '');
  return raw.split(/[\s,]+/).map(function (id) { return id.trim(); })
            .filter(Boolean);
}

// The metadata key an asserted selector arrives under. Deliberately NOT one any
// specification names, and deliberately ugly: a client author who copies it
// into production code should be able to see from the spelling alone that it is
// this service's own affordance and not part of the Workload API.
const ASSERTED_SELECTOR_KEY = 'x-sts-mock-workload-selector';

// ---------------------------------------------------------------------------
// THE TRANSPORT A CALL ARRIVED ON.
//
// This decides whether the caller is `local`, so it has to be right, and
// grpc-js does not answer it directly. Two signals, in this order:
//
//   * the AUTH CONTEXT. When `spiffe.authRequired` is on, the TCP listener for
//     the SPIRE Server API is TLS and the Unix socket is not — so
//     `transportSecurityType === 'ssl'` is conclusive proof of TCP.
//   * `getPeer()`. grpc-js builds it from `socket.remoteAddress`, which a Unix
//     socket does not have, so it answers the literal string `unknown` there
//     and `address:port` for TCP. That is an implementation detail of the
//     library rather than a documented API, which is why it is the SECOND
//     signal and not the only one.
//
// Getting this wrong in the direction that matters — calling a TCP caller
// `local` — would hand every method to anybody who could reach the port, so
// the fallback below defaults to TCP for anything it does not recognise.
// ---------------------------------------------------------------------------
function transportOf(call) {
  log.debug('Entering transportOf().');
  let context = null;
  try {
    context = call && typeof call.getAuthContext === 'function'
      ? call.getAuthContext() : null;
  } catch (e) {
    // grpc-js throws here if the stream is already gone, which happens when a
    // client cancels mid-call. Not a fault and not the caller's problem.
    log.debug('transportOf(): the auth context was not readable (' + e.message +
              '), so the peer address decides.');
  }
  if (context && context.transportSecurityType === 'ssl') {
    log.debug('Leaving transportOf().');
    return 'tcp';
  }
  let peer = '';
  try {
    peer = call && typeof call.getPeer === 'function' ? String(call.getPeer()) : '';
  } catch (e) {
    // Same case as above, and the same answer: assume the less trusting one.
    log.debug('transportOf(): the peer was not readable (' + e.message + ').');
  }
  if (!peer || peer === 'unknown' || peer.indexOf('unix:') === 0) {
    log.debug('Leaving transportOf().');
    return 'uds';
  }
  log.debug('Leaving transportOf().');
  return 'tcp';
}

function peerOf(call) {
  try {
    const peer = call && typeof call.getPeer === 'function' ? String(call.getPeer()) : '';
    return peer === 'unknown' ? '' : peer;
  } catch (e) {
    // See transportOf(). A peer that cannot be read is not an error here; it
    // is a column on a page that says nothing.
    log.debug('peerOf(): the peer was not readable (' + e.message + ').');
    return '';
  }
}

// The certificate the client presented, or null. `sslPeerCertificate` is absent
// rather than empty when none was sent — grpc-js only sets it when the DER is
// there — which is what distinguishes "no certificate" from "a certificate that
// did not verify", and those are two different refusals.
function peerCertificateOf(call) {
  try {
    const context = call && typeof call.getAuthContext === 'function'
      ? call.getAuthContext() : null;
    if (!context || !context.sslPeerCertificate) return null;
    return context.sslPeerCertificate.raw ? context.sslPeerCertificate : null;
  } catch (e) {
    log.debug('peerCertificateOf(): no readable auth context (' + e.message + ').');
    return null;
  }
}

// ---------------------------------------------------------------------------
// THE SPIFFE ID OFF A CERTIFICATE.
//
// It is the URI SAN and nothing else — not the subject, not a DNS name, not
// `CN=`. An X509-SVID carries exactly ONE URI SAN and that is its identity;
// reading a SPIFFE ID out of a common name would accept a certificate that is
// not an SVID at all and would let anyone who can obtain a certificate with a
// chosen CN name themselves anything.
//
// Node hands the SANs back as one comma-separated string —
// `URI:spiffe://example.org/a, DNS:host` — so it is split rather than indexed.
// A certificate with SEVERAL URI SANs is refused rather than having the first
// taken: the SVID specification permits one, and picking one of two would be
// choosing which identity a caller has on their behalf.
// ---------------------------------------------------------------------------
function spiffeIdFromCertificate(certificate) {
  log.debug('Entering spiffeIdFromCertificate().');
  const sans = String((certificate || {}).subjectaltname || '');
  const uris = sans.split(',').map(function (part) {
    return part.trim();
  }).filter(function (part) {
    return part.toLowerCase().indexOf('uri:') === 0;
  }).map(function (part) {
    return part.slice(4).trim();
  });
  if (!uris.length) {
    log.debug('Leaving spiffeIdFromCertificate(). No URI SAN.');
    return { ok: false, reason: 'The certificate carries no URI ' +
             'subjectAltName, so it is not an X509-SVID. An SVID\'s identity ' +
             'is its URI SAN; nothing else on a certificate names one.' };
  }
  if (uris.length > 1) {
    log.debug('Leaving spiffeIdFromCertificate(). ' + uris.length + ' URI SANs.');
    return { ok: false, reason: 'The certificate carries ' + uris.length +
             ' URI subjectAltNames. An X509-SVID has exactly one — choosing ' +
             'between them would be deciding which identity you have.' };
  }
  const parsed = spiffeId.parse(uris[0]);
  if (!parsed.ok) {
    log.debug('Leaving spiffeIdFromCertificate(). Not a SPIFFE ID.');
    return { ok: false, reason: 'The certificate\'s URI subjectAltName is not ' +
             'a valid SPIFFE ID: ' + parsed.reason };
  }
  log.debug('Leaving spiffeIdFromCertificate(). ' + parsed.id);
  return { ok: true, id: parsed.id };
}

// ---------------------------------------------------------------------------
// VERIFYING THE CERTIFICATE.
//
// This is done HERE and not by the TLS stack, and the reason is the one thing
// about this listener that has to be understood before changing it.
//
// The socket is bound `requestCert: true, rejectUnauthorized: false` — ask for
// a certificate, do not refuse a handshake that has none. It has to be, because
// `AttestAgent` is open to a caller with no SVID and an agent HAS no SVID until
// that call gives it one. A listener that rejected unauthorized connections
// would make agent bootstrapping impossible over TCP, which is the one thing
// this port is for. So OpenSSL is told to collect the certificate and this
// function decides what it is worth. `mtls.js` makes the same arrangement on
// the main HTTPS listener, for a related reason.
//
// What is checked: the validity window, then that some X.509 authority this
// service holds ISSUED and SIGNED it, then that the SPIFFE ID's trust domain is
// the one whose authority verified it. That last check is not decoration — a
// federated trust domain's authority verifying a certificate that claims to be
// in OUR trust domain is precisely the cross-domain confusion a bundle is meant
// to prevent.
//
// A chain longer than the leaf is NOT walked, deliberately: this CA signs
// leaves directly, an intermediate would have to be one this service issued
// through NewDownstreamX509CA, and pretending to build a path we do not build
// would be reporting a check that did not happen.
// ---------------------------------------------------------------------------
function authorityCertificates() {
  log.debug('Entering authorityCertificates().');
  const out = [];
  const state = ca.state();
  (state.x509Authorities || []).forEach(function (authority) {
    try {
      out.push({ trustDomain: ca.trustDomain(),
                 certificate: new crypto.X509Certificate(authority.certificatePem) });
    } catch (e) {
      // An authority this service minted itself that will not parse is a
      // defect here rather than a caller problem, so it is logged loudly and
      // the others are still usable.
      log.error('spiffe: one of this trust domain\'s own X.509 authorities ' +
                'would not parse and cannot verify anything: ' + e.message);
    }
  });
  ca.federatedBundles().forEach(function (foreign) {
    ((foreign.document || {}).keys || []).forEach(function (key) {
      if (key.use !== 'x509-svid') return;
      (key.x5c || []).forEach(function (b64) {
        try {
          out.push({ trustDomain: foreign.trustDomain,
                     certificate: new crypto.X509Certificate(Buffer.from(String(b64), 'base64')) });
        } catch (e) {
          // A malformed x5c in a bundle somebody pushed in. Skipped with the
          // same reasoning federatedX509BundleDer() gives: the rest of the
          // bundle is still usable, and a bad key is the pusher's problem.
          log.warn('spiffe: an x5c entry in the ' + foreign.trustDomain +
                   ' bundle would not parse and cannot verify anything: ' +
                   e.message);
        }
      });
    });
  });
  log.debug('Leaving authorityCertificates().');
  return out;
}

function verifyPresentedCertificate(certificate, id) {
  log.debug('Entering verifyPresentedCertificate(). id=' + id);
  let leaf;
  try {
    leaf = new crypto.X509Certificate(certificate.raw);
  } catch (e) {
    log.debug('Leaving verifyPresentedCertificate(). It would not parse.');
    return { ok: false, reason: 'The presented certificate would not parse: ' +
                                e.message };
  }
  // The clock, with this service's configured skew. An SVID's lifetime is
  // short — an hour by default — so a client whose clock is a few minutes out
  // meets this constantly, and a refusal that does not name the skew reads as
  // a broken certificate.
  const skew = Number(config.value('spiffe.clockSkew')) || 0;
  const now = nowSec();
  const from = Math.floor(new Date(leaf.validFrom).getTime() / 1000);
  const to = Math.floor(new Date(leaf.validTo).getTime() / 1000);
  if (Number.isFinite(from) && now + skew < from) {
    log.debug('Leaving verifyPresentedCertificate(). Not yet valid.');
    return { ok: false, reason: 'The presented SVID is not valid until ' +
             leaf.validFrom + ' and it is now ' + new Date().toISOString() +
             ' here (allowing ' + skew + 's of skew).' };
  }
  if (Number.isFinite(to) && now - skew > to) {
    log.debug('Leaving verifyPresentedCertificate(). Expired.');
    return { ok: false, reason: 'The presented SVID expired at ' + leaf.validTo +
             '. SVIDs here live for ' + config.value('spiffe.svidTtl') +
             's — fetch a new one rather than reusing this.' };
  }
  const authorities = authorityCertificates();
  if (!authorities.length) {
    log.debug('Leaving verifyPresentedCertificate(). No authorities.');
    return { ok: false, reason: 'This service holds no X.509 authority to ' +
             'verify an SVID against, which is a fault here rather than a ' +
             'problem with your certificate. See GET /spiffe.' };
  }
  for (let i = 0; i < authorities.length; i++) {
    const authority = authorities[i];
    let signed = false;
    try {
      signed = leaf.checkIssued(authority.certificate) &&
               leaf.verify(authority.certificate.publicKey);
    } catch (e) {
      // `verify` throws rather than returning false for a key of the wrong
      // type, which is the ordinary case when the bundle holds both an EC and
      // an RSA authority. Not an error: it means this one did not sign it.
      signed = false;
    }
    if (!signed) continue;
    const claimed = spiffeId.trustDomainOf(id);
    if (claimed !== authority.trustDomain) {
      log.debug('Leaving verifyPresentedCertificate(). Trust domain mismatch.');
      return { ok: false, reason: 'The certificate says it is ' + id +
               ', but the authority that signed it belongs to the trust ' +
               'domain ' + authority.trustDomain + '. A bundle verifies ' +
               'identities in ITS OWN trust domain and nowhere else; ' +
               'accepting this would be exactly the cross-domain confusion ' +
               'federation exists to prevent.' };
    }
    log.debug('Leaving verifyPresentedCertificate(). Verified against ' +
              authority.trustDomain + '.');
    return { ok: true, trustDomain: authority.trustDomain };
  }
  log.debug('Leaving verifyPresentedCertificate(). Nothing signed it.');
  return { ok: false, reason: 'No X.509 authority this service holds signed ' +
           'that certificate — neither this trust domain\'s (' +
           ca.trustDomain() + ') nor any federated one. It is a certificate ' +
           'from somewhere else, or from a previous run: the authorities here ' +
           'are generated at startup and do not survive a restart.' };
}

// ---------------------------------------------------------------------------
// CLASSIFYING A VERIFIED IDENTITY.
//
// Read from the registry on every call and never cached, which is the same
// rule `applications.js` follows about its entries and for the same reason: an
// `ldapmodify` of `spiffeAdmin` on an entry under ou=spiffe changes what that
// caller may do on the NEXT call, and a cache added for speed would quietly
// undo it.
// ---------------------------------------------------------------------------
function classify(id) {
  log.debug('Entering classify(). id=' + id);
  const entities = { local: false, agent: false, admin: false, downstream: false };
  const notes = [];
  if (!id) {
    log.debug('Leaving classify(). No identity.');
    return { entities: entities, notes: notes };
  }
  if (adminIds().indexOf(id) >= 0) {
    entities.admin = true;
    notes.push('named in spiffe.adminIds');
  }
  // The entries for this identity. An entry marked admin or downstream is what
  // an operator sets from /admin/spiffe/entries, and SPIRE reads both flags the
  // same way. Note that this is the first thing in this service that READS
  // those flags — they have been recorded and reported since the registry was
  // written, and the header of spiffe_api.js used to say nothing read them.
  registry.entriesForSpiffeId(id).forEach(function (entry) {
    if (entry.expired) return;
    if (entry.admin) {
      entities.admin = true;
      notes.push('registration entry ' + entry.id + ' is marked admin');
    }
    if (entry.downstream) {
      entities.downstream = true;
      notes.push('registration entry ' + entry.id + ' is marked downstream');
    }
  });
  if (spiffeId.isAgentId(id)) {
    const agent = registry.agentById(id);
    if (!agent) {
      notes.push('the id is agent-shaped but no agent by that name has ' +
                 'attested here');
    } else if (agent.banned) {
      // Not an agent for authorization purposes, and the note says so rather
      // than leaving a refusal that reads as "you are not an agent".
      notes.push('that agent is BANNED on this server');
    } else {
      entities.agent = true;
      notes.push('attested agent, last seen ' + (agent.attestedAt || 'unknown'));
    }
  }
  log.debug('Leaving classify(). ' + JSON.stringify(entities));
  return { entities: entities, notes: notes };
}

// ---------------------------------------------------------------------------
// THE CALLER. One object, built once per call, carried through the wrappers.
//
// Built for BOTH surfaces even though only one authorizes on it, because the
// Workload API needs the transport and the endpoint to derive its selectors and
// because `/admin/spiffe` reports the same shape for both.
// ---------------------------------------------------------------------------
function callerOf(call, surface) {
  log.debug('Entering callerOf(). surface=' + surface);
  const transport = transportOf(call);
  const caller = {
    surface: surface,
    transport: transport,
    peer: peerOf(call),
    spiffeId: '',
    authenticated: false,
    entities: { local: false, agent: false, admin: false, downstream: false },
    notes: [],
    certificate: null,
    refusal: ''
  };
  // The local entity. It is a property of the TRANSPORT and not of a
  // credential, which is why it is set before anything is read off a
  // certificate: a caller on the socket is local whether or not it also
  // presented an SVID, exactly as `spire-server` is.
  if (transport === 'uds' && trustLocalSocket()) {
    caller.entities.local = true;
    caller.notes.push('arrived on the Unix domain socket, which this server ' +
                      'trusts as local (spiffe.trustLocalSocket)');
  } else if (transport === 'uds') {
    caller.notes.push('arrived on the Unix domain socket, which is NOT ' +
                      'trusted as local here (spiffe.trustLocalSocket is off)');
  }
  const certificate = peerCertificateOf(call);
  if (!certificate) {
    log.debug('Leaving callerOf(). No certificate was presented.');
    return caller;
  }
  // ---------------------------------------------------------------------
  // `subject` AND `issuer` ARE OBJECTS WITH A NULL PROTOTYPE, and that cost a
  // debugging session. Node builds a `PeerCertificate`'s name fields with
  // `Object.create(null)`, so `String(cert.subject)` does not produce
  // "[object Object]" — it THROWS `Cannot convert object to primitive value`,
  // inside a gRPC handler, where it surfaces to the client as a generic
  // "server method handler threw error" naming neither the field nor this
  // file. `dnRfc4514()` renders them properly and is the same function
  // `tls_server.js` and `scim_auth.js` use.
  // ---------------------------------------------------------------------
  caller.certificate = {
    subject: tls.dnRfc4514(certificate.subject),
    issuer: tls.dnRfc4514(certificate.issuer),
    serialNumber: String(certificate.serialNumber || ''),
    validFrom: String(certificate.valid_from || ''),
    validTo: String(certificate.valid_to || ''),
    // The DER thumbprint, so that a page and a log line naming "the same
    // certificate" mean the same thing. Node hands `fingerprint256` back
    // colon-separated and upper case, which is a different string from every
    // other thumbprint in this service; it is left as node produced it and
    // named for what it is rather than being converted into a fourth spelling.
    fingerprintSha256: String(certificate.fingerprint256 || '')
  };
  const identity = spiffeIdFromCertificate(certificate);
  if (!identity.ok) {
    caller.refusal = identity.reason;
    caller.notes.push(identity.reason);
    log.debug('Leaving callerOf(). The certificate names no SPIFFE ID.');
    return caller;
  }
  const verified = verifyPresentedCertificate(certificate, identity.id);
  if (!verified.ok) {
    caller.refusal = verified.reason;
    caller.notes.push(verified.reason);
    // The id is recorded even though the certificate did not verify, because a
    // refusal naming the identity somebody CLAIMED is the one a client author
    // can act on. Nothing downstream reads it — `authenticated` is false.
    caller.claimedSpiffeId = identity.id;
    log.debug('Leaving callerOf(). The certificate did not verify.');
    return caller;
  }
  caller.spiffeId = identity.id;
  caller.authenticated = true;
  caller.trustDomain = verified.trustDomain;
  const classified = classify(identity.id);
  Object.keys(classified.entities).forEach(function (key) {
    if (classified.entities[key]) caller.entities[key] = true;
  });
  caller.notes = caller.notes.concat(classified.notes);
  log.debug('Leaving callerOf(). ' + identity.id + ' verified.');
  return caller;
}

// A one-line description, used in refusals, in the audit row and on the pages.
// One function so that three surfaces cannot describe the same caller three
// ways.
function describeCaller(caller) {
  if (!caller) return 'an unknown caller';
  const held = ENTITY_ORDER.filter(function (id) { return caller.entities[id]; });
  const who = caller.authenticated ? caller.spiffeId
    : (caller.claimedSpiffeId ? 'an unverified ' + caller.claimedSpiffeId
                              : 'an anonymous caller');
  return who + ' over ' + (caller.transport === 'uds' ? 'the Unix socket' : 'TCP') +
         (held.length ? ' (' + held.join(', ') + ')' : ' (no entity)');
}

// ---------------------------------------------------------------------------
// THE DECISION. Returns null to allow, or a descriptor to refuse.
//
// It never builds a gRPC error — see the header. `status` is the NAME of a
// grpc-js status and `spiffe_grpc.js` maps it, so this module needs no require
// into the transport and cannot join a cycle with it.
// ---------------------------------------------------------------------------
function authorize(caller, method) {
  log.debug('Entering authorize(). method=' + method);
  if (!authRequired()) {
    log.debug('Leaving authorize(). spiffe.authRequired is off.');
    return null;
  }
  const row = POLICY[method];
  if (!row) {
    // See the note on POLICY: no row means refuse. It is a defect in this
    // service rather than in the call, so it is logged as one and the message
    // says so — a client author must not spend an afternoon on it.
    log.error('spiffe: ' + method + ' has no row in spiffe_auth.js\'s POLICY ' +
              'table, so it is refused. That is a defect in this service: ' +
              'every method needs a row, copied from SPIRE\'s ' +
              'policy_data.json.');
    log.debug('Leaving authorize(). No policy row.');
    return { status: 'PERMISSION_DENIED',
             message: method + ' has no authorization rule in this service, ' +
                      'so it is refused rather than allowed. That is a bug ' +
                      'here rather than a problem with your call — please ' +
                      'report it.' };
  }
  if (row.any) {
    log.debug('Leaving authorize(). The method is open.');
    return null;
  }
  const allowed = ENTITY_ORDER.filter(function (id) { return row[id]; });
  for (let i = 0; i < allowed.length; i++) {
    if (caller.entities[allowed[i]]) {
      log.debug('Leaving authorize(). Allowed as ' + allowed[i] + '.');
      return null;
    }
  }
  // UNAUTHENTICATED when nothing was presented, PERMISSION_DENIED when
  // something was and it is not enough. The two are genuinely different
  // instructions to a client — "authenticate" and "you may not" — and SPIRE
  // distinguishes them; collapsing them sends a client that needs a credential
  // off to look for a permission it will never get.
  const nothingPresented = !caller.authenticated && !caller.certificate &&
                           !caller.entities.local;
  const reason = method + ' is allowed to: ' + allowed.join(', ') +
    '. This call came from ' + describeCaller(caller) + '.' +
    (caller.refusal ? ' The certificate presented was not accepted: ' +
                      caller.refusal : '') +
    ' The rule is SPIRE\'s own — see GET /spiffe for the whole table — and ' +
    'spiffe.authRequired turns all of it off.';
  log.debug('Leaving authorize(). Refused.');
  return { status: nothingPresented ? 'UNAUTHENTICATED' : 'PERMISSION_DENIED',
           message: reason };
}

// ---------------------------------------------------------------------------
// RECORDING THE IDENTITY — the second half of what this file is for.
//
// A credential that was PRESENTED AND ACCEPTED reaches
// `stats.recordAuthentication()`, which is the single funnel every one of the
// fifteen other families passes through, and the directory's observer creates
// or REUSES one entry for it. So an SVID presented here puts its holder on
// /admin/users beside everybody else, and a second presentation of the same
// identity lands on the same entry rather than a new one.
//
// **ONCE PER CONNECTION, NOT ONCE PER CALL.** The credential is the client
// certificate and it was accepted at the TLS handshake; a caller that then
// makes six RPCs on that connection has authenticated once. That is the same
// decision `tls_server.js` made deliberately about its own listeners, and
// counting per call would undo it from the other end. The key is the
// certificate's thumbprint and the peer address together — a TCP peer's
// ephemeral port differs per connection, so the pair is a connection.
//
// Bounded, like everything else held here, and FIFO: forgetting the oldest
// costs one duplicate row on a long-lived connection, where forgetting nothing
// is a map that grows for the life of the process.
// ---------------------------------------------------------------------------
const MAX_RECORDED_CONNECTIONS = 512;
const recordedConnections = new Map();

function alreadyRecorded(key) {
  if (!key) return false;
  if (recordedConnections.has(key)) return true;
  recordedConnections.set(key, nowSec());
  if (recordedConnections.size > MAX_RECORDED_CONNECTIONS) {
    const oldest = recordedConnections.keys().next().value;
    recordedConnections.delete(oldest);
  }
  return false;
}

// The one recording function every accepted SPIFFE credential goes through.
// `detail.method` is what was accepted — "X509-SVID (mTLS)", "join token" —
// and it is what shows on /admin/users, so it is written the way a person
// would read it rather than as a code.
function recordIdentity(detail) {
  log.debug('Entering recordIdentity(). presented=' + (detail || {}).presented);
  const info = detail || {};
  if (!info.presented) {
    log.debug('Leaving recordIdentity(). Nothing to record.');
    return;
  }
  if (info.once && alreadyRecorded(info.once)) {
    log.debug('Leaving recordIdentity(). Already recorded for this connection.');
    return;
  }
  try {
    stats.recordAuthentication({
      presented: info.presented,
      protocol: info.protocol || 'SPIFFE',
      method: info.method || 'unstated',
      note: info.note || ''
    });
  } catch (e) {
    // Recording an authentication must never be able to fail one — the rule
    // the observer in ldap_server.js already follows, applied at the caller as
    // well because this one runs inside a gRPC handler where a throw becomes
    // an Unknown status on a call that actually succeeded.
    log.error('spiffe: recording an accepted credential threw and was ' +
              'ignored: ' + e.message);
  }
  log.debug('Leaving recordIdentity().');
}

// The Server API's own recording, called from the wrappers once a caller has
// been built. Only an ACCEPTED credential is recorded: a certificate that did
// not verify is a refusal and belongs in the audit log rather than on
// /admin/users, which answers "who has authenticated here".
function recordCaller(caller) {
  if (!caller || !caller.authenticated || !caller.spiffeId) return;
  const once = (caller.certificate ? caller.certificate.fingerprintSha256 : '') +
               '|' + caller.peer;
  recordIdentity({
    presented: caller.spiffeId,
    protocol: 'SPIFFE',
    method: 'X509-SVID (mTLS)',
    note: describeCaller(caller),
    once: once
  });
}

// ---------------------------------------------------------------------------
// WHAT THE WORKLOAD API CAN SEE ABOUT ITS CALLER.
//
// The selector list. See the header for why these are spelt `transport:`,
// `endpoint:` and `peer:` rather than `unix:` and `k8s:`, and why an asserted
// selector is passed through verbatim while an observed one is not.
// ---------------------------------------------------------------------------
function assertedSelectorsOf(call) {
  log.debug('Entering assertedSelectorsOf().');
  const out = [];
  if (!acceptAssertedSelectors()) {
    log.debug('Leaving assertedSelectorsOf().');
    return out;
  }
  let values = [];
  try {
    values = (call && call.metadata && call.metadata.get(ASSERTED_SELECTOR_KEY)) || [];
  } catch (e) {
    // A call whose metadata is gone. Nothing to read and nothing to report.
    log.debug('assertedSelectorsOf(): the metadata was not readable (' +
              e.message + ').');
    log.debug('Leaving assertedSelectorsOf().');
    return out;
  }
  values.forEach(function (value) {
    // One header may carry several, comma-separated, because a client library
    // that folds repeated metadata keys into one value is ordinary and a
    // caller should not have to know which kind it has.
    String(value).split(',').forEach(function (text) {
      const selector = registry.parseSelector(text);
      if (selector) out.push(selector);
      else if (String(text).trim()) {
        log.warn('spiffe: a caller asserted the selector "' + String(text).trim() +
                 '", which is not `type:value` and was ignored.');
      }
    });
  });
  log.debug('Leaving assertedSelectorsOf().');
  return out;
}

// The address the caller reached, derived from configuration rather than from
// the call. grpc-js tells a handler about the PEER and not about the local end,
// and there is exactly one Workload API socket and one Workload API port — so
// the transport settles which of the two it was. Deriving it beats reading it:
// there is nothing to read.
function endpointFor(surface, transport) {
  if (surface === 'workload') {
    return transport === 'uds'
      ? String(config.value('spiffe.workloadSocket') || '')
      : String(config.value('spiffe.grpcHost') || '') + ':' +
        String(config.value('spiffe.workloadPort') || '');
  }
  return transport === 'uds'
    ? String(config.value('spiffe.serverSocket') || '')
    : String(config.value('spiffe.grpcHost') || '') + ':' +
      String(config.value('spiffe.serverPort') || '');
}

// The peer as a SELECTOR value, which is not the same string as the peer on the
// page. grpc-js builds `address:port` and the port is EPHEMERAL — a new one per
// connection — so a selector carrying it could never be written into a
// registration entry that matches twice. The address alone is the stable,
// matchable fact; the whole peer stays on the caller object, in the log and in
// the audit row, where a reader wants the connection and not the rule.
function peerSelectorValue(peer) {
  return String(peer || '').replace(/:\d+$/, '');
}

function workloadSelectors(call, caller, endpoint) {
  log.debug('Entering workloadSelectors().');
  const where = endpoint || endpointFor('workload', caller.transport);
  const out = [{ type: 'transport', value: caller.transport === 'uds' ? 'uds' : 'tcp' }];
  if (where) out.push({ type: 'endpoint', value: where });
  const address = peerSelectorValue(caller.peer);
  if (address) out.push({ type: 'peer', value: address });
  const asserted = assertedSelectorsOf(call);
  if (asserted.length) {
    log.info('spiffe: a Workload API caller asserted ' + asserted.length +
             ' selector(s) — ' + asserted.map(registry.selectorText).join(' ') +
             '. NOTHING VERIFIED THEM; this is spiffe.acceptAssertedSelectors, ' +
             'which exists so that selector matching can be exercised at all.');
  }
  const all = out.concat(asserted);
  log.debug('Leaving workloadSelectors(). ' + all.length + ' selector(s).');
  return all;
}

// ---------------------------------------------------------------------------
// WHAT THE PAGES DRAW. One shape, read by `GET /spiffe`, by `/admin/spiffe` and
// by the management API, so that three surfaces cannot disagree about what is
// enforced.
// ---------------------------------------------------------------------------
function state() {
  return {
    // The prose lives HERE and not on the pages, for the reason the two
    // discovery documents are built from one object: `GET /spiffe`,
    // `/admin/spiffe` and the management API all draw this, and three
    // explanations of one mechanism is two that will eventually be wrong.
    what: 'The SPIRE Server API only. Its TCP port is mutual TLS: a caller ' +
          'presents an X509-SVID from this trust domain, this service ' +
          'verifies it against the trust bundle and against the ' +
          'certificate\'s own validity window, takes the SPIFFE ID from the ' +
          'URI subjectAltName (never from the subject), classifies it as ' +
          'local, agent, admin or downstream, and authorizes the method ' +
          'against SPIRE\'s own policy_data.json, row for row. Its Unix ' +
          'socket is the `local` entity and needs no credential, which is how ' +
          'the spire-server CLI reaches a real server. The Workload API is ' +
          'deliberately untouched by all of it: its specification says a ' +
          'client MUST NOT be required to authenticate.',
    bootstrapping: 'The TCP port asks for a client certificate and does NOT ' +
          'require one, because AttestAgent is open to a caller with no SVID ' +
          '— an agent has none until that call gives it one. Fetch the bundle ' +
          'from the bundle endpoint, verify this server against it, and ' +
          'attest.',
    identityNote: 'An accepted credential is an IDENTITY here like any other: ' +
          'it reaches the same funnel every one of the sixteen protocol ' +
          'families uses, so its holder appears on /admin/users and gets a ' +
          'directory entry under ou=users — named by a digest, with the ' +
          'identifier on it as `spiffeSubject`, and REUSED when the same ' +
          'identity arrives again by another route. Three acceptances do ' +
          'that: an X509-SVID over mutual TLS (once per connection), an agent ' +
          'attesting, and a JWT-SVID verified at ValidateJWTSVID. AN ISSUANCE ' +
          'IS A FOURTH WAY IN and is not one of those three: every identity ' +
          'this trust domain mints an X509-SVID for gets the same entry, ' +
          'carrying the certificate as the same six `x509*` attributes a ' +
          'verified TLS client certificate writes — ASSIGNED rather than ' +
          'appended, because an SVID is minted afresh every half-lifetime, ' +
          'with `x509svidsIssued` and two timestamps beside them. It is not ' +
          'counted as an authentication, because being issued a credential is ' +
          'not presenting one.',
    credentialStatusNote: 'The entry also records whether the identity may ' +
          'still be issued a credential HERE — `spiffeCredentialStatus`, with ' +
          'a reason beside it. THAT IS NOT A CERTIFICATE STATUS AND NOTHING ' +
          'READS IT BACK: SPIFFE has no revocation, and an SVID already issued ' +
          'verifies against the bundle until it expires whatever the directory ' +
          'says. What it records is the three things that end an identity\'s ' +
          'ability to get a NEW one — its last registration entry deleted, its ' +
          'agent banned, its agent deleted — each of which is reversible and ' +
          'recorded the same way when it is reversed. The entry is never ' +
          'removed.',
    enforced: authRequired(),
    trustLocalSocket: trustLocalSocket(),
    adminIds: adminIds(),
    attestWorkloads: attestWorkloads(),
    acceptAssertedSelectors: acceptAssertedSelectors(),
    assertedSelectorHeader: ASSERTED_SELECTOR_KEY,
    entities: ENTITIES.map(function (entity) {
      return { id: entity.id, label: entity.label, what: entity.what };
    }),
    policy: Object.keys(POLICY).sort().map(function (method) {
      const row = POLICY[method];
      return {
        method: method,
        allow: row.any ? ['any']
          : ENTITY_ORDER.filter(function (id) { return row[id]; })
      };
    })
  };
}

module.exports = {
  ENTITIES: ENTITIES,
  POLICY: POLICY,
  ASSERTED_SELECTOR_KEY: ASSERTED_SELECTOR_KEY,
  authRequired: authRequired,
  trustLocalSocket: trustLocalSocket,
  attestWorkloads: attestWorkloads,
  acceptAssertedSelectors: acceptAssertedSelectors,
  adminIds: adminIds,
  transportOf: transportOf,
  callerOf: callerOf,
  describeCaller: describeCaller,
  authorize: authorize,
  recordIdentity: recordIdentity,
  recordCaller: recordCaller,
  workloadSelectors: workloadSelectors,
  endpointFor: endpointFor,
  peerSelectorValue: peerSelectorValue,
  spiffeIdFromCertificate: spiffeIdFromCertificate,
  verifyPresentedCertificate: verifyPresentedCertificate,
  state: state
};
