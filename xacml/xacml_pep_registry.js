'use strict';
//
// File: xacml_pep_registry.js
//
// ---------------------------------------------------------------------------
// THE REGISTER OF REMOTE POLICY ENFORCEMENT POINTS, AND `ou=peps` IS IT.
//
// The same arrangement `xacml_store.js` has with `ou=policies`, for the same
// three reasons argued there — persistence in all three modes with no driver
// change, per-realm isolation for free, and `ldapsearch` and
// `/admin/ldap/directory` as inspection tools that already exist. This module
// owns the SCHEMA and the directory functions arrive through `setDirectory()`,
// filled by `ldap/ldap_server.js` at require time.
//
// ---------------------------------------------------------------------------
// WHAT A ROW HERE IS, AND THE ONE THING IT IS NOT.
//
// It is a record that some other process is enforcing this service's policy,
// what it last pulled, and how to reach it. **IT IS NOT A PERMISSION.** A PEP
// that never registers can still pull `GET /xacml/pep/policies` and enforce
// perfectly, because that endpoint authenticates nobody for the reason
// `xacml.js` gives at length: a policy is a RULE, and a rule nobody can read
// is a rule nobody can check. Registering buys two things and neither is
// access — a row on the console saying this PEP exists and whether it is
// current, and an address for the nudge.
//
// That is worth stating plainly because the shape looks like an authorization
// register and is not one. If a future change makes registration a
// precondition for pulling policy, that is a different feature with a
// different argument, and the argument would have to be made rather than
// inherited from the fact that this file exists.
//
// ---------------------------------------------------------------------------
// ONE CERTIFICATE IS ONE ENTRY.
//
// The entry is NAMED from the client certificate, through
// `certificatePlan()`'s naming rule — which arrives across the slot rather
// than being reimplemented here, so that a PEP is filed under exactly the name
// this service already gives any identity that arrives holding a certificate.
// A PEP that restarts and re-registers UPDATES its row; it does not add a
// second one.
//
// So two instances of one component sharing a certificate collapse into one
// row, and that is correct rather than a limitation. The question this
// register answers is "which PEPs am I distributing policy to, and are they
// current" — and a nudge sent to either instance is a nudge to that
// deployment. Telling them apart needs certificates of their own, which is
// what telling them apart would need anywhere else in this service too.
//
// **THE ENTRY IS NOT CREATED IN `ou=users`.** `certificatePlan()`'s NAMING is
// reused; its entry creation is not. A PEP is a component rather than a
// person, and an `ou=users` entry per PEP would make `/admin/users` count
// components as people — which is exactly the distinction `spiffe_registry.js`
// had to draw between an ISSUANCE and an AUTHENTICATION, recorded in
// `spiffe/CLAUDE.md`. The DN the naming rule produces is stored as
// `xacmlPepIdentity` so that a PEP whose certificate HAS also signed in
// somewhere can be joined up with that entry by anybody reading either.
//
// ---------------------------------------------------------------------------
// THE SYNC TOKEN IS A DIGEST OF WHAT WOULD BE SENT, NOT A CLOCK.
//
// `syncToken()` hashes the documents of every ENABLED policy plus which one is
// the root — that is, exactly the bytes `GET /xacml/pep/policies` would answer
// with. Three consequences, and the third is the one that made it worth doing
// this way rather than stamping a modification time:
//
//   * a policy edited and edited back to what it was does NOT invalidate
//     anybody's copy, because the repository genuinely did not change;
//   * DISABLING a policy changes the token, because a disabled policy is not
//     sent and the PEP's copy is therefore wrong;
//   * a change made through ANY door moves it — the console, `/admin-api`, an
//     `ldapmodify` on 389, an LDIF restore — because the token is computed
//     from the store on the ask rather than maintained by whatever wrote last.
//     A counter incremented by the write path would have been correct for the
//     two doors that remembered to increment it.
//
// A PEP reports the token it last pulled on every heartbeat, so "current" is a
// comparison this service can make rather than a claim the PEP makes about
// itself.
// ---------------------------------------------------------------------------

const crypto = require('crypto');
const { log } = require('../common/helpers');
const config = require('../common/config');
const store = require('./xacml_store');

// ---------------------------------------------------------------------------
// THE SCHEMA. Published on `/admin/ldap/*` the way every other container's is,
// because this directory is schemaless and a container of entries carrying
// invented attributes needs to say what they mean somewhere.
// ---------------------------------------------------------------------------
const SCHEMA = {
  objectClasses: [
    { name: 'xacmlPep',
      what: 'One remote Policy Enforcement Point that has registered with ' +
            'this Policy Decision Point. THE ROW IS A RECORD AND NOT A ' +
            'PERMISSION — a PEP that never registers can still pull the ' +
            'repository and enforce. What a row buys is a place on the ' +
            'console and an address for the change nudge.' }
  ],
  attributes: [
    { name: 'xacmlPepIdentity',
      what: 'The DN certificatePlan() names this certificate\'s identity ' +
            'with. NO ENTRY IS CREATED THERE by a registration — the naming ' +
            'rule is reused, not the entry creation, because a PEP is a ' +
            'component and ou=users counts people.' },
    { name: 'xacmlPepCertificateSubject',
      what: 'The full subject of the client certificate the registration ' +
            'arrived on. Held whole beside the DN because the DN is the LEAF ' +
            'and this is what was actually presented.' },
    { name: 'xacmlPepThumbprint',
      what: 'RFC 8705 x5t#S256 of that certificate — the SHA-256 of its DER, ' +
            'base64url. The same computation the token endpoint binds a ' +
            'certificate-bound access token with, through the same function, ' +
            'so the two spellings cannot drift.' },
    { name: 'xacmlPepAuthenticated',
      what: '"TRUE" when the registration arrived on a connection carrying a ' +
            'client certificate, "FALSE" when xacml.pepRequireCertificate ' +
            'was off and it did not. NOT hidden and not conflated: an ' +
            'unauthenticated registration is a row that proved nothing, and ' +
            'the console says so on the row rather than in a footnote.' },
    { name: 'xacmlPepNotifyUrl',
      what: 'Where to POST the change nudge, if the PEP gave one. THE NUDGE ' +
            'IS NEVER THE MECHANISM — a PEP pulls on its own interval and ' +
            'converges without this — so an absent, refused or unreachable ' +
            'URL costs latency and nothing else.' },
    { name: 'xacmlPepBias',
      what: 'The bias the remote PEP reports it is running with. REPORTED BY ' +
            'IT, never set from here: xacml.pepBias governs the EMBEDDED PEP ' +
            'at /xacml/protected and a control that appeared to set a remote ' +
            'one would silently do nothing.' },
    { name: 'xacmlPepResource',
      what: 'What the remote PEP says it is guarding. Free text from the ' +
            'PEP, shown as its own claim about itself.' },
    { name: 'xacmlPepEnabled',
      what: '"TRUE" or "FALSE". A disabled PEP keeps its row and its ' +
            'counters and is not nudged. It does NOT stop enforcing, and the ' +
            'console says so — nothing here can reach into another process ' +
            'and turn it off.' },
    { name: 'xacmlPepRegisteredAt',
      what: 'When this PEP first registered. Kept across a re-registration, ' +
            'because a component that restarts hourly is a fact worth seeing ' +
            'and an entry whose age reset on every restart could never show ' +
            'it.' },
    { name: 'xacmlPepLastSeen',
      what: 'The last heartbeat or pull. xacml.pepStaleAfterS is how long ' +
            'since this before the console says "stale" — which changes ' +
            'nothing this service does, deliberately.' },
    { name: 'xacmlPepSyncToken',
      what: 'The repository digest this PEP last reported holding. Compared ' +
            'against syncToken() to decide whether it is CURRENT, so that ' +
            'being up to date is something this service works out rather ' +
            'than something the PEP asserts.' },
    { name: 'xacmlPepPolicyCount',
      what: 'How many policies the PEP says it loaded from that pull. A ' +
            'count that disagrees with this repository\'s is the signature ' +
            'of a PEP that pulled successfully and then refused a document.' },
    { name: 'xacmlPepDecisions',
      what: 'Decisions the remote PEP reports having MADE, cumulatively. Its ' +
            'own count, in its own process — this service did not see them, ' +
            'and that is the point of a remote PEP.' },
    { name: 'xacmlPepAllowed',
      what: 'How many of those it ALLOWED. Beside the decision count rather ' +
            'than derived from it, because the difference between them is ' +
            'what the bias and the obligation rule actually did.' },
    { name: 'xacmlPepRefused',
      what: 'How many it REFUSED, including Permits refused for an ' +
            'obligation it could not discharge (section 7.2).' },
    { name: 'xacmlPepUndischargeable',
      what: 'How many of those refusals were an undischargeable obligation ' +
            'on a Permit. Counted separately because it is the one ' +
            'enforcement outcome that looks like a bug from the client side ' +
            'and is the specification working.' },
    { name: 'xacmlPepVersion',
      what: 'What the remote PEP says it is. Free text.' },
    { name: 'xacmlPepLastNotify',
      what: 'What happened to the last nudge — the status, or the refusal ' +
            'sentence. THE ONLY PLACE A FAILED NUDGE IS RECORDED, for the ' +
            'reason ssf_streams.js gives about a refused push: it is ' +
            'invisible from the receiving end by definition.' },
    { name: 'description',
      what: 'Whatever the PEP said about itself when it registered.' }
  ]
};

// The directory functions, installed by `ldap/ldap_server.js`.
let directory = null;
let warnedAboutNoDirectory = false;

function setDirectory(fns) {
  log.debug('Entering setDirectory().');
  directory = fns || null;
  log.debug('Leaving setDirectory(). The PEP register ' +
            (directory ? 'has its container.' : 'has none.'));
}

// WHAT IS CURRENTLY INSTALLED, so that a test which stubs the slot can put
// back WHAT WAS THERE rather than `null`. `tests/CLAUDE.md` records why that
// distinction is not pedantry: `run.js` runs every file in one process, so
// this is one reference shared by the whole run, and restoring `null` is only
// correct in a process where `ldap/ldap_server.js` was never loaded — which is
// a fact about the file list rather than about the test. Nothing in the
// service calls this, exactly as nothing calls
// `applications.directoryInstalled()`.
function directoryInstalled() {
  return directory;
}

function haveDirectory() {
  if (directory) {
    return true;
  }
  if (!warnedAboutNoDirectory) {
    warnedAboutNoDirectory = true;
    log.warn('xacml: the embedded directory was never loaded, so there is ' +
             'no ou=peps to register a remote Policy Enforcement Point in. ' +
             'Registration is refused and the register is empty. This is the ' +
             'ordinary state of an in-process test that requires only app.js ' +
             'and one module; it is not a failure, and there is no fallback ' +
             'store, deliberately — a register that quietly lived in memory ' +
             'would list PEPs nobody could find.');
  }
  return false;
}

// ---------------------------------------------------------------------------
// WHAT IDENTITY A CLIENT CERTIFICATE IS.
//
// A passthrough to the slot, and it is a function here rather than a direct
// call from `xacml.js` for one reason: `xacml.js` would then have to know that
// the answer comes from the directory, and the whole arrangement exists so
// that a module which needs a NAME does not acquire a dependency on the
// store that happens to know it. `certificatePlan()` is on the other side.
//
// The SUBJECT is added here rather than crossing the slot, because it is on
// the certificate the caller already holds and does not need looking up.
// ---------------------------------------------------------------------------
function certificateIdentity(certificate) {
  log.debug('Entering certificateIdentity().');
  if (!haveDirectory() || typeof directory.certificateIdentity !== 'function') {
    // NO FALLBACK NAMING RULE, deliberately. Inventing one here would be the
    // second answer to "what identity is this certificate" that the slot
    // exists to prevent, and it would only ever be used in a process with no
    // directory — which is a process with no ou=peps to register into either.
    log.debug('Leaving certificateIdentity(). No directory.');
    return { dn: '', commonName: '', subject: '' };
  }
  // THE SUBJECT STRING COMES ACROSS THE SLOT TOO, rather than being built
  // here from node's subject object. That looks like the slot carrying one
  // thing too many and it is not: node hands back a null-prototype object of
  // RDN types, this service has exactly one function that turns it into a DN
  // (`helpers.dnRfc4514()`), and a second join written here would produce a
  // string that DIFFERED from the one the same certificate writes arriving on
  // 8443 or 636 — which is two identities for one certificate. The other side
  // of the slot has that function; this module does not and should not.
  const named = directory.certificateIdentity(certificate);
  log.debug('Leaving certificateIdentity(). dn=' + named.dn);
  return { dn: named.dn || '', commonName: named.commonName || '',
           subject: named.subject || '' };
}

function staleAfterS() {
  const value = config.value('xacml.pepStaleAfterS');
  return typeof value === 'number' && value > 0 ? value : 300;
}

// ---------------------------------------------------------------------------
// THE SYNC TOKEN. See the header — a digest of what would be SENT.
// ---------------------------------------------------------------------------
function syncToken() {
  log.debug('Entering syncToken().');
  const root = store.root();
  // Sorted by name so that the token is a property of the repository's
  // CONTENT rather than of the order the directory happened to iterate in. A
  // token that changed when nothing had would make every PEP re-pull on every
  // heartbeat and would look exactly like a PEP that cannot hold a copy.
  const parts = store.all().filter(function (row) {
    return row.enabled;
  }).map(function (row) {
    return row.name + ' ' + row.document;
  }).sort();
  parts.push('root ' + (root ? root.name : ''));
  const digest = crypto.createHash('sha256').update(parts.join(''))
                       .digest('base64')
                       .replace(/\+/g, '-').replace(/\//g, '_')
                       .replace(/=+$/, '');
  log.debug('Leaving syncToken(). ' + digest);
  return digest;
}

// ---------------------------------------------------------------------------
// READING. `attributeReader()` is `xacml_store.js`'s, and it is written out
// again here rather than exported from there for one reason: this module
// depends on that one for the repository CONTENT the sync token is computed
// over and for nothing else. Both are eight lines and both exist because LDAP
// attribute names come back LOWER-CASED (RFC 4512), which cost a boot in phase
// two — `xacml/CLAUDE.md` records it as the first of four silent defects.
// ---------------------------------------------------------------------------
function attributeReader(attributes) {
  const lowered = {};
  Object.keys(attributes || {}).forEach(function (key) {
    lowered[key.toLowerCase()] = attributes[key];
  });
  return function (name) {
    return one(lowered[String(name).toLowerCase()]);
  };
}

function one(value) {
  if (Array.isArray(value)) {
    return value.length ? String(value[0]) : null;
  }
  return value === undefined || value === null ? null : String(value);
}

function number(value) {
  const n = parseInt(value, 10);
  return isNaN(n) ? 0 : n;
}

function all() {
  log.debug('Entering all().');
  if (!haveDirectory()) {
    log.debug('Leaving all(). No directory.');
    return [];
  }
  const current = syncToken();
  const now = Date.now();
  const stale = staleAfterS() * 1000;
  const rows = directory.allPeps().map(function (entry) {
    const at = attributeReader(entry.attributes);
    const lastSeen = at('xacmlPepLastSeen') || '';
    const seenAt = lastSeen ? Date.parse(lastSeen) : NaN;
    const token = at('xacmlPepSyncToken') || '';
    return {
      name: entry.name,
      dn: entry.dn,
      identity: at('xacmlPepIdentity') || '',
      certificateSubject: at('xacmlPepCertificateSubject') || '',
      thumbprint: at('xacmlPepThumbprint') || '',
      authenticated: at('xacmlPepAuthenticated') === 'TRUE',
      notifyUrl: at('xacmlPepNotifyUrl') || '',
      bias: at('xacmlPepBias') || '',
      resource: at('xacmlPepResource') || '',
      description: at('description') || '',
      version: at('xacmlPepVersion') || '',
      enabled: at('xacmlPepEnabled') !== 'FALSE',
      registeredAt: at('xacmlPepRegisteredAt') || '',
      lastSeen: lastSeen,
      syncToken: token,
      policyCount: number(at('xacmlPepPolicyCount')),
      decisions: number(at('xacmlPepDecisions')),
      allowed: number(at('xacmlPepAllowed')),
      refused: number(at('xacmlPepRefused')),
      undischargeable: number(at('xacmlPepUndischargeable')),
      lastNotify: at('xacmlPepLastNotify') || '',
      // DERIVED, not stored, and both of them for the same reason: a stored
      // "current" would be a second copy of a comparison, and it would be
      // wrong the moment somebody edited a policy without this row being
      // rewritten.
      current: !!token && token === current,
      stale: !(seenAt > 0) || (now - seenAt) > stale
    };
  });
  log.debug('Leaving all(). ' + rows.length + ' registered PEP(s).');
  return rows;
}

function read(name) {
  log.debug('Entering read(). name=' + name);
  const found = all().filter(function (row) {
    return row.name === name;
  })[0] || null;
  log.debug('Leaving read(). ' + (found ? 'Found.' : 'Not found.'));
  return found;
}

// A PEP name is an entry name, so it follows `xacml_store.js`'s rule for one —
// and it is DERIVED from a certificate rather than typed, which means the
// characters a subject may legitimately hold have to be FOLDED rather than
// refused. A common name of `pep-1.example.com` keeps its dots; a subject with
// a comma or an equals sign in it has them replaced, because those are DN
// syntax and a name carrying them would have to be escaped by every reader
// separately.
function nameFrom(raw) {
  log.debug('Entering nameFrom(). raw=' + raw);
  const folded = String(raw || '').trim().replace(/[^A-Za-z0-9._-]+/g, '-')
                       .replace(/^-+|-+$/g, '').slice(0, 128);
  log.debug('Leaving nameFrom(). ' + folded);
  return folded;
}

// ---------------------------------------------------------------------------
// REGISTERING.
//
// `identity` is what the caller's certificate resolved to and is supplied by
// `xacml.js` rather than computed here — this module has no request, no socket
// and no `certificatePlan()`, and it is a library for exactly that reason.
// ---------------------------------------------------------------------------
function register(record) {
  log.debug('Entering register().');
  const given = record || {};
  if (!haveDirectory()) {
    log.debug('Leaving register(). No directory.');
    return { ok: false, why: 'There is no embedded directory, so there is ' +
                             'nowhere to register a Policy Enforcement ' +
                             'Point.' };
  }
  const name = nameFrom(given.name);
  if (!name) {
    log.debug('Leaving register(). No usable name.');
    return { ok: false,
             why: 'A remote PEP is named from the common name of the client ' +
                  'certificate it registered with, or — when ' +
                  'xacml.pepRequireCertificate is off — from the `name` in ' +
                  'the registration. Neither produced anything usable after ' +
                  'folding to letters, digits, dot, dash and underscore.' };
  }
  const existing = read(name);
  const now = new Date().toISOString();
  const attributes = {
    objectClass: ['top', 'xacmlPep'],
    xacmlPepIdentity: String(given.identity || ''),
    xacmlPepCertificateSubject: String(given.certificateSubject || ''),
    xacmlPepThumbprint: String(given.thumbprint || ''),
    xacmlPepAuthenticated: given.authenticated ? 'TRUE' : 'FALSE',
    xacmlPepNotifyUrl: String(given.notifyUrl || ''),
    xacmlPepBias: String(given.bias || ''),
    xacmlPepResource: String(given.resource || ''),
    xacmlPepVersion: String(given.version || ''),
    // A RE-REGISTRATION KEEPS THE ORIGINAL DATE. A component that restarts
    // every few minutes is a fact somebody wants to see, and a registration
    // date that reset on each restart could never show it.
    xacmlPepRegisteredAt: existing ? existing.registeredAt || now : now,
    xacmlPepLastSeen: now,
    // AND IT KEEPS THE COUNTERS AND THE SYNC TOKEN, which is the same decision
    // read from the other side: a PEP that re-registers has not un-enforced
    // anything, and zeroing its counters would make a restart loop look like a
    // component that has never done any work.
    xacmlPepSyncToken: existing ? existing.syncToken : '',
    xacmlPepPolicyCount: String(existing ? existing.policyCount : 0),
    xacmlPepDecisions: String(existing ? existing.decisions : 0),
    xacmlPepAllowed: String(existing ? existing.allowed : 0),
    xacmlPepRefused: String(existing ? existing.refused : 0),
    xacmlPepUndischargeable: String(existing ? existing.undischargeable : 0),
    xacmlPepLastNotify: existing ? existing.lastNotify : '',
    // ENABLED IS KEPT TOO, and this is the one that would have been a
    // security-shaped mistake to get wrong the other way round: a PEP an
    // administrator disabled must not be able to re-enable itself by
    // reconnecting.
    xacmlPepEnabled: existing && !existing.enabled ? 'FALSE' : 'TRUE'
  };
  if (given.description) {
    attributes.description = String(given.description);
  } else if (existing && existing.description) {
    attributes.description = existing.description;
  }
  const written = directory.writePep(name, attributes);
  if (!written) {
    log.debug('Leaving register(). The directory refused it.');
    return { ok: false,
             why: 'The directory refused the entry. ou=peps may be at its ' +
                  'maximum of ' + config.value('xacml.maxPeps') +
                  ' (xacml.maxPeps).' };
  }
  log.info('xacml: remote PEP "' + name + '" ' +
           (existing ? 're-registered' : 'registered') +
           (given.authenticated
             ? ' with client certificate ' + given.certificateSubject
             : ' WITHOUT a client certificate ' +
               '(xacml.pepRequireCertificate is off)') + '.');
  log.debug('Leaving register(). ' + (existing ? 'Updated.' : 'Created.'));
  return { ok: true, name: name, created: !existing };
}

// ---------------------------------------------------------------------------
// A HEARTBEAT.
//
// **THE COUNTERS ARE SET, NOT ADDED TO**, and that is the opposite of what a
// counter usually wants. A remote PEP reports its own CUMULATIVE totals, so
// adding them here would count every decision once per heartbeat — which
// produces a number that only ever goes up, looks entirely plausible, and is
// wrong by a factor of however often the PEP checks in. A PEP that restarts
// and resets its own counters therefore makes this row go DOWN, which is
// honest: what is shown is what that process has done since it started, which
// is the only thing it can truthfully report.
// ---------------------------------------------------------------------------
function heartbeat(name, report) {
  log.debug('Entering heartbeat(). name=' + name);
  if (!haveDirectory()) {
    log.debug('Leaving heartbeat(). No directory.');
    return { ok: false, why: 'There is no embedded directory.' };
  }
  const existing = read(name);
  if (!existing) {
    log.debug('Leaving heartbeat(). Not registered.');
    return { ok: false,
             why: 'No Policy Enforcement Point is registered as "' + name +
                  '". Register first — POST /xacml/pep/register. A heartbeat ' +
                  'does not create a row, deliberately: a row created by a ' +
                  'heartbeat would carry no certificate, no notify URL and ' +
                  'no registration date, and would be a PEP nobody could ' +
                  'nudge.' };
  }
  const said = report || {};
  const attributes = attributesOf(existing, {
    xacmlPepLastSeen: new Date().toISOString(),
    xacmlPepNotifyUrl: said.notifyUrl === undefined
      ? existing.notifyUrl : String(said.notifyUrl || ''),
    xacmlPepBias: said.bias === undefined
      ? existing.bias : String(said.bias || ''),
    xacmlPepResource: said.resource === undefined
      ? existing.resource : String(said.resource || ''),
    xacmlPepVersion: said.version === undefined
      ? existing.version : String(said.version || ''),
    xacmlPepSyncToken: said.syncToken === undefined
      ? existing.syncToken : String(said.syncToken || ''),
    xacmlPepPolicyCount: String(said.policyCount === undefined
      ? existing.policyCount : number(said.policyCount)),
    xacmlPepDecisions: String(said.decisions === undefined
      ? existing.decisions : number(said.decisions)),
    xacmlPepAllowed: String(said.allowed === undefined
      ? existing.allowed : number(said.allowed)),
    xacmlPepRefused: String(said.refused === undefined
      ? existing.refused : number(said.refused)),
    xacmlPepUndischargeable: String(said.undischargeable === undefined
      ? existing.undischargeable : number(said.undischargeable))
  });
  const written = directory.writePep(name, attributes);
  log.debug('Leaving heartbeat(). ' + (written ? 'Recorded.' : 'Refused.'));
  return written ? { ok: true, name: name, current: syncToken() }
                 : { ok: false, why: 'The directory refused the entry.' };
}

// What happened to the last nudge, written back onto the row. Separate from
// `heartbeat()` because it is this service talking about itself rather than
// the PEP reporting — and because it must not move `lastSeen`: a nudge that
// failed is evidence that the PEP is NOT reachable, and letting it stamp the
// liveness field would make an unreachable PEP look freshly seen.
function recordNotify(name, sentence) {
  log.debug('Entering recordNotify(). name=' + name);
  if (!haveDirectory()) {
    log.debug('Leaving recordNotify(). No directory.');
    return false;
  }
  const existing = read(name);
  if (!existing) {
    log.debug('Leaving recordNotify(). Not registered.');
    return false;
  }
  const written = directory.writePep(name, attributesOf(existing, {
    xacmlPepLastNotify: new Date().toISOString() + ' — ' + String(sentence)
  }));
  log.debug('Leaving recordNotify(). ' + (written ? 'Recorded.' : 'Refused.'));
  return written;
}

function setEnabled(name, on) {
  log.debug('Entering setEnabled(). name=' + name + ' on=' + on);
  if (!haveDirectory()) {
    log.debug('Leaving setEnabled(). No directory.');
    return false;
  }
  const existing = read(name);
  if (!existing) {
    log.debug('Leaving setEnabled(). Not registered.');
    return false;
  }
  const written = directory.writePep(name, attributesOf(existing, {
    xacmlPepEnabled: on ? 'TRUE' : 'FALSE'
  }));
  log.debug('Leaving setEnabled(). ' + (written ? 'Written.' : 'Refused.'));
  return written;
}

// ---------------------------------------------------------------------------
// THE WHOLE ENTRY AS ATTRIBUTES, with an override or two applied.
//
// `writePep()` REPLACES rather than merges — `writePolicy()`'s decision, for
// `writeFederation()`'s reason — so every caller that changes ONE field has to
// hand back all of them. Doing that in one place is what stops the next caller
// silently dropping a counter, which is a failure that would look like a PEP
// that had stopped enforcing.
// ---------------------------------------------------------------------------
function attributesOf(row, overrides) {
  const attributes = {
    objectClass: ['top', 'xacmlPep'],
    xacmlPepIdentity: row.identity,
    xacmlPepCertificateSubject: row.certificateSubject,
    xacmlPepThumbprint: row.thumbprint,
    xacmlPepAuthenticated: row.authenticated ? 'TRUE' : 'FALSE',
    xacmlPepNotifyUrl: row.notifyUrl,
    xacmlPepBias: row.bias,
    xacmlPepResource: row.resource,
    xacmlPepVersion: row.version,
    xacmlPepEnabled: row.enabled ? 'TRUE' : 'FALSE',
    xacmlPepRegisteredAt: row.registeredAt,
    xacmlPepLastSeen: row.lastSeen,
    xacmlPepSyncToken: row.syncToken,
    xacmlPepPolicyCount: String(row.policyCount),
    xacmlPepDecisions: String(row.decisions),
    xacmlPepAllowed: String(row.allowed),
    xacmlPepRefused: String(row.refused),
    xacmlPepUndischargeable: String(row.undischargeable),
    xacmlPepLastNotify: row.lastNotify
  };
  if (row.description) {
    attributes.description = row.description;
  }
  return Object.assign(attributes, overrides || {});
}

function remove(name) {
  log.debug('Entering remove(). name=' + name);
  if (!haveDirectory()) {
    log.debug('Leaving remove(). No directory.');
    return false;
  }
  const removed = directory.deletePep(name);
  log.debug('Leaving remove(). ' + (removed ? 'Removed.' : 'Not there.'));
  return removed;
}

// Every registered PEP that should be nudged: enabled, and holding a URL to
// nudge. NOT filtered on `stale`, deliberately — a PEP that has not been seen
// for an hour is exactly the one a nudge might wake up, and refusing to try
// would turn a latency problem into a permanent one.
function notifiable() {
  log.debug('Entering notifiable().');
  const rows = all().filter(function (row) {
    return row.enabled && row.notifyUrl;
  });
  log.debug('Leaving notifiable(). ' + rows.length + ' PEP(s).');
  return rows;
}

module.exports = {
  SCHEMA: SCHEMA,
  setDirectory: setDirectory,
  directoryInstalled: directoryInstalled,
  certificateIdentity: certificateIdentity,
  syncToken: syncToken,
  staleAfterS: staleAfterS,
  nameFrom: nameFrom,
  all: all,
  read: read,
  register: register,
  heartbeat: heartbeat,
  recordNotify: recordNotify,
  setEnabled: setEnabled,
  remove: remove,
  notifiable: notifiable
};
