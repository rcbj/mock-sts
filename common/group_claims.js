'use strict';
//
// File: group_claims.js
//
// ---------------------------------------------------------------------------
// THE DIRECTORY'S GROUPS, IN A TOKEN.
//
// For anybody who is a member of a group in the embedded LDAP directory, every
// OAuth 2.0 access token, OIDC ID Token, SAML 2.0 assertion and SAML 1.1
// assertion this service issues carries a claim naming those groups. It is
// automatic — there is nothing to tick per user and nothing to tick per set —
// and `groups.claim` turns the whole of it off.
//
// ---------------------------------------------------------------------------
// WHAT THIS DOES NOT CHANGE, AND THE SENTENCE IT DOES CHANGE.
//
// A GROUP HERE STILL GRANTS NOTHING. No endpoint in this service reads this
// claim, nothing decides anything on it, and adding somebody to
// `cn=directory-admins` still does not let them do one thing they could not do
// before. /admin/groups says so and goes on saying so.
//
// TWO GROUPS ARE NOW AN EXCEPTION AND NOT TO THIS SENTENCE. `admin.readGroup`
// and `admin.writeGroup` — `cn=admin-read` and `cn=admin-write` by default —
// decide who may use the ADMIN CONSOLE, and nothing about that reaches here:
// they are put in this claim exactly like any other group a person is in, and
// no endpoint reads the claim to find them. A client that saw `admin-write` in
// an access token and concluded the token could do something would be making
// precisely the mistake the paragraph above is about. See `admin-ui/admin_rbac.js`.
//
// What stopped being true is the OTHER half of that sentence, which used to run
// "...and no token carries a group from this directory". One now can. The two
// are different claims and merging them is the mistake to avoid — it is the
// same distinction this service already draws between an identity being
// RECORDED and an identity being AUTHENTICATED (a verified TLS client
// certificate, a presentation that verifies at the OID4VP Verifier). Carrying
// a fact is not acting on it.
//
// Why it is worth carrying at all: a groups claim is one of the two or three
// things a relying party actually branches on, and until now there was no way
// to produce one here. A client whose authorization code has never seen a
// `groups` member, or has only ever seen names where the next identity provider
// will send DNs, has never run that code. That is the whole value of this
// service, and `groups.claimValue` exists so both shapes are reachable.
//
// ---------------------------------------------------------------------------
// SIX THINGS ARE LOAD-BEARING.
//
// **It is a LIBRARY (rule 3) and it registers no route**, so its position in
// the require order is not a position at all. It requires `helpers.js`,
// `config.js` and `admin_stats.js`, and none of those requires it back — which
// is what keeps it out of the cycles rule 2 exists for. In particular
// `admin_stats.js` CANNOT require it: this file requires that one (for the four
// set ids, the reserved names and `identityKeyOf()`), so a require in the other
// direction would close a loop and node would hand back a half-initialised
// module whose exports are undefined. The symptom would arrive later and
// somewhere else as something that is not a function.
//
// **So the merge into a token is INVERTED, exactly as `claim_attributes.js`'s
// is.** `admin_stats.js` offers `setGroupResolver()` and this file fills it at
// ITS require time. That is what buys the thing that matters: NO ISSUANCE SITE
// CHANGED. `oauth2.js`'s calls to `stats.jwtClaims()` and the two assertion
// builders' calls to `stats.samlAttributes()` are the lines they always were,
// and the groups claim arrives through them. Four edited call sites would have
// been four that drift and a fifth added later that nobody remembers — the same
// reasoning that keeps `signJwt()` the single token counter.
//
// **AND THE DIRECTORY ARRIVES THROUGH A SECOND SLOT, pointing the other way.**
// The membership can only be answered by `ldap_server.js`, which is the LAST
// module `server.js` requires (rule 6): requiring it from here would drag every
// `/ldap` route to the front of the express router that `/admin/sts-metadata`
// is built by walking. So this file offers `setDirectory()` and that one fills
// it, the same shape `vc_claims.js` and `applications.js` already have.
//
// **THE CLAIM IS OMITTED ENTIRELY FOR SOMEBODY IN NO GROUP.** Not an empty
// array — absent. That is what makes `groups.claim` defensible as ON by
// default: on a fresh start the only people in a group are the ones the
// directory seeds, so a caller who has never touched `ou=groups` gets the
// tokens it got before this file existed. An empty array would be a new member
// in every token every existing client parses, which is the upgrade this
// repository's claim-attribute selection defaults to nothing to avoid.
//
// **THE MEMBERSHIP IS READ PER TOKEN, never cached.** That is the same rule
// `applications.js` follows for the registry and for the same reason: it is
// what makes an `ldapadd` of a member change the very next token, which is the
// thing somebody came here to watch. There is nothing to gain by a cache on a
// mock whose store is a Map in this process.
//
// **A RESERVED NAME IS REFUSED AT ISSUANCE, NOT AT CONFIGURATION TIME.**
// `config.js` requires nothing from this repository — that is deliberate and
// `helpers.js` requires IT — so the reserved list cannot be reached from a
// `check` over there without copying it, and a copied list is one that goes
// wrong. So the refusal is here, it logs, and the token goes out without the
// claim rather than with an `exp` a web form could set. Same rule
// `setClaimSet()` applies to a typed claim, made in the only place that can
// make it.
// ---------------------------------------------------------------------------

const { log } = require('./helpers');
const config = require('./config');
// The four claim sets, the reserved names, the SAML 1.1 default namespace and
// the identity normalisation. This is the module whose slot is filled at the
// bottom of this file, and the dependency runs in this direction only.
const stats = require('./admin_stats');

// ---------------------------------------------------------------------------
// The settings, read PER TOKEN rather than captured here.
//
// All four are `runtime: true` in config.js's table, and a module-level `const`
// is the one thing /admin/config cannot reach — it would fail in the direction
// that looks like the console is broken. So they are functions, the same way
// `maxEntries()` and `clockSkewSeconds()` are.
// ---------------------------------------------------------------------------
function enabled() {
  return !!config.value('groups.claim');
}

function claimName() {
  return String(config.value('groups.claimName') || '').trim();
}

function valueForm() {
  return String(config.value('groups.claimValue') || 'cn').trim();
}

function memberOfCounts() {
  return !!config.value('groups.claimFromMemberOf');
}

// ---------------------------------------------------------------------------
// THE DIRECTORY SLOT. See the header for why the direction is this way round.
//
// One function: groupsOfUser(key), which answers "which groups is this person
// in" for one identity key. What counts as a group, how a member value is
// resolved, and where the containers are stay over there — this module decides
// what to DO with the answer and nothing about what the answer is.
// ---------------------------------------------------------------------------
let directory = null;

function setDirectory(hooks) {
  directory = hooks || null;
  log.debug("A directory was installed; the groups claim can now be read from " +
            "the embedded LDAP directory.");
}

function directoryLoaded() {
  return !!(directory && typeof directory.groupsOfUser === 'function');
}

// Wrapped, for the reason every other directory read in this service is
// wrapped: a store this service consults must never be able to fail the
// issuance it was consulted during. A token missing its groups claim is a bug
// somebody can see and diagnose; a token endpoint returning 500 because an
// entry was mid-write is a bug that looks like the token endpoint.
//
// NO ENTERING/LEAVING PAIR HERE, NOR ON nameProblem() OR valuesFrom(), and the
// omission is deliberate rather than an oversight of the style rule. All three
// run inside groupsOf(), whose own pair already brackets them, and groupsOf()
// runs once per token and twice per assertion — three pairs around one call
// would be most of what the log said about issuing one. It is the same
// judgement admin_stats.js states beside its two resolver wrappers.
function readGroups(username) {
  if (!directoryLoaded()) {
    return null;
  }
  try {
    // Normalised for the reason vc_claims.js's directoryAttributes() gives: the
    // directory files a person under their local name, so an access token's
    // `urn:sts-mock:user:alice` and a Kerberos `alice@REALM` would otherwise
    // look up an entry nothing ever created. identityKeyOf() is the one place
    // that mapping is made, which is what keeps `alice` one person here and one
    // person on /admin/users.
    return directory.groupsOfUser(stats.identityKeyOf(username)) || null;
  } catch (e) {
    log.error('the directory threw while being read for the groups claim and ' +
              'was ignored; the token is issued without it: ' + e.message);
    return null;
  }
}

// ---------------------------------------------------------------------------
// Is the configured name usable?
//
// Returned as a reason string rather than a boolean, because both the console
// and the management API have to be able to SAY why a claim that is switched on
// is not arriving. "It is configured and nothing appears in my token" is the
// single most expensive way for this to fail, and an empty reason is what turns
// it into a support question.
// ---------------------------------------------------------------------------
function nameProblem() {
  const name = claimName();
  if (!name) {
    return 'groups.claimName is empty, so there is no claim to add.';
  }
  if (stats.RESERVED_JWT_CLAIMS.indexOf(name) >= 0) {
    return '"' + name + '" is one of the names this service sets itself (' +
           stats.RESERVED_JWT_CLAIMS.join(', ') + '), so it is refused for ' +
           'the same reason a typed custom claim of that name is: a settable ' +
           '`exp` or `scope` would produce tokens that fail to verify, or ' +
           'change what UserInfo answers, with nothing pointing back at the ' +
           'setting. Choose another groups.claimName.';
  }
  return '';
}

// ---------------------------------------------------------------------------
// THE VALUES.
//
// `via` and `viaMemberOf` come back per group from ldap_server.js and the
// choice between them is made HERE, because it is a policy
// (`groups.claimFromMemberOf`) and that module reports facts. See its
// groupsOfUser() header for why both answers exist at all: nothing in this
// directory maintains `memberOf` from the group's member list or the other way
// round, so a client can create a disagreement in one operation and
// /admin/groups exists partly to show it.
//
// Deduplicated on the VALUE and not on the DN, because two entries can share a
// `cn` — a `groupOfNames` somebody added under `ou=users` and a real one under
// `ou=groups` — and a claim listing `developers` twice is a claim every client
// has to defend against for no reason. First occurrence wins, and the order is
// the directory's own (DN order), so the same directory produces the same claim
// every time rather than one that reshuffles between tokens.
// ---------------------------------------------------------------------------
function valuesFrom(rows, form, useMemberOf) {
  const seen = new Set();
  const out = [];
  (rows || []).forEach(function (row) {
    if (!row.via.length && !useMemberOf) {
      return;
    }
    const value = form === 'dn' ? String(row.dn || '') : String(row.cn || '');
    if (!value || seen.has(value)) {
      return;
    }
    seen.add(value);
    out.push(value);
  });
  return out;
}

// Everything about one person's groups claim, in one object, so that the
// issuance path, the console's preview and the management API's reply are three
// readers of one answer rather than three walks that can disagree. That is the
// same reason claim_attributes.js's previewFor() is built on the function the
// issuance path calls.
function groupsOf(username) {
  log.debug("Entering groupsOf(). user=" + username);
  const out = {
    user: String(username == null ? '' : username),
    key: stats.identityKeyOf(username),
    enabled: enabled(),
    loaded: directoryLoaded(),
    claim: claimName(),
    valueForm: valueForm(),
    memberOfCounts: memberOfCounts(),
    reason: '',
    dn: '',
    entryFound: false,
    groups: [],
    values: []
  };
  if (!out.enabled) {
    out.reason = 'groups.claim is off, so no token or assertion carries a ' +
                 'groups claim.';
    log.debug("Leaving groupsOf(). The feature is off.");
    return out;
  }
  out.reason = nameProblem();
  if (out.reason) {
    log.debug("Leaving groupsOf(). The configured name is unusable.");
    return out;
  }
  if (!out.loaded) {
    out.reason = 'The embedded LDAP directory is not loaded in this process, ' +
                 'so there are no groups to read. Nothing else is affected.';
    log.debug("Leaving groupsOf(). There is no directory.");
    return out;
  }

  const read = readGroups(out.user);
  if (!read) {
    out.reason = 'The directory could not be read; the token is issued ' +
                 'without a groups claim.';
    log.debug("Leaving groupsOf(). The directory read failed.");
    return out;
  }
  out.dn = read.dn;
  out.entryFound = !!read.entryFound;
  out.groups = read.groups;
  out.values = valuesFrom(read.groups, out.valueForm, out.memberOfCounts);
  if (!out.values.length) {
    // Not an error and phrased as one of the two ordinary answers, because it
    // is BY FAR the common one and a reader who sees "reason" filled in assumes
    // something is broken otherwise.
    out.reason = read.groups.length
      ? 'This person is named by ' + read.groups.length + ' group(s), but only ' +
        'through their own memberOf, and groups.claimFromMemberOf is off.'
      : 'This person is in no group here, so the claim is omitted entirely ' +
        'rather than sent as an empty list.';
  }
  log.debug("Leaving groupsOf(). " + out.values.length + " group(s) for " +
            out.dn + ".");
  return out;
}

// Who the token is about. The two kinds of caller spell it differently and
// neither spelling is wrong — oauth2.js's context calls it `username` because
// that is the claim it carries, and the assertion builders call it `subject`
// because that is what a SAML Subject is. Reading both here is one line, and it
// is the same line claim_attributes.js has for the same reason.
function subjectOf(context) {
  const ctx = context || {};
  return String(ctx.username || ctx.subject || '');
}

// ---------------------------------------------------------------------------
// What the two resolver halves hand back.
//
// Both are shaped so an EMPTY answer is the ordinary one — `{}` and `[]` — and
// both go through groupsOf() rather than reading the directory themselves, so
// the console's preview cannot come to disagree with the token.
//
// `setId` is accepted and deliberately unread: all four sets carry the claim,
// because "automatically" is what this feature is for and a per-set selection
// is what /admin/claims already offers for everything that wants one. It stays
// in the signature because the resolver contract has it and because a future
// per-set rule would go here rather than at four call sites.
// ---------------------------------------------------------------------------
function jwtClaimsFor(setId, context) {
  const answer = groupsOf(subjectOf(context));
  if (!answer.values.length) {
    return {};
  }
  const out = {};
  out[answer.claim] = answer.values;
  return out;
}

// A SAML Attribute is multi-valued in both profiles — several <AttributeValue>
// children under one <Attribute> — and that is how this is emitted, through the
// `values` member both builders now understand. The alternative was one
// <Attribute> element per group with the same Name, which is the exact defect
// samlAttributes()'s dedup filter exists to prevent: a relying party reads the
// first and silently sees one group where the person is in four.
function samlAttributesFor(setId, context) {
  const answer = groupsOf(subjectOf(context));
  if (!answer.values.length) {
    return [];
  }
  const attribute = { name: answer.claim, value: answer.values[0],
                      values: answer.values.slice(0) };
  // The same default namespace a typed SAML 1.1 claim gets, for the reason
  // admin_stats.js states beside it: it is the claim namespace every
  // WS-Federation relying party already reads, so an attribute configured with
  // just a name arrives somewhere useful instead of somewhere nothing looks.
  if (setId === 'saml11') {
    attribute.namespace = stats.DEFAULT_SAML11_NAMESPACE;
  }
  return [attribute];
}

// The feature's own state, for /admin/claims and GET /admin-api/claims. Built
// here rather than in admin.js because two surfaces answer it and neither of
// them should be reading the four settings itself.
function state() {
  log.debug("Entering state().");
  const out = {
    enabled: enabled(),
    loaded: directoryLoaded(),
    claim: claimName(),
    valueForm: valueForm(),
    memberOfCounts: memberOfCounts(),
    sets: stats.CLAIM_SET_IDS.slice(0),
    problem: enabled() ? nameProblem() : '',
    // Said in the reply and not only on the page, because it is the sentence a
    // caller is most likely to get wrong about this feature, and the API is
    // read by people who never open the console.
    grants: 'A group here grants nothing. No endpoint in this service reads ' +
            'this claim and nothing decides anything on it; the token merely ' +
            'carries it. The two admin-console roles are the one exception ' +
            'and are not an exception to THIS sentence: they are read from ' +
            'the directory by /admin and never from this claim, so a token ' +
            'carrying admin-write can still do nothing a token without it ' +
            'cannot.',
    precedence: 'A typed claim and a directory attribute of the same name both ' +
                'win over the groups claim.',
    settings: ['groups.claim', 'groups.claimName', 'groups.claimValue',
               'groups.claimFromMemberOf']
  };
  log.debug("Leaving state(). enabled=" + out.enabled);
  return out;
}

// ---------------------------------------------------------------------------
// FILLING THE SLOT.
//
// This is the whole of the installation, and it is why no issuance site
// changed. admin_stats.js calls these two from inside jwtClaims() and
// samlAttributes(), wraps them, and merges what comes back UNDERNEATH both the
// typed claims and the directory attributes — see the note on precedence there.
//
// Done at require time, at module scope, like every other inverted dependency
// here. A process that never loads this module simply has no groups claim,
// which is a smaller service and not a broken one.
// ---------------------------------------------------------------------------
stats.setGroupResolver({
  jwtClaims: jwtClaimsFor,
  samlAttributes: samlAttributesFor
});

log.info('The group claim is loaded: an access token, an ID Token and both ' +
         'SAML assertions will carry "' + claimName() + '" for anybody who is ' +
         'a member of a group in the embedded directory. It is ' +
         (enabled() ? 'ON' : 'OFF') + ' (groups.claim), and the claim is ' +
         'omitted entirely for somebody who is in no group. A group here still ' +
         'grants nothing — no endpoint reads this claim.');

module.exports = {
  setDirectory: setDirectory,
  enabled: enabled,
  claimName: claimName,
  valueForm: valueForm,
  memberOfCounts: memberOfCounts,
  groupsOf: groupsOf,
  jwtClaimsFor: jwtClaimsFor,
  samlAttributesFor: samlAttributesFor,
  state: state
};
