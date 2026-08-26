'use strict';
//
// File: user_graph.js
//
// ---------------------------------------------------------------------------
// ONE PERSON, END TO END: everything this service has issued in their name,
// everything that was delegated on their behalf, and every application on the
// other side of both — as ONE graph.
//
// It is a LIBRARY, like `delegation.js` beside it and like `admin_stats.js`,
// `audit.js` and `dpop.js`: it registers no route, so its position in the
// require order does not matter and it cannot be the reason a route is missing.
// `admin.js` renders it at /admin/delegation/user; this file holds the model and
// none of the HTML.
//
// It requires `helpers.js`, `admin_stats.js` and `delegation.js`, and nothing
// requires IT except the console — so it cannot join a cycle and it cannot move
// a route. Rule 3e's test is therefore not reached: no slot is needed, because a
// plain require in the ordinary direction closes nothing.
//
// ---------------------------------------------------------------------------
// WHY THIS IS A FILE AND NOT A `filter()` ON /admin/delegation/map.
//
// The application drill-down next door genuinely is one: `actsForApplication()`
// narrows the acts and `delegation.graph()` draws what is left, because both
// halves of that question live in ONE store. **A person's does not.** The
// delegation register holds acts, and an act is by definition a request that
// carried two credentials; an ordinary sign-in that produced an ID Token is not
// an act and never will be. So the picture somebody actually wants — *what has
// this service done in alice's name* — is a UNION of two registers that have
// never had a reason to know about each other:
//
//   * `delegation.js` — who acted on her behalf, through what, to reach what.
//   * `admin_stats.js` — every JWT signed with her in it, every assertion,
//     ticket, SVID and credential issued to her, and every time she
//     authenticated.
//
// Doing that union in `admin.js` was the alternative and it is the one this
// codebase keeps warning about: the join is a statement about what the two
// stores MEAN — that a token exchange writes a row in both and is one event, that
// a `client_id` on a token and an `application` on a party are the same kind of
// thing, that `identityKeyOf()` is the one spelling of a person — and a renderer
// holding a second opinion about any of that is drift nothing can see. So the
// union is here, in the shape `delegation.graph()` already returns, and the
// console renders what it is handed.
//
// ---------------------------------------------------------------------------
// FIVE DECISIONS ARE JUDGEMENTS RATHER THAN MECHANICS.
//
// **THE GRAPH IS `delegation.graph()`'s SHAPE, EXTENDED — NOT A SECOND SHAPE.**
// Every node and every edge here carries the fields that file's do, so
// `delegation_map.js` draws this picture with no idea that it is different and
// the console's party and relationship tables work unchanged. What is added is
// added: `credentials` and `flows` on a node, `credentials` and `produced` on an
// issuance edge, and two new values of `relation`. A second shape would have
// meant a second renderer, and two renderers agreeing about what a box means is
// a thing that stays true for about a month.
//
// **AN ORDINARY GRANT IS A LINE FROM THE PERSON TO THE APPLICATION, AND ITS
// LABEL IS THE GRANT.** That is the whole of what was asked for and it is worth
// saying why it is drawn where it is: the delegation picture's `acts-for` line
// runs from the initial identity to the intermediary — *this party is acting for
// that person* — and an ordinary authorization code grant is the same sentence
// with nobody in the middle, *this client holds a credential naming that
// person*. Drawing it the same way round means a delegation and a plain sign-in
// LINE UP in one diagram instead of being two pictures on one page. What tells
// them apart is the label and the colour: an issuance line names the grant
// (`Authorization Code grant`, `RFC 6749 §4.1`) and is the console's own indigo,
// because it makes no claim about impersonation or delegation — those are
// properties of a mechanism this line is not.
//
// **AUTHENTICATING IS A LINE TOO, AND IT POINTS THE OTHER WAY.** The person
// signed in TO this service, so the arrow runs into the hexagon and is labelled
// with the family and the method — `the sign-in screen (password + a security
// key)`, `AS-REQ with PA-ENC-TIMESTAMP`, `a federated assertion`. Without it the
// picture would show tokens appearing beside somebody who, as far as the drawing
// went, had never been here; with it the three lines make a sentence. It is the
// **OIDC Authentication Flow** half of the ask, and it is a different fact from
// the grant: `client_credentials` has a grant and no sign-in, and a Kerberos
// AS-REQ is a sign-in with no grant.
//
// **A CREDENTIAL THAT BOTH REGISTERS KNOW ABOUT IS DRAWN ONCE.** An RFC 8693
// token exchange writes a delegation act AND a token record — the same access
// token, seen twice — so the issuance half skips any JWT whose `jti` the
// delegation half has already accounted for. It is deduplicated on the
// IDENTIFIER and nothing else: that is the one thing both registers record about
// the same object, and anything cleverer (matching on a time window, on a
// subject and a kind) would eventually collapse two real credentials into one,
// which is a worse failure than listing one twice. **The Kerberos case therefore
// survives on purpose**: an S4U service ticket is in both registers and has no
// identifier in either — a ticket genuinely has none to quote — so it is drawn
// on both its lines, and the console says which register each line came from
// rather than pretending the overlap is not there.
//
// **AN IDENTITY WITH NO AUTHENTICATION IS STILL A PERSON HERE.** S4U2Self and
// OnBehalfOf name somebody who was not present and proved nothing, and a token
// exchange presents a subject this service may never have seen. `userList()`
// therefore unions the identity register with `delegation.identityList()` and
// marks which side each name came from — because "there is no such person" and
// "somebody was impersonated who has never signed in" are opposite answers to
// the same question, and the second is the one worth finding.
// ---------------------------------------------------------------------------

const { log } = require('./helpers');
const stats = require('./admin_stats');
const delegation = require('./delegation');

// ---------------------------------------------------------------------------
// THE GRANTS AND THE FLOWS, WHICH ARE THE ANSWER TO *WHAT WAS THIS TOKEN
// ISSUED BY*.
//
// **`flow` IS THE STRING `oauth2.js` ALREADY RECORDS, VERBATIM.** Every JWT this
// service signs goes through `signJwt()` with an issuance context, and that
// context carries a `grant` — see `issuanceContext()` in `oauth-oidc/oauth2.js`
// and `recordJwt()` in `admin_stats.js`. Those strings are the identifiers here
// rather than a tidier vocabulary of this file's own, and that is deliberate:
// a table keyed on a prettier name would need a translation, and a translation
// that misses a value fails SILENTLY — the token is listed under a flow nobody
// can filter, or under nothing at all. Keeping the recorded string as the key
// means an unknown one is visibly unknown (see `flowRow()`), which is the same
// choice `delegation.js`'s `recordUnguarded()` makes about a type it does not
// know.
//
// `oidc` is the name OpenID Connect gives the same exchange where it gives it
// one, and it is a separate field rather than being folded into the label
// because they are genuinely two vocabularies for one thing: RFC 6749 has an
// *Authorization Code grant* and OpenID Connect Core has an *Authorization Code
// Flow*, and somebody debugging an OIDC client is looking for the second while
// the token endpoint is answering the first.
//
// **THE HYBRID AND IMPLICIT ROWS ARE THE AUTHORIZATION ENDPOINT'S**, and they
// are the reason this table is not just a list of `grant_type` values: a token
// that came back through the browser was never at the token endpoint at all and
// has no `grant_type` to be named after. `issueAuthorizationResponse()` records
// which of the two it was, and the distinction is worth keeping — hybrid means a
// code came back beside the token, so the SAME sign-on will also produce
// `authorization_code` rows at the token endpoint, and a reader seeing both
// should not conclude there were two sign-ins.
// ---------------------------------------------------------------------------
const FLOWS = [
  { flow: 'authorization_code', protocol: 'OAuth 2.0 / OIDC',
    label: 'Authorization Code grant', oidc: 'Authorization Code Flow',
    spec: 'RFC 6749 §4.1 · OpenID Connect Core 1.0 §3.1',
    browser: true,
    what: 'The client sent the person to /oauth2/authorize, got a code back ' +
          'through the browser and redeemed it at /oauth2/token over a ' +
          'back-channel it authenticated on. The token itself never went ' +
          'through the browser, which is the whole point of the grant.' },
  { flow: 'hybrid (authorization endpoint)', protocol: 'OAuth 2.0 / OIDC',
    label: 'Hybrid Flow — the half returned from the authorization endpoint',
    oidc: 'Hybrid Flow', spec: 'OpenID Connect Core 1.0 §3.3',
    browser: true,
    what: 'The authorization response carried a code AND a token, so this ' +
          'credential came back through the browser while a code went with it. ' +
          'The same sign-on will also show `authorization_code` rows when that ' +
          'code is redeemed — two rows, one sign-in.' },
  { flow: 'implicit', protocol: 'OAuth 2.0 / OIDC',
    label: 'Implicit Flow', oidc: 'Implicit Flow',
    spec: 'RFC 6749 §4.2 · OpenID Connect Core 1.0 §3.2',
    browser: true,
    what: 'The token came back from the authorization endpoint in the ' +
          'fragment, with no code and no call to the token endpoint. RFC 9700 ' +
          'section 2.1.2 says not to use it; this service issues it anyway ' +
          'unless that mode is on, which is what it is for.' },
  { flow: 'refresh_token', protocol: 'OAuth 2.0 / OIDC',
    label: 'Refresh Token grant', oidc: '', spec: 'RFC 6749 §6',
    browser: false,
    what: 'A refresh token was presented for a new access token. The row is ' +
          'filed under the SAME sign-on session as the refresh token that ' +
          'bought it — that link is recorded out of band, because no token ' +
          'here carries a session identifier.' },
  { flow: 'client_credentials', protocol: 'OAuth 2.0',
    label: 'Client Credentials grant', oidc: '', spec: 'RFC 6749 §4.4',
    browser: false,
    what: 'The client asked for a token about ITSELF. There is no person in ' +
          'this grant at all, which is why the identity on such a row is ' +
          'marked as a client rather than as somebody who signed in.' },
  { flow: 'password', protocol: 'OAuth 2.0',
    // The parenthetical is what the diagram drops: `shortType()` in
    // delegation_map.js strips a trailing `(...)` and everything after an em
    // dash, so a label written this way is precise in the tables and fits on a
    // line in the picture. RFC 6749's own name for it is nine characters too
    // long for an edge, and an ellipsis is exactly what a label saying WHICH
    // grant must not have.
    label: 'Password grant (resource owner credentials)', oidc: '',
    spec: 'RFC 6749 §4.3', browser: false,
    what: 'A username and password went straight to the token endpoint. This ' +
          'service checks no password in any grant, so what this row records ' +
          'is that a name was presented and accepted.' },
  { flow: 'token exchange', protocol: 'OAuth 2.0',
    label: 'Token Exchange', oidc: '', spec: 'RFC 8693',
    browser: false, delegating: true,
    // The sentence about it ALSO being a delegation act is deliberately NOT
    // here: the console appends one off the `delegating` marker, and saying it
    // in both places put the same claim in one table cell twice.
    what: 'A subject_token was exchanged for a token about its subject — an ' +
          'impersonation with no actor_token and a delegation with one, which ' +
          'RFC 8693 section 1.1 is explicit are different things.' },
  { flow: 'pre-authorized code', protocol: 'OpenID4VCI',
    label: 'Pre-Authorized Code grant', oidc: '',
    spec: 'OpenID4VCI 1.0 §4.1.1', browser: false,
    what: 'The wallet redeemed a code that came with a Credential Offer, ' +
          'having already identified itself to the issuer some other way. ' +
          'There is no authorization request in this grant.' }
];

const FLOW_IDS = FLOWS.map(function (one) { return one.flow; });

const FLOW_BY_ID = {};
FLOWS.forEach(function (one) { FLOW_BY_ID[one.flow] = one; });

// What a token that states no grant is filed under, and it is a real answer
// rather than a gap. `recordJwt()` fills `grant` from the issuance context and a
// caller that passes none is STATING that there was no grant: WS-Trust's JWT and
// the OID4VCI credential issuer both sign directly, and the signed UserInfo
// response is a reply rather than the product of one. The console prints this
// sentence instead of an empty cell, for the reason /admin/users prints it
// beside the same column.
const FLOW_NOT_STATED = {
  flow: '', protocol: '', label: 'No grant was stated', oidc: '', spec: '',
  browser: false,
  what: 'Whatever minted this said nothing about how. That is true of every ' +
        'JWT signed outside the token endpoint — WS-Trust\'s JWT token type ' +
        'and the credential issuer both sign directly — and of the signed ' +
        'UserInfo response, which is a reply rather than a credential a grant ' +
        'produced.'
};

// ---------------------------------------------------------------------------
// AND THE FAMILIES THAT HAVE NO GRANT AT ALL, WHICH IS MOST OF THIS SERVICE.
//
// A SAML assertion, a Kerberos ticket, an SVID and a verifiable credential are
// issued by protocols that have never heard of an OAuth grant, and the honest
// answer for them is the MECHANISM in their own specification rather than an
// empty cell or a borrowed word. So the "flow" of an artifact is read off its
// kind, which is the only thing `recordArtifact()` records about how it came to
// exist.
//
// **WHAT IS DELIBERATELY NOT GUESSED IS WHICH ENDPOINT MINTED IT.** A SAML 2.0
// assertion here could have come from WS-Trust, from a WS-Federation sign-in or
// from the Web Browser SSO profile, and the artifact register does not say
// which. It could be inferred from a sign-in that happened at about the same
// moment, and that is exactly the kind of inference this console does not make:
// a picture that says `issued by WS-Federation` because a WS-Federation
// sign-in was nearby is a picture that will be confidently wrong on a busy
// service. The authentication lines say which families were used; this line says
// what came out.
// ---------------------------------------------------------------------------
const ARTIFACT_FLOWS = [
  { match: 'SAML 2.0', protocol: 'SAML 2.0', label: 'A SAML 2.0 assertion',
    spec: 'saml-core-2.0-os §2.3',
    what: 'Issued through WS-Trust, through a WS-Federation sign-in response ' +
          'or through the SAML 2.0 Web Browser SSO profile. Which of the three ' +
          'is NOT recorded on the assertion and is deliberately not guessed ' +
          'here.' },
  { match: 'SAML 1.1', protocol: 'SAML 1.1', label: 'A SAML 1.1 assertion',
    spec: 'saml-core-1.1 §2.4',
    what: 'Issued through WS-Trust, through WS-Federation, or through one of ' +
          'the two SAML 1.1 browser profiles at /saml11.' },
  { match: 'Kerberos TGT', protocol: 'Kerberos v5',
    label: 'A ticket-granting ticket (AS-REQ)', spec: 'RFC 4120 §3.1',
    what: 'The KDC answered an AS-REQ. A TGT IS the Kerberos sign-on session ' +
          'and every service ticket below it was bought with one.' },
  { match: 'Kerberos service ticket', protocol: 'Kerberos v5',
    label: 'A service ticket (TGS-REQ)', spec: 'RFC 4120 §3.3',
    what: 'The KDC answered a TGS-REQ for one service. If it was an S4U ' +
          'request it is ALSO a delegation act, and a ticket has no identifier ' +
          'either register could collapse the two on — see this page\'s note.' },
  { match: 'SVID (X.509)', protocol: 'SPIFFE', label: 'An X509-SVID',
    spec: 'SPIFFE X509-SVID',
    what: 'Minted over the Workload API or by the SPIRE Server API. Nothing ' +
          'here attests a workload, and no SVID is revocable anywhere.' },
  { match: 'SVID (JWT)', protocol: 'SPIFFE', label: 'A JWT-SVID',
    spec: 'SPIFFE JWT-SVID',
    what: 'Minted over the Workload API or by the SPIRE Server API, for the ' +
          'audiences named on the row.' },
  { match: 'Credential (', protocol: 'OpenID4VCI',
    label: 'A verifiable credential', spec: 'OpenID4VCI 1.0 §7',
    what: 'Issued from the Credential Endpoint against an access token. ' +
          'Nothing in the values is verified — they are invented, which is ' +
          'what the issuer is for.' }
];

// The row for a recorded grant string. An UNKNOWN one comes back named after
// itself rather than as "no grant stated", which is the distinction that matters
// when somebody adds a grant to `oauth2.js` and forgets this table: the page
// then shows `device_code — not in this console's table`, which is a bug report.
// Collapsing it into the not-stated row would hide the omission behind a
// sentence that is not true of it.
function flowRow(id) {
  const wanted = String(id == null ? '' : id);
  if (!wanted) {
    return FLOW_NOT_STATED;
  }
  if (FLOW_BY_ID[wanted]) {
    return FLOW_BY_ID[wanted];
  }
  log.warn('user_graph: "' + wanted + '" is not one of the grants this file ' +
           'knows (' + FLOW_IDS.join(', ') + '). It is shown named after ' +
           'itself — add a row to FLOWS, or fix the caller that recorded it.');
  return { flow: wanted, protocol: '', label: wanted, oidc: '', spec: '',
           browser: false, unknown: true,
           what: 'Something recorded this grant and this console has no row ' +
                 'for it. That is a gap in FLOWS in common/user_graph.js ' +
                 'rather than anything wrong with the token.' };
}

// The same answer for an artifact, off its kind. `Credential (` is a prefix
// because the kind carries the FORMAT — `Credential (sd-jwt-vc)` — and three
// formats sharing one sentence is right where three specifications would not be.
function artifactFlowRow(kind) {
  const wanted = String(kind == null ? '' : kind);
  const row = ARTIFACT_FLOWS.filter(function (one) {
    return wanted === one.match || wanted.indexOf(one.match) === 0;
  })[0];
  if (row) {
    return row;
  }
  return { match: '', protocol: '', label: wanted || 'An artifact', spec: '',
           what: 'This console has no sentence for that kind of artifact. It ' +
                 'is a row in ARTIFACT_FLOWS in common/user_graph.js that ' +
                 'nobody has written yet.' };
}

// ---------------------------------------------------------------------------
// WHO GOT IT: the application on the other side of a credential.
//
// One function because the four families keep the answer in four different
// fields and a reader of the picture does not care which:
//
//   a JWT          `client_id` — which `recordJwt()` fills from `client_id`,
//                  `azp` or `aud`, so an ID Token names the client it was for
//   an assertion   `audience` — the relying party the AppliesTo or the service
//                  provider asked for
//   a ticket       `service` — the SPN the ticket was cut for. A TGT's is
//                  `krbtgt/REALM`, which is a real answer: the ticket IS to the
//                  ticket-granting service
//   an SVID        `audience` for a JWT-SVID (it has one) and NOTHING for an
//                  X509-SVID, which genuinely has no audience — such a
//                  credential is drawn as a line from this service to the
//                  person, because that is all that happened
//
// A credential with no holder is not an error and must not be drawn as one. The
// empty string is the answer and the caller draws the shorter line.
// ---------------------------------------------------------------------------
function holderOf(record) {
  if (record.family === 'token') {
    return String(record.client_id || '');
  }
  if (record.kind && String(record.kind).indexOf('Kerberos') === 0) {
    return String(record.service || '');
  }
  return String(record.audience || '');
}

// One line of detail worth reading beside a credential, in the vocabulary its
// own family uses. It is one column rather than five mostly-empty ones, which is
// the argument `userArtifactTable()` in admin.js already makes about the same
// four families.
function detailOf(record) {
  const parts = [];
  if (record.family === 'token') {
    if (record.scope) parts.push('scope: ' + record.scope);
    if (record.jkt) parts.push('DPoP-bound');
  }
  if (record.etype) parts.push('enc-type: ' + record.etype);
  if (record.entryId) parts.push('registration entry: ' + record.entryId);
  if (record.serial) parts.push('serial: ' + record.serial);
  if (record.configId) parts.push('configuration: ' + record.configId);
  if (record.signed === false) parts.push('UNSIGNED');
  return parts.join(', ');
}

// ---------------------------------------------------------------------------
// EVERY CREDENTIAL THE ISSUED REGISTER HOLDS FOR ONE PERSON, in one list.
//
// `stats.userDetail()` already answers "their tokens and their artifacts" and
// this is that answer flattened into rows that say the same things about each —
// which is `issuedList()`'s argument one level up, made again for one person
// because that function is not per-user and re-filtering it would walk every
// token in the process to find alice's four.
//
// `skipIdentifiers` is the token-exchange dedupe: the identifiers the delegation
// half of the picture has already drawn. See the header.
// ---------------------------------------------------------------------------
function credentialsFor(detail, skipIdentifiers) {
  log.debug("Entering credentialsFor().");
  const skip = skipIdentifiers || {};
  const out = [];
  let skipped = 0;
  (detail.tokens || []).forEach(function (record) {
    if (record.jti && skip[record.jti]) {
      // Already on a delegation line. Counted rather than dropped silently: the
      // page says how many, because a token the reader can see at
      // /admin/users and cannot find here would otherwise read as a bug.
      skipped++;
      return;
    }
    const flow = flowRow(record.grant);
    out.push({
      at: record.issuedAt,
      family: 'token',
      kind: record.kind,
      identifier: record.jti || '',
      flow: flow.flow, flowLabel: flow.label, flowProtocol: flow.protocol,
      flowSpec: flow.spec, flowOidc: flow.oidc, flowStated: !!record.grant,
      holder: String(record.client_id || ''),
      state: record.state,
      sessionId: record.sessionId || '',
      revocable: !!record.revocable,
      revoked: !!record.revoked,
      detail: detailOf(Object.assign({ family: 'token' }, record)),
      expiresAtMs: record.exp ? record.exp * 1000 : 0
    });
  });
  (detail.artifacts || []).forEach(function (record) {
    const flow = artifactFlowRow(record.kind);
    const family = String(record.kind).indexOf('Kerberos') === 0 ? 'ticket'
                 : String(record.kind).indexOf('SVID') === 0 ? 'svid'
                 : String(record.kind).indexOf('Credential') === 0 ? 'credential'
                 : 'assertion';
    out.push({
      at: record.issuedAt,
      family: family,
      kind: record.kind,
      identifier: record.id || '',
      // An artifact has no grant and this is not the not-stated row: it is the
      // mechanism its own specification names. `flow` stays empty so nothing
      // filters these as though they were grants.
      flow: '', flowLabel: flow.label, flowProtocol: flow.protocol,
      flowSpec: flow.spec, flowOidc: '', flowStated: false,
      holder: holderOf(Object.assign({ family: family }, record)),
      state: record.state,
      sessionId: '',
      revocable: false,
      revoked: false,
      detail: detailOf(Object.assign({ family: family }, record)),
      expiresAtMs: record.expiresAt || 0
    });
  });
  // Newest first, across the families together — the point of one list is that a
  // sign-on which produced an ID Token and a SAML assertion shows both, next to
  // each other, in the order they happened. `issuedList()`'s rule, applied to
  // one person.
  out.sort(function (a, b) { return b.at - a.at; });
  log.debug("Leaving credentialsFor(). " + out.length + " credential(s), " +
            skipped + " already on a delegation line.");
  return { credentials: out, skipped: skipped };
}

// ---------------------------------------------------------------------------
// THE CATALOGUE THE CHOOSER IS BUILT FROM.
//
// Every identity worth offering, which is the UNION of two lists that answer
// different questions — see the fifth decision in the header. `authenticated`
// says whether the identity register has a row (somebody presented a credential
// here) and `delegated` says whether any act names them; a person can be either,
// both, or — the interesting one — only the second.
//
// Sorted most recently active first, which is the order /admin/users itself
// uses. The application chooser sorts busiest first for a reason that does not
// apply here: thirty applications are a topology and the biggest one is usually
// the one somebody wants, where thirty people are a history and the one somebody
// wants is nearly always the one they just drove a client as.
// ---------------------------------------------------------------------------
function userList() {
  log.debug("Entering userList().");
  const byKey = new Map();
  stats.userRows().forEach(function (row) {
    byKey.set(row.key, {
      key: row.key,
      name: row.name,
      // The spelling to show. `forms` is already commonest-first from
      // countedRows(), and the commonest spelling is the one a reader
      // recognises.
      presented: (row.forms[0] && row.forms[0].form) || row.key,
      forms: row.forms.map(function (one) { return one.form; }),
      authenticated: !!row.authenticated,
      isClient: !!row.isClient,
      authentications: row.authentications,
      protocols: row.protocols.map(function (one) { return one.protocol; }),
      tokens: row.tokens,
      artifacts: row.artifacts,
      lastAt: row.lastActivityAt,
      delegated: false,
      acts: 0, issued: 0, refused: 0, chains: 0,
      roles: { initial: 0, intermediary: 0, target: 0 }
    });
  });
  delegation.identityList(delegation.list()).forEach(function (entry) {
    let row = byKey.get(entry.key);
    if (!row) {
      // Named in a delegation and unknown to the identity register. The whole
      // reason this union exists — see the header — so the row is created
      // rather than skipped, with `authenticated: false` saying which side it
      // came from.
      row = {
        key: entry.key, name: entry.key, presented: entry.presented,
        forms: entry.spellings.slice(),
        authenticated: false, isClient: false, authentications: 0,
        protocols: [],
        tokens: { issued: 0, valid: 0, expired: 0, revoked: 0, other: 0 },
        artifacts: 0, lastAt: 0,
        delegated: false,
        acts: 0, issued: 0, refused: 0, chains: 0,
        roles: { initial: 0, intermediary: 0, target: 0 }
      };
      byKey.set(entry.key, row);
    }
    row.delegated = true;
    row.acts = entry.acts;
    row.issued = entry.issued;
    row.refused = entry.refused;
    row.chains = entry.chains;
    row.roles = entry.roles;
    entry.protocols.forEach(function (name) {
      if (row.protocols.indexOf(name) < 0) row.protocols.push(name);
    });
    if (entry.lastAt > row.lastAt) row.lastAt = entry.lastAt;
  });
  const out = Array.from(byKey.values()).sort(function (a, b) {
    return b.lastAt - a.lastAt || a.key.localeCompare(b.key);
  });
  log.debug("Leaving userList(). " + out.length + " identity/identities, " +
            out.filter(function (one) { return one.delegated; }).length +
            " named in a delegation.");
  return out;
}

// ---------------------------------------------------------------------------
// THE PICTURE ITSELF.
//
// It starts as `delegation.graph()`'s answer for the acts naming this person —
// so the delegation half is drawn by the code that owns it, byte for byte the
// same as /admin/delegation/map draws it — and the issuance half is folded on
// top. Nothing here re-derives a delegation edge, which is the property that
// stops the two pictures disagreeing.
//
// The nodes and edges the fold ADDS carry the same fields the delegation ones
// do, plus the three this page needs, and `normaliseNode()` below is what
// guarantees a node from either half answers the same questions. A renderer
// reading `node.credentials` on a node that came out of `delegation.graph()`
// must get 0 rather than `undefined`, or every count on the page is `NaN`.
// ---------------------------------------------------------------------------

// The issuance fields, on a node from either half.
function normaliseNode(node) {
  if (node.credentials === undefined) node.credentials = 0;
  if (!node.flows) node.flows = [];
  if (node.authentications === undefined) node.authentications = 0;
  if (node.isSubject === undefined) node.isSubject = false;
  if (node.isClient === undefined) node.isClient = false;
  if (!node.kinds) node.kinds = [];
  return node;
}

function graphFor(key) {
  log.debug("Entering graphFor(). key=" + key);
  const wanted = String(key == null ? '' : key);
  const all = delegation.list();
  const acts = delegation.actsForIdentity(all, wanted);
  // The delegation half, drawn by delegation.js. An empty list is a legitimate
  // answer and still yields the hexagon with its realm on it, which is why this
  // is called unconditionally.
  const graph = delegation.graph(acts);
  const detail = stats.userDetail(wanted);

  const nodes = new Map();
  graph.nodes.forEach(function (node) { nodes.set(node.id, normaliseNode(node)); });
  const edges = new Map();
  // NORMALISED THE WAY THE NODES ARE, and for the same reason: the console
  // prints `edge.credentials` on every row of the relationship table, and an
  // edge that came out of `delegation.graph()` and was never touched by the fold
  // below — a `reaches` line, a refused chain — must answer 0 rather than
  // `undefined`, or that column reads as a bug on exactly the rows the
  // delegation half contributed.
  graph.edges.forEach(function (edge) {
    if (edge.credentials === undefined) edge.credentials = 0;
    if (!edge.protocols) edge.protocols = [];
    edges.set(edge.id, edge);
  });
  const sts = graph.nodes.filter(function (one) { return one.kind === 'sts'; })[0];

  // What the delegation half has already drawn, so the issuance half does not
  // draw it again. See the fourth decision in the header.
  const drawnIdentifiers = {};
  (graph.tokens || []).forEach(function (token) {
    if (token.identifier) drawnIdentifiers[token.identifier] = true;
  });

  function nodeFor(id, seed) {
    let node = nodes.get(id);
    if (!node) {
      node = normaliseNode({
        id: id, kind: 'party',
        key: '', presented: '', application: '', what: '',
        roles: { initial: 0, intermediary: 0, target: 0 },
        protocols: [],
        // The DELEGATION counters. They stay at zero on a box that only ever
        // received an ordinary token, and that is the honest answer rather than
        // a gap: nothing was delegated through it. The console prints the
        // credential count beside them so the row does not read as empty.
        acts: 0, issued: 0, refused: 0,
        firstAt: 0, lastAt: 0, selfTarget: false, chiefRole: ''
      });
      nodes.set(id, node);
    }
    if (seed) {
      if (seed.key && !node.key) node.key = seed.key;
      if (seed.presented && !node.presented) node.presented = seed.presented;
      if (seed.application && !node.application) node.application = seed.application;
    }
    return node;
  }

  function edgeFor(id, seed) {
    let edge = edges.get(id);
    if (!edge) {
      edge = Object.assign({
        id: id,
        acts: 0, issued: 0, refused: 0, credentials: 0,
        firstAt: 0, lastAt: 0,
        authorizedBy: '', reason: '',
        consumed: [], produced: [],
        skipped: [], chainKey: '', protocols: [],
        protocol: '', type: '', typeLabel: '', mode: '', spec: '',
        policed: false, subject: '', actor: ''
      }, seed);
      edges.set(id, edge);
    }
    if (edge.credentials === undefined) edge.credentials = 0;
    if (!edge.protocols) edge.protocols = [];
    return edge;
  }

  // One credential onto an edge's produced list, folded by kind the way
  // `delegation.js` folds its own — same shape, so `delegationEdgeRow()` in the
  // console reads both without knowing which half it is looking at.
  function foldOnto(edge, credential) {
    let held = edge.produced.filter(function (one) {
      return one.kind === credential.kind;
    })[0];
    if (!held) {
      held = { kind: credential.kind, count: 0, identifiers: [],
               moreIdentifiers: 0, notes: [] };
      edge.produced.push(held);
    }
    held.count++;
    if (credential.identifier) {
      if (held.identifiers.indexOf(credential.identifier) >= 0) {
        // The same credential seen twice, which is not what "more" means.
      } else if (held.identifiers.length < 6) {
        held.identifiers.push(credential.identifier);
      } else {
        held.moreIdentifiers++;
      }
    }
  }

  // THE PERSON. Created whether or not anything is known about them, because a
  // page that answers "nothing has been issued to bob" still has to draw bob —
  // an empty picture is not an answer, which is the argument delegation.js makes
  // about always drawing the hexagon.
  const person = nodeFor(wanted, {
    key: wanted,
    presented: (detail && detail.user.forms[0] && detail.user.forms[0].form) || wanted
  });
  person.isSubject = true;
  // WHETHER THIS IDENTITY IS A CLIENT RATHER THAN A PERSON, carried so the
  // console can draw it as one. Only `client_credentials` sets it — something
  // authenticated under this name and said the client IS the identity — and it
  // is the one case where the subject of this page is not somebody.
  person.isClient = !!(detail && detail.user.isClient);
  if (!person.chiefRole) {
    // Nothing in the delegation register says what they are, so the shape falls
    // to the role — and the subject of this page is a person. Without this the
    // fallback in `delegationNodeLook()` would draw them as a rectangle, since
    // an empty chiefRole is not 'initial'.
    person.chiefRole = 'initial';
  }

  // HOW THEY AUTHENTICATED, one line per protocol family. It is per FAMILY and
  // not per method deliberately: the families are what a reader is looking for
  // (`she signed in over Kerberos and over the browser`), and a line per method
  // would put four parallel arrows between the same two boxes for four spellings
  // of one login screen. The methods are on the line's label and in its tooltip.
  if (detail) {
    detail.user.protocols.forEach(function (family) {
      const edge = edgeFor('signed-in | ' + family.protocol, {
        from: person.id, to: sts.id,
        fromRole: 'subject', toRole: 'issuer',
        relation: 'signed-in',
        protocol: family.protocol,
        // The MECHANISM column of every table on this page reads `typeLabel`,
        // so the methods go there — that column asks "what was this, exactly",
        // and for an authentication the answer is the method.
        typeLabel: family.methods.map(function (one) {
          return one.method + ' ×' + one.count;
        }).join('; '),
        methods: family.methods,
        subject: person.id, actor: person.id
      });
      edge.acts += family.count;
      edge.issued += family.count;
      edge.lastAt = Math.max(edge.lastAt, family.lastAt);
      edge.firstAt = edge.firstAt ? Math.min(edge.firstAt, family.lastAt) : family.lastAt;
      person.authentications += family.count;
      if (person.protocols.indexOf(family.protocol) < 0) {
        person.protocols.push(family.protocol);
      }
    });
  }

  // EVERY CREDENTIAL, AS A LINE TO WHOEVER GOT IT.
  const found = detail ? credentialsFor(detail, drawnIdentifiers)
                       : { credentials: [], skipped: 0 };
  found.credentials.forEach(function (credential) {
    const holderId = credential.holder ? stats.identityKeyOf(credential.holder) : '';
    let holder = null;
    if (holderId && holderId !== person.id) {
      holder = nodeFor(holderId, { application: credential.holder });
      if (!holder.chiefRole) {
        // Same argument as the person's, the other way round: a box that only
        // ever RECEIVED a credential is a target, and a target is drawn as an
        // application.
        holder.chiefRole = 'target';
      }
      holder.credentials++;
      if (holder.kinds.indexOf(credential.kind) < 0) {
        holder.kinds.push(credential.kind);
      }
      if (credential.flowProtocol &&
          holder.protocols.indexOf(credential.flowProtocol) < 0) {
        holder.protocols.push(credential.flowProtocol);
      }
      holder.lastAt = Math.max(holder.lastAt, credential.at);
      holder.firstAt = holder.firstAt ? Math.min(holder.firstAt, credential.at)
                                      : credential.at;
    }
    person.credentials++;
    if (person.kinds.indexOf(credential.kind) < 0) {
      person.kinds.push(credential.kind);
    }
    const flowKey = credential.flow || credential.flowLabel || '(unstated)';
    if (person.flows.indexOf(flowKey) < 0) person.flows.push(flowKey);

    if (holder) {
      if (holder.flows.indexOf(flowKey) < 0) holder.flows.push(flowKey);
      // THE GRANT LINE. Keyed on the flow as well as on the two ends, so a
      // client that used the authorization code grant and then refreshed draws
      // TWO lines — which is the fact worth seeing, and the same decision
      // `delegation.js` makes about putting the chain key in an edge id.
      const edge = edgeFor('grant | ' + flowKey + ' | ' + person.id + ' > ' + holderId, {
        from: person.id, to: holderId,
        fromRole: 'subject', toRole: 'holder',
        relation: 'issued-for',
        // The flow, in the fields every mechanism column already reads. An
        // issuance has no `mode` — impersonation and delegation are properties
        // of a delegation mechanism — and leaving it empty is what keeps this
        // line the console's neutral indigo instead of borrowing a judgement it
        // has no business making.
        type: credential.flow, typeLabel: credential.flowLabel,
        protocol: credential.flowProtocol, spec: credential.flowSpec,
        mode: '', policed: false,
        subject: person.id, actor: holderId
      });
      edge.credentials++;
      edge.lastAt = Math.max(edge.lastAt, credential.at);
      edge.firstAt = edge.firstAt ? Math.min(edge.firstAt, credential.at) : credential.at;
      foldOnto(edge, credential);
      if (credential.flowProtocol && edge.protocols.indexOf(credential.flowProtocol) < 0) {
        edge.protocols.push(credential.flowProtocol);
      }
    }

    if (holder) {
      // AND THE LINE FROM THIS SERVICE, to whoever HOLDS the credential — the
      // same rule delegation.js follows for its own dashed grey line, and
      // DELIBERATELY THE SAME EDGE ID, so an application that both delegated
      // and received an ordinary token has ONE line from the hexagon rather
      // than two saying the same thing about two registers.
      const issued = edgeFor(' sts > ' + holder.id, {
        from: sts.id, to: holder.id,
        fromRole: 'issuer', toRole: 'asker',
        relation: 'issued',
        subject: '', actor: holder.id
      });
      issued.credentials++;
      issued.lastAt = Math.max(issued.lastAt, credential.at);
      issued.firstAt = issued.firstAt ? Math.min(issued.firstAt, credential.at)
                                      : credential.at;
      foldOnto(issued, credential);
      if (credential.flowProtocol && issued.protocols.indexOf(credential.flowProtocol) < 0) {
        issued.protocols.push(credential.flowProtocol);
      }
    } else {
      // NOBODY ELSE HOLDS IT, so there is one line and it must be the one
      // carrying the GRANT. `client_credentials` is the case that forced this:
      // the token is about the client itself, so the holder and the subject are
      // one box, there is no person-to-application line to label, and drawing
      // only the hexagon's grey `issued to` left the picture of a client
      // credentials grant saying nothing about which grant it was — on the page
      // whose whole ask is that the grant be named. An X509-SVID with no
      // audience is the same shape for a different reason.
      //
      // So the line runs FROM the hexagon, is labelled with the flow, and is
      // keyed on it: a client that used two grants gets two lines, which is the
      // same decision the person-to-application line makes.
      const issued = edgeFor('grant | ' + flowKey + ' |  sts > ' + person.id, {
        from: sts.id, to: person.id,
        fromRole: 'issuer', toRole: 'holder',
        relation: 'issued-for',
        type: credential.flow, typeLabel: credential.flowLabel,
        protocol: credential.flowProtocol, spec: credential.flowSpec,
        mode: '', policed: false,
        subject: person.id, actor: person.id
      });
      issued.credentials++;
      issued.lastAt = Math.max(issued.lastAt, credential.at);
      issued.firstAt = issued.firstAt ? Math.min(issued.firstAt, credential.at)
                                      : credential.at;
      foldOnto(issued, credential);
      if (credential.flowProtocol && issued.protocols.indexOf(credential.flowProtocol) < 0) {
        issued.protocols.push(credential.flowProtocol);
      }
      if (person.flows.indexOf(flowKey) < 0) person.flows.push(flowKey);
    }
    sts.credentials = (sts.credentials || 0) + 1;
  });

  graph.nodes = Array.from(nodes.values());
  graph.edges = Array.from(edges.values());
  graph.credentials = found.credentials;
  graph.credentialsOnDelegationLines = found.skipped;
  graph.subject = person.id;
  log.debug("Leaving graphFor(). " + graph.nodes.length + " node(s), " +
            graph.edges.length + " edge(s), " + found.credentials.length +
            " credential(s) from the issued register, " + acts.length +
            " delegation act(s).");
  return { graph: graph, acts: acts, credentials: found.credentials,
           skipped: found.skipped };
}

// ---------------------------------------------------------------------------
// EVERYTHING ONE PAGE NEEDS ABOUT ONE PERSON, in one call.
//
// `null` when the identity is in neither register, which the console draws as
// the chooser rather than as a 404 — /admin/logout's rule and the application
// page's, for the same reason: this is a lookup, and arriving with nothing
// selected (or with a name nothing has happened to) is how somebody gets here
// from a bookmark.
// ---------------------------------------------------------------------------
function activityFor(key) {
  log.debug("Entering activityFor(). key=" + key);
  const wanted = String(key == null ? '' : key);
  if (!wanted) {
    log.debug("Leaving activityFor(). Nothing was asked for.");
    return null;
  }
  const catalogue = userList();
  const entry = catalogue.filter(function (one) { return one.key === wanted; })[0] || null;
  if (!entry) {
    log.debug("Leaving activityFor(). Neither register names that identity.");
    return null;
  }
  const built = graphFor(wanted);
  // Which flows this person's credentials actually used, in the order the table
  // above declares them, so the page can explain the ones on the picture and
  // stay silent about the five that are not. It is derived from the credentials
  // rather than counted into a map as they are built, because the same
  // derivation then serves `?format=json` without a second walk.
  const used = [];
  built.credentials.forEach(function (credential) {
    if (!credential.flowStated) {
      return;
    }
    if (used.indexOf(credential.flow) < 0) used.push(credential.flow);
  });
  const flows = FLOWS.filter(function (one) {
    return used.indexOf(one.flow) >= 0;
  });
  const out = {
    key: wanted,
    entry: entry,
    graph: built.graph,
    acts: built.acts,
    credentials: built.credentials,
    // How many were left off the issued half because a delegation line already
    // carries them. The page prints it rather than letting the totals
    // disagree — see the fourth decision in the header.
    onDelegationLines: built.skipped,
    flows: flows,
    counts: {
      credentials: built.credentials.length,
      acts: built.acts.length,
      chains: built.graph.chains,
      authentications: entry.authentications,
      applications: built.graph.nodes.filter(function (node) {
        return node.kind === 'party' && node.id !== wanted;
      }).length
    }
  };
  log.debug("Leaving activityFor(). " + out.counts.credentials +
            " credential(s), " + out.counts.acts + " act(s), " +
            out.counts.applications + " other party/parties.");
  return out;
}

module.exports = {
  FLOWS: FLOWS,
  FLOW_IDS: FLOW_IDS,
  FLOW_NOT_STATED: FLOW_NOT_STATED,
  ARTIFACT_FLOWS: ARTIFACT_FLOWS,
  flowRow: flowRow,
  artifactFlowRow: artifactFlowRow,
  // WHO HOLDS A CREDENTIAL, and one line of detail about it. Exported for
  // `credential_graph.js`, which draws one credential's ancestry and has to put
  // the same party at the end of the same line as this file does — two answers
  // to "whose token is this" would be two pictures of one issuance, on two pages
  // of one console, and the reader comparing them would have no way to tell that
  // from two parties that really are different.
  holderOf: holderOf,
  detailOf: detailOf,
  userList: userList,
  graphFor: graphFor,
  activityFor: activityFor
};
