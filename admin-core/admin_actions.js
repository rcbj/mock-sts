'use strict';
//
// File: admin_actions.js
//
// ===========================================================================
// WHAT THE ADMIN CONSOLE AND THE MANAGEMENT API BOTH DO, WITH NEITHER OF THEM
// IN IT.
//
// Every control on /admin has an operation on /admin-api behind it — rule 7 —
// and until 2026-09-12 the way the two were kept from disagreeing was that
// `mgmt-api/admin_api.js` REQUIRED `admin-ui/admin.js` and called its action
// functions. That worked, and it made the API depend on the console: the
// surface a machine drives sat downstream of the surface a person reads, and
// the console was the home of logic that was never the console's.
//
// **THE FUNCTIONS WERE NEVER THE PROBLEM, WHICH IS THE WHOLE REASON THIS WAS
// CHEAP.** Not one of the thirty touched `req`, `res` or markup: each took a
// parsed body and an actor, called the domain module that owns the change,
// wrote its audit row and returned `{ ok, errors, ... }`. They were already a
// shared logic layer. What was wrong was where they lived. So this file is a
// MOVE and not a rewrite — every function below is the one that was in
// `admin-ui/admin.js`, carrying the comment that argued it, and the behaviour
// is intended to be identical to the line.
//
// ---------------------------------------------------------------------------
// WHAT MAY BE IN THIS FILE, AND WHAT MAY NOT.
//
// MAY: a decision. Validate what was sent, call the domain module that owns
// the change, write the audit row, return a result object.
//
// MAY NOT — and every one of these has an owner already:
//
//   * HTML, or anything that builds it. The console renders; this decides.
//   * `req` or `res`. An action is handed what was parsed and never the
//     request, which is why `applicationsAction(body, protocols)` takes the
//     repeated checkbox values as a PARAMETER rather than reading them:
//     `listField()` is the console's, it sits at the transport edge, and it
//     stays there. That boundary is what made this move possible at all.
//   * A ROUTE. Requiring a module registers its endpoints (rule 1), and this
//     file is required by two modules — so a route here would be registered
//     twice, once from the console and once from the management API. It
//     registers none, and `tests/admin_actions_layer.js` fails if that stops
//     being true.
//   * A SESSION, or anything read from one. The actor arrives in `context`,
//     and `via` says which door it came through.
//
// ---------------------------------------------------------------------------
// WHY THIS IS NOT IN common/, WHICH IS WHERE A SHARED LIBRARY NORMALLY GOES.
//
// Because of what it requires. The domain modules below include `oauth2`,
// `saml2`, `saml11` and `federation`, every one of which REGISTERS ROUTES when
// it is required — so anything that loads this file loads them too. That is
// harmless where this file stands, because the console (18) and the management
// API (19) both come after all of them in the require order, and every one of
// these requires is therefore a cache hit.
//
// It would NOT be harmless from `common/`, which reads as *anything may
// require this, at any point in the order*. The first module to do so from
// position 4 would pull the authorization server and both SAML profiles in
// ahead of themselves, and rule 1 says the require order IS the route order —
// so the symptom would be a handler winning that should not have, somewhere
// else entirely.
//
// **SO THE DIRECTORY IS THE WARNING.** This file may be required at 18 or
// later and nowhere earlier. `tests/admin_actions_layer.js` pins that as well.
//
// ---------------------------------------------------------------------------
// THE SEVEN COLLABORATORS, AND WHY THEY ARE STILL THE CONSOLE'S.
//
// Seven of these actions need something that is filled by a module further
// down the require order: the logout reader, the directory and group writers,
// the three Shared Signals reporters, and the XACML pages. Those are INVERTED
// HOOKS on `admin-ui/admin.js` (rule 3e), filled at require time by
// `ldap/ldap_server.js`, `ssf/ssf.js`, `logout/logout.js` and
// `xacml/xacml_admin.js` — and every one of those fillers, along with every
// sentence of CLAUDE.md that explains why the hook has to exist, names that
// module.
//
// Moving the slots here would have meant editing four fillers and rewriting
// that prose to say something no less true and no more useful. So the slot
// stays where it is, and the console FORWARDS what it was handed into this
// file from inside the setter it already had. One statement, two destinations,
// and a filler that has never heard of this file.
//
// **THAT IS ONE DECIDER WITH TWO CACHES, WHICH IS NOT THE SAME AS TWO ANSWERS
// — and the difference is worth stating because this repository refuses the
// second.** Nothing here is ever assigned from anywhere but the console's own
// setter, so the two cannot drift apart; what would make them two answers is a
// second writer, and `tests/admin_actions_layer.js` asserts that each of the
// seven setters in `admin-ui/admin.js` writes both.
// ===========================================================================

// The helpers this layer reaches for, and no more. `numberWord` builds the
// count in applicationsAction()'s refusal sentence and `signJwt` is reached
// from one action that mints; both were missed on the first pass of this move
// because the destructure they came from in admin-ui/admin.js is spread over
// thirty comment-interleaved lines. The symptom was a 500 with
// `numberWord is not defined` on exactly one refusal path — which is the kind
// of thing only a test that drives the surface can find, and
// tests/vendored/sts_admin_api_operations.js did, on the first run after.
const { log, b64uDecode, signJwt, numberWord } = require('../common/helpers');
const config = require('../common/config');
const credentials = require('../common/credentials');
const realms = require('../common/realms');
const stats = require('../common/admin_stats');
const rbac = require('../admin-ui/admin_rbac');
// THE MODE, for the one product-mode step a realm's creation takes: its
// bootstrap administrator's generated password. A leaf (rule 3).
const mode = require('../common/mode');
const vcClaims = require('../oid4vc/vc_claims');
const vpConfig = require('../oid4vc/vc_verifier_config');
const claimAttributes = require('../common/claim_attributes');
const auditLog = require('../common/audit');
const applications = require('../common/applications');
const spMetadata = require('../saml/sp_metadata');
const saml2 = require('../saml/saml2_sso');
const saml11 = require('../saml/saml11_sso');
const authorizationServers = require('../oauth-oidc/authorization_servers');
// The refresh-token JWE, so a pasted refresh token can be revoked by its jti.
const refreshTokenCrypto = require('../oauth-oidc/refresh_token_crypto');
// RFC 9728 protected resource metadata, for `load-resource-metadata`. A
// library: it registers nothing and requires nothing that reaches back here.
const resourceMetadata = require('../oauth-oidc/protected_resource_metadata');
// RFC 7591 SECTION 2.3 (2026-09-13): a LIBRARY (rule 3) registering no route,
// which signs a software statement as this realm and writes it onto the entry.
const softwareStatement = require('../oauth-oidc/software_statement');
// RFC 8705 (2026-09-13): a TLS client certificate issued TO an application,
// packaged once, and revoked among that application's own. A LIBRARY (rule 3)
// that registers no route.
const tlsClientCertificates = require('../common/tls_client_certificates');
const federation = require('../federation/federation');
const spiffeCa = require('../spiffe/spiffe_ca');
const spiffeRegistry = require('../spiffe/spiffe_registry');
const spiffeIdLib = require('../spiffe/spiffe_id');
const signals = require('../ssf/ssf_receivers');
// WHAT A CREDENTIAL CHANGE SAYS OVER CAEP AND RISC (2026-09-13). A LIBRARY that
// requires only the logger and reads `ssf/ssf.js` out of the require cache when
// an event is due, so requiring it here moves no route — see its header.
const accountSignals = require('../ssf/account_signals');
const oauth2 = require('../oauth-oidc/oauth2');
const appPermissions = require('../common/app_permissions');
const consent = require('../common/consent');
const roles = require('../common/roles');
// THE PASSWORD POLICY REGISTER (2026-09-12). A leaf that registers no route, so
// requiring it here moves nothing; the rules it holds are what both the action
// below and `credentials.setPassword()` ask.
const passwordPolicy = require('../common/password_policy');
// THE ERROR CODES (common/error_codes.js, a leaf). An action has no response to
// mark, so a refusal's code goes on the RESULT, under the same non-enumerable
// Symbol `mark()` writes on a response. JSON.stringify never sees a Symbol key,
// so `/admin-api` sends exactly the bytes it did and the console redirects with
// exactly the sentence it did; whichever surface answers reads the code back
// with `errorCodes.codeOf(result)`. A code is never sent to a client.
const errorCodes = require('../common/error_codes');

// A refusal THIS LAYER decided. Returns the result, so it wraps the literal.
function refused(code, result) {
  log.debug("Entering refused().");
  log.debug("Leaving refused().");
  return errorCodes.mark(result, code);
}

// The code a domain module already put on its own result, in either of the two
// ways one does: the non-enumerable mark, or an `errorCode` member on a result
// that is internal to this layer and never sent (the truststore's is).
function innerCode(result) {
  log.debug("Entering innerCode().");
  if (!result || typeof result !== 'object') {
    log.debug("Leaving innerCode().");
    return '';
  }
  log.debug("Leaving innerCode().");
  return errorCodes.codeOf(result) || String(result.errorCode || '');
}

// A result handed up from the domain module that owns the change. Its own code
// wins, because the owner knows the specific condition; this layer's names only
// the door it came through, and is used only when the owner gave none.
function refusedBy(code, result) {
  log.debug("Entering refusedBy().");
  if (result && result.ok === false) {
    errorCodes.mark(result, innerCode(result) || code);
  }
  log.debug("Leaving refusedBy().");
  return result;
}

// WHAT A CREATE THAT NAMES NO CREDENTIAL GETS (2026-09-12). Declared HERE, in
// the action layer, because the action is what applies it and the require
// between the two halves goes one way, views to actions: `admin_views.js`
// re-exports it for the form that preselects it.
const DEFAULT_CREDENTIAL = 'generate';
const krb5Principals = require('../kerberos/krb5_principals');
// STORED KERBEROS KEYS (2026-09-12). A LIBRARY (rule 3) that registers no
// route, and everything it requires is loaded above this line by the time the
// console reaches it — the principal database and the codec at 15, the
// credential store at 8, the registry and the keystore further up still — so
// this require moves no route and closes no cycle, which is rule 3e's test
// answered NO: a plain require rather than an eighth forwarded collaborator.
const krb5PersonKeys = require('../kerberos/krb5_person_keys');

// ---------------------------------------------------------------------------
// THE SEVEN, AS THE CONSOLE HANDS THEM OVER. See the header: this file does
// not own them and does not ask for them — `admin-ui/admin.js` forwards each
// one from inside the setter the filler already calls. They are `let` and not
// `const` because every one of them is filled AFTER this file is required.
// ---------------------------------------------------------------------------
let logoutReader = null;
let directoryWriter = null;
let groupWriter = null;
let signalsReporter = null;
let caepReporter = null;
let riscReporter = null;
let xacmlPages = null;
// THE EIGHTH, AND THE ONE NOT FILLED BY THE MODULE THAT OWNS IT (2026-09-12):
// the client-certificate truststore, whose array is `tls/tls_server.js`'s and
// whose slot `common/protocol_stack.js` fills. `admin-ui/admin.js`'s
// `setTruststore()` carries the argument.
let truststore = null;

function setLogoutReader(value) {
  log.debug("Entering setLogoutReader().");
  logoutReader = value;
  log.debug("Leaving setLogoutReader().");
}

function setDirectoryWriter(value) {
  log.debug("Entering setDirectoryWriter().");
  directoryWriter = value;
  log.debug("Leaving setDirectoryWriter().");
}

function setGroupWriter(value) {
  log.debug("Entering setGroupWriter().");
  groupWriter = value;
  log.debug("Leaving setGroupWriter().");
}

function setSignalsReporter(value) {
  log.debug("Entering setSignalsReporter().");
  signalsReporter = value;
  log.debug("Leaving setSignalsReporter().");
}

function setCaepReporter(value) {
  log.debug("Entering setCaepReporter().");
  caepReporter = value;
  log.debug("Leaving setCaepReporter().");
}

function setRiscReporter(value) {
  log.debug("Entering setRiscReporter().");
  riscReporter = value;
  log.debug("Leaving setRiscReporter().");
}

function setXacmlPages(value) {
  log.debug("Entering setXacmlPages().");
  xacmlPages = value;
  log.debug("Leaving setXacmlPages().");
}

function setTruststore(value) {
  log.debug("Entering setTruststore().");
  truststore = value;
  log.debug("Leaving setTruststore().");
}

// Both response shapes for a page, chosen by ?format=json. `no-store` on all of
// them: they describe live state, and a cached metrics page is a wrong one.
// `up`, when given, is what upTo() returned for the section this page hangs
// under. Only a drill-down passes it; a section's own list page does not, and
// the JSON answer ignores it either way — a way back up is a property of a page
// a person is reading, and a caller of ?format=json has the URL it asked for.
// ---------------------------------------------------------------------------
// THE CSRF TOKEN GOES INTO EVERY POST FORM THIS SHELL DRAWS (2026-09-06).
// OWASP A01/A08.
//
// **AT THE SHELL AND NOT AT EACH FORM, DELIBERATELY.** This console builds
// something like a hundred and forty forms as inline strings across sixty
// pages, and a scheme that required each author to remember a hidden field is a
// scheme that is one page away from being incomplete for ever — silently, since
// a missing token looks exactly like a page that works. Adding it HERE means a
// page written tomorrow is protected by having been drawn at all.
//
// It is a string rewrite, which is the part worth being uncomfortable about,
// and it is narrow on purpose: it matches the opening tag of a form whose
// method is post and inserts one input directly after it. It cannot match
// anything else, because `<form` with `method="post"` is not a sequence that
// occurs in prose here — and if it ever did, the worst outcome is a stray
// hidden input in a paragraph rather than a missing control.
//
// **A PAGE DRAWN FOR SOMEBODY WITH NO SESSION GETS NO TOKEN AND NEEDS NONE**:
// `checkCsrf()` passes a request with no session, because there is nothing to
// forge on behalf of an anonymous caller. See websecurity.js.
// ---------------------------------------------------------------------------
// THE FIELDS EVERY FORM ON THIS CONSOLE CARRIES THAT ARE NOT SETTINGS.
//
// Several action handlers refuse a field they do not recognise BY NAME rather
// than ignoring it, which is the right behaviour and is why this table has to
// exist: `action` has always been furniture, and since 2026-09-06 so is
// `csrf_token`, which `withCsrf()` puts into every POST form this shell draws.
// Without this the token — added to protect those forms — was refused BY them,
// and the failure read as though the caller had misspelt a setting.
//
// `back` and `from` are here for the same reason: they are how a form says
// where the reader was, and a handler that treated them as settings would
// refuse every button that keeps somebody's place.
const FORM_FURNITURE = {
  action: true,
  csrf_token: true,
  back: true,
  from: true
};

// The jti a caller named, from whichever of the two forms they used. A jti is
// accepted directly, and so is a whole token — because the thing somebody has
// in their hand when they want to invalidate it is the token, not its jti.
//
// The token's SIGNATURE IS NOT VERIFIED here, and that is safe rather than
// sloppy: the only thing read out of it is the jti, which is then looked up in
// this service's own registry. A forged token yields a jti this service never
// issued, and revoking a jti that was never issued invalidates nothing. RFC
// 7009's endpoint does verify, because there the token is the credential being
// presented; here it is merely a way of typing a jti that is 22 characters
// long.
function jtiFrom(target) {
  log.debug("Entering jtiFrom().");
  const text = String(target || '').trim();
  if (!text) {
    log.debug("Leaving jtiFrom(). Nothing was given.");
    return { jti: '', how: 'nothing was given' };
  }
  const parts = text.split('.');
  // AN ENCRYPTED REFRESH TOKEN (2026-09-12) is five parts, and its jti is
  // inside the JWE. Opened with this realm's keys; one that will not open is
  // read as a jti, which matches nothing and says so, rather than being
  // refused.
  if (parts.length === 5) {
    const opened = refreshTokenCrypto.claimsOfIssued(text);
    if (opened && opened.jti) {
      log.debug("Leaving jtiFrom(). Read the jti out of an encrypted refresh " +
                "token.");
      return { jti: String(opened.jti), claims: opened,
               how:
                 'read out of an encrypted refresh token after decrypting it' };
    }
  }
  if (parts.length !== 3) {
    log.debug("Leaving jtiFrom(). Treating it as a jti.");
    return { jti: text, how: 'read as a jti' };
  }
  try {
    const claims = JSON.parse(b64uDecode(parts[1]).toString('utf8'));
    log.debug("Leaving jtiFrom(). Read the jti out of a JWT.");
    return { jti: String(claims.jti || ''), how: 'read out of the JWT ' +
                                                 'payload without verifying it',
             claims: claims };
  } catch (e) {
    // Three dot-separated parts that are not a JWT. Fall back to treating the
    // whole string as a jti rather than refusing: it costs nothing and a jti
    // containing two dots is not forbidden anywhere.
    log.debug("Leaving jtiFrom(). It has three parts but is not a JWT: " +
              e.message);
    return { jti: text, how: 'read as a jti (it looked like a JWT but did ' +
                             'not decode)' };
  }
}

function tokenAction(body) {
  log.debug("Entering tokenAction(). action=" + (body.action || '(none)'));
  const action = String(body.action || '');

  if (action === 'revoke' || action === 'restore') {
    const found = jtiFrom(body.target || body.jti || body.token);
    if (!found.jti) {
      log.debug("Leaving tokenAction(). No jti was given.");
      return refused('STS-ADMIN-0502', { ok: false, errors: ['Give a jti, or ' +
                                   'paste the whole token and the jti will ' +
                                   'be read out of it.'] });
    }
    if (action === 'restore') {
      const was = stats.restore(found.jti);
      log.debug("Leaving tokenAction(). Restored.");
      return { ok: true, jti: found.jti,
               message: was ? 'The token with jti ' + found.jti + ' is no ' +
                              'longer revoked (NON-SPEC — a real ' +
                              'authorization server cannot undo a revocation).'
                            : 'The token with jti ' + found.jti + ' was not ' +
                                'revoked, so nothing changed.' };
    }
    const first = stats.revoke(found.jti, 'the admin console');
    log.debug("Leaving tokenAction(). Revoked.");
    return { ok: true, jti: found.jti,
             message: (first ? 'Revoked ' :
                       'Already revoked: ') + found.jti + ' ' +
                 '(' + found.how +
                      '). Introspection now reports it inactive, UserInfo ' +
                      'refuses it, and it will not refresh.' };
  }

  // ONE ASSERTION, TICKET OR SVID — this service's own position on a credential
  // it cannot recall.
  //
  // **IT CHANGES NOTHING OUT THERE AND THE MESSAGE SAYS SO, EVERY TIME.** That
  // sentence is the whole reason this action can exist without being a lie: a
  // relying party validates a SAML assertion's signature and its Conditions and
  // asks nobody; a Kerberos service decrypts a ticket with a key it already
  // has; an X509-SVID chains to a bundle. None of them will ever ask this
  // service, so the credential goes on working until it expires.
  //
  // What the mark buys is the three things that CAN carry it: a global logout
  // that reports what it disowned, a CAEP Security Event Token to a receiver
  // that subscribed, and SAML Single Logout for an assertion that came from a
  // browser profile. A WS-Trust assertion has neither channel and the mark is
  // all there is — which is exactly why it is worth having.
  //
  // Addressed by `artifact` (the row handle) rather than by the protocol's own
  // identifier, because a Kerberos ticket has none at all.
  if (action === 'revoke-artifact' || action === 'restore-artifact') {
    const handle = String(body.artifact || body.key || '').trim();
    if (!handle) {
      log.debug("Leaving tokenAction(). No artifact was named.");
      return refused('STS-ADMIN-0503', { ok: false, errors: ['Name the ' +
                                   'credential in `artifact`, as the `key` ' +
                                   'on every row of GET /admin-api/tokens ' +
                                   'gives it. It is this service\'s own ' +
                                   'handle rather than the protocol\'s, ' +
                                   'because a Kerberos ticket carries no ' +
                                   'identifier anybody can quote.'] });
    }
    const record = stats.artifactByKey(handle);
    if (!record) {
      log.debug("Leaving tokenAction(). No such artifact.");
      return refused('STS-ADMIN-0504', { ok: false, errors: ['Nothing here ' +
          'is called "' + handle + '" ' +
                                   'any more. Either it was never a ' +
                                   'credential in this register, or it has ' +
                                   'been forgotten to the cap since the page ' +
                                   'naming it was drawn — at which point ' +
                                   'this service has no position on it left ' +
                                   'to state.'] });
    }
    const notReached = ' THE HOLDER HAS NOT BEEN TOLD and cannot be by this ' +
      'action: nothing consults this service when ' +
      'a ' + record.kind + ' is presented, so it ' +
      'goes on working until it expires. What this buys is that a global ' +
      'logout can report it, that CAEP can transmit it to a receiver that ' +
      'subscribed, and that SAML Single Logout can carry it for an assertion ' +
      'issued through a browser profile.';
    if (action === 'restore-artifact') {
      const was = stats.restoreArtifact(record);
      log.debug("Leaving tokenAction(). Restored an artifact.");
      return { ok: true, artifact: handle, kind: record.kind,
               message: was
                 ? 'This service no longer disowns the ' + record.kind + ' ' +
                   (record.id || '(no identifier)') + '. NON-SPEC, like ' +
                                                      'every restore here.'
                 : 'The ' + record.kind + ' was not revoked, so nothing ' +
                                          'changed.' };
    }
    const first = stats.revokeArtifact(record, 'the admin console');
    log.debug("Leaving tokenAction(). Revoked an artifact.");
    return { ok: true, artifact: handle, kind: record.kind,
             revocationReach: 'record-only',
             message: (first ? 'Marked revoked: ' :
                       'Already revoked: ') + record.kind + ' ' +
                      (record.id || '(no identifier)') + '.' + notReached };
  }

  // ONE SET, IN ONE ACT — the button the tokens table draws on a grouped row.
  //
  // It is NOT a new kind of revocation and does not write anywhere new: each
  // revocable member goes through stats.revoke() exactly as its own button
  // would send it, into the same set of revoked jtis RFC 7009's /oauth2/revoke
  // writes to. What it saves is three clicks and, more to the point, the
  // mistake of revoking two of the three and believing the grant is dead — a
  // refresh token left behind mints a new access token, which is the whole
  // reason a set is worth being a row.
  //
  // THE MEMBERS ARE RE-READ HERE and never taken from the form, which is the
  // same rule terminate() follows and for the same reason: a page can be posted
  // an hour after it was drawn, and acting on the list it drew would revoke a
  // jti that has since been forgotten to the cap while missing one issued
  // since. The form carries the set KEY and nothing else.
  if (action === 'revoke-set' || action === 'restore-set') {
    const setKey = String(body.set || body.setKey || '').trim();
    if (!setKey) {
      log.debug("Leaving tokenAction(). No set was given.");
      return refused('STS-ADMIN-0505', { ok: false, errors: ['Give a set, as ' +
                                   'the `setKey` on every row of GET ' +
                                   '/admin-api/tokens names it.'] });
    }
    const set = stats.issuedSetByKey(setKey);
    if (!set) {
      log.debug("Leaving tokenAction(). No such set.");
      return refused('STS-ADMIN-0506', { ok: false, errors: ['Nothing here ' +
          'is called "' + setKey + '" ' +
                                   'any more. Either it was never a set, or ' +
                                   'it has been forgotten to the cap since ' +
                                   'the page this button is on was drawn — ' +
                                   'the registry holds at most ' +
                                   stats.MAX_TOKENS + ' tokens.'] });
    }
    const revocable = set.members.filter(function (
        member) { return member.revocable; });
    if (!revocable.length) {
      // A REFUSAL RATHER THAN A SUCCESS THAT DID NOTHING. It is a narrower case
      // than it was before 2026-09-05, when it covered every assertion, ticket
      // and SVID: those are revocable now — in this service's own record, which
      // is a different claim from being honoured and is why `revocationReach`
      // exists. What is left here is a set holding only credentials with NO
      // HANDLE TO ACT ON, which is the signed UserInfo response and the OID4VP
      // Request Object: no jti, nothing to name.
      log.debug("Leaving tokenAction(). Nothing in the set can be revoked.");
      return refused('STS-ADMIN-0507', { ok: false, setKey: setKey, errors: [
        'Nothing in this set can be revoked. It holds ' + set.kinds.join(', ') +
        ', and none of those carries an identifier to act on — a signed ' +
        'UserInfo response has no jti, and the WS-Trust JWT is signed ' +
        'directly rather than through signJwt(). There is nothing to name in ' +
        'a revocation.'] });
    }
    // EACH MEMBER THROUGH ITS OWN MECHANISM, decided by `revocationReach` and
    // never by the family: a JWT goes into the revoked-jti set that
    // /oauth2/revoke writes to, and an assertion, ticket or SVID is marked in
    // this service's own record and reaches nobody. A set can hold both — a
    // WS-Federation sign-in produces an ID Token AND a SAML assertion — so
    // this cannot be one branch taken once for the whole set.
    let changed = 0;
    let reached = 0;
    let recordOnly = 0;
    revocable.forEach(function (member) {
      let moved;
      if (member.revocationReach === 'record-only') {
        recordOnly += 1;
        const record = stats.artifactByKey(member.key);
        moved = action === 'restore-set'
          ? stats.restoreArtifact(record)
          : stats.revokeArtifact(record,
                                 'the admin console (the whole set ' + setKey +
                                 ')');
      } else {
        reached += 1;
        moved = action === 'restore-set'
          ? stats.restore(member.jti)
          : stats.revoke(member.jti,
                         'the admin console (the whole set ' + setKey + ')');
      }
      if (moved) changed += 1;
    });
    const verb = action === 'restore-set' ? 'restored' : 'revoked';
    log.debug("Leaving tokenAction(). " + verb + " " + changed + " of " +
              revocable.length + " in a set.");
    return { ok: true, setKey: setKey, set: setKey,
             revocable: revocable.length,
             revoked: action === 'restore-set' ? 0 : changed,
             restored: action === 'restore-set' ? changed : 0,
             // HOW MUCH OF THIS ACT ANYBODY OUTSIDE WILL NOTICE, reported as
             // two numbers rather than folded into one: the caller is entitled
             // to know that three of the four credentials it just revoked go on
             // working, and a single count would have hidden it.
             reachedProtocol: reached, recordOnly: recordOnly,
             kinds: revocable.map(function (member) { return member.kind; }),
             message: (changed
               ? (action === 'restore-set' ? 'Restored ' : 'Revoked ') + changed
               : 'Nothing changed: all ' + revocable.length + ' were already ' +
                 verb) +
               ' of the ' + revocable.length + ' revocable credential(s) in ' +
                                               'this set (' +
               revocable.map(function (member) { return member.kind; })
                        .join(', ') + ')' +
               (set.size > revocable.length
                 ? '. The other ' + (set.size - revocable.length) +
                   ' carry no identifier to act on and were left alone.'
                 : '.') +
               (recordOnly
                 ? ' ' + recordOnly + ' of them was marked IN THIS ' +
                   'SERVICE\'S RECORD ONLY — nothing consults this service ' +
                   'when an assertion, a ticket or an SVID is presented, so ' +
                   'those go on working out there until they expire.'
                 : '') };
  }

  if (action === 'revoke-kind') {
    const kind = String(body.kind || '');
    if (stats.REVOCABLE_KINDS.indexOf(kind) < 0) {
      log.debug("Leaving tokenAction(). Not a revocable kind.");
      return refused('STS-ADMIN-0508', { ok: false, errors: ['"' + kind + '" ' +
          'is not a kind that can be revoked. The three are: ' +
                                   stats.REVOCABLE_KINDS.join(', ') + '.'] });
    }
    const count =
        stats.revokeWhere(function (record) { return record.kind === kind; },
                                    'the admin console (every ' + kind + ')');
    log.debug("Leaving tokenAction(). Revoked " + count + " by kind.");
    return { ok: true, revoked: count,
             message: 'Revoked ' + count + ' ' + kind + '(s).' };
  }

  if (action === 'revoke-subject') {
    const subject = String(body.subject || '').trim();
    if (!subject) {
      log.debug("Leaving tokenAction(). No subject was given.");
      return refused('STS-ADMIN-0509', { ok: false, errors: ['Give a subject ' +
          'or a username.'] });
    }
    const count = stats.revokeWhere(function (record) {
      return record.sub === subject || record.username === subject;
    }, 'the admin console (everything for ' + subject + ')');
    log.debug("Leaving tokenAction(). Revoked " + count + " for a subject.");
    return { ok: true, revoked: count,
             message: 'Revoked ' + count + ' token(s) for ' + subject + '.' };
  }

  // The users page's button. It is not the same thing as revoke-subject above,
  // and the difference is the reason it exists: that one matches a `sub` or a
  // `username` EXACTLY, which is what somebody typing into the box on the
  // tokens page means, while a user on the users page is an identity that has
  // been seen under several spellings — `alice`, `urn:uuid:<entryUUID>`,
  // `alice@STS.MOCK`. Revoking "for alice" from that page has to mean all of
  // them, or the page would offer a button that visibly missed half of its own
  // table.
  if (action === 'revoke-user') {
    const key = String(body.user || '').trim();
    if (!key) {
      log.debug("Leaving tokenAction(). No user was given.");
      return refused('STS-ADMIN-0509', { ok: false, errors: ['Give a user, ' +
          'as the users page names them.'] });
    }
    const count = stats.revokeWhere(function (record) {
      return stats.holderKeyOf(record.username, record.sub) === key;
    }, 'the admin console (everything for the user ' + key + ')');
    log.debug("Leaving tokenAction(). Revoked " + count + " for a user.");
    return { ok: true, revoked: count, user: key,
             message: 'Revoked ' + count + ' token(s) for ' + key + ' — ' +
                      'every spelling of that identity, not just the one the ' +
                      'row showed.' };
  }

  if (action === 'revoke-all') {
    const count = stats.revokeWhere(function () { return true; }, 'the admin ' +
        'console (everything)');
    log.debug("Leaving tokenAction(). Revoked everything: " + count + ".");
    return { ok: true, revoked: count,
             message: 'Revoked ' + count + ' token(s) — every access token, ' +
                      'ID Token and refresh token this service has issued ' +
                      'and still remembers.' };
  }

  log.debug("Leaving tokenAction(). Unknown action.");
  return refused('STS-ADMIN-0500',
                 { ok: false, errors: ['Unknown action "' + action + '". ' +
                               'The ten are: revoke, restore, ' +
                               'revoke-artifact, restore-artifact, ' +
                               'revoke-set, restore-set, revoke-kind, ' +
                               'revoke-subject, revoke-user, revoke-all.'] });
}

// THE ONE ACTION, AND IT IS `logout.terminate()` WITH A SELECTION OF ONE.
//
// Not a second implementation of what ending a session means: that function
// re-collects from every family, ends what was named, writes the one audit row
// for the act and reports what it could not end and why — all of which a
// hand-written revoke here would have had to reproduce and would have
// reproduced differently. `/admin/sessions` is a VIEW of that model with a
// button on it.
//
// The `key` comes off the row rather than out of a name box, because
// terminate() is keyed on an identity and the row already knows which one; a
// posted key that names nobody simply ends nothing, and says so.
function sessionsAction(body, opts) {
  log.debug("Entering sessionsAction().");
  if (!logoutReader) {
    log.debug("Leaving sessionsAction(). No logout reader.");
    return refused('STS-ADMIN-0501', { ok: false, errors: [
      'logout/logout.js is not loaded in this process, so there is nothing ' +
      'to end.'] });
  }
  const asked = body || {};
  const action = String(asked.action || '');
  if (action !== 'revoke') {
    log.debug("Leaving sessionsAction(). Unknown action.");
    return refused('STS-ADMIN-0500',
                   { ok: false, errors: ['Unknown action "' + action +
      '". There is one: revoke.'] });
  }
  const key = String(asked.key || '').trim();
  const selected = String(asked.select || '').trim();
  if (!key || !selected) {
    log.debug("Leaving sessionsAction(). Nothing named.");
    return refused('STS-ADMIN-0510', { ok: false, errors: [
      'Both "key" (whose session it is) and "select" (the session id, in the ' +
      'form the sessions list gives it — "session:…", "ldap:…" or ' +
      '"krb5:…@REALM") are needed. GET /admin-api/sessions carries both on ' +
      'every row.'] });
  }
  const result = logoutReader.terminate(key, [selected], {
    actor: (opts && opts.actor) || '',
    by: (opts && opts.by) || 'the sessions page',
    channel: 'http'
  });
  // terminate() reports per row. One row was named, so its sentence IS the
  // answer — and a refusal (a Kerberos row while logout.kerberosSignOut is
  // off, a stale id from a page drawn a minute ago) has to come back as a
  // refusal rather than as a success that did nothing.
  const done = (result.terminated || []).length;
  const unknown = (result.unknown || []).length;
  const said = []
    .concat((result.terminated || []).map(function (
        one) { return one.message; }))
    .concat((result.skipped || []).map(function (one) { return one.message; }))
    .join(' ');
  if (done) {
    log.debug("Leaving sessionsAction(). Ended.");
    return { ok: true, message: said || 'the session was ended',
             result: result };
  }
  log.debug("Leaving sessionsAction(). Nothing was ended.");
  return refused(innerCode(result) || 'STS-ADMIN-0511',
                 { ok: false, result: result, errors: [
    said || (unknown
      ? 'Nothing here is called "' + selected + '" any more. It had already ' +
        'ended, or the list this button came from was drawn before it did.'
      : 'Nothing was ended.') ] });
}

// The action behind every control on this page, and behind
// POST /admin-api/logout/{action}. Four of them, and the two NON-SPEC ones are
// labelled as such wherever they appear — see the header.
function logoutAction(body) {
  log.debug("Entering logoutAction(). action=" + (body.action || '(none)'));
  const action = String(body.action || '');
  const user = String(body.user || body.username || '').trim();
  if (!logoutReader) {
    log.debug("Leaving logoutAction(). No logout reader is installed.");
    return refused('STS-ADMIN-0501', { ok: false, errors: ['The logout ' +
                                 'module is not loaded in this process, so ' +
                                 'there is nothing to end. See ' +
                                 '/admin/logout, which says why.'] });
  }
  if (!user) {
    log.debug("Leaving logoutAction(). No user was named.");
    return refused('STS-ADMIN-0512', { ok: false, errors: ['Name the ' +
                                 'identity to act on in `user`. This page ' +
                                 'always acts on somebody by name — it is ' +
                                 'the operator\'s door, and /logout is the ' +
                                 'one that defaults to whoever is signed ' +
                                 'in.'] });
  }
  const key = stats.identityKeyOf(user);

  if (action === 'global') {
    const result = logoutReader.terminate(key, [], {
      actor: user, channel: 'console', by: 'the admin console at /admin/logout'
    });
    log.debug("Leaving logoutAction(). A global logout ended " +
              result.terminated.length + ".");
    return { ok: true, result: result, message: result.message +
             ' The relying parties that had to be NOTIFIED cannot be reached ' +
             'from here: a front-channel notification is an iframe in the ' +
             'signed-out person\'s browser, and this console is not that ' +
             'browser. /logout is where those load.' };
  }

  if (action === 'end') {
    const raw = body.select === undefined ? [] : body.select;
    const selection = (Array.isArray(raw) ? raw : [raw]).filter(Boolean)
      .map(String);
    if (!selection.length) {
      // Deliberately NOT treated as a global logout here, which is the one
      // place this console departs from /logout's default. A form posting an
      // empty selection is a reader who ticked nothing and pressed a button; a
      // POST to /logout with an empty body is a caller who asked for
      // everything. Same absence, opposite intent, and the difference is which
      // door it arrived at.
      log.debug("Leaving logoutAction(). Nothing was selected.");
      return refused('STS-ADMIN-0513', { ok: false, errors: ['Nothing was ' +
                                   'selected. Use the global logout button ' +
                                   'to end everything — this action ends ' +
                                   'only what it is given, so that an empty ' +
                                   'form cannot sign somebody out of ' +
                                   'everything by accident.'] });
    }
    const result = logoutReader.terminate(key, selection, {
      actor: user, channel: 'console', by: 'the admin console at /admin/logout'
    });
    log.debug("Leaving logoutAction(). Ended " + result.terminated.length +
              ".");
    return { ok: true, result: result, message: result.message };
  }

  if (action === 'restore-token') {
    // NON-SPEC, and it is /admin/tokens' restore reached from here rather than
    // a second one: stats.restore() is the same function against the same set.
    // `jtiFrom()` answers an OBJECT — `{ jti, how }` — because it also accepts
    // a whole JWT and has to say where the jti came from. This read the object
    // itself as the jti: `stats.restore()` was handed one and matched nothing,
    // so the action ALWAYS reported "was not revoked, so nothing changed" and
    // put `[object Object]` in the sentence where the jti belongs. It is the
    // same call tokenAction() makes two hundred lines up, where it is spelt
    // `found.jti`, which is what makes /admin/tokens' restore work and this one
    // not.
    const found = jtiFrom(String(body.jti || body.target || ''));
    if (!found.jti) {
      log.debug("Leaving logoutAction().");
      return refused('STS-ADMIN-0502', { ok: false, errors: ['Name the token ' +
          'to restore in `jti`.'] });
    }
    const was = stats.restore(found.jti);
    log.debug("Leaving logoutAction().");
    return { ok: true, jti: found.jti,
             message: 'NON-SPEC: the token with jti ' + found.jti +
             (was ? ' is no longer revoked.' : ' was not revoked, so nothing ' +
                                               'changed.') +
             ' No authorization server could offer this — RFC 7009 has no ' +
             'such operation and a resource server may already have cached ' +
             'the refusal.' };
  }

  if (action === 'restore-kerberos') {
    // NON-SPEC in the same sense and for the same reason: it is what makes a
    // sign-out something a person can experiment with rather than restart out
    // of.
    const was = krb5Principals.clearSignOut([key], krb5Principals.REALM);
    log.debug("Leaving logoutAction().");
    return { ok: true,
             message: 'NON-SPEC: the sign-out instant on ' + key + '@' +
             krb5Principals.REALM +
             (was ? ' (' + was.toISOString() + ') is cleared, so tickets ' +
                    'issued before it are accepted again.'
                  : ' was not set, so nothing changed.') +
             ' A real KDC has no such operation; a fresh AS-REQ is the ' +
             'supported way back and clears it too.' };
  }

  log.debug("Leaving logoutAction(). Unknown action.");
  return refused('STS-ADMIN-0500',
                 { ok: false, errors: ['Unknown action "' + action + '". ' +
                               'There are four: global, end, restore-token, ' +
                               'restore-kerberos.'] });
}

// BUILT FROM THE SWITCH BELOW RATHER THAN TYPED, for the reason
// APPLICATION_ACTIONS gives at its own site: this repository's own
// tests/vendored/admin_api.js READS the refusal sentence to check that every
// console action has an /admin-api operation, so a list that is short by one is
// a list that turns the parity check off for that action.
const PERMISSION_ACTIONS = ['set-permission-base', 'define-permission',
                            'remove-permission', 'grant-permission',
                            'revoke-permission'];

function permissionsAction(body) {
  log.debug("Entering permissionsAction(). action=" +
            (body.action || '(none)'));
  const action = String(body.action || '');
  const actor = String(body.actor || '');
  const resource = String(body.resource || body.application || '').trim();
  const client = String(body.client || body.application || '').trim();

  // WHICH APPLICATION, ASKED ONCE FOR EACH SIDE. The two names are deliberately
  // different — `resource` for the application that EXPOSES a permission and
  // `client` for the one that HOLDS it — because this is the one feature here
  // where a body naming the wrong one still succeeds and writes a grant onto
  // the API instead of onto its caller. `application` is accepted for either as
  // a convenience for a caller editing one entry, and the refusals below name
  // the field that was missing rather than "an application".
  const needsResource = ['set-permission-base', 'define-permission',
                         'remove-permission'];
  const needsClient = ['grant-permission', 'revoke-permission'];
  if (needsResource.indexOf(action) >= 0 && !resource) {
    log.debug("Leaving permissionsAction(). No resource named.");
    return refused('STS-ADMIN-0514', { ok: false, errors: ['Which ' +
                                 'application exposes it? Send `resource` ' +
                                 'with the identifier exactly as the ' +
                                 'registry holds it — this is the ' +
                                 'application whose API the permission ' +
                                 'belongs to, not the one that will ask for ' +
                                 'it.'] });
  }
  if (needsClient.indexOf(action) >= 0 && !client) {
    log.debug("Leaving permissionsAction(). No client named.");
    return refused('STS-ADMIN-0515', { ok: false, errors: ['Which ' +
                                 'application holds it? Send `client` with ' +
                                 'the identifier exactly as the registry ' +
                                 'holds it — this is the application that ' +
                                 'will name the permission in a `scope`, not ' +
                                 'the one that exposes it.'] });
  }

  if (action === 'set-permission-base') {
    // The empty value is legal and CLEARS the base — see setBaseUri()'s
    // message, which says what that does to the permissions still on the entry.
    // It is the same convention every `set` on /admin/applications follows.
    const result = appPermissions.setBaseUri(resource,
                                             String(body.baseUri === undefined
      ? (body.value === undefined ? '' : body.value) : body.baseUri), actor);
    log.debug("Leaving permissionsAction(). set-permission-base " +
              (result.ok ? 'ok' : 'refused') + ".");
    return refusedBy('STS-ADMIN-0516', result);
  }

  if (action === 'define-permission') {
    const result = appPermissions.definePermission(resource,
      String(body.name || ''),
      String(body.description || ''), actor);
    log.debug("Leaving permissionsAction(). define-permission " +
              (result.ok ? 'ok' : 'refused') + ".");
    return refusedBy('STS-ADMIN-0516', result);
  }

  if (action === 'remove-permission') {
    // BY NAME AND NOT BY THE RAW ATTRIBUTE VALUE, deliberately. The value on
    // the entry is `name|description` and a form that posted it back would
    // break the moment somebody edited the description in an LDAP client — so
    // the name is the handle and `removePermission()` looks the raw value up.
    const result = appPermissions.removePermission(resource,
                                                   String(body.name || ''),
                                                   actor);
    log.debug("Leaving permissionsAction(). remove-permission " +
              (result.ok ? 'ok' : 'refused') + ".");
    return refusedBy('STS-ADMIN-0516', result);
  }

  if (action === 'grant-permission') {
    const result = appPermissions.grant(client, String(body.permission || ''),
                                        actor);
    log.debug("Leaving permissionsAction(). grant-permission " +
              (result.ok ? 'ok' : 'refused') + ".");
    return refusedBy('STS-ADMIN-0516', result);
  }

  if (action === 'revoke-permission') {
    const result = appPermissions.revoke(client, String(body.permission || ''),
                                         actor);
    log.debug("Leaving permissionsAction(). revoke-permission " +
              (result.ok ? 'ok' : 'refused') + ".");
    return refusedBy('STS-ADMIN-0516', result);
  }

  log.debug("Leaving permissionsAction(). Unknown action.");
  return refused('STS-ADMIN-0500',
                 { ok: false, errors: ['Unknown action "' + action + '". ' +
      'The ' +
                               numberWord(PERMISSION_ACTIONS.length) +
      ' are: ' +
                               PERMISSION_ACTIONS.join(', ') + '.'] });
}

function noXacml() {
  log.debug("Entering noXacml().");
  log.debug("Leaving noXacml().");
  return { xacml: false,
           message: 'The XACML module is not loaded in this process, so ' +
                    'there is no policy repository to report. ' +
                    'xacml/xacml_admin.js fills this reader when it is ' +
                    'required.' };
}

// ---------------------------------------------------------------------------
// THE CONSOLE SHAPE AND THE API SHAPE ARE NOT THE SAME, AND THIS IS THE
// BOUNDARY BETWEEN THEM.
//
// `xacml_admin.js`'s action functions answer `{ ok, why }` because that is what
// `respondToAction()` draws on a console page. **EVERY OTHER ACTION RESOURCE ON
// `/admin-api` ANSWERS `{ ok, errors: [...] }`** — ssf, permissions, realms,
// spiffe — and `tests/vendored/sts_admin_api_operations.js` reads that array on
// every one of them: it walks every documented POST resource, sends an unknown
// action, and requires the refusal SENTENCE to name the actions, because
// `admin_api.js`'s parity check reads that same sentence to find out what
// actions a resource has. A resource answering `why` is invisible to both.
//
// So the conversion happens HERE, at the one function the management API calls
// and the console does not — the console's own POST handlers call
// `combinedAction()` directly. `why` is kept BESIDE `errors` rather than being
// replaced, because a caller reading it is reading something true and a rename
// would break it for nothing.
//
// It went unnoticed from phase three until phase five for the reason three
// other XACML defects did: that job is this repository's OWN and had not been
// run against the branch.
// ---------------------------------------------------------------------------
function xacmlAction(body) {
  log.debug('Entering xacmlAction(). action=' + (body || {}).action);
  if (!xacmlPages) {
    log.debug('Leaving xacmlAction(). No XACML module.');
    return refused('STS-ADMIN-0501',
                   { ok: false, errors: [noXacml().message] });
  }
  const answered = xacmlPages.action(body);
  // `issue-pep-certificate` (2026-09-13) answers a PROMISE — a key pair and a
  // certificate are both asynchronous — and every other XACML action answers a
  // result. Settled here rather than by making every action asynchronous, so
  // that the in-process tests calling `combinedAction()` without awaiting are
  // unaffected; the caller of THIS function settles either shape with
  // `Promise.resolve()`.
  if (answered && typeof answered.then === 'function') {
    log.debug('Leaving xacmlAction(). Asynchronous.');
    return answered.then(converted);
  }
  log.debug('Leaving xacmlAction().');
  return converted(answered);

  function converted(result) {
    log.debug("Entering converted().");
    if (!result.ok && !result.errors && result.why) {
      log.debug('Leaving converted(). Refused.');
      return refused(innerCode(result) || 'STS-ADMIN-0517',
                     Object.assign({}, result, { errors: [result.why] }));
    }
    log.debug('Leaving converted(). ok=' + result.ok);
    return refusedBy('STS-ADMIN-0517', result);
  }
}

// ---------------------------------------------------------------------------
// THE ATTRIBUTES A CREATE CARRIES, IN THE TWO SPELLINGS THIS ACTION IS REACHED
// IN. The same shape `applicationFieldsFrom()` has one section down, and the
// same argument: the console's form posts one flat `field.<attribute>` per box
// and a JSON caller of `POST /admin-api/users/create` sends one `attributes`
// object, and two doors onto one action must not be two readings of what was
// sent.
//
// **IT VALIDATES NOTHING AND THAT IS THE POINT.** Which names are a person's
// attributes is `ldap_server.js`'s `personAttributesFrom()`, over
// `vc_claims.js`'s catalogue — the same place an `ldapadd` and a SCIM create
// are answered from. A check here would be a second opinion, and the one that
// said yes would be the one that produced the entry nothing else expects.
//
// **NO SPLIT ON NEWLINES**, which is where this differs from the applications
// version beside it and is worth saying rather than leaving as an apparent
// omission: every one of these attributes is a single-valued fact about a
// person — a given name, a postal code, a date of birth — so the whole value
// is the value, and a `postalAddress` legitimately containing a `$` separator
// would be cut into pieces by anything cleverer.
// ---------------------------------------------------------------------------
const USER_FIELD_PREFIX = 'field.';

function userFieldsFrom(body) {
  log.debug("Entering userFieldsFrom().");
  const fields = {};
  // A JSON body's own `attributes` object first, so a caller sending both gets
  // the flat fields merged OVER it rather than one of the two silently winning.
  const given = (body && typeof body.attributes === 'object' &&
                 body.attributes) || {};
  Object.keys(given).forEach(function (name) { fields[name] = given[name]; });
  Object.keys(body || {}).forEach(function (key) {
    if (key.indexOf(USER_FIELD_PREFIX) !== 0) {
      return;
    }
    const name = key.slice(USER_FIELD_PREFIX.length);
    if (!name) {
      return;
    }
    const value = String(body[key] === undefined ? '' : body[key]).trim();
    // AN EMPTY BOX IS NOT A VALUE. Every field on that form is drawn whether or
    // not it was filled in, so a create posts twenty-five of them and typically
    // means four — and "no value is recorded" is the promise the page makes.
    if (value !== '') {
      fields[name] = value;
    }
  });
  log.debug("Leaving userFieldsFrom(). " + Object.keys(fields).length + " " +
      "field(s).");
  return fields;
}

// A form's yes. Checkboxes post `on`, this console's own hidden fields post
// `yes` or `no`, and a JSON caller sends a real boolean — so all three are read
// here rather than at the three call sites. Anything else is false, including
// the empty string an unfilled hidden field posts.
function truthy(value) {
  log.debug("Entering truthy().");
  if (value === true) {
    log.debug("Leaving truthy().");
    return true;
  }
  const text = String(value === undefined || value === null ? '' : value)
                 .trim().toLowerCase();
  log.debug("Leaving truthy().");
  return text === 'true' || text === 'yes' || text === 'on' || text === '1';
}

// ---------------------------------------------------------------------------
// THE ONE THING THIS PAGE CAN CHANGE.
//
// Everything else on /admin/users is a report: who has authenticated, what they
// were issued, what the directory holds about them. This creates a person in
// the directory, and it is here rather than on /admin/groups or
// /admin/ldap/directory because this is the page a reader is on when they
// discover that somebody is missing.
//
// IT DECIDES NOTHING. Every rule about what a username may be, and the refusal
// of one that already exists, is in ldap_server.js's createUser() — reached
// through the slot above. This function reads the form and phrases the answer,
// which is the same split /admin/applications keeps with applications.js and
// the reason POST /admin-api/users/create can call straight into this without a
// second reading of any of it.
//
// WHAT IT DOES NOT DO is make the person appear in the list on this page. That
// list is identities this service has SEEN authenticate; the entry is in the
// DIRECTORY. The two are different questions — it is the same distinction
// /admin/groups draws when it marks a member "never here" — and the message
// says so outright, because an operator who created a user and could not find
// them in the table above would reasonably conclude the button was broken.
// ---------------------------------------------------------------------------
// The actions this resource accepts, built from the switch below rather than
// typed — the same arrangement MFA_ACTIONS had on the page this absorbed, and
// for the same reason: `tests/vendored/sts_admin_api_operations.js` reads the
// refusal sentence to discover what to check for, so a list that is short by
// one turns the parity check off for that action.
const USERS_ACTIONS = ['create', 'set-password', 'issue-activation',
                       'clear-totp', 'clear-key', 'clear-backup-codes',
                       // What an administrator does to somebody's
                       // credentials from their page (2026-09-13).
                       'reset-password', 'issue-password-reset',
                       'disable-primary-keys', 'disable-mfa',
                       'require-mfa', 'stop-requiring-mfa'];

// ---------------------------------------------------------------------------
// WHAT AN ADMINISTRATOR DOES TO SOMEBODY'S CREDENTIALS FROM THEIR PAGE
// (2026-09-13): six actions on the Users resource, drawn on a person's
// /admin/users page and mirrored at POST /admin-api/users/{action}.
//
//   reset-password         a generated password, returned ONCE; the person
//                          must change it at their next sign-in (pwdReset);
//                          they are signed out of everything.
//   issue-password-reset   a single-use link, returned ONCE; the password they
//                          had is REMOVED and they are signed out of
//                          everything, so the link is their way back.
//   disable-primary-keys   every PRIMARY security key off, so passkeys no
//                          longer sign them in; refused where that leaves no
//                          way in.
//   disable-mfa            every second factor off: authenticator app, `mfa`
//                          keys, recovery codes.
//   require-mfa            a second factor required of them at the sign-in
//   stop-requiring-mfa     screen, and the requirement taken away.
//
// **EACH SAYS WHAT HAPPENED OVER SHARED SIGNALS**, through
// `ssf/account_signals.js`: a CAEP credential-change for every credential that
// changed, RISC account-credential-change-required for a reset, RISC
// recovery-information-changed for cleared recovery codes. The sign-out's own
// sessions each say session-revoked through `dropSession()`, as every sign-out
// does. Nothing waits for any of it.
//
// **THE STORE DECIDES WHAT HAPPENS TO THE ENTRY** (`common/credentials.js`);
// this decides who asked, what is audited and what is said. Answers null for
// an action that is not one of the six, so `usersAction()` carries on.
// ---------------------------------------------------------------------------
const CREDENTIAL_ADMIN_ACTIONS = ['reset-password', 'issue-password-reset',
  'disable-primary-keys', 'disable-mfa', 'require-mfa', 'stop-requiring-mfa'];

// Sign somebody out of everything, through the same `terminate()`
// `/admin/logout`'s global button calls. A process without the logout module is
// reported rather than refused: the credential change has happened either way.
function signOutEverywhere(who, ctx, why) {
  log.debug("Entering signOutEverywhere(). who=" + who);
  if (!logoutReader) {
    log.debug("Leaving signOutEverywhere(). No logout module.");
    return { ended: false, terminated: 0,
             message: 'No sign-out module is loaded in this process, so no ' +
                      'session was ended.' };
  }
  const result = logoutReader.terminate(stats.identityKeyOf(who), [], {
    actor: ctx.actor || who, channel: ctx.via,
    by: why + ' (' + (ctx.via === 'api' ? '/admin-api/users'
                                         : 'the admin console') + ')'
  });
  log.debug("Leaving signOutEverywhere(). Ended " +
            (result.terminated || []).length + ".");
  return { ended: true, terminated: (result.terminated || []).length,
           message: result.message };
}

function credentialAdminAction(action, body, ctx) {
  log.debug("Entering credentialAdminAction(). action=" + action);
  if (CREDENTIAL_ADMIN_ACTIONS.indexOf(action) < 0) {
    log.debug("Leaving credentialAdminAction(). Not one of them.");
    return null;
  }
  const who = String(body.user || body.username || '').trim();
  if (!who) {
    log.debug("Leaving credentialAdminAction(). No person named.");
    return refused('STS-ADMIN-0518', { ok: false, errors: ['Name the person ' +
        'in `user`.'] });
  }
  const audited = function (name, summary, detail, outcome) {
    log.debug("Entering audited().");
    auditLog.record({ category: 'admin', action: name, actor: ctx.actor,
      target: who, outcome: outcome || 'success', summary: summary,
      detail: Object.assign({ username: who, via: ctx.via }, detail || {}) });
    log.debug("Leaving audited().");
  };

  if (action === 'reset-password') {
    const password = credentials.generatePassword(who);
    const set = credentials.setPassword(who, password, { generated: true });
    if (!set.ok) {
      log.debug("Leaving credentialAdminAction(). The password was refused.");
      return refusedBy('STS-ADMIN-0780', set);
    }
    const forced = credentials.setPasswordResetRequired(who, true);
    // A LINK OUTSTANDING IS SPENT BY THIS: the administrator has just decided
    // what the password is, and a link left behind would let whoever holds it
    // replace that decision.
    credentials.consumePasswordReset(who);
    const signedOut = signOutEverywhere(who, ctx, 'a password reset');
    audited('admin.password.reset',
            'an administrator reset the password of ' + who,
            { forcedChange: forced, sessionsEnded: signedOut.terminated });
    accountSignals.credentialChanged({ username: who,
      credentialType: 'password', changeType: 'update', via: ctx.via,
      reasonAdmin: 'An administrator reset the password of ' + who + '.',
      reasonUser: 'Your password was reset by an administrator and must be ' +
                  'changed when you next sign in.' });
    accountSignals.credentialChangeRequired({ username: who,
      reasonAdmin: 'An administrator reset the password of ' + who + '.' });
    log.info('admin: the password of "' + who + '" was reset by ' +
             (ctx.actor || 'an unnamed caller') + ' (' + ctx.via + ').');
    log.debug("Leaving credentialAdminAction(). reset-password.");
    return { ok: true, username: who, password: password,
             forcedChange: forced, signedOut: signedOut,
             message: 'The password of ' + who + ' was reset. IT IS SHOWN ' +
                      'ONCE — this service stores a scrypt hash and cannot ' +
                      'produce it again. Give it to them by a channel you ' +
                      'trust. ' + (forced
                        ? 'They must choose their own at their next sign-in. '
                        : 'The forced change could NOT be recorded, so they ' +
                          'will not be asked to choose their own. ') +
                      'They were signed out of everything: ' +
                      signedOut.message };
  }

  if (action === 'issue-password-reset') {
    const issued = credentials.issuePasswordReset(who);
    if (!issued.ok) {
      log.debug("Leaving credentialAdminAction(). The link was refused.");
      return refusedBy('STS-ADMIN-0781', issued);
    }
    const removed = credentials.removePassword(who);
    if (!removed.ok) {
      // THE LINK IS WITHDRAWN AGAIN: a link issued beside a password that is
      // still there is not what was asked for, and the administrator is told.
      credentials.consumePasswordReset(who);
      log.debug("Leaving credentialAdminAction(). The password stayed.");
      return refusedBy('STS-ADMIN-0782', removed);
    }
    // A password they no longer hold cannot be one they must change.
    credentials.setPasswordResetRequired(who, false);
    const signedOut = signOutEverywhere(who, ctx, 'a password reset link');
    const path = '/portal/reset-password?user=' + encodeURIComponent(who) +
                 '&token=' + encodeURIComponent(issued.token);
    audited('admin.password.reset-link',
            'an administrator issued a password reset link for ' + who,
            { expiresAt: issued.expiresAt, passwordRemoved: removed.removed,
              sessionsEnded: signedOut.terminated });
    if (removed.removed) {
      accountSignals.credentialChanged({ username: who,
        credentialType: 'password', changeType: 'revoke', via: ctx.via,
        reasonAdmin: 'An administrator revoked the password of ' + who +
                     ' and issued a reset link.',
        reasonUser: 'Your password was revoked. Use the reset link you were ' +
                    'sent to choose a new one.' });
    }
    accountSignals.credentialChangeRequired({ username: who,
      reasonAdmin: 'An administrator issued a password reset link for ' + who +
                   '.' });
    log.info('admin: a password reset link was issued for "' + who + '" by ' +
             (ctx.actor || 'an unnamed caller') + ' (' + ctx.via + ').');
    log.debug("Leaving credentialAdminAction(). issue-password-reset.");
    return { ok: true, username: who,
             resetUrl: (ctx.base || '') + path, expiresAt: issued.expiresAt,
             passwordRevoked: removed.removed, signedOut: signedOut,
             message: 'A password reset link for ' + who + ' is valid until ' +
                      issued.expiresAt + '. IT IS SHOWN ONCE — this service ' +
                      'stores only a hash. Send it to them by a channel you ' +
                      'trust: anybody holding it can set their password. ' +
                      (removed.removed ? 'Their old password was removed, ' +
                        'so until the link is used they cannot sign in with ' +
                        'a password. ' : '') +
                      'They were signed out of everything: ' +
                      signedOut.message };
  }

  if (action === 'disable-primary-keys') {
    const result = credentials.removePrimaryKeys(who);
    audited('admin.mfa.primary-keys.removed',
            (result.ok ? 'removed' : 'could not remove') + ' the primary ' +
            'security keys of ' + who,
            { removed: (result.removed || []).length,
              errors: result.ok ? undefined : (result.errors || []) },
            result.ok ? 'success' : 'failure');
    if (!result.ok) {
      log.debug("Leaving credentialAdminAction(). Keys refused.");
      return refusedBy('STS-ADMIN-0783', result);
    }
    result.removed.forEach(function (one) {
      accountSignals.credentialChanged({ username: who,
        credentialType: accountSignals.KEY_CREDENTIAL_TYPE,
        changeType: 'delete', friendlyName: one.label, via: ctx.via,
        reasonAdmin: 'An administrator disabled passwordless sign-in for ' +
                     who + '.',
        reasonUser: 'A security key that signed you in without a password ' +
                    'was removed from your account.' });
    });
    log.debug("Leaving credentialAdminAction(). disable-primary-keys.");
    return { ok: true, username: who, removed: result.removed,
             message: result.removed.length + ' primary security key(s) of ' +
                      who + ' removed. They sign in with their password now; ' +
                      'a key they hold as a second factor is untouched.' };
  }

  if (action === 'disable-mfa') {
    const result = credentials.removeSecondFactors(who);
    const removed = result.removed || { totp: false, keys: [],
                                        backupCodes: false };
    audited('admin.mfa.disabled',
            (result.ok ? 'disabled' : 'could not disable') + ' every second ' +
            'factor of ' + who,
            { totp: removed.totp, keys: removed.keys.length,
              backupCodes: removed.backupCodes,
              errors: result.ok ? undefined : (result.errors || []) },
            result.ok ? 'success' : 'failure');
    // SAID FOR WHATEVER WENT, even on a write that failed part way: those
    // credentials are gone, and a receiver not told would go on trusting them.
    if (removed.totp) {
      accountSignals.credentialChanged({ username: who,
        credentialType: accountSignals.TOTP_CREDENTIAL_TYPE,
        changeType: 'delete', via: ctx.via,
        reasonAdmin: 'An administrator disabled every second factor of ' +
                     who + '.',
        reasonUser: 'Your authenticator app was removed from your account.' });
    }
    removed.keys.forEach(function (one) {
      accountSignals.credentialChanged({ username: who,
        credentialType: accountSignals.KEY_CREDENTIAL_TYPE,
        changeType: 'delete', friendlyName: one.label, via: ctx.via,
        reasonAdmin: 'An administrator disabled every second factor of ' +
                     who + '.',
        reasonUser: 'A security key was removed from your account.' });
    });
    if (removed.backupCodes) {
      accountSignals.recoveryInformationChanged({ username: who,
        reasonAdmin: 'An administrator disabled every second factor of ' +
                     who + ', recovery codes included.' });
    }
    if (!result.ok) {
      log.debug("Leaving credentialAdminAction(). Second factors refused.");
      return refusedBy('STS-ADMIN-0784', result);
    }
    const requirement = credentials.mfaRequirementFor(who);
    log.debug("Leaving credentialAdminAction(). disable-mfa.");
    return { ok: true, username: who, removed: removed,
             requirement: requirement,
             message: 'Every second factor of ' + who + ' was removed (' +
                      'authenticator app: ' + (removed.totp ? 'yes' : 'no') +
                      ', security keys: ' + removed.keys.length +
                      ', recovery codes: ' +
                      (removed.backupCodes ? 'yes' : 'no') + '). ' +
                      (requirement.required
                        ? 'A second factor is still REQUIRED of them (' +
                          (requirement.byUser ? 'on their account'
                            : 'by the realm') +
                          '), so their next sign-in asks them to enrol ' +
                          'a new one.'
                        : 'A password alone signs them in now.') };
  }

  // require-mfa and stop-requiring-mfa
  const wanted = action === 'require-mfa';
  const result = credentials.setMfaRequired(who, wanted);
  audited(wanted ? 'admin.mfa.required' : 'admin.mfa.unrequired',
          (result.ok ? '' : 'could not ') +
          (wanted ? 'required a second factor of ' : 'stopped requiring a ' +
                    'second factor of ') + who, {
            errors: result.ok ? undefined : (result.errors || []) },
          result.ok ? 'success' : 'failure');
  if (!result.ok) {
    log.debug("Leaving credentialAdminAction(). The requirement was refused.");
    return refusedBy('STS-ADMIN-0785', result);
  }
  const mech = credentials.mechanismsFor(who);
  log.debug("Leaving credentialAdminAction(). " + action + ".");
  return { ok: true, username: who, required: wanted,
           requirement: mech.mfaRequirement,
           message: wanted
             ? 'A second factor is now required of ' + who + '. ' +
               (mech.mfaRequired
                 ? 'They already hold one, so nothing changes at their next ' +
                   'sign-in.'
                 : 'They hold none, so their next sign-in at the sign-in ' +
                   'screen asks them to enrol an authenticator app or a ' +
                   'security key before it continues.')
             : 'A second factor is no longer required of ' + who + ' on ' +
               'their account.' + (mech.mfaRequirement.byRealm
                 ? ' The REALM still requires one (authn.mfaRequired).' : '')
  };
}

function usersAction(body, context) {
  log.debug("Entering usersAction(). action=" + (body.action || '(none)'));
  const action = String(body.action || '');
  // WHO IS DOING IT, for the audit rows the two clears write. Read from the
  // caller rather than from a cookie in here, because the management API calls
  // this same function with an actor of its own — a function that reached for a
  // session would only work from one of the two doors. `via` is the door.
  // `base` (2026-09-13) is the address the request arrived on, realm prefix
  // included, so a password reset link can be handed back WHOLE — the one
  // thing an administrator does with it is send it to somebody.
  const ctx = { via: (context || {}).via || 'console',
                actor: (context || {}).actor || String(body.actor || ''),
                base: String((context || {}).base || '') };

  const credentialAnswer = credentialAdminAction(action, body, ctx);
  if (credentialAnswer) {
    log.debug("Leaving usersAction(). A credential action answered.");
    return credentialAnswer;
  }

  // ISSUE AN ACTIVATION LINK (2026-09-06). How somebody provisioned through
  // /admin-api, SCIM or an LDAP add comes to have a way in.
  //
  // **THE LINK IS RETURNED ONCE AND NEVER AGAIN**, like the bootstrap password
  // and a client secret, because what is stored is a hash — this service cannot
  // produce it a second time, only replace it. Issuing again invalidates the
  // previous one, which is also how a link that expired or was never delivered
  // is replaced.
  //
  // It is an ADMIN act rather than a self-service one, deliberately. There is
  // no mail channel here, so a self-service "send me a link" form would have to
  // show the link on screen — handing any visitor an activation link for any
  // unactivated account, which is an account takeover with a username as the
  // only input.
  if (action === 'issue-activation') {
    const who = String(body.user || body.username || '').trim();
    if (!who) {
      log.debug("Leaving tokenAction(). No user was named.");
      return refused('STS-ADMIN-0518', { ok: false, errors: ['Name the ' +
                                   'person to issue an activation link ' +
                                   'for.'] });
    }
    const issued = credentials.issueActivation(who);
    if (!issued.ok) {
      log.debug("Leaving tokenAction(). The activation link was refused.");
      return refusedBy('STS-ADMIN-0519', issued);
    }
    auditLog.record({
      category: 'authentication', action: 'activation.issued',
      actor: (body.actor || ''), target: who, outcome: 'success',
      summary: 'an activation link was issued for ' + who,
      detail: { expiresAt: issued.expiresAt }
    });
    log.debug("Leaving usersAction().");
    return { ok: true, username: who, expiresAt: issued.expiresAt,
             // THE ONLY TIME THIS VALUE EXISTS OUTSIDE THE PERSON'S BROWSER.
             activationUrl: '/portal/activate?user=' +
                            encodeURIComponent(who) + '&token=' +
                            encodeURIComponent(issued.token),
             message: 'An activation link for ' + who + ' is valid until ' +
                      issued.expiresAt + '. IT IS SHOWN ONCE — this service ' +
                      'stores only a hash and cannot produce it again. Send ' +
                      'it to them by whatever channel you already use; ' +
                      'anybody who has it can complete the account setup, so ' +
                      'treat it as the credential it is. Issuing another ' +
                      'invalidates this one.' };
  }


  // ---------------------------------------------------------------------
  // THE TWO SECOND-FACTOR REMOVALS (2026-09-10). THEY WERE `POST /admin/mfa`.
  //
  // They are here rather than on a resource of their own because the buttons
  // are here: the roster moved onto this page's columns and the per-person
  // detail onto this page's drill-down, and an action resource whose page no
  // longer exists is exactly the console/API drift rule 7 is written against.
  //
  // **THEY ARE NOT THE SAME ACT AND THE DIFFERENCE IS WHICH ONE CAN LOCK
  // SOMEBODY OUT.** Clearing an authenticator app cannot: a one-time code is
  // never a primary credential here, so it drops the account to one factor and
  // never to none. Removing a KEY can — it may be the only credential on the
  // account — which is why it goes through `credentials.removeKey()` rather
  // than a write of its own: that function is where the last-way-in refusal
  // lives, and an operator must not be able to do what the person themselves
  // is stopped from doing.
  //
  // **THERE IS NO ENROL BESIDE THEM AND THERE CANNOT BE.** Enrolling an
  // authenticator means being shown a shared secret, and an administrative
  // door that handed one out would mint a working second factor for any
  // account. A WebAuthn ceremony happens in the person's own browser against
  // their own authenticator, and this console is not that browser. Both are
  // `/portal`, or an activation link, which is itself a credential.
  // ---------------------------------------------------------------------
  if (action === 'clear-totp') {
    const who = String(body.user || body.username || '').trim();
    if (!who) {
      log.debug("Leaving usersAction(). No person named.");
      return refused('STS-ADMIN-0518', { ok: false, errors: ['Name the ' +
                                   'person whose authenticator app is being ' +
                                   'cleared.'] });
    }
    const result = credentials.removeTotp(who);
    auditLog.record({
      category: 'authentication', action: 'admin.mfa.totp.cleared',
      actor: ctx.actor, target: who, outcome: result.ok ? 'success' : 'failure',
      summary: (result.ok ? 'cleared' : 'could not clear') +
               ' the authenticator app enrolment for ' + who,
      detail: { username: who, via: ctx.via,
                errors: result.ok ? undefined : (result.errors || []) }
    });
    if (result.ok) {
      accountSignals.credentialChanged({ username: who,
        credentialType: accountSignals.TOTP_CREDENTIAL_TYPE,
        changeType: 'delete', via: ctx.via,
        reasonAdmin: 'An administrator cleared the authenticator app of ' +
                     who + '.',
        reasonUser: 'Your authenticator app was removed from your account.' });
      log.info('admin: the authenticator app for "' + who +
               '" was cleared by ' +
               (ctx.actor || 'an unnamed caller') + ' (' + ctx.via + '). ' +
               'That account is down to one factor and they can enrol again ' +
               'from /portal/mfa.');
    }
    log.debug("Leaving usersAction(). clear-totp " +
              (result.ok ? "ok." : "refused."));
    return refusedBy('STS-ADMIN-0520', result);
  }

  // ---------------------------------------------------------------------
  // THE THIRD REMOVAL (2026-09-10), AND IT STOPPED BEING AN ISSUING CONTROL ON
  // 2026-09-11.
  //
  // Clearing an authenticator app or a key takes a factor AWAY and that is all
  // it does. Clearing the recovery codes used to do something else as well:
  // it **re-armed the automatic issue**, because `ensureBackupCodes()` did
  // nothing while a set existed, so the next second factor the person enrolled
  // issued a new one. That was the whole path to a second set and it was
  // deliberately an operator's act.
  //
  // **THAT PATH IS GONE AND SO IS THE ARGUMENT FOR IT BEING AN OPERATOR'S.**
  // A person generates their own set from `/portal/mfa` now, as often as they
  // like, because there is no way to SEE a set they already have — so a
  // Replace control is the only answer to having lost one. This button is
  // therefore a plain removal again: it takes the way back away and nothing
  // re-arms.
  //
  // **IT IS KEPT BECAUSE THE OTHER REASON FOR IT NEVER WENT AWAY**: a set this
  // process cannot read, or one an operator has reason to believe has been
  // copied, is an operator's to remove — and unlike the person, an operator
  // can do it without being shown ten new strings.
  //
  // **IT CANNOT LOCK ANYBODY OUT** — a recovery code is never a way in on its
  // own, so the account keeps whatever it had. What it removes is the thing
  // that stops a lost phone being final, which is why it is audited like the
  // other two and why the button says so.
  // ---------------------------------------------------------------------
  if (action === 'clear-backup-codes') {
    const who = String(body.user || body.username || '').trim();
    if (!who) {
      log.debug("Leaving usersAction(). No person named.");
      return refused('STS-ADMIN-0518', { ok: false, errors: ['Name the ' +
                                   'person whose recovery codes are being ' +
                                   'cleared.'] });
    }
    const result = credentials.removeBackupCodes(who);
    auditLog.record({
      category: 'authentication', action: 'admin.mfa.backup-codes.cleared',
      actor: ctx.actor, target: who, outcome: result.ok ? 'success' : 'failure',
      summary: (result.ok ? 'cleared' : 'could not clear') +
               ' the recovery codes for ' + who,
      detail: { username: who, via: ctx.via,
                errors: result.ok ? undefined : (result.errors || []) }
    });
    if (result.ok) {
      accountSignals.recoveryInformationChanged({ username: who,
        reasonAdmin: 'An administrator cleared the recovery codes of ' + who +
                     '.' });
      log.info('admin: the recovery codes for "' + who + '" were cleared by ' +
               (ctx.actor || 'an unnamed caller') + ' (' + ctx.via + '). The ' +
               'next second factor they enrol issues a new set.');
    }
    log.debug("Leaving usersAction(). clear-backup-codes " +
              (result.ok ? "ok." : "refused."));
    return refusedBy('STS-ADMIN-0521', result);
  }

  if (action === 'clear-key') {
    const who = String(body.user || body.username || '').trim();
    if (!who) {
      log.debug("Leaving usersAction(). No person named.");
      return refused('STS-ADMIN-0518', { ok: false, errors: ['Name the ' +
                                   'person whose security key is being ' +
                                   'removed.'] });
    }
    // THROUGH `removeKey()` AND NOT A WRITE OF ITS OWN — see the header: that
    // function carries the refusal that matters.
    const going = credentials.keysOf(who).filter(function (one) {
      return one.credentialId === String(body.credentialId || '');
    })[0];
    const result = credentials.removeKey(who, String(body.credentialId || ''));
    if (result.ok) {
      accountSignals.credentialChanged({ username: who,
        credentialType: accountSignals.KEY_CREDENTIAL_TYPE,
        changeType: 'delete', via: ctx.via,
        friendlyName: going ? String(going.label || '') : '',
        reasonAdmin: 'An administrator removed a ' +
                     (going ? going.role : '') + ' security key of ' + who +
                     '.',
        reasonUser: 'A security key was removed from your account.' });
    }
    auditLog.record({
      category: 'authentication', action: 'admin.mfa.key.cleared',
      actor: ctx.actor, target: who, outcome: result.ok ? 'success' : 'failure',
      summary: (result.ok ? 'removed' : 'could not remove') +
               ' a security key for ' + who,
      detail: { username: who, via: ctx.via,
                credentialId: String(body.credentialId || ''),
                errors: result.ok ? undefined : (result.errors || []) }
    });
    log.debug("Leaving usersAction(). clear-key " +
              (result.ok ? "ok." : "refused."));
    return refusedBy('STS-ADMIN-0522', result);
  }

  // SET A PASSWORD ON SOMEBODY WHO IS ALREADY HERE (2026-09-06).
  //
  // **IT EXISTED IN PROSE BEFORE IT EXISTED IN CODE**, which is the reason it
  // is here rather than only inside `create` below: `credentials.js` names
  // `POST /admin-api/users/set-password` twice — in the sentence a refused
  // sign-in gets, and in the product-mode bootstrap banner that tells an
  // operator to change the generated password — and no such operation was ever
  // written. Somebody following either instruction got a 404 naming an
  // endpoint this service documents.
  //
  // It is `credentials.setPassword()` and nothing else: hashed there, never
  // here, and never written as an attribute — which is also why `userPassword`
  // is refused by the attribute door on `create`.
  if (action === 'set-password') {
    const who = String(body.user || body.username || '').trim();
    if (!who) {
      log.debug("Leaving usersAction(). No user was named.");
      return refused('STS-ADMIN-0518', { ok: false, errors: ['Name the ' +
          'person whose password to set.'] });
    }
    const wanted = String(body.password || '');
    const generate = truthy(body.generate);
    if (!wanted && !generate) {
      log.debug("Leaving usersAction(). No password.");
      return refused('STS-ADMIN-0523', { ok: false, errors: ['Send ' +
                                   '`password` with the password to set, or ' +
                                   '`generate` to have one made up and ' +
                                   'returned once.'] });
    }
    // A CONFIRMATION IS CHECKED WHERE ONE WAS SENT AND NOT REQUIRED. The
    // console's form always sends it, because a mistyped password nobody can
    // read back is a locked-out person; an API caller sending one value has
    // nothing to mistype against.
    if (!generate && body.passwordConfirm !== undefined &&
        String(body.passwordConfirm) !== wanted) {
      log.debug("Leaving usersAction(). The two passwords differ.");
      return refused('STS-ADMIN-0524', { ok: false, errors: ['The two ' +
                                   'passwords do not match. Nothing was ' +
                                   'changed.'] });
    }
    const password = generate ? credentials.generatePassword(who) : wanted;
    const set = credentials.setPassword(who, password, { generated: generate });
    if (!set.ok) {
      log.debug("Leaving usersAction(). The password was refused.");
      return refusedBy('STS-ADMIN-0525', set);
    }
    accountSignals.credentialChanged({ username: who,
      credentialType: 'password', changeType: 'update', via: ctx.via,
      reasonAdmin: 'An administrator set the password of ' + who + '.',
      reasonUser: 'Your password was changed by an administrator.' });
    auditLog.record({
      category: 'authentication', action: 'password.set',
      actor: (body.actor || ''), target: who, outcome: 'success',
      summary: 'a password was set for ' + who + ' by an administrator',
      // NO PASSWORD AND NO HASH IN THE AUDIT ROW, generated or typed. The row
      // records that it happened and by which door; the value existed in one
      // response and in one log line's absence.
      detail: { generated: generate }
    });
    log.debug("Leaving usersAction().");
    return { ok: true, username: who, generated: generate,
             // ONLY WHERE IT WAS GENERATED. Echoing a password the caller
             // already holds back to them buys nothing and puts it in a second
             // place — a proxy log, a browser history, a test fixture.
             password: generate ? password : undefined,
             message: generate
               ? 'A password for ' + who + ' has been generated and set. IT ' +
                 'IS SHOWN ONCE — this service stores a scrypt hash and ' +
                 'cannot produce it again, only replace it.'
               : 'The password for ' + who + ' is set. It is stored as a ' +
                 'hash and cannot be shown again.' };
  }

  if (action === 'create') {
    if (!directoryWriter) {
      log.debug("Leaving usersAction(). No directory is loaded.");
      return refused('STS-ADMIN-0501', { ok: false, errors: ['No LDAP ' +
                                   'directory is loaded in this process, so ' +
                                   'there is nowhere to put a person. The ' +
                                   'rest of this page is unaffected — it ' +
                                   'reports what this service has seen, ' +
                                   'which does not come from the ' +
                                   'directory.'] });
    }
    const username = String(body.username || body.user || '').trim();
    // WHAT THE OPERATOR TYPED, AND WHETHER TO MAKE UP THE REST.
    //
    // **`invent` DEFAULTS TO TRUE AND THAT IS BACKWARDS COMPATIBILITY RATHER
    // THAN A PREFERENCE.** Every caller that predates /admin/users/new — the
    // list page's own row, `POST /admin-api/users/create`, a test — asked for
    // a person and got the invented one, and the API's published description
    // still promises it. The new page sends `invent=no` explicitly, which is
    // the whole of how "no value is recorded" is expressed.
    const typed = userFieldsFrom(body);
    const invent = body.invent === undefined ? true : truthy(body.invent);
    const result = directoryWriter(username, {
      origin: 'console',
      note: String(body.note || '').trim() ||
            'created by hand on the admin console rather than by ' +
            'authenticating',
      channel: 'console',
      attributes: typed,
      invent: invent
    });
    if (!result.ok) {
      log.debug("Leaving usersAction(). create refused.");
      return refusedBy('STS-ADMIN-0526', result);
    }
    // ------------------------------------------------------------------
    // AND THE CREDENTIAL, WHICH IS A SECOND ACT ON A PERSON WHO NOW EXISTS.
    //
    // **THE ORDER IS LOAD-BEARING AND SO IS THE FAILURE MODE.** A password can
    // only be written onto an entry, so the entry has to be there first — and
    // that means a create whose credential step fails has ALREADY put somebody
    // in the directory. It is reported as a SUCCESS carrying a loud failure
    // rather than as a failure, because answering `ok: false` would send an
    // operator to press Create again and meet "that username is taken", which
    // is the least informative true sentence available.
    //
    // Four modes and **`generate` is the default since 2026-09-12**, on this
    // door and on the console's form alike. It was `none`, because that is
    // what this door did before there were any modes and development checks
    // no password; but a person created with nothing is, in product mode, a
    // person who cannot sign in, and rcbj asked for the default to be a
    // generated password drawn against the password policy and handed back
    // ONCE. A caller that wants nobody holding anything sends `none`.
    //
    // **WHAT IT COSTS IS ONE SCRYPT HASH PER CREATE** — about 70ms on the one
    // thread every socket is answered from — which is nothing for a person
    // and five minutes for a bulk load of five thousand; the bulk-load job
    // sends `none` for exactly that reason.
    // ------------------------------------------------------------------
    const credential = String(body.credential || DEFAULT_CREDENTIAL).trim() ||
                       DEFAULT_CREDENTIAL;
    const answer = { ok: true, dn: result.dn, username: result.username,
                     entry: result.entry, typed: result.typed || [],
                     invented: !!result.invented, credential: credential };
    let credentialSaid = '';
    if (credential === 'password' || credential === 'generate') {
      const generated = credential === 'generate';
      if (!generated && String(body.password || '') === '') {
        answer.credentialError = 'No password was sent, so none was set.';
      } else if (!generated && body.passwordConfirm !== undefined &&
                 String(body.passwordConfirm) !== String(body.password || '')) {
        answer.credentialError = 'The two passwords do not match, so none ' +
                                 'was set.';
      } else {
        const password = generated ?
                         credentials.generatePassword(result.username)
                                   : String(body.password || '');
        const set = credentials.setPassword(result.username, password,
                                            { generated: generated });
        if (!set.ok) {
          answer.credentialError = (set.errors || []).join(' ');
        } else {
          auditLog.record({
            category: 'authentication', action: 'password.set',
            actor: (body.actor || ''), target: result.username,
            outcome: 'success',
            summary: 'a password was set for ' + result.username +
                     ' as they were created',
            detail: { generated: generated }
          });
          answer.passwordSet = true;
          answer.generated = generated;
          if (generated) {
            // THE ONLY TIME THIS VALUE EXISTS OUTSIDE THE HASH.
            answer.password = password;
            credentialSaid = ' A password has been GENERATED for them and is ' +
              'shown once: this service stores a scrypt hash and cannot ' +
              'produce it again, only replace it.';
          } else {
            credentialSaid = ' The password you typed is set, stored as a ' +
              'scrypt hash, and cannot be shown again by anybody including ' +
              'this console.';
          }
        }
      }
    } else if (credential === 'activation') {
      const issued = credentials.issueActivation(result.username);
      if (!issued.ok) {
        answer.credentialError = (issued.errors || []).join(' ');
      } else {
        auditLog.record({
          category: 'authentication', action: 'activation.issued',
          actor: (body.actor || ''), target: result.username,
          outcome: 'success',
          summary: 'an activation link was issued for ' + result.username +
                   ' as they were created',
          detail: { expiresAt: issued.expiresAt }
        });
        answer.activationUrl = '/portal/activate?user=' +
                               encodeURIComponent(result.username) + '&token=' +
                               encodeURIComponent(issued.token);
        answer.expiresAt = issued.expiresAt;
        credentialSaid = ' They have NO credential and an activation link ' +
          'instead, valid until ' + issued.expiresAt + ' and shown once. ' +
          'They choose a password, a security key or both at it; nothing ' +
          'about this account is decided until they do.';
      }
    } else if (credential !== 'none') {
      answer.credentialError = 'Unknown credential option "' + credential +
        '". The four are: none, password, generate, activation. Nothing was ' +
        'set.';
    }
    if (answer.credentialError) {
      credentialSaid = ' THE PERSON EXISTS AND HAS NO CREDENTIAL: ' +
        answer.credentialError + ' Set one from their row on Users rather ' +
        'than creating them again — the name is taken now, by this entry.';
    }
    log.debug("Leaving usersAction(). Created " + result.dn + ".");
    answer.message = result.dn + ' now exists in the directory' +
      (result.invented
        ? ', with the invented person behind that name written onto it — so ' +
          'a credential issued ' +
          'for ' + result.username + ' and an ldapsearch ' +
          'for that entry say the same thing.'
        : ', carrying ' + (answer.typed.length
            ? 'the ' + answer.typed.length + ' attribute(s) you typed and ' +
                                             'nothing else'
            : 'no attributes at all beyond its object classes and its uid') +
          '. Nothing was invented for it.') +
      credentialSaid +
      ' They will NOT appear in the table on the Users page until they ' +
      'authenticate somewhere: that list is who this service has seen, and ' +
      'the entry is what the directory HOLDS.';
    log.debug("Leaving usersAction().");
    return answer;
  }

  log.debug("Leaving usersAction(). Unknown action.");
  return refused('STS-ADMIN-0500',
                 { ok: false, errors: ['Unknown action "' + action + '". ' +
      'The ' +
                               numberWord(USERS_ACTIONS.length) + ' are: ' +
                               USERS_ACTIONS.join(', ') + '.'] });
}

// Three answers again, and the first of them — no directory in this process —
// is the one an API caller is most likely to meet and least likely to expect,
// because it answers 200 with `directory: false` rather than failing.
// ---------------------------------------------------------------------------
// THE TWO THINGS THIS PAGE CAN CHANGE (2026-09-06).
//
// Everything else on /admin/groups is a report, exactly as everything else on
// /admin/users was until `create` arrived there. These two are here for the
// same reason that one is on that page: this is the page a reader is on when
// they discover that a group is missing, or that somebody is not in one.
//
// **IT DECIDES NOTHING.** Every rule about what a group may be called, the
// refusal of one that is already there, what a membership value points at and
// the choice to write a dangling one rather than refuse it, are in
// ldap_server.js's createGroup() and addGroupMember() — reached through the
// slot above. This function reads the form and phrases the answer, which is the
// same split usersAction() keeps with createUser() and the reason POST
// /admin-api/groups/{action} can call straight into it without a second reading
// of any of it.
//
// **WHAT IT DOES NOT DO is make the new group grant anything.** GROUPS_CAVEAT
// says it on both halves of this page and it is worth repeating at the one
// moment somebody has just made one: a group here changes what a directory
// client sees and what a token SAYS, and changes nothing about what that token
// can DO — with the two console roles as the only exceptions, and those are
// granted on /admin/rbac rather than here.
// ---------------------------------------------------------------------------
function groupsAction(body) {
  log.debug("Entering groupsAction(). action=" + (body.action || '(none)'));
  const action = String(body.action || '');

  if (!groupWriter) {
    // ONE REFUSAL FOR BOTH ACTIONS, and it says which half of the page is
    // affected: the reads above it are answered by a different slot, so a
    // reader whose table is plainly full of groups needs telling that it is the
    // WRITES that are absent rather than the directory.
    log.debug("Leaving groupsAction(). No directory writer is installed.");
    return refused('STS-ADMIN-0501', { ok: false, errors: ['No LDAP ' +
                                 'directory is loaded in this process, so ' +
                                 'there is nowhere to put a group. The rest ' +
                                 'of this page is unaffected — if it is ' +
                                 'showing you groups, they are being read ' +
                                 'through a different slot and only the ' +
                                 'writes are missing.'] });
  }

  if (action === 'create') {
    const name = String(body.group || body.displayName || body.cn || '').trim();
    // THE MEMBERS BOX IS SPLIT ON NEWLINES AND COMMAS, which is where this
    // differs from userFieldsFrom() one section up and is worth saying rather
    // than leaving as an apparent inconsistency: a person's attributes are
    // single-valued facts and the whole value is the value, while `member` is
    // multi-valued by definition and a textarea is how a form offers a list.
    // A JSON caller sends a real array and it is taken as it stands.
    const listed = Array.isArray(body.members)
      ? body.members
      : String(body.members === undefined ? '' : body.members)
          .split(/[\r\n,]+/);
    const members = listed.map(function (one) {
      return String(one == null ? '' : one).trim();
    }).filter(function (one) { return one !== ''; });
    const result = groupWriter.createGroup(name, {
      origin: 'console',
      note: String(body.note || '').trim() ||
            'created by hand on the admin console rather than by a directory ' +
            'client',
      channel: 'console',
      actor: String(body.actor || ''),
      members: members
    });
    if (!result.ok) {
      log.debug("Leaving groupsAction(). create refused.");
      return refusedBy('STS-ADMIN-0527', result);
    }
    log.debug("Leaving groupsAction(). Created " + result.dn + ".");
    return Object.assign({}, result, {
      message: result.dn + ' now exists' +
        (result.members.length
          ? ', listing ' + result.members.length + ' member(s)'
          : ' with no members at all — an empty groupOfNames is something a ' +
            'real directory refuses (RFC 4519 makes `member` MUST) and this ' +
            'one has no schema, so it is here because you asked for it') + '.' +
        (result.dangling.length
          ? ' ' + result.dangling.length + ' of those member value(s) name ' +
            'nothing this directory holds and are written anyway: nothing ' +
            'here does referential integrity, and the Dangling column above ' +
            'is where they show up.'
          : '') +
        ' IT GRANTS NOTHING. No endpoint in this service checks a group, and ' +
        'the only two that decide anything are the console roles on ' +
        '/admin/rbac. What it does change is what a directory client sees ' +
        'and what the groups claim in an issued token says.'
    });
  }

  if (action === 'add-member') {
    const group = String(body.group || '').trim();
    const member = String(body.member || body.user || body.username ||
                          '').trim();
    const result = groupWriter.addGroupMember(group, member, {
      origin: 'console',
      channel: 'console',
      actor: String(body.actor || '')
    });
    if (!result.ok) {
      log.debug("Leaving groupsAction(). add-member refused.");
      return refusedBy('STS-ADMIN-0528', result);
    }
    log.debug("Leaving groupsAction(). " +
              (result.changed ? "Added." : "Already a member."));
    return result;
  }

  log.debug("Leaving groupsAction(). Unknown action.");
  return refused('STS-ADMIN-0500',
                 { ok: false, errors: ['Unknown action "' + action + '". ' +
                               'The two are: create, add-member. Removing a ' +
                               'member is /admin/rbac for the two console ' +
                               'roles, and an ldapmodify or a SCIM PATCH for ' +
                               'every other group; deleting one is an ' +
                               'ldapdelete or a SCIM DELETE.'] });
}

// ---------------------------------------------------------------------------
// POST /admin/applications — the six actions.
//
// **The console is not a second door onto this registry**, and that is the
// whole design of these: every one calls a function in `applications.js` which
// does the same read-modify-write `seen()` does, through the same two
// conversions, against the same `ou=applications` entries. The store stays one
// store; what is added here is a set of controls in front of it. An
// `ldapmodify` and a form post are the same act arriving by two routes, and
// both are visible to the other immediately because nothing caches.
//
// **What may be changed is DECLARED and not DERIVED**, and that line is drawn
// in `applications.js`'s EDITABLE table rather than here: redirect URIs, grant
// types, scopes, the secret, whether the client is confidential —
// configuration, which is what RFC 9700 mode reads — but never the counters,
// the sightings, the kinds or the protocols, which are what happened. LDAP can
// still reach those; the difference between offering an operation and merely
// not preventing it is the point. This handler renders and decides nothing: it
// validates that an action exists and hands the rest over, exactly as the
// console does for groups.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// THE ATTRIBUTE VALUES A CREATE CARRIES, IN THE TWO SPELLINGS THIS FUNCTION IS
// REACHED IN.
//
// The console's form posts one flat field per attribute, named
// `field.<attribute>`, with a multi-valued one holding its values on separate
// lines in a textarea. A JSON caller of POST /admin-api/applications/create
// sends one `fields` object instead, whose members are strings or arrays. Both
// land here as the same object and `applications.normaliseFields()` is the one
// place either is validated — the same arrangement `listField()` gives the
// protocol checkboxes one field up, and for the same reason: two doors onto one
// action must not be two readings of what was sent.
//
// **THE SPLIT IS ON NEWLINES AND DELIBERATELY NOT ON COMMAS OR SPACES.** A
// redirect URI may legally contain both and may not contain a newline, so
// splitting on anything else would cut one URI into two that each fail to match
// — silently, and only in RFC 9700 mode, which is the worst possible place for
// it to surface. `protocols` splits on spaces and commas because a family id is
// a short lower-case word; these are URLs, DNs and URNs.
//
// The prefix is stripped rather than the whole body being scanned for schema
// names, so a future field called `name` or `action` cannot be mistaken for an
// attribute.
// ---------------------------------------------------------------------------
const FIELD_PREFIX = 'field.';

function applicationFieldsFrom(body) {
  log.debug("Entering applicationFieldsFrom().");
  const fields = {};
  // A JSON body's own `fields` object first, so a caller sending both gets the
  // flat fields merged over it rather than one of the two silently winning.
  const given = (body && typeof body.fields === 'object' && body.fields) || {};
  Object.keys(given).forEach(function (name) { fields[name] = given[name]; });
  Object.keys(body || {}).forEach(function (key) {
    if (key.indexOf(FIELD_PREFIX) !== 0) {
      return;
    }
    const name = key.slice(FIELD_PREFIX.length);
    if (!name) {
      return;
    }
    const values = String(body[key] === undefined ? '' : body[key])
      .split(/\r?\n/)
      .map(function (one) { return one.trim(); })
      .filter(function (one) { return one !== ''; });
    if (values.length) {
      fields[name] = values;
    }
  });
  log.debug("Leaving applicationFieldsFrom(). " + Object.keys(fields).length +
      " " +
      "field(s).");
  return fields;
}

// The actions this handler answers, in the order the switch below takes them.
// It exists so that the refusal at the bottom of that switch can be BUILT from
// it rather than typed beside it — see the comment there, and rule 7 in
// ../mgmt-api/CLAUDE.md, which is the rule that sentence serves.
const APPLICATION_ACTIONS = ['create', 'set', 'add', 'remove',
                             'confirm-address', 'discard-address',
                             'regenerate-secret', 'issue-software-statement',
                             'issue-tls-client-certificate',
                             'revoke-tls-client-certificate',
                             'revoke-registration', 'refresh-metadata',
                             'load-resource-metadata', 'forget'];

// `context` is what an action may not derive from a parsed body: the
// authorization servers of the realm the request arrived in, which
// `load-resource-metadata` compares a document against and which are addressed
// by the base URL of the REQUEST. The route computes it and hands it down —
// `listField()`'s arrangement one argument along — so this function still never
// sees `req`.
function applicationsAction(body, protocols, context) {
  log.debug("Entering applicationsAction(). action=" +
            (body.action || '(none)'));
  const action = String(body.action || '');
  const identifier = String(body.application || '').trim();
  const needsOne = ['set', 'add', 'remove', 'confirm-address',
                    'discard-address', 'regenerate-secret',
                    'issue-software-statement',
                    'issue-tls-client-certificate',
                    'revoke-tls-client-certificate',
                    'revoke-registration', 'forget'];
  if (needsOne.indexOf(action) >= 0 && !identifier) {
    log.debug("Leaving applicationsAction(). No application named.");
    return refused('STS-ADMIN-0529', { ok: false, errors: ['Which ' +
                                 'application? Send `application` with the ' +
                                 'identifier exactly as this registry holds ' +
                                 'it — the client_id, wtrealm, AppliesTo, ' +
                                 'entityID or service principal name.'] });
  }

  if (action === 'create') {
    // THE DECLARED PROTOCOL FAMILIES ARRIVE AS A SECOND ARGUMENT rather than
    // off `body`, and that is not ceremony — it is the same arrangement
    // claimsAction() has and it exists for the same reason. A checkbox column
    // is ONE FIELD REPEATED, and helpers.parseBody() builds a plain object, so
    // `body.protocol` is whichever box happened to be ticked last and every
    // other one is silently gone. listField() re-reads the raw body with
    // getAll(); the two routes that reach this function both call it, so the
    // console's form and a JSON body land here as the same list.
    //
    // The fallback to `body.protocols` is for a caller that did not go through
    // either route — a test requiring this module — and it is what keeps the
    // one-argument signature this function used to have working.
    const asked = protocols === undefined
      ? (body.protocols === undefined ? [] : body.protocols)
      : protocols;
    const result = applications.createApplication({
      identifier: String(body.identifier || body.application || ''),
      name: String(body.name || ''),
      // STILL TAKEN, though no form offers it any more: saml2Action() and
      // saml11Action() pass one when they register a service provider, and a
      // JSON caller may. What went was the select that asked a person to guess.
      kind: String(body.kind || ''),
      protocols: asked,
      fields: applicationFieldsFrom(body)
    });
    log.debug("Leaving applicationsAction(). create " +
              (result.ok ? 'ok' : 'refused') + ".");
    if (!result.ok) {
      log.debug("Leaving applicationsAction().");
      return refusedBy('STS-ADMIN-0530', result);
    }
    const declared = result.application.allowedProtocols || [];
    log.debug("Leaving applicationsAction().");
    return { ok: true, application: result.application,
             message: '"' + result.application.identifier + '" is in the ' +
                      'registry. It has authenticated nothing yet — the ' +
                      'counters are zero and the entry says it was created ' +
                      'by hand, so it cannot be mistaken for one that turned ' +
                      'up once. ' +
                      (declared.length
                        ? 'It is DECLARED for ' + declared.join(', ') + ', ' +
                          'which is a note on the entry and not a ' +
                          'permission: nothing in this service reads it, and ' +
                          'this application can still reach every other ' +
                          'protocol here. '
                        : 'No protocol family was declared for it, which ' +
                          'changes nothing about what it may reach — the ' +
                          'declaration is a record of intent. ') +
                      (Object.keys(applicationFieldsFrom(body)).length
                        ? 'The attributes given with it are on the entry ' +
                          'now: a redirect URI among them is what RFC 9700 ' +
                          'mode matches the next authorization request ' +
                          'against, by exact string comparison, and the rest ' +
                          'are recorded rather than checked.'
                        : 'It carries no identifier and no redirect URI yet. ' +
                          'Give it the ones it is allowed and RFC 9700 mode ' +
                          'will judge it against them; without them a ' +
                          'redirect_uri is judged against the ' +
                          'oauth2.redirectUris setting instead — and in ' +
                          'OAuth 2.1 mode it is refused.') };
  }

  if (action === 'set' || action === 'add' || action === 'remove') {
    const result = applications.updateApplication(identifier, {
      mode: action,
      attribute: String(body.attribute || ''),
      value: body.value === undefined ? '' : String(body.value)
    });
    log.debug("Leaving applicationsAction(). " + action + " " +
              (result.ok ? 'ok' : 'refused') + ".");
    return refusedBy('STS-ADMIN-0531', result);
  }

  // ---------------------------------------------------------------------
  // AN OBSERVED RETURN ADDRESS, CONFIRMED OR DISCARDED (2026-09-12).
  //
  // A development-mode request can put a return address on an entry, and
  // `applications.returnAddressesOf()` withholds it in product until it is
  // confirmed — see that function's block. These two are the only controls
  // that decide which way it goes, and they are ACTIONS of this resource
  // rather than a resource of their own because the mark is an attribute of
  // the application: `/admin-api/applications/confirm-address` sits beside
  // `/add` and `/remove`, which it is the provenance-aware sibling of.
  //
  // THE CHANGE IS BUILT FROM THREE NAMED FIELDS, as `set`/`add`/`remove`'s is,
  // so nothing else in the body — an `observed` flag above all — can reach the
  // registry.
  if (action === 'confirm-address' || action === 'discard-address') {
    const change = {
      attribute: String(body.attribute || ''),
      value: body.value === undefined ? '' : String(body.value)
    };
    const result = action === 'confirm-address'
      ? applications.confirmReturnAddress(identifier, change)
      : applications.discardReturnAddress(identifier, change);
    log.debug("Leaving applicationsAction(). " + action + " " +
              (result.ok ? 'ok' : 'refused') + ".");
    return refusedBy('STS-ADMIN-0531', result);
  }

  // ---------------------------------------------------------------------
  // A NEW CLIENT SECRET (2026-09-13), from the Credentials section of the
  // application's own page. Minted by `applications.regenerateClientSecret()`
  // — this action decides nothing about what a secret looks like — and the
  // reply carries it, which is what `/admin-api` hands a caller. The console
  // redirects with the MESSAGE only: the new value is on the page it lands
  // on, behind the same fold the old one was, and a secret in a query string
  // would be a secret in the browser history and every log on the way.
  if (action === 'regenerate-secret') {
    const result = applications.regenerateClientSecret(identifier);
    log.debug("Leaving applicationsAction(). regenerate-secret " +
              (result.ok ? 'ok' : 'refused') + ".");
    return refusedBy('STS-ADMIN-0620', result);
  }

  // ---------------------------------------------------------------------
  // A SOFTWARE STATEMENT, SIGNED AS THIS REALM (RFC 7591 section 2.3,
  // 2026-09-13), from the Software statements section of the application's
  // own page. `software_statement.issue()` decides everything about it —
  // what it may fix, its lifetime, its `iss` — and this action decides only
  // that the base URL comes from the REQUEST's context and never the body,
  // because the `iss` it names is the issuer a registration must then match.
  // The reply carries the statement, which is not a secret.
  if (action === 'issue-software-statement') {
    const ctx = context || {};
    const result = softwareStatement.issue({
      identifier: identifier,
      metadata: body.metadata,
      lifetimeSeconds: body.lifetimeSeconds,
      base: ctx.base || ''
    });
    log.debug("Leaving applicationsAction(). issue-software-statement " +
              (result.ok ? 'ok' : 'refused') + ".");
    return refusedBy('STS-ADMIN-0649', result);
  }

  // ---------------------------------------------------------------------
  // THE ONE ACTION HERE THAT IS ASYNCHRONOUS, and the only one in this console
  // that makes an outbound request.
  //
  // It returns a PROMISE where every other action returns an object, which both
  // dispatchers handle by checking for a `then`. That is a small ugliness and
  // it is deliberately smaller than the alternatives: making every action async
  // would put an `await` in front of forty call sites to serve one, and giving
  // this one its own route would mean a second door onto the applications
  // resource that the parity rule would then have to describe twice.
  //
  // WHY IT IS AN ACTION AND NOT PART OF ISSUING: sp_metadata.js's header argues
  // it at length — an assertion that had to wait on somebody else's web server
  // makes every sign-in as reliable as that server. This writes the certificate
  // onto the entry and issuing reads the entry.
  if (action === 'refresh-metadata') {
    log.debug("Leaving applicationsAction(). Fetching metadata for " +
              identifier + ".");
    return spMetadata.refresh(identifier).then(function (result) {
      return refusedBy('STS-ADMIN-0532', result);
    });
  }

  // RFC 9728 (2026-09-13): READ a protected resource's metadata document —
  // pasted in `document`, uploaded as `file`, or fetched from `url` — and
  // answer with the application it describes. IT CREATES NOTHING; the create is
  // `create`, with the fields this answer proposes. It is an action and not a
  // view because the fetch is an outbound request an administrator causes, and
  // both admin surfaces gate a POST behind Admin Write. A promise, like
  // `refresh-metadata`, for that action's reason.
  if (action === 'load-resource-metadata') {
    const ctx = context || {};
    const file = body.file && typeof body.file === 'object'
      ? body.file
      : (body.file ? { name: String(body.filename || ''),
                       text: String(body.file) } : null);
    log.debug("Leaving applicationsAction(). Loading RFC 9728 metadata.");
    return resourceMetadata.load({ document: body.document, url: body.url,
                                   file: file },
                                 { authorizationServers:
                                     ctx.authorizationServers || [],
                                   actor: ctx.actor || body.actor || '' })
      .then(function (result) {
        return refusedBy('STS-ADMIN-0644', result);
      });
  }

  // ---------------------------------------------------------------------
  // A TLS CLIENT CERTIFICATE FOR THE APPLICATION (RFC 8705, 2026-09-13), from
  // the Credentials section of its own page. `tls_client_certificates.issue()`
  // decides everything about the certificate — the realm's `tls-client`
  // Issuing CA, clientAuth, the urn:sts:application: name the token endpoint's
  // implicit mapping reads, the cap — and packages it; this action decides
  // that the application exists and that the file password is one. A PROMISE,
  // for `refresh-metadata`'s reason: generating the key and exporting the
  // PKCS#12 are asynchronous.
  //
  // **THE REPLY IS THE ONLY COPY OF THE PRIVATE KEY.** Nothing keeps it — not
  // the entry, not the certificate register — so the console draws the reply
  // as a page of downloads rather than redirecting, and `/admin-api` hands the
  // files back in the JSON. The password protecting them is neither stored
  // nor audited.
  if (action === 'issue-tls-client-certificate') {
    const target = applications.get(identifier);
    if (!target) {
      log.debug("Leaving applicationsAction(). No such application.");
      return refused('STS-ADMIN-0722', { ok: false, errors: ['There is no ' +
          'application called "' + identifier + '" here.'] });
    }
    const passwordSaid = tlsClientCertificates.pkcs12PasswordProblem(
      body.password, body.confirm === undefined ? undefined : body.confirm);
    if (passwordSaid) {
      log.debug("Leaving applicationsAction(). The file password.");
      return refused('STS-ADMIN-0721', { ok: false, errors: [passwordSaid] });
    }
    const holder = String(target.identifier);
    return tlsClientCertificates.issue(undefined, {
      kind: 'application', application: holder,
      keyAlg: body.keyAlg || undefined, label: body.label || '',
      days: body.days ? Number(body.days) : undefined
    }).then(function (made) {
      if (!made.ok) {
        log.debug("Leaving applicationsAction(). The issue was refused.");
        return refusedBy('STS-ADMIN-0720', made);
      }
      const issued = made.issued;
      return tlsClientCertificates.bundle(issued, String(body.password))
        .then(function (files) {
          log.debug("Leaving applicationsAction(). A TLS client certificate " +
                    "was issued to " + holder + ".");
          return {
            ok: true,
            message: 'A TLS client certificate was issued to "' + holder +
                     '" (serial ' + issued.serialHex + '). This is the only ' +
                     'time its private key can be downloaded.',
            application: applications.get(holder),
            certificate: {
              serialHex: issued.serialHex, subject: issued.subject,
              keyAlg: issued.keyAlg, label: issued.label,
              notBefore: issued.notBefore, notAfter: issued.notAfter,
              thumbprint: issued.thumbprint,
              certificatePem: issued.certificatePem,
              chainPem: issued.chainPem,
              implicitName: tlsClientCertificates.APPLICATION_URN + holder
            },
            files: files
          };
        });
    });
  }

  // Revoked among THIS application's certificates only, which is
  // `tls_client_certificates.revoke()`'s rule: a serial belonging to anybody
  // else matches nothing.
  if (action === 'revoke-tls-client-certificate') {
    const target = applications.get(identifier);
    if (!target) {
      log.debug("Leaving applicationsAction(). No such application.");
      return refused('STS-ADMIN-0722', { ok: false, errors: ['There is no ' +
          'application called "' + identifier + '" here.'] });
    }
    const done = tlsClientCertificates.revoke(undefined,
      String(target.identifier), String(body.serialHex || ''),
      String(body.reason || ''), 'application');
    if (done.ok) {
      done.message = 'The TLS client certificate ' +
        done.certificate.serialHex + ' of "' + target.identifier + '" was ' +
        'revoked (' + done.reason + '). It no longer authenticates the ' +
        'application at the token endpoint. An access token already bound ' +
        'to it stays usable until it expires: a resource server checks the ' +
        'binding and not the certificate\'s revocation (RFC 8705 section ' +
        '6.2).';
      done.application = applications.get(String(target.identifier));
    }
    log.debug("Leaving applicationsAction(). revoke-tls-client-certificate " +
              (done.ok ? 'ok' : 'refused') + ".");
    return refusedBy('STS-ADMIN-0723', done);
  }

  if (action === 'revoke-registration') {
    // Not a delete: the entry stays and its history with it. This is RFC 7592's
    // delete reached from the console instead of from the client that holds the
    // registration access token — the same function, so the outcome is the same
    // one and not a second reading of what "unregistered" means.
    const before = applications.get(identifier);
    if (!before) {
      log.debug("Leaving applicationsAction().");
      return refused('STS-ADMIN-0533', { ok: false, errors: ['There is no ' +
          'application called "' + identifier + '" ' +
          'here.'] });
    }
    if (!before.registered) {
      log.debug("Leaving applicationsAction().");
      return refused('STS-ADMIN-0534',
                     { ok: false, errors: ['"' + identifier + '" ' +
                                   'has no registration to revoke. It is a ' +
                                   'client_id this service has seen rather ' +
                                   'than one that went through POST ' +
                                   '/oauth2/register, which RFC 9700 mode ' +
                                   'already treats as public.'] });
    }
    applications.forgetRegistration(identifier);
    log.debug("Leaving applicationsAction(). The registration was revoked.");
    return { ok: true, application: applications.get(identifier),
             message: 'The RFC 7591 registration for "' + identifier + '" is ' +
                      'gone, along with its client_secret and its ' +
                      'registration access token. The ENTRY stays, with ' +
                      'everything it had recorded — losing that this ' +
                      'application was ever here because its registration ' +
                      'was withdrawn would be losing the fact rather than ' +
                      'the configuration. The redirect URIs it registered ' +
                      'stay on the entry and are still what a redirect_uri ' +
                      'is matched against; with its secret gone, a ' +
                      'confidential method on the entry has nothing to ' +
                      'check.' };
  }

  if (action === 'forget') {
    const result = applications.deleteApplication(identifier);
    log.debug("Leaving applicationsAction(). forget " +
              (result.ok ? 'ok' : 'refused') + ".");
    return refusedBy('STS-ADMIN-0535', result);
  }

  log.debug("Leaving applicationsAction(). Unknown action.");
  // THE LIST IS BUILT FROM THE SWITCH ABOVE RATHER THAN TYPED, and the reason
  // is that it was typed and went stale: `refresh-metadata` was added on
  // 2026-08-27 and this sentence still said "The six are" and named six. That
  // is not a cosmetic drift — this repository's own tests/vendored/admin_api.js
  // READS this sentence to check that every console action has an /admin-api
  // operation, so an action missing from it is an action the parity check
  // cannot see, and the API could lose the operation entirely with nothing
  // failing. A generated list cannot be short by one.
  return refused('STS-ADMIN-0500',
                 { ok: false, errors: ['Unknown action "' + action + '". ' +
      'The ' +
                               numberWord(APPLICATION_ACTIONS.length) +
                               ' are: ' + APPLICATION_ACTIONS.join(
                                   ', ') + '.'] });
}

function asAction(body) {
  log.debug("Entering asAction(). action=" + (body.action || '(none)'));
  const action = String(body.action || '');
  const id = String(body.profile || body.id || '').trim();

  if (action === 'create') {
    const result = authorizationServers.create({
      id: id, label: String(body.label || ''),
      description: String(body.description || '')
    });
    log.debug("Leaving asAction(). create " + (result.ok ? 'ok' : 'refused') +
              ".");
    if (!result.ok) {
      log.debug("Leaving asAction().");
      return refusedBy('STS-ADMIN-0536', result);
    }
    log.debug("Leaving asAction().");
    return { ok: true, profile: result.profile,
             message: 'The "' + result.profile.id + '" authorization server ' +
                                                    'is published at ' +
                      result.profile.urls.oauth + ' and ' +
                                                    result.profile.urls.oidc +
                                                    '. ' +
                      'It has no overrides yet, so both documents say ' +
                      'exactly what this service says about itself — which ' +
                      'is the right place to start from.' };
  }
  if (action === 'set') {
    const result = authorizationServers.setMember(id, body.member, body.value);
    log.debug("Leaving asAction(). set " + (result.ok ? 'ok' : 'refused') +
              ".");
    return refusedBy('STS-ADMIN-0536', result);
  }
  if (action === 'remove') {
    const result = authorizationServers.removeMember(id, body.member);
    log.debug("Leaving asAction(). remove " + (result.ok ? 'ok' : 'refused') +
              ".");
    return refusedBy('STS-ADMIN-0536', result);
  }
  if (action === 'reset') {
    const result = authorizationServers.resetMember(id, body.member);
    log.debug("Leaving asAction(). reset " + (result.ok ? 'ok' : 'refused') +
              ".");
    return refusedBy('STS-ADMIN-0536', result);
  }
  if (action === 'delete') {
    const result = authorizationServers.remove(id);
    log.debug("Leaving asAction(). delete " + (result.ok ? 'ok' : 'refused') +
              ".");
    return refusedBy('STS-ADMIN-0536', result);
  }
  log.debug("Leaving asAction(). Unknown action.");
  return refused('STS-ADMIN-0500',
                 { ok: false, errors: ['Unknown action "' + action + '". ' +
                               'The five are: create, set, remove, reset, ' +
                               'delete.'] });
}

// ---------------------------------------------------------------------------
// GET /admin/saml2, POST /admin/saml2 — THE SAML 2.0 IDENTITY PROVIDER.
//
// This page exists for ONE question that nothing else here can answer: WHICH
// METADATA DOCUMENT DO I CONFIGURE THIS SERVICE PROVIDER FROM? The profile
// publishes a document PER APPLICATION — a distinct identity provider entityID
// and its own SSO, SLO and artifact endpoints, the way Okta and Ping do it — so
// "the metadata URL" is not one URL, and somebody who has just been handed an
// entityID has no way to derive the slug in its path by hand.
//
// **IT HOLDS NOTHING.** Every row on it comes out of the applications registry,
// which is the embedded directory, and both of its writes go through
// `applications.updateApplication()` — the same function `/admin/applications`
// posts to and the same one an `ldapmodify` reaches. That is the one-store rule
// this console follows everywhere it has been tempted otherwise: a page keeping
// its own copy of a service provider's logout address would be a second answer
// to "where does the LogoutResponse go" that the profile could not see.
//
// **WHY IT IS NOT JUST A FILTER ON /admin/applications**, which was the obvious
// objection and is worth answering rather than leaving: that page reports what
// an application IS and what it has DONE, in the vocabulary of eight protocols
// at once. What a person configuring a service provider needs is four URLs, one
// entityID, and the two settings that decide whether the assertion they are
// about to receive is signed — none of which is a fact about the application at
// all. Three of them are facts about THIS SERVICE. So the drill-down here links
// to that page for the entry and does not reproduce it.
// ---------------------------------------------------------------------------
const SAML2_SP_KIND = 'saml2-service-provider';

// The four writes. Every one of them goes through the applications registry —
// see the header — so this function decides nothing except which attribute and
// which mode, and the registry refuses an attribute that is derived rather than
// declared without being asked twice.
function saml2Action(body) {
  log.debug("Entering saml2Action(). action=" + (body.action || '(none)'));
  const action = String(body.action || '');
  const identifier = String(body.sp || body.serviceProvider || '').trim();
  if (!identifier) {
    log.debug("Leaving saml2Action(). No service provider named.");
    return refused('STS-ADMIN-0537', { ok: false, errors: ['Name the service ' +
        'provider by its entityID, in `sp`.'] });
  }

  if (action === 'register') {
    const result = applications.createApplication({
      identifier: identifier, kind: SAML2_SP_KIND, protocol: 'SAML 2.0',
      note: 'registered as a SAML 2.0 service provider from the admin console',
      fields: { samlEntityId: identifier }
    });
    log.debug("Leaving saml2Action(). register " +
              (result.ok ? 'ok' : 'refused') + ".");
    if (!result.ok) {
      log.debug("Leaving saml2Action().");
      return refusedBy('STS-ADMIN-0530', result);
    }
    log.debug("Leaving saml2Action().");
    return { ok: true, application: result.application,
             message: 'Registered. Its identity provider metadata is at ' +
                      '/saml2/metadata/' +
                      encodeURIComponent(saml2.slugOf(identifier)) + ', and ' +
                      'it would have been created by the first AuthnRequest ' +
                      'or metadata fetch anyway — registering it early is ' +
                      'what gives you a document to hand somebody now.' };
  }
  if (action === 'set-logout-service' || action === 'remove-logout-service') {
    const result = applications.updateApplication(identifier, {
      attribute: 'samlSingleLogoutService',
      mode: action === 'set-logout-service' ? 'add' : 'remove',
      value: String(body.value || '')
    });
    log.debug("Leaving saml2Action(). " + action + " " +
              (result.ok ? 'ok' : 'refused') + ".");
    return refusedBy('STS-ADMIN-0531', result);
  }
  if (action === 'set-signing-certificate') {
    const result = applications.updateApplication(identifier, {
      attribute: 'samlSigningCertificate', mode: 'set',
      // Whitespace and any PEM armour stripped, because what the schema holds
      // is base64 DER — which is what a ds:X509Certificate carries and what the
      // metadata publishes. A PEM pasted in here would be stored as something
      // no reader of that attribute expects, and nothing would say so until the
      // day something tried to use it.
      value: String(body.value || '').replace(/-----[^-]+-----/g, '')
                                     .replace(/\s+/g, '')
    });
    log.debug("Leaving saml2Action(). set-signing-certificate " +
              (result.ok ? 'ok' : 'refused') + ".");
    return refusedBy('STS-ADMIN-0531', result);
  }
  log.debug("Leaving saml2Action(). Unknown action.");
  return refused('STS-ADMIN-0500',
                 { ok: false, errors: ['Unknown action "' + action + '". ' +
                               'The four are: register, set-logout-service, ' +
                               'remove-logout-service, ' +
                               'set-signing-certificate.'] });
}

// ---------------------------------------------------------------------------
// GET /admin/saml11, POST /admin/saml11 — THE SAML 1.1 IDENTITY PROVIDER.
//
// The same question /admin/saml2 exists for — WHICH METADATA DOCUMENT DO I
// CONFIGURE THIS RELYING PARTY FROM — and a second question that page never has
// to answer: **WHAT IS THIS RELYING PARTY CALLED?** SAML 1.1 has no request
// message, so nothing in the protocol makes a relying party identify itself.
// The profile takes the name from Shibboleth's `providerId` parameter, from the
// path segment, or it GUESSES from the origin of the TARGET. A guessed audience
// is the one thing on this page that is not a fact, and it is marked as such,
// because an assertion whose audience is `https://app.example.com` when the
// relying party expected `urn:example:app` fails inside a signature check with
// nothing saying why.
//
// **IT IS A SEPARATE PAGE FROM /admin/saml2 AND THAT IS NOT SYMMETRY FOR ITS
// OWN SAKE**, which was the obvious objection: half of what that page reports
// has no spelling here. There is no Single Logout in SAML 1.1, so there is no
// logout return address to declare and no `saml11.defaultSingleLogoutService`
// to fall back to. There is no request, so there is no request signature to
// record and no signing certificate to hold. What this page has instead is the
// artifact profile's own state and an attribute authority the 2.0 profile does
// not offer. One page with two modes would have been a page whose every row
// needed a footnote.
//
// **IT HOLDS NOTHING**, like every page in this console: every row comes out of
// the applications registry, which is the embedded directory, and its one write
// goes through `applications.createApplication()` — the same function
// /admin/applications posts to and the same one an `ldapadd` reaches.
// ---------------------------------------------------------------------------
const SAML11_RP_KIND = saml11.RP_KIND;

// ONE action, where /admin/saml2 has four, and the three it does not have are
// the three SAML 1.1 has no protocol for: a logout service to declare, a
// request signature to record, and a signing certificate to hold it in.
function saml11Action(body) {
  log.debug("Entering saml11Action(). action=" + (body.action || '(none)'));
  const action = String(body.action || '');
  const identifier = String(body.rp || body.relyingParty || '').trim();
  if (!identifier) {
    log.debug("Leaving saml11Action(). No relying party named.");
    return refused('STS-ADMIN-0538', { ok: false, errors: ['Name the relying ' +
        'party by its identifier, in `rp`.'] });
  }

  if (action === 'register') {
    const result = applications.createApplication({
      identifier: identifier, kind: SAML11_RP_KIND, protocol: 'SAML 1.1',
      note: 'registered as a SAML 1.1 relying party from the admin console',
      fields: { samlEntityId: identifier }
    });
    log.debug("Leaving saml11Action(). register " +
              (result.ok ? 'ok' : 'refused') + ".");
    if (!result.ok) {
      log.debug("Leaving saml11Action().");
      return refusedBy('STS-ADMIN-0530', result);
    }
    log.debug("Leaving saml11Action().");
    return { ok: true, application: result.application,
             message: 'Registered. Its identity provider metadata is at ' +
                      '/saml11/metadata/' +
                      encodeURIComponent(saml11.slugOf(identifier)) + ', and ' +
                      'it would have been created by the first flow or ' +
                      'metadata fetch anyway — registering it early is what ' +
                      'gives you a document to hand somebody now, and a name ' +
                      'to put in providerId so that nothing has to be ' +
                      'guessed.' };
  }
  log.debug("Leaving saml11Action(). Unknown action.");
  return refused('STS-ADMIN-0500',
                 { ok: false, errors: ['Unknown action "' + action + '". ' +
      'There is one: register.'] });
}

// The two acts, through the one switch that has them — **BEHIND A GUARD OF ITS
// OWN, and that guard is not ceremony.**
//
// `tests/vendored/sts_admin_api_operations.js` compares an action resource's
// REFUSAL SENTENCE against the operations the OpenAPI document declares for it,
// in both directions, because `tests/vendored/admin_api.js`'s parity check
// reads that sentence to discover what to look for. A bare delegation to
// `usersAction()` therefore answered `/admin-api/mfa/no-such-action` by naming
// all five actions the USERS resource has — so this resource claimed to offer
// `create`, `set-password` and `issue-activation`, which it does not and must
// not. It went red on the first full run, which is exactly what that assertion
// is for.
//
// So the repertoire is stated here and the WORK is not duplicated: an action
// outside these two is refused in this resource's own words, and the two that
// belong to it are handed to the one switch that performs them.
const MFA_ACTIONS = ['clear-totp', 'clear-key'];

function mfaAction(body, context) {
  log.debug("Entering mfaAction(). action=" + (body.action || '(none)'));
  const action = String(body.action || '');
  if (MFA_ACTIONS.indexOf(action) < 0) {
    log.debug("Leaving mfaAction(). Not an action of this resource.");
    return refused('STS-ADMIN-0500',
                   { ok: false, errors: ['Unknown action "' + action + '". ' +
        'There are ' +
                                 MFA_ACTIONS.length + ': ' +
                                 MFA_ACTIONS.join(' and ') + '. The rest of ' +
                                 'what can be done to a person is on ' +
                                 '/admin-api/users, which is also where ' +
                                 'these two answer.'] });
  }
  log.debug("Leaving mfaAction(). Handing " + action + " to usersAction().");
  return usersAction(body, context);
}

// Both writes, and neither decides anything: admin_rbac.js holds the rules and
// this reads two fields off a body. `actor` is threaded through so the
// `admin.role.change` audit row can say WHO made the grant — the one question
// an audit log of permissions changes exists to answer, and the one nothing
// else on the row could reconstruct.
function rbacAction(body, context) {
  log.debug("Entering rbacAction(). action=" + (body.action || '(none)'));
  const action = String(body.action || '');
  const username = String(body.username || body.user || '').trim();
  const role = String(body.role || '').trim();
  // THE ROSTER OF THE REALM BEING READ (2026-09-14, #32): the default realm's
  // is the service roster, any other realm's its own. A realm administrator
  // reaches only their own realm's page, which the gate has decided before
  // this runs.
  const ctx = { via: (context || {}).via || 'console',
                actor: (context || {}).actor || '',
                realm: realms.currentId() };

  if (action === 'grant') {
    const result = rbac.grant(username, role, ctx);
    log.debug("Leaving rbacAction(). grant " +
              (result.ok ? "ok." : "refused."));
    return refusedBy('STS-ADMIN-0539', result);
  }
  if (action === 'revoke') {
    const result = rbac.revoke(username, role, ctx);
    log.debug("Leaving rbacAction(). revoke " +
              (result.ok ? "ok." : "refused."));
    return refusedBy('STS-ADMIN-0539', result);
  }

  log.debug("Leaving rbacAction(). Unknown action.");
  return refused('STS-ADMIN-0500',
                 { ok: false, errors: ['Unknown action "' + action + '". ' +
                               'There are two: grant and revoke.'] });
}

// BUILT FROM THE SWITCH BELOW RATHER THAN TYPED, for the reason
// PERMISSION_ACTIONS gives at its own site: this repository's own
// tests/vendored/admin_api.js READS the refusal sentence to check that every
// console action has an /admin-api operation, so a list that is short by one is
// a list that turns the parity check off for that action.
const CONSENT_ACTIONS = ['grant-global-consent', 'revoke-global-consent',
                         'revoke-consent', 'forget-user-consent'];

function consentAction(body) {
  log.debug("Entering consentAction(). action=" + (body.action || '(none)'));
  const action = String(body.action || '');
  const actor = String(body.actor || '');
  // `client` for the application half and `username` for the person half, named
  // apart for `permissionsAction()`'s reason: this is another feature where a
  // body naming the wrong field still succeeds and writes the right-looking
  // thing onto the wrong entry. `application` is accepted for `client` as a
  // convenience for a caller editing one entry.
  const client = String(body.client || body.application || '').trim();
  const username = String(body.username || body.user || '').trim();
  const scope = String(body.scope || '').trim();

  if (action === 'grant-global-consent') {
    const result = consent.grantGlobal(client, scope, actor);
    log.debug("Leaving consentAction(). grant-global-consent " +
              (result.ok ? 'ok' : 'refused') + ".");
    return refusedBy('STS-ADMIN-0540', result);
  }

  if (action === 'revoke-global-consent') {
    const result = consent.revokeGlobal(client, scope, actor);
    log.debug("Leaving consentAction(). revoke-global-consent " +
              (result.ok ? 'ok' : 'refused') + ".");
    return refusedBy('STS-ADMIN-0540', result);
  }

  if (action === 'revoke-consent') {
    const result = consent.revoke(username, client, scope, actor);
    if (result.ok) {
      // THE AUDIT ROW IS WRITTEN HERE AND NOT IN consent.js, and that is the
      // same division `rbacAction()` has: the actor is the person whose session
      // got them through the gate, and the module underneath has no request to
      // read one from. `consent_screen.js` writes its own row for the same
      // reason from the other side — there the actor is the person consenting.
      auditLog.audit({ action: 'consent.revoke', actor: actor, target: client,
                    protocol: 'OAuth 2.0 / OIDC', channel: 'http',
                    detail: 'revoked "' + scope + '" for ' + username });
    }
    log.debug("Leaving consentAction(). revoke-consent " +
              (result.ok ? 'ok' : 'refused') + ".");
    return refusedBy('STS-ADMIN-0540', result);
  }

  if (action === 'forget-user-consent') {
    const result = consent.forget(username, actor);
    if (result.ok) {
      auditLog.audit({ action: 'consent.revoke', actor: actor, target: username,
                    protocol: 'OAuth 2.0 / OIDC', channel: 'http',
                    detail: 'forgot every consent (' + result.removed +
                            ') for ' + username });
    }
    log.debug("Leaving consentAction(). forget-user-consent " +
              (result.ok ? 'ok' : 'refused') + ".");
    return refusedBy('STS-ADMIN-0540', result);
  }

  log.debug("Leaving consentAction(). Unknown action.");
  return refused('STS-ADMIN-0500',
                 { ok: false, errors: ['Unknown action "' + action + '". ' +
      'The ' +
                               numberWord(CONSENT_ACTIONS.length) + ' are: ' +
                               CONSENT_ACTIONS.join(', ') + '.'] });
}

// BUILT FROM THE SWITCH BELOW RATHER THAN TYPED, for CONSENT_ACTIONS' reason:
// this repository's own tests/vendored/admin_api.js READS the refusal sentence
// to check that every console action has an /admin-api operation, so a list
// that is short by one turns the parity check off for that action.
const ROLE_ACTIONS = ['create-role', 'delete-role', 'add-member',
                      'remove-member', 'describe-role'];

// The three kinds of thing that can hold a role, in one table because four
// places have to agree about them — the two member actions, the console's
// select, the management API's enum and the register's own attribute names.
const ROLE_MEMBER_KINDS = [
  { kind: 'user', label: 'a person', field: 'users',
    what: 'A username. The person need not exist yet: this service creates a ' +
          'directory entry for any name on first sight, so a role can be ' +
          'granted before its holder has ever signed in.' },
  { kind: 'group', label: 'a group', field: 'groups',
    what: 'A group in ou=groups. Every member of it holds the role, resolved ' +
          'at DECISION TIME rather than expanded on write — so an ldapmodify ' +
          'adding somebody to the group changes the very next token.' },
  { kind: 'application', label: 'an application', field: 'applications',
    what: 'An application that holds the role AS ITSELF. This is what a ' +
          'client_credentials grant is decided on, where there is no person ' +
          'at all, and it is the reason an application is a first-class ' +
          'member of a role here.' }
];

function roleMemberKindOf(kind) {
  log.debug("Entering roleMemberKindOf().");
  log.debug("Leaving roleMemberKindOf().");
  return ROLE_MEMBER_KINDS.filter(function (one) {
    return one.kind === String(kind);
  })[0] || null;
}

// ---------------------------------------------------------------------------
// THE FIVE WRITES. Every one of them goes through `common/roles.js`, which
// holds the rules — the name grammar, the refusal to shadow a built-in one,
// and the cap — so this function reads fields off a body and decides nothing.
// It is the same division `rbacAction()` has with `admin_rbac.js`.
// ---------------------------------------------------------------------------
function rolesAction(body, context) {
  log.debug("Entering rolesAction(). action=" + (body.action || '(none)'));
  const action = String(body.action || '');
  const ctx = context || {};
  const actor = String(ctx.actor || body.actor || '');
  const name = String(body.role || body.name || '').trim();
  const kind = String(body.kind || '').trim();
  // `member` for the thing being added and never `name`, which is the ROLE's.
  // Named apart for `permissionsAction()`'s reason: this is another feature
  // where a body naming the wrong field still succeeds and writes the
  // right-looking thing into the wrong place — here, a role called `alice`.
  const member = String(body.member || '').trim();
  const description = String(body.description || '');

  if (action === 'create-role') {
    const existing = roles.read(name);
    if (existing) {
      log.debug("Leaving rolesAction(). create-role refused: it is there.");
      return refused('STS-ADMIN-0541', { ok: false, errors: ['There is ' +
          'already a role called "' + name +
                                   '". Roles are edited in place — add a ' +
                                   'member to it rather than creating it ' +
                                   'again.'] });
    }
    const result = roles.write(name, { description: description });
    if (result.ok) {
      auditLog.audit({ action: 'roles.create', actor: actor, target: name,
                    protocol: 'XACML', channel: 'http',
                    detail: 'created the role "' + name + '"' });
    }
    log.debug("Leaving rolesAction(). create-role " +
              (result.ok ? 'ok.' : 'refused.'));
    return result.ok ? result
      : refused(innerCode(result) || 'STS-ADMIN-0542',
                { ok: false, errors: [result.why] });
  }

  if (action === 'delete-role') {
    // WHAT STILL REQUIRES IT IS REPORTED AND THE DELETE STILL HAPPENS, which
    // is deliberate and is the more useful of the two behaviours. Refusing
    // would mean a role could not be removed until every application that
    // named it had been edited, and the application entries are the things
    // somebody is usually in the middle of changing. The reply names them, so
    // the consequence — those applications now require a role NOBODY holds,
    // and are therefore issued nothing — is said at the moment it is created
    // rather than discovered later as a service that stopped working.
    const stillRequired = applications.list().filter(function (row) {
      return applications.requiredRolesOf(row.identifier)
        .some(function (one) { return one === name; });
    }).map(function (row) { return row.identifier; });
    const result = roles.remove(name);
    if (!result.ok) {
      log.debug("Leaving rolesAction(). delete-role refused.");
      return refused(innerCode(result) || 'STS-ADMIN-0542',
                     { ok: false, errors: [result.why] });
    }
    auditLog.audit({ action: 'roles.delete', actor: actor, target: name,
                  protocol: 'XACML', channel: 'http',
                  detail: 'deleted the role "' + name + '"' +
                          (stillRequired.length
                             ? '; still required by ' + stillRequired.join(', ')
                             : '') });
    log.debug("Leaving rolesAction(). delete-role ok.");
    return { ok: true, name: name, stillRequired: stillRequired,
             message: 'The role "' + name + '" is gone.' +
                      (stillRequired.length
                         ? ' ' + numberWord(stillRequired.length) +
                           ' application(s) still require it and can now be ' +
                           'issued nothing: ' + stillRequired.join(', ') +
                           '. Clear appRequiredRole on each, or create the ' +
                           'role again.'
                         : '') };
  }

  if (action === 'describe-role') {
    const row = roles.read(name);
    if (!row) {
      log.debug("Leaving rolesAction(). describe-role refused.");
      return refused('STS-ADMIN-0543', { ok: false, errors: ['There is no ' +
          'role called "' + name + '".'] });
    }
    // THE WHOLE RECORD IS WRITTEN BACK and not just the description, because
    // `roles.write()` REPLACES an entry — a write carrying only the
    // description would empty the membership, which is the one mistake in this
    // file that would be silent and total.
    const result = roles.write(name, {
      description: description, users: row.users, groups: row.groups,
      applications: row.applications
    });
    log.debug("Leaving rolesAction(). describe-role " +
              (result.ok ? 'ok.' : 'refused.'));
    return result.ok ? result
      : refused(innerCode(result) || 'STS-ADMIN-0542',
                { ok: false, errors: [result.why] });
  }

  if (action === 'add-member' || action === 'remove-member') {
    const kindRow = roleMemberKindOf(kind);
    if (!kindRow) {
      log.debug("Leaving rolesAction(). Unknown member kind.");
      return refused('STS-ADMIN-0544', { ok: false, errors: ['"' + kind + '" ' +
                                   'is not a kind of member. There are ' +
                                   'three: ' +
                                   ROLE_MEMBER_KINDS.map(function (one) {
                                     return one.kind;
                                   }).join(', ') + '.'] });
    }
    if (!member) {
      log.debug("Leaving rolesAction(). No member named.");
      return refused('STS-ADMIN-0545', { ok: false, errors: ['`member` names ' +
          'the ' + kindRow.label +
                                   ' being ' + (action === 'add-member'
                                     ? 'added to' : 'removed from') +
                                   ' the role, and it is required. `role` is ' +
                                   'the role\'s own name.'] });
    }
    const row = roles.read(name);
    if (!row) {
      // A BUILT-IN ROLE IS NAMED IN THE REFUSAL RATHER THAN FALLING THROUGH TO
      // "no such role", because that is the mistake somebody will actually
      // make: the six built-in roles are in every menu on this page, they have
      // no members and cannot be given any, and "there is no role called
      // ALL_AUTHENTICATED_USERS" would be a flatly false sentence about a role
      // the page had just drawn.
      if (roles.isBuiltIn(name)) {
        log.debug("Leaving rolesAction(). Built-in role.");
        return refused('STS-ADMIN-0546',
                       { ok: false, errors: ['"' + name + '" ' +
                                     'is a BUILT-IN role. It is COMPUTED ' +
                                     'from the context of each decision ' +
                                     'rather than stored, so it has no ' +
                                     'membership to edit — everybody who ' +
                                     'matches it holds it, always. Create a ' +
                                     'role of your own to give somebody ' +
                                     'something they do not already have.'] });
      }
      log.debug("Leaving rolesAction(). No such role.");
      return refused('STS-ADMIN-0543', { ok: false, errors: ['There is no ' +
          'role called "' + name +
                                   '". Create it first.'] });
    }
    const held = {
      users: row.users.slice(), groups: row.groups.slice(),
      applications: row.applications.slice()
    };
    const list = held[kindRow.field];
    // Case-insensitively, for `roles.js`'s reason: a username here arrives
    // from a login form, a SAML subject, a Kerberos principal and a client_id,
    // and this service has always treated those as one identity however they
    // were typed.
    const at = list.map(function (one) {
      return String(one).toLowerCase();
    }).indexOf(member.toLowerCase());
    if (action === 'add-member') {
      if (at >= 0) {
        log.debug("Leaving rolesAction(). Already a member.");
        return refused('STS-ADMIN-0547',
                       { ok: false, errors: ['"' + member + '" ' +
            'already holds "' +
                                     name + '" as ' + kindRow.label + '.'] });
      }
      list.push(member);
    } else {
      if (at < 0) {
        log.debug("Leaving rolesAction(). Not a member.");
        return refused('STS-ADMIN-0548',
                       { ok: false, errors: ['"' + member + '" ' +
            'does not hold "' +
                                     name + '" as ' + kindRow.label + '.'] });
      }
      list.splice(at, 1);
    }
    const result = roles.write(name, {
      description: row.description, users: held.users, groups: held.groups,
      applications: held.applications
    });
    if (!result.ok) {
      log.debug("Leaving rolesAction(). The write was refused.");
      return refused(innerCode(result) || 'STS-ADMIN-0542',
                     { ok: false, errors: [result.why] });
    }
    auditLog.audit({
      action: action === 'add-member' ? 'roles.grant' : 'roles.revoke',
      actor: actor, target: member, protocol: 'XACML', channel: 'http',
      detail: (action === 'add-member' ? 'gave ' : 'took ') + kindRow.label +
              ' "' + member + '" the role "' + name + '"' +
              (action === 'add-member' ? '' : ' away') });
    log.debug("Leaving rolesAction(). " + action + " ok.");
    return { ok: true, role: name, kind: kind, member: member,
             message: action === 'add-member'
               ? '"' + member + '" now holds "' + name + '".'
               : '"' + member + '" no longer holds "' + name + '".' };
  }

  log.debug("Leaving rolesAction(). Unknown action.");
  return refused('STS-ADMIN-0500',
                 { ok: false, errors: ['Unknown action "' + action + '". ' +
      'The ' +
                               numberWord(ROLE_ACTIONS.length) + ' are: ' +
                               ROLE_ACTIONS.join(', ') + '.'] });
}

// ---------------------------------------------------------------------------
// THE PASSWORD POLICY'S TWO WRITES (2026-09-12), behind /admin/policies and
// POST /admin-api/policies/{action}.
//
// Every rule — which profile names may exist, what each field may be, how two
// fields relate — is in `common/password_policy.js`, so this reads a body and
// decides nothing, which is the division `rolesAction()` has with `roles.js`.
//
// **A SAVE REPLACES THE WHOLE PROFILE AND THE BODY CARRIES EVERY FIELD.** The
// console's form always does; an API caller that leaves one out is refused by
// name rather than having it reset to a default, because a save that quietly
// loosened a rule nobody mentioned is the one mistake here that nobody sees.
// `form: 'console'` is what tells the module an absent checkbox means "no".
// ---------------------------------------------------------------------------
const PASSWORD_POLICY_ACTIONS = ['save-password-policy',
                                 'reset-password-policy'];

function passwordPoliciesAction(body, context) {
  log.debug("Entering passwordPoliciesAction(). action=" +
            (body.action || '(none)'));
  const action = String(body.action || '');
  const ctx = context || {};
  const actor = String(ctx.actor || body.actor || '');
  const profileName = String(body.profile ||
                             passwordPolicy.DEFAULT_PROFILE).trim();
  const before = passwordPolicy.read(passwordPolicy.DEFAULT_PROFILE);
  const valuesOf = function (profile) {
    log.debug("Entering valuesOf().");
    const out = {};
    passwordPolicy.FIELDS.forEach(function (field) {
      out[field.key] = profile[field.key];
    });
    log.debug("Leaving valuesOf().");
    return out;
  };

  if (action === 'save-password-policy') {
    const given = Object.assign({}, body);
    if (ctx.via === 'console') {
      given.form = 'console';
    }
    const result = passwordPolicy.save(profileName, given);
    if (!result.ok) {
      log.debug("Leaving passwordPoliciesAction(). save refused.");
      return refused(innerCode(result) || 'STS-ADMIN-0549',
                     { ok: false, errors: result.errors });
    }
    auditLog.audit({
      action: 'admin.password-policy.change', actor: actor,
      target: result.profile.dn, channel: 'http',
      summary: 'saved the password policy profile "' + result.profile.name +
               '"',
      detail: { via: ctx.via || '', before: valuesOf(before),
                after: valuesOf(result.profile) }
    });
    log.debug("Leaving passwordPoliciesAction(). saved.");
    return { ok: true, profile: result.profile,
             rules: passwordPolicy.describe(result.profile),
             enforced: result.profile.enforced,
             message: 'The password policy profile "' + result.profile.name +
                      '" is saved at ' + result.profile.dn + '. It applies ' +
                      'to the NEXT password set in this realm and to nothing ' +
                      'already stored' +
                      (result.profile.enforced ? '.'
                        : ' — and it is not enforced here until this realm ' +
                          'is in product mode.') };
  }

  if (action === 'reset-password-policy') {
    const result = passwordPolicy.reset(profileName);
    if (!result.ok) {
      log.debug("Leaving passwordPoliciesAction(). reset refused.");
      return refused(innerCode(result) || 'STS-ADMIN-0550',
                     { ok: false, errors: result.errors });
    }
    if (result.removed) {
      auditLog.audit({
        action: 'admin.password-policy.change', actor: actor,
        target: before.dn, channel: 'http',
        summary: 'put the password policy profile "' + before.name + '" back ' +
                 'to the built-in defaults',
        detail: { via: ctx.via || '', before: valuesOf(before),
                  after: valuesOf(result.profile) }
      });
    }
    log.debug("Leaving passwordPoliciesAction(). reset.");
    return { ok: true, removed: result.removed, profile: result.profile,
             rules: passwordPolicy.describe(result.profile),
             message: result.removed
               ? 'The stored profile is gone and the built-in defaults are ' +
                 'in ' +
                 'force: ' +
                 passwordPolicy.describe(result.profile).join(', ') + '.'
               : 'Nothing was stored, so the built-in defaults were already ' +
                 'in force.' };
  }

  log.debug("Leaving passwordPoliciesAction(). Unknown action.");
  return refused('STS-ADMIN-0500',
                 { ok: false, errors: ['Unknown action "' + action + '". ' +
      'The two are: ' +
                               PASSWORD_POLICY_ACTIONS.join(', ') + '.'] });
}

// ---------------------------------------------------------------------------
// GET /admin/claims, POST /admin/claims
// GET /admin/saml-attributes, POST /admin/saml-attributes
// ---------------------------------------------------------------------------
// TWO PAGES, ONE ACTION FUNCTION AND ONE STORE. The four claim sets used to be
// four sections of /admin/claims; since 2026-08-24 the two JWT sets are there
// and the two SAML ones are on /admin/saml-attributes, under the console's own
// SAML group. What did NOT split is anything underneath: `CLAIM_SETS` is one
// object in admin_stats.js, `setClaimSet()` is the one door onto it, and this
// one function is what both pages and both /admin-api resources post to. A
// second action function would have been a second set of rules about reserved
// names and duplicates that agreed with the first until one of them changed.
//
// `names` is the second argument for the same reason vcAction() has one: a list
// that may appear more than once in a form body is not something
// helpers.parseBody() can answer, so the caller reads it with listField() and
// hands it in. It is only read by the `attributes` action; the other six ignore
// it.
//
// `allowed` is the third and it is what makes the SPLIT real rather than
// cosmetic: it is the set ids the door being knocked on carries, so a POST to
// /admin/claims naming `saml2` is refused by name instead of quietly changing a
// set whose page it is not on and then redirecting to a page that cannot show
// what it did. It defaults to all four, which is what a caller that has not
// been given a family — nothing today — would get.
function claimsAction(body, names, allowed) {
  log.debug("Entering claimsAction(). action=" + (body.action || '(none)'));
  const action = String(body.action || '');
  const setId = String(body.set || '');
  const sets = allowed && allowed.length ? allowed : stats.CLAIM_SET_IDS;
  if (sets.indexOf(setId) < 0) {
    log.debug("Leaving claimsAction(). No such set here.");
    return refused('STS-ADMIN-0551', { ok: false, errors: ['There is no ' +
        'claim set called "' + setId + '" ' +
                                 'here. The ones this door carries ' +
                                 'are: ' + sets.join(', ') + '.'] });
  }
  const label = stats.CLAIM_SETS[setId].label;

  if (action === 'add') {
    const entry = { name: String(body.name || '').trim(),
                    value: String(body.value == null ? '' : body.value) };
    if (body.nameFormat) entry.nameFormat = String(body.nameFormat).trim();
    if (body.namespace) entry.namespace = String(body.namespace).trim();
    const result = stats.setClaimSet(setId,
                                     stats.claimSet(setId).concat([entry]));
    log.debug("Leaving claimsAction(). add -> ok=" + result.ok);
    return result.ok
      ? { ok: true, set: setId, claims: result.claims,
          message: 'Added "' + entry.name + '" to the ' + label + ' claim ' +
                   'set. Every one of those issued from now on carries it; ' +
                   'nothing already issued changes.' }
      : refusedBy('STS-ADMIN-0552', result);
  }

  if (action === 'remove') {
    const name = String(body.name || '').trim();
    const remaining = stats.claimSet(setId)
                           .filter(function (c) { return c.name !== name; });
    if (remaining.length === stats.claimSet(setId).length) {
      log.debug("Leaving claimsAction(). Nothing named that.");
      return refused('STS-ADMIN-0553',
                     { ok: false, errors: ['The ' + label + ' ' +
          'claim set has no claim called "' + name + '".'] });
    }
    const result = stats.setClaimSet(setId, remaining);
    log.debug("Leaving claimsAction(). remove -> ok=" + result.ok);
    return result.ok
      ? { ok: true, set: setId, claims: result.claims,
          message: 'Removed "' + name + '" from the ' + label + ' claim set.' }
      : refusedBy('STS-ADMIN-0552', result);
  }

  if (action === 'clear') {
    stats.setClaimSet(setId, []);
    log.debug("Leaving claimsAction(). Cleared.");
    return { ok: true, set: setId, claims: [],
             message: 'The ' + label + ' claim set is empty again.' };
  }

  if (action === 'replace') {
    let entries = body.claims;
    if (typeof entries === 'string') {
      try {
        entries = JSON.parse(entries || '[]');
      } catch (e) {
        log.debug("Leaving claimsAction(). The JSON did not parse.");
        return refused('STS-ADMIN-0554', { ok: false, errors: ['That is not ' +
            'valid JSON: ' + e.message] });
      }
    }
    if (!Array.isArray(entries)) {
      log.debug("Leaving claimsAction(). Not an array.");
      return refused('STS-ADMIN-0555', { ok: false, errors: ['Give a JSON ' +
                                   'ARRAY of {"name": ..., "value": ...} ' +
                                   'objects. An empty array clears the ' +
                                   'set.'] });
    }
    const result = stats.setClaimSet(setId, entries);
    log.debug("Leaving claimsAction(). replace -> ok=" + result.ok);
    return result.ok
      ? { ok: true, set: setId, claims: result.claims,
          message: 'The ' + label + ' claim set now has ' +
              result.claims.length + ' ' +
              'custom claim(s).' }
      : refusedBy('STS-ADMIN-0552', result);
  }

  // ------------------------------------------------------------------------
  // The three that act on the DIRECTORY ATTRIBUTE half of a set rather than on
  // the typed claims above.
  //
  // They are three actions and not one with a mode, because each is a different
  // thing to authorise and a different row in the audit log: `attributes`
  // carries a list somebody chose, and the other two carry nothing and mean the
  // extremes. A single action taking a list would make "select all" a caller's
  // job to construct — the whole catalogue in a POST body to say "all of them"
  // — which is a list that has to be updated every time the catalogue is.
  //
  // What the split does NOT do is make an empty `attributes` unambiguous, and
  // it is worth being plain about that rather than implying otherwise. An empty
  // list and an absent one both mean "the selection is nothing", so a caller
  // that misspells the field clears the set. Three things make that recoverable
  // rather than silent, and they are the reason it is not refused instead: the
  // reply names every attribute it `removed`, the audit log keeps a row saying
  // the same, and unticking every box and pressing Update is a legitimate way
  // to clear a set that a refusal would have to break. `attributes-clear`
  // exists so that a caller which MEANS it can say so, and so that the
  // console's button does not depend on submitting an empty form.
  //
  // The console's buttons are form posts for the same reason every other
  // control here is: app.js sets `script-src 'none'` for the whole service, so
  // a browser-side "tick every box" is not available and would not be taken if
  // it were — a server-side select-all leaves an audit row, and a scripted one
  // would leave the boxes ticked and the set unchanged until somebody pressed
  // Update.
  // ------------------------------------------------------------------------
  if (action === 'attributes') {
    const result = claimAttributes.setSelection(setId, names || [], 'select');
    log.debug("Leaving claimsAction(). attributes -> ok=" + result.ok);
    return result.ok
      ? { ok: true, set: setId, attributes: result.attributes,
          added: result.added, removed: result.removed,
          message: 'The ' + label + ' set now carries ' +
                   result.attributes.length +
                   ' directory attribute(s): ' + (result.attributes.join(
                       ', ') || '(none)') +
                   '. Every one of those issued from now on carries them, ' +
                   'with the value on that person\'s entry; nothing already ' +
                   'issued changes.' }
      : refusedBy('STS-ADMIN-0552', result);
  }

  if (action === 'attributes-all') {
    const result = claimAttributes.selectAll(setId);
    log.debug("Leaving claimsAction(). attributes-all -> ok=" + result.ok);
    return result.ok
      ? { ok: true, set: setId, attributes: result.attributes,
          added: result.added, removed: result.removed,
          message: 'The ' + label + ' set now carries every attribute in the ' +
                                    'catalogue — ' +
                   result.attributes.length + ' of them. That is a ' +
                   'legitimate thing to test and it makes a large token; it ' +
                   'is not a mistake this page will correct.' }
      : refusedBy('STS-ADMIN-0552', result);
  }

  if (action === 'attributes-clear') {
    const result = claimAttributes.clearSelection(setId);
    log.debug("Leaving claimsAction(). attributes-clear -> ok=" + result.ok);
    return result.ok
      ? { ok: true, set: setId, attributes: [], added: [],
          removed: result.removed,
          message: 'The ' + label + ' set carries no directory attribute ' +
                                    'again. Removed: ' +
                   (result.removed.join(', ') || 'nothing — it was already ' +
                                                 'empty') + '. ' +
                   'The typed claims on this set, if any, are untouched.' }
      : refusedBy('STS-ADMIN-0552', result);
  }

  log.debug("Leaving claimsAction(). Unknown action.");
  return refused('STS-ADMIN-0500',
                 { ok: false, errors: ['Unknown action "' + action + '". ' +
                               'The seven are: add, remove, clear, replace, ' +
                               'attributes, attributes-all, ' +
                               'attributes-clear.'] });
}

// The sweep's outcome as a sentence, appended to whatever message the action
// itself produced. It is stated on EVERY selection change, including the ones
// that changed nothing in the directory, because "0 entries gained anything"
// and "there is no directory here" are different facts and the page must not
// read the same for both.
function sweepText(sweep) {
  log.debug("Entering sweepText().");
  if (!sweep.loaded) {
    log.debug("Leaving sweepText().");
    return ' The embedded directory is not loaded, so no entry was ' +
           'populated; credentials still carry these claims, generated per ' +
           'user.';
  }
  if (!sweep.ok) {
    log.debug("Leaving sweepText().");
    return ' The directory could not be populated: ' +
           (sweep.errors || []).join(' ');
  }
  log.debug("Leaving sweepText().");
  return ' Swept ' + sweep.examined + ' directory entry/entries; ' +
         sweep.changed +
         ' of them gained ' + sweep.values + ' value(s).';
}

function vcAction(body, names) {
  log.debug("Entering vcAction(). action=" + (body.action || '(none)'));
  const action = String(body.action || '');
  const current = vcClaims.selectedNames();

  if (action === 'select' || action === 'replace') {
    // `replace` is the same operation under the name a test would look for, and
    // the same name /admin/claims uses for "here is the whole set at once".
    const result = vcClaims.setSelection(names);
    if (!result.ok) {
      log.debug("Leaving vcAction(). The selection was refused.");
      return refusedBy('STS-ADMIN-0556', result);
    }
    const sweep = vcClaims.populateDirectory();
    log.debug("Leaving vcAction(). Selected " + result.selected.length + " " +
        "attribute(s).");
    return { ok: true, selected: result.selected, added: result.added,
             removed: result.removed,
             sweep: sweep,
             message: 'A credential issued from now on carries ' +
                      result.selected.length +
                      ' claim(s). Added: ' + (result.added.join(', ') ||
                                              'nothing') +
                      '. Removed: ' + (result.removed.join(', ') ||
                                       'nothing') + '.' +
                      sweepText(sweep) };
  }

  if (action === 'add' || action === 'remove') {
    const name = String(body.attribute || body.name || '').trim();
    if (!name) {
      log.debug("Leaving vcAction(). No attribute was named.");
      return refused('STS-ADMIN-0557', { ok: false, errors: ['Name the ' +
          'attribute to ' + action + '.'] });
    }
    const lower = name.toLowerCase();
    const already =
        current.some(function (n) { return n.toLowerCase() === lower; });
    if (action === 'add' && already) {
      log.debug("Leaving vcAction(). Already selected.");
      return refused('STS-ADMIN-0558', { ok: false, errors: ['"' + name + '" ' +
          'is already in the claim set.'] });
    }
    if (action === 'remove' && !already) {
      log.debug("Leaving vcAction(). Not selected.");
      return refused('STS-ADMIN-0559', { ok: false, errors: ['"' + name + '" ' +
          'is not in the claim set.'] });
    }
    const wanted = action === 'add' ? current.concat([name])
                                    : current.filter(
                                        function (
                                            n) {
                                          return n.toLowerCase() !== lower;
                                        });
    const result = vcClaims.setSelection(wanted);
    if (!result.ok) {
      log.debug("Leaving vcAction(). The attribute was refused.");
      return refusedBy('STS-ADMIN-0556', result);
    }
    const sweep = vcClaims.populateDirectory();
    log.debug("Leaving vcAction(). " + action + " -> " +
        result.selected.length + " " +
        "selected.");
    return { ok: true, selected: result.selected, sweep: sweep,
             message: (action === 'add' ? 'Added ' : 'Removed ') + name +
                      '. A credential issued from now on carries ' + result.selected.length +
                      ' claim(s).' + sweepText(sweep) };
  }

  if (action === 'defaults') {
    const result = vcClaims.resetSelection();
    const sweep = vcClaims.populateDirectory();
    log.debug("Leaving vcAction(). Restored the defaults.");
    return { ok: true, selected: result.selected, sweep: sweep,
             message: 'The claim set is the default ' + result.selected.length +
                      ' attribute(s) again — the six claims this issuer ' +
                      'carried before this page existed.' + sweepText(sweep) };
  }

  if (action === 'populate') {
    const sweep = vcClaims.populateDirectory();
    log.debug("Leaving vcAction(). Populated only.");
    return refusedBy('STS-ADMIN-0560', {
      ok: sweep.ok, errors: sweep.errors, selected: current, sweep: sweep,
      message: 'Populated the directory for the current claim set.' +
               sweepText(sweep) });
  }

  log.debug("Leaving vcAction(). Unknown action.");
  return refused('STS-ADMIN-0500',
                 { ok: false, errors: ['Unknown action "' + action + '". ' +
                               'The five are: select, add, remove, defaults, ' +
                               'populate.'] });
}

// ---------------------------------------------------------------------------
// GET /admin/vc-verifier-config, POST /admin/vc-verifier-config
//
// WHAT THE BAR DOOR ASKS FOR — the other end of the page above. /admin/vc
// decides what an issued credential CARRIES; this decides what the Verifier at
// /oid4vp/verifier ASKS FOR, and the two are deliberately separate settings
// because the interesting states are the ones where they disagree. A Verifier
// asking for a claim the issuer is not minting is the negative that exercises a
// wallet's "I cannot satisfy this request" path, and there is no way to reach
// it if one page sets both.
//
// The catalogue is vc_claims.js's, grouped into CLAIMS rather than listed as
// attribute types, and vc_verifier_config.js says at length why: a credential
// carries one Disclosure per top-level claim, so `address` is one unit of
// disclosure however many attribute types feed it. Offering six address
// checkboxes would offer a choice that does not exist on the wire.
//
// It is the third page here that changes what a protocol endpoint does, and the
// only one whose effect is visible in a document this service SENDS rather than
// in one it issues — the dcql_query in the next Authorization Request.
// ---------------------------------------------------------------------------
function vpConfigAction(body, names) {
  log.debug("Entering vpConfigAction(). action=" + (body.action || '(none)'));
  const action = String(body.action || '');

  if (action === 'select' || action === 'replace') {
    // An empty list is a legitimate save and not an empty form: DCQL with no
    // `claims` member asks for the WHOLE credential, so unticking everything is
    // how somebody tests that. It is stated in the message rather than left to
    // be discovered from a presentation that disclosed everything.
    const result = vpConfig.setRequested(names);
    if (!result.ok) {
      log.debug("Leaving vpConfigAction(). The selection was refused.");
      return refusedBy('STS-ADMIN-0561', result);
    }
    log.debug("Leaving vpConfigAction(). " + result.requested.length + " " +
        "claim(s) requested.");
    return { ok: true, requested: result.requested, added: result.added,
             removed: result.removed,
             message: result.requested.length
               ? 'The next Authorization Request asks for ' +
                 result.requested.length +
                 ' claim(s): ' + result.requested.join(', ') + '. Added: ' +
                 (result.added.join(', ') || 'nothing') + '. Removed: ' +
                 (result.removed.join(', ') || 'nothing') + '.'
               : 'The next Authorization Request names no claims at all, ' +
                 'which in DCQL asks for the WHOLE credential — the query ' +
                 'carries no claims member. Removed: ' +
                 (result.removed.join(', ') || 'nothing') + '.' };
  }

  if (action === 'add') {
    const name = String(body.claim || body.name || '').trim();
    const result = vpConfig.addRequested(name);
    if (!result.ok) {
      log.debug("Leaving vpConfigAction(). The claim was refused.");
      return refusedBy('STS-ADMIN-0561', result);
    }
    const known = vpConfig.rowFor(name);
    log.debug("Leaving vpConfigAction(). Added " + name + ".");
    return { ok: true, requested: result.requested,
             message: 'Now asking for ' + name + '.' + (known ? '' :
               ' It is not in the catalogue, so no credential this service ' +
               'issues carries it — which is what makes it a test of what ' +
               'your wallet does with a request it cannot satisfy. This ' +
               'Verifier will refuse the presentation on the "Requested ' +
               'claims" check and name it.') };
  }

  if (action === 'remove') {
    const name = String(body.claim || body.name || '').trim();
    const result = vpConfig.removeRequested(name);
    if (!result.ok) {
      log.debug("Leaving vpConfigAction(). Nothing named that.");
      return refusedBy('STS-ADMIN-0561', result);
    }
    log.debug("Leaving vpConfigAction(). Removed " + name + ".");
    return { ok: true, requested: result.requested,
             message: 'No longer asking for ' + name + '.' };
  }

  if (action === 'defaults') {
    const result = vpConfig.resetRequested();
    log.debug("Leaving vpConfigAction(). Restored the startup request.");
    return { ok: true, requested: result.requested,
             message: 'Back to what this process started with: ' +
                      (result.requested.join(', ') || '(no claims)') + '. ' +
                      'That is OID4VP_CLAIMS where it was set and ' +
                      'given_name, family_name where it was not.' };
  }

  if (action === 'format') {
    const result = vpConfig.setDefaultFormat(String(body.format || ''));
    if (!result.ok) {
      log.debug("Leaving vpConfigAction(). No such format.");
      return refusedBy('STS-ADMIN-0561', result);
    }
    log.debug("Leaving vpConfigAction(). Default format is " + result.format +
              ".");
    return { ok: true, format: result.format,
             message: 'A request that does not name a format now asks for a ' +
                      result.format +
                      ' credential. The three format links on the bar door ' +
                      'name one explicitly and are unaffected.' };
  }

  log.debug("Leaving vpConfigAction(). Unknown action.");
  return refused('STS-ADMIN-0500',
                 { ok: false, errors: ['Unknown action "' + action + '". ' +
                               'The five are: select, add, remove, defaults, ' +
                               'format.'] });
}

// The four writes. One function, the way every other page here has one, so that
// the console form and POST /admin-api/realms cannot come to disagree about
// what "remove" means.
function realmsAction(body) {
  log.debug("Entering realmsAction(). action=" + (body && body.action));
  const action = String((body && body.action) || '').trim();
  const id = String((body && body.id) || '').trim();

  if (action === 'create') {
    // `overrides` IS PASSED THROUGH, and until 2026-08-25 it was not. The
    // management API documents the field, gives it an example
    // (`{"saml2.entityId": "urn:acme:idp"}`) and says it wins over the six
    // seeded names — and this function built its argument out of three
    // properties and dropped the fourth, so a create carrying overrides
    // answered 200 and made a realm configured differently from the one that
    // was asked for. Nothing could have shown it: `realms.create()` validates
    // and merges overrides properly, the console's own form has no such field,
    // and a silently ignored parameter has no failure to point at.
    //
    // It is `undefined` rather than `{}` when nobody sent one, because
    // `create()` distinguishes them: an empty object is still merged over the
    // seeded names — harmlessly, but the intent is "the caller sent nothing".
    const result = realms.create({ id: id.toLowerCase(), name: body.name,
                                   description: body.description,
                                   overrides: body.overrides });
    if (!result.ok) {
      log.debug("Leaving realmsAction(). create refused.");
      return refusedBy('STS-ADMIN-0562', result);
    }
    // THE REALM'S OWN ADMINISTRATOR (2026-09-14, #32). A realm is born with a
    // bootstrap `admin` in both of ITS console roles, forced to change its
    // password at its first sign-in — the default realm's arrangement, one
    // realm down — and administering that realm alone. Seeded here, in the
    // one process that ran the create, rather than in every process that
    // hears the realm arrive: a replicated realm has its entry already.
    //
    // In product mode nobody's password is accepted unchecked, so the account
    // is given a generated one and it is handed back ONCE, in this result.
    // The console draws it on a page of its own rather than in a redirect,
    // for `/admin/users`' reset-password reason.
    const seeded = rbac.seedBootstrapAdministrator(result.realm.id);
    let password = '';
    if (seeded.ran && seeded.created && mode.isProduct()) {
      realms.run(result.realm, function () {
        const generated = credentials.generatePassword(seeded.username);
        const set = credentials.setPassword(seeded.username, generated,
                                            { generated: true });
        if (set.ok) {
          credentials.setPasswordResetRequired(seeded.username, true);
          password = generated;
        } else {
          log.error(errorCodes.tag('STS-ADMIN-0789') + 'admin: the "' +
                    result.realm.id + '" realm\'s bootstrap administrator ' +
                    'could not be given a password: ' +
                    (set.errors || []).join(' '));
        }
      });
    }
    log.debug("Leaving realmsAction(). create ok, " +
              Object.keys(result.realm.overrides).length + " setting(s).");
    return { ok: true, realm: result.realm.id,
             bootstrap: seeded.ran
               ? { username: seeded.username, created: !!seeded.created,
                   passwordResetRequired: !!seeded.created }
               : null,
             password: password || undefined,
             username: password ? seeded.username : undefined,
             message: 'The realm "' + result.realm.id + '" is defined. Every ' +
                      'HTTP endpoint this service has now answers under ' +
                      realms.prefixOf(result.realm) + '/ as well, with its ' +
                      'own signing key and nothing issued yet.' +
                      (seeded.ran
                        ? ' "' + seeded.username + '" administers it, and ' +
                          'only it, from ' + realms.prefixOf(result.realm) +
                          '/admin' + (seeded.created
                            ? ', and must choose a new password at its ' +
                              'first sign-in.'
                            : '.')
                        : '') };
  }

  if (action === 'update') {
    const result = realms.update(id,
                                 { name: body.name,
                                   description: body.description });
    if (!result.ok) {
      log.debug("Leaving realmsAction(). update refused.");
      return refusedBy('STS-ADMIN-0562', result);
    }
    log.debug("Leaving realmsAction(). update ok.");
    return { ok: true, realm: id, message: 'Saved.' };
  }

  if (action === 'set') {
    const key = String(body.key || '').trim();
    const result = realms.setOverride(id, key, body.value);
    if (!result.ok) {
      log.debug("Leaving realmsAction(). set refused.");
      return refusedBy('STS-ADMIN-0562', result);
    }
    log.debug("Leaving realmsAction(). set ok.");
    return { ok: true, realm: id, key: key,
             message: key + ' is set on the "' + id + '" realm. It applies ' +
                      'to the next request that arrives under that realm\'s ' +
                      'prefix, and to nothing else.' };
  }

  if (action === 'unset') {
    const key = String(body.key || '').trim();
    const result = realms.clearOverride(id, key);
    if (!result.ok) {
      log.debug("Leaving realmsAction(). unset refused.");
      return refusedBy('STS-ADMIN-0562', result);
    }
    log.debug("Leaving realmsAction(). unset ok.");
    return { ok: true, realm: id, key: key,
             message: key + ' is no longer set on the "' + id + '" realm; it ' +
                      'comes from whatever this service as a whole is ' +
                      'configured with.' };
  }

  if (action === 'remove') {
    // ------------------------------------------------------------------
    // A REALM MAY NOT REMOVE ITSELF, and this is the one refusal here that is
    // about the request rather than about the realm.
    //
    // The response to this POST is a 303 back to /admin/realms — a path that
    // app.js is about to rewrite into the realm that is being deleted, because
    // that is the realm the request arrived in. The reader would be redirected
    // into a prefix that had stopped existing one instruction earlier and would
    // meet `Cannot GET`. Everything else about the removal would have worked,
    // which is what makes it worth refusing rather than fixing: the fix is to
    // do it from another realm, and that is a sentence rather than a special
    // case in the redirect.
    // ------------------------------------------------------------------
    if (id && id === realms.currentId()) {
      log.debug("Leaving realmsAction(). A realm may not remove itself.");
      return refused('STS-ADMIN-0563', { ok: false, errors: ['This request ' +
          'arrived inside the "' + id +
        '" realm, so removing it would leave the caller on a path that no ' +
        'longer exists — the console would be redirected into a prefix that ' +
        'had stopped existing one instruction earlier. Do it from another ' +
        'realm: the switcher at the top of the console sidebar, or the same ' +
        'call under a different prefix.'] });
    }
    const result = realms.remove(id);
    if (!result.ok) {
      log.debug("Leaving realmsAction(). remove refused.");
      return refusedBy('STS-ADMIN-0562', result);
    }
    log.debug("Leaving realmsAction(). remove ok.");
    return { ok: true, realm: id,
             message: 'The realm "' + id + '" is gone, with its sessions, ' +
                      'its tokens, its statistics, its audit log and its ' +
                      'signing key. Nothing was removed from the shared ' +
                      'directory.' };
  }

  log.debug("Leaving realmsAction(). Unknown action.");
  return refused('STS-ADMIN-0500',
                 { ok: false, errors: ['Unknown action "' + action + '". ' +
    'The five are: create, update, set, unset, remove.'] });
}

// The action switch. `set` and `reset` name one setting; `set-many` is what a
// section's Save posts, and it is not a convenience — a section is how a person
// changes configuration, and turning that into one call per field would make a
// partly-applied section the ordinary outcome of a mistake in any one of them.
// So set-many is ALL-OR-NOTHING: every field is checked before any is written.
function configAction(body) {
  log.debug("Entering configAction(). action=" + (body && body.action));
  const action = String((body && body.action) || '').trim();

  if (action === 'set') {
    const key = String(body.key || '').trim();
    const result = config.setOverride(key, body.value);
    if (!result.ok) {
      log.debug("Leaving configAction(). set refused.");
      return refusedBy('STS-ADMIN-0564', result);
    }
    log.debug("Leaving configAction(). set ok.");
    return { ok: true, key: key,
             setting: config.describe(configSettingFor(key)),
             message: key + ' is now "' + config.text(key) + '". It applies ' +
                      'to the next token, assertion, ticket or search, and ' +
                      'is gone on restart.' };
  }

  if (action === 'set-many') {
    // Only the keys this service knows and that were actually posted. A form
    // posts its disabled inputs not at all, so a section holding restart-only
    // rows submits the editable ones and nothing else — which is why an absent
    // key is silently skipped rather than treated as an attempt to clear it.
    const wanted = Object.keys(body).filter(function (name) {
      return name !== 'action' && configKnows(name);
    });
    if (!wanted.length) {
      log.debug("Leaving configAction(). set-many named nothing.");
      return refused('STS-ADMIN-0565', { ok: false, errors: ['No settings ' +
        'were posted. Every name must be one of the keys GET ' +
        '/admin/config?format=json lists.'] });
    }
    // Checked first, every one of them, and only then written. A section that
    // applied its first three fields and refused the fourth would leave the
    // service in a state nobody asked for and the page showing it.
    const errors = [];
    wanted.forEach(function (key) {
      const problem = config.checkOverride(key, body[key]);
      if (problem) errors.push(problem);
    });
    if (errors.length) {
      log.debug("Leaving configAction(). set-many refused: " + errors.length +
          " " +
          "problem(s).");
      return refused('STS-ADMIN-0564', { ok: false, errors: errors });
    }
    const changed = [];
    wanted.forEach(function (key) {
      const before = config.text(key);
      config.setOverride(key, body[key]);
      if (config.text(key) !== before) changed.push(key);
    });
    log.debug("Leaving configAction(). set-many ok, " + changed.length + " " +
        "changed.");
    return { ok: true, applied: wanted, changed: changed,
             settings: wanted.map(function (key) {
               return config.describe(configSettingFor(key));
             }),
             message: changed.length
               ? changed.length + ' setting(s) changed: ' + changed.join(', ') +
                 '. Gone on restart.'
               : 'Nothing changed — every value posted was the one already ' +
                 'in force.' };
  }

  if (action === 'reset') {
    const key = String(body.key || '').trim();
    const result = config.clearOverride(key);
    if (!result.ok) {
      log.debug("Leaving configAction(). reset refused.");
      return refusedBy('STS-ADMIN-0564', result);
    }
    log.debug("Leaving configAction(). reset ok.");
    return { ok: true, key: key,
             setting: config.describe(configSettingFor(key)),
             message: key + ' is back to its ' + config.sourceOf(key) + ' ' +
                 'value, "' +
                      config.text(key) + '".' };
  }

  if (action === 'reset-all') {
    const result = config.clearAllOverrides();
    log.debug("Leaving configAction(). reset-all ok.");
    return { ok: true, cleared: result.cleared,
             message: result.cleared.length
               ? result.cleared.length + ' runtime override(s) cleared: ' +
                 result.cleared.join(', ') + '.'
               : 'There were no runtime overrides to clear.' };
  }

  log.debug("Leaving configAction(). Unknown action.");
  return refused('STS-ADMIN-0500',
                 { ok: false, errors: ['Unknown action "' + action + '". ' +
    'The four are: set, set-many, reset, reset-all.'] });
}

// Whether this service has a setting of that name. Asked before `describe()`,
// which throws on an unknown key by design — the throw is right for a caller
// that has a key it believes in, and wrong for a form body whose field names
// arrived from outside.
function configKnows(key) {
  log.debug("Entering configKnows().");
  log.debug("Leaving configKnows().");
  return config.SETTINGS.some(function (setting) {
    return setting.key === key;
  });
}

function configSettingFor(key) {
  log.debug("Entering configSettingFor().");
  log.debug("Leaving configSettingFor().");
  return config.SETTINGS.filter(function (setting) {
    return setting.key === key;
  })[0];
}

// The four keys, in the order the page draws them: the three lifetimes, then
// the allowance applied when reading one back. Written once, and every part of
// this page and its two API operations is derived from it, so a fifth setting
// is one entry here.
const TOKEN_LIFETIME_KEYS = ['oauth2.accessTokenTtlS', 'oauth2.idTokenTtlS',
                             'oauth2.refreshTokenTtlS',
                             'oauth2.refreshIdleSeconds',
                             'oauth2.revokeRefreshOnLogout',
                             'oauth2.clockSkewS'];

// The action switch. Two actions, and both write through config.js.
//
// `set` is ALL-OR-NOTHING for the reason configAction()'s set-many is: this
// form posts four fields at once, and applying two of them before refusing the
// third would leave the service issuing tokens with a lifetime combination
// nobody asked for and the page showing it as though it had been chosen.
//
// `defaults` clears the runtime override on these four ONLY. It is not
// config.js's reset-all, which would also drop an unrelated override somebody
// set on another page — that is the sort of button that is used once and
// regretted, and "reset all" already exists on /admin/config for whoever wants
// it.
function tokenLifetimesAction(body) {
  log.debug("Entering tokenLifetimesAction(). action=" + (body && body.action));
  const action = String((body && body.action) || '').trim();

  if (action === 'set') {
    // Only the four this page owns, and only the ones actually posted. A JSON
    // caller that sends one of them is setting one of them; a form sends all
    // four. A field named here that is NOT one of the four is refused by name
    // rather than ignored, because this action's whole surface is four keys and
    // a caller that misspelt one deserves to be told rather than to watch
    // nothing happen.
    const posted = Object.keys(body || {}).filter(function (name) {
      return !FORM_FURNITURE[name];
    });
    const unknown = posted.filter(function (name) {
      return TOKEN_LIFETIME_KEYS.indexOf(name) < 0;
    });
    if (unknown.length) {
      log.debug("Leaving tokenLifetimesAction(). Unknown field(s): " +
                unknown.join(', '));
      return refused('STS-ADMIN-0566', { ok: false, errors: ['This action ' +
          'sets only ' + TOKEN_LIFETIME_KEYS.join(', ') +
        '. It was also given: ' + unknown.join(', ') + '. Every other ' +
        'setting is on /admin/config and POST /admin-api/config/set.'] });
    }
    const wanted = posted.filter(function (name) {
      return TOKEN_LIFETIME_KEYS.indexOf(name) >= 0;
    });
    if (!wanted.length) {
      log.debug("Leaving tokenLifetimesAction(). Nothing was posted.");
      return refused('STS-ADMIN-0565', { ok: false, errors: ['No lifetime ' +
          'was posted. Name at least one of ' +
        TOKEN_LIFETIME_KEYS.join(', ') + '.'] });
    }
    const errors = [];
    wanted.forEach(function (key) {
      const problem = config.checkOverride(key, body[key]);
      if (problem) errors.push(problem);
    });
    if (errors.length) {
      log.debug("Leaving tokenLifetimesAction(). Refused: " + errors.length +
          " " +
          "problem(s).");
      return refused('STS-ADMIN-0564', { ok: false, errors: errors });
    }
    const changed = [];
    wanted.forEach(function (key) {
      const before = config.text(key);
      config.setOverride(key, body[key]);
      if (config.text(key) !== before) changed.push(key);
    });
    log.debug("Leaving tokenLifetimesAction(). " + changed.length +
              " changed.");
    return { ok: true, applied: wanted, changed: changed,
             settings: wanted.map(function (key) {
               return config.describe(configSettingFor(key));
             }),
             message: (changed.length
               ? changed.length + ' setting(s) changed: ' +
                 changed.map(function (key) {
                   return key + ' = ' + config.text(key) + 's';
                 }).join(', ') + '.'
               : 'Nothing changed — every value posted was the one already ' +
                 'in force.') +
               ' It applies to the NEXT token signed; nothing already issued ' +
               'is affected, because a lifetime is stamped into a token as ' +
               'its exp claim. Gone on restart.' };
  }

  if (action === 'defaults') {
    // clearOverride() refuses a key that was never overridden, which is the
    // right answer for a caller naming one key and the wrong one for a button
    // meaning "put these four back". So the refusals are counted rather than
    // returned: a page where three of the four were overridden must not fail
    // because the fourth was already where it belonged.
    const cleared = [];
    TOKEN_LIFETIME_KEYS.forEach(function (key) {
      if (config.clearOverride(key).ok) cleared.push(key);
    });
    log.debug("Leaving tokenLifetimesAction(). Cleared " + cleared.length +
              ".");
    return { ok: true, cleared: cleared,
             settings: TOKEN_LIFETIME_KEYS.map(function (key) {
               return config.describe(configSettingFor(key));
             }),
             message: cleared.length
               ? cleared.length + ' override(s) cleared: ' +
                 cleared.join(', ') + '. ' +
                 'Each is back to its environment or appconfig value.'
               : 'None of the four was overridden here, so nothing changed — ' +
                 'they are already coming from the environment or from one ' +
                 'of the two appconfig files.' };
  }

  log.debug("Leaving tokenLifetimesAction(). Unknown action.");
  return refused('STS-ADMIN-0500',
                 { ok: false, errors: ['Unknown action "' + action + '". ' +
      'The two are: set, defaults.'] });
}

// THE ELEVEN SETTINGS THIS PAGE OWNS: five per profile, plus the skew both
// share. `unit` is what an int row's number means; `kind` is the artifact kind
// whose count belongs beside it (only the two lifetimes have one, because only
// they govern how long an assertion lives); `profile` and `field` name the
// per-application attribute that OVERRIDES the row, which is what makes these
// ten defaults rather than settings. Written once, and every part of this page,
// its two API operations and the per-application resolver's documentation is
// derived from it.
const SAML_ASSERTION_SETTINGS = [
  { key: 'saml2.assertionLifetimeMin', unit: 'min', kind: 'SAML 2.0',
    profile: 'saml2', field: 'saml2AssertionLifetimeMin' },
  { key: 'saml2.signAssertion', unit: '', kind: null,
    profile: 'saml2', field: 'saml2SignAssertion' },
  { key: 'saml2.signResponse', unit: '', kind: null,
    profile: 'saml2', field: 'saml2SignResponse' },
  { key: 'saml2.nameIdFormat', unit: '', kind: null,
    profile: 'saml2', field: 'saml2NameIdFormat' },
  { key: 'saml2.artifactTtlS', unit: 's', kind: null,
    profile: 'saml2', field: 'saml2ArtifactTtlS' },
  // ENCRYPTION, added 2026-08-27. They are `saml2.*` and per application like
  // the five above, so they are drawn in the same section — a reader deciding
  // what a service provider receives should not have to visit two pages to see
  // that it is signed AND encrypted.
  { key: 'saml2.encryptAssertion', unit: '', kind: null,
    profile: 'saml2', field: 'saml2EncryptAssertion' },
  { key: 'saml2.encryptionAlgorithm', unit: '', kind: null,
    profile: 'saml2', field: 'saml2EncryptionAlgorithm' },
  { key: 'saml2.keyTransportAlgorithm', unit: '', kind: null,
    profile: 'saml2', field: 'saml2KeyTransportAlgorithm' },
  { key: 'saml2.encryptLogoutNameId', unit: '', kind: null,
    profile: 'saml2', field: 'saml2EncryptLogoutNameId' },
  { key: 'saml11.assertionLifetimeMin', unit: 'min', kind: 'SAML 1.1',
    profile: 'saml11', field: 'saml11AssertionLifetimeMin' },
  { key: 'saml11.signAssertion', unit: '', kind: null,
    profile: 'saml11', field: 'saml11SignAssertion' },
  { key: 'saml11.signResponse', unit: '', kind: null,
    profile: 'saml11', field: 'saml11SignResponse' },
  { key: 'saml11.nameIdFormat', unit: '', kind: null,
    profile: 'saml11', field: 'saml11NameIdFormat' },
  { key: 'saml11.artifactTtlS', unit: 's', kind: null,
    profile: 'saml11', field: 'saml11ArtifactTtlS' },
  // WS-FEDERATION'S ONE, and it is on this page rather than on /admin/wsfed
  // because a WS-Federation sign-in response carries a SAML 1.1 assertion built
  // by the same function the profile above uses. See SETTING_HOMES, where the
  // same argument is made about the group.
  { key: 'wsfed.assertionLifetimeMin', unit: 'min', kind: null,
    profile: 'wsfed', field: 'wsfedAssertionLifetimeMin' },
  // The one row with no `profile` and no per-application field, and that is
  // the whole of what distinguishes it: a skew is a fact about the clocks in
  // the estate this service issues into, which is decided once and not per
  // relying party. The ten above are per application because two service
  // providers in one estate legitimately want different answers.
  { key: 'saml.clockSkewS', unit: 's', kind: null, profile: '', field: '' }
];

const SAML_ASSERTION_KEYS = SAML_ASSERTION_SETTINGS.map(function (row) {
  return row.key;
});

function samlAssertionRowFor(key) {
  log.debug("Entering samlAssertionRowFor().");
  log.debug("Leaving samlAssertionRowFor().");
  return SAML_ASSERTION_SETTINGS.filter(function (row) {
    return row.key === key;
  })[0] || null;
}

// The action switch. Two actions, both writing through config.js, and both
// behaving exactly as /admin/token-lifetimes' do — including `set` being
// ALL-OR-NOTHING, for that page's reason: this form posts three fields at once,
// and applying two before refusing the third would leave this service issuing
// assertions with a combination nobody asked for and the page showing it as
// though it had been chosen.
function samlAssertionsAction(body) {
  log.debug("Entering samlAssertionsAction(). action=" + (body && body.action));
  const action = String((body && body.action) || '').trim();

  if (action === 'set') {
    // Only the three this page owns, and only the ones actually posted. A field
    // named here that is not one of them is refused BY NAME rather than
    // ignored: this action's whole surface is three keys, and a caller that
    // misspelt one deserves to be told rather than to watch nothing happen.
    const posted = Object.keys(body || {}).filter(function (name) {
      return !FORM_FURNITURE[name];
    });
    const unknown = posted.filter(function (name) {
      return SAML_ASSERTION_KEYS.indexOf(name) < 0;
    });
    if (unknown.length) {
      log.debug("Leaving samlAssertionsAction(). Unknown field(s): " +
                unknown.join(', '));
      return refused('STS-ADMIN-0566', { ok: false, errors: ['This action ' +
          'sets only ' + SAML_ASSERTION_KEYS.join(', ') +
        '. It was also given: ' + unknown.join(', ') + '. Every other ' +
        'setting is on /admin/config and POST /admin-api/config/set.'] });
    }
    const wanted = posted.filter(function (name) {
      return SAML_ASSERTION_KEYS.indexOf(name) >= 0;
    });
    if (!wanted.length) {
      log.debug("Leaving samlAssertionsAction(). Nothing was posted.");
      return refused('STS-ADMIN-0565', { ok: false, errors: ['No setting was ' +
          'posted. Name at least one of ' +
        SAML_ASSERTION_KEYS.join(', ') + '.'] });
    }
    const errors = [];
    wanted.forEach(function (key) {
      const problem = config.checkOverride(key, body[key]);
      if (problem) errors.push(problem);
    });
    if (errors.length) {
      log.debug("Leaving samlAssertionsAction(). Refused: " + errors.length +
          " " +
          "problem(s).");
      return refused('STS-ADMIN-0564', { ok: false, errors: errors });
    }
    const changed = [];
    wanted.forEach(function (key) {
      const before = config.text(key);
      config.setOverride(key, body[key]);
      if (config.text(key) !== before) changed.push(key);
    });
    log.debug("Leaving samlAssertionsAction(). " + changed.length +
              " changed.");
    return { ok: true, applied: wanted, changed: changed,
             settings: wanted.map(function (key) {
               return config.describe(configSettingFor(key));
             }),
             message: (changed.length
               ? changed.length + ' setting(s) changed: ' +
                 changed.map(function (key) {
                   const row = samlAssertionRowFor(key);
                   return key + ' = ' + config.text(key) +
                          (row ? row.unit : '');
                 }).join(', ') + '.'
               : 'Nothing changed — every value posted was the one already ' +
                 'in force.') +
               ' It applies to the NEXT assertion signed; nothing already ' +
               'issued is affected, because a validity window is stamped ' +
               'into an assertion when it is signed. Gone on restart.' };
  }

  if (action === 'defaults') {
    // clearOverride() refuses a key that was never overridden, which is right
    // for a caller naming one key and wrong for a button meaning "put these
    // three back". So the refusals are counted rather than returned.
    const cleared = [];
    SAML_ASSERTION_KEYS.forEach(function (key) {
      if (config.clearOverride(key).ok) cleared.push(key);
    });
    log.debug("Leaving samlAssertionsAction(). Cleared " + cleared.length +
              ".");
    return { ok: true, cleared: cleared,
             settings: SAML_ASSERTION_KEYS.map(function (key) {
               return config.describe(configSettingFor(key));
             }),
             message: cleared.length
               ? cleared.length + ' override(s) cleared: ' +
                 cleared.join(', ') + '. ' +
                 'Each is back to its environment or appconfig value.'
               : 'None of the sixteen was overridden here, so nothing ' +
                 'changed — they are already coming from the environment or ' +
                 'from one of the two appconfig files.' };
  }

  log.debug("Leaving samlAssertionsAction(). Unknown action.");
  return refused('STS-ADMIN-0500',
                 { ok: false, errors: ['Unknown action "' + action + '". ' +
      'The two are: set, defaults.'] });
}

// The one control. It empties this console's inbox and DOES NOT touch the
// stream — see `clearFor()`: clearing what a receiver has been shown and
// tearing down the agreement to send it more are two different acts, and the
// second one is `/admin/ssf`'s.
const SIGNALS_CONSOLE_ACTIONS = ['clear'];

function signalsAction(body) {
  log.debug("Entering signalsAction(). action=" + String((body || {}).action));
  const asked = body || {};
  const action = String(asked.action || '');
  if (SIGNALS_CONSOLE_ACTIONS.indexOf(action) < 0) {
    // THE SENTENCE IS THE HOUSE SHAPE — `Unknown action "x". <prose>: a, b.` —
    // AND IT IS READ RATHER THAN BEING STYLE.
    // `tests/vendored/sts_admin_api_operations.js` matches exactly that out of
    // `errors` on every action resource this API declares, and
    // `tests/vendored/admin_api.js` reads the same sentence to check that
    // every console action has an operation over there. This handler phrased
    // it its own way — `"x" is not one of clear.` — which parses as neither,
    // so it turned the parity check off for this resource with nothing
    // failing until that walk went red on it.
    //
    // The count comes from the list rather than being written out, for
    // `pki_admin.js`'s reason: a second action added tomorrow cannot leave the
    // sentence short by one.
    log.debug("Leaving signalsAction(). Unknown action.");
    return refused('STS-ADMIN-0500',
                   { ok: false, errors: ['Unknown action "' + action + '". ' +
      (SIGNALS_CONSOLE_ACTIONS.length === 1
        ? 'There is one: '
        : 'There are ' + SIGNALS_CONSOLE_ACTIONS.length + ': ') +
      SIGNALS_CONSOLE_ACTIONS.join(', ') + '.'] });
  }
  const gone = signals.clearFor(signals.ADMIN);
  log.debug("Leaving signalsAction(). " + gone + " dropped.");
  return { ok: true, dropped: gone,
    message: gone + ' delivered event(s) were dropped from this console\'s ' +
      'inbox. The stream is untouched and goes on delivering; what was ' +
      'RECORDED about each delivery is still in the ' +
      'audit log, which cannot be cleared.' };
}

// The four actions, shared with `POST /admin-api/ssf/:action`. It resolves
// rather than returning, for the reason the slot's header gives.
function ssfAction(body) {
  log.debug("Entering ssfAction().");
  const asked = body || {};
  if (!signalsReporter) {
    log.debug("Leaving ssfAction(). Not installed.");
    return Promise.resolve(refused('STS-ADMIN-0501', { ok: false, errors: [
      'ssf/ssf.js is not loaded in this process, so there is nothing to ' +
      'act on.'] }));
  }
  const name = String(asked.action || '');
  log.debug("Leaving ssfAction(). " + name);
  return Promise.resolve(signalsReporter.action(name, asked, null))
                .then(function (result) {
    return refusedBy('STS-ADMIN-0567', result);
  });
}

function caepAction(body) {
  log.debug("Entering caepAction().");
  const asked = body || {};
  if (!caepReporter) {
    log.debug("Leaving caepAction(). Not installed.");
    return Promise.resolve(refused('STS-ADMIN-0501', { ok: false, errors: [
      'ssf/ssf.js is not loaded in this process, so there is nothing to ' +
      'act on.'] }));
  }
  const name = String(asked.action || '');
  log.debug("Leaving caepAction(). " + name);
  return Promise.resolve(caepReporter.action(name, asked, null))
                .then(function (result) {
    return refusedBy('STS-ADMIN-0567', result);
  });
}

function riscAction(body) {
  log.debug("Entering riscAction().");
  const asked = body || {};
  if (!riscReporter) {
    log.debug("Leaving riscAction(). Not installed.");
    return Promise.resolve(refused('STS-ADMIN-0501', { ok: false, errors: [
      'ssf/ssf.js is not loaded in this process, so there is nothing to ' +
      'act on.'] }));
  }
  const name = String(asked.action || '');
  log.debug("Leaving riscAction(). " + name);
  return Promise.resolve(riscReporter.action(name, asked, null))
                .then(function (result) {
    return refusedBy('STS-ADMIN-0567', result);
  });
}

// ---------------------------------------------------------------------------
// THE CLIENT-CERTIFICATE TRUSTSTORE: ADD, AND REMOVE ONE (2026-09-12).
//
// What `/admin/tls/trust` posts and `POST /admin-api/tls/trust/{action}`
// calls. It decides nothing about a certificate — whether a block is one,
// whether OpenSSL can read it, whether it is already held and whether the
// truststore is full are all `tls/tls_server.js`'s answers, reached through the
// slot — and what it adds is the vocabulary, the audit row and the sentences.
//
// **THERE IS NO `clear`, AND THAT IS A REFUSAL RATHER THAN AN OMISSION.**
// `POST /tls/trust/clear` exists and is a development test control; a bulk
// clear on a GATED door is the one operation here whose blast radius is every
// client certificate every other caller relies on — `tests/CLAUDE.md` records
// a single unguarded clear costing a remote PEP its identity for the rest of a
// run. Removing is one row at a time, by the fingerprint on the row.
//
// **AN ADD IS PERSISTED WHERE A STORE IS INSTALLED, AND BOTH RESULTS SAY
// WHICH** (2026-09-12; this read *neither action persists anything* until
// then). `tls/tls_server.js` writes a runtime anchor to ou=trustAnchors as it
// adds it, so it survives a restart wherever the directory does; `persisted` is
// read off the truststore's own answer rather than asserted here. An anchor
// from `tls.trustAnchorsFile` still comes back at the next start however it was
// removed.
// ---------------------------------------------------------------------------
const TRUSTSTORE_ACTIONS = ['add', 'remove'];

function truststoreAction(body, context) {
  log.debug("Entering truststoreAction(). action=" +
            String((body || {}).action));
  const asked = body || {};
  const action = String(asked.action || '');
  const actor = String((context || {}).actor || '');
  const via = String((context || {}).via || 'console');
  if (TRUSTSTORE_ACTIONS.indexOf(action) < 0) {
    // THE HOUSE SENTENCE, which `tests/vendored/sts_admin_api_operations.js`
    // and `tests/vendored/admin_api.js` both READ — see signalsAction() above
    // for what a different phrasing silently turns off.
    log.debug("Leaving truststoreAction(). Unknown action.");
    return refused('STS-ADMIN-0500',
                   { ok: false, errors: ['Unknown action "' + action + '". ' +
        'There are ' +
      numberWord(TRUSTSTORE_ACTIONS.length) + ': ' +
      TRUSTSTORE_ACTIONS.join(', ') + '.'] });
  }
  if (!truststore) {
    log.debug("Leaving truststoreAction(). Not installed.");
    return refused('STS-ADMIN-0501', { ok: false, errors: ['The ' +
      'client-certificate truststore is not installed in this process — ' +
      'tls/tls_server.js was not handed to the console — so there is nothing ' +
      'to change.'] });
  }

  if (action === 'add') {
    // A JSON caller may send the bundle as one string or as an array of PEM
    // blocks; a form sends one textarea. All three are one bundle.
    const raw = Array.isArray(asked.certificates)
      ? asked.certificates.join('\n') : String(asked.certificates || '');
    const before = truststore.list();
    // The actor rides along so the stored entry under ou=trustAnchors can say
    // who added it — the one fact about a durable anchor an operator reading
    // the directory months later cannot get from the certificate.
    const result = truststore.add(raw, { actor: actor });
    if (result.error && !result.added) {
      log.debug("Leaving truststoreAction(). add refused.");
      return refused(innerCode(result) || 'STS-ADMIN-0568',
                     { ok: false, errors: [result.error],
               anchors: result.total, duplicates: result.duplicates || 0 });
    }
    const after = truststore.list();
    const known = {};
    before.anchors.forEach(function (one) {
      known[one.fingerprint256] = true;
    });
    const added = after.anchors.filter(function (one) {
      return !known[one.fingerprint256];
    });
    auditLog.audit({ action: 'admin.truststore.change', actor: actor,
                     protocol: 'TLS', channel: 'http',
                     target: added.map(function (one) { return one.subject; })
                                  .join('; '),
                     summary: added.length + ' client-certificate trust ' +
                              'anchor(s) added through the ' + via,
                     detail: { action: 'add', via: via,
                               fingerprints: added.map(function (one) {
                                 return one.fingerprint256;
                               }),
                               duplicates: result.duplicates || 0 } });
    log.debug("Leaving truststoreAction(). added=" + added.length);
    // PERSISTED ONLY IF EVERY ANCHOR THIS CALL ADDED WAS WRITTEN DOWN: a store
    // that took some and refused the rest (a full directory) must not be
    // reported as having kept them all.
    const addedPrints =
        added.map(function (one) { return one.fingerprint256; });
    const persisted = after.stored === true &&
                      after.anchors.filter(function (one) {
      return addedPrints.indexOf(one.fingerprint256) >= 0;
    }).every(function (one) { return one.persisted === true; });
    log.debug("Leaving truststoreAction().");
    return { ok: true, added: added.length,
             duplicates: result.duplicates || 0, anchors: after.anchors.length,
             addedAnchors: added.map(function (one) {
               return { subject: one.subject,
                        fingerprint256: one.fingerprint256,
                        source: one.source };
             }),
             persisted: persisted,
             // A partial add — the truststore filled part-way — is still a
             // success for what went in, and the reason the rest did not is
             // carried rather than dropped.
             warning: result.error || '',
             message: added.length + ' anchor(s) added' +
               (result.duplicates ? ', ' + result.duplicates + ' already held' :
                '') +
               '. The next handshake on 8443, 9443, LDAPS 636 and the main ' +
               'port is judged against ' + after.anchors.length + ' ' +
               'anchor(s); connections already open keep the truststore they ' +
               'were made under. ' + (persisted
                 ? 'Written to ou=trustAnchors in the directory, so it ' +
                   'survives a restart wherever the directory is persisted ' +
                   'and reaches every other process against the same store.'
                 : 'NOT PERSISTED — a runtime anchor is gone at the next ' +
                   'start; tls.trustAnchorsFile is the door for one that ' +
                   'must survive a restart.') +
               (result.error ? ' ' + result.error : '') };
  }

  // remove
  const result = truststore.remove(String(asked.fingerprint || ''));
  if (result.error) {
    log.debug("Leaving truststoreAction(). remove refused.");
    return refused(innerCode(result) || 'STS-ADMIN-0569',
                   { ok: false, errors: [result.error],
                     anchors: result.total });
  }
  const gone = result.anchor || {};
  auditLog.audit({ action: 'admin.truststore.change', actor: actor,
                   protocol: 'TLS', channel: 'http', target: gone.subject,
                   summary: 'A client-certificate trust anchor was removed ' +
                            'through the ' + via,
                   detail: { action: 'remove', via: via,
                             fingerprint: gone.fingerprint256,
                             source: gone.source } });
  log.debug("Leaving truststoreAction(). removed.");
  return { ok: true, removed: 1, anchors: result.total,
           persisted: truststore.list().stored === true,
           removedAnchor: { subject: gone.subject,
                            fingerprint256: gone.fingerprint256,
                            source: gone.source },
           message: 'Removed ' + gone.subject + '. The next handshake no ' +
             'longer verifies a client certificate that chains only to it; ' +
             'connections already open keep the truststore they were made ' +
             'under. ' + (gone.source === 'file'
               ? 'IT CAME FROM tls.trustAnchorsFile AND COMES BACK AT THE ' +
                 'NEXT START — take it out of that file to remove it for good.'
               : 'It was added at runtime, so nothing brings it back.') };
}

// ---------------------------------------------------------------------------
// THE ACTIONS.
//
// Three handlers, one per page, and each is what BOTH the console form and the
// management API call — with `action` taken from the URL there instead of from
// a hidden input here. That is rule 7's arrangement, and it is what makes an
// API operation most of the cost of a console control rather than a second
// implementation of it.
//
// Each returns `{ ok, errors, message }` and DECIDES NOTHING ITSELF: the work
// is in `spiffe_registry.js` and `spiffe_ca.js`, which the SPIRE Server API
// also calls.
// ---------------------------------------------------------------------------
function spiffeCommaList(value) {
  log.debug("Entering spiffeCommaList().");
  log.debug("Leaving spiffeCommaList().");
  return String(value == null ? '' : value).split(',')
    .map(function (part) { return part.trim(); })
    .filter(Boolean);
}

const SPIFFE_ENTRY_ACTIONS = ['create', 'update', 'delete'];

const SPIFFE_AGENT_ACTIONS = ['ban', 'unban', 'delete'];

function spiffeUnknownAction(action, known) {
  log.debug("Entering spiffeUnknownAction().");
  log.debug("Leaving spiffeUnknownAction().");
  return refused('STS-ADMIN-0500',
                 { ok: false,
                   errors: ['Unknown action "' + String(action) + '". ' +
    'The actions here are: ' + known.join(', ') + '.'] });
}

function spiffeEntriesAction(body) {
  log.debug("Entering spiffeEntriesAction(). action=" +
            (body.action || '(none)'));
  const action = String(body.action || '');
  const trustDomain = spiffeCa.trustDomain();

  if (action === 'create') {
    const result = spiffeRegistry.createEntry({
      spiffeId: String(body.spiffeId || '').trim(),
      parentId: String(body.parentId || '').trim() ||
                spiffeIdLib.serverId(trustDomain),
      selectors: spiffeCommaList(body.selectors)
        .map(spiffeRegistry.parseSelector).filter(Boolean),
      dnsNames: spiffeCommaList(body.dnsNames),
      federatesWith: spiffeCommaList(body.federatesWith),
      x509SvidTtl: parseInt(String(body.x509SvidTtl || '0'), 10) || 0,
      jwtSvidTtl: parseInt(String(body.jwtSvidTtl || '0'), 10) || 0,
      hint: String(body.hint || '').trim()
    }, 'console', trustDomain, '');
    log.debug("Leaving spiffeEntriesAction(). create " +
              (result.ok ? 'ok' : 'refused') + ".");
    if (!result.ok) {
      log.debug("Leaving spiffeEntriesAction().");
      return refusedBy('STS-ADMIN-0570', result);
    }
    log.debug("Leaving spiffeEntriesAction().");
    return { ok: true, id: result.id, entry: result.entry,
             message: 'The entry is in the registry as ' + result.id +
                      '. The next FetchX509SVID will include an SVID ' +
                      'for ' + result.entry.spiffeId + ' — this service ' +
                      'hands every caller every identity, so the selectors ' +
                      'do not narrow that.' };
  }

  if (action === 'update') {
    const id = String(body.entry || '').trim();
    if (!id) {
      log.debug("Leaving spiffeEntriesAction(). No entry named.");
      return refused('STS-ADMIN-0571', { ok: false, errors: ['Which entry? ' +
          'Send `entry` with its id.'] });
    }
    const field = String(body.field || '').trim();
    if (spiffeRegistry.EDITABLE.indexOf(fieldToAttribute(field)) < 0) {
      log.debug("Leaving spiffeEntriesAction(). Not editable.");
      return refused('STS-ADMIN-0572',
                     { ok: false, errors: ['"' + field + '" ' +
        'is not a field this page may change. The editable ones are what the ' +
        'entry may DO: spiffeId, parentId, selectors, dnsNames, ' +
        'federatesWith, x509SvidTtl, jwtSvidTtl, hint, expiresAt, admin, ' +
        'downstream, storeSvid. The rest is what HAPPENED, and only ' +
        'ldapmodify reaches it.'] });
    }
    const raw = body.value === undefined ? '' : String(body.value);
    const changes = {};
    if (field === 'selectors') {
      changes.selectors = spiffeCommaList(raw)
        .map(spiffeRegistry.parseSelector).filter(Boolean);
    } else if (field === 'dnsNames' || field === 'federatesWith') {
      changes[field] = spiffeCommaList(raw);
    } else if (field === 'x509SvidTtl' || field === 'jwtSvidTtl' ||
               field === 'expiresAt') {
      changes[field] = parseInt(raw, 10) || 0;
    } else if (field === 'admin' || field === 'downstream' ||
               field === 'storeSvid') {
      changes[field] = /^(1|true|yes|on)$/i.test(raw.trim());
    } else {
      changes[field] = raw.trim();
    }
    const result = spiffeRegistry.updateEntry(id, changes, trustDomain, '');
    log.debug("Leaving spiffeEntriesAction(). update " +
              (result.ok ? 'ok' : 'refused') + ".");
    if (!result.ok) {
      log.debug("Leaving spiffeEntriesAction().");
      return refusedBy('STS-ADMIN-0570', result);
    }
    log.debug("Leaving spiffeEntriesAction().");
    return { ok: true, id: id, entry: result.entry,
             message: field + ' is set. The entry is now at revision ' +
                      result.entry.revisionNumber + ', and the change ' +
                      'applies to the NEXT SVID issued from it — nothing ' +
                      'caches this and nothing already issued changes.' };
  }

  if (action === 'delete') {
    const id = String(body.entry || '').trim();
    if (!id) {
      log.debug("Leaving spiffeEntriesAction(). No entry named.");
      return refused('STS-ADMIN-0571', { ok: false, errors: ['Which entry? ' +
          'Send `entry` with its id.'] });
    }
    const result = spiffeRegistry.deleteEntry(id, '');
    log.debug("Leaving spiffeEntriesAction(). delete " +
              (result.ok ? 'ok' : 'refused') + ".");
    if (!result.ok) {
      log.debug("Leaving spiffeEntriesAction().");
      return refusedBy('STS-ADMIN-0570', result);
    }
    log.debug("Leaving spiffeEntriesAction().");
    return { ok: true, id: id,
             message: 'The entry is gone. Anything holding an SVID minted ' +
                      'from it keeps that SVID until it expires — SPIFFE has ' +
                      'no revocation.' };
  }

  log.debug("Leaving spiffeEntriesAction(). Unknown action.");
  return spiffeUnknownAction(action, SPIFFE_ENTRY_ACTIONS);
}

// The console names a field the way the record does and the EDITABLE table
// names it the way the DIRECTORY does. One map, here, rather than two
// vocabularies that drift: a form offering `dnsNames` while the table says
// `spiffeDnsName` would refuse every edit the form offers.
const SPIFFE_FIELD_ATTRIBUTES = {
  spiffeId: 'spiffeId', parentId: 'spiffeParentId', selectors: 'spiffeSelector',
  dnsNames: 'spiffeDnsName', federatesWith: 'spiffeFederatesWith',
  x509SvidTtl: 'spiffeX509SvidTtl', jwtSvidTtl: 'spiffeJwtSvidTtl',
  hint: 'spiffeHint', expiresAt: 'spiffeEntryExpiresAt', admin: 'spiffeAdmin',
  downstream: 'spiffeDownstream', storeSvid: 'spiffeStoreSvid'
};

function fieldToAttribute(field) {
  log.debug("Entering fieldToAttribute().");
  log.debug("Leaving fieldToAttribute().");
  return SPIFFE_FIELD_ATTRIBUTES[String(field)] || '';
}

function spiffeAgentsAction(body) {
  log.debug("Entering spiffeAgentsAction(). action=" +
            (body.action || '(none)'));
  const action = String(body.action || '');
  const id = String(body.agent || '').trim();
  if (SPIFFE_AGENT_ACTIONS.indexOf(action) >= 0 && !id) {
    log.debug("Leaving spiffeAgentsAction(). No agent named.");
    return refused('STS-ADMIN-0573', { ok: false, errors: ['Which agent? ' +
                                 'Send `agent` with its SPIFFE ID, which is ' +
                                 'under /spire/agent/.'] });
  }
  if (action === 'ban' || action === 'unban') {
    const result = spiffeRegistry.setAgentBanned(id, action === 'ban', '');
    log.debug("Leaving spiffeAgentsAction(). " + action + " " +
              (result.ok ? 'ok' : 'refused') + ".");
    if (!result.ok) {
      log.debug("Leaving spiffeAgentsAction().");
      return refusedBy('STS-ADMIN-0574', result);
    }
    log.debug("Leaving spiffeAgentsAction().");
    return { ok: true, id: id, agent: result.agent,
             message: action === 'ban'
               ? 'That agent is banned: AttestAgent now refuses it with ' +
                 'PermissionDenied. Whatever SVID it already holds keeps ' +
                 'working until it expires.'
               : 'That agent may attest again.' };
  }
  if (action === 'delete') {
    const result = spiffeRegistry.deleteAgent(id, '');
    log.debug("Leaving spiffeAgentsAction(). delete " +
              (result.ok ? 'ok' : 'refused') + ".");
    if (!result.ok) {
      log.debug("Leaving spiffeAgentsAction().");
      return refusedBy('STS-ADMIN-0574', result);
    }
    log.debug("Leaving spiffeAgentsAction().");
    return { ok: true, id: id,
             message: 'That agent is forgotten. It reappears the moment it ' +
                      'attests again, because attestation is not checked — ' +
                      'deleting is forgetting, not revoking. Ban it instead ' +
                      'if that is what you meant.' };
  }
  log.debug("Leaving spiffeAgentsAction(). Unknown action.");
  return spiffeUnknownAction(action, SPIFFE_AGENT_ACTIONS);
}

// ---------------------------------------------------------------------------
// THE ACTION FUNCTION. `/admin-api/federation/:action` calls exactly this, with
// `action` off the URL instead of out of a hidden input — rule 7, and it is
// what makes "every console control has an API operation" a property of the
// code rather than a promise in a comment.
//
// It decides NOTHING itself. Every branch calls `federation.js`, which owns the
// schema, the modes and the refusals — the same division `applicationsAction()`
// keeps with `applications.js`. A validation written here would be a second
// opinion about what a relationship may hold, and the one an `ldapmodify` never
// saw.
// ---------------------------------------------------------------------------
function federationAction(body) {
  log.debug("Entering federationAction(). action=" + (body.action || '(none)'));
  const action = String(body.action || '');
  const id = String(body.id || body.relationship || '').trim();

  if (action === 'create') {
    const result = federation.create({
      fedId: id,
      fedRole: String(body.role || ''),
      fedProtocol: String(body.protocol || ''),
      fedName: String(body.name || ''),
      fedPeer: String(body.peer || ''),
      fedApplication: String(body.application || '')
    });
    log.debug("Leaving federationAction(). create " +
              (result.ok ? 'ok' : 'refused') + ".");
    if (!result.ok) {
      log.debug("Leaving federationAction().");
      return refusedBy('STS-ADMIN-0575', result);
    }
    log.debug("Leaving federationAction().");
    return Object.assign({}, result, {
      message: 'Registered, and DISABLED. Set what it needs — ' +
        (result.readiness.missing.length
          ? result.readiness.missing.join(', ')
          : 'nothing is missing') +
        ' — and then enable it. A relationship does nothing at all until ' +
        'both are done.'
    });
  }

  if (!id) {
    log.debug("Leaving federationAction(). No relationship named.");
    return refused('STS-ADMIN-0576', { ok: false, errors: ['Name the ' +
        'relationship by its id, in `id`.'] });
  }

  if (action === 'set' || action === 'add-value' || action === 'remove-value') {
    const result = federation.update(id, {
      field: String(body.field || ''),
      value: String(body.value == null ? '' : body.value),
      mode: action === 'remove-value' ? 'remove' : 'add'
    });
    log.debug("Leaving federationAction(). " + action + " " +
              (result.ok ? 'ok' : 'refused') + ".");
    return refusedBy('STS-ADMIN-0575', result);
  }

  if (action === 'enable' || action === 'disable') {
    const result = federation.update(id, {
      field: 'fedEnabled', value: action === 'enable' ? 'TRUE' : 'FALSE'
    });
    log.debug("Leaving federationAction(). " + action + " " +
              (result.ok ? 'ok' : 'refused') + ".");
    return refusedBy('STS-ADMIN-0575', result);
  }

  if (action === 'delete') {
    const result = federation.remove(id);
    log.debug("Leaving federationAction(). delete " +
              (result.ok ? 'ok' : 'refused') + ".");
    return refusedBy('STS-ADMIN-0575', result);
  }

  log.debug("Leaving federationAction(). Unknown action.");
  return refused('STS-ADMIN-0500', { ok: false,
           errors: ['Unknown action "' + action + '". The seven are: create, ' +
                    'set, add-value, remove-value, enable, disable, ' +
                    'delete.'] });
}

// The three the SPIFFE page offers. It travels with spiffeAction() because
// that is the only thing that dispatches on it, and the page draws its
// buttons from the same array.
const SPIFFE_ACTIONS = ['rotate', 'federation-set', 'federation-remove'];

async function spiffeAction(body) {
  log.debug("Entering spiffeAction(). action=" + (body.action || '(none)'));
  const action = String(body.action || '');
  if (action === 'rotate') {
    const which = String(body.which || 'x509');
    const done = [];
    try {
      if (which === 'x509' || which === 'both') {
        const authority = await spiffeCa.rotateX509Authority();
        done.push('a new X.509 authority (' + authority.id + ')');
      }
      if (which === 'jwt' || which === 'both') {
        const authority = await spiffeCa.rotateJwtAuthority();
        done.push('a new JWT authority (kid ' + authority.id + ')');
      }
    } catch (e) {
      log.debug("Leaving spiffeAction(). Rotation failed.");
      return refused('STS-ADMIN-0577', { ok: false, errors: ['The authority ' +
          'could not be rotated: ' +
                                   e.message] });
    }
    if (!done.length) {
      log.debug("Leaving spiffeAction(). Nothing named.");
      return refused('STS-ADMIN-0578', { ok: false, errors: ['Rotate what? ' +
          '`which` is x509, jwt or both.'] });
    }
    auditLog.audit({ action: 'spiffe.bundle.change', actor: '',
                  protocol: 'SPIFFE',
                  channel: 'internal', target: spiffeCa.trustDomainId(),
                  summary: 'An authority was rotated from the console',
                  detail: { which: which, sequence: spiffeCa.sequence() } });
    log.debug("Leaving spiffeAction(). Rotated.");
    return { ok: true, message: 'Rotated: ' + done.join(' and ') + '. The ' +
      'previous authority is still published in the bundle, so SVIDs already ' +
      'issued go on verifying; the bundle sequence is now ' +
      spiffeCa.sequence() + '.' };
  }

  if (action === 'federation-set') {
    const name = String(body.trustDomain || '').trim().toLowerCase();
    if (!name) {
      log.debug("Leaving spiffeAction(). No trust domain.");
      return refused('STS-ADMIN-0579', { ok: false, errors: ['Which trust ' +
                                   'domain? Send `trustDomain` with its name ' +
                                   '— other.example, not ' +
                                   'spiffe://other.example.'] });
    }
    const result = spiffeCa.setFederatedBundle(name, body.document, {
      bundleEndpointUrl: String(body.bundleEndpointUrl || ''),
      bundleEndpointProfile: String(body.bundleEndpointProfile || 'https_web'),
      endpointSpiffeId: String(body.endpointSpiffeId || '')
    });
    if (!result.ok) {
      log.debug("Leaving spiffeAction(). Refused.");
      return refused(innerCode(result) || 'STS-ADMIN-0580',
                     { ok: false, errors: [result.reason] });
    }
    auditLog.audit({ action: 'spiffe.bundle.change', actor: '',
                  protocol: 'SPIFFE',
                  channel: 'internal', target: name,
                  summary: 'A federated bundle for ' + name + ' was set from ' +
                           'the console',
                  detail: { created: result.created } });
    log.debug("Leaving spiffeAction(). Federated bundle set.");
    return { ok: true, message: 'The bundle for ' + name + ' was ' +
      (result.created ? 'added' : 'replaced') + '. Any registration entry ' +
      'that federates with it will now hand it to its workloads. The ' +
      'endpoint URL is recorded and will not be fetched — see the note on ' +
      'this page.' };
  }

  if (action === 'federation-remove') {
    const name = String(body.trustDomain || '').trim().toLowerCase();
    const removed = spiffeCa.deleteFederatedBundle(name);
    if (!removed) {
      log.debug("Leaving spiffeAction(). Not held.");
      return refused('STS-ADMIN-0581', { ok: false, errors: ['This service ' +
                                   'holds no bundle for the trust ' +
                                   'domain ' + name + '.'] });
    }
    auditLog.audit({ action: 'spiffe.bundle.change', actor: '',
                  protocol: 'SPIFFE',
                  channel: 'internal', target: name,
                  summary: 'A federated bundle for ' + name + ' was removed ' +
                           'from the console', detail: {} });
    log.debug("Leaving spiffeAction(). Removed.");
    return { ok: true, message: 'The bundle for ' + name + ' is gone. Any ' +
      'entry that federates with it keeps the name and simply contributes no ' +
      'bundle, which is the same state as a relationship configured before ' +
      'its bundle arrives.' };
  }

  log.debug("Leaving spiffeAction(). Unknown action.");
  return spiffeUnknownAction(action, SPIFFE_ACTIONS);
}

// ---------------------------------------------------------------------------
// THE KERBEROS PRINCIPALS, AS `/admin/kerberos/principals` POSTS THEM AND
// `POST /admin-api/kerberos/principals/{action}` CALLS THEM (2026-09-12).
//
// Four actions and each is one function in `kerberos/krb5_person_keys.js`,
// which decides everything: what an SPN may be, whether a key already exists,
// the random keys, the seal, the keytab, the audit row. What this adds is the
// vocabulary and the house refusal sentence.
//
// **A CREATE AND A ROTATE ANSWER WITH THE KEYTAB, AND IT IS THE ONLY TIME IT
// EXISTS OUTSIDE THE SEAL.** The result carries it base64-encoded; the console
// draws it on a page marked shown-once and `/admin-api` returns it in the JSON.
// Nothing reads a stored key back out afterwards, so a keytab that was lost is
// replaced by rotating, never re-downloaded.
//
// **THEY ACT ON THE TRUST REALM THE CALL IS IN** (2026-09-15), and the result
// says which. This read *they act on the DEFAULT trust realm whatever prefix a
// call carries … a service principal "in acme" would be a key nothing ever asks
// for*: acme now has a Kerberos realm and a KDC of its own, so a service
// principal there is a key that realm's KDC issues tickets for. A realm whose
// Kerberos is off has no database to put one in, and the register refuses.
// ---------------------------------------------------------------------------
// The last two (2026-09-12) end the PREVIOUS-KEY-VERSION window early — a
// rotation or a password change keeps the version it replaced for as long as a
// ticket under it can be presented, and after a compromise an operator wants
// that to stop now. They drop the previous versions and nothing else: the
// current key, and so the person's sign-in or the service's current keytab, is
// untouched.
const KERBEROS_PRINCIPAL_ACTIONS = ['create-service', 'rotate-service',
                                    'delete-service', 'clear-person-keys',
                                    'drop-previous-service-keys',
                                    'drop-previous-person-keys'];

function kerberosPrincipalsAction(body, context) {
  log.debug("Entering kerberosPrincipalsAction(). action=" +
            String((body || {}).action));
  const asked = body || {};
  const action = String(asked.action || '');
  const ctx = { actor: String((context || {}).actor || ''),
                via: String((context || {}).via || 'console') };
  let result;
  if (action === 'create-service') {
    result = krb5PersonKeys.createServicePrincipal(asked.spn, ctx);
  } else if (action === 'rotate-service') {
    result = krb5PersonKeys.rotateServicePrincipal(asked.spn, ctx);
  } else if (action === 'delete-service') {
    result = krb5PersonKeys.deleteServicePrincipal(asked.spn, ctx);
  } else if (action === 'clear-person-keys') {
    result = krb5PersonKeys.clearPersonKeys(asked.username, ctx);
  } else if (action === 'drop-previous-service-keys') {
    result = krb5PersonKeys.dropPreviousServiceKeys(asked.spn, ctx);
  } else if (action === 'drop-previous-person-keys') {
    result = krb5PersonKeys.dropPreviousPersonKeys(asked.username, ctx);
  } else {
    // THE HOUSE SENTENCE, which `tests/vendored/sts_admin_api_operations.js`
    // and `tests/vendored/admin_api.js` both READ.
    log.debug("Leaving kerberosPrincipalsAction(). Unknown action.");
    return refused('STS-ADMIN-0602', { ok: false, errors: ['Unknown action "' +
      action + '". There are ' + numberWord(KERBEROS_PRINCIPAL_ACTIONS.length) +
      ': ' + KERBEROS_PRINCIPAL_ACTIONS.join(', ') + '.'] });
  }
  if (result && result.ok) {
    result.trustRealm = realms.currentId();
  }
  log.debug("Leaving kerberosPrincipalsAction(). ok=" +
            !!(result && result.ok));
  return refusedBy('STS-ADMIN-0602', result);
}

// ---------------------------------------------------------------------------
// THE TWO KEY LISTS, AS FUNCTIONS. `/admin-api` asks which settings each of
// these two pages owns, and the console answered with an inline lambda in its
// own exports — `function () { return TOKEN_LIFETIME_KEYS.slice(); }` — which
// is why they were invisible to an analysis that looks for named functions.
// A COPY each time, because the caller gets the list and the table is this
// file's.
// ---------------------------------------------------------------------------
function tokenLifetimeKeys() {
  log.debug("Entering tokenLifetimeKeys().");
  log.debug("Leaving tokenLifetimeKeys().");
  return TOKEN_LIFETIME_KEYS.slice();
}

function samlAssertionKeys() {
  log.debug("Entering samlAssertionKeys().");
  log.debug("Leaving samlAssertionKeys().");
  return SAML_ASSERTION_KEYS.slice();
}

module.exports = {
  tokenLifetimeKeys: tokenLifetimeKeys,
  samlAssertionKeys: samlAssertionKeys,
  // The seven the console forwards. See the header.
  setLogoutReader: setLogoutReader,
  setDirectoryWriter: setDirectoryWriter,
  setGroupWriter: setGroupWriter,
  setSignalsReporter: setSignalsReporter,
  setCaepReporter: setCaepReporter,
  setRiscReporter: setRiscReporter,
  setXacmlPages: setXacmlPages,
  setTruststore: setTruststore,
  TRUSTSTORE_ACTIONS: TRUSTSTORE_ACTIONS,
  truststoreAction: truststoreAction,
  KERBEROS_PRINCIPAL_ACTIONS: KERBEROS_PRINCIPAL_ACTIONS,
  kerberosPrincipalsAction: kerberosPrincipalsAction,
  // The thirty actions, the tables they dispatch on, and the pure helpers
  // they share with the pages that draw their buttons.
  FORM_FURNITURE: FORM_FURNITURE,
  jtiFrom: jtiFrom,
  tokenAction: tokenAction,
  sessionsAction: sessionsAction,
  logoutAction: logoutAction,
  PERMISSION_ACTIONS: PERMISSION_ACTIONS,
  permissionsAction: permissionsAction,
  noXacml: noXacml,
  xacmlAction: xacmlAction,
  USER_FIELD_PREFIX: USER_FIELD_PREFIX,
  userFieldsFrom: userFieldsFrom,
  truthy: truthy,
  USERS_ACTIONS: USERS_ACTIONS,
  usersAction: usersAction,
  groupsAction: groupsAction,
  FIELD_PREFIX: FIELD_PREFIX,
  applicationFieldsFrom: applicationFieldsFrom,
  APPLICATION_ACTIONS: APPLICATION_ACTIONS,
  applicationsAction: applicationsAction,
  asAction: asAction,
  SAML2_SP_KIND: SAML2_SP_KIND,
  saml2Action: saml2Action,
  SAML11_RP_KIND: SAML11_RP_KIND,
  saml11Action: saml11Action,
  MFA_ACTIONS: MFA_ACTIONS,
  mfaAction: mfaAction,
  rbacAction: rbacAction,
  CONSENT_ACTIONS: CONSENT_ACTIONS,
  consentAction: consentAction,
  ROLE_ACTIONS: ROLE_ACTIONS,
  ROLE_MEMBER_KINDS: ROLE_MEMBER_KINDS,
  roleMemberKindOf: roleMemberKindOf,
  rolesAction: rolesAction,
  passwordPoliciesAction: passwordPoliciesAction,
  PASSWORD_POLICY_ACTIONS: PASSWORD_POLICY_ACTIONS,
  DEFAULT_CREDENTIAL: DEFAULT_CREDENTIAL,
  claimsAction: claimsAction,
  sweepText: sweepText,
  vcAction: vcAction,
  vpConfigAction: vpConfigAction,
  realmsAction: realmsAction,
  configAction: configAction,
  configKnows: configKnows,
  configSettingFor: configSettingFor,
  TOKEN_LIFETIME_KEYS: TOKEN_LIFETIME_KEYS,
  tokenLifetimesAction: tokenLifetimesAction,
  SAML_ASSERTION_SETTINGS: SAML_ASSERTION_SETTINGS,
  SAML_ASSERTION_KEYS: SAML_ASSERTION_KEYS,
  samlAssertionRowFor: samlAssertionRowFor,
  samlAssertionsAction: samlAssertionsAction,
  SIGNALS_CONSOLE_ACTIONS: SIGNALS_CONSOLE_ACTIONS,
  signalsAction: signalsAction,
  ssfAction: ssfAction,
  caepAction: caepAction,
  riscAction: riscAction,
  spiffeCommaList: spiffeCommaList,
  SPIFFE_ENTRY_ACTIONS: SPIFFE_ENTRY_ACTIONS,
  SPIFFE_AGENT_ACTIONS: SPIFFE_AGENT_ACTIONS,
  spiffeUnknownAction: spiffeUnknownAction,
  spiffeEntriesAction: spiffeEntriesAction,
  SPIFFE_FIELD_ATTRIBUTES: SPIFFE_FIELD_ATTRIBUTES,
  fieldToAttribute: fieldToAttribute,
  spiffeAgentsAction: spiffeAgentsAction,
  spiffeAction: spiffeAction,
  SPIFFE_ACTIONS: SPIFFE_ACTIONS,
  federationAction: federationAction
};
