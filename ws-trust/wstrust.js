'use strict';
//
// File: wstrust.js
//
// ---------------------------------------------------------------------------
// WS-Trust 1.4 (and 1.0-1.3, which differ only in the namespace and action URIs):
// the SOAP RequestSecurityToken endpoint and everything that reads or writes one.
//
// It accepts an RST and dispatches on wst:RequestType:
//
//   Issue    -> RSTR Collection with a freshly minted, STS-signed SAML 2.0
//               assertion (or a JWT / plain UsernameToken echo, per TokenType),
//               a Lifetime, and an attached reference.
//   Renew    -> RSTR with a fresh token for the supplied RenewTarget.
//   Validate -> RSTR with wst:Status/wst:Code valid|invalid.
//   Cancel   -> RSTR with wst:RequestedTokenCancelled.
//
// Authentication: a WS-Security UsernameToken is accepted when username and
// password are both present (and the password is not the literal "invalid",
// which lets a negative test force an auth failure). A SAML assertion in the
// security header is accepted as a credential too, and a request carrying an
// OnBehalfOf/ActAs token (delegation) is accepted on top of either. This is a
// TEST STS — it does not verify request signatures or enforce real policy.
//
// EVERY accepted credential is put through stats.recordAuthentication(), on
// every one of the four operations, and that matters beyond the counter it
// increments: it is this service's single authentication funnel, so it is also
// what writes the audit log's `authentication` row and what makes the embedded
// LDAP directory grow a `uid=<name>,ou=users` entry for the person. Three
// things here used to miss it, and each one produced somebody who had
// authenticated through WS-Trust and had no directory object:
//
//   * Validate and Cancel answered before authenticate() was ever called.
//   * a request with BOTH a UsernameToken and an OnBehalfOf recorded only the
//     delegated subject — the requester, the one party that presented a
//     credential, was dropped.
//   * a Renew with no security header read the assertion out of its own
//     RenewTarget and recorded THAT as the credential; the token was talking,
//     not the requester.
//
// The SAML assertion itself is built and protected by saml2.js: WS-Trust carries
// tokens, it does not define them.
// ---------------------------------------------------------------------------

// One signer and one verifier for the whole service since 2026-08-27.
const stsCrypto = require('../common/crypto');
const { DOMParser, XMLSerializer } = require('@xmldom/xmldom');
const app = require('../common/app');
// firstByLocal/textByLocal were written here and now live in helpers.js: WS-Federation
// reads the same shapes (a `wreq` RST, and a `wresult` at its mock relying party), and a
// second copy of a reader that has to cope with four trust namespaces is a second copy
// that gets one of them wrong.
const { log, logArtifact, STS, xmlEscape, iso,
        firstByLocal, textByLocal } = require('../common/helpers');
// wstrust.issuer. A SAML token requested THROUGH WS-Trust is built by the
// SAML modules and carries saml.issuer instead; the two are separate
// settings for that reason and default to the same value.
const config = require('../common/config');
const { buildSamlAssertion, encryptAssertion } = require('../saml/saml2');
const stats = require('../common/admin_stats');
// The application registry (ou=applications in the embedded directory). A
// library that registers no route, so it cannot move anything in the require
// order this module sits in.
const applications = require('../common/applications');
// The delegation register (/admin/delegation). Two of the eight mechanisms that
// page knows are this module's — OnBehalfOf and ActAs — and they are the two
// where nothing is checked at all, which is a fact the page states beside the
// Kerberos rows where something is. A library like the two above: it registers
// no route.
const delegation = require('../common/delegation');
const WST_NS = 'http://docs.oasis-open.org/ws-sx/ws-trust/200512';

const SOAP12_NS = 'http://www.w3.org/2003/05/soap-envelope';

const SOAP11_NS = 'http://schemas.xmlsoap.org/soap/envelope/';

const SAML2_TOKEN_TYPE = 'http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0';

const JWT_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:jwt';

const STATUS_TOKEN_TYPE = WST_NS + '/RSTR/Status';

const STATUS_VALID = WST_NS + '/status/valid';

const STATUS_INVALID = WST_NS + '/status/invalid';

function soapNsFor(version) { return version === '1.1' ? SOAP11_NS : SOAP12_NS; }

function buildJwt(subject, audience, lifetimeMin) {
  // jsonwebtoken rejects an empty-string audience — only set it when present.
  log.debug("Entering buildJwt().");
  const opts = { 
    algorithm: 'RS256', 
    issuer: config.value('wstrust.issuer'), 
    expiresIn: (lifetimeMin > 0 ? lifetimeMin : 60) * 60 
  };
  if (audience) opts.audience = audience;
  const claims = { sub: subject, name: subject };
  logArtifact('WS-Trust JWT', 'before signing', { header: { alg: opts.algorithm }, payload: claims, options: opts });
  // Signed through the shared signer but NOT through helpers.signJwt(), so it
  // carries no jti and is in no register — see the note further down, which is
  // about the REGISTER and is unaffected by where the signature is made.
  const signed = stsCrypto.signJws(claims, STS.privateKey, opts);
  logArtifact('WS-Trust JWT', 'after signing', signed);
  log.debug("Leaving buildJwt().");
  return signed;
}

// Build the token element (what goes inside wst:RequestedSecurityToken).
function buildToken(tokenType, subject, audience, lifetimeMin) {
  log.debug("Entering buildToken(). tokenType=" + tokenType + ", subject=" + subject);
  if (tokenType === JWT_TOKEN_TYPE) {
    const raw = buildJwt(subject, audience, lifetimeMin);
    const token = { xml: '<wsse:BinarySecurityToken xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"' +
      ' ValueType="urn:ietf:params:oauth:token-type:jwt">' + raw + '</wsse:BinarySecurityToken>', ref: '', tokenType: JWT_TOKEN_TYPE, id: '' };
    log.debug("Leaving buildToken(). Issued a JWT.");
    return token;
  }
  const assertion = buildSamlAssertion(subject, audience, lifetimeMin);
  const idm = assertion.match(/\bID="([^"]+)"/);
  const id = idm ? idm[1] : '';
  const ref = '<wst:RequestedAttachedReference><wsse:SecurityTokenReference' +
    ' xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">' +
    '<wsse:KeyIdentifier ValueType="http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLID">' +
    xmlEscape(id) + '</wsse:KeyIdentifier></wsse:SecurityTokenReference></wst:RequestedAttachedReference>';
  log.debug("Leaving buildToken(). Issued a SAML 2.0 assertion with ID " + id + ".");
  // `id` is carried out because /admin/delegation quotes the identifier of what
  // a delegated request PRODUCED, and the AssertionID is the only one either
  // token type here has: the JWT branch above signs through the shared signer
  // but NOT through helpers.signJwt(), so it carries no jti and is not in the
  // tokens register either. (What puts a token in the register is that funnel,
  // not where the RSA signature is computed — centralizing the crypto on
  // 2026-08-27 did not change this and was not meant to.) A row for one of those says so rather than showing
  // an empty column that reads as a defect.
  return { xml: assertion, ref: ref, tokenType: SAML2_TOKEN_TYPE, id: id };
}

function envelope(version, action, bodyInner) {
  log.debug("Entering envelope(). version=" + version + ", action=" + action);
  const soapNs = soapNsFor(version);
  const header = action
    ? '<soap:Header><wsa:Action xmlns:wsa="http://www.w3.org/2005/08/addressing">' + action + '</wsa:Action></soap:Header>'
    : '';
  log.debug("Leaving envelope().");
  return '<?xml version="1.0" encoding="UTF-8"?>' +
    '<soap:Envelope xmlns:soap="' + soapNs + '">' + header +
    '<soap:Body>' + bodyInner + '</soap:Body></soap:Envelope>';
}

function soapFault(version, reason) {
  log.debug("Entering soapFault(). version=" + version + ", reason=" + reason);
  const soapNs = soapNsFor(version);
  const body = version === '1.1'
    ? '<soap:Fault><faultcode>soap:Client</faultcode><faultstring>' + xmlEscape(reason) + '</faultstring></soap:Fault>'
    : '<soap:Fault><soap:Code><soap:Value>soap:Sender</soap:Value></soap:Code>' +
      '<soap:Reason><soap:Text xml:lang="en">' + xmlEscape(reason) + '</soap:Text></soap:Reason></soap:Fault>';
  log.debug("Leaving soapFault().");
  return '<?xml version="1.0" encoding="UTF-8"?>' +
    '<soap:Envelope xmlns:soap="' + soapNs + '">' + '<soap:Body>' + body + '</soap:Body></soap:Envelope>';
}

// --- request handling ------------------------------------------------------
function detectSoapVersion(doc, contentType) {
  log.debug("Entering detectSoapVersion().");
  const root = doc && doc.documentElement;
  log.debug("Leaving detectSoapVersion().");
  if (root && root.namespaceURI === SOAP11_NS) return '1.1';
  if (root && root.namespaceURI === SOAP12_NS) return '1.2';
  return /text\/xml/i.test(contentType || '') ? '1.1' : '1.2';
}

// The elements of a WS-Trust request that hold SOMEBODY ELSE'S token. A
// UsernameToken or an Assertion inside one of these is not the requester's
// credential and must never be read as one.
const NOT_A_CREDENTIAL = ['OnBehalfOf', 'ActAs', 'RenewTarget',
                          'ValidateTarget', 'CancelTarget'];

// Is `node` inside one of them?
function insideAnotherPartysToken(node) {
  log.debug("Entering insideAnotherPartysToken().");
  let current = node && node.parentNode;
  while (current) {
    const name = current.localName || current.nodeName || '';
    if (NOT_A_CREDENTIAL.indexOf(String(name).split(':').pop()) >= 0) {
      log.debug("Leaving insideAnotherPartysToken(). It is inside " + name +
                ".");
      return true;
    }
    current = current.parentNode;
  }
  log.debug("Leaving insideAnotherPartysToken(). It is not.");
  return false;
}

// The first element of that local name under `root` that is the REQUESTER'S
// own, skipping any that belongs to somebody else.
//
// This exists because a WS-Trust request routinely carries several identities:
// the requester's UsernameToken in the security header, the subject named in
// `wst:OnBehalfOf` or `wst:ActAs`, and the token being renewed, validated or
// cancelled in `wst:RenewTarget` / `wst:ValidateTarget`. All of them are
// `wsse:UsernameToken` or `saml:Assertion` elements, so a plain search over the
// document answers "which comes first in DOCUMENT ORDER", which is not the
// question being asked.
//
// That is not hypothetical: a Renew whose RenewTarget held the expiring
// assertion, sent with no security header at all, used to authenticate as that
// assertion's NameID. It was the TOKEN talking, not the requester.
function firstOwnedByRequester(root, name) {
  log.debug("Entering firstOwnedByRequester(). name=" + name);
  const found = root.getElementsByTagNameNS('*', name);
  for (let i = 0; found && i < found.length; i++) {
    if (!insideAnotherPartysToken(found[i])) {
      log.debug("Leaving firstOwnedByRequester(). Found one at index " + i +
                ".");
      return found[i];
    }
  }
  log.debug("Leaving firstOwnedByRequester(). There is none.");
  return null;
}

// The element a REQUESTER's own credential may be read from: `wsse:Security`
// when the request has one, and the whole document when it has none. The
// fallback is deliberately lenient — a UsernameToken put somewhere other than
// the security header is still read — and it is safe because
// firstOwnedByRequester() below is what does the looking.
function credentialScope(doc) {
  log.debug("Entering credentialScope().");
  const security = firstByLocal(doc, 'Security');
  if (security) {
    log.debug("Leaving credentialScope(). The security header is the scope.");
    return security;
  }
  log.debug("Leaving credentialScope(). There is no security header, so the " +
            "whole document is the scope.");
  return doc;
}

// The requester's own credential, read from that scope. It returns null when
// nothing was presented, which is a different answer from a credential that was
// presented and refused.
function requesterCredential(doc) {
  log.debug("Entering requesterCredential().");
  const scope = credentialScope(doc);
  const ut = firstOwnedByRequester(scope, 'UsernameToken');
  if (ut) {
    const user = textByLocal(ut, 'Username');
    const pass = textByLocal(ut, 'Password');
    if (!user || !pass) {
      log.debug("Leaving requesterCredential(). Incomplete UsernameToken.");
      return { ok: false,
               reason: 'UsernameToken requires a username and password.' };
    }
    if (pass === 'invalid') {
      log.debug("Leaving requesterCredential(). The reserved password was " +
                "used, so this is a failure.");
      return { ok: false,
               reason: 'Authentication failed for user ' + user + '.' };
    }
    log.debug("Leaving requesterCredential(). A UsernameToken for " + user +
              ".");
    return { ok: true, subject: user, method: 'WS-Security UsernameToken',
             note: 'The password is not checked, except for the reserved ' +
                   'string "invalid".' };
  }
  // A SAML assertion presented directly as the credential.
  const assertion = firstOwnedByRequester(scope, 'Assertion');
  if (assertion) {
    const nameId = firstByLocal(assertion, 'NameID') ||
      firstByLocal(assertion, 'NameIdentifier');
    const named = (nameId && (nameId.textContent || '').trim()) ||
      'saml-subject';
    log.debug("Leaving requesterCredential(). A SAML assertion for " + named +
              ".");
    return { ok: true, subject: named,
             method: 'a SAML assertion as the credential',
             note: 'The assertion\'s signature and Conditions are not ' +
                   'checked; the NameID is read and believed.' };
  }
  log.debug("Leaving requesterCredential(). Nothing was presented.");
  return null;
}

// The subject named in `wst:OnBehalfOf` or `wst:ActAs`, and WHICH OF THE TWO it
// was. `{ subject: '', element: '' }` when the request delegates nothing.
//
// The two used to be collapsed with a `||`, which was right for everything that
// reads this — the token issued is identical either way, because this service
// polices nothing — and wrong for /admin/delegation, which is where the
// difference is the whole point. They are not two spellings of one thing:
//
//   * `wst:OnBehalfOf` (1.3 §9.2) asks for a token ABOUT somebody. The relying
//     party is handed an ordinary sign-in and cannot tell a middle tier was
//     involved. IMPERSONATION.
//   * `wst14:ActAs` (1.4 §9.3) is composite by definition: the token is about
//     the named subject AND says the requester is acting. DELEGATION, and the
//     element to reach for when the far end must be able to tell.
//
// A request carrying BOTH takes OnBehalfOf, which is the order the `||` always
// had; the row says which one it attributed the act to, so the choice is
// visible rather than silently made.
//
// AND THE IDENTIFIER OF THE TOKEN THAT WAS HANDED IN, which is the one thing
// here that /admin/tokens/credential cannot do without. That page walks a
// lineage by joining what an act PRODUCED to what the next act CONSUMED, on the
// identifier and on nothing else (see credential_graph.js). A chain of
// OnBehalfOf hops — the assertion one call issues is the assertion the next call
// delegates with — is exactly the shape it exists to draw, and it was invisible
// to it until this was read: the act's `consumed` named the requester's
// WS-Security credential, which this service never issued and cannot name, so
// every trail stopped one generation in at a wall.
//
// Three spellings, because three things can legitimately be inside one of these
// elements: a SAML 2.0 assertion (`ID`), a SAML 1.1 one (`AssertionID`), and a
// <wsse:SecurityTokenReference> naming a token by KeyIdentifier rather than
// carrying it. An element holding none of them yields '', which is not an error
// — it is the honest "this act consumed something this register cannot name",
// and the lineage page prints that as a reason rather than as an origin.
function delegatedTokenId(element) {
  log.debug("Entering delegatedTokenId().");
  const assertion = firstByLocal(element, 'Assertion');
  if (assertion) {
    const id = assertion.getAttribute('ID') ||
      assertion.getAttribute('AssertionID') || '';
    if (String(id).trim()) {
      log.debug("Leaving delegatedTokenId(). An assertion, " + id + ".");
      return String(id).trim();
    }
  }
  const keyIdentifier = firstByLocal(element, 'KeyIdentifier');
  if (keyIdentifier) {
    const named = (keyIdentifier.textContent || '').trim();
    if (named) {
      log.debug("Leaving delegatedTokenId(). A reference to " + named + ".");
      return named;
    }
  }
  log.debug("Leaving delegatedTokenId(). Nothing here carries an identifier.");
  return '';
}

function delegatedSubject(doc) {
  log.debug("Entering delegatedSubject().");
  const oboEl = firstByLocal(doc, 'OnBehalfOf');
  const actAsEl = firstByLocal(doc, 'ActAs');
  const obo = oboEl || actAsEl;
  if (!obo) {
    log.debug("Leaving delegatedSubject(). Nothing is delegated.");
    return { subject: '', element: '', tokenId: '' };
  }
  const element = oboEl ? 'OnBehalfOf' : 'ActAs';
  const nameId = firstByLocal(obo, 'NameID') ||
    firstByLocal(obo, 'NameIdentifier');
  const named = (nameId && (nameId.textContent || '').trim()) ||
    'delegated-subject';
  const tokenId = delegatedTokenId(obo);
  log.debug("Leaving delegatedSubject(). " + named + " via " + element + ".");
  return { subject: named, element: element, both: !!(oboEl && actAsEl),
           tokenId: tokenId };
}

// Who this request is from, who the token it asks for is about, and whether the
// credential presented was accepted.
//
// TWO identities can be in one request and BOTH are recorded, which is the part
// that used to be wrong: a request carrying a UsernameToken AND an OnBehalfOf
// returned at the delegation branch before it had looked at the UsernameToken,
// so the requester — the one party here that actually presented a credential —
// was recorded nowhere and grew no directory entry. The delegated subject is
// still what the token is ABOUT, and is still what this returns as the subject.
//
// Every accepted credential goes through stats.recordAuthentication(), which is
// this service's single authentication funnel: it is what the admin console's
// users page counts, what the audit log writes an `authentication` row from,
// and what the embedded LDAP directory grows a `uid=<name>,ou=users` entry
// from. A path that accepts a credential without calling it is a person who
// authenticated here and is in none of the three.
function authenticate(doc) {
  log.debug("Entering authenticate().");
  const credential = requesterCredential(doc);
  if (credential && !credential.ok) {
    log.debug("Leaving authenticate(). The credential was refused.");
    return { ok: false, reason: credential.reason };
  }
  if (credential) {
    stats.recordAuthentication({
      presented: credential.subject, protocol: 'WS-Trust',
      method: credential.method, note: credential.note
    });
  }
  const delegatedBy = delegatedSubject(doc);
  const delegated = delegatedBy.subject;
  if (delegated) {
    // Recorded, with what it is said plainly: the subject named in an
    // OnBehalfOf presented no credential of their own here. Something else
    // asked for a token about them, and this service — which checks nothing —
    // agreed. The users page prints the method, so the row is not mistaken for
    // a sign-in.
    stats.recordAuthentication({
      presented: delegated, protocol: 'WS-Trust',
      method: 'OnBehalfOf / ActAs (delegated)',
      note: 'The requester named this subject; the subject presented ' +
            'nothing. This service accepts any delegation without checking ' +
            'who may perform it.'
    });
    log.debug("Leaving authenticate(). Delegated request (OnBehalfOf/ActAs).");
    // `delegation` carries what /admin/delegation needs and nothing else reads:
    // WHICH element it was, and WHO presented a credential of their own — the
    // requester, who is the intermediary of the chain and is the one party this
    // function's `subject` deliberately does not name. handleRst() records the
    // act once the token exists; recording it here would claim a credential
    // that a later failure would have meant nobody held.
    return {
      ok: true, subject: delegated,
      delegation: {
        element: delegatedBy.element,
        both: !!delegatedBy.both,
        requester: credential ? credential.subject : '',
        requesterMethod: credential ? credential.method : '',
        // The identifier of the token that was delegated WITH, where it carried
        // one. handleRst() records it as what the act consumed, which is what
        // lets /admin/tokens/credential walk a chain of these hops back to the
        // sign-in that started it. See delegatedTokenId().
        tokenId: delegatedBy.tokenId || ''
      }
    };
  }
  if (credential) {
    log.debug("Leaving authenticate(). Accepted for " + credential.subject +
              ".");
    return { ok: true, subject: credential.subject };
  }
  // No credential — lenient (anonymous), so a "None" credential still issues.
  //
  // Deliberately NOT recorded as an authentication: no userid was presented, so
  // there is nothing to record. The assertion this issues names `anonymous`, and the
  // users page picks that up from the assertion instead — as a subject something was
  // issued to and who never authenticated, which is exactly what happened.
  log.debug("Leaving authenticate(). No credential was presented; treating as anonymous.");
  return { ok: true, subject: 'anonymous' };
}

function handleRst(rawBody, contentType, options) {
  log.debug("Entering handleRst().");
  options = options || {};
  const doc = new DOMParser().parseFromString(rawBody || '', 'text/xml');
  const version = detectSoapVersion(doc, contentType);
  const requestType = textByLocal(doc, 'RequestType');
  // Operation from the LAST path segment of RequestType, so any WS-Trust
  // version's namespace works (2004/04, 2005/02, or ws-sx 200512).
  const op = requestType.split('/').pop().toLowerCase();
  // Echo the request's trust namespace in the response (whatever version the
  // client used); fall back to 200512.
  const rstEl = firstByLocal(doc, 'RequestSecurityToken');
  const trustNs = (rstEl && rstEl.namespaceURI) || WST_NS;
  const statusTokenType = trustNs + '/RSTR/Status';
  const statusValid = trustNs + '/status/valid';
  const statusInvalid = trustNs + '/status/invalid';
  const keyTypeReq = textByLocal(doc, 'KeyType') || (trustNs + '/Bearer');

  const tokenTypeReq = textByLocal(doc, 'TokenType');
  const appliesToEl = firstByLocal(doc, 'AppliesTo');
  const audience = appliesToEl ? (textByLocal(appliesToEl, 'Address') || (appliesToEl.textContent || '').trim()) : '';
  const lifetimeEl = firstByLocal(doc, 'Lifetime');
  let lifetimeMin = 60;
  if (lifetimeEl) {
    const created = textByLocal(lifetimeEl, 'Created');
    const expires = textByLocal(lifetimeEl, 'Expires');
    if (created && expires) {
      const diff = (Date.parse(expires) - Date.parse(created)) / 60000;
      if (diff > 0) lifetimeMin = Math.round(diff);
    }
  }

  // EVERY operation authenticates, and it happens here — above the four
  // branches rather than inside two of them.
  //
  // Validate and Cancel used to return before this line was reached, so a
  // UsernameToken presented to either was accepted (the operation answered
  // 200) and recorded nowhere: the requester appeared in neither the admin
  // console's users page, nor the audit log, nor the embedded LDAP directory,
  // which grows its `uid=<name>,ou=users` entry off the same funnel. Half of
  // this endpoint's operations authenticated nobody.
  //
  // It also means the reserved password "invalid" now refuses a Validate and a
  // Cancel the way it already refused an Issue and a Renew, which is the answer
  // a client should get: a credential this service rejects does not become
  // acceptable because of what was asked with it.
  const auth = authenticate(doc);
  if (!auth.ok) {
    log.debug("Leaving handleRst(). Authentication failed, answering with a SOAP Fault.");
    return { status: 500, version: version, body: soapFault(version, auth.reason || 'Authentication failed.') };
  }

  if (op === 'validate') {
    const target = firstByLocal(doc, 'ValidateTarget');
    const hasToken = target && (firstByLocal(target, 'Assertion') || firstByLocal(target, 'BinarySecurityToken') || (target.textContent || '').trim());
    const code = hasToken ? statusValid : statusInvalid;
    const reason = hasToken ? 'The token is valid.' : 'No token to validate.';
    const rstr = '<wst:RequestSecurityTokenResponse xmlns:wst="' + trustNs + '">' +
      '<wst:TokenType>' + statusTokenType + '</wst:TokenType>' +
      '<wst:Status><wst:Code>' + code + '</wst:Code><wst:Reason>' + xmlEscape(reason) + '</wst:Reason></wst:Status>' +
      '</wst:RequestSecurityTokenResponse>';
    log.debug("Leaving handleRst(). Validate answered with wst:Status.");
    return { status: 200, version: version, body: envelope(version, trustNs + '/RSTR/ValidateFinal', rstr) };
  }

  if (op === 'cancel') {
    const rstr = '<wst:RequestSecurityTokenResponse xmlns:wst="' + trustNs + '">' +
      '<wst:RequestedTokenCancelled/></wst:RequestSecurityTokenResponse>';
    log.debug("Leaving handleRst(). Cancel answered with wst:RequestedTokenCancelled.");
    return { status: 200, version: version, body: envelope(version, trustNs + '/RSTR/CancelFinal', rstr) };
  }

  // Issue / Renew both mint (or re-mint) a token, for whoever authenticate()
  // above says this request is about.
  //
  // The one thing that answer does not cover is a Renew sent with NO credential
  // at all: the requester is anonymous, but the token being renewed names
  // somebody, and a renewal that came back about `anonymous` would have thrown
  // away the only subject in the exchange. So the RenewTarget's own NameID is
  // read for the SUBJECT — and only for the subject. It is not an
  // authentication and is not recorded as one: the token said it, nobody
  // presented it. A Renew that DID authenticate keeps its own subject, which is
  // what a service renewing a token in its own name should get.
  let subject = auth.subject;
  if (op === 'renew' && subject === 'anonymous') {
    const renewTarget = firstByLocal(doc, 'RenewTarget');
    const renewNameId = renewTarget && (firstByLocal(renewTarget, 'NameID') ||
      firstByLocal(renewTarget, 'NameIdentifier'));
    const renewNamed = renewNameId ?
      (renewNameId.textContent || '').trim() : '';
    if (renewNamed) {
      log.debug("An unauthenticated Renew; the subject is the one the " +
                "RenewTarget names, " + renewNamed + ".");
      subject = renewNamed;
    }
  }
  const tokenType = (tokenTypeReq === JWT_TOKEN_TYPE) ? JWT_TOKEN_TYPE : SAML2_TOKEN_TYPE;
  const tok = buildToken(tokenType, subject, audience, lifetimeMin);

  // Optional encryption (?encrypt=1): encrypt the SAML assertion to the recipient
  // certificate carried in the request's WS-Security signature (X509Data).
  if (options.encrypt && tok.tokenType === SAML2_TOKEN_TYPE) {
    const x509 = firstByLocal(doc, 'X509Certificate');
    const recipB64 = x509 ? (x509.textContent || '').replace(/\s+/g, '') : '';
    if (recipB64) {
      const recipPem = '-----BEGIN CERTIFICATE-----\n' + (recipB64.match(/.{1,64}/g) || []).join('\n') + '\n-----END CERTIFICATE-----\n';
      try { tok.xml = encryptAssertion(tok.xml, recipPem); tok.ref = ''; }
      catch (e) {
        log.error('encrypt failed, returning plaintext: ' + e.message);
      }
    } else {
      log.error('?encrypt=1 requested but no recipient certificate in the request signature; returning plaintext.');
    }
  }
  // THE RELYING PARTY. AppliesTo is WS-Trust's name for the service a token is
  // being issued FOR, and this is where one is about to be. It is optional in an
  // RST — a token with no AppliesTo has no audience restriction, which is a
  // state this service deliberately allows — so an absent one records nothing
  // rather than an empty application.
  //
  // The SECOND kind is the mirror of wsfed.js's: where the token issued is a
  // SAML 2.0 assertion, this AppliesTo is also its audience, which is exactly
  // what `saml2-service-provider` is defined as in KINDS. Recording only the
  // WS-Trust kind left that one reachable through WS-Federation alone, so the
  // console's filter answered "no SAML 2.0 service providers" for a service
  // that had just issued one. A JWT gets no second kind — there is no row for
  // it, and inventing a spelling here is how one application comes to be listed
  // under two.
  if (audience) {
    applications.seen({
      identifier: audience,
      kind: tok.tokenType === SAML2_TOKEN_TYPE
        ? ['wstrust-relying-party', 'saml2-service-provider']
        : 'wstrust-relying-party',
      protocol: 'WS-Trust',
      user: subject || '',
      note: 'a token was issued for this AppliesTo',
      fields: { wstrustAppliesTo: audience, samlEntityId: audience }
    });
  }

  // ---------------------------------------------------------------------------
  // THE DELEGATION ACT, for /admin/delegation.
  //
  // Recorded here rather than in authenticate() for the reason the KDC records
  // its own at the bottom of handleTgsReq(): this is the first line at which the
  // token EXISTS, and an act recorded where the decision was made would name a
  // credential nobody ever held. It is also the only place that knows the
  // AppliesTo, which is the TARGET of the chain — authenticate() reads the
  // security header and never sees it.
  //
  // Nothing about this is a check. This service accepts any delegation from
  // anybody about anybody, and the row says so in the column where a Kerberos
  // row names an attribute. That asymmetry is the most useful thing on the page:
  // the same picture, policed at one end and not at the other.
  // ---------------------------------------------------------------------------
  if (auth.delegation) {
    const via = auth.delegation.element;
    // -----------------------------------------------------------------------
    // WHICH APPLICATION THE AppliesTo IS, when one has registered it.
    //
    // The same resolution the token endpoint performs for an RFC 8693
    // `audience`, arriving through a different protocol, and it is here for the
    // same reason: this string names a SERVICE — `https://esb.example.com` —
    // and the register is keyed by the identifier an application PRESENTS. An
    // act filed under the URI draws a box on /admin/delegation/map that nothing
    // else in the picture mentions, so a two-hop chain through a middle tier
    // comes out as two unconnected halves: the AppliesTo the first hop asked
    // for and the name the second hop authenticated AS are one application
    // under two names.
    //
    // NOTHING IS REFUSED. An AppliesTo nobody registered resolves to null and
    // is recorded verbatim, exactly as it was before this existed — and the
    // raw string stays in the sentence beside the target either way, because
    // what was asked for is a fact about the request and must not be lost to a
    // resolution. See applications.forAppliesTo().
    // -----------------------------------------------------------------------
    const targetApplication = audience ? applications.forAppliesTo(audience)
                                       : null;
    if (targetApplication) {
      log.debug('the AppliesTo "' + audience + '" is registered to ' +
                'application "' + targetApplication.identifier + '" on ' +
                targetApplication.matchedAttribute + ', so the delegation is ' +
                'recorded against that application rather than against the URI.');
    }
    // AND WHETHER THE REQUESTER IS ONE TOO. The middle tier of a WS-Trust chain
    // authenticates with a credential rather than by naming an application, so
    // `presented` is where it belongs and is what the picture keys the box on.
    // But an ESB asking for a token to reach a back end IS an application, and
    // where this registry already holds an entry under that name the act says
    // so: the box then links to the entry and is drawn as a service rather than
    // as a person. A LOOKUP and not a claim — an unknown name leaves the slot
    // empty, exactly as before.
    const requesterApplication = auth.delegation.requester
      ? applications.get(auth.delegation.requester) : null;
    delegation.record({
      protocol: 'WS-Trust',
      type: via === 'ActAs' ? 'wstrust-actas' : 'wstrust-onbehalfof',
      outcome: 'issued',
      initial: {
        presented: subject,
        what: 'the subject named in <wst:' + via + '>, who presented nothing here'
      },
      intermediary: {
        // Empty where the request presented no credential of its own, which is
        // allowed here and is worth seeing: an ANONYMOUS requester asked for a
        // token about somebody else and got one. The page draws that as a gap
        // in the chain rather than as a missing value.
        presented: auth.delegation.requester,
        application: requesterApplication ? requesterApplication.identifier : '',
        what: auth.delegation.requester
          ? 'the requester, authenticated by ' + auth.delegation.requesterMethod +
            (requesterApplication
              ? ', and an application in this registry'
              : '')
          : 'nobody — the request presented no credential of its own, and this ' +
            'service issued the token anyway'
      },
      target: {
        application: targetApplication ? targetApplication.identifier : audience,
        what: audience
          ? (targetApplication
              ? 'the application registered for the AppliesTo "' + audience +
                '" on ' + targetApplication.matchedAttribute + ', which is ' +
                'also the assertion\'s audience. The request named the ' +
                'service; this registry named the application'
              : 'the AppliesTo, which is also the assertion\'s audience. No ' +
                'application here has registered it, so it is recorded ' +
                'exactly as it was asked for')
          : 'unstated — the RST carried no AppliesTo, so the token issued has ' +
            'no audience restriction at all'
      },
      authorizedBy: 'nothing. WS-Trust puts no authorization on ' +
                    '<wst:' + via + '> and this service adds none: any ' +
                    'requester may ask for a token about anybody. A real STS ' +
                    'decides this from policy that has no place in the message.',
      consumed: (auth.delegation.requester
        ? [{ kind: 'WS-Security credential',
             note: auth.delegation.requesterMethod }]
        : []).concat(auth.delegation.tokenId
        ? [{ kind: 'delegated token',
             identifier: auth.delegation.tokenId,
             note: 'the token inside <wst:' + via + '>, which is what this ' +
                   'request is delegating WITH. Its signature and Conditions ' +
                   'are not checked; the identifier is read so that the ' +
                   'lineage of what came out can be followed back through it' }]
        : []),
      produced: [{
        kind: tok.tokenType === SAML2_TOKEN_TYPE ? 'SAML 2.0 assertion' : 'JWT',
        identifier: tok.id || '',
        note: tok.id ? 'AssertionID'
                     : 'this token type carries no identifier here — the ' +
                       'WS-Trust JWT is signed directly rather than through ' +
                       'signJwt(), so it has no jti and is in no register'
      }],
      note: auth.delegation.both
        ? 'The request carried BOTH <wst:OnBehalfOf> and <wst14:ActAs>. ' +
          'OnBehalfOf is what this act is attributed to, which is the order ' +
          'this service has always read them in.'
        : (via === 'ActAs'
            ? 'ActAs is COMPOSITE: the far end is meant to be able to see that ' +
              'a middle tier is acting. Nothing in the token this service ' +
              'issues carries that, which is a gap in the mock rather than in ' +
              'the profile.'
            : 'OnBehalfOf is IMPERSONATION: the assertion names the subject ' +
              'and says nothing about the requester, so the relying party sees ' +
              'an ordinary sign-in.')
    });
  }

  const appliesToOut = audience
    ? '<wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy"' +
      ' xmlns:wsa="http://www.w3.org/2005/08/addressing"><wsa:EndpointReference><wsa:Address>' +
      xmlEscape(audience) + '</wsa:Address></wsa:EndpointReference></wsp:AppliesTo>'
    : '';
  const rstrInner =
    '<wst:TokenType>' + tok.tokenType + '</wst:TokenType>' +
    '<wst:RequestedSecurityToken>' + tok.xml + '</wst:RequestedSecurityToken>' +
    appliesToOut +
    '<wst:Lifetime xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">' +
    '<wsu:Created>' + iso(0) + '</wsu:Created><wsu:Expires>' + iso(lifetimeMin) + '</wsu:Expires></wst:Lifetime>' +
    '<wst:KeyType>' + keyTypeReq + '</wst:KeyType>' +
    tok.ref;

  if (op === 'renew') {
    const rstr = '<wst:RequestSecurityTokenResponse xmlns:wst="' + trustNs + '">' + rstrInner + '</wst:RequestSecurityTokenResponse>';
    log.debug("Leaving handleRst(). Renew answered with a fresh token.");
    return { status: 200, version: version, body: envelope(version, trustNs + '/RSTR/RenewFinal', rstr) };
  }

  // Issue -> RSTR Collection (WS-Trust 1.3+; pre-OASIS clients tolerate it too).
  const rstrc = '<wst:RequestSecurityTokenResponseCollection xmlns:wst="' + trustNs + '">' +
    '<wst:RequestSecurityTokenResponse>' + rstrInner + '</wst:RequestSecurityTokenResponse>' +
    '</wst:RequestSecurityTokenResponseCollection>';
  log.debug("Leaving handleRst(). Issue answered with an RSTR Collection.");
  return { status: 200, version: version, body: envelope(version, trustNs + '/RSTRC/IssueFinal', rstrc) };
}

app.get('/sts/cert', function (req, res) {
  log.debug("Entering the STS certificate endpoint.");
  res.type('text/plain').send(STS.certPem);
  log.debug("Leaving the STS certificate endpoint.");
});

app.get('/sts', function (req, res) {
  log.debug("Entering the STS description endpoint.");
  res.type('text/plain').send('WS-Trust STS mock. POST a SOAP RequestSecurityToken here.\nIssuer: ' +
                              config.value('wstrust.issuer') + '\n');
  log.debug("Leaving the STS description endpoint.");
});

app.post('/sts', function (req, res) {
  log.debug("Entering the WS-Trust STS endpoint.");
  const contentType = req.headers['content-type'] || '';
  try {
    const encrypt = req.query.encrypt === '1' || req.query.encrypt === 'true';
    const result = handleRst(req.body || '', contentType, { encrypt: encrypt });
    const ct = result.version === '1.1' ? 'text/xml; charset=utf-8' : 'application/soap+xml; charset=utf-8';
    res.status(result.status).type(ct).send(result.body);
    log.debug("Leaving the WS-Trust STS endpoint. HTTP " + result.status + ".");
  } catch (e) {
    log.error('STS error: ' + (e && e.stack ? e.stack : e));
    res.status(500).type('application/soap+xml; charset=utf-8')
       .send(soapFault('1.2', 'STS error: ' + (e && e.message ? e.message : String(e))));
    log.debug("Leaving the WS-Trust STS endpoint. It failed.");
  }
});

module.exports = {
  handleRst: handleRst,
  buildToken: buildToken,
  soapFault: soapFault
};
