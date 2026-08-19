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

const jwt = require('jsonwebtoken');
const { DOMParser, XMLSerializer } = require('@xmldom/xmldom');
const app = require('./app');
// firstByLocal/textByLocal were written here and now live in helpers.js: WS-Federation
// reads the same shapes (a `wreq` RST, and a `wresult` at its mock relying party), and a
// second copy of a reader that has to cope with four trust namespaces is a second copy
// that gets one of them wrong.
const { log, logArtifact, STS, xmlEscape, iso,
        firstByLocal, textByLocal } = require('./helpers');
// wstrust.issuer. A SAML token requested THROUGH WS-Trust is built by the
// SAML modules and carries saml.issuer instead; the two are separate
// settings for that reason and default to the same value.
const config = require('./config');
const { buildSamlAssertion, encryptAssertion } = require('./saml2');
const stats = require('./admin_stats');
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
  const signed = jwt.sign(claims, STS.privateKeyPem, opts);
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
      ' ValueType="urn:ietf:params:oauth:token-type:jwt">' + raw + '</wsse:BinarySecurityToken>', ref: '', tokenType: JWT_TOKEN_TYPE };
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
  return { xml: assertion, ref: ref, tokenType: SAML2_TOKEN_TYPE };
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

// The subject named in `wst:OnBehalfOf` or `wst:ActAs`, or '' when the request
// delegates nothing.
function delegatedSubject(doc) {
  log.debug("Entering delegatedSubject().");
  const obo = firstByLocal(doc, 'OnBehalfOf') || firstByLocal(doc, 'ActAs');
  if (!obo) {
    log.debug("Leaving delegatedSubject(). Nothing is delegated.");
    return '';
  }
  const nameId = firstByLocal(obo, 'NameID') ||
    firstByLocal(obo, 'NameIdentifier');
  const named = (nameId && (nameId.textContent || '').trim()) ||
    'delegated-subject';
  log.debug("Leaving delegatedSubject(). " + named + ".");
  return named;
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
  const delegated = delegatedSubject(doc);
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
    return { ok: true, subject: delegated };
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
