'use strict';
//
// File: sp_metadata.js
//
// ===========================================================================
// A SERVICE PROVIDER'S OWN METADATA: PARSING IT, AND FETCHING IT.
//
// Added 2026-08-27 with SAML 2.0 encryption, because encrypting to a service
// provider means holding its public key and this service had nowhere to get one
// from. `saml/CLAUDE.md` said for months that this profile "does not consume SP
// metadata"; it does now, in exactly one direction and for exactly one value.
//
// ---------------------------------------------------------------------------
// IT IS A LIBRARY. It registers no route (rule 3), and it is required by
// `admin-ui/admin.js` for the refresh action and by `saml2_sso.js` for the
// parse. It requires `helpers`, `config` and `applications` and nothing that
// requires it, so it closes no cycle and moves nothing in the router.
//
// ---------------------------------------------------------------------------
// THE FETCH NEVER HAPPENS DURING A FLOW, and that is the single most important
// property here.
//
// `refresh()` is called from a console button and from
// `POST /admin-api/applications/refresh-metadata`. It writes what it found onto
// the application entry, and ISSUING READS THE ENTRY. Nothing in the sign-on
// path dials anything.
//
// The alternative — resolve the URL when an assertion is being built — is what
// a real identity provider does with a cache, and it was rejected for a reason
// worth writing down: an assertion that has to wait on somebody else's web
// server makes every sign-in exactly as reliable as that server, and the
// failure arrives in the middle of a browser redirect where the only honest
// thing to render is a page about a timeout. A mock whose sign-ins fail because
// a metadata host is slow is a mock nobody can debug a client with.
//
// ---------------------------------------------------------------------------
// THIS IS THE SECOND OUTBOUND-REQUEST SURFACE IN THIS SERVICE, and federation
// was the first and, until now, the only one — `federation/CLAUDE.md` argues at
// length that dialling a URL is a capability this service does not hand out. The
// same three refusals apply here and for the same reasons:
//
//   * THE URL COMES OFF THE APPLICATION ENTRY and from nowhere else. `refresh()`
//     takes an application identifier, not a URL. A caller cannot ask this
//     service to dial an address of their choosing, which is the difference
//     between a metadata fetcher and an open proxy.
//   * THE SCHEME IS CHECKED. https always; http only with
//     `federation.outboundAllowInsecure` on. That setting is REUSED rather than
//     copied: a deployment has decided once whether this service may make a
//     request in the clear, and a second setting would be a second answer to
//     one question.
//   * IT TIMES OUT, on `federation.outboundTimeoutMs`, for the same reason.
//
// What it does NOT do is follow redirects or accept anything but XML, and
// neither is an oversight: a redirect is how a URL somebody vetted becomes a
// URL nobody vetted.
// ===========================================================================

const http = require('http');
const https = require('https');
const { URL } = require('url');
const { DOMParser } = require('@xmldom/xmldom');
const forge = require('node-forge');

const { log } = require('../common/helpers');
const config = require('../common/config');
const applications = require('../common/applications');

// The metadata namespace, and the two this file reads inside it. Matched on
// LOCAL NAME everywhere below — `getElementsByTagNameNS('*', ...)` — because a
// metadata document may use `md:`, `saml2:` or no prefix at all and all three
// are the same document. helpers.firstByLocal() follows the same rule.
const MAX_METADATA_BYTES = 512 * 1024;

// ---------------------------------------------------------------------------
// PARSE, and it answers rather than throws.
//
// `{ ok, certificate, entityId, acs[], slo[], why }`. What the caller wants is
// `certificate`; the rest is reported because a person looking at a metadata
// document wants to know this service read the same one they did.
//
// WHICH KEY IS THE ENCRYPTION KEY, in the order the specification implies:
// a KeyDescriptor with `use="encryption"`, then one with NO `use` at all —
// which section 2.4.1.1 says serves both purposes — and never one marked
// `use="signing"`, which is the key that would look right and be wrong. A
// document with a signing key only therefore yields no certificate here, and
// the CALLER falls back to `samlSigningCertificate` if it wants to; making that
// decision here would hide it inside a parser.
// ---------------------------------------------------------------------------
function parse(xml) {
  log.debug("Entering parse().");
  const text = String(xml || '').trim();
  if (!text) {
    log.debug("Leaving parse(). Empty.");
    return { ok: false, why: 'there is no metadata document to read' };
  }
  let doc;
  try {
    doc = new DOMParser().parseFromString(text, 'text/xml');
  } catch (e) {
    log.debug("Leaving parse(). It will not parse.");
    return { ok: false, why: 'the metadata is not well-formed XML: ' + e.message };
  }
  if (!doc || !doc.documentElement) {
    log.debug("Leaving parse(). No root element.");
    return { ok: false, why: 'the metadata has no root element' };
  }
  const root = doc.documentElement;
  // An EntitiesDescriptor holding several entities is legal and is NOT
  // supported: which of them this application is cannot be worked out from a
  // document that does not know which application it was fetched for, and
  // guessing the first would silently encrypt to whoever happened to be listed
  // first. Named rather than half-handled.
  if (root.localName === 'EntitiesDescriptor') {
    log.debug("Leaving parse(). An EntitiesDescriptor.");
    return { ok: false, why: 'this is an <md:EntitiesDescriptor> holding several entities. ' +
             'Give the <md:EntityDescriptor> for this one service provider — a document ' +
             'listing many does not say which of them this application is, and picking the ' +
             'first would encrypt to whoever happens to be listed first' };
  }

  const out = {
    ok: true,
    entityId: root.getAttribute('entityID') || '',
    certificate: '',
    certificateUse: '',
    acs: [],
    slo: []
  };

  const descriptors = doc.getElementsByTagNameNS('*', 'KeyDescriptor');
  let unqualified = '';
  for (let n = 0; n < descriptors.length; n++) {
    const use = (descriptors[n].getAttribute('use') || '').trim();
    const certs = descriptors[n].getElementsByTagNameNS('*', 'X509Certificate');
    if (!certs.length) continue;
    const value = (certs[0].textContent || '').replace(/\s+/g, '');
    if (!value) continue;
    if (use === 'encryption') {
      out.certificate = value;
      out.certificateUse = 'encryption';
      break;
    }
    if (!use && !unqualified) unqualified = value;
  }
  if (!out.certificate && unqualified) {
    out.certificate = unqualified;
    out.certificateUse = 'unspecified';
  }

  // The endpoints, reported and NOT written anywhere. This service already
  // learns an assertion consumer service URL from the request that named one,
  // which is a fact about what actually happened; a URL from metadata is a
  // claim about what should happen, and quietly preferring it would change
  // where responses go on the strength of a document somebody pasted.
  const collect = function (element, into) {
    const els = doc.getElementsByTagNameNS('*', element);
    for (let n = 0; n < els.length; n++) {
      const location = els[n].getAttribute('Location') || '';
      if (location && into.indexOf(location) < 0) into.push(location);
    }
  };
  collect('AssertionConsumerService', out.acs);
  collect('SingleLogoutService', out.slo);

  if (!out.certificate) {
    out.ok = false;
    out.why = 'the metadata carries no <md:KeyDescriptor> with an X509Certificate that ' +
              'can be used for encryption. A descriptor marked use="signing" is ' +
              'deliberately not taken — it is the key that would look right and be wrong';
  }
  log.debug("Leaving parse(). certificate=" + (out.certificate ? out.certificateUse : 'none'));
  return out;
}

// A base64 DER certificate as a PEM, which is what forge and the encryptor
// want. It ACCEPTS a PEM too, so an operator who pasted one into
// `samlEncryptionCertificate` is not told their certificate is invalid because
// of its punctuation.
function toPem(value) {
  const text = String(value || '').trim();
  if (!text) return '';
  if (text.indexOf('-----BEGIN') === 0) return text;
  const body = text.replace(/\s+/g, '').replace(/-----[^-]+-----/g, '');
  if (!body) return '';
  return '-----BEGIN CERTIFICATE-----\n' +
         (body.match(/.{1,64}/g) || []).join('\n') +
         '\n-----END CERTIFICATE-----\n';
}

// Is this actually a certificate? Called before anything is stored, so a
// paste-o is refused at the door rather than at the next sign-in — where the
// only symptom would be an assertion quietly going out in clear.
function certificateProblem(value) {
  const pem = toPem(value);
  if (!pem) return 'it is empty';
  try {
    const cert = forge.pki.certificateFromPem(pem);
    if (!cert.publicKey || !cert.publicKey.n) {
      return 'its public key is not an RSA key, and XML Encryption key transport here ' +
             'wraps to RSA';
    }
    return '';
  } catch (e) {
    return 'it is not a certificate this service can read (' + e.message + ')';
  }
}

function allowInsecure() {
  return !!config.value('federation.outboundAllowInsecure');
}

function timeoutMs() {
  return Number(config.value('federation.outboundTimeoutMs')) || 5000;
}

// The same shape federation_http.js's urlProblem() has, and it cites the same
// setting because it is the same question: may this service make a request in
// the clear?
function urlProblem(raw) {
  const text = String(raw || '').trim();
  if (!text) return 'there is no samlSpMetadataUrl on this application';
  let parsed;
  try {
    parsed = new URL(text);
  } catch (e) {
    return '"' + text + '" is not a URL (' + e.message + ')';
  }
  if (parsed.protocol === 'https:') return '';
  if (parsed.protocol === 'http:') {
    return allowInsecure() ? ''
      : 'it is an http:// URL and federation.outboundAllowInsecure is off. That setting ' +
        'is shared rather than duplicated: a deployment has decided once whether this ' +
        'service may make a request in the clear';
  }
  return 'its scheme is "' + parsed.protocol.replace(':', '') + '", and only https ' +
         '(or http, with federation.outboundAllowInsecure on) is dialled';
}

// ---------------------------------------------------------------------------
// FETCH ONE DOCUMENT. Returns a promise of `{ ok, xml, why, status }` and NEVER
// rejects, for federation_http.js's reason: a rejected promise would have to be
// caught at every call site, and the one added later would not be.
// ---------------------------------------------------------------------------
function fetchMetadata(url) {
  log.debug("Entering fetchMetadata(). url=" + url);
  return new Promise(function (resolve) {
    const problem = urlProblem(url);
    if (problem) {
      log.debug("Leaving fetchMetadata(). Refused: " + problem);
      resolve({ ok: false, why: problem });
      return;
    }
    const parsed = new URL(String(url).trim());
    const agent = parsed.protocol === 'https:' ? https : http;
    let settled = false;
    const done = function (answer) {
      if (settled) return;
      settled = true;
      resolve(answer);
    };
    const request = agent.get(String(url).trim(), {
      headers: { accept: 'application/samlmetadata+xml, application/xml, text/xml' }
    }, function (res) {
      // NO REDIRECT FOLLOWING, deliberately: a redirect is how a URL somebody
      // vetted becomes a URL nobody vetted, and this is one of two places in
      // this service that dials anything at all.
      if (res.statusCode >= 300 && res.statusCode < 400) {
        res.resume();
        done({ ok: false, status: res.statusCode,
               why: 'it answered ' + res.statusCode + ' with a redirect to "' +
                    (res.headers.location || '(no Location)') + '". Redirects are not ' +
                    'followed here — a redirect is how a vetted URL becomes an unvetted ' +
                    'one. Put the final URL on the entry' });
        return;
      }
      if (res.statusCode !== 200) {
        res.resume();
        done({ ok: false, status: res.statusCode,
               why: 'it answered ' + res.statusCode + ' rather than 200' });
        return;
      }
      let body = '';
      let size = 0;
      res.setEncoding('utf8');
      res.on('data', function (chunk) {
        size += chunk.length;
        if (size > MAX_METADATA_BYTES) {
          // A cap, because the other end is not this service's to trust and a
          // metadata document is kilobytes. Destroying the socket is what stops
          // an endless response from being read into memory.
          request.destroy();
          done({ ok: false, why: 'the document is larger than ' + MAX_METADATA_BYTES +
                 ' bytes, which no service provider metadata is' });
          return;
        }
        body += chunk;
      });
      res.on('end', function () {
        done({ ok: true, xml: body, status: 200 });
      });
    });
    request.setTimeout(timeoutMs(), function () {
      request.destroy();
      done({ ok: false, why: 'it did not answer within ' + timeoutMs() +
             'ms (federation.outboundTimeoutMs)' });
    });
    request.on('error', function (e) {
      // The message is the node error's, because "self-signed certificate",
      // "connection refused" and "getaddrinfo ENOTFOUND" send somebody to three
      // different places and a single word for all three sends them nowhere.
      done({ ok: false, why: 'the request failed: ' + e.message });
    });
  });
}

// ---------------------------------------------------------------------------
// THE WHOLE ACT: fetch what the entry names, parse it, and write back what was
// found. This is what the console button and the management API both call.
//
// IT WRITES THREE ATTRIBUTES — the document, the certificate and nothing else —
// and it writes NOTHING when anything fails, so a refresh that could not reach
// the host leaves the last good certificate in place. An application that was
// working does not stop working because a metadata server was down.
// ---------------------------------------------------------------------------
function refresh(identifier) {
  log.debug("Entering refresh(). identifier=" + identifier);
  const record = applications.get(identifier);
  if (!record) {
    log.debug("Leaving refresh(). No such application.");
    return Promise.resolve({ ok: false, errors: ['There is no application "' + identifier +
      '" in this registry. Create it first — a metadata URL is an attribute on an entry, ' +
      'and this action never takes a URL from the caller.'] });
  }
  const url = ((record.fields && record.fields.samlSpMetadataUrl) || '');
  const wanted = Array.isArray(url) ? url[0] : url;
  return fetchMetadata(wanted).then(function (answer) {
    if (!answer.ok) {
      log.warn('saml2: could not refresh metadata for ' + identifier + ' — ' + answer.why +
               '. Nothing on the entry was changed.');
      log.debug("Leaving refresh(). The fetch failed.");
      return { ok: false, errors: ['The metadata at "' + wanted + '" could not be read: ' +
        answer.why + '. Nothing on the entry was changed, so whatever certificate it ' +
        'already had is still in force.'] };
    }
    const parsed = parse(answer.xml);
    if (!parsed.ok) {
      log.debug("Leaving refresh(). The document is unusable.");
      return { ok: false, errors: ['The document at "' + wanted + '" was fetched but ' +
        parsed.why + '. Nothing on the entry was changed.'] };
    }
    const bad = certificateProblem(parsed.certificate);
    if (bad) {
      log.debug("Leaving refresh(). The certificate is unusable.");
      return { ok: false, errors: ['The metadata at "' + wanted + '" carries a certificate ' +
        'this service cannot use: ' + bad + '. Nothing on the entry was changed.'] };
    }
    const stored = [
      applications.updateApplication(identifier,
        { mode: 'set', attribute: 'samlSpMetadata', value: answer.xml }),
      applications.updateApplication(identifier,
        { mode: 'set', attribute: 'samlEncryptionCertificate', value: parsed.certificate })
    ];
    const failed = stored.filter(function (one) { return !one.ok; });
    if (failed.length) {
      log.debug("Leaving refresh(). The entry would not take it.");
      return { ok: false, errors: failed.reduce(function (all, one) {
        return all.concat(one.errors || []);
      }, []) };
    }
    log.info('saml2: refreshed the metadata for ' + identifier + ' from ' + wanted +
             '. Its encryption certificate is the ' + parsed.certificateUse +
             ' KeyDescriptor; entityID "' + parsed.entityId + '", ' + parsed.acs.length +
             ' assertion consumer service(s) and ' + parsed.slo.length +
             ' single logout service(s) are described and are REPORTED ONLY — ' +
             'this service still sends a response where the request asked.');
    log.debug("Leaving refresh(). Stored.");
    return { ok: true, application: identifier, url: wanted,
             entityId: parsed.entityId,
             certificateUse: parsed.certificateUse,
             assertionConsumerServices: parsed.acs,
             singleLogoutServices: parsed.slo,
             message: 'The metadata was fetched and its ' + parsed.certificateUse +
                      ' certificate is now on the entry, so an assertion for this service ' +
                      'provider can be encrypted to it. The endpoints in the document are ' +
                      'reported and NOT applied — a response still goes where the request ' +
                      'asks, which is what actually happened rather than what a document ' +
                      'claims should.' };
  });
}

module.exports = {
  parse: parse,
  toPem: toPem,
  certificateProblem: certificateProblem,
  urlProblem: urlProblem,
  fetchMetadata: fetchMetadata,
  refresh: refresh
};
