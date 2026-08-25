'use strict';
//
// File: spiffe_id.js
//
// ---------------------------------------------------------------------------
// THE SPIFFE ID GRAMMAR, and nothing else.
//
// A SPIFFE ID is a URI — `spiffe://<trust domain>/<path>` — and it is the one
// thing every other module in this family passes around: the registry keys
// entries by it, the CA puts it in a URI subjectAltName, the Workload API
// returns it beside every SVID, and the SPIRE Server API takes it apart into
// the `spire.api.types.SPIFFEID` message (a trust domain and a path, as two
// separate fields) and puts it back together again.
//
// It is a LIBRARY in the sense rule 3 means: it registers no route, and it
// requires only `helpers.js` for the log. Nothing here can join a cycle, and
// its position in the require order does not matter.
//
// ---------------------------------------------------------------------------
// WHY THIS IS A FILE RATHER THAN A REGULAR EXPRESSION AT FOUR CALL SITES
//
// Because the grammar is stricter than it looks, and every way of getting it
// wrong produces an identifier that is ACCEPTED by a URL parser, LOOKS right in
// a log, and is then refused by a real SPIFFE implementation — or, worse, is
// accepted by one and understood as naming something else.
//
//   * **The trust domain is lower-case.** `spiffe://Example.org/x` is not a
//     valid SPIFFE ID; it is not the same identifier as `spiffe://example.org/x`
//     either. The SPIFFE-ID specification says a trust domain name MUST contain
//     only lower-case letters, digits, dots, dashes and underscores. `new
//     URL()` will happily lower-case the host for you, which HIDES the defect:
//     a client that sent the upper-case form gets an SVID naming the lower-case
//     one and nothing anywhere reports a difference. So the check is made on
//     the raw text BEFORE any URL parsing, and the upper-case form is REFUSED
//     rather than normalised — this service exists to show a client author what
//     a conforming server would do with what they sent.
//
//   * **The path is NOT a URL path.** Percent-encoding is not permitted, an
//     empty segment is not permitted (so no trailing slash and no `//`), and
//     the relative segments `.` and `..` are not permitted. `new URL()` accepts
//     every one of those and normalises three of them away.
//
//   * **There is no port, no userinfo, no query and no fragment.** Each is a
//     way of writing an identifier that a naive `startsWith()` comparison
//     treats as belonging to a trust domain it does not belong to — which is an
//     authorization bug in anything that federates.
//
//   * **`/spire/…` is reserved**, and this service mints identifiers in it
//     itself (the server's own ID, and every agent's). An entry registered at a
//     reserved path would be an identifier this service issues for two
//     different reasons, so the registry refuses one — see `isReservedPath()`.
//
// The lengths are from the specification too: 2048 bytes for the whole
// identifier, 255 for the trust domain name. They are checked in BYTES rather
// than in characters, because the specification says bytes and a path may hold
// multi-byte UTF-8 in principle — though in practice the character class below
// keeps everything to one byte per character, so the two only differ on input
// that is already being refused.
// ---------------------------------------------------------------------------

const { log } = require('../common/helpers');

// The scheme, written once. Compared case-insensitively when reading (a URI
// scheme is case-insensitive per RFC 3986) and always written lower-case.
const SCHEME = 'spiffe';
const PREFIX = SCHEME + '://';

// From the SPIFFE-ID specification: the whole identifier, and the trust domain
// name within it.
const MAX_ID_BYTES = 2048;
const MAX_TRUST_DOMAIN_BYTES = 255;

// The two character classes, as they are written in the specification rather
// than as the shortest regular expression that happens to match them. The trust
// domain has NO upper case in it and the path does — that asymmetry is real and
// is the single most common thing to get wrong here.
const TRUST_DOMAIN_CHARS = /^[a-z0-9.\-_]+$/;
const PATH_SEGMENT_CHARS = /^[a-zA-Z0-9.\-_]+$/;

// The reserved path prefix. Everything under it belongs to the SPIFFE
// implementation itself — the server, the agents it attests, and the join
// tokens it mints — and a workload registered there would be given an
// identifier this service also issues on its own account.
const RESERVED_PREFIX = '/spire';

function byteLength(text) {
  return Buffer.byteLength(String(text == null ? '' : text), 'utf8');
}

// ---------------------------------------------------------------------------
// READING ONE.
//
// Returns an object rather than throwing, and it always returns an object: the
// callers are protocol handlers that have to answer with a specific error code
// (`InvalidArgument` on the SPIRE Server API, a refusal on the console, a 400
// on the bundle endpoint) and each of them wants the REASON in its own words.
// A thrown Error would make every caller write the same try/catch and would
// lose the distinction between "this is not a SPIFFE ID" and "this is a SPIFFE
// ID belonging to somebody else".
//
//   { ok: true,  id, trustDomain, path, segments }
//   { ok: false, reason }
//
// `path` is '' for a trust-domain-only identifier — `spiffe://example.org`,
// which is a valid SPIFFE ID and is what names the trust domain itself in a
// bundle map. That case is the reason `path` is not defaulted to '/'.
// ---------------------------------------------------------------------------
function parse(value) {
  log.debug('Entering parse(). value=' + value);
  const text = String(value == null ? '' : value);
  if (!text) {
    log.debug('Leaving parse(). Empty.');
    return { ok: false, reason: 'A SPIFFE ID is required and none was given.' };
  }
  if (byteLength(text) > MAX_ID_BYTES) {
    log.debug('Leaving parse(). Too long.');
    return { ok: false, reason: 'A SPIFFE ID may be at most ' + MAX_ID_BYTES +
                                ' bytes; this one is ' + byteLength(text) + '.' };
  }
  // The scheme, case-insensitively, and then everything after it is handled as
  // raw text. Deliberately NOT `new URL()`: that parser lower-cases the host,
  // normalises `.` and `..` out of the path, accepts percent-encoding and
  // accepts a port — four defects it would hide rather than report.
  if (text.slice(0, PREFIX.length).toLowerCase() !== PREFIX) {
    log.debug('Leaving parse(). Wrong scheme.');
    return { ok: false, reason: 'A SPIFFE ID begins with ' + PREFIX +
                                '; this one begins with ' +
                                text.slice(0, 16) + '.' };
  }
  const rest = text.slice(PREFIX.length);
  const slash = rest.indexOf('/');
  const authority = slash === -1 ? rest : rest.slice(0, slash);
  const path = slash === -1 ? '' : rest.slice(slash);

  // The authority is the trust domain name and NOTHING else. Userinfo and a
  // port are both refused by name rather than by the character class, because
  // "invalid character @" tells a caller much less than saying what the shape
  // of the thing is.
  if (!authority) {
    log.debug('Leaving parse(). No trust domain.');
    return { ok: false, reason: 'A SPIFFE ID names a trust domain between ' +
                                PREFIX + ' and the first /; this one names none.' };
  }
  if (authority.indexOf('@') !== -1) {
    log.debug('Leaving parse(). Userinfo.');
    return { ok: false, reason: 'A SPIFFE ID carries no userinfo; the trust ' +
                                'domain is the whole authority.' };
  }
  if (authority.indexOf(':') !== -1) {
    log.debug('Leaving parse(). Port.');
    return { ok: false, reason: 'A SPIFFE ID carries no port; the trust ' +
                                'domain is the whole authority.' };
  }
  if (byteLength(authority) > MAX_TRUST_DOMAIN_BYTES) {
    log.debug('Leaving parse(). Trust domain too long.');
    return { ok: false, reason: 'A trust domain name may be at most ' +
                                MAX_TRUST_DOMAIN_BYTES + ' bytes; this one is ' +
                                byteLength(authority) + '.' };
  }
  if (!TRUST_DOMAIN_CHARS.test(authority)) {
    // The upper-case case is called out on its own, because it is the one a
    // reader will otherwise stare at: `spiffe://Example.org/x` looks like a
    // perfectly ordinary URI and is refused for a reason that is invisible
    // unless somebody says it.
    const upper = /[A-Z]/.test(authority);
    log.debug('Leaving parse(). Bad trust domain characters.');
    return { ok: false, reason: upper
      ? 'A trust domain name is lower-case: ' + authority + ' is not a valid ' +
        'trust domain, and it is not another spelling of ' +
        authority.toLowerCase() + ' either — they are different identifiers.'
      : 'A trust domain name holds only lower-case letters, digits, dots, ' +
        'dashes and underscores; this one is ' + authority + '.' };
  }

  // The path. Empty is valid and names the trust domain itself.
  const segments = [];
  if (path) {
    if (path.indexOf('?') !== -1 || path.indexOf('#') !== -1) {
      log.debug('Leaving parse(). Query or fragment.');
      return { ok: false, reason: 'A SPIFFE ID carries no query and no ' +
                                  'fragment.' };
    }
    if (path.indexOf('%') !== -1) {
      log.debug('Leaving parse(). Percent-encoding.');
      return { ok: false, reason: 'A SPIFFE ID path is not percent-encoded; ' +
                                  '% is not a permitted character.' };
    }
    const parts = path.split('/');
    // The first is always '' because the path begins with '/'.
    for (let i = 1; i < parts.length; i++) {
      const segment = parts[i];
      if (!segment) {
        log.debug('Leaving parse(). Empty segment.');
        return { ok: false, reason: 'A SPIFFE ID path has no empty segment, ' +
                                    'so no trailing slash and no //.' };
      }
      if (segment === '.' || segment === '..') {
        log.debug('Leaving parse(). Relative segment.');
        return { ok: false, reason: 'A SPIFFE ID path has no relative ' +
                                    'segment: . and .. are not permitted.' };
      }
      if (!PATH_SEGMENT_CHARS.test(segment)) {
        log.debug('Leaving parse(). Bad path characters.');
        return { ok: false, reason: 'A SPIFFE ID path segment holds only ' +
                                    'letters, digits, dots, dashes and ' +
                                    'underscores; this one is ' + segment + '.' };
      }
      segments.push(segment);
    }
  }
  log.debug('Leaving parse(). trustDomain=' + authority + ', path=' + (path || '(none)'));
  return { ok: true, id: PREFIX + authority + path, trustDomain: authority,
           path: path, segments: segments };
}

// The plain question, for the many callers that only want yes or no.
function isValid(value) {
  return parse(value).ok;
}

// ---------------------------------------------------------------------------
// WRITING ONE.
//
// `make('example.org', 'ns/default/sa/web')` and `make('example.org',
// '/ns/default/sa/web')` are the same call: the leading slash is supplied where
// it is missing, because half the callers here have a path that came off a
// protobuf field (which carries it with the slash) and half are building one
// from parts. It THROWS on something that is not a valid identifier, which is
// the opposite of parse() and is deliberate — a caller building an identifier
// out of its own values has a bug if the result is invalid, where a caller
// reading one has been handed something.
// ---------------------------------------------------------------------------
function make(trustDomain, path) {
  log.debug('Entering make(). trustDomain=' + trustDomain);
  const domain = String(trustDomain == null ? '' : trustDomain).trim();
  let tail = String(path == null ? '' : path).trim();
  if (tail && tail.charAt(0) !== '/') tail = '/' + tail;
  const parsed = parse(PREFIX + domain + tail);
  if (!parsed.ok) {
    log.debug('Leaving make(). Invalid.');
    throw new Error('Cannot build a SPIFFE ID from trust domain "' + domain +
                    '" and path "' + path + '": ' + parsed.reason);
  }
  log.debug('Leaving make(). id=' + parsed.id);
  return parsed.id;
}

// The trust domain as an identifier in its own right — `spiffe://example.org`,
// with no path. This is what keys a bundle map on both the Workload API and the
// SPIRE Server API, and it is a valid SPIFFE ID rather than a special case.
function trustDomainId(trustDomain) {
  return PREFIX + String(trustDomain == null ? '' : trustDomain).trim().toLowerCase();
}

// The trust domain NAME out of an identifier, or '' if it is not one. Named
// separately from parse() because a great many callers want only this and
// reading `.trustDomain` off a failed parse silently gives undefined.
function trustDomainOf(value) {
  const parsed = parse(value);
  return parsed.ok ? parsed.trustDomain : '';
}

// Whether an identifier belongs to a trust domain. A STRING COMPARISON OF THE
// PARSED TRUST DOMAIN, never a `startsWith()` on the identifier: the prefix
// `spiffe://example.org` is also a prefix of `spiffe://example.org.attacker.com`,
// and every implementation that has got this wrong got it wrong that way.
function isMemberOf(value, trustDomain) {
  const parsed = parse(value);
  if (!parsed.ok) return false;
  return parsed.trustDomain ===
         String(trustDomain == null ? '' : trustDomain).trim().toLowerCase();
}

// ---------------------------------------------------------------------------
// THE RESERVED PATHS.
//
// `/spire/…` belongs to the implementation. This service mints two shapes in
// it — the server's own identifier and one per attested agent — so a
// registration entry there would be an identifier issued for two unrelated
// reasons, and whichever of the two a verifier met first would be the one it
// believed. `spiffe_registry.js` refuses one; nothing else needs to.
//
// The match is on the SEGMENT rather than on the string, because `/spirev2/x`
// starts with `/spire` and is not reserved.
// ---------------------------------------------------------------------------
function isReservedPath(value) {
  const parsed = parse(value);
  if (!parsed.ok) return false;
  return parsed.segments.length > 0 && parsed.segments[0] === 'spire';
}

// This service's own identifier as a SPIFFE server. SPIRE uses exactly this
// path and so does everything that talks to it.
function serverId(trustDomain) {
  return make(trustDomain, '/spire/server');
}

// An attested agent's identifier. The shape is SPIRE's —
// `/spire/agent/<attestor name>/<attestor-specific suffix>` — because an agent
// that attested against a real SPIRE server and then against this one should
// get an identifier of the same shape, and because the attestor name is the
// only part of it this service chooses.
function agentId(trustDomain, attestorName, suffix) {
  const attestor = String(attestorName == null ? '' : attestorName).trim() || 'unknown';
  const tail = String(suffix == null ? '' : suffix).trim() || 'unnamed';
  return make(trustDomain, '/spire/agent/' + attestor + '/' + tail);
}

function isAgentId(value) {
  const parsed = parse(value);
  return parsed.ok && parsed.segments.length >= 3 &&
         parsed.segments[0] === 'spire' && parsed.segments[1] === 'agent';
}

function isServerId(value) {
  const parsed = parse(value);
  return parsed.ok && parsed.segments.length === 2 &&
         parsed.segments[0] === 'spire' && parsed.segments[1] === 'server';
}

// ---------------------------------------------------------------------------
// THE PROTOBUF SHAPE.
//
// `spire.api.types.SPIFFEID` is a message with two fields — `trust_domain`
// (the NAME, with no scheme on it) and `path` (with the leading slash) — so
// every SPIRE Server API handler converts in both directions. Doing it here
// rather than in each handler is what stops one of them from putting
// `spiffe://example.org` in the trust_domain field, which produces an
// identifier of `spiffe://spiffe://example.org/x` at the far end.
// ---------------------------------------------------------------------------
function toProto(value) {
  const parsed = parse(value);
  if (!parsed.ok) return null;
  return { trust_domain: parsed.trustDomain, path: parsed.path };
}

function fromProto(message) {
  log.debug('Entering fromProto().');
  if (!message) {
    log.debug('Leaving fromProto().');
    return '';
  }
  const domain = String(message.trust_domain || '').trim();
  if (!domain) {
    log.debug('Leaving fromProto().');
    return '';
  }
  // A caller that put the whole identifier in trust_domain is a real and common
  // mistake, and one this service should NAME rather than silently repair: the
  // result of repairing it is that their code works here and against nothing
  // else. So the scheme is stripped for the purpose of building the identifier
  // — otherwise the result is not parseable at all and the error says nothing
  // useful — but parse() then reports on what was actually built.
  const bare = domain.slice(0, PREFIX.length).toLowerCase() === PREFIX
    ? domain.slice(PREFIX.length).split('/')[0]
    : domain;
  const path = String(message.path || '');
  const parsed = parse(PREFIX + bare + (path && path.charAt(0) !== '/' ? '/' + path : path));
  log.debug('Leaving fromProto().');
  return parsed.ok ? parsed.id : '';
}

module.exports = {
  SCHEME: SCHEME,
  PREFIX: PREFIX,
  MAX_ID_BYTES: MAX_ID_BYTES,
  MAX_TRUST_DOMAIN_BYTES: MAX_TRUST_DOMAIN_BYTES,
  RESERVED_PREFIX: RESERVED_PREFIX,
  parse: parse,
  isValid: isValid,
  make: make,
  trustDomainId: trustDomainId,
  trustDomainOf: trustDomainOf,
  isMemberOf: isMemberOf,
  isReservedPath: isReservedPath,
  serverId: serverId,
  agentId: agentId,
  isAgentId: isAgentId,
  isServerId: isServerId,
  toProto: toProto,
  fromProto: fromProto
};
