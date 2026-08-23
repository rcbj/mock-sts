'use strict';
//
// File: spiffe_api.js
//
// ---------------------------------------------------------------------------
// THE SPIRE SERVER API — the third server-side surface, and the largest: six
// gRPC services and forty-two methods, over the same two transports the
// Workload API uses.
//
//   Entry        registration entries: list, get, batch create/update/delete,
//                and the two an agent uses to learn what it may issue
//   Agent        attesting, renewing, listing, banning, join tokens
//   Bundle       this trust domain's bundle, and every federated one
//   SVID         minting on demand, and signing an agent's CSRs
//   TrustDomain  federation relationships
//   Debug        one method, and it is the cheapest health check there is
//
// A LIBRARY: it registers no HTTP route and starts no listener —
// `spiffe_server.js` mounts these handlers — and everything it requires
// (`helpers.js`, `config.js`, `audit.js`, `admin_stats.js`, `spiffe_id.js`,
// `spiffe_ca.js`, `spiffe_registry.js`, `spiffe_grpc.js`) is below it.
//
// ---------------------------------------------------------------------------
// THIS IS THE ONE SURFACE IN THE SPIFFE FAMILY THAT AUTHENTICATES ITS CALLER
//
// A real SPIRE server authorizes this API against the caller's own SVID: an
// agent may call `GetAuthorizedEntries` and `BatchNewX509SVID` and nothing
// else, an entry marked `admin` may create entries, a `downstream` entry may
// ask for an intermediate CA, and everybody else is refused. **This service now
// does the same**, and none of it is decided in this file: `spiffe_auth.js`
// builds the caller from the mutual-TLS X509-SVID and authorizes each method
// against SPIRE's own `policy_data.json`, and `spiffe_grpc.js`'s wrappers apply
// it before any handler here runs. So there is no authorization check in any of
// the forty-two handlers below, and there must not be one — a check beside the
// funnel is how a method comes to be guarded twice and differently.
//
// Three things follow that are easy to miss:
//
//   * **The `admin` and `downstream` flags on an entry are now READ.** They
//     used to be recorded, reported, and consulted by nothing — this file's
//     header said so. `spiffe_auth.classify()` reads them on every call, so
//     marking an entry `admin` on /admin/spiffe/entries, or with an
//     `ldapmodify`, changes what that identity may do on the NEXT call.
//
//   * **The Unix socket is the `local` entity and needs no credential**, which
//     is how the `spire-server` CLI reaches a real server. Two methods are open
//     to everybody — `AttestAgent`, because an agent has no SVID until that
//     call gives it one, and `GetBundle`, because a trust bundle is public —
//     and both are open in a real SPIRE server too.
//
//   * **`spiffe.authRequired` off restores the old posture completely**: the
//     TCP port binds plain, nothing is verified, and anybody who can reach it
//     can create a registration entry granting any identity in this trust
//     domain and then collect an SVID for it. That is still worth having, and
//     it is still what `GET /spiffe`, `/admin/spiffe` and `spiffe.grpcHost`
//     warn about — for that setting rather than for every deployment.
//
// **WHAT IS STILL NOT ATTESTED IS THE WORKLOAD API AND NODE ATTESTATION.** See
// `spiffe_workload.js`'s header for the first, which is the specification's
// requirement rather than this service's laxity, and `AttestAgent` below for
// the second.
//
// ---------------------------------------------------------------------------
// THE BATCH METHODS ANSWER PER ITEM AND DO NOT FAIL AS A WHOLE
//
// `BatchCreateEntry` takes a list and returns a list of `Result`, each with its
// own `Status`. A batch where one entry is bad returns OK at the RPC level with
// one failed result in it — it does not fail the call. Getting that wrong is
// how a client that submits fifty entries loses forty-nine because the
// thirteenth had a typo, and it is the reason `statusFor()` below exists rather
// than each handler throwing.
//
// The status codes are `google.rpc.Code` values, which happen to be the same
// numbers as the gRPC status codes — 0 OK, 3 INVALID_ARGUMENT, 5 NOT_FOUND, 6
// ALREADY_EXISTS, 8 RESOURCE_EXHAUSTED. `spiffe_grpc.js` re-exports grpc-js's
// table rather than a second copy here.
// ---------------------------------------------------------------------------

const crypto = require('crypto');
const { log, nowSec } = require('../common/helpers');
const config = require('../common/config');
const audit = require('../common/audit');
const stats = require('../common/admin_stats');
const spiffeId = require('./spiffe_id');
const ca = require('./spiffe_ca');
const registry = require('./spiffe_registry');
const rpc = require('./spiffe_grpc');
// For the caller on a call — see the header. This module never authorizes;
// it reads WHO, where a method's answer depends on it.
const auth = require('./spiffe_auth');

const status = rpc.grpc.status;

function trustDomain() { return ca.trustDomain(); }

// ---------------------------------------------------------------------------
// CONVERSIONS.
//
// A registration entry as this service holds it, and as `spire.api.types.Entry`
// describes it. Written once each way so that eight handlers cannot disagree
// about, for instance, whether `expires_at` is seconds or milliseconds — it is
// seconds, and a millisecond value there is an entry that expires in the year
// 56000 and is reported by every tool as valid.
// ---------------------------------------------------------------------------
function entryToProto(entry, mask) {
  if (!entry) return null;
  const full = {
    id: entry.id,
    spiffe_id: spiffeId.toProto(entry.spiffeId),
    parent_id: spiffeId.toProto(entry.parentId),
    selectors: (entry.selectors || []).map(function (s) {
      return { type: s.type, value: s.value };
    }),
    x509_svid_ttl: entry.x509SvidTtl || 0,
    jwt_svid_ttl: entry.jwtSvidTtl || 0,
    federates_with: (entry.federatesWith || []).slice(0),
    admin: !!entry.admin,
    downstream: !!entry.downstream,
    expires_at: String(entry.expiresAt || 0),
    dns_names: (entry.dnsNames || []).slice(0),
    revision_number: String(entry.revisionNumber || 0),
    store_svid: !!entry.storeSvid,
    hint: entry.hint || '',
    created_at: String(secondsFromGeneralizedTime(entry.createdAt))
  };
  return applyEntryMask(full, mask);
}

// An `EntryMask` names which fields the caller wants back. It is honoured
// rather than ignored, and the reason is not politeness: a client that asked
// for `id` alone and got a full entry cannot tell whether the server honoured
// the mask, so the first time it meets a server that DOES honour one, the
// fields it had been reading silently become empty.
//
// `id` is never masked out — it is the handle to everything else, and an entry
// without one is a result a caller cannot act on.
function applyEntryMask(full, mask) {
  if (!mask || !Object.keys(mask).length) return full;
  const anySet = Object.keys(mask).some(function (key) { return mask[key]; });
  if (!anySet) return full;
  const out = { id: full.id };
  Object.keys(mask).forEach(function (key) {
    if (mask[key] && Object.prototype.hasOwnProperty.call(full, key)) {
      out[key] = full[key];
    }
  });
  return out;
}

// The reverse. `parentId` defaults to this server's own SPIFFE ID, which is
// what SPIRE does for an entry describing a workload rather than a node, and is
// what makes `spire-server entry create -spiffeID x -selector y` work with no
// parent given.
function entryFromProto(message) {
  const proto = message || {};
  return {
    id: String(proto.id || '').trim(),
    spiffeId: spiffeId.fromProto(proto.spiffe_id),
    parentId: spiffeId.fromProto(proto.parent_id) || spiffeId.serverId(trustDomain()),
    selectors: (proto.selectors || []).map(function (s) {
      return { type: String(s.type || ''), value: String(s.value || '') };
    }),
    x509SvidTtl: Number(proto.x509_svid_ttl || 0),
    jwtSvidTtl: Number(proto.jwt_svid_ttl || 0),
    federatesWith: (proto.federates_with || []).map(String),
    admin: !!proto.admin,
    downstream: !!proto.downstream,
    expiresAt: Number(proto.expires_at || 0),
    dnsNames: (proto.dns_names || []).map(String),
    storeSvid: !!proto.store_svid,
    hint: String(proto.hint || '')
  };
}

function agentToProto(agent, mask) {
  if (!agent) return null;
  const full = {
    id: spiffeId.toProto(agent.id),
    attestation_type: agent.attestationType || '',
    x509svid_serial_number: agent.svidHash || '',
    x509svid_expires_at: String(agent.expiresAt || 0),
    selectors: (agent.selectors || []).map(function (s) {
      return { type: s.type, value: s.value };
    }),
    banned: !!agent.banned,
    can_reattest: !!agent.canReattest,
    agent_version: ''
  };
  if (!mask || !Object.keys(mask).length) return full;
  const anySet = Object.keys(mask).some(function (key) { return mask[key]; });
  if (!anySet) return full;
  const out = { id: full.id };
  Object.keys(mask).forEach(function (key) {
    if (mask[key] && Object.prototype.hasOwnProperty.call(full, key)) {
      out[key] = full[key];
    }
  });
  return out;
}

// A GeneralizedTime — which is what the directory stores — as seconds since the
// epoch, which is what the protobuf carries. Returns 0 rather than NaN on
// anything unparseable: a `created_at` of NaN serialises as an error naming the
// field, and 0 at least reads as "unknown".
function secondsFromGeneralizedTime(text) {
  const value = String(text || '');
  const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(value);
  if (!m) {
    const parsed = Date.parse(value);
    return Number.isFinite(parsed) ? Math.floor(parsed / 1000) : 0;
  }
  return Math.floor(Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]) / 1000);
}

function statusFor(code, message) {
  return { code: code, message: message || (code === status.OK ? 'OK' : '') };
}

function okStatus() { return statusFor(status.OK, 'OK'); }

// ---------------------------------------------------------------------------
// PAGING.
//
// Every `List*` method takes `page_size` and `page_token` and returns
// `next_page_token`. It is implemented rather than ignored for the reason the
// mask is: a client that pages will loop forever against a server that returns
// everything and an empty token — no, worse, it will loop forever against one
// that returns everything and a NON-empty token, which is the shape somebody
// reaches for when they add paging by copying the field names.
//
// The token is the INDEX of the next row, as a string. Opaque to a caller,
// which is what the specification requires, and stable enough for a store this
// size — the alternative, a cursor keyed on the last id, matters when rows are
// being inserted underneath a paging client, and a mock's registry is not.
// ---------------------------------------------------------------------------
function page(rows, pageSize, pageToken) {
  const size = Number(pageSize) > 0 ? Math.min(Number(pageSize), 1000) : rows.length;
  const start = Math.max(0, parseInt(String(pageToken || '0'), 10) || 0);
  const slice = rows.slice(start, start + size);
  const next = (start + size) < rows.length ? String(start + size) : '';
  return { rows: slice, nextPageToken: next };
}

// ---------------------------------------------------------------------------
// FILTERS.
//
// `ListEntries` and `ListAgents` both take one, and both are honoured. The
// selector match behaviours are the interesting part and there are four of
// them, each meaning something different:
//
//   MATCH_EXACT     the two sets are equal
//   MATCH_SUBSET    the entry's selectors are a subset of those given
//   MATCH_SUPERSET  the entry's selectors are a superset of those given
//   MATCH_ANY       at least one in common
//
// Implementing only MATCH_EXACT and treating the rest as it is the mistake that
// makes `spire-server entry show -selector unix:uid:1000` return nothing on a
// deployment where it should return everything.
// ---------------------------------------------------------------------------
function selectorSet(list) {
  const set = {};
  (list || []).forEach(function (s) {
    const text = registry.selectorText(s);
    if (text) set[text] = true;
  });
  return set;
}

function selectorMatches(entrySelectors, match) {
  if (!match) return true;
  const wanted = selectorSet(match.selectors);
  const have = selectorSet(entrySelectors);
  const wantedKeys = Object.keys(wanted);
  const haveKeys = Object.keys(have);
  if (!wantedKeys.length) return true;
  const behavior = String(match.match || 'MATCH_EXACT');
  if (behavior === 'MATCH_EXACT') {
    return wantedKeys.length === haveKeys.length &&
           wantedKeys.every(function (k) { return have[k]; });
  }
  if (behavior === 'MATCH_SUBSET') {
    return haveKeys.every(function (k) { return wanted[k]; });
  }
  if (behavior === 'MATCH_SUPERSET') {
    return wantedKeys.every(function (k) { return have[k]; });
  }
  if (behavior === 'MATCH_ANY') {
    return wantedKeys.some(function (k) { return have[k]; });
  }
  return true;
}

function federatesWithMatches(entryFederates, match) {
  if (!match) return true;
  const wanted = (match.trust_domains || []).map(function (t) {
    return String(t).trim().toLowerCase();
  }).filter(Boolean);
  if (!wanted.length) return true;
  const have = {};
  (entryFederates || []).forEach(function (t) { have[String(t).toLowerCase()] = true; });
  const haveKeys = Object.keys(have);
  const behavior = String(match.match || 'MATCH_EXACT');
  if (behavior === 'MATCH_EXACT') {
    return wanted.length === haveKeys.length &&
           wanted.every(function (t) { return have[t]; });
  }
  if (behavior === 'MATCH_SUBSET') {
    return haveKeys.every(function (t) { return wanted.indexOf(t) >= 0; });
  }
  if (behavior === 'MATCH_SUPERSET') {
    return wanted.every(function (t) { return have[t]; });
  }
  if (behavior === 'MATCH_ANY') {
    return wanted.some(function (t) { return have[t]; });
  }
  return true;
}

// A `google.protobuf.StringValue` / `BoolValue` wrapper. The whole point of a
// wrapper type is that "absent" and "empty" are different — `by_hint` unset
// means "do not filter on hint" and `by_hint: {value: ""}` means "entries whose
// hint is empty" — so reading `.value` without checking presence turns the
// first into the second and silently filters everything out.
function wrapped(value) {
  if (value === null || value === undefined) return undefined;
  if (typeof value === 'object' && Object.prototype.hasOwnProperty.call(value, 'value')) {
    return value.value;
  }
  return value;
}

function filterEntries(rows, filter) {
  if (!filter) return rows;
  const bySpiffe = spiffeId.fromProto(filter.by_spiffe_id);
  const byParent = spiffeId.fromProto(filter.by_parent_id);
  const byHint = wrapped(filter.by_hint);
  const byDownstream = wrapped(filter.by_downstream);
  return rows.filter(function (entry) {
    if (bySpiffe && entry.spiffeId !== bySpiffe) return false;
    if (byParent && entry.parentId !== byParent) return false;
    if (byHint !== undefined && String(entry.hint || '') !== String(byHint)) return false;
    if (byDownstream !== undefined && !!entry.downstream !== !!byDownstream) return false;
    if (!selectorMatches(entry.selectors, filter.by_selectors)) return false;
    if (!federatesWithMatches(entry.federatesWith, filter.by_federates_with)) return false;
    return true;
  });
}

function filterAgents(rows, filter) {
  if (!filter) return rows;
  const byType = String(filter.by_attestation_type || '');
  const byBanned = wrapped(filter.by_banned);
  const byReattest = wrapped(filter.by_can_reattest);
  const before = String(filter.by_expires_before || '');
  const beforeSeconds = before ? Math.floor(Date.parse(before) / 1000) : 0;
  return rows.filter(function (agent) {
    if (byType && agent.attestationType !== byType) return false;
    if (byBanned !== undefined && !!agent.banned !== !!byBanned) return false;
    if (byReattest !== undefined && !!agent.canReattest !== !!byReattest) return false;
    if (beforeSeconds && !(agent.expiresAt && agent.expiresAt < beforeSeconds)) return false;
    if (!selectorMatches(agent.selectors, filter.by_selector_match)) return false;
    return true;
  });
}

// ===========================================================================
// THE ENTRY SERVICE.
// ===========================================================================
const entryHandlers = {
  CountEntries: rpc.unary('server', 'Entry.CountEntries', async function (call) {
    const rows = filterEntries(registry.allEntries(), (call.request || {}).filter);
    return { count: rows.length };
  }),

  ListEntries: rpc.unary('server', 'Entry.ListEntries', async function (call) {
    const request = call.request || {};
    const rows = filterEntries(registry.allEntries(), request.filter);
    const paged = page(rows, request.page_size, request.page_token);
    return {
      entries: paged.rows.map(function (entry) {
        return entryToProto(entry, request.output_mask);
      }),
      next_page_token: paged.nextPageToken
    };
  }),

  GetEntry: rpc.unary('server', 'Entry.GetEntry', async function (call) {
    const request = call.request || {};
    const entry = registry.entryById(request.id);
    if (!entry) {
      throw rpc.notFound('No registration entry has the id ' +
                         String(request.id || '(none given)') + '.');
    }
    return entryToProto(entry, request.output_mask);
  }),

  BatchCreateEntry: rpc.unary('server', 'Entry.BatchCreateEntry', async function (call) {
    const request = call.request || {};
    const results = (request.entries || []).map(function (message) {
      const record = entryFromProto(message);
      const created = registry.createEntry(record, 'grpc', trustDomain(), '');
      if (!created.ok) {
        // Per item, never the whole call. See the header: a batch of fifty
        // that fails because the thirteenth had a typo is how a client loses
        // forty-nine entries it correctly submitted.
        return { status: statusFor(status.INVALID_ARGUMENT,
                                   created.errors.join(' ')), entry: null };
      }
      return { status: okStatus(),
               entry: entryToProto(created.entry, request.output_mask) };
    });
    return { results: results };
  }),

  BatchUpdateEntry: rpc.unary('server', 'Entry.BatchUpdateEntry', async function (call) {
    const request = call.request || {};
    const results = (request.entries || []).map(function (message) {
      const id = String(message.id || '').trim();
      if (!id) {
        return { status: statusFor(status.INVALID_ARGUMENT,
                                   'An update names the entry by its id, and ' +
                                   'this one has none.'), entry: null };
      }
      // The INPUT mask says which fields of the submitted entry to apply. It is
      // honoured, and it matters more than the output mask does: a client that
      // sends an entry with only `hint` set and an input mask naming only
      // `hint` expects the selectors to be left alone. Ignoring the mask and
      // applying the whole message wipes every field the client did not fill
      // in, which reads as the server losing data.
      const submitted = entryFromProto(message);
      const changes = maskedChanges(submitted, request.input_mask);
      const updated = registry.updateEntry(id, changes, trustDomain(), '');
      if (!updated.ok) {
        return { status: statusFor(
          /No registration entry has the id/.test(updated.errors[0] || '')
            ? status.NOT_FOUND : status.INVALID_ARGUMENT,
          updated.errors.join(' ')), entry: null };
      }
      return { status: okStatus(),
               entry: entryToProto(updated.entry, request.output_mask) };
    });
    return { results: results };
  }),

  BatchDeleteEntry: rpc.unary('server', 'Entry.BatchDeleteEntry', async function (call) {
    const request = call.request || {};
    const results = (request.ids || []).map(function (id) {
      const deleted = registry.deleteEntry(String(id), '');
      return { status: deleted.ok ? okStatus()
                 : statusFor(status.NOT_FOUND, deleted.errors.join(' ')),
               id: String(id) };
    });
    return { results: results };
  }),

  // What an AGENT calls to learn what it may issue. In a real server this is
  // authorized against the caller's own agent SVID and returns only the entries
  // beneath it. Here it returns every entry, because nothing identifies the
  // caller — the same answer the Workload API gives, for the same reason, and
  // it is the honest one rather than a guess at who is asking.
  GetAuthorizedEntries: rpc.unary('server', 'Entry.GetAuthorizedEntries', async function (call) {
    const request = call.request || {};
    return {
      entries: registry.allEntries().map(function (entry) {
        return entryToProto(entry, request.output_mask);
      })
    };
  }),

  // The streaming form of the same question, which an agent uses to keep its
  // cache current: it sends the ids it holds, and the server answers with the
  // revision of each plus the full entries for anything it does not have.
  //
  // Answered in ONE message with `more: false`. That is a conforming answer —
  // the field exists so a large result can be split — and it is the right one
  // for a registry this size. A client that handles `more: true` is untested by
  // this; a client that does not handle it works.
  SyncAuthorizedEntries: rpc.bidiStream('server', 'Entry.SyncAuthorizedEntries',
    async function (request) {
      const held = {};
      (request.ids || []).forEach(function (id) { held[String(id)] = true; });
      const rows = registry.allEntries();
      return {
        entry_revisions: rows.map(function (entry) {
          return { id: entry.id,
                   revision_number: String(entry.revisionNumber || 0),
                   created_at: String(secondsFromGeneralizedTime(entry.createdAt)) };
        }),
        entries: rows.filter(function (entry) { return !held[entry.id]; })
          .map(function (entry) {
            return entryToProto(entry, request.output_mask);
          }),
        more: false
      };
    })
};

// Which fields of a submitted entry to apply. No mask, or an empty one, means
// all of them — which is what the specification says and is what
// `spire-server entry update` relies on.
function maskedChanges(submitted, mask) {
  if (!mask) return submitted;
  const anySet = Object.keys(mask).some(function (key) { return mask[key]; });
  if (!anySet) return submitted;
  const FIELD_OF = {
    spiffe_id: 'spiffeId', parent_id: 'parentId', selectors: 'selectors',
    x509_svid_ttl: 'x509SvidTtl', jwt_svid_ttl: 'jwtSvidTtl',
    federates_with: 'federatesWith', admin: 'admin', downstream: 'downstream',
    expires_at: 'expiresAt', dns_names: 'dnsNames', store_svid: 'storeSvid',
    hint: 'hint'
  };
  const changes = {};
  Object.keys(mask).forEach(function (key) {
    if (mask[key] && FIELD_OF[key]) changes[FIELD_OF[key]] = submitted[FIELD_OF[key]];
  });
  return changes;
}

// ===========================================================================
// THE AGENT SERVICE.
// ===========================================================================

// The join tokens this service has minted. In memory, like everything else, and
// SINGLE-USE — a token redeemed once is gone, which is the one property a join
// token has that makes it different from a password. Not enforcing that would
// make `CreateJoinToken` a way of issuing a permanent credential, which is
// exactly what it exists not to be.
const joinTokens = new Map();

const agentHandlers = {
  CountAgents: rpc.unary('server', 'Agent.CountAgents', async function (call) {
    const rows = filterAgents(registry.allAgents(), (call.request || {}).filter);
    return { count: rows.length };
  }),

  ListAgents: rpc.unary('server', 'Agent.ListAgents', async function (call) {
    const request = call.request || {};
    const rows = filterAgents(registry.allAgents(), request.filter);
    const paged = page(rows, request.page_size, request.page_token);
    return {
      agents: paged.rows.map(function (agent) {
        return agentToProto(agent, request.output_mask);
      }),
      next_page_token: paged.nextPageToken
    };
  }),

  GetAgent: rpc.unary('server', 'Agent.GetAgent', async function (call) {
    const request = call.request || {};
    const id = spiffeId.fromProto(request.id);
    const agent = id ? registry.agentById(id) : null;
    if (!agent) {
      throw rpc.notFound('No agent has attested here as ' +
                         (id || '(no id given)') + '.');
    }
    return agentToProto(agent, request.output_mask);
  }),

  DeleteAgent: rpc.unary('server', 'Agent.DeleteAgent', async function (call) {
    const id = spiffeId.fromProto((call.request || {}).id);
    const deleted = registry.deleteAgent(id, '');
    if (!deleted.ok) throw rpc.notFound(deleted.errors.join(' '));
    return {};
  }),

  BanAgent: rpc.unary('server', 'Agent.BanAgent', async function (call) {
    const id = spiffeId.fromProto((call.request || {}).id);
    const banned = registry.setAgentBanned(id, true, '');
    if (!banned.ok) throw rpc.notFound(banned.errors.join(' '));
    return {};
  }),

  // ATTESTATION. The one place this service could have pretended hardest and
  // does not.
  //
  // A real server runs the named node attestor against the payload — verifies a
  // Kubernetes projected service account token, an AWS instance identity
  // document, a join token it minted — and derives the agent's SPIFFE ID and
  // selectors from what it proves. Some attestors then issue a CHALLENGE and
  // expect a signed response, which is why this is a bidirectional stream.
  //
  // Here: the payload is not verified, no challenge is ever issued, and the
  // agent id is derived from what the caller sent. What IS real is the CSR —
  // only the public key is read out of it, so an agent still cannot name itself
  // something it is not — the join token's single use, and the ban.
  AttestAgent: rpc.bidiStream('server', 'Agent.AttestAgent', async function (request, call) {
    await ca.ready();
    // A challenge response arriving when no challenge was issued. Refused
    // rather than ignored: a client in that state has misread the protocol, and
    // an empty answer would leave it waiting.
    if (request.challenge_response !== undefined && !request.params) {
      throw rpc.invalidArgument('This server issues no attestation challenge, ' +
                                'so there is nothing a challenge_response can ' +
                                'answer. Send the params step and the SVID ' +
                                'comes back immediately.');
    }
    const params = request.params || {};
    const data = params.data || {};
    const attestationType = String(data.type || '').trim() || 'unknown';
    const agentId = agentIdFor(attestationType, data.payload);
    const existing = registry.agentById(agentId);
    if (existing && existing.banned) {
      // One of the few refusals in this service, and it earns its place: a ban
      // that did not refuse would make the button on /admin/spiffe/agents a
      // lie. PERMISSION_DENIED with the reason SPIRE uses.
      throw rpc.permissionDenied('The agent ' + agentId + ' is banned on this ' +
                                 'server. Unban it from /admin/spiffe/agents ' +
                                 'or with the management API.');
    }
    const csr = (params.params || {}).csr;
    if (!csr || !csr.length) {
      throw rpc.invalidArgument('AttestAgent needs a certificate signing ' +
                                'request in params.params.csr: the agent keeps ' +
                                'its own private key, so there is nothing to ' +
                                'issue against without one.');
    }
    // ---------------------------------------------------------------------
    // A JOIN TOKEN IS A CREDENTIAL, SO IT IS CHECKED.
    //
    // It is the one attestation payload here that this service ISSUED and can
    // therefore verify: `CreateJoinToken` minted it, it has a lifetime, and it
    // is single-use. A server that accepted a join token it never issued would
    // be accepting a forgery of its own credential, which is a different thing
    // from being permissive about a payload somebody else's attestor would
    // have verified.
    //
    // Gated on `spiffe.authRequired` like everything else this file gained, so
    // the old behaviour — any token attests — stays reachable. The refusals
    // are three and they are deliberately distinguishable: a token nobody
    // minted, a token that ran out, and a token already spent are three
    // different bugs in a client and reading one message for all three would
    // send somebody looking in the wrong place.
    // ---------------------------------------------------------------------
    if (attestationType === 'join_token' && auth.authRequired()) {
      const presented = String(Buffer.from(data.payload || []).toString('utf8')).trim();
      const held = joinTokens.get(presented);
      if (!presented) {
        throw rpc.invalidArgument('A join_token attestation carries the token ' +
                                  'as params.data.payload, and this one is ' +
                                  'empty.');
      }
      if (!held) {
        throw rpc.permissionDenied('That join token was not issued by this ' +
                                   'server, or it has already been spent — a ' +
                                   'join token is single-use, and the one it ' +
                                   'attested is on /admin/spiffe/agents. Ask ' +
                                   'for a new one with CreateJoinToken. Note ' +
                                   'that tokens do not survive a restart: ' +
                                   'nothing here is persisted.');
      }
      if (held.expiresAt && held.expiresAt < nowSec()) {
        joinTokens.delete(presented);
        throw rpc.permissionDenied('That join token expired at ' +
          new Date(held.expiresAt * 1000).toISOString() + '. It has been ' +
          'discarded; ask for another with CreateJoinToken, which takes a ' +
          'ttl.');
      }
      if (held.agentId && held.agentId !== agentId) {
        // A token minted FOR a named agent, presented by another. SPIRE binds
        // the two; without this the `agent_id` argument to CreateJoinToken
        // would be a note rather than a constraint.
        throw rpc.permissionDenied('That join token was issued for ' +
          held.agentId + ' and this attestation would produce ' + agentId +
          '. A join token created for a named agent may only attest that ' +
          'agent.');
      }
    }
    const svid = await ca.signCsr(Buffer.from(csr), agentId, { ttl: 0 });
    const recorded = registry.recordAttestation(agentId, {
      attestationType: attestationType,
      selectors: selectorsFromAttestation(attestationType, data.payload),
      canReattest: attestationType !== 'join_token',
      svidHash: crypto.createHash('sha256').update(svid.certificateDer)
        .digest('hex').slice(0, 32),
      expiresAt: svid.expiresAt
    });
    if (recorded && recorded.banned) {
      throw rpc.permissionDenied('The agent ' + agentId + ' is banned.');
    }
    // A join token is spent HERE, at the successful attestation, and not when
    // it is looked up — the same reasoning that puts oauth2_bcp.js's
    // transaction check at the point the values are spent rather than at the
    // top of the endpoint.
    if (attestationType === 'join_token') {
      const token = String(Buffer.from(data.payload || []).toString('utf8')).trim();
      if (joinTokens.has(token)) {
        joinTokens.delete(token);
        log.info('spiffe: the join token ending ' + token.slice(-6) +
                 ' has been spent and cannot be used again.');
      }
    }
    stats.recordSvid('X.509', {
      subject: agentId, entryId: '', serial: svid.serialHex,
      expiresAt: svid.expiresAt
    });
    // ---------------------------------------------------------------------
    // THE ATTESTED AGENT IS AN IDENTITY, AND IT REACHES THE FUNNEL HERE.
    //
    // Here rather than at the top of the handler, because a row must mean "a
    // credential was ACCEPTED" — the same rule `recordAuthentication()` itself
    // follows by returning early on an identity it could not read, and the
    // same reason `/oid4vp/response` records the holder BELOW its refusals. An
    // agent that was banned, or whose join token was refused, threw several
    // lines above and records nothing.
    //
    // **WHAT WAS ACCEPTED IS NAMED, AND FOR A NODE ATTESTOR IT SAYS
    // `unverified`.** A join token this server minted and spent is a real
    // credential; a `k8s_psat` payload is a document nothing here verified, and
    // its agent entry carries `unverified:true` for exactly that reason. Both
    // create the identity — an agent that attested is an agent that is here —
    // but a page that reported them identically would be claiming a check that
    // did not happen.
    // ---------------------------------------------------------------------
    auth.recordIdentity({
      presented: agentId,
      protocol: 'SPIFFE',
      method: attestationType === 'join_token'
        ? 'agent attestation (join token)'
        : 'agent attestation (' + attestationType + ', unverified)',
      note: attestationType === 'join_token'
        ? 'attested with a join token this server minted and has now spent'
        : 'attested with a ' + attestationType + ' payload; NOTHING VERIFIED ' +
          'IT, which is why the agent\'s selectors carry unverified:true'
    });
    return {
      result: {
        svid: {
          cert_chain: [svid.certificateDer],
          id: spiffeId.toProto(agentId),
          expires_at: String(svid.expiresAt),
          hint: ''
        },
        reattestable: attestationType !== 'join_token'
      }
    };
  }),

  // ---------------------------------------------------------------------
  // RenewAgent — THE ONE METHOD AUTHENTICATION TURNED FROM A REFUSAL INTO AN
  // ANSWER, and the refusal it replaced is worth keeping in view.
  //
  // It used to be `Unimplemented`, and the message said why in terms: "a real
  // SPIRE server knows which agent is calling from the SVID on the mTLS
  // connection and renews THAT agent. Nothing here authenticates the caller,
  // so answering would mean either guessing which agent to renew or renewing
  // whichever one the caller named — and the second is a way for any caller to
  // obtain any agent's identity."
  //
  // Something here authenticates the caller now. The agent being renewed is
  // the one on the connection — `caller.spiffeId`, off the mutual-TLS SVID,
  // which `spiffe_auth.js` verified against this trust domain's bundle and
  // classified as an attested, unbanned agent — and it is NEVER read from the
  // request. The policy table already refuses this method to anybody who is
  // not an agent, so by the time this runs the caller is one; the check below
  // is for the OTHER mode, where `spiffe.authRequired` is off and the old
  // objection stands word for word.
  // ---------------------------------------------------------------------
  RenewAgent: rpc.unary('server', 'Agent.RenewAgent', async function (call) {
    await ca.ready();
    const csr = ((call.request || {}).params || {}).csr;
    if (!csr || !csr.length) {
      throw rpc.invalidArgument('RenewAgent needs a certificate signing ' +
                                'request in params.csr.');
    }
    const caller = call.spiffeCaller || {};
    if (!caller.authenticated || !caller.entities.agent) {
      throw rpc.statusError(status.UNIMPLEMENTED,
        'RenewAgent renews the agent on the CONNECTION, and this connection ' +
        'has no agent on it: ' + auth.describeCaller(caller) + '. With ' +
        'spiffe.authRequired off there is nothing to identify a caller by, so ' +
        'answering would mean renewing whichever agent the caller named — a ' +
        'way for anybody to obtain any agent\'s identity. Turn the setting ' +
        'on and present the agent\'s X509-SVID, or call AttestAgent again, ' +
        'which is not refused, re-issues, and records the attestation.');
    }
    const agent = registry.agentById(caller.spiffeId);
    if (!agent) {
      // Classified as an agent a moment ago and gone now: somebody deleted it
      // from /admin/spiffe/agents between the handshake and this call. NOT
      // FOUND rather than an invented re-attestation — a renewal is for an
      // agent that exists, and re-attesting one somebody has just removed
      // would undo the delete from the other end.
      throw rpc.notFound('The agent ' + caller.spiffeId + ' is no longer ' +
                         'recorded on this server — it was deleted between ' +
                         'this connection being made and this call. Call ' +
                         'AttestAgent to come back.');
    }
    if (agent.banned) {
      throw rpc.permissionDenied('The agent ' + caller.spiffeId + ' is banned ' +
                                 'on this server. Unban it from ' +
                                 '/admin/spiffe/agents or with the ' +
                                 'management API.');
    }
    const svid = await ca.signCsr(Buffer.from(csr), caller.spiffeId, { ttl: 0 });
    // The renewal is recorded as an attestation of the SAME kind the agent
    // already had. It is not a new attestation — nothing was attested here,
    // the agent proved possession of an SVID this server issued — so the
    // attestation type is carried over rather than invented, and the selectors
    // are left exactly as they were.
    registry.recordAttestation(caller.spiffeId, {
      attestationType: agent.attestationType,
      selectors: agent.selectors,
      canReattest: agent.canReattest,
      svidHash: crypto.createHash('sha256').update(svid.certificateDer)
        .digest('hex').slice(0, 32),
      expiresAt: svid.expiresAt
    });
    stats.recordSvid('X.509', {
      subject: caller.spiffeId, entryId: '', serial: svid.serialHex,
      expiresAt: svid.expiresAt
    });
    audit.audit({
      action: 'spiffe.agent.attest', actor: caller.spiffeId,
      protocol: 'SPIRE Server API', channel: 'grpc', target: caller.spiffeId,
      summary: 'An agent renewed its own SVID',
      detail: { serial: svid.serialHex, expiresAt: svid.expiresAt }
    });
    return {
      svid: {
        cert_chain: [svid.certificateDer],
        id: spiffeId.toProto(caller.spiffeId),
        expires_at: String(svid.expiresAt),
        hint: ''
      }
    };
  }),

  // A join token. Single-use (see `joinTokens`), and with a real TTL, because
  // both properties are what a join token IS — and because a client author
  // testing "my token expired" has nothing to test against otherwise.
  CreateJoinToken: rpc.unary('server', 'Agent.CreateJoinToken', async function (call) {
    const request = call.request || {};
    const ttl = Number(request.ttl) > 0 ? Number(request.ttl) : 600;
    const token = String(request.token || '').trim() ||
                  crypto.randomUUID();
    const expiresAt = nowSec() + ttl;
    const agentId = spiffeId.fromProto(request.agent_id);
    joinTokens.set(token, { token: token, expiresAt: expiresAt,
                            agentId: agentId || '' });
    // Bounded, like everything else held in memory here.
    if (joinTokens.size > 256) {
      const oldest = joinTokens.keys().next().value;
      joinTokens.delete(oldest);
    }
    audit.audit({
      action: 'spiffe.agent.create', actor: '', protocol: 'SPIRE Server API',
      channel: 'grpc', target: agentId || '',
      summary: 'A join token was created',
      // THE TOKEN ITSELF IS NEVER RECORDED — it is a credential, and
      // audit.js's rule holds here exactly as it does everywhere else.
      detail: { ttl: ttl, agentId: agentId || '' }
    });
    return { value: token, expires_at: String(expiresAt) };
  }),

  // An agent reporting its version and which bundle it holds. Recorded at debug
  // and otherwise ignored, which is all a real server does with it too.
  PostStatus: rpc.unary('server', 'Agent.PostStatus', async function (call) {
    const request = call.request || {};
    log.debug('spiffe: an agent posted its status. version=' +
              String(request.agent_version || '(unstated)') +
              ', bundle serial=' + String(request.current_bundle_serial || 0) +
              '; this server\'s bundle sequence is ' + ca.sequence() + '.');
    return {};
  })
};

// An agent's SPIFFE ID. SPIRE derives it from what the attestor PROVED; nothing
// is proved here, so it is derived from what was sent — a digest of the
// attestation payload, so that the same agent attesting twice is one entry
// rather than two, which is the property that makes the agents page readable.
function agentIdFor(attestationType, payload) {
  const material = Buffer.isBuffer(payload) ? payload
    : Buffer.from(String(payload || ''), 'utf8');
  const suffix = crypto.createHash('sha256')
    .update(attestationType + '|').update(material)
    .digest('hex').slice(0, 32);
  return spiffeId.agentId(trustDomain(), attestationType, suffix);
}

// The selectors an attestation "produced". A real attestor derives these from
// what it verified. These are derived from what was claimed and are marked as
// such — the `unverified` type is this service's own, and it is there so that
// nobody reading an agent's selectors mistakes them for attested facts.
function selectorsFromAttestation(attestationType, payload) {
  const out = [{ type: attestationType, value: 'unverified:true' }];
  const text = Buffer.isBuffer(payload) ? payload.toString('utf8')
    : String(payload || '');
  if (text && text.length <= 256 && /^[\x20-\x7e]*$/.test(text)) {
    // A short printable payload is usually a join token or a name, and having
    // it on the entry is what makes the agents page useful. Anything longer or
    // binary is a document (a signed JWT, an instance identity document) and
    // goes nowhere near a selector value.
    out.push({ type: attestationType, value: 'payload:' + text });
  }
  return out;
}

// ===========================================================================
// THE BUNDLE SERVICE.
// ===========================================================================
async function ownBundleProto(mask) {
  const state = ca.state();
  const document = await ca.bundle();
  const full = {
    trust_domain: ca.trustDomain(),
    x509_authorities: state.x509Authorities.map(function (authority) {
      return {
        asn1: Buffer.from(authority.certificatePem
          .replace(/-----[^-]+-----/g, '').replace(/\s+/g, ''), 'base64'),
        // `tainted` marks an authority being rotated out after a compromise.
        // Always false here: this service has no way to be told one was
        // compromised, and reporting a fact it cannot know would be worse than
        // reporting the absence of one.
        tainted: false
      };
    }),
    jwt_authorities: state.jwtAuthorities.map(function (authority) {
      return {
        public_key: derFromJwk(authority.jwk),
        key_id: authority.id,
        expires_at: '0',
        tainted: false
      };
    }),
    refresh_hint: String(document.spiffe_refresh_hint || 0),
    sequence_number: String(document.spiffe_sequence || 0),
    wit_authorities: []
  };
  if (!mask || !Object.keys(mask).some(function (k) { return mask[k]; })) return full;
  const out = { trust_domain: full.trust_domain };
  Object.keys(mask).forEach(function (key) {
    if (mask[key] && Object.prototype.hasOwnProperty.call(full, key)) {
      out[key] = full[key];
    }
  });
  return out;
}

// `JWTKey.public_key` is a DER-encoded SubjectPublicKeyInfo, NOT a JWK and not
// PEM. The bundle document publishes JWKs and this message publishes DER, so
// the conversion has to happen somewhere — here, once, rather than in each of
// the three methods that build a Bundle.
function derFromJwk(jwk) {
  try {
    return crypto.createPublicKey({ key: jwk, format: 'jwk' })
      .export({ type: 'spki', format: 'der' });
  } catch (e) {
    // A key this node cannot import. Empty rather than fatal: the rest of the
    // bundle is still usable, and a caller sees a key with no material rather
    // than no bundle at all.
    log.error('spiffe: a JWT authority could not be exported as DER and is ' +
              'being sent empty: ' + e.message);
    return Buffer.alloc(0);
  }
}

function federatedBundleProto(entry, mask) {
  const document = entry.document || {};
  const x509 = [];
  const jwt = [];
  (document.keys || []).forEach(function (key) {
    if (key.use === 'x509-svid') {
      (key.x5c || []).forEach(function (b64) {
        x509.push({ asn1: Buffer.from(String(b64), 'base64'), tainted: false });
      });
    } else if (key.use === 'jwt-svid') {
      jwt.push({ public_key: derFromJwk(key), key_id: key.kid || '',
                 expires_at: '0', tainted: false });
    }
  });
  const full = {
    trust_domain: entry.trustDomain,
    x509_authorities: x509,
    jwt_authorities: jwt,
    refresh_hint: String(document.spiffe_refresh_hint || 0),
    sequence_number: String(document.spiffe_sequence || 0),
    wit_authorities: []
  };
  if (!mask || !Object.keys(mask).some(function (k) { return mask[k]; })) return full;
  const out = { trust_domain: full.trust_domain };
  Object.keys(mask).forEach(function (key) {
    if (mask[key] && Object.prototype.hasOwnProperty.call(full, key)) {
      out[key] = full[key];
    }
  });
  return out;
}

// A `spire.api.types.Bundle` back into the JWK Set document this service holds.
// The reverse of the two functions above, and it is where a federated bundle
// submitted over gRPC becomes one `/spiffe/bundle` and the Workload API can
// serve.
function bundleDocumentFromProto(message) {
  const proto = message || {};
  const keys = [];
  (proto.x509_authorities || []).forEach(function (authority) {
    const der = Buffer.from(authority.asn1 || []);
    if (!der.length) return;
    let jwk = {};
    try {
      const cert = new crypto.X509Certificate(der);
      jwk = cert.publicKey.export({ format: 'jwk' });
      delete jwk.key_ops;
      delete jwk.ext;
    } catch (e) {
      // Not a certificate this node can parse. The x5c is still carried —
      // it is what an X.509 authority IS — with a minimal kty so the JWK is
      // well-formed. A consumer that can parse it will; one that cannot is no
      // worse off than if this were dropped.
      log.warn('spiffe: an x509 authority in a submitted bundle could not be ' +
               'parsed, and is being carried as x5c alone: ' + e.message);
      jwk = { kty: 'RSA' };
    }
    jwk.use = 'x509-svid';
    jwk.x5c = [der.toString('base64')];
    keys.push(jwk);
  });
  (proto.jwt_authorities || []).forEach(function (authority) {
    const der = Buffer.from(authority.public_key || []);
    if (!der.length) return;
    try {
      const jwk = crypto.createPublicKey({ key: der, format: 'der', type: 'spki' })
        .export({ format: 'jwk' });
      delete jwk.key_ops;
      delete jwk.ext;
      jwk.use = 'jwt-svid';
      jwk.kid = authority.key_id || '';
      keys.push(jwk);
    } catch (e) {
      // Dropped, and said so. A JWT authority is nothing BUT its key material,
      // so one that cannot be read carries nothing forward.
      log.warn('spiffe: a JWT authority in a submitted bundle could not be ' +
               'read and was dropped: ' + e.message);
    }
  });
  return {
    keys: keys,
    spiffe_sequence: Number(proto.sequence_number || 0),
    spiffe_refresh_hint: Number(proto.refresh_hint || 0)
  };
}

const bundleHandlers = {
  CountBundles: rpc.unary('server', 'Bundle.CountBundles', async function () {
    // The federated ones only, which is what SPIRE counts: this trust domain's
    // own bundle is not one OF them.
    return { count: ca.federatedBundles().length };
  }),

  GetBundle: rpc.unary('server', 'Bundle.GetBundle', async function (call) {
    await ca.ready();
    return await ownBundleProto((call.request || {}).output_mask);
  }),

  // Adding an authority to this trust domain's own bundle. REFUSED, and the
  // reason is not squeamishness: an X.509 authority in a bundle is a key that
  // may sign identities in this trust domain, and this service holds no private
  // key for one somebody else appends — so the effect would be to publish an
  // authority nothing here can issue against, which every workload would then
  // trust. Rotation is how a new authority appears, and it is on
  // /admin/spiffe.
  AppendBundle: rpc.unary('server', 'Bundle.AppendBundle', async function () {
    throw rpc.statusError(status.PERMISSION_DENIED,
      'This service will not append an authority to its OWN bundle. An ' +
      'authority in a trust domain\'s bundle is a key permitted to sign ' +
      'identities in that trust domain, and this server holds no private key ' +
      'for one somebody else submits — so appending would publish an authority ' +
      'that can issue nothing here, which every workload in the trust domain ' +
      'would nonetheless trust. To add an authority, rotate: POST ' +
      '/admin-api/spiffe/rotate, or the button on /admin/spiffe. ' +
      'Federated bundles are a different thing and are accepted — see ' +
      'BatchCreateFederatedBundle.');
  }),

  PublishJWTAuthority: rpc.unary('server', 'Bundle.PublishJWTAuthority', async function () {
    throw rpc.statusError(status.PERMISSION_DENIED,
      'This service will not publish a JWT authority into its own bundle, for ' +
      'the reason AppendBundle gives: it would advertise a signing key nothing ' +
      'here holds. Rotate instead.');
  }),

  PublishWITAuthority: rpc.unary('server', 'Bundle.PublishWITAuthority', async function () {
    throw rpc.statusError(status.UNIMPLEMENTED,
      'This service issues no WIT-SVIDs and holds no WIT authority. See GET ' +
      '/spiffe for why: the Workload Identity Token\'s format is not settled ' +
      'in a specification this service could implement against, and inventing ' +
      'one would be inventing a credential format.');
  }),

  ListFederatedBundles: rpc.unary('server', 'Bundle.ListFederatedBundles', async function (call) {
    const request = call.request || {};
    const rows = ca.federatedBundles();
    const paged = page(rows, request.page_size, request.page_token);
    return {
      bundles: paged.rows.map(function (entry) {
        return federatedBundleProto(entry, request.output_mask);
      }),
      next_page_token: paged.nextPageToken
    };
  }),

  GetFederatedBundle: rpc.unary('server', 'Bundle.GetFederatedBundle', async function (call) {
    const request = call.request || {};
    const name = String(request.trust_domain || '').trim().toLowerCase();
    const entry = ca.federatedBundle(name);
    if (!entry) {
      throw rpc.notFound('This service holds no bundle for the trust domain ' +
                         (name || '(none given)') + '.');
    }
    return federatedBundleProto(entry, request.output_mask);
  }),

  BatchCreateFederatedBundle: rpc.unary('server', 'Bundle.BatchCreateFederatedBundle',
    async function (call) {
      const request = call.request || {};
      return { results: (request.bundle || []).map(function (message) {
        const name = String(message.trust_domain || '').trim().toLowerCase();
        if (ca.federatedBundle(name)) {
          return { status: statusFor(status.ALREADY_EXISTS,
                                     'A bundle for ' + name + ' is already ' +
                                     'held; use BatchUpdateFederatedBundle or ' +
                                     'BatchSetFederatedBundle.'), bundle: null };
        }
        return setFederated(message, request.output_mask);
      }) };
    }),

  BatchUpdateFederatedBundle: rpc.unary('server', 'Bundle.BatchUpdateFederatedBundle',
    async function (call) {
      const request = call.request || {};
      return { results: (request.bundle || []).map(function (message) {
        const name = String(message.trust_domain || '').trim().toLowerCase();
        if (!ca.federatedBundle(name)) {
          return { status: statusFor(status.NOT_FOUND,
                                     'No bundle for ' + name + ' is held here.'),
                   bundle: null };
        }
        return setFederated(message, request.output_mask);
      }) };
    }),

  // Create-or-update. The one a client should reach for, and the one
  // `spire-server bundle set` uses.
  BatchSetFederatedBundle: rpc.unary('server', 'Bundle.BatchSetFederatedBundle',
    async function (call) {
      const request = call.request || {};
      return { results: (request.bundle || []).map(function (message) {
        return setFederated(message, request.output_mask);
      }) };
    }),

  BatchDeleteFederatedBundle: rpc.unary('server', 'Bundle.BatchDeleteFederatedBundle',
    async function (call) {
      const request = call.request || {};
      // The three modes say what to do about registration entries that federate
      // with the trust domain being deleted. RESTRICT refuses while any does,
      // DELETE removes them too, DISSOCIATE keeps them and drops the
      // federation. All three are implemented, because a client that tested
      // only the default would never learn that RESTRICT is the default.
      const mode = String(request.mode || 'RESTRICT');
      return { results: (request.trust_domains || []).map(function (name) {
        const domain = String(name).trim().toLowerCase();
        const dependents = registry.allEntries().filter(function (entry) {
          return (entry.federatesWith || []).indexOf(domain) >= 0;
        });
        if (dependents.length && mode === 'RESTRICT') {
          return { status: statusFor(status.FAILED_PRECONDITION,
            dependents.length + ' registration entry/entries federate with ' +
            domain + '. Delete them first, or send mode DELETE to remove them ' +
            'with it, or DISSOCIATE to keep them and drop the federation.'),
            trust_domain: domain };
        }
        dependents.forEach(function (entry) {
          if (mode === 'DELETE') {
            registry.deleteEntry(entry.id, '');
          } else if (mode === 'DISSOCIATE') {
            registry.updateEntry(entry.id, {
              federatesWith: (entry.federatesWith || []).filter(function (t) {
                return t !== domain;
              })
            }, trustDomain(), '');
          }
        });
        const removed = ca.deleteFederatedBundle(domain);
        if (!removed) {
          return { status: statusFor(status.NOT_FOUND,
                                     'No bundle for ' + domain + ' is held here.'),
                   trust_domain: domain };
        }
        auditBundleChange('a federated bundle for ' + domain + ' was deleted');
        return { status: okStatus(), trust_domain: domain };
      }) };
    })
};

function setFederated(message, mask) {
  const name = String(message.trust_domain || '').trim().toLowerCase();
  const document = bundleDocumentFromProto(message);
  const result = ca.setFederatedBundle(name, document, {});
  if (!result.ok) {
    return { status: statusFor(status.INVALID_ARGUMENT, result.reason),
             bundle: null };
  }
  auditBundleChange('a federated bundle for ' + name + ' was set');
  return { status: okStatus(),
           bundle: federatedBundleProto(ca.federatedBundle(name), mask) };
}

function auditBundleChange(what) {
  audit.audit({
    action: 'spiffe.bundle.change', actor: '', protocol: 'SPIRE Server API',
    channel: 'grpc', target: '', summary: 'The trust bundle changed: ' + what,
    detail: { sequence: ca.sequence() }
  });
}

// ===========================================================================
// THE SVID SERVICE.
// ===========================================================================
const svidHandlers = {
  // Minting outside any registration entry. This is `spire-server x509 mint`,
  // and it is deliberately not tied to an entry — an operator asking for a
  // one-off certificate is what it is for.
  MintX509SVID: rpc.unary('server', 'SVID.MintX509SVID', async function (call) {
    await ca.ready();
    const request = call.request || {};
    if (!request.csr || !request.csr.length) {
      throw rpc.invalidArgument('MintX509SVID takes a certificate signing ' +
                                'request; the SPIFFE ID is read from its URI ' +
                                'subjectAltName.');
    }
    // The one place a CSR's OWN subjectAltName is read, and it is safe here for
    // a reason that does not generalise: there is no entry to take the identity
    // from, so the request is the only statement of what is wanted. Everywhere
    // else — AttestAgent, BatchNewX509SVID — the identity comes from the entry
    // and only the public key is read out of the CSR.
    const wanted = spiffeIdFromCsr(request.csr);
    if (!wanted) {
      throw rpc.invalidArgument('That certificate signing request carries no ' +
                                'SPIFFE ID in a URI subjectAltName, so there ' +
                                'is nothing to mint. This is the one method ' +
                                'here that reads the identity out of the CSR: ' +
                                'there is no registration entry to take it ' +
                                'from.');
    }
    const svid = await ca.signCsr(Buffer.from(request.csr), wanted,
                                  { ttl: Number(request.ttl || 0) });
    stats.recordSvid('X.509', { subject: wanted, serial: svid.serialHex,
                                expiresAt: svid.expiresAt });
    auditSvid('An X509-SVID was minted for ' + wanted, wanted);
    return { svid: { cert_chain: [svid.certificateDer],
                     id: spiffeId.toProto(wanted),
                     expires_at: String(svid.expiresAt), hint: '' } };
  }),

  MintJWTSVID: rpc.unary('server', 'SVID.MintJWTSVID', async function (call) {
    await ca.ready();
    const request = call.request || {};
    const id = spiffeId.fromProto(request.id);
    if (!id) {
      throw rpc.invalidArgument('MintJWTSVID needs the SPIFFE ID to mint for, ' +
                                'as a trust_domain and a path.');
    }
    const audiences = (request.audience || []).map(String).filter(Boolean);
    if (!audiences.length) {
      throw rpc.invalidArgument('MintJWTSVID requires at least one audience: a ' +
                                'JWT-SVID is a bearer credential, and the ' +
                                'audience is what stops one being replayed ' +
                                'against a different service.');
    }
    const minted = await ca.mintJwtSvid(id, audiences,
                                        { ttl: Number(request.ttl || 0) });
    stats.recordSvid('JWT', { subject: id, audiences: audiences,
                              expiresAt: minted.expiresAt });
    auditSvid('A JWT-SVID was minted for ' + id, id);
    return { svid: { token: minted.token, id: spiffeId.toProto(id),
                     expires_at: String(minted.expiresAt),
                     issued_at: String(minted.issuedAt), hint: '' } };
  }),

  MintWITSVID: rpc.unary('server', 'SVID.MintWITSVID', async function () {
    throw rpc.statusError(status.UNIMPLEMENTED,
      'This service issues no WIT-SVIDs; see GET /spiffe for why. X509-SVIDs ' +
      'and JWT-SVIDs are fully implemented.');
  }),

  // What an AGENT calls: one CSR per registration entry it is handing an SVID
  // to. The identity comes from the ENTRY, and only the public key is read out
  // of the CSR — which is the check that stops an agent naming itself anything
  // it likes even though nothing here authenticates it.
  BatchNewX509SVID: rpc.unary('server', 'SVID.BatchNewX509SVID', async function (call) {
    await ca.ready();
    const request = call.request || {};
    const results = [];
    for (let i = 0; i < (request.params || []).length; i++) {
      const params = request.params[i];
      const entry = registry.entryById(String(params.entry_id || ''));
      if (!entry) {
        results.push({ status: statusFor(status.NOT_FOUND,
          'No registration entry has the id ' + String(params.entry_id || '') + '.'),
          svid: null });
        continue;
      }
      if (!params.csr || !params.csr.length) {
        results.push({ status: statusFor(status.INVALID_ARGUMENT,
          'Entry ' + entry.id + ' was given no certificate signing request.'),
          svid: null });
        continue;
      }
      try {
        const svid = await ca.signCsr(Buffer.from(params.csr), entry.spiffeId, {
          ttl: entry.x509SvidTtl, dnsNames: entry.dnsNames, hint: entry.hint
        });
        registry.noteSvidIssued(entry.id);
        stats.recordSvid('X.509', { subject: entry.spiffeId, entryId: entry.id,
                                    serial: svid.serialHex, hint: entry.hint,
                                    expiresAt: svid.expiresAt });
        results.push({ status: okStatus(),
                       svid: { cert_chain: [svid.certificateDer],
                               id: spiffeId.toProto(entry.spiffeId),
                               expires_at: String(svid.expiresAt),
                               hint: entry.hint || '' } });
      } catch (e) {
        // Per item, like every other batch here.
        results.push({ status: statusFor(status.INVALID_ARGUMENT, e.message),
                       svid: null });
      }
    }
    auditSvid(results.length + ' X509-SVID(s) were issued from registration entries', '');
    return { results: results };
  }),

  NewJWTSVID: rpc.unary('server', 'SVID.NewJWTSVID', async function (call) {
    await ca.ready();
    const request = call.request || {};
    const entry = registry.entryById(String(request.entry_id || ''));
    if (!entry) {
      throw rpc.notFound('No registration entry has the id ' +
                         String(request.entry_id || '(none given)') + '.');
    }
    const audiences = (request.audience || []).map(String).filter(Boolean);
    if (!audiences.length) {
      throw rpc.invalidArgument('NewJWTSVID requires at least one audience.');
    }
    const minted = await ca.mintJwtSvid(entry.spiffeId, audiences,
                                        { ttl: entry.jwtSvidTtl, hint: entry.hint });
    registry.noteSvidIssued(entry.id);
    stats.recordSvid('JWT', { subject: entry.spiffeId, entryId: entry.id,
                              audiences: audiences, hint: entry.hint,
                              expiresAt: minted.expiresAt });
    auditSvid('A JWT-SVID was issued from entry ' + entry.id, entry.spiffeId);
    return { svid: { token: minted.token, id: spiffeId.toProto(entry.spiffeId),
                     expires_at: String(minted.expiresAt),
                     issued_at: String(minted.issuedAt),
                     hint: entry.hint || '' } };
  }),

  BatchNewWITSVID: rpc.unary('server', 'SVID.BatchNewWITSVID', async function () {
    throw rpc.statusError(status.UNIMPLEMENTED,
      'This service issues no WIT-SVIDs; see GET /spiffe for why.');
  }),

  // An intermediate CA for a downstream SPIRE server. Issued, and the entry's
  // `downstream` flag is NOT checked — nothing here authenticates the caller,
  // so there is no entry to check it on. Said plainly rather than left as a
  // silent difference from a real server.
  NewDownstreamX509CA: rpc.unary('server', 'SVID.NewDownstreamX509CA', async function (call) {
    await ca.ready();
    const request = call.request || {};
    const downstream = await ca.downstreamCa({
      ttl: Number(request.preferred_ttl || 0)
    });
    const state = ca.state();
    auditSvid('A downstream X.509 CA was issued', '');
    return {
      ca_cert_chain: downstream.chainDer,
      x509_authorities: state.x509Authorities.map(function (authority) {
        return Buffer.from(authority.certificatePem
          .replace(/-----[^-]+-----/g, '').replace(/\s+/g, ''), 'base64');
      })
    };
  })
};

function spiffeIdFromCsr(csr) {
  try {
    // Node's own X509 parser cannot read a CSR, so this uses the same pkijs the
    // CA does — through a require here rather than an export from spiffe_ca.js,
    // because reading a CSR's SANs is this file's business and minting is that
    // one's.
    const pkijs = require('pkijs');
    const asn1js = require('asn1js');
    const buf = Buffer.isBuffer(csr) ? csr : Buffer.from(csr);
    const request = pkijs.CertificationRequest.fromBER(
      buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength));
    let found = '';
    (request.attributes || []).forEach(function (attribute) {
      if (found || attribute.type !== '1.2.840.113549.1.9.14') return;
      (attribute.values || []).forEach(function (value) {
        if (found) return;
        const extensions = new pkijs.Extensions({ schema: value });
        (extensions.extensions || []).forEach(function (extension) {
          if (found || extension.extnID !== '2.5.29.17') return;
          const names = new pkijs.GeneralNames({
            schema: asn1js.fromBER(extension.extnValue.valueBlock.valueHexView).result
          });
          (names.names || []).forEach(function (name) {
            if (found) return;
            if (name.type === 6 && spiffeId.isValid(name.value)) found = name.value;
          });
        });
      });
    });
    return found;
  } catch (e) {
    // Not a readable CSR, or one with no extensions. The caller answers
    // InvalidArgument with a message about the SPIFFE ID, which is the useful
    // thing to say; the parse failure itself is only interesting at debug.
    log.debug('spiffeIdFromCsr(): could not read a SPIFFE ID out of the CSR: ' +
              e.message);
    return '';
  }
}

function auditSvid(summary, subject) {
  audit.audit({
    action: 'spiffe.svid.issue', actor: '', protocol: 'SPIRE Server API',
    channel: 'grpc', target: subject || '', summary: summary,
    // No SVID and no key, exactly as on the Workload API side.
    detail: {}
  });
}

// ===========================================================================
// THE TRUST DOMAIN SERVICE — federation relationships.
//
// A relationship is the CONFIGURATION of a federation: which trust domain,
// where its bundle endpoint is, which profile, and optionally the bundle
// itself. This service holds all of it and FETCHES NOTHING — see
// `spiffe_ca.setFederatedBundle()` and `RefreshBundle` below.
// ===========================================================================
function relationshipProto(entry, mask) {
  const full = {
    trust_domain: entry.trustDomain,
    bundle_endpoint_url: entry.bundleEndpointUrl || '',
    trust_domain_bundle: federatedBundleProto(entry, null)
  };
  // The profile is a `oneof`, so exactly one of the two is set. Setting both —
  // which is easy to do by assigning them in sequence — leaves protobuf
  // silently keeping the last, and a relationship that says https_web when the
  // operator configured https_spiffe.
  if (entry.bundleEndpointProfile === 'https_spiffe') {
    full.https_spiffe = { endpoint_spiffe_id: entry.endpointSpiffeId || '' };
  } else {
    full.https_web = {};
  }
  if (!mask || !Object.keys(mask).some(function (k) { return mask[k]; })) return full;
  const out = { trust_domain: full.trust_domain };
  if (mask.bundle_endpoint_url) out.bundle_endpoint_url = full.bundle_endpoint_url;
  if (mask.bundle_endpoint_profile) {
    if (full.https_spiffe) out.https_spiffe = full.https_spiffe;
    else out.https_web = full.https_web;
  }
  if (mask.trust_domain_bundle) out.trust_domain_bundle = full.trust_domain_bundle;
  return out;
}

function setRelationship(message, mask) {
  const name = String(message.trust_domain || '').trim().toLowerCase();
  const existing = ca.federatedBundle(name);
  const document = message.trust_domain_bundle
    ? bundleDocumentFromProto(message.trust_domain_bundle)
    : (existing ? existing.document : { keys: [] });
  const profile = message.https_spiffe ? 'https_spiffe' : 'https_web';
  const result = ca.setFederatedBundle(name, document, {
    bundleEndpointUrl: message.bundle_endpoint_url || '',
    bundleEndpointProfile: profile,
    endpointSpiffeId: (message.https_spiffe || {}).endpoint_spiffe_id || ''
  });
  if (!result.ok) {
    return { status: statusFor(status.INVALID_ARGUMENT, result.reason),
             federation_relationship: null };
  }
  auditBundleChange('a federation relationship with ' + name + ' was set');
  return { status: okStatus(),
           federation_relationship: relationshipProto(ca.federatedBundle(name), mask) };
}

const trustDomainHandlers = {
  ListFederationRelationships: rpc.unary('server', 'TrustDomain.ListFederationRelationships',
    async function (call) {
      const request = call.request || {};
      const paged = page(ca.federatedBundles(), request.page_size, request.page_token);
      return {
        federation_relationships: paged.rows.map(function (entry) {
          return relationshipProto(entry, request.output_mask);
        }),
        next_page_token: paged.nextPageToken
      };
    }),

  GetFederationRelationship: rpc.unary('server', 'TrustDomain.GetFederationRelationship',
    async function (call) {
      const request = call.request || {};
      const name = String(request.trust_domain || '').trim().toLowerCase();
      const entry = ca.federatedBundle(name);
      if (!entry) {
        throw rpc.notFound('No federation relationship with ' +
                           (name || '(none given)') + ' is configured here.');
      }
      return relationshipProto(entry, request.output_mask);
    }),

  BatchCreateFederationRelationship: rpc.unary('server',
    'TrustDomain.BatchCreateFederationRelationship', async function (call) {
      const request = call.request || {};
      return { results: (request.federation_relationships || []).map(function (message) {
        const name = String(message.trust_domain || '').trim().toLowerCase();
        if (ca.federatedBundle(name)) {
          return { status: statusFor(status.ALREADY_EXISTS,
            'A federation relationship with ' + name + ' is already here.'),
            federation_relationship: null };
        }
        return setRelationship(message, request.output_mask);
      }) };
    }),

  BatchUpdateFederationRelationship: rpc.unary('server',
    'TrustDomain.BatchUpdateFederationRelationship', async function (call) {
      const request = call.request || {};
      return { results: (request.federation_relationships || []).map(function (message) {
        const name = String(message.trust_domain || '').trim().toLowerCase();
        if (!ca.federatedBundle(name)) {
          return { status: statusFor(status.NOT_FOUND,
            'No federation relationship with ' + name + ' is configured here.'),
            federation_relationship: null };
        }
        return setRelationship(message, request.output_mask);
      }) };
    }),

  BatchDeleteFederationRelationship: rpc.unary('server',
    'TrustDomain.BatchDeleteFederationRelationship', async function (call) {
      const request = call.request || {};
      return { results: (request.trust_domains || []).map(function (name) {
        const domain = String(name).trim().toLowerCase();
        const removed = ca.deleteFederatedBundle(domain);
        if (removed) auditBundleChange('a federation relationship with ' + domain + ' was deleted');
        return { status: removed ? okStatus()
                   : statusFor(status.NOT_FOUND,
                               'No federation relationship with ' + domain + '.'),
                 trust_domain: domain };
      }) };
    }),

  // THE ONE METHOD THAT EXISTS TO SAY NO, AND IT IS A POSITION RATHER THAN A
  // GAP.
  //
  // `RefreshBundle` asks the server to go and fetch a federated bundle from the
  // endpoint URL recorded in the relationship. This service will not: fetching
  // a URL that somebody registered, in order to obtain a key it will then use
  // to verify credentials, is a server-side request forgery with a
  // specification citation attached — and on a service that authenticates
  // nobody and accepts any registration, it is a blind HTTP client anybody can
  // point anywhere.
  //
  // The same refusal `wsfed.js` gives `wreqptr` and `client_auth.js` gives
  // `jwks_uri`. Holding the position in two files and not in a third would be
  // no position at all.
  RefreshBundle: rpc.unary('server', 'TrustDomain.RefreshBundle', async function (call) {
    const name = String((call.request || {}).trust_domain || '').trim().toLowerCase();
    const entry = ca.federatedBundle(name);
    if (!entry) {
      throw rpc.notFound('No federation relationship with ' +
                         (name || '(none given)') + ' is configured here.');
    }
    throw rpc.statusError(status.UNIMPLEMENTED,
      'This service records a bundle endpoint URL and never fetches it. ' +
      'Fetching a URL somebody registered, to obtain a key that will then ' +
      'verify credentials, is a server-side request forgery with a ' +
      'specification citation attached — and nothing here authenticates the ' +
      'caller who registered it. The same refusal this service gives ' +
      'WS-Federation\'s wreqptr and a client\'s jwks_uri. Push the bundle in ' +
      'instead: BatchSetFederatedBundle, POST /admin-api/spiffe/federation-set, ' +
      'or the form on /admin/spiffe. The URL recorded for ' + name + ' is ' +
      (entry.bundleEndpointUrl || '(none)') + '.');
  })
};

// ===========================================================================
// THE DEBUG SERVICE — one method, and the cheapest health check here.
// ===========================================================================
const debugHandlers = {
  GetInfo: rpc.unary('server', 'Debug.GetInfo', async function () {
    await ca.ready();
    const state = ca.state();
    const active = state.x509Authorities[0];
    return {
      // A real server reports its own SVID chain. This one has no SVID — it is
      // the CA — so it reports the CA certificate, which is the closest true
      // statement rather than an empty list that reads as a fault.
      svid_chain: active ? [{
        id: spiffeId.toProto(spiffeId.serverId(trustDomain())),
        expires_at: String(Math.floor(new Date(active.notAfter).getTime() / 1000)),
        subject: active.subject
      }] : [],
      uptime: Math.floor((Date.now() - (state.startedAt || Date.now())) / 1000),
      agents_count: registry.agentCount(),
      federated_bundles_count: ca.federatedBundles().length,
      entries_count: registry.entryCount()
    };
  })
};

// ===========================================================================
// WHAT THIS SURFACE IMPLEMENTS, for the pages that describe it.
//
// `implemented: false` is a claim with a reason attached, and there are six of
// them. A table that said forty-two of forty-two would be the most misleading
// thing in this repository — the same rule `sts_metadata.js`'s coverage notes
// follow, and the same rule that makes `oauth2_bcp.js` publish `enforced: 'no'`
// rows rather than omitting them.
// ===========================================================================
// The methods that answer `Unimplemented`, each with the reason it does —
// published on `GET /spiffe` and on the console, because a table reporting
// forty-two of forty-two would be the most misleading thing in this repository.
//
// **`Agent.RenewAgent` USED TO BE IN HERE AND IS NOT ANY MORE.** Its reason was
// that nothing authenticated the caller, so there was no way to know which
// agent to renew; mutual TLS on the SPIRE Server API answered that, and the
// method now renews the agent on the connection. It still refuses, with the
// same argument, when `spiffe.authRequired` is off — see the handler.
const NOT_IMPLEMENTED = {
  'Bundle.AppendBundle':
    'It would publish an authority this server holds no key for, which every ' +
    'workload in the trust domain would then trust. Rotate instead.',
  'Bundle.PublishJWTAuthority':
    'The same reason as AppendBundle.',
  'Bundle.PublishWITAuthority':
    'This service issues no WIT-SVIDs.',
  'SVID.MintWITSVID':
    'This service issues no WIT-SVIDs.',
  'SVID.BatchNewWITSVID':
    'This service issues no WIT-SVIDs.',
  'TrustDomain.RefreshBundle':
    'This service records a bundle endpoint URL and never fetches it — the ' +
    'same refusal it gives wreqptr and jwks_uri. Push the bundle in instead.'
};

const SERVICE_HANDLERS = [
  { name: 'entry', label: 'Entry', handlers: entryHandlers,
    what: 'Registration entries: what identity a workload gets, under which ' +
          'parent, matching which selectors. The store is the LDAP directory ' +
          'under ou=entries,ou=spiffe, so an ldapmodify and a BatchUpdateEntry ' +
          'are two doors onto one entry.' },
  { name: 'agent', label: 'Agent', handlers: agentHandlers,
    what: 'Attesting, listing, banning and join tokens. NODE ATTESTATION IS ' +
          'NEVER VERIFIED — whatever attestor an agent names and whatever ' +
          'payload it sends are taken on trust — but the CSR is real, a join ' +
          'token is single-use, and a ban is enforced.' },
  { name: 'bundle', label: 'Bundle', handlers: bundleHandlers,
    what: 'This trust domain\'s bundle, and every federated one. Appending to ' +
          'this trust domain\'s own is refused with a reason; federated ' +
          'bundles are accepted from a caller and never fetched.' },
  { name: 'svid', label: 'SVID', handlers: svidHandlers,
    what: 'Minting on demand and signing an agent\'s CSRs. Only the public key ' +
          'is read out of a CSR except at MintX509SVID, where there is no ' +
          'entry to take the identity from and the CSR is the only statement ' +
          'of what is wanted.' },
  { name: 'trustdomain', label: 'TrustDomain', handlers: trustDomainHandlers,
    what: 'Federation relationships: which trust domain, which bundle ' +
          'endpoint, which profile. RefreshBundle is refused — see its ' +
          'message.' },
  { name: 'debug', label: 'Debug', handlers: debugHandlers,
    what: 'GetInfo: uptime, and how many entries, agents and federated ' +
          'bundles this server holds. The cheapest health check here.' }
];

module.exports = {
  SERVICE_HANDLERS: SERVICE_HANDLERS,
  NOT_IMPLEMENTED: NOT_IMPLEMENTED,
  // Exported so the console can show what a join token is worth without a
  // second store — the one-store rule, applied to something that never reaches
  // the directory because a credential does not belong in one.
  joinTokens: joinTokens,
  entryToProto: entryToProto,
  entryFromProto: entryFromProto
};
