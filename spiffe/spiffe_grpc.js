'use strict';
//
// File: spiffe_grpc.js
//
// ---------------------------------------------------------------------------
// THE gRPC PLUMBING BOTH SPIFFE SURFACES SIT ON: loading the vendored `.proto`
// files, binding the listeners, the one header check the Workload Endpoint
// specification requires, and turning an ordinary thrown Error into a gRPC
// status.
//
// It is a LIBRARY: it registers no HTTP route, and it holds no protocol
// knowledge — `spiffe_workload.js` and `spiffe_api.js` are the two callers and
// each brings its own handlers. It requires `helpers.js`, `config.js`,
// `audit.js` and `admin_stats.js`, none of which requires it back.
//
// ---------------------------------------------------------------------------
// WHY `@grpc/grpc-js` IS A DEPENDENCY HERE, IN A PACKAGE THAT IS DELIBERATELY
// SHORT
//
// The argument this repository makes against `swagger-ui-dist` (see
// `admin_api_docs.js`) is a real argument and it was made again here, in the
// other direction. The Workload API is gRPC over HTTP/2 with protobuf framing;
// this service already hand-rolls ASN.1, NDR and a Kerberos PAC, so a
// hand-rolled protobuf codec and a gRPC server over node's built-in `http2`
// was a genuine option — around 900 lines, no dependency.
//
// It was not taken, and the reason is what this whole service is FOR. A mock
// exists to be talked to by REAL clients: `go-spiffe`, `spiffe-helper`, a SPIRE
// agent, the `spire-server` CLI. An interoperability bug in a hand-rolled
// HTTP/2 framer does not announce itself as a framing bug — it appears as a
// client that hangs, or that reports a truncated message, and the client author
// debugging it has no way to tell whether the fault is theirs or ours. That is
// the exact failure this service exists to prevent somebody suffering. The
// explorer script traded a familiar look for 11.7 MB; this trades ~30 packages
// for the wire being right.
//
// ---------------------------------------------------------------------------
// THE `.proto` FILES ARE VENDORED AND ARE LOAD-BEARING
//
// `protos/workloadapi.proto` is a verbatim copy of the SPIFFE project's own,
// and `protos/spire/**` of the `spire-api-sdk`'s. They are read AT REQUIRE
// TIME, at module scope, and a missing one is not a degraded feature — this
// module does not load. That is the same decision `bbs2023.js` makes about
// `contexts/`, and for a similar reason: a service that advertised the Workload
// API and then answered `Unimplemented` because a file was missing would be
// worse than one that did not start.
//
// **Do not edit them.** They are somebody else's files, and the whole value of
// the dependency above is that the wire matches what a real client expects.
// ---------------------------------------------------------------------------

const fs = require('fs');
const path = require('path');
const grpc = require('@grpc/grpc-js');
const loader = require('@grpc/proto-loader');
const { log } = require('../common/helpers');
const config = require('../common/config');
const audit = require('../common/audit');
const stats = require('../common/admin_stats');
// WHO IS CALLING. A library that decides and never answers — see its header —
// which is why this module maps its refusal descriptors onto statuses below
// rather than that one building a gRPC error. The require is the ordinary
// direction and closes no cycle: nothing it requires reaches back here.
const auth = require('./spiffe_auth');
// For the server's own SVID and the roots it verifies clients against. Both
// register nothing, so neither can move a route or close a cycle.
const spiffeId = require('./spiffe_id');
const ca = require('./spiffe_ca');

// ---------------------------------------------------------------------------
// LOADING.
//
// `keepCase: true` is the one option here that is not a default and it is
// load-bearing: without it, `spiffe_id` on the wire becomes `spiffeId` in the
// handler and `x509_svid_key` becomes `x509SvidKey`. Both spellings work as
// long as EVERY site uses the same one — which is exactly the kind of thing
// that is true until somebody writes one field by hand. The field names in the
// handlers below are therefore the field names in the `.proto` files, and a
// reader can compare them line for line.
//
// `longs: String` because `expires_at` is an int64 and JavaScript numbers are
// not. A protobuf int64 arriving as a `Long` object that stringifies to
// something unexpected is a class of bug that shows up as a certificate
// expiring in 1970.
// ---------------------------------------------------------------------------
const PROTO_DIR = path.join(__dirname, 'protos');

const LOAD_OPTIONS = {
  keepCase: true,
  longs: String,
  enums: String,
  defaults: true,
  oneofs: true,
  includeDirs: [PROTO_DIR]
};

const WORKLOAD_PROTO = 'workloadapi.proto';

const SERVER_PROTOS = [
  'spire/api/server/entry/v1/entry.proto',
  'spire/api/server/agent/v1/agent.proto',
  'spire/api/server/bundle/v1/bundle.proto',
  'spire/api/server/svid/v1/svid.proto',
  'spire/api/server/trustdomain/v1/trustdomain.proto',
  'spire/api/server/debug/v1/debug.proto'
];

function loadDefinitions() {
  log.debug('Entering loadDefinitions().');
  const workload = loader.loadSync(WORKLOAD_PROTO, LOAD_OPTIONS);
  const server = loader.loadSync(SERVER_PROTOS, LOAD_OPTIONS);
  log.debug('Leaving loadDefinitions().');
  return { workload: workload, server: server };
}

const DEFINITIONS = loadDefinitions();

// The service definitions, by the fully-qualified name the wire uses. Named
// here, once, so that a typo in a service name is a `TypeError` at startup
// rather than a method nothing ever routes to.
const SERVICES = {
  workload: DEFINITIONS.workload['SpiffeWorkloadAPI'],
  entry: DEFINITIONS.server['spire.api.server.entry.v1.Entry'],
  agent: DEFINITIONS.server['spire.api.server.agent.v1.Agent'],
  bundle: DEFINITIONS.server['spire.api.server.bundle.v1.Bundle'],
  svid: DEFINITIONS.server['spire.api.server.svid.v1.SVID'],
  trustdomain: DEFINITIONS.server['spire.api.server.trustdomain.v1.TrustDomain'],
  debug: DEFINITIONS.server['spire.api.server.debug.v1.Debug']
};

Object.keys(SERVICES).forEach(function (name) {
  if (!SERVICES[name]) {
    throw new Error('spiffe: the ' + name + ' service is not in the vendored ' +
                    'protos. This is a build problem rather than a runtime ' +
                    'one — see protos/ and the note at the top of ' +
                    'spiffe_grpc.js.');
  }
});

// What each surface publishes, for `/spiffe` and `/admin/sts-metadata` — which
// cannot see a gRPC method any more than they can see a raw socket, so the list
// is built HERE from the loaded definitions rather than typed out. A method
// that exists and goes undescribed is the drift `sts_metadata.js` exists to
// prevent, and this is the only way to have the same property for a surface
// Express knows nothing about.
function methodsOf(serviceName) {
  const service = SERVICES[serviceName];
  return Object.keys(service).map(function (key) {
    const method = service[key];
    return {
      name: method.originalName || key,
      path: method.path,
      requestStream: !!method.requestStream,
      responseStream: !!method.responseStream
    };
  }).sort(function (a, b) { return a.name.localeCompare(b.name); });
}

// ---------------------------------------------------------------------------
// THE ONE CHECK THE SPECIFICATION REQUIRES, AND WHY IT IS ON IN A SERVICE THAT
// REFUSES ALMOST NOTHING.
//
// The SPIFFE Workload Endpoint specification says a client MUST send
// `workload.spiffe.io: true` on every call and a server MUST refuse a call
// without it. It is not a security check — anybody can send a header — and it
// is not authentication. It exists so that a caller cannot reach the Workload
// API BY ACCIDENT: the endpoint is usually a Unix socket with permissive
// filesystem permissions, and the header is a positive statement that the
// caller meant to talk to a Workload API.
//
// This service checks it, and that is a deliberate exception to its permissive
// posture, for one reason: **a client that omits it has a bug, and this is the
// only thing that will ever tell them.** Every real Workload API will refuse
// them; a mock that accepted it would let a client author ship code that works
// against this and against nothing else. `spiffe.requireSecurityHeader` turns
// it off for the case where somebody is deliberately testing something else.
//
// The refusal is `InvalidArgument`, which is what SPIRE answers.
// ---------------------------------------------------------------------------
const SECURITY_HEADER = 'workload.spiffe.io';

function securityHeaderPresent(call) {
  const metadata = call && call.metadata;
  if (!metadata) return false;
  const values = metadata.get(SECURITY_HEADER) || [];
  for (let i = 0; i < values.length; i++) {
    if (String(values[i]).trim().toLowerCase() === 'true') return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// TURNING A THROWN ERROR INTO A STATUS.
//
// Every handler below is written as though it may throw, and this is the single
// place a throw becomes an answer. That is the same funnel argument
// `helpers.signJwt()` makes about counting tokens: a status built at each of
// forty-two call sites is forty-one that are right and one that reports
// `Unknown` for an argument problem.
//
// A handler may throw a plain Error — which becomes `Unknown` and is LOGGED as
// a defect, because an unclassified error in a mock is a bug in the mock — or
// one carrying a `.code`, built by `statusError()` below, which is what every
// deliberate refusal uses.
// ---------------------------------------------------------------------------
function statusError(code, message) {
  const err = new Error(message);
  err.code = code;
  return err;
}

function invalidArgument(message) {
  return statusError(grpc.status.INVALID_ARGUMENT, message);
}

function notFound(message) {
  return statusError(grpc.status.NOT_FOUND, message);
}

function permissionDenied(message) {
  return statusError(grpc.status.PERMISSION_DENIED, message);
}

function unavailable(message) {
  return statusError(grpc.status.UNAVAILABLE, message);
}

function errorToStatus(err, where) {
  if (err && typeof err.code === 'number') {
    return { code: err.code, details: err.message };
  }
  log.error('spiffe: ' + where + ' threw something that was not a status ' +
            'error, which is a defect in this service rather than in the ' +
            'call: ' + (err && err.stack ? err.stack : err));
  return { code: grpc.status.UNKNOWN,
           details: (err && err.message) || 'Something went wrong.' };
}

// ---------------------------------------------------------------------------
// WRAPPING A HANDLER.
//
// Every method goes through here, and it does five things that would otherwise
// be written forty-two times:
//
//   * refuses everything when `spiffe.enabled` is off, with `Unavailable` and a
//     message naming the setting. Read per call, so the switch works without a
//     restart;
//   * checks the security header, on the Workload API only — the SPIRE Server
//     API has no such requirement and adding one would refuse every real
//     `spire-server` client;
//   * logs the call at debug, which is what this service is for;
//   * records it, so `/admin/metrics` counts a gRPC call the way it counts an
//     HTTP one and `/admin/audit` has a row;
//   * turns a throw into a status.
//
// **A STREAMING METHOD IS NOT A UNARY ONE AND THE TWO ARE WRAPPED
// SEPARATELY.** The Workload API's `FetchX509SVID` is a server stream that a
// real client keeps open for the life of the process, expecting a new message
// whenever the SVID rotates. Wrapping it as though it were unary — write once,
// call `end()` — is the single most common way to build a Workload API that
// appears to work: `go-spiffe`'s first fetch succeeds and the client then
// treats the stream ending as an error and reconnects in a tight loop.
// ---------------------------------------------------------------------------
function enabled() {
  return !!config.value('spiffe.enabled');
}

function requireSecurityHeader() {
  return !!config.value('spiffe.requireSecurityHeader');
}

// A refusal descriptor from `spiffe_auth.js` — `{ status, message }` where
// `status` is the NAME of a grpc-js status — becomes a status error here. The
// mapping is in one place so that module can stay ignorant of the transport,
// and an unknown name becomes PERMISSION_DENIED rather than UNKNOWN: a
// misspelt status in a refusal must still refuse.
function fromDescriptor(descriptor) {
  const code = grpc.status[descriptor.status];
  if (typeof code !== 'number') {
    log.error('spiffe: spiffe_auth.js returned the status name "' +
              descriptor.status + '", which grpc-js does not have. Refusing ' +
              'with PERMISSION_DENIED; this is a defect in this service.');
    return statusError(grpc.status.PERMISSION_DENIED, descriptor.message);
  }
  return statusError(code, descriptor.message);
}

// ---------------------------------------------------------------------------
// EVERY CALL PASSES THROUGH HERE, AND IT IS THE ONLY PLACE AUTHORIZATION
// HAPPENS.
//
// Four checks and one side effect, in an order that matters:
//
//   1. is SPIFFE on at all;
//   2. the Workload API's security header (that surface only — the SPIRE
//      Server API has no such requirement and adding one would refuse every
//      real `spire-server` client);
//   3. WHO IS CALLING, built once and attached to the call as `spiffeCaller`
//      so a handler can read it without building it a second way;
//   4. whether that caller may call THIS method, against SPIRE's own table.
//
// The side effect is the identity: an ACCEPTED credential reaches
// `stats.recordAuthentication()` through `auth.recordCaller()`, once per
// connection, so the holder of an SVID appears on /admin/users and in the
// directory beside everybody else who has authenticated here.
//
// **It is here rather than in forty-two handlers** for the reason
// `helpers.signJwt()` is the single token counter: forty-two call sites is
// forty-one that are right and a forty-second added later with no check at all.
// A caller is built for the Workload API too, even though nothing authorizes on
// it there, because that surface derives its SELECTORS from the same object.
// ---------------------------------------------------------------------------
function prepareCall(call, surface, method) {
  log.debug('Entering prepareCall(). surface=' + surface + ', method=' + method);
  if (!enabled()) {
    log.debug('Leaving prepareCall(). SPIFFE is off.');
    return { caller: null,
             refusal: unavailable('SPIFFE is turned off on this service ' +
                       '(spiffe.enabled). The listeners are still bound and ' +
                       'GET /spiffe still says what this is; nothing will be ' +
                       'issued until it is turned back on, which needs no ' +
                       'restart.') };
  }
  if (surface === 'workload' && requireSecurityHeader() &&
      !securityHeaderPresent(call)) {
    log.debug('Leaving prepareCall(). No security header.');
    return { caller: null,
             refusal: invalidArgument('Every call to the SPIFFE Workload API ' +
                           'must carry the metadata header "' +
                           SECURITY_HEADER + ': true" (SPIFFE Workload ' +
                           'Endpoint specification). This one did not. Every ' +
                           'conforming Workload API will refuse it, which is ' +
                           'why this mock does too; ' +
                           'spiffe.requireSecurityHeader turns the check off ' +
                           'if you are deliberately testing something else.') };
  }
  const caller = auth.callerOf(call, surface);
  if (surface === 'workload') {
    // What this service can see about a Workload API caller, as selectors.
    // Built HERE rather than in the handlers because all four issuing methods
    // must answer the same question the same way — a FetchX509SVID that
    // returned three identities and a FetchJWTSVID that returned one would be
    // a mock contradicting itself.
    caller.selectors = auth.workloadSelectors(call, caller);
  }
  // Attached to the call rather than threaded through every handler signature.
  // `call` is the one object every handler already has, the property name says
  // whose it is, and a handler that does not care is unaffected.
  try {
    call.spiffeCaller = caller;
  } catch (e) {
    // A frozen call object would be a grpc-js change rather than anything a
    // caller did. The check still runs; only the handlers lose the detail.
    log.error('spiffe: the caller could not be attached to the call (' +
              e.message + '), so handlers will see none.');
  }
  if (surface === 'server') {
    const refusal = auth.authorize(caller, method);
    if (refusal) {
      // The refusal is audited with the identity that was refused, which is
      // the row somebody debugging "why can my agent not list entries" needs.
      // No credential goes in it — a SPIFFE ID is a name, not a secret, and
      // the certificate itself is never recorded.
      audit.audit({
        action: 'spiffe.call.refuse', actor: caller.spiffeId || '',
        protocol: 'SPIRE Server API', channel: 'grpc', target: method,
        summary: method + ' was refused for ' + auth.describeCaller(caller),
        detail: { status: refusal.status, caller: auth.describeCaller(caller) }
      });
      log.debug('Leaving prepareCall(). Not authorized.');
      return { caller: caller, refusal: fromDescriptor(refusal) };
    }
  }
  // An accepted credential is an authentication, and this is where it is
  // recorded — at the moment it was ACCEPTED, which is the rule every other
  // family here follows. A caller that presented nothing records nothing:
  // being allowed because a method is open is not authenticating.
  auth.recordCaller(caller);
  log.debug('Leaving prepareCall(). Allowed.');
  return { caller: caller, refusal: null };
}

// The audit and metrics row for one gRPC call. `channel: 'grpc'` is a new one
// beside http, ldap, ldaps and internal, and it is a channel rather than a
// protocol for the same reason those are: it says HOW the call arrived, which
// is the question a reader of a mixed log is asking.
function recordCall(surface, method, ok, detail, caller) {
  log.debug('Entering recordCall().');
  try {
    stats.recordCall('grpc:' + method, ok ? 200 : 500, 0);
  } catch (e) {
    // Statistics must never be able to fail a call — the same rule the JWT
    // recorder follows in helpers.js.
    log.error('spiffe: recording a gRPC call threw and was ignored: ' + e.message);
  }
  audit.audit({
    action: 'protocol.call',
    // The identity that made the call, where one was accepted. Empty for an
    // anonymous or local caller, which is most of the Workload API — an audit
    // row must not imply an identity nothing established.
    actor: (caller && caller.authenticated) ? caller.spiffeId : '',
    protocol: surface === 'workload' ? 'SPIFFE Workload API' : 'SPIRE Server API',
    channel: 'grpc',
    target: method,
    summary: (ok ? 'A ' : 'A refused ') + surface + ' gRPC call: ' + method,
    detail: detail || {}
  });
  log.debug('Leaving recordCall().');
}

function unary(surface, method, handler) {
  return function (call, callback) {
    log.debug('Entering the ' + method + ' handler.');
    const prepared = prepareCall(call, surface, method);
    if (prepared.refusal) {
      recordCall(surface, method, false, { refused: prepared.refusal.message },
                 prepared.caller);
      log.debug('Leaving the ' + method + ' handler. Refused.');
      callback(errorToStatus(prepared.refusal, method));
      return;
    }
    Promise.resolve()
      .then(function () { return handler(call); })
      .then(function (reply) {
        recordCall(surface, method, true, {}, prepared.caller);
        callback(null, reply || {});
        log.debug('Leaving the ' + method + ' handler.');
      })
      .catch(function (err) {
        const status = errorToStatus(err, method);
        recordCall(surface, method, false, { status: status.code }, prepared.caller);
        callback(status);
        log.debug('Leaving the ' + method + ' handler. ' + status.details);
      });
  };
}

// A server-streaming method. `handler` returns the FIRST message; the stream is
// then held open and nothing further is written unless `onUpdate` is given.
//
// **The stream is not ended**, and that is the whole point of this function.
// See the note above `unary()`: a Workload API client treats the stream ending
// as a fault. It ends when the client goes away, which is the `cancelled`
// listener below, or when the process does.
function serverStream(surface, method, handler) {
  return function (call) {
    log.debug('Entering the ' + method + ' stream handler.');
    const prepared = prepareCall(call, surface, method);
    if (prepared.refusal) {
      recordCall(surface, method, false, { refused: prepared.refusal.message },
                 prepared.caller);
      call.emit('error', errorToStatus(prepared.refusal, method));
      log.debug('Leaving the ' + method + ' stream handler. Refused.');
      return;
    }
    let open = true;
    // `cancelled` fires when the peer goes away. Without this listener a
    // rotation timer would go on writing to a dead stream, which grpc-js
    // reports as an unhandled error on the server.
    call.on('cancelled', function () {
      open = false;
      log.debug('spiffe: the ' + method + ' stream was cancelled by the client.');
    });
    call.on('error', function (err) {
      open = false;
      log.debug('spiffe: the ' + method + ' stream ended with ' + err.message);
    });
    Promise.resolve()
      .then(function () {
        return handler(call, function push(message) {
          // The push callback a handler uses to send a later message — an SVID
          // that rotated, a bundle that changed. Guarded on `open`, because the
          // handler holds it across time and the client may be long gone.
          if (!open) return false;
          call.write(message);
          return true;
        });
      })
      .then(function (first) {
        if (first && open) call.write(first);
        recordCall(surface, method, true, { streaming: true }, prepared.caller);
        log.debug('Leaving the ' + method + ' stream handler. The stream ' +
                  'stays open; a Workload API client treats it ending as a ' +
                  'fault.');
      })
      .catch(function (err) {
        const status = errorToStatus(err, method);
        recordCall(surface, method, false, { status: status.code }, prepared.caller);
        open = false;
        call.emit('error', status);
        log.debug('Leaving the ' + method + ' stream handler. ' + status.details);
      });
  };
}

// A bidirectional stream. Only `AttestAgent` and `SyncAuthorizedEntries` are
// one, and both are request/response in practice — the client sends, the server
// answers, and the stream closes. So the shape here is "for each message the
// client sends, answer it", which is what those two do and is much easier to
// get right than a general duplex.
function bidiStream(surface, method, handler) {
  return function (call) {
    log.debug('Entering the ' + method + ' bidi handler.');
    const prepared = prepareCall(call, surface, method);
    if (prepared.refusal) {
      recordCall(surface, method, false, { refused: prepared.refusal.message },
                 prepared.caller);
      call.emit('error', errorToStatus(prepared.refusal, method));
      log.debug('Leaving the ' + method + ' bidi handler. Refused.');
      return;
    }
    call.on('data', function (request) {
      Promise.resolve()
        .then(function () { return handler(request, call); })
        .then(function (reply) {
          if (reply) call.write(reply);
        })
        .catch(function (err) {
          const status = errorToStatus(err, method);
          recordCall(surface, method, false, { status: status.code },
                     prepared.caller);
          call.emit('error', status);
        });
    });
    call.on('end', function () {
      recordCall(surface, method, true, { streaming: true }, prepared.caller);
      call.end();
      log.debug('Leaving the ' + method + ' bidi handler. The client ended it.');
    });
    call.on('error', function (err) {
      log.debug('spiffe: the ' + method + ' bidi stream ended with ' + err.message);
    });
  };
}

// ---------------------------------------------------------------------------
// BINDING.
//
// Two transports, and the Unix socket is the interesting one.
//
// **THE SOCKET IS THE ONE THING THIS SERVICE PUTS ON A FILESYSTEM**, and it is
// worth being exact about what that does and does not mean. Nothing is
// PERSISTED through it: it is a rendezvous point, it holds no bytes, it is
// unlinked when the listener closes, and a fresh process makes a fresh one. The
// alternative — TCP only — would have been filesystem-clean and unreachable by
// every real client, because `SPIFFE_ENDPOINT_SOCKET` means a `unix://` path to
// `go-spiffe`, to `spiffe-helper` and to the SPIRE agent.
//
// A STALE SOCKET IS UNLINKED BEFORE BINDING. A process killed with SIGKILL
// leaves the file behind, and `bind` on an existing path fails with EADDRINUSE
// — which reads exactly like "another copy of this service has the port" and is
// usually not. Unlinking first is what every Unix socket server does; the cost
// is that two copies of this service pointed at one path will fight, with the
// second winning silently, so the path is LOGGED at startup.
// ---------------------------------------------------------------------------
function prepareSocketPath(socketPath) {
  log.debug('Entering prepareSocketPath(). path=' + socketPath);
  const directory = path.dirname(socketPath);
  try {
    fs.mkdirSync(directory, { recursive: true });
  } catch (e) {
    // The directory may exist already, which is not an error, or be
    // unwritable, which is — and which `bindAsync` will report in a moment
    // with the path in it. Nothing is lost by carrying on.
    log.debug('prepareSocketPath(): mkdir said ' + e.message +
              ', which bindAsync will report properly if it matters.');
  }
  try {
    const stat = fs.statSync(socketPath);
    if (stat.isSocket()) {
      fs.unlinkSync(socketPath);
      log.warn('spiffe: a stale socket was at ' + socketPath + ' and has been ' +
               'removed. That is the ordinary leftover of a killed process — ' +
               'but if another copy of this service is running and listening ' +
               'there, this one has just taken the path from it.');
    } else {
      // Something that is not a socket. NOT removed: this is a path from
      // configuration and deleting a regular file somebody named would be a
      // destructive act on the strength of a typo.
      log.error('spiffe: ' + socketPath + ' exists and is not a socket, so ' +
                'nothing here will bind it. It is left alone deliberately — ' +
                'removing a file named in configuration on the strength of a ' +
                'typo is not this service\'s decision to make.');
    }
  } catch (e) {
    // ENOENT is the ordinary case and needs no comment; anything else will be
    // reported by bindAsync with more context than there is here.
    log.debug('prepareSocketPath(): nothing at that path (' + e.code + ').');
  }
  log.debug('Leaving prepareSocketPath().');
}

// Build a server with a set of services on it. One function for both surfaces,
// because they differ only in which services they carry and where they bind.
function buildServer(services) {
  log.debug('Entering buildServer().');
  const server = new grpc.Server();
  services.forEach(function (entry) {
    server.addService(SERVICES[entry.name], entry.handlers);
  });
  log.debug('Leaving buildServer(). ' + services.length + ' service(s).');
  return server;
}

// Bind one address, and REPORT a failure rather than throwing it. That is the
// rule every listener in this service follows — see `ldap_server.js` and
// `tls_server.js` — and the reason is the same: a port can already be taken,
// and the fourteen other protocol families here are still useful when one
// listener is not.
function bindOne(server, address, credentials) {
  return new Promise(function (resolve) {
    server.bindAsync(address, credentials, function (err, port) {
      if (err) {
        log.error('spiffe: could not bind ' + address + ': ' + err.message);
        resolve({ address: address, listening: false, error: err.message,
                  port: 0 });
        return;
      }
      resolve({ address: address, listening: true, error: '', port: port });
    });
  });
}

// ---------------------------------------------------------------------------
// THE SPIRE SERVER API'S TLS CREDENTIALS — and the two things about them that
// are easy to get wrong in opposite directions.
//
// A real `spire-server` binds its TCP port as mutual TLS: it presents its own
// X509-SVID (`spiffe://<trust domain>/spire/server`) and asks the client for
// one. So this mints exactly that, from the same authority every other SVID
// here comes from, per start.
//
// **THE SERVER SVID IS NOT `tls_server.js`'S CERTIFICATE**, and must not become
// it. That one is a leaf with `serverAuth` for a host; this one is an identity
// in a trust domain. The two are unrelated trust decisions, which is the same
// argument that keeps the SPIFFE CA separate from that module's — see rule 3k.
// A client verifies this handshake against the TRUST BUNDLE, which it fetched
// from the bundle endpoint, and not against any web PKI.
//
// **THE HANDSHAKE ASKS FOR A CERTIFICATE AND DOES NOT REQUIRE ONE.** grpc-js's
// `createSsl(roots, pairs, checkClientCertificate)` sets `requestCert` from
// that third argument and leaves node's default `rejectUnauthorized: true` in
// place, which would refuse the handshake of any client that presented nothing
// — and `AttestAgent` is open to a caller with no SVID, because an agent HAS no
// SVID until that call gives it one. A port that could not be bootstrapped
// against is a port with no purpose. So the constructor options are reached for
// and `rejectUnauthorized` is turned off, which is `tls.RequestClientCert` —
// exactly what SPIRE does — and `spiffe_auth.js` then verifies what arrived
// itself, against the trust bundle rather than against a system CA store.
// `mtls.js` makes the same arrangement on the main HTTPS listener and the note
// there says the same thing.
//
// A failure to mint is REPORTED and the caller falls back to plain: a listener
// that did not come up at all would take the whole surface away for a reason
// nobody could see, and `GET /spiffe` says which of the two it got.
// ---------------------------------------------------------------------------
async function serverApiCredentials() {
  log.debug('Entering serverApiCredentials().');
  await ca.ready();
  const identity = spiffeId.serverId(ca.trustDomain());
  // ---------------------------------------------------------------------
  // THE SERVER'S OWN CERTIFICATE GETS THE AUTHORITY'S LIFETIME, NOT AN
  // SVID'S, AND THE DIFFERENCE IS A SERVICE THAT STOPS ANSWERING AFTER AN
  // HOUR.
  //
  // This is not a workload SVID. It is a LISTENER'S certificate, minted
  // ONCE at `listen()` and handed to `grpc.ServerCredentials.createSsl()`,
  // which holds it for the life of the process — there is no way to swap it
  // afterwards without rebinding the socket. So with `spiffe.svidTtl` (an
  // hour by default) it expires while the listener is still up, and from
  // that moment every mutual-TLS client is refused with `certificate has
  // expired`.
  //
  // That failure names the CLIENT'S trust store rather than this server's
  // clock: a caller sees only that the certificate it was handed will not
  // verify, and the obvious first move is to re-fetch the bundle — which is
  // perfectly good and changes nothing. A fresh container hides it
  // completely, so it appears as a SPIRE Server API that works right after a
  // restart and not otherwise.
  //
  // `spiffe.caTtl` is the right bound because it is the true one: nothing
  // this authority signs can outlive it, and `issueLeaf()` clamps to the
  // authority's own notAfter anyway. What is left is that the listener's
  // certificate now lasts exactly as long as the trust domain it speaks
  // for.
  // ---------------------------------------------------------------------
  const svid = await ca.mintX509Svid(identity,
    { ttl: config.value('spiffe.caTtl') });
  const roots = await ca.x509BundleDer();
  const credentials = grpc.ServerCredentials.createSsl(
    // The roots are handed over as PEM: node's `ca` option takes PEM or DER,
    // and the bundle here is concatenated DER, which node reads as ONE
    // certificate and silently ignores the rest of. Every authority has to be
    // its own PEM block or a client signed by the second one is refused with
    // no way to tell why.
    Buffer.from(ca.state().x509Authorities.map(function (authority) {
      return authority.certificatePem;
    }).join('\n'), 'utf8'),
    [{ private_key: Buffer.from(svid.privateKeyPem, 'utf8'),
       cert_chain: Buffer.from(svid.chainPem.join('\n'), 'utf8') }],
    true);
  try {
    // See the header. This is a reach into grpc-js's own options object and it
    // is deliberate: there is no argument for "request but do not require", the
    // difference matters here more than anywhere else in this service, and the
    // alternative is a bespoke ServerCredentials subclass that would have to be
    // kept in step with a library we do not otherwise touch.
    credentials._getConstructorOptions().rejectUnauthorized = false;
  } catch (e) {
    log.error('spiffe: the SPIRE Server API TLS listener could not be set to ' +
              'request-but-not-require a client certificate (' + e.message +
              '). It will REFUSE any client that presents none, which means ' +
              'AttestAgent cannot be reached over TCP. This is a grpc-js ' +
              'change rather than anything a caller did.');
  }
  log.info('spiffe: the SPIRE Server API TCP listener is mutual TLS as ' +
           identity + ' (serial ' + svid.serialHex + ', ' + roots.length +
           ' bytes of trust bundle). A client verifies it against the bundle ' +
           'at the bundle endpoint, presents its own X509-SVID, and is ' +
           'authorized per method against SPIRE\'s own table — see ' +
           'GET /spiffe.');
  log.debug('Leaving serverApiCredentials().');
  return credentials;
}

module.exports = {
  grpc: grpc,
  SERVICES: SERVICES,
  SECURITY_HEADER: SECURITY_HEADER,
  methodsOf: methodsOf,
  statusError: statusError,
  invalidArgument: invalidArgument,
  notFound: notFound,
  permissionDenied: permissionDenied,
  unavailable: unavailable,
  unary: unary,
  serverStream: serverStream,
  bidiStream: bidiStream,
  prepareSocketPath: prepareSocketPath,
  buildServer: buildServer,
  bindOne: bindOne,
  serverApiCredentials: serverApiCredentials,
  enabled: enabled
};
