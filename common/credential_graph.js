'use strict';
//
// File: credential_graph.js
//
// ---------------------------------------------------------------------------
// ONE CREDENTIAL, AND EVERY GENERATION BEHIND IT: who it was issued to, in
// whose name, to reach what — and, when it came out of a token exchange, the
// credential that was handed IN to get it, and the one behind that, back to the
// issuance that started the whole line.
//
// It is a LIBRARY, like `user_graph.js` beside it, like `delegation.js` and like
// `admin_stats.js`: it registers no route, so its position in the require order
// does not matter and it cannot be the reason a route is missing. `admin.js`
// renders it at /admin/tokens/credential; this file holds the model and none of
// the HTML.
//
// It requires `helpers.js`, `admin_stats.js`, `delegation.js` and
// `user_graph.js`, and nothing requires IT except the console — so it cannot
// join a cycle and it cannot move a route. Rule 3e's test is not reached. It
// required `applications.js` too until 2026-08-26, for one lookup that now
// lives in `user_graph.js` where the person's picture can share it.
//
// ---------------------------------------------------------------------------
// WHY IT IS A FILE, AND WHY IT IS NOT A FILTER ON THE PERSON'S PICTURE.
//
// `user_graph.js` answers *what has this service done in alice's name* and
// unions the two registers to do it. This answers a narrower question with a
// different shape: *where did THIS credential come from* — and the answer is a
// LINE rather than a fan. A token exchange consumes one credential and produces
// another, so the identifiers form a chain, and following it is the only way to
// get from an access token that reaches sp1 back to the browser sign-in three
// tiers away that everything after it rests on. Filtering the person's picture
// cannot do it: that picture shows every credential ever issued in their name,
// which for a person who has been driven through a suite is forty of them with
// nothing to say which four are this one's ancestors.
//
// ---------------------------------------------------------------------------
// FIVE DECISIONS THAT ARE JUDGEMENTS RATHER THAN MECHANICS.
//
// **THE JOIN IS ON THE IDENTIFIER AND ON NOTHING ELSE.** A delegation act
// records what it CONSUMED and what it PRODUCED, each with the identifier the
// protocol gives it — a `jti`, an `AssertionID` — and that identifier is the one
// thing the delegation register and the issued register both hold about the same
// object. So the walk is: the act whose `produced` names this identifier, then
// the identifiers on that act's `consumed`, and again. Anything cleverer —
// matching on a subject and a time window, on a kind and a client — would
// eventually join two credentials that merely look alike, and a lineage that is
// WRONG is worse than one that is short, because the whole page is an assertion
// about causation. It is `user_graph.js`'s dedupe rule read the other way round,
// and for the same reason.
//
// **A CREDENTIAL WITH NO IDENTIFIER ENDS THE WALK, AND THE PAGE SAYS SO RATHER
// THAN GOING QUIET.** Two of the mechanisms here genuinely have nothing to
// quote: a Kerberos ticket has no jti and no ID in the protocol at all, and
// WS-Trust's `consumed` is the WS-Security credential the requester presented,
// which this service never issued. So a trail can stop at a wall rather than at
// an origin, and those are DIFFERENT ANSWERS: one means "this is where it began"
// and the other means "it began somewhere this register cannot name". The result
// carries both, separately, and the console prints the second as a reason.
//
// **THE ORIGIN IS DRAWN AS AN ISSUANCE AND NOT AS A DELEGATION.** The credential
// at the head of the line was issued by an ordinary grant — nobody exchanged
// anything to get it — so it is drawn with `user_graph.js`'s two relations
// rather than with the delegation register's: `issued-for` from the person to
// the application that holds it, labelled with the GRANT, and the dashed `issued`
// line from this service. Using `acts-for` for it would colour an authorization
// code grant amber for impersonation, which is a claim about a mechanism that
// was not involved. The two pictures therefore agree about what an issuance
// looks like, which is the property that lets somebody read both.
//
// **THE AUDIENCE IS RESOLVED THROUGH THE APPLICATIONS REGISTRY, exactly as the
// token exchange resolves one.** A token addressed to `https://esb1.example.com`
// is addressed to the application that registered that URI on `oauthAudience`,
// and drawing the URI as a box of its own would put two boxes on this picture
// for one party — the failure the exchange's own lookup exists to prevent. So
// the same lookup is asked here, the box is the application, and the URI is on
// the line. An audience nobody registered is drawn as itself, which is the
// honest answer and is what a real resource server looks like here. Since
// 2026-08-26 the lookup is `user_graph.js`'s `audienceParties()` rather than a
// copy of it here, and it also answers the two questions this copy got wrong:
// several audiences are several parties, and an audience that is this SERVICE'S
// own is not a party at all.
//
// **IT WALKS BACKWARDS ONLY.** *Where did this come from* is the question a row
// on the tokens page raises; *what was later made from it* is a different one and
// its answer is a tree rather than a line — one subject token can be exchanged by
// any number of clients. Drawing both would make the common case (a token with
// no ancestry and no descendants at all) into a page that has to explain why it
// is empty in two directions. The forward direction is what /admin/delegation
// and its map are for.
// ---------------------------------------------------------------------------

const { log } = require('./helpers');
const stats = require('./admin_stats');
const delegation = require('./delegation');
const userGraph = require('./user_graph');

// How many generations to follow. Nothing here can produce a cycle — an
// identifier is produced once and the walk marks what it has seen — so this is
// not a cycle guard but a SIZE guard, for the case somebody points this at a
// service that has been exchanging tokens in a loop all afternoon. Reaching it
// is reported rather than silently truncating the line, because a lineage that
// stops early and does not say so reads as an origin that is not one.
const MAX_GENERATIONS = 50;

// ---------------------------------------------------------------------------
// The two halves of the join, as small functions with names, because each one
// encodes a rule that is stated in the header and would otherwise be an
// expression inside a loop.
// ---------------------------------------------------------------------------

// The act that PRODUCED this identifier, or null. `acts` arrives newest first
// (delegation.list()'s order), and the first match is the answer: an identifier
// is minted once, so two acts claiming to have produced it would be a bug in the
// recording rather than a case to resolve here.
function producerOf(acts, identifier) {
  log.debug("Entering producerOf(). identifier=" + identifier);
  const wanted = String(identifier || '');
  if (!wanted) {
    log.debug("Leaving producerOf(). Nothing was asked for.");
    return null;
  }
  const found = (acts || []).filter(function (row) {
    return (row.produced || []).some(function (one) {
      return String(one.identifier || '') === wanted;
    });
  });
  log.debug("Leaving producerOf(). " + found.length + " act(s) name it.");
  return found.length ? found[0] : null;
}

// What an act consumed, split into the credentials this register can FOLLOW and
// the ones it cannot. The second list is not an error and is most of the value
// of keeping them apart: a WS-Trust act consumes the requester's WS-Security
// credential, which this service never issued and cannot name, and a Kerberos
// act consumes a ticket that has no identifier in the protocol. Saying "the
// trail ends here because that credential has no identifier" is a different
// sentence from "the trail ends here because this is the beginning".
function consumedOf(act) {
  log.debug("Entering consumedOf().");
  const followable = [];
  const opaque = [];
  ((act && act.consumed) || []).forEach(function (one) {
    if (String(one.identifier || '')) {
      followable.push(one);
    } else {
      opaque.push(one);
    }
  });
  log.debug("Leaving consumedOf(). " + followable.length + " followable, " +
            opaque.length + " with no identifier.");
  return { followable: followable, opaque: opaque };
}

// The person a credential is ABOUT, in whichever field its family records one.
// The same two-field rule `recordJwt()` applies for the tokens page's User
// column — `username` on an access or refresh token, `preferred_username` on an
// ID Token, both already folded into `username` there — with the artifact
// families' single `subject` beside it.
function subjectOf(record) {
  log.debug("Entering subjectOf().");
  if (!record) {
    log.debug("Leaving subjectOf(). No record.");
    return '';
  }
  const named = record.family === 'token'
    ? (record.username || record.sub || '')
    : (record.subject || '');
  log.debug("Leaving subjectOf(). " + (named || '(nobody)'));
  return String(named);
}

// WHAT A TOKEN IS ADDRESSED TO is `user_graph.js`'s `audienceParties()`, and it
// was a copy of it here until 2026-08-26. Same argument as `holderOf()` and
// `detailOf()`: that file draws the same resource at the end of the same line on
// the person's picture, and two answers to *what is this token for* would be two
// pictures of one issuance on two pages of one console. The move brought two
// things this copy did not have — an `aud` naming SEVERAL resources comes back
// as several parties rather than as one box named after a joined string, and an
// audience that is this service's OWN (a refresh token's, or the `<base>/resource`
// stand-in an access token carries when nobody named a resource) is not drawn as
// a party at all.

// ---------------------------------------------------------------------------
// THE WALK. One credential in, every generation behind it out, newest first.
//
// `generations[0]` is always the credential that was asked about, whether or not
// either register still holds it — a page that answered nothing at all for an
// identifier somebody clicked would be indistinguishable from a broken link, and
// these stores are capped and drop the oldest.
// ---------------------------------------------------------------------------
function trailOf(identifier) {
  log.debug("Entering trailOf(). identifier=" + identifier);
  const wanted = String(identifier || '');
  const all = delegation.list();
  const generations = [];
  const acts = [];
  const origins = [];
  const walls = [];
  const seen = {};
  const queue = [{ identifier: wanted, depth: 0 }];
  let truncated = false;

  while (queue.length) {
    if (generations.length >= MAX_GENERATIONS) {
      truncated = true;
      log.warn('credential_graph: the lineage of "' + wanted + '" is longer ' +
               'than ' + MAX_GENERATIONS + ' generations, so the rest is not ' +
               'walked. The page says so rather than presenting the last one ' +
               'reached as the origin.');
      break;
    }
    const step = queue.shift();
    if (!step.identifier || seen[step.identifier]) {
      continue;
    }
    seen[step.identifier] = true;
    const credential = stats.issuedById(step.identifier);
    const act = producerOf(all, step.identifier);
    const consumed = consumedOf(act);
    generations.push({
      identifier: step.identifier,
      generation: step.depth,
      // Null when neither register still holds it: the delegation act names an
      // identifier and the issued register is capped separately, so a row can
      // legitimately know the credential existed and nothing else about it.
      credential: credential,
      // The act that produced it, or null — which is what makes this row the
      // origin rather than a hop.
      act: act,
      producedByExchange: !!act,
      consumed: consumed.followable,
      opaque: consumed.opaque
    });
    if (!act) {
      origins.push(step.identifier);
      continue;
    }
    acts.push(act);
    consumed.opaque.forEach(function (one) {
      walls.push({ identifier: step.identifier, act: act, credential: one });
    });
    consumed.followable.forEach(function (one) {
      queue.push({ identifier: String(one.identifier), depth: step.depth + 1 });
    });
  }

  log.debug("Leaving trailOf(). " + generations.length + " generation(s), " +
            acts.length + " act(s), " + origins.length + " origin(s), " +
            walls.length + " wall(s).");
  return { generations: generations, acts: acts, origins: origins,
           walls: walls, truncated: truncated };
}

// ---------------------------------------------------------------------------
// THE PICTURE. `delegation.graph()`'s shape, extended exactly as
// `user_graph.js` extends it, so `delegation_map.js` draws this with no idea
// that it is different and the console's party and relationship tables work
// unchanged.
//
// The delegation half is `delegation.graph()` over the acts in the trail — one
// call, that function's own answer, for the reason /admin/delegation/chain gives
// about drawing a subset. What this adds is the ISSUANCE at the head of the
// line, which no act recorded and which is therefore in the other register
// entirely.
// ---------------------------------------------------------------------------
// A node from `delegation.graph()` carries that file's fields and not the four
// this one adds, so every node is put through this before anything touches them
// — the ones this file creates AND the ones the delegation half handed over. It
// is `user_graph.js`'s `normaliseNode()` and it exists for the reason that one
// does: a box that was drawn by the delegation half and is then handed a
// credential would otherwise fail on `undefined.indexOf`, which is a crash on
// exactly the interesting case (a party that both delegated and was issued
// something) and never on the boring one.
function normalise(node) {
  if (node.credentials === undefined) node.credentials = 0;
  if (!node.flows) node.flows = [];
  if (!node.kinds) node.kinds = [];
  if (node.authentications === undefined) node.authentications = 0;
  return node;
}

function graphOf(trail) {
  log.debug("Entering graphOf().");
  const graph = delegation.graph(trail.acts);
  const nodes = new Map();
  const edges = new Map();
  graph.nodes.forEach(function (node) { nodes.set(node.id, normalise(node)); });
  graph.edges.forEach(function (edge) {
    if (edge.credentials === undefined) edge.credentials = 0;
    if (!edge.protocols) edge.protocols = [];
    edges.set(edge.id, edge);
  });
  const sts = graph.nodes.filter(function (one) {
    return one.kind === 'sts';
  })[0];

  function nodeFor(id, seed) {
    log.debug("Entering nodeFor(). id=" + id);
    let node = nodes.get(id);
    if (!node) {
      node = normalise({
        id: id, kind: 'party',
        key: '', presented: '', application: '', what: '',
        roles: { initial: 0, intermediary: 0, target: 0 },
        protocols: [],
        // The DELEGATION counters, which stay at zero on a box that only ever
        // received an ordinary token. That is the honest answer rather than a
        // gap — nothing was delegated through it — and it is the same decision
        // user_graph.js makes about the same fields.
        acts: 0, issued: 0, refused: 0,
        firstAt: 0, lastAt: 0, selfTarget: false, chiefRole: ''
      });
      nodes.set(id, node);
    }
    if (seed) {
      if (seed.key && !node.key) node.key = seed.key;
      if (seed.presented && !node.presented) node.presented = seed.presented;
      if (seed.application && !node.application) node.application = seed.application;
      if (seed.chiefRole && !node.chiefRole) node.chiefRole = seed.chiefRole;
    }
    log.debug("Leaving nodeFor().");
    return node;
  }

  function edgeFor(id, seed) {
    log.debug("Entering edgeFor(). id=" + id);
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
    log.debug("Leaving edgeFor().");
    return edge;
  }

  // One credential onto an edge's produced list, folded by kind the way
  // delegation.js folds its own — same shape, so the console's edge table reads
  // both halves without knowing which register a line came from.
  function foldOnto(edge, kind, identifier) {
    log.debug("Entering foldOnto(). kind=" + kind);
    let held = edge.produced.filter(function (one) {
      return one.kind === kind;
    })[0];
    if (!held) {
      held = { kind: kind, count: 0, identifiers: [], moreIdentifiers: 0,
               notes: [] };
      edge.produced.push(held);
    }
    held.count++;
    if (identifier && held.identifiers.indexOf(identifier) < 0) {
      held.identifiers.push(identifier);
    }
    log.debug("Leaving foldOnto().");
  }

  // THE ISSUANCE AT THE HEAD OF EACH LINE. There is normally exactly one; there
  // are two when an act consumed two credentials that were themselves issued
  // separately, which is what a delegation with an actor token is.
  const issuances = [];
  trail.generations.forEach(function (row) {
    if (row.producedByExchange || !row.credential) {
      return;
    }
    const credential = row.credential;
    const flow = credential.family === 'token'
      ? userGraph.flowRow(credential.grant)
      : userGraph.artifactFlowRow(credential.kind);
    const subject = subjectOf(credential);
    const holder = userGraph.holderOf(credential);
    const holderId = holder ? stats.identityKeyOf(holder) : '';
    const personId = subject ? stats.identityKeyOf(subject) : '';
    const addressed = userGraph.audienceParties(credential.audience, credential.iss);
    issuances.push({
      identifier: row.identifier, credential: credential, flow: flow,
      subject: subject, holder: holder,
      // A LIST, because `aud` is allowed to be one. `audience` stays beside it
      // carrying the first, so `?format=json` answers the shape it always did
      // for the ordinary single-audience token rather than changing under a
      // reader who never asked for several.
      audience: addressed[0] || { identifier: '', audience: '', registered: false },
      audiences: addressed
    });

    // THE PERSON, when there is one. A client_credentials token names no
    // End-User at all, and drawing a box for one would be inventing a party.
    let person = null;
    if (personId) {
      person = nodeFor(personId, { key: personId, presented: subject,
                                   chiefRole: 'initial' });
      person.credentials++;
      if (person.kinds.indexOf(credential.kind) < 0) {
        person.kinds.push(credential.kind);
      }
    }

    // THE APPLICATION THAT HOLDS IT.
    let held = null;
    if (holderId) {
      held = nodeFor(holderId, { application: holder, chiefRole: 'target' });
      held.credentials++;
      if (held.kinds.indexOf(credential.kind) < 0) {
        held.kinds.push(credential.kind);
      }
      if (flow.protocol && held.protocols.indexOf(flow.protocol) < 0) {
        held.protocols.push(flow.protocol);
      }
      held.lastAt = Math.max(held.lastAt, credential.issuedAt || 0);
      held.firstAt = held.firstAt
        ? Math.min(held.firstAt, credential.issuedAt || 0)
        : (credential.issuedAt || 0);
    }

    // THE GRANT LINE, from the person to whoever holds it. `mode` is left empty
    // deliberately: impersonation and delegation are properties of a delegation
    // mechanism, and an authorization code grant claims neither — which is what
    // keeps this line the console's neutral indigo. user_graph.js's rule, and
    // the reason both pages draw an issuance the same way.
    if (person && held && person.id !== held.id) {
      const grantEdge = edgeFor('grant | ' + (flow.flow || flow.label) + ' | ' +
                                person.id + ' > ' + held.id, {
        from: person.id, to: held.id,
        fromRole: 'subject', toRole: 'holder',
        relation: 'issued-for',
        type: flow.flow || '', typeLabel: flow.label,
        protocol: flow.protocol, spec: flow.spec,
        mode: '', policed: false,
        subject: person.id, actor: held.id
      });
      grantEdge.credentials++;
      grantEdge.lastAt = Math.max(grantEdge.lastAt, credential.issuedAt || 0);
      grantEdge.firstAt = grantEdge.firstAt
        ? Math.min(grantEdge.firstAt, credential.issuedAt || 0)
        : (credential.issuedAt || 0);
      foldOnto(grantEdge, credential.kind, row.identifier);
      if (flow.protocol && grantEdge.protocols.indexOf(flow.protocol) < 0) {
        grantEdge.protocols.push(flow.protocol);
      }
    }

    // AND THE LINE FROM THIS SERVICE, to whoever holds it — or to the person
    // where nothing does, which is what an X509-SVID with no audience looks
    // like. Its id is the same string user_graph.js and delegation.js both use,
    // so a party that was both issued a token and asked for a delegation has ONE
    // line from the hexagon rather than two saying the same thing.
    const to = held ? held.id : (person ? person.id : '');
    if (sts && to) {
      const issuedEdge = edgeFor(' sts > ' + to, {
        from: sts.id, to: to,
        fromRole: 'issuer', toRole: 'asker',
        relation: 'issued',
        subject: '', actor: to
      });
      issuedEdge.credentials++;
      issuedEdge.lastAt = Math.max(issuedEdge.lastAt, credential.issuedAt || 0);
      issuedEdge.firstAt = issuedEdge.firstAt
        ? Math.min(issuedEdge.firstAt, credential.issuedAt || 0)
        : (credential.issuedAt || 0);
      foldOnto(issuedEdge, credential.kind, row.identifier);
      if (flow.protocol && issuedEdge.protocols.indexOf(flow.protocol) < 0) {
        issuedEdge.protocols.push(flow.protocol);
      }
      sts.credentials = (sts.credentials || 0) + 1;
    }

    // WHAT IT IS ADDRESSED TO — one line per audience. Only for the issuance at
    // the head of the line: every credential below it was produced by an act,
    // and that act already says where it went, so drawing the audience again
    // would put two boxes on this picture for one party — the failure the
    // exchange's own audience lookup exists to prevent.
    addressed.forEach(function (one) {
      const audienceId = stats.identityKeyOf(one.identifier);
      if (!audienceId || !held || audienceId === held.id) {
        return;
      }
      const resource = nodeFor(audienceId, {
        application: one.identifier, chiefRole: 'target'
      });
      resource.lastAt = Math.max(resource.lastAt, credential.issuedAt || 0);
      const reachEdge = edgeFor('addressed | ' + row.identifier + ' | ' +
                                held.id + ' > ' + audienceId, {
        from: held.id, to: audienceId,
        fromRole: 'holder', toRole: 'target',
        relation: 'reaches',
        type: flow.flow || '', typeLabel: flow.label,
        protocol: flow.protocol, spec: flow.spec,
        mode: '', policed: false,
        subject: person ? person.id : '', actor: held.id,
        // The string the token actually carries, which is not always the name of
        // the box it points at: an audience the applications registry knows is
        // drawn as that application. See audienceParties().
        audience: one.audience,
        audienceRegistered: one.registered,
        // AND WHICH OF THAT RESOURCE'S DELEGATED PERMISSIONS THE TOKEN CARRIES
        // — `user_graph.js`'s `permissionsAddressedTo()`, for the reason its
        // export comment gives: this is the same `reaches` line that file draws
        // on /admin/delegation/user, and one relationship must not be labelled
        // two ways on two pages of one console.
        //
        // Seeded whole rather than folded, because this line is keyed on the
        // CREDENTIAL: there is exactly one token behind it, so there is nothing
        // to union. An EMPTY array is the answer where the token asked for none
        // of them, and it is drawn as `default permissions` rather than as
        // nothing — see delegation_map.js.
        permissions: userGraph.permissionsAddressedTo(credential.scope, one.audience),
        scopes: String(credential.scope || '').split(/\s+/).filter(Boolean)
      });
      reachEdge.credentials++;
      reachEdge.lastAt = Math.max(reachEdge.lastAt, credential.issuedAt || 0);
      reachEdge.firstAt = reachEdge.firstAt
        ? Math.min(reachEdge.firstAt, credential.issuedAt || 0)
        : (credential.issuedAt || 0);
      foldOnto(reachEdge, credential.kind, row.identifier);
    });
  });

  graph.nodes = Array.from(nodes.values());
  graph.edges = Array.from(edges.values());
  log.debug("Leaving graphOf(). " + graph.nodes.length + " node(s), " +
            graph.edges.length + " edge(s), " + issuances.length +
            " issuance(s) at the head of the line.");
  return { graph: graph, issuances: issuances };
}

// ---------------------------------------------------------------------------
// EVERYTHING ONE PAGE NEEDS ABOUT ONE CREDENTIAL, in one call.
//
// `null` only when nothing was asked for. An identifier NEITHER register holds
// is not null and is not a 404: it is a lineage of one generation that says so,
// because these stores are capped and an old link coming back empty is the
// ordinary outcome rather than a mistake — /admin/logout's rule, which the
// delegation drill-downs already follow.
// ---------------------------------------------------------------------------
function lineageOf(identifier) {
  log.debug("Entering lineageOf(). identifier=" + identifier);
  const wanted = String(identifier == null ? '' : identifier).trim();
  if (!wanted) {
    log.debug("Leaving lineageOf(). Nothing was asked for.");
    return null;
  }
  const trail = trailOf(wanted);
  const built = graphOf(trail);
  const asked = trail.generations[0] || null;
  const out = {
    identifier: wanted,
    // The credential the reader clicked, as the issued register holds it, or
    // null when it has been dropped to that store's cap.
    credential: asked ? asked.credential : null,
    held: !!(asked && asked.credential),
    generations: trail.generations,
    acts: trail.acts,
    // The identifiers at the head of each line — normally one.
    origins: trail.origins,
    issuances: built.issuances,
    // Where a line stopped at a credential this register cannot name rather than
    // at an origin. See the second decision in the header.
    walls: trail.walls,
    truncated: trail.truncated,
    graph: built.graph,
    counts: {
      generations: trail.generations.length,
      acts: trail.acts.length,
      // How many hops of DELEGATION are behind it, which is the number the page
      // leads with: 0 means this credential was issued directly.
      exchanges: trail.generations.filter(function (row) {
        return row.producedByExchange;
      }).length,
      parties: built.graph.nodes.filter(function (node) {
        return node.kind === 'party';
      }).length
    }
  };
  log.debug("Leaving lineageOf(). " + out.counts.generations +
            " generation(s), " + out.counts.exchanges + " exchange(s), " +
            out.counts.parties + " party/parties.");
  return out;
}

module.exports = {
  MAX_GENERATIONS: MAX_GENERATIONS,
  // Exported for the console's prose and for a test that wants the walk without
  // the drawing.
  trailOf: trailOf,
  lineageOf: lineageOf
};
