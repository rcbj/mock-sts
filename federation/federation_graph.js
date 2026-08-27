'use strict';
//
// File: federation_graph.js
//
// ===========================================================================
// THE FEDERATION REGISTER OF ONE TRUST REALM, AS A GRAPH.
//
// `/admin/federation` is a TABLE: one row per relationship, each row a complete
// description of one arrangement and none of them saying anything about the
// others. That is the right shape for configuring a partner and the wrong shape
// for the question this module answers, which is *what does this realm's
// federation actually look like* — how many applications are behind that
// partner, which of them have ever used it, and what happens to somebody who
// arrives at the identity-provider side.
//
// It is a LIBRARY, like `common/user_graph.js` and `common/credential_graph.js`
// beside it: it registers no route, so its position in the require order does
// not matter and it cannot be the reason a route is missing. `admin-ui/admin.js`
// renders it at `/admin/federation/map` through `admin-ui/federation_diagram.js`;
// this file holds the model and NONE of the geometry and none of the HTML.
//
// ---------------------------------------------------------------------------
// WHY IT MAY REQUIRE `federation.js` — rule 3o's test, taken again.
//
// Rule 3o's table lists who reaches the register and why each is safe. This is a
// fifth, and it passes that test more easily than any of the four: it registers
// no route itself, so nothing about requiring it can move one, and
// `federation.js` cannot require this back — there is nothing here it wants.
//
// The console reaches THIS module rather than assembling the graph inline, for
// `delegation.js`'s reason: a picture and the tables under it must be built from
// ONE model, or the two come to disagree about what is in the picture and there
// is no way to tell that from a filter working correctly.
//
// ---------------------------------------------------------------------------
// THE PICTURE IS THREE BANDS, AND THE BANDS ARE A CLAIM ABOUT DIRECTION.
//
//     WHO ASKS                THIS REALM            WHO AUTHENTICATES
//     an application    -->                  -->    a foreign identity provider
//     a foreign SP      -->    (the realm)   -->    (the same one, when brokered)
//
// Everything on the left is a party that ARRIVES wanting somebody signed in;
// everything on the right is a party this service ASKS to do the signing in.
//
// That is why an identity-provider-side relationship is drawn pointing INTO the
// hexagon rather than out of it, which is the one thing about this model that
// looks backwards at first glance: this service asserts TO that partner, so the
// arrow "ought" to leave. It points in because THE ARROW IS THE REQUEST AND NOT
// THE ASSERTION — and once it is, the identity broker draws itself. A foreign
// service provider asking this realm to authenticate somebody, and this realm
// consuming a foreign identity provider's assertion in order to do it, is ONE
// straight left-to-right line through the hexagon. Drawn the other way it is two
// arrows leaving the same box in the same direction with nothing joining them,
// which is the picture of a broker that does not show the brokering.
//
// ---------------------------------------------------------------------------
// A PARTNER IS KEYED BY ROLE AND PEER, WHICH IS NEITHER OF THE TWO OBVIOUS
// ANSWERS.
//
// Keying every partner box by its RELATIONSHIP would draw two boxes for one
// partner the moment somebody registers two relationships to it — which is the
// ordinary way to point two applications at one identity provider under two
// attribute release policies, and the picture would say there are two partners
// where there is one.
//
// Keying by PEER ALONE is worse, in a way that is not obvious until it is drawn.
// `federation/CLAUDE.md` is emphatic that a partner this service both consumes
// from and asserts to is TWO relationships, because everything that configures
// one differs by direction. Collapsing those onto one box puts a party in both
// bands at once — it asks and it answers — and dagre resolves that by breaking
// the resulting cycle somewhere arbitrary, so the picture silently stops being
// left-to-right and nothing says it has.
//
// So the key is the PAIR. The far end of every service-provider-side
// relationship is an identity provider; the far end of every
// identity-provider-side one is a service provider; and those are two different
// parties even when they answer to one name. Two relationships in the SAME
// direction to one peer still share a box, which is the case that ruled out
// keying by relationship.
//
// `fedPeer` FALLS BACK TO `fedId`, because a relationship may be created before
// anybody has typed the partner's name in — and a half-configured relationship
// is exactly what this picture exists to make visible, so it has to be drawable.
// ===========================================================================

const { log } = require('./../common/helpers');
const realms = require('./../common/realms');
const federation = require('./federation');

// ---------------------------------------------------------------------------
// THE NODE KINDS. Four, and each is drawn differently — see
// `admin-ui/federation_diagram.js`, which reads this vocabulary and knows
// nothing else about federation.
//
//   sts          this realm. Exactly one, always present even in an empty
//                register, because "this realm federates with nobody" is an
//                answer and a blank page is not.
//   application  a party at THIS end whose people are authenticated somewhere
//                else. An entry under ou=applications.
//   partner-sp   a FOREIGN SERVICE PROVIDER: the far end of an
//                identity-provider-side relationship. It asks, so it is on the
//                left.
//   partner-idp  a FOREIGN IDENTITY PROVIDER: the far end of a
//                service-provider-side relationship. It answers, so it is on
//                the right.
// ---------------------------------------------------------------------------
const STS_ID = 'sts';

function partyId(kind, name) {
  return kind + ':' + String(name);
}

// THE KEY FOR "THIS PARTY, BROKERED THROUGH THAT RELATIONSHIP", and it is
// JSON rather than the two strings joined by a separator. Both halves are
// values somebody typed — an application identifier and a relationship id —
// so any separator they are allowed to contain makes two different pairs
// collide: `("a b", "c")` and `("a", "b c")` are one key under a space, and
// `federation.js` has already had to state what it does about a pipe in an
// identifier. Two elements of an array cannot run together, whatever is in
// them.
function brokerKey(application, relationship) {
  return JSON.stringify([String(application), String(relationship)]);
}

// ---------------------------------------------------------------------------
// ONE RELATIONSHIP, WITH EVERYTHING THE PICTURE AND THE TABLES UNDER IT NEED.
//
// It is deliberately a SUPERSET of `admin.js`'s `federationRow()` rather than a
// second, smaller version of it: that function answers the list page and this
// one answers the map, and every field they share is computed by the same two
// calls into the register (`readinessOf`, `isEnabled`) so the two pages cannot
// disagree about whether a partner is usable. What this adds is the two things a
// table row has no room for — who is configured to use it, and what a person
// arriving at the identity-provider side actually meets.
// ---------------------------------------------------------------------------
function describe(record) {
  log.debug('Entering describe(). id=' + record.fedId);
  const readiness = federation.readinessOf(record);
  const protocolRow = federation.protocolRow(record.fedProtocol) || {};
  const roleRow = federation.roleRow(record.fedRole) || {};
  const mechanismId = String(record.fedAuthnMechanism || '').trim();
  const mechanismRow = mechanismId ? federation.mechanismRow(mechanismId) : null;
  const row = {
    id: record.fedId,
    name: record.fedName || record.fedId,
    role: record.fedRole,
    roleLabel: roleRow.short || record.fedRole,
    protocol: record.fedProtocol,
    protocolLabel: protocolRow.label || record.fedProtocol,
    peer: record.fedPeer || '',
    application: record.fedApplication || '',
    enabled: federation.isEnabled(record),
    ready: readiness.ready,
    missing: readiness.missing,
    usable: federation.isEnabled(record) && readiness.ready,
    authentications: parseInt(record.fedAuthentications, 10) || 0,
    users: parseInt(record.fedUsers, 10) || 0,
    lastUser: record.fedLastUser || '',
    lastSeen: record.fedLastSeen || '',
    lastError: record.fedLastError || '',
    lastErrorAt: record.fedLastErrorAt || '',
    // ---------------------------------------------------------------------
    // WHAT THE IDENTITY-PROVIDER SIDE IS CONFIGURED TO DO ABOUT AUTHENTICATING
    // SOMEBODY, which is the half of this feature no table has ever shown.
    //
    // FOUR STATES AND NOT THREE, and the fourth is the important one:
    //
    //   * a mechanism this service has        password, password-mfa, webauthn
    //   * `federation`                        THE BROKER CASE, which names an
    //                                         onward service-provider-side
    //                                         relationship
    //   * a mechanism that is not one of ours somebody typed something, and the
    //                                         relationship will refuse
    //   * NOTHING AT ALL                      and this is not "unknown". It is a
    //                                         decision with a name: the sign-in
    //                                         screen, which checks no password.
    //                                         Every relationship created before
    //                                         the attribute existed is in this
    //                                         state, so a picture that left it
    //                                         blank would be hiding the
    //                                         commonest answer there is.
    //
    // `authenticationFor()` resolves all four and this reads its answer rather
    // than deriving a second one, so the picture and the sign-in path cannot
    // come to disagree about what a relationship will do.
    // ---------------------------------------------------------------------
    mechanism: mechanismId,
    mechanismLabel: mechanismRow ? mechanismRow.label
      : (mechanismId
           ? mechanismId + ' — not a mechanism this service has'
           : 'The sign-in screen, which checks no password'),
    mechanismKnown: !!mechanismRow || !mechanismId,
    mechanismConfigured: !!mechanismId,
    brokersTo: '',
    brokerUsable: false,
    brokerProblem: '',
    // Filled by graph() when the ONWARD relationship is drawn — see there. It
    // is declared here so that every row carries the field whether or not it is
    // brokered: a caller reading the JSON should not have to tell an absent
    // member from a zero.
    brokeredUse: null,
    releases: (record.fedRelease || []).slice(0),
    dn: record.dn || ''
  };
  if (record.fedRole === 'identity-provider') {
    const resolved = federation.authenticationFor(record);
    if (resolved) {
      row.brokerProblem = resolved.problem || '';
      if (resolved.mechanism === 'federation') {
        // `onward` is the id it NAMES; `relationship` is null when that id names
        // nothing usable. BOTH are kept, because the picture has to draw the
        // intent even when it cannot draw the destination — a broker pointing at
        // a disabled partner otherwise looks exactly like one configured to use
        // the sign-in screen, which is the fallback the whole feature is careful
        // about.
        row.brokersTo = resolved.onward ||
                        String(record.fedAuthnRelationship || '').trim();
        row.brokerUsable = !!resolved.relationship;
      }
    }
  }
  log.debug('Leaving describe(). ' + row.id + ', ' + row.roleLabel + '.');
  return row;
}

// ---------------------------------------------------------------------------
// WHAT HAS CROSSED A RELATIONSHIP, PER APPLICATION, JOINED TO WHAT IS
// CONFIGURED TO CROSS IT.
//
// TWO SOURCES AND A FULL OUTER JOIN, and each of the three resulting states is
// something somebody needs to see:
//
//   * CONFIGURED AND USED         the ordinary case, and the number the picture
//                                 was asked for.
//   * CONFIGURED, NEVER USED      an application pointed at a partner that has
//                                 never authenticated anybody for it. This is
//                                 what a federation somebody set up last week
//                                 and has not tested looks like, and it is
//                                 invisible in every existing count in this
//                                 service, because every existing count is of
//                                 things that happened.
//   * USED, NO LONGER CONFIGURED  somebody edited `appFederationRelationship`
//                                 afterwards. The sign-ins still happened, so
//                                 they are still shown — flagged rather than
//                                 dropped, because a count that vanished when a
//                                 pointer was removed would leave the totals on
//                                 this page not adding up with nothing to say
//                                 why.
//
// The join is on the application identifier in the PACKED spelling
// `federation.js` files a row under, which is why both halves come from that
// module rather than one of them being re-derived here: the substitution rule
// belongs to whoever writes the attribute.
// ---------------------------------------------------------------------------
function applicationRows(record, row) {
  log.debug('Entering applicationRows(). id=' + row.id);
  // Only the service-provider side has a per-application split. See the schema
  // row for `fedApplicationUse`: an identity-provider-side relationship names
  // exactly ONE application, so its per-application count IS its own count and a
  // second list holding the same number is the copy that comes to disagree.
  if (row.role !== 'service-provider') {
    log.debug('Leaving applicationRows(). Not the service-provider side.');
    return [];
  }
  const byName = new Map();
  federation.applicationsUsing(row.id).forEach(function (one) {
    byName.set(one.application, {
      application: one.application,
      source: one.source, via: one.via || '',
      configured: true,
      authentications: 0, users: 0, lastUser: '', lastSeen: ''
    });
  });
  federation.applicationUse(record).forEach(function (use) {
    const existing = byName.get(use.application);
    if (existing) {
      existing.authentications = use.authentications;
      existing.users = use.users;
      existing.lastUser = use.lastUser;
      existing.lastSeen = use.lastSeen;
      return;
    }
    byName.set(use.application, {
      application: use.application, source: '', via: '',
      configured: false,
      authentications: use.authentications, users: use.users,
      lastUser: use.lastUser, lastSeen: use.lastSeen
    });
  });
  const rows = Array.from(byName.values());
  // Busiest first, then by name — the order `applicationUse()` already returns,
  // restated here rather than inherited because this list has members that one
  // does not and a half-sorted list is worse than an unsorted one.
  rows.sort(function (a, b) {
    if (b.authentications !== a.authentications) {
      return b.authentications - a.authentications;
    }
    return a.application < b.application ? -1 : a.application > b.application ? 1 : 0;
  });
  log.debug('Leaving applicationRows(). ' + rows.length + ' application(s).');
  return rows;
}

// ---------------------------------------------------------------------------
// THE GRAPH.
//
// `wanted` narrows it, and it narrows the WHOLE model rather than the drawing:
// the tables under the picture are built from what this returns, so a filter
// that hid boxes and left the rows standing would be two answers to one
// question. The three filters are the list page's own — role, protocol and a
// text match — because narrowing the table and narrowing the picture has to be
// one control rather than two that can take different values.
//
// IT MUST NOT THROW ON AN EMPTY REGISTER. A realm with no federation configured
// is the ordinary state of this service, and it comes back as the hexagon alone
// with `empty: true` — which is what lets the page say *this realm federates
// with nobody* instead of drawing an empty rectangle and leaving somebody to
// wonder whether the drawing failed.
// ---------------------------------------------------------------------------
function graph(wanted) {
  log.debug('Entering graph().');
  const want = wanted || {};
  const wantedRole = String(want.role || '').trim();
  const wantedProtocol = String(want.protocol || '').trim();
  const wantedText = String(want.q || '').trim().toLowerCase();

  const realm = realms.current();
  const records = federation.list();
  const rows = [];
  records.forEach(function (record) {
    const row = describe(record);
    if (wantedRole && row.role !== wantedRole) return;
    if (wantedProtocol && row.protocol !== wantedProtocol) return;
    if (wantedText) {
      const hay = (row.id + ' ' + row.name + ' ' + row.peer + ' ' +
                   row.application + ' ' + row.protocolLabel).toLowerCase();
      if (hay.indexOf(wantedText) < 0) return;
    }
    row.applications = applicationRows(record, row);
    row.applicationCount = row.applications.filter(function (one) {
      return one.configured;
    }).length;
    // -------------------------------------------------------------------
    // THE SIGN-INS THIS RELATIONSHIP COUNTED THAT NO APPLICATION ROW CLAIMS,
    // AND IT IS REPORTED RATHER THAN LEFT TO BE NOTICED.
    //
    // `fedAuthentications` counts every credential that crossed the
    // relationship. `fedApplicationUse` counts only the ones that named an
    // application this service is CONFIGURED for. So the two do not have to
    // agree, and there are three ordinary reasons they will not:
    //
    //   * somebody used the generic partner buttons at the foot of the sign-in
    //     screen, which offer every usable relationship and belong to no
    //     application;
    //   * somebody reached `/federation/login/{id}` directly, which needs no
    //     configuration at all to reach;
    //   * a sign-in named an application that is not configured for this
    //     relationship, which recordUse() refuses to file and logs.
    //
    // None of those is a fault, and every one of them makes a column of
    // per-application numbers add up to less than the total two columns to its
    // left. A reader who spots that and cannot account for it has found a
    // discrepancy in a page about counting, so the difference is a FIGURE with
    // a name rather than an absence.
    //
    // CLAMPED AT ZERO. These are attributes in a directory and `ldapmodify` is
    // a door onto them like any other, so `fedAuthentications` can be edited
    // down below the sum of the rows underneath it. A negative here would be a
    // second wrong number reported as confidently as the first.
    // -------------------------------------------------------------------
    const attributed = row.applications.reduce(function (n, one) {
      return n + one.authentications;
    }, 0);
    row.attributed = attributed;
    row.unattributed = Math.max(0, row.authentications - attributed);
    rows.push(row);
  });

  const nodes = [];
  const edges = [];
  const nodeById = new Map();
  const addNode = function (node) {
    if (nodeById.has(node.id)) {
      return nodeById.get(node.id);
    }
    nodeById.set(node.id, node);
    nodes.push(node);
    return node;
  };

  // THE HEXAGON, ALWAYS, AND IT CARRIES THE REALM. See the header: an empty
  // register is an answer, and a realm is a whole logical copy of this service
  // so the picture of one realm is not the picture of another. It is the same
  // decision `delegation_map.js` made about its own hexagon, and for the same
  // reason.
  addNode({
    id: STS_ID, kind: 'sts',
    label: 'This service',
    realm: realm.id,
    realmName: realm.name || realm.id
  });

  // ---------------------------------------------------------------------
  // THE IDENTITY-PROVIDER SIDE FIRST, AND THE ORDER IS LOAD-BEARING RATHER
  // THAN TIDY.
  //
  // A brokered application is reported by `federation.applicationsUsing()` as an
  // application of the ONWARD service-provider-side relationship as well — which
  // is correct, because its people really are authenticated there. Drawing both
  // would put two arrows between the same pair of boxes saying two true things
  // that a reader reads as one thing said twice.
  //
  // So the identity-provider side is drawn first and remembers which (party,
  // onward relationship) pairs it has covered, and the loop below skips exactly
  // those — carrying the COUNTS onto the arrow that was drawn rather than losing
  // them, because they are that pair's counts wherever the arrow ends up.
  // ---------------------------------------------------------------------
  const brokered = new Map();
  rows.filter(function (row) { return row.role === 'identity-provider'; })
      .forEach(function (row) {
    // `fedApplication` FIRST when it is set, because that is the name THIS
    // SERVICE knows the partner by — the same string that appears on
    // /admin/applications, in an audience and in a client_id. A box labelled
    // with the partner's own entityID sitting beside a registry that files it
    // under something else is two names for one party, on a page whose whole
    // job is to join them up.
    const name = row.application || row.peer || row.id;
    const id = partyId('partner-sp', name);
    const node = addNode({
      id: id, kind: 'partner-sp', label: name,
      application: row.application || '', peer: row.peer || '',
      relationships: []
    });
    node.relationships.push(row.id);
    const edge = {
      id: 'idp:' + row.id, from: id, to: STS_ID,
      relation: 'asks', relationship: row.id, row: row, use: null,
      brokeredTo: ''
    };
    edges.push(edge);
    if (row.brokersTo) {
      brokered.set(brokerKey(name, row.brokersTo), edge);
    }
  });

  rows.filter(function (row) { return row.role === 'service-provider'; })
      .forEach(function (row) {
    const name = row.peer || row.id;
    const id = partyId('partner-idp', name);
    const node = addNode({
      id: id, kind: 'partner-idp', label: name,
      peer: row.peer || '', relationships: []
    });
    node.relationships.push(row.id);
    edges.push({
      id: 'sp:' + row.id, from: STS_ID, to: id,
      relation: 'consumes', relationship: row.id, row: row
    });
    row.applications.forEach(function (use) {
      const owner = brokered.get(brokerKey(use.application, row.id));
      if (owner) {
        owner.use = use;
        owner.brokeredTo = row.id;
        // AND ONTO THE IDENTITY-PROVIDER-SIDE ROW ITSELF, because that row's
        // own counters are structurally zero and always will be: nothing
        // increments `fedAuthentications` on this side, since what it counts is
        // assertions CONSUMED and this side ISSUES them
        // (`federation/CLAUDE.md`, "What it deliberately does not do"). A table
        // printing a bare 0 there asserts that nobody has ever signed in for
        // this partner, which for a brokered one is false — the sign-ins
        // happened and were counted against the relationship they went
        // THROUGH. This is the only route by which the identity-provider side
        // can report a real number, so it goes on the ROW as well as on the
        // edge rather than being left for whichever of the two happens to be
        // rendered.
        owner.row.brokeredUse = use;
        return;
      }
      const partyNodeId = partyId('application', use.application);
      addNode({
        id: partyNodeId, kind: 'application', label: use.application,
        relationships: []
      }).relationships.push(row.id);
      edges.push({
        id: 'use:' + row.id + ':' + use.application,
        from: partyNodeId, to: STS_ID,
        relation: 'signs-in', relationship: row.id, row: row, use: use
      });
    });
  });

  const result = {
    realm: { id: realm.id, name: realm.name || realm.id,
             isDefault: realms.isDefault(realm) },
    nodes: nodes, edges: edges, relationships: rows,
    // `empty` is about the REGISTER and not about the filter, so that a page can
    // tell "nothing is configured" from "nothing matches". Two states, two
    // different things to say, and only one of them is a problem.
    empty: records.length === 0,
    filtered: records.length !== rows.length,
    counts: {
      relationships: rows.length,
      serviceProvider: rows.filter(function (r) {
        return r.role === 'service-provider';
      }).length,
      identityProvider: rows.filter(function (r) {
        return r.role === 'identity-provider';
      }).length,
      usable: rows.filter(function (r) { return r.usable; }).length,
      applications: nodes.filter(function (n) {
        return n.kind === 'application';
      }).length,
      partners: nodes.filter(function (n) {
        return n.kind === 'partner-sp' || n.kind === 'partner-idp';
      }).length,
      authentications: rows.reduce(function (n, r) {
        return n + r.authentications;
      }, 0)
    }
  };
  log.debug('Leaving graph(). ' + nodes.length + ' box(es), ' + edges.length +
            ' line(s), ' + rows.length + ' relationship(s).');
  return result;
}

module.exports = {
  STS_ID: STS_ID,
  graph: graph,
  // Exported for the relationship drill-down on /admin/federation, which shows
  // ONE relationship and reads it through the same describe() the whole picture
  // uses rather than making a second reading of the same entry.
  describe: describe
};
