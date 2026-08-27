'use strict';
//
// File: federation_map_bands.js
//
// ===========================================================================
// THE FEDERATION PICTURE IS THREE BANDS, THE BROKER IS ONE LINE, AND THE
// PER-APPLICATION COUNTS ADD UP OR SAY WHY THEY DO NOT.
//
// `/admin/federation/map` makes exactly one geometric claim and everything a
// reader takes off it rests on that claim being true: **everything to the LEFT
// of the hexagon arrives wanting somebody signed in, and everything to the
// RIGHT is a party this service asks to do the signing in.** An
// identity-provider-side relationship is therefore drawn pointing INTO the
// hexagon even though this service asserts outward, because the arrow is the
// REQUEST — and it is that inversion that turns an identity broker into one
// straight left-to-right line instead of two arrows leaving the same box.
//
// NONE OF THAT FAILS LOUDLY. Reverse the arrow on the identity-provider side
// and the picture still draws, every box is still there, every label still
// says something true — and a broker silently stops being a chain. Put a
// partner in the wrong band and the page is still a page. That is the whole
// reason for this file, and it is `delegation_map_bands.js`'s reason next door.
//
// WHY IN PROCESS, WHICH IS THE QUESTION tests/CLAUDE.md ASKS FIRST. Two
// answers, and they are different for the two halves:
//
//   * THE DRAWING is a pure function from a graph to an SVG document — no
//     store, no config, no request — so the cases worth asserting are ones the
//     running service cannot be made to produce on demand. A relationship in
//     each of the four states at once, a broker whose onward partner is
//     disabled, a pair counted and then un-configured: reaching those over HTTP
//     means driving federation traffic until the register happens to hold the
//     right shape. The parsing is the same either way; what cannot be done over
//     there is CHOOSING the graph.
//   * THE MODEL's interesting assertions are about arithmetic that a page
//     ROUNDS OFF. "The per-application rows add up to less than the
//     relationship's own total, by exactly the number of sign-ins that named no
//     configured application" is a statement about two registers, and the only
//     way to see it over HTTP is to have already trusted the number being
//     checked.
//
// IT ASSERTS GEOMETRY AND ARITHMETIC RATHER THAN MARKUP. Everything below reads
// numbers off the emitted SVG or off the graph, and none of it names a colour
// by value, an attribute order or a class. A rewrite of how a box is drawn must
// not fail this file; a rewrite that puts a partner in the wrong band, draws a
// broker twice, or loses a brokered pair's counts must.
// ===========================================================================

// Deleted rather than set, for the reason config_realm_layer.js gives: nothing
// here should depend on a developer's exported appconfig.
delete process.env.CONFIG_FILE;

const diagram = require('../admin-ui/federation_diagram');
// `ldap_server.js` is what fills `federation.js`'s directory slot — ou=federations
// IS the store and there is deliberately no fallback Map — so the model half
// below cannot run without it. Requiring it here registers the `/ldap` routes,
// which costs nothing in a test that never listens.
require('../ldap/ldap_server');
const federation = require('../federation/federation');
const federationGraph = require('../federation/federation_graph');
const applications = require('../common/applications');

// ---------------------------------------------------------------------------
// READING THE PICTURE BACK.
//
// A NODE is a rect or a hexagon path, each preceded by the `<title>` carrying
// its tooltip — so a box is found by the text of its own label, which is the
// one thing about a box this file is allowed to know. A LINE is a `<path>` with
// a `marker-end`, which is the only shape in the document that has one.
// ---------------------------------------------------------------------------
function boxes(svg) {
  const out = [];
  // `<title>…</title>` then either a rect (x/y/width/height) or a hexagon path
  // whose first two numbers are its left inset and its top.
  const re = /<title>([^<]*)<\/title>(?:<rect x="([-\d.]+)" y="([-\d.]+)" width="([\d.]+)" height="([\d.]+)"|<path d="M([\d.]+) ([\d.]+)H([\d.]+)L([\d.]+) ([\d.]+)L)/g;
  let m = re.exec(svg);
  while (m) {
    if (m[2] !== undefined) {
      out.push({ title: m[1], shape: 'rect', left: Number(m[2]),
                 right: Number(m[2]) + Number(m[4]),
                 mid: Number(m[2]) + Number(m[4]) / 2 });
    } else if (m[6] !== undefined) {
      // hexPath: M x+cut y H x+w-cut L x+w y+h/2 …  — so the right edge is the
      // fourth number and the left edge is not directly quoted. The MIDPOINT is
      // what every assertion below uses, and it is the mean of the two
      // horizontal extremes of the flat top, which is symmetric about the
      // centre by construction.
      out.push({ title: m[1], shape: 'hexagon',
                 left: Number(m[6]), right: Number(m[9]),
                 mid: (Number(m[6]) + Number(m[8])) / 2 });
    }
    m = re.exec(svg);
  }
  return out;
}

function lines(svg) {
  const out = [];
  const re = /<path d="([^"]+)" fill="none" stroke="([^"]+)"[^>]*marker-end/g;
  let m = re.exec(svg);
  while (m) {
    const points = m[1].split(/[ML]/).filter(Boolean).map(function (pair) {
      const xy = pair.trim().split(/\s+/);
      return { x: Number(xy[0]), y: Number(xy[1]) };
    });
    out.push({ d: m[1], stroke: m[2],
               from: points[0], to: points[points.length - 1] });
    m = re.exec(svg);
  }
  return out;
}

function boxNamed(svg, text) {
  return boxes(svg).filter(function (one) {
    return one.title.indexOf(text) >= 0;
  })[0] || null;
}

// ---------------------------------------------------------------------------
// A relationship record in whatever state the assertion needs, built by hand
// rather than through `federation.create()` — the state matters and the
// creation path deliberately refuses most of them (everything is created
// disabled and half of it is not settable at create). This is the register's
// own record shape, which is what `describe()` reads.
// ---------------------------------------------------------------------------
function relationship(over) {
  return Object.assign({
    fedId: 'r', fedName: '', fedRole: 'service-provider', fedProtocol: 'saml2',
    fedPeer: 'https://partner.example', fedApplication: '',
    fedEnabled: 'TRUE', fedSsoUrl: 'https://partner.example/sso',
    fedSigningCertificate: '-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----',
    fedAuthentications: '0', fedUsers: '0', fedLastUser: '', fedLastSeen: '',
    fedLastError: '', fedLastErrorAt: '', fedRelease: [],
    fedAuthnMechanism: '', fedAuthnRelationship: '', fedApplicationUse: []
  }, over || {});
}

function render(nodes, edges) {
  return diagram.render({ nodes: nodes, edges: edges },
                        { links: false, id: 't', label: 'test' });
}

module.exports = {
  name: 'federation_map_bands',
  describe: 'the federation picture is three bands, a broker is one line, ' +
            'and the per-application counts account for themselves',
  run: function (t) {

    // -------------------------------------------------------------------
    // 1. THE THREE BANDS.
    //
    // The graph is the ordinary shape: an application and a foreign service
    // provider both arriving, and a foreign identity provider being asked. The
    // claim is only about ORDER along x, never about a coordinate, so this
    // stays true if every metric in the file changes.
    // -------------------------------------------------------------------
    t.log.info('the three bands');
    const spRow = federationGraph.describe(relationship({ fedId: 'consume' }));
    spRow.applicationCount = 1;
    const idpRow = federationGraph.describe(relationship({
      fedId: 'assert', fedRole: 'identity-provider',
      fedApplication: 'partner-app', fedPeer: 'https://sp.example'
    }));

    const bands = render(
      [{ id: 'sts', kind: 'sts', label: 'This service', realm: 'default',
         realmName: 'Default' },
       { id: 'a', kind: 'application', label: 'webapp', relationships: [] },
       { id: 'p', kind: 'partner-sp', label: 'partner-app', relationships: [],
         application: 'partner-app', peer: 'https://sp.example' },
       { id: 'q', kind: 'partner-idp', label: 'far-idp', relationships: [],
         peer: 'far-idp' }],
      [{ id: 'e1', from: 'a', to: 'sts', relation: 'signs-in',
         relationship: 'consume', row: spRow, use: null },
       { id: 'e2', from: 'p', to: 'sts', relation: 'asks',
         relationship: 'assert', row: idpRow, use: null },
       { id: 'e3', from: 'sts', to: 'q', relation: 'consumes',
         relationship: 'consume', row: spRow }]);

    t.check(!bands.failed, 'the picture draws at all', bands.failed);
    const hex = boxNamed(bands.svg, 'in the trust realm');
    const app = boxNamed(bands.svg, 'An application registered in this realm');
    const fsp = boxNamed(bands.svg, 'A FOREIGN SERVICE PROVIDER');
    const fidp = boxNamed(bands.svg, 'A FOREIGN IDENTITY PROVIDER');
    t.check(hex && app && fsp && fidp, 'all four boxes are drawn',
            'hexagon=' + !!hex + ' application=' + !!app +
            ' partner-sp=' + !!fsp + ' partner-idp=' + !!fidp);

    if (hex && app && fsp && fidp) {
      // WHO ASKS IS LEFT. Both of them, and the foreign service provider is
      // the one that would move if somebody "fixed" the arrow direction — an
      // identity-provider-side relationship asserts OUTWARD, so the tempting
      // edge is sts -> partner, which puts this box on the right.
      t.check(app.right < hex.left,
              'an application is left of the hexagon',
              'application right edge ' + app.right + ', hexagon left ' + hex.left);
      t.check(fsp.right < hex.left,
              'a FOREIGN SERVICE PROVIDER is left of the hexagon — it asks, ' +
              'even though this service asserts to it',
              'partner-sp right edge ' + fsp.right + ', hexagon left ' + hex.left);
      // WHO AUTHENTICATES IS RIGHT.
      t.check(fidp.left > hex.right,
              'a FOREIGN IDENTITY PROVIDER is right of the hexagon',
              'partner-idp left edge ' + fidp.left + ', hexagon right ' + hex.right);
    }

    // Every line runs left to right, which is the same claim read off the
    // ARROWS rather than off the boxes — and it is the half that catches an
    // edge whose ends were swapped in the model while the layout still put the
    // boxes in the right bands.
    const drawn = lines(bands.svg);
    t.equal(drawn.length, 3, 'three lines are drawn');
    const backwards = drawn.filter(function (one) { return one.to.x <= one.from.x; });
    t.equal(backwards.length, 0,
            'every arrow points rightward — nothing asks from the right or ' +
            'answers from the left',
            backwards.map(function (one) { return one.d; }).join(' | '));

    // -------------------------------------------------------------------
    // 2. THE FOUR STATES ARE FOUR DIFFERENT STROKES.
    //
    // Asserted as "all different" rather than by naming a colour, so that
    // repainting the console cannot fail this file — what must not happen is
    // two states becoming indistinguishable, which is how "ENABLED and NOT
    // configured" comes to look like "ready".
    // -------------------------------------------------------------------
    t.log.info('the four states are told apart');
    const states = {
      ready: relationship({ fedId: 'ready' }),
      disabled: relationship({ fedId: 'disabled', fedEnabled: 'FALSE' }),
      half: relationship({ fedId: 'half', fedSigningCertificate: '' }),
      broker: relationship({ fedId: 'broker', fedRole: 'identity-provider',
                             fedApplication: 'app',
                             fedAuthnMechanism: 'federation',
                             fedAuthnRelationship: 'nothing-of-that-name' })
    };
    const strokes = {};
    Object.keys(states).forEach(function (key) {
      const row = federationGraph.describe(states[key]);
      const one = render(
        [{ id: 'x', kind: 'application', label: 'x', relationships: [] },
         { id: 'sts', kind: 'sts', label: 's', realm: '', realmName: '' }],
        [{ id: 'e', from: 'x', to: 'sts',
           relation: key === 'broker' ? 'asks' : 'signs-in',
           relationship: row.id, row: row, use: null }]);
      const line = lines(one.svg)[0];
      strokes[key] = line ? line.stroke : '(no line)';
    });
    const distinct = Object.keys(strokes).map(function (k) { return strokes[k]; })
      .filter(function (v, i, all) { return all.indexOf(v) === i; });
    t.equal(distinct.length, 4,
            'ready, disabled, enabled-but-unconfigured and a broker that ' +
            'cannot broker are four distinguishable strokes',
            JSON.stringify(strokes));

    // -------------------------------------------------------------------
    // 3. THE MODEL: A BROKER IS ONE LINE, AND THE PAIR'S COUNTS SURVIVE IT.
    //
    // `applicationsUsing()` reports a brokered application as an application of
    // the ONWARD relationship too — correctly, because its people really are
    // authenticated there. The graph must not therefore draw two arrows between
    // the same pair of boxes saying two true things a reader reads as one thing
    // said twice; and collapsing them must not throw the counts away, which is
    // the failure that would look like a working picture with a zero on it.
    // -------------------------------------------------------------------
    t.log.info('a broker is one line and keeps its counts');
    const made = [];
    const make = function (info) {
      const result = federation.create(info);
      if (!result.ok) {
        throw new Error('could not create ' + info.id + ': ' +
                        result.errors.join(' '));
      }
      made.push(info.id);
    };
    const set = function (id, field, value) {
      const result = federation.update(id, { field: field, value: value });
      if (!result.ok) {
        throw new Error('could not set ' + field + ' on ' + id + ': ' +
                        result.errors.join(' '));
      }
    };

    make({ id: 'fmb-upstream', role: 'service-provider', protocol: 'saml2',
           peer: 'https://upstream.example' });
    set('fmb-upstream', 'fedSsoUrl', 'https://upstream.example/sso');
    set('fmb-upstream', 'fedSigningCertificate',
        '-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----');
    set('fmb-upstream', 'fedEnabled', 'TRUE');

    make({ id: 'fmb-broker', role: 'identity-provider', protocol: 'oidc',
           peer: 'https://sp.example', application: 'fmb-partner-app' });
    set('fmb-broker', 'fedAuthnMechanism', 'federation');
    set('fmb-broker', 'fedAuthnRelationship', 'fmb-upstream');
    set('fmb-broker', 'fedEnabled', 'TRUE');

    // Two sign-ins for the brokered partner, and one for an application that
    // names the relationship on its own entry — so the assertions below can
    // tell the two routes apart.
    // BOTH RESULTS ARE CHECKED, and that is not belt-and-braces: the first
    // version of this file passed `field:` where updateApplication() reads
    // `attribute:`, so the pointer was never written, three assertions below
    // failed with plausible-looking numbers, and the call itself said nothing.
    // A fixture that silently does not happen is the one failure mode a test
    // cannot tell from the thing it is testing being broken.
    const created = applications.createApplication({ identifier: 'fmb-webapp',
                                                     kind: 'oidc-relying-party' });
    t.check(created.ok !== false, 'the fixture application was created',
            JSON.stringify(created.errors || []));
    const pointed = applications.updateApplication('fmb-webapp',
      { attribute: 'appFederationRelationship', value: 'fmb-upstream',
        mode: 'add' });
    t.check(pointed.ok !== false,
            'and pointed at the relationship through its own entry',
            JSON.stringify(pointed.errors || []));

    federation.recordUse('fmb-upstream', { user: 'alice',
                                           application: 'fmb-partner-app' });
    federation.recordUse('fmb-upstream', { user: 'bob',
                                           application: 'fmb-partner-app' });
    federation.recordUse('fmb-upstream', { user: 'carol',
                                           application: 'fmb-webapp' });
    // AND ONE THAT NAMES NOTHING, which is what somebody pressing a partner
    // button on the sign-in screen produces. It must move the relationship's
    // own total and no application row.
    federation.recordUse('fmb-upstream', { user: 'dave' });

    const graph = federationGraph.graph({ q: 'fmb-' });
    const upstream = graph.relationships.filter(function (r) {
      return r.id === 'fmb-upstream';
    })[0];
    const broker = graph.relationships.filter(function (r) {
      return r.id === 'fmb-broker';
    })[0];

    t.check(!!upstream && !!broker, 'both relationships are in the graph');

    if (upstream && broker) {
      // ONE ARROW for the brokered partner, not two.
      const partnerId = 'partner-sp:fmb-partner-app';
      const fromPartner = graph.edges.filter(function (e) {
        return e.from === partnerId;
      });
      t.equal(fromPartner.length, 1,
              'a brokered partner has ONE arrow into the hexagon, not one per ' +
              'relationship that describes it',
              fromPartner.map(function (e) { return e.id + '/' + e.relation; }).join(', '));
      t.equal((fromPartner[0] || {}).relation, 'asks',
              'and it is the identity-provider side\'s arrow — the one that ' +
              'names the relationship that brokered it');
      t.equal((fromPartner[0] || {}).brokeredTo, 'fmb-upstream',
              'which records where it was brokered to');

      // THE COUNTS SURVIVED the collapse, on the edge AND on the row.
      const use = (fromPartner[0] || {}).use || {};
      t.equal(use.authentications, 2,
              'the brokered pair\'s sign-ins are carried onto that arrow ' +
              'rather than lost with the edge that was not drawn');
      t.equal(use.users, 2, 'and its people');
      t.equal((broker.brokeredUse || {}).authentications, 2,
              'and onto the identity-provider-side ROW, which is the only ' +
              'number that side can ever report — nothing increments its own ' +
              'counters');
      t.equal(broker.authentications, 0,
              'while its own counter stays zero, as it always has: what it ' +
              'counts is assertions CONSUMED and this side issues them');

      // NO SECOND APPLICATION BOX for the brokered partner: it is the
      // partner-sp box and drawing it again as an `application` would be the
      // same party twice under two shapes.
      const appBoxes = graph.nodes.filter(function (n) {
        return n.kind === 'application' && n.label === 'fmb-partner-app';
      });
      t.equal(appBoxes.length, 0,
              'the brokered partner is not ALSO drawn as a local application — ' +
              'one party, one box');

      // THE ARITHMETIC. Four sign-ins crossed the relationship; three named a
      // configured application; one named none.
      t.equal(upstream.authentications, 4,
              'the relationship counted every sign-in that crossed it');
      t.equal(upstream.attributed, 3,
              'three of them named an application this service is configured for');
      t.equal(upstream.unattributed, 1,
              'and the remainder is REPORTED rather than left as a column that ' +
              'does not add up');
      t.equal(upstream.applicationCount, 2,
              'two applications are configured to use it — one through its own ' +
              'entry and one through the relationship brokering to it');
    }

    // -------------------------------------------------------------------
    // 4. AN UNCONFIGURED PAIR IS REFUSED A ROW.
    //
    // `application` reaches recordUse() from a query parameter on
    // /federation/login/{id}, which — alone in that module — needs no
    // configuration at all to reach. So the check is what stops anybody who can
    // reach the port growing an attribute on the one entry whose contents
    // decide whether an assertion is refused. It is the security-shaped half of
    // this feature and it must not be quietly relaxed into trusting the caller.
    // -------------------------------------------------------------------
    t.log.info('a pair this service is not configured for gets no row');
    federation.recordUse('fmb-upstream', { user: 'mallory',
                                           application: 'not-configured-at-all' });
    const after = federationGraph.graph({ q: 'fmb-upstream' }).relationships[0];
    const invented = (after.applications || []).filter(function (one) {
      return one.application === 'not-configured-at-all';
    });
    t.equal(invented.length, 0,
            'an application nothing names got no per-application row, however ' +
            'insistently the request named it');
    t.equal(after.authentications, 5,
            'while the relationship\'s own total still moved — the sign-in ' +
            'happened and is not hidden');
    t.equal(after.unattributed, 2,
            'and the difference grew by exactly one, which is where that ' +
            'sign-in is reported');

    // -------------------------------------------------------------------
    // RESTORE. tests/CLAUDE.md's second rule: this process is shared with every
    // other test file in the run, and a register left with four relationships
    // in it is a fixture the next file did not ask for.
    // -------------------------------------------------------------------
    made.forEach(function (id) { federation.remove(id); });
    applications.deleteApplication('fmb-webapp');
    const left = federation.list().filter(function (r) {
      return r.fedId.indexOf('fmb-') === 0;
    });
    t.equal(left.length, 0, 'this test cleaned up after itself',
            left.map(function (r) { return r.fedId; }).join(', '));
  }
};
