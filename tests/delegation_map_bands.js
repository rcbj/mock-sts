'use strict';
//
// File: delegation_map_bands.js
//
// ===========================================================================
// THE PICTURE IS TWO BANDS, AND THE ISSUER'S LABELS DO NOT SIT ON TOP OF EACH
// OTHER.
//
// `admin-ui/delegation_map.js` laid every box out with dagre until 2026-08-26,
// the hexagon among them, so the issuer got a RANK of its own in the flow: a
// person on the left, this service in the second column, and the applications
// strung out to the right of it. Two things were wrong with that and only one
// of them was ever going to be noticed by eye. The parties of one delegation
// ended up on four different vertical positions, because the issuer's own edges
// were competing with the chain for the ranking — a staircase where the ask was
// a line. And the hexagon, the box every single line touches, sat in the middle
// of the picture rather than over it.
//
// So the parties are laid out alone and the issuer is put back above them,
// centred, with its lines drawn by hand. What that bought is what this file
// asserts; what it COST is the label placement dagre used to do for those
// lines, which is the second half of the file — every one of them starts at the
// same point, so two labels at one fraction along are only as far apart as
// their boxes are, and the first version of the band wrote `signed in` across
// `issued to`.
//
// WHY IN PROCESS, WHICH IS THE QUESTION tests/CLAUDE.md ASKS FIRST. `render()`
// is a pure function from a graph to an SVG document: no store, no config, no
// request. That means the cases worth asserting are ones the running service
// cannot be made to produce on demand — a graph whose issuer lines all end
// within a few pixels of each other, an issuer with nothing attached to it at
// all — and reaching them over HTTP would mean driving protocol traffic until
// the register happened to hold the right shape, then parsing the geometry back
// out of the answer. The parsing is the same either way; what cannot be done
// over there is CHOOSING the graph.
//
// IT ASSERTS GEOMETRY RATHER THAN MARKUP, deliberately. Everything below reads
// the numbers off the emitted SVG — where a box is, where a label's panel is —
// and none of it names a colour, an attribute order or a class. A rewrite of
// how a box is drawn should not fail this file; a rewrite that puts the issuer
// back in the flow, or lets two labels overlap again, must.
// ===========================================================================

// Deleted rather than set, for the reason config_realm_layer.js gives: nothing
// here should depend on a developer's exported appconfig.
delete process.env.CONFIG_FILE;

const map = require('../admin-ui/delegation_map');

// ---------------------------------------------------------------------------
// READING THE PICTURE BACK.
//
// `render()` returns markup, so the assertions need the geometry out of it
// again. Two shapes are enough: a NODE is drawn as a rect, a hexagon path or a
// stick figure, and every one of them is preceded by the `<title>` that carries
// the party's tooltip — so a node is found by its title and measured from the
// shape after it. A LABEL is the white panel behind an edge's words, which is
// the only `<rect>` in the document carrying `fill-opacity`.
// ---------------------------------------------------------------------------
function panels(svg) {
  const out = [];
  const re = /<rect x="([-\d.]+)" y="([-\d.]+)" width="([\d.]+)" height="([\d.]+)" rx="3" fill="[^"]*" fill-opacity/g;
  let m = re.exec(svg);
  while (m) {
    out.push({ x: Number(m[1]), y: Number(m[2]),
               width: Number(m[3]), height: Number(m[4]) });
    m = re.exec(svg);
  }
  return out;
}

// THE HEXAGON, from the path `hexPath()` emits. It is matched whole rather than
// by a `<title>` or a class, so the numbers come from the shape actually drawn:
//   M x+cut y  H x+w-cut  L x+w y+h/2  L x+w-cut y+h  H x+cut  L x y+h/2  Z
function hexagon(svg) {
  const m = svg.match(/<path d="M([\d.]+) ([\d.]+)H([\d.]+)L([\d.]+) ([\d.]+)L([\d.]+) ([\d.]+)H([\d.]+)L([\d.]+) ([\d.]+)Z"/);
  if (!m) {
    return null;
  }
  return { top: Number(m[2]), bottom: Number(m[7]),
           left: Number(m[9]), right: Number(m[4]) };
}

// Every application box: the rounded rectangles, which are the only `rx="5"` in
// the document — an edge label's panel is `rx="3"` and the hexagon is a path.
function rects(svg) {
  const out = [];
  const re = /<rect x="([-\d.]+)" y="([-\d.]+)" width="([\d.]+)" height="([\d.]+)" rx="5"/g;
  let m = re.exec(svg);
  while (m) {
    out.push({ x: Number(m[1]), y: Number(m[2]),
               top: Number(m[2]), bottom: Number(m[2]) + Number(m[4]),
               width: Number(m[3]), height: Number(m[4]) });
    m = re.exec(svg);
  }
  return out;
}

// And the one person, found by the head of the stick figure. `personGlyph()`
// puts the circle a little under the top of the figure's box and the feet a
// little above its bottom, so the extent below is the drawn glyph rather than
// the space reserved for it — which is what an assertion about bands wants.
function figures(svg) {
  const out = [];
  const re = /<circle cx="([\d.]+)" cy="([\d.]+)" r="([\d.]+)"\/><path d="M[\d.]+ [\d.]+V([\d.]+)/g;
  let m = re.exec(svg);
  while (m) {
    out.push({ x: Number(m[1]), top: Number(m[2]) - Number(m[3]),
               bottom: Number(m[4]) });
    m = re.exec(svg);
  }
  return out;
}

// Where a box's own label was written, which is the only way to tell one box
// from another without asking this file to know how a box is drawn.
function labelY(svg, text) {
  const re = new RegExp('<text x="([\\d.]+)" y="([\\d.]+)"[^>]*>' + text + '<\\/text>');
  const m = svg.match(re);
  return m ? { x: Number(m[1]), y: Number(m[2]) } : null;
}

function overlap(a, b) {
  return a.x < b.x + b.width && b.x < a.x + a.width &&
         a.y < b.y + b.height && b.y < a.y + a.height;
}

// ---------------------------------------------------------------------------
// THE GRAPHS. Written out rather than built from `delegation.graph()`, because
// half the point of testing this file in process is being able to hand it a
// shape the register would take a suite of protocol traffic to produce.
// ---------------------------------------------------------------------------
function party(id, extra) {
  return Object.assign({
    id: id, kind: 'party', key: id, presented: id, application: id, what: '',
    roles: { initial: 0, intermediary: 0, target: 1 }, protocols: [],
    acts: 0, issued: 0, refused: 0, credentials: 0, flows: [], kinds: [],
    authentications: 0, isSubject: false, isClient: false,
    firstAt: 0, lastAt: 0, selfTarget: false, chiefRole: 'target'
  }, extra || {});
}

function edge(id, from, to, extra) {
  return Object.assign({
    id: id, from: from, to: to, fromRole: '', toRole: '', relation: 'reaches',
    acts: 0, issued: 0, refused: 0, credentials: 1, firstAt: 0, lastAt: 0,
    authorizedBy: '', reason: '', consumed: [], produced: [], skipped: [],
    chainKey: '', protocols: ['OAuth 2.0'], protocol: 'OAuth 2.0', type: '',
    typeLabel: 'Authorization Code grant', mode: '', spec: '', policed: false,
    subject: '', actor: ''
  }, extra || {});
}

const STS = { id: ' sts', kind: 'sts',
              realm: { id: '', name: 'Default', isDefault: true },
              issuer: 'urn:test', roles: { initial: 0, intermediary: 0, target: 0 },
              acts: 0, issued: 0, refused: 0 };

// A chain: a person, a client, and two services behind it. This is the shape
// the reorganisation was for — every party belongs on one line.
const CHAIN = {
  nodes: [STS,
          party('alice', { chiefRole: 'initial', isSubject: true }),
          party('webapp1'), party('apigw1'), party('esb1')],
  edges: [edge('a', 'alice', 'webapp1', { relation: 'issued-for', credentials: 3 }),
          edge('b', 'webapp1', 'apigw1'),
          edge('c', 'apigw1', 'esb1', { relation: 'acts-for', mode: 'impersonation',
                                        acts: 1, issued: 1, typeLabel: 'Token exchange' }),
          edge('d', ' sts', 'webapp1', { relation: 'issued', credentials: 3 }),
          edge('e', ' sts', 'apigw1', { relation: 'issued', credentials: 1 }),
          edge('f', ' sts', 'esb1', { relation: 'issued', credentials: 1 }),
          edge('g', 'alice', ' sts', { relation: 'signed-in', acts: 2, issued: 2,
                                       typeLabel: 'the sign-in screen' })]
};

// FOUR PARTIES SIDE BY SIDE WITH A LINE FROM THE ISSUER TO EACH, and no chain
// to spread them out. Every one of those lines starts at the same point and
// ends within a couple of hundred pixels of the next, which is the arrangement
// that made the labels collide.
const FAN = {
  nodes: [STS, party('alice', { chiefRole: 'initial', isSubject: true }),
          party('one'), party('two'), party('three'), party('four')],
  edges: [edge('1', ' sts', 'one', { relation: 'issued', credentials: 1 }),
          edge('2', ' sts', 'two', { relation: 'issued', credentials: 2 }),
          edge('3', ' sts', 'three', { relation: 'issued', credentials: 3 }),
          edge('4', ' sts', 'four', { relation: 'issued', credentials: 4 }),
          edge('5', 'alice', ' sts', { relation: 'signed-in', acts: 1, issued: 1,
                                       typeLabel: 'the sign-in screen' }),
          edge('6', 'alice', 'one', { relation: 'issued-for', credentials: 1 }),
          edge('7', 'alice', 'two', { relation: 'issued-for', credentials: 1 }),
          edge('8', 'alice', 'three', { relation: 'issued-for', credentials: 1 }),
          edge('9', 'alice', 'four', { relation: 'issued-for', credentials: 1 })]
};

// Nothing has ever happened. `delegation.graph([])`'s answer, which every one of
// these pages draws before anybody has chosen anything.
const ALONE = { nodes: [STS], edges: [] };

function run(t) {
  // -----------------------------------------------------------------------
  t.log.info('the issuer is in a band of its own, above every party');
  // -----------------------------------------------------------------------
  const chain = map.render(CHAIN, { id: 'chain', label: 'chain' });
  const hex = hexagon(chain.svg);
  const chainRects = rects(chain.svg);
  const chainFigures = figures(chain.svg);
  t.check(!!hex, 'the hexagon is drawn');
  t.equal(chainRects.length, 3, 'and a box for each of the three applications');
  t.equal(chainFigures.length, 1, 'and a stick figure for the person');
  const parties = chainRects.concat(chainFigures);
  const topmost = parties.reduce(function (held, one) {
    return Math.min(held, one.top);
  }, Infinity);
  t.check(!!hex && hex.bottom <= topmost,
          'THE HEXAGON ENDS ABOVE WHERE THE PARTIES BEGIN — two bands, not one flow',
          'issuer ends at ' + (hex && hex.bottom) +
          ', the topmost party begins at ' + topmost.toFixed(1));

  // Centred: the hexagon's own midpoint against the document's. Within a couple
  // of pixels, because every coordinate is rounded to a tenth on the way out.
  const width = Number((chain.svg.match(/viewBox="0 0 ([\d.]+)/) || [])[1]);
  const hexMid = hex ? (hex.left + hex.right) / 2 : 0;
  t.check(!!hex && Math.abs(hexMid - width / 2) <= 2,
          'and it is centred over them',
          'hexagon at ' + hexMid.toFixed(1) + ', picture is ' + width + ' wide');

  // -----------------------------------------------------------------------
  t.log.info('every party of a chain is on one plane');
  // -----------------------------------------------------------------------
  // The parties of CHAIN are a chain, so each is its own rank and dagre has no
  // reason to move any of them off the line the others are on. This is the
  // whole visible point of taking the issuer out of the layout: before it, the
  // issuer's edges pulled the ranks apart and the four boxes came out at four
  // heights.
  const centres = parties.map(function (one) { return (one.top + one.bottom) / 2; });
  const spread = Math.max.apply(null, centres) - Math.min.apply(null, centres);
  t.check(spread <= 30,
          'THEY SHARE ONE HORIZONTAL PLANE, within half a box',
          'centres ' + centres.map(function (c) { return c.toFixed(0); }).join(', '));

  // And they are in the order of the chain rather than in some order of dagre's
  // own — the person first, then the client, then what it reaches.
  const order = ['alice', 'webapp1', 'apigw1', 'esb1'].map(function (id) {
    const at = labelY(chain.svg, id);
    return at ? at.x : -1;
  });
  t.check(order.indexOf(-1) < 0, 'every party is labelled with its own name');
  t.check(order[0] < order[1] && order[1] < order[2] && order[2] < order[3],
          'and they run left to right in the order of the chain',
          order.map(function (x) { return x.toFixed(0); }).join(' < '));

  // -----------------------------------------------------------------------
  t.log.info('no two edge labels are drawn on top of each other');
  // -----------------------------------------------------------------------
  // Asserted on the FAN, which is the arrangement that broke: four lines out of
  // one point to four boxes in a row, plus the dotted sign-in going back the
  // other way. Every label is checked against every other rather than only the
  // issuer's — a band deep enough to separate these must not have pushed one of
  // them onto a line dagre placed.
  const fan = map.render(FAN, { id: 'fan', label: 'fan' });
  const fanPanels = panels(fan.svg);
  t.check(fanPanels.length >= 9, 'every line in the fan is labelled',
          fanPanels.length + ' label(s)');
  const clashes = [];
  fanPanels.forEach(function (one, i) {
    fanPanels.slice(i + 1).forEach(function (other) {
      if (overlap(one, other)) {
        clashes.push('(' + one.x.toFixed(0) + ',' + one.y.toFixed(0) + ') and (' +
                     other.x.toFixed(0) + ',' + other.y.toFixed(0) + ')');
      }
    });
  });
  t.check(clashes.length === 0,
          'NO TWO LABEL PANELS OVERLAP, which is what the label rows are for',
          clashes.length ? clashes.join('; ') : 'checked ' +
            (fanPanels.length * (fanPanels.length - 1) / 2) + ' pair(s)');

  // And on the chain too, where the issuer's three lines converge from a
  // narrower angle than the fan's four.
  const chainPanels = panels(chain.svg);
  const chainClashes = chainPanels.filter(function (one, i) {
    return chainPanels.slice(i + 1).filter(function (other) {
      return overlap(one, other);
    }).length > 0;
  });
  t.check(chainClashes.length === 0,
          'and none overlap on the chain either',
          chainClashes.length ? chainClashes.length + ' clash(es)' :
            chainPanels.length + ' label(s)');

  // -----------------------------------------------------------------------
  t.log.info('a label stays on the line it belongs to');
  // -----------------------------------------------------------------------
  // Rows separate the labels; they must not separate a label from its own line.
  // Each issuer label's panel is checked to contain a point of the path drawn
  // for that edge — which is what makes the row assignment a placement rather
  // than a scattering.
  const paths = [];
  const pre = /<path d="M([\d.]+) ([\d.]+)L([\d.]+) ([\d.]+)" fill="none"/g;
  let hit = pre.exec(fan.svg);
  while (hit) {
    paths.push({ x1: Number(hit[1]), y1: Number(hit[2]),
                 x2: Number(hit[3]), y2: Number(hit[4]) });
    hit = pre.exec(fan.svg);
  }
  t.check(paths.length >= 5, 'the issuer\'s lines are straight segments',
          paths.length + ' of them');
  const seated = fanPanels.filter(function (one) {
    const cx = one.x + one.width / 2;
    const cy = one.y + one.height / 2;
    return paths.filter(function (line) {
      // The point on that segment at this label's height, if the segment
      // spans it at all.
      if (cy < Math.min(line.y1, line.y2) || cy > Math.max(line.y1, line.y2)) {
        return false;
      }
      const t2 = (cy - line.y1) / ((line.y2 - line.y1) || 1);
      const x = line.x1 + (line.x2 - line.x1) * t2;
      return Math.abs(x - cx) <= 1;
    }).length > 0;
  });
  t.check(seated.length >= 5,
          'and each of their labels sits ON its own line rather than beside it',
          seated.length + ' of ' + fanPanels.length + ' panels are on a straight ' +
          'segment (the rest belong to lines dagre routed)');

  // -----------------------------------------------------------------------
  t.log.info('the issuer with nothing attached to it');
  // -----------------------------------------------------------------------
  // The band exists to hold the issuer's labels and to separate two things. A
  // picture with one shape in it has neither, and must not be padded with the
  // empty gap where the second band would have gone.
  const alone = map.render(ALONE, { id: 'alone', label: 'alone' });
  t.equal(alone.nodes, 1, 'one node is drawn');
  t.equal(alone.edges, 0, 'and no lines');
  const aloneBox = hexagon(alone.svg);
  t.check(!!aloneBox && alone.height - aloneBox.bottom <= 20,
          'AND THE PICTURE ENDS JUST BELOW IT — no empty band under a lone hexagon',
          'hexagon ends at ' + (aloneBox && aloneBox.bottom) +
          ', picture is ' + alone.height + ' tall');
}

module.exports = {
  name: 'delegation_map_bands',
  describe: 'the delegation picture is two bands, and no two edge labels overlap',
  run: run
};
