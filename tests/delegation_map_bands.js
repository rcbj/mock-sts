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
               // The horizontal extent as well, for the assertion that one
               // plane is a ROW: two boxes at the same height and the same x
               // are one box as far as a reader is concerned.
               left: Number(m[1]), right: Number(m[1]) + Number(m[3]),
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

// THE STRAIGHT LINES, which is every line the issuer draws — the party lines
// along the row are straight too and the arcs under it are cubics, so this is a
// superset and the assertions below say which ones they mean.
function segments(svg) {
  const out = [];
  const re = /<path d="M([\d.]+) ([\d.]+)L([\d.]+) ([\d.]+)" fill="none"/g;
  let m = re.exec(svg);
  while (m) {
    out.push({ x1: Number(m[1]), y1: Number(m[2]),
               x2: Number(m[3]), y2: Number(m[4]),
               d: m[1] + ' ' + m[2] + ' ' + m[3] + ' ' + m[4] });
    m = re.exec(svg);
  }
  return out;
}

// Whether a point is on a segment, read at that point's own height. The same
// question the label-seating assertion asks, in one place because two of them
// ask it.
function onSegment(line, x, y) {
  if (y < Math.min(line.y1, line.y2) || y > Math.max(line.y1, line.y2)) {
    return false;
  }
  const t = (y - line.y1) / ((line.y2 - line.y1) || 1);
  return Math.abs((line.x1 + (line.x2 - line.x1) * t) - x) <= 1;
}

// WHERE THE LINES STOP AND THE LABELS START, in DOCUMENT ORDER — which in an
// SVG is the whole of the stacking, there being no z-index. A line emitted
// after a label panel is painted ON TOP of the words in it.
function paintOrder(svg) {
  const lines = [];
  const reLine = /<path d="[^"]+" fill="none" stroke=/g;
  let m = reLine.exec(svg);
  while (m) {
    lines.push(m.index);
    m = reLine.exec(svg);
  }
  const labels = [];
  const rePanel = /<rect x="[-\d.]+" y="[-\d.]+" width="[\d.]+" height="[\d.]+" rx="3"/g;
  m = rePanel.exec(svg);
  while (m) {
    labels.push(m.index);
    m = rePanel.exec(svg);
  }
  return { lines: lines, labels: labels,
           lastLine: lines.length ? lines[lines.length - 1] : -1,
           firstLabel: labels.length ? labels[0] : Infinity };
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

// ONE PARTY WITH TWO LINES TO THE ISSUER, which was `bob_end_user`'s own
// picture and was drawn as ONE line until 2026-08-26. Every issuer line is a
// segment clipped to the two boxes at its ends, so two of them between the same
// pair were the same segment computed twice — one path exactly over the other —
// while their labels were seated in separate ROWS to keep labels from
// colliding. What that read as was a single line saying `signed in / OAuth 2.0
// / OIDC / 1 time` in one place and `signed in / OAuth 2.0 / 2 times` in
// another: one relationship contradicting itself.
//
// THAT PARTICULAR PAIR IS GONE FROM THE GRAPH — `user_graph.js` draws one
// sign-in line per person now, with the families listed on it, and
// `tests/user_graph_signin.js` holds it to that. This fixture is the shape that
// CANNOT be folded away, because the two lines say different things in
// different directions: a client that authenticated as itself is `signed in`
// one way and `issued for` the other, and the middle tier of a Kerberos chain
// both authenticates and is issued to. The renderer must not assume the graph
// handed to it folded anything.
const TWICE = {
  nodes: [STS, party('frontend', { chiefRole: 'initial', isSubject: true })],
  edges: [edge('signed-in', 'frontend', ' sts',
               { relation: 'signed-in', acts: 2, issued: 2,
                 protocol: '',
                 authentications: [
                   { protocol: 'OAuth 2.0', method: 'client_credentials',
                     count: 2 }
                 ],
                 typeLabel: 'OAuth 2.0 — client_credentials ×2' }),
          edge('grant |  sts > frontend', ' sts', 'frontend',
               { relation: 'issued-for', credentials: 2,
                 typeLabel: 'Client Credentials grant' })]
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

  const fan = map.render(FAN, { id: 'fan', label: 'fan' });

  // -----------------------------------------------------------------------
  t.log.info('every party of a FAN is on one plane too, and none of them share a seat');
  // -----------------------------------------------------------------------
  // THE CASE THE CHAIN ABOVE CANNOT SEE, and the one that was broken on
  // 2026-08-26 by the first attempt at this. In `rankdir: 'LR'` the RANK is the
  // x, so dagre gives every node on one rank the SAME x and tells them apart by
  // the y alone — which is the coordinate the row throws away. A chain has one
  // node per rank and comes out perfect either way; this fixture's four
  // applications are all on rank 1, and flattening the y without also owning the
  // x drew all four of them exactly on top of each other. Nothing in the file
  // failed: the label panels did not clash, the bands were still bands, and the
  // picture was four boxes in one place.
  //
  // So both halves are asserted, and the second is the one that matters: they
  // share a plane, AND no two of them overlap. `spread` alone is satisfied by
  // the bug.
  const fanRects = rects(fan.svg);
  const fanParties = fanRects.concat(figures(fan.svg));
  t.equal(fanParties.length, 5, 'the fan draws a box for each party');
  const fanCentres = fanParties.map(function (one) { return (one.top + one.bottom) / 2; });
  t.check(Math.max.apply(null, fanCentres) - Math.min.apply(null, fanCentres) <= 30,
          'THE FAN\'S PARTIES SHARE ONE PLANE, within half a box',
          'centres ' + fanCentres.map(function (c) { return c.toFixed(0); }).join(', '));
  // On the RECTS alone, which is the four applications — the stick figure is
  // drawn as a glyph and the markup carries no width for it, so an extent read
  // off the document would be invented. It is the four that shared a rank and
  // therefore the four that piled up; the person was on a rank of its own and
  // could not have.
  const stacked = [];
  fanRects.forEach(function (one, i) {
    fanRects.slice(i + 1).forEach(function (other) {
      if (one.left < other.right && one.right > other.left) {
        stacked.push('(' + one.left.toFixed(0) + '-' + one.right.toFixed(0) + ') and (' +
                     other.left.toFixed(0) + '-' + other.right.toFixed(0) + ')');
      }
    });
  });
  t.check(stacked.length === 0,
          'AND NO TWO OF THEM OVERLAP — one plane is a row, not a pile',
          stacked.length ? stacked.join('; ') : fanRects.length + ' box(es), none overlapping');

  // -----------------------------------------------------------------------
  t.log.info('no two edge labels are drawn on top of each other');
  // -----------------------------------------------------------------------
  // Asserted on the FAN, which is the arrangement that broke: four lines out of
  // one point to four boxes in a row, plus the dotted sign-in going back the
  // other way. Every label is checked against every other rather than only the
  // issuer's — a band deep enough to separate these must not have pushed one of
  // them onto a line dagre placed.
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
  t.log.info('two lines between one party and the issuer are two lines');
  // -----------------------------------------------------------------------
  // See the note on TWICE. This is asserted on the GEOMETRY rather than on the
  // count of `<path>` elements, because the bug drew both of them: there were
  // two paths in the document, with identical `d` attributes and identical
  // arrowheads, one exactly under the other. What a reader saw was one line
  // with two labels on it.
  const twice = map.render(TWICE, { id: 'twice', label: 'twice' });
  const twiceHex = hexagon(twice.svg);
  // EITHER END, because these two run in opposite directions: the sign-in
  // points INTO the hexagon and the grant comes back OUT of it, which is the
  // whole reason the graph cannot fold them into one.
  const atHex = function (line) {
    return !!twiceHex && (Math.abs(line.y1 - twiceHex.bottom) <= 1 ||
                          Math.abs(line.y2 - twiceHex.bottom) <= 1);
  };
  const hexEndOf = function (line) {
    return Math.abs(line.y1 - (twiceHex ? twiceHex.bottom : 0)) <= 1
      ? { x: line.x1, y: line.y1 } : { x: line.x2, y: line.y2 };
  };
  const signIns = segments(twice.svg).filter(atHex);
  t.check(signIns.length >= 2,
          'both of the party\'s lines to the issuer are drawn',
          signIns.length + ' segment(s) touch the hexagon');
  // COMPARED AS UNORDERED PAIRS OF POINTS, which matters here and would not
  // have in a fixture whose lines ran the same way: these two run in opposite
  // directions, so `M a L b` and `M b L a` are different strings for one
  // segment drawn twice. Comparing the strings would call that two lines.
  const distinct = {};
  signIns.forEach(function (line) {
    const ends = [line.x1 + ',' + line.y1, line.x2 + ',' + line.y2].sort();
    distinct[ends.join(' ')] = true;
  });
  t.check(Object.keys(distinct).length === signIns.length,
          'AND NO TWO OF THEM ARE THE SAME SEGMENT — one path over ' +
          'another is one line wearing two labels',
          signIns.map(function (line) { return line.d; }).join(' | '));

  // Both ends still land on their own box. The fan aims a line to one side of
  // the issuer's centre, so the hexagon end is clipped against the SHAPE rather
  // than scaled along a ray out of its middle — and getting that wrong does not
  // draw a wrong line, it draws a correct line that starts in mid-air a few
  // pixels off the hexagon it points at.
  const adrift = signIns.filter(function (line) {
    const end = hexEndOf(line);
    return !twiceHex || end.x < twiceHex.left - 1 || end.x > twiceHex.right + 1;
  });
  t.check(adrift.length === 0,
          'and each of them meets the hexagon rather than stopping beside it',
          adrift.length
            ? adrift.map(function (line) { return line.d; }).join(' | ')
            : 'both ends within the outline (' +
              (twiceHex ? twiceHex.left.toFixed(0) + '-' +
                          twiceHex.right.toFixed(0) : '?') + ')');

  // AND THE LABELS FOLLOWED THEM. Two lines drawn apart with both labels seated
  // on where the old single line was would be the same complaint in a new
  // place, so each panel is required to sit on one of these segments and no two
  // panels on the same one.
  const twicePanels = panels(twice.svg);
  const seats = signIns.map(function (line) {
    return twicePanels.filter(function (one) {
      return onSegment(line, one.x + one.width / 2, one.y + one.height / 2);
    }).length;
  });
  const oneEach = seats.filter(function (n) { return n === 1; });
  t.check(oneEach.length === signIns.length,
          'and each line carries exactly one of the two labels',
          'panels per line: ' + seats.join(', '));

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

  // -----------------------------------------------------------------------
  t.log.info('a DENSE graph — every pair in both directions, twice over');
  // -----------------------------------------------------------------------
  // THE PICTURE WAS NOT DRAWN AT ALL, and every table under it was right. On
  // 2026-09-01 `/admin/delegation/allowed` answered `The picture could not be
  // drawn: Not possible to find intersection inside of the rectangle` for the
  // delegated permission example — five applications, each granting the other
  // four `read` and `write`, which is five boxes and forty lines. The graph was
  // perfect; `?format=json` reported all forty, and the tables below the
  // picture were built from the same graph and were correct. Only the LAYOUT
  // threw, and `render()`'s guard turned that into a sentence where the diagram
  // goes — so a page whose whole purpose is the picture had everything on it
  // except the picture.
  //
  // The cause was dagre being handed a MULTIGRAPH, which it was because two
  // chains between one pair of boxes are two lines. It needs two ingredients
  // and the mesh is the smallest thing that has both: a pair joined in BOTH
  // directions, and PARALLEL lines within a pair. Given both, dagre 1.x leaves
  // a dummy node's position at NaN, and `assignNodeIntersects()` then finds
  // neither a dx nor a dy and throws. Either ingredient alone lays out fine,
  // which is why every fixture above missed it — CHAIN and FAN have neither,
  // and TWICE has the parallel pair without the cycle.
  //
  // WHY IN PROCESS, when `tests/vendored/sts_delegated_permissions_example.js`
  // builds this very mesh over HTTP: that job asserted the GRAPH and never
  // asked whether the picture drew, which is exactly the hole this fell
  // through, and it is being closed there too. What cannot be done over there
  // is asking the question CHEAPLY — this is the renderer's own contract, it
  // is a pure function, and a fixture here costs milliseconds and no container.
  const MESH_IDS = ['abcapp1', 'abcapp2', 'abcapp3', 'abcapp4', 'abcapp5'];
  const MESH = { nodes: [], edges: [] };
  MESH_IDS.forEach(function (id) {
    MESH.nodes.push(party(id, { chiefRole: 'target',
                                roles: { initial: 0, intermediary: 4, target: 4 } }));
  });
  MESH_IDS.forEach(function (client) {
    MESH_IDS.forEach(function (resource) {
      if (client === resource) {
        // `app_permissions.graph()` draws no line for a self-grant — an arrow
        // leaving a box and returning to it is a drawing of nothing — so the
        // fixture does not make one either.
        return;
      }
      ['read', 'write'].forEach(function (name) {
        const line = edge(client + ' | ' + resource + '/' + name, client, resource, {
          relation: 'may-reach', protocols: [], protocol: '', typeLabel: '',
          // The identifier is the resource's BASE followed by the name, which
          // is what `app_permissions.js` mints and what a client sends as an
          // OAuth scope. Written out in that shape rather than as a handle,
          // because the tooltip assertion below is that the whole of it is on
          // the picture somewhere. `credentials` is left OFF the edge on
          // purpose: `app_permissions.graph()` publishes no such member, and
          // that absence is exactly what put `undefined` in every tooltip.
          permissionId: 'https://' + resource + '.example.com/' + name,
          permissionName: name,
          baseUri: 'https://' + resource + '.example.com/',
          description: name + ' access to ' + resource, asked: false
        });
        // DELETED rather than set to a number or to zero. `app_permissions.js`
        // publishes no `credentials` member at all, and the ABSENCE is the
        // thing being reproduced: the generic `edge()` fixture above defaults
        // it to 1, which would put a plausible number in the tooltip and hide
        // the `undefined` the assertion below exists to catch.
        delete line.credentials;
        MESH.edges.push(line);
      });
    });
  });

  const mesh = map.render(MESH, { id: 'mesh', label: 'mesh' });
  t.check(!mesh.failed,
          'THE PICTURE IS DRAWN — five boxes and forty lines is a layout, not a failure',
          mesh.failed || (mesh.width + 'x' + mesh.height + ' of SVG'));
  t.equal(mesh.nodes, MESH_IDS.length, 'every box is in it');
  t.equal(mesh.edges, MESH.edges.length, 'and every line');

  // The boxes are still a ROW, which is the property every fixture above
  // asserts and the one a collapsed layout could quietly lose: dagre is being
  // kept for the ORDER alone, and an order it could not compute would stack
  // five boxes on one another rather than saying so.
  const meshBoxes = rects(mesh.svg);
  t.equal(meshBoxes.length, MESH_IDS.length, 'drawn as five rectangles');
  const meshLefts = meshBoxes.map(function (one) { return one.left; })
    .sort(function (a, b) { return a - b; });
  const meshStacked = meshLefts.filter(function (x, i) {
    return i > 0 && Math.abs(x - meshLefts[i - 1]) < 1;
  });
  t.check(meshStacked.length === 0,
          'each in a column of its own rather than on top of the last',
          'left edges: ' + meshLefts.map(function (x) { return x.toFixed(0); }).join(', '));

  // EVERY LINE IS PAINTED BEFORE EVERY LABEL, and on this graph that is the
  // difference between a picture and a mess. Each edge used to emit its own
  // line and then its own label, so document order interleaved them and the
  // fortieth line went straight across the first line's words: 25 of the 40
  // labels here were crossed by a line drawn ON TOP of them. The lane
  // assignment was never the problem — no two label panels overlap, on this
  // fixture or any other above, and the assertion below says so from the same
  // SVG so that the two failures cannot be confused for each other again.
  //
  // Asserted as ORDER rather than by counting crossings, because the crossings
  // are real: forty lines between five boxes cross each other whatever is done,
  // and the claim being made is only that a crossing goes BEHIND the words.
  const meshOrder = paintOrder(mesh.svg);
  t.check(meshOrder.lines.length > 0 && meshOrder.labels.length > 0 &&
          meshOrder.lastLine < meshOrder.firstLabel,
          'AND EVERY LINE IS DRAWN BEFORE EVERY LABEL — a crossing goes behind ' +
          'the words rather than through them',
          meshOrder.lines.length + ' line(s) ending at ' + meshOrder.lastLine +
          ', ' + meshOrder.labels.length + ' label(s) starting at ' +
          meshOrder.firstLabel);

  const meshPanels = panels(mesh.svg);
  t.equal(meshPanels.length, MESH.edges.length, 'every line carries its label');
  const meshClashes = [];
  meshPanels.forEach(function (one, i) {
    meshPanels.slice(i + 1).forEach(function (other) {
      if (overlap(one, other)) {
        meshClashes.push('(' + one.x.toFixed(0) + ',' + one.y.toFixed(0) + ') and (' +
                         other.x.toFixed(0) + ',' + other.y.toFixed(0) + ')');
      }
    });
  });
  t.check(meshClashes.length === 0,
          'and no two of the forty labels overlap — the arc lanes hold at this density',
          meshClashes.length ? meshClashes.slice(0, 5).join('; ')
                             : meshPanels.length + ' panel(s), none overlapping');

  // AND THE SENTENCE ON HOVER IS ABOUT THIS PICTURE. `edgeTitle()` ends with a
  // count of acts and of credentials from the issued register, which a
  // CONFIGURED permission has neither of — `app_permissions.graph()` publishes
  // no `credentials` member, correctly, so every one of the forty lines here
  // said `undefined credential(s) from the issued register, and no delegation
  // act: nothing was exchanged to get them` until 2026-09-01. The `undefined`
  // is the visible half; the sentence is wrong even with a number in it,
  // because "nothing was exchanged" is an observation about acts on a line
  // that describes no act. This is the one thing on the picture that carries
  // the whole permission identifier, which is why it is worth an assertion.
  t.check(mesh.svg.indexOf('undefined') < 0,
          'AND NO TOOLTIP SAYS `undefined` — a configured line has no credential ' +
          'count to report',
          mesh.svg.indexOf('undefined') < 0
            ? 'no occurrence in ' + mesh.svg.length + ' bytes'
            : mesh.svg.slice(Math.max(0, mesh.svg.indexOf('undefined') - 90),
                             mesh.svg.indexOf('undefined') + 40));
  t.check(mesh.svg.indexOf('nothing was exchanged') < 0 &&
          mesh.svg.indexOf('issued register') < 0,
          'and none of them reports acts or the issued register on a line that ' +
          'describes neither',
          'the may-reach tooltip ends at what the client has asked for');
  t.check(/MAY reach/.test(mesh.svg) &&
          mesh.svg.indexOf('has NEVER asked for it') >= 0 &&
          mesh.svg.indexOf('abcapp2.example.com/read') >= 0,
          'while still carrying what a configured line DOES say — the relation, ' +
          'the whole permission identifier, and whether it has ever been asked for',
          'MAY reach / the identifier / never asked for are all in the document');
}

module.exports = {
  name: 'delegation_map_bands',
  describe: 'the delegation picture is two bands, and no two edge labels overlap',
  run: run
};
