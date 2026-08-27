'use strict';
//
// File: federation_diagram.js
//
// ===========================================================================
// THE FEDERATION PICTURE. `federation/federation_graph.js`'s graph, drawn.
//
// It is a LIBRARY, like `delegation_map.js` beside it: it registers no route, so
// its position in the require order does not matter and it cannot be the reason
// a route is missing. `admin.js` registers `/admin/federation/map` and calls
// `render()`; this file holds the geometry and none of the console's HTML.
//
// It requires `../common/helpers` (for `log` and `xmlEscape`), `@dagrejs/dagre`,
// and `./delegation_map` — for the PALETTE, the hexagon and the two text
// functions, and for nothing else. That last require is worth being explicit
// about: it is not this picture reusing that one's layout. It reuses the
// arithmetic that decides how wide a box holding a given string is, and the
// colours the console has already taught a reader to read, because two answers
// to either of those is two pictures that do not look like one console.
//
// It is NAMED `federation_diagram.js` AND NOT `federation_map.js` for one
// reason, and it is worth a line because the collision is real:
// `federation/federation_map.js` already exists and is something else entirely —
// it maps a partner's ATTRIBUTE NAMES onto directory attributes. Two files
// called federation_map.js doing unrelated things in one repository is a bug
// waiting for somebody to open the wrong one.
//
// ---------------------------------------------------------------------------
// WHY THIS IS NOT `delegation_map.render()` WITH A DIFFERENT GRAPH, WHICH WAS
// THE FIRST THING TRIED.
//
// That renderer takes a graph and draws it, and its vocabulary is close enough
// to be tempting: it has a hexagon for this service, a rectangle for an
// application, and edges with labels. Two things stop it.
//
// **ITS LAYOUT IS A DELIBERATE SPECIALISATION AND THE SPECIALISATION IS WRONG
// HERE.** It takes the hexagon OUT of dagre's layout and puts it in a band
// ABOVE, then puts every other box on one horizontal centreline — because a
// delegation chain is a chain, and the issuer is the box every line touches so
// leaving it in the flow made a staircase. This graph is the opposite shape: the
// hexagon is the MIDDLE RANK of a three-rank left-to-right flow, and which side
// of it a box sits on is the entire claim the picture makes (see
// `federation_graph.js`'s header — left asks, right authenticates). Hoisting it
// into a band would delete exactly the thing being said.
//
// **AND ITS EDGE VOCABULARY IS DELEGATION'S.** `edgeLook()` and
// `edgeLabelLines()` there switch on `acts-for`, `issued`, `reaches`, and colour
// by impersonation-versus-delegation — a judgement that means nothing about a
// federation relationship. Teaching that function a second vocabulary would make
// one function that is really two, and the amber/green pairing a reader has
// learnt from `/admin/delegation` would start meaning something else on this
// page.
//
// So the layout here is the ORDINARY use of dagre — its ranks and ITS
// coordinates, both — which is also why this file is a third the size of that
// one. The hard case there was flattening a layered layout; there is no hard
// case here, because the graph really is layered.
//
// ---------------------------------------------------------------------------
// AND IT KEEPS THE CSP RULE INTACT, which is the root CLAUDE.md's second one and
// is the reason the delegation picture is drawn on the server. This is the same
// answer for the same reason and it is NOT the argument being made once and
// cited twice: a graph library in the browser — mermaid, cytoscape, d3 — would
// make this the first scripted page in the console to draw a diagram that does
// not move, and `script-src 'none'` would have to be relaxed for it. The SVG
// below is generated here and arrives as markup, so nothing is relaxed and
// `img-src` is not even reached. What it costs is pan and zoom, and the page
// says so out loud and offers `?format=svg` for something that does zoom.
// ===========================================================================

const { log, xmlEscape } = require('../common/helpers');
const dagre = require('@dagrejs/dagre');
const delegationMap = require('./delegation_map');

const COLOURS = delegationMap.COLOURS;
const INK = COLOURS.ink;
const INDIGO = COLOURS.indigo;
const GREEN = COLOURS.green;
const AMBER = COLOURS.amber;
const RED = COLOURS.red;
const QUIET = COLOURS.quiet;
const LINE = COLOURS.line;
const PANEL = COLOURS.panel;
const PAPER = COLOURS.paper;
const WASH = COLOURS.wash;

const textWidth = delegationMap.textWidth;
const wrapLabel = delegationMap.wrapLabel;
const hexPath = delegationMap.hexPath;
const MAX_LABEL_CHARS = delegationMap.MAX_LABEL_CHARS;

// An arrowhead carries its own fill and cannot inherit the path's, so every
// stroke colour a line can take needs a marker of that colour. Named by colour
// rather than by meaning, so that changing what a line MEANS does not leave a
// marker named after the old idea — `delegation_map.js`'s rule, and its prefix
// is different from this one's so the two pictures cannot share ids if they ever
// appear on one page.
const ARROW_COLOURS = [INDIGO, GREEN, AMBER, RED, QUIET];

function markerId(colour) {
  return 'fd-arrow-' + colour.replace('#', '');
}

function esc(v) {
  return xmlEscape(v == null ? '' : String(v));
}

function round(n) {
  return Math.round(n * 10) / 10;
}

function trim(text, max) {
  const value = String(text == null ? '' : text);
  return value.length > max ? value.slice(0, max - 1) + '…' : value;
}

// ---------------------------------------------------------------------------
// THE METRICS. Every number a box or a line is built out of, in one place, so
// that "the picture is too cramped" is one edit rather than a hunt. They are
// `delegation_map.js`'s where the two pictures draw the same thing, because two
// consoles' worth of slightly different rectangles is what makes a set of pages
// look assembled rather than designed.
// ---------------------------------------------------------------------------
const LABEL_SIZE = 12;      // a box's own name
const SUB_SIZE = 10;        // the line under it: what kind of thing this is
const EDGE_SIZE = 10;       // a line's label
const LINE_HEIGHT = 13;
const BOX_PAD_X = 14;
const BOX_PAD_Y = 8;
const MIN_BOX_W = 96;
const MAX_BOX_W = 250;
const HEX_PAD_X = 22;

// dagre's own knobs. `ranksep` is generous for the reason it is generous next
// door: an edge label sits BETWEEN two ranks and a cramped gap puts the words of
// one line on top of the words of the next. It is wider here than there because
// these labels are the point — a federation line carries the relationship's
// name, its protocol and its counts, where a delegation line carries a mechanism.
const RANK_SEP = 132;
const NODE_SEP = 30;
const EDGE_SEP = 22;
const MARGIN = 20;

// The white panel behind an edge's words, so a label crossing a line is still
// readable. Same construction as the delegation picture's, and the test next
// door finds a label by exactly this shape — which is why the `rx` and the
// `fill-opacity` are here rather than being tidied into a class.
const LABEL_PAD_X = 5;
const LABEL_PAD_Y = 3;

// ---------------------------------------------------------------------------
// WHAT A BOX LOOKS LIKE AND HOW BIG IT IS, answered by one function.
//
// `delegation_map.js`'s `measure()` makes the argument and it holds here
// unchanged: they are the same question asked twice, and two functions would be
// two chances for the drawing to be a shape the layout did not reserve room for.
//
// FOUR SHAPES, AND EACH IS A CLAIM RATHER THAN A DECORATION:
//
//   * A HEXAGON IS AN IDENTITY SERVICE. This realm is one; so is a foreign
//     identity provider. It is the same shape `/admin/delegation/map` uses for
//     this service, deliberately — a reader who has learnt it there reads it
//     here without being told.
//   * A RECTANGLE IS A PARTY THAT CONSUMES WHAT AN IDENTITY SERVICE ISSUES: an
//     application at this end, or a foreign service provider at the far end.
//     Again the delegation picture's own vocabulary.
//   * A DASHED OUTLINE MEANS FOREIGN — not this service, not something this
//     realm can see the inside of. Both partner shapes are dashed and neither
//     local shape is. That is the same three-state rule the delegation picture
//     follows for a party the directory has never heard of, narrowed to the one
//     distinction that matters here.
//
// So a foreign identity provider is a DASHED HEXAGON and a foreign service
// provider is a DASHED RECTANGLE, and the two facts a reader needs — what kind
// of party is this, and is it ours — are carried by two independent properties
// of the shape rather than by four shapes that have to be memorised.
// ---------------------------------------------------------------------------
function measure(look) {
  log.debug("Entering measure().");
  const lines = wrapLabel(look.label, MAX_LABEL_CHARS, 2);
  const subLines = look.sublabel ? wrapLabel(look.sublabel, MAX_LABEL_CHARS + 6, 2) : [];
  let textW = 0;
  lines.forEach(function (one) {
    textW = Math.max(textW, textWidth(one, LABEL_SIZE));
  });
  subLines.forEach(function (one) {
    textW = Math.max(textW, textWidth(one, SUB_SIZE));
  });
  const textH = lines.length * LINE_HEIGHT +
                (subLines.length ? subLines.length * (LINE_HEIGHT - 2) + 2 : 0);
  if (look.shape === 'hexagon') {
    log.debug("Leaving measure().");
    return {
      shape: 'hexagon',
      width: Math.min(MAX_BOX_W + 40, Math.max(MIN_BOX_W + 40, textW + HEX_PAD_X * 2 + 26)),
      height: Math.max(58, textH + BOX_PAD_Y * 2 + 8),
      lines: lines, subLines: subLines
    };
  }
  log.debug("Leaving measure().");
  return {
    shape: 'rect',
    width: Math.min(MAX_BOX_W, Math.max(MIN_BOX_W, textW + BOX_PAD_X * 2)),
    height: Math.max(40, textH + BOX_PAD_Y * 2),
    lines: lines, subLines: subLines
  };
}

// ---------------------------------------------------------------------------
// WHAT A BOX IS CALLED AND HOW IT IS DRAWN. One place, so that the picture and
// its legend cannot come to disagree.
//
// `options.resolve` may override it — the console passes one so that a box can
// link to that party's own page — but the SHAPE is decided here from the node's
// kind and is not the caller's to change. A caller that could would eventually
// draw a partner as a local box, which is the one distinction this picture is
// built to carry.
// ---------------------------------------------------------------------------
function lookOf(node, options) {
  log.debug("Entering lookOf(). kind=" + node.kind);
  const extra = typeof options.resolve === 'function' ? (options.resolve(node) || {}) : {};
  let look;
  if (node.kind === 'sts') {
    look = {
      shape: 'hexagon', colour: INDIGO, dashed: false, fill: WASH,
      label: node.label || 'This service',
      // THE REALM IS ON THE HEXAGON, not in the page's heading alone. A realm is
      // a whole logical copy of this service and this picture is of one of them;
      // a saved `?format=svg` document with no realm on it is a picture of
      // somewhere, and nobody can tell where.
      sublabel: 'trust realm ' + (node.realmName || node.realm || 'default'),
      title: 'This service, in the trust realm "' + (node.realm || 'default') +
             '". Every relationship on this picture belongs to this realm and to ' +
             'no other: the register is per realm, so an id that names a ' +
             'relationship in another realm names nothing here.'
    };
  } else if (node.kind === 'application') {
    look = {
      shape: 'rect', colour: INDIGO, dashed: false, fill: PAPER,
      label: node.label,
      sublabel: 'an application here',
      title: 'An application registered in this realm whose people are ' +
             'authenticated through a federation relationship. It is an entry ' +
             'under ou=applications; what points it at a partner is ' +
             'appFederationRelationship on that entry.'
    };
  } else if (node.kind === 'partner-sp') {
    look = {
      shape: 'rect', colour: GREEN, dashed: true, fill: PAPER,
      label: node.label,
      sublabel: 'a foreign service provider',
      title: 'A FOREIGN SERVICE PROVIDER. It asks this service to authenticate ' +
             'somebody and consumes what this service issues' +
             (node.peer && node.peer !== node.label
                ? '. Its own name for itself is "' + node.peer + '"' : '') +
             (node.application
                ? '; this service knows it as the application "' +
                  node.application + '"' : '') + '.'
    };
  } else {
    look = {
      shape: 'hexagon', colour: GREEN, dashed: true, fill: PAPER,
      label: node.label,
      sublabel: 'a foreign identity provider',
      title: 'A FOREIGN IDENTITY PROVIDER. It authenticates the person and this ' +
             'service consumes what it issues. Nothing about it is checked here ' +
             'except its SIGNATURE, against the certificate configured on the ' +
             'relationship — which is the one thing this service does check.'
    };
  }
  const merged = Object.assign(look, extra);
  log.debug("Leaving lookOf().");
  return merged;
}

// ---------------------------------------------------------------------------
// WHAT A LINE LOOKS LIKE, AND IT IS THE RELATIONSHIP'S STATE AND NOTHING ELSE.
//
// This is the one judgement in the file and it is worth stating rather than
// leaving in a switch. Four states, and they are `admin.js`'s
// `federationStateCell()`'s four — the same four sentences that page prints,
// drawn instead of written:
//
//   * READY (enabled and configured)     GREEN, solid. It will work.
//   * DISABLED                           GREY, dashed. It is off, which is how
//                                        every relationship starts, so this is
//                                        the ordinary state of something
//                                        somebody has not finished setting up
//                                        rather than a fault.
//   * ENABLED AND NOT CONFIGURED         RED, dashed. THE LOUD ONE, and it earns
//                                        being the only red on the page: it is a
//                                        relationship that will REFUSE at the
//                                        moment somebody tries to use it, and it
//                                        is the state that looks finished from
//                                        every angle except this one.
//   * A BROKER THAT CANNOT BROKER        AMBER, dashed. The relationship itself
//                                        is fine and its onward partner is not,
//                                        so the person meets the password box
//                                        instead of the partner — the silent
//                                        fallback this whole feature is careful
//                                        about, and the only failure here that
//                                        produces a working sign-in.
//
// AMBER AND GREEN MEAN WHAT THEY MEAN NEXT DOOR, which is why they were not
// picked freshly: on `/admin/delegation/map` amber is the state whose
// consequence is invisible everywhere else, and that is exactly what a silently
// un-brokered relationship is.
// ---------------------------------------------------------------------------
function edgeLook(edge) {
  log.debug("Entering edgeLook().");
  const row = edge.row || {};
  if (row.enabled && !row.ready) {
    log.debug("Leaving edgeLook().");
    return { colour: RED, dash: '5 3', weight: 1.8 };
  }
  if (!row.enabled) {
    log.debug("Leaving edgeLook().");
    return { colour: QUIET, dash: '4 3', weight: 1.3 };
  }
  if (edge.relation === 'asks' && row.brokersTo && !row.brokerUsable) {
    log.debug("Leaving edgeLook().");
    return { colour: AMBER, dash: '6 3', weight: 1.7 };
  }
  log.debug("Leaving edgeLook().");
  return { colour: GREEN, dash: '', weight: 1.8 };
}

// A count of PEOPLE and a count of SIGN-INS are different units and one word for
// both would report `4` on a line carrying four arrivals and on a line carrying
// four people, which are not comparable numbers. Both are said, or neither.
function useText(use) {
  if (!use) {
    return '';
  }
  if (!use.authentications) {
    return use.configured === false ? 'no longer configured' : 'never used';
  }
  return use.users + ' ' + (use.users === 1 ? 'person' : 'people') + ', ' +
         use.authentications + ' sign-in' + (use.authentications === 1 ? '' : 's');
}

// ---------------------------------------------------------------------------
// THE WORDS ON A LINE. Up to three short ones, and everything else is in the
// `<title>` and in the tables under the picture.
//
// That cap is `delegation_map.js`'s and the reason is its reason: a fourth line
// was tried there and it is what turns a diagram into a page of text laid out
// badly. What each line says differs by which of the three kinds of line it is,
// and the three are the three claims the picture makes.
// ---------------------------------------------------------------------------
function edgeLabelLines(edge) {
  log.debug("Entering edgeLabelLines().");
  const row = edge.row || {};
  const lines = [];
  if (edge.relation === 'signs-in') {
    // AN APPLICATION'S PEOPLE, THROUGH A NAMED RELATIONSHIP. The relationship's
    // id leads, because an application with two partners draws two of these and
    // the whole question is which is which.
    lines.push('via ' + trim(row.id, 24));
    const counts = useText(edge.use);
    if (counts) lines.push(counts);
  } else if (edge.relation === 'asks') {
    // A FOREIGN SERVICE PROVIDER ASKING. What it gets is the second line, and it
    // is the answer to the thing this picture was asked to show: the
    // authentication method configured on the identity-provider side.
    lines.push('asks · ' + trim(row.protocolLabel, 20));
    if (row.brokersTo) {
      lines.push('brokered to ' + trim(row.brokersTo, 20));
    } else {
      lines.push(trim(row.mechanismLabel, 32));
    }
    // -------------------------------------------------------------------
    // THE COUNTS COME OFF THE PAIR AND NEVER OFF THE RELATIONSHIP, and this
    // is the one line on the picture where using the obvious field would
    // print a number that can only ever be zero.
    //
    // `fedAuthentications` on an IDENTITY-PROVIDER-side relationship has
    // always read zero and still does — nothing increments it, because what
    // it counts is assertions CONSUMED and this side issues them
    // (`federation/CLAUDE.md`, "What it deliberately does not do"). So
    // `row.authentications` here is not a count that happens to be low, it is
    // a count nothing writes.
    //
    // What HAS happened for this partner is on `edge.use`: the brokered pair's
    // own row, carried onto this arrow by `federation_graph.js` precisely
    // because the arrow it belongs to is drawn here rather than on the onward
    // relationship. A partner brokered through a service-provider-side
    // relationship really has had people signed in for it, and that is the
    // number.
    // -------------------------------------------------------------------
    const counts = useText(edge.use);
    if (counts) {
      lines.push(counts);
    }
  } else {
    // THIS SERVICE CONSUMING FROM A PARTNER. The relationship, what it speaks,
    // and HOW MANY APPLICATIONS ARE BEHIND IT — which is the number a table of
    // relationships has never been able to show, because it is a fact about two
    // registers rather than about one entry.
    lines.push(trim(row.id, 24));
    lines.push(trim(row.protocolLabel, 20) +
               (row.applicationCount
                  ? ' · ' + row.applicationCount + ' app' +
                    (row.applicationCount === 1 ? '' : 's')
                  : ''));
    if (row.authentications) {
      lines.push(row.users + ' ' + (row.users === 1 ? 'person' : 'people') +
                 ', ' + row.authentications + ' sign-in' +
                 (row.authentications === 1 ? '' : 's'));
    }
  }
  log.debug("Leaving edgeLabelLines().");
  return lines.slice(0, 3);
}

// THE WHOLE STORY, on hover. Everything the three label lines had no room for,
// and it is where the state sentence lives — the picture says the state in
// COLOUR, which is fast to read and impossible to quote.
function edgeTitle(edge) {
  const row = edge.row || {};
  const parts = [];
  if (edge.relation === 'signs-in') {
    parts.push('This application\'s people are authenticated at "' +
               (row.peer || row.id) + '" through the federation relationship "' +
               row.id + '" (' + row.protocolLabel + ').');
    if (edge.use && edge.use.configured === false) {
      parts.push('IT IS NO LONGER CONFIGURED TO: nothing names this pair any ' +
                 'more, and the counts below are what happened before that ' +
                 'changed. They are shown rather than dropped so that the ' +
                 'relationship\'s own totals still add up.');
    }
    if (edge.use && edge.use.source === 'broker') {
      parts.push('It reaches it through the identity-provider-side ' +
                 'relationship "' + edge.use.via + '" rather than through its ' +
                 'own entry.');
    }
  } else if (edge.relation === 'asks') {
    parts.push('This foreign service provider asks this service to ' +
               'authenticate people, through the federation relationship "' +
               row.id + '" (' + row.protocolLabel + '). This service ASSERTS to ' +
               'it: the arrow is the request, not the assertion.');
    parts.push(row.brokersTo
      ? 'It authenticates them through another federation relationship, "' +
        row.brokersTo + '" — this service is an identity BROKER for this ' +
        'partner: it consumes somebody else\'s assertion and issues its own.'
      : 'How somebody is authenticated for it: ' + row.mechanismLabel + '.');
    if (row.brokerProblem) {
      parts.push('AND IT CANNOT: ' + row.brokerProblem + ' Until that is fixed ' +
                 'the person meets the sign-in screen instead, which checks no ' +
                 'password — a federated application authenticating people ' +
                 'locally looks exactly like a federated application working.');
    }
    if (edge.use && edge.use.authentications) {
      parts.push(edge.use.users + ' person(s) and ' + edge.use.authentications +
                 ' sign-in(s) have been brokered for it through "' +
                 edge.brokeredTo + '". The relationship\'s OWN counters read ' +
                 'zero and always will: nothing increments them, because what ' +
                 'they count is assertions CONSUMED and this side issues them.');
    }
    if (row.releases.length) {
      parts.push('Attributes released to it: ' + row.releases.join(', ') + '.');
    }
  } else {
    parts.push('This service consumes assertions from "' + (row.peer || row.id) +
               '" through the federation relationship "' + row.id + '" (' +
               row.protocolLabel + '). An assertion is refused unless it ' +
               'verifies against the certificate configured on this ' +
               'relationship.');
    parts.push(row.applicationCount
      ? row.applicationCount + ' application(s) here are configured to ' +
        'authenticate through it.'
      : 'NO application here is configured to authenticate through it. It is ' +
        'still reachable at /federation/login/' + row.id + ', which needs no ' +
        'configuration to reach.');
    if (row.unattributed) {
      parts.push(row.unattributed + ' of its ' + row.authentications +
                 ' sign-in(s) named no application this service is configured ' +
                 'for, so they belong to no application row: somebody used the ' +
                 'partner buttons on the sign-in screen, reached ' +
                 '/federation/login/' + row.id + ' directly, or named an ' +
                 'application that does not point here.');
    }
  }
  // The state, in words, because the picture says it in colour.
  parts.push(row.usable ? 'It is enabled and fully configured.'
    : !row.enabled
        ? 'IT IS DISABLED. Every relationship is created disabled deliberately ' +
          'and does nothing until it is enabled.'
        : 'IT IS ENABLED AND NOT FULLY CONFIGURED: ' + row.missing.join(', ') +
          ' still to set. It REFUSES rather than half-working.');
  if (row.lastError) {
    parts.push('Last refusal: ' + row.lastError);
  }
  return parts.join(' ');
}

// ---------------------------------------------------------------------------
// RENDER. graph -> { svg, width, height, nodes, edges }.
//
//   graph     federation_graph.js's graph()
//   options   `resolve(node)`, which may add an `href` and override a label;
//             `links`, which wraps every box in an <a> to its page in this
//             console; `id`, a prefix for every generated id in the document,
//             because two pictures in one HTML page would otherwise share
//             <defs> ids and the second one's arrowheads would be the first
//             one's; and `label`, the document's own accessible title.
//
// IT CANNOT THROW. The whole body is wrapped and a failure comes back as a
// picture SAYING it could not be drawn — `delegation_map.js`'s rule and its
// reason: a drawing on a console page must not be able to take the page down.
// Everything else on /admin/federation/map is built from the same graph WITHOUT
// going through the layout, so the tables are worth reading with no picture
// above them, and a stack trace where the diagram should be is worth less than
// a sentence.
// ---------------------------------------------------------------------------
function render(graph, options) {
  log.debug("Entering render().");
  try {
    const svg = renderUnguarded(graph || { nodes: [], edges: [] }, options || {});
    log.debug("Leaving render(). " + svg.svg.length + " bytes of SVG, " +
              svg.width + "x" + svg.height + ".");
    return svg;
  } catch (e) {
    log.error('federation map: the picture could not be drawn and the page was ' +
              'left alone: ' + e.message);
    return {
      svg: '<p class="err">The picture could not be drawn: ' + esc(e.message) +
           '. Everything below is unaffected — the tables are built from the ' +
           'same graph and do not go through the layout.</p>',
      width: 0, height: 0, nodes: 0, edges: 0, failed: e.message
    };
  }
}

function renderUnguarded(graph, options) {
  log.debug("Entering renderUnguarded().");
  const prefix = String(options.id || 'fd');
  const nodes = graph.nodes || [];
  const edges = graph.edges || [];

  // `multigraph` because one application may name TWO relationships to one
  // partner, and those are two lines between the same pair of boxes. dagre
  // without it keeps one, and the picture would silently say there is one
  // arrangement where there are two — which on this page is the whole point.
  // `compound` is off: there are no nested boxes here.
  const g = new dagre.graphlib.Graph({ multigraph: true });
  g.setGraph({
    rankdir: 'LR', nodesep: NODE_SEP, edgesep: EDGE_SEP, ranksep: RANK_SEP,
    marginx: MARGIN, marginy: MARGIN
  });
  g.setDefaultEdgeLabel(function () { return {}; });

  const drawn = {};
  nodes.forEach(function (node) {
    const look = lookOf(node, options);
    const size = measure(look);
    drawn[node.id] = { node: node, look: look, size: size };
    g.setNode(node.id, { width: size.width, height: size.height });
  });

  // ---------------------------------------------------------------------
  // THE LABELS ARE GIVEN TO DAGRE RATHER THAN PLACED AFTERWARDS, and that is
  // the whole reason this file has no lane-assignment code in it.
  //
  // `delegation_map.js` has about a hundred lines that hand out rows and lanes
  // so that two labels do not land on top of each other. It needs them because
  // it took the coordinate pass away from dagre — every party is on one
  // centreline there, so dagre no longer knows where anything is and cannot
  // reserve room for anything.
  //
  // This picture keeps dagre's coordinates, so it can simply say how big each
  // label is: dagre gives an edge label a rank of its own and routes around it.
  // The result is the same guarantee for none of the code, and it is the reason
  // `ranksep` is generous — that gap is where the labels live.
  // ---------------------------------------------------------------------
  const labels = {};
  edges.forEach(function (edge) {
    if (!drawn[edge.from] || !drawn[edge.to] || edge.from === edge.to) {
      return;
    }
    const lines = edgeLabelLines(edge);
    let w = 0;
    lines.forEach(function (one) {
      w = Math.max(w, textWidth(one, EDGE_SIZE));
    });
    labels[edge.id] = {
      lines: lines,
      width: w + LABEL_PAD_X * 2,
      height: lines.length * (LINE_HEIGHT - 1) + LABEL_PAD_Y * 2
    };
    g.setEdge(edge.from, edge.to,
              { width: labels[edge.id].width, height: labels[edge.id].height,
                labelpos: 'c' },
              edge.id);
  });

  dagre.layout(g);

  const info = g.graph();
  const width = Math.max(1, Math.ceil(info.width || 0));
  const height = Math.max(1, Math.ceil(info.height || 0));

  const defs = '<defs>' + ARROW_COLOURS.map(function (colour) {
    return '<marker id="' + prefix + '-' + markerId(colour) +
      '" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" ' +
      'orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" fill="' + colour +
      '"/></marker>';
  }).join('') + '</defs>';

  const edgeMarkup = edges.map(function (edge) {
    if (!labels[edge.id]) {
      return '';
    }
    const laid = g.edge({ v: edge.from, w: edge.to, name: edge.id });
    if (!laid || !laid.points || laid.points.length < 2) {
      return '';
    }
    return edgeMarkupFor(edge, laid, labels[edge.id], prefix);
  }).join('');

  const nodeMarkup = nodes.map(function (node) {
    const at = g.node(node.id);
    if (!at) {
      return '';
    }
    return nodeMarkupFor(drawn[node.id], at, options);
  }).join('');

  // `role="img"` and a `<title>` first, because the document is served on its
  // own at `?format=svg` as well as inline — and a picture with no accessible
  // name is a picture a screen reader announces as "graphic".
  const svg = '<svg xmlns="http://www.w3.org/2000/svg" ' +
    'xmlns:xlink="http://www.w3.org/1999/xlink" ' +
    'viewBox="0 0 ' + width + ' ' + height + '" width="' + width +
    '" height="' + height + '" role="img" font-family="system-ui, sans-serif">' +
    '<title>' + esc(options.label || 'Federation relationships') + '</title>' +
    defs + edgeMarkup + nodeMarkup + '</svg>';

  log.debug("Leaving renderUnguarded(). " + nodes.length + " box(es), " +
            Object.keys(labels).length + " line(s).");
  return { svg: svg, width: width, height: height,
           nodes: nodes.length, edges: Object.keys(labels).length, failed: '' };
}

// A line, its arrowhead and its words. dagre hands back the points; the path is
// a simple polyline through them rather than a spline, because a spline through
// four points that dagre already routed around the boxes buys nothing and can
// bow back INTO one.
function edgeMarkupFor(edge, laid, label, prefix) {
  log.debug("Entering edgeMarkupFor().");
  const look = edgeLook(edge);
  const d = laid.points.map(function (point, i) {
    return (i === 0 ? 'M' : 'L') + round(point.x) + ' ' + round(point.y);
  }).join('');
  const path = '<path d="' + d + '" fill="none" stroke="' + look.colour +
    '" stroke-width="' + look.weight + '"' +
    (look.dash ? ' stroke-dasharray="' + look.dash + '"' : '') +
    ' marker-end="url(#' + prefix + '-' + markerId(look.colour) + ')"/>';

  const x = laid.x == null ? laid.points[Math.floor(laid.points.length / 2)].x : laid.x;
  const y = laid.y == null ? laid.points[Math.floor(laid.points.length / 2)].y : laid.y;
  const top = y - label.height / 2;
  const panel = '<rect x="' + round(x - label.width / 2) + '" y="' + round(top) +
    '" width="' + round(label.width) + '" height="' + round(label.height) +
    '" rx="3" fill="' + PAPER + '" fill-opacity="0.92" stroke="' + LINE +
    '" stroke-width="0.6"/>';
  const words = label.lines.map(function (one, i) {
    return '<text x="' + round(x) + '" y="' +
      round(top + LABEL_PAD_Y + (i + 1) * (LINE_HEIGHT - 1) - 3) +
      '" text-anchor="middle" font-size="' + EDGE_SIZE + '" fill="' +
      (i === 0 ? INK : QUIET) + '">' + esc(one) + '</text>';
  }).join('');

  log.debug("Leaving edgeMarkupFor().");
  return '<g><title>' + esc(edgeTitle(edge)) + '</title>' + path + panel +
         words + '</g>';
}

// One box. `at` is dagre's, and dagre gives a CENTRE where every shape below is
// drawn from its top left — so the conversion happens once, here, rather than in
// each shape.
function nodeMarkupFor(entry, at, options) {
  log.debug("Entering nodeMarkupFor().");
  const look = entry.look;
  const size = entry.size;
  const x = at.x - size.width / 2;
  const y = at.y - size.height / 2;
  const dash = look.dashed ? ' stroke-dasharray="6 3"' : '';

  const shape = look.shape === 'hexagon'
    ? '<path d="' + hexPath(x, y, size.width, size.height) + '" fill="' +
      (look.fill || PAPER) + '" stroke="' + look.colour +
      '" stroke-width="1.6"' + dash + '/>'
    : '<rect x="' + round(x) + '" y="' + round(y) + '" width="' +
      round(size.width) + '" height="' + round(size.height) +
      '" rx="5" fill="' + (look.fill || PAPER) + '" stroke="' + look.colour +
      '" stroke-width="1.6"' + dash + '/>';

  const textH = size.lines.length * LINE_HEIGHT +
                (size.subLines.length ? size.subLines.length * (LINE_HEIGHT - 2) + 2 : 0);
  const textTop = y + (size.height - textH) / 2 + LINE_HEIGHT - 3;
  const cx = x + size.width / 2;
  const texts = size.lines.map(function (one, i) {
    return '<text x="' + round(cx) + '" y="' + round(textTop + i * LINE_HEIGHT) +
      '" text-anchor="middle" font-size="' + LABEL_SIZE +
      '" font-weight="600" fill="' + INK + '">' + esc(one) + '</text>';
  }).join('') + size.subLines.map(function (one, i) {
    return '<text x="' + round(cx) + '" y="' +
      round(textTop + size.lines.length * LINE_HEIGHT + i * (LINE_HEIGHT - 2)) +
      '" text-anchor="middle" font-size="' + SUB_SIZE + '" fill="' + QUIET +
      '">' + esc(one) + '</text>';
  }).join('');

  const body = '<title>' + esc(look.title || entry.node.id) + '</title>' +
               shape + texts;

  // A LINK ONLY WHEN THE CALLER ASKED FOR ONE, and it is `delegation_map.js`'s
  // reason unchanged: the picture is served two ways — inline in the console
  // page, where a box should go to that party's page, and as a standalone
  // document at ?format=svg, where the href would be a root-relative path in a
  // file somebody has saved. `app.js` rewrites root-relative links into the
  // current realm on the way out of a `text/html` response ONLY, so a link in a
  // standalone SVG would also be a link that quietly left the realm.
  if (options.links && look.href) {
    log.debug("Leaving nodeMarkupFor().");
    return '<a href="' + esc(look.href) + '">' + body + '</a>';
  }
  log.debug("Leaving nodeMarkupFor().");
  return '<g>' + body + '</g>';
}

module.exports = {
  render: render,
  // Exported for the legend on the page, so that the swatch beside "a foreign
  // identity provider" and the shape in the picture cannot come to be drawn from
  // two different palettes — `delegation_map.js`'s rule, and admin.js draws the
  // key out of these rather than naming the colours a second time.
  COLOURS: { ink: INK, indigo: INDIGO, green: GREEN, amber: AMBER, red: RED,
             quiet: QUIET, line: LINE, panel: PANEL, paper: PAPER, wash: WASH },
  hexPath: hexPath
};
