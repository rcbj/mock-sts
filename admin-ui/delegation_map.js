'use strict';
//
// File: delegation_map.js
//
// ---------------------------------------------------------------------------
// THE DELEGATION PICTURE. `common/delegation.js`'s graph, drawn.
//
// It is a LIBRARY, like `admin_rbac.js` next door and like `dpop.js`,
// `admin_stats.js` and `audit.js` in common/: it registers no route, so its
// position in the require order does not matter and it cannot be the reason a
// route is missing. `admin.js` registers `/admin/delegation/map` and calls
// `render()`; this file holds the geometry and none of the console's HTML.
//
// It requires `../common/helpers` (for `log` and `xmlEscape`) and `@dagrejs/dagre`,
// and NOTHING ELSE IN THIS SERVICE — no config, no directory, no store. That is
// deliberate and it is the whole reason this is a separate file: everything it
// draws arrives as an argument, so the picture can be drawn of any graph the
// caller can build, and a change to how the console decides what a box IS
// cannot reach the code that decides where a box GOES.
//
// ---------------------------------------------------------------------------
// WHY THERE IS A DEPENDENCY HERE AT ALL, WEIGHED THE WAY `scimmy` AND
// `swagger-ui-dist` WERE WEIGHED IN scim/CLAUDE.md AND mgmt-api/CLAUDE.md.
//
// `@dagrejs/dagre` is 1.4 MB unpacked with ONE dependency (`@dagrejs/graphlib`,
// 0.5 MB) and no transitive tail, no install script and no telemetry — nearer
// `scimmy`'s 735 KB than `swagger-ui-dist`'s 11.7 MB, in a package.json that is
// deliberately short and an image built where the registry may be the only
// thing reachable.
//
// **WHAT IT BRINGS IS THE HALF THAT IS ACTUALLY HARD**, and it is not the
// drawing. Laying a directed graph out in layers is the Sugiyama method and it
// is four passes — break the cycles, assign a rank to every node, ORDER each
// rank so that the lines cross as few times as possible, then assign
// coordinates so the ranks line up and the long edges run straight. The third
// of those is the one that decides whether a picture of eleven chains is
// readable or is a ball of wool, and a hand-rolled version of it is the kind of
// thing that looks right on the three-node example somebody tests it with. This
// service already has three chains' worth of that example; a real one has
// forty.
//
// **WHAT IT DOES NOT BRING IS THE DRAWING, AND THAT IS WHY IT IS THE RIGHT
// LIBRARY.** dagre computes positions and edge routes and emits no markup at
// all, so every shape below is this file's own — which is what the ask needed:
// Graphviz would have laid it out just as well and would have drawn its own
// boxes, and a STICK FIGURE is not one of its shapes. The alternative to a
// layout library was not "draw it by hand", it was "invent a layout algorithm";
// the alternative to a drawing library is one `<path>` per person, which is
// forty lines and is in `personGlyph()` below.
//
// **AND IT KEEPS THE CSP RULE INTACT.** The root CLAUDE.md's second CSP rule
// says a scripted page needs its argument made again from scratch, and the
// console has never needed one. A client-side graph library — mermaid,
// cytoscape, d3 — would have made this the FIFTH scripted page in the service
// and the first one in the console, to draw a picture that does not move. The
// SVG here is generated on the server and arrives as markup, so
// `script-src 'none'` is untouched and `img-src` is not even reached: the
// document is inline in the page rather than fetched.
// ---------------------------------------------------------------------------
//
// ---------------------------------------------------------------------------
// THE SHAPES, AND THE ONE THAT NEEDED A DECISION.
//
//   * A PERSON is a stick figure. Anything with an entry under `ou=users`.
//   * AN APPLICATION is a rectangle. Anything with an entry under
//     `ou=applications`.
//   * THIS SERVICE is a hexagon, and it carries the TRUST REALM, because a realm
//     is a whole logical copy of this service and the picture of one realm is
//     not the picture of another.
//   * A PARTY THE DIRECTORY HAS NEVER HEARD OF is drawn in the shape its ROLE
//     implies — an initial identity as a person, a target as an application —
//     with a DASHED outline and a note saying so. That is the three-state rule
//     `delegationPartyCell()` already follows in the table, kept rather than
//     collapsed: an RFC 8693 `audience` nobody has otherwise mentioned is an
//     ordinary and interesting thing to see, and a picture that drew it exactly
//     like a registered application would be the one place in this console where
//     that distinction was lost.
//
// **THE ONE THAT NEEDED A DECISION IS `both`, AND IT IS THE COMMONEST BOX ON THE
// PICTURE.** `HTTP/frontend.example.com` has an entry under `ou=users` (it
// authenticates, so the funnel files it with the people) AND an entry under
// `ou=applications` (tickets are issued FOR it) — the middle tier of every
// Kerberos chain is both, which is the fact `delegationPartyCell()` exists to
// show and the fact a shape-per-kind picture has no room for. Drawing it as one
// or the other would send half the readers to the wrong page and would quietly
// assert that this service's own model has one slot where it has two. So it is a
// RECTANGLE WITH A FIGURE INSIDE IT: the application's shape, with the person in
// it, which is what the party is.
// ---------------------------------------------------------------------------

const { log, xmlEscape } = require('../common/helpers');
const dagre = require('@dagrejs/dagre');

// ---------------------------------------------------------------------------
// THE PALETTE. The console's own, taken from `page()`'s stylesheet in admin.js
// rather than chosen again here, so that a line in the picture and a word in the
// table beside it mean the same thing by being the same colour.
//
// Two of them are load-bearing rather than decorative and both come off
// `modeCell()`: an IMPERSONATION is amber (`.state-expired`) and a DELEGATION is
// green (`.state-valid`), which is the judgement that file states at length —
// impersonation is the louder of the two not because it is worse but because it
// is the one whose consequence is invisible everywhere else. A reader who has
// learnt that pairing from the table reads it unprompted here.
// ---------------------------------------------------------------------------
const INK = '#222';
const INDIGO = '#12107c';
const GREEN = '#0b6b4f';
const AMBER = '#8a6d00';
const RED = '#b00020';
const GREY = '#8a8a99';
const QUIET = '#666';
const LINE = '#d5d5dd';
const PANEL = '#fbfbfd';
const PAPER = '#fff';
const WASH = '#eceaf6';

// Every stroke colour an edge can take needs an arrowhead of that colour,
// because a marker carries its own fill and cannot inherit the path's. They are
// declared once in <defs> and named by colour rather than by meaning, so that
// changing what an edge MEANS does not leave a marker named after the old idea.
const ARROW_COLOURS = [INDIGO, GREEN, AMBER, RED, GREY];

function markerId(colour) {
  return 'dm-arrow-' + colour.replace('#', '');
}

// ---------------------------------------------------------------------------
// AND EVERY LINE NEEDS A TAIL AS WELL AS A HEAD, WHICH IT DID NOT HAVE UNTIL
// 2026-09-02.
//
// A line here carried its direction in ONE place: the arrowhead, at the far
// end, against the box it points at. That is enough to read a picture of three
// boxes and it is not enough to read one of five — because the question a
// reader actually asks is asked from a BOX and not from a line. Standing at
// `abcapp1` on `/admin/delegation/allowed`, four lines touch it, and every one
// of them meets its perimeter as the same bare stroke: the two it grants leave
// from the same edge, at the same angle, in the same colour, as the two granted
// to it. The only thing that told them apart was several hundred pixels away at
// the other end of a curve that crosses three other curves on the way. So the
// answer to "is this one mine, or somebody's on me" was to trace each line
// across the whole picture, which is exactly the work a drawing exists to save.
//
// So the SOURCE end gets a mark of its own: a small filled disc of the line's
// own colour, sitting on the box the line leaves. It is the ball-and-arrow
// convention, and what recommends it over the alternatives is that it costs no
// new vocabulary — nobody has to be told that the round end is the start and
// the pointed end is the finish, and the picture reads the same at a glance and
// under a hover. The ones weighed against it:
//
//   * A SECOND arrowhead partway along each line. More legible still, and it
//     cannot be a marker: `marker-mid` fires at the path's own vertices, which
//     here are wherever the smoothing put them, so it would have meant a second
//     `<path>` per edge positioned by hand — forty more elements to make one
//     bit of information twice.
//   * A gradient from pale at the tail to full at the head. Subtler than a
//     disc, needs a `<linearGradient>` per edge because the geometry differs,
//     and reads as a colour difference in a picture where colour already MEANS
//     something (see `edgeLook()` — amber is impersonation, red is a refusal).
//   * Starting the line short of the box it leaves. Rejected outright: the
//     fanning note below turns on both ends being clipped to their own box
//     exactly, and a gap at the tail would read as a line to a party that is
//     not quite that one.
//
// The disc is DELIBERATELY SMALLER THAN THE ARROWHEAD, and points nowhere. Two
// marks of equal weight at the two ends of a line is a drawing of a
// relationship with no direction at all, which is the thing being fixed rather
// than a different way of saying it. `markerUnits` is left at its default of
// `strokeWidth` for both, as it always was, so a heavier line gets a
// proportionally heavier tail and the pair keep their ratio.
//
// `refX` is 0 rather than the centre, so the disc sits FORWARD of the path's
// first point along the line rather than straddling it. Edges are painted
// before nodes (see `renderUnguarded()`), so a disc centred on the perimeter
// would have its inner half covered by the box's own fill and would be drawn as
// a half moon.
// ---------------------------------------------------------------------------
const TAIL_SIZE = 5;
const TAIL_R = 4;

function tailId(colour) {
  return 'dm-tail-' + colour.replace('#', '');
}

// ---------------------------------------------------------------------------
// TEXT, WITHOUT A FONT.
//
// Nothing on the server can measure a string in a font the browser has not
// chosen yet, and every box here has to be sized before dagre is asked where to
// put it. So the width is ESTIMATED, per character, and the estimate is
// deliberately generous: a box slightly too wide is a picture with a little more
// air in it, and a box too narrow is a label sticking out of its own rectangle.
//
// The table is three buckets rather than a real font metric because that is all
// the accuracy the decision needs — the label is capped at MAX_LABEL_CHARS and
// wrapped, so the error cannot accumulate over more than about twenty
// characters.
// ---------------------------------------------------------------------------
const NARROW = 'iljtfIr.,:;!|\'`[](){}';
const WIDE = 'mwMW@%';

function textWidth(text, size) {
  log.debug("Entering textWidth().");
  let units = 0;
  const value = String(text == null ? '' : text);
  for (let i = 0; i < value.length; i++) {
    const ch = value.charAt(i);
    if (NARROW.indexOf(ch) >= 0) {
      units += 0.36;
    } else if (WIDE.indexOf(ch) >= 0) {
      units += 0.95;
    } else if (ch >= 'A' && ch <= 'Z') {
      units += 0.73;
    } else {
      units += 0.58;
    }
  }
  log.debug("Leaving textWidth().");
  return units * size;
}

// How many characters of a label are drawn before it is cut. The whole value is
// always in the <title> of the shape, so nothing is LOST by the cut — a hover
// says the rest — and a picture whose boxes are as wide as a
// `did:jwk:eyJrdHkiOi…` is a picture of one box.
const MAX_LABEL_CHARS = 30;

// WRAPPING AN IDENTIFIER, WHICH IS NOT WRAPPING A SENTENCE. There are no spaces
// in `HTTP/frontend.example.com@EXAMPLE.COM`, so a word-wrap would put the whole
// of it on one line and give up. It breaks AFTER a separator instead — the
// characters an identifier is actually built out of — and falls back to a hard
// cut in the middle of an unbroken run, which is what a base64 subject is.
const BREAK_AFTER = '/@.-_:+';

function wrapLabel(text, maxChars, maxLines) {
  log.debug("Entering wrapLabel().");
  const value = String(text == null ? '' : text);
  const lines = [];
  let line = '';
  for (let i = 0; i < value.length; i++) {
    line += value.charAt(i);
    const full = line.length >= maxChars;
    const breakable = BREAK_AFTER.indexOf(value.charAt(i)) >= 0 ||
                      value.charAt(i) === ' ';
    if (full || (breakable && line.length >= maxChars - 6)) {
      lines.push(line);
      line = '';
      if (lines.length === maxLines) {
        break;
      }
    }
  }
  if (line && lines.length < maxLines) {
    lines.push(line);
  }
  if (!lines.length) {
    log.debug("Leaving wrapLabel().");
    return [''];
  }
  // Everything that did not fit, marked on the last line rather than dropped
  // silently. The <title> still carries the whole string.
  const drawn = lines.join('').length;
  if (drawn < value.length) {
    const last = lines.length - 1;
    lines[last] = lines[last].slice(0, Math.max(1, maxChars - 1)) + '…';
  }
  log.debug("Leaving wrapLabel().");
  return lines;
}

function esc(v) {
  return xmlEscape(v == null ? '' : String(v));
}

// ---------------------------------------------------------------------------
// THE METRICS. Every number a box or a line is built out of, in one place, so
// that "the picture is too cramped" is one edit rather than a hunt.
// ---------------------------------------------------------------------------
const LABEL_SIZE = 12;      // a box's own name
const SUB_SIZE = 10;        // the line under it: what kind of thing this is
const EDGE_SIZE = 10;       // a line's label
const LINE_HEIGHT = 13;
const FIGURE_W = 26;        // a stick figure's bounding box
const FIGURE_H = 34;
const BOX_PAD_X = 14;
const BOX_PAD_Y = 8;
const MIN_BOX_W = 88;
const MAX_BOX_W = 260;
const HEX_PAD_X = 22;

// dagre's own knobs. `ranksep` is generous because an edge label sits BETWEEN
// two ranks — dagre reserves a rank of its own for it — and a cramped one puts
// the words of one line on top of the words of the next.
const RANK_SEP = 78;
const NODE_SEP = 26;
const EDGE_SEP = 18;
const MARGIN = 18;

// ---------------------------------------------------------------------------
// THE TWO BANDS, AND WHY THE ISSUER IS NOT IN THE LAYOUT AT ALL.
//
// Until 2026-08-26 the hexagon was one node among the others and dagre gave it a
// rank of its own, so it sat in the FLOW: a person on the left, the issuer in
// the second column, and the applications strung out to the right of it. That
// puts the one box every line touches in the middle of the chain and makes the
// picture a staircase — the parties of one delegation ended up on four
// different vertical positions because the issuer's own edges were competing
// with the chain for the ranking.
//
// So the picture is now two bands. The parties — the person AND every
// application — are laid out by dagre ALONE, which for a chain is the single
// horizontal line it always should have been. The issuer goes above them,
// centred, in a band of its own, and its edges are drawn straight down from it.
// Two things fall out of that and both are the point: every application is on
// one plane, so a reader compares them by looking along a line rather than
// hunting; and the dashed issuer lines all run the same way, so they read as
// one statement — *this service handed those parties something* — rather than
// as a relationship competing with the ones that matter.
//
// `STS_BAND_SEP` is the gap between the bands and it is `RANK_SEP` for the
// reason `RANK_SEP` is generous: an edge label lives in it.
// ---------------------------------------------------------------------------
const STS_BAND_SEP = RANK_SEP;

// ---------------------------------------------------------------------------
// THE PARTIES ARE ONE ROW, AND THE LINES THAT CANNOT FIT IN IT GO UNDER IT.
//
// The band above bought half of what it was for. Taking the issuer out of the
// layout stopped the hexagon competing with the chain for a rank, and a picture
// of ONE chain came out as the single horizontal line it always should have
// been — but the moment the graph BRANCHES it stops being a chain, and dagre
// goes back to spreading the parties vertically because that is what a layered
// layout is for. `bob_end_user`'s picture is the ordinary case: a person who
// signed in at one application and was delegated through two others is four
// boxes at four different heights, and a reader comparing them is hunting up
// and down a staircase for boxes that are all the same KIND of thing.
//
// So the y is taken away from dagre as well. Every party — the person and every
// application — is put on ONE CENTRELINE, and dagre keeps only what it is
// actually good at here: the ORDER of the boxes along it, which is the rank
// assignment and the crossing minimisation, and which is the whole reason the
// library is still worth 1.4 MB. What is thrown away is the coordinate pass,
// and it is thrown away deliberately rather than tuned: `align`, `ranker` and
// `nodesep` can all move the staircase around and none of them can flatten it,
// because a layered layout that put every node on one rank-perpendicular line
// would have nothing left to minimise crossings WITH.
//
// **WHICH IS THE COST, AND IT IS PAID IN THE LINES INSTEAD.** Crossings do not
// disappear because the boxes lined up; a line from the person to the third
// application has to get past the two in between. So a party line is drawn one
// of two ways:
//
//   * STRAIGHT, along the row, when the two boxes are neighbours on it and the
//     gap between them holds the label. That is the common case and it is the
//     one that reads best — a chain becomes a row of boxes joined left to right.
//   * AN ARC UNDER THE ROW otherwise: when a box sits between the two ends,
//     when the pair already has a straight line (two mechanisms between one pair
//     are two lines, and `multigraph` is why they both exist), or when the label
//     is wider than the gap it would have to sit in. It leaves the bottom of one
//     box and enters the bottom of the other, and its label sits at the apex.
//
// The arcs get LANES, assigned exactly the way the issuer's labels above are:
// greedily by x-overlap, fewest first. Two arcs in one lane cannot overlap
// horizontally, so they cannot cross each other; two in different lanes are
// separated vertically. It is the same problem as the labels and the same
// answer, which is why it is the same shape of code.
//
// **UNDER rather than over**, and that is not arbitrary: over is where the
// issuer's band is, and an arc that reached into it would cross seven dashed
// lines and land among their labels. Under the row there is nothing.
// ---------------------------------------------------------------------------
const ARC_LANE_H = 34;
const ARC_GUTTER = 14;
const ARC_PAD = 12;

// ---------------------------------------------------------------------------
// WHERE AN ARC MEETS THE BOX IT LEAVES OR ENTERS — A BERTH, AND UNTIL
// 2026-09-02 EVERY ARC AT ONE BOX SHARED ONE OF TWO.
//
// The rule was: a third of the box's width in from the centre, towards the far
// box. It reads as a spread and it is not one — it is a two-way SORT, so every
// arc whose far end is to the right leaves at one point and every arc whose far
// end is to the left leaves at another. On the ring at
// `/admin/delegation/allowed` that put THREE lines on one pixel of `abcapp1`'s
// bottom edge: the one it grants `abcapp2` leaving, and the two `abcapp5`
// grants it arriving. One tail disc and two arrowheads, drawn on top of each
// other, on a box whose whole question is which of these is mine.
//
// It is the fault the ask names — an outbound line starting exactly where the
// inbound ones come in — and no marking of the ENDS can fix it, because the
// ends were in the same place. So each arc endpoint at a box gets a BERTH of
// its own along that box's bottom edge.
//
// WHICH BERTH AN ARC GETS is decided so that no two arcs off one box cross each
// other on the way out; the rule and the geometry it comes from are with the
// sort itself, in `renderUnguarded()`, because it is about the arcs and this is
// about the edge they share. What is worth saying HERE is what was NOT done:
// the berths are not sorted by DIRECTION — every departure on one half of the
// edge and every arrival on the other. That would say which is which by
// position, which is what the tail disc already says, and it would buy the
// second saying of it by making every arc whose far end is the other way cross
// all of its neighbours.
//
// `BERTH` is the space one wants: wide enough that a tail disc and an arrowhead
// side by side are two marks rather than a blot. It is what a berth gets when
// the box is wide enough to give it; where there are more arcs than the box has
// room for, they share what there is, because a berth outside the box would be
// a line starting in mid-air beside a box rather than from under it.
// `BERTH_PAD` keeps the outermost off the rounded corner, where a line would
// appear to leave the side rather than the bottom.
// ---------------------------------------------------------------------------
const BERTH = 16;
const BERTH_PAD = 9;

// The gap between two boxes on the row: `GAP_PAD` of air on each side of the
// label that lies in it, and `GAP_MIN` where no line lies in it at all. The
// minimum is the one that needs a number rather than a measurement — two boxes
// nothing joins still have to read as two boxes, and `NODE_SEP` alone (which is
// what dagre separated a RANK's members by, in the other direction) is tight
// enough to look like a drawing error.
const GAP_MIN = 46;
const GAP_PAD = 20;

// ---------------------------------------------------------------------------
// WHERE THE ISSUER'S LABELS GO, WHICH IS THE ONE HARD PART OF DRAWING THE BAND.
//
// Every one of those lines starts at the SAME point. Put their labels all at one
// fraction along and they are only as far apart as their boxes are — which on a
// picture with four applications in a row is not far enough, and the first
// version of this band had `signed in` written across `issued to`.
//
// So the labels are given ROWS in the gap, and a line's label is drawn where
// that line crosses its row. Two in one row are separated horizontally by
// construction and two in different rows cannot touch at all, so the only thing
// left to decide is how many rows there are: they are assigned greedily by
// x-overlap, fewest first, and the gap is made tall enough to hold however many
// were needed. A picture whose lines fan out widely — the common one — comes
// back with a single row and a gap no deeper than it ever was.
//
// `MAX_LABEL_ROWS` is a giving-up point rather than a judgement. Past it the
// labels are allowed to overlap, because the alternative is a band taller than
// the picture under it: an issuer with thirty lines out of it is a busy diagram
// however it is drawn, and the tooltip and the tables under it still say
// everything the label does.
// ---------------------------------------------------------------------------
const LABEL_ROW_H = 46;
const LABEL_ROW_PAD = 10;
const LABEL_GUTTER = 10;
const MAX_LABEL_ROWS = 5;

// ---------------------------------------------------------------------------
// TWO LINES BETWEEN THE HEXAGON AND ONE PARTY ARE TWO LINES, AND UNTIL
// 2026-08-26 THEY WERE DRAWN ON TOP OF EACH OTHER.
//
// Every issuer line is a straight segment clipped to the two boxes at its ends,
// so two of them between the SAME pair are the same segment computed twice —
// one path exactly over the other, one arrowhead exactly over the other, and
// nothing in the picture to say there are two. The labels, meanwhile, are
// seated in ROWS by the block above precisely so that they do not collide, so
// what a reader sees is ONE line carrying TWO labels: on
// `bob_end_user`'s page, `signed in / OAuth 2.0 / OIDC / 1 time` above
// `signed in / OAuth 2.0 / 2 times`, which reads as one relationship
// contradicting itself rather than as the two it is (a sign-in at the screen,
// and two token exchanges naming him).
//
// THE CASE ABOVE IS FIXED WHERE IT BELONGS — `user_graph.js` now draws ONE
// sign-in line per person with the families listed on it, rather than one line
// per family — because two lines saying the same thing about the same pair is a
// fact about the GRAPH and not about the drawing. This stays, because the
// drawing has to survive the shapes it cannot fold: a party can hold a line
// INTO the hexagon and another back OUT of it (a client that authenticated as
// itself, drawn as `signed in` one way and `issued for` the other; the middle
// tier of a Kerberos chain, which both authenticates and is issued to), and
// those are the same segment with the arrowheads at opposite ends. Nothing in
// the renderer may assume the graph handed to it has folded anything.
//
// So the lines of one party are FANNED at the hexagon: each is aimed at a point
// `STS_FAN_SEP` to one side of the issuer's centre, spread about it, which
// separates them where they leave the hexagon and lets them converge on the one
// party. The hexagon end is the end that is fanned deliberately — the label
// rows are in the band immediately under it, so that is where the lines need to
// be furthest apart. Both ends are still clipped to their own box exactly (see
// `crossingPoint()`), so nothing gains a gap between an arrowhead and the shape
// it points at, and the label of a fanned line is seated on the line it belongs
// to because `fitLabels()` interpolates along the SAME aim.
//
// The separation is capped by the hexagon's own width rather than taken as
// given: the aim has to stay inside the shape, or the line it describes would
// leave the hexagon nowhere near it.
// ---------------------------------------------------------------------------
const STS_FAN_SEP = 26;
const STS_FAN_MARGIN = 12;

// How many entries a sign-in line's list draws before it counts the rest, and
// how wide one of them is allowed to be. See `signedInLines()`.
const SIGNED_IN_ENTRIES = 3;
// Wide enough for the longest entry the service can actually produce —
// `2 × Kerberos (AS-REQ with PA-ENC-TIMESTAMP)` — because the mechanism is the
// half of the entry that stops `OAuth 2.0 ×2` reading as two sign-ins, and an
// ellipsis through it puts the misleading half on the picture and the useful
// half in the tooltip.
const SIGNED_IN_CHARS = 44;

// ---------------------------------------------------------------------------
// WHAT A BOX LOOKS LIKE, AND HOW BIG IT IS.
//
// One function answers both, because they are the same question asked twice and
// two functions would be two chances for the drawing to be a shape the layout
// did not reserve room for. `measure()` returns the size AND the wrapped lines,
// and the drawing below takes both rather than re-wrapping.
// ---------------------------------------------------------------------------
function measure(node, look) {
  log.debug("Entering measure().");
  const lines = wrapLabel(look.label, MAX_LABEL_CHARS, 2);
  // TWO SUB-LINES AT MOST, AND THEY ARE DIFFERENT SENTENCES. The first is what
  // kind of thing this is — `application`, `person + application` — and the
  // second, added 2026-08-27, is the IDENTIFIER a protocol would have to
  // present to reach it, with that protocol's own word for it: `client_id:
  // acme-web`, `AppliesTo: https://esb.example.com`. They are concatenated
  // rather than joined into one string because they wrap independently: an
  // entityID is a URL and would otherwise push `application` off its own line.
  //
  // The caller decides whether there is a second one at all (see
  // `delegationNodeLook()` in admin.js — a box whose LABEL is already the
  // identifier gets the word alone, or nothing), so this is a list and not a
  // pair of fields, and everything below counts `subLines.length` rather than
  // asking whether there is one.
  //
  // The identifier gets TWO lines where the kind gets one, and that is not
  // generosity: the kind is a word from a closed list and an identifier is
  // whatever a protocol allows — `entityID / AppliesTo:
  // https://esb.example.com` is 44 characters and would otherwise be cut to
  // `entityID / AppliesTo: https://…`, which keeps the half a reader already
  // knew and throws away the half they opened the picture for.
  const subLines = (look.sublabel ? wrapLabel(look.sublabel, MAX_LABEL_CHARS + 6, 1) : [])
    .concat(look.identifier ? wrapLabel(look.identifier, MAX_LABEL_CHARS + 6, 2) : []);
  let textW = 0;
  lines.forEach(function (one) {
    textW = Math.max(textW, textWidth(one, LABEL_SIZE));
  });
  subLines.forEach(function (one) {
    textW = Math.max(textW, textWidth(one, SUB_SIZE));
  });
  const textH = lines.length * LINE_HEIGHT +
                (subLines.length ? subLines.length * LINE_HEIGHT - 2 : 0);

  if (look.shape === 'person') {
    // The figure sits above the name rather than beside it. A person's label is
    // a username and is short; a figure to the left of it would make every
    // person-box a wide rectangle in a picture where a rectangle already means
    // something else.
    log.debug("Leaving measure().");
    return {
      shape: 'person',
      width: Math.min(MAX_BOX_W, Math.max(MIN_BOX_W, textW + BOX_PAD_X * 2)),
      height: FIGURE_H + 6 + textH + BOX_PAD_Y,
      lines: lines, subLines: subLines
    };
  }
  if (look.shape === 'sts') {
    log.debug("Leaving measure().");
    return {
      shape: 'sts',
      width: Math.min(MAX_BOX_W + 40, Math.max(MIN_BOX_W + 40, textW + HEX_PAD_X * 2 + 26)),
      height: Math.max(58, textH + BOX_PAD_Y * 2 + 8),
      lines: lines, subLines: subLines
    };
  }
  // `application` and `both`. The second is the first with a figure inside it,
  // so it is the same rectangle with room made on the left.
  const inset = look.shape === 'both' ? FIGURE_W + 8 : 0;
  log.debug("Leaving measure().");
  return {
    shape: look.shape === 'both' ? 'both' : 'application',
    width: Math.min(MAX_BOX_W, Math.max(MIN_BOX_W, textW + BOX_PAD_X * 2 + inset)),
    height: Math.max(36, textH + BOX_PAD_Y * 2),
    lines: lines, subLines: subLines
  };
}

// A STICK FIGURE. Head, spine, arms, legs, drawn around (0,0) at its own top
// left. `stroke-linecap:round` is what stops the limbs looking like a diagram of
// a bridge.
function personGlyph(x, y, colour, dashed, scale) {
  log.debug("Entering personGlyph().");
  const s = scale || 1;
  const w = FIGURE_W * s;
  const h = FIGURE_H * s;
  const cx = x + w / 2;
  const headR = 4.6 * s;
  const headY = y + headR + 1;
  const neck = headY + headR;
  const hip = y + h * 0.62;
  const foot = y + h - 1;
  const arm = w / 2 - 1;
  const dash = dashed ? ' stroke-dasharray="3 2"' : '';
  log.debug("Leaving personGlyph().");
  return '<g fill="none" stroke="' + colour + '" stroke-width="' + (1.6 * s) +
    '" stroke-linecap="round"' + dash + '>' +
    '<circle cx="' + round(cx) + '" cy="' + round(headY) + '" r="' + round(headR) + '"/>' +
    '<path d="M' + round(cx) + ' ' + round(neck) + 'V' + round(hip) +
      'M' + round(cx - arm) + ' ' + round(neck + 4 * s) +
      'H' + round(cx + arm) +
      'M' + round(cx) + ' ' + round(hip) + 'L' + round(cx - arm) + ' ' + round(foot) +
      'M' + round(cx) + ' ' + round(hip) + 'L' + round(cx + arm) + ' ' + round(foot) +
    '"/>' +
    '</g>';
}

// A HEXAGON, for this service. Flat-topped, which is the shape nothing else here
// is: a rectangle is an application, a rounded rectangle would read as one, and
// a circle beside a stick figure's head reads as a second person.
function hexPath(x, y, w, h) {
  const cut = Math.min(22, w / 4);
  return 'M' + round(x + cut) + ' ' + round(y) +
    'H' + round(x + w - cut) +
    'L' + round(x + w) + ' ' + round(y + h / 2) +
    'L' + round(x + w - cut) + ' ' + round(y + h) +
    'H' + round(x + cut) +
    'L' + round(x) + ' ' + round(y + h / 2) + 'Z';
}

function round(n) {
  return Math.round(n * 10) / 10;
}

// WHERE A LINE LEAVES A BOX. The point at which the segment from that box's
// centre towards `towards` crosses the box's own edge, so an arrowhead sits on
// the boundary rather than under the label in the middle. dagre does this for
// the lines it routes; these are the ones it never saw.
function boundaryPoint(at, size, towards) {
  log.debug("Entering boundaryPoint().");
  const dx = towards.x - at.x;
  const dy = towards.y - at.y;
  if (!dx && !dy) {
    // Two boxes on top of each other, which nothing here produces — but a
    // divide by zero would put NaN in an SVG path, and a path with NaN in it
    // draws NOTHING at all rather than drawing something visibly wrong.
    log.debug("Leaving boundaryPoint(). The two boxes share a centre.");
    return { x: at.x, y: at.y };
  }
  const hw = size.width / 2;
  const hh = size.height / 2;
  const scale = Math.min(dx ? hw / Math.abs(dx) : Infinity,
                         dy ? hh / Math.abs(dy) : Infinity);
  log.debug("Leaving boundaryPoint().");
  return { x: at.x + dx * scale, y: at.y + dy * scale };
}

// ---------------------------------------------------------------------------
// WHERE A LINE REACHES A BOX IT IS AIMED INTO BUT NOT AT THE CENTRE OF.
//
// `boundaryPoint()` above scales a ray that STARTS at a box's own centre, which
// is every line in the picture but the fanned ones: those are aimed at a point
// `STS_FAN_SEP` to one side of the hexagon's centre, so the ray they travel on
// does not pass through it and scaling it would land beside the shape. This
// clips the segment against the box's two slabs instead and answers with the
// point where it ENTERS — the far side is behind the shape and is never the
// one wanted.
//
// `aim` is INSIDE the box (the fan is capped so that it is), so there is always
// a crossing; a caller that passed one outside would get the entry of the
// extended line, which is still on the boundary.
// ---------------------------------------------------------------------------
function crossingPoint(from, aim, centre, size) {
  log.debug("Entering crossingPoint().");
  const dx = aim.x - from.x;
  const dy = aim.y - from.y;
  if (!dx && !dy) {
    // The same divide-by-zero guard boundaryPoint() carries, for the same
    // reason: NaN in a path draws nothing at all.
    log.debug("Leaving crossingPoint(). The line has no length.");
    return { x: from.x, y: from.y };
  }
  const hw = size.width / 2;
  const hh = size.height / 2;
  const spans = [];
  if (dx) {
    spans.push(((centre.x + (dx > 0 ? -hw : hw)) - from.x) / dx);
  }
  if (dy) {
    spans.push(((centre.y + (dy > 0 ? -hh : hh)) - from.y) / dy);
  }
  // The LATER of the two entries is the one that is on the box: a segment
  // crosses the x slab and the y slab at two different points and only the
  // second of them is inside both.
  const t = Math.max.apply(null, spans);
  log.debug("Leaving crossingPoint().");
  return { x: from.x + dx * t, y: from.y + dy * t };
}

// ---------------------------------------------------------------------------
// AN EDGE'S ROUTE. dagre hands back the points a line should pass through — one
// per rank it crosses, including the invisible ranks it made for the labels —
// and a polyline through them has a corner at every one.
//
// So they are smoothed: a curve through the MIDPOINTS of consecutive segments,
// with each original point as the control. That is the standard trick and it has
// one property worth the two lines it costs — the curve touches the first and
// last points exactly, so a line still starts on the edge of the box it leaves
// and ends on the edge of the box it enters, which is the one thing a reader
// would notice if it were approximate.
// ---------------------------------------------------------------------------
function edgePath(points) {
  log.debug("Entering edgePath().");
  if (!points || points.length < 2) {
    log.debug("Leaving edgePath().");
    return '';
  }
  if (points.length === 2) {
    log.debug("Leaving edgePath().");
    return 'M' + round(points[0].x) + ' ' + round(points[0].y) +
           'L' + round(points[1].x) + ' ' + round(points[1].y);
  }
  let d = 'M' + round(points[0].x) + ' ' + round(points[0].y);
  for (let i = 1; i < points.length - 1; i++) {
    const midX = (points[i].x + points[i + 1].x) / 2;
    const midY = (points[i].y + points[i + 1].y) / 2;
    d += 'Q' + round(points[i].x) + ' ' + round(points[i].y) + ' ' +
         round(midX) + ' ' + round(midY);
  }
  const last = points[points.length - 1];
  d += 'L' + round(last.x) + ' ' + round(last.y);
  log.debug("Leaving edgePath().");
  return d;
}

// ---------------------------------------------------------------------------
// WHAT COLOUR A LINE IS, AND WHY.
//
// Read in this order and the first match wins, which is itself the judgement:
//
//   1. NOTHING WAS EVER ISSUED ON IT — red. A chain that has only ever been
//      refused is the row a person came to this page to find, and it is the one
//      state that must survive being glanced at.
//   2. IT CAME FROM THE ISSUER — grey, dashed. This is not a delegation
//      relationship, it is "this service handed that party something", and
//      drawing it in the same weight as the relationships would make the
//      hexagon the busiest thing in the picture.
//   3. IT IS A DELEGATION RELATIONSHIP — the MODE's colour, amber or green, the
//      pairing modeCell() uses in the table.
//   4. IT IS A TRUST RELATIONSHIP — indigo, the console's own colour. What this
//      line says is what the credential was FOR, which is a fact about this
//      service rather than about either party.
// ---------------------------------------------------------------------------
function edgeLook(edge) {
  log.debug("Entering edgeLook().");
  if (edge.acts && !edge.issued) {
    log.debug("Leaving edgeLook().");
    return { colour: RED, dash: '5 3', weight: 1.6 };
  }
  if (edge.relation === 'issued') {
    log.debug("Leaving edgeLook().");
    return { colour: GREY, dash: '4 3', weight: 1.2 };
  }
  // ---------------------------------------------------------------------------
  // THE TWO RELATIONS THE PERSON'S PICTURE ADDS (common/user_graph.js), and
  // NEITHER OF THEM TAKES A MODE COLOUR. That is the point rather than an
  // omission: amber and green are this file's judgement about impersonation
  // versus delegation, and an ordinary authorization code grant makes no such
  // claim — colouring it green because nothing was impersonated would tell a
  // reader who has learnt the pairing something false.
  //
  //   * `signed-in` — the person authenticated TO this service. DOTTED, because
  //     it is the one line that is not a credential going anywhere; it is how
  //     everything else on the picture came to be allowed.
  //   * `issued-for` — a credential naming this person went to that
  //     application. Solid indigo, the same weight as `reaches`, because it IS
  //     the trust relationship: what this token is FOR, said about a grant
  //     instead of about a delegation.
  // ---------------------------------------------------------------------------
  if (edge.relation === 'signed-in') {
    log.debug("Leaving edgeLook().");
    return { colour: INDIGO, dash: '2 3', weight: 1.4 };
  }
  if (edge.relation === 'issued-for') {
    log.debug("Leaving edgeLook().");
    return { colour: INDIGO, dash: '', weight: 1.6 };
  }
  // ---------------------------------------------------------------------------
  // THE RELATION THE CONFIGURED PICTURE ADDS (common/app_permissions.js), and
  // it is the FIRST line in this renderer that is not about something that
  // happened. Every other look above describes an act: a credential was issued,
  // refused, or carried a chain. A `may-reach` line says a client application
  // has been GRANTED a permission on a resource application and nothing more —
  // nobody has asked for it, no token exists, and there is no person anywhere
  // in it.
  //
  // **IT TAKES NO MODE COLOUR**, for `signed-in`'s reason said about a
  // different absence: amber and green are this file's judgement about
  // impersonation versus delegation, and a permission that has never been
  // exercised has performed neither. Colouring it green would tell a reader who
  // has learnt the pairing something false.
  //
  // **DASHED UNTIL IT HAS BEEN USED, SOLID AFTERWARDS**, and that one bit is
  // the most useful thing the configured picture says. `asked` is set when the
  // client's own entry records having requested that permission in a `scope`,
  // so a dashed line is a grant nobody has needed — which is the reading a
  // configuration register exists for and the one an acts diagram can never
  // give, because a grant nobody used draws no act at all.
  if (edge.relation === 'may-reach') {
    log.debug("Leaving edgeLook().");
    return { colour: INDIGO, dash: edge.asked ? '' : '6 4', weight: 1.5 };
  }
  if (edge.relation === 'acts-for') {
    const colour = edge.mode === 'impersonation' ? AMBER
                 : edge.mode === 'delegation' ? GREEN : INDIGO;
    // A jumped role is drawn as a broken line WHATEVER the mode, because the
    // thing being said is that part of this line is not known: an unconstrained
    // delegation reaches its target through a service this KDC was never told
    // the name of, and a solid line would assert a hop that nobody can name.
    log.debug("Leaving edgeLook().");
    return { colour: colour, dash: (edge.skipped || []).length ? '7 4' : '', weight: 1.8 };
  }
  log.debug("Leaving edgeLook().");
  return { colour: INDIGO, dash: (edge.skipped || []).length ? '7 4' : '', weight: 1.6 };
}

// The words on a line. Up to three short ones — what kind of relationship, the
// mechanism, and how it came out — because everything else is in the <title> and
// in the tables under the picture. A fourth line was tried and it is what turns
// a diagram into a page of text laid out badly.
//
// THE ONE EXCEPTION IS THE SIGN-IN LINE, which is allowed a fourth and a fifth
// because it is the one line that ABSORBED others: there was a line per
// protocol family until 2026-08-26, each with three lines of label, and they
// joined the same two boxes and were therefore drawn on top of each other. The
// list it carries instead is shorter than what it replaced.
function edgeLabelLines(edge, labelOf) {
  log.debug("Entering edgeLabelLines().");
  const lines = [];
  if (edge.relation === 'issued') {
    lines.push('issued to');
    if (edge.protocols && edge.protocols.length) {
      lines.push(edge.protocols.join(', '));
    }
  } else if (edge.relation === 'signed-in') {
    // ONE STATEMENT AND THEN A LIST — see `signedInLines()`. There is exactly
    // one of these lines per person, and what varies is on it: `1 × OAuth 2.0 /
    // OIDC (sign-in screen)`, `2 × OAuth 2.0 (token exchange)`.
    lines.push('signed in');
    signedInLines(edge).forEach(function (one) {
      lines.push(one);
    });
  } else if (edge.relation === 'issued-for') {
    // AND THE GRANT, WHICH IS THE WHOLE LABEL. `typeLabel` carries the flow's
    // own name — `Authorization Code grant`, `Refresh Token grant` — so this is
    // the same expression the mechanism gets on a delegation line, which is
    // what makes the two read as one picture.
    lines.push(edge.typeLabel ? shortType(edge.typeLabel) : 'issued for');
  } else if (edge.relation === 'may-reach') {
    // THE PERMISSION IS THE WHOLE LABEL, and it is the NAME rather than the
    // identifier: the base URI is what the box at the far end is called, so
    // repeating it on every line into that box would be the same forty
    // characters drawn once per edge. The `<title>` carries the identifier.
    lines.push('may reach');
    if (edge.permissionName) {
      lines.push(trim(edge.permissionName, 22));
    }
    // AND WHETHER IT HAS EVER BEEN ASKED FOR, said in words as well as in the
    // dash. A picture that carried the distinction only in a line style would
    // be one where the single most useful thing on it was invisible to anybody
    // who had not read the key.
    lines.push(edge.asked ? 'asked for' : 'never asked for');
    if (edge.typeLabel) {
      lines.push(shortType(edge.typeLabel));
    }
  } else {
    lines.push(edge.subject
      ? 'reaches as ' + trim(labelOf(edge.subject), 20) : 'reaches');
    // AND WHAT IT MAY DO THERE, on every line that came out of a CREDENTIAL.
    //
    // `user_graph.js` puts a `permissions` array on a `reaches` line it built
    // from a token and the identical relation out of `delegation.js` carries
    // none, which is what this test is: an ACT has no scope claim behind it, so
    // a line about one has nothing to say here and says nothing rather than
    // saying `default permissions` about a Kerberos ticket.
    //
    // **AN EMPTY ARRAY IS AN ANSWER AND IS DRAWN AS ONE.** The token named this
    // resource — by the client_id spelling, which takes the value off the scope
    // claim — and asked for none of its permissions, and `default permissions`
    // is this service's word for that. Leaving the line blank there would make
    // the commonest case indistinguishable from a line the renderer has not
    // been taught about, and it is exactly the distinction the configured
    // picture makes with `never asked for`.
    if (edge.permissions) {
      lines.push(edge.permissions.length
        ? trim(edge.permissions.join(', '), 26)
        : 'default permissions');
    }
    if (edge.typeLabel) {
      lines.push(shortType(edge.typeLabel));
    }
  }
  const counts = [];
  // A CREDENTIAL COUNT WHERE THE LINE IS ABOUT CREDENTIALS, an act count where
  // it is about acts. The two are different units and one column for both would
  // report `3 issued` on a line that carries three tokens and on a line that
  // carries three delegations, which are not comparable numbers.
  if (edge.relation === 'issued-for') {
    if (edge.credentials) {
      counts.push(edge.credentials + ' credential' + (edge.credentials === 1 ? '' : 's'));
    }
  } else if (edge.relation === 'signed-in') {
    // NOTHING. The count used to be here — `2 times` — and it is now on each
    // entry of the list above, where it says what it is a count OF. A total
    // under that list would be a third number on a line that already carries
    // two, and it is the number nobody was asking for: `3 times` across a
    // sign-in and two exchanges is arithmetic rather than a fact. The tooltip
    // still totals them.
  } else {
    if (edge.issued) counts.push(edge.issued + ' issued');
    if (edge.refused) counts.push(edge.refused + ' refused');
    // An `issued` line in a person's picture carries credentials that came out
    // of no delegation act at all, so its act count can be zero while it is the
    // busiest line on the page.
    if (!edge.acts && edge.credentials) {
      counts.push(edge.credentials + ' credential' + (edge.credentials === 1 ? '' : 's'));
    }
  }
  if (counts.length) {
    lines.push(counts.join(', '));
  }
  log.debug("Leaving edgeLabelLines().");
  // THREE, with TWO exceptions and both of them earned rather than granted by
  // analogy. The first is the line that carries a LIST — `signed in` plus its
  // entries, which is what the fold in `user_graph.js` bought: those entries
  // used to be a line each, with three lines of label apiece and every one of
  // them drawn on top of the last.
  //
  // The second is a `reaches` line carrying PERMISSIONS, and it is a fourth
  // line for the same reason the third one is worth having: the permission is
  // the answer to what this relationship IS, and the three that were already
  // there are who it is as, what mechanism issued it, and how many credentials
  // — none of which the permission can be inferred from. Dropping one of those
  // to make room was the alternative and each of them is somebody's reason for
  // reading the picture. Four lines is 44px, which is what the sign-in line
  // already occupies, so the bands below measure it and nothing new is needed.
  return lines.slice(0, edge.relation === 'signed-in' ? SIGNED_IN_ENTRIES + 1
    : edge.permissions ? 4 : 3);
}

// ---------------------------------------------------------------------------
// THE LIST ON A SIGN-IN LINE. One entry per (family, method) pair, busiest
// first, as `user_graph.js` ordered them.
//
// `SIGNED_IN_ENTRIES` is a giving-up point in the same spirit as
// `MAX_LABEL_ROWS`: four lines of label is 44px and the rows the issuer's
// labels are seated in are 46 apart, so a fifth entry is one that would be
// drawn into the row below. Past it the remainder is COUNTED rather than
// dropped — a list that silently stops is a list that reads as complete — and
// the tooltip and the table under the picture carry every entry.
//
// A graph with no `authentications` on the edge falls back to what this line
// said before the fold. That is not defensive dressing: `delegation_map.js`
// draws whatever graph it is handed and the fixtures in
// `tests/delegation_map_bands.js` are written by hand, so an edge with a
// protocol and a count and no list is a shape that really does arrive here.
// ---------------------------------------------------------------------------
function signedInLines(edge) {
  log.debug("Entering signedInLines().");
  const entries = edge.authentications || [];
  const out = [];
  if (!entries.length) {
    if (edge.protocol) {
      out.push(trim(edge.protocol, 26));
    }
    if (edge.acts) {
      out.push(edge.acts + ' time' + (edge.acts === 1 ? '' : 's'));
    }
    log.debug("Leaving signedInLines(). No list on the edge; " + out.length +
              " line(s) from the protocol and the count.");
    return out;
  }
  const shown = entries.length > SIGNED_IN_ENTRIES
    ? entries.slice(0, SIGNED_IN_ENTRIES - 1) : entries;
  shown.forEach(function (one) {
    // `shortType()` on the method for the reason it is used on a mechanism
    // everywhere else here: `sign-in screen (password and a security key)` is a
    // sentence and `sign-in screen` is the noun. The parenthetical is in the
    // tooltip.
    out.push(trim(one.count + ' × ' + one.protocol +
                  (one.method ? ' (' + shortType(one.method) + ')' : ''),
                  SIGNED_IN_CHARS));
  });
  if (shown.length < entries.length) {
    out.push('+' + (entries.length - shown.length) + ' more');
  }
  log.debug("Leaving signedInLines(). " + out.length + " line(s) for " +
            entries.length + " entry/entries.");
  return out;
}

// The mechanism's label, minus the parenthetical the table has room for. Every
// one of the eight is a phrase; the picture wants the noun.
function shortType(label) {
  return trim(String(label).replace(/\s*\(.*\)\s*$/, '').replace(/\s+—.*$/, ''), 26);
}

function trim(text, max) {
  const value = String(text == null ? '' : text);
  return value.length > max ? value.slice(0, max - 1) + '…' : value;
}

// ---------------------------------------------------------------------------
// WHAT THE CALLER SAYS ABOUT A BOX.
//
// `resolve(node)` is supplied by admin.js and answers the ONE question this file
// deliberately cannot: what is this party, as far as the embedded directory is
// concerned. It comes back as
//
//   { shape, label, sublabel, title, href, dashed }
//
// and the default below is what a caller that has no directory gets — the shape
// the ROLE implies, dashed, because "we do not know" is a state and not a
// failure. `spiffe_server.js` and the two SAML modules all pass a resolver of
// their own to somebody; this is the same arrangement and the reason is the one
// in the header: what a party IS belongs to the console, where the registry and
// the directory reader are, and where a box GOES belongs here.
// ---------------------------------------------------------------------------
function defaultResolve(node) {
  if (node.kind === 'sts') {
    return { shape: 'sts', label: 'mock STS', sublabel: '', dashed: false };
  }
  const person = node.chiefRole === 'initial';
  return {
    shape: person ? 'person' : 'application',
    label: node.id,
    sublabel: node.chiefRole || '',
    dashed: true
  };
}

// ---------------------------------------------------------------------------
// RENDER. graph -> { svg, width, height }.
//
//   graph     common/delegation.js's graph()
//   options   resolve(node) as above; `links`, which wraps every box in an <a>
//             to its page in this console; `id`, a prefix for every generated id
//             in the document, because two pictures in one HTML page would
//             otherwise share <defs> ids and the second one's arrowheads would
//             be the first one's.
//
// IT CANNOT THROW. The whole body is wrapped and a failure comes back as a
// picture SAYING it could not be drawn, for the reason `delegation.record()`
// gives about the table it feeds: a drawing on a console page must not be able
// to take the page down. Everything else on /admin/delegation/map — the tables,
// the counts, the legend — is worth reading with no picture above it, and a
// stack trace where the diagram should be is worth less than a sentence.
// ---------------------------------------------------------------------------
function render(graph, options) {
  log.debug("Entering render().");
  try {
    const svg = renderUnguarded(graph || { nodes: [], edges: [] }, options || {});
    log.debug("Leaving render(). " + svg.svg.length + " bytes of SVG, " +
              svg.width + "x" + svg.height + ".");
    return svg;
  } catch (e) {
    log.error('delegation map: the picture could not be drawn and the page was ' +
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
  const resolve = typeof options.resolve === 'function' ? options.resolve : defaultResolve;
  // What a party is CALLED, for the one place a line names a party that is
  // neither of its ends: a `reaches` edge says whose name the credential
  // carries. The caller supplies it because it is the same question `resolve()`
  // answers and the answer belongs to whoever knows the directory; with no
  // resolver the identity is its own name, which is what `defaultResolve()`
  // already does for a box.
  const nameOf = typeof options.labelOf === 'function'
    ? options.labelOf
    : function (id) { return id; };
  const prefix = String(options.id || 'dm');
  const nodes = graph.nodes || [];
  const edges = graph.edges || [];

  // THE ISSUER IS DRAWN, NOT LAID OUT — see the note on STS_BAND_SEP. It comes
  // out of the graph handed to dagre along with every line that touches it, and
  // is put back afterwards in a band of its own above everything else.
  const stsNode = nodes.filter(function (one) { return one.kind === 'sts'; })[0] || null;
  const isSts = function (id) { return !!stsNode && id === stsNode.id; };
  const partyNodes = nodes.filter(function (one) { return one !== stsNode; });
  const partyEdges = edges.filter(function (one) {
    return !isSts(one.from) && !isSts(one.to);
  });
  const stsEdges = edges.filter(function (one) {
    // A line with the hexagon at BOTH ends cannot exist — `delegation.js` never
    // makes one — and would be drawn as a point if it did, so it is dropped
    // here rather than divided by zero below.
    return (isSts(one.from) || isSts(one.to)) && one.from !== one.to;
  });

  // NOT a multigraph, and it stopped being one on 2026-09-01 for a reason worth
  // reading before it is put back. It was one because two chains between the
  // same pair of boxes are two lines — `alice -> frontend` by classic
  // constrained delegation and the same pair by RBCD are two arrangements — and
  // that is still true of the PICTURE. It was never true of what dagre is asked
  // for: everything it computes about an edge is thrown away below (its routes
  // described the staircase this file flattens, and its label positions
  // described a gap this file measures for itself), and the only thing kept out
  // of this whole layout is the ORDER of the boxes. Two lines between one pair
  // cannot change an order.
  //
  // Keeping them cost the picture outright. A dense graph — the delegated
  // permission register drawn at `/admin/delegation/allowed`, where five
  // applications each granting the other four two permissions is five boxes and
  // FORTY lines — has both a pair in each direction AND parallel lines within a
  // pair, and dagre 1.x positions a dummy node at NaN when it meets the two
  // together. `assignNodeIntersects()` then subtracts that NaN, finds neither a
  // dx nor a dy, and throws `Not possible to find intersection inside of the
  // rectangle` out of the whole render — so the page said the picture could not
  // be drawn, of a graph that draws perfectly. Neither ingredient does it alone:
  // parallel lines in one direction are fine, and a pair in both directions is
  // fine. Collapsing is what removes the one this file does not need.
  //
  // So the lines are collapsed to ONE per ordered pair on the way in, with their
  // weights SUMMED — which is what dagre's own `simplify()` does before ranking,
  // for the same reason — and `partyEdges` is untouched, so every one of the
  // forty is still drawn. `compound` is off — there are no nested boxes here.
  const g = new dagre.graphlib.Graph();
  g.setGraph({
    rankdir: 'LR', nodesep: NODE_SEP, edgesep: EDGE_SEP, ranksep: RANK_SEP,
    marginx: MARGIN, marginy: MARGIN
  });
  g.setDefaultEdgeLabel(function () { return {}; });

  const drawn = {};
  nodes.forEach(function (node) {
    const look = resolve(node) || defaultResolve(node);
    const size = measure(node, look);
    drawn[node.id] = { node: node, look: look, size: size };
  });
  partyNodes.forEach(function (node) {
    g.setNode(node.id, { width: drawn[node.id].size.width,
                         height: drawn[node.id].size.height });
  });

  const edgeLabels = {};
  edges.forEach(function (edge) {
    if (!drawn[edge.from] || !drawn[edge.to]) {
      return;
    }
    edgeLabels[edge.id] = edgeLabelLines(edge, nameOf);
  });

  const pairs = new Map();
  partyEdges.forEach(function (edge) {
    // An edge to or from a box that is not in the picture cannot be drawn and
    // must not be silently dropped into dagre either — it would invent the
    // missing node as a zero-sized one and the line would run to a point.
    if (!drawn[edge.from] || !drawn[edge.to]) {
      return;
    }
    const lines = edgeLabels[edge.id] || [];
    let width = 0;
    lines.forEach(function (one) {
      width = Math.max(width, textWidth(one, EDGE_SIZE));
    });
    // The key is the ORDERED pair: `a -> b` and `b -> a` are two lines to dagre
    // and always were, and collapsing those two would be collapsing a cycle into
    // an edge — which is the one thing that WOULD change the order it answers.
    const key = edge.from + ' ' + edge.to;
    let pair = pairs.get(key);
    if (!pair) {
      pair = { from: edge.from, to: edge.to, width: 0, height: 0, weight: 0 };
      pairs.set(key, pair);
    }
    // The widest and the tallest of the labels collapsed here. dagre reserves a
    // rank for a label and this is what it reserves; the gap the picture
    // actually leaves is measured again by `labelWidthOf()` below, off the
    // individual lines, so this figure has only to be honest rather than exact.
    pair.width = Math.max(pair.width, Math.ceil(width) + 10);
    pair.height = Math.max(pair.height, lines.length * (LINE_HEIGHT - 2) + 6);
    // Every line dagre sees now is a relationship — the issuer's are drawn by
    // hand below — so there is no longer a class of them to give less weight
    // to. The `issued` case this used to name is the whole of what was taken
    // out of the layout. SUMMING is what keeps a pair joined by four lines
    // pulled together four times as hard as a pair joined by one, which is the
    // whole of what the parallel lines were saying to the ordering pass.
    pair.weight += 3;
  });

  pairs.forEach(function (pair) {
    g.setEdge(pair.from, pair.to, {
      width: pair.width,
      height: pair.height,
      labelpos: 'c',
      weight: pair.weight,
      // A minimum length of 1 everywhere: the picture's ranks are the three
      // LAYERS of the model, and a longer minlen on any one of them would open a
      // gap that says something the model does not.
      minlen: 1
    });
  });

  dagre.layout(g);

  // ---------------------------------------------------------------------------
  // ONE CENTRELINE FOR THE PARTIES — see the note on ARC_LANE_H. dagre's ranking
  // and its ordering are kept; its coordinate pass is overwritten, which is done
  // by writing back into dagre's OWN nodes rather than into a map beside them so
  // that everything downstream — the label fitting, the placement loop, the
  // routing — reads one answer. A second copy of a node's position is how a
  // picture comes to have a line that ends slightly beside its own box.
  // ---------------------------------------------------------------------------
  let rowH = 0;
  partyNodes.forEach(function (node) {
    rowH = Math.max(rowH, drawn[node.id].size.height);
  });
  const rowCentre = MARGIN + rowH / 2;
  partyNodes.forEach(function (node) {
    const at = g.node(node.id);
    if (at) {
      at.y = rowCentre;
    }
  });

  // ---------------------------------------------------------------------------
  // THE ORDER ALONG THE ROW, AND WHY THE X IS TAKEN AWAY FROM DAGRE TOO.
  //
  // Flattening the y alone was not enough and the way it failed is worth
  // recording, because it looks correct on a chain and is catastrophic on
  // anything else. In a `rankdir: 'LR'` layout the RANK is the x, so every node
  // dagre puts on one rank has the SAME x and is told apart only by the y —
  // which is the coordinate that was just thrown away. A chain has one node per
  // rank and came out perfect; a FAN — one person, four applications, which is
  // the ordinary shape of a busy person's picture — came out as four boxes drawn
  // exactly on top of each other. `tests/delegation_map_bands.js` had that
  // fixture already and caught it.
  //
  // So the row owns both coordinates and dagre is left with the ONE thing it is
  // being kept for: the ORDER. Its rank assignment is the depth of the chain and
  // its ordering pass is the arrangement within a rank that crosses fewest
  // lines, so sorting by (x, then y) is that whole result read off as a
  // sequence — rank by rank, and inside a rank in the order it chose.
  //
  // Then the boxes are packed left to right along it, and the GAP between two of
  // them is the label of the line that will lie between them. That inverts what
  // dagre was doing: `ranksep` reserved a rank for an edge label and hoped it
  // fitted, and this measures the label and leaves exactly that much. It is also
  // what makes the straight-line rule below decidable at all — "are these two
  // neighbours" is a question about a sequence, not about geometry.
  // ---------------------------------------------------------------------------
  const order = partyNodes.filter(function (node) { return !!g.node(node.id); })
    .slice(0).sort(function (a, b) {
      const at = g.node(a.id);
      const bt = g.node(b.id);
      return at.x - bt.x || at.y - bt.y;
    });
  const seat = {};
  order.forEach(function (node, index) {
    seat[node.id] = index;
  });

  // How wide a line's label is, which is what decides both the gap it sits in
  // and the room an arc's lane has to hold.
  function labelWidthOf(edge) {
    let widest = 0;
    (edgeLabels[edge.id] || []).forEach(function (one) {
      widest = Math.max(widest, textWidth(one, EDGE_SIZE));
    });
    return widest;
  }

  // WHICH LINE LIES ALONG THE ROW. One per NEIGHBOURING PAIR: a second line
  // between the same two boxes is a second mechanism — `multigraph` is why they
  // both exist — and drawing both along the row would draw them on top of each
  // other. Everything else arcs under it.
  const straightAt = {};
  const route = {};
  partyEdges.forEach(function (edge) {
    if (!placedFor(edge) || edge.from === edge.to ||
        seat[edge.from] === undefined || seat[edge.to] === undefined) {
      return;
    }
    const width = labelWidthOf(edge);
    const lines = edgeLabels[edge.id] || [];
    const gapAt = Math.min(seat[edge.from], seat[edge.to]);
    const neighbours = Math.abs(seat[edge.from] - seat[edge.to]) === 1;
    if (neighbours && straightAt[gapAt] === undefined) {
      straightAt[gapAt] = width;
      route[edge.id] = { straight: true, labelWidth: width,
                         labelHeight: lines.length * (LINE_HEIGHT - 2) + 6 };
      return;
    }
    route[edge.id] = { straight: false, labelWidth: width,
                       labelHeight: lines.length * (LINE_HEIGHT - 2) + 6 };
  });

  // PACKED. The gap holds the straight line's label with air on both sides, or
  // is `GAP_MIN` where no line lies in it — two boxes that nothing joins still
  // have to look like two boxes.
  let cursor = MARGIN;
  order.forEach(function (node, index) {
    const size = drawn[node.id].size;
    if (index) {
      cursor += straightAt[index - 1] !== undefined
        ? Math.max(GAP_MIN, straightAt[index - 1] + GAP_PAD * 2) : GAP_MIN;
    }
    g.node(node.id).x = cursor + size.width / 2;
    cursor += size.width;
  });
  const packedW = cursor + MARGIN;

  // WHERE EACH ARC GOES, now that the boxes have their final x. A lane is the
  // first one nothing else in it overlaps — the same greedy first-fit the
  // issuer's labels get above, and enough for the same reason: there is no
  // arrangement a smarter one would find that this misses often enough to be
  // worth a reader having to understand it.
  const arcLanes = [];
  partyEdges.forEach(function (edge) {
    const how = route[edge.id];
    if (!how || how.straight) {
      return;
    }
    const a = g.node(edge.from);
    const b = g.node(edge.to);
    const widest = Math.max(drawn[edge.from].size.width, drawn[edge.to].size.width);
    const left = Math.min(a.x, b.x) - widest / 2;
    const right = Math.max(a.x, b.x) + widest / 2;
    // The label sits at the apex, so it is part of what the lane has to hold.
    const need = Math.max(right - left, how.labelWidth + GAP_PAD * 2);
    const middle = (left + right) / 2;
    const claim = { left: middle - need / 2, right: middle + need / 2 };
    let lane = 0;
    while (arcLanes[lane] && arcLanes[lane].filter(function (held) {
      return claim.left < held.right + ARC_GUTTER && claim.right > held.left - ARC_GUTTER;
    }).length) {
      lane++;
    }
    if (!arcLanes[lane]) {
      arcLanes[lane] = [];
    }
    arcLanes[lane].push(claim);
    how.lane = lane;
  });

  // ---------------------------------------------------------------------------
  // HOW DEEP EACH LANE IS, which is decided by the LABELS in it and not by a
  // constant — the same answer `fitLabels()` reaches above and for the same
  // reason. An arc's label sits at its apex, so two lanes a fixed distance apart
  // have their labels a fixed distance apart, and three lines of text at
  // `LINE_HEIGHT` do not fit in `ARC_LANE_H`. The first version of this used the
  // constant and the picture came back with `acts for / Token exchange / 1
  // issued` written across the arc under it — which is the failure the issuer's
  // label rows were invented to fix, one band lower.
  //
  // In the party band's OWN coordinates: `bandH` is not known yet, because how
  // deep the issuer's band is depends on how ITS labels fit and that is settled
  // below. The routing adds it, which is what the placement loop does to every
  // node position anyway.
  // ---------------------------------------------------------------------------
  const laneApex = [];
  const rowBottomRel = MARGIN + rowH;
  for (let lane = 0; lane < arcLanes.length; lane++) {
    let tallest = 0;
    Object.keys(route).forEach(function (id) {
      if (route[id].lane === lane) {
        tallest = Math.max(tallest, route[id].labelHeight || 0);
      }
    });
    const previous = laneApex[lane - 1];
    const clear = previous
      ? previous.y + previous.height / 2 + tallest / 2 + ARC_GUTTER
      : rowBottomRel + ARC_PAD + tallest / 2;
    laneApex.push({
      // The floor: an arc is its own line even with nothing written on it.
      y: Math.max(clear, (previous ? previous.y : rowBottomRel) + ARC_LANE_H),
      height: tallest
    });
  }

  const arcDepth = arcLanes.length
    ? (laneApex[laneApex.length - 1].y - rowBottomRel) +
      laneApex[laneApex.length - 1].height / 2 + ARC_PAD
    : 0;


  // WHERE EVERY BOX ENDED UP, and where every line runs. Two maps rather than
  // dagre's own graph, because half of what is in them did not come from dagre:
  // the hexagon's position and its lines are computed below, and the renderer
  // must not be able to tell which half it is drawing.
  const placed = {};
  const routed = {};
  // NOT dagre's width either: the boxes were repacked along the row above, so
  // the only thing that knows how wide the picture is is the packing.
  let partyW = Math.max(1, Math.ceil(packedW));
  // NOT dagre's height, which describes the staircase that was just flattened.
  // The row is as tall as its tallest box, and under it whatever the arcs
  // needed — nothing at all where every line lies along the row.
  let partyH = Math.max(1, Math.ceil(MARGIN + rowH + arcDepth + MARGIN));
  if (!partyNodes.length) {
    // Nothing but the issuer, which is what an empty register draws. dagre is
    // asked for the size of a graph with no nodes and answers with the margins
    // only, which would leave the hexagon with nothing to be centred over.
    partyW = MARGIN * 2;
    partyH = 0;
  }

  const stsSize = stsNode ? drawn[stsNode.id].size : null;
  const width = Math.max(partyW, stsNode ? Math.ceil(stsSize.width) + MARGIN * 2 : 0);
  // Centred over the parties when they are wider than the hexagon, and the
  // parties centred under IT when they are not — which is what a picture of one
  // application looks like.
  const shiftX = (width - partyW) / 2;

  // WHERE THE HEXAGON GOES, as ONE expression. `fitLabels()` below puts each
  // issuer label where that line crosses its row, which means solving for a
  // point on a segment that starts here — so a second spelling of this would
  // not draw the hexagon in the wrong place, it would draw every label BESIDE
  // its own line, which is the sort of wrong that looks like a rounding error.
  const stsAt = stsNode
    ? { x: width / 2, y: MARGIN + stsSize.height / 2 }
    : null;

  // HOW FAR TO ONE SIDE OF THE ISSUER'S CENTRE EACH LINE IS AIMED. See the note
  // on STS_FAN_SEP: the lines of ONE party are the same segment computed once
  // per line, so a party with two of them gets one path drawn over the other
  // and two labels seated over one line. They are grouped by the party at the
  // far end — every line touching the hexagon touches exactly one — and spread
  // about the centre, so a party with a single line is aimed at the centre and
  // is drawn exactly as it was.
  const stsFan = {};
  const stsLinesOf = {};
  stsEdges.forEach(function (edge) {
    if (!placedFor(edge)) {
      return;
    }
    const partyId = isSts(edge.from) ? edge.to : edge.from;
    if (!stsLinesOf[partyId]) {
      stsLinesOf[partyId] = [];
    }
    stsLinesOf[partyId].push(edge);
  });
  Object.keys(stsLinesOf).forEach(function (partyId) {
    const group = stsLinesOf[partyId];
    if (group.length < 2 || !stsSize) {
      return;
    }
    // Capped by the shape: the aim has to stay inside the hexagon, or the line
    // it describes leaves it somewhere the reader can see it did not.
    const room = Math.max(0, stsSize.width / 2 - STS_FAN_MARGIN);
    const step = Math.min(STS_FAN_SEP, (room * 2) / (group.length - 1));
    // Sorted by id rather than left in the order the graph was built, so the
    // same picture drawn twice fans the same way round — an edge order that
    // depends on which register was read first would move the lines under a
    // reader comparing two runs.
    group.slice(0).sort(function (a, b) {
      return String(a.id).localeCompare(String(b.id));
    }).forEach(function (edge, index) {
      stsFan[edge.id] = (index - (group.length - 1) / 2) * step;
    });
  });

  // THE ISSUER'S LINES, AND HOW DEEP THE GAP ABOVE THE PARTIES HAS TO BE. See
  // the note on LABEL_ROW_H: the answer is decided by the labels rather than by
  // a constant, so it is settled before anything is positioned.
  const stsLabelled = stsEdges.filter(function (edge) {
    return placedFor(edge) && (edgeLabels[edge.id] || []).length;
  }).map(function (edge) {
    const partyId = isSts(edge.from) ? edge.to : edge.from;
    const lines = edgeLabels[edge.id];
    let labelW = 0;
    lines.forEach(function (one) {
      labelW = Math.max(labelW, textWidth(one, EDGE_SIZE));
    });
    return {
      edge: edge, partyId: partyId,
      width: Math.ceil(labelW) + 10,
      height: lines.length * (LINE_HEIGHT - 2) + 6,
      // WHERE THIS LINE IS AIMED, so that its label is seated on the line that
      // is actually drawn rather than on the one that would have been drawn if
      // this were the party's only line. Zero for every party with one.
      fan: stsFan[edge.id] || 0,
      // Sorted on where the line ENDS, so the rows are filled left to right and
      // a reader following the fan outwards meets them in order.
      partyX: g.node(partyId).x + shiftX
    };
  }).sort(function (a, b) { return a.partyX - b.partyX; });

  function placedFor(edge) {
    return !!(drawn[edge.from] && drawn[edge.to]);
  }

  // One attempt at fitting every issuer label into `rows` rows. Returns the
  // assignment, or null when two of them would still overlap — the caller tries
  // again with one more row. Greedy and first-fit, which is enough: the labels
  // are sorted by where their lines end, so a row is filled left to right and a
  // clash is always with the one immediately before it.
  function fitLabels(rows) {
    log.debug("Entering fitLabels(). rows=" + rows);
    const gap = Math.max(STS_BAND_SEP, rows * LABEL_ROW_H + LABEL_ROW_PAD * 2);
    const bandTop = MARGIN + (stsSize ? stsSize.height : 0);
    const stsCentre = stsAt || { x: width / 2, y: 0 };
    const taken = [];
    const out = {};
    for (let i = 0; i < rows; i++) {
      taken.push([]);
    }
    for (let i = 0; i < stsLabelled.length; i++) {
      const one = stsLabelled[i];
      const partyAt = g.node(one.partyId);
      let put = false;
      for (let r = 0; r < rows && !put; r++) {
        const y = bandTop + LABEL_ROW_PAD + r * LABEL_ROW_H + LABEL_ROW_H / 2;
        // Where this line is when it crosses that row. The party's centre is
        // below the whole band, so the denominator cannot be zero.
        const span = (partyAt.y + (stsSize ? stsSize.height : 0) + gap) - stsCentre.y;
        // From the point this line is AIMED at rather than from the issuer's
        // centre — the same aim the routing below clips to, so the two cannot
        // disagree about where the line is.
        const originX = stsCentre.x + one.fan;
        const x = originX + (one.partyX - originX) * ((y - stsCentre.y) / span);
        const left = x - one.width / 2;
        const right = x + one.width / 2;
        const clash = taken[r].filter(function (held) {
          return left < held.right + LABEL_GUTTER && right > held.left - LABEL_GUTTER;
        }).length > 0;
        if (!clash) {
          taken[r].push({ left: left, right: right });
          out[one.edge.id] = { x: x, y: y };
          put = true;
        }
      }
      if (!put) {
        log.debug("Leaving fitLabels(). " + rows + " row(s) is not enough.");
        return null;
      }
    }
    log.debug("Leaving fitLabels(). " + stsLabelled.length + " label(s) in " +
              rows + " row(s).");
    return { gap: gap, at: out };
  }

  let fitted = null;
  for (let rows = 1; rows <= MAX_LABEL_ROWS && !fitted; rows++) {
    fitted = fitLabels(rows);
  }
  if (!fitted) {
    // Past the giving-up point. Everything goes in the last row it was offered
    // and some of them will overlap, which is the honest outcome rather than a
    // band taller than the diagram — see the note on MAX_LABEL_ROWS.
    log.warn('delegation_map: ' + stsLabelled.length + ' lines out of the ' +
             'issuer could not be labelled in ' + MAX_LABEL_ROWS + ' rows ' +
             'without overlapping. They are drawn anyway; the tooltip and the ' +
             'relationship table under the picture carry the same words.');
    fitted = fitLabels(MAX_LABEL_ROWS) || { gap: STS_BAND_SEP, at: {} };
  }

  // The gap exists to hold the issuer's labels and to separate two bands, so a
  // picture with only the hexagon in it has neither and gets neither: an empty
  // register draws one shape and 78 pixels of nothing under it otherwise.
  const bandH = !stsNode ? 0
              : partyNodes.length ? (stsSize.height + fitted.gap)
                                  : (stsSize.height + MARGIN);
  const height = Math.max(1, partyH + bandH);

  partyNodes.forEach(function (node) {
    const at = g.node(node.id);
    if (!at) {
      return;
    }
    placed[node.id] = { x: at.x + shiftX, y: at.y + bandH };
  });
  // ---------------------------------------------------------------------------
  // THE BERTHS, worked out for every box before any arc is drawn — because a
  // berth is a share of ONE box's bottom edge and cannot be decided from one
  // edge at a time. See the note on `BERTH` for what a berth is and why there
  // are any; the ORDER they go in is argued with the sort just below.
  // ---------------------------------------------------------------------------
  const berths = {};
  partyEdges.forEach(function (edge) {
    const how = route[edge.id];
    if (!how || how.straight || !placed[edge.from] || !placed[edge.to] ||
        edge.from === edge.to) {
      return;
    }
    [['from', edge.to], ['to', edge.from]].forEach(function (pair) {
      const at = pair[0] === 'from' ? edge.from : edge.to;
      if (!berths[at]) {
        berths[at] = [];
      }
      berths[at].push({ id: edge.id, end: pair[0], lane: how.lane || 0,
                        // Which way this arc leaves. `placed[at].x` is the box's
                        // own centre, so this is the side of it the far end is
                        // on and nothing subtler.
                        rightward: placed[pair[1]].x >= placed[at].x });
    });
  });
  const berthAt = {};
  Object.keys(berths).forEach(function (id) {
    const held = berths[id];
    // ---------------------------------------------------------------------
    // THE ORDER, AND IT IS THE ONE THAT MAKES NO TWO ARCS OFF ONE BOX CROSS.
    //
    // An arc drops STRAIGHT DOWN from its berth — the first control point
    // shares the berth's x — runs across at its lane's depth, and rises
    // straight into the far box's berth. So two arcs leaving one box the same
    // way cross exactly when the SHALLOWER of them is the outer one: it turns
    // across at a depth the deeper one is still descending through.
    //
    // Which gives the whole rule in two lines. Arcs going LEFT take the left of
    // the edge and arcs going RIGHT take the right, because two arcs leaving in
    // opposite directions from berths on the wrong sides of each other cross
    // immediately. And within each side the SHALLOWEST is the outermost — so
    // going left, lanes ascend from the left; going right, they descend into
    // it. The far box's x is not consulted at all: the lane is what a crossing
    // is actually about, and it usually agrees with distance and does not have
    // to.
    //
    // No two arcs at one box can share a lane — a lane holds arcs that do not
    // overlap horizontally, and two arcs off one box always overlap there — so
    // this is a total order and the id is only a tie-break that should never be
    // reached. It is here so that a picture drawn twice from one graph is the
    // same picture, which is what lets a reader compare it with the one they
    // were looking at a moment ago.
    // ---------------------------------------------------------------------
    held.sort(function (one, other) {
      if (one.rightward !== other.rightward) {
        return one.rightward ? 1 : -1;
      }
      const byLane = one.rightward ? other.lane - one.lane : one.lane - other.lane;
      return byLane || (one.id < other.id ? -1 : one.id > other.id ? 1 : 0);
    });
    const size = drawn[id].size;
    const usable = Math.max(0, size.width - BERTH_PAD * 2);
    const step = held.length > 1
      ? Math.min(BERTH, usable / (held.length - 1)) : 0;
    const span = step * (held.length - 1);
    held.forEach(function (one, index) {
      berthAt[one.id + '|' + one.end] = placed[id].x - span / 2 + step * index;
    });
  });
  // A berth if one was assigned, and the old lean if not — which is every arc
  // this loop is asked for that the block above did not see, and is not a state
  // that should arise. It is a FALLBACK rather than an assertion for the reason
  // `render()` is wrapped: a drawing on a console page must not be able to take
  // the page down, and a line a third of the way off centre is a worse picture
  // and still a picture.
  const berthX = function (id, edgeId, end, at, size, towards) {
    const held = berthAt[edgeId + '|' + end];
    if (held !== undefined) {
      return held;
    }
    const dx = towards.x - at.x;
    const step = Math.min(size.width / 3, Math.abs(dx) / 3);
    return at.x + (dx < 0 ? -step : step);
  };

  // ---------------------------------------------------------------------------
  // THE PARTY LINES, drawn from the decision made above rather than from what
  // dagre routed. Its routes described the staircase and every one of them would
  // now leave its box sideways into empty space.
  //
  // A straight line is clipped to both boxes so the arrowhead lands on an edge,
  // which is `boundaryPoint()`'s whole job. An arc is a cubic that leaves the
  // BOTTOM of one box and enters the bottom of the other, with both controls on
  // its lane — which is the one shape that comes back to the row at both ends
  // without a corner, and whose deepest point is three quarters of the way down
  // to the controls. That fraction is why the apex is computed and not assumed:
  // the label goes there, and a label at the control depth would sit clear of
  // the line it belongs to.
  // ---------------------------------------------------------------------------
  partyEdges.forEach(function (edge) {
    const how = route[edge.id];
    if (!how || !placed[edge.from] || !placed[edge.to]) {
      return;
    }
    const lines = edgeLabels[edge.id] || [];
    const box = {
      width: Math.ceil(how.labelWidth) + 10,
      height: lines.length * (LINE_HEIGHT - 2) + 6
    };
    if (how.straight) {
      const from = boundaryPoint(placed[edge.from], drawn[edge.from].size, placed[edge.to]);
      const to = boundaryPoint(placed[edge.to], drawn[edge.to].size, placed[edge.from]);
      routed[edge.id] = {
        points: [from, to],
        x: (from.x + to.x) / 2, y: (from.y + to.y) / 2,
        width: box.width, height: box.height
      };
      return;
    }
    const a = placed[edge.from];
    const b = placed[edge.to];
    const aSize = drawn[edge.from].size;
    const bSize = drawn[edge.to].size;
    // ITS BERTH ON EACH BOX'S BOTTOM EDGE, assigned above. The y is the bottom
    // edge itself, so the start is hidden under the box the way
    // `boundaryPoint()`'s is; only the x is the berth's.
    const from = { x: berthX(edge.from, edge.id, 'from', a, aSize, b),
                   y: a.y + aSize.height / 2 };
    const to = { x: berthX(edge.to, edge.id, 'to', b, bSize, a),
                 y: b.y + bSize.height / 2 };
    // WHERE THE CURVE ACTUALLY DIPS TO, solved for rather than assumed. A cubic
    // whose two controls share a y is at ((y0 + y1) / 8) + (3 / 4)c when it is
    // halfway along, which is where its lowest point is when the ends are level
    // — and they are NOT always level here, because two boxes on one centreline
    // have different heights when one of their labels wrapped. So the control is
    // computed from the lane's apex instead of the apex from the control: the
    // label goes at the apex, and a label a box-height away from its own line is
    // a label belonging to nothing.
    const apex = bandH + laneApex[how.lane].y;
    const control = (apex - (from.y + to.y) / 8) / 0.75;
    routed[edge.id] = {
      points: [from, to],
      // The exact curve, handed over rather than approximated through
      // `edgePath()`'s smoothing — which is built for a polyline with corners in
      // it and would round this one away from its own lane.
      path: 'M' + round(from.x) + ' ' + round(from.y) +
            'C' + round(from.x) + ' ' + round(control) + ' ' +
            round(to.x) + ' ' + round(control) + ' ' +
            round(to.x) + ' ' + round(to.y),
      x: (from.x + to.x) / 2, y: apex,
      width: box.width, height: box.height
    };
  });

  if (stsNode) {
    placed[stsNode.id] = stsAt;
    stsEdges.forEach(function (edge) {
      if (!placed[edge.from] || !placed[edge.to]) {
        return;
      }
      // A STRAIGHT LINE, clipped to both boxes so the arrowhead lands on the
      // edge of one rather than in the middle of its label. The hexagon is
      // clipped as a RECTANGLE, which is exact along its flat top and bottom —
      // where all but the outermost of these lines leave it — and a few pixels
      // generous at the two slanted ends. An arrow starting a little inside the
      // shape it is leaving is invisible; the alternative is intersecting a
      // six-sided path, for that.
      // THE AIM, which is the hexagon's centre for all but a fanned line — see
      // the note on STS_FAN_SEP. The party end is scaled along the ray it
      // travels on, exactly as an unfanned line is; the hexagon end cannot be,
      // because that ray no longer passes through the hexagon's centre, so it
      // is clipped against the shape instead.
      const partyId = isSts(edge.from) ? edge.to : edge.from;
      const fan = stsFan[edge.id] || 0;
      const aim = { x: stsAt.x + fan, y: stsAt.y };
      const partyEnd = boundaryPoint(placed[partyId], drawn[partyId].size, aim);
      const stsEnd = fan
        ? crossingPoint(placed[partyId], aim, stsAt, stsSize)
        : boundaryPoint(stsAt, stsSize, placed[partyId]);
      const from = isSts(edge.from) ? stsEnd : partyEnd;
      const to = isSts(edge.to) ? stsEnd : partyEnd;
      const lines = edgeLabels[edge.id] || [];
      const seat = fitted.at[edge.id];
      let labelW = 0;
      lines.forEach(function (one) {
        labelW = Math.max(labelW, textWidth(one, EDGE_SIZE));
      });
      routed[edge.id] = {
        points: [from, to],
        // Halfway along when there is no label to seat, which is where nothing
        // is drawn anyway.
        x: seat ? seat.x : (from.x + to.x) / 2,
        y: seat ? seat.y : (from.y + to.y) / 2,
        width: Math.ceil(labelW) + 10,
        height: lines.length * (LINE_HEIGHT - 2) + 6
      };
    });
  }

  const defs = '<defs>' + ARROW_COLOURS.map(function (colour) {
    return '<marker id="' + prefix + '-' + markerId(colour) + '" viewBox="0 0 10 10" ' +
      'refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">' +
      '<path d="M0 0L10 5L0 10z" fill="' + colour + '"/></marker>' +
      // The tail. See tailId() for why there is one and why it is the shape and
      // the size it is. `orient="auto"` looks pointless on a disc and is not:
      // it is what makes `refX="0"` mean "forward ALONG THE LINE" rather than
      // "to the right of the page", which is the default and which set the disc
      // beside the start of a line that leaves downwards instead of below it —
      // straddling the box's own bottom edge, where the box (painted after the
      // edges) covered its upper half and drew it as a half moon.
      '<marker id="' + prefix + '-' + tailId(colour) + '" viewBox="0 0 10 10" ' +
      'refX="0" refY="5" markerWidth="' + TAIL_SIZE + '" markerHeight="' + TAIL_SIZE +
      '" orient="auto">' +
      '<circle cx="5" cy="5" r="' + TAIL_R + '" fill="' + colour + '"/></marker>';
  }).join('') + '</defs>';

  // EDGES FIRST, so that a line passing near a box goes UNDER it rather than
  // across its label. SVG has no z-index; document order is the whole of the
  // stacking, which is the sort of thing that is obvious once and surprising
  // every other time.
  //
  // AND EVERY LINE BEFORE EVERY LABEL, WHICH IS THE SAME RULE APPLIED WITHIN
  // THE EDGES AND WAS NOT UNTIL 2026-09-01. Each edge used to emit its own line
  // and then its own label in one group, so document order interleaved them:
  // the label of the FIRST line was painted before the fortieth line was drawn,
  // and the fortieth line then went straight across the words. On the
  // delegated permission example — five applications each granting the other
  // four two permissions — 27 of the 40 labels were crossed by another line and
  // 25 of them were crossed by a line painted ON TOP, which is what the picture
  // looked unreadable BECAUSE OF. The lane assignment was not the problem and
  // is not touched: no two label panels overlapped there, then or now.
  //
  // The panel is semi-transparent on purpose — a label sits on its own line and
  // that line should read through it — so a crossing line is not hidden, it is
  // knocked back behind the words rather than drawn over them. Which is the
  // honest answer for a diagram this dense: the crossing is real and the
  // picture should show it; it must not be shown by writing it through a word.
  //
  // Each pass keeps its OWN `<title>`, so hovering a label still gives the
  // sentence — a label that had dropped out of the line's group would be the
  // one part of an edge with no tooltip on it, which is where the whole
  // identifier is (`edgeTitle()` says why the label cannot carry it).
  const edgeParts = edges.map(function (edge) {
    if (!drawn[edge.from] || !drawn[edge.to]) {
      return '';
    }
    const laid = routed[edge.id];
    if (!laid) {
      return '';
    }
    const look = edgeLook(edge);
    // An arc hands over its own path — see the routing above. Everything else
    // is a polyline to be smoothed, which is the issuer's two-point lines and
    // the party lines that lie along the row.
    const d = laid.path || edgePath(laid.points);
    if (!d) {
      return '';
    }
    const title = edgeTitle(edge);
    const lines = edgeLabels[edge.id] || [];
    // dagre gives the label's CENTRE and the box it reserved for it. The first
    // baseline is half the text's height above that centre plus most of a cap
    // height back down — an SVG <text> hangs from its baseline, not from its
    // top, and getting this wrong puts every edge label one line above its own
    // background panel.
    const labelStep = LINE_HEIGHT - 2;
    const labelTop = (laid.y || 0) - ((lines.length - 1) * labelStep) / 2 + 3.5;
    const label = lines.length
      ? '<g><rect x="' + round((laid.x || 0) - (laid.width || 0) / 2) +
        '" y="' + round((laid.y || 0) - (laid.height || 0) / 2) +
        '" width="' + round(laid.width || 0) + '" height="' + round(laid.height || 0) +
        '" rx="3" fill="' + PAPER + '" fill-opacity=".88"/>' +
        lines.map(function (one, i) {
          return '<text x="' + round(laid.x || 0) + '" y="' +
            round(labelTop + i * labelStep) + '" text-anchor="middle" ' +
            'font-size="' + EDGE_SIZE + '" fill="' +
            (i === 0 ? look.colour : QUIET) + '"' +
            (i === 0 ? ' font-weight="600"' : '') + '>' + esc(one) + '</text>';
        }).join('') + '</g>'
      : '';
    return {
      line: '<g><title>' + esc(title) + '</title>' +
        '<path d="' + d + '" fill="none" stroke="' + look.colour + '" stroke-width="' +
        look.weight + '"' + (look.dash ? ' stroke-dasharray="' + look.dash + '"' : '') +
        ' marker-start="url(#' + prefix + '-' + tailId(look.colour) + ')"' +
        ' marker-end="url(#' + prefix + '-' + markerId(look.colour) + ')"/></g>',
      label: label ? '<g><title>' + esc(title) + '</title>' + label + '</g>' : ''
    };
  }).filter(function (one) { return !!one; });

  const edgeMarkup = edgeParts.map(function (one) { return one.line; }).join('') +
                     edgeParts.map(function (one) { return one.label; }).join('');

  const nodeMarkup = nodes.map(function (node) {
    const at = placed[node.id];
    if (!at) {
      return '';
    }
    return nodeMarkupFor(drawn[node.id], at, options);
  }).join('');

  const svg = '<svg xmlns="http://www.w3.org/2000/svg" ' +
    'viewBox="0 0 ' + width + ' ' + height + '" width="' + width + '" height="' + height +
    '" role="img" aria-label="' + esc(options.label || 'Delegation relationships') + '">' +
    '<title>' + esc(options.label || 'Delegation relationships') + '</title>' +
    defs +
    '<g font-family="system-ui,-apple-system,Segoe UI,Arial,sans-serif">' +
    edgeMarkup + nodeMarkup +
    '</g></svg>';

  log.debug("Leaving renderUnguarded().");
  return { svg: svg, width: width, height: height,
           nodes: nodes.length, edges: edges.length };
}

// The sentence a line says on hover. It is the one place in the picture with
// room for the whole of it, which is why the drawn label is allowed to be three
// short lines.
function edgeTitle(edge) {
  log.debug("Entering edgeTitle().");
  const parts = [];
  if (edge.relation === 'issued') {
    parts.push('This service issued to this party.');
    if (edge.protocols && edge.protocols.length) {
      parts.push('Asked over: ' + edge.protocols.join(', ') + '.');
    }
  } else if (edge.relation === 'signed-in') {
    parts.push('This party AUTHENTICATED to this service — the sign-in that ' +
               'everything else here rests on.');
  } else if (edge.relation === 'issued-for') {
    parts.push('A credential NAMING this party was issued to that one, by an ' +
               'ordinary grant rather than by a delegation.');
  } else if (edge.relation === 'may-reach') {
    // THE TOOLTIP CARRIES THE FULL IDENTIFIER, which the label deliberately
    // does not (see edgeLabelLines()). It is also the one thing on this picture
    // a reader can copy into a client's `scope` and have work, so it is quoted
    // exactly rather than described.
    parts.push('MAY reach — a configured delegated permission, not something ' +
               'that has happened.');
    if (edge.permissionId) {
      parts.push('The permission is ' + edge.permissionId +
                 '. A client sends that string as an OAuth scope; the access ' +
                 'token comes back audienced to ' + (edge.baseUri || 'the base URI') +
                 ' with "' + (edge.permissionName || '') + '" on its scope claim.');
    }
    if (edge.description) {
      parts.push(edge.description);
    }
    parts.push(edge.asked
      ? 'This client HAS asked for it: the scope is recorded on its entry.'
      : 'This client has NEVER asked for it — the grant is configured and unused.');
  } else if (edge.relation === 'acts-for') {
    parts.push('Acts on behalf of.');
  } else {
    parts.push('Reaches' + (edge.subject ? ' as ' + edge.subject : '') +
               ' — what the credential is FOR.');
    // WHICH AUDIENCE, WHEN THE BOX IS NOT NAMED AFTER IT. A token addressed to
    // `https://apigw1.example.com` is drawn as the application that registered
    // that URI, and without this line there is nothing anywhere on the page
    // connecting the two — the label says who the credential is for and the box
    // says a name the token never mentions. Said only where they DIFFER: on a
    // line whose box IS the audience it would be the same string twice.
    if (edge.audience && edge.audience !== edge.to) {
      parts.push('Addressed to ' + edge.audience +
                 (edge.audienceRegistered
                   ? ', which this party has registered on oauthAudience.'
                   : ', which no application here has registered — so it is ' +
                     'drawn as itself.'));
    }
    // AND THE PERMISSIONS, IN FULL, because the label is capped at 26
    // characters and a resource exposing six of them would be cut there. The
    // scope claim goes with them: a reader asking why a line says `default
    // permissions` is asking what the token DID carry, and `openid profile` is
    // the whole answer in the ordinary case.
    if (edge.permissions && edge.permissions.length) {
      parts.push('Carries the delegated permission' +
                 (edge.permissions.length === 1 ? ' ' : 's ') +
                 edge.permissions.join(', ') + ' — the names on the token\'s ' +
                 'scope claim that this resource DEFINES. A client asks for one ' +
                 'by sending the whole identifier (the base URI followed by the ' +
                 'name) as a scope; the token comes back audienced to the base ' +
                 'with the bare name on its scope claim. Whether the client was ' +
                 'GRANTED it is the configured register\'s question and is at ' +
                 '/admin/delegation/allowed — this line is what was issued, and ' +
                 'oauth2.delegatedPermissionsEnforced is off by default.');
    } else if (edge.permissions) {
      parts.push('DEFAULT PERMISSIONS: the token names this resource and none ' +
                 'of its delegated permissions. That is what a scope naming the ' +
                 'resource\'s client_id produces — the value becomes the ' +
                 'audience and comes off the scope claim, so nothing on the ' +
                 'token asks for anything in particular. It is also what a ' +
                 'resource that defines no permissions can ever produce.');
    }
    if (edge.scopes && edge.scopes.length) {
      parts.push('The scope claim carries: ' + edge.scopes.join(' ') + '.');
    }
  }
  if (edge.typeLabel) {
    // The protocol only where the line HAS one. A sign-in line carries several
    // and leaves the field empty (see user_graph.js), and ` — ` with nothing in
    // front of it reads as a missing word rather than as an absent one.
    parts.push((edge.protocol ? edge.protocol + ' — ' : '') + edge.typeLabel +
               (edge.spec ? ' (' + edge.spec + ')' : '') + '.');
  }
  if (edge.mode) {
    parts.push(edge.mode === 'impersonation'
      ? 'IMPERSONATION: what came out names the initial identity and nothing ' +
        'else, so the far end cannot tell an intermediary was involved.'
      : 'DELEGATION: what came out carries the chain, so the far end can see ' +
        'who is really asking.');
  }
  if ((edge.skipped || []).length) {
    parts.push('The ' + edge.skipped.join(' and ') + ' is NOT NAMED on these ' +
               'acts, so this line jumps it.');
  }
  if (edge.relation === 'may-reach') {
    // NOTHING, AND THAT IS THE POINT. A configured permission has no acts to
    // count and no credentials in the issued register to report, so every
    // branch below is a sentence about the wrong picture. It fell through to
    // the last of them until 2026-09-01 and every line on
    // `/admin/delegation/allowed` said `undefined credential(s) from the
    // issued register, and no delegation act: nothing was exchanged to get
    // them` — the `undefined` because `app_permissions.graph()` publishes no
    // `credentials` member, correctly, and the rest because "nothing was
    // exchanged" is an observation about acts on a line that describes no act.
    // What such a line has to say is whether the client has ever ASKED, and
    // the `may-reach` branch above has already said it.
    log.debug("Leaving edgeTitle(). may-reach; no act or credential count belongs on it.");
    return parts.join('\n');
  }
  if (edge.relation === 'issued-for') {
    parts.push(edge.credentials + ' credential(s).');
  } else if (edge.relation === 'signed-in') {
    parts.push(edge.acts + ' authentication(s), all of them accepted — this ' +
               'service checks no password in any family.');
  } else if (edge.acts) {
    parts.push(edge.acts + ' act(s): ' + edge.issued + ' issued, ' +
               edge.refused + ' refused.');
    if (edge.credentials) {
      parts.push(edge.credentials + ' credential(s) from the issued register.');
    }
  } else {
    // NO ACTS AT ALL, which is what every line the person's picture adds looks
    // like: a credential was issued and nothing was delegated. `0 act(s): 0
    // issued, 0 refused` was printed here until 2026-08-26 and reads as a
    // delegation that was tried and came to nothing, which is the opposite of
    // what happened — see common/user_graph.js. The count of credentials is the
    // whole of what such a line has to report.
    parts.push(edge.credentials + ' credential(s) from the issued register, ' +
               'and no delegation act: nothing was exchanged to get them.');
  }
  (edge.produced || []).forEach(function (one) {
    parts.push('Produced ' + one.count + ' × ' + one.kind +
               (one.identifiers.length ? ' (' + one.identifiers.join(', ') +
                (one.moreIdentifiers ? ', +' + one.moreIdentifiers + ' more' : '') + ')'
              : '') + '.');
  });
  if (edge.authorizedBy) {
    parts.push('Authorized by: ' + edge.authorizedBy);
  }
  if (edge.reason) {
    parts.push('Refused because: ' + edge.reason);
  }
  log.debug("Leaving edgeTitle().");
  return parts.join('\n');
}

function nodeMarkupFor(entry, at, options) {
  log.debug("Entering nodeMarkupFor().");
  const look = entry.look;
  const size = entry.size;
  const node = entry.node;
  const x = at.x - size.width / 2;
  const y = at.y - size.height / 2;
  const dashed = !!look.dashed;
  const stroke = look.stroke || (dashed ? GREY : INDIGO);
  const fill = look.fill || (dashed ? PAPER : PANEL);
  const dash = dashed ? ' stroke-dasharray="4 3"' : '';

  let shape = '';
  let textX = at.x;
  let textTop = 0;
  let anchor = 'middle';

  if (size.shape === 'person') {
    shape = personGlyph(at.x - FIGURE_W / 2, y, stroke, dashed, 1);
    textTop = y + FIGURE_H + 6 + LABEL_SIZE - 2;
  } else if (size.shape === 'sts') {
    shape = '<path d="' + hexPath(x, y, size.width, size.height) + '" fill="' + WASH +
      '" stroke="' + INDIGO + '" stroke-width="1.8"/>';
    textTop = at.y - ((size.lines.length + size.subLines.length - 1) *
                      LINE_HEIGHT) / 2 + LABEL_SIZE / 2 - 1;
  } else {
    shape = '<rect x="' + round(x) + '" y="' + round(y) + '" width="' + round(size.width) +
      '" height="' + round(size.height) + '" rx="5" fill="' + fill + '" stroke="' +
      stroke + '" stroke-width="1.5"' + dash + '/>';
    if (size.shape === 'both') {
      // The person INSIDE the application's rectangle — see the header. Scaled
      // to fit the box's height rather than the figure's own, so a one-line
      // label and a two-line label do not get different-sized people.
      const scale = Math.min(1, (size.height - 8) / FIGURE_H);
      shape += personGlyph(x + 6, at.y - (FIGURE_H * scale) / 2, stroke, dashed, scale);
      textX = x + 6 + FIGURE_W * scale + 6;
      anchor = 'start';
    }
    textTop = at.y - ((size.lines.length + size.subLines.length - 1) *
                      LINE_HEIGHT) / 2 + LABEL_SIZE / 2 - 1;
  }

  const texts = size.lines.map(function (one, i) {
    return '<text x="' + round(textX) + '" y="' + round(textTop + i * LINE_HEIGHT) +
      '" text-anchor="' + anchor + '" font-size="' + LABEL_SIZE + '" font-weight="600" ' +
      'fill="' + (look.ink || INK) + '">' + esc(one) + '</text>';
  }).join('') + size.subLines.map(function (one, i) {
    return '<text x="' + round(textX) + '" y="' +
      round(textTop + (size.lines.length + i) * LINE_HEIGHT - 1) +
      '" text-anchor="' + anchor + '" font-size="' + SUB_SIZE + '" fill="' + QUIET +
      '">' + esc(one) + '</text>';
  }).join('');

  const body = '<title>' + esc(look.title || node.id) + '</title>' + shape + texts;

  // A LINK ONLY WHEN THE CALLER ASKED FOR ONE. The picture is served two ways —
  // inline in the console page, where a box should go to that party's page, and
  // as a standalone document at ?format=svg, where the href would be a
  // root-relative path in a file somebody has saved. app.js rewrites root-relative
  // links into the current realm on the way out of a text/html response ONLY, so
  // a link in a standalone SVG would also be a link that quietly left the realm.
  if (options.links && look.href) {
    log.debug("Leaving nodeMarkupFor().");
    return '<a href="' + esc(look.href) + '">' + body + '</a>';
  }
  log.debug("Leaving nodeMarkupFor().");
  return '<g>' + body + '</g>';
}

// ---------------------------------------------------------------------------
// ONE LINE, WITH BOTH ITS ENDS, FOR THE KEY BESIDE THE PICTURE.
//
// The legend in `admin.js` drew its own sample line and its own arrowhead,
// which was already the "second set of shapes" that `delegationMapKey()`'s own
// header warns about — and the tail disc would have made it a second set of
// two. So the sample is drawn HERE, out of the same numbers the markers are.
//
// It is SHAPES rather than the markers themselves, and it has to be: a marker
// lives in a `<defs>`, each swatch in the key is an `<svg>` of its own, and
// giving every one of a dozen swatches its own defs to draw one line would be
// more markup and one more thing to keep in step, not less. What is shared is
// the arithmetic — `TAIL_SIZE`, `TAIL_R` and the arrowhead's own geometry — so
// the two cannot drift in the way that matters, which is one of them being
// changed and the other not.
// ---------------------------------------------------------------------------
function edgeSample(colour, dash, weight) {
  const stroke = weight || 1.8;
  // What the markers come out as at this stroke width. `markerUnits` is left at
  // its default of `strokeWidth` on both, so both scale with the line.
  const tail = (TAIL_R / 10) * TAIL_SIZE * stroke;
  const head = 7 * stroke;
  const x1 = 4 + tail * 2;
  const x2 = 58 - head;
  return '<circle cx="' + round(4 + tail) + '" cy="20" r="' + round(tail) +
    '" fill="' + colour + '"/>' +
    '<path d="M' + round(x1) + ' 20H' + round(x2) + '" stroke="' + colour +
    '" stroke-width="' + stroke + '" fill="none"' +
    (dash ? ' stroke-dasharray="' + dash + '"' : '') + '/>' +
    '<path d="M' + round(x2) + ' ' + round(20 - head / 2) + 'L58 20L' +
    round(x2) + ' ' + round(20 + head / 2) + 'z" fill="' + colour + '"/>';
}

module.exports = {
  render: render,
  // The key beside the picture draws its sample lines with this, so that the
  // round end and the pointed end in the legend are the ones in the drawing.
  edgeSample: edgeSample,
  // Exported for the legend on the page, so that the swatch beside "an
  // application" and the box in the picture cannot come to be drawn from two
  // different palettes. admin.js draws the key out of these rather than naming
  // the colours a second time.
  COLOURS: {
    ink: INK, indigo: INDIGO, green: GREEN, amber: AMBER, red: RED,
    grey: GREY, quiet: QUIET, line: LINE, panel: PANEL, paper: PAPER, wash: WASH
  },
  personGlyph: personGlyph,
  hexPath: hexPath,
  // ---------------------------------------------------------------------
  // THE TEXT METRIC AND THE IDENTIFIER WRAP, exported for the SECOND picture
  // in this console — `admin-ui/federation_diagram.js`, which lays its own
  // graph out and draws its own shapes but must size a box the same way this
  // one does.
  //
  // They are shared rather than copied for the reason `COLOURS` is: two
  // estimates of how wide `HTTP/frontend.example.com` is would be two pictures
  // whose boxes are different sizes for the same string, and the error is
  // invisible until somebody puts the two pages side by side. Both are PURE —
  // no state, no config, no directory — so exporting them costs nothing and
  // couples nothing but the arithmetic.
  //
  // `wrapLabel` in particular is not a word-wrap and would be got wrong a
  // second time: it breaks after the characters an IDENTIFIER is built out of
  // (see BREAK_AFTER above), because there are no spaces in a service
  // principal name and a word-wrap gives up on one.
  // ---------------------------------------------------------------------
  textWidth: textWidth,
  wrapLabel: wrapLabel,
  MAX_LABEL_CHARS: MAX_LABEL_CHARS
};
