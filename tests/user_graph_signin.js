'use strict';
//
// File: user_graph_signin.js
//
// ===========================================================================
// ONE PERSON, ONE SIGN-IN LINE, AND THE LIST THAT IS ON IT.
//
// `/admin/delegation/user` draws everything issued in one person's name.
// `common/user_graph.js` builds that graph and `admin-ui/delegation_map.js`
// draws it, and until 2026-08-26 the first of them made ONE LINE PER PROTOCOL
// FAMILY somebody had authenticated with. Those lines join the same two boxes —
// the person and the hexagon — so the second of them computed the same clipped
// segment once per line and drew each over the last, while seating their labels
// in separate ROWS so that the labels would not collide.
//
// What that produced on `bob_end_user`'s page was ONE visible line saying
//
//     signed in / OAuth 2.0 / OIDC / 1 time
//     signed in / OAuth 2.0 / 2 times
//
// which reads as a single relationship contradicting itself. It is not: he
// signed in ONCE at the sign-in screen, and was named as the subject of TWO
// RFC 8693 token exchanges, which `oauth2.js` records as authentications under
// the bare `OAuth 2.0` family.
//
// So there is one line now, and the families are a LIST on it. This file
// asserts both halves of that and the JOIN between them, because each half is
// convincing alone and the bug was in neither: `user_graph.js` folding
// correctly while the label draws one entry, or the label drawing a list while
// two edges still arrive, are both green in a test that only looks at one.
//
// WHY IN PROCESS. Both modules are pure functions of what they are handed —
// `graphFor()` reads the registers, `render()` reads a graph — and the shape
// worth asserting is one authentication in one family and two in another, which
// over HTTP means driving a sign-in and two token exchanges and then parsing
// the geometry back out of an SVG. The parsing is the same either way; what
// cannot be done over there is CHOOSING the traffic. The parent project's
// `oauth2_delegation_chain.js` drives exactly that traffic against a running
// stack and is where the end-to-end claim lives.
// ===========================================================================

// Deleted rather than set, for the reason config_realm_layer.js gives: nothing
// here should depend on a developer's exported appconfig.
delete process.env.CONFIG_FILE;

const stats = require('../common/admin_stats');
const userGraph = require('../common/user_graph');
const map = require('../admin-ui/delegation_map');

// A name no other test and no seed uses, because the register is shared by
// every file in this run and an assertion about "the sign-in line" has to be
// about a person with exactly the sign-ins this file gave them.
const WHO = 'ug-signin-subject';

const SCREEN = 'sign-in screen (password)';
const EXCHANGE = 'token exchange (RFC 8693)';

// The two families, spelt as the service spells them: `authn.js` records a
// browser sign-in as `OAuth 2.0 / OIDC` and `oauth2.js` records a token
// exchange as bare `OAuth 2.0`. That difference is the whole reason the page
// drew two lines, so a fixture that used one string would assert nothing.
const BROWSER = 'OAuth 2.0 / OIDC';
const BARE = 'OAuth 2.0';

// The words drawn on a line, in the order they are drawn, for the line whose
// first word is `signed in`. Read out of the emitted SVG rather than off
// `edgeLabelLines()` directly: the assertion is about what a reader sees.
function signInLabel(svg) {
  const groups = svg.split('<g>');
  for (let i = 0; i < groups.length; i++) {
    const texts = [];
    const re = /<text [^>]*>([^<]*)<\/text>/g;
    let m = re.exec(groups[i]);
    while (m) {
      texts.push(m[1]);
      m = re.exec(groups[i]);
    }
    if (texts[0] === 'signed in') {
      return texts;
    }
  }
  return null;
}

// `&#215;` and friends: the label goes through xmlEscape() on the way out, so
// the multiplication sign a comparison is written with has to come back the
// way it went in.
function unescape(text) {
  return String(text)
    .replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"').replace(/&#39;/g, "'");
}

// Long enough that Date.now() has moved on, which is all this is for.
function pause() {
  return new Promise(function (resolve) {
    setTimeout(resolve, 4);
  });
}

async function run(t) {
  // -----------------------------------------------------------------------
  t.log.info('one sign-in and two token exchanges, in two families');
  // -----------------------------------------------------------------------
  // Recorded through the funnel every protocol module uses rather than by
  // writing a fixture: what this file is about is the shape the REGISTER
  // produces, and a hand-written `detail` would assert this file's idea of it.
  stats.recordAuthentication({ presented: WHO, protocol: BROWSER,
                               method: SCREEN, sub: WHO });
  // A REAL PAUSE BETWEEN THEM, because the order asserted below is the order
  // the families STARTED in and the register's clock is a millisecond. Three
  // calls in a row land in one tick, the two families are then indivisible by
  // time, and the assertion would be about whichever tie-break came last
  // rather than about the rule. The sign-in genuinely does come first in every
  // run this models — a token exchange quotes a token that a sign-in produced.
  await pause();
  stats.recordAuthentication({ presented: WHO, protocol: BARE,
                               method: EXCHANGE, sub: WHO });
  stats.recordAuthentication({ presented: WHO, protocol: BARE,
                               method: EXCHANGE, sub: WHO });
  const key = stats.identityKeyOf(WHO);
  const detail = stats.userDetail(key);
  t.check(!!detail && detail.user.authentications === 3,
          'the register holds three authentications for them',
          'authentications=' +
          (detail ? detail.user.authentications : 'no user'));
  t.equal(detail ? detail.user.protocols.length : 0, 2,
          'in two protocol families');

  // -----------------------------------------------------------------------
  t.log.info('the graph draws ONE line for them, not one per family');
  // -----------------------------------------------------------------------
  const built = userGraph.graphFor(key);
  const graph = built.graph;
  const signIns = graph.edges.filter(function (edge) {
    return edge.relation === 'signed-in';
  });
  t.equal(signIns.length, 1,
          'THERE IS EXACTLY ONE SIGN-IN LINE — two would be two segments ' +
          'between the same pair of boxes, drawn one over the other');
  const edge = signIns[0] || {};
  t.equal(edge.acts, 3, 'and it counts every authentication');
  t.check(edge.from === graph.subject,
          'it runs from the person', 'from=' + edge.from);

  // The list, which is what the single line now carries. Ordered oldest family
  // first, so the sign-in everything else rests on is read before the exchanges
  // that quote it.
  const list = edge.authentications || [];
  t.equal(list.length, 2, 'it carries one list entry per family and method');
  t.check(list[0] && list[0].protocol === BROWSER && list[0].count === 1,
          'the sign-in at the screen is first, counted once',
          JSON.stringify(list[0] || null));
  t.check(list[1] && list[1].protocol === BARE && list[1].count === 2 &&
          list[1].method === EXCHANGE,
          'AND THE TWO TOKEN EXCHANGES ARE THEIR OWN ENTRY, named by their ' +
          'mechanism — `OAuth 2.0 ×2` on its own is the sentence that read ' +
          'as two sign-ins',
          JSON.stringify(list[1] || null));
  t.check(!edge.protocol,
          'the line names no single protocol, because it carries two',
          'protocol=' + JSON.stringify(edge.protocol));
  t.check(String(edge.typeLabel).indexOf(EXCHANGE) >= 0 &&
          String(edge.typeLabel).indexOf(SCREEN) >= 0,
          'and the mechanism the tables and the tooltip read carries both',
          edge.typeLabel);

  // -----------------------------------------------------------------------
  t.log.info('and the picture draws that line with the list on it');
  // -----------------------------------------------------------------------
  // The JOIN. `graphFor()` folding correctly and `render()` drawing one entry
  // of the list would both pass everything above.
  const drawn = map.render(graph, { id: 'ug', label: 'user' });
  t.check(!drawn.failed, 'the picture is drawn', drawn.failed || '');
  const label = (signInLabel(drawn.svg) || []).map(unescape);
  t.check(label.length === 3,
          'the sign-in line is labelled with a statement and two entries',
          JSON.stringify(label));
  t.check(label[1] === '1 × ' + BROWSER + ' (sign-in screen)',
          'the first entry is the sign-in, with its own count',
          JSON.stringify(label[1]));
  t.check(label[2] === '2 × ' + BARE + ' (token exchange)',
          'AND THE SECOND NAMES THE EXCHANGES AND SAYS THERE WERE TWO — the ' +
          'complaint this fold answers',
          JSON.stringify(label[2]));
  t.check(label.indexOf('3 times') < 0 && label.indexOf('2 times') < 0,
          'and no line says `N times` any more, which is the count that ' +
          'was read as N sign-ins',
          JSON.stringify(label));

  // One dotted line into the hexagon, in the document rather than in the
  // graph: the assertion above is about the model and this one is about what
  // is on the page.
  const dotted = (drawn.svg.match(/stroke-dasharray="2 3"/g) || []).length;
  t.equal(dotted, 1,
          'and exactly one dotted line is drawn — the sign-in line is the ' +
          'only one that is dotted');
}

module.exports = {
  name: 'user_graph_signin',
  describe: 'one person has one sign-in line, with the families listed on it',
  run: run
};
