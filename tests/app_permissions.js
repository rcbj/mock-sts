'use strict';
//
// File: app_permissions.js
//
// ===========================================================================
// A CONFIGURED PERMISSION IS NOT AN ACT, AND THE PICTURE OF ONE MUST NOT LOOK
// LIKE THE PICTURE OF THE OTHER.
//
// `common/app_permissions.js` builds a graph in `common/delegation.js`'s shape
// and hands it to the SAME renderer the acts picture uses. That is what makes
// `/admin/delegation/allowed` cost one new relation instead of a second
// `delegation_map.js` — and it is also the whole risk of the arrangement: a
// graph in the acts' shape, drawn by the acts' renderer, can very easily come
// out looking like the acts. Every assertion below is about the difference.
//
// ---------------------------------------------------------------------------
// WHY IN PROCESS, WHICH IS THE QUESTION tests/CLAUDE.md ASKS FIRST.
//
// Most of this feature belongs over HTTP and is not here. That a permission
// must be defined before it is granted, that a base URI is normalised, that an
// ungranted scope is refused with `invalid_scope` when the setting is on — all
// of those are things a caller can drive against the running service, and
// `tests/vendored/sts_admin_api_operations.js` drives every one of the five
// operations. What is here is the two halves that CANNOT be driven:
//
//   * **CHOOSING THE GRAPH.** The states worth asserting are the ones a running
//     service will not produce on demand: a DANGLING grant (a permission
//     removed from under one, which both console doors refuse to create), and
//     an application granted its OWN permission, which `updateApplication()`
//     refuses outright and only an `ldapmodify` can write. Reaching either over
//     HTTP would mean driving the LDAP socket to make a state the API exists to
//     prevent, and then parsing the geometry back out of an SVG. The parsing is
//     the same either way; what cannot be done over there is choosing the graph
//     — the argument `delegation_map_bands.js` and `user_graph_signin.js`
//     already make.
//   * **THE PURE FUNCTIONS.** `base + name` and `name|description` are string
//     rules with edge cases that no request can reach: a description containing
//     the delimiter, a base already ending in `#`, a base URI written by hand
//     and therefore not normalised. Asking the service for them would be asking
//     it to echo back an answer this file can compute.
//
// It asserts GEOMETRY AND COLOUR rather than markup order, for
// `delegation_map_bands.js`'s reason: a rewrite of how a box is drawn should
// not fail this file, and a rewrite that lets a configured line take the
// impersonation colour must.
// ===========================================================================

// Deleted rather than set, for the reason config_realm_layer.js gives: nothing
// here should depend on a developer's exported appconfig.
delete process.env.CONFIG_FILE;

const applications = require('../common/applications');
const permissions = require('../common/app_permissions');
const map = require('../admin-ui/delegation_map');

// The two colours the ACTS picture uses to say impersonation and delegation,
// quoted here from `delegation_map.js`'s palette. A configured line must never
// take either: they are a judgement about a MECHANISM, and a permission nobody
// has exercised has performed no mechanism at all. Written out rather than
// imported because that module does not export them — and because a test that
// read the same constant would still pass if both changed together, which is
// exactly the change worth failing on.
const AMBER = '#8a6d00';
const GREEN = '#0b6b4f';

// One grant row in `register().grants`' shape. Built by hand rather than
// through the register, because the register reads `ou=applications` and the
// point of this file is the states a directory will not hand over.
function grant(client, resource, name, options) {
  const opts = options || {};
  const base = opts.baseUri === undefined ? 'https://example.com/' : opts.baseUri;
  return {
    client: client,
    clientName: opts.clientName || client,
    permissionId: opts.dangling ? base + name : base + name,
    resource: opts.dangling ? '' : resource,
    resourceName: opts.dangling ? '' : (opts.resourceName || resource),
    baseUri: opts.dangling ? '' : base,
    permissionName: opts.dangling ? '' : name,
    description: opts.description || '',
    dangling: !!opts.dangling,
    asked: !!opts.asked
  };
}

// Everything drawn with one stroke colour, as a list of its dash patterns. The
// SVG carries one `<path>` per edge; `stroke-dasharray` is absent on a solid
// one, so an absent attribute is reported as `''` rather than dropped — the
// distinction IS the assertion.
function edgeDashes(svg, colour) {
  const out = [];
  const paths = svg.match(/<path [^>]*>/g) || [];
  paths.forEach(function (one) {
    if (one.indexOf('stroke="' + colour + '"') < 0) return;
    // The arrowhead markers are <path>s too and carry a fill rather than a
    // stroke-width; an edge is the one with a width on it.
    if (one.indexOf('stroke-width') < 0) return;
    const dash = /stroke-dasharray="([^"]*)"/.exec(one);
    out.push(dash ? dash[1] : '');
  });
  return out;
}

function run(t) {
  // -----------------------------------------------------------------------
  t.log.info('a permission identifier is the base and the name, joined once');
  // -----------------------------------------------------------------------
  t.equal(applications.permissionIdOf('https://example.com/', 'write'),
          'https://example.com/write',
          'a base that already ends in a separator is used as it stands');
  t.equal(applications.permissionIdOf('https://example.com', 'write'),
          'https://example.com/write',
          'AND ONE THAT DOES NOT GETS A SEPARATOR — without this the two join ' +
          'into "https://example.comwrite", which is the failure the whole ' +
          'feature turns on and which nothing downstream could ever notice');
  t.equal(applications.permissionIdOf('api://8f2c/', 'Widgets.ReadWrite.All'),
          'api://8f2c/Widgets.ReadWrite.All',
          'Entra ID\'s own spelling composes the same way — nothing here ' +
          'requires an http scheme');
  t.equal(applications.permissionIdOf('https://example.com/api#', 'read'),
          'https://example.com/api#read',
          'a base ending in # is left alone, so a fragment-style identifier ' +
          'is available to anybody who wants one');
  t.equal(applications.permissionIdOf('https://example.com/', ''), '',
          'and a permission with no name has no identifier rather than one ' +
          'that is the bare base — which would be an identifier every ' +
          'nameless permission on the entry shared');

  // -----------------------------------------------------------------------
  t.log.info('the description is everything after the FIRST delimiter');
  // -----------------------------------------------------------------------
  const plain = applications.parsePermissionValue('write');
  t.equal(plain.name, 'write', 'a value with no delimiter is all name');
  t.equal(plain.description, '', 'and has no description');
  const rich = applications.parsePermissionValue('write|Change widgets|now');
  t.equal(rich.name, 'write', 'the name is what precedes the first delimiter');
  t.equal(rich.description, 'Change widgets|now',
          'AND EVERY LATER ONE BELONGS TO THE DESCRIPTION. A split on the ' +
          'character would silently drop the tail, and the value would still ' +
          'look right on the entry');

  // -----------------------------------------------------------------------
  t.log.info('a name that could not survive a scope parameter is refused');
  // -----------------------------------------------------------------------
  t.check(!applications.permissionNameProblem('Widgets.ReadWrite.All'),
          'a legal scope token is accepted');
  t.check(!!applications.permissionNameProblem('read write'),
          'a name with a space is refused — a scope list is space-delimited, ' +
          'so it would arrive at the token endpoint as two scopes neither of ' +
          'which is a permission',
          applications.permissionNameProblem('read write'));
  t.check(!!applications.permissionNameProblem('read|write'),
          'and one carrying the schema\'s own delimiter is refused, because ' +
          'it could never be read back as the name that was written');
  t.check(!!applications.permissionBaseProblem('example.com'),
          'a base that is not absolute is refused: it becomes an access ' +
          'token\'s aud, and a relative audience is one nothing can compare ' +
          'against');
  t.check(!applications.permissionBaseProblem('api://8f2c'),
          'and any absolute URI is accepted, whatever its scheme');

  // -----------------------------------------------------------------------
  t.log.info('the graph is applications and nothing else');
  // -----------------------------------------------------------------------
  const graph = permissions.graph([
    grant('webapp1', 'api1', 'write', { asked: true }),
    grant('webapp1', 'api1', 'read'),
    grant('batchjob', 'api1', 'admin')
  ]);
  t.equal(graph.nodes.length, 3, 'three applications, three boxes');
  t.check(graph.nodes.every(function (n) { return n.kind === 'party'; }),
          'THERE IS NO ISSUER BOX. The hexagon is on the acts picture because ' +
          'every line there exists because this service issued or refused ' +
          'something; not one line here has been asked for, so a hexagon ' +
          'would be a box with no edges — a drawing of a claim nobody made',
          JSON.stringify(graph.nodes.map(function (n) { return n.kind; })));
  t.check(graph.nodes.every(function (n) { return !n.key && !!n.application; }),
          'AND NO BOX IS A PERSON. `delegationNodeLook()` reaches for a stick ' +
          'figure when a node carries an identity key, and a configured ' +
          'permission has nobody in it — it says "this client may reach that ' +
          'API as whoever is signed in", and there is no whoever yet');
  t.check(graph.nodes.every(function (n) { return n.acts === 0; }),
          'and every box records nought acts, which is load-bearing: ' +
          'edgeLook() paints an edge RED when acts && !issued, so a box that ' +
          'claimed an act would draw every configured grant in the refusal ' +
          'colour');

  // -----------------------------------------------------------------------
  t.log.info('one line per permission, not one per pair of applications');
  // -----------------------------------------------------------------------
  t.equal(graph.edges.length, 3,
          'two grants between webapp1 and api1 are TWO lines. One labelled ' +
          '"2" would hide which permissions were granted, which is the only ' +
          'thing the picture is being asked');
  t.check(graph.edges.every(function (e) { return e.relation === 'may-reach'; }),
          'every line says MAY reach rather than `reaches` — that word is the ' +
          'acts picture\'s claim that a credential was issued for something');
  t.check(graph.edges.every(function (e) { return !e.mode; }),
          'and no line carries a mode, because impersonation and delegation ' +
          'are properties of a mechanism and none has been performed');

  // -----------------------------------------------------------------------
  t.log.info('a dangling grant draws no line, and is not silently lost');
  // -----------------------------------------------------------------------
  const dangling = permissions.graph([
    grant('webapp1', 'api1', 'write'),
    grant('webapp1', '', 'gone', { dangling: true })
  ]);
  t.equal(dangling.edges.length, 1,
          'the grant naming a permission nobody defines draws nothing — a ' +
          'line to nowhere would be a drawing of a resource that is there');
  const orphan = dangling.nodes.filter(function (n) { return n.id === 'webapp1'; })[0];
  t.equal(orphan && orphan.dangling, 1,
          'but the client\'s own box counts it, so the state is carried out ' +
          'of the graph rather than dropped on the floor of it');

  // -----------------------------------------------------------------------
  t.log.info('an application granted its own permission draws no loop');
  // -----------------------------------------------------------------------
  // Only an `ldapmodify` can produce this — `updateApplication()` refuses a
  // self-grant through both console doors — which is precisely why it is
  // asserted here and cannot be asserted over HTTP.
  const self = permissions.graph([grant('api1', 'api1', 'write')]);
  t.equal(self.edges.length, 0, 'no edge: an arrow from a box back to itself ' +
          'is a drawing of nothing');
  t.check(self.nodes[0] && self.nodes[0].selfTarget === true,
          'it is marked on the box instead, the way delegation.graph() marks ' +
          'an S4U2Self');

  // -----------------------------------------------------------------------
  t.log.info('and the picture draws an unused grant differently from a used one');
  // -----------------------------------------------------------------------
  // THE JOIN. Everything above would pass with a renderer that drew all three
  // lines identically; this is the assertion that the one bit a configured
  // picture can carry actually reaches the page.
  const drawn = map.render(graph, { id: 'perm', label: 'allowed' });
  t.check(!drawn.failed, 'the picture is drawn', drawn.failed || '');
  const indigo = edgeDashes(drawn.svg, '#12107c').sort();
  t.equal(JSON.stringify(indigo), JSON.stringify(['', '6 4', '6 4']),
          'THREE LINES, ONE SOLID AND TWO DASHED — the one grant that has ' +
          'been asked for against the two that never have. A grant nobody ' +
          'needed draws no act at all, so this is a reading the acts diagram ' +
          'cannot give and the single most useful thing on this one');
  t.equal(edgeDashes(drawn.svg, AMBER).length + edgeDashes(drawn.svg, GREEN).length, 0,
          'AND NOT ONE LINE IS AMBER OR GREEN. Those two say impersonation ' +
          'and delegation on the acts picture, and colouring a permission ' +
          'that has never been exercised would tell a reader who has learnt ' +
          'that pairing something false');
  t.check(drawn.svg.indexOf('may reach') > 0,
          'the lines are labelled `may reach`, so the distinction survives ' +
          'for a reader who has not been told what a dash means');
  t.check(drawn.svg.indexOf('never asked for') > 0 &&
          drawn.svg.indexOf('&gt;asked for') < 0,
          'and both states are said in words as well as in the dash — a ' +
          'picture whose most useful fact was invisible without a key would ' +
          'be one nobody read it off');
}

module.exports = {
  name: 'app_permissions',
  describe: 'a configured permission is drawn as intent, never as an act',
  run: run
};
