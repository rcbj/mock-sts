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

// A whole `register()` reply, for the clustering assertions below. It is built
// by hand for this file's own reason: the states worth partitioning are the
// ones a directory will not hand over, and two of them — a dangling grant and
// an application granted its own permission — are refused by both console
// doors. `resources` is the list of identifiers that carry a base URI or a
// permission, which is what `register()` means by one; `defined` is the
// permissions on them, as [resource, name] pairs.
function registerOf(grants, resources, defined) {
  return {
    resources: (resources || []).map(function (identifier) {
      return { identifier: identifier, name: identifier,
               baseUri: 'https://' + identifier + '/' };
    }),
    permissions: (defined || []).map(function (pair) {
      return { resource: pair[0], resourceName: pair[0],
               baseUri: 'https://' + pair[0] + '/', name: pair[1],
               description: '', id: 'https://' + pair[0] + '/' + pair[1],
               raw: pair[1], grantedTo: [] };
    }),
    grants: grants
  };
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

  // -----------------------------------------------------------------------
  t.log.info('the register partitions into groups, and direction is ignored');
  // -----------------------------------------------------------------------
  // WHY IN PROCESS, WHICH IS THE SAME QUESTION THIS FILE'S HEADER ANSWERS FOR
  // THE GRAPH. Two of the four states below cannot be produced over HTTP at
  // all: a DANGLING grant needs a permission removed from under one, and an
  // application granted its OWN permission is refused by both console doors.
  // The third — a resource with permissions and no grants — is reachable over
  // HTTP and is asserted here anyway, because the assertion is that it is IN
  // the answer, and that is a claim about the partition rather than about the
  // service. `tests/vendored/sts_admin_api_operations.js` drives the operation.
  //
  // The mesh below is deliberately the one shape that tells the two readings
  // apart. `webapp1 -> api1` and `webapp2 -> api1` are two arrows INTO one
  // resource: following the arrows, webapp1 reaches api1 and stops, and webapp2
  // is reachable only by walking one of them backwards. So webapp1 and webapp2
  // land in one group if and only if direction is ignored — and a
  // implementation that followed the arrows would still put `api1` and `api2`
  // together, which is why a chain alone would have asserted nothing.
  const mesh = registerOf([
    grant('webapp1', 'api1', 'read', { baseUri: 'https://api1/', asked: true }),
    grant('webapp1', 'api1', 'write', { baseUri: 'https://api1/' }),
    grant('webapp2', 'api1', 'read', { baseUri: 'https://api1/' }),
    grant('api1', 'api2', 'sync', { baseUri: 'https://api2/' }),
    // ONE CLIENT ON TWO RESOURCES, which is the shape that tells a real union
    // from a first-write-wins one: `webapp1` has already been joined to `api1`
    // when this row arrives, so an implementation that only sets a parent when
    // the client is still its own root would leave api5 in a group of its own
    // and every count in this file would still be right about the rest.
    grant('webapp1', 'api5', 'call', { baseUri: 'https://api5/' }),
    grant('batchjob', 'api3', 'run', { baseUri: 'https://api3/' }),
    // Neither of these joins anything, and each is a different reason.
    grant('ghost', 'gone', 'tmp', { baseUri: 'https://gone/', dangling: true }),
    grant('selfy', 'selfy', 'me', { baseUri: 'https://selfy/' })
  ], ['api1', 'api2', 'api3', 'api5', 'selfy', 'lonely'],
     [['api1', 'read'], ['api1', 'write'], ['api2', 'sync'], ['api3', 'run'],
      ['api5', 'call'], ['lonely', 'peek']]);
  const parts = permissions.clusters(mesh);
  const groupOf = function (identifier) {
    return permissions.clusterFor(identifier, parts);
  };

  t.equal(JSON.stringify(groupOf('webapp1').members),
          JSON.stringify(['api1', 'api2', 'api5', 'webapp1', 'webapp2']),
          'TWO CLIENTS OF ONE RESOURCE ARE IN ONE GROUP, which is the whole ' +
          'of the direction decision: following the arrows, webapp2 is ' +
          'reachable from webapp1 only by walking a grant backwards, so a ' +
          'partition that respected direction would put them in two groups ' +
          'and the picture would say that an API and its front ends have ' +
          'nothing to do with each other');
  t.equal(groupOf('api5').key, groupOf('webapp2').key,
          'AND ONE CLIENT ON TWO RESOURCES PUTS BOTH RESOURCES IN ONE GROUP: ' +
          'webapp1 reaches api1 and api5, so api5 is in webapp2\'s group ' +
          'though nothing joins the two directly. A join that only moved a ' +
          'node still standing on its own root would drop this one silently');
  t.equal(groupOf('api2').key, groupOf('webapp2').key,
          'and it is TRANSITIVE — api2 is two hops from webapp2 and in its ' +
          'group, because a group is a connected component and not a ' +
          'neighbour list');
  t.equal(groupOf('batchjob').key, 'api3',
          'a pair with nothing to do with the rest is a group of its own — ' +
          'this is the fact the whole feature exists to draw, and a ' +
          'partition that joined everything would be the whole-register ' +
          'picture with extra steps');
  t.equal(groupOf('webapp1').key, 'api1',
          'A GROUP IS NAMED AFTER THE MEMBER WHOSE IDENTIFIER SORTS FIRST, ' +
          'which is a property of the SET — the union-find root is whichever ' +
          'identifier the joins happened to leave on top, so naming a group ' +
          'after it would rename every group on the console the moment a ' +
          'grant was added anywhere inside it');

  // -----------------------------------------------------------------------
  t.log.info('and three states each make a group of ONE for three reasons');
  // -----------------------------------------------------------------------
  // `check` and not `equal`, because the mutant this is aimed at — a universe
  // built from the grants alone — makes `groupOf('lonely')` NULL, and a test
  // that dereferenced it would report a TypeError instead of the sentence.
  t.check(!!groupOf('lonely'),
          'A RESOURCE NOBODY HOLDS ANYTHING ON IS IN THE ANSWER. It appears ' +
          'in no grant at all, so a partition built from the grants alone ' +
          'would have left it out — and an API somebody described that ' +
          'nothing may reach is the most interesting group of one there is');
  t.equal(groupOf('lonely') ? groupOf('lonely').counts.applications : 0, 1,
          'and it is a group of one');
  t.equal(groupOf('lonely') ? groupOf('lonely').counts.permissions : 0, 1,
          'with the permission it exposes counted on it, which is the only ' +
          'thing its own page has to show');
  t.equal(groupOf('ghost').counts.applications, 1,
          'A DANGLING GRANT JOINS ITS CLIENT TO NOTHING — it names a ' +
          'permission no application defines, so there is no far end to be ' +
          'in a group with. A partition that keyed on the permission ' +
          'identifier rather than on the resource would have invented a ' +
          'second member out of a string');
  t.equal(groupOf('ghost').counts.dangling, 1,
          'and the row is COUNTED on the group rather than dropped, so the ' +
          'page can say why there is nothing to draw');
  t.equal(groupOf('selfy').counts.applications, 1,
          'AN APPLICATION GRANTED ITS OWN PERMISSION IS ONE APPLICATION, ' +
          'however it is drawn');
  t.equal(groupOf('selfy').counts.lines, 0,
          'and no line, because `graph()` draws no arrow from a box back to ' +
          'itself — the count on the group and the picture beside it have to ' +
          'agree, and a table reading `1 grant` above an empty diagram is the ' +
          'console disagreeing with itself about one row');
  t.equal(groupOf('selfy').counts.selfGrants, 1,
          'it is reported as what it is instead');

  t.equal(parts.counts.clusters, 5,
          'five groups over the whole register');
  t.equal(parts.counts.alone, 3,
          'three of them of one application, which is the number the page ' +
          'draws a tile for');
  t.equal(parts.clusters[0].counts.applications, 5,
          'BIGGEST FIRST. The list exists to surface the groups worth ' +
          'looking at, and the interesting one at position thirty-one is the ' +
          'problem the whole-register picture already had');

  // -----------------------------------------------------------------------
  t.log.info('every grant belongs to exactly one group, and to the right one');
  // -----------------------------------------------------------------------
  // THE ASSERTION A COUNT CANNOT MAKE. Every arithmetic check above would
  // still pass if a grant were filed under the wrong group, or under two — and
  // the picture would then draw a line between boxes that are not both on it,
  // which is the one failure that looks like a rendering bug.
  const filed = {};
  parts.clusters.forEach(function (group) {
    group.grants.forEach(function (one) {
      filed[one.client + '|' + one.permissionId] =
        (filed[one.client + '|' + one.permissionId] || 0) + 1;
      t.check(group.members.indexOf(one.client) >= 0,
              'the client of every grant is a member of the group it is filed ' +
              'under: ' + one.client + ' in ' + group.key);
      t.check(!one.resource || group.members.indexOf(one.resource) >= 0,
              'and so is its resource, where it has one: ' +
              (one.resource || '(dangling)') + ' in ' + group.key);
    });
  });
  t.equal(Object.keys(filed).length, mesh.grants.length,
          'every grant in the register is filed');
  t.check(Object.keys(filed).every(function (key) { return filed[key] === 1; }),
          'AND EACH IS FILED EXACTLY ONCE. A grant appearing in two groups ' +
          'would draw one relationship on two pictures and count it twice on ' +
          'the page that lists them',
          JSON.stringify(filed));

  // -----------------------------------------------------------------------
  t.log.info('a group\'s picture is the whole picture narrowed and nothing else');
  // -----------------------------------------------------------------------
  // THE JOIN, and it is what makes the count on the console a claim about the
  // renderer rather than about this module's arithmetic.
  const whole = permissions.graph(mesh.grants);
  const part = permissions.graph(groupOf('webapp1').grants);
  t.equal(part.nodes.length, 5,
          'the group draws five boxes where the whole register draws ' +
          whole.nodes.length);
  t.equal(part.edges.length, groupOf('webapp1').counts.lines,
          'AND THE `lines` COUNT ON THE GROUP IS WHAT THE RENDERER ACTUALLY ' +
          'DRAWS. It is computed in app_permissions.js and spent in a table ' +
          'beside the diagram, so a count that included the dangling and the ' +
          'self grants would be a page whose own numbers contradicted the ' +
          'picture under them');
  t.check(part.edges.every(function (edge) {
            return whole.edges.filter(function (one) {
              return one.id === edge.id && one.from === edge.from &&
                     one.to === edge.to && one.relation === edge.relation;
            }).length === 1;
          }),
          'and every line in the group is the SAME line the whole register ' +
          'draws, by id and by both ends — a group is the register narrowed, ' +
          'so a reader who has learnt what a dash means on one picture has ' +
          'learnt it on the other');

  // -----------------------------------------------------------------------
  t.log.info('and an identifier is matched exactly, here as everywhere else');
  // -----------------------------------------------------------------------
  t.equal(groupOf('WebApp1'), null,
          'NOTHING HERE CASE-FOLDS AN IDENTIFIER. `applications.js` does not, ' +
          'an audience that differs by a character is a different audience, ' +
          'and a lookup that matched loosely would be this module deciding a ' +
          'comparison rule on that one\'s behalf — and would hand a reader the ' +
          'group of an application they did not name');
  t.equal(groupOf(''), null,
          'and an empty name is not the first group in the list');
}

module.exports = {
  name: 'app_permissions',
  describe: 'a configured permission is drawn as intent, never as an act',
  run: run
};
