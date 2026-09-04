'use strict';
//
// File: user_graph_permissions.js
//
// ===========================================================================
// A BLUE LINE DRAWN FROM A TOKEN SAYS WHAT THAT TOKEN MAY DO AT THE FAR END.
//
// `/admin/delegation/allowed` draws the CONFIGURED register and every line on
// it carries the permission it is a grant of, because a configured grant IS a
// permission and nothing else. The pictures drawn from what actually happened —
// `/admin/delegation/user` and `/admin/tokens/credential` — draw the same
// `reaches` relation from an ISSUED token, and until 2026-09-02 those lines
// carried the mechanism and a credential count and said nothing at all about
// the permission. So the one picture that shows what a client DID was the one
// that could not say what it did it WITH.
//
// `common/user_graph.js`'s `permissionsAddressedTo()` is the rule that closed
// that, and this file is its guard. What it asserts is the READING rather than
// the plumbing: a client can name what it wants in TWO spellings, one of which
// leaves a permission name on the token and one of which deliberately does not,
// and both have to come out as one sentence on one line.
//
// ---------------------------------------------------------------------------
// WHY IN PROCESS, WHICH IS THE QUESTION tests/CLAUDE.md ASKS FIRST.
//
// The end-to-end claim is NOT here and belongs over HTTP:
// `tests/vendored/sts_delegated_permissions_example.js` builds five real
// applications, spends a real token and reads the line back off
// `/admin/delegation/user`, which is what proves the rule reaches a page.
//
// What cannot be driven over there is CHOOSING THE REGISTRY, and every case
// below turns on one:
//
//   * **AN AUDIENCE NOBODY ANSWERS TO.** A resource server that has never
//     spoken to this service is the ordinary state of a token addressed to one,
//     and the picture has to draw it without inventing a permission for it.
//     Producing that over HTTP means a token audienced at a URI no entry
//     carries — which the token endpoint will mint, but only if the registry
//     has been arranged not to know it, which is this file's arrangement made
//     the long way round.
//   * **A SCOPE VALUE THAT LOOKS LIKE A PERMISSION AND IS NOT.** `read` on a
//     token addressed to a resource that defines no `read` is the case the
//     intersection exists for, and the token endpoint will not produce it
//     against a resource that DOES define one — so the register has to be
//     chosen.
//   * **A RESOURCE WITH PERMISSIONS AND NO BASE URI.** `permissionsOf()` gives
//     those an empty identifier on purpose (no client can ever ask for one),
//     and `updateApplication()` refuses to create the state from either console
//     door. Only an `ldapmodify` writes it.
//
// The last of the three is the same argument `tests/app_permissions.js` makes
// about a dangling grant, and it is why that file and this one are neighbours
// rather than one file: that one is about the CONFIGURED register and this one
// is about an issued token read against it.
//
// It asserts the RENDERER too, and for `user_graph_signin.js`'s reason: the
// model folding correctly while the label drops the line, and the label drawing
// a line the model never fills, are both green in a test that looks at only one
// of them.
// ===========================================================================

// Deleted rather than set, for the reason config_realm_layer.js gives: nothing
// here should depend on a developer's exported appconfig.
delete process.env.CONFIG_FILE;

const applications = require('../common/applications');
const stats = require('../common/admin_stats');
const helpers = require('../common/helpers');
const userGraph = require('../common/user_graph');
const map = require('../admin-ui/delegation_map');

// The two clients this file mints tokens as. Names no other test and no seed
// uses, because the identity register is shared by every file in this run and
// an assertion about "the line into that resource" has to be about a person
// with exactly the tokens this file gave them.
const HOLDER = 'ugp-webapp';
const MACHINE = 'ugp-daemon';
const REFRESHER = 'ugp-refresher';

// ---------------------------------------------------------------------------
// THE REGISTRY, AS A STORE OF THIS FILE'S OWN.
//
// `applications.setDirectory()` is the slot `ldap/ldap_server.js` fills at
// require time, and requiring THAT module here would start an LDAP listener and
// register forty routes to answer a question about four entries. Only
// `allApplications()` is reached by the four lookups under test, so only that
// is supplied — a fuller fake would be four more functions nothing calls, each
// of which could be wrong without anything noticing.
//
// The entries are ATTRIBUTES rather than records, because that is what the
// directory hands back and `recordFromAttributes()` is part of what is being
// exercised: a fake that skipped it would be asserting this file's idea of an
// entry rather than the registry's.
// ---------------------------------------------------------------------------
function entry(identifier, attributes) {
  const attrs = { appIdentifier: [identifier], cn: [identifier] };
  Object.keys(attributes || {}).forEach(function (name) {
    attrs[name] = attributes[name];
  });
  // `operational` is a real member of what the directory hands back — the
  // attributes an entry has because it is an entry — and `view()` reads it. An
  // empty array is what such an entry carries here, not the absence of one.
  return { dn: 'cn=' + identifier + ',ou=applications', origin: 'test',
           createdAt: '', modifiedAt: '', operational: [], attributes: attrs };
}

// `abcapp2` exposes an API and `abcapp4` exposes the same two permissions under
// a base of its own — two resources, because a lookup that matched on a prefix,
// on a host or on the bare name would be right about one of them and wrong
// about the other, and one resource makes every such mistake invisible.
const REGISTRY = [
  entry('abcapp2', {
    oauthClientId: ['abcapp2'],
    oauthPermissionBaseUri: ['https://abcapp2.example1.com/'],
    oauthPermission: ['read|Read this application\'s data', 'write|Change it']
  }),
  entry('abcapp4', {
    oauthClientId: ['abcapp4'],
    oauthPermissionBaseUri: ['https://abcapp4.example1.com/'],
    oauthPermission: ['read', 'write']
  }),
  // THE SAME BASE WRITTEN THE OTHER WAY. An `ldapmodify` is not normalised —
  // the attribute's own schema row says so — so an entry can hold a base with
  // no trailing separator while every identifier this service composed from it
  // carries one, and the `aud` on a token is the composed form. Both sides have
  // to be normalised or this entry is unreachable from its own tokens.
  entry('looseapi', {
    oauthClientId: ['looseapi'],
    oauthPermissionBaseUri: ['https://looseapi.example1.com'],
    oauthPermission: ['read', 'write']
  }),
  // A resource server that has registered an audience and defines nothing.
  entry('plainapi', {
    oauthClientId: ['plainapi'],
    oauthAudience: ['https://plainapi.example1.com/']
  }),
  // AND THE STATE ONLY AN ldapmodify CAN WRITE: permissions with no base under
  // them, so every identifier they would have is empty.
  entry('baseless', {
    oauthClientId: ['baseless'],
    oauthPermission: ['read', 'write']
  })
];

// One `reaches` edge in `user_graph.js`'s shape, which is what the renderer is
// handed. Built by hand rather than through `graphFor()` for the reason the
// registry is: what is being asserted is the LABEL, and driving a whole
// person's picture to reach it would make a failure here indistinguishable
// from a failure in the fold.
function reachEdge(permissions, options) {
  const opts = options || {};
  return Object.assign({
    id: 'addressed | password | webapp1 > api', from: 'webapp1', to: 'api',
    fromRole: 'holder', toRole: 'target', relation: 'reaches',
    acts: 0, issued: 0, refused: 0, credentials: 1,
    firstAt: 1, lastAt: 1, authorizedBy: '', reason: '',
    consumed: [], produced: [], skipped: [], chainKey: '',
    protocols: ['OAuth 2.0'], protocol: 'OAuth 2.0',
    type: 'password', typeLabel: 'Password grant', mode: '', spec: '',
    policed: false, subject: 'alice', actor: 'webapp1',
    audience: 'https://abcapp2.example1.com/', audienceRegistered: false,
    scopes: ['openid'].concat(permissions || [])
  }, permissions === null ? {} : { permissions: permissions }, opts);
}

function graphOf(edges) {
  return {
    realm: { id: 'default', name: 'Default', isDefault: true },
    issuer: 'urn:test',
    nodes: [
      { id: 'webapp1', kind: 'party', application: 'webapp1', roles: {},
        acts: 0, issued: 0, refused: 0, credentials: 1, protocols: [],
        flows: [], kinds: [] },
      { id: 'api', kind: 'party', application: 'api', roles: {},
        acts: 0, issued: 0, refused: 0, credentials: 1, protocols: [],
        flows: [], kinds: [] }
    ],
    edges: edges
  };
}

// The words on the lines, with the SVG's escaping undone, so an assertion can
// look for a label the way a reader sees it.
function labels(svg) {
  return (svg.match(/<text[^>]*>[^<]*<\/text>/g) || []).map(function (one) {
    return one.replace(/<[^>]*>/g, '').replace(/&amp;/g, '&').replace(/&#39;/g, "'");
  });
}

function run(t) {
  // WHAT WAS THERE, rather than `null`. It was `null` until 2026-09-04, which
  // is right only in a process where `ldap/ldap_server.js` was never required
  // — and whether that is true depends on which test file happened to require
  // it first, because node's module cache means the fill runs once. Restoring
  // `null` in a run where it HAD been filled leaves every later file reading a
  // registry with no store.
  const before = applications.directoryInstalled();
  applications.setDirectory({
    allApplications: function () { return REGISTRY; }
  });

  // -----------------------------------------------------------------------
  t.log.info('the FULL PERMISSION IDENTIFIER spelling: the base is the ' +
             'audience and the names are on the scope claim');
  // -----------------------------------------------------------------------
  // What `audienceScopes()` writes for `scope=https://abcapp2.example1.com/read
  // https://abcapp2.example1.com/write`. No entry registers that base as an
  // `oauthAudience` and none answers to it as a client_id, so the only lookup
  // that can find it is `forPermissionBase()` — which is the whole reason that
  // lookup was added.
  t.equal(JSON.stringify(userGraph.permissionsAddressedTo(
            'openid read write', 'https://abcapp2.example1.com/')),
          JSON.stringify(['read', 'write']),
          'both names come back, in the order the token carries them');
  t.equal(JSON.stringify(userGraph.permissionsAddressedTo(
            'openid read write', 'https://abcapp2.example1.com')),
          JSON.stringify(['read', 'write']),
          'AN AUDIENCE WRITTEN WITHOUT ITS TRAILING SEPARATOR STILL RESOLVES');
  t.equal(JSON.stringify(userGraph.permissionsAddressedTo(
            'openid read', 'https://looseapi.example1.com/')),
          JSON.stringify(['read']),
          'AND SO DOES AN ENTRY THAT HOLDS ITS BASE THAT WAY, which is the ' +
          'direction that matters: an ldapmodify is not normalised, so an ' +
          'entry can carry `https://looseapi.example1.com` while every ' +
          'identifier composed from it — and therefore every `aud` a token ' +
          'addressed to it carries — ends in the separator. Normalising only ' +
          'the value asked for leaves that entry unreachable from its own ' +
          'tokens, and the line into it says `default permissions` for ever');
  t.check(userGraph.permissionsAddressedTo('openid read write',
            'https://abcapp2.example1.com/').indexOf('openid') < 0,
          'AND `openid` IS NOT ONE OF THEM. A scope claim carries the ' +
          'protocol\'s own words and anything else a client cared to send, so ' +
          'a line drawn from the scope claim alone would label a resource ' +
          'with words that have nothing to do with it');

  // -----------------------------------------------------------------------
  t.log.info('the CLIENT_ID spelling: nothing on the token names a permission');
  // -----------------------------------------------------------------------
  // `scope=abcapp4` produces `aud: abcapp4` and takes that value OFF the scope
  // claim, so what arrives here is a resource this registry knows perfectly
  // well and a scope claim with none of its permissions on it.
  t.equal(JSON.stringify(userGraph.permissionsAddressedTo('openid', 'abcapp4')),
          JSON.stringify([]),
          'THE ANSWER IS NONE, and it is an answer rather than a failure — ' +
          'the client named the resource and asked for none of its ' +
          'permissions, which the picture draws as `default permissions`');
  t.equal(JSON.stringify(userGraph.permissionsAddressedTo('openid read', 'abcapp4')),
          JSON.stringify(['read']),
          'AND A BARE NAME THAT IS ONE OF THAT RESOURCE\'S PERMISSIONS IS ' +
          'STILL NAMED. The question is asked of the TOKEN and not of the ' +
          'request, so however the client spelled it, what is on the scope ' +
          'claim beside that audience is what the line reports');

  // -----------------------------------------------------------------------
  t.log.info('the intersection is against THIS resource and no other');
  // -----------------------------------------------------------------------
  // Both resources define `read` and `write`. A lookup matching on a prefix, on
  // a host or on the bare name would be right about one of the two and would
  // have nothing on the page to say it was wrong about the other.
  t.equal(JSON.stringify(userGraph.permissionsAddressedTo(
            'read', 'https://abcapp4.example1.com/')),
          JSON.stringify(['read']),
          'abcapp4\'s base resolves to abcapp4');
  t.equal(JSON.stringify(userGraph.permissionsAddressedTo(
            'admin', 'https://abcapp2.example1.com/')),
          JSON.stringify([]),
          'AND A SCOPE VALUE THIS RESOURCE DOES NOT DEFINE IS NOT NAMED. ' +
          'Without this, any word a client sent would be reported as a ' +
          'permission of whatever the token happened to be addressed to');
  t.equal(JSON.stringify(userGraph.permissionsAddressedTo(
            'read', 'https://plainapi.example1.com/')),
          JSON.stringify([]),
          'a resource that has registered an audience and defined no ' +
          'permissions names none, however plausible the scope value looks');
  t.equal(JSON.stringify(userGraph.permissionsAddressedTo(
            'read', 'https://nobody.example1.com/')),
          JSON.stringify([]),
          'and an audience NOTHING here answers to names none either — which ' +
          'is what a real resource server looks like on this service, and is ' +
          'drawn as a box named after the URI with `default permissions` on ' +
          'the line into it');

  // -----------------------------------------------------------------------
  t.log.info('a permission with no base URI can never be asked for, so it is ' +
             'never reported as having been');
  // -----------------------------------------------------------------------
  // `permissionsOf()` gives these an empty identifier deliberately. The lookup
  // must not match them on the bare name, and it must not match the entry on an
  // empty base — which would make it the answer for every entry that has none.
  t.equal(JSON.stringify(userGraph.permissionsAddressedTo('read', 'baseless')),
          JSON.stringify(['read']),
          'reached by its client_id the entry is found and its permission is ' +
          'named — the name is on the entry, whatever its identifier is');
  t.equal(JSON.stringify(userGraph.permissionsAddressedTo('read', '')),
          JSON.stringify([]),
          'and a token with no audience at all names nothing');
  t.equal(applications.forPermissionBase(''), null,
          'AND THE LOOKUP ITSELF REFUSES AN EMPTY BASE, asked directly. ' +
          '`permissionBaseOf(\'\')` is the empty string, so a lookup that ' +
          'compared it without this guard would answer with the first entry ' +
          'that has NO base — which is the one entry it must never be, ' +
          'because those permissions have no identifier and no client can ' +
          'ever have asked for one');
  t.equal(applications.forPermissionBase('   '), null,
          'and a base that is only whitespace is the same answer, since that ' +
          'is what an attribute written by hand and then emptied looks like');

  // -----------------------------------------------------------------------
  t.log.info('and the picture says it, in words, on the line');
  // -----------------------------------------------------------------------
  const drawn = map.render(graphOf([reachEdge(['read', 'write'])]),
                           { id: 'perm', label: 'reached' });
  t.check(!drawn.failed, 'the picture is drawn', drawn.failed || '');
  const said = labels(drawn.svg);
  t.check(said.indexOf('read, write') >= 0,
          'THE PERMISSIONS ARE ON THE LABEL, which is the whole of what this ' +
          'change is for: the acts picture could say that a client reached a ' +
          'resource and could not say what it was allowed to do there',
          JSON.stringify(said));
  t.check(said.indexOf('reaches as alice') >= 0 &&
          said.indexOf('Password grant') >= 0 &&
          said.indexOf('1 credential') >= 0,
          'AND IT IS A FOURTH LINE RATHER THAN A REPLACEMENT. Who it is as, ' +
          'what mechanism issued it and how many credentials are each ' +
          'somebody\'s reason for reading this picture, and the permission ' +
          'cannot be inferred from any of them',
          JSON.stringify(said));
  t.check(drawn.svg.indexOf('Carries the delegated permissions read, write') > 0,
          'the tooltip carries them in full, because the label is capped and ' +
          'a resource exposing six of them would be cut there');

  const none = map.render(graphOf([reachEdge([])]), { id: 'perm', label: 'reached' });
  t.check(labels(none.svg).indexOf('default permissions') >= 0,
          'AN EMPTY LIST IS DRAWN AS `default permissions` AND NOT AS A BLANK ' +
          'LINE. It is what the client_id spelling produces, so it is the ' +
          'commonest state there is — and a blank would make it ' +
          'indistinguishable from a line the renderer has not been taught about',
          JSON.stringify(labels(none.svg)));

  // -----------------------------------------------------------------------
  t.log.info('a `reaches` line out of the DELEGATION register says none of it');
  // -----------------------------------------------------------------------
  // `delegation.graph()` emits the identical relation for a delegation ACT,
  // which has no scope claim anywhere behind it. The array's PRESENCE is what
  // tells the two apart, and an act line that said `default permissions` would
  // be the picture asserting something about a Kerberos ticket.
  const act = map.render(graphOf([reachEdge(null)]), { id: 'perm', label: 'acts' });
  t.check(labels(act.svg).indexOf('default permissions') < 0,
          'IT IS NOT LABELLED `default permissions`, because it is not a ' +
          'token: an act carries no scope claim, and saying anything here ' +
          'would be this renderer inventing a fact about a mechanism that has ' +
          'none',
          JSON.stringify(labels(act.svg)));
  t.check(act.svg.indexOf('Carries the delegated permission') < 0 &&
          act.svg.indexOf('DEFAULT PERMISSIONS') < 0,
          'and its tooltip says nothing about permissions either');

  // -----------------------------------------------------------------------
  t.log.info('the line keeps the console\'s neutral indigo');
  // -----------------------------------------------------------------------
  // Amber and green are this console's judgement about impersonation and
  // delegation. An ordinary grant claims neither, and a permission on the label
  // is not a reason to start claiming one.
  t.check(drawn.svg.indexOf('stroke="#8a6d00"') < 0 &&
          drawn.svg.indexOf('stroke="#0b6b4f"') < 0,
          'no line is amber or green — a permission says what a token may do ' +
          'and says nothing about whether anybody was impersonated');
  t.check(drawn.svg.indexOf('stroke="#12107c"') > 0,
          'it is indigo, the same as it was before it carried a permission');

  // -----------------------------------------------------------------------
  t.log.info('and the fold puts them on a real person\'s picture, from real ' +
             'token records');
  // -----------------------------------------------------------------------
  // Everything above would pass with a `graphFor()` that never called the
  // resolver. These are minted through `signJwt()`, so they go through the
  // recorder every token in this service goes through and arrive in the issued
  // register exactly as a token endpoint's would.
  //
  // WHAT CANNOT BE DRIVEN OVER HTTP HERE IS THE TRAFFIC, which is
  // `user_graph_signin.js`'s argument: one person holding one token addressed
  // to a resource by its BASE URI and another addressed to a second resource by
  // its CLIENT_ID, and nothing else, is a shape that takes two token requests
  // and a registry arranged around them to produce — and then the assertion is
  // about a graph, which over there means parsing it back out of an SVG.
  helpers.signJwt({
    typ: 'Bearer', jti: 'ugp-token-1', sub: HOLDER, iss: 'urn:test',
    client_id: HOLDER, aud: 'https://abcapp2.example1.com/',
    scope: 'openid read write'
  }, { grant: 'authorization_code' });
  helpers.signJwt({
    typ: 'Bearer', jti: 'ugp-token-2', sub: HOLDER, iss: 'urn:test',
    client_id: HOLDER, aud: 'abcapp4', scope: 'openid'
  }, { grant: 'authorization_code' });

  const picture = userGraph.graphFor(stats.identityKeyOf(HOLDER));
  const reaches = picture.graph.edges.filter(function (one) {
    return one.relation === 'reaches';
  });
  t.equal(reaches.length, 2, 'two resources reached, so two lines',
          JSON.stringify(reaches.map(function (one) { return one.to; })));
  const byBase = reaches.filter(function (one) {
    return one.audience === 'https://abcapp2.example1.com/';
  })[0];
  const byClientId = reaches.filter(function (one) {
    return one.audience === 'abcapp4';
  })[0];
  t.equal(JSON.stringify(byBase && byBase.permissions),
          JSON.stringify(['read', 'write']),
          'the line into the resource named by its base URI carries both ' +
          'permissions the token asked for');
  t.equal(JSON.stringify(byClientId && byClientId.permissions),
          JSON.stringify([]),
          'AND THE LINE INTO THE ONE NAMED BY ITS CLIENT_ID CARRIES AN EMPTY ' +
          'LIST RATHER THAN NO MEMBER AT ALL. The member is what the renderer ' +
          'tests to tell a token line from an act line, so an absent one here ' +
          'would silently draw this line as though it came out of the ' +
          'delegation register');
  t.check(byClientId && byClientId.scopes.indexOf('openid') >= 0,
          'the scope claim rides along for the tooltip, so a reader asking ' +
          'why a line says `default permissions` can see what the token did ' +
          'carry');

  // -----------------------------------------------------------------------
  t.log.info('a CLIENT CREDENTIALS token still draws the resource it reached');
  // -----------------------------------------------------------------------
  // The client is its own subject here, so there is no separate holder and the
  // person-to-application line collapses. The audience block sat inside that
  // holder's guard until 2026-09-02, so the one grant a machine-to-machine
  // client uses drew a grant line and NOTHING about the API it was for — on
  // the picture whose whole subject is which API a client reached.
  helpers.signJwt({
    typ: 'Bearer', jti: 'ugp-token-3', sub: MACHINE, iss: 'urn:test',
    client_id: MACHINE, aud: 'https://abcapp2.example1.com/',
    scope: 'read'
  }, { grant: 'client_credentials' });
  const machine = userGraph.graphFor(stats.identityKeyOf(MACHINE));
  const reached = machine.graph.edges.filter(function (one) {
    return one.relation === 'reaches';
  });
  t.equal(reached.length, 1,
          'THE LINE IS DRAWN AT ALL, which is the half of this that is not ' +
          'about a label: a client_credentials token names its resource in ' +
          'the same `aud` every other token does',
          JSON.stringify(machine.graph.edges.map(function (one) {
            return one.relation + ' ' + one.from + '>' + one.to;
          })));
  t.equal(reached[0] && reached[0].from, stats.identityKeyOf(MACHINE),
          'and it runs from the client itself, because there is no other box ' +
          'for it to run from');
  t.equal(JSON.stringify(reached[0] && reached[0].permissions),
          JSON.stringify(['read']),
          'carrying the permission it asked for');

  // -----------------------------------------------------------------------
  t.log.info('two credentials on ONE line are a union and not a last-one-wins');
  // -----------------------------------------------------------------------
  // The line is keyed on the GRANT rather than on the credential, so a client
  // that asked for `read`, then refreshed for `write`, has ONE line — and it
  // reaches that resource for both. Taking the last credential's answer would
  // make the label depend on the order the register happens to hold, which is
  // newest first and is not the order anything was asked in.
  helpers.signJwt({
    typ: 'Bearer', jti: 'ugp-token-4', sub: REFRESHER, iss: 'urn:test',
    client_id: REFRESHER, aud: 'https://abcapp2.example1.com/', scope: 'read'
  }, { grant: 'authorization_code' });
  helpers.signJwt({
    typ: 'Bearer', jti: 'ugp-token-5', sub: REFRESHER, iss: 'urn:test',
    client_id: REFRESHER, aud: 'https://abcapp2.example1.com/', scope: 'write'
  }, { grant: 'authorization_code' });
  const refreshed = userGraph.graphFor(stats.identityKeyOf(REFRESHER)).graph.edges
    .filter(function (one) { return one.relation === 'reaches'; });
  t.equal(refreshed.length, 1,
          'two credentials out of one grant to one resource are ONE line — ' +
          'three lines saying so would be the picture reporting the token ' +
          'endpoint\'s arithmetic');
  t.equal(JSON.stringify((refreshed[0].permissions || []).slice(0).sort()),
          JSON.stringify(['read', 'write']),
          'AND IT CARRIES BOTH. Either token alone names one of them, so a ' +
          'label built from the last credential seen would be right about ' +
          'half of what this line is for and would change with the order the ' +
          'register happened to hold');

  // CLEAN UP THE PROCESS-WIDE STATE. `applications.js`'s directory slot is one
  // reference for the whole process, and every other file in this run reads
  // through it — a fake left installed would answer every later question about
  // the registry with these four entries.
  applications.setDirectory(before);
}

module.exports = {
  name: 'user_graph_permissions',
  describe: 'a reaches line drawn from a token names the permissions on it',
  run: run
};
