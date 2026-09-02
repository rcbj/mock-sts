'use strict';
//
// File: app_permissions.js
//
// ---------------------------------------------------------------------------
// DELEGATED PERMISSIONS: WHO MAY REACH WHAT, DECIDED BEFOREHAND.
//
// `common/delegation.js` next door records what HAPPENED — one row per act, the
// moment a credential was issued or refused. This file is the other half of the
// same question and it is the CONFIGURED one: which client applications have
// been granted which permissions on which resource applications, typed in
// advance, before anybody has asked for anything.
//
// **THE TWO ARE NOT ONE REGISTER AND MUST NEVER BE DRAWN AS ONE.** That is the
// most important sentence in this file. An act is evidence; a grant is
// intent — and this repository already keeps exactly that distinction under two
// names one attribute apart (`appProtocol` is what happened, `appAllowedProtocol`
// is what somebody declared, and `applications.js`'s PROTOCOLS header spends a
// page on why collapsing them would be wrong). `/admin/delegation` shows both
// and says which is which on every heading, because the interesting reading is
// the DIFFERENCE: a grant nobody has used, and a delegation nobody granted.
//
// ---------------------------------------------------------------------------
// THE MODEL IS MICROSOFT ENTRA ID'S, DELIBERATELY AND BY NAME.
//
// A RESOURCE application exposes an API: it carries a base URI
// (`oauthPermissionBaseUri`, Entra's Application ID URI) and a list of
// permissions (`oauthPermission`, Entra's `oauth2PermissionScopes`). A CLIENT
// application is granted some of them (`oauthDelegatedPermission`, Entra's
// `requiredResourceAccess`). A permission is identified by its base URI
// followed by its name — `https://example.com/` and `write` make
// `https://example.com/write` — and a client asks for it by putting that whole
// string in an OAuth `scope`.
//
// Everything else follows from that one identifier:
//
//   * **1-to-many and many-to-1 both fall out of it** with no container of its
//     own. One client granted three permissions on one resource is three values
//     on the client's entry; three clients granted one permission is one value
//     on each of three entries. Nothing had to be invented for either shape.
//   * **The token says both halves.** `scope=openid https://example.com/write`
//     produces an access token audienced to `https://example.com/` carrying
//     `scope: openid write` — the base becomes the `aud` and the name becomes
//     the scope, which is exactly what Entra does and exactly what a resource
//     server wants: check `aud` once, then read bare permission names.
//     `oauth2.js`'s `audienceScopes()` is where that happens and it is the ONE
//     place it happens.
//   * **The grant is a QUESTION and not a gate, by default.** An ungranted
//     permission still produces the audience and the scope; it is recorded,
//     drawn as ungranted on the console, and logged. Only
//     `oauth2.delegatedPermissionsEnforced` — off by default — turns that into
//     `invalid_scope`. This service exists to exercise clients, and a refusal
//     that cannot be turned off removes a test case rather than adding one.
//
// ---------------------------------------------------------------------------
// IT IS A LIBRARY (rule 3) AND IT HOLDS NO STORE.
//
// It registers no route, so its position in the require order does not matter
// and it cannot be the reason a route is missing. It requires `helpers.js` and
// `applications.js`, and NOTHING ELSE in this service — no config, no directory,
// no express app. `applications.js` does not require it back, so there is no
// cycle and none of rule 3e's slots is needed.
//
// **`ou=applications` IS THE STORE AND THERE IS NO SECOND ONE HERE.** Every
// function below is a read of the registry or a write through
// `applications.updateApplication()`. That is not a simplification — it is the
// same rule `applications.js` states about itself at length: a Map in this file
// shadowing the directory would be a second store, it would look correct alone,
// and it would be the one that silently disagreed. It also means an
// `ldapmodify` IS a configuration change here, exactly as it is for a redirect
// URI: adding `oauthDelegatedPermission` to an entry by hand grants the
// permission, and this file will read it back.
//
// ---------------------------------------------------------------------------
// THE DIVISION OF LABOUR WITH `applications.js` IS EXACT.
//
// THAT module owns the SCHEMA — how a permission is spelled on an entry
// (`name` or `name|description`), how base and name are joined
// (`permissionIdOf()`), which spellings are legal, and the two lookups a reader
// of ONE entry needs (`forPermission()`, `holdsPermission()`). THIS module owns
// what the two halves MEAN when read against each other: the register in both
// directions, the five actions, and the graph. Neither knows the other's half,
// which is the same split `delegation.js` and `delegation_map.js` have and the
// reason both files stayed readable.
//
// **THE ORDERING RULE IS ENFORCED IN `applications.js` AND NOT HERE**, and that
// is worth stating because this is where somebody would look for it. A
// permission must be DEFINED before it can be GRANTED, and the check lives in
// `updateApplication()` because that is the ONE door the console form, the
// management API's generic `update` operation and the five actions below all go
// through. A copy of the rule here would be a second opinion, and the generic
// attribute editor would be the way around it.
// ---------------------------------------------------------------------------

const { log } = require('./helpers');
const applications = require('./applications');

// ---------------------------------------------------------------------------
// THE REGISTER, BOTH DIRECTIONS, FROM ONE WALK OF THE CONTAINER.
//
// One read of `ou=applications` answers every question this feature has, so it
// is done once and the two views are built from it. Two functions each walking
// the registry would be two linear reads per page and — the reason that
// actually matters — two chances to disagree about which entries count as
// resources.
//
// **A RESOURCE IS AN ENTRY THAT CARRIES A BASE URI OR A PERMISSION**, not one
// that carries both. An entry with a base and no permissions is an API somebody
// has started describing; an entry with permissions and no base is one whose
// base was removed from under them, and those permissions have no identifier
// and can never be asked for. Both are states worth SEEING, and an `is a
// resource` test that required both would have hidden the second one — which is
// the one that is actually broken.
// ---------------------------------------------------------------------------
function register() {
  log.debug("Entering register().");
  const rows = applications.list();

  // Every permission anybody defines, by identifier, so that a grant can be
  // resolved without a second walk. The value carries the resource as well as
  // the permission, because a grant names neither directly — it names the
  // composed identifier and both have to be recovered from it.
  const byId = {};
  const resources = [];

  rows.forEach(function (row) {
    const base = applications.permissionBaseOf((row.fields || {}).oauthPermissionBaseUri);
    const permissions = applications.permissionsOf(row);
    if (!base && !permissions.length) {
      return;
    }
    const resource = {
      identifier: row.identifier,
      name: row.name || row.identifier,
      baseUri: base,
      // The raw value beside the normalised one, because they can differ: an
      // `ldapmodify` is not normalised (the attribute's own row says so), so an
      // entry can hold `https://example.com` while every identifier computed
      // from it carries the `/` this module added. Showing only one of the two
      // would make the console disagree with an `ldapsearch`.
      rawBaseUri: String((row.fields || {}).oauthPermissionBaseUri || ''),
      permissions: permissions.map(function (one) {
        return {
          name: one.name,
          description: one.description,
          id: one.id,
          raw: one.raw,
          // Filled in below, once every client has been read. A permission
          // knows nothing about who holds it until the other half of the walk
          // has happened.
          grantedTo: []
        };
      }),
      grantsHeld: 0
    };
    resource.permissions.forEach(function (one) {
      if (one.id) {
        byId[one.id] = { resource: resource, permission: one };
      }
    });
    resources.push(resource);
  });

  // The grants. One row per (client, permission), which IS the relationship —
  // a client granted three permissions on one resource is three rows, because
  // three permissions is what was granted and collapsing them to one line
  // labelled `3` would be the page deciding that a permission is a detail of a
  // pair of applications. It is the other way round: the permission is the
  // relationship and the pair is what it happens to join.
  const grants = [];
  rows.forEach(function (row) {
    const held = ((row.fields || {}).oauthDelegatedPermission) || [];
    const list = Array.isArray(held) ? held : [held];
    // WHAT THIS CLIENT HAS ACTUALLY ASKED FOR, off `oauthScope` — the scopes
    // this application has been seen requesting. It is the only evidence in
    // this registry that a grant has ever been USED, and it is worth having on
    // the page precisely because the interesting reading of a configured
    // register is the difference between it and what happened. It is EVIDENCE
    // AND NOT PROOF: `oauthScope` records what was asked for, not what was
    // issued, and a request refused for some other reason still writes it.
    const asked = ((row.fields || {}).oauthScope) || [];
    const askedList = (Array.isArray(asked) ? asked : [asked]).map(String);
    list.forEach(function (value) {
      const id = String(value);
      const known = byId[id];
      const grant = {
        client: row.identifier,
        clientName: row.name || row.identifier,
        permissionId: id,
        // EMPTY ON A DANGLING GRANT, and the flag beside it says which of the
        // two states an empty resource means. See `dangling` below.
        resource: known ? known.resource.identifier : '',
        resourceName: known ? known.resource.name : '',
        baseUri: known ? known.resource.baseUri : '',
        permissionName: known ? known.permission.name : '',
        description: known ? known.permission.description : '',
        // NO APPLICATION DEFINES THIS PERMISSION. Not an error and not hidden:
        // the resource's entry may have been deleted, the permission removed
        // from under the grant, or an `ldapmodify` may have written a grant
        // that never resolved — and `updateApplication()` refuses to CREATE one
        // through either console door, so a dangling row is always something
        // that happened outside them. The same three-state honesty
        // `delegationPartyCell()` applies to a party it cannot resolve.
        dangling: !known,
        asked: askedList.indexOf(id) >= 0
      };
      grants.push(grant);
      if (known) {
        known.permission.grantedTo.push({
          identifier: row.identifier,
          name: row.name || row.identifier,
          asked: grant.asked
        });
        known.resource.grantsHeld++;
      }
    });
  });

  // Newest-activity order is what `applications.list()` already gives, and it
  // is the wrong order for a configuration table: a reader looking for a
  // relationship is looking for a NAME. Both lists are sorted by the names a
  // reader would search for, which also makes two runs of the same service
  // produce the same page.
  resources.sort(function (a, b) { return a.identifier.localeCompare(b.identifier); });
  grants.sort(function (a, b) {
    return a.client.localeCompare(b.client) ||
           a.permissionId.localeCompare(b.permissionId);
  });

  const permissions = [];
  resources.forEach(function (resource) {
    resource.permissions.forEach(function (one) {
      permissions.push({
        resource: resource.identifier,
        resourceName: resource.name,
        baseUri: resource.baseUri,
        name: one.name,
        description: one.description,
        id: one.id,
        raw: one.raw,
        grantedTo: one.grantedTo.slice(0)
      });
    });
  });

  const answer = {
    resources: resources,
    permissions: permissions,
    grants: grants,
    counts: {
      resources: resources.length,
      permissions: permissions.length,
      // The permissions nobody can ask for, counted separately because it is
      // the one number on this page that means something is WRONG rather than
      // merely unused.
      unidentified: permissions.filter(function (one) { return !one.id; }).length,
      grants: grants.length,
      dangling: grants.filter(function (one) { return one.dangling; }).length,
      // Grants nobody has used, and permissions nobody holds. These two are the
      // whole reason to draw a configured register beside an observed one.
      unused: grants.filter(function (one) { return !one.asked && !one.dangling; }).length,
      ungranted: permissions.filter(function (one) { return !one.grantedTo.length; }).length,
      clients: grants.reduce(function (all, one) {
        if (all.indexOf(one.client) < 0) all.push(one.client);
        return all;
      }, []).length
    }
  };
  log.debug("Leaving register(). " + answer.counts.permissions + " permission(s), " +
            answer.counts.grants + " grant(s).");
  return answer;
}

// Everything one application is on either side of, for the drill-down on
// `/admin/applications` and for the message an action answers with. Built from
// `register()` rather than from a read of the one entry, because half the
// answer — who holds MY permissions — is on other entries entirely.
function forApplication(identifier) {
  log.debug("Entering forApplication(). identifier=" + identifier);
  const wanted = String(identifier == null ? '' : identifier).trim();
  const all = register();
  const answer = {
    identifier: wanted,
    exposes: all.permissions.filter(function (one) { return one.resource === wanted; }),
    holds: all.grants.filter(function (one) { return one.client === wanted; }),
    // Who holds a permission THIS application defines. The third list rather
    // than a member of `exposes`, because it is the question a person asks
    // about the application as a whole — *who can reach me* — and answering it
    // by asking the reader to fold up a column would be the page doing
    // arithmetic on their behalf.
    grantedToOthers: all.grants.filter(function (one) { return one.resource === wanted; })
  };
  log.debug("Leaving forApplication(). exposes=" + answer.exposes.length +
            ", holds=" + answer.holds.length);
  return answer;
}

// ---------------------------------------------------------------------------
// THE FIVE ACTIONS.
//
// Every one of them is a call to `applications.updateApplication()` with a
// better sentence wrapped round it. That is the whole of what they add and it
// is deliberate: the RULES are in that function, where the console's generic
// attribute editor and the management API's generic `update` operation also go
// through them, and what is missing there is only that its messages are about
// an ATTRIBUTE (`added "https://example.com/write" to oauthDelegatedPermission`)
// where a reader of this feature is thinking about a RELATIONSHIP.
//
// They return `applications.updateApplication()`'s shape unchanged —
// `{ ok, changed, application, message, errors }` — so the console's
// `respondToAction()` and the management API's handler need nothing new.
// ---------------------------------------------------------------------------

// THE BASE URI. Set it, or clear it by sending an empty value.
function setBaseUri(resource, value) {
  log.debug("Entering setBaseUri(). resource=" + resource);
  const asked = String(value == null ? '' : value).trim();
  const result = applications.updateApplication(resource, {
    attribute: 'oauthPermissionBaseUri', mode: 'set', value: asked,
    actor: arguments[2] || ''
  });
  if (!result.ok) {
    log.debug("Leaving setBaseUri(). Refused.");
    return result;
  }
  const normalised = applications.permissionBaseOf(asked);
  log.debug("Leaving setBaseUri(). ok.");
  return Object.assign({}, result, {
    message: asked
      ? '"' + resource + '" exposes its permissions under ' + normalised +
        (normalised === asked
          ? '. '
          : ' — a trailing separator was added, because a permission identifier is the ' +
            'base followed by the name and "' + asked + '" + "write" would otherwise ' +
            'read as one word. ') +
        'A permission called `write` on it is now `' + normalised + 'write`, which is ' +
        'what a client puts in a `scope` and what an access token asking for it is ' +
        'AUDIENCED to.'
      : '"' + resource + '" no longer has a permission base URI. Any permission still on ' +
        'the entry has no identifier now and no client can ask for it — /admin/delegation ' +
        'lists those rather than hiding them. Grants already made are unaffected on the ' +
        'clients holding them and become DANGLING, which is the same honest state.'
  });
}

// DEFINE A PERMISSION on a resource. The name and the description arrive
// separately and are joined here, because `name|description` is the SCHEMA's
// spelling and a caller should not have to know it — that is exactly the kind
// of thing that ends up spelled two ways.
function definePermission(resource, name, description) {
  log.debug("Entering definePermission(). resource=" + resource + ", name=" + name);
  const leaf = String(name == null ? '' : name).trim();
  const value = applications.permissionValueOf(leaf, description);
  const result = applications.updateApplication(resource, {
    attribute: 'oauthPermission', mode: 'add', value: value,
    actor: arguments[3] || ''
  });
  if (!result.ok) {
    log.debug("Leaving definePermission(). Refused.");
    return result;
  }
  const base = applications.permissionBaseOf(
    ((result.application || {}).fields || {}).oauthPermissionBaseUri);
  log.debug("Leaving definePermission(). ok.");
  return Object.assign({}, result, {
    message: '"' + resource + '" now exposes the permission `' + leaf + '`, identified by ' +
             '`' + base + leaf + '`. NOTHING HOLDS IT YET — defining a permission grants it ' +
             'to nobody, which is the ordering this feature is built on. Grant it to a ' +
             'client and a request carrying `' + base + leaf + '` in its `scope` produces an ' +
             'access token audienced to ' + base + ' with `' + leaf + '` on its scope claim.'
  });
}

// REMOVE ONE. The value has to match what is on the entry exactly — description
// and all — so it is composed from the permission this module found rather than
// from what a form typed, which is why the caller passes the NAME and this
// looks the raw value up.
function removePermission(resource, name) {
  log.debug("Entering removePermission(). resource=" + resource + ", name=" + name);
  const leaf = String(name == null ? '' : name).trim();
  const entry = applications.get(resource);
  if (!entry) {
    log.debug("Leaving removePermission(). No such application.");
    return { ok: false, errors: ['There is no application called "' + resource + '" in this ' +
                                 'registry.'] };
  }
  const found = applications.permissionsOf(entry).filter(function (one) {
    return one.name === leaf;
  })[0];
  if (!found) {
    log.debug("Leaving removePermission(). No such permission.");
    return { ok: false, errors: ['"' + resource + '" defines no permission called "' + leaf +
                                 '". It defines: ' +
                                 (applications.permissionsOf(entry).map(function (one) {
                                   return one.name;
                                 }).join(', ') || '(none)') + '.'] };
  }
  const result = applications.updateApplication(resource, {
    attribute: 'oauthPermission', mode: 'remove', value: found.raw,
    actor: arguments[2] || ''
  });
  if (!result.ok) {
    log.debug("Leaving removePermission(). Refused.");
    return result;
  }
  // WHO STILL HOLDS IT, counted AFTER the removal, because that is the fact the
  // person needs and it is not obvious: removing a permission does NOT revoke
  // the grants naming it. They stay on the clients' entries and become
  // DANGLING, which the console reports. Silently tidying them would be this
  // action writing to entries the person did not name.
  const stranded = register().grants.filter(function (one) {
    return one.permissionId === found.id;
  });
  log.debug("Leaving removePermission(). ok, " + stranded.length + " stranded.");
  return Object.assign({}, result, {
    message: '"' + resource + '" no longer exposes `' + leaf + '`. ' +
      (stranded.length
        ? '<strong>' + stranded.length + ' grant(s) still name `' + found.id +
          '` and are now DANGLING</strong> — on ' +
          stranded.map(function (one) { return one.client; }).join(', ') +
          '. They were NOT removed, deliberately: revoking them would be this action ' +
          'writing to entries you did not name. Revoke each one, or define the permission ' +
          'again and they resolve exactly as before.'
        : 'Nothing was holding it, so no grant was stranded.')
  });
}

// GRANT one to a client. The ordering rule — the permission must already
// exist — is checked in `applications.updateApplication()`; see this file's
// header for why it is there and not here.
function grant(client, permissionId) {
  log.debug("Entering grant(). client=" + client);
  const id = String(permissionId == null ? '' : permissionId).trim();
  const result = applications.updateApplication(client, {
    attribute: 'oauthDelegatedPermission', mode: 'add', value: id,
    actor: arguments[2] || ''
  });
  if (!result.ok) {
    log.debug("Leaving grant(). Refused.");
    return result;
  }
  const defines = applications.forPermission(id);
  log.debug("Leaving grant(). ok.");
  return Object.assign({}, result, {
    message: '"' + client + '" is granted `' + id + '`' +
      (defines ? ', which "' + defines.identifier + '" exposes' : '') + '. A request from ' +
      'it carrying that string in `scope` produces an access token audienced to ' +
      (defines ? defines.baseUri : 'the permission\'s base URI') + ' with `' +
      (defines ? defines.name : id) + '` on its scope claim. <strong>It was already ' +
      'producing one</strong> — the grant is recorded and reported and refuses nothing ' +
      'unless `oauth2.delegatedPermissionsEnforced` is on, which is off by default because ' +
      'a refusal that cannot be turned off removes a test case rather than adding one.'
  });
}

function revoke(client, permissionId) {
  log.debug("Entering revoke(). client=" + client);
  const id = String(permissionId == null ? '' : permissionId).trim();
  const result = applications.updateApplication(client, {
    attribute: 'oauthDelegatedPermission', mode: 'remove', value: id,
    actor: arguments[2] || ''
  });
  if (!result.ok) {
    log.debug("Leaving revoke(). Refused.");
    return result;
  }
  log.debug("Leaving revoke(). ok.");
  return Object.assign({}, result, {
    message: '"' + client + '" no longer holds `' + id + '`. With ' +
             '`oauth2.delegatedPermissionsEnforced` OFF this changes nothing about what it ' +
             'is issued — the permission still becomes an audience and a scope, and ' +
             '/admin/delegation now shows those requests as UNGRANTED, which is the state ' +
             'the setting turns into a refusal.'
  });
}

// ---------------------------------------------------------------------------
// THE PICTURE, IN `delegation.graph()`'s SHAPE.
//
// It returns the same `{ nodes, edges }` that `common/delegation.js` returns,
// so `admin-ui/delegation_map.js` draws it with no argument about which graph
// it is looking at — the renderer takes a graph and knows nothing about where
// it came from, which is the property its header says it was split out to keep.
//
// **EVERY BOX IS AN APPLICATION AND THERE IS NO PERSON ON THIS PICTURE**, which
// is the whole visual difference from the acts diagram and is why the two must
// not be drawn on one canvas. A delegation ACT has three layers and the first
// of them is a PERSON — a stick figure, someone on whose behalf something
// happened. A configured permission has no person in it at all: it says
// `webapp1 may reach https://example.com/ as whoever is signed in`, and there
// is no whoever yet. Merging the two would put a picture of what may happen and
// a picture of what did happen in one frame with no way to tell a box that has
// been used from a box that has been described.
//
// **THIS SERVICE IS NOT ON IT EITHER**, and that is the second difference. The
// hexagon is on the acts picture because every line there exists because this
// service issued or refused something; not one line here has been issued at
// all. A hexagon would be a box with no edges, which is a drawing of a claim
// nobody made.
//
// **ONE EDGE PER PERMISSION, NOT PER PAIR.** Two grants between the same two
// applications are two lines, for `delegation.graph()`'s reason about two
// mechanisms joining the same boxes: `webapp1 -> api1` for `read` and the same
// pair for `write` are two different arrangements, and one line labelled `2`
// would hide which permissions were granted — which is the only thing the
// picture is being asked.
// ---------------------------------------------------------------------------
function graph(rows) {
  log.debug("Entering graph().");
  const source = rows || register().grants;
  const nodes = new Map();
  const edges = new Map();

  function nodeFor(identifier, role) {
    let node = nodes.get(identifier);
    if (!node) {
      node = {
        id: identifier,
        kind: 'party',
        // `application` is what makes `delegationNodeLook()` draw a RECTANGLE
        // and resolve the label out of `ou=applications`; `key` is left empty
        // because nothing here is a person, which is what stops the renderer
        // reaching for a stick figure. See that function — the shape falls out
        // of these two members and nothing else.
        key: '', presented: identifier, application: identifier,
        what: '',
        roles: { initial: 0, intermediary: 0, target: 0 },
        protocols: ['OAuth 2.0 / OIDC'],
        // `acts` MUST STAY ZERO ON EVERY BOX. `edgeLook()` colours an edge RED
        // when `acts && !issued`, which is its way of saying "this was tried and
        // refused" — and every line here has been tried nought times. A
        // configured grant drawn in the refusal colour would be the picture
        // asserting the one thing it cannot know.
        acts: 0, issued: 0, refused: 0,
        firstAt: 0, lastAt: 0,
        selfTarget: false,
        // This file's own two, read by the console's node table rather than by
        // the renderer.
        grants: 0, exposes: 0, dangling: 0
      };
      nodes.set(identifier, node);
    }
    node.roles[role]++;
    return node;
  }

  source.forEach(function (row) {
    // A DANGLING GRANT HAS NO RESOURCE BOX TO REACH, so it draws no line. It is
    // still on the tables and in the counts — the picture is not where that
    // state is reported, because a line to nowhere is not a drawing of a
    // missing resource, it is a drawing of a resource that is there.
    if (row.dangling || !row.resource) {
      const orphan = nodeFor(row.client, 'intermediary');
      orphan.dangling++;
      orphan.grants++;
      return;
    }
    const from = nodeFor(row.client, 'intermediary');
    const to = nodeFor(row.resource, 'target');
    from.grants++;
    to.exposes++;
    if (row.client === row.resource) {
      // Cannot happen through either console door — `updateApplication()`
      // refuses an application granting itself — and an `ldapmodify` can still
      // write it. Recorded on the box the way `delegation.graph()` records
      // S4U2Self, because an arrow leaving a box and returning to it is a
      // drawing of nothing.
      to.selfTarget = true;
      return;
    }
    const id = row.client + ' | ' + row.permissionId;
    if (!edges.has(id)) {
      edges.set(id, {
        id: id,
        from: from.id, to: to.id,
        fromRole: 'intermediary', toRole: 'target',
        // THE RELATION THIS FILE ADDS TO THE RENDERER, and the third one added
        // by a caller after `user_graph.js`'s two. It is deliberately NOT
        // `reaches`: that word is the acts picture's claim that a credential
        // was issued FOR something, and this line says only that one may be.
        relation: 'may-reach',
        // No mode, no mechanism and no spec, because a configured permission is
        // none of those. `edgeLabelLines()` and `edgeLook()` are given a
        // `may-reach` branch of their own rather than falling through to the
        // `reaches` default, so that neither borrows the impersonation/
        // delegation colouring — which is a judgement about a mechanism, and
        // there is no mechanism here.
        mode: '', type: '', typeLabel: '', spec: '', policed: false,
        skipped: [],
        subject: '', actor: '',
        acts: 0, issued: 0, refused: 0,
        firstAt: 0, lastAt: 0,
        authorizedBy: '', reason: '',
        consumedFold: {}, producedFold: {},
        // This file's own.
        permissionId: row.permissionId,
        permissionName: row.permissionName,
        baseUri: row.baseUri,
        description: row.description,
        asked: false
      });
    }
    const edge = edges.get(id);
    // WHETHER THE CLIENT HAS EVER ASKED FOR IT — the one thing on this picture
    // that comes from what happened rather than from what was configured. It is
    // carried so the line can be drawn SOLID when it has been used and dashed
    // when it has not, which is the single most useful thing a configured
    // picture can say: these are the grants nobody needed.
    if (row.asked) edge.asked = true;
  });

  const answer = {
    nodes: Array.from(nodes.values()),
    edges: Array.from(edges.values()),
    // The same members `delegation.graph()` publishes, so a caller can hand
    // either to the renderer and to `?format=json` without asking which it has.
    counts: {
      nodes: nodes.size,
      edges: edges.size,
      grants: source.length
    }
  };
  log.debug("Leaving graph(). " + answer.counts.nodes + " box(es), " +
            answer.counts.edges + " line(s).");
  return answer;
}

// ---------------------------------------------------------------------------
// THE GROUPINGS: WHICH APPLICATIONS CAN BE REACHED FROM WHICH, FOLLOWING A
// GRANT IN EITHER DIRECTION.
//
// `graph()` above answers *what may reach what* and it answers it for the whole
// registry at once. That is the right picture for a service with five
// applications in it and it is the wrong one for a service with eighty: the
// interesting reading of a permission register is almost never the whole of it,
// it is **which applications are joined to each other at all** — the API and the
// three front ends that hold permissions on it, the batch job that reaches two
// of them, and the twelve applications elsewhere in the registry that have
// nothing whatever to do with any of it.
//
// So this function partitions the register into GROUPS. A group is a connected
// component of the grant graph, and the whole of the definition is in the next
// paragraph.
//
// **DIRECTION IS IGNORED, DELIBERATELY, AND IT IS THE ONE DECISION HERE.** A
// grant is directed — a CLIENT is granted a permission a RESOURCE exposes, and
// the picture draws that with a round end and an arrowhead precisely because
// the two ends are not interchangeable. Following the arrows would answer *what
// can this client eventually reach*, which is a question about a chain; a
// permission register has no chains in it, because holding a permission on an
// API does not grant that API's own permissions to anybody. Following a grant
// EITHER WAY answers the question a reader actually brings to this page —
// *which applications are in the same conversation as this one* — and it is the
// only reading under which the API and the three front ends holding permissions
// on it come out as one group rather than as four. The PICTURE still draws
// every line with its direction on it, so nothing is lost: what is dropped is
// direction as a criterion for MEMBERSHIP, not direction as a fact.
//
// Three states join no two applications and each is a different reason:
//
//   * **A DANGLING grant** names a permission no application defines, so there
//     is no far end to be in a group with. Its client is a member of whatever
//     group its other grants put it in, and of a group of its own if it has
//     none — which is the honest drawing of *this application has been granted
//     something that does not exist*.
//   * **A SELF-GRANT** (client and resource the same entry, which only an
//     `ldapmodify` can write — see `graph()`) is one application, so it is one
//     group of one. `graph()` already refuses to draw an arrow from a box back
//     to itself; there is nothing for that arrow to connect either.
//   * **A RESOURCE NOBODY HOLDS ANYTHING ON** is a group of one, and it is in
//     this answer rather than left out of it. An API with permissions defined
//     and no grants against them is the most interesting group of one there is:
//     somebody described an API and nothing may reach it. Leaving it out would
//     have made this list a list of grants wearing a different hat.
//
// The MEMBERSHIP UNIVERSE is therefore every application the configured
// register touches at all: every resource `register()` found (an entry carrying
// a base URI or a permission), and every client holding a grant. An entry in
// `ou=applications` that is neither is not in any group, because this register
// has nothing to say about it — `/admin/applications` is where those live.
//
// **IT TAKES THE REGISTER RATHER THAN READING ONE.** `register()` is a walk of
// `ou=applications` and the console already has its answer in hand when it asks
// for this; a second walk would be a second linear read per page and — the part
// that actually matters — a second chance to disagree with the picture drawn
// beside it about which entries are resources.
// ---------------------------------------------------------------------------
function clusters(reg) {
  log.debug("Entering clusters().");
  const all = reg || register();

  // Union-find over the identifiers. A breadth-first walk of an adjacency map
  // would do as well and this is shorter to be sure of: there is no recursion
  // to blow a stack on a long chain, and the two halves — `add` and `join` —
  // are each three lines, so the whole partition is something a reader can
  // check rather than trust.
  const parent = {};
  function add(id) {
    if (!Object.prototype.hasOwnProperty.call(parent, id)) {
      parent[id] = id;
    }
  }
  function find(id) {
    let at = id;
    // Path halving. Every lookup shortens the chain it walked, so a register
    // built one grant at a time does not degenerate into a list.
    while (parent[at] !== at) {
      parent[at] = parent[parent[at]];
      at = parent[at];
    }
    return at;
  }
  function join(a, b) {
    const ra = find(a);
    const rb = find(b);
    if (ra !== rb) {
      parent[ra] = rb;
    }
  }

  all.resources.forEach(function (one) {
    add(one.identifier);
  });
  all.grants.forEach(function (one) {
    add(one.client);
    // A dangling grant has no resource — see the header. `row.resource` is the
    // empty string there rather than a name nothing answers to, which is
    // `register()`'s own three-state honesty and is why this test is on the
    // value and not on the `dangling` flag beside it.
    if (one.resource) {
      add(one.resource);
      join(one.client, one.resource);
    }
  });

  const membersOf = {};
  Object.keys(parent).forEach(function (id) {
    const root = find(id);
    (membersOf[root] = membersOf[root] || []).push(id);
  });

  // THE KEY IS THE ALPHABETICALLY FIRST MEMBER AND NOT THE UNION-FIND ROOT.
  // The root is whichever identifier the joins happened to leave on top, so it
  // moves when a grant is added anywhere in the group — which would make every
  // link to a group on the console a link that goes stale for a reason nobody
  // could see. The first member is a property of the SET, so a group keeps its
  // name until its membership changes.
  const keyOf = {};
  Object.keys(membersOf).forEach(function (root) {
    membersOf[root].sort(function (a, b) { return a.localeCompare(b); });
    keyOf[root] = membersOf[root][0];
  });
  const memberOf = {};
  Object.keys(parent).forEach(function (id) {
    memberOf[id] = keyOf[find(id)];
  });

  // Every grant and every permission filed under the group it belongs to. A
  // grant is filed by its CLIENT, which is enough: its resource is in the same
  // group by construction where it has one, and where it has not the grant is
  // dangling and belongs to the client alone.
  const grantsOf = {};
  all.grants.forEach(function (one) {
    const key = memberOf[one.client];
    (grantsOf[key] = grantsOf[key] || []).push(one);
  });
  const permissionsOf = {};
  all.permissions.forEach(function (one) {
    const key = memberOf[one.resource];
    (permissionsOf[key] = permissionsOf[key] || []).push(one);
  });

  const list = Object.keys(membersOf).map(function (root) {
    const key = keyOf[root];
    const members = membersOf[root];
    const grants = grantsOf[key] || [];
    const permissions = permissionsOf[key] || [];
    // WHAT THE PICTURE WILL ACTUALLY DRAW, counted here rather than by the page
    // that draws it. `graph()` draws no line for a dangling grant and none for
    // a self-grant, and a group whose table said `3 grants` above a diagram
    // with one line on it would be the console disagreeing with itself about
    // the same three rows.
    const drawn = grants.filter(function (one) {
      return !one.dangling && one.resource && one.resource !== one.client;
    });
    return {
      key: key,
      members: members,
      grants: grants,
      permissions: permissions,
      counts: {
        applications: members.length,
        grants: grants.length,
        lines: drawn.length,
        permissions: permissions.length,
        dangling: grants.filter(function (one) { return one.dangling; }).length,
        selfGrants: grants.filter(function (one) {
          return !one.dangling && one.resource && one.resource === one.client;
        }).length,
        // The two readings the whole configured register exists for, per group:
        // a grant somebody has asked for at least once, and one nobody has ever
        // needed. Dangling rows are in neither, because `asked` on a grant that
        // resolves to nothing is not evidence about a relationship.
        asked: drawn.filter(function (one) { return one.asked; }).length,
        unused: drawn.filter(function (one) { return !one.asked; }).length
      }
    };
  });

  // BIGGEST FIRST, because the page this feeds exists to surface the groups
  // worth looking at and a list of forty groups of one with the interesting one
  // at position thirty-one is the same problem the whole-register picture had.
  // Ties broken by the number of lines and then by the key, so that two runs of
  // the same service produce the same page — `register()` sorts for the same
  // reason and says so.
  list.sort(function (a, b) {
    return b.counts.applications - a.counts.applications ||
           b.counts.lines - a.counts.lines ||
           a.key.localeCompare(b.key);
  });

  const answer = {
    clusters: list,
    memberOf: memberOf,
    counts: {
      clusters: list.length,
      applications: Object.keys(parent).length,
      largest: list.length ? list[0].counts.applications : 0,
      alone: list.filter(function (one) { return one.counts.applications === 1; }).length,
      joined: list.filter(function (one) { return one.counts.applications > 1; }).length
    }
  };
  log.debug("Leaving clusters(). " + answer.counts.clusters + " group(s) over " +
            answer.counts.applications + " application(s); largest " +
            answer.counts.largest + ".");
  return answer;
}

// The one group an application is in, or null where the configured register has
// never heard of it. Exact equality on the identifier, for the reason `graph()`
// gives above and `applications.js` gives at length: nothing here case-folds an
// identifier, and matching loosely in this one function would be this module
// deciding a comparison rule on that one's behalf.
function clusterFor(identifier, reg) {
  const wanted = String(identifier == null ? '' : identifier).trim();
  log.debug("Entering clusterFor(). identifier=" + wanted);
  const all = reg || clusters();
  const key = all.memberOf[wanted];
  const found = key === undefined
    ? null
    : all.clusters.filter(function (one) { return one.key === key; })[0] || null;
  log.debug("Leaving clusterFor(). " +
            (found ? found.counts.applications + " application(s) in it."
                   : "Not in the configured register."));
  return found;
}

module.exports = {
  register: register,
  forApplication: forApplication,
  setBaseUri: setBaseUri,
  definePermission: definePermission,
  removePermission: removePermission,
  grant: grant,
  revoke: revoke,
  graph: graph,
  clusters: clusters,
  clusterFor: clusterFor
};
