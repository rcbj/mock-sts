'use strict';
//
// File: admin_rbac.js
//
// ---------------------------------------------------------------------------
// WHO MAY USE THE ADMIN CONSOLE, AND WHAT THEY MAY DO ON IT.
//
// Two roles — **Admin Read** and **Admin Write** — and one rule about them:
// WRITE IMPLIES READ. A role that could post a form to a page it was not
// allowed to look at would be a trap rather than a permission, and somebody
// would eventually be granted it on purpose.
//
// ---------------------------------------------------------------------------
// THE ROLES ARE TWO ORDINARY GROUPS IN THE EMBEDDED DIRECTORY.
//
// `cn=admin-read,ou=groups` and `cn=admin-write,ou=groups` by default, both
// renameable (`admin.readGroup`, `admin.writeGroup`). They are not a store of
// this console's own, and that was the first decision made here.
//
// The reason is the one-store rule this service follows everywhere it has been
// tempted otherwise: the revoked-jti set is shared between `/oauth2/revoke` and
// the console, the session store is owned by `authn.js` and read by three
// modules, and SCIM writes into the SAME directory `/admin/users` reads. A
// membership store of this module's own would be a SECOND answer to "is alice
// an admin" — one that an `ldapmodify`, a SCIM PATCH and `/admin/groups` could
// not see, and that would drift from them silently, because nothing anywhere
// compares two stores that were never meant to disagree.
//
// So there are FOUR DOORS onto one membership and they all end up in the same
// entry: this module's own screen at `/admin/rbac`, `POST /admin-api/rbac/…`,
// an `ldapmodify` on 389 or 636, and a SCIM PATCH of the Group resource. That
// is the point rather than a side effect — a mock exists to be driven, and a
// role you can only grant through a web form is one no test can grant.
//
// ---------------------------------------------------------------------------
// AND IT MAKES ONE SENTENCE IN THIS REPOSITORY NO LONGER UNIVERSALLY TRUE.
//
// "A group here grants nothing" is written in README.md, in three CLAUDE.md
// files, in `sts_metadata.js`, on `/admin/groups` itself and in `group_claims.js`.
// It is STILL true of every other group and it is still true of these two
// everywhere except this console: no token's scopes change, no assertion gains
// an attribute, no protocol endpoint reads them, and a member of `admin-write`
// has exactly the same access to `/oauth2/token` as anybody else. What changed
// is that ONE surface — `/admin` — now reads two named groups. Every place that
// sentence appears has been qualified rather than deleted, because deleting it
// would leave a reader believing that adding somebody to `cn=developers`
// changed what their token could do.
//
// ---------------------------------------------------------------------------
// THE EMPTY ROSTER, which is the only interesting decision in the file.
//
// This service has no password anywhere. It checks none, it stores none, and
// the roster lives in memory and dies with the process — so there is no
// bootstrap administrator and no way to make one out of band. A service that
// started with `admin.authRequired` on and an empty roster would therefore have
// a console that NO browser could ever reach, and no amount of signing in would
// help.
//
// So: while NEITHER role group has a single member, anybody who signs in holds
// BOTH roles, and every page says so in a banner that cannot be missed. The
// moment the first grant is made the roster is enforced, and the banner goes.
// `admin.openWhenEmpty` turns that off for somebody who wants the locked case,
// and the way back in from it is `/admin-api`, which is not gated.
//
// It is deliberately "no members" rather than "the groups do not exist": a
// group that exists with nobody in it is the state a revoke of the last grant
// leaves behind, and treating that as closed would mean the console silently
// locking itself the moment somebody tidied up. Both spellings of empty mean
// the same thing here, which is the answer that has no surprising edge.
//
// ---------------------------------------------------------------------------
// This module is a LIBRARY (rule 3). It registers no route, so its position in
// `server.js`'s require order does not matter, and it cannot join a cycle: it
// requires `config.js`, `helpers.js` and `audit.js`, none of which requires it.
//
// It reaches the directory through a SLOT that `ldap_server.js` fills at its
// own require time, for the reason `admin.js`'s five slots exist (rule 3e):
// requiring `ldap_server.js` from here would pull every `/ldap` route into the
// express router ahead of every `/admin` route, and `GET /sts-metadata` is built
// by walking that router. The slot is on THIS module rather than a sixth on
// `admin.js` because what fills it is one coherent thing — the group functions
// — and because both callers of it (`admin.js` and `admin_api.js`) want the
// decisions here rather than the raw directory.
//
// The slot takes ONE OBJECT where `admin.js` deliberately takes five separate
// functions, and the concern stated there — "a module that filled a combined
// slot with only the readers would silently disable creation" — is answered
// rather than ignored: `setDirectory()` CHECKS every member it needs and
// refuses a partial object loudly. A half-filled slot is a startup warning
// here, not a control that quietly does nothing.
// ---------------------------------------------------------------------------

const { log } = require('../common/helpers');
const config = require('../common/config');
const audit = require('../common/audit');

// The two roles. An array rather than two constants because everything below
// walks it — the screen, the API, the JSON view, the decision — and a third
// role, if there is ever one, should cost one row rather than six edits.
//
// `implies` is what makes WRITE IMPLY READ a property of the table rather than
// an `if` somewhere: `rolesOf()` expands it, so a page asking "may this person
// read" gets the same answer wherever it asks from.
const ROLES = [
  { id: 'read', label: 'Admin Read', setting: 'admin.readGroup',
    implies: [],
    what: 'Look at every page of this console, and at every ?format=json view ' +
          'of one. It changes nothing: a reader can see which tokens are ' +
          'revoked and cannot revoke one.' },
  { id: 'write', label: 'Admin Write', setting: 'admin.writeGroup',
    implies: ['read'],
    what: 'Post every form on this console — revoke a token, add a custom ' +
          'claim, change a setting, create a person, grant a role. IT ' +
          'INCLUDES READ, so a member of this role alone can use the whole ' +
          'console.' }
];

const ROLE_IDS = ROLES.map(function (role) { return role.id; });

function roleFor(id) {
  const wanted = String(id == null ? '' : id).trim().toLowerCase();
  return ROLES.filter(function (role) { return role.id === wanted; })[0] || null;
}

// The cn of the group behind a role, read WHERE IT IS USED rather than captured
// at require time, because both settings are `runtime: true` — somebody who
// renames the write group on /admin/config expects the next request to use the
// new name.
function groupCnFor(role) {
  return String(config.value(role.setting) || '').trim();
}

// ---------------------------------------------------------------------------
// The slot. See the header.
// ---------------------------------------------------------------------------

let directory = null;

// What the filler has to provide. Named here rather than checked inline so the
// warning can say which member was missing — "the admin roles cannot be read"
// with no further detail is the kind of message that costs an hour.
const DIRECTORY_MEMBERS = ['groupsOfUser', 'readGroupEntry', 'writeGroupEntry',
                           'groupDnFor', 'normalizeDn', 'existingUserEntry',
                           'usernameOfEntry', 'nameUsableInDn', 'allPersons',
                           'claimedMembersOf', 'usersDn', 'groupsDn'];

function setDirectory(fns) {
  log.debug("Entering setDirectory().");
  const given = fns || {};
  const missing = DIRECTORY_MEMBERS.filter(function (name) {
    return given[name] === undefined || given[name] === null;
  });
  if (missing.length) {
    // Refused rather than half-installed, which is the whole argument for a
    // single slot being safe here: the failure is one loud line at startup
    // instead of a grant button that answers 200 and writes nothing.
    log.error('admin_rbac: the directory slot was offered an object missing ' +
              missing.join(', ') + '. It is NOT installed — the console roles ' +
              'will read as "no directory is loaded", which is the same ' +
              'answer a build without ldap_server.js gives.');
    log.debug("Leaving setDirectory(). Refused: " + missing.length + " member(s) missing.");
    return false;
  }
  directory = given;
  log.debug("Leaving setDirectory(). Installed.");
  log.info('admin_rbac: the admin console roles are the directory groups ' +
           groupCnFor(ROLES[0]) + ' and ' + groupCnFor(ROLES[1]) + ' under ' +
           given.groupsDn + '. An ldapmodify, a SCIM PATCH, /admin/rbac and ' +
           'POST /admin-api/rbac are four doors onto the same membership.');
  return true;
}

function available() {
  return !!directory;
}

// ---------------------------------------------------------------------------
// Reading the roster.
// ---------------------------------------------------------------------------

function dnForRole(role) {
  return directory.groupDnFor(groupCnFor(role));
}

// One role's group as it stands: whether the entry is there at all, and who is
// in it with each membership value resolved to an entry or reported as
// dangling.
//
// A group that does not exist and a group with no members are DIFFERENT states
// here and the same decision — see the header — so both are reported and both
// count as empty. The distinction is kept because the screen says which, and
// "the group is not there" sends a reader somewhere different from "the group
// is there and you took the last person out of it".
function rosterFor(roleId) {
  log.debug("Entering rosterFor(). role=" + roleId);
  const role = roleFor(roleId);
  if (!role) {
    log.debug("Leaving rosterFor(). No such role.");
    return null;
  }
  const cn = groupCnFor(role);
  // Every member of this shape is present on EVERY branch, including the two
  // that return early. A role whose group does not exist used to come back
  // without `claimedCount` at all, so a caller walking both roles hit an
  // undefined on one of them — the sort of asymmetry that is invisible until
  // something iterates.
  const out = { role: role.id, label: role.label, what: role.what,
                implies: role.implies.slice(0), cn: cn, dn: '', exists: false,
                members: [], memberCount: 0, presentCount: 0, danglingCount: 0,
                claimed: [], claimedCount: 0 };
  if (!directory) {
    log.debug("Leaving rosterFor(). No directory is loaded.");
    return out;
  }
  out.dn = dnForRole(role);
  const entry = directory.readGroupEntry(out.dn);
  if (!entry) {
    log.debug("Leaving rosterFor(). " + out.dn + " does not exist.");
    return out;
  }
  out.exists = true;
  out.origin = entry.origin;
  out.modifiedAt = entry.modifiedAt;
  out.members = entry.members.map(function (member) {
    return {
      // `value` is what the attribute literally holds and `dn` is what it
      // RESOLVED to, which are different for memberUid — and a screen showing
      // only one of them cannot explain why removing `alice` also removed
      // `uid=alice,ou=users`.
      value: member.value,
      attribute: member.attribute,
      holds: member.holds,
      dn: member.dn,
      present: member.present,
      kind: member.kind,
      // The name this console knows them by, which is what links a row here to
      // /admin/users. Empty for a dangling member, and the screen says so
      // rather than drawing a link to a page about nobody.
      userKey: member.userKey,
      username: usernameOfMember(member)
    };
  });
  out.memberCount = out.members.length;
  out.presentCount = out.members.filter(function (m) { return m.present; }).length;
  out.danglingCount = out.memberCount - out.presentCount;
  addClaimedMembers(out);
  log.debug("Leaving rosterFor(). " + out.memberCount + " member value(s), " +
            out.claimedCount + " of them claimed from the other side.");
  return out;
}

// ---------------------------------------------------------------------------
// THE OTHER DIRECTION OF MEMBERSHIP, AND THE REASON IT IS NOT OPTIONAL HERE.
//
// A group lists its members; an entry's own `memberOf` claims a group. Nothing
// in this directory keeps the two in step — `memberOf` is not even a standard
// attribute — so a client can write one and produce a disagreement, which is a
// state `/admin/groups` reports rather than repairs.
//
// `groupsOfUser()` HONOURS BOTH DIRECTIONS, which means somebody added that way
// REALLY HOLDS THE ROLE. So a roster built from the group entry alone would have
// shown a console that person could use and a list they were not on — a
// permissions page that under-reports who has access, which is the single worst
// thing this page could do. They are merged in and marked, not hidden and not
// silently promoted: the row says which side of the disagreement it came from.
//
// **The edge worth knowing, because it cost a test to find:** a `memberOf`
// naming a group that DOES NOT EXIST grants nothing. `groupsOfUser()` resolves
// each claimed DN against the group index, and an unresolvable one is skipped —
// so writing `memberOf: cn=admin-read,...` onto an entry before anybody has ever
// been granted Admin Read does nothing at all, and starts working the moment the
// first ordinary grant creates that group. That is the directory's rule rather
// than this module's, and it is the same rule `/admin/groups` applies when it
// decides what counts as a group.
// ---------------------------------------------------------------------------
function addClaimedMembers(out) {
  if (!out.exists) {
    // Nothing claims a group that is not there — see the edge above. The
    // lookup would answer honestly anyway; skipping it says why.
    out.claimed = [];
    out.claimedCount = 0;
    return;
  }
  const claimed = directory.claimedMembersOf(out.dn) || [];
  out.claimed = claimed.map(function (row) {
    return { dn: row.dn, userKey: row.userKey, cn: row.cn, mail: row.mail };
  });
  out.claimedCount = out.claimed.length;
  claimed.forEach(function (row) {
    out.members.push({
      value: row.dn,
      // Named for what it IS rather than dressed as a `member` value: no
      // attribute on the group holds this, and a revoke has to go to the
      // PERSON'S entry instead — which this module does not do, and says so.
      attribute: 'memberOf (on their own entry)',
      holds: 'dn',
      dn: row.dn,
      present: true,
      kind: 'claimed',
      userKey: row.userKey,
      username: usernameOfMember({ holds: 'dn', dn: row.dn, value: row.dn })
    });
  });
  out.memberCount = out.members.length;
  out.presentCount = out.members.filter(function (m) { return m.present; }).length;
  out.danglingCount = out.memberCount - out.presentCount;
}

// What to CALL a membership value on the screen and in a revoke button.
//
// It is the local name wherever there is one, because that is what somebody
// typed into the grant form and what they will type to take it away again. A
// member value that resolves to an entry gives its own username; a DANGLING
// one has no entry to ask, so the RDN value is read off the DN — which is
// exactly the name a grant to somebody who has never authenticated wrote.
function usernameOfMember(member) {
  if (member.holds === 'uid') {
    return member.value;
  }
  const rdn = String(member.dn || '').split(',')[0] || '';
  const eq = rdn.indexOf('=');
  const value = eq > 0 ? rdn.slice(eq + 1) : '';
  // RFC 4514 escaping, undone: `cn=Smith\, John` is one RDN whose value has a
  // comma in it, and a name shown with the backslash still in is a name that
  // will not match when it is typed back.
  return value.replace(/\\([,+"\\<>;=#]|20|22|23|2B|2C|3B|3C|3D|3E|5C)/g,
                       function (whole, what) {
                         if (what.length === 1) {
                           return what;
                         }
                         return String.fromCharCode(parseInt(what, 16));
                       });
}

function roster() {
  log.debug("Entering roster().");
  const out = ROLE_IDS.map(rosterFor);
  log.debug("Leaving roster(). " + out.length + " role(s).");
  return out;
}

// Is the whole roster empty — which is what opens the console to anybody who
// signs in, while `admin.openWhenEmpty` says so.
//
// Note what it counts: MEMBERSHIP VALUES, not resolvable members. A grant to
// somebody who has never authenticated is a value naming an entry that is not
// there yet, and it is still a grant — treating it as empty would mean granting
// a role to a future colleague quietly leaving the door open.
function rosterEmpty() {
  return roster().reduce(function (n, row) { return n + row.memberCount; }, 0) === 0;
}

// ---------------------------------------------------------------------------
// The decision. Everything that guards a request comes through here.
// ---------------------------------------------------------------------------

// Every role a person holds, with `write` expanded to `read` by the table's own
// `implies`.
//
// Membership is asked of `groupsOfUser()` rather than read off the group entry,
// and that is not the same question asked backwards. That function does the
// three-shaped lookup every other reader here uses — a local name, a
// certificate's subject DN, a `did:` — and it reads BOTH directions of
// membership: the group listing the person, and the person's own `memberOf`
// naming the group. So somebody an LDAP client added by writing `memberOf` on
// their entry holds the role, which is what an administrator of a real
// directory would expect and is not what a scan of `member` would have said.
function rolesOf(username) {
  log.debug("Entering rolesOf(). username=" + username);
  const name = String(username == null ? '' : username).trim();
  const held = {};
  const out = { username: name, roles: [], read: false, write: false,
                groups: [], open: false, openable: false,
                available: !!directory, empty: false };
  if (!directory || !name) {
    log.debug("Leaving rolesOf(). " + (directory ? "No name." : "No directory."));
    return out;
  }

  const wanted = {};
  ROLES.forEach(function (role) {
    const cn = groupCnFor(role);
    if (cn) {
      wanted[cn.toLowerCase()] = role;
      wanted[directory.normalizeDn(dnForRole(role))] = role;
    }
  });

  const membership = directory.groupsOfUser(name);
  membership.groups.forEach(function (group) {
    const byCn = wanted[String(group.cn || '').trim().toLowerCase()];
    const byDn = wanted[directory.normalizeDn(group.dn)];
    const role = byCn || byDn;
    if (!role) {
      return;
    }
    out.groups.push({ role: role.id, cn: group.cn, dn: group.dn,
                      via: group.via, viaMemberOf: group.viaMemberOf });
    held[role.id] = true;
    role.implies.forEach(function (implied) { held[implied] = true; });
  });

  out.empty = rosterEmpty();
  // THE EMPTY-ROSTER RULE, and it is applied here rather than at the guard so
  // that the console's own banner, the management API's answer and the refusal
  // itself cannot come to disagree about whether the door is open.
  if (out.empty && !Object.keys(held).length) {
    out.openable = true;
    if (config.value('admin.openWhenEmpty')) {
      out.open = true;
      ROLE_IDS.forEach(function (id) { held[id] = true; });
    }
  }

  out.roles = ROLE_IDS.filter(function (id) { return !!held[id]; });
  out.read = !!held.read;
  out.write = !!held.write;
  log.debug("Leaving rolesOf(). " + name + " holds " +
            (out.roles.join(', ') || 'no role') + (out.open ? " (empty roster)." : "."));
  return out;
}

// ---------------------------------------------------------------------------
// Granting and revoking.
//
// Both go through the SAME two functions the directory offers everything else —
// `readGroupEntry()` and `writeGroupEntry()` — so a grant made here and a grant
// made with an `ldapmodify` leave the identical entry. Nothing about what a
// group IS is decided in this file; see the note at the end of admin.js's slots
// about the console not being a second definition of anything.
// ---------------------------------------------------------------------------

// The attributes of an existing group, ready to be written back: everything it
// holds MINUS the operational ones.
//
// `entryDN` is the one that matters and it is the reason this is a function.
// `readGroupEntry()` SYNTHESISES it — the DN is where the entry is, so holding a
// copy would be a second definition of the same fact — and writing the read
// object straight back would turn that synthesised value into a stored
// attribute, which is the one thing every door onto this directory is told
// never to do.
const NOT_WRITTEN_BACK = ['entrydn', 'createtimestamp', 'modifytimestamp'];

function writableAttributes(entry) {
  const out = {};
  Object.keys(entry.attributes).forEach(function (name) {
    if (NOT_WRITTEN_BACK.indexOf(name.toLowerCase()) >= 0) {
      return;
    }
    out[name] = entry.attributes[name].slice(0);
  });
  return out;
}

// WHERE THE MEMBERSHIP VALUE POINTS.
//
// The person's OWN entry when they have one, whatever it is named — somebody
// whose entry was created by a client certificate is at `cn=<name>,ou=users`
// and not at `uid=<name>,ou=users`, and a grant that wrote the uid form would
// dangle beside the entry it was meant to name. When there is no entry, the
// uid form is what a person created later will be at, so the value resolves the
// moment they authenticate.
function memberValueFor(username) {
  log.debug("Entering memberValueFor(). username=" + username);
  const existing = directory.existingUserEntry(username);
  if (existing) {
    log.debug("Leaving memberValueFor(). Their entry is at " + existing.dn + ".");
    return { dn: existing.dn, present: true };
  }
  const dn = 'uid=' + username + ',' + directory.usersDn;
  log.debug("Leaving memberValueFor(). Nothing there yet; " + dn + " is where they would go.");
  return { dn: dn, present: false };
}

// Is this person already in this group — asked across all three membership
// attributes, because the answer has to be the same one `rolesOf()` gives or a
// grant would appear to work and change nothing.
function memberIndex(entry, username, memberDn) {
  const normalized = directory.normalizeDn(memberDn);
  const wantedName = String(username).trim().toLowerCase();
  const hits = [];
  entry.members.forEach(function (member, index) {
    if (member.holds === 'uid') {
      if (String(member.value).trim().toLowerCase() === wantedName) {
        hits.push(index);
      }
      return;
    }
    if (directory.normalizeDn(member.value) === normalized) {
      hits.push(index);
      return;
    }
    // A value that resolved to the person's entry by some other spelling — the
    // dangling/present distinction again. Compared on the RESOLVED dn so that
    // `uid=alice,ou=users` and the same DN with different spacing are one
    // membership rather than two.
    if (member.present && directory.normalizeDn(member.dn) === normalized) {
      hits.push(index);
    }
  });
  return hits;
}

function nameProblem(username) {
  if (!username) {
    return 'No name was given. Choose somebody from the list, or type the ' +
           'name they will authenticate under.';
  }
  if (!directory.nameUsableInDn(username)) {
    return '"' + username + '" carries a character RFC 4514 reserves in a DN, ' +
           'so it cannot name an entry under ' + directory.usersDn + '. That ' +
           'is the same refusal creating a person gets, and for the same ' +
           'reason: names of that shape get into this directory by being ' +
           'PRESENTED — a certificate subject, a did: — rather than by being ' +
           'typed.';
  }
  return '';
}

function grant(username, roleId, context) {
  log.debug("Entering grant(). username=" + username + ", role=" + roleId);
  const name = String(username == null ? '' : username).trim();
  const role = roleFor(roleId);
  const via = (context || {}).via || 'console';
  const actor = (context || {}).actor || '';

  if (!directory) {
    log.debug("Leaving grant(). No directory is loaded.");
    return { ok: false, errors: [NO_DIRECTORY] };
  }
  if (!role) {
    log.debug("Leaving grant(). No such role.");
    return { ok: false, errors: ['Unknown role "' + roleId + '". There are two: ' +
                                 ROLE_IDS.join(' and ') + '.'] };
  }
  const problem = nameProblem(name);
  if (problem) {
    log.debug("Leaving grant(). " + problem);
    return { ok: false, errors: [problem] };
  }

  const dn = dnForRole(role);
  const cn = groupCnFor(role);
  const existing = directory.readGroupEntry(dn);
  const target = memberValueFor(name);
  const wasEmpty = rosterEmpty();

  if (existing && memberIndex(existing, name, target.dn).length) {
    // Not an error. Granting a role somebody already holds is the state the
    // caller wanted, and a 400 here would make a script that grants on every
    // run fail on its second one.
    log.debug("Leaving grant(). Already a member.");
    return { ok: true, changed: false, role: role.id, username: name, dn: dn,
             member: target.dn,
             message: name + ' already holds ' + role.label + ' — ' + dn +
                      ' lists them. Nothing was changed.' };
  }

  let attributes;
  if (existing) {
    attributes = writableAttributes(existing);
    attributes.member = (attributes.member || []).concat([target.dn]);
  } else {
    // The group is created on the first grant rather than seeded at startup,
    // which is what makes "no members" and "no group" the same state: a service
    // nobody has granted anything on has neither, and the screen says so once.
    attributes = {
      objectClass: ['top', 'groupOfNames'],
      cn: [cn],
      description: ['The ' + role.label + ' role for this service\'s admin ' +
                    'console. It grants nothing anywhere else: no token, ' +
                    'assertion, ticket or credential this service issues is ' +
                    'changed by being in it.'],
      member: [target.dn]
    };
  }

  const written = directory.writeGroupEntry(dn, attributes, 'console');
  if (!written.ok) {
    log.debug("Leaving grant(). The directory refused: " + written.reason);
    return { ok: false, errors: [refusalText(written, dn)], reason: written.reason };
  }

  audit.record({
    action: 'admin.role.change', outcome: 'success', actor: actor,
    target: dn, channel: via === 'api' ? 'http' : 'internal',
    summary: name + ' was granted ' + role.label,
    detail: { role: role.id, username: name, member: target.dn,
              created: written.created, via: via,
              resolves: target.present,
              rosterWasEmpty: wasEmpty }
  });

  log.debug("Leaving grant(). " + name + " now holds " + role.id + ".");
  return { ok: true, changed: true, role: role.id, username: name, dn: dn,
           member: target.dn, created: !!written.created,
           resolves: target.present,
           entry: written.entry,
           message: name + ' now holds ' + role.label + ', as ' + target.dn +
                    ' in ' + dn + '.' +
                    (written.created ? ' The group did not exist and was created.' : '') +
                    (target.present ? ''
                                    : ' NOTHING IS AT THAT DN YET — they have not ' +
                                      'authenticated here and nobody has created ' +
                                      'them, so the membership dangles until one of ' +
                                      'those happens. The role still counts.') +
                    (wasEmpty ? ' This was the FIRST grant, so the roster is now ' +
                                'enforced: whoever is not in one of these two groups ' +
                                'can no longer use this console.' : '') };
}

function revoke(username, roleId, context) {
  log.debug("Entering revoke(). username=" + username + ", role=" + roleId);
  const name = String(username == null ? '' : username).trim();
  const role = roleFor(roleId);
  const via = (context || {}).via || 'console';
  const actor = (context || {}).actor || '';

  if (!directory) {
    log.debug("Leaving revoke(). No directory is loaded.");
    return { ok: false, errors: [NO_DIRECTORY] };
  }
  if (!role) {
    log.debug("Leaving revoke(). No such role.");
    return { ok: false, errors: ['Unknown role "' + roleId + '". There are two: ' +
                                 ROLE_IDS.join(' and ') + '.'] };
  }
  if (!name) {
    log.debug("Leaving revoke(). No name.");
    return { ok: false, errors: ['No name was given.'] };
  }

  const dn = dnForRole(role);
  const existing = directory.readGroupEntry(dn);
  if (!existing) {
    log.debug("Leaving revoke(). The group does not exist.");
    return { ok: true, changed: false, role: role.id, username: name, dn: dn,
             message: 'There is no ' + dn + ', so nobody holds ' + role.label +
                      ' and there was nothing to take away.' };
  }

  const target = memberValueFor(name);
  const hits = memberIndex(existing, name, target.dn);
  if (!hits.length) {
    // A CLAIMED membership is the one case where "not in the group" and "does
    // not hold the role" come apart, and answering the ordinary "nothing was
    // changed" here would be a revoke that reports success and leaves somebody
    // with access. It is REFUSED with where to go instead, because the value is
    // on the PERSON'S entry and this module writes only to groups — writing to
    // a person from here would make the console a second definition of what an
    // entry may hold, which is the thing every slot in this feature avoids.
    const claimed = (directory.claimedMembersOf(dn) || []).filter(function (row) {
      return directory.normalizeDn(row.dn) === directory.normalizeDn(target.dn);
    });
    if (claimed.length) {
      log.debug("Leaving revoke(). Claimed through memberOf; refused.");
      return { ok: false, reason: 'claimed', role: role.id, username: name, dn: dn,
               errors: [name + ' holds ' + role.label + ' through a memberOf value on ' +
                        'THEIR OWN entry (' + target.dn + ') rather than through a member ' +
                        'value on ' + dn + ', so there is nothing in the group to remove. ' +
                        'Nothing here maintains memberOf — a client wrote it — and this ' +
                        'console writes only to groups, deliberately. Delete that value with ' +
                        'an ldapmodify or a SCIM PATCH of the person and the role goes with ' +
                        'it.'] };
    }
    log.debug("Leaving revoke(). Not a member.");
    return { ok: true, changed: false, role: role.id, username: name, dn: dn,
             message: name + ' does not hold ' + role.label + '. Nothing was changed.' };
  }

  // Removed from EVERY membership attribute that named them rather than from
  // the first one found. A person listed as both `member` and `memberUid` — two
  // clients, two conventions, one directory — would otherwise still hold the
  // role after a revoke that reported success, which is the worst shape a
  // permissions bug takes.
  const removed = hits.map(function (index) { return existing.members[index]; });
  const attributes = writableAttributes(existing);
  removed.forEach(function (member) {
    const key = Object.keys(attributes).filter(function (name2) {
      return name2.toLowerCase() === member.attribute.toLowerCase();
    })[0];
    if (!key) {
      return;
    }
    attributes[key] = attributes[key].filter(function (value) {
      return String(value) !== String(member.value);
    });
    if (!attributes[key].length) {
      delete attributes[key];
    }
  });

  const written = directory.writeGroupEntry(dn, attributes, 'console');
  if (!written.ok) {
    log.debug("Leaving revoke(). The directory refused: " + written.reason);
    return { ok: false, errors: [refusalText(written, dn)], reason: written.reason };
  }

  const nowEmpty = rosterEmpty();
  audit.record({
    action: 'admin.role.change', outcome: 'success', actor: actor,
    target: dn, channel: via === 'api' ? 'http' : 'internal',
    summary: name + ' was stripped of ' + role.label,
    detail: { role: role.id, username: name, via: via,
              values: removed.map(function (m) {
                return m.attribute + ': ' + m.value;
              }).join(', '),
              rosterNowEmpty: nowEmpty }
  });

  log.debug("Leaving revoke(). " + name + " no longer holds " + role.id + ".");
  return { ok: true, changed: true, role: role.id, username: name, dn: dn,
           removed: removed.length,
           message: name + ' no longer holds ' + role.label + ' — ' +
                    removed.length + ' membership value(s) removed from ' + dn + '.' +
                    (nowEmpty
                      ? ' THAT WAS THE LAST GRANT ON THIS SERVICE. The roster is ' +
                        'empty again, so ' +
                        (config.value('admin.openWhenEmpty')
                          ? 'this console is open to anybody who signs in until ' +
                            'somebody is granted a role.'
                          : 'nobody can use this console at all — ' +
                            'admin.openWhenEmpty is off. POST /admin-api/rbac/grant ' +
                            'is the way back in.')
                      : '') };
}

const NO_DIRECTORY =
  'No LDAP directory is loaded in this process, so there is nowhere to hold ' +
  'the roles. That is a build of this service without ldap_server.js and not a ' +
  'failure — but it means nobody can be granted anything, so admin.authRequired ' +
  'would leave this console reachable only while admin.openWhenEmpty is on.';

function refusalText(written, dn) {
  if (written.reason === 'notAGroup') {
    return 'There is already an entry at ' + dn + ' and it is not a group. ' +
           'Something wrote it — an ldapadd, a SCIM POST — and this console ' +
           'will not overwrite an entry it did not make. Delete it, or point ' +
           'the role at another cn on /admin/config.';
  }
  if (written.reason === 'noParent') {
    return 'There is no ' + written.parent + ' to put ' + dn + ' under. The ' +
           'groups container is created at startup, so something deleted it.';
  }
  if (written.reason === 'full') {
    return 'The directory holds its maximum number of entries (ldap.maxEntries), ' +
           'so the role group could not be created.';
  }
  return 'The directory refused to write ' + dn + ' (' + written.reason + ').';
}

// ---------------------------------------------------------------------------
// WHO CAN BE CHOSEN, for the screen's select.
//
// Two sources, unioned, and the difference between them is the difference this
// console keeps straight everywhere: the DIRECTORY holds whoever somebody wrote
// an entry for, and the console's user list holds whoever has actually
// presented a credential. A person can be in either and not the other, and a
// select built from one of them alone would silently refuse to offer half the
// people somebody wants to grant a role to.
//
// It is not a whitelist. A name that is in neither list can still be granted a
// role by typing it, because the interesting case for a mock — grant the role
// BEFORE the person first signs in, then watch them arrive with it — is exactly
// the one that is in neither.
// ---------------------------------------------------------------------------
function candidates(seen) {
  log.debug("Entering candidates().");
  const out = new Map();
  const add = function (name, source) {
    const value = String(name == null ? '' : name).trim();
    if (!value) {
      return;
    }
    const key = value.toLowerCase();
    if (!out.has(key)) {
      out.set(key, { username: value, inDirectory: false, seen: false });
    }
    out.get(key)[source] = true;
  };

  if (directory) {
    directory.allPersons().forEach(function (person) {
      // The RDN value, which is what `existingUserEntry()` matches a typed name
      // against — so what the select offers is what a grant will find.
      const rdn = String(person.dn).split(',')[0];
      const eq = rdn.indexOf('=');
      add(eq > 0 ? rdn.slice(eq + 1) : '', 'inDirectory');
    });
  }
  (seen || []).forEach(function (key) { add(key, 'seen'); });

  const rows = Array.from(out.values()).filter(function (row) {
    // A name that cannot be spelt in a DN cannot be granted a role, so offering
    // it in the select would be offering a control that answers with a refusal.
    // They are still listed on /admin/users; this is a grant form.
    return !directory || directory.nameUsableInDn(row.username);
  });
  rows.sort(function (a, b) {
    return a.username.toLowerCase() < b.username.toLowerCase() ? -1 : 1;
  });
  log.debug("Leaving candidates(). " + rows.length + " candidate(s).");
  return rows;
}

// ---------------------------------------------------------------------------
// The whole feature as one object, for the screen, for ?format=json and for
// GET /admin-api/rbac. One builder so that the three cannot disagree — the same
// rule /admin/scim follows about describing SCIM in the module that implements
// it.
// ---------------------------------------------------------------------------
function describe() {
  log.debug("Entering describe().");
  const rows = roster();
  const out = {
    enforced: !!config.value('admin.authRequired'),
    openWhenEmpty: !!config.value('admin.openWhenEmpty'),
    available: !!directory,
    groupsDn: directory ? directory.groupsDn : '',
    usersDn: directory ? directory.usersDn : '',
    roles: rows,
    grantCount: rows.reduce(function (n, row) { return n + row.memberCount; }, 0)
  };
  out.empty = out.grantCount === 0;
  // Said as one flag rather than left to the caller to compute from three,
  // because it is the sentence every surface has to render and three of them
  // computing it separately is three chances to say the door is shut while it
  // is open.
  out.openToAnyone = out.enforced && out.empty && out.openWhenEmpty;
  out.closedToEveryone = out.enforced && out.empty && !out.openWhenEmpty;
  log.debug("Leaving describe(). " + out.grantCount + " grant(s).");
  return out;
}

module.exports = {
  ROLES: ROLES,
  ROLE_IDS: ROLE_IDS,
  roleFor: roleFor,
  setDirectory: setDirectory,
  available: available,
  roster: roster,
  rosterFor: rosterFor,
  rosterEmpty: rosterEmpty,
  rolesOf: rolesOf,
  grant: grant,
  revoke: revoke,
  candidates: candidates,
  describe: describe
};
