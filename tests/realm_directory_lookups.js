'use strict';
//
// File: realm_directory_lookups.js
//
// ===========================================================================
// A LOOKUP BY DN ANSWERS ABOUT ONE REALM, AND UNTIL 2026-08-25 THE GROUP ONES
// ANSWERED ABOUT THE WHOLE TREE.
//
// When the embedded directory became a subtree per realm, the ENUMERATORS were
// scoped — `eachEntryInRealm()` and its two dozen callers — and every lookup
// that starts from a DN somebody handed in was left calling `getEntry()`, which
// reads the one Map that holds every realm's subtree. The list on a page was
// therefore right while the thing the page linked to was not:
//
//   * `/realm/acme/admin/groups?group=cn=x,ou=groups,dc=example,dc=com`
//     rendered the DEFAULT realm's group in full — members, attributes,
//     everything — beside a `groupsDn` that said acme's.
//   * `GET /realm/acme/scim/v2/Groups/{that same DN}` answered 200.
//   * `DELETE` on it answered **204, and the group was gone from the default
//     realm.** A cross-realm destructive write, verified before the fix.
//
// The person half never had it: `readPerson()` guards with `isPersonEntry()`,
// which tests placement under the AMBIENT realm's `usersDn()`, so an entry in
// another realm's subtree fails it. The group half guards with
// `groupRuleFor()`, which answers "this is a group" WHEREVER IT SITS — on
// purpose, because a group here can be one by objectClass alone — so the realm
// question had to be asked separately and was not. That asymmetry is the whole
// bug, and it is why this file asserts the person and application halves too:
// they are correct today, and nothing was stopping them from drifting.
//
// THE FIX WENT THROUGH TWO STAGES AND THIS FILE OUTLIVED THE FIRST. Each
// lookup was guarded by hand (`inRealm()`, `realmEntry()`); then the STORE was
// split — `const entries = realms.map()` — and the guards became unnecessary,
// because `getEntry()` reads the ambient realm's Map and another realm's entry
// is not in it. Both functions are gone. What this file asserts is the
// BEHAVIOUR both stages aimed at, which is why it survived the second one
// unchanged: it never named the mechanism.
//
// THE SOCKET HALF IS NOT ASSERTED HERE AND THAT IS THE ONE GAP WORTH KNOWING.
// On 389 the realm comes from the DN in the request and every handler is
// wrapped in `realms.run()` at registration. Testing that needs the listener,
// and tests/CLAUDE.md says a test that needs one belongs in the parent
// project's suite — so it was verified by hand with an ldapjs client and
// `ldap/CLAUDE.md` records what was checked.
//
// WHY IN PROCESS. Two of the four assertions below cannot be made over HTTP
// without leaving the damage behind — "the cross-realm DELETE was refused AND
// the group is still there" needs the store read back afterwards — and the
// rest is a module contract about `ldap_server.js`'s own accessors rather than
// about any endpoint. tests/CLAUDE.md carries the rule and the exception.
// ===========================================================================

// Deleted rather than set, for the reason config_realm_layer.js gives.
delete process.env.CONFIG_FILE;

const realms = require('../common/realms');
const dir = require('../ldap/ldap_server');
const applications = require('../common/applications');

// The attributes a group needs to be one by BOTH of groupRuleFor()'s rules —
// placement under ou=groups and an objectClass — so that a failure here can
// never be "it was not a group anyway".
function groupAttributes(cn) {
  return {
    objectclass: ['top', 'groupOfNames'],
    cn: [cn],
    description: ['Created by ' + __filename]
  };
}

// Create a realm, hand it to `fn`, and remove it however that goes. Same shape
// as the other two files here: the realm table is process-wide, and a realm
// left behind changes what a later test resolves.
function withRealm(t, id, fn) {
  const made = realms.create({ id: id, name: id,
                               description: 'Created by ' + __filename });
  if (!made.ok) {
    t.bad('could not create the realm "' + id + '"',
          (made.errors || []).join(' '));
    return undefined;
  }
  try {
    return fn(made.realm);
  } finally {
    realms.remove(id);
  }
}

// ---------------------------------------------------------------------------
// 1. READING A GROUP BY DN.
//
// Both directions, because they fail for different reasons and a fix that
// caught one and not the other would look complete. A non-default realm's base
// is a SIBLING of every other realm's, so "under my base" refuses the default
// realm's DN on its own; the DEFAULT realm's base CONTAINS every realm's
// subtree, so only the carve-out in `containedRealmBases()` refuses theirs.
// ---------------------------------------------------------------------------
function checkGroupReads(t) {
  t.log.info('reading a group by DN');

  withRealm(t, 'rdl-read', function (realm) {
    const inRealmDn = realms.run(realm, function () {
      const dn = dir.groupDnFor('rdl-inside');
      dir.writeGroupEntry(dn, groupAttributes('rdl-inside'), 'test');
      return dn;
    });
    const outsideDn = dir.groupDnFor('rdl-outside');
    dir.writeGroupEntry(outsideDn, groupAttributes('rdl-outside'), 'test');

    t.check(inRealmDn.indexOf('dc=rdl-read') > 0,
            'the realm\'s group went into the realm\'s subtree', inRealmDn);

    t.check(!!realms.run(realm, function () { return dir.readGroupEntry(inRealmDn); }),
            'the realm reads its own group', inRealmDn);
    t.check(dir.readGroupEntry(inRealmDn) === null,
            'the DEFAULT realm does not read the realm\'s group — the carve-out',
            inRealmDn);
    t.check(!!dir.readGroupEntry(outsideDn),
            'the default realm reads its own group', outsideDn);
    t.check(realms.run(realm, function () { return dir.readGroupEntry(outsideDn); }) === null,
            'and the realm does not read the default realm\'s',
            outsideDn);

    // The console's reader, which is a different function reaching the same
    // store and was separately wrong. `found` is what the page renders on.
    const seenFromRealm = realms.run(realm, function () {
      return dir.groupsFor(outsideDn);
    });
    t.equal(seenFromRealm.found, false,
            'groupsFor() in the realm reports the default realm\'s group as not found');
    t.equal(realms.run(realm, function () {
              return dir.groupsFor(inRealmDn).found;
            }), true,
            'and reports its own as found');

    // The list beside it, which was right all along — asserted so that a
    // "simplification" cannot make the pair agree by breaking both.
    const listedInRealm = realms.run(realm, function () {
      return dir.allGroupEntries().map(function (g) { return g.dn; });
    });
    t.check(listedInRealm.indexOf(outsideDn) < 0,
            'the realm\'s group LIST still excludes the default realm\'s groups',
            String(listedInRealm.length) + ' group(s)');

    realms.run(realm, function () { dir.deleteGroupEntry(inRealmDn); });
    dir.deleteGroupEntry(outsideDn);
  });
}

// ---------------------------------------------------------------------------
// 2. WRITING AND DELETING ONE.
//
// The assertion that matters is not the refusal — it is that the group is
// STILL THERE afterwards. A delete that answered "not found" and removed the
// entry anyway would pass a refusal-only test.
// ---------------------------------------------------------------------------
function checkGroupWrites(t) {
  t.log.info('writing and deleting a group by DN');

  withRealm(t, 'rdl-write', function (realm) {
    const dn = dir.groupDnFor('rdl-target');
    dir.writeGroupEntry(dn, groupAttributes('rdl-target'), 'test');

    const deleted = realms.run(realm, function () {
      return dir.deleteGroupEntry(dn);
    });
    t.equal(deleted.ok, false,
            'a realm cannot DELETE a group in the default realm');
    t.check(!!dir.readGroupEntry(dn),
            'and the group is still there afterwards — the assertion a refusal ' +
            'alone would not make', dn);

    const written = realms.run(realm, function () {
      return dir.writeGroupEntry(dn, groupAttributes('rdl-hijacked'), 'test');
    });
    t.equal(written.ok, false,
            'a realm cannot WRITE onto a group in the default realm');
    // Read defensively: when this guard is broken the group above is already
    // GONE, and reading `.attributes` off the null would throw — which run.js
    // reports as "the test could not run" and skips everything after it. A
    // broken guard has to read as a FAILURE, so the null is turned into one.
    const after = dir.readGroupEntry(dn);
    t.equal(after ? (after.attributes.cn || [])[0] : null, 'rdl-target',
            'and the group still carries its own cn');

    // The same three operations inside the realm that owns the group, so that
    // "refuses everything" cannot pass this file.
    const ownDn = realms.run(realm, function () {
      const own = dir.groupDnFor('rdl-own');
      dir.writeGroupEntry(own, groupAttributes('rdl-own'), 'test');
      return own;
    });
    t.check(!!realms.run(realm, function () { return dir.readGroupEntry(ownDn); }),
            'a realm still creates and reads a group of its own', ownDn);
    t.equal(realms.run(realm, function () { return dir.deleteGroupEntry(ownDn).ok; }),
            true, 'and still deletes it');

    dir.deleteGroupEntry(dn);
  });
}

// ---------------------------------------------------------------------------
// 3. THE PERSON AND APPLICATION HALVES, WHICH WERE ALREADY RIGHT.
//
// Here because they were right for two DIFFERENT reasons, neither of them the
// group half's: `readPerson()` tests placement under the ambient realm's
// `usersDn()`, and `applicationEntry()` builds the DN it looks up from
// `applicationsDn()`. Both are correct and both are incidental — a refactor
// that routed either through a bare `getEntry()` would reopen exactly the hole
// this file exists for, and nothing else in the repository would notice.
// ---------------------------------------------------------------------------
function checkPeopleAndApplications(t) {
  t.log.info('the person and application halves');

  withRealm(t, 'rdl-other', function (realm) {
    const person = dir.writePerson('uid=rdl-person,' + dir.usersDn(),
                                   { objectclass: ['top', 'inetOrgPerson'],
                                     uid: ['rdl-person'], cn: ['rdl-person'],
                                     sn: ['person'] }, 'test');
    const personDn = (person && person.dn) || ('uid=rdl-person,' + dir.usersDn());
    t.check(!!dir.readPerson(personDn),
            'the default realm reads its own person', personDn);
    t.check(realms.run(realm, function () { return dir.readPerson(personDn); }) === null,
            'and a realm does not read it', personDn);
    t.equal(realms.run(realm, function () { return dir.deletePerson(personDn).ok; }),
            false, 'nor delete it');
    t.check(!!dir.readPerson(personDn), 'so it is still there', personDn);
    dir.deletePerson(personDn);

    const made = applications.createApplication({ identifier: 'rdl-app',
                                                  name: 'rdl-app',
                                                  kind: 'oauth2-client' });
    t.equal(made.ok, true, 'an application was created in the default realm');
    t.check(!!applications.get('rdl-app'),
            'the default realm knows it', 'rdl-app');
    t.check(realms.run(realm, function () { return applications.get('rdl-app'); }) === null,
            'and a realm does not', 'rdl-app');
    t.equal(realms.run(realm, function () {
              return applications.deleteApplication('rdl-app').ok;
            }), false, 'nor can a realm delete it');
    t.check(!!applications.get('rdl-app'), 'so it is still registered', 'rdl-app');
    applications.deleteApplication('rdl-app');
  });
}

// ---------------------------------------------------------------------------
// 4. WITH NO REALM DEFINED, EVERY ONE OF THOSE LOOKUPS IS WHAT IT ALWAYS WAS.
//
// The property the whole realm design rests on, asserted for the accessors this
// file is about: with nothing defined, `containedRealmBases()` is empty and
// `inRealm()` is "under the naming context", which every entry is.
// ---------------------------------------------------------------------------
function checkDefaultUnchanged(t) {
  t.log.info('a service with no realms defined');

  t.equal(realms.count(), 1,
          'this test cleaned up after itself — only the default realm is left');

  const dn = dir.groupDnFor('rdl-plain');
  const written = dir.writeGroupEntry(dn, groupAttributes('rdl-plain'), 'test');
  t.equal(written.ok, true, 'a group is created in the default realm');
  t.check(!!dir.readGroupEntry(dn), 'read back by DN', dn);
  t.equal(dir.groupsFor(dn).found, true, 'and found by the console\'s reader');
  t.equal(dir.deleteGroupEntry(dn).ok, true, 'and deleted');
  t.check(dir.readGroupEntry(dn) === null, 'and gone afterwards', dn);
}

function run(t) {
  checkGroupReads(t);
  checkGroupWrites(t);
  checkPeopleAndApplications(t);
  checkDefaultUnchanged(t);
}

module.exports = {
  name: 'realm_directory_lookups',
  describe: 'a lookup by DN answers about one realm — groups, people and applications',
  run: run
};
