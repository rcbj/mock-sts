'use strict';
//
// File: roles.js
//
// ===========================================================================
// THE ROLE REGISTER AND THE ISSUANCE GATE, IN PROCESS.
//
// The line CLAUDE.md draws is "can it be asserted by driving the running
// service over HTTP?" Most of this feature CAN be — making a role, narrowing
// an application, watching `/oauth2/token` answer `access_denied` — and all of
// that is in `tests/vendored/sts_roles.js`, which drives an authoring door and
// a deciding door in one job because that is the only way either half means
// anything.
//
// WHAT IS HERE IS THE FIVE THINGS THAT CANNOT BE, and each is a property of
// the MODULES rather than of a running service:
//
//   1. **THE GATE WITH NO DECIDER ANSWERS "ALLOWED".** That is the single most
//      load-bearing sentence in `common/issuance_gate.js` — it is what makes a
//      process that never loaded the XACML family a SMALLER service rather
//      than a broken one, and it is what `npm test` and the parent project's
//      in-process Kerberos jobs run as. A running service that has the engine
//      cannot be asked it, and one that does not has no console to ask
//      through.
//   2. **A DECIDER THAT THROWS FAILS OPEN.** A throw is a defect and not a
//      decision, and the alternative — a mock whose every protocol family
//      stopped issuing because a policy module threw — would be unusable and,
//      worse, unfixable, since the console that would let somebody correct the
//      policy is reached through a session this service would then refuse to
//      mint. There is no way to make the engine throw over HTTP on purpose.
//   3. **`rolesInClaims()` READS THREE SHAPES.** A token this service issues
//      always carries an array, so the single string and the space-separated
//      string — which is what a `scope`-shaped claim looks like and what
//      several real products emit — are unreachable from any request this
//      service can be sent.
//   4. **THE REGISTER NEVER THROWS.** A directory that throws under
//      `rolesOf()` must leave the built-in roles answering, because an
//      issuance that FAILED because the role register threw would be worse
//      than a token missing a role. Reaching that means installing a slot that
//      throws.
//   5. **THE THREE CONTEXTS OF THE SIX BUILT-IN ROLES.** Four of the six are
//      about a party that has not authenticated or is an application, and the
//      combinations a live request can produce are a subset — nothing over
//      HTTP can ask this service what an unauthenticated application holds.
//
// **IT RESTORES BOTH SLOTS IT TOUCHES**, which `tests/CLAUDE.md` makes
// non-optional: `run.js` requires every file in this directory into ONE
// process, so a directory left installed here is what `xacml_service.js` gets
// when it runs next.
// ===========================================================================

const roles = require('../common/roles');
const gate = require('../common/issuance_gate');

// A directory in the shape `roles.setDirectory()` is offered one, built from a
// plain table so a test can say what is in the register without an LDAP server.
function directoryOf(table, groupsByUser) {
  return {
    allRoles: function () {
      return Object.keys(table).map(function (name) {
        return { name: name, dn: 'cn=' + name + ',ou=roles',
                 attributes: table[name] };
      });
    },
    groupsOfUser: function (name) {
      return (groupsByUser || {})[name] || [];
    }
  };
}

function run(t) {
  // WHAT WAS INSTALLED, not `null`. `xacml_store.js` argues why that
  // distinction is not pedantry and it is the same one-process, one-reference
  // situation here: another file in this run may have filled these.
  const beforeDirectory = roles.directoryInstalled();
  const beforeDecider = gate.deciderInstalled();

  builtInRoles(t);
  theRegister(t);
  theClaim(t);
  claimsComingIn(t);
  theGate(t);

  roles.setDirectory(beforeDirectory);
  gate.setDecider(beforeDecider);
}

// ---------------------------------------------------------------------------
// 1. THE SIX BUILT-IN ROLES, over every context that can produce one.
// ---------------------------------------------------------------------------
function builtInRoles(t) {
  t.log.info('=== The six built-in roles ===');
  roles.setDirectory(null);

  function held(who) {
    return roles.rolesOf(who).join(',');
  }

  t.equal(held({ kind: 'user', name: 'alice', authenticated: true }),
          'EVERYBODY,ALL_AUTHENTICATED_USERS',
          'a signed-in person holds EVERYBODY and ALL_AUTHENTICATED_USERS');
  t.equal(held({ kind: 'user', name: 'alice', authenticated: false }),
          'EVERYBODY,ALL_UNAUTHENTICATED_USERS',
          'and one who has not authenticated holds the other half of the pair');
  t.equal(held({ kind: 'application', name: 'webapp1', authenticated: true }),
          'EVERYBODY,ALL_APPLICATIONS,ALL_AUTHENTICATED_APPLICATIONS',
          'a client that proved who it is holds three');
  t.equal(held({ kind: 'application', name: 'webapp1', authenticated: false }),
          'EVERYBODY,ALL_APPLICATIONS,ALL_UNAUTHENTICATED_APPLICATIONS',
          'and a public client that proved nothing holds the other three — ' +
          'which is the combination no request to this service can produce ' +
          'on demand');

  // THE PAIRS ARE COMPLEMENTARY AND THAT IS THE POINT. XACML targets cannot
  // say "not", so "everyone who did not sign in" has to be a NAME a target can
  // match rather than a negation of the name beside it.
  t.check(held({ kind: 'user', name: 'a', authenticated: true })
            .indexOf('ALL_UNAUTHENTICATED_USERS') < 0 &&
          held({ kind: 'user', name: 'a', authenticated: false })
            .indexOf('ALL_AUTHENTICATED_USERS') < 0,
          'no context holds both halves of a pair',
          'which is what makes each of them usable in a target on its own');

  // ANONYMOUS IS A REAL ANSWER AND NOT AN ERROR. It is the whole reason
  // ALL_UNAUTHENTICATED_USERS exists.
  t.equal(held({ kind: 'user', name: '', authenticated: false }),
          'EVERYBODY,ALL_UNAUTHENTICATED_USERS',
          'a party with no name at all still holds the two that are true of ' +
          'them');

  t.equal(roles.DEFAULT_REQUIRED_ROLE, 'EVERYBODY',
          'EVERYBODY is the default requirement, which is what makes the ' +
          'whole feature off by default without being absent');
  t.check(roles.BUILT_IN_NAMES.every(function (name) {
            return roles.isBuiltIn(name);
          }) && !roles.isBuiltIn('staff'),
          'isBuiltIn() answers for exactly the six',
          roles.BUILT_IN_NAMES.join(', '));
}

// ---------------------------------------------------------------------------
// 2. THE REGISTER: three kinds of member, and a lookup that cannot throw.
// ---------------------------------------------------------------------------
function theRegister(t) {
  t.log.info('=== The register ===');
  roles.setDirectory(directoryOf({
    staff: { roleName: ['staff'], roleMemberUser: ['alice'],
             roleMemberGroup: ['developers'], description: ['Works here'] },
    robots: { roleName: ['robots'], roleMemberApplication: ['batch1'] }
  }, { bob: ['developers'], alice: [] }));

  function held(who) {
    return roles.rolesOf(who).filter(function (name) {
      return !roles.isBuiltIn(name);
    }).join(',');
  }

  t.equal(held({ kind: 'user', name: 'alice', authenticated: true }), 'staff',
          'a person named directly on the role entry holds it');
  t.equal(held({ kind: 'user', name: 'bob', authenticated: true }), 'staff',
          'and so does somebody who is only in a GROUP the role names — ' +
          'resolved here rather than expanded on write, so an ldapmodify ' +
          'adding somebody to that group changes the very next token');
  t.equal(held({ kind: 'user', name: 'carol', authenticated: true }), '',
          'and somebody in neither holds nothing');

  // AN APPLICATION IS A FIRST-CLASS MEMBER, which is the unusual half of this
  // register and the reason a client_credentials grant has anything to decide
  // on at all.
  t.equal(held({ kind: 'application', name: 'batch1', authenticated: true }),
          'robots',
          'an application holds a role AS ITSELF');
  t.equal(held({ kind: 'user', name: 'batch1', authenticated: true }), '',
          'and the SAME name as a person holds nothing — the three ' +
          'membership lists are three relations and not one list with a ' +
          'label on it');
  t.equal(held({ kind: 'application', name: 'alice', authenticated: true }), '',
          'read the other way round too');

  // CASE-INSENSITIVELY, for the reason the register gives: a username here
  // arrives from a login form, a SAML subject, a Kerberos principal and a
  // client_id, and this service has always treated those as one identity
  // however they were typed.
  t.equal(held({ kind: 'user', name: 'ALICE', authenticated: true }), 'staff',
          'a member matches however it was typed');

  // THE GROUPS MAY BE PASSED IN, which is what the issuance gate does where it
  // already read them — and they WIN over the directory, because the caller is
  // deciding about a session it holds.
  t.equal(held({ kind: 'user', name: 'carol', authenticated: true,
                 groups: ['developers'] }), 'staff',
          'groups handed in are used in place of a directory lookup');
  t.equal(held({ kind: 'user', name: 'bob', authenticated: true,
                 groups: [] }), '',
          'and an EMPTY list handed in is an answer rather than a request to ' +
          'go and look — which is the difference between "this session is in ' +
          'no group" and "I did not ask"');

  // IT NEVER THROWS. A register consulted during an issuance must not be able
  // to fail that issuance.
  roles.setDirectory({
    allRoles: function () { throw new Error('the directory is on fire'); }
  });
  t.equal(roles.rolesOf({ kind: 'user', name: 'alice', authenticated: true })
            .join(','), 'EVERYBODY,ALL_AUTHENTICATED_USERS',
          'a register that THROWS still answers the built-in roles',
          'which still contains EVERYBODY, so an unedited application still ' +
          'admits everybody it admitted before');

  roles.setDirectory(null);
  t.equal(roles.all().length, 0,
          'with no directory at all the register is empty rather than an ' +
          'error');
  t.equal(roles.write('staff', {}).ok, false,
          'and a write is refused rather than kept in memory — a role ' +
          'register that quietly lived in a Map would decide things nobody ' +
          'could find');
}

// ---------------------------------------------------------------------------
// 3. THE CLAIM. What is in it, and — more importantly — what is not.
// ---------------------------------------------------------------------------
function theClaim(t) {
  t.log.info('=== The roles claim ===');
  roles.setDirectory(directoryOf({
    staff: { roleName: ['staff'], roleMemberUser: ['alice'] },
    oncall: { roleName: ['oncall'], roleMemberUser: ['alice'] }
  }, {}));

  const claim = roles.claimFor({ kind: 'user', name: 'alice',
                                 authenticated: true });
  t.equal(JSON.stringify(claim), '{"roles":["oncall","staff"]}',
          'the claim carries the CONFIGURED roles, sorted');

  // THE BUILT-IN ONES ARE NEVER IN IT, and this is the assertion worth having:
  // EVERYBODY and ALL_AUTHENTICATED_USERS are true of almost every token this
  // service issues, so carrying them would add two meaningless members to
  // every token every existing client parses.
  t.check(JSON.stringify(claim).indexOf('EVERYBODY') < 0,
          'and never a built-in one', JSON.stringify(claim));

  t.equal(roles.claimFor({ kind: 'user', name: 'nobody',
                           authenticated: true }), null,
          'somebody with no configured role gets NO CLAIM AT ALL rather than ' +
          'an empty array — an empty array is a claim, and a client reading ' +
          'one would be told something false about a service that has no ' +
          'roles configured');
}

// ---------------------------------------------------------------------------
// 4. READING A CLAIM BACK OFF A TOKEN SOMEBODY PRESENTED.
// ---------------------------------------------------------------------------
function claimsComingIn(t) {
  t.log.info('=== Roles in a presented token ===');

  t.equal(roles.rolesInClaims({ roles: ['staff', 'oncall'] }).join(','),
          'staff,oncall', 'an array is read');
  t.equal(roles.rolesInClaims({ roles: 'staff' }).join(','), 'staff',
          'a single string is read — reading only the array would find ' +
          'nothing here, and finding nothing looks exactly like holding no ' +
          'roles');
  t.equal(roles.rolesInClaims({ roles: 'staff oncall' }).join(','),
          'staff,oncall',
          'and a space-separated string, which is what a scope-shaped claim ' +
          'looks like and what several real identity providers emit');
  t.equal(roles.rolesInClaims({ roles: 'staff, oncall' }).join(','),
          'staff,oncall', 'commas too');
  t.equal(roles.rolesInClaims({}).length, 0,
          'a token with no such claim carries no roles');
  t.equal(roles.rolesInClaims(null).length, 0, 'and neither does no token');
}

// ---------------------------------------------------------------------------
// 5. THE GATE. Absent-safe, off-safe, and open on a defect.
// ---------------------------------------------------------------------------
function theGate(t) {
  t.log.info('=== The issuance gate ===');
  const asked = { application: 'webapp1', kind: gate.ISSUANCE.ACCESS_TOKEN,
                  subject: { kind: 'user', name: 'alice',
                             authenticated: true } };

  gate.setDecider(null);
  const ungated = gate.check(asked);
  t.equal(ungated.allowed, true,
          'WITH NO DECIDER INSTALLED, EVERY ISSUANCE IS ALLOWED — which is ' +
          'what makes a process that never loaded the XACML family a ' +
          'smaller service rather than a broken one');
  t.check(/not loaded/.test(ungated.why),
          'and the sentence says why rather than reading as a decision',
          ungated.why);
  t.equal(ungated.decision, 'NotApplicable',
          'the decision is NotApplicable rather than Permit, because nothing ' +
          'decided anything');

  // NO APPLICATION IS NOT A DECISION EITHER. This service issues nothing to
  // nobody, so a call naming no application is a caller that does not know who
  // it is serving — WS-Trust's optional AppliesTo is the real case.
  let decided = 0;
  gate.setDecider(function () {
    decided += 1;
    return { allowed: false, decision: 'Deny', why: 'no', roles: [],
             required: [] };
  });
  t.equal(gate.check({ application: '', kind: gate.ISSUANCE.WSTRUST_TOKEN,
                       subject: { kind: 'user', name: 'a' } }).allowed, true,
          'a call naming no application is allowed without the decider being ' +
          'asked');
  t.equal(decided, 0, 'and the PDP was not consulted at all');

  t.equal(gate.check(asked).allowed, false,
          'an installed decider decides');
  t.equal(decided, 1, 'and it was asked exactly once');

  // A THROW IS A DEFECT AND NOT A DECISION, and it is the one place this file
  // fails open. See the header.
  gate.setDecider(function () { throw new Error('the engine is on fire'); });
  const threw = gate.check(asked);
  t.equal(threw.allowed, true,
          'a decider that THROWS allows the issuance',
          'a mock whose every protocol family stopped issuing because a ' +
          'policy module threw would be unusable and unfixable — the console ' +
          'that would let somebody correct the policy is reached through a ' +
          'session this service would then refuse to mint');
  t.check(/defect rather than a decision/.test(threw.why),
          'and says it was a defect, so nobody reads it as a policy having ' +
          'permitted something', threw.why);

  // THE NINE KINDS ARE A VOCABULARY POLICIES ARE WRITTEN AGAINST, so renaming
  // one silently stops every policy that named the old word from matching —
  // which is a policy that permits nothing rather than an error.
  t.equal(gate.KINDS.length, 9, 'there are nine kinds of issuance');
  t.equal(gate.KINDS.join(','),
          'start-session,issue-access-token,issue-id-token,' +
          'issue-refresh-token,issue-authorization-code,issue-saml-assertion,' +
          'issue-wsfed-token,issue-wstrust-token,issue-kerberos-ticket',
          'and these are their spellings, which are XACML action-ids and ' +
          'therefore part of the contract with every policy anybody writes');
}

module.exports = {
  name: 'roles',
  describe: 'the register never throws, and the gate with no decider issues',
  run: run
};
