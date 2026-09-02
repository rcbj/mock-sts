'use strict';
//
// File: consent.js
//
// ===========================================================================
// AN OVERRIDE IS NOT A RECORD, AND THE ONE THING THAT MUST NEVER HAPPEN IS FOR
// A PERSON TO BE ASKED ABOUT SOMETHING THEY HAVE ALREADY AGREED TO — OR NOT
// ASKED ABOUT SOMETHING THEY HAVE NOT.
//
// `common/consent.js` decides both, out of two attributes that live in
// different containers and mean different things: `oauthConsent` on a PERSON is
// what they answered, and `oauthGlobalConsent` on an APPLICATION is an operator
// saying nobody should be asked. Every assertion below is about the boundary
// between them.
//
// ---------------------------------------------------------------------------
// WHY IN PROCESS, WHICH IS THE QUESTION tests/CLAUDE.md ASKS FIRST.
//
// Most of this feature belongs over HTTP and is not here. That the screen is
// drawn, that Allow issues a code and Deny returns `access_denied`, that
// `prompt=none` answers `consent_required`, that a global consent suppresses
// the prompt for a real sign-in — all of those are driven against the running
// service by `tests/vendored/sts_consent.js` and
// `tests/vendored/sts_admin_api_operations.js`. What is here is the three
// things that CANNOT be:
//
//   * **THE VALUE GRAMMAR.** `<when> <scope> <client_id>` is a string rule
//     whose whole justification is an edge case no request can produce on
//     demand: a client_id containing a SPACE or a `|`. The rule is that the
//     client_id is LAST and takes the remainder of the value, and the only way
//     to show that it holds is to write such a value and read it back. Asking
//     the service would be asking it to echo an answer this file can compute.
//
//   * **THE PRECEDENCE.** Which of three answers covers a scope — the person's
//     own, the application's override, or neither — is a pure function of two
//     attribute sets. Producing all six combinations over HTTP would mean six
//     sign-ins, six directory writes and a race against the clock in the
//     timestamp; here it is a stub and six assertions.
//
//   * **THE STATE ONLY AN `ldapmodify` CAN WRITE.** A value on somebody's entry
//     that is not in the shape this service writes. Both console doors and the
//     management API produce well-formed values by construction, so the only
//     way to reach it over HTTP would be to drive the LDAP socket in order to
//     create a state the API exists to prevent.
//
// The BOTH-WAYS case is the one worth reading first — a scope covered by the
// override AND by the person's own answer must report as the person's, because
// that is the fact that survives the override being taken away, and reporting
// it the other way round would make `revoke-global-consent` look like it had
// asked people who had already agreed.
// ===========================================================================

// Deleted rather than set, for the reason config_realm_layer.js gives: nothing
// here should depend on a developer's exported appconfig.
delete process.env.CONFIG_FILE;

const applications = require('../common/applications');
const consent = require('../common/consent');

// ---------------------------------------------------------------------------
// THE TWO STUBS.
//
// `applications.setDirectory()` is the slot `ldap/ldap_server.js` fills at its
// own require time, and filling it here is what makes the registry answer
// without a directory, a socket or a realm — the same thing
// `user_graph_permissions.js` does and for the same reason.
//
// `consent.setDirectory()` is this feature's own slot. The stub is a plain
// object keyed by identity, so that a test can put a value on somebody's entry
// that the service would never write.
// ---------------------------------------------------------------------------
function entry(identifier, attributes) {
  const attrs = { appIdentifier: [identifier], cn: [identifier] };
  Object.keys(attributes || {}).forEach(function (name) {
    attrs[name] = attributes[name];
  });
  return { dn: 'cn=' + identifier + ',ou=applications', origin: 'test',
           createdAt: '', modifiedAt: '', operational: [], attributes: attrs };
}

// `resource1` and `resource2` expose a permission of the SAME NAME under
// different bases. That is the pair the whole "record the WHOLE identifier"
// rule exists for: a consent stored as the bare `read` would cover both, and
// there is no way to notice from either one alone.
const REGISTRY = [
  entry('webapp1', {
    oauthClientId: ['webapp1'],
    oauthGlobalConsent: ['openid', 'https://resource1.example/read']
  }),
  entry('webapp2', { oauthClientId: ['webapp2'] }),
  entry('resource1', {
    oauthClientId: ['resource1'],
    oauthPermissionBaseUri: ['https://resource1.example/'],
    oauthPermission: ['read|Read resource1\'s data', 'write']
  }),
  entry('resource2', {
    oauthClientId: ['resource2'],
    oauthPermissionBaseUri: ['https://resource2.example/'],
    oauthPermission: ['read']
  })
];

function consentStore(seed) {
  const held = {};
  Object.keys(seed || {}).forEach(function (key) {
    held[key] = (seed[key] || []).slice(0);
  });
  return {
    values: held,
    hooks: {
      consentsOf: function (key) {
        return { dn: 'uid=' + key + ',ou=users', found: !!held[key],
                 values: (held[key] || []).slice(0) };
      },
      addConsent: function (key, values) {
        held[key] = (held[key] || []).concat(values.filter(function (one) {
          return (held[key] || []).indexOf(one) < 0;
        }));
        return { ok: true, dn: 'uid=' + key + ',ou=users' };
      },
      removeConsent: function (key, values) {
        const before = (held[key] || []).length;
        held[key] = (held[key] || []).filter(function (one) {
          return values.indexOf(one) < 0;
        });
        return { ok: true, dn: 'uid=' + key + ',ou=users',
                 removed: before - held[key].length };
      },
      listConsents: function () {
        return Object.keys(held).map(function (key) {
          return { dn: 'uid=' + key + ',ou=users', username: key,
                   values: held[key].slice(0) };
        });
      }
    }
  };
}

// Which scopes came back outstanding, as a plain sorted list, so an assertion
// reads as the sentence it is making.
function names(result) {
  return result.names.slice(0).sort().join(' ');
}

function run(t) {
  // `readApplication` as well as `allApplications`, because this feature reads
  // ONE entry by identifier — `applications.get(clientId)` — where
  // `user_graph_permissions.js` only ever walks the container. A stub short by
  // that member throws inside load() rather than answering "no such
  // application", which is a failure that names applications.js and has
  // nothing to do with it.
  applications.setDirectory({
    allApplications: function () { return REGISTRY; },
    readApplication: function (identifier) {
      return REGISTRY.filter(function (one) {
        return (one.attributes.appIdentifier || [])[0] === identifier;
      })[0] || null;
    }
  });

  // -----------------------------------------------------------------------
  t.log.info('the value grammar: the client_id is LAST because it is the one ' +
             'field with no rule');
  // -----------------------------------------------------------------------
  const when = new Date(Date.UTC(2026, 8, 1, 14, 30, 0));
  t.equal(consent.consentValueOf('openid', 'webapp1', when),
          '20260901143000Z openid webapp1',
          'a GeneralizedTime, the scope and the client, space-separated — the ' +
          'same spelling ldap_server.js writes every other timestamp in');

  const plain = consent.parseConsentValue('20260901143000Z openid webapp1');
  t.equal(plain.scope, 'openid', 'the scope reads back');
  t.equal(plain.client, 'webapp1', 'and so does the client');
  t.equal(plain.at, '20260901143000Z', 'and the instant it was agreed');

  const spaced = consent.parseConsentValue(
    consent.consentValueOf('https://resource1.example/read', 'a client with spaces', when));
  t.equal(spaced.client, 'a client with spaces',
          'A CLIENT_ID CONTAINING SPACES SURVIVES THE ROUND TRIP, which is the ' +
          'whole reason it is last: identifierProblem() refuses only a line ' +
          'break, a NUL and 512 characters, so a client_id may contain ' +
          'anything at all — and a grammar that split it on the last space ' +
          'would file that person\'s consent under a name nothing could ever ' +
          'revoke');
  t.equal(spaced.scope, 'https://resource1.example/read',
          'and the permission identifier is intact beside it');

  const barred = consent.parseConsentValue(
    consent.consentValueOf('write', 'weird|client', when));
  t.equal(barred.client, 'weird|client',
          'AND SO DOES ONE CONTAINING `|` — which is why the delimiter here is ' +
          'a space and not this repository\'s usual pipe: `oauthPermission`\'s ' +
          '`name|description` works because the unconstrained field is last ' +
          'there too, and here the unconstrained field contains pipes as ' +
          'happily as anything else');

  const junk = consent.parseConsentValue('something-somebody-typed');
  t.equal(junk.scope, '',
          'a value with no delimiters at all reads as NOT A CONSENT rather ' +
          'than as a consent to something — an ldapmodify can put anything in ' +
          'this attribute, and a parser that guessed would grant it');
  t.equal(consent.parseConsentValue('20260901143000Z openid').scope, '',
          'and so does one with only two fields: without a client_id it names ' +
          'no application, so there is nothing it could be a consent TO');
  t.equal(consent.parseConsentValue('this is not a consent').scope, '',
          'AND SO DOES A SENTENCE, which is the case that forced the timestamp ' +
          'to be CHECKED rather than merely split off: three words separated ' +
          'by spaces fit the grammar exactly, so a parser that only counted ' +
          'delimiters would read this as a consent to `is` for a client called ' +
          '`not a consent` — a permission granted to nobody, invented out of ' +
          'prose somebody left on an entry');

  // -----------------------------------------------------------------------
  t.log.info('a scope list is deduplicated and keeps its order');
  // -----------------------------------------------------------------------
  t.equal(consent.scopesOf('openid profile openid').join(' '), 'openid profile',
          'RFC 6749 section 3.3 says nothing about repetition, so `openid ' +
          'openid profile` is two scopes — and a screen that listed the same ' +
          'word twice would be asking one question twice');
  t.equal(consent.scopesOf('   ').length, 0,
          'and an empty scope parameter asks for nothing, so nothing is ' +
          'outstanding and no screen is drawn');

  // -----------------------------------------------------------------------
  t.log.info('THE PRECEDENCE: which of three answers covers a scope');
  // -----------------------------------------------------------------------
  // `alice` has agreed `profile` for webapp1 and nothing else. `webapp1`
  // carries a global consent for `openid` and for resource1's `read`.
  const store = consentStore({
    alice: [consent.consentValueOf('profile', 'webapp1', when)]
  });
  consent.setDirectory(store.hooks);

  const mixed = consent.outstanding({
    username: 'alice', clientId: 'webapp1',
    scope: 'openid profile email https://resource1.example/read'
  });
  t.equal(names(mixed), 'email',
          'ONLY `email` IS ASKED. `openid` is covered by the override, ' +
          '`profile` by what alice answered, and the delegated permission by ' +
          'the override again — three different reasons that all have to end ' +
          'in the same silence');

  const row = mixed.scopes.filter(function (one) { return one.scope === 'profile'; })[0];
  t.check(row && row.consented === true && row.global === false,
          'the row for a scope alice agreed to says so, and does not claim an ' +
          'override she never had');
  const globalRow = mixed.scopes.filter(function (one) { return one.scope === 'openid'; })[0];
  t.check(globalRow && globalRow.global === true && globalRow.consented === false,
          'and the row for the override says the opposite — the two are ' +
          'reported separately because removing them does different things');

  // BOTH AT ONCE. alice now also agrees `openid` personally, which the override
  // was already covering.
  store.hooks.addConsent('alice', [consent.consentValueOf('openid', 'webapp1', when)]);
  const both = consent.outstanding({ username: 'alice', clientId: 'webapp1',
                                     scope: 'openid' });
  const bothRow = both.scopes[0];
  t.check(bothRow.consented === true && bothRow.global === true,
          'A SCOPE COVERED BOTH WAYS REPORTS BOTH, and the person\'s own ' +
          'answer is the one that survives the override being taken away — ' +
          'a register that reported only the override would make ' +
          'revoke-global-consent look as though it had started asking people ' +
          'who had already agreed');

  // -----------------------------------------------------------------------
  t.log.info('THE OVERRIDE IS KEYED ON (APPLICATION, SCOPE) AND NEVER ON THE ' +
             'SCOPE ALONE');
  // -----------------------------------------------------------------------
  const other = consent.outstanding({ username: 'alice', clientId: 'webapp2',
                                      scope: 'openid https://resource1.example/read' });
  t.equal(names(other), 'https://resource1.example/read openid',
          'BOTH ARE ASKED OF webapp2. webapp1 carries an override for exactly ' +
          'these two, and it consents them for webapp1 — an application ' +
          'registered afterwards that spells the same words is still asked, ' +
          'which is the whole reason the override is a pair rather than a ' +
          'service-wide list of harmless scopes');
  t.equal(names(consent.outstanding({ username: 'bob', clientId: 'webapp1',
                                      scope: 'openid profile' })),
          'profile',
          'AND IT COVERS EVERYBODY ON THE APPLICATION IT IS ON: bob has never ' +
          'signed in anywhere and is not asked about `openid` either');

  // -----------------------------------------------------------------------
  t.log.info('AN OVERRIDE ON A DELEGATED PERMISSION IS THE SAME OVERRIDE, and ' +
             'the identifier is what is matched');
  // -----------------------------------------------------------------------
  // The assertion this whole "store the WHOLE identifier" rule exists for.
  // resource1 and resource2 both expose `read`; webapp1's override names
  // resource1's.
  const twoReads = consent.outstanding({
    username: 'bob', clientId: 'webapp1',
    scope: 'https://resource1.example/read https://resource2.example/read'
  });
  t.equal(names(twoReads), 'https://resource2.example/read',
          'RESOURCE2\'S `read` IS STILL ASKED. Both permissions are called ' +
          '`read` and only one is consented, so a register that had stored ' +
          'the bare name would have silently consented an API nobody ' +
          'mentioned — and nothing downstream could ever have noticed, ' +
          'because the token it produces is a perfectly ordinary one');
  const permissionRow = twoReads.scopes.filter(function (one) {
    return one.scope === 'https://resource1.example/read';
  })[0];
  t.check(permissionRow && permissionRow.permission &&
          permissionRow.permission.identifier === 'resource1',
          'and the row resolves to the application that EXPOSES it, so the ' +
          'screen can say whose API is being asked for rather than printing a ' +
          'URL');
  t.equal(permissionRow.permission.description, 'Read resource1\'s data',
          'with the description somebody typed — a screen that listed five ' +
          'opaque words is a screen that teaches a person to press Allow');

  // -----------------------------------------------------------------------
  t.log.info('prompt=consent asks again and takes nothing away');
  // -----------------------------------------------------------------------
  const again = consent.outstanding({ username: 'alice', clientId: 'webapp1',
                                      scope: 'openid profile', all: true });
  t.equal(names(again), 'openid profile',
          'OIDC Core section 3.1.2.1: every requested scope is outstanding ' +
          'whatever is on the entry');
  t.equal(consent.consentsOf('alice').length, 2,
          'AND NOTHING WAS DELETED BY ASKING. Re-consenting adds nothing that ' +
          'is not already there and somebody who cancels keeps what they had — ' +
          'a prompt that cleared the entry first would make Deny destructive');

  // -----------------------------------------------------------------------
  t.log.info('a value only an ldapmodify can write is reported, never obeyed');
  // -----------------------------------------------------------------------
  store.values.carol = ['this is not a consent'];
  const register = consent.register();
  const odd = register.users.filter(function (one) { return one.username === 'carol'; })[0];
  t.check(odd && odd.unreadable === true,
          'the register marks it unreadable and shows the raw value — a value ' +
          'the page silently dropped would be one somebody wrote on purpose ' +
          'and could not find out was being ignored');
  t.equal(names(consent.outstanding({ username: 'carol', clientId: 'webapp2',
                                      scope: 'profile' })),
          'profile',
          'AND IT CONSENTS NOTHING: carol is asked about `profile` exactly as ' +
          'though her entry were empty');
  t.equal(register.counts.unreadable, 1,
          'and the count says how many there are, so a directory somebody has ' +
          'been editing by hand says so on the page rather than in a log');

  // -----------------------------------------------------------------------
  t.log.info('the register keeps the two halves apart');
  // -----------------------------------------------------------------------
  const globals = register.globals.filter(function (one) { return one.client === 'webapp1'; });
  t.equal(globals.length, 2, 'both of webapp1\'s overrides are listed');
  const permissionGlobal = globals.filter(function (one) {
    return one.scope === 'https://resource1.example/read';
  })[0];
  t.equal(permissionGlobal.resource, 'resource1',
          'the one that names a permission says which application exposes it');
  t.equal(permissionGlobal.granted, false,
          'AND WHETHER THE CLIENT HOLDS THE GRANT, which is a different ' +
          'question and is answered separately: webapp1 has been consented ' +
          'this permission by an operator and never GRANTED it, so with ' +
          'oauth2.delegatedPermissionsEnforced on the request is refused ' +
          'anyway — consent and permission are two gates and this is the one ' +
          'place both are visible at once');
  const plainGlobal = globals.filter(function (one) { return one.scope === 'openid'; })[0];
  t.equal(plainGlobal.resource, '',
          'and an ordinary scope names no resource rather than being reported ' +
          'as a broken permission — most scopes are not permissions');

  // -----------------------------------------------------------------------
  t.log.info('with no directory installed, an answer is NOT remembered and NOT ' +
             'silently granted');
  // -----------------------------------------------------------------------
  consent.setDirectory(null);
  t.equal(consent.storable(), true,
          'a refused install leaves the previous one standing rather than ' +
          'half-replacing it — setDirectory() validates the object WHOLE, ' +
          'because a filler that installed the reads and neither write would ' +
          'draw the screen, record nothing, and draw it again');
  consent.setDirectory({ consentsOf: function () { return { values: [] }; },
                         addConsent: function () { return { ok: false, reason: 'noEntry' }; },
                         removeConsent: function () { return { ok: false }; },
                         listConsents: function () { return []; } });
  const unstored = consent.record('dave', 'webapp2', ['profile']);
  t.equal(unstored.ok, true,
          'the authorization request is NOT failed — a mock that stopped ' +
          'issuing because it could not file the paperwork would be a mock ' +
          'that stopped answering');
  t.equal(unstored.stored, false,
          'AND IT SAYS IT WAS NOT WRITTEN DOWN, so the person is asked again ' +
          'next time. That is the honest consequence of ldap.autoCreateUsers ' +
          'being off, and it is the opposite of the tempting shortcut: an ' +
          'agreement that cannot be remembered is one nobody gave');
  t.equal(names(consent.outstanding({ username: 'dave', clientId: 'webapp2',
                                      scope: 'profile' })),
          'profile',
          'and the very next request asks again, which is what "not written ' +
          'down" has to mean if it means anything');
}

module.exports = {
  name: 'consent',
  describe: 'an override is not a record, and neither is a value somebody typed',
  run: run
};
