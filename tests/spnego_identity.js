'use strict';
//
// File: spnego_identity.js
//
// ===========================================================================
// WHAT A KERBEROS TICKET SAYS, AND WHAT THE SESSION MINTED FROM IT CLAIMS.
//
// `/authn/spnego` turns a service ticket into the browser session sixteen
// protocol families read. Two pure functions in `kerberos/spnego_authn.js`
// decide what that session IS — `usernameFor()` picks the identity out of the
// client principal, and `factorsFor()` reads `amr` and `acr` off the ticket's
// own flags — and both are one line of arithmetic with a paragraph of argument
// behind them. This file asserts the argument.
//
// WHY IN PROCESS, which is the only question this directory's own rule asks.
//
// `factorsFor()` is the reason, and it is the same shape as
// `config_realm_layer.js`'s: **the cases worth asserting are ones the running
// service cannot be made to produce.** A ticket carrying NEITHER `pre-authent`
// NOR `hw-authent` is the interesting one — the honest answer is an EMPTY `amr`
// and `acr "0"`, because filling in `pwd` there would tell a relying party a
// password was checked when nothing knows whether one was — and this KDC
// requires pre-authentication, so no client driving it over HTTP can obtain
// such a ticket. `hw-authent` is worse: nothing in this service ever sets it,
// so the two-factor branch is unreachable from outside the process entirely.
// A test over HTTP could assert the ONE case that is reachable and would report
// green over three branches it never ran.
//
// `usernameFor()` is reachable over HTTP for the local realm and not for a
// foreign one — a cross-realm ticket needs the trusted realm's own KDC path —
// and it is here because the two halves are one decision and splitting them
// would leave the asymmetry (strip the local realm, keep a foreign one)
// asserted nowhere.
//
// The end-to-end claim — that a real AP-REQ over a real socket produces a real
// session — is not this file's and cannot be: it needs a listener. It belongs
// in the parent project's suite beside `krb5_spnego_http.js`, which already
// drives the acceptor this door shares.
// ===========================================================================

// Deleted rather than set, for the reason config_realm_layer.js gives: nothing
// here should depend on a developer's exported appconfig.
delete process.env.CONFIG_FILE;

const door = require('../kerberos/spnego_authn.js');
const principals = require('../kerberos/krb5_principals.js');

// ---------------------------------------------------------------------------
// The realm this KDC serves, read rather than written down. `krb5.realm` is a
// setting, so a suite that hard-coded EXAMPLE.COM would pass for the wrong
// reason on a machine that had exported KRB5_REALM — and would then be
// asserting that a LOCAL principal keeps its realm, which is the opposite of
// what this function does.
// ---------------------------------------------------------------------------
const REALM = principals.REALM;

function theLocalRealmIsStrippedAndAForeignOneIsNot(t) {
  t.equal(door.usernameFor('alice@' + REALM), 'alice',
    'the local realm is stripped: the session username becomes ' +
    'sub urn:sts-mock:user:<name> in every token that follows, and leaving ' +
    'the realm on would make a typed sign-in and a ticket sign-in TWO ' +
    'subjects for one person');

  t.equal(door.usernameFor('bob@PARTNER.EXAMPLE.COM'), 'bob@PARTNER.EXAMPLE.COM',
    'a FOREIGN realm is kept whole — bob@PARTNER is not this service\'s bob, ' +
    'and issuing a token saying he is would be an assertion nothing here has ' +
    'any basis for');

  // The asymmetry above is the whole of this function and it is easy to
  // "simplify" into stripping everything, which is why it is asserted from
  // both sides rather than once.
  t.check(door.usernameFor('bob@PARTNER.EXAMPLE.COM').indexOf('@') !== -1 &&
          door.usernameFor('alice@' + REALM).indexOf('@') === -1,
    'the two directions disagree on purpose, which is what makes this a ' +
    'decision rather than a formatting step');

  t.equal(door.usernameFor('alice@' + REALM.toLowerCase()),
    'alice@' + REALM.toLowerCase(),
    'and the comparison is CASE-SENSITIVE: Kerberos realms are ' +
    'case-sensitive by specification, so EXAMPLE.COM and example.com are two ' +
    'realms and folding them here would be this module deciding a question ' +
    'the KDC did not');
}

function aMultiComponentNameSurvivesWhole(t) {
  t.equal(door.usernameFor('HTTP/web.example.com@' + REALM),
    'HTTP/web.example.com',
    'a service-shaped principal signing in is unusual and not wrong, and the ' +
    'components ARE the name — splitting on the first slash would file a ' +
    'service under "HTTP"');

  // A UPN-shaped account name is ordinary in a Windows realm, which is why
  // admin_stats.js's identityOf() splits on the LAST '@' and why this does too.
  t.equal(door.usernameFor('alice@corp.example@' + REALM), 'alice@corp.example',
    'the LAST @ separates the realm: a principal name may itself contain one ' +
    'and a realm never does');

  t.equal(door.usernameFor('alice'), 'alice',
    'a bare name with no realm at all is left alone rather than being ' +
    'treated as a foreign one');
  t.equal(door.usernameFor(''), '',
    'and an empty principal produces an empty name rather than throwing on ' +
    'the way into a sign-in');
  t.equal(door.usernameFor('@' + REALM), '@' + REALM,
    'a principal that is ONLY a realm keeps its @ — lastIndexOf at position 0 ' +
    'is not a split, and stripping there would produce an empty username and ' +
    'a session for nobody');
}

function theFactorsAreReadOffTheTicketAndNotInvented(t) {
  // RFC 4120 section 2.1: pre-authent means the KDC verified
  // pre-authentication before issuing the initial ticket. On this KDC that is
  // PA-ENC-TIMESTAMP, a timestamp encrypted under a key derived from a
  // password — so RFC 8176's `pwd` is the honest value.
  const password = door.factorsFor(['forwardable', 'renewable', 'initial',
                                    'pre-authent']);
  t.equal(password.amr.join(','), 'pwd',
    'pre-authent means a long-term key derived from a password was proven to ' +
    'the KDC, which is RFC 8176 `pwd`');
  t.equal(password.acr, '1', 'and one factor is acr "1"');

  // The flag beside it, and nothing in this service ever sets it — which is
  // exactly why it has to be asserted here rather than over HTTP.
  const hardware = door.factorsFor(['hw-authent']);
  t.equal(hardware.amr.join(','), 'hwk',
    'hw-authent means the initial authentication required hardware expected ' +
    'to be possessed solely by the client, which is `hwk` and nothing else ' +
    'in RFC 8176 fits it');
  t.equal(hardware.acr, '1', 'and one factor is still one factor');

  const both = door.factorsFor(['pre-authent', 'hw-authent']);
  t.equal(both.amr.join(','), 'pwd,hwk', 'both flags claim both factors');
  t.equal(both.acr, 'mfa',
    'and only BOTH is "mfa" — the same rule authn.js applies to the ' +
    'passwordless WebAuthn path: one factor does not become two by being ' +
    'phishing-resistant, and a relying party that asked for two must not be ' +
    'told it got them');
}

function aTicketClaimingNothingMakesThisServiceClaimNothing(t) {
  // THE CASE THIS FILE EXISTS FOR. It is unreachable over HTTP against this
  // KDC, and it is the one where an implementation is most tempted to fill in
  // a plausible value.
  const nothing = door.factorsFor(['forwardable', 'renewable']);
  t.equal(nothing.amr.length, 0,
    'a ticket claiming neither flag produces an EMPTY amr: this service will ' +
    'not name a factor no credential evidenced, and `pwd` here would tell a ' +
    'relying party a password was checked when nothing knows whether one was');
  t.equal(nothing.acr, '0',
    'and acr "0", which is how RFC 6711 says no level of assurance is being ' +
    'claimed — not "1", which would be a claim');

  t.equal(door.factorsFor([]).acr, '0', 'an empty flag list is the same case');
  t.equal(door.factorsFor(null).acr, '0',
    'and so is a missing one — the acceptor returns ticketFlags only when it ' +
    'got as far as decrypting the ticket, and a caller must not have to know ' +
    'that');
  t.equal(door.factorsFor(null).amr.length, 0, 'with nothing claimed');
}

function initialIsNotAFactor(t) {
  // `initial` says WHERE the credential was minted — straight from the AS
  // exchange rather than through the TGS — and says nothing about what was
  // checked. It is on the page and used for nothing, and reading it as
  // evidence is the most plausible wrong move available here: a ticket
  // carrying `initial` almost always carries `pre-authent` too, so the mistake
  // would be invisible in every ordinary case.
  const initialOnly = door.factorsFor(['initial']);
  t.equal(initialOnly.amr.length, 0,
    '`initial` is not an authentication method: it says the ticket came ' +
    'straight from the AS exchange, not that anything was verified');
  t.equal(initialOnly.acr, '0', 'so nothing is claimed for it');

  // And the other direction: a SECOND-HAND ticket still claims what its
  // lineage claims. A service ticket out of the TGS carries no `initial` and
  // inherits `pre-authent` from the AS exchange that produced the TGT — which
  // is Kerberos's model rather than a weakness here, and is what makes the
  // session's authTime mean something.
  const secondHand = door.factorsFor(['forwardable', 'pre-authent']);
  t.equal(secondHand.amr.join(','), 'pwd',
    'a ticket from the TGS carries no `initial` and still claims the ' +
    'pre-authentication it inherited, which is the ordinary case and must not ' +
    'depend on `initial` being there');
}

function theMethodSentenceSaysWhichCaseItWas(t) {
  // It goes on /admin/users through startSession()'s sixth argument, and it is
  // the only place a reader of that page can tell the four cases apart —
  // `amr` is not rendered there. A blank or identical sentence would make all
  // four look like one.
  const sentences = [
    door.factorsFor(['pre-authent']).method,
    door.factorsFor(['hw-authent']).method,
    door.factorsFor(['pre-authent', 'hw-authent']).method,
    door.factorsFor([]).method
  ];
  const distinct = {};
  sentences.forEach(function (one) { distinct[one] = true; });
  t.equal(Object.keys(distinct).length, 4,
    'the four cases produce four different sentences on /admin/users, where ' +
    'amr is not rendered and this is the only thing that tells them apart');
  sentences.forEach(function (one, i) {
    t.check(/^Kerberos ticket over SPNEGO/.test(one),
      'sentence ' + i + ' names the mechanism first, so the page groups them: ' +
      one);
  });
}

module.exports = {
  name: 'spnego_identity',
  describe: 'the identity and the factors a SPNEGO sign-in claims, off the ticket',
  run: function (t) {
    theLocalRealmIsStrippedAndAForeignOneIsNot(t);
    aMultiComponentNameSurvivesWhole(t);
    theFactorsAreReadOffTheTicketAndNotInvented(t);
    aTicketClaimingNothingMakesThisServiceClaimNothing(t);
    initialIsNotAFactor(t);
    theMethodSentenceSaysWhichCaseItWas(t);
  }
};
