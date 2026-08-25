'use strict';
//
// File: drive.js
//
// ===========================================================================
// ONE SIGN-IN, ACROSS THREE SERVICES, ASSERTED AT EVERY HOP.
//
// It stands in for a browser: three cookie jars, redirects followed, one form
// submitted. What it asserts is not "did a page load" but **which service
// answered, in which order, and what each of them recorded** — because a
// federated sign-in that ends on a hello-world page is not evidence of very
// much on its own. The interesting failures all produce a green page:
//
//   * a shared cookie jar makes the two identity services read each other's
//     sessions, and somebody ends up signed in for reasons unrelated to
//     federation;
//   * a service provider that skipped the signature check would sign the same
//     person in just as cheerfully;
//   * an application whose ID Token came from the WRONG issuer looks identical
//     from the outside.
//
// So the assertions below are about the SHAPE of the flow and the STATE left
// behind, and the happy page at the end is the least of them.
//
// ---------------------------------------------------------------------------
// THE ONE THING BEING DEMONSTRATED, in a sentence: the web application asks ONE
// provider ONE question and gets ONE answer, and the fact that a second
// identity service actually authenticated the person is invisible to it. That
// is asserted directly — the ID Token the application verified says `iss:
// sts-sp`, and the person it names has never had a credential checked there.
// ===========================================================================

const bunyan = require('bunyan');
// The suite's convention, and this repository's: bunyan rather than console,
// so that a run reads the same way as the parent project's tests/*.js and can
// be filtered by level. `./node_modules/.bin/bunyan` prettifies it.
const log = bunyan.createLogger({ name: 'drive',
                                  level: process.env.LOG_LEVEL || 'info' });

const cfg = require('./config');
const client = require('./http_client');

let passed = 0;
let failed = 0;
const failures = [];

function ok(what, detail) {
  passed++;
  log.info('✓ ' + what + (detail ? '  — ' + detail : ''));
}

function bad(what, detail) {
  failed++;
  failures.push(what + (detail ? ': ' + detail : ''));
  log.error('✗ ' + what + (detail ? '  — ' + detail : ''));
}

function check(condition, what, detail) {
  if (condition) ok(what, detail); else bad(what, detail);
  return !!condition;
}

function heading(text) {
  log.info('=== ' + text + ' ' + '='.repeat(Math.max(0, 62 - text.length)));
}

function showTrail(trail) {
  trail.forEach(function (hop) {
    const to = hop.to ? '→ ' + hop.to : '(the page)';
    log.info('      ' + hop.status + ' ' + shorten(hop.from) + '  ' + shorten(to));
  });
}

function shorten(url) {
  return String(url).replace(/\?.*$/, function (query) {
    return query.length > 44 ? query.slice(0, 44) + '…' : query;
  });
}

// Which of the three services an URL belongs to, for asserting the shape of
// the flow rather than its exact query strings.
function whose(url) {
  // The last hop of a trail has no target — it IS the page — so an empty
  // string reaches here on every successful follow. Named rather than guarded
  // away, because "(the page)" is what the trail should print for it.
  if (!url) return '(the page)';
  const origin = client.originOf(url);
  if (origin === client.originOf(cfg.APP_FRONT)) return 'webapp';
  if (origin === client.originOf(cfg.SP_FRONT)) return 'sts-sp';
  if (origin === client.originOf(cfg.IDP_FRONT)) return 'sts-idp';
  return origin;
}

async function json(url) {
  const response = await client.request('GET', url, {});
  try {
    return JSON.parse(response.text);
  } catch (e) {
    throw new Error('expected JSON from ' + url + ', got ' + response.status + ': ' +
                    response.text.slice(0, 160));
  }
}

async function main() {
  log.debug('Entering main().');
  log.info('Federation end to end: ' + cfg.APP_FRONT + ' → ' + cfg.SP_FRONT +
              ' → ' + cfg.IDP_FRONT);
  log.info('Signing in as "' + cfg.FED_USERNAME + '". No password is checked anywhere in ' +
              'this stack.');

  await client.waitFor(cfg.APP_FRONT + '/healthz', 90);
  await client.waitFor(cfg.SP_FRONT + '/healthcheck', 90);
  await client.waitFor(cfg.IDP_FRONT + '/healthcheck', 90);

  // The state each service is in BEFORE the flow, so that "one sign-in
  // happened" can be asserted as a difference rather than as an absolute — the
  // stack is meant to be driven repeatedly without being torn down.
  const before = {
    relationship: await json(cfg.SP_FRONT + '/admin-api/federation?relationship=' +
                             encodeURIComponent(cfg.RELATIONSHIP))
  };
  check(before.relationship.usable, 'the relationship is configured and enabled',
        before.relationship.usable ? '' : 'run configure.js first');
  if (!before.relationship.usable) throw new Error('nothing can work until the relationship is usable');

  // -----------------------------------------------------------------------
  heading('1. The application, signed out');
  // -----------------------------------------------------------------------
  let trail = [];
  let response = await client.follow('GET', cfg.APP_FRONT + '/', {}, trail);
  check(response.status === 200, 'the application answers', String(response.status));
  check(/You are not signed in/.test(response.text), 'it says nobody is signed in');
  check(!/federation/i.test(response.text.replace(/knows nothing about federation/gi, '')),
        'and it does not mention federation as something it does',
        'the only mention is the line saying it knows nothing about it');

  // -----------------------------------------------------------------------
  heading('2. The application sends the browser to ITS provider (sts-sp)');
  // -----------------------------------------------------------------------
  trail = [];
  response = await client.follow('GET', cfg.APP_FRONT + '/login', {}, trail);
  showTrail(trail);
  const toSp = trail.filter(function (h) { return whose(h.to) === 'sts-sp'; });
  check(toSp.length > 0, 'the browser is sent to sts-sp');
  check(/\/oauth2\/authorize/.test(toSp.length ? toSp[0].to : ''),
        'and it is an ordinary authorization request',
        'response_type=code, PKCE, nonce');
  check(/code_challenge_method=S256/.test(toSp.length ? toSp[0].to : ''),
        'the application sent PKCE');
  check(response.status === 200 && /Sign in/.test(response.text),
        'it lands on the sts-sp sign-in screen');
  check(/\/authn\/login/.test(response.url), 'which is /authn/login', shorten(response.url));

  // -----------------------------------------------------------------------
  heading('3. The sts-sp sign-in screen offers the federation partner');
  // -----------------------------------------------------------------------
  const buttons = client.links(response.text, /\/federation\/login\//);
  check(buttons.length === 1, 'exactly one federated partner is offered',
        buttons.map(function (b) { return b.text; }).join(', '));
  if (!buttons.length) throw new Error('no federation button on the sts-sp sign-in screen');
  const button = buttons[0];
  check(button.href.indexOf('/federation/login/' + cfg.RELATIONSHIP) === 0,
        'the button points at the relationship', button.href.split('?')[0]);
  check(/returnTo=/.test(button.href),
        'and it carries the whole authorization request as returnTo',
        'which is how a federated identity satisfies a flow already in progress');
  const returnTo = decodeURIComponent((button.href.match(/returnTo=([^&]*)/) || [])[1] || '');
  check(/\/oauth2\/authorize/.test(returnTo), 'returnTo is the application\'s own request',
        shorten(returnTo));

  // -----------------------------------------------------------------------
  heading('4. Following it crosses to the SECOND identity service (sts-idp)');
  // -----------------------------------------------------------------------
  trail = [];
  response = await client.follow('GET', cfg.SP_FRONT + button.href, {}, trail);
  showTrail(trail);
  const toIdp = trail.filter(function (h) { return whose(h.to) === 'sts-idp'; });
  check(toIdp.length > 0, 'the browser is sent to sts-idp');
  check(/\/oauth2\/authorize/.test(toIdp.length ? toIdp[0].to : ''),
        'as an OIDC authorization request from sts-sp',
        'sts-sp is a CLIENT here, not a provider');
  check(/code_challenge_method=S256/.test(toIdp.length ? toIdp[0].to : ''),
        'sts-sp sent PKCE too', 'always, and there is no setting to stop it');
  check(/nonce=/.test(toIdp.length ? toIdp[0].to : ''), 'and a nonce');
  check(response.status === 200 && /Sign in/.test(response.text),
        'it lands on the sts-idp sign-in screen');
  check(client.originOf(response.url) === client.originOf(cfg.IDP_FRONT),
        'which is a DIFFERENT service from the one the application knows',
        client.originOf(response.url));
  check(client.links(response.text, /\/federation\/login\//).length === 0,
        'sts-idp offers no federation partners of its own',
        'it has none configured, so its screen is the ordinary one');

  // -----------------------------------------------------------------------
  heading('5. The one place a name is typed, in the whole stack');
  // -----------------------------------------------------------------------
  const authnId = client.inputValue(response.text, 'authn_id');
  check(!!authnId, 'the sign-in screen carries its pending-authentication id');
  trail = [];
  response = await client.follow('POST', cfg.IDP_FRONT + '/authn/login', {
    form: { authn_id: authnId, username: cfg.FED_USERNAME, password: 'not-checked', action: 'login' }
  }, trail);
  showTrail(trail);

  const order = trail.map(function (h) { return whose(h.from); })
    .filter(function (v, i, a) { return i === 0 || v !== a[i - 1]; });
  check(order.join(' → ').indexOf('sts-idp → sts-sp') >= 0,
        'the answer comes back from sts-idp to sts-sp', order.join(' → '));
  const acs = trail.filter(function (h) { return /\/federation\/acs\//.test(h.from); });
  check(acs.length > 0, 'and it arrives at the assertion consumer service',
        acs.length ? shorten(acs[0].from) : 'never reached');
  check(order.indexOf('webapp') > order.indexOf('sts-sp'),
        'and then back to the application, last', order.join(' → '));

  // -----------------------------------------------------------------------
  heading('6. The application is signed in, and cannot tell what happened');
  // -----------------------------------------------------------------------
  check(response.status === 200, 'the final page is a 200', String(response.status));
  check(whose(response.url) === 'webapp', 'and it is the application\'s own page',
        response.url);
  const hello = (response.text.match(/<h1>Hello, ([^<.]*)\.?<\/h1>/) || [])[1];
  check(!!hello, 'it says hello to somebody', hello || 'no greeting on the page');
  check(String(hello || '').toLowerCase().indexOf(cfg.FED_USERNAME) >= 0,
        'and that somebody is who was typed at sts-idp', hello);

  const issuerShown = (response.text.match(/Signed in through <code>([^<]*)<\/code>/) || [])[1];
  check(!!issuerShown, 'the application names the issuer it verified', issuerShown);
  check(issuerShown === cfg.SP_BACK,
        'THE ID TOKEN CAME FROM sts-sp, not from sts-idp',
        'the application asked one provider and got one answer; the second identity ' +
        'service is invisible to it');

  const shownClaims = [];
  const claimRe = /<th><code>([^<]+)<\/code><\/th><td><code>([^<]*)<\/code><\/td>/g;
  let m;
  while ((m = claimRe.exec(response.text)) !== null) shownClaims.push([m[1], m[2]]);
  check(shownClaims.length > 0, 'the ID Token carried claims', shownClaims.length + ' of them');
  const byName = {};
  shownClaims.forEach(function (pair) { byName[pair[0]] = pair[1]; });
  check(String(byName.sub || '').indexOf(cfg.FED_USERNAME) >= 0,
        'sub names the federated person', byName.sub);
  // THE REGRESSION THIS TEST FOUND ON ITS FIRST RUN. The partner's own `sub`
  // was `urn:sts-mock:user:alice` — this service's subject format, because the
  // partner IS this service — and it reached startSession() unnormalised, so
  // userFor() applied the prefix a second time and every downstream token
  // carried `urn:sts-mock:user:urn:sts-mock:user:alice`. It would have happened
  // with any partner whose subject carried an '@' too. Asserted here rather
  // than only in the unit-shaped checks, because this is the layer where it
  // was visible.
  check(!/urn:sts-mock:user:.*urn:sts-mock:user:/.test(String(byName.sub || '')),
        'and sub carries this service\'s subject prefix exactly once',
        'a foreign subject is normalised before it becomes a local username');
  check(!/urn:sts-mock:user:/.test(String(hello || '')),
        'the greeting is a person\'s name rather than a raw foreign subject', hello);

  // -----------------------------------------------------------------------
  heading('7. What sts-sp recorded — the service provider of the relationship');
  // -----------------------------------------------------------------------
  const after = await json(cfg.SP_FRONT + '/admin-api/federation?relationship=' +
                           encodeURIComponent(cfg.RELATIONSHIP));
  check(after.authentications === before.relationship.authentications + 1,
        'the relationship counted exactly one federated sign-in',
        before.relationship.authentications + ' → ' + after.authentications);
  check(after.lastError === '', 'and recorded no refusal',
        after.lastError || 'fedLastError is empty, which a success clears');
  check(after.lastUser.indexOf(cfg.FED_USERNAME) >= 0, 'against the right person', after.lastUser);

  const spUsers = await json(cfg.SP_FRONT + '/admin-api/users?q=' + encodeURIComponent(cfg.FED_USERNAME));
  const spUser = (spUsers.users || [])[0];
  check(!!spUser, 'sts-sp has a record of them on /admin/users', spUser ? spUser.key : 'none');
  // `protocols` is an ARRAY of rows, not an object keyed by name. Reading it
  // with Object.keys() gave "0" — the index of the first element — which is
  // falsy for the test above it and looked like the protocol not being
  // recorded at all.
  const protocols = spUser
    ? (spUser.protocols || []).map(function (row) { return row.protocol; }).join(', ') : '';
  check(/Federation/.test(protocols), 'filed under the federation protocol', protocols);

  const dir = await json(cfg.SP_FRONT + '/ldap/directory?format=json');
  const entry = (dir.entries || []).filter(function (e) {
    return new RegExp('uid=' + cfg.FED_USERNAME + ',', 'i').test(e.dn);
  })[0];
  check(!!entry, 'and an entry in its embedded directory', entry ? entry.dn : 'none created');
  if (entry) {
    const attrs = {};
    Object.keys(entry.attributes).forEach(function (k) { attrs[k.toLowerCase()] = entry.attributes[k]; });
    check((attrs.federationrelationship || []).indexOf(cfg.RELATIONSHIP) >= 0,
          'the entry names the relationship they came through',
          (attrs.federationrelationship || []).join(', '));
    check((attrs.federationissuer || [])[0] === after.peer,
          'and the foreign issuer that asserted them', (attrs.federationissuer || [])[0]);
    const fromPartner = attrs.federationattribute || [];
    check(fromPartner.length > 0,
          'and which of its attributes came from the partner rather than being invented',
          fromPartner.join(', '));
    check(fromPartner.indexOf('employeeType') >= 0,
          'including the one only a PER-PARTNER mapping could have written',
          'groups=employeeType, a name the default table has not got');
    check((attrs.uid || [])[0] === cfg.FED_USERNAME,
          'uid is the local username and was not overwritten by the partner',
          (attrs.uid || [])[0]);
  }

  const spApps = await json(cfg.SP_FRONT + '/admin-api/applications');
  const partnerApp = (spApps.applications || []).filter(function (a) {
    return a.identifier === after.peer;
  })[0];
  check(!!partnerApp, 'sts-sp recorded the foreign identity provider as a party',
        partnerApp ? partnerApp.identifier : 'not recorded');
  check(partnerApp && (partnerApp.kinds || []).indexOf('federation-identity-provider') >= 0,
        'under a kind that says it is not a client of this service',
        partnerApp ? (partnerApp.kinds || []).join(', ') : '');
  const appApp = (spApps.applications || []).filter(function (a) {
    return a.identifier === cfg.APP_CLIENT_ID;
  })[0];
  check(!!appApp, 'and the web application as an ordinary OAuth client',
        appApp ? (appApp.kinds || []).join(', ') : 'not recorded');

  // -----------------------------------------------------------------------
  heading('8. What sts-idp recorded — the identity provider of the relationship');
  // -----------------------------------------------------------------------
  const idpUsers = await json(cfg.IDP_FRONT + '/admin-api/users?q=' + encodeURIComponent(cfg.FED_USERNAME));
  const idpUser = (idpUsers.users || [])[0];
  check(!!idpUser, 'sts-idp authenticated them at its own screen',
        idpUser ? idpUser.key : 'none');
  const idpProtocols = idpUser
    ? (idpUser.protocols || []).map(function (row) { return row.protocol; }).join(', ') : '';
  check(!/Federation/.test(idpProtocols),
        'and it knows nothing about federation',
        idpProtocols + ' — an ordinary sign-in, as far as it is concerned');

  const idpApps = await json(cfg.IDP_FRONT + '/admin-api/applications');
  const spAsClient = (idpApps.applications || []).filter(function (a) {
    return a.identifier === cfg.FED_CLIENT_ID;
  })[0];
  check(!!spAsClient, 'it recorded sts-sp as an ordinary OIDC client of its own',
        spAsClient ? (spAsClient.kinds || []).join(', ') : 'not recorded');

  const idpFed = await json(cfg.IDP_FRONT + '/admin-api/federation');
  check(idpFed.relationshipCount === 0,
        'and it has no federation relationships at all',
        'the two services run the same image and differ only in configuration');

  // -----------------------------------------------------------------------
  heading('9. The refusal, which is the half a happy path proves nothing about');
  // -----------------------------------------------------------------------
  // A response this service never asked for, carrying a code it never issued.
  // It must be refused on the STATE before anything is dialled — the state is
  // one-shot and was spent by the sign-in above.
  const forged = await client.request('GET',
    cfg.SP_FRONT + '/federation/acs/' + encodeURIComponent(cfg.RELATIONSHIP) +
    '?code=not-a-real-code&state=not-a-real-state', {});
  check(forged.status === 401, 'an unsolicited callback is refused', String(forged.status));
  check(/did not start that sign-in/i.test(forged.text),
        'because the state is not one this service minted',
        'which is what a cross-site request forgery on that callback looks like');

  const afterForged = await json(cfg.SP_FRONT + '/admin-api/federation?relationship=' +
                                 encodeURIComponent(cfg.RELATIONSHIP));
  check(afterForged.lastError !== '', 'and the refusal is recorded on the relationship',
        afterForged.lastError.slice(0, 70));
  check(afterForged.authentications === after.authentications,
        'without counting as a sign-in',
        after.authentications + ' before, ' + afterForged.authentications + ' after');

  // -----------------------------------------------------------------------
  log.info('='.repeat(64));
  log.info(passed + ' passed, ' + failed + ' failed');
  if (failed) {
    failures.forEach(function (f) {
      log.error('FAILED: ' + f);
    });
  }
  log.info('='.repeat(64));
  log.debug('Leaving main().');
  return failed === 0;
}

main().then(function (allPassed) {
  process.exit(allPassed ? 0 : 1);
}).catch(function (e) {
  log.error('DRIVER FAILED: ' + (e && e.stack ? e.stack : e));
  process.exit(1);
});
