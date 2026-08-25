'use strict';
//
// File: configure.js
//
// ===========================================================================
// TURN THE TWO IDENTITY SERVICES INTO A FEDERATION.
//
// This is the step that has no equivalent anywhere else in this repository.
// Every other protocol here works with nothing provisioned: point a SAML
// service provider at `/saml2` and its metadata is minted on the ask; send any
// `client_id` to the token endpoint and a token comes back. Federation cannot
// work that way — see `federation/CLAUDE.md` — so a relationship has to be
// created, filled in, and then deliberately enabled.
//
// It runs against the MANAGEMENT API, which is not gated, and that is the
// reason this script can exist at all: the console is behind a sign-on session
// and a role, and a test with no cookie jar cannot reach it.
//
// It is IDEMPOTENT. Run it twice and the second run reports what was already
// there rather than failing on a duplicate id, because the commonest way to use
// this stack is `docker compose up` once and `node drive.js` twenty times.
// ===========================================================================

const cfg = require('./config');
const client = require('./http_client');

function line() {
  console.log(Array.prototype.slice.call(arguments).join(' '));
}

async function api(base, action, body) {
  const response = await client.request('POST', base + '/admin-api/federation/' + action,
                                        { json: body });
  let parsed = null;
  try {
    parsed = JSON.parse(response.text);
  } catch (e) {
    throw new Error(action + ' at ' + base + ' answered ' + response.status +
                    ' with something that is not JSON: ' + response.text.slice(0, 200));
  }
  return parsed;
}

async function main() {
  line('Waiting for the two identity services…');
  await client.waitFor(cfg.SP_FRONT + '/healthcheck', 90);
  await client.waitFor(cfg.IDP_FRONT + '/healthcheck', 90);
  line('  service provider : ' + cfg.SP_FRONT + '   (dialled internally as ' + cfg.SP_BACK + ')');
  line('  identity provider: ' + cfg.IDP_FRONT + '   (dialled internally as ' + cfg.IDP_BACK + ')');

  // ---------------------------------------------------------------------
  // WHAT THE PARTNER PUBLISHES, read from the partner rather than written
  // down here. Two reasons and the second is the one that matters: the
  // endpoints are what they are, and reading them proves the identity
  // provider is actually up and answering as itself before anything is
  // configured against it.
  //
  // Fetched over the FRONT channel, because that is the address this script
  // can reach — and then the back-channel URLs are BUILT rather than taken
  // from the document, because the document's own URLs carry whichever host
  // answered this request. That substitution is the whole difficulty of
  // federating between containers, and doing it here in three visible lines
  // is better than a discovery document that quietly says the wrong thing.
  // ---------------------------------------------------------------------
  const discoveryUrl = cfg.IDP_FRONT + '/.well-known/openid-configuration';
  const response = await client.request('GET', discoveryUrl, {});
  if (response.status !== 200) {
    throw new Error('discovery at ' + discoveryUrl + ' answered ' + response.status);
  }
  const document = JSON.parse(response.text);
  line('');
  line('The identity provider publishes:');
  line('  issuer                 : ' + document.issuer);
  line('  authorization_endpoint : ' + document.authorization_endpoint);

  // The PINNED issuer is what a token from over there will actually carry, and
  // it is what `fedPeer` has to match. If these two disagree, STS_OAUTH2_ISSUER
  // was not set on the identity provider and every federated sign-in will be
  // refused with "it was issued by somebody else" — which is a correct refusal
  // about a real mismatch, and takes a while to recognise.
  if (document.issuer !== cfg.IDP_BACK) {
    line('');
    line('  NOTE: the published issuer is "' + document.issuer + '" and this stack expects');
    line('        "' + cfg.IDP_BACK + '". fedPeer is set to what the service actually');
    line('        publishes, because that is what an ID Token will carry — but if these');
    line('        differ, STS_OAUTH2_ISSUER is not pinned on the identity provider and');
    line('        the issuer will change with whichever address the request arrived at.');
  }
  const peer = document.issuer;

  // Front channel for the browser, back channel for everything this service
  // dials. See the compose file's header.
  const frontAuthorize = cfg.IDP_FRONT + '/oauth2/authorize';
  const backToken = cfg.IDP_BACK + '/oauth2/token';
  const backJwks = cfg.IDP_BACK + '/oauth2/jwks';

  line('');
  line('Configuring the relationship "' + cfg.RELATIONSHIP + '" on the service provider…');
  const created = await api(cfg.SP_FRONT, 'create', {
    id: cfg.RELATIONSHIP,
    role: 'service-provider',
    protocol: 'oidc',
    name: 'The upstream identity provider',
    peer: peer
  });
  if (created.ok) {
    line('  created, and DISABLED — which is what this register always does.');
  } else if (/already registered/.test(String(created.errors))) {
    line('  it is already registered; bringing its settings up to date.');
  } else {
    throw new Error('create refused: ' + JSON.stringify(created.errors));
  }

  const settings = [
    ['fedSsoUrl', frontAuthorize, 'FRONT channel — a browser follows this'],
    ['fedTokenUrl', backToken, 'BACK channel — this service dials it'],
    ['fedJwksUri', backJwks, 'BACK channel — this service dials it'],
    ['fedClientId', cfg.FED_CLIENT_ID, 'what the service provider calls itself over there'],
    ['fedScope', 'openid profile email', ''],
    ['fedResponseType', 'code', 'the authorization code flow, so there IS a back channel'],
    ['fedPeer', peer, 'CHECKED against the ID Token\'s iss']
  ];
  for (const [field, value, why] of settings) {
    const result = await api(cfg.SP_FRONT, 'set',
                             { id: cfg.RELATIONSHIP, field: field, value: value });
    if (!result.ok) throw new Error('set ' + field + ' refused: ' + JSON.stringify(result.errors));
    line('  ' + field.padEnd(16) + ' = ' + value + (why ? '   (' + why + ')' : ''));
  }

  // ---------------------------------------------------------------------
  // AND A MAPPING THE DEFAULT TABLE DOES NOT HAVE, because a stack that only
  // ever exercised the defaults would not show that per-partner mapping works
  // at all. The mock STS puts a `groups` claim in every token it issues, and
  // nothing maps that name — so without this it arrives, is reported as
  // unmapped, and is thrown away. With it, it lands on the directory entry.
  // ---------------------------------------------------------------------
  const mapping = 'groups=employeeType';
  const mapped = await api(cfg.SP_FRONT, 'add-value',
                           { id: cfg.RELATIONSHIP, field: 'fedAttributeMap', value: mapping });
  if (mapped.ok) line('  fedAttributeMap  + ' + mapping + '   (a name the default table has not got)');
  else if (/already carries/.test(String(mapped.errors))) line('  fedAttributeMap  already has ' + mapping);
  else throw new Error('add-value refused: ' + JSON.stringify(mapped.errors));

  line('');
  const enabled = await api(cfg.SP_FRONT, 'enable', { id: cfg.RELATIONSHIP });
  if (!enabled.ok) throw new Error('enable refused: ' + JSON.stringify(enabled.errors));

  const view = await client.request('GET',
    cfg.SP_FRONT + '/admin-api/federation?relationship=' + encodeURIComponent(cfg.RELATIONSHIP), {});
  const relationship = JSON.parse(view.text);
  line('The relationship is ' + (relationship.enabled ? 'ENABLED' : 'disabled') + ' and ' +
       (relationship.ready ? 'READY.' : 'NOT READY: ' + relationship.missing.join(', ')));
  if (!relationship.usable) {
    throw new Error('the relationship is not usable, so nothing downstream can work');
  }
  line('');
  line('What to give the partner (this service is the SP, so these are OUR addresses):');
  line('  redirect_uri : ' + relationship.endpoints.assertionConsumerService);
  line('  sign-in here : ' + cfg.SP_FRONT + relationship.endpoints.login);
  line('');
  line('Configured. Nothing was provisioned on the identity provider — it accepts any');
  line('client_id, which is the mock\'s ordinary permissiveness and is exactly what a');
  line('real partner would NOT do.');
}

main().then(function () {
  process.exit(0);
}).catch(function (e) {
  console.error('\nCONFIGURE FAILED: ' + e.message);
  process.exit(1);
});
