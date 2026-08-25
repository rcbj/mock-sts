'use strict';
//
// File: config.js
//
// ===========================================================================
// WHERE THE THREE SERVICES ARE, IN BOTH OF THE TWO ADDRESSES EACH ONE HAS.
//
// One file rather than a constant in each script, because getting a
// front-channel URL and a back-channel URL the wrong way round is the failure
// this whole stack is arranged to demonstrate, and it must not be possible for
// `config.js` and `drive.js` to disagree about which is which.
//
// EVERY VALUE IS OVERRIDABLE BY ENVIRONMENT VARIABLE, and the defaults are the
// compose stack's. `HOST_RUN=1` switches the back-channel addresses to
// loopback, which is what running the three as plain node processes needs —
// see `CLAUDE.md`, *Running it without docker*.
// ===========================================================================

// A host run has no docker DNS, so the back channel is loopback too. The
// FRONT channel is unchanged either way, which is the point: what the browser
// does is identical, and only what one service dials of another moves.
const HOST_RUN = process.env.FED_HOST_RUN === '1' || process.env.FED_HOST_RUN === 'true';

function env(name, fallback) {
  return process.env[name] || fallback;
}

// The two identity services, back channel: what one CONTAINER dials of another.
// These are also the values pinned into `STS_OAUTH2_ISSUER`, so an ID Token's
// `iss` is this string whichever address the request arrived at — see the
// compose file's header, where that trap is argued at length.
const SP_BACK = env('FED_SP_BACK', HOST_RUN ? 'http://127.0.0.1:8081' : 'http://sts-sp:8081');
const IDP_BACK = env('FED_IDP_BACK', HOST_RUN ? 'http://127.0.0.1:8082' : 'http://sts-idp:8081');

// Front channel: what the BROWSER visits, and what these scripts — which are
// standing in for the browser — reach everything at.
const SP_FRONT = env('FED_SP_FRONT', 'http://localhost:8081');
const IDP_FRONT = env('FED_IDP_FRONT', 'http://localhost:8082');
const APP_FRONT = env('FED_APP_FRONT', 'http://localhost:3000');

module.exports = {
  HOST_RUN: HOST_RUN,
  SP_BACK: SP_BACK,
  IDP_BACK: IDP_BACK,
  SP_FRONT: SP_FRONT,
  IDP_FRONT: IDP_FRONT,
  APP_FRONT: APP_FRONT,

  // The relationship's id on the service provider. It is the last segment of
  // `/federation/login/{id}` and of `/federation/acs/{id}`, so it is a URL
  // segment as well as a key.
  RELATIONSHIP: env('FED_RELATIONSHIP', 'upstream'),

  // What the service provider calls itself AT the identity provider. The mock
  // STS accepts any client_id, so nothing has to be registered over there
  // first — which is worth knowing when reading this against a real partner,
  // where it would be the first thing to arrange.
  FED_CLIENT_ID: env('FED_CLIENT_ID', 'sts-sp-federation-client'),

  // The web application's client at the service provider. Also unregistered,
  // also a public client: it has no secret and sends PKCE.
  APP_CLIENT_ID: env('FED_APP_CLIENT_ID', 'hello-world-app'),

  // Who signs in. There is no password anywhere in this stack — the name typed
  // at the identity provider's screen IS the identity, which is the mock's
  // whole premise — so this is the only thing a person contributes.
  //
  // **NOT `USERNAME`**, which cost a confusing five minutes on the first run:
  // that name is already in the environment of every interactive shell, so
  // `env('USERNAME', 'alice')` silently signed in as whoever was running the
  // test. It looked exactly like the stack working perfectly, for the wrong
  // person. Every variable this file reads is prefixed `FED_` for that reason.
  FED_USERNAME: env('FED_USERNAME', 'alice')
};
