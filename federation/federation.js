'use strict';
//
// File: federation.js
//
// ===========================================================================
// EVERY FEDERATION RELATIONSHIP THIS SERVICE HAS BEEN CONFIGURED WITH.
//
// A federation relationship is a protocol relationship — a SAML 2.0 assertion,
// a WS-Federation sign-in response, an OpenID Connect ID Token — with ONE fact
// added that changes what has to be true of it: the party on the other end is
// SOMEBODY ELSE'S IDENTITY SERVICE. Every other relationship this service has
// is with a client, and the whole premise of this repository is that a client
// gets whatever it asks for. A federation partner is the opposite case in both
// directions:
//
//   * WHERE THIS SERVICE IS THE SERVICE PROVIDER it CONSUMES an assertion it
//     did not mint, from a signer whose key it does not hold, naming a person
//     it has never heard of. There is nothing here that can be permissive
//     about: an assertion this service cannot verify is not a permissive
//     acceptance, it is an unauthenticated request with XML attached. So this
//     is the one register in this repository that must be CONFIGURED BEFORE IT
//     WILL DO ANYTHING, and every relationship starts disabled.
//
//   * WHERE THIS SERVICE IS THE IDENTITY PROVIDER the partner is a foreign
//     service provider rather than a test client somebody wrote, and what a
//     real federation configures per-partner is WHICH ATTRIBUTES ARE RELEASED
//     TO IT. That is the whole of the identity-provider half here, and it is
//     deliberately narrow — see THE RELEASE FILTER below.
//
// ---------------------------------------------------------------------------
// WHY THIS CANNOT BE MOCKED, WHICH IS THE ONE PLACE THIS FEATURE ARGUES WITH
// THE REST OF THE SERVICE.
//
// `README.md` and every directory `CLAUDE.md` here say the same thing: this
// service checks no password, validates no access token and attests no
// workload. Three surfaces are already the exception (SCIM, the SPIRE Server
// API, the admin console) and each has its argument written down. This is the
// FOURTH, and its argument is different from all three of theirs.
//
// Those three REFUSE a caller in order to make a client exercise a refusal.
// This one refuses because THERE IS NO PERMISSIVE ANSWER AVAILABLE. "Accept
// any SAML Response" does not mean "be generous", it means "let anybody who
// can reach this port POST a document naming themselves as anybody and get a
// session for it" — and the session is the one this service's OAuth2, SAML,
// WS-Federation and console surfaces all read. The permissive version of this
// feature is not a mock of federation; it is a hole underneath every other
// protocol here.
//
// So the shape of the exception is: **a relationship must be configured, and
// what it configures is a KEY**. Once configured, everything downstream is as
// permissive as the rest of this service — any username in the assertion is
// accepted, any attribute is mapped, nothing about the person is checked, and
// an entry is created for them. The gate is on the SIGNER, not on the SUBJECT,
// which is exactly the line `spiffe_auth.js` draws and for the same reason.
//
// ---------------------------------------------------------------------------
// ONE RELATIONSHIP IS ONE DIRECTION, AND THAT IS A DECISION.
//
// A partner this service both consumes from and asserts to is TWO
// relationships, not one record with two halves. Everything that configures a
// relationship differs by direction — the endpoints are theirs or ours, the
// certificate is theirs or ours, the attribute mapping runs inbound or the
// release list runs outbound — so a single record would need two of each field
// and every page and every form would have to say which half it meant. Two
// records with two ids says it once, in the `fedRole` attribute, and the
// console lists them side by side.
//
// ---------------------------------------------------------------------------
// THE STORE IS THE DIRECTORY, exactly as `../common/applications.js`'s is.
//
// `ou=federations,<base>` IS the register. There is no Map in this file
// shadowing it; every function below is a directory read or write. That gives
// an `ldapmodify` for free — changing `fedSigningCertificate` on an entry
// changes which signer the next assertion is verified against — and it is the
// same one-store rule that keeps the RFC 7591 registrations in
// `ou=applications` rather than in a second map inside `oauth2.js`.
//
// **WHAT IT DELIBERATELY DOES NOT HOLD is anything the applications registry
// already holds.** An identity-provider-side relationship names an application
// by its identifier (`fedApplication`) and stops. That partner's entityID, its
// assertion consumer service, its redirect URIs and its signing certificate
// are on the `ou=applications` entry, where every protocol module already reads
// them — copying them here would be the two-stores failure this whole
// repository is arranged to avoid, and the copy would be the one an operator
// edited.
//
// The service-provider side is the opposite case and holds everything, because
// there is nothing on the other side to hold it: the partner is a foreign
// identity provider, and a foreign identity provider is not an application.
// `ou=applications` is "what this service has been ASKED ABOUT" — a party that
// asks this service for nothing has no business being in it.
//
// ---------------------------------------------------------------------------
// THE RELEASE FILTER, AND WHY IT IS NARROW ON PURPOSE.
//
// `releaseFilterFor(context)` is consulted by `admin_stats.js` at its two
// existing funnels — `jwtClaims()` and `samlAttributes()` — and by nothing
// else. What it can remove is exactly what those two functions ADD: the typed
// claims, the directory-attribute claims and the groups claim. It cannot
// remove `sub`, `iss`, `exp`, a NameID or anything else a protocol module puts
// in a token itself, and that is not a limitation to fix later:
//
//   * those are the protocol's own, not attributes about a person, and a
//     partner-specific `exp` is a lifetime rather than a release rule;
//   * every one of them is what makes the artifact verifiable at all, so a
//     release list that could drop `iss` would be a form producing assertions
//     that fail to verify with nothing pointing back at the page — which is the
//     exact argument `setClaimSet()` already makes for refusing the reserved
//     names on the way IN.
//
// A relationship with NO release list declared filters nothing. That is the
// difference between "release nothing to this partner" and "this partner has
// no release policy", and they must not be the same state: the second is what
// every partner is on the day it is created, and treating it as the first
// would mean registering a partner silently stopped it receiving the
// attributes it received the day before.
//
// ---------------------------------------------------------------------------
// IT IS A LIBRARY (rule 3) AND ITS DIRECTORY HALF IS INVERTED (rule 6).
//
// It registers no route. It requires `helpers.js`, `config.js` and `audit.js`
// and nothing else in this repository, which is what lets `admin_stats.js`,
// `authn/authn.js`, `admin-ui/admin.js` and `federation_sp.js` all require it
// in the ordinary direction with no cycle and no route moved. Do not let it
// grow a require of anything that registers a route.
//
// The DIRECTORY half is inverted for `applications.js`'s reason: `ldap_server.js`
// is near the end of the require order because requiring it pulls every `/ldap`
// route into the router at that point, and a module the sign-in screen reads
// cannot drag those routes to the front. So this file offers `setDirectory()`
// and that module fills it at ITS require time.
//
// The division of labour is the same one and worth keeping: THIS module owns
// the SCHEMA and both conversions, and that module owns the directory
// mechanics — where the container is, how an entry is created, what the cap is.
//
// ---------------------------------------------------------------------------
// THE CLIENT SECRET AND THE CERTIFICATE ARE STORED, AND THEY ARE NOT THE SAME
// KIND OF THING.
//
// `fedClientSecret` is OUR credential AT THE PARTNER — a real secret at a real
// foreign service, which is a stronger statement than anything else in this
// directory: `oauthClientSecret` is a secret this service minted for a mock
// client and can mint again, and this one is not ours to regenerate. It is
// held in the clear for the reason that attribute's header gives, it is marked
// `sensitive` so no page prints it and no audit row carries it, and the honest
// consequence is stated here rather than buried: anybody who can read this
// directory can authenticate as this service at that partner. A deployment
// that federates with something real should say so out loud.
//
// `fedSigningCertificate` is the opposite — the partner's PUBLIC key, worth
// nothing to whoever reads it, and it is the single most important attribute
// on a service-provider-side entry because it is the ONE thing standing
// between this service and the hole described at the top of this file.
// ===========================================================================

const crypto = require('crypto');
const config = require('./../common/config');
const { log, nowSec, randomId } = require('./../common/helpers');
const audit = require('./../common/audit');

// ---------------------------------------------------------------------------
// THE TWO ROLES. Which end of the relationship THIS SERVICE is.
//
// Named for what this service does rather than for what the partner does,
// because every page and every log line here is written from this service's
// point of view and "identity provider" meaning "them" on one screen and "us"
// on the next is the ambiguity this vocabulary exists to remove.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// THE PATHS, HERE RATHER THAN IN `federation_sp.js` WHERE THEY ARE SERVED.
//
// Three things need them and only one of them may require that module.
// `federation_sp.js` registers routes, so `admin-ui/admin.js` must not require
// it — `server.js` loads that module BEFORE the console, and a require in the
// other direction would be the reason a route moved the day somebody reorders
// the two (the line already drawn around `spiffe_server.js`). But the console
// page's whole job is to tell an operator WHICH URL to configure at the
// partner, so it has to know.
//
// So the strings live in the library both sides may reach, and neither writes
// them out. A console printing `/federation/acs/x` while the router serves
// `/federation/callback/x` is the single most expensive mistake this feature
// could make: the person configures the wrong URL at the partner, signs in
// successfully somewhere else, and lands on a 404 with nothing to point at.
// ---------------------------------------------------------------------------
const PATHS = {
  base: '/federation',
  login: '/federation/login',
  acs: '/federation/acs',
  metadata: '/federation/metadata'
};

const ROLES = [
  { role: 'service-provider', label: 'This service is the service provider',
    short: 'Service provider',
    what: 'A FOREIGN identity provider authenticates the person and this ' +
          'service consumes what it issues. This is the direction that ' +
          'creates directory entries for people this service has never seen, ' +
          'and the direction that cannot be permissive: an assertion is ' +
          'refused unless it verifies against the key on this relationship.' },
  { role: 'identity-provider', label: 'This service is the identity provider',
    short: 'Identity provider',
    what: 'This service authenticates the person and a FOREIGN service ' +
          'provider consumes what it issues. Every protocol endpoint here ' +
          'already does that for any caller — what the relationship adds is ' +
          'the partner being marked as a federation partner rather than a ' +
          'test client, and a list of which attributes are released to it.' }
];

const ROLE_IDS = ROLES.map(function (one) { return one.role; });

// ---------------------------------------------------------------------------
// THE FIVE PROTOCOLS. Closed on purpose, for the reason applications.js's KINDS
// list is closed: a typo that silently became a sixth protocol is how a page
// comes to offer `oidc` and `openid-connect` as two things.
//
// `consumes` and `asserts` say which ROLES a protocol can take here. All five
// can do both, which is worth stating rather than leaving to be inferred — it
// is the reason the form is one form with a role select rather than two forms.
//
// `needs` is what a relationship of this protocol in the SERVICE PROVIDER role
// must carry before it can be enabled. It is read by `readyFor()` below and by
// nothing else, so the rule a form enforces and the rule the endpoint enforces
// are one list rather than two.
// ---------------------------------------------------------------------------
const PROTOCOLS = [
  { protocol: 'saml2', label: 'SAML 2.0', family: 'SAML 2.0',
    what: 'The Web Browser SSO profile. This service sends an <AuthnRequest> ' +
          'to the partner and consumes the <Response> at its assertion ' +
          'consumer service, or issues one to the partner from /saml2.',
    needs: ['fedSsoUrl', 'fedSigningCertificate'],
    spec: 'saml-profiles-2.0-os section 4.1' },
  { protocol: 'saml11', label: 'SAML 1.1', family: 'SAML 1.1',
    what: 'The Browser/POST profile. THERE IS NO REQUEST MESSAGE — a SAML 1.1 ' +
          'flow is identity-provider-initiated, so what this service sends the ' +
          'browser to is an inter-site transfer URL carrying a TARGET, and what ' +
          'comes back is a <Response> with no InResponseTo to match. See the ' +
          'note about replay on fedNonce below.',
    needs: ['fedSsoUrl', 'fedSigningCertificate'],
    spec: 'saml-profiles-1.1 section 4.1' },
  { protocol: 'wsfed', label: 'WS-Federation 1.2', family: 'WS-Federation',
    what: 'The passive requestor profile. This service sends wa=wsignin1.0 ' +
          'with its own wtrealm and consumes the wresult, which carries a ' +
          'SAML 1.1 or SAML 2.0 assertion inside an RSTR.',
    needs: ['fedSsoUrl', 'fedSigningCertificate'],
    spec: 'WS-Federation 1.2 section 13' },
  { protocol: 'oidc', label: 'OpenID Connect', family: 'OAuth 2.0 / OIDC',
    what: 'The authorization code flow by default, and response_type=id_token ' +
          'with response_mode=form_post where there is to be no back channel ' +
          'at all. The attributes come off the ID Token, and off UserInfo ' +
          'where one is configured.',
    needs: ['fedSsoUrl', 'fedClientId'],
    spec: 'OpenID Connect Core 1.0 section 3' },
  { protocol: 'oauth2', label: 'OAuth 2.0', family: 'OAuth 2.0 / OIDC',
    what: 'The authorization code flow with NO ID Token — the attributes come ' +
          'off the access token where it is a JWT, and off a configured ' +
          'userinfo-shaped endpoint otherwise. It is a distinct protocol here ' +
          'rather than OIDC with a flag because what identifies the person is ' +
          'a different artifact, and getting that wrong is the whole of what ' +
          'goes wrong when people use OAuth 2.0 for authentication.',
    needs: ['fedSsoUrl', 'fedTokenUrl', 'fedClientId'],
    spec: 'RFC 6749 section 4.1' }
];

const PROTOCOL_IDS = PROTOCOLS.map(function (one) { return one.protocol; });

function protocolRow(id) {
  const wanted = String(id || '');
  for (let i = 0; i < PROTOCOLS.length; i++) {
    if (PROTOCOLS[i].protocol === wanted) return PROTOCOLS[i];
  }
  return null;
}

function roleRow(id) {
  const wanted = String(id || '');
  for (let i = 0; i < ROLES.length; i++) {
    if (ROLES[i].role === wanted) return ROLES[i];
  }
  return null;
}

// Which protocol family a relationship belongs to, for the audit log and for
// the application record an identity-provider-side relationship points at. One
// function so the four spellings cannot drift.
function familyOf(protocolId) {
  const row = protocolRow(protocolId);
  return row ? row.family : String(protocolId || 'unstated');
}

// ---------------------------------------------------------------------------
// THE SCHEMA.
//
// One row per attribute and the row is the whole definition, exactly as
// `applications.js`'s is: `GET /ldap/federations` publishes this table, the
// console builds its forms from it, `ldap_server.js` writes the entry from it,
// and there is no second list anywhere. An attribute that is not here is not
// written.
//
// `single` vs `multi` is load-bearing rather than descriptive — a multi-valued
// attribute ACCUMULATES and a single-valued one is ASSIGNED — and getting it
// backwards on a counter produces an entry with fifty `fedAuthentications`
// values, which is the visible symptom of a bug nobody can locate.
//
// `role` on a row says which direction the attribute is FOR. It is what stops
// the console offering a token endpoint on a relationship where this service
// is the one issuing the token, and it is read by `fieldsForRole()` rather
// than by any form directly.
// ---------------------------------------------------------------------------
const SCHEMA = {
  objectClasses: [
    { name: 'top', where: 'RFC 4512', standard: true,
      what: 'The abstract class every entry carries.' },
    { name: 'applicationProcess', where: 'RFC 4519 section 3.3', standard: true,
      what: 'The same registered class ou=applications uses, and for the same ' +
            'reason: it is the one that fits a party in a protocol at all, and ' +
            'it brings cn, description, seeAlso, ou and l with it.' },
    { name: 'stsFederation', where: 'this service', standard: false,
      what: 'INVENTED. No registered LDAP schema has a federation partner, ' +
            'because every product that stores one (AD FS, Shibboleth, ' +
            'Keycloak, Ping) keeps it in its own database. These are this ' +
            'service\'s own names in the way stsApplication\'s already are.' }
  ],
  attributes: [
    // --- identity ---------------------------------------------------------
    { name: 'fedId', kind: 'single', role: 'both', from: 'this register',
      what: 'THE KEY: a short name an operator chose, unique across both ' +
            'roles. It is the RDN as well, unlike an application\'s, because ' +
            'this register is CONFIGURED rather than observed — nobody has to ' +
            'accept whatever a protocol presented, so the id can simply be ' +
            'required to be RDN-safe and short.' },
    { name: 'cn', kind: 'single', role: 'both', standard: true,
      from: 'this register',
      what: 'The RDN value, equal to fedId. Unlike an application entry there ' +
            'is no digest case here: an id that would not fit is refused at ' +
            'creation rather than hashed.' },
    { name: 'fedName', kind: 'single', role: 'both', from: 'this register',
      what: 'What to call the partner on a page. The id is the name when none ' +
            'is given, because inventing a friendly name would be inventing a ' +
            'fact.' },
    { name: 'fedRole', kind: 'single', role: 'both', from: 'this register',
      what: 'WHICH END THIS SERVICE IS: service-provider (it consumes) or ' +
            'identity-provider (it asserts). One relationship is one ' +
            'direction — see the header.' },
    { name: 'fedProtocol', kind: 'single', role: 'both', from: 'this register',
      what: 'One of saml2, saml11, wsfed, oidc, oauth2.' },
    { name: 'fedPeer', kind: 'single', role: 'both', from: 'this register',
      what: 'THE PARTNER\'S OWN IDENTIFIER, in whatever its protocol calls it: ' +
            'a SAML entityID, an OpenID Connect issuer, a WS-Federation ' +
            'wtrealm. On a service-provider-side relationship it is CHECKED — ' +
            'an assertion whose Issuer is not this string is refused — which ' +
            'is why it is not merely documentation.' },
    { name: 'fedEnabled', kind: 'single', role: 'both', from: 'this register',
      what: 'TRUE/FALSE. A relationship is created DISABLED and nothing about ' +
            'it does anything until it is turned on: a half-configured ' +
            'partner that silently accepted assertions would be the failure ' +
            'this whole register exists to prevent.' },
    { name: 'description', kind: 'multi', role: 'both', standard: true,
      from: 'this register',
      what: 'One line per thing that has happened to this relationship.' },

    // --- the service provider half: what this service CONSUMES ------------
    { name: 'fedSsoUrl', kind: 'single', role: 'service-provider',
      from: 'this register',
      what: 'WHERE THE BROWSER IS SENT. The partner\'s SAML Single Sign-On ' +
            'service, its SAML 1.1 inter-site transfer service, its ' +
            'WS-Federation passive endpoint, or its OAuth 2.0 authorization ' +
            'endpoint. Required in every protocol, because a relationship ' +
            'with nowhere to send anybody cannot begin.' },
    { name: 'fedTokenUrl', kind: 'single', role: 'service-provider',
      from: 'this register',
      what: 'The partner\'s token endpoint, for the authorization code flow. ' +
            'THIS IS ONE OF THE TWO URLS THIS SERVICE WILL ACTUALLY DIAL — ' +
            'see federation_http.js, which is the only outbound request in ' +
            'this repository and argues why a configured URL is a different ' +
            'thing from a registered one.' },
    { name: 'fedUserinfoUrl', kind: 'single', role: 'service-provider',
      from: 'this register',
      what: 'The partner\'s UserInfo endpoint, or any endpoint that answers ' +
            'JSON about the bearer of an access token. OPTIONAL for OIDC, ' +
            'where the ID Token usually carries enough, and the ONLY source ' +
            'of attributes for a plain OAuth 2.0 partner whose access token ' +
            'is opaque. The second URL this service will dial.' },
    { name: 'fedJwksUri', kind: 'single', role: 'service-provider',
      from: 'this register',
      what: 'The partner\'s JWKS. FETCHED — which is the exact opposite of ' +
            'what oauthJwksUri on an application entry does, and the ' +
            'difference is the whole argument in federation_http.js: that one ' +
            'is a URL an unauthenticated caller REGISTERED, this one is a URL ' +
            'an administrator CONFIGURED. Leave it empty and paste the keys ' +
            'into fedJwks instead if this service is not to make the call.' },
    { name: 'fedJwks', kind: 'single', role: 'service-provider',
      from: 'this register',
      what: 'The partner\'s public keys as a JWKS document, verbatim. Read ' +
            'BEFORE fedJwksUri and never refreshed, so a relationship ' +
            'carrying this makes no outbound request for keys at all.' },
    { name: 'fedSigningCertificate', kind: 'single', role: 'service-provider',
      from: 'this register',
      what: 'THE PARTNER\'S SIGNING CERTIFICATE, base64 DER — the same ' +
            'spelling a ds:X509Certificate carries and the same one ' +
            'samlSigningCertificate uses on an application entry, so one ' +
            'certificate has one spelling across this service. It is what ' +
            'every SAML and WS-Federation assertion is verified against, and ' +
            'it is the single attribute standing between this service and an ' +
            'endpoint anybody could assert anything at.' },
    { name: 'fedClientId', kind: 'single', role: 'service-provider',
      from: 'this register',
      what: 'THIS SERVICE\'S client_id AT THE PARTNER. Ours, issued by them — ' +
            'not to be confused with an oauthClientId on an application ' +
            'entry, which is a mock client\'s id here.' },
    { name: 'fedClientSecret', kind: 'single', role: 'service-provider',
      sensitive: true, from: 'this register',
      what: 'THIS SERVICE\'S SECRET AT THE PARTNER, in the clear, in a ' +
            'directory where every bind succeeds. It is a REAL credential at ' +
            'a REAL foreign service, which is a stronger statement than ' +
            'anything else in this directory — see the header. Never written ' +
            'to the audit log and never printed on a page.' },
    { name: 'fedScope', kind: 'single', role: 'service-provider',
      from: 'this register',
      what: 'The scope asked of the partner. `openid profile email` is the ' +
            'default for an OIDC relationship and there is no default for an ' +
            'OAuth 2.0 one, because what an OAuth 2.0 authorization server ' +
            'will give you is entirely local to it.' },
    { name: 'fedResponseType', kind: 'single', role: 'service-provider',
      from: 'this register',
      what: 'code (the default) or id_token. `id_token` with form_post is the ' +
            'shape that needs NO back channel and therefore no token ' +
            'endpoint, no client secret and no outbound request — which is ' +
            'the only way to federate with an OIDC partner from a deployment ' +
            'that has no egress at all.' },
    { name: 'fedBinding', kind: 'single', role: 'service-provider',
      from: 'this register',
      what: 'Which binding the outbound SAML AuthnRequest goes on: ' +
            'HTTP-Redirect (the default, and what every identity provider ' +
            'supports) or HTTP-POST. It says nothing about the response, ' +
            'which arrives on whatever binding the partner sends it on and is ' +
            'accepted on all of them.' },
    { name: 'fedSignRequest', kind: 'single', role: 'service-provider',
      from: 'this register',
      what: 'Sign the outbound AuthnRequest with THIS service\'s key. OFF by ' +
            'default: most identity providers do not require it, and a ' +
            'partner that does will refuse the request in a way that names ' +
            'the problem. When it is on, the certificate to configure at the ' +
            'partner is the one on this service\'s own SAML metadata.' },
    { name: 'fedUsernameSource', kind: 'single', role: 'service-provider',
      from: 'this register',
      what: 'WHICH INCOMING VALUE BECOMES THE LOCAL USERNAME — a claim name ' +
            'for OIDC/OAuth 2.0, a SAML Attribute Name for the others. Empty ' +
            'means the subject itself: the NameID, or `sub`. This is the one ' +
            'mapping decision that cannot be got wrong quietly, because it ' +
            'decides which directory entry a person lands on.' },
    { name: 'fedAttributeMap', kind: 'multi', role: 'service-provider',
      from: 'this register',
      what: 'ONE VALUE PER MAPPING, written `<incoming name>=<LDAP ' +
            'attribute>`. What is NOT listed here still arrives — ' +
            'federation_map.js has a default table covering the ordinary ' +
            'OIDC claims, the SAML urn:oid: names and the WS-Federation claim ' +
            'URIs — so this is for the partner\'s own inventions rather than ' +
            'for the names everybody uses.' },
    { name: 'fedAutocreateUsers', kind: 'single', role: 'service-provider',
      from: 'this register',
      what: 'Create a directory entry for a person this partner ' +
            'authenticates. ON by default, because it is the point of the ' +
            'feature; OFF gives a session and no entry, which is how to watch ' +
            'what a federated sign-in does WITHOUT filling ou=users up.' },
    { name: 'fedAllowUnsolicited', kind: 'single', role: 'service-provider',
      from: 'this register',
      what: 'Accept a response this service did not ask for — SAML 2.0\'s ' +
            'unsolicited Response, and SAML 1.1\'s ONLY mode of operation. ' +
            'OFF by default for SAML 2.0 and forced ON for SAML 1.1, because ' +
            'that profile has no request to be in response to. Turning it on ' +
            'for SAML 2.0 removes the InResponseTo check, which is worth ' +
            'knowing rather than worth hiding.' },

    // --- the identity provider half: what this service ASSERTS ------------
    { name: 'fedApplication', kind: 'single', role: 'identity-provider',
      from: 'this register',
      what: 'THE POINTER, and the whole of what this side stores about the ' +
            'partner: the identifier of its entry in ou=applications. Its ' +
            'entityID, its assertion consumer service, its redirect URIs and ' +
            'its certificate live THERE, where every protocol module already ' +
            'reads them. Copying any of them here would be the two-stores ' +
            'failure this repository is arranged to avoid.' },
    { name: 'fedRelease', kind: 'multi', role: 'identity-provider',
      from: 'this register',
      what: 'WHICH ATTRIBUTES ARE RELEASED TO THIS PARTNER, by claim or ' +
            'attribute name. It FILTERS what /admin/claims, ' +
            '/admin/saml-attributes and the groups claim would otherwise put ' +
            'in an artifact for this audience, and it can touch nothing else ' +
            '— not sub, not iss, not exp, not a NameID. NO VALUES HERE MEANS ' +
            'NO POLICY, not release nothing; see the header, where the ' +
            'difference is argued.' },

    // --- what has happened ------------------------------------------------
    { name: 'fedFirstSeen', kind: 'single', role: 'both', from: 'this register',
      what: 'GeneralizedTime: when this relationship was first USED, which is ' +
            'not when it was created.' },
    { name: 'fedLastSeen', kind: 'single', role: 'both', from: 'this register',
      what: 'GeneralizedTime, the most recent use.' },
    { name: 'fedAuthentications', kind: 'single', role: 'both',
      from: 'this register',
      what: 'How many credentials have crossed this relationship. ASSIGNED on ' +
            'every change — a counter that accumulated values would be ' +
            'nonsense — and it is a live number in a directory entry, which a ' +
            'real directory would not hold.' },
    { name: 'fedUsers', kind: 'single', role: 'both', from: 'this register',
      what: 'How many distinct identities have crossed it. Counted against ' +
            'fedLastUser, so it counts a CHANGE of user rather than a set: ' +
            'right for the ordinary case and an undercount for somebody ' +
            'alternating between two partners. Stated here because it is a ' +
            'number on a page.' },
    { name: 'fedLastUser', kind: 'single', role: 'both', from: 'this register',
      what: 'The most recent identity. On the entry rather than in memory ' +
            'because the entry is the store.' },
    { name: 'fedLastError', kind: 'single', role: 'both', from: 'this register',
      what: 'WHY THE LAST ATTEMPT FAILED, in this service\'s own words. It is ' +
            'the most useful attribute here and it is why refusals are ' +
            'recorded rather than only logged: a federation that does not ' +
            'work fails at somebody else\'s service, and "the signature did ' +
            'not verify against the configured certificate" is the sentence ' +
            'that ends the argument about whose end is broken.' },
    { name: 'fedLastErrorAt', kind: 'single', role: 'both', from: 'this register',
      what: 'GeneralizedTime for the line above. Separate, so that an old ' +
            'error beside a recent success reads as history rather than as ' +
            'the current state.' }
  ]
};

// ---------------------------------------------------------------------------
// WHAT A CONSOLE MAY CHANGE, which is a different question from what an entry
// carries — the same DERIVED-versus-DECLARED split `applications.js` draws, and
// it lands differently here because almost everything on these entries is
// declared.
//
// Everything a relationship is CONFIGURED with is editable. The six counters
// and the two error fields are not: a form that could rewrite them would make
// this page lie about what actually happened, and the lie would be
// indistinguishable from a bug in the recording.
//
// `fedId`, `fedRole` and `fedProtocol` are NOT editable either, and that is a
// third category rather than an oversight. They are the entry's identity: the
// id is the RDN, and the role and the protocol decide which of the fields
// above even apply. Changing one of them on an existing entry would leave a
// SAML relationship carrying a token endpoint, which no form could then draw.
// Delete it and make another; there is no state to lose but the counters.
//
// LDAP can still change every one of them, exactly as it can on an application
// entry, and that is the same line: an operator with an ldapmodify is doing
// something deliberate.
// ---------------------------------------------------------------------------
const EDITABLE = {
  fedName: 'set',
  fedPeer: 'set',
  fedEnabled: 'set',
  fedSsoUrl: 'set',
  fedTokenUrl: 'set',
  fedUserinfoUrl: 'set',
  fedJwksUri: 'set',
  fedJwks: 'set',
  fedSigningCertificate: 'set',
  fedClientId: 'set',
  fedClientSecret: 'set',
  fedScope: 'set',
  fedResponseType: 'set',
  fedBinding: 'set',
  fedSignRequest: 'set',
  fedUsernameSource: 'set',
  fedAutocreateUsers: 'set',
  fedAllowUnsolicited: 'set',
  fedApplication: 'set',
  fedAttributeMap: 'multi',
  fedRelease: 'multi',
  description: 'multi'
};

SCHEMA.attributes.forEach(function (row) {
  row.editable = EDITABLE[row.name] || false;
});

const ATTRIBUTE_BY_NAME = {};
SCHEMA.attributes.forEach(function (row) { ATTRIBUTE_BY_NAME[row.name] = row; });

// Every attribute that applies to a relationship in this role, in schema order.
// The console draws its form from this and the action validates against the
// same call, which is what stops a form offering a field the action refuses.
function fieldsForRole(role, mode) {
  log.debug('Entering fieldsForRole(). role=' + role + ', mode=' + (mode || 'any'));
  const wanted = String(role || '');
  const rows = SCHEMA.attributes.filter(function (row) {
    if (row.role !== 'both' && row.role !== wanted) return false;
    if (mode) return row.editable === mode;
    return !!row.editable;
  });
  log.debug('Leaving fieldsForRole(). ' + rows.length + ' field(s).');
  return rows;
}

function editableFields(mode) {
  return SCHEMA.attributes.filter(function (row) {
    return mode ? row.editable === mode : !!row.editable;
  });
}

// ---------------------------------------------------------------------------
// THE STORE IS THE DIRECTORY. These are the only ways in and out of it.
//
// `ldap_server.js` fills this at its require time with the same five functions
// the applications registry takes, and the two directions are DELIBERATELY NOT
// SYMMETRICAL for the reason stated there: a WRITE speaks in attribute objects
// because that is all a record has to say, and a READ hands back the whole
// ENTRY because THE DN IS NOT AN ATTRIBUTE.
//
// Without the directory there is no register. It does NOT fall back to a Map:
// a fallback store is a second store, and it would be the one that silently
// disagreed. It says so once in the log and every function below answers empty
// — which means a deployment that never required ldap_server.js has no
// federation, and the sign-in screen simply shows no partners.
// ---------------------------------------------------------------------------
let directory = null;
let warnedAboutNoDirectory = false;

function setDirectory(fns) {
  log.debug('Entering setDirectory().');
  directory = fns || null;
  log.debug('Leaving setDirectory(). The register ' +
            (directory ? 'has its container.' : 'has none.'));
}

function haveDirectory() {
  if (directory) return true;
  if (!warnedAboutNoDirectory) {
    warnedAboutNoDirectory = true;
    log.warn('federation: the embedded directory was never loaded, so there is ' +
             'no ou=federations to hold a relationship. Every federation ' +
             'function answers empty and no partner appears on the sign-in ' +
             'screen. This is the ordinary state of an in-process test that ' +
             'requires only app.js and one protocol module; it is not a ' +
             'failure and there is no fallback store, deliberately.');
  }
  return false;
}

// ---------------------------------------------------------------------------
// A RECORD, AND THE TWO CONVERSIONS THIS MODULE OWNS.
//
// The record is the shape everything above the directory speaks in: a plain
// object with the schema's attribute names as members, single-valued ones
// holding a string and multi-valued ones holding an array. `attributesFor()`
// turns one into what the directory writes and `recordFromAttributes()` turns
// an entry back into one.
//
// EMPTY IS NOT WRITTEN. An attribute with no value is left off the entry
// rather than written as an empty string, because `ldapsearch` shows an empty
// attribute and a reader cannot tell it from a configured blank — and on
// `fedSigningCertificate` those two states are "not configured" and
// "configured to trust nothing", which must not look alike.
// ---------------------------------------------------------------------------
function attributesFor(record) {
  log.debug('Entering attributesFor(). id=' + (record && record.fedId));
  const out = {
    objectClass: ['top', 'applicationProcess', 'stsFederation']
  };
  SCHEMA.attributes.forEach(function (row) {
    if (row.name === 'objectClass') return;
    const value = record[row.name];
    if (value == null) return;
    if (row.kind === 'multi') {
      const values = (Array.isArray(value) ? value : [value])
        .map(function (one) { return String(one); })
        .filter(function (one) { return one !== ''; });
      if (values.length) out[row.name] = values;
      return;
    }
    const single = String(value);
    if (single !== '') out[row.name] = [single];
  });
  log.debug('Leaving attributesFor(). ' + Object.keys(out).length + ' attribute(s).');
  return out;
}

// LDAP attribute names are case-insensitive and the directory hands them back
// canonically spelled, but a caller that has been through an `ldapmodify` may
// have any casing at all. One lookup function, so that a record read back
// through the console and one read back through the register are the same
// record.
function byLowerName(attributes, name) {
  const wanted = String(name).toLowerCase();
  const keys = Object.keys(attributes || {});
  for (let i = 0; i < keys.length; i++) {
    if (keys[i].toLowerCase() === wanted) return attributes[keys[i]];
  }
  return undefined;
}

function recordFromAttributes(attributes) {
  const record = {};
  SCHEMA.attributes.forEach(function (row) {
    const values = byLowerName(attributes, row.name);
    if (values === undefined) {
      record[row.name] = row.kind === 'multi' ? [] : '';
      return;
    }
    const list = (Array.isArray(values) ? values : [values])
      .map(function (one) { return String(one); });
    record[row.name] = row.kind === 'multi' ? list : (list[0] || '');
  });
  return record;
}

// TRUE/FALSE on an entry, read the way every other boolean attribute in this
// directory is read. It is a STRING in LDAP, so `'FALSE'` is truthy in
// JavaScript and a naive read makes every relationship enabled — which is the
// one bug in this file that would be silent and would matter.
function boolOf(value, dflt) {
  const text = String(value == null ? '' : value).trim().toUpperCase();
  if (text === 'TRUE' || text === 'YES' || text === '1' || text === 'ON') return true;
  if (text === 'FALSE' || text === 'NO' || text === '0' || text === 'OFF') return false;
  return !!dflt;
}

function boolText(value) {
  return value ? 'TRUE' : 'FALSE';
}

function generalizedTime(ms) {
  const d = ms ? new Date(ms) : new Date();
  const pad = function (n, w) { return String(n).padStart(w || 2, '0'); };
  return d.getUTCFullYear() + pad(d.getUTCMonth() + 1) + pad(d.getUTCDate()) +
    pad(d.getUTCHours()) + pad(d.getUTCMinutes()) + pad(d.getUTCSeconds()) + 'Z';
}

// ---------------------------------------------------------------------------
// THE ID.
//
// It is the RDN, so it has to be safe in one; it appears in a URL
// (`/federation/login/<id>`), so it has to be safe in one of those too; and it
// is short because it is a label on a button. All three are enforced HERE
// rather than at the three doors, so the console, the management API and an
// `ldapadd` cannot disagree about what an id is.
//
// An `ldapadd` can still create `cn=a+b,ou=federations` with the escaping
// written out by hand, which is the same line `applications.js` draws between
// what a door offers and what it merely does not prevent. Such an entry is
// listed and is never matched by `get()`, which is the honest outcome: the
// register found something it cannot address.
// ---------------------------------------------------------------------------
const ID_SHAPE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$/;

function idProblem(id) {
  const text = String(id == null ? '' : id).trim();
  if (!text) return 'Name the relationship. An id is required — it is the key, the RDN and the URL segment.';
  if (!ID_SHAPE.test(text)) {
    return 'The id "' + text + '" will not do. It has to start with a letter or a digit and ' +
           'hold only letters, digits, dot, dash and underscore, up to 63 characters — it is ' +
           'an RDN and a URL segment as well as a key.';
  }
  return '';
}

// ---------------------------------------------------------------------------
// READING THE REGISTER.
// ---------------------------------------------------------------------------
function list() {
  log.debug('Entering list().');
  if (!haveDirectory()) {
    log.debug('Leaving list(). There is no directory.');
    return [];
  }
  const rows = directory.allFederations().map(function (entry) {
    const record = recordFromAttributes(entry.attributes);
    record.dn = entry.dn;
    record.createdAt = entry.createdAt || '';
    record.modifiedAt = entry.modifiedAt || '';
    record.entry = entry;
    return record;
  });
  // By id, so the console's list, the management API's list and an ldapsearch
  // in tree order are three views of one order rather than three orders.
  rows.sort(function (a, b) { return String(a.fedId).localeCompare(String(b.fedId)); });
  log.debug('Leaving list(). ' + rows.length + ' relationship(s).');
  return rows;
}

function get(id) {
  log.debug('Entering get(). id=' + id);
  if (!haveDirectory()) {
    log.debug('Leaving get(). There is no directory.');
    return null;
  }
  const entry = directory.readFederation(String(id || ''));
  if (!entry) {
    log.debug('Leaving get(). Not here.');
    return null;
  }
  const record = recordFromAttributes(entry.attributes);
  record.dn = entry.dn;
  record.createdAt = entry.createdAt || '';
  record.modifiedAt = entry.modifiedAt || '';
  record.entry = entry;
  log.debug('Leaving get(). Found ' + record.dn + '.');
  return record;
}

function count() {
  return haveDirectory() ? directory.countFederations() : 0;
}

function containerDn() {
  return haveDirectory() ? directory.containerDn() : '';
}

function maxRelationships() {
  return haveDirectory() ? directory.maxFederations() : 0;
}

// ---------------------------------------------------------------------------
// IS THIS RELATIONSHIP USABLE?
//
// Two different questions and both of them are asked, which is why this
// returns a list of reasons rather than a boolean:
//
//   * ENABLED is what an operator decided.
//   * READY is whether the fields the protocol needs are actually filled in,
//     read off `PROTOCOLS[].needs` so the form's rule and the endpoint's rule
//     are one list.
//
// A relationship that is enabled and not ready is the interesting state and it
// is REPORTED rather than silently skipped: it is what somebody who has just
// half-configured a partner is looking at, and "nothing happened" is the worst
// possible answer for them.
// ---------------------------------------------------------------------------
function readinessOf(record) {
  log.debug('Entering readinessOf(). id=' + (record && record.fedId));
  const missing = [];
  if (!record) {
    log.debug('Leaving readinessOf(). There is no relationship.');
    return { ready: false, missing: ['the relationship does not exist'] };
  }
  if (record.fedRole === 'service-provider') {
    const row = protocolRow(record.fedProtocol);
    const needs = row ? row.needs : [];
    needs.forEach(function (name) {
      if (!String(record[name] || '').trim()) missing.push(name);
    });
    // The two OIDC shapes need different things and the difference is exactly
    // what fedResponseType selects, so it cannot be a static list on the
    // protocol row. `code` needs somewhere to redeem the code; `id_token`
    // needs a key to verify it with and needs no back channel at all.
    if (record.fedProtocol === 'oidc') {
      if (String(record.fedResponseType || 'code') === 'code') {
        if (!String(record.fedTokenUrl || '').trim()) missing.push('fedTokenUrl');
      } else if (!String(record.fedJwks || '').trim() &&
                 !String(record.fedJwksUri || '').trim()) {
        missing.push('fedJwks or fedJwksUri');
      }
    }
    // A JWT from an OAuth 2.0 partner is verified against a key like any
    // other, and an OPAQUE one cannot be read at all — so a plain OAuth 2.0
    // relationship needs either keys or a userinfo endpoint, and the message
    // says which two rather than naming one and leaving the other to be found.
    if (record.fedProtocol === 'oauth2' &&
        !String(record.fedJwks || '').trim() &&
        !String(record.fedJwksUri || '').trim() &&
        !String(record.fedUserinfoUrl || '').trim()) {
      missing.push('fedUserinfoUrl (or fedJwks / fedJwksUri, if the access token is a JWT)');
    }
  }
  if (record.fedRole === 'identity-provider' &&
      !String(record.fedApplication || '').trim()) {
    missing.push('fedApplication');
  }
  log.debug('Leaving readinessOf(). ' + (missing.length ? missing.length + ' field(s) missing.'
                                                        : 'Ready.'));
  return { ready: missing.length === 0, missing: missing };
}

function isEnabled(record) {
  return !!record && boolOf(record.fedEnabled, false);
}

function isUsable(record) {
  return isEnabled(record) && readinessOf(record).ready;
}

// Every relationship in one role, usable or not. The callers want different
// halves of that — the sign-in screen wants the usable ones and the console
// wants all of them — so the filter is the caller's rather than being baked in
// here, and there is one list function rather than two that could drift.
function inRole(role) {
  const wanted = String(role || '');
  return list().filter(function (record) { return record.fedRole === wanted; });
}

// What the sign-in screen offers: the service-provider-side relationships that
// would actually work if somebody clicked them. A button that led to a refusal
// would be worse than no button, which is why this is `isUsable` and not
// `isEnabled`.
function signInOptions() {
  log.debug('Entering signInOptions().');
  const rows = inRole('service-provider').filter(isUsable).map(function (record) {
    return {
      id: record.fedId,
      label: record.fedName || record.fedId,
      protocol: record.fedProtocol,
      protocolLabel: (protocolRow(record.fedProtocol) || {}).label || record.fedProtocol,
      peer: record.fedPeer
    };
  });
  log.debug('Leaving signInOptions(). ' + rows.length + ' partner(s) to offer.');
  return rows;
}

// ---------------------------------------------------------------------------
// THE RELEASE FILTER — the identity-provider half, and the only thing in this
// module anything outside `federation/` calls on the ISSUING path.
//
// `admin_stats.js` asks it, at `jwtClaims()` and `samlAttributes()`, with the
// context those two already build. It answers `null` for "no policy, change
// nothing" and a Set for "these names and no others".
//
// It looks the partner up by `client_id` FIRST and by `audience` second, and
// the order matters: an ID Token carries both, and the client_id is the exact
// identifier an application entry is filed under while the audience may be a
// space-joined list. A SAML context has only the audience, which is the
// entityID, and that is the application identifier for a service provider.
//
// IT MUST NOT THROW AND MUST NOT BE SLOW. It runs on every token and every
// assertion this service issues, so the early return for an empty register is
// the ordinary path and is deliberately the first line.
// ---------------------------------------------------------------------------
let releaseIndex = null;
let releaseIndexAt = 0;

// The index is rebuilt rather than kept up to date, on a short timer, and both
// halves of that are deliberate. Rebuilt, because there are four doors onto
// these entries — the console, the management API, an ldapmodify and an
// ldapadd — and only two of them come through this module, so an index this
// module maintained would be wrong exactly when somebody had just edited the
// entry by hand. On a timer, because the alternative is walking the register on
// every token issued. Five seconds is short enough that nobody testing a
// release list notices and long enough that a load test does not walk a
// directory per token.
const RELEASE_INDEX_TTL_MS = 5000;

function releaseIndexNow() {
  const now = Date.now();
  if (releaseIndex && now - releaseIndexAt < RELEASE_INDEX_TTL_MS) return releaseIndex;
  const index = new Map();
  inRole('identity-provider').forEach(function (record) {
    if (!isEnabled(record)) return;
    const application = String(record.fedApplication || '').trim();
    const names = (record.fedRelease || []).map(function (one) { return String(one).trim(); })
      .filter(function (one) { return one !== ''; });
    // NO VALUES MEANS NO POLICY. See the header: a partner registered with no
    // release list must receive exactly what it received the day before.
    if (!application || !names.length) return;
    index.set(application, { id: record.fedId, names: new Set(names) });
  });
  releaseIndex = index;
  releaseIndexAt = now;
  return index;
}

function releaseFilterFor(context) {
  const index = releaseIndexNow();
  if (!index.size) return null;
  const info = context || {};
  const clientId = String(info.client_id || '').trim();
  if (clientId && index.has(clientId)) return index.get(clientId);
  const audience = String(info.audience || '').trim();
  if (!audience) return null;
  if (index.has(audience)) return index.get(audience);
  // A JWT `aud` may be a list, joined with spaces by the context builder. Each
  // member is tried, and the FIRST match wins rather than the union of them —
  // a token for two audiences with two release policies is a state nothing here
  // can resolve correctly, so it resolves it predictably and says so in the log
  // rather than quietly intersecting two lists.
  const parts = audience.split(/\s+/).filter(function (one) { return one !== ''; });
  if (parts.length < 2) return null;
  for (let i = 0; i < parts.length; i++) {
    if (index.has(parts[i])) {
      log.debug('releaseFilterFor(): the audience names ' + parts.length + ' parties and ' +
                parts[i] + ' has a release policy; it is the one applied.');
      return index.get(parts[i]);
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// WRITING.
// ---------------------------------------------------------------------------
function persist(record, why) {
  log.debug('Entering persist(). id=' + record.fedId);
  const ok = directory.writeFederation(record.fedId, attributesFor(record));
  log.debug('Leaving persist(). ' + (ok ? 'Written.' : 'Refused by the directory.'));
  return ok;
}

// The audit row for a change to a relationship. ONE function, because there are
// three doors (the console, the management API, this module's own counters) and
// three copies of this would be three rows that came to disagree about what a
// federation change is.
//
// NO VALUES ARE NAMED, only field names — the same rule every LDAP row here
// follows, and it matters more on these entries than on any other:
// `fedClientSecret` is a real credential at a real foreign service.
function recordChange(action, record, summary, detail) {
  audit.audit({
    action: action,
    actor: '',
    protocol: familyOf(record.fedProtocol),
    channel: 'internal',
    target: record.fedId,
    summary: summary,
    detail: Object.assign({
      id: record.fedId,
      role: record.fedRole,
      protocol: record.fedProtocol,
      peer: record.fedPeer || ''
    }, detail || {})
  });
}

// ---------------------------------------------------------------------------
// CREATE.
//
// Everything a relationship needs to EXIST is checked here; everything it needs
// to WORK is checked by readinessOf() and reported rather than refused. The
// split is deliberate and it is the same one `/admin/token-lifetimes` makes
// about a legal-but-surprising combination: a half-configured partner is a
// state somebody is passing through, and refusing to save it would mean
// configuring the whole thing in one form submission with no way to come back
// to it.
//
// WHAT IS REFUSED: a bad id, a duplicate id, an unknown role, an unknown
// protocol, and a full container. Nothing else.
//
// IT IS CREATED DISABLED whatever the caller asked for, and that is the one
// place this function overrides its input. See the header: the failure this
// register exists to prevent is a partner that half-exists and silently
// accepts. Enabling is a second, deliberate act.
// ---------------------------------------------------------------------------
function create(spec) {
  log.debug('Entering create(). id=' + (spec && spec.fedId));
  const info = spec || {};
  const errors = [];
  const id = String(info.fedId || info.id || '').trim();
  const problem = idProblem(id);
  if (problem) errors.push(problem);
  const role = String(info.fedRole || info.role || '').trim();
  if (ROLE_IDS.indexOf(role) === -1) {
    errors.push('Unknown role "' + role + '". The two are: ' + ROLE_IDS.join(', ') + '.');
  }
  const protocol = String(info.fedProtocol || info.protocol || '').trim();
  if (PROTOCOL_IDS.indexOf(protocol) === -1) {
    errors.push('Unknown protocol "' + protocol + '". The five are: ' +
                PROTOCOL_IDS.join(', ') + '.');
  }
  if (errors.length) {
    log.debug('Leaving create(). Refused: ' + errors.join(' '));
    return { ok: false, errors: errors };
  }
  if (!haveDirectory()) {
    log.debug('Leaving create(). There is no directory to write into.');
    return { ok: false,
             errors: ['There is no embedded directory loaded, so there is no ' +
                      'ou=federations to hold a relationship.'] };
  }
  if (get(id)) {
    log.debug('Leaving create(). It is already here.');
    return { ok: false,
             errors: ['A relationship called "' + id + '" is already registered. An id ' +
                      'names ONE relationship here, so the answer to "it is already ' +
                      'there" is to change what it holds rather than to create it twice.'] };
  }
  const record = recordFromAttributes({});
  record.fedId = id;
  record.cn = id;
  record.fedRole = role;
  record.fedProtocol = protocol;
  record.fedName = String(info.fedName || info.name || '').trim() || id;
  record.fedPeer = String(info.fedPeer || info.peer || '').trim();
  // See the header: DISABLED, whatever was asked for.
  record.fedEnabled = boolText(false);
  record.fedAuthentications = '0';
  record.fedUsers = '0';
  // The defaults that are a protocol's convention rather than this service's
  // preference, written onto the entry rather than applied at read time — so
  // that `ldapsearch` shows what will actually happen instead of showing
  // nothing and leaving the behaviour in this file.
  if (role === 'service-provider') {
    record.fedAutocreateUsers = boolText(true);
    record.fedSignRequest = boolText(false);
    if (protocol === 'saml2' || protocol === 'saml11') {
      record.fedBinding = 'HTTP-Redirect';
      // SAML 1.1 has no request, so there is nothing for a response to be in
      // response to and every response is unsolicited by definition. Written
      // onto the entry rather than special-cased at the endpoint, because a
      // reader of the entry should not have to know that.
      record.fedAllowUnsolicited = boolText(protocol === 'saml11');
    }
    if (protocol === 'oidc') {
      record.fedResponseType = 'code';
      record.fedScope = 'openid profile email';
    }
    if (protocol === 'oauth2') {
      record.fedResponseType = 'code';
    }
  }
  if (role === 'identity-provider') {
    record.fedApplication = String(info.fedApplication || info.application || '').trim();
  }
  // Phrased to need no indefinite article. "a OpenID Connect" and "an SAML
  // 2.0" are both wrong, and the usual a/an-by-first-letter rule produces
  // exactly those two — the article follows the SOUND, and three of these five
  // labels are initialisms.
  const note = 'registered as a federation relationship: ' +
    (protocolRow(protocol) || {}).label + ', with this service as the ' +
    String((roleRow(role) || {}).short || role).toLowerCase();
  record.description = [note];
  if (!persist(record)) {
    log.debug('Leaving create(). The directory refused it.');
    return { ok: false,
             errors: ['The directory would not hold another relationship: ' +
                      'ou=federations is at its maximum of ' + maxRelationships() +
                      ' (federation.max), or the directory itself is full.'] };
  }
  releaseIndex = null;
  recordChange('federation.create', record,
               'the federation relationship ' + id + ' was registered (' + note + ')',
               { enabled: false,
                 note: 'created disabled; a relationship does nothing until it is ' +
                       'enabled deliberately' });
  log.info('federation: registered ' + id + ' — ' + note + '. It is DISABLED and will ' +
           'do nothing until it is enabled.');
  const stored = get(id);
  log.debug('Leaving create(). ' + id + ' is registered.');
  return { ok: true, relationship: stored, readiness: readinessOf(stored) };
}

// ---------------------------------------------------------------------------
// UPDATE — one field at a time, in the mode the SCHEMA says.
//
// The mode is read from the attribute row and never from the caller, exactly as
// `applications.updateApplication()` reads it, and for the same reason: a `set`
// on a multi-valued attribute leaves the entry with one value where the schema
// promises a list, and the console and an `ldapmodify` then disagree about what
// the attribute holds.
// ---------------------------------------------------------------------------
function update(id, change) {
  log.debug('Entering update(). id=' + id + ', field=' + (change && change.field));
  const record = get(id);
  if (!record) {
    log.debug('Leaving update(). No such relationship.');
    return { ok: false, errors: ['There is no federation relationship called "' + id + '".'] };
  }
  const info = change || {};
  const field = String(info.field || info.attribute || '').trim();
  const row = ATTRIBUTE_BY_NAME[field];
  if (!row) {
    log.debug('Leaving update(). Unknown field.');
    return { ok: false,
             errors: ['"' + field + '" is not an attribute of a federation relationship. ' +
                      'GET /ldap/federations publishes the whole schema.'] };
  }
  if (!row.editable) {
    log.debug('Leaving update(). Not editable.');
    return { ok: false,
             errors: ['"' + field + '" is not editable here. ' +
                      (row.name === 'fedId' || row.name === 'fedRole' || row.name === 'fedProtocol'
                        ? 'It is part of the relationship\'s identity — delete it and make ' +
                          'another; there is no state to lose but the counters.'
                        : 'It records what HAPPENED, and a form that could rewrite it would ' +
                          'make this page lie about the service\'s own behaviour.') +
                      ' An ldapmodify can still change it.'] };
  }
  if (row.role !== 'both' && row.role !== record.fedRole) {
    log.debug('Leaving update(). Wrong role for this field.');
    return { ok: false,
             errors: ['"' + field + '" applies to a ' + row.role + '-side relationship, and ' +
                      id + ' is ' + record.fedRole + '-side. Nothing was changed.'] };
  }
  const value = String(info.value == null ? '' : info.value);
  const before = row.kind === 'multi' ? (record[field] || []).slice() : record[field];
  if (row.editable === 'multi') {
    const mode = String(info.mode || 'add');
    const values = (record[field] || []).slice();
    if (mode === 'remove') {
      const at = values.indexOf(value);
      if (at === -1) {
        log.debug('Leaving update(). There was no such value to remove.');
        return { ok: false, errors: ['"' + value + '" is not one of ' + field + '\'s values.'] };
      }
      values.splice(at, 1);
    } else {
      if (!value) {
        log.debug('Leaving update(). Nothing to add.');
        return { ok: false, errors: ['Give a value to add to ' + field + '.'] };
      }
      if (values.indexOf(value) !== -1) {
        log.debug('Leaving update(). It is already a value.');
        return { ok: false, errors: [field + ' already carries "' + value + '".'] };
      }
      values.push(value);
    }
    record[field] = values;
  } else {
    record[field] = value;
  }
  // The one field whose value is normalised rather than stored as typed, and
  // the reason is `saml2Action()`'s: what the schema holds is base64 DER, which
  // is what a ds:X509Certificate carries. A PEM pasted in here would be stored
  // as something no reader of the attribute expects, and nothing would say so
  // until the day an assertion failed to verify.
  if (field === 'fedSigningCertificate') {
    record[field] = String(record[field]).replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
  }
  // And the two booleans, so that `on`, `true`, `1` and a ticked checkbox all
  // reach the entry as the same string. Without this the entry holds whatever
  // the form posted and `boolOf()` has to guess.
  if (row.name === 'fedEnabled' || row.name === 'fedAutocreateUsers' ||
      row.name === 'fedSignRequest' || row.name === 'fedAllowUnsolicited') {
    record[field] = boolText(boolOf(record[field], false));
  }
  if (!persist(record)) {
    log.debug('Leaving update(). The directory refused the write.');
    return { ok: false, errors: ['The directory refused the write.'] };
  }
  releaseIndex = null;
  const stored = get(id);
  const readiness = readinessOf(stored);
  recordChange('federation.update', stored,
               field + ' was changed on the federation relationship ' + id,
               { field: field,
                 mode: row.editable === 'multi' ? String(info.mode || 'add') : 'set',
                 // NO VALUE. See recordChange(): fedClientSecret is among the
                 // fields that reach here.
                 sensitive: !!row.sensitive,
                 ready: readiness.ready,
                 missing: readiness.missing.join(', ') });
  log.info('federation: ' + field + ' changed on ' + id + '. It is ' +
           (isEnabled(stored) ? 'ENABLED' : 'disabled') + ' and ' +
           (readiness.ready ? 'ready.' : 'NOT ready — ' + readiness.missing.join(', ') +
            ' still to configure.'));
  log.debug('Leaving update(). ' + field + ' changed.');
  return { ok: true, relationship: stored, readiness: readiness,
           message: field + ' changed. ' +
             (isEnabled(stored)
               ? (readiness.ready
                   ? 'The relationship is enabled and ready.'
                   : 'The relationship is ENABLED but NOT READY: ' +
                     readiness.missing.join(', ') + ' still to configure. It will refuse ' +
                     'rather than half-work.')
               : 'The relationship is still disabled.') };
}

function remove(id) {
  log.debug('Entering remove(). id=' + id);
  const record = get(id);
  if (!record) {
    log.debug('Leaving remove(). No such relationship.');
    return { ok: false, errors: ['There is no federation relationship called "' + id + '".'] };
  }
  if (!directory.deleteFederation(record.fedId)) {
    log.debug('Leaving remove(). The directory would not delete it.');
    return { ok: false, errors: ['The directory would not delete ' + record.dn + '.'] };
  }
  releaseIndex = null;
  recordChange('federation.delete', record,
               'the federation relationship ' + id + ' was deleted',
               { dn: record.dn,
                 note: 'nothing else was deleted: the people this partner ' +
                       'authenticated keep their entries under ou=users, which is ' +
                       'the rule everywhere in this directory' });
  log.info('federation: deleted ' + id + '. The people it authenticated keep their ' +
           'entries — nothing here is ever deleted from ou=users.');
  log.debug('Leaving remove(). Gone.');
  return { ok: true,
           message: 'Deleted. The people this partner authenticated keep their entries ' +
                    'under ou=users — nothing is ever deleted from there — and any session ' +
                    'they hold is unaffected until it expires or is ended.' };
}

// ---------------------------------------------------------------------------
// THE COUNTERS.
//
// Called from `federation_sp.js` when a credential is ACCEPTED, and from
// nowhere else. It is the same rule `recordAuthentication()` follows and for
// the same reason: a row that meant "an assertion arrived" rather than "an
// assertion was believed" would make the number on the page meaningless.
//
// It cannot throw. A federation that worked must not be failed by a counter,
// which is the argument the JWT recorder and the user observer both make.
// ---------------------------------------------------------------------------
function recordUse(id, detail) {
  log.debug('Entering recordUse(). id=' + id);
  try {
    const record = get(id);
    if (!record) {
      log.debug('Leaving recordUse(). No such relationship.');
      return null;
    }
    const info = detail || {};
    const now = generalizedTime();
    record.fedFirstSeen = record.fedFirstSeen || now;
    record.fedLastSeen = now;
    record.fedAuthentications = String((parseInt(record.fedAuthentications, 10) || 0) + 1);
    const user = String(info.user || '').trim();
    if (user && user !== record.fedLastUser) {
      record.fedUsers = String((parseInt(record.fedUsers, 10) || 0) + 1);
      record.fedLastUser = user;
    }
    // A success CLEARS the last error, and that is worth the line: an error
    // left standing beside a rising success count is the state that sends
    // somebody to debug a problem they already fixed.
    record.fedLastError = '';
    record.fedLastErrorAt = '';
    persist(record);
    releaseIndex = null;
    log.debug('Leaving recordUse(). ' + record.fedAuthentications + ' so far.');
    return get(id);
  } catch (e) {
    log.error('federation: the register threw while recording a use of ' + id +
              ' and was ignored; the sign-in itself stands: ' + e.message);
    log.debug('Leaving recordUse(). It threw.');
    return null;
  }
}

// And the other half, which is the more useful one. See fedLastError's schema
// row: a federation that does not work fails at somebody else's service, and
// this is where this service writes down what it thought was wrong.
function recordFailure(id, why) {
  log.debug('Entering recordFailure(). id=' + id);
  try {
    const record = get(id);
    if (!record) {
      log.debug('Leaving recordFailure(). No such relationship.');
      return null;
    }
    record.fedLastError = String(why || 'refused, with no reason recorded');
    record.fedLastErrorAt = generalizedTime();
    persist(record);
    releaseIndex = null;
    // An audit row as well as the attribute, because the attribute holds ONE
    // failure and somebody debugging a partner that intermittently fails needs
    // the sequence. The audit log is the only place here that answers "when,
    // and how many times".
    recordChange('federation.refused', record,
                 'a federated sign-in through ' + id + ' was refused: ' + record.fedLastError,
                 { why: record.fedLastError });
    log.warn('federation: ' + id + ' refused a sign-in — ' + record.fedLastError);
    log.debug('Leaving recordFailure(). Recorded.');
    return get(id);
  } catch (e) {
    log.error('federation: the register threw while recording a failure of ' + id +
              ' and was ignored: ' + e.message);
    log.debug('Leaving recordFailure(). It threw.');
    return null;
  }
}

module.exports = {
  PATHS: PATHS,
  ROLES: ROLES,
  ROLE_IDS: ROLE_IDS,
  PROTOCOLS: PROTOCOLS,
  PROTOCOL_IDS: PROTOCOL_IDS,
  SCHEMA: SCHEMA,
  protocolRow: protocolRow,
  roleRow: roleRow,
  familyOf: familyOf,
  setDirectory: setDirectory,
  attributesFor: attributesFor,
  recordFromAttributes: recordFromAttributes,
  idProblem: idProblem,
  boolOf: boolOf,
  boolText: boolText,
  list: list,
  get: get,
  count: count,
  inRole: inRole,
  containerDn: containerDn,
  maxRelationships: maxRelationships,
  fieldsForRole: fieldsForRole,
  editableFields: editableFields,
  readinessOf: readinessOf,
  isEnabled: isEnabled,
  isUsable: isUsable,
  signInOptions: signInOptions,
  // The identity-provider half, and the one function on the ISSUING path. See
  // the header: it is consulted by admin_stats.js at its two existing funnels
  // and by nothing else.
  releaseFilterFor: releaseFilterFor,
  create: create,
  update: update,
  remove: remove,
  recordUse: recordUse,
  recordFailure: recordFailure
};
