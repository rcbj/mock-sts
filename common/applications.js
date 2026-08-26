'use strict';
//
// File: applications.js
//
// ===========================================================================
// EVERY APPLICATION THIS SERVICE HAS EVER BEEN ASKED ABOUT, IN ONE PLACE.
//
// A person who authenticates here has had an entry in the directory and a row
// on /admin/users since the day the user observer was written. The thing on the
// OTHER side of every one of those authentications — the OAuth client, the
// OpenID Connect relying party, the SAML service provider, the WS-Federation
// application, the Kerberos service — had nowhere at all. It was six fragments:
// a `registeredClients` Map in oauth2.js, a `client_id` that reached the
// console and was thrown away, a `wtrealm` read and forgotten, an `AppliesTo`
// echoed into an assertion, an SPN created on demand in a principal database,
// and a verifier id in a config row. Each was correct where it stood and there
// was no way to ask this service "what applications have you seen?".
//
// This is that place, and it is one store rather than a seventh fragment: the
// RFC 7591 registrations live HERE now (see `register()` below), so there is no
// second registry to disagree with it about a redirect URI. That is the same
// rule that keeps WS-Federation out of a session store of its own — two stores
// each look correct alone and never see each other.
//
// ---------------------------------------------------------------------------
// THE DIRECTORY IS THE SOURCE OF TRUTH, AND THIS MODULE HOLDS NO COPY.
//
// `ou=applications,<base>` in the embedded LDAP directory IS the registry.
// There is no Map in this file shadowing it: `seen()` reads the entry, changes
// it and writes it back, and every query below is a directory read. That is a
// deliberate choice and it has three consequences worth knowing before
// changing anything here.
//
// **An `ldapmodify` is a configuration change.** Adding a value to
// `oauthRedirectUri` on an application's entry adds a redirect URI that RFC
// 9700 mode will then accept by exact match, because the check reads the same
// attribute this registry writes. That is the point rather than a side effect —
// it is what makes the directory worth being the source of truth, and it is the
// shape the federation work needs.
//
// **The attributes win over the registration document.** RFC 7591 lets a client
// register arbitrary metadata and RFC 7592's read has to hand back what was
// registered, which no set of LDAP attributes can represent — so the whole
// registration is kept verbatim in `appRegistrationJson` beside the attributes.
// When the record is reconstructed, the JSON is the STARTING POINT and every
// member that has a schema attribute is then overwritten from that attribute.
// Otherwise an operator who edited `oauthRedirectUri` would find the edit
// ignored by the one check that matters, which is precisely the two-stores
// failure this arrangement exists to avoid.
//
// **Without the directory there is no registry.** If `ldap_server.js` was never
// required — which happens in the parent project's in-process tests, where only
// the KDC and `app.js` are loaded — `setDirectory()` was never called, every
// function here answers empty, and it says so once in the log. It does NOT fall
// back to an internal Map: a fallback store is a second store, and it would be
// the one that silently disagreed.
//
// ---------------------------------------------------------------------------
// THE SCHEMA, AND WHAT "SCHEMA" CAN HONESTLY MEAN HERE.
//
// `node-ldapjs` has NO schema subsystem. It is protocol machinery — messages,
// filters, DN parsing, a client and a server — and the only three mentions of
// objectClass in the whole of its lib/ tree are a default search filter and the
// names of result codes 65 and 69, which a server would have to raise itself.
// It is also a SUBMODULE this repository does not modify. So there was nothing
// to extend and nothing to register with: the schema below is DEFINED HERE, and
// it is a VOCABULARY rather than a constraint. Nothing rejects an entry for
// disobeying it, exactly as nothing rejects one anywhere else in this
// deliberately schemaless directory — `GET /ldap` says so at length.
//
// Where a standard name exists it is used. `applicationProcess` (RFC 4519
// section 3.3) is the one registered object class that fits an application at
// all, and it brings `cn`, `description`, `seeAlso`, `ou` and `l` with it. What
// it does not bring is a `client_id`, a `redirect_uris`, an `entityID` or a
// service principal name — no registered LDAP schema has those, because every
// product that stores OAuth clients (Keycloak, AD FS, Okta) keeps them in its
// own database rather than in a directory. So `stsApplication` is invented, and
// its attributes are this service's own names in exactly the way `x509subject`,
// `didSubject` and `authnMethod` already are on the user entries next door.
//
// ---------------------------------------------------------------------------
// ONE RECORD PER IDENTIFIER, AND WHY THAT IS THE RIGHT KEY.
//
// The key is the identifier the protocol presented, verbatim. Not lower-cased:
// a `client_id` is case-sensitive and so is most of a URI. Not namespaced by
// protocol either, and that is the interesting half — an application that
// appears as an OAuth `client_id` and again as a WS-Federation `wtrealm` under
// the same string is ONE application that speaks two protocols, and this
// registry says so by accumulating `appKind` and `appProtocol` rather than
// filing it twice. That is the same reasoning that makes `alice`,
// `urn:sts-mock:user:alice` and `alice@REALM` one person on /admin/users, and
// it is the shape the federation work will need: a relying party that federates
// over both OIDC and SAML is one relationship, not two.
//
// ---------------------------------------------------------------------------
// IT IS A LIBRARY (rule 3), AND ITS DIRECTORY HALF IS INVERTED (rule 6).
//
// It registers no route and requires `helpers.js`, `audit.js` and `config.js`
// (and `crypto`) — none of which requires it back, so it cannot join a cycle
// and its position in the require order does not matter. `config.js` requires
// nothing from this repository at all, which is the property that makes it safe
// to reach for here; it is read by the startup seeding at the foot of this file
// and by nothing else. `admin_stats.js` requires it in the ORDINARY direction
// (there is no fifth hook here; see rule 3e — a slot is what you reach for when
// a require would close a cycle or move a route, and this one would do
// neither).
//
// The DIRECTORY half has to be inverted, for the reason `vc_claims.js`'s is:
// `ldap_server.js` is last in the require order because requiring it pulls every
// `/ldap` route into the router at that point, and a module the token endpoint
// reads cannot drag those routes to the front. So this file offers
// `setDirectory()` and `ldap_server.js` fills it at ITS require time — with
// READ as well as write functions now, since the entries are the store.
//
// The division of labour between the two files is exact and worth keeping:
// THIS module owns the SCHEMA and therefore both conversions
// (`attributesFor()`, `recordFromAttributes()`), and that module owns the
// directory mechanics — where the container is, how an entry is created, what
// the caps are. Neither knows the other's half.
//
// ---------------------------------------------------------------------------
// THE CLIENT SECRET IS STORED, AND THAT IS A DECISION RATHER THAN AN OVERSIGHT.
//
// `oauthClientSecret` holds the secret this service minted at registration, on
// an entry in a directory where every bind succeeds and which `GET
// /ldap/directory` prints on an unprotected page. The same objection applies to
// `GET /krb5/principals`, which prints every Kerberos password, and the answer
// is the one written there: a debugger whose accounts are unusable without
// reading the source is worse than one that says what they are. The secret is
// generated per registration, lives in memory and dies with the process.
//
// It is worth being precise about what that costs now that RFC 9700 mode
// CHECKS that secret (section 2.5): anyone who can read this directory can
// authenticate as that client. On a service that authenticates nobody and says
// so on every page, that is the honest state of affairs rather than a hole —
// but it is why `audit.js` must never be given this value. Its rule that no
// credential is ever recorded is about the audit log and stands untouched: the
// rows this module writes name the application and never its secret.
// ===========================================================================

const crypto = require('crypto');
const config = require('./config');
const { log, nowSec, randomId } = require('./helpers');
const audit = require('./audit');

// ---------------------------------------------------------------------------
// THE KINDS. One per way an application can present itself to this service.
//
// A record may carry SEVERAL — see the note about one identifier above — and
// the list is closed on purpose: a caller passing a kind that is not here is
// recorded with what it said and warned about, because a typo that silently
// becomes a new kind is how a page comes to list `wsfed-rp` and
// `wsfed-relying-party` as two things.
// ---------------------------------------------------------------------------
const KINDS = [
  { kind: 'oauth2-client', label: 'OAuth 2.0 client',
    what: 'A client_id presented at the authorization or token endpoint.' },
  { kind: 'oidc-relying-party', label: 'OpenID Connect relying party',
    what: 'The same client_id where the request asked for the openid scope — a ' +
          'relying party is an OAuth client that also wants an ID Token, so a ' +
          'record commonly carries both kinds.' },
  { kind: 'saml2-service-provider', label: 'SAML 2.0 service provider',
    what: 'The audience of a SAML 2.0 assertion this service issued.' },
  { kind: 'saml11-relying-party', label: 'SAML 1.1 relying party',
    what: 'The audience of a SAML 1.1 assertion — which is what a WS-Federation ' +
          'relying party is handed by default, so these two commonly appear together.' },
  { kind: 'wsfed-relying-party', label: 'WS-Federation application',
    what: 'A wtrealm from a wsignin1.0 request (section 13.2.1).' },
  { kind: 'wstrust-relying-party', label: 'WS-Trust relying party',
    what: 'An AppliesTo from a RequestSecurityToken — the service the token is for.' },
  { kind: 'oid4vp-verifier', label: 'OpenID4VP verifier',
    what: 'The client_id the mock Verifier presents in an Authorization Request.' },
  { kind: 'federation-identity-provider', label: 'Federated identity provider',
    what: 'A FOREIGN identity service this instance federates with as a service ' +
          'provider — it authenticates people TO this service rather than asking ' +
          'anything OF it, which makes it the one kind here that is not a client. ' +
          'It is in this registry anyway, because the question this container ' +
          'exists to answer is "what parties has this service dealt with?" and a ' +
          'federation partner is the most consequential of them: it is a party ' +
          'whose signature this service BELIEVES. See federation/CLAUDE.md. The ' +
          'relationship itself — the endpoints, the certificate, the attribute ' +
          'mapping — lives under ou=federations and not here; this record is the ' +
          'partner as a party, and that one is the arrangement with it.' },
  { kind: 'kerberos-service', label: 'Kerberos service principal',
    what: 'A service principal name a ticket was issued for, or that the acceptor ' +
          'was asked to be.' }
];

const KIND_IDS = KINDS.map(function (one) { return one.kind; });

// ---------------------------------------------------------------------------
// THE PROTOCOL FAMILIES AN APPLICATION MAY BE DECLARED FOR.
//
// A DIFFERENT TABLE FROM KINDS ABOVE, feeding a DIFFERENT ATTRIBUTE FROM
// `appProtocol`, and both of those distinctions are the whole reason it exists.
//
//   * `appProtocol` is DERIVED — the families this application has actually
//     appeared in, accumulated by seen() as each one happens. Nothing may edit
//     it, for the reason EDITABLE's header gives at length.
//   * `appAllowedProtocol` is DECLARED — the families somebody has said this
//     application is FOR, ticked on /admin/applications/new before it has ever
//     connected to anything. It is configuration, like the redirect URIs beside
//     it, and it is editable.
//
// A KIND is what an application IS in one protocol's own vocabulary: an
// `oauth2-client` is a client_id, a `saml2-service-provider` is an entityID.
// A FAMILY is coarser and is CHOSEN rather than observed, which is why one row
// here can cover two kinds, and why this list runs past the families that have
// a kind at all — an application may be declared for LDAP, SCIM or SPIFFE,
// where this service has no application identifier to record and therefore
// nothing to give it a kind from.
//
// **DECLARING A FAMILY GRANTS AND REFUSES NOTHING**, and this is the sentence
// to change if that ever stops being true rather than a page's. No endpoint in
// this service reads this attribute: an application declared for SAML 2.0 alone
// is still issued an access token at /oauth2/token, because that is what this
// service is for and a mock that refused would remove a test case rather than
// add one. It is a record of INTENT, which is the same claim the applications
// page already makes about the entry as a whole ("an entry here grants
// nothing") narrowed to one attribute.
//
// `kinds` IS WHAT MAKES THE DECLARATION COMPARABLE WITH WHAT HAPPENED, and it
// is deliberately the kinds rather than the protocol LABELS on `appProtocol`.
// That was the first attempt and it was wrong in a way worth recording, because
// it looked right: `appProtocol` holds prose — 'OAuth 2.0 / OIDC', 'SAML 1.1',
// 'WS-Federation 1.2' — written by whichever module called seen(), and a
// FEDERATION sighting is recorded under the protocol the RELATIONSHIP speaks.
// So matching on labels made every ordinary OAuth client read as a federation
// partner, since both write 'OAuth 2.0'. The kinds do not have that problem:
// they are a closed vocabulary seen() warns about, and `federation-identity-
// provider` is a thing an application IS rather than a protocol it spoke.
//
// A row's `kind` is the ONE kind this family would be recorded as, which is
// what the pages show; `kinds` is every kind that COUNTS as a sighting of it,
// which is usually the same one list. The exception is OAuth 2.0, whose list
// carries the OpenID Connect kind as well — a relying party IS an OAuth client,
// and a request carrying the openid scope is filed under the narrower kind
// only, so an OAuth row that ignored it would report "never seen" about a
// client signing somebody in every minute.
//
// **A row may have NO kind at all**, and those rows are the reason this is
// stated rather than left to be inferred: LDAP, SCIM, SPIFFE, mutual TLS and
// OpenID4VCI record no application identifier anywhere in this service, so
// nothing will EVER mark them seen. That is a different fact from "it has not
// happened yet", and the pages say so rather than showing a bare no.
//
// ---------------------------------------------------------------------------
// `identifierAttribute` AND `redirectAttribute`: WHERE A FAMILY'S OWN NAMES GO.
//
// Added 2026-08-25, and they are the reason the create form no longer asks for
// a KIND. That select and this table were two vocabularies for one question —
// "what is this application?" — and a reader had to choose in both, from lists
// that did not line up: eight kinds against fourteen families, with five
// families having no kind at all. The families won because they are the coarser
// and the honest one, and because THEY are what an operator is actually
// declaring. The kind is still accumulated by `seen()` when a protocol
// recognises the identifier, which is where a derived attribute belongs.
//
// So a family row now carries the two attributes that family's CONFIGURATION
// lands on:
//
//   * `identifierAttribute` — the attribute holding the name this application
//     answers to in that family. A client_id, an entityID, a wtrealm, an
//     AppliesTo, an SPN, a SPIFFE ID, a bind DN.
//   * `redirectAttribute` — where a response goes back to, for the three
//     families that send one through a browser. Empty everywhere else, because
//     inventing a redirect URI for LDAP would be inventing a fact.
//
// **SEVERAL FAMILIES MAY NAME ONE ATTRIBUTE, AND THAT IS THE POINT rather than
// a shortcut.** OAuth 2.0, OpenID Connect and OpenID4VCI all name
// `oauthClientId` because a relying party IS an OAuth client and a wallet
// collecting a credential authenticates as one — the specifications share the
// identifier, so two attributes would be two spellings of one fact and would
// disagree the first time somebody edited one. SAML 2.0 and SAML 1.1 share
// `samlEntityId` and `samlAssertionConsumerService` for the same reason. The
// console walks this table, DEDUPES BY ATTRIBUTE and draws one field per
// attribute, listing the families it serves — so the form has eleven identifier
// fields for fourteen families and says why.
//
// **EVERY ONE OF THEM IS MULTI-VALUED BAR ONE.** An application legitimately
// answers to two client_ids, two entityIDs or two SPNs here — one per
// environment being exercised — so these accumulate like the redirect URIs
// beside them. The exception is `oauthTlsClientAuthSubjectDn`, which mutual TLS
// names: it is SINGLE-valued because `client_auth.js` compares it to the
// certificate's subject by exact string equality for RFC 8705 section 2.1, and
// a list arriving there would stringify to `dn1,dn2` and match nothing. It is
// the one attribute in this group that something ENFORCES, which is exactly why
// it is the one that cannot be widened without deciding what "any of these"
// means to a security check. Stated here and on the form rather than left as an
// inconsistency somebody re-derives.
//
// **DECLARING ONE STILL GRANTS NOTHING**, the same as ticking the family does.
// The five families this service records no identifier for — LDAP, SCIM,
// SPIFFE, OpenID4VCI, mutual TLS — get a field anyway, because "what is this
// application called when it talks LDAP to us" is a fact an operator has and
// this registry had nowhere to put. Nothing will ever write those attributes on
// its own, so they read as declaration and only ever as declaration.
// ---------------------------------------------------------------------------
const PROTOCOLS = [
  { id: 'oauth2', label: 'OAuth 2.0', kind: 'oauth2-client',
    kinds: ['oauth2-client', 'oidc-relying-party'],
    identifierAttribute: 'oauthClientId', redirectAttribute: 'oauthRedirectUri',
    what: 'A client_id at the authorization and token endpoints.' },
  { id: 'oidc', label: 'OpenID Connect', kind: 'oidc-relying-party',
    kinds: ['oidc-relying-party'],
    identifierAttribute: 'oauthClientId', redirectAttribute: 'oauthRedirectUri',
    what: 'The same client_id asking for the openid scope, and therefore for an ID Token. ' +
          'A relying party IS an OAuth client, so these two are usually ticked together; ' +
          'ticking this one alone is legal and says the entry is for an OIDC flow.' },
  { id: 'saml2', label: 'SAML 2.0', kind: 'saml2-service-provider',
    kinds: ['saml2-service-provider'],
    identifierAttribute: 'samlEntityId',
    redirectAttribute: 'samlAssertionConsumerService',
    what: 'A service provider entityID in the Web Browser SSO profile at /saml2, or the ' +
          'audience of a SAML 2.0 assertion issued anywhere else here.' },
  { id: 'saml11', label: 'SAML 1.1', kind: 'saml11-relying-party',
    kinds: ['saml11-relying-party'],
    identifierAttribute: 'samlEntityId',
    redirectAttribute: 'samlAssertionConsumerService',
    what: 'A relying party of the two browser profiles at /saml11 — and what a ' +
          'WS-Federation application is handed by default, which is why these two are ' +
          'commonly ticked together.' },
  { id: 'wsfed', label: 'WS-Federation', kind: 'wsfed-relying-party',
    kinds: ['wsfed-relying-party'],
    identifierAttribute: 'wsfedRealm', redirectAttribute: 'wsfedReplyUrl',
    what: 'A wtrealm in a wsignin1.0 request (section 13.2.1).' },
  { id: 'wstrust', label: 'WS-Trust', kind: 'wstrust-relying-party',
    kinds: ['wstrust-relying-party'],
    identifierAttribute: 'wstrustAppliesTo', redirectAttribute: '',
    what: 'An AppliesTo in a RequestSecurityToken — the service the token is issued FOR.' },
  { id: 'krb5', label: 'Kerberos v5', kind: 'kerberos-service',
    kinds: ['kerberos-service'],
    identifierAttribute: 'krb5ServicePrincipalName', redirectAttribute: '',
    what: 'A service principal name a ticket may be issued for, or that the acceptor may be ' +
          'asked to be.' },
  { id: 'oid4vci', label: 'OpenID4VCI', kind: '',
    kinds: [],
    identifierAttribute: 'oauthClientId', redirectAttribute: 'oauthRedirectUri',
    what: 'A wallet collecting a verifiable credential from the issuer. The wallet presents ' +
          'no application identifier of its own on that flow — it authenticates as an OAuth ' +
          'client and is recorded as one — so this family has no kind and nothing will ever ' +
          'mark it seen.' },
  { id: 'oid4vp', label: 'OpenID4VP', kind: 'oid4vp-verifier',
    kinds: ['oid4vp-verifier'],
    identifierAttribute: 'oid4vpClientId', redirectAttribute: '',
    what: 'A verifier client_id in an Authorization Request asking for a presentation.' },
  { id: 'federation', label: 'Federation', kind: 'federation-identity-provider',
    kinds: ['federation-identity-provider'],
    identifierAttribute: 'federationPartnerId', redirectAttribute: '',
    what: 'A FOREIGN identity service on the other side of a federation relationship. It is ' +
          'the one thing in this registry that is not a client of this service — it ' +
          'authenticates people TO it. Its SIGHTING is recorded under whichever protocol the ' +
          'relationship speaks, so the protocol label on such an entry is indistinguishable ' +
          'from an ordinary client\'s and the KIND is the only thing that tells them apart — ' +
          'which is the whole reason this table matches on kinds. The relationship itself ' +
          'lives under ou=federations; see federation/CLAUDE.md.' },
  { id: 'ldap', label: 'LDAP', kind: '',
    kinds: [],
    identifierAttribute: 'ldapBindDn', redirectAttribute: '',
    what: 'A directory client binding on 389 or LDAPS 636. EVERY BIND HERE SUCCEEDS and none ' +
          'of them names an application, so nothing will ever record a sighting for this ' +
          'family — ticking it says what the entry is for and nothing more.' },
  { id: 'scim', label: 'SCIM 2.0', kind: '',
    kinds: [],
    identifierAttribute: 'scimClientId', redirectAttribute: '',
    what: 'A provisioning client at /scim/v2. That surface authenticates its CALLER — in any ' +
          'of the six schemes RFC 7644 section 2 names — rather than an application ' +
          'identifier, so, as with LDAP, nothing writes this family into appProtocol.' },
  { id: 'spiffe', label: 'SPIFFE', kind: '',
    kinds: [],
    identifierAttribute: 'spiffeWorkloadId', redirectAttribute: '',
    what: 'A workload on the Workload API, or an agent or admin on the SPIRE Server API. A ' +
          'SPIFFE identity gets an entry of its own under ou=spiffe rather than one here ' +
          '(see spiffe/CLAUDE.md), so this is a declaration and never a record.' },
  { id: 'mtls', label: 'TLS / mutual TLS', kind: '',
    kinds: [],
    identifierAttribute: 'oauthTlsClientAuthSubjectDn', redirectAttribute: '',
    what: 'A client presenting a certificate on 8443 or 9443, or authenticating to the token ' +
          'endpoint under RFC 8705. The two attributes that make the second REAL are on this ' +
          'entry and are genuinely read — oauthTlsClientAuthSubjectDn for section 2.1 and ' +
          'oauthTlsClientCertificateThumbprint for section 2.2 — so ticking this box is the ' +
          'note to self, and those two are the configuration.' }
];

const PROTOCOL_IDS = PROTOCOLS.map(function (one) { return one.id; });

const PROTOCOL_BY_ID = {};
PROTOCOLS.forEach(function (row) { PROTOCOL_BY_ID[row.id] = row; });

// Which declared families a KIND counts as a sighting of — the inverse of the
// `kinds` member, built once rather than searched per row per page. The value
// is a LIST because one kind can belong to two families: `oidc-relying-party`
// is a sighting of OpenID Connect AND of OAuth 2.0, since a relying party is an
// OAuth client. Dropping one of them would leave a page reporting that an
// application signing somebody in every minute had never been seen.
const PROTOCOLS_BY_KIND = {};
PROTOCOLS.forEach(function (row) {
  row.kinds.forEach(function (kind) {
    if (!PROTOCOLS_BY_KIND[kind]) PROTOCOLS_BY_KIND[kind] = [];
    if (PROTOCOLS_BY_KIND[kind].indexOf(row.id) < 0) PROTOCOLS_BY_KIND[kind].push(row.id);
  });
});

function protocolRow(id) {
  return PROTOCOL_BY_ID[String(id || '')] || null;
}

// The declared families a record's KINDS amount to a sighting of. Used by the
// pages to mark a declared family that has actually turned up, and to notice
// one that turned up without ever being declared. A kind this table has no row
// for maps onto nothing rather than throwing: seen() warns about an unknown
// kind and records it anyway, so a record can carry one, and this function is
// not its validator.
function protocolIdsForKinds(kinds) {
  const out = [];
  (kinds || []).forEach(function (kind) {
    (PROTOCOLS_BY_KIND[String(kind)] || []).forEach(function (id) {
      if (out.indexOf(id) < 0) out.push(id);
    });
  });
  // Table order, for the reason normaliseProtocols() puts a declaration back
  // into it: two lists in the same order can be read against each other.
  return PROTOCOL_IDS.filter(function (id) { return out.indexOf(id) >= 0; });
}

// A declared list as it arrives from a form's checkboxes or an API body, made
// into a validated list of ids or into the one refusal this vocabulary makes.
//
// It is REFUSED rather than recorded when a value is not in the table, which is
// the same decision createApplication() makes about `kind` and for the same
// reason: a typo that silently became a new protocol family is how one
// application comes to be declared for `saml2` and `saml-2` and read as two
// different things by whatever comes to read this attribute later. Duplicates
// and blanks are dropped rather than refused — a form that posts one box twice
// is a browser doing something odd, not a caller asking for something wrong.
function normaliseProtocols(value) {
  log.debug("Entering normaliseProtocols().");
  const asked = (Array.isArray(value) ? value : [value])
    .filter(function (one) { return one !== undefined && one !== null; })
    // A single string may carry several, because a JSON caller writing this by
    // hand will send "oauth2 oidc" or "oauth2,oidc" at least as often as an
    // array, and the checkbox form sends one value per field either way.
    .reduce(function (all, one) { return all.concat(String(one).split(/[\s,]+/)); }, [])
    .map(function (one) { return one.trim(); })
    .filter(Boolean);
  const chosen = [];
  const unknown = [];
  asked.forEach(function (one) {
    if (PROTOCOL_IDS.indexOf(one) < 0) {
      if (unknown.indexOf(one) < 0) unknown.push(one);
      return;
    }
    if (chosen.indexOf(one) < 0) chosen.push(one);
  });
  if (unknown.length) {
    log.debug("Leaving normaliseProtocols(). " + unknown.length + " unknown.");
    return { ok: false, protocols: [],
             errors: [unknown.map(function (one) { return '"' + one + '"'; }).join(', ') +
                      (unknown.length > 1 ? ' are not protocol families' : ' is not a protocol family') +
                      ' this registry knows. The ' + PROTOCOL_IDS.length + ' are: ' +
                      PROTOCOL_IDS.join(', ') + '.'] };
  }
  // Back into TABLE ORDER rather than the order they were ticked in. The table
  // is ordered by how a reader thinks about the families, and an entry whose
  // attribute order depends on which box somebody clicked first would make two
  // identical declarations look different in an ldapsearch.
  const ordered = PROTOCOL_IDS.filter(function (id) { return chosen.indexOf(id) >= 0; });
  log.debug("Leaving normaliseProtocols(). " + ordered.length + " family/families.");
  return { ok: true, protocols: ordered, errors: [] };
}

// ---------------------------------------------------------------------------
// THE SCHEMA.
//
// One row per attribute, and the row is the whole definition: `GET
// /ldap/applications` publishes this table, `ldap_server.js` builds the entry
// from it, and there is no second list anywhere to update. An attribute that is
// not here is not written, which is what makes the published schema worth
// reading — the lesson `vc_claims.js` learned about an issuer advertising five
// claims and minting fourteen.
//
// `single` vs `multi` is load-bearing rather than descriptive, because it says
// how a repeat is treated. A multi-valued attribute ACCUMULATES — a second
// redirect URI joins the first — and a single-valued one is ASSIGNED. Getting
// that backwards on a counter is the trap `applyVcAttributes()` writes its
// second rule about: an entry that accumulated one `appAuthentications` per
// sign-in would be the visible symptom of a bug nobody could locate.
// ---------------------------------------------------------------------------
const SCHEMA = {
  objectClasses: [
    { name: 'top', where: 'RFC 4512', standard: true,
      what: 'The abstract class every entry carries.' },
    { name: 'applicationProcess', where: 'RFC 4519 section 3.3', standard: true,
      what: 'The one REGISTERED object class that fits an application. It brings cn, ' +
            'description, seeAlso, ou and l — so the NAME of an application here is a ' +
            'standard attribute even though nothing else about it can be.' },
    { name: 'stsApplication', where: 'this service', standard: false,
      what: 'INVENTED, because no registered LDAP schema has a client_id, a set of ' +
            'redirect URIs, an entityID or a service principal name. Every product that ' +
            'stores OAuth clients keeps them in its own database rather than in a ' +
            'directory, so there was nothing to borrow. These are this service\'s own ' +
            'names in the way x509subject and didSubject already are.' }
  ],
  attributes: [
    // --- identity ---------------------------------------------------------
    { name: 'appIdentifier', kind: 'single', from: 'every protocol',
      what: 'THE KEY: the identifier exactly as the protocol presented it. The entry\'s ' +
            'own cn may be a digest of it where it is too long to be a readable RDN, so ' +
            'this is the attribute to search on — the same arrangement didSubject has on ' +
            'a DID-named person.' },
    { name: 'cn', kind: 'single', from: 'this registry', standard: true,
      what: 'The RDN value: the identifier itself, or app-<12 hex> where that would be ' +
            'longer than 64 characters.' },
    { name: 'appName', kind: 'single', from: 'RFC 7591 client_name, or the identifier',
      what: 'What to call it on a page. A registration supplies one; otherwise the ' +
            'identifier is the name, because inventing a friendly name for an opaque id ' +
            'would be inventing a fact.' },
    { name: 'appKind', kind: 'multi', from: 'every protocol',
      what: 'What this application IS, one value per role it has been seen in. Several ' +
            'is the ordinary case and is the point: an OAuth client that asks for the ' +
            'openid scope is also a relying party.' },
    { name: 'appProtocol', kind: 'multi', from: 'every protocol',
      what: 'The protocol families it has appeared in, accumulated.' },
    { name: 'appAllowedProtocol', kind: 'multi',
      from: 'the console, the management API, or by hand',
      what: 'THE PROTOCOL FAMILIES THIS APPLICATION IS DECLARED FOR, one value per family, ' +
            'from the closed table PROTOCOLS publishes. It is the DECLARED twin of ' +
            'appProtocol above and the two must not be read as one thing: that attribute is ' +
            'what has happened and cannot be edited, this one is what somebody said the ' +
            'application is for and is ticked on /admin/applications/new before it has ever ' +
            'connected. NOTHING IN THIS SERVICE READS IT — an application declared for SAML ' +
            '2.0 alone is still issued an access token, because a mock that refused would ' +
            'remove a test case rather than add one — so it grants nothing and refuses ' +
            'nothing, exactly as being in this registry at all does.' },
    { name: 'appAuthorizationServer', kind: 'multi', from: 'OAuth 2.0 / OIDC',
      what: 'WHICH AUTHORIZATION SERVERS this client has used, by the name in their paths — ' +
            'one value per server it has been seen at. This process publishes several, each ' +
            'with its own capabilities and its own endpoints under /{id}/oauth2/…, and EVERY ' +
            'CLIENT MAY USE EVERY ONE of them: nothing here restricts a client to a server, ' +
            'so this records where it HAS been rather than where it may go. Accumulated, ' +
            'because a client that talks to two of them is one client with two values and not ' +
            'two clients.' },
    { name: 'description', kind: 'multi', from: 'this registry', standard: true,
      what: 'One line per protocol that first brought this application here.' },

    // --- what has happened ------------------------------------------------
    { name: 'appFirstSeen', kind: 'single', from: 'this registry',
      what: 'GeneralizedTime, when this identifier was first presented.' },
    { name: 'appLastSeen', kind: 'single', from: 'this registry',
      what: 'GeneralizedTime, the most recent time.' },
    { name: 'appAuthentications', kind: 'single', from: 'this registry',
      what: 'How many credentials this service has accepted FOR this application. ' +
            'ASSIGNED on every change — a counter that accumulated values would be ' +
            'nonsense — and it is a live number in a directory entry, which is unusual ' +
            'enough to say out loud: a real directory would not hold one.' },
    { name: 'appSessions', kind: 'single', from: 'this registry',
      what: 'How many DISTINCT browser sign-on sessions have involved it. Counted from ' +
            'the session id that rides on the authentication funnel, so a direct grant ' +
            'with no browser session behind it adds nothing.' },
    { name: 'appUsers', kind: 'single', from: 'this registry',
      what: 'How many distinct identities have authenticated for it. The identities ' +
            'themselves are NOT listed here: an application used by two thousand people ' +
            'would otherwise put two thousand values on one entry.' },
    { name: 'appLastSession', kind: 'single', from: 'this registry',
      what: 'The most recent sign-on session id. It is what appSessions is counted ' +
            'against — a different one increments the count — and it is on the entry ' +
            'rather than in memory because the entry is the store: without it a restart ' +
            'of nothing at all would recount the session already counted.' },
    { name: 'appLastUser', kind: 'single', from: 'this registry',
      what: 'The most recent identity, for the same reason and with the same limitation: ' +
            'it counts a CHANGE of user rather than a distinct set, which is right for ' +
            'the ordinary case and undercounts somebody alternating between two ' +
            'applications. Stated in seen() where the trade is made.' },

    // --- OAuth 2.0 / OpenID Connect ---------------------------------------
    { name: 'appRegistered', kind: 'single', from: 'POST /oauth2/register',
      what: 'TRUE when this application went through dynamic client registration here, ' +
            'FALSE when it is simply a client_id that turned up. The distinction is what ' +
            'RFC 9700 mode reads: a registered client is judged against its OWN redirect ' +
            'URIs and can be confidential, and an unregistered one is judged against the ' +
            'oauth2.redirectUris setting and is treated as public.' },
    { name: 'oauthClientId', kind: 'multi', from: 'OAuth 2.0 / OIDC / OpenID4VCI',
      identifier: true,
      what: 'THE CLIENT_ID, and the identifier attribute of three families: an OpenID ' +
            'Connect relying party IS an OAuth client, and a wallet collecting a ' +
            'credential at the OpenID4VCI issuer authenticates as one, so all three ' +
            'declare their name here rather than in three attributes that would be three ' +
            'spellings of one fact. Usually equal to appIdentifier, which is what a ' +
            'protocol sighting writes; a SECOND value is a client_id this application also ' +
            'answers to — a per-environment id — and is why this accumulates rather than ' +
            'being assigned. Absent on an entry no OAuth family has been declared for.' },
    { name: 'oauthAudience', kind: 'multi',
      from: 'the console, the management API, or by hand',
      what: 'THE AUDIENCE THIS APPLICATION ANSWERS TO — the `aud` an access token ' +
            'addressed to it carries, and what a client puts in RFC 8693 section 2.1\'s ' +
            '`audience` (or `resource`) when it exchanges a token to reach this ' +
            'application. It is the OAuth spelling of a fact three other families here ' +
            'already record under their own names: `wstrustAppliesTo` is the same thing ' +
            'in a RequestSecurityToken and `samlEntityId` is the same thing in an ' +
            'assertion\'s AudienceRestriction, and one attribute holding all three would ' +
            'be one string that has to mean whichever protocol asked last.\n\nIt is ' +
            'DECLARED — nobody presents an audience as their own name, so nothing here ' +
            'writes it and it cannot be derived — and it is a URI rather than a ' +
            'client_id because that is what an audience is: the resource, not the client ' +
            'that calls it. Several values is the ordinary case (a per-environment ' +
            'hostname), which is why it accumulates.\n\n**IT IS READ, WHICH MAKES IT ' +
            'THE EXCEPTION** among the declaration attributes beside it. The token ' +
            'exchange looks an `audience` UP here — forAudience() — so that a delegation ' +
            'recorded for `https://esb1.example.com` names the application `esb1` on ' +
            '/admin/delegation and in its picture, instead of drawing a box for a URL ' +
            'that nothing else in the register mentions. It is a LOOKUP and not a ' +
            'permission: an audience nobody registered is exchanged for exactly as ' +
            'before and recorded verbatim, because a mock that refused would remove a ' +
            'test case rather than add one.' },
    { name: 'oauthClientSecret', kind: 'single', from: 'POST /oauth2/register',
      sensitive: true,
      what: 'THE SECRET THIS SERVICE MINTED, in the clear, in a directory where every ' +
            'bind succeeds. Deliberate, and it is the same decision GET /krb5/principals ' +
            'makes about the Kerberos passwords: a debugger whose accounts are unusable ' +
            'without reading the source is worse than one that says what they are. In RFC ' +
            '9700 mode this secret is CHECKED, so anyone who can read this directory can ' +
            'authenticate as this client — which is the honest state of a service that ' +
            'authenticates nobody. It is never written to the audit log.' },
    { name: 'oauthRedirectUri', kind: 'multi', from: 'OAuth 2.0 / OIDC',
      what: 'Registered redirect URIs from a registration, and any redirect_uri this ' +
            'service has ACCEPTED for the application beside them. The two are not the ' +
            'same claim and the registry does not merge them silently — see ' +
            'appRedirectUriObserved.' },
    { name: 'appRedirectUriObserved', kind: 'multi', from: 'OAuth 2.0 / OIDC',
      what: 'A redirect_uri seen on an authorization request that this service answered. ' +
            'Kept apart from oauthRedirectUri because "registered" and "used" are ' +
            'different facts, and RFC 9700 section 2.1 is entirely about not confusing ' +
            'them: an exact-match check reads the registered list, and this one is ' +
            'evidence of what a client actually does.' },
    { name: 'oauthPostLogoutRedirectUri', kind: 'multi', from: 'POST /oauth2/register',
      what: 'Registered post_logout_redirect_uris, which RP-Initiated Logout matches ' +
            'against in RFC 9700 mode.' },
    { name: 'oauthFrontchannelLogoutUri', kind: 'single',
      from: 'POST /oauth2/register, the console, or by hand',
      what: 'WHERE THIS CLIENT IS TOLD THAT THE USER SIGNED OUT — OpenID Connect ' +
            'Front-Channel Logout 1.0 section 2\'s frontchannel_logout_uri. The ' +
            'sign-out page loads it in a hidden iframe, with iss and sid on the query ' +
            'string when the client asked for them. It is SINGLE-valued because the ' +
            'specification defines one URI per client, unlike the redirect URIs beside ' +
            'it; a client with none registered is not notified at all and is listed on ' +
            '/logout as such rather than silently skipped.' },
    { name: 'oauthFrontchannelLogoutSessionRequired', kind: 'single',
      from: 'POST /oauth2/register, the console, or by hand',
      what: 'TRUE if this client requires `iss` and `sid` on the notification above — ' +
            'Front-Channel Logout 1.0 section 2\'s ' +
            'frontchannel_logout_session_required. It matters because an RP with ' +
            'several sessions in one browser cannot tell which one ended without the ' +
            'sid, and RFC 7591 section 2 makes an omitted boolean FALSE rather than ' +
            'unknown — so an absent value here means the client did not ask, which is ' +
            'a different fact from the client not having registered.' },
    { name: 'oauthGrantType', kind: 'multi', from: 'OAuth 2.0 / OIDC',
      what: 'Grant types registered or observed at the token endpoint.' },
    { name: 'oauthResponseType', kind: 'multi', from: 'OAuth 2.0 / OIDC',
      what: 'response_type values seen at the authorization endpoint.' },
    { name: 'oauthScope', kind: 'multi', from: 'OAuth 2.0 / OIDC',
      what: 'Scopes this application has asked for.' },
    { name: 'oauthTokenEndpointAuthMethod', kind: 'single', from: 'POST /oauth2/register',
      what: 'How it authenticates. RFC 7591 section 2 makes client_secret_basic the ' +
            'default when a registration omits it, which is why an omission means ' +
            'CONFIDENTIAL rather than unknown.' },
    { name: 'oauthJwks', kind: 'single', from: 'POST /oauth2/register, or by hand',
      what: 'THE CLIENT\'S PUBLIC KEYS, as a JWKS document — what private_key_jwt is verified ' +
            'against (RFC 7591 `jwks`). This is the asymmetric credential RFC 9700 section 2.5 ' +
            'RECOMMENDS, and it is the one credential attribute here that is NOT a secret: it ' +
            'is public key material, worth nothing to anybody who reads it, which is the whole ' +
            'point of preferring it to a shared secret.' },
    { name: 'oauthJwksUri', kind: 'single', from: 'POST /oauth2/register',
      what: 'RFC 7591 `jwks_uri`. RECORDED AND NEVER FETCHED: following it would mean this ' +
            'service making an outbound request to a URL somebody registered in order to ' +
            'verify a credential, which is a server-side request forgery with a specification ' +
            'citation attached — the same refusal WS-Federation\'s wreqptr gets. A client that ' +
            'registers only this is told to register `jwks` instead, by name, when it tries to ' +
            'authenticate.' },
    { name: 'oauthTlsClientAuthSubjectDn', kind: 'single', from: 'by hand',
      identifier: true,
      what: 'RFC 8705 section 2.1.2 `tls_client_auth_subject_dn`: the subject DN of the PKI ' +
            'certificate this client authenticates with, in RFC 4514 form — the same spelling ' +
            '/admin/users files a verified certificate under, so one DN has one spelling across ' +
            'this service. IT IS ALSO THE IDENTIFIER ATTRIBUTE OF THE `mtls` FAMILY, and it is ' +
            'THE ONE THAT IS STILL SINGLE-VALUED while every other identifier here ' +
            'accumulates. The reason is that something ENFORCES it: client_auth.js compares ' +
            'this string to the certificate\'s subject by exact equality, so a second value ' +
            'would stringify to "dn1,dn2" and match nothing — widening it means first deciding ' +
            'what "any of these" should mean to a security check, which is a different change ' +
            'from giving a form a field. Said here and on /admin/applications/new rather than ' +
            'left as an inconsistency somebody re-derives.' },
    { name: 'oauthTlsClientCertificateThumbprint', kind: 'single', from: 'by hand',
      what: 'For RFC 8705 section 2.2 self_signed_tls_client_auth: the base64url SHA-256 of the ' +
            'DER of the certificate this client authenticates with. THIS SERVICE\'S OWN NAME — ' +
            'the RFC matches a self-signed certificate against the client\'s registered jwks, ' +
            'and a thumbprint is the same check with far less to get wrong on a mock. Fetch a ' +
            'certificate\'s with GET /tls/whoami, or compute it: openssl x509 -outform DER | ' +
            'openssl dgst -sha256 -binary | base64url.' },
    { name: 'oauthConfidential', kind: 'single', from: 'this registry',
      what: 'TRUE/FALSE, the determination RFC 9700 mode makes about it — and therefore ' +
            'whether PKCE is required of it and whether its secret is checked. Written ' +
            'here so the answer can be read rather than inferred.' },

    // --- SAML, WS-Federation, WS-Trust ------------------------------------
    { name: 'samlEntityId', kind: 'multi', from: 'SAML 2.0 / SAML 1.1',
      identifier: true,
      what: 'THE SERVICE PROVIDER\'S ENTITYID — the assertion audience, and the identifier ' +
            'attribute of BOTH SAML families. SAML 1.1 has no entityID of its own in the ' +
            'protocol (there is no request message for one to travel in) and what stands in ' +
            'for it — Shibboleth\'s providerId, the path segment, or the TARGET\'s origin — ' +
            'names the same party, so one attribute holds it rather than two that would ' +
            'disagree the first time an application was declared for both. Accumulates: an ' +
            'application answering to two entityIDs is one application.' },
    { name: 'samlAssertionConsumerService', kind: 'multi', from: 'SAML 2.0 / SAML 1.1',
      what: 'THE ASSERTION CONSUMER SERVICE URL — where a SAML response is posted back to, ' +
            'and the redirect URI of both SAML families. It held WS-Federation\'s `wreply` ' +
            'as well until 2026-08-25; that moved to wsfedReplyUrl, because the SAML pages ' +
            'read this attribute for the Single Logout fallback and a wreply arriving in it ' +
            'made a WS-Federation application look as though it had named a SAML ACS. ' +
            'RECORDED AND NOT CHECKED: a response goes wherever the request asked, and a ' +
            'URL that is not on this list is not refused.' },
    { name: 'samlSingleLogoutService', kind: 'multi', from: 'by hand',
      what: 'WHERE A <samlp:LogoutResponse> IS SENT for this service provider, and where a ' +
            'LogoutRequest goes when this identity provider starts the logout. DECLARED, ' +
            'not observed, and it is the one SAML attribute that has to be: a LogoutRequest ' +
            'carries no return address, only SP METADATA does, and this service does not ' +
            'consume SP metadata. With none recorded the fallback is the assertion consumer ' +
            'service URL above, which is a guess this service makes out loud rather than ' +
            'quietly — see saml2.defaultSingleLogoutService.' },
    { name: 'samlNameIdFormat', kind: 'multi', from: 'SAML 2.0',
      what: 'Every NameID Format this service provider has asked for in a NameIDPolicy, ' +
            'accumulated. It is evidence rather than configuration: this identity provider ' +
            'answers with whatever was asked for, including a format nobody has ever heard ' +
            'of, so a value here does not restrict the next request.' },
    { name: 'samlResponseBinding', kind: 'multi', from: 'SAML 2.0',
      what: 'The ProtocolBinding values it has asked its responses back on — HTTP-POST, ' +
            'HTTP-Redirect or HTTP-Artifact. Several is the ordinary case for a service ' +
            'provider being exercised, which is what makes this a list.' },
    { name: 'samlSigningCertificate', kind: 'single', from: 'SAML 2.0, or by hand',
      what: 'THE SERVICE PROVIDER\'S SIGNING CERTIFICATE, base64 DER, taken off the ' +
            'ds:KeyInfo of a signed AuthnRequest when one carries it. It is RECORDED AND ' +
            'NOT CHECKED — see saml/CLAUDE.md, where the refusal to verify a request ' +
            'signature is argued rather than assumed — so it is here to be read, and to be ' +
            'what a later verification would read, rather than because anything depends on ' +
            'it today. Public key material, so unlike oauthClientSecret it is worth nothing ' +
            'to whoever reads this directory.' },
    { name: 'samlAuthnRequestSigned', kind: 'single', from: 'SAML 2.0',
      what: 'TRUE when the last AuthnRequest from this service provider carried a signature ' +
            '— an enveloped ds:Signature on the POST binding, or the Signature parameter of ' +
            'section 3.4.4.1 on the Redirect binding. ASSIGNED rather than accumulated, ' +
            'because it is a fact about the last request and a history of booleans would ' +
            'say nothing.' },
    { name: 'wsfedRealm', kind: 'multi', from: 'WS-Federation',
      identifier: true,
      what: 'THE WTREALM from a wsignin1.0 request (section 13.2.1) — WS-Federation\'s ' +
            'identifier attribute. Accumulates, for the reason every identifier here does.' },
    { name: 'wsfedReplyUrl', kind: 'multi',
      from: 'WS-Federation, the console, or by hand',
      what: 'WHERE A SIGN-IN RESPONSE IS POSTED BACK TO for this application: the `wreply` ' +
            'of section 13.2.1, WS-Federation\'s redirect URI. It was written into ' +
            'samlAssertionConsumerService until 2026-08-25, which put a wreply in the ' +
            'attribute the SAML pages read for an assertion consumer service and for the ' +
            'Single Logout fallback — one attribute holding two protocols\' return ' +
            'addresses, so a WS-Federation application appeared to have a SAML ACS it had ' +
            'never named. Two facts, two attributes. Like the SAML one beside it this is ' +
            'RECORDED AND NOT CHECKED: nothing here refuses a wreply that is not on the ' +
            'list, because a mock that refused would remove a test case rather than add ' +
            'one.' },
    { name: 'wstrustAppliesTo', kind: 'multi', from: 'WS-Trust',
      identifier: true,
      what: 'THE APPLIESTO ADDRESS from a RequestSecurityToken — the service the token is ' +
            'issued FOR, and WS-Trust\'s identifier attribute. Accumulates.' },

    // --- Kerberos and OID4VP ----------------------------------------------
    { name: 'krb5ServicePrincipalName', kind: 'multi', from: 'Kerberos v5',
      identifier: true,
      what: 'THE SPN, e.g. HTTP/sts@EXAMPLE.COM — Kerberos v5\'s identifier attribute. A ' +
            'Kerberos service is an application like the others here, and it is the one ' +
            'whose identifier this service may have created on demand ' +
            '(KRB5_SERVICE_DOMAINS). It accumulates, and here that is the ordinary case ' +
            'rather than the unusual one: one service commonly answers to several SPNs — ' +
            'HTTP/host and HTTP/host.example.com — and a real KDC holds them all against ' +
            'one account.' },
    { name: 'appRegistrationJson', kind: 'single', from: 'POST /oauth2/register',
      what: 'THE RFC 7591 REGISTRATION VERBATIM, as JSON on one attribute. It is here ' +
            'because RFC 7591 lets a client register arbitrary metadata and RFC 7592\'s read ' +
            'has to hand back what was registered — which no fixed set of LDAP attributes ' +
            'can represent. It is the STARTING POINT when the record is reconstructed and ' +
            'not the last word: every member that also has an attribute above is then ' +
            'overwritten FROM that attribute, so an ldapmodify of oauthRedirectUri is what ' +
            'RFC 9700 mode enforces. Edit this only to change a member that has no ' +
            'attribute of its own.' },
    { name: 'appRegistrationAccessToken', kind: 'single', from: 'POST /oauth2/register',
      sensitive: true,
      what: 'The RFC 7592 registration access token, which is what guards the read, update ' +
            'and delete operations on this client. In the clear for the same stated reason ' +
            'oauthClientSecret is, and never written to the audit log.' },
    { name: 'oid4vpClientId', kind: 'multi', from: 'OpenID4VP',
      identifier: true,
      what: 'THE VERIFIER\'S CLIENT_ID in an Authorization Request asking for a ' +
            'presentation — OpenID4VP\'s identifier attribute. This service\'s own mock ' +
            'Verifier takes its from configuration (oid4vp.clientId) rather than from a ' +
            'caller, so that record appears the first time a presentation is verified; a ' +
            'value declared here is a FOREIGN verifier somebody is configuring.' },

    // --- THE FOUR FAMILIES THAT ONLY EVER DECLARE ------------------------
    // Nothing in this service writes any of these four. That is the whole
    // point of them rather than a gap: LDAP, SCIM, SPIFFE and Federation
    // either authenticate the CALLER rather than an application (the first
    // two), file the identity in a container of its own (the third), or keep
    // the arrangement under ou=federations (the fourth) — so the registry had
    // nowhere to put "what is this application called when it talks to us that
    // way", which is a fact an operator has before anything connects. They are
    // declaration and only ever declaration, exactly as appAllowedProtocol is,
    // and like it they grant and refuse nothing.
    { name: 'federationPartnerId', kind: 'multi', from: 'the console, or by hand',
      identifier: true,
      what: 'WHAT A FEDERATION PARTNER CALLS ITSELF — a foreign identity provider\'s ' +
            'entityID, or its issuer identifier where the relationship speaks OpenID ' +
            'Connect. THE RELATIONSHIP IS NOT HERE: the endpoints, the certificate and the ' +
            'attribute mapping live under ou=federations and are what /federation/acs/{id} ' +
            'actually verifies against (see federation/CLAUDE.md). This entry is the ' +
            'partner as a PARTY, and this attribute is the name it goes by — so a value ' +
            'here federates with nobody, which is the one place in this service where that ' +
            'sentence has teeth.' },
    { name: 'ldapBindDn', kind: 'multi', from: 'the console, or by hand',
      identifier: true,
      what: 'THE DN A DIRECTORY CLIENT BINDS AS on 389 or LDAPS 636. EVERY BIND HERE ' +
            'SUCCEEDS — any DN, any password, anonymous — so nothing will ever write this ' +
            'and nothing will ever read it; it is where an operator records which ' +
            'credential an application is expected to use, beside the rest of what that ' +
            'application is.' },
    { name: 'scimClientId', kind: 'multi', from: 'the console, or by hand',
      identifier: true,
      what: 'WHAT A PROVISIONING CLIENT AT /scim/v2 IS CALLED — the OAuth client_id it ' +
            'presents a token from, or the username it sends in Basic. That surface ' +
            'authenticates its CALLER in any of the six schemes RFC 7644 section 2 names ' +
            'rather than an application identifier, so it writes nothing here; the value is ' +
            'a declaration, and scim.authRequired is what decides whether a credential is ' +
            'demanded at all.' },
    { name: 'spiffeWorkloadId', kind: 'multi', from: 'the console, or by hand',
      identifier: true,
      what: 'A SPIFFE ID this application is expected to hold — spiffe://<trust ' +
            'domain>/<path>. A SPIFFE identity gets an entry of its OWN under ou=spiffe ' +
            '(see spiffe/CLAUDE.md) and the registry there is what an SVID is actually ' +
            'issued against, so this writes nothing and reads nothing: it is the link ' +
            'between an application in this registry and an identity in that one, said by ' +
            'hand because no protocol says it.' }
  ]
};

// ---------------------------------------------------------------------------
// WHAT A CONSOLE MAY CHANGE, which is a different question from what an entry
// carries and is therefore a table of its own rather than a field on the rows
// above.
//
// The distinction is DERIVED versus DECLARED. An application entry holds both
// kinds and they must not be edited alike:
//
//   * DECLARED — what this application IS allowed to do. Its redirect URIs, its
//     grant types, its secret, whether it is confidential. Nothing about them is
//     a fact about the past; they are configuration, they are what RFC 9700 mode
//     READS, and being able to change them is the point of having a registry at
//     all. These are editable.
//
//   * DERIVED — what HAPPENED. The counters, the first and last sighting, the
//     kinds and protocols it has been seen in, the redirect URIs it has actually
//     used. A form that could rewrite those would make this page lie about the
//     service's own behaviour, and the lie would be indistinguishable from a
//     bug in the recording. These are not editable here.
//
// LDAP can still change every one of them — this directory enforces nothing and
// `ldapmodify` reaches any attribute on any entry. That is not an inconsistency
// to fix: an operator with an LDAP client is doing something deliberate, and the
// console is a set of controls somebody clicks. Refusing the derived ones HERE
// is the difference between offering an operation and merely not preventing it.
//
// `set` replaces (single-valued), `multi` adds and removes values. The mode has
// to match the attribute's own `kind` or the entry ends up with a list where the
// schema promises one value, so both are read from these two tables and never
// from a caller.
// ---------------------------------------------------------------------------
const EDITABLE = {
  appName: 'set',
  // DECLARED, which is the whole of why it is here and `appProtocol` is not.
  // See the PROTOCOLS table above: one of those two attributes is what somebody
  // said this application is for and the other is what happened to it.
  appAllowedProtocol: 'multi',
  // THE IDENTIFIER ATTRIBUTES, one per protocol family (see the PROTOCOLS
  // table). Every one of them is `multi` bar oauthTlsClientAuthSubjectDn below,
  // whose own row says why — an application answering to two client_ids or two
  // SPNs is one application, and a `set` here would replace the list with one
  // value and read afterwards as the others having been forgotten.
  oauthClientId: 'multi',
  // THE AUDIENCE, which is the identifier from the OTHER side: what a token
  // addressed to this application says in `aud`, rather than what the
  // application calls itself at the token endpoint. `multi` because a per-
  // environment hostname is the ordinary case, and because it is the one
  // attribute here something LOOKS UP — see forAudience(), and the row in
  // SCHEMA, where the difference between a lookup and a permission is spelled
  // out.
  oauthAudience: 'multi',
  oauthClientSecret: 'set',
  oauthTokenEndpointAuthMethod: 'set',
  oauthJwks: 'set',
  oauthJwksUri: 'set',
  oauthTlsClientAuthSubjectDn: 'set',
  oauthTlsClientCertificateThumbprint: 'set',
  oauthConfidential: 'set',
  appRegistrationAccessToken: 'set',
  samlEntityId: 'multi',
  // DECLARED, both of them, which is why they are here and the four SAML
  // attributes beside them are not: where a LogoutResponse goes and which
  // certificate the service provider signs with are configuration, and the
  // NameID formats it has asked for and whether its last request was signed
  // are what HAPPENED.
  samlSigningCertificate: 'set',
  samlSingleLogoutService: 'multi',
  wsfedRealm: 'multi',
  wstrustAppliesTo: 'multi',
  krb5ServicePrincipalName: 'multi',
  oid4vpClientId: 'multi',
  // The four that are ONLY ever declared — nothing in this service writes them.
  federationPartnerId: 'multi',
  ldapBindDn: 'multi',
  scimClientId: 'multi',
  spiffeWorkloadId: 'multi',
  oauthRedirectUri: 'multi',
  oauthPostLogoutRedirectUri: 'multi',
  oauthFrontchannelLogoutUri: 'set',
  oauthFrontchannelLogoutSessionRequired: 'set',
  oauthGrantType: 'multi',
  oauthResponseType: 'multi',
  oauthScope: 'multi',
  samlAssertionConsumerService: 'multi',
  // WS-Federation's return address, which used to be recorded in the attribute
  // above. Its own row says why the two were split.
  wsfedReplyUrl: 'multi',
  description: 'multi'
};

// Merged onto the rows so that one table answers "what is this attribute?" and
// "may I change it?" — the console builds its two selects from it and the action
// validates against the same thing, which is what stops a form offering a field
// the action would refuse.
SCHEMA.attributes.forEach(function (row) {
  row.editable = EDITABLE[row.name] || false;
});

const ATTRIBUTE_BY_NAME = {};
SCHEMA.attributes.forEach(function (row) { ATTRIBUTE_BY_NAME[row.name] = row; });

function editableAttributes(mode) {
  return SCHEMA.attributes.filter(function (row) {
    return mode ? row.editable === mode : !!row.editable;
  });
}

// ---------------------------------------------------------------------------
// THE ATTRIBUTES A DECLARATION IS MADE OF, ONE ROW PER ATTRIBUTE AND NOT ONE
// PER FAMILY.
//
// `/admin/applications/new` draws a field for each of these and `GET
// /admin-api/applications/new` publishes them, so the form and the document a
// caller reads to learn what it may send come off ONE walk of the PROTOCOLS
// table. Building the list in the console instead was the obvious thing and it
// is exactly the drift this module exists to prevent: the page would have had
// its own idea of which attribute a family's identifier goes in, and
// `createApplication()` would have had another.
//
// **IT IS DEDUPED BY ATTRIBUTE**, which is what makes it fourteen rows for
// fourteen families rather than fourteen for fourteen by coincidence. Three
// families name `oauthClientId` and two name `samlEntityId`, because the
// specifications genuinely share those identifiers — see the PROTOCOLS header —
// so a row carries the LIST of families it serves and the form says so under
// the field. Two inputs writing one attribute would be a form that silently
// dropped whichever the reader filled in second.
//
// The order is first appearance in the PROTOCOLS table, with a family's
// identifier ahead of its redirect URI, so the fields read in the order the
// checkboxes above them do.
// ---------------------------------------------------------------------------
function declarationAttributes() {
  log.debug("Entering declarationAttributes().");
  const rows = [];
  const byAttribute = {};
  function note(attribute, role, family) {
    if (!attribute) {
      return;
    }
    const schemaRow = ATTRIBUTE_BY_NAME[attribute];
    if (!schemaRow) {
      // A family naming an attribute the schema does not have. It cannot be
      // written — setField() refuses it — so drawing a field for it would be
      // offering a control whose only outcome is a silent no. Warned rather
      // than thrown for the reason setField() warns: this is a table somebody
      // edited, and the service starting is more useful than it not.
      log.warn('applications: the protocol table names "' + attribute + '" as an ' +
               'attribute and SCHEMA.attributes has no such row. No field is offered for ' +
               'it. Add the row rather than removing the reference.');
      return;
    }
    if (!byAttribute[attribute]) {
      byAttribute[attribute] = {
        attribute: attribute,
        role: role,
        kind: schemaRow.kind,
        editable: schemaRow.editable,
        sensitive: !!schemaRow.sensitive,
        what: schemaRow.what,
        families: []
      };
      rows.push(byAttribute[attribute]);
    }
    byAttribute[attribute].families.push({ id: family.id, label: family.label });
  }
  PROTOCOLS.forEach(function (family) {
    note(family.identifierAttribute, 'identifier', family);
    note(family.redirectAttribute, 'redirect', family);
  });
  log.debug("Leaving declarationAttributes(). " + rows.length + " attribute(s) for " +
            PROTOCOLS.length + " family/families.");
  return rows;
}

const DECLARATION_ATTRIBUTE_NAMES = declarationAttributes().map(function (row) {
  return row.attribute;
});

// ---------------------------------------------------------------------------
// THE VALUES A CREATE MAY CARRY, validated whole before anything is written.
//
// Same rule the protocol families go through one function above and for the
// same reason: a create that half-succeeded — the entry there, one field
// silently dropped — is worse than a refusal, because what is left reads as a
// complete declaration of what somebody typed.
//
// **THE GATE IS `EDITABLE`, NOT THE SCHEMA.** An attribute has to be in the
// table AND declared rather than derived: a create that could set
// `appAuthentications` or `appProtocol` would let a form assert that things had
// happened, which is the line this module's EDITABLE header draws and the one
// `updateApplication()` already refuses at. So this refuses the derived ones by
// name and says which they are, rather than writing them and leaving the page
// to lie.
//
// A `single` attribute given several values is REFUSED rather than truncated.
// Taking the first would be a form quietly keeping one of two things a person
// typed, and the only single-valued identifier here is the one an RFC 8705
// check compares by exact string — where quietly keeping one is precisely the
// wrong answer.
// ---------------------------------------------------------------------------
function normaliseFields(value) {
  log.debug("Entering normaliseFields().");
  const asked = (value && typeof value === 'object') ? value : {};
  const errors = [];
  const fields = {};
  Object.keys(asked).forEach(function (name) {
    const values = valuesOf(asked[name]);
    if (!values.length) {
      // An empty box is not a value and is not an error either. Every field on
      // the create form is optional, so most of them arrive empty on every
      // post.
      return;
    }
    const row = ATTRIBUTE_BY_NAME[name];
    if (!row) {
      errors.push('"' + name + '" is not in the published schema. GET /ldap/applications ' +
                  'lists every attribute an entry may carry; adding one that is not there ' +
                  'means adding a row to SCHEMA.attributes, not writing it through this.');
      return;
    }
    if (!row.editable) {
      errors.push('"' + name + '" cannot be given here. It is DERIVED — what has happened ' +
                  'to this application rather than what it may do — and an entry created ' +
                  'with one would be asserting a past it does not have. It is accumulated ' +
                  'by the protocol endpoints as they accept this identifier.');
      return;
    }
    if (row.kind !== 'multi' && values.length > 1) {
      errors.push('"' + name + '" holds ONE value and ' + values.length + ' were given. ' +
                  'It is single-valued in the published schema, so the alternative to ' +
                  'refusing this is keeping one of them and discarding the rest silently.');
      return;
    }
    fields[name] = row.kind === 'multi' ? values : values[0];
  });
  log.debug("Leaving normaliseFields(). " + Object.keys(fields).length + " field(s), " +
            errors.length + " error(s).");
  return { ok: !errors.length, fields: fields, errors: errors };
}

// ---------------------------------------------------------------------------
// THE STORE IS THE DIRECTORY. These are the only ways in and out of it.
//
// `ldap_server.js` fills this at its require time with four functions:
//
//   readApplication(identifier)   the entry, or null
//   writeApplication(identifier, attributes)  create or update it
//   allApplications()             every entry, in tree order
//   countApplications()           how many there are, for the cap message
//
// The two directions are DELIBERATELY NOT SYMMETRICAL, which is worth saying
// because it looks like an oversight. A WRITE speaks in ATTRIBUTE OBJECTS
// ({name: [values]}) — that is all a record has to say, and the conversion is
// this module's because this module owns the schema. A READ hands back the
// whole ENTRY:
//
//   { dn, origin, createdAt, modifiedAt, operational: [...], attributes: {...} }
//
// the same shape ldap_server.js's objectFor() gives the console for a person.
// It has to be the entry rather than the attributes, because THE DN IS NOT AN
// ATTRIBUTE — it is the key the entry is stored under — so a caller handed only
// `attributes` had no way to learn where in the tree the application lives, and
// every applications page could show the `cn` and nothing else. That was the
// bug. `attributes` now also arrives CANONICALLY SPELLED and with the
// operational attributes included, `entryDN` among them, which is why every
// lookup below goes through byLowerName() rather than indexing the map.
// ---------------------------------------------------------------------------
let directory = null;
let warnedAboutNoDirectory = false;

function setDirectory(fns) {
  log.debug("Entering setDirectory().");
  directory = fns || null;
  log.debug("Leaving setDirectory(). The registry " +
            (directory ? "is now backed by the directory." : "has no store."));
}

// Every read and every write goes through here, so the "there is no store"
// case is answered in one place and complained about once rather than per call.
function store() {
  log.debug("Entering store().");
  if (directory) {
    log.debug("Leaving store().");
    return directory;
  }
  if (!warnedAboutNoDirectory) {
    warnedAboutNoDirectory = true;
    log.warn('applications: ldap_server.js was never required, so there is no ' +
             'ou=applications container and therefore no application registry. ' +
             'This module keeps no store of its own on purpose — a fallback Map ' +
             'would be a second source of truth, and it would be the one that ' +
             'silently disagreed. Every query answers empty until that module ' +
             'is loaded.');
  }
  log.debug("Leaving store().");
  return null;
}

function generalizedTime(when) {
  const d = when ? new Date(when) : new Date();
  const pad = function (n) { return String(n).padStart(2, '0'); };
  return d.getUTCFullYear() + pad(d.getUTCMonth() + 1) + pad(d.getUTCDate()) +
         pad(d.getUTCHours()) + pad(d.getUTCMinutes()) + pad(d.getUTCSeconds()) + 'Z';
}

function fromGeneralizedTime(value) {
  const text = String(value || '');
  const m = text.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/);
  if (!m) {
    return 0;
  }
  return Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]);
}

// A short, stable name for an identifier too long to be a readable RDN. The
// same device didUid() uses on a DID, for the same reason and with the same
// consequence: the cn is then NOT the identity — `appIdentifier` is, and that
// is the attribute every lookup here searches on.
function shortName(identifier) {
  return 'app-' + crypto.createHash('sha256').update(String(identifier), 'utf8')
    .digest('hex').slice(0, 12);
}

const MAX_RDN_LENGTH = 64;

function labelFor(identifier) {
  const text = String(identifier);
  return text.length <= MAX_RDN_LENGTH ? text : shortName(text);
}

// ---------------------------------------------------------------------------
// THE TWO CONVERSIONS, which are the whole of what "a schema" means here.
//
// A record is the convenient shape; the attributes are what is stored. Both are
// built by WALKING `SCHEMA.attributes` rather than by naming each one, so a row
// added to that table reaches the directory, the page and the JSON view with no
// second edit. That property is the reason to have a table at all — it is the
// lesson vc_claims.js writes down about an issuer advertising five claims and
// minting fourteen.
// ---------------------------------------------------------------------------
function valuesOf(value) {
  if (value === undefined || value === null || value === '') {
    return [];
  }
  return (Array.isArray(value) ? value : [value])
    .map(function (one) { return String(one); })
    .filter(function (one) { return one !== ''; });
}

function attributesFor(record) {
  log.debug("Entering attributesFor(). identifier=" + record.identifier);
  const attributes = {
    objectClass: SCHEMA.objectClasses.map(function (one) { return one.name; }),
    cn: [labelFor(record.identifier)],
    appIdentifier: [record.identifier],
    appName: [record.name || record.identifier],
    appKind: record.kinds.slice(0),
    appProtocol: record.protocols.slice(0),
    appFirstSeen: [generalizedTime(record.firstAt)],
    appLastSeen: [generalizedTime(record.lastAt)],
    appAuthentications: [String(record.authentications)],
    appSessions: [String(record.sessions.length)],
    appUsers: [String(record.users.length)],
    appRegistered: [record.registered ? 'TRUE' : 'FALSE'],
    description: record.descriptions.slice(0)
  };
  // The protocol-specific half, from the table. Anything not in the table was
  // refused at setField() and cannot get here.
  Object.keys(record.fields).forEach(function (name) {
    if (attributes[name] === undefined) {
      attributes[name] = valuesOf(record.fields[name]);
    }
  });
  // Two operational counts that are NOT attributes and must not become them:
  // the distinct session and user ids themselves. An application used by two
  // thousand people would otherwise put two thousand values on one entry, and
  // the count is the fact anybody wanted.
  // An attribute with NO VALUES is not an attribute. LDAP has no such thing —
  // the last value takes the attribute with it, which is what the modify handler
  // in ldap_server.js does for every other entry — so an empty list is dropped
  // here rather than stored. Without this a hand-created application carries an
  // `appProtocol` with nothing in it, which reads on every page and in every
  // ldapsearch as a protocol whose name went missing.
  Object.keys(attributes).forEach(function (name) {
    const values = attributes[name];
    if (Array.isArray(values) && !values.length) {
      delete attributes[name];
    }
  });
  log.debug("Leaving attributesFor(). " + Object.keys(attributes).length + " attribute(s).");
  return attributes;
}

// Attribute names arrive from the directory in one of TWO spellings and every
// lookup here has to survive both. The store lower-cases them, because
// @ldapjs/attribute lower-cases a type on the way in; readApplication() then
// puts the CANONICAL spelling back so that a page does not show `oauthclientid`
// beside a published schema that says `oauthClientId`. So an index that assumed
// either one would silently find nothing — and finding nothing here does not
// throw, it produces a record with an empty identifier and no fields, which
// reads as an application that lost its attributes rather than as a lookup that
// missed. LDAP attribute descriptions are case-insensitive anyway (RFC 4512
// section 2.5), so folding is the correct answer and not merely the defensive
// one.
function byLowerName(attributes) {
  const index = {};
  Object.keys(attributes || {}).forEach(function (name) {
    index[String(name).toLowerCase()] = attributes[name];
  });
  return index;
}

function firstValue(attributes, name) {
  const values = attributes[String(name).toLowerCase()];
  return (values && values.length) ? String(values[0]) : '';
}

function allValues(attributes, name) {
  const values = attributes[String(name).toLowerCase()];
  return (values || []).map(function (one) { return String(one); });
}

function recordFromAttributes(attributes) {
  log.debug("Entering recordFromAttributes().");
  const attrs = byLowerName(attributes);
  const record = {
    identifier: firstValue(attrs, 'appIdentifier'),
    label: firstValue(attrs, 'cn'),
    name: firstValue(attrs, 'appName'),
    kinds: allValues(attrs, 'appKind'),
    protocols: allValues(attrs, 'appProtocol'),
    descriptions: allValues(attrs, 'description'),
    firstAt: fromGeneralizedTime(firstValue(attrs, 'appFirstSeen')),
    lastAt: fromGeneralizedTime(firstValue(attrs, 'appLastSeen')),
    authentications: parseInt(firstValue(attrs, 'appAuthentications') || '0', 10) || 0,
    // Read back as COUNTS. The identities behind them are not on the entry (see
    // attributesFor()), so a record reconstructed from the directory can add to
    // these numbers but cannot tell whether a session it is now seeing was
    // already counted — which is stated in seen() where it matters.
    sessions: [],
    users: [],
    sessionCount: parseInt(firstValue(attrs, 'appSessions') || '0', 10) || 0,
    userCount: parseInt(firstValue(attrs, 'appUsers') || '0', 10) || 0,
    registered: firstValue(attrs, 'appRegistered') === 'TRUE',
    fields: {}
  };
  SCHEMA.attributes.forEach(function (row) {
    // The computed ones above are not fields; reading them back as fields would
    // put two copies of appKind on the next write.
    if (['appIdentifier', 'cn', 'appName', 'appKind', 'appProtocol', 'description',
         'appFirstSeen', 'appLastSeen', 'appAuthentications', 'appSessions',
         'appUsers', 'appRegistered'].indexOf(row.name) >= 0) {
      return;
    }
    const values = allValues(attrs, row.name);
    if (!values.length) {
      return;
    }
    record.fields[row.name] = row.kind === 'multi' ? values : values[0];
  });
  log.debug("Leaving recordFromAttributes(). identifier=" + record.identifier);
  return record;
}

function blankRecord(identifier) {
  return {
    identifier: String(identifier),
    label: labelFor(identifier),
    name: String(identifier),
    kinds: [],
    protocols: [],
    descriptions: [],
    firstAt: 0,
    lastAt: 0,
    authentications: 0,
    sessions: [],
    users: [],
    sessionCount: 0,
    userCount: 0,
    registered: false,
    fields: {}
  };
}

// Read one application out of the directory, or a blank record if it is not
// there yet. `known` says which, because the caller has to tell a first sight
// from a repeat and cannot infer it from an empty record.
//
// `entry` is the third thing it returns and it is NOT derivable from the other
// two: it carries the DN, the origin and the timestamps, none of which is an
// attribute of the record. Callers that only want to write ignore it — a write
// is built from the record — and the two callers that render an application read
// it, because "where does this entry live" is the question the pages could not
// answer. It is null when there is no directory, which is a different state from
// an entry with nothing on it and the pages say so.
function load(identifier) {
  const backing = store();
  if (!backing) {
    return { record: blankRecord(identifier), known: false, entry: null };
  }
  const entry = backing.readApplication(String(identifier));
  if (!entry) {
    return { record: blankRecord(identifier), known: false, entry: null };
  }
  return { record: recordFromAttributes(entry.attributes), known: true, entry: entry };
}

function save(record) {
  const backing = store();
  if (!backing) {
    return false;
  }
  return !!backing.writeApplication(record.identifier, attributesFor(record));
}

function addTo(list, value) {
  const text = String(value == null ? '' : value).trim();
  if (!text || list.indexOf(text) >= 0) {
    return false;
  }
  list.push(text);
  return true;
}

// Set a schema field, honouring the row's `kind`: multi accumulates, single is
// assigned. The one place that distinction is applied, so a caller cannot get
// it wrong per attribute — and an attribute that is not in the table is REFUSED
// rather than written, which is what keeps the published schema true.
function setField(record, name, value) {
  log.debug("Entering setField().");
  const row = ATTRIBUTE_BY_NAME[name];
  if (!row) {
    log.warn('applications: "' + name + '" is not in the schema and was not recorded. ' +
             'Add a row to SCHEMA.attributes rather than writing an attribute nothing ' +
             'publishes.');
    log.debug("Leaving setField().");
    return false;
  }
  if (value === undefined || value === null || value === '') {
    log.debug("Leaving setField().");
    return false;
  }
  if (row.kind === 'multi') {
    if (!record.fields[name]) record.fields[name] = [];
    let changed = false;
    (Array.isArray(value) ? value : [value]).forEach(function (one) {
      if (addTo(record.fields[name], one)) changed = true;
    });
    log.debug("Leaving setField().");
    return changed;
  }
  const text = String(value);
  if (record.fields[name] === text) {
    log.debug("Leaving setField().");
    return false;
  }
  record.fields[name] = text;
  log.debug("Leaving setField().");
  return true;
}

// ---------------------------------------------------------------------------
// SEEN — the one way an application gets into this registry.
//
// Called wherever a protocol ACCEPTS an application identifier, which is not
// the same moment as accepting a credential and therefore not the same funnel.
// That is worth stating because the user side has exactly one funnel and this
// side cannot: `admin_stats.recordAuthentication()` is reached when a PERSON is
// authenticated, and in the authorization code flow that happens in `authn.js`,
// which knows nothing about OAuth by design — the sign-in screen never reads a
// client_id. So the application is recorded where its own protocol decides it
// is real, and each of those points is named in the module that owns it.
//
// `detail` carries whatever that protocol knows:
//
//   identifier  REQUIRED — the client_id, wtrealm, AppliesTo, SPN, entityID
//   kind        one of KIND_IDS, or a LIST of them where an application is
//               genuinely several things at once — a wtrealm is both a
//               WS-Federation application and the audience of the assertion it
//               was handed. A list is one sighting and counts once
//   protocol    the family name, as /admin/users spells it
//   name        a friendly name, where there is one
//   fields      {schemaAttribute: value}, applied through setField()
//   sessionId   the sign-on session this happened on, when there is one
//   user        the identity key of whoever authenticated, when there is one
//   counts      false to record the appearance WITHOUT counting an
//               authentication — an authorization request is not an
//               authentication, and counting one there would double every
//               code flow
//
// ON THE DISTINCT COUNTS. `appSessions` and `appUsers` are counts of distinct
// ids, and the ids themselves are deliberately not kept on the entry — so this
// function cannot check whether the session it is looking at was already
// counted. It increments when the caller passes one that differs from the LAST
// one recorded, which is right for the ordinary case (a session signs in to an
// application once) and undercounts a person who alternates between two
// applications and back. That is the honest trade for not putting an unbounded
// list of session ids in a directory entry, and it is why the schema calls
// these counts rather than lists.
// ---------------------------------------------------------------------------
function seen(detail) {
  log.debug("Entering seen().");
  const info = detail || {};
  const identifier = String(info.identifier == null ? '' : info.identifier).trim();
  // Normalised ONCE, because three lines below print it and a bare `info.kind`
  // renders a list as "a,b" in one of them and not in the others.
  const statedKinds = (Array.isArray(info.kind) ? info.kind : [info.kind])
    .filter(Boolean).map(function (one) { return String(one); });
  const kindPhrase = statedKinds.length ? ' (' + statedKinds.join(', ') + ')' : '';
  log.debug("Entering seen(). identifier=" + (identifier || '(none)') +
            ", kind=" + (statedKinds.join(', ') || '(unstated)'));
  if (!identifier) {
    log.debug("Leaving seen(). There was no identifier to record.");
    log.debug("Leaving seen().");
    return null;
  }
  const loaded = load(identifier);
  const record = loaded.record;
  const known = loaded.known;
  const now = Date.now();
  let changed = !known;

  // ONE SIGHTING MAY NAME SEVERAL KINDS, and two protocols need it to. A
  // wtrealm handed a SAML 1.1 assertion is a WS-Federation application AND the
  // audience of that assertion — both are true of the same request, and the
  // registry accumulates rather than choosing. Passing a list rather than
  // calling seen() twice matters: a second call would count a second
  // authentication for one act, which is the trap `counts: false` exists for
  // one field over.
  statedKinds.forEach(function (kind) {
    if (KIND_IDS.indexOf(kind) < 0) {
      log.warn('applications: "' + kind + '" is not one of the kinds this registry ' +
               'knows (' + KIND_IDS.join(', ') + '). It is recorded as given, which is ' +
               'how one application comes to be listed under two spellings — fix the ' +
               'caller or add a row to KINDS.');
    }
    if (addTo(record.kinds, kind)) changed = true;
  });
  if (info.protocol && addTo(record.protocols, info.protocol)) changed = true;
  if (info.name) {
    const name = String(info.name);
    if (record.name !== name) {
      record.name = name;
      changed = true;
    }
  }
  if (info.note && addTo(record.descriptions, info.note)) changed = true;

  Object.keys(info.fields || {}).forEach(function (name) {
    if (setField(record, name, info.fields[name])) changed = true;
  });

  record.firstAt = record.firstAt || now;
  record.lastAt = now;
  if (info.counts !== false) {
    record.authentications++;
    changed = true;
  }
  // See the note above about what these can and cannot know.
  if (info.sessionId && record.fields.appLastSession !== String(info.sessionId)) {
    record.sessionCount++;
    setField(record, 'appLastSession', info.sessionId);
    changed = true;
  }
  if (info.user && record.fields.appLastUser !== String(info.user)) {
    record.userCount++;
    setField(record, 'appLastUser', info.user);
    changed = true;
  }
  record.sessions = new Array(record.sessionCount);
  record.users = new Array(record.userCount);

  if (!changed) {
    log.debug("Leaving seen(). It was already known and said nothing new.");
    log.debug("Leaving seen().");
    return record;
  }
  save(record);

  if (!known) {
    log.info('applications: first sight of "' + identifier + '"' +
             kindPhrase + '. ' + count() +
             ' application(s) in the directory.');
  }

  // The audit row. `application.create` on first sight and
  // `application.update` when an existing record learned something — never for
  // a repeat that changed nothing, or every token request would produce a row
  // saying nothing happened.
  //
  // audit() cannot throw (see its header) and carries no credential: neither
  // the client secret nor the registration access token that may be on this
  // record is ever a field here.
  audit.audit({
    action: known ? 'application.update' : 'application.create',
    actor: info.user || '',
    protocol: String(info.protocol || 'unstated'),
    channel: 'internal',
    target: identifier,
    summary: (known ? 'Application "' : 'A new application "') + identifier +
             (known ? '" recorded something new' : '" was seen for the first time') +
             kindPhrase,
    detail: {
      identifier: identifier,
      kinds: record.kinds.join(', '),
      protocols: record.protocols.join(', '),
      authentications: record.authentications,
      registered: record.registered
    }
  });
  log.debug("Leaving seen(). " + (known ? "It was already known." : "It is new."));
  log.debug("Leaving seen().");
  return record;
}

// ---------------------------------------------------------------------------
// DYNAMIC CLIENT REGISTRATION (RFC 7591) LIVES IN THE DIRECTORY.
//
// It used to be a `registeredClients` Map in oauth2.js. It moved for the
// one-store rule: this registry would otherwise hold half of what is known
// about a client and that Map the other half, and the first time the two
// disagreed about a redirect URI it would be an RFC 9700 refusal nobody could
// explain. oauth2.js now reads through `registrationOf()` and writes through
// these three functions, which is the same number of call sites it had.
//
// The document is stored WHOLE in `appRegistrationJson` — see that row in the
// schema for why an attribute set cannot replace it — and the members that DO
// have attributes are written to them as well, because those attributes are
// what the checks read and what an operator edits.
// ---------------------------------------------------------------------------
function applyRegistrationFields(record, registration) {
  log.debug("Entering applyRegistrationFields().");
  const meta = registration || {};
  setField(record, 'appRegistrationJson', JSON.stringify(meta));
  setField(record, 'appRegistrationAccessToken', meta.registration_access_token);
  setField(record, 'oauthClientId', record.identifier);
  setField(record, 'oauthClientSecret', meta.client_secret);
  // RFC 7591's key members. `jwks` is stored as text because that is what the
  // verifier parses and what an operator edits; `jwks_uri` is recorded and never
  // followed (see its schema row).
  if (meta.jwks) {
    setField(record, 'oauthJwks',
             typeof meta.jwks === 'string' ? meta.jwks : JSON.stringify(meta.jwks));
  }
  setField(record, 'oauthJwksUri', meta.jwks_uri);
  setField(record, 'oauthTlsClientAuthSubjectDn', meta.tls_client_auth_subject_dn);
  setField(record, 'oauthRedirectUri', meta.redirect_uris);
  setField(record, 'oauthPostLogoutRedirectUri', meta.post_logout_redirect_uris);
  // Front-Channel Logout 1.0 section 2. The boolean is written as the string
  // TRUE/FALSE the directory holds, and only when the registration SAID
  // something: RFC 7591 section 2 makes an omitted member false, but "false"
  // and "not stated" are different facts about a client and this registry
  // records which one happened. clientConfigOf() below applies the default.
  setField(record, 'oauthFrontchannelLogoutUri', meta.frontchannel_logout_uri);
  if (meta.frontchannel_logout_session_required !== undefined) {
    setField(record, 'oauthFrontchannelLogoutSessionRequired',
             meta.frontchannel_logout_session_required ? 'TRUE' : 'FALSE');
  }
  setField(record, 'oauthGrantType', meta.grant_types);
  setField(record, 'oauthResponseType', meta.response_types);
  if (meta.scope) setField(record, 'oauthScope', String(meta.scope).split(/\s+/));
  // RFC 7591 section 2: an omitted method means client_secret_basic, so the
  // attribute states the EFFECTIVE value rather than the absence. An entry
  // saying nothing here would read as "unknown", and RFC 9700 mode's answer for
  // this client is not unknown — it is confidential.
  const method = meta.token_endpoint_auth_method === undefined
    ? 'client_secret_basic' : String(meta.token_endpoint_auth_method);
  setField(record, 'oauthTokenEndpointAuthMethod', method);
  setField(record, 'oauthConfidential', method && method !== 'none' ? 'TRUE' : 'FALSE');
  log.debug("Leaving applyRegistrationFields().");
}

function register(clientId, registration) {
  log.debug("Entering register(). client_id=" + clientId);
  const loaded = load(clientId);
  const record = loaded.record;
  const now = Date.now();
  record.registered = true;
  record.firstAt = record.firstAt || now;
  record.lastAt = now;
  addTo(record.kinds, 'oauth2-client');
  addTo(record.protocols, 'OAuth 2.0');
  addTo(record.descriptions, 'registered through RFC 7591 dynamic client registration');
  if (registration.client_name) record.name = String(registration.client_name);
  applyRegistrationFields(record, registration);
  const written = save(record);
  audit.audit({
    action: loaded.known ? 'application.update' : 'application.create',
    actor: '', protocol: 'OAuth 2.0', channel: 'internal',
    target: String(clientId),
    summary: 'Client "' + clientId + '" registered through RFC 7591',
    detail: { identifier: String(clientId), registered: true,
              redirectUris: (registration.redirect_uris || []).length,
              storedInDirectory: written }
  });
  if (!written) {
    log.warn('applications: client "' + clientId + '" was registered but could not be ' +
             'stored — there is no directory (see store()) or it is full. The response ' +
             'to the client is still correct; the RFC 7592 management operations on it ' +
             'will answer 404, because the directory is where they read from.');
  }
  log.debug("Leaving register().");
  return record;
}

function updateRegistration(clientId, registration) {
  log.debug("Entering updateRegistration(). client_id=" + clientId);
  const loaded = load(clientId);
  if (!loaded.known) {
    log.debug("Leaving updateRegistration(). No such application.");
    return null;
  }
  const record = loaded.record;
  record.lastAt = Date.now();
  if (registration.client_name) record.name = String(registration.client_name);
  applyRegistrationFields(record, registration);
  save(record);
  log.debug("Leaving updateRegistration().");
  return record;
}

// RFC 7592's delete. The REGISTRATION goes; the application entry stays, with
// `appRegistered` back to FALSE. That is not a half-measure — this registry
// records what this service has SEEN, and deleting the history of an
// application because its registration was withdrawn would lose the fact that
// it was ever here. It is also what RFC 9700 mode needs to be right about the
// client afterwards: an unregistered client_id is judged against the
// oauth2.redirectUris setting and treated as public, which is exactly what it
// now is.
//
// The secret and the registration access token are REMOVED with it rather than
// left on the entry: they are credentials for a registration that no longer
// exists, and an entry that kept them would let the deleted client go on
// authenticating in RFC 9700 mode.
function forgetRegistration(clientId) {
  log.debug("Entering forgetRegistration(). client_id=" + clientId);
  const loaded = load(clientId);
  if (!loaded.known) {
    log.debug("Leaving forgetRegistration(). No such application.");
    return false;
  }
  const record = loaded.record;
  record.registered = false;
  delete record.fields.appRegistrationJson;
  delete record.fields.appRegistrationAccessToken;
  delete record.fields.oauthClientSecret;
  setField(record, 'oauthConfidential', 'FALSE');
  addTo(record.descriptions, 'its RFC 7592 registration was deleted');
  record.lastAt = Date.now();
  save(record);
  log.debug("Leaving forgetRegistration(). The registration is gone; the entry stays.");
  return true;
}

// What oauth2.js's `registeredClients.get(id)` used to answer: the RFC 7591
// record, or null for an application that merely turned up. "Registered" is the
// distinction RFC 9700 mode's redirect URI and client authentication rules turn
// on, so an application with no registration must answer null rather than a
// half-filled object.
//
// THE ATTRIBUTES WIN. The stored document is the starting point — it is the only
// thing that can carry a member with no attribute of its own — and then every
// member that has one is overwritten from it. That is what makes an
// `ldapmodify` of `oauthRedirectUri` a configuration change rather than a note.
function registrationOf(clientId) {
  log.debug("Entering registrationOf().");
  const loaded = load(clientId);
  if (!loaded.known || !loaded.record.registered) {
    log.debug("Leaving registrationOf().");
    return null;
  }
  const record = loaded.record;
  let document = {};
  const raw = record.fields.appRegistrationJson;
  if (raw) {
    try {
      document = JSON.parse(raw);
    } catch (e) {
      // Somebody edited the attribute by hand and left it unparseable. The
      // attributes below still describe this client, so the registration is
      // rebuilt from them alone rather than the client being told it does not
      // exist — and the reason is logged, because a hand-edited entry silently
      // losing half its members is worse than either outcome.
      log.warn('applications: appRegistrationJson on "' + clientId + '" is not valid ' +
               'JSON and was ignored; the registration is rebuilt from the attributes ' +
               'beside it. ' + e.message);
      document = {};
    }
  }
  const fields = record.fields;
  if (fields.oauthClientSecret !== undefined) document.client_secret = fields.oauthClientSecret;
  if (fields.appRegistrationAccessToken !== undefined) {
    document.registration_access_token = fields.appRegistrationAccessToken;
  }
  if (fields.oauthRedirectUri) document.redirect_uris = fields.oauthRedirectUri.slice(0);
  if (fields.oauthPostLogoutRedirectUri) {
    document.post_logout_redirect_uris = fields.oauthPostLogoutRedirectUri.slice(0);
  }
  if (fields.oauthFrontchannelLogoutUri !== undefined) {
    document.frontchannel_logout_uri = fields.oauthFrontchannelLogoutUri;
  }
  if (fields.oauthFrontchannelLogoutSessionRequired !== undefined) {
    document.frontchannel_logout_session_required =
      String(fields.oauthFrontchannelLogoutSessionRequired).toUpperCase() === 'TRUE';
  }
  if (fields.oauthGrantType) document.grant_types = fields.oauthGrantType.slice(0);
  if (fields.oauthResponseType) document.response_types = fields.oauthResponseType.slice(0);
  if (fields.oauthTokenEndpointAuthMethod !== undefined) {
    document.token_endpoint_auth_method = fields.oauthTokenEndpointAuthMethod;
  }
  document.client_id = record.identifier;
  log.debug("Leaving registrationOf().");
  return document;
}

// ---------------------------------------------------------------------------
// WHAT RFC 9700 MODE READS, normalised into one object.
//
// `registrationOf()` above answers "what did this client REGISTER", which is an
// RFC 7591/7592 question. This answers a different one: "what is this client
// ALLOWED to do", which is what the security checks need — and the two stopped
// being the same question the moment the console could create an application
// and give it redirect URIs without a registration behind it.
//
// So this is built from the ATTRIBUTES and not from the registration document.
// That is the same precedence rule `registrationOf()` follows and it is the
// whole point of the directory being the source of truth: an `oauthRedirectUri`
// added by `ldapmodify`, by the console, by the management API or by
// registration is the same attribute, and the check cannot tell — or care —
// which put it there. `appRegistered` records HOW an application got here, not
// whether what it holds counts.
//
// `known: false` means this service has never seen the identifier at all, which
// is a different answer from an entry with nothing on it: the first falls back
// to the `oauth2.redirectUris` setting, the second is a client somebody has
// begun configuring and has not finished.
// ---------------------------------------------------------------------------
function clientConfigOf(identifier) {
  log.debug("Entering clientConfigOf(). identifier=" + identifier);
  const loaded = load(identifier);
  if (!loaded.known) {
    log.debug("Leaving clientConfigOf(). Never seen.");
    return { known: false, registered: false, redirect_uris: [],
             post_logout_redirect_uris: [], token_endpoint_auth_method: '',
             frontchannel_logout_uri: '', frontchannel_logout_session_required: false,
             client_secret: '' };
  }
  const fields = loaded.record.fields;
  // RFC 7591 section 2 makes client_secret_basic the default when a
  // REGISTRATION omits the member — so an omission means confidential for a
  // registered client and says nothing at all for one that was created by hand.
  // The two are told apart here rather than at the check, because this is where
  // both facts are.
  const method = fields.oauthTokenEndpointAuthMethod !== undefined
    ? String(fields.oauthTokenEndpointAuthMethod)
    : (loaded.record.registered ? 'client_secret_basic' : '');
  const config = {
    known: true,
    registered: loaded.record.registered,
    redirect_uris: (fields.oauthRedirectUri || []).slice(0),
    post_logout_redirect_uris: (fields.oauthPostLogoutRedirectUri || []).slice(0),
    // Where a sign-out notifies this client, and whether it wants to be told
    // WHICH session ended. The boolean defaults FALSE per RFC 7591 section 2's
    // rule for an omitted member — the same rule the auth method above follows
    // — so a client that registered a URI and said nothing else is notified
    // without iss and sid, which is what it asked for.
    frontchannel_logout_uri: fields.oauthFrontchannelLogoutUri === undefined
      ? '' : String(fields.oauthFrontchannelLogoutUri),
    frontchannel_logout_session_required:
      String(fields.oauthFrontchannelLogoutSessionRequired || '').toUpperCase() === 'TRUE',
    token_endpoint_auth_method: method,
    client_secret: fields.oauthClientSecret === undefined
      ? '' : String(fields.oauthClientSecret),
    // What an ASYMMETRIC method verifies against. Public key material and two
    // certificate facts — none of them a secret, which is the property RFC 9700
    // section 2.5 is recommending them for.
    jwks: fields.oauthJwks === undefined ? '' : String(fields.oauthJwks),
    jwks_uri: fields.oauthJwksUri === undefined ? '' : String(fields.oauthJwksUri),
    tls_client_auth_subject_dn: fields.oauthTlsClientAuthSubjectDn === undefined
      ? '' : String(fields.oauthTlsClientAuthSubjectDn),
    certificate_thumbprint: fields.oauthTlsClientCertificateThumbprint === undefined
      ? '' : String(fields.oauthTlsClientCertificateThumbprint)
  };
  log.debug("Leaving clientConfigOf(). " + config.redirect_uris.length +
            " redirect URI(s), method=" + (method || '(unstated)') + ".");
  return config;
}

// ---------------------------------------------------------------------------
// The authentication funnel's half of it. `admin_stats.recordAuthentication()`
// calls this for every accepted credential that names an application, which
// covers the grants where the client IS the identity (client_credentials) and
// every protocol that passes a client_id along. The protocols whose application
// identifier never reaches that funnel call `seen()` directly — see its header.
// ---------------------------------------------------------------------------
function recordAuthentication(info) {
  log.debug("Entering recordAuthentication().");
  const detail = info || {};
  const identifier = String(detail.client_id || '').trim();
  if (!identifier) {
    log.debug("Leaving recordAuthentication().");
    return null;
  }
  log.debug("Entering recordAuthentication(). client_id=" + identifier);
  const kind = detail.applicationKind || 'oauth2-client';
  // Which ATTRIBUTE the identifier lands in follows the kind, because these are
  // three different things that happen to arrive through one field: a client_id
  // at the token endpoint, the Verifier's own client_id, and a service principal
  // name. Writing all three to `oauthClientId` would put an SPN in the attribute
  // RFC 9700 mode reads, which is the sort of thing that looks harmless until
  // something enforces it.
  const fields = {};
  if (kind === 'oid4vp-verifier') {
    fields.oid4vpClientId = identifier;
  } else if (kind === 'kerberos-service') {
    fields.krb5ServicePrincipalName = identifier;
  } else {
    fields.oauthClientId = identifier;
  }
  const record = seen({
    identifier: identifier,
    kind: kind,
    protocol: detail.protocol || 'OAuth 2.0',
    sessionId: detail.sessionId || '',
    user: detail.user || '',
    note: detail.note || '',
    fields: fields
  });
  log.debug("Leaving recordAuthentication().");
  log.debug("Leaving recordAuthentication().");
  return record;
}

// ---------------------------------------------------------------------------
// WRITING — the console's and the management API's half.
//
// Every one of these does the same read-modify-write `seen()` does, through the
// same two conversions, so the console is not a second door onto this registry:
// it is the same door with a form in front of it. That is what keeps the
// one-store rule intact now that there are three ways in — the protocol
// endpoints, LDAP, and these — rather than three stores that agree until they
// do not.
//
// None of them counts an authentication. `seen()` is the only thing that does,
// because only a protocol accepting a credential is one; an operator adding a
// redirect URI has not authenticated anybody, and a counter that moved when
// somebody edited a form would make the number mean nothing.
// ---------------------------------------------------------------------------

// A name that could be a person, a group, or this service's own container. The
// registry is not the place to file one, and an entry created here with a DN
// that collides with something else in the tree is a directory problem rather
// than a refusal somebody can act on — so the shapes are refused by name.
function identifierProblem(identifier) {
  log.debug("Entering identifierProblem().");
  const text = String(identifier || '').trim();
  if (!text) {
    log.debug("Leaving identifierProblem().");
    return 'An identifier is required — the client_id, wtrealm, AppliesTo, entityID or ' +
           'service principal name this application is known by.';
  }
  if (text.length > 512) {
    log.debug("Leaving identifierProblem().");
    return 'That identifier is ' + text.length + ' characters. The longest this registry ' +
           'will hold is 512, which is already far past anything a client_id or an ' +
           'entityID should be.';
  }
  if (/[\r\n\0]/.test(text)) {
    log.debug("Leaving identifierProblem().");
    return 'An identifier cannot contain a line break or a NUL.';
  }
  log.debug("Leaving identifierProblem().");
  return null;
}

function createApplication(detail) {
  log.debug("Entering createApplication().");
  const info = detail || {};
  const identifier = String(info.identifier || '').trim();
  log.debug("Entering createApplication(). identifier=" + identifier);
  const problem = identifierProblem(identifier);
  if (problem) {
    log.debug("Leaving createApplication(). " + problem);
    log.debug("Leaving createApplication().");
    return { ok: false, errors: [problem] };
  }
  if (!store()) {
    log.debug("Leaving createApplication(). There is no directory to create it in.");
    log.debug("Leaving createApplication().");
    return { ok: false, errors: ['There is no directory loaded in this process, so there is ' +
                                 'no ou=applications container and nothing to create. The ' +
                                 'registry has no store of its own on purpose.'] };
  }
  const loaded = load(identifier);
  if (loaded.known) {
    log.debug("Leaving createApplication(). It is already here.");
    log.debug("Leaving createApplication().");
    return { ok: false, errors: ['"' + identifier + '" is already in this registry. Change ' +
                                 'what it holds instead of creating it again — an identifier ' +
                                 'names one application here whatever protocol brought it.'] };
  }
  const kind = String(info.kind || '').trim();
  if (kind && KIND_IDS.indexOf(kind) < 0) {
    log.debug("Leaving createApplication(). Unknown kind.");
    log.debug("Leaving createApplication().");
    return { ok: false, errors: ['"' + kind + '" is not one of the kinds this registry knows. ' +
                                 'The eight are: ' + KIND_IDS.join(', ') + '.'] };
  }
  // THE DECLARED PROTOCOL FAMILIES, validated before anything is written, for
  // the reason the kind above is: a create that half-succeeded — the entry
  // there, one of the ticked boxes silently dropped — is worse than a refusal,
  // because the entry then reads as a complete declaration.
  const asked = normaliseProtocols(info.protocols === undefined ? [] : info.protocols);
  if (!asked.ok) {
    log.debug("Leaving createApplication(). Unknown protocol family.");
    log.debug("Leaving createApplication().");
    return { ok: false, errors: asked.errors };
  }
  // THE ATTRIBUTES THE CREATE CARRIES — the per-family identifiers and the
  // redirect URIs the form asks for, and anything else editable a caller sends.
  // Validated before the entry exists, for the reason the families above are:
  // an entry created with a client_id and without the redirect URI somebody
  // typed beside it is an entry that reads as finished.
  //
  // THIS PARAMETER WAS BEING IGNORED. `saml2Action()` and `saml11Action()` in
  // admin.js have passed `fields: { samlEntityId: identifier }` since they were
  // written and it went nowhere — so registering a service provider from the
  // console produced an entry with no entityID on it, and the attribute only
  // appeared later when a real AuthnRequest arrived and seen() wrote it. Both
  // now work, which is a change in what those two buttons produce.
  const given = normaliseFields(info.fields);
  if (!given.ok) {
    log.debug("Leaving createApplication(). " + given.errors.length + " bad field(s).");
    log.debug("Leaving createApplication().");
    return { ok: false, errors: given.errors };
  }
  const record = loaded.record;
  const now = Date.now();
  record.firstAt = now;
  record.lastAt = now;
  if (info.name) record.name = String(info.name);
  if (kind) addTo(record.kinds, kind);
  // The declaration goes on `appAllowedProtocol` and DELIBERATELY NOT on
  // `appKind` or `appProtocol`, even though every row of the PROTOCOLS table
  // names the kind its family would produce. Ticking SAML 2.0 is a statement
  // about what this application is FOR; writing `saml2-service-provider` into
  // its kinds would be this registry claiming it has SEEN one, which is the
  // derived-versus-declared line EDITABLE's header draws, and the kinds are on
  // the wrong side of it. So the page shows what the kind WOULD be and the
  // entry says nothing until a protocol actually recognises the identifier.
  if (asked.protocols.length) {
    setField(record, 'appAllowedProtocol', asked.protocols);
  }
  // Through setField(), so a `multi` attribute accumulates and a `single` one is
  // assigned exactly as they would on any other write. The record is blank here
  // so nothing can be accumulated ONTO — but going round setField() would be a
  // second place that decision is made, and the first time the two disagreed
  // would be the first time somebody created an application over one that had
  // just been deleted.
  Object.keys(given.fields).forEach(function (name) {
    setField(record, name, given.fields[name]);
  });
  // WHERE IT CAME FROM, said on the entry itself. An application created here
  // has never authenticated anything and its counters are zero; without this
  // line a reader would have to infer that from the zeros, and "created by hand"
  // and "turned up once and never again" would look alike.
  addTo(record.descriptions, 'created from the console; nothing has authenticated for it yet');
  if (!save(record)) {
    log.debug("Leaving createApplication(). The container would not take it.");
    log.debug("Leaving createApplication().");
    return { ok: false, errors: ['The ou=applications container is full (applications.max) or ' +
                                 'the directory is. Nothing was created.'] };
  }
  audit.audit({
    action: 'application.create', actor: info.actor || '', protocol: 'console',
    channel: 'internal', target: identifier,
    summary: 'Application "' + identifier + '" was created from the console' +
             (kind ? ' (' + kind + ')' : ''),
    detail: { identifier: identifier, kind: kind || '', createdByHand: true,
              protocols: asked.protocols.join(', '),
              // The NAMES only. One of the editable attributes a create can
              // carry is oauthClientSecret, and audit.js's no-credential rule
              // is not something this caller gets to make an exception to.
              attributes: Object.keys(given.fields).join(', ') }
  });
  log.info('applications: "' + identifier + '" was created by hand' +
           (asked.protocols.length ? ', declared for ' + asked.protocols.join(', ') : '') +
           '. ' + count() + ' application(s) in the directory.');
  log.debug("Leaving createApplication(). Created.");
  log.debug("Leaving createApplication().");
  return { ok: true, application: viewAfterWrite(identifier, record) };
}

// What an action hands back about the application it just wrote: the ENTRY as
// the directory now holds it, re-read rather than reconstructed from the record
// in hand. Re-reading is not ceremony — the record does not know the DN, the
// origin or modifyTimestamp, all three of which the directory decides, so a
// reply built from it would be missing exactly the facts this shape was widened
// to carry. The fallback covers the one case where the write did not land (no
// directory attached, or the container full): the caller still gets the
// application it asked about, with `dn` null saying why.
function viewAfterWrite(identifier, record) {
  return get(identifier) || view(record, null);
}

// One attribute changed, in the mode its schema row allows. `mode` is checked
// against the row rather than trusted, because a `set` on a multi-valued
// attribute would replace a list of redirect URIs with one and read afterwards
// as the others having been forgotten.
function updateApplication(identifier, change) {
  log.debug("Entering updateApplication().");
  const asked = change || {};
  const attribute = String(asked.attribute || '');
  const mode = String(asked.mode || '');
  log.debug("Entering updateApplication(). identifier=" + identifier +
            ", attribute=" + attribute + ", mode=" + mode);
  const loaded = load(identifier);
  if (!loaded.known) {
    log.debug("Leaving updateApplication(). No such application.");
    log.debug("Leaving updateApplication().");
    return { ok: false, errors: ['There is no application called "' + identifier + '" in this ' +
                                 'registry. An entry appears when an identifier is ACCEPTED by ' +
                                 'a protocol, or when one is created here.'] };
  }
  const row = ATTRIBUTE_BY_NAME[attribute];
  if (!row) {
    log.debug("Leaving updateApplication(). Not in the schema.");
    log.debug("Leaving updateApplication().");
    return { ok: false, errors: ['"' + attribute + '" is not in the published schema. ' +
                                 'GET /ldap/applications lists every attribute an entry may ' +
                                 'carry; adding one that is not there means adding a row to ' +
                                 'SCHEMA.attributes, not writing it through this.'] };
  }
  if (!row.editable) {
    log.debug("Leaving updateApplication(). Not editable.");
    log.debug("Leaving updateApplication().");
    return { ok: false, errors: ['"' + attribute + '" is not editable here. It is DERIVED — ' +
                                 'what happened rather than what this application may do — and ' +
                                 'a form that could rewrite it would make this page lie about ' +
                                 'the service\'s own behaviour. The ' +
                                 editableAttributes().length + ' that are editable are: ' +
                                 editableAttributes().map(function (one) {
                                   return one.name;
                                 }).join(', ') + '.'] };
  }
  if (row.editable === 'set' && mode !== 'set') {
    log.debug("Leaving updateApplication().");
    return { ok: false, errors: ['"' + attribute + '" holds ONE value, so it is set rather ' +
                                 'than added to or removed from.'] };
  }
  if (row.editable === 'multi' && mode !== 'add' && mode !== 'remove') {
    log.debug("Leaving updateApplication().");
    return { ok: false, errors: ['"' + attribute + '" holds a LIST, so values are added and ' +
                                 'removed rather than set — a set would replace the list with ' +
                                 'one value and read afterwards as the others having been ' +
                                 'forgotten.'] };
  }
  const value = String(asked.value == null ? '' : asked.value);
  if (mode !== 'set' && !value) {
    log.debug("Leaving updateApplication().");
    return { ok: false, errors: ['A value is required to ' + mode + '.'] };
  }
  // THE ONE EDITABLE ATTRIBUTE WITH A CLOSED VOCABULARY, checked here so that
  // this edit and the create form cannot disagree about what a protocol family
  // is — a `create` that refuses "saml-2" beside an `add` that records it would
  // leave the registry holding two spellings of one family, which is the exact
  // failure the KINDS table's comment describes.
  //
  // ONLY AN ADD IS CHECKED, deliberately. A remove has to name a value that is
  // ALREADY on the entry, and `ldapmodify` reaches this attribute like every
  // other — so refusing to remove a value this table does not recognise would
  // shut the one door that could tidy up what LDAP had put there.
  if (attribute === 'appAllowedProtocol' && mode === 'add') {
    const known = normaliseProtocols(value);
    if (!known.ok) {
      log.debug("Leaving updateApplication(). Unknown protocol family.");
      return { ok: false, errors: known.errors };
    }
  }
  const record = loaded.record;
  let changed = false;
  let what = '';

  // `appName` and `description` are not schema FIELDS — they are computed from
  // the record in attributesFor() — so they are written to the record itself.
  // Everything else is a field. This is the one place that distinction leaks out
  // of the two conversions, and it leaks here rather than into the caller.
  if (attribute === 'appName') {
    changed = record.name !== value;
    record.name = value;
    what = 'appName is now "' + value + '"';
  } else if (attribute === 'description') {
    if (mode === 'add') {
      changed = addTo(record.descriptions, value);
      what = 'added a description';
    } else {
      const before = record.descriptions.length;
      record.descriptions = record.descriptions.filter(function (one) { return one !== value; });
      changed = record.descriptions.length !== before;
      what = 'removed a description';
    }
  } else if (mode === 'set') {
    changed = setField(record, attribute, value);
    // setField() ignores an empty value, which is how a caller CLEARS one — so
    // the clear is done here rather than left as a silent no-op that reads as
    // the form not working.
    if (!value && record.fields[attribute] !== undefined) {
      delete record.fields[attribute];
      changed = true;
    }
    what = value ? attribute + ' is now "' + value + '"' : attribute + ' was cleared';
  } else if (mode === 'add') {
    changed = setField(record, attribute, value);
    what = 'added "' + value + '" to ' + attribute;
  } else {
    const have = record.fields[attribute] || [];
    const left = have.filter(function (one) { return one !== value; });
    changed = left.length !== have.length;
    if (left.length) {
      record.fields[attribute] = left;
    } else {
      // The last value takes the attribute with it, which is what the LDAP
      // modify handler in ldap_server.js does for every other entry (result
      // code 16 territory) and what an operator reading this directory with an
      // LDAP client will expect to see.
      delete record.fields[attribute];
    }
    what = 'removed "' + value + '" from ' + attribute;
  }

  if (!changed) {
    log.debug("Leaving updateApplication(). Nothing changed.");
    log.debug("Leaving updateApplication().");
    return { ok: true, changed: false, application: viewAfterWrite(identifier, record),
             message: 'Nothing changed: ' + attribute + ' already said that.' };
  }
  record.lastAt = record.lastAt || Date.now();
  save(record);
  audit.audit({
    action: 'application.update', actor: asked.actor || '', protocol: 'console',
    channel: 'internal', target: String(identifier),
    summary: 'Application "' + identifier + '": ' + what,
    // The ATTRIBUTE is named and the value is not, because two of the editable
    // attributes are credentials. That is the same rule every LDAP row in this
    // service follows and it is why it is applied here rather than judged per
    // attribute — a rule with an exception in it is one somebody will get wrong
    // when the next credential attribute is added.
    detail: { identifier: String(identifier), attribute: attribute, mode: mode,
              editedByHand: true }
  });
  log.info('applications: "' + identifier + '" — ' + what + '.');
  log.debug("Leaving updateApplication(). " + what + ".");
  log.debug("Leaving updateApplication().");
  return { ok: true, changed: true, application: viewAfterWrite(identifier, record),
           message: what + '.' };
}

// The entry goes entirely. Different from forgetRegistration(), which keeps it
// and takes only the registration away: this is for an application that should
// not be in the registry at all — a client_id somebody typed wrong, a realm from
// a test that is over. It is the one operation here that LOSES a fact, so it
// says so in the message rather than reporting a tidy success.
function deleteApplication(identifier, options) {
  log.debug("Entering deleteApplication().");
  const opts = options || {};
  log.debug("Entering deleteApplication(). identifier=" + identifier);
  const backing = store();
  if (!backing || !backing.deleteApplication) {
    log.debug("Leaving deleteApplication(). There is no directory.");
    log.debug("Leaving deleteApplication().");
    return { ok: false, errors: ['There is no directory loaded in this process, so there is ' +
                                 'nothing to delete from.'] };
  }
  const loaded = load(identifier);
  if (!loaded.known) {
    log.debug("Leaving deleteApplication(). No such application.");
    log.debug("Leaving deleteApplication().");
    return { ok: false, errors: ['There is no application called "' + identifier + '" here.'] };
  }
  const gone = backing.deleteApplication(String(identifier));
  if (!gone) {
    log.debug("Leaving deleteApplication().");
    return { ok: false, errors: ['The directory would not delete "' + identifier + '".'] };
  }
  audit.audit({
    action: 'application.delete', actor: opts.actor || '', protocol: 'console',
    channel: 'internal', target: String(identifier),
    summary: 'Application "' + identifier + '" was deleted from the registry',
    detail: { identifier: String(identifier), authentications: loaded.record.authentications,
              registered: loaded.record.registered }
  });
  log.info('applications: "' + identifier + '" was deleted. ' + count() + ' left.');
  log.debug("Leaving deleteApplication(). Gone.");
  log.debug("Leaving deleteApplication().");
  return { ok: true,
           message: '"' + identifier + '" is gone from the registry, along with what it had ' +
                    'recorded: ' + loaded.record.authentications + ' authentication(s) and ' +
                    'whatever attributes it carried. It will reappear, empty, the next time ' +
                    'that identifier is accepted by a protocol.' };
}

// ---------------------------------------------------------------------------
// Reading the registry. Every one of these is a directory read; there is no
// cache, which is what keeps an ldapmodify effective on the next request rather
// than after a restart.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// ONE APPLICATION AS EVERY PAGE AND EVERY API REPLY SEES IT.
//
// `record` is what this module understands about it; `entry` is what the
// directory holds. Both, because they are not the same set and the difference
// was invisible from outside:
//
//   * `attributes` IS THE WHOLE ENTRY now, canonically spelled, operational
//     attributes and `entryDN` included. It used to be `record.fields`, which is
//     the schema half MINUS the twelve names recordFromAttributes() reads into
//     named members instead — so `objectClass`, `cn`, `appIdentifier`,
//     `appName`, `appKind`, `appProtocol`, `description`, both timestamps, the
//     three counters and `appRegistered` were all missing from a table headed
//     "every attribute the entry carries", and so was anything an ldapmodify had
//     written by hand. The named members are still here beside it: a caller that
//     wants the identifier should not have to know which attribute holds it.
//   * `dn` is where the entry IS. Not an attribute — the key it is stored under
//     — so it could not have appeared in the old map however complete that map
//     was. It is repeated inside `attributes` as `entryDN`, the RFC 5020 name,
//     because that is the name an ldapsearch filter matches it by here and a
//     dump that called the same fact two things would teach the reader a wrong
//     one.
//   * `operational` names which attributes a SEARCH would have withheld unless
//     asked for by name (RFC 4511 section 4.5.1.8), so a page can mark them
//     rather than pretend the distinction does not exist. This is a dump of the
//     store and not a search, so it shows them always.
//
// `entry` is absent — null — only when no directory is loaded in this process,
// which is the state store() warns about once and in which there is no registry
// at all. It is not the same as an entry carrying nothing.
// ---------------------------------------------------------------------------
function view(record, entry) {
  return {
    identifier: record.identifier,
    dnLabel: record.label,
    dn: entry ? entry.dn : null,
    name: record.name,
    kinds: record.kinds.slice(0),
    protocols: record.protocols.slice(0),
    // The DECLARED families, beside the observed ones above. It is lifted out
    // of `fields` — where it also still appears, because every schema attribute
    // does — so that a caller reading this shape does not have to know that one
    // of the two protocol lists is a top-level member and the other is not.
    // `recordedProtocols` is the same vocabulary again, worked out from the
    // KINDS this record carries rather than from `protocols` — see the
    // PROTOCOLS table's header, where matching on the protocol LABELS is
    // recorded as the wrong answer and why: a federation partner's sighting is
    // written under the protocol its relationship speaks, so by label every
    // OAuth client read as a federation partner.
    //
    // IT IS NOT "HAS AUTHENTICATED", and the name says so. A kind is usually
    // written when a protocol recognises the identifier, but createApplication()
    // takes one as well — so a hand-made entry can be recorded in a family it
    // has never connected in, and `authentications` is the number that answers
    // whether anything has actually happened.
    allowedProtocols: valuesOf(record.fields.appAllowedProtocol),
    recordedProtocols: protocolIdsForKinds(record.kinds),
    registered: record.registered,
    firstSeen: record.firstAt ? new Date(record.firstAt).toISOString() : '',
    lastSeen: record.lastAt ? new Date(record.lastAt).toISOString() : '',
    authentications: record.authentications,
    sessions: record.sessionCount,
    users: record.userCount,
    descriptions: record.descriptions.slice(0),
    // The entry's own facts, which are facts about the ENTRY rather than about
    // the application: when the directory created it, when it last changed, and
    // whether this service wrote it or a client did.
    origin: entry ? entry.origin : null,
    createdAt: entry ? entry.createdAt : null,
    modifiedAt: entry ? entry.modifiedAt : null,
    operational: entry ? entry.operational.slice(0) : [],
    attributes: entry ? entry.attributes : {},
    // The schema half on its own, kept because it is a different question —
    // "what has this module recorded about it" rather than "what does the entry
    // carry" — and because dropping it would silently change what a caller of
    // this API had already parsed.
    fields: record.fields
  };
}

function list() {
  log.debug("Entering list().");
  const backing = store();
  if (!backing) {
    log.debug("Leaving list().");
    return [];
  }
  const rows = backing.allApplications().map(function (entry) {
    return view(recordFromAttributes(entry.attributes), entry);
  });
  // Newest activity first. `lastSeen` comes off the entry as GeneralizedTime,
  // which has ONE-SECOND resolution, so applications touched in the same second
  // tie — and a tie keeps directory order, which is the order they were created
  // in. That is stable and it is why a burst of client_ids registered together
  // reads in the order they arrived rather than jumbled; it is not the sort
  // failing to work.
  rows.sort(function (a, b) { return String(b.lastSeen).localeCompare(String(a.lastSeen)); });
  log.debug("Leaving list().");
  return rows;
}

function get(identifier) {
  const loaded = load(identifier);
  return loaded.known ? view(loaded.record, loaded.entry) : null;
}

// ---------------------------------------------------------------------------
// WHICH APPLICATION ANSWERS TO THIS AUDIENCE, or null.
//
// The one lookup in this module that is not by identifier, and the only thing
// in this service that READS `oauthAudience`. The token endpoint calls it when
// it records a delegation: a client exchanging a token for
// `https://esb1.example.com` has named a resource rather than a client_id, and a
// register that filed the act under the URL would draw a box in
// /admin/delegation/map that nothing else in the picture ever mentions — while
// the application it means is sitting in this registry two rows away.
//
// THREE THINGS IT DELIBERATELY IS NOT.
//
// It is not a PERMISSION. An audience nobody registered returns null and the
// caller records what was asked for, verbatim; nothing is refused, because a
// mock that refused would remove a test case rather than add one. It is not
// CASE-FOLDED or normalised: RFC 8693 leaves an audience as an opaque string the
// authorization server understands, and an audience that differs by a character
// is a different audience — quietly matching `HTTPS://ESB1` to `https://esb1`
// would be this registry deciding a URI comparison rule on the caller's behalf.
// And it does not fall back to the IDENTIFIER: `applications.get(audience)`
// already answers that question, and a lookup that tried both would make
// `audience=esb1` and `audience=https://esb1.example.com` indistinguishable in
// the one place the difference is the point.
//
// It walks the container, which is a linear read per exchange. That is honest
// for a registry capped by `applications.max` and holding tens of entries; an
// index would be a second copy of the attribute, and this module's whole
// argument is that the directory is the one store.
// ---------------------------------------------------------------------------
function forAudience(audience) {
  log.debug("Entering forAudience(). audience=" + audience);
  const wanted = String(audience == null ? '' : audience).trim();
  if (!wanted) {
    log.debug("Leaving forAudience(). Nothing was asked for.");
    return null;
  }
  const found = list().filter(function (row) {
    return valuesOf(row.fields.oauthAudience).indexOf(wanted) >= 0;
  });
  if (!found.length) {
    log.debug("Leaving forAudience(). No application has registered it.");
    return null;
  }
  if (found.length > 1) {
    // Two entries claiming one audience is a configuration mistake rather than
    // a state to resolve here, and the first is as good an answer as any — but
    // it is said out loud, because the consequence is a delegation filed under
    // one of two applications with nothing on the page to say the other exists.
    log.warn('applications: ' + found.length + ' applications have registered ' +
             'the audience "' + wanted + '" (' +
             found.map(function (row) { return row.identifier; }).join(', ') +
             '). The first is what a token exchange for it will be recorded ' +
             'against. An audience names one resource; remove it from the ' +
             'others.');
  }
  log.debug("Leaving forAudience(). " + found[0].identifier + ".");
  return found[0];
}

function count() {
  const backing = store();
  return backing ? backing.countApplications() : 0;
}

// Two facts about the STORE rather than about an application, asked for by the
// console and by the management API so that a reply can say where these entries
// live and how many the container will hold. They are ldap_server.js's answers
// — this module does not know where the container is, which is the division the
// header describes — so they are absent when no directory is attached, and the
// callers render that as null rather than as a guess.
function containerDn() {
  const backing = store();
  return (backing && backing.containerDn && backing.containerDn()) || null;
}

function maxApplications() {
  const backing = store();
  return (backing && backing.maxApplications && backing.maxApplications()) || null;
}

// ---------------------------------------------------------------------------
// THIS SERVICE'S OWN TWO APPLICATIONS, SEEDED AT STARTUP.
//
// Every other entry in this registry arrives because somebody PRESENTED an
// identifier — a client_id at the authorization endpoint, a wtrealm on a
// wsignin1.0, an SPN in a TGS request. Two applications never do, and they are
// the two a reader is most likely to go looking for: the ADMIN CONSOLE at
// /admin and the MANAGEMENT API at /admin-api. They are surfaces of THIS
// process, so no caller ever names them from outside, and until this ran the
// one question the registry exists to answer — what applications have you
// seen? — came back with everything except the two things the reader was
// standing in.
//
// THEY ARE SEEDED AS FULL RFC 7591 REGISTRATIONS AND NOT AS LABELS, which is
// the decision here. A descriptive entry would be a row on a page; a
// registration is a CLIENT: its secret is what RFC 9700 mode (section 2.5)
// checks, its redirect URI is what that mode matches by exact string, and GET
// /oauth2/register/sts-admin-console answers with the document below to
// whoever holds the registration access token on the entry. So the two rows
// are drivable by the thing this service exists for rather than merely
// visible.
//
// NOTHING SERVES /admin/callback, and it is said here because somebody will
// look for it. The console's gate is a sign-on session and two directory
// groups (`admin_rbac.js`), not an OAuth flow, so the redirect URI below is
// what the console WOULD use if that gate ever moved onto OIDC. It is ON THE
// ENTRY rather than in a comment because this container IS the registry: an
// `ldapmodify`, a form on /admin/applications or a PUT to
// /oauth2/register/{id} changes it, and the change is what the checks then
// read. The same goes for the two scopes on the API's registration, which are
// named after the console's two roles and GRANT NOTHING — nothing under
// /admin-api is gated at all, and a scope that looked like a permission
// without being one would be worse than no scope.
//
// THE SECRETS ARE MINTED PER START and sit in the clear on an entry in a
// directory where every bind succeeds. That is the decision `oauthClientSecret`
// argues at length in its schema row, made once more here and for the same
// reason; they die with the process, and neither is ever written to the audit
// log.
//
// SEEDED ONLY WHERE THE IDENTIFIER IS FREE, which is `spiffe_registry.js`'s
// seeding rule and is here for its reason: an operator who deleted one of these
// meant it, and re-creating it would make the delete button appear not to work.
// Nothing here is persisted, so the next restart does seed them again.
//
// `applications.seedInternal` turns the whole of this off. It is restart-only
// because it runs once, as `ldap_server.js` fills the directory slot above.
// ---------------------------------------------------------------------------

// Where this service answers, as a URL, at a moment when THERE IS NO REQUEST to
// read a Host header from — `helpers.js` and `vc_did.js` fall back to
// 'localhost:' + PORT at the same wall. It is a starting value and not a fact:
// a deployment behind a proxy wants its own name, and putting one there is an
// ldapmodify of oauthRedirectUri.
function internalBaseUrl() {
  log.debug("Entering internalBaseUrl().");
  const scheme = config.value('global.https') ? 'https' : 'http';
  const base = scheme + '://localhost:' + config.value('global.port');
  log.debug("Leaving internalBaseUrl(). base=" + base);
  return base;
}

// The two, built fresh on each call because each carries two credentials that
// are generated rather than declared.
function internalApplications() {
  log.debug("Entering internalApplications().");
  const base = internalBaseUrl();
  const issued = nowSec();
  const rows = [
    { identifier: 'sts-admin-console',
      name: 'Admin console',
      kinds: ['oauth2-client', 'oidc-relying-party'],
      protocols: ['OAuth 2.0 / OIDC'],
      description: 'seeded at startup: this service\'s own admin console at ' +
                   '/admin (applications.seedInternal)',
      registration: {
        client_id: 'sts-admin-console',
        client_name: 'Admin console',
        client_id_issued_at: issued,
        client_secret: randomId(24),
        client_secret_expires_at: 0,
        registration_access_token: randomId(24),
        registration_client_uri: base + '/oauth2/register/sts-admin-console',
        client_uri: base + '/admin',
        application_type: 'web',
        redirect_uris: [base + '/admin/callback'],
        post_logout_redirect_uris: [base + '/admin'],
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
        scope: 'openid profile email',
        token_endpoint_auth_method: 'client_secret_basic'
      } },
    { identifier: 'sts-management-api',
      name: 'Management API',
      kinds: ['oauth2-client'],
      protocols: ['OAuth 2.0'],
      description: 'seeded at startup: this service\'s own management API at ' +
                   '/admin-api (applications.seedInternal)',
      registration: {
        client_id: 'sts-management-api',
        client_name: 'Management API',
        client_id_issued_at: issued,
        client_secret: randomId(24),
        client_secret_expires_at: 0,
        registration_access_token: randomId(24),
        registration_client_uri: base + '/oauth2/register/sts-management-api',
        client_uri: base + '/admin-api/docs',
        application_type: 'web',
        // NO redirect URI and no response type: this one is a back-channel
        // client on client_credentials, and a redirect URI on it would be a
        // registration saying it can do a flow it cannot.
        redirect_uris: [],
        grant_types: ['client_credentials'],
        response_types: [],
        scope: 'admin:read admin:write',
        token_endpoint_auth_method: 'client_secret_basic'
      } }
  ];
  log.debug("Leaving internalApplications(). " + rows.length + " row(s).");
  return rows;
}

// One of them. Returns whether an entry was CREATED, which is not the same as
// whether all is well: an identifier already in the registry is the ordinary
// outcome of an operator having made one by hand, and it is left exactly as it
// is rather than overwritten.
function seedInternalApplication(spec) {
  log.debug("Entering seedInternalApplication(). identifier=" +
            spec.identifier);
  const loaded = load(spec.identifier);
  if (loaded.known) {
    log.debug("Leaving seedInternalApplication(). It is already here and was " +
              "left alone.");
    return false;
  }
  const record = loaded.record;
  const now = Date.now();
  record.registered = true;
  record.firstAt = now;
  record.lastAt = now;
  record.name = spec.name;
  spec.kinds.forEach(function (kind) {
    addTo(record.kinds, kind);
  });
  spec.protocols.forEach(function (protocol) {
    addTo(record.protocols, protocol);
  });
  addTo(record.descriptions, spec.description);
  applyRegistrationFields(record, spec.registration);
  if (!save(record)) {
    log.warn('applications: "' + spec.identifier + '" was not seeded — the ' +
             'ou=applications container is full (applications.max) or the ' +
             'directory is. Nothing else is affected; the surface it names ' +
             'answers exactly as it did.');
    log.debug("Leaving seedInternalApplication(). The container would not " +
              "take it.");
    return false;
  }
  // The same row an RFC 7591 registration writes, with the channel saying
  // where it came from. NO CREDENTIAL IS NAMED — audit.js's rule, and this is
  // one of the two places in this module that holds one.
  audit.audit({
    action: 'application.create', actor: '', protocol: 'internal',
    channel: 'internal', target: spec.identifier,
    summary: 'Application "' + spec.identifier + '" was seeded at startup (' +
             spec.name + ')',
    detail: { identifier: spec.identifier, kinds: spec.kinds.join(', '),
              registered: true, seeded: true }
  });
  log.debug("Leaving seedInternalApplication(). Created.");
  return true;
}

// Called by `ldap_server.js` the moment it has filled setDirectory() — which is
// the earliest point at which there is a container to write into, and the
// latest at which the entries are there before anything can ask for them.
function seedInternalApplications() {
  log.debug("Entering seedInternalApplications().");
  if (!config.value('applications.seedInternal')) {
    log.info('applications: the console and the management API were not ' +
             'seeded as applications; applications.seedInternal is off.');
    log.debug("Leaving seedInternalApplications(). The setting is off.");
    return 0;
  }
  if (!store()) {
    log.warn('applications: the console and the management API were not ' +
             'seeded — there is no directory in this process, so there is no ' +
             'ou=applications container to put them in. See store().');
    log.debug("Leaving seedInternalApplications(). There is no directory.");
    return 0;
  }
  const rows = internalApplications();
  let made = 0;
  rows.forEach(function (one) {
    if (seedInternalApplication(one)) made++;
  });
  log.info('applications: ' + made + ' of this service\'s own ' + rows.length +
           ' application(s) were seeded. They are ORDINARY entries — edit ' +
           'one, or delete it, and it stays that way until a restart.');
  log.debug("Leaving seedInternalApplications(). " + made + " created.");
  return made;
}

module.exports = {
  KINDS: KINDS,
  KIND_IDS: KIND_IDS,
  // The DECLARED protocol vocabulary, exported whole rather than as a list of
  // ids: the console draws a checkbox per row from the label and the prose, the
  // management API turns the ids into an `enum` in its document, and both read
  // one table — which is what stops a form offering a family the create would
  // refuse, the same property editableAttributes() gives the two edit selects.
  PROTOCOLS: PROTOCOLS,
  PROTOCOL_IDS: PROTOCOL_IDS,
  protocolRow: protocolRow,
  // The kind-to-family translation, exported because the pages compare the
  // declared list with what happened and a second copy of that map would be a
  // second answer to "has this family ever been seen".
  protocolIdsForKinds: protocolIdsForKinds,
  normaliseProtocols: normaliseProtocols,
  // The identifier and redirect-URI attributes the create form is built from,
  // deduped by attribute and carrying the families each one serves. One walk of
  // the PROTOCOLS table serves the console's fields and the management API's
  // document, so neither can offer a field the other has never heard of.
  declarationAttributes: declarationAttributes,
  DECLARATION_ATTRIBUTE_NAMES: DECLARATION_ATTRIBUTE_NAMES,
  normaliseFields: normaliseFields,
  SCHEMA: SCHEMA,
  seen: seen,
  register: register,
  updateRegistration: updateRegistration,
  forgetRegistration: forgetRegistration,
  registrationOf: registrationOf,
  clientConfigOf: clientConfigOf,
  recordAuthentication: recordAuthentication,
  setDirectory: setDirectory,
  // The two conversions, exported because ldap_server.js seeds and reads
  // entries with them and this module owns the schema they encode.
  attributesFor: attributesFor,
  recordFromAttributes: recordFromAttributes,
  labelFor: labelFor,
  editableAttributes: editableAttributes,
  createApplication: createApplication,
  seedInternalApplications: seedInternalApplications,
  updateApplication: updateApplication,
  deleteApplication: deleteApplication,
  list: list,
  get: get,
  // The audience lookup, exported for the token endpoint. See its header for
  // why it is a lookup and not a check.
  forAudience: forAudience,
  count: count,
  containerDn: containerDn,
  maxApplications: maxApplications
};
