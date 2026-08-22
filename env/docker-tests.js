// Configuration for the containerized test stack (docker-compose-run-tests.yml).
//
// Identical to env/local.js apart from this comment: the level is kept at debug
// because the STS log is the record of what the mock issued when a test fails,
// and it is the only place the signed artifacts are written down. See
// env/local.js's header and `config.js` for what each setting means.
var config = {
  // Bunyan log level (trace|debug|info|warn|error|fatal).
  logLevel: "debug",

  // --- Global ------------------------------------------------------------
  global: {
    host: "0.0.0.0", // restart to apply
    port: 8081,      // restart to apply

    // Believe X-Forwarded-Proto and X-Forwarded-Host. OFF: with nothing in
    // front of this service they are headers any client can set, and believing
    // them lets a caller choose what this service thinks its own issuer,
    // endpoints and DPoP htu are. Turn it ON behind a reverse proxy — see
    // GET /tls/forwarded, which shows what arrived and what was believed.
    trustProxy: false
  },

  // --- OAuth 2.0 / OIDC --------------------------------------------------
  oauth2: {
    issuer: "",

    // RFC 9700 (OAuth 2.0 Security BCP) enforcement on the authorization flow.
    // OFF, which is what keeps every existing caller working: the debugger's
    // own panes use an unregistered redirect_uri, no PKCE and — in one of them
    // — the implicit grant, all of which this mode refuses. Turn it on to
    // exercise a client against a server that behaves like a real deployment.
    // GET /oauth2/rfc9700 lists what it does and does not enforce.
    rfc9700: false,

    // What the mode compares redirect_uri against, by exact string match, for
    // any client that did not register its own. Empty, so the mode refuses
    // every authorization request until this is filled in; the refusal says so.
    redirectUris: "",

    // RFC 8252 section 7.3's exception, which RFC 9700 says a server MUST
    // honour. Off makes this server non-compliant on purpose.
    loopbackPortWildcard: true,

    // Put a deliberately WRONG nonce in every ID Token, so that a client which
    // accepts one is shown not to be validating it — the one part of RFC 9700's
    // nonce requirement this server cannot enforce. Not part of RFC 9700 mode;
    // useful in either. Off, and loud when on.
    breakIdTokenNonce: false,

    // How far out a client assertion's exp/nbf/iat may be (private_key_jwt and
    // client_secret_jwt), and how long past expiry its jti is remembered.
    clientAssertionSkewS: 60,

    // RFC 9700 mode only. How long a refresh CHAIN may go unused before it
    // stops working (0 turns it off), and whether ending a sign-on session
    // revokes the refresh tokens issued on it.
    refreshIdleSeconds: 86400,
    revokeRefreshOnLogout: true
  },

  // --- Applications ------------------------------------------------------
  // The registry of every OAuth client, relying party, service provider and
  // Kerberos service this instance has been asked about. It IS the
  // ou=applications container in the embedded directory — see /ldap/applications
  // — so this is a directory limit: past it a new application is refused rather
  // than an old one evicted.
  applications: {
    max: 500
  },

  // --- SAML --------------------------------------------------------------
  saml: {
    issuer: "urn:wstrust:mock:sts"
  },

  // --- WS-Trust ----------------------------------------------------------
  wstrust: {
    issuer: "urn:wstrust:mock:sts"
  },

  // --- WS-Federation -----------------------------------------------------
  wsfed: {
    entityId: "urn:wstrust:mock:sts"
  },

  // --- TLS ---------------------------------------------------------------
  tls: {
    port: 8443,                                          // restart to apply
    mutualPort: 9443,                                    // restart to apply
    hostnames: "localhost,sts,sts-mock,sts.example.com", // restart to apply
    ips: "127.0.0.1"                                     // restart to apply
  },

  // --- OID4VCI -----------------------------------------------------------
  oid4vci: {
    walletUrl: "http://localhost:3000",
    authorizationServer: "",
    batchSize: 4,
    deferredReadyMs: 4000,
    deferredIntervalS: 2,
    offerUsername: "diploma.student",
    requestEncryptionRequired: false
  },

  // --- OID4VP ------------------------------------------------------------
  oid4vp: {
    clientId: "sts-mock-verifier",
    // walletUrl: falls back to oid4vci.walletUrl. Uncomment to point the mock
    //   Verifier at a different wallet from the issuer's.
    kbMaxAgeS: 600,
    claims: "given_name,family_name"
  },

  // --- Kerberos ----------------------------------------------------------
  krb5: {
    realm: "EXAMPLE.COM",                                          // restart to apply
    kdcPort: 88,                                                   // restart to apply
    servicePort: 8888,                                             // restart to apply
    servicePrincipal: "HTTP/web.example.com",                      // restart to apply
    clockSkew: 300,
    clockOffset: 0,
    userPassword: "password!",                                     // restart to apply
    unknownUsers: "nosuchuser,nobody",
    // serviceDomains: derived from krb5.realm. Uncomment to replace the whole list;
    //   an empty string creates no service accounts at all.
    autoServicePassword: "auto-service-password",                  // restart to apply
    krbtgtPassword: "krbtgt-mock-password",                        // restart to apply
    domainSid: "S-1-5-21-1004336348-1177238915-682003330",         // restart to apply
    trustedRealm: "PARTNER.COM",                                   // restart to apply
    trustPassword: "inter-realm-trust-password",                   // restart to apply
    trustedDomainSid: "S-1-5-21-2035427030-2118130302-1178042555", // restart to apply
    trustedKrbtgtPassword: "partner-krbtgt-password",              // restart to apply
    s2kparams: "omit"
  },

  // --- LDAP --------------------------------------------------------------
  ldap: {
    port: 389,                   // restart to apply
    tlsPort: 636,                // restart to apply
    baseDn: "dc=example,dc=com", // restart to apply
    // ON. It was `false` in all three env files, which is what an
    // appconfig value does: it beats the default, and the default is
    // what every document here describes. So a person signed in through
    // any protocol and the directory stayed empty — which reads as a
    // broken hook and is a setting doing what it was told.
    autocreateUsers: true,
    maxEntries: 2000,
    sizeLimit: 500
  },

  // --- SCIM --------------------------------------------------------------
  //
  // SCIM 2.0 provisions into the directory above — the same entries, the same
  // cap — so `ldap.maxEntries` is what a POST /scim/v2/Users runs out of and
  // there is nothing here about storage. What IS here is authentication: see
  // the second half of the block, and GET /scim for what each scheme costs a
  // caller (which is very little — it is a turnstile, not a lock).
  scim: {
    enabled: true,
    maxResults: 200,
    bulkMaxOperations: 100,
    bulkMaxPayloadSize: 1048576,

    // The SCIM endpoints are the one surface here that refuses a caller who
    // presents nothing — they create and delete accounts. All six schemes RFC
    // 7644 section 2 names are offered and every one of them is permissive:
    // anybody can get a token with either scope, any password but "invalid"
    // works over Basic, any username works over Digest with the shared
    // password below, and anybody may register a HOBA key. Turn authRequired
    // off to get the unauthenticated behaviour these endpoints used to have.
    authRequired: true,
    authDiscovery: false,
    authRealm: "SCIM",
    scopeRead: "scim:read",
    scopeWrite: "scim:write",
    authBearer: true,
    authBasic: true,
    authDigest: true,
    digestPassword: "password!",
    digestNonceSeconds: 300,
    authHoba: true,
    hobaMaxAgeSeconds: 600,
    authCookie: true,
    authClientCert: true
  },

  // --- The group claim ---------------------------------------------------
  //
  // A groups claim in every access token, ID Token and SAML assertion, for
  // anybody who is a member of a group in the embedded directory. Omitted
  // entirely for somebody who is in none, which is why ON by default changes
  // nothing for a caller who never touched ou=groups. A group still GRANTS
  // nothing here — see /admin/groups — the token merely carries it.
  groups: {
    claim: true,
    claimName: "groups",
    claimValue: "cn",       // "cn" or "dn"
    claimFromMemberOf: true
  },

  // --- Audit log ---------------------------------------------------------
  audit: {
    maxEvents: 5000,
    protocolCalls: true
  },

  // --- SPIFFE / SPIRE ------------------------------------------------------
  //
  // The bundle endpoint, the Workload API and the SPIRE Server API. Four of
  // these are bound sockets and three are material derived at startup (the
  // trust domain and the two key types), which is why config.js marks them
  // restart-only.
  spiffe: {
    // Whether the three SPIFFE surfaces answer.
    enabled: true,
    // The trust domain this service issues for.
    trustDomain: 'example.org',
    // The X.509 authority's key. What SPIRE issues by default.
    x509KeyType: 'ec-p256',
    // The JWT authority's key, which decides the alg of every JWT-SVID.
    jwtKeyType: 'ec-p256',
    // How long the X.509 authority's own certificate is valid, in seconds.
    caTtl: 86400,
    // The default X509-SVID lifetime, in seconds.
    svidTtl: 3600,
    // The default JWT-SVID lifetime, in seconds. Shorter because it is a bearer credential.
    jwtSvidTtl: 300,
    // spiffe_refresh_hint in the published bundle, in seconds.
    refreshHint: 300,
    // The X.501 subject on every SVID. SPIRE's own value; the identity is the URI SAN.
    svidSubject: 'C=US,O=SPIRE',
    // Invent a registration entry for a workload that matches none. Off is how a client's "I have no identity" path is exercised.
    autoCreateEntries: true,
    // Refuse a Workload API call with no workload.spiffe.io: true header, as every conforming implementation does.
    requireSecurityHeader: true,
    // Mutual TLS and SPIRE's own per-method authorization on the SPIRE Server API's TCP port. Restart-only: it decides how the socket is bound.
    authRequired: true,
    // Trust a caller on the SPIRE Server API's Unix socket as the `local` entity, the way a real spire-server trusts its private socket.
    trustLocalSocket: true,
    // SPIFFE IDs that are administrators of the SPIRE Server API, comma-separated. SPIRE's admin_ids; no registration entry needed.
    adminIds: '',
    // How far out a caller's clock may be when its X509-SVID is checked, in seconds.
    clockSkew: 60,
    // Answer a Workload API caller with the entries its observable selectors match, rather than with every entry.
    attestWorkloads: true,
    // Believe selectors a workload sends in a metadata header. NOT attestation; it exists so selector matching can be exercised at all.
    acceptAssertedSelectors: false,
    // How many registration entries may live under ou=spiffe.
    maxEntries: 500,
    // How many attested agents are held.
    maxAgents: 200,
    // How many foreign trust domains' bundles are held.
    maxFederatedBundles: 32,
    // Where the trust bundle is published.
    bundlePath: '/spiffe/bundle',
    // Serve the Workload API on a Unix socket. What SPIFFE_ENDPOINT_SOCKET means to every real client.
    workloadSocketEnabled: true,
    // Where that socket lives. SPIRE's own default path.
    workloadSocket: '/tmp/spire-agent/public/api.sock',
    // The Workload API over TCP. 0 turns it off.
    workloadPort: 8092,
    // The SPIRE Server API over gRPC. SPIRE's own default is 8081, which this service's HTTP port already has.
    serverPort: 8181,
    // Also serve the SPIRE Server API on a Unix socket.
    serverSocketEnabled: false,
    // Where that socket lives when it is on.
    serverSocket: '/tmp/spire-server/private/api.sock',
    // The address both TCP gRPC listeners bind.
    grpcHost: '0.0.0.0'
  },
};

module.exports = config;
