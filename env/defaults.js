// File: env/defaults.js
//
// ---------------------------------------------------------------------------
// THE DEFAULT APPCONFIG FILE. It is not selected with CONFIG_FILE and is not
// meant to be edited to configure a deployment — it is the BASE LAYER that the
// file CONFIG_FILE names is unioned on top of.
//
// Why it exists. Since 2026-08-24 this service REFUSES TO START when a setting
// has no value in the appconfig layer and no environment variable: a value that
// nobody configured, arriving from a constant buried in a module, is the thing
// that makes "what is this service configured with?" unanswerable. But the same
// rule read literally would mean that a file which is not this service's — the
// parent project's in-process Kerberos jobs point CONFIG_FILE at the TEST
// suite's own config — could no longer load these modules at all, and that a
// setting added to the table tomorrow would break every existing config file in
// the world on the day it was added.
//
// The union is what makes both true at once. common/config.js reads THIS file
// first and the operator's file over it, key by key, and the operator's value
// wins wherever the two overlap. So every setting always has an appconfig-layer
// value, an operator's file may carry as few or as many keys as it likes, and
// the startup refusal fires on the one case it is actually for: a setting in
// the table with no row here, which is a setting somebody added and did not
// finish adding.
//
// THE VALUES HERE ARE THE `dflt` COLUMN OF config.js's TABLE, and this file is
// GENERATED from it — do not hand-edit a value. Changing a default means
// changing the table, which is the one place that also carries the reasoning
// for what the default is; a value edited only here would disagree with what
// /admin/config reports as the default, with the OpenAPI document's `default`
// property, and with README.md's table, all three of which read the table.
//
// THREE SETTINGS ARE DELIBERATELY ABSENT: global.https, oid4vp.walletUrl and
// krb5.serviceDomains are DERIVED from a neighbour (from oauth2.rfc9700, from
// oid4vci.walletUrl and from krb5.realm respectively). A literal here would
// freeze the derivation at whatever it evaluated to the day this file was
// written, so they resolve through their neighbour instead and are exempt from
// the startup refusal for that reason.
//
// See common/CLAUDE.md, and README.md's *Configuration*, which lists every
// setting, its environment variable and its default in one table.
// ---------------------------------------------------------------------------
var config = {
  // --- The log level ---------------------------------------------------
  logLevel: "info", // Log level

  // --- Global ----------------------------------------------------------
  global: {
    host: "0.0.0.0",   // HTTP bind address; restart to apply
    port: 8081,        // HTTP port; restart to apply
    trustProxy: false  // Trust forwarded headers
  },

  // --- Global ----------------------------------------------------------
  workers: {
    count: 2  // Worker processes
  },

  // --- Trust realms ----------------------------------------------------
  realms: {
    enabled: true,        // Trust realms enabled
    pathSegment: "realm"  // Realm path segment
  },

  // --- OAuth 2.0 / OIDC ------------------------------------------------
  oauth2: {
    issuer: "",                  // Issuer identifier
    rfc9700: false,              // RFC 9700 mode; restart to apply
    breakIdTokenNonce: false,    // Break the ID Token nonce
    refreshIdleSeconds: 86400,   // Refresh token idle timeout (s)
    revokeRefreshOnLogout: true, // Revoke refresh tokens on sign-out
    eddsaCurve: "Ed25519",       // EdDSA curve
    clientAssertionSkewS: 60,    // Client assertion clock skew (s)
    accessTokenTtlS: 3600,       // Access token lifetime (s)
    idTokenTtlS: 3600,           // ID Token lifetime (s)
    refreshTokenTtlS: 86400,     // Refresh token lifetime (s)
    clockSkewS: 30,              // Token clock skew (s)
    redirectUris: "",            // Registered redirect URIs
    loopbackPortWildcard: true,  // Loopback port wildcard
    frontchannelLogout: true     // OpenID Connect Front-Channel Logout
  },

  // --- Admin console ---------------------------------------------------
  admin: {
    authRequired: true,        // Require a sign-in for /admin
    readGroup: "admin-read",   // Admin Read role
    writeGroup: "admin-write", // Admin Write role
    openWhenEmpty: true        // Open while no role has a member
  },

  // --- Applications ----------------------------------------------------
  applications: {
    max: 500,           // Applications remembered
    seedInternal: true  // Seed the console and this API as applications; restart to apply
  },

  // --- Federation ------------------------------------------------------
  federation: {
    enabled: true,                // Federation endpoints answer
    max: 50,                      // Relationships remembered
    usernamePrefix: "",           // Prefix for federated usernames
    loginButtons: true,           // Offer partners at the sign-in screen
    outbound: true,               // Make back-channel requests to partners
    outboundTimeoutMs: 15000,     // Back-channel timeout (ms)
    outboundAllowInsecure: false, // Allow http:// and untrusted TLS to a partner
    requestTtlMin: 10             // Outbound request lifetime (minutes)
  },

  // --- SAML ------------------------------------------------------------
  saml: {
    issuer: "urn:wstrust:mock:sts", // Assertion issuer
    clockSkewS: 0                   // Assertion clock skew (s)
  },

  // --- SAML 2.0 --------------------------------------------------------
  saml2: {
    entityId: "urn:sts-mock:idp",                                          // Identity provider entityID
    perApplicationEntityId: true,                                          // An entityID per service provider
    assertionLifetimeMin: 60,                                              // Assertion lifetime (minutes)
    signAssertion: true,                                                   // Sign the assertion
    signResponse: true,                                                    // Sign the response
    nameIdFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified", // Default NameID format
    artifactTtlS: 300,                                                     // Artifact lifetime (seconds)
    encryptAssertion: false,                                               // Encrypt the assertion
    encryptionAlgorithm: "aes256-gcm",                                     // Encryption algorithm
    keyTransportAlgorithm: "rsa-oaep-mgf1p",                               // Key transport algorithm
    encryptLogoutNameId: false,                                            // Encrypt the NameID in a LogoutRequest
    autocreateApplications: true,                                          // Register a service provider on sight
    defaultSingleLogoutService: ""                                         // Fallback logout return address
  },

  // --- SAML 1.1 --------------------------------------------------------
  saml11: {
    providerId: "urn:sts-mock:idp:saml11",                                 // Identity provider providerID
    perApplicationProviderId: true,                                        // A providerID per relying party
    assertionLifetimeMin: 60,                                              // Assertion lifetime (minutes)
    signAssertion: true,                                                   // Sign the assertion
    signResponse: true,                                                    // Sign the response
    nameIdFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified", // Default NameIdentifier format
    defaultProfile: "post",                                                // Default browser profile
    artifactTtlS: 300,                                                     // Artifact lifetime (seconds)
    autocreateApplications: true                                           // Register relying parties on sight
  },

  // --- WS-Trust --------------------------------------------------------
  wstrust: {
    issuer: "urn:wstrust:mock:sts"  // Token issuer
  },

  // --- WS-Federation assertions ----------------------------------------
  wsfed: {
    assertionLifetimeMin: 60,         // Assertion lifetime (minutes)
    entityId: "urn:wstrust:mock:sts"  // Entity ID
  },

  // --- TLS -------------------------------------------------------------
  tls: {
    port: 8443,                                          // TLS port; restart to apply
    mutualPort: 9443,                                    // Mutual-TLS port; restart to apply
    hostnames: "localhost,sts,sts-mock,sts.example.com", // Certificate hostnames; restart to apply
    ips: "127.0.0.1",                                    // Certificate IP addresses; restart to apply
    certificateAlgorithms: "rsa",                        // Server certificate algorithms; restart to apply
    certificateFile: "",                                 // Server certificate file; restart to apply
    keyFile: ""                                          // Server private key file; restart to apply
  },

  // --- OID4VCI ---------------------------------------------------------
  oid4vci: {
    walletUrl: "http://localhost:3000", // Wallet URL
    authorizationServer: "",            // Authorization server
    batchSize: 4,                       // Batch size
    deferredReadyMs: 4000,              // Deferred: ready after (ms)
    deferredIntervalS: 2,               // Deferred: poll interval (s)
    offerUsername: "diploma.student",   // Offer username
    requestEncryptionRequired: false,   // Require encrypted credential requests
    sdJwtIssuerDid: false,              // Name the SD-JWT VC issuer by DID; restart to apply
    ldpVcIssuerDid: false               // Name the ldp_vc issuer by DID; restart to apply
  },

  // --- OID4VP ----------------------------------------------------------
  oid4vp: {
    clientId: "sts-mock-verifier",    // Verifier client ID
    kbMaxAgeS: 600,                   // Key Binding max age (s)
    claims: "given_name,family_name"  // Requested claims
  },

  // --- Kerberos --------------------------------------------------------
  krb5: {
    realm: "EXAMPLE.COM",                                          // Realm; restart to apply
    kdcPort: 88,                                                   // KDC port; restart to apply
    servicePort: 8888,                                             // Test service port; restart to apply
    servicePrincipal: "HTTP/web.example.com",                      // Service principal; restart to apply
    clockSkew: 300,                                                // Clock skew (s)
    clockOffset: 0,                                                // Clock offset (s)
    userPassword: "password!",                                     // User password; restart to apply
    unknownUsers: "nosuchuser,nobody",                             // Names that stay unknown
    autoServicePassword: "auto-service-password",                  // Auto-created service password; restart to apply
    krbtgtPassword: "krbtgt-mock-password",                        // krbtgt password; restart to apply
    domainSid: "S-1-5-21-1004336348-1177238915-682003330",         // Domain SID; restart to apply
    trustedRealm: "PARTNER.COM",                                   // Trusted realm; restart to apply
    trustPassword: "inter-realm-trust-password",                   // Trust password; restart to apply
    trustedDomainSid: "S-1-5-21-2035427030-2118130302-1178042555", // Trusted domain SID; restart to apply
    trustedKrbtgtPassword: "partner-krbtgt-password",              // Trusted realm krbtgt password; restart to apply
    spnegoAuthentication: true,                                    // Sign in with a Kerberos ticket
    spnegoLoginButton: true,                                       // Offer Kerberos at the sign-in screen
    s2kparams: "omit"                                              // Send s2kparams
  },

  // --- LDAP ------------------------------------------------------------
  ldap: {
    port: 389,                   // LDAP port; restart to apply
    tlsPort: 636,                // LDAPS port; restart to apply
    baseDn: "dc=example,dc=com", // Base DN; restart to apply
    autocreateUsers: true,       // Auto-create users
    maxEntries: 2000,            // Maximum entries
    sizeLimit: 500               // Search size limit
  },

  // --- SCIM ------------------------------------------------------------
  scim: {
    enabled: true,               // SCIM enabled
    maxResults: 200,             // Maximum results per page
    bulkMaxOperations: 100,      // Bulk operation limit
    bulkMaxPayloadSize: 1048576, // Bulk payload limit
    authRequired: true,          // Require authentication
    authDiscovery: false,        // Authenticate discovery too
    authRealm: "SCIM",           // Authentication realm
    scopeRead: "scim:read",      // OAuth scope to read
    scopeWrite: "scim:write",    // OAuth scope to write
    authBearer: true,            // Offer OAuth 2.0 tokens
    authBasic: true,             // Offer HTTP Basic
    authDigest: true,            // Offer HTTP Digest
    digestPassword: "password!", // The shared Digest password
    digestNonceSeconds: 300,     // Digest nonce lifetime
    authHoba: true,              // Offer HOBA
    hobaMaxAgeSeconds: 600,      // HOBA challenge lifetime
    authCookie: true,            // Offer the session cookie
    authClientCert: true         // Offer TLS client certificates
  },

  // --- SSF -------------------------------------------------------------
  ssf: {
    enabled: true,                                                                                                                                        // SSF enabled
    issuer: "",                                                                                                                                           // Transmitter issuer identifier
    signingAlgorithm: "RS256",                                                                                                                            // Algorithm SETs are signed with
    deliveryMethods: "urn:ietf:rfc:8935,urn:ietf:rfc:8936",                                                                                               // Delivery methods offered
    defaultSubjects: "ALL",                                                                                                                               // What an empty subject list means
    streamStatusOnCreate: "enabled",                                                                                                                      // Status a new stream is created in
    minVerificationInterval: 60,                                                                                                                          // Minimum verification interval (s)
    verificationRateLimit: false,                                                                                                                         // Enforce the verification interval
    criticalSubjectMembers: "",                                                                                                                           // Critical complex-subject members
    eventsSupported: "https://schemas.openid.net/secevent/ssf/event-type/verification,https://schemas.openid.net/secevent/ssf/event-type/stream-updated", // Event types offered
    pushDelivery: true,                                                                                                                                   // Make outbound push requests
    pushAllowedHosts: "",                                                                                                                                 // Push endpoint allowlist
    pushAllowInsecure: false,                                                                                                                             // Allow http:// and untrusted TLS to a receiver
    pushTimeoutMs: 10000,                                                                                                                                 // Push timeout (ms)
    maxStreams: 25,                                                                                                                                       // Streams per realm
    maxSubjectsPerStream: 100,                                                                                                                            // Subjects per stream
    maxQueuedEvents: 200,                                                                                                                                 // Queued events per stream
    pollMaxEvents: 20,                                                                                                                                    // Events per poll
    maxReceivedEvents: 200,                                                                                                                               // Received events kept
    maxStreamLogEntries: 200,                                                                                                                             // Log lines per stream
    authRequired: true,                                                                                                                                   // Require authentication
    authScopeRead: "ssf:read",                                                                                                                            // Scope to read a stream
    authScopeWrite: "ssf:write",                                                                                                                          // Scope to change a stream
    receiveEnabled: true,                                                                                                                                 // Accept pushed events
    receiveRequireSignature: false,                                                                                                                       // Refuse a SET whose signature does not verify
    legacySubClaim: false,                                                                                                                                // Also emit the deprecated `sub` claim
    breakSetSignature: false                                                                                                                              // Sign every SET badly
  },

  // --- Group claim -----------------------------------------------------
  groups: {
    claim: true,             // Carry a groups claim
    claimName: "groups",     // Claim name
    claimValue: "cn",        // What names a group
    claimFromMemberOf: true  // Believe an entry's own memberOf
  },

  // --- Audit log -------------------------------------------------------
  audit: {
    maxEvents: 5000,     // Maximum events held
    protocolCalls: true  // Record protocol endpoint calls
  },

  // --- Delegation ------------------------------------------------------
  delegation: {
    maxRecords: 2000  // Maximum delegation acts held
  },

  // --- Logout ----------------------------------------------------------
  logout: {
    anyUser: true,         // Allow /logout to name somebody else
    kerberosSignOut: true, // A logout stops older Kerberos tickets at the KDC
    ldapDisconnect: true,  // A logout drops LDAP connections bound as that person
    maxRows: 500           // Maximum rows in one logout inventory
  },

  // --- SPIFFE ----------------------------------------------------------
  spiffe: {
    enabled: true,                                      // Enable SPIFFE
    trustDomain: "example.org",                         // Trust domain; restart to apply
    x509KeyType: "ec-p256",                             // X.509 authority key; restart to apply
    jwtKeyType: "ec-p256",                              // JWT authority key; restart to apply
    caTtl: 86400,                                       // Authority lifetime (seconds); restart to apply
    svidTtl: 3600,                                      // X509-SVID lifetime (seconds)
    jwtSvidTtl: 300,                                    // JWT-SVID lifetime (seconds)
    refreshHint: 300,                                   // Bundle refresh hint (seconds)
    svidSubject: "C=US,O=SPIRE",                        // SVID subject DN
    autoCreateEntries: true,                            // Invent a registration entry on first sight
    requireSecurityHeader: true,                        // Require the workload.spiffe.io header
    authRequired: true,                                 // Authenticate the SPIRE Server API; restart to apply
    trustLocalSocket: true,                             // Trust the SPIRE Server API socket as local
    adminIds: "",                                       // Administrator SPIFFE IDs
    clockSkew: 60,                                      // Clock skew (s)
    attestWorkloads: true,                              // Match Workload API callers on selectors
    acceptAssertedSelectors: false,                     // Believe selectors a workload asserts
    maxEntries: 500,                                    // Maximum registration entries
    maxAgents: 200,                                     // Maximum attested agents
    maxFederatedBundles: 32,                            // Maximum federated bundles
    bundlePath: "/spiffe/bundle",                       // Bundle endpoint path; restart to apply
    workloadSocketEnabled: true,                        // Workload API on a Unix socket; restart to apply
    workloadSocket: "/tmp/spire-agent/public/api.sock", // Workload API socket path; restart to apply
    workloadPort: 8092,                                 // Workload API TCP port; restart to apply
    serverPort: 8181,                                   // SPIRE Server API TCP port; restart to apply
    serverSocketEnabled: false,                         // SPIRE Server API on a Unix socket; restart to apply
    serverSocket: "/tmp/spire-server/private/api.sock", // SPIRE Server API socket path; restart to apply
    grpcHost: "0.0.0.0"                                 // gRPC bind address; restart to apply
  },

  // --- Persistence -----------------------------------------------------
  persistence: {
    mode: "memory",                                       // Persistence mode; restart to apply
    dataDir: "./data",                                    // Data directory; restart to apply
    databaseUrl: "postgres://sts:sts@localhost:5432/sts", // Database connection string; restart to apply
    databaseTlsRejectUnauthorized: false,                 // Verify the database certificate; restart to apply
    writeDelay: 1500,                                     // Write delay (ms)
    realms: true,                                         // Persist the realm registry; restart to apply
    appconfig: true                                       // Persist runtime setting changes; restart to apply
  },
};

module.exports = config;
