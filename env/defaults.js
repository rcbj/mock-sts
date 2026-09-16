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
// FOUR SETTINGS ARE DELIBERATELY ABSENT: global.https, oid4vp.walletUrl,
// krb5.serviceDomains and adminApi.audience are DERIVED from a neighbour (from
// oauth2.rfc9700, from oid4vci.walletUrl, from krb5.realm, and from the public
// base URL or the listener's scheme, host and port). A literal here would
// freeze the derivation at whatever it evaluated to the day this file was
// written, so they resolve through their neighbour instead and are exempt from
// the startup refusal for that reason.
//
// See common/CLAUDE.md, and README.md's *Configuration*, which lists every
// setting, its environment variable and its default in one table.
// ---------------------------------------------------------------------------
var config = {
  // --- The log level ---------------------------------------------------
  mode: "development", // Mode
  logLevel: "info",    // Log level

  // --- Global ----------------------------------------------------------
  global: {
    host: "0.0.0.0",              // HTTP bind address; restart to apply
    port: 8081,                   // HTTP port; restart to apply
    trustProxy: false,            // Trust forwarded headers
    trustedProxies: "",           // Trusted proxy addresses
    proxyProtocol: "off",         // PROXY protocol on the TCP listeners; restart to apply
    proxyProtocolTimeoutMs: 5000, // PROXY protocol header timeout (ms)
    publicBaseUrl: "",            // Public base URL
    corsOrigins: ""               // Origins treated as this service's own
  },

  // --- Admin console ---------------------------------------------------
  admin: {
    bootstrapUsername: "admin", // Bootstrap administrator account; restart to apply
    readGroup: "admin-read",    // Admin Read role
    writeGroup: "admin-write",  // Admin Write role
    openWhenEmpty: true         // Open until the bootstrap administrator signs in
  },

  // --- GNAP ------------------------------------------------------------
  gnap: {
    enabled: true,                                                         // Run the GNAP authorization server
    accessTokenFormat: "jwt-signed",                                       // Default access token format
    tokenFormats: "jwt-signed,jwt-encrypted,macaroon,biscuit,zcap",        // Token formats offered
    accessTokenLifetimeS: 3600,                                            // Access token lifetime (seconds)
    interactionLifetimeS: 600,                                             // Interaction lifetime (seconds)
    continueWaitS: 5,                                                      // Continuation wait (seconds)
    maxPolls: 60,                                                          // Polls allowed before too_many_attempts
    signatureMaxAgeS: 300,                                                 // Key proof freshness (seconds)
    interactionStartModes: "redirect,app,user_code,user_code_uri",         // Interaction start modes
    finishMethods: "redirect,push",                                        // Interaction finish methods
    keyProofs: "httpsig,mtls,jwsd,jws",                                    // Key proofing methods
    subIdFormats: "opaque,iss_sub,email,account,uri,phone_number,aliases", // Subject identifier formats
    assertionFormats: "id_token,saml2",                                    // Subject assertion formats
    assertionMaxAgeS: 300,                                                 // Grace for an expired user assertion (seconds)
    keyRotation: true,                                                     // Allow access token key rotation
    tokenManagement: true,                                                 // Offer token management
    bearerTokens: true,                                                    // Issue bearer tokens on request
    durableTokens: false,                                                  // Mark access tokens durable
    revokeOnModify: true,                                                  // Revoke earlier tokens on modification
    instanceIds: true,                                                     // Issue instance identifiers
    continueAfterApproval: true,                                           // Keep approved grants continuable
    consentRequired: true,                                                 // Ask the resource owner
    rememberApprovals: true,                                               // Remember approvals
    allowCrossUser: false,                                                 // Allow a different person to approve
    userCodeLength: 8,                                                     // User code length
    unknownAccessReferences: "accept",                                     // Unregistered access references
    introspection: true,                                                   // Offer token introspection
    resourceRegistration: true,                                            // Offer resource set registration
    tokenDerivation: true,                                                 // Allow downstream token derivation
    pushFinish: true,                                                      // Deliver push interaction finishes
    pushAllowInsecure: false,                                              // Allow http:// and untrusted TLS for push
    pushAllowedHosts: "",                                                  // Push host allowlist
    pushTimeoutMs: 5000,                                                   // Push timeout (ms)
    jweEnc: "A256GCM",                                                     // jwt-encrypted content encryption
    accessTokenCertificateHeader: "x5u",                                   // JWT access token certificate header
    demoResourceServer: true,                                              // Run the demonstration resource server
    caepEvents: true,                                                      // Emit CAEP for grants and tokens
    scopedSignals: true                                                    // Scope a GNAP web application's streams
  },

  // --- XACML -----------------------------------------------------------
  xacml: {
    enforceAccess: true,             // Decide access with policy
    accessPolicy: "access-control",  // Access policy name
    enabled: true,                   // XACML enabled
    maxPolicies: 200,                // Policies the repository may hold
    pepBias: "deny-biased",          // What the embedded PEP does with a non-Permit
    returnPolicyIdList: false,       // Always return the applicable policy identifiers
    remotePeps: true,                // Remote Policy Enforcement Points may register
    pepRequireCertificate: true,     // A registering PEP must present a client certificate
    pipMaxPerWindow: 600,            // PIP queries one caller may make per rate-limit window
    pipMaxDesignators: 50,           // Attributes one PIP query may ask about
    maxPeps: 50,                     // Remote PEPs the register may hold
    pepStaleAfterS: 300,             // Seconds before a registered PEP is reported stale
    pepNotify: true,                 // Nudge a registered PEP when the repository changes
    pepNotifyAllowedHosts: "",       // Notify endpoint allowlist
    pepNotifyAllowInsecure: false,   // Allow http:// and untrusted TLS for a nudge
    pepNotifyTimeoutMs: 2000,        // Nudge timeout (ms)
    issuancePolicy: "role-issuance"  // The policy issuance decisions are made with
  },

  // --- Web security ----------------------------------------------------
  security: {
    rateLimitWindowS: 60,        // Rate-limit window (seconds)
    rateLimitPerIdentity: 5,     // Attempts per identity per window
    rateLimitPerAddress: 20,     // Attempts per address per window
    activationTtlMinutes: 1440,  // Activation link lifetime (minutes)
    passwordResetTtlMinutes: 60, // Password reset link lifetime (minutes)
    passwordHashLogN: 15,        // Password hash cost (log2 of scrypt N)
    passwordHashR: 8,            // Password hash block size (scrypt r)
    passwordHashP: 1             // Password hash parallelism (scrypt p)
  },

  // --- Web security ----------------------------------------------------
  authn: {
    sessionLifetimeS: 3600,         // Session lifetime (seconds)
    sessionIdleTimeoutS: 0,         // Session idle timeout (seconds, 0 = none)
    pendingTtlS: 600,               // How long a sign-in waits at the screen (seconds)
    mfaStepTtlS: 300,               // How long a second-factor step waits (seconds)
    mfaRequired: false,             // Require a second factor of everybody
    unauthenticatedSessions: false  // Offer "Continue without signing in"
  },

  // --- Web security ----------------------------------------------------
  oidcRp: {
    maxFlows: 200,           // Console and portal sign-ins in flight, per realm
    backChannelTimeoutS: 10, // Console and portal back-channel timeout (seconds)
    maxRedirectUris: 20,     // Most redirect URIs the console and portal clients may learn
    renewBeforeExpiryS: 60   // Console and portal token renewal lead time (seconds)
  },

  // --- Web security ----------------------------------------------------
  credentials: {
    factorScanLimit: 5000  // People read for the second-factor roster
  },

  // --- TOTP MFA --------------------------------------------------------
  totp: {
    enabled: true,           // Offer authenticator apps (TOTP)
    issuer: "",              // Authenticator app label
    algorithm: "SHA1",       // HMAC digest
    digits: 6,               // Digits in a code
    period: 30,              // Seconds in a step
    window: 1,               // Steps of clock skew forgiven
    secretBytes: 20,         // Shared secret length (bytes)
    enrolmentTtlMinutes: 10  // Unconfirmed enrolment lifetime (minutes)
  },

  // --- Backup codes ----------------------------------------------------
  backupCodes: {
    enabled: true,    // Issue recovery codes with a second factor
    count: 10,        // Codes in a set
    length: 10,       // Characters in a code
    pendingTtlS: 900, // How long an unconfirmed set of recovery codes waits (seconds)
    groupSize: 5      // Characters between the dashes
  },

  // --- WebAuthn --------------------------------------------------------
  webauthn: {
    enabled: true,                       // Offer security keys (WebAuthn)
    rpName: "Mock authorization server", // Relying party name
    rpId: "",                            // RP ID override
    allowedOrigins: "",                  // Allowed origins
    algorithms: "ES256,RS256",           // Algorithms offered
    userVerification: "preferred",       // User verification
    attestation: "direct",               // Attestation conveyance
    timeoutMs: 60000,                    // Ceremony timeout (ms)
    authenticatorAttachment: "any",      // Authenticator attachment (CTAP)
    residentKey: "discouraged",          // Discoverable credential (CTAP resident key)
    credProps: true,                     // Ask for the credProps extension
    primaryAllowed: true,                // Allow a key as a PRIMARY credential
    mfaAllowed: true,                    // Allow a key as a SECOND factor
    maxKeysPerPerson: 10                 // Keys per person
  },

  // --- Key material ----------------------------------------------------
  keys: {
    source: "auto",                  // Where signing keys come from; restart to apply
    plaintextRetention: "timed",     // How long a decrypted private key is kept
    plaintextTtlS: 300,              // Decrypted key idle timeout (seconds)
    kidFormat: "internal",           // Signed token kid format
    kekProvider: "file",             // Key-encryption key provider; restart to apply
    kekFile: "/run/secrets/sts-kek", // Key-encryption key file; restart to apply
    kekRef: "",                      // Key-encryption key reference; restart to apply
    kekVault: "",                    // Vault or Key Vault URL; restart to apply
    vaultClientCert: "",             // Client certificate for the secret store; restart to apply
    vaultClientKey: "",              // Client key for the secret store; restart to apply
    vaultCaCert: "",                 // Trust anchor for the secret store; restart to apply
    vaultCertRole: "",               // Certificate auth role; restart to apply
    vaultCertAuthMount: "cert",      // Certificate auth mount path; restart to apply
    kekField: "value",               // Vault secret field; restart to apply
    kekToken: "",                    // Vault token; restart to apply
    storeProbeTimeoutMs: 5000,       // Secret store probe timeout (ms)
    kekRegion: ""                    // AWS region; restart to apply
  },

  // --- Global ----------------------------------------------------------
  workers: {
    count: 5,                                                      // Worker processes
    jobTimeoutS: 120,                                              // Worker job timeout (seconds)
    requestCount: 0,                                               // Request worker processes; restart to apply
    dispatch: "",                                                  // Handled in a request worker; restart to apply
    fanout: "/scim,/xacml,/admin-api",                             // Dispatched paths with no session affinity; restart to apply
    surfaceCount: 0,                                               // Hosted-surface worker processes; restart to apply
    surfaces: "/admin,/portal",                                    // Paths handled by the hosted-surface workers; restart to apply
    batch: "/scim,/admin/signals/receive,/portal/signals/receive", // Batch traffic paths
    batchWorkerShare: 50,                                          // Share of workers batch traffic may use (%)
    batchConcurrency: 8,                                           // Batch requests in flight per lane worker
    batchQueueLimit: 5000,                                         // Batch requests waiting
    batchQueueTimeoutS: 60,                                        // Longest a batch request waits (seconds)
    maxSockets: 64,                                                // Connections per request worker; restart to apply
    readYourWrite: false,                                          // Read-your-write across request workers
    socketDir: ""                                                  // Request worker socket directory; restart to apply
  },

  // --- Trust realms ----------------------------------------------------
  realms: {
    enabled: true,        // Trust realms enabled
    pathSegment: "realm"  // Realm path segment
  },

  // --- OAuth 2.0 / OIDC ------------------------------------------------
  oauth2: {
    issuer: "",                                  // Issuer identifier
    rfc9700: false,                              // RFC 9700 mode; restart to apply
    oauth21: false,                              // OAuth 2.1 mode; restart to apply
    consentRequired: true,                       // Ask for consent
    delegatedPermissionsEnforced: false,         // Enforce delegated permissions
    tokenExchangeRefreshToken: "when-requested", // Refresh token from a token exchange
    breakIdTokenNonce: false,                    // Break the ID Token nonce
    refreshIdleSeconds: 86400,                   // Refresh token idle timeout (s)
    revokeRefreshOnLogout: true,                 // Revoke refresh tokens on sign-out
    eddsaCurve: "Ed25519",                       // EdDSA curve
    jwtBearerGrant: true,                        // JWT bearer authorization grant (RFC 7523 section 2.1)
    jwtBearerRequireRegisteredIssuer: true,      // Require a registered assertion issuer
    jwtBearerMaxLifetimeS: 300,                  // Longest assertion lifetime accepted (s)
    saml2BearerGrant: true,                      // SAML 2.0 bearer authorization grant (RFC 7522 section 2.1)
    saml2BearerRequireRegisteredIssuer: true,    // Require a registered SAML assertion issuer
    saml2BearerMaxLifetimeS: 300,                // Longest SAML assertion lifetime accepted (s)
    clientAssertionSkewS: 60,                    // Client assertion clock skew (s)
    assertionReplayCacheSize: 1000,              // Assertion replay cache size (per realm)
    dpopNonceRequired: false,                    // Require a DPoP server nonce
    dpopIatSkewS: 300,                           // DPoP proof iat window (s)
    dpopNonceTtlS: 300,                          // DPoP server nonce lifetime (s)
    openRegistration: false,                     // Open dynamic client registration (product mode)
    softwareStatementRequireTrustedIssuer: true, // Refuse a software statement from an undeclared issuer
    softwareStatementOpensRegistration: true,    // A trusted software statement opens a closed registration endpoint
    softwareStatementRequired: false,            // Require a software statement on every registration
    softwareStatementLifetimeS: 31536000,        // Issued software statement lifetime (s)
    registeredSecretLifetimeS: 0,                // Dynamically registered secret lifetime (s)
    registeredClientIdPrefix: "sts-client-",     // Dynamically registered client_id prefix
    registeredClientIdBytes: 8,                  // Dynamically registered client_id random bytes
    registeredSecretBytes: 24,                   // Dynamically registered secret random bytes
    authorizationCodeTtlS: 300,                  // Authorization code lifetime (s)
    maxPendingTransactions: 500,                 // RFC 9700: remembered transactions (per realm)
    maxRefreshTokenFamilies: 2000,               // RFC 9700: remembered refresh tokens (per realm)
    signedMetadataAlgorithm: "RS256",            // Algorithm signed_metadata is signed with
    accessTokenCertificateHeader: "x5u",         // Access token certificate header
    idTokenCertificateHeader: "x5u",             // ID Token certificate header
    refreshTokenCertificateHeader: "x5u",        // Refresh token certificate header
    userinfoCertificateHeader: "x5u",            // Signed UserInfo certificate header
    introspectionCertificateHeader: "x5u",       // JWT introspection response certificate header
    signedMetadataCertificateHeader: "x5u",      // signed_metadata certificate header
    signedMetadataCacheS: 60,                    // signed_metadata cache (s)
    maxSignedMetadataEntries: 64,                // signed_metadata cache entries
    basicAuthRealm: "sts",                       // Token endpoint Basic realm
    maxAuthorizationServerProfiles: 200,         // Named authorization servers (per realm)
    maxRequestedClaims: 64,                      // Claims one claims request may name
    accessTokenTtlS: 3600,                       // Access token lifetime (s)
    idTokenTtlS: 3600,                           // ID Token lifetime (s)
    refreshTokenTtlS: 86400,                     // Refresh token lifetime (s)
    clockSkewS: 30,                              // Token clock skew (s)
    redirectUris: "",                            // Registered redirect URIs
    loopbackPortWildcard: true,                  // Loopback port wildcard
    refreshTokenEncryptionAlg: "RSA-OAEP-256",   // Refresh token encryption: key management (alg)
    refreshTokenEncryptionEnc: "A256GCM",        // Refresh token encryption: content (enc)
    refreshTokenEncryptionKeyBits: 2048,         // Refresh token encryption: RSA key size (bits)
    refreshTokenEncryptionCurve: "P-256",        // Refresh token encryption: EC curve
    requireSignedRequestObject: false,           // Require a signed request object (RFC 9101)
    authorizationDetailsMaxEntries: 20,          // Most authorization_details entries in one request (RFC 9396)
    requestUriTimeoutMs: 5000,                   // request_uri fetch timeout (ms)
    requestUriMaxBytes: 65536,                   // request_uri largest response (bytes)
    requireRequestObjectType: false,             // Require typ oauth-authz-req+jwt on a request object
    requireRequestObjectIssuerAudience: false,   // Require iss and aud in a request object
    requestUriCacheS: 0,                         // request_uri content cache (s)
    requestObjectEncryptionKeyBits: 2048,        // Request object encryption: RSA key size (bits)
    requestObjectEncryptionCurve: "P-256",       // Request object encryption: EC curve
    pushedAuthorizationRequests: true,           // Pushed authorization requests (RFC 9126)
    requirePushedAuthorizationRequests: false,   // Require pushed authorization requests
    parRequestUriLifetimeS: 60,                  // Pushed request_uri lifetime (seconds)
    parMaxRequests: 10000,                       // Pushed requests held at once
    parMaxBodyBytes: 65536,                      // Largest pushed authorization request (bytes)
    parRequestsPerMinute: 600,                   // Pushed requests per client per window
    parAllowUnregisteredRedirectUris: false,     // Pushed requests may name an unregistered redirect_uri
    stepUpAcrValues: "",                         // Step-up: acr values this service's resource server requires
    stepUpMaxAgeS: -1,                           // Step-up: oldest authentication this service's resource server accepts (s)
    frontchannelLogout: true                     // OpenID Connect Front-Channel Logout
  },

  // --- PKI -------------------------------------------------------------
  pki: {
    crlLifetimeMinutes: 60,                    // How long a CRL claims to be fresh
    httpPort: 8082,                            // Plain-HTTP revocation listener port; restart to apply
    distributionBaseUrl: "",                   // Base URL published in CRL and OCSP addresses
    distributionPort: 0,                       // Port published in HTTP CRL and OCSP addresses
    distributionLdapHost: "",                  // Host published in ldap:// CRL addresses
    distributionLdapPort: 0,                   // Port published in ldap:// CRL addresses
    publishCrlToDirectory: true,               // Publish every CRL into the embedded directory
    autoBuild: true,                           // Build the certificate authority at startup; restart to apply
    keyAlgorithm: "rsa-2048",                  // Default CA key algorithm
    signatureAlgorithm: "",                    // Default CA signature algorithm
    organisation: "sts",                       // Default organisation name (O=)
    personSelfService: true,                   // Let a person issue their own signing key pair
    leafLifetimeDays: 365,                     // Default lifetime of an issued key pair (days)
    rootLifetimeYears: 0,                      // Root CA lifetime (years, 0 = the profile's)
    intermediateLifetimeYears: 0,              // Intermediate CA lifetime (years, 0 = the profile's)
    issuingLifetimeYears: 0,                   // Issuing CA lifetime (years, 0 = the profile's)
    maxStoredObjects: 200,                     // Certificates and keys the workbench store keeps, per realm
    personSelfServicePerIdentity: 5,           // Self-issued key pairs one person may ask for per window
    personSelfServicePerAddress: 5,            // Self-issued key pairs one address may ask for per window
    personTlsClientCertificateMax: 5,          // TLS client certificates one person may hold
    applicationTlsClientCertificateMax: 5,     // TLS client certificates one application may hold
    revocationCheck: "auto",                   // Revocation check on a presented certificate
    revocationRequireDistributionPoint: false, // Hard-fail refuses a certificate whose issuer names no CRL
    revocationFetchTimeoutMs: 3000,            // CRL fetch timeout (milliseconds)
    revocationMaxCrlBytes: 1048576,            // Largest CRL fetched (bytes)
    revocationCrlCacheEntries: 256,            // Foreign CRLs kept in memory
    revocationCrlMaxAgeS: 3600,                // Longest a fetched CRL is believed (seconds)
    revocationFailureRetryS: 60,               // Wait before retrying a CRL that failed (seconds)
    revocationOcsp: "first",                   // OCSP for a foreign certificate
    revocationOcspMaxAgeS: 3600,               // Longest an OCSP response is believed (seconds)
    revocationOcspRequireNonce: false,         // Refuse an OCSP response that does not echo the nonce
    revocationClockSkewS: 300,                 // Clock skew allowed on CRL and OCSP freshness (seconds)
    revocationCrlIssuersFile: "",              // Certificates that may sign an indirect CRL
    revocationLdap: "ldaps",                   // LDAP revocation addresses
    revocationLdapCaFile: "",                  // CA certificates for ldaps revocation directories
    revocationLdapDirectory: "",               // Directory for CRL names relative to their issuer
    enrollmentMaxCertificatesPerEntry: 20      // Enrolled certificates one entry may hold
  },

  // --- ACME ------------------------------------------------------------
  acme: {
    enabled: true,                                                                                                                                 // Run the ACME server
    allowedProfiles: "tls-server,tls-client,tls-server-client,digital-signature,key-encipherment,code-signing,email,timestamping,smartcard-logon", // Certificate profiles ACME may issue
    defaultProfile: "tls-client",                                                                                                                  // Profile when an order names none
    certificateLifetimeDays: 90,                                                                                                                   // Certificate lifetime (days)
    maxRequestBytes: 65536,                                                                                                                        // Largest request body (bytes)
    attemptsPerIdentity: 30,                                                                                                                       // Failed requests per account a window
    attemptsPerAddress: 120,                                                                                                                       // Failed requests per address a window
    nonceLifetimeS: 300,                                                                                                                           // Replay nonce lifetime (seconds)
    orderLifetimeS: 86400,                                                                                                                         // Order lifetime (seconds)
    eabLifetimeS: 604800                                                                                                                           // External account binding key lifetime (seconds)
  },

  // --- EST -------------------------------------------------------------
  est: {
    enabled: true,                                                                                                                                 // Run the EST server
    allowedProfiles: "tls-server,tls-client,tls-server-client,digital-signature,key-encipherment,code-signing,email,timestamping,smartcard-logon", // Certificate profiles EST may issue
    defaultProfile: "tls-client",                                                                                                                  // Profile at the unlabelled path
    certificateLifetimeDays: 365,                                                                                                                  // Certificate lifetime (days)
    maxRequestBytes: 65536,                                                                                                                        // Largest request body (bytes)
    attemptsPerIdentity: 10,                                                                                                                       // Failed requests per identity a window
    attemptsPerAddress: 60,                                                                                                                        // Failed requests per address a window
    basicAuthentication: true,                                                                                                                     // Accept HTTP Basic
    certificateAuthentication: true,                                                                                                               // Accept a TLS client certificate
    serverKeyGeneration: true                                                                                                                      // Offer /serverkeygen
  },

  // --- SCEP ------------------------------------------------------------
  scep: {
    enabled: true,                                                                                                                                 // Run the SCEP server
    allowedProfiles: "tls-server,tls-client,tls-server-client,digital-signature,key-encipherment,code-signing,email,timestamping,smartcard-logon", // Certificate profiles SCEP may issue
    defaultProfile: "tls-client",                                                                                                                  // Profile a new challenge defaults to
    certificateLifetimeDays: 365,                                                                                                                  // Certificate lifetime (days)
    maxRequestBytes: 262144,                                                                                                                       // Largest PKIOperation message (bytes)
    attemptsPerIdentity: 10,                                                                                                                       // Failed requests per challenge a window
    attemptsPerAddress: 60,                                                                                                                        // Failed requests per address a window
    challengeLifetimeS: 3600,                                                                                                                      // Challenge password lifetime (seconds)
    raKeyAlgorithm: "rsa-2048"                                                                                                                     // RA certificate key algorithm
  },

  // --- Management API --------------------------------------------------
  adminApi: {
    authRequired: true, // Require an access token on /admin-api
    clientSecret: ""    // The management API client's secret; restart to apply
  },

  // --- Protocol debugger -----------------------------------------------
  debugger: {
    enabled: "auto",                       // Embed the protocol debugger; restart to apply
    port: 8444,                            // Debugger listener port; restart to apply
    publicBaseUrl: "",                     // Debugger public base URL; restart to apply
    uiDirectory: "debugger/embedded/ui",   // Built debugger UI; restart to apply
    apiDirectory: "debugger/embedded/api", // Built debugger api; restart to apply
    allowedDestinations: "",               // Extra destinations the api may dial in product mode; restart to apply
    startTimeoutS: 30,                     // Seconds the api process has to start
    restartLimit: 5,                       // Failed starts before the api is given up on
    proxyTimeoutS: 120,                    // Seconds an /api call may take
    maxRequestBytes: 5242880               // Largest /api request body
  },

  // --- Applications ----------------------------------------------------
  applications: {
    max: 500,           // Applications remembered
    seedInternal: true  // Seed the console and this API as applications; restart to apply
  },

  // --- Applications ----------------------------------------------------
  portal: {
    applicationScanLimit: 1000  // Applications the user portal evaluates for one person
  },

  // --- Federation ------------------------------------------------------
  federation: {
    enabled: true,                                                           // Federation endpoints answer
    max: 50,                                                                 // Relationships remembered
    usernamePrefix: "",                                                      // Prefix for federated usernames
    loginButtons: true,                                                      // Offer partners at the sign-in screen
    outbound: true,                                                          // Make back-channel requests to partners
    outboundTimeoutMs: 15000,                                                // Back-channel timeout (ms)
    outboundAllowInsecure: false,                                            // Allow http:// and untrusted TLS to a partner
    requestTtlMin: 10,                                                       // Outbound request lifetime (minutes)
    maxContexts: 500,                                                        // Sign-ins in flight per realm
    maxApplicationLength: 256,                                               // Longest application a sign-in may name
    maxApplicationUse: 64,                                                   // Per-application counters kept per relationship
    releaseIndexTtlMs: 5000,                                                 // Release-policy index lifetime (ms)
    maxResponseBytes: 262144,                                                // Largest back-channel response (bytes)
    jwtAlgorithms: "RS256,RS384,RS512,PS256,PS384,PS512,ES256,ES384,ES512",  // Algorithms accepted on a partner's JWT
    spNameIdFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified"  // NameIDFormat in this service's SP metadata
  },

  // --- SAML ------------------------------------------------------------
  saml: {
    issuer: "urn:wstrust:mock:sts",                         // Assertion issuer
    clockSkewS: 0,                                          // Assertion clock skew (s)
    signatureAlgorithm: "rsa-sha256",                       // XML signature algorithm
    canonicalizationAlgorithm: "exclusive",                 // XML canonicalization
    organizationName: "sts",                                // Metadata OrganizationName
    organizationDisplayName: "Mock security token service", // Metadata OrganizationDisplayName
    organizationUrl: ""                                     // Metadata OrganizationURL
  },

  // --- SAML 2.0 --------------------------------------------------------
  saml2: {
    entityId: "urn:sts:idp",                                               // Identity provider entityID
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
    defaultSingleLogoutService: "",                                        // Fallback logout return address
    requestTtlMin: 10,                                                     // Held AuthnRequest lifetime (minutes)
    mockSpContextTtlMin: 30,                                               // Mock service provider RelayState lifetime (minutes)
    redirectWarnLength: 8000,                                              // Redirect-binding length warning (characters)
    spMetadataMaxBytes: 524288                                             // Largest SP metadata document fetched (bytes)
  },

  // --- SAML 1.1 --------------------------------------------------------
  saml11: {
    providerId: "urn:sts:idp:saml11",                                      // Identity provider providerID
    perApplicationProviderId: true,                                        // A providerID per relying party
    assertionLifetimeMin: 60,                                              // Assertion lifetime (minutes)
    signAssertion: true,                                                   // Sign the assertion
    signResponse: true,                                                    // Sign the response
    nameIdFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified", // Default NameIdentifier format
    defaultProfile: "post",                                                // Default browser profile
    artifactTtlS: 300,                                                     // Artifact lifetime (seconds)
    autocreateApplications: true,                                          // Register relying parties on sight
    requestTtlMin: 10,                                                     // Held flow lifetime (minutes)
    assertionCacheMax: 500                                                 // Assertions kept for AssertionIDReference
  },

  // --- WS-Trust --------------------------------------------------------
  wstrust: {
    issuer: "urn:wstrust:mock:sts", // Token issuer
    tokenLifetimeMin: 60,           // Token lifetime (minutes)
    maxTokenLifetimeMin: 1440,      // Longest lifetime a request may ask for (minutes)
    jwtAlgorithm: "RS256",          // JWT signature algorithm
    jwtCertificateHeader: "x5u"     // JWT certificate header
  },

  // --- WS-Federation assertions ----------------------------------------
  wsfed: {
    assertionLifetimeMin: 60,         // Assertion lifetime (minutes)
    entityId: "urn:wstrust:mock:sts", // Entity ID
    mockRpContextTtlMin: 30           // Mock relying party wctx lifetime (minutes)
  },

  // --- TLS -------------------------------------------------------------
  tls: {
    port: 8443,                                          // TLS port; restart to apply
    mutualPort: 9443,                                    // Mutual-TLS port; restart to apply
    trustIssuedClientCertificates: true,                 // Trust TLS client certificates issued on the user portal; restart to apply
    hostnames: "localhost,sts,sts-mock,sts.example.com", // Certificate hostnames; restart to apply
    ips: "127.0.0.1",                                    // Certificate IP addresses; restart to apply
    certificateAlgorithms: "rsa",                        // Server certificate algorithms; restart to apply
    certificateFile: "",                                 // Server certificate file; restart to apply
    keyFile: "",                                         // Server private key file; restart to apply
    minVersion: "TLSv1.2",                               // Minimum TLS version; restart to apply
    ciphers: "",                                         // TLS cipher list; restart to apply
    trustAnchorsFile: "",                                // Client certificate trust anchors file; restart to apply
    selfSignedKeyBits: 2048,                             // Self-signed certificate RSA key size; restart to apply
    selfSignedValidityYears: 2,                          // Self-signed certificate validity (years); restart to apply
    selfSignedOrganization: "sts"                        // Self-signed certificate organization; restart to apply
  },

  // --- OID4VCI ---------------------------------------------------------
  oid4vci: {
    walletUrl: "http://localhost:3000",                    // Wallet URL
    authorizationServer: "",                               // Authorization server
    batchSize: 4,                                          // Batch size
    deferredReadyMs: 4000,                                 // Deferred: ready after (ms)
    deferredIntervalS: 2,                                  // Deferred: poll interval (s)
    offerUsername: "diploma.student",                      // Offer username
    requestEncryptionRequired: false,                      // Require encrypted credential requests
    txCodeLength: 5,                                       // Transaction Code length (digits)
    txCodeMaxAttempts: 5,                                  // Wrong Transaction Codes before the code is spent (product)
    offerTtlS: 600,                                        // Credential Offer lifetime (s)
    preAuthorizedPollIntervalS: 5,                         // Pre-authorized grant: interval (s)
    walletIssuancePath: "/vc-issuance-1.html",             // Wallet issuance page
    allowedWalletUrls: "",                                 // Other wallet URLs an offer link may name (product)
    requestEncryptionKeyBits: 2048,                        // Request encryption key size (bits)
    requestEncryptionEncValues: "A128GCM,A256GCM",         // Request encryption: enc values
    responseEncryptionEncValues: "A128GCM,A256GCM",        // Response encryption: enc values
    responseEncryptionRequired: false,                     // Require encrypted credential responses
    credentialLifetimeS: 2592000,                          // Issued credential lifetime (s)
    credentialSigningAlgorithm: "RS256",                   // Algorithm credentials are signed with
    credentialCertificateHeader: "x5u",                    // Credential certificate header
    signedMetadataCertificateHeader: "x5u",                // Issuer signed_metadata certificate header
    proofIatWindowS: 600,                                  // Proof of possession iat window (s)
    cNonceTtlS: 300,                                       // c_nonce lifetime (s)
    issuerDisplayName: "IdP Tools Mock Credential Issuer", // Issuer display name
    domainLinkageLifetimeS: 31536000,                      // Domain Linkage Credential lifetime (s)
    generatedDidCredentialLifetimeS: 3600,                 // /did/generate credential lifetime (s)
    sdJwtIssuerDid: false,                                 // Name the SD-JWT VC issuer by DID; restart to apply
    ldpVcIssuerDid: false                                  // Name the ldp_vc issuer by DID; restart to apply
  },

  // --- OID4VP ----------------------------------------------------------
  oid4vp: {
    clientId: "sts-verifier",                          // Verifier client ID
    requestObjectCertificateHeader: "x5u",             // Request Object certificate header
    kbMaxAgeS: 600,                                    // Key Binding max age (s)
    claims: "given_name,family_name",                  // Requested claims
    presentationRequestTtlS: 600,                      // Presentation request lifetime (s)
    walletPresentationPath: "/vc-presentation-1.html", // Wallet presentation page
    allowedWalletUrls: "",                             // Other wallet URLs a request link may name (product)
    trustedIssuerCertificates: "",                     // Other trusted credential issuers (PEM)
    expectedVct: "urn:idptools:sd-jwt-vc:identity",    // Expected SD-JWT VC type (vct)
    maxRequestedClaims: 40                             // Claims one request may ask for
  },

  // --- Kerberos --------------------------------------------------------
  krb5: {
    enabled: true,                                                 // Enable Kerberos
    realm: "EXAMPLE.COM",                                          // Realm; restart to apply
    kdcPort: 88,                                                   // KDC port; restart to apply
    servicePort: 8888,                                             // Test service port; restart to apply
    servicePrincipal: "HTTP/web.example.com",                      // Service principal; restart to apply
    servicePassword: "service-account-password",                   // Service principal password; restart to apply
    serviceSalt: "",                                               // Service principal salt; restart to apply
    enctypes: "18,17,20,19,23",                                    // Encryption types; restart to apply
    kvno: 3,                                                       // Key version number; restart to apply
    ticketLifetimeSeconds: 36000,                                  // Ticket lifetime (s)
    renewLifetimeSeconds: 604800,                                  // Renewable lifetime (s)
    logonServer: "DC01",                                           // PAC logon server
    maxRequestBytes: 131072,                                       // Largest KDC request over TCP (bytes)
    udpMaxReplyBytes: 1465,                                        // Largest KDC reply over UDP (bytes)
    serviceMaxTokenBytes: 65536,                                   // Largest AP-REQ the acceptor reads (bytes)
    replayCacheMaxEntries: 10000,                                  // Replay cache size
    spnegoPendingTtlSeconds: 120,                                  // Unfinished SPNEGO negotiation lifetime (s)
    spnegoMaxPending: 64,                                          // Unfinished SPNEGO negotiations held
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
    personKeys: true,                                              // Kerberos keys for directory people
    retainedKeyVersions: 1,                                        // Previous key versions kept
    retainedKeyTtlS: 0,                                            // Previous key version lifetime (s)
    spnegoLoginButton: true,                                       // Offer Kerberos at the sign-in screen
    s2kparams: "omit"                                              // Send s2kparams
  },

  // --- LDAP ------------------------------------------------------------
  ldap: {
    port: 389,                                                                                                                                  // LDAP port; restart to apply
    tlsPort: 636,                                                                                                                               // LDAPS port; restart to apply
    baseDn: "dc=example,dc=com",                                                                                                                // Base DN; restart to apply
    autocreateUsers: true,                                                                                                                      // Auto-create users
    maxEntries: 2000,                                                                                                                           // Maximum entries
    sizeLimit: 500,                                                                                                                             // Search size limit
    plainListener: true,                                                                                                                        // Plain LDAP listener; restart to apply
    selfWritableAttributes: "telephoneNumber,mobile,homePhone,displayName,preferredLanguage,postalAddress,street,l,st,postalCode,userPassword"  // Attributes a person may change on their own entry
  },

  // --- SCIM ------------------------------------------------------------
  scim: {
    enabled: true,               // SCIM enabled
    maxResults: 200,             // Maximum results per page
    bulkMaxOperations: 100,      // Bulk operation limit
    bulkMaxPayloadSize: 1048576, // Bulk payload limit
    authDiscovery: false,        // Authenticate discovery too
    authRealm: "SCIM",           // Authentication realm
    scopeRead: "scim:read",      // OAuth scope to read
    scopeWrite: "scim:write",    // OAuth scope to write
    authBearer: true,            // Offer OAuth 2.0 tokens
    authBasic: true,             // Offer HTTP Basic
    authDigest: true,            // Offer HTTP Digest
    digestPassword: "password!", // The shared Digest password
    digestNonceSeconds: 300,     // Digest nonce lifetime
    digestMd5: true,             // Offer MD5 for Digest
    maxDigestNonces: 2000,       // Digest nonces held
    authHoba: true,              // Offer HOBA
    hobaMaxAgeSeconds: 600,      // HOBA challenge lifetime
    maxHobaChallenges: 2000,     // HOBA challenges held
    maxHobaSeen: 5000,           // HOBA signatures remembered
    authCookie: true,            // Offer the session cookie
    authClientCert: true         // Offer TLS client certificates
  },

  // --- SSF -------------------------------------------------------------
  ssf: {
    enabled: true,                                                                                                                                        // SSF enabled
    issuer: "",                                                                                                                                           // Transmitter issuer identifier
    signingAlgorithm: "RS256",                                                                                                                            // Algorithm SETs are signed with
    setCertificateHeader: "x5u",                                                                                                                          // SET certificate header
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
    pushMaxResponseBytes: 65536,                                                                                                                          // Largest push response read (bytes)
    pushRetries: 0,                                                                                                                                       // Push retries
    pushRetryDelayMs: 1000,                                                                                                                               // Push retry delay (ms)
    pushConcurrency: 8,                                                                                                                                   // Concurrent pushes
    pushBacklog: 2000,                                                                                                                                    // Pushes waiting for a slot
    deadStreamTimeoutS: 300,                                                                                                                              // Dead stream timeout (seconds)
    deadLetterRetentionS: 3600,                                                                                                                           // Dead letters kept (seconds)
    deadLetterMaxPerStream: 1000,                                                                                                                         // Dead letters per stream
    deadLetterSweepS: 60,                                                                                                                                 // Dead-letter sweep interval (seconds)
    authBasic: true,                                                                                                                                      // Offer HTTP Basic
    internalReceivers: true,                                                                                                                              // Register the console and the portal as receivers; restart to apply
    maxStreams: 25,                                                                                                                                       // Streams per realm
    maxSubjectsPerStream: 100,                                                                                                                            // Subjects per stream
    maxQueuedEvents: 200,                                                                                                                                 // Queued events per stream
    pollMaxEvents: 20,                                                                                                                                    // Events per poll
    maxReceivedEvents: 200,                                                                                                                               // Received events kept
    maxStreamLogEntries: 200,                                                                                                                             // Log lines per stream
    authScopeRead: "ssf:read",                                                                                                                            // Scope to read a stream
    authScopeWrite: "ssf:write",                                                                                                                          // Scope to change a stream
    receiveEnabled: true,                                                                                                                                 // Accept pushed events
    receiveRequireSignature: false,                                                                                                                       // Refuse a SET whose signature does not verify
    legacySubClaim: false,                                                                                                                                // Also emit the deprecated `sub` claim
    breakSetSignature: false                                                                                                                              // Sign every SET badly
  },

  // --- CAEP ------------------------------------------------------------
  caep: {
    enabled: true,                                                                                                                                                                    // CAEP enabled
    autoEmit: true,                                                                                                                                                                   // Emit events when something really happens
    autoEmitTypes: "session-established,session-presented,session-revoked,credential-change,assurance-level-change",                                                                  // Which acts emit automatically
    eventsSupported: "session-revoked,session-established,session-presented,token-claims-change,credential-change,assurance-level-change,device-compliance-change,risk-level-change", // CAEP event types offered
    assuranceNamespace: "NIST-AAL",                                                                                                                                                   // Assurance namespace
    defaultRiskLevel: "MEDIUM",                                                                                                                                                       // Default risk level
    reasonLanguage: "en",                                                                                                                                                             // Language tag on reason_admin / reason_user
    includeReasons: true,                                                                                                                                                             // Send reason_admin and reason_user
    maxSessionsTracked: 200,                                                                                                                                                          // Sessions tracked
    eventsPerSession: 25,                                                                                                                                                             // Events remembered per session
    historyPerSession: 10,                                                                                                                                                            // Credential changes remembered per session
    omitEventTimestamp: false                                                                                                                                                         // Leave event_timestamp out
  },

  // --- RISC ------------------------------------------------------------
  risc: {
    enabled: true,                                                                                                                                                                                                                                                                                    // RISC enabled
    autoEmit: true,                                                                                                                                                                                                                                                                                   // Emit events when the directory really changes
    autoEmitTypes: "account-purged,account-disabled,account-enabled,identifier-changed,account-credential-change-required,recovery-information-changed",                                                                                                                                              // Which acts emit automatically
    eventsSupported: "account-credential-change-required,account-purged,account-disabled,account-enabled,identifier-changed,identifier-recycled,credential-compromise,opt-in,opt-out-initiated,opt-out-cancelled,opt-out-effective,recovery-activated,recovery-information-changed,sessions-revoked", // RISC event types offered
    subjectFormat: "iss_sub",                                                                                                                                                                                                                                                                         // How an account subject is named
    honourOptOut: true,                                                                                                                                                                                                                                                                               // Stop sending about an account that opted out
    googleSubjectType: false,                                                                                                                                                                                                                                                                         // Write subject_type instead of format
    reasonLanguage: "en",                                                                                                                                                                                                                                                                             // Language tag on reason_admin / reason_user
    includeReasons: true,                                                                                                                                                                                                                                                                             // Send reason_admin and reason_user
    omitEventTimestamp: false,                                                                                                                                                                                                                                                                        // Leave event_timestamp out
    maxAccountsTracked: 200,                                                                                                                                                                                                                                                                          // Accounts tracked
    eventsPerAccount: 25,                                                                                                                                                                                                                                                                             // Events remembered per account
    historyPerAccount: 10                                                                                                                                                                                                                                                                             // Credential and identifier changes remembered per account
  },

  // --- Group claim -----------------------------------------------------
  groups: {
    claim: true,             // Carry a groups claim
    claimName: "groups",     // Claim name
    claimValue: "cn",        // What names a group
    claimFromMemberOf: true  // Believe an entry's own memberOf
  },

  // --- Roles -----------------------------------------------------------
  roles: {
    claim: true,                   // Carry a roles claim
    claimName: "roles",            // Role claim name
    enforceIssuance: true,         // Decide issuance on roles
    maxRoles: 200,                 // Maximum roles
    remotePepGroup: "remote-peps", // Group granting the REMOTE_PEPS role
    xacmlUserGroup: "xacml-users"  // Group granting the XACML_USER role
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
    enabled: true,                                           // Enable SPIFFE
    trustDomain: "example.org",                              // Trust domain; restart to apply
    x509KeyType: "ec-p256",                                  // X.509 authority key; restart to apply
    jwtKeyType: "ec-p256",                                   // JWT authority key; restart to apply
    caTtl: 86400,                                            // Authority lifetime (seconds); restart to apply
    svidTtl: 3600,                                           // X509-SVID lifetime (seconds)
    jwtSvidTtl: 300,                                         // JWT-SVID lifetime (seconds)
    refreshHint: 300,                                        // Bundle refresh hint (seconds)
    svidSubject: "C=US,O=SPIRE",                             // SVID subject DN
    caSubject: "CN=sts SPIFFE {kind} ({trustDomain}),O=sts", // CA subject DN template
    retainedAuthorities: 4,                                  // Authorities kept published after a rotation
    agentSvidTtl: 0,                                         // Agent SVID lifetime (seconds)
    joinTokenTtl: 600,                                       // Join token lifetime (seconds)
    maxJoinTokens: 256,                                      // Unspent join tokens held
    maxPageSize: 1000,                                       // Largest page a List* returns
    maxRecordedConnections: 512,                             // mTLS connections remembered
    autoCreateEntries: true,                                 // Invent a registration entry on first sight
    requireSecurityHeader: true,                             // Require the workload.spiffe.io header
    trustLocalSocket: true,                                  // Trust the SPIRE Server API socket as local
    adminIds: "",                                            // Administrator SPIFFE IDs
    clockSkew: 60,                                           // Clock skew (s)
    attestWorkloads: true,                                   // Match Workload API callers on selectors
    acceptAssertedSelectors: false,                          // Believe selectors a workload asserts
    maxEntries: 500,                                         // Maximum registration entries
    maxAgents: 200,                                          // Maximum attested agents
    maxFederatedBundles: 32,                                 // Maximum federated bundles
    bundlePath: "/spiffe/bundle",                            // Bundle endpoint path; restart to apply
    workloadSocketEnabled: true,                             // Workload API on a Unix socket; restart to apply
    workloadSocket: "/tmp/spire-agent/public/api.sock",      // Workload API socket path; restart to apply
    workloadPort: 8092,                                      // Workload API TCP port; restart to apply
    serverPort: 8181,                                        // SPIRE Server API TCP port; restart to apply
    serverSocketEnabled: false,                              // SPIRE Server API on a Unix socket; restart to apply
    serverSocket: "/tmp/spire-server/private/api.sock",      // SPIRE Server API socket path; restart to apply
    grpcHost: "0.0.0.0"                                      // gRPC bind address; restart to apply
  },

  // --- Persistence -----------------------------------------------------
  persistence: {
    mode: "memory",                                       // Persistence mode; restart to apply
    metricsTimeoutMs: 5000,                               // Database metrics statement timeout (ms)
    dataDir: "./data",                                    // Data directory; restart to apply
    databaseUrl: "postgres://sts:sts@localhost:5432/sts", // Database connection string; restart to apply
    databasePasswordProvider: "none",                     // Where the database password is read from; restart to apply
    databasePasswordRef: "",                              // The database password's location; restart to apply
    databasePasswordField: "databasePassword",            // The field the password is in; restart to apply
    databasePasswordVault: "",                            // Vault or Key Vault URL for the database password; restart to apply
    databasePasswordRegion: "",                           // AWS region for the database password; restart to apply
    databasePasswordToken: "",                            // Vault token for the database password; restart to apply
    databaseTlsRejectUnauthorized: false,                 // Verify the database certificate; restart to apply
    writeDelay: 1500,                                     // Write delay (ms)
    realms: true,                                         // Persist the realm registry; restart to apply
    appconfig: true,                                      // Persist runtime setting changes; restart to apply
    minted: true,                                         // Persist sessions, tokens and the audit log; restart to apply
    mintedRetention: 604800000,                           // Minted state retention (ms)
    coordinate: true,                                     // Coordinate with other processes; restart to apply
    pollInterval: 5000,                                   // Change poll interval (ms)
    changeLogRetentionS: 3600                             // Change log retention (s)
  },

  // --- Cluster ---------------------------------------------------------
  cluster: {
    mode: "auto",                  // Cluster mode; restart to apply
    nodeName: "",                  // Node name; restart to apply
    heartbeatMs: 2000,             // Heartbeat interval (ms); restart to apply
    nodeTtlMs: 30000,              // Node lifetime (ms); restart to apply
    acceptMissingCapabilities: ""  // Capabilities accepted as missing; restart to apply
  },
};

module.exports = config;
