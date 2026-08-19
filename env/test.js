// Configuration for a quieter run (e.g. a long soak) — info level only.
//
// Identical to env/local.js apart from the log level. See that file's header
// and `config.js` for what each setting means.
var config = {
  // Bunyan log level (trace|debug|info|warn|error|fatal).
  logLevel: "info",

  // --- Global ------------------------------------------------------------
  global: {
    host: "0.0.0.0", // restart to apply
    port: 8081       // restart to apply
  },

  // --- OAuth 2.0 / OIDC --------------------------------------------------
  oauth2: {
    issuer: ""
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
    autocreateUsers: false,
    maxEntries: 2000,
    sizeLimit: 500
  },

  // --- Audit log ---------------------------------------------------------
  audit: {
    maxEvents: 5000,
    protocolCalls: true
  }
};

module.exports = config;
