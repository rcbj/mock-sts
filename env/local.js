// Local (docker-compose / bare `node server.js`) configuration for the STS mock.
//
// Selected with CONFIG_FILE, the same way the api and client services choose
// theirs — e.g. CONFIG_FILE=./env/local.js node server.js.
//
// EVERY SETTING THIS SERVICE HAS IS BELOW, grouped by the protocol it belongs
// to, and every value here is the one the service used before this file listed
// them — so a run with this file behaves exactly as one with the old file that
// carried only `logLevel`.
//
// `config.js` is the table these keys come from and is where each one's
// REASONING lives: what it does, why the default is the default, and for the
// ones marked "restart to apply", what was already derived from it by the time
// the service was listening. /admin/config shows the same table with the
// effective value of each and where it came from, and the management API
// answers it at GET /admin-api/config.
//
// An ENVIRONMENT VARIABLE STILL WINS over anything here (STS_PORT, KRB5_REALM,
// and so on — `config.js` names each one), which is what keeps every existing
// container and test working unchanged. A key deleted from this file falls back
// to the identical built-in default rather than to nothing.
var config = {
  // Bunyan log level (trace|debug|info|warn|error|fatal).
  logLevel: "debug",

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
    // ON. It was `false` in all three env files, which is what an
    // appconfig value does: it beats the default, and the default is
    // what every document here describes. So a person signed in through
    // any protocol and the directory stayed empty — which reads as a
    // broken hook and is a setting doing what it was told.
    autocreateUsers: true,
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
