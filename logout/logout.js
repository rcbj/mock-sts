'use strict';
//
// File: logout.js
//
// ---------------------------------------------------------------------------
// GET|POST /logout — THE PROTOCOL-INDEPENDENT SIGN-OUT.
//
// Every protocol family here that can sign somebody IN has its own way of
// signing them out, and each one signs them out of itself:
//
//   /oauth2/logout          OpenID Connect RP-Initiated Logout
//   /wsfed?wa=wsignout1.0   WS-Federation 1.2 section 13.2.4
//   /saml2/slo              SAML 2.0 Single Logout
//
// None of them is the question a person actually arrives with, which is *what
// am I still signed into, and how do I stop being signed into it*. That
// question is protocol-independent, and so is the answer this endpoint gives:
// ONE LIST of everything this service is still holding for one identity, across
// every family, with a checkbox against each, and — by default, and by design —
// a single button that ends all of it.
//
// It is the same shape `common/delegation.js` takes and for the same reason:
// eight delegation mechanisms in three families collapse to one model because
// the question is protocol-independent. So does this one.
//
// ---------------------------------------------------------------------------
// SEVEN THINGS ARE WORTH KNOWING BEFORE READING FURTHER.
//
// **IT HOLDS NO STATE OF ITS OWN AND MUST NOT GROW ANY.** Every row on the page
// is read live from the module that OWNS that thing — the session store in
// `authn.js`, the token registry and its one revocation set in
// `admin_stats.js`, the authorization codes in `oauth2.js`, the pre-authorized
// codes in `vc_offers.js`, the connection list in `ldap_server.js`, the
// principal database in `krb5_principals.js` — and every termination is a call
// into that same module. A cache here would be a second answer to "is this
// still live", and the wrong half of it would be the half on the page a person
// is about to act on. This is the one-store rule that keeps the revocation set
// in one place, applied to nine stores at once.
//
// **IT IS A PLAIN REQUIRE OF EVERYTHING AND NEEDS NO SLOT.** Rule 3e says a
// slot is what you reach for when a require would close a cycle or move a
// route, and neither applies here: `server.js` requires this module SECOND TO
// LAST — after every module it reads, before `sts_metadata.js` — so each
// require below is a cache hit that registers nothing, and nothing in this
// service requires this file back. Do not add an inverted hook for a family
// added later; add a row to `FAMILIES`.
//
// **A FAMILY IS ONE ROW IN `FAMILIES` AND THAT IS THE EXTENSION POINT.** Each
// carries `collect()` (what is live for this person) and `terminate()` (end one
// of them), plus the prose the page prints. A new protocol that grows a session
// is one entry. What must NOT happen is a second place that decides what a live
// credential is.
//
// **WHAT CANNOT BE ENDED IS LISTED ANYWAY, WITH THE REASON.** A SAML assertion
// already in a service provider's hands, a Kerberos service ticket already in a
// cache, an X509-SVID already minted: none of them can be recalled, by this
// service or by a real one, because nothing consults the issuer when they are
// presented. Filtering those off the page would make a global logout look
// complete when it is not, which is the single most misleading thing this
// endpoint could do. They are rows with no checkbox and a sentence saying why —
// the same decision `/admin/sts-metadata` makes about coverage notes.
//
// **THE DEFAULT IS GLOBAL.** A POST that selects nothing ends everything, and
// the button says so. The per-row checkboxes exist because "sign me out of that
// one relying party" is a real thing to want and no protocol here offers it
// across families — but a logout endpoint whose default was partial would be a
// logout endpoint that quietly left something behind.
//
// **NO PASSWORD IS CHECKED AND `?username=` IS HONOURED.** With no parameter
// this endpoint acts on whoever the session cookie names, and a browser with no
// session is sent to the sign-in screen and returned here. `username=` names
// somebody else, and it grants nothing that was not already true: no sign-in
// screen in this service checks a password, so anybody who can reach this port
// can already BECOME that person in one request. What it buys is a headless
// test. `logout.anyUser` turns it off for a deployment that wants the tighter
// story, and the page says which of the two it is running under.
//
// **THE OPERATOR'S DOOR IS `/admin/logout`, AND IT IS A DIFFERENT SURFACE.**
// This page is a person signing themselves out. The console's is an operator
// looking at somebody, is behind the console's two roles, and is where an
// UNDO lives (a Kerberos sign-out instant can be cleared; a revoked token can
// be restored). Both call the functions in this file, which is what makes them
// one behaviour rather than two — rule 7, and the reason `admin_api.js` gets an
// operation for each control.
// ---------------------------------------------------------------------------

const crypto = require('crypto');
const app = require('../common/app');
const { log, xmlEscape, baseUrlOf, parseBody, nowSec } = require('../common/helpers');
const config = require('../common/config');
// The token registry, its ONE revocation set, and identityKeyOf() — which is
// what makes `alice`, `alice@STS.MOCK` and `urn:sts-mock:user:alice` one person
// here rather than three, exactly as it does on /admin/users.
const stats = require('../common/admin_stats');
const audit = require('../common/audit');
// The session store. Everything about ending one — the RFC 9700 refresh
// revocation and the single `session.end` audit row — is behind
// endSessionById(), which is why this module never touches the map itself.
const authn = require('../authn/authn');
// The authorization codes, and the issuer identifier a front-channel
// notification's `iss` carries.
const oauth2 = require('../oauth-oidc/oauth2');
// The front-channel fan-out, shared with /oauth2/logout so that both sign-outs
// notify the same relying parties in the same way.
const frontchannel = require('../oauth-oidc/frontchannel_logout');
// The two federated lists that live ON the session, each built by the module
// that wrote it. See their own headers for why the builder is not here.
const wsfed = require('../ws-federation/wsfed');
const saml2Sso = require('../saml/saml2_sso');
// The pre-authorized codes a Credential Offer minted. Exported as Maps by that
// module, which is what rule 2 made it for.
const vcOffers = require('../oid4vc/vc_offers');
// The principal database, for the sign-out instant that stops an older
// ticket-granting ticket at the KDC.
const krb5Principals = require('../kerberos/krb5_principals');
// The embedded directory, for the bound connections that ARE the LDAP session.
const ldapServer = require('../ldap/ldap_server');

const LOGOUT_PATH = '/logout';

// An opaque, stable handle for a row whose natural key is a CREDENTIAL. An
// authorization code and a pre-authorized code are both redeemable for tokens,
// so neither may appear in a form field, a URL or an audit row — the same rule
// audit.js applies to every credential. The hash is stable for as long as the
// code is, which is all a checkbox needs, and `resolve` below looks the code
// back up by hashing the candidates rather than by keeping a map.
function handleFor(secret) {
  return crypto.createHash('sha256').update(String(secret), 'utf8').digest('hex').slice(0, 16);
}

// How many rows one inventory will draw. See `logout.maxRows`: the cap is on
// what is LISTED, never on what a termination reaches.
function maxRows() {
  return config.value('logout.maxRows');
}

function anyUserAllowed() {
  return !!config.value('logout.anyUser');
}

// ---------------------------------------------------------------------------
// THE MODEL.
//
// One row is one live thing that can be presented again. Every family produces
// this shape and nothing downstream can tell them apart, which is the whole
// point — the page groups by family and the termination does not care.
//
//   id           `family:handle`, what a checkbox carries
//   family       the FAMILIES row it came from
//   kind         what it is, in that family's vocabulary
//   label        the thing itself, for a person
//   detail       the second line: who issued it, to whom, what rides on it
//   startedAt    epoch ms, or 0 when the family cannot say
//   expiresAt    epoch ms, or 0 for "no expiry was stated" — which is the
//                honest answer for several of these rather than an expiry of now
//   terminable   whether ending it is something this service can do
//   why          when it is not, the reason, in a sentence
//   sessionId    the browser session it hangs off, where there is one
// ---------------------------------------------------------------------------
function row(family, kind, handle, detail) {
  return Object.assign({
    id: family + ':' + handle,
    family: family,
    kind: kind,
    handle: handle,
    label: '',
    detail: '',
    startedAt: 0,
    expiresAt: 0,
    terminable: true,
    why: '',
    sessionId: ''
  }, detail || {});
}

// The sessions this identity holds, worked out once per inventory because four
// families hang off them. `identityKeyOf()` is applied to the session's
// username so that a session started as `alice@REALM` is found by a logout for
// `alice` — the normalisation every other door here uses.
function sessionsForKey(key) {
  log.debug("Entering sessionsForKey(). key=" + key);
  const wanted = String(key || '');
  const out = [];
  authn.sessions.forEach(function (session) {
    const username = (session.user && session.user.username) || '';
    if (stats.identityKeyOf(username) === wanted) out.push(session);
  });
  out.sort(function (a, b) { return (b.authTime || 0) - (a.authTime || 0); });
  log.debug("Leaving sessionsForKey(). " + out.length + " session(s).");
  return out;
}

// ---------------------------------------------------------------------------
// THE FAMILIES.
//
// One entry per kind of live thing this service holds, in the order a person
// should read them: the session first, because everything else on the page
// either hangs off it or was issued by it.
//
// `collect(ctx)` returns rows; `terminate(row, ctx)` ends one and returns
// `{ ok, message }`. `ctx` carries what both need and is built once per
// request: the identity key, the sessions, and the base URL a notification is
// addressed from.
//
// A family whose things CANNOT be ended has no `terminate` and returns rows
// with `terminable: false`. That is not a stub to be filled in later — see the
// header: those rows are the honest half of this page.
// ---------------------------------------------------------------------------
const FAMILIES = [

  // -------------------------------------------------------------------------
  { id: 'session', endOrder: 90,
    label: 'Browser sign-on session',
    protocol: 'Authentication service',
    spec: 'Not a protocol. The session this service holds and the three ' +
          'browser protocols share.',
    what: 'The cookie from /authn/login. OAuth 2.0 / OIDC, WS-Federation, SAML ' +
          '2.0 and the admin console all read THIS session, which is why ' +
          'signing out of one signs out of all of them — and why a row here ' +
          'takes the three lists below with it.',
    collect: function (ctx) {
      return ctx.sessions.map(function (session) {
        const rides = [];
        const oidc = frontchannel.clientsOf(session).length;
        const realms = Object.keys(session.wsfedRealms || {}).length;
        const sps = Object.keys(session.saml2ServiceProviders || {}).length;
        if (oidc) rides.push(oidc + ' OIDC relying part' + (oidc === 1 ? 'y' : 'ies'));
        if (realms) rides.push(realms + ' WS-Federation realm' + (realms === 1 ? '' : 's'));
        if (sps) rides.push(sps + ' SAML 2.0 service provider' + (sps === 1 ? '' : 's'));
        return row('session', 'sign-on session', session.id, {
          label: session.id,
          detail: 'signed in as ' + ((session.user && session.user.username) || '?') +
                  ' (' + ((session.amr || []).join(', ') || 'no amr recorded') +
                  ', acr ' + (session.acr || 'none') + ')' +
                  (rides.length ? '; carries ' + rides.join(', ') : '; nothing signed into on it'),
          startedAt: (session.authTime || 0) * 1000,
          expiresAt: session.expires || 0,
          sessionId: session.id
        });
      });
    },
    terminate: function (r) {
      // Through endSessionById(), never by deleting from the map: that function
      // is where the RFC 9700 section 2.2.2 refresh revocation and the one
      // `session.end` audit row live, and a delete here would be a sign-out
      // that revoked nothing and logged nothing while looking identical.
      const ended = authn.endSessionById(r.handle, 'the protocol-independent logout');
      return ended
        ? { ok: true, message: 'the sign-on session ' + r.handle + ' was ended' }
        : { ok: false, message: 'there was no session ' + r.handle + ' to end; it had ' +
                                'already expired or already been signed out' };
    } },

  // -------------------------------------------------------------------------
  { id: 'oidc-rp', endOrder: 10,
    label: 'OpenID Connect relying parties',
    protocol: 'OAuth 2.0 / OIDC',
    spec: 'OpenID Connect Front-Channel Logout 1.0',
    what: 'The clients this session was issued an authorization response for. ' +
          'Ending one sends that relying party a front-channel notification at ' +
          'its registered frontchannel_logout_uri and forgets it here; the ' +
          'tokens it already holds are a separate row, because a notified ' +
          'relying party that kept a live refresh token is not signed out.',
    collect: function (ctx) {
      const rows = [];
      ctx.sessions.forEach(function (session) {
        frontchannel.notificationsFor(session, ctx.issuer).forEach(function (note) {
          rows.push(row('oidc-rp', 'relying party', session.id + '|' + note.clientId, {
            label: note.clientId,
            detail: note.url
              ? 'will be notified at ' + note.uri +
                (note.sessionRequired ? ' with iss and sid' : ' without iss or sid, as registered')
              : note.why,
            sessionId: session.id,
            // Still terminable with no URI: forgetting it here is real, and the
            // row's detail says the notification is the half that cannot happen.
            terminable: true
          }));
        });
      });
      return rows;
    },
    terminate: function (r, ctx) {
      const parts = String(r.handle).split('|');
      const session = authn.sessionById(parts[0]);
      const clientId = parts.slice(1).join('|');
      if (!session) {
        return { ok: false, message: 'the session that relying party was signed into on has ' +
                                     'already ended, which signed it out too' };
      }
      // The notification is built BEFORE the client is forgotten, because the
      // list it is built from is the thing about to be removed.
      const note = frontchannel.notificationsFor(session, ctx.issuer).filter(function (one) {
        return one.clientId === clientId;
      })[0];
      if (note) ctx.notifications.push(note);
      if (session.oidcClients) delete session.oidcClients[clientId];
      return { ok: true,
               message: clientId + ' was forgotten on session ' + session.id +
                        (note && note.url ? ' and notified at ' + note.uri
                                          : ' (there was nowhere to notify it)') };
    } },

  // -------------------------------------------------------------------------
  { id: 'wsfed-rp', endOrder: 11,
    label: 'WS-Federation relying parties',
    protocol: 'WS-Federation',
    spec: 'WS-Federation 1.2 section 13.2.4',
    what: 'The realms this session signed into. Ending one sends that realm a ' +
          'wsignoutcleanup1.0 request — the same one wsignout1.0 sends, built ' +
          'by the same function in wsfed.js — as a one-pixel image, with the ' +
          'URL printed beside it so a failed ping can be seen rather than ' +
          'guessed at.',
    collect: function (ctx) {
      const rows = [];
      ctx.sessions.forEach(function (session) {
        wsfed.cleanupTargetsFor(session).forEach(function (target) {
          rows.push(row('wsfed-rp', 'realm', session.id + '|' + target.realm, {
            label: target.realm,
            detail: target.url ? 'cleanup goes to ' + target.url
                               : 'this realm supplied no wreply, so there is nowhere to send a ' +
                                 'cleanup request',
            sessionId: session.id
          }));
        });
      });
      return rows;
    },
    terminate: function (r, ctx) {
      const parts = String(r.handle).split('|');
      const session = authn.sessionById(parts[0]);
      const realm = parts.slice(1).join('|');
      if (!session) {
        return { ok: false, message: 'the session that realm was signed into on has already ' +
                                     'ended, which took its cleanup list with it' };
      }
      const target = wsfed.cleanupTargetsFor(session).filter(function (one) {
        return one.realm === realm;
      })[0];
      if (target) ctx.cleanups.push(target);
      if (session.wsfedRealms) delete session.wsfedRealms[realm];
      return { ok: true,
               message: realm + ' was forgotten on session ' + session.id +
                        (target && target.url ? ' and a cleanup request was sent'
                                              : ' (there was nowhere to send a cleanup request)') };
    } },

  // -------------------------------------------------------------------------
  { id: 'saml2-sp', endOrder: 12,
    label: 'SAML 2.0 service providers',
    protocol: 'SAML 2.0',
    spec: 'saml-profiles-2.0-os section 4.4, Single Logout',
    what: 'The service providers this session signed into, each with a signed ' +
          'LogoutRequest built for it. They are LINKS and not an automatic ' +
          'fan-out, which is /saml2/slo\'s own decision reused rather than ' +
          'reconsidered: a WS-Federation cleanup is an idempotent GET that ' +
          'works as an image, and a LogoutRequest is a signed message a ' +
          'service provider ANSWERS. Firing those into hidden frames would ' +
          'claim a federation-wide logout this service cannot observe.',
    collect: function (ctx) {
      const rows = [];
      ctx.sessions.forEach(function (session) {
        saml2Sso.logoutTargetsFor(session).forEach(function (target) {
          rows.push(row('saml2-sp', 'service provider', session.id + '|' + target.entityId, {
            label: target.entityId,
            detail: target.url ? 'a LogoutRequest is ready for ' + target.from
                               : 'no SingleLogoutService is known for it, so there is nowhere ' +
                                 'to send a LogoutRequest',
            sessionId: session.id
          }));
        });
      });
      return rows;
    },
    terminate: function (r, ctx) {
      const parts = String(r.handle).split('|');
      const session = authn.sessionById(parts[0]);
      const entityId = parts.slice(1).join('|');
      if (!session) {
        return { ok: false, message: 'the session that service provider was signed into on has ' +
                                     'already ended, which took its logout list with it' };
      }
      const target = saml2Sso.logoutTargetsFor(session).filter(function (one) {
        return one.entityId === entityId;
      })[0];
      if (target) ctx.logoutRequests.push(target);
      if (session.saml2ServiceProviders) delete session.saml2ServiceProviders[entityId];
      return { ok: true,
               message: entityId + ' was forgotten on session ' + session.id +
                        (target && target.url
                          ? '; the LogoutRequest for it is on the page and has to be sent by ' +
                            'following the link'
                          : ' (there is nowhere to send a LogoutRequest)') };
    } },

  // -------------------------------------------------------------------------
  { id: 'token', endOrder: 20,
    label: 'Tokens',
    protocol: 'OAuth 2.0 / OIDC',
    spec: 'RFC 7009 for the revocation; RFC 9700 section 2.2.2 for why a ' +
          'sign-out is one of the moments to perform it',
    what: 'Every access token, refresh token and ID Token this service still ' +
          'holds a record of for this identity and has not already revoked. ' +
          'Ending one adds its jti to the ONE revocation set — the same set ' +
          '/oauth2/revoke and the console write to — so /oauth2/introspect ' +
          'reports it inactive on the next call. A token this registry has ' +
          'forgotten to its cap cannot be listed and is the reason a global ' +
          'logout is not a promise about tokens issued long ago.',
    collect: function (ctx) {
      const detail = stats.userDetail(ctx.key);
      if (!detail) return [];
      return detail.tokens.filter(function (record) {
        // Only what can still be presented AND can still be acted on. A
        // revoked one is already ended, an expired one ended itself, and one
        // with no jti cannot be revoked at all — which the registry already
        // records as `revocable: false` rather than leaving to be inferred.
        return record.revocable && record.state !== 'revoked' && record.state !== 'expired';
      }).map(function (record) {
        return row('token', record.kind, record.jti, {
          label: record.kind + ' ' + record.jti,
          detail: 'for ' + (record.client_id || 'no client') +
                  (record.scope ? ', scope ' + record.scope : '') +
                  (record.jkt ? ', DPoP-bound' : '') +
                  (record.sessionId ? ', issued on session ' + record.sessionId
                                    : ', issued with no browser session'),
          startedAt: record.issuedAt || 0,
          expiresAt: (record.exp || 0) * 1000,
          sessionId: record.sessionId || ''
        });
      });
    },
    terminate: function (r) {
      const first = stats.revoke(r.handle, 'a protocol-independent logout at /logout');
      return { ok: true,
               message: first ? 'the token with jti ' + r.handle + ' is revoked'
                              : 'the token with jti ' + r.handle + ' was already revoked' };
    } },

  // -------------------------------------------------------------------------
  { id: 'code', endOrder: 21,
    label: 'Authorization codes',
    protocol: 'OAuth 2.0 / OIDC',
    spec: 'RFC 6749 section 4.1.2',
    what: 'Codes issued to a client and not yet redeemed. For their five ' +
          'minutes each one is a live credential that mints a whole token set, ' +
          'so a sign-out that revoked the tokens and left these behind would ' +
          'have left the thing that makes more of them. They are shown by a ' +
          'HANDLE and never by their value: a code on a web page is a code in ' +
          'a browser history.',
    collect: function (ctx) {
      return oauth2.outstandingCodesFor(ctx.key).map(function (code) {
        return row('code', 'authorization code', handleFor(code.code), {
          label: 'a code for ' + (code.clientId || 'no client'),
          detail: 'redirect_uri ' + (code.redirectUri || '(none)') +
                  (code.scope ? ', scope ' + code.scope : ''),
          startedAt: code.issuedAt || 0,
          expiresAt: code.expiresAt || 0,
          sessionId: code.sessionId || '',
          // Kept so terminate() can find it again without a map of handles,
          // and deliberately NOT part of `id`, which is what reaches a form.
          secret: code.code
        });
      });
    },
    terminate: function (r, ctx) {
      // The handle is re-resolved against the CURRENT codes rather than trusted
      // from the form: five minutes may have passed, and a handle that no
      // longer names anything must end nothing rather than something else.
      const match = oauth2.outstandingCodesFor(ctx.key).filter(function (code) {
        return handleFor(code.code) === r.handle;
      })[0];
      if (!match) {
        return { ok: false, message: 'that authorization code has already been redeemed or has ' +
                                     'expired, so there is nothing left to end' };
      }
      oauth2.dropCode(match.code);
      return { ok: true, message: 'an authorization code for ' + (match.clientId || 'no client') +
                                  ' was discarded and can no longer be redeemed' };
    } },

  // -------------------------------------------------------------------------
  { id: 'vci-code', endOrder: 22,
    label: 'Credential Offer pre-authorized codes',
    protocol: 'OpenID4VCI',
    spec: 'OpenID for Verifiable Credential Issuance 1.0 section 4.1.1',
    what: 'Pre-authorized codes from a Credential Offer made for this person. ' +
          'Each is redeemable once at the token endpoint for an access token ' +
          'that issues a credential, so it is a live credential in the same ' +
          'sense an authorization code is, and it is shown by a handle for the ' +
          'same reason.',
    collect: function (ctx) {
      const rows = [];
      const at = Date.now();
      vcOffers.preAuthorizedCodes.forEach(function (record, code) {
        const username = (record.user && record.user.username) || '';
        if (stats.identityKeyOf(username) !== ctx.key) return;
        if (record.expires && record.expires < at) return;
        rows.push(row('vci-code', 'pre-authorized code', handleFor(code), {
          label: 'a pre-authorized code for ' +
                 (record.configurationIds || []).join(', ') || 'a credential',
          detail: (record.txCode ? 'a transaction code is required with it' : 'no transaction code') +
                  (record.deferred ? '; the credential is issued deferred' : ''),
          expiresAt: record.expires || 0,
          secret: code
        }));
      });
      return rows;
    },
    terminate: function (r, ctx) {
      let found = '';
      vcOffers.preAuthorizedCodes.forEach(function (record, code) {
        const username = (record.user && record.user.username) || '';
        if (stats.identityKeyOf(username) !== ctx.key) return;
        if (handleFor(code) === r.handle) found = code;
      });
      if (!found) {
        return { ok: false, message: 'that pre-authorized code has already been redeemed or has ' +
                                     'expired, so there is nothing left to end' };
      }
      vcOffers.preAuthorizedCodes.delete(found);
      return { ok: true, message: 'a pre-authorized code was discarded; the Credential Offer it ' +
                                  'came from can no longer be redeemed' };
    } },

  // -------------------------------------------------------------------------
  { id: 'ldap', endOrder: 23,
    label: 'Directory connections',
    protocol: 'LDAP',
    spec: 'RFC 4511 section 4.2',
    what: 'Connections to the embedded directory — 389 and LDAPS 636 alike — ' +
          'bound as this person. A Bind sets the authorization state of a ' +
          'CONNECTION and it lasts until the next Bind or an Unbind, so in ' +
          'LDAP the connection IS the session and closing it is the only ' +
          'sign-out the protocol has. What the client sees is its socket ' +
          'closing mid-conversation. An UNSOLICITED NOTICE OF DISCONNECTION ' +
          '(section 4.4.1) would be the polite form and node-ldapjs has no way ' +
          'to send one — it is a submodule this repository uses unmodified.',
    collect: function (ctx) {
      if (!config.value('logout.ldapDisconnect')) {
        // Still listed, and said to be untouched. A family that vanished when
        // its setting was off would make a global logout look complete.
        return ldapServer.boundConnections().filter(function (c) {
          return c.key && c.key === ctx.key;
        }).map(function (c) {
          return row('ldap', 'connection', c.id, {
            label: c.dn, terminable: false,
            detail: 'bound on ' + (c.secure ? 'LDAPS ' : 'plain ') + c.port,
            why: 'logout.ldapDisconnect is off, so this logout leaves directory connections ' +
                 'alone. Turn it on to have them closed.'
          });
        });
      }
      return ldapServer.boundConnections().filter(function (c) {
        return c.key && c.key === ctx.key;
      }).map(function (c) {
        return row('ldap', 'connection', c.id, {
          label: c.dn,
          detail: 'bound on ' + (c.secure ? 'LDAPS ' : 'plain ') + c.port + ', connection ' + c.id
        });
      });
    },
    terminate: function (r, ctx) {
      const dropped = ldapServer.dropConnectionsFor(ctx.key).filter(function (one) {
        return one.id === r.handle;
      });
      // dropConnectionsFor() closes every connection for this person, which is
      // what a logout means — so a second row for the same person finds nothing
      // left and says so rather than reporting a failure.
      return dropped.length
        ? { ok: true, message: 'the directory connection ' + r.handle + ' bound as ' +
                               dropped[0].dn + ' was closed' }
        : { ok: true, message: 'the directory connection ' + r.handle + ' was already closed' };
    } },

  // -------------------------------------------------------------------------
  { id: 'krb5', endOrder: 24,
    label: 'Kerberos tickets',
    protocol: 'Kerberos v5',
    spec: 'None — Kerberos defines no logout, no session and no revocation. ' +
          'KDC_ERR_TGT_REVOKED (20) is a registered code (RFC 4120 section ' +
          '7.5.9) whose text says what is meant, but the specification ' +
          'defines no mechanism that emits it; this is an invention using it.',
    what: 'A ticket-granting ticket is an encrypted blob in somebody\'s cache ' +
          'and there is no list of them here — there could not be one on a ' +
          'real KDC either, which is deliberate: a KDC keeps no state about ' +
          'the tickets it has issued, and that is what lets one be replicated ' +
          'read-only. A ticket is valid because it decrypts and its endtime ' +
          'has not passed, and a service never contacts the KDC to accept one, ' +
          'so SHORT LIFETIMES are the whole revocation model Kerberos has. ' +
          'What a KDC does see is the next TGS-REQ, so a ' +
          'sign-out records an INSTANT on the principal and a request ' +
          'presenting a ticket authenticated before it is refused ' +
          'KDC_ERR_TGT_REVOKED. IT DOES NOT REACH A SERVICE TICKET ALREADY IN ' +
          'A CACHE: accepting one never contacts this KDC, which is a fact ' +
          'about Kerberos rather than a gap here. A fresh AS-REQ succeeds and ' +
          'clears the instant, because signing out is not being locked out.',
    collect: function (ctx) {
      if (!ctx.key) return [];
      const realm = krb5Principals.REALM;
      const already = krb5Principals.signedOutAt([ctx.key], realm);
      const principal = krb5Principals.find([ctx.key], realm);
      if (!principal) {
        // No principal means this person has never authenticated to the KDC and
        // there is nothing to stamp. Reported rather than omitted, because the
        // absence is the answer: a global logout did not skip Kerberos, there
        // was no Kerberos to reach. Stamping one into existence would put an
        // account in the database because somebody typed a name at a logout
        // screen.
        return [row('krb5', 'ticket-granting tickets', ctx.key + '@' + realm, {
          label: ctx.key + '@' + realm,
          terminable: false,
          detail: 'no such principal in this KDC',
          why: 'nothing has authenticated to this KDC as that name, so there is no principal ' +
               'to stamp a sign-out instant on. One appears the first time an AS-REQ names it.'
        })];
      }
      if (!config.value('logout.kerberosSignOut')) {
        return [row('krb5', 'ticket-granting tickets', ctx.key + '@' + realm, {
          label: ctx.key + '@' + realm,
          terminable: false,
          detail: already ? 'signed out at ' + already.toISOString() : 'no sign-out instant is set',
          why: 'logout.kerberosSignOut is off, so this logout leaves the KDC alone and a ' +
               'ticket-granting ticket already issued goes on working. Turn it on to have ' +
               'older tickets refused.'
        })];
      }
      return [row('krb5', 'ticket-granting tickets', ctx.key + '@' + realm, {
        label: ctx.key + '@' + realm,
        startedAt: already ? already.getTime() : 0,
        detail: already
          ? 'already signed out at ' + already.toISOString() +
            '; ending it again moves the instant to now, which catches any ticket issued since'
          : 'every ticket-granting ticket authenticated before now will be refused at the KDC'
      })];
    },
    terminate: function (r, ctx) {
      const realm = krb5Principals.REALM;
      const principal = krb5Principals.signOut([ctx.key], realm);
      if (!principal) {
        return { ok: false, message: 'this KDC has no principal named ' + ctx.key + '@' + realm +
                                     ', so there was nothing to sign out' };
      }
      return { ok: true,
               message: principal.name.join('/') + '@' + principal.realm + ' signed out at ' +
                        principal.signedOutAt.toISOString() + '; a TGS-REQ presenting an older ' +
                        'ticket is now refused KDC_ERR_TGT_REVOKED. A service ticket already in ' +
                        'a cache still works against the service that accepts it.' };
    } },

  // -------------------------------------------------------------------------
  // THE FAMILY WITH NO `terminate`, AND IT IS THE MOST IMPORTANT ONE ON THE
  // PAGE. See the header: what cannot be ended is listed with the reason,
  // because a global logout that quietly omitted these would look complete.
  { id: 'issued', endOrder: 99,
    label: 'Issued and beyond recall',
    protocol: 'SAML 2.0, SAML 1.1, WS-Trust, WS-Federation, OpenID4VCI, SPIFFE',
    spec: 'Nothing to cite: no specification here defines a way to recall one.',
    what: 'Assertions, service tickets, verifiable credentials and X509-SVIDs ' +
          'already issued for this person. NONE of them can be ended, by this ' +
          'service or by a real one, and the reason is the same in every case: ' +
          'nothing contacts the issuer when they are presented. A relying ' +
          'party validates a SAML assertion\'s signature and its conditions ' +
          'and asks nobody; a Kerberos service decrypts a ticket with its own ' +
          'key; an X509-SVID verifies against a bundle. They are here so that ' +
          'a global logout says what it did NOT reach.',
    collect: function (ctx) {
      const detail = stats.userDetail(ctx.key);
      if (!detail) return [];
      return detail.artifacts.filter(function (record) {
        return record.state !== 'expired';
      }).map(function (record) {
        return row('issued', record.kind, handleFor(record.kind + '|' + (record.id || '') + '|' +
                                                    (record.issuedAt || 0)), {
          label: record.kind + (record.id ? ' ' + record.id : ''),
          detail: (record.audience ? 'for ' + record.audience : 'no audience recorded') +
                  (record.state ? ', ' + record.state : ''),
          startedAt: record.issuedAt || 0,
          expiresAt: record.expiresAt || 0,
          terminable: false,
          why: 'nothing consults this service when it is presented, so there is no revocation ' +
               'this service could perform. It stops working when it expires.'
        });
      });
    } }
];

const FAMILY_BY_ID = {};
FAMILIES.forEach(function (family) { FAMILY_BY_ID[family.id] = family; });

// ---------------------------------------------------------------------------
// THE CONTEXT every collector and every termination is handed. Built ONCE per
// request, because four families read the same session list and re-deriving it
// per family would let two of them disagree about what is live — the same
// argument `gateStateFor()` in admin.js makes about the console's banner and
// its guard, which were written separately and disagreed within the hour.
// ---------------------------------------------------------------------------
function contextFor(key, issuer) {
  return {
    key: String(key || ''),
    sessions: sessionsForKey(key),
    issuer: issuer || '',
    // What a termination accumulates for the page to render afterwards: the
    // front-channel notifications to load in iframes, the WS-Federation cleanup
    // pings, and the SAML LogoutRequests to offer as links. They are collected
    // rather than sent from inside terminate() because sending them IS the
    // page — a notification is something a browser does, not something this
    // process does.
    notifications: [],
    cleanups: [],
    logoutRequests: []
  };
}

// ---------------------------------------------------------------------------
// THE INVENTORY: everything live for one identity, across every family.
//
// `key` is the console's identity key — `stats.identityKeyOf()` applied to
// whatever was presented — so that a person who signed in as `alice`, holds a
// Kerberos principal `alice@STS.MOCK` and has a token with `sub`
// `urn:sts-mock:user:alice` is ONE row set rather than three.
//
// A COLLECTOR THAT THROWS DOES NOT TAKE THE PAGE DOWN. Nine modules are read
// here and one of them being mid-change is exactly when somebody needs this
// page; a family that cannot answer is reported as such, in its own row, which
// is more useful than a stack trace and far more useful than a family silently
// missing from a list whose whole value is completeness.
// ---------------------------------------------------------------------------
function inventoryFor(key, issuer) {
  log.debug("Entering inventoryFor(). key=" + key);
  const ctx = contextFor(key, issuer);
  const families = [];
  let total = 0;
  let listed = 0;
  const cap = maxRows();
  FAMILIES.forEach(function (family) {
    let rows = [];
    let failure = '';
    try {
      rows = family.collect(ctx) || [];
    } catch (e) {
      // Reported and not thrown. See the block above.
      failure = e.message;
      log.warn('logout: the ' + family.id + ' family could not be read: ' + e.message);
    }
    total += rows.length;
    // The cap is on what is DRAWN. A global logout still reaches everything —
    // terminate() re-collects and does not consult this list — which is the one
    // property that makes truncating safe here.
    const shown = rows.slice(0, Math.max(0, cap - listed));
    listed += shown.length;
    families.push({
      id: family.id, label: family.label, protocol: family.protocol,
      spec: family.spec, what: family.what,
      terminable: typeof family.terminate === 'function',
      rows: shown.map(function (r) {
        // `secret` never leaves this module. It is on the row so that a
        // collector and its terminate() can share a lookup, and a page or a
        // JSON reply carrying it would be this endpoint handing out the
        // credentials it exists to take away.
        const copy = Object.assign({}, r);
        delete copy.secret;
        return copy;
      }),
      held: rows.length,
      notListed: rows.length - shown.length,
      failure: failure
    });
  });
  const result = {
    key: ctx.key,
    sessions: ctx.sessions.length,
    families: families,
    total: total,
    listed: listed,
    notListed: total - listed,
    maxRows: cap,
    at: Date.now()
  };
  log.debug("Leaving inventoryFor(). " + total + " row(s), " + listed + " listed.");
  return result;
}

// Every row, flattened, WITH its secret — the internal form, for terminate().
// Not exported: `inventoryFor()` is what anything outside this module reads.
function allRows(ctx) {
  const rows = [];
  FAMILIES.forEach(function (family) {
    try {
      (family.collect(ctx) || []).forEach(function (r) { rows.push(r); });
    } catch (e) {
      // Same rule as inventoryFor(): a family that cannot be read must not stop
      // the rest being ended. Logged, and the caller's report says how many
      // rows it acted on, so a short answer is visible rather than silent.
      log.warn('logout: the ' + family.id + ' family could not be read while terminating: ' +
               e.message);
    }
  });
  return rows;
}

// ---------------------------------------------------------------------------
// THE TERMINATION.
//
// `selection` is a list of row ids, or empty for GLOBAL — which is the default
// and the whole point of the endpoint. Rows are re-collected here and NOT taken
// from whatever the page drew: a form can be posted an hour after it was
// rendered, and acting on a stale list would end something that has since been
// reissued under the same id.
//
// THE READING ORDER AND THE ENDING ORDER ARE NOT THE SAME ORDER, and that cost
// a silent bug the first time this ran. `FAMILIES` is in the order a person
// should READ it — the session first, because everything else on the page
// either hangs off it or was issued by it. Ending in that order destroys the
// session BEFORE the relying parties, service providers and clients whose lists
// live on it, so a global logout ended the session and then found nothing to
// notify: every federated partner went on believing the person was signed in,
// and the page said so in a way that looked like there had been nobody to tell.
//
// So each family carries `endOrder`, and terminations run in that order while
// the page keeps the table's. The three federated lists go first (they are read
// off the session), the credentials next, and the SESSION LAST. A family added
// later needs a number: without one it sorts to the end, beside the sessions,
// which is the safe default for anything that does not depend on them and the
// wrong one for anything that does — so state it.
// ---------------------------------------------------------------------------
function terminate(key, selection, opts) {
  log.debug("Entering terminate(). key=" + key + ", selected=" +
            ((selection && selection.length) || 'all'));
  const options = opts || {};
  const ctx = contextFor(key, options.issuer);
  const wanted = (selection || []).map(String).filter(Boolean);
  const global = !wanted.length;
  const wantedSet = {};
  wanted.forEach(function (id) { wantedSet[id] = true; });

  const done = [];
  const skipped = [];
  const unknown = {};
  wanted.forEach(function (id) { unknown[id] = true; });

  // See the block above: the ending order is not the reading order, and a copy
  // is sorted rather than FAMILIES itself — the table's own order is what the
  // page draws, and sorting it in place would silently rearrange the page.
  const inEndingOrder = FAMILIES.slice(0).sort(function (a, b) {
    return (a.endOrder === undefined ? 99 : a.endOrder) -
           (b.endOrder === undefined ? 99 : b.endOrder);
  });
  inEndingOrder.forEach(function (family) {
    let rows = [];
    try {
      rows = family.collect(ctx) || [];
    } catch (e) {
      log.warn('logout: the ' + family.id + ' family could not be read while terminating: ' +
               e.message);
      skipped.push({ id: family.id + ':*', family: family.id,
                     message: 'this family could not be read: ' + e.message });
      return;
    }
    rows.forEach(function (r) {
      if (!global && !wantedSet[r.id]) return;
      delete unknown[r.id];
      if (!r.terminable || typeof family.terminate !== 'function') {
        // In a GLOBAL logout these are the honest short-fall and are reported
        // as such rather than counted. In a SELECTIVE one somebody has ticked
        // something that says it cannot be ended, which is worth answering
        // plainly rather than ignoring.
        skipped.push({ id: r.id, family: family.id, kind: r.kind, label: r.label,
                       message: r.why || 'this cannot be ended' });
        return;
      }
      let outcome;
      try {
        outcome = family.terminate(r, ctx) || { ok: false, message: 'no answer' };
      } catch (e) {
        log.warn('logout: ending ' + r.id + ' failed: ' + e.message);
        outcome = { ok: false, message: 'ending this failed: ' + e.message };
      }
      (outcome.ok ? done : skipped).push({
        id: r.id, family: family.id, kind: r.kind, label: r.label, message: outcome.message
      });
    });
  });

  const unknownIds = Object.keys(unknown);

  // ONE audit row for the ACT, and not one per thing ended. Every termination
  // that has an audit row of its own already wrote it — `session.end` from
  // dropSession(), the revocation's own log line — and a second row per item
  // here would be the double-count rule 3c warns about. What this row adds is
  // the thing none of those can say: that these were one act, asked for by one
  // person, at one moment.
  audit.audit({
    action: global ? 'logout.global' : 'logout.selective',
    outcome: done.length ? 'success' : 'refused',
    actor: options.actor || ctx.key,
    protocol: 'Logout',
    channel: options.channel || 'http',
    target: ctx.key,
    summary: (global ? 'a global logout' : 'a selective logout') + ' for ' + ctx.key +
             ' ended ' + done.length + ' of ' + (done.length + skipped.length) + ' live item(s)',
    detail: {
      scope: global ? 'global' : 'selected',
      requested: global ? 'everything' : String(wanted.length),
      ended: String(done.length),
      // The count of things that could not be ended, and the count of ids that
      // named nothing. Two different failures and collapsing them would hide
      // the one that means a stale form was posted.
      couldNotEnd: String(skipped.length),
      namedNothing: String(unknownIds.length),
      families: done.map(function (one) { return one.family; })
                    .filter(function (f, i, list) { return list.indexOf(f) === i; }).join(', '),
      by: options.by || 'the /logout endpoint'
    }
  });

  const result = {
    ok: true,
    key: ctx.key,
    scope: global ? 'global' : 'selected',
    terminated: done,
    skipped: skipped,
    unknown: unknownIds,
    // What the page still has to make the BROWSER do. None of it is something
    // this process can perform: a front-channel notification is an iframe, a
    // cleanup is an image, a LogoutRequest is a link somebody follows.
    notifications: ctx.notifications,
    cleanups: ctx.cleanups,
    logoutRequests: ctx.logoutRequests,
    message: (global ? 'Global logout for ' : 'Logout for ') + ctx.key + ': ' +
             done.length + ' item(s) ended' +
             (skipped.length ? ', ' + skipped.length + ' that could not be' : '') +
             (unknownIds.length ? ', ' + unknownIds.length + ' that named nothing' : '') + '.'
  };
  log.info('logout: ' + result.message);
  log.debug("Leaving terminate(). " + done.length + " ended.");
  return result;
}

// ---------------------------------------------------------------------------
// THE PAGE.
//
// It is drawn HERE and not through `admin.js`'s shell, and that is deliberate:
// this is not a console page. It is reached by a person who may hold no console
// role at all and it must not carry the console's nav, its gate banner or its
// breadcrumb — all three would tell somebody signing themselves out that they
// are somewhere they are not. `/admin/logout` is the console's view of the same
// functions and wears the console's chrome, which is what rule 7's parity asks
// for.
//
// NO SCRIPT, like every page in this service bar the four that argue for one.
// The checkboxes are checkboxes and the buttons are submit buttons; the
// selective and global forms are two forms rather than one with a script
// deciding, because that is what makes both work with `script-src 'none'`.
// ---------------------------------------------------------------------------
function page(title, inner, policy) {
  return { policy: policy || app.contentSecurityPolicy({}),
    html: '<!doctype html><html lang="en"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width, initial-scale=1">' +
    '<title>' + xmlEscape(title) + '</title><style>' +
    'body{font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;margin:2rem auto;' +
    'max-width:60rem;padding:0 1rem;line-height:1.5;color:#111}' +
    'h1{font-size:1.5rem;margin-bottom:.2rem}h2{font-size:1.05rem;margin:1.6rem 0 .3rem}' +
    '.sub{color:#555;font-size:.9rem}.what{color:#444;font-size:.88rem;margin:.2rem 0 .6rem}' +
    '.ok{background:#e8f5e9;border-left:4px solid #2e7d32;padding:.6rem .8rem;margin:1rem 0}' +
    '.warn{background:#fff8e1;border-left:4px solid #f9a825;padding:.6rem .8rem;margin:1rem 0}' +
    '.err{background:#ffebee;border-left:4px solid #b00020;padding:.6rem .8rem;margin:1rem 0}' +
    'table{border-collapse:collapse;width:100%;margin:.3rem 0 1rem}' +
    'th,td{text-align:left;padding:.4rem .5rem;border-bottom:1px solid #ddd;vertical-align:top;' +
    'font-size:.92rem}' +
    'th{font-size:.8rem;text-transform:uppercase;letter-spacing:.03em;color:#555}' +
    'code{background:#f4f4f4;padding:.05rem .25rem;border-radius:3px;word-break:break-all}' +
    '.cannot{color:#8a6d00}.spec{color:#555;font-size:.82rem}' +
    'button{font:inherit;padding:.45rem .9rem;border-radius:4px;border:1px solid #999;' +
    'background:#f6f6f6;cursor:pointer}' +
    'button.global{background:#b00020;border-color:#8a0018;color:#fff;font-weight:600}' +
    '.actions{margin:1.2rem 0;display:flex;gap:.8rem;flex-wrap:wrap;align-items:center}' +
    '</style></head><body>' + inner + '</body></html>' };
}

function whenText(ms) {
  if (!ms) return '—';
  return new Date(ms).toISOString();
}

// One family's table. The checkbox column is omitted entirely for a family that
// cannot be ended, rather than drawn disabled: a disabled control invites
// somebody to work out why it is disabled, and the sentence in the row already
// says.
function familyTable(family) {
  const head = '<h2>' + xmlEscape(family.label) + '</h2>' +
    '<div class="spec">' + xmlEscape(family.protocol) + ' — ' + xmlEscape(family.spec) + '</div>' +
    '<div class="what">' + xmlEscape(family.what) + '</div>';
  if (family.failure) {
    return head + '<div class="err">This could not be read: ' + xmlEscape(family.failure) +
           '. Everything else on this page is unaffected, and a global logout still ' +
           'tries this family again.</div>';
  }
  if (!family.rows.length) {
    return head + '<p class="sub">Nothing live here.</p>';
  }
  const body = family.rows.map(function (r) {
    const box = r.terminable
      ? '<input type="checkbox" name="select" value="' + xmlEscape(r.id) + '">'
      : '<span class="cannot" title="' + xmlEscape(r.why) + '">—</span>';
    return '<tr><td>' + box + '</td>' +
      '<td><code>' + xmlEscape(r.label) + '</code><br><span class="sub">' +
      xmlEscape(r.detail) + '</span>' +
      (r.terminable ? '' : '<br><span class="cannot">' + xmlEscape(r.why) + '</span>') + '</td>' +
      '<td>' + xmlEscape(r.kind) + '</td>' +
      '<td class="sub">' + xmlEscape(whenText(r.startedAt)) + '</td>' +
      '<td class="sub">' + xmlEscape(whenText(r.expiresAt)) + '</td></tr>';
  }).join('');
  return head +
    '<table><thead><tr><th>End</th><th>What</th><th>Kind</th><th>Since</th><th>Until</th>' +
    '</tr></thead><tbody>' + body + '</tbody></table>' +
    (family.notListed
      ? '<p class="sub">' + family.notListed + ' more not listed (logout.maxRows is ' +
        '<code>' + family.held + '</code> held against a cap). A GLOBAL logout still ends ' +
        'every one of them — the cap is on what is drawn, never on what a termination ' +
        'reaches.</p>'
      : '');
}

function inventoryPage(base, inventory, username, message, error) {
  log.debug("Entering inventoryPage(). key=" + inventory.key);
  const inner =
    '<h1>Sign out</h1>' +
    '<p class="sub">Everything this service is still holding for <code>' +
    xmlEscape(username) + '</code>, across every protocol family it speaks.</p>' +
    (error ? '<div class="err">' + xmlEscape(error) + '</div>' : '') +
    (message ? '<div class="ok">' + xmlEscape(message) + '</div>' : '') +
    '<div class="warn"><strong>' + inventory.total + ' live item(s)</strong> in ' +
    inventory.families.filter(function (f) { return f.rows.length; }).length +
    ' famil' + (inventory.families.filter(function (f) { return f.rows.length; }).length === 1
                ? 'y' : 'ies') + '. ' +
    'Some of them cannot be ended by anybody — they are listed with the reason, because a ' +
    'sign-out that hid them would look complete when it is not.</div>' +
    '<form method="post" action="' + xmlEscape(LOGOUT_PATH) + '">' +
    '<input type="hidden" name="username" value="' + xmlEscape(username) + '">' +
    inventory.families.map(familyTable).join('') +
    '<div class="actions">' +
    '<button type="submit" name="scope" value="selected">End the ticked items</button>' +
    '<span class="sub">Nothing ticked ends nothing.</span>' +
    '</div></form>' +
    '<form method="post" action="' + xmlEscape(LOGOUT_PATH) + '">' +
    '<input type="hidden" name="username" value="' + xmlEscape(username) + '">' +
    '<input type="hidden" name="scope" value="global">' +
    '<div class="actions">' +
    '<button type="submit" class="global">Global logout — end everything above</button>' +
    '<span class="sub">The default. A POST to <code>/logout</code> with nothing selected does ' +
    'exactly this.</span>' +
    '</div></form>' +
    '<p class="sub">This service checks no password anywhere' +
    (anyUserAllowed()
      ? ', so <code>?username=</code> names anybody and grants nothing that was not already ' +
        'true — signing in as them takes one request. <code>logout.anyUser</code> turns that off.'
      : '. <code>logout.anyUser</code> is off, so this endpoint acts only on the session you ' +
        'are holding.') +
    ' The operator\'s view of the same lists, with an undo, is <code>/admin/logout</code>.</p>';
  log.debug("Leaving inventoryPage().");
  return page('Sign out', inner);
}

// The page a termination answers with: what was ended, what was not and why,
// and the three things only the BROWSER can do — the front-channel iframes, the
// WS-Federation cleanup images, and the SAML LogoutRequests as links.
function resultPage(base, result, inventory) {
  log.debug("Entering resultPage().");
  const listOf = function (rows, cls) {
    return '<table><tbody>' + rows.map(function (one) {
      return '<tr><td><code>' + xmlEscape(one.label || one.id) + '</code></td>' +
        '<td class="' + cls + '">' + xmlEscape(one.message) + '</td></tr>';
    }).join('') + '</tbody></table>';
  };
  const cleanupRows = result.cleanups.map(function (target) {
    return '<tr><td><code>' + xmlEscape(target.realm) + '</code></td><td>' +
      (target.url
        ? '<a href="' + xmlEscape(target.url) + '" target="_blank" rel="noopener noreferrer">' +
          xmlEscape(target.url) + '</a>'
        : '<span class="cannot">no wreply was supplied, so there is nowhere to send one</span>') +
      '</td></tr>';
  }).join('');
  const logoutRows = result.logoutRequests.map(function (target) {
    return '<tr><td><code>' + xmlEscape(target.entityId) + '</code></td><td>' +
      (target.url
        ? '<a href="' + xmlEscape(target.url) + '">send the LogoutRequest</a><br>' +
          '<span class="sub">' + xmlEscape(target.from) + '</span>'
        : '<span class="cannot">no SingleLogoutService is known for it</span>') +
      '</td></tr>';
  }).join('');
  const images = result.cleanups.filter(function (t) { return !!t.url; }).map(function (t) {
    return '<img src="' + xmlEscape(t.url) + '" alt="" width="1" height="1">';
  }).join('');
  const inner =
    '<h1>' + (result.scope === 'global' ? 'Signed out everywhere' : 'Signed out of what was ticked') +
    '</h1>' +
    '<p class="sub">' + xmlEscape(result.message) + '</p>' +
    (result.terminated.length
      ? '<h2>Ended</h2>' + listOf(result.terminated, 'sub')
      : '<div class="warn">Nothing was ended. Either nothing was live, or everything ticked ' +
        'had already gone.</div>') +
    (result.skipped.length
      ? '<h2>Not ended</h2>' + listOf(result.skipped, 'cannot') +
        '<p class="sub">These are the honest half. Most of them cannot be ended by anybody: ' +
        'nothing consults this service when an assertion, a service ticket or an SVID is ' +
        'presented, so there is no revocation to perform.</p>'
      : '') +
    (result.notifications.length
      ? frontchannel.render(result.notifications)
      : '') +
    (result.cleanups.length
      ? '<h2>WS-Federation cleanup requests</h2>' +
        '<table><thead><tr><th>Realm</th><th>Cleanup URL</th></tr></thead><tbody>' +
        cleanupRows + '</tbody></table>' +
        '<p class="sub">Each was fetched as a one-pixel image as this page loaded — ' +
        'front-channel logout — and the links are the same URLs so a failed ping can be seen ' +
        'rather than guessed at.</p>' + images
      : '') +
    (result.logoutRequests.length
      ? '<h2>SAML 2.0 LogoutRequests</h2>' +
        '<table><thead><tr><th>Service provider</th><th>LogoutRequest</th></tr></thead><tbody>' +
        logoutRows + '</tbody></table>' +
        '<p class="sub">Links rather than an automatic fan-out, which is /saml2/slo\'s own ' +
        'decision reused: a LogoutRequest is a signed message a service provider ANSWERS, and ' +
        'firing those into hidden frames would claim a federation-wide logout this service ' +
        'cannot observe.</p>'
      : '') +
    '<h2>What is still live</h2>' +
    (inventory.total
      ? '<p class="sub">' + inventory.total + ' item(s) remain. <a href="' +
        xmlEscape(LOGOUT_PATH + '?username=' + encodeURIComponent(result.key)) +
        '">Look again</a>.</p>'
      : '<div class="ok">Nothing. This service is holding no live session or credential for ' +
        xmlEscape(result.key) + ' that it can still see.</div>');
  // The two relaxations this one response needs, and only these: `frame-src`
  // for the front-channel iframes, enumerated from the URLs actually being
  // loaded, and `img-src` for the cleanup pings, which are third-party by
  // definition. Both go through app.contentSecurityPolicy(), which re-adds
  // `frame-ancestors` and `base-uri` whatever is asked for — this page cannot
  // drop them and must not want to.
  const origins = frontchannel.frameOriginsOf(result.notifications);
  const overrides = {};
  if (origins.length) overrides['frame-src'] = origins.join(' ');
  if (images) overrides['img-src'] = "'self' data: *";
  log.debug("Leaving resultPage().");
  return page('Signed out', inner, app.contentSecurityPolicy(overrides));
}

function send(res, built, status) {
  res.status(status || 200).type('text/html')
     .set('Cache-Control', 'no-store')
     .set('Content-Security-Policy', built.policy)
     .send(built.html);
}

// ---------------------------------------------------------------------------
// WHO THIS REQUEST IS ABOUT.
//
// Three answers and the order matters:
//
//   1. an explicit `username`, when `logout.anyUser` allows one. It is checked
//      FIRST so that a person holding a session can still look at somebody
//      else's list — which is what a test driving this endpoint does.
//   2. the session cookie.
//   3. nobody, which is not an error: it means "sign in first", and the caller
//      is sent to the authentication service and returned here.
//
// The identity KEY is what everything downstream uses (`stats.identityKeyOf`),
// and the username as typed is what the page prints. Keeping both is what makes
// `alice@STS.MOCK` and `alice` one inventory while the page still says which
// spelling was asked about.
// ---------------------------------------------------------------------------
function subjectOf(req, body) {
  log.debug("Entering subjectOf().");
  const asked = String((body && body.username) || req.query.username || '').trim();
  if (asked) {
    if (!anyUserAllowed()) {
      log.debug("Leaving subjectOf(). A name was given and logout.anyUser is off.");
      return { refused: true, asked: asked };
    }
    log.debug("Leaving subjectOf(). Named: " + asked);
    return { username: asked, key: stats.identityKeyOf(asked), named: true };
  }
  const session = authn.sessionOf(req);
  if (session) {
    const username = (session.user && session.user.username) || '';
    log.debug("Leaving subjectOf(). From the session cookie: " + username);
    return { username: username, key: stats.identityKeyOf(username), session: session };
  }
  log.debug("Leaving subjectOf(). Nobody.");
  return {};
}

// Does this caller want JSON? The same three tests `admin.js`'s `wantsJson()`
// makes, and for the same reason — a program driving this endpoint cannot read
// an HTML page, and a browser's `Accept` mentions JSON on its wildcard. It is
// spelt out here rather than imported because requiring `admin.js` from this
// module would be a require into the console for six lines.
function wantsJson(req) {
  if (String((req.query || {}).format || '') === 'json') return true;
  if (/json/i.test(String(req.headers['content-type'] || ''))) return true;
  const accept = String(req.headers.accept || '');
  return /json/i.test(accept) && !/text\/html/i.test(accept);
}

function refusedNamedUser(req, res, asked) {
  const message = 'logout.anyUser is off on this instance, so /logout acts only on the session ' +
                  'you are holding. It was asked about "' + asked + '".';
  if (wantsJson(req)) {
    res.status(403).type('application/json').set('Cache-Control', 'no-store')
       .send(JSON.stringify({ error: 'forbidden', error_description: message }, null, 2));
    return;
  }
  send(res, page('Sign out', '<h1>Sign out</h1><div class="err">' + xmlEscape(message) +
                 '</div><p class="sub">Sign in as that person at <code>/authn/login</code> — ' +
                 'no password is checked — or use <code>/admin/logout</code>, which is the ' +
                 'operator\'s door and is behind the console\'s two roles.</p>'), 403);
}

// The issuer identifier a front-channel notification's `iss` carries. This
// process runs several named authorization servers and an RP is expecting the
// one that issued ITS tokens; /logout is not under any of them, so it uses the
// default, which is what a client that never chose a profile got.
function issuerFor(req) {
  return oauth2.issuerOf(baseUrlOf(req));
}

// ---------------------------------------------------------------------------
// GET /logout — the inventory.
//
// With no session and no `username`, the browser goes to the authentication
// service and comes back here. That is the same contract every protocol module
// follows (`beginAuthentication()` with a `returnTo` on this service), and it
// is worth noticing what it means: signing out may require signing in first,
// because this service has no other way to know who is asking. The session that
// creates is listed like any other and a global logout ends it too — which is
// why the cookie is cleared on the way out of the POST.
// ---------------------------------------------------------------------------
app.get(LOGOUT_PATH, function (req, res) {
  log.debug("Entering the logout endpoint.");
  const subject = subjectOf(req, null);
  if (subject.refused) {
    refusedNamedUser(req, res, subject.asked);
    log.debug("Leaving the logout endpoint. A name was given and logout.anyUser is off.");
    return;
  }
  if (!subject.key) {
    if (wantsJson(req)) {
      // A program is told to name somebody rather than redirected to a screen
      // it cannot read — the distinction admin.js's gate makes, for the same
      // reason: a 302 to HTML arrives as a 200 full of markup.
      res.status(401).type('application/json').set('Cache-Control', 'no-store')
         .send(JSON.stringify({
           error: 'no_subject',
           error_description: anyUserAllowed()
             ? 'There is no session cookie on this request. Name somebody with ?username=, or ' +
               'sign in at /authn/login first.'
             : 'There is no session cookie on this request, and logout.anyUser is off, so ' +
               'there is nobody for this endpoint to act on. Sign in at /authn/login first.'
         }, null, 2));
      log.debug("Leaving the logout endpoint. No subject, answered 401.");
      return;
    }
    res.redirect(302, authn.beginAuthentication({
      returnTo: LOGOUT_PATH,
      protocol: 'Logout',
      details: [{ label: 'what happens next',
                  value: 'you will be shown everything this service is still holding for you',
                  note: 'signing out may mean signing in first: this service has no other way ' +
                        'to know who is asking. The session this creates is listed too.' }]
    }));
    log.debug("Leaving the logout endpoint. Sent to the authentication service first.");
    return;
  }
  const inventory = inventoryFor(subject.key, issuerFor(req));
  if (wantsJson(req)) {
    res.status(200).type('application/json').set('Cache-Control', 'no-store')
       .send(JSON.stringify(Object.assign({ username: subject.username }, inventory), null, 2));
    log.debug("Leaving the logout endpoint. Answered JSON.");
    return;
  }
  send(res, inventoryPage(baseUrlOf(req), inventory, subject.username,
                          String(req.query.notice || ''), ''));
  log.debug("Leaving the logout endpoint. " + inventory.total + " live item(s).");
});

// ---------------------------------------------------------------------------
// POST /logout — end them.
//
// `select` repeated names rows; anything else — including a body with nothing
// in it at all — is a GLOBAL logout, which is the documented default and the
// reason `curl -X POST .../logout` with a cookie does the obvious thing.
//
// The cookie is cleared whenever the CALLER'S OWN session was among the things
// ended, and only then: this endpoint can end somebody else's sessions, and
// clearing the cookie of a browser signed in as a third party would sign the
// wrong person out.
// ---------------------------------------------------------------------------
app.post(LOGOUT_PATH, function (req, res) {
  log.debug("Entering the logout action endpoint.");
  const body = parseBody(req);
  const subject = subjectOf(req, body);
  if (subject.refused) {
    refusedNamedUser(req, res, subject.asked);
    log.debug("Leaving the logout action endpoint. A name was given and logout.anyUser is off.");
    return;
  }
  if (!subject.key) {
    const message = anyUserAllowed()
      ? 'There is nobody to sign out: this request carries no session cookie and named no ' +
        'username. A POST is never redirected to the sign-in screen — a 303 would make it a ' +
        'GET and the fields would be gone.'
      : 'There is nobody to sign out: this request carries no session cookie, and ' +
        'logout.anyUser is off.';
    if (wantsJson(req)) {
      res.status(401).type('application/json').set('Cache-Control', 'no-store')
         .send(JSON.stringify({ error: 'no_subject', error_description: message }, null, 2));
    } else {
      send(res, page('Sign out', '<h1>Sign out</h1><div class="err">' + xmlEscape(message) +
                     '</div><p class="sub"><a href="' + xmlEscape(LOGOUT_PATH) +
                     '">Start again</a>.</p>'), 401);
    }
    log.debug("Leaving the logout action endpoint. No subject.");
    return;
  }
  // `scope=global` is explicit and an empty selection means the same thing.
  // Both are spelt out because the button says "global" and a caller with no
  // form should get the same behaviour from an empty body.
  const explicitGlobal = String(body.scope || '') === 'global';
  const raw = body.select === undefined ? [] : body.select;
  const selection = explicitGlobal ? [] : (Array.isArray(raw) ? raw : [raw]).filter(Boolean);
  const ownSessionId = subject.session ? subject.session.id : '';
  const result = terminate(subject.key, selection, {
    issuer: issuerFor(req),
    actor: subject.username,
    by: subject.named ? '/logout, naming ' + subject.username : '/logout, on its own session'
  });
  // Did the caller's own session go? Only then is the cookie cleared. It is
  // checked against what was actually ENDED rather than against the scope, so a
  // selective logout that happened to include this browser's session clears it
  // too — a cookie naming a session this service no longer holds is a browser
  // that looks signed in and is not.
  const endedOwn = !!ownSessionId && result.terminated.some(function (one) {
    return one.id === 'session:' + ownSessionId;
  });
  if (endedOwn) authn.clearSessionCookie(res);
  if (wantsJson(req)) {
    res.status(200).type('application/json').set('Cache-Control', 'no-store')
       .send(JSON.stringify(Object.assign({ username: subject.username,
                                            ownSessionEnded: endedOwn }, result), null, 2));
    log.debug("Leaving the logout action endpoint. Answered JSON.");
    return;
  }
  // The inventory is read AGAIN, after the terminations, so the page's "what is
  // still live" is the state now rather than the state the form was drawn from.
  const remaining = inventoryFor(subject.key, issuerFor(req));
  send(res, resultPage(baseUrlOf(req), result, remaining));
  log.debug("Leaving the logout action endpoint. " + result.terminated.length + " ended.");
});

// ---------------------------------------------------------------------------
// THE CONSOLE'S SLOT, FILLED HERE — AND IT IS RULE 3e's TEST ANSWERING YES.
//
// `/admin/logout` is this feature's operator door and `admin.js` draws it. That
// module cannot require this one: this one requires `ldap_server.js` (for the
// bound connections that ARE the LDAP session) and `ldap_server.js` requires
// `admin.js` to fill its five slots — so the require would close a cycle AND
// drag every `/ldap` route into the router ahead of the console's own. Both
// halves of the test, so the direction is inverted, exactly as it is for the
// directory reader, the SPIFFE reader, the SCIM reader, the group reader and
// the directory writer.
//
// It is ONE object and `setLogoutReader()` validates it whole, because a
// partial one would leave that page listing what is live and unable to end any
// of it. The guard is the same shape `ldap_server.js` uses when it fills
// `admin_rbac.js`: a console that will not start is worse than one page that
// says why it cannot answer.
const adminConsole = require('../admin-ui/admin');
if (typeof adminConsole.setLogoutReader === 'function') {
  adminConsole.setLogoutReader({
    FAMILIES: FAMILIES.map(function (family) {
      return { id: family.id, label: family.label, protocol: family.protocol,
               spec: family.spec, what: family.what,
               terminable: typeof family.terminate === 'function' };
    }),
    inventoryFor: inventoryFor,
    terminate: terminate
  });
}

module.exports = {
  LOGOUT_PATH: LOGOUT_PATH,
  // The list of families, for /admin/logout and the management API's OpenAPI
  // document — both describe what this endpoint reaches, and a second list over
  // there would be a second answer that goes stale on the day a family is
  // added. Only the prose: `collect` and `terminate` stay in here.
  FAMILIES: FAMILIES.map(function (family) {
    return { id: family.id, label: family.label, protocol: family.protocol,
             spec: family.spec, what: family.what,
             terminable: typeof family.terminate === 'function' };
  }),
  // The two functions everything else calls. `admin.js` renders them at
  // /admin/logout and `admin_api.js` serves them at /admin-api/logout, which is
  // what makes the console, the API and this page one behaviour rather than
  // three — rule 7.
  inventoryFor: inventoryFor,
  terminate: terminate
};
