'use strict';
//
// File: spnego.js
//
// NOTE ON THE NAME. The RFC 4178 codec beside this file is krb5_spnego.js and
// is VENDORED — a byte-identical copy of common/krb5/krb5_spnego.js in the
// parent project, kept honest by tests/krb5_codec_sync.js. This file is the
// mock's own, so it is named for the protocol like wsfed.js and wstrust.js
// rather than for the codec. Do not merge the two: one is somebody else's file.
//
// ---------------------------------------------------------------------------
// A SPNEGO-protected web page: Kerberos over HTTP, RFC 4559 and RFC 4178.
//
// krb5_service.js said this would come — "an HTTP service wrapping the same
// token in a `Negotiate` header is SPNEGO, which is the next phase; the
// acceptor logic here is written as its own function so that phase adds a
// transport and no protocol code". This is that phase, and the promise held:
// every Kerberos check still happens in krb5_service.js's accept(), and what is
// here is the negotiation around it and the HTTP that carries it.
//
// ---------------------------------------------------------------------------
// THE EXCHANGE, which is two round trips and looks like one.
//
//   GET /spnego/protected                          (no Authorization)
//   401 WWW-Authenticate: Negotiate                (the bare challenge)
//
//   GET /spnego/protected
//   Authorization: Negotiate <NegTokenInit>        mechTypes + an AP-REQ
//   200 WWW-Authenticate: Negotiate <NegTokenResp> accept-completed + AP-REP
//
// The first 401 carries NO token. That is RFC 4559 section 4: the server says
// only that it will negotiate, and the client — which already knows the SPN
// from the URL — goes to the KDC by itself. Nothing about which KDC, which
// realm or which SPN is in this exchange at all, which is why a SPNEGO failure
// so often turns out to be a DNS or SPN problem with no evidence on the wire.
//
// ---------------------------------------------------------------------------
// WHAT THIS ACCEPTOR IS DELIBERATELY STRICT ABOUT, AND WHAT IT IS NOT.
//
// Strict: the mechanism list must contain Kerberos, the mechListMIC is verified
// when one is sent, and a MIC that does not verify is a REJECT rather than a
// warning. That last one is the whole point of RFC 4178 section 5 — the MIC is
// what makes a mechanism list unforgeable, so an acceptor that logs a bad MIC
// and continues has implemented the syntax and none of the protection.
//
// Not strict: it accepts a BARE Kerberos InitialContextToken (no negotiation at
// all), because real clients send one and a debugger that refused it would be
// teaching something false. It says so in the response body rather than hiding
// the difference.
//
// ---------------------------------------------------------------------------
// THE KEY THE mechListMIC IS COMPUTED WITH, which is the one thing here nobody
// can guess and every implementation has to agree on.
//
// The two MICs use DIFFERENT keys, and the asymmetry is forced by when each one
// is computed rather than chosen:
//
//  * The INITIATOR's mechListMIC travels in the NegTokenInit, which is built
//    before any answer exists. The only context key that exists at that moment
//    is the subkey in its own Authenticator (or, if it sent none, the ticket's
//    session key). So that is the key, with the initiator's key usage, 25.
//  * The ACCEPTOR's mechListMIC travels beside the AP-REP, by which point the
//    acceptor has offered a subkey of its own — and RFC 4121 makes THAT the
//    context key once it is offered. So the acceptor's MIC uses the acceptor
//    subkey, with the acceptor's key usage, 23.
//
// Both are over the DER of the MechTypeList — the SEQUENCE, not the `[0]`
// wrapper it sits behind inside NegTokenInit (RFC 4178 section 5). Both use
// sequence number 0. Getting any of that wrong produces a MIC that verifies
// against nothing, and an error naming a checksum.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// THE EXCHANGE ITSELF MOVED OUT ON 2026-08-26, AND THIS FILE KEPT THE PAGE.
//
// Everything above this line still describes what happens; `spnego_exchange.js`
// is where it happens now. The split was forced by a SECOND DOOR — the sign-in
// at `/authn/spnego`, which turns this same handshake into a session — and the
// argument is the one `krb5_service.js` made when THIS module was written: two
// transports over one acceptor, because two acceptors would be a page that
// documents a check the sign-in does not make, with nothing anywhere to fail.
//
// So what is below is a RENDERER. It asks `negotiate()` for a verdict, switches
// on the verdict's `code`, and writes the prose. Not one line of Kerberos or
// RFC 4178 is left in this file, and that is the property to keep: a branch
// added here that decides something rather than describing it belongs one file
// over.
// ---------------------------------------------------------------------------
const app = require('../common/app');
const { log, xmlEscape } = require('../common/helpers');
// For one thing only: whether the SIGN-IN door beside this page is open, which
// the advertisement reports rather than implies. A library that registers no
// route, so requiring it moves nothing.
const config = require('../common/config');
const spnego = require('./krb5_spnego.js');
const principals = require('./krb5_principals.js');
const exchange = require('./spnego_exchange.js');

// Re-exported from the library, because this page names them in its
// advertisement and a second list would be a page describing an acceptor that
// is not the one behind it.
const SUPPORTED_MECHS = exchange.SUPPORTED_MECHS;

// ---------------------------------------------------------------------------
// The HTML the two pages share. A local copy of wsfed.js's page() rather than a
// require of it: server.js's require order IS the route order and the modules
// deliberately do not reach sideways into each other (see CLAUDE.md rule 2), so
// a shared page helper would belong in helpers.js and moving it there means
// touching five protocols for one new page.
// ---------------------------------------------------------------------------
function page(title, inner) {
  log.debug('Entering page().');
  log.debug('Leaving page().');
  return '<!DOCTYPE html>\n<html lang="en"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width, initial-scale=1">' +
    '<title>' + xmlEscape(title) + '</title><style>' +
    'body{font-family:system-ui,-apple-system,"Segoe UI",Arial,sans-serif;background:#f4f4f7;margin:0;' +
    'padding:2rem;color:#222;line-height:1.45}' +
    '.card{background:#fff;border:1px solid #d5d5dd;border-radius:10px;padding:24px 28px;' +
    'max-width:52rem;margin:0 auto;box-shadow:0 6px 24px rgba(0,0,0,.08)}' +
    'h1{font-size:1.3em;margin:0 0 4px;color:#12107c}h2{font-size:1em;margin:1.4em 0 .4em}' +
    'p.sub{color:#666;font-size:.85em;margin:0 0 18px}' +
    'table{border-collapse:collapse;width:100%;margin:.5rem 0 1rem;font-size:.85em}' +
    'th,td{border:1px solid #ddd;padding:.35rem .55rem;text-align:left;vertical-align:top}' +
    'th{background:#f0f0f5}.pass{color:#0b6b4f;font-weight:600;white-space:nowrap}' +
    '.fail{color:#b00020;font-weight:600;white-space:nowrap}' +
    '.err{background:#fdecea;border:1px solid #f5c6c2;color:#b00020;padding:8px 10px;border-radius:5px;' +
    'font-size:.9em;margin-bottom:12px}' +
    '.ok{background:#e8f5e9;border:1px solid #a5d6a7;padding:8px 10px;border-radius:5px;' +
    'font-size:.9em;margin-bottom:12px}' +
    'pre{background:#f4f4f8;border:1px solid #e2e2ea;border-radius:5px;padding:.6rem;font-size:.75rem;' +
    'overflow-x:auto;white-space:pre-wrap;word-break:break-all}' +
    'code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.85em;background:#f4f4f8;' +
    'padding:.1rem .25rem;border-radius:3px;word-break:break-all}a{color:#12107c}' +
    'ul{margin:.3em 0;padding-left:1.2em}li{margin:.2em 0}' +
    '</style></head><body><div class="card">' + inner + '</div></body></html>\n';
}

function checksTable(checks) {
  log.debug('Entering checksTable().');
  const rows = (checks || []).map(function (c) {
    return '<tr><td>' + xmlEscape(c.name) + '</td><td class="' +
      (c.ok ? 'pass">passed' : 'fail">FAILED') + '</td><td>' +
      xmlEscape(c.detail == null ? '' : String(c.detail)) + '</td></tr>';
  }).join('');
  log.debug('Leaving checksTable().');
  return '<table><tr><th>Check</th><th>Result</th><th>Detail</th></tr>' +
    rows + '</table>';
}

// ---------------------------------------------------------------------------
// The advertisement. A page that says a protected resource exists, what SPN it
// is behind, and what a client has to do — which is the part a real intranet
// site never tells you and the part that is always wrong.
// ---------------------------------------------------------------------------
const SPN = exchange.SPN;

app.get('/spnego', function (req, res) {
  log.debug('Entering GET /spnego.');
  const principal = SPN + '@' + principals.REALM;
  if (String(req.query.format || '').toLowerCase() === 'json') {
    log.debug('Leaving GET /spnego. JSON.');
    return res.status(200).json({
      protectedResource: '/spnego/protected',
      // THE SECOND DOOR, named here because this page is where somebody comes
      // to find out what SPNEGO surface this service has and the two are easy
      // to confuse: the resource above proves a handshake and stops, and this
      // one turns the same handshake into a session sixteen protocol families
      // read. Its own availability is a setting, so it is reported rather than
      // implied.
      signInResource: '/authn/spnego',
      signInEnabled: !!config.value('krb5.spnegoAuthentication'),
      servicePrincipalName: principal,
      // The SPN a client DERIVES from this URL's host is usually not the
      // canonical one above — RFC 4559 clients guess `HTTP/<url host>`, so
      // reaching this mock at localhost or by its compose name produces
      // HTTP/localhost or HTTP/sts. This service holds a key for any SPN whose
      // host matches one of these, and the KDC registers it on first sight, so a
      // client's own guess works. NOTHING IN SPNEGO CARRIES THIS: it is an
      // affordance of the mock, published so a debugger can show what a real
      // deployment would make you look up in DNS and in the account's keytab.
      acceptsAnySpnForHosts: principals.SERVICE_DOMAINS,
      spnHostRule: 'a host matches when it IS one of acceptsAnySpnForHosts or ' +
        'ends with a dot and one of them',
      mechanisms: SUPPORTED_MECHS.map(function (oid) {
        return { oid: oid, name: spnego.mechName(oid) };
      }),
      scheme: 'Negotiate',
      specifications: ['RFC 4178 (SPNEGO)', 'RFC 4559 (Negotiate over HTTP)',
                       'RFC 4121 (the Kerberos v5 GSS-API mechanism)'],
      knobs: {
        'mic=require': 'answer the first token with request-mic, forcing the ' +
          'mechListMIC exchange and a second round trip',
        'mech=none': 'support no mechanism the client offers, so the ' +
          'negotiation is rejected',
        'mutual=off': 'accept the ticket but send no AP-REP back'
      },
      // The knobs above are THIS page's and the sign-in door takes none of
      // them, deliberately: a door that mints sessions with a query parameter
      // that makes it fail in an instructive way is a footgun rather than a
      // lesson, and the lesson is available here.
      knobsApplyTo: '/spnego/protected only',
      lastExchange: exchange.lastExchange()
    });
  }
  const inner = '<h1>A SPNEGO-protected page lives here</h1>' +
    '<p class="sub">Kerberos over HTTP: RFC 4559 carries RFC 4178, which ' +
    'carries RFC 4121, which carries the AP-REQ.</p>' +
    '<p><a href="/spnego/protected"><strong>/spnego/protected</strong></a> ' +
    'answers <code>401</code> with <code>WWW-Authenticate: Negotiate</code> ' +
    'to anyone who asks for it without a ticket. Your browser will most ' +
    'likely fail that: Chrome and Firefox use Negotiate only for hosts on an ' +
    'explicit allow-list, so what you will see is the 401 itself. That is ' +
    'the point of the debugger &mdash; it performs the handshake by hand and ' +
    'shows you both halves.</p>' +
    '<h2>And the same handshake as a sign-in</h2>' +
    '<p><a href="/authn/spnego"><strong>/authn/spnego</strong></a> performs ' +
    'exactly the negotiation above &mdash; same acceptor, same checks, same ' +
    'code &mdash; and then <strong>starts a browser session</strong> for the ' +
    'principal the ticket named. Past it, an OAuth 2.0 authorization ' +
    'request, a <code>wsignin1.0</code>, a SAML <code>AuthnRequest</code> and ' +
    'the admin console all complete without anybody typing anything, because ' +
    'every protocol here reads the one session.</p>' +
    '<p>That is the difference between the two doors, and it is the only ' +
    'difference: this one proves a handshake and stops, that one acts on it. ' +
    'It is available to every application and registered for none &mdash; a ' +
    'button on the sign-in screen, <code>appAuthnMechanism: spnego</code> on ' +
    'an application entry, or <code>fedAuthnMechanism: spnego</code> on a ' +
    'federation relationship. ' +
    (config.value('krb5.spnegoAuthentication')
       ? ''
       : '<strong>It is switched off right now</strong> ' +
         '(<code>krb5.spnegoAuthentication</code>), so it answers 403 and ' +
         'says so. ') +
    'The three knobs below are this page&rsquo;s alone: a sign-in door with a ' +
    'query parameter that makes it fail in an instructive way is a footgun ' +
    'rather than a lesson.</p>' +
    '<h2>What a client needs before it can get in</h2>' +
    '<table>' +
    '<tr><th>Thing</th><th>Value</th></tr>' +
    '<tr><td>Service principal name</td><td><code>' +
      xmlEscape(principal) + '</code></td></tr>' +
    '<tr><td>Realm</td><td><code>' + xmlEscape(principals.REALM) +
      '</code></td></tr>' +
    '<tr><td>Authentication scheme</td><td><code>Negotiate</code></td></tr>' +
    '<tr><td>Mechanisms accepted</td><td>' +
      SUPPORTED_MECHS.map(function (oid) {
        return '<code>' + xmlEscape(oid) + '</code> (' +
          xmlEscape(spnego.mechName(oid)) + ')';
      }).join('<br>') + '</td></tr>' +
    '</table>' +
    '<p>Note what is <em>not</em> in the exchange: the realm, the KDC, and ' +
    'the SPN. The client derives the SPN from the URL&rsquo;s host name and ' +
    'finds the KDC from its own configuration, so a SPNEGO failure is ' +
    'usually a DNS or SPN problem that leaves no evidence on the wire at ' +
    'all. The SPN this service holds a key for is above; a ticket for any ' +
    'other name is refused with <code>KRB_AP_ERR_NOT_US</code>.</p>' +
    '<h2>Deliberate misconfigurations</h2>' +
    '<p>Add these to <code>/spnego/protected</code> to make the negotiation ' +
    'go wrong in one specific way &mdash; which is what this mock is for:</p>' +
    '<ul>' +
    '<li><code>?mic=require</code> &mdash; answer with ' +
      '<code>request-mic</code>, so the mechListMIC exchange becomes ' +
      'mandatory and the handshake takes a second round trip.</li>' +
    '<li><code>?mech=none</code> &mdash; support nothing the client offers, ' +
      'so the negotiation ends in <code>reject</code> with no explanation, ' +
      'exactly as the protocol requires.</li>' +
    '<li><code>?mutual=off</code> &mdash; accept the ticket and send no ' +
      'AP-REP, so the client is authenticated and has proved nothing about ' +
      'the server.</li>' +
    '</ul>' +
    '<p class="sub"><a href="/spnego?format=json">This page as JSON</a> ' +
    '&middot; <a href="/krb5/principals">the KDC&rsquo;s principals</a> ' +
    '&middot; <a href="/admin/sts-metadata">everything this service ' +
    'speaks</a></p>';
  res.status(200).type('html').send(page('SPNEGO-protected page', inner));
  log.debug('Leaving GET /spnego.');
});

// ---------------------------------------------------------------------------
// THE PROTECTED RESOURCE — a renderer over `negotiate()`'s verdict.
//
// One case per outcome in `spnego_exchange.js`'s OUTCOMES table, and the switch
// is EXHAUSTIVE on purpose rather than defensive: a new outcome added over
// there falls into `default`, which says so out loud instead of drawing a page
// that quietly describes the wrong thing. That is the whole reason the codes
// are a named table rather than a set of strings written at the branches.
//
// Nothing in here decides anything. Every heading below is a sentence about a
// decision made one file over, and the moment one of them starts computing
// something the split has been undone.
// ---------------------------------------------------------------------------

// The heading each verdict gets, and the `<title>`. Kept as a table because the
// two are chosen together and a switch would have interleaved them with the
// prose, where a reader comparing two branches has to hold both in their head.
const HEADINGS = {
  'no-authorization':        ['Authentication required', '401 &mdash; authentication required'],
  'wrong-scheme':            ['Wrong scheme', '401 &mdash; wrong authentication scheme'],
  'empty-token':             ['Empty token', '401 &mdash; an empty Negotiate token'],
  'no-mech-token':           ['Send a token', '401 &mdash; send the mechanism&rsquo;s token'],
  'ticket-refused':          ['Ticket refused', '401 &mdash; the ticket was refused'],
  'request-mic':             ['Send the MIC', '401 &mdash; send the mechListMIC'],
  'accepted':                ['Authenticated', '200 &mdash; you are in']
};

// Everything not in the table above is a REJECT, and they share one page: the
// heading is the negotiation being rejected, the reason is in the banner, and
// the detail below it is the only place a client could ever learn why.
const REJECTED = ['Rejected', '401 &mdash; the negotiation was rejected'];

// The paragraph under the banner, per outcome. A function rather than a table
// because five of them read facts off the verdict.
function detailFor(verdict) {
  log.debug('Entering detailFor(). code=' + verdict.code);
  let html = '';
  switch (verdict.code) {
    case 'no-authorization':
      html = '<p>This resource is protected with <code>Negotiate</code>. The ' +
        'challenge above carries <strong>no token</strong>, which is RFC 4559 ' +
        'section 4: the server says only that it will negotiate, and the ' +
        'client is expected to know the rest already.</p>' +
        '<p>What the client has to work out for itself, with no help from this ' +
        'exchange: that the service principal name is <code>' +
        xmlEscape(SPN) + '</code>, which realm that is in, and where that ' +
        'realm&rsquo;s KDC is.</p>';
      break;
    case 'wrong-scheme':
      html = '<div class="err">This resource speaks <code>Negotiate</code>. The ' +
        'request offered <code>' + xmlEscape(verdict.scheme) + '</code>.</div>';
      break;
    case 'empty-token':
      html = '<div class="err">The <code>Authorization</code> header named ' +
        '<code>Negotiate</code> and carried nothing after it.</div>';
      break;
    case 'undecodable':
      html = '<p>The bytes after <code>Negotiate </code> must be a SPNEGO ' +
        'negotiation token (RFC 4178) or a bare Kerberos GSS token (RFC 4121).' +
        '</p>';
      break;
    case 'no-common-mechanism':
      html = '<p>The client offered ' + verdict.offered.length + ' mechanism(s): ' +
        verdict.offered.map(function (oid, i) {
          return '<code>' + xmlEscape(oid) + '</code> (' +
            xmlEscape(verdict.offeredNames[i]) + ')';
        }).join(', ') + '. This service supports ' +
        (verdict.supported.length
          ? verdict.supported.map(function (oid) {
              return '<code>' + xmlEscape(oid) + '</code>';
            }).join(', ')
          : '<strong>nothing</strong> &mdash; <code>?mech=none</code> is set') +
        '.</p>';
      break;
    case 'no-mech-token':
      html = '<p>The <code>NegTokenInit</code> carried a mechanism list and no ' +
        '<code>mechToken</code>, so this reply selects <code>' +
        xmlEscape(spnego.mechName(verdict.selected)) + '</code> and asks for one: ' +
        '<code>accept-incomplete</code>. That is the round trip the ' +
        '&ldquo;optimistic&rdquo; token exists to avoid.</p>';
      break;
    case 'non-kerberos-mechanism':
      html = '<p>Selected <code>' + xmlEscape(verdict.selected) + '</code>.</p>';
      break;
    case 'ticket-refused':
      html = '<div class="err">The negotiation selected Kerberos and the AP-REQ ' +
        'did not pass.</div>' +
        '<p>The reason is in the <code>responseToken</code> of the ' +
        '<code>WWW-Authenticate</code> header, as a <code>KRB-ERROR</code>. ' +
        'SPNEGO itself carries no error detail at all, so a client that reads ' +
        'only <code>negState</code> learns nothing but &ldquo;no&rdquo;.</p>';
      break;
    case 'bad-mech-list-mic':
      // TWO WORDINGS FOR ONE CODE, and the distinction is the verdict's. On the
      // first token the ticket was good and the MIC was computed over the wrong
      // bytes; on the continuation the client was asked for exactly this one
      // thing and got it wrong.
      html = verdict.continuation
        ? '<p>Computed over the DER of the <code>MechTypeList</code> &mdash; the ' +
          'SEQUENCE, not the <code>[0]</code> wrapper (RFC 4178 section 5).</p>'
        : '<p>The client&rsquo;s ticket was perfectly good. What failed is the ' +
          'integrity check over the <em>mechanism list</em> &mdash; so either ' +
          'the list was altered in transit, or the client computed the MIC ' +
          'over the wrong bytes. The commonest cause of the second is signing ' +
          '<code>[0] MechTypeList</code> rather than <code>MechTypeList</code>: ' +
          'two bytes, and RFC 4178 section 5 spells the distinction out because ' +
          'implementations kept getting it wrong.</p>';
      break;
    case 'mic-required':
      html = '<p>' + xmlEscape(verdict.requirement.reason) + '</p>';
      break;
    case 'request-mic':
      html = '<p>The ticket was accepted, and this reply is ' +
        '<code>request-mic</code>: the mechanism list must be integrity ' +
        'protected before the context is usable. Legal only in the ' +
        'acceptor&rsquo;s first reply (RFC 4178 section 4.2.2).</p>' +
        '<p>Answer with a bare <code>NegTokenResp</code> carrying only the ' +
        '<code>mechListMIC</code>, computed over the DER of the ' +
        '<code>MechTypeList</code> with the subkey from your Authenticator.</p>';
      break;
    case 'no-pending-continuation':
      html = '<p>A bare <code>NegTokenResp</code> arrived, but nothing here is ' +
        'waiting for one. A real acceptor keeps this state on the ' +
        '<em>connection</em>, which is why SPNEGO breaks behind ' +
        'connection-pooling proxies and on HTTP/2 in ways nothing reports.</p>';
      break;
    case 'continuation-no-mic':
      html = '<p>The previous reply was <code>request-mic</code>, so the only ' +
        'thing this token needed was the MIC.</p>';
      break;
    default:
      html = '';
      break;
  }
  log.debug('Leaving detailFor().');
  return html;
}

// The success page. Everything on it is read off the verdict, including the two
// facts a person cannot get any other way: whether an AP-REP went back, and
// whether the mechanism list was protected.
function acceptedPage(verdict) {
  log.debug('Entering acceptedPage().');
  const inner = '<h1>' + HEADINGS.accepted[1] + '</h1>' +
    '<div class="ok">Authenticated as <strong>' +
    xmlEscape(verdict.client || 'unknown') + '</strong> to <code>' +
    xmlEscape(SPN) + '</code>.</div>' +
    '<p>This is the protected content. Getting here took a Kerberos AP-REQ ' +
    'inside an RFC 4121 GSS token inside an RFC 4178 negotiation inside an ' +
    'RFC 4559 HTTP header &mdash; four layers, of which HTTP shows you one.' +
    '</p>' +
    '<table>' +
    '<tr><th>What</th><th>Value</th></tr>' +
    '<tr><td>Client</td><td><code>' +
      xmlEscape(verdict.client || 'unknown') + '</code></td></tr>' +
    '<tr><td>Mechanism selected</td><td><code>' +
      xmlEscape(verdict.selected) + '</code> (' +
      xmlEscape(spnego.mechName(verdict.selected)) + ')</td></tr>' +
    '<tr><td>Negotiation</td><td>' + (verdict.rawKerberos
      ? 'none &mdash; a bare Kerberos token. Accepted, but understand what ' +
        'it means: with no mechanism list there is nothing for a mechListMIC ' +
        'to protect, so none of SPNEGO&rsquo;s downgrade defence applies.'
      : 'SPNEGO, RFC 4178') + '</td></tr>' +
    '<tr><td>mechListMIC</td><td>' + (verdict.micVerified
      ? '<span class="pass">verified</span>'
      : '<span class="fail">not sent</span> &mdash; ' +
        xmlEscape(verdict.requirement.reason)) + '</td></tr>' +
    '<tr><td>Mutual authentication</td><td>' + (verdict.mutual
      ? 'an AP-REP is in the <code>WWW-Authenticate</code> header; check its ' +
        'echoed <code>ctime</code> and you have proved who answered'
      : verdict.mutualOff
        ? '<span class="fail">none</span> &mdash; <code>?mutual=off</code> is ' +
          'set, so nothing has proved this server is who it claims to be'
        : 'none in this reply') + '</td></tr>' +
    (verdict.micNote ? '<tr><td>Note</td><td>' + xmlEscape(verdict.micNote) +
      '</td></tr>' : '') +
    '</table>' +
    (verdict.checks ? '<h2>What this service checked</h2>' +
      checksTable(verdict.checks) : '');
  log.debug('Leaving acceptedPage().');
  return inner;
}

// Everything that is not the success page.
function refusalPage(verdict) {
  log.debug('Entering refusalPage(). code=' + verdict.code);
  const heading = HEADINGS[verdict.code] || REJECTED;
  const rejected = !HEADINGS[verdict.code];
  const inner = '<h1>' + heading[1] + '</h1>' +
    // The banner is the REASON, and it is only drawn where the heading has not
    // already said it — the three bare-challenge pages put their sentence in
    // the detail, which is where it reads as an explanation rather than as an
    // error about an error.
    (rejected ? '<div class="err">' + xmlEscape(verdict.reason) + '</div>' : '') +
    detailFor(verdict) +
    (verdict.checks ? '<h2>What this service checked</h2>' +
      checksTable(verdict.checks) : '') +
    (rejected
      ? '<p class="sub">SPNEGO&rsquo;s <code>reject</code> carries no reason of ' +
        'its own &mdash; the structure has no field for one. Everything above ' +
        'this line is out of band, and a real server tells you none of it.</p>'
      : '');
  log.debug('Leaving refusalPage().');
  return inner;
}

async function handleProtected(req, res) {
  log.debug('Entering handleProtected().');
  const verdict = await exchange.negotiate(req, {
    door: '/spnego/protected',
    // THE THREE KNOBS, and they are this page's alone. `/authn/spnego` takes
    // none of them: a sign-in door with a query parameter that makes it fail
    // in an instructive way is a footgun rather than a lesson, and the lesson
    // is available here.
    supported: String(req.query.mech || '') === 'none' ? [] : SUPPORTED_MECHS,
    wantMic: String(req.query.mic || '') === 'require',
    mutualOff: String(req.query.mutual || '') === 'off'
  });
  exchange.applyVerdict(res, verdict);
  const heading = HEADINGS[verdict.code] || REJECTED;
  res.type('html').send(page(heading[0],
    verdict.ok ? acceptedPage(verdict) : refusalPage(verdict)));
  log.debug('Leaving handleProtected(). ' + verdict.code + '.');
}

app.get('/spnego/protected', function (req, res) {
  log.debug('Entering GET /spnego/protected.');
  handleProtected(req, res).catch(function (e) {
    // The no-response branch must answer. This handler is async and every
    // path in it writes a response; an exception that escaped would otherwise
    // leave the client holding an open request, which reads as an unreachable
    // service rather than as a fault here.
    log.error('krb5-spnego: unhandled failure: ' + (e.stack || e.message));
    if (!res.headersSent) {
      res.status(500).type('html').send(page('Failed',
        '<h1>500</h1><div class="err">' + xmlEscape(e.message) + '</div>'));
    }
  });
  log.debug('Leaving GET /spnego/protected.');
});

module.exports = {
  SPN: SPN,
  SUPPORTED_MECHS: SUPPORTED_MECHS,
  // THE SHELL AND THE CHECK TABLE, for `spnego_authn.js` and for nothing else.
  //
  // Exported rather than copied, and the choice of WHICH look the sign-in door
  // wears is the reason. Its pages could have been drawn in `authn.js`'s
  // CARD_CSS — they are met mid-sign-in, and that is the stylesheet a person
  // has just been looking at. They are drawn in THIS one because of what has
  // to be on them: when a Kerberos sign-in fails, what the person needs is the
  // nine checks `krb5_service.js` made and the sentence saying which one did
  // not pass, and that is a table rather than a card. A third stylesheet was
  // the other option and it would have been ten lines nobody would ever diff —
  // the argument `authn.js` makes above CARD_CSS, reached from the other side.
  page: page,
  checksTable: checksTable,
  // Still exported from here, because `GET /spnego` is the page that renders it
  // and this is the module that page lives in. The RECORD is the library's now,
  // and it covers both doors — see its header for why one record rather than
  // two.
  lastExchange: exchange.lastExchange
};
