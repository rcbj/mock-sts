'use strict';
//
// File: xacml_admin.js
//
// ---------------------------------------------------------------------------
// THE POLICY ADMINISTRATION POINT: FOUR CONSOLE PAGES.
//
//   /admin/xacml            settings, and what the PDP currently decides with
//   /admin/xacml/policies   the repository — enable, disable, choose the root,
//                           delete, and create from a template
//   /admin/xacml/editor     THE GUIDED EDITOR
//   /admin/xacml/decide     ask the PDP a question and see the answer
//
// Drawn HERE rather than in `admin-ui/admin.js`, the way `ldap/ldap_server.js`
// draws its five `/admin/ldap/*` pages: a console page is a `path` and a
// `label` in that file's `SECTIONS` whoever builds the body. What crosses is
// `admin.respond()` for the shell, `admin.configFormsFor()` for the settings
// block and `admin.respondToAction()` for a form POST — three functions rather
// than a copy of the console.
//
// ---------------------------------------------------------------------------
// EVERY CONTROL ON THESE PAGES IS A PLAIN FORM POST, AND THE EDITOR IS THE
// REASON THAT IS WORTH ARGUING RATHER THAN ASSUMING.
//
// `app.js` sets `script-src 'none'` for the whole service and
// `admin-ui/CLAUDE.md` refuses a script NINE times over — twice for pages that
// draw graphs — under a rule that says the argument has to be MADE each time
// and that "the page next door does it" is not one. The test it sets is
// whether the page CANNOT work without a script.
//
// A policy editor can. So the "pick the next valid element" dropdowns are a
// `<select>` per node whose `<option>`s were computed on the server by
// `xacml_editor.js`, and choosing one is a POST that re-renders the page.
//
// WHAT THAT COSTS: a round trip per element. Building a five-rule policy by
// hand is perhaps forty POSTs, and this page says so rather than leaving
// somebody to discover it. The templates are the answer — they are the first
// twenty clicks already made.
//
// WHAT IT BUYS, and this is the half that is not a consolation: the menu is
// computed by the same process that will validate the policy, against the real
// function library, so THE EDITOR CANNOT OFFER SOMETHING THE VALIDATOR WILL
// REFUSE. A browser-side editor would have needed a second copy of the grammar
// shipped to the page, and a second copy of a grammar is the thing this whole
// directory is arranged to avoid.
//
// ---------------------------------------------------------------------------
// THE EDITOR HOLDS NO SESSION STATE, AND THAT IS DELIBERATE.
//
// The draft IS the stored policy. Every edit loads the document from
// `ou=policies`, applies one change, serializes it and writes it back. There
// is no "unsaved" state anywhere, which means there is nothing to lose when a
// browser is closed, nothing to expire, and no second copy of a policy that
// could disagree with the stored one.
//
// What it costs is that editing is LIVE: a policy being edited is the policy
// the PDP is deciding with, and a half-finished rule affects decisions
// immediately. The page says so. The way to avoid it is to leave a policy
// disabled while working on it, and the editor puts that control at the top
// rather than making somebody find it on another page.
// ---------------------------------------------------------------------------

const app = require('../common/app');
const { log, parseBody } = require('../common/helpers');
const config = require('../common/config');
const audit = require('../common/audit');
const admin = require('../admin-ui/admin');
const model = require('./xacml_model');
const xml = require('./xacml_xml');
const store = require('./xacml_store');
const editor = require('./xacml_editor');
const templates = require('./xacml_templates');
const validate = require('./xacml_validate');
const alfa = require('./xacml_alfa');
const pip = require('./xacml_pip');
const peps = require('./xacml_pep_registry');
const pepHttp = require('./xacml_pep_http');

const esc = admin.esc;

// ---------------------------------------------------------------------------
// SMALL RENDERING HELPERS. Local rather than exported from admin.js, because
// they are about POLICIES rather than about the console.
// ---------------------------------------------------------------------------
function select(name, options, selected, extra) {
  const body = options.map(function (one) {
    const value = one.value === undefined ? one.uri : one.value;
    return '<option value="' + esc(value) + '"' +
      (String(value) === String(selected) ? ' selected' : '') + '>' +
      esc(one.label) + '</option>';
  }).join('');
  return '<select name="' + esc(name) + '"' + (extra || '') + '>' + body +
    '</select>';
}

function hidden(name, value) {
  return '<input type="hidden" name="' + esc(name) + '" value="' +
    esc(value === null || value === undefined ? '' : value) + '">';
}

function textField(name, value, size) {
  return '<input type="text" name="' + esc(name) + '" value="' +
    esc(value === null || value === undefined ? '' : value) + '"' +
    (size ? ' size="' + size + '"' : '') + '>';
}

// ---------------------------------------------------------------------------
// /admin/xacml — SETTINGS AND WHAT THE PDP DECIDES WITH.
// ---------------------------------------------------------------------------
function overviewJson() {
  log.debug('Entering overviewJson().');
  const rows = store.all();
  const root = store.root();
  const json = {
    enabled: config.value('xacml.enabled') !== false,
    pepBias: config.value('xacml.pepBias'),
    policies: rows.length,
    enabledPolicies: rows.filter(function (one) {
      return one.enabled;
    }).length,
    root: root ? root.name : null,
    pipAvailable: pip.available(),
    // `configSettingsJson()` and NOT `protocolSettingsJsonFor()`. The second
    // is keyed by admin.js's own PROTOCOL_SETTINGS_PAGES table and throws for
    // a path that table does not carry — which is right for the pages that
    // file generates and wrong for one drawn here. It cost a 500 on this page
    // and nothing else, because it is the only caller outside that table.
    settings: admin.configSettingsJson
      ? admin.configSettingsJson('/admin/xacml') : null
  };
  log.debug('Leaving overviewJson().');
  return json;
}

app.get('/admin/xacml', function (req, res) {
  log.debug('Entering the admin XACML page.');
  const json = overviewJson();
  const root = store.root();
  const tiles = '<div class="tiles">' +
    admin.tile(json.policies, 'policies') +
    admin.tile(json.enabledPolicies, 'enabled') +
    admin.tile(root ? root.name : '—', 'root policy') +
    admin.tile(json.pepBias, 'PEP bias') +
    admin.tile(json.pipAvailable ? 'yes' : 'no', 'PIP has the directory') +
    '</div>';

  const rootWarning = root ? '' : admin.warn(
    'No policy is marked as the root, so <strong>every decision is ' +
    'NotApplicable</strong>. A PDP evaluates one document and reaches the ' +
    'rest through <code>PolicyIdReference</code>, so exactly one policy in ' +
    'the repository is where evaluation starts. Choose one on the ' +
    '<a href="/admin/xacml/policies">Policies</a> page.',
    'There is no root policy');

  const what = admin.note(
    '<p>This service is a <strong>Policy Decision Point</strong>. It is the ' +
    'only protocol family here that answers a question about somebody ' +
    'else&rsquo;s boundary: every other one authenticates or provisions a ' +
    'person, and this one is handed a subject who was authenticated ' +
    'somewhere else and asked whether they may.</p>' +
    '<p>Policies live in <code>ou=policies</code> in the embedded directory. ' +
    'That container <em>is</em> the repository rather than a copy of one, so ' +
    'an <code>ldapmodify</code> there changes what the PDP decides on the ' +
    'next request — and a policy survives a restart whenever ' +
    '<code>persistence.mode</code> is not <code>memory</code>.</p>' +
    '<p>The <strong>PIP</strong> reads attributes off the ' +
    'subject&rsquo;s own directory entry, so a policy can grant on ' +
    '<code>employeeType</code> ' +
    'without the caller having to assert it. What the REQUEST carries wins ' +
    'over the directory, because a PEP asserting an attribute is describing ' +
    'that request while the directory is describing the world.</p>' +
    '<p><code>xacml.pepBias</code> below is the <em>embedded ' +
    'PEP&rsquo;s</em> decision and not the PDP&rsquo;s. Deny-biased and ' +
    'permit-biased agree ' +
    'on every Permit and every Deny and differ on Indeterminate and ' +
    'NotApplicable — which is exactly the case nobody tests, and the reason ' +
    'the setting is here to flip.</p>',
    'What this page configures');

  admin.respond(req, res, json, 'XACML', '/admin/xacml',
                tiles + rootWarning + what +
                admin.configFormsFor('/admin/xacml'));
  log.debug('Leaving the admin XACML page.');
});

// ---------------------------------------------------------------------------
// /admin/xacml/policies — THE REPOSITORY.
// ---------------------------------------------------------------------------
function policiesJson() {
  log.debug('Entering policiesJson().');
  const root = store.root();
  const rows = store.all().map(function (row) {
    const view = { name: row.name, policyId: row.id, kind: row.kind,
                   version: row.version, enabled: row.enabled,
                   isRoot: !!(root && root.name === row.name),
                   combiningAlgId: row.combiningAlgId,
                   description: row.description, problems: [] };
    try {
      view.problems = validate.problemsIn(store.parseDocument(row.document));
    } catch (error) {
      view.problems = [error.message];
    }
    return view;
  });
  log.debug('Leaving policiesJson(). ' + rows.length + ' policy(ies).');
  return { root: root ? root.name : null, policies: rows,
           templates: templates.catalogue() };
}

app.get('/admin/xacml/policies', function (req, res) {
  log.debug('Entering the admin XACML policies page.');
  const json = policiesJson();
  const writable = admin.mayWrite(req);

  const rows = json.policies.map(function (row) {
    const problems = row.problems.length
      ? '<div class="sub" style="color:#b00">' +
        row.problems.map(esc).join('<br>') + '</div>'
      : '';
    const actions = writable ? '<form method="post" ' +
      'action="/admin/xacml/policies" style="display:inline">' +
      hidden('action', row.enabled ? 'disable' : 'enable') +
      hidden('name', row.name) +
      '<button type="submit">' + (row.enabled ? 'Disable' : 'Enable') +
      '</button></form> ' +
      (row.isRoot ? '' : '<form method="post" ' +
        'action="/admin/xacml/policies" style="display:inline">' +
        hidden('action', 'set-root') + hidden('name', row.name) +
        '<button type="submit">Make root</button></form> ') +
      '<form method="post" action="/admin/xacml/policies" ' +
      'style="display:inline">' +
      hidden('action', 'delete') + hidden('name', row.name) +
      '<button type="submit">Delete</button></form>'
      : '<span class="sub">read-only</span>';
    return '<tr><td><a href="/admin/xacml/editor?policy=' +
      encodeURIComponent(row.name) + '"><code>' + esc(row.name) +
      '</code></a>' + (row.isRoot ? ' <strong>(root)</strong>' : '') +
      '</td><td><code>' + esc(row.policyId) + '</code>' + problems +
      '</td><td>' + esc(row.kind) + '</td><td>' +
      esc(editor.shortName(row.combiningAlgId)
        .replace(/^.*combining-algorithm:/, '')) +
      '</td><td>' + (row.enabled ? 'enabled' : '<em>disabled</em>') +
      '</td><td>' + actions + '</td></tr>';
  }).join('') ||
    '<tr><td colspan="6">The repository is empty, so every decision is ' +
    'NotApplicable. Create one from a template below.</td></tr>';

  // THE TEMPLATE FORMS ARE DERIVED FROM `xacml_templates.js`'s table. Adding a
  // template is a row there and nothing here — which is the promise that file
  // makes, and this loop is what keeps it.
  const templateForms = writable ? json.templates.map(function (one) {
    const fields = one.parameters.map(function (parameter) {
      return '<tr><td>' + esc(parameter.label) + '</td><td>' +
        textField('p_' + parameter.name, parameter.dflt, 40) +
        '</td><td class="sub">' + esc(parameter.help || '') + '</td></tr>';
    }).join('');
    return '<details><summary>' + esc(one.label) + '</summary>' +
      '<p>' + esc(one.blurb) + '</p><p class="sub">' + esc(one.what) + '</p>' +
      '<form method="post" action="/admin/xacml/policies">' +
      hidden('action', 'create-from-template') + hidden('template', one.id) +
      '<table><tr><td>Name for the policy</td><td>' +
      textField('name', one.id, 30) +
      '</td><td class="sub">Names the directory entry. The PolicyId inside ' +
      'the document is separate and may be any URI.</td></tr>' + fields +
      '</table><button type="submit">Create</button></form></details>';
  }).join('') : '';

  const body = admin.note(
    '<p><code>ou=policies</code> in the embedded directory ' +
    '<strong>is</strong> this table. An <code>ldapmodify</code> of ' +
    '<code>xacmlPolicyDocument</code> changes what the PDP decides on the ' +
    'next request, and <code>xacmlEnabled</code> takes a policy out of the ' +
    'decision without deleting it.</p>' +
    '<p><strong>Exactly one policy is the root.</strong> A PDP evaluates one ' +
    'document and reaches the rest through <code>PolicyIdReference</code>, ' +
    'so the root is where evaluation starts. A repository with none decides ' +
    'nothing; one with two is refused rather than resolved arbitrarily.</p>' +
    '<p>A policy that does not type-check is shown in red here and was ' +
    'refused when it was written — XACML is statically typed, so such a ' +
    'policy is wrong for every request rather than for some.</p>',
    'What this page is') +
    '<table><tr><th>Name</th><th>PolicyId</th><th>Kind</th>' +
    '<th>Combining</th><th>State</th><th>Actions</th></tr>' + rows +
    '</table>' +
    (writable
      ? '<h2>Import ALFA</h2>' + admin.note(
          '<p>ALFA is the readable syntax for XACML. Paste one here and it ' +
          'is parsed, converted and STORED AS XACML XML — the repository ' +
          'holds one representation, because two would be two things to ' +
          'keep in step.</p>' +
          '<p>Every attribute must be DECLARED before it is used. That is ' +
          'ALFA\'s own rule and it is the most useful refusal in the ' +
          'parser: a typo in an attribute name is otherwise a policy that ' +
          'quietly matches nothing, which looks exactly like a policy that ' +
          'is working and denying you. Open any policy in the editor to see ' +
          'the shape.</p>',
          'What this accepts') +
        '<form method="post" action="/admin/xacml/policies">' +
        hidden('action', 'import-alfa') +
        '<p>Name ' + textField('name', 'imported', 24) + '</p>' +
        '<textarea name="alfa" rows="14" cols="88" ' +
        'placeholder="namespace example { ... }"></textarea>' +
        '<p><button type="submit">Import</button></p></form>'
      : '') +
    (templateForms
      ? '<h2>Create from a template</h2>' + admin.note(
          '<p>A template is the first twenty clicks of the editor already ' +
          'made: a working, valid, evaluable policy in a shape people ' +
          'actually write. The editor takes it from there.</p>' +
          '<p>RBAC asks <em>what role do you hold</em>; ABAC asks <em>what ' +
          'is true about you, this resource and right now</em>. The first is ' +
          'what most deployments have and the second is what they wanted — ' +
          'having both here, producing documents in the same language, is ' +
          'the clearest way to see what the difference costs in policy.</p>',
          'What a template is') + templateForms
      : '');

  admin.respond(req, res, json, 'XACML policies', '/admin/xacml/policies',
                body, '/admin/xacml');
  log.debug('Leaving the admin XACML policies page.');
});

// ---------------------------------------------------------------------------
// /admin/xacml/peps — THE REMOTE ENFORCEMENT POINTS (phase five).
//
// A LIST AND THREE CONTROLS, and it is worth saying what it is NOT before
// what it is: it is not a control panel for those processes. Nothing on this
// page reaches into another process. Disabling a PEP here stops this service
// NUDGING it and takes it off the distribution the console reports; it does
// not stop it enforcing, because a remote PEP holds its own copy of the engine
// and its own copy of the policy and will go on deciding with them. The page
// says that out loud on every disabled row, because a control labelled
// "disable" that leaves the thing running is the single most misleading thing
// a console can do.
//
// WHAT IT IS FOR is the question a distributed authorization deployment
// actually has, which is not "is the PDP up" but **"is everybody deciding with
// the same policy"**. Three columns answer it: whether the PEP is CURRENT (a
// comparison this service performs between the sync token it holds and the one
// the repository has now), whether it is STALE (nothing heard for
// `xacml.pepStaleAfterS`), and what happened to the last nudge. A PEP that is
// stale AND current is fine and idle; one that is fresh and not current is
// mid-pull; one that is stale and not current is the state worth seeing, and
// it is invisible from every other page in this console.
// ---------------------------------------------------------------------------
function pepsJson() {
  log.debug('Entering pepsJson().');
  const rows = peps.all().map(function (row) {
    const view = Object.assign({}, row);
    // THE NOTIFY URL'S PROBLEM IS COMPUTED RATHER THAN REMEMBERED, so that
    // changing `xacml.pepNotifyAllowedHosts` changes what this page says
    // about a PEP registered an hour ago. A stored verdict would have been
    // right when it was written and wrong from then on.
    view.notifyProblem = pepHttp.urlProblem(row.notifyUrl);
    return view;
  });
  const json = {
    enabled: config.value('xacml.remotePeps') !== false,
    syncToken: peps.syncToken(),
    staleAfterS: peps.staleAfterS(),
    requiresCertificate:
      config.value('xacml.pepRequireCertificate') !== false,
    notify: {
      on: pepHttp.notifyAllowed(),
      allowedHosts: pepHttp.allowedHosts(),
      allowInsecure: pepHttp.allowInsecure(),
      timeoutMs: pepHttp.timeoutMs()
    },
    peps: rows,
    current: rows.filter(function (row) {
      return row.current;
    }).length,
    stale: rows.filter(function (row) {
      return row.stale;
    }).length
  };
  log.debug('Leaving pepsJson(). ' + rows.length + ' registered PEP(s).');
  return json;
}

app.get('/admin/xacml/peps', function (req, res) {
  log.debug('Entering the admin XACML remote PEPs page.');
  const json = pepsJson();
  const writable = admin.mayWrite(req);

  const rows = json.peps.map(function (row) {
    const state = [];
    state.push(row.current
      ? '<span title="This PEP reported holding the repository digest this ' +
        'service has now.">current</span>'
      : '<strong title="The sync token this PEP last reported is not the ' +
        'one the repository has now. It converges on its next poll.">not ' +
        'current</strong>');
    state.push(row.stale
      ? '<strong title="Nothing has been heard from this PEP for longer ' +
        'than xacml.pepStaleAfterS. It may still be enforcing — this ' +
        'service cannot tell.">stale</strong>'
      : 'live');
    if (!row.enabled) {
      state.push('<em>not nudged</em>');
    }
    // THE AUTHENTICATION IS ON THE ROW AND NOT IN A FOOTNOTE. A registration
    // that proved nothing must not look the same as one that proved
    // something, which is the whole reason the flag is stored rather than
    // inferred from whether a subject happens to be present.
    const who = row.authenticated
      ? '<code>' + esc(row.certificateSubject) + '</code>'
      : '<strong>unauthenticated</strong><div class="sub">Registered with ' +
        'no client certificate, which xacml.pepRequireCertificate allowed. ' +
        'Nothing about this row is proven.</div>';
    const notify = row.notifyUrl
      ? '<code>' + esc(row.notifyUrl) + '</code>' +
        (row.notifyProblem
          ? '<div class="sub" style="color:#b00">' + esc(row.notifyProblem) +
            '</div>'
          : '') +
        (row.lastNotify
          ? '<div class="sub">' + esc(row.lastNotify) + '</div>'
          : '')
      : '<span class="sub">none — never nudged, and it converges on its ' +
        'own poll anyway</span>';
    const actions = writable
      ? '<form method="post" action="/admin/xacml/peps" ' +
        'style="display:inline">' +
        hidden('action', row.enabled ? 'disable-pep' : 'enable-pep') +
        hidden('name', row.name) +
        '<button type="submit">' + (row.enabled ? 'Stop nudging' : 'Nudge') +
        '</button></form> ' +
        '<form method="post" action="/admin/xacml/peps" ' +
        'style="display:inline">' +
        hidden('action', 'forget-pep') + hidden('name', row.name) +
        '<button type="submit">Forget</button></form>'
      : '<span class="sub">read-only</span>';
    return '<tr><td><code>' + esc(row.name) + '</code>' +
      (row.resource ? '<div class="sub">guards ' + esc(row.resource) +
                      '</div>' : '') +
      (row.version ? '<div class="sub">' + esc(row.version) + '</div>' : '') +
      '</td><td>' + who + '</td><td>' + state.join(', ') +
      '<div class="sub">last seen ' + esc(row.lastSeen || 'never') +
      '</div></td><td>' + esc(row.bias || 'not reported') +
      '</td><td>' + row.decisions + ' decided, ' + row.allowed +
      ' allowed, ' + row.refused + ' refused' +
      (row.undischargeable
        ? '<div class="sub">' + row.undischargeable + ' of those refused for ' +
          'an obligation it could not discharge</div>'
        : '') +
      '</td><td>' + notify + '</td><td>' + actions + '</td></tr>';
  }).join('') ||
    '<tr><td colspan="7">No remote Policy Enforcement Point has registered. ' +
    'That does not mean none is running: registering is not what lets a PEP ' +
    'enforce, and one that only ever pulls <code>/xacml/pep/policies</code> ' +
    'works perfectly and never appears here.</td></tr>';

  const body = admin.note(
    '<p>A <strong>remote</strong> Policy Enforcement Point runs in another ' +
    'process, holds its own copy of this engine, <strong>pulls</strong> the ' +
    'enabled policies from <code>/xacml/pep/policies</code> and decides ' +
    'locally. That is the point of having one: a PEP that asked this ' +
    'service per request would be <code>POST /xacml/pdp</code> with a ' +
    'network hop in front of every access decision.</p>' +
    '<p><strong>The pull is the contract.</strong> When the repository ' +
    'changes this service also POSTs a few bytes to each PEP that gave a ' +
    'notify URL, saying only that something changed. That is an ' +
    'optimisation over the polling interval and never a replacement for it ' +
    '&mdash; a nudge that is refused, blocked or never delivered costs one ' +
    'polling interval and nothing else, which is why the failure is worth ' +
    'showing here and not worth alarming about.</p>' +
    '<p><strong>Nothing on this page reaches into another process.</strong> ' +
    '&ldquo;Stop nudging&rdquo; stops this service dialling that PEP; it ' +
    'does not stop it enforcing, because it already holds the engine and ' +
    'the policy. &ldquo;Forget&rdquo; removes the row. Neither takes a ' +
    'running enforcement point out of service, and a console that implied ' +
    'otherwise would be worse than one with no controls at all.</p>' +
    '<p>Registering is <em>not</em> a permission. An unregistered PEP can ' +
    'pull and enforce exactly as well; what a row buys is this page and an ' +
    'address for the nudge.</p>',
    'What this page is') +
    '<p>The repository&rsquo;s sync token is <code>' +
    esc(json.syncToken) + '</code>. ' + json.current + ' of ' +
    json.peps.length + ' registered PEP(s) hold it; ' + json.stale +
    ' have not been heard from for ' + json.staleAfterS + 's.</p>' +
    (json.enabled ? ''
      : '<p><strong>Remote Policy Enforcement Points are turned off</strong> ' +
        '(<code>xacml.remotePeps</code>), so the three endpoints under ' +
        '<code>/xacml/pep</code> answer 501 and nothing here is nudged. The ' +
        'register below is untouched and comes back when it is turned on.</p>') +
    (json.notify.on ? ''
      : '<p><strong>The nudge is turned off</strong> ' +
        '(<code>xacml.pepNotify</code>), so nothing below is dialled. Every ' +
        'PEP still converges on its own poll &mdash; that is what makes this ' +
        'safe to turn off.</p>') +
    '<table><tr><th>PEP</th><th>Certificate</th><th>State</th>' +
    '<th>Its bias</th><th>What it enforced</th><th>Notify</th>' +
    '<th>Actions</th></tr>' + rows + '</table>' +
    admin.note(
      '<p>The decision counts are the PEP&rsquo;s own, reported by it, ' +
      'cumulative in its process. This service did not see one of those ' +
      'decisions &mdash; that is what a remote PEP is &mdash; so a PEP that ' +
      'restarts makes its counts go down, which is honest rather than ' +
      'broken.</p>' +
      '<p>The bias column is likewise <em>reported</em>. ' +
      '<code>xacml.pepBias</code> on the settings page governs the ' +
      '<em>embedded</em> PEP at <code>/xacml/protected</code> and nothing ' +
      'here; a control that appeared to set a remote PEP&rsquo;s bias would ' +
      'silently do nothing.</p>',
      'Where these numbers come from');

  admin.respond(req, res, json, 'Remote PEPs', '/admin/xacml/peps',
                body, '/admin/xacml');
  log.debug('Leaving the admin XACML remote PEPs page.');
});

// ---------------------------------------------------------------------------
// THE THREE ACTIONS BEHIND THAT PAGE.
//
// Named `-pep` rather than reusing `enable`, `disable` and `delete`, and that
// is not decoration: `combinedAction()` dispatches on the action name across
// all three of this family's POST endpoints, so a second `disable` would be
// ambiguous between a policy and a PEP — and the ambiguity would resolve
// silently in favour of whichever list was tested first.
// ---------------------------------------------------------------------------
const PEP_ACTIONS = ['enable-pep', 'disable-pep', 'forget-pep'];

function pepAction(body) {
  log.debug('Entering pepAction(). action=' + (body || {}).action);
  const action = String((body || {}).action || '');
  const name = String((body || {}).name || '');
  if (!name) {
    log.debug('Leaving pepAction(). No name.');
    return { ok: false, why: 'Which registered PEP? Send `name`.' };
  }
  const row = peps.read(name);
  if (!row) {
    log.debug('Leaving pepAction(). Not registered.');
    return { ok: false,
             why: 'No Policy Enforcement Point is registered as "' + name +
                  '". The register is ou=peps in the embedded directory and ' +
                  'GET /admin-api/xacml/peps lists it.' };
  }
  if (action === 'forget-pep') {
    const gone = peps.remove(name);
    audit.audit({ action: 'xacml.pep.forget', actor: '', protocol: 'XACML',
                  detail: 'Removed the register row for remote PEP "' +
                          name + '".' });
    log.debug('Leaving pepAction(). Removed.');
    return gone
      ? { ok: true,
          what: '"' + name + '" is no longer in the register. IT MAY STILL ' +
                'BE ENFORCING — this removed a row, not a process, and a PEP ' +
                'that pulls again simply registers again. What has changed ' +
                'is that this service will not nudge it in the meantime.' }
      : { ok: false, why: 'The directory would not remove it.' };
  }
  const on = action === 'enable-pep';
  const written = peps.setEnabled(name, on);
  if (!written) {
    log.debug('Leaving pepAction(). The directory refused it.');
    return { ok: false, why: 'The directory refused the change.' };
  }
  audit.audit({ action: 'xacml.pep.' + (on ? 'enable' : 'disable'), actor: '',
                protocol: 'XACML',
                detail: 'Remote PEP "' + name + '" is ' +
                        (on ? 'nudged again.' : 'no longer nudged.') });
  log.debug('Leaving pepAction(). ' + (on ? 'Enabled.' : 'Disabled.'));
  return { ok: true,
           what: on
             ? '"' + name + '" is nudged again when the repository changes.'
             : '"' + name + '" is no longer nudged. IT HAS NOT STOPPED ' +
               'ENFORCING: it holds its own copy of the engine and of the ' +
               'policy, and it will go on pulling and deciding. What this ' +
               'changed is that this service no longer dials it, so it now ' +
               'converges only on its own polling interval.' };
}

app.post('/admin/xacml/peps', function (req, res) {
  log.debug('Entering the admin XACML remote PEPs action.');
  const body = parseBody(req);
  if (!admin.mayWrite(req)) {
    admin.respondToAction(req, res, '/admin/xacml/peps',
                          { ok: false, why: 'This console session may read ' +
                                            'but not write.' });
    log.debug('Leaving the admin XACML remote PEPs action. Read-only.');
    return;
  }
  admin.respondToAction(req, res, '/admin/xacml/peps', pepAction(body));
  log.debug('Leaving the admin XACML remote PEPs action.');
});

// ---------------------------------------------------------------------------
// THE ACTIONS BEHIND THAT PAGE.
//
// The refusal sentence names every action, and the count comes from the list
// rather than being written out — `ssf/CLAUDE.md` records that this exact
// sentence is READ by two tests, and a handler that phrases it its own way
// turns those checks off with nothing failing.
// ---------------------------------------------------------------------------
const POLICY_ACTIONS = ['enable', 'disable', 'set-root', 'delete',
                        'create-from-template', 'import-alfa'];

function policyAction(body, req) {
  log.debug('Entering policyAction(). action=' + (body || {}).action);
  const action = String((body || {}).action || '');
  const name = String((body || {}).name || '');

  if (POLICY_ACTIONS.indexOf(action) < 0) {
    log.debug('Leaving policyAction(). Unknown action.');
    return { ok: false,
             why: 'Unknown action "' + action + '". The ' +
                  numberWord(POLICY_ACTIONS.length) + ' are: ' +
                  POLICY_ACTIONS.join(', ') + '.' };
  }

  if (action === 'import-alfa') {
    // ALFA IN, MODEL, XML OUT — which is the whole of what an ALFA compiler
    // is here, and is why this action is nine lines rather than a subsystem.
    // The document that gets STORED is XACML XML, because the store holds one
    // representation and a second would be a second thing to keep in step.
    let policy;
    try {
      policy = alfa.parse(String(body.alfa || ''));
    } catch (error) {
      log.debug('Leaving policyAction(). The ALFA would not parse.');
      return { ok: false, why: error.message };
    }
    const document = xml.writePolicy(policy);
    const isRoot = !store.root();
    const written = store.write(name || 'imported', document,
                                { isRoot: isRoot, enabled: true,
                                  description: policy.description });
    if (!written.ok) {
      log.debug('Leaving policyAction(). The store refused.');
      return written;
    }
    audit.audit({ action: 'xacml.policy.write', actor: '', protocol: 'XACML',
                  detail: 'Imported "' + (name || 'imported') +
                          '" from ALFA.' });
    log.debug('Leaving policyAction(). Imported.');
    return { ok: true,
             what: 'Imported "' + (name || 'imported') + '" as ' + policy.id +
                   '.' + (isRoot ? ' It is the root, because the repository ' +
                                   'had none.' : '') };
  }

  if (action === 'create-from-template') {
    const answers = {};
    Object.keys(body || {}).forEach(function (key) {
      if (key.indexOf('p_') === 0) {
        answers[key.slice(2)] = body[key];
      }
    });
    const built = templates.build(String(body.template || ''), answers,
                                  { name: name || body.template });
    if (!built.ok) {
      log.debug('Leaving policyAction(). The template refused.');
      return built;
    }
    const document = xml.writePolicy(built.policy);
    // The FIRST policy in an empty repository becomes the root, because a
    // repository with a policy and no root decides nothing and the person who
    // just created one plainly meant it to be used.
    const isRoot = !store.root();
    const written = store.write(name || built.template.id, document,
                                { isRoot: isRoot, enabled: true,
                                  description: built.policy.description });
    if (!written.ok) {
      log.debug('Leaving policyAction(). The store refused.');
      return written;
    }
    audit.audit({ action: 'xacml.policy.write', actor: '', protocol: 'XACML',
                  detail: 'Created "' + (name || built.template.id) +
                          '" from the ' + built.template.id + ' template.' });
    log.debug('Leaving policyAction(). Created.');
    return { ok: true,
             what: 'Created "' + (name || built.template.id) + '"' +
                   (isRoot ? ' and made it the root, because the repository ' +
                             'had none.' : '.') };
  }

  const existing = store.read(name);
  if (!existing) {
    log.debug('Leaving policyAction(). No such policy.');
    return { ok: false, why: 'There is no policy called "' + name + '".' };
  }

  if (action === 'delete') {
    store.remove(name);
    audit.audit({ action: 'xacml.policy.delete', actor: '',
                  protocol: 'XACML', detail: 'Deleted "' + name + '".' });
    log.debug('Leaving policyAction(). Deleted.');
    return { ok: true, what: 'Deleted "' + name + '".' +
             (existing.isRoot
               ? ' It was the ROOT, so this repository now decides nothing ' +
                 'until another policy is made the root.' : '') };
  }

  const enabled = action === 'disable' ? false
    : (action === 'enable' ? true : existing.enabled);
  // SET-ROOT CLEARS THE OTHER ONE FIRST. `store.write()` refuses a second
  // root, so promoting a policy has to demote the incumbent — and doing it in
  // this order means a failure leaves the repository with no root rather than
  // with two, which is the recoverable one of the two bad states.
  if (action === 'set-root') {
    const current = store.root();
    if (current && current.name !== name) {
      store.write(current.name, current.document,
                  { isRoot: false, enabled: current.enabled,
                    description: current.description });
    }
  }
  const written = store.write(name, existing.document, {
    isRoot: action === 'set-root' ? true : existing.isRoot,
    enabled: enabled,
    description: existing.description
  });
  if (!written.ok) {
    log.debug('Leaving policyAction(). The store refused.');
    return written;
  }
  audit.audit({ action: 'xacml.policy.write', actor: '', protocol: 'XACML',
                detail: action + ' on "' + name + '".' });
  log.debug('Leaving policyAction(). ' + action + '.');
  return { ok: true, what: action === 'set-root'
    ? '"' + name + '" is now the root policy.'
    : '"' + name + '" is now ' + (enabled ? 'enabled' : 'disabled') + '.' };
}

function numberWord(n) {
  const words = ['no', 'one', 'two', 'three', 'four', 'five', 'six', 'seven',
                 'eight', 'nine', 'ten'];
  return words[n] || String(n);
}

app.post('/admin/xacml/policies', function (req, res) {
  log.debug('Entering the admin XACML policies action endpoint.');
  const body = parseBody(req);
  if (!admin.mayWrite(req)) {
    admin.respondToAction(req, res, '/admin/xacml/policies',
                          { ok: false,
                            why: 'This console session holds Admin Read and ' +
                                 'not Admin Write.' });
    log.debug('Leaving the admin XACML policies action endpoint. Read-only.');
    return;
  }
  admin.respondToAction(req, res, '/admin/xacml/policies',
                        policyAction(body, req));
  log.debug('Leaving the admin XACML policies action endpoint.');
});


// ---------------------------------------------------------------------------
// /admin/xacml/editor — THE GUIDED EDITOR.
//
// One policy at a time, selected by `?policy=<name>`. The tree comes from
// `xacml_editor.js`; every row carries the menu of what may legally be added
// UNDER it, computed by the same process that will validate the result.
// ---------------------------------------------------------------------------
// The ALFA rendering, or a note saying why there is none. Never throws: this
// is a VIEW, and a policy whose ALFA cannot be produced is still a policy the
// page has to draw.
function alfaOf(policy) {
  log.debug('Entering alfaOf().');
  try {
    const text = alfa.write(policy);
    log.debug('Leaving alfaOf(). ' + text.length + ' bytes.');
    return text;
  } catch (error) {
    log.debug('Leaving alfaOf(). Could not be rendered.');
    return '// This policy cannot be rendered as ALFA: ' + error.message;
  }
}

function editorJson(name) {
  log.debug('Entering editorJson(). name=' + name);
  const rows = store.all();
  const chosen = name ? store.read(name) : (store.root() || rows[0] || null);
  if (!chosen) {
    log.debug('Leaving editorJson(). Nothing to edit.');
    return { policies: rows.map(function (one) { return one.name; }),
             policy: null };
  }
  let parsed = null;
  let problem = null;
  try {
    parsed = store.parseDocument(chosen.document);
  } catch (error) {
    problem = error.message;
  }
  const json = {
    policies: rows.map(function (one) { return one.name; }),
    policy: { name: chosen.name, enabled: chosen.enabled,
              isRoot: chosen.isRoot, policyId: parsed ? parsed.id : null,
              // WHICH IT IS, because a PolicySet and a Policy take different
              // children and a caller of /admin-api/xacml/editor that could
              // not tell them apart would have to guess which actions apply.
              kind: parsed ? (parsed.kind || 'Policy') : null,
              version: parsed ? (parsed.version || '1.0') : null,
              combiningAlgId: parsed ? parsed.combiningAlgId : null,
              description: parsed ? parsed.description : '' },
    problem: problem,
    tree: parsed ? editor.tree(parsed).map(function (row) {
      return { path: row.path, depth: row.depth, kind: row.kind,
               label: row.label, detail: row.detail,
               options: editor.optionsAt(parsed, row.path) };
    }) : [],
    problems: parsed ? validate.problemsIn(parsed) : [problem],
    // NOT a static type problem and deliberately kept out of that list: it is
    // a schema rule (section 5.14) that changes no decision this PDP makes,
    // so it is reported on its own rather than mixed in with the errors that
    // stop a policy loading. See `xacml_editor.js`'s `xpathVersionGaps()`.
    xpathVersionGaps: parsed ? editor.xpathVersionGaps(parsed) : [],
    document: chosen.document,
    // Emitted rather than stored. ALFA is a VIEW of the model here, not a
    // second copy of the policy — a stored ALFA text and a stored XML one
    // would be two documents that could disagree, which is the whole thing
    // this directory is arranged to avoid.
    alfa: parsed ? alfaOf(parsed) : null
  };
  log.debug('Leaving editorJson(). ' + json.tree.length + ' node(s).');
  return json;
}

// The inline edit form for one node, or '' where the node has no fields of its
// own. This is where the "next valid element" idea stops being a menu and
// becomes a form: a Match's function dropdown carries only the two-argument
// boolean predicates, and choosing one RESETS the datatype of both its value
// and its attribute, because a Match whose literal is a string and whose
// designator is an integer does not typecheck.
// A yes/no control that can say NO. It is a <select> and not a checkbox, and
// that is the one piece of markup on this page worth arguing about: an
// unchecked checkbox SENDS NOTHING, so a form carrying one could never turn
// MustBePresent off — the handler cannot tell "unchecked" from "this form does
// not edit that field", and it has to keep the value for the second case or
// every other form on the row would silently clear it. Two states that must
// both be sendable is exactly what a select is for.
function yesNo(name, value) {
  return select(name, [{ value: 'false', label: 'no' },
                       { value: 'true', label: 'yes' }],
                value ? 'true' : 'false');
}

function typeOptions() {
  return editor.typeMenu().map(function (one) {
    return { value: one.uri, label: one.label };
  });
}

function categoryOptions() {
  return editor.CATEGORY_MENU.map(function (one) {
    return { value: one.uri, label: one.label };
  });
}

function functionOptions() {
  return editor.applyFunctions().map(function (one) {
    return { value: one.uri,
             label: one.label + '  (' + one.arity + ' → ' + one.returns + ')' };
  });
}

// The inline edit form for one node, or '' where the node has no fields of its
// own. This is where the "next valid element" idea stops being a menu and
// becomes a form: a Match's function dropdown carries only the two-argument
// boolean predicates, and choosing one RESETS the datatype of both its value
// and its attribute, because a Match whose literal is a string and whose
// designator is an integer does not typecheck.
//
// SEVERAL ROWS CARRY MORE THAN ONE FORM, and they are separate on purpose
// rather than being one wide one. Every edit action here keeps whatever the
// submitted form did not mention, so a small form that changes a Match's
// function cannot disturb its attribute — and a person pressing Update under
// "Reference" can see that the function is not part of what they are changing.
function editFormFor(policy, row) {
  const located = editor.nodeAt(policy, row.path);
  if (!located) {
    return '';
  }
  const node = located.node;
  const head = '<form method="post" action="/admin/xacml/editor" ' +
    'class="inline">' + hidden('policy', policy.__editorName) +
    hidden('path', row.path);

  // A POLICY AND A POLICY SET TAKE THE SAME FORM AND NOT THE SAME MENU. The
  // rule-combining and policy-combining algorithm URIs differ by one segment
  // and a set carrying the rule spelling names an algorithm no combiner can
  // find, so the menu comes from `algorithmMenuFor()` — one function, used
  // here and by the handler that validates the answer, so the page cannot
  // offer something the edit then refuses.
  if (row.kind === 'policy' || row.kind === 'policySet') {
    const menu = editor.algorithmMenuFor(node);
    const chosen = menu.filter(function (one) {
      return one.uri === node.combiningAlgId;
    })[0] || {};
    return head + hidden('action', 'edit-policy') +
      (row.kind === 'policySet' ? 'PolicySetId ' : 'PolicyId ') +
      textField('id', node.id, 40) + ' ' +
      select('combiningAlgId', menu.map(function (one) {
        return { value: one.uri, label: one.label };
      }), node.combiningAlgId) +
      ' Version ' + textField('version', node.version || '1.0', 6) +
      '<br>Description ' + textField('description', node.description, 60) +
      '<br>MaxDelegationDepth ' +
      textField('maxDelegationDepth', node.maxDelegationDepth, 4) +
      ' XPathVersion ' + textField('xpathVersion', node.xpathVersion, 44) +
      ' <button type="submit">Update</button></form>' +
      '<div class="sub">' + esc(chosen.what || '') + '</div>' +
      '<div class="sub">Version is dot-separated numbers. ' +
      '<strong>MaxDelegationDepth is carried and not honoured</strong> — ' +
      'this PDP implements no administrative delegation, so the attribute ' +
      'survives a round trip and is read by nothing. XPathVersion belongs in ' +
      '&lt;' + (row.kind === 'policySet' ? 'PolicySetDefaults'
                                          : 'PolicyDefaults') + '&gt; and the ' +
      'specification asks for it whenever the document holds an ' +
      'AttributeSelector or an xpathExpression.</div>';
  }

  if (row.kind === 'reference') {
    return head + hidden('action', 'edit-reference') +
      esc(node.kind) + ' ' + textField('ref', node.ref, 44) +
      ' Version ' + textField('version', node.version, 8) +
      ' <button type="submit">Update</button></form>' +
      '<div class="sub">The id of a policy stored <em>separately</em> in this ' +
      'repository. It is resolved when a decision is made rather than when ' +
      'this document is loaded, so naming one that does not exist yet is ' +
      'allowed — an unresolved reference is reported on the decision. Leave ' +
      'Version empty for no constraint.</div>';
  }

  if (row.kind === 'rule') {
    return head + hidden('action', 'edit-rule') +
      select('effect', [{ value: 'Permit', label: 'Permit' },
                        { value: 'Deny', label: 'Deny' }], node.effect) +
      ' RuleId ' + textField('id', node.id, 36) +
      ' Description ' + textField('description', node.description, 40) +
      ' <button type="submit">Update</button></form>';
  }

  if (row.kind === 'variable') {
    const rename = head + hidden('action', 'edit-variable') +
      // FROM THE PATH rather than from the label: the label is prose this
      // page composes and a change to it would silently start renaming
      // variables to something with a description stuck on the end.
      'VariableId $' + textField('variableId',
                                 String(row.path).split('.').pop(), 12) +
      ' <button type="submit">Rename</button></form>' +
      '<div class="sub">Every <code>VariableReference</code> naming it is ' +
      'rewritten with it — a rename that left them behind would produce a ' +
      'document that does not load, and the write would be refused. The ' +
      'scope is <strong>this policy</strong>: a sibling policy in the same ' +
      'set cannot see it.</div>';
    // The definition IS an expression, so the expression's own form follows —
    // one row, two forms, rather than a variable you can rename and whose
    // value you cannot reach.
    return rename + expressionForm(policy, row, node);
  }

  if (row.kind === 'match') {
    const menu = editor.matchFunctions().map(function (one) {
      return { value: one.uri, label: one.label };
    });
    const reference = node.reference || {};
    const selector = reference.kind === 'selector';
    const test = head + hidden('action', 'edit-match') +
      select('matchId', menu, node.matchId) + ' ' +
      textField('value', node.value.lexical, 18) +
      ' <button type="submit">Update</button></form>' +
      '<div class="sub">The datatype follows the function — both sides ' +
      'become ' + esc(editor.shortType(node.value.type)) + '.</div>';
    const against = head + hidden('action', 'edit-match') +
      'against ' +
      select('referenceKind',
             [{ value: 'designator', label: 'an attribute' },
              { value: 'selector', label: 'an XPath selector' }],
             selector ? 'selector' : 'designator') + ' ' +
      (selector ? 'Path ' + textField('path', reference.path, 24)
                : 'AttributeId ' +
                  textField('attributeId', reference.attributeId, 24)) +
      ' in ' + select('category', categoryOptions(), reference.category) +
      (selector
         ? ' ContextSelectorId ' +
           textField('contextSelectorId', reference.contextSelectorId, 20)
         : ' Issuer ' + textField('issuer', reference.issuer, 16)) +
      ' must be present ' + yesNo('mustBePresent', reference.mustBePresent) +
      ' <button type="submit">Update</button></form>' +
      '<div class="sub">A <code>Match</code> holds an ' +
      '<code>AttributeDesignator</code> <em>or</em> an ' +
      '<code>AttributeSelector</code> and never both. Switching the kind ' +
      'redraws this form with the fields that kind takes. <strong>Must be ' +
      'present</strong> is the difference between an absent attribute being ' +
      'an empty bag and being Indeterminate — which is the difference ' +
      'between a policy that quietly does not apply and one that fails ' +
      'closed.</div>';
    return test + against;
  }

  if (row.kind === 'assignment') {
    return head + hidden('action', 'edit-assignment') +
      'AttributeId ' + textField('attributeId', node.attributeId, 30) +
      ' Category ' + select('category',
                            [{ value: '', label: '(none)' }]
                              .concat(categoryOptions()),
                            node.category || '') +
      ' Issuer ' + textField('issuer', node.issuer, 16) +
      ' <button type="submit">Update</button></form>' +
      '<div class="sub">What the PEP is handed alongside the obligation. ' +
      'Category and Issuer are optional and mean "this assignment is about ' +
      'that category" — leave them empty for a plain named value. The value ' +
      'itself is the expression below.</div>';
  }

  if (row.kind === 'obligation') {
    return head + hidden('action', 'edit-obligation') +
      textField('id', node.id, 40) + ' fires on ' +
      select('on', [{ value: 'Permit', label: 'Permit' },
                    { value: 'Deny', label: 'Deny' }], node.on) +
      ' <button type="submit">Update</button></form>';
  }

  if (row.kind === 'expression') {
    return expressionForm(policy, row, node);
  }
  return '';
}

// The five expression kinds that have fields of their own. Separate from
// `editFormFor()` because a VariableDefinition is an expression too and needs
// exactly these forms under its rename box — written twice they would drift,
// and the sixth kind (`variableRef`) is deliberately absent from both: its
// whole content is which variable it names, and that is chosen by REPLACING it
// from the Add menu, where the list of legal names is computed.
function expressionForm(policy, row, node) {
  const head = '<form method="post" action="/admin/xacml/editor" ' +
    'class="inline">' + hidden('policy', policy.__editorName) +
    hidden('path', row.path);

  if (node.kind === 'value') {
    const xpath = node.type === model.TYPE.XPATH_EXPRESSION;
    return head + hidden('action', 'edit-value') +
      textField('lexical', node.lexical, 24) + ' as ' +
      select('type', typeOptions(), node.type) +
      (xpath
         ? ' over ' + select('xpathCategory', categoryOptions(),
                             node.xpathCategory || model.CATEGORY.RESOURCE)
         : '') +
      ' <button type="submit">Update</button></form>' +
      (xpath
         ? '<div class="sub">An <code>xpathExpression</code> value is an ' +
           'XPath, and <code>XPathCategory</code> is the request category it ' +
           'runs against. The prefix bindings it uses travel with the ' +
           'document.</div>'
         : '');
  }

  if (node.kind === 'designator') {
    return head + hidden('action', 'edit-designator') +
      textField('attributeId', node.attributeId, 24) + ' in ' +
      select('category', categoryOptions(), node.category) + ' as ' +
      select('dataType', typeOptions(), node.dataType) +
      ' Issuer ' + textField('issuer', node.issuer, 16) +
      ' must be present ' + yesNo('mustBePresent', node.mustBePresent) +
      ' <button type="submit">Update</button></form>' +
      '<div class="sub">An empty <strong>Issuer</strong> means <em>any</em> ' +
      'issuer, which is not the same as an issuer whose name is the empty ' +
      'string — so clearing the box removes the attribute rather than ' +
      'writing one.</div>';
  }

  if (node.kind === 'selector') {
    const bindings = Object.keys(node.namespaces || {})
      .filter(function (prefix) {
        return prefix !== '';
      }).sort().map(function (prefix) {
        return '<code>' + esc(prefix) + '</code> → <code>' +
          esc(node.namespaces[prefix]) + '</code>';
      }).join(', ');
    return head + hidden('action', 'edit-selector') +
      'Path ' + textField('path', node.path, 30) + ' over ' +
      select('category', categoryOptions(), node.category) + ' as ' +
      select('dataType', typeOptions(), node.dataType) +
      '<br>ContextSelectorId ' +
      textField('contextSelectorId', node.contextSelectorId, 24) +
      ' must be present ' + yesNo('mustBePresent', node.mustBePresent) +
      ' &nbsp; namespace ' + textField('namespacePrefix', '', 6) + ' = ' +
      textField('namespaceUri', '', 30) +
      ' <button type="submit">Update</button></form>' +
      '<div class="sub">An <code>AttributeSelector</code> runs an XPath over ' +
      'the <code>&lt;Content&gt;</code> of a request category and returns a ' +
      '<strong>bag</strong>, exactly as a designator does — so most ' +
      'functions still need a <code>one-and-only</code> around it. ' +
      '<code>ContextSelectorId</code> names an attribute holding the node to ' +
      'start from; empty means the whole content.</div>' +
      '<div class="sub">Namespace bindings' +
      (bindings ? ': ' + bindings : ': none') + '. A prefix in the path ' +
      'means nothing without one, and they travel with the document. Type a ' +
      'prefix and a URI to add or change one; a prefix with an empty URI ' +
      'removes it.</div>';
  }

  if (node.kind === 'function') {
    return head + hidden('action', 'edit-function') +
      select('functionId', functionOptions(), node.functionId) +
      ' <button type="submit">Update</button></form>' +
      '<div class="sub">Named here as a <strong>value</strong> rather than ' +
      'applied — this is the first argument of a higher-order function such ' +
      'as <code>any-of</code>, <code>all-of</code> or <code>map</code>. ' +
      'Applying it instead is the commonest way to write one of those ' +
      'wrongly.</div>';
  }

  if (node.kind === 'apply') {
    return head + hidden('action', 'edit-apply') +
      select('functionId', functionOptions(), node.functionId) +
      ' Description ' + textField('description', node.description, 30) +
      ' <button type="submit">Update</button></form>';
  }

  if (node.kind === 'variableRef') {
    // POINTING IT AT ANOTHER VARIABLE IS A REPLACEMENT, and the same action
    // the Add menu uses: `set-expression-variable` puts a new
    // VariableReference where this one is. The menu is the variables THIS
    // POLICY defines — computed by the grammar rather than listed here, so a
    // reference to a variable belonging to a sibling policy cannot be chosen.
    const scope = editor.variablesInScope(policy, row.path);
    if (!scope.length) {
      return '<div class="sub">Names <code>$' + esc(node.variableId) +
        '</code>, which this policy does not define — so the document will ' +
        'not load. Add a variable definition to the policy, or replace this ' +
        'expression from the Add menu.</div>';
    }
    return head + hidden('action', 'set-expression-variable') +
      select('variableId', scope.map(function (one) {
        return { value: one.id, label: '$' + one.id + '  — ' + one.detail };
      }), node.variableId) +
      ' <button type="submit">Update</button></form>' +
      '<div class="sub">Only the variables <strong>this policy</strong> ' +
      'defines are offered. A VariableReference may not name one belonging ' +
      'to a sibling policy in the same set — section 5.24 — and the ' +
      'document would not load.</div>';
  }
  return '';
}

app.get('/admin/xacml/editor', function (req, res) {
  log.debug('Entering the admin XACML editor page.');
  const name = String(req.query.policy || '');
  const json = editorJson(name);
  const writable = admin.mayWrite(req);

  if (!json.policy) {
    admin.respond(req, res, json, 'Policy editor', '/admin/xacml/editor',
                  admin.warn('The repository is empty, so there is nothing ' +
                             'to edit. Create a policy from a template on ' +
                             'the <a href="/admin/xacml/policies">Policies' +
                             '</a> page.', 'Nothing to edit'),
                  '/admin/xacml');
    log.debug('Leaving the admin XACML editor page. Nothing to edit.');
    return;
  }

  let parsed = null;
  try {
    parsed = store.parseDocument(json.document);
    parsed.__editorName = json.policy.name;
  } catch (error) {
    parsed = null;
  }

  const chooser = '<form method="get" action="/admin/xacml/editor">' +
    'Policy ' + select('policy', json.policies.map(function (one) {
      return { value: one, label: one };
    }), json.policy.name) +
    ' <button type="submit">Open</button></form>';

  const liveWarning = json.policy.enabled && json.policy.isRoot
    ? admin.warn(
        'This policy is <strong>enabled and is the root</strong>, so it is ' +
        'what the PDP is deciding with <em>right now</em>. There is no draft ' +
        'state in this editor — the draft IS the stored policy, and every ' +
        'change below takes effect on the next request. That is deliberate: ' +
        'nothing can be lost by closing the browser, and there is no second ' +
        'copy that could disagree with the stored one. To work on it ' +
        'safely, disable it first on the ' +
        '<a href="/admin/xacml/policies">Policies</a> page.',
        'Editing is live')
    : '';

  const xpathGap = json.xpathVersionGaps.length
    ? admin.warn(
        'This document holds an <code>AttributeSelector</code> or an ' +
        '<code>xpathExpression</code> value, and ' +
        (json.xpathVersionGaps.length === 1
           ? '<code>' + esc(json.xpathVersionGaps[0]) + '</code> declares'
           : 'these declare') +
        ' no <code>XPathVersion</code>' +
        (json.xpathVersionGaps.length === 1 ? '' :
           ': <code>' + json.xpathVersionGaps.map(esc).join('</code>, <code>') +
           '</code>') +
        '. Section 5.14 says the element MUST be present when a policy uses ' +
        'one. <strong>Nothing here will refuse the document</strong> — this ' +
        'PDP has one XPath engine and does not choose a dialect by URI, so ' +
        'the decision is the same either way — but a schema validator ' +
        'elsewhere will refuse it, and this is the kind of defect that ' +
        'travels a long way before anybody finds out. The field is on the ' +
        'policy\'s own row above: ' +
        '<code>http://www.w3.org/TR/1999/REC-xpath-19991116</code> is what ' +
        'the conformance suite uses.',
        'No XPathVersion, and this document needs one')
    : '';

  const problems = json.problems.length
    ? admin.warn('<ul><li>' + json.problems.map(esc).join('</li><li>') +
                 '</li></ul><p>XACML is statically typed, so these are wrong ' +
                 'for every request rather than for some. The policy is ' +
                 'stored, but it will not load — the PDP reports ' +
                 'Indeterminate and names the first problem.</p>',
                 'This policy does not type-check')
    : '';

  const rows = parsed ? json.tree.map(function (row) {
    const adds = row.options.additions;
    const menu = writable && adds.length
      ? '<form method="post" action="/admin/xacml/editor" class="inline">' +
        hidden('policy', json.policy.name) + hidden('path', row.path) +
        select('action', adds.map(function (one) {
          return { value: one.action, label: one.label };
        }), '') +
        ' <button type="submit">Add</button></form>'
      : '';
    const remove = writable && row.options.removable
      ? '<form method="post" action="/admin/xacml/editor" class="inline">' +
        hidden('policy', json.policy.name) + hidden('path', row.path) +
        hidden('action', 'remove') +
        '<button type="submit">Remove</button></form>'
      : '';
    const helps = adds.filter(function (one) { return one.help; })
      .map(function (one) {
        return '<strong>' + esc(one.label) + '</strong> — ' + esc(one.help);
      }).join('<br>');
    return '<tr><td style="padding-left:' + (row.depth * 1.4) + 'rem">' +
      '<code>' + esc(row.label) + '</code>' +
      (row.detail ? '<div class="sub">' + esc(row.detail) + '</div>' : '') +
      (writable ? editFormFor(parsed, row) : '') +
      (helps ? '<div class="sub">' + helps + '</div>' : '') +
      '</td><td class="sub">' + esc(row.kind) + '</td>' +
      '<td>' + menu + ' ' + remove + '</td></tr>';
  }).join('') : '';

  const explain = admin.note(
    '<p>Each row is one element of the policy. The <strong>Add</strong> ' +
    'dropdown beside it offers <em>exactly</em> what XACML allows at that ' +
    'point and nothing else — a <code>Match</code> may only go inside an ' +
    'alternative, a <code>Condition</code> only on a rule and only one per ' +
    'rule, and the function list on a Match is the two-argument boolean ' +
    'predicates rather than all 275 functions.</p>' +
    '<p>Those menus are computed <strong>on the server</strong>, by the same ' +
    'code that validates the policy, against the real function library — so ' +
    'the editor cannot offer you something that will then be refused. This ' +
    'console runs under <code>script-src \'none\'</code> and has no ' +
    'JavaScript anywhere, which is why every control is a form and every ' +
    'choice is a round trip. The cost is real: a five-rule policy built by ' +
    'hand is perhaps forty of them. The templates on the ' +
    '<a href="/admin/xacml/policies">Policies</a> page are the first twenty ' +
    'already made.</p>' +
    '<p>Every element you add arrives <em>complete and valid</em> — a new ' +
    'rule has a Target and an Effect, a new Match has a function, a value ' +
    'and an attribute. An editor that produced half-built elements would ' +
    'hold a document that could not be saved, and a document that cannot be ' +
    'saved cannot be evaluated, which is when you most want to look at it.</p>' +
    '<p><strong>A <code>PolicySet</code> is edited here too, and it holds ' +
    'policies rather than rules.</strong> Its children may be a policy ' +
    'written inline, a nested set, or a <code>PolicyIdReference</code> ' +
    'naming a policy stored separately in this repository — which is how a ' +
    'PDP reaches more than one document: the root is evaluated and ' +
    'references are resolved when a decision is made. Its combining ' +
    'algorithm comes from the <em>policy</em>-combining list, which is a ' +
    'different set of URIs from the rule-combining one they are almost ' +
    'spelt the same as.</p>' +
    '<p>The rest of the syntax is here as well: ' +
    '<code>VariableDefinition</code> (named once, evaluated once per ' +
    'request, visible to its own policy only), <code>AttributeSelector</code>' +
    ' (an XPath over a request category\u2019s content, with the namespace ' +
    'bindings its prefixes need), <code>Function</code> as a value (what a ' +
    'higher-order function such as <code>any-of</code> or <code>map</code> ' +
    'takes as its first argument), the attribute assignments under an ' +
    'obligation, and the optional attributes — <code>Version</code>, ' +
    '<code>Issuer</code>, <code>MustBePresent</code>, ' +
    '<code>ContextSelectorId</code>, <code>XPathVersion</code> and ' +
    '<code>MaxDelegationDepth</code>.</p>' +
    '<p><strong>Two things are shown and cannot be added.</strong> The four ' +
    'combiner-parameter elements are drawn and removable, because a ' +
    'document may arrive carrying them and an element you cannot see is one ' +
    'you cannot delete — but there is no Add button, since section C of the ' +
    'specification says none of the twelve standard combining algorithms ' +
    'takes a parameter, and a control that provably changes no decision ' +
    'would be the first such control on this console. ' +
    '<code>&lt;PolicyIssuer&gt;</code> is not here at all: it belongs to the ' +
    'administrative delegation profile, which this PDP does not implement, ' +
    'so a document carrying one loses it here.</p>',
    'How this editor works');

  const body = chooser + liveWarning + problems + xpathGap + explain +
    '<table><tr><th>Element</th><th>Kind</th><th>Add / remove</th></tr>' +
    rows + '</table>' +
    '<details><summary>The same policy as ALFA</summary>' +
    admin.note(
      '<p>ALFA — the Abbreviated Language For Authorization — is the third ' +
      'rendering of this policy and the one worth reading. Forty lines of ' +
      'XML are eight of ALFA and the eight say the same thing.</p>' +
      '<p>It is an OASIS <strong>Committee Specification Draft</strong> ' +
      'rather than a ratified standard: there is no conformance suite for ' +
      'it and no second implementation to disagree with. So the contract ' +
      'here is the one that can actually be kept — <em>anything this emits, ' +
      'it reads back, and the policy decides identically either way</em> — ' +
      'and not that it reads every ALFA document in the world.</p>',
      'What ALFA is') +
    '<pre>' + esc(json.alfa || '') + '</pre></details>' +
    '<details><summary>The document as stored</summary><pre>' +
    esc(json.document) + '</pre></details>';

  admin.respond(req, res, json, 'Policy editor', '/admin/xacml/editor', body,
                '/admin/xacml');
  log.debug('Leaving the admin XACML editor page.');
});

// ---------------------------------------------------------------------------
// ONE EDIT: LOAD, APPLY, SERIALIZE, WRITE BACK.
//
// The write goes through `store.write()`, which validates — so an edit that
// would produce a policy that does not type-check is REFUSED and the stored
// document is unchanged. That is the property that makes a live editor
// tolerable: you cannot break the running policy by half-finishing an
// expression, because the half-finished version never lands.
// ---------------------------------------------------------------------------
function editorAction(body) {
  log.debug('Entering editorAction(). action=' + (body || {}).action);
  const name = String((body || {}).policy || '');
  const path = String((body || {}).path || '');
  const action = String((body || {}).action || '');
  const existing = store.read(name);
  if (!existing) {
    log.debug('Leaving editorAction(). No such policy.');
    return { ok: false, why: 'There is no policy called "' + name + '".' };
  }
  let policy;
  try {
    policy = store.parseDocument(existing.document);
  } catch (error) {
    log.debug('Leaving editorAction(). It will not load.');
    return { ok: false,
             why: 'That policy does not load, so it cannot be edited here: ' +
                  error.message };
  }
  // A DEEP COPY, because `applyEdit()` mutates and `parseDocument()` returns
  // the CACHED parse — editing that object in place would leave the cache
  // holding a policy that no longer matches the document it is keyed by, and
  // every later reader would get the edit whether or not it was saved.
  policy = xml.parsePolicy(xml.writePolicy(policy));
  const applied = editor.applyEdit(policy, path, action, body);
  if (!applied.ok) {
    log.debug('Leaving editorAction(). The edit was refused.');
    return applied;
  }
  const document = xml.writePolicy(policy);
  const written = store.write(name, document, {
    isRoot: existing.isRoot, enabled: existing.enabled,
    description: existing.description
  });
  if (!written.ok) {
    log.debug('Leaving editorAction(). The store refused.');
    return { ok: false,
             why: 'That edit would leave the policy invalid, so it was not ' +
                  'saved and the stored document is unchanged. ' +
                  written.why };
  }
  audit.audit({ action: 'xacml.policy.write', actor: '', protocol: 'XACML',
                detail: action + ' at "' + (path || '(root)') + '" in "' +
                        name + '".' });
  log.debug('Leaving editorAction(). ' + applied.what);
  return { ok: true, what: applied.what };
}

app.post('/admin/xacml/editor', function (req, res) {
  log.debug('Entering the admin XACML editor action endpoint.');
  const body = parseBody(req);
  if (!admin.mayWrite(req)) {
    admin.respondToAction(req, res, '/admin/xacml/editor',
                          { ok: false,
                            why: 'This console session holds Admin Read and ' +
                                 'not Admin Write.' });
    log.debug('Leaving the admin XACML editor action endpoint. Read-only.');
    return;
  }
  const result = editorAction(body);
  admin.respondToAction(req, res, '/admin/xacml/editor?policy=' +
                        encodeURIComponent(String(body.policy || '')), result);
  log.debug('Leaving the admin XACML editor action endpoint.');
});

// ---------------------------------------------------------------------------
// /admin/xacml/decide — ASK THE PDP.
//
// A form that builds a request and shows the answer. It exists because a
// policy you cannot try is a policy you are guessing about, and because the
// interesting part of a decision is never the decision alone — it is WHICH
// POLICIES applied, what the PIP found, and what the PEP would then do with
// it. All four are on this page.
// ---------------------------------------------------------------------------
function decideJson(query) {
  log.debug('Entering decideJson().');
  const subject = String((query || {}).subject || '');
  const action = String((query || {}).action || 'GET');
  const resource = String((query || {}).resource || '');
  if (!subject && !resource) {
    log.debug('Leaving decideJson(). Nothing asked.');
    return { asked: false };
  }
  // Required late so that requiring this file does not pull the routes module
  // in — `xacml.js` requires THIS file, so a require the other way at the top
  // would be a cycle, and node answers a cycle with a half-initialised module
  // whose exports are undefined rather than with an error.
  const xacml = require('./xacml');
  const categories = [
    { category: model.CATEGORY.ACCESS_SUBJECT, id: null, content: null,
      attributes: subject
        ? [{ attributeId: model.ATTRIBUTE.SUBJECT_ID, issuer: null,
             includeInResult: true,
             values: [{ type: model.TYPE.STRING, lexical: subject }] }]
        : [] },
    { category: model.CATEGORY.ACTION, id: null, content: null,
      attributes: [{ attributeId: model.ATTRIBUTE.ACTION_ID, issuer: null,
                     includeInResult: true,
                     values: [{ type: model.TYPE.STRING,
                                lexical: action }] }] },
    { category: model.CATEGORY.ENVIRONMENT, id: null, content: null,
      attributes: [] }
  ];
  if (resource) {
    categories.push({ category: model.CATEGORY.RESOURCE, id: null,
                      content: null,
                      attributes: [{ attributeId: model.ATTRIBUTE.RESOURCE_ID,
                                     issuer: null, includeInResult: true,
                                     values: [{ type: model.TYPE.ANYURI,
                                                lexical: resource }] }] });
  }
  const request = { returnPolicyIdList: true, combinedDecision: false,
                    categories: categories };
  const answer = xacml.decide(request);
  const enforcement = xacml.enforce(answer);
  log.debug('Leaving decideJson(). ' + answer.decision);
  return { asked: true, subject: subject, action: action,
           resource: resource || null,
           decision: answer.decision, status: answer.status,
           obligations: (answer.obligations || []).map(function (one) {
             return one.id;
           }),
           advice: (answer.advice || []).map(function (one) { return one.id; }),
           applicablePolicies: answer.policyIdentifiers || [],
           enforcement: { allowed: enforcement.allowed,
                          bias: enforcement.bias, why: enforcement.why } };
}

app.get('/admin/xacml/decide', function (req, res) {
  log.debug('Entering the admin XACML decide page.');
  const json = decideJson(req.query);
  const form = '<form method="get" action="/admin/xacml/decide">' +
    '<table><tr><td>Subject</td><td>' +
    textField('subject', json.subject || 'alice', 24) +
    '</td><td class="sub">A name, a DN or a certificate subject — all three ' +
    'resolve the way they do everywhere else here. The PIP reads this ' +
    'person&rsquo;s directory entry for any attribute the policy asks ' +
    'for.</td></tr>' +
    '<tr><td>Action</td><td>' + textField('action', json.action || 'GET', 24) +
    '</td><td class="sub">Becomes the standard action-id attribute.</td></tr>' +
    '<tr><td>Resource</td><td>' +
    textField('resource', json.resource || '', 40) +
    '</td><td class="sub">Optional. Becomes resource-id, as an ' +
    'anyURI.</td></tr></table>' +
    '<button type="submit">Ask the PDP</button></form>';

  let answer = '';
  if (json.asked) {
    const policies = json.applicablePolicies.length
      ? json.applicablePolicies.map(function (one) {
          return '<code>' + esc(one.id) + '</code>';
        }).join(', ')
      : '<em>none — nothing in the repository applied</em>';
    answer = '<h2>' + esc(json.decision) + '</h2>' +
      '<div class="tiles">' +
      admin.tile(json.decision, 'PDP decision') +
      admin.tile(json.enforcement.allowed ? 'allowed' : 'refused',
                 'the embedded PEP') +
      admin.tile(json.enforcement.bias, 'PEP bias') +
      '</div>' +
      '<p>' + esc(json.enforcement.why) + '</p>' +
      '<table><tr><th>Applicable policies</th><td>' + policies + '</td></tr>' +
      '<tr><th>Obligations</th><td>' +
      (json.obligations.length ? json.obligations.map(esc).join(', ')
                               : '<em>none</em>') + '</td></tr>' +
      '<tr><th>Advice</th><td>' +
      (json.advice.length ? json.advice.map(esc).join(', ')
                          : '<em>none</em>') + '</td></tr>' +
      '<tr><th>Status</th><td><code>' +
      esc((json.status || {}).code || '') + '</code>' +
      ((json.status || {}).message
        ? '<div class="sub">' + esc(json.status.message) + '</div>' : '') +
      '</td></tr></table>';
  }

  const explain = admin.note(
    '<p>The <strong>decision</strong> is the PDP&rsquo;s and the ' +
    '<strong>outcome</strong> is the PEP&rsquo;s, and this page shows both ' +
    'because they are not the same answer. A deny-biased PEP refuses an ' +
    'Indeterminate and a permit-biased one allows it; the two agree on every ' +
    'Permit and every Deny. When somebody says a policy &ldquo;is not ' +
    'working&rdquo;, it is nearly always because only one of these two was ' +
    'being looked at.</p>' +
    '<p>Nothing here asserts an attribute in the request beyond the subject, ' +
    'the action and the resource — so anything else the policy needs comes ' +
    'from the <strong>PIP</strong>, off that person&rsquo;s directory entry. ' +
    'That is what makes this a test of the whole path rather than of the ' +
    'engine alone.</p>',
    'What you are looking at');

  admin.respond(req, res, json, 'Try a decision', '/admin/xacml/decide',
                explain + form + answer, '/admin/xacml');
  log.debug('Leaving the admin XACML decide page.');
});


// ---------------------------------------------------------------------------
// FILL admin.js's TENTH SLOT, so that `/admin-api` can mirror these four pages
// without requiring this module — which it must not do, because it is 19 in
// the require order and this file is reached at 23c, and a require the wrong
// way would register every /xacml route ahead of the management API's own.
//
// THE ACTION IS ONE FUNCTION over both surfaces. `/admin/xacml/policies` and
// `/admin/xacml/editor` are two pages with two POST endpoints, and a
// management API that mirrored them as two resources would make a caller work
// out which one owns "enable" — so there is one action function, its names are
// the union, and it routes on the action itself. The console keeps two
// endpoints because a form posts back to the page it came from.
// ---------------------------------------------------------------------------
const EDITOR_ACTIONS = ['remove', 'add-rule', 'add-target-anyof', 'add-allof',
                        'add-match', 'edit-match', 'edit-rule', 'edit-policy',
                        'add-condition', 'set-expression-apply',
                        'set-expression-value', 'set-expression-designator',
                        'set-expression-selector', 'set-expression-function',
                        'set-expression-variable', 'add-argument',
                        'edit-apply', 'edit-value', 'edit-designator',
                        'edit-selector', 'edit-function',
                        'add-rule-obligation', 'add-policy-obligation',
                        'add-rule-advice', 'add-policy-advice',
                        'edit-obligation', 'add-assignment', 'edit-assignment',
                        'add-variable', 'edit-variable',
                        // THE POLICY SET'S FOUR. `add-policy` and `add-rule`
                        // are not two spellings of one move: a set holds
                        // policies and a policy holds rules, and the editor
                        // offered only the second until a policy set could be
                        // edited at all — which is how it came to accept a
                        // rule on a set, report it added, and write a document
                        // without it.
                        'add-policy', 'add-policyset',
                        'add-policy-reference', 'add-policyset-reference',
                        'edit-reference'];

function actionNames() {
  return POLICY_ACTIONS.concat(EDITOR_ACTIONS).concat(PEP_ACTIONS);
}

function combinedAction(body) {
  log.debug('Entering combinedAction(). action=' + (body || {}).action);
  const action = String((body || {}).action || '');
  if (POLICY_ACTIONS.indexOf(action) >= 0) {
    log.debug('Leaving combinedAction(). A repository action.');
    return policyAction(body, null);
  }
  if (EDITOR_ACTIONS.indexOf(action) >= 0) {
    log.debug('Leaving combinedAction(). An editor action.');
    return editorAction(body);
  }
  if (PEP_ACTIONS.indexOf(action) >= 0) {
    log.debug('Leaving combinedAction(). A remote PEP action.');
    return pepAction(body);
  }
  // The refusal sentence names every action and counts them, which is the
  // shape `ssf/CLAUDE.md` records two tests as READING — a handler that
  // phrased it its own way would turn both checks off with nothing failing.
  const all = actionNames();
  log.debug('Leaving combinedAction(). Unknown action.');
  return { ok: false,
           why: 'Unknown action "' + action + '". There are ' + all.length +
                ': ' + all.join(', ') + '.' };
}

if (typeof admin.setXacmlPages === 'function') {
  admin.setXacmlPages({
    overview: function () {
      return overviewJson();
    },
    policies: function () {
      return policiesJson();
    },
    editor: function (name) {
      return editorJson(name);
    },
    peps: function () {
      return pepsJson();
    },
    // THE SIXTH VIEW, AND IT WAS MISSING UNTIL PHASE FIVE. Rule 7 says every
    // console page gets an operation on /admin-api in the same commit, and
    // /admin/xacml/decide shipped in phase three without one — which
    // `tests/vendored/admin_api.js` catches by reading the console's own page
    // list rather than a list in the test, and which nothing noticed because
    // that job had not been run against this branch. The fix is here rather
    // than in a route of its own because the parity is about the VIEW.
    decide: function (query) {
      return decideJson(query);
    },
    action: combinedAction,
    actionNames: actionNames
  });
} else {
  log.warn('xacml: the admin console offers no setXacmlPages(), so ' +
           '/admin-api cannot mirror the five /admin/xacml pages. The pages ' +
           'themselves are unaffected.');
}

module.exports = {
  overviewJson: overviewJson,
  pepsJson: pepsJson,
  pepAction: pepAction,
  PEP_ACTIONS: PEP_ACTIONS,
  combinedAction: combinedAction,
  actionNames: actionNames,
  EDITOR_ACTIONS: EDITOR_ACTIONS,
  editorJson: editorJson,
  editorAction: editorAction,
  decideJson: decideJson,
  policiesJson: policiesJson,
  policyAction: policyAction,
  POLICY_ACTIONS: POLICY_ACTIONS
};
