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
const pip = require('./xacml_pip');

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
// THE ACTIONS BEHIND THAT PAGE.
//
// The refusal sentence names every action, and the count comes from the list
// rather than being written out — `ssf/CLAUDE.md` records that this exact
// sentence is READ by two tests, and a handler that phrases it its own way
// turns those checks off with nothing failing.
// ---------------------------------------------------------------------------
const POLICY_ACTIONS = ['enable', 'disable', 'set-root', 'delete',
                        'create-from-template'];

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
              combiningAlgId: parsed ? parsed.combiningAlgId : null,
              description: parsed ? parsed.description : '' },
    problem: problem,
    tree: parsed ? editor.tree(parsed).map(function (row) {
      return { path: row.path, depth: row.depth, kind: row.kind,
               label: row.label, detail: row.detail,
               options: editor.optionsAt(parsed, row.path) };
    }) : [],
    problems: parsed ? validate.problemsIn(parsed) : [problem],
    document: chosen.document
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
function editFormFor(policy, row) {
  const located = editor.nodeAt(policy, row.path);
  if (!located) {
    return '';
  }
  const node = located.node;
  const head = '<form method="post" action="/admin/xacml/editor" ' +
    'class="inline">' + hidden('policy', policy.__editorName) +
    hidden('path', row.path);

  if (row.kind === 'policy') {
    return head + hidden('action', 'edit-policy') +
      'PolicyId ' + textField('id', node.id, 44) + ' ' +
      select('combiningAlgId', editor.RULE_ALG_MENU.map(function (one) {
        return { value: one.uri, label: one.label };
      }), node.combiningAlgId) +
      ' <button type="submit">Update</button></form>' +
      '<div class="sub">' + esc((editor.RULE_ALG_MENU.filter(function (one) {
        return one.uri === node.combiningAlgId;
      })[0] || {}).what || '') + '</div>';
  }

  if (row.kind === 'rule') {
    return head + hidden('action', 'edit-rule') +
      select('effect', [{ value: 'Permit', label: 'Permit' },
                        { value: 'Deny', label: 'Deny' }], node.effect) +
      ' RuleId ' + textField('id', node.id, 40) +
      ' <button type="submit">Update</button></form>';
  }

  if (row.kind === 'match') {
    const menu = editor.matchFunctions().map(function (one) {
      return { value: one.uri, label: one.label };
    });
    return head + hidden('action', 'edit-match') +
      select('matchId', menu, node.matchId) + ' ' +
      textField('value', node.value.lexical, 18) + ' against ' +
      textField('attributeId', node.reference.attributeId, 24) + ' in ' +
      select('category', editor.CATEGORY_MENU.map(function (one) {
        return { value: one.uri, label: one.label };
      }), node.reference.category) +
      ' <button type="submit">Update</button></form>' +
      '<div class="sub">The datatype follows the function — both sides ' +
      'become ' + esc(editor.shortType(node.value.type)) + '.</div>';
  }

  if (row.kind === 'expression' && node.kind === 'value') {
    return head + hidden('action', 'edit-value') +
      textField('lexical', node.lexical, 24) + ' as ' +
      select('type', editor.typeMenu().map(function (one) {
        return { value: one.uri, label: one.label };
      }), node.type) +
      ' <button type="submit">Update</button></form>';
  }

  if (row.kind === 'expression' && node.kind === 'designator') {
    return head + hidden('action', 'edit-designator') +
      textField('attributeId', node.attributeId, 24) + ' in ' +
      select('category', editor.CATEGORY_MENU.map(function (one) {
        return { value: one.uri, label: one.label };
      }), node.category) + ' as ' +
      select('dataType', editor.typeMenu().map(function (one) {
        return { value: one.uri, label: one.label };
      }), node.dataType) +
      ' <label><input type="checkbox" name="mustBePresent" value="true"' +
      (node.mustBePresent ? ' checked' : '') + '> must be present</label>' +
      ' <button type="submit">Update</button></form>';
  }

  if (row.kind === 'expression' && node.kind === 'apply') {
    return head + hidden('action', 'edit-apply') +
      select('functionId', editor.applyFunctions().map(function (one) {
        return { value: one.uri,
                 label: one.label + '  (' + one.arity + ' → ' +
                        one.returns + ')' };
      }), node.functionId) +
      ' <button type="submit">Update</button></form>';
  }

  if (row.kind === 'obligation') {
    return head + hidden('action', 'edit-obligation') +
      textField('id', node.id, 40) + ' fires on ' +
      select('on', [{ value: 'Permit', label: 'Permit' },
                    { value: 'Deny', label: 'Deny' }], node.on) +
      ' <button type="submit">Update</button></form>';
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
    'saved cannot be evaluated, which is when you most want to look at it.</p>',
    'How this editor works');

  const body = chooser + liveWarning + problems + explain +
    '<table><tr><th>Element</th><th>Kind</th><th>Add / remove</th></tr>' +
    rows + '</table>' +
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
                        'set-expression-variable', 'add-argument',
                        'edit-apply', 'edit-value', 'edit-designator',
                        'add-rule-obligation', 'add-policy-obligation',
                        'add-rule-advice', 'add-policy-advice',
                        'edit-obligation', 'add-assignment'];

function actionNames() {
  return POLICY_ACTIONS.concat(EDITOR_ACTIONS);
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
    action: combinedAction,
    actionNames: actionNames
  });
} else {
  log.warn('xacml: the admin console offers no setXacmlPages(), so ' +
           '/admin-api cannot mirror the four /admin/xacml pages. The pages ' +
           'themselves are unaffected.');
}

module.exports = {
  overviewJson: overviewJson,
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
