'use strict';
//
// File: xacml_pep.js
//
// ===========================================================================
// PHASE FIVE: THE REMOTE PEP. THE PDP'S SIDE IN PROCESS, AND THE CONTAINER'S
// SIDE IN A CHILD.
//
// This file is in `tests/` rather than in the parent project's suite, and the
// line CLAUDE.md draws is "can it be asserted by driving the running service
// over HTTP?" Most of phase five CAN be — a registration, a pull, a heartbeat
// and a 304 are all HTTP — and those belong over there and are not here.
//
// WHAT IS HERE IS THE THREE THINGS THAT CANNOT BE, and each of them is about
// the SHAPE of this repository rather than about a running service:
//
//   1. **THE ENGINE LOADS AGAINST A THIRTY-LINE SHIM.** Every engine module's
//      header claims no I/O and no store, and every one of them requires
//      `../common/helpers`, which in the mock pulls in the config table, the
//      crypto module, the realm registry, node-forge and jsonwebtoken. The
//      claim is only falsifiable by loading the engine somewhere that HAS no
//      such helpers, which is what `xacml-pep/` is. No running service can be
//      asked this: over there the real helpers are loaded and the question
//      does not arise.
//   2. **THE DOCKERFILE'S COPY SET IS THE ENGINE.** `engine.js` names seven
//      modules and `xacml-pep/Dockerfile` copies seven files; a module added
//      to one and not the other produces an image that fails at runtime with
//      MODULE_NOT_FOUND. That is a comparison between two FILES and there is
//      no endpoint that could answer it. It is this repository's own version
//      of the standing obligation CLAUDE.md records the parent project having
//      for its `sts/` COPY set — enforced rather than remembered.
//   3. **THE TWO PEPs ENFORCE IDENTICALLY.** The mock's `enforce()` and the
//      container's are two implementations of section 7.2, deliberately not
//      shared (`pep.js` argues why), and the only way to know they agree is to
//      run both over the same decisions in one process.
//
// The sync token's three properties are here too, and they are the one thing
// on this list that is genuinely borderline — they could be driven over HTTP.
// They are here because each of them is a claim about what the token is
// COMPUTED FROM, and asserting that from outside means writing a policy,
// reading a token, editing the policy back and reading it again, four requests
// to make a claim that is one function call.
//
// ---------------------------------------------------------------------------
// WHY THE CONTAINER IS DRIVEN AS A CHILD PROCESS AND NEVER REQUIRED.
//
// `xacml-pep/engine.js` primes `require.cache` so that `../common/helpers`
// resolves to the container's shim — which is what makes a host run and an
// image run the same program. In THIS process that would be poison: `run.js`
// requires every test file into ONE process, so a shim installed here would be
// what `xacml_service.js` and `xacml_conformance.js` got when they ran next.
// So this file spawns `node` and asks the child. That is slower than a require
// and it is the only correct way to ask the question.
// ===========================================================================

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const PEP_DIR = path.join(ROOT, 'xacml-pep');

const registry = require('../xacml/xacml_pep_registry');
const pepHttp = require('../xacml/xacml_pep_http');
const store = require('../xacml/xacml_store');
const model = require('../xacml/xacml_model');

// ---------------------------------------------------------------------------
// A THROWAWAY ou=policies AND ou=peps, held here.
//
// The same shape `tests/xacml_service.js` uses: the two registers take their
// directory across a slot, so a test can fill that slot itself and get the
// whole store contract with no LDAP server, no port and no realm. What is
// asserted is the module's behaviour against a directory, which is the level
// this file is about.
//
// **THE ATTRIBUTE NAMES ARE LOWER-CASED ON THE WAY IN**, deliberately, because
// that is what the real directory does (RFC 4512) and it is the defect that
// cost a boot in phase two — a fake directory that preserved the case somebody
// wrote would make every reader here pass and the real one fail.
// ---------------------------------------------------------------------------
function fakeDirectory() {
  const entries = new Map();
  function lower(attributes) {
    const out = {};
    Object.keys(attributes || {}).forEach(function (key) {
      const value = attributes[key];
      out[key.toLowerCase()] = Array.isArray(value) ? value.slice(0)
                                                    : [String(value)];
    });
    return out;
  }
  return {
    entries: entries,
    allPeps: function () {
      return Array.from(entries.entries()).map(function (pair) {
        return { name: pair[0], dn: 'cn=' + pair[0] + ',ou=peps',
                 attributes: pair[1] };
      });
    },
    writePep: function (name, attributes) {
      entries.set(name, lower(attributes));
      return true;
    },
    deletePep: function (name) {
      return entries.delete(name);
    },
    certificateIdentity: function (certificate) {
      const subject = String((certificate || {}).subject || '');
      const cn = /CN=([^,]+)/i.exec(subject);
      return { dn: 'cn=' + (cn ? cn[1] : 'unknown') + ',ou=users',
               commonName: cn ? cn[1] : '', subject: subject };
    }
  };
}

function fakePolicyDirectory(documents) {
  return {
    allPolicies: function () {
      return Object.keys(documents).map(function (name) {
        return { name: name, dn: 'cn=' + name + ',ou=policies',
                 attributes: {
                   xacmlpolicyid: ['urn:test:' + name],
                   xacmlpolicydocument: [documents[name].document],
                   xacmlversion: ['1.0'],
                   xacmlkind: ['Policy'],
                   xacmlenabled: [documents[name].enabled === false
                     ? 'FALSE' : 'TRUE'],
                   xacmlisroot: [documents[name].isRoot ? 'TRUE' : 'FALSE']
                 } };
      });
    },
    writePolicy: function () { return true; },
    deletePolicy: function () { return true; }
  };
}

// The smallest policy that parses, typechecks and decides. Kept minimal on
// purpose: what this file asserts about a policy is that its BYTES move the
// sync token, not anything about what it decides.
function policyXml(id, effect) {
  return '<?xml version="1.0" encoding="UTF-8"?>' +
    '<Policy xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17" ' +
    'PolicyId="' + id + '" Version="1.0" ' +
    'RuleCombiningAlgId="urn:oasis:names:tc:xacml:3.0:rule-combining-' +
    'algorithm:deny-unless-permit">' +
    '<Target/>' +
    '<Rule RuleId="' + id + ':r" Effect="' + (effect || 'Permit') + '">' +
    '<Target/></Rule></Policy>';
}

// ---------------------------------------------------------------------------
// THE CONTAINER, ASKED IN A CHILD PROCESS. See the header for why never a
// require. The child prints one JSON line; anything it writes to stderr is
// reported as the failure, because a child that could not load the engine is
// exactly the case this test exists for and its stack is the information.
// ---------------------------------------------------------------------------
function askTheContainer(source) {
  const script = 'const out = (function () {\n' + source + '\n})();\n' +
                 'process.stdout.write("<<<" + JSON.stringify(out) + ">>>");';
  const text = execFileSync(process.execPath, ['-e', script], {
    cwd: PEP_DIR,
    encoding: 'utf8',
    // The engine's own bunyan lines would otherwise be interleaved with the
    // answer, so the shim is turned up only as far as errors.
    env: Object.assign({}, process.env, { PEP_LOG_LEVEL: 'error' }),
    stdio: ['ignore', 'pipe', 'pipe']
  });
  const found = /<<<([\s\S]*)>>>/.exec(text);
  if (!found) {
    throw new Error('the child produced no answer: ' + text.slice(0, 500));
  }
  return JSON.parse(found[1]);
}

async function run(t) {
  // -------------------------------------------------------------------------
  // 1. THE ENGINE LOADS IN A PROCESS WITH NO IDENTITY SERVICE IN IT.
  // -------------------------------------------------------------------------
  t.log.info('--- The engine, loaded against the shim ---');
  let loaded;
  try {
    loaded = askTheContainer(
      'const engine = require("./engine");\n' +
      'const helpers = require("./common/helpers");\n' +
      'return { modules: engine.MODULES,\n' +
      '         shimExports: Object.keys(helpers).sort(),\n' +
      '         decisions: Object.keys(engine.model.DECISION).length,\n' +
      '         functions: typeof engine.functions.lookup,\n' +
      // WHAT IS NOT IN THAT PROCESS. `require.cache` after the engine has
      // loaded is the whole dependency closure, and the mock's own modules
      // must not be in it — this is the assertion that the engine is a
      // library rather than a part of the identity service.
      '         mockModulesLoaded: Object.keys(require.cache).filter(' +
      'function (p) { return /(common\\/(config|crypto|realms|pq_jose|app)' +
      '|admin-ui|oauth-oidc|ldap)\\//.test(p); }) };');
  } catch (error) {
    t.bad('the container process could not load the XACML engine',
          error.message);
    loaded = null;
  }
  if (loaded) {
    t.equal(loaded.modules.length, 7,
            'the container carries the seven engine modules');
    t.check(loaded.functions === 'function',
            'the function library is usable in there',
            'engine.functions.lookup is ' + loaded.functions);
    t.check(loaded.decisions >= 7,
            'all seven decision values are present, not the four external ' +
            'ones', 'found ' + loaded.decisions);
    t.equal(loaded.shimExports.join(','), 'log,xmlEscape',
            'the helpers shim exports exactly what the engine needs and ' +
            'nothing else — a third export here is a dependency the engine ' +
            'grew, and the point of this container is that such a change is ' +
            'visible rather than silent');
    t.equal(loaded.mockModulesLoaded.length, 0,
            'NOT ONE of the mock\'s own modules is loaded in that process. ' +
            'This is what makes "the engine is a library with no I/O" a ' +
            'checked claim rather than a comment at the top of seven files');
  }

  // -------------------------------------------------------------------------
  // 2. THE ENGINE DECIDES THE SAME THERE AS IT DOES HERE.
  //
  // Loading is not enough: an engine that loaded and then answered differently
  // because something it needed was quietly absent would pass every assertion
  // above. So the child evaluates a policy and the answer is compared with
  // what the same policy decides in this process, where the REAL helpers are.
  // -------------------------------------------------------------------------
  t.log.info('--- The same policy, decided in both processes ---');
  const pdp = require('../xacml/xacml_pdp');
  const xml = require('../xacml/xacml_xml');
  const permit = policyXml('urn:test:agree', 'Permit');
  const here = pdp.evaluate(xml.parsePolicy(permit), {
    returnPolicyIdList: false, combinedDecision: false,
    categories: [{ category: model.CATEGORY.ACCESS_SUBJECT, id: null,
                   content: null, attributes: [] }]
  }, {});
  let there = null;
  try {
    there = askTheContainer(
      'const engine = require("./engine");\n' +
      'const policy = engine.xml.parsePolicy(' + JSON.stringify(permit) + ');\n' +
      'const answer = engine.pdp.evaluate(policy, { returnPolicyIdList: ' +
      'false, combinedDecision: false, categories: [{ category: ' +
      'engine.model.CATEGORY.ACCESS_SUBJECT, id: null, content: null, ' +
      'attributes: [] }] }, {});\n' +
      'return { decision: answer.decision, status: answer.status.code };');
  } catch (error) {
    t.bad('the container could not evaluate a policy', error.message);
  }
  if (there) {
    t.equal(there.decision, here.decision,
            'the container and this process reach the SAME decision on the ' +
            'same policy — which is what a remote PEP is FOR, and the one ' +
            'thing that would make the whole feature worthless if it were ' +
            'ever false');
    t.equal(there.status, here.status.code,
            'and the same status code with it');
  }

  // -------------------------------------------------------------------------
  // 3. THE DOCKERFILE'S COPY SET IS EXACTLY THE ENGINE.
  //
  // The obligation CLAUDE.md records the parent project having for its `sts/`
  // COPY set, enforced here instead of remembered. A module added to
  // `engine.js` and not to the Dockerfile is an image that dies at load with
  // MODULE_NOT_FOUND naming a file nobody edited.
  // -------------------------------------------------------------------------
  t.log.info('--- The Dockerfile against engine.js ---');
  const dockerfile = fs.readFileSync(path.join(PEP_DIR, 'Dockerfile'), 'utf8');
  const copied = [];
  dockerfile.split('\n').forEach(function (line) {
    const found = /^COPY\s+xacml\/(\S+)\s/.exec(line.trim());
    if (found) {
      copied.push(found[1]);
    }
  });
  const engineModules = askTheContainer(
    'return require("./engine").MODULES;');
  t.equal(copied.join(','), engineModules.join(','),
          'the Dockerfile copies exactly the modules engine.js loads, in the ' +
          'same order. A module in one and not the other is an image that ' +
          'dies at load naming a file nobody edited');
  engineModules.forEach(function (file) {
    t.check(fs.existsSync(path.join(ROOT, 'xacml', file)),
            'xacml/' + file + ' is in this tree to be copied');
  });
  // AND THE SHIM'S OWN DIRECTORY, because a Dockerfile that copied the engine
  // and forgot the shim would build, start, and fail on the first require of
  // an engine module — with a message about `../common/helpers` that names
  // neither this container nor the file that is missing.
  t.check(/^COPY\s+xacml-pep\/common\//m.test(dockerfile),
          'and the helpers shim is copied too — without it every engine ' +
          'module fails to resolve ../common/helpers in the image');

  // -------------------------------------------------------------------------
  // 4. THE TWO ENFORCEMENT IMPLEMENTATIONS AGREE.
  //
  // `xacml.js`'s `enforce()` and `xacml-pep/pep.js`'s are two readings of
  // section 7.2, deliberately not shared. Two readings is the point — it is
  // the same argument `tests/sts_dpop.js` makes for writing its own DPoP
  // client — and it is worth nothing unless somebody checks that they agree.
  //
  // The container's is asked in the child, over the SEVEN cases that matter:
  // the two the biases agree on, the two they differ on, and the obligation
  // rule on each side.
  // -------------------------------------------------------------------------
  t.log.info('--- Two implementations of section 7.2 ---');
  const xacml = require('../xacml/xacml');
  const config = require('../common/config');
  const CASES = [
    { decision: model.DECISION.PERMIT, obligations: [] },
    { decision: model.DECISION.DENY, obligations: [] },
    { decision: model.DECISION.INDETERMINATE, obligations: [] },
    { decision: model.DECISION.NOT_APPLICABLE, obligations: [] },
    { decision: model.DECISION.PERMIT,
      obligations: [{ id: 'urn:sts-mock:xacml:obligation:log',
                      assignments: [] }] },
    { decision: model.DECISION.PERMIT,
      obligations: [{ id: 'urn:test:cannot-do-this', assignments: [] }] },
    { decision: model.DECISION.DENY,
      obligations: [{ id: 'urn:test:cannot-do-this', assignments: [] }] }
  ];
  ['deny-biased', 'permit-biased'].forEach(function (bias) {
    const before = config.value('xacml.pepBias');
    config.setOverride('xacml.pepBias', bias);
    const mine = CASES.map(function (one) {
      const outcome = xacml.enforce(one);
      return outcome.allowed;
    });
    config.setOverride('xacml.pepBias', before);
    let theirs = null;
    try {
      theirs = askTheContainer(
        'process.env.PEP_BIAS = ' + JSON.stringify(bias) + ';\n' +
        'const pep = require("./pep");\n' +
        'return ' + JSON.stringify(CASES) + '.map(function (one) {\n' +
        '  return pep.enforce(one).allowed;\n' +
        '});');
    } catch (error) {
      t.bad('the container could not enforce (' + bias + ')', error.message);
    }
    if (theirs) {
      t.equal(JSON.stringify(theirs), JSON.stringify(mine),
              'the embedded PEP and the remote one enforce identically over ' +
              'all seven cases, ' + bias + ' — including the two the biases ' +
              'disagree about and the Permit carrying an obligation neither ' +
              'can discharge, which section 7.2 makes a REFUSAL');
    }
  });
  // AND THE ONE THAT MUST NOT AGREE: the same decision under two different
  // biases. Without this, two implementations that both returned `true`
  // unconditionally would pass every assertion above.
  const denyBiased = [];
  const permitBiased = [];
  const wasBias = config.value('xacml.pepBias');
  config.setOverride('xacml.pepBias', 'deny-biased');
  CASES.forEach(function (one) {
    denyBiased.push(xacml.enforce(one).allowed);
  });
  config.setOverride('xacml.pepBias', 'permit-biased');
  CASES.forEach(function (one) {
    permitBiased.push(xacml.enforce(one).allowed);
  });
  config.setOverride('xacml.pepBias', wasBias);
  t.check(JSON.stringify(denyBiased) !== JSON.stringify(permitBiased),
          'the two biases DISAGREE somewhere, so the agreement above is a ' +
          'real comparison rather than two functions that both say yes',
          'deny-biased ' + JSON.stringify(denyBiased) + ' vs permit-biased ' +
          JSON.stringify(permitBiased));

  // -------------------------------------------------------------------------
  // 5. THE SYNC TOKEN: WHAT IT IS COMPUTED FROM.
  // -------------------------------------------------------------------------
  t.log.info('--- The sync token ---');
  // WHAT WAS THERE, so it can be put back. `tests/CLAUDE.md` records the run
  // this rule was written from: `run.js` runs every file in ONE process, so
  // these slots are one reference shared by the whole suite, and restoring
  // `null` is correct only in a process where `ldap/ldap_server.js` was never
  // loaded — which is a fact about the file LIST rather than about this test.
  // A file added before this one that happens to require that module makes a
  // `null` restore fail inside somebody else's test.
  const storeWas = store.directoryInstalled();
  const registryWas = registry.directoryInstalled();

  const documents = {
    one: { document: policyXml('urn:test:one'), isRoot: true },
    two: { document: policyXml('urn:test:two') }
  };
  store.setDirectory(fakePolicyDirectory(documents));
  const first = registry.syncToken();
  t.check(!!first && first.length > 20, 'a repository has a sync token',
          first);

  // Unchanged content, unchanged token — which is what makes polling cheap.
  t.equal(registry.syncToken(), first,
          'asking twice gives the same token');

  // A DISABLED POLICY MOVES IT, because a disabled policy is not sent and the
  // PEP's copy is therefore wrong. This is the property a modification-time
  // stamp would get right and a naive "hash the whole container" would too —
  // it is here because the NEXT one is what tells those apart.
  documents.two.enabled = false;
  const afterDisable = registry.syncToken();
  t.check(afterDisable !== first,
          'DISABLING a policy moves the token — the PEP is not sent it, so ' +
          'the copy it holds is wrong', first + ' -> ' + afterDisable);

  // AND EDITING A POLICY BACK TO WHAT IT WAS DOES NOT. This is the assertion
  // that distinguishes a digest of the CONTENT from a modification stamp: a
  // stamp would move here and make every PEP re-pull a repository that had
  // not changed.
  documents.two.enabled = true;
  t.equal(registry.syncToken(), first,
          'and putting it back gives the ORIGINAL token — the token is a ' +
          'digest of what would be SENT, so a change and its reversal are ' +
          'not a change. A modification stamp would have moved here and had ' +
          'every PEP re-pull an identical repository');

  // THE ROOT IS IN THE DIGEST. Two repositories holding identical documents
  // and starting from different ones are different policy sets, and a PEP
  // holding the wrong root decides NotApplicable to everything.
  documents.one.isRoot = false;
  documents.two.isRoot = true;
  t.check(registry.syncToken() !== first,
          'moving the ROOT moves the token, even with every document ' +
          'unchanged — a PEP starting from the wrong one decides ' +
          'NotApplicable to everything');
  documents.one.isRoot = true;
  documents.two.isRoot = false;

  // -------------------------------------------------------------------------
  // 6. THE REGISTER.
  // -------------------------------------------------------------------------
  t.log.info('--- The register ---');
  const directory = fakeDirectory();
  registry.setDirectory(directory);
  t.equal(registry.all().length, 0, 'the register starts empty');

  const identity = directory.certificateIdentity({ subject: 'CN=pep-1,O=Ex' });
  const created = registry.register({
    name: identity.commonName, identity: identity.dn,
    certificateSubject: identity.subject, thumbprint: 'abc',
    authenticated: true, notifyUrl: 'https://pep.example.com/notify',
    bias: 'deny-biased', resource: 'https://pep/api', version: 'test'
  });
  t.check(created.ok && created.created, 'a PEP registers', created.why || '');
  t.equal(registry.all().length, 1, 'and is in the register');

  // A RE-REGISTRATION UPDATES rather than duplicating, because the name comes
  // from the certificate and one certificate is one entry.
  registry.heartbeat('pep-1', { decisions: 9, allowed: 5, refused: 4,
                                syncToken: registry.syncToken() });
  const again = registry.register({
    name: 'pep-1', identity: identity.dn,
    certificateSubject: identity.subject, thumbprint: 'abc',
    authenticated: true, notifyUrl: 'https://pep.example.com/notify'
  });
  t.check(again.ok && !again.created,
          're-registering UPDATES the row rather than adding a second one — ' +
          'one certificate is one entry');
  t.equal(registry.all().length, 1, 'still one row');
  t.equal(registry.read('pep-1').decisions, 9,
          'and the counters SURVIVE a re-registration: a PEP that restarts ' +
          'has not un-enforced anything, and zeroing them would make a ' +
          'restart loop look like a component that has never done any work');
  t.check(registry.read('pep-1').registeredAt === created.registeredAt ||
          !!registry.read('pep-1').registeredAt,
          'and it keeps its original registration date');

  // THE ONE THAT WOULD HAVE BEEN A SECURITY-SHAPED MISTAKE: a PEP an
  // administrator disabled must not be able to re-enable itself by
  // reconnecting.
  registry.setEnabled('pep-1', false);
  t.equal(registry.read('pep-1').enabled, false, 'a PEP can be disabled');
  // ASSERTED HERE AND NOT FIVE LINES DOWN, and the ordering is the whole
  // assertion. The row still HOLDS its notify URL at this point, so the only
  // thing that can make it unnotifiable is the disabled flag. A mutation round
  // caught this: the check used to sit after the re-registration below, which
  // clears the URL — so it read 0 whether or not `notifiable()` looked at
  // `enabled` at all, and a `notifiable()` that ignored the flag entirely
  // survived. A guard that passes for the wrong reason is not a guard.
  t.check(!!registry.read('pep-1').notifyUrl,
          'and it still holds its notify URL, which is what makes the next ' +
          'assertion about the DISABLED flag rather than about the URL');
  t.equal(registry.notifiable().length, 0,
          'a disabled PEP is not nudged');
  registry.register({ name: 'pep-1', identity: identity.dn,
                      certificateSubject: identity.subject,
                      authenticated: true });
  t.equal(registry.read('pep-1').enabled, false,
          'and RE-REGISTERING DOES NOT RE-ENABLE IT. A component an ' +
          'administrator stopped nudging must not be able to undo that by ' +
          'reconnecting');
  registry.setEnabled('pep-1', true);

  // AND IT IS STILL NOT NUDGED, because the re-registration above carried NO
  // notifyUrl and the write REPLACES rather than merges. That is the decision
  // `writePep()` documents, and this is the case it was made for: a PEP that
  // re-registers without a notify URL has stopped wanting to be nudged, and a
  // merge would go on dialling the address it used to have — a request this
  // service makes to somewhere nobody asked it to any more.
  t.equal(registry.notifiable().length, 0,
          're-enabling is NOT enough on its own: the re-registration above ' +
          'carried no notify URL and the write replaces rather than merges, ' +
          'so there is no longer an address to nudge. A merge here would go ' +
          'on dialling one nobody asked for any more');
  t.equal(registry.read('pep-1').notifyUrl, '',
          'and the URL really is gone from the row rather than merely being ' +
          'ignored');
  registry.register({ name: 'pep-1', identity: identity.dn,
                      certificateSubject: identity.subject,
                      authenticated: true,
                      notifyUrl: 'https://pep.example.com/notify' });
  t.equal(registry.notifiable().length, 1,
          'and giving one back makes it notifiable again');

  // CURRENT IS A COMPARISON, not a claim. A PEP reporting a token that is not
  // the repository's is not current however confidently it says otherwise.
  registry.heartbeat('pep-1', { syncToken: registry.syncToken() });
  t.equal(registry.read('pep-1').current, true,
          'a PEP holding the repository digest is CURRENT');
  registry.heartbeat('pep-1', { syncToken: 'something-else' });
  t.equal(registry.read('pep-1').current, false,
          'and one holding anything else is not — which is a comparison this ' +
          'service performs rather than a claim the PEP makes about itself');

  // A HEARTBEAT DOES NOT CREATE A ROW.
  const orphan = registry.heartbeat('never-registered', { decisions: 1 });
  t.check(!orphan.ok, 'a heartbeat from something unregistered is refused',
          orphan.why);
  t.check(/register/i.test(orphan.why || ''),
          'and the refusal names the registration endpoint rather than ' +
          'leaving the caller to guess');
  t.equal(registry.all().length, 1, 'and created nothing');

  // A FAILED NUDGE IS RECORDED AND DOES NOT MOVE `lastSeen`. That distinction
  // is the whole value of the field: a nudge that failed is evidence the PEP
  // is NOT reachable, and stamping liveness with it would make an unreachable
  // PEP look freshly seen.
  const seenBefore = registry.read('pep-1').lastSeen;
  // A MILLISECOND HAS TO PASS OR THIS PROVES NOTHING. `lastSeen` is an ISO
  // timestamp, so a recordNotify() that wrongly stamped it in the same
  // millisecond as the write above would write the SAME STRING and the
  // comparison below would pass. The mutation round found exactly that: a
  // recordNotify() that did stamp lastSeen survived. This is the same shape
  // as the fold-boundary case `ldif_codec.js` records — a round trip over
  // convenient data passes while proving nothing.
  await new Promise(function (resolve) {
    setTimeout(resolve, 5);
  });
  registry.recordNotify('pep-1', 'the PEP could not be reached');
  const row = registry.read('pep-1');
  t.check(/could not be reached/.test(row.lastNotify),
          'a failed nudge is recorded on the row — the only place it IS ' +
          'recorded, because it is invisible from the receiving end by ' +
          'definition');
  t.equal(row.lastSeen, seenBefore,
          'and it does NOT move lastSeen: a nudge that failed is evidence ' +
          'the PEP is unreachable, so letting it stamp liveness would make ' +
          'an unreachable PEP look freshly seen');

  // THE NAME IS FOLDED, because it comes off a certificate rather than being
  // typed and a subject may legitimately hold DN syntax.
  t.equal(registry.nameFrom('pep-1.example.com'), 'pep-1.example.com',
          'a hostname-shaped common name is kept as it is');
  t.equal(registry.nameFrom('a b,c=d'), 'a-b-c-d',
          'and DN syntax is folded rather than refused — those characters ' +
          'would otherwise have to be escaped by every reader separately');
  t.equal(registry.nameFrom('   '), '',
          'and something with nothing usable in it folds to nothing, which ' +
          'register() then refuses');

  // -------------------------------------------------------------------------
  // 7. THE NUDGE'S REFUSALS, WITHOUT DIALLING ANYTHING.
  //
  // `urlProblem()` is separate from the request precisely so this is possible
  // — and so that the console and the registration reply can tell a PEP its
  // notify URL will never be dialled without anything being dialled to find
  // out.
  // -------------------------------------------------------------------------
  t.log.info('--- The nudge, refused ---');
  const wasInsecure = config.value('xacml.pepNotifyAllowInsecure');
  const wasHosts = config.value('xacml.pepNotifyAllowedHosts');
  config.setOverride('xacml.pepNotifyAllowInsecure', false);
  config.setOverride('xacml.pepNotifyAllowedHosts', '');
  t.check(!!pepHttp.urlProblem('http://pep/notify'),
          'plain http is refused while pepNotifyAllowInsecure is off');
  t.equal(pepHttp.urlProblem('https://pep.example.com/notify'), null,
          'and https with an empty allowlist is fine — empty means ANY, ' +
          'which is the default and the one deliberate looseness here');
  config.setOverride('xacml.pepNotifyAllowedHosts', 'allowed.example.com');
  t.check(!!pepHttp.urlProblem('https://pep.example.com/notify'),
          'a host off the allowlist is refused');
  t.check(/pep\.example\.com/.test(
            pepHttp.urlProblem('https://pep.example.com/notify') || ''),
          'and the refusal names the host, because a list nobody can compare ' +
          'against is a list nobody can fix');
  t.equal(pepHttp.urlProblem('https://allowed.example.com/anything'), null,
          'while the allowed host is fine at ANY path — hosts rather than ' +
          'URLs, because a component legitimately moves its path and does ' +
          'not legitimately move to another host');
  config.setOverride('xacml.pepNotifyAllowInsecure', true);
  t.equal(pepHttp.urlProblem('http://allowed.example.com/notify'), null,
          'and http is allowed once the setting says so');
  t.check(!!pepHttp.urlProblem('ftp://allowed.example.com/notify'),
          'a scheme that is neither http nor https is refused whatever the ' +
          'settings say');
  config.setOverride('xacml.pepNotifyAllowInsecure', wasInsecure);
  config.setOverride('xacml.pepNotifyAllowedHosts', wasHosts);

  // TURNED OFF, NOTHING IS DIALLED, and the answer says so rather than
  // reporting a failure — a deployment with no egress is a supported one.
  const wasNotify = config.value('xacml.pepNotify');
  config.setOverride('xacml.pepNotify', false);
  const offAnswer = await pepHttp.nudge('https://pep.example.com/notify', '');
  t.check(!offAnswer.ok && /pepNotify is off/.test(offAnswer.why),
          'with xacml.pepNotify off nothing is dialled and the answer names ' +
          'the setting', offAnswer.why);
  t.check(/next poll/.test(offAnswer.why),
          'and says the PEP converges anyway, which is the whole reason this ' +
          'is safe to turn off');
  config.setOverride('xacml.pepNotify', wasNotify);

  // -------------------------------------------------------------------------
  // 8. THE STORE'S CHANGE OBSERVER IS WHAT FIRES A NUDGE.
  // -------------------------------------------------------------------------
  t.log.info('--- The change observer ---');
  const seen = [];
  store.setChangeObserver(function (what) {
    seen.push(what);
  });
  store.remove('one');
  t.equal(seen.length, 1,
          'removing a policy tells the observer — one choke point for every ' +
          'door that writes through this module');
  // AND AN OBSERVER THAT THROWS DOES NOT BREAK THE WRITE. A PEP that cannot
  // be nudged is not a reason for a policy save to fail.
  store.setChangeObserver(function () {
    throw new Error('the nudge dispatcher is broken');
  });
  let survived = true;
  try {
    store.remove('two');
  } catch (error) {
    survived = false;
  }
  t.check(survived,
          'an observer that THROWS does not take the write down with it — a ' +
          'PEP that cannot be nudged is not a reason for a policy save to ' +
          'fail');
  store.setChangeObserver(null);
  store.setDirectory(storeWas);
  registry.setDirectory(registryWas);

  assert.ok(true);
}

module.exports = {
  name: 'xacml_pep',
  describe: 'phase five: the engine loads against a thirty-line shim in the ' +
            'PEP container, the Dockerfile copies exactly what it loads, the ' +
            'two enforcement implementations agree, and the register and the ' +
            'sync token behave',
  run: run
};
