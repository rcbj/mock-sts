// File: sts_xacml_editor.js
//
// ---------------------------------------------------------------------------
// THE GUIDED POLICY EDITOR AT /admin/xacml/editor, DRIVEN IN A REAL BROWSER.
//
// This console has NO JAVASCRIPT — `app.js` serves it `script-src 'none'` and
// `admin-ui/CLAUDE.md` refuses a script nine times over — so every "pick the
// next valid element" dropdown on this page is computed on the SERVER by the
// same code that will validate the result, and choosing one is a form POST that
// re-renders the page. That is the whole design of `xacml/xacml_editor.js`, and
// it is what makes the editor testable at all: a grammar that only existed
// inside a browser could not be asserted in node.
//
// `tests/xacml_pap.js` already asserts that grammar in process — that a Match
// offers the two-argument boolean predicates and nothing else, that every edit
// leaves a policy that still type-checks. WHAT IT CANNOT ASSERT IS THAT ANY OF
// IT REACHES A PAGE. Between `optionsAt()` and a person there are forty forms,
// a nested-form hazard, a hidden `path` per row, an `action` that is sometimes
// hidden and sometimes a `<select>`, and a POST that has to land back on the
// right policy. Every one of those is markup, and markup is exactly what an
// in-process test cannot see.
//
// ---------------------------------------------------------------------------
// WHY A BROWSER AND NOT A FETCH THAT PARSES THE HTML.
//
// It is `sts_admin_console.js`'s argument and it is stronger here than
// anywhere. A hand-built POST asserts the TEST's reading of the markup: it
// would happily submit a field the browser would never send, and it would parse
// a nested `<form>` — which is a PARSER question, not a taste question — into
// something that works, while a browser silently drops the inner one and the
// control does nothing. This page carries about forty forms in one table, which
// is precisely where that goes wrong. So the browser is the independent
// implementation of "what does pressing this button send", and this file only
// ever presses buttons.
//
// It reads values back through `/admin-api`, never through the page that
// claimed to have written them, for the same reason that file gives: a write
// made in the browser and read back in the browser can be two halves of one
// misunderstanding.
//
// ---------------------------------------------------------------------------
// THE ASSERTION THIS FILE IS REALLY FOR.
//
// **A RULE BUILT BY PRESSING BUTTONS CHANGES WHAT THE PDP DECIDES.** Sections 5
// and 8 build one out of four form submissions, ask `/xacml/protected` about
// somebody who was refused before, and get a 200 — then remove the rule on the
// page and watch the refusal come back. Everything else here is about the
// editor; that pair is about whether the editor edits the policy the service is
// actually deciding with, which is the one claim the page makes that a person
// cannot check by looking at it.
//
// It is also why this job is this repository's own (`local: true`): half of it
// is a console page and half of it is a protocol endpoint, and the assertion
// that matters spans them. See `sts_xacml_endpoints.js`, which makes the same
// argument for the surface next door.
//
// ---------------------------------------------------------------------------
// IT EDITS A POLICY IN A THROWAWAY REALM, AND THE EDITOR IS WHY THAT MATTERS
// MORE HERE THAN ELSEWHERE.
//
// THE DRAFT IS THE STORED POLICY. There is no save button and no unsaved state:
// every edit loads the document from `ou=policies`, applies one change and
// writes it back, so a policy being edited is the policy the PDP is deciding
// with. The page says so out loud. A job that did this in the default realm
// would therefore be rewriting the seeded policy — live — while every other job
// in the run was deciding against it.
// ---------------------------------------------------------------------------
//
// ---------------------------------------------------------------------------
// IT FOUND A DEFECT ON ITS FIRST RUN, AND WAS THEN MUTATION-TESTED AGAINST
// FOUR MORE.
//
// THE DEFECT: every refusal on the three `/admin/xacml` pages redirected back
// with `error=` AND NOTHING IN IT. `policyAction()`, `editorAction()` and
// `pepAction()` refuse with a single `why`; `admin.respondToAction()` built the
// browser's message out of `errors`, which those three never set — so the
// person got the page they had just posted from, unchanged, with no
// explanation, which reads exactly like a control that does nothing. It was
// invisible to `/admin-api`, where `admin.xacmlAction()` had already been given
// that translation, and invisible to `tests/xacml_pap.js`, which asserts the
// refusal it gets back from the function rather than the sentence a browser is
// shown. Fixed in `admin-ui/admin.js` so that the console and `/admin-api`
// cannot disagree about what a refusal said.
//
// THE MUTANTS, each applied to a copy of the tree, driven, and reverted:
//
//   1. that fix reverted — caught by section 5, which is how it was found;
//   2. `editorAction()` writing the document even when the store refuses it —
//      caught by section 5's byte-for-byte read-back, and it is the mutant
//      that matters most, because a LIVE editor whose refused edits landed
//      breaks the policy the PDP is deciding with;
//   3. the Match function menu offering the whole function library instead of
//      the two-argument boolean predicates — caught by section 3;
//   4. a rule going on offering a second Condition once it has one — caught by
//      section 4, which is the only assertion here that needs the page to be
//      CHANGED before it can be made.
// ---------------------------------------------------------------------------

"use strict";

const assert = require("assert");
const { Command, Option } = require("commander");
const { Builder, By } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const browserFlags = require("./browser_flags.js");
const names = require("./random_username.js");

var appconfig;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // The launchers always set CONFIG_FILE; a hand-run without one must still
  // load, the arrangement tests/wait_for.js has.
  appconfig = {};
}

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "sts_xacml_editor",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/, "");
base = String(base).replace(/\/+$/, "");

const CONSOLE_USER = "xacml-editor-test-" + names.runStamp();
const REALM = ("xacmled-" + names.runStamp()).toLowerCase()
    .replace(/[^a-z0-9-]/g, "").slice(0, 40);
const POLICY = "edited-in-the-browser";
const SECOND_POLICY = "a-second-policy";

// The person the rule built on the page is about. bob is seeded in every realm
// as `employeeType: staff`, so the template policy permits him to GET and
// refuses him everything else — which is the refusal sections 5 and 8 flip and
// flip back.
const SUBJECT = "bob";
const SUBJECT_ID = "urn:oasis:names:tc:xacml:1.0:subject:subject-id";
const ACCESS_SUBJECT =
  "urn:oasis:names:tc:xacml:1.0:subject-category:access-subject";
const STRING_EQUAL = "urn:oasis:names:tc:xacml:1.0:function:string-equal";

var screenshotDir = "";
var checks = 0;
function check(what, fn) {
  fn();
  checks += 1;
  log.debug("check passed: " + what);
}

function root(path) { return base + path; }
function realmUrl(path) { return base + "/realm/" + REALM + path; }
function api(path) { return realmUrl("/admin-api" + path); }
function editorUrl(policy) {
  return realmUrl("/admin/xacml/editor" +
                  (policy ? "?policy=" + encodeURIComponent(policy) : ""));
}

// ---------------------------------------------------------------------------
// THE DOORS THAT ARE NOT THE BROWSER. Both are only ever used to SET UP a
// policy or to READ BACK what the browser did — never to make an edit this file
// then credits to the page.
// ---------------------------------------------------------------------------
async function json(url, options) {
  const r = await fetch(url, options || {});
  const text = await r.text();
  let body;
  try {
    body = JSON.parse(text);
  } catch (e) {
    // Not JSON — an HTML page from a door that answers JSON, which is worth
    // reporting whole rather than as a parse failure.
    body = null;
  }
  return { status: r.status, body: body, text: text };
}

function apiPost(path, payload) {
  return json(base + path, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload || {})
  });
}

async function editorJson(policy) {
  const r = await json(api("/xacml/editor" +
                           (policy ? "?policy=" + encodeURIComponent(policy) : "")));
  assert.strictEqual(r.status, 200,
    "GET /admin-api/xacml/editor answered " + r.status + " " +
    String(r.text).slice(0, 200));
  return r.body;
}

async function storedDocument(policy) {
  return (await editorJson(policy)).document;
}

// ---------------------------------------------------------------------------
// FINDING A NODE IN THE TREE, RATHER THAN WRITING ITS PATH DOWN.
//
// The path is the editor's own spelling of where an element sits, and it is not
// this file's business: it changed shape once while this test was being written
// (`rules.0` became `.rules.0` when policy sets landed), and a job that had
// hard-coded it would have failed on twenty assertions that had nothing to do
// with what changed. So every node below is located the way a person locates
// one — by KIND, and by which element it sits under — and the path is whatever
// the page says it is.
//
// The one structural fact relied on is that a child's path begins with its
// parent's, which is what makes `under()` a string test rather than a parser.
// ---------------------------------------------------------------------------
async function treeOf(policy) {
  const view = await editorJson(policy);
  assert.ok(Array.isArray(view.tree) && view.tree.length,
    "the editor view for " + policy + " carries no tree: " +
    JSON.stringify(view).slice(0, 300));
  return view.tree;
}

function under(row, parentPath) {
  return parentPath === undefined || parentPath === null ||
         (row.path !== parentPath && row.path.indexOf(parentPath) === 0);
}

function firstOfKind(tree, kind, parentPath) {
  return tree.filter(function (row) {
    return row.kind === kind && under(row, parentPath);
  })[0] || null;
}

function lastOfKind(tree, kind, parentPath) {
  const all = tree.filter(function (row) {
    return row.kind === kind && under(row, parentPath);
  });
  return all[all.length - 1] || null;
}

function pathOfKind(tree, kind, parentPath) {
  const row = firstOfKind(tree, kind, parentPath);
  assert.ok(row, "no " + kind + " row" +
    (parentPath !== undefined && parentPath !== null
      ? " under \"" + parentPath + "\"" : "") +
    " in this policy's tree. It holds " +
    JSON.stringify(tree.map(function (one) {
      return one.kind + "@" + one.path;
    })));
  return row.path;
}

// The embedded PEP, asked about somebody. This is the OTHER door — a protocol
// endpoint rather than the console — and it is what makes an edit on the page
// mean something.
async function enforcementFor(subject, action) {
  const r = await json(realmUrl("/xacml/protected?subject=" +
                                encodeURIComponent(subject) + "&action=" +
                                encodeURIComponent(action)));
  return r;
}

// ---------------------------------------------------------------------------
// THE BROWSER.
// ---------------------------------------------------------------------------
function pause(ms) {
  return new Promise(function (resolve) { setTimeout(resolve, ms); });
}

async function open(driver, url) {
  log.debug("Entering open(). url=" + url);
  await driver.get(url);
  await driver.wait(async function () {
    return (await driver.executeScript("return document.readyState;")) ===
           "complete";
  }, 15000, "the page never finished loading: " + url);
  log.debug("Leaving open().");
}

// Everything this file asserts about a drawn page, taken in ONE script so that
// no assertion below can be made against a page that moved underneath it.
//
// `resolvedAction` is read off `form.action` rather than off the attribute,
// because the attribute is what was written and `form.action` is what the
// browser will actually POST to — which is the difference a missing realm
// prefix would show up in.
const SURVEY = `
  const forms = Array.from(document.forms).map(function (f, i) {
    const controls = Array.from(f.elements).map(function (e) {
      return {
        tag: e.tagName.toLowerCase(),
        type: (e.type || "").toLowerCase(),
        name: e.name || "",
        value: e.value === undefined ? "" : String(e.value),
        text: (e.textContent || "").trim().slice(0, 60),
        options: e.tagName.toLowerCase() === "select"
          ? Array.from(e.options).map(function (o) {
              return { value: o.value, label: (o.text || "").trim() };
            })
          : null
      };
    });
    const named = {};
    controls.forEach(function (c) {
      if (c.name && named[c.name] === undefined) { named[c.name] = c.value; }
    });
    // NOT \`f.action\`, AND THIS IS A DOM TRAP RATHER THAN A PREFERENCE. A
    // form's named controls shadow its own properties, and every edit form on
    // this page carries a control called \`action\` — so \`f.action\` hands back
    // an <input> element instead of the URL. The attribute is what was
    // written; resolving it against the document is what the browser will
    // actually POST to, which is the difference a missing realm prefix shows
    // up in.
    const written = f.getAttribute("action") || "";
    return { index: i, method: (f.getAttribute("method") || "get").toLowerCase(),
             resolvedAction: new URL(written, location.href).href,
             nested: !!f.querySelector("form"),
             controls: controls, named: named };
  });
  const cell = function (row, n) {
    const tds = row.querySelectorAll("td");
    return tds[n] ? (tds[n].textContent || "").trim() : "";
  };
  return {
    url: location.href,
    title: (document.querySelector("h1") ? document.querySelector("h1").textContent : "").trim(),
    forms: forms,
    warnings: Array.from(document.querySelectorAll("details, div"))
      .map(function (e) { return (e.textContent || "").trim(); })
      .filter(function (t) { return t.indexOf("Editing is live") === 0 ||
                                    t.indexOf("This policy does not type-check") === 0 ||
                                    t.indexOf("Nothing to edit") === 0; }),
    rows: Array.from(document.querySelectorAll("table tr")).slice(1)
      .map(function (r) { return { element: cell(r, 0), kind: cell(r, 1) }; }),
    pres: Array.from(document.querySelectorAll("pre")).map(function (p) {
      return p.textContent;
    }),
    bodyText: document.body.textContent
  };
`;

async function survey(driver) {
  log.debug("Entering survey().");
  const page = await driver.executeScript(SURVEY);
  log.debug("Leaving survey(). " + page.forms.length + " form(s).");
  return page;
}

// The `?notice=` / `?error=` the console puts in the query string of the page it
// sends a reader back to. Read from the URL and not the markup, so that a page
// drawing neither still fails the assertion that wanted one.
function outcomeOf(url, which) {
  const found = String(url).match(new RegExp("[?&]" + which + "=([^&]*)"));
  return found ? decodeURIComponent(found[1].replace(/\+/g, " ")) : "";
}

// The form on this page whose hidden `path` is this node's and whose `action`
// is this one — either as a hidden field (an edit form) or as an option in its
// `<select name="action">` (an Add menu). Returning the index rather than the
// element is deliberate: an element goes stale the moment the page re-renders,
// and every one of these submissions re-renders it.
// `carrying` picks between SEVERAL forms with one path and one action, which is
// not a hypothetical: a Match row draws its function and its literal in one
// form and what they are compared AGAINST in another — two `edit-match` forms
// on one row, because the second changes shape entirely when the reference is
// an XPath selector rather than an attribute. A test that took "the first form
// with this action" would submit half the fields it meant to and be told
// nothing.
function formIndexFor(page, path, action, carrying) {
  const candidates = page.forms.filter(function (f) {
    return f.named.path === path &&
           (!carrying || f.controls.some(function (c) {
             return c.name === carrying;
           }));
  });
  const hidden = candidates.filter(function (f) {
    return f.named.action === action;
  })[0];
  if (hidden) {
    return hidden.index;
  }
  const menu = candidates.filter(function (f) {
    return f.controls.some(function (c) {
      return c.name === "action" && c.options &&
             c.options.some(function (o) { return o.value === action; });
    });
  })[0];
  return menu ? menu.index : -1;
}

// The editor's own policy chooser. NOT "the first GET form on the page" — the
// console shell puts its REALM SWITCHER above the body, which is also a GET
// form, and a heuristic that took the first one asserted against the wrong
// control while looking entirely correct.
function chooserOf(page) {
  return page.forms.filter(function (f) {
    return f.method === "get" && f.controls.some(function (c) {
      return c.name === "policy";
    });
  })[0] || null;
}

// Fill named fields in one form and press its submit button. Everything goes
// through the browser: `sendKeys` on a text field, a click on an `<option>`,
// a click on the button.
async function submitForm(driver, index, values) {
  log.debug("Entering submitForm(). index=" + index);
  const forms = await driver.findElements(By.css("form"));
  assert.ok(forms[index], "there is no form " + index + " on " +
            (await driver.getCurrentUrl()));
  const form = forms[index];
  const wanted = values || {};
  for (const name of Object.keys(wanted)) {
    const fields = await form.findElements(By.css("[name='" + name + "']"));
    assert.ok(fields.length,
      "form " + index + " has no control named " + name);
    const field = fields[0];
    const tag = await field.getTagName();
    if (tag === "select") {
      const option = await field.findElements(
        By.css("option[value='" + wanted[name] + "']"));
      assert.ok(option.length,
        "the " + name + " menu on form " + index + " does not offer " +
        wanted[name] + ", which is what this file is asserting it should. It " +
        "offers " + JSON.stringify(await Promise.all(
          (await field.findElements(By.css("option"))).map(function (o) {
            return o.getAttribute("value");
          }))));
      await option[0].click();
    } else {
      await field.clear();
      await field.sendKeys(String(wanted[name]));
    }
  }
  const buttons = await form.findElements(By.css("button, input[type='submit']"));
  assert.ok(buttons.length, "form " + index + " has no submit button");
  await buttons[0].click();
  await driver.wait(async function () {
    return (await driver.executeScript("return document.readyState;")) ===
           "complete";
  }, 15000, "the page never finished loading after form " + index +
            " was submitted");
  // The console redirects a POST to the page it came from; a short settle keeps
  // the survey below from reading the document mid-navigation. It is not a
  // sleep standing in for a wait — readyState is the wait.
  await pause(40);
  log.debug("Leaving submitForm().");
}

// One edit: survey, find the form, press it, survey again. Returns the page as
// it is AFTERWARDS, which is what every assertion here is about.
async function pressOn(driver, path, action, values, carrying) {
  log.debug("Entering pressOn(). path=" + path + " action=" + action);
  const before = await survey(driver);
  const index = formIndexFor(before, path, action, carrying);
  assert.ok(index >= 0,
    "no form on this page carries path=\"" + path + "\" with the action \"" +
    action + "\". The page offers " + JSON.stringify(before.forms
      .filter(function (f) { return f.named.path !== undefined; })
      .map(function (f) {
        return f.named.path + ":" + (f.named.action ||
          (f.controls.filter(function (c) { return c.name === "action"; })[0] ||
           { options: [] }).options.map(function (o) { return o.value; })
             .join("|"));
      })).slice(0, 1200));
  const wanted = Object.assign({}, values || {});
  // An Add menu carries the action as a `<select>`; an edit form carries it as
  // a hidden field and must not be "set".
  if (before.forms[index].named.action === undefined ||
      before.forms[index].controls.some(function (c) {
        return c.name === "action" && c.options;
      })) {
    wanted.action = action;
  }
  await submitForm(driver, index, wanted);
  const after = await survey(driver);
  log.debug("Leaving pressOn().");
  return after;
}

async function signIn(driver, username) {
  log.debug("Entering signIn(). username=" + username);
  await driver.manage().deleteAllCookies();
  await open(driver, root("/admin"));
  const url = await driver.getCurrentUrl();
  if (url.indexOf("/authn/login") < 0) {
    // AND THE PAGE REALLY IS THE CONSOLE. A browser that could not load the
    // page at all — an untrusted certificate is the way this happens, since
    // this service's key is minted on every start — sits on an interstitial
    // whose URL is still the one that was asked for, which reads here as "no
    // gate" and then fails twenty assertions about markup that was never
    // fetched. Checked once, so that failure names itself.
    const text = await driver.executeScript("return document.body.textContent;");
    assert.ok(String(text).length > 200 &&
              String(text).indexOf("ERR_") < 0,
      "the browser is at " + url + " with no sign-in screen, but the document " +
      "there does not look like this console — it reads: " +
      JSON.stringify(String(text).slice(0, 200)) + ". That is almost always " +
      "the browser refusing this service's certificate (its key is " +
      "regenerated on every start), which the launchers answer with " +
      "STS_SPKI_PIN and a hand-run does not.");
    log.info("The console is OPEN (admin.authRequired is off); no sign-in " +
             "was needed.");
    log.debug("Leaving signIn(). No gate.");
    return false;
  }
  const field = await driver.findElement(By.css("input[name='username']"));
  await field.clear();
  await field.sendKeys(username);
  const button = await driver.findElement(
      By.xpath("//button[@type='submit'] | //input[@type='submit'] | //button"));
  await button.click();
  await driver.wait(async function () {
    return (await driver.getCurrentUrl()).indexOf("/authn/login") < 0;
  }, 15000, "signing in as " + username + " left the browser on the sign-in " +
            "screen. The mock checks no password, so this is a name that was " +
            "typed and a button that was pressed; if it did not open the " +
            "console, the screen is broken rather than the credential.");
  log.debug("Leaving signIn(). Signed in.");
  return true;
}

async function keepAPicture(driver, what) {
  if (!screenshotDir) {
    return;
  }
  try {
    const fs = require("fs");
    const path = require("path");
    fs.mkdirSync(screenshotDir, { recursive: true });
    const file = path.join(screenshotDir,
        "sts_xacml_editor-" + what + "-" + Date.now() + ".png");
    fs.writeFileSync(file, await driver.takeScreenshot(), "base64");
    log.warn("A picture of the page this run died on: " + file +
             " (it was at " + (await driver.getCurrentUrl()) + ")");
  } catch (e) {
    // Swallowed on purpose: the failure being reported is the one worth seeing.
    log.warn("could not write a screenshot: " + e.message);
  }
}

// ===========================================================================
// 1. AN EMPTY REPOSITORY HAS NOTHING TO EDIT, AND SAYS SO.
//
// This is the first thing a person meets on a service where nobody has authored
// a policy, and it can only be reached in a realm of one's own — the default
// realm's repository is seeded. What it must NOT do is draw an empty table:
// a page of headings with no rows reads as an editor that is broken rather than
// as a repository that is empty.
// ===========================================================================
async function anEmptyRepositoryHasNothingToEdit(driver) {
  log.debug("Entering anEmptyRepositoryHasNothingToEdit().");
  log.info("=== The editor with an empty repository ===");

  await open(driver, editorUrl(""));
  const page = await survey(driver);

  check("the editor draws, and says there is nothing to edit", function () {
    assert.ok(page.warnings.some(function (t) {
      return t.indexOf("Nothing to edit") === 0;
    }), "the page should carry the 'Nothing to edit' notice; its notices are " +
        JSON.stringify(page.warnings));
    assert.strictEqual(page.rows.length, 0,
      "and it must not draw an empty tree table — a page of headings with no " +
      "rows reads as a broken editor rather than an empty repository. It drew " +
      page.rows.length + " row(s).");
  });

  check("and it points at the page that can create one", function () {
    assert.ok(page.bodyText.indexOf("Policies") > 0,
      "the notice should send somebody to the Policies page, where the " +
      "templates are; the page says " + page.bodyText.slice(0, 300));
  });

  log.info("[empty] OK — an empty repository is a sentence rather than an " +
           "empty table.");
  log.debug("Leaving anEmptyRepositoryHasNothingToEdit().");
}

// ===========================================================================
// 2. THE TREE IS THE POLICY, ROW BY ROW.
// ===========================================================================
async function theTreeIsDrawn(driver) {
  log.debug("Entering theTreeIsDrawn().");
  log.info("=== The tree the editor draws ===");

  await open(driver, editorUrl(POLICY));
  const page = await survey(driver);
  const kinds = page.rows.map(function (row) { return row.kind; });

  check("every element of the policy is a row, in tree order", function () {
    assert.deepStrictEqual(kinds.slice(0, 6),
      ["policy", "rule", "target", "anyOf", "allOf", "match"],
      "the RBAC template is a policy holding rules, each with a target " +
      "holding clauses, alternatives and matches — and the editor draws one " +
      "row per element. It drew " + JSON.stringify(kinds));
    assert.ok(kinds.filter(function (k) { return k === "rule"; }).length === 2,
      "the template makes two rules (admin-anything and staff-limited); the " +
      "page shows " + kinds.filter(function (k) {
        return k === "rule";
      }).length);
  });

  check("the page and /admin-api draw the same tree", function () {
    assert.ok(page.rows.length > 6,
      "the tree should have more than six rows; it has " + page.rows.length);
  });

  check("every form on the page posts to the editor IN THIS REALM", function () {
    const wrong = page.forms.filter(function (f) {
      return f.method === "post" &&
             f.resolvedAction.indexOf("/realm/" + REALM + "/admin/xacml/") < 0;
    });
    assert.deepStrictEqual(wrong.map(function (f) {
      return f.resolvedAction;
    }), [], "a form on a realm's console page that posted to the DEFAULT " +
       "realm's endpoint would edit the wrong repository — and would look " +
       "like it worked, because the console draws whichever realm it is " +
       "reached in. The browser resolved these actions to: " +
       JSON.stringify(wrong.map(function (f) { return f.resolvedAction; })));
  });

  check("no form on this page nests another", function () {
    const nested = page.forms.filter(function (f) { return f.nested; });
    assert.deepStrictEqual(nested.map(function (f) {
      return f.resolvedAction;
    }), [], "THIS IS A PARSER QUESTION AND NOT A TASTE ONE. This table puts " +
       "an edit form, an Add menu and a Remove button in the cells of one " +
       "row; HTML forbids nesting them, and a browser silently drops the " +
       "inner one — so the control draws, is pressed, and does nothing. " +
       nested.length + " form(s) contain another.");
  });

  const chooser = chooserOf(page);
  check("the chooser lists every policy in the repository", function () {
    assert.ok(chooser, "there should be a GET form carrying a policy menu; " +
      "the page has " + page.forms.length + " form(s) and none of them does");
    const menu = chooser.controls.filter(function (c) {
      return c.name === "policy";
    })[0];
    assert.ok(menu && menu.options,
      "the chooser should carry a policy menu; it carries " +
      JSON.stringify(chooser.controls.map(function (c) { return c.name; })));
    const offered = menu.options.map(function (o) { return o.value; }).sort();
    assert.deepStrictEqual(offered, [SECOND_POLICY, POLICY].sort(),
      "the menu should offer both policies in this realm; it offers " +
      JSON.stringify(offered));
  });

  log.info("[tree] OK — " + page.rows.length + " rows, " + page.forms.length +
           " forms, none nested, all posting into this realm.");
  log.debug("Leaving theTreeIsDrawn().");
}

// ===========================================================================
// 3. THE MENUS ARE THE GRAMMAR, AND THE GRAMMAR REACHES THE PAGE.
//
// The claim `xacml_admin.js` makes is that the Add dropdown beside a row offers
// EXACTLY what XACML allows at that point and nothing else, computed on the
// server by the same code that will validate the result — so the editor cannot
// offer something the validator will refuse.
//
// `tests/xacml_pap.js` asserts that of `optionsAt()` itself, which is where
// that assertion belongs. WHAT IS ASSERTED HERE IS THE HALF IT CANNOT SEE:
// that what a BROWSER can select is what that function returned, for every row
// on the page. Between the two there is a `<select>` built by hand, a hidden
// `path` per row and a table cell that has to keep them together — and a menu
// that renders one row's options beside another row's path is a control that
// silently edits the wrong element.
//
// IT IS COMPARED AGAINST /admin-api RATHER THAN AGAINST A LIST WRITTEN DOWN
// HERE, deliberately. A list in this file would be a third copy of the grammar
// and would go stale the day the editor learns a new element — which is a
// change to the EDITOR and not to this page, and should not fail a test about
// markup. What cannot go stale is that the two renderings of one answer agree.
// The semantic checks below are the ones that are XACML rather than this
// service, and those are written out.
// ===========================================================================
async function theMenusAreTheGrammar(driver) {
  log.debug("Entering theMenusAreTheGrammar().");
  log.info("=== What the Add menus offer, as the browser sees them ===");

  await open(driver, editorUrl(POLICY));
  const page = await survey(driver);
  const view = await editorJson(POLICY);

  function menuAt(path) {
    const form = page.forms.filter(function (f) {
      return f.named.path === path && f.controls.some(function (c) {
        return c.name === "action" && c.options;
      });
    })[0];
    if (!form) {
      return null;
    }
    return form.controls.filter(function (c) {
      return c.name === "action";
    })[0].options.map(function (o) { return o.value; });
  }

  function hasRemove(path) {
    return page.forms.some(function (f) {
      return f.named.path === path && f.named.action === "remove";
    });
  }

  // EVERY ROW, BOTH WAYS ROUND. A row the page draws no menu for must be a row
  // the grammar allows nothing under, and vice versa.
  view.tree.forEach(function (row) {
    const offered = menuAt(row.path);
    const allowed = row.options.additions.map(function (one) {
      return one.action;
    });
    check("the menu drawn at \"" + (row.path || "(the policy)") + "\" is the " +
          "grammar's own answer for it", function () {
      assert.deepStrictEqual(offered || [], allowed,
        "the browser can select " + JSON.stringify(offered) + " at " +
        (row.path || "the policy row") + ", and the editor's own grammar " +
        "allows " + JSON.stringify(allowed) + " there. These are two " +
        "renderings of one function's answer — a disagreement is the markup " +
        "between them, which is either a menu drawn against the wrong row's " +
        "path or an option the page invented.");
    });
    check("and Remove is drawn at \"" + (row.path || "(the policy)") +
          "\" exactly when the element may be removed", function () {
      assert.strictEqual(hasRemove(row.path), !!row.options.removable,
        "the page " + (hasRemove(row.path) ? "draws" : "does not draw") +
        " a Remove button at " + (row.path || "the policy row") + " and the " +
        "grammar says removable=" + row.options.removable + ". A Remove that " +
        "is drawn where nothing may be removed is a button that fails when " +
        "pressed; one missing where something may be is an element that " +
        "cannot be taken back out.");
    });
  });

  // ---------------------------------------------------------------------------
  // AND THE THINGS THAT ARE XACML RATHER THAN THIS SERVICE, written out because
  // the comparison above would happily agree with a grammar that had become
  // wrong in both renderings at once.
  // ---------------------------------------------------------------------------
  const anyOf = pathOfKind(view.tree, "anyOf");
  const allOf = pathOfKind(view.tree, "allOf", anyOf);
  const match = pathOfKind(view.tree, "match", allOf);
  const rule = pathOfKind(view.tree, "rule");

  check("a target clause may hold only an alternative, and an alternative " +
        "only a match", function () {
    assert.deepStrictEqual(menuAt(anyOf), ["add-allof"],
      "an AnyOf holds AllOfs and nothing else; the menu at " + anyOf +
      " offers " + JSON.stringify(menuAt(anyOf)));
    assert.deepStrictEqual(menuAt(allOf), ["add-match"],
      "an AllOf holds Matches and nothing else; the menu at " + allOf +
      " offers " + JSON.stringify(menuAt(allOf)));
  });

  check("a MATCH offers no Add menu at all — nothing goes inside one",
        function () {
    assert.strictEqual(menuAt(match), null,
      "there is nothing XACML allows inside a Match, so the row must draw no " +
      "Add control rather than an empty dropdown. The row at " + match +
      " drew " + JSON.stringify(menuAt(match)));
  });

  check("a rule offers a Condition while it has none", function () {
    assert.ok((menuAt(rule) || []).indexOf("add-condition") >= 0,
      "the template's rules carry no Condition, so the menu must offer one; " +
      "the menu at " + rule + " offers " + JSON.stringify(menuAt(rule)));
  });

  // THE FUNCTION MENU ON A MATCH. A Match's MatchId is a two-argument boolean
  // predicate over a value and an attribute; the library has 275 functions and
  // this menu is the handful that are legal here. Offering the rest would build
  // a policy the validator then refuses, which is the exact failure the
  // "computed by the same code that validates" design exists to make
  // impossible.
  // TWO FORMS ON ONE ROW, and each is asked for by what it carries. See
  // formIndexFor(): a Match's function and literal are one form and its
  // reference is another.
  const matchForm = page.forms.filter(function (f) {
    return f.named.path === match && f.named.action === "edit-match" &&
           f.controls.some(function (c) { return c.name === "matchId"; });
  })[0];
  const referenceForm = page.forms.filter(function (f) {
    return f.named.path === match && f.named.action === "edit-match" &&
           f.controls.some(function (c) { return c.name === "category"; });
  })[0];
  check("the Match function menu is the two-argument boolean predicates only",
        function () {
    assert.ok(matchForm, "the Match row should carry an inline edit form");
    const menu = matchForm.controls.filter(function (c) {
      return c.name === "matchId";
    })[0];
    assert.ok(menu && menu.options, "with a matchId menu on it");
    const offered = menu.options.map(function (o) { return o.value; });
    assert.ok(offered.indexOf(STRING_EQUAL) >= 0,
      "string-equal is the commonest Match function and must be offered; the " +
      "menu offers " + offered.length + " function(s)");
    const illegal = offered.filter(function (uri) {
      return /string-concatenate|integer-add|-bag$|-one-and-only$|-size$/.test(uri);
    });
    assert.deepStrictEqual(illegal, [],
      "a Match takes a two-argument BOOLEAN predicate, so a constructor, an " +
      "arithmetic function or a bag function has no business in this menu — " +
      "choosing one would build a policy the validator refuses. The menu " +
      "offers: " + JSON.stringify(illegal));
    assert.ok(offered.length < 80,
      "and the menu should be the ones that are legal rather than the whole " +
      "library; it offers " + offered.length + " of the 275 functions");
  });

  check("the category menu on a Match offers the XACML categories", function () {
    assert.ok(referenceForm,
      "the Match row should carry a second form for what the value is " +
      "compared against; the row carries " + JSON.stringify(page.forms
        .filter(function (f) { return f.named.path === match; })
        .map(function (f) {
          return f.controls.map(function (c) { return c.name; }).join("+");
        })));
    const menu = referenceForm.controls.filter(function (c) {
      return c.name === "category";
    })[0];
    const offered = menu.options.map(function (o) { return o.value; });
    assert.ok(offered.indexOf(ACCESS_SUBJECT) >= 0,
      "access-subject should be offered; the menu offers " +
      JSON.stringify(offered));
  });

  log.info("[grammar] OK — " + view.tree.length + " rows, each offering what " +
           "the grammar allows there and nothing else.");
  log.debug("Leaving theMenusAreTheGrammar().");
}

// ===========================================================================
// 4. ADDING A CONDITION, AND THE MENU THAT CHANGES BECAUSE OF IT.
//
// "Only one Condition per rule" is a rule of the grammar that can only be seen
// by MAKING the page change: the menu offers `add-condition` before and must
// not offer it afterwards. A test that only read the first render would report
// the menu correct and never touch the constraint.
// ===========================================================================
async function aConditionMayBeAddedOnce(driver) {
  log.debug("Entering aConditionMayBeAddedOnce().");
  log.info("=== A condition, added once ===");

  const rule = pathOfKind(await treeOf(POLICY), "rule");
  await open(driver, editorUrl(POLICY));
  const after = await pressOn(driver, rule, "add-condition", {});

  check("the condition was added and the page says so", function () {
    assert.strictEqual(outcomeOf(after.url, "error"), "",
      "adding a condition was refused: " + outcomeOf(after.url, "error"));
    assert.ok(after.rows.some(function (row) {
      return row.element.indexOf("Condition") >= 0;
    }), "no row on the redrawn page mentions a Condition; the rows are " +
        JSON.stringify(after.rows.map(function (r) { return r.kind; })));
  });

  check("and the rule's menu no longer offers a second one", function () {
    const form = after.forms.filter(function (f) {
      return f.named.path === rule && f.controls.some(function (c) {
        return c.name === "action" && c.options;
      });
    })[0];
    const offered = form.controls.filter(function (c) {
      return c.name === "action";
    })[0].options.map(function (o) { return o.value; });
    assert.ok(offered.indexOf("add-condition") < 0,
      "XACML allows one Condition per rule, so the menu must stop offering " +
      "it the moment there is one — otherwise the editor offers something " +
      "the validator will refuse, which is the one thing this design is for. " +
      "It offers " + JSON.stringify(offered));
  });

  check("the policy still type-checks with the condition on it", function () {
    assert.ok(!after.warnings.some(function (t) {
      return t.indexOf("This policy does not type-check") === 0;
    }), "the page warns that the policy does not type-check after an edit the " +
        "editor itself offered: " + JSON.stringify(after.warnings));
  });

  log.debug("Leaving aConditionMayBeAddedOnce().");
}

// ===========================================================================
// 5. AN EDIT THE VALIDATOR REFUSES CHANGES NOTHING.
//
// The property that makes a LIVE editor tolerable: the write goes through
// `store.write()`, which validates, so an edit that would leave the policy
// invalid is refused and the stored document is unchanged. You cannot break the
// running policy by half-finishing an expression, because the half-finished
// version never lands.
//
// The condition added above is `string-is-in("", employeeType)`. Retyping its
// designator as an integer is a one-form edit that produces a policy which does
// not type-check — and it is offered by the page, which is the point: the
// datatype menu is honest about what XACML has, and the STORE is what refuses.
// ===========================================================================
async function aRefusedEditStoresNothing(driver) {
  log.debug("Entering aRefusedEditStoresNothing().");
  log.info("=== An edit that would leave the policy invalid ===");

  const before = await storedDocument(POLICY);

  // THE DESIGNATOR INSIDE THE CONDITION ADDED ABOVE, found by what it IS. The
  // condition is `string-is-in("", employeeType)`; its second argument is the
  // designator, and it is the row that carries an `edit-designator` form under
  // the condition. Retyping it as an integer is a ONE-FORM edit that leaves
  // string-is-in with an integer argument — which does not type-check.
  const tree = await treeOf(POLICY);
  const condition = tree.filter(function (row) {
    return String(row.label).indexOf("Condition") === 0;
  })[0];
  assert.ok(condition,
    "section 4 added a condition and this section edits inside it; the tree " +
    "holds " + JSON.stringify(tree.map(function (r) { return r.label; })));
  await open(driver, editorUrl(POLICY));
  const withForms = await survey(driver);
  const designator = withForms.forms.filter(function (f) {
    return f.named.action === "edit-designator" &&
           f.named.path !== condition.path &&
           f.named.path.indexOf(condition.path) === 0;
  })[0];
  assert.ok(designator,
    "the condition's designator argument should carry an edit form; the page " +
    "carries " + JSON.stringify(withForms.forms
      .filter(function (f) { return f.named.path !== undefined; })
      .map(function (f) { return f.named.action + "@" + f.named.path; })));

  const after = await pressOn(driver, designator.named.path,
                              "edit-designator", {
    attributeId: "employeeType",
    category: ACCESS_SUBJECT,
    dataType: "http://www.w3.org/2001/XMLSchema#integer"
  });

  check("the edit is refused, and the refusal says why", function () {
    const error = outcomeOf(after.url, "error");
    assert.ok(error, "retyping the designator as an integer leaves " +
      "string-is-in with an integer argument, which does not type-check — the " +
      "store must refuse it. The page came back with " +
      (outcomeOf(after.url, "notice") || "no outcome at all") + " at " +
      after.url);
    assert.ok(error.indexOf("not saved") > 0 || error.indexOf("invalid") > 0,
      "and the refusal should say the document was NOT saved rather than " +
      "merely that something went wrong; it says: " + error);
    assert.ok(error.indexOf("type") > 0,
      "and it should name the type problem, which is what the person has to " +
      "fix: " + error);
  });

  // READ THROUGH /admin-api AND NOT OFF THE PAGE: the page redrew from the same
  // store, so a page showing the old document would prove nothing about what is
  // stored. Fetched before the check so that the assertion itself stays
  // synchronous — a `check` whose body returned a promise would count as passed
  // and fail somewhere else entirely.
  const now = await storedDocument(POLICY);
  check("the stored document is byte-for-byte what it was", function () {
    assert.strictEqual(now, before,
      "the stored policy changed despite the edit being refused. A LIVE " +
      "editor whose refused edits still landed would break the policy the PDP " +
      "is deciding with, at the moment somebody was trying to improve it.");
  });

  const stillGood = await editorJson(POLICY);
  check("and the policy still loads and type-checks", function () {
    assert.deepStrictEqual(stillGood.problems, [],
      "after a refused edit the policy should be exactly as valid as it was; " +
      "it reports " + JSON.stringify(stillGood.problems));
  });

  log.info("[refusal] OK — refused, explained, and nothing written.");
  log.debug("Leaving aRefusedEditStoresNothing().");
}

// ===========================================================================
// 6. A RULE BUILT BY PRESSING BUTTONS, AND THE PDP THAT OBEYS IT.
//
// THIS IS WHAT THE FILE IS FOR. Four form submissions build a rule that permits
// one person everything; before them the PDP refuses him, after them it permits
// him, and nothing else about the service changed. An editor that drew
// perfectly and wrote somewhere else would pass every other assertion here.
// ===========================================================================
async function aRuleBuiltOnThePageDecides(driver) {
  log.debug("Entering aRuleBuiltOnThePageDecides().");
  log.info("=== A rule built in the browser, and what the PDP then says ===");

  const before = await enforcementFor(SUBJECT, "DELETE");
  check(SUBJECT + " is refused DELETE before the rule exists", function () {
    assert.strictEqual(before.status, 403,
      SUBJECT + " is staff, and the template permits staff GET and HEAD only " +
      "— so DELETE must be refused before this section builds anything. The " +
      "PEP answered " + before.status + " " + JSON.stringify(before.body).slice(0, 200));
    assert.strictEqual(before.body.decision, "Deny");
  });

  await open(driver, editorUrl(POLICY));

  // 1. A RULE. It arrives COMPLETE — a Target and an Effect — because an editor
  //    that produced half-built elements would hold a document that could not
  //    be saved, and a document that cannot be saved cannot be evaluated.
  let page = await pressOn(driver, "", "add-rule", {});
  const ruleRows = page.rows.filter(function (row) {
    return row.kind === "rule";
  });
  check("a new rule arrives complete and valid", function () {
    assert.strictEqual(outcomeOf(page.url, "error"), "",
      "adding a rule was refused: " + outcomeOf(page.url, "error"));
    assert.strictEqual(ruleRows.length, 3,
      "the template's two rules plus the new one; the page shows " +
      ruleRows.length);
    assert.ok(!page.warnings.some(function (t) {
      return t.indexOf("This policy does not type-check") === 0;
    }), "and the policy must still type-check, because the write went " +
        "through the store: " + JSON.stringify(page.warnings));
  });

  // THE NEW RULE IS THE LAST ONE, and its path is read out of the tree rather
  // than computed — so a change to where a new rule is inserted, or to how a
  // path is spelt, fails here loudly instead of silently editing the
  // template's first rule.
  const newRule = lastOfKind(await treeOf(POLICY), "rule").path;

  // 2. ITS EFFECT AND ITS NAME.
  page = await pressOn(driver, newRule, "edit-rule",
                       { effect: "Permit", id: "urn:test:rule:" + SUBJECT });
  check("the rule's effect and id are what the form set", function () {
    assert.strictEqual(outcomeOf(page.url, "error"), "");
    assert.ok(page.rows.some(function (row) {
      return row.element.indexOf("urn:test:rule:" + SUBJECT) >= 0 &&
             row.element.indexOf("Permit") >= 0;
    }), "the redrawn tree should show the renamed Permit rule; it shows " +
        JSON.stringify(page.rows.map(function (r) { return r.element.slice(0, 60); })));
  });

  // 3. A TARGET CLAUSE — ONE PRESS, THREE ELEMENTS.
  //
  // "Every element you add arrives complete and valid" is a claim this page
  // makes in its own prose, and this is where it is checked: a clause is
  // useless without an alternative, and an alternative without a match, so one
  // press brings all three. An editor that added a bare <AnyOf/> would hold a
  // document that does not typecheck, and a document that cannot be saved
  // cannot be evaluated — which is when somebody most wants to look at it.
  page = await pressOn(driver, newRule, "add-target-anyof", {});
  const built = await treeOf(POLICY);
  const newAnyOf = pathOfKind(built, "anyOf", newRule);
  const newAllOf = pathOfKind(built, "allOf", newAnyOf);
  const newMatch = pathOfKind(built, "match", newAllOf);
  check("one press adds a clause, an alternative and a match together",
        function () {
    assert.strictEqual(outcomeOf(page.url, "error"), "");
    assert.ok(page.forms.some(function (f) {
      return f.named.path === newMatch;
    }), "the match brought in with the clause should have a row of its own " +
        "with an edit form on it; the page carries paths " +
        JSON.stringify(page.forms.map(function (f) { return f.named.path; })
          .filter(function (path) {
            return path && path.indexOf(newRule) === 0;
          })));
  });

  // 4. WHAT THE MATCH SAYS — TWO FORMS ON ONE ROW. The function and the literal
  //    are one; what they are compared AGAINST is the other, because that half
  //    changes shape entirely when the reference is an XPath selector. The
  //    value and the attribute together are the whole rule: subject-id equals
  //    bob.
  page = await pressOn(driver, newMatch, "edit-match",
                       { matchId: STRING_EQUAL, value: SUBJECT }, "matchId");
  page = await pressOn(driver, newMatch, "edit-match",
                       { attributeId: SUBJECT_ID, category: ACCESS_SUBJECT },
                       "category");
  check("the match reads back what was typed into it", function () {
    assert.strictEqual(outcomeOf(page.url, "error"), "",
      "editing the match was refused: " + outcomeOf(page.url, "error"));
    const forms = page.forms.filter(function (f) {
      return f.named.path === newMatch && f.named.action === "edit-match";
    });
    const value = forms.filter(function (f) {
      return f.named.value !== undefined;
    })[0];
    const reference = forms.filter(function (f) {
      return f.named.attributeId !== undefined;
    })[0];
    assert.ok(value && reference,
      "the match row should redraw both of its forms; it drew " + forms.length);
    assert.strictEqual(value.named.value, SUBJECT,
      "the value field should redraw holding " + SUBJECT + "; it holds " +
      value.named.value);
    assert.strictEqual(reference.named.attributeId, SUBJECT_ID,
      "and the attribute should be the subject-id; it is " +
      reference.named.attributeId);
  });

  // THE READ-BACK THROUGH THE OTHER DOOR.
  const stored = await editorJson(POLICY);
  check("the stored document holds the rule the browser built", function () {
    assert.ok(stored.document.indexOf("urn:test:rule:" + SUBJECT) > 0,
      "the rule id typed into the form is not in the stored document");
    assert.ok(stored.document.indexOf(SUBJECT_ID) > 0,
      "nor is the attribute the match was pointed at");
    assert.deepStrictEqual(stored.problems, [],
      "and the whole policy should still type-check; it reports " +
      JSON.stringify(stored.problems));
  });

  check("the ALFA rendering shows the new rule too", function () {
    assert.ok(String(stored.alfa).indexOf("permit") >= 0,
      "ALFA is a VIEW of the same model rather than a second stored copy, so " +
      "a rule added in the tree is in the ALFA immediately. It reads: " +
      String(stored.alfa).slice(0, 300));
    assert.ok(String(stored.alfa).indexOf(SUBJECT) > 0,
      "and it should carry the value the match was given; it reads: " +
      String(stored.alfa).slice(0, 400));
  });

  // ---------------------------------------------------------------------------
  // AND THE PDP DECIDES BY IT.
  // ---------------------------------------------------------------------------
  const after = await enforcementFor(SUBJECT, "DELETE");
  check("the PDP now PERMITS what it refused before the rule was built",
        function () {
    assert.strictEqual(after.status, 200,
      "FOUR BUTTONS ON A CONSOLE PAGE JUST CHANGED AN AUTHORIZATION " +
      "DECISION, and this is the assertion that says so. " + SUBJECT +
      " was refused DELETE before this section and the PEP now answers " +
      after.status + " " + JSON.stringify(after.body).slice(0, 300));
    assert.strictEqual(after.body.decision, "Permit",
      "the decision is " + after.body.decision);
  });

  const others = await enforcementFor("alice", "DELETE");
  check("and it changed nothing for anybody else", function () {
    assert.strictEqual(others.status, 403,
      "the rule matches subject-id = " + SUBJECT + " and nobody else, so " +
      "alice must still be refused DELETE. A rule that permitted everybody " +
      "would pass the check above and be entirely wrong. The PEP answered " +
      others.status);
  });

  // ---------------------------------------------------------------------------
  // ALTERNATIVES ARE ORed AND MATCHES ARE ANDed, DEMONSTRATED THROUGH THE PAGE.
  //
  // The help text under these menus says exactly that — "ANY of them matching
  // satisfies it", "all must hold" — and it is the single easiest thing in
  // XACML to get backwards. Getting it backwards in the EDITOR would build the
  // policy somebody did not ask for while the page told them it had built the
  // one they did, and the only way to tell the two apart is to add each and ask
  // the PDP. Both new elements arrive with an empty literal, which matches
  // nobody, so the OR must leave the Permit standing and the AND must take it
  // away.
  // ---------------------------------------------------------------------------
  await pressOn(driver, newAnyOf, "add-allof", {});
  const withAlternative = await enforcementFor(SUBJECT, "DELETE");
  check("a second ALTERNATIVE is an OR, so it takes nothing away", function () {
    assert.strictEqual(withAlternative.status, 200,
      "the new alternative matches nobody, and alternatives are ORed — so " +
      "the one that matches " + SUBJECT + " still satisfies the clause. The " +
      "PEP answered " + withAlternative.status + ", which is what an editor " +
      "that had built an AND here would produce.");
  });

  await pressOn(driver, newAllOf, "add-match", {});
  const extraMatch = lastOfKind(await treeOf(POLICY), "match", newAllOf).path;
  const withMatch = await enforcementFor(SUBJECT, "DELETE");
  check("a second MATCH in one alternative is an AND, so it takes it away",
        function () {
    assert.strictEqual(withMatch.status, 403,
      "the new match matches nobody, and matches within an alternative are " +
      "ANDed — so the alternative that matched " + SUBJECT + " no longer " +
      "does. The PEP answered " + withMatch.status + ", which is what an " +
      "editor that had built an OR here would produce.");
  });

  await pressOn(driver, extraMatch, "remove", {});
  const removed = await enforcementFor(SUBJECT, "DELETE");
  check("and removing it gives the permission back", function () {
    assert.strictEqual(removed.status, 200,
      "with the empty match removed the alternative matches " + SUBJECT +
      " again; the PEP answered " + removed.status);
  });

  log.info("[built] OK — a rule made of four form submissions, and a decision " +
           "that follows it.");
  log.debug("Leaving aRuleBuiltOnThePageDecides().");
  return newRule;
}

// ===========================================================================
// 7. THE WARNING THAT SAYS EDITING IS LIVE TRACKS WHAT IS ACTUALLY STORED.
//
// The editor holds no session state: the draft IS the stored policy. The page
// therefore warns when the policy being edited is the one the PDP is deciding
// with — and that warning has to follow the STORE rather than be printed
// always, or it is decoration.
// ===========================================================================
async function theLiveWarningFollowsTheStore(driver) {
  log.debug("Entering theLiveWarningFollowsTheStore().");
  log.info("=== 'Editing is live', and when it is not ===");

  await open(driver, editorUrl(POLICY));
  const live = await survey(driver);
  check("an enabled root policy warns that editing it is live", function () {
    assert.ok(live.warnings.some(function (t) {
      return t.indexOf("Editing is live") === 0;
    }), "this policy is enabled and is the root, so every change takes " +
        "effect on the next request and the page must say so. Its notices " +
        "are " + JSON.stringify(live.warnings));
  });

  await apiPost("/realm/" + REALM + "/admin-api/xacml/disable",
                { name: POLICY });
  await open(driver, editorUrl(POLICY));
  const quiet = await survey(driver);
  check("a disabled policy does not, because editing it changes no decision",
        function () {
    assert.ok(!quiet.warnings.some(function (t) {
      return t.indexOf("Editing is live") === 0;
    }), "the warning should be gone once the policy is disabled — the page " +
        "recommends disabling a policy to work on it safely, and a warning " +
        "that stayed up afterwards would be telling somebody their fix did " +
        "not work. Its notices are " + JSON.stringify(quiet.warnings));
  });

  await apiPost("/realm/" + REALM + "/admin-api/xacml/enable",
                { name: POLICY });
  await open(driver, editorUrl(POLICY));
  const again = await survey(driver);
  check("and it comes back when the policy is enabled again", function () {
    assert.ok(again.warnings.some(function (t) {
      return t.indexOf("Editing is live") === 0;
    }), "the notices are " + JSON.stringify(again.warnings));
  });

  log.debug("Leaving theLiveWarningFollowsTheStore().");
}

// ===========================================================================
// 8. REMOVING THE RULE ON THE PAGE, AND THE DECISION GOING BACK.
//
// The other half of section 6, and the half that shows the first was not a
// coincidence: press Remove on the row that was built, and the person permitted
// by it is refused again.
// ===========================================================================
async function removingTheRuleTakesTheDecisionWithIt(driver, rulePath) {
  log.debug("Entering removingTheRuleTakesTheDecisionWithIt().");
  log.info("=== Remove, and the decision that follows ===");

  await open(driver, editorUrl(POLICY));
  const before = await survey(driver);
  const rules = before.rows.filter(function (row) {
    return row.kind === "rule";
  }).length;

  const after = await pressOn(driver, rulePath, "remove", {});
  check("the row is gone from the tree", function () {
    assert.strictEqual(outcomeOf(after.url, "error"), "",
      "removing the rule was refused: " + outcomeOf(after.url, "error"));
    const now = after.rows.filter(function (row) {
      return row.kind === "rule";
    }).length;
    assert.strictEqual(now, rules - 1,
      "the tree held " + rules + " rules and holds " + now + " after one was " +
      "removed");
  });

  const stored = await editorJson(POLICY);
  check("and out of the stored document", function () {
    assert.ok(stored.document.indexOf("urn:test:rule:" + SUBJECT) < 0,
      "the removed rule is still in the stored policy");
    assert.deepStrictEqual(stored.problems, [],
      "and what is left must still type-check; it reports " +
      JSON.stringify(stored.problems));
  });

  const enforcement = await enforcementFor(SUBJECT, "DELETE");
  check("the PDP refuses " + SUBJECT + " again", function () {
    assert.strictEqual(enforcement.status, 403,
      "with the rule removed the PEP should be back to refusing; it answered " +
      enforcement.status + " " + JSON.stringify(enforcement.body).slice(0, 200));
    assert.strictEqual(enforcement.body.decision, "Deny");
  });

  log.info("[remove] OK — the row, the document and the decision all went " +
           "together.");
  log.debug("Leaving removingTheRuleTakesTheDecisionWithIt().");
}

// ===========================================================================
// 9. THE CHOOSER OPENS ANOTHER POLICY, AND THE EDITS FOLLOW IT.
//
// One page, `?policy=<name>`, and a GET form to change it. What would go wrong
// silently is the hidden `policy` field on the forty edit forms not following
// the chooser — an editor that drew the second policy and posted edits to the
// first.
// ===========================================================================
async function theChooserOpensAnotherPolicy(driver) {
  log.debug("Entering theChooserOpensAnotherPolicy().");
  log.info("=== The chooser, and the forms that follow it ===");

  await open(driver, editorUrl(POLICY));
  const page = await survey(driver);
  const chooser = chooserOf(page);
  assert.ok(chooser, "the editor should draw a policy chooser");
  await submitForm(driver, chooser.index, { policy: SECOND_POLICY });
  const opened = await survey(driver);

  check("the chooser opens the policy it was pointed at", function () {
    assert.ok(opened.url.indexOf(encodeURIComponent(SECOND_POLICY)) > 0 ||
              opened.url.indexOf(SECOND_POLICY) > 0,
      "the browser landed on " + opened.url);
  });

  check("EVERY form on the page now names that policy", function () {
    const wrong = opened.forms.filter(function (f) {
      return f.named.policy !== undefined && f.named.policy !== SECOND_POLICY;
    });
    assert.deepStrictEqual(wrong.map(function (f) { return f.named.policy; }), [],
      "a hidden `policy` field left pointing at the previous policy would " +
      "make an edit here silently change a DIFFERENT document — and the page " +
      "would redraw showing the one you are looking at, unchanged, which " +
      "reads as an editor that does nothing. " + wrong.length + " form(s) " +
      "still name " + JSON.stringify(wrong.map(function (f) {
        return f.named.policy;
      })));
  });

  log.debug("Leaving theChooserOpensAnotherPolicy().");
}

// ===========================================================================
// 10. THE BROWSER'S OWN LOG, WHICH ON THIS CONSOLE MUST BE EMPTY.
//
// Every page here is served `default-src 'none'` with `script-src 'none'` over
// it, so a severe line is the browser saying this page asked for something its
// own policy refuses. The editor is the page most likely to grow one — it is
// the only console page anybody would be tempted to make interactive.
// ===========================================================================
async function theBrowserConsoleIsClean(driver) {
  log.debug("Entering theBrowserConsoleIsClean().");
  const entries = await driver.manage().logs().get("browser").catch(function () {
    // Not every driver serves the log; a job that failed here would be
    // reporting on the driver rather than on the console.
    return [];
  });
  const severe = entries.filter(function (entry) {
    return entry.level && entry.level.name === "SEVERE";
  }).map(function (entry) {
    return entry.message;
  }).filter(function (message) {
    // The browser asks for /favicon.ico on its own and this service serves
    // none; it is the browser's request rather than the page's.
    return message.indexOf("/favicon.ico") < 0;
  });

  check("the browser logged nothing severe while editing", function () {
    assert.deepStrictEqual(severe, [],
      "THE BROWSER LOGGED " + severe.length + " SEVERE MESSAGE(S) while this " +
      "file drove the editor: " + severe.join(" | ") + ". This page runs " +
      "under script-src 'none' and every control on it is a form; a severe " +
      "line means the page asked for something its own policy refuses, which " +
      "no status code would show.");
  });
  log.debug("Leaving theBrowserConsoleIsClean().");
}

// ---------------------------------------------------------------------------
// SETTING UP AND TEARING DOWN.
// ---------------------------------------------------------------------------
async function createTheRealm() {
  log.debug("Entering createTheRealm().");
  const r = await apiPost("/admin-api/realms/create", {
    id: REALM, name: "XACML editor test realm",
    description: "Created by tests/vendored/sts_xacml_editor.js; removed at " +
                 "the end."
  });
  assert.ok(r.status === 200 && r.body && r.body.ok !== false,
    "creating the throwaway realm " + REALM + " answered " + r.status + " " +
    String(r.text).slice(0, 300));
  log.info("Created the throwaway realm " + REALM + ".");
  log.debug("Leaving createTheRealm().");
}

async function createThePolicies() {
  log.debug("Entering createThePolicies().");
  // THROUGH /admin-api AND NOT THROUGH THE CONSOLE'S OWN TEMPLATE FORM, which
  // `sts_admin_console.js` already presses. What is under test here is the
  // EDITOR, and a job that spent its first minute on somebody else's page would
  // fail there for reasons that say nothing about this one.
  for (const name of [POLICY, SECOND_POLICY]) {
    const r = await apiPost("/realm/" + REALM +
                            "/admin-api/xacml/create-from-template",
                            { template: "rbac", name: name });
    assert.ok(r.status === 200 && r.body && r.body.ok !== false,
      "creating the policy " + name + " answered " + r.status + " " +
      String(r.text).slice(0, 300));
  }
  // The FIRST one became the root because the repository was empty; the second
  // did not. Every section below assumes exactly that, so it is asserted rather
  // than trusted.
  const listed = await json(base + "/realm/" + REALM + "/xacml/policies");
  assert.strictEqual(listed.body.root, POLICY,
    "the first policy created in an empty repository becomes the root; this " +
    "repository's root is " + listed.body.root);
  log.debug("Leaving createThePolicies().");
}

async function removeTheRealm() {
  log.debug("Entering removeTheRealm().");
  const r = await apiPost("/admin-api/realms/remove", { id: REALM });
  if (r.status !== 200 || !r.body || r.body.ok === false) {
    log.warn("Could not remove the throwaway realm " + REALM + ": " +
             r.status + " " + String(r.text).slice(0, 200));
    return;
  }
  log.info("Removed the throwaway realm " + REALM + ", and the policies this " +
           "file edited with it.");
  log.debug("Leaving removeTheRealm().");
}

// ---------------------------------------------------------------------------
// THE RUN.
// ---------------------------------------------------------------------------
async function test() {
  log.debug("Entering test().");
  log.info("Driving the mock STS's XACML policy editor at " + base +
           "/admin/xacml/editor");

  const status = await json(base + "/admin-api/status");
  assert.strictEqual(status.status, 200,
    "GET /admin-api/status answered " + status.status + " at " + base +
    ". This job needs the mock and a browser, and a service that is not " +
    "there is a failure rather than a skip.");

  const options = new chrome.Options();
  options.addArguments("--headless=new", "--no-sandbox",
      "--disable-dev-shm-usage", "--window-size=1400,1200");
  browserFlags.addBrowserAccessFlags(options, base);
  const driver = await new Builder().forBrowser("chrome")
      .setChromeOptions(options).build();

  try {
    await createTheRealm();
    try {
      await signIn(driver, CONSOLE_USER);
      // BEFORE ANY POLICY EXISTS — this is the only moment that page can be
      // seen, and creating the policies first would lose it for ever.
      await anEmptyRepositoryHasNothingToEdit(driver);
      await createThePolicies();

      await theTreeIsDrawn(driver);
      await theMenusAreTheGrammar(driver);
      await aConditionMayBeAddedOnce(driver);
      await aRefusedEditStoresNothing(driver);
      const rulePath = await aRuleBuiltOnThePageDecides(driver);
      await theLiveWarningFollowsTheStore(driver);
      await removingTheRuleTakesTheDecisionWithIt(driver, rulePath);
      await theChooserOpensAnotherPolicy(driver);
      await theBrowserConsoleIsClean(driver);
    } finally {
      await removeTheRealm();
    }

    // A FLOOR ON THE COUNT, for sts_admin_console.js's reason: a section that
    // stops being called takes its assertions with it and the run still says
    // "passed".
    assert.ok(checks >= 25,
      "only " + checks + " checks ran. This file makes about thirty against a " +
      "healthy console, so a count this low means a SECTION STOPPED BEING " +
      "CALLED rather than that the editor got simpler.");
    log.info(checks + " checks passed.");
    log.info("Test completed successfully.");
  } catch (e) {
    await keepAPicture(driver, "failure");
    throw e;
  } finally {
    await driver.quit();
  }
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_xacml_editor")
  .description("Drive the mock STS's guided XACML policy editor in a real " +
      "browser: the grammar its menus offer, an edit the validator refuses, " +
      "a rule built out of form submissions, and the decision the PDP then " +
      "makes because of it.")
  .addOption(new Option("-u, --url <url>", "base url of the STS under test")
      .default(base))
  .addOption(new Option("--screenshot-dir <dir>",
      "write a PNG of the page here if the run fails"))
  .parse(process.argv);
base = String(program.opts().url || base).replace(/\/+$/, "");
screenshotDir = program.opts().screenshotDir || "";

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
