#!/usr/bin/env node
'use strict';
//
// File: tests/tools/coverage-report.js
//
// ===========================================================================
// THE COVERAGE REPORT, RENDERED FROM V8'S OWN DATA AND NOTHING ELSE.
//
// `./run-coverage.sh` is the way in. This file turns the raw JSON that
// `NODE_V8_COVERAGE=<dir>` leaves behind into coverage/index.html, one
// annotated page per source file, and coverage/lcov.info for anything that
// reads the standard format.
//
// ---------------------------------------------------------------------------
// WHY IT IS WRITTEN HERE RATHER THAN BEING `c8`.
//
// The parent project renders its two coverage domains with c8 and nyc, both
// devDependencies of the images that run them. This repository cannot do that,
// and the reason is not taste:
//
//   * `.npmrc` here carries `omit=dev` and the Dockerfile passes `--omit=dev`
//     as well (see the root CLAUDE.md — it is what keeps ldapjs's ~200 test
//     packages out). A devDependency added for coverage would therefore be
//     SILENTLY NOT INSTALLED by the ordinary `npm install`, and this script
//     would fail for everybody with a message about a missing binary.
//   * tests/CLAUDE.md's closing rule is that the moment this directory needs a
//     dependency to run, it stops being cheaper than the parent suite. A
//     coverage renderer that needs a network fetch to work is exactly that.
//
// So: node builtins only, no install, works offline, and the raw V8 data is
// left in place for anyone who would rather point c8 at it themselves.
//
// ---------------------------------------------------------------------------
// WHAT THE NUMBERS MEAN, PRECISELY, BECAUSE A COVERAGE PERCENTAGE THAT NOBODY
// CAN DEFINE IS WORSE THAN NONE.
//
//   FUNCTIONS — exact. V8 reports every function it compiled and how many
//   times each was called. Nothing is inferred.
//
//   LINES — derived, and here is the derivation. V8 reports RANGES of source
//   offsets with an execution count, nested: the outer range is the function,
//   the inner ones are the blocks inside it that ran a different number of
//   times. A line's count is the count of the INNERMOST range containing its
//   first non-whitespace character. A line is EXECUTABLE when it is not blank
//   and not wholly a comment — which is a heuristic, and the one place a
//   number here can be argued with. It is stated rather than hidden, and it
//   errs towards counting a line (a `}` on its own is counted), so this report
//   is not flattering.
//
//   BRANCHES are not reported at all. V8's block ranges are not branch arms,
//   and a branch percentage inferred from them would be a number with no
//   definition — the failure mode this section exists to avoid.
//
// ---------------------------------------------------------------------------
// MERGING, AND THE ONE THING THAT IS EASY TO GET WRONG.
//
// A run produces several files: one per test job, and — because the throwaway
// service writes its coverage on SIGTERM and AGAIN when it exits (see
// coverage_entry.js) — two from the SAME process, the second a superset of the
// first. Summing those would double every count in the service's half.
//
// So the pid in the file name is used: within one pid the same range keeps its
// LARGEST count, and across pids counts are summed. Nothing about
// covered-versus-not changes either way, but the hit counts on the annotated
// pages are then real numbers rather than inflated ones.
// ===========================================================================

const fs = require('fs');
const path = require('path');
const bunyan = require('bunyan');

// ---------------------------------------------------------------------------
// THE `Entering`/`Leaving` PAIR IS ON THE FUNCTIONS THAT RUN A BOUNDED NUMBER
// OF TIMES PER RUN, AND NOT ON THE ONES INSIDE THE PASS — argued here rather
// than left to be noticed, which is this repository's pattern for an exemption
// from its own code style.
//
// `executableLines()`, `countsByLine()`, `summariseFile()`, `foldScript()`,
// `addSets()` and `fileOf()` are the rendering pass: they run once per file,
// per label, per script and — inside the first two — once per LINE of every
// file in this repository, which is hundreds of thousands of calls. A debug
// line each would make the log they would be written into unreadable, which is
// the opposite of what the rule is for. `render()`, `readRaw()`,
// `mergeLabel()`, `allSourceFiles()`, `writeLcov()` and `main()` all carry the
// pair.
// ---------------------------------------------------------------------------

// Never coverage's subject: dependencies, the tests themselves, generated
// output, and this tooling. `tests/` is excluded for the ordinary reason — a
// suite that covers itself reports its own size, not the service's.
const SKIP_DIR = /(^|\/)(node_modules|node-ldapjs|coverage|docs|data|\.git|tests)(\/|$)/;

function defaultLog() {
  return bunyan.createLogger({ name: 'coverage',
                               level: process.env.LOG_LEVEL || 'info' });
}

// ---------------------------------------------------------------------------
// Every raw V8 file in a directory, keyed by the pid that wrote it. The name
// is `coverage-<pid>-<timestamp>-<n>.json`; a file that does not carry one is
// given a key of its own so it is never merged with anything.
// ---------------------------------------------------------------------------
function readRaw(dir, log) {
  log.debug('Entering readRaw(). dir=' + dir);
  const byPid = {};
  let files = [];
  try {
    files = fs.readdirSync(dir).filter(function (f) {
      return /\.json$/.test(f);
    });
  } catch (e) {
    log.debug('Leaving readRaw(). No such directory: ' + e.message);
    return byPid;
  }
  files.forEach(function (f) {
    let parsed;
    try {
      parsed = JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8'));
    } catch (e) {
      // A file V8 was still writing when the run ended, or a truncated one.
      // Skipping it loses one process's data; failing would lose the report.
      log.warn('ignoring unreadable coverage file ' + f + ': ' + e.message);
      return;
    }
    const m = /^coverage-(\d+)-/.exec(f);
    const pid = m ? m[1] : f;
    byPid[pid] = byPid[pid] || [];
    byPid[pid].push(parsed.result || []);
  });
  log.debug('Leaving readRaw(). ' + files.length + ' file(s).');
  return byPid;
}

// One script's functions, as a map from a stable key to its ranges. `merge` is
// how two counts for the same range are combined — Math.max within a pid,
// addition across pids.
function foldScript(into, script, merge) {
  const fns = into[script.url] = into[script.url] || {};
  (script.functions || []).forEach(function (fn) {
    const ranges = fn.ranges || [];
    if (!ranges.length) {
      return;
    }
    const key = (fn.functionName || '') + '|' + ranges[0].startOffset + '|' +
      ranges[0].endOffset;
    const slot = fns[key] = fns[key] || {};
    ranges.forEach(function (r) {
      const rk = r.startOffset + ':' + r.endOffset;
      slot[rk] = slot[rk] === undefined ? r.count : merge(slot[rk], r.count);
    });
  });
}

// ---------------------------------------------------------------------------
// All of one label's data, merged: max within a pid, sum across pids. Returns
// url -> [{start,end,count}].
// ---------------------------------------------------------------------------
function mergeLabel(byPid, log) {
  log.debug('Entering mergeLabel().');
  const perPid = {};
  Object.keys(byPid).forEach(function (pid) {
    const one = {};
    byPid[pid].forEach(function (result) {
      result.forEach(function (script) {
        foldScript(one, script, Math.max);
      });
    });
    perPid[pid] = one;
  });
  const all = {};
  Object.keys(perPid).forEach(function (pid) {
    const one = perPid[pid];
    Object.keys(one).forEach(function (url) {
      const into = all[url] = all[url] || {};
      Object.keys(one[url]).forEach(function (key) {
        const slot = into[key] = into[key] || {};
        Object.keys(one[url][key]).forEach(function (rk) {
          slot[rk] = (slot[rk] || 0) + one[url][key][rk];
        });
      });
    });
  });
  log.debug('Leaving mergeLabel(). ' + Object.keys(all).length + ' script(s).');
  return all;
}

// Two merged sets added together, for the combined column.
function addSets(a, b) {
  const out = {};
  [a, b].forEach(function (set) {
    Object.keys(set).forEach(function (url) {
      const into = out[url] = out[url] || {};
      Object.keys(set[url]).forEach(function (key) {
        const slot = into[key] = into[key] || {};
        Object.keys(set[url][key]).forEach(function (rk) {
          slot[rk] = (slot[rk] || 0) + set[url][key][rk];
        });
      });
    });
  });
  return out;
}

function fileOf(url, root) {
  if (url.indexOf('file://') !== 0) {
    return '';
  }
  let file;
  try {
    file = decodeURIComponent(url.slice('file://'.length));
  } catch (e) {
    // A URL this service never produced. Not ours either way.
    return '';
  }
  if (file.indexOf(root + path.sep) !== 0) {
    return '';
  }
  const rel = path.relative(root, file);
  if (SKIP_DIR.test(rel) || !/\.js$/.test(rel)) {
    return '';
  }
  return rel;
}

// ---------------------------------------------------------------------------
// Which lines of this file may be counted. Blank ones and wholly-comment ones
// are not code; everything else is. The block-comment state is tracked with a
// scanner rather than a regexp per line, because `/*` and `*/` are on
// different lines by definition and this repository's comment blocks are long.
//
// It does not understand a `/*` inside a string or a regular expression, and
// that is an accepted limit: the effect is to call a few code lines comments,
// which lowers the denominator slightly and can only make this report LESS
// flattering than the truth.
// ---------------------------------------------------------------------------
function executableLines(source) {
  const lines = source.split('\n');
  const executable = new Array(lines.length).fill(false);
  let inBlock = false;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    if (inBlock) {
      const end = trimmed.indexOf('*/');
      if (end >= 0) {
        inBlock = false;
        const after = trimmed.slice(end + 2).trim();
        executable[i] = after.length > 0 && after.indexOf('//') !== 0;
      }
      continue;
    }
    if (!trimmed) {
      continue;
    }
    if (trimmed.indexOf('//') === 0) {
      continue;
    }
    if (trimmed.indexOf('/*') === 0) {
      const end = trimmed.indexOf('*/', 2);
      if (end < 0) {
        inBlock = true;
        continue;
      }
      const after = trimmed.slice(end + 2).trim();
      executable[i] = after.length > 0 && after.indexOf('//') !== 0;
      continue;
    }
    if (trimmed === "'use strict';" || trimmed === '"use strict";') {
      // Hoisted out of every function body by V8 and never given a range of
      // its own; counting it would put one permanently uncovered line in
      // every file in the repository.
      continue;
    }
    executable[i] = true;
  }
  return { lines: lines, executable: executable };
}

// ---------------------------------------------------------------------------
// The count at each line, by the nested-interval sweep the header describes: a
// stack of the ranges currently open, and the innermost one wins.
// ---------------------------------------------------------------------------
function countsByLine(source, ranges, executable) {
  const lines = source.split('\n');
  // The offset of the first non-whitespace character of each line, which is
  // the position a line's count is read at.
  const probes = [];
  let offset = 0;
  for (let i = 0; i < lines.length; i++) {
    const lead = lines[i].length - lines[i].replace(/^\s+/, '').length;
    probes.push(offset + lead);
    offset += lines[i].length + 1;
  }
  const sorted = ranges.slice().sort(function (a, b) {
    return a.start - b.start || b.end - a.end;
  });
  const counts = new Array(lines.length).fill(null);
  const stack = [];
  let ri = 0;
  for (let i = 0; i < lines.length; i++) {
    if (!executable[i]) {
      continue;
    }
    const at = probes[i];
    while (ri < sorted.length && sorted[ri].start <= at) {
      stack.push(sorted[ri]);
      ri++;
    }
    while (stack.length && stack[stack.length - 1].end <= at) {
      stack.pop();
    }
    // A range popped from the top can uncover one that is still open, so the
    // stack is walked from the top for the innermost that actually contains
    // this offset rather than trusted blindly.
    let count = null;
    for (let s = stack.length - 1; s >= 0; s--) {
      if (stack[s].start <= at && stack[s].end > at) {
        count = stack[s].count;
        break;
      }
    }
    counts[i] = count;
  }
  return counts;
}

// ---------------------------------------------------------------------------
// One file's numbers, for one merged set.
// ---------------------------------------------------------------------------
function summariseFile(rel, root, fns) {
  let source;
  try {
    source = fs.readFileSync(path.join(root, rel), 'utf8');
  } catch (e) {
    // Covered but no longer on disk — a file deleted between the run and the
    // render. Reporting it with no numbers is better than crashing.
    return null;
  }
  const ranges = [];
  let functions = 0;
  let functionsHit = 0;
  Object.keys(fns || {}).forEach(function (key) {
    const slot = fns[key];
    let outer = null;
    Object.keys(slot).forEach(function (rk) {
      const parts = rk.split(':');
      const r = { start: Number(parts[0]), end: Number(parts[1]),
                  count: slot[rk] };
      ranges.push(r);
      if (!outer || r.start < outer.start ||
          (r.start === outer.start && r.end > outer.end)) {
        outer = r;
      }
    });
    functions++;
    if (outer && outer.count > 0) {
      functionsHit++;
    }
  });
  const { executable } = executableLines(source);
  const counts = countsByLine(source, ranges, executable);
  let lines = 0;
  let hit = 0;
  const perLine = [];
  for (let i = 0; i < executable.length; i++) {
    if (!executable[i]) {
      perLine.push(null);
      continue;
    }
    lines++;
    // A line with no range over it at all, in a file V8 loaded, is code that
    // was compiled and never entered — uncovered, not unknown.
    const c = counts[i] === null ? 0 : counts[i];
    if (c > 0) {
      hit++;
    }
    perLine.push(c);
  }
  return { rel: rel, lines: lines, hit: hit, functions: functions,
           functionsHit: functionsHit, perLine: perLine,
           source: source.split('\n') };
}

// Every .js file in the tree that coverage COULD have reported, so a file that
// no test loads is a zero rather than an absence. It is the difference between
// "this service is 84% covered" and "the eight modules the tests load are".
function allSourceFiles(root) {
  const log = defaultLog();
  log.debug('Entering allSourceFiles(). root=' + root);
  const out = [];
  (function walk(dir) {
    let entries = [];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch (e) {
      return;
    }
    entries.forEach(function (e) {
      const full = path.join(dir, e.name);
      const rel = path.relative(root, full);
      if (SKIP_DIR.test(rel)) {
        return;
      }
      if (e.isDirectory()) {
        walk(full);
      } else if (/\.js$/.test(e.name)) {
        out.push(rel);
      }
    });
  })(root);
  log.debug('Leaving allSourceFiles(). ' + out.length + ' file(s).');
  return out.sort();
}

function pct(hit, total) {
  if (!total) {
    return 100;
  }
  return Math.round((hit / total) * 1000) / 10;
}

function escapeHtml(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

const STYLE = [
  ':root{color-scheme:light dark;--fg:#1a1a1a;--bg:#fbfbfa;--muted:#6b6b6b;',
  '--line:#e3e3e0;--card:#fff;--good:#1a7f37;--mid:#8a6d00;--bad:#b3261e;',
  '--hitbg:rgba(26,127,55,.10);--missbg:rgba(179,38,30,.13);}',
  '@media (prefers-color-scheme:dark){:root{--fg:#e6e6e6;--bg:#171717;',
  '--muted:#a0a0a0;--line:#333;--card:#1f1f1f;--good:#4ac26b;--mid:#d4a72c;',
  '--bad:#ff7b72;--hitbg:rgba(74,194,107,.10);--missbg:rgba(255,123,114,.16);}}',
  'body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 -apple-system,',
  'BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;}',
  '.wrap{max-width:1100px;margin:0 auto;padding:24px 20px 64px;}',
  'h1{font-size:20px;margin:0 0 4px;}h2{font-size:16px;margin:28px 0 8px;}',
  '.sub{color:var(--muted);margin:0 0 16px;}',
  'table{border-collapse:collapse;width:100%;background:var(--card);',
  'border:1px solid var(--line);border-radius:8px;overflow:hidden;}',
  'th,td{text-align:left;padding:6px 10px;border-bottom:1px solid var(--line);}',
  'th{font-size:12px;color:var(--muted);}tr:last-child td{border-bottom:none;}',
  'th.num{text-align:right;}',
  'td.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap;}',
  '.good{color:var(--good);}.mid{color:var(--mid);}.bad{color:var(--bad);}',
  'code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;',
  'font-size:12px;}',
  '.src{background:var(--card);border:1px solid var(--line);border-radius:8px;',
  'overflow-x:auto;}',
  '.src table{border:none;border-radius:0;}',
  '.src td{border:none;padding:0 8px;white-space:pre;font-family:ui-monospace,',
  'SFMono-Regular,Menlo,Consolas,monospace;font-size:12px;line-height:1.45;}',
  '.src td.ln,.src td.ct{color:var(--muted);text-align:right;user-select:none;',
  'font-variant-numeric:tabular-nums;}',
  '.hit{background:var(--hitbg);}.miss{background:var(--missbg);}',
  '.bar{display:inline-block;width:110px;height:8px;border-radius:4px;',
  'background:var(--line);vertical-align:middle;overflow:hidden;}',
  '.bar span{display:block;height:100%;background:var(--good);}',
  '.banner{padding:10px 14px;border-radius:8px;border:1px solid var(--line);',
  'background:var(--card);margin:14px 0;}',
  'details{margin:8px 0;}summary{cursor:pointer;}'
].join('');

function klass(p) {
  return p >= 80 ? 'good' : (p >= 50 ? 'mid' : 'bad');
}

function bar(p) {
  return '<span class="bar"><span style="width:' + p + '%"></span></span>';
}

function fileSlug(rel) {
  return rel.replace(/[^A-Za-z0-9]+/g, '-');
}

// ---------------------------------------------------------------------------
// One annotated source page. Every executable line carries the number of times
// it ran; an uncovered one is marked. No script — the same rule the console
// and the test report hold, and here it also means the page opens instantly
// from a file:// URL on a machine with nothing installed.
// ---------------------------------------------------------------------------
function writeFilePage(outDir, summary) {
  const rows = summary.source.map(function (line, i) {
    const c = summary.perLine[i];
    const cls = c === null ? '' : (c > 0 ? 'hit' : 'miss');
    return '<tr class="' + cls + '"><td class="ln">' + (i + 1) +
      '</td><td class="ct">' + (c === null ? '' : (c > 0 ? c + '×' : '0')) +
      '</td><td>' + escapeHtml(line) + '</td></tr>';
  }).join('');
  const html = '<!doctype html><html lang="en"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width,initial-scale=1">' +
    '<title>' + escapeHtml(summary.rel) + ' — coverage</title><style>' +
    STYLE + '</style></head><body><div class="wrap">' +
    '<p class="sub"><a href="../index.html">← all files</a></p>' +
    '<h1>' + escapeHtml(summary.rel) + '</h1>' +
    '<p class="sub">' + summary.hit + '/' + summary.lines + ' lines (' +
    pct(summary.hit, summary.lines) + '%), ' + summary.functionsHit + '/' +
    summary.functions + ' functions (' +
    pct(summary.functionsHit, summary.functions) + '%)</p>' +
    '<div class="src"><table>' + rows + '</table></div>' +
    '</div></body></html>';
  fs.writeFileSync(path.join(outDir, 'files', fileSlug(summary.rel) + '.html'),
                   html);
}

// LCOV, so that anything standard — genhtml, a CI plug-in, an editor gutter —
// can read this run without knowing about the HTML above.
function writeLcov(outFile, summaries) {
  const log = defaultLog();
  log.debug('Entering writeLcov(). ' + summaries.length + ' file(s).');
  const out = [];
  summaries.forEach(function (s) {
    out.push('SF:' + s.rel);
    out.push('FNF:' + s.functions);
    out.push('FNH:' + s.functionsHit);
    s.perLine.forEach(function (c, i) {
      if (c !== null) {
        out.push('DA:' + (i + 1) + ',' + c);
      }
    });
    out.push('LF:' + s.lines);
    out.push('LH:' + s.hit);
    out.push('end_of_record');
  });
  fs.writeFileSync(outFile, out.join('\n') + '\n');
  log.debug('Leaving writeLcov().');
}

// ---------------------------------------------------------------------------
// The whole thing. `inputs` is one entry per COLUMN — the in-process suite and
// the protocol jobs are collected separately so the report can say which half
// of the run reached a file, which is the question somebody writing the next
// test actually has.
// ---------------------------------------------------------------------------
function render(opts) {
  const log = opts.log || defaultLog();
  log.debug('Entering render().');
  const root = opts.root;
  const outDir = opts.outDir;
  fs.mkdirSync(path.join(outDir, 'files'), { recursive: true });

  const sets = {};
  let combined = {};
  const labels = [];
  opts.inputs.forEach(function (input) {
    const merged = mergeLabel(readRaw(input.dir, log), log);
    sets[input.label] = merged;
    combined = addSets(combined, merged);
    labels.push(input.label);
  });

  // Which files to report on: every source file in the tree, so that one that
  // no test loads is a nought rather than a silence.
  const known = {};
  Object.keys(combined).forEach(function (url) {
    const rel = fileOf(url, root);
    if (rel) {
      known[rel] = (known[rel] || {});
      Object.keys(combined[url]).forEach(function (k) {
        known[rel][k] = combined[url][k];
      });
    }
  });
  const everyFile = allSourceFiles(root);
  const perLabelByFile = {};
  labels.forEach(function (label) {
    perLabelByFile[label] = {};
    Object.keys(sets[label]).forEach(function (url) {
      const rel = fileOf(url, root);
      if (!rel) {
        return;
      }
      const into = perLabelByFile[label][rel] = perLabelByFile[label][rel] || {};
      Object.keys(sets[label][url]).forEach(function (k) {
        into[k] = sets[label][url][k];
      });
    });
  });

  const summaries = [];
  const neverLoaded = [];
  everyFile.forEach(function (rel) {
    if (!known[rel]) {
      neverLoaded.push(rel);
      return;
    }
    // FUNCTIONS come from the merged set, where a key union is exactly right:
    // V8 compiles lazily, so one domain can report a function the other never
    // saw, and a function is covered when ANY of them called it.
    const s = summariseFile(rel, root, known[rel]);
    if (!s) {
      return;
    }
    // LINES DO NOT, AND THIS IS THE ONE PLACE THE MERGE HAD TO BE THOUGHT
    // ABOUT RATHER THAN WRITTEN. V8's block ranges are not the same in two
    // processes — a branch one of them never entered is a range the other
    // does not have at all — so unioning the RANGES and then reading lines off
    // the union lets a 0-count block from the protocol run sit inside a
    // covered function from the unit run and mark its lines missed. It showed
    // up as a file whose combined percentage was BELOW one of its columns,
    // which is arithmetically impossible for a union and is what sent anybody
    // looking. So each domain's lines are derived on its OWN ranges and then
    // added: a line is covered when any run covered it, and its count is the
    // total across runs.
    const perLabel = {};
    labels.forEach(function (label) {
      perLabel[label] = perLabelByFile[label][rel]
        ? summariseFile(rel, root, perLabelByFile[label][rel])
        : null;
    });
    const contributing = labels.map(function (l) { return perLabel[l]; })
      .filter(Boolean);
    if (contributing.length) {
      for (let i = 0; i < s.perLine.length; i++) {
        if (s.perLine[i] === null) {
          continue;
        }
        let total = 0;
        contributing.forEach(function (one) {
          const c = one.perLine[i];
          if (c) {
            total += c;
          }
        });
        s.perLine[i] = total;
      }
      s.hit = s.perLine.filter(function (c) {
        return c !== null && c > 0;
      }).length;
    }
    s.byLabel = {};
    labels.forEach(function (label) {
      s.byLabel[label] = perLabel[label]
        ? pct(perLabel[label].hit, perLabel[label].lines) : null;
    });
    summaries.push(s);
    writeFilePage(outDir, s);
  });

  // The totals INCLUDE the files nothing loaded, counted as zero — the whole
  // point of listing them. Their line count is read the same way as everything
  // else's so the denominator is the same kind of number.
  let totalLines = 0;
  let totalHit = 0;
  let totalFns = 0;
  let totalFnsHit = 0;
  summaries.forEach(function (s) {
    totalLines += s.lines;
    totalHit += s.hit;
    totalFns += s.functions;
    totalFnsHit += s.functionsHit;
  });
  let unloadedLines = 0;
  neverLoaded.forEach(function (rel) {
    let source;
    try {
      source = fs.readFileSync(path.join(root, rel), 'utf8');
    } catch (e) {
      return;
    }
    const { executable } = executableLines(source);
    unloadedLines += executable.filter(Boolean).length;
  });

  summaries.sort(function (a, b) {
    return pct(a.hit, a.lines) - pct(b.hit, b.lines) ||
      a.rel.localeCompare(b.rel);
  });

  let html = '<!doctype html><html lang="en"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width,initial-scale=1">' +
    '<title>mock STS coverage</title><style>' + STYLE +
    '</style></head><body><div class="wrap">';
  html += '<h1>mock STS coverage</h1><p class="sub">' +
    new Date().toISOString() + ' · rendered from V8\'s own data, no ' +
    'instrumentation and no dependencies</p>';
  html += '<div class="banner"><strong>How to read this.</strong> ' +
    '<em>Functions</em> is exact — V8 counted the calls. <em>Lines</em> is ' +
    'derived: a line\'s count is that of the innermost V8 range containing ' +
    'its first non-blank character, and a line counts as code when it is ' +
    'neither blank nor wholly a comment. There are no branch numbers, ' +
    'because V8\'s block ranges are not branch arms and a percentage with no ' +
    'definition is worse than none. Files nothing loaded are listed at the ' +
    'bottom and are the honest half of the picture: this service has ' +
    'sixteen protocol families and the in-process suite reaches the module ' +
    'contracts it was written for.</div>';
  html += '<table><tr><th>total</th><th class="num">lines</th>' +
    '<th class="num">functions</th></tr>' +
    '<tr><td>files V8 loaded (' + summaries.length + ')</td>' +
    '<td class="num ' + klass(pct(totalHit, totalLines)) + '">' +
    pct(totalHit, totalLines) + '% ' + bar(pct(totalHit, totalLines)) +
    ' <span class="sub">' + totalHit + '/' + totalLines + '</span></td>' +
    '<td class="num ' + klass(pct(totalFnsHit, totalFns)) + '">' +
    pct(totalFnsHit, totalFns) + '% <span class="sub">' + totalFnsHit + '/' +
    totalFns + '</span></td></tr>' +
    '<tr><td>the whole tree (' + (summaries.length + neverLoaded.length) +
    ' files)</td><td class="num ' +
    klass(pct(totalHit, totalLines + unloadedLines)) + '">' +
    pct(totalHit, totalLines + unloadedLines) + '% ' +
    bar(pct(totalHit, totalLines + unloadedLines)) +
    ' <span class="sub">' + totalHit + '/' + (totalLines + unloadedLines) +
    '</span></td><td class="num"></td></tr></table>';

  html += '<h2>By file</h2><table><tr><th>file</th><th class="num">lines</th>' +
    '<th class="num">functions</th>' + labels.map(function (l) {
      return '<th class="num">' + escapeHtml(l) + '</th>';
    }).join('') + '</tr>';
  summaries.forEach(function (s) {
    const p = pct(s.hit, s.lines);
    html += '<tr><td><a href="files/' + fileSlug(s.rel) + '.html"><code>' +
      escapeHtml(s.rel) + '</code></a></td>' +
      '<td class="num ' + klass(p) + '">' + p + '% ' + bar(p) +
      ' <span class="sub">' + s.hit + '/' + s.lines + '</span></td>' +
      '<td class="num ' + klass(pct(s.functionsHit, s.functions)) + '">' +
      pct(s.functionsHit, s.functions) + '%</td>' +
      labels.map(function (l) {
        return '<td class="num">' + (s.byLabel[l] === null ? '—'
          : s.byLabel[l] + '%') + '</td>';
      }).join('') + '</tr>';
  });
  html += '</table>';

  if (neverLoaded.length) {
    html += '<h2>Never loaded (' + neverLoaded.length + ' files, about ' +
      unloadedLines + ' lines)</h2>' +
      '<details><summary>What no job in this run required at all</summary>' +
      '<table>' + neverLoaded.map(function (rel) {
        return '<tr><td><code>' + escapeHtml(rel) + '</code></td></tr>';
      }).join('') + '</table></details>';
  }
  html += '</div></body></html>';
  const htmlFile = path.join(outDir, 'index.html');
  fs.writeFileSync(htmlFile, html);
  writeLcov(path.join(outDir, 'lcov.info'), summaries);

  const summary = {
    files: summaries.length, neverLoaded: neverLoaded.length,
    lines: totalLines, linesHit: totalHit,
    linesPct: pct(totalHit, totalLines),
    treePct: pct(totalHit, totalLines + unloadedLines),
    functions: totalFns, functionsHit: totalFnsHit,
    functionsPct: pct(totalFnsHit, totalFns)
  };
  fs.writeFileSync(path.join(outDir, 'summary.json'),
                   JSON.stringify(summary, null, 2) + '\n');
  log.info('coverage: ' + summary.linesPct + '% of the ' + summary.files +
           ' files loaded (' + summary.treePct + '% of the whole tree), ' +
           summary.functionsPct + '% of functions.');
  log.debug('Leaving render().');
  return { htmlFile: htmlFile, lcovFile: path.join(outDir, 'lcov.info'),
           summary: summary };
}

// Standalone: render whatever raw data is already on disk. Useful after a run
// that was interrupted before it rendered, and for pointing at a directory
// somebody else's run produced.
function main() {
  const log = defaultLog();
  log.debug('Entering main().');
  const args = process.argv.slice(2);
  const inputs = [];
  let outDir = path.resolve(__dirname, '..', '..', 'coverage');
  let root = path.resolve(__dirname, '..', '..');
  args.forEach(function (a) {
    if (a.indexOf('--in=') === 0) {
      const spec = a.slice('--in='.length);
      const at = spec.indexOf(':');
      inputs.push({ label: spec.slice(0, at), dir: path.resolve(spec.slice(at + 1)) });
    } else if (a.indexOf('--out=') === 0) {
      outDir = path.resolve(a.slice('--out='.length));
    } else if (a.indexOf('--root=') === 0) {
      root = path.resolve(a.slice('--root='.length));
    }
  });
  if (!inputs.length) {
    inputs.push({ label: 'unit', dir: path.join(outDir, 'raw', 'unit') });
    inputs.push({ label: 'protocol', dir: path.join(outDir, 'raw', 'protocol') });
  }
  const out = render({ inputs: inputs, outDir: outDir, root: root });
  process.stdout.write(out.htmlFile + '\n');
  log.debug('Leaving main().');
}

if (require.main === module) {
  main();
}

module.exports = { render: render, executableLines: executableLines,
                   countsByLine: countsByLine };
