#!/usr/bin/env node
/**
 * tessl-audit.js — Security posture report for plugins declared in tessl.json
 *
 * Usage:
 *   npx tessl-audit [--json] [--version] [--help] [path/to/tessl.json]
 *
 * The script reads tessl.json, fetches live security data from the Tessl
 * registry via `tessl tile info`, then renders a table with:
 *
 *   • Plugin type   docs / skill / rules / skill+rules
 *   • Quality       Registry quality score (%)
 *   • Uplift        Agent uplift multiplier from registry
 *   • Security      Passed / Advisory / Risky / Critical / Not run / Unknown
 *   • Warnings      Count + codes from the registry security scan
 *   • Report URL    Direct link to the full registry security page
 *
 * Additional sections:
 *   • Quality & Uplift stats — averages, ranges, worst performers
 *   • Recommended Actions — targeted tessl CLI commands to improve quality,
 *     run missing evals, and invoke the skill-optimizer
 */

'use strict';

const fs     = require('fs');
const path   = require('path');
const { execFile } = require('child_process');
const { version: VERSION } = require('./package.json');

// ─── config ─────────────────────────────────────────────────────────────────

const REGISTRY_BASE = 'https://tessl.io/registry';
const CONCURRENCY   = 6;   // parallel `tessl tile info` calls

// ─── ANSI colour helpers ─────────────────────────────────────────────────────

const isTTY = process.stdout.isTTY;

function color(code) { return (s) => isTTY ? `\x1b[${code}m${s}\x1b[0m` : s; }
const green  = color('32');
const yellow = color('33');
const red    = color('31');
const dim    = color('2');
const bold   = color('1');
const orange = color('38;5;208');

function securityColor(status) {
  if (status === 'Passed')   return green;
  if (status === 'Advisory') return yellow;
  if (status === 'Risky')    return orange;
  if (status === 'Critical') return red;
  if (status === 'Not run')  return dim;
  if (status === 'n/a')      return dim;
  return (s) => s;
}

// ─── input validation ────────────────────────────────────────────────────────

// Alphanumeric start required — blocks leading dots, `..`, and path traversal attempts.
const DEP_NAME_RE = /^[a-zA-Z0-9][a-zA-Z0-9_-]*\/[a-zA-Z0-9][a-zA-Z0-9_-]*$/;

function validateDepName(name) {
  return DEP_NAME_RE.test(name);
}

function stripAnsi(s) {
  return String(s)
    .replace(/\x1b\[[0-9;]*[a-zA-Z]/g, '')              // CSI sequences (e.g. colours)
    .replace(/\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)/g, ''); // OSC sequences (e.g. hyperlinks)
}

// ─── plugin local analysis ───────────────────────────────────────────────────

function classifyPlugin(plugin) {
  const hasSkills = plugin.skills && Object.keys(plugin.skills).length > 0;
  const hasRules  = plugin.rules  && Object.keys(plugin.rules).length  > 0;
  const isDocs    = Boolean(plugin.describes);

  let type;
  if (isDocs && !hasSkills && !hasRules) type = 'docs';
  else if (hasSkills && hasRules)         type = 'skill+rules';
  else if (hasSkills)                     type = 'skill';
  else if (hasRules)                      type = 'rules';
  else                                    type = 'docs';

  return {
    type,
    skillCount: hasSkills ? Object.keys(plugin.skills).length : 0,
    ruleCount:  hasRules  ? Object.keys(plugin.rules).length  : 0,
  };
}

// ─── registry fetch ──────────────────────────────────────────────────────────

function fetchPluginInfo(pluginName) {
  if (!validateDepName(pluginName)) {
    return Promise.resolve({ ok: false, raw: `Skipped: invalid plugin name "${pluginName}"` });
  }
  return new Promise((resolve) => {
    execFile('tessl', ['tile', 'info', pluginName], { timeout: 20_000 }, (err, stdout, stderr) => {
      if (err) return resolve({ ok: false, raw: stderr || err.message });
      resolve({ ok: true, raw: stdout });
    });
  });
}

/*
 * Parse the human-readable output of `tessl tile info`.
 * Example lines we care about:
 *   Verified           ✔  (or  -)
 *   Passed Moderation  ✔  (or  ✖)
 *   ✔ Quality   84%
 *   ✔ Uplift    ↑1.78x
 *   ✔ Security  Passed · No known issues
 *   ⚠ Security  Advisory · Suggest reviewing before use
 *   ⚠ Security review has not been run yet.
 *     W011 Third-party content exposure detected …
 *     View full report: https://tessl.io/registry/…/security
 */
function parsePluginInfo(raw) {
  const lines = raw.split('\n');
  const result = {
    quality:          null,
    uplift:           null,
    security:         'Unknown',
    warnings:         [],
    reportUrl:        null,
    verified:         null,
    passedModeration: null,
  };

  let inSecurity = false;

  for (const line of lines) {
    // Match quality/uplift on the raw line — the stripped version removes % and spaces
    const qualityMatch = line.match(/Quality\s+(\d+%)/);
    if (qualityMatch) { result.quality = qualityMatch[1]; inSecurity = false; continue; }

    const upliftMatch = line.match(/Uplift\s+([↑↓][\d.]+x)/);
    if (upliftMatch) { result.uplift = upliftMatch[1]; inSecurity = false; continue; }

    // Character range 0x20 (space) through 0x2D (dash) — removes spaces and
    // intervening punctuation to normalise lines with variable whitespace/symbols.
    const stripped = line.replace(/[ --]/g, '').trim();

    if (/^Verified/.test(stripped)) {
      result.verified = stripped.includes('✔');
      continue;
    }
    if (/^PassedModeration/.test(stripped)) {
      result.passedModeration = stripped.includes('✔');
      continue;
    }

    if (/Security/.test(stripped)) {
      inSecurity = true;
      if (/Critical/.test(stripped))   { result.security = 'Critical'; continue; }
      if (/Risky/.test(stripped))      { result.security = 'Risky';    continue; }
      if (/Advisory/.test(stripped))   { result.security = 'Advisory'; continue; }
      if (/Passed/.test(stripped))     { result.security = 'Passed';   continue; }
      if (/notbeenrun/.test(stripped)) { result.security = 'Not run'; inSecurity = false; continue; }
      continue;
    }

    if (inSecurity) {
      const trimmed = line.trim();

      const reportMatch = trimmed.match(/View full report:\s*(https?:\/\/\S+)/);
      if (reportMatch) { result.reportUrl = stripAnsi(reportMatch[1]); inSecurity = false; continue; }

      const warnMatch = trimmed.match(/^(W\d+)\s+(.+)/);
      if (warnMatch) { result.warnings.push({ code: warnMatch[1], message: stripAnsi(warnMatch[2]) }); continue; }

      if (trimmed === '') inSecurity = false;
    }
  }

  return result;
}

// ─── numeric parsers ─────────────────────────────────────────────────────────

function parseQuality(q) {
  const m = String(q || '').match(/(\d+)/);
  return m ? parseInt(m[1], 10) : null;
}

function parseUplift(u) {
  const m = String(u || '').match(/([\d.]+)x/);
  return m ? parseFloat(m[1]) : null;
}

// ─── concurrency pool ────────────────────────────────────────────────────────

async function runConcurrent(items, fn, limit) {
  const results = new Array(items.length);
  let index = 0;
  async function worker() {
    while (index < items.length) {
      const i = index++;
      results[i] = await fn(items[i], i);
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return results;
}

// ─── table renderer ──────────────────────────────────────────────────────────

function pad(s, n, right = false) {
  const str   = String(s ?? '');
  const vis   = str.replace(/\x1b\[[0-9;]*m/g, '');
  const extra = str.length - vis.length;
  const target = n + extra;
  const padded = right ? str.padStart(target) : str.padEnd(target);
  if (vis.length > n) return str.slice(0, n - 1 + extra) + '…';
  return padded;
}

function printTable(rows) {
  const cols = [
    { key: 'plugin',   label: 'Plugin',   width: 36 },
    { key: 'version',  label: 'Version',  width: 10 },
    { key: 'type',     label: 'Type',     width: 12 },
    { key: 'quality',  label: 'Quality',  width: 8, right: true },
    { key: 'uplift',   label: 'Uplift',   width: 8, right: true },
    { key: 'security', label: 'Security', width: 10 },
    { key: 'warnings', label: 'Warnings', width: 10 },
  ];

  const sep  = ' │ ';
  const hr   = cols.map(c => '─'.repeat(c.width)).join('─┼─');
  const head = cols.map(c => bold(pad(c.label, c.width, c.right))).join(sep);

  console.log();
  console.log('  ' + head);
  console.log('  ' + hr);

  for (const row of rows) {
    const secCol = securityColor(row.security)(pad(row.security, cols[5].width));
    const cells  = cols.map((c, i) => i === 5 ? secCol : pad(row[c.key], c.width, c.right));
    console.log('  ' + cells.join(sep));
  }

  console.log('  ' + hr);
  console.log();
}

function printSummary(rows) {
  const bySec  = {};
  let warnings = 0;
  for (const r of rows) {
    bySec[r.security] = (bySec[r.security] ?? 0) + 1;
    warnings += r.warningCount;
  }

  console.log(bold('Summary'));
  console.log('─'.repeat(44));
  console.log(`  Total plugins : ${rows.length}`);
  for (const [status, count] of Object.entries(bySec)) {
    console.log(`  ${securityColor(status)(status.padEnd(12))}: ${count}`);
  }
  if (warnings > 0) console.log(`  Total warnings: ${yellow(String(warnings))}`);
  console.log();
}

function printWarnings(rows) {
  const critical = rows.filter(r => r.security === 'Critical' && r.warningsList.length > 0);
  const risky    = rows.filter(r => r.security === 'Risky'    && r.warningsList.length > 0);
  const advisory = rows.filter(r => r.security === 'Advisory' && r.warningsList.length > 0);

  if (!critical.length && !risky.length && !advisory.length) return;

  console.log(bold('Security Findings'));
  console.log('─'.repeat(44));

  function printGroup(label, colorFn, group) {
    if (!group.length) return;
    console.log(colorFn(`\n${label}:`));
    for (const r of group) {
      console.log(`  • ${bold(r.plugin)}`);
      if (r.reportUrl) console.log(`    ${dim(r.reportUrl)}`);
      const grouped = new Map();
      for (const w of r.warningsList) {
        if (!grouped.has(w.code)) grouped.set(w.code, { count: 0, message: w.message });
        grouped.get(w.code).count++;
      }
      for (const [code, { count, message }] of grouped) {
        const countStr = count > 1 ? ` ×${count}` : '';
        console.log(`    ${colorFn(code + countStr)}  ${message}`);
      }
    }
  }

  printGroup('Critical plugins — do not use without review', red,    critical);
  printGroup('Risky plugins — do not use without review',    orange, risky);
  printGroup('Advisory plugins — worth reviewing',           yellow, advisory);

  console.log();
}

// ─── quality / uplift stats & CTAs ──────────────────────────────────────────

function printStatsAndCTAs(rows) {
  const activeRows = rows.filter(r => r.type !== 'docs' && r.type !== '?');

  const withQuality = activeRows
    .map(r => ({ ...r, qn: parseQuality(r.quality) }))
    .filter(r => r.qn !== null);

  const withUplift = activeRows
    .map(r => ({ ...r, un: parseUplift(r.uplift) }))
    .filter(r => r.un !== null);

  const noEvals = activeRows.filter(
    r => (r.type === 'skill' || r.type === 'skill+rules') && r.uplift === '-'
  );

  console.log(bold('Quality & Uplift'));
  console.log('─'.repeat(44));

  if (!withQuality.length) {
    console.log('  No quality data available.\n');
    return;
  }

  const qAvg    = Math.round(withQuality.reduce((s, r) => s + r.qn, 0) / withQuality.length);
  const qMin    = Math.min(...withQuality.map(r => r.qn));
  const qMax    = Math.max(...withQuality.map(r => r.qn));
  const below80 = withQuality.filter(r => r.qn < 80).sort((a, b) => a.qn - b.qn);

  console.log(`  Quality  avg ${bold(qAvg + '%')}  range ${qMin}%–${qMax}%  below 80%: ${below80.length}`);

  const lowImpact = withUplift.filter(r => r.un < 1.2);
  if (withUplift.length) {
    const uAvg = (withUplift.reduce((s, r) => s + r.un, 0) / withUplift.length).toFixed(2);
    const uMin = Math.min(...withUplift.map(r => r.un)).toFixed(2);
    const uMax = Math.max(...withUplift.map(r => r.un)).toFixed(2);
    console.log(`  Uplift   avg ↑${bold(uAvg + 'x')}  range ↑${uMin}x–↑${uMax}x  low impact (<1.2x): ${lowImpact.length}`);
  }

  if (noEvals.length) {
    console.log(`  No evals : ${noEvals.length} skill plugin(s) have no uplift data`);
  }

  console.log();
  console.log(bold('Recommended Actions'));
  console.log('─'.repeat(44));

  if (below80.length) {
    console.log(`\n  Quality Review  (${below80.length} plugin${below80.length !== 1 ? 's' : ''} below 80%)`);
    for (const r of below80) {
      console.log(`    ${String(r.qn + '%').padStart(4)}  ${r.plugin}`);
    }
    console.log(`\n  Run:  tessl skill review --optimize <plugin>`);
    console.log(`  e.g.  tessl skill review --optimize ${below80[0].plugin}`);
  }

  if (noEvals.length) {
    console.log(`\n  Evals Needed  (${noEvals.length} plugin${noEvals.length !== 1 ? 's' : ''})`);
    for (const r of noEvals) {
      console.log(`    ${r.plugin}`);
    }
    console.log(`\n  Generate scenarios first, then run the eval:`);
    console.log(`    1. tessl scenario generate --count 5 <plugin>`);
    console.log(`    2. tessl eval run <plugin>`);
    console.log(`  e.g.  tessl scenario generate --count 5 ${noEvals[0].plugin}`);
    console.log(`        tessl eval run ${noEvals[0].plugin}`);
  }

  if (lowImpact.length || noEvals.length) {
    const targets = [...new Set([...lowImpact, ...noEvals])].slice(0, 6);
    console.log(`\n  Skill Optimizer  (improve quality and eval scores)`);
    console.log(`    tessl install tessl-labs/skill-optimizer   # install once`);
    console.log(`    Then invoke /tessl__skill-optimizer in Claude Code`);
    if (targets.length) {
      console.log(`  Priority targets:`);
      for (const r of targets) {
        console.log(`    ${r.plugin}`);
      }
    }
  }

  console.log();
  console.log(bold('Further Reading'));
  console.log('─'.repeat(44));
  console.log(`  Evals & scenarios  ${dim('https://docs.tessl.io/evaluate/evaluate-skill-quality-using-scenarios')}`);
  console.log(`  Reviewing plugins  ${dim('https://docs.tessl.io/evaluate/evaluating-skills')}`);
  console.log(`  Skill Optimizer    ${dim('https://tessl.io/registry/tessl-labs/skill-optimizer')}`);
  console.log();
}

// ─── auth preflight ──────────────────────────────────────────────────────────

function checkAuth(json) {
  return new Promise((resolve) => {
    execFile('tessl', ['whoami'], { timeout: 10_000 }, (err) => {
      if (err) {
        const notFound = err.code === 'ENOENT';
        if (json) {
          const payload = notFound
            ? { error: 'tessl_not_found', message: 'tessl CLI not found — install with: npm i -g tessl', docs: 'https://docs.tessl.io/introduction-to-tessl/installation' }
            : { error: 'not_authenticated', message: 'Run: tessl auth login', docs: 'https://docs.tessl.io/introduction-to-tessl/installation' };
          process.stderr.write(JSON.stringify(payload) + '\n');
        } else if (notFound) {
          console.error('Error: tessl CLI not found.');
          console.error('Install: npm i -g tessl');
          console.error('Docs: https://docs.tessl.io/introduction-to-tessl/installation');
        } else {
          console.error('Error: not authenticated with Tessl.');
          console.error('Run:  tessl auth login');
          console.error('Docs: https://docs.tessl.io/introduction-to-tessl/installation');
        }
        process.exit(1);
      }
      resolve();
    });
  });
}

// ─── main ────────────────────────────────────────────────────────────────────

async function main() {
  const args    = process.argv.slice(2);
  const json    = args.includes('--json');
  const argFile = args.find(a => !a.startsWith('--'));

  if (args.includes('--version') || args.includes('-v')) {
    console.log(VERSION);
    process.exit(0);
  }

  if (args.includes('--help') || args.includes('-h')) {
    console.log(`
Usage: tessl-audit [options] [path/to/tessl.json]

Options:
  --json        Emit machine-readable JSON instead of the table
  --version     Print version and exit
  --help        Print this help and exit

Reads tessl.json and reports security, quality, and uplift data
for every installed plugin from the Tessl registry.

Docs: https://github.com/AI-Native-Dev-Community/tessl-audit
    `.trim());
    process.exit(0);
  }

  const tessljsonPath = argFile
    ? path.resolve(argFile)
    : path.join(process.cwd(), 'tessl.json');

  if (!fs.existsSync(tessljsonPath)) {
    console.error(`Error: tessl.json not found at ${tessljsonPath}`);
    console.error(`To create one, run: tessl init`);
    console.error(`Docs: https://docs.tessl.io/reference/configuration#tessl.json`);
    process.exit(1);
  }

  let tessljson;
  try {
    tessljson = JSON.parse(fs.readFileSync(tessljsonPath, 'utf8'));
  } catch {
    console.error(`Error: could not parse tessl.json at ${tessljsonPath}`);
    console.error(`Docs: https://docs.tessl.io/reference/configuration#tessl.json`);
    process.exit(1);
  }

  const projectRoot = path.dirname(tessljsonPath);
  const pluginsDir  = path.join(projectRoot, '.tessl', 'tiles');
  const deps        = Object.entries(tessljson.dependencies ?? {});

  if (!json) {
    console.log(`\nTessl Plugin Security Posture Report`);
    console.log(`${'═'.repeat(80)}`);
    console.log(`Project : ${tessljson.name ?? path.basename(projectRoot)}`);
    console.log(`File    : ${tessljsonPath}`);
    console.log(`Plugins : ${deps.length}`);
  }

  await checkAuth(json);

  if (!json) {
    process.stdout.write(`\nFetching registry data for ${deps.length} plugins`);
  }

  const rows = await runConcurrent(deps, async ([depName, depMeta]) => {
    if (!validateDepName(depName)) {
      if (!json) process.stdout.write('.');
      return null;
    }

    const [publisher, pkg] = depName.split('/');

    const pluginJsonPath     = path.join(pluginsDir, publisher, pkg, 'tile.json');
    const resolvedPluginJson = path.resolve(pluginJsonPath);
    const resolvedPluginsDir = path.resolve(pluginsDir);

    let pluginJson = null;
    let localType  = '?';
    let skillCount = 0;
    let ruleCount  = 0;

    if (resolvedPluginJson.startsWith(resolvedPluginsDir + path.sep) && fs.existsSync(resolvedPluginJson)) {
      try {
        pluginJson = JSON.parse(fs.readFileSync(resolvedPluginJson, 'utf8'));
        const c = classifyPlugin(pluginJson);
        localType  = c.type;
        skillCount = c.skillCount;
        ruleCount  = c.ruleCount;
      } catch { /* ignore unreadable tile.json */ }
    }

    let quality      = '-';
    let uplift       = '-';
    let security     = 'Unknown';
    let warningsList = [];
    let reportUrl    = `${REGISTRY_BASE}/${publisher}/${pkg}/security`;
    let verified     = null;
    let moderation   = null;

    if (!json) process.stdout.write('.');
    const { ok, raw } = await fetchPluginInfo(depName);
    if (ok) {
      const info   = parsePluginInfo(raw);
      quality      = info.quality      ?? '-';
      uplift       = info.uplift       ?? '-';
      security     = info.security;
      warningsList = info.warnings;
      if (info.reportUrl) reportUrl = info.reportUrl;
      verified     = info.verified;
      moderation   = info.passedModeration;
    }

    if (localType === 'docs' && (security === 'Unknown' || security === 'Not run')) {
      security = 'n/a';
    }

    return {
      plugin:       depName,
      version:      typeof depMeta === 'string' ? depMeta : (depMeta?.version ?? '-'),
      type:         localType,
      publisher,
      skillCount,
      ruleCount,
      quality,
      uplift,
      security,
      warningCount: warningsList.length,
      warnings:     warningsList.length > 0
                      ? `${warningsList.length} (${[...new Set(warningsList.map(w => w.code))].join(',')})`
                      : '-',
      warningsList,
      reportUrl,
      verified,
      moderation,
    };
  }, CONCURRENCY);

  if (!json) process.stdout.write('\n');

  const validRows = rows.filter(Boolean);

  const secOrder = { Critical: 0, Risky: 1, Advisory: 2, Unknown: 3, 'Not run': 4, Passed: 5, 'n/a': 6 };
  validRows.sort((a, b) => {
    const sd = (secOrder[a.security] ?? 9) - (secOrder[b.security] ?? 9);
    return sd !== 0 ? sd : a.plugin.localeCompare(b.plugin);
  });

  if (json) {
    const activeRows  = validRows.filter(r => r.type !== 'docs' && r.type !== '?');
    const withQuality = activeRows.map(r => ({ plugin: r.plugin, quality: parseQuality(r.quality) })).filter(r => r.quality !== null);
    const withUplift  = activeRows.map(r => ({ plugin: r.plugin, uplift: parseUplift(r.uplift) })).filter(r => r.uplift !== null);

    console.log(JSON.stringify({
      plugins: validRows.map(r => ({
        plugin:     r.plugin,
        version:    r.version,
        type:       r.type,
        publisher:  r.publisher,
        skillCount: r.skillCount,
        ruleCount:  r.ruleCount,
        quality:    r.quality,
        uplift:     r.uplift,
        security:   r.security,
        warnings:   r.warningsList,
        reportUrl:  r.reportUrl,
        verified:   r.verified,
        moderation: r.moderation,
      })),
      stats: {
        quality: withQuality.length ? {
          avg:     Math.round(withQuality.reduce((s, r) => s + r.quality, 0) / withQuality.length),
          min:     Math.min(...withQuality.map(r => r.quality)),
          max:     Math.max(...withQuality.map(r => r.quality)),
          below80: withQuality.filter(r => r.quality < 80).map(r => r.plugin),
        } : null,
        uplift: withUplift.length ? {
          avg:       parseFloat((withUplift.reduce((s, r) => s + r.uplift, 0) / withUplift.length).toFixed(2)),
          min:       Math.min(...withUplift.map(r => r.uplift)),
          max:       Math.max(...withUplift.map(r => r.uplift)),
          lowImpact: withUplift.filter(r => r.uplift < 1.2).map(r => r.plugin),
        } : null,
        noEvals: validRows
          .filter(r => (r.type === 'skill' || r.type === 'skill+rules') && r.uplift === '-')
          .map(r => r.plugin),
      },
    }, null, 2));
    return;
  }

  printTable(validRows);
  printSummary(validRows);
  printWarnings(validRows);
  printStatsAndCTAs(validRows);

  console.log(`${dim('Registry')} : ${REGISTRY_BASE}`);
  console.log(`${dim('Security')} : Passed=no issues  Advisory=worth reviewing  Risky/Critical=do not use without review`);
  console.log();
}

main().catch(e => { console.error(e.message); process.exit(1); });
