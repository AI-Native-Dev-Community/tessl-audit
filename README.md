# tessl-audit

[![npm version](https://img.shields.io/npm/v/tessl-audit.svg)](https://www.npmjs.com/package/tessl-audit)
[![License](https://img.shields.io/npm/l/tessl-audit.svg)](LICENSE)
[![Node.js](https://img.shields.io/node/v/tessl-audit.svg)](https://nodejs.org)

Security posture and quality report for the Tessl plugins installed in your project.

Run it in any project that has a `tessl.json` — no installation required:

```
npx tessl-audit
```

---

## Prerequisites

- [Node.js](https://nodejs.org) 18 or later
- A Tessl account, authenticated: `tessl auth login` (the CLI installs automatically)
- A `tessl.json` in your project root

---

## Usage

```
npx tessl-audit [--json] [path/to/tessl.json]
```

| Flag | Description |
|------|-------------|
| `--json` | Emit machine-readable JSON instead of the table (useful in CI) |
| `path/to/tessl.json` | Path to a specific `tessl.json` (defaults to `./tessl.json`) |

---

## What you get

### Security table

A row per plugin, sorted by risk (most critical first):

```
  Plugin                               │ Version    │ Type         │ Quality  │  Uplift  │ Security   │ Warnings
  ─────────────────────────────────────────────────────────────────────────────────────────────────────────────
  tessl-labs/intent-integrity-kit      │ 2.9.8      │ skill+rules  │     91%  │   ↑2.1x  │ Passed     │ -
  jbvc/frontend-patterns               │ 0.1.0      │ skill        │     63%  │       -  │ Advisory   │ 1 (W011)
  ...
```

**Columns explained:**

| Column | What it means |
|--------|---------------|
| Type | `docs`, `skill`, `rules`, or `skill+rules` |
| Quality | Registry quality score — how well-written and complete the plugin is (0–100%) |
| Uplift | How much the plugin improves agent task performance vs baseline (e.g. `↑2.1x`) |
| Security | Result of the registry security scan (see below) |
| Warnings | Count and codes of specific warnings from the scan |

**Security statuses:**

| Status | Meaning |
|--------|---------|
| `Passed` | No known issues |
| `Advisory` | Worth reviewing before use |
| `Risky` | Do not use without review |
| `Critical` | Do not use without review |
| `Not run` | Security scan hasn't been run yet |
| `Unknown` | Could not fetch data from registry |

### Summary section

Totals by security status, plus any flagged plugins with their warning codes and links to the full registry security report.

### Recommended Actions

After the table, the report gives you concrete next steps:

**Quality Review** — plugins scoring below 80% quality:
```
tessl skill review --optimize <publisher/plugin>
```

**Evals Needed** — skill plugins with no uplift data yet. Generate scenarios first, then run the eval:
```
tessl scenario generate --count 5 <publisher/plugin>
tessl eval run <publisher/plugin>
```

**Skill Optimizer** — for plugins with low uplift scores or no evals, the skill optimizer can help improve both:
```
tessl install tessl-labs/skill-optimizer   # install once
# then invoke /tessl__skill-optimizer in Claude Code
```

---

## JSON output

Use `--json` to get structured output for CI pipelines or dashboards:

```bash
npx tessl-audit --json | jq '.plugins[] | select(.security == "Critical")'
```

The JSON shape:

```json
{
  "plugins": [
    {
      "plugin": "publisher/plugin",
      "version": "1.0.0",
      "type": "skill",
      "quality": "84%",
      "uplift": "↑1.8x",
      "security": "Passed",
      "warnings": [],
      "reportUrl": "https://tessl.io/registry/publisher/plugin/security"
    }
  ],
  "stats": {
    "quality": { "avg": 82, "min": 63, "max": 97, "below80": ["jbvc/frontend-patterns"] },
    "uplift":  { "avg": 1.9, "min": 1.1, "max": 3.2, "lowImpact": [] },
    "noEvals": ["g14wxz/storage-resumable-upload"]
  }
}
```

---

## Use in CI

Add a quality gate to your pipeline:

```yaml
# GitHub Actions example
- name: Audit Tessl plugins
  run: |
    npx tessl-audit --json > audit.json
    # Fail if any Critical plugins are installed
    node -e "
      const fs = require('fs');
      const r = JSON.parse(fs.readFileSync('./audit.json', 'utf8'));
      const critical = r.plugins.filter(t => t.security === 'Critical');
      if (critical.length) {
        console.error('Critical plugins found:', critical.map(t => t.plugin));
        process.exit(1);
      }
    "
```

---

## Further reading

- [Evaluate skill quality using scenarios](https://docs.tessl.io/evaluate/evaluate-skill-quality-using-scenarios)
- [Review a skill against best practices](https://docs.tessl.io/evaluate/evaluating-skills)
- [Skill Optimizer plugin](https://tessl.io/registry/tessl-labs/skill-optimizer)
- [Tessl registry](https://tessl.io/registry)
