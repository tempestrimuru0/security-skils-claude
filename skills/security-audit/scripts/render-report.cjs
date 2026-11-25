#!/usr/bin/env node

'use strict';

const fs = require('node:fs');

const ORDER = ['critical', 'high', 'medium', 'low', 'informational'];

function location(f) {
  const step = Array.isArray(f.source_trace) ? f.source_trace[0] : null;
  if (step) return `${step.file}:${step.line}`;
  const parts = String(f.fingerprint ?? '').split(':');
  return parts.length >= 3 ? parts.slice(0, -1).join(':') : 'unknown';
}

function cell(text) {
  return String(text ?? '').replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
}

function render(findings, meta = {}) {
  const confirmed = findings
    .filter((f) => f.verdict === 'confirmed')
    .sort((a, b) => ORDER.indexOf(a.severity) - ORDER.indexOf(b.severity) || a.id.localeCompare(b.id));
  const needs = findings.filter((f) => f.verdict === 'needs_validation');
  const rejected = findings.filter((f) => f.verdict === 'rejected');

  const out = [];
  out.push(`# Security Audit: ${meta.name ?? 'repository'}`, '');
  out.push(`- Commit reviewed: ${meta.commit ?? 'N/A (not provided)'}`);
  out.push(`- Profile: ${meta.profile ?? 'standard'}`);
  out.push(`- Scope: ${meta.scope ?? 'whole repository'}`);
  out.push(`- Date: ${meta.date ?? new Date().toISOString().slice(0, 10)}`, '');

  out.push('## Coverage', '');
  out.push(meta.coverage ? meta.coverage.trim() : '_Not provided. State what was checked and what was not._');
  out.push('', 'This is one pass. It is not a claim that the repository is free of vulnerabilities.', '');

  out.push('## Summary', '', '| Severity | Count |', '|---|---|');
  for (const s of ORDER) out.push(`| ${s} | ${confirmed.filter((f) => f.severity === s).length} |`);
  out.push('', `Needs validation: ${needs.length}. Rejected candidates: ${rejected.length}.`, '');

  out.push('## Findings', '');
  if (confirmed.length === 0) out.push('No confirmed findings.', '');
  for (const f of confirmed) {
    out.push(`### ${f.id}: ${f.title ?? f.fingerprint} (${f.severity})`, '');
    out.push(`- Location: \`${location(f)}\``);
    out.push(`- Class: ${f.class}`);
    if (f.surface) out.push(`- Surface: ${f.surface}`);
    out.push(`- Attacker: ${f.attacker}`);
    out.push(`- Impact: ${f.impact}`);
    if (Array.isArray(f.source_trace) && f.source_trace.length > 0) {
      out.push('- Evidence:');
      for (const s of f.source_trace) out.push(`  - \`${s.file}:${s.line}\`: ${s.note}`);
    }
    out.push(`- Fix: ${f.fix}`, '');
  }

  out.push('## Needs validation', '');
  if (needs.length === 0) {
    out.push('None.', '');
  } else {
    out.push('| ID | Question | How to settle it |', '|---|---|---|');
    for (const f of needs) out.push(`| ${f.id} | ${cell(f.unresolved_fact)} | ${cell(f.validation_plan)} |`);
    out.push('');
  }

  if (rejected.length > 0) {
    out.push('## Rejected candidates', '', '| ID | Location | Reason |', '|---|---|---|');
    for (const f of rejected) out.push(`| ${f.id} | \`${location(f)}\` | ${cell(f.rejection_reason)} |`);
    out.push('');
  }

  return out.join('\n');
}

function parseArgs(argv) {
  const args = { file: null, meta: {}, output: null };
  const flags = { '--name': 'name', '--commit': 'commit', '--profile': 'profile', '--scope': 'scope', '--date': 'date' };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (flags[a]) {
      if (argv[i + 1] === undefined) return null;
      args.meta[flags[a]] = argv[++i];
    } else if (a === '--coverage') {
      if (argv[i + 1] === undefined) return null;
      try {
        args.meta.coverage = fs.readFileSync(argv[++i], 'utf8');
      } catch {
        return null;
      }
    } else if (a === '--output') {
      if (argv[i + 1] === undefined) return null;
      args.output = argv[++i];
    } else if (!args.file) {
      args.file = a;
    } else {
      return null;
    }
  }
  return args.file ? args : null;
}

function main(argv) {
  const args = parseArgs(argv);
  if (!args) {
    process.stderr.write('usage: node render-report.cjs <findings.json> [--name N] [--commit SHA] [--profile P] [--scope S] [--date D] [--coverage file.md] [--output REPORT.md]\n');
    return 2;
  }
  let findings;
  try {
    findings = JSON.parse(fs.readFileSync(args.file, 'utf8'));
  } catch (err) {
    process.stderr.write(`cannot read ${args.file}: ${err.message}\n`);
    return 2;
  }
  if (!Array.isArray(findings)) {
    process.stderr.write('findings.json must be an array\n');
    return 2;
  }
  const text = render(findings, args.meta);
  if (args.output) fs.writeFileSync(args.output, text);
  else process.stdout.write(text);
  return 0;
}

if (require.main === module) {
  process.exitCode = main(process.argv.slice(2));
}

module.exports = { render };
