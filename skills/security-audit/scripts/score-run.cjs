#!/usr/bin/env node

'use strict';

const fs = require('node:fs');
const path = require('node:path');

const DEFAULT_TOLERANCE = 3;

function parseFingerprint(fp) {
  const parts = String(fp ?? '').split(':');
  if (parts.length < 3) return null;
  const cls = parts.pop();
  const line = Number(parts.pop());
  const file = parts.join(':');
  if (!Number.isInteger(line)) return null;
  return { file, line, cls };
}

function sameFile(a, b) {
  return path.posix.basename(a.replace(/\\/g, '/')) === path.posix.basename(b.replace(/\\/g, '/'));
}

function score(findings, answerKey) {
  const items = answerKey.items ?? [];
  const used = new Set();
  const matches = new Map(); // item.key -> finding id

  for (const item of items) {
    const tol = item.tolerance ?? DEFAULT_TOLERANCE;
    const candidate = findings.find((f, idx) => {
      if (used.has(idx)) return false;
      const loc = parseFingerprint(f.fingerprint);
      if (!loc) return false;
      return sameFile(loc.file, item.file)
        && Math.abs(loc.line - item.line) <= tol
        && (item.accept_classes ?? [item.class]).includes(f.class)
        && (item.accept_verdicts ?? ['confirmed']).includes(f.verdict);
    });
    if (candidate) {
      used.add(findings.indexOf(candidate));
      matches.set(item.key, candidate.id);
    }
  }

  const major = items.filter((i) => !i.minor);
  const majorHit = major.filter((i) => matches.has(i.key));
  const allHit = items.filter((i) => matches.has(i.key));

  const falsePositives = findings.filter((f, idx) => {
    if (f.verdict !== 'confirmed') return false;
    if (used.has(idx)) return false;
    return true;
  });

  return {
    majorTotal: major.length,
    majorHit: majorHit.length,
    allTotal: items.length,
    allHit: allHit.length,
    missed: items.filter((i) => !matches.has(i.key)).map((i) => ({ key: i.key, minor: !!i.minor })),
    matches: Object.fromEntries(matches),
    falsePositives: falsePositives.map((f) => ({ id: f.id, fingerprint: f.fingerprint, title: f.title ?? '' })),
  };
}

function pct(a, b) {
  return b === 0 ? 'n/a' : `${Math.round((a / b) * 100)}%`;
}

function main(argv) {
  if (argv.length !== 2) {
    process.stderr.write('usage: node score-run.cjs <findings.json> <expected.json>\n');
    return 2;
  }
  let findings;
  let answerKey;
  try {
    findings = JSON.parse(fs.readFileSync(argv[0], 'utf8'));
    answerKey = JSON.parse(fs.readFileSync(argv[1], 'utf8'));
  } catch (err) {
    process.stderr.write(`cannot read input: ${err.message}\n`);
    return 2;
  }
  if (!Array.isArray(findings)) {
    process.stderr.write('findings.json must be an array\n');
    return 2;
  }

  const r = score(findings, answerKey);
  const out = [];
  out.push(`Major recall: ${r.majorHit}/${r.majorTotal} (${pct(r.majorHit, r.majorTotal)})`);
  out.push(`All-item recall: ${r.allHit}/${r.allTotal} (${pct(r.allHit, r.allTotal)})`);
  out.push(`Unlisted confirmed findings: ${r.falsePositives.length} (check each by hand: real vulnerability missing from the key, or false positive)`);
  for (const fp of r.falsePositives) out.push(`  - ${fp.id} ${fp.fingerprint} ${fp.title}`);
  out.push('Missed:');
  if (r.missed.length === 0) out.push('  (none)');
  for (const m of r.missed) out.push(`  - ${m.key}${m.minor ? ' (minor)' : ''}`);
  process.stdout.write(out.join('\n') + '\n');
  return 0;
}

if (require.main === module) {
  process.exitCode = main(process.argv.slice(2));
}

module.exports = { score, parseFingerprint };
