#!/usr/bin/env node

'use strict';

const fs = require('node:fs');

const LEVELS = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
  informational: 'note',
};

function parseFingerprint(fp) {
  const parts = String(fp ?? '').split(':');
  if (parts.length < 3) return null;
  parts.pop();
  const line = Number(parts.pop());
  if (!Number.isInteger(line) || line < 1) return null;
  return { file: parts.join(':'), line };
}

function toUri(file) {
  return String(file).replace(/\\/g, '/');
}

function toSarif(findings, options = {}) {
  const reported = findings.filter((f) => f.verdict === 'confirmed' || f.verdict === 'needs_validation');
  const ruleIds = [...new Set(reported.map((f) => f.class))].sort();

  const results = reported.map((f) => {
    const loc = parseFingerprint(f.fingerprint)
      ?? (Array.isArray(f.source_trace) && f.source_trace[0]
        ? { file: f.source_trace[0].file, line: f.source_trace[0].line }
        : { file: 'unknown', line: 1 });
    const confirmed = f.verdict === 'confirmed';
    const detail = confirmed ? f.impact : f.unresolved_fact;
    return {
      ruleId: f.class,
      level: confirmed ? (LEVELS[f.severity] ?? 'warning') : 'note',
      message: { text: `${f.title ?? f.id}${detail ? `: ${detail}` : ''}` },
      locations: [{
        physicalLocation: {
          artifactLocation: { uri: toUri(loc.file) },
          region: { startLine: loc.line },
        },
      }],
      partialFingerprints: { 'security-audit/fingerprint': f.fingerprint },
      properties: {
        id: f.id,
        verdict: f.verdict,
        ...(f.severity ? { severity: f.severity } : {}),
        ...(f.surface ? { surface: f.surface } : {}),
        ...(confirmed && f.fix ? { fix: f.fix } : {}),
        ...(!confirmed && f.validation_plan ? { validation_plan: f.validation_plan } : {}),
      },
    };
  });

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: options.toolName ?? 'security-audit',
          rules: ruleIds.map((id) => ({ id, name: id, shortDescription: { text: id } })),
        },
      },
      results,
    }],
  };
}

function main(argv) {
  if (argv.length < 1 || argv.length > 2) {
    process.stderr.write('usage: node to-sarif.cjs <findings.json> [output.sarif]\n');
    return 2;
  }
  let findings;
  try {
    findings = JSON.parse(fs.readFileSync(argv[0], 'utf8'));
  } catch (err) {
    process.stderr.write(`cannot read ${argv[0]}: ${err.message}\n`);
    return 2;
  }
  if (!Array.isArray(findings)) {
    process.stderr.write('findings.json must be an array\n');
    return 2;
  }
  const out = JSON.stringify(toSarif(findings), null, 2) + '\n';
  if (argv[1]) fs.writeFileSync(argv[1], out);
  else process.stdout.write(out);
  return 0;
}

if (require.main === module) {
  process.exitCode = main(process.argv.slice(2));
}

module.exports = { toSarif, parseFingerprint };
