#!/usr/bin/env node

'use strict';

const fs = require('node:fs');
const path = require('node:path');

const VERDICTS = ['confirmed', 'needs_validation', 'rejected'];
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'informational'];
const CLASSES = [
  'injection', 'access-control', 'authentication', 'client-side', 'ssrf',
  'files-and-paths', 'cryptography', 'secrets-and-config', 'config',
  'information-disclosure', 'availability', 'supply-chain',
  'memory-safety', 'other',
];
const ID_RE = /^SA-\d{3,}$/;
const FINGERPRINT_RE = /^[^:\s]+:\d+:[a-z0-9-]+$/;

function isNonEmptyString(v) {
  return typeof v === 'string' && v.trim().length > 0;
}

function validateCommon(rec, where, errors) {
  if (!ID_RE.test(rec.id ?? '')) errors.push(`${where}: id must match SA-NNN`);
  if (!FINGERPRINT_RE.test(rec.fingerprint ?? '')) {
    errors.push(`${where}: fingerprint must be <path>:<line>:<class-slug>`);
  } else if (rec.fingerprint.split(':').pop() !== rec.class) {
    errors.push(`${where}: fingerprint suffix must equal class (${rec.class})`);
  }
  if (!CLASSES.includes(rec.class)) {
    errors.push(`${where}: class must be one of ${CLASSES.join(', ')}`);
  }
  if (!isNonEmptyString(rec.surface)) errors.push(`${where}: surface is required`);
}

function validateTrace(trace, where, errors) {
  if (!Array.isArray(trace) || trace.length === 0) {
    errors.push(`${where}: source_trace must be a non-empty array`);
    return;
  }
  trace.forEach((step, i) => {
    if (!isNonEmptyString(step.file)) errors.push(`${where}: source_trace[${i}].file is required`);
    if (!Number.isInteger(step.line) || step.line < 1) {
      errors.push(`${where}: source_trace[${i}].line must be a positive integer`);
    }
    if (!isNonEmptyString(step.note)) errors.push(`${where}: source_trace[${i}].note is required`);
    if (step.quote !== undefined && !isNonEmptyString(step.quote)) {
      errors.push(`${where}: source_trace[${i}].quote must be a non-empty string when given`);
    }
  });
}

function validateRecord(rec, index, errors) {
  const where = `record[${index}]${rec && rec.id ? ` (${rec.id})` : ''}`;
  if (!rec || typeof rec !== 'object' || Array.isArray(rec)) {
    errors.push(`${where}: must be an object`);
    return;
  }
  validateCommon(rec, where, errors);

  if (!VERDICTS.includes(rec.verdict)) {
    errors.push(`${where}: verdict must be one of ${VERDICTS.join(', ')}`);
    return;
  }

  if (rec.verdict === 'confirmed') {
    if (!SEVERITIES.includes(rec.severity)) {
      errors.push(`${where}: confirmed records need severity (${SEVERITIES.join(', ')})`);
    }
    validateTrace(rec.source_trace, where, errors);
    if (!isNonEmptyString(rec.attacker)) errors.push(`${where}: attacker is required`);
    if (!isNonEmptyString(rec.impact)) errors.push(`${where}: impact is required`);
    if (!isNonEmptyString(rec.fix)) errors.push(`${where}: fix is required`);
  }

  if (rec.verdict === 'needs_validation') {
    if (rec.severity !== undefined) {
      errors.push(`${where}: needs_validation records must not have severity`);
    }
    validateTrace(rec.source_trace, where, errors);
    if (!isNonEmptyString(rec.unresolved_fact)) {
      errors.push(`${where}: unresolved_fact is required`);
    }
    if (!isNonEmptyString(rec.validation_plan)) {
      errors.push(`${where}: validation_plan is required`);
    }
  }

  if (rec.verdict === 'rejected') {
    if (rec.severity !== undefined) errors.push(`${where}: rejected records must not have severity`);
    if (!isNonEmptyString(rec.rejection_reason)) {
      errors.push(`${where}: rejection_reason is required`);
    }
  }
}

function resolveInRepo(repoRoot, relFile) {
  if (path.isAbsolute(relFile)) return null;
  const normalized = path.normalize(relFile);
  if (normalized.split(/[\\/]/).includes('..')) return null;
  const full = path.resolve(repoRoot, normalized);
  const root = path.resolve(repoRoot);
  if (full !== root && !full.startsWith(root + path.sep)) return null;
  return full;
}

function checkLocation(file, line, quote, where, repoRoot, cache, errors) {
  const full = resolveInRepo(repoRoot, file);
  if (!full) {
    errors.push(`${where}: cited file escapes the repo or is absolute: ${file}`);
    return;
  }
  if (!cache.has(full)) {
    try {
      cache.set(full, fs.readFileSync(full, 'utf8').split(/\r?\n/));
    } catch {
      cache.set(full, null);
    }
  }
  const lines = cache.get(full);
  if (lines === null) {
    errors.push(`${where}: cited file does not exist: ${file}`);
    return;
  }
  if (line < 1 || line > lines.length) {
    errors.push(`${where}: line ${line} is out of range for ${file} (${lines.length} lines)`);
    return;
  }
  if (quote !== undefined && !lines[line - 1].includes(quote)) {
    errors.push(`${where}: quote not found on ${file}:${line}`);
  }
}

function checkLocations(rec, where, repoRoot, cache, errors) {
  if (Array.isArray(rec.source_trace)) {
    rec.source_trace.forEach((step, i) => {
      if (!step || !isNonEmptyString(step.file) || !Number.isInteger(step.line)) return;
      checkLocation(step.file, step.line, step.quote, `${where} source_trace[${i}]`, repoRoot, cache, errors);
    });
  }
  if (FINGERPRINT_RE.test(rec.fingerprint ?? '')) {
    const parts = rec.fingerprint.split(':');
    const file = parts.slice(0, -2).join(':');
    const line = Number(parts[parts.length - 2]);
    checkLocation(file, line, undefined, `${where} fingerprint`, repoRoot, cache, errors);
  }
}

function validateFindings(findings, options = {}) {
  const errors = [];
  if (!Array.isArray(findings)) {
    return { ok: false, errors: ['top level must be an array of records'] };
  }

  const ids = new Set();
  const fingerprints = new Set();
  const cache = new Map();
  findings.forEach((rec, i) => {
    validateRecord(rec, i, errors);
    if (rec && typeof rec === 'object') {
      if (ids.has(rec.id)) errors.push(`record[${i}]: duplicate id ${rec.id}`);
      if (fingerprints.has(rec.fingerprint)) {
        errors.push(`record[${i}]: duplicate fingerprint ${rec.fingerprint}`);
      }
      ids.add(rec.id);
      fingerprints.add(rec.fingerprint);
      if (options.repoRoot) {
        checkLocations(rec, `record[${i}]${rec.id ? ` (${rec.id})` : ''}`, options.repoRoot, cache, errors);
      }
    }
  });

  return { ok: errors.length === 0, errors };
}

function parseArgs(argv) {
  const args = { file: null, repoRoot: null };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--repo') {
      args.repoRoot = argv[++i] ?? null;
    } else if (!args.file) {
      args.file = argv[i];
    } else {
      return null;
    }
  }
  if (!args.file) return null;
  if (argv.includes('--repo') && !args.repoRoot) return null;
  return args;
}

function main(argv) {
  const args = parseArgs(argv);
  if (!args) {
    process.stderr.write('usage: node validate-findings.cjs <findings.json> [--repo <dir>]\n');
    return 2;
  }
  let findings;
  try {
    findings = JSON.parse(fs.readFileSync(args.file, 'utf8'));
  } catch (err) {
    process.stderr.write(`cannot read ${args.file}: ${err.message}\n`);
    return 2;
  }
  const result = validateFindings(findings, { repoRoot: args.repoRoot });
  if (result.ok) {
    const mode = args.repoRoot ? ' (schema and source locations)' : ' (schema only)';
    process.stdout.write(`OK: ${findings.length} record(s) valid${mode}\n`);
    return 0;
  }
  for (const e of result.errors) process.stderr.write(`ERROR: ${e}\n`);
  return 1;
}

if (require.main === module) {
  process.exitCode = main(process.argv.slice(2));
}

module.exports = { validateFindings, resolveInRepo };
