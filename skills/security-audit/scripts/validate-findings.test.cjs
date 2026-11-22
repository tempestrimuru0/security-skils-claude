'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { validateFindings } = require('./validate-findings.cjs');

const base = {
  id: 'SA-001',
  fingerprint: 'src/a.ts:10:injection',
  class: 'injection',
  surface: 'HTTP route POST /search',
};

const confirmed = {
  ...base,
  verdict: 'confirmed',
  severity: 'high',
  source_trace: [{ file: 'src/a.ts', line: 10, note: 'raw SQL built from req.body.q' }],
  attacker: 'unauthenticated user',
  impact: 'reads any row in the users table',
  fix: 'use parameterized query',
};

const needs = {
  ...base,
  id: 'SA-002',
  fingerprint: 'src/b.ts:5:ssrf',
  class: 'ssrf',
  verdict: 'needs_validation',
  source_trace: [{ file: 'src/b.ts', line: 5, note: 'fetches user URL' }],
  unresolved_fact: 'whether the egress proxy blocks internal addresses',
  validation_plan: 'check the deployment config',
};

const rejected = {
  ...base,
  id: 'SA-003',
  fingerprint: 'src/c.ts:7:access-control',
  class: 'access-control',
  verdict: 'rejected',
  rejection_reason: 'tenant filter applied on line 6',
};

test('accepts a valid mix of verdicts', () => {
  const r = validateFindings([confirmed, needs, rejected]);
  assert.equal(r.ok, true, r.errors.join('\n'));
});

test('rejects a non-array top level', () => {
  assert.equal(validateFindings({}).ok, false);
});

test('confirmed without severity is invalid', () => {
  const { severity, ...rest } = confirmed;
  const r = validateFindings([rest]);
  assert.equal(r.ok, false);
  assert.match(r.errors.join(' '), /need severity/);
});

test('confirmed with unknown severity is invalid', () => {
  const r = validateFindings([{ ...confirmed, severity: 'severe' }]);
  assert.equal(r.ok, false);
});

test('confirmed without source_trace is invalid', () => {
  const r = validateFindings([{ ...confirmed, source_trace: [] }]);
  assert.equal(r.ok, false);
  assert.match(r.errors.join(' '), /source_trace/);
});

test('needs_validation with severity is invalid', () => {
  const r = validateFindings([{ ...needs, severity: 'low' }]);
  assert.equal(r.ok, false);
  assert.match(r.errors.join(' '), /must not have severity/);
});

test('needs_validation without unresolved_fact is invalid', () => {
  const { unresolved_fact, ...rest } = needs;
  const r = validateFindings([rest]);
  assert.equal(r.ok, false);
});

test('rejected without reason is invalid', () => {
  const { rejection_reason, ...rest } = rejected;
  assert.equal(validateFindings([rest]).ok, false);
});

test('duplicate fingerprints are invalid', () => {
  const r = validateFindings([confirmed, { ...rejected, fingerprint: confirmed.fingerprint }]);
  assert.equal(r.ok, false);
  assert.match(r.errors.join(' '), /duplicate fingerprint/);
});

test('fingerprint suffix must match class', () => {
  const r = validateFindings([{ ...confirmed, fingerprint: 'src/a.ts:10:path-traversal' }]);
  assert.equal(r.ok, false);
  assert.match(r.errors.join(' '), /suffix must equal class/);
});

test('new class slugs are accepted', () => {
  const r = validateFindings([{
    ...confirmed,
    class: 'secrets-and-config',
    fingerprint: 'src/a.ts:10:secrets-and-config',
  }]);
  assert.equal(r.ok, true, r.errors.join('\n'));
});

test('bad id format is invalid', () => {
  const r = validateFindings([{ ...confirmed, id: 'X-1' }]);
  assert.equal(r.ok, false);
});

test('unknown verdict is invalid', () => {
  const r = validateFindings([{ ...confirmed, verdict: 'maybe' }]);
  assert.equal(r.ok, false);
});
