'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { validateFindings, resolveInRepo } = require('./validate-findings.cjs');

function makeRepo() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sa-repo-'));
  fs.writeFileSync(path.join(root, 'app.js'), 'const a = 1;\nexec(userInput);\nconst b = 2;\n');
  return root;
}

function record(overrides = {}) {
  return {
    id: 'SA-001',
    fingerprint: 'app.js:2:injection',
    class: 'injection',
    surface: 'HTTP route POST /run',
    verdict: 'confirmed',
    severity: 'critical',
    source_trace: [{ file: 'app.js', line: 2, note: 'userInput reaches exec' }],
    attacker: 'unauthenticated client',
    impact: 'runs commands',
    fix: 'use execFile with an argument array',
    ...overrides,
  };
}

test('real location passes with repo check', () => {
  const repo = makeRepo();
  const r = validateFindings([record()], { repoRoot: repo });
  assert.equal(r.ok, true, r.errors.join('\n'));
});

test('line out of range is rejected', () => {
  const repo = makeRepo();
  const bad = record({ source_trace: [{ file: 'app.js', line: 99, note: 'x' }] });
  const r = validateFindings([bad], { repoRoot: repo });
  assert.equal(r.ok, false);
  assert.match(r.errors.join(' '), /out of range/);
});

test('missing file is rejected', () => {
  const repo = makeRepo();
  const bad = record({ source_trace: [{ file: 'nope.js', line: 1, note: 'x' }] });
  const r = validateFindings([bad], { repoRoot: repo });
  assert.equal(r.ok, false);
  assert.match(r.errors.join(' '), /does not exist/);
});

test('quote must appear on the cited line', () => {
  const repo = makeRepo();
  const ok = record({ source_trace: [{ file: 'app.js', line: 2, note: 'x', quote: 'exec(' }] });
  assert.equal(validateFindings([ok], { repoRoot: repo }).ok, true);
  const bad = record({ source_trace: [{ file: 'app.js', line: 2, note: 'x', quote: 'eval(' }] });
  const r = validateFindings([bad], { repoRoot: repo });
  assert.equal(r.ok, false);
  assert.match(r.errors.join(' '), /quote not found/);
});

test('fingerprint location is checked too', () => {
  const repo = makeRepo();
  const bad = record({ fingerprint: 'app.js:50:injection' });
  const r = validateFindings([bad], { repoRoot: repo });
  assert.equal(r.ok, false);
  assert.match(r.errors.join(' '), /fingerprint.*out of range/);
});

test('paths escaping the repo are rejected', () => {
  const repo = makeRepo();
  const bad = record({ source_trace: [{ file: '../etc/passwd', line: 1, note: 'x' }] });
  const r = validateFindings([bad], { repoRoot: repo });
  assert.equal(r.ok, false);
  assert.match(r.errors.join(' '), /escapes the repo/);
});

test('absolute paths are rejected', () => {
  assert.equal(resolveInRepo('/repo', '/etc/passwd'), null);
});

test('without repoRoot the location is not checked', () => {
  const bad = record({ source_trace: [{ file: 'nope.js', line: 500, note: 'x' }] });
  assert.equal(validateFindings([bad]).ok, true);
});
