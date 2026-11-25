'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { toSarif, parseFingerprint } = require('./to-sarif.cjs');
const { render } = require('./render-report.cjs');

const findings = [
  {
    id: 'SA-001', fingerprint: 'src/a.js:10:injection', class: 'injection', title: 'SQL injection in login',
    surface: 'POST /login', verdict: 'confirmed', severity: 'critical',
    source_trace: [{ file: 'src/a.js', line: 10, note: 'body concatenated into SQL' }],
    attacker: 'anyone', impact: 'logs in as any user', fix: 'parameterize',
  },
  {
    id: 'SA-002', fingerprint: 'src/b.js:5:config', class: 'config', title: 'Cookie without flags',
    surface: 'login', verdict: 'confirmed', severity: 'low',
    source_trace: [{ file: 'src/b.js', line: 5, note: 'no HttpOnly' }],
    attacker: 'script on page', impact: 'cookie readable', fix: 'set flags',
  },
  {
    id: 'SA-003', fingerprint: 'src/c.js:7:ssrf', class: 'ssrf', title: 'Fetch of user URL', surface: 'GET /fetch',
    verdict: 'needs_validation', source_trace: [{ file: 'src/c.js', line: 7, note: 'fetch(url)' }],
    unresolved_fact: 'egress filtered | maybe', validation_plan: 'check proxy',
  },
  {
    id: 'SA-004', fingerprint: 'src/d.js:3:access-control', class: 'access-control', surface: 'GET /x',
    verdict: 'rejected', rejection_reason: 'filter on line 2',
  },
];

test('sarif omits rejected records and maps severity to level', () => {
  const sarif = toSarif(findings);
  assert.equal(sarif.version, '2.1.0');
  const results = sarif.runs[0].results;
  assert.equal(results.length, 3);
  assert.equal(results.find((r) => r.properties.id === 'SA-001').level, 'error');
  assert.equal(results.find((r) => r.properties.id === 'SA-002').level, 'note');
  assert.equal(results.find((r) => r.properties.id === 'SA-003').level, 'note');
});

test('sarif locations come from the fingerprint and use forward slashes', () => {
  const r = toSarif([{ ...findings[0], fingerprint: 'src\\a.js:10:injection' }]).runs[0].results[0];
  assert.equal(r.locations[0].physicalLocation.artifactLocation.uri, 'src/a.js');
  assert.equal(r.locations[0].physicalLocation.region.startLine, 10);
});

test('sarif lists one rule per class', () => {
  const ids = toSarif(findings).runs[0].tool.driver.rules.map((r) => r.id);
  assert.deepEqual(ids, ['config', 'injection', 'ssrf']);
});

test('parseFingerprint rejects malformed input', () => {
  assert.equal(parseFingerprint('nope'), null);
  assert.deepEqual(parseFingerprint('C:/x/a.js:4:injection'), { file: 'C:/x/a.js', line: 4 });
});

test('report orders findings by severity and counts verdicts', () => {
  const text = render([findings[1], findings[0], findings[2], findings[3]], { name: 'demo', date: '2026-01-01' });
  assert.match(text, /# Security Audit: demo/);
  assert.ok(text.indexOf('SA-001') < text.indexOf('SA-002'));
  assert.match(text, /\| critical \| 1 \|/);
  assert.match(text, /\| low \| 1 \|/);
  assert.match(text, /Needs validation: 1\. Rejected candidates: 1\./);
});

test('report escapes pipes in tables and lists rejected candidates', () => {
  const text = render(findings, {});
  assert.match(text, /egress filtered \\\| maybe/);
  assert.match(text, /## Rejected candidates/);
  assert.match(text, /filter on line 2/);
});

test('report with no confirmed findings says so', () => {
  assert.match(render([findings[3]], {}), /No confirmed findings\./);
});

test('coverage text is included when given', () => {
  assert.match(render([], { coverage: 'Checked: routes.' }), /Checked: routes\./);
});
