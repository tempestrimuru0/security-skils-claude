'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { score, parseFingerprint } = require('./score-run.cjs');

const key = {
  items: [
    { key: 'sqli', file: 'server.cjs', line: 76, class: 'injection', accept_verdicts: ['confirmed'] },
    { key: 'cors', file: 'server.cjs', line: 62, class: 'config', accept_classes: ['config', 'client-side'], accept_verdicts: ['confirmed', 'needs_validation'] },
    { key: 'timing', file: 'server.cjs', line: 138, class: 'cryptography', accept_verdicts: ['confirmed', 'rejected'], minor: true },
  ],
};

test('parseFingerprint splits path, line and class', () => {
  assert.deepEqual(parseFingerprint('C:/x/server.cjs:76:injection'), { file: 'C:/x/server.cjs', line: 76, cls: 'injection' });
  assert.equal(parseFingerprint('nonsense'), null);
});

test('perfect run gives full recall and no false positives', () => {
  const findings = [
    { id: 'SA-1', fingerprint: 'server.cjs:76:injection', class: 'injection', verdict: 'confirmed' },
    { id: 'SA-2', fingerprint: 'server.cjs:62:client-side', class: 'client-side', verdict: 'needs_validation' },
  ];
  const r = score(findings, key);
  assert.equal(r.majorHit, 2);
  assert.equal(r.majorTotal, 2);
  assert.equal(r.falsePositives.length, 0);
  assert.deepEqual(r.missed, [{ key: 'timing', minor: true }]);
});

test('line tolerance is applied', () => {
  const findings = [{ id: 'SA-1', fingerprint: 'server.cjs:78:injection', class: 'injection', verdict: 'confirmed' }];
  assert.equal(score(findings, key).majorHit, 1);
});

test('a finding outside tolerance is a false positive when confirmed', () => {
  const findings = [{ id: 'SA-9', fingerprint: 'server.cjs:200:injection', class: 'injection', verdict: 'confirmed' }];
  const r = score(findings, key);
  assert.equal(r.majorHit, 0);
  assert.equal(r.falsePositives.length, 1);
});

test('needs_validation outside tolerance is not a false positive', () => {
  const findings = [{ id: 'SA-9', fingerprint: 'other.cjs:5:injection', class: 'injection', verdict: 'needs_validation' }];
  assert.equal(score(findings, key).falsePositives.length, 0);
});

test('wrong verdict does not match', () => {
  const findings = [{ id: 'SA-1', fingerprint: 'server.cjs:76:injection', class: 'injection', verdict: 'needs_validation' }];
  const r = score(findings, key);
  assert.equal(r.majorHit, 0);
});

test('each finding matches at most one item', () => {
  const twoItems = {
    items: [
      { key: 'a', file: 'server.cjs', line: 10, class: 'injection' },
      { key: 'b', file: 'server.cjs', line: 11, class: 'injection' },
    ],
  };
  const findings = [{ id: 'SA-1', fingerprint: 'server.cjs:10:injection', class: 'injection', verdict: 'confirmed' }];
  const r = score(findings, twoItems);
  assert.equal(r.allHit, 1);
});

test('accept_classes lets a different but valid class match', () => {
  const findings = [{ id: 'SA-1', fingerprint: 'server.cjs:62:client-side', class: 'client-side', verdict: 'confirmed' }];
  assert.equal(score(findings, key).allHit, 1);
});
