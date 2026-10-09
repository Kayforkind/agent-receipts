import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { makeReceipt, verifyReceipt, canonicalize } from './receipt.mjs';

const dir = () => mkdtempSync(join(tmpdir(), 'receipt-'));
const ok = 'node -e "process.exit(0)"';
const bad = 'node -e "process.exit(3)"';

test('a passing receipt verifies against its artifacts', () => {
  const root = dir();
  writeFileSync(join(root, 'out.txt'), 'hello');
  const r = makeReceipt({ task: 'write out.txt', checks: [['exit-ok', ok]], artifacts: ['out.txt'], cwd: root });
  assert.equal(r.result, 'pass');
  assert.deepEqual(verifyReceipt(r, { root }), { valid: true, problems: [] });
});

test('editing an artifact after the receipt is caught', () => {
  const root = dir();
  writeFileSync(join(root, 'out.txt'), 'hello');
  const r = makeReceipt({ task: 't', checks: [['exit-ok', ok]], artifacts: ['out.txt'], cwd: root });
  writeFileSync(join(root, 'out.txt'), 'changed');
  const v = verifyReceipt(r, { root });
  assert.equal(v.valid, false);
  assert.ok(v.problems.some((p) => p.includes('artifact changed')));
});

test('editing the receipt itself breaks selfHash', () => {
  const r = makeReceipt({ task: 't', checks: [['exit-ok', ok]], cwd: dir() });
  const forged = { ...r, result: 'pass', checks: [{ ...r.checks[0], exitCode: 0 }] };
  forged.task = 'something else';
  const v = verifyReceipt(forged, { root: dir() });
  assert.equal(v.valid, false);
  assert.ok(v.problems.some((p) => p.includes('selfHash')));
});

test('a failing check produces a fail receipt that does not verify as pass', () => {
  const r = makeReceipt({ task: 't', checks: [['good', ok], ['bad', bad]], cwd: dir() });
  assert.equal(r.result, 'fail');
  const v = verifyReceipt(r, { root: dir() });
  assert.equal(v.valid, false);
  assert.ok(v.problems.some((p) => p.includes('"bad" did not pass')));
});

test('a "done" claim with no checks is rejected', () => {
  const r = makeReceipt({ task: 't', checks: [], cwd: dir() });
  assert.equal(r.result, 'fail');
  const v = verifyReceipt(r, { root: dir() });
  assert.equal(v.valid, false);
  assert.ok(v.problems.some((p) => p.includes('no checks ran')));
});

test('canonical JSON is key-order independent', () => {
  assert.equal(canonicalize({ b: 1, a: { d: 2, c: 3 } }), canonicalize({ a: { c: 3, d: 2 }, b: 1 }));
});

test('a receipt written to disk round-trips through JSON and still verifies', () => {
  const root = dir();
  writeFileSync(join(root, 'a.txt'), 'data');
  const r = makeReceipt({ task: 'rt', checks: [['ok', ok]], artifacts: ['a.txt'], cwd: root });
  const path = join(root, 'RECEIPT.json');
  writeFileSync(path, JSON.stringify(r, null, 2));
  const back = JSON.parse(readFileSync(path, 'utf8'));
  assert.equal(verifyReceipt(back, { root }).valid, true);
});
