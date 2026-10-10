import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { makeReceipt, verifyReceipt, canonicalize, generateKeys, signReceipt, selfHashOf } from './receipt.mjs';

const dir = () => mkdtempSync(join(tmpdir(), 'receipt-'));
const ok = 'node -e "process.exit(0)"';
const bad = 'node -e "process.exit(3)"';
const hang = 'node -e "setTimeout(() => {}, 60000)"';

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

test('malformed receipt schemas are rejected without throwing', () => {
  for (const value of [null, {}, { version: '0.2', task: 'x', checks: {}, artifacts: [] }, { version: '0.2', task: 'x', checks: [null], artifacts: [null] }]) {
    assert.equal(verifyReceipt(value).valid, false);
  }
});

test('artifact traversal cannot read outside the verification root', () => {
  const root = dir();
  const r = makeReceipt({ task: 't', checks: [['ok', ok]], cwd: root });
  r.artifacts = [{ path: '../secret', sha256: '0'.repeat(64) }];
  r.selfHash = selfHashOf(r);
  assert.equal(verifyReceipt(r, { root }).valid, false);
  assert.throws(() => makeReceipt({ task: 't', checks: [], artifacts: [process.execPath], cwd: root }), /relative/);
});

test('malformed signatures and contradictory timeout evidence fail closed', () => {
  const keys = generateKeys();
  const r = makeReceipt({ task: 't', checks: [['ok', ok]], cwd: dir() });
  r.signature = { alg: 'ed25519', value: {} };
  assert.equal(verifyReceipt(r, { publicKeyPem: keys.publicPem }).valid, false);
  r.checks[0].timedOut = true;
  r.selfHash = selfHashOf(r);
  assert.equal(verifyReceipt(r).valid, false);
});

test('CLI rejects missing values and unknown flags', () => {
  for (const args of [['make', '--check'], ['make', '--wat', 'x'], ['make', '--timeout', '1.5']]) {
    const r = spawnSync(process.execPath, ['receipt.mjs', ...args], { encoding: 'utf8' });
    assert.equal(r.status, 1);
    assert.ok(!r.stderr.includes('at main'));
  }
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

test('a check that exceeds its timeout is killed and recorded as a failure', () => {
  const r = makeReceipt({ task: 't', checks: [['slow', hang]], cwd: dir(), timeoutMs: 500 });
  assert.equal(r.checks[0].timedOut, true);
  assert.equal(r.checks[0].exitCode, 124);
  assert.equal(r.result, 'fail');
  const v = verifyReceipt(r, { root: dir() });
  assert.ok(v.problems.some((p) => p.includes('"slow" did not pass (timed out)')));
});

test('a signed receipt verifies with the matching public key', () => {
  const { privatePem, publicPem } = generateKeys();
  const r = signReceipt(makeReceipt({ task: 'signed', checks: [['ok', ok]], cwd: dir() }), privatePem);
  assert.equal(r.signature.alg, 'ed25519');
  assert.deepEqual(verifyReceipt(r, { root: dir(), publicKeyPem: publicPem }), { valid: true, problems: [] });
});

test('a signed receipt that was forged and re-hashed is rejected by signature check', () => {
  const { privatePem, publicPem } = generateKeys();
  const r = signReceipt(makeReceipt({ task: 'real task', checks: [['ok', bad]], cwd: dir() }), privatePem);
  // An attacker flips the result and recomputes selfHash, which passes the hash check.
  const forged = { ...r, result: 'fail', checks: [{ ...r.checks[0], exitCode: 0, passed: true }] };
  forged.result = 'pass';
  forged.selfHash = (() => {
    const { selfHash: _s, signature: _g, ...rest } = forged;
    return createHash('sha256').update(canonicalize(rest)).digest('hex');
  })();
  const v = verifyReceipt(forged, { root: dir(), publicKeyPem: publicPem });
  assert.equal(v.valid, false);
  assert.ok(v.problems.some((p) => p.includes('signature does not verify')));
});

test('an unsigned receipt fails when a public key is required', () => {
  const { publicPem } = generateKeys();
  const r = makeReceipt({ task: 't', checks: [['ok', ok]], cwd: dir() });
  const v = verifyReceipt(r, { root: dir(), publicKeyPem: publicPem });
  assert.ok(v.problems.some((p) => p.includes('not signed')));
});

test('a receipt signed by one key does not verify with another key', () => {
  const a = generateKeys();
  const b = generateKeys();
  const r = signReceipt(makeReceipt({ task: 't', checks: [['ok', ok]], cwd: dir() }), a.privatePem);
  const v = verifyReceipt(r, { root: dir(), publicKeyPem: b.publicPem });
  assert.ok(v.problems.some((p) => p.includes('signature does not verify')));
});

test('keygen, make --sign-key and verify --pubkey work end to end from the CLI', () => {
  const root = dir();
  const cli = join(process.cwd(), 'receipt.mjs');
  const kg = spawnSync(process.execPath, [cli, 'keygen', '--out-dir', join(root, 'keys')], { encoding: 'utf8' });
  assert.equal(kg.status, 0, kg.stderr);
  assert.ok(existsSync(join(root, 'keys', 'private.pem')) && existsSync(join(root, 'keys', 'public.pem')));

  const mk = spawnSync(process.execPath, [cli, 'make', '--task', 'cli', '--check', 'ok=' + ok, '--sign-key', join(root, 'keys', 'private.pem'), '--out', join(root, 'R.json')], { encoding: 'utf8', cwd: root });
  assert.equal(mk.status, 0, mk.stdout + mk.stderr);

  const good = spawnSync(process.execPath, [cli, 'verify', join(root, 'R.json'), '--pubkey', join(root, 'keys', 'public.pem')], { encoding: 'utf8', cwd: root });
  assert.equal(good.status, 0, good.stdout);

  const again = spawnSync(process.execPath, [cli, 'keygen', '--out-dir', join(root, 'keys')], { encoding: 'utf8' });
  assert.equal(again.status, 1, 'keygen must refuse to overwrite existing keys');
});
