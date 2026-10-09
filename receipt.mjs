#!/usr/bin/env node
/**
 * Agent receipts v0.2 — evidence that an agent's "Done" claim is backed by checks.
 *
 * A RECEIPT.json records:
 *  - task: what the agent says it did
 *  - checks: named commands, each with exitCode, duration, and a SHA-256 of its output.
 *    A check that runs longer than its timeout is killed and recorded with exitCode 124.
 *  - artifacts: files the work produced, each with a SHA-256
 *  - result: "pass" only if every check exited 0 and at least one check ran
 *  - selfHash: SHA-256 of the canonical JSON of the receipt (without selfHash and signature)
 *  - signature (optional): Ed25519 signature over selfHash, made with a private key
 *
 * verifyReceipt() recomputes everything from disk, so a receipt cannot be
 * edited after the fact without the verifier noticing. A signature also proves
 * who issued it: anyone can recompute a hash, but only the key holder can sign.
 *
 * Paths (artifacts) resolve against the project root = current directory unless --root is given.
 *
 * Usage:
 *   node receipt.mjs keygen --out-dir keys                      # writes keys/private.pem and keys/public.pem
 *   node receipt.mjs make   --task "..." --check "name=command" [...] [--artifact path] [...]
 *                           [--timeout ms] [--sign-key keys/private.pem] --out RECEIPT.json
 *   node receipt.mjs verify RECEIPT.json [--root dir] [--pubkey keys/public.pem]
 * Exit codes: make -> 0 pass / 1 any check failed; verify -> 0 valid / 1 invalid; keygen -> 0 / 1.
 */
import { createHash, generateKeyPairSync, sign, verify, createPrivateKey, createPublicKey } from 'node:crypto';
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { resolve, isAbsolute, join, dirname } from 'node:path';

export const VERSION = '0.2';
export const DEFAULT_TIMEOUT_MS = 10 * 60 * 1000;
export const TIMEOUT_EXIT_CODE = 124;

export function canonicalize(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonicalize).join(',') + ']';
  const keys = Object.keys(value).sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonicalize(value[k])).join(',') + '}';
}

const sha256 = (data) => createHash('sha256').update(data).digest('hex');

export function selfHashOf(receipt) {
  const { selfHash: _omit, signature: _sig, ...rest } = receipt;
  return sha256(canonicalize(rest));
}

/** Run a named check through the shell and record the evidence. */
export function runCheck(name, command, cwd = process.cwd(), timeoutMs = DEFAULT_TIMEOUT_MS) {
  const start = Date.now();
  const r = spawnSync(command, { shell: true, cwd, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, timeout: timeoutMs });
  const output = (r.stdout ?? '') + (r.stderr ?? '');
  const timedOut = r.error?.code === 'ETIMEDOUT';
  const exitCode = timedOut ? TIMEOUT_EXIT_CODE : (r.status ?? (r.error ? 127 : 1));
  return {
    name,
    command,
    exitCode,
    passed: exitCode === 0,
    timedOut,
    durationMs: Date.now() - start,
    outputSha256: sha256(output),
  };
}

export function hashFile(path) {
  return sha256(readFileSync(path));
}

export function makeReceipt({ task, agent = 'unknown', checks, artifacts = [], cwd = process.cwd(), timeoutMs = DEFAULT_TIMEOUT_MS }) {
  const checkResults = checks.map(([name, command]) => runCheck(name, command, cwd, timeoutMs));
  const artifactResults = artifacts.map((p) => {
    const abs = isAbsolute(p) ? p : join(cwd, p);
    return { path: p, sha256: hashFile(abs) };
  });
  const result = checkResults.length > 0 && checkResults.every((c) => c.passed) ? 'pass' : 'fail';
  const receipt = {
    version: VERSION,
    task,
    agent,
    createdAt: new Date().toISOString(),
    result,
    checks: checkResults,
    artifacts: artifactResults,
  };
  receipt.selfHash = selfHashOf(receipt);
  return receipt;
}

/** Adds an Ed25519 signature over selfHash. Call after makeReceipt. */
export function signReceipt(receipt, privateKeyPem) {
  const key = createPrivateKey(privateKeyPem);
  receipt.signature = {
    alg: 'ed25519',
    value: sign(null, Buffer.from(receipt.selfHash, 'utf8'), key).toString('base64'),
  };
  return receipt;
}

function signatureProblem(receipt, publicKeyPem) {
  if (!receipt.signature) return 'receipt is not signed';
  if (receipt.signature.alg !== 'ed25519') return `unsupported signature algorithm: ${receipt.signature.alg}`;
  let key;
  try {
    key = createPublicKey(publicKeyPem);
  } catch {
    return 'could not read the public key';
  }
  const ok = verify(null, Buffer.from(receipt.selfHash, 'utf8'), key, Buffer.from(receipt.signature.value, 'base64'));
  return ok ? null : 'signature does not verify with the given public key';
}

/**
 * Recompute and check a receipt. Returns { valid, problems[] }.
 * Artifact paths resolve against `root`. Pass `publicKeyPem` to require a valid signature.
 */
export function verifyReceipt(receipt, { root = process.cwd(), publicKeyPem } = {}) {
  const problems = [];
  if (receipt?.version !== VERSION && receipt?.version !== '0.1') problems.push(`unsupported version: ${receipt?.version}`);
  if (typeof receipt?.task !== 'string' || !receipt.task) problems.push('missing task');
  if (!Array.isArray(receipt?.checks)) problems.push('missing checks');
  if (!Array.isArray(receipt?.artifacts)) problems.push('missing artifacts');
  if (problems.length) return { valid: false, problems };

  if (selfHashOf(receipt) !== receipt.selfHash) problems.push('selfHash does not match receipt contents (edited after creation)');

  for (const c of receipt.checks) {
    if (c.exitCode !== 0 || c.passed !== true) {
      const why = c.timedOut ? 'timed out' : `exitCode ${c.exitCode}`;
      problems.push(`check "${c.name}" did not pass (${why})`);
    }
  }
  if (receipt.checks.length === 0) problems.push('no checks ran, so the "done" claim has no evidence');

  for (const a of receipt.artifacts) {
    const abs = isAbsolute(a.path) ? a.path : resolve(root, a.path);
    if (!existsSync(abs)) {
      problems.push(`artifact missing: ${a.path}`);
    } else if (hashFile(abs) !== a.sha256) {
      problems.push(`artifact changed since receipt: ${a.path}`);
    }
  }

  const expected = receipt.checks.every((c) => c.passed) && receipt.checks.length > 0 ? 'pass' : 'fail';
  if (receipt.result !== expected) problems.push(`result says "${receipt.result}" but checks imply "${expected}"`);

  if (publicKeyPem) {
    const sigProblem = signatureProblem(receipt, publicKeyPem);
    if (sigProblem) problems.push(sigProblem);
  }

  return { valid: problems.length === 0, problems };
}

export function generateKeys() {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  return {
    privatePem: privateKey.export({ type: 'pkcs8', format: 'pem' }),
    publicPem: publicKey.export({ type: 'spki', format: 'pem' }),
  };
}

function parseArgs(argv) {
  const out = { checks: [], artifacts: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--task') out.task = argv[++i];
    else if (a === '--agent') out.agent = argv[++i];
    else if (a === '--out') out.out = argv[++i];
    else if (a === '--out-dir') out.outDir = argv[++i];
    else if (a === '--root') out.root = argv[++i];
    else if (a === '--timeout') {
      const ms = Number(argv[++i]);
      if (!Number.isFinite(ms) || ms <= 0) throw new Error('--timeout must be a positive number of milliseconds');
      out.timeoutMs = ms;
    } else if (a === '--sign-key') out.signKey = argv[++i];
    else if (a === '--pubkey') out.pubkey = argv[++i];
    else if (a === '--check') {
      const v = argv[++i];
      const eq = v.indexOf('=');
      if (eq < 1) throw new Error(`--check needs name=command, got "${v}"`);
      out.checks.push([v.slice(0, eq), v.slice(eq + 1)]);
    } else if (a === '--artifact') out.artifacts.push(argv[++i]);
    else out.positional = [...(out.positional ?? []), a];
  }
  return out;
}

async function main() {
  const [cmd, ...rest] = process.argv.slice(2);
  if (cmd === 'keygen') {
    const o = parseArgs(rest);
    const dir = o.outDir ?? '.';
    const priv = join(dir, 'private.pem');
    const pub = join(dir, 'public.pem');
    if (existsSync(priv) || existsSync(pub)) throw new Error(`keygen: ${priv} or ${pub} already exists; refusing to overwrite`);
    const { privatePem, publicPem } = generateKeys();
    mkdirSync(dirname(priv), { recursive: true });
    writeFileSync(priv, privatePem, { mode: 0o600 });
    writeFileSync(pub, publicPem);
    console.log(`wrote ${priv} (keep secret) and ${pub}`);
    process.exit(0);
  } else if (cmd === 'make') {
    const o = parseArgs(rest);
    if (!o.task) throw new Error('make: --task is required');
    if (!o.out) throw new Error('make: --out is required');
    const receipt = makeReceipt({ task: o.task, agent: o.agent, checks: o.checks, artifacts: o.artifacts, timeoutMs: o.timeoutMs });
    if (o.signKey) signReceipt(receipt, readFileSync(o.signKey, 'utf8'));
    writeFileSync(o.out, JSON.stringify(receipt, null, 2) + '\n');
    console.log(`receipt ${receipt.result.toUpperCase()}${receipt.signature ? ' (signed)' : ''} -> ${o.out}`);
    process.exit(receipt.result === 'pass' ? 0 : 1);
  } else if (cmd === 'verify') {
    const o = parseArgs(rest);
    const file = o.positional?.[0];
    if (!file) throw new Error('verify: receipt path required');
    const receipt = JSON.parse(readFileSync(file, 'utf8'));
    // Artifact paths are relative to the project root (the working directory by default),
    // the same base `make` uses. Pass --root to verify from elsewhere.
    const root = o.root ?? process.cwd();
    const publicKeyPem = o.pubkey ? readFileSync(o.pubkey, 'utf8') : undefined;
    const v = verifyReceipt(receipt, { root, publicKeyPem });
    if (v.valid) console.log(`VALID: ${file}${publicKeyPem ? ' (signature checked)' : ''}`);
    else {
      console.log(`INVALID: ${file}`);
      for (const p of v.problems) console.log(`  - ${p}`);
    }
    process.exit(v.valid ? 0 : 1);
  } else {
    console.error('usage: receipt.mjs keygen|make|verify ... (see header)');
    process.exit(1);
  }
}

if (import.meta.url === `file://${process.argv[1].replace(/\\/g, '/')}` || process.argv[1]?.endsWith('receipt.mjs')) {
  main().catch((e) => {
    console.error(e.message);
    process.exit(1);
  });
}
