#!/usr/bin/env node
/**
 * Agent receipts v0.1 — evidence that an agent's "Done" claim is backed by checks.
 *
 * A RECEIPT.json records:
 *  - task: what the agent says it did
 *  - checks: named commands, each with exitCode, duration, and a SHA-256 of its output
 *  - artifacts: files the work produced, each with a SHA-256
 *  - result: "pass" only if every check exited 0 and at least one check ran
 *  - selfHash: SHA-256 of the canonical JSON of the receipt (without selfHash)
 *
 * verifyReceipt() recomputes everything from disk, so a receipt cannot be
 * edited after the fact without the verifier noticing.
 *
 * Paths (artifacts) resolve against the project root = current directory unless --root is given.
 *
 * Usage:
 *   node receipt.mjs make   --task "..." --check "name=command" [...] [--artifact path] [...] --out RECEIPT.json
 *   node receipt.mjs verify RECEIPT.json [--root dir]
 * Exit codes: make -> 0 pass / 1 any check failed; verify -> 0 valid / 1 invalid.
 */
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { resolve, isAbsolute, join } from 'node:path';

export const VERSION = '0.1';

export function canonicalize(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonicalize).join(',') + ']';
  const keys = Object.keys(value).sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonicalize(value[k])).join(',') + '}';
}

const sha256 = (data) => createHash('sha256').update(data).digest('hex');

export function selfHashOf(receipt) {
  const { selfHash: _omit, ...rest } = receipt;
  return sha256(canonicalize(rest));
}

/** Run a named check through the shell and record the evidence. */
export function runCheck(name, command, cwd = process.cwd()) {
  const start = Date.now();
  const r = spawnSync(command, { shell: true, cwd, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  const output = (r.stdout ?? '') + (r.stderr ?? '');
  const exitCode = r.status ?? (r.error ? 127 : 1);
  return {
    name,
    command,
    exitCode,
    passed: exitCode === 0,
    durationMs: Date.now() - start,
    outputSha256: sha256(output),
  };
}

export function hashFile(path) {
  return sha256(readFileSync(path));
}

export function makeReceipt({ task, agent = 'unknown', checks, artifacts = [], cwd = process.cwd() }) {
  const checkResults = checks.map(([name, command]) => runCheck(name, command, cwd));
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

/**
 * Recompute and check a receipt. Returns { valid, problems[] }.
 * Artifact paths resolve against `root` (default: the receipt's folder).
 */
export function verifyReceipt(receipt, { root = process.cwd() } = {}) {
  const problems = [];
  if (receipt?.version !== VERSION) problems.push(`unsupported version: ${receipt?.version}`);
  if (typeof receipt?.task !== 'string' || !receipt.task) problems.push('missing task');
  if (!Array.isArray(receipt?.checks)) problems.push('missing checks');
  if (!Array.isArray(receipt?.artifacts)) problems.push('missing artifacts');
  if (problems.length) return { valid: false, problems };

  if (selfHashOf(receipt) !== receipt.selfHash) problems.push('selfHash does not match receipt contents (edited after creation)');

  for (const c of receipt.checks) {
    if (c.exitCode !== 0 || c.passed !== true) problems.push(`check "${c.name}" did not pass (exitCode ${c.exitCode})`);
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

  return { valid: problems.length === 0, problems };
}

function parseArgs(argv) {
  const out = { checks: [], artifacts: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--task') out.task = argv[++i];
    else if (a === '--agent') out.agent = argv[++i];
    else if (a === '--out') out.out = argv[++i];
    else if (a === '--root') out.root = argv[++i];
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
  if (cmd === 'make') {
    const o = parseArgs(rest);
    if (!o.task) throw new Error('make: --task is required');
    if (!o.out) throw new Error('make: --out is required');
    const receipt = makeReceipt({ task: o.task, agent: o.agent, checks: o.checks, artifacts: o.artifacts });
    writeFileSync(o.out, JSON.stringify(receipt, null, 2) + '\n');
    console.log(`receipt ${receipt.result.toUpperCase()} -> ${o.out}`);
    process.exit(receipt.result === 'pass' ? 0 : 1);
  } else if (cmd === 'verify') {
    const o = parseArgs(rest);
    const file = o.positional?.[0];
    if (!file) throw new Error('verify: receipt path required');
    const receipt = JSON.parse(readFileSync(file, 'utf8'));
    // Artifact paths are relative to the project root (the working directory by default),
    // the same base `make` uses. Pass --root to verify from elsewhere.
    const root = o.root ?? process.cwd();
    const v = verifyReceipt(receipt, { root });
    if (v.valid) console.log(`VALID: ${file}`);
    else {
      console.log(`INVALID: ${file}`);
      for (const p of v.problems) console.log(`  - ${p}`);
    }
    process.exit(v.valid ? 0 : 1);
  } else {
    console.error('usage: receipt.mjs make|verify ... (see header)');
    process.exit(1);
  }
}

if (import.meta.url === `file://${process.argv[1].replace(/\\/g, '/')}` || process.argv[1]?.endsWith('receipt.mjs')) {
  main().catch((e) => {
    console.error(e.message);
    process.exit(1);
  });
}
