# Agent receipts v0.2

A RECEIPT.json is evidence that an agent's "done" claim is backed by checks.
It records the task, each named check's exit code and output hash, the SHA-256
of each produced artifact, a `selfHash` over the whole receipt, and optionally
an Ed25519 signature that proves who issued it.

Zero dependencies. Node 20+.

## Fields

| field | meaning |
| --- | --- |
| `version` | `"0.2"` (v0.1 receipts still verify) |
| `task` | what the agent says it did |
| `agent` | who produced it |
| `result` | `"pass"` only if every check exited 0 and at least one check ran |
| `checks[]` | `name`, `command`, `exitCode`, `passed`, `timedOut`, `durationMs`, `outputSha256` |
| `artifacts[]` | `path`, `sha256` (paths relative to the project root) |
| `selfHash` | SHA-256 of the canonical JSON of the receipt without `selfHash` and `signature` |
| `signature` | optional `{ alg: "ed25519", value }` over `selfHash` |

## Use

```bash
# once: create a signing key pair (refuses to overwrite)
node receipt.mjs keygen --out-dir keys        # keep keys/private.pem secret; commit keys/public.pem

# make a receipt, killing any check that runs longer than 5 minutes
node receipt.mjs make --task "Fix login redirect" --agent my-agent \
  --check "tests=npm test" --check "typecheck=npm run typecheck" \
  --artifact src/login.ts --timeout 300000 \
  --sign-key keys/private.pem --out RECEIPT.json

# verify from the project root, requiring a valid signature from the known key
node receipt.mjs verify RECEIPT.json --pubkey keys/public.pem
```

`make` exits 1 when any check fails, so it can gate a CI job. A check that hits
its timeout is killed and recorded with `exitCode` 124 and `timedOut: true`.
`verify` exits 1 when the receipt was edited, an artifact changed, a check
failed, the `result` disagrees with the checks, or the signature does not match
the public key. Without `--pubkey`, verify checks consistency only.

## Limits

- Verification recomputes hashes but does not re-run the checks. A verifier that
  wants fresh evidence should run `make` again.
- A signature proves the key holder issued the receipt. It does not prove the
  checks were run honestly on the machine that signed it.
- Check outputs are hashed, not stored. Keep your CI logs if you need them.
- Signing uses Ed25519 only.
