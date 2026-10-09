# Agent receipts v0.1

A RECEIPT.json is evidence that an agent's "done" claim is backed by checks.
It records the task, each named check's exit code and output hash, the SHA-256
of each produced artifact, and a `selfHash` over the whole receipt.

## Fields

| field | meaning |
| --- | --- |
| `version` | `"0.1"` |
| `task` | what the agent says it did |
| `agent` | who produced it |
| `result` | `"pass"` only if every check exited 0 and at least one check ran |
| `checks[]` | `name`, `command`, `exitCode`, `passed`, `durationMs`, `outputSha256` |
| `artifacts[]` | `path`, `sha256` (paths relative to the project root) |
| `selfHash` | SHA-256 of the canonical JSON of the receipt without `selfHash` |

## Use

```bash
node receipt.mjs make --task "Fix login redirect" --agent my-agent \
  --check "tests=npm test" --check "typecheck=npm run typecheck" \
  --artifact src/login.ts --out RECEIPT.json
node receipt.mjs verify RECEIPT.json          # run from the project root
```

`make` exits 1 when any check fails, so it can gate a CI job. `verify` exits 1
when the receipt was edited, an artifact changed, a check failed, or the
`result` field disagrees with the checks.

## Limits (v0.1)

- Verification recomputes hashes but does not re-run the checks. A verifier that
  wants fresh evidence should run `make` again.
- No signatures: a receipt proves consistency, not who created it. Signing is
  the next step.
- Check outputs are hashed, not stored.
