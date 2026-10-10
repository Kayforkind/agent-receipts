# Security policy

## Scope and support

The current checkout is a locally hardened release candidate, not an independent security certification. Use a currently supported Node LTS (22 or 24), a reviewed lockfile and `npm ci --ignore-scripts`. Run `npm run verify` before use. Do not treat heuristic PASS/checked/verified results as proof of safety, privacy, accessibility compliance or scientific truth. See README for tool-specific boundaries.

## Deployment boundaries

These are local CLI/stdio tools, not public multi-tenant services. Run adversarial files in a dedicated low-privilege process with OS memory/time limits and minimal filesystem/network access. Do not execute commands from untrusted receipts or install skills solely because a scan passed. Realpath checks do not eliminate concurrent local filesystem races. Keep inputs and reports private; reports can disclose names, paths or extracted data. The PDF MCP server returns content to the AI client, whose model-provider policy applies.

## Reporting vulnerabilities

Use this repository's GitHub private vulnerability reporting feature if enabled. Otherwise ask the maintainer to provide a private reporting channel without posting payloads, secrets or customer documents in a public issue. No dedicated monitored security inbox or response-time SLA has been established.

## Checks

Security CI runs syntax and regression checks on Linux and Windows, Node 22 and 24, with read-only repository permissions and pinned actions. Dependency audits are included where runtime packages are installed; audits only detect known advisories and do not certify bundled code. External GitHub Actions results and live-client integration must be confirmed separately before release.
