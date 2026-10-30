# Evidence and benchmarks

Everything here was measured on the code in this repository. Re-run it yourself; do not rely on this page alone.

## Environment

Windows 11 Home, Node.js 24.15.0, 14 logical CPUs, date 2026-10-31, version 0.1.0.

## Test results

Command: `npm test` (builds, then `node --test test/*.test.mjs`).

| Metric | Value |
|---|---|
| Tests | 56 |
| Passed | 55 |
| Failed | 0 |
| Skipped | 1 (symlink-escape test; Windows denied symlink creation, so that behaviour was **not** exercised on this run) |

What the tests cover: 31 vulnerable/clean fixture pairs, `VS-PROC-001` presence/absence, secret redaction in 5 formats, fingerprint stability and line-shift resilience, paths with spaces and non-ASCII characters, CRLF line numbers, size and binary limits, default ignores, HTML escaping, hostile repository instructions, SARIF structure, JSON-schema required keys, a static no-network check on `src/`, scan immutability, policy parsing, CLI exit codes, baseline and verify, `init` and adapter install/uninstall safety, skill frontmatter, and a self-audit.

## Detection quality: what is and is not claimed

- On the **31 controlled fixture pairs**, every vulnerable fixture is flagged and no clean fixture is. Because the fixtures were written by the rule author, this shows rules behave as designed, **not** real-world accuracy.
- **Not measured:** false-positive rate on real repositories, recall on public vulnerability benchmarks, comparison against other scanners. Treat any `potential` finding as a lead to review.

## Performance

Measured with `audit()` called in-process, one run each, cold file cache not controlled.

| Target | Files scanned | Size | Time | Process RSS |
|---|---|---|---|---|
| `node_modules/typescript` | 129 | 6.1 MiB | about 177 ms | about 74 MiB |
| This repository | 53 | 0.2 MiB | about 32 ms | about 75 MiB |

Files over the size limit (default 1 MiB) are skipped and counted, so the TypeScript figure excludes its largest bundles. No large-monorepo test has been run.

## Reproduce

```bash
git clone https://github.com/shahvatsalofficial/vigilsutra.git && cd vigilsutra
npm install && npm test
node dist/cli.js audit examples/intentionally-insecure --format json
node dist/cli.js audit . --fail-on medium     # self-audit
```

## Sample reports

`examples/sample-reports/` holds Markdown, SARIF and JSON generated from `examples/intentionally-insecure`. They are samples, contain only fake values, and are excluded from self-audit by `.vigilsutra.yml`.
