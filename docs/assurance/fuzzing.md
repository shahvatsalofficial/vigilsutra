# Fuzzing and ReDoS testing

Tests: `test/fuzz.test.mjs` (run by `npm test`). Raw timings: [fuzz-results.json](fuzz-results.json).

## What is tested

1. **No rule throws** on 40 rounds of generated input: 60 lines each of 1 to 2,400 characters, drawn from 22 shapes (long runs of one character, near-matches of each rule's pattern, quote and backtick storms, random tokens including NUL, lone surrogates, right-to-left controls and CJK), against 12 file kinds (Dockerfile, JS, Python, workflow, Kubernetes YAML, Terraform, agent file, MCP JSON, `.env`, PEM, shell, JSON).
2. **ReDoS guard**: every rule is given files of 1,000 adversarial lines of 1,990 characters (16 shapes) and must finish in under 1,500 ms per file. Lines over 2,000 characters are skipped by design.
3. **Whole-audit robustness**: malformed UTF-8, lone surrogates, NUL bytes and a 900 KB single line.
4. **Parser robustness**: the policy parser with 1 MB values, 50,000 list items, 100,000 colons, NUL and surrogate floods; baseline and previous-result inputs that are `{`, `[]`, `null`, wrong types or a 100 KB number must be rejected with exit code 2.

The PRNG is seeded, so failures reproduce.

## Results (2026-11-01, Windows 11, Node 24)

All tests pass. Slowest rules on the 1,000-line adversarial files:

| Rule | Worst time for 1,000 adversarial lines |
|---|---|
| VS-DOCKER-002 | 94 ms |
| VS-AGENT-002 | 56 ms |
| VS-PRIV-002 | 32 ms |
| every other rule | under 25 ms |

## What fuzzing found

Before the fixes, the same test failed:

- `VS-CICD-001` took **4.4 s** on 1,000 whitespace-only lines (a quadratic pattern `^\s*-?\s*uses:`).
- `VS-CICD-002` and the Kubernetes detector took **1.7 s** on a 2 MB file of blank lines because `\s*` in a multi-line regex spans newlines.

Both were fixed (see [IR-8](internal-review.md)). Without this test they would have shipped.

## Limits of this evidence

- Sixteen adversarial shapes are not exhaustive. A formal analysis or a dedicated regex-safety tool has not been run.
- Timings depend on the machine and are loose upper bounds, not benchmarks.
- Fuzzing covers the rules and parsers, not the filesystem walk.
