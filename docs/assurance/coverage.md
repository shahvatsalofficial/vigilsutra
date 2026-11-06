# Test coverage

Measured with Node's built-in coverage (`node --test --experimental-test-coverage`) over the compiled `dist/` of the whole suite, including code reached through the CLI subprocess tests. Raw output: [coverage-raw.txt](coverage-raw.txt). Date 2026-11-07, Windows 11, Node 24.15.

| Metric | Value |
|---|---|
| Tests | 126 (125 passed, 0 failed, 1 skipped) |
| Line coverage | **95.38 %** |
| Branch coverage | **79.88 %** |
| Function coverage | **96.14 %** |

| File | Lines | Branches |
|---|---|---|
| `engine.js` | 99.36 % | 93.13 % |
| `policy.js` | 100 % | 91.30 % |
| `rules/secrets.js`, `rules/code.js`, `rules/infra.js` | 100 % | 96 to 100 % |
| `rules/supply.js` | 96.12 % | 84.38 % |
| `advisories.js` | 97.59 % | 74.51 % |
| `components.js` | 98.28 % | 92.68 % |
| `taint.js` | 100 % | 89.13 % |
| `fix.js` | 97.65 % | 61.90 % |
| `cli.js` | 93.58 % | 52.73 % |
| `adapters.js` | 86.92 % | 68.18 % |
| `git-index.js` | 88.05 % | 51.52 % |
| `git-objects.js` | 89.61 % | 65.75 % |
| `scope.js` | 87.58 % | 72.34 % |

The 2026-11-01 run reported 98.36 % lines and 89.60 % branches on 94 tests. The 0.3.0 run reported 95.24 % lines. This table is the 0.4.0 run. Uncovered lines are still the hard-to-trigger ones: a corrupt pack, a missing advisory file, a scan root outside the work tree, and file symlinks.

## How to read this

- Coverage shows which code ran, not that it is correct.
- `git-objects.js` and `scope.js` are the safety-critical modules with the lowest coverage. Uncovered lines are the hard-to-trigger ones: a corrupt pack, a scan root outside the work tree, a stuck clock, and file symlinks (the junction case is tested on Windows; file symlinks need privileges that were not available, so that test skipped).
- No minimum threshold is enforced in CI.
- No mutation testing has been done.

## Reproduce

```bash
npm run build
node --test --experimental-test-coverage test/vigilsutra.test.mjs test/offline-runtime.test.mjs test/fuzz.test.mjs
```
