# Test coverage

Measured with Node's built-in coverage (`node --test --experimental-test-coverage`) over the compiled `dist/` of the whole suite, including code reached through the CLI subprocess tests. Raw output: [coverage-raw.txt](coverage-raw.txt). Date 2026-11-01, Windows 11, Node 24.15.

| Metric | Value |
|---|---|
| Tests | 94 (93 passed, 0 failed, 1 skipped) |
| Line coverage | **98.36 %** |
| Branch coverage | **89.60 %** |
| Function coverage | **98.82 %** |

| File | Lines | Branches | Not covered |
|---|---|---|---|
| `engine.js` | 99.12 % | 91.58 % | an error path |
| `policy.js` | 100 % | 98.25 % | |
| `reporters/index.js` | 100 % | 92.00 % | |
| `rules/*` | 100 % | 96 to 100 % | one helper function |
| `cli.js` | 98.02 % | 62.79 % | two lines; many option branches |
| `adapters.js` | 97.33 % | 72.22 % | two lines |
| `scope.js` | 86.99 % | 71.74 % | time limit, unreadable files and directories, the symlink (not junction) branch, swapped-file branch |

## How to read this

- Coverage shows which code ran, not that it is correct. A line can run without its result being checked.
- `scope.js` has the lowest coverage and is the safety-critical module. The uncovered branches are the hard-to-trigger ones: the time limit, permission errors, a file swapped for a link during the scan, and file symlinks (the junction case is tested on Windows; file symlinks need privileges that were not available, so that test skipped).
- No minimum threshold is enforced in CI yet.
- No mutation testing has been done.

## Reproduce

```bash
npm run build
node --test --experimental-test-coverage test/vigilsutra.test.mjs test/offline-runtime.test.mjs test/fuzz.test.mjs
```
