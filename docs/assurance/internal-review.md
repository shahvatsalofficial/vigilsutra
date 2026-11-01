# Internal security review

> **Warning:** this review was done by the project's maintainer working with an AI assistant. It is **not independent**. It exists so that known weaknesses are fixed and visible, and so an outside reviewer has a starting point. See [REVIEW-REQUEST.md](REVIEW-REQUEST.md) for how to ask for an independent review.

Date: 2026-11-01. Scope: all of `src/` (about 1,900 lines), the CLI contract, report writers, the Claude adapter, the GitHub workflows and the fuzz/benchmark data. Method: manual read-through against the threat model, adversarial tests, fuzzing, and a run over 18 public repositories.

## Findings and fixes

| ID | Severity | Finding | Fix | Test |
|---|---|---|---|---|
| IR-1 | medium | **Adapter uninstall trusted its manifest.** The check used a string prefix, so a manifest listing a sibling such as `.claude/skills-evil/x/SKILL.md` would pass and be deleted. The manifest lives in the project and can be edited by anyone with write access. | Entries must resolve to exactly `.claude/skills/<name>/SKILL.md` (path-relative check, no `..`, no absolute paths) | `review: adapter uninstall refuses manifest entries outside ...` |
| IR-2 | medium | **A hostile project can silence the scan.** The project's own `.vigilsutra.yml` can ignore every file or disable rules, so auditing someone else's repository could report "clean". | Reports now state when scope was narrowed by a policy (`scope.policy`, a limitation line). New `--policy <file>` uses a trusted policy and `--no-policy` ignores the project's | `review: a project policy that narrows scope is disclosed ...` |
| IR-3 | low | **Time-of-check/time-of-use symlink swap.** A path could be replaced by a symlink between `lstat` and the read, so the read would follow it out of the project. | Each file is opened once; the descriptor's device and inode must match the earlier `lstat`, otherwise the file is refused. Also halves file opens | `review: isInside ...`, junction test; a race itself is not simulated |
| IR-4 | medium | **Invalid SARIF for unusual paths.** File URIs were not percent-encoded, so paths with spaces, `#` or `%` produce invalid locations in code-scanning tools. | Each path segment is `encodeURIComponent`-encoded | `review: SARIF file locations are percent-encoded URIs` |
| IR-5 | low | **Markdown injection through file names.** A backtick in a file name closed the inline code span in the Markdown report. | Backticks and line breaks replaced in code spans | `review: Markdown report cannot be broken out ...` |
| IR-6 | low | **Terminal escape injection.** ANSI escapes or bidi controls in file names or excerpts reached the terminal. | Control characters neutralized in excerpts and in the text report | `review: terminal control characters ... are neutralized` |
| IR-7 | low | **Unbounded output.** One rule matching every line of a 1 MiB file could create hundreds of thousands of findings. | Cap of 200 findings per rule per file; the cut is disclosed in `limitations` and `scope.cappedFindings` | `review: one rule matching thousands of lines ... is capped` |
| IR-8 | medium | **Two quadratic regular expressions** (found by the fuzz tests): `^\s*-?\s*uses:` on whitespace-only lines and multi-line `\s*` that spans newlines in YAML detection. One crafted 2 MB file took 4 seconds. | Anchored patterns without overlapping quantifiers; `[ \t]*` for same-line whitespace | `ReDoS guard: each rule handles 1,000 adversarial 1,990-character lines quickly` |
| IR-9 | low | **Wrong line used by look-back filters.** Rules located the matched line with `indexOf(line)`, which returns the first identical line in the file, so a later egress block was judged by an earlier ingress block. Found by the holdout benchmark. | Filters receive the real line number | `IAC-001 uses the real line ...` |

| IR-10 | low | **Check-then-write races in `init` and the adapter** (reported by GitHub CodeQL, an independent static analyzer, after it was added to CI). `existsSync` followed by a write could overwrite a file created in between. | `init` creates with the exclusive `wx` flag; adapter installs use `COPYFILE_EXCL` for new files and treat "already exists" as skip | `init creates policy once and never overwrites`, `adapters: claude install is previewable, non-destructive ...` |

All ten were fixed and each has a test (IR-10 reuses existing no-overwrite tests). The test suite grew from 56 to 94 tests as a result of this work. CodeQL's other alerts were a regular expression it judged unanchored (rewritten), a documentation-generator escaping bug (fixed, it would have mis-rendered pipe characters in `docs/rules.md`) and a race in a test helper (dismissed: test code).

## Checked and found acceptable

- No `child_process`, network, `eval` or dynamic `import()` in `src/` (static test and runtime test with blocked network and subprocess APIs).
- `--out` writes where the user asks; nothing else is written by `audit`, `verify`, `explain`, `rules` or `doctor`.
- HTML report: every untrusted value passes through one escaper; strict CSP; tested with hostile names and code.
- Fingerprints never include secret values; secret spans from all rules on a line are removed from every finding that quotes the line.
- Policy and baseline parsers reject malformed and hostile input with exit code 2 (tested with 1 MB lines, 50,000 list items, NUL and lone surrogates).

## Residual risks (not fixed)

1. Pattern rules are evadable by obfuscation and produce false positives (measured in [benchmark.md](benchmark.md)).
2. The time limit is checked between files, so a stalled filesystem read is not interrupted.
3. Regular-expression safety is evidenced by fuzzing with 16 adversarial shapes, not by a formal proof.
4. The TOCTOU defence is not tested with a real race; it relies on the descriptor's device and inode, which some filesystems report as zero (the check is skipped there).
5. Windows long paths (over 260 characters) were not tested.
6. The Claude adapter copies skill text; a malicious or compromised copy of this package could ship hostile skill instructions. Install from the official npm package or repository and review `agents/*/SKILL.md`.
7. No third-party has reviewed any of this.
