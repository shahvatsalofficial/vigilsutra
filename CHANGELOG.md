# Changelog

## 0.2.0 - 2026-11-04

- **Reports as files.** New `vigilsutra report` command, and `audit --report` / `--report-dir`, write `report.md`, `report.html`, `results.json` and `results.sarif` (plus a `.gitignore`) to `./vigilsutra-report/`. In an interactive terminal, `audit` without `--format` or `--out` now does this by default; piped or CI runs are unchanged. `--no-report` turns it off.
- **Clearer reports.** Markdown and HTML now open with a plain-language "what to do first" summary, severity counts, a how-to-read guide, a findings table, findings grouped by severity with Fix and Verify steps, next steps, and scope and limits. The HTML file is self-contained, supports light and dark mode and printing, and has no scripts or remote resources.
- The `vigilsutra-report/` folder is ignored by scans, so reports are never re-scanned.
- CI: macOS runs Node 22 and 26 only (macOS runners were queued for hours and showed as failed checks); Dependabot no longer proposes major `@types/node` bumps.

## 0.1.3 - 2026-11-04

- Build with TypeScript 7.0.2 (`tsconfig.json` now lists `"types": ["node"]`); GitHub Actions updated to current majors (checkout 7, setup-node 7, codeql-action 4, upload-artifact 7), still pinned to commit SHAs.

## 0.1.2 - 2026-11-01

- CI now tests Node 20, 22, 24 and 26 (current LTS) on Ubuntu, macOS and Windows; all 12 jobs pass. Docs updated. No code changes.

## 0.1.1 - 2026-11-01

- Release workflow publishing to npm with provenance (Trusted Publishing); Dependabot for Actions and npm; workflow actions pinned to commit SHAs; OpenSSF Scorecard workflow; manual benchmark workflow.
- **Security fixes from an internal review** (see docs/assurance/internal-review.md): adapter uninstall validates manifest entries; a project policy that narrows scope is disclosed in reports (`--policy`, `--no-policy` added); single-descriptor file reads with inode check; SARIF paths percent-encoded; Markdown and terminal output neutralize hostile file names and control characters; per-rule per-file finding cap.
- **Two quadratic regular expressions fixed** (found by new fuzz tests).
- **Fewer false positives**, found by running on 18 public repositories (quoted local workflows, string-literal matches, JWT `verify=False`, `usedforsecurity=False`, routes and egress rules, `Effect: Deny`, `$variable` placeholders, `.env` placeholders, nonroot images, sanitized HTML, translation files). Findings in test, example, archived and vendored paths now have low confidence and `pathContext: test-or-example`.
- `failOn` in `.vigilsutra.yml` is now applied.
- New: runtime offline test, fuzz/ReDoS tests, benchmark tooling (`benchmarks/`), assurance documentation (`docs/assurance/`), SBOMs, coverage report.

## 0.1.0 - 2026-10-31

First public release (early). Published to npm as `vigilsutra@0.1.0`.

- Offline, read-only CLI: `audit`, `baseline`, `verify`, `rules`, `explain`, `doctor`, `init`, `adapters`.
- 32 rules across secrets, GitHub Actions, Docker, Kubernetes, Terraform, JS/TS/Python code patterns, AI agents, privacy signals and process.
- Reports: text, JSON, Markdown, SARIF 2.1.0, escaped HTML.
- Secret redaction in all formats; stable fingerprints that exclude secret values and line numbers.
- Safe scoping: symlinks never followed, size/count/time limits, binary skipping.
- Six Agent Skills and a Claude Code project adapter (preview, no-overwrite, manifest-based uninstall).
- Not included yet: dependency/SBOM/advisories, other IDE adapters, local-LLM adapter, waivers, patch proposals.
