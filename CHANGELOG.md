# Changelog

## 0.2.3 - 2026-11-06

- `vigilsutra audit` and `vigilsutra report` always write `vigilsutra-report/report.md` and `report.html` (plus `results.json` and `results.sarif`), including when the command is piped or run in CI. The short summary stays on stdout. `--no-report` skips the files. The folder notice goes to stderr so JSON and SARIF on stdout stay valid.

## 0.2.2 - 2026-11-06

- Local `.env` files are no longer reviewed when git does not track them. `VS-SECRET-006` and the other rules see an environment file only if it is listed in the git index, or if the folder has no usable git index. `.env.example`, `.env.sample`, and `.env.template` are unchanged. The check reads the index file directly and does not run `git`. Path compare follows `core.ignorecase` (on by default for Windows and macOS).
- Required CI is Ubuntu and Windows on Node 20, 22, 24 and 26. Hosted `macos-latest` jobs stayed queued and were cancelled with zero steps, which failed the check before any test ran. The suite is plain Node and has no native addon.

## 0.2.1 - 2026-11-04

- Rewrote the six agent skills (`agents/*/SKILL.md`): descriptions that trigger on what users actually say, the reason behind each safety rule, the new `vigilsutra report` command, `--no-policy` for code you do not own, `pathContext` triage, and explicit "not for" and limits sections.

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
