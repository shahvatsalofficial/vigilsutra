# Changelog

## Unreleased

- Security: every secret on a line is redacted, including a second value matched by the same rule and values found in different windows of a long line.
- A placeholder first on a line no longer hides a real secret after it.
- The placeholder filter now skips only values made entirely of filler words, so real secrets that start with `password`, `secret`, `test` and similar are reported.
- The CLI accepts `--flag=value` and rejects unknown options, so a mistyped `--fail-on` can no longer pass a CI gate.
- `--staged` applies policy ignore patterns and the file size limit.
- With `--fail-on`, an incomplete scan (time or file limit, including git history) exits 2 instead of passing.
- UTF-16 files with a byte-order mark are scanned. A byte-order mark no longer breaks `.vigilsutra.yml`.
- SBOM: scoped npm packages get a valid purl (`pkg:npm/%40scope/name@1.0.0`).
- `fix --apply` no longer rewrites SHA-1, which protocols such as the WebSocket handshake require.
- GitHub Action: pull request and merge queue runs use the base commit's `.vigilsutra.yml`, so a pull request cannot ignore its own findings.
- Secret rules now read `dist/`, `build/`, `out/`, `vendor/` and `*.min.js`. Other rules still skip them.
- `VS-SECRET-004` reads unquoted values in YAML, shell, `.npmrc`, `.properties`, TOML, INI and Dockerfiles, and the names `token` and `cryptoKey`.
- Advisory matching and the SBOM read lockfiles at any depth, npm lockfile version 1 and Yarn Berry.
- `VS-IAC-001` reports open ingress that follows an egress block, and Azure `*`/`Internet` sources. `VS-IAC-003` reports `*` anywhere in an action list.
- Evidence for long lines shows the matched text, and a note counts further matches on the same line.
- HTML report: badge colours meet 4.5:1 contrast in light and dark, and severities can be filtered without scripts.
- `.env.example`, `.env.sample` and `.env.template` files are checked for real-looking credentials.
- More generated cache folders are ignored by default.
- Removed a stale rule count from the report summary and a missing folder from the package file list.
- Fingerprints can change for lines with repeated secrets; refresh a baseline if needed.

## Unreleased (after pull request 17)

- New rule `VS-AGENT-004`: hidden Unicode (direction controls, tag characters, and zero-width characters in agent instruction files). Rules version `1.3.0`, 43 rules.
- SARIF adds `security-severity`, `helpUri` and `automationDetails` for code scanning.
- The GitHub Action writes the Markdown report to the job summary.
- Fixed: `VS-IAC-001` again ignores `aws_vpc_security_group_egress_rule` and similar egress resources.

## Unreleased (reports, CLI and workflows)

- New rules `VS-DB-001`, `VS-DB-002` (databases without authentication), `VS-IAC-004` (public database or storage) and `VS-IAC-005` (access granted to everyone). Rules version `1.6.0`, 56 rules.
- `vigilsutra completion <bash|zsh|powershell>` prints a shell completion script.
- Tests fail when rule docs, rule counts or the help text drift from the code.
- New JavaScript, TypeScript and Python rules `VS-CODE-008` to `VS-CODE-012`: NoSQL injection, path traversal, SSRF, open redirect and weak cookie flags. They match request data used on the same line. Rules version `1.5.0`, 52 rules.
- Findings from Git history state the commit date and whether the file still exists in HEAD.
- New rules `VS-K8S-004` (hostPath), `VS-K8S-005` (dangerous capabilities), `VS-K8S-006` (RBAC wildcard) and `VS-COMPOSE-001` (host-level Compose settings). Rules version `1.4.0`, 47 rules.
- Waivers accept a wildcard path, an optional `:line` and an optional reason.
- The SBOM reads `Cargo.lock`, `poetry.lock`, `composer.lock` and `Gemfile.lock`. Advisory matching covers the Poetry packages (PyPI), not the other three ecosystems.
- Fixed: `--report-dir` on a folder with other files, such as the project root, no longer overwrites its `.gitignore`.
- Report files are readable by the owner only (POSIX), and a report folder inside a commonly published folder prints a warning.
- `SOURCE_DATE_EPOCH` pins report and SBOM timestamps and the SBOM serial number, for byte-identical output.
- Mistyped commands and options suggest the closest one.
- `VS-CICD-002` reports checkout of `refs/pull/.../merge`. `VS-CICD-004` also reads `actions/github-script` scripts.

## 0.4.2 - 2026-11-24

- New documentation site (`site/`): guided pages, diagrams, charts, six real-world scenarios, light theme by default with a dark option, phone and desktop layouts, search, and a fresh sample report generated from the real CLI. Built by a zero-dependency generator and deployed by the Pages workflow. No rule or CLI changes.

## 0.4.1 - 2026-11-16

- Report footers (HTML and Markdown) show the author credit as plain text instead of a link to shahvatsal.com, so the HTML report contains no remote links and stays fully offline.
- The author credit links to shahvatsal.com in the README, `llms.txt`, `CITATION.cff` and `package.json`.
- No rule or CLI behaviour changes.

## 0.4.0 - 2026-11-07

- Git history reads SHA-1 and SHA-256 objects (loose and pack index version 2, including deltas) until the time limit. The 200-commit and 2,500-blob caps are gone. A blob over 1 MiB is still skipped. `--no-history` skips the pass.
- `VS-SUPPLY-004` matches resolved npm, PyPI, and Go versions against `advisories/db.json.gz`, an OSV snapshot built 2026-11-07 (npm, PyPI, Go). No network call. `--no-advisories` skips it. `--advisories <file>` selects another snapshot.
- `vigilsutra sbom` writes a CycloneDX 1.6 JSON bill from `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, pinned `requirements.txt` lines, and `go.mod`. Ranges are not listed as if they were exact.
- `vigilsutra fix` prints deterministic edits and writes them only with `--apply`. It can flip privileged and host-namespace flags, a public storage ACL, disabled TLS checks, and MD5/SHA-1 hash calls. It does not delete secrets or invent a user name or a commit SHA.
- Request-like names (`req`, `request`, `params`, `query`, `body`, `input`, `event`) are tracked through relative JavaScript, TypeScript, and Python imports. `VS-CODE-001` raises confidence when that name reaches `eval` or `exec`. Object fields, dynamic `import()`, and function return values are not tracked.
- Rules version is `1.2.0`.

## 0.3.0 - 2026-11-07

- Git history is read from `.git` objects (loose and SHA-1 packs, including deltas) without running `git`. Removed secrets can still be reported under `git-history/<commit>/<path>`. Caps: 200 commits, 2,500 blobs. `--no-history` skips it. Identical worktree copies are not reported twice.
- `--since <rev>` scans only worktree files that differ from that revision. `--staged` scans the git index, which is what `vigilsutra init --hook` installs as a pre-commit hook.
- New secret rules: JWT (`VS-SECRET-007`), npm tokens (`008`), Stripe secret keys (`009`), Google API keys (`010`), Azure storage account keys (`011`), GitLab personal access tokens (`012`). Excerpts stay redacted.
- Manifest rules `VS-SUPPLY-001` through `003` flag unauthenticated dependency URLs, wildcard versions, and install scripts that download code. Advisories are still not matched.
- Waivers in `.vigilsutra.yml` use `ruleId|path|owner|YYYY-MM-DD`. A waiver past its date does not hide the finding. Active waivers are disclosed.
- `VS-CODE-001` raises confidence when the same file assigns a request-like name into `eval`. That is not interprocedural taint analysis.
- Lines longer than 2,000 characters are scanned in overlapping windows. When a filesystem reports inode 0, a swapped file is refused if size or mtime changed.
- File-copy adapters for Cursor, Codex, Gemini CLI, and Copilot, beside Claude. In-IDE invocation is not automated-tested. Twelve specialist skills shipped; skills that have no rule say "not assessed".
- `Dockerfile` (not published), composite `action.yml`, and a GitHub Pages workflow for `docs/`.
- Rules version is `1.1.0`. Docs that still said v0.1.0 were corrected.

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
