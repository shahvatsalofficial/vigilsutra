<!--meta nav="Configuration" group="Guides" desc="The .vigilsutra.yml policy file, ignores and limits, baselines, dated waivers, fail thresholds and scanning only what changed."-->
# Configuration

<p class="lead">VigilSutra works with zero configuration. When you need to tune it, there is one small policy file, a baseline, and dated waivers. This page shows each and when to use it.</p>

## Which tool for which problem

| You want to... | Use | Lives in |
|---|---|---|
| Skip folders or files | `ignore` | `.vigilsutra.yml` |
| Turn a noisy rule off everywhere | `disableRules` | `.vigilsutra.yml` |
| Accept every existing finding, block new ones | a **baseline** | `.vigilsutra-baseline.json` |
| Allow one rule on one path for a limited time | a **waiver** | `.vigilsutra.yml` |
| Fail the build at a severity | `failOn` or `--fail-on` | policy or command line |
| Scan only what changed | `--since <rev>` or `--staged` | command line |

## Create the policy file

```bash
vigilsutra init
```

This writes `.vigilsutra.yml` and never overwrites an existing one. Every key is optional:

```yaml
version: 1
ignore:
  - examples/sample-reports/**
maxFileSize: 1048576      # bytes; larger files are skipped and counted
maxFiles: 20000           # scanning stops and says so beyond this
timeLimitMs: 60000        # wall-clock limit for the walk
failOn: high              # same as --fail-on high
disableRules: []          # for example: - VS-CODE-006
```

| Key | Meaning |
|---|---|
| `ignore` | Extra glob patterns. They **add to** the built-in ignores, never replace them |
| `maxFileSize`, `maxFiles`, `timeLimitMs` | Safety limits. If a limit stops the scan, the report says it was truncated |
| `failOn` | Default exit-1 threshold when `--fail-on` is not given |
| `disableRules` | Rule ids that do not run |
| `waivers` | Dated exceptions (below) |

The parser is strict on purpose: an unknown key is an error, so a typo can never quietly change what is scanned.

### What is ignored by default

`.git`, `node_modules`, virtual environments, cache folders such as `__pycache__`, `.cache` and `.turbo`, `coverage`, `.next`, `target`, `vigilsutra-report` and common lockfiles for content scanning (lockfiles are still read for dependency checks). **`dist`, `build`, `out`, `vendor` and `*.min.js` are read by secret rules only**, because they ship to users. **`.env` files are not ignored**: a committed `.env` is exactly the kind of thing the scan should catch. An untracked local `.env` in a git repository is skipped and its contents are not read.

## Silencing a finding on purpose

Pick the narrowest tool.

### Baseline: accept today's findings

```bash
vigilsutra baseline . --out .vigilsutra-baseline.json
vigilsutra audit . --baseline .vigilsutra-baseline.json
```

The summary keeps counting what is hidden ("16 suppressed by baseline"), so the debt stays visible. If a file is moved, its accepted findings stay accepted; a copy is still reported. See [scenario 2](scenarios.html#scenario-2-adopt-it-on-a-legacy-repo-without-a-red-build).

### Waivers

A waiver hides **one rule on one path, or a wildcard of paths, until a date**. After the date it stops hiding the finding, so exceptions cannot become permanent by accident.

```yaml
waivers:
  - VS-CODE-001|src/legacy.js:12|dana|2026-12-31|rewrite planned
  - VS-CODE-006|tools/**|dana|2026-12-31
```

The parts are `rule id | path[:line] | owner | last day (UTC, inclusive) | reason (optional)`. A path with `*` or `**` is a wildcard; any other path must match exactly. The report counts active waivers and says that the policy narrowed the scan.

### Disable a rule

Use `disableRules` only for a rule that is wrong for your whole project. The report notes that a rule was disabled.

## Scanning only what changed

| Flag | What it scans | Good for |
|---|---|---|
| (default) | The whole working folder, plus git history | A full audit |
| `--staged` | The git index, i.e. what the next commit would record | Pre-commit hooks |
| `--local` | The working folder including untracked `.env` files, with local-only findings marked | Checking your machine before you commit |
| `--since <rev>` | Worktree files that differ from `<rev>` (skips history) | Pull request checks that should judge the change |
| `--no-history` | Skips reading git objects | When the job must not read `.git` |

## Auditing code you do not own

> **Warning.** A project's own `.vigilsutra.yml` is written by the project. It can ignore every file or switch rules off. For code you do not own, use `--no-policy` (built-in defaults only) or `--policy <your-file>` (a policy you trust). Reports say when a project policy narrowed the scan, but do not count on spotting that line. See [scenario 3](scenarios.html#scenario-3-auditing-a-repo-that-tries-to-hide-its-problems).

## Other switches

| Flag | Effect |
|---|---|
| `--rules <file>` | Add your own rules from a JSON file (see the README). Never read from the project on its own |
| `--no-advisories` | Do not match the bundled advisory snapshot |
| `--advisories <file>` | Match a snapshot you supply instead |
| `--no-report` / `--report-dir <dir>` | Control where report files go |
| `--no-color` or `NO_COLOR=1` | Plain output for logs |

## Exit codes

| Code | Meaning |
|---|---|
| `0` | The scan finished and nothing reached the `--fail-on` threshold |
| `1` | At least one finding reached the threshold (or `verify` found new findings) |
| `2` | Usage or runtime error, for example a bad flag or an invalid policy, or an incomplete scan with `--fail-on` |
