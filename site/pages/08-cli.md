<!--meta nav="CLI reference" group="Reference" desc="Every command and flag, exit codes, the files the tool reads and writes, and the exact help text of the installed version."-->
# CLI reference

<p class="lead">Every command, with what it reads, what it writes, and when to use it. The help text at the bottom is generated from the real CLI on every site build, so it cannot drift.</p>

## Commands at a glance

| Command | What it does | Writes files? |
|---|---|---|
| `vigilsutra report [path]` | Scan and write `report.md`, `report.html`, `results.json`, `results.sarif` | Yes, the report folder |
| `vigilsutra audit [path]` | The same scan. Prints the summary and, in a terminal, also writes the report folder | Report folder unless `--no-report` |
| `vigilsutra fix [path]` | Preview deterministic safe edits | Only with `--apply` |
| `vigilsutra verify --previous <results.json>` | Re-scan and compare with an earlier run | No |
| `vigilsutra baseline --out <file>` | Record current findings as accepted | The baseline file |
| `vigilsutra sbom [path]` | CycloneDX 1.6 bill of materials | Only with `--out` |
| `vigilsutra explain <RULE-ID>` | Explain one rule: why, fix, verification, false positives | No |
| `vigilsutra rules list` | List all rules | No |
| `vigilsutra doctor` | Environment and offline-readiness check | No |
| `vigilsutra init [path]` | Create `.vigilsutra.yml` (never overwrites); `--hook` adds a pre-commit hook | The policy file, the hook |
| `vigilsutra adapters ...` | Install or remove AI-assistant skills | Skill files |

## `audit` flags

| Flag | Meaning |
|---|---|
| `--format <f>` | `text` (default), `json`, `markdown`, `sarif`, `html`, `csv`, `junit` |
| `--out <file>` | Write that format to a file instead of the screen |
| `--fail-on <sev>` | Exit 1 if any finding is at or above `critical`, `high`, `medium`, `low` or `info` |
| `--baseline <file>` | Hide findings recorded in the baseline; the count is still shown |
| `--policy <file>` / `--no-policy` | Use a policy file you trust / ignore the project's own policy |
| `--report`, `--report-dir <dir>`, `--no-report` | Control the report folder |
| `--no-history` | Do not read git objects |
| `--since <rev>` | Scan only worktree files that differ from a git revision |
| `--staged` | Scan the git index (what the next commit records) |
| `--local` | Also read untracked `.env` files, and mark findings that are not in the last commit. They still count for `--fail-on` |
| `--no-advisories` / `--advisories <file>` | Skip or replace the advisory snapshot |
| `--no-color` | Plain output; `NO_COLOR` also works |

## Flags of other commands

| Flag | Meaning |
|---|---|
| `--project <dir>` | `adapters install` and `uninstall`: the project to change |
| `--rules <file>` | Also apply custom rules from a JSON file |
| `--force` | `adapters install`: overwrite existing files |
| `--dry-run` | `adapters install`: show the plan only |
| `--annotate` | Also print GitHub Actions annotations |

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Finished; nothing reached the `--fail-on` threshold |
| `1` | A finding reached the threshold, or `verify` found new findings |
| `2` | Usage or runtime error, or an incomplete scan with `--fail-on` |

## Files it reads and writes

```diagram
pipeline
```

| Reads | Writes |
|---|---|
| Files inside the folder you name (never outside, never through links) | `vigilsutra-report/` when you ask or run interactively |
| `.vigilsutra.yml` and any baseline or advisory file you name | `.vigilsutra.yml` from `init` |
| Git objects under `.git` (without running `git`) unless `--no-history` | A pre-commit hook from `init --hook` |
| Its own bundled advisory snapshot | Edited files only from `fix --apply` |

It makes no network requests and runs no subprocesses.

## Exact help text

```term vigilsutra --help
{{help}}
```
