<!--meta nav="CI/CD and hooks" group="Guides" desc="Run VigilSutra in GitHub Actions with SARIF upload, as a pre-commit hook, on pull requests that only scan the change, and in any other CI."-->
# CI/CD and hooks

<p class="lead">Put the scan where mistakes happen: on the developer's machine before a commit, and on every pull request before a merge.</p>

```diagram
ciGate
```

## GitHub Actions with code scanning

```yaml
name: vigilsutra
on: [pull_request]
permissions:
  contents: read
  security-events: write   # only to upload SARIF
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<full-commit-sha>   # v4 or newer
        with:
          fetch-depth: 0
      - uses: actions/setup-node@<full-commit-sha>
        with:
          node-version: 22
      - run: npx --yes vigilsutra audit . --format sarif --out vigilsutra.sarif --fail-on high --no-report
      - uses: github/codeql-action/upload-sarif@<full-commit-sha>
        if: always()
        with:
          sarif_file: vigilsutra.sarif
```

> **Important.** Pin every action to a **full commit SHA**, not a tag such as `@v4`. A tag can be moved. This is exactly what rule `VS-CICD-001` reports, and VigilSutra's own workflows follow the rule.

### Why these settings

| Setting | Reason |
|---|---|
| `permissions: contents: read` | The job only needs to read code. `security-events: write` is added only for the upload |
| `fetch-depth: 0` | Lets the git-history pass see older commits |
| `--format sarif --out ...` | The format GitHub code scanning reads |
| `--fail-on high` | Makes the step exit 1 on high or critical findings, so the check can block a merge |
| `--no-report` | Do not write the report folder on the runner |
| `if: always()` | Upload alerts even when the scan step failed the job |

### Ready-made action

The repository ships an `action.yml`. After a release tag exists, a job can use `uses: shahvatsalofficial/vigilsutra@<tag>` instead of `npx`. It installs the tool inside the action directory and writes `vigilsutra.sarif`.

## Only look at what the pull request changed

On a pull request you often want the gate to judge the change, not the whole history of the repository:

```bash
npx --yes vigilsutra audit . --since origin/main --fail-on high --no-report
```

`--since` scans worktree files that differ from the revision and does not read older history.

## Fail only on new findings

For an existing project, add a baseline so only new findings can fail the job:

```bash
npx --yes vigilsutra audit . --baseline .vigilsutra-baseline.json --fail-on high --no-report
```

See [scenario 2](scenarios.html#scenario-2-adopt-it-on-a-legacy-repo-without-a-red-build) for how the baseline is created and shrunk.

## Pre-commit hook

```bash
npm install -g vigilsutra
vigilsutra init --hook
```

`init --hook` installs `.git/hooks/pre-commit` only if no hook exists there. The hook runs:

```bash
vigilsutra audit . --staged --fail-on high --no-report --no-history
```

So it scans what you are about to commit and stops the commit on high or critical findings. If `vigilsutra` is not on the `PATH`, the hook stops the commit and says so, rather than silently skipping.

Bypassing a hook (`git commit --no-verify`) is always possible, which is why the CI gate matters too.

## Other CI systems

Anything that can run Node 20 or newer works. The pattern is always:

```bash
npx --yes vigilsutra audit . --fail-on high --no-report
```

| System | Note |
|---|---|
| GitLab CI | Run the command in a `node:22` image; upload `results.json` as a job artifact |
| Jenkins | Same command in a Node agent; archive `vigilsutra-report/` if you drop `--no-report` |
| Azure Pipelines, CircleCI, Bitbucket | Same command; there is no vendor lock-in |

## Good practice

- **Keep artifact retention short.** Reports contain paths and redacted excerpts. Do not publish them for private repositories.
- **Do not scan untrusted forks with powerful tokens.** VigilSutra does not run the code it scans, but the workflow around it might. Use `pull_request`, not `pull_request_target`, for untrusted code.
- **Use `--no-policy` on code you do not own.** See [Configuration](configuration.html#auditing-code-you-do-not-own).
- **Do not run `vigilsutra` on a self-hosted runner that holds long-lived secrets in the scanned folder.** Reports redact what they recognise; they cannot recognise everything.
