# CI/CD usage

Pin every action to a commit SHA. A floating tag such as `@v4` is what `VS-CICD-001` reports.

```yaml
permissions:
  contents: read
  security-events: write   # only to upload SARIF
steps:
  - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
  - uses: actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1 # v7.1.0
    with:
      node-version: 22
  - run: npx --yes vigilsutra@0.4.0 audit . --format sarif --out vigilsutra.sarif --fail-on high --no-report
  - uses: github/codeql-action/upload-sarif@9b3254085494b55a0f7c4c2b3d2d52cc712ce370 # v4.39.1
    if: always()
    with:
      sarif_file: vigilsutra.sarif
```

This repository also ships `action.yml`. After a release tag exists, a job can call `uses: shahvatsalofficial/vigilsutra@v0.4.0` instead of `npx`. The action runs `npm ci` inside the action directory, then writes `vigilsutra.sarif`.

- Use `--since <base-sha>` on a pull request when you want the gate to look at the change, not the whole tree. That mode does not read older history.
- Use `--baseline .vigilsutra-baseline.json` to fail only on new fingerprints.
- Use `--no-history` when the job should not read `.git/objects`.
- Reports may contain paths and redacted excerpts: keep artifact retention short and do not publish them for private repos.
- Do not audit untrusted forks with elevated tokens. VigilSutra does not execute scanned code, but the workflow around it might.
