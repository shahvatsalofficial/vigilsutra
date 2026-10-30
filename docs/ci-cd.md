# CI/CD usage

```yaml
permissions:
  contents: read
  security-events: write   # only to upload SARIF
steps:
  - uses: actions/checkout@v4          # pin to a commit SHA in production
  - run: node dist/cli.js audit . --format sarif --out vigilsutra.sarif --fail-on high
  - uses: github/codeql-action/upload-sarif@v3
    if: always()
    with:
      sarif_file: vigilsutra.sarif
```

- Use `--baseline .vigilsutra-baseline.json` to fail only on new findings.
- Reports may contain paths and redacted excerpts: keep artifact retention short and do not publish them for private repos.
- Do not audit untrusted forks with elevated tokens. VigilSutra does not execute scanned code, but the workflow around it might.
