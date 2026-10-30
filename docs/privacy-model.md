# Privacy model

- VigilSutra collects nothing: no telemetry, account, cloud storage or update check.
- Reports go only where you point `--out`. They contain paths and redacted excerpts, which can still be sensitive. Do not publish reports of private repositories.
- Secret values are never written to reports. Personal data is flagged by category and location, not exported.
- AI use is optional and outside the CLI. If an AI IDE reads a report, that IDE's data policy applies. Share the redacted JSON, not source, when unsure.
- `VS-PRIV-*` findings are engineering prompts, not legal conclusions. Have a qualified professional assess GDPR, India DPDP, CCPA/CPRA or other obligations.
