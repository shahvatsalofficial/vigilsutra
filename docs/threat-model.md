# Threat model

**Assets:** source and secrets on the user's disk; report integrity; trust in findings.
**Trust boundary:** everything inside the scanned folder is untrusted input.

| Threat | Control | Status |
|---|---|---|
| Malicious repo with instructions aimed at an AI agent | Content is data; flagged by VS-AGENT-001; skills restate rules | Tested (scope unchanged) |
| Symlink or junction pointing at `~/.ssh` or elsewhere | Never followed; counted in report | Tested where the OS permits symlinks |
| Huge, binary or deeply nested files (DoS) | Size, count, time limits; binary skip | Size and binary tested; time limit not stress-tested |
| Secret leakage via report, SARIF, HTML, console | Redaction at source plus scrub step | Tested in all formats |
| Stored XSS in HTML report from hostile names or code | Escaping and CSP | Tested |
| Supply-chain attack on this tool | Zero runtime dependencies; lockfile for dev dependencies | Automated dependency audit not yet added |
| Adapter overwrites user files | Preview, no-overwrite default, manifest uninstall | Tested |
| Update-channel compromise | No auto-update exists | N/A |
| Remote-inference leakage | No remote inference in v0.1 | N/A |
| Server multi-tenant isolation | No server mode in v0.1 | N/A |
