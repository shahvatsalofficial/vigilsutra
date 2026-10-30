<div align="center">

# VigilSutra AI

**Inspect Everything. Expose Risks. Protect What Matters.**

Open-source, offline-first **security and privacy auditor** for your codebase, plus portable **AI agent skills** (Claude Code and more).
Finds hardcoded secrets, risky GitHub Actions, Docker and Kubernetes misconfigurations, Terraform exposure, injection patterns and unsafe AI-agent setups, then writes redacted, evidence-based reports in **SARIF, JSON, Markdown and HTML**.

[![CI](https://github.com/shahvatsalofficial/vigilsutra/actions/workflows/test.yml/badge.svg)](https://github.com/shahvatsalofficial/vigilsutra/actions/workflows/test.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
![Node >=20](https://img.shields.io/badge/node-%3E%3D20-339933)
![No telemetry](https://img.shields.io/badge/telemetry-none-brightgreen)
![Offline](https://img.shields.io/badge/works-offline-brightgreen)

</div>

> Created by **Vatsal Shah**. Status: **v0.1.0, early release.** Every feature listed as *Implemented* below is covered by automated tests in this repository; everything else is labelled *Planned*.

## Why VigilSutra

- **Local-first and private.** The scan runs on your machine. No account, no API key, no AI model, no telemetry, no network requests. A test enforces that the source imports no network modules.
- **Read-only by default.** It never executes scanned code, never follows symlinks out of the project, and never edits your files.
- **Evidence before assertion.** Each finding has a rule ID, file and line, redacted evidence, **severity and confidence reported separately**, and a status: `confirmed` (evidence is conclusive) or `potential` (needs human confirmation).
- **Secrets are never printed.** Values are redacted in every output format and excluded from fingerprints.
- **Honest scope.** Reports list what was scanned, skipped and *not assessed*. There is no "100% secure" score.
- **Works with AI IDEs.** Ships Agent Skills (`vigilsutra-prime`, `codeguard`, `secretwatch`, `privacylens`, `infraguard`, `verify`) that call the same CLI, so your IDE's own model reviews redacted results without another API key.

## Quickstart

Requires Node.js 20+.

```bash
git clone https://github.com/shahvatsalofficial/vigilsutra.git
cd vigilsutra
npm install
npm run build
node dist/cli.js audit examples/intentionally-insecure
```

Typical use on your own project:

```bash
# human-readable summary
node dist/cli.js audit /path/to/project

# reports for CI and code scanning
node dist/cli.js audit . --format sarif    --out vigilsutra.sarif
node dist/cli.js audit . --format json     --out vigilsutra-results.json
node dist/cli.js audit . --format markdown --out vigilsutra-report.md
node dist/cli.js audit . --format html     --out vigilsutra-report.html

# fail a CI job on high or critical findings
node dist/cli.js audit . --fail-on high
```

> npm publication is not done yet; the `vigilsutra` package name is reserved for a future release. Until then run from a clone, or `npm link` to get a global `vigilsutra` command.

## Commands

| Command | What it does |
|---|---|
| `vigilsutra audit [path]` | Read-only scan. Formats: `text`, `json`, `markdown`, `sarif`, `html`. Flags: `--out`, `--fail-on`, `--baseline`, `--no-color`. |
| `vigilsutra baseline --out f.json` | Record current findings as accepted risk. |
| `vigilsutra verify --previous results.json` | Re-scan and show what is gone, remaining or new. |
| `vigilsutra rules list` / `explain <ID>` | Browse rules, fixes and false-positive notes. |
| `vigilsutra doctor` | Environment, offline readiness and adapter status. |
| `vigilsutra init` | Create `.vigilsutra.yml` (never overwrites). |
| `vigilsutra adapters list / install claude / uninstall claude` | Manage AI-IDE skills (`--dry-run` previews). |

Exit codes: `0` ok, `1` findings at or above `--fail-on` (or new findings in `verify`), `2` usage or runtime error.

## What it checks (feature matrix)

| Area | Rules | Status |
|---|---|---|
| Secrets (AWS key IDs, GitHub tokens, Slack tokens, private keys, hardcoded credentials, `.env` files) | `VS-SECRET-001..006` | **Implemented** |
| GitHub Actions (unpinned actions, `pull_request_target` checkout, `write-all`, expression injection) | `VS-CICD-001..004` | **Implemented** |
| Docker (root user, `:latest`, `curl \| sh`) | `VS-DOCKER-001..003` | **Implemented** |
| Kubernetes (privileged, host namespaces, root / privilege escalation) | `VS-K8S-001..003` | **Implemented** |
| Terraform / IaC (open CIDR, public ACL, wildcard IAM) | `VS-IAC-001..003` | **Implemented** |
| JS / TS / Python code patterns (eval, shell injection, deserialization, SQLi, TLS off, weak hash, HTML sinks) | `VS-CODE-001..007` | **Implemented** (pattern-based, no taint analysis) |
| AI agents (prompt-injection phrases, disabled approvals, unpinned MCP servers) | `VS-AGENT-001..003` | **Implemented** |
| Privacy signals (PII in logs, trackers) and missing `SECURITY.md` | `VS-PRIV-001..002`, `VS-PROC-001` | **Implemented** |
| SARIF 2.1.0, JSON, Markdown, HTML (escaped), baselines, verify | | **Implemented** |
| Claude Code skill adapter (install, uninstall, dry-run) | | **Implemented** (file install tested; in-IDE behaviour depends on Claude Code) |
| Dependency inventory, SBOM, advisories | | Planned |
| Cursor, Codex, Gemini CLI, Copilot adapters | | Planned (not verified) |
| Local LLM / provider adapters, patch proposals, server mode | | Planned |
| Waivers with owner and expiry | | Planned |

See [docs/rules.md](docs/rules.md) for the full rule list and [docs/compatibility.md](docs/compatibility.md) for tested environments.

## Use it from Claude Code (optional)

```bash
node dist/cli.js adapters install claude --project /path/to/project --dry-run   # preview
node dist/cli.js adapters install claude --project /path/to/project
```

Then ask: *"Use vigilsutra-prime to audit this repository and cite exact evidence."* The skill runs the offline CLI and reasons over the redacted JSON using your IDE's own model. Existing skill files are never overwritten without `--force`; `uninstall` removes only files VigilSutra installed.

## CI example

```yaml
name: security
on: [pull_request]
permissions:
  contents: read
jobs:
  vigilsutra:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4   # pin to a commit SHA in production
      - run: |
          git clone --depth 1 https://github.com/shahvatsalofficial/vigilsutra.git /tmp/vs
          cd /tmp/vs && npm ci && npm run build
          node /tmp/vs/dist/cli.js audit "$GITHUB_WORKSPACE" --format sarif --out vigilsutra.sarif --fail-on high
```

More in [docs/ci-cd.md](docs/ci-cd.md).

## Privacy and security model

- No network access, telemetry, accounts or hidden uploads. `vigilsutra doctor` states this and the test suite checks it statically.
- Scanned files are treated as untrusted data. Instructions inside them (for example in `AGENTS.md`) are reported as findings, never followed.
- Findings contain redacted excerpts only. Secret values never reach reports, fingerprints or AI prompts.
- Read the [threat model](docs/threat-model.md), [security model](docs/security-model.md) and [privacy model](docs/privacy-model.md).

## Limitations (please read)

VigilSutra is a defensive review aid, not a pentest tool, certification service or substitute for human review. It uses pattern rules without data-flow analysis, so many results are `potential`. It does not scan git history, dependencies or running systems, and a clean report is not proof of security. CWE identifiers are shown for orientation only; no OWASP, NIST, SOC 2, ISO or GDPR compliance is claimed.

## Contributing, security, license

- [CONTRIBUTING.md](CONTRIBUTING.md) | [SECURITY.md](SECURITY.md) | [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) | [docs/rule-authoring.md](docs/rule-authoring.md)
- Licensed under [Apache-2.0](LICENSE). See [NOTICE](NOTICE).
- Author and maintainer: **Vatsal Shah** ([@shahvatsalofficial](https://github.com/shahvatsalofficial)).

<sub>Keywords: security scanner, secret scanning, SAST, DevSecOps, GitHub Actions security, Docker security, Kubernetes security, Terraform security, SARIF, privacy audit, AI agent security, MCP security, Claude Code skills, offline security tool.</sub>
