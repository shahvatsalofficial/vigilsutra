# Request for independent review

VigilSutra has had **no independent review**. If you are a security engineer, you can help build (or break) trust in it.

## What to review

| Area | Where | Questions |
|---|---|---|
| Scope safety | `src/scope.ts`, `src/policy.ts` | Can a hostile repository make the scan read outside the project, hang, or hide findings? |
| Redaction | `src/engine.ts`, `src/redact.ts`, `src/reporters/` | Can any secret value reach a report, fingerprint, console or SARIF? |
| Rules | `src/rules/` | Are the claims in each rule's description and false-positive text true? |
| Report safety | `src/reporters/index.ts` | HTML, Markdown and SARIF injection |
| Adapter | `src/adapters.ts`, `agents/*/SKILL.md` | Install/uninstall safety; could a skill be abused through a hostile repository? |
| Supply chain | `package.json`, `.github/workflows/` | Release process, pinning, permissions |

## How

1. Read [internal-review.md](internal-review.md) and [the threat model](../threat-model.md).
2. Run `npm ci && npm test` and the [benchmark](benchmark.md) workflow.
3. Open a **private** report for anything exploitable (see [SECURITY.md](../../SECURITY.md)), or a normal issue for false positives and documentation errors.
4. If you are willing to be named, say so. A short signed-off statement ("reviewed commit X, scope Y, findings Z") will be added to [security-advisories.md](../security-advisories.md) with your permission.

Labels in the benchmark were assigned by an AI assistant. Independent re-labeling of `benchmarks/labels-*.json` is equally welcome: open a pull request with your disagreements.
