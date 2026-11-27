<!--meta nav="FAQ and glossary" group="Trust" desc="Answers to common questions, troubleshooting for common surprises, and a plain-language glossary."-->
# FAQ and glossary

## Common questions

**Does VigilSutra send my code anywhere?**
No. The scan makes no network request and has no telemetry. A test enforces this. If you give a report to an AI assistant, that assistant's policy applies; share `results.json`, which is already redacted.

**Do I need an account, an API key or an AI model?**
No. The scan is deterministic. AI is optional and comes from your own assistant.

**Is it a penetration-testing tool?**
No. It reads files. It does not probe live systems, exploit anything, or test whether a credential works.

**Does a clean report mean my project is secure?**
No. It means the checks found nothing. Dependencies beyond the bundled snapshot, logic flaws, authentication design and runtime state are not assessed. Every report lists what was **not** checked.

**Which languages are supported?**
Code rules cover JavaScript, TypeScript and Python. Config rules cover Dockerfile, Kubernetes YAML, Terraform, GitHub Actions and AI-agent or MCP files. Secret rules apply to any text file.

**Why are so many findings "potential"?**
Pattern matching cannot prove a data path. `potential` means a person or assistant should confirm it. Each rule explains what would make it a false positive.

**Will it find secrets that were already deleted from the code?**
Yes, within limits. It reads git objects (without running `git`) until the time limit, so a key committed last year and removed since can still be found. Gitleaks and TruffleHog support more token types; use one of them for deep history work.

**What should I do when it finds a leaked key?**
Rotate or revoke it at the provider first. Deleting the line does not undo exposure. Then replace it with an environment variable or secret manager reference.

**How do I silence a known finding?**
Use the narrowest tool: a [baseline](configuration.html#baseline-accept-todays-findings) for everything that exists today, a [waiver](configuration.html#waivers) for one rule on one path until a date, `disableRules` for a rule that is wrong for your whole project.

**Is it compliant with OWASP, NIST, SOC 2 or GDPR?**
No such claim is made. CWE ids appear for orientation only. It is not a certification or legal tool.

**Can I use it commercially?**
Yes. It is Apache-2.0, provided as is, with no warranty.

**What does "Sutra" mean?**
A Sanskrit word for a thread or a concise rule. The name suggests a thread of vigilance through your code.

## Troubleshooting

| What you see | Why, and what to do |
|---|---|
| `vigilsutra: command not found` | Use `npx vigilsutra ...`, or install globally with `npm install -g vigilsutra` |
| The pre-commit hook says "not on PATH" | The hook needs a global install: `npm install -g vigilsutra` |
| "Scanned 0 files" | Everything was ignored, too large or binary. Look at the skip counts on the summary line, and check for a project policy that ignores `**` (try `--no-policy`) |
| "Scan was truncated" | A file-count or time limit stopped the scan. Raise `maxFiles` or `timeLimitMs`, or scan a narrower path |
| A `vigilsutra-report/` folder appeared | It is the default output. It has its own `.gitignore`. Use `--no-report` to skip |
| `.vigilsutra.yml line N: unsupported syntax` | The policy parser accepts a small YAML subset (`key: value` and `- item` lists) on purpose |
| `unknown key "..."` | A typo in the policy. Unknown keys are errors so a typo cannot change scope silently |
| Exit code 2 | Bad flag, bad path, invalid policy or baseline file, or a scan cut short while `--fail-on` was set. The message says which |
| A finding you disagree with | `vigilsutra explain <rule id>` shows when it is a false positive. Open an issue with a minimal example (fake values only) |
| Windows: file symlinks not followed | By design. Links are never followed |

## Glossary

| Term | Meaning |
|---|---|
| Baseline | A saved list of finding fingerprints accepted for now, so only new findings are reported |
| Confidence | How reliable a rule is on a match: high, medium or low |
| Confirmed | The evidence alone settles the finding, for example a token in a known format |
| CWE | Common Weakness Enumeration, a public catalogue of weakness types. Shown for orientation only |
| Fingerprint | A stable identity for a finding that ignores line numbers and secret values |
| MCP | Model Context Protocol, a way for AI assistants to use external tools |
| Not assessed | Something the tool did not examine. Never read as "safe" |
| Path context | A marker on findings in test, example, archived or vendored folders |
| Potential | A pattern match that a person must confirm |
| Prompt injection | Text written to make an AI assistant ignore its instructions |
| Redaction | Replacing a secret value with `[REDACTED]` before any output |
| SARIF | A standard file format for security results, used by GitHub code scanning |
| SBOM | Software bill of materials: a list of the components in your software |
| Severity | How bad a finding would be if it is real |
| Waiver | A dated exception for one rule on one path |
