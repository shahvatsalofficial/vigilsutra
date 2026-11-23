<!--meta nav="Security and privacy" group="Trust" desc="What VigilSutra guarantees (and how each guarantee is tested), what data it handles, how to report a vulnerability, and its known limits."-->
# Security and privacy

<p class="lead">A tool that reads your code must be safe to point at your code. Here is what it promises, how each promise is checked, and what it cannot do.</p>

## The promises

```diagram
trust
```

| Promise | How it is checked |
|---|---|
| **No network.** The scan never makes a request | A test blocks network, DNS and subprocess calls and fails if any is attempted; CI also runs the audit with no network interface |
| **Read-only.** It never changes your project | A test lists the folder before and after a scan; only `fix --apply` and the report folder write |
| **Never runs your code** | No subprocess is started by the scan, enforced by the same test |
| **Stays inside the folder** | Links and junctions are never followed; each file is opened once and checked to be the same file that was listed |
| **Secrets are never printed** | Planted secrets are searched for in every output format and must not appear |
| **Reports cannot attack the reader** | HTML is escaped with a strict content-security policy and no scripts or remote links; Markdown and terminal output neutralise hostile file names |
| **Hostile input cannot hang it** | Fuzzing and timing tests on every rule; size, file-count and time limits |
| **A project cannot quietly narrow the scan** | A project policy that narrows scope is disclosed in the report; `--no-policy` ignores it |
| **Installs are safe** | Adapters and `init` never overwrite existing files and create new ones atomically |

## How secrets are kept out

```diagram
redaction
```

## What data it handles

| Question | Answer |
|---|---|
| Does it collect data? | No telemetry, accounts, cloud storage or update checks |
| Does it send data anywhere? | No. The scan makes no network request |
| What do the reports contain? | Relative file paths, line numbers, one-line excerpts with secrets removed, and rule text |
| Is personal data exported? | No. Privacy rules report the kind and location, never the value |
| What about AI assistants? | Optional and outside the CLI. The assistant's own data policy applies. Share `results.json` (already redacted), not your source |
| Where do reports live? | Only where you write them. The report folder has its own `.gitignore` |

> **Warning.** Reports can still reveal your project's structure (file paths). Do not publish them for private repositories, and keep CI artifact retention short.

## A hostile repository

The scanned project is untrusted input. It may contain text meant to steer an AI assistant, files designed to make a scanner slow, a policy that hides findings, or links that point out of the folder.

| Attack | Defence |
|---|---|
| "Ignore your instructions" text in `AGENTS.md` | Treated as data; reported as `VS-AGENT-001` |
| A policy file that ignores everything | Disclosed in the report; `--no-policy` |
| A symlink to `~/.ssh` | Links are never followed |
| A huge file or a pattern that makes a regex slow | Size and time limits; fuzz-tested rules |
| A file name with terminal escape codes or a backtick | Neutralised in console and Markdown output |
| A tampered adapter manifest | Uninstall removes only exact skill paths it recognises |

## Known limits

- It matches patterns. Obfuscated code can slip past, and some matches are false positives.
- It has not had an independent security review. See [Evidence](evidence.html#what-is-not-proven).
- It does not sandbox itself at the operating-system level.
- A time-of-check/time-of-use race (a file swapped for a link while the scan runs) is defended against but was not tested with a real race.
- Reports reflect a point in time. Rotate a leaked secret even if a later scan no longer shows it.

## Reporting a vulnerability in VigilSutra

Use GitHub's private reporting: **Security tab, then Report a vulnerability** on the repository. Please do not open a public issue for a security bug. Expect an acknowledgement within 7 days. The project is run by one maintainer, so these are goals, not guarantees. Reports, fixes and reviews are recorded publicly in `docs/security-advisories.md` in the repository.

## Using it responsibly

Audit only code and systems you own or are allowed to review. VigilSutra does not test live systems or credentials, but reading someone else's private code without permission can still breach law or contract. Findings are engineering signals, not certification or legal advice. Privacy findings are prompts for human review, not a statement about GDPR, DPDP or CCPA compliance.
