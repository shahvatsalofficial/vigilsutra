<!--meta nav="Reading a report" group="Guides" desc="How to read the HTML and Markdown reports, what severity, confidence and status mean, and a triage routine that works."-->
# Reading a report

<p class="lead">A report is only useful if the next action is obvious. This page shows what is in each file, how to read a finding, and a triage routine you can use on a Monday morning.</p>

## The four files

```diagram
reportFiles
```

| File | Who it is for | Use it to |
|---|---|---|
| `report.html` | People | Read in a browser. Self-contained: one file, light and dark mode, prints cleanly, loads nothing from the network |
| `report.md` | People | Paste into a pull request, ticket or wiki |
| `results.json` | Scripts | Feed dashboards, `vigilsutra verify`, and your own tooling |
| `results.sarif` | Tools | Upload to GitHub code scanning (SARIF 2.1.0) |

Try the real thing: [open a sample HTML report](samples/report.html), [Markdown](samples/report.md), [JSON](samples/results.json).

## What the report contains, top to bottom

| Section | What it tells you |
|---|---|
| One-line summary | The first thing to do, in a plain sentence |
| Severity counts | How many critical, high, medium, low and info findings |
| Top priorities | The five most urgent findings from real project code, not from tests |
| How to read this report | A short legend of the terms below |
| All findings | One table, every finding, each linked to its detail |
| Details | Each finding: where, evidence, **Why it matters**, **Fix**, **Verify**, **May be a false positive when** |
| Next steps | A short list: rotate secrets, fix, re-run, baseline |
| Scope and limits | What was scanned, what was skipped, what was **not** checked, and whether a policy narrowed the scan |

## The three words that matter

```diagram
decision
```

| Word | Plain meaning | Example |
|---|---|---|
| **Severity** | How bad it would be if the finding is real | A privileged container is high; a missing `SECURITY.md` is info |
| **Confidence** | How much you can trust the rule on this match | Findings in tests and examples are low |
| **Status** | `confirmed`: the evidence settles it. `potential`: a person must check. `informational`: a note | A token in AWS key format is confirmed. `eval(x)` is potential |

> **Tip.** Treat **confirmed + high** as "do it now". Treat **potential** as a question to answer, not an accusation. The rule's **May be a false positive when** text tells you what to look for.

## A 15-minute triage routine

```steps
1. **Read the summary line.** It tells you whether anything is critical or high.
2. **Handle secrets first.** Any `VS-SECRET-*` finding that is `confirmed` means a credential may be exposed. Rotate it at the provider before anything else.
3. **Work the Top priorities list.** For each one open the detail, read **Why it matters** and **Fix**.
4. **Check potential findings against the code.** Ask where the input really comes from. If it is a constant or trusted data, close it with a baseline or a dated waiver and write down why.
5. **Skim the test and example findings last.** They are kept visible but rarely urgent.
6. **Re-run and verify.** Use `vigilsutra verify --previous results.json` so you see what is gone and what is new.
```

## What a finding in a test folder means

Findings under `test`, `tests`, `__tests__`, `spec`, `fixtures`, `examples`, `_archived`, `vendor` and similar folders are marked **test, example or vendored path** and get low confidence. They are real constructs (a test really does call `eval`), but they rarely carry the same risk. They sort after project code so they do not bury the real issues.

## Secrets in a report

Secret values never appear. You will see `[REDACTED]` in the evidence line. The file path and line number are shown so you can find and rotate the credential. A finding also tells you the **type** (cloud key, GitHub token, private key and so on) but never proves the credential is live: VigilSutra never tests a credential.

> **Warning.** Reports contain file paths and one-line excerpts. They are safe to share with your team, but do not publish them for private repositories. The report folder has its own `.gitignore` so it is not committed by accident.

## Sharing results

| Goal | How |
|---|---|
| Show a manager | Send `report.html` |
| Put it in a pull request | Paste `report.md` |
| Track over time | Keep `results.json` from each run and compare with `verify` |
| See alerts in GitHub | Upload `results.sarif` ([guide](ci-cd.html)) |
| Give an AI assistant the context | Give it `results.json`: it is already redacted. See [AI assistants](ai-assistants.html) |
