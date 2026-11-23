<!--meta nav="How it works" group="Learn" desc="The scan pipeline, trust boundaries, how a match becomes a finding, and how secrets are removed. Diagrams and plain language."-->
# How it works

<p class="lead">VigilSutra is a small program with one job: read a folder safely, judge what it finds honestly, and report without leaking. Here is each part, with pictures.</p>

## The scan, step by step

```diagram
pipeline
```

| Step | What happens | Why it is built this way |
|---|---|---|
| 1 Resolve | The folder is turned into its real path | Every later check uses one trusted location |
| 2 Inventory | Files are listed. Links and junctions are never followed | A repo cannot point the scan at your home folder |
| 3 Filter | Ignored folders, files over 1 MiB and binary files are skipped and counted | The scan stays fast and the skips are visible |
| 4 Check | Each file is tested by the rules that apply to its type | Docker rules never run on Python, so noise stays low |
| 5 Redact | Secret values are cut out of the text | Nothing built after this can leak them |
| 6 Report | Findings are sorted, fingerprinted and written | The same input gives the same report every time |

The dashed boxes in the picture are optional passes that feed the same list:

- **Git history.** Reads git objects directly, without running the `git` program, to find secrets that were removed from the files but still sit in history. Skip it with `--no-history`.
- **Advisory snapshot.** Compares pinned package versions with a bundled OSV snapshot. It is a snapshot, not a live feed. Skip it with `--no-advisories`.
- **Name tracking.** Follows request-like names such as `req`, `body` and `query` through relative imports to raise confidence that user input reaches `eval` or `exec`. It does not follow object fields or values returned from functions.

## Who is trusted

```diagram
trust
```

The most important idea: **everything in the project you scan is untrusted.** A README, an `AGENTS.md`, a comment, even the project's own policy file may be written by someone who wants the scan to look clean or wants an AI assistant to misbehave. VigilSutra treats all of it as data. It never executes it and never obeys it.

## How a match becomes a finding

```diagram
decision
```

Three separate questions, three separate fields:

| Field | Question | Values |
|---|---|---|
| Severity | How bad would this be if it is real? | critical, high, medium, low, info |
| Confidence | How reliable is this rule on this match? | high, medium, low |
| Status | Does the evidence alone settle it? | confirmed, potential, informational |

Keeping them apart is deliberate. A secret in the shape of a real AWS key is **confirmed** (the evidence settles the format) and **high** severity. A call to `eval` is only **potential** until a person traces where its input comes from, even though the severity is high.

Findings in test folders, examples, archives and vendored code are kept but get **low confidence** and sort last, because the same pattern in a test is rarely the same risk.

## How secrets stay out of the report

```diagram
redaction
```

The value is removed before the excerpt, the fingerprint or any output is built. If two rules match the same line, every secret on that line is removed from every finding that quotes the line. There is also a last-resort scrub for token-shaped text. This is tested across text, JSON, Markdown, SARIF and HTML output.

## Why the same finding keeps the same fingerprint

Each finding has a stable fingerprint made from the rule, the file, the cleaned line and its position among identical lines. It does **not** include the line number or the secret value. So adding code above a finding does not change it, which makes baselines and `verify` reliable.

## What it never does

- It never runs your code, your scripts or your tests.
- It never makes a network request. A test blocks network and subprocess calls and fails if anything tries.
- It never edits your files, except `fix --apply` (which you must ask for) and the report folder you asked for.
- It never reads outside the folder you named.

Next: see it in action in the [real-world scenarios](scenarios.html).
