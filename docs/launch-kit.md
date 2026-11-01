# Launch kit

Material for announcing VigilSutra honestly. Every number below comes from [assurance/benchmark.md](assurance/benchmark.md) and the other assurance pages; update them when you re-run.

## One-paragraph description

VigilSutra AI is an open-source, offline security and privacy auditor for codebases. One command scans a project read-only, with no account, API key or network access, and writes redacted SARIF, JSON, Markdown or HTML reports. It checks secrets, GitHub Actions, Dockerfiles, Kubernetes, Terraform, JS/TS/Python code patterns and AI-agent configuration, and ships agent skills so an AI assistant can drive it. Early release; Apache-2.0.

## Short post (Hacker News / Reddit / dev.to)

> **Show HN: VigilSutra, an offline security scanner for repos, built to be honest about what it finds**
>
> I built a small, zero-dependency CLI (`npx vigilsutra audit .`) that scans a repo locally for hardcoded secrets, risky GitHub Actions, Docker/Kubernetes/Terraform misconfigurations, injection patterns and unsafe AI-agent/MCP setups. It never touches the network (there is a test that blocks the network and subprocesses and checks nothing is attempted), redacts secrets in every output, and labels each finding `confirmed` or `potential` with a separate confidence.
>
> To check myself I ran it on 18 public repos (OWASP Juice Shop, NodeGoat, TerraGoat, Kubernetes Goat, Django, Prometheus and others) and labeled 240 findings. The first version had an 18% false-positive share in my sample; after fixing the classes I found it was 0 of 32 on a fresh sample (small sample: the true rate could be up to about 9%). Fuzzing found two quadratic regexes I would have shipped. I also compared against Gitleaks and Semgrep: Gitleaks is the better secrets scanner, and Semgrep covers code I do not, so this is a complement, not a replacement.
>
> Caveats up front: pattern-based (no taint analysis), only JS/TS/Python code rules, no dependency or git-history scanning, labels were assigned by me with an AI assistant, and nobody independent has reviewed it yet. I would love a review: <https://github.com/shahvatsalofficial/vigilsutra/blob/main/docs/assurance/REVIEW-REQUEST.md>.

## Blog outline

1. The problem: first-pass security review that is private and does not need accounts.
2. Design rules: read-only, offline, redact before output, severity and confidence separate, never claim "secure".
3. How I tried to break it: fuzzing found 2 real quadratic regexes; a hostile-repository test; network-blocked runtime test.
4. Measuring on real code: method, the false-positive classes found, before and after, what was lost.
5. How it compares: Gitleaks, Semgrep.
6. Honest limits and what I want reviewed.

## Where to share

| Place | Notes |
|---|---|
| Hacker News (Show HN), r/netsec, r/devops, r/cybersecurity, dev.to, Lobsters | Read each community's self-promotion rules first |
| "awesome" lists: awesome-security, awesome-devsecops, awesome-static-analysis, awesome-claude-code, awesome-mcp | Open a pull request following each list's format |
| Claude Code / agent-skills communities | Share the skills in `agents/` |
| GitHub: social preview image (1280x640) in repository settings, Discussions on, "good first issue" labels | Settings, owner action |
| OpenSSF: Scorecard badge once its first run is public | Workflow is in place |

## Assets to create (owner)

- Social preview image 1280x640 (name, tagline, a 4-line terminal excerpt).
- A 20-second screen recording of `npx vigilsutra audit .`; the static terminal image in `docs/assets/demo.svg` is generated from real output.

## What not to say

Do not claim "secure", "audited", "certified", "enterprise-ready", any recall or detection percentage, or any user count you cannot show.

## Good first issues to open

1. Add `VS-SECRET` rules for more token formats (Stripe, npm, Slack webhooks) with fixtures. (Verify each format from the provider's documentation.)
2. Add a `vigilsutra explain --json` output.
3. Add a Java rule family (`Runtime.exec` with concatenation, `ObjectInputStream`), with fixtures and a benchmark check.
4. Independent re-labeling of `benchmarks/labels-*.json`.
5. Add a Windows long-path (over 260 characters) test.
