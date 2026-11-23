<!--meta nav="Evidence" group="Trust" desc="What was measured, how, and what was not: benchmark on 18 public repos, comparison with Gitleaks and Semgrep, tests, coverage and limits."-->
# Evidence

<p class="lead">A security tool that asks for trust should show its work, including its weak spots. This page lists what was measured, how, and what is **not** proven. Every number links to data in the repository.</p>

{{stats}}

> **Important.** The accuracy and comparison numbers below come from a study on **version 0.1.x**. They were **not re-measured** for 0.3 or 0.4, which added rules. Recall (how many real problems are missed) was never measured. The labels were assigned by the maintainer's AI assistant, not by an independent person. Treat these as an honest first pass, not a verdict.

## Accuracy on real code

The tool was run on 18 public repositories: 7 deliberately vulnerable projects (Juice Shop, NodeGoat, TerraGoat, Kubernetes Goat and others) and 11 mainstream projects (Django, Prometheus, Express and others). Samples of findings were labeled **TP** (a real weakness in project code), **TT** (real construct, but in tests or vendored code) or **FP** (the rule misread the code). After each sample the rules were fixed, then a fresh sample was drawn.

```chart
falsePositives
Sample C was never used to tune a rule. With only 32 findings, 0 false positives still allows a true rate up to about 9 percent.
```

| Sample | Findings labeled | Role |
|---|---|---|
| A: released v0.1.0 rules | 140 | Found the first classes of false positives; rules were tuned on it |
| B: after round-1 fixes | 68 | Found more; rules were tuned on it |
| C: after all fixes | 32 | Never used for tuning: the honest estimate |

What the fixes removed: quoted local workflows read as third-party actions, `eval(` inside strings, JWT `verify=False` read as TLS, `usedforsecurity=False` hashes, route and egress rules read as ingress, wildcard `Deny` statements, placeholder `.env` files, nonroot images, sanitized HTML, translation files and more. Three labels were corrected during checks, which shows the first pass was imperfect.

## Compared with other open-source scanners

Same commits, same Linux CI run (Gitleaks 8.30.1, Semgrep 1.183.0 with `p/security-audit`). The unit is files with at least one finding, summed over the repositories.

```chart
vsGitleaks
Gitleaks found more kinds of secrets (generic API keys, JWTs, Kubernetes secrets) and also scans git history in depth. Use both.
```

```chart
vsSemgrep
The overlap is small because the tools look at different things: that Semgrep ruleset is mostly framework rules; VigilSutra mostly covers CI, Docker, Kubernetes and Terraform. VigilSutra does not replace Semgrep.
```

## Speed

```chart
scanTime
Measured on a GitHub Linux runner in the 0.1.x study. The largest repository, Django, has thousands of files.
```

## Tests and checks that run on every change

| Check | What it proves |
|---|---|
| {{tests}} automated tests | Each rule has a bad and a clean example; redaction, scope, reports, CLI and adapters are covered |
| {{cov}} % line coverage | Measured with Node's built-in coverage (branch coverage {{covb}} %) |
| Offline test | The CLI runs with network and subprocess calls blocked and fails if any is attempted |
| Linux network-namespace step | CI runs the audit where no network interface exists |
| Fuzz and ReDoS tests | Hostile input cannot hang or crash the rules (two real slow patterns were found and fixed) |
| CodeQL and OpenSSF Scorecard | Independent static analysis and a public supply-chain score on the project itself |
| Matrix CI | Ubuntu and Windows on Node 20, 22, 24 and 26 gate every change. macOS runs as a separate, non-blocking job because GitHub's macOS runners are often queued for hours |
| Signed releases | Published from GitHub Actions with provenance, so the package links to the source it was built from |

## What is not proven

- **Recall.** No ground truth exists for how many real problems are missed. Do not read a clean report as "secure".
- **Independent review.** The code has had the maintainer's review and CodeQL, not an outside security reviewer.
- **Independent labels.** The benchmark labels are public in the repository so anyone can disagree.
- **Languages.** Code rules cover JavaScript, TypeScript and Python only.
- **Freshness.** Advisory matches use a dated snapshot, not a live feed.
- **Trademark.** A quick search found no exact match for the name but registered marks with a similar stem exist. That is not a clearance.

## Re-run it yourself

```bash
git clone https://github.com/shahvatsalofficial/vigilsutra.git && cd vigilsutra
npm ci && npm test
node --test --experimental-test-coverage test/*.test.mjs
node benchmarks/run.mjs out          # clones and scans the 18 repositories
```

The full write-ups are in the repository under `docs/assurance/`. If you can review the code or re-label the benchmark, that is the most valuable help the project can get: see `docs/assurance/REVIEW-REQUEST.md`.
