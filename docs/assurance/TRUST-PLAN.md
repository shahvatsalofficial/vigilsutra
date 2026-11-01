# Trust plan: gaps, work done, what remains

Written 2026-11-01 after an independent-auditor style review of what a skeptical visitor would ask for. Status values: **Done**, **Done with caveat**, **Blocked** (needs the owner or an outside party), **Not possible by tooling**.

| # | Gap | Status | What was done | What remains |
|---|---|---|---|---|
| 1 | Real-world accuracy evidence (fixtures were written by the rule author) | **Done with caveat** | Ran 18 public repos; labeled a sample; found and fixed 20+ false-positive classes; measured a holdout sample; regression-checked that real findings survive: [benchmark.md](benchmark.md) | Labels are AI-assigned and the sample is not random. Independent human re-labeling would strengthen it |
| 2 | Comparison with other tools on a shared corpus | **Done with caveat** | Gitleaks 8.30.1 and Semgrep 1.183.0 on identical commits, on Linux CI; 7 deliberately vulnerable projects included | Trivy and CodeQL not run. Recall not measured |
| 3 | Independent verification | **Blocked / not possible by tooling** | Internal review with 9 fixes and tests: [internal-review.md](internal-review.md); open request for reviewers: [REVIEW-REQUEST.md](REVIEW-REQUEST.md) | Someone outside the project has to review it. Owner: recruit a reviewer |
| 4 | npm provenance | **Blocked** | `release.yml` publishes with provenance via Trusted Publishing; Actions pinned; Dependabot on | Owner must add the Trusted Publisher on npmjs.com and run a release. Version 0.1.0 on npm has no provenance |
| 5 | Verified offline claim | **Done** | Runtime test with blocked network/subprocess APIs; Linux network-namespace step in CI: [offline-verification.md](offline-verification.md) | |
| 6 | Visible CI status | **Done** | CI badge, 3 OS x Node 20/22 matrix, compatibility page; Scorecard workflow added | Scorecard badge appears after its first run on `main` |
| 7 | Fuzz and ReDoS testing | **Done** | Seeded fuzz and adversarial-timing tests; found 2 real quadratic regexes: [fuzzing.md](fuzzing.md) | No formal regex analysis |
| 8 | Coverage figure | **Done** | 98.4 % lines, 89.6 % branches: [coverage.md](coverage.md) | No enforced threshold or mutation testing |
| 9 | Dependency, license and SBOM report | **Done** | CycloneDX and SPDX SBOMs, license table, `npm audit`: [supply-chain.md](supply-chain.md) | Zero runtime dependencies, so little to report |
| 10 | Security response record | **Done with caveat** | Policy, targets, public ledger: [security-advisories.md](../security-advisories.md) | There is no external report history yet and none was invented |
| 11 | Real demo | **Done with caveat** | Terminal image generated from real output (`docs/assets/demo.svg`) | A public demo repository showing alerts in GitHub's code-scanning tab was **not created** (needs the owner's approval to create another public repository). No animated GIF |
| 12 | Stars, early adopters, answered issues | **Not possible by tooling** | `ADOPTERS.md`, issue templates, [launch-kit.md](../launch-kit.md) | Real users and their feedback |
| 13 | Launch write-up with real numbers | **Done with caveat** | Draft in [launch-kit.md](../launch-kit.md) using measured numbers | Owner to publish and promote |
| 14 | Public changelog and cadence | **Done with caveat** | CHANGELOG, tags, releases | Cadence depends on the maintainer |
| 15 | Rule precision claims in docs | **Done** | Each rule's false-positive text kept; benchmark per-rule table; confidence lowered for test and example paths | |
| H1 | Exposed GitHub token | **Blocked** | Never written to the repo | Owner must revoke it |
| H2 | npm package owned by a personal account, org exists | **Blocked** | | `npm owner add` / transfer to the `vigilsutra` org |
| H3 | Trademark clearance | **Blocked** | Preliminary search: [trademark-search.md](trademark-search.md) | Formal search by an attorney |
| H4 | Dependabot major bumps (TypeScript 7, @types/node 26, checkout 7) | **Pending** | PR checks exist; TypeScript 7 failed CI | Review and close or merge each |

## Principles used

1. Publish measured results only, with method and limits next to the number.
2. Fix what the measurement finds, then measure again on data the fixes were not tuned on.
3. Never invent users, reviews, reports or endorsements.
