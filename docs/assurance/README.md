# Trust and verification

Everything on this page can be re-run. Where something has **not** been verified, it says so.

## Claim, evidence, how to check

| Claim | Evidence | Reproduce |
|---|---|---|
| Works offline, no network or subprocess use | Static test, runtime test with blocked network and subprocess APIs, Linux network-namespace test in CI: [offline-verification.md](offline-verification.md) | `npm test` |
| Does not crash, hang or leak on hostile input | Fuzz and ReDoS tests; two real quadratic regexes were found and fixed: [fuzzing.md](fuzzing.md) | `npm test` |
| Tests exercise the code | 98.4 % line, 89.6 % branch coverage: [coverage.md](coverage.md) | see file |
| Few false positives on real code | Benchmark on 18 public repositories with a labeled sample, a holdout sample and a regression check: [benchmark.md](benchmark.md) | `node benchmarks/run.mjs` |
| How it compares | Same commits scanned with Gitleaks and Semgrep: [benchmark.md](benchmark.md#comparison-with-other-open-source-scanners) | **benchmark** workflow |
| Small, auditable supply chain | Zero runtime dependencies, SBOMs, `npm audit` clean, pinned Actions: [supply-chain.md](supply-chain.md) | `npm sbom`, `npm audit` |
| Reviewed for security flaws | Internal review, nine fixes with tests: [internal-review.md](internal-review.md). **Not independent.** | read the tests |
| Name conflicts | Preliminary search, **not clearance**: [trademark-search.md](trademark-search.md) | |
| How vulnerabilities are handled | [SECURITY.md](../../SECURITY.md) and the public ledger [security-advisories.md](../security-advisories.md) | |

## What is deliberately not claimed

- No claim of certification, compliance, or "secure".
- No recall figure: how many real problems VigilSutra misses is **not measured**.
- No independent review or independent labels yet; [REVIEW-REQUEST.md](REVIEW-REQUEST.md) explains how to provide them.
- No adoption claims. See [ADOPTERS.md](../../ADOPTERS.md).

## The plan behind this page

[TRUST-PLAN.md](TRUST-PLAN.md) lists every gap that was identified, what was done and what remains (some items need the owner or an outside party).
