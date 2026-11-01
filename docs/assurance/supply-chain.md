# Supply chain: dependencies, licenses, SBOM

Date 2026-11-01. Package `vigilsutra@0.1.0`.

## Runtime dependencies: none

`package.json` has no `dependencies`. Installing `vigilsutra` from npm installs one package: itself. The CycloneDX 1.5 SBOM for production contains **0 components** ([sbom-production.cdx.json](sbom-production.cdx.json)); an SPDX version is in [sbom-production.spdx.json](sbom-production.spdx.json).

## Development dependencies (build and test only, never shipped)

| Package | Version | License |
|---|---|---|
| typescript | 5.9.3 | Apache-2.0 |
| @types/node | 22.20.5 | MIT |
| undici-types (via @types/node) | 6.21.0 | MIT |

Full dev SBOM: [sbom-full-dev.cdx.json](sbom-full-dev.cdx.json). All licenses are compatible with Apache-2.0 distribution.

## Known vulnerabilities

`npm audit` on 2026-11-01 reported **0** vulnerabilities (info 0, low 0, moderate 0, high 0, critical 0) across 3 dev dependencies ([npm-audit.json](npm-audit.json)). An audit is a point-in-time check against the npm advisory database.

## Build and release integrity

| Control | State |
|---|---|
| Lockfile committed, `npm ci` in CI | yes |
| GitHub Actions pinned to commit SHAs | yes, all workflows |
| Dependabot for Actions and npm | enabled |
| Workflow permissions | `contents: read` by default; `id-token: write` and `security-events: write` only where needed |
| OpenSSF Scorecard workflow | added; first result pending |
| npm provenance (attestation linking the package to this repository and workflow) | **workflow written, not yet exercised.** Requires the owner to configure Trusted Publishing on npmjs.com; see [releasing.md](../releasing.md). The published 0.1.0 was uploaded by hand and has no provenance |
| Reproducible builds | not verified |
| Package contents | 44 files in `dist`, `agents`, `adapters`, `policies`, `schemas`, `docs`, `templates` and top-level docs; no source maps, no tests |

## Reproduce

```bash
npm ci && npm audit
npm sbom --sbom-format cyclonedx --omit dev
npm pack --dry-run
```
