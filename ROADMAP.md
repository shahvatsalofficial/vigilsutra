# Roadmap

Plans, not promises. Order may change; nothing here is implemented unless the README feature matrix says so.

## Next (v0.2)
- Dependency inventory from lockfiles (offline), with clear "advisory data not loaded" status.
- Waivers with owner, reason and expiry.
- More rule fixtures from real-world false-positive reports.

## Later
- SBOM export (CycloneDX) from verified inventory data.
- Optional git-history secret scan.
- Additional adapters (Cursor, Codex, Gemini CLI, Copilot) only after checking each host's current documentation.
- Optional local-LLM and provider adapters with an explicit redacted-content preview.
- Safe patch proposals as diffs for human review.
- Public benchmark suite with measured precision and recall.

## Non-goals
Exploitation, credential testing, automatic fixes without approval, telemetry, mandatory accounts or cloud services.
