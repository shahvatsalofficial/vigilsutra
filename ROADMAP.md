# Roadmap

Plans, not promises. Order may change; nothing here is implemented unless the README feature matrix says so.

## Shipped in 0.4.0
- SHA-1 and SHA-256 git history until the time limit. The 200-commit and 2,500-blob caps are gone. Blobs over 1 MiB are skipped.
- Offline advisory match against the 2026-11-07 OSV snapshot (`VS-SUPPLY-004`).
- `vigilsutra sbom` (CycloneDX 1.6) and `vigilsutra fix` (dry-run unless `--apply`).
- Relative-import name tracking for `VS-CODE-001`. Object fields, dynamic imports, and call returns stay untracked.

## Shipped in 0.3.0
- Git-history secret scan, `--since`, `--staged`, and a pre-commit hook.
- Manifest rules `VS-SUPPLY-001` through `003`.
- Waivers with owner and an inclusive expiry date.
- File-copy adapters for Cursor, Codex, Gemini CLI, and Copilot. In-IDE invocation is still not automated-tested.

## Later
- Optional local-LLM adapters with an explicit redacted-content preview.
- A public benchmark with recall measured by someone other than the maintainer. The 18-repo study was not re-run for 0.4.0, and recall is still unknown.
- An independent human review. The 2026-11-01 review was not independent, and 0.4.0 does not add one.

## Non-goals
Exploitation, credential testing, deleting secrets automatically, telemetry, mandatory accounts or cloud services.
