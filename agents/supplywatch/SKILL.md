---
name: supplywatch
description: Use when the user asks about dependencies, lockfiles, install scripts, SBOMs, or VS-SUPPLY findings. Matches the shipped advisory snapshot. It does not call a live feed.
---

# SupplyWatch

Part of VigilSutra AI, created by Vatsal Shah.

`VS-SUPPLY-001` flags `http://` and `git://` dependencies. `VS-SUPPLY-002` flags `*`, `latest`, or an empty version in package.json. `VS-SUPPLY-003` flags preinstall, install, or postinstall scripts that download code. `VS-SUPPLY-004` matches a resolved version to a range in the advisory snapshot shipped with this version. That snapshot is not a live feed. Say so. `vigilsutra sbom` writes CycloneDX JSON for pinned components.

Never run an install script to see what it does.
