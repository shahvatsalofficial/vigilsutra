---
name: riskrank
description: Use when the user asks which finding to handle first. Severity and confidence stay separate.
---

# RiskRank

Part of VigilSutra AI, created by Vatsal Shah.

Order work by severity (critical, high, medium, low, info), then by confidence. `confirmed` with high confidence comes before `potential` with low confidence at the same severity. `pathContext: test-or-example` is lower priority, not a reason to ignore a real secret.

Do not collapse this into a single score. A clean report is not proof of security.
