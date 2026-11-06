---
name: threatmap
description: Use when the user wants the audit summary grouped by severity and category, without a new score.
---

# ThreatMap

Part of VigilSutra AI, created by Vatsal Shah.

Read `results.json`. Group findings by `severity`, then by `category`. Quote `path`, `startLine`, and `ruleId`. Do not invent a risk score, and do not hide `potential` findings.

State the `notAssessed` list from the same file. A short list is not a threat model of the business.
