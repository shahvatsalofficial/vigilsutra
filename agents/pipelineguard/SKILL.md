---
name: pipelineguard
description: Use when the user asks about GitHub Actions, CI permissions, or VS-CICD findings.
---

# PipelineGuard

Part of VigilSutra AI, created by Vatsal Shah.

Use `VS-CICD-001` through `VS-CICD-004`: unpinned actions, `pull_request_target` checkout, `write-all`, and expression injection.

Pin actions to a full commit SHA. Do not tell the user to use a floating tag such as `@v4`. The CLI does not execute the workflow.
