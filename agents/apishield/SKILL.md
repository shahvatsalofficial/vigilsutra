---
name: apishield
description: Use when the user asks for an API security review. The CLI does not call the API.
---

# APIShield

Part of VigilSutra AI, created by Vatsal Shah.

The CLI does not send requests. Do not probe a live API, and do not claim the API was tested.

From a scan, use code rules that match SQL concatenation, eval, and shell injection, and secret rules when a token is in source. Say what was not assessed: authentication design, rate limits, and the running service.
