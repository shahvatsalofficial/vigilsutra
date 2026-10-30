# Compatibility matrix

Last verified: 2026-10-31 on the build in this repository.

| Environment | Status | Evidence |
|---|---|---|
| Windows 11, Node 24.15, PowerShell and Git Bash | Tested | `npm test` run locally; the symlink test is skipped when symlink creation is not permitted |
| Linux / macOS, Node 20 and 22 | CI configured; results not yet recorded | `.github/workflows/test.yml` |
| Paths with spaces and non-ASCII characters | Tested on Windows | unit test |
| Claude Code skills adapter | File install and uninstall tested; invocation inside Claude Code not automated-tested | `adapters install claude` |
| Cursor, Codex, Gemini CLI, Copilot, Windsurf, Kiro, Cline | Not implemented. Generic mode: run the CLI and share its JSON or Markdown report | Planned, unverified |
| Docker image | Not published | Planned |

The CLI works in any editor or CI that can launch a process. Native skill use requires an IDE that supports the Agent Skills format.
