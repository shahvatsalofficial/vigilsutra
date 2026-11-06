# Compatibility matrix

Last verified: 2026-11-06 on the build in this repository.

| Environment | Status | Evidence |
|---|---|---|
| Windows 11, Node 24.15, PowerShell and Git Bash | Tested | `npm test` on 2026-11-07: 119 passed, 1 skipped (symlink creation not permitted; the directory-junction case does run) |
| Ubuntu and Windows on Node 20, 22, 24 and 26 (GitHub Actions) | Required CI. Node 27 is only an alpha and is not tested | `.github/workflows/test.yml` |
| macOS | Not in required CI. On 2026-11-04, `macos-latest` jobs for Node 22 and 26 stayed queued and were cancelled with zero steps (runs 41882166871, 41885847962, 41886196642), which failed the workflow before any test ran. No Mac was available to re-run the suite locally. The program is plain Node with no native addon; path matching follows `core.ignorecase` | `.github/workflows/test.yml` |
| Paths with spaces and non-ASCII characters | Tested on Windows | unit test |
| Claude Code, Cursor, Codex, Gemini CLI, Copilot | File copy tested (`adapters install <name>`). Invocation inside each IDE is not automated-tested | `src/adapters.ts` |
| Windsurf, Kiro, Cline | Not implemented. Run the CLI and share its JSON or Markdown report | No adapter |
| Docker image | `Dockerfile` is in the repo and copies the advisory snapshot. It was not built on the 2026-11-07 Windows machine because `docker` was not installed. Nothing is pushed to a registry | `docker build -t vigilsutra .` |

The CLI works in any editor or CI that can launch a process. Native skill use requires an IDE that supports the Agent Skills format.
