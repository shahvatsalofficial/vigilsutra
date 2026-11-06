# Security model

Guarantees by design (tested unless noted):

| Guarantee | Mechanism |
|---|---|
| Read-only | Scan path only reads. A test checks the tree is unchanged after a scan. |
| No network | `src/` imports no network modules and calls no `fetch`; enforced by a static test. Not verified at firewall level. |
| No code execution | Scanned files are read as text. `src/` uses no `child_process`. |
| Scope confinement | Root is resolved with `realpath`; symlinks and junctions are never followed. |
| Resource limits | Per-file size, file count and wall-clock limits; binaries skipped; truncation is reported. |
| Secret redaction | Spans removed before excerpts and fingerprints are built; known token shapes scrubbed again. Tested in all five formats. |
| Report safety | HTML escapes untrusted text and ships a restrictive CSP; Markdown escapes titles. |
| Untrusted repo content | Instruction-like text in scanned files is a finding, never a command. |
| Non-destructive installs | Adapters preview, never overwrite without `--force`, uninstall only manifest-listed files. |

Known gaps: obfuscation can evade patterns; long lines are scanned in 2,000-character windows, so a match split across a window boundary can be missed; ReDoS resistance of every regex is not formally proven; the tool does not sandbox itself at OS level. When inode is 0, a swap that keeps the same size and mtime is not detected. Git history stops at the time limit, and a blob over 1 MiB is skipped. SHA-1 and SHA-256 object ids are both read. The advisory file is a snapshot from 2026-11-07, not a live feed, and a match does not prove the vulnerable function runs. Name tracking does not follow object fields, dynamic imports, or function returns. `vigilsutra fix --apply` writes only the deterministic edits it printed; it does not delete a secret.
