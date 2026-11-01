# Offline and no-execution verification

The README claims VigilSutra makes no network requests, runs no subprocesses and executes no scanned code. Three independent checks back that up.

## 1. Static check (every `npm test`)

`src/` may not import `node:http`, `https`, `http2`, `net`, `tls`, `dgram` or `dns`, and may not call `fetch`, `XMLHttpRequest` or use `child_process` (rule files are excluded from the last check because they contain pattern text).

## 2. Runtime check with blocked network and subprocess APIs (every `npm test`)

`test/offline-runtime.test.mjs` starts the real CLI with a preload (`test/block-network.mjs`) that replaces `net.Socket.connect`, `net.connect`, `net.createConnection`, `dns.lookup`, `dns.resolve`, `fetch` and every `child_process` entry point with functions that **record the attempt to a log file and throw**. Proxy variables point to a closed port.

- A self-check proves the preload really catches `fetch`, a socket connect and a subprocess call.
- Twelve commands then run (audit in text, JSON, SARIF, HTML and Markdown formats on the demo project and on the repository itself, `rules list`, `explain`, `doctor`, `adapters list`, `adapters install --dry-run`, `init`). Each must finish normally and the attempt log must be **empty**.

This catches dynamic imports and indirect calls that a text search would miss.

## 3. Operating-system level check on Linux CI

The `test` workflow runs the audit in a network namespace that has no network interfaces (`unshare --net`), so an outbound connection cannot succeed at the kernel level. See `.github/workflows/test.yml`.

## What this does not prove

- It does not cover Node.js itself or any code outside `dist/`. `npx` downloads the package from npm before running it; the scan after that is offline.
- The AI-IDE skills run inside your IDE and are governed by its policies; they are outside the CLI's guarantees.
- Anything added later must keep these tests passing, but the tests are only as complete as the checks above.
