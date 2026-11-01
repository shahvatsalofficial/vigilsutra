import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, existsSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { spawnSync } from "node:child_process";

const CLI = resolve("dist/cli.js");
const PRELOAD = pathToFileURL(resolve("test/block-network.mjs")).href;

function run(args, log, extra = {}) {
  return spawnSync(process.execPath, ["--import", PRELOAD, ...args], {
    encoding: "utf8",
    env: { ...process.env, VS_NET_LOG: log, HTTP_PROXY: "http://127.0.0.1:9", HTTPS_PROXY: "http://127.0.0.1:9", ...extra }
  });
}

test("preload really blocks and records network, DNS and subprocess attempts (self-check)", () => {
  const log = join(mkdtempSync(join(tmpdir(), "vs-net-")), "log.txt");
  const probe = "try{await fetch('http://example.invalid')}catch{};import('node:net').then(n=>{try{n.default.connect(80,'127.0.0.1')}catch{}});import('node:child_process').then(c=>{try{c.default.execSync('echo hi')}catch{}})";
  const r = spawnSync(process.execPath, ["--import", PRELOAD, "--input-type=module", "-e", probe], { encoding: "utf8", env: { ...process.env, VS_NET_LOG: log } });
  const seen = readFileSync(log, "utf8");
  assert.match(seen, /fetch/);
  assert.match(seen, /net\.(Socket\.)?connect/);
  assert.match(seen, /child_process\.execSync/);
  assert.equal(r.signal, null);
});

test("every offline command runs to completion with the network and subprocesses blocked", () => {
  const log = join(mkdtempSync(join(tmpdir(), "vs-net-")), "log.txt");
  writeFileSync(log, "");
  const work = mkdtempSync(join(tmpdir(), "vs-proj-"));
  const cmds = [
    [CLI, "audit", "examples/intentionally-insecure"],
    [CLI, "audit", "examples/intentionally-insecure", "--format", "json"],
    [CLI, "audit", "examples/intentionally-insecure", "--format", "sarif"],
    [CLI, "audit", "examples/intentionally-insecure", "--format", "html"],
    [CLI, "audit", "examples/intentionally-insecure", "--format", "markdown"],
    [CLI, "audit", "."],
    [CLI, "rules", "list"],
    [CLI, "explain", "VS-SECRET-001"],
    [CLI, "doctor"],
    [CLI, "adapters", "list"],
    [CLI, "adapters", "install", "claude", "--project", work, "--dry-run"],
    [CLI, "init", work]
  ];
  for (const c of cmds) {
    const r = run(c, log);
    assert.ok(r.status === 0 || r.status === 1, `${c.slice(1).join(" ")} exited ${r.status}: ${r.stderr}`);
    assert.doesNotMatch(r.stderr, /blocked:/, c.slice(1).join(" "));
  }
  const attempts = readFileSync(log, "utf8").trim();
  assert.equal(attempts, "", `network or subprocess attempts detected:\n${attempts}`);
  assert.ok(existsSync(join(work, ".vigilsutra.yml")));
});
