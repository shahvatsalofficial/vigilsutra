import test from "node:test";
import assert from "node:assert/strict";
import { writeFileSync } from "node:fs";
import { ALL_RULES } from "../dist/rules/index.js";
import { audit } from "../dist/engine.js";
import { parsePolicy } from "../dist/policy.js";
import { mkdtempSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// Deterministic PRNG so failures reproduce.
let seed = 0x5eed1234;
const rnd = () => ((seed = (seed * 1664525 + 1013904223) >>> 0) / 2 ** 32);
const pick = (a) => a[Math.floor(rnd() * a.length)];

const FILES = [
  "Dockerfile",
  "a.js",
  "a.py",
  ".github/workflows/x.yml",
  "d.yaml",
  "m.tf",
  "AGENTS.md",
  "mcp.json",
  ".env",
  "k.pem",
  "run.sh",
  "p.json"
];
const K8S_HEAD = "apiVersion: v1\nkind: Pod\n";
const TOKENS = ["password", "secret", "token", "api_key", "= ", ": ", "\"", "'", "`", "${", "${{ ", "}}", "exec(", "eval(", "FROM ", "RUN ", "curl ", "| ", "sh", "-----BEGIN ", "PRIVATE KEY", "AKIA", "ghp_", "xox", "uses: ", "@", "run: ", "github.event.", "pull_request_target", "privileged: ", "cidr_blocks", "0.0.0.0/0", "Action", "*", "[", "]", "npx", "command", "-y", "console.log(", "logger.", "pickle.", "yaml.load(", "subprocess.", "shell=True", ".query(", "SELECT ", "innerHTML", "createHash(", "md5", "ignore previous instructions", "\\", "\t", "\u0000", "\uD800", "é", "日本語", "\u202e"];

const lineOf = (kind, len) => {
  switch (kind) {
    case 0: return "a".repeat(len);
    case 1: return " ".repeat(len);
    case 2: return '"'.repeat(len);
    case 3: return 'password = "' + "a".repeat(Math.max(0, len - 14)) + "";
    case 4: return "exec(" + "a".repeat(Math.max(0, len - 5));
    case 5: return "${{ " + "x ".repeat(Math.max(0, Math.floor((len - 4) / 2)));
    case 6: return "FROM " + "a:".repeat(Math.max(0, Math.floor((len - 5) / 2)));
    case 7: return "-----BEGIN " + "RSA ".repeat(Math.max(0, Math.floor((len - 11) / 4)));
    case 8: return "AKIA" + "A".repeat(Math.max(0, len - 4));
    case 9: return "uses: " + "a/".repeat(Math.max(0, Math.floor((len - 6) / 2)));
    case 10: return "curl " + "-s ".repeat(Math.max(0, Math.floor((len - 5) / 3)));
    case 11: return "console.log(" + "password,".repeat(Math.max(0, Math.floor((len - 12) / 9)));
    case 12: return '"command": "npx", ' + "x".repeat(Math.max(0, len - 18));
    case 13: return "db.query(" + '"SELECT " + '.repeat(Math.max(0, Math.floor((len - 9) / 13)));
    case 14: return "ignore " + "all ".repeat(Math.max(0, Math.floor((len - 7) / 4)));
    default: {
      let s = "";
      while (s.length < len) s += pick(TOKENS);
      return s.slice(0, len);
    }
  }
};

function mkFile(name, lines) {
  const text = (/\.ya?ml$/.test(name) && !name.includes("workflows") ? K8S_HEAD : "") + lines.join("\n");
  const base = name.split("/").pop().toLowerCase();
  return { path: name, name: base, ext: base.includes(".") ? "." + base.split(".").pop() : "", text, lines: text.split(/\r\n|\n|\r/) };
}

test("no rule throws on adversarial, malformed or random input", () => {
  for (let round = 0; round < 40; round++) {
    const lines = Array.from({ length: 60 }, () => lineOf(Math.floor(rnd() * 22), 1 + Math.floor(rnd() * 2400)));
    for (const name of FILES) {
      const f = mkFile(name, lines);
      for (const rule of ALL_RULES) {
        if (!rule.applies(f)) continue;
        assert.doesNotThrow(() => rule.check(f), `${rule.id} threw on fuzz round ${round} (${name})`);
      }
    }
  }
});

test("ReDoS guard: each rule handles 1,000 adversarial 1,990-character lines quickly", () => {
  const results = [];
  for (const rule of ALL_RULES) {
    let worst = 0;
    for (let kind = 0; kind < 16; kind++) {
      const lines = Array.from({ length: 1000 }, () => lineOf(kind, 1990));
      for (const name of FILES) {
        const f = mkFile(name, lines);
        if (!rule.applies(f)) continue;
        const t = performance.now();
        rule.check(f);
        worst = Math.max(worst, performance.now() - t);
      }
    }
    results.push({ rule: rule.id, worstMs: Math.round(worst) });
    assert.ok(worst < 1500, `${rule.id} took ${Math.round(worst)} ms on a 1,000-line adversarial file`);
  }
  if (process.env.VS_FUZZ_OUT) writeFileSync(process.env.VS_FUZZ_OUT, JSON.stringify(results, null, 2));
});

test("lines above 2,000 characters are skipped by line rules rather than scanned", () => {
  const f = mkFile("a.js", ["eval(x)" + " ".repeat(2500)]);
  const rule = ALL_RULES.find((r) => r.id === "VS-CODE-001");
  assert.equal(rule.check(f).length, 0);
});

test("malformed Unicode, NUL bytes and huge single lines do not crash a full audit", () => {
  const root = join(mkdtempSync(join(tmpdir(), "vs-fz-")), "p");
  mkdirSync(root);
  writeFileSync(join(root, "a.js"), "eval(x)\n\uD800\uDC00 \uD800 broken\u0000\n" + "x".repeat(5_000_000).slice(0, 900_000));
  writeFileSync(join(root, "b.py"), Buffer.from([0xff, 0xfe, 0x00, 0x41, 0xc3, 0x28]));
  const r = audit({ root });
  assert.ok(r.scope.filesScanned + r.scope.skippedBinary >= 2);
});

test("policy parser survives deep, huge and hostile input without hanging", () => {
  const t = performance.now();
  for (const bad of ["a: " + "x".repeat(1_000_000), "ignore:\n" + "  - a\n".repeat(50_000), ":".repeat(100_000), "\u0000\uD800".repeat(10_000), "a:\n  - " + "[".repeat(100_000)]) {
    try {
      parsePolicy(bad);
    } catch (e) {
      assert.ok(e instanceof Error);
    }
  }
  assert.ok(performance.now() - t < 5000, "policy parsing too slow");
});

test("JSON baseline and previous-result inputs that are hostile are rejected, not trusted", async () => {
  const { spawnSync } = await import("node:child_process");
  const { resolve } = await import("node:path");
  const dir = mkdtempSync(join(tmpdir(), "vs-bl-"));
  const bad = join(dir, "b.json");
  for (const body of ["{", "[]", '{"fingerprints":"x"}', "null", "9".repeat(100000)]) {
    writeFileSync(bad, body);
    const r = spawnSync(process.execPath, [resolve("dist/cli.js"), "audit", "examples/secure-config", "--no-report", "--baseline", bad], { encoding: "utf8" });
    assert.equal(r.status, 2, `baseline ${body.slice(0, 20)} should be rejected`);
    const v = spawnSync(process.execPath, [resolve("dist/cli.js"), "verify", "examples/secure-config", "--previous", bad], { encoding: "utf8" });
    assert.equal(v.status, 2, `verify ${body.slice(0, 20)} should be rejected`);
  }
});
