// Builds a deterministic labeling sample: up to N findings per rule, with redacted context.
// Usage: node benchmarks/sample.mjs <resultsDir> <workDir> <N> <outFile>
import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
const [resDir, workDir, nArg, outFile] = process.argv.slice(2);
const N = Number(nArg ?? 8);
const { scrubTokens } = await import(pathToFileURL(resolve("dist/redact.js")).href);
const all = [];
for (const f of readdirSync(resDir).filter((x) => x.endsWith(".json") && x !== "summary.json")) {
  const r = JSON.parse(readFileSync(join(resDir, f), "utf8"));
  const repo = f.replace(".json", "");
  for (const x of r.findings) all.push({ repo, ...x });
}
const byRule = {};
for (const f of all) (byRule[f.ruleId] ??= []).push(f);
const counts = Object.fromEntries(Object.entries(byRule).map(([k, v]) => [k, v.length]));
const sample = [];
for (const [rule, list] of Object.entries(byRule).sort()) {
  // spread across repos: round-robin over repos, ordered by fingerprint for determinism
  const groups = {};
  for (const f of list.sort((a, b) => (a.fingerprint < b.fingerprint ? -1 : 1))) (groups[f.repo] ??= []).push(f);
  const picked = [];
  const repos = Object.keys(groups).sort();
  while (picked.length < Math.min(N, list.length)) {
    let progressed = false;
    for (const r of repos) {
      const g = groups[r];
      if (g.length && picked.length < N) { picked.push(g.shift()); progressed = true; }
    }
    if (!progressed) break;
  }
  for (const f of picked) {
    let ctx = "";
    try {
      const lines = readFileSync(join(workDir, f.repo, f.path), "utf8").split(/\r?\n/);
      const lo = Math.max(0, f.startLine - 2), hi = Math.min(lines.length, f.startLine + 1);
      ctx = lines.slice(lo, hi).map((l, i) => `${lo + i + 1}: ${scrubTokens(l).slice(0, 160)}`).join(" | ");
    } catch { ctx = "(file not readable)"; }
    sample.push({ key: `${f.repo}|${f.path}|${f.startLine}|${f.ruleId}`, repo: f.repo, rule: f.ruleId, status: f.status, path: f.path, line: f.startLine, evidence: f.excerpt, ctx });
  }
}
writeFileSync(outFile, JSON.stringify({ counts, total: all.length, sample }, null, 2));
console.log("total findings", all.length, "sample", sample.length);
console.log(Object.entries(counts).sort().map(([k, v]) => `${k}:${v}`).join(" "));
