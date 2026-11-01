// File-level comparison of VigilSutra with Gitleaks (secrets) and Semgrep (code/config) on the same repos.
// Usage: node benchmarks/compare-tools.mjs <ciOutDir>   (a directory with vigilsutra/, gitleaks/, semgrep/)
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
const dir = process.argv[2];
const norm = (p) => p.split(String.fromCharCode(92)).join("/");
const rd = (f) => { try { return JSON.parse(readFileSync(f, "utf8") || "null"); } catch { return null; } };
const secretsCats = new Set(["secrets"]);
const rows = [];
const glOnlyRules = {};
const sgRules = {};
for (const f of readdirSync(join(dir, "vigilsutra")).filter((x) => x.endsWith(".json") && x !== "summary.json")) {
  const repo = f.replace(".json", "");
  const vs = rd(join(dir, "vigilsutra", f)).findings;
  const vsSecretFiles = new Set(vs.filter((x) => secretsCats.has(x.category)).map((x) => x.path));
  const vsCodeFiles = new Set(vs.filter((x) => !secretsCats.has(x.category) && x.category !== "process" && x.category !== "privacy").map((x) => x.path));
  const gl = rd(join(dir, "gitleaks", f)) ?? [];
  const glFiles = new Map();
  for (const g of gl) {
    const p = norm(g.File);
    const i = p.indexOf(`vigilsutra-bench/${repo}/`);
    const rel = i >= 0 ? p.slice(i + `vigilsutra-bench/${repo}/`.length) : p;
    if (!glFiles.has(rel)) glFiles.set(rel, g.RuleID);
  }
  const sg = rd(join(dir, "semgrep", f))?.results ?? [];
  const sgFiles = new Map();
  for (const s of sg) { const rel = norm(s.path).replace(/^\.\//, ""); if (!sgFiles.has(rel)) sgFiles.set(rel, s.check_id); sgRules[s.check_id.split(".").slice(-1)[0]] = (sgRules[s.check_id.split(".").slice(-1)[0]] ?? 0) + 1; }
  const inter = (a, b) => [...a].filter((x) => b.has(x)).length;
  const onlyGl = [...glFiles.keys()].filter((p) => !vsSecretFiles.has(p));
  for (const p of onlyGl) glOnlyRules[glFiles.get(p)] = (glOnlyRules[glFiles.get(p)] ?? 0) + 1;
  rows.push({
    repo,
    secrets: { vigilsutra: vsSecretFiles.size, gitleaks: glFiles.size, both: inter(vsSecretFiles, glFiles), onlyVigilSutra: vsSecretFiles.size - inter(vsSecretFiles, glFiles), onlyGitleaks: onlyGl.length },
    code: { vigilsutraFiles: vsCodeFiles.size, semgrepFiles: sgFiles.size, both: inter(vsCodeFiles, sgFiles), onlyVigilSutra: vsCodeFiles.size - inter(vsCodeFiles, sgFiles), onlySemgrep: sgFiles.size - inter(vsCodeFiles, sgFiles), semgrepFindings: sg.length }
  });
}
const sum = (sel) => rows.reduce((a, r) => a + sel(r), 0);
const totals = {
  secrets: { vigilsutra: sum((r) => r.secrets.vigilsutra), gitleaks: sum((r) => r.secrets.gitleaks), both: sum((r) => r.secrets.both), onlyVigilSutra: sum((r) => r.secrets.onlyVigilSutra), onlyGitleaks: sum((r) => r.secrets.onlyGitleaks) },
  code: { vigilsutraFiles: sum((r) => r.code.vigilsutraFiles), semgrepFiles: sum((r) => r.code.semgrepFiles), both: sum((r) => r.code.both), onlyVigilSutra: sum((r) => r.code.onlyVigilSutra), onlySemgrep: sum((r) => r.code.onlySemgrep), semgrepFindings: sum((r) => r.code.semgrepFindings) }
};
const top = (o, n) => Object.fromEntries(Object.entries(o).sort((a, b) => b[1] - a[1]).slice(0, n));
console.log(JSON.stringify({ unit: "files with at least one finding, per repo", rows, totals, gitleaksRulesVigilSutraMissed: glOnlyRules, topSemgrepRules: top(sgRules, 12) }, null, 1));
