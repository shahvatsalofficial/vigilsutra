// Compares VigilSutra secret findings with Gitleaks findings at file level, per repo.
// Usage: node benchmarks/compare-secrets.mjs <vigilsutraResultsDir> <gitleaksDir> <workDir>
import { readdirSync, readFileSync, realpathSync } from "node:fs";
import { join, relative, resolve } from "node:path";
const [vsDir, glDir, work] = process.argv.slice(2);
const rows = [];
const onlyGl = {};
for (const f of readdirSync(vsDir).filter((x) => x.endsWith(".json") && x !== "summary.json")) {
  const repo = f.replace(".json", "");
  const vs = JSON.parse(readFileSync(join(vsDir, f), "utf8")).findings.filter((x) => x.category === "secrets");
  let gl = [];
  try { gl = JSON.parse(readFileSync(join(glDir, f), "utf8") || "[]"); } catch {}
  const vsFiles = new Set(vs.map((x) => x.path));
  const glFiles = new Map();
  for (const g of gl) {
    const rel = relative(realpathSync(resolve(work, repo)), realpathSync(resolve(work, "..", g.File))).split(String.fromCharCode(92)).join("/");
    if (!glFiles.has(rel)) glFiles.set(rel, g.RuleID);
  }
  const both = [...vsFiles].filter((p) => glFiles.has(p)).length;
  const onlyVs = [...vsFiles].filter((p) => !glFiles.has(p)).length;
  const onlyG = [...glFiles.keys()].filter((p) => !vsFiles.has(p));
  for (const p of onlyG) onlyGl[glFiles.get(p)] = (onlyGl[glFiles.get(p)] ?? 0) + 1;
  rows.push({ repo, vsFiles: vsFiles.size, glFiles: glFiles.size, both, onlyVigilSutra: onlyVs, onlyGitleaks: onlyG.length });
}
const sum = (k) => rows.reduce((a, r) => a + r[k], 0);
console.log(JSON.stringify({ rows, totals: { vsFiles: sum("vsFiles"), glFiles: sum("glFiles"), both: sum("both"), onlyVigilSutra: sum("onlyVigilSutra"), onlyGitleaks: sum("onlyGitleaks") }, gitleaksRulesVigilSutraMissed: onlyGl }, null, 1));
