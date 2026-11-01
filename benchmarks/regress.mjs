// Compares labeled findings from an earlier run with a new run of the same repository commits.
// Usage: node benchmarks/regress.mjs <labels.json> <newResultsDir>
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
const [labelsFile, dir] = process.argv.slice(2);
const { labels } = JSON.parse(readFileSync(labelsFile, "utf8"));
const now = new Map();
let total = 0;
for (const f of readdirSync(dir).filter((x) => x.endsWith(".json") && x !== "summary.json")) {
  const r = JSON.parse(readFileSync(join(dir, f), "utf8"));
  const repo = f.replace(".json", "");
  for (const x of r.findings) { now.set(`${repo}|${x.path}|${x.startLine}|${x.ruleId}`, x); total++; }
}
const t = { TP: { n: 0, kept: 0, lowConf: 0 }, TT: { n: 0, kept: 0, lowConf: 0 }, FP: { n: 0, kept: 0, lowConf: 0 } };
const lost = [];
for (const [k, v] of Object.entries(labels)) {
  const c = t[v.label]; c.n++;
  const f = now.get(k);
  if (f) { c.kept++; if (f.confidence === "low") c.lowConf++; } else if (v.label === "TP") lost.push(k + " " + v.note);
}
console.log(JSON.stringify({ totalFindingsNow: total, byLabel: t, truePositivesLost: lost }, null, 1));
