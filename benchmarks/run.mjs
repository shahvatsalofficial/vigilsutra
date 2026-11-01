// Real-world benchmark runner. Shallow-clones public repos into a temp folder OUTSIDE this
// project and scans them read-only with VigilSutra. Scanned code is never executed.
// Usage: node benchmarks/run.mjs <outDir>
import { spawnSync } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync, existsSync, rmSync } from "node:fs";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { pathToFileURL } from "node:url";

const out = resolve(process.argv[2] ?? "benchmarks/results");
const work = join(tmpdir(), "vigilsutra-bench");
mkdirSync(out, { recursive: true });
mkdirSync(work, { recursive: true });
const { audit } = await import(pathToFileURL(resolve("dist/engine.js")).href);
const { repos } = JSON.parse(readFileSync("benchmarks/repos.json", "utf8"));
const summary = [];
for (const r of repos) {
  const dir = join(work, r.name.replace("/", "__"));
  if (!existsSync(dir)) {
    const c = spawnSync("git", ["-c", "core.symlinks=false", "-c", "core.longpaths=true", "-c", "core.hooksPath=NUL", "clone", "--depth", "1", "--quiet", `https://github.com/${r.name}.git`, dir], { encoding: "utf8" });
    if (c.status !== 0) { summary.push({ ...r, error: (c.stderr || "").slice(0, 200) }); console.log("clone failed", r.name); continue; }
  }
  const sha = spawnSync("git", ["-C", dir, "rev-parse", "HEAD"], { encoding: "utf8" }).stdout.trim();
  const t = performance.now();
  const res = audit({ root: dir });
  const ms = Math.round(performance.now() - t);
  writeFileSync(join(out, r.name.replace("/", "__") + ".json"), JSON.stringify(res, null, 2));
  summary.push({ ...r, commit: sha, files: res.scope.filesScanned, mib: +(res.scope.bytesScanned / 1048576).toFixed(1), ms, truncated: res.scope.truncated, skippedTooLarge: res.scope.skippedTooLarge, total: res.summary.total, bySeverity: res.summary.bySeverity, detected: res.project.detected });
  console.log(r.name, res.scope.filesScanned, "files", ms, "ms", res.summary.total, "findings");
}
writeFileSync(join(out, "summary.json"), JSON.stringify({ generatedAt: new Date().toISOString(), tool: "vigilsutra", repos: summary }, null, 2));
console.log("workdir:", work);
