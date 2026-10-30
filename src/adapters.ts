import { existsSync, mkdirSync, readFileSync, rmSync, readdirSync, writeFileSync, copyFileSync, rmdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { VERSION } from "./engine.js";

export const PACKAGE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

export interface AdapterInfo {
  name: string;
  status: "supported" | "unverified" | "planned";
  detail: string;
}

export const ADAPTERS: AdapterInfo[] = [
  { name: "claude", status: "supported", detail: "Copies Agent Skills to <project>/.claude/skills/<name>/SKILL.md. File format follows Claude Code's skill layout; install/uninstall is tested, in-IDE invocation is not automated-tested." },
  { name: "generic-cli", status: "supported", detail: "Any editor or CI: run `vigilsutra audit .` and feed the JSON/Markdown report to your assistant." },
  { name: "codex", status: "unverified", detail: "Reads AGENTS.md; no VigilSutra-specific adapter shipped. Planned." },
  { name: "cursor", status: "planned", detail: "Planned. Not verified against current Cursor docs." },
  { name: "gemini", status: "planned", detail: "Planned. Not verified against current Gemini CLI docs." },
  { name: "copilot", status: "planned", detail: "Planned. Not verified against current Copilot agent docs." }
];

const MANIFEST = ".vigilsutra-managed.json";

export function skillNames(): string[] {
  const dir = join(PACKAGE_ROOT, "agents");
  return readdirSync(dir, { withFileTypes: true })
    .filter((d) => d.isDirectory() && existsSync(join(dir, d.name, "SKILL.md")))
    .map((d) => d.name)
    .sort();
}

export interface Plan {
  action: "create" | "skip-exists" | "overwrite";
  from: string;
  to: string;
}

export function planClaudeInstall(projectRoot: string, force: boolean): Plan[] {
  return skillNames().map((n) => {
    const to = join(projectRoot, ".claude", "skills", n, "SKILL.md");
    const from = join(PACKAGE_ROOT, "agents", n, "SKILL.md");
    const exists = existsSync(to);
    return { action: !exists ? "create" : force ? "overwrite" : "skip-exists", from, to };
  });
}

export function installClaude(projectRoot: string, force: boolean): Plan[] {
  const plan = planClaudeInstall(projectRoot, force);
  const written: string[] = [];
  for (const p of plan) {
    if (p.action === "skip-exists") continue;
    mkdirSync(dirname(p.to), { recursive: true });
    copyFileSync(p.from, p.to);
    written.push(p.to.slice(projectRoot.length + 1).replace(/\\/g, "/"));
  }
  if (written.length) {
    const manifestPath = join(projectRoot, ".claude", "skills", MANIFEST);
    const prev: string[] = existsSync(manifestPath) ? (JSON.parse(readFileSync(manifestPath, "utf8")).files ?? []) : [];
    writeFileSync(manifestPath, JSON.stringify({ tool: "vigilsutra", version: VERSION, files: [...new Set([...prev, ...written])] }, null, 2) + "\n");
  }
  return plan;
}

/** Removes only files this tool installed (listed in the manifest). */
export function uninstallClaude(projectRoot: string): string[] {
  const manifestPath = join(projectRoot, ".claude", "skills", MANIFEST);
  if (!existsSync(manifestPath)) return [];
  const files: string[] = JSON.parse(readFileSync(manifestPath, "utf8")).files ?? [];
  const removed: string[] = [];
  for (const rel of files) {
    const abs = resolve(projectRoot, rel);
    // Never delete outside the project's .claude/skills directory.
    if (!abs.startsWith(resolve(projectRoot, ".claude", "skills"))) continue;
    if (existsSync(abs)) {
      rmSync(abs);
      removed.push(rel);
      try {
        rmdirSync(dirname(abs));
      } catch {
        /* directory not empty: leave user files alone */
      }
    }
  }
  rmSync(manifestPath);
  return removed;
}
