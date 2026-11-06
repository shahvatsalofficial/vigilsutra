import { constants, existsSync, mkdirSync, readFileSync, rmSync, readdirSync, writeFileSync, copyFileSync, rmdirSync } from "node:fs";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { VERSION } from "./engine.js";

export const PACKAGE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

export interface AdapterInfo {
  name: string;
  status: "supported" | "unverified" | "planned";
  detail: string;
}

export const ADAPTERS: AdapterInfo[] = [
  { name: "claude", status: "supported", detail: "Copies skills to <project>/.claude/skills/<name>/SKILL.md. File copy is tested. Invocation inside Claude Code is not automated-tested." },
  { name: "cursor", status: "supported", detail: "Copies skills to <project>/.cursor/skills/<name>/SKILL.md. File copy is tested. Invocation inside Cursor is not automated-tested." },
  { name: "codex", status: "supported", detail: "Copies skills to <project>/.codex/skills/<name>/SKILL.md and does not edit AGENTS.md. File copy is tested. Invocation inside Codex is not automated-tested." },
  { name: "gemini", status: "supported", detail: "Copies skills to <project>/.gemini/skills/<name>/SKILL.md. File copy is tested. Invocation inside Gemini CLI is not automated-tested." },
  { name: "copilot", status: "supported", detail: "Copies skills to <project>/.github/agents/<name>.agent.md. File copy is tested. Invocation inside Copilot is not automated-tested." },
  { name: "generic-cli", status: "supported", detail: "Any editor or CI: run `vigilsutra audit .` and feed the JSON or Markdown report to your assistant." }
];

export type AdapterName = "claude" | "cursor" | "codex" | "gemini" | "copilot";

const LAYOUT: Record<AdapterName, { root: string[]; file: (name: string) => string; allowed: RegExp }> = {
  claude: { root: [".claude", "skills"], file: (n) => `${n}/SKILL.md`, allowed: /^[^/\\]+[/\\]SKILL\.md$/ },
  cursor: { root: [".cursor", "skills"], file: (n) => `${n}/SKILL.md`, allowed: /^[^/\\]+[/\\]SKILL\.md$/ },
  codex: { root: [".codex", "skills"], file: (n) => `${n}/SKILL.md`, allowed: /^[^/\\]+[/\\]SKILL\.md$/ },
  gemini: { root: [".gemini", "skills"], file: (n) => `${n}/SKILL.md`, allowed: /^[^/\\]+[/\\]SKILL\.md$/ },
  copilot: { root: [".github", "agents"], file: (n) => `${n}.agent.md`, allowed: /^[^/\\]+\.agent\.md$/ }
};

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

export function planAdapter(projectRoot: string, adapter: AdapterName, force: boolean): Plan[] {
  const layout = LAYOUT[adapter];
  return skillNames().map((n) => {
    const to = join(projectRoot, ...layout.root, ...layout.file(n).split("/"));
    const from = join(PACKAGE_ROOT, "agents", n, "SKILL.md");
    const exists = existsSync(to);
    return { action: !exists ? "create" : force ? "overwrite" : "skip-exists", from, to };
  });
}

export function planClaudeInstall(projectRoot: string, force: boolean): Plan[] {
  return planAdapter(projectRoot, "claude", force);
}

export function installAdapter(projectRoot: string, adapter: AdapterName, force: boolean): Plan[] {
  const plan = planAdapter(projectRoot, adapter, force);
  const written: string[] = [];
  for (const p of plan) {
    if (p.action === "skip-exists") continue;
    mkdirSync(dirname(p.to), { recursive: true });
    try {
      // A new file is created exclusively, so a file that appears after the plan was made is never overwritten.
      copyFileSync(p.from, p.to, p.action === "create" ? constants.COPYFILE_EXCL : 0);
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === "EEXIST") {
        p.action = "skip-exists";
        continue;
      }
      throw e;
    }
    written.push(relative(projectRoot, p.to).split("\\").join("/"));
  }
  if (written.length) {
    const manifestPath = join(projectRoot, ...LAYOUT[adapter].root, MANIFEST);
    let prev: string[] = [];
    try {
      prev = JSON.parse(readFileSync(manifestPath, "utf8")).files ?? [];
    } catch {
      /* no manifest yet */
    }
    writeFileSync(manifestPath, JSON.stringify({ tool: "vigilsutra", version: VERSION, files: [...new Set([...prev, ...written])] }, null, 2) + "\n");
  }
  return plan;
}

export function installClaude(projectRoot: string, force: boolean): Plan[] {
  return installAdapter(projectRoot, "claude", force);
}

/** Removes only files this tool installed (listed in the manifest). */
export function uninstallAdapter(projectRoot: string, adapter: AdapterName): string[] {
  const layout = LAYOUT[adapter];
  const manifestPath = join(projectRoot, ...layout.root, MANIFEST);
  if (!existsSync(manifestPath)) return [];
  const files: string[] = JSON.parse(readFileSync(manifestPath, "utf8")).files ?? [];
  const removed: string[] = [];
  for (const rel of files) {
    const abs = resolve(projectRoot, rel);
    // The manifest lives in the project and can be edited, so each path is checked against the adapter root.
    const inside = relative(resolve(projectRoot, ...layout.root), abs);
    if (inside.startsWith("..") || isAbsolute(inside) || !layout.allowed.test(inside)) continue;
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

export function uninstallClaude(projectRoot: string): string[] {
  return uninstallAdapter(projectRoot, "claude");
}
