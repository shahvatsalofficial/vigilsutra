import { randomUUID } from "node:crypto";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

export interface Component {
  ecosystem: "npm" | "pypi" | "golang";
  name: string;
  version: string;
  path: string;
}

const MAX = 20 * 1024 * 1024;

function readText(root: string, rel: string): string | null {
  const abs = join(root, rel);
  try {
    if (!existsSync(abs)) return null;
    const buf = readFileSync(abs);
    if (buf.length > MAX || buf.subarray(0, 8192).includes(0)) return null;
    return buf.toString("utf8");
  } catch {
    return null;
  }
}

const MANIFESTS = new Set(["package-lock.json", "npm-shrinkwrap.json", "requirements.txt", "yarn.lock", "pnpm-lock.yaml", "go.mod"]);
const SKIP_DIRS = new Set([".git", "node_modules", "dist", "build", "out", "vendor", ".venv", "venv", "__pycache__", "coverage", ".next", "target", "vigilsutra-report"]);

/** Relative paths of manifests at any depth. Symlinks are not followed. */
function findManifests(root: string, skip: (rel: string) => boolean, dir = "", depth = 0): string[] {
  let entries;
  try {
    entries = readdirSync(join(root, dir), { withFileTypes: true });
  } catch {
    return [];
  }
  entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  const out: string[] = [];
  for (const e of entries) {
    const rel = dir ? `${dir}/${e.name}` : e.name;
    if (e.isFile() && MANIFESTS.has(e.name) && !skip(rel)) out.push(rel);
    if (e.isDirectory() && depth < 8 && !SKIP_DIRS.has(e.name) && !skip(rel + "/placeholder")) out.push(...findManifests(root, skip, rel, depth + 1));
  }
  return out;
}

interface V1Dependency {
  version?: string;
  dependencies?: Record<string, V1Dependency>;
}

/** Resolved components from lockfiles and pinned manifests. Ranges are skipped. Lockfiles are read even when the scan ignores them. */
export function readComponents(root: string, skip: (rel: string) => boolean = () => false): Component[] {
  const out: Component[] = [];
  const seen = new Set<string>();
  const add = (c: Component) => {
    if (!c.version || !/^\d/.test(c.version.replace(/^v/, ""))) return;
    const key = `${c.ecosystem}\0${c.name.toLowerCase()}\0${c.version}`;
    if (seen.has(key)) return;
    seen.add(key);
    out.push(c);
  };
  for (const path of findManifests(root, skip)) {
    const text = readText(root, path);
    if (!text) continue;
    const file = path.split("/").pop()!;
    const lines = text.split(/\r?\n/);
    if (file === "package-lock.json" || file === "npm-shrinkwrap.json") {
      try {
        const json = JSON.parse(text) as { packages?: Record<string, { version?: string; name?: string }>; dependencies?: Record<string, V1Dependency> };
        for (const [at, meta] of Object.entries(json.packages ?? {})) {
          if (!at || !meta.version) continue;
          const name = meta.name ?? at.split("node_modules/").pop();
          if (!name || name === at) continue;
          add({ ecosystem: "npm", name, version: meta.version, path });
        }
        // Lockfile version 1 has only a nested dependency tree.
        const walk = (deps: Record<string, V1Dependency>) => {
          for (const [name, meta] of Object.entries(deps)) {
            add({ ecosystem: "npm", name, version: meta.version ?? "", path });
            if (meta.dependencies) walk(meta.dependencies);
          }
        };
        if (!json.packages) walk(json.dependencies ?? {});
      } catch {
        /* not a lockfile */
      }
    } else if (file === "requirements.txt") {
      for (const line of lines) {
        const m = /^\s*([A-Za-z0-9_.-]+)\s*==\s*([0-9][^\\\s]*)/.exec(line);
        if (m) add({ ecosystem: "pypi", name: m[1], version: m[2], path });
      }
    } else if (file === "yarn.lock") {
      let name = "";
      for (const line of lines) {
        if (line && !line.startsWith(" ") && !line.startsWith("\t")) name = line.includes("@workspace:") ? "" : (/^"?(@?[^@"\s]+)@/.exec(line)?.[1] ?? "");
        // Classic writes `version "1.0.0"`, Berry writes `version: 1.0.0`.
        const ver = /^ {2}version:? "?(\d[^"\s]*)/.exec(line);
        if (ver && name) add({ ecosystem: "npm", name, version: ver[1], path });
      }
    } else if (file === "pnpm-lock.yaml") {
      for (const line of lines) {
        const m = /^\s{2}['"]?\/?(@?[^@\s'"]+)@(\d[^:(/'"]*)/.exec(line);
        if (m) add({ ecosystem: "npm", name: m[1], version: m[2], path });
      }
    } else {
      for (const line of lines) {
        const m = /(?:^|\s)([A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)+)\s+v([0-9][^\s]*)/.exec(line);
        if (m) add({ ecosystem: "golang", name: m[1], version: m[2], path });
      }
    }
  }
  return out;
}

export function cycloneDx(components: Component[], version: string): string {
  const bom = {
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    serialNumber: `urn:uuid:${randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: { components: [{ type: "application", name: "vigilsutra", version }] },
      component: { type: "application", name: "scanned-project" }
    },
    components: components.map((c) => ({
      type: "library",
      name: c.name,
      version: c.version,
      purl: purl(c),
      properties: [{ name: "vigilsutra:manifest", value: c.path }]
    }))
  };
  return JSON.stringify(bom, null, 2) + "\n";
}

function purl(c: Component): string {
  if (c.ecosystem === "npm") return `pkg:npm/${c.name.replace(/^@/, "%40")}@${c.version}`;
  if (c.ecosystem === "pypi") return `pkg:pypi/${c.name.toLowerCase()}@${c.version}`;
  return `pkg:golang/${c.name}@v${c.version}`;
}
