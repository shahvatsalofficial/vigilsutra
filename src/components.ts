import { randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
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

/** Resolved components from lockfiles and pinned manifests. Ranges are skipped. Lockfiles are read even when the scan ignores them. */
export function readComponents(root: string): Component[] {
  const out: Component[] = [];
  const seen = new Set<string>();
  const add = (c: Component) => {
    if (!c.version || !/^\d/.test(c.version.replace(/^v/, ""))) return;
    const key = `${c.ecosystem}\0${c.name.toLowerCase()}\0${c.version}`;
    if (seen.has(key)) return;
    seen.add(key);
    out.push(c);
  };
  const lock = readText(root, "package-lock.json");
  if (lock) {
    try {
      const json = JSON.parse(lock) as { packages?: Record<string, { version?: string; name?: string }> };
      for (const [path, meta] of Object.entries(json.packages ?? {})) {
        if (!path || !meta.version) continue;
        const name = meta.name ?? path.split("node_modules/").pop();
        if (!name || name === path) continue;
        add({ ecosystem: "npm", name, version: meta.version, path: "package-lock.json" });
      }
    } catch {
      /* not a lockfile */
    }
  }
  const req = readText(root, "requirements.txt");
  if (req) {
    for (const line of req.split(/\n/)) {
      const m = /^\s*([A-Za-z0-9_.-]+)\s*==\s*([0-9][^\\\s]*)/.exec(line);
      if (m) add({ ecosystem: "pypi", name: m[1], version: m[2], path: "requirements.txt" });
    }
  }
  const yarn = readText(root, "yarn.lock");
  if (yarn) {
    let name = "";
    for (const line of yarn.split(/\n/)) {
      if (!line.startsWith(" ") && !line.startsWith("\t")) {
        const head = /^"?(@?[^@"\s]+)@/.exec(line);
        if (head) name = head[1];
      }
      const ver = /^ {2}version "(\d[^"]*)"/.exec(line);
      if (ver && name) add({ ecosystem: "npm", name, version: ver[1], path: "yarn.lock" });
    }
  }
  const pnpm = readText(root, "pnpm-lock.yaml");
  if (pnpm) {
    for (const line of pnpm.split(/\n/)) {
      const m = /^\s{2}\/?(@?[^@\s'"]+)@(\d[^:(/'"]*)/.exec(line);
      if (m) add({ ecosystem: "npm", name: m[1], version: m[2], path: "pnpm-lock.yaml" });
    }
  }
  const gomod = readText(root, "go.mod");
  if (gomod) {
    for (const line of gomod.split(/\n/)) {
      const m = /(?:^|\s)([A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)+)\s+v([0-9][^\s]*)/.exec(line);
      if (m) add({ ecosystem: "golang", name: m[1], version: m[2], path: "go.mod" });
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
  if (c.ecosystem === "npm") return `pkg:npm/${c.name.replace("/", "%2F")}@${c.version}`;
  if (c.ecosystem === "pypi") return `pkg:pypi/${c.name.toLowerCase()}@${c.version}`;
  return `pkg:golang/${c.name}@v${c.version}`;
}
