import { createHash, randomUUID } from "node:crypto";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { stamp } from "./clock.js";

export interface Component {
  ecosystem: "npm" | "pypi" | "golang" | "cargo" | "composer" | "gem";
  name: string;
  version: string;
  path: string;
  /** Subresource integrity string from an npm lockfile. */
  integrity?: string;
  /** Licence text as the lockfile states it. */
  license?: string;
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

const MANIFESTS = new Set(["package-lock.json", "npm-shrinkwrap.json", "requirements.txt", "yarn.lock", "pnpm-lock.yaml", "go.mod", "Cargo.lock", "poetry.lock", "composer.lock", "Gemfile.lock", "Pipfile.lock", "uv.lock"]);
/** Dependency files this version recognises but cannot read. */
const UNREAD = new Set(["pom.xml", "build.gradle", "build.gradle.kts", "gradle.lockfile", "packages.lock.json", "Package.resolved", "pubspec.lock", "mix.lock", "bun.lockb", "bun.lock", "conda-lock.yml"]);

export const unreadManifests = (root: string, skip: (rel: string) => boolean = () => false): string[] => findManifests(root, skip, UNREAD);
const SKIP_DIRS = new Set([".git", "node_modules", "dist", "build", "out", "vendor", ".venv", "venv", "__pycache__", "coverage", ".next", "target", "vigilsutra-report"]);

/** Relative paths of manifests at any depth. Symlinks are not followed. */
function findManifests(root: string, skip: (rel: string) => boolean, names: Set<string> = MANIFESTS, dir = "", depth = 0): string[] {
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
    if (e.isFile() && names.has(e.name) && !skip(rel)) out.push(rel);
    if (e.isDirectory() && depth < 8 && !SKIP_DIRS.has(e.name) && !skip(rel + "/placeholder")) out.push(...findManifests(root, skip, names, rel, depth + 1));
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
        const json = JSON.parse(text) as { packages?: Record<string, { version?: string; name?: string; integrity?: string; license?: unknown }>; dependencies?: Record<string, V1Dependency> };
        for (const [at, meta] of Object.entries(json.packages ?? {})) {
          if (!at || !meta.version) continue;
          const name = meta.name ?? at.split("node_modules/").pop();
          if (!name || name === at) continue;
          add({ ecosystem: "npm", name, version: meta.version, path, integrity: meta.integrity, license: typeof meta.license === "string" ? meta.license : undefined });
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
    } else if (file === "Pipfile.lock") {
      try {
        const json = JSON.parse(text) as Record<string, Record<string, { version?: unknown }>>;
        for (const group of ["default", "develop"]) {
          for (const [name, meta] of Object.entries(json[group] ?? {})) {
            if (typeof meta.version === "string") add({ ecosystem: "pypi", name, version: meta.version.replace(/^==/, ""), path });
          }
        }
      } catch {
        /* not a lockfile */
      }
    } else if (file === "Cargo.lock" || file === "poetry.lock" || file === "uv.lock") {
      const ecosystem = file === "Cargo.lock" ? "cargo" : "pypi";
      let name = "";
      for (const line of lines) {
        if (line.startsWith("[")) name = "";
        name = /^name = "([^"]+)"/.exec(line)?.[1] ?? name;
        const version = /^version = "([^"]+)"/.exec(line)?.[1];
        if (version && name) add({ ecosystem, name, version, path });
      }
    } else if (file === "composer.lock") {
      try {
        const json = JSON.parse(text) as Record<string, { name?: string; version?: string }[]>;
        for (const p of [...(json.packages ?? []), ...(json["packages-dev"] ?? [])]) {
          if (p.name) add({ ecosystem: "composer", name: p.name, version: (p.version ?? "").replace(/^v/, ""), path });
        }
      } catch {
        /* not a lockfile */
      }
    } else if (file === "Gemfile.lock") {
      // Resolved gems are indented four spaces; their dependency ranges are indented six.
      for (const line of lines) {
        const m = /^ {4}([A-Za-z0-9_.-]+) \((\d[^)\s]*)\)$/.exec(line);
        if (m) add({ ecosystem: "gem", name: m[1], version: m[2], path });
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

/** Random by default; derived from the content when SOURCE_DATE_EPOCH asks for reproducible output. */
function serial(components: Component[], version: string): string {
  if (!process.env.SOURCE_DATE_EPOCH) return randomUUID();
  const h = createHash("sha256").update(JSON.stringify([version, components])).digest("hex");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-4${h.slice(13, 16)}-8${h.slice(17, 20)}-${h.slice(20, 32)}`;
}

/** CycloneDX wants hexadecimal digests. Strings that are not a SHA integrity value are left out. */
function hashes(integrity: string | undefined): { hashes?: { alg: string; content: string }[] } {
  const m = /^sha(1|256|384|512)-([A-Za-z0-9+/]+={0,2})(?:\s|$)/.exec(typeof integrity === "string" ? integrity : "");
  return m ? { hashes: [{ alg: `SHA-${m[1]}`, content: Buffer.from(m[2], "base64").toString("hex") }] } : {};
}

/** Name and version of the scanned project, when its root package.json states them. */
export function projectIdentity(root: string): { name: string; version?: string } | undefined {
  try {
    const { name, version } = JSON.parse(readText(root, "package.json") ?? "") as { name?: unknown; version?: unknown };
    return typeof name === "string" && name ? { name, ...(typeof version === "string" ? { version } : {}) } : undefined;
  } catch {
    return undefined;
  }
}

export function cycloneDx(components: Component[], version: string, project: { name: string; version?: string } = { name: "scanned-project" }): string {
  // Names that differ only in spelling can share a purl; a reference must stay unique.
  const refs = new Map<string, number>();
  const ref = (c: Component): string => {
    const id = purl(c);
    const n = refs.get(id) ?? 0;
    refs.set(id, n + 1);
    return n ? `${id}#${n}` : id;
  };
  const bom = {
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    serialNumber: `urn:uuid:${serial(components, version)}`,
    version: 1,
    metadata: {
      timestamp: stamp(),
      tools: { components: [{ type: "application", name: "vigilsutra", version }] },
      component: { type: "application", ...project }
    },
    components: components.map((c) => ({
      type: "library",
      "bom-ref": ref(c),
      name: c.name,
      version: c.version,
      purl: purl(c),
      ...hashes(c.integrity),
      ...(c.license ? { licenses: [{ license: { name: c.license } }] } : {}),
      properties: [{ name: "vigilsutra:manifest", value: c.path }]
    }))
  };
  return JSON.stringify(bom, null, 2) + "\n";
}

function purl(c: Component): string {
  if (c.ecosystem === "npm") return `pkg:npm/${c.name.replace(/^@/, "%40")}@${c.version}`;
  // The purl type and PEP 503 treat runs of `-`, `_` and `.` in PyPI names as one hyphen.
  if (c.ecosystem === "pypi") return `pkg:pypi/${c.name.toLowerCase().replace(/[-_.]+/g, "-")}@${c.version}`;
  if (c.ecosystem === "golang") return `pkg:golang/${c.name}@v${c.version}`;
  return `pkg:${c.ecosystem}/${c.name}@${c.version}`;
}
