import { dirname, join } from "node:path";
import type { ScannedFile } from "./types.js";
import { isJs, isPy } from "./rules/util.js";

const SOURCE = /\b(req|request|params|query|body|input|event)\b/;

/**
 * Tracks identifier names from a request-like assignment across relative imports.
 * Does not follow object fields, dynamic import(), or function calls.
 */
export function propagateTaint(files: ScannedFile[]): void {
  const byPath = new Map(files.filter((f) => !f.path.startsWith("git-history/")).map((f) => [f.path, f]));
  const tainted = new Map<string, Set<string>>();
  for (const f of byPath.values()) {
    const set = new Set<string>();
    if (isJs(f) || isPy(f)) {
      for (const line of f.lines) {
        const assigned = /(?:^|[^\w$])([A-Za-z_$][\w$]*)\s*=\s*([^=].*)$/.exec(line);
        if (assigned && SOURCE.test(assigned[2])) set.add(assigned[1]);
      }
    }
    tainted.set(f.path, set);
  }
  let changed = true;
  for (let guard = 0; changed && guard < byPath.size + 1; guard++) {
    changed = false;
    for (const f of byPath.values()) {
      const mine = tainted.get(f.path);
      if (!mine) continue;
      for (const line of f.lines) {
        for (const binding of importBindings(line)) {
          const target = resolveImport(f.path, binding.from, byPath);
          const theirs = target ? tainted.get(target) : undefined;
          if (!theirs || !theirs.has(binding.remote) || mine.has(binding.local)) continue;
          mine.add(binding.local);
          changed = true;
        }
      }
    }
  }
  for (const [path, set] of tainted) {
    const file = byPath.get(path);
    if (file && set.size) file.tainted = set;
  }
}

function importBindings(line: string): { from: string; remote: string; local: string }[] {
  const js = /\bimport\s*\{([^}]+)\}\s*from\s*["'](\.[^"']+)["']/.exec(line) ?? /\b(?:const|let|var)\s*\{([^}]+)\}\s*=\s*require\(\s*["'](\.[^"']+)["']\s*\)/.exec(line);
  if (js) {
    return js[1].split(",").flatMap((part) => {
      const m = /^\s*([A-Za-z_$][\w$]*)(?:\s+as\s+([A-Za-z_$][\w$]*))?\s*$/.exec(part);
      if (!m) return [];
      return [{ from: js[2], remote: m[1], local: m[2] ?? m[1] }];
    });
  }
  const py = /^\s*from\s+(\.+[\w.]*)\s+import\s+([A-Za-z_][\w,\s]*)/.exec(line);
  if (!py) return [];
  const spec = pythonSpec(py[1]);
  if (!spec) return [];
  return py[2].split(",").flatMap((part) => {
    const m = /^\s*([A-Za-z_]\w*)(?:\s+as\s+([A-Za-z_]\w*))?\s*$/.exec(part);
    if (!m) return [];
    return [{ from: spec, remote: m[1], local: m[2] ?? m[1] }];
  });
}

function pythonSpec(raw: string): string {
  const m = /^(\.+)(.*)$/.exec(raw);
  if (!m?.[2]) return "";
  const ups = m[1].length - 1;
  const rest = m[2].replace(/\./g, "/");
  const prefix = ups === 0 ? "." : Array.from({ length: ups }, () => "..").join("/");
  return `${prefix}/${rest}`;
}

function resolveImport(fromFile: string, spec: string, files: Map<string, ScannedFile>): string | null {
  const base = join(dirname(fromFile), spec).replace(/\\/g, "/").replace(/^\.\//, "");
  const candidates = [base, `${base}.js`, `${base}.mjs`, `${base}.cjs`, `${base}.ts`, `${base}.tsx`, `${base}.py`, `${base}/index.js`, `${base}/index.ts`];
  return candidates.find((c) => files.has(c)) ?? null;
}
