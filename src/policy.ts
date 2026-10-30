import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import type { Severity } from "./types.js";

export interface Policy {
  ignore: string[];
  maxFileSize: number;
  maxFiles: number;
  timeLimitMs: number;
  failOn?: Severity;
  disableRules: string[];
}

export const DEFAULT_IGNORE = [
  "**/.git/**",
  "**/node_modules/**",
  "**/dist/**",
  "**/build/**",
  "**/out/**",
  "**/vendor/**",
  "**/.venv/**",
  "**/venv/**",
  "**/__pycache__/**",
  "**/coverage/**",
  "**/.next/**",
  "**/target/**",
  "*.min.js",
  "package-lock.json",
  "yarn.lock",
  "pnpm-lock.yaml"
];

export const DEFAULT_POLICY: Policy = {
  ignore: DEFAULT_IGNORE,
  maxFileSize: 1024 * 1024,
  maxFiles: 20000,
  timeLimitMs: 60000,
  disableRules: []
};

/**
 * Parses the small YAML subset used by .vigilsutra.yml:
 * `key: scalar` and `key:` followed by `- item` lines. Comments start with `#`.
 * Anything else is rejected so a typo never silently widens or narrows scope.
 */
export function parsePolicy(text: string): Partial<Policy> {
  const out: Record<string, string | string[]> = {};
  let listKey: string | null = null;
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i].replace(/\s+#.*$/, "").replace(/^#.*$/, "");
    if (!raw.trim()) continue;
    const item = /^\s+-\s+(.+)$/.exec(raw);
    if (item && listKey) {
      (out[listKey] as string[]).push(stripQuotes(item[1].trim()));
      continue;
    }
    const kv = /^([A-Za-z][A-Za-z0-9_]*):\s*(.*)$/.exec(raw);
    if (!kv) throw new Error(`.vigilsutra.yml line ${i + 1}: unsupported syntax`);
    if (kv[2] === "") {
      listKey = kv[1];
      out[listKey] = [];
    } else {
      listKey = null;
      out[kv[1]] = stripQuotes(kv[2].trim());
    }
  }
  const known = new Set(["ignore", "maxFileSize", "maxFiles", "timeLimitMs", "failOn", "disableRules", "version"]);
  for (const k of Object.keys(out)) if (!known.has(k)) throw new Error(`.vigilsutra.yml: unknown key "${k}"`);
  const p: Partial<Policy> = {};
  if (Array.isArray(out.ignore)) p.ignore = out.ignore;
  if (Array.isArray(out.disableRules)) p.disableRules = out.disableRules;
  for (const k of ["maxFileSize", "maxFiles", "timeLimitMs"] as const) {
    if (typeof out[k] === "string") {
      const n = Number(out[k]);
      if (!Number.isInteger(n) || n <= 0) throw new Error(`.vigilsutra.yml: ${k} must be a positive integer`);
      p[k] = n;
    }
  }
  if (typeof out.failOn === "string") {
    if (!["critical", "high", "medium", "low", "info"].includes(out.failOn)) throw new Error(`.vigilsutra.yml: invalid failOn`);
    p.failOn = out.failOn as Severity;
  }
  return p;
}

function stripQuotes(s: string): string {
  return /^(['"]).*\1$/.test(s) ? s.slice(1, -1) : s;
}

export function loadPolicy(root: string): Policy {
  const file = join(root, ".vigilsutra.yml");
  if (!existsSync(file)) return { ...DEFAULT_POLICY };
  const user = parsePolicy(readFileSync(file, "utf8"));
  return {
    ...DEFAULT_POLICY,
    ...user,
    // User ignores extend, never replace, the safe defaults.
    ignore: [...DEFAULT_IGNORE, ...(user.ignore ?? [])]
  };
}

export function globToRegExp(glob: string): RegExp {
  let re = "";
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === "*") {
      if (glob[i + 1] === "*") {
        i++;
        if (glob[i + 1] === "/") {
          i++;
          re += "(?:.*/)?";
        } else re += ".*";
      } else re += "[^/]*";
    } else if (c === "?") re += "[^/]";
    else re += c.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  }
  // A pattern without a slash matches the base name at any depth.
  return glob.includes("/") ? new RegExp(`^${re}$`) : new RegExp(`(^|/)${re}$`);
}

export function makeIgnoreMatcher(patterns: string[]): (relPath: string) => boolean {
  const res = patterns.map(globToRegExp);
  return (p) => res.some((r) => r.test(p));
}
