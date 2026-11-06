import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { Finding } from "./types.js";

/** Deterministic text replacements. A secret is never rewritten. A value that cannot be known (a user name, a commit SHA) is not invented. */
const REPLACEMENTS: Record<string, { from: RegExp; to: string }[]> = {
  "VS-K8S-001": [{ from: /privileged:\s*true\b/, to: "privileged: false" }],
  "VS-K8S-002": [{ from: /host(?:Network|PID|IPC):\s*true\b/, to: "$&" }],
  "VS-K8S-003": [
    { from: /allowPrivilegeEscalation:\s*true\b/, to: "allowPrivilegeEscalation: false" },
    { from: /runAsNonRoot:\s*false\b/, to: "runAsNonRoot: true" }
  ],
  "VS-IAC-002": [
    { from: /public-read-write/, to: "private" },
    { from: /public-read/, to: "private" }
  ],
  "VS-CODE-005": [
    { from: /rejectUnauthorized\s*:\s*false/, to: "rejectUnauthorized: true" },
    { from: /NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0["']?/, to: "NODE_TLS_REJECT_UNAUTHORIZED=1" },
    { from: /\bverify\s*=\s*False\b/, to: "verify=True" }
  ],
  "VS-CODE-006": [
    { from: /createHash\(\s*["']md5["']\s*\)/i, to: 'createHash("sha256")' },
    { from: /createHash\(\s*["']sha1["']\s*\)/i, to: 'createHash("sha256")' },
    { from: /hashlib\.md5\s*\(/i, to: "hashlib.sha256(" },
    { from: /hashlib\.sha1\s*\(/i, to: "hashlib.sha256(" }
  ]
};

export interface PlannedEdit {
  path: string;
  line: number;
  ruleId: string;
  before: string;
  after: string;
}

export function planFixes(findings: Finding[], root: string): PlannedEdit[] {
  const out: PlannedEdit[] = [];
  const seen = new Set<string>();
  for (const f of findings) {
    if (!REPLACEMENTS[f.ruleId] || f.path === "." || f.path.startsWith("git-history/") || f.path.includes("..")) continue;
    const key = `${f.path}:${f.startLine}:${f.ruleId}`;
    if (seen.has(key)) continue;
    seen.add(key);
    let text: string;
    try {
      text = readFileSync(join(root, f.path), "utf8");
    } catch {
      continue;
    }
    const lines = text.split(/\r?\n/);
    const line = lines[f.startLine - 1];
    if (line === undefined) continue;
    const after = rewrite(f.ruleId, line);
    if (!after || after === line) continue;
    out.push({ path: f.path, line: f.startLine, ruleId: f.ruleId, before: line, after });
  }
  return out;
}

function rewrite(ruleId: string, line: string): string | null {
  if (ruleId === "VS-K8S-002") return line.replace(/host(Network|PID|IPC):\s*true\b/, "host$1: false");
  let after = line;
  for (const r of REPLACEMENTS[ruleId] ?? []) after = after.replace(r.from, r.to);
  return after;
}

export function applyFixes(edits: PlannedEdit[], root: string): number {
  const byPath = new Map<string, PlannedEdit[]>();
  for (const e of edits) byPath.set(e.path, [...(byPath.get(e.path) ?? []), e]);
  let written = 0;
  for (const [path, list] of byPath) {
    const abs = join(root, path);
    const text = readFileSync(abs, "utf8");
    const nl = text.includes("\r\n") ? "\r\n" : "\n";
    const lines = text.split(/\r?\n/);
    let changed = false;
    for (const e of list) {
      if (lines[e.line - 1] !== e.before) continue;
      lines[e.line - 1] = e.after;
      changed = true;
      written++;
    }
    if (changed) writeFileSync(abs, lines.join(nl));
  }
  return written;
}
