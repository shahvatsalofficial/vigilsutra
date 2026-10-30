import { createHash } from "node:crypto";
import { existsSync, readFileSync, realpathSync } from "node:fs";
import { basename, join } from "node:path";
import { ALL_RULES, CWE_NOTE, RULES_VERSION, findRule } from "./rules/index.js";
import { inventory, type Inventory } from "./scope.js";
import { loadPolicy, type Policy } from "./policy.js";
import { redactSpan, scrubTokens, tidy } from "./redact.js";
import { SEVERITY_ORDER, type Finding, type Hit, type Rule, type ScanResult, type ScannedFile, type Severity } from "./types.js";

export const VERSION = "0.1.0";

export interface AuditOptions {
  root: string;
  baselineFile?: string;
  policy?: Policy;
}

function sha(s: string): string {
  return createHash("sha256").update(s).digest("hex");
}

/**
 * Fingerprints never include secret values: the hit's secret span is replaced
 * before hashing, and line numbers are excluded so edits above a finding do not churn it.
 */
function redactAll(line: string, spans: [number, number][]): string {
  // Merge overlaps, then replace right-to-left so offsets stay valid.
  const sorted = [...spans].sort((a, b) => a[0] - b[0]);
  const merged: [number, number][] = [];
  for (const sp of sorted) {
    const last = merged[merged.length - 1];
    if (last && sp[0] <= last[1]) last[1] = Math.max(last[1], sp[1]);
    else merged.push([sp[0], sp[1]]);
  }
  let out = line;
  for (const sp of merged.reverse()) out = redactSpan(out, sp);
  return out;
}

function fingerprint(rule: Rule, path: string, hit: Hit, occurrence: number, spans: [number, number][]): string {
  const basis = redactAll(hit.excerpt ?? "", spans).replace(/\s+/g, " ").trim();
  return sha(`${rule.id}|${rule.version}|${path}|${basis}|${occurrence}`).slice(0, 32);
}

function toFinding(rule: Rule, file: { path: string }, hit: Hit, occurrence: number, spans: [number, number][] = hit.secretSpan ? [hit.secretSpan] : []): Finding {
  const redacted = spans.length > 0 || rule.category === "secrets";
  let excerpt = tidy(redactAll(hit.excerpt ?? "", spans));
  excerpt = scrubTokens(excerpt);
  const fp = fingerprint(rule, file.path, hit, occurrence, spans);
  return {
    id: `${rule.id}-${fp.slice(0, 8)}`,
    fingerprint: fp,
    ruleId: rule.id,
    ruleVersion: rule.version,
    title: rule.title,
    category: rule.category,
    severity: hit.severity ?? rule.severity,
    confidence: hit.confidence ?? rule.confidence,
    status: rule.status,
    agent: rule.agent,
    path: file.path,
    startLine: hit.line,
    endLine: hit.endLine ?? hit.line,
    evidenceType: "source-line",
    excerpt,
    redacted,
    description: rule.description,
    remediation: rule.remediation,
    falsePositives: rule.falsePositives,
    verification: rule.verification,
    cwe: rule.cwe ?? [],
    mappingNote: CWE_NOTE,
    note: hit.note
  };
}

export function detectProject(files: ScannedFile[]): string[] {
  const has = (re: RegExp): boolean => files.some((f) => re.test(f.path));
  const out: string[] = [];
  if (has(/(^|\/)package\.json$/)) out.push("node");
  if (has(/\.(ts|tsx)$/)) out.push("typescript");
  if (has(/(^|\/)(requirements\.txt|pyproject\.toml|setup\.py)$/) || has(/\.py$/)) out.push("python");
  if (has(/(^|\/)dockerfile/i)) out.push("docker");
  if (has(/\.tf$/)) out.push("terraform");
  if (has(/^\.github\/workflows\//)) out.push("github-actions");
  if (files.some((f) => /\.ya?ml$/.test(f.path) && /^\s*apiVersion:/m.test(f.text) && /^\s*kind:/m.test(f.text))) out.push("kubernetes");
  if (has(/(^|\/)(agents\.md|claude\.md|\.cursorrules|skill\.md)$/i) || has(/mcp.*\.json$/i)) out.push("ai-agents");
  return out;
}

export function loadBaseline(file: string): Set<string> {
  const data = JSON.parse(readFileSync(file, "utf8")) as { fingerprints?: unknown };
  if (!Array.isArray(data.fingerprints)) throw new Error("baseline file has no fingerprints array");
  return new Set(data.fingerprints.filter((x): x is string => typeof x === "string"));
}

export function audit(opts: AuditOptions): ScanResult {
  const root = realpathSync(opts.root);
  const policy = opts.policy ?? loadPolicy(root);
  const inv: Inventory = inventory(root, policy);
  const disabled = new Set(policy.disableRules.map((r) => r.toUpperCase()));
  const rules = ALL_RULES.filter((r) => !disabled.has(r.id));
  const baseline = opts.baselineFile ? loadBaseline(opts.baselineFile) : new Set<string>();

  let findings: Finding[] = [];
  for (const file of inv.files) {
    const raw: { rule: Rule; hits: Hit[] }[] = [];
    // Every secret span found on a line is redacted from every finding that quotes that line.
    const lineSpans = new Map<number, [number, number][]>();
    for (const rule of rules) {
      let applies = false;
      try {
        applies = rule.applies(file);
      } catch {
        applies = false;
      }
      if (!applies) continue;
      let hits: Hit[] = [];
      try {
        hits = rule.check(file);
      } catch {
        // A faulty rule must never abort the scan; it simply yields no findings.
        continue;
      }
      raw.push({ rule, hits });
      for (const h of hits) {
        if (h.secretSpan) lineSpans.set(h.line, [...(lineSpans.get(h.line) ?? []), h.secretSpan]);
      }
    }
    for (const { rule, hits } of raw) {
      const seen = new Map<string, number>();
      for (const hit of hits) {
        const key = `${hit.excerpt ?? ""}`;
        const n = seen.get(key) ?? 0;
        seen.set(key, n + 1);
        findings.push(toFinding(rule, file, hit, n, lineSpans.get(hit.line) ?? []));
      }
    }
  }

  const proc = findRule("VS-PROC-001");
  if (proc && !disabled.has(proc.id) && !inv.stats.truncated) {
    const found = ["security.md", ".github/security.md", "docs/security.md"].some((p) => [...inv.allPaths].some((x) => x.toLowerCase() === p));
    if (!found) {
      findings.push({
        ...toFinding(proc, { path: "." }, { line: 1, excerpt: "SECURITY.md not found" }, 0),
        evidenceType: "file-absence"
      });
    }
  }

  let suppressed = 0;
  findings = findings.filter((f) => {
    if (baseline.has(f.fingerprint)) {
      suppressed++;
      return false;
    }
    return true;
  });

  findings.sort((a, b) => {
    const s = SEVERITY_ORDER.indexOf(b.severity) - SEVERITY_ORDER.indexOf(a.severity);
    if (s) return s;
    if (a.path !== b.path) return a.path < b.path ? -1 : 1;
    if (a.startLine !== b.startLine) return a.startLine - b.startLine;
    return a.ruleId < b.ruleId ? -1 : a.ruleId > b.ruleId ? 1 : 0;
  });

  const bySeverity: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const byStatus: Record<string, number> = {};
  for (const f of findings) {
    bySeverity[f.severity]++;
    byStatus[f.status] = (byStatus[f.status] ?? 0) + 1;
  }

  const limitations = [
    "Pattern-based static review of text files only; no data-flow or taint analysis.",
    "Source-pattern matches are reported as 'potential' unless the evidence itself is conclusive (for example a token format or an explicit unsafe setting).",
    "A match on a secret format shows the format, not that the credential is live. No credential was tested.",
    "Git history, dependencies, advisories, running systems and remote cloud state were not inspected.",
    "Absence of findings is not evidence of security."
  ];
  if (inv.stats.truncated) limitations.push(`Scan was truncated: ${inv.stats.truncatedReason}. Results are incomplete.`);

  return {
    schemaVersion: "1.0",
    tool: { name: "vigilsutra", version: VERSION, rulesVersion: RULES_VERSION },
    generatedAt: new Date().toISOString(),
    mode: "local",
    project: { name: basename(root), detected: detectProject(inv.files) },
    scope: inv.stats,
    summary: { total: findings.length, bySeverity, byStatus, baselineSuppressed: suppressed },
    categoriesAssessed: ["secrets", "cicd", "containers", "iac", "code", "ai-agents", "privacy", "process"],
    notAssessed: ["dependencies and advisories", "git history", "authentication and authorization design", "runtime / cloud state", "mobile apps", "data-flow and taint analysis"],
    limitations,
    findings
  };
}

export function exceeds(result: ScanResult, failOn: Severity): boolean {
  const min = SEVERITY_ORDER.indexOf(failOn);
  return result.findings.some((f) => SEVERITY_ORDER.indexOf(f.severity) >= min);
}

export function hasFile(root: string, rel: string): boolean {
  return existsSync(join(root, rel));
}
