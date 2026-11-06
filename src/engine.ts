import { createHash } from "node:crypto";
import { existsSync, readFileSync, realpathSync } from "node:fs";
import { basename, extname, join } from "node:path";
import { ALL_RULES, CWE_NOTE, RULES_VERSION, findRule } from "./rules/index.js";
import { isTestPath } from "./rules/util.js";
import { inventory, type Inventory } from "./scope.js";
import { blobHash, revisionTree, scanHistory, stagedBlobs } from "./git-objects.js";
import { readComponents } from "./components.js";
import { matchAdvisories, openAdvisoryDb } from "./advisories.js";
import { propagateTaint } from "./taint.js";
import { DEFAULT_POLICY, loadPolicy, type Policy } from "./policy.js";
import { redactSpan, scrubTokens, tidy } from "./redact.js";
import { SEVERITY_ORDER, type Finding, type Hit, type Rule, type ScanResult, type ScannedFile, type Severity } from "./types.js";

export const VERSION = "0.4.0";

/** Per rule, per file. Keeps one noisy file from producing an unbounded report. */
export const MAX_PER_RULE_PER_FILE = 200;

export interface AuditOptions {
  root: string;
  baselineFile?: string;
  policy?: Policy;
  /** Use this policy file instead of the project's own. */
  policyFile?: string;
  /** Ignore the project's .vigilsutra.yml (use built-in defaults). */
  ignoreProjectPolicy?: boolean;
  /** Read git objects reachable from HEAD. Default true. */
  history?: boolean;
  /** Scan only worktree files whose bytes differ from this revision. Skips history. */
  since?: string;
  /** Scan staged blobs from the git index instead of the worktree. Skips history. */
  staged?: boolean;
  /** Advisory snapshot to match. Default is the database shipped with this package. */
  advisoriesFile?: string;
  /** Skip advisory matching. */
  advisories?: boolean;
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
  const testCtx = file.path !== "." && isTestPath(file.path) && rule.category !== "process";
  return {
    id: `${rule.id}-${fp.slice(0, 8)}`,
    fingerprint: fp,
    ruleId: rule.id,
    ruleVersion: rule.version,
    title: rule.title,
    category: rule.category,
    severity: hit.severity ?? rule.severity,
    // Constructs in tests, examples and vendored code are real but rarely actionable: lower confidence, keep visible.
    confidence: testCtx ? "low" : hit.confidence ?? rule.confidence,
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
    note: testCtx ? [hit.note, "Located in a test, example, archived or vendored path; confidence lowered."].filter(Boolean).join(" ") : hit.note,
    ...(testCtx ? { pathContext: "test-or-example" as const } : {})
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
  if (files.some((f) => /\.ya?ml$/.test(f.path) && /^[ \t]*apiVersion:/m.test(f.text) && /^[ \t]*kind:/m.test(f.text))) out.push("kubernetes");
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
  const policy = opts.policy ?? loadPolicy(root, { explicitFile: opts.policyFile, ignoreProjectPolicy: opts.ignoreProjectPolicy });
  const deadline = Date.now() + policy.timeLimitMs;
  const inv: Inventory = inventory(root, policy, deadline);
  const extraNotes: string[] = [];
  let historyRan = false;
  let files = inv.files;
  if (opts.staged && opts.since) throw new Error("use either --staged or --since, not both");
  if (opts.staged) {
    const staged = stagedBlobs(root);
    if (!staged) throw new Error("--staged needs a readable git index in this project");
    files = staged.map((s) => ({ path: s.path, name: basename(s.path).toLowerCase(), ext: extname(s.path).toLowerCase(), text: s.text, lines: s.text.split(/\r\n|\n|\r/) }));
    extraNotes.push("Staged scan reads blobs in the git index. The worktree and older history were not scanned.");
  } else if (opts.since) {
    const rev = revisionTree(root, opts.since);
    if (!rev.blobs) throw new Error(rev.note);
    files = files.filter((f) => rev.blobs!.get(f.path) !== blobHash(f.text, rev.algo));
    extraNotes.push(`Diff scan kept worktree files that differ from ${opts.since}. Git history was not scanned. Run without --since to read history.`);
  } else if (opts.history !== false) {
    const current = new Map(files.map((f) => [f.path, f.text]));
    const hist = scanHistory(root, policy.ignore, current, deadline);
    files = files.concat(hist.files);
    extraNotes.push(...hist.notes);
    historyRan = hist.commitsSeen > 0 || hist.notes.some((n) => n.startsWith("Git history read"));
  } else {
    extraNotes.push("Git history was not scanned (--no-history).");
  }
  propagateTaint(files);
  const opened = opts.advisories === false
    ? { db: null, note: "Advisory matching was skipped (--no-advisories)." }
    : openAdvisoryDb(opts.advisoriesFile);
  extraNotes.push(opened.note);
  let capped = 0;
  const disabled = new Set(policy.disableRules.map((r) => r.toUpperCase()));
  const rules = ALL_RULES.filter((r) => !disabled.has(r.id));
  const baseline = opts.baselineFile ? loadBaseline(opts.baselineFile) : new Set<string>();

  let findings: Finding[] = [];
  for (const file of files) {
    if (Date.now() > deadline) {
      inv.stats.truncated = true;
      inv.stats.truncatedReason = inv.stats.truncatedReason ?? "time limit reached";
      extraNotes.push("The time limit was reached while applying rules. Results are incomplete.");
      break;
    }
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
      for (const [i, hit] of hits.entries()) {
        // Bound output: one rule reporting thousands of lines in one file adds noise, not information.
        if (i >= MAX_PER_RULE_PER_FILE) {
          capped += hits.length - MAX_PER_RULE_PER_FILE;
          break;
        }
        const key = `${hit.excerpt ?? ""}`;
        const n = seen.get(key) ?? 0;
        seen.set(key, n + 1);
        findings.push(toFinding(rule, file, hit, n, lineSpans.get(hit.line) ?? []));
      }
    }
  }

  const advRule = findRule("VS-SUPPLY-004");
  if (advRule && opened.db && !disabled.has(advRule.id)) {
    const matches = matchAdvisories(readComponents(root), opened.db);
    const shown = matches.slice(0, 500);
    if (matches.length > shown.length) extraNotes.push(`${matches.length - shown.length} advisory match(es) were not listed (cap 500).`);
    for (const m of shown) {
      findings.push(toFinding(advRule, { path: m.component.path }, {
        line: 1,
        excerpt: `${m.component.name}@${m.component.version} ${m.advisory.id}`,
        severity: m.advisory.severity,
        note: `Recorded range starts at ${m.advisory.introduced}${m.advisory.fixed ? ` and is fixed in ${m.advisory.fixed}` : m.advisory.lastAffected ? ` through ${m.advisory.lastAffected}` : " and has no recorded fix"}.`
      }, 0));
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
  let waiversApplied = 0;
  let waiversExpired = 0;
  const today = new Date().toISOString().slice(0, 10);
  findings = findings.filter((f) => {
    if (baseline.has(f.fingerprint)) {
      suppressed++;
      return false;
    }
    const waiver = policy.waivers.find((w) => w.ruleId === f.ruleId && w.path === f.path);
    if (!waiver) return true;
    if (waiver.until < today) {
      waiversExpired++;
      return true;
    }
    waiversApplied++;
    return false;
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
    "Pattern-based static review of text files. A request-like assignment is tracked by identifier through relative imports in this project. Object fields, dynamic import(), and values returned from functions are not tracked.",
    "Source-pattern matches are reported as 'potential' unless the evidence itself is conclusive (for example a token format or an explicit unsafe setting).",
    "A match on a secret format shows the format, not that the credential is live. No credential was tested.",
    opened.db
      ? "Advisory matches use the database shipped with this version. It is a snapshot of recorded ranges, not a live feed, and it does not prove a vulnerable function is reachable."
      : "No advisory database was loaded, so known vulnerabilities were not matched.",
    "Untracked .env files are not read when a git index is present. .env.example, .env.sample and .env.template are never treated as secret files.",
    "Lines longer than 2,000 characters are scanned in overlapping windows. The excerpt is the window that matched.",
    "When a filesystem reports inode 0, a swapped file is refused only when size or mtime also changes.",
    "Git history is read until the time limit. A blob larger than 1 MiB is skipped. SHA-1 and SHA-256 object ids are both read.",
    "Absence of findings is not evidence of security.",
    ...extraNotes
  ];
  if (inv.stats.truncated) limitations.push(`Scan was truncated: ${inv.stats.truncatedReason}. Results are incomplete.`);
  const limitsOverridden = policy.maxFileSize !== DEFAULT_POLICY.maxFileSize || policy.maxFiles !== DEFAULT_POLICY.maxFiles || policy.timeLimitMs !== DEFAULT_POLICY.timeLimitMs;
  const narrowed = (policy.userIgnores ?? 0) > 0 || policy.disableRules.length > 0 || policy.waivers.length > 0 || limitsOverridden;
  if (narrowed) {
    limitations.push(
      `Scan scope was changed by ${policy.source}: ${policy.userIgnores ?? 0} extra ignore pattern(s), ${policy.disableRules.length} disabled rule(s), ${policy.waivers.length} waiver(s)${limitsOverridden ? ", custom limits" : ""}. If you did not write this policy (for example when auditing someone else's repository), re-run with --no-policy.`
    );
  }
  if (waiversExpired) limitations.push(`${waiversExpired} finding(s) matched a waiver whose until date has passed. Those findings stay in the report.`);
  if (capped > 0) limitations.push(`${capped} additional finding(s) were not listed because a rule exceeded ${MAX_PER_RULE_PER_FILE} matches in one file.`);
  inv.stats.policy = { source: policy.source ?? "built-in defaults", userIgnorePatterns: policy.userIgnores ?? 0, disabledRules: [...policy.disableRules], limitsOverridden };
  if (capped > 0) inv.stats.cappedFindings = capped;

  return {
    schemaVersion: "1.0",
    tool: { name: "vigilsutra", version: VERSION, rulesVersion: RULES_VERSION },
    generatedAt: new Date().toISOString(),
    mode: "local",
    project: { name: basename(root), detected: detectProject(inv.files) },
    scope: inv.stats,
    summary: { total: findings.length, bySeverity, byStatus, baselineSuppressed: suppressed, waiversApplied, waiversExpired },
    categoriesAssessed: ["secrets", "cicd", "containers", "iac", "code", "ai-agents", "privacy", "process", "supply"],
    notAssessed: [
      ...(historyRan ? [] : ["git history"]),
      ...(opened.db ? [] : ["vulnerability advisories"]),
      "authentication and authorization design",
      "runtime and cloud state",
      "mobile applications",
      "object-field, dynamic-import, and call-return taint"
    ],
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
