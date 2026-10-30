export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Confidence = "high" | "medium" | "low";
export type Status = "confirmed" | "potential" | "informational" | "not-assessed" | "resolved";

export const SEVERITY_ORDER: Severity[] = ["info", "low", "medium", "high", "critical"];
export const CONFIDENCE_ORDER: Confidence[] = ["low", "medium", "high"];

export interface ScannedFile {
  /** POSIX-style path relative to the scan root. */
  path: string;
  /** Lower-case file name. */
  name: string;
  /** Lower-case extension including dot, or "". */
  ext: string;
  text: string;
  lines: string[];
}

/** A raw match produced by a rule; the engine turns it into a Finding. */
export interface Hit {
  line: number;
  endLine?: number;
  /** Text of the offending line(s). Redacted by the engine if `secret` is set. */
  excerpt?: string;
  /** Character ranges inside `excerpt` that hold a secret value to redact. */
  secretSpan?: [number, number];
  /** Overrides rule defaults when the hit is weaker/stronger than the rule baseline. */
  confidence?: Confidence;
  severity?: Severity;
  note?: string;
}

export interface Rule {
  id: string;
  version: string;
  title: string;
  category: string;
  severity: Severity;
  confidence: Confidence;
  status: Status;
  /** CWE ids for orientation only; not a compliance claim. */
  cwe?: string[];
  description: string;
  remediation: string;
  falsePositives: string;
  verification: string;
  /** Specialist role (see docs/agent-contract.md). */
  agent: string;
  applies(file: ScannedFile): boolean;
  check(file: ScannedFile): Hit[];
}

export interface Finding {
  id: string;
  fingerprint: string;
  ruleId: string;
  ruleVersion: string;
  title: string;
  category: string;
  severity: Severity;
  confidence: Confidence;
  status: Status;
  agent: string;
  path: string;
  startLine: number;
  endLine: number;
  evidenceType: "source-line" | "file-presence" | "file-absence";
  excerpt: string;
  redacted: boolean;
  description: string;
  remediation: string;
  falsePositives: string;
  verification: string;
  cwe: string[];
  mappingNote: string;
  note?: string;
  baseline?: boolean;
}

export interface ScopeStats {
  root: string;
  filesScanned: number;
  bytesScanned: number;
  skippedIgnored: number;
  skippedSymlinks: number;
  skippedTooLarge: number;
  skippedBinary: number;
  skippedUnreadable: number;
  truncated: boolean;
  truncatedReason?: string;
}

export interface ScanResult {
  schemaVersion: "1.0";
  tool: { name: "vigilsutra"; version: string; rulesVersion: string };
  generatedAt: string;
  mode: "local";
  project: { name: string; detected: string[] };
  scope: ScopeStats;
  summary: {
    total: number;
    bySeverity: Record<Severity, number>;
    byStatus: Record<string, number>;
    baselineSuppressed: number;
  };
  categoriesAssessed: string[];
  notAssessed: string[];
  limitations: string[];
  findings: Finding[];
}
