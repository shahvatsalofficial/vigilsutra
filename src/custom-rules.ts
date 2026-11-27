import { readFileSync } from "node:fs";
import { globToRegExp } from "./policy.js";
import { lineRule } from "./rules/util.js";
import { SEVERITY_ORDER, type Rule, type Severity } from "./types.js";

export interface CustomRule {
  rule: Rule;
  /** Example lines the pattern must and must not match. */
  match: string[];
  noMatch: string[];
}

const KEYS = new Set(["id", "title", "severity", "pattern", "flags", "files", "remediation", "secretGroup", "tests"]);

const strings = (v: unknown): v is string[] => Array.isArray(v) && v.every((x) => typeof x === "string");

/**
 * Rules from a JSON file named with --rules. They are never read from the scanned project on their own:
 * a pattern is code that runs against every line, and a slow one can stall the scan.
 */
export function loadCustomRules(file: string): CustomRule[] {
  const data = JSON.parse(readFileSync(file, "utf8").replace(/^\uFEFF/, "")) as { rules?: unknown };
  if (!Array.isArray(data.rules) || !data.rules.length) throw new Error(`${file}: expected {"rules": [ ... ]}`);
  const seen = new Set<string>();
  return (data.rules as Record<string, unknown>[]).map((raw, i) => {
    const bad = (why: string): never => {
      throw new Error(`${file}: rule ${i + 1}: ${why}`);
    };
    for (const key of Object.keys(raw)) if (!KEYS.has(key)) bad(`unknown key "${key}"`);
    const { id, title, severity, pattern, flags = "", files, remediation, secretGroup, tests = {} } = raw;
    if (typeof id !== "string" || !/^VS-CUSTOM-\d{3}$/.test(id) || seen.has(id)) bad("id must be a unique VS-CUSTOM-000 style id");
    seen.add(id as string);
    if (typeof title !== "string" || !title) bad("title is required");
    if (!SEVERITY_ORDER.includes(severity as Severity)) bad("severity must be critical|high|medium|low|info");
    if (typeof pattern !== "string" || !pattern) bad("pattern is required");
    if (typeof flags !== "string" || !/^[ius]*$/.test(flags)) bad("flags may contain only i, u and s");
    if (files !== undefined && !strings(files)) bad("files must be a list of globs");
    if (secretGroup !== undefined && !(Number.isInteger(secretGroup) && (secretGroup as number) >= 0)) bad("secretGroup must be a group number");
    const { match = [], noMatch = [] } = tests as { match?: unknown; noMatch?: unknown };
    if (!strings(match) || !strings(noMatch)) bad("tests.match and tests.noMatch must be lists of strings");
    let re: RegExp;
    try {
      re = new RegExp(pattern as string, flags as string);
    } catch (e) {
      return bad((e as Error).message);
    }
    const globs = ((files as string[] | undefined) ?? []).map(globToRegExp);
    const rule: Rule = {
      id: id as string,
      version: "1.0.0",
      title: title as string,
      category: secretGroup === undefined ? "custom" : "secrets",
      agent: "Custom",
      severity: severity as Severity,
      confidence: "medium",
      status: "potential",
      description: `Custom rule from a rules file: ${title}`,
      remediation: typeof remediation === "string" ? remediation : "Follow the guidance of whoever maintains the rules file.",
      falsePositives: "Depends on the custom pattern.",
      verification: "Re-run the audit with the same --rules file.",
      applies: (f) => !globs.length || globs.some((g) => g.test(f.path)),
      check: (f) => {
        const group = secretGroup as number | undefined;
        // A match without the secret group would leave the value unredacted, so the whole match is used.
        return lineRule(f, re, group === undefined ? {} : { secretGroup: group });
      }
    };
    return { rule, match: match as string[], noMatch: noMatch as string[] };
  });
}

/** Failed examples, as readable messages. */
export function testCustomRules(rules: CustomRule[]): string[] {
  const failures: string[] = [];
  for (const { rule, match, noMatch } of rules) {
    const hits = (line: string): boolean => rule.check({ path: "example", name: "example", ext: "", text: line, lines: [line] }).length > 0;
    for (const line of match) if (!hits(line)) failures.push(`${rule.id}: should match: ${line}`);
    for (const line of noMatch) if (hits(line)) failures.push(`${rule.id}: should not match: ${line}`);
  }
  return failures;
}
