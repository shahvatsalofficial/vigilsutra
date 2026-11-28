import type { Finding, ScanResult } from "../types.js";

const COLUMNS = ["ruleId", "severity", "confidence", "status", "path", "startLine", "title", "excerpt", "fingerprint"] as const;

/** Quotes every cell and defuses text a spreadsheet would run as a formula. File names come from the scanned project. */
const cell = (value: string | number): string => {
  const text = String(value);
  return `"${(/^[=+\-@\t\r]/.test(text) ? "'" + text : text).replace(/"/g, '""')}"`;
};

export function toCsv(r: ScanResult): string {
  return [COLUMNS.join(","), ...r.findings.map((f) => COLUMNS.map((k) => cell(f[k])).join(","))].join("\r\n") + "\r\n";
}

/** XML 1.0 forbids most control characters, even escaped. */
const xml = (s: string): string =>
  s.replace(/[^\t\n\r\u0020-\ud7ff\ue000-\ufffd\u{10000}-\u{10ffff}]/gu, "?").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

export function toJunit(r: ScanResult): string {
  const test = (f: Finding): string =>
    `  <testcase classname="${xml(f.ruleId)}" name="${xml(`${f.path}:${f.startLine} ${f.title}`)}">\n    <failure type="${f.severity}" message="${xml(f.title)}">${xml(`${f.excerpt}\n${f.remediation}`)}</failure>\n  </testcase>`;
  const cases = r.findings.length ? r.findings.map(test).join("\n") : '  <testcase classname="vigilsutra" name="no findings from the implemented rules"/>';
  return `<?xml version="1.0" encoding="UTF-8"?>\n<testsuite name="vigilsutra" tests="${Math.max(1, r.findings.length)}" failures="${r.findings.length}">\n${cases}\n</testsuite>\n`;
}
