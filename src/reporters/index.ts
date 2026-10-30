import { ALL_RULES } from "../rules/index.js";
import type { Finding, ScanResult, Severity } from "../types.js";

export type Format = "text" | "json" | "markdown" | "sarif" | "html";
export const FORMATS: Format[] = ["text", "json", "markdown", "sarif", "html"];

const SEV: Severity[] = ["critical", "high", "medium", "low", "info"];

export function toJson(r: ScanResult): string {
  return JSON.stringify(r, null, 2) + "\n";
}

export function toText(r: ScanResult, color = false): string {
  const c = (code: string, s: string): string => (color ? `\x1b[${code}m${s}\x1b[0m` : s);
  const paint: Record<Severity, string> = { critical: "1;31", high: "31", medium: "33", low: "36", info: "2" };
  const out: string[] = [];
  out.push(`VigilSutra AI ${r.tool.version} - local read-only audit of "${r.project.name}"`);
  out.push(`Scanned ${r.scope.filesScanned} files (${r.scope.bytesScanned} bytes). Skipped: ${r.scope.skippedIgnored} ignored, ${r.scope.skippedSymlinks} symlinks, ${r.scope.skippedTooLarge} too large, ${r.scope.skippedBinary} binary.`);
  if (r.project.detected.length) out.push(`Detected: ${r.project.detected.join(", ")}`);
  out.push("");
  if (!r.findings.length) out.push("No findings from the implemented rules. This is not proof of security; see limitations.");
  for (const f of r.findings) {
    out.push(`${c(paint[f.severity], f.severity.toUpperCase().padEnd(8))} ${f.ruleId}  ${f.title}`);
    out.push(`         ${f.path}:${f.startLine}  [${f.status}, confidence ${f.confidence}]`);
    out.push(`         evidence: ${f.excerpt}`);
  }
  out.push("");
  out.push(`Summary: ${SEV.map((s) => `${r.summary.bySeverity[s]} ${s}`).join(", ")}${r.summary.baselineSuppressed ? `; ${r.summary.baselineSuppressed} suppressed by baseline` : ""}`);
  out.push("Limits: pattern-based, offline, no taint analysis. Run `vigilsutra explain <RULE-ID>` for fixes.");
  return out.join("\n") + "\n";
}

const mdEsc = (s: string): string => s.replace(/[\\`*_{}[\]<>#|]/g, "\\$&");

export function toMarkdown(r: ScanResult): string {
  const o: string[] = [];
  o.push(`# VigilSutra AI audit report: ${mdEsc(r.project.name)}`, "");
  o.push(`- Generated: ${r.generatedAt}`, `- Tool: vigilsutra ${r.tool.version} (rules ${r.tool.rulesVersion})`, `- Mode: ${r.mode} (read-only, offline)`, `- Detected: ${r.project.detected.join(", ") || "none"}`, "");
  o.push("## Executive summary", "");
  o.push(`${r.summary.total} finding(s): ${SEV.map((s) => `${r.summary.bySeverity[s]} ${s}`).join(", ")}.`);
  const confirmed = r.summary.byStatus["confirmed"] ?? 0;
  const potential = r.summary.byStatus["potential"] ?? 0;
  o.push(`Confirmed by evidence: ${confirmed}. Potential (needs human verification): ${potential}.`, "");
  const top = r.findings.filter((f) => f.severity === "critical" || f.severity === "high").slice(0, 5);
  if (top.length) {
    o.push("### Top priorities", "");
    top.forEach((f, i) => o.push(`${i + 1}. **${f.ruleId}** ${mdEsc(f.title)} at \`${f.path}:${f.startLine}\``));
    o.push("");
  }
  o.push("### Scope and limits", "");
  o.push(`Scanned ${r.scope.filesScanned} files. Skipped: ${r.scope.skippedIgnored} ignored, ${r.scope.skippedSymlinks} symlinks (never followed), ${r.scope.skippedTooLarge} too large, ${r.scope.skippedBinary} binary.`, "");
  o.push("Assessed: " + r.categoriesAssessed.join(", ") + ".", "", "Not assessed: " + r.notAssessed.join("; ") + ".", "");
  r.limitations.forEach((l) => o.push(`- ${l}`));
  o.push("", "## Findings", "");
  if (!r.findings.length) o.push("No findings from the implemented rules. This is not proof of security.", "");
  for (const f of r.findings) {
    o.push(`### ${f.ruleId}: ${mdEsc(f.title)}`, "");
    o.push(`- Severity: **${f.severity}** | Confidence: **${f.confidence}** | Status: **${f.status}**`);
    o.push(`- Location: \`${f.path}:${f.startLine}\``, `- Fingerprint: \`${f.fingerprint}\`${f.cwe.length ? ` | ${f.cwe.join(", ")} (orientation only)` : ""}`);
    o.push("- Evidence" + (f.redacted ? " (redacted)" : "") + ":", "", "  ```text", "  " + f.excerpt.replace(/`/g, "'"), "  ```", "");
    o.push(`**Why it matters.** ${f.description}`, "", `**Fix.** ${f.remediation}`, "", `**Verify.** ${f.verification}`, "", `**May be a false positive when.** ${f.falsePositives}`, "");
  }
  o.push("---", "Created by Vatsal Shah. VigilSutra reports engineering evidence, not certification or legal advice.", "");
  return o.join("\n");
}

const level = (s: Severity): "error" | "warning" | "note" => (s === "critical" || s === "high" ? "error" : s === "medium" ? "warning" : "note");

export function toSarif(r: ScanResult): string {
  const used = new Set(r.findings.map((f) => f.ruleId));
  const rules = ALL_RULES.filter((x) => used.has(x.id)).map((x) => ({
    id: x.id,
    name: x.title.replace(/[^A-Za-z0-9]+/g, " ").trim().replace(/ (\w)/g, (_m, ch: string) => ch.toUpperCase()),
    shortDescription: { text: x.title },
    fullDescription: { text: x.description },
    help: { text: `${x.remediation}\nVerify: ${x.verification}` },
    defaultConfiguration: { level: level(x.severity) },
    properties: { tags: ["security", x.category, ...(x.cwe ?? [])], precision: x.confidence }
  }));
  const sarif = {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: { driver: { name: "VigilSutra AI", version: r.tool.version, informationUri: "https://github.com/shahvatsalofficial/vigilsutra", rules } },
        results: r.findings.map((f: Finding) => ({
          ruleId: f.ruleId,
          level: level(f.severity),
          message: { text: `${f.title} (${f.status}, confidence ${f.confidence})` },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: f.path === "." ? "." : f.path, uriBaseId: "%SRCROOT%" },
                region: { startLine: f.startLine, endLine: f.endLine }
              }
            }
          ],
          partialFingerprints: { "vigilsutra/v1": f.fingerprint },
          properties: { confidence: f.confidence, status: f.status, severity: f.severity }
        }))
      }
    ]
  };
  return JSON.stringify(sarif, null, 2) + "\n";
}

export const htmlEsc = (s: string): string =>
  s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");

export function toHtml(r: ScanResult): string {
  const rows = r.findings
    .map(
      (f) =>
        `<tr><td>${htmlEsc(f.severity)}</td><td>${htmlEsc(f.ruleId)}</td><td>${htmlEsc(f.title)}</td><td><code>${htmlEsc(f.path)}:${f.startLine}</code></td><td>${htmlEsc(f.status)} / ${htmlEsc(f.confidence)}</td><td><code>${htmlEsc(f.excerpt)}</code></td></tr>`
    )
    .join("\n");
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>VigilSutra AI report - ${htmlEsc(r.project.name)}</title>
<style>body{font:14px/1.5 system-ui,sans-serif;margin:2rem auto;max-width:72rem;padding:0 1rem}table{border-collapse:collapse;width:100%}td,th{border:1px solid #888;padding:.35rem;text-align:left;vertical-align:top}code{word-break:break-all}</style>
</head><body>
<h1>VigilSutra AI report: ${htmlEsc(r.project.name)}</h1>
<p>${r.summary.total} finding(s). Generated ${htmlEsc(r.generatedAt)} by vigilsutra ${htmlEsc(r.tool.version)}. Offline, read-only, pattern-based; not a certification.</p>
<table><thead><tr><th>Severity</th><th>Rule</th><th>Title</th><th>Location</th><th>Status / confidence</th><th>Evidence (redacted)</th></tr></thead><tbody>
${rows}
</tbody></table>
<h2>Limitations</h2><ul>${r.limitations.map((l) => `<li>${htmlEsc(l)}</li>`).join("")}</ul>
<p>Created by Vatsal Shah.</p>
</body></html>
`;
}

export function render(r: ScanResult, f: Format, color = false): string {
  switch (f) {
    case "json":
      return toJson(r);
    case "markdown":
      return toMarkdown(r);
    case "sarif":
      return toSarif(r);
    case "html":
      return toHtml(r);
    default:
      return toText(r, color);
  }
}
