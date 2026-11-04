import { ALL_RULES } from "../rules/index.js";
import type { Finding, ScanResult, Severity } from "../types.js";
import { toHtml, toMarkdown, htmlEsc } from "./rich.js";

export { toHtml, toMarkdown, htmlEsc };

export type Format = "text" | "json" | "markdown" | "sarif" | "html";
export const FORMATS: Format[] = ["text", "json", "markdown", "sarif", "html"];

const SEV: Severity[] = ["critical", "high", "medium", "low", "info"];

export function toJson(r: ScanResult): string {
  return JSON.stringify(r, null, 2) + "\n";
}

export function toText(r: ScanResult, color = false): string {
  const c = (code: string, s: string): string => (color ? `\x1b[${code}m${s}\x1b[0m` : s);
  // File names come from the scanned project and are untrusted: neutralize terminal control characters.
  const safe = (t: string): string => t.replace(/[\u0000-\u001f\u007f-\u009f‪-‮⁦-⁩]/g, "?");
  const paint: Record<Severity, string> = { critical: "1;31", high: "31", medium: "33", low: "36", info: "2" };
  const out: string[] = [];
  out.push(`VigilSutra AI ${r.tool.version} - local read-only audit of "${safe(r.project.name)}"`);
  out.push(`Scanned ${r.scope.filesScanned} files (${r.scope.bytesScanned} bytes). Skipped: ${r.scope.skippedIgnored} ignored, ${r.scope.skippedSymlinks} symlinks, ${r.scope.skippedTooLarge} too large, ${r.scope.skippedBinary} binary.`);
  if (r.project.detected.length) out.push(`Detected: ${r.project.detected.join(", ")}`);
  out.push("");
  if (!r.findings.length) out.push("No findings from the implemented rules. This is not proof of security; see limitations.");
  for (const f of r.findings) {
    out.push(`${c(paint[f.severity], f.severity.toUpperCase().padEnd(8))} ${f.ruleId}  ${f.title}`);
    out.push(`         ${safe(f.path)}:${f.startLine}  [${f.status}, confidence ${f.confidence}]`);
    out.push(`         evidence: ${f.excerpt}`);
  }
  out.push("");
  out.push(`Summary: ${SEV.map((s) => `${r.summary.bySeverity[s]} ${s}`).join(", ")}${r.summary.baselineSuppressed ? `; ${r.summary.baselineSuppressed} suppressed by baseline` : ""}`);
  out.push("Limits: pattern-based, offline, no taint analysis. Run `vigilsutra explain <RULE-ID>` for fixes.");
  return out.join("\n") + "\n";
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
                artifactLocation: { uri: f.path === "." ? "." : f.path.split("/").map(encodeURIComponent).join("/"), uriBaseId: "%SRCROOT%" },
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
