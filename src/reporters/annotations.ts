import type { ScanResult } from "../types.js";

/** GitHub workflow command escaping; properties also escape the separators. */
const data = (s: string): string => s.replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
const prop = (s: string): string => data(s).replace(/:/g, "%3A").replace(/,/g, "%2C");

/** One annotation per finding that points at a file in the checkout, most severe first. */
export function annotations(r: ScanResult): string {
  return r.findings
    .filter((f) => f.path !== "." && !f.path.startsWith("git-history/"))
    .map((f) => {
      const level = f.severity === "critical" || f.severity === "high" ? "error" : f.severity === "medium" ? "warning" : "notice";
      return `::${level} file=${prop(f.path)},line=${f.startLine},title=${prop(f.ruleId)}::${data(f.title)}\n`;
    })
    .join("");
}
