import { ALL_RULES, RULES_VERSION } from "../dist/rules/index.js";
const o = [`# Rules (version ${RULES_VERSION})`, "", "Generated from the rule definitions by `node docs/gen-rules.mjs > docs/rules.md`. CWE ids are orientation only; no standards control mapping is asserted (mapping unverified).", "", "| ID | Title | Severity | Confidence | Status | Specialist | CWE |", "|---|---|---|---|---|---|---|"];
for (const r of ALL_RULES) o.push(`| ${r.id} | ${r.title.replace(/\|/g, "\|")} | ${r.severity} | ${r.confidence} | ${r.status} | ${r.agent} | ${(r.cwe ?? []).join(", ")} |`);
o.push("", "## Details", "");
for (const r of ALL_RULES) o.push(`### ${r.id}: ${r.title}`, "", r.description, "", `- **Fix:** ${r.remediation}`, `- **Verify:** ${r.verification}`, `- **False positives:** ${r.falsePositives}`, "");
process.stdout.write(o.join("\n"));
