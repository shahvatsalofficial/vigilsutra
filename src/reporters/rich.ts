import type { Finding, ScanResult, Severity } from "../types.js";

const SEV: Severity[] = ["critical", "high", "medium", "low", "info"];
const SEV_LABEL: Record<Severity, string> = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" };

/** Text placed inside an inline code span must not contain backticks or line breaks (file names can). */
const mdCode = (s: string): string => s.replace(/[`\r\n]/g, "'");
const mdEsc = (s: string): string => s.replace(/[\\`*_{}[\]<>#|]/g, "\\$&");

export const htmlEsc = (s: string): string =>
  s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");

/** One plain-language sentence a non-specialist can act on. */
export function plainSummary(r: ScanResult): string {
  const b = r.summary.bySeverity;
  if (r.summary.total === 0) return "No problems were found by the 32 built-in checks. That is not proof the project is secure: some areas are not checked (see Scope and limits).";
  const urgent = b.critical + b.high;
  if (urgent > 0) return `Start with the ${urgent} critical and high item${urgent === 1 ? "" : "s"}. They are the most likely to cause real harm. The rest can be scheduled afterwards.`;
  if (b.medium > 0) return `No critical or high items. Review the ${b.medium} medium item${b.medium === 1 ? "" : "s"} next; low and info items are hardening and housekeeping.`;
  return "Only low-severity and informational items were found. Review them when convenient.";
}

const NEXT_STEPS = [
  "Fix critical and high items first. Each finding below has a **Fix** and a **Verify** step.",
  "Treat any exposed secret as compromised: rotate or revoke it at the provider before deleting it from the code.",
  "Items marked *potential* need a person to confirm; read **May be a false positive when** before acting.",
  "After fixing, re-run the audit, or run `vigilsutra verify --previous <results.json>` to see what is gone and what is new.",
  "To accept existing findings and fail only on new ones, create a baseline: `vigilsutra baseline --out .vigilsutra-baseline.json`."
];

const READING_GUIDE: [string, string][] = [
  ["Severity", "How bad it would be if the finding is real: critical, high, medium, low or info."],
  ["Confidence", "How reliable the check is: high, medium or low. Findings in test, example or vendored folders are marked low."],
  ["Status", "**confirmed**: the evidence alone is conclusive. **potential**: a pattern match that a person must confirm. **informational**: a note, not a defect."],
  ["Evidence", "The line that triggered the finding. Secret values are always replaced with [REDACTED]."]
];

function ordered(r: ScanResult): Finding[] {
  // Real project code first, then findings in test/example paths, within each severity group order is already stable.
  return [...r.findings].sort((a, b) => Number(!!a.pathContext) - Number(!!b.pathContext));
}

export function toMarkdown(r: ScanResult): string {
  const o: string[] = [];
  const sevCount = (s: Severity): number => r.summary.bySeverity[s];
  o.push(`# VigilSutra AI audit report: ${mdEsc(r.project.name)}`, "");
  o.push(`> Generated ${r.generatedAt} by vigilsutra ${r.tool.version} (rules ${r.tool.rulesVersion}). Offline, read-only scan. Secrets are redacted. Detected: ${r.project.detected.join(", ") || "none"}.`, "");

  o.push("## At a glance", "", `**${plainSummary(r)}**`, "");
  o.push("| Severity | Findings |", "|---|---|");
  for (const s of SEV) o.push(`| ${SEV_LABEL[s]} | ${sevCount(s)} |`);
  o.push(`| **Total** | **${r.summary.total}** |`, "");
  const confirmed = r.summary.byStatus["confirmed"] ?? 0;
  const potential = r.summary.byStatus["potential"] ?? 0;
  const inTests = r.findings.filter((f) => f.pathContext).length;
  o.push(`Confirmed by evidence: **${confirmed}**. Potential (needs a person to confirm): **${potential}**. In test, example or vendored paths: **${inTests}**.${r.summary.baselineSuppressed ? ` Hidden by baseline: ${r.summary.baselineSuppressed}.` : ""}`, "");

  const top = ordered(r).filter((f) => f.severity === "critical" || f.severity === "high").slice(0, 5);
  if (top.length) {
    o.push("## Top priorities", "");
    top.forEach((f, i) => o.push(`${i + 1}. **${f.ruleId}** ${mdEsc(f.title)}: \`${mdCode(f.path)}:${f.startLine}\` (${f.status}, ${f.severity})`));
    o.push("");
  }

  o.push("## How to read this report", "");
  for (const [k, v] of READING_GUIDE) o.push(`- **${k}.** ${v}`);
  o.push("");

  o.push("## All findings", "");
  if (!r.findings.length) o.push("No findings from the implemented rules. This is not proof of security.", "");
  else {
    o.push("| # | Severity | Rule | What | Where | Status |", "|---|---|---|---|---|---|");
    r.findings.forEach((f, i) => o.push(`| ${i + 1} | ${SEV_LABEL[f.severity]} | ${f.ruleId} | ${mdEsc(f.title)} | \`${mdCode(f.path)}:${f.startLine}\` | ${f.status}${f.pathContext ? ", test/example" : ""} |`));
    o.push("");
  }

  o.push("## Details", "");
  let n = 0;
  for (const s of SEV) {
    const group = r.findings.filter((f) => f.severity === s);
    if (!group.length) continue;
    o.push(`### ${SEV_LABEL[s]} (${group.length})`, "");
    for (const f of group) {
      n++;
      o.push(`#### ${n}. ${f.ruleId}: ${mdEsc(f.title)}`, "");
      o.push(`- **Where:** \`${mdCode(f.path)}:${f.startLine}\``);
      o.push(`- **Severity** ${f.severity} | **Confidence** ${f.confidence} | **Status** ${f.status}${f.pathContext ? " | test, example or vendored path" : ""}`);
      o.push(`- **Evidence${f.redacted ? " (redacted)" : ""}:** \`${mdCode(f.excerpt)}\``);
      o.push(`- **Fingerprint:** \`${f.fingerprint}\`${f.cwe.length ? ` | ${f.cwe.join(", ")} (orientation only)` : ""}`, "");
      o.push(`**Why it matters.** ${f.description}`, "", `**Fix.** ${f.remediation}`, "", `**Verify.** ${f.verification}`, "", `**May be a false positive when.** ${f.falsePositives}`, "");
    }
  }

  o.push("## Next steps", "");
  NEXT_STEPS.forEach((t, i) => o.push(`${i + 1}. ${t}`));
  o.push("");
  o.push("## Scope and limits", "");
  o.push(`Scanned ${r.scope.filesScanned} files. Skipped: ${r.scope.skippedIgnored} ignored, ${r.scope.skippedSymlinks} symlinks (never followed), ${r.scope.skippedTooLarge} too large, ${r.scope.skippedBinary} binary.`, "");
  o.push("**Checked:** " + r.categoriesAssessed.join(", ") + ".", "", "**Not checked:** " + r.notAssessed.join("; ") + ".", "");
  r.limitations.forEach((l) => o.push(`- ${l}`));
  o.push("", "---", "Created by Vatsal Shah. VigilSutra reports engineering evidence, not certification or legal advice.", "");
  return o.join("\n");
}

const md = (s: string): string =>
  htmlEsc(s)
    .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
    .replace(/\*([^*]+)\*/g, "<em>$1</em>")
    .replace(/`([^`]+)`/g, "<code>$1</code>");

const CSS = `
:root{--bg:#f6f7fb;--card:#fff;--text:#161a2b;--muted:#586079;--line:#dde1ee;--accent:#3b46d9;--crit:#7a0f1a;--high:#c0392b;--med:#b9770e;--low:#2563eb;--info:#6b7280;--ok:#0f7a4d}
@media (prefers-color-scheme:dark){:root{--bg:#0d111c;--card:#151b2e;--text:#e8ebf7;--muted:#9aa4c2;--line:#27304f;--accent:#8c96ff;--crit:#ff6b7d;--high:#ff8a80;--med:#f2c35b;--low:#7aa7ff;--info:#9aa4c2;--ok:#52d6a0}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:16px/1.65 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:62rem;margin:0 auto;padding:1.5rem 1rem 4rem}h1{font-size:1.9rem;margin:.2rem 0}h2{margin:2.2rem 0 .7rem;font-size:1.35rem}
.meta{color:var(--muted);font-size:.9rem}.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:1rem 1.2rem;margin:.8rem 0}
.lead{font-size:1.15rem;font-weight:600}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(8.5rem,1fr));gap:.7rem}
.stat{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:.7rem 1rem}.stat b{display:block;font-size:1.7rem;line-height:1.1}.stat span{color:var(--muted);font-size:.85rem}
.bar{height:.5rem;border-radius:99px;background:var(--line);margin-top:.5rem;overflow:hidden}.bar i{display:block;height:100%}
.sev{display:inline-block;padding:.05rem .55rem;border-radius:6px;font-size:.75rem;font-weight:700;text-transform:uppercase;color:#fff}
.critical{background:var(--crit)}.high{background:var(--high)}.medium{background:var(--med)}.low{background:var(--low)}.info{background:var(--info)}
.chip{display:inline-block;padding:.05rem .55rem;border-radius:99px;border:1px solid var(--line);font-size:.78rem;color:var(--muted);margin-right:.3rem}
details{background:var(--card);border:1px solid var(--line);border-radius:10px;margin:.5rem 0;padding:.1rem 1rem}summary{cursor:pointer;padding:.7rem 0;font-weight:600}
summary:focus-visible{outline:3px solid var(--accent);border-radius:6px}.where{font-family:ui-monospace,Consolas,monospace;font-size:.88rem;color:var(--muted);word-break:break-all}
pre,code{font-family:ui-monospace,Consolas,monospace}pre{background:#0f1424;color:#e7ebfa;padding:.7rem .9rem;border-radius:8px;overflow:auto;font-size:.85rem;white-space:pre-wrap;word-break:break-word}
code{background:color-mix(in srgb,var(--line) 55%,transparent);padding:.1em .35em;border-radius:5px;font-size:.88em}table{border-collapse:collapse;width:100%;font-size:.9rem}
th,td{border-bottom:1px solid var(--line);padding:.45rem .5rem;text-align:left;vertical-align:top}th{color:var(--muted);font-size:.75rem;text-transform:uppercase}.tw{overflow-x:auto}
a{color:var(--accent)}dt{font-weight:700;margin-top:.5rem}dd{margin:0 0 .3rem 0;color:var(--muted)}footer{color:var(--muted);font-size:.85rem;margin-top:2.5rem}
@media print{details{break-inside:avoid}details>*{display:block}}`;

function findingHtml(f: Finding, i: number): string {
  return `<details id="f-${htmlEsc(f.fingerprint.slice(0, 12))}"${f.severity === "critical" || f.severity === "high" ? " open" : ""}>
<summary><span class="sev ${f.severity}">${f.severity}</span> ${htmlEsc(f.ruleId)}: ${htmlEsc(f.title)}</summary>
<p class="where">${htmlEsc(f.path)}:${f.startLine}</p>
<p><span class="chip">${htmlEsc(f.status)}</span><span class="chip">confidence ${htmlEsc(f.confidence)}</span>${f.pathContext ? '<span class="chip">test, example or vendored path</span>' : ""}${f.cwe.map((c) => `<span class="chip">${htmlEsc(c)}</span>`).join("")}</p>
<p><strong>Evidence${f.redacted ? " (redacted)" : ""}</strong></p><pre>${htmlEsc(f.excerpt)}</pre>
<dl><dt>Why it matters</dt><dd>${htmlEsc(f.description)}</dd><dt>Fix</dt><dd>${htmlEsc(f.remediation)}</dd><dt>Verify</dt><dd>${htmlEsc(f.verification)}</dd><dt>May be a false positive when</dt><dd>${htmlEsc(f.falsePositives)}</dd></dl>
<p class="meta">Finding ${i}. Fingerprint <code>${htmlEsc(f.fingerprint)}</code></p>
</details>`;
}

export function toHtml(r: ScanResult): string {
  const max = Math.max(1, ...SEV.map((s) => r.summary.bySeverity[s]));
  const stats = SEV.map((s) => `<div class="stat"><b>${r.summary.bySeverity[s]}</b><span>${SEV_LABEL[s]}</span><div class="bar"><i class="${s}" style="width:${Math.round((r.summary.bySeverity[s] / max) * 100)}%"></i></div></div>`).join("");
  const confirmed = r.summary.byStatus["confirmed"] ?? 0;
  const potential = r.summary.byStatus["potential"] ?? 0;
  const top = ordered(r).filter((f) => f.severity === "critical" || f.severity === "high").slice(0, 5);
  let n = 0;
  const groups = SEV.map((s) => {
    const g = r.findings.filter((f) => f.severity === s);
    if (!g.length) return "";
    return `<h3>${SEV_LABEL[s]} (${g.length})</h3>\n${g.map((f) => findingHtml(f, ++n)).join("\n")}`;
  }).join("\n");
  const rows = r.findings.map((f, i) => `<tr><td>${i + 1}</td><td><span class="sev ${f.severity}">${f.severity}</span></td><td>${htmlEsc(f.ruleId)}</td><td>${htmlEsc(f.title)}</td><td class="where"><a href="#f-${htmlEsc(f.fingerprint.slice(0, 12))}">${htmlEsc(f.path)}:${f.startLine}</a></td><td>${htmlEsc(f.status)}</td></tr>`).join("");
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<meta name="color-scheme" content="light dark">
<title>VigilSutra AI audit report - ${htmlEsc(r.project.name)}</title>
<style>${CSS}</style></head><body><main>
<p class="meta">VigilSutra AI ${htmlEsc(r.tool.version)} &middot; rules ${htmlEsc(r.tool.rulesVersion)} &middot; ${htmlEsc(r.generatedAt)} &middot; offline, read-only</p>
<h1>Audit report: ${htmlEsc(r.project.name)}</h1>
<p class="meta">Detected: ${htmlEsc(r.project.detected.join(", ") || "none")}</p>
<div class="card"><p class="lead">${htmlEsc(plainSummary(r))}</p>
<p class="meta">Confirmed by evidence: <strong>${confirmed}</strong> &middot; Potential (needs a person to confirm): <strong>${potential}</strong> &middot; Total: <strong>${r.summary.total}</strong>${r.summary.baselineSuppressed ? ` &middot; Hidden by baseline: ${r.summary.baselineSuppressed}` : ""}</p></div>
<div class="grid">${stats}</div>
${top.length ? `<h2>Top priorities</h2><ol>${top.map((f) => `<li><a href="#f-${htmlEsc(f.fingerprint.slice(0, 12))}"><strong>${htmlEsc(f.ruleId)}</strong> ${htmlEsc(f.title)}</a> <span class="where">${htmlEsc(f.path)}:${f.startLine}</span></li>`).join("")}</ol>` : ""}
<h2>How to read this report</h2>
<dl>${READING_GUIDE.map(([k, v]) => `<dt>${htmlEsc(k)}</dt><dd>${md(v)}</dd>`).join("")}</dl>
<h2>All findings</h2>
${r.findings.length ? `<div class="tw card"><table><thead><tr><th>#</th><th>Severity</th><th>Rule</th><th>What</th><th>Where</th><th>Status</th></tr></thead><tbody>${rows}</tbody></table></div>` : "<p>No findings from the implemented rules. This is not proof of security.</p>"}
<h2>Details</h2>
${groups || "<p>Nothing to show.</p>"}
<h2>Next steps</h2><ol>${NEXT_STEPS.map((t) => `<li>${md(t)}</li>`).join("")}</ol>
<h2>Scope and limits</h2>
<div class="card"><p>Scanned ${r.scope.filesScanned} files. Skipped: ${r.scope.skippedIgnored} ignored, ${r.scope.skippedSymlinks} symlinks (never followed), ${r.scope.skippedTooLarge} too large, ${r.scope.skippedBinary} binary.</p>
<p><strong>Checked:</strong> ${htmlEsc(r.categoriesAssessed.join(", "))}.</p><p><strong>Not checked:</strong> ${htmlEsc(r.notAssessed.join("; "))}.</p>
<ul>${r.limitations.map((l) => `<li>${htmlEsc(l)}</li>`).join("")}</ul></div>
<footer>Created by Vatsal Shah. VigilSutra reports engineering evidence, not certification or legal advice. This file is self-contained and loads nothing from the network.</footer>
</main></body></html>
`;
}
