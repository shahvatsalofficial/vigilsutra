// Inline SVG diagrams and charts for the docs site. Zero dependencies; colors come from CSS variables
// so every figure follows the light/dark theme. All text is escaped.
const esc = (s) => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

const DEFS = `<defs><marker id="ah" viewBox="0 0 10 10" refX="8.5" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" class="ahead"/></marker></defs>`;

/** A rounded box with a title and an optional sub line. cls: "", "a" (accent), "ok", "warn", "bad", "mute". */
const box = (x, y, w, h, title, sub = "", cls = "") => {
  const ty = sub ? y + h / 2 - 3 : y + h / 2 + 5;
  return `<rect class="box ${cls}" x="${x}" y="${y}" width="${w}" height="${h}" rx="10"/><text x="${x + w / 2}" y="${ty}" text-anchor="middle" class="t">${esc(title)}</text>${sub ? `<text x="${x + w / 2}" y="${y + h / 2 + 14}" text-anchor="middle" class="s">${esc(sub)}</text>` : ""}`;
};
const arrow = (d, dashed = false) => `<path class="arrow${dashed ? " dash" : ""}" d="${d}"/>`;
const label = (x, y, text, anchor = "middle") => `<text x="${x}" y="${y}" text-anchor="${anchor}" class="s">${esc(text)}</text>`;
const diamond = (cx, cy, w, h, text, cls = "") =>
  `<polygon class="box ${cls}" points="${cx},${cy - h / 2} ${cx + w / 2},${cy} ${cx},${cy + h / 2} ${cx - w / 2},${cy}"/><text x="${cx}" y="${cy + 4}" text-anchor="middle" class="t">${esc(text)}</text>`;
const svg = (w, h, aria, body) => `<svg viewBox="0 0 ${w} ${h}" role="img" aria-label="${esc(aria)}" xmlns="http://www.w3.org/2000/svg">${DEFS}${body}</svg>`;

export const DIAGRAMS = {
  /** The six steps of one scan, plus the optional passes. */
  pipeline: {
    caption: "What happens during one scan. Every step reads; only the last one writes, and only the report files you asked for.",
    svg: svg(920, 250, "Scan pipeline from resolving the folder to writing the report", [
      box(10, 50, 130, 72, "1 Resolve", "real path of the root", "a"),
      box(165, 50, 130, 72, "2 Inventory", "walk files, skip links", "a"),
      box(320, 50, 130, 72, "3 Filter", "ignore, size, binary", "a"),
      box(475, 50, 130, 72, "4 Check", "42 rules per file", "a"),
      box(630, 50, 130, 72, "5 Redact", "secrets removed first", "ok"),
      box(785, 50, 125, 72, "6 Report", "md, html, json, sarif", "ok"),
      arrow("M140 86H165"), arrow("M295 86H320"), arrow("M450 86H475"), arrow("M605 86H630"), arrow("M760 86H785"),
      box(165, 170, 170, 56, "Git history", "objects read, no git binary", "mute"),
      box(375, 170, 170, 56, "Advisory snapshot", "offline OSV data", "mute"),
      box(585, 170, 170, 56, "Name tracking", "req, body, query via imports", "mute"),
      arrow("M250 170V122", true), arrow("M460 170V122", true), arrow("M670 170L545 122", true),
      label(460, 22, "Nothing is executed. Nothing leaves the machine."),
      label(530, 246, "optional passes feed the same findings list"),
    ].join(""))
  },

  /** Trust boundaries. */
  trust: {
    caption: "Everything in the project you scan is treated as untrusted data. Redaction sits between the engine and every output.",
    svg: svg(920, 300, "Trust boundaries", [
      `<rect class="zone bad" x="10" y="24" width="270" height="250" rx="14"/>`, label(28, 46, "UNTRUSTED: the project", "start"),
      box(30, 66, 230, 56, "Source, configs, docs", "may contain hostile text", "bad"),
      box(30, 142, 230, 56, "AGENTS.md, prompts, policy", "may try to steer a tool", "bad"),
      box(30, 218, 230, 40, "Links, huge or binary files", "skipped or limited", "mute"),
      `<rect class="zone ok" x="325" y="24" width="270" height="250" rx="14"/>`, label(343, 46, "TRUSTED: the vigilsutra process", "start"),
      box(345, 66, 230, 56, "Engine and rules", "reads files as plain text", "ok"),
      box(345, 142, 230, 56, "Redaction layer", "runs before any output", "ok"),
      box(345, 218, 230, 40, "No network, no subprocess", "tested, not promised", "ok"),
      `<rect class="zone warn" x="640" y="24" width="270" height="250" rx="14"/>`, label(658, 46, "HANDLE WITH CARE: outputs", "start"),
      box(660, 66, 230, 56, "Report files", "paths + redacted lines", "warn"),
      box(660, 142, 230, 56, "AI assistant (optional)", "its own data policy applies", "warn"),
      box(660, 218, 230, 40, "Code-scanning upload", "your CI, your choice", "warn"),
      arrow("M260 94H345"), arrow("M460 122V142"), arrow("M575 170H660"), arrow("M775 122V142"),
    ].join(""))
  },

  /** How a pattern match becomes a finding with a status. */
  decision: {
    caption: "How one match is judged. Severity says how bad it would be. Confidence says how sure the rule is. Status says whether the evidence alone settles it.",
    svg: svg(920, 360, "Decision flow from pattern match to finding status", [
      box(10, 148, 130, 56, "Rule matches", "a line or a file", "a"),
      arrow("M140 176H180"),
      diamond(250, 176, 140, 96, "Placeholder or", ""),
      `<text x="250" y="186" text-anchor="middle" class="t">example value?</text>`,
      arrow("M250 224V300"), label(262, 262, "yes", "start"), box(180, 300, 140, 46, "Dropped", "not reported", "mute"),
      arrow("M320 176H370"), label(345, 168, "no"),
      diamond(450, 176, 160, 96, "Evidence alone", ""),
      `<text x="450" y="186" text-anchor="middle" class="t">conclusive?</text>`,
      arrow("M450 128V70"), label(462, 100, "yes", "start"), box(380, 24, 140, 46, "confirmed", "token format, unsafe flag", "bad"),
      arrow("M530 176H590"), label(560, 168, "no"), box(590, 150, 140, 52, "potential", "a person must confirm", "warn"),
      arrow("M730 176H770"),
      diamond(840, 176, 120, 96, "In tests or", ""),
      `<text x="840" y="186" text-anchor="middle" class="t">examples?</text>`,
      arrow("M840 224V262"), label(852, 246, "yes", "start"), box(770, 262, 140, 54, "confidence: low", "kept, sorted last", "mute"),
      arrow("M840 128V92"), label(852, 112, "no", "start"), box(770, 44, 140, 48, "confidence: rule's", "full weight", "ok"),
      box(560, 300, 190, 46, "Baseline / waiver?", "hidden, count shown", "mute"),
      arrow("M650 202V300", true),
    ].join(""))
  },

  /** Where secrets are removed. */
  redaction: {
    caption: "A secret value is cut out of the text before anything is built from it, so it cannot reach a report, a fingerprint, or an AI prompt.",
    svg: svg(920, 220, "Redaction flow", [
      box(10, 70, 180, 70, "Line in your code", 'const key = "AKIA…"', "bad"),
      box(230, 70, 170, 70, "Rule finds the span", "start and end position", "a"),
      box(440, 70, 190, 70, "Span replaced", "[REDACTED], same on every line", "ok"),
      box(670, 28, 240, 56, "Excerpt + fingerprint", "built from the cleaned text", "ok"),
      box(670, 126, 240, 56, "Text, JSON, MD, SARIF, HTML", "tested: no secret in any", "ok"),
      arrow("M190 105H230"), arrow("M400 105H440"), arrow("M630 92L670 60"), arrow("M630 118L670 150"),
      label(460, 200, "A token-shaped string that survives anywhere is scrubbed again as a last guard."),
    ].join(""))
  },

  /** Scenario 1: stopping a leaked key before it is committed. */
  seqLeak: {
    caption: "Scenario 1. The scan runs on what would be committed, so the key never enters history.",
    svg: svg(920, 280, "Sequence: developer stages a file, vigilsutra blocks the commit", [
      label(90, 28, "Developer"), label(330, 28, "git pre-commit hook"), label(580, 28, "vigilsutra"), label(820, 28, "Provider console"),
      ...[90, 330, 580, 820].map((x) => `<line class="life" x1="${x}" y1="40" x2="${x}" y2="262"/>`),
      arrow("M90 70H330"), label(210, 62, "git commit"),
      arrow("M330 100H580"), label(455, 92, "audit --staged --fail-on high"),
      arrow("M580 132H330"), label(455, 124, "HIGH VS-SECRET-001, exit 1"),
      arrow("M330 162H90"), label(210, 154, "commit blocked"),
      arrow("M90 202H820"), label(455, 194, "rotate the key"),
      arrow("M90 240H330"), label(210, 232, "remove it, commit again"),
    ].join(""))
  },

  /** Scenario 2: the baseline ratchet. */
  ratchet: {
    caption: "Scenario 2. Accept what exists, block what is new, then pay the old debt down over time.",
    svg: svg(920, 230, "Baseline ratchet loop", [
      box(10, 80, 170, 70, "Day 1", "16 findings in a legacy repo", "bad"),
      box(220, 80, 170, 70, "baseline --out", "records 16 fingerprints", "a"),
      box(430, 80, 170, 70, "CI: audit --baseline", "fails only on new ones", "ok"),
      box(640, 80, 130, 70, "Fix some", "baseline shrinks", "warn"),
      box(810, 80, 100, 70, "Goal", "empty baseline", "ok"),
      arrow("M180 115H220"), arrow("M390 115H430"), arrow("M600 115H640"), arrow("M770 115H810"),
      arrow("M705 80C705 20 515 20 515 80", true), label(610, 36, "every merge"),
    ].join(""))
  },

  /** Scenario 4: a hostile repository and an AI assistant. */
  seqHostile: {
    caption: "Scenario 3. A project can hide findings with its own policy file, so use --no-policy on code you do not own.",
    svg: svg(920, 280, "Sequence: auditing a project that tries to hide findings", [
      label(110, 28, "Unknown repo"), label(380, 28, "You / your AI assistant"), label(680, 28, "vigilsutra"),
      ...[110, 380, 680].map((x) => `<line class="life" x1="${x}" y1="40" x2="${x}" y2="262"/>`),
      arrow("M380 70H680"), label(530, 62, "audit . (trusts the repo's policy)"),
      arrow("M680 100H380"), label(530, 92, "0 high: policy ignores **"),
      `<rect class="note" x="215" y="116" width="330" height="40" rx="8"/>`, label(380, 140, "Looks clean, but the repo wrote the rules."),
      arrow("M380 186H680"), label(530, 178, "audit . --no-policy"),
      arrow("M680 216H380"), label(530, 208, "HIGH eval, MEDIUM agent override"),
      arrow("M380 246H110", true), label(245, 238, "findings are data, not orders"),
    ].join(""))
  },

  /** CI gate. */
  ciGate: {
    caption: "Scenario 4. A pull request is scanned, results appear in the Security tab, and the check blocks the merge on high findings.",
    svg: svg(920, 190, "CI gate flow", [
      box(10, 60, 130, 70, "Pull request", "opened", "a"),
      box(175, 60, 150, 70, "npx vigilsutra", "audit --fail-on high", "a"),
      diamond(430, 95, 110, 86, "Any high?", "a"),
      box(520, 20, 140, 56, "Check fails", "merge blocked", "bad"), arrow("M485 80L520 56"), label(507, 74, "yes", "start"),
      box(520, 114, 140, 56, "Check passes", "merge allowed", "ok"), arrow("M485 110L520 142"), label(507, 132, "no", "start"),
      box(710, 60, 200, 70, "SARIF upload", "alerts in Security tab", "mute"),
      arrow("M140 95H175"), arrow("M325 95H375"), arrow("M660 48C690 48 690 80 710 85", true), arrow("M660 142C690 142 690 108 710 105", true),
    ].join(""))
  },

  /** Which command do I want. */
  whichCommand: {
    caption: "Pick the command by what you want to do.",
    svg: svg(920, 330, "Which command to use", [
      box(360, 10, 200, 50, "What do I want?", "", "a"),
      box(10, 110, 200, 56, "See the problems", "vigilsutra report .", "ok"), arrow("M400 60L110 110"),
      box(230, 110, 200, 56, "Block a bad commit", "audit --staged --fail-on high", "ok"), arrow("M440 60L330 110"),
      box(450, 110, 200, 56, "Gate pull requests", "audit --fail-on high --baseline", "ok"), arrow("M480 60L550 110"),
      box(670, 110, 240, 56, "Audit code I do not own", "audit . --no-policy", "warn"), arrow("M520 60L790 110"),
      box(10, 230, 200, 56, "Preview safe edits", "vigilsutra fix .", "ok"), arrow("M110 166V230"),
      box(230, 230, 200, 56, "Prove a fix worked", "verify --previous results.json", "ok"), arrow("M330 166V230"),
      box(450, 230, 200, 56, "List my dependencies", "vigilsutra sbom .", "ok"), arrow("M550 166V230"),
      box(670, 230, 240, 56, "Understand a rule", "explain VS-K8S-001", "ok"), arrow("M790 166V230"),
    ].join(""))
  },

  /** Reading a finding. */
  anatomy: {
    caption: "How to read one finding in the console. The HTML and Markdown reports show the same parts with a fix and a verification step.",
    svg: svg(920, 250, "Anatomy of a finding", [
      `<rect class="term" x="10" y="20" width="900" height="130" rx="10"/>`,
      `<text x="30" y="58" class="m crit">HIGH</text><text x="110" y="58" class="m">VS-K8S-001  Kubernetes container runs privileged</text>`,
      `<text x="110" y="88" class="m dim">deployment.yaml:13  [confirmed, confidence high]</text>`,
      `<text x="110" y="118" class="m dim">evidence: privileged: true</text>`,
      box(10, 172, 150, 60, "Severity", "how bad if real", "bad"), arrow("M85 172V152", true),
      box(190, 172, 150, 60, "Rule id", "vigilsutra explain <id>", "a"), arrow("M265 172V152", true),
      box(370, 172, 150, 60, "Where", "file and line", "a"), arrow("M445 172V152", true),
      box(550, 172, 150, 60, "Status + confidence", "settled or needs a person", "warn"), arrow("M625 172V152", true),
      box(730, 172, 180, 60, "Evidence", "secrets show [REDACTED]", "ok"), arrow("M820 172V152", true),
    ].join(""))
  },

  /** Report files. */
  reportFiles: {
    caption: "One scan, four files. Humans read the first two; tools read the last two.",
    svg: svg(920, 220, "Report files written by one scan", [
      box(10, 80, 150, 60, "vigilsutra report .", "one command", "a"),
      box(230, 14, 330, 52, "report.html", "open in a browser, print, share", "ok"),
      box(230, 78, 330, 52, "report.md", "paste into a ticket or pull request", "ok"),
      box(230, 142, 330, 52, "results.json", "scripts, dashboards, verify", "mute"),
      box(600, 78, 310, 52, "results.sarif", "GitHub code scanning", "mute"),
      arrow("M160 110L230 40"), arrow("M160 110H230"), arrow("M160 110L230 168"), arrow("M160 110L200 110L200 200L755 200L755 132", true),
    ].join(""))
  }
};

/* ---------- charts ---------- */

/** Horizontal bars. rows: [{label, value, cls?, note?}] */
export function barChart(rows, { width = 860, unit = "", title = "", max = 0 } = {}) {
  const m = max || Math.max(1, ...rows.map((r) => r.value));
  const rowH = 34, left = 190, right = 120, top = title ? 34 : 10;
  const h = top + rows.length * rowH + 12;
  const iw = width - left - right;
  const body = rows
    .map((r, i) => {
      const y = top + i * rowH;
      const w = Math.max(2, Math.round((r.value / m) * iw));
      return `<text x="${left - 10}" y="${y + 19}" text-anchor="end" class="s">${esc(r.label)}</text><rect class="bar ${r.cls ?? ""}" x="${left}" y="${y + 4}" width="${w}" height="20" rx="4"/><text x="${left + w + 8}" y="${y + 19}" class="t">${esc(r.value)}${esc(unit)}${r.note ? ` <tspan class="s">${esc(r.note)}</tspan>` : ""}</text>`;
    })
    .join("");
  return `<svg viewBox="0 0 ${width} ${h}" role="img" aria-label="${esc(title || "bar chart")}" xmlns="http://www.w3.org/2000/svg">${title ? `<text x="0" y="18" class="t">${esc(title)}</text>` : ""}${body}</svg>`;
}

/** Grouped bars for two series per row. rows: [{label, a, b}] */
export function pairChart(rows, { width = 860, aName = "A", bName = "B", title = "" } = {}) {
  const m = Math.max(1, ...rows.flatMap((r) => [r.a, r.b]));
  const rowH = 52, left = 170, right = 80, top = 50;
  const h = top + rows.length * rowH + 10;
  const iw = width - left - right;
  const body = rows
    .map((r, i) => {
      const y = top + i * rowH;
      const wa = Math.max(2, Math.round((r.a / m) * iw)), wb = Math.max(2, Math.round((r.b / m) * iw));
      return `<text x="${left - 10}" y="${y + 26}" text-anchor="end" class="s">${esc(r.label)}</text><rect class="bar a" x="${left}" y="${y + 4}" width="${wa}" height="17" rx="4"/><text x="${left + wa + 8}" y="${y + 17}" class="t">${r.a}</text><rect class="bar b" x="${left}" y="${y + 24}" width="${wb}" height="17" rx="4"/><text x="${left + wb + 8}" y="${y + 37}" class="t">${r.b}</text>`;
    })
    .join("");
  const legend = `<rect class="bar a" x="${left}" y="4" width="14" height="14" rx="3"/><text x="${left + 20}" y="16" class="s">${esc(aName)}</text><rect class="bar b" x="${left + 190}" y="4" width="14" height="14" rx="3"/><text x="${left + 210}" y="16" class="s">${esc(bName)}</text>`;
  return `<svg viewBox="0 0 ${width} ${h}" role="img" aria-label="${esc(title || "comparison chart")}" xmlns="http://www.w3.org/2000/svg">${legend}${body}</svg>`;
}

/** A single big stat tile row as SVG-free HTML. */
export const statRow = (items) => `<div class="stats">${items.map((s) => `<div class="stat"><b>${esc(s.value)}</b><span>${esc(s.label)}</span></div>`).join("")}</div>`;
