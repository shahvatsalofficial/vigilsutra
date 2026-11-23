#!/usr/bin/env node
// Builds the docs site: site/pages/*.md (+ index.html template) -> site/dist/*.html. Zero dependencies.
// Needs `npm run build` first: rules, CLI help and the sample report come from the real compiled CLI.
import { copyFileSync, cpSync, existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { spawnSync } from "node:child_process";
import { DIAGRAMS, barChart, pairChart, statRow } from "./diagrams.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "..");
const OUT = join(HERE, "dist");
const PAGES = join(HERE, "pages");
const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));
const VERSION = pkg.version;
const SITE = "https://shahvatsalofficial.github.io/vigilsutra/";
const REPO = "https://github.com/shahvatsalofficial/vigilsutra";

mkdirSync(OUT, { recursive: true });
// Empty the folder but keep the folder itself: a preview server inside it would block removing it.
for (const name of readdirSync(OUT)) rmSync(join(OUT, name), { recursive: true, force: true });
mkdirSync(join(OUT, "assets"), { recursive: true });
mkdirSync(join(OUT, "samples"), { recursive: true });

/* ---------- real data from the repo ---------- */
const read = (p) => readFileSync(join(ROOT, p), "utf8");
const json = (p) => JSON.parse(read(p));
const cli = (args) => spawnSync(process.execPath, [join(ROOT, "dist", "cli.js"), ...args], { encoding: "utf8", cwd: ROOT }).stdout;

const { ALL_RULES, RULES_VERSION } = await import(pathToFileURL(join(ROOT, "dist", "rules", "index.js")).href);
const helpText = cli(["--help"]);

const byCategory = {};
const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
for (const r of ALL_RULES) {
  byCategory[r.category] = (byCategory[r.category] ?? 0) + 1;
  bySeverity[r.severity]++;
}

const labelSet = (file) => {
  const t = { n: 0, TP: 0, TT: 0, FP: 0 };
  for (const v of Object.values(json(file).labels)) { t.n++; t[v.label]++; }
  return t;
};
const SETS = { A: labelSet("benchmarks/labels-v0.1.0.json"), B: labelSet("benchmarks/labels-holdout-1.json"), C: labelSet("benchmarks/labels-final-holdout.json") };
const cmp = json("benchmarks/comparison-results.json").totals;
const bench = json("benchmarks/results-summary.json");
const cov = /all files\s*\|\s*([\d.]+)\s*\|\s*([\d.]+)\s*\|\s*([\d.]+)/.exec(read("docs/assurance/coverage-raw.txt"));
const testsN = /\| Tests \| (\d+)/.exec(read("docs/assurance/coverage.md"))?.[1] ?? "n/a";

const CHARTS = {
  rulesByCategory: () => barChart(Object.entries(byCategory).sort((a, b) => b[1] - a[1]).map(([k, v]) => ({ label: k, value: v })), { title: `${ALL_RULES.length} rules by area`, unit: " rules" }),
  rulesBySeverity: () => barChart(Object.entries(bySeverity).map(([k, v]) => ({ label: k, value: v, cls: k === "critical" || k === "high" ? "bad" : k === "medium" ? "warn" : "mute" })), { title: "Rules by default severity", unit: " rules" }),
  falsePositives: () =>
    barChart(
      [
        { label: "A: released rules", value: Math.round((SETS.A.FP / SETS.A.n) * 100), cls: "bad", note: `${SETS.A.FP} of ${SETS.A.n}` },
        { label: "B: after round 1", value: Math.round((SETS.B.FP / SETS.B.n) * 100), cls: "warn", note: `${SETS.B.FP} of ${SETS.B.n}` },
        { label: "C: after all fixes", value: Math.round((SETS.C.FP / SETS.C.n) * 100), cls: "ok", note: `${SETS.C.FP} of ${SETS.C.n}, untouched sample` }
      ],
      { title: "False-positive share in labeled samples", unit: " %", max: 25 }
    ),
  vsGitleaks: () => pairChart([{ label: "Files flagged", a: cmp.secrets.vigilsutra, b: cmp.secrets.gitleaks }, { label: "Flagged by both", a: cmp.secrets.both, b: cmp.secrets.both }, { label: "Only this tool", a: cmp.secrets.onlyVigilSutra, b: cmp.secrets.onlyGitleaks }], { aName: "VigilSutra", bName: "Gitleaks", title: "Secrets" }),
  vsSemgrep: () => pairChart([{ label: "Files flagged", a: cmp.code.vigilsutraFiles, b: cmp.code.semgrepFiles }, { label: "Flagged by both", a: cmp.code.both, b: cmp.code.both }, { label: "Only this tool", a: cmp.code.onlyVigilSutra, b: cmp.code.onlySemgrep }], { aName: "VigilSutra", bName: "Semgrep p/security-audit", title: "Code and configuration" }),
  scanTime: () => {
    const rows = [...bench.repos].filter((r) => r.files).sort((a, b) => b.files - a.files).slice(0, 7).map((r) => ({ label: `${r.name.split("/")[1]} (${r.files} files)`, value: r.ms, cls: "ok" }));
    return barChart(rows, { title: "Scan time on a GitHub Linux runner", unit: " ms" });
  }
};

/* ---------- markdown ---------- */
const esc = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
const slug = (s) => s.toLowerCase().replace(/<[^>]+>/g, "").replace(/`/g, "").replace(/[^a-z0-9\s-]/g, "").trim().replace(/\s+/g, "-");

function inline(src) {
  const codes = [];
  let s = src.replace(/`([^`]+)`/g, (_m, c) => `\u0000${codes.push(`<code>${esc(c)}</code>`) - 1}\u0000`);
  s = esc(s);
  s = s.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>").replace(/(^|[\s(])\*([^*\s][^*]*)\*(?=[\s).,:;]|$)/g, "$1<em>$2</em>");
  s = s.replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, (_m, t, href) => {
    href = href.replace(/&amp;/g, "&");
    const ext = /^https?:/i.test(href) ? ' rel="noopener noreferrer"' : "";
    if (!/^[a-z]+:/i.test(href) && !href.startsWith("#")) href = href.replace(/\.md(#|$)/, ".html$1");
    return `<a href="${esc(href)}"${ext}>${t}</a>`;
  });
  return s.replace(/\u0000(\d+)\u0000/g, (_m, i) => codes[+i]);
}

const cell = (t) => {
  const v = t.trim();
  return /^(critical|high|medium|low|info)$/i.test(v) ? `<span class="sev ${v.toLowerCase()}">${v}</span>` : inline(v);
};

function termHtml(title, body) {
  const lines = body.split("\n").map((l) => {
    const e = esc(l);
    const sev = /^(CRITICAL|HIGH|MEDIUM|LOW|INFO)(\s+)(.*)$/.exec(l);
    if (sev) return `<span class="c-${sev[1].toLowerCase()}">${esc(sev[1])}</span>${esc(sev[2])}${esc(sev[3])}`;
    if (/^\$ /.test(l)) return `<span class="c-ok">$</span> <span class="c-cmd">${esc(l.slice(2))}</span>`;
    if (/^\s{4,}/.test(l) || /^(Summary|Limits|Scanned|Detected|Verify|Reports written|Baseline|Dry run)/.test(l)) return `<span class="c-dim">${e}</span>`;
    return e;
  });
  return `<div class="term"><div class="bar"><i></i><i></i><i></i><span>${esc(title || "terminal")}</span></div><pre><code>${lines.join("\n")}</code></pre></div>`;
}

function render(md) {
  const lines = md.replace(/\r\n/g, "\n").split("\n");
  const html = [];
  const heads = [];
  let i = 0;
  const listRe = /^(\s*)([-*]|\d+\.)\s+(.*)$/;
  while (i < lines.length) {
    const line = lines[i];
    if (!line.trim()) { i++; continue; }
    if (line.startsWith("<!--meta")) { i++; continue; }
    if (line.trim() === ":::scenario") { html.push('<div class="scenario">'); i++; continue; }
    if (line.trim() === ":::") { html.push("</div>"); i++; continue; }
    const fence = /^```(\S*)\s*(.*)$/.exec(line);
    if (fence) {
      const buf = [];
      i++;
      while (i < lines.length && !/^```\s*$/.test(lines[i])) buf.push(lines[i++]);
      i++;
      const [kind, info] = [fence[1], fence[2]];
      if (kind === "term") html.push(termHtml(info, buf.join("\n")));
      else if (kind === "steps") html.push(renderSteps(buf));
      else if (kind === "diagram" || kind === "chart") {
        const name = buf[0].trim();
        if (kind === "diagram") {
          const d = DIAGRAMS[name];
          if (!d) throw new Error(`unknown diagram ${name}`);
          html.push(`<figure class="dia">${d.svg}<figcaption>${esc(d.caption)}</figcaption></figure>`);
        } else {
          if (!CHARTS[name]) throw new Error(`unknown chart ${name}`);
          html.push(`<figure class="dia">${CHARTS[name]()}<figcaption>${esc(buf[1] ?? "")}</figcaption></figure>`);
        }
      } else html.push(`<pre><button class="copy" type="button" aria-label="Copy code">Copy</button><code>${esc(buf.join("\n"))}</code></pre>`);
      continue;
    }
    const h = /^(#{1,4})\s+(.*)$/.exec(line);
    if (h) {
      const lvl = h[1].length, text = h[2], id = slug(text);
      if (lvl === 2 || lvl === 3) heads.push({ lvl, text: text.replace(/`/g, ""), id });
      html.push(`<h${lvl} id="${id}">${inline(text)}${lvl === 2 || lvl === 3 ? `<a class="a" href="#${id}" aria-label="Link to this section">#</a>` : ""}</h${lvl}>`);
      i++;
      continue;
    }
    if (/^---+\s*$/.test(line)) { html.push("<hr>"); i++; continue; }
    if (line.trimStart().startsWith("<") && !line.trimStart().startsWith("<http")) {
      const buf = [];
      while (i < lines.length && lines[i].trim()) buf.push(lines[i++]);
      html.push(buf.join("\n"));
      continue;
    }
    if (line.startsWith("|") && /^\|?\s*:?-{2,}/.test(lines[i + 1] ?? "")) {
      const split = (r) => r.trim().replace(/^\||\|$/g, "").split(/(?<!\\)\|/).map((c) => c.replace(/\\\|/g, "|"));
      const head = split(line);
      i += 2;
      const rows = [];
      while (i < lines.length && lines[i].startsWith("|")) rows.push(split(lines[i++]));
      html.push(`<div class="tw"><table><thead><tr>${head.map((c) => `<th>${inline(c.trim())}</th>`).join("")}</tr></thead><tbody>${rows.map((r) => `<tr>${r.map((c) => `<td>${cell(c)}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`);
      continue;
    }
    if (line.startsWith(">")) {
      const buf = [];
      while (i < lines.length && lines[i].startsWith(">")) buf.push(lines[i++].replace(/^>\s?/, ""));
      const first = buf[0] ?? "";
      const cls = /^\*\*(Warning|Caution|Important)/i.test(first) ? "warn" : /^\*\*(Danger|Security)/i.test(first) ? "bad" : /^\*\*(Tip|Result|Verified)/i.test(first) ? "ok" : "";
      html.push(`<blockquote class="${cls}">${buf.join(" ").split(/\s{2,}/).map((p) => `<p>${inline(p)}</p>`).join("")}</blockquote>`);
      continue;
    }
    if (listRe.test(line)) { const r = renderList(lines, i, listRe); html.push(r.html); i = r.next; continue; }
    const buf = [];
    while (i < lines.length && lines[i].trim() && !/^(#{1,4}\s|```|>|\||---+\s*$|:::)/.test(lines[i]) && !listRe.test(lines[i]) && !lines[i].trimStart().startsWith("<")) buf.push(lines[i++]);
    html.push(`<p>${inline(buf.join(" "))}</p>`);
  }
  return { html: html.join("\n"), heads };
}

function renderList(lines, start, listRe, cls = "") {
  let i = start;
  const stack = [];
  const out = [];
  while (i < lines.length && (listRe.test(lines[i]) || (/^\s{2,}\S/.test(lines[i]) && stack.length))) {
    const m = listRe.exec(lines[i]);
    if (!m) { out.push(" " + inline(lines[i].trim())); i++; continue; }
    const depth = Math.floor(m[1].length / 2);
    const tag = /\d/.test(m[2]) ? "ol" : "ul";
    while (stack.length > depth + 1) out.push(`</li></${stack.pop()}>`);
    if (stack.length === depth + 1) out.push("</li>");
    else { stack.push(tag); out.push(`<${tag}${depth === 0 && cls ? ` class="${cls}"` : ""}>`); }
    out.push(`<li>${inline(m[3])}`);
    i++;
  }
  while (stack.length) out.push(`</li></${stack.pop()}>`);
  return { html: out.join(""), next: i };
}
const renderSteps = (buf) => renderList(buf, 0, /^(\s*)([-*]|\d+\.)\s+(.*)$/, "steps").html;

/* ---------- pages ---------- */
const GROUPS = ["Learn", "Guides", "Reference", "Trust"];
const files = readdirSync(PAGES).filter((f) => f.endsWith(".md")).sort();
const pages = files.map((f) => {
  const src = readFileSync(join(PAGES, f), "utf8");
  const meta = /^<!--meta\s+nav="([^"]*)"\s+group="([^"]*)"\s+desc="([^"]*)"\s*-->/.exec(src) ?? [];
  const slugName = f.replace(/^\d+-/, "").replace(/\.md$/, "");
  return { slug: slugName, src, nav: meta[1] ?? slugName, group: meta[2] ?? "Learn", desc: meta[3] ?? "" };
});

// generated pages that stay in sync with the code
const rulesMd = [
  '<!--meta nav="All 42 rules" group="Reference" desc="Every rule with severity, confidence, status, fix and false-positive guidance."-->'.replace("42", String(ALL_RULES.length)),
  "# Rules catalog",
  "",
  `<div class="chips"><span class="chip">Rules version ${RULES_VERSION}</span><span class="chip">${ALL_RULES.length} rules</span><span class="chip ok">Generated from the code</span></div>`,
  "",
  "This page is generated from the compiled rule definitions on every build, so it cannot drift from what the tool does. CWE ids are for orientation only; no OWASP or NIST control mapping is claimed.",
  "",
  "```chart",
  "rulesByCategory",
  "Every area has rules that were tested against a bad example and a clean example.",
  "```",
  "",
  "```chart",
  "rulesBySeverity",
  "Severity is the default; a finding can be reported lower (for example in test paths, via confidence).",
  "```",
  "",
  "## Summary",
  "",
  "| ID | What it finds | Severity | Confidence | Status |",
  "|---|---|---|---|---|",
  ...ALL_RULES.map((r) => `| \`${r.id}\` | ${r.title.replace(/\|/g, "\\|")} | ${r.severity} | ${r.confidence} | ${r.status} |`),
  "",
  "## Details",
  ""
];
for (const r of ALL_RULES) rulesMd.push(`### ${r.id}: ${r.title}`, "", `Severity **${r.severity}**, confidence **${r.confidence}**, status **${r.status}**, area **${r.category}**${r.cwe?.length ? `, ${r.cwe.join(", ")}` : ""}.`, "", r.description, "", `- **Fix:** ${r.remediation}`, `- **Verify:** ${r.verification}`, `- **Not a problem when:** ${r.falsePositives}`, "");
pages.push({ slug: "rules", src: rulesMd.join("\n"), nav: `All ${ALL_RULES.length} rules`, group: "Reference", desc: "Every rule with severity, confidence, status, fix and false-positive guidance." });

pages.sort((a, b) => GROUPS.indexOf(a.group) - GROUPS.indexOf(b.group) || files.indexOf(a.slug) - files.indexOf(b.slug));

// put charts into the CHARTS registry used by the fenced-block syntax:  ```chart\nname\ncaption\n```
for (const p of pages) {
  const STATS = statRow([{ value: String(ALL_RULES.length), label: "rules, each tested" }, { value: "0", label: "network calls" }, { value: "0", label: "runtime dependencies" }, { value: cov ? `${Number(cov[1]).toFixed(0)}%` : "n/a", label: "line coverage" }, { value: testsN, label: "automated tests" }]);
  const r = render(
    p.src
      .replace(/\{\{version\}\}/g, VERSION)
      .replace(/\{\{rules\}\}/g, String(ALL_RULES.length))
      .replace(/\{\{cov\}\}/g, cov ? Number(cov[1]).toFixed(1) : "n/a")
      .replace(/\{\{covb\}\}/g, cov ? Number(cov[2]).toFixed(1) : "n/a")
      .replace(/\{\{tests\}\}/g, testsN)
      .replace(/\{\{stats\}\}/g, STATS)
      .replace(/\{\{help\}\}/g, () => helpText.trimEnd())
  );
  p.html = r.html;
  p.heads = r.heads;
  p.title = (/^#\s+(.*)$/m.exec(p.src)?.[1] ?? p.nav).replace(/`/g, "");
}

const LOGO = `<svg viewBox="0 0 32 32" aria-hidden="true"><path d="M16 2l11 4v9c0 7-4.6 12.5-11 15C9.6 27.5 5 22 5 15V6z" fill="#3a45d6"/><path d="M10.5 16l4 4 7.5-8.5" fill="none" stroke="#fff" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"/></svg>`;
const TOP = [["start.html", "Start"], ["scenarios.html", "Scenarios"], ["how-it-works.html", "How it works"], ["cli.html", "Reference"], ["evidence.html", "Trust"]];

function shell({ title, desc, body, current, url, extraHead = "", main = true }) {
  const nav = TOP.map(([h, t]) => `<a href="${h}"${h === current ? " aria-current=\"page\"" : ""}>${t}</a>`).join("");
  return `<!doctype html>
<html lang="en" data-base="">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)}</title>
<meta name="description" content="${esc(desc)}">
<link rel="canonical" href="${SITE}${url}">
<meta name="author" content="Vatsal Shah"><meta name="color-scheme" content="light dark"><meta name="theme-color" content="#3a45d6">
<meta property="og:title" content="${esc(title)}"><meta property="og:description" content="${esc(desc)}"><meta property="og:type" content="website"><meta property="og:url" content="${SITE}${url}">
<meta name="twitter:card" content="summary"><link rel="icon" href="assets/favicon.svg" type="image/svg+xml">
<link rel="stylesheet" href="assets/style.css">${extraHead}
<script>try{var t=localStorage.getItem("vs-theme");if(t)document.documentElement.setAttribute("data-theme",t)}catch(e){}</script></head>
<body><a class="skip" href="#content">Skip to content</a>
<header class="top"><button class="btn menu" id="menu" type="button" aria-expanded="false" aria-controls="side">Menu</button>
<a class="brand" href="index.html">${LOGO}<span>VigilSutra<small> docs</small></span></a><nav aria-label="Main">${nav}</nav><span class="sp"></span>
<input id="q" type="search" placeholder="Find /" aria-label="Search the docs" autocomplete="off"><div id="results" role="listbox"></div>
<a class="btn" href="${REPO}" rel="noopener noreferrer">GitHub</a><button class="btn" id="theme" type="button" aria-label="Toggle color theme">Theme</button></header>
${body}
<footer class="site">VigilSutra AI v${VERSION} &middot; Apache-2.0 &middot; Created by Vatsal Shah. A pattern-based review aid, not a certification or legal advice.</footer>
<script src="assets/site.js"></script></body></html>
`;
}

function sidebar(current) {
  return GROUPS.map((g) => {
    const items = pages.filter((p) => p.group === g);
    return items.length ? `<h2>${g}</h2><ul>${items.map((p) => `<li><a href="${p.slug}.html"${p.slug + ".html" === current ? ' aria-current="page"' : ""}>${esc(p.nav)}</a></li>`).join("")}</ul>` : "";
  }).join("");
}

pages.forEach((p, idx) => {
  const prev = pages[idx - 1], next = pages[idx + 1];
  const toc = p.heads.length ? `<nav class="toc" aria-label="On this page"><h2>On this page</h2><ul>${p.heads.map((h) => `<li class="l${h.lvl}"><a href="#${h.id}">${esc(h.text)}</a></li>`).join("")}</ul></nav>` : "<div></div>";
  const body = `<div class="layout"><nav class="side" id="side" aria-label="Documentation"><ul><li><a href="index.html">Home</a></li></ul>${sidebar(p.slug + ".html")}</nav>
<main id="content"><article>${p.html}<div class="pager">${prev ? `<a href="${prev.slug}.html"><small>Previous</small>${esc(prev.nav)}</a>` : "<span></span>"}${next ? `<a class="n" href="${next.slug}.html"><small>Next</small>${esc(next.nav)}</a>` : ""}</div></article></main>${toc}</div>`;
  writeFileSync(join(OUT, `${p.slug}.html`), shell({ title: `${p.title} | VigilSutra AI`, desc: p.desc || p.title, body, current: `${p.slug}.html`, url: `${p.slug}.html` }));
});

/* ---------- landing ---------- */
const landingTpl = read("site/landing.html")
  .replace(/\{\{version\}\}/g, VERSION)
  .replace(/\{\{rules\}\}/g, String(ALL_RULES.length))
  .replace(/\{\{diagram:(\w+)\}\}/g, (_m, n) => `<figure class="dia">${DIAGRAMS[n].svg}<figcaption>${esc(DIAGRAMS[n].caption)}</figcaption></figure>`)
  .replace(/\{\{chart:(\w+)\}\}/g, (_m, n) => `<figure class="dia">${CHARTS[n]()}</figure>`)
  .replace(/\{\{stats\}\}/g, statRow([{ value: String(ALL_RULES.length), label: "rules, each tested" }, { value: "0", label: "network calls" }, { value: "0", label: "runtime dependencies" }, { value: cov ? `${Number(cov[1]).toFixed(0)}%` : "n/a", label: "line coverage" }, { value: "18", label: "public repos benchmarked" }]));
const ld = JSON.stringify({ "@context": "https://schema.org", "@type": "SoftwareSourceCode", name: "VigilSutra AI", codeRepository: REPO, license: "https://www.apache.org/licenses/LICENSE-2.0", version: VERSION, programmingLanguage: "TypeScript", author: { "@type": "Person", name: "Vatsal Shah", url: "https://shahvatsal.com" }, url: SITE });
writeFileSync(join(OUT, "index.html"), shell({ title: "VigilSutra AI: offline security audit for your repo", desc: `Offline, read-only security and privacy auditor with ${ALL_RULES.length} rules, redacted HTML and Markdown reports, no telemetry. Apache-2.0.`, body: landingTpl, current: "", url: "", extraHead: `<script type="application/ld+json">${ld}</script>` }));

/* ---------- 404, search, sitemap, robots, assets, samples ---------- */
writeFileSync(join(OUT, "404.html"), shell({ title: "Page not found | VigilSutra AI", desc: "Page not found", url: "404.html", body: `<div class="wrap" id="content" style="padding:4rem 1.2rem"><h1>Page not found</h1><p class="lead">That page moved or never existed. Try the <a href="index.html">home page</a>, the <a href="start.html">5-minute start</a>, or press <code>/</code> to search.</p></div>` }));
writeFileSync(join(OUT, "search.json"), JSON.stringify(pages.map((p) => ({ url: `${p.slug}.html`, title: p.title, desc: p.desc, heads: p.heads.map((h) => h.text), text: p.html.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").slice(0, 4000) }))));
writeFileSync(join(OUT, "sitemap.xml"), `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${["", ...pages.map((p) => `${p.slug}.html`)].map((u) => `<url><loc>${SITE}${u}</loc></url>`).join("\n")}\n</urlset>\n`);
writeFileSync(join(OUT, "robots.txt"), `User-agent: *\nAllow: /\nSitemap: ${SITE}sitemap.xml\n`);
if (existsSync(join(ROOT, "llms.txt"))) copyFileSync(join(ROOT, "llms.txt"), join(OUT, "llms.txt"));
cpSync(join(HERE, "assets"), join(OUT, "assets"), { recursive: true });
writeFileSync(join(OUT, "assets", "favicon.svg"), `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><path d="M16 2l11 4v9c0 7-4.6 12.5-11 15C9.6 27.5 5 22 5 15V6z" fill="#3a45d6"/><path d="M10.5 16l4 4 7.5-8.5" fill="none" stroke="#fff" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"/></svg>`);

// a fresh real report, generated by the compiled CLI from the demo project
const demo = join(ROOT, "examples", "intentionally-insecure");
spawnSync(process.execPath, [join(ROOT, "dist", "cli.js"), "report", demo, "--report-dir", join(OUT, "samples"), "--no-color"], { encoding: "utf8", cwd: ROOT });
for (const f of ["report.html", "report.md", "results.json", "results.sarif"]) if (!existsSync(join(OUT, "samples", f))) throw new Error(`sample ${f} was not generated`);
rmSync(join(OUT, "samples", ".gitignore"), { force: true });

console.log(`Built ${pages.length} pages + landing into ${OUT}`);
