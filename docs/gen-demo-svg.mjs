// Renders a static terminal-style SVG from REAL CLI output (not hand-typed).
// Usage: node docs/gen-demo-svg.mjs > docs/assets/demo.svg   (run after `npm run build`)
import { spawnSync } from "node:child_process";
const cmd = "vigilsutra audit examples/intentionally-insecure";
const r = spawnSync(process.execPath, ["dist/cli.js", "audit", "examples/intentionally-insecure", "--no-color"], { encoding: "utf8" });
const lines = r.stdout.split("\n").filter((l) => l.trim() !== "").slice(0, 30).map((l) => l.slice(0, 104));
const esc = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
const color = (l) => (/^HIGH|^CRITICAL/.test(l) ? "#ff7b72" : /^MEDIUM/.test(l) ? "#e3b341" : /^LOW/.test(l) ? "#79c0ff" : /^INFO/.test(l) ? "#8b949e" : /^Summary/.test(l) ? "#56d364" : "#c9d1d9");
const h = 64 + (lines.length + 1) * 19;
let y = 62;
const body = [`<text x="22" y="${y}" fill="#56d364">$</text><text x="40" y="${y}" fill="#c9d1d9">${esc(cmd)}</text>`];
for (const l of lines) { y += 19; body.push(`<text x="22" y="${y}" fill="${color(l)}" xml:space="preserve">${esc(l)}</text>`); }
process.stdout.write(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 880 ${h}" width="880" role="img" aria-label="VigilSutra audit of the intentionally insecure demo project: 16 findings">
<title>vigilsutra audit examples/intentionally-insecure (real output)</title>
<rect width="880" height="${h}" rx="10" fill="#0d1117"/><rect width="880" height="34" rx="10" fill="#161b22"/>
<circle cx="20" cy="17" r="6" fill="#ff5f56"/><circle cx="40" cy="17" r="6" fill="#ffbd2e"/><circle cx="60" cy="17" r="6" fill="#27c93f"/>
<g font-family="ui-monospace,SFMono-Regular,Menlo,Consolas,monospace" font-size="12.5">${body.join("")}</g></svg>\n`);
