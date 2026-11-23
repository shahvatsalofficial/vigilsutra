// Verifies the built site: no leftover placeholders, every local link and #anchor resolves.
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
const dir = process.argv[2] ?? "dist";
let bad = 0;
const pages = readdirSync(dir).filter((f) => f.endsWith(".html"));
const ids = new Map(pages.map((f) => [f, new Set([...readFileSync(join(dir, f), "utf8").matchAll(/ id="([^"]+)"/g)].map((m) => m[1]))]));
for (const f of pages) {
  const t = readFileSync(join(dir, f), "utf8");
  if (/\{\{|\}\}/.test(t.replace(/\$\{\{[^}]*\}\}/g, ""))) { console.log(f, "leftover {{ }}"); bad++; }
  for (const m of t.matchAll(/(?:href|src)="([^"]+)"/g)) {
    const h = m[1];
    if (/^(https?:|mailto:|data:)/.test(h) || h === "#") continue;
    if (h.startsWith("#")) { if (!ids.get(f).has(h.slice(1))) { console.log(f, "missing anchor", h); bad++; } continue; }
    const [file, anc] = h.split("#");
    if (!existsSync(join(dir, file))) { console.log(f, "missing file", h); bad++; continue; }
    if (anc && file.endsWith(".html") && !ids.get(file)?.has(anc)) { console.log(f, "missing anchor in", file, anc); bad++; }
  }
}
console.log(`${pages.length} pages checked, ${bad} problem(s)`);
process.exit(bad ? 1 : 0);
