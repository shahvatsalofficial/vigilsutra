import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

const root = join(import.meta.dirname, "..");
const run = (...args) => spawnSync(process.execPath, args, { cwd: root, encoding: "utf8" });

test("docs site builds and every local link and anchor resolves", () => {
  const build = run("site/build.mjs");
  assert.equal(build.status, 0, build.stderr);
  const check = run("site/check.mjs", "site/dist");
  assert.equal(check.status, 0, check.stdout + check.stderr);
  for (const f of ["index.html", "scenarios.html", "evidence.html", "search.json", "sitemap.xml"]) {
    assert.ok(existsSync(join(root, "site/dist", f)), `${f} missing`);
  }
});

test("docs site defaults to the light theme and makes no remote requests", () => {
  const css = readFileSync(join(root, "site/assets/style.css"), "utf8");
  assert.ok(!/prefers-color-scheme/.test(css), "dark mode must be opt-in");
  const html = readFileSync(join(root, "site/dist/index.html"), "utf8");
  assert.ok(!/(src|href)="https?:\/\/(?!github\.com|www\.npmjs\.com|shahvatsalofficial\.github\.io)/.test(html), "unexpected remote asset");
});
