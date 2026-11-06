import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { gunzipSync } from "node:zlib";
import type { Component } from "./components.js";
import type { Severity } from "./types.js";

export interface Advisory {
  id: string;
  introduced: string;
  /** Exclusive. Absent means no fix is recorded. */
  fixed?: string | null;
  /** Inclusive. Set for an exact version or a `last_affected` event. */
  lastAffected?: string | null;
  severity: Severity;
}

export type AdvisoryDb = Map<string, Advisory[]>;

export function defaultAdvisoryPath(): string {
  const dir = join(dirname(fileURLToPath(import.meta.url)), "..", "advisories");
  const json = join(dir, "db.json");
  return existsSync(json) ? json : join(dir, "db.json.gz");
}

export function loadAdvisoryDb(file: string): AdvisoryDb {
  let buf = readFileSync(file);
  if (buf.length >= 2 && buf[0] === 0x1f && buf[1] === 0x8b) buf = gunzipSync(buf);
  const raw = JSON.parse(buf.toString("utf8")) as { packages?: Record<string, Advisory[]> };
  const db: AdvisoryDb = new Map();
  for (const [key, list] of Object.entries(raw.packages ?? {})) {
    if (Array.isArray(list)) db.set(key, list);
  }
  return db;
}

const cache = new Map<string, AdvisoryDb>();

export function openAdvisoryDb(file = defaultAdvisoryPath()): { db: AdvisoryDb | null; note: string } {
  if (!existsSync(file)) return { db: null, note: `No advisory database at ${file}. Known vulnerabilities were not matched.` };
  const hit = cache.get(file);
  if (hit) return { db: hit, note: advisoryNote(file, hit) };
  try {
    const db = loadAdvisoryDb(file);
    cache.set(file, db);
    return { db, note: advisoryNote(file, db) };
  } catch (e) {
    return { db: null, note: `Advisory database could not be read: ${(e as Error).message}` };
  }
}

function advisoryNote(file: string, db: AdvisoryDb): string {
  return `Advisory database ${file} (${db.size} package names). Match is name and version against recorded ranges. It is a snapshot, not a live feed.`;
}

export interface AdvisoryMatch {
  component: Component;
  advisory: Advisory;
}

export function matchAdvisories(components: Component[], db: AdvisoryDb): AdvisoryMatch[] {
  const out: AdvisoryMatch[] = [];
  for (const c of components) {
    const list = db.get(`${c.ecosystem}\0${c.name.toLowerCase()}`);
    if (!list) continue;
    for (const advisory of list) {
      if (affected(c.version, advisory)) out.push({ component: c, advisory });
    }
  }
  return out;
}

function affected(version: string, advisory: Advisory): boolean {
  const v = version.replace(/^v/, "");
  if (cmp(v, advisory.introduced.replace(/^v/, "")) < 0) return false;
  if (advisory.fixed && cmp(v, advisory.fixed.replace(/^v/, "")) >= 0) return false;
  if (advisory.lastAffected && cmp(v, advisory.lastAffected.replace(/^v/, "")) > 0) return false;
  return true;
}

/** Numeric semver compare. A pre-release is less than the same release. Build metadata is ignored. */
export function cmp(a: string, b: string): number {
  const [am, ap] = a.split("+")[0].split("-");
  const [bm, bp] = b.split("+")[0].split("-");
  const as = am.split(".").map((n) => (/^\d+/.exec(n)?.[0] ?? "0"));
  const bs = bm.split(".").map((n) => (/^\d+/.exec(n)?.[0] ?? "0"));
  const n = Math.max(as.length, bs.length);
  for (let i = 0; i < n; i++) {
    const d = Number(as[i] ?? 0) - Number(bs[i] ?? 0);
    if (d) return d < 0 ? -1 : 1;
  }
  if (ap && !bp) return -1;
  if (!ap && bp) return 1;
  if (ap && bp && ap !== bp) return ap < bp ? -1 : 1;
  return 0;
}
