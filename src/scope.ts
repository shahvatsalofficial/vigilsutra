import { lstatSync, readdirSync, readFileSync, realpathSync, openSync, readSync, closeSync } from "node:fs";
import { join, basename, extname } from "node:path";
import type { ScannedFile, ScopeStats } from "./types.js";
import { makeIgnoreMatcher, type Policy } from "./policy.js";

export interface Inventory {
  files: ScannedFile[];
  stats: ScopeStats;
  /** Relative paths of every non-ignored regular file seen (for presence checks). */
  allPaths: Set<string>;
}

function looksBinary(abs: string): boolean {
  const fd = openSync(abs, "r");
  try {
    const buf = Buffer.alloc(8192);
    const n = readSync(fd, buf, 0, 8192, 0);
    for (let i = 0; i < n; i++) if (buf[i] === 0) return true;
    return false;
  } finally {
    closeSync(fd);
  }
}

/**
 * Read-only inventory. Symlinks are never followed (they are counted and skipped), so a
 * repository can not redirect the scan outside its root. Nothing is executed.
 */
export function inventory(rootInput: string, policy: Policy): Inventory {
  const root = realpathSync(rootInput);
  const ignored = makeIgnoreMatcher(policy.ignore);
  const stats: ScopeStats = {
    root: basename(root),
    filesScanned: 0,
    bytesScanned: 0,
    skippedIgnored: 0,
    skippedSymlinks: 0,
    skippedTooLarge: 0,
    skippedBinary: 0,
    skippedUnreadable: 0,
    truncated: false
  };
  const files: ScannedFile[] = [];
  const allPaths = new Set<string>();
  const deadline = Date.now() + policy.timeLimitMs;

  const walk = (dirAbs: string, dirRel: string): void => {
    if (stats.truncated) return;
    let entries;
    try {
      entries = readdirSync(dirAbs, { withFileTypes: true });
    } catch {
      stats.skippedUnreadable++;
      return;
    }
    entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    for (const e of entries) {
      if (stats.truncated) return;
      if (Date.now() > deadline) {
        stats.truncated = true;
        stats.truncatedReason = "time limit reached";
        return;
      }
      const rel = dirRel ? `${dirRel}/${e.name}` : e.name;
      const abs = join(dirAbs, e.name);
      let st;
      try {
        st = lstatSync(abs);
      } catch {
        stats.skippedUnreadable++;
        continue;
      }
      if (st.isSymbolicLink()) {
        stats.skippedSymlinks++;
        continue;
      }
      if (st.isDirectory()) {
        if (ignored(rel + "/placeholder")) {
          stats.skippedIgnored++;
          continue;
        }
        walk(abs, rel);
        continue;
      }
      if (!st.isFile()) continue;
      if (ignored(rel)) {
        stats.skippedIgnored++;
        continue;
      }
      allPaths.add(rel);
      if (st.size > policy.maxFileSize) {
        stats.skippedTooLarge++;
        continue;
      }
      if (files.length >= policy.maxFiles) {
        stats.truncated = true;
        stats.truncatedReason = "file count limit reached";
        return;
      }
      try {
        if (looksBinary(abs)) {
          stats.skippedBinary++;
          continue;
        }
        const text = readFileSync(abs, "utf8");
        files.push({
          path: rel,
          name: e.name.toLowerCase(),
          ext: extname(e.name).toLowerCase(),
          text,
          lines: text.split(/\r\n|\n|\r/)
        });
        stats.filesScanned++;
        stats.bytesScanned += st.size;
      } catch {
        stats.skippedUnreadable++;
      }
    }
  };
  walk(root, "");
  return { files, stats, allPaths };
}
