import { lstatSync, readdirSync, realpathSync, openSync, readSync, closeSync, fstatSync, type Stats } from "node:fs";
import { join, basename, extname, relative, isAbsolute } from "node:path";
import type { ScannedFile, ScopeStats } from "./types.js";
import { makeIgnoreMatcher, type Policy } from "./policy.js";
import { createGitCache, shouldSkipUntrackedDotenv } from "./git-index.js";

export interface Inventory {
  files: ScannedFile[];
  stats: ScopeStats;
  /** Relative paths of every non-ignored regular file seen (for presence checks). */
  allPaths: Set<string>;
}

/** True when `p` is `root` or lies beneath it (case-insensitive on Windows). */
export function isInside(root: string, p: string): boolean {
  const fix = (s: string): string => (process.platform === "win32" ? s.toLowerCase() : s);
  const rel = relative(fix(root), fix(p));
  return rel === "" || (!rel.startsWith("..") && !isAbsolute(rel));
}

/**
 * Opens the file once and reads it through that descriptor. Defence against a time-of-check/time-of-use
 * swap: if the path was replaced by a symlink after the earlier lstat, the descriptor refers to a
 * different file, so its device/inode no longer match and the file is refused.
 */
function readChecked(abs: string, expected: Stats): string | "binary" | "swapped" {
  const fd = openSync(abs, "r");
  try {
    const now = fstatSync(fd);
    if (!now.isFile() || (expected.ino !== 0 && (now.ino !== expected.ino || now.dev !== expected.dev))) return "swapped";
    const buf = Buffer.alloc(now.size);
    let off = 0;
    while (off < buf.length) {
      const n = readSync(fd, buf, off, buf.length - off, off);
      if (n === 0) break;
      off += n;
    }
    const head = Math.min(off, 8192);
    for (let i = 0; i < head; i++) if (buf[i] === 0) return "binary";
    return buf.toString("utf8", 0, off);
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
  const gitCache = createGitCache();
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
      // A local .env that git does not track is not a committed secret. Leave it unread.
      // With no usable git index, the file is still reviewed.
      if (shouldSkipUntrackedDotenv(e.name, abs, gitCache)) {
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
        const got = readChecked(abs, st);
        if (got === "swapped") {
          stats.skippedSymlinks++;
          continue;
        }
        if (got === "binary") {
          stats.skippedBinary++;
          continue;
        }
        const text = got;
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
