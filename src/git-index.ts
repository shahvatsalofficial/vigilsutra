import { createHash } from "node:crypto";
import { closeSync, fstatSync, lstatSync, openSync, readSync, type Stats } from "node:fs";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";

const MAX_INDEX_BYTES = 32 * 1024 * 1024;
const MAX_GITDIR_FILE = 4096;

export interface GitCache {
  dir: Map<string, GitInfo | "none">;
  index: Map<string, IndexInfo>;
}

interface IndexInfo {
  /** Null when the index could not be read. Empty when the repo tracks nothing. */
  paths: Set<string> | null;
  ignoreCase: boolean;
}

interface GitInfo {
  workTree: string;
  paths: Set<string> | null;
  /** From `core.ignorecase`, else true on Windows and macOS. */
  ignoreCase: boolean;
}

export function createGitCache(): GitCache {
  return { dir: new Map(), index: new Map() };
}

/** `.env`, `.env.local`, `.env.production`, and similar. Example and template files are not secret files. */
export function isDotenvName(name: string): boolean {
  return /^\.env(\..+)?$/i.test(name) && !/\.(example|sample|template)$/i.test(name);
}

/**
 * True when `absFile` is listed in the git index that owns it.
 * `null` means there is no usable index (no repository, or the index could not be parsed).
 * Reads the index file only. Does not run git.
 */
export function gitTracks(absFile: string, cache: GitCache): boolean | null {
  const info = gitFor(dirname(absFile), cache);
  if (info === "none" || info.paths === null) return null;
  let rel = relative(info.workTree, absFile);
  rel = rel.split("\\").join("/");
  if (rel === "" || rel === ".." || rel.startsWith("../") || isAbsolute(rel)) return null;
  if (info.ignoreCase) rel = rel.toLowerCase();
  return info.paths.has(rel);
}

/** Local environment files that git does not track are not part of the review. */
export function shouldSkipUntrackedDotenv(name: string, absFile: string, cache: GitCache): boolean {
  return isDotenvName(name) && gitTracks(absFile, cache) === false;
}

function gitFor(dir: string, cache: GitCache): GitInfo | "none" {
  const hit = cache.dir.get(dir);
  if (hit) return hit;
  const found = readGitAt(dir, cache);
  if (found) {
    cache.dir.set(dir, found);
    return found;
  }
  const parent = dirname(dir);
  if (parent === dir) {
    cache.dir.set(dir, "none");
    return "none";
  }
  const up = gitFor(parent, cache);
  cache.dir.set(dir, up);
  return up;
}

function readGitAt(dir: string, cache: GitCache): GitInfo | null {
  const gitPath = join(dir, ".git");
  let st: Stats;
  try {
    st = lstatSync(gitPath);
  } catch {
    return null;
  }
  if (st.isSymbolicLink()) return null;
  if (st.isDirectory()) {
    if (!isRegularFile(join(gitPath, "HEAD"))) return null;
    return { workTree: dir, ...loadIndex(join(gitPath, "index"), cache, gitPath) };
  }
  if (!st.isFile() || st.size > MAX_GITDIR_FILE || st.size === 0) return null;
  const raw = readRegular(gitPath, st);
  if (!raw) return null;
  const m = /^gitdir:[ \t]*([^\r\n]+)$/m.exec(raw.toString("utf8"));
  if (!m) return null;
  const gitdir = resolve(dir, m[1].trim());
  let gst: Stats;
  try {
    gst = lstatSync(gitdir);
  } catch {
    return { workTree: dir, paths: null, ignoreCase: false };
  }
  if (!gst.isDirectory() || gst.isSymbolicLink()) return { workTree: dir, paths: null, ignoreCase: false };
  if (!isRegularFile(join(gitdir, "HEAD"))) return { workTree: dir, paths: null, ignoreCase: false };
  return { workTree: dir, ...loadIndex(join(gitdir, "index"), cache, gitdir) };
}

function loadIndex(indexPath: string, cache: GitCache, gitDir: string): IndexInfo {
  const cached = cache.index.get(gitDir);
  if (cached) return cached;
  const ignoreCase = readIgnoreCase(gitDir);
  const store = (paths: Set<string> | null): IndexInfo => {
    const info = { paths: paths && ignoreCase ? new Set([...paths].map((p) => p.toLowerCase())) : paths, ignoreCase };
    cache.index.set(gitDir, info);
    return info;
  };
  let st: Stats;
  try {
    st = lstatSync(indexPath);
  } catch {
    return store(new Set());
  }
  if (!st.isFile() || st.isSymbolicLink() || st.size === 0 || st.size > MAX_INDEX_BYTES) return store(null);
  const buf = readRegular(indexPath, st);
  return store(buf ? parseGitIndex(buf) : null);
}

/** `core.ignorecase` when the config says so. Windows and macOS default to true; Linux defaults to false. */
function readIgnoreCase(gitDir: string): boolean {
  const fallback = process.platform === "win32" || process.platform === "darwin";
  const cfgPath = join(gitDir, "config");
  let st: Stats;
  try {
    st = lstatSync(cfgPath);
  } catch {
    return fallback;
  }
  if (!st.isFile() || st.isSymbolicLink() || st.size > 1024 * 1024) return fallback;
  const buf = readRegular(cfgPath, st);
  if (!buf) return fallback;
  const m = /^[ \t]*ignorecase[ \t]*=[ \t]*(true|false)[ \t]*$/im.exec(buf.toString("utf8"));
  return m ? m[1].toLowerCase() === "true" : fallback;
}

function isRegularFile(abs: string): boolean {
  try {
    const st = lstatSync(abs);
    return st.isFile() && !st.isSymbolicLink();
  } catch {
    return false;
  }
}

/** Read a regular file that is still the same inode we just stat'ed. Returns null if it was swapped or is not a file. */
function readRegular(abs: string, expected: Stats): Buffer | null {
  let fd: number;
  try {
    fd = openSync(abs, "r");
  } catch {
    return null;
  }
  try {
    const now = fstatSync(fd);
    if (!sameIdentity(expected, now)) return null;
    const buf = Buffer.alloc(now.size);
    let off = 0;
    while (off < buf.length) {
      const n = readSync(fd, buf, off, buf.length - off, off);
      if (n === 0) break;
      off += n;
    }
    if (off !== buf.length) return null;
    return buf;
  } catch {
    return null;
  } finally {
    closeSync(fd);
  }
}

const FILE_MODES = new Set([0o100644, 0o100755, 0o100664, 0o120000, 0o160000]);

/** Same file after open: inode when the filesystem has one, otherwise size and mtime. */
export function sameIdentity(expected: { ino: number; dev: number; size: number; mtimeMs: number; isFile(): boolean }, now: { ino: number; dev: number; size: number; mtimeMs: number; isFile(): boolean }): boolean {
  if (!now.isFile() || now.size !== expected.size) return false;
  if (expected.ino !== 0 || now.ino !== 0) return now.ino === expected.ino && now.dev === expected.dev;
  return now.mtimeMs === expected.mtimeMs;
}

export interface IndexEntry {
  path: string;
  sha: string;
}

/** Parse a git index (versions 2, 3, and 4; SHA-1 or SHA-256). Returns null if the bytes are not a valid index. */
export function parseGitIndex(buf: Buffer): Set<string> | null {
  const entries = parseGitIndexEntries(buf);
  return entries ? new Set(entries.map((e) => e.path)) : null;
}

/** Index paths plus the staged blob id. Returns null if the bytes are not a valid index. */
export function parseGitIndexEntries(buf: Buffer): IndexEntry[] | null {
  return parseWithHash(buf, 20) ?? parseWithHash(buf, 32);
}

function parseWithHash(buf: Buffer, hashLen: number): IndexEntry[] | null {
  if (buf.length < 12 + hashLen) return null;
  if (buf.toString("latin1", 0, 4) !== "DIRC") return null;
  const version = buf.readUInt32BE(4);
  if (version < 2 || version > 4) return null;
  const count = buf.readUInt32BE(8);
  if (count > 5_000_000) return null;
  const end = buf.length - hashLen;
  const algo = hashLen === 32 ? "sha256" : "sha1";
  const sum = createHash(algo).update(buf.subarray(0, end)).digest();
  if (!sum.equals(buf.subarray(end))) return null;

  const entries: IndexEntry[] = [];
  let pos = 12;
  let prev = "";
  const flagAt = 40 + hashLen;
  for (let i = 0; i < count; i++) {
    if (pos + flagAt + 2 > end) return null;
    const mode = buf.readUInt32BE(pos + 24);
    if (!FILE_MODES.has(mode)) return null;
    const flags = buf.readUInt16BE(pos + flagAt);
    const extended = (flags & 0x4000) !== 0;
    if (extended && version < 3) return null;
    let nameAt = pos + flagAt + 2;
    if (extended) nameAt += 2;
    if (nameAt > end) return null;

    let name: string;
    let next: number;
    if (version === 4) {
      const dec = decodeVarint(buf, nameAt, end);
      if (!dec) return null;
      const nul = buf.indexOf(0, dec.pos);
      if (nul < 0 || nul >= end) return null;
      if (dec.value > prev.length) return null;
      name = prev.slice(0, prev.length - dec.value) + buf.toString("utf8", dec.pos, nul);
      prev = name;
      next = nul + 1;
    } else {
      const declared = flags & 0xfff;
      let nameEnd: number;
      if (declared === 0xfff) {
        nameEnd = buf.indexOf(0, nameAt);
        if (nameEnd < 0 || nameEnd >= end) return null;
      } else {
        nameEnd = nameAt + declared;
        if (nameEnd >= end || buf[nameEnd] !== 0) return null;
      }
      name = buf.toString("utf8", nameAt, nameEnd);
      const raw = nameEnd + 1 - pos;
      next = pos + ((raw + 7) & ~7);
    }
    if (!name || name.includes("\\") || name.startsWith("/") || name.split("/").includes("..")) return null;
    entries.push({ path: name, sha: buf.subarray(pos + 40, pos + 40 + hashLen).toString("hex") });
    if (next <= pos || next > end) return null;
    pos = next;
  }
  while (pos + 8 <= end) {
    const sig = buf.toString("latin1", pos, pos + 4);
    const size = buf.readUInt32BE(pos + 4);
    if (size > end || pos + 8 + size > end) return null;
    // A split index keeps the real entries elsewhere. Don't treat a partial list as complete.
    if (sig === "link") return null;
    pos += 8 + size;
  }
  if (pos !== end) return null;
  return entries;
}

/** Git's offset varint: continuation bytes are biased by +1. See git's decode_varint. */
function decodeVarint(buf: Buffer, pos: number, end: number): { value: number; pos: number } | null {
  if (pos >= end) return null;
  let c = buf[pos++];
  let val = c & 127;
  let guard = 0;
  while (c & 128) {
    if (pos >= end || ++guard > 9) return null;
    val += 1;
    c = buf[pos++];
    val = val * 128 + (c & 127);
  }
  return { value: val, pos };
}
