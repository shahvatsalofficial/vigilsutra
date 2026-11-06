import { createHash } from "node:crypto";
import { lstatSync, readdirSync, readFileSync } from "node:fs";
import { join, relative, resolve, extname, basename, isAbsolute } from "node:path";
import { inflateSync } from "node:zlib";
import { parseGitIndexEntries } from "./git-index.js";
import { makeIgnoreMatcher } from "./policy.js";
import type { ScannedFile } from "./types.js";

/** Blobs larger than this are not loaded from history. The worktree scan uses the same 1 MiB default. */
export const HISTORY_MAX_BLOB_BYTES = 1024 * 1024;

export interface GitLocation {
  workTree: string;
  gitDir: string;
}

interface GitObj {
  type: "commit" | "tree" | "blob" | "tag";
  data: Buffer;
}

/**
 * Finds the .git directory for `start` by walking parents. A symlink `.git` is ignored.
 * A worktree `gitdir:` file is followed only when it points at a real directory.
 */
export function locateGit(start: string): GitLocation | null {
  let dir = resolve(start);
  for (;;) {
    const gitPath = join(dir, ".git");
    let st;
    try {
      st = lstatSync(gitPath);
    } catch {
      const parent = resolve(dir, "..");
      if (parent === dir) return null;
      dir = parent;
      continue;
    }
    if (st.isSymbolicLink()) return null;
    if (st.isDirectory()) {
      if (!isFile(join(gitPath, "HEAD"))) return null;
      return { workTree: dir, gitDir: gitPath };
    }
    if (!st.isFile() || st.size > 4096 || st.size === 0) return null;
    const text = readFileSync(gitPath, "utf8");
    const m = /^gitdir:[ \t]*([^\r\n]+)$/m.exec(text);
    if (!m) return null;
    const gitDir = resolve(dir, m[1].trim());
    let gst;
    try {
      gst = lstatSync(gitDir);
    } catch {
      return null;
    }
    if (!gst.isDirectory() || gst.isSymbolicLink() || !isFile(join(gitDir, "HEAD"))) return null;
    return { workTree: dir, gitDir };
  }
}

function isFile(p: string): boolean {
  try {
    const st = lstatSync(p);
    return st.isFile() && !st.isSymbolicLink();
  } catch {
    return false;
  }
}

/** HEAD, a full object id, or a ref name such as `main` or `refs/heads/main`. */
export function resolveRevision(gitDir: string, rev: string): string | null {
  const name = rev.trim();
  if (/^[0-9a-f]{40}$|^[0-9a-f]{64}$/i.test(name)) return name.toLowerCase();
  if (name === "HEAD") return peel(gitDir, readText(join(gitDir, "HEAD")));
  if (name.startsWith("refs/")) return peel(gitDir, readText(join(gitDir, name))) ?? packed(gitDir, name);
  return peel(gitDir, readText(join(gitDir, "refs", "heads", name))) ?? packed(gitDir, `refs/heads/${name}`);
}

function peel(gitDir: string, text: string | null): string | null {
  if (!text) return null;
  const line = text.trim();
  const ref = /^ref:\s*(\S+)/.exec(line);
  if (ref) return resolveRevision(gitDir, ref[1]);
  return /^[0-9a-f]{40}$|^[0-9a-f]{64}$/i.test(line) ? line.toLowerCase() : null;
}

function packed(gitDir: string, ref: string): string | null {
  const text = readText(join(gitDir, "packed-refs"));
  if (!text) return null;
  for (const line of text.split(/\n/)) {
    if (line.startsWith("#") || line.startsWith("^")) continue;
    const m = /^([0-9a-f]{40}|[0-9a-f]{64})\s+(\S+)/i.exec(line);
    if (m && m[2] === ref) return m[1].toLowerCase();
  }
  return null;
}

function readText(p: string): string | null {
  try {
    const st = lstatSync(p);
    if (!st.isFile() || st.isSymbolicLink() || st.size > 1024 * 1024) return null;
    return readFileSync(p, "utf8");
  } catch {
    return null;
  }
}

class Store {
  private readonly bySha = new Map<string, GitObj | null>();
  private readonly resolving = new Set<string>();
  private readonly packs: { pack: Buffer; shas: Buffer; offsets: number[]; hashLen: number }[] = [];
  readonly notes: string[] = [];
  readonly hashLen: number;
  readonly hashAlgo: "sha1" | "sha256";

  constructor(private readonly gitDir: string) {
    this.hashLen = /objectformat\s*=\s*sha256/i.test(readText(join(gitDir, "config")) ?? "") ? 32 : 20;
    this.hashAlgo = this.hashLen === 32 ? "sha256" : "sha1";
    this.loadPacks();
  }

  get(sha: string): GitObj | null {
    const key = sha.toLowerCase();
    if (this.bySha.has(key)) return this.bySha.get(key) ?? null;
    if (this.resolving.has(key)) return null;
    this.resolving.add(key);
    const found = this.load(key);
    this.resolving.delete(key);
    this.bySha.set(key, found);
    return found;
  }

  private load(key: string): GitObj | null {
    const loose = this.loose(key);
    if (loose) return loose;
    for (const pack of this.packs) {
      const off = offsetOf(pack.shas, pack.offsets, key, pack.hashLen);
      if (off === null) continue;
      return this.at(pack.pack, off, 0);
    }
    return null;
  }

  private loose(sha: string): GitObj | null {
    const p = join(this.gitDir, "objects", sha.slice(0, 2), sha.slice(2));
    try {
      const st = lstatSync(p);
      if (!st.isFile() || st.isSymbolicLink() || st.size > 8 * 1024 * 1024) return null;
      return parseLoose(inflateSync(readFileSync(p)));
    } catch {
      return null;
    }
  }

  private loadPacks(): void {
    const dir = join(this.gitDir, "objects", "pack");
    let names: string[] = [];
    try {
      names = readdirSync(dir);
    } catch {
      return;
    }
    for (const name of names) {
      if (!name.endsWith(".idx")) continue;
      const idxPath = join(dir, name);
      const packPath = idxPath.slice(0, -4) + ".pack";
      try {
        const idx = readFileSync(idxPath);
        const pack = readFileSync(packPath);
        const parsed = parseIdx(idx, this.hashLen);
        if (!parsed) {
          this.notes.push(`Pack index ${name} was skipped (version 2 SHA-1 or SHA-256 indexes are read).`);
          continue;
        }
        this.packs.push({ pack, shas: parsed.shas, offsets: parsed.offsets, hashLen: this.hashLen });
      } catch {
        this.notes.push(`Pack ${name} could not be read.`);
      }
    }
  }

  private at(pack: Buffer, offset: number, depth: number): GitObj | null {
    if (depth > 40 || offset < 0 || offset >= pack.length) return null;
    const header = packHeader(pack, offset, this.hashLen);
    if (!header) return null;
    let payload: Buffer;
    try {
      payload = inflateSync(pack.subarray(header.dataAt));
    } catch {
      return null;
    }
    if (header.type === "ofs") {
      const base = this.at(pack, offset - header.distance, depth + 1);
      if (!base) return null;
      const data = applyDelta(base.data, payload);
      return data ? { type: base.type, data } : null;
    }
    if (header.type === "ref") {
      const base = this.get(header.base);
      if (!base) return null;
      const data = applyDelta(base.data, payload);
      return data ? { type: base.type, data } : null;
    }
    if (payload.length !== header.size) return null;
    return { type: header.type, data: payload };
  }
}

function parseLoose(raw: Buffer): GitObj | null {
  const nul = raw.indexOf(0);
  if (nul < 0) return null;
  const head = raw.toString("utf8", 0, nul);
  const m = /^(commit|tree|blob|tag) (\d+)$/.exec(head);
  if (!m || Number(m[2]) !== raw.length - nul - 1) return null;
  return { type: m[1] as GitObj["type"], data: raw.subarray(nul + 1) };
}

function parseIdx(buf: Buffer, hashLen: number): { shas: Buffer; offsets: number[] } | null {
  if (buf.length < 8 + 256 * 4 || buf.readUInt32BE(0) !== 0xff744f63 || buf.readUInt32BE(4) !== 2) return null;
  const n = buf.readUInt32BE(8 + 255 * 4);
  const shaAt = 8 + 256 * 4;
  const crcAt = shaAt + n * hashLen;
  const offAt = crcAt + n * 4;
  if (offAt + n * 4 > buf.length) return null;
  const offsets: number[] = [];
  let large = 0;
  for (let i = 0; i < n; i++) {
    const v = buf.readUInt32BE(offAt + i * 4);
    if (v & 0x80000000) large++;
    offsets.push(v);
  }
  const largeAt = offAt + n * 4;
  if (large && largeAt + large * 8 > buf.length) return null;
  for (let i = 0; i < n; i++) {
    const v = offsets[i];
    if (v & 0x80000000) {
      const idx = v & 0x7fffffff;
      if (idx >= large) return null;
      const hi = buf.readUInt32BE(largeAt + idx * 8);
      const lo = buf.readUInt32BE(largeAt + idx * 8 + 4);
      if (hi !== 0) return null;
      offsets[i] = lo;
    }
  }
  return { shas: buf.subarray(shaAt, shaAt + n * hashLen), offsets };
}

function offsetOf(shas: Buffer, offsets: number[], sha: string, hashLen: number): number | null {
  const want = Buffer.from(sha, "hex");
  if (want.length !== hashLen) return null;
  let lo = 0;
  let hi = offsets.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    const cmp = want.compare(shas, mid * hashLen, mid * hashLen + hashLen);
    if (cmp === 0) return offsets[mid];
    if (cmp < 0) hi = mid - 1;
    else lo = mid + 1;
  }
  return null;
}

function packHeader(pack: Buffer, offset: number, hashLen: number): { type: GitObj["type"] | "ofs" | "ref"; size: number; dataAt: number; distance: number; base: string } | null {
  if (offset + 1 >= pack.length) return null;
  let p = offset;
  let c = pack[p++];
  const typeN = (c >> 4) & 7;
  let size = c & 15;
  let shift = 4;
  while (c & 0x80) {
    if (p >= pack.length || shift > 32) return null;
    c = pack[p++];
    size |= (c & 0x7f) << shift;
    shift += 7;
  }
  let distance = 0;
  let base = "";
  if (typeN === 6) {
    if (p >= pack.length) return null;
    c = pack[p++];
    distance = c & 0x7f;
    while (c & 0x80) {
      if (p >= pack.length) return null;
      c = pack[p++];
      distance = ((distance + 1) << 7) | (c & 0x7f);
    }
  } else if (typeN === 7) {
    if (p + hashLen > pack.length) return null;
    base = pack.subarray(p, p + hashLen).toString("hex");
    p += hashLen;
  }
  const type = typeN === 1 ? "commit" : typeN === 2 ? "tree" : typeN === 3 ? "blob" : typeN === 4 ? "tag" : typeN === 6 ? "ofs" : typeN === 7 ? "ref" : null;
  if (!type) return null;
  return { type, size, dataAt: p, distance, base };
}

function applyDelta(base: Buffer, delta: Buffer): Buffer | null {
  let p = 0;
  const readSize = (): number | null => {
    let size = 0;
    let shift = 0;
    while (p < delta.length) {
      const c = delta[p++];
      size |= (c & 127) << shift;
      if (!(c & 128)) return size;
      shift += 7;
      if (shift > 32) return null;
    }
    return null;
  };
  const srcSize = readSize();
  const dstSize = readSize();
  if (srcSize === null || dstSize === null || srcSize !== base.length || dstSize > HISTORY_MAX_BLOB_BYTES) return null;
  const out = Buffer.alloc(dstSize);
  let o = 0;
  while (p < delta.length) {
    const cmd = delta[p++];
    if (cmd === 0) return null;
    if (cmd & 0x80) {
      let off = 0;
      let size = 0;
      for (let i = 0; i < 4; i++) if (cmd & (1 << i)) off |= delta[p++] << (8 * i);
      for (let i = 0; i < 3; i++) if (cmd & (1 << (4 + i))) size |= delta[p++] << (8 * i);
      if (size === 0) size = 0x10000;
      if (off + size > base.length || o + size > dstSize) return null;
      base.copy(out, o, off, off + size);
      o += size;
    } else {
      if (p + cmd > delta.length || o + cmd > dstSize) return null;
      delta.copy(out, o, p, p + cmd);
      p += cmd;
      o += cmd;
    }
  }
  return o === dstSize ? out : null;
}

function commitTree(obj: GitObj): string | null {
  const m = /^tree ([0-9a-f]{64}|[0-9a-f]{40})/m.exec(obj.data.toString("utf8"));
  return m ? m[1] : null;
}

function commitParents(obj: GitObj): string[] {
  const out: string[] = [];
  for (const line of obj.data.toString("utf8").split("\n")) {
    if (line.startsWith("parent ")) out.push(line.slice(7).trim());
    else if (line === "") break;
  }
  return out;
}

function parseTree(data: Buffer, hashLen: number): { mode: string; name: string; sha: string }[] | null {
  const out: { mode: string; name: string; sha: string }[] = [];
  let p = 0;
  while (p < data.length) {
    const sp = data.indexOf(0x20, p);
    const nul = data.indexOf(0, sp + 1);
    if (sp < 0 || nul < 0 || nul + 1 + hashLen > data.length) return null;
    out.push({ mode: data.toString("utf8", p, sp), name: data.toString("utf8", sp + 1, nul), sha: data.subarray(nul + 1, nul + 1 + hashLen).toString("hex") });
    p = nul + 1 + hashLen;
  }
  return out;
}

export interface HistoryScan {
  files: ScannedFile[];
  commitsSeen: number;
  blobsRead: number;
  capped: boolean;
  notes: string[];
}

/** Blobs reachable from HEAD, newest commits first, skipping paths still identical in the worktree. */
export function scanHistory(scanRoot: string, ignore: string[], current: Map<string, string>, deadline: number): HistoryScan {
  const located = locateGit(scanRoot);
  const empty: HistoryScan = { files: [], commitsSeen: 0, blobsRead: 0, capped: false, notes: [] };
  if (!located) {
    empty.notes.push("No git directory was found, so git history was not read.");
    return empty;
  }
  const store = new Store(located.gitDir);
  const head = resolveRevision(located.gitDir, "HEAD");
  if (!head) {
    empty.notes.push("HEAD did not resolve, so git history was not read.");
    empty.notes.push(...store.notes);
    return empty;
  }
  const ignored = makeIgnoreMatcher(ignore);
  const scanRel = relative(located.workTree, resolve(scanRoot)).split("\\").join("/");
  const prefix = scanRel && scanRel !== "." ? scanRel.replace(/\/$/, "") + "/" : "";
  if (prefix.startsWith("..")) {
    empty.notes.push("Scan root is outside the git work tree, so history was not read.");
    return empty;
  }
  const seenCommits = new Set<string>();
  const seenBlobs = new Set<string>();
  const queue = [head];
  const files: ScannedFile[] = [];
  let capped = false;
  while (queue.length) {
    if (Date.now() > deadline) {
      capped = true;
      break;
    }
    const sha = queue.shift()!;
    if (seenCommits.has(sha)) continue;
    seenCommits.add(sha);
    const commit = store.get(sha);
    if (!commit || commit.type !== "commit") continue;
    for (const parent of commitParents(commit)) if (!seenCommits.has(parent)) queue.push(parent);
    const tree = commitTree(commit);
    if (!tree) continue;
    const blobs = flatten(store, tree, "");
    for (const [path, blobSha] of blobs) {
      if (prefix && !path.startsWith(prefix)) continue;
      const rel = prefix ? path.slice(prefix.length) : path;
      if (!rel || ignored(rel)) continue;
      const key = `${rel}\0${blobSha}`;
      if (seenBlobs.has(key)) continue;
      seenBlobs.add(key);
      if (current.get(rel) !== undefined && createHash(store.hashAlgo).update(`blob ${Buffer.byteLength(current.get(rel)!)}\0${current.get(rel)}`).digest("hex") === blobSha) continue;
      const obj = store.get(blobSha);
      if (!obj || obj.type !== "blob" || obj.data.length > HISTORY_MAX_BLOB_BYTES) continue;
      if (obj.data.subarray(0, 8192).includes(0)) continue;
      const text = obj.data.toString("utf8");
      files.push(virtualFile(`git-history/${sha.slice(0, 12)}/${rel}`, text));
    }
  }
  const notes = [...store.notes];
  if (capped) notes.push(`Git history stopped at the time limit after ${seenCommits.size} commit(s). Older commits were not read.`);
  else notes.push(`Git history read ${seenCommits.size} commit(s) from HEAD without running git (${store.hashAlgo}). Objects still identical to the worktree were not reported twice.`);
  return { files, commitsSeen: seenCommits.size, blobsRead: files.length, capped, notes };
}

function flatten(store: Store, sha: string, prefix: string): Map<string, string> {
  const out = new Map<string, string>();
  const obj = store.get(sha);
  if (!obj || obj.type !== "tree") return out;
  const entries = parseTree(obj.data, store.hashLen);
  if (!entries) return out;
  for (const e of entries) {
    if (e.name === ".." || e.name.includes("\\") || e.name.includes("/")) continue;
    const path = prefix ? `${prefix}/${e.name}` : e.name;
    if (e.mode === "40000" || e.mode === "040000") {
      for (const [k, v] of flatten(store, e.sha, path)) out.set(k, v);
    } else if (e.mode === "100644" || e.mode === "100755") out.set(path, e.sha);
  }
  return out;
}

export function blobSha1(text: string): string {
  return blobHash(text, "sha1");
}

export function blobHash(text: string, algo: "sha1" | "sha256"): string {
  return createHash(algo).update(`blob ${Buffer.byteLength(text)}\0${text}`).digest("hex");
}

/** Blob ids in `rev`, keyed by path. `note` is set when the revision cannot be read. */
export function revisionTree(scanRoot: string, rev: string): { blobs: Map<string, string> | null; note: string; algo: "sha1" | "sha256" } {
  const located = locateGit(scanRoot);
  if (!located) return { blobs: null, note: `No git directory; --since ${rev} cannot be resolved.`, algo: "sha1" };
  const sha = resolveRevision(located.gitDir, rev);
  if (!sha) return { blobs: null, note: `Revision "${rev}" did not resolve.`, algo: "sha1" };
  const store = new Store(located.gitDir);
  const commit = store.get(sha);
  const tree = commit && commit.type === "commit" ? commitTree(commit) : null;
  if (!tree) return { blobs: null, note: `Revision "${rev}" has no tree.`, algo: "sha1" };
  return { blobs: flatten(store, tree, ""), note: "", algo: store.hashAlgo };
}

export function stagedBlobs(scanRoot: string): { path: string; text: string }[] | null {
  const located = locateGit(scanRoot);
  if (!located) return null;
  const idx = join(located.gitDir, "index");
  let buf: Buffer;
  try {
    const st = lstatSync(idx);
    if (!st.isFile() || st.isSymbolicLink() || st.size > 32 * 1024 * 1024) return null;
    buf = readFileSync(idx);
  } catch {
    return null;
  }
  const entries = parseGitIndexEntries(buf);
  if (!entries) return null;
  const store = new Store(located.gitDir);
  const out: { path: string; text: string }[] = [];
  for (const e of entries) {
    if (e.path.includes("..")) continue;
    const obj = store.get(e.sha);
    if (!obj || obj.type !== "blob" || obj.data.length > HISTORY_MAX_BLOB_BYTES) continue;
    if (obj.data.subarray(0, 8192).includes(0)) continue;
    out.push({ path: e.path, text: obj.data.toString("utf8") });
  }
  return out;
}

function virtualFile(path: string, text: string): ScannedFile {
  const name = basename(path).toLowerCase();
  return { path, name, ext: extname(name), text, lines: text.split(/\r\n|\n|\r/) };
}

export function insideWorkTree(scanRoot: string, abs: string): boolean {
  const located = locateGit(scanRoot);
  if (!located) return false;
  const rel = relative(located.workTree, abs);
  return rel === "" || (!rel.startsWith("..") && !isAbsolute(rel));
}
