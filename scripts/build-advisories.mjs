import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { inflateRawSync, gzipSync } from "node:zlib";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ECO = { npm: "npm", PyPI: "pypi", Go: "golang" };
const SEV = { CRITICAL: "critical", HIGH: "high", MODERATE: "medium", MEDIUM: "medium", LOW: "low" };

const files = process.argv.slice(2);
if (!files.length) {
  process.stderr.write("usage: node scripts/build-advisories.mjs <osv.zip>...\n");
  process.exit(2);
}

const packages = new Map();
let docs = 0;
for (const file of files) {
  process.stderr.write(`reading ${file}\n`);
  const buf = readFileSync(file);
  for (const doc of zipJson(buf)) {
    docs++;
    ingest(doc);
  }
}

const out = {
  generated: new Date().toISOString().slice(0, 10),
  source: "OSV snapshots for npm, PyPI and Go. Ranges only. Not a live feed.",
  documents: docs,
  packages: Object.fromEntries([...packages.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1)))
};
const json = JSON.stringify(out);
const dir = join(dirname(fileURLToPath(import.meta.url)), "..", "advisories");
mkdirSync(dir, { recursive: true });
const dest = json.length > 4_000_000 ? join(dir, "db.json.gz") : join(dir, "db.json");
writeFileSync(dest, json.length > 4_000_000 ? gzipSync(Buffer.from(json)) : json);
process.stderr.write(`wrote ${dest} from ${docs} documents, ${packages.size} package names, ${json.length} json bytes\n`);

function ingest(doc) {
  if (!doc || typeof doc.id !== "string" || !Array.isArray(doc.affected)) return;
  for (const aff of doc.affected) {
    const eco = ECO[aff.package?.ecosystem];
    const name = aff.package?.name;
    if (!eco || typeof name !== "string" || !name) continue;
    const key = `${eco}\0${name.toLowerCase()}`;
    const list = packages.get(key) ?? [];
    const severity = severityOf(doc, aff);
    for (const range of rangesOf(aff)) {
      const row = { id: doc.id, introduced: range.introduced, severity };
      if (range.fixed) row.fixed = range.fixed;
      if (range.lastAffected) row.lastAffected = range.lastAffected;
      const sig = `${row.id}|${row.introduced}|${row.fixed ?? ""}|${row.lastAffected ?? ""}`;
      if (!list.some((x) => `${x.id}|${x.introduced}|${x.fixed ?? ""}|${x.lastAffected ?? ""}` === sig)) list.push(row);
    }
    if (list.length) packages.set(key, list);
  }
}

function severityOf(doc, aff) {
  for (const c of [doc.database_specific?.severity, aff?.database_specific?.severity, aff?.ecosystem_specific?.severity]) {
    const hit = SEV[String(c ?? "").toUpperCase()];
    if (hit) return hit;
  }
  return "medium";
}

function rangesOf(aff) {
  const out = [];
  for (const r of aff.ranges ?? []) {
    if (r.type && r.type !== "SEMVER" && r.type !== "ECOSYSTEM") continue;
    let open = null;
    for (const ev of r.events ?? []) {
      if (ev.introduced !== undefined) open = String(ev.introduced);
      else if (open !== null && ev.fixed !== undefined) {
        out.push({ introduced: open, fixed: String(ev.fixed), lastAffected: null });
        open = null;
      } else if (open !== null && ev.last_affected !== undefined) {
        out.push({ introduced: open, fixed: null, lastAffected: String(ev.last_affected) });
        open = null;
      }
    }
    if (open !== null) out.push({ introduced: open, fixed: null, lastAffected: null });
  }
  if (!out.length && Array.isArray(aff.versions)) {
    for (const v of aff.versions) {
      if (typeof v === "string" && /^\d/.test(v)) out.push({ introduced: v, fixed: null, lastAffected: v });
    }
  }
  return out.filter((r) => r.introduced !== "");
}

function* zipJson(buf) {
  let eocd = -1;
  const min = Math.max(0, buf.length - 22 - 65535);
  for (let i = buf.length - 22; i >= min; i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) throw new Error("zip has no end-of-central-directory record");
  let cdSize = buf.readUInt32LE(eocd + 12);
  let cdOffset = buf.readUInt32LE(eocd + 16);
  if (cdOffset === 0xffffffff) {
    const loc = eocd - 20;
    if (buf.readUInt32LE(loc) !== 0x07064b50) throw new Error("zip64 locator missing");
    const z64 = Number(buf.readBigUInt64LE(loc + 8));
    cdSize = Number(buf.readBigUInt64LE(z64 + 40));
    cdOffset = Number(buf.readBigUInt64LE(z64 + 48));
  }
  let p = cdOffset;
  const end = cdOffset + cdSize;
  while (p + 46 <= end && p + 46 <= buf.length) {
    if (buf.readUInt32LE(p) !== 0x02014b50) break;
    const method = buf.readUInt16LE(p + 10);
    const compSize = buf.readUInt32LE(p + 20);
    const nameLen = buf.readUInt16LE(p + 28);
    const extraLen = buf.readUInt16LE(p + 30);
    const commentLen = buf.readUInt16LE(p + 32);
    let localOff = buf.readUInt32LE(p + 42);
    const name = buf.toString("utf8", p + 46, p + 46 + nameLen);
    const extra = buf.subarray(p + 46 + nameLen, p + 46 + nameLen + extraLen);
    p += 46 + nameLen + extraLen + commentLen;
    if (localOff === 0xffffffff) localOff = zip64(extra, 0x0001);
    if (!name.endsWith(".json") || name.includes("..") || localOff == null) continue;
    if (localOff + 30 > buf.length || buf.readUInt32LE(localOff) !== 0x04034b50) continue;
    const ln = buf.readUInt16LE(localOff + 26);
    const le = buf.readUInt16LE(localOff + 28);
    const start = localOff + 30 + ln + le;
    if (start + compSize > buf.length) continue;
    const slice = buf.subarray(start, start + compSize);
    try {
      const raw = method === 0 ? slice : method === 8 ? inflateRawSync(slice) : null;
      if (raw) yield JSON.parse(raw.toString("utf8"));
    } catch {
      /* skip a bad entry */
    }
  }
}

function zip64(extra, id) {
  let i = 0;
  while (i + 4 <= extra.length) {
    const header = extra.readUInt16LE(i);
    const size = extra.readUInt16LE(i + 2);
    if (header === id && size >= 8) return Number(extra.readBigUInt64LE(i + 4));
    i += 4 + size;
  }
  return null;
}
