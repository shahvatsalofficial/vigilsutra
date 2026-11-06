import type { Hit, ScannedFile } from "../types.js";

export const CODE_EXT = new Set([".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".py"]);
export const JS_EXT = new Set([".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"]);

export const isCode = (f: ScannedFile): boolean => CODE_EXT.has(f.ext);
export const isJs = (f: ScannedFile): boolean => JS_EXT.has(f.ext);
export const isPy = (f: ScannedFile): boolean => f.ext === ".py";
export const isWorkflow = (f: ScannedFile): boolean => /^\.github\/workflows\/[^/]+\.ya?ml$/.test(f.path);
export const isDockerfile = (f: ScannedFile): boolean => /^dockerfile(\..+)?$/.test(f.name) || f.name.endsWith(".dockerfile");
export const isYaml = (f: ScannedFile): boolean => f.ext === ".yaml" || f.ext === ".yml";
export const isTerraform = (f: ScannedFile): boolean => f.ext === ".tf";
export const isK8s = (f: ScannedFile): boolean => isYaml(f) && /^[ \t]*apiVersion:/m.test(f.text) && /^[ \t]*kind:[ \t]*(Pod|Deployment|StatefulSet|DaemonSet|Job|CronJob|ReplicaSet)\b/m.test(f.text);

/** True for a line that is only a comment in the common syntaxes we scan. */
export function isCommentLine(line: string): boolean {
  return /^\s*(\/\/|#|\*|\/\*|<!--)/.test(line);
}

/** Values that are clearly placeholders, examples or templating. */
export function isPlaceholder(value: string): boolean {
  const v = value.trim();
  return (
    v.length < 8 ||
    /^\[?redacted\]?$/i.test(v) ||
    /^(x+|\*+|\.+|<.*>|\$\{.*\}|\{\{.*\}\}|%.*%|your[-_ ]|example|changeme|change[-_]me|placeholder|dummy|sample|test|todo|password|secret|none|null|undefined|process\.env|os\.environ|env\()/i.test(v) ||
    /(^|[^a-z])(example|placeholder|dummy|changeme|xxxx)/i.test(v)
  );
}

export function lineRule(file: ScannedFile, re: RegExp, opts: { skipComments?: boolean; filter?: (m: RegExpExecArray, line: string, lineNo: number) => boolean; secretGroup?: number } = {}): Hit[] {
  const hits: Hit[] = [];
  const g = new RegExp(re.source, re.flags.includes("g") ? re.flags : re.flags + "g");
  file.lines.forEach((line, i) => {
    // Long lines are scanned in overlapping windows so a token past 2,000 characters is still seen.
    // The excerpt is the window, not the whole line.
    const parts = line.length > 2000 ? windows(line, 2000, 1900) : [{ text: line }];
    for (const part of parts) {
      if (opts.skipComments && isCommentLine(part.text)) continue;
      g.lastIndex = 0;
      const m = g.exec(part.text);
      if (!m) continue;
      if (opts.filter && !opts.filter(m, part.text, i + 1)) continue;
      const hit: Hit = { line: i + 1, excerpt: part.text };
      if (opts.secretGroup !== undefined) {
        const val = m[opts.secretGroup];
        const start = part.text.indexOf(val, m.index);
        hit.secretSpan = [start, start + val.length];
      }
      hits.push(hit);
      break;
    }
  });
  return hits;
}

function windows(line: string, size: number, step: number): { text: string }[] {
  const out: { text: string }[] = [];
  for (let i = 0; i < line.length; i += step) {
    out.push({ text: line.slice(i, i + size) });
    if (i + size >= line.length) break;
  }
  return out;
}

/** True when index `idx` of `line` is inside a single-, double- or backtick-quoted string. */
export function insideString(line: string, idx: number): boolean {
  let quote = "";
  for (let i = 0; i < idx; i++) {
    const c = line[i];
    if (quote) {
      if (c === "\\") i++;
      else if (c === quote) quote = "";
    } else if (c === '"' || c === "'" || c === "`") quote = c;
  }
  return quote !== "";
}

/** Line with the contents of string literals removed, to test identifiers only. */
export function stripStrings(line: string): string {
  return line.replace(/"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|`(?:[^`\\]|\\.)*`/g, '""');
}

/** Looks back up to `n` lines (inclusive of the hit line) for a pattern. */
export function lookBack(f: ScannedFile, line: number, n: number, re: RegExp): boolean {
  for (let i = Math.max(0, line - 1 - n); i <= line - 1; i++) if (re.test(f.lines[i] ?? "")) return true;
  return false;
}

const TEST_PATH =
  /(^|\/)(tests?|__tests__|specs?|testdata|test_data|fixtures?|e2e|cypress|examples?|_archived|samples?|vendor|third[_-]?party|mocks?)(\/|$)|\.(test|spec)\.[cm]?[jt]sx?$|(^|\/)test_[^/]+\.py$|_test\.(go|py)$|\.min\.js$/i;

/** Paths where a matching construct is usually a test, demo, archived example or vendored code. */
export const isTestPath = (p: string): boolean => TEST_PATH.test(p);
