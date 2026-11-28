import type { Hit, ScannedFile } from "../types.js";

export const CODE_EXT = new Set([".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".py"]);
export const JS_EXT = new Set([".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"]);

export const isCode = (f: ScannedFile): boolean => CODE_EXT.has(f.ext);
export const isJs = (f: ScannedFile): boolean => JS_EXT.has(f.ext);
export const isPy = (f: ScannedFile): boolean => f.ext === ".py";
export const isWorkflow = (f: ScannedFile): boolean => /^\.github\/workflows\/[^/]+\.ya?ml$/.test(f.path);
/** A composite action: its steps use `uses:` and `run:` like a workflow job. */
export const isCompositeAction = (f: ScannedFile): boolean => /^action\.ya?ml$/.test(f.name) && /^\s*using:\s*["']?composite\b/m.test(f.text);
export const isDockerfile = (f: ScannedFile): boolean => /^dockerfile(\..+)?$/.test(f.name) || f.name.endsWith(".dockerfile");
export const isYaml = (f: ScannedFile): boolean => f.ext === ".yaml" || f.ext === ".yml";
export const isTerraform = (f: ScannedFile): boolean => f.ext === ".tf";
export const isK8s = (f: ScannedFile): boolean => isYaml(f) && /^[ \t]*apiVersion:/m.test(f.text) && /^[ \t]*kind:[ \t]*(Pod|Deployment|StatefulSet|DaemonSet|Job|CronJob|ReplicaSet)\b/m.test(f.text);

/** True for a line that is only a comment in the common syntaxes we scan. */
export function isCommentLine(line: string): boolean {
  return /^\s*(\/\/|#|\*|\/\*|<!--)/.test(line);
}

const FILLER = new Set("your my example change me changeme placeholder dummy sample test todo password secret none null undefined key token api here value xxx".split(" "));

/** Values that are clearly placeholders, examples or templating. */
export function isPlaceholder(value: string): boolean {
  const v = value.trim();
  return (
    v.length < 8 ||
    /^\[?redacted\]?$/i.test(v) ||
    /^(x+|\*+|\.+|<.*>|\$\{.*\}|\{\{.*\}\}|%.*%)$|^(your[-_ ]|process\.env|os\.environ|env\()/i.test(v) ||
    // Instructions in example files, such as "replace-with-a-long-random-value".
    /^(replace|insert|put|enter|set)[-_ ](with|me|your|this)(?![a-z])/i.test(v) ||
    // Only a value made entirely of filler words is a placeholder: "test-password-123" is, "password-Xk9fQ2" is not.
    // "!" is not a separator: "Password123!" is a common real password.
    v.toLowerCase().split(/[-_ .]+|\d+/).every((w) => !w || FILLER.has(w)) ||
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
    let hit: Hit | undefined;
    const secrets: string[] = [];
    const matched = new Set<number>(); // line offsets; windows overlap
    for (const [p, part] of parts.entries()) {
      if (opts.skipComments && isCommentLine(part.text)) continue;
      g.lastIndex = 0;
      // Every match is read: to count them, and so that no second secret on the line survives in an excerpt.
      for (let m = g.exec(part.text); m; m = g.exec(part.text)) {
        if (opts.secretGroup !== undefined) secrets.push(m[opts.secretGroup] ?? m[0]);
        if (!opts.filter || opts.filter(m, part.text, i + 1)) {
          hit ??= { line: i + 1, excerpt: part.text, at: m.index };
          matched.add(p * 1900 + m.index);
        }
        if (!m[0]) g.lastIndex++;
      }
    }
    if (!hit) return;
    if (matched.size > 1) hit.note = `${matched.size - 1} more match(es) on this line.`;
    hits.push(secrets.length ? { ...hit, secrets } : hit);
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

const blockCache = new WeakMap<ScannedFile, { open: number[][]; end: Map<number, number> }>();

/**
 * The `{}` blocks around a line: the opener lines, outermost first, and the text of the innermost block.
 * Braces are counted per line; comment lines are ignored.
 */
export function enclosingBlock(f: ScannedFile, line: number): { openers: string[]; body: string } {
  let b = blockCache.get(f);
  if (!b) {
    const open: number[][] = [];
    const end = new Map<number, number>();
    const stack: number[] = [];
    f.lines.forEach((text, i) => {
      open.push(stack.slice(-8));
      if (isCommentLine(text)) return;
      for (const c of text) {
        if (c === "{") stack.push(i);
        else if (c === "}" && stack.length) end.set(stack.pop()!, i);
      }
    });
    blockCache.set(f, (b = { open, end }));
  }
  const chain = b.open[line - 1] ?? [];
  const inner = chain[chain.length - 1];
  return {
    openers: chain.map((i) => f.lines[i]),
    body: inner === undefined ? "" : f.lines.slice(inner, (b.end.get(inner) ?? f.lines.length - 1) + 1).join("\n")
  };
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
