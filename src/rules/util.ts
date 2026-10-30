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
export const isK8s = (f: ScannedFile): boolean => isYaml(f) && /^\s*apiVersion:/m.test(f.text) && /^\s*kind:\s*(Pod|Deployment|StatefulSet|DaemonSet|Job|CronJob|ReplicaSet)\b/m.test(f.text);

/** True for a line that is only a comment in the common syntaxes we scan. */
export function isCommentLine(line: string): boolean {
  return /^\s*(\/\/|#|\*|\/\*|<!--)/.test(line);
}

/** Values that are clearly placeholders, examples or templating. */
export function isPlaceholder(value: string): boolean {
  const v = value.trim();
  return (
    v.length < 8 ||
    /^(x+|\*+|\.+|<.*>|\$\{.*\}|\{\{.*\}\}|%.*%|your[-_ ]|example|changeme|change[-_]me|placeholder|dummy|sample|test|todo|password|secret|none|null|undefined|process\.env|os\.environ|env\()/i.test(v) ||
    /(^|[^a-z])(example|placeholder|dummy|changeme|xxxx)/i.test(v)
  );
}

export function lineRule(file: ScannedFile, re: RegExp, opts: { skipComments?: boolean; filter?: (m: RegExpExecArray, line: string) => boolean; secretGroup?: number } = {}): Hit[] {
  const hits: Hit[] = [];
  const g = new RegExp(re.source, re.flags.includes("g") ? re.flags : re.flags + "g");
  file.lines.forEach((line, i) => {
    if (line.length > 2000) return;
    if (opts.skipComments && isCommentLine(line)) return;
    g.lastIndex = 0;
    const m = g.exec(line);
    if (!m) return;
    if (opts.filter && !opts.filter(m, line)) return;
    const hit: Hit = { line: i + 1, excerpt: line };
    if (opts.secretGroup !== undefined) {
      const val = m[opts.secretGroup];
      const start = line.indexOf(val, m.index);
      hit.secretSpan = [start, start + val.length];
    }
    hits.push(hit);
  });
  return hits;
}
