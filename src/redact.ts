/** Replace `[start,end)` of `text` with a fixed marker. Never reveals length or prefix. */
export function redactSpan(text: string, span?: [number, number]): string {
  if (!span) return text;
  return text.slice(0, span[0]) + "[REDACTED]" + text.slice(span[1]);
}

/** Collapse whitespace and cap length so excerpts stay small and diff-stable. */
export function tidy(excerpt: string, max = 200): string {
  const t = excerpt.replace(/\s+/g, " ").trim();
  return t.length > max ? t.slice(0, max) + "…" : t;
}

/** Defence in depth: scrub well-known token shapes that survive in any excerpt. */
const TOKEN_SHAPES: RegExp[] = [
  /AKIA[0-9A-Z]{16}/g,
  /gh[pousr]_[A-Za-z0-9]{30,}/g,
  /github_pat_[A-Za-z0-9_]{30,}/g,
  /xox[baprs]-[A-Za-z0-9-]{10,}/g,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*/g
];

export function scrubTokens(s: string): string {
  let out = s;
  for (const re of TOKEN_SHAPES) out = out.replace(re, "[REDACTED]");
  return out;
}
