/** The candidate within two edits of `input`, if there is one. */
export function closest(input: string, candidates: string[]): string | undefined {
  const distance = (a: string, b: string): number => {
    let row = Array.from({ length: b.length + 1 }, (_v, i) => i);
    for (let i = 1; i <= a.length; i++) {
      const next = [i];
      for (let j = 1; j <= b.length; j++) next[j] = Math.min(next[j - 1] + 1, row[j] + 1, row[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
      row = next;
    }
    return row[b.length];
  };
  // Long input cannot be a typo of a short word, and skipping it bounds the work.
  if (input.length > 40) return undefined;
  const [best] = candidates.map((c) => [distance(input, c), c] as const).sort((a, b) => a[0] - b[0]);
  return best && best[0] <= 2 ? best[1] : undefined;
}
