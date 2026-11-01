#!/usr/bin/env bash
# Runs VigilSutra, Gitleaks and Semgrep over the same public repositories (Linux CI only).
# Output: out/vigilsutra, out/gitleaks, out/semgrep, out/versions.txt
set -euo pipefail
OUT="${1:-out}"
WORK="${TMPDIR:-/tmp}/vigilsutra-bench"
mkdir -p "$OUT/vigilsutra" "$OUT/gitleaks" "$OUT/semgrep"

GL=8.30.1
curl -sSfL -o /tmp/gl.tgz "https://github.com/gitleaks/gitleaks/releases/download/v${GL}/gitleaks_${GL}_linux_x64.tar.gz"
curl -sSfL -o /tmp/gl.sums "https://github.com/gitleaks/gitleaks/releases/download/v${GL}/gitleaks_${GL}_checksums.txt"
(cd /tmp && grep "gitleaks_${GL}_linux_x64.tar.gz" gl.sums | sed 's#gitleaks_#gl#; s#  gl#  gl#' >/dev/null; want=$(grep "gitleaks_${GL}_linux_x64.tar.gz" gl.sums | cut -d' ' -f1); got=$(sha256sum gl.tgz | cut -d' ' -f1); test "$want" = "$got")
mkdir -p /tmp/glbin && tar -xzf /tmp/gl.tgz -C /tmp/glbin gitleaks
python3 -m pip install --quiet "semgrep==1.183.0"

node benchmarks/run.mjs "$OUT/vigilsutra"
for d in "$WORK"/*/; do
  n=$(basename "$d")
  /tmp/glbin/gitleaks dir "$d" --no-banner --exit-code 0 --redact --report-format json --report-path "$OUT/gitleaks/$n.json" >/dev/null 2>&1 || true
  (cd "$d" && semgrep scan --config p/security-audit --metrics off --quiet --json -o "$GITHUB_WORKSPACE/$OUT/semgrep/$n.json" . >/dev/null 2>&1) || echo "semgrep failed on $n" >> "$OUT/semgrep-errors.txt"
done
{ echo "gitleaks $GL"; semgrep --version | sed 's/^/semgrep /'; node -v | sed 's/^/node /'; uname -a; } > "$OUT/versions.txt"
