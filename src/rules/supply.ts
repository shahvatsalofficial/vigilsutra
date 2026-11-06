import type { Hit, Rule, ScannedFile } from "../types.js";

const b = {
  version: "1.0.0",
  category: "supply",
  agent: "SupplyWatch",
  cwe: ["CWE-829"],
    verification: "Re-run `vigilsutra audit` after the manifest change.",
    remediation: "Pin a trusted version from the official registry over HTTPS. Review install scripts before they run."
};

function hitAt(file: ScannedFile, needle: string): Hit {
  const idx = file.lines.findIndex((l) => l.includes(needle));
  return { line: idx >= 0 ? idx + 1 : 1, excerpt: idx >= 0 ? file.lines[idx] : needle };
}

export const supplyRules: Rule[] = [
  {
    ...b,
    id: "VS-SUPPLY-001",
    title: "Dependency fetched over an unauthenticated URL",
    severity: "high",
    confidence: "high",
    status: "confirmed",
    description: "A package manifest downloads a dependency with http:// or git://. Those URLs can be changed in transit. No advisory database is consulted.",
    falsePositives: "An internal registry that is only reachable over plain HTTP on a network you trust. Prefer HTTPS anyway.",
    applies: (f) => f.name === "package.json" || f.name === "requirements.txt",
    check: (f) => {
      if (f.name === "requirements.txt") {
        return f.lines.flatMap((line, i) => (/^\s*(?:-i|--index-url|--extra-index-url)\s+http:\/\//i.test(line) || /(?:git\+)?http:\/\/|git:\/\//i.test(line) ? [{ line: i + 1, excerpt: line }] : []));
      }
      return depHits(f, (ver) => /^(?:git\+)?http:\/\//i.test(ver) || /^git:\/\//i.test(ver));
    }
  },
  {
    ...b,
    id: "VS-SUPPLY-002",
    title: "Dependency version is a wildcard",
    severity: "medium",
    confidence: "medium",
    status: "potential",
    description: "A package.json dependency is `*`, `latest`, or empty, so a later install can resolve to a different version. This is not a vulnerability match.",
    falsePositives: "A private tool that regenerates the lockfile in the same change. The lockfile, when present, is what the install actually uses.",
    applies: (f) => f.name === "package.json",
    check: (f) => depHits(f, (ver) => ver === "*" || ver === "latest" || ver === "")
  },
  {
    ...b,
    id: "VS-SUPPLY-003",
    title: "Install script downloads code",
    severity: "medium",
    confidence: "medium",
    status: "potential",
    cwe: ["CWE-829"],
    description: "A package.json lifecycle script (preinstall, install, or postinstall) downloads or pipes remote content. The script runs on install. The remote body was not fetched.",
    falsePositives: "A script that downloads a checksum-pinned artifact inside a build you already review.",
    applies: (f) => f.name === "package.json",
    check: (f) => {
      let pkg: { scripts?: Record<string, unknown> };
      try {
        pkg = JSON.parse(f.text) as { scripts?: Record<string, unknown> };
      } catch {
        return [];
      }
      const hits: Hit[] = [];
      for (const key of ["preinstall", "install", "postinstall"]) {
        const script = pkg.scripts?.[key];
        if (typeof script === "string" && /\b(curl|wget|Invoke-WebRequest)\b|https?:\/\//i.test(script)) hits.push(hitAt(f, script.slice(0, 40)));
      }
      return hits;
    }
  },
  {
    ...b,
    id: "VS-SUPPLY-004",
    title: "Dependency version matches a recorded advisory",
    severity: "high",
    confidence: "high",
    status: "confirmed",
    cwe: ["CWE-1395"],
    description: "A resolved package version falls inside a range recorded in the advisory database shipped with VigilSutra. The database is a snapshot, not a live feed, and the scan does not call the network.",
    remediation: "Upgrade to the fixed version named in the finding, then re-run the audit. If the database has no fix, remove the package or replace it.",
    falsePositives: "An advisory withdrawn after this database was built, or a version the range comparison mis-orders because it is not numeric semver.",
    verification: "The lockfile resolves to a version outside the recorded range. Re-run `vigilsutra audit`.",
    applies: () => false,
    check: () => []
  }
];

function depHits(file: ScannedFile, bad: (version: string) => boolean): Hit[] {
  let pkg: { dependencies?: Record<string, unknown>; devDependencies?: Record<string, unknown>; optionalDependencies?: Record<string, unknown> };
  try {
    pkg = JSON.parse(file.text);
  } catch {
    return [];
  }
  const deps = { ...pkg.dependencies, ...pkg.devDependencies, ...pkg.optionalDependencies };
  const hits: Hit[] = [];
  for (const [name, ver] of Object.entries(deps)) {
    if (typeof ver !== "string" || !bad(ver)) continue;
    hits.push(hitAt(file, `"${name}"`));
  }
  return hits;
}
