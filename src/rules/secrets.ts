import type { Rule } from "../types.js";
import { isPlaceholder, lineRule } from "./util.js";

const base = {
  version: "1.0.0",
  category: "secrets",
  agent: "SecretWatch",
  cwe: ["CWE-798"],
  verification: "Re-run `vigilsutra audit` after removing the value; then confirm the credential was rotated at the issuer and review git history for earlier exposure.",
  remediation:
    "Treat the credential as compromised: revoke or rotate it at the issuer first, then remove it from the repository and load it from an environment variable or secret manager. Deleting it from the latest commit does not remove it from git history."
};

export const secretRules: Rule[] = [
  {
    ...base,
    id: "VS-SECRET-001",
    title: "AWS access key ID in source",
    severity: "high",
    confidence: "high",
    status: "confirmed",
    description: "A string matching the AWS access key ID format (AKIA + 16 characters) is committed. The match proves the format, not that the key is live.",
    falsePositives: "AWS documentation example keys and deliberately fake test values. Rotate anyway if unsure.",
    applies: () => true,
    check: (f) => lineRule(f, /\b(AKIA[0-9A-Z]{16})\b/, { secretGroup: 1, filter: (m) => !/EXAMPLE/.test(m[1]) })
  },
  {
    ...base,
    id: "VS-SECRET-002",
    title: "Private key material committed",
    severity: "critical",
    confidence: "high",
    status: "confirmed",
    cwe: ["CWE-321", "CWE-798"],
    description: "A PEM private key header is present, which means key material is stored in the repository.",
    falsePositives: "Documentation that quotes only the header line, or intentionally public test fixtures. Check that the body follows the header.",
    applies: () => true,
    check: (f) => {
      const hits = lineRule(f, /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----/);
      return hits.map((h) => ({ ...h, excerpt: "-----BEGIN PRIVATE KEY----- [REDACTED]", secretSpan: undefined }));
    }
  },
  {
    ...base,
    id: "VS-SECRET-003",
    title: "GitHub token in source",
    severity: "high",
    confidence: "high",
    status: "confirmed",
    description: "A string matching a GitHub personal access or app token format is committed. The match proves the format, not that the token is still valid.",
    falsePositives: "Revoked tokens and obviously fake test strings.",
    applies: () => true,
    check: (f) => lineRule(f, /\b((?:gh[pousr]_[A-Za-z0-9]{36,})|(?:github_pat_[A-Za-z0-9_]{50,}))\b/, { secretGroup: 1 })
  },
  {
    ...base,
    id: "VS-SECRET-004",
    title: "Hardcoded credential assigned to a secret-named variable",
    severity: "medium",
    confidence: "medium",
    status: "potential",
    description: "A variable or key named like a password, secret, token or API key is assigned a non-placeholder string literal.",
    falsePositives: "Test data, example config, i18n labels. Values that look like placeholders, environment lookups or templates are skipped.",
    applies: (f) => !/\.(md|txt|lock)$/.test(f.name),
    check: (f) =>
      lineRule(f, /(?:pass(?:word|wd)?|secret|api[_-]?key|auth[_-]?token|access[_-]?token|private[_-]?key|client[_-]?secret)["']?\s*[:=]\s*["']([^"'\s]{8,})["']/i, {
        skipComments: true,
        secretGroup: 1,
        filter: (m) => !isPlaceholder(m[1])
      })
  },
  {
    ...base,
    id: "VS-SECRET-005",
    title: "Slack token in source",
    severity: "high",
    confidence: "high",
    status: "confirmed",
    description: "A string matching a Slack token format (xox?-…) is committed.",
    falsePositives: "Revoked or fake tokens in tests.",
    applies: () => true,
    check: (f) => lineRule(f, /\b(xox[baprs]-[A-Za-z0-9-]{10,})\b/, { secretGroup: 1 })
  },
  {
    ...base,
    id: "VS-SECRET-006",
    title: "Environment file present in scanned tree",
    severity: "medium",
    confidence: "medium",
    status: "potential",
    cwe: ["CWE-312", "CWE-798"],
    description: "A `.env`-style file exists in the scanned tree. If it is tracked by git it exposes whatever it contains. File contents are not echoed.",
    falsePositives: "Files that are git-ignored and never committed. This scanner does not read git state in v0.1, so it cannot tell.",
    applies: (f) => /^\.env(\..+)?$/.test(f.name) && !/\.(example|sample|template)$/.test(f.name),
    check: (f) => [{ line: 1, excerpt: "(file contents not shown)" }]
  }
];
