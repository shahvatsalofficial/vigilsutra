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
    applies: (f) => !/\.(md|txt|lock)$/.test(f.name) && !/(^|\/)(i18n|locales?|lang|translations?)\//i.test(f.path),
    check: (f) =>
      lineRule(f, /(?:pass(?:word|wd)?|secret|api[_-]?key|auth[_-]?token|access[_-]?token|private[_-]?key|client[_-]?secret)["']?\s*[:=]\s*["']([^"'\s]{8,})["']/i, {
        skipComments: true,
        secretGroup: 1,
        // Skip placeholders and variable references such as '$password' used in templates or SQL text.
        // A real credential contains ASCII letters or digits; UI labels in other scripts do not.
        filter: (m) => !isPlaceholder(m[1]) && !/^\$\{?\w+\}?$/.test(m[1]) && /[A-Za-z0-9]/.test(m[1])
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
    title: "Tracked environment file with a secret value",
    severity: "medium",
    confidence: "medium",
    status: "potential",
    cwe: ["CWE-312", "CWE-798"],
    description: "A `.env` file (not an example, sample, or template) contains a secret-named variable with a non-placeholder value. File contents are not echoed. When a git index is present, environment files that are not listed in it are not read. When there is no usable git index, the file is still reviewed.",
    falsePositives: "Placeholder values and non-secret settings. `.env.example`, `.env.sample`, and `.env.template` are not reported. A local `.env` that git does not track is not a finding.",
    applies: (f) => /^\.env(\..+)?$/.test(f.name) && !/\.(example|sample|template)$/.test(f.name),
    check: (f) => {
      const idx = f.lines.findIndex((l) => {
        const m = /^\s*(?:export\s+)?([A-Za-z_][\w.]*)\s*=\s*["']?([^"'#\s]+)/.exec(l);
        return !!m && /pass|secret|token|key|credential|private|auth/i.test(m[1]) && !isPlaceholder(m[2]) && !/^<.*>$/.test(m[2]);
      });
      return idx >= 0 ? [{ line: idx + 1, excerpt: "(file contents not shown)" }] : [];
    }
  },
  {
    ...base,
    id: "VS-SECRET-007",
    title: "JSON Web Token in source",
    severity: "medium",
    confidence: "medium",
    status: "potential",
    description: "A string with the three-part JWT compact shape (header.payload.signature) is committed. The match proves the shape, not that the token is still accepted.",
    falsePositives: "Documentation samples and tokens that were already revoked. Public, non-sensitive sample tokens still look the same.",
    applies: () => true,
    check: (f) => lineRule(f, /\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/, { secretGroup: 1, filter: (m) => !/example|placeholder/i.test(m[1]) })
  },
  {
    ...base,
    id: "VS-SECRET-008",
    title: "npm access token in source",
    severity: "high",
    confidence: "high",
    status: "confirmed",
    description: "A string matching an npm access token (npm_ plus 36 or more token characters) is committed.",
    falsePositives: "Revoked tokens and values that only share the npm_ prefix.",
    applies: () => true,
    check: (f) => lineRule(f, /\b(npm_[A-Za-z0-9]{36,})\b/, { secretGroup: 1 })
  },
  {
    ...base,
    id: "VS-SECRET-009",
    title: "Stripe secret key in source",
    severity: "high",
    confidence: "high",
    status: "confirmed",
    description: "A string matching a Stripe secret or restricted key (sk_live_, sk_test_, rk_live_, rk_test_) is committed.",
    falsePositives: "Revoked keys. Publishable keys (pk_) are not matched.",
    applies: () => true,
    check: (f) => lineRule(f, /\b((?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,})\b/, { secretGroup: 1 })
  },
  {
    ...base,
    id: "VS-SECRET-010",
    title: "Google API key in source",
    severity: "high",
    confidence: "medium",
    status: "potential",
    description: "A string matching a Google API key (AIza plus 35 characters) is committed. The match proves the shape, not which API it can call.",
    falsePositives: "Keys restricted to a public client and already-rotated keys. Restrict or rotate if the repository was shared.",
    applies: () => true,
    check: (f) => lineRule(f, /\b(AIza[0-9A-Za-z_-]{35})\b/, { secretGroup: 1 })
  },
  {
    ...base,
    id: "VS-SECRET-011",
    title: "Azure storage account key in source",
    severity: "high",
    confidence: "high",
    status: "confirmed",
    description: "An Azure Storage connection string contains an AccountKey value.",
    falsePositives: "Documentation that shows the AccountKey name with a placeholder shorter than 40 characters.",
    applies: () => true,
    check: (f) => lineRule(f, /AccountKey=([A-Za-z0-9+/]{40,}={0,2})/, { secretGroup: 1 })
  },
  {
    ...base,
    id: "VS-SECRET-012",
    title: "GitLab personal access token in source",
    severity: "high",
    confidence: "high",
    status: "confirmed",
    description: "A string matching a GitLab personal access token (glpat-) is committed.",
    falsePositives: "Revoked tokens.",
    applies: () => true,
    check: (f) => lineRule(f, /\b(glpat-[A-Za-z0-9_-]{20,})\b/, { secretGroup: 1 })
  }
];
