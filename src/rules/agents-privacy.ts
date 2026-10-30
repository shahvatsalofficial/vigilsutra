import type { Rule } from "../types.js";
import { isCode, lineRule } from "./util.js";

const ag = { version: "1.0.0", category: "ai-agents", agent: "AgentShield" };
const pv = { version: "1.0.0", category: "privacy", agent: "PrivacyLens" };
const pr = { version: "1.0.0", category: "process", agent: "Prime" };

const AGENT_FILE = (p: string): boolean =>
  /(^|\/)(agents\.md|claude\.md|gemini\.md|\.cursorrules|copilot-instructions\.md|skill\.md|\.windsurfrules)$/i.test(p) ||
  /(^|\/)\.cursor\/rules\//i.test(p) ||
  /(^|\/)\.claude\/(?:agents|commands)\//i.test(p);

export const agentPrivacyRules: Rule[] = [
  {
    ...ag,
    id: "VS-AGENT-001",
    title: "Instruction file tries to override agent safety or scope",
    severity: "medium",
    confidence: "low",
    status: "potential",
    cwe: ["CWE-1427"],
    description: "An agent instruction file contains phrases typical of prompt injection (ignore previous instructions, disable safety, exfiltrate). Repositories are untrusted input to any AI agent that reads them.",
    remediation: "Review the file. Remove instructions that widen tool permissions or bypass user approval. Keep agent instructions to project conventions only.",
    falsePositives: "Security documentation that quotes such phrases as examples, including this scanner's own docs.",
    verification: "A human reviewer confirms the wording is benign or removes it.",
    applies: (f) => AGENT_FILE(f.path),
    check: (f) =>
      lineRule(f, /ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions|disregard\s+(?:the\s+)?(?:system|safety)|disable\s+(?:all\s+)?safety|(?:proceed|continue|run|execute|act|do\s+(?:it|so|this))\s+without\s+(?:asking|confirmation|approval|permission)|send\s+.{0,40}\b(?:to|via)\s+https?:\/\/|exfiltrat/i, { filter: (_m, line) => !/(?:do not|don't|never|must not|should not)/i.test(line) })
  },
  {
    ...ag,
    id: "VS-AGENT-002",
    title: "Agent configuration disables permission prompts",
    severity: "high",
    confidence: "medium",
    status: "potential",
    cwe: ["CWE-250"],
    description: "A committed agent configuration or script bypasses human approval for tool use (for example, a skip-permissions flag), which lets injected instructions run commands unattended.",
    remediation: "Remove the bypass from shared config. Use an explicit allowlist of safe commands and keep approval for writes and network access.",
    falsePositives: "Throw-away sandboxes with no credentials and no network.",
    verification: "Setting removed; agent prompts for privileged actions again.",
    applies: (f) => /(^|\/)\.claude\/settings(\.local)?\.json$/.test(f.path) || /\.(sh|ps1|cmd|bat|json|ya?ml|md)$/.test(f.name),
    check: (f) => lineRule(f, /--dangerously-skip-permissions|["']?bypassPermissions["']?|--yolo\b|--dangerously-bypass-approvals-and-sandbox/)
  },
  {
    ...ag,
    id: "VS-AGENT-003",
    title: "MCP server launched via unpinned remote package",
    severity: "low",
    confidence: "medium",
    status: "potential",
    cwe: ["CWE-829"],
    description: "An MCP server entry runs `npx -y` or `uvx` without a pinned version, so each launch executes whatever the registry currently serves with the agent's privileges.",
    remediation: "Pin an exact version (`pkg@1.2.3`), review the package, and run servers with least privilege.",
    falsePositives: "Local, vetted packages already pinned through a lockfile.",
    verification: "Command pins an exact version or points to a reviewed local path.",
    applies: (f) => f.ext === ".json" && (/mcp/i.test(f.path) || /mcp/i.test(f.text)),
    check: (f) =>
      lineRule(f, /["']command["']\s*:\s*["'](?:npx|uvx|pipx)["']/, {
        filter: (_m, line) => {
          // Look at this line and the next few for a version pin such as pkg@1.2.3.
          const i = f.lines.indexOf(line);
          const window = f.lines.slice(i, i + 5).join(" ");
          return !/["'][^"'\s]+@\d[^"'\s]*["']/.test(window);
        }
      })
  },
  {
    ...pv,
    id: "VS-PRIV-001",
    title: "Possible personal data or credential written to logs",
    severity: "medium",
    confidence: "low",
    status: "potential",
    cwe: ["CWE-532"],
    description: "A logging call references a variable named like a password, token, SSN, email or card number. Logs are commonly retained, shipped to third parties and broadly readable.",
    remediation: "Log stable identifiers instead of values, mask sensitive fields, and add a redaction layer to the logger.",
    falsePositives: "Log messages that only mention the word (for example 'password reset sent').",
    verification: "Logged payload no longer contains the field; a test asserts redaction.",
    applies: isCode,
    check: (f) =>
      lineRule(f, /\b(?:console\.(?:log|info|debug|warn|error)|logger\.\w+|logging\.\w+|print)\s*\([^)]*\b(?:password|passwd|secret|token|ssn|credit_?card|card_?number|aadhaar)\b(?!["'`]\s*[,)])/i, {
        skipComments: true,
        filter: (_m, line) => !/["'`][^"'`]*\b(?:password|token|secret)\b[^"'`]*["'`]\s*\)\s*;?\s*$/.test(line)
      })
  },
  {
    ...pv,
    id: "VS-PRIV-002",
    title: "Third-party analytics or tracking SDK referenced",
    severity: "info",
    confidence: "medium",
    status: "informational",
    description: "A known analytics or advertising tracker is referenced. This is a privacy review prompt, not a defect: it may need consent handling and disclosure.",
    remediation: "Confirm purpose, lawful basis and consent flow with your privacy owner; disclose the vendor; configure IP anonymisation and retention where offered.",
    falsePositives: "Self-hosted analytics with no third-party transfer.",
    verification: "Data-flow inventory lists the vendor, data sent and retention.",
    applies: (f) => isCode(f) || f.ext === ".html" || f.name === "package.json",
    check: (f) => lineRule(f, /google-analytics\.com|googletagmanager\.com|\bgtag\s*\(|segment\.com\/analytics|["']@segment\/analytics|mixpanel|amplitude\.com|connect\.facebook\.net|fbq\s*\(|hotjar\.com/i, { skipComments: true })
  }
];

export const processRules: Rule[] = [
  {
    ...pr,
    id: "VS-PROC-001",
    title: "No security policy file found",
    severity: "info",
    confidence: "high",
    status: "informational",
    description: "No SECURITY.md was found, so reporters have no documented way to disclose vulnerabilities privately.",
    remediation: "Add SECURITY.md with a private contact or GitHub private vulnerability reporting link and a response expectation.",
    falsePositives: "Policy kept in an org-level `.github` repository.",
    verification: "SECURITY.md exists at the repository root, `.github/` or `docs/`.",
    applies: () => false,
    check: () => []
  }
];
