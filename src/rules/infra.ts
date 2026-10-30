import type { Hit, Rule } from "../types.js";
import { isDockerfile, isK8s, isTerraform, isWorkflow, isYaml, lineRule } from "./util.js";

const wf = { version: "1.0.0", category: "cicd", agent: "PipelineGuard" };
const dk = { version: "1.0.0", category: "containers", agent: "ContainerGuard" };
const k8 = { version: "1.0.0", category: "containers", agent: "ContainerGuard" };
const iac = { version: "1.0.0", category: "iac", agent: "InfraGuard" };

export const infraRules: Rule[] = [
  {
    ...wf,
    id: "VS-CICD-001",
    title: "GitHub Action not pinned to a commit SHA",
    severity: "low",
    confidence: "high",
    status: "potential",
    cwe: ["CWE-829"],
    description: "A third-party action is referenced by a mutable tag or branch. If the tag is moved or the publisher is compromised, the workflow runs attacker-controlled code.",
    remediation: "Pin third-party actions to a full 40-character commit SHA and keep a trailing comment with the version. Use Dependabot or Renovate to update pins.",
    falsePositives: "First-party `actions/*` references are lower risk; local `./` actions and Docker digests are skipped.",
    verification: "Every `uses:` line for a non-local action ends in @<40 hex>.",
    applies: isWorkflow,
    check: (f) =>
      lineRule(f, /^\s*-?\s*uses:\s*([^\s#]+)/, {
        filter: (m) => {
          const ref = m[1];
          if (ref.startsWith("./") || ref.startsWith("docker://")) return false;
          return !/@[0-9a-f]{40}$/.test(ref);
        }
      })
  },
  {
    ...wf,
    id: "VS-CICD-002",
    title: "pull_request_target workflow checks out pull-request code",
    severity: "high",
    confidence: "medium",
    status: "potential",
    cwe: ["CWE-829", "CWE-94"],
    description: "A workflow triggered by `pull_request_target` runs with repository secrets and a write token. Checking out the PR head and then running its code lets an outside contributor execute code with those privileges.",
    remediation: "Use `pull_request` for untrusted code. If `pull_request_target` is required, do not check out or execute PR-controlled content, and keep permissions minimal.",
    falsePositives: "Workflows that check out the PR head but never build, run or source it (for example, labelling only).",
    verification: "Confirm no step after the checkout executes files from the PR head, or remove the head checkout.",
    applies: isWorkflow,
    check: (f) => {
      if (!/^\s*pull_request_target\s*:|\bon:\s*\[?[^\n]*pull_request_target/m.test(f.text)) return [];
      return lineRule(f, /ref:\s*\$\{\{\s*github\.(?:event\.pull_request\.head\.(?:sha|ref)|head_ref)\s*\}\}/);
    }
  },
  {
    ...wf,
    id: "VS-CICD-003",
    title: "Workflow grants write-all permissions",
    severity: "medium",
    confidence: "high",
    status: "confirmed",
    cwe: ["CWE-250", "CWE-732"],
    description: "`permissions: write-all` gives every job a token that can modify repository contents, packages and more.",
    remediation: "Declare `permissions: contents: read` at the top level and grant additional scopes per job only where required.",
    falsePositives: "None expected; the setting is explicit.",
    verification: "No `write-all` remains and the workflow still passes.",
    applies: isWorkflow,
    check: (f) => lineRule(f, /^\s*permissions:\s*write-all\b/)
  },
  {
    ...wf,
    id: "VS-CICD-004",
    title: "Untrusted GitHub context interpolated into a shell step",
    severity: "high",
    confidence: "medium",
    status: "potential",
    cwe: ["CWE-78", "CWE-77"],
    description: "Attacker-controlled fields (PR title/body, branch name, issue or comment text) are expanded directly inside a `run:` script. A crafted value can inject shell commands.",
    remediation: "Pass the value through an environment variable (`env: TITLE: ${{ github.event.pull_request.title }}`) and reference it as `\"$TITLE\"` in the script.",
    falsePositives: "Fields restricted by GitHub to safe characters. Only matches inside run blocks are reported when detectable; verify context.",
    verification: "The expression no longer appears inside a `run:` body.",
    applies: isWorkflow,
    check: (f) => {
      const hits: Hit[] = [];
      let inRun = false;
      let runIndent = 0;
      f.lines.forEach((line, i) => {
        const run = /^(\s*)(?:-\s*)?run:\s*(.*)$/.exec(line);
        const indent = line.search(/\S|$/);
        if (run) {
          inRun = true;
          runIndent = run[1].length;
          if (run[2] && !/^[|>][-+]?$/.test(run[2])) {
            if (risky(run[2])) hits.push({ line: i + 1, excerpt: line });
            inRun = false;
          }
          return;
        }
        if (inRun) {
          if (line.trim() && indent <= runIndent) inRun = false;
          else if (risky(line)) hits.push({ line: i + 1, excerpt: line });
        }
      });
      return hits;
    }
  },
  {
    ...dk,
    id: "VS-DOCKER-001",
    title: "Container runs as root (no USER instruction)",
    severity: "medium",
    confidence: "high",
    status: "confirmed",
    cwe: ["CWE-250"],
    description: "The Dockerfile never sets a non-root USER, so the final image runs as root by default. A compromise of the app gives root inside the container.",
    remediation: "Create an unprivileged user and add `USER <name>` before the final CMD/ENTRYPOINT.",
    falsePositives: "Images intentionally run as root for tooling or build-only stages.",
    verification: "`docker run --rm <image> id -u` returns a non-zero UID.",
    applies: isDockerfile,
    check: (f) => {
      const froms = f.lines.map((l, i) => (/^\s*FROM\s/i.test(l) ? i : -1)).filter((i) => i >= 0);
      if (!froms.length) return [];
      const last = froms[froms.length - 1];
      const user = f.lines.slice(last).find((l) => /^\s*USER\s+(?!root\b|0\b)\S+/i.test(l));
      return user ? [] : [{ line: last + 1, excerpt: f.lines[last] }];
    }
  },
  {
    ...dk,
    id: "VS-DOCKER-002",
    title: "Base image uses :latest or no tag",
    severity: "low",
    confidence: "high",
    status: "confirmed",
    cwe: ["CWE-829"],
    description: "An unpinned base image changes without notice, which breaks reproducibility and can pull in vulnerable or malicious content.",
    remediation: "Pin to a specific version and, for production, an image digest (`image@sha256:…`).",
    falsePositives: "`FROM scratch` and references to earlier build stages are skipped.",
    verification: "Every FROM line has an explicit tag or digest.",
    applies: isDockerfile,
    check: (f) => {
      const stages = new Set<string>();
      const hits: Hit[] = [];
      f.lines.forEach((line, i) => {
        const m = /^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?/i.exec(line);
        if (!m) return;
        const img = m[1];
        const ok = img.toLowerCase() === "scratch" || stages.has(img.toLowerCase()) || img.includes("@sha256:") || img.includes("$");
        if (m[2]) stages.add(m[2].toLowerCase());
        if (ok) return;
        const tag = img.split("/").pop()!.split(":")[1];
        if (!tag || tag === "latest") hits.push({ line: i + 1, excerpt: line });
      });
      return hits;
    }
  },
  {
    ...dk,
    id: "VS-DOCKER-003",
    title: "Remote script piped into a shell during build",
    severity: "medium",
    confidence: "medium",
    status: "potential",
    cwe: ["CWE-494"],
    description: "`curl|sh` or `wget|sh` executes whatever the remote server returns at build time, with no integrity check.",
    remediation: "Download to a file, verify a pinned checksum or signature, then execute. Prefer the distribution's package manager.",
    falsePositives: "Installers from a source you control and trust. Still no integrity verification.",
    verification: "No `| sh` / `| bash` remains; a checksum verification step precedes execution.",
    applies: (f) => isDockerfile(f) || f.ext === ".sh",
    check: (f) => lineRule(f, /\b(?:curl|wget)\b[^|\n]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b/, { skipComments: true })
  },
  {
    ...k8,
    id: "VS-K8S-001",
    title: "Kubernetes container runs privileged",
    severity: "high",
    confidence: "high",
    status: "confirmed",
    cwe: ["CWE-250"],
    description: "`privileged: true` gives the container nearly all host capabilities and device access, so a container escape is trivial.",
    remediation: "Remove `privileged: true`. Add only the specific capabilities needed and set `allowPrivilegeEscalation: false`.",
    falsePositives: "Node-level system agents (CNI, storage drivers) that genuinely require it; keep them isolated.",
    verification: "Manifest has no `privileged: true`; workload still starts.",
    applies: isK8s,
    check: (f) => lineRule(f, /^\s*privileged:\s*true\b/)
  },
  {
    ...k8,
    id: "VS-K8S-002",
    title: "Pod shares host network, PID or IPC namespace",
    severity: "high",
    confidence: "high",
    status: "confirmed",
    cwe: ["CWE-653"],
    description: "hostNetwork, hostPID or hostIPC removes namespace isolation between the pod and the node.",
    remediation: "Remove the host namespace flags unless the workload is a vetted node agent.",
    falsePositives: "Node-level infrastructure agents.",
    verification: "Flags removed; workload tested.",
    applies: isK8s,
    check: (f) => lineRule(f, /^\s*host(?:Network|PID|IPC):\s*true\b/)
  },
  {
    ...k8,
    id: "VS-K8S-003",
    title: "Container allows privilege escalation or runs as root",
    severity: "medium",
    confidence: "high",
    status: "confirmed",
    cwe: ["CWE-250"],
    description: "`allowPrivilegeEscalation: true`, `runAsUser: 0` or `runAsNonRoot: false` is set explicitly.",
    remediation: "Set `allowPrivilegeEscalation: false`, `runAsNonRoot: true` and a non-zero `runAsUser`.",
    falsePositives: "Images that cannot run unprivileged; document the exception.",
    verification: "securityContext shows the hardened values and the pod is Running.",
    applies: isK8s,
    check: (f) => lineRule(f, /^\s*(?:allowPrivilegeEscalation:\s*true|runAsUser:\s*0|runAsNonRoot:\s*false)\b/)
  },
  {
    ...iac,
    id: "VS-IAC-001",
    title: "Security group or firewall open to the whole internet",
    severity: "medium",
    confidence: "medium",
    status: "potential",
    cwe: ["CWE-284"],
    description: "A Terraform rule allows 0.0.0.0/0 (or ::/0). Open ingress to administrative or database ports exposes them to internet scanning and attack.",
    remediation: "Restrict CIDR ranges to known addresses or place the service behind a load balancer, VPN or bastion.",
    falsePositives: "Intentionally public web ports (80/443) and egress rules. Review the port and direction.",
    verification: "Ingress CIDRs are restricted or documented as intentionally public.",
    applies: isTerraform,
    check: (f) => lineRule(f, /["'](?:0\.0\.0\.0\/0|::\/0)["']/, { skipComments: true })
  },
  {
    ...iac,
    id: "VS-IAC-002",
    title: "Public-read or public-write storage ACL",
    severity: "high",
    confidence: "high",
    status: "confirmed",
    cwe: ["CWE-732"],
    description: "A storage bucket ACL is set to a public canned ACL, exposing objects to anyone.",
    remediation: "Use `private`, enable block-public-access, and serve public assets through a CDN with origin access control.",
    falsePositives: "Buckets deliberately serving public static assets with no sensitive content.",
    verification: "ACL is private and public access block is enabled.",
    applies: isTerraform,
    check: (f) => lineRule(f, /\bacl\s*=\s*["']public-read(?:-write)?["']/)
  },
  {
    ...iac,
    id: "VS-IAC-003",
    title: "IAM policy with wildcard action",
    severity: "high",
    confidence: "medium",
    status: "potential",
    cwe: ["CWE-269", "CWE-732"],
    description: "An IAM statement allows `*` actions, which grants administrator-level power to whoever assumes the role.",
    remediation: "List only the actions the workload needs and scope resources to specific ARNs.",
    falsePositives: "Deny statements and break-glass roles that are tightly controlled. Check Effect.",
    verification: "Wildcard replaced with an explicit action list.",
    applies: (f) => isTerraform(f) || f.ext === ".json" || isYaml(f),
    check: (f) => lineRule(f, /["']?(?:Action|actions)["']?\s*[:=]\s*(?:\[\s*)?["']\*["']/)
  }
];

function risky(s: string): boolean {
  return /\$\{\{\s*github\.(?:event\.(?:pull_request\.(?:title|body|head\.ref|head\.label)|issue\.(?:title|body)|comment\.body|review\.body|head_commit\.message|commits\[[^\]]*\]\.message)|head_ref)\s*\}\}/.test(s);
}
