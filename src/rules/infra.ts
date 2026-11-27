import type { Hit, Rule, ScannedFile } from "../types.js";
import { isDockerfile, isK8s, isTerraform, isWorkflow, isYaml, lineRule, lookBack, enclosingBlock } from "./util.js";

const wf = { version: "1.0.0", category: "cicd", agent: "PipelineGuard" };
const dk = { version: "1.0.0", category: "containers", agent: "ContainerGuard" };
const k8 = { version: "1.0.0", category: "containers", agent: "ContainerGuard" };
const iac = { version: "1.0.0", category: "iac", agent: "InfraGuard" };

const isCompose = (f: ScannedFile): boolean => isYaml(f) && /^(?:docker-)?compose(?:[.-].*)?\.ya?ml$/.test(f.name);
const isRbac = (f: ScannedFile): boolean => isYaml(f) && /^[ \t]*kind:[ \t]*(?:Cluster)?Role[ \t]*$/m.test(f.text);

/** The key that owns a YAML list line: the line itself, or the nearest key above its `- item` lines. */
function listKey(f: ScannedFile, lineNo: number): string {
  for (let i = lineNo - 1; i >= 0; i--) {
    const key = /^\s*(?:-\s+)?([A-Za-z_]+):/.exec(f.lines[i]);
    if (key) return key[1];
    if (!/^\s*(?:-|#|$)/.test(f.lines[i])) break;
  }
  return "";
}

const isDbConfig = (f: ScannedFile): boolean => isYaml(f) || isDockerfile(f) || /\.(?:env|conf|cfg|ini|properties|sh)$|^\.env/.test(f.name);

export const infraRules: Rule[] = [
  {
    ...iac,
    id: "VS-DB-001",
    title: "Database accepts connections without a password",
    severity: "high",
    confidence: "high",
    status: "potential",
    cwe: ["CWE-306"],
    description: "A setting lets a database accept logins with no password (PostgreSQL `trust`, or an allowed empty MySQL or MariaDB password).",
    remediation: "Require a password from a secret store and use `scram-sha-256` for PostgreSQL.",
    falsePositives: "Throw-away databases in local development or CI that no other host can reach.",
    verification: "A connection without a password is refused.",
    applies: isDbConfig,
    check: (f) => lineRule(f, /\bPOSTGRES_HOST_AUTH_METHOD["']?\s*[:=]\s*["']?trust\b|\b(?:MYSQL|MARIADB)?_?ALLOW_EMPTY(?:_ROOT)?_PASSWORD["']?\s*[:=]\s*["']?(?:yes|true|1)\b/i, { skipComments: true })
  },
  {
    ...iac,
    id: "VS-DB-002",
    title: "Database or search engine security switched off",
    severity: "high",
    confidence: "medium",
    status: "potential",
    cwe: ["CWE-306"],
    description: "Redis protected mode, Elasticsearch or OpenSearch security, or MongoDB authorization is disabled.",
    remediation: "Enable authentication and bind the service to a private network.",
    falsePositives: "Local development setups that no other host can reach.",
    verification: "An unauthenticated request is refused.",
    applies: isDbConfig,
    check: (f) => lineRule(f, /^\s*protected-mode\s+no\b|\bxpack\.security\.enabled["']?\s*[:=]\s*["']?false\b|\bplugins\.security\.disabled["']?\s*[:=]\s*["']?true\b|^\s*authorization:\s*["']?disabled\b/, { skipComments: true })
  },
  {
    ...iac,
    id: "VS-IAC-004",
    title: "Database or storage exposed publicly",
    severity: "high",
    confidence: "high",
    status: "potential",
    cwe: ["CWE-284"],
    description: "A Terraform setting makes a database publicly accessible, or turns off a block on public storage access.",
    remediation: "Keep databases in private networks and leave public access blocks enabled.",
    falsePositives: "Buckets or databases that are public by documented design.",
    verification: "The plan shows public access disabled.",
    applies: isTerraform,
    check: (f) => lineRule(f, /^\s*(?:publicly_accessible|allow_blob_public_access|allow_nested_items_to_be_public)\s*=\s*true\b|^\s*(?:block_public_acls|block_public_policy|ignore_public_acls|restrict_public_buckets)\s*=\s*false\b/)
  },
  {
    ...iac,
    id: "VS-IAC-005",
    title: "Access granted to everyone",
    severity: "high",
    confidence: "medium",
    status: "potential",
    cwe: ["CWE-732"],
    description: "A policy grants access to `*`, `allUsers` or `allAuthenticatedUsers`.",
    remediation: "Name the accounts, roles or service principals that need access, or add a restricting condition.",
    falsePositives: "Public website objects, and statements narrowed by a condition. Check the condition.",
    verification: "The grant names specific principals.",
    applies: (f) => isTerraform(f) || f.ext === ".json" || isYaml(f),
    check: (f) =>
      lineRule(f, /["'](?:allUsers|allAuthenticatedUsers)["']|["']?Principal["']?\s*[:=]\s*(?:\{\s*["']?AWS["']?\s*[:=]\s*)?["']\*["']/, {
        skipComments: true,
        // A Deny statement for everyone is a guardrail.
        filter: (_m, _line, lineNo) => !/\b[Ee]ffect["']?\s*[:=]\s*["']Deny["']/.test(enclosingBlock(f, lineNo).body)
      })
  },
  {
    ...k8,
    id: "VS-K8S-004",
    title: "Pod mounts a host path",
    severity: "medium",
    confidence: "high",
    status: "potential",
    cwe: ["CWE-668"],
    description: "A `hostPath` volume exposes files of the node to the pod. A writable or sensitive path lets a compromised container take over the node.",
    remediation: "Use a persistent volume, ConfigMap or emptyDir. If a node agent needs the path, mount it read-only and as narrowly as possible.",
    falsePositives: "Node agents such as log collectors that must read one specific path.",
    verification: "No `hostPath` volume remains, or the exception is documented and read-only.",
    applies: isK8s,
    check: (f) => lineRule(f, /^\s*(?:-\s+)?hostPath:\s*(?:\{|$)/)
  },
  {
    ...k8,
    id: "VS-K8S-005",
    title: "Container adds a dangerous Linux capability",
    severity: "high",
    confidence: "medium",
    status: "potential",
    cwe: ["CWE-250"],
    description: "Adding `ALL`, `SYS_ADMIN`, `SYS_MODULE`, `SYS_PTRACE` or `NET_ADMIN` gives the container powers close to root on the host.",
    remediation: "Drop all capabilities and add only a narrow one the workload is shown to need.",
    falsePositives: "Network and storage agents that need the capability.",
    verification: "The capability is gone from `add` or `cap_add` and the workload still runs.",
    applies: (f) => isK8s(f) || isCompose(f),
    check: (f) =>
      lineRule(f, /\b(?:ALL|SYS_ADMIN|SYS_MODULE|SYS_PTRACE|NET_ADMIN)\b/, {
        skipComments: true,
        filter: (_m, line, lineNo) => {
          const inline = /\b(add|cap_add|drop|cap_drop):/.exec(line);
          return ["add", "cap_add"].includes(inline ? inline[1] : listKey(f, lineNo));
        }
      })
  },
  {
    ...k8,
    id: "VS-K8S-006",
    title: "RBAC role grants a wildcard",
    severity: "high",
    confidence: "high",
    status: "potential",
    cwe: ["CWE-269"],
    description: "A Role or ClusterRole lists `*` as a verb or resource, which grants far more than a workload needs.",
    remediation: "List the exact verbs and resources, and prefer a namespaced Role.",
    falsePositives: "Cluster administration roles that are bound only to operators.",
    verification: "No `*` remains in `verbs` or `resources`.",
    applies: isRbac,
    check: (f) =>
      lineRule(f, /["']\*["']/, {
        skipComments: true,
        filter: (_m, line, lineNo) => {
          const inline = /\b(verbs|resources):/.exec(line);
          return ["verbs", "resources"].includes(inline ? inline[1] : listKey(f, lineNo));
        }
      })
  },
  {
    ...k8,
    id: "VS-COMPOSE-001",
    title: "Compose service has host-level access",
    severity: "high",
    confidence: "high",
    status: "confirmed",
    cwe: ["CWE-250"],
    description: "`privileged: true`, host network or PID mode, or a mounted Docker socket lets the service control the host.",
    remediation: "Remove the setting. If a tool needs the Docker API, put a filtering proxy in front of the socket.",
    falsePositives: "Local development tools that manage containers by design.",
    verification: "The setting is gone and the service still starts.",
    applies: isCompose,
    check: (f) => lineRule(f, /^\s*privileged:\s*true\b|^\s*(?:network_mode|pid):\s*["']?host\b|^\s*-\s*["']?\/var\/run\/docker\.sock:/)
  },
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
      lineRule(f, /^\s*(?:-\s*)?uses:\s*([^\s#]+)/, {
        filter: (m) => {
          const ref = m[1].replace(/^['"]|['"]$/g, "");
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
      if (!/^[ \t]*pull_request_target[ \t]*:|\bon:[ \t]*\[?[^\n]*pull_request_target/m.test(f.text)) return [];
      return lineRule(f, /ref:\s*["']?(?:\$\{\{\s*github\.(?:event\.pull_request\.head\.(?:sha|ref)|head_ref)\s*\}\}|refs\/pull\/\$\{\{[^}]*\}\}\/(?:merge|head))/);
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
    title: "Untrusted GitHub context interpolated into a script step",
    severity: "high",
    confidence: "medium",
    status: "potential",
    cwe: ["CWE-78", "CWE-77"],
    description: "Attacker-controlled fields (PR title/body, branch name, issue or comment text) are expanded directly inside a `run:` or `actions/github-script` script. A crafted value can inject commands.",
    remediation: "Pass the value through an environment variable (`env: TITLE: ${{ github.event.pull_request.title }}`) and reference it as `\"$TITLE\"` in the script.",
    falsePositives: "Fields restricted by GitHub to safe characters. Only matches inside run blocks are reported when detectable; verify context.",
    verification: "The expression no longer appears inside a `run:` body.",
    applies: isWorkflow,
    check: (f) => {
      const hits: Hit[] = [];
      let inRun = false;
      let runIndent = 0;
      f.lines.forEach((line, i) => {
        const found = /^(\s*)(?:-\s*)?(run|script):\s*(.*)$/.exec(line);
        // `script:` is code only as an input of actions/github-script.
        const run = found && (found[2] === "run" || lookBack(f, i + 1, 8, /uses:\s*["']?actions\/github-script@/)) ? found : null;
        const indent = line.search(/\S|$/);
        if (run) {
          inRun = true;
          runIndent = run[1].length;
          if (run[3] && !/^[|>][-+]?$/.test(run[3])) {
            if (risky(run[3])) hits.push({ line: i + 1, excerpt: line });
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
      // Images published as non-root (for example distroless ":nonroot" tags) already default to an unprivileged user.
      if (/nonroot|rootless/i.test(f.lines[last])) return [];
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
    check: (f) => lineRule(f, /\b(?:curl|wget)\b[^|\n]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b/, { skipComments: true, filter: (_m, line) => !/\becho\s+["']/.test(line) })
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
    description: "A Terraform rule allows 0.0.0.0/0, ::/0 or an Azure `*`/`Internet` source. Open ingress to administrative or database ports exposes them to internet scanning and attack.",
    remediation: "Restrict CIDR ranges to known addresses or place the service behind a load balancer, VPN or bastion.",
    falsePositives: "Intentionally public web ports (80/443) and egress rules. Review the port and direction.",
    verification: "Ingress CIDRs are restricted or documented as intentionally public.",
    applies: isTerraform,
    check: (f) =>
      lineRule(f, /["'](?:0\.0\.0\.0\/0|::\/0)["']|\bsource_address_prefix(?:es)?\s*=\s*\[?\s*["'](?:\*|Internet)["']/, {
        skipComments: true,
        filter: (_m, line, lineNo) => {
          // Routes, egress rules and deny rules are not internet-facing ingress. Only the enclosing blocks count.
          if (/destination_(?:ipv6_)?(?:cidr_block|address)|\begress\b|egress_/.test(line)) return false;
          const { openers, body } = enclosingBlock(f, lineNo);
          if (openers.some((o) => /^\s*(?:route|egress|deny)\b/.test(o) || /egress_/.test(o))) return false;
          return !/\btype\s*=\s*["']egress["']|\bdirection\s*=\s*["'](?:egress|outbound)["']|\baccess\s*=\s*["']deny["']|^\s*deny\s*\{/im.test(body);
        }
      })
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
    check: (f) =>
      lineRule(f, /["']\*["']/, {
        filter: (_m, line, lineNo) => {
          let isAction = /\b(?:Action|actions)["']?\s*[:=]\s*(?:\[[^\]]*)?["']\*["']/i.test(line);
          // A `*` on its own line inside a multi-line action list.
          for (let i = lineNo - 2; !isAction && !line.includes("=") && i >= 0 && !f.lines[i].includes("]"); i--) {
            if (/\b(?:Action|actions)["']?\s*[:=]\s*\[/i.test(f.lines[i])) isAction = true;
            else if (/[:=]\s*\[/.test(f.lines[i])) break;
          }
          if (!isAction) return false;
          // A Deny statement with a wildcard is a guardrail, not a grant.
          const deny = /\b[Ee]ffect["']?\s*[:=]\s*["']Deny["']/;
          const { body } = enclosingBlock(f, lineNo);
          return !(body ? deny.test(body) : lookBack(f, lineNo, 4, deny));
        }
      })
  }
];

function risky(s: string): boolean {
  return /\$\{\{\s*github\.(?:event\.(?:pull_request\.(?:title|body|head\.ref|head\.label)|issue\.(?:title|body)|comment\.body|review\.body|head_commit\.message|commits\[[^\]]*\]\.message)|head_ref)\s*\}\}/.test(s);
}
