import type { Hit, Rule, ScannedFile } from "../types.js";
import { isDockerfile, isK8s, isTerraform, isWorkflow, isYaml, lineRule, lookBack, enclosingBlock, isCompositeAction } from "./util.js";

const workflowOrAction = (f: ScannedFile): boolean => isWorkflow(f) || isCompositeAction(f);
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

/** True when the workflow lists one of these events as a trigger. */
const triggeredBy = (f: ScannedFile, events: string): boolean => new RegExp(`^[ \\t]*(?:-[ \\t]*)?(?:${events})[ \\t]*(?::|$)|\\bon:[ \\t]*\\[?[^\\n]*\\b(?:${events})\\b`, "m").test(f.text);

const WORKLOAD = /^[ \t]*kind:[ \t]*(?:Pod|Deployment|StatefulSet|DaemonSet|Job|CronJob|ReplicaSet)\b/m;

/** The documents of a multi-document YAML file, with the line where each starts. Templates are read as text. */
function yamlDocs(f: ScannedFile): { start: number; lines: string[]; text: string }[] {
  const starts = [0, ...f.lines.flatMap((l, i) => (/^---(?:\s|$)/.test(l) ? [i + 1] : []))];
  return starts.map((start, n) => {
    const lines = f.lines.slice(start, n + 1 < starts.length ? starts[n + 1] - 1 : f.lines.length);
    return { start, lines, text: lines.join("\n") };
  });
}

/** One hit per document that matches `kind` and lacks what `has` looks for, at the first line matching `at`. */
function perDocument(f: ScannedFile, kind: RegExp, has: RegExp, at: RegExp): Hit[] {
  return yamlDocs(f).flatMap((d) => {
    if (!kind.test(d.text) || has.test(d.text)) return [];
    const i = d.lines.findIndex((l) => at.test(l));
    return i < 0 ? [] : [{ line: d.start + i + 1, excerpt: d.lines[i] }];
  });
}

/** Keys that contain the line, nearest first, judged by indentation. */
function ancestors(f: ScannedFile, lineNo: number): string[] {
  const out: string[] = [];
  let indent = f.lines[lineNo - 1].search(/\S|$/);
  for (let i = lineNo - 2; i >= 0 && indent > 0; i--) {
    const depth = f.lines[i].search(/\S|$/);
    if (f.lines[i].trim() && depth < indent) {
      out.push(f.lines[i].trim());
      indent = depth;
    }
  }
  return out;
}

const isBinding = (f: ScannedFile): boolean => isYaml(f) && /^[ \t]*kind:[ \t]*(?:Cluster)?RoleBinding[ \t]*$/m.test(f.text);
const isCloudFormation = (f: ScannedFile): boolean => (isYaml(f) || f.ext === ".json") && /AWSTemplateFormatVersion|["']?Type["']?\s*:\s*["']?AWS::/.test(f.text);

export const infraRules: Rule[] = [
  {
    ...k8,
    id: "VS-K8S-008",
    title: "Workload image has no fixed tag",
    severity: "low",
    confidence: "high",
    status: "potential",
    cwe: ["CWE-829"],
    description: "A container image without a tag, or with `latest`, can change between deployments.",
    remediation: "Pin a version tag, and for production a digest (`image@sha256:…`).",
    falsePositives: "Local development manifests.",
    verification: "Every image names a version or digest.",
    applies: isK8s,
    check: (f) => lineRule(f, /^\s*(?:-\s+)?image:\s*["']?([^\s"'#]+)/, { filter: (m) => !m[1].includes("{{") && !m[1].includes("@sha256:") && /^[^:]*$|:latest$/.test(m[1].split("/").pop()!) })
  },
  {
    ...k8,
    id: "VS-K8S-009",
    title: "Workload does not make its filesystem read-only",
    severity: "low",
    confidence: "medium",
    status: "potential",
    cwe: ["CWE-732"],
    description: "No `readOnlyRootFilesystem: true` appears in the workload, so a compromised process can change files in the container.",
    remediation: "Add a `securityContext` with `readOnlyRootFilesystem: true` and mount writable folders explicitly.",
    falsePositives: "Applications that must write to their image. The check looks at each manifest, not each container.",
    verification: "The workload runs with a read-only root filesystem.",
    applies: isK8s,
    check: (f) => perDocument(f, WORKLOAD, /\breadOnlyRootFilesystem:\s*true\b/, /^\s*(?:-\s+)?containers\s*:/)
  },
  {
    ...k8,
    id: "VS-K8S-010",
    title: "Service account token mounted on purpose",
    severity: "low",
    confidence: "high",
    status: "potential",
    cwe: ["CWE-522"],
    description: "`automountServiceAccountToken: true` places a cluster credential in the pod.",
    remediation: "Set it to `false` unless the workload calls the Kubernetes API.",
    falsePositives: "Controllers and operators that use the API.",
    verification: "The setting is false, or the need is documented.",
    applies: (f) => isYaml(f) && /^[ \t]*apiVersion:/m.test(f.text),
    check: (f) => lineRule(f, /^\s*automountServiceAccountToken:\s*true\b/)
  },
  {
    ...k8,
    id: "VS-K8S-011",
    title: "Secret written as a plain environment value",
    severity: "medium",
    confidence: "medium",
    status: "potential",
    cwe: ["CWE-798"],
    description: "A container environment variable with a secret-like name has its value in the manifest.",
    remediation: "Use `valueFrom.secretKeyRef` or an external secret manager, and rotate the exposed value.",
    falsePositives: "Names that only point to a file or another resource.",
    verification: "The manifest references a secret and holds no value.",
    applies: isK8s,
    check: (f) =>
      lineRule(f, /^\s*value:\s*["']?([^\s"'#{]{4,})/, {
        secretGroup: 1,
        filter: (m, _line, lineNo) => /^\s*-\s+name:\s*["']?\w*(?:PASS(?:WORD|WD)?|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY)(?:_?VALUE)?["']?\s*$/i.test(f.lines[lineNo - 2] ?? "") && !/^(?:true|false|\d+|[./].*|changeme.*|example.*)$/i.test(m[1])
      })
  },
  {
    ...k8,
    id: "VS-K8S-012",
    title: "LoadBalancer service open to every address",
    severity: "low",
    confidence: "medium",
    status: "potential",
    cwe: ["CWE-284"],
    description: "A `LoadBalancer` service without `loadBalancerSourceRanges` usually accepts connections from anywhere.",
    remediation: "List the allowed ranges, or put the service behind an ingress with access control.",
    falsePositives: "Public web entry points, or ranges enforced by cloud annotations or firewalls.",
    verification: "Only the listed ranges can connect.",
    applies: (f) => isYaml(f) && /^[ \t]*type:[ \t]*LoadBalancer\b/m.test(f.text),
    check: (f) => perDocument(f, /^[ \t]*kind:[ \t]*Service[ \t]*$/m, /\bloadBalancerSourceRanges\s*:/, /^\s*type:\s*LoadBalancer\b/)
  },
  {
    ...k8,
    id: "VS-K8S-013",
    title: "Binding grants cluster-admin",
    severity: "high",
    confidence: "high",
    status: "potential",
    cwe: ["CWE-269"],
    description: "A role binding gives `cluster-admin`, which controls the whole cluster.",
    remediation: "Create a role with only the permissions the subject needs.",
    falsePositives: "Bindings for cluster operators.",
    verification: "No application account is bound to `cluster-admin`.",
    applies: isBinding,
    check: (f) => lineRule(f, /^\s*name:\s*["']?cluster-admin["']?\s*$/, { filter: (_m, _line, lineNo) => ancestors(f, lineNo).some((a) => a.startsWith("roleRef")) })
  },
  {
    ...iac,
    id: "VS-IAC-006",
    title: "CloudFormation or Bicep resource open to the internet",
    severity: "high",
    confidence: "medium",
    status: "potential",
    cwe: ["CWE-284", "CWE-732"],
    description: "A security group, network rule or storage setting allows public access.",
    remediation: "Restrict source ranges and turn public storage access off.",
    falsePositives: "Public web ports and buckets that are meant to be public.",
    verification: "The deployed resource refuses public access.",
    applies: (f) => f.ext === ".bicep" || isCloudFormation(f),
    check: (f) => {
      if (f.ext === ".bicep")
        return lineRule(f, /\ballowBlobPublicAccess\s*:\s*true\b|\bpublicAccess\s*:\s*'(?:Blob|Container)'|\bsourceAddressPrefix\s*:\s*'(?:\*|0\.0\.0\.0\/0|Internet)'/, {
          skipComments: true,
          filter: (m, _line, lineNo) => !m[0].startsWith("sourceAddressPrefix") || !/direction\s*:\s*'Outbound'|access\s*:\s*'Deny'/.test(enclosingBlock(f, lineNo).body)
        });
      return lineRule(f, /["']?Cidr(?:Ip|Ipv6)["']?\s*:\s*["']?(?:0\.0\.0\.0\/0|::\/0)|["']?AccessControl["']?\s*:\s*["']?PublicRead/, {
        skipComments: true,
        filter: (_m, _line, lineNo) => {
          if (ancestors(f, lineNo).some((a) => /Egress/.test(a))) return false;
          for (let i = lineNo - 1; i >= 0; i--) {
            const type = /Type["']?\s*:\s*["']?(AWS::\S+)/.exec(f.lines[i]);
            if (type) return !type[1].includes("Egress");
          }
          return true;
        }
      });
    }
  },
  {
    ...wf,
    id: "VS-CICD-006",
    title: "Reusable workflow receives every secret",
    severity: "medium",
    confidence: "high",
    status: "potential",
    cwe: ["CWE-250"],
    description: "`secrets: inherit` passes all repository and organisation secrets to the called workflow.",
    remediation: "Pass only the secrets the called workflow needs, by name.",
    falsePositives: "A reusable workflow in the same repository that needs most secrets.",
    verification: "No `secrets: inherit` remains and the called workflow still runs.",
    applies: isWorkflow,
    check: (f) => lineRule(f, /^\s*secrets:\s*inherit\b/)
  },
  {
    ...wf,
    id: "VS-CICD-007",
    title: "Untrusted input written to GITHUB_ENV or GITHUB_PATH",
    severity: "high",
    confidence: "medium",
    status: "potential",
    cwe: ["CWE-74"],
    description: "An event field is written to the environment or path file, so a crafted value can set variables or put a program on the path for later steps.",
    remediation: "Do not write event data to these files. Pass it through `env:` to the one step that needs it.",
    falsePositives: "Fields that GitHub limits to safe characters, such as numbers.",
    verification: "The write is removed or uses a validated value.",
    applies: workflowOrAction,
    check: (f) => lineRule(f, /\$\{\{\s*github\.(?:event\.|head_ref)[^}]*\}\}.*>>\s*["']?\$\{?GITHUB_(?:ENV|PATH)\b/, { filter: (_m, line) => !/\.(?:number|id|sha)\s*\}\}/.test(line) })
  },
  {
    ...wf,
    id: "VS-CICD-008",
    title: "Pull request workflow runs on a self-hosted runner",
    severity: "medium",
    confidence: "medium",
    status: "potential",
    cwe: ["CWE-829"],
    description: "A pull request can run its code on your own machine, which keeps state between jobs. On a public repository anyone can open one.",
    remediation: "Use hosted runners for pull requests, or ephemeral runners with approval required for outside contributors.",
    falsePositives: "Private repositories where every contributor is trusted.",
    verification: "Pull request jobs no longer select a self-hosted runner.",
    applies: isWorkflow,
    check: (f) => (triggeredBy(f, "pull_request|pull_request_target") ? lineRule(f, /^\s*(?:runs-on:.*|-\s*)\bself-hosted\b/, { skipComments: true }) : [])
  },
  {
    ...wf,
    id: "VS-CICD-009",
    title: "Privileged workflow_run downloads an artifact",
    severity: "medium",
    confidence: "medium",
    status: "potential",
    cwe: ["CWE-829", "CWE-345"],
    description: "A `workflow_run` workflow has secrets and a write token, while the artifact it downloads was built by an untrusted run.",
    remediation: "Treat the artifact as untrusted: extract it into an empty folder, validate its content, and never execute it.",
    falsePositives: "Artifacts that are only read as data and validated.",
    verification: "The artifact is validated before use, or the download is removed.",
    applies: isWorkflow,
    check: (f) => (triggeredBy(f, "workflow_run") ? lineRule(f, /uses:\s*["']?(?:actions\/download-artifact|dawidd6\/action-download-artifact)@|\.downloadArtifact\s*\(/, { skipComments: true }) : [])
  },
  {
    ...wf,
    id: "VS-CICD-010",
    title: "Privileged workflow keeps checkout credentials",
    severity: "medium",
    confidence: "medium",
    status: "potential",
    cwe: ["CWE-522"],
    description: "`actions/checkout` stores the token in the git configuration by default. In a privileged workflow, later steps can read it.",
    remediation: "Set `persist-credentials: false` on the checkout step.",
    falsePositives: "Jobs that push to the repository and run no outside code.",
    verification: "The checkout step sets `persist-credentials: false`.",
    applies: isWorkflow,
    check: (f) => {
      if (!triggeredBy(f, "pull_request_target|workflow_run")) return [];
      return lineRule(f, /uses:\s*["']?actions\/checkout@/, {
        skipComments: true,
        filter: (_m, line, lineNo) => {
          // The step ends at the next list item that is not indented deeper than this one.
          const indent = line.search(/\S/);
          for (let i = lineNo; i < f.lines.length; i++) {
            const next = f.lines[i];
            if (/^\s*persist-credentials:\s*false\b/.test(next)) return false;
            if (next.trim() && (next.search(/\S/) < indent || (next.search(/\S/) === indent && /^\s*-/.test(next)))) break;
          }
          return true;
        }
      });
    }
  },
  {
    ...wf,
    id: "VS-CICD-005",
    title: "Workflow does not limit token permissions",
    severity: "low",
    confidence: "high",
    status: "potential",
    cwe: ["CWE-250"],
    description: "The workflow declares no `permissions`, so its token gets the repository default, which may include write access.",
    remediation: "Add `permissions: contents: read` at the top level and grant more to single jobs only where needed.",
    falsePositives: "Repositories whose default token permission is already read-only.",
    verification: "The workflow declares `permissions` and still passes.",
    applies: isWorkflow,
    check: (f) => {
      if (/^[ \t]*permissions[ \t]*:/m.test(f.text)) return [];
      const at = f.lines.findIndex((l) => /^jobs[ \t]*:/.test(l));
      return at < 0 ? [] : [{ line: at + 1, excerpt: f.lines[at] }];
    }
  },
  {
    ...k8,
    id: "VS-K8S-007",
    title: "Workload sets no resource limits",
    severity: "low",
    confidence: "medium",
    status: "potential",
    cwe: ["CWE-770"],
    description: "No `limits` appear in the manifest, so one container can use all the CPU or memory of a node.",
    remediation: "Set memory and CPU requests and limits for each container.",
    falsePositives: "Clusters that apply defaults with a LimitRange. The check looks at each manifest, not each container.",
    verification: "`kubectl describe pod` shows limits.",
    applies: isK8s,
    check: (f) => perDocument(f, WORKLOAD, /\blimits[ \t]*:/, /^\s*(?:-\s+)?containers\s*:/)
  },
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
    applies: workflowOrAction,
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
    title: "Privileged workflow checks out pull-request code",
    severity: "high",
    confidence: "medium",
    status: "potential",
    cwe: ["CWE-829", "CWE-94"],
    description: "A workflow triggered by `pull_request_target` or `workflow_run` runs with repository secrets and a write token. Checking out the PR head and then running its code lets an outside contributor execute code with those privileges.",
    remediation: "Use `pull_request` for untrusted code. If `pull_request_target` is required, do not check out or execute PR-controlled content, and keep permissions minimal.",
    falsePositives: "Workflows that check out the PR head but never build, run or source it (for example, labelling only).",
    verification: "Confirm no step after the checkout executes files from the PR head, or remove the head checkout.",
    applies: isWorkflow,
    check: (f) => {
      if (!/^[ \t]*(?:pull_request_target|workflow_run)[ \t]*:|\bon:[ \t]*\[?[^\n]*(?:pull_request_target|workflow_run)/m.test(f.text)) return [];
      return lineRule(f, /ref:\s*["']?(?:\$\{\{\s*github\.(?:event\.pull_request\.head\.(?:sha|ref)|event\.workflow_run\.head_(?:sha|branch)|head_ref)\s*\}\}|refs\/pull\/\$\{\{[^}]*\}\}\/(?:merge|head))|repository:\s*["']?\$\{\{\s*github\.event\.(?:pull_request\.head|workflow_run\.head_repository)(?:\.repo)?\.full_name/);
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
    applies: workflowOrAction,
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
  return /\$\{\{\s*github\.(?:event\.(?:pull_request\.(?:title|body|head\.ref|head\.label)|issue\.(?:title|body)|comment\.body|review\.body|head_commit\.(?:message|author\.(?:name|email))|commits\[[^\]]*\]\.(?:message|author\.(?:name|email))|pull_request\.head\.repo\.default_branch|workflow_run\.(?:head_branch|head_commit\.(?:message|author\.(?:name|email)))|discussion\.(?:title|body)|pages\[[^\]]*\]\.page_name)|head_ref)\s*\}\}/.test(s);
}
