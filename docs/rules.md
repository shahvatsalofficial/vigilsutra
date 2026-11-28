# Rules (version 1.10.0)

Generated from the rule definitions by `node docs/gen-rules.mjs > docs/rules.md`. CWE ids are orientation only; no standards control mapping is asserted (mapping unverified).

| ID | Title | Severity | Confidence | Status | Specialist | CWE |
|---|---|---|---|---|---|---|
| VS-SECRET-001 | AWS access key ID in source | high | high | confirmed | SecretWatch | CWE-798 |
| VS-SECRET-002 | Private key material committed | critical | high | confirmed | SecretWatch | CWE-321, CWE-798 |
| VS-SECRET-003 | GitHub token in source | high | high | confirmed | SecretWatch | CWE-798 |
| VS-SECRET-004 | Hardcoded credential assigned to a secret-named variable | medium | medium | potential | SecretWatch | CWE-798 |
| VS-SECRET-005 | Slack token in source | high | high | confirmed | SecretWatch | CWE-798 |
| VS-SECRET-006 | Tracked environment file with a secret value | medium | medium | potential | SecretWatch | CWE-312, CWE-798 |
| VS-SECRET-007 | JSON Web Token in source | medium | medium | potential | SecretWatch | CWE-798 |
| VS-SECRET-008 | npm access token in source | high | high | confirmed | SecretWatch | CWE-798 |
| VS-SECRET-009 | Stripe secret key in source | high | high | confirmed | SecretWatch | CWE-798 |
| VS-SECRET-010 | Google API key in source | high | medium | potential | SecretWatch | CWE-798 |
| VS-SECRET-011 | Azure storage account key in source | high | high | confirmed | SecretWatch | CWE-798 |
| VS-SECRET-012 | GitLab personal access token in source | high | high | confirmed | SecretWatch | CWE-798 |
| VS-CICD-006 | Reusable workflow receives every secret | medium | high | potential | PipelineGuard | CWE-250 |
| VS-CICD-007 | Untrusted input written to GITHUB_ENV or GITHUB_PATH | high | medium | potential | PipelineGuard | CWE-74 |
| VS-CICD-008 | Pull request workflow runs on a self-hosted runner | medium | medium | potential | PipelineGuard | CWE-829 |
| VS-CICD-009 | Privileged workflow_run downloads an artifact | medium | medium | potential | PipelineGuard | CWE-829, CWE-345 |
| VS-CICD-010 | Privileged workflow keeps checkout credentials | medium | medium | potential | PipelineGuard | CWE-522 |
| VS-CICD-005 | Workflow does not limit token permissions | low | high | potential | PipelineGuard | CWE-250 |
| VS-K8S-007 | Workload sets no resource limits | low | medium | potential | ContainerGuard | CWE-770 |
| VS-DB-001 | Database accepts connections without a password | high | high | potential | InfraGuard | CWE-306 |
| VS-DB-002 | Database or search engine security switched off | high | medium | potential | InfraGuard | CWE-306 |
| VS-IAC-004 | Database or storage exposed publicly | high | high | potential | InfraGuard | CWE-284 |
| VS-IAC-005 | Access granted to everyone | high | medium | potential | InfraGuard | CWE-732 |
| VS-K8S-004 | Pod mounts a host path | medium | high | potential | ContainerGuard | CWE-668 |
| VS-K8S-005 | Container adds a dangerous Linux capability | high | medium | potential | ContainerGuard | CWE-250 |
| VS-K8S-006 | RBAC role grants a wildcard | high | high | potential | ContainerGuard | CWE-269 |
| VS-COMPOSE-001 | Compose service has host-level access | high | high | confirmed | ContainerGuard | CWE-250 |
| VS-CICD-001 | GitHub Action not pinned to a commit SHA | low | high | potential | PipelineGuard | CWE-829 |
| VS-CICD-002 | Privileged workflow checks out pull-request code | high | medium | potential | PipelineGuard | CWE-829, CWE-94 |
| VS-CICD-003 | Workflow grants write-all permissions | medium | high | confirmed | PipelineGuard | CWE-250, CWE-732 |
| VS-CICD-004 | Untrusted GitHub context interpolated into a script step | high | medium | potential | PipelineGuard | CWE-78, CWE-77 |
| VS-DOCKER-001 | Container runs as root (no USER instruction) | medium | high | confirmed | ContainerGuard | CWE-250 |
| VS-DOCKER-002 | Base image uses :latest or no tag | low | high | confirmed | ContainerGuard | CWE-829 |
| VS-DOCKER-003 | Remote script piped into a shell during build | medium | medium | potential | ContainerGuard | CWE-494 |
| VS-K8S-001 | Kubernetes container runs privileged | high | high | confirmed | ContainerGuard | CWE-250 |
| VS-K8S-002 | Pod shares host network, PID or IPC namespace | high | high | confirmed | ContainerGuard | CWE-653 |
| VS-K8S-003 | Container allows privilege escalation or runs as root | medium | high | confirmed | ContainerGuard | CWE-250 |
| VS-IAC-001 | Security group or firewall open to the whole internet | medium | medium | potential | InfraGuard | CWE-284 |
| VS-IAC-002 | Public-read or public-write storage ACL | high | high | confirmed | InfraGuard | CWE-732 |
| VS-IAC-003 | IAM policy with wildcard action | high | medium | potential | InfraGuard | CWE-269, CWE-732 |
| VS-CODE-013 | Request data reaches a shell or SQL call (Go, Java, Kotlin, PHP, Ruby, C#) | high | medium | potential | CodeGuard | CWE-78, CWE-89 |
| VS-CODE-001 | Dynamic code execution (eval / new Function / exec) | high | medium | potential | CodeGuard | CWE-95 |
| VS-CODE-002 | Shell command built from a dynamic string | high | medium | potential | CodeGuard | CWE-78 |
| VS-CODE-003 | Insecure deserialization (pickle / unsafe YAML) | high | medium | potential | CodeGuard | CWE-502 |
| VS-CODE-004 | SQL query built with string concatenation or interpolation | high | medium | potential | CodeGuard | CWE-89 |
| VS-CODE-005 | TLS certificate verification disabled | high | high | confirmed | CodeGuard | CWE-295 |
| VS-CODE-006 | Weak hash algorithm (MD5 / SHA-1) | low | low | potential | CodeGuard | CWE-327 |
| VS-CODE-007 | Raw HTML sink (innerHTML / dangerouslySetInnerHTML) | medium | low | potential | CodeGuard | CWE-79 |
| VS-CODE-008 | Request data used as a database query (NoSQL injection) | high | medium | potential | CodeGuard | CWE-943 |
| VS-CODE-009 | Request data used as a file path (path traversal) | high | medium | potential | CodeGuard | CWE-22 |
| VS-CODE-010 | Request data used as an outbound URL (SSRF) | high | medium | potential | CodeGuard | CWE-918 |
| VS-CODE-011 | Redirect target taken from the request (open redirect) | medium | medium | potential | CodeGuard | CWE-601 |
| VS-CODE-012 | Session cookie protection switched off | medium | medium | potential | CodeGuard | CWE-1004, CWE-614 |
| VS-AGENT-004 | Hidden Unicode characters in code or agent instructions | medium | high | potential | AgentShield | CWE-1007 |
| VS-AGENT-001 | Instruction file tries to override agent safety or scope | medium | low | potential | AgentShield | CWE-1427 |
| VS-AGENT-002 | Agent configuration disables permission prompts | high | medium | potential | AgentShield | CWE-250 |
| VS-AGENT-003 | MCP server launched via unpinned remote package | low | medium | potential | AgentShield | CWE-829 |
| VS-PRIV-001 | Possible personal data or credential written to logs | medium | low | potential | PrivacyLens | CWE-532 |
| VS-PRIV-002 | Third-party analytics or tracking SDK referenced | info | medium | informational | PrivacyLens |  |
| VS-PROC-001 | No security policy file found | info | high | informational | Prime |  |
| VS-SUPPLY-001 | Dependency fetched over an unauthenticated URL | high | high | confirmed | SupplyWatch | CWE-829 |
| VS-SUPPLY-002 | Dependency version is a wildcard | medium | medium | potential | SupplyWatch | CWE-829 |
| VS-SUPPLY-003 | Install script downloads code | medium | medium | potential | SupplyWatch | CWE-829 |
| VS-SUPPLY-004 | Dependency version matches a recorded advisory | high | high | confirmed | SupplyWatch | CWE-1395 |

## Details

### VS-SECRET-001: AWS access key ID in source

A string matching the AWS access key ID format (AKIA + 16 characters) is committed. The match proves the format, not that the key is live.

- **Fix:** Treat the credential as compromised: revoke or rotate it at the issuer first, then remove it from the repository and load it from an environment variable or secret manager. Deleting it from the latest commit does not remove it from git history.
- **Verify:** Re-run `vigilsutra audit` after removing the value; then confirm the credential was rotated at the issuer and review git history for earlier exposure.
- **False positives:** AWS documentation example keys and deliberately fake test values. Rotate anyway if unsure.

### VS-SECRET-002: Private key material committed

A PEM private key header is present, which means key material is stored in the repository.

- **Fix:** Treat the credential as compromised: revoke or rotate it at the issuer first, then remove it from the repository and load it from an environment variable or secret manager. Deleting it from the latest commit does not remove it from git history.
- **Verify:** Re-run `vigilsutra audit` after removing the value; then confirm the credential was rotated at the issuer and review git history for earlier exposure.
- **False positives:** Documentation that quotes only the header line, or intentionally public test fixtures. Check that the body follows the header.

### VS-SECRET-003: GitHub token in source

A string matching a GitHub personal access or app token format is committed. The match proves the format, not that the token is still valid.

- **Fix:** Treat the credential as compromised: revoke or rotate it at the issuer first, then remove it from the repository and load it from an environment variable or secret manager. Deleting it from the latest commit does not remove it from git history.
- **Verify:** Re-run `vigilsutra audit` after removing the value; then confirm the credential was rotated at the issuer and review git history for earlier exposure.
- **False positives:** Revoked tokens and obviously fake test strings.

### VS-SECRET-004: Hardcoded credential assigned to a secret-named variable

A variable or key named like a password, secret, token or API key is assigned a non-placeholder string literal.

- **Fix:** Treat the credential as compromised: revoke or rotate it at the issuer first, then remove it from the repository and load it from an environment variable or secret manager. Deleting it from the latest commit does not remove it from git history.
- **Verify:** Re-run `vigilsutra audit` after removing the value; then confirm the credential was rotated at the issuer and review git history for earlier exposure.
- **False positives:** Test data, example config, i18n labels. Values that look like placeholders, environment lookups or templates are skipped.

### VS-SECRET-005: Slack token in source

A string matching a Slack token format (xox?-…) is committed.

- **Fix:** Treat the credential as compromised: revoke or rotate it at the issuer first, then remove it from the repository and load it from an environment variable or secret manager. Deleting it from the latest commit does not remove it from git history.
- **Verify:** Re-run `vigilsutra audit` after removing the value; then confirm the credential was rotated at the issuer and review git history for earlier exposure.
- **False positives:** Revoked or fake tokens in tests.

### VS-SECRET-006: Tracked environment file with a secret value

A `.env` file (not an example, sample, or template) contains a secret-named variable with a non-placeholder value. File contents are not echoed. When a git index is present, environment files that are not listed in it are not read. When there is no usable git index, the file is still reviewed.

- **Fix:** Treat the credential as compromised: revoke or rotate it at the issuer first, then remove it from the repository and load it from an environment variable or secret manager. Deleting it from the latest commit does not remove it from git history.
- **Verify:** Re-run `vigilsutra audit` after removing the value; then confirm the credential was rotated at the issuer and review git history for earlier exposure.
- **False positives:** Placeholder values and non-secret settings. `.env.example`, `.env.sample`, and `.env.template` are left to VS-SECRET-004, which reports values that look real. A local `.env` that git does not track is not a finding.

### VS-SECRET-007: JSON Web Token in source

A string with the three-part JWT compact shape (header.payload.signature) is committed. The match proves the shape, not that the token is still accepted.

- **Fix:** Treat the credential as compromised: revoke or rotate it at the issuer first, then remove it from the repository and load it from an environment variable or secret manager. Deleting it from the latest commit does not remove it from git history.
- **Verify:** Re-run `vigilsutra audit` after removing the value; then confirm the credential was rotated at the issuer and review git history for earlier exposure.
- **False positives:** Documentation samples and tokens that were already revoked. Public, non-sensitive sample tokens still look the same.

### VS-SECRET-008: npm access token in source

A string matching an npm access token (npm_ plus 36 or more token characters) is committed.

- **Fix:** Treat the credential as compromised: revoke or rotate it at the issuer first, then remove it from the repository and load it from an environment variable or secret manager. Deleting it from the latest commit does not remove it from git history.
- **Verify:** Re-run `vigilsutra audit` after removing the value; then confirm the credential was rotated at the issuer and review git history for earlier exposure.
- **False positives:** Revoked tokens and values that only share the npm_ prefix.

### VS-SECRET-009: Stripe secret key in source

A string matching a Stripe secret or restricted key (sk_live_, sk_test_, rk_live_, rk_test_) is committed.

- **Fix:** Treat the credential as compromised: revoke or rotate it at the issuer first, then remove it from the repository and load it from an environment variable or secret manager. Deleting it from the latest commit does not remove it from git history.
- **Verify:** Re-run `vigilsutra audit` after removing the value; then confirm the credential was rotated at the issuer and review git history for earlier exposure.
- **False positives:** Revoked keys. Publishable keys (pk_) are not matched.

### VS-SECRET-010: Google API key in source

A string matching a Google API key (AIza plus 35 characters) is committed. The match proves the shape, not which API it can call.

- **Fix:** Treat the credential as compromised: revoke or rotate it at the issuer first, then remove it from the repository and load it from an environment variable or secret manager. Deleting it from the latest commit does not remove it from git history.
- **Verify:** Re-run `vigilsutra audit` after removing the value; then confirm the credential was rotated at the issuer and review git history for earlier exposure.
- **False positives:** Keys restricted to a public client and already-rotated keys. Restrict or rotate if the repository was shared.

### VS-SECRET-011: Azure storage account key in source

An Azure Storage connection string contains an AccountKey value.

- **Fix:** Treat the credential as compromised: revoke or rotate it at the issuer first, then remove it from the repository and load it from an environment variable or secret manager. Deleting it from the latest commit does not remove it from git history.
- **Verify:** Re-run `vigilsutra audit` after removing the value; then confirm the credential was rotated at the issuer and review git history for earlier exposure.
- **False positives:** Documentation that shows the AccountKey name with a placeholder shorter than 40 characters.

### VS-SECRET-012: GitLab personal access token in source

A string matching a GitLab personal access token (glpat-) is committed.

- **Fix:** Treat the credential as compromised: revoke or rotate it at the issuer first, then remove it from the repository and load it from an environment variable or secret manager. Deleting it from the latest commit does not remove it from git history.
- **Verify:** Re-run `vigilsutra audit` after removing the value; then confirm the credential was rotated at the issuer and review git history for earlier exposure.
- **False positives:** Revoked tokens.

### VS-CICD-006: Reusable workflow receives every secret

`secrets: inherit` passes all repository and organisation secrets to the called workflow.

- **Fix:** Pass only the secrets the called workflow needs, by name.
- **Verify:** No `secrets: inherit` remains and the called workflow still runs.
- **False positives:** A reusable workflow in the same repository that needs most secrets.

### VS-CICD-007: Untrusted input written to GITHUB_ENV or GITHUB_PATH

An event field is written to the environment or path file, so a crafted value can set variables or put a program on the path for later steps.

- **Fix:** Do not write event data to these files. Pass it through `env:` to the one step that needs it.
- **Verify:** The write is removed or uses a validated value.
- **False positives:** Fields that GitHub limits to safe characters, such as numbers.

### VS-CICD-008: Pull request workflow runs on a self-hosted runner

A pull request can run its code on your own machine, which keeps state between jobs. On a public repository anyone can open one.

- **Fix:** Use hosted runners for pull requests, or ephemeral runners with approval required for outside contributors.
- **Verify:** Pull request jobs no longer select a self-hosted runner.
- **False positives:** Private repositories where every contributor is trusted.

### VS-CICD-009: Privileged workflow_run downloads an artifact

A `workflow_run` workflow has secrets and a write token, while the artifact it downloads was built by an untrusted run.

- **Fix:** Treat the artifact as untrusted: extract it into an empty folder, validate its content, and never execute it.
- **Verify:** The artifact is validated before use, or the download is removed.
- **False positives:** Artifacts that are only read as data and validated.

### VS-CICD-010: Privileged workflow keeps checkout credentials

`actions/checkout` stores the token in the git configuration by default. In a privileged workflow, later steps can read it.

- **Fix:** Set `persist-credentials: false` on the checkout step.
- **Verify:** The checkout step sets `persist-credentials: false`.
- **False positives:** Jobs that push to the repository and run no outside code.

### VS-CICD-005: Workflow does not limit token permissions

The workflow declares no `permissions`, so its token gets the repository default, which may include write access.

- **Fix:** Add `permissions: contents: read` at the top level and grant more to single jobs only where needed.
- **Verify:** The workflow declares `permissions` and still passes.
- **False positives:** Repositories whose default token permission is already read-only.

### VS-K8S-007: Workload sets no resource limits

No `limits` appear in the manifest, so one container can use all the CPU or memory of a node.

- **Fix:** Set memory and CPU requests and limits for each container.
- **Verify:** `kubectl describe pod` shows limits.
- **False positives:** Clusters that apply defaults with a LimitRange. The check looks at the whole file, not each container.

### VS-DB-001: Database accepts connections without a password

A setting lets a database accept logins with no password (PostgreSQL `trust`, or an allowed empty MySQL or MariaDB password).

- **Fix:** Require a password from a secret store and use `scram-sha-256` for PostgreSQL.
- **Verify:** A connection without a password is refused.
- **False positives:** Throw-away databases in local development or CI that no other host can reach.

### VS-DB-002: Database or search engine security switched off

Redis protected mode, Elasticsearch or OpenSearch security, or MongoDB authorization is disabled.

- **Fix:** Enable authentication and bind the service to a private network.
- **Verify:** An unauthenticated request is refused.
- **False positives:** Local development setups that no other host can reach.

### VS-IAC-004: Database or storage exposed publicly

A Terraform setting makes a database publicly accessible, or turns off a block on public storage access.

- **Fix:** Keep databases in private networks and leave public access blocks enabled.
- **Verify:** The plan shows public access disabled.
- **False positives:** Buckets or databases that are public by documented design.

### VS-IAC-005: Access granted to everyone

A policy grants access to `*`, `allUsers` or `allAuthenticatedUsers`.

- **Fix:** Name the accounts, roles or service principals that need access, or add a restricting condition.
- **Verify:** The grant names specific principals.
- **False positives:** Public website objects, and statements narrowed by a condition. Check the condition.

### VS-K8S-004: Pod mounts a host path

A `hostPath` volume exposes files of the node to the pod. A writable or sensitive path lets a compromised container take over the node.

- **Fix:** Use a persistent volume, ConfigMap or emptyDir. If a node agent needs the path, mount it read-only and as narrowly as possible.
- **Verify:** No `hostPath` volume remains, or the exception is documented and read-only.
- **False positives:** Node agents such as log collectors that must read one specific path.

### VS-K8S-005: Container adds a dangerous Linux capability

Adding `ALL`, `SYS_ADMIN`, `SYS_MODULE`, `SYS_PTRACE` or `NET_ADMIN` gives the container powers close to root on the host.

- **Fix:** Drop all capabilities and add only a narrow one the workload is shown to need.
- **Verify:** The capability is gone from `add` or `cap_add` and the workload still runs.
- **False positives:** Network and storage agents that need the capability.

### VS-K8S-006: RBAC role grants a wildcard

A Role or ClusterRole lists `*` as a verb or resource, which grants far more than a workload needs.

- **Fix:** List the exact verbs and resources, and prefer a namespaced Role.
- **Verify:** No `*` remains in `verbs` or `resources`.
- **False positives:** Cluster administration roles that are bound only to operators.

### VS-COMPOSE-001: Compose service has host-level access

`privileged: true`, host network or PID mode, or a mounted Docker socket lets the service control the host.

- **Fix:** Remove the setting. If a tool needs the Docker API, put a filtering proxy in front of the socket.
- **Verify:** The setting is gone and the service still starts.
- **False positives:** Local development tools that manage containers by design.

### VS-CICD-001: GitHub Action not pinned to a commit SHA

A third-party action is referenced by a mutable tag or branch. If the tag is moved or the publisher is compromised, the workflow runs attacker-controlled code.

- **Fix:** Pin third-party actions to a full 40-character commit SHA and keep a trailing comment with the version. Use Dependabot or Renovate to update pins.
- **Verify:** Every `uses:` line for a non-local action ends in @<40 hex>.
- **False positives:** First-party `actions/*` references are lower risk; local `./` actions and Docker digests are skipped.

### VS-CICD-002: Privileged workflow checks out pull-request code

A workflow triggered by `pull_request_target` or `workflow_run` runs with repository secrets and a write token. Checking out the PR head and then running its code lets an outside contributor execute code with those privileges.

- **Fix:** Use `pull_request` for untrusted code. If `pull_request_target` is required, do not check out or execute PR-controlled content, and keep permissions minimal.
- **Verify:** Confirm no step after the checkout executes files from the PR head, or remove the head checkout.
- **False positives:** Workflows that check out the PR head but never build, run or source it (for example, labelling only).

### VS-CICD-003: Workflow grants write-all permissions

`permissions: write-all` gives every job a token that can modify repository contents, packages and more.

- **Fix:** Declare `permissions: contents: read` at the top level and grant additional scopes per job only where required.
- **Verify:** No `write-all` remains and the workflow still passes.
- **False positives:** None expected; the setting is explicit.

### VS-CICD-004: Untrusted GitHub context interpolated into a script step

Attacker-controlled fields (PR title/body, branch name, issue or comment text) are expanded directly inside a `run:` or `actions/github-script` script. A crafted value can inject commands.

- **Fix:** Pass the value through an environment variable (`env: TITLE: ${{ github.event.pull_request.title }}`) and reference it as `"$TITLE"` in the script.
- **Verify:** The expression no longer appears inside a `run:` body.
- **False positives:** Fields restricted by GitHub to safe characters. Only matches inside run blocks are reported when detectable; verify context.

### VS-DOCKER-001: Container runs as root (no USER instruction)

The Dockerfile never sets a non-root USER, so the final image runs as root by default. A compromise of the app gives root inside the container.

- **Fix:** Create an unprivileged user and add `USER <name>` before the final CMD/ENTRYPOINT.
- **Verify:** `docker run --rm <image> id -u` returns a non-zero UID.
- **False positives:** Images intentionally run as root for tooling or build-only stages.

### VS-DOCKER-002: Base image uses :latest or no tag

An unpinned base image changes without notice, which breaks reproducibility and can pull in vulnerable or malicious content.

- **Fix:** Pin to a specific version and, for production, an image digest (`image@sha256:…`).
- **Verify:** Every FROM line has an explicit tag or digest.
- **False positives:** `FROM scratch` and references to earlier build stages are skipped.

### VS-DOCKER-003: Remote script piped into a shell during build

`curl|sh` or `wget|sh` executes whatever the remote server returns at build time, with no integrity check.

- **Fix:** Download to a file, verify a pinned checksum or signature, then execute. Prefer the distribution's package manager.
- **Verify:** No `| sh` / `| bash` remains; a checksum verification step precedes execution.
- **False positives:** Installers from a source you control and trust. Still no integrity verification.

### VS-K8S-001: Kubernetes container runs privileged

`privileged: true` gives the container nearly all host capabilities and device access, so a container escape is trivial.

- **Fix:** Remove `privileged: true`. Add only the specific capabilities needed and set `allowPrivilegeEscalation: false`.
- **Verify:** Manifest has no `privileged: true`; workload still starts.
- **False positives:** Node-level system agents (CNI, storage drivers) that genuinely require it; keep them isolated.

### VS-K8S-002: Pod shares host network, PID or IPC namespace

hostNetwork, hostPID or hostIPC removes namespace isolation between the pod and the node.

- **Fix:** Remove the host namespace flags unless the workload is a vetted node agent.
- **Verify:** Flags removed; workload tested.
- **False positives:** Node-level infrastructure agents.

### VS-K8S-003: Container allows privilege escalation or runs as root

`allowPrivilegeEscalation: true`, `runAsUser: 0` or `runAsNonRoot: false` is set explicitly.

- **Fix:** Set `allowPrivilegeEscalation: false`, `runAsNonRoot: true` and a non-zero `runAsUser`.
- **Verify:** securityContext shows the hardened values and the pod is Running.
- **False positives:** Images that cannot run unprivileged; document the exception.

### VS-IAC-001: Security group or firewall open to the whole internet

A Terraform rule allows 0.0.0.0/0, ::/0 or an Azure `*`/`Internet` source. Open ingress to administrative or database ports exposes them to internet scanning and attack.

- **Fix:** Restrict CIDR ranges to known addresses or place the service behind a load balancer, VPN or bastion.
- **Verify:** Ingress CIDRs are restricted or documented as intentionally public.
- **False positives:** Intentionally public web ports (80/443) and egress rules. Review the port and direction.

### VS-IAC-002: Public-read or public-write storage ACL

A storage bucket ACL is set to a public canned ACL, exposing objects to anyone.

- **Fix:** Use `private`, enable block-public-access, and serve public assets through a CDN with origin access control.
- **Verify:** ACL is private and public access block is enabled.
- **False positives:** Buckets deliberately serving public static assets with no sensitive content.

### VS-IAC-003: IAM policy with wildcard action

An IAM statement allows `*` actions, which grants administrator-level power to whoever assumes the role.

- **Fix:** List only the actions the workload needs and scope resources to specific ARNs.
- **Verify:** Wildcard replaced with an explicit action list.
- **False positives:** Deny statements and break-glass roles that are tightly controlled. Check Effect.

### VS-CODE-013: Request data reaches a shell or SQL call (Go, Java, Kotlin, PHP, Ruby, C#)

A request value is placed into a command, evaluated code or SQL text on the same line, which allows command or SQL injection.

- **Fix:** Pass arguments as a list and use parameterised queries. Never build commands or SQL from request text.
- **Verify:** Send shell and quote characters and confirm they have no effect.
- **False positives:** Values validated or escaped before this line.

### VS-CODE-001: Dynamic code execution (eval / new Function / exec)

Strings are compiled and executed as code. If any part is attacker-influenced this is remote code execution. Confidence is raised when the argument name traces to a request-like assignment in this project, including through a relative import. Object fields, dynamic imports, and function calls are not tracked.

- **Fix:** Replace with a data-driven approach (lookup table, JSON.parse, ast.literal_eval). Never pass user input to an evaluator.
- **Verify:** The call is removed or its argument is proven constant; add a test with a malicious input.
- **False positives:** Constant strings, build tooling, or sandboxed evaluators. Trace the argument to confirm.

### VS-CODE-002: Shell command built from a dynamic string

A shell is invoked with an interpolated or concatenated command string (or Python `shell=True`). Untrusted input can inject extra commands.

- **Fix:** Use an argument array without a shell: `execFile(cmd, [args])` in Node, `subprocess.run([cmd, *args])` in Python. Validate inputs against an allowlist.
- **Verify:** Command uses an argument array; a test confirms metacharacters are not interpreted.
- **False positives:** Fully constant commands. Interpolated values that are validated constants.

### VS-CODE-003: Insecure deserialization (pickle / unsafe YAML)

`pickle.load(s)` and `yaml.load` without a safe loader can instantiate arbitrary objects and execute code when fed untrusted data.

- **Fix:** Use `json`, `yaml.safe_load`, or a schema-validated format. Never unpickle data from untrusted sources.
- **Verify:** Replaced with a safe loader; tests cover malformed input.
- **False positives:** Data that is produced and consumed only by trusted, integrity-protected code paths.

### VS-CODE-004: SQL query built with string concatenation or interpolation

A SQL statement is assembled from variables instead of bound parameters, which can allow SQL injection when any value is user-controlled.

- **Fix:** Use parameterised queries or a query builder that binds values (`?`, `$1`, `%s` placeholders passed separately).
- **Verify:** Query text is a constant; values passed as parameters; test with a quote-containing input.
- **False positives:** Interpolated identifiers that come from a fixed allowlist, or constants.

### VS-CODE-005: TLS certificate verification disabled

Certificate validation is turned off, so any network attacker can impersonate the remote server.

- **Fix:** Remove the override and trust the proper CA bundle (`NODE_EXTRA_CA_CERTS`, `verify=<ca-path>`).
- **Verify:** Option removed; request to a bad-cert host now fails.
- **False positives:** Local development against a self-signed server; it must never ship to production.

### VS-CODE-006: Weak hash algorithm (MD5 / SHA-1)

MD5 and SHA-1 are broken for collision resistance and unsuitable for passwords or signatures. Use here is only a problem for security purposes.

- **Fix:** Use SHA-256+ for integrity, and Argon2id, scrypt or bcrypt for passwords.
- **Verify:** Algorithm replaced for security-relevant uses; confirm context.
- **False positives:** Non-security uses such as cache keys or legacy protocol checksums.

### VS-CODE-007: Raw HTML sink (innerHTML / dangerouslySetInnerHTML)

Assigning strings to HTML sinks can cause cross-site scripting if the content includes untrusted data.

- **Fix:** Use `textContent` or the framework's escaped bindings. If HTML is required, sanitise with a vetted library.
- **Verify:** Sink removed or input proven sanitised; test with a `<script>` payload.
- **False positives:** Constant markup or content already sanitised.

### VS-CODE-008: Request data used as a database query (NoSQL injection)

A request object is passed straight into a query, or text is built into a `$where` clause. An attacker can send operators such as `$ne` or script and change what the query matches.

- **Fix:** Pick the expected fields, check their type, and avoid `$where`.
- **Verify:** Send an object where a string is expected and confirm it is rejected.
- **False positives:** Input already validated against a schema before this line.

### VS-CODE-009: Request data used as a file path (path traversal)

A file is opened, sent or deleted using a request value, so `../` sequences can reach files outside the intended folder.

- **Fix:** Resolve the path and require it to stay inside an allowed folder, or map an id to a known file name.
- **Verify:** Request `../` and an absolute path and confirm both are refused.
- **False positives:** Values already reduced to a base name or checked against an allow list.

### VS-CODE-010: Request data used as an outbound URL (SSRF)

The server fetches a URL taken from the request, which can reach internal services and cloud metadata endpoints.

- **Fix:** Allow only known hosts, resolve and block private address ranges, and do not follow redirects to them.
- **Verify:** Request a loopback or link-local address and confirm it is refused.
- **False positives:** A value checked against an allow list before this line.

### VS-CODE-011: Redirect target taken from the request (open redirect)

The redirect destination comes from the request, so a link to this site can send people to an attacker's site.

- **Fix:** Redirect to relative paths or to an allow list of destinations.
- **Verify:** Request an external destination and confirm it is refused.
- **False positives:** A value validated as a local path before this line.

### VS-CODE-012: Session cookie protection switched off

`httpOnly` or `secure` is disabled for a cookie, which exposes it to scripts or to unencrypted connections.

- **Fix:** Set `httpOnly` and `secure` to true and choose a `sameSite` value.
- **Verify:** The Set-Cookie response header carries HttpOnly and Secure.
- **False positives:** Cookies that scripts must read, or settings used only for local development.

### VS-AGENT-004: Hidden Unicode characters in code or agent instructions

Invisible or direction-changing characters make a file read differently to a person than to a compiler or AI assistant (Trojan Source, rules-file backdoor).

- **Fix:** Delete the characters, then read the line again. Treat hidden text in an instruction file as hostile until its author explains it.
- **Verify:** Re-run `vigilsutra audit`; an editor that shows invisible characters displays none on the line.
- **False positives:** Right-to-left text that needs direction controls in a string, and test data about Unicode.

### VS-AGENT-001: Instruction file tries to override agent safety or scope

An agent instruction file contains phrases typical of prompt injection (ignore previous instructions, disable safety, exfiltrate). Repositories are untrusted input to any AI agent that reads them.

- **Fix:** Review the file. Remove instructions that widen tool permissions or bypass user approval. Keep agent instructions to project conventions only.
- **Verify:** A human reviewer confirms the wording is benign or removes it.
- **False positives:** Security documentation that quotes such phrases as examples, including this scanner's own docs.

### VS-AGENT-002: Agent configuration disables permission prompts

A committed agent configuration or script bypasses human approval for tool use (for example, a skip-permissions flag), which lets injected instructions run commands unattended.

- **Fix:** Remove the bypass from shared config. Use an explicit allowlist of safe commands and keep approval for writes and network access.
- **Verify:** Setting removed; agent prompts for privileged actions again.
- **False positives:** Throw-away sandboxes with no credentials and no network.

### VS-AGENT-003: MCP server launched via unpinned remote package

An MCP server entry runs `npx -y` or `uvx` without a pinned version, so each launch executes whatever the registry currently serves with the agent's privileges.

- **Fix:** Pin an exact version (`pkg@1.2.3`), review the package, and run servers with least privilege.
- **Verify:** Command pins an exact version or points to a reviewed local path.
- **False positives:** Local, vetted packages already pinned through a lockfile.

### VS-PRIV-001: Possible personal data or credential written to logs

A logging call references a variable named like a password, token, SSN, email or card number. Logs are commonly retained, shipped to third parties and broadly readable.

- **Fix:** Log stable identifiers instead of values, mask sensitive fields, and add a redaction layer to the logger.
- **Verify:** Logged payload no longer contains the field; a test asserts redaction.
- **False positives:** Log messages that only mention the word (for example 'password reset sent').

### VS-PRIV-002: Third-party analytics or tracking SDK referenced

A known analytics or advertising tracker is referenced. This is a privacy review prompt, not a defect: it may need consent handling and disclosure.

- **Fix:** Confirm purpose, lawful basis and consent flow with your privacy owner; disclose the vendor; configure IP anonymisation and retention where offered.
- **Verify:** Data-flow inventory lists the vendor, data sent and retention.
- **False positives:** Self-hosted analytics with no third-party transfer.

### VS-PROC-001: No security policy file found

No SECURITY.md was found, so reporters have no documented way to disclose vulnerabilities privately.

- **Fix:** Add SECURITY.md with a private contact or GitHub private vulnerability reporting link and a response expectation.
- **Verify:** SECURITY.md exists at the repository root, `.github/` or `docs/`.
- **False positives:** Policy kept in an org-level `.github` repository.

### VS-SUPPLY-001: Dependency fetched over an unauthenticated URL

A package manifest downloads a dependency with http:// or git://. Those URLs can be changed in transit. No advisory database is consulted.

- **Fix:** Pin a trusted version from the official registry over HTTPS. Review install scripts before they run.
- **Verify:** Re-run `vigilsutra audit` after the manifest change.
- **False positives:** An internal registry that is only reachable over plain HTTP on a network you trust. Prefer HTTPS anyway.

### VS-SUPPLY-002: Dependency version is a wildcard

A package.json dependency is `*`, `latest`, or empty, so a later install can resolve to a different version. This is not a vulnerability match.

- **Fix:** Pin a trusted version from the official registry over HTTPS. Review install scripts before they run.
- **Verify:** Re-run `vigilsutra audit` after the manifest change.
- **False positives:** A private tool that regenerates the lockfile in the same change. The lockfile, when present, is what the install actually uses.

### VS-SUPPLY-003: Install script downloads code

A package.json lifecycle script (preinstall, install, or postinstall) downloads or pipes remote content. The script runs on install. The remote body was not fetched.

- **Fix:** Pin a trusted version from the official registry over HTTPS. Review install scripts before they run.
- **Verify:** Re-run `vigilsutra audit` after the manifest change.
- **False positives:** A script that downloads a checksum-pinned artifact inside a build you already review.

### VS-SUPPLY-004: Dependency version matches a recorded advisory

A resolved package version falls inside a range recorded in the advisory database shipped with VigilSutra. The database is a snapshot, not a live feed, and the scan does not call the network.

- **Fix:** Upgrade to the fixed version named in the finding, then re-run the audit. If the database has no fix, remove the package or replace it.
- **Verify:** The lockfile resolves to a version outside the recorded range. Re-run `vigilsutra audit`.
- **False positives:** An advisory withdrawn after this database was built, or a version the range comparison mis-orders because it is not numeric semver.
