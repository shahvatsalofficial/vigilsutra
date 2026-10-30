# Rules (version 1.0.0)

Generated from the rule definitions by `node docs/gen-rules.mjs > docs/rules.md`. CWE ids are orientation only; no standards control mapping is asserted (mapping unverified).

| ID | Title | Severity | Confidence | Status | Specialist | CWE |
|---|---|---|---|---|---|---|
| VS-SECRET-001 | AWS access key ID in source | high | high | confirmed | SecretWatch | CWE-798 |
| VS-SECRET-002 | Private key material committed | critical | high | confirmed | SecretWatch | CWE-321, CWE-798 |
| VS-SECRET-003 | GitHub token in source | high | high | confirmed | SecretWatch | CWE-798 |
| VS-SECRET-004 | Hardcoded credential assigned to a secret-named variable | medium | medium | potential | SecretWatch | CWE-798 |
| VS-SECRET-005 | Slack token in source | high | high | confirmed | SecretWatch | CWE-798 |
| VS-SECRET-006 | Environment file present in scanned tree | medium | medium | potential | SecretWatch | CWE-312, CWE-798 |
| VS-CICD-001 | GitHub Action not pinned to a commit SHA | low | high | potential | PipelineGuard | CWE-829 |
| VS-CICD-002 | pull_request_target workflow checks out pull-request code | high | medium | potential | PipelineGuard | CWE-829, CWE-94 |
| VS-CICD-003 | Workflow grants write-all permissions | medium | high | confirmed | PipelineGuard | CWE-250, CWE-732 |
| VS-CICD-004 | Untrusted GitHub context interpolated into a shell step | high | medium | potential | PipelineGuard | CWE-78, CWE-77 |
| VS-DOCKER-001 | Container runs as root (no USER instruction) | medium | high | confirmed | ContainerGuard | CWE-250 |
| VS-DOCKER-002 | Base image uses :latest or no tag | low | high | confirmed | ContainerGuard | CWE-829 |
| VS-DOCKER-003 | Remote script piped into a shell during build | medium | medium | potential | ContainerGuard | CWE-494 |
| VS-K8S-001 | Kubernetes container runs privileged | high | high | confirmed | ContainerGuard | CWE-250 |
| VS-K8S-002 | Pod shares host network, PID or IPC namespace | high | high | confirmed | ContainerGuard | CWE-653 |
| VS-K8S-003 | Container allows privilege escalation or runs as root | medium | high | confirmed | ContainerGuard | CWE-250 |
| VS-IAC-001 | Security group or firewall open to the whole internet | medium | medium | potential | InfraGuard | CWE-284 |
| VS-IAC-002 | Public-read or public-write storage ACL | high | high | confirmed | InfraGuard | CWE-732 |
| VS-IAC-003 | IAM policy with wildcard action | high | medium | potential | InfraGuard | CWE-269, CWE-732 |
| VS-CODE-001 | Dynamic code execution (eval / new Function / exec) | high | medium | potential | CodeGuard | CWE-95 |
| VS-CODE-002 | Shell command built from a dynamic string | high | medium | potential | CodeGuard | CWE-78 |
| VS-CODE-003 | Insecure deserialization (pickle / unsafe YAML) | high | medium | potential | CodeGuard | CWE-502 |
| VS-CODE-004 | SQL query built with string concatenation or interpolation | high | medium | potential | CodeGuard | CWE-89 |
| VS-CODE-005 | TLS certificate verification disabled | high | high | confirmed | CodeGuard | CWE-295 |
| VS-CODE-006 | Weak hash algorithm (MD5 / SHA-1) | low | low | potential | CodeGuard | CWE-327 |
| VS-CODE-007 | Raw HTML sink (innerHTML / dangerouslySetInnerHTML) | medium | low | potential | CodeGuard | CWE-79 |
| VS-AGENT-001 | Instruction file tries to override agent safety or scope | medium | low | potential | AgentShield | CWE-1427 |
| VS-AGENT-002 | Agent configuration disables permission prompts | high | medium | potential | AgentShield | CWE-250 |
| VS-AGENT-003 | MCP server launched via unpinned remote package | low | medium | potential | AgentShield | CWE-829 |
| VS-PRIV-001 | Possible personal data or credential written to logs | medium | low | potential | PrivacyLens | CWE-532 |
| VS-PRIV-002 | Third-party analytics or tracking SDK referenced | info | medium | informational | PrivacyLens |  |
| VS-PROC-001 | No security policy file found | info | high | informational | Prime |  |

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

### VS-SECRET-006: Environment file present in scanned tree

A `.env`-style file exists in the scanned tree. If it is tracked by git it exposes whatever it contains. File contents are not echoed.

- **Fix:** Treat the credential as compromised: revoke or rotate it at the issuer first, then remove it from the repository and load it from an environment variable or secret manager. Deleting it from the latest commit does not remove it from git history.
- **Verify:** Re-run `vigilsutra audit` after removing the value; then confirm the credential was rotated at the issuer and review git history for earlier exposure.
- **False positives:** Files that are git-ignored and never committed. This scanner does not read git state in v0.1, so it cannot tell.

### VS-CICD-001: GitHub Action not pinned to a commit SHA

A third-party action is referenced by a mutable tag or branch. If the tag is moved or the publisher is compromised, the workflow runs attacker-controlled code.

- **Fix:** Pin third-party actions to a full 40-character commit SHA and keep a trailing comment with the version. Use Dependabot or Renovate to update pins.
- **Verify:** Every `uses:` line for a non-local action ends in @<40 hex>.
- **False positives:** First-party `actions/*` references are lower risk; local `./` actions and Docker digests are skipped.

### VS-CICD-002: pull_request_target workflow checks out pull-request code

A workflow triggered by `pull_request_target` runs with repository secrets and a write token. Checking out the PR head and then running its code lets an outside contributor execute code with those privileges.

- **Fix:** Use `pull_request` for untrusted code. If `pull_request_target` is required, do not check out or execute PR-controlled content, and keep permissions minimal.
- **Verify:** Confirm no step after the checkout executes files from the PR head, or remove the head checkout.
- **False positives:** Workflows that check out the PR head but never build, run or source it (for example, labelling only).

### VS-CICD-003: Workflow grants write-all permissions

`permissions: write-all` gives every job a token that can modify repository contents, packages and more.

- **Fix:** Declare `permissions: contents: read` at the top level and grant additional scopes per job only where required.
- **Verify:** No `write-all` remains and the workflow still passes.
- **False positives:** None expected; the setting is explicit.

### VS-CICD-004: Untrusted GitHub context interpolated into a shell step

Attacker-controlled fields (PR title/body, branch name, issue or comment text) are expanded directly inside a `run:` script. A crafted value can inject shell commands.

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

A Terraform rule allows 0.0.0.0/0 (or ::/0). Open ingress to administrative or database ports exposes them to internet scanning and attack.

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

### VS-CODE-001: Dynamic code execution (eval / new Function / exec)

Strings are compiled and executed as code. If any part is attacker-influenced this is remote code execution. This rule matches the call, not the data flow.

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
