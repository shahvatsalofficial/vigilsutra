# VigilSutra AI audit report: intentionally-insecure

- Generated: (sample)
- Tool: vigilsutra 0.1.0 (rules 1.0.0)
- Mode: local (read-only, offline)
- Detected: docker, terraform, github-actions, kubernetes

## Executive summary

16 finding(s): 0 critical, 8 high, 5 medium, 2 low, 1 info.
Confirmed by evidence: 6. Potential (needs human verification): 9.

### Top priorities

1. **VS-CICD-002** pull\_request\_target workflow checks out pull-request code at `.github/workflows/ci.yml:10`
2. **VS-CICD-004** Untrusted GitHub context interpolated into a shell step at `.github/workflows/ci.yml:11`
3. **VS-K8S-002** Pod shares host network, PID or IPC namespace at `deployment.yaml:8`
4. **VS-K8S-001** Kubernetes container runs privileged at `deployment.yaml:13`
5. **VS-IAC-002** Public-read or public-write storage ACL at `main.tf:9`

### Scope and limits

Scanned 5 files. Skipped: 0 ignored, 0 symlinks (never followed), 0 too large, 0 binary.

Assessed: secrets, cicd, containers, iac, code, ai-agents, privacy, process.

Not assessed: dependencies and advisories; git history; authentication and authorization design; runtime / cloud state; mobile apps; data-flow and taint analysis.

- Pattern-based static review of text files only; no data-flow or taint analysis.
- Source-pattern matches are reported as 'potential' unless the evidence itself is conclusive (for example a token format or an explicit unsafe setting).
- A match on a secret format shows the format, not that the credential is live. No credential was tested.
- Git history, dependencies, advisories, running systems and remote cloud state were not inspected.
- Absence of findings is not evidence of security.

## Findings

### VS-CICD-002: pull\_request\_target workflow checks out pull-request code

- Severity: **high** | Confidence: **medium** | Status: **potential**
- Location: `.github/workflows/ci.yml:10`
- Fingerprint: `11e3248dc10a2e4d5f1a7ca3436ca693` | CWE-829, CWE-94 (orientation only)
- Evidence:

  ```text
  ref: ${{ github.event.pull_request.head.sha }}
  ```

**Why it matters.** A workflow triggered by `pull_request_target` runs with repository secrets and a write token. Checking out the PR head and then running its code lets an outside contributor execute code with those privileges.

**Fix.** Use `pull_request` for untrusted code. If `pull_request_target` is required, do not check out or execute PR-controlled content, and keep permissions minimal.

**Verify.** Confirm no step after the checkout executes files from the PR head, or remove the head checkout.

**May be a false positive when.** Workflows that check out the PR head but never build, run or source it (for example, labelling only).

### VS-CICD-004: Untrusted GitHub context interpolated into a shell step

- Severity: **high** | Confidence: **medium** | Status: **potential**
- Location: `.github/workflows/ci.yml:11`
- Fingerprint: `3bcdb287dbc0be65a5784aaa62a0ac9b` | CWE-78, CWE-77 (orientation only)
- Evidence:

  ```text
  - run: echo "Title is ${{ github.event.pull_request.title }}"
  ```

**Why it matters.** Attacker-controlled fields (PR title/body, branch name, issue or comment text) are expanded directly inside a `run:` script. A crafted value can inject shell commands.

**Fix.** Pass the value through an environment variable (`env: TITLE: ${{ github.event.pull_request.title }}`) and reference it as `"$TITLE"` in the script.

**Verify.** The expression no longer appears inside a `run:` body.

**May be a false positive when.** Fields restricted by GitHub to safe characters. Only matches inside run blocks are reported when detectable; verify context.

### VS-K8S-002: Pod shares host network, PID or IPC namespace

- Severity: **high** | Confidence: **high** | Status: **confirmed**
- Location: `deployment.yaml:8`
- Fingerprint: `e8757449db9c9c28022eceed1a643272` | CWE-653 (orientation only)
- Evidence:

  ```text
  hostNetwork: true
  ```

**Why it matters.** hostNetwork, hostPID or hostIPC removes namespace isolation between the pod and the node.

**Fix.** Remove the host namespace flags unless the workload is a vetted node agent.

**Verify.** Flags removed; workload tested.

**May be a false positive when.** Node-level infrastructure agents.

### VS-K8S-001: Kubernetes container runs privileged

- Severity: **high** | Confidence: **high** | Status: **confirmed**
- Location: `deployment.yaml:13`
- Fingerprint: `872a8614818c1adfd9352829ee453c5f` | CWE-250 (orientation only)
- Evidence:

  ```text
  privileged: true
  ```

**Why it matters.** `privileged: true` gives the container nearly all host capabilities and device access, so a container escape is trivial.

**Fix.** Remove `privileged: true`. Add only the specific capabilities needed and set `allowPrivilegeEscalation: false`.

**Verify.** Manifest has no `privileged: true`; workload still starts.

**May be a false positive when.** Node-level system agents (CNI, storage drivers) that genuinely require it; keep them isolated.

### VS-IAC-002: Public-read or public-write storage ACL

- Severity: **high** | Confidence: **high** | Status: **confirmed**
- Location: `main.tf:9`
- Fingerprint: `acd7e6c2c716833b88217086f1c02364` | CWE-732 (orientation only)
- Evidence:

  ```text
  acl = "public-read"
  ```

**Why it matters.** A storage bucket ACL is set to a public canned ACL, exposing objects to anyone.

**Fix.** Use `private`, enable block-public-access, and serve public assets through a CDN with origin access control.

**Verify.** ACL is private and public access block is enabled.

**May be a false positive when.** Buckets deliberately serving public static assets with no sensitive content.

### VS-CODE-002: Shell command built from a dynamic string

- Severity: **high** | Confidence: **medium** | Status: **potential**
- Location: `server.js:5`
- Fingerprint: `5f4c07837cbbbd543925e4c2c6d365b1` | CWE-78 (orientation only)
- Evidence:

  ```text
  exec('ping -c 1 ${req.query.host}', () => res.send("ok"));
  ```

**Why it matters.** A shell is invoked with an interpolated or concatenated command string (or Python `shell=True`). Untrusted input can inject extra commands.

**Fix.** Use an argument array without a shell: `execFile(cmd, [args])` in Node, `subprocess.run([cmd, *args])` in Python. Validate inputs against an allowlist.

**Verify.** Command uses an argument array; a test confirms metacharacters are not interpreted.

**May be a false positive when.** Fully constant commands. Interpolated values that are validated constants.

### VS-CODE-004: SQL query built with string concatenation or interpolation

- Severity: **high** | Confidence: **medium** | Status: **potential**
- Location: `server.js:6`
- Fingerprint: `821316a53c548a607dd94a1fd5c6919e` | CWE-89 (orientation only)
- Evidence:

  ```text
  db.query("SELECT * FROM users WHERE id = " + req.query.id);
  ```

**Why it matters.** A SQL statement is assembled from variables instead of bound parameters, which can allow SQL injection when any value is user-controlled.

**Fix.** Use parameterised queries or a query builder that binds values (`?`, `$1`, `%s` placeholders passed separately).

**Verify.** Query text is a constant; values passed as parameters; test with a quote-containing input.

**May be a false positive when.** Interpolated identifiers that come from a fixed allowlist, or constants.

### VS-CODE-001: Dynamic code execution (eval / new Function / exec)

- Severity: **high** | Confidence: **medium** | Status: **potential**
- Location: `server.js:7`
- Fingerprint: `a53ed37df0b77f8d570605e2df75ad47` | CWE-95 (orientation only)
- Evidence:

  ```text
  eval(req.body.expr);
  ```

**Why it matters.** Strings are compiled and executed as code. If any part is attacker-influenced this is remote code execution. This rule matches the call, not the data flow.

**Fix.** Replace with a data-driven approach (lookup table, JSON.parse, ast.literal_eval). Never pass user input to an evaluator.

**Verify.** The call is removed or its argument is proven constant; add a test with a malicious input.

**May be a false positive when.** Constant strings, build tooling, or sandboxed evaluators. Trace the argument to confirm.

### VS-CICD-003: Workflow grants write-all permissions

- Severity: **medium** | Confidence: **high** | Status: **confirmed**
- Location: `.github/workflows/ci.yml:3`
- Fingerprint: `55d0df202ef3630a18b3c2bd9bfc28a9` | CWE-250, CWE-732 (orientation only)
- Evidence:

  ```text
  permissions: write-all
  ```

**Why it matters.** `permissions: write-all` gives every job a token that can modify repository contents, packages and more.

**Fix.** Declare `permissions: contents: read` at the top level and grant additional scopes per job only where required.

**Verify.** No `write-all` remains and the workflow still passes.

**May be a false positive when.** None expected; the setting is explicit.

### VS-DOCKER-001: Container runs as root (no USER instruction)

- Severity: **medium** | Confidence: **high** | Status: **confirmed**
- Location: `Dockerfile:1`
- Fingerprint: `b8e95fb4db1dcce6db599478c54f942f` | CWE-250 (orientation only)
- Evidence:

  ```text
  FROM node:latest
  ```

**Why it matters.** The Dockerfile never sets a non-root USER, so the final image runs as root by default. A compromise of the app gives root inside the container.

**Fix.** Create an unprivileged user and add `USER <name>` before the final CMD/ENTRYPOINT.

**Verify.** `docker run --rm <image> id -u` returns a non-zero UID.

**May be a false positive when.** Images intentionally run as root for tooling or build-only stages.

### VS-DOCKER-003: Remote script piped into a shell during build

- Severity: **medium** | Confidence: **medium** | Status: **potential**
- Location: `Dockerfile:2`
- Fingerprint: `018c189f742cf1fc9702bf7266200d45` | CWE-494 (orientation only)
- Evidence:

  ```text
  RUN curl -fsSL https://example.invalid/install.sh | sh
  ```

**Why it matters.** `curl|sh` or `wget|sh` executes whatever the remote server returns at build time, with no integrity check.

**Fix.** Download to a file, verify a pinned checksum or signature, then execute. Prefer the distribution's package manager.

**Verify.** No `| sh` / `| bash` remains; a checksum verification step precedes execution.

**May be a false positive when.** Installers from a source you control and trust. Still no integrity verification.

### VS-IAC-001: Security group or firewall open to the whole internet

- Severity: **medium** | Confidence: **medium** | Status: **potential**
- Location: `main.tf:6`
- Fingerprint: `3a0a43d3f3282b7189719f53a4405a85` | CWE-284 (orientation only)
- Evidence:

  ```text
  cidr_blocks = ["0.0.0.0/0"]
  ```

**Why it matters.** A Terraform rule allows 0.0.0.0/0 (or ::/0). Open ingress to administrative or database ports exposes them to internet scanning and attack.

**Fix.** Restrict CIDR ranges to known addresses or place the service behind a load balancer, VPN or bastion.

**Verify.** Ingress CIDRs are restricted or documented as intentionally public.

**May be a false positive when.** Intentionally public web ports (80/443) and egress rules. Review the port and direction.

### VS-SECRET-004: Hardcoded credential assigned to a secret-named variable

- Severity: **medium** | Confidence: **medium** | Status: **potential**
- Location: `server.js:3`
- Fingerprint: `18d98d5cedc5076fd3c45eb622051cd6` | CWE-798 (orientation only)
- Evidence (redacted):

  ```text
  const db_password = "[REDACTED]";
  ```

**Why it matters.** A variable or key named like a password, secret, token or API key is assigned a non-placeholder string literal.

**Fix.** Treat the credential as compromised: revoke or rotate it at the issuer first, then remove it from the repository and load it from an environment variable or secret manager. Deleting it from the latest commit does not remove it from git history.

**Verify.** Re-run `vigilsutra audit` after removing the value; then confirm the credential was rotated at the issuer and review git history for earlier exposure.

**May be a false positive when.** Test data, example config, i18n labels. Values that look like placeholders, environment lookups or templates are skipped.

### VS-CICD-001: GitHub Action not pinned to a commit SHA

- Severity: **low** | Confidence: **high** | Status: **potential**
- Location: `.github/workflows/ci.yml:8`
- Fingerprint: `78b329a94b37c68e38f24aed9717798c` | CWE-829 (orientation only)
- Evidence:

  ```text
  - uses: actions/checkout@v4
  ```

**Why it matters.** A third-party action is referenced by a mutable tag or branch. If the tag is moved or the publisher is compromised, the workflow runs attacker-controlled code.

**Fix.** Pin third-party actions to a full 40-character commit SHA and keep a trailing comment with the version. Use Dependabot or Renovate to update pins.

**Verify.** Every `uses:` line for a non-local action ends in @<40 hex>.

**May be a false positive when.** First-party `actions/*` references are lower risk; local `./` actions and Docker digests are skipped.

### VS-DOCKER-002: Base image uses :latest or no tag

- Severity: **low** | Confidence: **high** | Status: **confirmed**
- Location: `Dockerfile:1`
- Fingerprint: `a44375af9a3b7bae297ac58c69029c1a` | CWE-829 (orientation only)
- Evidence:

  ```text
  FROM node:latest
  ```

**Why it matters.** An unpinned base image changes without notice, which breaks reproducibility and can pull in vulnerable or malicious content.

**Fix.** Pin to a specific version and, for production, an image digest (`image@sha256:…`).

**Verify.** Every FROM line has an explicit tag or digest.

**May be a false positive when.** `FROM scratch` and references to earlier build stages are skipped.

### VS-PROC-001: No security policy file found

- Severity: **info** | Confidence: **high** | Status: **informational**
- Location: `.:1`
- Fingerprint: `dc01ae019e233f9810fdf7da89927440`
- Evidence:

  ```text
  SECURITY.md not found
  ```

**Why it matters.** No SECURITY.md was found, so reporters have no documented way to disclose vulnerabilities privately.

**Fix.** Add SECURITY.md with a private contact or GitHub private vulnerability reporting link and a response expectation.

**Verify.** SECURITY.md exists at the repository root, `.github/` or `docs/`.

**May be a false positive when.** Policy kept in an org-level `.github` repository.

---
Created by Vatsal Shah. VigilSutra reports engineering evidence, not certification or legal advice.
