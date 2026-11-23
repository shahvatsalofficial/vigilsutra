<!--meta nav="Start in 5 minutes" group="Learn" desc="Install nothing, run one command, read your first report, fix a finding and prove the fix. A five-minute tutorial with real output."-->
# Start in 5 minutes

<p class="lead">You will scan a project, open a readable report, fix one problem, and prove it is gone. No account, no API key, no install.</p>

<div class="chips"><span class="chip">Time: 5 minutes</span><span class="chip">Needs: Node.js 20 or newer</span><span class="chip ok">Nothing leaves your machine</span></div>

## Before you begin

Check that Node.js is installed:

```bash
node --version
```

Any version from `v20` up works. If the command is not found, install Node.js from nodejs.org first.

## The whole journey

```diagram
whichCommand
```

The rest of this page walks the first branch: see the problems, fix one, prove it.

## Step by step

```steps
1. **Scan.** Go to a project folder and run the command below. It reads the files, writes four report files into `vigilsutra-report/`, and prints a summary.
2. **Open the report.** Open `vigilsutra-report/report.html` in your browser. Start with the line at the top that says what to do first.
3. **Pick one high finding.** Run `vigilsutra explain <rule id>` to see why it matters and how to fix it.
4. **Fix it.** Edit the file, or preview a safe automatic edit with `vigilsutra fix .`.
5. **Prove it.** Run `vigilsutra verify` against the earlier results to see what is gone and whether anything new appeared.
```

### 1. Scan

```bash
npx vigilsutra report .
```

Want to try it without a project of your own? Clone the repository and scan the deliberately insecure demo:

```bash
git clone https://github.com/shahvatsalofficial/vigilsutra.git
cd vigilsutra
npx vigilsutra report examples/intentionally-insecure
```

You will see this (shortened):

```term vigilsutra report examples/intentionally-insecure
HIGH     VS-K8S-001  Kubernetes container runs privileged
         deployment.yaml:13  [confirmed, confidence high]
         evidence: privileged: true
HIGH     VS-CODE-001  Dynamic code execution (eval / new Function / exec)
         server.js:7  [potential, confidence medium]
         evidence: eval(req.body.expr);
MEDIUM   VS-SECRET-004  Hardcoded credential assigned to a secret-named variable
         server.js:3  [potential, confidence medium]
         evidence: const db_password = "[REDACTED]";

Summary: 0 critical, 8 high, 5 medium, 2 low, 1 info
```

Notice `[REDACTED]`. The password value is never printed, not on screen, not in any file.

### 2. Open the report

```diagram
reportFiles
```

Open `vigilsutra-report/report.html`. You can also look at a [real sample report](samples/report.html) right now. It starts with one plain sentence, for example:

> **Result.** Start with the 8 critical and high items. They are the most likely to cause real harm. The rest can be scheduled afterwards.

Then you get severity counts, a table of every finding, and each finding with **Why it matters**, **Fix**, **Verify**, and **May be a false positive when**.

### 3. Understand one finding

```diagram
anatomy
```

Ask the tool to explain any rule:

```bash
vigilsutra explain VS-K8S-001
```

### 4. Fix it

Edit `deployment.yaml` and remove `privileged: true`. Or let the tool propose the change first. The default is a preview that changes nothing:

```term vigilsutra fix .
deployment.yaml:8 VS-K8S-002
-       hostNetwork: true
+       hostNetwork: false
deployment.yaml:13 VS-K8S-001
-             privileged: true
+             privileged: false
main.tf:9 VS-IAC-002
-   acl = "public-read"
+   acl = "private"
Dry run. Pass --apply to write these edits.
```

Add `--apply` to write them. Secrets are never rewritten or deleted by `fix`: a leaked secret needs rotating at its provider, not just editing.

### 5. Prove the fix

Keep the earlier scan results, fix, then compare:

```bash
vigilsutra audit . --format json --out before.json --no-report
# ...make your fix...
vigilsutra verify . --previous before.json
```

```term vigilsutra verify . --previous before.json
Verify: 1 no longer detected, 15 persisting, 0 new.
  gone      VS-K8S-001 deployment.yaml:13
  remaining VS-CICD-002 .github/workflows/ci.yml:10 [high]
  remaining VS-K8S-002 deployment.yaml:8 [high]
```

> **Important.** "No longer detected" means the rule stopped matching. Read the change and run your tests before you call it fixed. For a leaked secret, rotating it at the provider is the fix.

## Make it a habit

| When | Command |
|---|---|
| Before every commit | `vigilsutra init --hook` once, then it runs automatically on staged files |
| On every pull request | See the [CI/CD guide](ci-cd.html) |
| Adopting on an old repo | See the [legacy repo scenario](scenarios.html#scenario-2-adopt-it-on-a-legacy-repo-without-a-red-build) |
| Using an AI assistant | See [AI assistants](ai-assistants.html) |

## If something looks wrong

| You see | Why and what to do |
|---|---|
| `vigilsutra-report/` appears in your project | It is the default output folder. It has its own `.gitignore` so it is not committed, and scans skip it. Use `--no-report` to skip writing it |
| Fewer files scanned than you expected | Ignored folders, large files and links are skipped and counted on the summary line. See [Configuration](configuration.html) |
| A finding you think is wrong | Read the rule's **Not a problem when** section with `vigilsutra explain`, then [baseline or waive it](configuration.html#silencing-a-finding-on-purpose) |
| Anything else | See the [FAQ](faq.html) |
