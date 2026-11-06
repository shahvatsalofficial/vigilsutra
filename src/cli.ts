#!/usr/bin/env node
import { existsSync, mkdirSync, readFileSync, realpathSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { audit, exceeds, VERSION } from "./engine.js";
import { loadPolicy } from "./policy.js";
import { render, FORMATS, type Format } from "./reporters/index.js";
import { ALL_RULES, findRule, RULES_VERSION } from "./rules/index.js";
import { ADAPTERS, PACKAGE_ROOT, installAdapter, planAdapter, uninstallAdapter, type AdapterName } from "./adapters.js";
import { locateGit } from "./git-objects.js";
import { cycloneDx, readComponents } from "./components.js";
import { applyFixes, planFixes } from "./fix.js";
import { SEVERITY_ORDER, type ScanResult, type Severity } from "./types.js";

const HELP = `VigilSutra AI ${VERSION} - offline, read-only security & privacy auditor. Created by Vatsal Shah.

Usage: vigilsutra <command> [options]

Commands:
  audit [path]            Scan a project (default: .). Read-only; no network; no code execution.
      --format <f>        text (default) | json | markdown | sarif | html
      --out <file>        Write the report to a file instead of stdout
      --fail-on <sev>     Exit 1 if any finding is at/above critical|high|medium|low|info
      --baseline <file>   Suppress findings whose fingerprints are in this baseline
      --policy <file>     Use this policy file instead of the project's .vigilsutra.yml
      --no-policy         Ignore the project's .vigilsutra.yml (use when auditing code you do not own)
      --report            Write report.md and report.html (also results.json and results.sarif) to ./vigilsutra-report/. This is the default.
      --report-dir <dir>  Same, into <dir>
      --no-report         Do not write those files
      --no-history        Do not read git objects for secrets that were removed from the worktree
      --since <rev>       Scan only worktree files that differ from this git revision (skips history)
      --staged            Scan the git index (what a commit would record) instead of the worktree
      --no-advisories     Do not match the shipped advisory snapshot
      --advisories <file> Match this advisory snapshot instead of the shipped one
      --no-color          Plain output (also honours NO_COLOR)
  report [path]           Same scan as audit. Always writes report.md and report.html (plus JSON and SARIF)
  sbom [path]             Write a CycloneDX 1.6 JSON SBOM of pinned npm, PyPI and Go components
      --out <file>        Write the SBOM to a file instead of stdout
  fix [path]              Show deterministic safe edits (dry-run). Secrets are never rewritten
      --apply             Write those edits
  baseline [path] --out <file>   Record current findings as an accepted baseline
  verify [path] --previous <results.json>   Re-scan and compare with an earlier JSON result
  rules list              List implemented rules
  explain <RULE-ID>       Show rule details, fix and false-positive notes
  doctor                  Environment and offline-readiness check
  init [path]             Create .vigilsutra.yml if absent (never overwrites)
      --hook              Also install templates/pre-commit as .git/hooks/pre-commit if that hook is absent
  adapters list           Show adapter status
  adapters install <claude|cursor|codex|gemini|copilot> [--project <dir>] [--dry-run] [--force]
  adapters uninstall <claude|cursor|codex|gemini|copilot> [--project <dir>]
  --help, --version

Exit codes: 0 ok | 1 findings at/above --fail-on | 2 usage or runtime error
`;

interface Args {
  pos: string[];
  flags: Map<string, string | true>;
}

const VALUE_FLAGS = new Set(["format", "out", "fail-on", "baseline", "previous", "project", "policy", "report-dir", "since", "advisories"]);

function parse(argv: string[]): Args {
  const pos: string[] = [];
  const flags = new Map<string, string | true>();
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith("--")) {
      const k = a.slice(2);
      if (VALUE_FLAGS.has(k)) {
        const v = argv[++i];
        if (v === undefined) throw new Error(`--${k} needs a value`);
        flags.set(k, v);
      } else flags.set(k, true);
    } else pos.push(a);
  }
  return { pos, flags };
}

function policyOpts(flags: Map<string, string | true>): { policyFile?: string; ignoreProjectPolicy?: boolean } {
  const p = flags.get("policy");
  return { policyFile: typeof p === "string" ? resolve(p) : undefined, ignoreProjectPolicy: flags.has("no-policy") };
}

function auditOpts(root: string, flags: Map<string, string | true>) {
  const since = flags.get("since");
  const advisories = flags.get("advisories");
  return {
    root,
    history: !flags.has("no-history"),
    since: typeof since === "string" ? since : undefined,
    staged: flags.has("staged"),
    advisories: !flags.has("no-advisories"),
    advisoriesFile: typeof advisories === "string" ? resolve(advisories) : undefined,
    ...policyOpts(flags)
  };
}

function fail(msg: string): never {
  process.stderr.write(`vigilsutra: ${msg}\n`);
  process.exit(2);
}

function checkRoot(p: string): string {
  const abs = resolve(p);
  if (!existsSync(abs) || !statSync(abs).isDirectory()) fail(`not a directory: ${p}`);
  return realpathSync(abs);
}

/** Writes report.md, report.html, results.json and results.sarif. The folder gets a .gitignore so reports are not committed by accident. */
function writeReportFolder(dir: string, result: ScanResult): void {
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "report.md"), render(result, "markdown"));
  writeFileSync(join(dir, "report.html"), render(result, "html"));
  writeFileSync(join(dir, "results.json"), render(result, "json"));
  writeFileSync(join(dir, "results.sarif"), render(result, "sarif"));
  writeFileSync(join(dir, ".gitignore"), "# Reports contain file paths and redacted excerpts; do not commit them.\n*\n");
}

function writeOut(file: string, data: string): void {
  const abs = resolve(file);
  mkdirSync(dirname(abs), { recursive: true });
  writeFileSync(abs, data);
}

function sev(v: string | true | undefined): Severity | undefined {
  if (v === undefined) return undefined;
  if (typeof v !== "string" || !SEVERITY_ORDER.includes(v as Severity)) fail("--fail-on must be one of critical|high|medium|low|info");
  return v as Severity;
}

function main(): void {
  const argv = process.argv.slice(2);
  if (!argv.length || argv[0] === "--help" || argv[0] === "-h" || argv[0] === "help") {
    process.stdout.write(HELP);
    return;
  }
  if (argv[0] === "--version" || argv[0] === "-v") {
    process.stdout.write(VERSION + "\n");
    return;
  }
  const cmd = argv[0];
  const { pos, flags } = parse(argv.slice(1));
  const color = !flags.has("no-color") && !process.env.NO_COLOR && !!process.stdout.isTTY;

  switch (cmd) {
    case "audit":
    case "report": {
      const root = checkRoot(pos[0] ?? ".");
      const format = (flags.get("format") as string | undefined) ?? "text";
      if (!FORMATS.includes(format as Format)) fail(`unknown format "${format}"`);
      const baselineFile = flags.get("baseline");
      const pol = policyOpts(flags);
      const result = audit({
        ...auditOpts(root, flags),
        baselineFile: typeof baselineFile === "string" ? resolve(baselineFile) : undefined
      });
      const failOn = sev(flags.get("fail-on")) ?? loadPolicy(root, { explicitFile: pol.policyFile, ignoreProjectPolicy: pol.ignoreProjectPolicy }).failOn;
      const out = flags.get("out");
      if (typeof out === "string") {
        writeOut(out, render(result, format as Format, false));
        process.stderr.write(`Report written to ${out} (${result.summary.total} findings)\n`);
      } else process.stdout.write(render(result, format as Format, color));
      // Readable reports are files, not only a terminal scrollback. Stdout stays the chosen format.
      const dirFlag = flags.get("report-dir");
      if (!flags.has("no-report")) {
        const dir = resolve(typeof dirFlag === "string" ? dirFlag : "vigilsutra-report");
        writeReportFolder(dir, result);
        process.stderr.write(`Reports written to ${dir}\n  report.html  open this in a browser\n  report.md    Markdown version\n  results.json, results.sarif  for tools and CI\n`);
      }
      if (failOn && exceeds(result, failOn)) process.exit(1);
      return;
    }
    case "baseline": {
      const root = checkRoot(pos[0] ?? ".");
      const out = flags.get("out");
      if (typeof out !== "string") fail("baseline needs --out <file>");
      const result = audit(auditOpts(root, flags));
      writeOut(out, JSON.stringify({ tool: "vigilsutra", version: VERSION, createdAt: result.generatedAt, fingerprints: result.findings.map((f) => f.fingerprint).sort() }, null, 2) + "\n");
      process.stdout.write(`Baseline of ${result.findings.length} finding(s) written to ${out}\n`);
      return;
    }
    case "verify": {
      const root = checkRoot(pos[0] ?? ".");
      const prevFile = flags.get("previous");
      if (typeof prevFile !== "string") fail("verify needs --previous <results.json>");
      let prev: ScanResult;
      try {
        prev = JSON.parse(readFileSync(resolve(prevFile), "utf8")) as ScanResult;
      } catch (e) {
        fail(`cannot read previous results: ${(e as Error).message}`);
      }
      if (!Array.isArray(prev.findings)) fail("previous file is not a VigilSutra JSON result");
      const now = audit(auditOpts(root, flags));
      const before = new Map(prev.findings.map((f) => [f.fingerprint, f]));
      const after = new Map(now.findings.map((f) => [f.fingerprint, f]));
      const resolved = [...before.values()].filter((f) => !after.has(f.fingerprint));
      const added = [...after.values()].filter((f) => !before.has(f.fingerprint));
      const persisting = [...after.values()].filter((f) => before.has(f.fingerprint));
      process.stdout.write(`Verify: ${resolved.length} no longer detected, ${persisting.length} persisting, ${added.length} new.\n`);
      for (const f of resolved) process.stdout.write(`  gone      ${f.ruleId} ${f.path}:${f.startLine}\n`);
      for (const f of added) process.stdout.write(`  NEW       ${f.ruleId} ${f.path}:${f.startLine} [${f.severity}]\n`);
      for (const f of persisting) process.stdout.write(`  remaining ${f.ruleId} ${f.path}:${f.startLine} [${f.severity}]\n`);
      process.stdout.write("'No longer detected' means the rule no longer matches; it is not proof the weakness is fixed. Review the change and re-test.\n");
      if (added.length) process.exit(1);
      return;
    }
    case "sbom": {
      const root = checkRoot(pos[0] ?? ".");
      const text = cycloneDx(readComponents(root), VERSION);
      const out = flags.get("out");
      if (typeof out === "string") {
        writeOut(out, text);
        process.stderr.write(`SBOM written to ${out}\n`);
      } else process.stdout.write(text);
      return;
    }
    case "fix": {
      const root = checkRoot(pos[0] ?? ".");
      const result = audit({ ...auditOpts(root, flags), history: false });
      const edits = planFixes(result.findings, root);
      if (!edits.length) {
        process.stdout.write("No safe edits. Secrets, users, and commit SHAs are never invented.\n");
        return;
      }
      for (const e of edits) process.stdout.write(`${e.path}:${e.line} ${e.ruleId}\n- ${e.before}\n+ ${e.after}\n`);
      if (flags.has("apply")) {
        const n = applyFixes(edits, root);
        process.stdout.write(`Applied ${n} edit(s).\n`);
      } else process.stdout.write("Dry run. Pass --apply to write these edits.\n");
      return;
    }
    case "rules": {
      if (pos[0] !== "list") fail("usage: vigilsutra rules list");
      process.stdout.write(`Rules version ${RULES_VERSION}: ${ALL_RULES.length} rules\n`);
      for (const r of ALL_RULES) process.stdout.write(`${r.id.padEnd(15)} ${r.severity.padEnd(8)} ${r.status.padEnd(13)} ${r.agent.padEnd(13)} ${r.title}\n`);
      return;
    }
    case "explain": {
      const r = pos[0] ? findRule(pos[0]) : undefined;
      if (!r) fail(`unknown rule "${pos[0] ?? ""}". Try: vigilsutra rules list`);
      process.stdout.write(
        [
          `${r.id} v${r.version}: ${r.title}`,
          `Severity ${r.severity} | confidence ${r.confidence} | status ${r.status} | specialist ${r.agent} | category ${r.category}`,
          r.cwe?.length ? `CWE (orientation only): ${r.cwe.join(", ")}` : "",
          "",
          `Why: ${r.description}`,
          `Fix: ${r.remediation}`,
          `Verify: ${r.verification}`,
          `Possible false positives: ${r.falsePositives}`,
          ""
        ]
          .filter((l, i, a) => l !== "" || a[i - 1] !== "")
          .join("\n") + "\n"
      );
      return;
    }
    case "doctor": {
      const lines = [
        `VigilSutra AI ${VERSION}`,
        `Node: ${process.version} ${/^v(2\d|[3-9]\d)\./.test(process.version) ? "(ok)" : "(needs >=20)"}`,
        `OS: ${process.platform} ${process.arch}`,
        `Working dir: ${process.cwd()}`,
        `Policy file (.vigilsutra.yml): ${existsSync(join(process.cwd(), ".vigilsutra.yml")) ? "present" : "absent (defaults used)"}`,
        `Rules: ${ALL_RULES.length} (version ${RULES_VERSION})`,
        "Offline readiness: ready. The audit path makes no network requests, needs no API key or model, and executes no scanned code.",
        "Telemetry: none.",
        "Adapters:",
        ...ADAPTERS.map((a) => `  ${a.name.padEnd(12)} ${a.status.padEnd(10)} ${a.detail}`),
        `Claude project skills: ${existsSync(join(process.cwd(), ".claude", "skills", ".vigilsutra-managed.json")) ? "installed" : "not-installed"}`
      ];
      process.stdout.write(lines.join("\n") + "\n");
      return;
    }
    case "init": {
      const root = checkRoot(pos[0] ?? ".");
      const file = join(root, ".vigilsutra.yml");
      const tpl = readFileSync(join(PACKAGE_ROOT, "policies", "safe-default.yaml"), "utf8");
      try {
        // "wx" creates the file only if it does not exist, atomically (no check-then-write race).
        writeFileSync(file, tpl, { flag: "wx" });
        process.stdout.write(`Created ${file}\n`);
      } catch (e) {
        if ((e as NodeJS.ErrnoException).code === "EEXIST") process.stdout.write(".vigilsutra.yml already exists; not modified.\n");
        else throw e;
      }
      if (flags.has("hook")) {
        const located = locateGit(root);
        if (!located) fail("--hook needs a git directory for this project");
        const dest = join(located.gitDir, "hooks", "pre-commit");
        const hook = readFileSync(join(PACKAGE_ROOT, "templates", "pre-commit"), "utf8");
        try {
          mkdirSync(join(located.gitDir, "hooks"), { recursive: true });
          writeFileSync(dest, hook, { flag: "wx", mode: 0o755 });
          process.stdout.write(`Created ${dest}\n`);
        } catch (e) {
          if ((e as NodeJS.ErrnoException).code === "EEXIST") process.stdout.write("pre-commit hook already exists; not modified.\n");
          else throw e;
        }
      }
      return;
    }
    case "adapters": {
      const sub = pos[0];
      if (sub === "list") {
        for (const a of ADAPTERS) process.stdout.write(`${a.name.padEnd(12)} ${a.status.padEnd(10)} ${a.detail}\n`);
        return;
      }
      const names = new Set(["claude", "cursor", "codex", "gemini", "copilot"]);
      if ((sub === "install" || sub === "uninstall") && names.has(pos[1] ?? "")) {
        const adapter = pos[1] as AdapterName;
        const proj = checkRoot(typeof flags.get("project") === "string" ? (flags.get("project") as string) : ".");
        if (sub === "uninstall") {
          const removed = uninstallAdapter(proj, adapter);
          process.stdout.write(removed.length ? `Removed:\n${removed.map((r) => "  " + r).join("\n")}\n` : "Nothing installed by VigilSutra found.\n");
          return;
        }
        const force = flags.has("force");
        if (flags.has("dry-run")) {
          for (const p of planAdapter(proj, adapter, force)) process.stdout.write(`${p.action.padEnd(12)} ${p.to}\n`);
          process.stdout.write("Dry run: no files written.\n");
          return;
        }
        for (const p of installAdapter(proj, adapter, force)) process.stdout.write(`${p.action.padEnd(12)} ${p.to}\n`);
        process.stdout.write("Existing files are never overwritten without --force. In-IDE behaviour is not automated-tested.\n");
        return;
      }
      fail("usage: vigilsutra adapters list | install <claude|cursor|codex|gemini|copilot> | uninstall <claude|cursor|codex|gemini|copilot>");
    }
    default:
      fail(`unknown command "${cmd}". Run: vigilsutra --help`);
  }
}

try {
  main();
} catch (e) {
  fail((e as Error).message);
}
