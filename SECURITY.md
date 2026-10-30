# Security Policy

## Reporting a vulnerability

Please report vulnerabilities in VigilSutra privately through GitHub: **Security tab -> Report a vulnerability** at
<https://github.com/shahvatsalofficial/vigilsutra/security/advisories/new>.

Do not open a public issue for a security bug. Include the version (`vigilsutra --version`), a minimal reproduction, and the impact. Never include real secrets or personal data.

Expect an acknowledgement within 7 days. This is a volunteer project and no fixed fix time is promised.

## Supported versions

Only the latest `0.x` release receives fixes.

## Scope

In scope: path traversal or symlink escape during scanning, secret leakage in any report format, report injection (HTML/Markdown/SARIF), unsafe file writes by `init` or `adapters`, any unexpected network or process execution.

Out of scope: findings that are false positives or false negatives of a rule (open a normal issue), and results from scanning systems you do not own.

## Safe use

VigilSutra is for auditing code and systems you are authorized to review.
