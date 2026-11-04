---
name: secretwatch
description: Secrets and credential exposure responder. Use this whenever the user mentions a leaked or committed key, token, password, private key or .env file, asks "did I commit a secret", or when a vigilsutra audit reports VS-SECRET findings. Gives the correct order of actions (rotate first, then clean up) and never prints secret values.
---

# SecretWatch: leaked credential response

Part of VigilSutra AI, created by Vatsal Shah.

Deleting a secret from the latest commit does not make it safe: anyone who cloned, forked or cached the repository still has it, and it stays in git history. The only fix is to make the old value worthless, so the order of steps matters more than the cleanup.

## Ground rules

- **Never print, quote, summarise or paste a secret value.** Not in chat, not in a report, not in a commit message. The CLI redacts excerpts; do not open the offending line to look at the value. Cite `path:line`, rule id and the credential type.
- Do not test whether a credential is live. That is using it.
- Do not rewrite git history, push, or rotate anything without explicit approval.

## Procedure

1. Start from `VS-SECRET-*` findings in `results.json` (`vigilsutra report .`; add `--no-policy` for code you do not own).
2. For each, state the **type** (cloud key, GitHub token, Slack token, private key, hardcoded password, `.env` file) and **where**. `VS-SECRET-004` and `VS-SECRET-006` are patterns and may be placeholders or test data; say what would make it a false positive. Findings under test or example paths are lower priority but still worth a glance.
3. Give the steps in this order:
   1. **Revoke or rotate at the issuer** (cloud console, GitHub settings, Slack admin). This is the step that actually protects the user.
   2. **Check the provider's audit log** for use of the old credential since it was committed.
   3. **Replace it** with an environment variable or secret manager reference, and add the file to `.gitignore` if appropriate.
   4. **Decide on history.** Ask whether the repository was ever public or shared. Rewriting history (for example with `git filter-repo`) is a separate decision with side effects; offer it, do not do it.
4. Recommend prevention: push protection or a pre-commit secret scan, and short-lived credentials.
5. Remember VigilSutra does **not** scan git history or the full pattern set of a dedicated scanner (Gitleaks, TruffleHog). Recommend one of those for history.

## Output

A short list: credential type, location, the ordered action list above, and what to verify afterwards (the old credential no longer works; a re-run of `vigilsutra report .` shows the finding gone).
