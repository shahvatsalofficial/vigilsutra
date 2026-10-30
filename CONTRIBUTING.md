# Contributing to VigilSutra AI

Thanks for helping. Contributors are credited in git history and release notes.

## Setup

```bash
git clone https://github.com/shahvatsalofficial/vigilsutra.git
cd vigilsutra
npm install
npm test          # builds, then runs all tests
npm run audit:self
```

## Ground rules

1. **Evidence first.** A rule is merged only with a vulnerable fixture it flags and a clean fixture it does not. Add both to the table in `test/vigilsutra.test.mjs`.
2. **No fake certainty.** Pattern-only rules are `potential`. Use `confirmed` only when the match itself is conclusive.
3. **No secrets in the repo.** Build secret-shaped test strings at runtime (string concatenation). Never commit real credentials, even revoked ones.
4. **Stay offline.** No network, telemetry, or subprocess APIs in `src/` (a test enforces this). No new runtime dependencies without discussion.
5. **Redaction.** Anything that can contain a secret must go through the redaction path.
6. **Honest docs.** Update the README feature matrix, `docs/rules.md` and `CHANGELOG.md`. Mark unverified things as planned.

See [docs/rule-authoring.md](docs/rule-authoring.md) for writing a rule.

## Pull requests

Keep changes focused, describe the behaviour change and list tests you ran. By contributing you agree your work is licensed under Apache-2.0.
