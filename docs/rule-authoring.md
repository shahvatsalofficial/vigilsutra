# Rule authoring

1. Add the rule to the matching file in `src/rules/` (`id`, `version`, `severity`, `confidence`, `status`, `description`, `remediation`, `verification`, `falsePositives`, `agent`, `applies`, `check`). Use `lineRule` for single-line patterns.
2. Use `confirmed` only if a match alone is conclusive; otherwise `potential`. Keep severity and confidence independent.
3. For secrets, return `secretGroup` so the value is redacted. Never put the value in `excerpt` yourself.
4. Add a vulnerable and a clean fixture to `PAIRS` in `test/vigilsutra.test.mjs`. Build secret-shaped strings at runtime.
5. Prefer precision. Add `filter` callbacks to skip placeholders, comments and examples.
6. Run `npm test`, then `node docs/gen-rules.mjs > docs/rules.md`, and update the CHANGELOG.
7. Third-party executable plugins are not supported in v0.1; rules are reviewed source.
