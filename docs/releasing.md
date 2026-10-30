# Releasing (npm with provenance)

Releases publish from GitHub Actions (`.github/workflows/release.yml`) using npm Trusted Publishing, so no long-lived npm token is stored and the package carries a provenance attestation linking it to this repository and workflow run.

## One-time setup (maintainer, on npmjs.com)
1. Open the `vigilsutra` package -> Settings -> **Trusted Publisher** -> GitHub Actions.
2. Owner `shahvatsalofficial`, repository `vigilsutra`, workflow `release.yml`, environment `npm`.
3. In GitHub: Settings -> Environments -> `npm` (created automatically on first run); optionally require a reviewer.

## Each release
1. Bump the version in `package.json`, `src/engine.ts` (`VERSION`) and `CITATION.cff`; update `CHANGELOG.md`.
2. `npm test && npm run audit:self`, commit, push to `main`, wait for CI.
3. `git tag -a vX.Y.Z -m "..." && git push origin vX.Y.Z`, then publish a GitHub release for that tag.
4. The workflow checks the tag matches `package.json`, runs tests and the self-audit, then runs `npm publish --provenance --access public`.

Fallback without Trusted Publishing: create a granular npm token limited to this package, store it as the repository secret `NPM_TOKEN`, and add `NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}` to the publish step.
