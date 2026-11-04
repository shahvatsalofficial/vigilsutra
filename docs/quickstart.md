# Quickstart

Prerequisite: Node.js 20 or newer. No API key, account or network access is needed to scan.

## Windows PowerShell
```powershell
git clone https://github.com/shahvatsalofficial/vigilsutra.git
cd vigilsutra
npm install; npm run build
node dist\cli.js audit examples\intentionally-insecure
node dist\cli.js audit "C:\path with spaces\my-project" --format markdown --out report.md
```

## macOS / Linux
```bash
git clone https://github.com/shahvatsalofficial/vigilsutra.git && cd vigilsutra
npm install && npm run build
node dist/cli.js audit examples/intentionally-insecure
```

## From npm
```bash
npx vigilsutra audit .
npm install -g vigilsutra
```

## Global `vigilsutra` command (from a clone)
```bash
npm link      # from the cloned repo; remove with: npm unlink -g vigilsutra
vigilsutra doctor
```

## Docker
No official image is published yet (planned). To run in a container yourself, mount the project read-only with networking disabled:

```bash
docker run --rm --network none -v "$PWD":/work:ro -v /path/to/vigilsutra:/vs:ro -w /work node:22 node /vs/dist/cli.js audit .
```

## Get a readable report
```bash
vigilsutra report .      # writes ./vigilsutra-report/report.html, report.md, results.json, results.sarif
```
Open `report.html` in a browser, or `report.md` in any Markdown viewer. The folder has its own `.gitignore`; reports contain file paths and redacted excerpts, so do not publish them for private projects.

## Next steps
1. `vigilsutra init` to create `.vigilsutra.yml`.
2. `vigilsutra audit . --format sarif --out vigilsutra.sarif` for code scanning.
3. `vigilsutra baseline --out .vigilsutra-baseline.json` to accept current findings, then pass `--baseline` in CI to fail only on new ones.
4. After fixing, run `vigilsutra verify --previous vigilsutra-results.json`.
