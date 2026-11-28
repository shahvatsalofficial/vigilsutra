<!--meta nav="Stability" group="Reference" desc="What tools built on VigilSutra output can rely on: schema version, fingerprints, exit codes and reproducible reports."-->
# Stability promise

<p class="lead">What you can rely on when a script, dashboard or baseline reads VigilSutra output.</p>

## Report format

JSON results carry `schemaVersion`, currently `1.0`. The schemas are `schemas/scan.schema.json` and `schemas/finding.schema.json` in the package, and the test suite checks findings against them.

- Adding an optional field keeps the major version.
- Removing or renaming a field, or changing its type, needs a new major `schemaVersion` and a note in the changelog.

## Fingerprints

A fingerprint identifies a finding for baselines. It is built from the rule id, the rule version, the file path, the redacted evidence line and the occurrence number on that evidence.

| Change | Fingerprint |
|---|---|
| Lines added above the finding | Unchanged |
| The evidence line is edited | Changes |
| The file is moved | Changes; a baseline still accepts it when the old path is gone |
| The rule version changes | Changes |

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Finished; nothing reached the `--fail-on` threshold |
| `1` | A finding reached the threshold, or `verify` found new findings |
| `2` | Usage or runtime error, or an incomplete scan with `--fail-on` |

## Reproducible output

Set `SOURCE_DATE_EPOCH` to a time in seconds. Two runs over the same files with the same version then give byte-identical JSON reports and SBOM. Reports use paths relative to the scanned folder. A time limit that cuts a scan short, or a different advisory file, changes the result.
