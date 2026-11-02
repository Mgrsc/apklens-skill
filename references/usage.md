# Usage

## Environment

- Python 3.10 or newer; locally tested on Python 3.14.8.
- No third-party Python packages, JVM, Gradle, or standalone binaries required for base analysis.
- Device collection requires an installed `adb` executable; local APK mode requires neither a device nor ADB.
- Supplemental decompiled source analysis in `decompile` mode requires an existing jadx executable specified via `--jadx`; jadx itself may require Java. The base scripts do not install external tools or manage their execution environments.
- Scripts run directly from source. When using the full local Skill, keep `SKILL.md`, `scripts/`, and `references/` together. For online use, send the [GitHub link of the online bootstrap entry](https://github.com/Mgrsc/apklens-skill/blob/main/online-static-analysis/SKILL.md) to an AI; the AI reads the [entry instructions](../online-static-analysis/SKILL.md), prepares the project from the [GitHub repository](https://github.com/Mgrsc/apklens-skill), and hands off to the local main Skill without requiring manual installation.
- Online bootstrapping requires Git, network access for the initial clone, and local filesystem/shell tools; subsequent runs reuse the recorded commit without automatic updates. Project acquisition never uploads analysis inputs or installs dependencies, and this project is never automatically installed into a global skills directory.

This directory can serve as the root of an independent repository containing `SKILL.md`, `scripts/`, `references/`, and `tests/`. The commands below are run from the directory containing `SKILL.md`; for other directories, use absolute paths to scripts.

## Inspecting Environment

```sh
python3 scripts/analyze.py doctor
```

Inspects executable paths only, without contacting devices or downloading tools. To list devices explicitly:

```sh
python3 scripts/analyze.py devices
```

## Local APKs and Splits

```sh
python3 scripts/analyze.py scan \
  --apk /path/to/base.apk \
  --apk /path/to/split_config.en.apk \
  --output .dev/analysis/local-001
```

Artifacts are grouped by package name and version from their manifests. Distinct packages are analyzed separately; differing versions of the same package produce separate results. Missing splits, duplicated base files, version conflicts, and unreadable identities are recorded in coverage metadata. Local inputs cannot prove that all device splits were provided, nor do they include runtime grant state.

Quick preview mode:

```sh
python3 scripts/analyze.py scan \
  --apk /path/to/base.apk \
  --mode quick \
  --output .dev/analysis/quick-001
```

## One-time Device Collection

When analyzing a device, ensure USB debugging or wireless debugging is enabled and authorized on the host. Enabling developer options, granting host authorizations, or pairing devices are connection prerequisites that the analysis scripts do not perform automatically. The ADB host must be able to reach the target device; verify the target displays state `device` in `adb devices -l`, and pass the first-column identifier as `--device`. Skip phone connection when analyzing local APKs.

```sh
python3 scripts/analyze.py scan \
  --device SERIAL \
  --user 0 \
  --output .dev/analysis/device-001
```

When `--package` is omitted, all enumerable applications for the specified user are analyzed without filtering by `INTERNET` or sensitive permissions. To restrict analysis to specific packages:

```sh
python3 scripts/analyze.py scan \
  --device SERIAL \
  --user 10 \
  --package com.example.app \
  --package com.example.other \
  --output .dev/analysis/selected-001
```

Device interactions are restricted to package inventory, `dumpsys package`, `settings get`, `cmd appops get`, `pm path`, and `adb pull`. All enumerated readable APKs are pulled; paths and versions are verified upon completion. Snapshots are non-atomic and do not reflect ongoing state.

ADB output formatting varies by vendor; unparseable blocks or permission denials are recorded in `coverage`. AppOps `default` is not interpreted as granted; unlisted permissions or special access settings cannot be assumed denied.

## Supplemental Decompiled Source Analysis

```sh
python3 scripts/analyze.py scan \
  --apk /path/to/base.apk \
  --mode decompile \
  --jadx /path/to/jadx \
  --output .dev/analysis/decompile-001
```

This mode runs base static analysis first, then invokes jadx to decompile code and scan Java/Kotlin text line-by-line for endpoints and rule signals, merging file paths, line numbers, and findings into the report. It does not perform cross-method dataflow analysis or prove data transmission.

If `--jadx` is omitted, base static analysis executes and the supplemental decompilation stage is marked `UNAVAILABLE`. Supplemental decompilation runs sequentially to avoid high concurrent memory usage; base artifact parsing uses a bounded worker pool. Decompiled text and rule findings are not cached.

## Querying Existing Results

```sh
python3 scripts/query_results.py .dev/analysis/local-001/analysis.json

python3 scripts/query_results.py .dev/analysis/local-001/analysis.json \
  --section apps --offset 0 --limit 20

python3 scripts/query_results.py .dev/analysis/local-001/analysis.json \
  --section endpoints --package com.example.app --limit 50

python3 scripts/query_results.py .dev/analysis/local-001/analysis.json \
  --section coverage --package com.example.app --limit 100

python3 scripts/query_results.py .dev/analysis/local-001/analysis.json \
  --section evidence --id EVIDENCE_ID
```

Available sections: `summary`, `apps`, `permissions`, `capabilities`, `endpoints`, `sdks`, `signals`, `findings`, `coverage`, and `evidence`. `summary` provides an unfilterable run overview; other sections support pagination, `--package`, `--id`, and `--contains`.

Pagination limits range from 1 to 500; inspect `total` to determine subsequent pages. URL query parameters, fragments, and credentials are redacted by default; `--include-sensitive` is reserved for authorized local inspection of original values.

## Re-exporting Reports

```sh
python3 scripts/export_report.py .dev/analysis/local-001/analysis.json \
  --output .dev/analysis/export-001 \
  --view-limit 200
```

Exports summary JSON, Markdown, all domain candidates, and telemetry domain candidates without re-running analysis or duplicating original `analysis.json`.

## Outputs and Exit Codes

| File | Meaning |
|---|---|
| `analysis.json` | Versioned machine-readable results including facts, evidence, coverage, and input paths; may contain sensitive original values |
| `summary.json` | Redacted summary with an overview of up to 20 applications |
| `report.md` | Base Markdown report with bounded table views (default 100 rows per table) |
| `domains.txt` | All extracted host and bare-domain candidates; may include documentation, package names, or test fixtures |
| `telemetry-domains.txt` | Telemetry host candidates supported by paths or SDK rules; does not prove actual upload |
| `artifacts/` | Input snapshots keyed by content hash |
| `device/` | Raw metadata snapshot from device mode; temporary downloaded APKs are cleared after snapshot creation |
| `sources/` | Decompiled source code from explicit `decompile` mode with jadx |

- `0`: Analysis or export completed; overall status may still be `PARTIAL`. Always check JSON status and coverage.
- `1`: Failure to complete analysis, tool crash, or input/output error; partially collected results may remain in the output directory.
- `2`: Command-line syntax error.
- `130`: Interrupted or cancelled; partial results are preserved where possible and marked `CANCELLED`.

Existing output directories are never overwritten. Historical reports, snapshots, and caches are not automatically purged.

## Resources and Caching

```sh
python3 scripts/analyze.py scan \
  --apk /path/to/base.apk \
  --jobs 2 \
  --timeout 300 \
  --max-entry-mib 128 \
  --max-total-mib 512 \
  --max-results 50000 \
  --cache-dir .dev/cache/static-analysis \
  --output .dev/analysis/budget-001
```

Default limits: maximum 1 GiB input APK, 128 MiB per entry, 512 MiB total inspected member bytes, 30,000 ZIP entries, 500,000 DEX/resource strings, 1 MiB per string, 50,000 endpoints/signals each, and 20 evidence items per endpoint. `--jobs` ranges from 1 to 8 (default: 2).

These limits are cooperative in-process budgets, not OS-level sandboxing. External jadx output does not have hard disk quotas; untrusted or oversized artifacts should be analyzed in dedicated restricted environments.

The cache defaults to a sibling `cache/` directory relative to the output directory. Cache keys incorporate input SHA-256, engine and rule versions, mode, and budgets. Duplicated content within a run is parsed only once. Failed, partial, or unreadable runs are not cached as successes; corrupt caches are discarded and recalculated. `--no-cache` disables analysis caching without skipping input snapshotting.

Integrity verification requires reading APK bytes. Input snapshots are captured per run to ensure subsequent evidence references the exact bytes analyzed.
