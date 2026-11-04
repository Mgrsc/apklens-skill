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

Artifacts are checkpointed in `analysis.sqlite3` as each parsing job returns, before application aggregation. Queries can use this database after a report has been finalized; if a task stops earlier, resume it first. The compatible `analysis.json` export retains `schema_version: 1` and is written incrementally rather than assembled into a single string.

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

## Offline Snapshots and Recovery

For a long device acquisition, check free disk space first. Acquisition and analysis may be separated explicitly:

```sh
python3 scripts/analyze.py scan \
  --device SERIAL --user 0 --collect-only \
  --output .dev/analysis/collection-001

python3 scripts/analyze.py scan \
  --snapshot .dev/analysis/collection-001/snapshot.json \
  --output .dev/analysis/offline-001
```

The snapshot records artifact hashes and paths, selected targets, collection stages, and captured device grants, AppOps, and special access. It is atomically updated after individual pulls and packages. `collection_complete` means acquisition reached its end, not that every pull or metadata lookup succeeded; inspect stage statuses. Offline analysis verifies saved APK sizes and SHA-256 hashes without copying them or contacting the device. Keep referenced task directories intact; missing or changed APKs fail verification. An interrupted collection remains partial, with uncollected targets explicitly represented rather than silently omitted.

When a saved collection is restored, historical `CANCELLED` stages become `PARTIAL` coverage gaps and retain `original_status: CANCELLED`. The source snapshot is unchanged. Only a cancellation of the current execution returns exit code `130`; the historical acquisition interruption does not cancel a completed offline analysis.

Resume parsing into a new directory:

```sh
python3 scripts/analyze.py scan \
  --resume .dev/analysis/offline-001 \
  --output .dev/analysis/resumed-001
```

- Stop the original task before resuming. Existing reports and artifacts are never overwritten. SQLite rollback recovery, when required after a crash, runs on a private temporary database copy in the new output directory; allow additional free space for that copy.
- Compatible `COMPLETE` and `PARTIAL` artifact checkpoints are reused. `FAILED`, `CANCELLED`, missing, and memory-interrupted checkpoints are retried. Add `--retry-incomplete` to retry other `PARTIAL` results; this verifies saved stage facts even if a previous import incorrectly recorded completion metadata. Source tasks remain unchanged.
- Mode, coverage budgets, requested concurrency, and explicit memory budget inherit from `snapshot.json` unless overridden. Changing semantic limits or mode invalidates the corresponding checkpoint/cache identity and triggers parsing again. An automatic memory budget is recalculated for the current host and does not invalidate compatible facts.
- External executables are never restored as implicit execution instructions. Pass `--jadx` explicitly when supplemental decompilation must be rerun. Changing the selected jadx path prevents reuse of completed supplemental results.
- A collection-only task can be passed to `--resume`; without a database, artifacts are parsed normally. `--snapshot` reuses acquisition only and does not import prior parsing checkpoints.
- Tasks created by older versions without `snapshot.json` cannot use this recovery entrypoint. Supply their local base/split APKs with repeated `--apk` and point `--cache-dir` to a known existing cache. That path creates fresh input snapshots; device state and partial parse results absent from durable outputs cannot be reconstructed from APKs.

Older interrupted scans could incorrectly save a `COMPLETE` checkpoint when cancellation skipped SDK matching. Such checkpoints contain no cancellation stage, so `--retry-incomplete` cannot identify them reliably. For a task known to be affected, rebuild parsing from its saved collection without importing checkpoints or reading analysis caches:

```sh
python3 scripts/analyze.py scan \
  --snapshot .dev/analysis/interrupted-001/snapshot.json \
  --no-cache \
  --output .dev/analysis/reparsed-001
```

This verifies and reuses the saved APKs and device snapshot, preserving the source task without contacting the device. Current scans check method/call signal loops and completion boundaries independently of caching, so cancellations produce retryable checkpoints.

## Supplemental Decompiled Source Analysis

```sh
python3 scripts/analyze.py scan \
  --apk /path/to/base.apk \
  --mode decompile \
  --jadx /path/to/jadx \
  --output .dev/analysis/decompile-001
```

This mode runs base static analysis, including bounded DEX E3/E4 models, then invokes jadx to decompile code and scan Java/Kotlin text line-by-line for endpoints and rule signals. Supplemental text contributes file/line clues, not E3/E4 evidence or proof of transmission. See [privacy models and limits](privacy-analysis.md).

If `--jadx` is omitted, base static analysis executes and the supplemental decompilation stage is marked `UNAVAILABLE`. Supplemental decompilation runs sequentially to avoid high concurrent memory usage; base artifact parsing uses a bounded worker pool. Decompiled text and rule findings are not cached.

## Querying Existing Results

```sh
python3 scripts/query_results.py .dev/analysis/local-001/analysis.sqlite3

python3 scripts/query_results.py .dev/analysis/local-001/analysis.sqlite3 \
  --section apps --offset 0 --limit 20

python3 scripts/query_results.py .dev/analysis/local-001/analysis.sqlite3 \
  --section apps --package com.example.app --limit 20

python3 scripts/query_results.py .dev/analysis/local-001/analysis.sqlite3 \
  --section endpoints --package com.example.app --limit 50

python3 scripts/query_results.py .dev/analysis/local-001/analysis.sqlite3 \
  --section coverage --package com.example.app --limit 100

python3 scripts/query_results.py .dev/analysis/local-001/analysis.sqlite3 \
  --section evidence --id EVIDENCE_ID

python3 scripts/query_results.py .dev/analysis/local-001/analysis.sqlite3 \
  --section findings --id FINDING_ID

python3 scripts/query_results.py .dev/analysis/local-001/analysis.sqlite3 \
  --section methods --package com.example.app --limit 50
```

Available sections: `summary`, `apps`, `permissions`, `capabilities`, `endpoints`, `sdks`, `signals`, `findings`, `methods`, `fields`, `coverage`, and `evidence`. `summary` provides an unfilterable run overview; other sections support pagination, `--package`, `--id`, and `--contains`. A finding's `evidence_ids` identify its supporting locations. Summary fields disclose important review totals and how many applications are outside the 20-app display cap; paginate to inspect all targets.

`apps` adds `installation` context and recorded `recommendations` to each application overview. Installation context includes the captured user/UID, installer, flags, shared UID, AppOps, special access and collection stages; raw paths and duplicate permission collections are omitted. Query `permissions` separately for grants. `installation=null` means no saved installation context. The projected `is_system` is unknown unless package metadata is `COMPLETE` and captured flags are nonempty; do not rely on a raw false system marker from a snapshot with missing metadata. Inspect `package_metadata_status` and stages. AppOps `default`, absent entries and unknown special access do not establish that access is allowed or denied.

Recommendation projections preserve the recorded action, change requirement and execution policy. Instead of expanding all finding IDs, they expose `finding_count`, up to three `finding_id_sample` values and `finding_ids_truncated`; page through `findings` for complete relevant evidence. The lightweight `summary` intentionally omits installation context and recommendations. These projections are computed when reading saved results, including supported older databases, without rewriting them or rerunning analysis.

Recorded actions and the Markdown action table are review prompts, not package-disabling decisions. AI assessments follow [User Advice](user-advice.md) and save a separate `user-advice.md` when running the Skill. The CLI alone does not generate a personalized action assessment. Neither installation classification nor a priority score proves that an app is safe to disable.

Pagination limits range from 1 to 500; inspect `has_more` and `next_offset` to continue until the selected scope is exhausted. `total` is the matching population, independent of the display limit. URL query parameters, fragments, and credentials are redacted by default; `--include-sensitive` is reserved for authorized local inspection of original values.

Use `summary.facts` and each application's `facts` for counting and coverage. Endpoint and SDK totals use app-scope records once, not artifact plus app records. SDK records, names and affected application groups have separate units. Permission records distinguish Manifest declarations and snapshot-only grants. Inventory targets, applications with/without APKs and artifact statuses use separate denominators. Tables report total/shown/not_shown; no display cap establishes the audit scope.

New SQLite databases apply exact IDs, counts, and pagination to indexed facts; evidence IDs use persisted references instead of rescanning every endpoint and signal. Summaries use committed lightweight application views, and Markdown stops reading display collections at the requested row limits. Substring filters preserve Unicode casefold behavior and can still scan candidates; known package scopes and exact IDs narrow that work. Deep offsets and exact counts can still traverse indexes. Legacy `analysis.json` remains accepted, but is loaded as a whole and rejected above 256 MiB; use the explicit `analysis.sqlite3` path for large reports. A database is authoritative only for its own task; the query command does not silently substitute a neighboring database for a requested JSON file.

New tasks write `store_version: 3`, including bounded method/field structure and path findings with compact views and evidence references committed alongside application facts. The existing version 1/2 readers remain, without a new migration framework. Resume writes version 3 in a new directory, checks engine/rule/model identities and rebuilds application analysis without modifying the source. Older programs do not read version 3 databases; JSON retains schema 1 and existing field meanings. Evidence references add disk space but do not duplicate evidence bodies.

## Preparing an Application Assessment

```sh
python3 scripts/assess_results.py prepare TASK/analysis.sqlite3 \
  --output TASK/assessment-draft

python3 scripts/assess_results.py validate TASK/analysis.sqlite3 \
  --assessment TASK/assessment-draft/assessment.json

python3 scripts/assess_results.py render TASK/analysis.sqlite3 \
  --assessment TASK/assessment-draft/assessment.json \
  --output TASK/assessment-final --language zh-CN
```

Fill the draft after inspecting each application's evidence. Preparation registers every group; validation checks identity, references, evidence levels, review states and action prerequisites. `PASS` / exit code 0 is structural validation, not a completed audit: inspect `outstanding_review`, `unavailable_code`, state counts and `analysis_status`. Rendering derives source counts and review states, and formats the AI-authored claim text and validated reference IDs into a separate `user-advice.md`, preserving the source report. It does not embed the cited evidence bodies or establish that free-text claims are justified; retrieve and inspect the referenced records. See the [assessment contract](assessment.md) for claim types, prerequisites, revision handling and publication review.

## Re-exporting Reports

```sh
python3 scripts/export_report.py .dev/analysis/local-001/analysis.sqlite3 \
  --output .dev/analysis/export-001 \
  --view-limit 200
```

Exports summary JSON, Markdown, all domain candidates, and telemetry domain candidates without re-running analysis or duplicating original `analysis.json`.

## Outputs and Exit Codes

| File | Meaning |
|---|---|
| `analysis.json` | Versioned machine-readable results including facts, evidence, coverage, and input paths; may contain sensitive original values |
| `analysis.sqlite3` | Durable artifact checkpoints, finalized facts, and query projections; preferred input for large queries and re-exports, with independent `store_version: 3` |
| `snapshot.json` | Reusable collection manifest, analysis configuration, artifact identities/paths, and available device state; may contain sensitive values |
| `progress.json` | Last task milestone; inspect database checkpoints and coverage for authoritative completion |
| `summary.json` | Redacted summary with an overview of up to 20 applications |
| `report.md` | Base Markdown report with bounded table views (default 100 rows per table) |
| `assessment.json` | Separate AI-filled application register, source-bound claims and conditional decisions; created by `assess_results.py` |
| `user-advice.md` | Advice rendered from the validated register; review completion and input gaps remain explicit |
| `domains.txt` | All extracted host and bare-domain candidates; may include documentation, package names, or test fixtures |
| `telemetry-domains.txt` | Telemetry host candidates supported by paths or SDK rules; does not prove actual upload |
| `artifacts/` | Input snapshots keyed by content hash |
| `device/` | Raw metadata snapshot from device mode; temporary downloaded APKs are cleared after snapshot creation |
| `sources/` | Decompiled source code from explicit `decompile` mode with jadx |

- `0`: Analysis or export completed; overall status may still be `PARTIAL`. Always check JSON status and coverage.
- `1`: Failure to complete analysis, tool crash, or input/output error; partially collected results may remain in the output directory.
- `2`: Command-line syntax error.
- `130`: Interrupted or cancelled; partial results are preserved where possible and marked `CANCELLED`.

A cooperative memory stop also interrupts dispatch and returns `130`; stdout and `progress.json` identify `stop_reason: memory_budget`. Missing jobs are checkpointed as cancelled, and resource-interrupted facts are retried on resume. Cancellation during aggregation or export stops further record processing and preserves committed checkpoints; final report files may be absent until the task is resumed. `done` progress counts returned jobs, not successful parsers: artifact events include status counts, persistence, and checkpoint reuse; application aggregation, export, and final completion have separate milestones. Per-artifact checkpoints commit before progress announces persistence.

The RSS guard also covers checkpoint imports, application aggregation, and report export, including tasks that reuse every artifact. A stop in these phases preserves valid committed artifact checkpoints without marking them as incomplete parsing results; an unfinished import or application transaction is rolled back. Fatal checkpoint or progress-write errors stop other workers cooperatively before returning the original failure with exit code `1`.

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
  --memory-mib 4096 \
  --cache-dir .dev/cache/static-analysis \
  --output .dev/analysis/budget-001
```

Default limits: maximum 1 GiB input APK, 128 MiB per entry, 512 MiB total inspected member bytes, 30,000 ZIP entries, 500,000 DEX/resource strings, 1 MiB per string, 50,000 endpoints/signals each, and 20 evidence items per endpoint. `--jobs` ranges from 1 to 8 (default: 2).

These limits are cooperative in-process budgets, not OS-level sandboxing. On Linux, process RSS is sampled and available host/cgroup memory informs a default budget with headroom; requested worker concurrency can be reduced conservatively. `--memory-mib` overrides the process RSS budget. On hosts without RSS sampling, preflight reports that the guard is unavailable. Native allocations, single large operations, external jadx, and concurrent memory users can exceed cooperative estimates. External jadx output does not have hard memory or disk quotas; untrusted or oversized artifacts should be analyzed in dedicated restricted environments.

Resource/XML string pools and DEX tables check cancellation, timeout, and RSS during parsing and at phase completion, including quick-mode non-instruction tables. String decoding also checks by processed byte volume to observe repeated-offset expansion. Memory stops preserve retryable checkpoints; class-scan timeouts retain the existing partial-coverage semantics.

The number of retained completed artifacts no longer determines the parser's live working set: worker results are committed to SQLite and released. Application merging, evidence deduplication, domain projection, and the JSON export stream records from disk, including for a large single application. This increases disk use: allow space for both SQLite facts and the compatible JSON export, plus retained APKs and any recovery copy. Do not use a fixed application count as a memory guarantee or disable resource protection when expanding coverage.

The cache defaults to a sibling `cache/` directory relative to the output directory. Cache keys incorporate input SHA-256, engine, rule and privacy-model versions, mode, and budgets. Duplicated content within a run is parsed only once. Failed, partial, or unreadable runs are not cached as successes; corrupt caches are discarded and recalculated. `--no-cache` disables analysis caching without skipping input snapshotting.

Cache entries and task checkpoints have different lifetimes: partial results still receive a transactional checkpoint even when ineligible for the successful-result cache. The checksum format remains unchanged; engine/rule/model identity changes invalidate prior analysis caches and checkpoints. Caches continue to load one artifact at a time with a 256 MiB JSON limit; an oversized or invalid cache is ignored and reparsed, rather than treated as completed evidence.

Integrity verification requires reading APK bytes. Input snapshots are captured per run to ensure subsequent evidence references the exact bytes analyzed.
