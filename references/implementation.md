# Implementation and Performance

## Entrypoints and Ownership

This directory can serve directly as the root of an independent repository. All paths below are relative to the project root containing `SKILL.md`.

```text
online-static-analysis/SKILL.md
  -> Acquire or reuse a recorded Git checkout
  -> Read the checkout's SKILL.md
SKILL.md
  -> scripts/analyze.py
     -> static_analysis/device.py
     -> static_analysis/common.py
     -> static_analysis/tasks.py / storage.py
     -> static_analysis/engine.py
        -> binary.py / manifest.py / endpoints.py / rules.py
     -> static_analysis/reports.py
  -> scripts/query_results.py
  -> scripts/export_report.py
```

| File | Ownership |
|---|---|
| `online-static-analysis/SKILL.md` | Single-file online bootstrap: acquire or reuse a specific checkout, then hand off to its main Skill |
| `analyze.py` | CLI commands, arguments, signals, tasks, collection and parsing orchestration, output |
| `device.py` | Read-only ADB interactions, package enumeration, permissions, shared UIDs, special access, split pulling |
| `common.py` | Budgets, statuses, input snapshots, atomic writes, process timeouts, structured diagnostics |
| `tasks.py` | Reusable collection manifests, saved input verification, configuration defaults, resource preflight |
| `storage.py` | Standard-library SQLite checkpoints, transactional application facts/views/evidence references, indexed record pages, isolated crash recovery |
| `binary.py` | Bounded binary XML, resource string pools, DEX parsing and instruction references |
| `manifest.py` | Permission declarations, components, application configurations, unparsed resource references |
| `endpoints.py` | Endpoint extraction, bounded decoding, normalization, provenance, limited redaction |
| `rules.py` | Versioned capability mappings, SDK fingerprints, API signals, telemetry events, diagnostic fields |
| `engine.py` | Artifact analysis, content caching, bounded worker pools, decompilation analysis, application aggregation |
| `reports.py` | Paginated queries, summaries, Markdown generation, domain projections from unified facts |

Base analysis relies solely on the Python standard library; device collection and optional decompiled source analysis use external processes. The `static-analysis` name in the Skill frontmatter serves as the capability identifier.

## Workflow

The online bootstrap entry clones code and documentation from `https://github.com/Mgrsc/apklens-skill.git` during initial setup and records the repository URL, commit SHA, and path; subsequent runs reuse this checkout. It does not duplicate rules or upload data. Updates require an explicit request into a fresh directory.

1. Validate inputs, device identifiers, and a new output directory; generate a task ID.
2. Capture content snapshots and SHA-256 hashes for local files; capture one-time metadata and pull readable APKs for device targets. Persist `snapshot.json` incrementally; snapshot/resume inputs verify saved bytes and reuse their paths offline.
3. Deduplicate artifacts by content hash within the run; process via a bounded worker pool of up to `jobs` workers.
4. Check the versioned cache. On a cache miss, read selected ZIP entries and parse manifests, DEX files, resources, and strings according to the selected mode.
5. Record endpoints, SDKs, signals, and stage statuses with stable evidence IDs and artifact provenance. Commit every returned artifact, including partial/failed results, to `analysis.sqlite3`, then release worker-owned results. Resume imports only checkpoints compatible with input identity, semantic budgets, mode, and supplemental tool selection.
6. When `decompile` mode and jadx are specified, run supplemental decompilation sequentially, scanning generated Java/Kotlin text for file and line matches; this supplements base analysis without upgrading to E3/E4 dataflow.
7. Aggregate by application identity using per-record SQLite merges, attaching permission snapshots, capabilities, findings, and coverage without building a full application evidence tree in memory. Commit compact application views, evidence references, and domain projections in the same transaction as finalized application facts.
8. Commit finalized report metadata. Generate the compatible JSON export incrementally, and project bounded summaries/Markdown and disk-deduplicated domains. Follow-up queries prefer SQLite facts without re-scanning or whole-report loading.

## Performance Tradeoffs

- Reads selected members directly from ZIP archives without decompressing entire APKs or running shell extractors on the device.
- Enumerates all DEX files matching entry name patterns; budget truncation or unsupported features are recorded explicitly.
- Base analysis produces no intermediate source files; jadx is invoked only when explicitly requested.
- Regular expressions are compiled at module load time; endpoint and signal matching rules remain deterministic.
- Parsed artifact facts are cached by content hash, engine version, budget, and mode; device grant states are never cached.
- Duplicated APKs within a run are parsed once; distinct runs still snapshot inputs.
- Default 2 requested worker threads overlap file I/O; preflight can reduce concurrency according to available memory and member-size estimates. CPU parsing is bounded by interpreter constraints. Linux RSS checks are cooperative, with separate headroom for SQLite and export work; they are not hard isolation.
- Summary views keep only the top 20 applications and read committed compact views. Markdown stops reading display collections at their row caps and uses single-pass signal statistics. New database queries apply exact IDs, counts, and pagination in SQLite; evidence queries follow persisted references to parent facts without rescanning all evidence. Reference uniqueness is per application, retaining the first endpoint/SDK/signal occurrence and existing order. Index construction adds disk space and one-time aggregation work.
- JSON serialization streams outer collections, encodes individual fact records together, and buffers a bounded number of characters. Finding ID projections read stored business keys without decoding whole findings. Cache checksums retain their existing incremental format. Legacy JSON reads retain their 256 MiB limit; caches read at most one bounded artifact JSON per worker.
- Substring filters retain Python Unicode casefold semantics and can scan candidates; exact IDs and package scopes narrow those candidates first. Exact totals and deep offsets still require index traversal. Version 1 databases remain readable through slower fallbacks without modifying their files.
- Bare-domain exclusion walks sorted URL intervals instead of comparing every domain with earlier domains. SDK domain evidence is limited to the first three matches and shared across DEX files within an artifact; type evidence retains its DEX provenance. Application finding generation uses a bounded per-application host-match cache.
- Device collection collects APKs first, then parses; pipelined producer-consumer processing is deferred until benchmarks justify the state complexity.

SQLite uses a bounded page cache and file-backed temporary work. Artifact checkpoints and applications commit independently; unfinished application aggregation is rebuilt from durable artifact facts. Source checkpoint reads hold a consistent transaction. If a hot rollback journal prevents read-only access after process death, recovery uses a temporary copy under the new task directory and preserves the original database/journal. Python 3.10 errors without numeric SQLite metadata may use the same private-copy recovery only when a rollback journal exists; known non-readonly error codes still propagate directly. Partial collection snapshots retain expected targets and never imply that missing grants or artifacts were observed.

Artifact status is derived from the stage records written in the same transaction, so importing one-shot record streams preserves partial, failed, and cancelled states. Requests to retry incomplete checkpoints verify the actual stage facts, including previously misclassified completion metadata, without modifying the source database.

`done` counts returned artifact jobs. Progress additionally records individual status counts, checkpoint persistence/reuse, and distinct collection, preflight, aggregation, export, and completion milestones. A soft memory stop halts further dispatch, preserves acquired facts, and marks pending work cancelled for a subsequent run.

Restored collection stages normalize historical cancellation to `PARTIAL`, retaining `original_status: CANCELLED` in the new snapshot and coverage without changing the source. Current execution cancellation remains distinct. A shared task RSS budget covers checkpoint import, application grouping/merging/projection, and exports without imposing a task-wide artifact timeout or changing cache identity. Stops roll back unfinished work and preserve valid committed artifact facts; the task records the memory stop separately from parser resource flags. Fatal scheduling or persistence exceptions signal and cancel outstanding workers before the executor waits, then propagate the original error.

Resource/XML string pools and DEX string, type, prototype, parameter, method, and class-data loops check the existing artifact budget at 256-item boundaries and phase completion. String decoding also checks after approximately 1 MiB of encoded string data, limiting unchecked expansion through repeated offsets. Class-scan timeouts retain partial facts through the existing gap path; cancellation and memory exceptions propagate to checkpoint and task handling. These checks retain RSS sampling and single-allocation limitations rather than providing a hard memory ceiling.

DEX method-ID and invocation signal matching reuse the bounded iteration checks. SDK matching checks its budget before completing, and artifact finalization records cancellation even when it skips SDK matching and never writes a cache. Cancellation preserves extracted facts without producing reusable successful checkpoints; memory stops retain their resource flag and partial status. Older checkpoints already missing both SDK results and cancellation stages cannot be distinguished from legitimate results; affected tasks must be reparsed from their saved snapshot with caching disabled, as described in the recovery instructions.

Caches store successful artifact facts only. Partial failures, unreadable files, or cancellations are never cached as successes. Cache writes use atomic file replacement with payload validation and cancellation checks between records. Rule updates require bumping `RULE_VERSION`; parser changes that alter extracted facts require bumping `ENGINE_VERSION`. Output-equivalent performance changes retain compatible successful caches. Known legacy DEX memory-interruption gaps are retried even when their original checkpoint omitted the resource flag.

Cache reads use bounded byte chunks, and payload checksums check cancellation, time, and RSS budgets during encoding. Admission estimates eight times the cache file size against available host/cgroup and process-budget headroom; a skipped cache remains untouched while its APK is parsed, and that run does not replace the skipped file. This is a conservative estimate, not a hard allocation bound: JSON decoding still occurs as one operation, and concurrent workers share process memory. Cache resource interruptions propagate instead of falling back as ordinary corruption, and write interruptions retain extracted facts. Report exports check cancellation across stages, domain rows, and atomic replacement; the CLI checks again before reporting completion. Committed analysis facts remain usable if export is interrupted. DEX checksum operations use views over the existing byte buffer without copying the full input.

## Scope

See [LICENSE](../LICENSE).

- Supports applications, permissions, manifests, URLs, SDKs, static signals, JSON/Markdown/domain exports, caching, and optional decompilation analysis.
- `priority` provides explainable review ordering; it does not represent breach probability or upload volume.
- Historical results are accessed through query scripts; no automatic package management or AppOps modification is performed.
- JSON contract follows `schema_version: 1`; existing output directories are never overwritten.
- New SQLite storage uses independent `store_version: 2`; reusable snapshots remain version `1`. Current scripts read version 1 databases without mutating them. Resume imports artifact facts into a new version 2 output and rebuilds application views and evidence indexes; it never migrates the source database in place. Version 2 databases require current scripts; schema 1 JSON remains available for existing JSON consumers. Older tasks without a collection manifest still use explicit local APK input and known successful-result caches.
- E3/E4 dataflow, complete resource evaluation, and cross-run diffing are currently unimplemented.

## Verification

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
ruff check --no-cache --target-version py310 scripts tests
ruff format --check --no-cache --target-version py310 scripts tests
git diff --check
```

Tests use synthetic XML, AXML, DEX, resources, and APKs alongside mocked ADB calls. They verify parser logic and boundaries without requiring live devices or commercial applications.

Repeatable synthetic performance probes use only the standard library:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 tests/benchmarks/performance.py --output .dev/benchmarks/postprocess.json
PYTHONDONTWRITEBYTECODE=1 python3 tests/benchmarks/parser.py --output .dev/benchmarks/parser.json
```

Each probe warms up once and defaults to five measured runs. Postprocessing reports phase times, record decodes, file hashes/sizes, and domain scaling; parser probes compare worker counts, successful caches, and checkpoint imports. Linux process RSS and VmHWM are reported separately from Python allocation profiling. OS page-cache state is uncontrolled. Synthetic results do not establish throughput or memory limits for real large APKs; include index construction and disk growth when assessing end-to-end gains.
