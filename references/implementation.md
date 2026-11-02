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
2. Capture content snapshots and SHA-256 hashes for local files; capture one-time metadata and pull readable APKs for device targets.
3. Deduplicate artifacts by content hash within the run; process via a bounded worker pool of up to `jobs` workers.
4. Check the versioned cache. On a cache miss, read selected ZIP entries and parse manifests, DEX files, resources, and strings according to the selected mode.
5. Record endpoints, SDKs, signals, and stage statuses with stable evidence IDs and artifact provenance.
6. When `decompile` mode and jadx are specified, run supplemental decompilation sequentially, scanning generated Java/Kotlin text for file and line matches; this supplements base analysis without upgrading to E3/E4 dataflow.
7. Aggregate by application identity, attaching permission snapshots, capabilities, findings, and coverage.
8. Generate output files from the unified result model. Follow-up queries read existing results without re-scanning.

## Performance Tradeoffs

- Reads selected members directly from ZIP archives without decompressing entire APKs or running shell extractors on the device.
- Enumerates all DEX files matching entry name patterns; budget truncation or unsupported features are recorded explicitly.
- Base analysis produces no intermediate source files; jadx is invoked only when explicitly requested.
- Regular expressions are compiled at module load time; endpoint and signal matching rules remain deterministic.
- Parsed artifact facts are cached by content hash, engine version, budget, and mode; device grant states are never cached.
- Duplicated APKs within a run are parsed once; distinct runs still snapshot inputs.
- Default 2 worker threads overlap file I/O; CPU parsing is bounded by interpreter constraints.
- Summary views cap applications at 20; queries paginate; Markdown reports enforce row caps. Base `analysis.json` is written and read as a whole, rejecting files over 256 MiB by default.
- Device collection collects APKs first, then parses; pipelined producer-consumer processing is deferred until benchmarks justify the state complexity.

Caches store successful artifact facts only. Partial failures, unreadable files, or cancellations are never cached as successes. Cache writes use atomic file replacement with payload validation. Rule updates require bumping `RULE_VERSION`; parser changes require bumping `ENGINE_VERSION`.

## Scope

See [LICENSE](../LICENSE).

- Supports applications, permissions, manifests, URLs, SDKs, static signals, JSON/Markdown/domain exports, caching, and optional decompilation analysis.
- `priority` provides explainable review ordering; it does not represent breach probability or upload volume.
- Historical results are accessed through query scripts; no automatic package management or AppOps modification is performed.
- JSON contract follows `schema_version: 1`; existing output directories are never overwritten.
- E3/E4 dataflow, complete resource evaluation, and cross-run diffing are currently unimplemented.

## Verification

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
ruff check --no-cache --target-version py310 scripts tests
ruff format --check --no-cache --target-version py310 scripts tests
git diff --check
```

Tests use synthetic XML, AXML, DEX, resources, and APKs alongside mocked ADB calls. They verify parser logic and boundaries without requiring live devices or commercial applications.
