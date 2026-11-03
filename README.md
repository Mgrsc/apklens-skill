# Android Static Analysis Skill

[中文](README.zh-CN.md)

An Android static analysis Skill designed for AI Agents. Powered by a built-in, pure Python 3.10+ standard library deterministic engine, it enables AI to inspect application permissions, telemetry clues, SDKs, and network endpoints with zero third-party dependencies, JVM, or build steps—ideal for friction-free execution in any workspace or sandbox.

## Features

- **Zero-Dependency & Sandbox-Friendly**: Pure Python 3.10+ standard library implementation; zero third-party packages or complex runtimes, tailor-made for AI containers and restricted execution sandboxes.
- **Context-Friendly & Built-in Redaction**: Structured lightweight summaries and pagination prevent blowing model context windows, with automatic masking for network credentials and sensitive parameters.
- **Full Static Deconstruction**: Inspects single or multi-split APKs, extracting DEX references, resource string pools, manifest permissions, exported components, and candidate endpoints.
- **Device Snapshot Collection**: Reads one-time metadata and APK snapshots from authorized physical devices via ADB.
- **Durable Batch Analysis**: Checkpoints each artifact in standard-library SQLite, merges and exports from disk, and resumes interrupted tasks in a new directory. Saved collection snapshots support offline analysis without another APK copy.
- **Strict Evidence Boundaries**: Categorizes static evidence into levels E0–E2 without inferring unproven runtime dataflow or hallucinating privacy leaks.

## Quickstart

### Method 1: Remote / Zero-Install (Recommended)

No manual download is required. Send the following prompt and link to an AI with command execution and web access:

> Read and follow this Skill, prepare the project in my current workspace, then analyze the APK or authorized device I provide. Read the complete instructions before proceeding:
>
> https://github.com/Mgrsc/apklens-skill/blob/main/online-static-analysis/SKILL.md

The AI will fetch the project via [online-static-analysis/SKILL.md](online-static-analysis/SKILL.md), record the commit, and hand off execution to the main Skill. If the web page does not display the full content, the AI can read the [raw Markdown](https://raw.githubusercontent.com/Mgrsc/apklens-skill/main/online-static-analysis/SKILL.md).

### Method 2: Local Workspace

If you have cloned this repository into your local workspace, simply instruct your local AI assistant:

> Read [SKILL.md](SKILL.md) in this project root and follow its guidelines to analyze the APK or authorized device I provide.

- **Direct CLI Execution (Optional)**: Without an AI, you can also run the deterministic analysis script directly:
  ```sh
  python3 scripts/analyze.py scan --apk path/to/app.apk --output output_dir
  ```
- **Physical Device Analysis**: When analyzing a physical device, ensure USB or wireless debugging is enabled so that `adb devices -l` lists the device in state `device`. The AI will guide you through pairing and snapshot collection interactively.

## Output Artifacts

Upon completion, standard artifacts are generated in the output directory:

- `report.md`: Structured Markdown comprehensive audit report.
- `summary.json`: High-priority lightweight summary optimized for AI context consumption.
- `analysis.json`: Machine-readable full evidence database containing all E0–E2 facts and call sites.
- `analysis.sqlite3`: Durable checkpoints and finalized facts; preferred input for large queries and re-exports.
- `snapshot.json` / `progress.json`: Reusable collection state and the latest execution milestone.
- `domains.txt` / `telemetry-domains.txt`: Normalized network endpoints and third-party telemetry domain candidates.

For a large task, query `analysis.sqlite3` instead of loading the full JSON export. New databases index IDs, pages, and evidence references; lightweight views avoid repeated full scans for summaries and row-limited reports. Current scripts read database versions 1 and 2; new tasks write version 2 while JSON stays at schema 1. Recover with `python3 scripts/analyze.py scan --resume previous_task_dir --output new_task_dir`; keep referenced APKs and the previous directory intact. Recovery rebuilds derived indexes in the new directory. See the usage reference for collection-only runs, offline snapshots, memory budgets, and recovery of older tasks without manifests.

## Documentation and References

- [Main Skill](SKILL.md): Local Agent execution rules, analysis workflow, and safety boundaries.
- [Online Bootstrap Skill](online-static-analysis/SKILL.md): Single-file online acquisition and handoff instructions.
- [Usage Reference](references/usage.md): Full CLI syntax, advanced filtering, options, and query examples.
- [Evidence and Coverage](references/evidence-and-coverage.md): E0–E4 evidence levels, decoding rules, and stage statuses.
- [Implementation and Performance](references/implementation.md): Component ownership, pipeline architecture, and benchmarks.

## Development and Verification

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
```

With Ruff available:

```sh
ruff check --no-cache --target-version py310 scripts tests
ruff format --check --no-cache --target-version py310 scripts tests
```

## Contributing and License

- See [CONTRIBUTING.md](CONTRIBUTING.md).
- Distributed under the [MIT License](LICENSE).
