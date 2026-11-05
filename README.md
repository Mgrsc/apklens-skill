# Android Static Analysis Skill

[中文](README.zh-CN.md)

An Android static analysis Skill designed for AI Agents. Powered by a built-in, pure Python 3.10+ standard library deterministic engine, it enables AI to inspect application permissions, telemetry clues, SDKs, and network endpoints with zero third-party dependencies, JVM, or build steps—ideal for friction-free execution in any workspace or sandbox.

## Features

- **Zero-Dependency & Sandbox-Friendly**: Pure Python 3.10+ standard library implementation; zero third-party packages or complex runtimes, tailor-made for AI containers and restricted execution sandboxes.
- **Context-Friendly & Built-in Redaction**: Structured lightweight summaries and pagination prevent blowing model context windows, with automatic masking for network credentials and sensitive parameters.
- **Full Static Deconstruction**: Inspects single or multi-split APKs, extracting DEX references, resource string pools, manifest permissions, exported components, and candidate endpoints.
- **Device Snapshot Collection**: Reads one-time metadata and APK snapshots from authorized physical devices via ADB.
- **Durable Batch Analysis**: Checkpoints each artifact in standard-library SQLite, merges and exports from disk, and resumes interrupted tasks in a new directory. Saved collection snapshots support offline analysis without another APK copy.
- **Bounded Privacy Dataflow**: Tracks modeled sensitive sources through payloads, encoding/encryption, resolved methods and selected callbacks to network sinks; preserves unknown calls and resource limits as coverage gaps.
- **Strict Evidence Boundaries**: Separates E0–E2 clues from E3/E4 static possible paths, without claiming observed uploads or confirmed privacy violations.
- **Practical User Advice**: The AI assesses which apps to retain and restrict, uninstall if unwanted, or consider disabling after dependency review, explaining evidence, prerequisites, functional impact and recovery. Unknown state remains explicit.

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
- `analysis.json`: Machine-readable evidence export with E0–E4 findings and bounded method/field structure.
- `analysis.sqlite3`: Durable checkpoints and finalized facts; preferred input for large queries and re-exports.
- `snapshot.json` / `progress.json`: Reusable collection state and the latest execution milestone.
- `performance.json`: Local phase timings, resource peaks, effective configuration and code identity.
- `domains.txt` / `telemetry-domains.txt`: Normalized network endpoints and third-party telemetry domain candidates.

When analysis is performed through the Skill, the AI prepares a full `assessment.json` register, inspects evidence and records application-specific decisions, then validates and renders a separate `user-advice.md`. The [assessment contract](references/assessment.md) defines the CLI and review states. Validation PASS does not mean every app has been reviewed; pending, deferred and metadata-only targets remain explicit. The scripted `report.md` contains facts and review prompts. Query `--section apps --package PACKAGE` for saved installation context and bounded recommendation evidence samples. Recommendations do not authorize device changes or imply that a high review score makes an app safe to disable.

Use `summary.facts` for app-scope endpoint candidates, SDK match records/names/affected apps, permission origins and separate input/parse denominators. Do not add artifact and app totals. Summary and Markdown limits are display limits; paginate all targets using `has_more` / `next_offset`. System flags do not establish factory preload or user installation intent. Two-phase method retention and root quotas give later sensitive regions analysis opportunities while keeping omitted bodies, unstarted roots and model gaps visible.

For a large task, query `analysis.sqlite3` instead of loading the full JSON export. Databases index IDs, pages and evidence references; lightweight views avoid full scans for summaries. New tasks write database version 4 with shared immutable fact bodies and copy-on-write application updates, while JSON stays at schema 1; version 1/2/3 databases remain readable without migration. Recover with `python3 scripts/analyze.py scan --resume previous_task_dir --output new_task_dir`; keep referenced APKs and the previous directory intact. Recovery rebuilds application analysis and indexes in the new directory. See the usage reference for collection-only runs, offline snapshots and memory budgets.

For CPU-heavy batches on Linux, select `--executor process --jobs 2`; the default remains `thread`. Process workers use private result databases, a single final-database writer, task-tree RSS checks and bounded shutdown. They require additional memory and temporary I/O; compare local measurements for your workload. `--skip-analysis-json` explicitly omits the full JSON export while retaining SQLite and lightweight reports. Preflight estimates additional disk use and maintains a safety reserve; estimates and RSS limits are cooperative, not hard quotas. Preflight refuses to start analysis if free space is below the estimated additional peak plus a reserve of max(4 GiB, 20% of that peak), including small and metadata-only tasks; there is no override.

Endpoint records now contain explicit URLs/IPs and hosts with network context. Other dotted tokens are unknown, with counts and bounded provenance samples in coverage and `summary.facts.endpoints.selection`; fewer endpoint records do not establish reduced risk. Domain exports contain only retained network candidates.

The summary's `review_required_total` counts applications with declared capabilities or sensitive clues that need review, not proven privacy issues or transmission paths. Review priority counts distinct evidence-path and endpoint groups rather than condition variants; finding counts still reflect retained records. Each group retains at most four condition variants, with truncation marked partial. Retained method/field facts and interpretation limits are distinct; see [Privacy Models and Limits](references/privacy-analysis.md) for their budgets and shared E3/E4 coverage metrics.

Malformed or unsupported URL literals produce located dataflow gaps while analysis continues. Ordinary application-owned version fields alone do not trigger sensitive fingerprint review. Signal-derived capabilities retain their strongest evidence level; permission declarations remain E0.

## Documentation and References

- [Main Skill](SKILL.md): Local Agent execution rules, analysis workflow, and safety boundaries.
- [Online Bootstrap Skill](online-static-analysis/SKILL.md): Single-file online acquisition and handoff instructions.
- [Usage Reference](references/usage.md): Full CLI syntax, advanced filtering, options, and query examples.
- [Evidence and Coverage](references/evidence-and-coverage.md): E0–E4 evidence levels, decoding rules, and stage statuses.
- [Mobile Telemetry Blocking List](mobile-telemetry-domains.txt) (Chinese): Commented domains and hostname keywords for users to write blocking rules, grouped by service with exact, suffix and keyword match types.
- [Privacy Models and Limits](references/privacy-analysis.md): Supported sources, propagation, asynchronous handoffs, query examples and explicit stopping boundaries.
- [User Advice](references/user-advice.md): Criteria for retaining, restricting, uninstalling or considering disabling apps, with evidence, impact, recovery and unknowns.
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
