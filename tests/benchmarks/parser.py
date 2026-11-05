import argparse
import hashlib
import json
import os
import resource
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

from performance import SOURCE_ROOT, common, engine, memory_metrics, storage, support

VOLATILE_KEYS = frozenset(
    {"elapsed_seconds", "duration_ms", "started_at", "finished_at"}
)


def normalized(value):
    if isinstance(value, dict):
        return {
            key: normalized(item)
            for key, item in value.items()
            if key not in VOLATILE_KEYS
        }
    if isinstance(value, (list, tuple)):
        return [normalized(item) for item in value]
    return value


def logical_hashes(database):
    result = {}
    with_store = storage.AnalysisStore(database, readonly=True)
    try:
        for scope, owners, sections in (
            (
                "artifact",
                storage.ArtifactResults(with_store),
                storage.ARTIFACT_SECTIONS,
            ),
            (
                "app",
                [app["id"] for app in storage.Apps(with_store)],
                storage.APP_SECTIONS,
            ),
        ):
            for section in sections:
                digest = hashlib.sha256()
                count = 0
                for owner in sorted(owners):
                    for record in with_store.records(scope, owner, section):
                        digest.update(
                            json.dumps(
                                [owner, normalized(record)],
                                sort_keys=True,
                                ensure_ascii=True,
                                separators=(",", ":"),
                            ).encode()
                        )
                        digest.update(b"\n")
                        count += 1
                result[f"{scope}.{section}"] = {
                    "count": count,
                    "sha256": digest.hexdigest(),
                }
    finally:
        with_store.close()
    return result


def process_tree_rss(pid):
    pending = [pid]
    visited = set()
    total = 0
    while pending:
        current = pending.pop()
        if current in visited:
            continue
        visited.add(current)
        try:
            total += int(
                Path(f"/proc/{current}/statm").read_text().split()[1]
            ) * os.sysconf("SC_PAGE_SIZE")
            pending.extend(
                int(item)
                for item in Path(f"/proc/{current}/task/{current}/children")
                .read_text()
                .split()
            )
        except (OSError, ValueError, IndexError):
            continue
    return total


def run_real(args):
    corpus = json.loads(args.corpus.read_text())
    selected = corpus["benchmark_sets"][args.benchmark_set]
    snapshot = json.loads(args.snapshot.read_text())
    if "packages" in selected:
        packages = set(selected["packages"])
        snapshot["artifacts"] = [
            item
            for item in snapshot["artifacts"]
            if item.get("package_hint") in packages
        ]
        snapshot["device"]["packages"] = {
            key: value
            for key, value in snapshot["device"]["packages"].items()
            if key in packages
        }
        snapshot["device"]["selected_packages"] = sorted(packages)
    for item in snapshot["artifacts"]:
        item["path"] = str((args.snapshot.parent / item["path"]).resolve())
    task_root = args.task_root.resolve()
    task_root.mkdir(parents=True, exist_ok=False)
    saved = task_root / "input-snapshot.json"
    saved.write_text(json.dumps(snapshot, separators=(",", ":")) + "\n")
    samples = []
    for repeat in range(args.repeats):
        output = task_root / f"run-{repeat + 1}"
        command = [
            sys.executable,
            str(SOURCE_ROOT / "scripts/analyze.py"),
            "scan",
            "--snapshot",
            str(saved),
            "--output",
            str(output),
            "--no-cache",
            "--quiet",
            "--jobs",
            str(args.jobs),
        ]
        if args.executor:
            command.extend(["--executor", args.executor])
        if args.skip_analysis_json:
            command.append("--skip-analysis-json")
        before = resource.getrusage(resource.RUSAGE_CHILDREN)
        started = time.perf_counter()
        peak_rss = 0
        with (
            (task_root / f"run-{repeat + 1}.stdout").open("w") as stdout,
            (task_root / f"run-{repeat + 1}.stderr").open("w") as stderr,
        ):
            process = subprocess.Popen(
                command,
                stdout=stdout,
                stderr=stderr,
                env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
            )
            while process.poll() is None:
                peak_rss = max(peak_rss, process_tree_rss(process.pid))
                time.sleep(0.1)
        elapsed = time.perf_counter() - started
        after = resource.getrusage(resource.RUSAGE_CHILDREN)
        if process.returncode != 0:
            raise RuntimeError(
                f"Benchmark failed with exit code {process.returncode}; inspect {task_root}"
            )
        sample = {
            "repeat": repeat + 1,
            "wall_seconds": elapsed,
            "cpu_seconds": after.ru_utime
            + after.ru_stime
            - before.ru_utime
            - before.ru_stime,
            "process_tree_peak_rss_bytes": peak_rss,
            "database_bytes": (output / "analysis.sqlite3").stat().st_size,
            "output_bytes": sum(
                file.stat().st_size for file in output.rglob("*") if file.is_file()
            ),
            "logical_hashes": logical_hashes(output / "analysis.sqlite3"),
        }
        samples.append(sample)
        print(
            json.dumps(
                {key: value for key, value in sample.items() if key != "logical_hashes"}
            ),
            flush=True,
        )
    return {
        "source_root": str(SOURCE_ROOT),
        "benchmark_set": args.benchmark_set,
        "input": selected,
        "volatile_keys": sorted(VOLATILE_KEYS),
        "page_cache": "uncontrolled",
        "samples": samples,
        "median_seconds": statistics.median(item["wall_seconds"] for item in samples),
    }


def measured(operation, repeats):
    samples = []
    for repeat in range(repeats + 1):
        started = time.perf_counter()
        operation(repeat)
        if repeat:
            samples.append(time.perf_counter() - started)
    return {"median_seconds": statistics.median(samples), "samples": samples}


def run(args):
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        limits = common.Limits()
        artifacts = [
            common.snapshot_file(
                support.make_apk(
                    root / f"input-{index}.apk",
                    entries={
                        "classes.dex": support.make_dex(
                            [
                                f"https://example.org/app{index}/{item}/events"
                                for item in range(args.records)
                            ]
                        )
                    },
                ),
                root / "artifacts",
                limits,
                threading.Event(),
            )
            for index in range(4)
        ]

        def analyze(repeat, jobs, cache=None, resume=None):
            with_store = storage.AnalysisStore(
                root / f"task-{jobs}-{repeat}-{time.monotonic_ns()}.sqlite3"
            )
            try:
                results = engine.analyze_many(
                    artifacts,
                    limits,
                    "standard",
                    threading.Event(),
                    jobs,
                    cache,
                    lambda event: None,
                    store=with_store,
                    resume_store=resume,
                )
                assert len(results) == len(artifacts)
                assert all(
                    not result.get("resource_limited") for result in results.values()
                )
                return with_store.path
            finally:
                with_store.close()

        timings = {}
        for jobs in (1, 2, 4):
            timings[f"parse_and_checkpoint_jobs_{jobs}"] = measured(
                lambda repeat, workers=jobs: analyze(repeat, workers), args.repeats
            )
        cache = root / "cache"
        checkpoint = analyze(0, 2, cache=cache)
        timings["successful_cache_and_checkpoint"] = measured(
            lambda repeat: analyze(repeat, 2, cache=cache), args.repeats
        )
        with_store = storage.AnalysisStore(checkpoint, readonly=True)
        try:
            timings["checkpoint_import"] = measured(
                lambda repeat: analyze(repeat, 2, resume=with_store), args.repeats
            )
        finally:
            with_store.close()
        return {
            "records_per_dex": args.records,
            "artifact_count": len(artifacts),
            "repeats": args.repeats,
            "phases": timings,
            "memory": memory_metrics(),
            "page_cache": "uncontrolled",
        }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--records", type=int, default=3000)
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--corpus", type=Path)
    parser.add_argument("--snapshot", type=Path)
    parser.add_argument("--task-root", type=Path)
    parser.add_argument(
        "--benchmark-set",
        choices=("smoke", "development", "representative", "full"),
        default="smoke",
    )
    parser.add_argument("--jobs", type=int, default=2)
    parser.add_argument("--executor", choices=("thread", "process"))
    parser.add_argument("--skip-analysis-json", action="store_true")
    args = parser.parse_args()
    if min(args.records, args.repeats) < 1:
        parser.error("Counts must be positive")
    if args.corpus and not (args.snapshot and args.task_root):
        parser.error("Real benchmarks require --snapshot and --task-root")
    result = run_real(args) if args.corpus else run(args)
    payload = json.dumps(result, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload + "\n", encoding="utf-8")
    if args.corpus and args.output:
        print(
            json.dumps(
                {
                    "benchmark_set": args.benchmark_set,
                    "median_seconds": result["median_seconds"],
                    "output": str(args.output),
                }
            )
        )
    else:
        print(payload)


if __name__ == "__main__":
    main()
