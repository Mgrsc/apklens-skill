import argparse
import json
import statistics
import tempfile
import threading
import time
from pathlib import Path

from performance import common, engine, memory_metrics, storage, support


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
    args = parser.parse_args()
    if min(args.records, args.repeats) < 1:
        parser.error("Counts must be positive")
    result = run(args)
    payload = json.dumps(result, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload + "\n", encoding="utf-8")
    print(payload)


if __name__ == "__main__":
    main()
