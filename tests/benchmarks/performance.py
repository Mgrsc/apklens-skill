import argparse
import copy
import hashlib
import importlib
import json
import os
import sqlite3
import statistics
import sys
import tempfile
import threading
import time
from collections import Counter
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SOURCE_ROOT = Path(os.environ.get("APKLENS_BENCHMARK_SOURCE", ROOT)).resolve()
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(SOURCE_ROOT))
common = importlib.import_module("scripts.static_analysis.common")
engine = importlib.import_module("scripts.static_analysis.engine")
reports = importlib.import_module("scripts.static_analysis.reports")
storage = importlib.import_module("scripts.static_analysis.storage")
endpoints = importlib.import_module("scripts.static_analysis.endpoints")
support = importlib.import_module("support")
SIGNAL_TYPES = (
    "device_identifier",
    "network_api",
    "sensor_api",
    "telemetry_event",
    "diagnostic_field",
    "clipboard_api",
    "installed_apps_api",
    "cryptography",
    "dynamic_loading",
    "reflection",
)


def synthetic_result(template, app_index, split_index, count):
    identity = f"{app_index * 10000 + split_index:064x}"
    result = copy.deepcopy(template)
    result.update(
        sha256=identity,
        size=1,
        cache={"hit": False},
        cache_key=engine.cache_key(identity, common.Limits(), "standard"),
        stages=[common.stage("dex", source="classes.dex", artifact=identity)],
        statistics={"entries": 2},
    )
    result.pop("elapsed_seconds", None)
    result["manifest"]["package"] = f"com.example.app{app_index}"
    result["manifest"]["split"] = f"feature{split_index}" if split_index else None
    result["endpoints"] = []
    result["signals"] = []
    result["sdks"] = []
    for index in range(count):
        key = f"{app_index}-{split_index}-{index}"
        result["endpoints"].append(
            {
                "id": f"endpoint-{key}",
                "kind": "url",
                "value": f"https://events.sentry.io/{key}/events",
                "host": "events.sentry.io",
                "tags": ["telemetry_path_candidate"],
                "has_userinfo": False,
                "evidence_level": "E1",
                "evidence": [
                    {
                        "id": f"endpoint-evidence-{key}-{ordinal}",
                        "artifact": identity,
                        "entry": "classes.dex",
                        "kind": "dex_string",
                        "string_index": index,
                        "excerpt": "https://events.sentry.io/events",
                    }
                    for ordinal in range(3)
                ],
            }
        )
        result["signals"].append(
            {
                "id": f"signal-{key}",
                "type": SIGNAL_TYPES[index % len(SIGNAL_TYPES)],
                "evidence_level": "E2" if index % 2 else "E1",
                "evidence": [
                    {
                        "id": f"signal-evidence-{key}",
                        "artifact": identity,
                        "entry": "classes.dex",
                        "kind": "dex_invocation",
                        "excerpt": SIGNAL_TYPES[index % len(SIGNAL_TYPES)],
                    }
                ],
            }
        )
    return result


def build_fixture(root, app_count, record_count, split_count=1):
    cancel = threading.Event()
    limits = common.Limits()
    artifact = common.snapshot_file(
        support.make_apk(root / "input.apk"),
        root / "artifacts",
        limits,
        cancel,
    )
    template = engine.analyze_artifact(artifact, limits, "standard", cancel)
    store = storage.AnalysisStore(root / "analysis.sqlite3", cancel=cancel)
    artifacts = []
    started = time.perf_counter()
    for app_index in range(app_count):
        for split_index in range(split_count):
            result = synthetic_result(template, app_index, split_index, record_count)
            item = {"sha256": result["sha256"], "size": 1, "path": "synthetic.apk"}
            artifacts.append(item)
            store.save_artifact(item["sha256"], result)
    checkpoint_seconds = time.perf_counter() - started
    started = time.perf_counter()
    apps = engine.build_apps(
        artifacts,
        storage.ArtifactResults(store),
        None,
        limits,
        "standard",
        store=store,
    )
    merge_seconds = time.perf_counter() - started
    report = {
        "schema_version": 1,
        "engine_version": "1.0.0",
        "run": {"id": "performance-benchmark", "status": "PARTIAL", "mode": "standard"},
        "apps": apps,
        "artifacts": artifacts,
        "snapshot": None,
        "stages": [],
        "limitations": [],
        "totals": {
            "apps": len(apps),
            "artifacts": len(artifacts),
            "endpoints": app_count * record_count * split_count,
            "findings": sum(len(app["findings"]) for app in apps),
            "cache_hits": 0,
        },
    }
    store.save_report(report)
    return store, report, {"checkpoint": checkpoint_seconds, "merge": merge_seconds}


def memory_metrics():
    try:
        values = {}
        for line in Path("/proc/self/status").read_text().splitlines():
            name, _, value = line.partition(":")
            if name in {"VmRSS", "VmHWM"}:
                values[name] = int(value.split()[0]) * 1024
        return values
    except OSError:
        return {}


def file_checksum(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def benchmark_operations(report, root, suffix):
    return {
        "endpoints_limit_1": lambda: reports.query(report, "endpoints", limit=1),
        "endpoint_exact_id": lambda: reports.query(
            report, "endpoints", identity=f"endpoint-{suffix}", limit=1
        ),
        "evidence_exact_id": lambda: reports.query(
            report,
            "evidence",
            identity=f"signal-evidence-{suffix}",
            limit=1,
        ),
        "apps_limit_1": lambda: reports.query(report, "apps", limit=1),
        "summary": lambda: reports.summary(report),
        "markdown_limit_1": lambda: reports.markdown(report, limit=1),
        "markdown_limit_100": lambda: reports.markdown(report, limit=100),
        "full_export": lambda: reports.export_reports(report, root / "export"),
        "record_json": lambda: common.atomic_json(
            root / "records.json", report["apps"][0]["endpoints"]
        ),
    }


def run(args):
    phases = {}
    decodes = {}
    sizes = {}
    digests = {}
    for repeat in range(args.repeats + 1):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store, report, setup = build_fixture(
                root, args.apps, args.records, args.splits
            )
            try:
                suffix = f"{args.apps - 1}-{args.splits - 1}-{args.records - 1}"
                operations = benchmark_operations(report, root, suffix)
                timings = dict(setup)
                counts = Counter()
                original_loads = json.loads

                def audited_loads(
                    payload, *values, _loads=original_loads, _counts=counts, **options
                ):
                    value = _loads(payload, *values, **options)
                    if isinstance(value, dict) and any(
                        key in value for key in ("evidence", "evidence_ids", "stage")
                    ):
                        _counts["records"] += 1
                    return value

                for name, operation in operations.items():
                    counts.clear()
                    started = time.perf_counter()
                    with patch.object(
                        storage,
                        "json",
                        SimpleNamespace(loads=audited_loads, dumps=json.dumps),
                    ):
                        operation()
                    timings[name] = time.perf_counter() - started
                    decodes[name] = dict(counts)
                if repeat:
                    for name, seconds in timings.items():
                        phases.setdefault(name, []).append(seconds)
                sizes = {
                    "database_bytes": store.path.stat().st_size,
                    "json_bytes": (root / "export/analysis.json").stat().st_size,
                }
                digests = {
                    path.name: file_checksum(path)
                    for path in sorted((root / "export").iterdir())
                }
            finally:
                store.close()
    domains = {}
    for count in (1000, 2000, 4000, 8000):
        value = " ".join(f"host{index}.example.org" for index in range(count))
        samples = []
        for repeat in range(args.repeats + 1):
            collector = endpoints.EndpointCollector(common.Limits())
            started = time.perf_counter()
            collector.add_text(
                value,
                {
                    "artifact": "synthetic",
                    "entry": "domains.txt",
                    "kind": "asset_strings",
                },
            )
            seconds = time.perf_counter() - started
            assert len(collector.results()) == count
            if repeat:
                samples.append(seconds)
        domains[str(count)] = {
            "median_seconds": statistics.median(samples),
            "samples": samples,
        }
    return {
        "configuration": vars(args)
        | {
            "output": str(args.output) if args.output else None,
            "source_root": str(SOURCE_ROOT),
            "python": sys.version,
            "sqlite": sqlite3.sqlite_version,
            "page_cache": "uncontrolled",
        },
        "phases": {
            name: {"median_seconds": statistics.median(samples), "samples": samples}
            for name, samples in phases.items()
        },
        "decoded_records": decodes,
        "sizes": sizes,
        "digests": digests,
        "domains": domains,
        "memory": memory_metrics(),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--apps", type=int, default=10)
    parser.add_argument("--records", type=int, default=1000)
    parser.add_argument("--splits", type=int, default=1)
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if min(args.apps, args.records, args.splits, args.repeats) < 1:
        parser.error("Counts must be positive")
    result = run(args)
    payload = json.dumps(result, ensure_ascii=True, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload + "\n", encoding="utf-8")
    print(payload)


if __name__ == "__main__":
    main()
