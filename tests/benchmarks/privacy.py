import argparse
import gc
import hashlib
import importlib
import json
import resource
import statistics
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests"))
from privacy_fixtures import IDENTITY, privacy_dex, transmission
from support import make_apk


def measure(source, count, repeats):
    sys.path.insert(0, str(source))
    common = importlib.import_module("scripts.static_analysis.common")
    engine = importlib.import_module("scripts.static_analysis.engine")
    storage = importlib.import_module("scripts.static_analysis.storage")
    reports = importlib.import_module("scripts.static_analysis.reports")
    data = privacy_dex(
        [
            {
                "signature": f"Lsample/App;->run{index}(Landroid/telephony/TelephonyManager;)V",
                "code": [
                    ("invoke", IDENTITY, [7], False),
                    ("result", 0),
                    *transmission(),
                    0x0E,
                ],
            }
            for index in range(count)
        ]
    )
    runs = []
    for iteration in range(repeats + 1):
        gc.collect()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cancel = threading.Event()
            limits = common.Limits()
            artifact = common.snapshot_file(
                make_apk(root / "input.apk", entries={"classes.dex": data}),
                root / "artifacts",
                limits,
                cancel,
            )
            started = time.perf_counter()
            result = engine.analyze_artifact(artifact, limits, "standard", cancel)
            parsed = time.perf_counter()
            store = storage.AnalysisStore(root / "analysis.sqlite3", cancel=cancel)
            try:
                store.save_artifact(artifact["sha256"], result)
                persisted = time.perf_counter()
                del result
                apps = engine.build_apps(
                    [artifact],
                    storage.ArtifactResults(store),
                    None,
                    limits,
                    "standard",
                    store=store,
                )
                analyzed = time.perf_counter()
                flows = sum(
                    item["type"] == "privacy_transmission_path"
                    for app in apps
                    for item in app["findings"]
                )
                report = {
                    "schema_version": 1,
                    "engine_version": "benchmark",
                    "run": {
                        "id": "privacy-benchmark",
                        "status": "PARTIAL",
                        "mode": "standard",
                    },
                    "apps": apps,
                    "artifacts": [artifact],
                    "snapshot": None,
                    "stages": [],
                    "limitations": [],
                    "totals": {
                        "apps": len(apps),
                        "artifacts": 1,
                        "endpoints": sum(len(app["endpoints"]) for app in apps),
                        "findings": sum(len(app["findings"]) for app in apps),
                        "cache_hits": 0,
                    },
                }
                store.save_report(report)
                reports.export_reports(report, root / "exports")
                exported = time.perf_counter()
                coverage = [
                    item
                    for app in apps
                    for item in app["coverage"]
                    if item["stage"]
                    in {"method_dataflow_E3", "interprocedural_dataflow_E4"}
                ]
                run = {
                    "parse_seconds": parsed - started,
                    "persist_seconds": persisted - parsed,
                    "analysis_seconds": analyzed - persisted,
                    "export_seconds": exported - analyzed,
                    "total_seconds": exported - started,
                    "flows": flows,
                    "database_bytes": store.path.stat().st_size,
                    "json_bytes": (root / "exports/analysis.json").stat().st_size,
                }
                if iteration:
                    runs.append(run)
            finally:
                store.close()
    medians = {key: statistics.median(item[key] for item in runs) for key in runs[0]}
    return {
        "methods": count,
        "input_dex_sha256": hashlib.sha256(data).hexdigest(),
        "dataflow_coverage": coverage,
        "repeats": repeats,
        "medians": medians,
        "peak_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        "runs": runs,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, default=ROOT)
    parser.add_argument("--methods", type=int, default=100)
    parser.add_argument("--repeats", type=int, default=5)
    args = parser.parse_args()
    if not 1 <= args.methods <= 1000 or not 1 <= args.repeats <= 10:
        parser.error("Methods must be 1..1000 and repeats must be 1..10")
    print(json.dumps(measure(args.source, args.methods, args.repeats), sort_keys=True))


if __name__ == "__main__":
    main()
