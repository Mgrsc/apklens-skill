import argparse
import json
import shutil
import signal
import sqlite3
import sys
import threading
import time
import uuid
from contextlib import ExitStack
from dataclasses import asdict, replace
from datetime import datetime, timezone
from itertools import chain
from pathlib import Path

from static_analysis import ENGINE_VERSION, SCHEMA_VERSION
from static_analysis.common import (
    AnalysisError,
    Cancelled,
    Limits,
    MemoryBudgetExceeded,
    TaskBudget,
    aggregate_status,
    atomic_json,
    check_resources,
    diagnostic,
    run_command,
    snapshot_file,
    stage,
)
from static_analysis.device import PACKAGE_PATTERN, DeviceCollector, parse_devices
from static_analysis.engine import analyze_many, build_apps, source_view
from static_analysis.privacy_models import MODEL_VERSION
from static_analysis.reports import export_reports
from static_analysis.rules import RULE_VERSION
from static_analysis.storage import AnalysisStore, artifact_status, checkpoint_source
from static_analysis.tasks import (
    DEFAULT_CONFIGURATION,
    load_snapshot,
    resource_plan,
    restore_collection,
    save_snapshot,
    verify_artifacts,
)

LIMITATIONS = [
    "Only supplied or successfully collected APK artifacts are analyzed; inaccessible system services, firmware and dynamically delivered code are outside this result.",
    "Static evidence does not prove that collection or transmission occurred, or that every telemetry implementation was found.",
    "E0 denotes capability, E1 denotes a static clue, E2 denotes a direct DEX reference, and E3/E4 denote bounded modeled intra/inter-method possible dataflow. Unknown calls, unsupported instructions and exhausted budgets remain coverage gaps.",
    "Entry reachability, default settings, cloud controls, authorization, actual uploads, capture duration, file retention and automatic reinstallation require separately authorized runtime evidence; this scan does not collect it.",
    "Resource string pools are inspected, but resource references, configuration qualifiers and effective network-security or backup policies are not resolved.",
    "Native analysis is limited to printable strings. Complex reflection, encrypted strings, arbitrary runtime construction and nested compressed assets are not fully resolved.",
    "Bare domains may be package names, documentation or examples. SDK and telemetry classifications are versioned heuristics, not observed network behavior.",
    "Device metadata is a non-atomic, user-scoped snapshot. Missing permission or AppOps entries are unknown, not denied or granted.",
    "Results and caches remain local, but sending evidence to a remote model is a separate disclosure. URL redaction is limited and does not remove every possible secret.",
]


def positive_int(value):
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("Value must be positive")
    return number


def build_parser():
    parser = argparse.ArgumentParser(
        description="Read-only Android static analysis using local scripts"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    doctor = commands.add_parser(
        "doctor",
        help="Inspect local executable availability without contacting a device",
    )
    doctor.add_argument("--adb", default="adb")
    doctor.add_argument("--jadx", default="jadx")
    devices = commands.add_parser(
        "devices", help="List devices using an explicitly requested ADB call"
    )
    devices.add_argument("--adb", default="adb")
    scan = commands.add_parser(
        "scan", help="Analyze supplied APK files or collect a one-time device snapshot"
    )
    sources = scan.add_mutually_exclusive_group(required=True)
    sources.add_argument(
        "--apk", action="append", type=Path, help="Repeat for each base or split APK"
    )
    sources.add_argument("--device", help="Explicit authorized device serial")
    sources.add_argument(
        "--snapshot",
        type=Path,
        help="Analyze a saved collection snapshot without contacting a device",
    )
    sources.add_argument(
        "--resume",
        type=Path,
        help="Reuse a previous task's snapshot and compatible checkpoints in a new output directory",
    )
    scan.add_argument("--user", type=int, default=0)
    scan.add_argument("--package", action="append", default=[])
    scan.add_argument(
        "--output",
        type=Path,
        required=True,
        help="New output directory; existing directories are never overwritten",
    )
    scan.add_argument("--mode", choices=("quick", "standard", "decompile"))
    scan.add_argument("--jobs", type=positive_int)
    scan.add_argument("--cache-dir", type=Path)
    scan.add_argument("--no-cache", action="store_true")
    scan.add_argument("--max-entry-mib", type=positive_int)
    scan.add_argument("--max-total-mib", type=positive_int)
    scan.add_argument("--max-results", type=positive_int)
    scan.add_argument("--timeout", type=positive_int)
    scan.add_argument(
        "--memory-mib",
        type=positive_int,
        help="Cooperative process RSS budget; default adapts to available host/cgroup memory",
    )
    scan.add_argument(
        "--collect-only",
        action="store_true",
        help="Persist a reusable collection snapshot without parsing APKs",
    )
    scan.add_argument(
        "--retry-incomplete",
        action="store_true",
        help="Also retry compatible PARTIAL checkpoints when resuming",
    )
    scan.add_argument("--adb-timeout", type=positive_int, default=120)
    scan.add_argument("--adb", default="adb")
    scan.add_argument(
        "--jadx",
        help="Explicit jadx executable for decompile mode; never downloaded automatically",
    )
    scan.add_argument("--quiet", action="store_true")
    return parser


def validate_scan(args):
    if args.output.exists():
        raise AnalysisError("Output directory already exists; choose a new directory")
    if args.user < 0 or args.jobs > 8:
        raise AnalysisError("User must be nonnegative and jobs must be between 1 and 8")
    if args.mode not in {"quick", "standard", "decompile"}:
        raise AnalysisError("Invalid analysis mode in saved configuration")
    for key in DEFAULT_CONFIGURATION:
        value = getattr(args, key)
        if (
            key != "mode"
            and not (key == "memory_mib" and value is None)
            and (type(value) is not int or value < 1)
        ):
            raise AnalysisError(f"Invalid analysis setting: {key}")
    if args.retry_incomplete and not args.resume:
        raise AnalysisError("Retrying incomplete checkpoints requires --resume")
    if args.device and (
        args.device.startswith("-")
        or any(character.isspace() or ord(character) < 32 for character in args.device)
    ):
        raise AnalysisError("Invalid device serial")
    if args.package and not args.device:
        raise AnalysisError("Package selection is supported only for a device input")
    if any(not PACKAGE_PATTERN.fullmatch(package) for package in args.package):
        raise AnalysisError("Invalid package name")
    for path in args.apk or []:
        if not path.is_file():
            raise AnalysisError(f"APK does not exist: {path}")
    if args.device and not shutil.which(args.adb):
        raise AnalysisError("ADB executable is unavailable")
    if args.jadx and args.mode != "decompile":
        raise AnalysisError("An explicit jadx executable requires decompile mode")
    if args.jadx and not shutil.which(args.jadx):
        raise AnalysisError("The requested jadx executable is unavailable")


def scan(args):
    saved = (
        load_snapshot(args.resume / "snapshot.json" if args.resume else args.snapshot)
        if args.resume or args.snapshot
        else None
    )
    for key, default in DEFAULT_CONFIGURATION.items():
        if getattr(args, key) is None:
            setattr(
                args,
                key,
                saved["configuration"].get(key, default) if saved else default,
            )
    validate_scan(args)
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=False)
    configuration = {key: getattr(args, key) for key in DEFAULT_CONFIGURATION}
    limits = Limits(
        max_entry_bytes=args.max_entry_mib * 1024 * 1024,
        max_total_bytes=args.max_total_mib * 1024 * 1024,
        max_results=args.max_results,
        timeout=float(args.timeout),
    )
    cancel = threading.Event()
    handlers = {}

    def interrupt(signum, frame):
        cancel.set()

    for signum in (signal.SIGINT, signal.SIGTERM):
        handlers[signum] = signal.signal(signum, interrupt)
    started = time.monotonic()
    run_id = uuid.uuid4().hex
    started_at = datetime.now(timezone.utc).isoformat()
    stages = []
    artifacts = []
    snapshot = None
    collection_complete = False
    input_kind = (
        saved["input_kind"] if saved else "device" if args.device else "local_apk"
    )
    store = None
    resume_store = None
    results = None
    task_budget = None
    resources = ExitStack()

    def stop_reason():
        if (task_budget is not None and task_budget.memory_exceeded) or (
            results is not None
            and any(result.get("resource_limited") for result in results.values())
        ):
            return "memory_budget"
        return "cancelled" if cancel.is_set() else None

    def progress(event):
        kind = event["event"]
        fields = {key: value for key, value in event.items() if key != "event"}
        atomic_json(
            args.output / "progress.json", {"run_id": run_id, "event": kind, **fields}
        )
        if not args.quiet:
            event_name = {
                "artifact_complete": "analysis.artifact_completed",
                "app_complete": "analysis.app_completed",
            }.get(kind, "analysis." + kind)
            diagnostic(event_name, correlation_id=run_id, **fields)

    def persist(complete=False):
        save_snapshot(
            args.output / "snapshot.json",
            configuration,
            artifacts,
            snapshot,
            stages,
            complete,
            input_kind,
        )

    def device_checkpoint(device, complete):
        save_snapshot(
            args.output / "snapshot.json",
            configuration,
            device["artifacts"],
            device,
            device["stages"],
            complete,
            "device",
        )

    try:
        if saved:
            restore_collection(saved)
            artifacts = saved["artifacts"]
            snapshot = saved["device"]
            stages = list(saved["stages"])
            collection_complete = saved["collection_complete"]
            persist(collection_complete)
            progress({"event": "verification_started", "total": len(artifacts)})
            verify_artifacts(artifacts, cancel)
            if not collection_complete:
                stages.append(
                    stage(
                        "input_collection",
                        "PARTIAL",
                        reason="Saved collection was interrupted; unavailable artifacts were not recollected",
                    )
                )
        elif args.device:
            persist()
            collector = DeviceCollector(
                args.adb,
                args.device,
                args.user,
                args.output / "device",
                limits,
                cancel,
                args.adb_timeout,
                checkpoint=device_checkpoint,
            )
            try:
                snapshot = collector.collect(args.package)
                collection_complete = not cancel.is_set()
            except (AnalysisError, OSError) as error:
                snapshot = collector.snapshot()
                stages.append(
                    stage("device_collection", "FAILED", args.device, str(error))
                )
            artifacts = snapshot["artifacts"]
            stages.extend(snapshot["stages"])
        else:
            persist()
            for path in args.apk:
                try:
                    artifacts.append(
                        snapshot_file(path, args.output / "artifacts", limits, cancel)
                    )
                    stages.append(stage("input_collection", source=str(path)))
                except (AnalysisError, OSError) as error:
                    stages.append(
                        stage(
                            "input_collection",
                            "CANCELLED" if isinstance(error, Cancelled) else "FAILED",
                            str(path),
                            str(error),
                        )
                    )
                persist()
            collection_complete = not cancel.is_set()
        if snapshot:
            for package in snapshot["selected_packages"]:
                snapshot["packages"].setdefault(
                    package,
                    {
                        "package": package,
                        "permissions": {},
                        "appops": {},
                        "special_access": {},
                        "stages": [
                            stage(
                                "artifact_collection",
                                "UNAVAILABLE",
                                package,
                                "Collection did not reach this package",
                            )
                        ],
                    },
                )
        persist(collection_complete)
        progress(
            {
                "event": "collection_completed",
                "artifacts": len(artifacts),
                "collection_complete": collection_complete,
            }
        )
        if args.collect_only:
            collection_stages = (
                chain(
                    stages,
                    (
                        item
                        for package in snapshot["packages"].values()
                        for item in package["stages"]
                    ),
                )
                if snapshot
                else stages
            )
            status = aggregate_status(collection_stages)
            if cancel.is_set():
                status = "CANCELLED"
            elif not artifacts:
                status = "FAILED"
            files = {"snapshot.json": str(args.output / "snapshot.json")}
            print(
                json.dumps(
                    {
                        "schema_version": SCHEMA_VERSION,
                        "status": status,
                        "totals": {"artifacts": len(artifacts)},
                        "files": files,
                    },
                    ensure_ascii=True,
                )
            )
            return 130 if status == "CANCELLED" else 1 if status == "FAILED" else 0
        plan = resource_plan(artifacts, args.output, limits, args.jobs, args.memory_mib)
        limits = replace(limits, memory_bytes=plan["memory_budget_bytes"])
        task_budget = TaskBudget(limits, cancel)
        progress({"event": "preflight", **plan})
        store = AnalysisStore(
            args.output / "analysis.sqlite3", cancel=cancel, budget=task_budget
        )
        resources.callback(store.close)
        store.set_metadata("configuration", configuration)
        store.connection.commit()
        if args.resume and (args.resume / "analysis.sqlite3").is_file():
            resume_store = resources.enter_context(
                checkpoint_source(args.resume / "analysis.sqlite3", args.output)
            )
        cache_directory = (
            None if args.no_cache else (args.cache_dir or args.output.parent / "cache")
        )
        results = analyze_many(
            artifacts,
            limits,
            args.mode,
            cancel,
            plan["jobs"],
            cache_directory,
            progress,
            store=store,
            resume_store=resume_store,
            retry_incomplete=args.retry_incomplete,
            source_tool=args.jadx,
        )
        if cancel.is_set():
            raise Cancelled("Artifact analysis interrupted; checkpoints preserved")
        task_budget.check()
        if args.mode == "decompile":
            progress({"event": "decompilation_started"})
            for identity in results:
                task_budget.check()
                result = results[identity]
                if result.get("source_view_complete"):
                    continue
                source_limited = False
                with store.connection:
                    if cancel.is_set():
                        result["stages"].append(
                            stage(
                                "source_view",
                                "CANCELLED",
                                identity,
                                "Decompiled source scan cancelled",
                            )
                        )
                    elif args.jadx:
                        artifact = next(
                            item for item in artifacts if item["sha256"] == identity
                        )
                        try:
                            extra = source_view(
                                artifact,
                                args.output / "sources" / identity,
                                args.jadx,
                                limits,
                                cancel,
                            )
                            for key in ("endpoints", "signals", "stages"):
                                result[key].extend(extra[key])
                            source_limited = extra["resource_limited"]
                        except OSError as error:
                            result["stages"].append(
                                stage("source_view", "FAILED", identity, str(error))
                            )
                    else:
                        result["stages"].append(
                            stage(
                                "source_view",
                                "UNAVAILABLE",
                                identity,
                                "Decompiled source scan requires an explicit --jadx executable",
                            )
                        )
                    store.update_artifact_metadata(
                        identity,
                        {
                            "source_view_complete": not cancel.is_set(),
                            "source_view_tool": args.jadx,
                            "resource_limited": result.get("resource_limited", False)
                            or source_limited,
                        },
                    )
        if cancel.is_set():
            raise Cancelled("Supplemental analysis interrupted; checkpoints preserved")
        progress({"event": "aggregation_started"})
        apps = build_apps(
            artifacts,
            results,
            snapshot,
            limits,
            args.mode,
            store=store,
            progress=progress,
        )
        all_stages = chain(stages, (item for app in apps for item in app["coverage"]))
        if cancel.is_set():
            status = "CANCELLED"
        elif not apps or not any(app["manifests"] for app in apps):
            status = "FAILED"
        else:
            status = aggregate_status(all_stages)
        snapshot_summary = (
            {
                key: value
                for key, value in snapshot.items()
                if key not in {"packages", "artifacts", "settings"}
            }
            if snapshot
            else None
        )
        report = {
            "schema_version": SCHEMA_VERSION,
            "engine_version": ENGINE_VERSION,
            "run": {
                "id": run_id,
                "status": status,
                "mode": args.mode,
                "rule_version": RULE_VERSION,
                "model_version": MODEL_VERSION,
                "started_at": started_at,
                "finished_at": datetime.now(timezone.utc).isoformat(),
                "elapsed_seconds": round(time.monotonic() - started, 3),
                "input_kind": input_kind,
                "limits": asdict(limits),
                "jobs": plan["jobs"],
                "resumed_from": str(args.resume.resolve()) if args.resume else None,
                "stop_reason": stop_reason(),
                "resource_plan": plan,
            },
            "stages": stages,
            "snapshot": snapshot_summary,
            "apps": apps,
            "artifacts": [
                {
                    **artifact,
                    "statistics": results[artifact["sha256"]].get("statistics", {}),
                    "status": artifact_status(results[artifact["sha256"]]),
                    "cache": results[artifact["sha256"]]["cache"],
                }
                for artifact in artifacts
            ],
            "totals": {
                "apps": len(apps),
                "artifacts": len({item["sha256"] for item in artifacts}),
                "endpoints": sum(len(app["endpoints"]) for app in apps),
                "findings": sum(len(app["findings"]) for app in apps),
                "cache_hits": sum(
                    result["cache"]["hit"] for result in results.values()
                ),
            },
            "limitations": LIMITATIONS,
        }
        store.save_report(report)
        progress({"event": "export_started", "status": status, **report["totals"]})
        files = export_reports(report, args.output, cancel=cancel, budget=task_budget)
        check_resources(cancel, task_budget)
        files["analysis.sqlite3"] = str(store.path)
        files["snapshot.json"] = str(args.output / "snapshot.json")
        progress(
            {
                "event": "completed",
                "status": status,
                "duration_ms": round((time.monotonic() - started) * 1000),
                **report["totals"],
            }
        )
        print(
            json.dumps(
                {
                    "schema_version": SCHEMA_VERSION,
                    "status": status,
                    "totals": report["totals"],
                    "files": files,
                },
                ensure_ascii=True,
            )
        )
        return 130 if status == "CANCELLED" else 1 if status == "FAILED" else 0
    except (Cancelled, MemoryBudgetExceeded) as error:
        reason = (
            "memory_budget"
            if isinstance(error, MemoryBudgetExceeded)
            else stop_reason() or "cancelled"
        )
        files = {"snapshot.json": str(args.output / "snapshot.json")}
        if store:
            files["analysis.sqlite3"] = str(store.path)
        progress({"event": "interrupted", "status": "CANCELLED", "stop_reason": reason})
        print(
            json.dumps(
                {
                    "schema_version": SCHEMA_VERSION,
                    "status": "CANCELLED",
                    "stop_reason": reason,
                    "files": files,
                },
                ensure_ascii=True,
            )
        )
        return 130
    finally:
        resources.close()
        for signum, handler in handlers.items():
            signal.signal(signum, handler)


def main():
    args = build_parser().parse_args()
    try:
        if args.command == "doctor":
            print(
                json.dumps(
                    {
                        "python": sys.version.split()[0],
                        "engine_version": ENGINE_VERSION,
                        "adb": shutil.which(args.adb),
                        "jadx": shutil.which(args.jadx),
                        "third_party_python_dependencies": [],
                        "device_contacted": False,
                    }
                )
            )
            return 0
        if args.command == "devices":
            result = run_command([args.adb, "devices", "-l"], timeout=15)
            print(
                json.dumps(
                    {
                        "status": result["status"],
                        "devices": parse_devices(result["stdout"]),
                        "reason": result["reason"],
                    }
                )
            )
            return 0 if result["status"] == "COMPLETE" else 1
        return scan(args)
    except Cancelled as error:
        diagnostic(
            "analysis.failed", level="WARN", status="CANCELLED", error=str(error)
        )
        return 130
    except (
        AnalysisError,
        OSError,
        ValueError,
        KeyError,
        TypeError,
        sqlite3.Error,
    ) as error:
        diagnostic("analysis.failed", level="ERROR", status="FAILED", error=str(error))
        return 1


if __name__ == "__main__":
    sys.exit(main())
