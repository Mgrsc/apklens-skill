import argparse
import json
import shutil
import signal
import sys
import threading
import time
import uuid
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from static_analysis import ENGINE_VERSION, SCHEMA_VERSION
from static_analysis.common import (
    AnalysisError,
    Cancelled,
    Limits,
    aggregate_status,
    diagnostic,
    run_command,
    snapshot_file,
    stage,
)
from static_analysis.device import PACKAGE_PATTERN, DeviceCollector, parse_devices
from static_analysis.engine import analyze_many, build_apps, source_view
from static_analysis.reports import export_reports

LIMITATIONS = [
    "Only supplied or successfully collected APK artifacts are analyzed; inaccessible system services, firmware and dynamically delivered code are outside this result.",
    "Static evidence does not prove that collection or transmission occurred, or that every telemetry implementation was found.",
    "E0 denotes capability, E1 denotes a static clue, and E2 denotes a direct DEX string reference or invocation. E3 and E4 dataflow are not implemented.",
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
    scan.add_argument("--user", type=int, default=0)
    scan.add_argument("--package", action="append", default=[])
    scan.add_argument(
        "--output",
        type=Path,
        required=True,
        help="New output directory; existing directories are never overwritten",
    )
    scan.add_argument(
        "--mode", choices=("quick", "standard", "decompile"), default="standard"
    )
    scan.add_argument("--jobs", type=positive_int, default=2)
    scan.add_argument("--cache-dir", type=Path)
    scan.add_argument("--no-cache", action="store_true")
    scan.add_argument("--max-entry-mib", type=positive_int, default=128)
    scan.add_argument("--max-total-mib", type=positive_int, default=512)
    scan.add_argument("--max-results", type=positive_int, default=50000)
    scan.add_argument("--timeout", type=positive_int, default=300)
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
    validate_scan(args)
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=False)
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

    def progress(event):
        if not args.quiet:
            diagnostic(
                "analysis.artifact_completed",
                correlation_id=run_id,
                **{key: value for key, value in event.items() if key != "event"},
            )

    try:
        if args.device:
            collector = DeviceCollector(
                args.adb,
                args.device,
                args.user,
                args.output / "device",
                limits,
                cancel,
                args.adb_timeout,
            )
            try:
                snapshot = collector.collect(args.package)
                artifacts = snapshot["artifacts"]
                stages.extend(snapshot["stages"])
            except (AnalysisError, OSError) as error:
                snapshot = {
                    "serial": args.device,
                    "user": args.user,
                    "packages": collector.packages,
                    "installed_count": len(collector.packages),
                    "selected_packages": args.package,
                    "excluded_packages": [],
                    "stages": collector.stages,
                }
                artifacts = collector.artifacts
                stages.extend(collector.stages)
                stages.append(
                    stage("device_collection", "FAILED", args.device, str(error))
                )
        else:
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
        cache_directory = (
            None if args.no_cache else (args.cache_dir or args.output.parent / "cache")
        )
        results = analyze_many(
            artifacts, limits, args.mode, cancel, args.jobs, cache_directory, progress
        )
        if args.mode == "decompile":
            for identity, result in results.items():
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
        apps = build_apps(artifacts, results, snapshot, limits, args.mode)
        all_stages = stages + [item for app in apps for item in app["coverage"]]
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
                "started_at": started_at,
                "finished_at": datetime.now(timezone.utc).isoformat(),
                "elapsed_seconds": round(time.monotonic() - started, 3),
                "input_kind": "device" if args.device else "local_apk",
                "limits": asdict(limits),
                "jobs": args.jobs,
            },
            "stages": stages,
            "snapshot": snapshot_summary,
            "apps": apps,
            "artifacts": [
                {
                    **artifact,
                    "statistics": results[artifact["sha256"]].get("statistics", {}),
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
        files = export_reports(report, args.output)
        if not args.quiet:
            diagnostic(
                "analysis.completed",
                level="WARN" if status != "COMPLETE" else "INFO",
                correlation_id=run_id,
                status=status,
                duration_ms=round((time.monotonic() - started) * 1000),
                **report["totals"],
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
    finally:
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
    except (AnalysisError, OSError, ValueError) as error:
        diagnostic("analysis.failed", level="ERROR", status="FAILED", error=str(error))
        return 1


if __name__ == "__main__":
    sys.exit(main())
