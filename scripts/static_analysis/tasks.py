import hashlib
import re
import shutil
from pathlib import Path

from .common import (
    AnalysisError,
    Cancelled,
    JsonRecordMapping,
    JsonRecords,
    atomic_json,
    available_memory,
    read_json,
    resident_bytes,
)

SNAPSHOT_VERSION = 1
MIB = 1024 * 1024
MEMORY_HEADROOM_RATIO = 0.6
WORKER_ENTRY_MULTIPLIER = 4
WORKER_OVERHEAD_BYTES = 128 * MIB
DATABASE_INPUT_MULTIPLIER = 3
MIN_DATABASE_BYTES = 64 * MIB
MIN_DISK_RESERVE_BYTES = 4096 * MIB
DISK_RESERVE_RATIO = 0.2
DEFAULT_CONFIGURATION = {
    "mode": "standard",
    "executor": "thread",
    "jobs": 2,
    "max_entry_mib": 128,
    "max_total_mib": 512,
    "max_results": 50000,
    "timeout": 300,
    "analysis_timeout": 1800,
    "memory_mib": None,
}


def snapshot_payload(configuration, artifacts, device, stages, complete, input_kind):
    return {
        "snapshot_version": SNAPSHOT_VERSION,
        "configuration": configuration,
        "input_kind": input_kind,
        "collection_complete": complete,
        "artifacts": artifacts,
        "device": {key: value for key, value in device.items() if key != "artifacts"}
        if device
        else None,
        "stages": stages,
    }


def save_snapshot(path, configuration, artifacts, device, stages, complete, input_kind):
    value = snapshot_payload(
        configuration, artifacts, device, stages, complete, input_kind
    )
    value["artifacts"] = JsonRecords(value["artifacts"], bounded=True)
    value["stages"] = JsonRecords(value["stages"], bounded=True)
    if value["device"]:
        if "packages" in value["device"]:
            value["device"]["packages"] = JsonRecordMapping(value["device"]["packages"])
        if "stages" in value["device"]:
            value["device"]["stages"] = JsonRecords(
                value["device"]["stages"], bounded=True
            )
    atomic_json(path, value)


def load_snapshot(path):
    path = Path(path).resolve()
    value = read_json(path)
    if (
        not isinstance(value, dict)
        or value.get("snapshot_version") != SNAPSHOT_VERSION
        or not isinstance(value.get("artifacts"), list)
        or not isinstance(value.get("configuration"), dict)
        or not isinstance(value.get("stages"), list)
        or not isinstance(value.get("collection_complete"), bool)
        or value.get("input_kind") not in {"device", "local_apk"}
        or (value.get("device") is not None and not isinstance(value["device"], dict))
    ):
        raise AnalysisError("Unsupported collection snapshot")
    for artifact in value["artifacts"]:
        if (
            not isinstance(artifact, dict)
            or not isinstance(artifact.get("sha256"), str)
            or not re.fullmatch(r"[a-f0-9]{64}", artifact["sha256"])
            or not isinstance(artifact.get("path"), str)
            or not isinstance(artifact.get("size"), int)
            or artifact["size"] < 0
        ):
            raise AnalysisError("Invalid artifact in collection snapshot")
        artifact_path = Path(artifact["path"])
        artifact["path"] = str((path.parent / artifact_path).resolve())
    return value


def restore_collection(snapshot):
    collections = [snapshot["stages"]]
    device = snapshot["device"]
    if device:
        collections.append(device["stages"])
        collections.extend(item["stages"] for item in device["packages"].values())
    for records in collections:
        for item in records:
            if item["status"] == "CANCELLED":
                item["original_status"] = "CANCELLED"
                item["status"] = "PARTIAL"


def verify_artifacts(artifacts, cancel):
    for artifact in artifacts:
        digest = hashlib.sha256()
        path = Path(artifact["path"])
        with path.open("rb") as handle:
            before = path.stat()
            while chunk := handle.read(MIB):
                if cancel.is_set():
                    raise Cancelled("Snapshot verification cancelled")
                digest.update(chunk)
            after = path.stat()
        if (
            before.st_size != artifact["size"]
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
            or digest.hexdigest() != artifact["sha256"]
        ):
            raise AnalysisError(f"Saved artifact identity changed: {path}")


def resource_plan(
    artifacts,
    output,
    limits,
    requested_jobs,
    memory_mib,
    write_analysis=True,
    resume_path=None,
    executor="thread",
):
    available = available_memory()
    resident = resident_bytes() or 0
    memory_bytes = (
        memory_mib * MIB
        if memory_mib
        else (
            resident + int(available * MEMORY_HEADROOM_RATIO)
            if available is not None
            else None
        )
    )
    worker_bytes = (
        limits.max_entry_bytes * WORKER_ENTRY_MULTIPLIER + WORKER_OVERHEAD_BYTES
    )
    jobs = min(requested_jobs, max(1, len({item["sha256"] for item in artifacts})))
    if memory_bytes:
        jobs = max(1, min(jobs, max(0, memory_bytes - resident) // worker_bytes))
    inputs = {item["sha256"]: item["size"] for item in artifacts}
    input_bytes = sum(inputs.values())
    database_bytes = max(MIN_DATABASE_BYTES, input_bytes * DATABASE_INPUT_MULTIPLIER)
    json_bytes = database_bytes // 2 if write_analysis else 0
    temporary_bytes = database_bytes // 2
    worker_spool_bytes = (
        sum(sorted(inputs.values(), reverse=True)[:jobs]) * DATABASE_INPUT_MULTIPLIER
        if executor == "process"
        else 0
    )
    recovery_bytes = 0
    if resume_path is not None:
        source = Path(resume_path) / "analysis.sqlite3"
        journal = Path(str(source) + "-journal")
        if source.is_file() and journal.is_file():
            recovery_bytes = source.stat().st_size + journal.stat().st_size
    additional_bytes = (
        database_bytes
        + json_bytes
        + temporary_bytes
        + worker_spool_bytes
        + recovery_bytes
    )
    reserve_bytes = max(
        MIN_DISK_RESERVE_BYTES, int(additional_bytes * DISK_RESERVE_RATIO)
    )
    available_disk = shutil.disk_usage(output).free
    if available_disk < additional_bytes + reserve_bytes:
        raise AnalysisError(
            f"Insufficient disk space: estimated additional peak {additional_bytes} bytes plus reserve {reserve_bytes} bytes, available {available_disk} bytes"
        )
    return {
        "artifact_count": len({item["sha256"] for item in artifacts}),
        "input_size_bytes": input_bytes,
        "available_memory_bytes": available,
        "memory_budget_bytes": memory_bytes,
        "available_disk_bytes": available_disk,
        "estimated_database_bytes": database_bytes,
        "estimated_json_bytes": json_bytes,
        "estimated_temporary_bytes": temporary_bytes,
        "estimated_worker_spool_bytes": worker_spool_bytes,
        "estimated_recovery_bytes": recovery_bytes,
        "estimated_additional_peak_bytes": additional_bytes,
        "disk_reserve_bytes": reserve_bytes,
        "disk_estimate_input_multiplier": DATABASE_INPUT_MULTIPLIER,
        "requested_jobs": requested_jobs,
        "jobs": jobs,
        "memory_guard_available": resident_bytes() is not None,
    }
