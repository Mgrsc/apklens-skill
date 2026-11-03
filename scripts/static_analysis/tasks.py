import hashlib
import re
import shutil
from pathlib import Path

from .common import (
    AnalysisError,
    Cancelled,
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
DEFAULT_CONFIGURATION = {
    "mode": "standard",
    "jobs": 2,
    "max_entry_mib": 128,
    "max_total_mib": 512,
    "max_results": 50000,
    "timeout": 300,
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
    atomic_json(
        path,
        snapshot_payload(
            configuration, artifacts, device, stages, complete, input_kind
        ),
    )


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


def resource_plan(artifacts, output, limits, requested_jobs, memory_mib):
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
    jobs = requested_jobs
    if memory_bytes:
        jobs = max(1, min(jobs, max(0, memory_bytes - resident) // worker_bytes))
    return {
        "artifact_count": len({item["sha256"] for item in artifacts}),
        "input_size_bytes": sum(item["size"] for item in artifacts),
        "available_memory_bytes": available,
        "memory_budget_bytes": memory_bytes,
        "available_disk_bytes": shutil.disk_usage(output).free,
        "requested_jobs": requested_jobs,
        "jobs": jobs,
        "memory_guard_available": resident_bytes() is not None,
    }
