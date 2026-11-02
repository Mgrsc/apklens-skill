import hashlib
import json
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path


class AnalysisError(Exception):
    pass


class Cancelled(AnalysisError):
    pass


class BudgetExceeded(AnalysisError):
    pass


@dataclass(frozen=True)
class Limits:
    max_apk_bytes: int = 1024 * 1024 * 1024
    max_entry_bytes: int = 128 * 1024 * 1024
    max_total_bytes: int = 512 * 1024 * 1024
    max_entries: int = 30000
    max_strings: int = 500000
    max_string_bytes: int = 1024 * 1024
    max_results: int = 50000
    max_evidence: int = 20
    max_references: int = 100000
    timeout: float = 300.0

    def signature(self):
        return asdict(self)


class Budget:
    def __init__(self, limits, cancel=None):
        self.limits = limits
        self.cancel = cancel or threading.Event()
        self.started = time.monotonic()

    def check(self):
        if self.cancel.is_set():
            raise Cancelled("Analysis cancelled")
        if time.monotonic() - self.started > self.limits.timeout:
            raise BudgetExceeded("Artifact time budget exceeded")


def stage(name, status="COMPLETE", source=None, reason=None, **metrics):
    result = {"stage": name, "status": status}
    if source is not None:
        result["source"] = source
    if reason:
        result["reason"] = reason
    if metrics:
        result["metrics"] = metrics
    return result


def aggregate_status(stages):
    states = {item["status"] for item in stages}
    if "CANCELLED" in states:
        return "CANCELLED"
    if states & {"FAILED", "PARTIAL", "UNAVAILABLE", "DEFERRED"}:
        return "PARTIAL"
    return "COMPLETE"


def stable_id(*values):
    payload = json.dumps(
        values, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    )
    return hashlib.sha256(payload.encode()).hexdigest()[:24]


def diagnostic(event, level="INFO", correlation_id=None, **fields):
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "level": level,
        "event": event,
        "service": "static_analysis",
        **fields,
    }
    if correlation_id:
        record["correlation_id"] = correlation_id
    print(json.dumps(record, ensure_ascii=True), file=sys.stderr, flush=True)


def atomic_text(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent, delete=False
        ) as handle:
            temporary = Path(handle.name)
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def atomic_json(path, value):
    atomic_text(
        path, json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    )


def read_json(path, max_bytes=256 * 1024 * 1024):
    path = Path(path)
    with path.open("rb") as handle:
        data = handle.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise AnalysisError("JSON input exceeds the supported size")
    return json.loads(data)


def snapshot_file(source, directory, limits, cancel):
    source = Path(source)
    if not source.is_file():
        raise AnalysisError(f"APK does not exist: {source}")
    directory.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    size = 0
    temporary = None
    try:
        with (
            source.open("rb") as incoming,
            tempfile.NamedTemporaryFile(dir=directory, delete=False) as outgoing,
        ):
            temporary = Path(outgoing.name)
            before = os.fstat(incoming.fileno())
            if before.st_size > limits.max_apk_bytes:
                raise BudgetExceeded("APK exceeds the input size budget")
            while chunk := incoming.read(1024 * 1024):
                if cancel.is_set():
                    raise Cancelled("Input collection cancelled")
                size += len(chunk)
                if size > limits.max_apk_bytes:
                    raise BudgetExceeded("APK exceeds the input size budget")
                digest.update(chunk)
                outgoing.write(chunk)
            after = os.fstat(incoming.fileno())
            if (before.st_size, before.st_mtime_ns) != (
                after.st_size,
                after.st_mtime_ns,
            ):
                raise AnalysisError("APK changed while it was being collected")
        identity = digest.hexdigest()
        destination = directory / f"{identity}.apk"
        os.replace(temporary, destination)
        return {
            "sha256": identity,
            "size": size,
            "path": str(destination),
            "input": str(source),
        }
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def run_command(
    arguments,
    timeout=30,
    cancel=None,
    max_output_bytes=16 * 1024 * 1024,
    watched_file=None,
    max_file_bytes=None,
):
    cancel = cancel or threading.Event()
    if cancel.is_set():
        return {
            "status": "CANCELLED",
            "reason": "Command cancelled before launch",
            "exit_code": None,
            "stdout": "",
            "stderr": "",
            "elapsed_seconds": 0.0,
        }
    started = time.monotonic()
    process = None
    status = "COMPLETE"
    reason = None
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        try:
            process = subprocess.Popen(
                arguments,
                stdout=stdout,
                stderr=stderr,
                stdin=subprocess.DEVNULL,
                start_new_session=os.name == "posix",
            )
            while process.poll() is None:
                if cancel.is_set():
                    status, reason = "CANCELLED", "Command cancelled"
                elif time.monotonic() - started > timeout:
                    status, reason = "FAILED", "Command timeout"
                elif (
                    os.fstat(stdout.fileno()).st_size
                    + os.fstat(stderr.fileno()).st_size
                    > max_output_bytes
                ):
                    status, reason = "PARTIAL", "Command output budget exceeded"
                elif (
                    watched_file
                    and Path(watched_file).exists()
                    and Path(watched_file).stat().st_size > max_file_bytes
                ):
                    status, reason = (
                        "FAILED",
                        "Collected file exceeds the input size budget",
                    )
                if reason:
                    break
                time.sleep(0.05)
        finally:
            if process is not None and process.poll() is None:
                if os.name == "posix":
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                else:
                    process.kill()
                process.wait()
        stdout.seek(0)
        stderr.seek(0)
        output = stdout.read(max_output_bytes + 1)
        errors = stderr.read(max_output_bytes + 1)
        if len(output) + len(errors) > max_output_bytes:
            status, reason = "PARTIAL", "Command output budget exceeded"
        if status == "COMPLETE" and process.returncode != 0:
            status, reason = "FAILED", "Command returned a nonzero exit code"
        return {
            "status": status,
            "reason": reason,
            "exit_code": process.returncode,
            "stdout": output[:max_output_bytes].decode("utf-8", "replace"),
            "stderr": errors[:max_output_bytes].decode("utf-8", "replace"),
            "elapsed_seconds": round(time.monotonic() - started, 3),
        }
