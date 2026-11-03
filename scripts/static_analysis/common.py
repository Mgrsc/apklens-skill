import hashlib
import json
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Mapping, Sequence
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

MEMORY_SAMPLE_SECONDS = 0.1
MEMORY_BUDGET_MESSAGE = "Process memory exceeds the cooperative memory budget"
JSON_BUFFER_CHARACTERS = 64 * 1024
JSON_READ_BYTES = 1024 * 1024
CHECKSUM_CHECK_INTERVAL = 1024
_memory_sample = (0.0, None)


def resident_bytes():
    global _memory_sample
    now = time.monotonic()
    if now - _memory_sample[0] < MEMORY_SAMPLE_SECONDS:
        return _memory_sample[1]
    try:
        value = int(Path("/proc/self/statm").read_text().split()[1]) * os.sysconf(
            "SC_PAGE_SIZE"
        )
    except (OSError, ValueError, IndexError, AttributeError):
        value = None
    _memory_sample = (now, value)
    return value


def available_memory():
    candidates = []
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemAvailable:"):
                candidates.append(int(line.split()[1]) * 1024)
    except (OSError, ValueError, IndexError):
        pass
    paths = {
        (Path("/sys/fs/cgroup"), "memory.max", "memory.current"),
        (
            Path("/sys/fs/cgroup/memory"),
            "memory.limit_in_bytes",
            "memory.usage_in_bytes",
        ),
    }
    try:
        for line in Path("/proc/self/cgroup").read_text().splitlines():
            _, controllers, relative = line.split(":", 2)
            if controllers and "memory" not in controllers.split(","):
                continue
            mount = Path("/sys/fs/cgroup/memory" if controllers else "/sys/fs/cgroup")
            directory = (mount / relative.lstrip("/")).resolve()
            while directory.is_relative_to(mount):
                paths.add(
                    (
                        directory,
                        "memory.limit_in_bytes" if controllers else "memory.max",
                        "memory.usage_in_bytes" if controllers else "memory.current",
                    )
                )
                if directory == mount:
                    break
                directory = directory.parent
    except (OSError, ValueError):
        pass
    for directory, limit_name, usage_name in paths:
        try:
            limit = (directory / limit_name).read_text().strip()
            if limit != "max":
                candidates.append(
                    max(0, int(limit) - int((directory / usage_name).read_text()))
                )
        except (OSError, ValueError):
            pass
    return min(candidates) if candidates else None


class AnalysisError(Exception):
    pass


class Cancelled(AnalysisError):
    pass


class BudgetExceeded(AnalysisError):
    pass


class MemoryBudgetExceeded(BudgetExceeded):
    pass


def check_resources(cancel=None, budget=None):
    if cancel is not None and cancel.is_set():
        raise Cancelled("Analysis cancelled")
    if budget is not None:
        budget.check()


def check_memory(memory_bytes):
    if memory_bytes:
        usage = resident_bytes()
        if usage is not None and usage > memory_bytes:
            raise MemoryBudgetExceeded(MEMORY_BUDGET_MESSAGE)


class TaskBudget:
    def __init__(self, limits, cancel):
        self.limits = limits
        self.cancel = cancel
        self.memory_exceeded = False

    def check(self):
        check_resources(self.cancel)
        try:
            check_memory(self.limits.memory_bytes)
        except MemoryBudgetExceeded:
            self.memory_exceeded = True
            self.cancel.set()
            raise


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
    memory_bytes: int | None = None

    def signature(self):
        return {
            key: value for key, value in asdict(self).items() if key != "memory_bytes"
        }


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
        check_memory(self.limits.memory_bytes)


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


@contextmanager
def atomic_writer(path, cancel=None, budget=None):
    check_resources(cancel, budget)
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent, delete=False
        ) as handle:
            temporary = Path(handle.name)
            yield handle
            check_resources(cancel, budget)
            handle.flush()
            os.fsync(handle.fileno())
        check_resources(cancel, budget)
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def atomic_text(path, value, cancel=None, budget=None):
    with atomic_writer(path, cancel=cancel, budget=budget) as handle:
        handle.write(value)


class JsonRecords(Sequence):
    def __init__(self, values):
        self.values = values

    def __len__(self):
        return len(self.values)

    def __getitem__(self, index):
        return self.values[index]

    def __iter__(self):
        return iter(self.values)


def json_chunks(value, cancel=None):
    if cancel is not None and cancel.is_set():
        raise Cancelled("Report export cancelled")
    if isinstance(value, Mapping):
        yield "{"
        separator = ""
        for key, item in value.items():
            yield separator
            yield json.dumps(key, ensure_ascii=False)
            yield ":"
            yield from json_chunks(item, cancel)
            separator = ","
        yield "}"
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        yield "["
        separator = ""
        for item in value:
            if cancel is not None and cancel.is_set():
                raise Cancelled("Report export cancelled")
            yield separator
            if isinstance(value, JsonRecords):
                yield json.dumps(
                    item, ensure_ascii=False, allow_nan=False, separators=(",", ":")
                )
            else:
                yield from json_chunks(item, cancel)
            separator = ","
        yield "]"
    else:
        yield json.dumps(value, ensure_ascii=False, allow_nan=False)


def atomic_json(path, value, cancel=None, budget=None):
    with atomic_writer(path, cancel=cancel, budget=budget) as handle:
        chunks = []
        characters = 0
        for chunk in json_chunks(value, cancel):
            chunks.append(chunk)
            characters += len(chunk)
            if characters >= JSON_BUFFER_CHARACTERS:
                check_resources(cancel, budget)
                handle.write("".join(chunks))
                chunks.clear()
                characters = 0
        if chunks:
            handle.write("".join(chunks))
        handle.write("\n")


def json_checksum(value, cancel=None, budget=None):
    check_resources(cancel, budget)
    digest = hashlib.sha256()
    encoder = json.JSONEncoder(sort_keys=True, ensure_ascii=True)
    chunks_until_check = CHECKSUM_CHECK_INTERVAL
    for chunk in encoder.iterencode(value):
        chunks_until_check -= 1
        if not chunks_until_check:
            check_resources(cancel, budget)
            chunks_until_check = CHECKSUM_CHECK_INTERVAL
        digest.update(chunk.encode())
    check_resources(cancel, budget)
    return digest.hexdigest()


def read_json(path, max_bytes=256 * 1024 * 1024, cancel=None, budget=None):
    check_resources(cancel, budget)
    path = Path(path)
    with path.open("rb") as handle:
        if os.fstat(handle.fileno()).st_size > max_bytes:
            raise AnalysisError("JSON input exceeds the supported size")
        data = bytearray()
        while chunk := handle.read(min(JSON_READ_BYTES, max_bytes - len(data) + 1)):
            check_resources(cancel, budget)
            data.extend(chunk)
            if len(data) > max_bytes:
                raise AnalysisError("JSON input exceeds the supported size")
    check_resources(cancel, budget)
    value = json.loads(data)
    check_resources(cancel, budget)
    return value


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
