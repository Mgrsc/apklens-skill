import errno
import hashlib
import json
import os
import shutil
import signal
import stat
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
DISK_BUDGET_SAMPLE_SECONDS = 1.0
MEMORY_BUDGET_MESSAGE = "Process memory exceeds the cooperative memory budget"
JSON_BUFFER_CHARACTERS = 64 * 1024
JSON_READ_BYTES = 1024 * 1024
JSON_RECORD_CHARACTERS = 1024 * 1024
JSON_RECORD_ITEMS = 16384
JSON_SCALAR_CHARACTERS = 64
CHECKSUM_CHECK_INTERVAL = 1024
LINK_UNSUPPORTED_ERRORS = {
    errno.EXDEV,
    errno.EPERM,
    errno.EOPNOTSUPP,
    errno.ENOSYS,
    errno.EMLINK,
}
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


def process_tree_rss(pid=None):
    pending = [os.getpid() if pid is None else pid]
    visited = set()
    total = 0
    observed = False
    while pending:
        current = pending.pop()
        if current in visited:
            continue
        visited.add(current)
        try:
            total += int(
                Path(f"/proc/{current}/statm").read_text().split()[1]
            ) * os.sysconf("SC_PAGE_SIZE")
            observed = True
            for task in Path(f"/proc/{current}/task").iterdir():
                try:
                    pending.extend(
                        int(item) for item in (task / "children").read_text().split()
                    )
                except (OSError, ValueError):
                    continue
        except (OSError, ValueError, IndexError, AttributeError):
            continue
    return total if observed else None


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


class DiskBudgetExceeded(BudgetExceeded):
    pass


class AnalysisDeadline:
    def __init__(self, seconds):
        self.seconds = seconds
        self.started = time.monotonic()
        self.exhausted = False

    def remaining(self):
        remaining = max(0.0, self.seconds - (time.monotonic() - self.started))
        self.exhausted |= remaining == 0
        return remaining

    def expired(self):
        return self.remaining() == 0


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
    def __init__(
        self, limits, cancel, disk_path=None, min_free_bytes=0, process_tree=False
    ):
        self.limits = limits
        self.cancel = cancel
        self.memory_exceeded = False
        self.disk_exceeded = False
        self.disk_path = disk_path
        self.min_free_bytes = min_free_bytes
        self.next_disk_check = 0.0
        self.process_tree = process_tree
        self.next_memory_check = 0.0

    def check(self):
        check_resources(self.cancel)
        try:
            if self.process_tree:
                if time.monotonic() >= self.next_memory_check:
                    self.next_memory_check = time.monotonic() + MEMORY_SAMPLE_SECONDS
                    usage = process_tree_rss()
                    if usage is None:
                        raise AnalysisError(
                            "Process tree memory sampling is unavailable"
                        )
                    if self.limits.memory_bytes and usage > self.limits.memory_bytes:
                        raise MemoryBudgetExceeded(
                            "Task process tree exceeds the cooperative memory budget"
                        )
            else:
                check_memory(self.limits.memory_bytes)
        except MemoryBudgetExceeded:
            self.memory_exceeded = True
            self.cancel.set()
            raise
        self.check_disk()

    def check_disk(self):
        if self.disk_path is not None and time.monotonic() >= self.next_disk_check:
            self.next_disk_check = time.monotonic() + DISK_BUDGET_SAMPLE_SECONDS
            if shutil.disk_usage(self.disk_path).free < self.min_free_bytes:
                self.disk_exceeded = True
                self.cancel.set()
                raise DiskBudgetExceeded(
                    "Available disk space fell below the task safety reserve"
                )


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
    def __init__(self, values, bounded=False):
        self.values = values
        self.bounded = bounded

    def __len__(self):
        return len(self.values)

    def __getitem__(self, index):
        return self.values[index]

    def __iter__(self):
        return iter(self.values)


class JsonRecordMapping(Mapping):
    def __init__(self, values):
        self.values = values

    def __len__(self):
        return len(self.values)

    def __iter__(self):
        return iter(self.values)

    def __getitem__(self, key):
        return self.values[key]


def bounded_record(value, cancel=None):
    pending = [value]
    characters = 0
    items = 0
    while pending:
        if cancel is not None and cancel.is_set():
            raise Cancelled("Report export cancelled")
        current = pending.pop()
        items += 1
        if type(current) is dict:
            if items + len(pending) + 2 * len(current) > JSON_RECORD_ITEMS:
                return False
            pending.extend(current.keys())
            pending.extend(current.values())
        elif type(current) in (list, tuple):
            if items + len(pending) + len(current) > JSON_RECORD_ITEMS:
                return False
            pending.extend(current)
        elif type(current) is str:
            characters += len(current) * 6
        elif type(current) in (int, float, bool, type(None)):
            characters += JSON_SCALAR_CHARACTERS
        else:
            return False
        if (
            characters > JSON_RECORD_CHARACTERS
            or items + len(pending) > JSON_RECORD_ITEMS
        ):
            return False
    return True


def record_chunks(value, cancel=None):
    if bounded_record(value, cancel):
        yield json.dumps(
            value, ensure_ascii=False, allow_nan=False, separators=(",", ":")
        )
    else:
        if type(value) is dict:
            value = JsonRecordMapping(value)
        elif type(value) in (list, tuple):
            value = JsonRecords(value, bounded=True)
        yield from json_chunks(value, cancel)


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
            if isinstance(value, JsonRecordMapping):
                yield from record_chunks(item, cancel)
            else:
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
                if getattr(value, "bounded", False):
                    yield from record_chunks(item, cancel)
                else:
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
            tempfile.NamedTemporaryFile(
                dir=directory, suffix=".apk", delete=False
            ) as outgoing,
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
        destination = publish_snapshot(
            temporary, destination, identity, size, limits, cancel
        )
        if destination == temporary:
            temporary = None
        return {
            "sha256": identity,
            "size": size,
            "path": str(destination),
            "input": str(source),
        }
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def file_identity(value):
    return (
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def hash_regular_file(source, limits, cancel):
    before_path = source.lstat()
    if not stat.S_ISREG(before_path.st_mode):
        raise AnalysisError("Collected APK is not a regular private file")
    descriptor = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as incoming:
        before = os.fstat(incoming.fileno())
        if file_identity(before) != file_identity(before_path):
            raise AnalysisError("Collected APK changed before hashing")
        if before.st_size > limits.max_apk_bytes:
            raise BudgetExceeded("APK exceeds the input size budget")
        digest = hashlib.sha256()
        size = 0
        check_resources(cancel)
        while chunk := incoming.read(JSON_READ_BYTES):
            check_resources(cancel)
            size += len(chunk)
            if size > limits.max_apk_bytes:
                raise BudgetExceeded("APK exceeds the input size budget")
            digest.update(chunk)
        after = os.fstat(incoming.fileno())
    if (
        size != before.st_size
        or file_identity(before) != file_identity(after)
        or file_identity(after) != file_identity(source.lstat())
    ):
        raise AnalysisError("Collected APK changed while hashing")
    return digest.hexdigest(), size, after


def validate_snapshot(path, identity, size, limits, cancel):
    actual, actual_size, _ = hash_regular_file(path, limits, cancel)
    if (actual, actual_size) != (identity, size):
        raise AnalysisError("Existing content-addressed APK failed validation")


def publish_snapshot(source, destination, identity, size, limits, cancel):
    check_resources(cancel)
    before = source.lstat()
    if not stat.S_ISREG(before.st_mode):
        raise AnalysisError("Collected APK is not a regular private file")
    try:
        os.link(source, destination, follow_symlinks=False)
    except FileExistsError:
        validate_snapshot(destination, identity, size, limits, cancel)
        return destination
    except NotImplementedError:
        return source
    except OSError as error:
        if error.errno not in LINK_UNSUPPORTED_ERRORS:
            raise
        return source
    after = destination.lstat()
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        destination.unlink()
        raise AnalysisError("Collected APK changed during publication")
    return destination


def publish_collected_file(source, directory, limits, cancel, metrics=None):
    from .metrics import phase

    source, directory = Path(source), Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    with phase(metrics, "collection_hash"):
        identity, size, observed = hash_regular_file(source, limits, cancel)
    if metrics:
        metrics.increment(collection_hashed_bytes=size)
    if file_identity(source.lstat()) != file_identity(observed):
        raise AnalysisError("Collected APK changed before publication")
    with phase(metrics, "collection_publish"):
        destination = publish_snapshot(
            source, directory / f"{identity}.apk", identity, size, limits, cancel
        )
    if destination == source:
        with phase(metrics, "collection_copy"):
            result = snapshot_file(source, directory, limits, cancel)
        if result["sha256"] != identity or result["size"] != size:
            raise AnalysisError("Collected APK changed during fallback copying")
        if metrics:
            metrics.increment(
                collection_copied_bytes=size, collection_hashed_bytes=size
            )
        return result
    if metrics:
        metrics.increment(collection_copied_bytes=0)
    return {
        "sha256": identity,
        "size": size,
        "path": str(destination),
        "input": str(source),
    }


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
