import ctypes
import multiprocessing
import os
import signal
import sqlite3
import stat
import tempfile
import time
import uuid
from itertools import chain, islice
from pathlib import Path

from . import ENGINE_VERSION
from .common import (
    AnalysisError,
    Cancelled,
    DiskBudgetExceeded,
    MemoryBudgetExceeded,
)
from .metrics import phase
from .privacy_models import MODEL_VERSION
from .rules import RULE_VERSION
from .storage import STORE_VERSION, AnalysisStore, ArtifactResults

POLL_SECONDS = 0.05
SHUTDOWN_SECONDS = 2.0
STARTUP_SECONDS = 30.0
RESULT_IDLE_SECONDS = 60.0
STOP_NONE = 0
STOP_CANCELLED = 1
STOP_MEMORY = 2
STOP_DISK = 3
STOP_FAILED = 4
PR_SET_PDEATHSIG = 1


def request_stop(event, reason, value):
    with reason.get_lock():
        if reason.value == STOP_NONE:
            reason.value = value
    event.set()


class WorkerStop:
    def __init__(self, event, reason, heartbeat):
        self.event = event
        self.reason = reason
        self.heartbeat = heartbeat

    def is_set(self):
        self.heartbeat.value = time.monotonic()
        return self.event.is_set()

    def set(self):
        request_stop(self.event, self.reason, STOP_MEMORY)


def arm_parent_death(parent_pid):
    library = ctypes.CDLL(None, use_errno=True)
    operation = library.prctl
    operation.argtypes = (
        ctypes.c_int,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
    )
    operation.restype = ctypes.c_int
    if operation(PR_SET_PDEATHSIG, signal.SIGKILL, 0, 0, 0) != 0:
        number = ctypes.get_errno()
        raise OSError(number, os.strerror(number))
    if os.getppid() != parent_pid:
        os._exit(1)


def worker_main(
    connection,
    event,
    reason,
    heartbeat,
    directory,
    token,
    limits,
    mode,
    cache_directory,
    parent_pid,
):
    arm_parent_death(parent_pid)
    os.setsid()
    from .engine import ARTIFACT_EXCEPTIONS, artifact_failure, cache_key, timed_artifact

    cancel = WorkerStop(event, reason, heartbeat)
    directory = Path(directory)
    connection.send({"event": "ready"})
    try:
        while not event.is_set():
            if not connection.poll(POLL_SECONDS):
                continue
            command = connection.recv()
            if command["command"] == "stop":
                return
            artifact = command["artifact"]
            identity = artifact["sha256"]
            try:
                result, timings = timed_artifact(
                    artifact, limits, mode, cancel, cache_directory
                )
            except ARTIFACT_EXCEPTIONS as error:
                result = artifact_failure(artifact, error)
                timings = None
            result.setdefault("cache_key", cache_key(identity, limits, mode))
            connection.send({"event": "parsed", "artifact": identity})
            database = directory / "result.sqlite3"
            started = time.perf_counter()
            cpu = time.thread_time()

            def values(records):
                for record in records:
                    heartbeat.value = time.monotonic()
                    yield record

            result_store = AnalysisStore(database)
            try:
                from .storage import ARTIFACT_SECTIONS

                for section in ARTIFACT_SECTIONS:
                    result[section] = values(result.get(section, ()))
                result_store.set_metadata(
                    "worker_identity",
                    {
                        "token": token,
                        "artifact": identity,
                        "engine": ENGINE_VERSION,
                        "rules": RULE_VERSION,
                        "model": MODEL_VERSION,
                        "store": STORE_VERSION,
                    },
                )
                result_store.save_artifact(identity, result)
            finally:
                result_store.close()
            del result
            connection.send(
                {
                    "event": "result",
                    "artifact": identity,
                    "token": token,
                    "timings": timings,
                    "persist_timings": {
                        "wall_seconds": time.perf_counter() - started,
                        "cpu_seconds": time.thread_time() - cpu,
                    },
                }
            )
            while not connection.poll(POLL_SECONDS):
                if event.is_set():
                    return
            acknowledgement = connection.recv()
            if acknowledgement != {"command": "ack", "artifact": identity}:
                raise AnalysisError("Invalid worker acknowledgement")
            database.unlink()
    except (EOFError, BrokenPipeError):
        return
    except (sqlite3.Error, *ARTIFACT_EXCEPTIONS) as error:
        try:
            connection.send({"event": "failed", "error_type": type(error).__name__})
        except (EOFError, BrokenPipeError, OSError):
            pass
    finally:
        connection.close()


def validate_result(worker, identity, limits, mode):
    from .engine import cache_key

    path = worker["directory"] / "result.sqlite3"
    if (
        not stat.S_ISREG(path.lstat().st_mode)
        or path.resolve().parent != worker["directory"]
    ):
        raise AnalysisError("Worker result is not a private regular database")
    source = AnalysisStore(path, readonly=True)
    try:
        expected = {
            "token": worker["token"],
            "artifact": identity,
            "engine": ENGINE_VERSION,
            "rules": RULE_VERSION,
            "model": MODEL_VERSION,
            "store": STORE_VERSION,
        }
        if (
            source.metadata("worker_identity") != expected
            or source.version != STORE_VERSION
        ):
            raise AnalysisError("Worker result identity does not match the task")
        results = ArtifactResults(source)
        if list(results) != [identity]:
            raise AnalysisError("Worker result has unexpected artifacts")
        result = results[identity]
        if result.get("sha256") != identity or result.get("cache_key") != cache_key(
            identity, limits, mode
        ):
            raise AnalysisError("Worker artifact identity does not match the task")
    except BaseException:
        source.close()
        raise
    return source


def stop_workers(workers, event, reason):
    request_stop(event, reason, STOP_NONE)
    deadline = time.monotonic() + SHUTDOWN_SECONDS
    for worker in workers:
        worker["connection"].close()
    for worker in workers:
        worker["process"].join(max(0, deadline - time.monotonic()))
    for worker in workers:
        process = worker["process"]
        if process.is_alive():
            try:
                if os.getpgid(process.pid) == process.pid:
                    os.killpg(process.pid, signal.SIGKILL)
                else:
                    process.kill()
            except ProcessLookupError:
                pass
        process.join()
        process.close()


def analyze_processes(
    pending,
    limits,
    mode,
    cancel,
    jobs,
    cache_directory,
    store,
    completion,
    metrics=None,
):
    if metrics:
        metrics.runtime["worker_processes_started"] = 0
    if cancel.is_set():
        return
    if store.budget:
        store.budget.check()
    initial = list(islice(pending, jobs))
    if not initial:
        return
    jobs = len(initial)
    pending = chain(initial, pending)
    if metrics:
        metrics.runtime["effective_jobs"] = jobs
    context = multiprocessing.get_context("spawn")
    event = context.Event()
    reason = context.Value("i", STOP_NONE)
    workers = []
    stopping = None
    exhausted = False

    def response_timeout(worker):
        if worker["state"] == "starting":
            return STARTUP_SECONDS
        if worker["state"] == "persisting":
            return RESULT_IDLE_SECONDS
        return limits.timeout + SHUTDOWN_SECONDS

    def observe_stop():
        nonlocal stopping
        if stopping is not None or not (cancel.is_set() or event.is_set()):
            return
        cause = (
            STOP_DISK
            if store.budget and store.budget.disk_exceeded
            else STOP_MEMORY
            if store.budget and store.budget.memory_exceeded
            else reason.value or STOP_CANCELLED
        )
        request_stop(event, reason, cause)
        cancel.set()
        if store.budget and reason.value == STOP_MEMORY:
            store.budget.memory_exceeded = True
        stopping = time.monotonic() + SHUTDOWN_SECONDS

    def fail_worker(worker, message):
        from .engine import artifact_failure

        error = AnalysisError(
            f"{message}; phase={worker['state']}, response_timeout_seconds={response_timeout(worker):g}"
        )
        artifact = worker["artifact"]
        if artifact:
            result = artifact_failure(artifact, error)
            store.save_artifact(artifact["sha256"], result)
            completion(artifact, result)
        raise error

    with tempfile.TemporaryDirectory(
        prefix=".workers-", dir=store.path.parent
    ) as temporary:
        try:
            for index in range(jobs):
                directory = (Path(temporary) / str(index)).resolve()
                directory.mkdir()
                parent, child = context.Pipe()
                heartbeat = context.Value("d", time.monotonic(), lock=False)
                token = uuid.uuid4().hex
                process = context.Process(
                    target=worker_main,
                    args=(
                        child,
                        event,
                        reason,
                        heartbeat,
                        str(directory),
                        token,
                        limits,
                        mode,
                        cache_directory,
                        os.getpid(),
                    ),
                )
                try:
                    process.start()
                except BaseException:
                    parent.close()
                    child.close()
                    if process.pid is not None:
                        process.kill()
                        process.join()
                    process.close()
                    raise
                child.close()
                if metrics:
                    metrics.runtime["worker_processes_started"] += 1
                workers.append(
                    {
                        "process": process,
                        "connection": parent,
                        "heartbeat": heartbeat,
                        "directory": directory,
                        "token": token,
                        "state": "starting",
                        "artifact": None,
                        "started": time.monotonic(),
                    }
                )
            while True:
                if stopping is None:
                    try:
                        if store.budget:
                            store.budget.check()
                    except (Cancelled, MemoryBudgetExceeded, DiskBudgetExceeded):
                        cancel.set()
                    observe_stop()

                def check_import():
                    if stopping is None:
                        store.check_cancel()
                    else:
                        if time.monotonic() > stopping:
                            raise Cancelled("Worker result drain deadline exceeded")
                        if store.budget:
                            store.budget.check_disk()

                active = False
                for worker in workers:
                    connection = worker["connection"]
                    process = worker["process"]
                    if connection.poll():
                        try:
                            message = connection.recv()
                        except EOFError:
                            message = {"event": "closed"}
                        if (
                            message.get("event") == "ready"
                            and worker["state"] == "starting"
                        ):
                            worker["state"] = "idle"
                        elif (
                            message.get("event") == "parsed"
                            and worker["state"] == "parsing"
                            and message.get("artifact") == worker["artifact"]["sha256"]
                        ):
                            worker["state"] = "persisting"
                            worker["heartbeat"].value = time.monotonic()
                        elif (
                            message.get("event") == "result"
                            and worker["state"] == "persisting"
                            and message.get("token") == worker["token"]
                            and message.get("artifact") == worker["artifact"]["sha256"]
                        ):
                            artifact = worker["artifact"]
                            identity = artifact["sha256"]
                            source = validate_result(worker, identity, limits, mode)
                            try:
                                with phase(metrics, "artifact_persist"):
                                    store.import_artifact(
                                        source, identity, check=check_import
                                    )
                            except Cancelled:
                                if stopping is None:
                                    raise
                            else:
                                if metrics:
                                    if message["timings"]:
                                        metrics.record(
                                            "artifact_parse", **message["timings"]
                                        )
                                    metrics.record(
                                        "worker_persist", **message["persist_timings"]
                                    )
                                result = store.artifact(identity)
                                if result.get("resource_limited"):
                                    request_stop(event, reason, STOP_MEMORY)
                                completion(artifact, result)
                            finally:
                                source.close()
                            observe_stop()
                            if process.is_alive() and stopping is None:
                                connection.send(
                                    {"command": "ack", "artifact": identity}
                                )
                            worker["state"] = "idle"
                            worker["artifact"] = None
                        elif stopping is None:
                            if message.get("event") == "failed":
                                fail_worker(
                                    worker, "Worker failed: " + message["error_type"]
                                )
                            fail_worker(
                                worker, "Worker exited or violated the result protocol"
                            )
                    observe_stop()
                    if worker["state"] == "idle" and stopping is None and not exhausted:
                        artifact = next(pending, None)
                        if artifact is None:
                            exhausted = True
                        else:
                            connection.send(
                                {"command": "analyze", "artifact": artifact}
                            )
                            worker.update(
                                state="parsing",
                                artifact=artifact,
                                started=time.monotonic(),
                            )
                    if worker["state"] != "idle":
                        active = True
                        now = time.monotonic()
                        started = (
                            worker["heartbeat"].value
                            if worker["state"] == "persisting"
                            else worker["started"]
                        )
                        deadline = started + response_timeout(worker)
                        if stopping is None and (
                            not process.is_alive() or now > deadline
                        ):
                            fail_worker(
                                worker,
                                "Worker crashed or exceeded its response deadline",
                            )
                if stopping is not None:
                    if time.monotonic() >= stopping or (
                        not any(worker["process"].is_alive() for worker in workers)
                        and not any(worker["connection"].poll() for worker in workers)
                    ):
                        break
                elif exhausted and not active:
                    break
                time.sleep(POLL_SECONDS)
        except BaseException:
            cancel.set()
            request_stop(event, reason, STOP_FAILED)
            raise
        finally:
            stop_workers(workers, event, reason)
