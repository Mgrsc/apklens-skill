import hashlib
import os
import platform
import sqlite3
import sys
import threading
import time
from collections import Counter
from contextlib import contextmanager, nullcontext
from datetime import datetime, timezone
from pathlib import Path

from .common import atomic_json, diagnostic, process_tree_rss

RESOURCE_SAMPLE_SECONDS = 0.2
DISK_SAMPLE_SECONDS = 1.0


def phase(metrics, name):
    return metrics.measure(name) if metrics is not None else nullcontext()


class PerformanceMetrics:
    def __init__(self, output, run_id, configuration=None):
        self.output = Path(output)
        self.run_id = run_id
        self.configuration = configuration or {}
        self.runtime = {}
        digest = hashlib.sha256()
        scripts = Path(__file__).parent.parent
        for path in sorted(scripts.glob("*.py")) + sorted(
            Path(__file__).parent.glob("*.py")
        ):
            digest.update(path.relative_to(scripts).as_posix().encode())
            digest.update(path.read_bytes())
        self.code_sha256 = digest.hexdigest()
        self.started = time.monotonic()
        self.started_at = datetime.now(timezone.utc).isoformat()
        self.phases = {}
        self.counters = Counter()
        self.artifacts = {}
        self.peak_rss_bytes = 0
        self.peak_output_bytes = 0
        self.timestamps = {}
        self.lock = threading.Lock()
        self.stopped = threading.Event()
        self.sampler = threading.Thread(target=self._sample_loop, daemon=True)
        self.sampler.start()

    def record(self, name, wall_seconds, cpu_seconds):
        with self.lock:
            value = self.phases.setdefault(
                name, {"count": 0, "wall_seconds": 0.0, "cpu_seconds": 0.0}
            )
            value["count"] += 1
            value["wall_seconds"] += wall_seconds
            value["cpu_seconds"] += cpu_seconds

    @contextmanager
    def measure(self, name):
        started = time.perf_counter()
        cpu = time.thread_time()
        try:
            yield
        finally:
            self.record(name, time.perf_counter() - started, time.thread_time() - cpu)

    def increment(self, **values):
        with self.lock:
            self.counters.update(values)

    def artifact(self, identity, value):
        with self.lock:
            self.artifacts[identity] = value

    def milestone(self, name):
        self.timestamps[name] = datetime.now(timezone.utc).isoformat()

    def _sample(self, disk=False):
        usage = process_tree_rss()
        if usage is not None:
            self.peak_rss_bytes = max(self.peak_rss_bytes, usage)
        if disk:
            total = 0
            for directory, _, names in os.walk(self.output):
                for name in names:
                    try:
                        total += (Path(directory) / name).stat().st_size
                    except OSError:
                        continue
            self.peak_output_bytes = max(self.peak_output_bytes, total)

    def _sample_loop(self):
        last_disk = 0.0
        while not self.stopped.is_set():
            now = time.monotonic()
            disk = now - last_disk >= DISK_SAMPLE_SECONDS
            self._sample(disk=disk)
            if disk:
                last_disk = now
            self.stopped.wait(RESOURCE_SAMPLE_SECONDS)

    def close(self, status):
        self.stopped.set()
        self.sampler.join()
        self._sample(disk=True)
        self.milestone("task_finished_at")
        value = {
            "metrics_version": 1,
            "run_id": self.run_id,
            "configuration": self.configuration,
            "runtime": self.runtime,
            "code_sha256": self.code_sha256,
            "status": status,
            "started_at": self.started_at,
            "duration_seconds": time.monotonic() - self.started,
            "python": platform.python_version(),
            "sqlite": sqlite3.sqlite_version,
            "cpu_count": os.cpu_count(),
            "gil_enabled": getattr(sys, "_is_gil_enabled", lambda: True)(),
            "process_tree_peak_rss_bytes": self.peak_rss_bytes,
            "output_peak_bytes": self.peak_output_bytes,
            "resource_sample_seconds": RESOURCE_SAMPLE_SECONDS,
            "disk_sample_seconds": DISK_SAMPLE_SECONDS,
            "phases_overlap": True,
            "phases": self.phases,
            "counters": dict(self.counters),
            "artifacts": self.artifacts,
            **self.timestamps,
        }
        try:
            atomic_json(self.output / "performance.json", value)
        except (OSError, ValueError) as error:
            diagnostic(
                "analysis.metrics_unavailable",
                level="WARN",
                correlation_id=self.run_id,
                error_type=type(error).__name__,
            )
